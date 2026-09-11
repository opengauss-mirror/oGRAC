/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * knl_parallel_log.c
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_parallel_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_persist_module.h"
#include "knl_parallel_log.h"
#include "knl_log.h"
#include "knl_database.h"
#include "knl_recovery.h"
#include "srv_instance.h"
#include "cm_futex.h"
#include "dtc_database.h"
#include "knl_ctrl_restore.h"
#include "knl_ckpt.h"
#include "cm_memory.h"
#include "cm_date.h"
#include "cm_log.h"
#include "cm_checksum.h"
#include <numa.h>

typedef char knl_log_file_head_size_check[(sizeof(log_file_head_t) == OG_LOG_FILE_HEAD_SIZE) ? 1 : -1];

static void para_log_persist_ctrl_if_dirty(knl_session_t *session, para_log_context_t *ogx);
static void para_log_fix_curr_by_asn(knl_session_t *session, para_log_context_t *ogx);
static void para_log_rebuild_free_size(para_log_context_t *ogx);

static inline uint64 para_log_commit_now(const knl_session_t *session)
{
    return cm_atomic_barrier_read(&session->kernel->para_log_lsn_ctl.s.commit);
}

static inline bool32 para_log_lsn_in_commit_space(uint64 lsn, uint64 commit_hi)
{
    if (lsn == 0 || lsn == OG_INVALID_ID64) {
        return OG_FALSE;
    }

    return (bool32)(lsn <= commit_hi);
}

static void para_log_reset_lsn_ctl(knl_instance_t *kernel, uint64 commit, uint64 lsn)
{
    para_log_lsn_ctl_t ctl;

    ctl.s.lsn = lsn;
    ctl.s.commit = commit;
    kernel->para_log_lsn_ctl.value = ctl.value;
}

uint32 para_log_bind_group(const knl_session_t *session)
{
    uint32 group_count;
    uint32 numa;

    if (session == NULL || session->kernel == NULL) {
        return 0;
    }

    group_count = SYS_NUMA_GROUP_COUNT;
    if (group_count == 0) {
        return 0;
    }

    numa = session->ass_numa;
    if (numa >= group_count) {
        numa %= group_count;
    }

    return numa;
}

para_log_context_t *para_log_ctx_of(const knl_session_t *session)
{
    uint32 group;

    if (session == NULL || session->kernel == NULL) {
        return NULL;
    }

    group = para_log_bind_group(session);
    return session->kernel->para_log_ctx[group];
}

para_log_flush_lsn_bitmap_t *para_log_bitmap_of(const knl_session_t *session)
{
    if (session == NULL || session->kernel == NULL) {
        return NULL;
    }

    return session->kernel->para_log_bitmap;
}

static void para_log_dfx_dump(knl_session_t *session, para_log_context_t *ogx, const char *reason)
{
    log_context_t *redo;
    para_log_flush_lsn_bitmap_t *bm;
    log_file_t *file = NULL;
    const char *fname = "-";
    uint32 asn = 0;
    uint64 wpos = 0;
    uint64 file_max = 0;
    uint64 commit_lsn;
    uint64 flushed;
    uint64 lag;

    if (ogx == NULL || session == NULL || session->kernel == NULL) {
        return;
    }

    if (!ENABLE_PARA_LOG_DFX(session)) {
        return;
    }

    redo = &session->kernel->redo_ctx;
    bm = session->kernel->para_log_bitmap;
    if (para_log_file_slot_valid(ogx, ogx->curr_file)) {
        file = ogx->files[ogx->curr_file];
        file_max = ogx->file_max_lsn[ogx->curr_file];
        if (file != NULL && file->ctrl != NULL) {
            fname = file->ctrl->name;
            asn = file->head.asn;
            wpos = file->head.write_pos;
        }
    }

    commit_lsn = para_log_commit_now(session);
    flushed = cm_atomic_barrier_read(&redo->flushed_lsn);
    lag = (commit_lsn > flushed) ? (commit_lsn - flushed) : 0;
    OG_LOG_RUN_INF("[PARA LOG] stat reason=%s group=%u writes=%llu wbytes=%llu wretry=%llu slot_wait=%llu "
                   "flush=%llu fbytes=%llu fentries=%llu empty=%llu commit_loop=%llu switch=%llu recycle=%llu bm_block=%llu "
                   "active=%u curr=%u file=%s asn=%u wpos=%llu file_max_lsn=%llu free=%lld "
                   "commit_lsn=%llu flushed=%llu lag=%llu bm_base=%llu bm_max=%llu",
                   (reason == NULL) ? "-" : reason, ogx->thread_idx, ogx->dfx.write_cnt, ogx->dfx.write_bytes,
                   ogx->dfx.write_retry, ogx->dfx.slot_wait, ogx->dfx.flush_cnt, ogx->dfx.flush_bytes,
                   ogx->dfx.flush_entries, ogx->dfx.empty_poll, ogx->dfx.commit_wait_loop, ogx->dfx.switch_cnt,
                   ogx->dfx.recycle_cnt, ogx->dfx.bitmap_block, ogx->active_file, ogx->curr_file, fname, asn, wpos,
                   file_max, (int64)cm_atomic_get(&ogx->free_size), commit_lsn, flushed, lag,
                   (bm == NULL) ? 0 : para_log_u64_load(&bm->base_lsn),
                   (bm == NULL) ? 0 : para_log_u64_load(&bm->max_marked_lsn));
}

static void para_log_dfx_dump_due(knl_session_t *session, para_log_context_t *ogx)
{
    date_t now;

    if (ogx == NULL || session == NULL || !ENABLE_PARA_LOG_DFX(session)) {
        return;
    }

    now = cm_now();
    if (ogx->dfx.last_dump != 0 &&
        (now - ogx->dfx.last_dump) < ((date_t)LOG_PRINT_INTERVAL_SECOND_10 * MICROSECS_PER_SECOND)) {
        return;
    }

    ogx->dfx.last_dump = now;
    para_log_dfx_dump(session, ogx, "period");
}

static void para_log_free_flush_buf(para_log_context_t *ogx)
{
    /* need free all numa alloced buffer */
    para_log_buf_ctx_t *buf_ctx = &ogx->log_buf_ctx;
    if (buf_ctx->buffer != NULL) {
        numa_free(buf_ctx->buffer, buf_ctx->buffer_size);
        buf_ctx->buffer = NULL;
        buf_ctx->buffer_size = 0;
    }

    if (buf_ctx->status_table != NULL) {
        numa_free(buf_ctx->status_table, buf_ctx->status_tbl_size);
        buf_ctx->status_table = NULL;
    }

    if (ogx->flush_buf != NULL) {
        numa_free(ogx->flush_buf, (size_t)ogx->flush_buf_size);
        ogx->flush_buf = NULL;
        ogx->flush_buf_size = 0;
    }

    if (ogx->logwr_head_buf != NULL) {
        numa_free(ogx->logwr_head_buf, (size_t)CM_CALC_ALIGN(sizeof(log_file_head_t), OG_DFLT_LOG_BLOCK_SIZE));
        ogx->logwr_head_buf = NULL;
    }
}

status_t para_log_init(knl_session_t *session)
{
    uint32 status_entries_count = 1 << RD_STATUS_ENTRIES_POWER;
    uint32 cluster_count = SYS_NUMA_GROUP_COUNT;
    uint32 numa_count = SYS_NUMA_NODE_COUNT;
    uint64 per_numa_buffer_size;
    uint64 flush_buf_size;
    knl_session_t *lgwr_se;
    errno_t ret;

    if (cluster_count == 0) {
        OG_LOG_RUN_ERR("[LOG] para log group count is 0");
        return OG_ERROR;
    }

    lgwr_se = session->kernel->sessions[SESSION_ID_PARA_LOG_FLUSH];
    if (lgwr_se == NULL) {
        OG_LOG_RUN_ERR("[LOG] para log lgwr session %u is not initialized", SESSION_ID_PARA_LOG_FLUSH);
        return OG_ERROR;
    }

    per_numa_buffer_size = session->kernel->attr.log_buf_size / cluster_count;
    flush_buf_size = (uint64)OG_MAX_BATCH_SIZE / cluster_count;

    for (uint32 i = 0; i < cluster_count; i++) {
        uint32 phys_numa = 0;

        if (numa_count > 0) {
            phys_numa = i * numa_count / cluster_count;
        }

        session->kernel->para_log_ctx[i] =
            (para_log_context_t *)numa_alloc_onnode(sizeof(para_log_context_t), (int)phys_numa);
        if (session->kernel->para_log_ctx[i] == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(para_log_context_t), "para log context");
            OG_LOG_RUN_ERR("failed to malloc para log context for numa %u", i);
            goto err_cleanup;
        }

        ret = memset_sp(session->kernel->para_log_ctx[i], sizeof(para_log_context_t), 0, sizeof(para_log_context_t));
        knl_securec_check(ret);
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];

        /* files[] / file_max_lsn[] are embedded arrays; whole-context memset already zeroed them. */
        ogx->log_file_idx = 0;
        ogx->thread_idx = i;
        ogx->session = lgwr_se;
        ogx->tx_queue.atomic_first = (int64)NULL;
        ogx->leader_wait_cond.futex = 0;
        cm_futex_init(&ogx->kick_futex);
        cm_futex_init(&ogx->ack_futex);
        cm_futex_init(&ogx->space_futex);

        para_log_buf_ctx_t *buf_ctx = &ogx->log_buf_ctx;
        
        buf_ctx->buffer = (char *)numa_alloc_onnode(per_numa_buffer_size, (int)phys_numa);
        if (buf_ctx->buffer == NULL) {
            OG_LOG_RUN_ERR("failed to malloc wal buffer for numa %d", i);
            CM_ABORT(0, "ABORT INFO: failed to malloc wal buffer");
        }

        ret = memset_sp(buf_ctx->buffer, per_numa_buffer_size, 0, per_numa_buffer_size);
        knl_securec_check(ret);
        buf_ctx->buffer_size = per_numa_buffer_size;

        
        ret = memset_sp(&buf_ctx->ctl, sizeof(para_log_buf_ctl_t), 0, sizeof(para_log_buf_ctl_t));
        knl_securec_check(ret);
        buf_ctx->ctl.struct128.curr_byte_pos = 0;
        buf_ctx->ctl.struct128.curr_byte_size = 0;
        buf_ctx->ctl.struct128.curr_lrc = 0;
        
        buf_ctx->status_tbl_size = sizeof(para_log_ins_status_ent_t) * status_entries_count;
        buf_ctx->status_table =
            (para_log_ins_status_ent_t *)numa_alloc_onnode(buf_ctx->status_tbl_size, (int)phys_numa);
        if (buf_ctx->status_table == NULL) {
            OG_LOG_RUN_ERR("failed to malloc status_table for numa %d", i);
            CM_ABORT(0, "ABORT INFO: failed to malloc status_table");
        }

        ret = memset_sp(buf_ctx->status_table, buf_ctx->status_tbl_size, 0, buf_ctx->status_tbl_size);
        knl_securec_check(ret);
        
        ogx->last_flushed_entry = -1;
        ogx->last_flushed_pos = 0;
        ogx->flush_buf = NULL;
        ogx->flush_buf_size = 0;
        ogx->file_write_pos = 0;

        ogx->flush_buf = (char *)numa_alloc_onnode((size_t)flush_buf_size, (int)phys_numa);
        if (ogx->flush_buf == NULL) {
            OG_LOG_RUN_ERR("failed to alloc numa wal flush buf for numa %d", i);
            goto err_cleanup;
        }

        ogx->logwr_head_buf =
            (char *)numa_alloc_onnode(CM_CALC_ALIGN(sizeof(log_file_head_t), OG_DFLT_LOG_BLOCK_SIZE), (int)phys_numa);
        if (ogx->logwr_head_buf == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY,
                           (uint64)CM_CALC_ALIGN(sizeof(log_file_head_t), OG_DFLT_LOG_BLOCK_SIZE),
                           "para log head buf");
            OG_LOG_RUN_ERR("failed to alloc numa wal head buf for numa %u", i);
            goto err_cleanup;
        }
        
        ogx->flush_buf_size = flush_buf_size;
        OG_LOG_RUN_INF("[PARA LOG] init group=%u phys_numa=%u sid=%u wal_buf=%llu flush_buf=%llu status_entries=%u",
                       i, phys_numa, lgwr_se->id, per_numa_buffer_size, flush_buf_size, status_entries_count);
    }

    session->kernel->para_log_bitmap = (para_log_flush_lsn_bitmap_t *)malloc(sizeof(para_log_flush_lsn_bitmap_t));
    if (session->kernel->para_log_bitmap == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(para_log_flush_lsn_bitmap_t), "para log bitmap");
        OG_LOG_RUN_ERR("failed to malloc para log bitmap");
        goto err_cleanup;
    }

    ret = memset_sp(session->kernel->para_log_bitmap, sizeof(para_log_flush_lsn_bitmap_t), 0,
        sizeof(para_log_flush_lsn_bitmap_t));
    knl_securec_check(ret);
    
    para_log_reset_lsn_ctl(session->kernel, 0, 0);
    session->kernel->para_log_init = OG_FALSE;
    OG_LOG_RUN_INF("[PARA LOG] init done groups=%u numa_nodes=%u log_buf=%llu bitmap_window=%u lgwr_session=%u",
                   cluster_count, numa_count, session->kernel->attr.log_buf_size, LOG_FLUSH_BITMAP_WINDOW_SIZE,
                   (uint32)SESSION_ID_PARA_LOG_FLUSH);
    return OG_SUCCESS;

err_cleanup:
    para_log_close(session);
    return OG_ERROR;
}

status_t para_log_check_unsupported(knl_session_t *session)
{
    knl_instance_t *kernel;
    logfile_set_t *logfile_set;
    uint32 i;

    if (!ENABLE_PARA_LOG_FLUSH(session)) {
        return OG_SUCCESS;
    }

    kernel = session->kernel;

    if (KNL_RBP_ENABLE(kernel)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "RBP with parallel log flush");
        OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support RBP, set USE_RBP=FALSE");
        return OG_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(kernel)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "RAFT with parallel log flush");
        OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support RAFT");
        return OG_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "DBStor with parallel log flush");
        OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support DBStor");
        return OG_ERROR;
    }

    if (kernel->db.ctrl.core.log_mode == ARCHIVE_LOG_ON || kernel->arch_ctx.is_archive) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "archivelog with parallel log flush");
        OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support archive log");
        return OG_ERROR;
    }

    if (kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "logic replication with parallel log flush");
        OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support logic replication");
        return OG_ERROR;
    }

    if (kernel->lsnd_ctx.standby_num > 0) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "physical standby (lsnd) with parallel log flush");
        OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support lsnd/physical standby");
        return OG_ERROR;
    }

    for (i = 0; i < OG_MAX_ARCH_DEST; i++) {
        arch_attr_t *arch_attr = &kernel->attr.arch_attr[i];
        if (arch_attr->dest_mode == LOG_ARCH_DEST_SERVICE && arch_attr->enable) {
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "physical standby (lsnd) with parallel log flush");
            OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support lsnd archive dest");
            return OG_ERROR;
        }
    }

    logfile_set = MY_LOGFILE_SET(session);
    for (i = 0; i < logfile_set->logfile_hwm; i++) {
        log_file_t *file = &logfile_set->items[i];
        if (file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (file->ctrl->type == DEV_TYPE_ULOG) {
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "ULOG with parallel log flush");
            OG_LOG_RUN_ERR("[PARA LOG] parallel log flush does not support ULOG file %s", file->ctrl->name);
            return OG_ERROR;
        }
    }

    OG_LOG_RUN_INF("[PARA LOG] capability check passed groups=%u rbp=%u raft=%u archive=%u",
                   SYS_NUMA_GROUP_COUNT, (uint32)KNL_RBP_ENABLE(kernel),
                   (uint32)DB_IS_RAFT_ENABLED(kernel), (uint32)kernel->arch_ctx.is_archive);
    return OG_SUCCESS;
}

static bool32 para_log_slot_in_active_range(para_log_context_t *ogx, uint32 file_id)
{
    if (ogx->active_file <= ogx->curr_file) {
        return (bool32)(file_id >= ogx->active_file && file_id <= ogx->curr_file);
    }

    return (bool32)(file_id >= ogx->active_file || file_id <= ogx->curr_file);
}

status_t para_log_file_load(knl_session_t *session)
{
    log_context_t *ogx = &session->kernel->redo_ctx;
    para_log_flush_lsn_bitmap_t *bm = session->kernel->para_log_bitmap;
    uint32 group_count = SYS_NUMA_GROUP_COUNT;

    if (bm == NULL) {
        OG_LOG_RUN_ERR("[PARA LOG] file_load failed: bitmap is not initialized");
        return OG_ERROR;
    }

    uint64 start_commit = dtc_my_ctrl(session)->lrp_point.lsn;
    uint64 start_lsn = (uint64)cm_atomic_get(&session->kernel->lsn);
    if (start_lsn < start_commit) {
        start_lsn = start_commit;
    }

    para_log_reset_lsn_ctl(session->kernel, start_commit, start_lsn);
    cm_atomic_set((atomic_t *)&ogx->flushed_lsn, (int64)start_commit);
    // in parallel mode flushed_lfn is a commit-prefix placeholder, aligned with flushed_lsn
    cm_atomic_set((atomic_t *)&ogx->flushed_lfn, (int64)ogx->flushed_lsn);

    // init LSN bitmap window; bm->flushed_lsn must align with redo_ctx, otherwise the first advance scans from 0 to base-1
    bm->base_lsn = ogx->flushed_lsn;
    bm->max_marked_lsn = ogx->flushed_lsn;
    bm->flushed_lsn = ogx->flushed_lsn;

    for (uint32 i = 0; i < group_count; i++) {
        para_log_context_t *para_ogx = session->kernel->para_log_ctx[i];
        log_file_t *curr_file = NULL;

        if (para_ogx == NULL) {
            continue;
        }

        if (para_ogx->log_file_idx > CPU_SEG_MAX_NUM) {
            OG_LOG_RUN_ERR("[PARA LOG] group %u log_file_idx %u exceeds %u, refuse to truncate "
                           "(would skip log files and create recovery holes)",
                           i, para_ogx->log_file_idx, CPU_SEG_MAX_NUM);
            return OG_ERROR;
        }

        /* ctrl's para_log_last may lag behind the file head ASN (ctrl is flushed async after file switch). */
        para_log_fix_curr_by_asn(session, para_ogx);

        if (para_log_file_slot_valid(para_ogx, para_ogx->curr_file)) {
            curr_file = para_ogx->files[para_ogx->curr_file];
        }

        if (curr_file != NULL) {
            para_ogx->file_write_pos = curr_file->head.write_pos;
        }

        for (uint32 file_id = 0; file_id < para_log_file_slot_count(para_ogx); file_id++) {
            log_file_t *file = para_ogx->files[file_id];
            bool32 in_use;

            if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg) ||
                file->head.asn == OG_INVALID_ASN) {
                para_ogx->file_max_lsn[file_id] = 0;
                continue;
            }

            in_use = para_log_slot_in_active_range(para_ogx, file_id);
            if (!in_use) {
                para_ogx->file_max_lsn[file_id] = 0;
                OG_LOG_RUN_INF("[PARA LOG] load skip unused group=%u slot=%u file=%s asn=%u write_pos=%llu",
                               i, file_id, file->ctrl->name, file->head.asn, file->head.write_pos);
                continue;
            }

            {
                uint64 hdr_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);

                /* empty file has only the header: ignore leftover Lamport first/last_lsn from build, otherwise it can never be recycled */
                if (file->head.write_pos <= hdr_size) {
                    file->head.first_lsn = 0;
                    file->head.last_lsn = 0;
                    para_ogx->file_max_lsn[file_id] = 0;
                } else if (para_log_lsn_in_commit_space(file->head.last_lsn, start_commit)) {
                    para_ogx->file_max_lsn[file_id] = file->head.last_lsn;
                } else {
                    /* has data but last_lsn is outside commit space: do not recycle by this value, fall back to flushed_lsn when recycling */
                    para_ogx->file_max_lsn[file_id] = OG_INVALID_ID64;
                    OG_LOG_RUN_WAR("[PARA LOG] load ignore stale last_lsn group=%u slot=%u file=%s "
                                   "last_lsn=%llu start_commit=%llu write_pos=%llu",
                                   i, file_id, file->ctrl->name, file->head.last_lsn, start_commit,
                                   file->head.write_pos);
                }
            }
            OG_LOG_RUN_INF("[PARA LOG] load group=%u slot=%u file=%s asn=%u status=%d write_pos=%llu "
                           "first_lsn=%llu last_lsn=%llu in_use=%u file_max_lsn=%llu",
                           i, file_id, file->ctrl->name, file->head.asn, file->ctrl->status, file->head.write_pos,
                           file->head.first_lsn, file->head.last_lsn, in_use, para_ogx->file_max_lsn[file_id]);
        }

        /* INACTIVE file head may still be at EOF, cannot compute free space by write_pos */
        para_log_rebuild_free_size(para_ogx);

        OG_LOG_RUN_INF("[PARA LOG] load group=%u files=%u active=%u curr=%u write_pos=%llu free=%lld",
                       i, para_ogx->log_file_idx, para_ogx->active_file, para_ogx->curr_file,
                       para_ogx->file_write_pos, (int64)cm_atomic_get(&para_ogx->free_size));
        para_log_persist_ctrl_if_dirty(session, para_ogx);
    }

    session->kernel->para_log_init = OG_TRUE;
    OG_LOG_RUN_INF("[PARA LOG] file_load done start_commit_lsn=%llu flushed=%llu groups=%u",
                   start_commit, ogx->flushed_lsn, group_count);
    return OG_SUCCESS;
}

void para_log_close(knl_session_t *session)
{
    uint32 cluster_count = SYS_NUMA_GROUP_COUNT;
    uint32 i;

    OG_LOG_RUN_INF("[PARA LOG] close begin groups=%u flushed=%llu", cluster_count,
                   cm_atomic_barrier_read(&session->kernel->redo_ctx.flushed_lsn));
    // stop all lgwr threads before freeing buffers; otherwise flush_by_numa may still be using flush_buf
    for (i = 0; i < cluster_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];
        if (ogx != NULL) {
            para_log_dfx_dump(session, ogx, "close");

            ogx->thread.closed = OG_TRUE;
            cm_futex_wake(&ogx->kick_futex, 1);
            cm_close_thread(&ogx->thread);
        }
    }

    for (i = 0; i < cluster_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];
        if (ogx != NULL) {
            para_log_persist_ctrl_if_dirty(session, ogx);
        }
    }

    for (i = 0; i < cluster_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];
        if (ogx == NULL) {
            continue;
        }

        para_log_free_flush_buf(ogx);
        numa_free(ogx, sizeof(para_log_context_t));
        session->kernel->para_log_ctx[i] = NULL;
    }

    if (session->kernel->para_log_bitmap != NULL) {
        free(session->kernel->para_log_bitmap);
        session->kernel->para_log_bitmap = NULL;
    }
}

static log_file_t *para_log_checked_file(const para_log_context_t *ogx, uint32 slot)
{
    log_file_t *file;

    knl_panic_log(ogx != NULL, "para log context is null");

    knl_panic_log(para_log_file_slot_valid(ogx, slot),
                  "para log file slot is out of range, panic info: group=%u slot=%u file_count=%u",
                  ogx->thread_idx, slot, ogx->log_file_idx);

    file = ogx->files[slot];
    knl_panic_log(file != NULL && file->ctrl != NULL,
                  "para log file pointer is null, panic info: group=%u slot=%u file_count=%u",
                  ogx->thread_idx, slot, ogx->log_file_idx);
    return file;
}

static uint64 para_log_file_capacity(const para_log_context_t *ogx)
{
    log_file_t *file;

    if (!para_log_file_slot_valid(ogx, ogx->curr_file)) {
        return 0;
    }

    file = ogx->files[ogx->curr_file];
    if (file == NULL || file->ctrl == NULL || file->ctrl->size <= 0) {
        return 0;
    }

    return (uint64)file->ctrl->size;
}

static uint64 para_log_inactive_capacity(const log_file_t *file)
{
    uint64 hdr;

    if (file == NULL || file->ctrl == NULL || file->ctrl->size <= 0) {
        return 0;
    }

    hdr = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    if ((uint64)file->ctrl->size <= hdr) {
        return 0;
    }

    /* switched-out INACTIVE file head write_pos often stays at EOF, cannot use log_file_freesize */
    return (uint64)file->ctrl->size - hdr;
}

static void para_log_rebuild_free_size(para_log_context_t *ogx)
{
    uint64 total = 0;
    uint32 i;
    uint32 n;

    if (ogx == NULL) {
        return;
    }

    n = para_log_file_slot_count(ogx);
    for (i = 0; i < n; i++) {
        log_file_t *file = ogx->files[i];

        if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (file->ctrl->status == LOG_FILE_CURRENT) {
            total += log_file_freesize(file);
            continue;
        }

        if (file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED) {
            total += para_log_inactive_capacity(file);
        }
    }

    cm_atomic_set(&ogx->free_size, (int64)total);
}

static bool32 para_log_has_inactive_slot(const para_log_context_t *ogx)
{
    uint32 i;
    uint32 n;

    if (ogx == NULL) {
        return OG_FALSE;
    }

    n = para_log_file_slot_count(ogx);
    for (i = 0; i < n; i++) {
        log_file_t *file = ogx->files[i];

        if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (i == ogx->curr_file || i == ogx->active_file) {
            continue;
        }

        if (file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static uint64 para_log_keep_size(knl_session_t *session, const para_log_context_t *ogx)
{
    uint32 groups;
    uint64 session_keep;
    uint64 file_size;

    groups = SYS_NUMA_GROUP_COUNT;
    if (groups == 0) {
        groups = 1;
    }

    session_keep = LOG_KEEP_SIZE(session, session->kernel) / groups;
    file_size = para_log_file_capacity(ogx);
    if (file_size == 0 || session_keep < file_size) {
        return session_keep;
    }

    return file_size;
}

bool32 para_log_has_keep_space(knl_session_t *session, para_log_context_t *ogx)
{
    uint64 free_size;

    knl_panic_log(session != NULL && ogx != NULL, "para log keep space args are null");
    free_size = (uint64)cm_atomic_get(&ogx->free_size);
    if (free_size > para_log_keep_size(session, ogx)) {
        return OG_TRUE;
    }

        /* when an INACTIVE file is available to switch to, do not stall business just because CURRENT tail is smaller than KEEP */
    return para_log_has_inactive_slot(ogx);
}

void para_log_wait_keep_space(knl_session_t *session, para_log_context_t *ogx)
{
    knl_panic_log(session != NULL && ogx != NULL, "para log keep wait args are null");
    ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
    (void)cm_futex_wait(&ogx->space_futex, PARA_LOG_SPACE_WAIT_SLICE_MS);
}

static void para_log_wake_space_waiters(para_log_context_t *ogx)
{
    if (ogx == NULL) {
        return;
    }

    cm_futex_wake(&ogx->space_futex, PARA_LOG_SPACE_WAKE_COUNT);
}

/* b_flush_lock is a spinlock; recycling wait must happen outside the lock. */
static void para_log_wait_if_switch_blocked(knl_session_t *session, para_log_context_t *ogx)
{
    if (session == NULL || ogx == NULL) {
        return;
    }

    if (cm_atomic32_get(&ogx->switch_blocked) == 0) {
        return;
    }

    ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
    (void)cm_futex_wait(&ogx->space_futex, PARA_LOG_SPACE_WAIT_SLICE_MS);
}

static void para_log_maybe_kick_ckpt(knl_session_t *session, para_log_context_t *ogx)
{
    uint64 file_size;
    uint64 watermark;
    uint64 free_size;
    date_t now;

    if (session == NULL || ogx == NULL || DB_NOT_READY(session)) {
        return;
    }

    if (ogx->active_file == ogx->curr_file) {
        return;
    }

    file_size = para_log_file_capacity(ogx);
    if (file_size == 0) {
        return;
    }

    watermark = file_size * 2;
    free_size = (uint64)cm_atomic_get(&ogx->free_size);
    if (free_size > watermark) {
        return;
    }

    now = cm_now();
    if (ogx->last_ckpt_kick != 0 && (now - ogx->last_ckpt_kick) < PARA_LOG_CKPT_KICK_INTERVAL) {
        return;
    }

    ogx->last_ckpt_kick = now;
    ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
}

static bool32 para_log_get_next_file(knl_session_t *session, para_log_context_t *ogx, uint32 *next,
    bool32 use_curr, bool32 require_free)
{
    uint32 scanned = 0;
    uint32 file_count = para_log_file_slot_count(ogx);

    (void)session;

    if (use_curr) {
        knl_panic_log(para_log_file_slot_valid(ogx, ogx->curr_file),
                      "para log current file slot is out of range, panic info: group=%u curr_file=%u file_count=%u",
                      ogx->thread_idx, ogx->curr_file, ogx->log_file_idx);
        *next = ogx->curr_file;
    }

    if (file_count == 0) {
        return OG_FALSE;
    }

    for (;;) {
        log_file_t *logfile;

        CM_CYCLED_MOVE_NEXT(ogx->log_file_idx, *next);
        scanned++;
        if (scanned > file_count) {
            if (require_free) {
                return OG_FALSE;
            }

            knl_panic_log(0, "para log get next file wrapped without candidate, panic info: group=%u start=%u",
                          ogx->thread_idx, ogx->curr_file);
            return OG_FALSE;
        }

        logfile = para_log_checked_file(ogx, *next);
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }

        if (require_free) {
            if (logfile->ctrl->status == LOG_FILE_INACTIVE || logfile->ctrl->status == LOG_FILE_UNUSED) {
                return OG_TRUE;
            }

            continue;
        }

        return OG_TRUE;
    }
}

static bool32 para_log_pick_inactive_slot(knl_session_t *session, para_log_context_t *ogx, uint32 *next)
{
    log_file_t *file;

    if (!para_log_get_next_file(session, ogx, next, OG_TRUE, OG_TRUE)) {
        return OG_FALSE;
    }

    if (*next == ogx->curr_file || *next == ogx->active_file) {
        return OG_FALSE;
    }

    file = para_log_checked_file(ogx, *next);
    if (file->ctrl->status != LOG_FILE_INACTIVE && file->ctrl->status != LOG_FILE_UNUSED) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static void para_log_flush_head(para_log_context_t *ogx, log_file_t *file)
{
    char *log_head_buf = ogx->logwr_head_buf;
    if (file->ctrl->type == DEV_TYPE_ULOG) {
        OG_LOG_RUN_INF("NO need flush head for ulog %s.", file->ctrl->name);
        return;
    }

    log_calc_head_checksum(ogx->session, &file->head);

    /* since rebuild ctrlfiles was supported, the log file ctrl info was backup in the first block of log file. in
     * order not to overwrite it, we need to read it before write in flush log file head */
    int32 size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    if (cm_read_device(file->ctrl->type, file->handle, 0, log_head_buf, size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[LOG] failed to read %s ", file->ctrl->name);
        CM_ABORT(0, "[LOG] ABORT INFO: read redo head:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
                 sizeof(log_file_head_t));
    }

    *(log_file_head_t *)log_head_buf = file->head;

    size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    if (cm_write_device(file->ctrl->type, file->handle, 0, log_head_buf, size) != OG_SUCCESS) {
        OG_LOG_ALARM(WARN_FLUSHREDO, "'file-name':'%s'}", file->ctrl->name);
        CM_ABORT(0, "[LOG] ABORT INFO: flush redo file:%s, offset:%u, size:%lu failed.", file->ctrl->name, 0,
                 sizeof(log_file_head_t));
    }

    if (para_log_fredosync(file->ctrl->type, file->handle) != OG_SUCCESS) {
        OG_LOG_ALARM(WARN_FLUSHREDO, "'file-name':'%s'}", file->ctrl->name);
        CM_ABORT(0, "[LOG] ABORT INFO: fdatasync redo file head %s failed.", file->ctrl->name);
    }

    OG_LOG_DEBUG_INF("Flush log[%u] head with asn %u status %d rcy_off %llu", file->ctrl->file_id, file->head.asn,
                     file->ctrl->status, file->head.rcy_off);
}

void para_log_ckpt_flush_rcy_off(knl_session_t *session)
{
    uint64 rcy_lsn;
    uint32 group_count;
    uint32 i;

    if (session == NULL || session->kernel == NULL || !ENABLE_PARA_LOG_FLUSH(session)) {
        return;
    }

    rcy_lsn = dtc_my_ctrl(session)->rcy_point.lsn;
    if (rcy_lsn == 0) {
        return;
    }

    group_count = SYS_NUMA_GROUP_COUNT;
    for (i = 0; i < group_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];
        uint32 slot;
        uint32 nslot;

        if (ogx == NULL) {
            continue;
        }

        nslot = para_log_file_slot_count(ogx);
        cm_spin_lock(&ogx->b_flush_lock.lock, NULL);
        for (slot = 0; slot < nslot; slot++) {
            log_file_t *file = ogx->files[slot];
            uint64 hdr;
            uint64 wpos;
            uint64 last_lsn;

            if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg) ||
                file->head.asn == OG_INVALID_ASN) {
                continue;
            }

            hdr = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            wpos = file->head.write_pos;
            last_lsn = file->head.last_lsn;
            if (!para_log_lsn_in_commit_space(last_lsn, rcy_lsn) || wpos <= hdr) {
                continue;
            }

            if (file->head.rcy_off == wpos) {
                continue;
            }

            file->head.rcy_off = wpos;
            para_log_flush_head(ogx, file);
            OG_LOG_RUN_INF("[PARA LOG] ckpt rcy_off group=%u slot=%u file=%s rcy_off=%llu last_lsn=%llu "
                           "rcy_lsn=%llu status=%d",
                           i, slot, file->ctrl->name, file->head.rcy_off, last_lsn, rcy_lsn, file->ctrl->status);
        }
        cm_spin_unlock(&ogx->b_flush_lock.lock);
    }
}

static status_t para_log_check_active_log_asn(knl_session_t *session, para_log_context_t *ogx, uint32 *pre_asn)
{
    log_file_t *active_file;

    if (!para_log_file_slot_valid(ogx, ogx->active_file) || ogx->files[ogx->active_file] == NULL ||
        ogx->files[ogx->active_file]->ctrl == NULL) {
        OG_LOG_RUN_ERR("[LOG] para log group %u active file index %u is invalid, file_count %u",
                       ogx->thread_idx, ogx->active_file, ogx->log_file_idx);
        return OG_ERROR;
    }

    active_file = ogx->files[ogx->active_file];
    *pre_asn = active_file->head.asn;
    uint32 file_id = ogx->active_file;
    log_file_t *logfile = NULL;

    while (file_id != ogx->curr_file) {
        if (!para_log_file_slot_valid(ogx, file_id) || ogx->files[file_id] == NULL ||
            ogx->files[file_id]->ctrl == NULL) {
            OG_LOG_RUN_ERR("[LOG] para log group %u file index %u is invalid, file_count %u",
                           ogx->thread_idx, file_id, ogx->log_file_idx);
            return OG_ERROR;
        }

        logfile = ogx->files[file_id];
        if (logfile->ctrl->status == LOG_FILE_UNUSED) {
            (void)para_log_get_next_file(session, ogx, &file_id, OG_FALSE, OG_FALSE);
            continue;
        }

        if (logfile->head.asn == OG_INVALID_ASN) {
            OG_LOG_RUN_ERR("[LOG] asn of redo log %s is invalid", logfile->ctrl->name);
            return OG_ERROR;
        }

        if (file_id != ogx->active_file && *pre_asn != OG_INVALID_ASN && logfile->head.asn != *pre_asn + 1) {
            OG_LOG_RUN_ERR("[LOG] redo log asn are not continuous, %s asn: %u, previous log asn: %u",
                logfile->ctrl->name, logfile->head.asn, *pre_asn);
            return OG_ERROR;
        }

        *pre_asn = logfile->head.asn;
        (void)para_log_get_next_file(session, ogx, &file_id, OG_FALSE, OG_FALSE);
    }
    return OG_SUCCESS;
}

status_t para_log_check_asn(knl_session_t *session)
{
    uint32 group_count = SYS_NUMA_GROUP_COUNT;
    for (uint32 i = 0; i < group_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];
        log_file_t *logfile;

        if (ogx == NULL || ogx->log_file_idx == 0) {
            continue;
        }

        if (!para_log_file_slot_valid(ogx, ogx->curr_file) || ogx->files[ogx->curr_file] == NULL) {
            OG_LOG_RUN_ERR("[LOG] para log group %u current file index %u is invalid, file_count %u", i,
                           ogx->curr_file, ogx->log_file_idx);
            return OG_ERROR;
        }

        logfile = ogx->files[ogx->curr_file];
        if (logfile->ctrl == NULL) {
            OG_LOG_RUN_ERR("[LOG] para log group %u current file ctrl is null", i);
            return OG_ERROR;
        }

        if (logfile->ctrl->type == DEV_TYPE_ULOG) {
            continue;
        }

        /* Parallel redo has no log_batch_t; do not parse first-batch LFN. ckpt synth points use asn=0. */
        if (logfile->head.asn == OG_INVALID_ASN || logfile->ctrl->status != LOG_FILE_CURRENT) {
            OG_LOG_RUN_ERR("[LOG] para log group %u current file %s asn/status invalid, asn=%u status=%d", i,
                           logfile->ctrl->name, logfile->head.asn, logfile->ctrl->status);
            return OG_ERROR;
        }

        if (ogx->active_file == ogx->curr_file) {
            continue;
        }

        uint32 last_active_asn;
        if (para_log_check_active_log_asn(session, ogx, &last_active_asn) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (logfile->head.asn != last_active_asn + 1) {
            OG_LOG_RUN_ERR("[LOG] redo log asn are not continuous, %s asn: %u, previous log asn: %u",
                logfile->ctrl->name, logfile->head.asn, last_active_asn);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t para_log_fredosync(device_type_t type, int32 handle)
{
    if (type != DEV_TYPE_FILE) {
        return OG_SUCCESS;
    }

    return cm_fdatasync_file(handle);
}

bool32 para_log_need_flush(knl_session_t *session)
{
    uint32 cluster_count = SYS_NUMA_GROUP_COUNT;
    for (int i = 0; i < cluster_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];        
        if (ogx == NULL) {
            continue;
        }

        if (cm_atomic_barrier_read(&ogx->last_flushed_pos) !=
            cm_atomic_barrier_read((volatile uint64 *)&ogx->log_buf_ctx.ctl.struct128.curr_byte_pos)) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

void para_log_recycle_file(knl_session_t *session, uint32 group_id, log_point_t *point)
{
    para_log_context_t *ogx;
    arch_log_id_t last_arch_log;
    uint64 rcy_lsn;

    if (group_id >= CPU_SEG_MAX_NUM) {
        return;
    }

    ogx = session->kernel->para_log_ctx[group_id];
    if (ogx == NULL) {
        return;
    }

    if (point != NULL) {
        rcy_lsn = point->lsn;
    } else {
        rcy_lsn = dtc_my_ctrl(session)->rcy_point.lsn;
    }

    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    log_lock_logfile(session);
    uint32 file_id = ogx->active_file;
    while (file_id != ogx->curr_file) {
        log_file_t *file;
        bool32 can_recycle;

        if (!para_log_file_slot_valid(ogx, file_id)) {
            break;
        }

        file = ogx->files[file_id];
        if (file == NULL || file->ctrl == NULL) {
            break;
        }

        if (cm_dbs_is_enable_dbs() == OG_TRUE || !session->kernel->arch_ctx.is_archive) {
            can_recycle = OG_TRUE;
        } else if (last_arch_log.asn == OG_INVALID_ASN) {
            can_recycle = (file->head.asn == OG_INVALID_ASN) ? OG_TRUE : OG_FALSE;
        } else {
            can_recycle = (file->head.asn <= last_arch_log.asn) ? OG_TRUE : OG_FALSE;
        }

        if (!can_recycle) {
            break;
        }

        {
            uint64 max_lsn = ogx->file_max_lsn[file_id];
            uint64 commit_now = para_log_commit_now(session);

            /* Lamport last_lsn in the header inflates file_max_lsn beyond rcy reach. Switched-out files only contain flushed WAL. */
            if (!para_log_lsn_in_commit_space(max_lsn, commit_now)) {
                max_lsn = cm_atomic_barrier_read(&session->kernel->redo_ctx.flushed_lsn);
            }

            if (max_lsn > rcy_lsn) {
                OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA LOG] recycle blocked group=%u slot=%u file=%s max_lsn=%llu "
                                     "stored_max=%llu rcy_lsn=%llu",
                                     group_id, file_id, file->ctrl->name, max_lsn,
                                     ogx->file_max_lsn[file_id], rcy_lsn);
                break;
            }
        }

        OG_LOG_RUN_INF("[PARA LOG] recycle group=%u slot=%u file=%s asn=%u max_lsn=%llu rcy_lsn=%llu",
                       group_id, file_id, file->ctrl->name, file->head.asn, ogx->file_max_lsn[file_id], rcy_lsn);
        file->ctrl->status = LOG_FILE_INACTIVE;
        file->ctrl->archived = OG_FALSE;
        knl_begin_session_wait(session, LOG_RECYCLE, OG_FALSE);
        cm_latch_x(&file->latch, session->id, NULL);
        file->head.asn = OG_INVALID_ASN;
        file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        file->head.last_lsn = 0;
        file->head.first_lsn = 0;
        file->head.rcy_off = 0;
        ogx->file_max_lsn[file_id] = 0;
        file->arch_pos = 0;
        cm_unlatch(&file->latch, NULL);

        cm_atomic_add(&ogx->free_size, (int64)log_file_freesize(file));
        para_log_wake_space_waiters(ogx);
        (void)para_log_get_next_file(session, ogx, &file_id, OG_FALSE, OG_FALSE);
        if (!para_log_file_slot_valid(ogx, file_id) || ogx->files[file_id] == NULL ||
            ogx->files[file_id]->ctrl == NULL) {
            break;
        }

        knl_panic_log(ogx->files[file_id]->ctrl->status == LOG_FILE_ACTIVE ||
                      ogx->files[file_id]->ctrl->status == LOG_FILE_CURRENT,
                      "para log recycle set invalid active_file, panic info: group=%u slot=%u status=%u",
                      group_id, file_id, ogx->files[file_id]->ctrl->status);

        ogx->active_file = (uint16)file_id;
        dtc_my_ctrl(session)->para_log_first[group_id] = (uint32)file_id;
        ogx->dfx.recycle_cnt++;
        para_log_dfx_dump(session, ogx, "recycle");
        /* file_id is a group-local slot; db_save_log_ctrl needs the new active file's global logfile id. */
        if (db_save_log_ctrl(session, ogx->files[file_id]->ctrl->file_id, session->kernel->id) != OG_SUCCESS) {
            CM_ABORT(0, "[LOG] ABORT INFO: save core control file failed when recycling para log file");
        }
    }

    knl_end_session_wait(session, LOG_RECYCLE);
    log_unlock_logfile(session);
}

static void para_log_recycle_status_entry(volatile para_log_ins_status_ent_t *entry)
{
    int32 old_lrc;
    int32 next_lrc;

    old_lrc = (int32)cm_atomic32_get((atomic32_t *)&entry->lrc);
    next_lrc = get_log_buf_next_lrc(old_lrc, RD_STATUS_ENTRIES_POWER);
    (void)cm_atomic32_set((atomic32_t *)&entry->lrc, next_lrc);
    /* release: lrc before NOT_COPIED, plain STR on ARM cannot guarantee this order */
    para_log_status_store_release(entry, RD_NOT_COPIED);
}

static inline void para_log_wait_and_claim_slot(para_log_buf_ctx_t *buf_ctx,
    volatile para_log_ins_status_ent_t *entry, int32 curr_lrc, uint32 group_id, uint64 *spin_acc)
{
    uint32 power = RD_STATUS_ENTRIES_POWER;
    uint32 wait_times = 0;

    for (;;) {
        /* acquire-read status first: if already NOT_COPIED, subsequent lrc reads observe the ticket written by recycling. */
        uint8 status = para_log_status_load_acquire(entry);
        int32 entry_lrc;

        if (status == RD_COPIED) {
            if ((++wait_times & 0xFFF) == 1) {
                OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA LOG] slot wait COPIED group=%u lrc=%d entry_lrc=%d spins=%u",
                                     group_id, curr_lrc, (int32)cm_atomic32_get((atomic32_t *)&entry->lrc),
                                     wait_times);
            }

            if (spin_acc != NULL) {
                (*spin_acc)++;
            }

            cm_spin_sleep();
            continue;
        }

        entry_lrc = (int32)cm_atomic32_get((atomic32_t *)&entry->lrc);

        if (entry_lrc != 0) {
            knl_panic_log(is_log_buf_same_slot(entry_lrc, curr_lrc, power),
                "redo slot index mismatch, entry_lrc %d curr_lrc %d power %u", entry_lrc, curr_lrc, power);
            if (entry_lrc != curr_lrc) {
                if ((++wait_times & 0xFFF) == 1) {
                    OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                         "[PARA LOG] slot wait ticket group=%u lrc=%d entry_lrc=%d spins=%u",
                                         group_id, curr_lrc, entry_lrc, wait_times);
                }

                if (spin_acc != NULL) {
                    (*spin_acc)++;
                }

                cm_spin_sleep();
                continue;
            }
        }

        if (status != RD_NOT_COPIED) {
            cm_spin_sleep();
            continue;
        }

        (void)cm_atomic32_exchange((atomic32_t *)&entry->lrc, curr_lrc);
        return;
    }
}

static bool32 para_log_writer_alive(const para_log_context_t *ogx)
{
    return (bool32)(ogx != NULL && ogx->thread.id != 0 && !ogx->thread.closed);
}

static void para_log_kick_writer(para_log_context_t *ogx, bool32 new_req)
{
    if (ogx == NULL) {
        return;
    }

    if (new_req) {
        (void)cm_atomic_inc(&ogx->flush_req);
    }

    cm_futex_wake(&ogx->kick_futex, 1);
}

static status_t para_log_direct_flush_group(knl_session_t *session, para_log_context_t *ogx, uint32 group_id)
{
    status_t flush_ret;

    cm_spin_lock(&ogx->b_flush_lock.lock, &session->stat->spin_stat.stat_log_flush);
    flush_ret = para_log_flush_by_numa(session, group_id);
    cm_spin_unlock(&ogx->b_flush_lock.lock);
    para_log_wait_if_switch_blocked(session, ogx);
    para_log_persist_ctrl_if_dirty(session, ogx);
    para_log_dfx_dump_due(session, ogx);

    return flush_ret;
}

status_t para_log_self_flush(knl_session_t *session, log_point_t *point, knl_scn_t *scn, uint64 *lsn)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    status_t result = OG_SUCCESS;
    uint32 group_count = SYS_NUMA_GROUP_COUNT;
    uint64 target_lsn;
    uint32 wait_loops = 0;
    bool32 any_writer = OG_FALSE;
    date_t wait_begin;

    target_lsn = para_log_commit_now(session);
    wait_begin = cm_now();

    for (uint32 i = 0; i < group_count; i++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[i];
        status_t flush_ret;

        if (ogx == NULL) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] self_flush skip uninitialized group=%u", i);
            continue;
        }

        if (para_log_writer_alive(ogx)) {
            para_log_kick_writer(ogx, OG_TRUE);
            any_writer = OG_TRUE;
            continue;
        }

        flush_ret = para_log_direct_flush_group(session, ogx, i);
        if (flush_ret != OG_SUCCESS) {
            result = flush_ret;
        }
    }

    while (cm_atomic_barrier_read(&redo_ctx->flushed_lsn) < target_lsn) {
        bool32 alive = OG_FALSE;
        para_log_context_t *wait_ogx = NULL;

        for (uint32 i = 0; i < group_count; i++) {
            para_log_context_t *ogx = session->kernel->para_log_ctx[i];
            status_t flush_ret;

            if (ogx == NULL) {
                continue;
            }

            if (para_log_writer_alive(ogx)) {
                alive = OG_TRUE;
                if (wait_ogx == NULL) {
                    wait_ogx = ogx;
                }

                para_log_kick_writer(ogx, OG_FALSE);
            } else {
                flush_ret = para_log_direct_flush_group(session, ogx, i);
                if (flush_ret != OG_SUCCESS) {
                    result = flush_ret;
                }
            }
        }

        if (!alive) {
            break;
        }

        if (para_log_wait_timed_out(wait_begin)) {
            CM_ABORT(0, "[PARA LOG] ABORT INFO: self_flush wait timeout, target=%llu flushed=%llu",
                     target_lsn, cm_atomic_barrier_read(&redo_ctx->flushed_lsn));
        }

        if ((++wait_loops & 0x3F) == 1) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] self_flush wait target=%llu flushed=%llu writers=%u",
                                 target_lsn, cm_atomic_barrier_read(&redo_ctx->flushed_lsn), (uint32)any_writer);
        }

        if (wait_ogx != NULL) {
            (void)cm_futex_wait(&wait_ogx->ack_futex, 5);
        } else {
            cm_spin_sleep_ex(1000);
        }
    }

    // return global progress (parallel safe point = redo_ctx.flushed_lsn), not per-group ogx->curr_point (unmaintained)
    if (point != NULL) {
        point->asn = 0;
        point->block_id = 0;
        point->rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
        point->lfn = cm_atomic_barrier_read(&redo_ctx->flushed_lfn);
        point->lsn = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);
    }

    if (scn != NULL) {
        *scn = redo_ctx->curr_scn;
    }

    if (lsn != NULL) {
        *lsn = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);
    }

    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                         "[PARA LOG] self_flush flushed_lsn=%llu flushed_lfn=%llu scn=%llu target=%llu signal=%u",
                         cm_atomic_barrier_read(&redo_ctx->flushed_lsn),
                         cm_atomic_barrier_read(&redo_ctx->flushed_lfn), (uint64)redo_ctx->curr_scn,
                         target_lsn, (uint32)any_writer);

    return result;
}

/**
 * @brief Write WAL data to disk (single write, length is aligned_size)
 */
static inline status_t para_log_flush_write_aligned(
    para_log_context_t *ogx,
    log_file_t *file,
    const char *buf,
    uint64 batch_lsn,
    uint64 file_pos,
    uint32 data_size,
    uint32 aligned_size
)
{
    if (cm_write_device(file->ctrl->type, file->handle, (int64)file_pos, buf, aligned_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    file->head.write_pos += aligned_size;
    ogx->file_write_pos = file->head.write_pos;
    if (file->head.first == OG_INVALID_ID64) {
        para_log_flush_head(ogx, file);
    }
    cm_atomic_sub(&ogx->free_size, (int64)aligned_size);
    return OG_SUCCESS;
}

static inline status_t para_log_flush_stash_buf(para_log_context_t *ogx, para_log_buf_ctx_t *buf_ctx,
    uint64 start_flush_pos, uint64 end_log_pos, uint32 data_size, uint32 aligned_size)
{
    char *staging = ogx->flush_buf;
    uint64 first_part;
    uint64 second_part;
    errno_t ret;

    knl_panic_log(staging != NULL && aligned_size <= ogx->flush_buf_size,
        "invalid numa flush staging buf, aligned_size %u capacity %llu",
        aligned_size, ogx->flush_buf_size);

    if (end_log_pos > start_flush_pos) {
        ret = memcpy_sp(staging, (size_t)ogx->flush_buf_size,
            buf_ctx->buffer + start_flush_pos, data_size);
        knl_securec_check(ret);
    } else {
        first_part = buf_ctx->buffer_size - start_flush_pos;
        second_part = data_size - first_part;
        if (first_part > 0) {
            ret = memcpy_sp(staging, (size_t)ogx->flush_buf_size,
                buf_ctx->buffer + start_flush_pos, (size_t)first_part);
            knl_securec_check(ret);
        }
        ret = memcpy_sp(staging + first_part, (size_t)ogx->flush_buf_size - (size_t)first_part,
            buf_ctx->buffer, (size_t)second_part);
        knl_securec_check(ret);
    }

    if (aligned_size > data_size) {
        ret = memset_sp(staging + data_size, (size_t)(ogx->flush_buf_size - data_size),
            0, aligned_size - data_size);
        knl_securec_check(ret);
    }
    return OG_SUCCESS;
}

static status_t para_log_flush_to_disk(para_log_context_t *ogx, log_file_t *file, para_log_buf_ctx_t *buf_ctx, uint64 batch_lsn,
    uint64 file_pos, uint64 start_flush_pos, uint64 end_log_pos, uint32 data_size, uint32 aligned_size)
{
    uint64 direct_buf_addr = (uint64)(uintptr_t)(buf_ctx->buffer + start_flush_pos);
    if (end_log_pos > start_flush_pos && aligned_size == data_size &&
        ((file_pos & (file->ctrl->block_size - 1)) == 0) &&
        ((direct_buf_addr & (file->ctrl->block_size - 1)) == 0)) {
        return para_log_flush_write_aligned(ogx, file, buf_ctx->buffer + start_flush_pos, batch_lsn, file_pos,
            data_size, aligned_size);
    }

    if (para_log_flush_stash_buf(ogx, buf_ctx, start_flush_pos, end_log_pos, data_size,
        aligned_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return para_log_flush_write_aligned(ogx, file, ogx->flush_buf, batch_lsn, file_pos, data_size,
        aligned_size);
}

static void para_log_flush_bitmap_check(para_log_flush_lsn_bitmap_t *bm, uint64 new_base)
{
    uint64 old_base;
    uint64 max_marked;
    int64 offset;
    uint64 active_start_off;
    uint64 active_end_off;
    uint64 start_word;
    uint64 end_word;
    uint64 move_words;
    uint64 bit_offset;
    uint64 old_seq;
    uint64 expected_seq;

    // writer mutual exclusion: serialize with mark-OR, avoid memmove and atomic OR misalignment creating stray bits
    cm_spin_lock(&bm->lock, NULL);

    // seq+1 turns odd: prevents scan readers from adopting torn data during this memmove
    old_seq = para_log_u64_load(&bm->seq);
    if (old_seq & 1) {
        cm_spin_unlock(&bm->lock);
        return;
    }
    expected_seq = old_seq;
    if (!para_log_u64_cas(&bm->seq, &expected_seq, old_seq + 1)) {
        cm_spin_unlock(&bm->lock);
        return;
    }

    // inside the lock, no concurrent mark-OR, safe to memmove
    old_base = para_log_u64_load(&bm->base_lsn);
    max_marked = para_log_u64_load(&bm->max_marked_lsn);
    offset = (int64)(new_base - old_base);

    if (offset <= 0) {
        (void)para_log_u64_add(&bm->seq, 1);
        cm_spin_unlock(&bm->lock);
        return;
    }

    /*
     * If all marked LSNs are before new_base, or new_base jumps over a full window,
     * simply clear bitmap and restart window from new_base.
     */
    if (max_marked < new_base || offset >= (int64)LOG_FLUSH_BITMAP_WINDOW_SIZE) {
        errno_t ret = memset_sp((void *)bm->bitmap, sizeof(bm->bitmap), 0, sizeof(bm->bitmap));
        knl_securec_check(ret);
        para_log_u64_store(&bm->base_lsn, new_base);
        if (para_log_u64_load(&bm->max_marked_lsn) < new_base) {
            para_log_u64_store(&bm->max_marked_lsn, new_base);
        }

        (void)para_log_u64_add(&bm->seq, 1);
        cm_spin_unlock(&bm->lock);
        OG_LOG_RUN_INF("[PARA LOG] bitmap reset old_base=%llu new_base=%llu max_marked=%llu offset=%lld",
                       old_base, new_base, max_marked, offset);
        return;
    }

    /*
     * Move only the active range [new_base, max_marked], instead of moving
     * almost a full window every slide.
     */
    active_start_off = (uint64)offset;
    active_end_off = max_marked - old_base;
    if (active_end_off >= LOG_FLUSH_BITMAP_WINDOW_SIZE) {
        active_end_off = LOG_FLUSH_BITMAP_WINDOW_SIZE - 1;
    }

    start_word = active_start_off >> LOG_FLUSH_BITMAP_WORD_SHIFT;
    end_word = active_end_off >> LOG_FLUSH_BITMAP_WORD_SHIFT;
    move_words = end_word - start_word + 1;
    bit_offset = active_start_off & LOG_FLUSH_BITMAP_WORD_MASK;

    if (bit_offset == 0) {
        /* when aligned to a 64-bit word, the whole block can be moved directly. */
        errno_t mem_ret = memmove_s((void *)bm->bitmap, sizeof(bm->bitmap),
                                    (const void *)(bm->bitmap + start_word),
                                    move_words * sizeof(uint64));
        knl_securec_check(mem_ret);
    } else {
        /* when not word-aligned, rebuild the target word via "low bits right-shifted + high bits filled in". */
        for (uint64 i = 0; i < move_words; i++) {
            uint64 src_idx = start_word + i;
            uint64 low_bits = bm->bitmap[src_idx] >> bit_offset;
            uint64 high_bits = 0;
            if (src_idx + 1 <= end_word) {
                high_bits = bm->bitmap[src_idx + 1] << (64 - bit_offset);
            }
            bm->bitmap[i] = low_bits | high_bits;
        }
    }

    /* Clear tail outside the moved active range. */
    if (move_words < LOG_FLUSH_BITMAP_WORDS) {
        errno_t tail_ret = memset_sp((void *)(bm->bitmap + move_words),
                                      sizeof(bm->bitmap) - move_words * sizeof(uint64),
                                      0, (LOG_FLUSH_BITMAP_WORDS - move_words) * sizeof(uint64));
        knl_securec_check(tail_ret);
    }

    para_log_u64_store(&bm->base_lsn, new_base);
    (void)para_log_u64_add(&bm->seq, 1);
    cm_spin_unlock(&bm->lock);
    OG_LOG_RUN_INF("[PARA LOG] bitmap slide old_base=%llu new_base=%llu max_marked=%llu move_words=%llu bit_off=%llu",
                   old_base, new_base, max_marked, move_words, bit_offset);
}

static inline void para_log_atomic_or_u64(volatile uint64 *ptr, uint64 mask)
{
    uint64 oldv;
    uint64 newv;
    do {
        oldv = para_log_u64_load(ptr);
        newv = oldv | mask;
        if (newv == oldv) {
            return;
        }
    } while (!para_log_u64_cas(ptr, &oldv, newv));
}

static inline void para_log_update_max_marked_lsn(para_log_flush_lsn_bitmap_t *bm, uint64 local_max_lsn)
{
    uint64 old_max;
    for (;;) {
        old_max = para_log_u64_load(&bm->max_marked_lsn);
        if (local_max_lsn <= old_max) {
            break;
        }

        if (para_log_u64_cas(&bm->max_marked_lsn, &old_max, local_max_lsn)) {
            break;
        }
    }
}

static inline void para_log_atomic_max_u64(volatile uint64 *ptr, uint64 value)
{
    uint64 oldv;
    for (;;) {
        oldv = para_log_u64_load(ptr);
        if (value <= oldv) {
            return;
        }

        if (para_log_u64_cas(ptr, &oldv, value)) {
            return;
        }
    }
}

static inline uint64 para_log_scan_contiguous_lsn(para_log_flush_lsn_bitmap_t *bm, uint64 old_flushed)
{
    uint64 base;
    uint64 next;
    uint64 offset;
    uint64 word_idx;
    uint64 bit_idx;
    uint64 word;
    uint64 mask;
    uint64 step;
    uint64 seq1;
    uint64 seq2;

    for (;;) {
        seq1 = para_log_u64_load(&bm->seq);
        if (seq1 & 1) {
            CM_RELEASE_CPU;
            continue;
        }

        base = para_log_u64_load(&bm->base_lsn);
        next = old_flushed + 1;
        if (next < base) {
            next = base;
        }
        offset = next - base;

        while (offset < LOG_FLUSH_BITMAP_WINDOW_SIZE) {
            word_idx = offset >> LOG_FLUSH_BITMAP_WORD_SHIFT;
            bit_idx = offset & LOG_FLUSH_BITMAP_WORD_MASK;
            word = para_log_u64_load(&bm->bitmap[word_idx]);

            if (bit_idx == 0 && word == UINT64_MAX) {
                next += 64;
                offset += 64;
                continue;
            }

            mask = UINT64_MAX << bit_idx;
            if ((word & mask) == mask) {
                step = 64 - bit_idx;
                next += step;
                offset += step;
                continue;
            }

            while (bit_idx < 64 && (word & (1ULL << bit_idx)) != 0) {
                next++;
                offset++;
                bit_idx++;
            }
            break;
        }

        CM_MFENCE;
        seq2 = para_log_u64_load(&bm->seq);
        if (seq1 == seq2 && !(seq2 & 1)) {
            return next -  1;
        }
    }
}

// advance flushed_lsn: CAS monotonic, forward only, concurrent lgwr will not regress
static inline void para_log_advance_lsn(knl_session_t *session)
{
    para_log_flush_lsn_bitmap_t *bm = para_log_bitmap_of(session);
    uint64 old_flushed;
    uint64 new_flushed;

    knl_panic_log(bm != NULL, "para log bitmap is not initialized");

    for (;;) {
        old_flushed = para_log_u64_load(&bm->flushed_lsn);
        new_flushed = para_log_scan_contiguous_lsn(bm, old_flushed);
        if (new_flushed <= old_flushed) {
            uint64 max_marked = para_log_u64_load(&bm->max_marked_lsn);
            uint64 base = para_log_u64_load(&bm->base_lsn);

            if (max_marked > old_flushed + 1) {
                OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA LOG] flushed prefix hole flushed=%llu max_marked=%llu base=%llu gap=%llu",
                                     old_flushed, max_marked, base,
                                     (max_marked > old_flushed) ? (max_marked - old_flushed) : 0);
            }

            /* slide the window even when the prefix is stalled, otherwise occupancy stays at the backpressure line and writers wait for lgwr to raise flushed, causing self-deadlock */
            if (old_flushed > base && (old_flushed - base) >= LOG_FLUSH_BITMAP_SLIDE_SIZE) {
                para_log_flush_bitmap_check(bm, old_flushed);
            }

            return;
        }

        if (para_log_u64_cas(&bm->flushed_lsn, &old_flushed, new_flushed)) {
            break;
        }
        // CAS failed (changed by another lgwr), re-read and rescan
    }

    // global flushed_lsn also advances monotonically (commit wait reads this)
    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->redo_ctx.flushed_lsn, new_flushed);
    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->redo_ctx.flushed_lfn, new_flushed);
    knl_scn_t prefix_scn = db_next_scn(session);
    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->redo_ctx.curr_scn, (uint64)prefix_scn);

    {
        uint64 base = para_log_u64_load(&bm->base_lsn);

        if (new_flushed > base && (new_flushed - base) >= LOG_FLUSH_BITMAP_SLIDE_SIZE) {
            para_log_flush_bitmap_check(bm, new_flushed);
        }
    }
}

// batch-mark LSNs as flushed by entry range (one max update per pass + word-aggregated atomic OR)
static inline void para_log_mark_lsn_batch_flushed(knl_session_t *session, uint32 numa_id,
    para_log_buf_ctx_t *buf_ctx, int32 start_entry_idx, int32 end_entry_idx)
{
    para_log_flush_lsn_bitmap_t *bm = para_log_bitmap_of(session);
    uint64 base_lsn;
    uint64 cache_word_idx[OG_LOG_FLUSH_WORD_CACHE_SIZE];
    uint64 cache_word_mask[OG_LOG_FLUSH_WORD_CACHE_SIZE];
    uint64 pass_max_lsn;
    uint64 curr_base;
    uint64 curr_flushed;
    int32 pending_entry_idx = start_entry_idx;
    uint32 spin_retry = 0;
    bool32 reached_end;
    bool32 blocked_by_window;
    bool32 has_pass_mark;

    (void)numa_id;  // mark_count removed, numa_id kept for API compatibility

    knl_panic_log(bm != NULL, "para log bitmap is not initialized");

    if (start_entry_idx < 0) {
        return;
    }

    for (;;) {
        // writer mutual exclusion: serialize with sliding memmove, base is stable inside the lock, OR will not misalign on a stale base and create stray bits
        cm_spin_lock(&bm->lock, NULL);
        base_lsn = para_log_u64_load(&bm->base_lsn);

        for (uint32 i = 0; i < OG_LOG_FLUSH_WORD_CACHE_SIZE; i++) {
            cache_word_idx[i] = UINT64_MAX;
            cache_word_mask[i] = 0;
        }

        reached_end = OG_FALSE;
        blocked_by_window = OG_FALSE;
        has_pass_mark = OG_FALSE;
        pass_max_lsn = 0;
        int32 entry_idx = pending_entry_idx;
        for (;;) {
            int32 idx = get_status_entry_index(RD_STATUS_ENTRIES_POWER, entry_idx);
            volatile para_log_ins_status_ent_t *entry_ptr = &buf_ctx->status_table[idx];
            uint64 entry_lsn = entry_ptr->lsn;
            int64 offset = (int64)(entry_lsn - base_lsn);

            if (offset < 0) {
                // already on the left side of the window, meaning this LSN is covered by the window advance, process the next entry directly.
            } else if (offset >= (int64)LOG_FLUSH_BITMAP_WINDOW_SIZE) {
                // beyond the right side of the window: cannot skip, stay on the current entry and retry after the window slides forward.
                blocked_by_window = OG_TRUE;
                pending_entry_idx = entry_idx;
                break;
            } else {
                uint64 word_idx = (uint64)offset >> LOG_FLUSH_BITMAP_WORD_SHIFT;
                uint64 bit_idx = (uint64)offset & LOG_FLUSH_BITMAP_WORD_MASK;
                uint64 mask = (1ULL << bit_idx);
                uint64 slot = word_idx & (OG_LOG_FLUSH_WORD_CACHE_SIZE - 1);

                if (cache_word_idx[slot] == word_idx) {
                    cache_word_mask[slot] |= mask;
                } else {
                    if (cache_word_idx[slot] != UINT64_MAX && cache_word_mask[slot] != 0) {
                        para_log_atomic_or_u64(&bm->bitmap[cache_word_idx[slot]], cache_word_mask[slot]);
                    }
                    cache_word_idx[slot] = word_idx;
                    cache_word_mask[slot] = mask;
                }

                has_pass_mark = OG_TRUE;
                pass_max_lsn = (entry_lsn > pass_max_lsn) ? entry_lsn : pass_max_lsn;
            }

            if (entry_idx == end_entry_idx) {
                reached_end = OG_TRUE;
                break;
            }
            entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, entry_idx);
        }

        for (uint32 i = 0; i < OG_LOG_FLUSH_WORD_CACHE_SIZE; i++) {
            if (cache_word_idx[i] != UINT64_MAX && cache_word_mask[i] != 0) {
                para_log_atomic_or_u64(&bm->bitmap[cache_word_idx[i]], cache_word_mask[i]);
            }
        }

        // update max_marked_lsn inside the lock: mutually exclusive with sliding memmove, the bit just OR-ed will not be cleared by the tail memset
        if (has_pass_mark) {
            para_log_update_max_marked_lsn(bm, pass_max_lsn);
        }

        cm_spin_unlock(&bm->lock);

        if (reached_end) {
            return;
        }

        if (blocked_by_window) {
            para_log_advance_lsn(session);
            curr_base = para_log_u64_load(&bm->base_lsn);
            curr_flushed = para_log_u64_load(&bm->flushed_lsn);
            if (curr_flushed > curr_base) {
                para_log_flush_bitmap_check(bm, curr_flushed);
            }

            if ((++spin_retry & 0x3F) == 0) {
                para_log_context_t *ogx = session->kernel->para_log_ctx[numa_id];
                if (ogx != NULL) {
                    ogx->dfx.bitmap_block++;
                }
                OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA LOG] bitmap mark blocked group=%u entry_idx=%d base=%llu flushed=%llu",
                                     numa_id, pending_entry_idx, curr_base, curr_flushed);
                cm_spin_sleep();
            } else {
                CM_RELEASE_CPU;
            }
            continue;
        }
    }
}

static void para_log_fix_curr_by_asn(knl_session_t *session, para_log_context_t *ogx)
{
    uint32 i;
    uint32 best_slot = OG_INVALID_ID32;
    uint32 best_asn = 0;
    uint32 ctrl_last;
    log_file_t *file;
    log_file_t *old_file;

    if (ogx == NULL) {
        return;
    }

    ctrl_last = ogx->curr_file;
    for (i = 0; i < para_log_file_slot_count(ogx); i++) {
        file = ogx->files[i];
        if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (file->head.asn == OG_INVALID_ASN) {
            continue;
        }

        if (best_slot == OG_INVALID_ID32 || file->head.asn > best_asn) {
            best_asn = file->head.asn;
            best_slot = i;
        }
    }

    if (best_slot == OG_INVALID_ID32 || best_slot == ctrl_last) {
        return;
    }

    file = ogx->files[best_slot];
    OG_LOG_RUN_INF("[PARA LOG] load recover curr by asn group=%u ctrl_last=%u new_curr=%u new_asn=%u",
                   ogx->thread_idx, ctrl_last, best_slot, best_asn);

    if (para_log_file_slot_valid(ogx, ctrl_last)) {
        old_file = ogx->files[ctrl_last];
        if (old_file != NULL && old_file->ctrl != NULL && old_file->head.asn != OG_INVALID_ASN) {
            old_file->ctrl->status = LOG_FILE_ACTIVE;
        }
    }

    ogx->curr_file = (uint16)best_slot;
    file->ctrl->status = LOG_FILE_CURRENT;
    dtc_my_ctrl(session)->para_log_last[ogx->thread_idx] = best_slot;
    (void)cm_atomic32_set(&ogx->ctrl_dirty, 1);
}

static void para_log_persist_ctrl_if_dirty(knl_session_t *session, para_log_context_t *ogx)
{
    log_file_t *file;
    uint32 slot;
    uint32 file_id;

    if (ogx == NULL || session == NULL) {
        return;
    }

    while (cm_atomic32_cas(&ogx->ctrl_dirty, 1, 0)) {
        slot = ogx->curr_file;
        if (!para_log_file_slot_valid(ogx, slot) || ogx->files[slot] == NULL || ogx->files[slot]->ctrl == NULL) {
            return;
        }

        file = ogx->files[slot];
        file_id = (uint32)file->ctrl->file_id;
        if (db_save_log_ctrl(session, file_id, session->kernel->id) != OG_SUCCESS) {
            (void)cm_atomic32_set(&ogx->ctrl_dirty, 1);
            OG_LOG_RUN_ERR("[PARA LOG] deferred ctrl save failed group=%u slot=%u file_id=%u",
                           ogx->thread_idx, slot, file_id);
            return;
        }

        OG_LOG_RUN_INF("[PARA LOG] deferred ctrl save group=%u slot=%u file_id=%u asn=%u",
                       ogx->thread_idx, slot, file_id, file->head.asn);
    }
}

static status_t para_log_switch_file(knl_session_t *session, para_log_context_t *ogx)
{
    reset_log_t resetlog = session->kernel->db.ctrl.core.resetlogs;
    uint32 next;
    uint32 old_slot;
    uint64 old_pos;
    log_file_t *curr_file = NULL;

    if (!para_log_pick_inactive_slot(session, ogx, &next)) {
        return OG_ERROR;
    }

    knl_panic_log((next != ogx->active_file) && (next != ogx->curr_file),
                  "failed to switch log file, current file is %d, active file is %d, next is %u, log free size is %llu",
                  ogx->curr_file, ogx->active_file, next, cm_atomic_get(&ogx->free_size));

    curr_file = para_log_checked_file(ogx, ogx->curr_file);
    old_slot = ogx->curr_file;
    old_pos = curr_file->head.write_pos;
    curr_file->ctrl->status = LOG_FILE_ACTIVE;
    log_flush_head(session, curr_file);  // flush last_lsn before file switch, for file_max_lsn recovery on restart
    uint32 asn = curr_file->head.asn;
    uint32 rst_id = (curr_file->head.asn == resetlog.last_asn) ? (resetlog.rst_id) : curr_file->head.rst_id;
    ogx->curr_file = next;

    log_file_t *next_file = para_log_checked_file(ogx, next);
    next_file->arch_pos = 0;
    next_file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), next_file->ctrl->block_size);
    next_file->head.block_size = next_file->ctrl->block_size;
    next_file->head.rst_id = rst_id;
    next_file->head.asn = asn + 1;
    next_file->head.first = OG_INVALID_ID64;
    next_file->head.first_lsn = 0;
    next_file->head.last_lsn = 0;
    next_file->head.rcy_off = 0;
    next_file->head.cmp_algorithm = COMPRESS_NONE;
    if (para_log_file_slot_valid(ogx, next)) {
        ogx->file_max_lsn[next] = 0;
    }

    ogx->file_write_pos = next_file->head.write_pos;
    next_file->ctrl->status = LOG_FILE_CURRENT;
    next_file->ctrl->archived = OG_FALSE;
    log_flush_head(session, next_file);

    dtc_my_ctrl(session)->para_log_last[ogx->thread_idx] = ogx->curr_file;
    (void)cm_atomic32_set(&ogx->ctrl_dirty, 1);
    ogx->stat.switch_count++;
    ogx->dfx.switch_cnt++;

    para_log_rebuild_free_size(ogx);
    para_log_wake_space_waiters(ogx);

    OG_LOG_RUN_INF("[PARA LOG] switch group=%u old_slot=%u old_file=%s old_asn=%u old_pos=%llu "
                   "new_slot=%u new_file=%s new_asn=%u active=%u free=%lld",
                   ogx->thread_idx, old_slot, curr_file->ctrl->name, asn, old_pos, next, next_file->ctrl->name,
                   next_file->head.asn, ogx->active_file, (int64)cm_atomic_get(&ogx->free_size));
    para_log_dfx_dump(session, ogx, "switch");

    return OG_SUCCESS;
}

static status_t para_log_flush_init(knl_session_t *session, para_log_context_t *ogx, uint32 batch_size_input)
{
    uint32 batch_size = batch_size_input;
    log_file_t *file = para_log_checked_file(ogx, ogx->curr_file);
    uint64 curr_free;
    uint64 keep;
    uint64 file_size;
    bool32 need_switch = OG_FALSE;

    if (file->ctrl->type == DEV_TYPE_ULOG) {
        batch_size = cm_align_device_size(file->ctrl->type, batch_size);
    }

    para_log_maybe_kick_ckpt(session, ogx);

    curr_free = log_file_freesize(file);
    keep = para_log_keep_size(session, ogx);
    file_size = para_log_file_capacity(ogx);
    if (curr_free < batch_size) {
        need_switch = OG_TRUE;
    } else if (keep < file_size && curr_free <= keep && para_log_has_inactive_slot(ogx)) {
        /* CURRENT tail no longer meets KEEP but INACTIVE files remain: switch proactively to avoid business stalling in log_atomic_op_begin */
        need_switch = OG_TRUE;
    }

    if (!need_switch) {
        ogx->switch_wait_begin = 0;
        (void)cm_atomic32_set(&ogx->switch_blocked, 0);
        return OG_SUCCESS;
    }

    log_flush_head(session, file);

    if (para_log_switch_file(session, ogx) != OG_SUCCESS) {
        date_t now = cm_now();

        if (ogx->switch_wait_begin == 0) {
            ogx->switch_wait_begin = now;
        } else if ((now - ogx->switch_wait_begin) >= PARA_LOG_SWITCH_WAIT_TIMEOUT) {
            CM_ABORT(0, "[PARA LOG] ABORT INFO: switch wait recycle timeout group=%u curr=%u active=%u free=%lld",
                     ogx->thread_idx, ogx->curr_file, ogx->active_file, (int64)cm_atomic_get(&ogx->free_size));
        }

        (void)cm_atomic32_set(&ogx->switch_blocked, 1);
        ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
        OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                             "[PARA LOG] switch blocked group=%u curr=%u active=%u free=%lld, wait recycle",
                             ogx->thread_idx, ogx->curr_file, ogx->active_file,
                             (int64)cm_atomic_get(&ogx->free_size));
        return OG_ERROR;
    }

    ogx->switch_wait_begin = 0;
    (void)cm_atomic32_set(&ogx->switch_blocked, 0);
    ogx->stat.space_requests++;

    file = para_log_checked_file(ogx, ogx->curr_file);
    knl_panic_log(log_file_freesize(file) >= batch_size, "the log_file_freesize is smaller than batch_size, "
                  "panic info: freesize %llu batch_size %u", log_file_freesize(file), batch_size);
    return OG_SUCCESS;
}

status_t para_log_flush_by_numa(knl_session_t *session, uint32 numa_id)
{
    para_log_context_t *ogx = session->kernel->para_log_ctx[numa_id];

    if (!session->kernel->para_log_init) {
        return OG_SUCCESS;
    }
    
    para_log_buf_ctx_t *buf_ctx = &ogx->log_buf_ctx;
    
    int32 start_entry_idx;
    int32 curr_entry_idx;
    int32 next_entry_idx;
    volatile para_log_ins_status_ent_t *start_entry_ptr = NULL;
    volatile para_log_ins_status_ent_t *curr_entry_ptr = NULL;
    volatile para_log_ins_status_ent_t *next_entry_ptr = NULL;

    start_entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, 
                                             ogx->last_flushed_entry);
    start_entry_ptr = &buf_ctx->status_table[start_entry_idx];

    if (para_log_status_load_acquire(start_entry_ptr) != RD_COPIED) {
        ogx->dfx.empty_poll++;
        return OG_SUCCESS;
    }

    next_entry_idx = start_entry_idx;
    next_entry_ptr = start_entry_ptr;
    curr_entry_idx = start_entry_idx;
    curr_entry_ptr = start_entry_ptr;
    uint64 batch_lsn = cm_atomic_barrier_read(&start_entry_ptr->lsn);
    int32 ring_size = get_log_buf_ring_size(RD_STATUS_ENTRIES_POWER);
    uint32 scanned = 1;

    for (;;) {
        next_entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, curr_entry_idx);
        next_entry_ptr = &buf_ctx->status_table[next_entry_idx];

        if (next_entry_idx == start_entry_idx) {
            break;
        }

        /* acquire-read COPIED first then read lrc/lsn, to avoid seeing new lrc with stale status on ARM. */
        if (para_log_status_load_acquire(next_entry_ptr) != RD_COPIED) {
            break;
        }

        if (((cm_atomic32_get((atomic32_t *)&curr_entry_ptr->lrc) + 1) & 0x7FFFFFFF) !=
            cm_atomic32_get((atomic32_t *)&next_entry_ptr->lrc)) {
            break;
        }

        scanned++;
        knl_panic_log(scanned <= (uint32)ring_size,
                      "para log flush scan wrapped status ring, panic info: group=%u start=%d scanned=%u",
                      numa_id, start_entry_idx, scanned);

        curr_entry_ptr = next_entry_ptr;
        curr_entry_idx = next_entry_idx;
        {
            uint64 next_lsn = cm_atomic_barrier_read(&curr_entry_ptr->lsn);
            batch_lsn = batch_lsn >= next_lsn ? batch_lsn : next_lsn;
        }
    }

    uint64 end_log_pos = cm_atomic_barrier_read(&curr_entry_ptr->end_log_pos);
    uint64 start_flush_pos = cm_atomic_barrier_read(&ogx->last_flushed_pos);
    
    if (start_flush_pos == end_log_pos) {
        ogx->dfx.empty_poll++;
        return OG_SUCCESS;
    }
    
    uint32 data_size;
    if (end_log_pos > start_flush_pos) {
        data_size = (uint32)(end_log_pos - start_flush_pos);
    } else {
        data_size = (uint32)(buf_ctx->buffer_size - start_flush_pos + end_log_pos);
    }

    if (para_log_flush_init(session, ogx, data_size) != OG_SUCCESS) {
        return OG_SUCCESS;
    }
    /* ensure data size is aligned to block_size; curr_file may have changed after a file switch, must re-validate. */
    log_file_t *file = para_log_checked_file(ogx, ogx->curr_file);
    uint32 aligned_size = CM_CALC_ALIGN(data_size, file->ctrl->block_size);
    uint64 current_file_pos = file->head.write_pos;
    {
        uint64 commit_now = para_log_commit_now(session);

        if (!para_log_lsn_in_commit_space(file->head.last_lsn, commit_now) || file->head.last_lsn < batch_lsn) {
            file->head.last_lsn = batch_lsn;
        }
    }

    if (file->head.first_lsn == 0) {
        file->head.first_lsn = batch_lsn;
    }

    uint64 scn = db_next_scn(session);
    if (para_log_flush_to_disk(ogx, file, buf_ctx, batch_lsn, current_file_pos, start_flush_pos, end_log_pos,
        data_size, aligned_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PARA LOG] flush write failed group=%u file=%s pos=%llu size=%u aligned=%u "
                       "batch_lsn=%llu start_pos=%llu end_pos=%llu",
                       numa_id, file->ctrl->name, current_file_pos, data_size, aligned_size, batch_lsn,
                       start_flush_pos, end_log_pos);
        CM_ABORT(0, "[PARA LOG] ABORT INFO: log_flush_by_numa write failed.");
        return OG_ERROR;
    }

    if (file->ctrl->type != DEV_TYPE_ULOG &&
        para_log_fredosync(file->ctrl->type, file->handle) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PARA LOG] flush fdatasync failed group=%u file=%s pos=%llu size=%u",
                       numa_id, file->ctrl->name, current_file_pos, aligned_size);
        CM_ABORT(0, "[PARA LOG] ABORT INFO: log_flush_by_numa fdatasync failed.");
        return OG_ERROR;
    }

    if (para_log_file_slot_valid(ogx, ogx->curr_file)) {
        uint64 commit_now = para_log_commit_now(session);
        uint64 *file_max = &ogx->file_max_lsn[ogx->curr_file];

        if (!para_log_lsn_in_commit_space(*file_max, commit_now) || *file_max < batch_lsn) {
            *file_max = batch_lsn;
        }
    }

    /*
     * Bitmap mode only marks flushed LSNs here.
     * We no longer set per-entry pending state before IO, reducing one full status_table traversal.
     */
    para_log_mark_lsn_batch_flushed(session, numa_id, buf_ctx, start_entry_idx, curr_entry_idx);
    para_log_advance_lsn(session);
    file->head.last = scn;
    if (file->head.first == OG_INVALID_ID64) {
        file->head.first = scn;
        log_flush_head(session, file);
    }
    
    (void)cm_atomic_set_u64(&ogx->last_flushed_pos, end_log_pos);

    {
        log_point_t synth_pt;
        synth_pt.asn = 0;
        synth_pt.block_id = 0;
        synth_pt.rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
        synth_pt.lfn = cm_atomic_barrier_read(&session->kernel->redo_ctx.flushed_lfn);
        synth_pt.lsn = cm_atomic_barrier_read(&session->kernel->redo_ctx.flushed_lsn);
        ckpt_set_trunc_point(session, &synth_pt);
    }

    ogx->dfx.flush_cnt++;
    ogx->dfx.flush_bytes += aligned_size;
    {
        int32 nent = 1;
        int32 walk = start_entry_idx;

        while (walk != curr_entry_idx) {
            nent++;
            knl_panic_log(nent <= ring_size,
                          "para log flush entry count overflow, panic info: group=%u start=%d curr=%d nent=%d",
                          numa_id, start_entry_idx, curr_entry_idx, nent);
            walk = get_next_status_entry(RD_STATUS_ENTRIES_POWER, walk);
        }

        ogx->dfx.flush_entries += (uint64)nent;
        OG_LOG_DEBUG_INF("[PARA LOG] flush group=%u entries=%d size=%u aligned=%u file=%s pos=%llu "
                         "batch_lsn=%llu flushed=%llu start_pos=%llu end_pos=%llu",
                         numa_id, nent, data_size, aligned_size, file->ctrl->name, current_file_pos,
                         batch_lsn, cm_atomic_barrier_read(&session->kernel->redo_ctx.flushed_lsn),
                         start_flush_pos, end_log_pos);
    }

    int32 entry_idx = start_entry_idx;
    uint32 recycled = 0;

    while (entry_idx != curr_entry_idx) {
        int32 idx = get_status_entry_index(RD_STATUS_ENTRIES_POWER, entry_idx);

        para_log_recycle_status_entry(&buf_ctx->status_table[idx]);
        recycled++;
        knl_panic_log(recycled <= (uint32)ring_size,
                      "para log recycle walk overflow, panic info: group=%u start=%d curr=%d recycled=%u",
                      numa_id, start_entry_idx, curr_entry_idx, recycled);
        entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, entry_idx);
    }

    para_log_recycle_status_entry(&buf_ctx->status_table[get_status_entry_index(RD_STATUS_ENTRIES_POWER,
                                                                               curr_entry_idx)]);

    ogx->last_flushed_entry = curr_entry_idx;

    return OG_SUCCESS;
}

void para_log_proc(thread_t *thread)
{
    para_log_context_t *ogx = (para_log_context_t *)thread->argument;
    knl_session_t *session = ogx->session;
    uint32 cpuid = ogx->thread_idx * SYS_CPUS_PER_GROUP;
    char thread_name[16];
    errno_t name_ret = snprintf_s(thread_name, sizeof(thread_name), sizeof(thread_name) - 1, "para_log_wr_%u", cpuid);
    knl_securec_check(name_ret);
    cm_set_thread_name(thread_name);
    OG_LOG_RUN_INF("[PARA LOG] lgwr start group=%u cpu=%u sid=%u", ogx->thread_idx, cpuid, session->id);
    cpu_set_t log_proc_set;
    CPU_ZERO(&log_proc_set);
    CPU_SET(cpuid, &log_proc_set);
    int rc = sched_setaffinity(0, sizeof(cpu_set_t), &log_proc_set);
    if (rc == -1) {
        OG_LOG_RUN_ERR("[PARA LOG] lgwr bind cpu failed group=%u cpu=%u", ogx->thread_idx, cpuid);
    }

    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    uint64 last_notified_lsn = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);

    while (!thread->closed) {
        uint64 req = (uint64)cm_atomic_get(&ogx->flush_req);
        uint64 ack = (uint64)cm_atomic_get(&ogx->flush_ack);
        bool32 kicked = (bool32)(req != ack);

        if (!kicked && (DB_NOT_READY(session) || DB_IS_READONLY(session))) {
            para_log_dfx_dump_due(session, ogx);
            (void)cm_futex_wait(&ogx->kick_futex, 200);
            continue;
        }

        cm_spin_lock(&ogx->b_flush_lock.lock, NULL);
        (void)para_log_flush_by_numa(session, ogx->thread_idx);
        cm_spin_unlock(&ogx->b_flush_lock.lock);
        para_log_wait_if_switch_blocked(session, ogx);

        if (kicked) {
            (void)cm_atomic_set(&ogx->flush_ack, (int64)req);
            cm_futex_wake(&ogx->ack_futex, 1);
        }

        uint64 curr_flushed_lsn = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);
        if (curr_flushed_lsn > last_notified_lsn) {
            cm_futex_wake(&ogx->leader_wait_cond.futex, 5);
            last_notified_lsn = curr_flushed_lsn;
        }

        /* commit already woken by flushed_lsn, ctrl fsync is deferred outside the lock, retry on failure next time. */
        para_log_persist_ctrl_if_dirty(session, ogx);

        para_log_dfx_dump_due(session, ogx);
    }

    para_log_dfx_dump(session, ogx, "lgwr_stop");
    OG_LOG_RUN_INF("[PARA LOG] lgwr stop group=%u", ogx->thread_idx);
}

status_t para_log_commit_flush(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    para_log_context_t *ogx = para_log_ctx_of(session);
    uint64 target_lsn = session->commit_lsn;
    if (target_lsn == 0) {
        return OG_SUCCESS;
    }
    knl_panic_log(ogx != NULL, "para log context is not initialized");

    knl_begin_session_wait(session, LOG_FILE_SYNC, OG_TRUE);
    para_log_commit_queue_t* target_queue = &(ogx->tx_queue);
    para_log_leader_cond_t *leader_wait = &(ogx->leader_wait_cond);
    bool i_am_leader = OG_FALSE;
    volatile uint64 already_flushed = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);
    uint32 wait_loops = 0;
    date_t wait_begin = cm_now();

    while (target_lsn > already_flushed) {
        if (para_log_wait_timed_out(wait_begin)) {
            CM_ABORT(0, "[PARA LOG] ABORT INFO: commit flush wait timeout, sid=%u group=%u target=%llu flushed=%llu",
                     session->id, ogx->thread_idx, target_lsn, already_flushed);
        }

        ogx->dfx.commit_wait_loop++;
        if ((++wait_loops & 0x3F) == 1) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] commit wait sid=%u group=%u target=%llu flushed=%llu leader=%u loops=%u",
                                 session->id, ogx->thread_idx, target_lsn, already_flushed,
                                 (uint32)i_am_leader, wait_loops);
        }
        int64 next_head = cm_atomic_get(&target_queue->atomic_first);
        for (;;) {
            session->log_next = (knl_session_t *)next_head;
            CM_MFENCE;
            if (cm_atomic_compare_exchange_64(&target_queue->atomic_first, &next_head, (int64)session)) {
                break;
            }
        }

        knl_session_t *next_head_ptr = (knl_session_t *)next_head;
        if (next_head_ptr != NULL) {
            i_am_leader = OG_FALSE;
            cm_futex_wait(&session->futex, 50);
        } else {
            i_am_leader = OG_TRUE;
            cm_futex_wait(&leader_wait->futex, 50);
            if (session->kernel->attr.enable_boc) {
                tx_scn_broadcast(session);
            }
            knl_session_t *begin = (knl_session_t *)cm_atomic_exchange(&target_queue->atomic_first, (int64)NULL);
            if (begin == NULL) {
                CM_ABORT(0, "[LOG] ABORT INFO: commit flush log failed");
                return OG_ERROR;
            }

            knl_session_t *next = NULL;
            knl_session_t *curr = begin;
            while (curr) {
                next = curr->log_next;
                curr->log_next = NULL;
                if (curr != session) {
                    cm_futex_wake(&curr->futex, 1);
                }
                curr = next;
            }
        }
        already_flushed = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);
    }

    if (i_am_leader) {
        if (session->kernel->attr.enable_boc) {
            tx_scn_broadcast(session);
        }
    }
    knl_end_session_wait(session, LOG_FILE_SYNC);
    return OG_SUCCESS;
}

static bool32 para_log_wrbuf_space_enough_at(uint64 curr_pos, uint64 last_flushed_pos, uint64 buffer_size,
                                             uint32 record_size)
{
    uint64 new_curr_pos = curr_pos + record_size;

    if (new_curr_pos <= buffer_size) {
        return (bool32)((last_flushed_pos <= curr_pos) || (last_flushed_pos > new_curr_pos));
    }

    uint64 second_part = record_size - (buffer_size - curr_pos);
    return (bool32)((last_flushed_pos <= curr_pos) && (last_flushed_pos > second_part));
}

static bool32 para_log_bitmap_need_backpressure(knl_session_t *session)
{
    para_log_flush_lsn_bitmap_t *bm = para_log_bitmap_of(session);
    uint64 next_commit;
    uint64 base;
    uint64 occupancy;

    knl_panic_log(bm != NULL, "para log bitmap is not initialized");

    next_commit = para_log_commit_now(session) + 1;
    base = para_log_u64_load(&bm->base_lsn);
    occupancy = (next_commit > base) ? (next_commit - base) : 0;

    return (bool32)(occupancy >= LOG_FLUSH_BITMAP_BACKPRESSURE_SIZE);
}

static status_t para_log_write_wait_progress(knl_session_t *session, date_t begin)
{
    uint32 group_count;
    uint32 i;

    if (para_log_wait_timed_out(begin)) {
        return OG_TIMEDOUT;
    }

    group_count = SYS_NUMA_GROUP_COUNT;
    for (i = 0; i < group_count; i++) {
        para_log_context_t *peer = session->kernel->para_log_ctx[i];

        if (peer == NULL) {
            continue;
        }

        if (para_log_writer_alive(peer)) {
            para_log_kick_writer(peer, OG_TRUE);
            continue;
        }

        if (para_log_direct_flush_group(session, peer, i) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    cm_spin_sleep_ex(1000);
    return OG_SUCCESS;
}

static status_t para_log_wait_bitmap_window(knl_session_t *session, para_log_context_t *ogx, date_t begin)
{
    para_log_flush_lsn_bitmap_t *bm = para_log_bitmap_of(session);
    uint32 wait_times = 0;
    status_t wait_ret;

    knl_panic_log(bm != NULL, "para log bitmap is not initialized, group=%u", ogx->thread_idx);

    while (para_log_bitmap_need_backpressure(session)) {
        uint64 flushed = para_log_u64_load(&bm->flushed_lsn);
        uint64 base = para_log_u64_load(&bm->base_lsn);

        /* when flushed catches up to commit lgwr stops advancing, must slide base past the prefix here, otherwise occupancy never drops */
        if (flushed > base) {
            para_log_flush_bitmap_check(bm, flushed);
            continue;
        }

        if ((++wait_times & 0x3FF) == 1) {
            uint64 next_commit = para_log_commit_now(session) + 1;
            uint64 max_marked = para_log_u64_load(&bm->max_marked_lsn);

            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] bitmap backpressure group=%u base=%llu flushed=%llu max_marked=%llu "
                                 "next_commit=%llu occupancy=%llu window=%u",
                                 ogx->thread_idx, base, flushed, max_marked, next_commit,
                                 (next_commit > base) ? (next_commit - base) : 0,
                                 LOG_FLUSH_BITMAP_WINDOW_SIZE);
        }

        wait_ret = para_log_write_wait_progress(session, begin);
        if (wait_ret != OG_SUCCESS) {
            if (wait_ret == OG_TIMEDOUT) {
                OG_LOG_RUN_ERR("[PARA LOG] bitmap backpressure timeout group=%u waits=%u", ogx->thread_idx,
                               wait_times);
            } else {
                OG_LOG_RUN_ERR("[PARA LOG] bitmap backpressure flush failed group=%u waits=%u", ogx->thread_idx,
                               wait_times);
            }

            return wait_ret;
        }
    }

    return OG_SUCCESS;
}

static bool32 para_log_try_reserve_wrbuf(para_log_context_t *ogx, uint32 record_size, uint64 *start_pos,
                                         uint64 *end_pos, int32 *curr_lrc_ptr)
{
    para_log_buf_ctx_t *buf_ctx = &ogx->log_buf_ctx;
    volatile uint128_u *ctl_val = (volatile uint128_u *)&buf_ctx->ctl.value;

    for (;;) {
        para_log_buf_ctl_t old_ctl;
        para_log_buf_ctl_t new_ctl;
        uint128_u cas_ret;
        uint64 last_flushed_pos;
        uint64 start;
        uint64 new_curr_pos;
        int32 lrc;

        old_ctl.value = buf_ctx->ctl.value;
        last_flushed_pos = cm_atomic_barrier_read(&ogx->last_flushed_pos);
        start = old_ctl.struct128.curr_byte_pos;
        lrc = old_ctl.struct128.curr_lrc;

        if (!para_log_wrbuf_space_enough_at(start, last_flushed_pos, buf_ctx->buffer_size, record_size)) {
            return OG_FALSE;
        }

        new_curr_pos = start + record_size;
        if (new_curr_pos > buf_ctx->buffer_size) {
            new_curr_pos -= buf_ctx->buffer_size;
        }

        new_ctl.struct128.curr_byte_pos = new_curr_pos;
        new_ctl.struct128.curr_byte_size = record_size;
        new_ctl.struct128.curr_lrc = (lrc + 1) & 0x7FFFFFFF;

        cas_ret = cm_compare_and_swap_u128(ctl_val, old_ctl.value, new_ctl.value);
        if (cas_ret.u128 != old_ctl.value.u128) {
            continue;
        }

        *start_pos = start;
        if (start + record_size <= buf_ctx->buffer_size) {
            *end_pos = start + record_size;
        } else {
            *end_pos = start + record_size - buf_ctx->buffer_size;
        }
        *curr_lrc_ptr = lrc;
        return OG_TRUE;
    }
}

static uint32 para_log_checksum_wrbuf(const para_log_buf_ctx_t *buf_ctx, uint64 start_pos, uint32 size)
{
    const char *first;
    const char *second;
    uint32 first_part;
    uint32 second_part;
    uint32 crc;

    if (start_pos + size <= buf_ctx->buffer_size) {
        return cm_get_checksum(buf_ctx->buffer + start_pos, size);
    }

    first_part = (uint32)(buf_ctx->buffer_size - start_pos);
    second_part = size - first_part;
    first = buf_ctx->buffer + start_pos;
    second = buf_ctx->buffer;

    cm_init_crc32c(&crc);

#if defined(HAVE_ARM_ACLE)
    if (cm_crc32c_aarch_available()) {
        crc = cm_crc32c_aarch(first, first_part, crc);
        crc = cm_crc32c_aarch(second, second_part, crc);
        cm_final_crc32c(&crc);
        return crc;
    }
#else
    if (cm_crc32c_sse42_available()) {
        crc = cm_crc32c_sse42(first, first_part, crc);
        crc = cm_crc32c_sse42(second, second_part, crc);
        cm_final_crc32c(&crc);
        return crc;
    }
#endif

    crc = cm_crc32c_sb8(first, first_part, crc);
    crc = cm_crc32c_sb8(second, second_part, crc);
    if (!IS_BIG_ENDIAN) {
        cm_final_crc32c(&crc);
    } else {
        cm_final_crc32c_bendian(&crc);
    }

    return crc;
}

static void para_log_copy_wrbuf(para_log_buf_ctx_t *buf_ctx, uint64 start_pos, const char *src, uint32 size)
{
    errno_t ret;

    if (size == 0) {
        return;
    }

    knl_panic_log(start_pos <= buf_ctx->buffer_size, "the start_pos is out of wal buffer range, panic info: "
                  "start_pos %llu, buffer_size %llu", start_pos, buf_ctx->buffer_size);

    if (start_pos + size <= buf_ctx->buffer_size) {
        ret = memcpy_sp(buf_ctx->buffer + start_pos, buf_ctx->buffer_size - start_pos, src, size);
        knl_securec_check(ret);
        return;
    }

    uint32 first_part = (uint32)(buf_ctx->buffer_size - start_pos);
    uint32 second_part = size - first_part;

    if (first_part > 0) {
        ret = memcpy_sp(buf_ctx->buffer + start_pos, first_part, src, first_part);
        knl_securec_check(ret);
    }

    ret = memcpy_sp(buf_ctx->buffer, buf_ctx->buffer_size, src + first_part, second_part);
    knl_securec_check(ret);
}

static void para_log_copy_logic_data(knl_session_t *session, para_log_buf_ctx_t *buf_ctx, uint64 start_pos)
{
    knl_rm_t *rm = session->rm;
    char *logic_log_buf = rm->logic_log_buf;

    knl_panic_log(rm->logic_log_size > 0, "the logic_log_size is abnormal, panic info: logic_log_size %u",
                  rm->logic_log_size);
    knl_panic_log(rm->need_copy_logic_log, "the need_copy_logic_log is false.");

    if (rm->logic_log_size > KNL_LOGIC_LOG_BUF_SIZE) {
        knl_panic_log(rm->large_page_id != OG_INVALID_ID32, "the rm's large_page_id is invalid.");
        logic_log_buf = mpool_page_addr(session->kernel->attr.large_pool, rm->large_page_id);
    }

    para_log_copy_wrbuf(buf_ctx, start_pos, logic_log_buf, rm->logic_log_size);

    if (!DB_IS_CLUSTER(session)) {
        if (rm->large_page_id != OG_INVALID_ID32) {
            mpool_free_page(session->kernel->attr.large_pool, rm->large_page_id);
            rm->large_page_id = OG_INVALID_ID32;
        }
    }

    session->logic_log_size = rm->logic_log_size;
    rm->logic_log_size = 0;
    rm->need_copy_logic_log = OG_FALSE;
    session->log_entry = NULL;
}

static void para_log_assign_write_lsn(knl_session_t *session)
{
    volatile uint128_u *ptr = &session->kernel->para_log_lsn_ctl.value;
    para_log_lsn_ctl_t old_ctl;
    para_log_lsn_ctl_t new_ctl;
    uint128_u cas_ret;
    uint64 kernel_lsn;

    for (;;) {
        old_ctl.value = session->kernel->para_log_lsn_ctl.value;
        kernel_lsn = (uint64)cm_atomic_get(&session->kernel->lsn);
        new_ctl.s.lsn = ((old_ctl.s.lsn > kernel_lsn) ? old_ctl.s.lsn : kernel_lsn) + 1;
        new_ctl.s.commit = old_ctl.s.commit + 1;
        cas_ret = cm_compare_and_swap_u128(ptr, old_ctl.value, new_ctl.value);
        if (cas_ret.u128 == old_ctl.value.u128) {
            break;
        }
    }

    session->curr_lsn = new_ctl.s.lsn;
    session->commit_lsn = new_ctl.s.commit;
    /* in parallel mode curr_lfn is a placeholder for commit_lsn, keeping lastest_lfn/flushed_lfn in the same commit space */
    session->curr_lfn = new_ctl.s.commit;
    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->lsn, new_ctl.s.lsn);
}

static void para_log_lrc_futex_wait(volatile int32 *addr, int32 observed, uint32 timeout_ms)
{
    struct timespec ts;
    cm_futex_args_t args;

    cm_futex_rel_timeout_ms(&ts, timeout_ms);
    args.uaddr = (atomic32_t *)(void *)addr;
    args.op = FUTEX_WAIT;
    args.val = (uint32)observed;
    args.utime = &ts;
    args.uaddr2 = NULL;
    args.val3 = 0;
    (void)cm_futex_syscall(&args);
}

static void para_log_lrc_futex_wake(volatile int32 *addr)
{
    cm_futex_args_t args;

    args.uaddr = (atomic32_t *)(void *)addr;
    args.op = FUTEX_WAKE;
    args.val = PARA_LOG_LRC_WAKE_COUNT;
    args.utime = NULL;
    args.uaddr2 = NULL;
    args.val3 = 0;
    (void)cm_futex_syscall(&args);
}

static void para_log_assign_lsn_in_lrc_order(knl_session_t *session, para_log_context_t *ogx, int32 curr_lrc,
                                             date_t begin)
{
    uint32 spins = 0;

    for (;;) {
        int32 next = __atomic_load_n(&ogx->next_assign_lrc, __ATOMIC_ACQUIRE);
        int32 successor;

        if (next == curr_lrc) {
            break;
        }

        successor = (next + 1) & 0x7FFFFFFF;
        if (curr_lrc == successor && spins < OG_SPIN_COUNT) {
            CM_SPIN_BUCKET_PAUSE();
            spins++;
            continue;
        }

        spins = 0;
        para_log_lrc_futex_wait(&ogx->next_assign_lrc, next, PARA_LOG_LRC_WAIT_SLICE_MS);
        if (para_log_wait_timed_out(begin)) {
            CM_ABORT(0, "[PARA LOG] ABORT INFO: lrc-order lsn assign timeout group=%u lrc=%d next=%d",
                     ogx->thread_idx, curr_lrc, __atomic_load_n(&ogx->next_assign_lrc, __ATOMIC_RELAXED));
        }
    }

    para_log_assign_write_lsn(session);
    __atomic_store_n(&ogx->next_assign_lrc, (curr_lrc + 1) & 0x7FFFFFFF, __ATOMIC_RELEASE);
    para_log_lrc_futex_wake(&ogx->next_assign_lrc);
}

void para_log_write(knl_session_t *session, uint32 total_size, log_group_t *group, uint32 ori_group_size)
{
    para_log_context_t *ogx = para_log_ctx_of(session);
    para_log_buf_ctx_t *buf_ctx;
    uint64 start_pos;
    uint64 end_pos;
    int32 curr_lrc = -1;
    date_t begin;
    uint64 wait_times = 0;
    status_t wait_ret;
    uint32 disk_size = total_size + PARA_LOG_GROUP_CKS_SIZE;

    knl_panic_log(ogx != NULL, "para log context is not initialized");
    buf_ctx = &ogx->log_buf_ctx;

    knl_begin_session_wait(session, LOG_WRITE_RESERVE_SPACE, OG_TRUE);
    begin = cm_now();
    for (;;) {
        wait_ret = para_log_wait_bitmap_window(session, ogx, begin);
        if (wait_ret != OG_SUCCESS) {
            knl_end_session_wait(session, LOG_WRITE_RESERVE_SPACE);
            if (wait_ret == OG_TIMEDOUT) {
                CM_ABORT(0, "[PARA LOG] ABORT INFO: write reserve timeout on bitmap backpressure, group=%u",
                         ogx->thread_idx);
            }

            CM_ABORT(0, "[PARA LOG] ABORT INFO: write reserve flush redo log failed on bitmap backpressure, group=%u",
                     ogx->thread_idx);
        }

        if (para_log_bitmap_need_backpressure(session) ||
            !para_log_try_reserve_wrbuf(ogx, disk_size, &start_pos, &end_pos, &curr_lrc)) {
            ogx->dfx.write_retry++;
            wait_times++;
            if ((wait_times & 0x3FF) == 1) {
                OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA LOG] write reserve retry group=%u size=%u flushed_pos=%llu buf_pos=%llu "
                                     "retries=%llu",
                                     ogx->thread_idx, disk_size, ogx->last_flushed_pos,
                                     buf_ctx->ctl.struct128.curr_byte_pos, wait_times);
            }

            wait_ret = para_log_write_wait_progress(session, begin);
            if (wait_ret != OG_SUCCESS) {
                knl_end_session_wait(session, LOG_WRITE_RESERVE_SPACE);
                if (wait_ret == OG_TIMEDOUT) {
                    CM_ABORT(0, "[PARA LOG] ABORT INFO: write reserve timeout, group=%u size=%u retries=%llu",
                             ogx->thread_idx, disk_size, wait_times);
                }

                CM_ABORT(0, "[PARA LOG] ABORT INFO: write reserve flush redo log failed, group=%u size=%u retries=%llu",
                         ogx->thread_idx, disk_size, wait_times);
            }

            continue;
        }

        /* obtained the unique lrc for this lane, claim commit_lsn in lrc order, still monotonic within the file */
        para_log_assign_lsn_in_lrc_order(session, ogx, curr_lrc, begin);
        break;
    }

    knl_end_session_wait(session, LOG_WRITE_RESERVE_SPACE);
    knl_panic_log(curr_lrc >= 0, "para log reserve did not assign lrc");

    uint32 current_entry = get_status_entry_index(RD_STATUS_ENTRIES_POWER, curr_lrc);
    volatile para_log_ins_status_ent_t *status_entry_ptr = &buf_ctx->status_table[current_entry];

    para_log_wait_and_claim_slot(buf_ctx, status_entry_ptr, curr_lrc, ogx->thread_idx, &ogx->dfx.slot_wait);

    session->curr_lrc = curr_lrc;
    group->lsn = session->curr_lsn;
    group->commit_lsn = session->commit_lsn;

    para_log_copy_wrbuf(buf_ctx, start_pos, (char *)group, ori_group_size);

    if (session->rm->need_copy_logic_log) {
        uint64 logic_start_pos = start_pos + ori_group_size;
        if (logic_start_pos >= buf_ctx->buffer_size) {
            logic_start_pos -= buf_ctx->buffer_size;
        }

        log_add_group_size(group, session->rm->logic_log_size);
        para_log_copy_logic_data(session, buf_ctx, logic_start_pos);
    }

    {
        uint32 payload_size = LOG_GROUP_ACTUAL_SIZE(group);
        uint32 cks = para_log_checksum_wrbuf(buf_ctx, start_pos, payload_size);
        uint64 cks_pos = start_pos + payload_size;
        if (cks_pos >= buf_ctx->buffer_size) {
            cks_pos -= buf_ctx->buffer_size;
        }

        para_log_copy_wrbuf(buf_ctx, cks_pos, (const char *)&cks, PARA_LOG_GROUP_CKS_SIZE);
    }

    para_log_u64_store_release(&status_entry_ptr->end_log_pos, end_pos);
    para_log_u64_store_release(&status_entry_ptr->lsn, session->commit_lsn);
    /* release: WAL copy and end_log_pos/lsn before COPIED. Does not rely on volatile for ordering of plain writes. */
    para_log_status_store_release(status_entry_ptr, RD_COPIED);
    ogx->dfx.write_cnt++;
    ogx->dfx.write_bytes += disk_size;
    OG_LOG_DEBUG_INF("[PARA LOG] write group=%u sid=%u lrc=%d commit_lsn=%llu curr_lsn=%llu size=%u pos=%llu..%llu",
                     ogx->thread_idx, session->id, curr_lrc, session->commit_lsn, session->curr_lsn, disk_size,
                     start_pos, end_pos);
}

static int32 para_log_rcy_file_handle(log_file_t *file, const int32 *handles)
{
    int32 fid;

    if (file == NULL || file->ctrl == NULL) {
        return OG_INVALID_HANDLE;
    }

    fid = file->ctrl->file_id;
    if (handles != NULL && fid >= 0 && (uint32)fid < OG_MAX_LOG_FILES && handles[fid] != OG_INVALID_HANDLE) {
        return handles[fid];
    }

    return file->handle;
}

static void para_log_rcy_cursor_set_file(para_log_rcy_cursor_t *cur, uint32 file_idx)
{
    log_file_t *file = cur->files[file_idx];
    int64 wpos;
    int64 fsize;

    cur->file_idx = file_idx;
    cur->cache_valid = 0;
    cur->cache_off = -1;
    if (file == NULL || file->ctrl == NULL) {
        cur->eof = OG_TRUE;
        return;
    }

    cur->blk_size = file->ctrl->block_size;
    if (cur->blk_size == 0) {
        cur->blk_size = OG_DFLT_LOG_BLOCK_SIZE;
    }

    cur->offset = (int64)CM_CALC_ALIGN(sizeof(log_file_head_t), cur->blk_size);
    wpos = (int64)file->head.write_pos;
    fsize = (int64)file->ctrl->size;

    if (file->ctrl->status != LOG_FILE_CURRENT && wpos > cur->offset && (fsize <= 0 || wpos < fsize)) {
        cur->file_limit = wpos;
    } else if (fsize > cur->offset) {
        cur->file_limit = fsize;
    } else {
        cur->file_limit = cur->offset;
    }

    if (cur->rcy_lsn > 0) {
        int64 rcy_off = (int64)file->head.rcy_off;

        if (rcy_off > cur->offset && rcy_off <= cur->file_limit && cur->blk_size > 0 &&
            (rcy_off % (int64)cur->blk_size) == 0) {
            OG_LOG_RUN_INF("[PARA RCY] cursor file group=%u idx=%u start rcy_off=%lld (was %lld) rcy_lsn=%llu",
                           cur->group_id, file_idx, rcy_off, cur->offset, cur->rcy_lsn);
            cur->offset = rcy_off;
        }
    }

    OG_LOG_RUN_INF("[PARA RCY] cursor file group=%u idx=%u %s asn=%u status=%d write_pos=%lld size=%lld "
                   "limit=%lld offset=%lld rcy_off=%llu",
                   cur->group_id, file_idx, file->ctrl->name, file->head.asn, file->ctrl->status, wpos, fsize,
                   cur->file_limit, cur->offset, file->head.rcy_off);
}

static bool32 para_log_rcy_file_usable(para_log_rcy_cursor_t *cur, uint32 file_idx)
{
    log_file_t *file = cur->files[file_idx];

    if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg)) {
        return OG_FALSE;
    }

    if (file->head.asn == OG_INVALID_ASN) {
        return OG_FALSE;
    }

    if (cur->handles[file_idx] == OG_INVALID_HANDLE) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static void para_log_rcy_cursor_next_file(para_log_rcy_cursor_t *cur)
{
    uint32 start = cur->file_idx;

    if (cur->compact_count == 0 || cur->eof) {
        cur->eof = OG_TRUE;
        return;
    }

    if (cur->file_idx == cur->last_idx) {
        cur->eof = OG_TRUE;
        return;
    }

    for (;;) {
        CM_CYCLED_MOVE_NEXT(cur->compact_count, cur->file_idx);
        if (para_log_rcy_file_usable(cur, cur->file_idx)) {
            para_log_rcy_cursor_set_file(cur, cur->file_idx);
            return;
        }

        if (cur->file_idx == cur->last_idx || cur->file_idx == start) {
            cur->eof = OG_TRUE;
            return;
        }
    }
}

static status_t para_log_rcy_cursor_ensure(para_log_rcy_cursor_t *cur, uint32 need)
{
    log_file_t *file;
    int64 aligned;
    int64 to_read;
    int64 avail;

    if (cur->eof) {
        return OG_SUCCESS;
    }

    if (cur->offset + (int64)need > cur->file_limit) {
        return OG_SUCCESS;
    }

    avail = (cur->cache_off >= 0) ? (cur->cache_off + (int64)cur->cache_valid - cur->offset) : -1;
    if (avail >= (int64)need && cur->offset >= cur->cache_off) {
        return OG_SUCCESS;
    }

    file = cur->files[cur->file_idx];
    aligned = cur->offset - (cur->offset % (int64)cur->blk_size);
    to_read = cur->file_limit - aligned;
    if (to_read > cur->cache.buf_size) {
        to_read = cur->cache.buf_size;
    }

    to_read = to_read - (to_read % (int64)cur->blk_size);
    if (to_read < (int64)cur->blk_size) {
        return OG_SUCCESS;
    }

    if (cm_read_device(file->ctrl->type, cur->handles[cur->file_idx], aligned, cur->cache.aligned_buf,
                       (int32)to_read) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PARA RCY] failed to read %s offset=%lld size=%lld", file->ctrl->name, aligned, to_read);
        return OG_ERROR;
    }

    cur->cache_off = aligned;
    cur->cache_valid = (uint32)to_read;
    return OG_SUCCESS;
}

static char *para_log_rcy_cursor_ptr(para_log_rcy_cursor_t *cur)
{
    return cur->cache.aligned_buf + (cur->offset - cur->cache_off);
}

static int64 para_log_rcy_next_block_off(int64 offset, uint32 blk_size)
{
    int64 next = (int64)CM_CALC_ALIGN((uint64)offset, blk_size);

    if (next <= offset) {
        next = offset + (int64)blk_size;
    }

    return next;
}

static void para_log_rcy_skip_to_next_block(para_log_rcy_cursor_t *cur, const char *reason, uint32 actual,
                                            uint32 expect_cks, uint32 got_cks)
{
    int64 old_off = cur->offset;
    int64 next = para_log_rcy_next_block_off(cur->offset, cur->blk_size);

    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                         "[PARA RCY] %s group=%u file=%u off=%lld next=%lld limit=%lld actual=%u expect=%u got=%u",
                         reason, cur->group_id, cur->file_idx, old_off, next, cur->file_limit, actual, expect_cks,
                         got_cks);

    if (next >= cur->file_limit) {
        para_log_rcy_cursor_next_file(cur);
        return;
    }

    cur->offset = next;
    cur->has_group = OG_FALSE;
}

static bool32 para_log_rcy_is_flush_padding(para_log_rcy_cursor_t *cur, const log_group_t *hdr)
{
    int64 next;
    int64 pad;

    if (hdr->lsn != 0) {
        return OG_FALSE;
    }

    next = (int64)CM_CALC_ALIGN((uint64)cur->offset, cur->blk_size);
    if (next <= cur->offset) {
        return OG_FALSE;
    }

    pad = next - cur->offset;
    if (pad < (int64)sizeof(log_group_t)) {
        return OG_TRUE;
    }

    if (hdr->commit_lsn == 0 && hdr->size == 0) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t para_log_rcy_cursor_load_group(para_log_rcy_cursor_t *cur)
{
    log_group_t *hdr;
    uint32 actual;
    uint32 disk_size;
    uint32 remain;
    uint32 expect_cks;
    uint32 got_cks;
    errno_t ret;

    cur->has_group = OG_FALSE;
    while (!cur->eof) {
        if (cur->offset + (int64)sizeof(log_group_t) > cur->file_limit) {
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        if (para_log_rcy_cursor_ensure(cur, sizeof(log_group_t)) != OG_SUCCESS) {
            return OG_ERROR;
        }

        remain = (cur->cache_off >= 0) ? (uint32)(cur->cache_off + (int64)cur->cache_valid - cur->offset) : 0;
        if (remain < sizeof(log_group_t)) {
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        hdr = (log_group_t *)para_log_rcy_cursor_ptr(cur);

        if (hdr->size == 0 || para_log_rcy_is_flush_padding(cur, hdr)) {
            para_log_rcy_skip_to_next_block(cur, "skip padding", 0, 0, 0);
            continue;
        }

        actual = LOG_GROUP_ACTUAL_SIZE(hdr);
        if (actual < sizeof(log_group_t) || actual > OG_MAX_LOG_GROUP_SIZE) {
            /* Mid-file garbage must not skip the rest of this file (false commit_lsn hole). */
            para_log_rcy_skip_to_next_block(cur, "skip invalid size", actual, 0, 0);
            continue;
        }

        disk_size = actual + PARA_LOG_GROUP_CKS_SIZE;
        if (cur->offset + (int64)disk_size > cur->file_limit) {
            OG_LOG_RUN_INF("[PARA RCY] torn group missing cks group=%u file=%u off=%lld actual=%u limit=%lld",
                           cur->group_id, cur->file_idx, cur->offset, actual, cur->file_limit);
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        if (para_log_rcy_cursor_ensure(cur, disk_size) != OG_SUCCESS) {
            return OG_ERROR;
        }

        remain = (cur->cache_off >= 0) ? (uint32)(cur->cache_off + (int64)cur->cache_valid - cur->offset) : 0;
        if (remain < disk_size) {
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        hdr = (log_group_t *)para_log_rcy_cursor_ptr(cur);
        ret = memcpy_sp(&expect_cks, sizeof(expect_cks), (char *)hdr + actual, sizeof(expect_cks));
        knl_securec_check(ret);
        got_cks = cm_get_checksum(hdr, actual);

        if (got_cks != expect_cks) {
            if ((cur->file_limit - cur->offset) <= (int64)cur->blk_size * 2) {
                OG_LOG_RUN_INF("[PARA RCY] torn checksum mismatch group=%u file=%u off=%lld actual=%u "
                               "expect=%u got=%u limit=%lld",
                               cur->group_id, cur->file_idx, cur->offset, actual, expect_cks, got_cks,
                               cur->file_limit);
                para_log_rcy_cursor_next_file(cur);
            } else {
                para_log_rcy_skip_to_next_block(cur, "checksum mismatch skip block", actual, expect_cks, got_cks);
            }

            continue;
        }

        if (cur->last_commit_lsn != 0 && hdr->commit_lsn < cur->last_commit_lsn) {
            OG_LOG_RUN_INF("[PARA RCY] leftover eof group=%u file=%u off=%lld commit_lsn=%llu last=%llu",
                           cur->group_id, cur->file_idx, cur->offset, hdr->commit_lsn, cur->last_commit_lsn);
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        cur->last_commit_lsn = hdr->commit_lsn;
        cur->has_group = OG_TRUE;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static log_group_t *para_log_rcy_cursor_group(para_log_rcy_cursor_t *cur)
{
    if (!cur->has_group) {
        return NULL;
    }

    return (log_group_t *)para_log_rcy_cursor_ptr(cur);
}

static void para_log_rcy_cursor_advance(para_log_rcy_cursor_t *cur)
{
    log_group_t *group = para_log_rcy_cursor_group(cur);

    if (group == NULL) {
        return;
    }

    cur->offset += (int64)PARA_LOG_GROUP_DISK_SIZE(group);
    cur->has_group = OG_FALSE;
}

static status_t para_log_rcy_cursor_skip_to_rcy(para_log_rcy_cursor_t *cur, uint64 rcy_lsn)
{
    log_group_t *group;
    uint64 skipped = 0;
    uint64 next_lsn = 0;

    if (para_log_rcy_cursor_load_group(cur) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (cur->has_group) {
        group = para_log_rcy_cursor_group(cur);

        if (group->commit_lsn > rcy_lsn) {
            next_lsn = group->commit_lsn;
            OG_LOG_RUN_INF("[PARA RCY] skip_to_rcy group=%u skipped=%llu rcy_lsn=%llu next_commit_lsn=%llu "
                           "file=%u off=%lld limit=%lld",
                           cur->group_id, skipped, rcy_lsn, next_lsn, cur->file_idx, cur->offset, cur->file_limit);
            return OG_SUCCESS;
        }

        skipped++;
        para_log_rcy_cursor_advance(cur);

        if (para_log_rcy_cursor_load_group(cur) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    OG_LOG_RUN_INF("[PARA RCY] skip_to_rcy group=%u skipped=%llu rcy_lsn=%llu eof=%u",
                   cur->group_id, skipped, rcy_lsn, cur->eof);
    return OG_SUCCESS;
}

static void para_log_rcy_cursor_close(para_log_rcy_cursor_t *cur)
{
    cm_aligned_free(&cur->cache);
}

static status_t para_log_rcy_cursor_open(knl_session_t *session, uint8 node_id, uint32 group_id, const int32 *handles,
                                         uint64 rcy_lsn, para_log_rcy_cursor_t *cur)
{
    logfile_set_t *set = LOGFILE_SET(session, node_id);
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);
    uint32 first;
    uint32 last;
    uint32 i;

    MEMS_RETURN_IFERR(memset_sp(cur, sizeof(para_log_rcy_cursor_t), 0, sizeof(para_log_rcy_cursor_t)));
    cur->group_id = group_id;
    cur->rcy_lsn = rcy_lsn;
    cur->cache_off = -1;
    for (i = 0; i < CPU_SEG_MAX_NUM; i++) {
        cur->handles[i] = OG_INVALID_HANDLE;
    }

    /*
     * Compact order must match log_file_init: every file of this group_id occupies a slot, including dropped
     * ones. para_log_first/last are indices into that array, not into the live-file subset.
     * Do not silently drop files beyond CPU_SEG_MAX_NUM: that would skip redo and create a false LSN hole.
     */
    for (i = 0; i < set->logfile_hwm; i++) {
        log_file_t *file = &set->items[i];

        if (file->ctrl == NULL) {
            continue;
        }

        if (file->ctrl->group_id != group_id) {
            continue;
        }

        if (cur->compact_count >= CPU_SEG_MAX_NUM) {
            OG_LOG_RUN_ERR("[PARA RCY] too many log files for group %u, max %u, refuse to skip remaining files",
                           group_id, CPU_SEG_MAX_NUM);
            return OG_ERROR;
        }

        cur->files[cur->compact_count] = file;
        cur->handles[cur->compact_count] = para_log_rcy_file_handle(file, handles);
        cur->compact_count++;
    }

    if (cur->compact_count == 0) {
        cur->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    if (cm_aligned_malloc((int64)PARA_LOG_RCY_CACHE_SIZE, "para rcy cache", &cur->cache) != OG_SUCCESS) {
        return OG_ERROR;
    }

    first = ctrl->para_log_first[group_id];
    last = ctrl->para_log_last[group_id];
    if (first >= cur->compact_count) {
        first = 0;
    }

    /*
     * Walk the whole compact ring from first. A stale para_log_last must not hide files that
     * still have a valid ASN (false commit_lsn hole). Unusable slots are skipped later.
     */
    {
        uint32 idx = first;
        uint32 scan_last = first;
        uint32 ctrl_last = last;
        bool32 have_usable = OG_FALSE;

        do {
            if (para_log_rcy_file_usable(cur, idx)) {
                scan_last = idx;
                have_usable = OG_TRUE;
            }

            CM_CYCLED_MOVE_NEXT(cur->compact_count, idx);
        } while (idx != first);

        if (!have_usable) {
            cur->first_idx = first;
            cur->last_idx = first;
            cur->eof = OG_TRUE;
            return OG_SUCCESS;
        }

        last = scan_last;
        OG_LOG_RUN_INF("[PARA RCY] group=%u first=%u last=%u ctrl_last=%u compact=%u",
                       group_id, first, last, ctrl_last, cur->compact_count);
    }

    cur->first_idx = first;
    cur->last_idx = last;
    if (!para_log_rcy_file_usable(cur, first)) {
        cur->file_idx = first;
        para_log_rcy_cursor_next_file(cur);
        if (cur->eof) {
            return OG_SUCCESS;
        }
    } else {
        para_log_rcy_cursor_set_file(cur, first);
    }

    return OG_SUCCESS;
}

static status_t para_log_rcy_stream_prime(para_log_rcy_stream_t *stream)
{
    uint32 i;

    stream->expected = stream->rcy_lsn + 1;
    stream->recovered_end = stream->rcy_lsn;
    stream->peeked_writer = -1;
    stream->done = OG_FALSE;
    for (i = 0; i < stream->writer_count; i++) {
        if (para_log_rcy_cursor_skip_to_rcy(&stream->cursors[i], stream->rcy_lsn) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t para_log_rcy_stream_create(knl_session_t *session, uint8 node_id, uint64 rcy_lsn, const int32 *handles,
                                    para_log_rcy_stream_t **stream_out)
{
    para_log_rcy_stream_t *stream;
    uint32 i;
    uint32 writers = SYS_NUMA_GROUP_COUNT;
    errno_t ret;

    *stream_out = NULL;
    stream = (para_log_rcy_stream_t *)malloc(sizeof(para_log_rcy_stream_t));
    if (stream == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(para_log_rcy_stream_t), "para rcy stream");
        return OG_ERROR;
    }

    ret = memset_sp(stream, sizeof(para_log_rcy_stream_t), 0, sizeof(para_log_rcy_stream_t));
    knl_securec_check(ret);
    stream->session = session;
    stream->node_id = node_id;
    stream->rcy_lsn = rcy_lsn;
    stream->writer_count = writers;
    stream->peeked_writer = -1;

    for (i = 0; i < writers; i++) {
        if (para_log_rcy_cursor_open(session, node_id, i, handles, rcy_lsn, &stream->cursors[i]) != OG_SUCCESS) {
            para_log_rcy_stream_close(stream);
            return OG_ERROR;
        }
    }

    if (para_log_rcy_stream_prime(stream) != OG_SUCCESS) {
        para_log_rcy_stream_close(stream);
        return OG_ERROR;
    }

    *stream_out = stream;
    OG_LOG_RUN_INF("[PARA RCY] stream open node=%u rcy_lsn=%llu writers=%u", node_id, rcy_lsn, writers);
    return OG_SUCCESS;
}

void para_log_rcy_stream_close(para_log_rcy_stream_t *stream)
{
    uint32 i;

    if (stream == NULL) {
        return;
    }

    for (i = 0; i < stream->writer_count; i++) {
        para_log_rcy_cursor_close(&stream->cursors[i]);
    }

    free(stream);
}

status_t para_log_rcy_stream_reset(para_log_rcy_stream_t *stream)
{
    uint32 i;
    para_log_rcy_cursor_t *cur;

    if (stream == NULL) {
        return OG_SUCCESS;
    }

    for (i = 0; i < stream->writer_count; i++) {
        cur = &stream->cursors[i];
        cur->eof = OG_FALSE;
        cur->has_group = OG_FALSE;
        if (cur->compact_count == 0) {
            cur->eof = OG_TRUE;
            continue;
        }

        if (!para_log_rcy_file_usable(cur, cur->first_idx)) {
            cur->file_idx = cur->first_idx;
            para_log_rcy_cursor_next_file(cur);
        } else {
            para_log_rcy_cursor_set_file(cur, cur->first_idx);
        }
    }

    return para_log_rcy_stream_prime(stream);
}

status_t para_log_rcy_stream_peek(para_log_rcy_stream_t *stream, log_group_t **group)
{
    uint32 i;
    int32 best = -1;
    uint64 best_lsn = OG_INVALID_ID64;
    uint64 skipped_stale = 0;
    log_group_t *tmp;
    para_log_rcy_cursor_t *cur;

    *group = NULL;
    if (stream == NULL || stream->done) {
        return OG_SUCCESS;
    }

    if (stream->peeked_writer >= 0) {
        *group = para_log_rcy_cursor_group(&stream->cursors[stream->peeked_writer]);
        return OG_SUCCESS;
    }

    for (i = 0; i < stream->writer_count; i++) {
        cur = &stream->cursors[i];

        for (;;) {
            if (!cur->has_group && !cur->eof) {
                if (para_log_rcy_cursor_load_group(cur) != OG_SUCCESS) {
                    return OG_ERROR;
                }
            }

            if (!cur->has_group) {
                break;
            }

            tmp = para_log_rcy_cursor_group(cur);

            if (tmp->commit_lsn < stream->expected) {
                skipped_stale++;
                OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA RCY] skip stale group=%u file=%u off=%lld commit_lsn=%llu expected=%llu",
                                     i, cur->file_idx, cur->offset, tmp->commit_lsn, stream->expected);
                para_log_rcy_cursor_advance(cur);
                continue;
            }

            if (best < 0 || tmp->commit_lsn < best_lsn) {
                best = (int32)i;
                best_lsn = tmp->commit_lsn;
            }

            break;
        }
    }

    if (best < 0 || best_lsn != stream->expected) {
        stream->done = OG_TRUE;
        stream->recovered_end = (stream->expected > 0) ? (stream->expected - 1) : 0;
        OG_LOG_RUN_INF("[PARA RCY] node=%u prefix end commit_lsn=%llu expected=%llu next_best=%llu skipped_stale=%llu",
                       stream->node_id, stream->recovered_end, stream->expected,
                       (best < 0) ? 0 : best_lsn, skipped_stale);
        for (i = 0; i < stream->writer_count; i++) {
            if (stream->cursors[i].has_group) {
                tmp = para_log_rcy_cursor_group(&stream->cursors[i]);
                OG_LOG_RUN_INF("[PARA RCY] writer=%u next_commit_lsn=%llu file=%u off=%lld eof=%u",
                               i, tmp->commit_lsn, stream->cursors[i].file_idx,
                               stream->cursors[i].offset, stream->cursors[i].eof);
            } else {
                OG_LOG_RUN_INF("[PARA RCY] writer=%u no_group file=%u eof=%u",
                               i, stream->cursors[i].file_idx, stream->cursors[i].eof);
            }
        }

        return OG_SUCCESS;
    }

    stream->peeked_writer = best;
    *group = para_log_rcy_cursor_group(&stream->cursors[best]);
    return OG_SUCCESS;
}

void para_log_rcy_stream_consume(para_log_rcy_stream_t *stream)
{
    para_log_rcy_cursor_t *cur;

    if (stream == NULL || stream->peeked_writer < 0) {
        return;
    }

    cur = &stream->cursors[stream->peeked_writer];
    para_log_rcy_cursor_advance(cur);
    stream->recovered_end = stream->expected;
    stream->expected++;
    stream->peeked_writer = -1;
}

uint64 para_log_rcy_stream_recovered_end(const para_log_rcy_stream_t *stream)
{
    if (stream == NULL) {
        return 0;
    }

    return stream->recovered_end;
}

static status_t para_log_rcy_zero_range(log_file_t *file, int32 handle, int64 offset, int64 len, uint32 blk_size)
{
    aligned_buf_t zbuf;
    int64 remain = len;
    int64 pos = offset;
    int32 chunk;
    errno_t ret;

    if (len <= 0) {
        return OG_SUCCESS;
    }

    if (cm_aligned_malloc((int64)SIZE_M(1), "para rcy zero", &zbuf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ret = memset_sp(zbuf.aligned_buf, (size_t)zbuf.buf_size, 0, (size_t)zbuf.buf_size);
    knl_securec_check(ret);
    while (remain > 0) {
        chunk = (int32)MIN((int64)zbuf.buf_size, remain);
        chunk = (int32)(chunk - (chunk % (int32)blk_size));
        if (chunk < (int32)blk_size) {
            break;
        }

        if (cm_write_device(file->ctrl->type, handle, pos, zbuf.aligned_buf, chunk) != OG_SUCCESS) {
            cm_aligned_free(&zbuf);
            OG_LOG_RUN_ERR("[PARA RCY] failed to zero %s offset=%lld", file->ctrl->name, pos);
            return OG_ERROR;
        }

        pos += chunk;
        remain -= chunk;
    }

    cm_aligned_free(&zbuf);
    return OG_SUCCESS;
}

static status_t para_log_rcy_save_head(knl_session_t *session, log_file_t *file, int32 handle, uint32 node_id)
{
    aligned_buf_t hbuf;
    int32 size;

    if (file == NULL || file->ctrl == NULL || handle == OG_INVALID_HANDLE) {
        return OG_ERROR;
    }

    /* Own aligned buffer: log_flush_head reuses local lgwr head buf and races with live writers. */
    size = CM_CALC_ALIGN((uint32)sizeof(log_file_head_t), file->ctrl->block_size);
    if (cm_aligned_malloc((int64)size, "para rcy head", &hbuf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    log_calc_head_checksum(session, &file->head);
    if (cm_read_device(file->ctrl->type, handle, 0, hbuf.aligned_buf, size) != OG_SUCCESS) {
        cm_aligned_free(&hbuf);
        OG_LOG_RUN_ERR("[PARA RCY] failed to read head %s", file->ctrl->name);
        return OG_ERROR;
    }

    *(log_file_head_t *)hbuf.aligned_buf = file->head;
    if (cm_write_device(file->ctrl->type, handle, 0, hbuf.aligned_buf, size) != OG_SUCCESS) {
        cm_aligned_free(&hbuf);
        OG_LOG_RUN_ERR("[PARA RCY] failed to write head %s", file->ctrl->name);
        return OG_ERROR;
    }

    if (para_log_fredosync(file->ctrl->type, handle) != OG_SUCCESS) {
        cm_aligned_free(&hbuf);
        OG_LOG_RUN_ERR("[PARA RCY] failed to sync head %s", file->ctrl->name);
        return OG_ERROR;
    }

    cm_aligned_free(&hbuf);
    if (db_save_log_ctrl(session, (uint32)file->ctrl->file_id, node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static void para_log_rcy_init_keep_from_rcy_off(para_log_rcy_cursor_t *cur, uint32 *keep_file, int64 *keep_end)
{
    uint32 idx;
    uint32 start;

    if (cur->rcy_lsn == 0 || cur->compact_count == 0) {
        return;
    }

    start = cur->first_idx;
    idx = start;
    do {
        if (para_log_rcy_file_usable(cur, idx)) {
            log_file_t *file = cur->files[idx];
            uint64 hdr = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            uint64 rcy_off = file->head.rcy_off;

            if (rcy_off > hdr && (int64)rcy_off <= (int64)file->ctrl->size) {
                *keep_file = idx;
                *keep_end = (int64)rcy_off;
            }
        }

        if (idx == cur->last_idx) {
            break;
        }
        CM_CYCLED_MOVE_NEXT(cur->compact_count, idx);
    } while (idx != start);
}

static status_t para_log_rcy_truncate_writer(knl_session_t *session, uint8 node_id, uint32 group_id,
                                             uint64 recovered_end, const int32 *handles)
{
    para_log_rcy_cursor_t cur;
    log_group_t *group;
    uint32 keep_file = OG_INVALID_ID32;
    int64 keep_end = 0;
    int64 scan_end = 0;
    uint32 scan_file = OG_INVALID_ID32;

    if (para_log_rcy_cursor_open(session, node_id, group_id, handles, recovered_end, &cur) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cur.compact_count == 0 || cur.eof) {
        para_log_rcy_cursor_close(&cur);
        return OG_SUCCESS;
    }

    para_log_rcy_init_keep_from_rcy_off(&cur, &keep_file, &keep_end);

    while (!cur.eof) {
        if (para_log_rcy_cursor_load_group(&cur) != OG_SUCCESS) {
            para_log_rcy_cursor_close(&cur);
            return OG_ERROR;
        }

        if (!cur.has_group) {
            break;
        }

        group = para_log_rcy_cursor_group(&cur);
        scan_file = cur.file_idx;
        scan_end = cur.offset + (int64)PARA_LOG_GROUP_DISK_SIZE(group);
        if (group->commit_lsn <= recovered_end) {
            keep_file = cur.file_idx;
            keep_end = scan_end;
        }

        para_log_rcy_cursor_advance(&cur);
    }

    if (keep_file != OG_INVALID_ID32) {
        log_file_t *file = cur.files[keep_file];
        uint32 blk = cur.blk_size;
        int64 new_pos = (int64)CM_CALC_ALIGN((uint64)keep_end, blk);
        int64 old_pos = (int64)file->head.write_pos;
        int64 zero_to = MAX(old_pos, scan_end);
        if (scan_file != keep_file) {
            zero_to = MAX(zero_to, file->ctrl->size);
        }

        if (zero_to > new_pos) {
            int64 zlen = zero_to - new_pos;
            zlen = zlen - (zlen % (int64)blk);
            if (para_log_rcy_zero_range(file, cur.handles[keep_file], new_pos, zlen, blk) != OG_SUCCESS) {
                para_log_rcy_cursor_close(&cur);
                return OG_ERROR;
            }
        }

        file->head.write_pos = (uint64)new_pos;
        if (file->head.last_lsn > recovered_end) {
            file->head.last_lsn = recovered_end;
        }
        file->head.rcy_off = (uint64)new_pos;

        if (para_log_rcy_save_head(session, file, cur.handles[keep_file], node_id) != OG_SUCCESS) {
            para_log_rcy_cursor_close(&cur);
            return OG_ERROR;
        }

        if (node_id == session->kernel->id && session->kernel->para_log_ctx[group_id] != NULL) {
            para_log_context_t *ogx = session->kernel->para_log_ctx[group_id];
            ogx->curr_file = (uint16)keep_file;
            ogx->file_write_pos = file->head.write_pos;
            if (para_log_file_slot_valid(ogx, keep_file)) {
                ogx->file_max_lsn[keep_file] = recovered_end;
            }
        }

        dtc_get_ctrl(session, node_id)->para_log_last[group_id] = keep_file;
        OG_LOG_RUN_INF("[PARA RCY] truncate node=%u group=%u keep_slot=%u write_pos=%llu recovered_end=%llu",
                       node_id, group_id, keep_file, file->head.write_pos, recovered_end);
    }

    if (keep_file != OG_INVALID_ID32 && scan_file != OG_INVALID_ID32 && scan_file != keep_file) {
        uint32 idx = keep_file;
        while (idx != cur.last_idx) {
            CM_CYCLED_MOVE_NEXT(cur.compact_count, idx);
            if (!para_log_rcy_file_usable(&cur, idx)) {
                if (idx == cur.last_idx) {
                    break;
                }

                continue;
            }

            log_file_t *file = cur.files[idx];
            uint32 blk = file->ctrl->block_size;
            int64 hdr = (int64)CM_CALC_ALIGN(sizeof(log_file_head_t), blk);
            int64 old_pos = (int64)file->head.write_pos;
            if (old_pos > hdr) {
                int64 zlen = old_pos - hdr;
                zlen = zlen - (zlen % (int64)blk);
                (void)para_log_rcy_zero_range(file, cur.handles[idx], hdr, zlen, blk);
            }

            file->head.write_pos = (uint64)hdr;
            file->head.last_lsn = 0;
            file->head.rcy_off = 0;
            (void)para_log_rcy_save_head(session, file, cur.handles[idx], node_id);
            if (idx == cur.last_idx) {
                break;
            }
        }
    }

    para_log_rcy_cursor_close(&cur);
    return OG_SUCCESS;
}

status_t para_log_rcy_apply_reset(knl_session_t *session, uint8 node_id, uint64 recovered_end, uint64 last_curr_lsn,
                                  const int32 *handles)
{
    uint32 writers = SYS_NUMA_GROUP_COUNT;
    uint32 i;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);

    OG_LOG_RUN_INF("[PARA RCY] apply reset node=%u recovered_end=%llu last_curr_lsn=%llu", node_id, recovered_end,
                   last_curr_lsn);
    for (i = 0; i < writers; i++) {
        if (para_log_rcy_truncate_writer(session, node_id, i, recovered_end, handles) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (node_id == session->kernel->id) {
        log_context_t *ogx = &session->kernel->redo_ctx;
        para_log_flush_lsn_bitmap_t *bm = session->kernel->para_log_bitmap;
        {
            uint64 ctl_lsn = (uint64)cm_atomic_get(&session->kernel->lsn);

            if (last_curr_lsn > ctl_lsn) {
                ctl_lsn = last_curr_lsn;
            }

            if (recovered_end > ctl_lsn) {
                ctl_lsn = recovered_end;
            }

            para_log_reset_lsn_ctl(session->kernel, recovered_end, ctl_lsn);
        }

        cm_atomic_set((atomic_t *)&ogx->flushed_lsn, (int64)recovered_end);
        cm_atomic_set((atomic_t *)&ogx->flushed_lfn, (int64)recovered_end);
        if (bm != NULL) {
            errno_t ret = memset_sp((void *)bm->bitmap, sizeof(bm->bitmap), 0, sizeof(bm->bitmap));
            knl_securec_check(ret);
            bm->base_lsn = recovered_end;
            bm->max_marked_lsn = recovered_end;
            bm->flushed_lsn = recovered_end;
        }

        ogx->curr_point.asn = 0;
        ogx->curr_point.block_id = 0;
        ogx->curr_point.rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
        ogx->curr_point.lfn = recovered_end;
        ogx->curr_point.lsn = recovered_end;

        for (i = 0; i < writers; i++) {
            para_log_context_t *para_ogx = session->kernel->para_log_ctx[i];

            if (para_ogx == NULL) {
                continue;
            }

            para_log_rebuild_free_size(para_ogx);
            OG_LOG_RUN_INF("[PARA LOG] apply reset rebuild free group=%u active=%u curr=%u free=%lld",
                           i, para_ogx->active_file, para_ogx->curr_file,
                           (int64)cm_atomic_get(&para_ogx->free_size));
        }
    }

    ctrl->rcy_point.asn = 0;
    ctrl->rcy_point.block_id = 0;
    ctrl->rcy_point.lsn = recovered_end;
    ctrl->rcy_point.lfn = recovered_end;
    ctrl->lrp_point.asn = 0;
    ctrl->lrp_point.block_id = 0;
    ctrl->lrp_point.lsn = recovered_end;
    ctrl->lrp_point.lfn = recovered_end;
    ctrl->consistent_lfn = recovered_end;
    ctrl->lfn = recovered_end;
    if (last_curr_lsn > ctrl->lsn) {
        ctrl->lsn = last_curr_lsn;
    }

    if (dtc_save_ctrl(session, node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t para_log_recover(knl_session_t *session)
{
    para_log_rcy_stream_t *stream = NULL;
    log_group_t *group = NULL;
    log_context_t *ogx = &session->kernel->redo_ctx;
    dtc_node_ctrl_t *ctrl = dtc_my_ctrl(session);
    uint64 rcy_lsn = ctrl->rcy_point.lsn;
    uint64 recovered_end;
    logfile_set_t *set = MY_LOGFILE_SET(session);
    int32 handles[OG_MAX_LOG_FILES];
    uint32 i;

    for (i = 0; i < OG_MAX_LOG_FILES; i++) {
        handles[i] = OG_INVALID_HANDLE;
    }

    for (i = 0; i < set->logfile_hwm && i < OG_MAX_LOG_FILES; i++) {
        handles[i] = set->items[i].handle;
    }

    OG_LOG_RUN_INF("[PARA RCY] recover begin node=%u rcy_lsn=%llu rcy_lfn=%llu lrp_lsn=%llu lrp_lfn=%llu",
                   session->kernel->id, rcy_lsn, (uint64)ctrl->rcy_point.lfn, ctrl->lrp_point.lsn,
                   (uint64)ctrl->lrp_point.lfn);

    if (session->kernel->rcy_ctx.max_scn != OG_INVALID_ID64) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "PITR until time with parallel log flush");
        OG_LOG_RUN_ERR("[PARA RCY] parallel log flush does not support time-based PITR");
        return OG_ERROR;
    }

    if (para_log_rcy_stream_create(session, (uint8)session->kernel->id, rcy_lsn, handles, &stream) != OG_SUCCESS) {
        return OG_ERROR;
    }

    {
        uint64 replayed = 0;
        for (;;) {
            if (para_log_rcy_stream_peek(stream, &group) != OG_SUCCESS) {
                para_log_rcy_stream_close(stream);
                return OG_ERROR;
            }

            if (group == NULL) {
                break;
            }

            if (rcy_replay_group(session, ogx, group) != OG_SUCCESS) {
                para_log_rcy_stream_close(stream);
                return OG_ERROR;
            }

            replayed++;
            if ((replayed & 0x3FFF) == 0) {
                OG_LOG_RUN_INF("[PARA RCY] replay progress groups=%llu commit_lsn=%llu curr_lsn=%llu",
                               replayed, group->commit_lsn, group->lsn);
            }

            DB_SET_LSN(session->kernel->lsn, group->lsn);
            DB_SET_LFN(&ogx->lfn, group->commit_lsn);
            para_log_rcy_stream_consume(stream);
        }

        recovered_end = para_log_rcy_stream_recovered_end(stream);
        OG_LOG_RUN_INF("[PARA RCY] replay finished groups=%llu recovered_end=%llu", replayed, recovered_end);
    }

    para_log_rcy_stream_close(stream);

    if (recovered_end < ctrl->lrp_point.lfn && !RCY_IGNORE_CORRUPTED_LOG(&session->kernel->rcy_ctx)) {
        OG_THROW_ERROR(ERR_INVALID_RCV_END_POINT, 0, 0, ctrl->lrp_point.asn, ctrl->lrp_point.block_id);
        OG_LOG_RUN_ERR("[PARA RCY] recover end %llu < lrp %llu", recovered_end, (uint64)ctrl->lrp_point.lfn);
        return OG_ERROR;
    }

    if (para_log_rcy_apply_reset(session, (uint8)session->kernel->id, recovered_end, session->kernel->lsn,
                                handles) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[PARA RCY] single-node recover done recovered_end=%llu kernel_lsn=%llu", recovered_end,
                   (uint64)session->kernel->lsn);
    return OG_SUCCESS;
}
