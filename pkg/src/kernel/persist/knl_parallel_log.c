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

static inline bool32 para_log_lsn_in_page_space(uint64 lsn, uint64 curr_hi)
{
    if (lsn == 0 || lsn == OG_INVALID_ID64) {
        return OG_FALSE;
    }

    return (bool32)(lsn <= curr_hi);
}

static inline bool32 para_log_rcy_group_before_ckpt(const log_group_t *hdr, uint64 rcy_lsn)
{
    if (rcy_lsn == 0 || hdr == NULL) {
        return OG_FALSE;
    }

    return (bool32)(hdr->lsn <= rcy_lsn);
}

/* Previous ASN leftover on a reused CURRENT file. Do not use "LSN decreased along offset"
 * as EOF — that misses valid same-gen groups (9914d98d). Primary leftover stop is
 * para_log_rcy_group_wrong_asn; first_lsn is only a defense for unstamped groups. */
static inline bool32 para_log_rcy_group_foreign_gen(const log_group_t *hdr, uint64 first_lsn)
{
    if (first_lsn == 0 || hdr == NULL) {
        return OG_FALSE;
    }

    return (bool32)(hdr->lsn + PARA_LOG_RCY_GEN_INVERT_SLACK < first_lsn);
}

static inline bool32 para_log_rcy_group_wrong_asn(const log_group_t *hdr, uint32 file_asn)
{
    if (hdr == NULL || file_asn == 0 || file_asn == OG_INVALID_ASN) {
        return OG_FALSE;
    }

    /* Unstamped groups cannot be judged by ASN; first_lsn heuristic remains as defense. */
    if (hdr->asn == 0 || hdr->asn == OG_INVALID_ASN) {
        return OG_FALSE;
    }

    return (bool32)(hdr->asn != file_asn);
}

static inline void para_log_stamp_group_file(log_group_t *group, const log_file_t *file)
{
    if (group == NULL || file == NULL) {
        return;
    }

    group->asn = file->head.asn;
    group->rst_id = file->head.rst_id;
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

uint32 para_log_file_lgwr_count(void)
{
    uint32 groups = SYS_NUMA_GROUP_COUNT;

    if (groups == 0) {
        return 1;
    }
    return groups;
}

uint32 para_log_group_to_numa(uint32 group_id)
{
    /* Return group_id when lgwr to WAL group is 1:1 */
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 nodes = para_log_file_lgwr_count();

    if (groups == 0) {
        return 0;
    }
    return group_id * nodes / groups;
}

uint32 para_log_numa_home_group(uint32 numa_id)
{
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 nodes = para_log_file_lgwr_count();

    if (nodes == 0) {
        return 0;
    }
    return numa_id * groups / nodes;
}

uint32 para_log_numa_group_end(uint32 numa_id)
{
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 nodes = para_log_file_lgwr_count();

    if (nodes == 0) {
        return groups;
    }
    return (numa_id + 1) * groups / nodes;
}

static uint64 para_log_home_flush_buf_size(uint32 file_numa, uint64 per_group_wal)
{
    uint32 begin = para_log_numa_home_group(file_numa);
    uint32 end = para_log_numa_group_end(file_numa);
    uint32 nsrc = (end > begin) ? (end - begin) : 1;
    uint64 size = per_group_wal * (uint64)nsrc + SIZE_K(8);

    if (size < PARA_LOG_FLUSH_BATCH_SIZE) {
        size = PARA_LOG_FLUSH_BATCH_SIZE;
    }
    return size;
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

para_log_context_t *para_log_file_ogx_of(const knl_session_t *session, const para_log_context_t *ogx)
{
    uint32 home;

    if (session == NULL || session->kernel == NULL || ogx == NULL) {
        return NULL;
    }

    home = para_log_numa_home_group(ogx->file_numa_id);
    if (home >= CPU_SEG_MAX_NUM) {
        return NULL;
    }
    return session->kernel->para_log_ctx[home];
}

static void para_log_dfx_dump(knl_session_t *session, para_log_context_t *ogx, const char *reason)
{
    log_context_t *redo;
    log_file_t *file = NULL;
    const char *fname = "-";
    uint32 asn = 0;
    uint64 wpos = 0;
    uint64 file_max = 0;
    uint64 flushed;

    if (ogx == NULL || session == NULL || session->kernel == NULL) {
        return;
    }

    if (!ENABLE_PARA_LOG_DFX(session)) {
        return;
    }

    redo = &session->kernel->redo_ctx;
    if (para_log_file_slot_valid(ogx, ogx->curr_file)) {
        file = ogx->files[ogx->curr_file];
        file_max = ogx->file_max_lsn[ogx->curr_file];
        if (file != NULL && file->ctrl != NULL) {
            fname = file->ctrl->name;
            asn = file->head.asn;
            wpos = file->head.write_pos;
        }
    }

    flushed = cm_atomic_barrier_read(&redo->flushed_lsn);
    OG_LOG_RUN_INF("[PARA LOG] stat reason=%s group=%u writes=%llu wbytes=%llu wretry=%llu slot_wait=%llu "
                   "flush=%llu fbytes=%llu fentries=%llu empty=%llu hold=%llu commit_loop=%llu switch=%llu "
                   "recycle=%llu active=%u curr=%u file=%s asn=%u wpos=%llu file_max_lsn=%llu free=%lld "
                   "flushed_curr=%llu flushed_lrc=%d",
                   (reason == NULL) ? "-" : reason, ogx->thread_idx, ogx->dfx.write_cnt, ogx->dfx.write_bytes,
                   ogx->dfx.write_retry, ogx->dfx.slot_wait, ogx->dfx.flush_cnt, ogx->dfx.flush_bytes,
                   ogx->dfx.flush_entries, ogx->dfx.empty_poll, ogx->dfx.flush_hold, ogx->dfx.commit_wait_loop,
                   ogx->dfx.switch_cnt, ogx->dfx.recycle_cnt, ogx->active_file, ogx->curr_file, fname, asn, wpos,
                   file_max, (int64)cm_atomic_get(&ogx->free_size), flushed,
                   para_log_lrc_load_acquire(&ogx->last_flushed_lrc));
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
    uint64 flush_buf_size = PARA_LOG_FLUSH_BATCH_SIZE;
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

    for (uint32 i = 0; i < cluster_count; i++) {
        uint32 phys_numa = 0;
        uint32 file_numa;
        uint32 home_group;

        if (numa_count > 0) {
            phys_numa = i * numa_count / cluster_count;
        }
        file_numa = para_log_group_to_numa(i);
        home_group = para_log_numa_home_group(file_numa);
        if (i == home_group) {
            flush_buf_size = para_log_home_flush_buf_size(file_numa, per_numa_buffer_size);
        } else {
            flush_buf_size = PARA_LOG_FLUSH_BATCH_SIZE;
        }

        session->kernel->para_log_ctx[i] = (para_log_context_t *)numa_alloc_onnode(sizeof(para_log_context_t), (int)phys_numa);
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
        ogx->file_numa_id = file_numa;
        ogx->session = lgwr_se;
        ogx->tx_queue.atomic_first = (int64)NULL;
        ogx->leader_wait_cond.futex = 0;
        (void)cm_atomic32_set(&ogx->lrc_wake_seq, 0);
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
        buf_ctx->status_table = (para_log_ins_status_ent_t *)numa_alloc_onnode(buf_ctx->status_tbl_size, (int)phys_numa);
        if (buf_ctx->status_table == NULL) {
            OG_LOG_RUN_ERR("failed to malloc status_table for numa %d", i);
            CM_ABORT(0, "ABORT INFO: failed to malloc status_table");
        }

        ret = memset_sp(buf_ctx->status_table, buf_ctx->status_tbl_size, 0, buf_ctx->status_tbl_size);
        knl_securec_check(ret);
        
        ogx->last_flushed_entry = -1;
        para_log_lrc_store_release(&ogx->last_flushed_lrc, -1);
        para_log_lrc_store_release(&ogx->reserved_lrc, 0);
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
        OG_LOG_RUN_INF("[PARA LOG] init group=%u phys_numa=%u file_numa=%u home=%u sid=%u wal_buf=%llu "
                       "flush_buf=%llu status_entries=%u",
                       i, phys_numa, file_numa, home_group, lgwr_se->id, per_numa_buffer_size, flush_buf_size,
                       status_entries_count);
    }

    session->kernel->para_log_init = OG_FALSE;
    OG_LOG_RUN_INF("[PARA LOG] init done groups=%u numa_nodes=%u file_lgwr=%u log_buf=%llu lgwr_session=%u",
                   cluster_count, numa_count, para_log_file_lgwr_count(), session->kernel->attr.log_buf_size,
                   (uint32)SESSION_ID_PARA_LOG_FLUSH);
    return OG_SUCCESS;

err_cleanup:
    para_log_close(session);
    return OG_ERROR;
}

/*
 * The redo layout is decided at CREATE DATABASE and cannot follow ENABLE_PARA_LOG_FLUSH: the
 * per-lane binding lives in logfile ctrl->group_id, which is only ever written there. Opening a
 * serially created database in parallel mode leaves every file in group 0 and lanes 1..N-1 with
 * no file at all, and the opposite direction hands a set of N CURRENT files to serial code that
 * assumes exactly one. Neither is detected anywhere else, so refuse the mismatch up front.
 *
 * Runs in both modes. Called before any lane state is built.
 */
status_t para_log_check_db_mode(knl_session_t *session)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    bool32 enabled = ENABLE_PARA_LOG_FLUSH(session);
    uint32 groups = SYS_NUMA_GROUP_COUNT;

    if (core->para_log_mode == PARA_LOG_DB_MODE_UNKNOWN) {
        /*
         * Control file written before the mode was recorded. Nothing to compare against, so fall
         * through: para_log_check_group_coverage() still rejects a serial layout opened in
         * parallel mode, which is the direction that corrupts redo.
         */
        OG_LOG_RUN_WAR("[PARA LOG] control file has no recorded redo layout, relying on logfile "
                       "group coverage (enable_para_log_flush=%u)", (uint32)enabled);
        return OG_SUCCESS;
    }

    if (enabled && core->para_log_mode != PARA_LOG_DB_MODE_PARA) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "enable parallel log flush on a serially created database");
        OG_LOG_RUN_ERR("[PARA LOG] database was created without parallel log flush, recreate the instance or set "
                       "ENABLE_PARA_LOG_FLUSH=FALSE");
        return OG_ERROR;
    }

    if (!enabled && core->para_log_mode == PARA_LOG_DB_MODE_PARA) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "disable parallel log flush on a database created with it");
        OG_LOG_RUN_ERR("[LOG] database was created with parallel log flush, set ENABLE_PARA_LOG_FLUSH=TRUE");
        return OG_ERROR;
    }

    /*
     * SYS_NUMA_GROUP_COUNT comes from the live hardware topology, so moving the data directory to
     * a host with a different NUMA layout silently changes the lane count. group_id was baked as
     * (file_index % create_time_groups), so any change breaks the mapping.
     */
    if (enabled && core->para_log_groups != (uint8)groups) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "open a parallel log database with a different lane group count");
        OG_LOG_RUN_ERR("[PARA LOG] database was created with %u lane groups but this instance reports %u",
                       (uint32)core->para_log_groups, groups);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/*
 * Every lane writes only into its own files, so a lane with no file has nothing to make current
 * and its lgwr would dereference files[0] == NULL. log_file_init() only rejects a group_id that
 * is out of range and para_log_file_load() only rejects too many files, so an empty lane used to
 * pass startup unnoticed.
 */
static status_t para_log_check_group_coverage(knl_session_t *session)
{
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 g;

    for (g = 0; g < groups; g++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[g];

        if (ogx == NULL) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "open parallel log flush without a context for every lane");
            OG_LOG_RUN_ERR("[PARA LOG] lane group %u has no context, groups=%u", g, groups);
            return OG_ERROR;
        }

        if (ogx->log_file_idx < OG_MIN_LOG_FILES) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "open parallel log flush with too few logfiles per lane");
            OG_LOG_RUN_ERR("[PARA LOG] lane group %u owns %u logfiles, at least %u required; the database was most "
                           "likely not created with parallel log flush",
                           g, ogx->log_file_idx, OG_MIN_LOG_FILES);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
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

/* Fill file_max_lsn from the on-disk head. Unused slots keep this too: recycle may
 * later advance active_file onto them, and a cached 0 would pin the ring forever. */
static void para_log_load_set_file_max_lsn(para_log_context_t *ogx, uint32 group_id, uint32 file_id,
                                           log_file_t *file, uint64 start_lsn)
{
    uint64 hdr_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);

    if (file->head.write_pos <= hdr_size) {
        file->head.first_lsn = 0;
        file->head.last_lsn = 0;
        ogx->file_max_lsn[file_id] = 0;
        return;
    }

    if (para_log_lsn_in_page_space(file->head.last_lsn, start_lsn)) {
        ogx->file_max_lsn[file_id] = file->head.last_lsn;
        return;
    }

    /* Has data but last_lsn not in commit space: forbid recycling by this value. */
    ogx->file_max_lsn[file_id] = OG_INVALID_ID64;
    OG_LOG_RUN_WAR("[PARA LOG] load ignore stale last_lsn group=%u slot=%u file=%s "
                   "last_lsn=%llu start_lsn=%llu write_pos=%llu",
                   group_id, file_id, file->ctrl->name, file->head.last_lsn, start_lsn, file->head.write_pos);
}

/*
 * Slots outside [active, curr] are not in this generation's ring. A previous switch
 * can leave their ctrl status ACTIVE; skip_idle only skips INACTIVE/UNUSED, so recycle
 * would later land on them and stall. Demote and persist so the slot is reusable.
 */
static status_t para_log_load_demote_unused_active(knl_session_t *session, para_log_context_t *ogx,
                                                   uint32 group_id, uint32 file_id, log_file_t *file)
{
    int32 old_status;

    if (session == NULL || ogx == NULL || file == NULL || file->ctrl == NULL) {
        return OG_SUCCESS;
    }

    if (file_id == ogx->curr_file || file_id == ogx->active_file) {
        return OG_SUCCESS;
    }

    old_status = (int32)file->ctrl->status;
    if (old_status != LOG_FILE_ACTIVE && old_status != LOG_FILE_CURRENT) {
        return OG_SUCCESS;
    }

    file->ctrl->status = LOG_FILE_INACTIVE;
    OG_LOG_RUN_INF("[PARA LOG] load demote leftover group=%u slot=%u file=%s asn=%u status %d -> INACTIVE",
                   group_id, file_id, file->ctrl->name, file->head.asn, old_status);

    if (db_save_log_ctrl(session, (uint32)file->ctrl->file_id, session->kernel->id) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PARA LOG] load demote save ctrl failed group=%u slot=%u file=%s",
                       group_id, file_id, file->ctrl->name);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t para_log_file_load(knl_session_t *session)
{
    log_context_t *ogx = &session->kernel->redo_ctx;
    uint32 group_count = SYS_NUMA_GROUP_COUNT;

    OG_RETURN_IFERR(para_log_check_group_coverage(session));

    uint64 start_lsn = (uint64)cm_atomic_get(&session->kernel->lsn);
    uint64 start_curr = dtc_my_ctrl(session)->lrp_point.lsn;
    if (start_lsn < start_curr) {
        start_lsn = start_curr;
    }

    cm_atomic_set((atomic_t *)&ogx->flushed_lsn, (int64)start_lsn);
    cm_atomic_set((atomic_t *)&ogx->flushed_lfn, (int64)ogx->flushed_lsn);

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
            para_log_load_set_file_max_lsn(para_ogx, i, file_id, file, start_lsn);
            if (!in_use) {
                if (para_log_load_demote_unused_active(session, para_ogx, i, file_id, file) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                OG_LOG_RUN_INF("[PARA LOG] load skip unused group=%u slot=%u file=%s asn=%u status=%d "
                               "write_pos=%llu file_max_lsn=%llu",
                               i, file_id, file->ctrl->name, file->head.asn, file->ctrl->status,
                               file->head.write_pos, para_ogx->file_max_lsn[file_id]);
                continue;
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
    OG_LOG_RUN_INF("[PARA LOG] file_load done start_lsn=%llu flushed=%llu groups=%u",
                   start_lsn, ogx->flushed_lsn, group_count);
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

    groups = para_log_file_lgwr_count();
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
    para_log_context_t *file_ogx;
    uint64 free_size;

    knl_panic_log(session != NULL && ogx != NULL, "para log keep space args are null");
    file_ogx = para_log_file_ogx_of(session, ogx);
    if (file_ogx == NULL) {
        file_ogx = ogx;
    }
    free_size = (uint64)cm_atomic_get(&file_ogx->free_size);
    if (free_size > para_log_keep_size(session, file_ogx)) {
        return OG_TRUE;
    }

    /* When an INACTIVE slot is available to switch to, do not stall business because CURRENT tail is below KEEP */
    return para_log_has_inactive_slot(file_ogx);
}

void para_log_wait_keep_space(knl_session_t *session, para_log_context_t *ogx)
{
    para_log_context_t *file_ogx;

    knl_panic_log(session != NULL && ogx != NULL, "para log keep wait args are null");
    file_ogx = para_log_file_ogx_of(session, ogx);
    if (file_ogx == NULL) {
        file_ogx = ogx;
    }
    ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
    (void)cm_futex_wait(&file_ogx->space_futex, PARA_LOG_SPACE_WAIT_SLICE_MS);
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

static void para_log_write_file_head(para_log_context_t *ogx, log_file_t *file)
{
    char *log_head_buf = ogx->logwr_head_buf;
    int32 size;

    if (file->ctrl->type == DEV_TYPE_ULOG) {
        return;
    }

    log_calc_head_checksum(ogx->session, &file->head);

    /* since rebuild ctrlfiles was supported, the log file ctrl info was backup in the first block of log file. in
     * order not to overwrite it, we need to read it before write in flush log file head */
    size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
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
}

static void para_log_flush_head(para_log_context_t *ogx, log_file_t *file)
{
    if (file->ctrl->type == DEV_TYPE_ULOG) {
        OG_LOG_RUN_INF("NO need flush head for ulog %s.", file->ctrl->name);
        return;
    }

    para_log_write_file_head(ogx, file);

    if (para_log_fredosync(file->ctrl->type, file->handle) != OG_SUCCESS) {
        OG_LOG_ALARM(WARN_FLUSHREDO, "'file-name':'%s'}", file->ctrl->name);
        CM_ABORT(0, "[LOG] ABORT INFO: fdatasync redo file head %s failed.", file->ctrl->name);
    }

    OG_LOG_DEBUG_INF("Flush log[%u] head with asn %u status %d rcy_off %llu write_pos=%llu first_lsn=%llu",
                     file->ctrl->file_id, file->head.asn, file->ctrl->status, file->head.rcy_off, file->head.write_pos,
                     file->head.first_lsn);
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
            if (!para_log_lsn_in_page_space(last_lsn, rcy_lsn) || wpos <= hdr) {
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
        /* Recycle marks slots INACTIVE (not UNUSED). Skip both so a just-recycled
         * slot between active and curr does not fail the ASN walk. */
        if (logfile->ctrl->status == LOG_FILE_UNUSED || logfile->ctrl->status == LOG_FILE_INACTIVE) {
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
    uint32 i;

    /*
     * After recovery, drop already-checkpointed files before the ASN walk.
     * A stale file_max_lsn=0 used to pin active_file on an old slot; later
     * switches reused the other slots and left a hole (e.g. asn 3 then 6)
     * that this check would reject, refusing OPEN.
     */
    for (i = 0; i < group_count; i++) {
        para_log_recycle_file(session, i, NULL);
    }

    for (i = 0; i < group_count; i++) {
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

/*
 * Snapshot the per-lane flush barrier: the last LRC reserved in each lane at the moment
 * self_flush starts. Waiting on the live reservation counter instead (as para_log_need_flush
 * does) makes the target move with incoming traffic, so under sustained write load the waiter
 * never catches up and the 60s guard aborts the instance.
 *
 * The reservation counter inside the 128-bit ctl is read rather than the cached reserved_lrc:
 * reserved_lrc is published after the CAS, so concurrent reservers can make it momentarily go
 * backwards and understate the barrier. The commit path avoids touching the ctl cache line on
 * purpose, but self_flush runs per checkpoint, not per commit, so one load per lane is free.
 */
static void para_log_snap_flush_lrc(knl_session_t *session, int32 *targets, uint32 groups)
{
    uint32 g;

    for (g = 0; g < groups; g++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[g];
        int32 flushed;
        int32 next_lrc;

        if (ogx == NULL) {
            targets[g] = -1;
            continue;
        }

        flushed = para_log_lrc_load_acquire(&ogx->last_flushed_lrc);
        next_lrc = (int32)cm_atomic32_get((atomic32_t *)&ogx->log_buf_ctx.ctl.struct128.curr_lrc);
        if (next_lrc == 0) {
            targets[g] = (flushed < 0) ? -1 : 0x7FFFFFFF;
            continue;
        }
        targets[g] = next_lrc - 1;
    }
}

static bool32 para_log_flush_lrc_reached(knl_session_t *session, const int32 *targets, uint32 groups,
                                         uint32 *lag_group)
{
    uint32 g;

    for (g = 0; g < groups; g++) {
        para_log_context_t *ogx = session->kernel->para_log_ctx[g];

        if (ogx == NULL) {
            continue;
        }

        if (!para_log_lrc_reached(para_log_lrc_load_acquire(&ogx->last_flushed_lrc), targets[g])) {
            *lag_group = g;
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

/*
 * Resolve the LSN used to decide recycle. Cached file_max_lsn may be 0 when:
 *  - the slot was unused at load, then active_file later advanced onto it, or
 *  - switch zeroed the cache and no flush has published a new last_lsn yet.
 * Treating 0 as "not in page LSN space" pins active_file and the ring wraps
 * around the stuck slot, creating an ASN hole. Fall back to the file head;
 * header-only files are empty and recyclable.
 */
static bool32 para_log_recycle_resolve_max_lsn(para_log_context_t *ogx, uint32 file_id, log_file_t *file,
                                               uint64 curr_hi, uint64 *max_lsn)
{
    uint64 cached;
    uint64 hdr;

    cached = ogx->file_max_lsn[file_id];
    if (para_log_lsn_in_page_space(cached, curr_hi)) {
        *max_lsn = cached;
        return OG_TRUE;
    }

    if (para_log_lsn_in_page_space(file->head.last_lsn, curr_hi)) {
        ogx->file_max_lsn[file_id] = file->head.last_lsn;
        *max_lsn = file->head.last_lsn;
        OG_LOG_RUN_INF("[PARA LOG] recycle refresh max_lsn group=%u slot=%u file=%s from_head=%llu",
                       ogx->thread_idx, file_id, file->ctrl->name, file->head.last_lsn);
        return OG_TRUE;
    }

    hdr = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    if (file->head.write_pos <= hdr) {
        ogx->file_max_lsn[file_id] = 0;
        *max_lsn = 0;
        return OG_TRUE;
    }

    *max_lsn = cached;
    return OG_FALSE;
}

static bool32 para_log_recycle_skip_idle(knl_session_t *session, para_log_context_t *ogx, uint32 *file_id)
{
    uint32 scanned = 0;
    uint32 file_count = para_log_file_slot_count(ogx);

    for (;;) {
        log_file_t *file;

        if (!para_log_file_slot_valid(ogx, *file_id) || ogx->files[*file_id] == NULL ||
            ogx->files[*file_id]->ctrl == NULL) {
            return OG_FALSE;
        }

        file = ogx->files[*file_id];
        if (*file_id == ogx->curr_file || file->ctrl->status == LOG_FILE_ACTIVE ||
            file->ctrl->status == LOG_FILE_CURRENT) {
            return OG_TRUE;
        }

        OG_LOG_RUN_INF("[PARA LOG] recycle skip idle group=%u slot=%u status=%u", ogx->thread_idx, *file_id,
                       file->ctrl->status);
        if (!para_log_get_next_file(session, ogx, file_id, OG_FALSE, OG_FALSE)) {
            return OG_FALSE;
        }
        scanned++;
        if (scanned > file_count) {
            return OG_FALSE;
        }
    }
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

    rcy_lsn = dtc_my_ctrl(session)->rcy_point.lsn;
    if (point != NULL && point->lsn < rcy_lsn) {
        rcy_lsn = point->lsn;
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

        if (file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED) {
            if (!para_log_recycle_skip_idle(session, ogx, &file_id)) {
                break;
            }
            ogx->active_file = (uint16)file_id;
            dtc_my_ctrl(session)->para_log_first[group_id] = (uint32)file_id;
            continue;
        }

        // Archive check (inlined because log_can_recycle is static in knl_log.c, not visible across files)
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
            uint64 max_lsn = 0;
            uint64 curr_hi = (uint64)cm_atomic_get(&session->kernel->lsn);

            if (!para_log_recycle_resolve_max_lsn(ogx, file_id, file, curr_hi, &max_lsn)) {
                OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                     "[PARA LOG] recycle blocked group=%u slot=%u file=%s max_lsn=%llu "
                                     "rcy_lsn=%llu (not in page LSN space)",
                                     group_id, file_id, file->ctrl->name, max_lsn, rcy_lsn);
                break;
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
        /*
         * The lgwr picks its next file by scanning for an INACTIVE/UNUSED slot and does so
         * without log_lock_logfile, so ctrl->status is what publishes the slot as reusable.
         * Reset the header and credit the free size first and only then flip the status,
         * otherwise a concurrent para_log_switch_file() can grab the slot, write its new
         * header and start appending, and the resets below would wipe that header back to
         * OG_INVALID_ASN / an empty write_pos - losing the whole file worth of WAL.
         */
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

        CM_MFENCE;
        file->ctrl->archived = OG_FALSE;
        file->ctrl->status = LOG_FILE_INACTIVE;

        para_log_wake_space_waiters(ogx);
        (void)para_log_get_next_file(session, ogx, &file_id, OG_FALSE, OG_FALSE);
        if (!para_log_recycle_skip_idle(session, ogx, &file_id)) {
            break;
        }

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
    para_log_context_t *home;

    if (ogx == NULL || ogx->session == NULL) {
        return OG_FALSE;
    }

    home = para_log_file_ogx_of(ogx->session, ogx);
    if (home == NULL) {
        home = (para_log_context_t *)ogx;
    }
    return (bool32)(home->thread.id != 0 && !home->thread.closed);
}

static void para_log_kick_writer(para_log_context_t *ogx, bool32 new_req)
{
    para_log_context_t *home;

    if (ogx == NULL) {
        return;
    }

    home = (ogx->session != NULL) ? para_log_file_ogx_of(ogx->session, ogx) : ogx;
    if (home == NULL) {
        home = ogx;
    }

    if (new_req) {
        (void)cm_atomic_inc(&home->flush_req);
    }

    cm_futex_wake(&home->kick_futex, 1);
}

static status_t para_log_direct_flush_group(knl_session_t *session, para_log_context_t *ogx, uint32 group_id)
{
    para_log_context_t *file_ogx;
    status_t flush_ret;

    file_ogx = para_log_file_ogx_of(session, ogx);
    if (file_ogx == NULL) {
        file_ogx = ogx;
    }

    cm_spin_lock(&file_ogx->b_flush_lock.lock, &session->stat->spin_stat.stat_log_flush);
    flush_ret = para_log_flush_by_numa(session, group_id);
    cm_spin_unlock(&file_ogx->b_flush_lock.lock);
    para_log_wait_if_switch_blocked(session, file_ogx);
    para_log_persist_ctrl_if_dirty(session, file_ogx);
    para_log_dfx_dump_due(session, file_ogx);

    return flush_ret;
}

status_t para_log_self_flush(knl_session_t *session, log_point_t *point, knl_scn_t *scn, uint64 *lsn)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    status_t result = OG_SUCCESS;
    uint32 lgwr_count = para_log_file_lgwr_count();
    uint64 durable_lsn;
    uint32 wait_loops = 0;
    bool32 any_writer = OG_FALSE;
    date_t wait_begin;
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 lag_group = 0;
    int32 targets[KNL_PARA_LOG_MAX_GROUPS];

    wait_begin = cm_now();
    if (groups > KNL_PARA_LOG_MAX_GROUPS) {
        groups = KNL_PARA_LOG_MAX_GROUPS;
    }
    para_log_snap_flush_lrc(session, targets, groups);

    for (uint32 numa = 0; numa < lgwr_count; numa++) {
        uint32 home = para_log_numa_home_group(numa);
        para_log_context_t *ogx = session->kernel->para_log_ctx[home];
        status_t flush_ret;

        if (ogx == NULL) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] self_flush skip uninitialized file_numa=%u home=%u", numa, home);
            continue;
        }

        if (para_log_writer_alive(ogx)) {
            para_log_kick_writer(ogx, OG_TRUE);
            any_writer = OG_TRUE;
            continue;
        }

        flush_ret = para_log_direct_flush_group(session, ogx, home);
        if (flush_ret != OG_SUCCESS) {
            result = flush_ret;
        }
    }

    while (!para_log_flush_lrc_reached(session, targets, groups, &lag_group)) {
        bool32 alive = OG_FALSE;
        para_log_context_t *wait_ogx = NULL;

        for (uint32 numa = 0; numa < lgwr_count; numa++) {
            uint32 home = para_log_numa_home_group(numa);
            para_log_context_t *ogx = session->kernel->para_log_ctx[home];
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
                flush_ret = para_log_direct_flush_group(session, ogx, home);
                if (flush_ret != OG_SUCCESS) {
                    result = flush_ret;
                }
            }
        }

        if (!alive) {
            break;
        }

        if (para_log_wait_timed_out(wait_begin)) {
            para_log_context_t *lag_ogx = session->kernel->para_log_ctx[lag_group];

            CM_ABORT(0, "[PARA LOG] ABORT INFO: self_flush wait timeout, lag_group=%u need_lrc=%d flushed_lrc=%d",
                     lag_group, targets[lag_group],
                     (lag_ogx == NULL) ? -1 : para_log_lrc_load_acquire(&lag_ogx->last_flushed_lrc));
        }

        if ((++wait_loops & 0x3F) == 1) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] self_flush wait lag_group=%u need_lrc=%d writers=%u", lag_group,
                                 targets[lag_group], (uint32)any_writer);
        }

        if (wait_ogx != NULL) {
            (void)cm_futex_wait(&wait_ogx->ack_futex, 5);
        } else {
            cm_spin_sleep_ex(1000);
        }
    }

    durable_lsn = cm_atomic_barrier_read(&redo_ctx->flushed_lsn);
    if (point != NULL) {
        point->asn = 0;
        point->block_id = 0;
        point->rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
        point->lfn = durable_lsn;
        point->lsn = durable_lsn;
    }

    if (scn != NULL) {
        *scn = redo_ctx->curr_scn;
    }

    if (lsn != NULL) {
        *lsn = durable_lsn;
    }

    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                         "[PARA LOG] self_flush durable_lsn=%llu curr_lsn=%llu scn=%llu signal=%u",
                         durable_lsn, DB_CURR_LSN(session), (uint64)redo_ctx->curr_scn, (uint32)any_writer);

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
        para_log_write_file_head(ogx, file);
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

/* Destination file is only known at flush (switch may happen after reserve). Restamp
 * each group + recompute CRC so leftover scan matches the file we actually wrote. */
static void para_log_stamp_linear_groups(char *buf, uint32 data_size, const log_file_t *file)
{
    uint32 off = 0;
    uint32 asn;
    uint32 rst_id;

    if (buf == NULL || file == NULL || data_size < sizeof(log_group_t)) {
        return;
    }

    asn = file->head.asn;
    rst_id = file->head.rst_id;
    if (asn == 0 || asn == OG_INVALID_ASN) {
        return;
    }

    while (off + sizeof(log_group_t) <= data_size) {
        log_group_t *hdr = (log_group_t *)(buf + off);
        uint32 actual;
        uint32 disk_size;
        uint32 cks;
        errno_t ret;

        if (hdr->size == 0) {
            break;
        }

        actual = LOG_GROUP_ACTUAL_SIZE(hdr);
        if (actual < sizeof(log_group_t) || actual > OG_MAX_LOG_GROUP_SIZE) {
            break;
        }

        disk_size = actual + PARA_LOG_GROUP_CKS_SIZE;
        if (off + disk_size > data_size) {
            break;
        }

        if (hdr->asn != asn || hdr->rst_id != rst_id) {
            hdr->asn = asn;
            hdr->rst_id = rst_id;
            cks = cm_get_checksum(hdr, actual);
            ret = memcpy_sp(buf + off + actual, PARA_LOG_GROUP_CKS_SIZE, &cks, sizeof(cks));
            knl_securec_check(ret);
        }

        off += disk_size;
    }
}

static status_t para_log_flush_to_disk(para_log_context_t *ogx, log_file_t *file, para_log_buf_ctx_t *buf_ctx,
    uint64 batch_lsn, uint64 file_pos, uint64 start_flush_pos, uint64 end_log_pos, uint32 data_size,
    uint32 aligned_size)
{
    uint64 direct_buf_addr = (uint64)(uintptr_t)(buf_ctx->buffer + start_flush_pos);
    if (end_log_pos > start_flush_pos && aligned_size == data_size &&
        ((file_pos & (file->ctrl->block_size - 1)) == 0) &&
        ((direct_buf_addr & (file->ctrl->block_size - 1)) == 0)) {
        para_log_stamp_linear_groups(buf_ctx->buffer + start_flush_pos, data_size, file);
        return para_log_flush_write_aligned(ogx, file, buf_ctx->buffer + start_flush_pos, batch_lsn, file_pos,
            data_size, aligned_size);
    }

    if (para_log_flush_stash_buf(ogx, buf_ctx, start_flush_pos, end_log_pos, data_size,
        aligned_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    para_log_stamp_linear_groups(ogx->flush_buf, data_size, file);
    return para_log_flush_write_aligned(ogx, file, ogx->flush_buf, batch_lsn, file_pos, data_size,
        aligned_size);
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

/* flushed_lsn / flushed_lfn are just high-water marks of flushed curr_lsn, not a dense prefix. */
static void para_log_note_flushed_curr(knl_session_t *session, uint64 batch_max_curr)
{
    knl_scn_t prefix_scn;

    if (batch_max_curr == 0) {
        return;
    }

    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->redo_ctx.flushed_lsn, batch_max_curr);
    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->redo_ctx.flushed_lfn, batch_max_curr);
    prefix_scn = db_next_scn(session);
    para_log_atomic_max_u64((volatile uint64 *)&session->kernel->redo_ctx.curr_scn, (uint64)prefix_scn);
}

static bool32 para_log_file_status_idle(const log_file_t *file)
{
    if (file == NULL || file->ctrl == NULL) {
        return OG_TRUE;
    }

    return (bool32)(file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED);
}

static void para_log_fix_curr_by_asn(knl_session_t *session, para_log_context_t *ogx)
{
    uint32 i;
    uint32 best_slot = OG_INVALID_ID32;
    uint32 idle_slot = OG_INVALID_ID32;
    uint32 ctrl_last;
    log_file_t *file;
    log_file_t *old_file;
    log_file_t *best;
    bool32 curr_idle = OG_TRUE;
    bool32 need_fix;

    if (ogx == NULL) {
        return;
    }

    ctrl_last = ogx->curr_file;
    if (para_log_file_slot_valid(ogx, ctrl_last)) {
        curr_idle = para_log_file_status_idle(ogx->files[ctrl_last]);
    }

    for (i = 0; i < para_log_file_slot_count(ogx); i++) {
        file = ogx->files[i];
        if (file == NULL || file->ctrl == NULL || LOG_IS_DROPPED(file->ctrl->flg) ||
            file->head.asn == OG_INVALID_ASN) {
                continue;
            }

        if (para_log_file_status_idle(file)) {
            if (idle_slot == OG_INVALID_ID32) {
                idle_slot = i;
            } else {
                log_file_t *idle = ogx->files[idle_slot];

                if (file->head.last_lsn > idle->head.last_lsn ||
                    (file->head.last_lsn == idle->head.last_lsn && file->head.asn > idle->head.asn)) {
                    idle_slot = i;
                }
            }
            continue;
        }

        if (best_slot == OG_INVALID_ID32) {
            best_slot = i;
            continue;
        }

        best = ogx->files[best_slot];
        if (file->head.asn > best->head.asn ||
            (file->head.asn == best->head.asn && file->head.last_lsn > best->head.last_lsn)) {
            best_slot = i;
        }
    }

    if (best_slot == OG_INVALID_ID32) {
        best_slot = idle_slot;
    }

    if (best_slot == OG_INVALID_ID32) {
        return;
    }

    file = ogx->files[best_slot];
    need_fix = (bool32)(best_slot != ctrl_last || curr_idle || file->ctrl->status != LOG_FILE_CURRENT);
    if (!need_fix) {
        return;
    }

    OG_LOG_RUN_INF("[PARA LOG] load recover curr by asn group=%u ctrl_last=%u last_status=%d new_curr=%u "
                   "new_asn=%u new_status=%d last_lsn=%llu",
                   ogx->thread_idx, ctrl_last,
                   (para_log_file_slot_valid(ogx, ctrl_last) && ogx->files[ctrl_last] != NULL &&
                    ogx->files[ctrl_last]->ctrl != NULL) ?
                       ogx->files[ctrl_last]->ctrl->status : -1,
                   best_slot, file->head.asn, file->ctrl->status, file->head.last_lsn);

    if (best_slot != ctrl_last && para_log_file_slot_valid(ogx, ctrl_last)) {
        old_file = ogx->files[ctrl_last];
        /* Recycled slot stays INACTIVE; do not revert to ACTIVE just because it was once curr */
        if (old_file != NULL && old_file->ctrl != NULL && old_file->ctrl->status == LOG_FILE_CURRENT) {
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

static status_t para_log_flush_by_numa_ex(knl_session_t *session, uint32 group_id);

status_t para_log_flush_by_numa(knl_session_t *session, uint32 numa_id)
{
    return para_log_flush_by_numa_ex(session, numa_id);
}

static uint32 para_log_wal_span(const para_log_buf_ctx_t *buf_ctx, uint64 start_pos, uint64 end_pos)
{
    if (end_pos == start_pos) {
        return 0;
    }
    if (end_pos > start_pos) {
        return (uint32)(end_pos - start_pos);
    }
    return (uint32)(buf_ctx->buffer_size - start_pos + end_pos);
}

static void para_log_recycle_entry_range(para_log_context_t *ogx, int32 start_idx, int32 last_idx)
{
    para_log_buf_ctx_t *buf_ctx = &ogx->log_buf_ctx;
    int32 ring_size = get_log_buf_ring_size(RD_STATUS_ENTRIES_POWER);
    int32 entry_idx = start_idx;
    uint32 recycled = 0;

    while (entry_idx != last_idx) {
        int32 idx = get_status_entry_index(RD_STATUS_ENTRIES_POWER, entry_idx);
        para_log_recycle_status_entry(&buf_ctx->status_table[idx]);
        recycled++;
        knl_panic_log(recycled <= (uint32)ring_size,
                      "para log recycle walk overflow, panic info: group=%u start=%d last=%d recycled=%u",
                      ogx->thread_idx, start_idx, last_idx, recycled);
        entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, entry_idx);
    }
    para_log_recycle_status_entry(&buf_ctx->status_table[get_status_entry_index(RD_STATUS_ENTRIES_POWER, last_idx)]);
}

static void para_log_snap_copied_lrc(knl_session_t *session)
{
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 g;
    uint32 own = session->commit_wal_group;

    if (groups > KNL_PARA_LOG_MAX_GROUPS) {
        groups = KNL_PARA_LOG_MAX_GROUPS;
    }

    for (g = 0; g < groups; g++) {
        para_log_context_t *peer = session->kernel->para_log_ctx[g];
        int32 next_lrc;
        int32 flushed_lrc;

        if (peer == NULL || g == own) {
            session->commit_copied_lrc[g] = -1;
            continue;
        }

        flushed_lrc = para_log_lrc_load_acquire(&peer->last_flushed_lrc);
        next_lrc = para_log_lrc_load_acquire(&peer->reserved_lrc);
        if (next_lrc == 0) {
            session->commit_copied_lrc[g] = (flushed_lrc < 0) ? -1 : 0x7FFFFFFF;
            continue;
        }
        session->commit_copied_lrc[g] = next_lrc - 1;
    }
}

static bool32 para_log_commit_lrc_ready(knl_session_t *session, para_log_context_t *ogx, uint32 *lag_group,
                                        int32 *lag_need, int32 *lag_flushed)
{
    uint32 groups = SYS_NUMA_GROUP_COUNT;
    uint32 g;
    int32 flushed;

    flushed = para_log_lrc_load_acquire(&ogx->last_flushed_lrc);
    if (!para_log_lrc_reached(flushed, session->curr_lrc)) {
        if (lag_group != NULL) {
            *lag_group = ogx->thread_idx;
            *lag_need = session->curr_lrc;
            *lag_flushed = flushed;
        }
        return OG_FALSE;
    }

    if (groups > KNL_PARA_LOG_MAX_GROUPS) {
        groups = KNL_PARA_LOG_MAX_GROUPS;
    }

    for (g = 0; g < groups; g++) {
        int32 need;
        para_log_context_t *peer;

        if (g == ogx->thread_idx) {
            continue;
        }

        need = session->commit_copied_lrc[g];
        if (need < 0) {
            continue;
        }

        peer = session->kernel->para_log_ctx[g];
        if (peer == NULL) {
            continue;
        }

        flushed = para_log_lrc_load_acquire(&peer->last_flushed_lrc);
        if (!para_log_lrc_reached(flushed, need)) {
            if (lag_group != NULL) {
                *lag_group = g;
                *lag_need = need;
                *lag_flushed = flushed;
            }
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static void para_log_wake_commit(para_log_context_t *ogx)
{
    (void)cm_atomic32_inc(&ogx->lrc_wake_seq);
    cm_futex_wake_value(&ogx->lrc_wake_seq, CM_FUTEX_WAKE_ALL);
}

/*
 * Flushes whatever is already COPIED in this lane, coalescing consecutive entries into one
 * write. It never waits to accumulate a larger batch: the target storage is NVMe-over-Fabrics
 * all-flash, where an extra round trip costs far more than the syscall a bigger batch saves.
 */
static status_t para_log_flush_by_numa_ex(knl_session_t *session, uint32 group_id)
{
    para_log_context_t *ogx;
    para_log_buf_ctx_t *buf_ctx;
    volatile para_log_ins_status_ent_t *start_entry_ptr;
    volatile para_log_ins_status_ent_t *curr_entry_ptr;
    volatile para_log_ins_status_ent_t *next_entry_ptr;
    log_file_t *file;
    int32 start_entry_idx;
    int32 curr_entry_idx;
    int32 next_entry_idx;
    uint64 batch_min_curr;
    uint64 batch_max_curr;
    uint64 end_log_pos;
    uint64 start_flush_pos;
    uint64 current_file_pos;
    uint64 scn;
    uint32 data_size;
    uint32 aligned_size;
    uint32 taken = 1;

    if (!session->kernel->para_log_init) {
        return OG_SUCCESS;
    }

    ogx = (group_id < CPU_SEG_MAX_NUM) ? session->kernel->para_log_ctx[group_id] : NULL;
    if (ogx == NULL) {
        return OG_SUCCESS;
    }

    buf_ctx = &ogx->log_buf_ctx;
    start_entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, ogx->last_flushed_entry);
    start_entry_ptr = &buf_ctx->status_table[start_entry_idx];

    if (para_log_status_load_acquire(start_entry_ptr) != RD_COPIED) {
        ogx->dfx.empty_poll++;
        return OG_SUCCESS;
    }

    next_entry_idx = start_entry_idx;
    next_entry_ptr = start_entry_ptr;
    batch_min_curr = cm_atomic_barrier_read(&start_entry_ptr->curr_lsn);
    batch_max_curr = batch_min_curr;

    do {
        uint64 next_curr;
        uint32 next_size;

        curr_entry_ptr = next_entry_ptr;
        curr_entry_idx = next_entry_idx;
        next_entry_idx = get_next_status_entry(RD_STATUS_ENTRIES_POWER, curr_entry_idx);
        next_entry_ptr = &buf_ctx->status_table[next_entry_idx];

        if (((cm_atomic32_get((atomic32_t *)&curr_entry_ptr->lrc) + 1) & 0x7FFFFFFF) !=
            cm_atomic32_get((atomic32_t *)&next_entry_ptr->lrc)) {
            break;
        }
        if (para_log_status_load_acquire(next_entry_ptr) == RD_NOT_COPIED) {
            break;
        }

        next_curr = cm_atomic_barrier_read(&next_entry_ptr->curr_lsn);
        end_log_pos = cm_atomic_barrier_read(&next_entry_ptr->end_log_pos);
        start_flush_pos = cm_atomic_barrier_read(&ogx->last_flushed_pos);
        next_size = para_log_wal_span(buf_ctx, start_flush_pos, end_log_pos);
        if ((uint64)next_size + SIZE_K(8) > ogx->flush_buf_size) {
            break;
        }

        if (next_curr < batch_min_curr) {
            batch_min_curr = next_curr;
        }
        if (next_curr > batch_max_curr) {
            batch_max_curr = next_curr;
        }
        taken++;
    } while (true);

    end_log_pos = cm_atomic_barrier_read(&curr_entry_ptr->end_log_pos);
    start_flush_pos = cm_atomic_barrier_read(&ogx->last_flushed_pos);
    if (start_flush_pos == end_log_pos) {
        return OG_SUCCESS;
    }

    data_size = para_log_wal_span(buf_ctx, start_flush_pos, end_log_pos);
    if (data_size == 0) {
        ogx->dfx.empty_poll++;
        return OG_SUCCESS;
    }

    if (para_log_flush_init(session, ogx, data_size) != OG_SUCCESS) {
        return OG_SUCCESS;
    }
    
    file = para_log_checked_file(ogx, ogx->curr_file);
    aligned_size = CM_CALC_ALIGN(data_size, file->ctrl->block_size);
    knl_panic_log(aligned_size <= ogx->flush_buf_size,
                  "para log aligned flush exceeds staging, aligned=%u cap=%llu",
                  aligned_size, ogx->flush_buf_size);

    current_file_pos = file->head.write_pos;
    if (batch_max_curr == 0) {
        batch_max_curr = DB_CURR_LSN(session);
    }
    if (!para_log_lsn_in_page_space(file->head.last_lsn, batch_max_curr) || file->head.last_lsn < batch_max_curr) {
        file->head.last_lsn = batch_max_curr;
    }
    if (file->head.first_lsn == 0) {
        file->head.first_lsn = (batch_min_curr != 0) ? batch_min_curr : batch_max_curr;
    }

    scn = db_next_scn(session);
    if (para_log_flush_to_disk(ogx, file, buf_ctx, batch_max_curr, current_file_pos, start_flush_pos, end_log_pos,
        data_size, aligned_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PARA LOG] flush write failed group=%u file=%s pos=%llu size=%u aligned=%u batch_lsn=%llu",
                       ogx->thread_idx, file->ctrl->name, current_file_pos, data_size, aligned_size, batch_max_curr);
        CM_ABORT(0, "[PARA LOG] ABORT INFO: log_flush_by_numa write failed.");
        return OG_ERROR;
    }

    if (file->ctrl->type != DEV_TYPE_ULOG &&
        para_log_fredosync(file->ctrl->type, file->handle) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PARA LOG] flush fdatasync failed group=%u file=%s pos=%llu size=%u",
                       ogx->thread_idx, file->ctrl->name, current_file_pos, aligned_size);
        CM_ABORT(0, "[PARA LOG] ABORT INFO: log_flush_by_numa fdatasync failed.");
        return OG_ERROR;
    }

    if (para_log_file_slot_valid(ogx, ogx->curr_file)) {
        uint64 *file_max = &ogx->file_max_lsn[ogx->curr_file];

        if (!para_log_lsn_in_page_space(*file_max, batch_max_curr) || *file_max < batch_max_curr) {
            *file_max = batch_max_curr;
        }
    }

    para_log_note_flushed_curr(session, batch_max_curr);
    {
        int32 flushed_lrc = (int32)cm_atomic32_get((atomic32_t *)&curr_entry_ptr->lrc);

        para_log_recycle_entry_range(ogx, start_entry_idx, curr_entry_idx);
        (void)cm_atomic_set_u64(&ogx->last_flushed_pos, end_log_pos);
        ogx->last_flushed_entry = curr_entry_idx;
        para_log_lrc_store_release(&ogx->last_flushed_lrc, flushed_lrc);
    }
    ogx->dfx.flush_entries += taken;

    file->head.last = scn;
    if (file->head.first == OG_INVALID_ID64) {
        file->head.first = scn;
        log_flush_head(session, file);
    }
    
    {
        log_point_t synth_pt;
        synth_pt.asn = 0;
        synth_pt.block_id = 0;
        synth_pt.rst_id = session->kernel->db.ctrl.core.resetlogs.rst_id;
        synth_pt.lfn = batch_max_curr;
        synth_pt.lsn = batch_max_curr;
        ckpt_set_trunc_point(session, &synth_pt);
    }

    ogx->dfx.flush_cnt++;
    ogx->dfx.flush_bytes += aligned_size;
    OG_LOG_DEBUG_INF("[PARA LOG] flush group=%u size=%u aligned=%u file=%s pos=%llu "
                     "min_curr=%llu max_curr=%llu flushed=%llu",
                     ogx->thread_idx, data_size, aligned_size, file->ctrl->name, current_file_pos,
                     batch_min_curr, batch_max_curr, cm_atomic_barrier_read(&session->kernel->redo_ctx.flushed_lsn));

    return OG_SUCCESS;
}

void para_log_proc(thread_t *thread)
{
    para_log_context_t *ogx = (para_log_context_t *)thread->argument;
    knl_session_t *session = ogx->session;
    uint32 cpuid = ogx->thread_idx * SYS_CPUS_PER_GROUP;
    uint32 file_numa = ogx->file_numa_id;
    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "para_log_wr_%u", ogx->thread_idx);
    cm_set_thread_name(thread_name);
    OG_LOG_RUN_INF("[PARA LOG] lgwr start group=%u file_numa=%u cpu=%u sid=%u",
                   ogx->thread_idx, file_numa, cpuid, session->id);
    cpu_set_t log_proc_set;
    CPU_ZERO(&log_proc_set);
    CPU_SET(cpuid, &log_proc_set);
    int rc = sched_setaffinity(0, sizeof(cpu_set_t), &log_proc_set);
    if (rc == -1) {
        OG_LOG_RUN_ERR("[PARA LOG] lgwr bind cpu failed group=%u cpu=%u", ogx->thread_idx, cpuid);
    }

    int32 last_notified_lrc = para_log_lrc_load_acquire(&ogx->last_flushed_lrc);

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
        (void)para_log_flush_by_numa_ex(session, ogx->thread_idx);
        cm_spin_unlock(&ogx->b_flush_lock.lock);
        para_log_wait_if_switch_blocked(session, ogx);

        if (kicked) {
            (void)cm_atomic_set(&ogx->flush_ack, (int64)req);
            cm_futex_wake(&ogx->ack_futex, 1);
        }

        int32 curr_flushed_lrc = para_log_lrc_load_acquire(&ogx->last_flushed_lrc);

        if (curr_flushed_lrc != last_notified_lrc) {
            para_log_wake_commit(ogx);
            last_notified_lrc = curr_flushed_lrc;
        }

        /* commit already woken by last_flushed_lrc; ctrl fsync deferred outside lock, retried next time on failure */
        para_log_persist_ctrl_if_dirty(session, ogx);

        para_log_dfx_dump_due(session, ogx);
    }

    para_log_dfx_dump(session, ogx, "lgwr_stop");
    OG_LOG_RUN_INF("[PARA LOG] lgwr stop group=%u", ogx->thread_idx);
}

status_t para_log_commit_flush(knl_session_t *session)
{
    para_log_context_t *ogx;
    uint32 lag_group = 0;
    int32 lag_need = -1;
    int32 lag_flushed = -1;
    uint32 wal_group;
    uint32 wait_loops = 0;
    date_t wait_begin;

    if (session->curr_lrc < 0) {
        return OG_SUCCESS;
    }
    wal_group = session->commit_wal_group;
    knl_panic_log(wal_group < CPU_SEG_MAX_NUM, "para log commit group is invalid, group=%u", wal_group);
    ogx = session->kernel->para_log_ctx[wal_group];
    knl_panic_log(ogx != NULL, "para log context is not initialized");

    knl_begin_session_wait(session, LOG_FILE_SYNC, OG_TRUE);
    wait_begin = cm_now();

    while (!para_log_commit_lrc_ready(session, ogx, &lag_group, &lag_need, &lag_flushed)) {
        para_log_context_t *lag_ogx;
        uint32 seq;

        if (para_log_wait_timed_out(wait_begin)) {
            CM_ABORT(0, "[PARA LOG] ABORT INFO: commit flush wait timeout, sid=%u group=%u own_lrc=%d "
                     "lag_group=%u need_lrc=%d flushed_lrc=%d curr_lsn=%llu",
                     session->id, ogx->thread_idx, session->curr_lrc, lag_group, lag_need, lag_flushed,
                     session->curr_lsn);
        }

        ogx->dfx.commit_wait_loop++;
        if ((++wait_loops & 0x3F) == 1) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA LOG] commit wait sid=%u group=%u own_lrc=%d flushed_lrc=%d "
                                 "lag_group=%u need_lrc=%d lag_flushed=%d loops=%u",
                                 session->id, ogx->thread_idx, session->curr_lrc,
                                 para_log_lrc_load_acquire(&ogx->last_flushed_lrc), lag_group, lag_need, lag_flushed,
                                 wait_loops);
        }

        lag_ogx = (lag_group < CPU_SEG_MAX_NUM) ? session->kernel->para_log_ctx[lag_group] : NULL;
        if (lag_ogx == NULL) {
            cm_spin_sleep_ex(1000);
            continue;
        }

        seq = (uint32)cm_atomic32_get(&lag_ogx->lrc_wake_seq);
        if (para_log_commit_lrc_ready(session, ogx, &lag_group, &lag_need, &lag_flushed)) {
                break;
            }
        if (lag_ogx->thread_idx != lag_group) {
            continue;
        }

        (void)cm_futex_wait_value(&lag_ogx->lrc_wake_seq, seq, PARA_LOG_COMMIT_WAIT_SLICE_MS);
    }

            if (session->kernel->attr.enable_boc) {
                tx_scn_broadcast(session);
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

static status_t para_log_write_wait_progress(knl_session_t *session, date_t begin)
{
    uint32 lgwr_count;
    uint32 numa;

    if (para_log_wait_timed_out(begin)) {
        return OG_TIMEDOUT;
    }

    lgwr_count = para_log_file_lgwr_count();
    for (numa = 0; numa < lgwr_count; numa++) {
        uint32 home = para_log_numa_home_group(numa);
        para_log_context_t *peer = session->kernel->para_log_ctx[home];

        if (peer == NULL) {
            continue;
        }

        if (para_log_writer_alive(peer)) {
            para_log_kick_writer(peer, OG_TRUE);
            continue;
        }

        if (para_log_direct_flush_group(session, peer, home) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    cm_spin_sleep_ex(1000);
    return OG_SUCCESS;
}

/*
 * reserved_lrc must only ever move forward. The publish happens after the CAS, so a thread that
 * won an earlier lrc can be descheduled and store its value after a later winner already stored
 * a higher one: with a blind store reserved_lrc would go backwards. The commit barrier snapshots
 * reserved_lrc - 1 as "everything this peer lane has reserved", so an understated value lets a
 * commit return while a peer entry it should have covered is still unflushed - after a crash that
 * surfaces as a lost redo dependency. CAS-max keeps it monotonic; reserved_lrc has its own cache
 * line, so this does not add traffic to the 128-bit ctl that the reservation loop spins on.
 */
static inline void para_log_publish_reserved_lrc(para_log_context_t *ogx, int32 new_lrc)
{
    int32 curr = para_log_lrc_load_acquire(&ogx->reserved_lrc);

    while (!para_log_lrc_reached(curr, new_lrc)) {
        if (cm_atomic32_compare_exchange(&ogx->reserved_lrc, &curr, new_lrc)) {
            return;
        }
    }
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

        para_log_publish_reserved_lrc(ogx, new_ctl.struct128.curr_lrc);

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

void para_log_write(knl_session_t *session, uint32 total_size, log_group_t *group, uint32 ori_group_size)
{
    para_log_context_t *ogx = para_log_ctx_of(session);
    para_log_buf_ctx_t *buf_ctx;
    uint64 start_pos, end_pos;
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
        if (!para_log_try_reserve_wrbuf(ogx, disk_size, &start_pos, &end_pos, &curr_lrc)) {
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

        break;
    }

    knl_end_session_wait(session, LOG_WRITE_RESERVE_SPACE);
    knl_panic_log(curr_lrc >= 0, "para log reserve did not assign lrc");

    uint32 current_entry = get_status_entry_index(RD_STATUS_ENTRIES_POWER, curr_lrc);
    volatile para_log_ins_status_ent_t *status_entry_ptr = &buf_ctx->status_table[current_entry];

    para_log_wait_and_claim_slot(buf_ctx, status_entry_ptr, curr_lrc, ogx->thread_idx, &ogx->dfx.slot_wait);

    /*
     * curr_lsn = Lamport (kernel->lsn). Commit relies on this record's LRC + cross-lane reservation snapshot, no dense numbers issued.
     */
    session->curr_lsn = (uint64)DB_INC_LSN(session);
    session->curr_lfn = session->curr_lsn;
    session->curr_lrc = curr_lrc;
    session->commit_wal_group = ogx->thread_idx;
    group->lsn = session->curr_lsn;
    para_log_stamp_group_file(group, para_log_checked_file(ogx, ogx->curr_file));

    if (session->rm->need_copy_logic_log) {
        log_add_group_size(group, session->rm->logic_log_size);
    }

    para_log_copy_wrbuf(buf_ctx, start_pos, (char *)group, ori_group_size);

    if (session->rm->need_copy_logic_log) {
        uint64 logic_start_pos = start_pos + ori_group_size;
        if (logic_start_pos >= buf_ctx->buffer_size) {
            logic_start_pos -= buf_ctx->buffer_size;
        }

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
    para_log_u64_store_release(&status_entry_ptr->curr_lsn, session->curr_lsn);
    /* release: WAL copy and end_log_pos/lsn precede COPIED. Does not rely on volatile for ordering of plain writes. */
    para_log_status_store_release(status_entry_ptr, RD_COPIED);
    para_log_snap_copied_lrc(session);
    ogx->dfx.write_cnt++;
    ogx->dfx.write_bytes += disk_size;
    OG_LOG_DEBUG_INF("[PARA LOG] write group=%u sid=%u lrc=%d curr_lsn=%llu size=%u pos=%llu..%llu",
                     ogx->thread_idx, session->id, curr_lrc, session->curr_lsn, disk_size,
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

static int64 para_log_rcy_file_scan_limit(const para_log_rcy_cursor_t *cur, const log_file_t *file)
{
    int64 hdr;
    int64 wpos;
    int64 fsize;

    hdr = (int64)CM_CALC_ALIGN(sizeof(log_file_head_t), cur->blk_size);
    wpos = (int64)file->head.write_pos;
    fsize = (int64)file->ctrl->size;

    if (file->ctrl->status != LOG_FILE_CURRENT) {
        if (wpos > hdr && (fsize <= 0 || wpos < fsize)) {
            return wpos;
        }
        return (fsize > hdr) ? fsize : hdr;
    }

    /* Switched in, no payload this ASN: leftover body must not be scanned. */
    if (file->head.first_lsn == 0 && wpos <= hdr) {
        return hdr;
    }

    /*
     * CURRENT write_pos is not flushed on the hot path. A short window after a
     * stale head (often just the file header) sits entirely in the already
     * checkpointed prefix; refusing to open the rest drops the post-ckpt tail
     * (PCN mismatch / missed SYS_MON_MODS redo). Group ASN stops leftover.
     */
    return (fsize > hdr) ? fsize : hdr;
}

static void para_log_rcy_cursor_set_file(para_log_rcy_cursor_t *cur, uint32 file_idx)
{
    log_file_t *file = cur->files[file_idx];
    int64 wpos;
    int64 fsize;

    cur->file_idx = file_idx;
    cur->cache_valid = 0;
    cur->cache_off = -1;
    cur->cache_file_idx = -1;
    cur->garbage_skip = OG_FALSE;
    cur->seen_post_ckpt = OG_FALSE;
    cur->last_group_lsn = 0;
    cur->file_first_lsn = 0;
    cur->file_asn = 0;
    cur->durable_wpos = 0;
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
    cur->file_first_lsn = file->head.first_lsn;
    cur->file_asn = file->head.asn;
    cur->durable_wpos = (wpos > cur->offset) ? wpos : cur->offset;
    cur->file_limit = para_log_rcy_file_scan_limit(cur, file);

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
                   "limit=%lld offset=%lld rcy_off=%llu first_lsn=%llu",
                   cur->group_id, file_idx, file->ctrl->name, file->head.asn, file->ctrl->status, wpos, fsize,
                   cur->file_limit, cur->offset, file->head.rcy_off, cur->file_first_lsn);
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

    /*
     * The cache is keyed on the file slot as well as the offset, so a window read for one group
     * can serve every following group that falls inside it. Without the file check the cache
     * would have to be dropped on every reposition, which turned replay into one pread per
     * redo group.
     */
    avail = (cur->cache_file_idx == (int32)cur->file_idx && cur->cache_off >= 0)
                ? (cur->cache_off + (int64)cur->cache_valid - cur->offset)
                : -1;
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
    cur->cache_file_idx = (int32)cur->file_idx;
    return OG_SUCCESS;
}

static char *para_log_rcy_cursor_ptr(para_log_rcy_cursor_t *cur)
{
    return cur->cache.aligned_buf + (cur->offset - cur->cache_off);
}

/* Bytes readable at cur->offset from the cached window, 0 when the window does not cover it. */
static inline uint32 para_log_rcy_cursor_cached(const para_log_rcy_cursor_t *cur)
{
    if (cur->cache_file_idx != (int32)cur->file_idx || cur->cache_off < 0 || cur->offset < cur->cache_off) {
        return 0;
    }

    return (uint32)(cur->cache_off + (int64)cur->cache_valid - cur->offset);
}

static int64 para_log_rcy_next_block_off(int64 offset, uint32 blk_size)
{
    int64 next;

    if (blk_size == 0) {
        blk_size = OG_DFLT_LOG_BLOCK_SIZE;
    }

    // Next 512-aligned boundary. Cannot use offset+blk: when unaligned it stays misaligned and
    // never scans to the real group header.
    next = (int64)CM_CALC_ALIGN((uint64)offset + 1, (uint64)blk_size);
    if (next <= offset) {
        next = offset + (int64)blk_size;
    }

    return next;
}

static status_t para_log_rcy_probe_valid_group(para_log_rcy_cursor_t *cur, bool32 hunt_cap,
                                              bool32 allow_ckpt_prefix, bool32 *ok)
{
    log_group_t *hdr;
    uint32 actual;
    uint32 disk_size;
    uint32 remain;
    uint32 expect_cks;
    uint32 got_cks;
    errno_t ret;

    *ok = OG_FALSE;
    if (cur->offset + (int64)sizeof(log_group_t) > cur->file_limit) {
        return OG_SUCCESS;
    }

    if (para_log_rcy_cursor_ensure(cur, sizeof(log_group_t)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    remain = para_log_rcy_cursor_cached(cur);
    if (remain < sizeof(log_group_t)) {
        return OG_SUCCESS;
    }

    hdr = (log_group_t *)para_log_rcy_cursor_ptr(cur);
    if (hdr->size == 0) {
        return OG_SUCCESS;
    }

    actual = LOG_GROUP_ACTUAL_SIZE(hdr);
    if (actual < sizeof(log_group_t) || actual > OG_MAX_LOG_GROUP_SIZE) {
        return OG_SUCCESS;
    }
    if (hunt_cap && actual > SIZE_K(256)) {
        return OG_SUCCESS;
    }

    disk_size = actual + PARA_LOG_GROUP_CKS_SIZE;
    if (cur->offset + (int64)disk_size > cur->file_limit) {
        return OG_SUCCESS;
    }

    if (para_log_rcy_cursor_ensure(cur, disk_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    remain = para_log_rcy_cursor_cached(cur);
    if (remain < disk_size) {
        return OG_SUCCESS;
    }

    hdr = (log_group_t *)para_log_rcy_cursor_ptr(cur);
    ret = memcpy_sp(&expect_cks, sizeof(expect_cks), (char *)hdr + actual, sizeof(expect_cks));
    knl_securec_check(ret);
    got_cks = cm_get_checksum(hdr, actual);
    if (got_cks != expect_cks) {
        return OG_SUCCESS;
    }

    /* Hunt must not land on leftover or already-replayed prefix. Extend may
     * see a before_ckpt group at a stale write_pos and still needs to open
     * the rest of this ASN. */
    if (para_log_rcy_group_wrong_asn(hdr, cur->file_asn) ||
        para_log_rcy_group_foreign_gen(hdr, cur->file_first_lsn)) {
        return OG_SUCCESS;
    }
    if (!allow_ckpt_prefix && para_log_rcy_group_before_ckpt(hdr, cur->rcy_lsn)) {
        return OG_SUCCESS;
    }

    *ok = OG_TRUE;
    return OG_SUCCESS;
}

static status_t para_log_rcy_skip_to_next_block(para_log_rcy_cursor_t *cur, const char *reason, uint32 actual,
                                                uint32 expect_cks, uint32 got_cks, bool32 hunt)
{
    int64 old_off = cur->offset;
    int64 blk_end = para_log_rcy_next_block_off(cur->offset, cur->blk_size);
    int64 hunt_off;
    bool32 ok = OG_FALSE;

    cur->garbage_skip = OG_TRUE;
    cur->has_group = OG_FALSE;

    if (hunt) {
        for (hunt_off = old_off + 1; hunt_off < blk_end; hunt_off++) {
            cur->offset = hunt_off;
            if (para_log_rcy_probe_valid_group(cur, OG_TRUE, OG_FALSE, &ok) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (ok) {
                OG_LOG_RUN_INF("[PARA RCY] resync %s group=%u file=%u from=%lld to=%lld curr_lsn=%llu",
                               reason, cur->group_id, cur->file_idx, old_off, hunt_off,
                               ((log_group_t *)para_log_rcy_cursor_ptr(cur))->lsn);
                return OG_SUCCESS;
            }
        }
    }

    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                         "[PARA RCY] %s group=%u file=%u off=%lld next=%lld limit=%lld actual=%u expect=%u got=%u",
                         reason, cur->group_id, cur->file_idx, old_off, blk_end, cur->file_limit, actual, expect_cks,
                         got_cks);

    /*
     * Flush pads each batch to the next block. That is not end-of-generation.
     * Stopping here after seen_post_ckpt drops the rest of the same ASN
     * (107: redo012 stopped at 1.4GB / last=9098882, then a later group
     * lsn=12011970 was applied and PCN jumped 1→66). Leftover is ASN mismatch.
     */
    if (blk_end >= cur->file_limit) {
        para_log_rcy_cursor_next_file(cur);
        return OG_SUCCESS;
    }

    cur->offset = blk_end;
    return OG_SUCCESS;
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

    if (hdr->size == 0) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

/*
 * Durable CURRENT write_pos often lags. If the next group is still this ASN,
 * open the rest of the file (including a before_ckpt prefix) and stop later
 * on leftover ASN / foreign gen, not on LSN decrease.
 */
static bool32 para_log_rcy_try_extend_stale_wpos(para_log_rcy_cursor_t *cur)
{
    log_file_t *file = cur->files[cur->file_idx];
    int64 fsize;
    int64 old_limit;
    bool32 ok = OG_FALSE;
    log_group_t *hdr;

    if (file == NULL || file->ctrl == NULL || file->ctrl->status != LOG_FILE_CURRENT) {
        return OG_FALSE;
    }

    fsize = (int64)file->ctrl->size;
    if (fsize <= cur->file_limit) {
        return OG_FALSE;
    }

    old_limit = cur->file_limit;
    cur->file_limit = fsize;
    if (para_log_rcy_probe_valid_group(cur, OG_FALSE, OG_TRUE, &ok) != OG_SUCCESS || !ok) {
        cur->file_limit = old_limit;
        return OG_FALSE;
    }

    hdr = (log_group_t *)para_log_rcy_cursor_ptr(cur);
    if (para_log_rcy_group_wrong_asn(hdr, cur->file_asn) ||
        para_log_rcy_group_foreign_gen(hdr, cur->file_first_lsn)) {
        cur->file_limit = old_limit;
        return OG_FALSE;
    }

    OG_LOG_RUN_INF("[PARA RCY] stale write_pos extend group=%u file=%u from=%lld to=%lld curr_lsn=%llu "
                   "durable_wpos=%lld first_lsn=%llu",
                   cur->group_id, cur->file_idx, old_limit, fsize, hdr->lsn, cur->durable_wpos, cur->file_first_lsn);
    return OG_TRUE;
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
            if (para_log_rcy_try_extend_stale_wpos(cur)) {
                continue;
            }
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        if (para_log_rcy_cursor_ensure(cur, sizeof(log_group_t)) != OG_SUCCESS) {
            return OG_ERROR;
        }

        remain = para_log_rcy_cursor_cached(cur);
        if (remain < sizeof(log_group_t)) {
            if (para_log_rcy_try_extend_stale_wpos(cur)) {
                continue;
            }
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        hdr = (log_group_t *)para_log_rcy_cursor_ptr(cur);

        if (hdr->size == 0 || para_log_rcy_is_flush_padding(cur, hdr)) {
            if (hdr->size == 0 && cur->blk_size > 0 &&
                (cur->offset % (int64)cur->blk_size) == 0 && !cur->garbage_skip) {
                OG_LOG_RUN_INF("[PARA RCY] zero-tail eof group=%u file=%u off=%lld limit=%lld",
                               cur->group_id, cur->file_idx, cur->offset, cur->file_limit);
                para_log_rcy_cursor_next_file(cur);
                continue;
            }
            if (para_log_rcy_skip_to_next_block(cur, "skip padding", 0, 0, 0,
                                                (bool32)(hdr->size != 0)) != OG_SUCCESS) {
                return OG_ERROR;
            }
            continue;
        }

        actual = LOG_GROUP_ACTUAL_SIZE(hdr);
        if (actual < sizeof(log_group_t) || actual > OG_MAX_LOG_GROUP_SIZE) {
            /* Mid-file garbage must not skip the rest of this file. */
            if (para_log_rcy_skip_to_next_block(cur, "skip invalid size", actual, 0, 0, OG_TRUE) != OG_SUCCESS) {
                return OG_ERROR;
            }
            continue;
        }

        disk_size = actual + PARA_LOG_GROUP_CKS_SIZE;
        if (cur->offset + (int64)disk_size > cur->file_limit) {
            if (para_log_rcy_try_extend_stale_wpos(cur)) {
                continue;
            }
            OG_LOG_RUN_INF("[PARA RCY] torn group missing cks group=%u file=%u off=%lld actual=%u limit=%lld",
                           cur->group_id, cur->file_idx, cur->offset, actual, cur->file_limit);
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        if (para_log_rcy_cursor_ensure(cur, disk_size) != OG_SUCCESS) {
            return OG_ERROR;
        }

        remain = para_log_rcy_cursor_cached(cur);
        if (remain < disk_size) {
            if (para_log_rcy_try_extend_stale_wpos(cur)) {
                continue;
            }
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
            } else if (para_log_rcy_skip_to_next_block(cur, "checksum mismatch skip block", actual, expect_cks,
                                                      got_cks, OG_TRUE) != OG_SUCCESS) {
                return OG_ERROR;
            }

            continue;
        }

        if (para_log_rcy_group_wrong_asn(hdr, cur->file_asn)) {
            OG_LOG_RUN_INF("[PARA RCY] leftover asn eof group=%u file=%u off=%lld curr_lsn=%llu "
                           "hdr_asn=%u file_asn=%u rst_id=%u",
                           cur->group_id, cur->file_idx, cur->offset, hdr->lsn, hdr->asn, cur->file_asn,
                           hdr->rst_id);
            para_log_rcy_cursor_next_file(cur);
            continue;
        }

        if (para_log_rcy_group_before_ckpt(hdr, cur->rcy_lsn) ||
            para_log_rcy_group_foreign_gen(hdr, cur->file_first_lsn)) {
            if (cur->seen_post_ckpt) {
                OG_LOG_RUN_INF("[PARA RCY] leftover eof group=%u file=%u off=%lld curr_lsn=%llu rcy=%llu "
                               "last=%llu first_lsn=%llu",
                               cur->group_id, cur->file_idx, cur->offset, hdr->lsn, cur->rcy_lsn, cur->last_group_lsn,
                               cur->file_first_lsn);
                para_log_rcy_cursor_next_file(cur);
                continue;
            }
            OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                                 "[PARA RCY] skip ckpt/stale group=%u file=%u off=%lld curr_lsn=%llu rcy=%llu "
                                 "first_lsn=%llu",
                                 cur->group_id, cur->file_idx, cur->offset, hdr->lsn, cur->rcy_lsn,
                                 cur->file_first_lsn);
            cur->offset += (int64)disk_size;
            cur->garbage_skip = OG_FALSE;
            continue;
        }

        if (cur->garbage_skip && cur->last_group_lsn != 0 && hdr->lsn < cur->last_group_lsn) {
            OG_LOG_RUN_INF("[PARA RCY] keep out-of-order group=%u file=%u off=%lld curr_lsn=%llu last=%llu",
                           cur->group_id, cur->file_idx, cur->offset, hdr->lsn, cur->last_group_lsn);
        }

        cur->seen_post_ckpt = OG_TRUE;
        cur->last_group_lsn = hdr->lsn;
        cur->has_group = OG_TRUE;
        cur->garbage_skip = OG_FALSE;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

/*
 * Only the group pointer is dropped, not the window read that backs it: the caller repositions
 * the cursor right after and para_log_rcy_cursor_ensure() revalidates the cache against the new
 * file slot and offset by itself.
 */
static void para_log_rcy_cursor_drop_group(para_log_rcy_cursor_t *cur)
{
    cur->has_group = OG_FALSE;
}

static log_group_t *para_log_rcy_cursor_group(para_log_rcy_cursor_t *cur)
{
    if (!cur->has_group || cur->cache_file_idx != (int32)cur->file_idx || cur->cache_off < 0 ||
        cur->offset < cur->cache_off) {
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

#define PARA_LOG_RCY_IDX_INIT_CAP ((uint32)1024)

static int para_log_rcy_idx_cmp(const void *a, const void *b)
{
    const para_log_rcy_idx_ent_t *x = (const para_log_rcy_idx_ent_t *)a;
    const para_log_rcy_idx_ent_t *y = (const para_log_rcy_idx_ent_t *)b;

    if (x->lsn < y->lsn) {
        return -1;
    }
    if (x->lsn > y->lsn) {
        return 1;
    }
    if (x->file_idx != y->file_idx) {
        return (x->file_idx < y->file_idx) ? -1 : 1;
    }
    if (x->offset < y->offset) {
        return -1;
    }
    if (x->offset > y->offset) {
        return 1;
    }
    return 0;
}

static status_t para_log_rcy_idx_push(para_log_rcy_cursor_t *cur, const log_group_t *group)
{
    para_log_rcy_idx_ent_t *next;
    uint32 cap;
    size_t new_bytes;
    size_t old_bytes;

    // idx and cap must be paired: when pointer is NULL, cap is treated as 0;
    // forbidden to use uninitialized cap for *2
    if (cur->idx == NULL) {
        cur->idx_cap = 0;
        cur->idx_count = 0;
    }

    if (cur->idx_count >= cur->idx_cap) {
        if (cur->idx_cap == 0) {
            cap = PARA_LOG_RCY_IDX_INIT_CAP;
        } else if (cur->idx_cap > (OG_MAX_UINT32 / 2)) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)cur->idx_cap, "para rcy idx overflow");
            return OG_ERROR;
        } else {
            cap = cur->idx_cap * 2;
        }

        new_bytes = (size_t)cap * sizeof(para_log_rcy_idx_ent_t);
        next = (para_log_rcy_idx_ent_t *)malloc(new_bytes);
        if (next == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_bytes, "para rcy idx");
            return OG_ERROR;
        }
        if (cur->idx != NULL && cur->idx_count > 0) {
            old_bytes = (size_t)cur->idx_count * sizeof(para_log_rcy_idx_ent_t);
            if (memcpy_sp(next, new_bytes, cur->idx, old_bytes) != EOK) {
                free(next);
                OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)new_bytes, "para rcy idx");
                return OG_ERROR;
            }
        }
        if (cur->idx != NULL) {
            free(cur->idx);
        }
        cur->idx = next;
        cur->idx_cap = cap;
    }

    cur->idx[cur->idx_count].lsn = group->lsn;
    cur->idx[cur->idx_count].offset = cur->offset;
    cur->idx[cur->idx_count].file_idx = cur->file_idx;
    cur->idx[cur->idx_count].disk_size = PARA_LOG_GROUP_DISK_SIZE(group);
    cur->idx_count++;
    return OG_SUCCESS;
}

static status_t para_log_rcy_cursor_build_idx(para_log_rcy_cursor_t *cur)
{
    log_group_t *group;

    cur->idx_count = 0;
    cur->idx_pos = 0;
    if (cur->idx == NULL) {
        cur->idx_cap = 0;
    }
    while (!cur->eof) {
        if (para_log_rcy_cursor_load_group(cur) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (!cur->has_group) {
            break;
        }
        group = para_log_rcy_cursor_group(cur);
        if (para_log_rcy_idx_push(cur, group) != OG_SUCCESS) {
            return OG_ERROR;
        }
        para_log_rcy_cursor_advance(cur);
    }

    if (cur->idx_count > 1) {
        qsort(cur->idx, cur->idx_count, sizeof(para_log_rcy_idx_ent_t), para_log_rcy_idx_cmp);
    }

    cur->has_group = OG_FALSE;
    cur->idx_pos = 0;
    cur->eof = (bool32)(cur->idx_count == 0);
    OG_LOG_RUN_INF("[PARA RCY] idx built group=%u groups=%u rcy_lsn=%llu", cur->group_id, cur->idx_count,
                   cur->rcy_lsn);
    return OG_SUCCESS;
}

static status_t para_log_rcy_cursor_load_indexed(para_log_rcy_cursor_t *cur)
{
    para_log_rcy_idx_ent_t *ent;
    log_file_t *file;
    int64 wpos;
    int64 need;

    para_log_rcy_cursor_drop_group(cur);
    if (cur->idx_pos >= cur->idx_count) {
        cur->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    ent = &cur->idx[cur->idx_pos];
    file = cur->files[ent->file_idx];
    if (file == NULL || file->ctrl == NULL) {
        cur->eof = OG_TRUE;
        return OG_ERROR;
    }

    cur->file_idx = ent->file_idx;
    cur->blk_size = file->ctrl->block_size;
    if (cur->blk_size == 0) {
        cur->blk_size = OG_DFLT_LOG_BLOCK_SIZE;
    }
    cur->offset = ent->offset;
    cur->eof = OG_FALSE;
    cur->garbage_skip = OG_FALSE;
    wpos = (int64)file->head.write_pos;
    cur->file_first_lsn = file->head.first_lsn;
    cur->file_asn = file->head.asn;
    cur->durable_wpos = wpos;
    cur->file_limit = para_log_rcy_file_scan_limit(cur, file);
    if (cur->offset + (int64)ent->disk_size > cur->file_limit) {
        cur->file_limit = cur->offset + (int64)ent->disk_size;
    }

    need = (int64)ent->disk_size;
    if (para_log_rcy_cursor_ensure(cur, ent->disk_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cur->cache_file_idx != (int32)cur->file_idx || cur->cache_off < 0 || cur->offset < cur->cache_off ||
        cur->offset + need > cur->cache_off + (int64)cur->cache_valid) {
        OG_LOG_RUN_ERR("[PARA RCY] indexed load miss group=%u file=%u off=%lld size=%u cache_file=%d cache_off=%lld "
                       "valid=%u eof=%u",
                       cur->group_id, ent->file_idx, cur->offset, ent->disk_size, cur->cache_file_idx, cur->cache_off,
                       cur->cache_valid, cur->eof);
        return OG_ERROR;
    }

    cur->has_group = OG_TRUE;
    return OG_SUCCESS;
}

static void para_log_rcy_cursor_close(para_log_rcy_cursor_t *cur)
{
    if (cur->idx != NULL) {
        free(cur->idx);
        cur->idx = NULL;
    }
    cur->idx_count = 0;
    cur->idx_cap = 0;
    cur->idx_pos = 0;
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
    cur->cache_file_idx = -1;
    cur->idx = NULL;
    cur->idx_count = 0;
    cur->idx_cap = 0;
    cur->idx_pos = 0;
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
     * still have a valid ASN. Unusable slots are skipped later.
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
        if (para_log_rcy_cursor_build_idx(&stream->cursors[i]) != OG_SUCCESS) {
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
    OG_LOG_RUN_INF("[PARA RCY] stream open node=%u rcy_lsn=%llu writers=%u merge=curr_lsn write-zone",
                   node_id, rcy_lsn, writers);
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

    stream->peeked_writer = -1;
    stream->done = OG_FALSE;
    stream->recovered_end = stream->rcy_lsn;
    stream->expected = stream->rcy_lsn + 1;
    for (i = 0; i < stream->writer_count; i++) {
        cur = &stream->cursors[i];
        cur->idx_pos = 0;
        para_log_rcy_cursor_drop_group(cur);
        cur->eof = (bool32)(cur->idx_count == 0);
    }

    return OG_SUCCESS;
}

status_t para_log_rcy_stream_peek(para_log_rcy_stream_t *stream, log_group_t **group)
{
    uint32 i;
    int32 best = -1;
    uint64 best_lsn = OG_INVALID_ID64;
    para_log_rcy_cursor_t *cur;
    para_log_rcy_idx_ent_t *ent;

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
        if (cur->idx_pos >= cur->idx_count) {
            continue;
        }
        ent = &cur->idx[cur->idx_pos];
        if (best < 0 || ent->lsn < best_lsn) {
            best = (int32)i;
            best_lsn = ent->lsn;
        }
    }

    if (best < 0) {
        stream->done = OG_TRUE;
        OG_LOG_RUN_INF("[PARA RCY] node=%u write-zone eof recovered_end=%llu", stream->node_id, stream->recovered_end);
        return OG_SUCCESS;
    }

    para_log_rcy_cursor_drop_group(&stream->cursors[best]);
    if (para_log_rcy_cursor_load_indexed(&stream->cursors[best]) != OG_SUCCESS) {
        return OG_ERROR;
    }

    stream->peeked_writer = best;
    *group = para_log_rcy_cursor_group(&stream->cursors[best]);
    if (*group == NULL) {
        OG_LOG_RUN_ERR("[PARA RCY] indexed peek empty group node=%u writer=%u idx_pos=%u", stream->node_id, best,
                       stream->cursors[best].idx_pos);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void para_log_rcy_stream_consume(para_log_rcy_stream_t *stream)
{
    para_log_rcy_cursor_t *cur;
    log_group_t *group;

    if (stream == NULL || stream->peeked_writer < 0) {
        return;
    }

    cur = &stream->cursors[stream->peeked_writer];
    group = para_log_rcy_cursor_group(cur);
    if (group != NULL && group->lsn > stream->recovered_end) {
        stream->recovered_end = group->lsn;
    }
    cur->idx_pos++;
    para_log_rcy_cursor_drop_group(cur);
    if (cur->idx_pos >= cur->idx_count) {
        cur->eof = OG_TRUE;
    }
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

static uint32 para_log_rcy_current_idx(para_log_rcy_cursor_t *cur)
{
    uint32 i;
    uint32 best_active = OG_INVALID_ID32;
    uint32 best_asn = 0;

    for (i = 0; i < cur->compact_count; i++) {
        log_file_t *file;

        if (!para_log_rcy_file_usable(cur, i)) {
            continue;
        }

        file = cur->files[i];
        if (file->ctrl->status == LOG_FILE_CURRENT) {
            return i;
        }

        if (file->ctrl->status == LOG_FILE_ACTIVE &&
            (best_active == OG_INVALID_ID32 || file->head.asn >= best_asn)) {
            best_asn = file->head.asn;
            best_active = i;
        }
    }

    return best_active;
}

static void para_log_rcy_init_keep_from_rcy_off(para_log_rcy_cursor_t *cur, uint32 *keep_file, int64 *keep_end)
{
    uint32 idx;
    log_file_t *file;
    uint64 hdr;
    uint64 rcy_off;

    if (cur->rcy_lsn == 0 || cur->compact_count == 0) {
        return;
    }

    idx = para_log_rcy_current_idx(cur);
    if (idx == OG_INVALID_ID32 || !para_log_rcy_file_usable(cur, idx)) {
        return;
    }

    file = cur->files[idx];
    hdr = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    rcy_off = file->head.rcy_off;
    if (rcy_off > hdr && (int64)rcy_off <= (int64)file->ctrl->size) {
        *keep_file = idx;
        *keep_end = (int64)rcy_off;
    }
}

static status_t para_log_rcy_truncate_writer(knl_session_t *session, uint8 node_id, uint32 group_id,
                                             uint64 ckpt_rcy, const int32 *handles)
{
    para_log_rcy_cursor_t cur;
    log_group_t *group;
    uint32 keep_file = OG_INVALID_ID32;
    int64 keep_end = 0;
    int64 scan_end = 0;
    uint32 scan_file = OG_INVALID_ID32;
    uint64 keep_max_lsn = 0;

    if (para_log_rcy_cursor_open(session, node_id, group_id, handles, ckpt_rcy, &cur) != OG_SUCCESS) {
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
        // Keep all CRC-valid groups of this generation in the write region;
        // no longer discard larger numbers by dense prefix
        keep_file = cur.file_idx;
        keep_end = scan_end;
        if (group->lsn > keep_max_lsn) {
            keep_max_lsn = group->lsn;
        }

        para_log_rcy_cursor_advance(&cur);
    }

    if (keep_max_lsn == 0) {
        uint32 curr_idx = para_log_rcy_current_idx(&cur);
        log_file_t *cfile;
        uint64 hdr;
        uint64 rcy_off;

        if (curr_idx == OG_INVALID_ID32 || !para_log_rcy_file_usable(&cur, curr_idx)) {
            para_log_rcy_cursor_close(&cur);
            return OG_SUCCESS;
        }

        cfile = cur.files[curr_idx];
        hdr = CM_CALC_ALIGN(sizeof(log_file_head_t), cfile->ctrl->block_size);
        keep_file = curr_idx;
        rcy_off = cfile->head.rcy_off;
        if (rcy_off > hdr && (int64)rcy_off <= (int64)cfile->ctrl->size) {
            keep_end = (int64)rcy_off;
        } else if (cfile->head.write_pos > hdr) {
            keep_end = (int64)cfile->head.write_pos;
        } else {
            keep_end = (int64)hdr;
        }
        if (cfile->head.last_lsn != 0 && cfile->head.last_lsn != OG_INVALID_ID64) {
            keep_max_lsn = cfile->head.last_lsn;
        }
        OG_LOG_RUN_INF("[PARA RCY] truncate keep current node=%u group=%u slot=%u write_pos=%lld last_lsn=%llu "
                       "(no post-ckpt group)",
                       node_id, group_id, keep_file, keep_end, keep_max_lsn);
    }

    if (keep_file != OG_INVALID_ID32) {
        log_file_t *file = cur.files[keep_file];
        uint32 blk = file->ctrl->block_size;
        int64 new_pos;
        int64 old_pos = (int64)file->head.write_pos;
        int64 zero_to = MAX(old_pos, scan_end);
        uint64 hdr_size;

        if (blk == 0) {
            blk = cur.blk_size;
        }
        if (blk == 0) {
            blk = OG_DFLT_LOG_BLOCK_SIZE;
        }
        new_pos = (int64)CM_CALC_ALIGN((uint64)keep_end, blk);
        if (scan_file != OG_INVALID_ID32 && scan_file != keep_file) {
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
        if (keep_max_lsn > 0) {
            file->head.last_lsn = keep_max_lsn;
        }
        /*
         * rcy_off must stay where the pre-crash checkpoint left it. It is the offset the next
         * scan starts from, and everything we just replayed is still only in the buffer pool.
         * Advancing it to new_pos here would make a second crash before the post-recovery
         * checkpoint skip [rcy_off, new_pos) for good, i.e. silently drop that redo.
         * para_log_ckpt_flush_rcy_off() moves it forward once the pages are on disk.
         * The clamp only guards against a head that already points past the kept payload.
         */
        if (file->head.rcy_off > (uint64)new_pos) {
            file->head.rcy_off = (uint64)new_pos;
        }

        if (para_log_rcy_save_head(session, file, cur.handles[keep_file], node_id) != OG_SUCCESS) {
            para_log_rcy_cursor_close(&cur);
            return OG_ERROR;
        }

        hdr_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        if (node_id == session->kernel->id && session->kernel->para_log_ctx[group_id] != NULL) {
            para_log_context_t *ogx = session->kernel->para_log_ctx[group_id];
            ogx->curr_file = (uint16)keep_file;
            ogx->file_write_pos = file->head.write_pos;
            if (para_log_file_slot_valid(ogx, keep_file)) {
                if (keep_max_lsn > 0) {
                    ogx->file_max_lsn[keep_file] = keep_max_lsn;
                } else if (file->head.write_pos <= hdr_size) {
                    ogx->file_max_lsn[keep_file] = 0;
                } else if (file->head.last_lsn != 0 && file->head.last_lsn != OG_INVALID_ID64) {
                    ogx->file_max_lsn[keep_file] = file->head.last_lsn;
                } else {
                    /* Has payload but neither scan nor file header yields max lsn: forbid writing 0, otherwise recycle gets stuck */
                    ogx->file_max_lsn[keep_file] = OG_INVALID_ID64;
                }
            }
        }

        dtc_get_ctrl(session, node_id)->para_log_last[group_id] = keep_file;
        OG_LOG_RUN_INF("[PARA RCY] truncate node=%u group=%u keep_slot=%u write_pos=%llu keep_max_lsn=%llu",
                       node_id, group_id, keep_file, file->head.write_pos, keep_max_lsn);
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

    OG_LOG_RUN_INF("[PARA RCY] apply reset node=%u recovered_end=%llu last_curr_lsn=%llu ckpt_rcy=%llu", node_id,
                   recovered_end, last_curr_lsn, ctrl->rcy_point.lsn);
    for (i = 0; i < writers; i++) {
        if (para_log_rcy_truncate_writer(session, node_id, i, ctrl->rcy_point.lsn, handles) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (node_id == session->kernel->id) {
        log_context_t *ogx = &session->kernel->redo_ctx;
        uint64 ctl_lsn = (uint64)cm_atomic_get(&session->kernel->lsn);

        if (last_curr_lsn > ctl_lsn) {
            ctl_lsn = last_curr_lsn;
        }
        if (recovered_end > ctl_lsn) {
            ctl_lsn = recovered_end;
        }
        DB_SET_LSN(session->kernel->lsn, ctl_lsn);

        cm_atomic_set((atomic_t *)&ogx->flushed_lsn, (int64)recovered_end);
        cm_atomic_set((atomic_t *)&ogx->flushed_lfn, (int64)recovered_end);

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

    /*
     * ctrl->rcy_point deliberately keeps its pre-recovery value. The redo we just replayed only
     * exists in the buffer pool, so publishing recovered_end as the new recovery start would
     * open a window where a second crash before the post-recovery CKPT_TRIGGER_FULL replays
     * nothing and silently loses those changes. rcy_point belongs to the checkpoint:
     * ckpt_update_log_point() advances it from the trunc_point of pages it has really written,
     * which keeps recovery re-runnable from the same point until then.
     */
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
                OG_LOG_RUN_INF("[PARA RCY] replay progress groups=%llu curr_lsn=%llu",
                               replayed, group->lsn);
            }

            DB_SET_LSN(session->kernel->lsn, group->lsn);
            DB_SET_LFN(&ogx->lfn, group->lsn);
            para_log_rcy_stream_consume(stream);
        }

        recovered_end = para_log_rcy_stream_recovered_end(stream);
        OG_LOG_RUN_INF("[PARA RCY] replay finished groups=%llu recovered_end=%llu", replayed, recovered_end);
    }

    para_log_rcy_stream_close(stream);
    if (recovered_end < ctrl->lrp_point.lfn && !RCY_IGNORE_CORRUPTED_LOG(&session->kernel->rcy_ctx)) {
        OG_LOG_RUN_WAR("[PARA RCY] recover max curr %llu < lrp %llu (gap=%llu), write-zone scan finished, continue",
                       recovered_end, (uint64)ctrl->lrp_point.lfn, (uint64)ctrl->lrp_point.lfn - recovered_end);
    }

    if (para_log_rcy_apply_reset(session, (uint8)session->kernel->id, recovered_end, session->kernel->lsn,
                                handles) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[PARA RCY] single-node recover done recovered_end=%llu kernel_lsn=%llu", recovered_end,
                   (uint64)session->kernel->lsn);
    return OG_SUCCESS;
}
