/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "knl_replication_module.h"
#include "repl_log_recv.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_abr.h"
#include "knl_ctrl_restore.h"
#include "dtc_database.h"

#define SUSPEND_INTERVAL 1000
#define EMPTY_LOG_POINT(pt) (((pt).rst_id == 0) && ((pt).asn == 0) && ((pt).offset == 0) && ((pt).lfn == 0))
#define LRCV_IS_RUNING(lrcv) ((lrcv)->session != NULL)
#define LRCV_INVALID_DBID(peer_dbid, local_dbid) ((peer_dbid) != 0 && (peer_dbid) != (local_dbid))

static inline void lrcv_disconnect(lrcv_context_t *lrcv)
{
    cs_disconnect(lrcv->pipe);
}

static void lrcv_reset_bak_task(lrcv_context_t *lrcv)
{
    rep_bak_task_t *task = &lrcv->task;

    if (task->status == BAK_TASK_DONE) {
        return;
    }

    if (task->status == BAK_TASK_WAIT_PROCESS) {
        lrcv->task.error_no = ERR_SEND_RECORD_REQ_FAILED;
    } else {
        lrcv->task.error_no = ERR_RECORD_BACKUP_FAILED;
    }

    task->status = BAK_TASK_DONE;
}

static void lrcv_set_conn_err(lrcv_context_t *lrcv)
{
    lrcv_disconnect(lrcv);
    lrcv_reset_bak_task(lrcv);
}

static status_t lrcv_process_heart_beat(lrcv_context_t *lrcv);

/*
 * ---- per-stream log file group accessors (N-to-M replication) ----
 *
 * A standby node accepts one redo stream per source primary node.  Stream
 * `src_node_id` is stored in the per-node log file group
 * LOGFILE_SET(session, src_node_id), reusing the cluster per-node
 * recovery/archiving machinery.  Stream 0 (src_node_id == local node id)
 * keeps the legacy single-stream behavior and mirrors `redo_ctx`.
 */
static inline bool32 lrcv_is_remote_stream(lrcv_context_t *lrcv)
{
    return (lrcv->stream_bound && lrcv->src_node_id != lrcv->session->kernel->id);
}

static inline logfile_set_t *lrcv_get_file_set(lrcv_context_t *lrcv)
{
    if (lrcv->stream_bound) {
        return LOGFILE_SET(lrcv->session, lrcv->src_node_id);
    }
    return MY_LOGFILE_SET(lrcv->session);
}

static inline dtc_node_ctrl_t *lrcv_get_node_ctrl(lrcv_context_t *lrcv)
{
    if (lrcv->stream_bound && lrcv->src_node_id < lrcv->session->kernel->db.ctrl.core.node_count) {
        return dtc_get_ctrl(lrcv->session, lrcv->src_node_id);
    }
    return dtc_my_ctrl(lrcv->session);
}

static inline void lrcv_lock_logfile(lrcv_context_t *lrcv)
{
    if (lrcv_is_remote_stream(lrcv)) {
        cm_spin_lock(&lrcv->stream_lock, NULL);
    } else {
        log_lock_logfile(lrcv->session);
    }
}

static inline void lrcv_unlock_logfile(lrcv_context_t *lrcv)
{
    if (lrcv_is_remote_stream(lrcv)) {
        cm_spin_unlock(&lrcv->stream_lock);
    } else {
        log_unlock_logfile(lrcv->session);
    }
}

/* Mirror per-stream file state back to redo_ctx for the local stream. */
static inline void lrcv_sync_stream_state(lrcv_context_t *lrcv)
{
    if (!lrcv->stream_bound || lrcv_is_remote_stream(lrcv)) {
        return;
    }

    log_context_t *redo = &lrcv->session->kernel->redo_ctx;
    redo->curr_file = lrcv->stream_curr_file;
    redo->active_file = lrcv->stream_active_file;
    redo->logfile_hwm = lrcv->stream_logfile_hwm;
    redo->free_size = lrcv->stream_free_size;
}

static inline uint16 lrcv_get_curr_file(lrcv_context_t *lrcv)
{
    if (lrcv->stream_bound) {
        return lrcv->stream_curr_file;
    }
    return lrcv->session->kernel->redo_ctx.curr_file;
}

/*
 * whether this stream's log file group is backed by DSS (ulog addressed by
 * LSN, or raw device that cannot be byte-scanned via lseek); such devices
 * cannot use log_get_file_offset for write-pos repair.
 */
static inline bool32 lrcv_is_dss_log(lrcv_context_t *lrcv)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    if (file_set == NULL || file_set->logfile_hwm == 0 || file_set->items[0].ctrl == NULL) {
        return OG_FALSE;
    }
    return (file_set->items[0].ctrl->type == DEV_TYPE_ULOG ||
            file_set->items[0].ctrl->type == DEV_TYPE_RAW);
}

static inline uint16 lrcv_get_active_file(lrcv_context_t *lrcv)
{
    if (lrcv->stream_bound) {
        return lrcv->stream_active_file;
    }
    return lrcv->session->kernel->redo_ctx.active_file;
}

static inline uint32 lrcv_get_logfile_hwm(lrcv_context_t *lrcv)
{
    if (lrcv->stream_bound) {
        return lrcv->stream_logfile_hwm;
    }
    return lrcv->session->kernel->redo_ctx.logfile_hwm;
}

static inline uint64 lrcv_get_free_size(lrcv_context_t *lrcv)
{
    if (lrcv->stream_bound) {
        return lrcv->stream_free_size;
    }
    return lrcv->session->kernel->redo_ctx.free_size;
}

static inline void lrcv_set_free_size(lrcv_context_t *lrcv, uint64 free_size)
{
    lrcv->stream_free_size = free_size;
    if (!lrcv->stream_bound || !lrcv_is_remote_stream(lrcv)) {
        lrcv->session->kernel->redo_ctx.free_size = free_size;
    }
}

static inline void lrcv_get_next_file(lrcv_context_t *lrcv, uint32 *next, bool32 use_curr)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    uint32 hwm = lrcv_get_logfile_hwm(lrcv);

    if (use_curr) {
        *next = lrcv_get_curr_file(lrcv);
    }

    for (;;) {
        CM_CYCLED_MOVE_NEXT(hwm, *next);
        if (!LOG_IS_DROPPED(file_set->items[*next].ctrl->flg)) {
            break;
        }
    }
}

/*
 * Flush a stream log file head using the receiver's own handle (remote
 * streams must not use the shared log_file_t.handle owned by the archiver /
 * dtc recovery).  Writes only the head itself, never touching the redo
 * batches after it.
 */
static void lrcv_flush_head(lrcv_context_t *lrcv, log_file_t *file)
{
    log_calc_head_checksum(lrcv->session, &file->head);
    if (DB_IS_RAFT_ENABLED(lrcv->session->kernel)) {
        raft_log_flush_async_head(&lrcv->session->kernel->raft_ctx, file);
        return;
    }

    int32 handle = lrcv_is_remote_stream(lrcv) ? lrcv->stream_handle[file - lrcv->file_set->items] : file->handle;
    int32 size = (int32)CM_CALC_ALIGN(sizeof(log_file_head_t), FILE_BLOCK_SIZE);
    if (cm_write_device(file->ctrl->type, handle, 0, &file->head, size) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[Log Receiver] failed to flush head of %s", file->ctrl->name);
    }
}

static void lrcv_flush_stream_head(lrcv_context_t *lrcv, log_file_t *file)
{
    if (lrcv_is_remote_stream(lrcv)) {
        lrcv_flush_head(lrcv, file);
    } else {
        log_flush_head(lrcv->session, file);
    }
}

/*
 * Whether the log switch to (spec_file_id, spec_asn) has to wait: the target
 * asn maps to a different file id in the local stream file group.
 */
static bool32 lrcv_switch_need_wait(lrcv_context_t *lrcv, uint16 spec_file_id, uint32 spec_asn)
{
    uint32 curr_asn;

    lrcv_lock_logfile(lrcv);
    uint32 next_asn = lrcv_get_file_set(lrcv)->items[lrcv_get_curr_file(lrcv)].head.asn;
    uint32 next_file = lrcv_get_curr_file(lrcv);

    for (;;) {
        curr_asn = next_asn;
        lrcv_get_next_file(lrcv, &next_file, OG_FALSE);
        next_asn = curr_asn + 1;

        if (spec_asn == next_asn && next_file != spec_file_id) {
            lrcv_unlock_logfile(lrcv);
            return OG_TRUE;
        }

        if (spec_file_id == OG_INVALID_FILEID || spec_asn == OG_INVALID_ASN ||
            (next_file == spec_file_id && next_asn == spec_asn)) {
            break;
        }
    }

    lrcv_unlock_logfile(lrcv);
    return OG_FALSE;
}

/* Switch the stream current log file to the next file (mirror of log_switch_file). */
static status_t lrcv_switch_stream_file(lrcv_context_t *lrcv)
{
    knl_session_t *session = lrcv->session;
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    reset_log_t resetlog = session->kernel->db.ctrl.core.resetlogs;
    uint32 next;
    log_file_t *curr_file = NULL;
    dtc_node_ctrl_t *node_ctrl = lrcv_get_node_ctrl(lrcv);

    if (file_set->items[0].ctrl->type == DEV_TYPE_ULOG) {
        curr_file = &file_set->items[lrcv->stream_curr_file];
        curr_file->head.write_pos = 0;
        OG_LOG_RUN_INF("[Log Receiver] Succeed to switch logfile active %u current %u for stream %u.",
                       lrcv->stream_active_file, lrcv->stream_curr_file, lrcv->src_node_id);
        return OG_SUCCESS;
    }

    lrcv_get_next_file(lrcv, &next, OG_TRUE);
    knl_panic_log((next != lrcv->stream_active_file), "failed to switch log file, current file is %u, "
                  "active file is %u, log free size is %llu, stream is %u",
                  lrcv->stream_curr_file, lrcv->stream_active_file, lrcv->stream_free_size, lrcv->src_node_id);

    curr_file = &file_set->items[lrcv->stream_curr_file];
    curr_file->ctrl->status = LOG_FILE_ACTIVE;
    uint32 asn = curr_file->head.asn;
    uint32 rst_id = (curr_file->head.asn == resetlog.last_asn) ? resetlog.rst_id : curr_file->head.rst_id;
    lrcv->stream_free_size -= log_file_freesize(curr_file);
    lrcv->stream_curr_file = (uint16)next;

    log_file_t *next_file = &file_set->items[next];
    next_file->arch_pos = 0;
    next_file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), next_file->ctrl->block_size);
    next_file->head.block_size = next_file->ctrl->block_size;
    next_file->head.rst_id = rst_id;
    next_file->head.asn = asn + 1;
    next_file->head.first = OG_INVALID_ID64;
    next_file->head.cmp_algorithm = COMPRESS_NONE;
    next_file->ctrl->status = LOG_FILE_CURRENT;
    next_file->ctrl->archived = OG_FALSE;
    lrcv_flush_stream_head(lrcv, next_file);

    node_ctrl->log_last = lrcv->stream_curr_file;
    if (db_save_log_ctrl(session, lrcv->stream_curr_file, lrcv->src_node_id) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch stream log file");
    }
    if (ctrl_backup_log_ctrl(session, curr_file->ctrl->file_id, lrcv->src_node_id) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: backup log control info failed when switch stream log file");
    }

    OG_LOG_RUN_INF("[Log Receiver] Succeed to switch logfile active %u current %u for stream %u.",
                   lrcv->stream_active_file, lrcv->stream_curr_file, lrcv->src_node_id);
    lrcv_sync_stream_state(lrcv);
    return OG_SUCCESS;
}

/*
 * Switch the stream log file to (spec_file_id, spec_asn); keep heart beating
 * while the switch is blocked (current file is the active file).
 */
static status_t lrcv_switch_logfile(lrcv_context_t *lrcv, uint16 spec_file_id, uint32 spec_asn)
{
    knl_session_t *session = lrcv->session;
    status_t status;
    uint32 next;
    time_t last_send_time = cm_current_time();
    bool32 need_skip = OG_FALSE;

    lrcv_lock_logfile(lrcv);

    log_file_t *file = &lrcv_get_file_set(lrcv)->items[lrcv->stream_curr_file];
    if (file->head.write_pos == CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) {
        if (spec_file_id == OG_INVALID_FILEID || spec_asn == OG_INVALID_ASN ||
            (lrcv->stream_curr_file == spec_file_id && file->head.asn == spec_asn)) {
            lrcv_unlock_logfile(lrcv);
            return OG_SUCCESS;
        }

        need_skip = OG_TRUE;
        OG_LOG_RUN_INF("[Log Receiver] Switch stream %u log, need to skip file %u asn %u state %d",
                       lrcv->src_node_id, lrcv->stream_curr_file, file->head.asn, file->ctrl->status);
    }

    lrcv_unlock_logfile(lrcv);

    for (;;) {
        lrcv_get_next_file(lrcv, &next, OG_TRUE);
        while (next == lrcv->stream_active_file) {
            ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
            cm_sleep(1);

            if (session->killed) {
                OG_THROW_ERROR(ERR_OPERATION_KILLED);
                return OG_ERROR;
            }

            time_t now = cm_current_time();
            if ((now - last_send_time) >= REPL_HEART_BEAT_CHECK) {
                if (lrcv_process_heart_beat(lrcv) != OG_SUCCESS) {
                    OG_THROW_ERROR(ERR_SWITCH_LOGFILE, "the standby failed to send heart beat message to primary");
                    return OG_ERROR;
                }
                last_send_time = now;
            }

            lrcv_get_next_file(lrcv, &next, OG_TRUE);
        }

        if (spec_file_id != OG_INVALID_FILEID && spec_asn != OG_INVALID_ASN) {
            log_file_t *curr = &lrcv_get_file_set(lrcv)->items[lrcv->stream_curr_file];
            uint32 next_asn = curr->head.asn + 1;
            if (spec_asn == next_asn && next != spec_file_id) {
                OG_THROW_ERROR(ERR_SWITCH_LOGFILE,
                    "asn %u located in different fileid %u/%u on peer node and local node",
                    spec_asn, spec_file_id, next);
                OG_LOG_RUN_ERR("[Log Receiver] asn %u located in different fileid %u/%u on peer node and local node, "
                               "perhaps the add/drop logfile has not been replayed",
                               spec_asn, spec_file_id, next);
                return OG_ERROR;
            }
        }

        lrcv_lock_logfile(lrcv);

        file = &lrcv_get_file_set(lrcv)->items[lrcv->stream_curr_file];
        if (file->head.write_pos == CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) {
            if (spec_file_id == OG_INVALID_FILEID || spec_asn == OG_INVALID_ASN) {
                lrcv_unlock_logfile(lrcv);
                return OG_SUCCESS;
            }
        }

        lrcv_get_next_file(lrcv, &next, OG_TRUE);
        if (next == lrcv->stream_active_file) {
            lrcv_unlock_logfile(lrcv);
            continue;
        }

        uint16 pre_fileid = lrcv->stream_curr_file;
        file = &lrcv_get_file_set(lrcv)->items[lrcv->stream_curr_file];
        if (DB_NOT_READY(session) && log_repair_file_offset(session, file) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_SWITCH_LOGFILE, "repair current log offset failed");
            lrcv_unlock_logfile(lrcv);
            return OG_ERROR;
        }
        lrcv_flush_stream_head(lrcv, file);
        status = lrcv_switch_stream_file(lrcv);

        if (need_skip) {
            file = &lrcv_get_file_set(lrcv)->items[pre_fileid];
            file->head.asn = OG_INVALID_ASN;
            file->ctrl->status = LOG_FILE_INACTIVE;
            file->ctrl->archived = OG_FALSE;
            lrcv_flush_stream_head(lrcv, file);
            if (db_save_log_ctrl(session, pre_fileid, lrcv->src_node_id) != OG_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch stream log file");
            }
        }

        file = &lrcv_get_file_set(lrcv)->items[lrcv->stream_curr_file];
        if (status == OG_SUCCESS &&
            !(spec_file_id == OG_INVALID_FILEID || spec_asn == OG_INVALID_ASN ||
              (lrcv->stream_curr_file == spec_file_id && file->head.asn == spec_asn))) {
            need_skip = OG_TRUE;
            lrcv_unlock_logfile(lrcv);
            OG_LOG_RUN_INF("[Log Receiver] Switch stream %u log, need to skip file %u asn %u state %d",
                           lrcv->src_node_id, lrcv->stream_curr_file, file->head.asn, file->ctrl->status);
            continue;
        }

        lrcv_unlock_logfile(lrcv);
        return status;
    }
}

void lrcv_update_frontier(lrcv_context_t *lrcv, uint64 lsn)
{
    if (lrcv == NULL || !lrcv->stream_bound) {
        return;
    }

    if (lsn > lrcv->lsn_frontier) {
        lrcv->lsn_frontier = lsn;
    }
}

/* close the log file handles opened by this receiver for a remote stream */
void lrcv_close_stream_files(lrcv_context_t *lrcv)
{
    if (lrcv == NULL || !lrcv->stream_bound || lrcv->file_set == NULL ||
        lrcv->src_node_id == lrcv->session->kernel->id) {
        return;
    }

    for (uint32 i = 0; i < lrcv->stream_logfile_hwm; i++) {
        if (lrcv->stream_handle[i] >= 0) {
            log_file_t *file = &lrcv->file_set->items[i];
            cm_close_device(file->ctrl->type, &lrcv->stream_handle[i]);
            lrcv->stream_handle[i] = -1;
        }
    }
}

lrcv_context_t *lrcv_get_stream(knl_session_t *session, uint32 src_node_id)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        if (lrcv->stream_bound && lrcv->src_node_id == src_node_id) {
            return lrcv;
        }
    }
    return NULL;
}

/*
 * Recycle stream log files whose head is before the given point.  Only the
 * local stream (src_node_id == local node id) recycles files; remote streams
 * rely on the per-node archive recycle handled by the archiver, so this is a
 * per-stream variant of log_recycle_file used by lrcv_wait_logfile_no_active.
 */
static void lrcv_recycle_file(lrcv_context_t *lrcv, log_point_t *point)
{
    if (DB_CLUSTER_NO_CMS) {
        return;
    }
    if (lrcv_is_dss_log(lrcv)) {
        /* DBStor standby recycle is per-node and handled in log_recycle_file. */
        log_recycle_file(lrcv->session, point);
        return;
    }

    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    arch_log_id_t last_arch_log;
    arch_last_archived_log(lrcv->session, ARCH_DEFAULT_DEST, &last_arch_log);

    log_file_t *file = &file_set->items[lrcv->stream_active_file];
    if (lrcv->wait_info.waiting) {
        return;
    }

    lrcv_lock_logfile(lrcv);
    uint32 file_id = lrcv->stream_active_file;
    while (LOG_POINT_FILE_LT(file_set->items[file_id].head, *point)) {
        file = &file_set->items[file_id];
        if ((file_id == lrcv->stream_curr_file) ||
            (file->head.asn > last_arch_log.asn ||
             (file->ctrl->status == LOG_FILE_ACTIVE && !file->ctrl->archived))) {
            break;
        }

        file->ctrl->status = LOG_FILE_INACTIVE;
        file->ctrl->archived = OG_FALSE;
        cm_latch_x(&file->latch, lrcv->session->id, NULL);
        file->head.asn = OG_INVALID_ASN;
        file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        file->arch_pos = 0;
        cm_unlatch(&file->latch, NULL);

        lrcv->stream_free_size += log_file_freesize(file);
        lrcv_get_next_file(lrcv, &file_id, OG_FALSE);
        lrcv->stream_active_file = (uint16)file_id;
        lrcv_get_node_ctrl(lrcv)->log_first = file_id;
        if (db_save_log_ctrl(lrcv->session, file_id, lrcv->src_node_id) != OG_SUCCESS) {
            CM_ABORT(0, "[Log Receiver] ABORT INFO: save core control file failed when recycling stream log file");
        }
    }
    lrcv_sync_stream_state(lrcv);
    lrcv_unlock_logfile(lrcv);
}

static bool32 lrcv_need_suspend(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (lrcv->session->kernel->lftc_client_ctx.arch_lost) {
        lrcv->status = LRCV_NEED_REPAIR;
        return OG_TRUE;
    }

    if (lrcv->session->kernel->rcy_ctx.log_decrypt_failed) {
        lrcv->status = LRCV_NEED_REPAIR;
        return OG_TRUE;
    }

    if (lrcv->status == LRCV_NEED_REPAIR && DB_IS_PHYSICAL_STANDBY(db) && lrcv->peer_role == PEER_PRIMARY) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static bool32 lrcv_rcv_msg_is_valid(lrcv_context_t *lrcv)
{
    char *extend_buf = lrcv->extend_buf.read_buf.aligned_buf;

    switch (lrcv->header.type) {
        case REP_BATCH_REQ: {
            rep_batch_req_t *req = (rep_batch_req_t *)extend_buf;
            if (log_point_is_invalid(&req->log_point) || log_point_is_invalid(&req->curr_point) ||
                req->compress_alg < COMPRESS_NONE || req->compress_alg > COMPRESS_LZ4 ||
                req->log_file_id >= lrcv_get_logfile_hwm(lrcv)) {
                return OG_FALSE;
            }
            break;
        }

        case REP_QUERY_STATUS_REQ: {
            rep_query_status_req_t *query_req = (rep_query_status_req_t *)extend_buf;
            if (log_point_is_invalid(&query_req->curr_point)) {
                return OG_FALSE;
            }
            break;
        }

        case REP_SWITCH_RESP: {
            rep_switch_resp_t *switch_resp = (rep_switch_resp_t *)extend_buf;
            if (switch_resp->state < REP_STATE_NORMAL || switch_resp->state > REP_STATE_REJECTED) {
                return OG_FALSE;
            }
            break;
        }

        case REP_ABR_REQ: {
            rep_abr_req_t *abr_req = (rep_abr_req_t *)extend_buf;
            if (abr_req->blk_size != lrcv->session->kernel->attr.page_size) {
                return OG_FALSE;
            }
            break;
        }

        case REP_HEART_BEAT_REQ:
        case REP_RECORD_BACKUPSET_RESP: {
            break;
        }

        default: {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 lrcv_need_exit(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (lrcv->session->killed) {
        OG_LOG_RUN_INF("Log receiver thread has been killed");
        return OG_TRUE;
    }

    if (db->status >= DB_STATUS_MOUNT && DB_IS_PRIMARY(db)) {
        OG_LOG_RUN_INF("[Log Receiver] database role is primary, database status is %s, thread will exit normally",
                       db_get_status(lrcv->session));
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t lrcv_flush_log(lrcv_context_t *lrcv, log_point_t *log_point, void *batch, uint32 size)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    log_file_t *file = &file_set->items[lrcv_get_curr_file(lrcv)];
    /*
     * DBStor (DEV_TYPE_ULOG) redo is addressed by LSN, while file/raw devices
     * are addressed by byte offset.  The primary writes ulog at the batch LSN,
     * so the receiver must do the same.  For byte-addressed files the receiver
     * appends at ITS OWN sequential write position: the BUILD snapshot does
     * not necessarily reproduce the primary's physical block layout, so using
     * the primary-side block id here would leave holes/gaps in the standby's
     * log file that the redo replay read point cannot follow.  The primary's
     * block id is kept in the flush point (see lrcv_process_batch) so the
     * sender still resumes at the right position in ITS file.
     */
    uint64 offset = (file->ctrl->type == DEV_TYPE_ULOG) ? (uint64)log_point->lsn
                                                        : (uint64)file->head.write_pos;
    uint32 space_size = CM_CALC_ALIGN(size, file->ctrl->block_size);
    log_batch_t *batch_x = (log_batch_t *)batch;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch_x->size - sizeof(log_batch_tail_t));

    int32 write_handle = (lrcv->stream_bound && lrcv_is_remote_stream(lrcv))
                             ? lrcv->stream_handle[lrcv_get_curr_file(lrcv)]
                             : file->handle;
    if (cm_write_device(file->ctrl->type, write_handle, offset, batch, space_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to write log into %s[%u] with log size %u at point [%u-%u/%llu]",
                       file->ctrl->name, lrcv_get_curr_file(lrcv), space_size,
                       file->head.rst_id, file->head.asn, file->head.write_pos);
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[Log Receiver] Write space size %u into log file[%u] at point [%u-%u/%llu] to %llu "
                     "size %u head [%llx/%llu/%llu] tail [%llx/%llu]",
                     space_size, lrcv_get_curr_file(lrcv), file->head.rst_id, file->head.asn,
                     file->head.write_pos, offset + space_size, batch_x->size, batch_x->head.magic_num,
                     (uint64)batch_x->head.point.lfn, batch_x->raft_index, tail->magic_num, (uint64)tail->point.lfn);
    lrcv->stream_flushed_lfn = log_point->lfn;
    if (!lrcv->stream_bound || !lrcv_is_remote_stream(lrcv)) {
        lrcv->session->kernel->lfn = log_point->lfn;
    }
    file->head.write_pos = offset + space_size;
    file->head.last = batch_x->scn;
    if (file->head.first == OG_INVALID_ID64) {
        file->head.first = batch_x->scn;
    }
    /*
     * Persist the file head on every flush.  The head carries the authoritative
     * write position of the received redo; if it is only written on the first
     * batch (or on log switch), an unclean stop leaves a stale on-disk head and
     * the standby's startup recovery treats the file as empty, skipping the
     * un-applied tail that was already received.
     */
    lrcv_flush_stream_head(lrcv, file);
    log_point->block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
    lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) - space_size);
    lrcv->stream_curr_point = *log_point;

    return OG_SUCCESS;
}

static status_t lrcv_process_heart_beat(lrcv_context_t *lrcv)
{
    knl_session_t *session = lrcv->session;
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_hb_resp_t *rep_hb_resp = (rep_hb_resp_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_hb_resp_t);
    rep_msg_header->type = REP_HEART_BEAT_RESP;

    rep_hb_resp->flush_point = lrcv->flush_point;
    rep_hb_resp->rcy_point = lrcv_get_node_ctrl(lrcv)->rcy_point;
    rep_hb_resp->replay_lsn = (uint64)lrcv_get_node_ctrl(lrcv)->lsn;
    rep_hb_resp->flush_scn = lrcv->flush_scn;
    rep_hb_resp->current_scn = DB_CURR_SCN(lrcv->session);
    rep_hb_resp->contflush_point.rst_id = lrcv->contflush_point.rst_id;
    rep_hb_resp->contflush_point.asn = lrcv->contflush_point.asn;

    status = cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                             (int32)cm_atomic_get(&session->kernel->attr.repl_pkg_size));
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send heart beat response message to primary");
    }
    return status;
}

static status_t lrcv_fetch_archived_log(lrcv_context_t *lrcv, log_file_t *file, bool32 need_wait,
    char *arch_name, uint32 arch_name_buf_size)
{
    lftc_task_handle_t lftc_handle;
    bool32 lftc_done = OG_FALSE;
    time_t last_send_time = cm_current_time();

    uint32 rst_id = file->head.rst_id;
    uint32 asn = file->head.asn;
    uint32 node_id = lrcv->stream_bound ? lrcv->src_node_id : lrcv->session->kernel->id;

    // Check whether corresponding archived log exists
    if (arch_get_archived_log_name(lrcv->session, rst_id, asn, ARCH_DEFAULT_DEST, arch_name, arch_name_buf_size,
                                   node_id)) {
        return OG_SUCCESS;
    }

    arch_set_archive_log_name(lrcv->session, rst_id, asn, ARCH_DEFAULT_DEST, arch_name, arch_name_buf_size,
                              node_id);
    OG_LOG_RUN_INF("[Log Receiver] Archive log %s for node %d not found", arch_name, node_id);
    if (cm_file_exist(arch_name)) {
        return OG_SUCCESS;
    }

    if (lftc_clt_create_task(lrcv->session, rst_id, asn, arch_name, &lftc_handle) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // Loop to check whether corresponding archived log exists & keep heart beat
    for (;;) {
        if (lrcv_need_exit(lrcv) || lrcv_need_suspend(lrcv)) {
            return OG_ERROR;
        }

        if (need_wait) {
            time_t now = cm_current_time();
            if ((now - last_send_time) >= REPL_HEART_BEAT_CHECK) {
                if (lrcv_process_heart_beat(lrcv) != OG_SUCCESS) {
                    lrcv_set_conn_err(lrcv);
                    return OG_ERROR;
                }
                last_send_time = now;
            }
        }

        if (lftc_clt_task_running(lrcv->session, &lftc_handle, &lftc_done)) {
            cm_sleep(100);
            continue;
        }

        if (lftc_done) {
            return OG_SUCCESS;
        }
        if (!need_wait) {
            return OG_ERROR;
        }

        // Sleep 1 seconds and retry
        cm_sleep(1000);

        // If failed to fetch log from primary, restart the task
        arch_set_archive_log_name(lrcv->session, rst_id, asn, ARCH_DEFAULT_DEST, arch_name, arch_name_buf_size,
                                  node_id);
        if (lftc_clt_create_task(lrcv->session, rst_id, asn, arch_name, &lftc_handle) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t lrcv_verify_checksum_batch(knl_session_t *session, log_batch_t *batch_input, uint32 size, log_point_t
    *log_point)
{
    uint32 left_size = size;
    log_batch_t *batch = batch_input;
    if (batch == NULL) {
        OG_LOG_RUN_ERR("[Log Receiver] batch is NULL!");
        return OG_ERROR;
    }
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

    while (left_size >= sizeof(log_batch_t)) {
        if (!rcy_validate_batch(batch, tail)) {
            OG_LOG_RUN_ERR("[Log Receiver] invalid received batch with lfn %llu, size is [%u/%u]",
                           (uint64)batch->head.point.lfn, left_size, size);
            return OG_ERROR;
        }

        if (rcy_verify_checksum(session, batch) != OG_SUCCESS) {
            return OG_ERROR;
        }

        log_point->lfn = batch->head.point.lfn;

        if (left_size <= batch->space_size) {
            break;
        }

        left_size -= batch->space_size;

        batch = (log_batch_t *)((char *)batch + batch->space_size);
        tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    }

    return OG_SUCCESS;
}

static inline void lrcv_set_switch_wait(lrcv_context_t *lrcv, rep_batch_req_t *req)
{
    lrcv->wait_info.waiting = OG_TRUE;
    lrcv->wait_info.wait_point = req->log_point;
    lrcv->wait_info.wait_point.block_id = 0; // Set to 0, easy to compare it with replay point
    lrcv->wait_info.file_id = req->log_file_id;
}

static void lrcv_reset_switch_wait(lrcv_context_t *lrcv)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    log_file_t *file = &file_set->items[lrcv_get_curr_file(lrcv)];
    log_point_t *wait_point = &lrcv->wait_info.wait_point;
    dtc_node_ctrl_t *node_ctrl = lrcv_get_node_ctrl(lrcv);
    uint32 node_id = lrcv->stream_bound ? lrcv->src_node_id : lrcv->session->kernel->id;

    lrcv_lock_logfile(lrcv);

    /* Invalidate current log file if it exists still */
    if (!LOG_IS_DROPPED(file->ctrl->flg)) {
        uint64 start_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        cm_latch_x(&file->latch, lrcv->session->id, NULL);
        file->head.asn = OG_INVALID_ASN;
        lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) + file->head.write_pos - start_pos);
        file->head.write_pos = start_pos;
        file->head.rcy_off = 0;
        file->ctrl->status = LOG_FILE_INACTIVE;
        file->ctrl->archived = OG_FALSE;
        lrcv_flush_stream_head(lrcv, file);
        if (db_save_log_ctrl(lrcv->session, lrcv_get_curr_file(lrcv), node_id) != OG_SUCCESS) {
            CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when reset switch wait");
        }
        cm_unlatch(&file->latch, NULL);
    }

    lrcv->stream_active_file = (uint16)lrcv->wait_info.file_id;
    lrcv->stream_curr_file = (uint16)lrcv->wait_info.file_id;

    /* Reset current log file */
    file = &file_set->items[lrcv->stream_curr_file];
    cm_latch_x(&file->latch, lrcv->session->id, NULL);
    file->head.asn = wait_point->asn;
    file->head.rst_id = (uint32)wait_point->rst_id;
    file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    file->head.rcy_off = 0;
    file->ctrl->status = LOG_FILE_CURRENT;
    file->ctrl->archived = OG_FALSE;
    lrcv_flush_stream_head(lrcv, file);
    if (db_save_log_ctrl(lrcv->session, lrcv->stream_curr_file, node_id) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when reset switch wait");
    }
    cm_unlatch(&file->latch, NULL);
    lrcv_unlock_logfile(lrcv);

    node_ctrl->log_first = lrcv->stream_active_file;
    node_ctrl->log_last = lrcv->stream_curr_file;
    if (db_save_core_ctrl(lrcv->session) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when reset switch wait");
    }
    lrcv_sync_stream_state(lrcv);

    /* Reset switch wait info */
    lrcv->wait_info.waiting = OG_FALSE;
    errno_t err = memset_sp(wait_point, sizeof(log_point_t), 0, sizeof(log_point_t));
    knl_securec_check(err);
    lrcv->wait_info.file_id = OG_INVALID_FILEID;
}

static status_t lrcv_send_switch_wait(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_log_switch_wait_t *rep_switch_wait = (rep_log_switch_wait_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_log_switch_wait_t);
    rep_msg_header->type = REP_LOG_SWITCH_WAIT_REQ;

    rep_switch_wait->wait_point = lrcv->wait_info.wait_point;
    status = cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send log switch wait message to primary");
    }

    return status;
}

static status_t lrcv_process_switch_wait(lrcv_context_t *lrcv)
{
    knl_session_t *session = lrcv->session;
    dtc_node_ctrl_t *node_ctrl = lrcv_get_node_ctrl(lrcv);
    log_point_t *rcy_point = &node_ctrl->rcy_point;
    log_point_t *lrp_point = &node_ctrl->lrp_point;
    log_point_t *wait_point = &lrcv->wait_info.wait_point;
    log_file_head_t *head = &session->kernel->rcy_ctx.arch_file.head;
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    log_file_head_t *curr = &file_set->items[lrcv_get_curr_file(lrcv)].head;
    if (!lrcv->wait_info.waiting) {
        return OG_SUCCESS;
    }

    /*
     * The following three situations indicate that all logs have been replayed
     * 1. Replay point is at the end of the last archive log (the previous one of the wait point),
     * 2. Replay point is at the end of current file (replay point is on current file),
     * 3. Replay point is equal to wait point.
     */
    if (!(log_cmp_point(rcy_point, wait_point) >= 0 ||
        (head->asn == wait_point->asn - 1 && rcy_point->block_id * head->block_size == head->write_pos) ||
        (curr->asn == wait_point->asn - 1 && rcy_point->block_id > 1 &&
        rcy_point->block_id * curr->block_size == curr->write_pos))) {
        return OG_SUCCESS;
    }

    rcy_wait_replay_complete(session);

    /* Wait rcy point reaches to lrp point */
    if (rcy_point->lfn < lrp_point->lfn) {
        ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
        cm_sleep(10);
        return OG_SUCCESS;
    }

    OG_LOG_RUN_INF("[Log Receiver] asn %u can locate in fileid %u on stream %u, log switch will succeed",
        lrcv->wait_info.wait_point.asn, lrcv->wait_info.file_id, lrcv->src_node_id);

    lrcv_reset_switch_wait(lrcv);
    if (lrcv_send_switch_wait(lrcv) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t lrcv_process_batch(lrcv_context_t *lrcv)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    dtc_node_ctrl_t *node_ctrl = lrcv_get_node_ctrl(lrcv);
    log_batch_t *batch = (log_batch_t *)(lrcv->recv_buf.read_buf.aligned_buf);
    rep_batch_req_t *req = (rep_batch_req_t *)lrcv->extend_buf.read_buf.aligned_buf;
    uint32 node_id = lrcv->stream_bound ? lrcv->src_node_id : lrcv->session->kernel->id;

    if (lrcv->header.size <= sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t)) {
        OG_LOG_RUN_ERR("[Log Receiver] invalid batch head size %u received, which is smaller than %u",
                       lrcv->header.size, (uint32)(sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t)));
        return OG_ERROR;
    }

    uint32 size = lrcv->header.size - sizeof(rep_msg_header_t) - sizeof(rep_batch_req_t);

    OG_LOG_DEBUG_INF("[Log Receiver] Received batch with size %u on log file[%u] at point [%u-%u/%u/%llu], "
                     "current log file is %u",
                     size, req->log_file_id, req->log_point.rst_id, req->log_point.asn,
                     req->log_point.block_id, (uint64)req->log_point.lfn, lrcv_get_curr_file(lrcv));

    lrcv->primary_curr_point = req->curr_point;

    if (lrcv->status == LRCV_PREPARE) {
        log_file_t *file = &file_set->items[lrcv_get_curr_file(lrcv)];

        /*
         * 1) req log_point > file head scenario: primary switched logfile during disconnection.
         * 2) req log_point = file head scenario: standby has just been built end.
         * 3) req log_point < file head scenario: this is cascaded standby, redo switched with skip,
         *                                        and peer node has failovered.
         */
        if (LRCV_LOG_POINT_ON_POST_FILE(req->log_point, file->head) ||
            (LRCV_LOG_POINT_ON_CURR_FILE(req->log_point, file->head) && req->log_file_id != lrcv_get_curr_file(lrcv)) ||
            LRCV_LOG_POINT_ON_PRE_FILE(req->log_point, file->head)) {
            uint64 start_pos;
            uint32 file_id = lrcv_get_active_file(lrcv);
            char arch_name[OG_FILE_NAME_BUFFER_SIZE];

            if (LRCV_LOG_POINT_ON_POST_FILE(req->log_point, file->head)) {
                if (lrcv_fetch_archived_log(lrcv, file, OG_TRUE, arch_name, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
                    OG_LOG_RUN_ERR("[Log Receiver] failed to fetch archive log file [%u/%u] from primary",
                                   file->head.rst_id, file->head.asn);
                    return OG_ERROR;
                }
            }

            lrcv_lock_logfile(lrcv);

            // Need to invalidate current log file
            start_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            cm_latch_x(&file->latch, lrcv->session->id, NULL);
            file->head.asn = OG_INVALID_ASN;
            file->head.rst_id = (uint32)req->log_point.rst_id;
            lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) + file->head.write_pos - start_pos);
            file->head.write_pos = start_pos;
            file->head.rcy_off = 0;
            file->ctrl->status = LOG_FILE_INACTIVE;
            file->ctrl->archived = OG_FALSE;
            lrcv_flush_stream_head(lrcv, file);
            if (db_save_log_ctrl(lrcv->session, lrcv_get_curr_file(lrcv), node_id) != OG_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch log file");
            }
            cm_unlatch(&file->latch, NULL);

            OG_LOG_RUN_INF("[Log Receiver] Invalidate current file, active %u current %u for stream %u",
                           lrcv_get_active_file(lrcv), lrcv_get_curr_file(lrcv), lrcv->src_node_id);

            while (file_id != lrcv_get_curr_file(lrcv)) {
                file = file_set->items + file_id;
                if (file->ctrl->status == LOG_FILE_ACTIVE) {
                    start_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
                    lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) + (uint64)file->ctrl->size - start_pos);
                    file->ctrl->status = LOG_FILE_UNUSED;
                }
                lrcv_get_next_file(lrcv, &file_id, OG_FALSE);
            }

            lrcv->stream_active_file = (uint16)req->log_file_id;
            lrcv->stream_curr_file = (uint16)req->log_file_id;

            file = &file_set->items[lrcv->stream_curr_file];
            cm_latch_x(&file->latch, lrcv->session->id, NULL);
            file->head.asn = req->log_point.asn;
            file->head.rst_id = (uint32)req->log_point.rst_id;
            file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            file->head.rcy_off = 0;
            file->ctrl->status = LOG_FILE_CURRENT;
            file->ctrl->archived = OG_FALSE;
            lrcv_flush_stream_head(lrcv, file);
            if (db_save_log_ctrl(lrcv->session, lrcv->stream_curr_file, node_id) != OG_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch log file");
            }
            cm_unlatch(&file->latch, NULL);
            lrcv_unlock_logfile(lrcv);

            OG_LOG_RUN_INF("[Log Receiver] Reset current file asn %u status %d, active %u current %u for stream %u",
                           file->head.asn, file->ctrl->status, lrcv->stream_active_file, lrcv->stream_curr_file,
                           lrcv->src_node_id);

            node_ctrl->log_first = lrcv->stream_active_file;
            node_ctrl->log_last = lrcv->stream_curr_file;
            if (OG_SUCCESS != db_save_core_ctrl(lrcv->session)) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch log file");
            }
            lrcv_sync_stream_state(lrcv);
        }

        lrcv->reset_asn = req->log_point.asn;
        lrcv->status = LRCV_READY;
    }

    if (req->log_file_id != lrcv_get_curr_file(lrcv) ||
        req->log_point.asn != file_set->items[lrcv_get_curr_file(lrcv)].head.asn) {
        if (lrcv_switch_need_wait(lrcv, (uint16)req->log_file_id, req->log_point.asn)) {
            lrcv_set_switch_wait(lrcv, req);
            OG_LOG_RUN_INF("[Log Receiver] asn %u does not locate in fileid %u on stream %u, log switch should wait",
                req->log_point.asn, req->log_file_id, lrcv->src_node_id);
            return OG_SUCCESS;
        }

        if (lrcv_switch_logfile(lrcv, (uint16)req->log_file_id, req->log_point.asn) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[Log Receiver] failed to switch log file to %u with asn %u", req->log_file_id,
                           req->log_point.asn);
            return OG_ERROR;
        }
    }

    knl_panic(req->log_file_id == lrcv_get_curr_file(lrcv));

    if (lrcv_verify_checksum_batch(lrcv->session, batch, size, &req->log_point) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lrcv_flush_log(lrcv, &req->log_point, (void *)batch, size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    lrcv->flush_point = req->log_point;
    lrcv->flush_scn = req->scn;
    lrcv_update_frontier(lrcv, batch->lsn);

    return OG_SUCCESS;
}

static status_t lrcv_send_batch_ack(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_batch_resp_t *rep_batch_resp = (rep_batch_resp_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_batch_resp_t);
    rep_msg_header->type = REP_BATCH_RESP;

    rep_batch_resp->flush_point = lrcv->flush_point;
    rep_batch_resp->rcy_point = lrcv_get_node_ctrl(lrcv)->rcy_point;
    rep_batch_resp->replay_lsn = (uint64)lrcv_get_node_ctrl(lrcv)->lsn;
    rep_batch_resp->flush_scn = lrcv->flush_scn;
    rep_batch_resp->current_scn = DB_CURR_SCN(lrcv->session);
    rep_batch_resp->contflush_point.rst_id = lrcv->contflush_point.rst_id;
    rep_batch_resp->contflush_point.asn = lrcv->contflush_point.asn;

    status = cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send batch response message to primary");
    }
    return status;
}

static void lrcv_needrepair(lrcv_context_t *lrcv)
{
    lrcv->status = LRCV_NEED_REPAIR;
    cm_sleep(2000);
}

static status_t lrcv_wait_logfile_no_active(lrcv_context_t *lrcv)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    log_point_t *rcy_point = &lrcv_get_node_ctrl(lrcv)->rcy_point;
    uint32 file_id = lrcv_get_active_file(lrcv);
    log_file_t *file = NULL;
    uint64 lfn;
    uint64 scn;
    uint32 node_id = lrcv->stream_bound ? lrcv->src_node_id : lrcv->session->kernel->id;

    OG_LOG_RUN_INF("[Log Receiver] log file active %u current %u for stream %u", lrcv_get_active_file(lrcv),
                   lrcv_get_curr_file(lrcv), lrcv->src_node_id);
    // Wait for all log files before current file to become LOG_STATE_INACTIVE or LOG_STATE_UNUSED
    while (file_id != lrcv_get_curr_file(lrcv)) {
        ckpt_trigger(lrcv->session, OG_FALSE, CKPT_TRIGGER_INC);

        file = file_set->items + file_id;
        if (file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED) {
            lrcv_get_next_file(lrcv, &file_id, OG_FALSE);
        } else if (file->ctrl->status == LOG_FILE_ACTIVE) {
            if (LRCV_LOG_POINT_ON_CURR_FILE(*rcy_point, file->head)) {
                char arch_name[OG_FILE_NAME_BUFFER_SIZE];

                if (arch_get_archived_log_name(lrcv->session, file->head.rst_id, file->head.asn, ARCH_DEFAULT_DEST,
                                               arch_name, OG_FILE_NAME_BUFFER_SIZE, node_id)) {
                    uint64 file_offset = 0;
                    if (log_get_file_offset(lrcv->session, arch_name, &lrcv->recv_buf.read_buf, &file_offset,
                                            &lfn, &scn) != OG_SUCCESS) {
                        OG_LOG_RUN_ERR("[Log Receiver] failed to get file offset for archived log %s ", arch_name);
                        return OG_ERROR;
                    }

                    if (rcy_point->lfn >= lfn || lrcv->stream_flushed_lfn >= lfn) {
                        OG_LOG_RUN_INF("[Log Receiver] rcy_point [%u-%u/%u/%llu] or replay lfn %llu has reached "
                                       "the end of log file[%u] [%u-%u/%llu/%llu]",
                                       rcy_point->rst_id, rcy_point->asn, rcy_point->block_id,
                                       (uint64)rcy_point->lfn, lrcv->stream_flushed_lfn, file_id,
                                       file->head.rst_id, file->head.asn, file_offset, lfn);
                        lrcv_get_next_file(lrcv, &file_id, OG_FALSE);
                    } else {
                        OG_LOG_DEBUG_INF("[Log Receiver] rcy_point [%u-%u/%u/%llu] has not reached the end of "
                                         "log file[%u] [%u-%u/%llu/%llu], so continue",
                                         rcy_point->rst_id, rcy_point->asn, rcy_point->block_id,
                                         (uint64)rcy_point->lfn, file_id, file->head.rst_id,
                                         file->head.asn, file_offset, lfn);
                        cm_sleep(100);
                    }
                }
            } else if (LRCV_LOG_POINT_ON_POST_FILE(*rcy_point, file->head)) {
                if (file->head.asn != OG_INVALID_ASN) {
                    lrcv_recycle_file(lrcv, rcy_point);
                } else {
                    lrcv_get_next_file(lrcv, &file_id, OG_FALSE);
                }
            } else {
                cm_sleep(1000);

                if (lrcv_process_heart_beat(lrcv) != OG_SUCCESS) {
                    return OG_ERROR;
                }
            }
        } else {
            cm_sleep(10);
        }

        if (lrcv->session->killed || lrcv->thread.closed) {
            OG_LOG_RUN_INF("Log receiver thread has been killed");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t lrcv_prepare_log_files(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    dtc_node_ctrl_t *node_ctrl = lrcv_get_node_ctrl(lrcv);
    log_point_t *lrp_point = &node_ctrl->lrp_point;
    log_point_t *rcy_point = &node_ctrl->rcy_point;
    uint64 curr_lfn = 0;
    uint64 scn;
    log_file_t *file = NULL;
    uint32 node_id = lrcv->stream_bound ? lrcv->src_node_id : lrcv->session->kernel->id;

    if (lrcv_wait_logfile_no_active(lrcv) != OG_SUCCESS) {
        return OG_ERROR;
    }

    arch_reset_file_id(lrcv->session, ARCH_DEFAULT_DEST);

    lrcv->flush_point.lfn = 0;
    lrcv->contflush_point.rst_id = node_ctrl->rcy_point.rst_id;
    lrcv->contflush_point.asn = node_ctrl->rcy_point.asn;
    file = &file_set->items[lrcv_get_curr_file(lrcv)];

    OG_LOG_RUN_INF("[Log Receiver] Standby current log file[%u] status %d log point is [%u-%u/%llu/%llu]",
                   lrcv_get_curr_file(lrcv), file->ctrl->status, file->head.rst_id,
                   file->head.asn, file->head.write_pos, curr_lfn);
    OG_LOG_RUN_INF("[Log Receiver] Standby lrp_point is [%u-%u/%u/%llu] rcy_point is [%u-%u/%u/%llu]",
                   lrp_point->rst_id, lrp_point->asn, lrp_point->block_id, (uint64)lrp_point->lfn,
                   rcy_point->rst_id, rcy_point->asn, rcy_point->block_id, (uint64)rcy_point->lfn);
    OG_LOG_RUN_INF("[Log Receiver] Primary current log point is [%u-%u/%u/%llu]",
                   req->curr_point.rst_id, req->curr_point.asn,
                   req->curr_point.block_id, (uint64)req->curr_point.lfn);

    if (LRCV_LOG_POINT_ON_CURR_FILE(*lrp_point, file->head)) {
        if (LRCV_LOG_POINT_ON_CURR_FILE(req->curr_point, file->head)) {
            if (!lrcv->reconnected) {
                lrcv->flush_point.rst_id = file->head.rst_id;
                lrcv->flush_point.asn = file->head.asn;
                if (lrcv_is_dss_log(lrcv)) {
                    /*
                     * DSS-backed log files cannot be byte-scanned; the head write pos is
                     * maintained by the receiver itself, and the replay point is
                     * the authoritative receive position on a freshly built
                     * standby.
                     */
                    curr_lfn = lrp_point->lfn;
                } else {
                    if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                            (uint64 *)&file->head.write_pos, &curr_lfn, &scn) != OG_SUCCESS) {
                        OG_LOG_RUN_ERR("[Log Receiver] failed to get file offset for online log %s ",
                                       file->ctrl->name);
                        return OG_ERROR;
                    }
                }
                OG_LOG_RUN_INF("[Log Receiver] Standby repaired current log file[%u] status %d log point is [%u-%u/%llu/%llu]",
                               lrcv_get_curr_file(lrcv), file->ctrl->status, file->head.rst_id, file->head.asn,
                               file->head.write_pos, curr_lfn);
                lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
                if (curr_lfn == 0) {
                    /*
                     * Freshly built standby: the current file contains no
                     * redo yet, so the file scan cannot tell the primary
                     * where to resume.  Resume from the APPLIED point (rcy)
                     * instead of the unavailable lrp, otherwise the primary
                     * re-sends the whole stream from lfn 1 (wasteful but
                     * still safe via duplicate skipping) or, worse, resumes
                     * from a point past unapplied redo.
                     */
                    lrcv->flush_point.lfn = rcy_point->lfn;
                    OG_LOG_RUN_INF("[Log Receiver] fresh log file, resume stream from applied point lfn %llu",
                                   (uint64)lrcv->flush_point.lfn);
                } else {
                    lrcv->flush_point.lfn = curr_lfn;
                }
            } else {
                lrcv->flush_point = lrcv->stream_curr_point;
            }
            /*
             * N-to-M standby resume alignment: the BUILD snapshot records the
             * rcy/lrp point with the primary-side block id, but the standby's
             * own log file may start the next asn at a different block (the
             * build leaves the current file freshly initialized).  The
             * receiver's flush point is the true position where the next
             * batch lands, so when the applied lfn matches the received lfn,
             * move the apply cursor to the receiver's block position.
             * Otherwise the LRPL starts reading mid-stream and reports
             * "not continuous" for every batch.
             */
            if (node_ctrl->rcy_point.lfn == lrcv->flush_point.lfn &&
                (node_ctrl->rcy_point.asn != lrcv->flush_point.asn ||
                 node_ctrl->rcy_point.rst_id != lrcv->flush_point.rst_id ||
                 node_ctrl->rcy_point.block_id != lrcv->flush_point.block_id)) {
                OG_LOG_RUN_INF("[Log Receiver] align node %u rcy/lrp point [%u-%u/%u] -> [%u-%u/%u] at lfn %llu "
                               "with stream flush point",
                               node_id, node_ctrl->rcy_point.rst_id, node_ctrl->rcy_point.asn,
                               node_ctrl->rcy_point.block_id, lrcv->flush_point.rst_id,
                               lrcv->flush_point.asn, lrcv->flush_point.block_id,
                               (uint64)lrcv->flush_point.lfn);
                node_ctrl->rcy_point.rst_id = lrcv->flush_point.rst_id;
                node_ctrl->rcy_point.asn = lrcv->flush_point.asn;
                node_ctrl->rcy_point.block_id = lrcv->flush_point.block_id;
                node_ctrl->lrp_point.rst_id = lrcv->flush_point.rst_id;
                node_ctrl->lrp_point.asn = lrcv->flush_point.asn;
                node_ctrl->lrp_point.block_id = lrcv->flush_point.block_id;
            }
            OG_LOG_RUN_INF("[Log Receiver] lrp_point is on current log, and primary/standby log has no gap");
        } else if (LRCV_LOG_POINT_ON_POST_FILE(req->curr_point, file->head)) {
            char arch_name[OG_FILE_NAME_BUFFER_SIZE];
            uint64 write_pos_ori = file->head.write_pos;
            uint64 write_pos_new;

            // Start LFTC to fetch corresponding archived log from primary
            if (lrcv_fetch_archived_log(lrcv, file, OG_FALSE, arch_name, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to fetch archive log file [%u/%u] from primary",
                               file->head.rst_id, file->head.asn);
                return OG_ERROR;
            }
            file->ctrl->archived = OG_TRUE;
            if (db_save_log_ctrl(lrcv->session, lrcv_get_curr_file(lrcv), node_id) != OG_SUCCESS) {
                CM_ABORT(0, "[Log Receiver] ABORT INFO: save control redo file failed when prepare logfile");
            }
            lrcv->flush_point.rst_id = file->head.rst_id;
            lrcv->flush_point.asn = file->head.asn;
            if (log_get_file_offset(lrcv->session, arch_name, &lrcv->recv_buf.read_buf,
                                    &write_pos_new, &curr_lfn, &scn) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to get file offset for archived log %s ", arch_name);
                return OG_ERROR;
            }

            log_set_logfile_writepos(lrcv->session, file, write_pos_new);
            OG_LOG_RUN_INF("[Log Receiver] Standby repaired current log file[%u] status %d log point "
                           "is [%u-%u/%llu/%llu] with old pos %llu",
                           lrcv_get_curr_file(lrcv), file->ctrl->status, file->head.rst_id, file->head.asn,
                           file->head.write_pos, curr_lfn, write_pos_ori);
            if (lrcv->reconnected) {
                lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) - (file->head.write_pos - write_pos_ori));
            }
            lrcv->flush_point.lfn = curr_lfn;
            lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
            OG_LOG_RUN_INF("[Log Receiver] lrp_point is on current log, and primary/standby log has gap");
        } else if (req->curr_point.lfn >= lrp_point->lfn) {
            /*
             * Log-switch boundary: the primary's current point is still on the
             * previous file (asn N, possibly with a higher LFN) while the
             * standby's current file is the next file (asn N+1) created by
             * the build snapshot.  Resume from the end of the standby's
             * previous file (lfn 949) so the primary re-sends its remaining
             * asn-N batches; the first batch will naturally switch the
             * receiver's current file, and the re-sent bytes are idempotent.
             */
            lrcv->flush_point.rst_id = req->curr_point.rst_id;
            lrcv->flush_point.asn = req->curr_point.asn;
            lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
            lrcv->flush_point.lfn = lrp_point->lfn;
            OG_LOG_RUN_INF("[Log Receiver] primary still on previous file asn %u (lfn %llu), "
                           "resume from flush point [%u-%u/%u/%llu]",
                           req->curr_point.asn, (uint64)req->curr_point.lfn,
                           lrcv->flush_point.rst_id, lrcv->flush_point.asn, lrcv->flush_point.block_id,
                           (uint64)lrcv->flush_point.lfn);
        } else {
            OG_LOG_RUN_ERR("[Log Receiver] current log point [%u-%u/%u/%llu] from primary is "
                           "less than standby current log [%u-%u]",
                           req->curr_point.rst_id, req->curr_point.asn, req->curr_point.block_id,
                           (uint64)req->curr_point.lfn, file->head.rst_id, file->head.asn);
            return OG_ERROR;
        }
    } else if (LRCV_LOG_POINT_ON_PRE_FILE(*lrp_point, file->head)) {
        lrcv->flush_point = lrcv->stream_curr_point;

        if (!lrcv->reconnected) {
            if (lrcv_is_dss_log(lrcv)) {
                curr_lfn = lrcv->stream_curr_point.lfn;
            } else {
                if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                        (uint64 *)&file->head.write_pos, &curr_lfn, &scn) != OG_SUCCESS) {
                    OG_LOG_RUN_ERR("[Log Receiver] failed to get file offset for logfile[%u] %s, latest lfn %llu",
                                   lrcv_get_curr_file(lrcv), file->ctrl->name, curr_lfn);
                    return OG_ERROR;
                }
            }
        }

        /*
         * The current point of the primary node is smaller than the current file of the standby node,
         * this issue occurs only when redo skips and the peer node becomes the primary node after failover.
         * In this case, we set flush point with redo current point.
         */
        if (!LRCV_LOG_POINT_ON_PRE_FILE(req->curr_point, file->head)) {
            lrcv->flush_point.rst_id = file->head.rst_id;
            lrcv->flush_point.asn = file->head.asn;
            lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
            if (curr_lfn > lrcv->flush_point.lfn) {
                lrcv->flush_point.lfn = curr_lfn;
            }
        }

        OG_LOG_RUN_INF("[Log Receiver] lrp_point is on previous log");
    } else if (file->head.asn == OG_INVALID_ASN || req->curr_point.lfn >= lrp_point->lfn) {
        /*
         * The replay point is after the current file (log-switch boundary:
         * lrp sits at the start of the next file) or the current file is
         * invalid.  Resume from the replay point in the primary's file
         * representation; the first batch will switch the receiver's current
         * file naturally.
         */
        lrcv->flush_point.rst_id = req->curr_point.rst_id;
        lrcv->flush_point.asn = req->curr_point.asn;
        lrcv->flush_point.block_id = 1;
        /*
         * Resume from the APPLIED point (rcy), not the available point (lrp):
         * on a freshly built standby the local file may not contain the redo
         * between rcy and lrp, and resuming from lrp would silently skip
         * unapplied redo.  Any re-sent prefix is idempotent (the replay
         * skips batches whose lfn is not ahead of rcy).
         */
        lrcv->flush_point.lfn = rcy_point->lfn;
        OG_LOG_RUN_INF("[Log Receiver] stream %u replay point after current file, "
                       "resume from applied point [%u-%u/%u/%llu]",
                       lrcv->src_node_id, lrcv->flush_point.rst_id, lrcv->flush_point.asn,
                       lrcv->flush_point.block_id, (uint64)lrcv->flush_point.lfn);
    } else {
        knl_panic(0);
    }

    if (!lrcv->reconnected) {
        lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) + log_file_freesize(file));
    }

    OG_LOG_RUN_INF("[Log Receiver] Set flush point to [%u-%u/%u/%llu], log free size is %llu",
                   lrcv->flush_point.rst_id, lrcv->flush_point.asn, lrcv->flush_point.block_id,
                   (uint64)lrcv->flush_point.lfn, lrcv_get_free_size(lrcv));
    return OG_SUCCESS;
}

static bool32 lrcv_log_ctrl_check(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    log_file_t *logfile = NULL;
    log_file_ctrl_t *ctrl_pri = NULL;
    uint32 hwm = lrcv_get_logfile_hwm(lrcv);

    if (req->log_num != hwm) {
        OG_LOG_RUN_ERR("[Log Receiver] Redo hwm [%u/%u] is no equal for primary/standby, need repair",
                       req->log_num, hwm);
        return OG_FALSE;
    }

    ctrl_pri = (log_file_ctrl_t *)((char *)req + sizeof(rep_query_status_req_t));
    for (uint32 i = 0; i < hwm; i++) {
        logfile = &file_set->items[i];

        if (logfile->ctrl->flg != ctrl_pri->flg) {
            OG_LOG_RUN_ERR("[Log Receiver] %s flag %u is different from %s flag %u (0-normal, 1-dropped, 2-alarmed), "
                           "need repair", (strlen(ctrl_pri->name) != 0) ? ctrl_pri->name : "redo", ctrl_pri->flg,
                           (strlen(logfile->ctrl->name) != 0) ? logfile->ctrl->name : "redo", logfile->ctrl->flg);
            return OG_FALSE;
        }

        if (logfile->ctrl->block_size != ctrl_pri->block_size) {
            OG_LOG_RUN_ERR("[Log Receiver] %s block size %u is different from %s block size %u, need repair",
                           ctrl_pri->name, ctrl_pri->block_size, logfile->ctrl->name, logfile->ctrl->block_size);
            return OG_FALSE;
        }

        if (logfile->ctrl->file_id != ctrl_pri->file_id) {
            OG_LOG_RUN_ERR("[Log Receiver] %s fileid %d is different from %s fileid %d, need repair",
                           ctrl_pri->name, ctrl_pri->file_id, logfile->ctrl->name, logfile->ctrl->file_id);
            return OG_FALSE;
        }

        if (logfile->ctrl->size != ctrl_pri->size) {
            OG_LOG_RUN_ERR("[Log Receiver] %s file size %lld is different from %s file size %lld, need repair",
                           ctrl_pri->name, ctrl_pri->size, logfile->ctrl->name, logfile->ctrl->size);
            return OG_FALSE;
        }

        if (logfile->ctrl->type != ctrl_pri->type) {
            OG_LOG_RUN_ERR("[Log Receiver] %s type %u is different from %s type %u (1-file, 2-raw, 3-cfs), "
                           "need repair", ctrl_pri->name, ctrl_pri->type, logfile->ctrl->name, logfile->ctrl->type);
            return OG_FALSE;
        }

        ctrl_pri++;
    }

    return OG_TRUE;
}

static void lrcv_repair_logfile_rstid(lrcv_context_t *lrcv, reset_log_t *rst_log)
{
    log_file_t *file = NULL;
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);

    for (uint32 i = 0; i < lrcv_get_logfile_hwm(lrcv); i++) {
        file = &file_set->items[i];

        if (file->head.asn > rst_log->last_asn && file->head.rst_id < rst_log->rst_id) {
            OG_LOG_RUN_INF("[Log Receiver] logfile %s asn %u larger than resetlog asn %u, "
                           "but rstid %u less than resetlog rstid %u, revise file rstid with %u",
                           file->ctrl->name, file->head.asn, rst_log->last_asn, file->head.rst_id,
                           rst_log->rst_id, rst_log->rst_id);
            file->head.rst_id = rst_log->rst_id;
            lrcv_flush_stream_head(lrcv, file);
        }
    }
}

static status_t lrcv_check_resetid(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    log_point_t *point = &lrcv->stream_curr_point;
    database_t *db = &lrcv->session->kernel->db;
    log_point_t *rcy_point = &lrcv_get_node_ctrl(lrcv)->rcy_point;
    reset_log_t *resetlog = &db->ctrl.core.resetlogs;

    if (req->rst_log.rst_id == resetlog->rst_id && resetlog->rst_id != 0 &&
        req->rst_log.last_lfn != resetlog->last_lfn) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] primary has same resetid [%u] with standby, "
                       "but last lfn is not equal [%llu/%llu], "
                       "they are different sources, need repair",
                       req->rst_log.rst_id, req->rst_log.last_lfn, resetlog->last_lfn);
        return OG_ERROR;
    }

    if (req->rst_log.rst_id > point->rst_id + OG_MAX_RESETLOG_DISTANCE) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] Resetlog distance is larger than [%u], need repair, "
                       "rst_id in message/curr_point is %u/%u",
                       OG_MAX_RESETLOG_DISTANCE, req->rst_log.rst_id, point->rst_id);
        return OG_ERROR;
    }

    if (req->rst_log.rst_id > rcy_point->rst_id + OG_MAX_RESETLOG_DISTANCE) {
        // wait ckpt update rcy point
        ckpt_trigger(lrcv->session, OG_TRUE, CKPT_TRIGGER_FULL);
        if (req->rst_log.rst_id > rcy_point->rst_id + OG_MAX_RESETLOG_DISTANCE) {
            lrcv_needrepair(lrcv);
            OG_LOG_RUN_ERR("[Log Receiver] Resetlog distance is larger than [%u], need repair, "
                           "rst_id in message/rcy_point is %u/%u",
                           OG_MAX_RESETLOG_DISTANCE, req->rst_log.rst_id, rcy_point->rst_id);
            return OG_ERROR;
        }
    }

    if (req->rst_log.rst_id < point->rst_id || req->rst_log.rst_id < resetlog->rst_id) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] Standby current point resetid [%u] or resetlogs resetid [%u] is faster "
                       "than primary resetlogs [%u], need repair",
                       point->rst_id, resetlog->rst_id, req->rst_log.rst_id);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void lrcv_reset_primary_host(knl_session_t *session)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        errno_t ret = memset_sp(&mgr->streams[i].primary_host, sizeof(mgr->streams[i].primary_host), 0,
                                sizeof(mgr->streams[i].primary_host));
        knl_securec_check(ret);
    }
}

static void lrcv_trigger_start_lsnd(lrcv_context_t *lrcv)
{
    knl_session_t *session = lrcv->session;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    arch_ctx->arch_dest_state_changed = OG_TRUE;
    while (arch_ctx->arch_dest_state_changed) {
        if (session->killed) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            return;
        }
        cm_sleep(1);
    }

    cm_spin_unlock(&arch_ctx->dest_lock);
}


static status_t lrcv_resetlog_check(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    log_point_t *point = &lrcv->stream_curr_point;
    database_t *db = &lrcv->session->kernel->db;
    log_point_t *rcy_point = &lrcv_get_node_ctrl(lrcv)->rcy_point;
    log_point_t *lrp_point = &lrcv_get_node_ctrl(lrcv)->lrp_point;
    reset_log_t *resetlog = &db->ctrl.core.resetlogs;
    bool32 resetid_changed = OG_FALSE;

    if (req->version >= ST_VERSION_1 && req->notify_repair) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] primary detects invalid batches based on the sending point returned by "
                       "standby, need repair");
        return OG_ERROR;
    }

    if (!db->ctrl.core.is_restored && LRCV_INVALID_DBID(req->dbid, db->ctrl.core.dbid)) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] primary dbid [%u] is not equal to standby dbid [%u], need repair",
                       req->dbid, db->ctrl.core.dbid);
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[Log Receiver] resetlog_check primary resetlog is [%u/%u/%llu], standby resetlog is [%u/%u/%llu], "
                   "primary current point is [%u/%u/%llu], standby current point is [%u/%u/%llu], "
                   "standby rcy point is [%u/%u/%llu], lrp point is [%u/%u/%llu], "
                   "standby flush point is [%u/%u/%llu]",
                   req->rst_log.rst_id, req->rst_log.last_asn, req->rst_log.last_lfn,
                   resetlog->rst_id, resetlog->last_asn, resetlog->last_lfn,
                   req->curr_point.rst_id, req->curr_point.asn, (uint64)req->curr_point.lfn,
                   point->rst_id, point->asn, (uint64)point->lfn,
                   rcy_point->rst_id, rcy_point->asn, (uint64)rcy_point->lfn,
                   lrp_point->rst_id, lrp_point->asn, (uint64)lrp_point->lfn,
                   lrcv->flush_point.rst_id, lrcv->flush_point.asn, (uint64)lrcv->flush_point.lfn);

    if (lrcv_check_resetid(lrcv, req) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /*
     * "Standby faster" must be decided by LFN (the monotonic per-stream
     * sequence), not by the (rst_id, asn) file representation: at a log-switch
     * boundary the standby may be at the start of the next file while the
     * primary is still at the end of the previous one with the same LFN, and
     * the standby may be behind in LFN while its file asn looks higher.
     * Fall back to the file comparison only when both LFN values are
     * uninitialized.
     */
    if (point->lfn > req->curr_point.lfn ||
        (point->lfn == 0 && req->curr_point.lfn == 0 && LOG_POINT_FILE_LT(req->curr_point, *point))) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] Standby current point [%u/%u/%llu] is faster "
                       "than primary current point [%u/%u/%llu], need repair", point->rst_id, point->asn,
                       (uint64)point->lfn, req->curr_point.rst_id, req->curr_point.asn, (uint64)req->curr_point.lfn);
        return OG_ERROR;
    }

    if (req->rst_log.rst_id != point->rst_id &&
        ((req->rst_log.last_lfn < lrp_point->lfn - 1) || (req->rst_log.last_lfn < point->lfn))) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] Standby log lrp point [%u/%llu] current redo point [%u/%llu] is faster "
                       "than primary [%u/%llu], need repair",
                       point->rst_id, (uint64)lrp_point->lfn - 1, point->rst_id,
                       (uint64)point->lfn, req->rst_log.rst_id, req->rst_log.last_lfn);
        return OG_ERROR;
    }

    if (!lrcv_log_ctrl_check(lrcv, req)) {
        lrcv_needrepair(lrcv);
        return OG_ERROR;
    }

    /*
     * Consider the disaster recovery scenario as follows: node A is primary, node B & C is standby,
     * and node D is cascaded standby.
     * A ----------> C
     * |             |
     * B             D
     *
     * If node A is down abnormally, and node B is promoted to primary by failover, then node B will
     * connect to node C.
     * A        ---> C
     *        /      |
     * B ----        D
     *
     * resetlog in node C will be different from D. So node C should reconnect to node D to transfer
     * new resetlog to node D.
     */
    if (req->rst_log.rst_id > resetlog->rst_id) {
        resetid_changed = OG_TRUE;
    }

    *resetlog = req->rst_log;
    if (!OG_INVALID_SCN(req->reset_log_scn)) {
        db->ctrl.core.reset_log_scn = req->reset_log_scn;
    }
    if (db_save_core_ctrl(lrcv->session) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: Save core control file failed when database reset logs, need repair");
    }

    if (resetid_changed || lrcv->host_changed) {
        lsnd_mark_reconnect(lrcv->session, resetid_changed, lrcv->host_changed);
    }

    lrcv_repair_logfile_rstid(lrcv, &req->rst_log);

    OG_LOG_RUN_INF("[Log Receiver] Resetlog check passed. Current reset log is [%u/%u/%llu], "
                   "current log point in redo context is [%u-%u/%u/%llu]",
                   req->rst_log.rst_id, req->rst_log.last_asn, req->rst_log.last_lfn,
                   point->rst_id, point->asn, point->block_id, (uint64)point->lfn);

    return OG_SUCCESS;
}

static void lrcv_try_change_db_role(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (lrcv->role_spec_building) {
        return;
    }

    if (DB_IS_PHYSICAL_STANDBY(db) && (lrcv->peer_role == PEER_STANDBY)) {
        db->ctrl.core.db_role = REPL_ROLE_CASCADED_PHYSICAL_STANDBY;
        OG_LOG_RUN_INF("[Log Receiver] Changes database role from physical standby to cascaded physical standby");
    }

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && (lrcv->peer_role == PEER_PRIMARY)) {
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
        lrcv_trigger_start_lsnd(lrcv);
        OG_LOG_RUN_INF("[Log Receiver] Changes database role from cascaded physical standby to physical standby");
    }

    if (db->status == DB_STATUS_OPEN && db_save_core_ctrl(lrcv->session) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: Save core control file failed when changes database role");
    }
}

static void lrcv_try_save_dbid(lrcv_context_t *lrcv)
{
    database_t *db = &lrcv->session->kernel->db;

    if (db->ctrl.core.is_restored) {
        db->ctrl.core.dbid = lrcv->dbid;
        db_set_ctrl_restored(lrcv->session, OG_FALSE);
    }
}

/*
 * Bind this receiver connection to a redo stream identified by
 * (src_dbid, src_node_id).  The stream is admitted once: if another active
 * connection already serves the same stream, the new one is rejected
 * (same-stream dual-primary protection).  The context is migrated to slot
 * src_node_id when that slot is free, so that streams[src_node_id] always
 * holds the stream with the same source node id (legacy paths use
 * streams[0] as the default stream).
 */
static lrcv_context_t *lrcv_bind_stream(lrcv_context_t *lrcv, rep_query_status_req_t *req)
{
    knl_instance_t *kernel = lrcv->session->kernel;
    lrcv_mgr_t *mgr = &kernel->lrcv_mgr;
    uint32 src_node_id = req->src_node_id;
    uint32 src_dbid = req->src_dbid;

    /* legacy peer (version < ST_VERSION_2): single stream, node 0 */
    if (req->version < ST_VERSION_2) {
        src_node_id = 0;
        src_dbid = req->dbid;
    }

    if (src_node_id >= OG_MAX_INSTANCES) {
        lrcv_needrepair(lrcv);
        OG_LOG_RUN_ERR("[Log Receiver] invalid source node id %u from primary, need repair", src_node_id);
        return NULL;
    }

    cm_spin_lock(&mgr->lock, NULL);
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *other = &mgr->streams[i];
        if (other == lrcv) {
            continue;
        }
        if (other->stream_bound && other->src_node_id == src_node_id && other->session != NULL) {
            cm_spin_unlock(&mgr->lock);
            OG_THROW_ERROR(ERR_DB_TOO_MANY_PRIMARY,
                "another primary has connected for the same redo stream (src_node_id %u)", src_node_id);
            OG_LOG_RUN_ERR("[Log Receiver] stream %u already has an active connection, reject the new one",
                           src_node_id);
            return NULL;
        }
    }

    lrcv->src_node_id = src_node_id;
    lrcv->src_dbid = src_dbid;
    lrcv->stream_bound = OG_TRUE;

    /*
     * The stream identity lives in the context itself (src_node_id), so the
     * slot index is only a pool allocation and does not need to match the
     * stream id.  Never migrate the context between slots: another connection
     * may be initializing the target slot concurrently, and overwriting it
     * would corrupt that connection's session/buffers.
     */
    mgr->stream_count = MAX(mgr->stream_count, src_node_id + 1);
    cm_spin_unlock(&mgr->lock);

    /*
     * While the database is not OPEN (e.g. standby in NOMOUNT before/while
     * BUILD), the control file / node ctrl may not be loaded yet.  Do not
     * initialize the per-stream file group from unloaded state; the stream
     * simply stays not-ready until the database opens.
     */
    if (lrcv->session->kernel->db.status < DB_STATUS_OPEN) {
        OG_LOG_RUN_INF("[Log Receiver] stream %u bound but database not open, wait for open", src_node_id);
        return lrcv;
    }

    /* initialize per-stream log file group state */
    logfile_set_t *file_set = LOGFILE_SET(lrcv->session, src_node_id);
    dtc_node_ctrl_t *node_ctrl = dtc_get_ctrl(lrcv->session, src_node_id);
    lrcv->file_set = file_set;
    if (src_node_id == kernel->id) {
        lrcv->stream_curr_file = kernel->redo_ctx.curr_file;
        lrcv->stream_active_file = kernel->redo_ctx.active_file;
        lrcv->stream_logfile_hwm = kernel->redo_ctx.logfile_hwm;
        lrcv->stream_free_size = kernel->redo_ctx.free_size;
        lrcv->stream_curr_point = kernel->redo_ctx.curr_point;
    } else {
        file_set->logfile_hwm = node_ctrl->log_hwm;
        file_set->log_count = node_ctrl->log_count;
        for (uint32 h = 0; h < OG_MAX_LOG_FILES; h++) {
            lrcv->stream_handle[h] = -1;
        }
        /*
         * Bind per-node ctrl pointers and open the source node's log files so
         * the receiver can write this stream's redo into the correct file
         * group.  File heads are derived from the node ctrl / replay point
         * instead of being read from the device: DSS-backed devices may not
         * support the byte-scanned head read, and the node ctrl already
         * carries the authoritative rst_id/asn/write position.
         */
        for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
            log_file_t *file = &file_set->items[i];
            file->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(lrcv->session->kernel->db.ctrl.pages, i,
                                                                 sizeof(log_file_ctrl_t),
                                                                 lrcv->session->kernel->db.ctrl.log_segment,
                                                                 src_node_id);
            if (LOG_IS_DROPPED(file->ctrl->flg)) {
                continue;
            }

            /* same not-used rule as dtc_log_file_not_used */
            bool32 not_used = OG_FALSE;
            if (node_ctrl->log_first <= node_ctrl->log_last) {
                not_used = (i < node_ctrl->log_first || i > node_ctrl->log_last);
            } else {
                not_used = (i < node_ctrl->log_first && i > node_ctrl->log_last);
            }
            /*
             * Open into the receiver's own handle array: the file structs of a
             * remote node are shared with the archiver / dtc recovery, so the
             * receiver must not touch their handles (avoid double close).
             */
            lrcv->stream_handle[i] = -1;
            if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(lrcv->session),
                               &lrcv->stream_handle[i]) != OG_SUCCESS) {
                OG_LOG_RUN_WAR("[Log Receiver] failed to open stream log file=%s for src node %u",
                               file->ctrl->name, src_node_id);
                continue;
            }

            /*
             * If the file head was not yet initialized (dtc recovery normally
             * loads the real heads during open), derive it from the replay
             * point so the prepare logic has a consistent current file.
             */
            if (not_used) {
                /*
                 * Keep the head loaded by dtc recovery (it may carry the real
                 * rst_id/asn/write_pos of a previously used file); the receiver
                 * only writes to the current file and re-initializes heads on
                 * log switch.
                 */
                continue;
            }
            if (i == node_ctrl->log_last &&
                (file->head.asn == 0 || file->head.asn != node_ctrl->lrp_point.asn)) {
                /*
                 * Prefer the REAL on-disk head: the BUILD snapshot writes the
                 * remote node's redo into this file group, so write_pos/asn
                 * must continue from the actual data end.  Resetting write_pos
                 * to the head size would make the receiver overwrite the
                 * build data from block 1 and desync the redo replay read
                 * point.  Fall back to the ctrl-derived values only when the
                 * device head cannot be read (e.g. ULOG-addressed DBStor).
                 */
                log_file_head_t disk_head;
                errno_t err = memset_sp(&disk_head, sizeof(disk_head), 0, sizeof(disk_head));
                knl_securec_check(err);
                int32 head_size = (int32)CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
                if (file->ctrl->type != DEV_TYPE_ULOG &&
                    cm_read_device(file->ctrl->type, lrcv->stream_handle[i], 0, &disk_head, head_size) == OG_SUCCESS &&
                    disk_head.asn != 0 && disk_head.block_size != 0) {
                    file->head = disk_head;
                } else {
                    file->head.rst_id = node_ctrl->lrp_point.rst_id;
                    file->head.asn = node_ctrl->lrp_point.asn;
                    file->head.block_size = file->ctrl->block_size;
                    if (file->ctrl->type == DEV_TYPE_ULOG) {
                        file->head.write_pos = 0;
                    } else {
                        file->head.write_pos =
                            CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
                    }
                }
            }
            OG_LOG_RUN_INF("[Log Receiver] stream %u logfile %s head [%u-%u] write_pos %llu",
                           src_node_id, file->ctrl->name, file->head.rst_id, file->head.asn,
                           (uint64)file->head.write_pos);
        }
        lrcv->stream_curr_file = node_ctrl->log_last;
        lrcv->stream_active_file = node_ctrl->log_first;
        lrcv->stream_logfile_hwm = file_set->logfile_hwm;
        lrcv->stream_free_size = 0;
        lrcv->stream_curr_point = node_ctrl->lrp_point;
    }
    lrcv->lsn_frontier = 0;
    lrcv->stream_flushed_lfn = 0;

    OG_LOG_RUN_INF("[Log Receiver] stream bound: src_dbid %u src_node_id %u, file set hwm %u, "
                   "active %u current %u, lrp [%u-%u/%u/%llu]",
                   lrcv->src_dbid, lrcv->src_node_id, lrcv->stream_logfile_hwm, lrcv->stream_active_file,
                   lrcv->stream_curr_file, node_ctrl->lrp_point.rst_id, node_ctrl->lrp_point.asn,
                   node_ctrl->lrp_point.block_id, (uint64)node_ctrl->lrp_point.lfn);
    return lrcv;
}

static status_t lrcv_process_query_status(lrcv_context_t **lrcv_ptr, rep_query_status_req_t *req)
{
    lrcv_context_t *lrcv = *lrcv_ptr;
    database_t *db = &lrcv->session->kernel->db;
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *msg_hdr = (rep_msg_header_t *)buf;
    rep_query_status_resp_t *resp = (rep_query_status_resp_t *)(buf + sizeof(rep_msg_header_t));
    status_t status;
    bool32 is_building_cascaded = OG_FALSE;

    lrcv = lrcv_bind_stream(lrcv, req);
    if (lrcv == NULL) {
        return OG_ERROR;
    }
    *lrcv_ptr = lrcv;

    lrcv->peer_repl_port = req->repl_port;
    lrcv->peer_role = req->is_standby ? PEER_STANDBY : PEER_PRIMARY;

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && lrcv->role_spec_building) {
        is_building_cascaded = OG_TRUE;
    }

    lrcv->dbid = req->dbid;
    lrcv->primary_curr_point = req->curr_point;
    lrcv->primary_resetlog = req->rst_log;
    lrcv->primary_reset_log_scn = req->reset_log_scn;

    if (db->status != DB_STATUS_OPEN || (is_building_cascaded && lrcv->peer_role == PEER_PRIMARY)) {
        resp->is_ready = OG_FALSE;
    } else {
        if (lrcv_resetlog_check(lrcv, req) == OG_SUCCESS) {
            if (lrcv_prepare_log_files(lrcv, req) == OG_SUCCESS) {
                resp->is_ready = OG_TRUE;
                resp->flush_point = lrcv->flush_point;
                resp->rcy_point = lrcv_get_node_ctrl(lrcv)->rcy_point;
                resp->replay_lsn = (uint64)lrcv_get_node_ctrl(lrcv)->lsn;
                lrcv->status = LRCV_PREPARE;
                lrcv->reconnected = OG_TRUE;

                lrcv_try_save_dbid(lrcv);
                lrcv_try_change_db_role(lrcv);
            } else {
                OG_LOG_RUN_ERR("[Log Receiver] Failed to prepare log files");
                resp->is_ready = OG_FALSE;
            }
        } else {
            OG_LOG_RUN_ERR("[Log Receiver] Failed to check reset log");
            return OG_ERROR;
        }
    }

    resp->is_building_cascaded = is_building_cascaded;
    resp->is_building = lrcv->is_building;
    msg_hdr->size = sizeof(rep_msg_header_t) + sizeof(rep_query_status_resp_t);
    msg_hdr->type = REP_QUERY_STATUS_RESP;
    status = cs_write_stream(lrcv->pipe, buf, msg_hdr->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send query status response to primary");
    }
    return status;
}

status_t lrcv_buf_alloc(knl_session_t *session, lrcv_context_t *lrcv)
{
    uint32 log_size = (uint32)LOG_LGWR_BUF_SIZE(session); /* LOG_LGWR_BUF_SIZE(session) <= 64M, cannot overflow */
    uint32 buf_size;

    if (lrcv->recv_buf.read_buf.alloc_buf != NULL) {
        return OG_SUCCESS;
    }

    buf_size = log_size + SIZE_K(4);
    if (cm_aligned_malloc((int64)buf_size, "lrcv recv buffer", &lrcv->recv_buf.read_buf) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to alloc recv buffer with size %u", buf_size);
        return OG_ERROR;
    }
    lrcv->recv_buf.illusion_count = 0;
    lrcv->recv_buf.read_pos = 0;
    lrcv->recv_buf.write_pos = 0;

    lrcv->d_ctx.zstd_dctx = ZSTD_createDCtx();
    lrcv->d_ctx.buf_size = (uint32)LZ4_compressBound((int32)log_size) + SIZE_K(4);
    lrcv->d_ctx.data_size = 0;
    if (cm_aligned_malloc((int64)lrcv->d_ctx.buf_size, "lrcv compressed buffer",
                          &lrcv->d_ctx.compressed_buf) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to alloc compressed buffer with size %u", lrcv->d_ctx.buf_size);
        cm_aligned_free(&lrcv->recv_buf.read_buf);
        return OG_ERROR;
    }

    buf_size = SIZE_K(64);
    if (cm_aligned_malloc((int64)buf_size, "lrcv send buffer", &lrcv->send_buf.read_buf) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to alloc send buffer with size %u", buf_size);
        cm_aligned_free(&lrcv->recv_buf.read_buf);
        cm_aligned_free(&lrcv->d_ctx.compressed_buf);
        return OG_ERROR;
    }
    lrcv->send_buf.illusion_count = 0;
    lrcv->send_buf.read_pos = 0;
    lrcv->send_buf.write_pos = 0;

    buf_size = SIZE_M(1);
    if (cm_aligned_malloc((int64)buf_size, "lrcv extend buffer", &lrcv->extend_buf.read_buf) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to alloc extend buffer with size %u", buf_size);
        cm_aligned_free(&lrcv->recv_buf.read_buf);
        cm_aligned_free(&lrcv->send_buf.read_buf);
        cm_aligned_free(&lrcv->d_ctx.compressed_buf);
        return OG_ERROR;
    }
    lrcv->extend_buf.illusion_count = 0;
    lrcv->extend_buf.read_pos = 0;
    lrcv->extend_buf.write_pos = 0;

    return OG_SUCCESS;
}

static status_t lrcv_process_switch_response(lrcv_context_t *lrcv, rep_switch_resp_t *resp)
{
    switch_ctrl_t *ctrl = &lrcv->session->kernel->switch_ctrl;

    cm_spin_lock(&lrcv->lock, NULL);
    if (lrcv->state != REP_STATE_WAITING_DEMOTE) {
        cm_spin_unlock(&lrcv->lock);
        OG_LOG_RUN_INF("[Log Receiver] ignore switchover response message from primary");
        return OG_SUCCESS;
    }

    if (resp->state != REP_STATE_PROMOTE_APPROVE) {
        lrcv->state = REP_STATE_REJECTED;
        cm_spin_unlock(&lrcv->lock);
        OG_LOG_RUN_INF("[Log Receiver] switchover request is rejected by primary");
        return OG_SUCCESS;
    }

    OG_LOG_RUN_INF("[Log Receiver] received switchover response message from primary");

    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->request = SWITCH_REQ_PROMOTE;
    cm_spin_unlock(&ctrl->lock);

    lrcv->state = REP_STATE_STANDBY_PROMOTING;
    cm_spin_unlock(&lrcv->lock);

    return OG_SUCCESS;
}

static status_t lrcv_process_abr_req(lrcv_context_t *lrcv, rep_abr_req_t *abr_req)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *msg_hdr = (rep_msg_header_t *)buf;
    rep_abr_resp_t *abr_resp = (rep_abr_resp_t *)(buf + sizeof(rep_msg_header_t));
    uint32 page_offset = sizeof(rep_msg_header_t) + sizeof(rep_abr_resp_t);
    page_id_t page_id;
    status_t status;
    errno_t err;

    page_id.file = abr_req->file;
    page_id.page = abr_req->page;

    msg_hdr->size = page_offset + abr_req->blk_size;
    msg_hdr->type = REP_ABR_RESP;

    abr_resp->lsnd_id = abr_req->lsnd_id;
    abr_resp->file = abr_req->file;
    abr_resp->page = abr_req->page;

    if (abr_req->blk_size != lrcv->session->kernel->attr.page_size) {
        OG_LOG_RUN_ERR("[Log Receiver] receives invalid ABR message, request page size is %u, default page size is %u",
                       abr_req->blk_size, lrcv->session->kernel->attr.page_size);
        return OG_ERROR;
    }

    if (abr_wait_paral_rcy_compelte(lrcv->session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (buf_read_page(lrcv->session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] ABR standby failed to read page [%u-%u]", page_id.file, page_id.page);
        return OG_ERROR;
    }
    err = memcpy_sp(buf + page_offset, (uint32)lrcv->send_buf.read_buf.buf_size - page_offset, lrcv->session->curr_page,
                    abr_req->blk_size);
    knl_securec_check(err);
    buf_leave_page(lrcv->session, OG_FALSE);

    status = cs_write_stream(lrcv->pipe, buf, msg_hdr->size,
                             (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size));
    OG_LOG_RUN_INF("[Log Receiver] send ABR response to primary for file %u page %u with lsnd id %u status %d",
                   abr_req->file, abr_req->page, abr_req->lsnd_id, status);
    return status;
}

static status_t lrcv_process_message(lrcv_context_t **lrcv_ptr)
{
    lrcv_context_t *lrcv = *lrcv_ptr;
    char *extend_buf = lrcv->extend_buf.read_buf.aligned_buf;

    switch (lrcv->header.type) {
        case REP_BATCH_REQ: {
            /* The remaining batches in the message queue should be discarded */
            if (SECUREC_UNLIKELY(lrcv->wait_info.waiting)) {
                break;
            }

            if (lrcv_process_batch(lrcv) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (SECUREC_UNLIKELY(lrcv->wait_info.waiting)) {
                if (lrcv_send_switch_wait(lrcv) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                break;
            }

            if (lrcv_send_batch_ack(lrcv) != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;
        }

        case REP_QUERY_STATUS_REQ: {
            rep_query_status_req_t *rep_query_status_req = (rep_query_status_req_t *)extend_buf;
            if (lrcv_process_query_status(lrcv_ptr, rep_query_status_req) != OG_SUCCESS) {
                return OG_ERROR;
            }
            lrcv = *lrcv_ptr;
            break;
        }

        case REP_HEART_BEAT_REQ: {
            /*
             * Drain certificate: since version ST_VERSION_2 the heart beat
             * request carries {curr_lsn, drained}.  A drained certificate
             * promises that all redo with lsn <= curr_lsn has been generated
             * and already delivered to this standby, so the per-stream LSN
             * frontier can be pushed forward.  Red line: only update the
             * frontier after this stream's redo has been flushed, which is
             * guaranteed here because heart beats are processed after all
             * preceding batches have been flushed synchronously.
             */
            if (lrcv->header.size > sizeof(rep_msg_header_t)) {
                rep_hb_req_t *hb_req = (rep_hb_req_t *)extend_buf;
                if (hb_req->drained) {
                    lrcv_update_frontier(lrcv, hb_req->curr_lsn);
                    OG_LOG_DEBUG_INF("[Log Receiver] stream %u drain certificate: curr_lsn %llu, frontier %llu",
                                     lrcv->src_node_id, (uint64)hb_req->curr_lsn, (uint64)lrcv->lsn_frontier);
                }
            }
            if (lrcv_process_heart_beat(lrcv) != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;
        }

        case REP_SWITCH_RESP: {
            rep_switch_resp_t *switch_resp = (rep_switch_resp_t *)extend_buf;

            if (lrcv_process_switch_response(lrcv, switch_resp) != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;
        }

        case REP_ABR_REQ: {
            rep_abr_req_t *abr_req = (rep_abr_req_t *)extend_buf;

            if (lrcv_process_abr_req(lrcv, abr_req) != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;
        }

        case REP_RECORD_BACKUPSET_RESP: {
            lrcv->task.failed = *(bool32 *)extend_buf;
            if (lrcv->task.failed) {
                lrcv->task.error_no = ERR_RECORD_BACKUP_FAILED;
            }
            lrcv->task.status = BAK_TASK_DONE;
            break;
        }

        default:
            OG_LOG_RUN_ERR("[Log Receiver] invalid replication message type %u", lrcv->header.type);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t lrcv_zstd_decompress(lrcv_context_t *lrcv, const char *buf, uint32 size, uint32 *data_size)
{
    if (lrcv->recv_buf.read_buf.buf_size != OG_MAX_BATCH_SIZE + SIZE_K(4)) {
        uint64 ori_batches_size = ZSTD_getFrameContentSize(buf, size);
        if (ori_batches_size == ZSTD_CONTENTSIZE_ERROR || ori_batches_size == ZSTD_CONTENTSIZE_UNKNOWN) {
            OG_LOG_RUN_ERR("[Log Receiver] failed to decompress(zstd) log batch message");
            return OG_ERROR;
        }
        if (ori_batches_size > lrcv->recv_buf.read_buf.buf_size) {
            if (cm_aligned_realloc((int64)(OG_MAX_BATCH_SIZE + SIZE_K(4)), "lrcv recv buffer",
                                   &lrcv->recv_buf.read_buf) != OG_SUCCESS) {
                CM_ABORT(0, "ABORT INFO: malloc lrcv compressed buffer fail.");
            }
        }
    }

    *data_size = (uint32)ZSTD_decompressDCtx(lrcv->d_ctx.zstd_dctx, lrcv->recv_buf.read_buf.aligned_buf,
                                             (size_t)lrcv->recv_buf.read_buf.buf_size, buf, size);
    if (ZSTD_isError(*data_size)) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to decompress(zstd) log batch message");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t lrcv_lz4_decompress(lrcv_context_t *lrcv, const char *buf, uint32 size, uint32 *data_size)
{
    int result = LZ4_decompress_safe(buf, lrcv->recv_buf.read_buf.aligned_buf, (int32)size,
                                     (int32)lrcv->recv_buf.read_buf.buf_size);
    if (result <= 0) {
        if (lrcv->recv_buf.read_buf.buf_size != OG_MAX_BATCH_SIZE + SIZE_K(4)) {
            if (cm_aligned_realloc((int64)(OG_MAX_BATCH_SIZE + SIZE_K(4)), "lrcv recv buffer",
                                   &lrcv->recv_buf.read_buf) != OG_SUCCESS) {
                CM_ABORT(0, "ABORT INFO: malloc lrcv compressed buffer fail.");
            }
            result = LZ4_decompress_safe(buf, lrcv->recv_buf.read_buf.aligned_buf, (int32)size,
                                         (int32)lrcv->recv_buf.read_buf.buf_size);
            if (result < 0) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to decompress(lz4) log batch message");
                return OG_ERROR;
            }
        } else {
            OG_LOG_RUN_ERR("[Log Receiver] failed to decompress(lz4) log batch message");
            return OG_ERROR;
        }
    }
    *data_size = (uint32)result;
    return OG_SUCCESS;
}

static status_t lrcv_compress_receive(lrcv_context_t *lrcv, rep_batch_req_t *req, uint32 remain_size, int32 *recv_size)
{
    uint32 batches_size = 0;
    if (cs_read_stream(lrcv->pipe, lrcv->d_ctx.compressed_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                       recv_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary with size %u", remain_size);
        return OG_ERROR;
    }
    if ((uint32)*recv_size != remain_size) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary with size %u, %u received",
                       remain_size, *recv_size);
        return OG_ERROR;
    }

    switch (req->compress_alg) {
        case COMPRESS_ZSTD:
            if (lrcv_zstd_decompress(lrcv, lrcv->d_ctx.compressed_buf.aligned_buf, (uint32)*recv_size,
                &batches_size) != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;
        case COMPRESS_LZ4:
            if (lrcv_lz4_decompress(lrcv, lrcv->d_ctx.compressed_buf.aligned_buf, (uint32)*recv_size,
                &batches_size) != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;
        default:
            break;
    }

    lrcv->header.size = sizeof(rep_msg_header_t) + sizeof(rep_batch_req_t) + batches_size;
    return OG_SUCCESS;
}

static status_t lrcv_receive(lrcv_context_t *lrcv, uint32 timeout, int32 *recv_size)
{
    rep_batch_req_t *rep_batch_req = NULL;
    uint32 remain_size;
    uint32 new_compress_buf_size = 0;
    uint32 new_buf_size;

    if (cs_read_stream(lrcv->pipe, (char *)&lrcv->header, timeout, sizeof(rep_msg_header_t), recv_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to receive message from primary");
        return OG_ERROR;
    }

    if (*recv_size == 0) {
        return OG_SUCCESS;
    }

    if (lrcv->header.size < (uint32)*recv_size) {
        OG_LOG_RUN_ERR("[Log Receiver] invalid head size %u received, which is smaller than %u", lrcv->header.size,
            (uint32)*recv_size);
        return OG_ERROR;
    }

    remain_size = lrcv->header.size - (uint32)*recv_size;

    if (lrcv->header.type == REP_BATCH_REQ) {
        // For batch message, batch should be 4K aligned in recv_buf
        if (cs_read_stream(lrcv->pipe, lrcv->extend_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT,
                           sizeof(rep_batch_req_t), recv_size) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[Log Receiver] failed to receive rep_batch_req_t message from primary with size %u",
                           (uint32)sizeof(rep_batch_req_t));
            return OG_ERROR;
        }
        if (*recv_size != sizeof(rep_batch_req_t)) {
            OG_LOG_RUN_ERR("[Log Receiver] failed to receive rep_batch_req_t message from "
                           "primary with size %u, %u received",
                           (uint32)sizeof(rep_batch_req_t), *recv_size);
            return OG_ERROR;
        }
        rep_batch_req = (rep_batch_req_t *)lrcv->extend_buf.read_buf.aligned_buf;
        if (remain_size <= (uint32)*recv_size) {
            OG_LOG_RUN_ERR("[Log Receiver] invalid head size %u received, which is smaller than %u", lrcv->header.size,
                lrcv->header.size - remain_size + (uint32)*recv_size);
                return OG_ERROR;
        }
        remain_size -= (uint32)*recv_size;

        if (rep_batch_req->compress_alg == COMPRESS_NONE) {
            if (lrcv->header.size > lrcv->recv_buf.read_buf.buf_size) {
                new_buf_size = OG_MAX_BATCH_SIZE + SIZE_K(8);
                if (cm_aligned_realloc((int64)new_buf_size, "lrcv recv buffer",
                                       &lrcv->recv_buf.read_buf) != OG_SUCCESS) {
                    CM_ABORT(0, "[Log Receiver] failed to alloc recv buffer with size %u", new_buf_size);
                }
            }
            if (remain_size > lrcv->recv_buf.read_buf.buf_size) {
                OG_LOG_RUN_ERR("[Log Receiver] the remain data size %u exceeds the receive buffer size %u",
                               remain_size, (uint32)lrcv->extend_buf.read_buf.buf_size);
                return OG_ERROR;
            }
            // Now we are truly receiving the log batch
            if (cs_read_stream(lrcv->pipe, lrcv->recv_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                               recv_size) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary with size %u",
                               remain_size);
                return OG_ERROR;
            }
            if ((uint32)*recv_size != remain_size) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to receive log batch message from primary "
                               "with size %u, %u received",
                               remain_size, *recv_size);
                return OG_ERROR;
            }
        } else {
            if (lrcv->header.size > lrcv->d_ctx.compressed_buf.buf_size) {
                if (rep_batch_req->compress_alg == COMPRESS_ZSTD) {
                    new_compress_buf_size = (uint32)ZSTD_compressBound(OG_MAX_BATCH_SIZE) + SIZE_K(4);
                } else if (rep_batch_req->compress_alg == COMPRESS_LZ4) {
                    new_compress_buf_size = (uint32)LZ4_compressBound((int32)OG_MAX_BATCH_SIZE) + SIZE_K(4);
                } else {
                    OG_LOG_RUN_ERR("[Log Receiver] unsupported compress algorithm.");
                    return OG_ERROR;
                }
                if (cm_aligned_realloc((int64)new_compress_buf_size, "lrcv compressed buffer",
                                       &lrcv->d_ctx.compressed_buf) != OG_SUCCESS) {
                    CM_ABORT(0, "ABORT INFO: malloc lrcv compress buffer fail.");
                }
                lrcv->d_ctx.compressed_buf.buf_size = new_compress_buf_size;
            }
            if (lrcv_compress_receive(lrcv, rep_batch_req, remain_size, recv_size) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    } else {
        if (remain_size > 0) {
            if (remain_size > lrcv->extend_buf.read_buf.buf_size) {
                OG_LOG_RUN_ERR("[Log Receiver] the remain data size %u exceeds the receive buffer size %u",
                               remain_size, (uint32)lrcv->extend_buf.read_buf.buf_size);
                return OG_ERROR;
            }
            if (cs_read_stream(lrcv->pipe, lrcv->extend_buf.read_buf.aligned_buf, REPL_RECV_TIMEOUT, remain_size,
                               recv_size) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to receive message %u from primary with size %u",
                               lrcv->header.type, remain_size);
                return OG_ERROR;
            }
            if ((uint32)*recv_size != remain_size) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to receive message %u from primary with size %u, %u received",
                               lrcv->header.type, remain_size, *recv_size);
                return OG_ERROR;
            }
        }
    }

    (*recv_size) = lrcv->header.size;

    if (!lrcv_rcv_msg_is_valid(lrcv)) {
        OG_LOG_RUN_ERR("[Log Receiver] invalid message %u received", lrcv->header.type);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t lrcv_send_switch_request(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;

    rep_msg_header->size = sizeof(rep_msg_header_t);
    rep_msg_header->type = REP_SWITCH_REQ;

    if (cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send switchover request message to primary");
        return OG_ERROR;
    }

    lrcv->state = REP_STATE_WAITING_DEMOTE;

    OG_LOG_RUN_INF("[Log Receiver] send switchover request to primary");

    return OG_SUCCESS;
}

static status_t lrcv_send_record_backupset(lrcv_context_t *lrcv)
{
    bak_context_t *bak_ctx = &lrcv->session->kernel->backup_ctx;
    bak_record_t *record = &bak_ctx->bak.record;
    rep_msg_header_t rep_msg_header;

    rep_msg_header.size = sizeof(rep_msg_header_t) + sizeof(bak_record_t);
    rep_msg_header.type = REP_RECORD_BACKUPSET_REQ;

    if (cs_write_stream(lrcv->pipe, (char *)&rep_msg_header, sizeof(rep_msg_header_t),
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send record backupset request message to primary");
        return OG_ERROR;
    }

    if (cs_write_stream(lrcv->pipe, (char *)record, sizeof(bak_record_t),
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send backupset record data to standby");
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[Log Receiver] send record backupset request to primary");

    return OG_SUCCESS;
}

static void lrcv_process_backup_req(lrcv_context_t *lrcv)
{
    rep_bak_task_t *task = &lrcv->task;

    if (task->status != BAK_TASK_WAIT_PROCESS) {
        return;
    }

    if (lrcv_send_record_backupset(lrcv) != OG_SUCCESS) {
        task->status = BAK_TASK_DONE;
        task->failed = OG_TRUE;
        task->error_no = ERR_SEND_RECORD_REQ_FAILED;
    } else {
        task->status = BAK_TASK_WAIT_RESPONSE;
    }
}

static status_t lrcv_process_req(lrcv_context_t *lrcv)
{
    if (lrcv->state == REP_STATE_DEMOTE_REQUEST) {
        return lrcv_send_switch_request(lrcv);
    }

    lrcv_process_backup_req(lrcv);

    if (lrcv_process_switch_wait(lrcv) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t lrcv_process_msg_loop(lrcv_context_t **lrcv_ptr)
{
    int32 recv_size;

    do {
        if (lrcv_process_message(lrcv_ptr) != OG_SUCCESS) {
            return OG_ERROR;
        }
    
        if (lrcv_process_req(*lrcv_ptr) != OG_SUCCESS) {
            return OG_ERROR;
        }
    
        if (lrcv_receive(*lrcv_ptr, 0, &recv_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } while (recv_size > 0);

    return OG_SUCCESS;
}

static inline void lrcv_try_set_repl_port(lrcv_context_t *lrcv, int32 recv_size)
{
    if (recv_size == 0) {
        return;
    }

    if (lrcv->header.type == REP_QUERY_STATUS_REQ) {
        rep_query_status_req_t *req = (rep_query_status_req_t *)lrcv->extend_buf.read_buf.aligned_buf;
        lrcv->peer_repl_port = req->repl_port;
    }
}

status_t lrcv_proc(lrcv_context_t *lrcv)
{
    thread_t *thread = &lrcv->thread;
    int32 recv_size;
    uint32 recv_retry_cnt = 0;

    cm_set_thread_name("log_receiver");
    OG_LOG_RUN_INF("log receiver thread started");

    while (!thread->closed) {
        if (lrcv_need_exit(lrcv)) {
            lrcv_set_conn_err(lrcv);
            return OG_ERROR;
        }

        if (lrcv_process_req(lrcv) != OG_SUCCESS) {
            lrcv_set_conn_err(lrcv);
            return OG_ERROR;
        }

        if (lrcv_receive(lrcv, LRCV_RECV_INTERVAL, &recv_size) != OG_SUCCESS) {
            lrcv_set_conn_err(lrcv);
            return OG_ERROR;
        }

        if (lrcv_need_suspend(lrcv)) {
            lrcv_try_set_repl_port(lrcv, recv_size);
            cm_sleep(SUSPEND_INTERVAL);
            continue;
        }

        if (recv_size > 0) {
            recv_retry_cnt = 0;
            if (lrcv_process_msg_loop(&lrcv) != OG_SUCCESS) {
                lrcv_set_conn_err(lrcv);
                return OG_ERROR;
            }
        } else {
            if ((lrcv->status == LRCV_PREPARE || lrcv->status == LRCV_READY) &&
                (recv_retry_cnt++ > lrcv->timeout * MILLISECS_PER_SECOND / LRCV_RECV_INTERVAL)) {
                OG_LOG_RUN_INF("[Log Receiver] lrcv has not received message more than %us, primary is down probably",
                               lrcv->timeout);
                lrcv_set_conn_err(lrcv);
                return OG_ERROR;
            }
        }
    }

    lrcv_set_conn_err(lrcv);
    OG_LOG_RUN_INF("log receiver thread closed");
    return OG_SUCCESS;
}

void lrcv_close(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    lrcv_mgr_t *mgr = &kernel->lrcv_mgr;

    lrcv_reset_primary_host(session);
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        if (lrcv->thread.closed) {
            continue;
        }
        lrcv->thread.closed = OG_TRUE;
        while (LRCV_IS_RUNING(lrcv) && lrcv->thread.closed) {
            cm_sleep(10);
        }
    }
}

static status_t lrcv_get_primary_host(knl_session_t *session, int32 retry_count_input, char *host, uint32 host_buf_size)
{
    int32 retry_count = retry_count_input;
    lrcv_context_t *lrcv = NULL;
    errno_t ret;

    while (session->kernel->lrcv_mgr.streams[0].pipe == NULL) {
        if (retry_count == 0) {
            OG_LOG_RUN_ERR("[Log Receiver] abort wait connection ready during to exceeded max retries");
            OG_THROW_ERROR(ERR_PRI_NOT_CONNECT, "primary info");
            return OG_ERROR;
        }

        if (knl_failover_triggered(session->kernel)) {
            OG_LOG_RUN_ERR("[Log Receiver] abort wait connection ready during to force promote");
            return OG_ERROR;
        }

        if (session->kernel->lrpl_ctx.thread.closed) {
            OG_LOG_RUN_ERR("[Log Receiver] abort wait connection ready during to lrpl closed");
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }
        cm_sleep(5);

        if (retry_count > 0) {
            retry_count--;
        }
    }

    lrcv = &session->kernel->lrcv_mgr.streams[0];
    ret = strncpy_s(host, host_buf_size, lrcv->primary_host, OG_HOST_NAME_BUFFER_SIZE - 1);

    knl_securec_check(ret);
    return OG_SUCCESS;
}

status_t lrcv_get_primary_server(knl_session_t *session, int32 retry_count,
    char *host, uint32 host_buf_size, uint16 *port)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_mgr.streams[0];

    if (lrcv_get_primary_host(session, retry_count, host, host_buf_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (port == NULL) {
        return OG_SUCCESS;
    }

    *port = lrcv->peer_repl_port;
    if (*port == 0) {
        OG_THROW_ERROR(ERR_INVALID_REPL_PORT);
        OG_LOG_RUN_ERR("[Log Receiver] peer repl port is 0, it may be that the REPL_PORT parameter "
                       "of the peer node is not set, or it has been disconnected from the peer node");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

bool32 lrcv_switchover_enabled(knl_session_t *session)
{
    char pri_host[OG_HOST_NAME_BUFFER_SIZE];
    uint16 pri_port;
    knl_attr_t *attr = &session->kernel->attr;
    arch_attr_t *arch_attr = NULL;

    if (lrcv_get_primary_server(session, 0, pri_host, OG_HOST_NAME_BUFFER_SIZE, &pri_port) != OG_SUCCESS) {
        return OG_FALSE;
    }

    for (uint32 i = 1; i < OG_MAX_ARCH_DEST; i++) {
        arch_attr = &attr->arch_attr[i];

        if (strcmp(pri_host, arch_attr->service.host) == 0 && pri_port == arch_attr->service.port &&
            arch_attr->enable && arch_attr->role_valid != VALID_FOR_STANDBY_ROLE) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

void lrcv_trigger_backup_task(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_mgr.streams[0];
    rep_bak_task_t *task = &lrcv->task;

    CM_ASSERT(task->status == BAK_TASK_DONE);

    if (LRCV_IS_RUNING(lrcv)) {
        task->failed = OG_FALSE;
        task->status = BAK_TASK_WAIT_PROCESS;
    } else {
        task->failed = OG_TRUE;
        task->error_no = ERR_SEND_RECORD_REQ_FAILED;
    }
}

status_t lrcv_wait_task_process(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_mgr.streams[0];
    rep_bak_task_t *task = &lrcv->task;

    while (task->status != BAK_TASK_DONE) {
        if (session->canceled) {
            OG_THROW_ERROR(ERR_OPERATION_CANCELED);
            return OG_ERROR;
        }

        if (session->killed) {
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }

        cm_sleep(100);
    }

    if (task->failed) {
        OG_THROW_ERROR(task->error_no);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void lrcv_wait_status_prepared(knl_session_t *session)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_mgr.streams[0];

    while (lrcv->status < LRCV_PREPARE) {
        if (lrcv->session == NULL || lrcv->session->killed) {
            return;
        }

        cm_sleep(100);
    }
}

void lrcv_clear_needrepair_for_failover(knl_session_t *session)
{
    session->kernel->lrcv_mgr.streams[0].status = LRCV_DISCONNECTED;
    session->kernel->lftc_client_ctx.arch_lost = OG_FALSE;
    session->kernel->rcy_ctx.log_decrypt_failed = OG_FALSE;
}
