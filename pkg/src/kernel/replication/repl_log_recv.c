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
#include "dtc_recovery.h"
#include "dtc_switchover.h"

#define SUSPEND_INTERVAL 1000
#define EMPTY_LOG_POINT(pt) (((pt).rst_id == 0) && ((pt).asn == 0) && ((pt).offset == 0) && ((pt).lfn == 0))
#define LRCV_IS_RUNING(lrcv) ((lrcv)->session != NULL)
#define LRCV_INVALID_DBID(peer_dbid, local_dbid) ((peer_dbid) != 0 && (peer_dbid) != (local_dbid))

static inline void lrcv_disconnect(lrcv_context_t *lrcv)
{
    /*
     * The connection may already have been torn down by another thread's
     * error path (lrcv_set_conn_err / srv_clear_lrcv_ctx) when the receiver
     * thread itself notices the failure, so a NULL pipe is a normal state
     * here, not a bug.  cs_disconnect asserts a non-NULL pipe, therefore
     * guard it and clear the pointer so a later disconnect is a no-op.
     */
    if (lrcv->pipe != NULL) {
        cs_disconnect(lrcv->pipe);
        lrcv->pipe = NULL;
    }
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
 * recovery/archiving machinery.  The stream whose source id equals the local
 * node id mirrors `redo_ctx`; its connection-pool slot is not fixed.
 */
static inline bool32 lrcv_stream_active(const lrcv_context_t *lrcv)
{
    return (lrcv->stream_bound && !lrcv->taken_over);
}

static inline bool32 lrcv_is_remote_stream(lrcv_context_t *lrcv)
{
    return (lrcv_stream_active(lrcv) && lrcv->src_node_id != lrcv->session->kernel->id);
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
    if (!lrcv_stream_active(lrcv)) {
        return;
    }

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
    /*
     * Persist the rotated-out file's status transition.  The saves below
     * only write the NEW current file's ctrl (and the core ctrl), so without
     * this the disk copy keeps the rotated-out file as LOG_FILE_CURRENT.
     * The standby's LRPL cycle reloads the per-file ctrl statuses from disk
     * at every cycle start (dtc_rcy_init_rcynode -> dtc_read_node_ctrl); the
     * stale CURRENT then comes back to life with the old asn still equal to
     * the read point, dtc_rcy_next_file parks on it forever, and the standby
     * replay freezes while the receiver keeps appending the real current file
     * (observed under two-node TPCC load: node read stuck at the old file
     * tail, recv watermark frozen, the other node's batches permanently gated
     * by the cross-node drain frontier).
     */
    if (db_save_log_ctrl(session, lrcv->stream_curr_file, lrcv->src_node_id) != OG_SUCCESS) {
        CM_ABORT(0, "[Log Receiver] ABORT INFO: save control space file failed when switch stream log file");
    }
    /*
     * Record the last batch lfn written into the file being rotated out;
     * the recycle logic on a standby compares this against the applied point
     * by lfn (the per-node files and the saved rcy point use different asn
     * numbering after a (re)send, so an asn-based comparison is not valid).
     */
    lrcv->stream_file_last_lfn[lrcv->stream_curr_file] = lrcv->flush_point.lfn;
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
static void lrcv_recycle_file(lrcv_context_t *lrcv, log_point_t *point);
static void lrcv_fill_peer_flush_point(const lrcv_context_t *lrcv, log_point_t *point);
static void lrcv_update_primary_report_point(lrcv_context_t *lrcv, const log_point_t *primary_start,
    void *batch_buf, uint32 size, uint32 block_size);
static status_t lrcv_primary_point_from_lfn(lrcv_context_t *lrcv, uint64 target_lfn, log_point_t *out);

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
            /*
             * No free file: recycle the stream's consumed files by the
             * applied point.  A remote stream on a physical standby is not
             * archived, so without this the group fills up and the switch
             * (and with it the whole receiver message loop, including
             * heartbeat processing) blocks forever; the LRPL then waits on
             * the drain frontier and the applied point can never advance.
             */
            lrcv_recycle_file(lrcv, &lrcv_get_node_ctrl(lrcv)->rcy_point);
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

static lrcv_context_t *lrcv_get_stream_locked(lrcv_mgr_t *mgr, uint32 src_node_id)
{
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        if (lrcv->stream_bound && lrcv->src_node_id == src_node_id) {
            return lrcv;
        }
    }
    return NULL;
}

lrcv_context_t *lrcv_get_stream(knl_session_t *session, uint32 src_node_id)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    lrcv_context_t *result;

    cm_spin_lock(&mgr->lock, NULL);
    result = lrcv_get_stream_locked(mgr, src_node_id);
    cm_spin_unlock(&mgr->lock);
    return result;
}

lrcv_context_t *lrcv_get_local_stream(knl_session_t *session)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    lrcv_context_t *result = NULL;
    bool32 has_bound_stream = OG_FALSE;

    cm_spin_lock(&mgr->lock, NULL);
    result = lrcv_get_stream_locked(mgr, session->kernel->id);
    if (result != NULL) {
        cm_spin_unlock(&mgr->lock);
        return result;
    }

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        if (mgr->streams[i].stream_bound) {
            has_bound_stream = OG_TRUE;
            break;
        }
    }

    /* Before the first source is bound, preserve the legacy default context. */
    if (!has_bound_stream) {
        result = &mgr->streams[0];
    }
    cm_spin_unlock(&mgr->lock);
    return result;
}

bool32 lrcv_has_active_session(knl_session_t *session)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    bool32 result = OG_FALSE;

    cm_spin_lock(&mgr->lock, NULL);
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        if (mgr->streams[i].session != NULL) {
            result = OG_TRUE;
            break;
        }
    }
    cm_spin_unlock(&mgr->lock);
    return result;
}

bool32 lrcv_has_status(knl_session_t *session, lrcv_status_t status)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    bool32 result = OG_FALSE;
    bool32 has_bound_stream = OG_FALSE;
    bool32 legacy_match = OG_FALSE;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->stream_bound) {
            has_bound_stream = OG_TRUE;
            if (lrcv->status == status) {
                result = OG_TRUE;
            }
        } else if (i == 0 && lrcv->session != NULL && lrcv->status == status) {
            /* Keep pre-bind errors visible through the legacy context. */
            legacy_match = OG_TRUE;
        }
        cm_spin_unlock(&lrcv->lock);
    }
    return (bool32)(result || (!has_bound_stream && legacy_match));
}

bool32 lrcv_has_state(knl_session_t *session, rep_state_t state)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    bool32 result = OG_FALSE;
    bool32 has_bound_stream = OG_FALSE;
    bool32 legacy_match = OG_FALSE;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->stream_bound) {
            has_bound_stream = OG_TRUE;
            if (lrcv->state == state) {
                result = OG_TRUE;
            }
        } else if (i == 0 && lrcv->session != NULL && lrcv->state == state) {
            legacy_match = OG_TRUE;
        }
        cm_spin_unlock(&lrcv->lock);
    }
    return (bool32)(result || (!has_bound_stream && legacy_match));
}

bool32 lrcv_has_unready_stream(knl_session_t *session)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    bool32 result = OG_FALSE;
    bool32 has_bound_stream = OG_FALSE;
    bool32 legacy_unready = OG_FALSE;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->stream_bound) {
            has_bound_stream = OG_TRUE;
            if (lrcv->session != NULL && lrcv->status < LRCV_PREPARE) {
                result = OG_TRUE;
            }
        } else if (i == 0 && lrcv->session != NULL && lrcv->status < LRCV_PREPARE) {
            legacy_unready = OG_TRUE;
        }
        cm_spin_unlock(&lrcv->lock);
    }
    return (bool32)(result || (!has_bound_stream && legacy_unready));
}

void lrcv_set_reconnected(knl_session_t *session, bool32 reconnected)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    bool32 has_bound_stream = OG_FALSE;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->stream_bound) {
            has_bound_stream = OG_TRUE;
            lrcv->reconnected = reconnected;
        }
        cm_spin_unlock(&lrcv->lock);
    }
    if (!has_bound_stream) {
        cm_spin_lock(&mgr->streams[0].lock, NULL);
        mgr->streams[0].reconnected = reconnected;
        cm_spin_unlock(&mgr->streams[0].lock);
    }
}

void lrcv_set_timeout(knl_session_t *session, uint32 timeout)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        cm_spin_lock(&mgr->streams[i].lock, NULL);
        mgr->streams[i].timeout = timeout;
        cm_spin_unlock(&mgr->streams[i].lock);
    }
}

/*
 * Recycle stream log files whose head is before the given point.
 *
 * Local stream: the file group is the node's own redo files and is recycled
 * by the kernel (log_recycle_file), including the DBStor/RAW path.
 *
 * Remote stream: the group is LOGFILE_SET(session, src_node_id), which on a
 * physical standby is never touched by the archiver (the standby archiver
 * only handles the local node).  If the archive requirement were kept here,
 * the group would fill up and the receiver's log switch would block forever:
 * the switch waits for a free file, the LRPL waits for the drain frontier
 * (which needs this receiver to keep processing messages), recycling needs
 * the applied point to advance (which needs the LRPL) -- a cycle with no
 * exit.  Received redo on a standby is consumed by replay, so the archive
 * gate is dropped there; on a primary node the gate is kept so a file is
 * only reused after the archiver has covered it.
 */
static void lrcv_recycle_file(lrcv_context_t *lrcv, log_point_t *point)
{
    if (DB_CLUSTER_NO_CMS) {
        return;
    }

    /*
     * On a cluster standby every bound stream is a received stream,
     * including the one whose src_node_id equals the local node id.  The
     * legacy local path (log_recycle_file) is meant for a node's own online
     * redo and refuses to recycle a file until it has been archived, but a
     * non-DBStor standby never starts an archiver for the received files
     * (arch_start skips non-primary nodes and arch_init_proc_standby only
     * runs in DBStor mode), so a fully replayed file could never become
     * INACTIVE and lrcv_wait_logfile_no_active would spin forever on
     * ckpt_trigger.  Route such streams through the same per-node recycle
     * logic as the remote streams, which consumes by replay point and skips
     * the archive requirement on a standby (physical or cascaded).
     */
    bool32 received_stream = lrcv_is_remote_stream(lrcv) ||
        (DB_IS_CLUSTER(lrcv->session) && !DB_IS_PRIMARY(&lrcv->session->kernel->db));
    if (!received_stream) {
        log_recycle_file(lrcv->session, point);
        return;
    }

    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    database_t *db = &lrcv->session->kernel->db;
    bool32 need_arch = !DB_IS_PHYSICAL_STANDBY(db);
    arch_log_id_t last_arch_log;
    if (need_arch) {
        arch_last_archived_log(lrcv->session, ARCH_DEFAULT_DEST, &last_arch_log);
    }

    log_file_t *file = &file_set->items[lrcv->stream_active_file];
    if (lrcv->wait_info.waiting) {
        return;
    }

    lrcv_lock_logfile(lrcv);
    uint32 file_id = lrcv->stream_active_file;
    while (lrcv->stream_file_last_lfn[file_id] <= point->lfn) {
        file = &file_set->items[file_id];
        if ((file_id == lrcv->stream_curr_file) ||
            (need_arch && (file->head.asn > last_arch_log.asn ||
                           (file->ctrl->status == LOG_FILE_ACTIVE && !file->ctrl->archived)))) {
            break;
        }
        /*
         * An ACTIVE file whose last lfn is unknown (carried over a
         * reconnect/restart whose bind-time scan failed, or a ULOG file that
         * has no physical ring) may still hold an un-applied tail.  The
         * lfn-based comparison above would treat the zero seed as "already
         * consumed" and recycle it, losing redo.  Keep it active and let the
         * caller retry once the applied point has provably passed it.
         */
        if (file->ctrl->status == LOG_FILE_ACTIVE && lrcv->stream_file_last_lfn[file_id] == 0) {
            OG_LOG_RUN_WAR("[Log Receiver] refuse to recycle active file %u of stream %u: last lfn unknown, "
                           "rcy [%u-%u/%u/%llu]",
                           file_id, lrcv->src_node_id, point->rst_id, point->asn, point->block_id,
                           (uint64)point->lfn);
            break;
        }

        file->ctrl->status = LOG_FILE_INACTIVE;
        file->ctrl->archived = OG_FALSE;
        cm_latch_x(&file->latch, lrcv->session->id, NULL);
        file->head.asn = OG_INVALID_ASN;
        file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
        /*
         * Keep the block size consistent on every head (re)initialization:
         * freshly created per-node files on a standby may carry a zeroed
         * head, and readers that consume the head (log-switch wait, redo
         * alignment scan) rely on a valid block size.
         */
        file->head.block_size = file->ctrl->block_size;
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

        case REP_CLUSTER_SWITCH_RESP: {
            rep_cluster_switch_resp_t *resp = (rep_cluster_switch_resp_t *)extend_buf;
            if (resp->state < REP_STATE_NORMAL || resp->state > REP_STATE_REJECTED) {
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
    /* Read by the LRPL idle-skip logic from another thread, so write it atomically. */
    cm_atomic_set((atomic_t *)&lrcv->stream_flushed_lfn, (int64)log_point->lfn);
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
    lrcv_fill_peer_flush_point(lrcv, &rep_hb_resp->flush_point);
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
    if (!lrcv_stream_active(lrcv)) {
        lrcv->wait_info.waiting = OG_FALSE;
        return;
    }

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

    if (!lrcv_stream_active(lrcv)) {
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

    if (!rcy_wait_replay_complete(session)) {
        OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
            "[Log Receiver] defer log switch wait while parallel recovery context is closing");
        return OG_SUCCESS;
    }

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

static void lrcv_needrepair(lrcv_context_t *lrcv);

static inline void lrcv_fill_peer_flush_point(const lrcv_context_t *lrcv, log_point_t *point)
{
    if (lrcv->primary_report_point.lfn != 0) {
        *point = lrcv->primary_report_point;
        return;
    }
    *point = lrcv->flush_point;
}

/*
 * Advance primary_report_point from the batch(es) just written.  primary_start
 * is the sender-side point from rep_batch_req (valid before lrcv_flush_log
 * rewrites block_id to the local file end).
 */
static void lrcv_update_primary_report_point(lrcv_context_t *lrcv, const log_point_t *primary_start,
    void *batch_buf, uint32 size, uint32 block_size)
{
    log_batch_t *batch = (log_batch_t *)batch_buf;
    uint32 left = size;
    log_point_t report = *primary_start;

    if (block_size == 0) {
        return;
    }

    while (left >= sizeof(log_batch_t)) {
        if (left < batch->space_size) {
            break;
        }
        report.rst_id = batch->head.point.rst_id;
        report.asn = batch->head.point.asn;
        report.lfn = batch->head.point.lfn;
        report.block_id += batch->space_size / block_size;
        left -= batch->space_size;
        batch = (log_batch_t *)((char *)batch + batch->space_size);
    }

    if (report.lfn != 0) {
        lrcv->primary_report_point = report;
    }
}

static status_t lrcv_scan_file_primary_point(knl_session_t *session, const char *file_name, uint64 target_lfn,
    aligned_buf_t *buf, log_point_t *out, bool32 *found)
{
    log_file_head_t head;
    int32 handle = OG_INVALID_HANDLE;
    bool32 finished = OG_FALSE;
    uint64 size;
    uint64 remain_size;
    char *read_buf = buf->aligned_buf;
    uint64 buf_size = buf->buf_size;
    uint64 offset;
    device_type_t type = cm_device_type(file_name);

    *found = OG_FALSE;

    if (log_get_file_head(file_name, &head) != OG_SUCCESS) {
        return OG_ERROR;
    }

    bool32 compressed = (head.cmp_algorithm == COMPRESS_ZSTD);
    if (cm_open_device(file_name, type, knl_arch_io_flag(session, compressed), &handle) != OG_SUCCESS) {
        return OG_ERROR;
    }

    int64 file_size = -1;
    if (cm_get_size_device(type, handle, &file_size) != OG_SUCCESS || file_size == -1) {
        cm_close_device(type, &handle);
        return OG_ERROR;
    }

    offset = CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)head.block_size);
    while (1) {
        size = (uint64)file_size - offset;
        size = size > buf_size ? buf_size : size;
        if (finished || size == 0) {
            break;
        }

        if (cm_read_device(type, handle, offset, read_buf, size) != OG_SUCCESS) {
            cm_close_device(type, &handle);
            return OG_ERROR;
        }

        log_batch_t *batch = (log_batch_t *)read_buf;
        if (log_need_realloc_buf(batch, buf, "lrcv primary point scan", OG_MAX_BATCH_SIZE + SIZE_K(4))) {
            read_buf = buf->aligned_buf;
            buf_size = buf->buf_size;
            continue;
        }
        log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

        remain_size = size;
        uint64 batch_offset = offset;
        while (remain_size >= sizeof(log_batch_t)) {
            if (remain_size < batch->space_size || !rcy_validate_batch(batch, tail) ||
                batch->head.point.rst_id != head.rst_id) {
                finished = OG_TRUE;
                break;
            }

            if (batch->head.point.lfn == target_lfn) {
                out->rst_id = batch->head.point.rst_id;
                out->asn = batch->head.point.asn;
                out->lfn = batch->head.point.lfn;
                out->block_id = (uint32)((batch_offset + batch->space_size) / head.block_size);
                *found = OG_TRUE;
                cm_close_device(type, &handle);
                return OG_SUCCESS;
            }

            batch_offset += batch->space_size;
            remain_size -= batch->space_size;
            batch = (log_batch_t *)((char *)batch + batch->space_size);
            tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
        }
        offset = batch_offset;
    }

    cm_close_device(type, &handle);
    return OG_SUCCESS;
}

static status_t lrcv_primary_point_from_lfn(lrcv_context_t *lrcv, uint64 target_lfn, log_point_t *out)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    bool32 found = OG_FALSE;

    for (uint32 i = 0; i < lrcv_get_logfile_hwm(lrcv); i++) {
        log_file_t *file = &file_set->items[i];
        if (LOG_IS_DROPPED(file->ctrl->flg) || file->ctrl->name[0] == '\0') {
            continue;
        }

        if (lrcv_scan_file_primary_point(lrcv->session, file->ctrl->name, target_lfn,
                                         &lrcv->recv_buf.read_buf, out, &found) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (found) {
            return OG_SUCCESS;
        }
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
            /*
             * Before the reset below discards any file, make sure replay has
             * consumed it.  The current file (and every ACTIVE file before
             * it) may still hold un-applied redo; the "primary re-sends from
             * the applied point" assumption only holds while the primary
             * still retains that range (online or archive-readable).  Under
             * heavy load the primary can recycle the online file right after
             * a send-timeout disconnect, and the re-send then skips the
             * missing range -- the standby's ring ends up with a hole and
             * replay either panics (PCN mismatch, knl_recovery.c) or must be
             * rebuilt.  Defer through the switch-wait path instead: the
             * files stay intact, replay drains them, and only then is the
             * file reset and the primary told to re-send (same contract as
             * lrcv_switch_logfile's no-free-file wait).  A file whose last
             * lfn is unknown (never rotated out or not scanned at bind) is
             * treated as still needed, i.e. conservative.
             */
            uint32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            bool32 can_release = OG_TRUE;
            uint32 check_id = lrcv_get_active_file(lrcv);
            uint32 guard_pass = 0;
            for (;;) {
                log_file_t *check_file = &file_set->items[check_id];
                if ((check_file->ctrl->status == LOG_FILE_ACTIVE ||
                     check_file->ctrl->status == LOG_FILE_CURRENT) &&
                    check_file->head.write_pos > head_size) {
                    uint64 file_last_lfn = lrcv->stream_file_last_lfn[check_id];
                    if (file_last_lfn == 0 || node_ctrl->rcy_point.lfn < file_last_lfn) {
                        can_release = OG_FALSE;
                        break;
                    }
                }
                if (check_id == lrcv_get_curr_file(lrcv)) {
                    break;
                }
                lrcv_get_next_file(lrcv, &check_id, OG_FALSE);
                if (++guard_pass > lrcv_get_logfile_hwm(lrcv)) {
                    can_release = OG_FALSE;
                    break;
                }
            }
            if (!can_release) {
                OG_LOG_RUN_INF("[Log Receiver] stream %u defers file reset: current/active files still hold redo "
                               "replay needs (rcy [%u-%u/%u/%llu]); switch-wait resets after replay consumes them",
                               lrcv->src_node_id, node_ctrl->rcy_point.rst_id, node_ctrl->rcy_point.asn,
                               node_ctrl->rcy_point.block_id, (uint64)node_ctrl->rcy_point.lfn);
                lrcv_set_switch_wait(lrcv, req);
                return OG_SUCCESS;
            }

            uint64 start_pos;
            uint32 file_id = lrcv_get_active_file(lrcv);
            char arch_name[OG_FILE_NAME_BUFFER_SIZE];

            /*
             * The batch is ahead of the current file: normally the primary
             * switched files while disconnected and the receiver must fetch
             * the archive of the current file to bridge the gap.  When the
             * current file is EMPTY (only the head, e.g. right after a fresh
             * build / standby restart), there is nothing to preserve: the
             * missing redo is re-sent by the primary from the applied point.
             * The same applies when the archive path is a DBStor logical path
             * ("+vg..."): the log fetcher creates its temp file with raw file
             * APIs, which cannot address DBStor objects, so the fetch could
             * never succeed and would stall the receiver's message loop
             * forever.  The bind-time flush-point reset makes the primary
             * re-send every batch after the applied point, so the invalidate
             * below loses nothing; log and skip the fetch instead of waiting
             * on an archive that cannot be created locally.
             */
            bool32 need_fetch = OG_FALSE;
            if (LRCV_LOG_POINT_ON_POST_FILE(req->log_point, file->head) &&
                file->head.write_pos > CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) {
                arch_set_archive_log_name(lrcv->session, file->head.rst_id, file->head.asn, ARCH_DEFAULT_DEST,
                                          arch_name, OG_FILE_NAME_BUFFER_SIZE, node_id);
                need_fetch = (arch_name[0] != '+');
                if (!need_fetch) {
                    OG_LOG_RUN_WAR("[Log Receiver] skip fetching DBStor archive %s for stream %u; "
                                   "the primary re-sends from the applied point",
                                   arch_name, lrcv->src_node_id);
                }
            }
            if (need_fetch) {
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
            file->head.block_size = file->ctrl->block_size;
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
            file->head.block_size = file->ctrl->block_size;
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

    /*
     * The stream must stay lfn-continuous with what has already been flushed.
     * A forward jump means the primary could not supply the range in between
     * and resumed at a later point instead: under replay lag the online file
     * holding that range can be recycled without being archived, and after a
     * send-timeout disconnect the re-send then starts past it.  Flushing this
     * batch would punch a permanent hole into the local files and advance the
     * persisted flush/rcy point beyond it; replay cannot reconstruct those
     * pages afterwards, so startup recovery detects the gap and aborts the
     * instance on every restart -- an unrecoverable crash loop that also
     * destroys the evidence of where the hole came from.  Park the stream in
     * NEED_REPAIR before anything reaches disk instead: the receiver stays
     * suspended, open is refused, and the standby is rebuilt from a state
     * that is still consistent.
     * A re-sent prefix (lfn not ahead of the flush point) is idempotent and
     * must not trip this.  A zero flush lfn means the cursor has not been
     * established yet (bind in progress) and carries no continuity claim.
     * Use the first batch header lfn in the payload, not rep_batch_req's
     * log_point.lfn: the sender may pack multiple batches per message and
     * leaves the header at the last batch's lfn.
     */
    if (lrcv->flush_point.lfn != 0 && batch->head.point.lfn > lrcv->flush_point.lfn + 1) {
        OG_LOG_RUN_ERR("[Log Receiver] stream %u received non-continuous batch at [%u-%u/%u/%llu]: flushed lfn "
                       "is %llu, so redo for lfn %llu..%llu is missing on the primary and cannot be recovered. "
                       "Standby must be re-synced (rebuild).",
                       lrcv->src_node_id, batch->head.point.rst_id, batch->head.point.asn,
                       batch->head.point.block_id, (uint64)batch->head.point.lfn,
                       (uint64)lrcv->flush_point.lfn, (uint64)lrcv->flush_point.lfn + 1,
                       (uint64)batch->head.point.lfn - 1);
        lrcv_needrepair(lrcv);
        return OG_ERROR;
    }

    log_point_t primary_start = req->log_point;
    if (lrcv_flush_log(lrcv, &req->log_point, (void *)batch, size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    lrcv->flush_point = req->log_point;
    lrcv_update_primary_report_point(lrcv, &primary_start, batch, size,
                                     file_set->items[lrcv_get_curr_file(lrcv)].ctrl->block_size);
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
    lrcv_fill_peer_flush_point(lrcv, &rep_batch_resp->flush_point);
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
                } else {
                    /*
                     * No archived copy exists (a non-DBStor standby never
                     * archives the received files, and a primary may not
                     * have archived this file yet): the file is still being
                     * consumed by replay.  Pace the wait -- without this the
                     * loop spins at 100% CPU on ckpt_trigger while the
                     * replay point catches up.
                     */
                    OG_LOG_DEBUG_INF("[Log Receiver] no archived log for active file %u [%u-%u] of stream %u, "
                                     "wait for replay to consume it",
                                     file_id, file->head.rst_id, file->head.asn, lrcv->src_node_id);
                    cm_sleep(100);
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

/*
 * Best-effort recycle pass used at bind time on a cluster standby.
 *
 * A blocking wait here would deadlock: an ACTIVE file whose tail is still
 * un-applied can only be drained by replay, and replay is gated by the
 * cross-node drain-certificate frontier, which needs this stream to answer
 * QUERY_STATUS READY first.  The receiver would wait for replay while replay
 * waits for the receiver (observed as a permanent LSND CONNECTED / stream-0
 * bind stall after a send-timeout disconnect under TPCC load).
 *
 * Recycle only the files replay has already consumed (rcy_point past the
 * file's asn); leave the rest ACTIVE.  They are re-checked and recycled by
 * lrcv_switch_logfile while the message loop (and heartbeat) stays alive, so
 * the primary keeps flowing and replay can advance past them.
 */
static void lrcv_recycle_consumed_logfiles(lrcv_context_t *lrcv)
{
    logfile_set_t *file_set = lrcv_get_file_set(lrcv);
    log_point_t *rcy_point = &lrcv_get_node_ctrl(lrcv)->rcy_point;
    uint32 file_id = lrcv_get_active_file(lrcv);
    uint32 curr_file = lrcv_get_curr_file(lrcv);

    while (file_id != curr_file) {
        log_file_t *file = &file_set->items[file_id];
        if (file->ctrl->status == LOG_FILE_INACTIVE || file->ctrl->status == LOG_FILE_UNUSED) {
            lrcv_get_next_file(lrcv, &file_id, OG_FALSE);
            continue;
        }
        if (file->ctrl->status == LOG_FILE_ACTIVE &&
            LRCV_LOG_POINT_ON_POST_FILE(*rcy_point, file->head) &&
            file->head.asn != OG_INVALID_ASN) {
            /* lrcv_recycle_file advances stream_active_file itself; the next
             * iteration re-reads the same file_id, now INACTIVE. */
            lrcv_recycle_file(lrcv, rcy_point);
            continue;
        }
        OG_LOG_RUN_INF("[Log Receiver] stream %u defers recycling active file %u [%u-%u] (rcy "
                       "[%u-%u/%u/%llu]): replay still consuming it, the log-switch path will recycle it",
                       lrcv->src_node_id, file_id, file->head.rst_id, file->head.asn,
                       rcy_point->rst_id, rcy_point->asn, rcy_point->block_id, (uint64)rcy_point->lfn);
        break;
    }
}

/*
 * Force the stream resume cursor onto the true end of the local current
 * file when that file already carries redo.
 *
 * After BUILD STANDBY the ctrl rcy/lrp points carry the PRIMARY-side block
 * ids, which may not be a batch boundary in the standby's own file (a batch
 * payload instead of a header).  Reporting such a block makes the primary
 * read mid-batch and tear the stream down with "invalid batch".  The
 * receiver appends every received batch at ITS OWN sequential write_pos, so
 * the only safe resume position is the local file end: the primary then
 * re-sends only redo the standby does not have yet, and the redo the standby
 * already holds (including the un-applied tail) is consumed from the file by
 * replay.  An empty file keeps the existing flush point (the caller's
 * fresh-build / applied-point paths handle it).
 */
static void lrcv_align_flush_point_to_file_end(lrcv_context_t *lrcv, log_file_t *file, log_point_t *flush_point)
{
    uint32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    uint32 file_block;

    if (file->head.write_pos <= head_size || file->ctrl->block_size == 0) {
        return; /* empty file: no received redo to resume from */
    }

    file_block = (uint32)(file->head.write_pos / file->ctrl->block_size);
    if (flush_point->rst_id == file->head.rst_id && flush_point->asn == file->head.asn &&
        flush_point->block_id == file_block) {
        return; /* already at the file end */
    }

    OG_LOG_RUN_INF("[Log Receiver] align stream resume point [%u-%u/%u/%llu] to local current file end "
                   "[%u-%u/%u] (write_pos %llu) of %s",
                   flush_point->rst_id, flush_point->asn, flush_point->block_id, (uint64)flush_point->lfn,
                   file->head.rst_id, file->head.asn, file_block, (uint64)file->head.write_pos, file->ctrl->name);
    flush_point->rst_id = file->head.rst_id;
    flush_point->asn = file->head.asn;
    flush_point->block_id = file_block;
}

static bool32 lrcv_primary_resume_point_valid(const log_point_t *point)
{
    return (bool32)(point->asn != OG_INVALID_ASN && point->lfn != 0 && point->block_id != 0);
}

void lrcv_capture_primary_resume_point(knl_session_t *session, uint32 node_id, const log_point_t *point)
{
    if (node_id >= OG_MAX_INSTANCES || !lrcv_primary_resume_point_valid(point)) {
        return;
    }

    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;

    /*
     * Fast path: while a stream for this node is bound, the captured point is
     * never consumed (first_bind_after_build is only armed by the seed while
     * the node is unbound), so skip the lock entirely on the hot replay path.
     * The read races with bind/unbind but is a hint only: a stale "bound"
     * skips an update that would not be used, a stale "unbound" only costs an
     * extra lock acquisition.
     */
    if ((mgr->bound_mask & ((uint64)1 << node_id)) != 0) {
        return;
    }

    cm_spin_lock(&mgr->lock, NULL);
    log_point_t *stored = &mgr->primary_resume_point[node_id];
    log_point_t candidate = *point;
    /*
     * Order by (rst_id, asn, block_id) like the rest of the redo stack:
     * comparing lfn alone would keep a stale point across a resetlogs (or on
     * DBStor where the ordering metric is LSN) and could make the next bind
     * report a boundary from the wrong resetlog generation.
     */
    if (stored->lfn == 0 || log_cmp_point(&candidate, stored) > 0) {
        *stored = candidate;
    }
    cm_spin_unlock(&mgr->lock);
}

void lrcv_seed_primary_resume_points(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    if (!db->ctrl.core.build_completed) {
        return;
    }
    if (!DB_IS_PHYSICAL_STANDBY(db) && !DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
        return;
    }

    uint32 node_count = db->ctrl.core.node_count;
    for (uint32 i = 0; i < node_count; i++) {
        lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;

        cm_spin_lock(&mgr->lock, NULL);
        if ((mgr->bound_mask & ((uint64)1 << i)) != 0) {
            /*
             * The stream already bound before recovery finished (receiver
             * waits for OPEN): its first bind has already run, arming now
             * would only make the next reconnect take the first-bind shortcut
             * instead of the dedicated reconnect path.
             */
            cm_spin_unlock(&mgr->lock);
            continue;
        }
        /*
         * Arm the first-bind path only for a real captured batch-head point.
         * The persisted ctrl rcy/lrp cursor is the standby's local replay
         * position and may not be a valid batch boundary in the primary's
         * file (BUILD snapshots commonly carry block id 0); falling back to
         * the normal flush-point derivation is safer than reporting such a
         * point to the sender.
         */
        if (lrcv_primary_resume_point_valid(&mgr->primary_resume_point[i])) {
            mgr->first_bind_after_build[i] = OG_TRUE;
        }
        cm_spin_unlock(&mgr->lock);
    }
}

/*
 * The first bind after BUILD resumes flush_point in primary coordinates.
 * Return OG_TRUE when the caller must skip deriving a point from local files.
 */
static bool32 lrcv_take_first_bind_resume_point(lrcv_context_t *lrcv)
{
    uint32 node_id;
    log_point_t point;
    lrcv_mgr_t *mgr;

    if (lrcv->reconnected) {
        return OG_FALSE;
    }

    node_id = lrcv->stream_bound ? lrcv->src_node_id : lrcv->session->kernel->id;
    mgr = &lrcv->session->kernel->lrcv_mgr;
    cm_spin_lock(&mgr->lock, NULL);
    if (!mgr->first_bind_after_build[node_id]) {
        cm_spin_unlock(&mgr->lock);
        return OG_FALSE;
    }
    point = mgr->primary_resume_point[node_id];
    mgr->first_bind_after_build[node_id] = OG_FALSE;
    cm_spin_unlock(&mgr->lock);

    if (!lrcv_primary_resume_point_valid(&point)) {
        OG_LOG_RUN_WAR("[Log Receiver] stream %u first bind after build but primary resume point is invalid",
                       node_id);
        return OG_FALSE;
    }

    lrcv->flush_point = point;
    OG_LOG_RUN_INF("[Log Receiver] stream %u first bind after build, resume from primary resume point "
                   "[%u-%u/%u/%llu]",
                   node_id, lrcv->flush_point.rst_id, lrcv->flush_point.asn,
                   lrcv->flush_point.block_id, (uint64)lrcv->flush_point.lfn);
    return OG_TRUE;
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

    /*
     * On a cluster standby the cross-node drain-certificate frontier gates
     * replay and only opens once this stream is READY.  A bind that waits
     * for replay to drain the ACTIVE files would therefore never complete
     * (receiver waits for replay, replay waits for the receiver's READY).
     * Recycle best-effort instead and defer the rest to the log-switch path.
     * On a primary (or a single-node standby) replay is never frontier-gated,
     * so the original blocking wait is kept.
     */
    if (DB_IS_CLUSTER(lrcv->session) && !DB_IS_PRIMARY(&lrcv->session->kernel->db)) {
        lrcv_recycle_consumed_logfiles(lrcv);
    } else if (lrcv_wait_logfile_no_active(lrcv) != OG_SUCCESS) {
        return OG_ERROR;
    }

    arch_reset_file_id(lrcv->session, ARCH_DEFAULT_DEST);

    lrcv->flush_point.lfn = 0;
    if (!lrcv->reconnected) {
        errno_t err = memset_sp(&lrcv->primary_report_point, sizeof(log_point_t), 0, sizeof(log_point_t));
        knl_securec_check(err);
    }
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

    if (lrcv_take_first_bind_resume_point(lrcv)) {
        goto prepare_flush_point_done;
    }

    if (LRCV_LOG_POINT_ON_CURR_FILE(*lrp_point, file->head)) {
        if (LRCV_LOG_POINT_ON_CURR_FILE(req->curr_point, file->head)) {
            if (!lrcv->reconnected) {
                lrcv->flush_point.rst_id = file->head.rst_id;
                lrcv->flush_point.asn = file->head.asn;
                /*
                 * Scan the current file on every physical device type.  The
                 * head write_pos alone is not authoritative on a freshly
                 * built cluster standby: recovery has already consumed and
                 * recycled the restored redo, leaving an empty current file
                 * whose head still carries a stale write_pos (observed
                 * 45568 bytes with all-zero content).  Only the scan can
                 * tell that no received batch exists (curr_lfn == 0), which
                 * the fresh-file branch below turns into the applied point.
                 * log_get_file_offset reads through the device layer, so it
                 * works on DSS/RAW devices as well.  ULOG files are
                 * LSN-addressed with no physical ring and keep the legacy
                 * lrp-derived lfn.
                 */
                if (file->ctrl->type == DEV_TYPE_ULOG) {
                    curr_lfn = lrp_point->lfn;
                } else if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                               (uint64 *)&file->head.write_pos, &curr_lfn, &scn) != OG_SUCCESS) {
                    OG_LOG_RUN_ERR("[Log Receiver] failed to get file offset for online log %s ",
                                   file->ctrl->name);
                    return OG_ERROR;
                }
                OG_LOG_RUN_INF("[Log Receiver] Standby repaired current log file[%u] status %d log point is [%u-%u/%llu/%llu]",
                               lrcv_get_curr_file(lrcv), file->ctrl->status, file->head.rst_id, file->head.asn,
                               file->head.write_pos, curr_lfn);
                lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
                if (curr_lfn == 0) {
                    /*
                     * Freshly built standby / empty current file: the local
                     * file carries no received redo, so the sender cannot
                     * resume from its end.  Fall back to the ctrl rcy point
                     * when no primary resume point was captured (the unified
                     * first-bind path above handles the normal BUILD case).
                     */
                    lrcv->flush_point.rst_id = rcy_point->rst_id;
                    lrcv->flush_point.asn = rcy_point->asn;
                    lrcv->flush_point.block_id = rcy_point->block_id;
                    lrcv->flush_point.lfn = rcy_point->lfn;
                    OG_LOG_RUN_INF("[Log Receiver] fresh log file, resume stream from applied point "
                                   "[%u-%u/%u/%llu] (local current file is empty)",
                                   lrcv->flush_point.rst_id, lrcv->flush_point.asn,
                                   lrcv->flush_point.block_id, (uint64)lrcv->flush_point.lfn);
                } else {
                    lrcv->flush_point.lfn = curr_lfn;
                }
            } else {
                lrcv->flush_point = lrcv->stream_curr_point;
                /*
                 * The stream point seeded at bind may be the standby's own
                 * redo/ctrl point captured by the BUILD snapshot, which can
                 * lie PAST the end of the redo the receiver has actually
                 * written into its current file (the BUILD file copy races
                 * with the live redo tail).  Reporting such a point makes the
                 * primary resume mid-batch: the sender reads at
                 * flush_point.block_id, hits a batch payload instead of a
                 * batch header and tears the stream down as "invalid batch"
                 * (observed after a primary restart with the standby parked
                 * at [2/862/2139] while its file only reaches block 845).
                 * Clamp the resume cursor to the receiver's real write
                 * position; the alignment logic below then also moves
                 * rcy/lrp onto the clamped point and replay continues from
                 * the true applied position.
                 */
                uint32 file_block = (uint32)(file->head.write_pos / file->ctrl->block_size);
                uint32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
                /*
                 * Only clamp onto the local file end when the file actually
                 * carries received redo.  On a freshly built standby whose
                 * redo was consumed during recovery the current file is
                 * empty (stale head write_pos, all-zero content):
                 * stream_curr_point is then the ctrl point captured from the
                 * PRIMARY -- its block_id is a real batch boundary in the
                 * primary's file -- while the local write_pos is meaningless
                 * to the sender.  Clamping in that case hands the sender a
                 * block id that exists only in the standby's empty file and
                 * reproduces "found invalid batch".
                 */
                bool32 file_has_redo = OG_FALSE;
                if (file->ctrl->type != DEV_TYPE_ULOG) {
                    uint64 file_last_lfn = 0;
                    uint64 file_write_pos = 0;
                    uint64 file_scn = 0;
                    if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                            &file_write_pos, &file_last_lfn, &file_scn) == OG_SUCCESS) {
                        file_has_redo = (file_last_lfn != 0);
                    }
                }
                if (file_has_redo && file->head.write_pos > head_size &&
                    lrcv->flush_point.block_id > file_block) {
                    OG_LOG_RUN_INF("[Log Receiver] clamp stream resume point [%u-%u/%u/%llu] to current "
                                   "file end [%u-%u/%u] (write_pos %llu)",
                                   lrcv->flush_point.rst_id, lrcv->flush_point.asn,
                                   lrcv->flush_point.block_id, (uint64)lrcv->flush_point.lfn,
                                   file->head.rst_id, file->head.asn, file_block,
                                   (uint64)file->head.write_pos);
                    lrcv->flush_point.rst_id = file->head.rst_id;
                    lrcv->flush_point.asn = file->head.asn;
                    lrcv->flush_point.block_id = file_block;
                }
            }
            /*
             * Whatever the ctrl-derived resume cursor was, the primary can
             * only resume from a real batch boundary in the local file.  The
             * receiver appends sequentially, so the only guaranteed-safe
             * boundary on a non-empty file is its end (write_pos).  This
             * covers the mid-batch BUILD snapshot block id that used to make
             * the primary read a batch payload as a header ("invalid batch").
             */
            lrcv_align_flush_point_to_file_end(lrcv, file, &lrcv->flush_point);
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
                /*
                 * Only move the saved apply cursor when it is clearly bogus
                 * (block 0, or past the end of the receiver's current file --
                 * e.g. a BUILD snapshot carrying a primary-side block id).
                 * A valid applied point must not be rewritten here: the LRPL
                 * read alignment resolves the read cursor against the file
                 * content every cycle anyway, and rewriting the ctrl while a
                 * recovery cycle is running races with
                 * dtc_rcy_update_node_info saving its point at the cycle end
                 * -- the ctrl jumps ahead of the applied point and the next
                 * save panics on the regression.
                 */
                uint64 saved_off = (uint64)node_ctrl->rcy_point.block_id * file->ctrl->block_size;
                if (node_ctrl->rcy_point.block_id == 0 || saved_off >= file->head.write_pos) {
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
            }
            OG_LOG_RUN_INF("[Log Receiver] lrp_point is on current log, and primary/standby log has no gap");
        } else if (LRCV_LOG_POINT_ON_POST_FILE(req->curr_point, file->head)) {
            char arch_name[OG_FILE_NAME_BUFFER_SIZE];
            uint64 write_pos_ori = file->head.write_pos;
            uint64 write_pos_new;
            uint64 file_last_lfn = 0;
            bool32 local_file_consistent = OG_FALSE;

            /*
             * The primary is on a post file relative to this standby's current
             * file.  This is normally the offline/repair case (fetch the
             * archived current file), but after a cluster switchover the
             * roles reversed: this node was the old primary, its local file
             * is self-consistent up to the applied point, and the new primary
             * re-sends the continuation directly - no archive to fetch (the
             * new primary does not carry this node's archives).  Detect a
             * self-consistent local file (its content covers the replay
             * point) and resume from it instead of LFTC.
             */
            if (lrcv_is_dss_log(lrcv)) {
                file_last_lfn = lrp_point->lfn;
            } else if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                           (uint64 *)&file->head.write_pos, &file_last_lfn, &scn) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[Log Receiver] failed to get file offset for online log %s", file->ctrl->name);
                return OG_ERROR;
            }

            local_file_consistent = (file_last_lfn >= lrp_point->lfn && lrp_point->lfn != 0);
            if (local_file_consistent) {
                OG_LOG_RUN_INF("[Log Receiver] local file self-consistent (last lfn %llu >= lrp %llu), "
                               "resume without LFTC (topology reversal after switchover)",
                               (uint64)file_last_lfn, (uint64)lrp_point->lfn);
                lrcv->flush_point.rst_id = file->head.rst_id;
                lrcv->flush_point.asn = file->head.asn;
                lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
                lrcv->flush_point.lfn = file_last_lfn;
            } else {
                // Start LFTC to fetch corresponding archived log from primary
                if (lrcv_fetch_archived_log(lrcv, file, OG_FALSE, arch_name, OG_FILE_NAME_BUFFER_SIZE) !=
                    OG_SUCCESS) {
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
            }
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
            uint32 head_size = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
            if (file->head.write_pos <= head_size) {
                /*
                 * Freshly built standby: the current file was (re)initialized
                 * empty by the BUILD snapshot with the primary's current-file
                 * asn, while the applied/recovery points (rcy/lrp) still live
                 * in the PREVIOUS asn.  The un-applied redo between rcy and
                 * lrp therefore exists only on the primary's previous file;
                 * point the flush cursor at that file at the applied position
                 * so the primary re-sends it.  Resuming from the empty local
                 * current file (lrp lfn) would skip those batches and the
                 * replay would start at a non-continuous lfn (observed:
                 * first received batch lfn 1657 while rcy lfn 1644).
                 */
                lrcv->flush_point.rst_id = lrp_point->rst_id;
                lrcv->flush_point.asn = lrp_point->asn;
                lrcv->flush_point.block_id = rcy_point->block_id;
                lrcv->flush_point.lfn = rcy_point->lfn;
                OG_LOG_RUN_INF("[Log Receiver] fresh stream file empty, resume from applied point "
                               "[%u-%u/%u/%llu] in primary previous file",
                               lrcv->flush_point.rst_id, lrcv->flush_point.asn,
                               lrcv->flush_point.block_id, (uint64)lrcv->flush_point.lfn);
            } else {
                lrcv->flush_point.rst_id = file->head.rst_id;
                lrcv->flush_point.asn = file->head.asn;
                lrcv->flush_point.block_id = (uint32)(file->head.write_pos / file->ctrl->block_size);
                if (curr_lfn > lrcv->flush_point.lfn) {
                    lrcv->flush_point.lfn = curr_lfn;
                }
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
        if (req->curr_point.rst_id > lrp_point->rst_id ||
            (req->curr_point.rst_id == lrp_point->rst_id && req->curr_point.asn > lrp_point->asn)) {
            /*
             * The primary has already switched past the file that carries the
             * un-applied redo (rcy..lrp).  This is the freshly built standby
             * case: the local current file is empty/invalid while the needed
             * redo still lives in the primary's PREVIOUS file (asn =
             * lrp.asn).  Point the flush cursor there at the applied position,
             * otherwise the primary resumes in its current file and the
             * batches between rcy and lrp are never shipped (replay then
             * starts at a non-continuous lfn, observed as the first received
             * batch lfn 1657 while rcy lfn 1644).
             */
            lrcv->flush_point.rst_id = lrp_point->rst_id;
            lrcv->flush_point.asn = lrp_point->asn;
            lrcv->flush_point.block_id = rcy_point->block_id;
        } else {
            lrcv->flush_point.rst_id = req->curr_point.rst_id;
            lrcv->flush_point.asn = req->curr_point.asn;
            lrcv->flush_point.block_id = 1;
        }
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

prepare_flush_point_done:
    if (!lrcv->reconnected) {
        lrcv_set_free_size(lrcv, lrcv_get_free_size(lrcv) + log_file_freesize(file));
    }

    OG_LOG_RUN_INF("[Log Receiver] Set flush point to [%u-%u/%u/%llu], log free size is %llu",
                   lrcv->flush_point.rst_id, lrcv->flush_point.asn, lrcv->flush_point.block_id,
                   (uint64)lrcv->flush_point.lfn, lrcv_get_free_size(lrcv));

    if (lrcv->primary_report_point.lfn == 0 && lrcv->flush_point.lfn != 0) {
        log_point_t primary_point;
        bool32 found = OG_FALSE;

        errno_t err = memset_sp(&primary_point, sizeof(log_point_t), 0, sizeof(log_point_t));
        knl_securec_check(err);
        if (lrcv_primary_point_from_lfn(lrcv, lrcv->flush_point.lfn, &primary_point) == OG_SUCCESS &&
            primary_point.lfn == lrcv->flush_point.lfn) {
            found = OG_TRUE;
            lrcv->primary_report_point = primary_point;
            OG_LOG_RUN_INF("[Log Receiver] stream %u report primary flush point [%u-%u/%u/%llu] "
                           "(local flush [%u-%u/%u/%llu]) from applied redo batch header",
                           lrcv->src_node_id, primary_point.rst_id, primary_point.asn,
                           primary_point.block_id, (uint64)primary_point.lfn,
                           lrcv->flush_point.rst_id, lrcv->flush_point.asn, lrcv->flush_point.block_id,
                           (uint64)lrcv->flush_point.lfn);
        }
        if (!found) {
            lrcv->primary_report_point = lrcv->flush_point;
            OG_LOG_RUN_INF("[Log Receiver] stream %u no applied batch header for lfn %llu, "
                           "fall back to local flush point for peer report",
                           lrcv->src_node_id, (uint64)lrcv->flush_point.lfn);
        }
    }

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
        /*
         * The primary says the sending point we reported is not a valid
         * batch boundary (normally the BUILD-snapshot block id, which can
         * point mid-batch).  Do not hard-reject the connection: that made
         * the primary keep notify_repair set forever (it only clears the
         * flag after a successful query response) and every reconnect was
         * rejected again -- a permanent reject loop.  Continue the bind:
         * lrcv_prepare_log_files re-derives the resume cursor from the real
         * file content below, the query response goes back, and the primary
         * clears notify_repair.  If the local files genuinely need a rebuild
         * the replay path fails loudly instead of silently skipping redo.
         */
        OG_LOG_RUN_WAR("[Log Receiver] primary detected invalid batches based on the sending point returned by "
                       "standby; re-deriving the resume point from local files");
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
 * Cluster standby recovery (startup catch-up / BUILD STANDBY recovery) is
 * DTC-driven: the replay threads consume the current redo files and wait for
 * the receiver to append the primary's live redo into them.  On a freshly
 * built standby the restored current files are empty, so recovery can never
 * finish unless the receiver binds and flushes while the database is still
 * below OPEN -- waiting for OPEN as lrcv_bind_stream used to do deadlocks
 * (the replayer waits for redo, the receiver waits for OPEN).
 *
 * The database must be past the control-file load (>= RECOVERY, which also
 * excludes the NOMOUNT/CREATING restore phase where files are under
 * construction) and the source node must exist in the topology so the
 * per-node log ctrl is valid.
 */
static inline bool32 lrcv_standby_recovery_active(knl_session_t *session, uint32 src_node_id)
{
    database_t *db;

    if (session == NULL) {
        return OG_FALSE;
    }
    db = &session->kernel->db;
    if (DB_IS_PRIMARY(db) || !DB_IS_CLUSTER(session)) {
        return OG_FALSE;
    }
    if (db->status < DB_STATUS_RECOVERY || db->status >= DB_STATUS_OPEN) {
        return OG_FALSE;
    }
    return (src_node_id < db->ctrl.core.node_count);
}

/*
 * Bind this receiver connection to a redo stream identified by
 * (src_dbid, src_node_id).  A newer connection for an already-served stream
 * takes the old one over (the primary only reconnects after dropping the
 * previous connection; the epoch check above rejects stale-epoch peers).
 * The context remains in its connection-pool slot; later lookups use the
 * source node id stored in the context rather than the array index.
 */
static void lrcv_takeover_stale_stream(lrcv_context_t *other, uint32 src_node_id)
{
    other->taken_over = OG_TRUE;
    errno_t err = memset_sp(&other->wait_info, sizeof(log_switch_wait_info_t), 0, sizeof(log_switch_wait_info_t));
    knl_securec_check(err);
    other->reset_asn = OG_INVALID_ASN;
    lrcv_disconnect(other);
    lrcv_close_stream_files(other);
    other->stream_bound = OG_FALSE;
    /* called with mgr->lock held by lrcv_bind_stream; session stays valid */
    other->session->kernel->lrcv_mgr.bound_mask &= ~((uint64)1 << other->src_node_id);
    other->src_node_id = 0;
    other->src_dbid = 0;
    other->file_set = NULL;
    other->lsn_frontier = 0;
    other->stream_flushed_lfn = 0;
    OG_LOG_RUN_WAR("[Log Receiver] stream %u: stale bound connection taken over by a new connection "
                   "(old thread closed=%u), reset stream state", src_node_id, other->thread.closed);
}

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

    /*
     * Brain-split backstop: after a cluster failover the new primary bumps
     * core_ctrl.cluster_epoch; a peer that still carries the old epoch must
     * not be accepted as a stream source.
     */
    {
        uint32 peer_epoch = (uint32)req->reserved[0];
        uint32 local_epoch = kernel->db.ctrl.core.cluster_epoch;
        if (peer_epoch < local_epoch) {
            lrcv_needrepair(lrcv);
            OG_LOG_RUN_ERR("[Log Receiver] stream %u epoch mismatch: peer=%u local=%u, reject as source, need repair",
                src_node_id, peer_epoch, local_epoch);
            return NULL;
        }
    }

    cm_spin_lock(&mgr->lock, NULL);
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *other = &mgr->streams[i];
        if (other == lrcv) {
            continue;
        }
        if (other->stream_bound && other->src_node_id == src_node_id && other->session != NULL) {
            /*
             * The primary only opens a new connection after it has dropped
             * the previous one (send timeout / RST).  A stream that is still
             * marked bound here -- receiver thread already exited, pipe
             * already torn down, or the old thread wedged after a failed
             * file reset -- must not reject the fresh connection forever
             * (observed as a 1s OG-00777 reject loop after a send-timeout
             * disconnect under TPCC load).  Take the new connection over:
             * force-close the stale socket so any blocked receive unblocks,
             * mark the old context taken_over so its thread stops touching
             * stream files, then unbind.  The epoch check above already
             * rejected stale-epoch peers, so a same-epoch duplicate is a
             * reconnect, not a brain split; the old context keeps its
             * session pointer so its own thread cleanup still finds it.
             */
            lrcv_takeover_stale_stream(other, src_node_id);
            break;
        }
    }

    lrcv->src_node_id = src_node_id;
    lrcv->src_dbid = src_dbid;
    lrcv->taken_over = OG_FALSE;
    lrcv->stream_bound = OG_TRUE;
    /* a new source connection starts a fresh stream; clear any stale terminal mark */
    lrcv->terminal = OG_FALSE;
    kernel->lrcv_mgr.source_absent &= ~((uint64)1 << src_node_id);
    mgr->bound_mask |= ((uint64)1 << src_node_id);

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
     *
     * Exception: a cluster physical standby that is mid-recovery (BUILD
     * STANDBY DATABASE / startup recovery after the ctrl is restored but
     * before OPEN) has its node ctrl loaded and its replay threads already
     * consuming the current redo files.  The receiver must bind and flush
     * the primary's live redo into those files immediately, otherwise the
     * replayer waits for data that never arrives (the restored current redo
     * files are empty) while the receiver waits for OPEN -- a deadlock
     * observed right after BUILD STANDBY DATABASE on a cluster standby.
     */
    if (lrcv->session->kernel->db.status < DB_STATUS_OPEN &&
        !lrcv_standby_recovery_active(lrcv->session, src_node_id)) {
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
                if (file->ctrl->type != DEV_TYPE_ULOG) {
                    /*
                     * The device layer requires a 512-byte aligned buffer;
                     * a stack struct is not guaranteed to be aligned, so read
                     * into a scratch aligned buffer first.  The recv buffer
                     * is free here: the receiver processes messages strictly
                     * one at a time and this is the bind path (no batch is
                     * being read concurrently).
                     */
                    aligned_buf_t *head_buf = &lrcv->recv_buf.read_buf;
                    if (cm_read_device(file->ctrl->type, lrcv->stream_handle[i], 0, head_buf->aligned_buf,
                                       head_size) == OG_SUCCESS) {
                        err = memcpy_sp(&disk_head, sizeof(disk_head), head_buf->aligned_buf, sizeof(disk_head));
                        knl_securec_check(err);
                    } else {
                        err = memset_sp(&disk_head, sizeof(disk_head), 0, sizeof(disk_head));
                        knl_securec_check(err);
                    }
                }
                if (disk_head.asn != 0 && disk_head.block_size != 0) {
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
    cm_atomic_set((atomic_t *)&lrcv->stream_flushed_lfn, 0);
    for (uint32 i = 0; i < OG_MAX_LOG_FILES; i++) {
        lrcv->stream_file_last_lfn[i] = 0;
    }
    /*
     * Seed the per-file last-lfn map for files that still carry redo across
     * a reconnect.  An ACTIVE file rotated out by a previous receiver
     * session may still hold an un-applied tail; lrcv_recycle_file compares
     * this map against the applied point, and a zero seed would make every
     * file look already consumed and recycle it before replay finished
     * (redo loss).  The file scan is safe here: the receiver processes
     * messages strictly one at a time and this is the bind path (no batch is
     * being read concurrently).  ULOG files are LSN-addressed and have no
     * physical ring, so they never need recycling.
     */
    for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
        log_file_t *file = &file_set->items[i];
        if (file->ctrl == NULL || file->ctrl->status != LOG_FILE_ACTIVE ||
            i == lrcv->stream_curr_file || file->ctrl->type == DEV_TYPE_ULOG) {
            continue;
        }
        uint64 file_last_lfn = 0;
        uint64 file_write_pos = 0;
        uint64 file_scn = 0;
        if (log_get_file_offset(lrcv->session, file->ctrl->name, &lrcv->recv_buf.read_buf,
                                &file_write_pos, &file_last_lfn, &file_scn) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[Log Receiver] failed to scan active log file %s of stream %u at bind, "
                           "recycle deferred until the file is provably applied",
                           file->ctrl->name, lrcv->src_node_id);
            continue;
        }
        lrcv->stream_file_last_lfn[i] = file_last_lfn;
        OG_LOG_RUN_INF("[Log Receiver] stream %u active log file %s last lfn %llu",
                       lrcv->src_node_id, file->ctrl->name, (uint64)file_last_lfn);
    }

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

    /*
     * Report ready while the database is still below OPEN when a cluster
     * physical standby is mid-recovery (BUILD STANDBY / startup catch-up):
     * the replay threads are already consuming the current redo files and
     * wait for the receiver to append the primary's live redo.  If the
     * receiver keeps answering "not ready" here, the primary's log sender
     * stays in QUERYING forever and never ships the redo that recovery is
     * waiting for (deadlock observed right after BUILD STANDBY DATABASE).
     * lrcv_prepare_log_files already handles the freshly-built-file resume
     * (resume from the applied point), so making the stream ready early is
     * safe and idempotent.
     */
    if ((db->status != DB_STATUS_OPEN && !lrcv_standby_recovery_active(lrcv->session, lrcv->src_node_id)) ||
        (is_building_cascaded && lrcv->peer_role == PEER_PRIMARY)) {
        resp->is_ready = OG_FALSE;
    } else {
        if (lrcv_resetlog_check(lrcv, req) == OG_SUCCESS) {
            if (lrcv_prepare_log_files(lrcv, req) == OG_SUCCESS) {
                /*
                 * The source cluster announces its online node bitmap in the
                 * query status.  After a cluster switchover the source cluster
                 * may run fewer nodes than the logical node_count (e.g. the
                 * simulated standby cluster runs node0 only): streams without
                 * a source must be excluded from the replay drain barrier,
                 * otherwise their zero frontier gates every other stream and
                 * the standby can never drain.  A stream that reconnects later
                 * clears its terminal flag on bind.
                 */
                uint64 source_nodes = (uint64)req->reserved[1];
                if (source_nodes != 0 && source_nodes != ~(uint64)0) {
                    uint32 node_count = lrcv->session->kernel->db.ctrl.core.node_count;
                    knl_instance_t *kernel = lrcv->session->kernel;
                    for (uint32 i = 0; i < node_count; i++) {
                        if ((source_nodes & ((uint64)1 << i)) != 0) {
                            continue;
                        }
                        lrcv_context_t *absent = lrcv_get_stream(lrcv->session, i);
                        if (absent != NULL && !absent->stream_bound) {
                            absent->terminal = OG_TRUE;
                        }
                        kernel->lrcv_mgr.source_absent |= ((uint64)1 << i);
                        OG_LOG_RUN_INF("[Log Receiver] stream %u has no source in the new topology "
                                       "(source bitmap %llx), marked absent", i, source_nodes);
                    }
                }
                resp->is_ready = OG_TRUE;
                resp->flush_point = lrcv->flush_point;
                lrcv_fill_peer_flush_point(lrcv, &resp->flush_point);
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

        case REP_CLUSTER_SWITCH_RESP: {
            rep_cluster_switch_resp_t *resp = (rep_cluster_switch_resp_t *)extend_buf;

            if (lrcv->header.size != sizeof(rep_msg_header_t) + sizeof(rep_cluster_switch_resp_t)) {
                OG_LOG_RUN_ERR("[Log Receiver] invalid cluster switch response size %u", lrcv->header.size);
                return OG_ERROR;
            }
            OG_LOG_RUN_INF("[Log Receiver] received cluster switch response from primary: state=%d demoted=%llx",
                (int)resp->state, resp->demoted_nodes);
            dtc_switch_set_resp(lrcv->session, resp->state, resp->demoted_nodes);
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

    /*
     * Defensive guard: after a cluster role flip the receiver slot may be
     * recycled while a stale connection is still being torn down; a NULL pipe
     * must be treated as a normal disconnect (the log sender retries), not a
     * NULL dereference in cs_read_stream.
     */
    if (lrcv->pipe == NULL) {
        OG_LOG_RUN_WAR("[Log Receiver] stream %u pipe is NULL, treat as disconnect", lrcv->src_node_id);
        return OG_ERROR;
    }

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

static status_t lrcv_send_cluster_switch_request(lrcv_context_t *lrcv)
{
    char *buf = lrcv->send_buf.read_buf.aligned_buf;
    rep_msg_header_t *rep_msg_header = (rep_msg_header_t *)buf;
    rep_cluster_switch_req_t *req = (rep_cluster_switch_req_t *)(buf + sizeof(rep_msg_header_t));
    knl_instance_t *kernel = lrcv->session->kernel;
    uint32 node_count = kernel->db.ctrl.core.node_count;
    uint32 i;
    uint64 expected_nodes = 0;

    rep_msg_header->size = sizeof(rep_msg_header_t) + sizeof(rep_cluster_switch_req_t);
    rep_msg_header->type = REP_CLUSTER_SWITCH_REQ;
    req->epoch = kernel->db.ctrl.core.cluster_epoch;
    req->node_count = node_count;
    /*
     * Demote set = the streams actually bound on this standby.  A source
     * cluster may run fewer nodes than the logical node_count (e.g. the
     * simulated standby cluster runs node0 only), so do not blindly require
     * every node id; the primary coordinator validates the set against its
     * own cluster view.
     */
    for (i = 0; i < node_count; i++) {
        lrcv_context_t *stream = lrcv_get_stream(lrcv->session, i);
        if (stream != NULL && stream->stream_bound && stream->session != NULL) {
            expected_nodes |= ((uint64)1 << i);
        }
    }
    if (expected_nodes == 0) {
        expected_nodes = 1; // safety: at least the handshake stream itself
    }
    req->expected_nodes = expected_nodes;
    req->reserved = 0;

    if (cs_write_stream(lrcv->pipe, buf, rep_msg_header->size,
                        (int32)cm_atomic_get(&lrcv->session->kernel->attr.repl_pkg_size)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[Log Receiver] failed to send cluster switchover request message to primary");
        return OG_ERROR;
    }

    lrcv->state = REP_STATE_WAITING_DEMOTE;
    OG_LOG_RUN_INF("[Log Receiver] send cluster switchover request to primary, epoch=%u nodes=%u expected=%llx",
        req->epoch, node_count, expected_nodes);
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
    if (lrcv->state == REP_STATE_CLUSTER_DEMOTE_REQUEST) {
        return lrcv_send_cluster_switch_request(lrcv);
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
        if (lrcv->taken_over) {
            OG_LOG_RUN_INF("[Log Receiver] exiting after the stream was taken over by a new connection");
            return OG_SUCCESS;
        }

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

    while ((lrcv = lrcv_get_local_stream(session)) == NULL || lrcv->pipe == NULL) {
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

    lrcv = lrcv_get_local_stream(session);
    if (lrcv == NULL) {
        OG_THROW_ERROR(ERR_PRI_NOT_CONNECT, "primary info");
        return OG_ERROR;
    }
    ret = strncpy_s(host, host_buf_size, lrcv->primary_host, OG_HOST_NAME_BUFFER_SIZE - 1);

    knl_securec_check(ret);
    return OG_SUCCESS;
}

status_t lrcv_get_primary_server(knl_session_t *session, int32 retry_count,
    char *host, uint32 host_buf_size, uint16 *port)
{
    lrcv_context_t *lrcv;

    if (lrcv_get_primary_host(session, retry_count, host, host_buf_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    lrcv = lrcv_get_local_stream(session);
    if (lrcv == NULL) {
        OG_THROW_ERROR(ERR_PRI_NOT_CONNECT, "primary info");
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
    lrcv_context_t *lrcv = lrcv_get_local_stream(session);
    if (lrcv == NULL) {
        return;
    }
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
    lrcv_context_t *lrcv = lrcv_get_local_stream(session);
    if (lrcv == NULL) {
        OG_THROW_ERROR(ERR_SEND_RECORD_REQ_FAILED);
        return OG_ERROR;
    }
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
    lrcv_context_t *lrcv = lrcv_get_local_stream(session);

    while (lrcv != NULL && lrcv->status < LRCV_PREPARE) {
        if (lrcv->session == NULL || lrcv->session->killed) {
            return;
        }

        cm_sleep(100);
        lrcv = lrcv_get_local_stream(session);
    }
}

void lrcv_clear_needrepair_for_failover(knl_session_t *session)
{
    lrcv_mgr_t *mgr = &session->kernel->lrcv_mgr;
    bool32 has_bound_stream = OG_FALSE;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        lrcv_context_t *lrcv = &mgr->streams[i];
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->stream_bound) {
            has_bound_stream = OG_TRUE;
            lrcv->status = LRCV_DISCONNECTED;
        }
        cm_spin_unlock(&lrcv->lock);
    }
    if (!has_bound_stream) {
        lrcv_context_t *lrcv = lrcv_get_local_stream(session);
        if (lrcv != NULL) {
            lrcv->status = LRCV_DISCONNECTED;
        }
    }
    session->kernel->lftc_client_ctx.arch_lost = OG_FALSE;
    session->kernel->rcy_ctx.log_decrypt_failed = OG_FALSE;
}
