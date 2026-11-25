/* -------------------------------------------------------------------------
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * This file is part of the oGRAC project.
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
 * dtc_switchover.c
 *
 * Cluster-level switchover / failover orchestration for N-to-M redo stream
 * replication between two oGRAC clusters.
 *
 * Reuse strategy:
 *  - per-node demote  : srv_process_demote_request (trigger + completion hook only)
 *  - cluster promote  : db_promote_cluster_role (reformer + follower paths)
 *  - cross-cluster msg: existing REP_* link over the ready handshake stream
 *    (stream 0 preferred), new message types
 *  - in-cluster coord : MES broadcast / unicast ack
 *
 * Isolation:
 *  - single-node switchover path in knl_db_alter.c / srv_instance.c untouched
 *  - storage-DR (dbstor/DBS) role callback path untouched
 *  - all new state lives in this module (g_dtc_switch)
 *
 * IDENTIFICATION
 * src/cluster/dtc_switchover.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_log.h"
#include "repl_log_recv.h"
#include "repl_log_send.h"
#include "repl_log_replay.h"
#include "dtc_database.h"
#include "rc_reform.h"
#include "mes_func.h"
#include "dtc_switchover.h"

/* --------------------------------------------------------------------- */
/*  MES message payloads                                                 */
/* --------------------------------------------------------------------- */
typedef struct st_msg_dtc_switch_demote_req {
    mes_message_head_t head;
    uint32 epoch;
    uint64 expected_nodes;
} msg_dtc_switch_demote_req_t;

typedef struct st_msg_dtc_switch_demote_ack {
    mes_message_head_t head;
    uint32 node_id;
    bool32 result;
} msg_dtc_switch_demote_ack_t;

typedef struct st_msg_dtc_switch_promote_notify {
    mes_message_head_t head;
    uint32 epoch;
} msg_dtc_switch_promote_notify_t;

/* --------------------------------------------------------------------- */
/*  Local state                                                          */
/* --------------------------------------------------------------------- */
static dtc_switch_ctrl_t g_dtc_switch;

static void dtc_switch_reset(void)
{
    cm_spin_lock(&g_dtc_switch.lock, NULL);
    g_dtc_switch.state = DTC_SWITCH_IDLE;
    g_dtc_switch.epoch = 0;
    g_dtc_switch.self_id = 0;
    g_dtc_switch.expected_nodes = 0;
    g_dtc_switch.demoted_nodes = 0;
    g_dtc_switch.coordinator_inst = 0;
    g_dtc_switch.coordinator_rsn = 0;
    g_dtc_switch.coordinator_sid = 0;
    g_dtc_switch.resp_state = REP_STATE_NORMAL;
    g_dtc_switch.demote_in_progress = OG_FALSE;
    g_dtc_switch.am_coordinator = OG_FALSE;
    cm_spin_unlock(&g_dtc_switch.lock);
}

void dtc_switch_init(void)
{
    g_dtc_switch.lock = 0;
    dtc_switch_reset();
}

bool32 dtc_switch_in_progress(void)
{
    return g_dtc_switch.demote_in_progress;
}

bool32 dtc_switch_in_demote_wait(void)
{
    bool32 in_wait;

    cm_spin_lock(&g_dtc_switch.lock, NULL);
    in_wait = (g_dtc_switch.state == DTC_SWITCH_DEMOTE_WAIT &&
               g_dtc_switch.resp_state == REP_STATE_NORMAL);
    cm_spin_unlock(&g_dtc_switch.lock);
    return in_wait;
}

bool32 dtc_switch_am_coordinator(void)
{
    return g_dtc_switch.am_coordinator;
}

static bool32 dtc_switch_try_begin(void)
{
    cm_spin_lock(&g_dtc_switch.lock, NULL);
    if (g_dtc_switch.state != DTC_SWITCH_IDLE) {
        cm_spin_unlock(&g_dtc_switch.lock);
        return OG_FALSE;
    }
    g_dtc_switch.state = DTC_SWITCH_GATE_CHECK;
    g_dtc_switch.resp_state = REP_STATE_NORMAL;
    g_dtc_switch.demoted_nodes = 0;
    g_dtc_switch.demote_in_progress = OG_FALSE;
    g_dtc_switch.am_coordinator = OG_FALSE;
    cm_spin_unlock(&g_dtc_switch.lock);
    return OG_TRUE;
}

/* --------------------------------------------------------------------- */
/*  Gate A: all expected redo streams must be connected and ready        */
/* --------------------------------------------------------------------- */
/*
 * Pick the redo stream used for the cross-cluster control handshake.
 *
 * Any connected, ready stream can carry the handshake: the primary-side
 * coordinator is simply the node whose log sender receives the request
 * (see lsnd_process_cluster_switch_request / dtc_switch_start_primary_demote),
 * so the source node does not have to be node0.  A degraded primary cluster
 * may run without node0, in which case the lowest ready src_node_id is used;
 * stream 0 keeps priority as the legacy default when it is available.
 */
static lrcv_context_t *dtc_switch_pick_handshake_stream(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 node_count = kernel->db.ctrl.core.node_count;
    uint32 i;

    for (i = 0; i < node_count; i++) {
        lrcv_context_t *lrcv = lrcv_get_stream(session, i);
        if (lrcv != NULL && lrcv->stream_bound && lrcv->session != NULL &&
            (lrcv->status == LRCV_READY || lrcv->status == LRCV_PREPARE)) {
            return lrcv;
        }
    }
    return NULL;
}

/*
 * Is any redo stream to the old primary cluster still connected?
 *
 * Failover is only safe without FORCE when the old primary is fully
 * unreachable; a live connection on any stream means a primary node may
 * still be serving writes, so the caller must require FORCE.
 */
static bool32 dtc_switch_any_stream_connected(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 node_count = kernel->db.ctrl.core.node_count;
    uint32 i;

    for (i = 0; i < node_count; i++) {
        lrcv_context_t *lrcv = lrcv_get_stream(session, i);
        if (lrcv != NULL && lrcv->stream_bound && lrcv->session != NULL) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t dtc_switch_gate_check(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 node_count = kernel->db.ctrl.core.node_count;
    uint32 i;

    for (i = 0; i < node_count; i++) {
        lrcv_context_t *lrcv = lrcv_get_stream(session, i);
        /*
         * A missing stream (no bound receiver) is allowed: the source cluster
         * may legitimately run fewer nodes than the logical node_count (e.g.
         * the simulated standby cluster runs node0 only).  The demote set is
         * derived from the actually-bound streams (see
         * lrcv_send_cluster_switch_request), and the primary coordinator
         * validates it against its own cluster view.
         */
        if (lrcv == NULL || !lrcv->stream_bound || lrcv->session == NULL) {
            OG_LOG_RUN_WAR("[CLUSTER SWITCHOVER] stream %u not bound, skip gate check (source cluster may run fewer nodes)",
                i);
            continue;
        }
        if (lrcv->status != LRCV_READY && lrcv->status != LRCV_PREPARE) {
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] stream %u not ready for switchover "
                           "(bound=%d session=%d status=%d)",
                i, lrcv != NULL ? (int)lrcv->stream_bound : 0,
                lrcv != NULL && lrcv->session != NULL, lrcv != NULL ? (int)lrcv->status : -1);
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster switchover requires all redo streams ready");
            return OG_ERROR;
        }
    }

    /* the handshake link: at least one connected, ready stream is required */
    if (dtc_switch_pick_handshake_stream(session) == NULL) {
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
            "cluster switchover requires at least one connected redo stream for the handshake");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* --------------------------------------------------------------------- */
/*  Gate B: drain wait - no replay cycle in flight and barrier opened    */
/* --------------------------------------------------------------------- */
static status_t dtc_switch_wait_drained(knl_session_t *session, uint32 timeout)
{
    knl_instance_t *kernel = session->kernel;
    lrpl_context_t *lrpl = &kernel->lrpl_ctx;
    date_t begin_time = g_timer()->now;

    while (lrpl->is_replaying || lrpl->pending_gated_redo) {
        if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= timeout) {
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] drain wait timeout, is_replaying=%d pending_gated=%d",
                (int)lrpl->is_replaying, (int)lrpl->pending_gated_redo);
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster switchover drain timeout");
            return OG_ERROR;
        }
        cm_sleep(DTC_SWITCH_POLL_INTERVAL);
    }
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] standby drained, no pending gated redo");
    return OG_SUCCESS;
}

/* --------------------------------------------------------------------- */
/*  Promote: reuse db_promote_cluster_role, then cleanup for redo-stream  */
/* --------------------------------------------------------------------- */
static void dtc_switch_broadcast_promote(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 node_count = kernel->db.ctrl.core.node_count;
    uint64 all_bits = (node_count >= 64) ? ~(uint64)0 : (((uint64)1 << node_count) - 1);
    uint64 peer_bits = all_bits & ~((uint64)1 << kernel->id);
    uint64 suc_inst = 0;
    msg_dtc_switch_promote_notify_t req;

    if (peer_bits == 0) {
        return;
    }

    mes_init_send_head(&req.head, MES_CMD_DTC_SWITCH_PROMOTE_NOTIFY,
        sizeof(msg_dtc_switch_promote_notify_t), OG_INVALID_ID32, kernel->id, 0,
        session->id, OG_INVALID_ID16);
    req.epoch = kernel->db.ctrl.core.cluster_epoch;

    if (mes_broadcast_and_wait(session->id, peer_bits, &req, DTC_SWITCH_TIMEOUT_DEFAULT, &suc_inst) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[CLUSTER SWITCHOVER] promote notify broadcast partial, suc=%llx peer=%llx",
            suc_inst, peer_bits);
    }
}

static status_t dtc_switch_promote(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    lrpl_context_t *lrpl = &kernel->lrpl_ctx;
    database_t *db = &kernel->db;
    date_t begin_time = g_timer()->now;

    /*
     * The file-group reset below renumbers the local redo files; it must not
     * race a running DTC replay cycle (the read thread would see renumbered
     * heads, lose the online-file match and spin in the archive lookup).
     * Switchover already drained (Gate B), so this is instant there; force
     * failover accepts a bounded settle wait for the current cycle to end.
     */
    while (lrpl->is_replaying &&
           (g_timer()->now - begin_time) / MICROSECS_PER_SECOND < DTC_SWITCH_DRAIN_TIMEOUT) {
        cm_sleep(DTC_SWITCH_POLL_INTERVAL);
    }

    /*
     * The promote engine is storage-DR oriented and does not renumber the
     * standby-written log files.  Re-initialize the local node's own file
     * group against its rcy point BEFORE the engine runs: the engine's undo
     * rollback generates redo that must land in a consistent file layout, and
     * the new primary must restart cleanly (log_check_asn).  Mirrors the
     * single-node failover reset in lrpl_process_for_failover.
     */
    lrpl_reset_logfile_for_promote(session);

    /*
     * The single-node failover path persists reset_log_scn = curr_scn when the
     * replayer drains; the cluster LRPL path does not, so do it here.
     */
    if (OG_INVALID_SCN(db->ctrl.core.reset_log_scn)) {
        db->ctrl.core.reset_log_scn = kernel->redo_ctx.curr_scn;
        if (db_save_core_ctrl(session) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failed to save reset_log_scn before promote");
            return OG_ERROR;
        }
    }

    /* standby cluster followers run the same promote engine */
    dtc_switch_broadcast_promote(session);

    if (cm_create_thread(db_promote_cluster_role, 0, NULL, &lrpl->promote_thread) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failed to create cluster promote thread");
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] cluster promote thread started");

    while (!DB_IS_PRIMARY(db) || lrpl->is_promoting) {
        if (session->killed) {
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }
        if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= DTC_SWITCH_PROMOTE_TIMEOUT) {
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] promote timeout, role=%u is_promoting=%d",
                (uint32)db->ctrl.core.db_role, (int)lrpl->is_promoting);
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster promote timeout");
            return OG_ERROR;
        }
        cm_sleep(DTC_SWITCH_POLL_INTERVAL);
    }

    /*
     * The promote engine is storage-DR oriented: it does not stop the log
     * receivers nor start log senders.  For redo-stream replication the new
     * primary must stop receiving old streams and start pushing to the old
     * primary (now standby).
     */
    lrcv_close(session);
    if (lsnd_init(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[CLUSTER SWITCHOVER] failed to start log sender after promote");
    }
    return OG_SUCCESS;
}

/* --------------------------------------------------------------------- */
/*  RPO recording for failover                                           */
/* --------------------------------------------------------------------- */
static void dtc_switch_record_rpo(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 node_count = kernel->db.ctrl.core.node_count;
    uint32 i;

    for (i = 0; i < node_count; i++) {
        lrcv_context_t *lrcv = lrcv_get_stream(session, i);
        if (lrcv == NULL || !lrcv->stream_bound) {
            continue;
        }
        OG_LOG_RUN_WAR("[CLUSTER FAILOVER] stream %u RPO: local flush lfn=%llu, peer curr lfn=%llu",
            i, (uint64)lrcv->flush_point.lfn, (uint64)lrcv->primary_curr_point.lfn);
    }
}

/* --------------------------------------------------------------------- */
/*  Primary side: coordinator starts in-cluster demote broadcast         */
/* --------------------------------------------------------------------- */
void dtc_switch_start_primary_demote(knl_session_t *session, uint32 epoch, uint64 expected_nodes)
{
    knl_instance_t *kernel = session->kernel;
    uint64 peer_bits;
    uint64 suc_inst = 0;
    msg_dtc_switch_demote_req_t req;

    cm_spin_lock(&g_dtc_switch.lock, NULL);
    g_dtc_switch.state = DTC_SWITCH_DEMOTE_WAIT;
    g_dtc_switch.epoch = epoch;
    g_dtc_switch.self_id = kernel->id;
    g_dtc_switch.expected_nodes = expected_nodes;
    g_dtc_switch.demoted_nodes = 0;
    g_dtc_switch.am_coordinator = OG_TRUE;
    g_dtc_switch.demote_in_progress = OG_TRUE;
    cm_spin_unlock(&g_dtc_switch.lock);

    peer_bits = expected_nodes & ~((uint64)1 << kernel->id);
    if (peer_bits == 0) {
        return;
    }

    mes_init_send_head(&req.head, MES_CMD_DTC_SWITCH_DEMOTE_REQ,
        sizeof(msg_dtc_switch_demote_req_t), OG_INVALID_ID32, kernel->id, 0,
        session->id, OG_INVALID_ID16);
    req.epoch = epoch;
    req.expected_nodes = expected_nodes;

    if (mes_broadcast_and_wait(session->id, peer_bits, &req, DTC_SWITCH_TIMEOUT_DEFAULT, &suc_inst) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] demote broadcast partial, suc=%llx peer=%llx", suc_inst, peer_bits);
    }
}

/* --------------------------------------------------------------------- */
/*  Primary side: coordinator waits for all peer demote acks             */
/* --------------------------------------------------------------------- */
status_t dtc_switch_wait_peers_demoted(void)
{
    date_t begin_time = g_timer()->now;
    uint64 peer_mask;
    uint64 done = 0;

    for (;;) {
        cm_spin_lock(&g_dtc_switch.lock, NULL);
        peer_mask = g_dtc_switch.expected_nodes & ~((uint64)1 << g_dtc_switch.self_id);
        done = g_dtc_switch.demoted_nodes & peer_mask;
        cm_spin_unlock(&g_dtc_switch.lock);

        if (done == peer_mask) {
            OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] all peers demoted, bitmap=%llx", done);
            return OG_SUCCESS;
        }
        if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= DTC_SWITCH_TIMEOUT_DEFAULT) {
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] wait peers demote timeout: done=%llx peer=%llx", done, peer_mask);
            return OG_ERROR;
        }
        cm_sleep(DTC_SWITCH_POLL_INTERVAL);
    }
}

/* --------------------------------------------------------------------- */
/*  Primary side: wait until every active stream is caught up            */
/* --------------------------------------------------------------------- */
status_t dtc_switch_wait_local_sync(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    lsnd_context_t *ogx = &kernel->lsnd_ctx;
    date_t begin_time = g_timer()->now;
    uint32 timeout = kernel->attr.repl_wait_timeout * REPL_WAIT_MULTI;

    for (;;) {
        bool32 synced = OG_TRUE;
        uint16 i;

        cm_latch_s(&ogx->latch, session->id, OG_FALSE, NULL);
        for (i = 0; i < ogx->standby_num; i++) {
            lsnd_t *lsnd = ogx->lsnd[i];
            if (lsnd == NULL || lsnd->is_disable || lsnd->status < LSND_STATUS_QUERYING) {
                /*
                 * A stream that was expected to sync for this demote must not
                 * silently disappear: if its sender drops before the peer
                 * replay point has reached the local redo tail, the peer can
                 * never report a sync certificate and continuing would risk
                 * losing the unreplicated tail.  The last known peer rcy
                 * point survives a disconnect (lsnd_set_conn_error does not
                 * clear it), so a stream that synced before dropping is
                 * accepted, while one that never reached the tail fails the
                 * demote (the coordinator then rejects the handshake).
                 */
                if (lsnd != NULL && !lsnd->is_disable && lsnd->status < LSND_STATUS_QUERYING &&
                    lsnd->peer_rcy_point.lfn < kernel->redo_ctx.lfn) {
                    cm_unlatch(&ogx->latch, NULL);
                    OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] stream %u sender disconnected before sync "
                                   "(peer rcy lfn %llu < local lfn %llu), abort demote",
                                   i, (uint64)lsnd->peer_rcy_point.lfn, (uint64)kernel->redo_ctx.lfn);
                    return OG_ERROR;
                }
                continue;
            }
            if (lsnd->peer_rcy_point.lfn < kernel->redo_ctx.lfn) {
                synced = OG_FALSE;
                OG_LOG_DEBUG_INF("[CLUSTER SWITCHOVER] stream %u not synced: peer lfn=%llu local lfn=%llu",
                    i, (uint64)lsnd->peer_rcy_point.lfn, (uint64)kernel->redo_ctx.lfn);
                break;
            }
        }
        cm_unlatch(&ogx->latch, NULL);

        if (synced) {
            OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] local redo streams synced, lfn=%llu",
                (uint64)kernel->redo_ctx.lfn);
            return OG_SUCCESS;
        }
        if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= timeout) {
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] wait local stream sync timeout");
            return OG_ERROR;
        }
        cm_sleep(DTC_SWITCH_POLL_INTERVAL);
    }
}

/* --------------------------------------------------------------------- */
/*  Primary side: demote completion hook (called by srv_instance.c)      */
/* --------------------------------------------------------------------- */
void dtc_switch_notify_demote_done(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 self_id = kernel->id;
    bool32 is_coord = OG_FALSE;
    uint32 coord_inst;
    mes_message_head_t ack_head;
    msg_dtc_switch_demote_ack_t ack;

    if (!g_dtc_switch.demote_in_progress) {
        return;
    }

    cm_spin_lock(&g_dtc_switch.lock, NULL);
    g_dtc_switch.demoted_nodes |= ((uint64)1 << self_id);
    is_coord = g_dtc_switch.am_coordinator;
    coord_inst = g_dtc_switch.coordinator_inst;
    cm_spin_unlock(&g_dtc_switch.lock);

    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] node %u demote done, coordinator=%d", self_id, (int)is_coord);

    if (!is_coord) {
        mes_init_send_head(&ack_head, MES_CMD_DTC_SWITCH_DEMOTE_ACK,
            sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(bool32), OG_INVALID_ID32, self_id, (uint8)coord_inst,
            session->id, OG_INVALID_ID16);
        ack.node_id = self_id;
        ack.result = OG_TRUE;
        if (mes_send_data2(&ack_head, &ack.node_id) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] failed to send demote ack to coordinator %u", coord_inst);
        }
    }

    /* local demote is complete; release the state for future operations */
    dtc_switch_reset();
}

/* --------------------------------------------------------------------- */
/*  MES handlers                                                         */
/* --------------------------------------------------------------------- */
void dtc_switch_process_demote_req(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    mes_message_head_t head;
    msg_dtc_switch_demote_req_t *req;

    if (msg->head->size != sizeof(msg_dtc_switch_demote_req_t)) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] invalid demote req size %u", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    req = (msg_dtc_switch_demote_req_t *)msg->buffer;

    cm_spin_lock(&g_dtc_switch.lock, NULL);
    g_dtc_switch.epoch = req->epoch;
    g_dtc_switch.self_id = session->kernel->id;
    g_dtc_switch.expected_nodes = req->expected_nodes;
    g_dtc_switch.demoted_nodes = 0;
    g_dtc_switch.am_coordinator = OG_FALSE;
    g_dtc_switch.demote_in_progress = OG_TRUE;
    g_dtc_switch.coordinator_inst = msg->head->src_inst;
    g_dtc_switch.coordinator_rsn = msg->head->rsn;
    g_dtc_switch.coordinator_sid = msg->head->src_sid;
    cm_spin_unlock(&g_dtc_switch.lock);

    /* trigger the local demote through the existing server switch path */
    {
        switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request == SWITCH_REQ_NONE) {
            ctrl->request = SWITCH_REQ_DEMOTE;
        }
        cm_spin_unlock(&ctrl->lock);
    }
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] node %u received demote req from coordinator %u",
        session->kernel->id, msg->head->src_inst);

    mes_init_ack_head(msg->head, &head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] failed to ack demote req");
    }
}

void dtc_switch_process_demote_ack(void *sess, mes_message_t *msg)
{
    msg_dtc_switch_demote_ack_t *ack;

    if (msg->head->size != sizeof(msg_dtc_switch_demote_ack_t)) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] invalid demote ack size %u", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    ack = (msg_dtc_switch_demote_ack_t *)msg->buffer;

    cm_spin_lock(&g_dtc_switch.lock, NULL);
    g_dtc_switch.demoted_nodes |= ((uint64)1 << ack->node_id);
    cm_spin_unlock(&g_dtc_switch.lock);
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] peer node %u demote ack received", ack->node_id);
    mes_release_message_buf(msg->buffer);
}

void dtc_switch_process_promote_notify(void *sess, mes_message_t *msg)
{
    knl_session_t *session = (knl_session_t *)sess;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    mes_message_head_t head;

    if (msg->head->size != sizeof(msg_dtc_switch_promote_notify_t)) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] invalid promote notify size %u", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] node %u received promote notify, start cluster promote",
        session->kernel->id);
    if (cm_create_thread(db_promote_cluster_role, 0, NULL, &lrpl->promote_thread) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] follower failed to start promote thread");
    }

    mes_init_ack_head(msg->head, &head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), OG_INVALID_ID16);
    mes_release_message_buf(msg->buffer);
    if (mes_send_data(&head) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] failed to ack promote notify");
    }
}

/* --------------------------------------------------------------------- */
/*  Cross-cluster response path (lrcv thread -> command thread)          */
/* --------------------------------------------------------------------- */
void dtc_switch_set_resp(knl_session_t *session, rep_state_t state, uint64 demoted_nodes)
{
    uint32 i;

    cm_spin_lock(&g_dtc_switch.lock, NULL);
    g_dtc_switch.resp_state = state;
    g_dtc_switch.demoted_nodes = demoted_nodes;
    cm_spin_unlock(&g_dtc_switch.lock);

    /*
     * The response carries the bitmap of primary nodes that have finished
     * demoting: their redo streams are terminal.  Mark them so the replay
     * drain barrier stops gating the remaining streams on their frozen
     * frontiers, allowing the standby to drain and promote.
     */
    if (state == REP_STATE_PROMOTE_APPROVE) {
        for (i = 0; i < session->kernel->db.ctrl.core.node_count; i++) {
            if ((demoted_nodes & ((uint64)1 << i)) == 0) {
                /*
                 * A stream that was not part of the demoted set has no source
                 * in the new topology (the source cluster may run fewer nodes
                 * than the logical node_count).  Record it in the source-absent
                 * bitmap so the replay drain barrier does not gate the
                 * remaining streams on a stream that will never connect again.
                 */
                lrcv_context_t *unbound = lrcv_get_stream(session, i);
                if (unbound == NULL || !unbound->stream_bound) {
                    if (unbound != NULL) {
                        unbound->terminal = OG_TRUE;
                    }
                    session->kernel->lrcv_mgr.source_absent |= ((uint64)1 << i);
                    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] stream %u has no source in the new topology, "
                                   "marked absent", i);
                }
                continue;
            }
            lrcv_context_t *lrcv = lrcv_get_stream(session, i);
            if (lrcv != NULL) {
                lrcv->terminal = OG_TRUE;
                OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] stream %u marked terminal", i);
            } else {
                /*
                 * The stream may already have been torn down and cleared
                 * during the demote window (see srv_clear_lrcv_ctx), so the
                 * terminal flag on the pooled context is unreachable through
                 * lrcv_get_stream().  Record the node in the persistent
                 * source-absent bitmap so the drain barrier skips its frozen
                 * watermark; a later bind clears the bit.
                 */
                session->kernel->lrcv_mgr.source_absent |= ((uint64)1 << i);
                OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] stream %u context already cleared, marked absent", i);
            }
        }
    }
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] cross-cluster response: state=%d demoted=%llx",
        (int)state, demoted_nodes);
}

void dtc_switch_fill_resp(rep_cluster_switch_resp_t *resp)
{
    cm_spin_lock(&g_dtc_switch.lock, NULL);
    resp->demoted_nodes = g_dtc_switch.demoted_nodes;
    resp->epoch = g_dtc_switch.epoch;
    cm_spin_unlock(&g_dtc_switch.lock);
}

/* --------------------------------------------------------------------- */
/*  Command entries (standby cluster master only)                        */
/* --------------------------------------------------------------------- */
static status_t dtc_switch_common_check(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster switchover/failover can only be issued in OPEN status");
        return OG_ERROR;
    }
    if (db->terminate_lfn != OG_INVALID_LFN) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "switchover with terminated lfn");
        return OG_ERROR;
    }
    if (DB_IS_RAFT_ENABLED(kernel)) {
        OG_THROW_ERROR(ERR_RAFT_ENABLED);
        return OG_ERROR;
    }
    if (!DB_IS_PHYSICAL_STANDBY(db)) {
        OG_THROW_ERROR(ERR_DATABASE_ROLE, "cluster switchover/failover", "not in standby mode");
        return OG_ERROR;
    }
    if (!rc_is_master()) {
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
            "cluster switchover/failover must be issued on the standby cluster master");
        return OG_ERROR;
    }
    if (!dtc_switch_try_begin()) {
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "another cluster switch is in progress");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t dtc_alter_switchover(knl_session_t *session, knl_alterdb_def_t *def)
{
    lrcv_context_t *lrcv;
    date_t begin_time = g_timer()->now;
    status_t status;

    if (dtc_switch_common_check(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Gate A: all streams connected and ready */
    if (dtc_switch_gate_check(session) != OG_SUCCESS) {
        dtc_switch_reset();
        return OG_ERROR;
    }

    /* trigger the cross-cluster handshake over the chosen stream */
    lrcv = dtc_switch_pick_handshake_stream(session);
    if (lrcv == NULL) {
        dtc_switch_reset();
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "no connected redo stream for cluster switchover handshake");
        return OG_ERROR;
    }
    cm_spin_lock(&lrcv->lock, NULL);
    if (lrcv->session == NULL || (lrcv->status != LRCV_PREPARE && lrcv->status != LRCV_READY)) {
        cm_spin_unlock(&lrcv->lock);
        dtc_switch_reset();
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "could not issue cluster switchover when primary isn't connected");
        return OG_ERROR;
    }
    if (lrcv->state != REP_STATE_NORMAL) {
        cm_spin_unlock(&lrcv->lock);
        dtc_switch_reset();
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster switchover aborted by other request");
        return OG_ERROR;
    }
    lrcv->state = REP_STATE_CLUSTER_DEMOTE_REQUEST;
    cm_spin_unlock(&lrcv->lock);

    g_dtc_switch.state = DTC_SWITCH_DEMOTE_WAIT;
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] switchover started, waiting primary cluster demote");

    /* wait for the cross-cluster response */
    while (g_dtc_switch.resp_state == REP_STATE_NORMAL) {
        if (session->killed) {
            dtc_switch_reset();
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }
        if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= DTC_SWITCH_TIMEOUT_DEFAULT) {
            dtc_switch_reset();
            OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] wait primary demote response timeout");
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster switchover timeout waiting primary response");
            return OG_ERROR;
        }
        cm_sleep(DTC_SWITCH_POLL_INTERVAL);
    }

    if (g_dtc_switch.resp_state != REP_STATE_PROMOTE_APPROVE) {
        dtc_switch_reset();
        OG_LOG_RUN_ERR("[CLUSTER SWITCHOVER] primary rejected switchover, resp=%d",
            (int)g_dtc_switch.resp_state);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "cluster switchover rejected by primary");
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] primary cluster demoted, bitmap=%llx",
        g_dtc_switch.demoted_nodes);

    /* Gate B: drain the standby replay */
    g_dtc_switch.state = DTC_SWITCH_DRAIN_WAIT;
    status = dtc_switch_wait_drained(session, DTC_SWITCH_DRAIN_TIMEOUT);
    if (status != OG_SUCCESS) {
        dtc_switch_reset();
        return status;
    }

    /* promote the standby cluster */
    g_dtc_switch.state = DTC_SWITCH_PROMOTE;
    status = dtc_switch_promote(session);
    if (status != OG_SUCCESS) {
        dtc_switch_reset();
        return status;
    }

    dtc_switch_reset();
    OG_LOG_RUN_INF("[CLUSTER SWITCHOVER] switchover completed, running as primary");
    return OG_SUCCESS;
}

status_t dtc_alter_failover(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = session->kernel;
    database_t *db = &kernel->db;
    status_t status;

    if (dtc_switch_common_check(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (dtc_switch_any_stream_connected(session) && !def->force_failover) {
        dtc_switch_reset();
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
            "could not issue failover when not disconnected, please try force failover");
        return OG_ERROR;
    }

    if (def->force_failover) {
        /* close residual receiver connections; record RPO per stream */
        dtc_switch_record_rpo(session);
        lrcv_close(session);
        /*
         * Force failover accepts RPO: received-but-barrier-gated redo may not
         * be applied.  Clear the gate so the promote engine can finish.
         */
        kernel->lrpl_ctx.pending_gated_redo = OG_FALSE;
    }

    /* bump epoch to invalidate old primary streams (brain-split backstop) */
    db->ctrl.core.cluster_epoch++;
    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        dtc_switch_reset();
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failed to save cluster epoch before failover");
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[CLUSTER FAILOVER] failover started, epoch=%u", db->ctrl.core.cluster_epoch);

    g_dtc_switch.state = DTC_SWITCH_PROMOTE;
    status = dtc_switch_promote(session);
    if (status != OG_SUCCESS) {
        dtc_switch_reset();
        return status;
    }

    dtc_switch_reset();
    OG_LOG_RUN_INF("[CLUSTER FAILOVER] failover completed, running as primary, epoch=%u",
        db->ctrl.core.cluster_epoch);
    return OG_SUCCESS;
}
