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
 * dtc_switchover.h
 *
 * Cluster-level switchover/failover orchestration for N-to-M redo stream
 * replication between two oGRAC clusters.
 *
 * Design: reuse the per-node demote engine (srv_process_demote_request) and
 * the cluster promote engine (db_promote_cluster_role).  This module only
 * orchestrates: readiness gate, cross-cluster handshake, in-cluster demote
 * broadcast/ack aggregation, drain wait and post-promote cleanup.  It is
 * isolated from the single-node switchover path and from the storage-DR
 * (dbstor/DBS) role callback path.
 *
 * IDENTIFICATION
 * src/cluster/dtc_switchover.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_SWITCHOVER_H__
#define __DTC_SWITCHOVER_H__

#include "cm_defs.h"
#include "knl_session.h"
#include "db_defs.h"
#include "repl_msg.h"
#include "mes_type.h"
#include "mes_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_SWITCH_TIMEOUT_DEFAULT      180   /* seconds */
#define DTC_SWITCH_DRAIN_TIMEOUT        60    /* seconds */
#define DTC_SWITCH_PROMOTE_TIMEOUT      120   /* seconds */
#define DTC_SWITCH_POLL_INTERVAL        100

typedef enum en_dtc_switch_state {
    DTC_SWITCH_IDLE = 0,
    DTC_SWITCH_GATE_CHECK,
    DTC_SWITCH_DEMOTE_WAIT,
    DTC_SWITCH_DRAIN_WAIT,
    DTC_SWITCH_PROMOTE,
    DTC_SWITCH_DONE,
    DTC_SWITCH_ABORT,
} dtc_switch_state_t;

typedef struct st_dtc_switch_ctrl {
    spinlock_t lock;
    volatile dtc_switch_state_t state;
    uint32 epoch;
    uint32 self_id;                   /* local instance id during a cluster switch */
    uint64 expected_nodes;            /* primary cluster nodes expected to demote */
    volatile uint64 demoted_nodes;    /* primary nodes that completed demote */
    uint32 coordinator_inst;          /* primary coordinator instance id */
    uint32 coordinator_rsn;           /* primary coordinator MES rsn (for demote ack) */
    uint32 coordinator_sid;           /* primary coordinator MES src sid */
    volatile rep_state_t resp_state;  /* REP_STATE_PROMOTE_APPROVE / REJECTED ... */
    volatile bool32 demote_in_progress;  /* local node is doing a cluster demote */
    volatile bool32 am_coordinator;      /* local node is the primary-side coordinator */
} dtc_switch_ctrl_t;

/*
 * Command entries: called from db_alter_switchover / db_alter_failover when
 * the database is clustered.  Only the standby cluster master may run them.
 */
status_t dtc_alter_switchover(knl_session_t *session, knl_alterdb_def_t *def);
status_t dtc_alter_failover(knl_session_t *session, knl_alterdb_def_t *def);

/* ---- hooks called from other modules (isolation boundaries) ---- */

/* dtc_context.c: initialize the cluster switch state at DTC startup */
void dtc_switch_init(void);
/* srv_instance.c: is a cluster demote in progress on this node? */
bool32 dtc_switch_in_progress(void);
/* standby side: is the cluster switchover waiting for the primary demote response? */
bool32 dtc_switch_in_demote_wait(void);
/* srv_instance.c: is this node the primary-side demote coordinator? */
bool32 dtc_switch_am_coordinator(void);
/* srv_instance.c: called at the end of srv_process_demote_request */
void dtc_switch_notify_demote_done(knl_session_t *session);
/* srv_instance.c: coordinator waits for all other primary nodes' demote acks */
status_t dtc_switch_wait_peers_demoted(void);
/* srv_instance.c: wait until every active lsnd stream is caught up (cluster demote) */
status_t dtc_switch_wait_local_sync(knl_session_t *session);

/* repl_log_send.c: primary coordinator starts the in-cluster demote broadcast */
void dtc_switch_start_primary_demote(knl_session_t *session, uint32 epoch, uint64 expected_nodes);
/* repl_log_send.c: build the cluster switch response payload */
void dtc_switch_fill_resp(rep_cluster_switch_resp_t *resp);

/* repl_log_recv.c: lrcv thread reports the cross-cluster switch response */
void dtc_switch_set_resp(knl_session_t *session, rep_state_t state, uint64 demoted_nodes);

/* MES handlers (registered in dtc_context.c) */
void dtc_switch_process_demote_req(void *sess, mes_message_t *msg);
void dtc_switch_process_demote_ack(void *sess, mes_message_t *msg);
void dtc_switch_process_promote_notify(void *sess, mes_message_t *msg);

#ifdef __cplusplus
}
#endif
#endif
