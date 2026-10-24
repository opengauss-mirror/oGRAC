/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co., Ltd. All rights reserved.
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
 */

#ifndef DTC_TXN_HOT_H
#define DTC_TXN_HOT_H

#include "cm_atomic.h"
#include "knl_tran.h"
typedef struct st_remote_sga remote_sga_t;
typedef void (*dtc_txn_hot_send_awake_t)(knl_session_t *session, xid_t *xid, knl_scn_t scn, uint32 dst_inst,
    uint32 cmd);

#define DTC_TXN_HOT_MAGIC 0x544E4832U
#define DTC_TXN_HOT_LAYOUT_VER 4U
#define DTC_TXN_HOT_MAX_RETRY 32U

/*
 * Phase-C wait meta lives in the former padding of each hot slot:
 * - wait_mask: bit i set => instance i enrolled as waiter (UB visible)
 * - wake_seq: bumped on END publish so waiters can detect kick without MES WAIT_TXN
 */
typedef struct st_dtc_txn_hot {
    atomic_t seq;
    atomic_t scn;
    atomic_t pack;
    atomic_t end_lsn;
    atomic_t wait_mask;
    atomic32_t wake_seq;
    uint8 padding[20];
} dtc_txn_hot_t;

typedef struct st_dtc_txn_hot_hdr {
    uint32 magic;
    uint32 layout_ver;
    uint32 header_size;
    uint32 hot_slot_size;
    uint32 undo_segments;
    uint32 capacity_per_seg;
    uint32 txn_cap_per_inst;
    uint32 page_size;
    uint64 txn_hot_offset;
    uint64 region_size;
    uint64 layout_fingerprint;
    atomic_t ready;
} dtc_txn_hot_hdr_t;

typedef enum en_dtc_txn_hot_stat_type {
    DTC_TXN_HOT_STAT_INFO_HOT = 0,
    DTC_TXN_HOT_STAT_INFO_REMOTE,
    DTC_TXN_HOT_STAT_SNAPSHOT_HOT,
    DTC_TXN_HOT_STAT_SNAPSHOT_REMOTE,
    DTC_TXN_HOT_STAT_INFO_RESOLVE_FAIL,
    DTC_TXN_HOT_STAT_WAIT_END,         /* first hot read already END */
    DTC_TXN_HOT_STAT_WAIT_UB_WAKE,     /* ended after UB enroll / local sleep / kick */
    DTC_TXN_HOT_STAT_WAIT_MES_FALLBACK,/* hot unusable / reform -> MES WAIT_TXN */
    DTC_TXN_HOT_STAT_CEIL
} dtc_txn_hot_stat_type_t;

typedef struct st_dtc_txn_hot_stat {
    uint64 info_hot;
    uint64 info_remote;
    uint64 snapshot_hot;
    uint64 snapshot_remote;
    uint64 info_resolve_fail;
    uint64 wait_end;
    uint64 wait_ub_wake;
    uint64 wait_mes_fallback;
} dtc_txn_hot_stat_t;

/* Result of one Phase-C wait attempt (no MES WAIT_TXN inside). */
typedef enum en_dtc_txn_hot_ub_wait_result {
    DTC_TXN_HOT_UB_ENDED = 0,    /* txn END observed, skip MES */
    DTC_TXN_HOT_UB_PENDING = 1,  /* still ACTIVE; caller should retry UB path */
    DTC_TXN_HOT_UB_FALLBACK = 2  /* must use MES WAIT_TXN */
} dtc_txn_hot_ub_wait_result_t;

status_t dtc_txn_hot_region_init(remote_sga_t *remote_sga);
uint64 dtc_txn_hot_pool_layout_end(const remote_sga_t *sga, uint32 undo_segments, uint64 tran_buf_size);
void dtc_txn_hot_rebuild(knl_session_t *session, undo_set_t *undo_set, uint32 lseg_no, uint32 rseg_no);
void dtc_txn_hot_publish_item_locked(knl_session_t *session, tx_item_t *item, txn_t *txn, uint64 end_lsn);
void dtc_txn_hot_publish_item(knl_session_t *session, tx_item_t *item, txn_t *txn, uint64 end_lsn);
status_t dtc_get_txn_info_from_hot(knl_session_t *session, bool32 is_scan, xid_t xid,
    uint8 owner_inst, txn_info_t *txn_info);
status_t dtc_get_txn_snapshot_from_hot(knl_session_t *session, xmap_t xmap, uint8 owner_inst,
    txn_snapshot_t *snapshot);
bool32 dtc_txn_hot_enabled(knl_session_t *session);
void dtc_txn_hot_stat_inc(dtc_txn_hot_stat_type_t type);
void dtc_txn_hot_stat_get(dtc_txn_hot_stat_t *stat);

/*
 * Phase-C: enroll on owner wait_mask, sleep on local cond (AWAKE via kick or timeout),
 * re-read hot. Does not send MES WAIT_TXN.
 */
dtc_txn_hot_ub_wait_result_t dtc_txn_hot_ub_wait(knl_session_t *session, xid_t xid, uint8 owner);

/*
 * Owner side: after END published, take wait_mask and MES AWAKE enrolled instances.
 * send_func is typically dls_send_txn_msg with MES_CMD_AWAKE_TXN.
 */
void dtc_txn_hot_kick_ub_waiters(knl_session_t *session, xid_t *xid, knl_scn_t scn,
    dtc_txn_hot_send_awake_t send_func);

#endif
