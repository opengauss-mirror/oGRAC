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
 * dtc_remote_lock.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_remote_lock.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_REMOTE_LOCK_H
#define DTC_REMOTE_LOCK_H

#include "knl_session.h"
#include "knl_buffer.h"
#include "dtc_remote_buffer.h"
#include "ub_dist_comm_queue.h"
#include "ub_dist_lock.h"

typedef struct st_drc_gbp_diag_ctrl_info {
    uint8 load_status;
    uint8 lock_mode;
    bool32 is_in_gbp;
    bool32 has_shmem_meta;
} drc_gbp_diag_ctrl_info_t;

typedef enum en_drc_gbp_diag_kind {
    DRC_GBP_DIAG_STARTUP = 0,
    DRC_GBP_DIAG_DCS_NOT_READABLE,
    DRC_GBP_DIAG_TRY_LOCAL_OK,
    DRC_GBP_DIAG_IN_GBP_NO_META,
    DRC_GBP_DIAG_GBP_META_LOCK_BREAK,
    DRC_GBP_DIAG_TRY_REMOTE_OK,
    DRC_GBP_DIAG_TRY_REMOTE_FAIL,
    DRC_GBP_DIAG_FINISH_NEED_LOAD,
    DRC_GBP_DIAG_FINISH_UBSMEM_OFF,
    DRC_GBP_DIAG_FINISH_NO_META,
    DRC_GBP_DIAG_FINISH_GBP_CHECK,
    DRC_GBP_DIAG_FINISH_LOAD_FROM_GBP,
    DRC_GBP_DIAG_META_ASSIGNED,
    DRC_GBP_DIAG_CHECK_LOCAL_FAIL,
    DRC_GBP_DIAG_S_LOCK_OK,
    DRC_GBP_DIAG_S_LOCK_FAIL,
    DRC_GBP_DIAG_X_LOCK_OK,
    DRC_GBP_DIAG_X_LOCK_FAIL,
    DRC_GBP_DIAG_ASK_OWNER_GBP_FAIL,
    DRC_GBP_DIAG_KIND_COUNT
} drc_gbp_diag_kind_e;

typedef enum en_gbp_mig_skip_reason {
    GBP_MIG_SKIP_UBSMEM_OFF = 0,
    GBP_MIG_SKIP_NOT_CAN_CVT,
    GBP_MIG_SKIP_REQ_FAILED,
    GBP_MIG_SKIP_NOT_EXCLUSIVE,
    GBP_MIG_SKIP_ALREADY_OWNER,
    GBP_MIG_SKIP_WINDOW_NOT_ELAPSED,
    GBP_MIG_SKIP_BELOW_THRESHOLD,
    GBP_MIG_SKIP_WAITING,
    GBP_MIG_SKIP_REASON_COUNT
} gbp_mig_skip_reason_e;

#ifdef __cplusplus
extern "C" {
#endif

status_t drc_gbp_distribute_lock(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, latch_mode_t mode);
status_t drc_gbp_distribute_lock_for_store(knl_session_t *session, uint64 lock_ptr, page_id_t page_id);
status_t drc_gbp_distribute_lock_reenter(knl_session_t *session, uint64 lock_ptr, page_id_t page_id);
void drc_gbp_begin_page_store(knl_session_t *session, uint64 lock_ptr);
void drc_gbp_end_page_store(knl_session_t *session, uint64 lock_ptr);
status_t drc_gbp_distribute_unlock(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, latch_mode_t mode);

void ub_rw_lock_set_readonly(ub_rw_lock_t *lock, bool32 readonly, const char *phase);
bool32 ub_rw_lock_get_readonly(ub_rw_lock_t *lock);
void ub_rw_lock_begin_page_store(ub_rw_lock_t *lock);
void ub_rw_lock_end_page_store(ub_rw_lock_t *lock);
void ub_gbp_wait_readonly_fence(ub_rw_lock_t *lock);
ub_lock_result_t ub_gbp_x_lock_fence(ub_rw_lock_t *lock, const ub_lock_policy_t *policy,
    const ub_location_t *location);
ub_lock_result_t ub_gbp_s_lock_fence(ub_rw_lock_t *lock, const ub_lock_policy_t *policy,
    const ub_location_t *location);
ub_lock_result_t ub_rw_lock_x_lock_for_store(ub_rw_lock_t *lock, const ub_location_t *location);
ub_lock_result_t ub_rw_lock_x_lock_reenter(ub_rw_lock_t *lock, const ub_location_t *location);
uint64 ub_rw_lock_get_owner_node(ub_rw_lock_t *lock);
int32 ub_rw_lock_get_state(ub_rw_lock_t *lock);
bool32 ub_rw_lock_is_x_held_by_current_thread(ub_rw_lock_t *lock, uint8_t node_id, int32_t tid);
uint64 ub_rw_lock_peek_lock_word(const ub_rw_lock_t *lock);

typedef struct st_ub_gbp_lock_raw {
    int32 g_lock_word;
    uint32 g_waiters;
    uint64 word0;
    uint64 owner_x;
    uint64 owner_sx;
    uint64 reserve_owner;
    uint32 shared_bitmap;
    uint32 s_readers;
    uint8 owner_x_node;
    int32 owner_x_tid;
    uint8 reserve_node;
    char g_phase[12];
    uint64 word1;
    uint32 u32_off8;
    int32 st_le32;
    int32 decode_state;
    uint8 decode_node;
    int32 decode_tid;
    uint32 state_raw24;
    int32 write_waiters;
    bool32 readonly;
} ub_gbp_lock_raw_t;

void ub_gbp_lock_read_raw(const ub_rw_lock_t *lock, ub_gbp_lock_raw_t *raw);

/* libubs-atomic FIFO wait queue peek (USE_ATOMIC_LOCK=OFF only). */
typedef struct st_ub_gbp_wait_q_snap {
    uint32 head;
    uint32 tail;
    uint32 waiters;
    uint32 head_idx;
    uint32 head_seq;
    int32 head_mode;
    uint8 head_node;
    int32 head_tid;
    uint32 next_seq;
    int32 next_mode;
    uint8 next_node;
    int32 next_tid;
    bool32 valid;
} ub_gbp_wait_q_snap_t;

void ub_gbp_lock_read_wait_queue(const ub_rw_lock_t *lock, ub_gbp_wait_q_snap_t *snap);

void drc_gbp_lock_log_flow(const char *phase);
void drc_gbp_lock_probe_impl(const char *phase);
void drc_gbp_lock_log_dist(const char *op, page_id_t page_id, latch_mode_t mode, int32 ub_ret, bool32 force);
void drc_gbp_lock_log_runtime_op(const char *op, page_id_t page_id, latch_mode_t mode, int32 ub_ret);
void drc_gbp_log_migrate_skip(knl_session_t *session, page_id_t page_id, gbp_mig_skip_reason_e reason,
    uint64 owner_chg, uint32 threshold, uint64 elapsed_ms, uint32 timeout_ms);
void drc_gbp_log_migrate_trigger(knl_session_t *session, page_id_t page_id, uint64 owner_chg, uint32 threshold);
void drc_gbp_log_migrate_copy_done(knl_session_t *session, page_id_t page_id);
void drc_gbp_lock_diag(knl_session_t *session, page_id_t page_id, latch_mode_t mode, drc_gbp_diag_kind_e kind,
    drc_gbp_diag_ctrl_info_t ctrl_info, bool32 has_ctrl);

void drc_gbp_lock_diag_log_page(knl_session_t *session, uint64 lock_ptr, page_id_t page_id, const char *phase);
void drc_gbp_lock_log_fail_detail(knl_session_t *session, uint64 lock_ptr, page_id_t page_id,
    latch_mode_t mode, int32 ub_ret, const char *phase);

/*
 * GBP page access audit: correlate logical page_id, GBP meta slot, lock_ptr/slot and lock op.
 * Verbose logging requires _UB_GBP_LOCK_DEBUG=TRUE; meta/slot mismatches are always logged at WAR.
 */
void drc_gbp_page_access_log(knl_session_t *session, const char *op, buf_ctrl_t *ctrl,
    remote_page_info_t *meta, uint64 lock_ptr, latch_mode_t lock_mode);

void drc_gbp_lock_info_debug_snapshot(uint64 lock_ptr, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid);
int32 drc_gbp_lock_ptr_home_node(uint64 lock_ptr);
const char *drc_gbp_ub_ret_str(int32 ub_ret);
void drc_gbp_log_ask_owner_gbp_fail(knl_session_t *session, page_id_t page_id, status_t ret,
    uint8 master_id, uint8 gbp_owner, uint64 lock_ptr);
    
status_t init_lock_comm_queue();
status_t drc_dist_comm_coordinated_init(knl_session_t *session);
void drc_process_dist_comm_reset(void *sess, mes_message_t *msg);
void drc_process_dist_comm_init(void *sess, mes_message_t *msg);
void drc_process_dist_comm_sync(void *sess, mes_message_t *msg);
bool32 drc_lock_comm_queue_is_inited(void);
status_t drc_wait_lock_comm_queue_prereq(uint32 timeout_ms);
void drc_init_remote_lock(ub_rw_lock_t **ub_lock);
status_t drc_create_page_ub_lock(ub_rw_lock_t *lock);
status_t drc_gbp_ensure_lock_attached(knl_session_t *session, uint64 lock_ptr, page_id_t page_id);
void drc_ubturbo_on_comm_queue_ready(void);

#ifdef __cplusplus
}
#endif
#endif
