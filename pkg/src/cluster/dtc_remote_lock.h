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
#include "dtc_remote_buffer.h"
#include "ub_dist_comm_queue.h"
#include "ub_dist_lock.h"

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
ub_lock_result_t ub_rw_lock_x_lock_for_store(ub_rw_lock_t *lock, const ub_location_t *location);
ub_lock_result_t ub_rw_lock_x_lock_reenter(ub_rw_lock_t *lock, const ub_location_t *location);
uint64 ub_rw_lock_get_owner_node(ub_rw_lock_t *lock);
int32 ub_rw_lock_get_state(ub_rw_lock_t *lock);
bool32 ub_rw_lock_is_x_held_by_current_thread(ub_rw_lock_t *lock, uint8_t node_id, int32_t tid);

void drc_gbp_lock_info_debug_snapshot(uint64 lock_ptr, int32 *atomic_state, int32 *x_owner_node,
    int32 *write_waiters, int32 *owner_tid);
    
status_t init_lock_comm_queue();
void drc_init_remote_lock(ub_rw_lock_t **ub_lock, ub_lock_config_t *config, ub_location_t *creator);

#ifdef __cplusplus
}
#endif
#endif
