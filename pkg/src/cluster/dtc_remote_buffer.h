/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
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
 * dtc_remote_buffer.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_remote_buffer.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_REMOTE_BUFFER_H
#define DTC_REMOTE_BUFFER_H

#include "cm_defs.h"
#include "cm_atomic.h"
#include "dtc_drc_util.h"
#include "knl_session.h"
#include "knl_context.h"
#include "srv_instance.h"
#include "dtc_reform.h"
#include "mes_func.h"
#include "dtc_drc_stat.h"
#include "dtc_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRC_MIN_SHM_SIZE (SIZE_M(512))
#define DRC_BASE_ADDR_0 0xA0000000000
#define DRC_BASE_ADDR_1 0xB0000000000

#define DRC_DIST_QUE_SIZE (SIZE_M(256))
#define DRC_DISK_LCK_SIZE (SIZE_G(10))  /* max lock region size */
#define DRC_REMOTE_BUF_OFFSET (uint64)0

#define DRC_NODE_FLUSH_LSN_SIZE align_to_128m(sizeof(atomic_t))

typedef struct st_remote_buf_context {
    buf_set_t buf_set[OG_MAX_BUF_POOL_NUM];
    uint32 buf_set_count;
    thread_lock_t buf_mutex;
} remote_buf_context_t;

typedef struct st_mes_remote_buf_mmap_bcast {
    mes_message_head_t head;
    uint32 node_id;
} mes_remote_buf_mmap_bcast_t;

typedef struct st_remote_sga {
    uint64 remote_total_pool_size;  // DTC_REMOTE_SGA_SIZE after align 128M
    uint64 remote_buf_alloc_size;   // data buf  remote_data_buf_size after align 4k size
    uint64 remote_lock_alloc_size;  // lock buf  remote_lock_size
    uint64 remote_pool_reserve_offset;
    char *remote_buf_addr[OG_MAX_INSTANCES]; /* allocated in UB shared memory */
    bool map_success[OG_MAX_INSTANCES];
    char *data_buf; /* each remote data buf is managed by master node. */
    char *lock_buf;
    char *node_flush_lsn;
} remote_sga_t;

static inline uint64 drc_get_dist_que_offset(const remote_sga_t *remote_sga)
{
    return DRC_REMOTE_BUF_OFFSET + remote_sga->remote_buf_alloc_size;
}

static inline uint64 drc_get_dist_lck_offset(const remote_sga_t *remote_sga)
{
    return drc_get_dist_que_offset(remote_sga) + DRC_DIST_QUE_SIZE;
}

static inline uint64 drc_get_node_flush_lsn_offset(const remote_sga_t *remote_sga)
{
    return drc_get_dist_lck_offset(remote_sga) + remote_sga->remote_lock_alloc_size;
}

#pragma pack(push, 1)
typedef struct st_remote_page_info {
    uint64 lock_ptr;
    uint64 head_lsn;
    uint16 file_id;  // file_identifier
    uint32 page_id;  // page_identifier
    uint8 claimed_owner;
    uint16 touch_number;
    uint16 ref_num;
    uint16 xlog_owner_node;  // last repair node
    uint8 xlog_owner_node_timeline_id[6];
    uint8 reserved[5];
    uint64 ckpt_flush_state;
} remote_page_info_t;

#pragma pack(pop)

#define GBP_CKPT_MARK_MASK (1ULL << 63)
#define GBP_CKPT_LSN_MASK  (~GBP_CKPT_MARK_MASK)

static inline uint64 gbp_ckpt_pack_state(bool32 is_marked, uint64 lsn)
{
    return (lsn & GBP_CKPT_LSN_MASK) | (is_marked ? GBP_CKPT_MARK_MASK : 0);
}

static inline bool32 gbp_ckpt_state_is_marked(uint64 state)
{
    return (bool32)((state & GBP_CKPT_MARK_MASK) != 0);
}

static inline uint64 gbp_ckpt_state_lsn(uint64 state)
{
    return (state & GBP_CKPT_LSN_MASK);
}

static inline uint64 gbp_ckpt_get_state(remote_page_info_t *page_info)
{
    return (uint64)cm_atomic_get((atomic_t *)&page_info->ckpt_flush_state);
}

static inline bool32 gbp_ckpt_cas_state(remote_page_info_t *page_info, uint64 old_state, uint64 new_state)
{
    return cm_atomic_cas((atomic_t *)&page_info->ckpt_flush_state, (int64)old_state, (int64)new_state);
}

static inline void gbp_ckpt_set_state(remote_page_info_t *page_info, uint64 state)
{
    (void)cm_atomic_set((atomic_t *)&page_info->ckpt_flush_state, (int64)state);
}

typedef enum buffer_type {
    DATA_TYPE,
    LOCK_TYPE,
    LOCK_QUEUE,
} buffer_type_t;

#define OFFSET_PAGE_ID offsetof(remote_page_info_t, page_id)
#define OFFSET_HEAD_LSN offsetof(remote_page_info_t, head_lsn)
#define OFFSET_TAIL_LSN sizeof(remote_page_info_t) + g_dtc->kernel->attr.page_size

static inline void remote_page_info_set_timeline_id(remote_page_info_t *info, uint64 timeline_id)
{
    timeline_id &= 0xFFFFFFFFFFFFULL;
    info->xlog_owner_node_timeline_id[0] = (uint8)(timeline_id);
    info->xlog_owner_node_timeline_id[1] = (uint8)(timeline_id >> 8);
    info->xlog_owner_node_timeline_id[2] = (uint8)(timeline_id >> 16);
    info->xlog_owner_node_timeline_id[3] = (uint8)(timeline_id >> 24);
    info->xlog_owner_node_timeline_id[4] = (uint8)(timeline_id >> 32);
    info->xlog_owner_node_timeline_id[5] = (uint8)(timeline_id >> 40);
}

static inline uint64 remote_page_info_get_timeline_id(const remote_page_info_t *info)
{
    return ((uint64)info->xlog_owner_node_timeline_id[0]) |
           ((uint64)info->xlog_owner_node_timeline_id[1] << 8) |
           ((uint64)info->xlog_owner_node_timeline_id[2] << 16) |
           ((uint64)info->xlog_owner_node_timeline_id[3] << 24) |
           ((uint64)info->xlog_owner_node_timeline_id[4] << 32) |
           ((uint64)info->xlog_owner_node_timeline_id[5] << 40);
}

static inline void drc_set_node_timeline_id(remote_sga_t *rsga, uint64 timeline_id)
{
    if (rsga->node_flush_lsn != NULL) {
        cm_atomic_set((atomic_t *)(rsga->node_flush_lsn + sizeof(atomic_t)), (int64)timeline_id);
    }
}

static inline uint64 drc_get_node_timeline_id(remote_sga_t *rsga, uint32 node_id)
{
    atomic_t *peer_timeline_id_ptr =
        (atomic_t *)(rsga->remote_buf_addr[node_id] + drc_get_node_flush_lsn_offset(rsga) + sizeof(atomic_t));
    return (uint64)cm_atomic_get(peer_timeline_id_ptr);
}

static inline void drc_set_node_flush_lsn(remote_sga_t *rsga, uint64 lsn)
{
    if (rsga->node_flush_lsn != NULL) {
        cm_atomic_set((atomic_t *)rsga->node_flush_lsn, (int64)lsn);
    }
}

static inline uint64 drc_get_node_flush_lsn(remote_sga_t *rsga, uint32 node_id)
{
    atomic_t *peer_flush_lsn_ptr = (atomic_t *)(rsga->remote_buf_addr[node_id] + drc_get_node_flush_lsn_offset(rsga));
    return (uint64)cm_atomic_get(peer_flush_lsn_ptr);
}

status_t drc_init_remote_buffer();
void broadcast_remote_buf_allocated();
EXTER_ATTACK void drc_process_remote_buf_mmap(void *sess, mes_message_t *msg);
status_t dtc_mmap_remote_data_buf(remote_sga_t *remote_sga, uint32 node_id);
status_t dtc_buf_try_load_from_gbp(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode);
status_t dtc_buf_try_store_to_gbp(knl_session_t *session, buf_ctrl_t *ctrl, uint64 curr_lsn);
status_t dtc_buf_check_local_page(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode, bool32 *is_load);
status_t dtc_buf_gbp_wait_reload_done(knl_session_t *session, buf_ctrl_t *ctrl);
static inline bool32 dtc_buf_gbp_reload_owned_by_session(knl_session_t *session, buf_ctrl_t *ctrl)
{
    return (bool32)(ctrl->gbp_reload_in_progress && ctrl->gbp_reload_sid == session->id);
}
void dtc_buf_gbp_hold(buf_ctrl_t *ctrl, latch_mode_t mode);
status_t dtc_buf_gbp_unhold(knl_session_t *session, buf_ctrl_t *ctrl, latch_mode_t mode);
bool32 dtc_buf_gbp_should_unlock_on_leave(knl_session_t *session, buf_ctrl_t *ctrl, uint32 stack_idx,
    latch_mode_t mode);
bool32 dtc_buf_session_owns_gbp_store_fence(knl_session_t *session, buf_ctrl_t *ctrl);

#ifdef __cplusplus
}
#endif
#endif
