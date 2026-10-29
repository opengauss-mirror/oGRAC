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
#include <limits.h>
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

/*
 * GBP buf_set layout (128B-aligned page starts):
 *   [ meta×N ] + pad + [ page | tail_lsn | pad_slot ]×N + [ ctrl×N ] + [ bucket×... ]
 * tail_lsn remains immediately after each page; slot pad makes next page 128B-aligned.
 */
#define GBP_SLOT_ALIGN 128ULL
#define GBP_META_SIZE ((uint64)sizeof(remote_page_info_t))
#define GBP_PAGE_SLOT_SIZE(page_size) CM_CALC_ALIGN((uint64)(page_size) + sizeof(uint64), GBP_SLOT_ALIGN)

#define OFFSET_PAGE_ID offsetof(remote_page_info_t, page_id)
#define OFFSET_HEAD_LSN offsetof(remote_page_info_t, head_lsn)

/* Prefer gbp_tail_ptr_from_page(ctrl->shmem_page_addr, page_size). */
static inline uint64 *gbp_tail_ptr_from_page(const void *page, uint32 page_size)
{
    return (uint64 *)((char *)page + page_size);
}

static inline uint64 gbp_page_slot_size(uint32 page_size)
{
    return GBP_PAGE_SLOT_SIZE(page_size);
}

static inline uint32 gbp_calc_part_capacity(uint64 part_size, uint32 page_size)
{
    uint64 page_slot = gbp_page_slot_size(page_size);
    uint64 per = GBP_META_SIZE + page_slot + sizeof(buf_ctrl_t) + (uint64)BUCKET_TIMES * sizeof(buf_bucket_t);
    uint32 n;

    if (per == 0 || part_size < per) {
        return 0;
    }
    n = (uint32)(part_size / per);
    while (n > 0) {
        uint64 meta_bytes = (uint64)n * GBP_META_SIZE;
        uint64 page_off = CM_CALC_ALIGN(meta_bytes, GBP_SLOT_ALIGN);
        uint64 total = page_off + (uint64)n * page_slot + (uint64)n * sizeof(buf_ctrl_t) +
            (uint64)n * BUCKET_TIMES * sizeof(buf_bucket_t);
        if (total <= part_size) {
            return n;
        }
        n--;
    }
    return 0;
}

static inline remote_page_info_t *gbp_meta_at(const buf_set_t *set, uint32 id)
{
    return (remote_page_info_t *)(set->meta_buf + (uint64)id * GBP_META_SIZE);
}

static inline page_head_t *gbp_page_at(const buf_set_t *set, uint32 id, uint32 page_size)
{
    return (page_head_t *)(set->page_buf + (uint64)id * gbp_page_slot_size(page_size));
}

static inline uint64 *gbp_tail_at(const buf_set_t *set, uint32 id, uint32 page_size)
{
    return gbp_tail_ptr_from_page(gbp_page_at(set, id, page_size), page_size);
}

static inline uint32 gbp_slot_from_meta(const buf_set_t *set, const remote_page_info_t *meta)
{
    return (uint32)(((const char *)meta - set->meta_buf) / GBP_META_SIZE);
}

static inline page_head_t *gbp_page_from_meta(const buf_set_t *set, remote_page_info_t *meta, uint32 page_size)
{
    return gbp_page_at(set, gbp_slot_from_meta(set, meta), page_size);
}

static inline uint64 *gbp_tail_from_meta(const buf_set_t *set, remote_page_info_t *meta, uint32 page_size)
{
    return gbp_tail_at(set, gbp_slot_from_meta(set, meta), page_size);
}

/* Resolve meta/page from pool base + meta_off (MES path). */
status_t gbp_resolve_from_meta_off(char *pool_base, uint64 meta_off, remote_page_info_t **meta_out,
    page_head_t **page_out);

/* Local GBP: derive meta from page address (page is in local buf_set page region). */
status_t gbp_meta_from_page_local(page_head_t *page, remote_page_info_t **meta_out);

/* Local GBP: derive page from meta address. */
status_t gbp_page_from_meta_local(remote_page_info_t *meta, page_head_t **page_out);

static inline void remote_page_info_set_timeline_id(remote_page_info_t *info, uint64 timeline_id)
{
    timeline_id &= 0xFFFFFFFFFFFFULL;
    for (uint32 i = 0; i < sizeof(info->xlog_owner_node_timeline_id); i++) {
        info->xlog_owner_node_timeline_id[i] = (uint8)(timeline_id >> (i * CHAR_BIT));
    }
}

static inline uint64 remote_page_info_get_timeline_id(const remote_page_info_t *info)
{
    uint64 timeline_id = 0;
    for (uint32 i = 0; i < sizeof(info->xlog_owner_node_timeline_id); i++) {
        timeline_id |= ((uint64)info->xlog_owner_node_timeline_id[i]) << (i * CHAR_BIT);
    }
    return timeline_id;
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
void dtc_buf_free_gbp_copy_temp(knl_session_t *session);
status_t dtc_buf_try_store_to_gbp(knl_session_t *session, buf_ctrl_t *ctrl, uint64 curr_lsn);
/* UB-stats: LBP->GBP raw memcpy latency by kind (meta / page / tail lsn). */
typedef enum en_ub_gbp_store_copy_kind {
    UB_GBP_STORE_COPY_META = 0,
    UB_GBP_STORE_COPY_PAGE,
    UB_GBP_STORE_COPY_TAIL_LSN
} ub_gbp_store_copy_kind_t;
void dtc_buf_stat_gbp_store_copy(knl_session_t *session, ub_gbp_store_copy_kind_t kind, uint64 copy_us);
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
