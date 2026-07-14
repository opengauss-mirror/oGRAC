/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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
 * dtc_rbp_rt_aly.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_rbp_rt_aly.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DTC_RBP_RT_ALY_H__
#define __DTC_RBP_RT_ALY_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_device.h"
#include "knl_session.h"
#include "knl_log.h"
#include "dtc_recovery.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runtime DTC-RBP analysis is an optional accelerator for two-node partial
 * recovery. It analyzes peer redo during normal service, routes page events by
 * page hash to owner workers, and merges the owner local sets with recovery tail
 * analysis during failover.
 */
#define DTC_RBP_RT_BATCH_QUEUE_COUNT      16
#define DTC_RBP_RT_READ_BUF_SIZE         OG_MAX_BATCH_SIZE
#define DTC_RBP_RT_SLEEP_MS              10
#define DTC_RBP_RT_PRUNE_INTERVAL        1024
#define DTC_RBP_RT_LFN_POINT_COUNT       262144
#define DTC_RBP_RT_MAX_PARSE_WORKERS     PARAL_ANALYZE_THREAD_NUM
#define DTC_RBP_RT_MAX_OWNER_WORKERS     PARAL_ANALYZE_THREAD_NUM
#define DTC_RBP_RT_DEFAULT_PARSE_WORKERS 2
#define DTC_RBP_RT_DEFAULT_OWNER_WORKERS 4
#define DTC_RBP_RT_EVENT_CHUNK_SIZE      256
#define DTC_RBP_RT_EVENT_CHUNK_LIMIT     8192
#define DTC_RBP_RT_DRAIN_TIMEOUT_MS      30000
#define DTC_RBP_RT_ACTIVE_REBUILD_BUDGET 1024

typedef enum en_dtc_rbp_rt_status {
    DTC_RBP_RT_DISABLED = 0,
    DTC_RBP_RT_RUNNING,
    DTC_RBP_RT_FROZEN,
    DTC_RBP_RT_UNSAFE,
    DTC_RBP_RT_CLOSED,
} dtc_rbp_rt_status_t;

typedef enum en_dtc_rbp_rt_batch_state {
    DTC_RBP_RT_BATCH_FREE = 0,
    DTC_RBP_RT_BATCH_READY,
    DTC_RBP_RT_BATCH_WORKING,
    DTC_RBP_RT_BATCH_DONE,
} dtc_rbp_rt_batch_state_t;

typedef struct st_dtc_rbp_rt_batch_slot {
    aligned_buf_t buf;
    log_point_t begin_point;
    log_point_t end_point;
    uint32 node_id;
    uint32 block_size;
    uint32 size;
    uint64 seq;
    uint32 pending_chunks;
    bool8 parse_done;
    uint8 reserved[3];
    volatile uint32 state;
} dtc_rbp_rt_batch_slot_t;

typedef struct st_dtc_rbp_rt_lfn_point {
    uint64 lfn;
    log_point_t point;
    log_point_t head_point;
} dtc_rbp_rt_lfn_point_t;

typedef enum en_dtc_rbp_rt_event_type {
    DTC_RBP_RT_EVENT_ENTER_PAGE = 0,
    DTC_RBP_RT_EVENT_LEAVE_CHANGED,
} dtc_rbp_rt_event_type_t;

typedef struct st_dtc_rbp_rt_page_event {
    page_id_t page_id;
    uint64 lsn;
    uint64 batch_lfn;
    uint32 pcn;
    uint32 space_id;
    uint32 node_id;
    uint8 type;
    uint8 reserved[7];
} dtc_rbp_rt_page_event_t;

typedef struct st_dtc_rbp_rt_event_chunk {
    struct st_dtc_rbp_rt_event_chunk *next;
    uint32 owner_id;
    uint32 batch_idx;
    uint32 count;
    uint32 reserved;
    dtc_rbp_rt_page_event_t events[DTC_RBP_RT_EVENT_CHUNK_SIZE];
} dtc_rbp_rt_event_chunk_t;

typedef struct st_dtc_rbp_rt_event_queue {
    spinlock_t lock;
    dtc_rbp_rt_event_chunk_t *head;
    dtc_rbp_rt_event_chunk_t *tail;
    uint32 depth;
    uint32 peak_depth;
    uint64 pushed;
    uint64 popped;
} dtc_rbp_rt_event_queue_t;

typedef struct st_dtc_rbp_rt_worker_arg {
    knl_session_t *session;
    uint32 worker_id;
} dtc_rbp_rt_worker_arg_t;

typedef struct st_dtc_rbp_rt_aly_ctx {
    thread_t reader_thread;
    thread_t parser_threads[DTC_RBP_RT_MAX_PARSE_WORKERS];
    thread_t owner_threads[DTC_RBP_RT_MAX_OWNER_WORKERS];
    spinlock_t state_lock;

    uint32 peer_node;
    uint32 self_node;
    uint32 parse_worker_count;
    uint32 owner_worker_count;
    volatile bool32 started;
    volatile bool32 closing;
    volatile bool32 frozen;
    volatile bool32 unsafe;
    volatile bool32 has_gap;
    volatile bool32 reset_requested;
    volatile uint32 status;

    log_point_t begin_point;
    log_point_t curr_point;
    log_point_t safe_analyzed_point;
    log_point_t safe_analyzed_head_point;
    log_point_t peer_prune_point;
    log_point_t reset_point;
    log_point_t snapshot_safe_point;
    log_point_t snapshot_safe_head_point;
    log_point_t snapshot_next_point;
    uint64 rt_start_lfn;
    uint64 safe_seq;
    uint64 next_seq;
    uint64 commit_seq;
    uint64 unsafe_reason;
    uint64 last_prune_batch_count;

    uint64 analyzed_batches;
    uint64 analyzed_groups;
    uint64 analyzed_pages;
    uint64 pruned_items;
    uint64 pruned_touches;
    uint64 owner_prune_lfn[DTC_RBP_RT_MAX_OWNER_WORKERS];
    uint64 parsed_events;
    uint64 applied_events;
    uint64 queue_full_count;
    uint64 commit_full_count;
    uint64 tail_retry_count;
    uint32 outstanding_event_chunks;
    uint32 event_chunk_peak;

    knl_session_t *rt_session;
    knl_session_t *parser_sessions[DTC_RBP_RT_MAX_PARSE_WORKERS];
    knl_session_t *owner_sessions[DTC_RBP_RT_MAX_OWNER_WORKERS];
    int32 log_handle[OG_MAX_LOG_FILES];
    aligned_buf_t read_buf;
    uint64 batch_buf_size;
    dtc_rbp_rt_batch_slot_t batch_slots[DTC_RBP_RT_BATCH_QUEUE_COUNT];
    uint32 commit_idx[DTC_RBP_RT_BATCH_QUEUE_COUNT];
    dtc_rcy_atomic_list free_list;
    dtc_rcy_atomic_list used_list;
    atomic32_t running_parser_num;
    atomic32_t running_owner_num;

    dtc_rbp_rt_event_queue_t owner_queues[DTC_RBP_RT_MAX_OWNER_WORKERS];
    dtc_rcy_local_set_t rt_owner_rcy[DTC_RBP_RT_MAX_OWNER_WORKERS];
    dtc_rcy_local_set_t snapshot_owner_rcy[DTC_RBP_RT_MAX_OWNER_WORKERS];
    bool8 local_inited;
    bool8 snapshot_valid;
    bool8 reserved[6];

    dtc_rbp_rt_worker_arg_t parser_args[DTC_RBP_RT_MAX_PARSE_WORKERS];
    dtc_rbp_rt_worker_arg_t owner_args[DTC_RBP_RT_MAX_OWNER_WORKERS];
    dtc_rbp_rt_lfn_point_t *lfn_points;
    uint32 lfn_point_start;
    uint32 lfn_point_count;
    uint32 lfn_point_capacity;
} dtc_rbp_rt_aly_ctx_t;

status_t dtc_rbp_rt_aly_start(knl_session_t *session);
void dtc_rbp_rt_aly_close(knl_session_t *session);
void dtc_rbp_rt_aly_mark_unsafe(uint64 reason);
bool32 dtc_rbp_rt_aly_prepare_partial(knl_session_t *session, log_point_t *safe_point,
    log_point_t *safe_head_point, log_point_t *next_point);
status_t dtc_rbp_rt_aly_finish_partial(knl_session_t *session);
void dtc_rbp_rt_aly_abort_partial(knl_session_t *session);
bool32 dtc_rbp_rt_aly_try_build_partial(knl_session_t *session);

#ifdef __cplusplus
}
#endif
#endif
