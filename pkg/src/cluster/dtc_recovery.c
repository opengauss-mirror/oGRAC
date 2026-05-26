/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
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
 * dtc_recovery.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_recovery.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "knl_recovery.h"
#include "knl_rbp.h"
#include "dtc_database.h"
#include "dtc_rbp_rt_aly.h"
#include "dtc_drc.h"
#include "dtc_reform.h"
#include "cm_dbs_intf.h"
#include "cm_dbs_ulog.h"
#include "dirent.h"
#include "knl_space_log.h"
#include "knl_map.h"
#include "rcr_btree.h"
#include "knl_create_space.h"
#include "knl_buffer.h"
#include "knl_page.h"
#include "knl_undo.h"
#include "knl_punch_space.h"
#include "cm_io_record.h"
#include "dtc_backup.h"

dtc_rcy_analyze_paral_node_t g_analyze_paral_mgr;
dtc_rcy_replay_paral_node_t g_replay_paral_mgr = { 0 };
page_stack_t g_dtc_rcy_page_id_stack;

#define DTC_RCY_ANALYZE_DIAG_INTERVAL          100000ULL
#define DTC_RCY_ANALYZE_PROGRESS_INTERVAL      10000ULL
#define DTC_RCY_ANALYZE_WORKER_IDLE_INTERVAL   10000ULL
#define DTC_RCY_READ_WAIT_DIAG_INTERVAL        100000ULL
#define DTC_RCY_ANALYZE_SLOW_US                1000000ULL
#define DTC_RCY_ANALYZE_GROUP_SLOW_US          20000ULL
#define DTC_RCY_ANALYZE_RECORD_SLOW_US         10000ULL
#define DTC_RCY_ANALYZE_PARTIAL_SLOW_US        10000ULL
#define DTC_RCY_ANALYZE_ENTRY_SLOW_US          5000ULL
#define DTC_RCY_ANALYZE_GROUP_DIAG_INTERVAL_US MICROSECS_PER_SECOND

/*
 * Hot-path analysis diagnostics: 1 enables per-entry/per-record cm_now() timing (debug only).
 * Production partial recovery should keep 0 and use counts-only mode in analyze workers.
 * Must be 0/1 (not OG_TRUE/OG_FALSE) because #if requires integer preprocessor constants.
 */
#define DTC_RCY_ANALYZE_HOT_DIAG               0

/*
 * Inflight analyze stage tracking and progress/read-buffer diag logs. Production keep 0.
 */
#define DTC_RCY_ANALYZE_INFLIGHT_DIAG          0

/*
 * Paral replay per-group timing and end-of-replay timing summaries. Production keep 0.
 * Batch-level wall time for slow replay batch is always kept.
 */
#define DTC_RCY_REPLAY_HOT_DIAG                0

#define DTC_RCY_ANALYZE_STAGE_IDLE             0U
#define DTC_RCY_ANALYZE_STAGE_MAIN_COPY        1U
#define DTC_RCY_ANALYZE_STAGE_MAIN_PUSH_USED   2U
#define DTC_RCY_ANALYZE_STAGE_MAIN_FETCH_NEXT  3U
#define DTC_RCY_ANALYZE_STAGE_WORKER_BATCH     4U
#define DTC_RCY_ANALYZE_STAGE_WORKER_GROUP     5U

static volatile uint32 g_dtc_rcy_analyze_main_stage = DTC_RCY_ANALYZE_STAGE_IDLE;
static volatile uint32 g_dtc_rcy_analyze_main_idx = OG_INVALID_ID32;
static volatile uint32 g_dtc_rcy_analyze_main_node = OG_INVALID_ID32;
static volatile uint32 g_dtc_rcy_analyze_main_space = 0;
static volatile uint64 g_dtc_rcy_analyze_main_lfn = 0;
static volatile uint64 g_dtc_rcy_analyze_main_lsn = 0;
static volatile date_t g_dtc_rcy_analyze_main_start = 0;

static volatile uint32 g_dtc_rcy_analyze_worker_stage[PARAL_ANALYZE_THREAD_NUM];
static volatile uint32 g_dtc_rcy_analyze_worker_idx[PARAL_ANALYZE_THREAD_NUM];
static volatile uint32 g_dtc_rcy_analyze_worker_node[PARAL_ANALYZE_THREAD_NUM];
static volatile uint32 g_dtc_rcy_analyze_worker_space[PARAL_ANALYZE_THREAD_NUM];
static volatile uint32 g_dtc_rcy_analyze_worker_rmid[PARAL_ANALYZE_THREAD_NUM];
static volatile uint64 g_dtc_rcy_analyze_worker_lfn[PARAL_ANALYZE_THREAD_NUM];
static volatile uint64 g_dtc_rcy_analyze_worker_lsn[PARAL_ANALYZE_THREAD_NUM];
static volatile uint64 g_dtc_rcy_analyze_worker_group_lsn[PARAL_ANALYZE_THREAD_NUM];
static volatile date_t g_dtc_rcy_analyze_worker_start[PARAL_ANALYZE_THREAD_NUM];

static void dtc_rcy_local_reset_active_chains(dtc_rcy_local_set_t *local);
static void dtc_rcy_local_append_active_shard_chain(dtc_rcy_local_set_t *local, rcy_set_item_t *item);

#define DTC_RCY_DIAG_INC(diag, counts, field) \
    do {                                      \
        if ((diag) != NULL) {                 \
            (diag)->field++;                  \
        } else if ((counts) != NULL) {        \
            (counts)->field++;                \
        }                                     \
    } while (0)

typedef struct st_dtc_rcy_analysis_worker_stat {
    uint64 groups;
    uint64 entries;
    uint64 record_calls;
    uint64 record_new;
    uint64 record_hit;
    uint64 partial_calls;
    uint64 slow_groups;
    uint64 max_group_us;
    uint64 group_us;
    uint64 record_us;
    uint64 partial_us;
    uint64 lock_us;
    uint64 alloc_us;
    uint64 drc_us;
} dtc_rcy_analysis_worker_stat_t;

typedef struct st_dtc_rcy_fetch_diag_stat {
    uint64 fetch_calls;
    uint64 fetch_ok;
    uint64 node_scan_iters;
    uint64 validate_calls;
    uint64 checksum_calls;
    uint64 release_slot_count;
    uint64 ring_wait_us;
    uint64 update_batch_us;
    uint64 validate_us;
    uint64 checksum_us;
    uint64 lfn_map_us;
    uint64 commit_us;
    uint64 rbp_jump_us;
    uint64 node_scan_us;
} dtc_rcy_fetch_diag_stat_t;

typedef struct st_dtc_rcy_analysis_main_stat {
    uint64 fetch_us;
    uint64 copy_us;
    uint64 push_used_us;
    uint64 wait_free_us;
    dtc_rcy_fetch_diag_stat_t fetch_diag;
} dtc_rcy_analysis_main_stat_t;

typedef struct st_dtc_rcy_local_finalize_stat {
    uint64 merge_us;
    uint64 merge_rcy_us;
    uint64 merge_partial_us;
    uint64 merge_rcy_us_sum;
    uint64 merge_partial_us_sum;
    uint64 merge_space_us;
    uint64 materialize_us;
    uint64 materialize_init_us;
    uint64 finalize_us;
    uint64 local_items_scanned;
    uint64 global_items_after;
    uint64 merge_insert_new;
    uint64 merge_update_hit;
    uint64 merge_touch_overflow;
    uint64 merge_scan_total;
    uint64 merge_scan_skipped;
    uint64 rcy_items_scanned;
    uint64 partial_items_created;
    uint64 partial_touch_overflow;
    uint64 partial_bucket_lock_us;
    uint64 partial_global_lock_us;
    uint8 merge_fused;
    uint8 reserved[7];
} dtc_rcy_local_finalize_stat_t;

typedef struct st_dtc_rcy_merge_shard_stat {
    uint64 merge_rcy_us;
    uint64 merge_partial_us;
    uint64 merge_scan_total;
    uint64 merge_scan_skipped;
    uint64 merge_insert_new;
    uint64 merge_update_hit;
    uint64 merge_touch_overflow;
    uint64 rcy_items_scanned;
    uint64 partial_items_created;
    uint64 partial_touch_overflow;
    uint64 partial_bucket_lock_us;
    uint64 partial_global_lock_us;
} dtc_rcy_merge_shard_stat_t;

typedef struct st_dtc_rcy_merge_shard_ctx {
    uint32 shard_id;
    rcy_set_item_pool_t *item_pools;
    rcy_set_item_pool_t *curr_item_pools;
    rbp_partial_item_pool_t *partial_item_pools;
    rbp_partial_item_pool_t *curr_partial_item_pool;
    uint64 partial_item_count;
    dtc_rcy_merge_shard_stat_t stat;
} dtc_rcy_merge_shard_ctx_t;

typedef struct st_dtc_rcy_merge_shard_worker_arg {
    knl_session_t *session;
    uint32 shard_id;
    rcy_set_t *rcy_set;
    rbp_partial_context_t *partial_ctx;
    dtc_rcy_merge_shard_ctx_t *shard_ctx;
    dtc_rcy_local_set_t *locals;
    uint32 local_count;
    dtc_rcy_local_item_filter_t filter;
    void *filter_arg;
    bool32 use_active;
    status_t ret;
} dtc_rcy_merge_shard_worker_arg_t;

typedef struct st_dtc_rcy_compact_shard_worker_arg {
    uint32 shard_id;
    uint32 bucket_count;
    dtc_rcy_local_set_t *locals;
    uint32 local_count;
    dtc_rcy_local_item_filter_t filter;
    void *filter_arg;
    dtc_rcy_local_set_t *compact_local;
    uint64 unique_count;
    uint64 duplicate_count;
    uint64 compact_us;
    dtc_rcy_local_finalize_stat_t stat;
    status_t ret;
} dtc_rcy_compact_shard_worker_arg_t;

#define DTC_RCY_REPLAY_BATCH_SLOW_US (5 * MICROSECS_PER_SECOND)
#define DTC_RCY_REPLAY_BATCH_NOW() (g_timer()->now)
#if DTC_RCY_REPLAY_HOT_DIAG
#define DTC_RCY_REPLAY_DIAG_NOW() (g_timer()->now)
#else
#define DTC_RCY_REPLAY_DIAG_NOW() 0
#endif

/* Main-thread stage totals: always sampled for default RUN summary (one cm_now per batch step). */
#define DTC_RCY_ANALYZE_MAIN_STEP_BEGIN(var)       ((var) = cm_now())
#define DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(var, acc)  ((acc) += (uint64)(cm_now() - (var)))

/* Active only during paral analyze main loop; dtc_rcy_fetch_log_batch/update_batch accumulate here. */
static dtc_rcy_fetch_diag_stat_t *g_dtc_rcy_fetch_diag_active = NULL;

#define DTC_RCY_FETCH_DIAG_ACCUM(field, begin)                                         \
    do {                                                                               \
        if (g_dtc_rcy_fetch_diag_active != NULL) {                                     \
            g_dtc_rcy_fetch_diag_active->field += (uint64)(cm_now() - (begin));        \
        }                                                                              \
    } while (0)

static void dtc_rcy_fetch_diag_inc_slot_release(void)
{
    if (g_dtc_rcy_fetch_diag_active != NULL) {
        g_dtc_rcy_fetch_diag_active->release_slot_count++;
    }
}

static void dtc_rcy_log_fetch_diag_summary(const dtc_rcy_fetch_diag_stat_t *diag, uint64 fetch_us_total)
{
    uint64 batches_per_slot_x1000 = 0;
    uint64 accounted_us;
    uint64 other_us;

    if (diag == NULL) {
        return;
    }
    if (diag->release_slot_count > 0) {
        batches_per_slot_x1000 = diag->fetch_ok * 1000ULL / diag->release_slot_count;
    } else if (diag->fetch_ok > 0) {
        batches_per_slot_x1000 = diag->fetch_ok * 1000ULL;
    }
    /* validate/checksum/ring_wait/update_batch are sub-spans of node_scan_us; lfn_map_us is a sub-span of commit_us. */
    accounted_us = diag->rbp_jump_us + diag->node_scan_us + diag->commit_us;
    other_us = (fetch_us_total > accounted_us) ? (fetch_us_total - accounted_us) : 0;
    OG_LOG_RUN_INF("[DTC RCY][analysis fetch breakdown] fetch_us_total=%llu accounted_us=%llu other_us=%llu "
                   "fetch_calls=%llu fetch_ok=%llu ring_wait_us=%llu update_batch_us=%llu validate_us=%llu "
                   "checksum_us=%llu lfn_map_us=%llu commit_us=%llu rbp_jump_us=%llu node_scan_us=%llu "
                   "node_scan_iters=%llu validate_calls=%llu checksum_calls=%llu release_slot_count=%llu "
                   "batches_per_slot_x1000=%llu",
                   fetch_us_total, accounted_us, other_us, diag->fetch_calls, diag->fetch_ok, diag->ring_wait_us,
                   diag->update_batch_us, diag->validate_us, diag->checksum_us, diag->lfn_map_us, diag->commit_us,
                   diag->rbp_jump_us, diag->node_scan_us, diag->node_scan_iters, diag->validate_calls,
                   diag->checksum_calls, diag->release_slot_count, batches_per_slot_x1000);
}

typedef struct st_dtc_rcy_replay_batch_diag {
    uint64 batch_count;
    uint64 group_count;
    uint64 enter_page_count;
    uint64 normal_group_count;
    uint64 logic_group_count;
    uint64 pitr_end_count;
    uint64 fetch_group_us;
    uint64 pitr_check_us;
    uint64 add_pages_us;
    uint64 group_bookkeeping_us;
    uint64 normal_prepare_us;
    uint64 add_bucket_us;
    uint64 logic_group_us;
    uint64 update_lsn_us;
    uint64 debug_log_us;
    uint64 dec_group_us;
    uint64 max_batch_us;
    uint64 max_batch_lfn;
    uint64 max_batch_lsn;
    uint64 max_batch_groups;
    uint64 max_batch_enter_pages;
    uint64 max_batch_logic_groups;
    uint32 max_batch_idx;
    uint32 max_batch_node_idx;
    uint32 max_batch_space_size;
} dtc_rcy_replay_batch_diag_t;

static bool32 dtc_rcy_rbp_window_usable(knl_session_t *session, rbp_read_ckpt_resp_t *resp);
static status_t dtc_rcy_try_delayed_rbp_jump(knl_session_t *session);
static status_t dtc_rcy_rbp_prepare_partial(knl_session_t *session);
static bool32 dtc_rcy_rbp_tail_replay_active(knl_session_t *session, dtc_rcy_context_t *dtc_rcy);
static void dtc_rcy_rbp_clear_lfn_point_maps(dtc_rcy_context_t *dtc_rcy);
static void dtc_rcy_rbp_reset_lfn_point_maps(dtc_rcy_context_t *dtc_rcy);
static status_t dtc_rcy_rbp_record_lfn_point(knl_session_t *session, uint32 node_id, log_batch_t *batch,
    log_point_t *point);
static rbp_partial_item_t *dtc_rcy_rbp_partial_find_locked(rbp_partial_bucket_t *bucket, page_id_t page_id);
static rbp_partial_item_t *dtc_rcy_rbp_partial_alloc_item(rbp_partial_context_t *ctx,
    dtc_rcy_analysis_group_diag_t *diag);
static rbp_partial_item_pool_t *dtc_rcy_rbp_partial_alloc_pool(void);
static bool32 dtc_rcy_rbp_partial_disable_jump_locked(uint32 node_id);
static void dtc_rcy_rbp_partial_disable_jump(uint32 node_id, rbp_partial_item_t *item);
static void dtc_record_space_id(uint32 space_id);
static status_t dtc_rcy_try_alloc_itempool(rcy_set_t *rcy_set, rcy_set_item_pool_t *old_pool);
static void dtc_rcy_local_sets_clear_all(void);
static status_t dtc_rcy_rbp_partial_alloc_side_table(rbp_partial_context_t *ctx);
static void dtc_rcy_rbp_partial_reset_analyze_state(knl_session_t *session);
static status_t dtc_rcy_runtime_reset_result(knl_session_t *session);
static status_t dtc_rcy_analyze_finalize_local(knl_session_t *session,
    const dtc_rcy_analysis_main_stat_t *main_stat);
static status_t dtc_rcy_analyze_batches_paral(knl_session_t *session);
#if DTC_RCY_USE_LEGACY_FINALIZE
static uint64 dtc_rcy_count_global_rcy_pool_items(const rcy_set_t *rcy_set);
#endif
static status_t dtc_rcy_merge_local_rcy_sets_sharded(knl_session_t *session, dtc_rcy_local_set_t *locals,
    uint32 local_count, dtc_rcy_local_item_filter_t filter, void *filter_arg, bool32 use_active,
    dtc_rcy_local_finalize_stat_t *stat);
static void dtc_rcy_rbp_partial_materialize_apply_overflow(rbp_partial_context_t *ctx, rbp_partial_item_t *item,
    uint64 overflow_bitmap, bool32 overflow_before, dtc_rcy_local_finalize_stat_t *stat);
static void dtc_rcy_rbp_partial_materialize_merge_existing(rbp_partial_item_t *item, rcy_set_item_t *rcy_item,
    rbp_partial_context_t *ctx, dtc_rcy_local_finalize_stat_t *stat);

typedef struct {
    bool32 found;
    uint32 blk_size;
    uint64 write_pos;
    uint64 ctrl_size;
    uint64 max_blk_by_write_pos;
    uint64 read_offset;
    bool32 offset_gt_write_pos;
    bool32 use_logical_file_size;
    char file_name[OG_FILE_NAME_BUFFER_SIZE];
} dtc_rcy_point_bounds_t;

static bool32 g_rbp_root_first_cursor_fly[OG_MAX_INSTANCES];

static bool32 dtc_rcy_get_point_bounds(knl_session_t *session, uint32 inst_node_id, const log_point_t *pt,
    dtc_rcy_point_bounds_t *bounds);
static void dtc_rcy_rbp_log_root_cause(knl_session_t *session, uint32 inst_node_id, const char *tag,
    const char *reason, const log_point_t *cursor, const log_batch_t *batch, const dtc_rcy_point_bounds_t *bounds,
    uint32 blk_before, uint32 blk_after);
static void dtc_rcy_rbp_check_point_root(knl_session_t *session, uint32 inst_node_id, const char *tag,
    const char *reason, const log_point_t *cursor, const log_batch_t *batch, uint32 blk_before, uint32 blk_after);
static void dtc_rcy_rbp_check_cursor_fly_first(knl_session_t *session, uint32 inst_node_id, const char *tag,
    const char *reason, const log_point_t *cursor, const log_batch_t *batch, uint32 blk_before, uint32 blk_after);
static void dtc_rcy_rbp_reset_root_diag(uint32 inst_node_id);

static inline log_point_t dtc_rcy_make_batch_end_point(log_batch_t *batch, uint32 block_size)
{
    log_point_t point = batch->head.point;

    point.lsn = batch->lsn;
    if (block_size != 0) {
        point.block_id += batch->space_size / block_size;
    }
    return point;
}

log_batch_t *dtc_rcy_get_curr_batch(dtc_rcy_context_t *dtc_rcy, uint32 idx, uint8 index)
{
    return ((log_batch_t *)((dtc_rcy)->rcy_nodes[(idx)].read_buf[(index)].aligned_buf +
                            (dtc_rcy)->rcy_nodes[(idx)].read_pos[(index)]));
}

void dtc_rcy_inc_need_analysis_leave_page_cnt(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->need_analysis_leave_page_cnt++;
    }
}

void dtc_rcy_dec_need_analysis_leave_page_cnt(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->need_analysis_leave_page_cnt--;
    }
}

void dtc_rcy_reset_need_analysis_leave_page_cnt(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->need_analysis_leave_page_cnt = 0;
    }
}

bool8 dtc_rcy_is_need_analysis_leave_page(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        return (dtc_rcy->need_analysis_leave_page_cnt > 0);
    }
    return OG_FALSE;
}

bool8 dtc_rcy_set_pitr_end_analysis(bool32 recover_flag)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->is_end_restore_recover = OG_TRUE;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool8 dtc_rcy_check_is_end_restore_recovery(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    return dtc_rcy->is_end_restore_recover;
}

bool8 dtc_rcy_set_pitr_end_replay(bool32 recover_flag, uint64 lsn)
{
    if (recover_flag) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        if (lsn >= dtc_rcy->end_lsn_restore_recovery) {
            dtc_rcy->is_end_restore_recover = OG_TRUE;
            return OG_TRUE;
        }
        return OG_FALSE;
    }
    return OG_FALSE;
}

static inline uint32 dtc_rcy_bucket_hash(page_id_t page_id, uint32 range)
{
    /* after mod range, the result is less than 0xffffffff */
    return (HASH_SEED * page_id.page + page_id.file) * HASH_SEED % range;
}

rcy_set_item_t *dtc_rcy_get_item(rcy_set_bucket_t *bucket, page_id_t page_id)
{
    rcy_set_item_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }

        item = item->next_item;
    }

    return NULL;
}

static inline void dtc_rcy_add_to_bucket(rcy_set_bucket_t *bucket, rcy_set_item_t *item)
{
    item->next_item = bucket->first;
    bucket->first = item;
    bucket->count++;
}

static inline void reset_read_buffer()
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    for (int i = 0; i < dtc_rcy->node_count; ++i) {
        dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[i];
        for (int j = 0; j < read_buf_size; ++j) {
            rcy_node->read_buf_ready[j] = OG_FALSE;
            rcy_node->write_pos[j] = 0;
            rcy_node->read_pos[j] = 0;
            rcy_node->read_size[j] = OG_INVALID_ID32;
            rcy_node->not_finished[j] = OG_TRUE;
        }
        rcy_node->read_buf_read_index = 0;
        rcy_node->read_buf_write_index = 0;
    }
}

static status_t close_read_log_proc(thread_t *read_log_thread, knl_session_t *session)
{
    OG_LOG_RUN_INF("[DTC RCY] start close "
                   "rcy read log thread, closed = %d result = %d",
                   read_log_thread->closed, read_log_thread->result);
    read_log_thread->closed = OG_TRUE;
    uint32 time_out = OG_DTC_RCY_NODE_READ_BUF_TIMEOUT;
    for (;;) {
        if (read_log_thread->result == OG_FALSE) {
            cm_sleep(OG_DTC_RCY_NODE_READ_BUF_SLEEP_TIME);
            time_out -= OG_DTC_RCY_NODE_READ_BUF_SLEEP_TIME;
            if (time_out <= 0) {
                OG_LOG_RUN_WAR("[DTC RCY] dtc rcy close read log proc time out");
                time_out = OG_DTC_RCY_NODE_READ_BUF_TIMEOUT;
            }
        } else {
            break;
        }
    }
    reset_read_buffer();
    g_knl_callback.release_knl_session(session);
    cm_close_thread(read_log_thread);
    OG_LOG_RUN_INF("[DTC RCY] finish close read log proc");
    return OG_SUCCESS;
}

static status_t wait_for_read_buf_finish_read(uint32 index)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[index];
    timeval_t begin_time;
    uint64 sleep_time = 0;
    ELAPSED_BEGIN(begin_time);
    // wait for read buf ready
    OG_LOG_DEBUG_INF("[DTC RCY] dtc fetch log start wait for read buf node_id = %u", rcy_node->node_id);
    uint32 time_out = OG_DTC_RCY_NODE_READ_BUF_TIMEOUT;
    for (;;) {
        if (SECUREC_UNLIKELY(rcy_node->read_size[rcy_node->read_buf_read_index] == OG_INVALID_ID32)) {
            cm_sleep(OG_DTC_RCY_NODE_READ_BUF_SLEEP_TIME);
            time_out -= OG_DTC_RCY_NODE_READ_BUF_SLEEP_TIME;
            if (time_out <= 0) {
                OG_LOG_RUN_WAR("[DTC RCY] dtc rcy fetch log batch wait for read buf time out node_id =%u", index);
                time_out = OG_DTC_RCY_NODE_READ_BUF_TIMEOUT;
            }
        } else {
            break;
        }
    }
    ELAPSED_END(begin_time, sleep_time);
    if (g_dtc_rcy_fetch_diag_active != NULL) {
        g_dtc_rcy_fetch_diag_active->ring_wait_us += sleep_time;
    }
    OG_LOG_DEBUG_INF("[DTC RCY] dtc fetch log finish wait for "
                     "read buf sleep time = %llu node_id = %u",
                     sleep_time, rcy_node->node_id);
    return OG_SUCCESS;
}

status_t dtc_rcy_set_item_update_need_replay(rcy_set_bucket_t *bucket, page_id_t page_id, bool8 need_replay)
{
    rcy_set_item_t *item = bucket->first;
    uint64 curr_page_lsn = OG_INVALID_ID64;
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        buf_bucket_t *buf_bucket = buf_find_bucket(session, page_id);
        cm_spin_lock_bucket(&buf_bucket->lock, NULL);
        buf_ctrl_t *ctrl = buf_find_from_bucket(buf_bucket, page_id);
        if (!ctrl || ctrl->lock_mode == DRC_LOCK_NULL) {
            /* If the page is not in memory or lock mode is null, the partial recovery for that page can't be skipped,
            as the page on disk may be not the latest one. */
            curr_page_lsn = 0;
            cm_spin_unlock_bucket(&buf_bucket->lock);
        } else {
            curr_page_lsn = (ctrl->page)->lsn;
            cm_spin_unlock_bucket(&buf_bucket->lock);
        }
    }
    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            if (item->last_dirty_lsn <= curr_page_lsn) {
                item->need_replay = need_replay;
            }
            return OG_SUCCESS;
        }
        item = item->next_item;
    }
    return OG_ERROR;
}

rcy_set_item_t *dtc_rcy_get_item_internal(page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_bucket_t *bucket = NULL;
    uint32 hash_id;
    hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    bucket = &rcy_set->buckets[hash_id];
    return (dtc_rcy_get_item(bucket, page_id));
}

bool32 dtc_rcy_is_partial_replay(void)
{
    if (g_dtc == NULL) {
        return OG_FALSE;
    }

    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    return (bool32)(dtc_rcy->in_progress && !dtc_rcy->full_recovery && dtc_rcy->phase == PHASE_RECOVERY);
}

static void dtc_rcy_init_last_recovery_stat(instance_list_t *recover_list)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;

    stat->last_rcy_log_size = 0;
    stat->last_rcy_set_num = 0;
    stat->last_rcy_analyze_elapsed = 0;
    stat->last_rcy_set_revise_elapsed = 0;
    stat->last_rcy_replay_elapsed = 0;
    stat->last_rcy_elapsed = 0;
    stat->last_rcy_is_full_recovery = OG_FALSE;
    stat->last_rcy_logic_log_group_count = 0;
    stat->last_rcy_logic_log_elapsed = 0;
    stat->latc_rcy_logic_log_wait_time = 0;
    MEMS_RETVOID_IFERR(memset_sp(&stat->rcy_log_points, sizeof(rcy_node_stat_t) * OG_MAX_INSTANCES, 0,
                                 sizeof(rcy_node_stat_t) * OG_MAX_INSTANCES));

    MEMS_RETVOID_IFERR(
        memcpy_s(&stat->last_rcy_inst_list, sizeof(instance_list_t), recover_list, sizeof(instance_list_t)));
}

static rcy_set_item_pool_t *dtc_rcy_alloc_itempool(rcy_set_t *rcy_set)
{
    rcy_set_item_pool_t *item_pool = NULL;
    uint64 item_pool_size = sizeof(rcy_set_item_t) * rcy_set->capacity + sizeof(rcy_set_item_pool_t);

    // free in dtc_recovery_close
    item_pool = (rcy_set_item_pool_t *)malloc(item_pool_size);
    if (item_pool == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc rcy set itempool");
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, item_pool_size, "dtc recovery set itempool");
        return NULL;
    }
    errno_t ret = memset_sp(item_pool, item_pool_size, 0, item_pool_size);
    knl_securec_check(ret);
    item_pool->items = (rcy_set_item_t *)((char *)item_pool + sizeof(rcy_set_item_pool_t));
    item_pool->hwm = 0;
    item_pool->capacity = (int64)rcy_set->capacity;
    item_pool->next = NULL;

    OG_LOG_RUN_INF("[DTC RCY] alloc rcy_set itempool successfully, recovery set capacity=%llu, itempool size=%llu",
                   rcy_set->capacity, item_pool_size);
    return item_pool;
}

static rcy_set_item_pool_t *dtc_rcy_shard_alloc_itempool(int64 capacity)
{
    rcy_set_item_pool_t *item_pool = NULL;
    uint64 item_pool_size = (uint64)sizeof(rcy_set_item_t) * (uint64)capacity + sizeof(rcy_set_item_pool_t);

    item_pool = (rcy_set_item_pool_t *)malloc(item_pool_size);
    if (item_pool == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc shard rcy set itempool, capacity=%lld", capacity);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, item_pool_size, "dtc recovery shard set itempool");
        return NULL;
    }
    errno_t ret = memset_sp(item_pool, item_pool_size, 0, item_pool_size);
    knl_securec_check(ret);
    item_pool->items = (rcy_set_item_t *)((char *)item_pool + sizeof(rcy_set_item_pool_t));
    item_pool->hwm = 0;
    item_pool->capacity = capacity;
    item_pool->next = NULL;
    return item_pool;
}

static inline bool32 dtc_rcy_rbp_partial_collecting(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    return (bool32)(dtc_rcy->in_progress && !dtc_rcy->full_recovery && dtc_rcy->phase == PHASE_ANALYSIS &&
                    KNL_RBP_ENABLE(session->kernel) && KNL_RBP_FOR_RECOVERY(session->kernel) &&
                    !session->kernel->db.recover_for_restore);
}

static inline bool32 dtc_rcy_use_analyze_local_path(knl_session_t *session, uint32 worker_slot)
{
    return (bool32)(dtc_rcy_rbp_partial_collecting(session) && worker_slot < PARAL_ANALYZE_THREAD_NUM &&
                    g_analyze_paral_mgr.local_rcy_inited);
}

static void dtc_rcy_analyze_rbp_reset(rcy_set_analyze_rbp_t *meta)
{
    errno_t ret;

    if (meta == NULL) {
        return;
    }
    ret = memset_sp(meta, sizeof(rcy_set_analyze_rbp_t), 0, sizeof(rcy_set_analyze_rbp_t));
    knl_securec_check(ret);
}

static rcy_set_item_pool_t *dtc_rcy_local_alloc_itempool(dtc_rcy_local_set_t *local)
{
    rcy_set_item_pool_t *item_pool = NULL;
    uint64 item_pool_size = (uint64)sizeof(rcy_set_item_t) * (uint64)local->pool_capacity + sizeof(rcy_set_item_pool_t);
    errno_t ret;

    item_pool = (rcy_set_item_pool_t *)malloc(item_pool_size);
    if (item_pool == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][local rcy] failed to alloc local itempool, size=%llu", item_pool_size);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, item_pool_size, "dtc local recovery set itempool");
        return NULL;
    }
    ret = memset_sp(item_pool, item_pool_size, 0, item_pool_size);
    knl_securec_check(ret);
    item_pool->items = (rcy_set_item_t *)((char *)item_pool + sizeof(rcy_set_item_pool_t));
    item_pool->hwm = 0;
    item_pool->capacity = (int64)local->pool_capacity;
    item_pool->next = NULL;
    return item_pool;
}

status_t dtc_rcy_local_set_init(dtc_rcy_local_set_t *local)
{
    uint64 bucket_size;
    errno_t ret;

    if (local->inited) {
        return OG_SUCCESS;
    }
    local->bucket_num = DTC_RCY_LOCAL_SET_BUCKET_NUM;
    local->pool_capacity = DTC_RCY_LOCAL_SET_POOL_CAPACITY;
    bucket_size = (uint64)local->bucket_num * sizeof(rcy_local_bucket_t);
    local->buckets = (rcy_local_bucket_t *)malloc(bucket_size);
    if (local->buckets == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][local rcy] failed to alloc local buckets size=%llu", bucket_size);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, bucket_size, "dtc local recovery set bucket");
        return OG_ERROR;
    }
    ret = memset_sp(local->buckets, bucket_size, 0, bucket_size);
    knl_securec_check(ret);
    local->item_pools = dtc_rcy_local_alloc_itempool(local);
    if (local->item_pools == NULL) {
        CM_FREE_PTR(local->buckets);
        return OG_ERROR;
    }
    local->curr_item_pools = local->item_pools;
    ret = memset_sp(local->merge_shard_heads, sizeof(local->merge_shard_heads), 0, sizeof(local->merge_shard_heads));
    knl_securec_check(ret);
    ret = memset_sp(local->merge_shard_tails, sizeof(local->merge_shard_tails), 0, sizeof(local->merge_shard_tails));
    knl_securec_check(ret);
    dtc_rcy_local_reset_active_chains(local);
    local->active_rebuild_pool = NULL;
    local->active_epoch = 0;
    local->active_prune_lfn = 0;
    local->active_rebuild_idx = 0;
    local->active_tracking = OG_FALSE;
    local->active_rebuild_done = OG_FALSE;
    ret = memset_sp(local->space_id_set, sizeof(local->space_id_set), OG_INVALID_ID32, sizeof(local->space_id_set));
    knl_securec_check(ret);
    local->space_set_size = 0;
    local->inited = OG_TRUE;
    return OG_SUCCESS;
}

void dtc_rcy_local_set_clear(dtc_rcy_local_set_t *local)
{
    rcy_set_item_pool_t *pool = NULL;
    rcy_set_item_pool_t *next;
    errno_t ret;

    if (!local->inited) {
        return;
    }
    CM_FREE_PTR(local->buckets);
    pool = local->item_pools;
    while (pool != NULL) {
        next = pool->next;
        free(pool);
        pool = next;
    }
    local->item_pools = NULL;
    local->curr_item_pools = NULL;
    ret = memset_sp(local->merge_shard_heads, sizeof(local->merge_shard_heads), 0, sizeof(local->merge_shard_heads));
    knl_securec_check(ret);
    ret = memset_sp(local->merge_shard_tails, sizeof(local->merge_shard_tails), 0, sizeof(local->merge_shard_tails));
    knl_securec_check(ret);
    dtc_rcy_local_reset_active_chains(local);
    local->active_rebuild_pool = NULL;
    local->active_epoch = 0;
    local->active_prune_lfn = 0;
    local->active_rebuild_idx = 0;
    local->active_tracking = OG_FALSE;
    local->active_rebuild_done = OG_FALSE;
    local->space_set_size = 0;
    local->inited = OG_FALSE;
}

static status_t dtc_rcy_local_set_init_slot(uint32 slot)
{
    return dtc_rcy_local_set_init(&g_analyze_paral_mgr.local_rcy[slot]);
}

static void dtc_rcy_local_set_clear_slot(uint32 slot)
{
    dtc_rcy_local_set_clear(&g_analyze_paral_mgr.local_rcy[slot]);
}

static status_t dtc_rcy_local_sets_init_all(void)
{
    if (g_analyze_paral_mgr.local_rcy_inited) {
        dtc_rcy_local_sets_clear_all();
    }
    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        if (dtc_rcy_local_set_init_slot(i) != OG_SUCCESS) {
            for (uint32 j = 0; j < i; j++) {
                dtc_rcy_local_set_clear_slot(j);
            }
            return OG_ERROR;
        }
    }
    g_analyze_paral_mgr.local_rcy_inited = OG_TRUE;
    return OG_SUCCESS;
}

static void dtc_rcy_local_sets_clear_all(void)
{
    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        dtc_rcy_local_set_clear_slot(i);
    }
    g_analyze_paral_mgr.local_rcy_inited = OG_FALSE;
}

static void dtc_rcy_analyze_abort_local_sets(void)
{
    if (g_analyze_paral_mgr.local_rcy_inited) {
        dtc_rcy_local_sets_clear_all();
    }
}

static rcy_set_item_t *dtc_rcy_local_get_item(rcy_local_bucket_t *bucket, page_id_t page_id)
{
    rcy_set_item_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }
        item = item->next_item;
    }
    return NULL;
}

static void dtc_rcy_local_add_to_bucket(rcy_local_bucket_t *bucket, rcy_set_item_t *item)
{
    item->next_item = bucket->first;
    bucket->first = item;
    bucket->count++;
}

static status_t dtc_rcy_local_try_alloc_itempool(dtc_rcy_local_set_t *local)
{
    rcy_set_item_pool_t *item_pool;

    if (local->curr_item_pools->hwm < local->pool_capacity) {
        return OG_SUCCESS;
    }
    item_pool = dtc_rcy_local_alloc_itempool(local);
    if (item_pool == NULL) {
        return OG_ERROR;
    }
    local->curr_item_pools->next = item_pool;
    local->curr_item_pools = item_pool;
    return OG_SUCCESS;
}

static bool32 dtc_rcy_rbp_touch_range_connected(const rbp_partial_touch_t *touch, uint64 min_lfn, uint64 max_lfn)
{
    uint64 left_max;
    uint64 right_max;

    if (touch == NULL || !touch->used) {
        return OG_FALSE;
    }
    left_max = (max_lfn == OG_INVALID_ID64) ? max_lfn : (max_lfn + 1);
    right_max = (touch->touch_max_lfn == OG_INVALID_ID64) ? touch->touch_max_lfn : (touch->touch_max_lfn + 1);
    return (bool32)(min_lfn <= right_max && touch->touch_min_lfn <= left_max);
}

static bool32 dtc_rcy_rbp_touch_coalesce_nearest(rcy_set_analyze_rbp_t *meta, uint32 node_id, uint64 min_lfn,
    uint64 max_lfn)
{
    uint32 best_slot = RBP_PARTIAL_TOUCH_SLOT_COUNT;
    uint64 best_span = OG_INVALID_ID64;
    uint64 best_min = 0;
    uint64 best_max = 0;

    for (uint32 i = 0; i < RBP_PARTIAL_TOUCH_SLOT_COUNT; i++) {
        rbp_partial_touch_t *touch = &meta->touches[i];
        uint64 merged_min;
        uint64 merged_max;
        uint64 span;

        if (!touch->used || touch->node_id != node_id) {
            continue;
        }
        merged_min = MIN(touch->touch_min_lfn, min_lfn);
        merged_max = MAX(touch->touch_max_lfn, max_lfn);
        span = merged_max - merged_min;
        if (best_slot == RBP_PARTIAL_TOUCH_SLOT_COUNT || span < best_span) {
            best_slot = i;
            best_span = span;
            best_min = merged_min;
            best_max = merged_max;
        }
    }

    if (best_slot == RBP_PARTIAL_TOUCH_SLOT_COUNT) {
        return OG_FALSE;
    }

    meta->touches[best_slot].touch_min_lfn = best_min;
    meta->touches[best_slot].touch_max_lfn = best_max;
    OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                         "[DTC RCY][RBP][partial] touch slots coalesced overflow_node=%u input=%llu-%llu "
                         "slot=%u merged=%llu-%llu slots=%u",
                         node_id, (uint64)min_lfn, (uint64)max_lfn, best_slot, (uint64)best_min,
                         (uint64)best_max, (uint32)RBP_PARTIAL_TOUCH_SLOT_COUNT);
    return OG_TRUE;
}

void dtc_rcy_rbp_analyze_touch_apply_range(rcy_set_analyze_rbp_t *meta, uint32 node_id, uint64 min_lfn,
    uint64 max_lfn)
{
    uint32 free_slot = RBP_PARTIAL_TOUCH_SLOT_COUNT;
    uint64 merged_min;
    uint64 merged_max;
    bool32 merged;
    uint64 tmp_lfn;

    if (meta == NULL || node_id >= OG_MAX_INSTANCES || min_lfn == 0 || max_lfn == 0) {
        return;
    }
    if (min_lfn > max_lfn) {
        tmp_lfn = min_lfn;
        min_lfn = max_lfn;
        max_lfn = tmp_lfn;
    }

    meta->touched = OG_TRUE;
    merged_min = min_lfn;
    merged_max = max_lfn;
    do {
        merged = OG_FALSE;
        free_slot = RBP_PARTIAL_TOUCH_SLOT_COUNT;
        for (uint32 i = 0; i < RBP_PARTIAL_TOUCH_SLOT_COUNT; i++) {
            rbp_partial_touch_t *touch = &meta->touches[i];

            if (!touch->used) {
                if (free_slot == RBP_PARTIAL_TOUCH_SLOT_COUNT) {
                    free_slot = i;
                }
                continue;
            }
            if (touch->node_id != node_id || !dtc_rcy_rbp_touch_range_connected(touch, merged_min, merged_max)) {
                continue;
            }
            merged_min = MIN(merged_min, touch->touch_min_lfn);
            merged_max = MAX(merged_max, touch->touch_max_lfn);
            touch->used = OG_FALSE;
            merged = OG_TRUE;
        }
    } while (merged);

    if (free_slot < RBP_PARTIAL_TOUCH_SLOT_COUNT) {
        rbp_partial_touch_t *touch = &meta->touches[free_slot];
        touch->used = OG_TRUE;
        touch->node_id = (uint8)node_id;
        touch->touch_min_lfn = merged_min;
        touch->touch_max_lfn = merged_max;
        return;
    }

    if (dtc_rcy_rbp_touch_coalesce_nearest(meta, node_id, merged_min, merged_max)) {
        return;
    }

    meta->overflow_disable_bitmap |= ((uint64)1 << node_id);
    if (!meta->touch_overflow) {
        meta->touch_overflow = OG_TRUE;
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] touch overflow no same-node slot overflow_node=%u range=%llu-%llu",
                       node_id, (uint64)min_lfn, (uint64)max_lfn);
    }
}

static void dtc_rcy_rbp_analyze_touch_apply(rcy_set_analyze_rbp_t *meta, uint32 node_id, uint64 batch_lfn)
{
    dtc_rcy_rbp_analyze_touch_apply_range(meta, node_id, batch_lfn, batch_lfn);
}

static void dtc_rcy_rbp_analyze_merge_meta(rcy_set_analyze_rbp_t *dst, const rcy_set_analyze_rbp_t *src)
{
    if (dst == NULL || src == NULL || !src->touched) {
        return;
    }
    dst->touched = OG_TRUE;
    if (src->expect_lsn > dst->expect_lsn) {
        dst->expect_lsn = src->expect_lsn;
        dst->expect_lfn = src->expect_lfn;
    }
    dst->touch_overflow = (bool8)(dst->touch_overflow || src->touch_overflow);
    dst->overflow_disable_bitmap |= src->overflow_disable_bitmap;
    for (uint32 i = 0; i < RBP_PARTIAL_TOUCH_SLOT_COUNT; i++) {
        const rbp_partial_touch_t *st = &src->touches[i];

        if (!st->used) {
            continue;
        }
        dtc_rcy_rbp_analyze_touch_apply_range(dst, (uint32)st->node_id, st->touch_min_lfn, st->touch_max_lfn);
    }
}

static void dtc_rcy_merge_rcy_item_fields(rcy_set_item_t *dst, const rcy_set_item_t *src,
    dtc_rcy_local_finalize_stat_t *stat)
{
    if (dst == NULL || src == NULL) {
        return;
    }
    if (src->first_dirty_lsn < dst->first_dirty_lsn || dst->first_dirty_lsn == 0) {
        dst->first_dirty_lsn = src->first_dirty_lsn;
    }
    if (src->last_dirty_lsn > dst->last_dirty_lsn) {
        dst->last_dirty_lsn = src->last_dirty_lsn;
        dst->pcn = src->pcn;
    }
    if (src->dirty_min_lfn != 0 && (dst->dirty_min_lfn == 0 || src->dirty_min_lfn < dst->dirty_min_lfn)) {
        dst->dirty_min_lfn = src->dirty_min_lfn;
    }
    if (src->dirty_max_lfn > dst->dirty_max_lfn) {
        dst->dirty_max_lfn = src->dirty_max_lfn;
    }
    dst->need_replay = (bool8)(dst->need_replay || src->need_replay);
    dst->need_check_leave_changed = (bool8)(dst->need_check_leave_changed || src->need_check_leave_changed);
    {
        bool32 overflow_before = dst->analyze_rbp.touch_overflow;

        dtc_rcy_rbp_analyze_merge_meta(&dst->analyze_rbp, &src->analyze_rbp);
        if (dst->analyze_rbp.touch_overflow && !overflow_before) {
            stat->merge_touch_overflow++;
        }
    }
}

#if DTC_RCY_USE_LEGACY_FINALIZE
static status_t dtc_rcy_global_alloc_item_single(rcy_set_t *rcy_set, rcy_set_item_t **out_item)
{
    rcy_set_item_pool_t *item_pool;
    int64 idx;

    item_pool = rcy_set->curr_item_pools;
    if (item_pool->hwm >= item_pool->capacity) {
        if (dtc_rcy_try_alloc_itempool(rcy_set, item_pool) != OG_SUCCESS) {
            return OG_ERROR;
        }
        item_pool = rcy_set->curr_item_pools;
    }
    idx = item_pool->hwm;
    item_pool->hwm++;
    *out_item = &item_pool->items[idx];
    dtc_rcy_analyze_rbp_reset(&(*out_item)->analyze_rbp);
    return OG_SUCCESS;
}

static status_t dtc_rcy_merge_local_item_into_global(rcy_set_t *rcy_set, const rcy_set_item_t *local_item,
    dtc_rcy_local_finalize_stat_t *stat)
{
    uint32 hash_id = dtc_rcy_bucket_hash(local_item->page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *dst = dtc_rcy_get_item(bucket, local_item->page_id);

    if (dst != NULL) {
        dtc_rcy_merge_rcy_item_fields(dst, local_item, stat);
        stat->merge_update_hit++;
        return OG_SUCCESS;
    }
    if (dtc_rcy_global_alloc_item_single(rcy_set, &dst) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *dst = *local_item;
    dst->next_item = NULL;
    dst->merge_next = NULL;
    dst->active_next = NULL;
    dst->active_epoch = 0;
    dtc_rcy_add_to_bucket(bucket, dst);
    stat->merge_insert_new++;
    return OG_SUCCESS;
}
#endif

static status_t dtc_rcy_shard_alloc_item_single(dtc_rcy_merge_shard_ctx_t *shard_ctx, rcy_set_item_t **out_item)
{
    rcy_set_item_pool_t *item_pool;
    int64 idx;

    if (shard_ctx->curr_item_pools == NULL) {
        item_pool = dtc_rcy_shard_alloc_itempool(DTC_RCY_MERGE_SHARD_POOL_CAPACITY);
        if (item_pool == NULL) {
            return OG_ERROR;
        }
        shard_ctx->item_pools = item_pool;
        shard_ctx->curr_item_pools = item_pool;
    }
    item_pool = shard_ctx->curr_item_pools;
    if (item_pool->hwm >= item_pool->capacity) {
        rcy_set_item_pool_t *new_pool = dtc_rcy_shard_alloc_itempool(DTC_RCY_MERGE_SHARD_POOL_CAPACITY);
        if (new_pool == NULL) {
            return OG_ERROR;
        }
        shard_ctx->curr_item_pools->next = new_pool;
        shard_ctx->curr_item_pools = new_pool;
        item_pool = new_pool;
    }
    idx = item_pool->hwm;
    item_pool->hwm++;
    *out_item = &item_pool->items[idx];
    dtc_rcy_analyze_rbp_reset(&(*out_item)->analyze_rbp);
    (*out_item)->merge_next = NULL;
    return OG_SUCCESS;
}

static status_t dtc_rcy_shard_partial_ensure_curr_pool(dtc_rcy_merge_shard_ctx_t *shard_ctx)
{
    rbp_partial_item_pool_t *pool;
    rbp_partial_item_pool_t *new_pool;

    if (shard_ctx->curr_partial_item_pool == NULL) {
        pool = dtc_rcy_rbp_partial_alloc_pool();
        if (pool == NULL) {
            return OG_ERROR;
        }
        shard_ctx->partial_item_pools = pool;
        shard_ctx->curr_partial_item_pool = pool;
        return OG_SUCCESS;
    }
    pool = shard_ctx->curr_partial_item_pool;
    if (pool->hwm >= RBP_PARTIAL_ITEM_POOL_SIZE) {
        if (pool->next == NULL) {
            new_pool = dtc_rcy_rbp_partial_alloc_pool();
            if (new_pool == NULL) {
                return OG_ERROR;
            }
            pool->next = new_pool;
        }
        shard_ctx->curr_partial_item_pool = pool->next;
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static status_t dtc_rcy_shard_partial_take_item(dtc_rcy_merge_shard_ctx_t *shard_ctx, rbp_partial_item_t **out_item)
{
    rbp_partial_item_pool_t *pool = shard_ctx->curr_partial_item_pool;

    if (pool == NULL || pool->hwm >= RBP_PARTIAL_ITEM_POOL_SIZE) {
        return OG_ERROR;
    }
    *out_item = &pool->items[pool->hwm++];
    shard_ctx->partial_item_count++;
    return OG_SUCCESS;
}

static inline void dtc_rcy_local_append_merge_shard_chain(dtc_rcy_local_set_t *local, rcy_set_item_t *item,
    page_id_t page_id)
{
    /*
     * Merge workers insert into the global rcy_set without taking bucket locks.
     * Partition by the global bucket hash so one global bucket is owned by only
     * one merge shard, even when the local-set bucket count differs.
     */
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, OG_RCY_SET_BUCKET);
    uint32 shard_id = hash_id % DTC_RCY_ANALYZE_MERGE_SHARD_NUM;

    item->merge_next = NULL;
    if (local->merge_shard_tails[shard_id] == NULL) {
        local->merge_shard_heads[shard_id] = item;
    } else {
        local->merge_shard_tails[shard_id]->merge_next = item;
    }
    local->merge_shard_tails[shard_id] = item;
}

static inline bool32 dtc_rcy_local_item_after_prune(const rcy_set_item_t *item, uint64 prune_lfn)
{
    if (item == NULL || !item->need_replay) {
        return OG_FALSE;
    }
    if (prune_lfn == 0) {
        return OG_TRUE;
    }
    return (bool32)(item->dirty_max_lfn == 0 || item->dirty_max_lfn >= prune_lfn);
}

static void dtc_rcy_local_reset_active_chains(dtc_rcy_local_set_t *local)
{
    errno_t ret;

    ret = memset_sp(local->active_shard_heads, sizeof(local->active_shard_heads), 0,
                    sizeof(local->active_shard_heads));
    knl_securec_check(ret);
    ret = memset_sp(local->active_shard_tails, sizeof(local->active_shard_tails), 0,
                    sizeof(local->active_shard_tails));
    knl_securec_check(ret);
    local->active_item_count = 0;
}

static void dtc_rcy_local_append_active_shard_chain(dtc_rcy_local_set_t *local, rcy_set_item_t *item)
{
    uint32 hash_id;
    uint32 shard_id;

    if (!local->active_tracking || item == NULL || item->active_epoch == local->active_epoch ||
        !dtc_rcy_local_item_after_prune(item, local->active_prune_lfn)) {
        return;
    }
    hash_id = dtc_rcy_bucket_hash(item->page_id, OG_RCY_SET_BUCKET);
    shard_id = hash_id % DTC_RCY_ANALYZE_MERGE_SHARD_NUM;
    item->active_next = NULL;
    item->active_epoch = local->active_epoch;
    if (local->active_shard_tails[shard_id] == NULL) {
        local->active_shard_heads[shard_id] = item;
    } else {
        local->active_shard_tails[shard_id]->active_next = item;
    }
    local->active_shard_tails[shard_id] = item;
    local->active_item_count++;
}

void dtc_rcy_local_set_enable_active_tracking(dtc_rcy_local_set_t *local)
{
    if (local == NULL || !local->inited) {
        return;
    }
    local->active_tracking = OG_TRUE;
    local->active_rebuild_done = OG_TRUE;
    local->active_epoch = 1;
    local->active_prune_lfn = 0;
    local->active_rebuild_pool = NULL;
    local->active_rebuild_idx = 0;
    dtc_rcy_local_reset_active_chains(local);
}

void dtc_rcy_local_set_begin_active_rebuild(dtc_rcy_local_set_t *local, uint64 prune_lfn)
{
    if (local == NULL || !local->inited || !local->active_tracking || local->active_prune_lfn >= prune_lfn) {
        return;
    }
    local->active_prune_lfn = prune_lfn;
    local->active_epoch++;
    if (local->active_epoch == 0) {
        local->active_epoch = 1;
    }
    dtc_rcy_local_reset_active_chains(local);
    local->active_rebuild_pool = local->item_pools;
    local->active_rebuild_idx = 0;
    local->active_rebuild_done = (bool8)(local->active_rebuild_pool == NULL);
}

void dtc_rcy_local_set_rebuild_active_budget(dtc_rcy_local_set_t *local, uint32 budget)
{
    uint32 scanned = 0;

    if (local == NULL || !local->inited || !local->active_tracking || local->active_rebuild_done) {
        return;
    }
    while (local->active_rebuild_pool != NULL && scanned < budget) {
        rcy_set_item_pool_t *pool = local->active_rebuild_pool;

        while (local->active_rebuild_idx < pool->hwm && scanned < budget) {
            rcy_set_item_t *item = &pool->items[local->active_rebuild_idx++];

            dtc_rcy_local_append_active_shard_chain(local, item);
            scanned++;
        }
        if (local->active_rebuild_idx >= pool->hwm) {
            local->active_rebuild_pool = pool->next;
            local->active_rebuild_idx = 0;
        }
    }
    if (local->active_rebuild_pool == NULL) {
        local->active_rebuild_done = OG_TRUE;
    }
}

bool32 dtc_rcy_local_set_active_ready(const dtc_rcy_local_set_t *local)
{
    return (bool32)(local != NULL && local->inited && local->active_tracking && local->active_rebuild_done);
}

static status_t dtc_rcy_merge_shard_item_into_global(rcy_set_t *rcy_set, dtc_rcy_merge_shard_ctx_t *shard_ctx,
    const rcy_set_item_t *local_item, dtc_rcy_merge_shard_stat_t *stat, rcy_set_item_t **merged_item)
{
    uint32 hash_id = dtc_rcy_bucket_hash(local_item->page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *dst = dtc_rcy_get_item(bucket, local_item->page_id);
    dtc_rcy_local_finalize_stat_t touch_stat = { 0 };

    if (dst != NULL) {
        dtc_rcy_merge_rcy_item_fields(dst, local_item, &touch_stat);
        stat->merge_update_hit++;
        stat->merge_touch_overflow += touch_stat.merge_touch_overflow;
        if (merged_item != NULL) {
            *merged_item = dst;
        }
        return OG_SUCCESS;
    }
    if (dtc_rcy_shard_alloc_item_single(shard_ctx, &dst) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *dst = *local_item;
    dst->next_item = NULL;
    dst->merge_next = NULL;
    dst->active_next = NULL;
    dst->active_epoch = 0;
    dtc_rcy_add_to_bucket(bucket, dst);
    stat->merge_insert_new++;
    if (merged_item != NULL) {
        *merged_item = dst;
    }
    return OG_SUCCESS;
}

static rbp_partial_item_t *dtc_rcy_merge_partial_apply_one(rbp_partial_context_t *ctx,
    dtc_rcy_merge_shard_ctx_t *shard_ctx, page_id_t page_id, rcy_set_item_t *rcy_item,
    dtc_rcy_merge_shard_stat_t *stat)
{
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, ctx->bucket_num);
    rbp_partial_bucket_t *bucket = &ctx->buckets[hash_id];
    rbp_partial_item_t *item = NULL;
    dtc_rcy_local_finalize_stat_t partial_stat = { 0 };
    date_t bucket_lock_begin;
    errno_t ret;

    if (shard_ctx != NULL) {
        if (dtc_rcy_shard_partial_ensure_curr_pool(shard_ctx) != OG_SUCCESS) {
            return NULL;
        }
    }

    bucket_lock_begin = cm_now();
    cm_spin_lock(&bucket->lock, NULL);
    item = dtc_rcy_rbp_partial_find_locked(bucket, page_id);
    if (item != NULL) {
        dtc_rcy_rbp_partial_materialize_merge_existing(item, rcy_item, ctx, &partial_stat);
        cm_spin_unlock(&bucket->lock);
        stat->partial_bucket_lock_us += (uint64)(cm_now() - bucket_lock_begin);
        stat->partial_touch_overflow += partial_stat.partial_touch_overflow;
        return item;
    }
    if (shard_ctx != NULL) {
        if (dtc_rcy_shard_partial_take_item(shard_ctx, &item) != OG_SUCCESS) {
            cm_spin_unlock(&bucket->lock);
            stat->partial_bucket_lock_us += (uint64)(cm_now() - bucket_lock_begin);
            return NULL;
        }
    } else {
        date_t global_lock_begin = cm_now();

        item = dtc_rcy_rbp_partial_alloc_item(ctx, NULL);
        stat->partial_global_lock_us += (uint64)(cm_now() - global_lock_begin);
        if (item == NULL) {
            cm_spin_unlock(&bucket->lock);
            stat->partial_bucket_lock_us += (uint64)(cm_now() - bucket_lock_begin);
            return NULL;
        }
    }
    item->page_id = page_id;
    item->rcy_item = rcy_item;
    item->expect_lsn = rcy_item->analyze_rbp.expect_lsn;
    item->expect_lfn = rcy_item->analyze_rbp.expect_lfn;
    item->touch_overflow = rcy_item->analyze_rbp.touch_overflow;
    item->best_lsn = 0;
    item->best_source_node = OG_INVALID_ID32;
    item->next = bucket->first;
    bucket->first = item;
    bucket->count++;
    ret = memcpy_sp(item->touches, sizeof(item->touches), rcy_item->analyze_rbp.touches,
                    sizeof(rcy_item->analyze_rbp.touches));
    knl_securec_check(ret);
    cm_spin_unlock(&bucket->lock);
    stat->partial_bucket_lock_us += (uint64)(cm_now() - bucket_lock_begin);
    stat->partial_items_created++;
    partial_stat.partial_touch_overflow = 0;
    dtc_rcy_rbp_partial_materialize_apply_overflow(ctx, item, rcy_item->analyze_rbp.overflow_disable_bitmap,
        OG_FALSE, &partial_stat);
    stat->partial_touch_overflow += partial_stat.partial_touch_overflow;
    return item;
}

static void dtc_rcy_merge_shard_worker_proc(thread_t *thread)
{
    dtc_rcy_merge_shard_worker_arg_t *arg = (dtc_rcy_merge_shard_worker_arg_t *)thread->argument;
    dtc_rcy_merge_shard_ctx_t *shard_ctx = arg->shard_ctx;
    rcy_set_t *rcy_set = arg->rcy_set;
    rbp_partial_context_t *partial_ctx = arg->partial_ctx;
    uint32 shard_id = arg->shard_id;
    rcy_set_item_pool_t *pool = NULL;
    date_t phase1_begin;
    date_t phase2_begin;

    arg->ret = OG_SUCCESS;
    phase1_begin = cm_now();
    for (uint32 slot = 0; slot < arg->local_count; slot++) {
        dtc_rcy_local_set_t *local = &arg->locals[slot];
        rcy_set_item_t *local_item;

        if (!local->inited) {
            continue;
        }
        local_item = arg->use_active ? local->active_shard_heads[shard_id] : local->merge_shard_heads[shard_id];
        while (local_item != NULL) {
            rcy_set_item_t *merged_item = NULL;
            rcy_set_item_t *next_item = arg->use_active ? local_item->active_next : local_item->merge_next;

            shard_ctx->stat.merge_scan_total++;
            if (arg->filter != NULL && !arg->filter(local_item, arg->filter_arg)) {
                shard_ctx->stat.merge_scan_skipped++;
                local_item = next_item;
                continue;
            }
            if (dtc_rcy_merge_shard_item_into_global(rcy_set, shard_ctx, local_item, &shard_ctx->stat,
                &merged_item) !=
                OG_SUCCESS) {
                arg->ret = OG_ERROR;
                return;
            }
            if (partial_ctx != NULL && dtc_rcy_rbp_partial_collecting(arg->session) && merged_item != NULL &&
                merged_item->need_replay && merged_item->analyze_rbp.touched &&
                merged_item->analyze_rbp.expect_lsn != 0) {
                shard_ctx->stat.rcy_items_scanned++;
                if (dtc_rcy_merge_partial_apply_one(partial_ctx, shard_ctx, merged_item->page_id, merged_item,
                    &shard_ctx->stat) == NULL) {
                    OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] shard materialize failed page %u-%u shard=%u",
                                   merged_item->page_id.file, merged_item->page_id.page, arg->shard_id);
                    arg->ret = OG_ERROR;
                    return;
                }
            }
            local_item = next_item;
        }
    }
    shard_ctx->stat.merge_rcy_us = (uint64)(cm_now() - phase1_begin);

    if (partial_ctx == NULL || !dtc_rcy_rbp_partial_collecting(arg->session)) {
        return;
    }

    phase2_begin = cm_now();
#if DTC_RCY_USE_LEGACY_FINALIZE
    pool = shard_ctx->item_pools;
    while (pool != NULL) {
        for (int64 i = 0; i < pool->hwm; i++) {
            rcy_set_item_t *rcy_item = &pool->items[i];

            shard_ctx->stat.rcy_items_scanned++;
            if (!rcy_item->need_replay || !rcy_item->analyze_rbp.touched || rcy_item->analyze_rbp.expect_lsn == 0) {
                continue;
            }
            if (dtc_rcy_merge_partial_apply_one(partial_ctx, shard_ctx, rcy_item->page_id, rcy_item,
                &shard_ctx->stat) == NULL) {
                OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] shard materialize failed page %u-%u shard=%u",
                               rcy_item->page_id.file, rcy_item->page_id.page, arg->shard_id);
                arg->ret = OG_ERROR;
                return;
            }
        }
        pool = pool->next;
    }
#else
    (void)pool;
#endif
    shard_ctx->stat.merge_partial_us = (uint64)(cm_now() - phase2_begin);
}

static void dtc_rcy_attach_shard_pools(rcy_set_t *rcy_set, dtc_rcy_merge_shard_ctx_t *shard_ctxs, uint32 shard_num)
{
    rcy_set_item_pool_t *tail = rcy_set->item_pools;
    rcy_set_item_pool_t *last = tail;

    if (tail == NULL) {
        return;
    }
    while (tail->next != NULL) {
        tail = tail->next;
    }
    last = tail;
    for (uint32 i = 0; i < shard_num; i++) {
        if (shard_ctxs[i].item_pools == NULL) {
            continue;
        }
        tail->next = shard_ctxs[i].item_pools;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        last = tail;
    }
    rcy_set->curr_item_pools = last;
}

static void dtc_rcy_transfer_shard_pools_to_rcy_set(rcy_set_t *rcy_set, dtc_rcy_merge_shard_ctx_t *shard_ctxs,
    uint32 shard_num)
{
    dtc_rcy_attach_shard_pools(rcy_set, shard_ctxs, shard_num);
    for (uint32 i = 0; i < shard_num; i++) {
        shard_ctxs[i].item_pools = NULL;
        shard_ctxs[i].curr_item_pools = NULL;
    }
}

static void dtc_rcy_attach_shard_partial_pools(rbp_partial_context_t *ctx, dtc_rcy_merge_shard_ctx_t *shard_ctxs,
    uint32 shard_num, uint64 *attached_count)
{
    rbp_partial_item_pool_t *tail;

    if (ctx == NULL || !ctx->enabled || ctx->item_pools == NULL) {
        return;
    }
    tail = ctx->item_pools;
    while (tail->next != NULL) {
        tail = tail->next;
    }
    for (uint32 i = 0; i < shard_num; i++) {
        if (shard_ctxs[i].partial_item_pools == NULL) {
            continue;
        }
        tail->next = shard_ctxs[i].partial_item_pools;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        if (attached_count != NULL) {
            *attached_count += shard_ctxs[i].partial_item_count;
        }
    }
    ctx->curr_item_pool = tail;
}

static bool32 dtc_rcy_shard_partial_pools_exist(dtc_rcy_merge_shard_ctx_t *shard_ctxs, uint32 shard_num)
{
    for (uint32 i = 0; i < shard_num; i++) {
        if (shard_ctxs[i].partial_item_pools != NULL) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static void dtc_rcy_free_shard_partial_pools(dtc_rcy_merge_shard_ctx_t *shard_ctxs, uint32 shard_num)
{
    for (uint32 i = 0; i < shard_num; i++) {
        rbp_partial_item_pool_t *pool = shard_ctxs[i].partial_item_pools;

        while (pool != NULL) {
            rbp_partial_item_pool_t *next = pool->next;

            CM_FREE_PTR(pool);
            pool = next;
        }
        shard_ctxs[i].partial_item_pools = NULL;
        shard_ctxs[i].curr_partial_item_pool = NULL;
        shard_ctxs[i].partial_item_count = 0;
    }
}

static void dtc_rcy_transfer_shard_partial_pools_to_ctx(rbp_partial_context_t *ctx,
    dtc_rcy_merge_shard_ctx_t *shard_ctxs, uint32 shard_num)
{
    uint64 attached_count = 0;

    if (!dtc_rcy_shard_partial_pools_exist(shard_ctxs, shard_num)) {
        return;
    }
    if (ctx == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] shard partial pool transfer skipped: ctx is NULL");
        dtc_rcy_free_shard_partial_pools(shard_ctxs, shard_num);
        return;
    }
    if (!ctx->enabled) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] shard partial pool transfer skipped: ctx disabled");
        dtc_rcy_free_shard_partial_pools(shard_ctxs, shard_num);
        return;
    }
    if (ctx->item_pools == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] shard partial pool transfer skipped: item_pools is NULL");
        dtc_rcy_free_shard_partial_pools(shard_ctxs, shard_num);
        return;
    }
    dtc_rcy_attach_shard_partial_pools(ctx, shard_ctxs, shard_num, &attached_count);
    ctx->item_count += attached_count;
    for (uint32 i = 0; i < shard_num; i++) {
        shard_ctxs[i].partial_item_pools = NULL;
        shard_ctxs[i].curr_partial_item_pool = NULL;
        shard_ctxs[i].partial_item_count = 0;
    }
}

static void dtc_rcy_transfer_all_shard_resources(rcy_set_t *rcy_set, rbp_partial_context_t *partial_ctx,
    dtc_rcy_merge_shard_ctx_t *shard_ctxs, uint32 shard_num)
{
    dtc_rcy_transfer_shard_pools_to_rcy_set(rcy_set, shard_ctxs, shard_num);
    dtc_rcy_transfer_shard_partial_pools_to_ctx(partial_ctx, shard_ctxs, shard_num);
}

static void dtc_rcy_merge_shard_stats_aggregate(dtc_rcy_local_finalize_stat_t *stat,
    const dtc_rcy_merge_shard_ctx_t *shard_ctxs, uint32 shard_num)
{
    uint64 merge_rcy_max = 0;
    uint64 merge_partial_max = 0;

    for (uint32 i = 0; i < shard_num; i++) {
        const dtc_rcy_merge_shard_stat_t *shard_stat = &shard_ctxs[i].stat;

        merge_rcy_max = MAX(merge_rcy_max, shard_stat->merge_rcy_us);
        merge_partial_max = MAX(merge_partial_max, shard_stat->merge_partial_us);
        stat->merge_rcy_us_sum += shard_stat->merge_rcy_us;
        stat->merge_partial_us_sum += shard_stat->merge_partial_us;
        stat->merge_scan_total += shard_stat->merge_scan_total;
        stat->merge_scan_skipped += shard_stat->merge_scan_skipped;
        stat->merge_insert_new += shard_stat->merge_insert_new;
        stat->merge_update_hit += shard_stat->merge_update_hit;
        stat->merge_touch_overflow += shard_stat->merge_touch_overflow;
        stat->rcy_items_scanned += shard_stat->rcy_items_scanned;
        stat->partial_items_created += shard_stat->partial_items_created;
        stat->partial_touch_overflow += shard_stat->partial_touch_overflow;
        stat->partial_bucket_lock_us += shard_stat->partial_bucket_lock_us;
        stat->partial_global_lock_us += shard_stat->partial_global_lock_us;
    }
    stat->merge_rcy_us = merge_rcy_max;
    stat->merge_partial_us = merge_partial_max;
    stat->local_items_scanned = stat->merge_insert_new + stat->merge_update_hit;
}

static status_t dtc_rcy_merge_local_rcy_sets_sharded(knl_session_t *session, dtc_rcy_local_set_t *locals,
    uint32 local_count, dtc_rcy_local_item_filter_t filter, void *filter_arg, bool32 use_active,
    dtc_rcy_local_finalize_stat_t *stat)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rbp_partial_context_t *partial_ctx = &dtc_rcy->rbp_partial_ctx;
    dtc_rcy_merge_shard_ctx_t shard_ctxs[DTC_RCY_ANALYZE_MERGE_SHARD_NUM];
    dtc_rcy_merge_shard_worker_arg_t shard_args[DTC_RCY_ANALYZE_MERGE_SHARD_NUM];
    thread_t shard_threads[DTC_RCY_ANALYZE_MERGE_SHARD_NUM];
    date_t merge_begin = cm_now();
    uint64 global_items_before = rcy_set->size;
    status_t ret = OG_SUCCESS;
    errno_t memset_ret;

    memset_ret = memset_sp(shard_ctxs, sizeof(shard_ctxs), 0, sizeof(shard_ctxs));
    knl_securec_check(memset_ret);
    memset_ret = memset_sp(shard_args, sizeof(shard_args), 0, sizeof(shard_args));
    knl_securec_check(memset_ret);
    memset_ret = memset_sp(shard_threads, sizeof(shard_threads), 0, sizeof(shard_threads));
    knl_securec_check(memset_ret);

    if (global_items_before != 0) {
        OG_LOG_RUN_INF("[DTC RCY][RBP][partial] sharded finalize merges into non-empty global set, count=%llu",
                       global_items_before);
    }

    for (uint32 shard_id = 0; shard_id < DTC_RCY_ANALYZE_MERGE_SHARD_NUM; shard_id++) {
        shard_ctxs[shard_id].shard_id = shard_id;
        shard_args[shard_id].session = session;
        shard_args[shard_id].shard_id = shard_id;
        shard_args[shard_id].rcy_set = rcy_set;
        shard_args[shard_id].partial_ctx = partial_ctx;
        shard_args[shard_id].shard_ctx = &shard_ctxs[shard_id];
        shard_args[shard_id].locals = locals;
        shard_args[shard_id].local_count = local_count;
        shard_args[shard_id].filter = filter;
        shard_args[shard_id].filter_arg = filter_arg;
        shard_args[shard_id].use_active = use_active;
        shard_args[shard_id].ret = OG_SUCCESS;
        ret = cm_create_thread(dtc_rcy_merge_shard_worker_proc, 0, &shard_args[shard_id], &shard_threads[shard_id]);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to create merge shard worker, shard=%u", shard_id);
            for (uint32 j = 0; j < shard_id; j++) {
                cm_close_thread(&shard_threads[j]);
            }
            dtc_rcy_transfer_all_shard_resources(rcy_set, partial_ctx, shard_ctxs, DTC_RCY_ANALYZE_MERGE_SHARD_NUM);
            return ret;
        }
    }

    for (uint32 shard_id = 0; shard_id < DTC_RCY_ANALYZE_MERGE_SHARD_NUM; shard_id++) {
        cm_close_thread(&shard_threads[shard_id]);
        if (shard_args[shard_id].ret != OG_SUCCESS) {
            ret = shard_args[shard_id].ret;
        }
    }
    dtc_rcy_transfer_all_shard_resources(rcy_set, partial_ctx, shard_ctxs, DTC_RCY_ANALYZE_MERGE_SHARD_NUM);
    if (ret != OG_SUCCESS) {
        return ret;
    }

    dtc_rcy_merge_shard_stats_aggregate(stat, shard_ctxs, DTC_RCY_ANALYZE_MERGE_SHARD_NUM);
    stat->merge_us = (uint64)(cm_now() - merge_begin);
    stat->merge_fused = 1;
    stat->materialize_us = 0;
    stat->global_items_after = global_items_before + stat->merge_insert_new;
    rcy_set->size = stat->global_items_after;
    OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] fused merge done: shard_num=%u partial_items=%llu rcy_scanned=%llu",
                   (uint32)DTC_RCY_ANALYZE_MERGE_SHARD_NUM, stat->partial_items_created, stat->rcy_items_scanned);
    return OG_SUCCESS;
}

static rcy_set_item_t *dtc_rcy_compact_get_item(rcy_set_item_t *head, page_id_t page_id)
{
    rcy_set_item_t *item = head;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }
        item = item->merge_next;
    }
    return NULL;
}

static void dtc_rcy_compact_shard_worker_proc(thread_t *thread)
{
    dtc_rcy_compact_shard_worker_arg_t *arg = (dtc_rcy_compact_shard_worker_arg_t *)thread->argument;
    rcy_set_item_t **dedup_buckets = NULL;
    uint64 bucket_size = (uint64)arg->bucket_count * sizeof(rcy_set_item_t *);
    date_t begin = cm_now();
    errno_t ret;

    arg->ret = OG_SUCCESS;
    dedup_buckets = (rcy_set_item_t **)malloc(bucket_size);
    if (dedup_buckets == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, bucket_size, "dtc rcy compact merge buckets");
        arg->ret = OG_ERROR;
        return;
    }
    ret = memset_sp(dedup_buckets, bucket_size, 0, bucket_size);
    knl_securec_check(ret);

    for (uint32 slot = 0; slot < arg->local_count; slot++) {
        dtc_rcy_local_set_t *local = &arg->locals[slot];
        rcy_set_item_t *item;

        if (!local->inited) {
            continue;
        }
        item = local->merge_shard_heads[arg->shard_id];
        while (item != NULL) {
            rcy_set_item_t *next = item->merge_next;
            uint32 hash_id = dtc_rcy_bucket_hash(item->page_id, OG_RCY_SET_BUCKET);
            uint32 bucket_id = hash_id / DTC_RCY_ANALYZE_MERGE_SHARD_NUM;
            rcy_set_item_t *dst;
            dtc_rcy_local_finalize_stat_t touch_stat = { 0 };

            arg->stat.merge_scan_total++;
            if ((hash_id % DTC_RCY_ANALYZE_MERGE_SHARD_NUM) != arg->shard_id || bucket_id >= arg->bucket_count) {
                OG_LOG_RUN_ERR("[DTC RCY][local merge] compact shard mismatch: page=%u-%u hash=%u shard=%u "
                               "expected=%u bucket=%u/%u",
                               item->page_id.file, item->page_id.page, hash_id,
                               hash_id % DTC_RCY_ANALYZE_MERGE_SHARD_NUM, arg->shard_id, bucket_id,
                               arg->bucket_count);
                arg->ret = OG_ERROR;
                CM_FREE_PTR(dedup_buckets);
                return;
            }
            if (arg->filter != NULL && !arg->filter(item, arg->filter_arg)) {
                arg->stat.merge_scan_skipped++;
                item = next;
                continue;
            }
            dst = dtc_rcy_compact_get_item(dedup_buckets[bucket_id], item->page_id);
            if (dst != NULL) {
                dtc_rcy_merge_rcy_item_fields(dst, item, &touch_stat);
                arg->stat.merge_touch_overflow += touch_stat.merge_touch_overflow;
                arg->duplicate_count++;
                item = next;
                continue;
            }
            item->merge_next = dedup_buckets[bucket_id];
            dedup_buckets[bucket_id] = item;
            arg->unique_count++;
            item = next;
        }
    }

    for (uint32 bucket_id = 0; bucket_id < arg->bucket_count; bucket_id++) {
        rcy_set_item_t *item = dedup_buckets[bucket_id];

        while (item != NULL) {
            rcy_set_item_t *next = item->merge_next;

            dtc_rcy_local_append_merge_shard_chain(arg->compact_local, item, item->page_id);
            item = next;
        }
    }
    arg->compact_us = (uint64)(cm_now() - begin);
    CM_FREE_PTR(dedup_buckets);
}

static void dtc_rcy_compact_shard_stats_aggregate(dtc_rcy_local_finalize_stat_t *stat,
    dtc_rcy_compact_shard_worker_arg_t *args, uint32 shard_num, uint64 *unique_count, uint64 *duplicate_count,
    uint64 *compact_worker_us)
{
    *unique_count = 0;
    *duplicate_count = 0;
    *compact_worker_us = 0;
    for (uint32 i = 0; i < shard_num; i++) {
        stat->merge_scan_total += args[i].stat.merge_scan_total;
        stat->merge_scan_skipped += args[i].stat.merge_scan_skipped;
        stat->merge_touch_overflow += args[i].stat.merge_touch_overflow;
        *unique_count += args[i].unique_count;
        *duplicate_count += args[i].duplicate_count;
        *compact_worker_us = MAX(*compact_worker_us, args[i].compact_us);
    }
}

static status_t dtc_rcy_compact_local_sets_for_merge(dtc_rcy_local_set_t *locals, uint32 local_count,
    dtc_rcy_local_item_filter_t filter, void *filter_arg, dtc_rcy_local_set_t *compact_local,
    dtc_rcy_local_finalize_stat_t *stat, uint64 *unique_count, uint64 *duplicate_count, uint64 *compact_us,
    uint64 *compact_worker_us)
{
    dtc_rcy_compact_shard_worker_arg_t args[DTC_RCY_ANALYZE_MERGE_SHARD_NUM];
    thread_t threads[DTC_RCY_ANALYZE_MERGE_SHARD_NUM];
    uint32 bucket_count = (OG_RCY_SET_BUCKET + DTC_RCY_ANALYZE_MERGE_SHARD_NUM - 1) /
        DTC_RCY_ANALYZE_MERGE_SHARD_NUM;
    date_t begin = cm_now();
    status_t ret = OG_SUCCESS;
    errno_t memset_ret;

    *unique_count = 0;
    *duplicate_count = 0;
    *compact_us = 0;
    *compact_worker_us = 0;
    memset_ret = memset_sp(compact_local, sizeof(*compact_local), 0, sizeof(*compact_local));
    knl_securec_check(memset_ret);
    memset_ret = memset_sp(args, sizeof(args), 0, sizeof(args));
    knl_securec_check(memset_ret);
    memset_ret = memset_sp(threads, sizeof(threads), 0, sizeof(threads));
    knl_securec_check(memset_ret);
    compact_local->bucket_num = OG_RCY_SET_BUCKET;
    compact_local->inited = OG_TRUE;

    for (uint32 shard_id = 0; shard_id < DTC_RCY_ANALYZE_MERGE_SHARD_NUM; shard_id++) {
        args[shard_id].shard_id = shard_id;
        args[shard_id].bucket_count = bucket_count;
        args[shard_id].locals = locals;
        args[shard_id].local_count = local_count;
        args[shard_id].filter = filter;
        args[shard_id].filter_arg = filter_arg;
        args[shard_id].compact_local = compact_local;
        args[shard_id].ret = OG_SUCCESS;
        ret = cm_create_thread(dtc_rcy_compact_shard_worker_proc, 0, &args[shard_id], &threads[shard_id]);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY][local merge] failed to create compact shard worker, shard=%u", shard_id);
            for (uint32 j = 0; j < shard_id; j++) {
                cm_close_thread(&threads[j]);
            }
            return ret;
        }
    }

    for (uint32 shard_id = 0; shard_id < DTC_RCY_ANALYZE_MERGE_SHARD_NUM; shard_id++) {
        cm_close_thread(&threads[shard_id]);
        if (args[shard_id].ret != OG_SUCCESS) {
            ret = args[shard_id].ret;
        }
    }
    dtc_rcy_compact_shard_stats_aggregate(stat, args, DTC_RCY_ANALYZE_MERGE_SHARD_NUM, unique_count,
        duplicate_count, compact_worker_us);
    *compact_us = (uint64)(cm_now() - begin);
    return ret;
}

/* Partial parallel analyze only: no dtc_rcy_handle_pcn_discon(); restore/PITR uses global dtc_rcy_record_page(). */
status_t dtc_rcy_record_page_into_local(knl_session_t *session, dtc_rcy_local_set_t *local, page_id_t page_id,
    uint64 lsn, uint64 batch_lfn, uint32 pcn, dtc_rcy_analysis_group_diag_t *diag,
    dtc_rcy_analysis_group_count_t *counts)
{
    uint32 hash_id;
    rcy_local_bucket_t *bucket;
    rcy_set_item_t *item;
    rcy_set_item_pool_t *item_pool;
    int64 idx;
    date_t record_begin = (diag == NULL) ? 0 : cm_now();

    if (local == NULL || !local->inited) {
        return OG_ERROR;
    }
    hash_id = dtc_rcy_bucket_hash(page_id, local->bucket_num);
    bucket = &local->buckets[hash_id];

    DTC_RCY_DIAG_INC(diag, counts, record_calls);
    item = dtc_rcy_local_get_item(bucket, page_id);
    if (item != NULL) {
        DTC_RCY_DIAG_INC(diag, counts, record_hit);
        item->need_replay = OG_TRUE;
        if (lsn > item->last_dirty_lsn) {
            item->last_dirty_lsn = lsn;
        }
        if (batch_lfn != 0) {
            item->dirty_min_lfn = (item->dirty_min_lfn == 0) ? batch_lfn : MIN(item->dirty_min_lfn, batch_lfn);
            item->dirty_max_lfn = MAX(item->dirty_max_lfn, batch_lfn);
        }
        dtc_rcy_local_append_active_shard_chain(local, item);
        if (diag != NULL) {
            diag->record_us += (uint64)(cm_now() - record_begin);
        }
        return OG_SUCCESS;
    }
    {
        date_t alloc_begin = (diag == NULL) ? 0 : cm_now();

        if (dtc_rcy_local_try_alloc_itempool(local) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (diag != NULL) {
            diag->alloc_itempool_us += (uint64)(cm_now() - alloc_begin);
        }
    }
    item_pool = local->curr_item_pools;
    idx = item_pool->hwm;
    item_pool->hwm++;
    item = &item_pool->items[idx];
    item->page_id = page_id;
    item->merge_next = NULL;
    item->active_next = NULL;
    item->active_epoch = 0;
    item->first_dirty_lsn = lsn;
    item->last_dirty_lsn = lsn;
    item->dirty_min_lfn = batch_lfn;
    item->dirty_max_lfn = batch_lfn;
    item->pcn = pcn;
    item->need_replay = OG_TRUE;
    item->rbp_required = OG_FALSE;
    item->rbp_verified = OG_FALSE;
    item->need_check_leave_changed = OG_FALSE;
    dtc_rcy_analyze_rbp_reset(&item->analyze_rbp);
    DTC_RCY_DIAG_INC(diag, counts, record_new);
    {
        date_t drc_begin = (diag == NULL) ? 0 : cm_now();

        if (drc_get_page_master_id(page_id, &item->master_id) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY][local rcy] failed to get master id of page [%u-%u]", page_id.file, page_id.page);
            return OG_ERROR;
        }
        if (diag != NULL) {
            diag->drc_master_us += (uint64)(cm_now() - drc_begin);
        }
    }
    dtc_rcy_local_add_to_bucket(bucket, item);
    dtc_rcy_local_append_merge_shard_chain(local, item, page_id);
    dtc_rcy_local_append_active_shard_chain(local, item);
    if (diag != NULL) {
        diag->record_us += (uint64)(cm_now() - record_begin);
    }
    (void)session;
    return OG_SUCCESS;
}

static status_t dtc_rcy_record_page_local(uint32 worker_slot, page_id_t page_id, uint64 lsn, uint64 batch_lfn,
    uint32 pcn, dtc_rcy_analysis_group_diag_t *diag, dtc_rcy_analysis_group_count_t *counts)
{
    dtc_rcy_local_set_t *local = &g_analyze_paral_mgr.local_rcy[worker_slot];

    return dtc_rcy_record_page_into_local(NULL, local, page_id, lsn, batch_lfn, pcn, diag, counts);
}

void dtc_rcy_rbp_analyze_leave_into_local(dtc_rcy_local_set_t *local, page_id_t page_id, uint32 node_id,
    uint64 batch_lfn, uint64 changed_lsn, dtc_rcy_analysis_group_diag_t *diag,
    dtc_rcy_analysis_group_count_t *counts)
{
    uint32 hash_id;
    rcy_local_bucket_t *bucket;
    rcy_set_item_t *item;
    date_t partial_begin = (diag == NULL) ? 0 : cm_now();

    DTC_RCY_DIAG_INC(diag, counts, partial_calls);
    if (local == NULL || !local->inited || node_id >= OG_MAX_INSTANCES || batch_lfn == 0 || changed_lsn == 0) {
        goto end;
    }
    hash_id = dtc_rcy_bucket_hash(page_id, local->bucket_num);
    bucket = &local->buckets[hash_id];
    item = dtc_rcy_local_get_item(bucket, page_id);
    if (item == NULL || !item->need_replay) {
        goto end;
    }
    item->analyze_rbp.touched = OG_TRUE;
    if (changed_lsn > item->analyze_rbp.expect_lsn) {
        item->analyze_rbp.expect_lsn = changed_lsn;
        item->analyze_rbp.expect_lfn = batch_lfn;
    }
    dtc_rcy_rbp_analyze_touch_apply(&item->analyze_rbp, node_id, batch_lfn);
end:
    if (diag != NULL) {
        diag->partial_us += (uint64)(cm_now() - partial_begin);
    }
}

static void dtc_rcy_rbp_analyze_leave_local(uint32 worker_slot, page_id_t page_id, uint32 node_id, uint64 batch_lfn,
    uint64 changed_lsn, dtc_rcy_analysis_group_diag_t *diag, dtc_rcy_analysis_group_count_t *counts)
{
    dtc_rcy_local_set_t *local = &g_analyze_paral_mgr.local_rcy[worker_slot];

    dtc_rcy_rbp_analyze_leave_into_local(local, page_id, node_id, batch_lfn, changed_lsn, diag, counts);
}

void dtc_rcy_record_space_id_into_local(dtc_rcy_local_set_t *local, uint32 space_id)
{
    uint32 *space_id_set;

    if (local == NULL || !local->inited) {
        return;
    }
    space_id_set = local->space_id_set;
    for (uint32 i = 0; i < local->space_set_size; i++) {
        if (space_id == space_id_set[i]) {
            return;
        }
    }
    if (local->space_set_size >= OG_MAX_SPACES) {
        return;
    }
    space_id_set[local->space_set_size++] = space_id;
}

static void dtc_rcy_record_space_id_local(uint32 worker_slot, uint32 space_id)
{
    dtc_rcy_record_space_id_into_local(&g_analyze_paral_mgr.local_rcy[worker_slot], space_id);
}

#if DTC_RCY_USE_LEGACY_FINALIZE
static uint64 dtc_rcy_count_global_rcy_pool_items(const rcy_set_t *rcy_set)
{
    rcy_set_item_pool_t *pool = rcy_set->item_pools;
    uint64 count = 0;

    while (pool != NULL) {
        count += (uint64)pool->hwm;
        pool = pool->next;
    }
    return count;
}

static status_t dtc_rcy_merge_local_rcy_sets(knl_session_t *session, dtc_rcy_local_finalize_stat_t *stat)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_item_pool_t *pool;
    date_t begin = cm_now();

    for (uint32 slot = 0; slot < PARAL_ANALYZE_THREAD_NUM; slot++) {
        dtc_rcy_local_set_t *local = &g_analyze_paral_mgr.local_rcy[slot];
        if (!local->inited) {
            continue;
        }
        pool = local->item_pools;
        while (pool != NULL) {
            for (int64 i = 0; i < pool->hwm; i++) {
                stat->local_items_scanned++;
                if (dtc_rcy_merge_local_item_into_global(rcy_set, &pool->items[i], stat) != OG_SUCCESS) {
                    return OG_ERROR;
                }
            }
            pool = pool->next;
        }
    }
    stat->merge_us = (uint64)(cm_now() - begin);
    stat->global_items_after = dtc_rcy_count_global_rcy_pool_items(rcy_set);
    rcy_set->size = stat->global_items_after;
    (void)session;
    return OG_SUCCESS;
}
#endif

static void dtc_rcy_merge_local_space_ids(dtc_rcy_local_finalize_stat_t *stat)
{
    date_t begin = cm_now();

    for (uint32 slot = 0; slot < PARAL_ANALYZE_THREAD_NUM; slot++) {
        dtc_rcy_local_set_t *local = &g_analyze_paral_mgr.local_rcy[slot];
        if (!local->inited) {
            continue;
        }
        for (uint32 i = 0; i < local->space_set_size; i++) {
            dtc_record_space_id(local->space_id_set[i]);
        }
    }
    stat->merge_space_us = (uint64)(cm_now() - begin);
}

static void dtc_rcy_merge_space_ids_from_locals(dtc_rcy_local_set_t *locals, uint32 local_count,
    dtc_rcy_local_finalize_stat_t *stat)
{
    date_t begin = cm_now();

    for (uint32 slot = 0; slot < local_count; slot++) {
        dtc_rcy_local_set_t *local = &locals[slot];
        if (!local->inited) {
            continue;
        }
        for (uint32 i = 0; i < local->space_set_size; i++) {
            dtc_record_space_id(local->space_id_set[i]);
        }
    }
    stat->merge_space_us += (uint64)(cm_now() - begin);
}

static void dtc_rcy_rbp_partial_materialize_apply_overflow(rbp_partial_context_t *ctx, rbp_partial_item_t *item,
    uint64 overflow_bitmap, bool32 overflow_before, dtc_rcy_local_finalize_stat_t *stat)
{
    bool32 disable_logged = OG_FALSE;

    if (!item->touch_overflow) {
        return;
    }
    cm_spin_lock(&ctx->lock, NULL);
    if (!overflow_before) {
        if (stat != NULL) {
            stat->partial_touch_overflow++;
        }
        ctx->overflow_items++;
    }
    for (uint32 overflow_node = 0; overflow_node < OG_MAX_INSTANCES; overflow_node++) {
        if ((overflow_bitmap & ((uint64)1 << overflow_node)) != 0) {
            if (dtc_rcy_rbp_partial_disable_jump_locked(overflow_node)) {
                disable_logged = OG_TRUE;
            }
        }
    }
    cm_spin_unlock(&ctx->lock);
    if (disable_logged) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] disable staged jump on overflow apply page %u-%u",
                       item->page_id.file, item->page_id.page);
    }
}

static void dtc_rcy_rbp_partial_materialize_merge_existing(rbp_partial_item_t *item, rcy_set_item_t *rcy_item,
    rbp_partial_context_t *ctx, dtc_rcy_local_finalize_stat_t *stat)
{
    rcy_set_analyze_rbp_t merged;
    bool32 overflow_before = item->touch_overflow;
    errno_t ret;

    item->rcy_item = rcy_item;
    if (!rcy_item->analyze_rbp.touched) {
        return;
    }
    ret = memset_sp(&merged, sizeof(merged), 0, sizeof(merged));
    knl_securec_check(ret);
    merged.expect_lsn = item->expect_lsn;
    merged.expect_lfn = item->expect_lfn;
    merged.touch_overflow = item->touch_overflow;
    merged.touched = OG_TRUE;
    ret = memcpy_sp(merged.touches, sizeof(merged.touches), item->touches, sizeof(item->touches));
    knl_securec_check(ret);
    dtc_rcy_rbp_analyze_merge_meta(&merged, &rcy_item->analyze_rbp);
    item->expect_lsn = merged.expect_lsn;
    item->expect_lfn = merged.expect_lfn;
    item->touch_overflow = merged.touch_overflow;
    ret = memcpy_sp(item->touches, sizeof(item->touches), merged.touches, sizeof(merged.touches));
    knl_securec_check(ret);
    dtc_rcy_rbp_partial_materialize_apply_overflow(ctx, item, merged.overflow_disable_bitmap, overflow_before, stat);
}

#if DTC_RCY_USE_LEGACY_FINALIZE
static rbp_partial_item_t *dtc_rcy_rbp_partial_materialize_one(rbp_partial_context_t *ctx, page_id_t page_id,
    rcy_set_item_t *rcy_item, dtc_rcy_local_finalize_stat_t *stat)
{
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, ctx->bucket_num);
    rbp_partial_bucket_t *bucket = &ctx->buckets[hash_id];
    rbp_partial_item_t *item = NULL;
    errno_t ret;

    cm_spin_lock(&bucket->lock, NULL);
    item = dtc_rcy_rbp_partial_find_locked(bucket, page_id);
    if (item != NULL) {
        dtc_rcy_rbp_partial_materialize_merge_existing(item, rcy_item, ctx, stat);
        cm_spin_unlock(&bucket->lock);
        return item;
    }
    item = dtc_rcy_rbp_partial_alloc_item(ctx, NULL);
    if (item == NULL) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }
    item->page_id = page_id;
    item->rcy_item = rcy_item;
    item->expect_lsn = rcy_item->analyze_rbp.expect_lsn;
    item->expect_lfn = rcy_item->analyze_rbp.expect_lfn;
    item->touch_overflow = rcy_item->analyze_rbp.touch_overflow;
    item->best_lsn = 0;
    item->best_source_node = OG_INVALID_ID32;
    item->next = bucket->first;
    bucket->first = item;
    bucket->count++;
    ret = memcpy_sp(item->touches, sizeof(item->touches), rcy_item->analyze_rbp.touches,
                    sizeof(rcy_item->analyze_rbp.touches));
    knl_securec_check(ret);
    cm_spin_unlock(&bucket->lock);
    stat->partial_items_created++;
    dtc_rcy_rbp_partial_materialize_apply_overflow(ctx, item, rcy_item->analyze_rbp.overflow_disable_bitmap,
        OG_FALSE, stat);
    return item;
}

static status_t dtc_rcy_rbp_partial_materialize_from_rcy_set(knl_session_t *session,
    dtc_rcy_local_finalize_stat_t *stat)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_item_pool_t *pool;
    date_t begin = cm_now();
    date_t init_begin = cm_now();

    if (!dtc_rcy_rbp_partial_collecting(session)) {
        stat->materialize_us = 0;
        return OG_SUCCESS;
    }
    if (dtc_rcy_rbp_partial_alloc_side_table(ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ctx->overflow_items = 0;
    stat->materialize_init_us = (uint64)(cm_now() - init_begin);
    pool = rcy_set->item_pools;
    while (pool != NULL) {
        for (int64 i = 0; i < pool->hwm; i++) {
            rcy_set_item_t *rcy_item = &pool->items[i];
            stat->rcy_items_scanned++;
            if (!rcy_item->need_replay || !rcy_item->analyze_rbp.touched || rcy_item->analyze_rbp.expect_lsn == 0) {
                continue;
            }
            if (dtc_rcy_rbp_partial_materialize_one(ctx, rcy_item->page_id, rcy_item, stat) == NULL) {
                OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] materialize failed page %u-%u", rcy_item->page_id.file,
                               rcy_item->page_id.page);
                return OG_ERROR;
            }
        }
        pool = pool->next;
    }
    stat->materialize_us = (uint64)(cm_now() - begin);
    OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] materialize done: partial_items=%llu rcy_scanned=%llu",
                     stat->partial_items_created, stat->rcy_items_scanned);
    return OG_SUCCESS;
}
#endif

status_t dtc_rcy_rbp_partial_materialize_global(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_item_pool_t *pool;
    dtc_rcy_merge_shard_stat_t stat = { 0 };
    date_t begin = cm_now();
    date_t init_begin = cm_now();

    if (!dtc_rcy_rbp_partial_collecting(session)) {
        return OG_SUCCESS;
    }
    if (dtc_rcy_rbp_partial_alloc_side_table(ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ctx->overflow_items = 0;
    stat.partial_global_lock_us += (uint64)(cm_now() - init_begin);

    pool = rcy_set->item_pools;
    while (pool != NULL) {
        for (int64 i = 0; i < pool->hwm; i++) {
            rcy_set_item_t *rcy_item = &pool->items[i];

            stat.rcy_items_scanned++;
            if (!rcy_item->need_replay || !rcy_item->analyze_rbp.touched || rcy_item->analyze_rbp.expect_lsn == 0) {
                continue;
            }
            if (dtc_rcy_merge_partial_apply_one(ctx, NULL, rcy_item->page_id, rcy_item, &stat) == NULL) {
                OG_LOG_RUN_ERR("[DTC RBP RT] materialize partial side table failed page %u-%u",
                               rcy_item->page_id.file, rcy_item->page_id.page);
                return OG_ERROR;
            }
        }
        pool = pool->next;
    }

    OG_LOG_RUN_INF("[DTC RBP RT] materialize global partial done: rcy_scanned=%llu partial_items=%llu "
                   "partial_touch_overflow=%llu elapsed_us=%llu",
                   stat.rcy_items_scanned, stat.partial_items_created, stat.partial_touch_overflow,
                   (uint64)(cm_now() - begin));
    return OG_SUCCESS;
}

static void dtc_rcy_log_analyze_finalize_stats(const dtc_rcy_analysis_main_stat_t *main_stat,
    const dtc_rcy_local_finalize_stat_t *stat)
{
    OG_LOG_RUN_INF("[DTC RCY][analysis finalize summary] finalize_us=%llu merge_us=%llu merge_rcy_us=%llu "
                   "merge_partial_us=%llu materialize_us=%llu wait_free_us=%llu merge_fused=%u "
                   "partial_items=%llu rcy_scanned=%llu merge_scan_skipped=%llu rbp_partial_item_count=%llu",
                   stat->finalize_us, stat->merge_us, stat->merge_rcy_us, stat->merge_partial_us,
                   stat->materialize_us, main_stat != NULL ? main_stat->wait_free_us : 0ULL,
                   (uint32)stat->merge_fused, stat->partial_items_created, stat->rcy_items_scanned,
                   stat->merge_scan_skipped, (uint64)DTC_RCY_CONTEXT->rbp_partial_ctx.item_count);
    if (stat->finalize_us >= DTC_RCY_ANALYZE_FINALIZE_SLOW_US) {
        OG_LOG_RUN_WAR("[DTC RCY][analysis finalize slow] finalize_us=%llu merge_us=%llu merge_rcy_us=%llu "
                       "merge_partial_us=%llu materialize_us=%llu partial_items_created=%llu merge_scan_skipped=%llu",
                       stat->finalize_us, stat->merge_us, stat->merge_rcy_us, stat->merge_partial_us,
                       stat->materialize_us, stat->partial_items_created, stat->merge_scan_skipped);
    }
}

static status_t dtc_rcy_analyze_finalize_local(knl_session_t *session, const dtc_rcy_analysis_main_stat_t *main_stat)
{
    dtc_rcy_local_finalize_stat_t stat = { 0 };
    date_t begin = cm_now();
    status_t ret = OG_SUCCESS;

    if (!g_analyze_paral_mgr.local_rcy_inited) {
        return OG_SUCCESS;
    }
#if DTC_RCY_USE_LEGACY_FINALIZE
    ret = dtc_rcy_merge_local_rcy_sets(session, &stat);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
    dtc_rcy_merge_local_space_ids(&stat);
    ret = dtc_rcy_rbp_partial_materialize_from_rcy_set(session, &stat);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
#else
    if (dtc_rcy_rbp_partial_collecting(session)) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
        date_t init_begin = cm_now();

        ret = dtc_rcy_rbp_partial_alloc_side_table(ctx);
        if (ret != OG_SUCCESS) {
            goto cleanup;
        }
        ctx->overflow_items = 0;
        stat.materialize_init_us = (uint64)(cm_now() - init_begin);
    }
    ret = dtc_rcy_merge_local_rcy_sets_sharded(session, g_analyze_paral_mgr.local_rcy, PARAL_ANALYZE_THREAD_NUM,
        NULL, NULL, OG_FALSE, &stat);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
    dtc_rcy_merge_local_space_ids(&stat);
#endif
    stat.finalize_us = (uint64)(cm_now() - begin);
    dtc_rcy_log_analyze_finalize_stats(main_stat, &stat);
cleanup:
    dtc_rcy_local_sets_clear_all();
    return ret;
}

status_t dtc_rcy_merge_local_sets_to_recovery(knl_session_t *session, dtc_rcy_local_set_t *locals,
    uint32 local_count, dtc_rcy_local_item_filter_t filter, void *filter_arg, bool32 clear_after, const char *tag)
{
    dtc_rcy_local_finalize_stat_t stat = { 0 };
    date_t begin = cm_now();
    status_t ret = OG_SUCCESS;

    if (locals == NULL || local_count == 0) {
        return OG_SUCCESS;
    }
    if (dtc_rcy_rbp_partial_collecting(session)) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
        date_t init_begin = cm_now();

        ret = dtc_rcy_rbp_partial_alloc_side_table(ctx);
        if (ret != OG_SUCCESS) {
            goto cleanup;
        }
        stat.materialize_init_us = (uint64)(cm_now() - init_begin);
    }
    ret = dtc_rcy_merge_local_rcy_sets_sharded(session, locals, local_count, filter, filter_arg, OG_FALSE, &stat);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
    dtc_rcy_merge_space_ids_from_locals(locals, local_count, &stat);
    stat.finalize_us = (uint64)(cm_now() - begin);
    OG_LOG_RUN_INF("[DTC RCY][local merge] %s finalize_us=%llu merge_us=%llu merge_rcy_us=%llu "
                   "merge_partial_us=%llu partial_items=%llu rcy_scanned=%llu skipped=%llu global_items=%llu",
                   (tag == NULL) ? "merge" : tag, stat.finalize_us, stat.merge_us, stat.merge_rcy_us,
                   stat.merge_partial_us, stat.partial_items_created, stat.rcy_items_scanned,
                   stat.merge_scan_skipped, stat.global_items_after);

cleanup:
    if (clear_after) {
        for (uint32 i = 0; i < local_count; i++) {
            dtc_rcy_local_set_clear(&locals[i]);
        }
    }
    return ret;
}

status_t dtc_rcy_merge_active_local_sets_to_recovery(knl_session_t *session, dtc_rcy_local_set_t *locals,
    uint32 local_count, dtc_rcy_local_item_filter_t filter, void *filter_arg, bool32 clear_after, const char *tag)
{
    dtc_rcy_local_finalize_stat_t stat = { 0 };
    date_t begin = cm_now();
    status_t ret = OG_SUCCESS;
    uint64 active_items = 0;

    if (locals == NULL || local_count == 0) {
        return OG_SUCCESS;
    }
    for (uint32 i = 0; i < local_count; i++) {
        if (!dtc_rcy_local_set_active_ready(&locals[i])) {
            OG_LOG_RUN_WAR("[DTC RCY][local merge] %s active merge fallback required: owner=%u ready=%u",
                           (tag == NULL) ? "merge" : tag, i, (uint32)dtc_rcy_local_set_active_ready(&locals[i]));
            return OG_ERROR;
        }
        active_items += locals[i].active_item_count;
    }
    if (dtc_rcy_rbp_partial_collecting(session)) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
        date_t init_begin = cm_now();

        ret = dtc_rcy_rbp_partial_alloc_side_table(ctx);
        if (ret != OG_SUCCESS) {
            goto cleanup;
        }
        stat.materialize_init_us = (uint64)(cm_now() - init_begin);
    }
    ret = dtc_rcy_merge_local_rcy_sets_sharded(session, locals, local_count, filter, filter_arg, OG_TRUE, &stat);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
    dtc_rcy_merge_space_ids_from_locals(locals, local_count, &stat);
    stat.finalize_us = (uint64)(cm_now() - begin);
    OG_LOG_RUN_INF("[DTC RCY][local merge] %s active finalize_us=%llu merge_us=%llu merge_rcy_us=%llu "
                   "merge_partial_us=%llu active_items=%llu partial_items=%llu rcy_scanned=%llu skipped=%llu "
                   "global_items=%llu",
                   (tag == NULL) ? "merge" : tag, stat.finalize_us, stat.merge_us, stat.merge_rcy_us,
                   stat.merge_partial_us, active_items, stat.partial_items_created, stat.rcy_items_scanned,
                   stat.merge_scan_skipped, stat.global_items_after);

cleanup:
    if (clear_after) {
        for (uint32 i = 0; i < local_count; i++) {
            dtc_rcy_local_set_clear(&locals[i]);
        }
    }
    return ret;
}

status_t dtc_rcy_merge_compact_local_sets_to_recovery(knl_session_t *session, dtc_rcy_local_set_t *locals,
    uint32 local_count, dtc_rcy_local_item_filter_t filter, void *filter_arg, bool32 clear_after, const char *tag)
{
    dtc_rcy_local_finalize_stat_t stat = { 0 };
    dtc_rcy_local_set_t compact_local;
    date_t begin = cm_now();
    uint64 compact_unique = 0;
    uint64 compact_duplicate = 0;
    uint64 compact_us = 0;
    uint64 compact_worker_us = 0;
    status_t ret = OG_SUCCESS;

    if (locals == NULL || local_count == 0) {
        return OG_SUCCESS;
    }
    if (dtc_rcy_rbp_partial_collecting(session)) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
        date_t init_begin = cm_now();

        ret = dtc_rcy_rbp_partial_alloc_side_table(ctx);
        if (ret != OG_SUCCESS) {
            goto cleanup;
        }
        stat.materialize_init_us = (uint64)(cm_now() - init_begin);
    }
    ret = dtc_rcy_compact_local_sets_for_merge(locals, local_count, filter, filter_arg, &compact_local, &stat,
        &compact_unique, &compact_duplicate, &compact_us, &compact_worker_us);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
    ret = dtc_rcy_merge_local_rcy_sets_sharded(session, &compact_local, 1, NULL, NULL, OG_FALSE, &stat);
    if (ret != OG_SUCCESS) {
        goto cleanup;
    }
    dtc_rcy_merge_space_ids_from_locals(locals, local_count, &stat);
    stat.finalize_us = (uint64)(cm_now() - begin);
    OG_LOG_RUN_INF("[DTC RCY][local merge] %s finalize_us=%llu compact_us=%llu compact_worker_us=%llu "
                   "merge_us=%llu merge_rcy_us=%llu merge_partial_us=%llu compact_unique=%llu compact_dup=%llu "
                   "partial_items=%llu rcy_scanned=%llu scanned=%llu skipped=%llu global_items=%llu",
                   (tag == NULL) ? "merge" : tag, stat.finalize_us, compact_us, compact_worker_us, stat.merge_us,
                   stat.merge_rcy_us, stat.merge_partial_us, compact_unique, compact_duplicate,
                   stat.partial_items_created, stat.rcy_items_scanned, stat.merge_scan_total, stat.merge_scan_skipped,
                   stat.global_items_after);

cleanup:
    if (clear_after) {
        for (uint32 i = 0; i < local_count; i++) {
            dtc_rcy_local_set_clear(&locals[i]);
        }
    }
    return ret;
}

bool32 dtc_rcy_rbp_partial_enabled(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    return (bool32)(dtc_rcy->in_progress && !dtc_rcy->full_recovery && KNL_RBP_ENABLE(session->kernel) &&
                    KNL_RBP_FOR_RECOVERY(session->kernel) && dtc_rcy->rbp_partial_ctx.enabled);
}

static rbp_partial_item_pool_t *dtc_rcy_rbp_partial_alloc_pool(void)
{
    uint64 pool_size = sizeof(rbp_partial_item_pool_t) +
        (uint64)RBP_PARTIAL_ITEM_POOL_SIZE * sizeof(rbp_partial_item_t);
    rbp_partial_item_pool_t *pool = (rbp_partial_item_pool_t *)malloc(pool_size);
    errno_t ret;

    if (pool == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] failed to alloc partial item pool, size=%llu", pool_size);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, pool_size, "rbp partial recovery item pool");
        return NULL;
    }

    ret = memset_sp(pool, pool_size, 0, pool_size);
    knl_securec_check(ret);
    pool->items = (rbp_partial_item_t *)((char *)pool + sizeof(rbp_partial_item_pool_t));
    return pool;
}

static status_t dtc_rcy_rbp_partial_alloc_side_table(rbp_partial_context_t *ctx)
{
    uint64 bucket_size;
    errno_t ret;

    if (ctx->enabled) {
        return OG_SUCCESS;
    }

    ctx->bucket_num = RBP_PARTIAL_BUCKET_NUM;
    bucket_size = (uint64)ctx->bucket_num * sizeof(rbp_partial_bucket_t);
    ctx->buckets = (rbp_partial_bucket_t *)malloc(bucket_size);
    if (ctx->buckets == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] failed to alloc partial buckets, size=%llu", bucket_size);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, bucket_size, "rbp partial recovery buckets");
        return OG_ERROR;
    }
    ret = memset_sp(ctx->buckets, bucket_size, 0, bucket_size);
    knl_securec_check(ret);

    ctx->item_pools = dtc_rcy_rbp_partial_alloc_pool();
    if (ctx->item_pools == NULL) {
        CM_FREE_PTR(ctx->buckets);
        return OG_ERROR;
    }
    ctx->curr_item_pool = ctx->item_pools;
    ctx->enabled = OG_TRUE;
    ctx->required_built = OG_FALSE;
    ctx->required_count = 0;
    ctx->required_capacity = 0;
    ctx->item_count = 0;
    ctx->overflow_items = 0;
    ctx->miss_count = 0;
    OG_LOG_RUN_INF("[DTC RCY][RBP][partial] side table allocated: buckets=%u item_pool_size=%u",
                   ctx->bucket_num, (uint32)RBP_PARTIAL_ITEM_POOL_SIZE);
    return OG_SUCCESS;
}

static void dtc_rcy_rbp_partial_reset_analyze_state(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    dtc_rcy_rbp_reset_lfn_point_maps(dtc_rcy);
    session->kernel->redo_ctx.rbp_aly_lsn = 0;
    session->kernel->redo_ctx.redo_end_point.lfn = 0;
    rbp_reset_unsafe(session);
}

static void dtc_rcy_runtime_reset_rcy_set(rcy_set_t *rcy_set)
{
    rcy_set_item_pool_t *base_pool = rcy_set->item_pools;
    rcy_set_item_pool_t *pool;
    rcy_set_item_pool_t *next;
    errno_t ret;

    if (rcy_set->buckets != NULL && rcy_set->bucket_num != 0) {
        ret = memset_sp(rcy_set->buckets, (uint64)rcy_set->bucket_num * sizeof(rcy_set_bucket_t), 0,
                        (uint64)rcy_set->bucket_num * sizeof(rcy_set_bucket_t));
        knl_securec_check(ret);
    }

    if (base_pool != NULL) {
        pool = base_pool->next;
        while (pool != NULL) {
            next = pool->next;
            CM_FREE_PTR(pool);
            pool = next;
        }
        base_pool->hwm = 0;
        base_pool->next = NULL;
    }
    rcy_set->curr_item_pools = base_pool;
    rcy_set->size = 0;

    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        CM_FREE_PTR(rcy_set->pages[i]);
        rcy_set->page_count[i] = 0;
    }
    ret = memset_sp(rcy_set->space_id_set, sizeof(rcy_set->space_id_set), OG_INVALID_ID32,
                    sizeof(rcy_set->space_id_set));
    knl_securec_check(ret);
    rcy_set->space_set_size = 0;
}

static status_t dtc_rcy_runtime_reset_result(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;

    dtc_rcy_runtime_reset_rcy_set(rcy_set);
    if (rcy_set->item_pools == NULL) {
        rcy_set->item_pools = dtc_rcy_alloc_itempool(rcy_set);
        if (rcy_set->item_pools == NULL) {
            return OG_ERROR;
        }
        rcy_set->curr_item_pools = rcy_set->item_pools;
    }
    dtc_rcy_rbp_partial_clear(dtc_rcy);
    dtc_rcy_rbp_clear_lfn_point_maps(dtc_rcy);
    dtc_rcy_rbp_partial_reset_analyze_state(session);
    return OG_SUCCESS;
}

static status_t dtc_rcy_rbp_partial_init(knl_session_t *session)
{
    rbp_partial_context_t *ctx = &DTC_RCY_CONTEXT->rbp_partial_ctx;
    bool32 first_alloc = (bool32)!ctx->enabled;

    if (dtc_rcy_rbp_partial_alloc_side_table(ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (first_alloc) {
        dtc_rcy_rbp_partial_reset_analyze_state(session);
    }
    return OG_SUCCESS;
}

static void dtc_rcy_rbp_partial_reset_candidate_items(rbp_partial_context_t *ctx)
{
    errno_t ret;

    if (ctx->candidate_items == NULL || ctx->candidate_capacity == 0) {
        return;
    }

    for (uint32 i = 0; i < ctx->candidate_capacity; i++) {
        rbp_partial_candidate_t *candidate = &ctx->candidate_items[i];
        if (candidate->used && candidate->item != NULL && candidate->item->candidate == candidate) {
            candidate->item->candidate = NULL;
        }
    }
    ret = memset_sp(ctx->candidate_items, (size_t)ctx->candidate_capacity * sizeof(rbp_partial_candidate_t), 0,
                    (size_t)ctx->candidate_capacity * sizeof(rbp_partial_candidate_t));
    knl_securec_check(ret);
    ctx->candidate_count = 0;
    ctx->candidate_clock = 0;
}

static void dtc_rcy_rbp_partial_free_candidate_cache(rbp_partial_context_t *ctx)
{
    dtc_rcy_rbp_partial_reset_candidate_items(ctx);
    CM_FREE_PTR(ctx->candidate_items);
    CM_FREE_PTR(ctx->candidate_pages);
    ctx->candidate_capacity = 0;
    ctx->candidate_page_size = 0;
}

bool32 dtc_rcy_rbp_partial_copy_candidate(knl_session_t *session, rbp_partial_item_t *item, char *page_buf,
    uint32 buf_size, uint64 *page_lsn, uint32 *source_node)
{
    rbp_partial_context_t *ctx = &DTC_RCY_CONTEXT->rbp_partial_ctx;
    rbp_partial_candidate_t *candidate;
    errno_t ret;

    if (item == NULL || page_buf == NULL || !ctx->enabled) {
        return OG_FALSE;
    }

    cm_spin_lock(&ctx->lock, NULL);
    candidate = item->candidate;
    if (candidate == NULL || !candidate->used || candidate->page == NULL || candidate->item != item ||
        !IS_SAME_PAGID(candidate->page_id, item->page_id)) {
        ctx->candidate_miss_count++;
        cm_spin_unlock(&ctx->lock);
        return OG_FALSE;
    }

    ret = memcpy_sp(page_buf, buf_size, candidate->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    if (page_lsn != NULL) {
        *page_lsn = candidate->page_lsn;
    }
    if (source_node != NULL) {
        *source_node = candidate->source_node;
    }
    ctx->candidate_hit_count++;
    cm_spin_unlock(&ctx->lock);
    return OG_TRUE;
}

void dtc_rcy_rbp_partial_clear(dtc_rcy_context_t *dtc_rcy)
{
    rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
    rbp_partial_item_pool_t *pool = ctx->item_pools;
    rbp_partial_item_pool_t *next = NULL;
    errno_t ret;

    while (pool != NULL) {
        next = pool->next;
        CM_FREE_PTR(pool);
        pool = next;
    }
    dtc_rcy_rbp_partial_free_candidate_cache(ctx);
    CM_FREE_PTR(ctx->buckets);
    CM_FREE_PTR(ctx->required_items);
    ret = memset_sp(ctx, sizeof(rbp_partial_context_t), 0, sizeof(rbp_partial_context_t));
    knl_securec_check(ret);
    ret = memset_sp(dtc_rcy->rbp_partial_jump_disabled, sizeof(dtc_rcy->rbp_partial_jump_disabled), 0,
                    sizeof(dtc_rcy->rbp_partial_jump_disabled));
    knl_securec_check(ret);
    dtc_rcy->rbp_partial_disabled_count = 0;
}

static rbp_partial_item_t *dtc_rcy_rbp_partial_find_locked(rbp_partial_bucket_t *bucket, page_id_t page_id)
{
    rbp_partial_item_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }
        item = item->next;
    }
    return NULL;
}

rbp_partial_item_t *dtc_rcy_rbp_partial_get_item(page_id_t page_id)
{
    rbp_partial_context_t *ctx = &DTC_RCY_CONTEXT->rbp_partial_ctx;
    uint32 hash_id;

    if (!ctx->enabled || ctx->buckets == NULL || ctx->bucket_num == 0) {
        return NULL;
    }
    hash_id = dtc_rcy_bucket_hash(page_id, ctx->bucket_num);
    return dtc_rcy_rbp_partial_find_locked(&ctx->buckets[hash_id], page_id);
}

static rbp_partial_item_t *dtc_rcy_rbp_partial_alloc_item(rbp_partial_context_t *ctx,
    dtc_rcy_analysis_group_diag_t *diag)
{
    rbp_partial_item_pool_t *pool;
    rbp_partial_item_t *item;
    date_t lock_begin = (diag == NULL) ? 0 : cm_now();

    cm_spin_lock(&ctx->lock, NULL);
    pool = ctx->curr_item_pool;
    if (pool->hwm >= RBP_PARTIAL_ITEM_POOL_SIZE) {
        date_t alloc_begin = (diag == NULL) ? 0 : cm_now();
        rbp_partial_item_pool_t *new_pool = dtc_rcy_rbp_partial_alloc_pool();
        if (diag != NULL) {
            diag->partial_alloc_pool_us += (uint64)(cm_now() - alloc_begin);
        }
        if (new_pool == NULL) {
            cm_spin_unlock(&ctx->lock);
            if (diag != NULL) {
                diag->partial_global_lock_us += (uint64)(cm_now() - lock_begin);
            }
            return NULL;
        }
        pool->next = new_pool;
        ctx->curr_item_pool = new_pool;
        pool = new_pool;
    }
    item = &pool->items[pool->hwm++];
    ctx->item_count++;
    cm_spin_unlock(&ctx->lock);
    if (diag != NULL) {
        diag->partial_global_lock_us += (uint64)(cm_now() - lock_begin);
    }
    return item;
}

static rbp_partial_item_t *dtc_rcy_rbp_partial_get_or_create(page_id_t page_id, rcy_set_item_t *rcy_item,
    bool32 *created, dtc_rcy_analysis_group_diag_t *diag)
{
    rbp_partial_context_t *ctx = &DTC_RCY_CONTEXT->rbp_partial_ctx;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, ctx->bucket_num);
    rbp_partial_bucket_t *bucket = &ctx->buckets[hash_id];
    rbp_partial_item_t *item;
    date_t lock_begin = (diag == NULL) ? 0 : cm_now();

    if (created != NULL) {
        *created = OG_FALSE;
    }
    cm_spin_lock(&bucket->lock, NULL);
    item = dtc_rcy_rbp_partial_find_locked(bucket, page_id);
    if (item != NULL) {
        item->rcy_item = rcy_item;
        if (diag != NULL) {
            diag->partial_hit++;
        }
        cm_spin_unlock(&bucket->lock);
        if (diag != NULL) {
            diag->partial_bucket_lock_us += (uint64)(cm_now() - lock_begin);
        }
        return item;
    }

    item = dtc_rcy_rbp_partial_alloc_item(ctx, diag);
    if (item == NULL) {
        cm_spin_unlock(&bucket->lock);
        if (diag != NULL) {
            diag->partial_bucket_lock_us += (uint64)(cm_now() - lock_begin);
        }
        return NULL;
    }
    item->page_id = page_id;
    item->rcy_item = rcy_item;
    item->best_lsn = 0;
    item->best_source_node = OG_INVALID_ID32;
    item->next = bucket->first;
    bucket->first = item;
    bucket->count++;
    if (created != NULL) {
        *created = OG_TRUE;
    }
    if (diag != NULL) {
        diag->partial_created++;
    }
    cm_spin_unlock(&bucket->lock);
    if (diag != NULL) {
        diag->partial_bucket_lock_us += (uint64)(cm_now() - lock_begin);
    }
    return item;
}

static bool32 dtc_rcy_rbp_partial_disable_jump_locked(uint32 node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    if (node_id >= OG_MAX_INSTANCES) {
        return OG_FALSE;
    }
    if (!dtc_rcy->rbp_partial_jump_disabled[node_id]) {
        dtc_rcy->rbp_partial_jump_disabled[node_id] = OG_TRUE;
        dtc_rcy->rbp_partial_disabled_count++;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void dtc_rcy_rbp_partial_disable_jump(uint32 node_id, rbp_partial_item_t *item)
{
    if (dtc_rcy_rbp_partial_disable_jump_locked(node_id)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] disable node %u staged jump because page %u-%u exceeded %u touch slots",
                       node_id, item->page_id.file, item->page_id.page, (uint32)RBP_PARTIAL_TOUCH_SLOT_COUNT);
    }
}

static void dtc_rcy_rbp_partial_record_changed(knl_session_t *session, page_id_t page_id, uint32 node_id,
    uint64 batch_lfn, uint64 changed_lsn, dtc_rcy_analysis_group_diag_t *diag,
    dtc_rcy_analysis_group_count_t *counts)
{
    rcy_set_item_t *rcy_item;
    rbp_partial_item_t *item;
    bool32 created = OG_FALSE;
    date_t partial_begin = (diag == NULL) ? 0 : cm_now();

    DTC_RCY_DIAG_INC(diag, counts, partial_calls);
    if (!dtc_rcy_rbp_partial_collecting(session)) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip not_collecting: page %u-%u node=%u "
                         "batch_lfn=%llu changed_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn);
        goto end;
    }
    if (node_id >= OG_MAX_INSTANCES) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip invalid_node: page %u-%u node=%u "
                         "batch_lfn=%llu changed_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn);
        goto end;
    }
    if (batch_lfn == 0) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip batch_lfn_zero: page %u-%u node=%u "
                         "changed_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)changed_lsn);
        goto end;
    }
    if (changed_lsn == 0) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip changed_lsn_zero: page %u-%u node=%u "
                         "batch_lfn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn);
        goto end;
    }
    date_t lookup_begin = (diag == NULL) ? 0 : cm_now();
    rcy_item = dtc_rcy_get_item_internal(page_id);
    if (diag != NULL) {
        diag->rcy_lookup_us += (uint64)(cm_now() - lookup_begin);
    }
    if (rcy_item == NULL) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip no_rcy_item: page %u-%u node=%u "
                         "batch_lfn=%llu changed_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn);
        goto end;
    }
    if (!rcy_item->need_replay) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip no_need_replay: page %u-%u node=%u "
                         "batch_lfn=%llu changed_lsn=%llu last_dirty_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn,
                         (uint64)rcy_item->last_dirty_lsn);
        goto end;
    }
    date_t init_begin = (diag == NULL) ? 0 : cm_now();
    if (dtc_rcy_rbp_partial_init(session) != OG_SUCCESS) {
        if (diag != NULL) {
            diag->partial_init_us += (uint64)(cm_now() - init_begin);
        }
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip partial_init_fail: page %u-%u node=%u "
                         "batch_lfn=%llu changed_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn);
        goto end;
    }
    if (diag != NULL) {
        diag->partial_init_us += (uint64)(cm_now() - init_begin);
    }

    item = dtc_rcy_rbp_partial_get_or_create(page_id, rcy_item, &created, diag);
    if (item == NULL) {
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed skip get_or_create_fail: page %u-%u node=%u "
                         "batch_lfn=%llu changed_lsn=%llu",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn);
        goto end;
    }
    {
        uint64 old_expect = item->expect_lsn;
        if (changed_lsn > item->expect_lsn) {
            item->expect_lsn = changed_lsn;
            item->expect_lfn = batch_lfn;
        }
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] record_changed ok: page %u-%u node=%u batch_lfn=%llu "
                         "changed_lsn=%llu old_expect=%llu new_expect=%llu expect_lfn=%llu last_dirty_lsn=%llu "
                         "created=%u",
                         page_id.file, page_id.page, node_id, (uint64)batch_lfn, (uint64)changed_lsn,
                         (uint64)old_expect, (uint64)item->expect_lsn, (uint64)item->expect_lfn,
                         (uint64)rcy_item->last_dirty_lsn, (uint32)created);
    }

    if (!item->touch_overflow) {
        rcy_set_analyze_rbp_t merged;
        bool32 overflow_before = item->touch_overflow;
        errno_t ret;

        ret = memset_sp(&merged, sizeof(merged), 0, sizeof(merged));
        knl_securec_check(ret);
        merged.touched = OG_TRUE;
        merged.touch_overflow = item->touch_overflow;
        ret = memcpy_sp(merged.touches, sizeof(merged.touches), item->touches, sizeof(item->touches));
        knl_securec_check(ret);
        dtc_rcy_rbp_analyze_touch_apply_range(&merged, node_id, batch_lfn, batch_lfn);
        item->touch_overflow = merged.touch_overflow;
        ret = memcpy_sp(item->touches, sizeof(item->touches), merged.touches, sizeof(merged.touches));
        knl_securec_check(ret);
        if (item->touch_overflow && !overflow_before) {
            DTC_RCY_CONTEXT->rbp_partial_ctx.overflow_items++;
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                                 "[DTC RCY][RBP][partial] touch overflow page %u-%u overflow_node=%u slots=%u",
                                 page_id.file, page_id.page, node_id, (uint32)RBP_PARTIAL_TOUCH_SLOT_COUNT);
        }
    }
    if (item->touch_overflow) {
        dtc_rcy_rbp_partial_disable_jump(node_id, item);
    }
end:
    (void)created;
    if (diag != NULL) {
        diag->partial_us += (uint64)(cm_now() - partial_begin);
    }
}

static status_t dtc_rcy_try_alloc_itempool(rcy_set_t *rcy_set, rcy_set_item_pool_t *old_pool)
{
    static atomic32_t count = 0;
    int32 times = cm_atomic32_inc(&count);
    if (times == 1 && rcy_set->curr_item_pools == old_pool) {
        rcy_set_item_pool_t *item_pool = dtc_rcy_alloc_itempool(rcy_set);
        if (item_pool == NULL) {
            cm_atomic32_dec(&count);
            OG_LOG_RUN_ERR("[DTC RCY] failed to alloc itempool");
            return OG_ERROR;
        }
        rcy_set->curr_item_pools->next = item_pool;
        rcy_set->curr_item_pools = item_pool;
        cm_atomic32_dec(&count);
    } else {
        cm_atomic32_dec(&count);
        while (rcy_set->curr_item_pools == old_pool) {
            cm_sleep(1);
        }
    }
    return OG_SUCCESS;
}

static void dtc_rcy_handle_pcn_discon(knl_session_t *session, rcy_set_item_t *item, page_id_t page_id, uint32 pcn,
                                      uint64 lsn)
{
    if (pcn == 0 || pcn == (uint32)(item->pcn + 1)) {
        item->pcn = pcn;
        return;
    }
    if (pcn == (uint32)(item->pcn)) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        dtc_rcy->pcn_is_equal_num++;
        return;
    }
    if (pcn < item->pcn) {
        OG_LOG_RUN_INF("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu,"
                       "last_dirty_lsn: %llu, curr_dirty_lsn: %llu, pcn[%u-%u]",
                       page_id.file, page_id.page, item->first_dirty_lsn, item->last_dirty_lsn, lsn, pcn, item->pcn);
        item->need_check_leave_changed = OG_TRUE;
        dtc_rcy_inc_need_analysis_leave_page_cnt(session->kernel->db.recover_for_restore);
        return;
    }

    datafile_t *datafile = DATAFILE_GET(session, page_id.file);
    if (!datafile->ctrl->used || !DATAFILE_IS_ONLINE(datafile)) {
        OG_LOG_RUN_ERR("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu,"
                       "last_dirty_lsn: %llu, curr_dirty_lsn: %llu, pcn[%u-%u]",
                       page_id.file, page_id.page, item->first_dirty_lsn, item->last_dirty_lsn, lsn, pcn, item->pcn);
        dtc_rcy_set_pitr_end_analysis(session->kernel->db.recover_for_restore);
        return;
    }
    buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    if (item->pcn < ((page_head_t *)session->curr_page)->pcn) {
        item->pcn = pcn;
    } else {
        OG_LOG_RUN_ERR("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu,"
                       "last_dirty_lsn: %llu, curr_dirty_lsn: %llu, pcn[%u-%u]",
                       page_id.file, page_id.page, item->first_dirty_lsn, item->last_dirty_lsn, lsn, pcn, item->pcn);
        dtc_rcy_set_pitr_end_analysis(session->kernel->db.recover_for_restore);
    }
    buf_leave_page(session, OG_FALSE);
}

void dtc_rcy_init_page_id_stack(bool32 recover_flag)
{
    if (recover_flag) {
        g_dtc_rcy_page_id_stack.depth = 0;
    }
}

void dtc_rcy_push_page_id(bool32 recover_flag, page_id_t page_id)
{
    if (recover_flag) {
        knl_panic(g_dtc_rcy_page_id_stack.depth < KNL_MAX_PAGE_STACK_DEPTH);
        g_dtc_rcy_page_id_stack.rbp_aly_page_id[g_dtc_rcy_page_id_stack.depth] = page_id;
        g_dtc_rcy_page_id_stack.depth++;
    }
}

void dtc_rcy_pop_page_id(bool32 recover_flag, page_id_t *page_id)
{
    if (recover_flag) {
        knl_panic(g_dtc_rcy_page_id_stack.depth > 0);
        g_dtc_rcy_page_id_stack.depth--;
        *page_id = g_dtc_rcy_page_id_stack.rbp_aly_page_id[g_dtc_rcy_page_id_stack.depth];
    }
}

static void dtc_rcy_get_page_id(bool32 recover_flag, page_id_t *page_id)
{
    if (recover_flag) {
        knl_panic(g_dtc_rcy_page_id_stack.depth > 0);
        *page_id = g_dtc_rcy_page_id_stack.rbp_aly_page_id[g_dtc_rcy_page_id_stack.depth - 1];
    }
}

static void check_node_read_end(uint32 node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    // if no more log, set recover done
    if (!rcy_node->not_finished[rcy_node->read_buf_read_index] ||
        rcy_node->read_size[rcy_node->read_buf_read_index] == 0) {
        rcy_node->recover_done = OG_TRUE;
        if (dtc_rcy->phase == PHASE_ANALYSIS) {
            OG_LOG_RUN_INF("[DTC RCY] analysis read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                           rcy_node->analysis_read_end_point.asn, rcy_node->analysis_read_end_point.block_id,
                           (uint64)rcy_node->analysis_read_end_point.rst_id,
                           (uint64)rcy_node->analysis_read_end_point.lfn, rcy_node->analysis_read_end_point.lsn);
        }
        if (dtc_rcy->phase == PHASE_RECOVERY &&
            (rcy_node->latest_rcy_end_lsn != rcy_node->recovery_read_end_point.lsn)) {
            OG_LOG_RUN_INF("[DTC RCY] recovery read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                           rcy_node->recovery_read_end_point.asn, rcy_node->recovery_read_end_point.block_id,
                           (uint64)rcy_node->recovery_read_end_point.rst_id,
                           (uint64)rcy_node->recovery_read_end_point.lfn, rcy_node->recovery_read_end_point.lsn);
            rcy_node->latest_rcy_end_lsn = rcy_node->recovery_read_end_point.lsn;
        }
    }
}

static status_t dtc_rcy_record_page(knl_session_t *session, page_id_t page_id, uint64 lsn, uint32 pcn,
    uint32 node_id, uint64 batch_lfn, dtc_rcy_analysis_group_diag_t *diag,
    dtc_rcy_analysis_group_count_t *counts)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    rcy_set_item_pool_t *item_pool;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    int64 idx;
    date_t record_begin = (diag == NULL) ? 0 : cm_now();
    date_t lock_begin;

    DTC_RCY_DIAG_INC(diag, counts, record_calls);
    dtc_rcy_push_page_id(session->kernel->db.recover_for_restore, page_id);

    lock_begin = (diag == NULL) ? 0 : cm_now();
    cm_spin_lock(&bucket->lock, NULL);
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    if (item != NULL) {
        DTC_RCY_DIAG_INC(diag, counts, record_hit);
        OG_LOG_DEBUG_INF("[DTC RCY] analyze update page [%u-%u], hash id=%u, first_dirty_lsn=%llu, last_dirty_lsn=%llu"
                         ", curr_dirty_lsn=%llu, pcn=%u, node_id=%u, batch_lfn=%llu, item_pcn=%u",
                         page_id.file, page_id.page, hash_id, (uint64)item->first_dirty_lsn,
                         (uint64)item->last_dirty_lsn, (uint64)lsn, pcn, node_id, (uint64)batch_lfn, item->pcn);
        if (lsn > item->last_dirty_lsn) {
            item->last_dirty_lsn = lsn;
        }
        if (session->kernel->db.recover_for_restore) {
            dtc_rcy_handle_pcn_discon(session, item, page_id, pcn, lsn);
        }
        cm_spin_unlock(&bucket->lock);
        if (diag != NULL) {
            diag->rcy_bucket_lock_us += (uint64)(cm_now() - lock_begin);
            diag->record_us += (uint64)(cm_now() - record_begin);
        }
        return OG_SUCCESS;
    }

    status_t ret = OG_SUCCESS;
    do {
        item_pool = rcy_set->curr_item_pools;
        idx = item_pool->hwm;
        if (idx >= item_pool->capacity) {
            date_t alloc_begin = (diag == NULL) ? 0 : cm_now();
            SYNC_POINT_GLOBAL_START(OGRAC_RECOVERY_RCY_SET_ALLOC_ITEMPOOL_FAIL, &ret, OG_ERROR);
            ret = dtc_rcy_try_alloc_itempool(rcy_set, item_pool);
            SYNC_POINT_GLOBAL_END;
            if (diag != NULL) {
                diag->alloc_itempool_us += (uint64)(cm_now() - alloc_begin);
            }
            if (ret != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to alloc itmepool for recovery set");
                if (diag != NULL) {
                    diag->rcy_bucket_lock_us += (uint64)(cm_now() - lock_begin);
                    diag->record_us += (uint64)(cm_now() - record_begin);
                }
                return OG_ERROR;
            }
            item_pool = rcy_set->curr_item_pools;
            idx = item_pool->hwm;
            continue;
        }
    } while (!cm_atomic_cas(&item_pool->hwm, idx, idx + 1));

    item = &item_pool->items[idx];
    item->page_id = page_id;
    item->first_dirty_lsn = lsn;
    item->last_dirty_lsn = lsn;
    item->pcn = pcn;
    item->need_replay = OG_TRUE;
    item->rbp_required = OG_FALSE;
    item->rbp_verified = OG_FALSE;
    item->need_check_leave_changed = OG_FALSE;
    dtc_rcy_analyze_rbp_reset(&item->analyze_rbp);
    DTC_RCY_DIAG_INC(diag, counts, record_new);

    OG_LOG_DEBUG_INF("[DTC RCY] analyze record page [%u-%u], hash id=%u, first_dirty_lsn=%llu, last_dirty_lsn=%llu"
                     ", curr_dirty_lsn=%llui, pcn=%u, node_id=%u, batch_lfn=%llu, need replay=%u",
                     page_id.file, page_id.page, hash_id, (uint64)item->first_dirty_lsn, (uint64)item->last_dirty_lsn,
                     (uint64)lsn, item->pcn, node_id, (uint64)batch_lfn, item->need_replay);
    date_t drc_begin = (diag == NULL) ? 0 : cm_now();
    if (drc_get_page_master_id(page_id, &item->master_id) != OG_SUCCESS) {
        if (diag != NULL) {
            diag->drc_master_us += (uint64)(cm_now() - drc_begin);
        }
        OG_LOG_RUN_ERR("[DTC RCY] failed to get master id of page [%u-%u]", page_id.file, page_id.page);
        cm_spin_unlock(&bucket->lock);
        if (diag != NULL) {
            diag->rcy_bucket_lock_us += (uint64)(cm_now() - lock_begin);
            diag->record_us += (uint64)(cm_now() - record_begin);
        }
        return OG_ERROR;
    }
    if (diag != NULL) {
        diag->drc_master_us += (uint64)(cm_now() - drc_begin);
    }

    dtc_rcy_add_to_bucket(bucket, item);
    cm_spin_unlock(&bucket->lock);
    if (diag != NULL) {
        diag->rcy_bucket_lock_us += (uint64)(cm_now() - lock_begin);
        diag->record_us += (uint64)(cm_now() - record_begin);
    }
    return OG_SUCCESS;
}

#define DTC_GET_PAGE_ID_REDO(ptr, type, member, page_id) \
    ({                                                   \
        type *__redo = (type *)(ptr);                    \
        page_id = __redo->member;                        \
    })

bool8 dtc_get_page_id_by_redo(log_entry_t *log, page_id_t *page_id_value)
{
    switch (log->type) {
        case RD_HEAP_FORMAT_PAGE:
        case RD_HEAP_FORMAT_MAP:
        case RD_HEAP_FORMAT_ENTRY:
            DTC_GET_PAGE_ID_REDO(log->data, rd_heap_format_page_t, page_id, *page_id_value);
            break;
        case RD_BTREE_FORMAT_PAGE:
            DTC_GET_PAGE_ID_REDO(log->data, rd_btree_page_init_t, page_id, *page_id_value);
            break;
        case RD_BTREE_INIT_ENTRY:
            DTC_GET_PAGE_ID_REDO(log->data, rd_btree_init_entry_t, page_id, *page_id_value);
            break;
        case RD_SPC_UPDATE_HEAD:
            DTC_GET_PAGE_ID_REDO(log->data, rd_update_head_t, entry, *page_id_value);
            break;
        case RD_SPC_INIT_MAP_HEAD:
        case RD_SPC_INIT_MAP_PAGE:
            *page_id_value = AS_PAGID(log->data);
            break;
        case RD_UNDO_CREATE_SEGMENT:
        case RD_UNDO_FORMAT_TXN:
        case RD_LOB_PAGE_INIT:
        case RD_LOB_PAGE_EXT_INIT: {
            page_head_t *redo = (page_head_t *)log->data;
            *page_id_value = AS_PAGID(redo->id);
            break;
        }
        case RD_UNDO_FORMAT_PAGE: {
            rd_undo_fmt_page_t *undo_fmt = (rd_undo_fmt_page_t *)log->data;
            *page_id_value = MAKE_PAGID(undo_fmt->page_id.file, undo_fmt->page_id.page);
            break;
        }
        case RD_PUNCH_FORMAT_PAGE:
            DTC_GET_PAGE_ID_REDO(log->data, rd_punch_page_t, page_id, *page_id_value);
            break;
        case RD_LEAVE_PAGE:
        case RD_LEAVE_TXN_PAGE: {
            dtc_rcy_pop_page_id(OG_TRUE, page_id_value);
            return dtc_rcy_is_need_analysis_leave_page(OG_TRUE);
        }
        case RD_SPC_FREE_PAGE: {
            dtc_rcy_get_page_id(OG_TRUE, page_id_value);
            break;
        }
        default:
            return OG_FALSE;
    }
    return OG_TRUE;
}

void dtc_rcy_try_set_pitr_end_analysis(bool32 recover_flag, page_id_t *page_id, rcy_set_item_t *item, bool32 changed)
{
    if (recover_flag) {
        if (item->need_check_leave_changed) {
            dtc_rcy_dec_need_analysis_leave_page_cnt(recover_flag);
            if (changed) {
                OG_LOG_RUN_ERR("[DTC RCY] analyze update page [%u-%u], first_dirty_lsn: %llu, "
                               "last_dirty_lsn: %llu, pcn %u",
                               page_id->file, page_id->page, item->first_dirty_lsn, item->last_dirty_lsn, item->pcn);
                (void)dtc_rcy_set_pitr_end_analysis(recover_flag);
            }
        }
        item->need_check_leave_changed = OG_FALSE;
    }
    return;
}

static status_t dtc_rcy_reset_page_pcn(knl_session_t *session, log_entry_t *log)
{
    page_id_t page_id;
    if (!dtc_get_page_id_by_redo(log, &page_id)) {
        return OG_SUCCESS;
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];

    cm_spin_lock(&bucket->lock, NULL);
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    if (item != NULL) {
        OG_LOG_DEBUG_INF("[DTC RCY] analyze update page [%u-%u], hash: %u, first_dirty_lsn: %llu,"
                         "last_dirty_lsn: %llu",
                         page_id.file, page_id.page, hash_id, item->first_dirty_lsn, item->last_dirty_lsn);

        if (RD_TYPE_IS_LEAVE_PAGE(log->type)) {
            dtc_rcy_try_set_pitr_end_analysis(session->kernel->db.recover_for_restore, &page_id, item,
                                              *(bool32 *)log->data);
        } else {
            item->pcn = 0;
        }
        cm_spin_unlock(&bucket->lock);
        return OG_SUCCESS;
    }
    cm_spin_unlock(&bucket->lock);
    OG_LOG_DEBUG_INF("[DTC RCY] analyze record page [%u-%u], now is format, but no page enter", page_id.file,
                     page_id.page);
    return OG_SUCCESS;
}

static void dtc_record_space_id(uint32 space_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 *space_id_set = rcy_set->space_id_set;
    for (uint32 i = 0; i < rcy_set->space_set_size; i++) {
        if (space_id == space_id_set[i]) {
            return;
        }
    }
    space_id_set[rcy_set->space_set_size] = space_id;
    rcy_set->space_set_size++;
    OG_LOG_RUN_INF("[DTC RCY] add new space_id %u, space_set_size %u", space_id, rcy_set->space_set_size);
    return;
}

static status_t dtc_rcy_analyze_entry(knl_session_t *session, log_entry_t *log, uint64 lsn, bool32 is_create_df,
    uint32 node_id, uint64 batch_lfn, uint32 worker_slot, dtc_rcy_analysis_group_diag_t *diag,
    dtc_rcy_analysis_group_count_t *counts, bool32 runtime_sink)
{
    knl_panic(log->type >= RD_ENTER_PAGE);
    if (!(log->type == RD_ENTER_PAGE || log->type == RD_ENTER_TXN_PAGE)) {
        if (runtime_sink) {
            return OG_SUCCESS;
        }
        if (!session->kernel->db.recover_for_restore) {
            return OG_SUCCESS;
        }
        return dtc_rcy_reset_page_pcn(session, log);
    }

    rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
    page_id_t page_id = MAKE_PAGID(redo->file, redo->page);
    if (runtime_sink) {
        return OG_SUCCESS;
    }

    if (session->kernel->db.recover_for_restore) {
        return dtc_rcy_record_page(session, page_id, lsn, redo->pcn, node_id, batch_lfn, diag, counts);
    }

    datafile_t *df = DATAFILE_GET(session, redo->file);
    if (!is_create_df && (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used || df->file_no == OG_INVALID_ID32)) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to verify df");
        knl_panic(0);
        return OG_ERROR;
    }

    space_t *space = SPACE_GET(session, df->space_id);
    if (!is_create_df && (!SPACE_IS_ONLINE(space) || !space->ctrl->used)) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to verify space cfg");
        knl_panic(0);
        return OG_ERROR;
    }
    if (dtc_rcy_use_analyze_local_path(session, worker_slot)) {
        dtc_rcy_record_space_id_local(worker_slot, df->space_id);
    } else {
        dtc_record_space_id(df->space_id);
    }

    if (dtc_rcy_use_analyze_local_path(session, worker_slot)) {
        if (dtc_rcy_record_page_local(worker_slot, page_id, lsn, batch_lfn, redo->pcn, diag, counts) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to record page [%u-%u] in local recovery_set", page_id.file, page_id.page);
            return OG_ERROR;
        }
    } else if (dtc_rcy_record_page(session, page_id, lsn, redo->pcn, node_id, batch_lfn, diag, counts) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to record page [%u-%u] in recovery_set", page_id.file, page_id.page);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t dtc_rcy_analyze_group_ex_diag(knl_session_t *session, log_group_t *group, uint32 node_id,
    uint64 batch_lfn, uint32 worker_slot, dtc_rcy_analysis_group_diag_t *diag,
    dtc_rcy_analysis_group_count_t *counts, bool32 runtime_sink)
{
    uint32 offset = sizeof(log_group_t);
    log_entry_t *log = NULL;
    knl_session_t *analyze_session = runtime_sink ? session : session->kernel->sessions[SESSION_ID_KERNEL];

    if (!runtime_sink) {
        analyze_session->dtc_session_type = session->dtc_session_type;
    }
    bool32 is_create_df = OG_FALSE;
    bool32 partial_rbp_collect = (bool32)(!runtime_sink && dtc_rcy_rbp_partial_collecting(session) &&
        node_id < OG_MAX_INSTANCES && batch_lfn != 0);
    bool32 runtime_collect = (bool32)(runtime_sink && node_id < OG_MAX_INSTANCES && batch_lfn != 0);
    page_id_t partial_page_stack[KNL_MAX_PAGE_STACK_DEPTH];
    uint32 partial_page_depth = 0;
    dtc_rcy_init_page_id_stack(session->kernel->db.recover_for_restore);
    dtc_rcy_reset_need_analysis_leave_page_cnt(session->kernel->db.recover_for_restore);
    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        log = (log_entry_t *)((char *)group + offset);
        page_id_t entry_page = { 0 };
        bool32 is_enter = RD_TYPE_IS_ENTER_PAGE(log->type);
        bool32 is_leave = RD_TYPE_IS_LEAVE_PAGE(log->type);

        knl_panic(log->size > 0);
        if (is_enter && (partial_rbp_collect || runtime_collect)) {
            rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
            entry_page = MAKE_PAGID(redo->file, redo->page);
        }
        DTC_RCY_DIAG_INC(diag, counts, entries);
        if (is_enter) {
            DTC_RCY_DIAG_INC(diag, counts, enter_entries);
        }
        if (is_leave) {
            DTC_RCY_DIAG_INC(diag, counts, leave_entries);
        }
        if (!is_create_df && log->type == RD_SPC_CREATE_DATAFILE) {
            is_create_df = OG_TRUE;
        }
        if (partial_rbp_collect && is_enter) {
            knl_panic_log(partial_page_depth < KNL_MAX_PAGE_STACK_DEPTH,
                          "[DTC RCY][RBP][partial] page stack overflow in analyze, lfn=%llu lsn=%llu",
                          (uint64)batch_lfn, (uint64)group->lsn);
            partial_page_stack[partial_page_depth++] = entry_page;
        } else if (runtime_collect && is_enter) {
            knl_panic_log(partial_page_depth < KNL_MAX_PAGE_STACK_DEPTH,
                          "[DTC RBP RT] page stack overflow in runtime analyze, lfn=%llu lsn=%llu",
                          (uint64)batch_lfn, (uint64)group->lsn);
            partial_page_stack[partial_page_depth++] = entry_page;
        }
        if (dtc_rcy_analyze_entry(analyze_session, log, group->lsn, is_create_df, node_id, batch_lfn, worker_slot,
            diag, counts, runtime_sink) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to analyze redo entry");
            return OG_ERROR;
        }
        if (is_leave) {
            bool32 changed = *((bool32 *)log->data);

            if (changed && !partial_rbp_collect && !runtime_collect) {
                dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
                OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] analyze leave changed=1 collect_off: group_lsn=%llu "
                                 "batch_lfn=%llu node_id=%u collecting=%u node_valid=%u batch_lfn_nonzero=%u "
                                 "in_progress=%u full_recovery=%u phase=%u rbp_enable=%u rbp_for_rcy=%u "
                                 "recover_for_restore=%u",
                                 (uint64)group->lsn, (uint64)batch_lfn, node_id,
                                 (uint32)dtc_rcy_rbp_partial_collecting(session),
                                 (uint32)(node_id < OG_MAX_INSTANCES), (uint32)(batch_lfn != 0),
                                 (uint32)dtc_rcy->in_progress, (uint32)dtc_rcy->full_recovery,
                                 (uint32)dtc_rcy->phase, (uint32)KNL_RBP_ENABLE(session->kernel),
                                 (uint32)KNL_RBP_FOR_RECOVERY(session->kernel),
                                 (uint32)session->kernel->db.recover_for_restore);
            }
            if (partial_rbp_collect) {
                page_id_t page_id;

                knl_panic_log(partial_page_depth > 0,
                              "[DTC RCY][RBP][partial] page stack underflow in analyze, lfn=%llu lsn=%llu",
                              (uint64)batch_lfn, (uint64)group->lsn);
                page_id = partial_page_stack[--partial_page_depth];
                if (changed) {
                    DTC_RCY_DIAG_INC(diag, counts, changed_leave_entries);
                    OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] analyze leave changed=1: page %u-%u group_lsn=%llu "
                                     "batch_lfn=%llu node_id=%u stack_depth=%u",
                                     page_id.file, page_id.page, (uint64)group->lsn, (uint64)batch_lfn, node_id,
                                     partial_page_depth);
                    if (dtc_rcy_use_analyze_local_path(session, worker_slot)) {
                        dtc_rcy_rbp_analyze_leave_local(worker_slot, page_id, node_id, batch_lfn, group->lsn, diag,
                            counts);
                    } else {
                        dtc_rcy_rbp_partial_record_changed(session, page_id, node_id, batch_lfn, group->lsn, diag,
                            counts);
                    }
                }
            } else if (runtime_collect) {
                page_id_t page_id;

                knl_panic_log(partial_page_depth > 0,
                              "[DTC RBP RT] page stack underflow in runtime analyze, lfn=%llu lsn=%llu",
                              (uint64)batch_lfn, (uint64)group->lsn);
                partial_page_depth--;
                page_id = partial_page_stack[partial_page_depth];
                (void)page_id;
                if (changed) {
                    DTC_RCY_DIAG_INC(diag, counts, changed_leave_entries);
                }
            }
        }
        if (dtc_rcy_check_is_end_restore_recovery()) {
            break;
        }
        offset += log->size;
    }
    return OG_SUCCESS;
}

status_t dtc_rcy_analyze_group_ex(knl_session_t *session, log_group_t *group, uint32 node_id, uint64 batch_lfn)
{
    return dtc_rcy_analyze_group_ex_diag(session, group, node_id, batch_lfn, OG_INVALID_ID32, NULL, NULL, OG_FALSE);
}

status_t dtc_rcy_analyze_group_into_local(knl_session_t *session, log_group_t *group, uint32 node_id,
    uint64 batch_lfn, dtc_rcy_local_set_t *local, uint64 *enter_count)
{
    uint32 offset = sizeof(log_group_t);
    log_entry_t *log = NULL;
    bool32 is_create_df = OG_FALSE;
    page_id_t page_stack[KNL_MAX_PAGE_STACK_DEPTH];
    uint32 page_depth = 0;
    uint64 enters = 0;

    if (group == NULL || local == NULL || !local->inited || node_id >= OG_MAX_INSTANCES || batch_lfn == 0) {
        return OG_ERROR;
    }
    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        log = (log_entry_t *)((char *)group + offset);
        bool32 is_enter = RD_TYPE_IS_ENTER_PAGE(log->type);
        bool32 is_leave = RD_TYPE_IS_LEAVE_PAGE(log->type);

        knl_panic(log->size > 0);
        if (!is_create_df && log->type == RD_SPC_CREATE_DATAFILE) {
            is_create_df = OG_TRUE;
        }
        if (is_enter) {
            rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
            page_id_t page_id = MAKE_PAGID(redo->file, redo->page);
            datafile_t *df = DATAFILE_GET(session, redo->file);

            knl_panic_log(page_depth < KNL_MAX_PAGE_STACK_DEPTH,
                          "[DTC RBP RT] page stack overflow in local analyze, lfn=%llu lsn=%llu",
                          (uint64)batch_lfn, (uint64)group->lsn);
            page_stack[page_depth++] = page_id;
            if (!is_create_df && (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used || df->file_no == OG_INVALID_ID32)) {
                OG_LOG_RUN_ERR("[DTC RBP RT] failed to verify df for local analyze, page=%u-%u",
                               page_id.file, page_id.page);
                return OG_ERROR;
            }
            space_t *space = SPACE_GET(session, df->space_id);
            if (!is_create_df && (!SPACE_IS_ONLINE(space) || !space->ctrl->used)) {
                OG_LOG_RUN_ERR("[DTC RBP RT] failed to verify space for local analyze, page=%u-%u",
                               page_id.file, page_id.page);
                return OG_ERROR;
            }
            dtc_rcy_record_space_id_into_local(local, df->space_id);
            if (dtc_rcy_record_page_into_local(session, local, page_id, group->lsn, batch_lfn, redo->pcn, NULL, NULL) !=
                OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RBP RT] failed to record page [%u-%u] in local analyze", page_id.file,
                               page_id.page);
                return OG_ERROR;
            }
            enters++;
        } else if (is_leave) {
            bool32 changed = *((bool32 *)log->data);
            page_id_t page_id;

            knl_panic_log(page_depth > 0,
                          "[DTC RBP RT] page stack underflow in local analyze, lfn=%llu lsn=%llu",
                          (uint64)batch_lfn, (uint64)group->lsn);
            page_id = page_stack[--page_depth];
            if (changed) {
                dtc_rcy_rbp_analyze_leave_into_local(local, page_id, node_id, batch_lfn, group->lsn, NULL, NULL);
            }
        }
        offset += log->size;
    }
    if (enter_count != NULL) {
        *enter_count += enters;
    }
    return OG_SUCCESS;
}

status_t dtc_rcy_analyze_group(knl_session_t *session, log_group_t *group)
{
    return dtc_rcy_analyze_group_ex(session, group, OG_INVALID_ID32, 0);
}

static inline void dtc_rcy_inc_rcy_set_ref_num(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->rcy_set_ref_num++;
    cm_spin_unlock(&dtc_rcy->lock);
}

static inline void dtc_rcy_dec_rcy_set_ref_num(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->rcy_set_ref_num--;
    cm_spin_unlock(&dtc_rcy->lock);
}

static inline void dtc_rcy_inc_msg_sent(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->msg_sent++;
    cm_spin_unlock(&dtc_rcy->lock);
}

static inline void dtc_rcy_inc_msg_recv(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    dtc_rcy->msg_recv++;
    cm_spin_unlock(&dtc_rcy->lock);
}

static status_t dtc_rcy_check_rcyset_msg(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    // check if reformer rev ack msg from alive nodes timeout
    date_t time_now = KNL_NOW(session);
    if (time_now - dtc_rcy->rcy_set_send_time >= dtc_rcy->msg_sent * DTC_RCY_RECV_RCY_SET_ACK_TIMEOUT) {
        OG_LOG_RUN_WAR("[DTC RCY] wait nodes collects page info in rcy_set timeout, %u msg_sent, %u msg_recv, "
                       "time spend=%lld",
                       dtc_rcy->msg_sent, dtc_rcy->msg_recv, time_now - dtc_rcy->rcy_set_send_time);
        dtc_rcy->failed = OG_TRUE;
        return OG_ERROR;
    }
    if (dtc_rcy->msg_recv == dtc_rcy->msg_sent) {
        dtc_rcy->phase = PHASE_HANDLE_RCYSET_DONE;
    }
    cm_spin_unlock(&dtc_rcy->lock);
    return OG_SUCCESS;
}

status_t dtc_send_page_to_node(knl_session_t *session, page_id_t *pages, uint32 count, bool32 finished, uint8 node_id,
                               uint8 cmd)
{
    dtc_rcy_set_msg_t req;
    status_t status;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;

    mes_init_send_head(&req.head, cmd, sizeof(dtc_rcy_set_msg_t), OG_INVALID_ID32, session->kernel->id, node_id,
                       session->id, OG_INVALID_ID16);

    req.count = count;
    req.finished = finished;
    req.buffer_len = req.count * sizeof(page_id_t);
    req.head.size = (uint16)(sizeof(dtc_rcy_set_msg_t) + req.count * sizeof(page_id_t));
    req.reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    if (count > 0) {
        status = mes_send_data3(&req.head, sizeof(dtc_rcy_set_msg_t), pages);
    } else {
        status = mes_send_data(&req.head);
    }

    if (cmd == MES_CMD_SEND_RCY_SET) {
        dtc_rcy_inc_msg_sent();
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    OG_LOG_RUN_INF("[DTC RCY] send num=%u pages size=%u to instance=%u with status=%d, rcy_set ref num=%u", count,
                   req.head.size, node_id, status, dtc_rcy->rcy_set_ref_num);

    return status;
}

static page_id_t *dtc_rcy_alloc_page_space(uint32 size)
{
    if (size == 0) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc page space, size=%u", size);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, size, "dtc recovery page space");
        return NULL;
    }
    page_id_t *pages = (page_id_t *)malloc(size);
    if (pages == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc page space, size=%u", size);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, size, "dtc recovery page space");
        return NULL;
    }

    errno_t ret = memset_sp(pages, size, 0, size);
    knl_securec_check(ret);
    return pages;
}

static status_t dtc_send_rcy_set_by_pool(knl_session_t *session, rcy_set_item_pool_t *pool, rcy_set_t *rcy_set)
{
    uint32 size = DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM * sizeof(page_id_t);
    rcy_set_item_t *item = NULL;
    page_id_t *pages = NULL;
    uint32 *page_count = NULL;
    uint8 node_id;

    for (uint32 i = 0; i < pool->hwm; i++) {
        item = &pool->items[i];
        if (!item->need_replay) {
            continue;
        }
        node_id = item->master_id;
        if (node_id >= OG_MAX_INSTANCES) {
            OG_LOG_RUN_ERR("[DTC RCY] invalid rcy set page master, page=%u-%u master=%u", item->page_id.file,
                           item->page_id.page, node_id);
            return OG_ERROR;
        }

        pages = rcy_set->pages[node_id];
        page_count = &rcy_set->page_count[node_id];
        // malloc memory for the first time
        if (pages == NULL) {
            pages = dtc_rcy_alloc_page_space(size);
            if (pages == NULL) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to malloc %u bytes for sending rcyset to instance=%u", size, node_id);
                return OG_ERROR;
            }
            *page_count = 0;
            rcy_set->pages[node_id] = pages;
        }

        pages[*page_count] = item->page_id;
        (*page_count)++;

        // send to master if message buffer is full
        if (*page_count >= DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM) {
            if (dtc_send_page_to_node(session, pages, *page_count, OG_FALSE, node_id, MES_CMD_SEND_RCY_SET) !=
                OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to send num=%u pages from rcy set to node=%u, max_page_count=%lu",
                               *page_count, node_id, DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM);
                return OG_ERROR;
            }

            *page_count = 0;
        }
    }
    return OG_SUCCESS;
}

static status_t dtc_send_rcy_set(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools;
    status_t ret = OG_SUCCESS;

    // set recovery phase to PHASE_HANDLE_RCYSET
    dtc_rcy->phase = PHASE_HANDLE_RCYSET;
    OG_LOG_RUN_INF("[DTC RCY] start send rcy set to each master, dtc_rcy->phase=%u", dtc_rcy->phase);
    while (pool != NULL) {
        dtc_rcy_inc_rcy_set_ref_num();
        SYNC_POINT_GLOBAL_START(OGRAC_RECOVERY_SEND_RCY_SET_FAIL, &ret, OG_ERROR);
        ret = dtc_send_rcy_set_by_pool(session, pool, &dtc_rcy->rcy_set);
        SYNC_POINT_GLOBAL_END;
        if (ret != OG_SUCCESS) {
            dtc_rcy_dec_rcy_set_ref_num();
            OG_LOG_RUN_ERR("[DTC RCY] failed to send rcy set by pool, pool capacity=%llu, dtc_rcy->phase=%u, "
                           "rcy_set ref num=%u",
                           pool->hwm, dtc_rcy->phase, dtc_rcy->rcy_set_ref_num);
            return OG_ERROR;
        }
        dtc_rcy_dec_rcy_set_ref_num();
        OG_LOG_RUN_INF("[DTC RCY] send rcy set by pool, dtc_rcy->phase=%u, rcy_set ref num=%u", dtc_rcy->phase,
                       dtc_rcy->rcy_set_ref_num);
        pool = pool->next;
    }

    page_id_t *pages = NULL;
    uint32 *page_count = NULL;
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        dtc_rcy_inc_rcy_set_ref_num();
        pages = dtc_rcy->rcy_set.pages[i];
        page_count = &dtc_rcy->rcy_set.page_count[i];
        if (pages == NULL || *page_count == 0) {
            dtc_rcy_dec_rcy_set_ref_num();
            continue;
        }

        // send the rest page to each master if successful
        if (dtc_send_page_to_node(session, pages, *page_count, OG_TRUE, i, MES_CMD_SEND_RCY_SET) != OG_SUCCESS) {
            dtc_rcy_dec_rcy_set_ref_num();
            OG_LOG_RUN_ERR("[DTC RCY] failed to send rcy set to node=%u, page_count=%u, rcy_set ref num=%u", i,
                           *page_count, dtc_rcy->rcy_set_ref_num);
            return OG_ERROR;
        }
        *page_count = 0;
        dtc_rcy_dec_rcy_set_ref_num();
        OG_LOG_RUN_INF("[DTC RCY] send rcy set to node=%u, page_count=%u, rcy_set ref num=%u", i, *page_count,
                       dtc_rcy->rcy_set_ref_num);
    }

    if (dtc_rcy->msg_sent == 0) {
        dtc_rcy->phase = PHASE_HANDLE_RCYSET_DONE;
    }

    dtc_rcy->rcy_set_send_time = KNL_NOW(session);  // record time when all pages in rcy_set have sent successfully
    OG_LOG_RUN_INF("[DTC RCY] send %u rcy set messages, dtc_rcy->phase=%u, send time=%lld", dtc_rcy->msg_sent,
                   dtc_rcy->phase, dtc_rcy->rcy_set_send_time);
    return OG_SUCCESS;
}

static status_t dtc_check_rcy_set_err_ack_msg(mes_message_t *msg)
{
    if (sizeof(dtc_rcy_set_msg_t) > msg->head->size) {
        return OG_ERROR;
    }
    dtc_rcy_set_msg_t *request = (dtc_rcy_set_msg_t *)msg->buffer;
    if (sizeof(dtc_rcy_set_msg_t) + request->buffer_len != msg->head->size) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void dtc_process_rcy_set_err_ack(void *sess, mes_message_t *msg)
{
    if (dtc_check_rcy_set_err_ack_msg(msg) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_set_msg_t *ack = (dtc_rcy_set_msg_t *)msg->buffer;
    bool32 finished = ack->finished;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;

    if (g_rc_ctx->status > REFORM_RECOVER_DONE || g_rc_ctx->status < REFORM_FROZEN ||
        ack->reform_trigger_version < remaster_mngr->reform_info.trigger_version) {
        OG_LOG_RUN_ERR("[DTC RCY] process rcy set err ack from master=%u, finished=%u, reform status(%u), msg reform "
                       "trigger version(%llu), local reform trigger version(%llu)",
                       ack->head.src_inst, finished, g_rc_ctx->status, ack->reform_trigger_version,
                       remaster_mngr->reform_info.trigger_version);
        mes_release_message_buf(msg->buffer);
        return;
    }

    OG_LOG_RUN_INF("[DTC RCY] process rcy set err ack from master=%u, finished=%u", ack->head.src_inst, finished);
    if (!finished) {
        dtc_rcy->failed = OG_TRUE;
    }
    dtc_rcy_inc_msg_recv();
    mes_release_message_buf(msg->buffer);
    return;
}

status_t dtc_rcy_set_update_no_need_replay_batch(rcy_set_t *rcy_set, page_id_t *no_rcy_pages, uint32 count)
{
    rcy_set_bucket_t *bucket = NULL;
    uint32 hash_id;
    page_id_t *page_id = NULL;
    status_t ret = OG_SUCCESS;
    bool8 need_replay = OG_TRUE;
    for (uint32 i = 0; i < count; i++) {
        page_id = no_rcy_pages + i;
        hash_id = dtc_rcy_bucket_hash(*page_id, rcy_set->bucket_num);
        bucket = &rcy_set->buckets[hash_id];
        cm_spin_lock(&bucket->lock, NULL);
        need_replay = OG_FALSE;
        ret = dtc_rcy_set_item_update_need_replay(bucket, *page_id, need_replay);
        OG_LOG_RUN_RET_INFO(ret, "[DTC RCY][%u-%u] update need replay(%u) in rcy set", page_id->file, page_id->page,
                            need_replay);
        if (ret != OG_SUCCESS) {
            cm_spin_unlock(&bucket->lock);
            return ret;
        }
        cm_spin_unlock(&bucket->lock);
    }
    return ret;
}

static status_t dtc_check_rcy_set_ack_msg(mes_message_t *msg)
{
    if (sizeof(dtc_rcy_set_msg_t) > msg->head->size) {
        return OG_ERROR;
    }
    dtc_rcy_set_msg_t *request = (dtc_rcy_set_msg_t *)msg->buffer;
    if ((sizeof(dtc_rcy_set_msg_t) + request->buffer_len) != msg->head->size) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void dtc_process_rcy_set_ack(void *sess, mes_message_t *msg)
{
    if (dtc_check_rcy_set_ack_msg(msg) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;
    dtc_rcy_set_msg_t *ack = (dtc_rcy_set_msg_t *)msg->buffer;

    uint32 count = ack->count;
    uint32 buffer_len = ack->buffer_len;
    if (buffer_len != count * sizeof(page_id_t) || g_rc_ctx->status >= REFORM_RECOVER_DONE ||
        g_rc_ctx->status < REFORM_FROZEN || ack->reform_trigger_version != remaster_mngr->reform_info.trigger_version ||
        count > DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM || ack->head.size != sizeof(dtc_rcy_set_msg_t) + buffer_len) {
        OG_LOG_RUN_ERR("[DTC RCY] receive page count=%u, max_page_count=%lu, no_rcy_pages buffer len=%u, reform "
                       "status(%u), msg reform trigger version(%llu), local reform trigger version(%llu), msg size(%u)",
                       count, DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM, buffer_len, g_rc_ctx->status,
                       ack->reform_trigger_version, remaster_mngr->reform_info.trigger_version, ack->head.size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    page_id_t *no_rcy_pages = (page_id_t *)(msg->buffer + sizeof(dtc_rcy_set_msg_t));
    bool32 finished = ack->finished;
    OG_LOG_RUN_INF("[DTC RCY] process rcy set with edp from master=%u, no_rcy page count=%u, finished=%u",
                   ack->head.src_inst, count, finished);
    if (!finished) {
        dtc_rcy->failed = OG_TRUE;
        dtc_rcy_inc_msg_recv();
        mes_release_message_buf(msg->buffer);
        OG_LOG_RUN_ERR("[DTC RCY] collect page info from inst=%u, finished=%u", ack->head.src_inst, finished);
        return;
    }
    if (dtc_rcy->failed) {
        mes_release_message_buf(msg->buffer);
        return;
    }

    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    dtc_rcy_inc_rcy_set_ref_num();

    if (dtc_rcy_set_update_no_need_replay_batch(rcy_set, no_rcy_pages, count) != OG_SUCCESS) {
        dtc_rcy->failed = OG_TRUE;
    }
    OG_LOG_RUN_INF("[DTC RCY] finish delete no_rcy page count=%u, rcy_set ref num=%u", count, dtc_rcy->rcy_set_ref_num);

    dtc_rcy_inc_msg_recv();
    dtc_rcy_dec_rcy_set_ref_num();
    OG_LOG_RUN_INF("[DTC RCY] finish process rcy set with edp ack, rcy_set ref num=%u", dtc_rcy->rcy_set_ref_num);
    mes_release_message_buf(msg->buffer);
}

static bool32 dtc_rcy_page_need_recover(knl_session_t *session, page_id_t *page_id)
{
    return drc_page_need_recover(session, page_id);
}

status_t dtc_send_page_back_to_node(knl_session_t *session, page_id_t *pages, uint32 count, bool32 finished,
                                    uint8 node_id, uint8 cmd)
{
    dtc_rcy_set_msg_t req;
    status_t status;
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;

    mes_init_send_head(&req.head, cmd, sizeof(dtc_rcy_set_msg_t), OG_INVALID_ID32, session->kernel->id, node_id,
                       session->id, OG_INVALID_ID16);

    req.count = count;
    req.finished = finished;
    req.buffer_len = req.count * sizeof(page_id_t);
    req.head.size = (uint16)(sizeof(dtc_rcy_set_msg_t) + req.buffer_len);
    req.reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    if (count > 0) {
        status = mes_send_data3(&req.head, sizeof(dtc_rcy_set_msg_t), pages);
    } else {
        status = mes_send_data(&req.head);
    }
    OG_LOG_RUN_INF("[DTC RCY] send %u pages no need to rcy to instance=%u with cmd=%d, status=%d", count, node_id, cmd,
                   status);

    return status;
}

static status_t dtc_process_rcy_set_parameter_check(dtc_rcy_set_msg_t *req, uint32 size)
{
    drc_remaster_mngr_t *remaster_mngr = &g_drc_res_ctx.part_mngr.remaster_mngr;
    uint32 buffer_len = req->buffer_len;
    if (g_rc_ctx->status >= REFORM_RECOVER_DONE || g_rc_ctx->status < REFORM_FROZEN || req->count == 0 ||
        req->count > DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM || buffer_len != size ||
        buffer_len > DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM * sizeof(page_id_t) ||
        req->reform_trigger_version != remaster_mngr->reform_info.trigger_version ||
        sizeof(dtc_rcy_set_msg_t) + size != req->head.size) {
        OG_LOG_RUN_ERR("[DTC RCY] receive page count=%u, max_page_count=%lu, buffer len=%u, max buffer len=%lu, reform"
                       " status(%u), msg reform trigger version(%llu), local reform trigger version(%llu), msgsize(%u)",
                       req->count, DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM, buffer_len,
                       DTC_RCY_SET_SEND_MSG_MAX_PAGE_NUM * sizeof(page_id_t), g_rc_ctx->status,
                       req->reform_trigger_version, remaster_mngr->reform_info.trigger_version, req->head.size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t dtc_check_process_rcy_set_msg(mes_message_t *msg)
{
    if (sizeof(dtc_rcy_set_msg_t) > msg->head->size) {
        return OG_ERROR;
    }
    dtc_rcy_set_msg_t *request = (dtc_rcy_set_msg_t *)msg->buffer;
    if ((sizeof(dtc_rcy_set_msg_t) + request->count * sizeof(page_id_t)) != msg->head->size) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void dtc_process_rcy_set(void *sess, mes_message_t *receive_msg)
{
    if (dtc_check_process_rcy_set_msg(receive_msg) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    knl_session_t *session = (knl_session_t *)sess;
    dtc_rcy_set_msg_t *req = (dtc_rcy_set_msg_t *)receive_msg->buffer;
    page_id_t *pages_recv = (page_id_t *)(receive_msg->buffer + sizeof(dtc_rcy_set_msg_t));
    uint8 src_inst = receive_msg->head->src_inst;
    uint32 size = req->count * sizeof(page_id_t);
    uint32 count = 0;
    bool32 need_recover = OG_FALSE;

    if (dtc_process_rcy_set_parameter_check(req, size) != OG_SUCCESS) {
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    page_id_t *page_id = NULL;
    page_id_t *pages = NULL;
    pages = dtc_rcy_alloc_page_space(size);
    if (pages == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to malloc %u bytes to collect do not need rcy page info from instance=%u",
                       size, receive_msg->head->src_inst);
        mes_release_message_buf(receive_msg->buffer);
        if (dtc_send_page_back_to_node(session, pages, count, OG_FALSE, src_inst, MES_CMD_SEND_RCY_SET_ERR_ACK) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to send error msg to instance=%u", src_inst);
        }
        return;
    }
    OG_LOG_RUN_INF("[DTC RCY] process recovery set of %u pages size=%u from instance=%u", req->count, size, src_inst);

    for (uint32 i = 0; i < req->count; i++) {
        page_id = pages_recv + i;
        need_recover = dtc_rcy_page_need_recover(session, page_id);
        if (!need_recover) {
            pages[count++] = *page_id;
            OG_LOG_DEBUG_INF("[DTC RCY] process recovery set, page [%u-%u] no need to rcy in instance=%u",
                             page_id->file, page_id->page, session->inst_id);
        }
    }
    OG_LOG_RUN_INF("[DTC RCY] master process rcy set, total check page count=%u, collect no_rcy page count=%u",
                   req->count, count);

    mes_release_message_buf(receive_msg->buffer);
    // send the no_rcy pages to reformer
    if (dtc_send_page_back_to_node(session, pages, count, OG_TRUE, src_inst, MES_CMD_SEND_RCY_SET_ACK) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to send rcy set result to instance=%u", src_inst);
        CM_FREE_PTR(pages);
        return;
    }
    CM_FREE_PTR(pages);
}

bool8 dtc_rcy_page_in_rcyset(page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    if (dtc_rcy->full_recovery) {
        return OG_TRUE;
    }

    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    uint32 curr_idx = dtc_rcy->curr_node_idx;
    uint64 curr_lfn = 0;
    uint64 recovery_lfn = 0;
    uint8 jump_taken = OG_FALSE;

    if (curr_idx < dtc_rcy->node_count) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[curr_idx].node_id;

        curr_lfn = dtc_rcy->rcy_log_points[curr_idx].rcy_point.lfn;
        recovery_lfn = dtc_rcy->rcy_nodes[curr_idx].recovery_read_end_point.lfn;
        if (node_id < OG_MAX_INSTANCES) {
            jump_taken = dtc_rcy->rbp_jump_taken[node_id];
        }
    }
    knl_panic_log(item != NULL,
                  "rcy set item is NULL, panic info: page[%u-%u] is not in rcy set, but appears in "
                  "replay, phase=%u curr_idx=%u curr_lfn=%llu recovery_lfn=%llu rbp_jump=%u",
                  page_id.file, page_id.page, (uint32)dtc_rcy->phase, curr_idx, curr_lfn, recovery_lfn,
                  (uint32)jump_taken);
    return item->need_replay;
}

bool32 dtc_page_in_rcyset(knl_session_t *session, page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    uint64 curr_page_lsn = OG_INVALID_ID64;
    if (item != NULL && item->need_replay) {
        buf_bucket_t *buf_bucket = buf_find_bucket(session, page_id);
        cm_spin_lock_bucket(&buf_bucket->lock, NULL);
        buf_ctrl_t *ctrl = buf_find_from_bucket(buf_bucket, page_id);
        if (!ctrl || ctrl->lock_mode == DRC_LOCK_NULL) {
            /* If the page is not in memory or lock mode is null, the partial recovery for that page can't be skipped,
            as the page on disk may be not the latest one. */
            curr_page_lsn = 0;
            cm_spin_unlock_bucket(&buf_bucket->lock);
        } else {
            curr_page_lsn = (ctrl->page)->lsn;
            cm_spin_unlock_bucket(&buf_bucket->lock);
        }

        if (item->last_dirty_lsn <= curr_page_lsn) {
            item->need_replay = OG_FALSE;
            return OG_FALSE;
        } else {
            return item->need_replay;
        }
    }
    return OG_FALSE;
}

void dtc_rcy_page_update_need_replay(page_id_t page_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    uint32 hash_id = dtc_rcy_bucket_hash(page_id, rcy_set->bucket_num);
    rcy_set_bucket_t *bucket = &rcy_set->buckets[hash_id];
    rcy_set_item_t *item = dtc_rcy_get_item(bucket, page_id);
    knl_panic_log(item != NULL,
                  "rcy set item is NULL, panic info: page[%u-%u] is not in rcy set, but appears in "
                  "replay",
                  page_id.file, page_id.page);
    item->need_replay = OG_TRUE;
}

static void dtc_print_batch(log_batch_t *batch, uint8 node_id)
{
    OG_LOG_DEBUG_INF("[DTC RCY] Log Batch lfn=%llu, lsn=%llu, scn=%llu, head magic=%llx. point [%u-%u/%u], "
                     "size=%u, space size=%u for instance=%u",
                     (uint64)batch->head.point.lfn, batch->lsn, batch->scn, batch->head.magic_num,
                     batch->head.point.rst_id, batch->head.point.asn, batch->head.point.block_id, batch->size,
                     batch->space_size, node_id);
}

static void dtc_rcy_close_logfile(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    if (dtc_rcy->rcy_nodes == NULL) {
        return;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[i];

        if (rcy_node == NULL) {
            continue;
        }

        if (rcy_node->arch_file.handle != OG_INVALID_HANDLE) {
            cm_close_device(cm_device_type(rcy_node->arch_file.name), &rcy_node->arch_file.handle);
            rcy_node->arch_file.handle = OG_INVALID_HANDLE;
            rcy_node->arch_file.name[0] = '\0';
            rcy_node->arch_file.head.rst_id = 0;
            rcy_node->arch_file.head.asn = 0;
        }

        logfile_set_t *log_set = LOGFILE_SET(session, rcy_node->node_id);
        for (uint32 j = 0; j < log_set->logfile_hwm; j++) {
            if (rcy_node->handle[j] != OG_INVALID_HANDLE) {
                cm_close_device(log_set->items[j].ctrl->type, &rcy_node->handle[j]);
                rcy_node->handle[j] = OG_INVALID_HANDLE;
            }
        }
    }
}

static void free_paral_mgr()
{
    CM_FREE_PTR(g_analyze_paral_mgr.free_list.array);
    CM_FREE_PTR(g_analyze_paral_mgr.buf_list);
    CM_FREE_PTR(g_analyze_paral_mgr.node_ids);
    CM_FREE_PTR(g_analyze_paral_mgr.batch_points);
    CM_FREE_PTR(g_analyze_paral_mgr.used_list.array);
    CM_FREE_PTR(g_replay_paral_mgr.buf_list);
    CM_FREE_PTR(g_replay_paral_mgr.group_list);
    CM_FREE_PTR(g_replay_paral_mgr.batch_scn);
    CM_FREE_PTR(g_replay_paral_mgr.node_id);
    CM_FREE_PTR(g_replay_paral_mgr.batch_rpl_start_time);
    CM_FREE_PTR(g_replay_paral_mgr.free_list.array);
    free((void *)g_replay_paral_mgr.group_num);
    g_replay_paral_mgr.group_num = NULL;
}

void dtc_recovery_close(knl_session_t *session)
{
    OG_LOG_RUN_INF("[DTC RCY] start dtc recovery close");
    if (rc_is_master() == OG_FALSE) {
        return;
    }

    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    // [reformer] close logfile handle
    dtc_rcy_close_logfile(session);
    dtc_rcy_rbp_clear_lfn_point_maps(dtc_rcy);

    // [reformer] release memory malloced in dtc_rcy_init_rcyset
    while (dtc_rcy->rcy_set_ref_num != 0) {
        OG_LOG_RUN_INF("[DTC RCY] wait rcy_set ref num=%u", dtc_rcy->rcy_set_ref_num);
        cm_sleep(DTC_RCY_WAIT_REF_NUM_CLEAN_SLEEP_TIME);
    }
    dtc_rcy_rbp_partial_clear(dtc_rcy);
    if (!dtc_rcy->full_recovery) {
        rbp_finish_partial_recovery_page_write(session);
    }

    // [reformer] release memory malloced in paral analyze
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        if (dtc_rcy->rcy_set.pages[i] != NULL) {
            CM_FREE_PTR(dtc_rcy->rcy_set.pages[i]);
        }
    }

    rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools;
    rcy_set_item_pool_t *next = NULL;
    while (pool != NULL) {
        next = pool->next;
        CM_FREE_PTR(pool);
        pool = next;
    }

    // [reformer] release memory malloced in dtc_rcy_init_rcynode
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    if (dtc_rcy->rcy_nodes != NULL) {
        for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
            for (int j = 0; j < read_buf_size; ++j) {
                cm_aligned_free(&dtc_rcy->rcy_nodes[i].read_buf[j]);
            }
            CM_FREE_PTR(dtc_rcy->rcy_nodes[i].read_buf_ready);
            CM_FREE_PTR(dtc_rcy->rcy_nodes[i].read_pos);
            CM_FREE_PTR(dtc_rcy->rcy_nodes[i].write_pos);
            CM_FREE_PTR(dtc_rcy->rcy_nodes[i].read_size);
            CM_FREE_PTR(dtc_rcy->rcy_nodes[i].not_finished);
        }
    }
    // [reformer] release memroy malloced in dtc_rcy_init_context
    CM_FREE_PTR(dtc_rcy->rcy_nodes);
    free_paral_mgr();

    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    if (rcy_set->buckets != NULL) {
        CM_FREE_PTR(rcy_set->buckets);
    }

    // [reformer][paral_rcy] release memory and session malloced in dtc_rcy_init_replay_proc
    if (dtc_rcy->paral_rcy) {
        rcy_close_proc(session);
        rcy_free_buffer(&session->kernel->rcy_ctx);
    }

    // [reformer][partial_recovery]
    if (!dtc_rcy->full_recovery) {
        g_knl_callback.release_knl_session(session);
    }

    dtc_rcy->in_progress = OG_FALSE;
    dtc_rcy->ss->dtc_session_type = DTC_TYPE_NONE;
    OG_LOG_RUN_INF("[DTC RCY] finish dtc recovery close");
}

static inline bool32 dtc_log_file_not_used(dtc_node_ctrl_t *ctrl, uint32 file)
{
    bool32 not_used = OG_FALSE;

    if (ctrl->log_first <= ctrl->log_last) {
        not_used = file < ctrl->log_first || file > ctrl->log_last;
    } else {
        not_used = file < ctrl->log_first && file > ctrl->log_last;
    }
    return not_used;
}

static inline void dtc_init_not_used_log_file(log_file_t *file, database_t *db)
{
    file->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    file->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size);
    file->head.block_size = file->ctrl->block_size;
    file->head.asn = OG_INVALID_ASN;
}

static inline void dtc_init_dbs_log_file(log_file_t *file, database_t *db)
{
    file->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    file->head.write_pos = 0;
}

static status_t dtc_init_node_logset(knl_session_t *session, uint8 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    logfile_set_t *file_set = LOGFILE_SET(session, rcy_node->node_id);
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, rcy_node->node_id);
    database_t *db = &session->kernel->db;
    log_file_t *file = NULL;
    char *buf = rcy_node->read_buf[rcy_node->read_buf_read_index].aligned_buf;

    if (session->kernel->id == rcy_node->node_id) {
        return OG_SUCCESS;
    }

    file_set->logfile_hwm = ctrl->log_hwm;
    file_set->log_count = ctrl->log_count;

    for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
        file = &file_set->items[i];
        file->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                             db->ctrl.log_segment, rcy_node->node_id);
        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (dtc_log_file_not_used(ctrl, i)) {
            dtc_init_not_used_log_file(file, db);
            continue;
        }

        // logfile can be opened for a long time, closed in db_close_log_files
        if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(session), &rcy_node->handle[i]) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DB] failed to open redo log file=%s ", file->ctrl->name);
            return OG_ERROR;
        }
        // The log header does not need to be written.
        if (cm_dbs_is_enable_dbs() == OG_TRUE) {
            dtc_init_dbs_log_file(file, db);
            OG_LOG_RUN_INF("[DTC RCY] Init logfile=%s, handle=%d, point=[%u-%u] write_pos=%llu for instance=%u",
                           file->ctrl->name, rcy_node->handle[i], file->head.rst_id, file->head.asn,
                           file->head.write_pos, rcy_node->node_id);
            break;
        }
        if (cm_read_device(file->ctrl->type, rcy_node->handle[i], 0, buf,
                           CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DB] failed to open redo log file=%s ", file->ctrl->name);
            // close file in dtc_rcy_close
            return OG_ERROR;
        }

        if (log_verify_head_checksum(session, (log_file_head_t *)buf, file->ctrl->name) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to verify head checksum of log file=%s", file->ctrl->name);
            // close file in dtc_rcy_close
            return OG_ERROR;
        }

        errno_t ret = memcpy_sp(&file->head, sizeof(log_file_head_t), buf, sizeof(log_file_head_t));
        knl_securec_check(ret);
        OG_LOG_RUN_INF("[DTC RCY] Init logfile=%s, handle=%d, point=[%u-%u] write_pos=%llu for instance=%u",
                       file->ctrl->name, rcy_node->handle[i], file->head.rst_id, file->head.asn, file->head.write_pos,
                       rcy_node->node_id);
    }

    return OG_SUCCESS;
}

static inline bool32 dtc_stats_lsn_is_changed(uint64 *lsn_record, uint64 curr_lsn)
{
    bool32 changed = (curr_lsn != *lsn_record);
    if (changed) {
        *lsn_record = curr_lsn;
    }
    return changed;
}

void dtc_rcy_next_file(knl_session_t *session, uint32 idx, bool32 *need_more_log)
{
    OG_LOG_DEBUG_INF("[DTC RCY] dtc rcy next file");
    reset_log_t *reset_log = &session->kernel->db.ctrl.core.resetlogs;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    log_point_t *point = &rcy_log_point->rcy_write_point;
    log_point_t *reply_point = &rcy_log_point->rcy_point;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);

    if (cm_dbs_is_enable_dbs() == OG_FALSE) {
        logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
        uint32 curr_file = ctrl->log_last;
        if (LOG_POINT_FILE_EQUAL(*point, log_set->items[curr_file].head)) {
            *need_more_log = OG_FALSE;
            return;
        }
    }
    if (point->rst_id < reset_log->rst_id && point->asn == ctrl->last_asn && (uint64)point->lfn == ctrl->last_lfn) {
        point->rst_id++;
        point->asn++;
        point->block_id = 0;
        reply_point->rst_id++;
        reply_point->asn++;
        reply_point->block_id = 0;
        *need_more_log = OG_TRUE;
        if (rcy_node->latest_rcy_end_lsn != rcy_node->recovery_read_end_point.lsn) {
            OG_LOG_RUN_INF("[DTC RCY] Move log point to [%u-%u/%u/%llu]", (uint32)point->rst_id, point->asn,
                           point->block_id, (uint64)point->lfn);
        }
    } else {
        point->asn++;
        point->block_id = 0;
        reply_point->asn++;
        reply_point->block_id = 0;
        *need_more_log = OG_TRUE;
        if (rcy_node->latest_rcy_end_lsn != rcy_node->recovery_read_end_point.lsn &&
            dtc_stats_lsn_is_changed(&(rcy_node->lsn_records.move_point_lsn_record),
                                     rcy_log_point->rcy_write_point.lsn)) {
            OG_LOG_RUN_INF("[DTC RCY] Move log point to [%u-%u/%u/%llu]", (uint32)point->rst_id, point->asn,
                           point->block_id, (uint64)point->lfn);
        }
    }
    rcy_node->curr_file_length = 0;
}

// only call in dbstor opened
static bool32 dtc_rcy_check_ulog(knl_session_t *session, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    log_point_t *point = &rcy_log_point->rcy_point;
    uint64 start_lsn = point->lsn + 1;
    int32 *handle = &rcy_node->handle[0];
    logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
    log_file_t *file = &log_set->items[0];
    device_type_t type = cm_device_type(file->ctrl->name);
    // logfile can be opened for a long time, closed in db_close_log_files
    if (cm_open_device(file->ctrl->name, type, knl_io_flag(session), handle) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DB] failed to open redo log file %s ", file->ctrl->name);
        return OG_ERROR;
    }

    bool32 ulog_is_valid = cm_check_device_offset_valid(type, *handle, start_lsn);
    OG_LOG_RUN_INF("[DTC RCY] check ulog lsn %lld from %s, handle %d, inst_id %u result  %d", start_lsn,
                   file->ctrl->name, *handle, rcy_log_point->node_id, ulog_is_valid);
    return ulog_is_valid;
}

// only call in dbstor opened
static bool32 dtc_rcy_check_log_is_exist(knl_session_t *session, uint32 idx)
{
    return dtc_rcy_check_ulog(session, idx);
}

uint32 dtc_rcy_get_logfile_by_node(knl_session_t *session, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
    log_point_t *point = &rcy_log_point->rcy_write_point;
    log_file_t *file = NULL;
    OG_LOG_DEBUG_INF("[DTC RCY] dtc_rcy_get_logfile_by_node point->rst_id = %u,"
                     " point->asn = %u siz log_set->logfile_hwm = %u",
                     point->rst_id, point->asn, log_set->logfile_hwm);
    for (uint32 i = 0; i < log_set->logfile_hwm; i++) {
        file = &log_set->items[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }
        // Only one log file is required for DBStor.
        if (cm_dbs_is_enable_dbs() == OG_TRUE) {
            if (rcy_node->ulog_exist_data) {
                return i;
            }
            return OG_INVALID_ID32;
        }

        if (file->head.rst_id != point->rst_id || file->head.asn != point->asn) {
            continue;
        }

        cm_latch_s(&file->latch, session->id, OG_FALSE, NULL);
        if (file->head.rst_id != point->rst_id || file->head.asn != point->asn) {
            cm_unlatch(&file->latch, NULL);
            continue;
        }

        return i;
    }

    return OG_INVALID_ID32;
}

status_t dtc_rcy_set_batch_invalidate(knl_session_t *session, log_batch_t *batch)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[dtc_rcy->curr_node_idx];
    if (rcy_node->curr_file_length < batch->space_size) {
        return OG_SUCCESS;
    }
    rcy_node->curr_file_length -= batch->space_size;
    arch_file_t *file = &rcy_node->arch_file;
    device_type_t type = cm_device_type(file->name);
    batch->head.magic_num = LOG_INVALIDATE_MAGIC_NUMBER;
    int64 offset = (int64)(rcy_node->curr_file_length + rcy_node->blk_size);
    if (cm_write_device(type, file->handle, offset, (void *)batch, (int32)batch->space_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] ABORT INFO: flush batch:%s, offset:%lld, size:%d failed.", file->name, offset,
                       (int32)batch->space_size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t dtc_rcy_read_log(knl_session_t *session, int32 *handle, const char *name, int64 offset, void *buf,
                          int64 buf_size, int64 size_need_read, uint32 *size_read)
{
    int64 size = size_need_read;
    *size_read = 0;
    if (size_need_read == 0) {
        OG_LOG_DEBUG_WAR("[DTC RCY] read redo log size_need_read=%lld, offset=%lld, logfile handle=%d "
                         "from file=%s",
                         size_need_read, offset, *handle, name);
        return OG_SUCCESS;
    }
    if (size_need_read > buf_size) {
        size = buf_size;
    }
    device_type_t type = cm_device_type(name);
    if (type != DEV_TYPE_ULOG) {
        type = arch_get_device_type(name);
    }
    if (cm_open_device(name, type, knl_io_flag(session), handle) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to open redo log, filename=%s", name);
        return OG_ERROR;
    }
    /* size <= buf_size, (uint32)size cannot overflow */
    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        int32 return_size = 0;
        if (cm_read_device_nocheck(type, *handle, offset, buf, (int32)size, &return_size) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to read redo log size_need_read=%lld, offset=%lld, logfile handle=%d "
                           "from file=%s",
                           size_need_read, offset, *handle, name);
            if (DB_IS_MAXFIX(session)) {
                errno_t ret = memset_sp(buf, size, 0, size);
                knl_securec_check(ret);
                *size_read = size;
                return OG_SUCCESS;
            }
            return OG_ERROR;
        }
        *size_read = return_size;
    } else {
        if (cm_read_device(type, *handle, offset, buf, (int32)size) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to read redo log size_need_read=%lld, offset=%lld, logfile handle=%d "
                           "from file=%s",
                           size_need_read, offset, *handle, name);
            return OG_ERROR;
        }
        *size_read = (int32)size;
    }
    OG_LOG_DEBUG_INF("[DTC RCY] read redo log size=%lld, offset=%lld from=%s, size_need_read=%lld", size, offset, name,
                     size_need_read);
    return OG_SUCCESS;
}

static status_t dtc_rcy_read_online_log(knl_session_t *session, uint32 file_id, uint32 idx, uint32 *size_read)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    logfile_set_t *log_set = LOGFILE_SET(session, rcy_log_point->node_id);
    log_file_t *file = &log_set->items[file_id];
    int32 *handle = &rcy_node->handle[file_id];
    char *buf = rcy_node->read_buf[rcy_node->read_buf_write_index].aligned_buf;
    int64 buf_size = rcy_node->read_buf[rcy_node->read_buf_write_index].buf_size;
    log_point_t *point = &rcy_log_point->rcy_write_point;

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (rcy_node->blk_size == 0) {
        rcy_node->blk_size = file->ctrl->block_size;
    }

    int64 file_size = file->head.write_pos;
    if (file->ctrl->status == LOG_FILE_CURRENT) {
        // the write_pos of current log file is not accurate
        file_size = file->ctrl->size;
    }

    int64 offset = (int64)point->block_id * file->ctrl->block_size;
    int64 size_need_read = file_size - offset;
    // Obtain logs based on the LSN for DBStor.
    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        offset = point->lsn + 1;    // read redo data after rcy_point.
        size_need_read = buf_size;  // read as much data as possible.
        OG_LOG_DEBUG_INF("[DTC RCY] dtc_rcy_read_online_log cm_dbs_is_enable_dbs() == OG_TRUE offset=%llu", offset);
    }
    if (rcy_node->latest_lsn != offset) {
        OG_LOG_RUN_INF("[DTC RCY] start read online redo log point %u/%u/%lld from %s", point->asn, point->block_id,
                       offset, file->ctrl->name);
        rcy_node->latest_lsn = offset;
    }

    {
        dtc_rcy_point_bounds_t bounds;
        if (dtc_rcy_get_point_bounds(session, rcy_log_point->node_id, point, &bounds)) {
            if (bounds.offset_gt_write_pos) {
                dtc_rcy_rbp_log_root_cause(session, rcy_log_point->node_id, "read_online", "READ_OFFSET_GE_WRITE_POS",
                    point, NULL, &bounds, 0, point->block_id);
            } else if (bounds.use_logical_file_size && size_need_read > 0 &&
                (uint64)offset + (uint64)size_need_read > bounds.write_pos) {
                dtc_rcy_rbp_log_root_cause(session, rcy_log_point->node_id, "read_online",
                    "READ_PAST_EOF_USING_CTRL_SIZE", point, NULL, &bounds, 0, point->block_id);
            }
        }
    }

    return dtc_rcy_read_log(session, handle, file->ctrl->name, offset, buf, buf_size, size_need_read, size_read);
}

static status_t dtc_rcy_load_archfile_no_dbs(knl_session_t *session, uint32 idx, arch_file_t *file, log_point_t *point)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    if (!arch_get_archived_log_name(session, (uint32)point->rst_id, point->asn, ARCH_DEFAULT_DEST, file->name,
                                    OG_FILE_NAME_BUFFER_SIZE, rcy_node->node_id)) {
        // Need to use the archive dest of corresponding node
        arch_set_archive_log_name(session, (uint32)point->rst_id, point->asn, ARCH_DEFAULT_DEST, file->name,
                                  OG_FILE_NAME_BUFFER_SIZE, rcy_node->node_id);
        if (!cm_exist_device(arch_get_device_type(file->name), file->name)) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to get archived redo log file[%u-%u] for instance %u name:%s",
                           (uint32)point->rst_id, point->asn, rcy_node->node_id, file->name);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t dtc_rcy_load_archfile(knl_session_t *session, uint32 idx, arch_file_t *file, log_point_t *point,
                                      bool8 *finish)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    bool32 is_dbstor = cm_dbs_is_enable_dbs();
    if (!DB_CLUSTER_NO_CMS && !is_dbstor && file->head.rst_id == point->rst_id && file->head.asn == point->asn) {
        // already load the need archived logfile.
        OG_LOG_RUN_INF("[DTC RCY] dtc rcy load archfile already load the need archived logfile %u/%u/ ", point->asn,
                       point->block_id);
        return OG_SUCCESS;
    }
    device_type_t type = arch_get_device_type(file->name);
    if (file->handle != OG_INVALID_HANDLE) {
        cm_close_device(type, &file->handle);
        file->handle = OG_INVALID_HANDLE;
    }

    if (is_dbstor || DB_CLUSTER_NO_CMS) {
        arch_ctrl_t *arch_ctrl = arch_get_archived_log_info_for_recovery(session, (uint32)point->rst_id, point->asn,
                                                                         ARCH_DEFAULT_DEST, point->lsn,
                                                                         rcy_node->node_id);
        if (arch_ctrl == NULL) {
            OG_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                                 "[RECOVERY] failed to get archived log for [%u-%u-%u-%llu]", rcy_node->node_id,
                                 point->rst_id, point->asn, point->lsn);
            if (!DB_CLUSTER_NO_CMS) {
                return OG_ERROR;
            }
            if (dtc_rcy_load_archfile_no_dbs(session, idx, file, point) != OG_SUCCESS) {
                OG_LOG_RUN_WAR("[DTC RCY] dtc rcy load archfile no dbs is null %u/%u/%s ", point->asn, point->block_id,
                               file->name);
                *finish = OG_TRUE;
                return OG_SUCCESS;
            }
        }
        if (arch_ctrl != NULL) {
            point->asn = arch_ctrl->asn;
            OG_LOG_RUN_INF("[DTC RCY] dtc rcy load archfile arch ctrl is null %u/%u/%s ", point->asn, point->block_id,
                           file->name);
            arch_file_name_info_t file_name_info = {
                arch_ctrl->rst_id,    arch_ctrl->asn,     rcy_node->node_id, OG_FILE_NAME_BUFFER_SIZE,
                arch_ctrl->start_lsn, arch_ctrl->end_lsn, file->name
            };
            char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
            status_t ret = snprintf_s(str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s", file->name);
            knl_securec_check_ss(ret);
            arch_set_archive_log_name_with_lsn(session, ARCH_DEFAULT_DEST, &file_name_info);
            if (!cm_exist_device(type, file->name)) {
                OG_LOG_RUN_WAR("[DTC RCY] get archived redo log file[%u-%u] for instance %u", (uint32)point->rst_id,
                               point->asn, rcy_node->node_id);
                if (!DB_CLUSTER_NO_CMS) {
                    return OG_ERROR;
                }
                ret = snprintf_s(file->name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s", str_buf);
                knl_securec_check_ss(ret);
                if (dtc_rcy_load_archfile_no_dbs(session, idx, file, point) != OG_SUCCESS) {
                    OG_LOG_RUN_INF("[DTC RCY] dtc rcy load archfile no dbs is null %u/%u/%s ", point->asn,
                                   point->block_id, file->name);
                    *finish = OG_TRUE;
                    return OG_SUCCESS;
                }
            }
        }
    } else {
        if (dtc_rcy_load_archfile_no_dbs(session, idx, file, point) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] dtc rcy load archfile %u/%u/%s ", point->asn, point->block_id, file->name);
            return OG_ERROR;
        }
    }

    type = arch_get_device_type(file->name);
    if (cm_open_device(file->name, type, knl_io_flag(session), &file->handle) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to open archived redo log file %s", file->name);
        return OG_ERROR;
    }

    /* size <= buf_size, (uint32)size cannot overflow */
    if (cm_read_device(type, file->handle, 0, rcy_node->read_buf[rcy_node->read_buf_write_index].aligned_buf,
                       CM_CALC_ALIGN((uint32)sizeof(log_file_head_t), 512)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to read %s, offset 0 handle %d", file->name, file->handle);
        return OG_ERROR;
    }

    errno_t errcode;
    errcode = memcpy_s(&file->head, (int32)sizeof(log_file_head_t),
                       rcy_node->read_buf[rcy_node->read_buf_write_index].aligned_buf, (int32)sizeof(log_file_head_t));
    knl_securec_check(errcode);

    return log_verify_head_checksum(session, &file->head, file->name);
}

bool32 dtc_rcy_validate_batch(log_batch_t *batch)
{
    if (batch == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] dtc rcy validate batch is NULL");
        return OG_FALSE;
    }
    if (batch->size < sizeof(log_batch_t) || batch->space_size < batch->size ||
        batch->size > OG_MAX_BATCH_SIZE || batch->space_size > OG_MAX_BATCH_SIZE) {
        OG_LOG_RUN_ERR("[DTC RCY] validate batch failed: invalid size, magic=%llx size=%u space_size=%u",
                    (uint64)batch->head.magic_num, batch->size, batch->space_size);
        return OG_FALSE;
    }
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    if (tail == NULL) {
        OG_LOG_RUN_ERR("dtc rcy validate batch tail is NULL");
        return OG_FALSE;
    }
    if (batch->head.magic_num == LOG_MAGIC_NUMBER && tail->magic_num == LOG_MAGIC_NUMBER &&
        batch->head.point.lfn == tail->point.lfn && batch->size != 0) {
        return OG_TRUE;
    }

    if (batch->head.magic_num == LOG_INVALIDATE_MAGIC_NUMBER && tail->magic_num == LOG_MAGIC_NUMBER &&
        batch->head.point.lfn == tail->point.lfn && batch->size != 0) {
        return OG_FALSE;
    }
    OG_LOG_RUN_ERR("[DTC RCY] head magic_num:%llx, lsn:%llu, lfn:%llu, tail magic_num:%llx, lsn:%llu, "
                   "lfn:%llu, size:%u",
                   batch->head.magic_num, batch->head.point.lsn, (uint64)batch->head.point.lfn, tail->magic_num,
                   tail->point.lsn, (uint64)tail->point.lfn, batch->size);
    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        if (g_instance->kernel.db.open_status == DB_OPEN_STATUS_MAX_FIX) {
            return OG_FALSE;
        }
        knl_panic(0);
    }
    return OG_FALSE;
}

status_t dtc_rcy_find_batch_by_lsn(char *buf, dtc_rcy_node_t *rcy_node, log_point_t *point, int32 size_read,
                                   bool8 *is_find_start)
{
    int32 buffer_size = size_read;
    uint32 invalide_size = 0;
    log_batch_t *batch = NULL;
    if (buf == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] batch is null, read_size[%d], invalide_size[%u], point[%u/%u/%u%llu/%llu]", size_read,
                       invalide_size, point->rst_id, point->asn, point->block_id, point->lsn, (uint64)point->lfn);
        return OG_ERROR;
    }
    while (buffer_size >= sizeof(log_batch_t)) {
        batch = (log_batch_t *)(buf + invalide_size);
        if (buffer_size < batch->size) {
            break;
        }
        if (!dtc_rcy_validate_batch(batch)) {
            OG_LOG_RUN_ERR("[DTC RCY] batch is invalidate, read_size[%d], invalide_size[%u], point[%u/%u/%u%llu/%llu]",
                           size_read, invalide_size, point->rst_id, point->asn, point->block_id, point->lsn,
                           (uint64)point->lfn);
            rcy_node->recover_done = OG_TRUE;
            *is_find_start = OG_TRUE;
            rcy_node->read_pos[rcy_node->read_buf_write_index] += invalide_size;
            return OG_ERROR;
        }
        if (batch->head.point.lsn > point->lsn) {
            break;
        }
        invalide_size += batch->space_size;
        buffer_size -= batch->space_size;
    }
    point->block_id += invalide_size / rcy_node->blk_size;
    rcy_node->curr_file_length += invalide_size;
    if (batch->head.point.lsn > point->lsn) {
        *is_find_start = OG_TRUE;
        rcy_node->read_pos[rcy_node->read_buf_write_index] += invalide_size;
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

status_t dtc_rcy_read_archived_log(knl_session_t *session, uint32 idx, uint32 *size_read)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    arch_file_t *file = &rcy_node->arch_file;
    char *buf = rcy_node->read_buf[rcy_node->read_buf_write_index].aligned_buf;
    int64 buf_size = rcy_node->read_buf[rcy_node->read_buf_write_index].buf_size;
    log_point_t *point = &rcy_log_point->rcy_write_point;
    bool8 is_find_start = OG_TRUE;
    bool8 repair_finish = OG_FALSE;

    if (dtc_rcy_load_archfile(session, idx, file, point, &repair_finish) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (repair_finish) {
        OG_LOG_RUN_INF("repair page read archiver log finish");
        return OG_SUCCESS;
    }

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (point->block_id == OG_INFINITE32) {
        is_find_start = OG_FALSE;
        point->block_id = 1;
    }

    if (rcy_node->blk_size == 0) {
        rcy_node->blk_size = file->head.block_size;
    }

    do {
        int64 offset = (int64)point->block_id * file->head.block_size;
        int64 size_need_read = file->head.write_pos - offset;
        status_t status = dtc_rcy_read_log(session, &file->handle, file->name, offset, buf, buf_size, size_need_read,
                                           size_read);
        if (status != OG_SUCCESS) {
            return status;
        }
        if (*size_read == 0) {
            return status;
        }
        if (is_find_start) {
            break;
        }
        // seek batch pos by lsn, only recovery for restore and opened dbstor
        // other by blockid
        if (dtc_rcy_find_batch_by_lsn(buf, rcy_node, point, (int32)(*size_read), &is_find_start) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } while (*size_read != 0 && !is_find_start);
    return OG_SUCCESS;
}

static status_t dtc_recover_check_assign_nodeid(knl_session_t *session, uint32_t node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = NULL;
    dtc_node_ctrl_t *ctrl = NULL;

    knl_panic(node_id <= dtc_rcy->node_count);

    rcy_log_point = &dtc_rcy->rcy_log_points[node_id];
    ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);

    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                         "[DTC RCY] node:%u, recovery real end with file: %u, point: %u, lfn: %llu",
                         rcy_log_point->node_id, rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                         (uint64)rcy_log_point->rcy_point.lfn);
    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                         "[DTC RCY] node:%u, current lfn: %llu, rcy point lfn: %llu, lrp point lfn: %llu",
                         rcy_log_point->node_id, (uint64)rcy_log_point->rcy_point.lfn, (uint64)ctrl->rcy_point.lfn,
                         (uint64)(uint64)ctrl->lrp_point.lfn);
    OG_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                         "[DTC RCY] node:%u, recovery real end with file: %u, read node log proc point: %u, lfn: %llu",
                         rcy_log_point->node_id, rcy_log_point->rcy_write_point.asn,
                         rcy_log_point->rcy_write_point.block_id, (uint64)rcy_log_point->rcy_write_point.lfn);

    if (rcy_log_point->rcy_write_point.lfn >= ctrl->lrp_point.lfn) {
        return OG_SUCCESS;
    }

    cm_reset_error();
    OG_THROW_ERROR(ERR_INVALID_RCV_END_POINT, rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                   rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id);
    return OG_ERROR;
}

bool8 dtc_rcy_check_recovery_is_done(knl_session_t *session, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    if ((cm_dbs_is_enable_dbs() == OG_TRUE) && (session->kernel->db.recover_for_restore == OG_FALSE) &&
        (rcy_node->ulog_exist_data == OG_FALSE)) {
        rcy_node->recover_done = OG_TRUE;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void dtc_standby_update_lrp(knl_session_t *session, uint32 idx, uint32 size_read)
{
    OG_LOG_DEBUG_INF("[DTC RCY] dtc start standby update lrp idx=%u size_read=%u", idx, size_read);
    if (DB_IS_PRIMARY(&session->kernel->db)) {
        OG_LOG_DEBUG_INF("[DTC RCY] dtc standby update lrp idx=%u size_read=%u DB_IS_PRIMARY", idx, size_read);
        return;
    }

    // just update ctrl lrp point in lrpl_proc
    lrpl_context_t *lrpl_ctx = &session->kernel->lrpl_ctx;
    if (lrpl_ctx->is_replaying == OG_FALSE) {
        OG_LOG_DEBUG_INF("[DTC RCY] dtc standby update lrp idx=%u size_read=%u is not replaying ", idx, size_read);
        return;
    }

    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    // find last lsn in log
    log_batch_t *batch = NULL;
    log_batch_t *tmp_batch = dtc_rcy_get_curr_batch(dtc_rcy, idx, rcy_node->read_buf_write_index);
    uint32 left_size;
    for (;;) {
        left_size = size_read - rcy_node->read_pos[rcy_node->read_buf_write_index];
        OG_LOG_DEBUG_INF("[DTC RCY] dtc standby update lrp idx=%u size_read=%u process batch left_size=%u", idx,
                         size_read, left_size);
        if (left_size < sizeof(log_batch_t) || left_size < tmp_batch->space_size) {
            break;
        }
        batch = dtc_rcy_get_curr_batch(dtc_rcy, idx, rcy_node->read_buf_write_index);
        rcy_node->read_pos[rcy_node->read_buf_write_index] += batch->space_size;
        tmp_batch = dtc_rcy_get_curr_batch(dtc_rcy, idx, rcy_node->read_buf_write_index);
    }
    if (batch == NULL) {
        OG_LOG_DEBUG_INF("[DTC RCY] dtc standby update lrp idx=%u size_read=%u batch==null", idx, size_read);
        return;
    }
    rcy_node->read_pos[rcy_node->read_buf_write_index] = 0;
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, idx);
    OG_LOG_DEBUG_INF("[DTC RCY] ctrl lsn %llu lfn %llu ,log end lsn %llu, lfn %llu", ctrl->lsn, ctrl->lfn,
                     batch->head.point.lsn, (uint64)batch->head.point.lfn);
    if (ctrl->lrp_point.lsn < batch->head.point.lsn) {
        ctrl->lrp_point = batch->head.point;
        ctrl->scn = DB_CURR_SCN(session);
        ctrl->lsn = batch->head.point.lsn;
        ctrl->lfn = (uint64)batch->head.point.lfn;
        if (dtc_save_ctrl(session, idx) != OG_SUCCESS) {
            CM_ABORT(0, "ABORT INFO: save core control file failed when update standby cluster ctrl");
        }
    }
    return;
}

status_t dtc_rcy_read_node_log(knl_session_t *session, uint32 idx, uint32 *size_read)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];

    status_t status;
    uint64_t tv_begin;

    rcy_node->read_pos[rcy_node->read_buf_write_index] = 0;
    rcy_node->write_pos[rcy_node->read_buf_write_index] = 0;

    if (DB_IS_PRIMARY(&session->kernel->db) && rcy_node->recover_done) {
        // current instance has nothing to recover.
        return OG_SUCCESS;
    }

    if (DB_IS_PRIMARY(&session->kernel->db) && dtc_rcy_check_recovery_is_done(session, idx)) {
        return OG_SUCCESS;
    }
    uint32 logfile_id = dtc_rcy_get_logfile_by_node(session, idx);
    if (logfile_id != OG_INVALID_ID32) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_RECOVERY_READ_ONLINE_LOG, &tv_begin);
        status = dtc_rcy_read_online_log(session, logfile_id, idx, size_read);
        log_unlatch_file(session, logfile_id);
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_RECOVERY_READ_ONLINE_LOG, &tv_begin);
        if (!DB_IS_PRIMARY(&session->kernel->db) && (*size_read == 0)) {
            OG_LOG_DEBUG_INF("[DTC RCY] finish read online redo log of crashed node=%u, logfile_id=%u, size_read=%u",
                             rcy_node->node_id, logfile_id, *size_read);
        } else {
            dtc_standby_update_lrp(session, idx, *size_read);
            if (dtc_stats_lsn_is_changed(&(rcy_node->lsn_records.read_log_lsn_record),
                                         rcy_log_point->rcy_write_point.lsn)) {
                OG_LOG_RUN_INF("[DTC RCY] finish read online redo log of crashed node=%u, logfile_id=%u, size_read=%u",
                               rcy_node->node_id, logfile_id, *size_read);
            }
        }
    } else {
        status = dtc_rcy_read_archived_log(session, idx, size_read);
        OG_LOG_DEBUG_INF("[DTC RCY] dtc rcy read archived redo log of crashed node=%u, logfile_id=%u, size_read=%u",
                         rcy_node->node_id, logfile_id, *size_read);
        if ((status != OG_SUCCESS) && (dtc_recover_check_assign_nodeid(session, idx) == OG_SUCCESS)) {
            return OG_SUCCESS;
        }
    }

    if (status == OG_ERROR) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to load redo log of crashed node=%u", rcy_node->node_id);
        return OG_ERROR;
    }

    rcy_node->write_pos[rcy_node->read_buf_write_index] += *size_read;

    if (dtc_rcy->rcy_stat.last_rcy_set_num <= 0) {
        dtc_rcy->rcy_stat.last_rcy_log_size += *size_read;
    }

    return OG_SUCCESS;
}

static status_t dtc_read_all_logs(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    // load redo log into buffer
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        if (dtc_init_node_logset(session, i) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to init logset for crashed node=%u", dtc_rcy->rcy_nodes[i].node_id);
            return OG_ERROR;
        }

        if (cm_dbs_is_enable_dbs() == OG_TRUE) {
            dtc_rcy->rcy_nodes[i].ulog_exist_data = dtc_rcy_check_log_is_exist(session, i);
        }
    }

    return OG_SUCCESS;
}

status_t dtc_rcy_verify_analysis_and_recovery_log_point(log_point_t analysis_read_end_point,
                                                        log_point_t recovery_read_end_point)
{
    if (analysis_read_end_point.asn != recovery_read_end_point.asn) {
        return OG_ERROR;
    }
    if (analysis_read_end_point.block_id != recovery_read_end_point.block_id) {
        return OG_ERROR;
    }
    if (analysis_read_end_point.lfn != recovery_read_end_point.lfn) {
        return OG_ERROR;
    }
    if (analysis_read_end_point.lsn != recovery_read_end_point.lsn) {
        return OG_ERROR;
    }
    if (analysis_read_end_point.rst_id != recovery_read_end_point.rst_id) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static uint64 dtc_rcy_get_ddl_pitr_lsn(knl_session_t *session, uint64 curr_batch_lsn)
{
    if (session->kernel->db.recover_for_restore && session->kernel->db.ctrl.core.ddl_pitr_lsn != 0) {
        return session->kernel->db.ctrl.core.ddl_pitr_lsn;
    } else {
        return curr_batch_lsn;
    }
}

status_t dtc_find_next_batch(knl_session_t *session, log_batch_t **batch, uint32 cur_block_id, uint64 cur_lsn,
                             uint32 node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[node_id];
    rcy_node->read_pos[rcy_node->read_buf_read_index] = rcy_node->write_pos[rcy_node->read_buf_read_index];
    rcy_log_point->rcy_point.block_id = cur_block_id + 1;
    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        rcy_log_point->rcy_point.lsn = cur_lsn + 1;
    }

    OG_RETURN_IFERR(dtc_update_batch(session, node_id));
    if (rcy_node->recover_done == OG_TRUE) {
        OG_LOG_RUN_INF("recovery done");
        return OG_SUCCESS;
    }
    *batch = dtc_rcy_get_curr_batch(dtc_rcy, node_id, rcy_node->read_buf_read_index);
    return OG_SUCCESS;
}

status_t dtc_skip_batch(knl_session_t *session, log_batch_t **batch, uint32 node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[node_id];
    rcy_node->read_pos[rcy_node->read_buf_read_index] += (*batch)->space_size;
    rcy_log_point->rcy_point.block_id += (*batch)->space_size / rcy_node->blk_size;
    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        rcy_log_point->rcy_point.lsn = (*batch)->lsn;
    }
    OG_RETURN_IFERR(dtc_update_batch(session, node_id));
    if (rcy_node->recover_done == OG_TRUE) {
        OG_LOG_RUN_INF("recovery done");
        return OG_SUCCESS;
    }
    *batch = dtc_rcy_get_curr_batch(dtc_rcy, node_id, rcy_node->read_buf_read_index);
    return OG_SUCCESS;
}

status_t dtc_skip_damage_batch(knl_session_t *session, log_batch_t **batch, uint32 node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[node_id];
    uint32 cur_block_id = rcy_log_point->rcy_point.block_id;
    uint64 cur_lsn = rcy_log_point->rcy_point.lsn;
    do {
        if (dtc_rcy_validate_batch(*batch)) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to verify log batch checksum of instance %u with rcy point"
                           " [%u-%u/%u%llu], betch_lsn=%llu",
                           rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                           rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn, (*batch)->lsn);
            OG_RETURN_IFERR(dtc_skip_batch(session, batch, node_id));
        } else {
            OG_LOG_RUN_ERR("[DTC RCY] batch is invalid, find next batch by block_id[%u] lsn[%llu]", cur_block_id,
                           cur_lsn);
            OG_RETURN_IFERR(dtc_find_next_batch(session, batch, cur_block_id, cur_lsn, node_id));
            cur_block_id++;
            cur_lsn++;
        }
        if (rcy_node->recover_done == OG_TRUE) {
            OG_LOG_RUN_INF("recovery done");
            return OG_SUCCESS;
        }
    } while (!dtc_rcy_validate_batch(*batch) || (rcy_verify_checksum(session, *batch) != OG_SUCCESS));

    OG_LOG_RUN_INF("find new batch and continue");
    return OG_SUCCESS;
}

static bool32 dtc_standby_rcy_end(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 node_id = 0; node_id < session->kernel->db.ctrl.core.node_count; node_id++) {
        reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[node_id];
        dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);
        if (rcy_log_point->rcy_point.lfn < ctrl->lrp_point.lfn) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

status_t dtc_update_batch(knl_session_t *session, uint32 node_id)
{
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    log_batch_t *batch = NULL;
    uint32 left_size;
    date_t update_begin = 0;

    if (g_dtc_rcy_fetch_diag_active != NULL) {
        update_begin = cm_now();
    }
    if (!DB_IS_PRIMARY(&session->kernel->db) && (DB_NOT_READY(session) || !dtc_rcy->full_recovery) &&
        dtc_standby_rcy_end(session)) {
        rcy_node->recover_done = OG_TRUE;
        rcy_node->read_size[rcy_node->read_buf_read_index] = OG_INVALID_ID32;
        rcy_node->read_buf_ready[rcy_node->read_buf_read_index] = OG_FALSE;
        if (dtc_rcy->phase == PHASE_ANALYSIS) {
            OG_LOG_RUN_INF("[DTC RCY] analysis read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                           rcy_node->analysis_read_end_point.asn, rcy_node->analysis_read_end_point.block_id,
                           (uint64)rcy_node->analysis_read_end_point.rst_id,
                           (uint64)rcy_node->analysis_read_end_point.lfn, rcy_node->analysis_read_end_point.lsn);
        }
        if (dtc_rcy->phase == PHASE_RECOVERY) {
            OG_LOG_RUN_INF("[DTC RCY] recovery read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                           rcy_node->recovery_read_end_point.asn, rcy_node->recovery_read_end_point.block_id,
                           (uint64)rcy_node->recovery_read_end_point.rst_id,
                           (uint64)rcy_node->recovery_read_end_point.lfn, rcy_node->recovery_read_end_point.lsn);
        }
        DTC_RCY_FETCH_DIAG_ACCUM(update_batch_us, update_begin);
        return OG_SUCCESS;
    }

    wait_for_read_buf_finish_read(node_id);
    if (rcy_node->read_size[rcy_node->read_buf_read_index] == 0) {
        check_node_read_end(node_id);
        rcy_node->read_size[rcy_node->read_buf_read_index] = OG_INVALID_ID32;
        rcy_node->read_buf_ready[rcy_node->read_buf_read_index] = OG_FALSE;
        OG_LOG_DEBUG_INF("dtc update batch rcy_node->read_size[rcy_node->read_buf_read_index] == 0 node_id=%u",
                         node_id);
        DTC_RCY_FETCH_DIAG_ACCUM(update_batch_us, update_begin);
        return OG_SUCCESS;
    }
    batch = dtc_rcy_get_curr_batch(dtc_rcy, node_id, rcy_node->read_buf_read_index);
    left_size = rcy_node->write_pos[rcy_node->read_buf_read_index] - rcy_node->read_pos[rcy_node->read_buf_read_index];
    if (left_size < sizeof(log_batch_t) || left_size < batch->space_size) {
        rcy_node->read_size[rcy_node->read_buf_read_index] = OG_INVALID_ID32;
        rcy_node->read_buf_ready[rcy_node->read_buf_read_index] = OG_FALSE;
        rcy_node->read_buf_read_index = (rcy_node->read_buf_read_index + 1) % read_buf_size;
        dtc_rcy_fetch_diag_inc_slot_release();
        OG_LOG_DEBUG_INF("[DTC RCY] dtc update batch left size < sizeof(log_batch_t)"
                         " node_id = %u read_buf_read_index = %u",
                         rcy_node->node_id, rcy_node->read_buf_read_index);
        wait_for_read_buf_finish_read(node_id);
        check_node_read_end(node_id);
    }
    DTC_RCY_FETCH_DIAG_ACCUM(update_batch_us, update_begin);
    return OG_SUCCESS;
}

static void dtc_rcy_release_read_buf(uint32 node_id, const char *reason)
{
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    uint8 read_idx = rcy_node->read_buf_read_index;

    if (!rcy_node->read_buf_ready[read_idx]) {
        return;
    }

    rcy_node->read_size[read_idx] = OG_INVALID_ID32;
    rcy_node->read_buf_ready[read_idx] = OG_FALSE;
    rcy_node->read_buf_read_index = (read_idx + 1) % read_buf_size;
    dtc_rcy_fetch_diag_inc_slot_release();
    OG_LOG_DEBUG_INF("[DTC RCY] release read buf idx=%u node_id=%u read_idx=%u next_read_idx=%u reason=%s",
                     node_id, rcy_node->node_id, read_idx, rcy_node->read_buf_read_index, reason);
}

static void dtc_rcy_release_read_buf_if_exhausted(uint32 node_id, const char *reason)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    uint8 read_idx = rcy_node->read_buf_read_index;

    if (!rcy_node->read_buf_ready[read_idx]) {
        return;
    }

    uint32 left_size = rcy_node->write_pos[read_idx] - rcy_node->read_pos[read_idx];
    if (left_size >= sizeof(log_batch_t)) {
        log_batch_t *batch = dtc_rcy_get_curr_batch(dtc_rcy, node_id, read_idx);
        if (batch != NULL && batch->space_size != 0 && left_size >= batch->space_size) {
            return;
        }
    }

    dtc_rcy_release_read_buf(node_id, reason);
}

static void find_max_lsn_and_move_point(uint32 idx, uint32 *size_read)
{
    OG_LOG_DEBUG_INF("[DTC RCY] start find max lsn and move point idx=%u size_read=%u", idx, *size_read);
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[idx];
    log_batch_t *batch = NULL;
    log_batch_t *tmp_batch = dtc_rcy_get_curr_batch(dtc_rcy, idx, rcy_node->read_buf_write_index);
    uint32 left_size = *size_read - rcy_node->read_pos[rcy_node->read_buf_write_index];
    if (left_size < sizeof(log_batch_t) || tmp_batch == NULL || left_size < tmp_batch->space_size) {
        OG_LOG_DEBUG_INF("[DTC RCY] find max lsn and move point left_size"
                         " < sizeof(log_batch_t) || left_size < tmp_batch->space_size");
        return;
    }
    if (dtc_rcy_validate_batch(tmp_batch) == OG_FALSE) {
        OG_LOG_RUN_ERR("[DTC RCY] find max lsn and move point batch is invalidate, read_size=%u", *size_read);
        reform_rcy_node_t *rcy_log_point_bad = &dtc_rcy->rcy_log_points[idx];
        if (dtc_rcy->phase == PHASE_RECOVERY && !dtc_rcy->full_recovery &&
            rcy_log_point_bad->node_id < OG_MAX_INSTANCES &&
            dtc_rcy->rbp_jump_taken[rcy_log_point_bad->node_id]) {
            uint64 invalid_lfn = (uint64)tmp_batch->head.point.lfn;

            if (dtc_rcy->rbp_tail_find_max_invalid_count == 0) {
                dtc_rcy->rbp_tail_find_max_invalid_first_lfn = invalid_lfn;
            }
            dtc_rcy->rbp_tail_find_max_invalid_count++;
            dtc_rcy->rbp_tail_find_max_invalid_bytes += *size_read;
            dtc_rcy->rbp_tail_find_max_invalid_last_lfn = invalid_lfn;
        }
        if (dtc_rcy->ss != NULL) {
            dtc_rcy_rbp_log_root_cause(dtc_rcy->ss, rcy_log_point_bad->node_id, "find_max", "INVALID_BATCH_FIND_MAX",
                &rcy_log_point_bad->rcy_write_point, tmp_batch, NULL, 0,
                rcy_log_point_bad->rcy_write_point.block_id);
        }
        *size_read = 0;
        return;
    }
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    uint32 old_read_pos = rcy_node->read_pos[rcy_node->read_buf_write_index];
    for (;;) {
        left_size = *size_read - rcy_node->read_pos[rcy_node->read_buf_write_index];
        if (left_size < sizeof(log_batch_t) || tmp_batch == NULL || left_size < tmp_batch->space_size) {
            OG_LOG_DEBUG_INF("[DTC RCY] find max lsn and move point left_size "
                             "< sizeof(log_batch_t) || left_size < tmp_batch->space_size");
            break;
        }
        batch = dtc_rcy_get_curr_batch(dtc_rcy, idx, rcy_node->read_buf_write_index);
        {
            uint32 blk_before = rcy_log_point->rcy_write_point.block_id;
            rcy_log_point->rcy_write_point.block_id += batch->space_size / rcy_node->blk_size;
            if (dtc_rcy->ss != NULL) {
                dtc_rcy_rbp_check_cursor_fly_first(dtc_rcy->ss, rcy_log_point->node_id, "find_max",
                    "FIRST_CURSOR_FLY_FIND_MAX", &rcy_log_point->rcy_write_point, batch, blk_before,
                    rcy_log_point->rcy_write_point.block_id);
            }
        }
        rcy_node->read_pos[rcy_node->read_buf_write_index] += batch->space_size;
        left_size = *size_read - rcy_node->read_pos[rcy_node->read_buf_write_index];
        tmp_batch = dtc_rcy_get_curr_batch(dtc_rcy, idx, rcy_node->read_buf_write_index);
        if (left_size < sizeof(log_batch_t) || tmp_batch == NULL || left_size < tmp_batch->space_size) {
            OG_LOG_DEBUG_INF("[DTC RCY] get next batch, find max lsn and move point left_size "
                             "< sizeof(log_batch_t) || left_size < tmp_batch->space_size");
            break;
        }
        if (dtc_rcy_validate_batch(tmp_batch) == OG_FALSE) {
            OG_LOG_RUN_ERR("[DTC RCY] find max lsn and move point batch is invalidate, read_size=%u", *size_read);
            if (dtc_rcy->phase == PHASE_RECOVERY && rcy_log_point->node_id < OG_MAX_INSTANCES &&
                dtc_rcy->rbp_jump_taken[rcy_log_point->node_id]) {
                uint64 invalid_lfn = (uint64)tmp_batch->head.point.lfn;

                if (dtc_rcy->rbp_tail_find_max_invalid_count == 0) {
                    dtc_rcy->rbp_tail_find_max_invalid_first_lfn = invalid_lfn;
                }
                dtc_rcy->rbp_tail_find_max_invalid_count++;
                dtc_rcy->rbp_tail_find_max_invalid_bytes += *size_read;
                dtc_rcy->rbp_tail_find_max_invalid_last_lfn = invalid_lfn;
            }
            break;
        }
    }
    if (batch == NULL) {
        return;
    }
    rcy_node->read_pos[rcy_node->read_buf_write_index] = old_read_pos;
    rcy_log_point->rcy_write_point.lsn = batch->lsn;
    rcy_log_point->rcy_write_point.lfn = batch->head.point.lfn;
    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        rcy_log_point->rcy_write_point.lsn = batch->lsn;
    }
    OG_LOG_DEBUG_INF("[DTC RCY] finish find max lsn and move point idx=%u size_read=%u lsn=%llu block_id=%u", idx,
                     *size_read, rcy_log_point->lsn, rcy_log_point->rcy_point.block_id);
}

static status_t dtc_read_node_log(dtc_rcy_context_t *dtc_rcy, knl_session_t *session, uint32 node_id, uint32 *read_size)
{
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[node_id];
    // need to read log
    if (dtc_rcy_read_node_log(session, node_id, read_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to load redo log of crashed node=%u", rcy_node->node_id);
        CM_ABORT(0, "ABORT INFO:dtc read node log failed");
        return OG_ERROR;
    }
    if (*read_size == 0) {
        // try to advance log point to next file
        bool32 not_finished = OG_TRUE;
        dtc_rcy_next_file(session, node_id, &not_finished);

        if (not_finished) {
            // read log again after advancing the log point
            if (dtc_rcy_read_node_log(session, node_id, read_size) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to load redo log of instance=%u", rcy_node->node_id);
                CM_ABORT(0, "ABORT INFO:dtc read node log failed");
                return OG_ERROR;
            }
        }
        rcy_node->not_finished[rcy_node->read_buf_write_index] = not_finished;
    }
    if (*read_size != 0) {
        find_max_lsn_and_move_point(node_id, read_size);
    }
    return OG_SUCCESS;
}

bool32 dtc_log_need_reload(knl_session_t *session, uint32 node_id, bool32 batch_loaded)
{
    lrpl_context_t *lrpl_ctx = &session->kernel->lrpl_ctx;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    if (DB_IS_PRIMARY(&session->kernel->db) || (DB_NOT_READY(session) || !dtc_rcy->full_recovery) || node_id == 0) {
        lrpl_ctx->redo_is_reload = OG_FALSE;
        return OG_FALSE;
    }
    if (batch_loaded == OG_TRUE) {
        lrpl_ctx->redo_is_reload = OG_FALSE;
        return OG_FALSE;
    }
    // if node 1 is not a new buffer, no need to reload
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[1];
    if (rcy_node->read_pos[rcy_node->read_buf_read_index] != 0) {
        lrpl_ctx->redo_is_reload = OG_FALSE;
        return OG_FALSE;
    }

    OG_LOG_DEBUG_INF("[DTC LRPL] lrpl_ctx->redo_is_reload = %u, node_id = %u", lrpl_ctx->redo_is_reload, node_id);
    if (lrpl_ctx->redo_is_reload) {
        lrpl_ctx->redo_is_reload = OG_FALSE;
        OG_LOG_DEBUG_INF("[DTC LRPL] redo no need reload");
        return OG_FALSE;
    }
    lrpl_ctx->redo_is_reload = OG_TRUE;
    OG_LOG_DEBUG_INF("[DTC LRPL] redo need reload");
    return OG_TRUE;
}

static status_t dtc_rcy_fetch_log_batch(knl_session_t *session, log_batch_t **batch_out, uint32 *curr_node_idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_batch_t *batch = NULL;
    bool32 batch_loaded = OG_FALSE;
    dtc_rcy_node_t *rcy_node = NULL;
    reform_rcy_node_t *rcy_log_point = NULL;
    uint64 curr_batch_lsn = OG_INVALID_ID64;
    uint8 curr_node = OG_INVALID_ID8;
    date_t rbp_jump_begin;
    date_t node_scan_begin;
    date_t validate_begin;
    date_t checksum_begin;
    date_t commit_begin;
    date_t lfn_map_begin;
    bool32 retry_rbp_tail = OG_FALSE;
    bool32 retry_fetch = OG_TRUE;
    *batch_out = NULL;

    if (g_dtc_rcy_fetch_diag_active != NULL) {
        g_dtc_rcy_fetch_diag_active->fetch_calls++;
    }

    while (retry_fetch) {
        retry_fetch = OG_FALSE;
        batch = NULL;
        batch_loaded = OG_FALSE;
        curr_batch_lsn = OG_INVALID_ID64;
        retry_rbp_tail = OG_FALSE;
        *batch_out = NULL;

        rbp_jump_begin = cm_now();
        OG_RETURN_IFERR(dtc_rcy_try_delayed_rbp_jump(session));
        DTC_RCY_FETCH_DIAG_ACCUM(rbp_jump_us, rbp_jump_begin);

        for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
            if (g_dtc_rcy_fetch_diag_active != NULL) {
                g_dtc_rcy_fetch_diag_active->node_scan_iters++;
            }
            node_scan_begin = cm_now();
            dtc_standby_reset_recovery_stat(session);
            rcy_node = &dtc_rcy->rcy_nodes[i];
            rcy_log_point = &dtc_rcy->rcy_log_points[i];
            if (rcy_node->recover_done) {
                OG_LOG_DEBUG_INF("[DTC RCY] dtc fetch log recover done node_id = %u", rcy_node->node_id);
                if (!dtc_rcy->full_recovery && dtc_rcy->phase == PHASE_RECOVERY &&
                    dtc_rcy_verify_analysis_and_recovery_log_point(rcy_node->analysis_read_end_point,
                                                                   rcy_node->recovery_read_end_point) != OG_SUCCESS) {
                    uint32 node_id = (uint32)rcy_log_point->node_id;
                    if (dtc_rcy_rbp_tail_replay_active(session, dtc_rcy) && node_id < OG_MAX_INSTANCES &&
                        dtc_rcy->rbp_jump_taken[node_id]) {
                        DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                        continue;
                    }
                    knl_panic_log(
                        0,
                        "[DTC RCY] analysis read end point[asn(%u)-block_id(%u)-rst_id(%llu)-"
                        "lfn(%llu)-lsn(%llu)] is not "
                        "equal recovery read end point[asn(%u)-block_id(%u)-rst_id(%llu)-lfn(%llu)-lsn(%llu)]",
                        rcy_node->analysis_read_end_point.asn, rcy_node->analysis_read_end_point.block_id,
                        (uint64)rcy_node->analysis_read_end_point.rst_id,
                        (uint64)rcy_node->analysis_read_end_point.lfn,
                        rcy_node->analysis_read_end_point.lsn, rcy_node->recovery_read_end_point.asn,
                        rcy_node->recovery_read_end_point.block_id, (uint64)rcy_node->recovery_read_end_point.rst_id,
                        (uint64)rcy_node->recovery_read_end_point.lfn, rcy_node->recovery_read_end_point.lsn);
                }
                DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                continue;
            }

            // get batch from log buffer
            OG_RETURN_IFERR(dtc_update_batch(session, i));
            if (rcy_node->recover_done == OG_TRUE) {
                OG_LOG_DEBUG_INF("[DTC RCY] read node log proc node is done node_id = %u", i);
                DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                continue;
            }
            if (rcy_node->read_buf_ready[rcy_node->read_buf_read_index] == OG_FALSE) {
                OG_LOG_DEBUG_INF("[DTC RCY] read node log proc node buf not ready node_id = %u", i);
                DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                continue;
            }

            batch = dtc_rcy_get_curr_batch(dtc_rcy, i, rcy_node->read_buf_read_index);
            OG_LOG_DEBUG_INF(
                "[DTC RCY] fetch batch from instance %u point [%u-%u/%u/%llu],"
                " head lfn:%llu, batch writepos:%u, readpos:%u, space_size:%u, current lsn:%llu, start lsn:%llu",
                rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn, (uint64)batch->head.point.lfn,
                rcy_node->write_pos[rcy_node->read_buf_read_index], rcy_node->read_pos[rcy_node->read_buf_read_index],
                batch->space_size, rcy_log_point->rcy_point.lsn, rcy_log_point->rcy_point_saved.lsn);
            uint32 left_size = rcy_node->write_pos[rcy_node->read_buf_read_index] -
                               rcy_node->read_pos[rcy_node->read_buf_read_index];
            /*
             * Partial RBP prepare advances rcy_log_points[].rcy_point to rbp_rcy_point without advancing this node's
             * ring read_pos. The next buffered batch may still start in the skipped LFN range, so LFN_IS_CONTINUOUS
             * would fail and recover_done would drop the tail redo. Skip valid batches until head.lfn reaches
             * rcy_point.lfn + 1 (same invariant as single-node log_reset_point + rcy_load).
             */
            for (;;) {
                if (left_size < sizeof(log_batch_t) || batch == NULL || left_size < batch->space_size) {
                    break;
                }
                if (dtc_rcy->phase == PHASE_RECOVERY && !dtc_rcy->full_recovery &&
                    KNL_RECOVERY_WITH_RBP(session->kernel) &&
                    rcy_log_point->node_id < OG_MAX_INSTANCES && dtc_rcy->rbp_jump_taken[rcy_log_point->node_id] &&
                    dtc_rcy_validate_batch(batch) && batch->head.point.lfn < rcy_log_point->rcy_point.lfn + 1) {
                    OG_LOG_RUN_INF(
                        "[DTC RCY][RBP][partial] skip buffered batch node=%u head_lfn=%llu "
                        "expect_next_lfn=%llu (ring align after "
                        "RBP JUMP)",
                        rcy_log_point->node_id, (uint64)batch->head.point.lfn,
                        (uint64)(rcy_log_point->rcy_point.lfn + 1));
                    rcy_node->read_pos[rcy_node->read_buf_read_index] += batch->space_size;
                    rcy_node->curr_file_length += batch->space_size;
                    /* Match dtc_skip_batch: keep rcy_point file/lsn cursor with bytes skipped (DBStor reads by lsn). */
                    rcy_log_point->rcy_point.block_id += batch->space_size / rcy_node->blk_size;
                    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
                        rcy_log_point->rcy_point.lsn = batch->lsn;
                    }
                    left_size = rcy_node->write_pos[rcy_node->read_buf_read_index] -
                                rcy_node->read_pos[rcy_node->read_buf_read_index];
                    if (left_size < sizeof(log_batch_t)) {
                        break;
                    }
                    batch = dtc_rcy_get_curr_batch(dtc_rcy, i, rcy_node->read_buf_read_index);
                    if (left_size < batch->space_size) {
                        break;
                    }
                    continue;
                }
                break;
            }
            if (left_size < sizeof(log_batch_t) || batch == NULL || left_size < batch->space_size) {
                retry_rbp_tail = (bool32)(retry_rbp_tail || (dtc_rcy_rbp_tail_replay_active(session, dtc_rcy) &&
                    rcy_log_point->node_id < OG_MAX_INSTANCES && dtc_rcy->rbp_jump_taken[rcy_log_point->node_id] &&
                    !rcy_node->recover_done &&
                    LOG_LFN_LT(rcy_node->recovery_read_end_point, rcy_node->analysis_read_end_point)));
                OG_LOG_DEBUG_INF("[DTC RCY] recover fetch batch, find max lsn and move point left_size "
                                 "< sizeof(log_batch_t) || left_size < tmp_batch->space_size");
                dtc_rcy_release_read_buf_if_exhausted(i, "rbp skip drained read buffer");
                DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                continue;
            }
            validate_begin = cm_now();
            if (!dtc_rcy_validate_batch(batch)) {
                DTC_RCY_FETCH_DIAG_ACCUM(validate_us, validate_begin);
                if (g_dtc_rcy_fetch_diag_active != NULL) {
                    g_dtc_rcy_fetch_diag_active->validate_calls++;
                }
                if (!(DB_IS_MAXFIX(session) && cm_dbs_is_enable_dbs())) {
                    dtc_rcy_rbp_log_root_cause(session, rcy_log_point->node_id, "fetch", "INVALID_BATCH_AT_CURSOR",
                        &rcy_log_point->rcy_point, batch, NULL, 0, rcy_log_point->rcy_point.block_id);
                    // Batch is invalid
                    if (dtc_rcy->phase == PHASE_RECOVERY && !dtc_rcy->full_recovery &&
                        rcy_log_point->node_id < OG_MAX_INSTANCES &&
                        dtc_rcy->rbp_jump_taken[rcy_log_point->node_id]) {
                        dtc_rcy->rbp_tail_invalid_cursor_count++;
                    }
                    rcy_node->recover_done = OG_TRUE;
                    OG_LOG_RUN_INF(
                        "[DTC RCY] Invalid batch from instance %u, recovery done with point [%u-%u/%u/%llu],"
                        " head lfn:%llu, batch writepos:%u, readpos:%u, space_size:%u, current lsn:%llu, "
                        "start lsn:%llu",
                        rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                        rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn,
                        (uint64)batch->head.point.lfn, rcy_node->write_pos[rcy_node->read_buf_read_index],
                        rcy_node->read_pos[rcy_node->read_buf_read_index], batch->space_size,
                        rcy_log_point->rcy_point.lsn,
                        rcy_log_point->rcy_point_saved.lsn);
                    dtc_rcy_release_read_buf(i, "invalid batch recovery done");
                    DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                    continue;
                }
            } else {
                DTC_RCY_FETCH_DIAG_ACCUM(validate_us, validate_begin);
                if (g_dtc_rcy_fetch_diag_active != NULL) {
                    g_dtc_rcy_fetch_diag_active->validate_calls++;
                }
            }

            if (!LFN_IS_CONTINUOUS(batch->head.point.lfn, rcy_log_point->rcy_point.lfn)) {
                // batch is not continuous
                if (DB_IS_MAXFIX(session)) {
                    OG_LOG_RUN_WAR("[DTC RCY] damage log batch skipped,not continuous batch from instance %u, "
                                   "recovery with point [%u-%u/%u/%llu/%llu],current point [%u-%u/%u/%llu/%llu]",
                                   rcy_log_point->node_id, batch->head.point.rst_id, batch->head.point.asn,
                                   batch->head.point.block_id, (uint64)batch->head.point.lfn, batch->head.point.lsn,
                                   rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                                   rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn,
                                   rcy_log_point->rcy_point.lsn);
                } else {
                    OG_LOG_RUN_INF("[DTC RCY] not continuous batch from instance %u, "
                                   "recovery done with point [%u-%u/%u/%llu/%llu],current point [%u-%u/%u/%llu/%llu]",
                                   rcy_log_point->node_id, batch->head.point.rst_id, batch->head.point.asn,
                                   batch->head.point.block_id, (uint64)batch->head.point.lfn, batch->head.point.lsn,
                                   rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                                   rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn,
                                   rcy_log_point->rcy_point.lsn);
                    CM_ABORT_REASONABLE(!cm_dbs_is_enable_dbs() || session->kernel->db.recover_for_restore,
                                        "[DTC RCY] ABORT INFO: dbstor batch not continuous");
                    rcy_node->recover_done = OG_TRUE;
                    dtc_rcy_release_read_buf(i, "not continuous recovery done");
                    DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                    continue;
                }
            }

            checksum_begin = cm_now();
            if (rcy_verify_checksum(session, batch) != OG_SUCCESS) {
                DTC_RCY_FETCH_DIAG_ACCUM(checksum_us, checksum_begin);
                if (g_dtc_rcy_fetch_diag_active != NULL) {
                    g_dtc_rcy_fetch_diag_active->checksum_calls++;
                }
                OG_LOG_RUN_ERR("[DTC RCY] failed to verify log batch checksum of instance %u with rcy point"
                               " [%u-%u/%u%llu], betch_lsn=%llu",
                               rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                               rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn, batch->lsn);
                if (DB_IS_MAXFIX(session)) {
                    OG_RETURN_IFERR(dtc_skip_damage_batch(session, &batch, i));
                    if (rcy_node->recover_done == OG_TRUE) {
                        DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                        continue;
                    }
                } else {
                    DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                    return OG_ERROR;
                }
            } else {
                DTC_RCY_FETCH_DIAG_ACCUM(checksum_us, checksum_begin);
                if (g_dtc_rcy_fetch_diag_active != NULL) {
                    g_dtc_rcy_fetch_diag_active->checksum_calls++;
                }
            }
            if (dtc_log_need_reload(session, i, batch_loaded)) {
                DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
                break;
            }

            if (batch->lsn < curr_batch_lsn) {
                *curr_node_idx = (uint8)i;
                curr_node = rcy_node->node_id;
                curr_batch_lsn = batch->lsn;
                batch_loaded = OG_TRUE;
                OG_LOG_DEBUG_INF(
                    "[DTC RCY] finish fetch batch from instance %u, recovery point [%u-%u/%u/%llu],"
                    " head lfn:%llu, batch writepos:%u, readpos:%u, space_size:%u, current lsn:%llu, start lsn:%llu",
                    rcy_log_point->node_id, rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                    rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn,
                    (uint64)batch->head.point.lfn,
                    rcy_node->write_pos[rcy_node->read_buf_read_index],
                    rcy_node->read_pos[rcy_node->read_buf_read_index],
                    batch->space_size, rcy_log_point->rcy_point.lsn, rcy_log_point->rcy_point_saved.lsn);
            }
            DTC_RCY_FETCH_DIAG_ACCUM(node_scan_us, node_scan_begin);
        }

        if (!batch_loaded && retry_rbp_tail) {
            retry_fetch = OG_TRUE;
        }
    }

    if (batch_loaded) {
        commit_begin = cm_now();
        rcy_node = &dtc_rcy->rcy_nodes[*curr_node_idx];
        *batch_out = dtc_rcy_get_curr_batch(dtc_rcy, *curr_node_idx, rcy_node->read_buf_read_index);
        dtc_print_batch(*batch_out, curr_node);
        dtc_rcy->curr_node_idx = *curr_node_idx;
        dtc_rcy->curr_node = curr_node;
        dtc_rcy->curr_batch_lsn = curr_batch_lsn;
        rcy_node = &dtc_rcy->rcy_nodes[*curr_node_idx];
        rcy_log_point = &dtc_rcy->rcy_log_points[*curr_node_idx];

        // move rcy point to log point of read batch
        rcy_log_point->lsn = curr_batch_lsn;
        rcy_log_point->rcy_point.lfn = (*batch_out)->head.point.lfn;
        rcy_log_point->rcy_point.block_id += (*batch_out)->space_size / rcy_node->blk_size;

        rcy_node->read_pos[rcy_node->read_buf_read_index] += (*batch_out)->space_size;
        rcy_node->curr_file_length += (*batch_out)->space_size;
        if (cm_dbs_is_enable_dbs() == OG_TRUE) {
            rcy_log_point->rcy_point.lsn = curr_batch_lsn;
        }

        OG_LOG_DEBUG_INF("[DTC RCY] fetch batch lfn=%llu lsn=%llu", (uint64)rcy_log_point->rcy_point.lfn,
                         rcy_log_point->rcy_point.lsn);
        if ((*batch_out)->head.point.lfn >= rcy_node->pitr_lfn && rcy_node->ddl_lsn_pitr == OG_INVALID_ID64) {
            rcy_node->ddl_lsn_pitr = dtc_rcy_get_ddl_pitr_lsn(session, curr_batch_lsn);
            OG_LOG_RUN_INF("[DTC RCY] batch lfn %llu, pitr_lfn %llu, rcy ddl lsn pitr[core %llu/curr %llu], node id %u",
                           (uint64)(*batch_out)->head.point.lfn, rcy_node->pitr_lfn,
                           session->kernel->db.ctrl.core.ddl_pitr_lsn, rcy_node->ddl_lsn_pitr, *curr_node_idx);
        }
        if (dtc_rcy->phase == PHASE_ANALYSIS) {
            rcy_node->analysis_read_end_point = (*batch_out)->head.point;
            lfn_map_begin = cm_now();
            if (dtc_rcy_rbp_record_lfn_point(session, rcy_node->node_id, *batch_out,
                                             &rcy_log_point->rcy_point) != OG_SUCCESS) {
                DTC_RCY_FETCH_DIAG_ACCUM(lfn_map_us, lfn_map_begin);
                DTC_RCY_FETCH_DIAG_ACCUM(commit_us, commit_begin);
                return OG_ERROR;
            }
            DTC_RCY_FETCH_DIAG_ACCUM(lfn_map_us, lfn_map_begin);
        } else if (dtc_rcy->phase == PHASE_RECOVERY) {
            rcy_node->recovery_read_end_point = (*batch_out)->head.point;
        }
        OG_LOG_DEBUG_INF("[DTC RCY] Move log point to [%u-%u/%u/%llu] with read pos %u write pos %u for instance %u,"
                         " curr_batch_lsn=%llu",
                         rcy_log_point->rcy_point.rst_id, rcy_log_point->rcy_point.asn,
                         rcy_log_point->rcy_point.block_id, (uint64)rcy_log_point->rcy_point.lfn,
                         rcy_node->read_pos[rcy_node->read_buf_read_index],
                         rcy_node->write_pos[rcy_node->read_buf_read_index], rcy_node->node_id, curr_batch_lsn);
        DTC_RCY_FETCH_DIAG_ACCUM(commit_us, commit_begin);
        if (g_dtc_rcy_fetch_diag_active != NULL) {
            g_dtc_rcy_fetch_diag_active->fetch_ok++;
        }
    }

    return OG_SUCCESS;
}

static bool32 dtc_rcy_rbp_tail_replay_active(knl_session_t *session, dtc_rcy_context_t *dtc_rcy)
{
    return (bool32)(dtc_rcy != NULL && !dtc_rcy->full_recovery && dtc_rcy->phase == PHASE_RECOVERY &&
                    KNL_RECOVERY_WITH_RBP(session->kernel) && KNL_RBP_ENABLE(session->kernel) &&
                    KNL_RBP_FOR_RECOVERY(session->kernel) && !session->kernel->db.recover_for_restore);
}

static status_t dtc_rcy_rbp_check_tail_replay_complete(knl_session_t *session, const char *stage)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    if (!dtc_rcy_rbp_tail_replay_active(session, dtc_rcy)) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        dtc_rcy_node_t *node = &dtc_rcy->rcy_nodes[i];

        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_jump_taken[node_id]) {
            continue;
        }
        if (dtc_rcy_verify_analysis_and_recovery_log_point(node->analysis_read_end_point,
                                                           node->recovery_read_end_point) == OG_SUCCESS) {
            continue;
        }

        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] tail replay incomplete before %s: node=%u "
                       "analysis=[%u-%u/%u/%llu/%llu] recovery=[%u-%u/%u/%llu/%llu] "
                       "skip_lfn=%llu rbp_rcy_lfn=%llu recover_done=%u",
                       (stage == NULL) ? "finish" : stage, node_id,
                       node->analysis_read_end_point.rst_id, node->analysis_read_end_point.asn,
                       node->analysis_read_end_point.block_id, (uint64)node->analysis_read_end_point.lfn,
                       node->analysis_read_end_point.lsn, node->recovery_read_end_point.rst_id,
                       node->recovery_read_end_point.asn, node->recovery_read_end_point.block_id,
                       (uint64)node->recovery_read_end_point.lfn, node->recovery_read_end_point.lsn,
                       (uint64)dtc_rcy->rbp_skip_points[node_id].lfn,
                       (uint64)dtc_rcy->rbp_rcy_points[node_id].lfn, (uint32)node->recover_done);
        rbp_knl_mark_dtc_fallback(session, node_id, RBP_READ_RESULT_ERROR,
                                  RBP_DTC_FALLBACK_TAIL_INCOMPLETE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static uint64 dtc_rcy_get_ddl_lsn_pitr(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = NULL;
    rcy_node = &dtc_rcy->rcy_nodes[dtc_rcy->curr_node_idx];
    return rcy_node->ddl_lsn_pitr;
}

static void dtc_convert_scn_to_time(knl_session_t *session, uint64 batch_scn, char *time_str)
{
    timeval_t time_val = { 0 };
    KNL_SCN_TO_TIME(batch_scn, &time_val, DB_INIT_TIME(session));
    time_t scn_time = cm_date2time(cm_timeval2date(time_val));
    text_t fmt_text = { 0 };
    cm_str2text("YYYY-MM-DD HH24:MI:SS", &fmt_text);
    text_t time_text = { 0 };
    time_text.str = time_str;
    time_text.len = 0;
    cm_time2text(scn_time, &fmt_text, &time_text, OG_MAX_TIME_STRLEN);
    return;
}

static void dtc_rcy_pcn_diag_finish_rbp_prepare(knl_session_t *session, uint32 path)
{
    dtc_rcy_context_t *c = DTC_RCY_CONTEXT;
    c->pcn_diag_rbp_prepare = path;
    c->pcn_diag_redo_end_lfn_snapshot = session->kernel->redo_ctx.redo_end_point.lfn;
    c->pcn_diag_rbp_rcy_lfn_snapshot = session->kernel->redo_ctx.rbp_rcy_point.lfn;
    c->pcn_diag_rcy_with_rbp_after_prepare = (uint8)(KNL_RECOVERY_WITH_RBP(session->kernel) ? 1 : 0);
}

void dtc_rcy_log_pcn_mismatch_diag(knl_session_t *session, const char *stage, uint32 log_pcn, uint32 page_pcn,
    log_type_t log_type)
{
    log_context_t *ogx = &session->kernel->redo_ctx;
    const char *ap_str = "unset";
    const char *gp_str = "unset";

    if (!DB_IS_CLUSTER(session)) {
        OG_LOG_RUN_ERR("[PCN-DIAG] stage=%s log_pcn=%u page_pcn=%u log_type=%u curr_lsn=%llu kernel_lfn=%llu "
                       "redo_end_lfn=%llu (single-instance / non-DTC; no dtc_rcy path snapshot)",
                       stage, log_pcn, page_pcn, (uint32)log_type, (uint64)session->curr_lsn,
                       (uint64)ogx->lfn, (uint64)ogx->redo_end_point.lfn);
        return;
    }

    dtc_rcy_context_t *c = DTC_RCY_CONTEXT;
    if (c->pcn_diag_analyze_path == DTC_PCND_ANALYZE_SERIAL_BATCHES) {
        ap_str = "serial_batches";
    } else if (c->pcn_diag_analyze_path == DTC_PCND_ANALYZE_PARAL) {
        ap_str = "paral_analyze";
    }
    if (c->pcn_diag_rbp_prepare == DTC_PCND_RBP_PREP_SKIP_NO_RBP) {
        gp_str = "skip_no_rbp";
    } else if (c->pcn_diag_rbp_prepare == DTC_PCND_RBP_PREP_PARTIAL_UNAVAILABLE) {
        gp_str = "partial_unavailable";
    } else if (c->pcn_diag_rbp_prepare == DTC_PCND_RBP_PREP_PARTIAL_CHECKED) {
        gp_str = "partial_checked";
    }
    OG_LOG_RUN_ERR(
        "[PCN-DIAG] stage=%s log_pcn=%u page_pcn=%u log_type=%u curr_lsn=%llu | "
        "in_progress=%u full_recovery=%u paral_rcy=%u recovery_status=%u phase=%u node_count=%u curr_node=%u "
        "curr_batch_lsn=%llu | analyze_path=%u(%s) rbp_prepare=%u(%s) "
        "rcy_with_rbp_now=%u rcy_with_rbp@prepare=%u rbp_unsafe=%u | snap redo_end_lfn=%llu rbp_rcy_lfn=%llu "
        "kernel_lfn=%llu analysis_lfn=%llu",
        stage, log_pcn, page_pcn, (uint32)log_type, (uint64)session->curr_lsn, (uint32)c->in_progress,
        (uint32)c->full_recovery, (uint32)c->paral_rcy, (uint32)c->recovery_status, (uint32)c->phase, c->node_count,
        (uint32)c->curr_node, (uint64)c->curr_batch_lsn, c->pcn_diag_analyze_path, ap_str,
        c->pcn_diag_rbp_prepare, gp_str,
        (uint32)KNL_RECOVERY_WITH_RBP(session->kernel), (uint32)c->pcn_diag_rcy_with_rbp_after_prepare,
        (uint32)ogx->rbp_aly_result.rbp_unsafe, (uint64)c->pcn_diag_redo_end_lfn_snapshot,
        (uint64)c->pcn_diag_rbp_rcy_lfn_snapshot, (uint64)ogx->lfn, (uint64)ogx->analysis_lfn);
}

status_t dtc_rcy_process_batch(knl_session_t *session, log_batch_t *batch)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_cursor_t cursor;
    log_group_t *group = NULL;
    log_context_t *ogx = &session->kernel->redo_ctx;

    rcy_init_log_cursor(&cursor, batch);
    group = log_fetch_group(ogx, &cursor);
    if (group == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] the group is NULL.");
        return OG_ERROR;
    }
    uint64 batch_start_lsn = group->lsn;
    while (group != NULL) {
        if (dtc_rcy->phase == PHASE_RECOVERY) {
            if (dtc_rcy_set_pitr_end_replay(session->kernel->db.recover_for_restore, group->lsn)) {
                OG_LOG_RUN_INF("[DTC RCY] pcn is invalide, lsn=%llu, rmid=%u, batch_start_lsn=%llu", group->lsn,
                               group->rmid, batch_start_lsn);
                break;
            }
            session->ddl_lsn_pitr = dtc_rcy_get_ddl_lsn_pitr();
            if (rcy_replay_group(session, ogx, group) != OG_SUCCESS) {
                return OG_ERROR;
            }
            OG_LOG_DEBUG_INF("[DTC RCY] before redo replay log group, lsn=%llu, rmid=%u, session->kernel->lsn=%llu",
                             group->lsn, group->rmid, session->kernel->lsn);
            // set kernel lsn after replaying one log group
            // DB_SET_LSN(session->kernel->lsn, group->lsn);
            dtc_update_lsn(session, group->lsn);
            OG_LOG_DEBUG_INF("[DTC RCY] after redo replay log group, lsn=%llu, rmid=%u, session->kernel->lsn=%llu",
                             group->lsn, group->rmid, session->kernel->lsn);
        } else {
            if (dtc_rcy_analyze_group(session, group) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to analyze redo log group, lsn %llu, rmid=%u", group->lsn,
                               group->rmid);
                return OG_ERROR;
            }
            if (dtc_rcy_check_is_end_restore_recovery()) {
                OG_LOG_RUN_INF("[DTC RCY] pcn is invalide, lsn=%llu, rmid=%u, batch_start_lsn=%llu, batch scn=%llu",
                               group->lsn, group->rmid, batch_start_lsn, batch->scn);
                dtc_rcy->end_lsn_restore_recovery = batch_start_lsn;
                uint64 pitr_scn = session->kernel->rcy_ctx.max_scn;
                if (pitr_scn != OG_INVALID_ID64 && batch->scn < pitr_scn) {
                    char time_str[OG_MAX_TIME_STRLEN] = { 0 };
                    dtc_convert_scn_to_time(session, batch->scn, time_str);
                    OG_LOG_RUN_WAR("[DTC RCY] the end replay batch scn %llu is smaller than pitr scn %llu, "
                                   "replay batch end time: %s",
                                   batch->scn, pitr_scn, time_str);
                }
                break;
            }
        }

        group = log_fetch_group(ogx, &cursor);
    }

    OG_LOG_DEBUG_INF("[DTC RCY] Log batch lfn=%llu, lsn=%llu, point [%u-%u/%u] has been processed for instance=%u",
                     (uint64)batch->head.point.lfn, batch->lsn, batch->head.point.rst_id, batch->head.point.asn,
                     batch->head.point.block_id, dtc_rcy->curr_node);
    return OG_SUCCESS;
}

static status_t dtc_recover_check(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = NULL;
    dtc_node_ctrl_t *ctrl = NULL;
    status_t status = OG_SUCCESS;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_log_point = &dtc_rcy->rcy_log_points[i];
        ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);

        OG_LOG_RUN_INF("[DTC RCY] node:%u, recovery real end with file:%u,point:%u,lfn:%llu", rcy_log_point->node_id,
                       rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                       (uint64)rcy_log_point->rcy_point.lfn);
        OG_LOG_RUN_INF("[DTC RCY] node:%u, current lfn %llu, rcy point lfn %llu, lrp point lfn %llu",
                       rcy_log_point->node_id, (uint64)rcy_log_point->rcy_point.lfn, (uint64)ctrl->rcy_point.lfn,
                       (uint64)(uint64)ctrl->lrp_point.lfn);

        if (rcy_log_point->rcy_point.lfn >= ctrl->lrp_point.lfn) {
            continue;
        }

        OG_LOG_RUN_ERR("[DTC RCY] failed to check dtc recovery rcy point");
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_RCV_END_POINT, rcy_log_point->rcy_point.asn, rcy_log_point->rcy_point.block_id,
                       ctrl->lrp_point.asn, ctrl->lrp_point.block_id);
        status = OG_ERROR;
    }
    return status;
}

static status_t dtc_rcy_update_node_info(knl_session_t *session, reform_rcy_node_t *rcy_log_point)
{
    dtc_node_ctrl_t *ctrl = NULL;

    ctrl = dtc_get_ctrl(session, rcy_log_point->node_id);
    knl_panic(DB_IS_MAXFIX(session) || log_cmp_point(&ctrl->rcy_point, &rcy_log_point->rcy_point) <= 0);
    knl_panic(DB_IS_MAXFIX(session) || ctrl->rcy_point.lfn <= rcy_log_point->rcy_point.lfn);
    ctrl->rcy_point = rcy_log_point->rcy_point;
    ctrl->lrp_point = rcy_log_point->rcy_point;
    ctrl->consistent_lfn = rcy_log_point->rcy_point.lfn;
    ctrl->lsn = rcy_log_point->lsn;
    ctrl->lfn = rcy_log_point->rcy_point.lfn;

    OG_LOG_RUN_INF("[DTC RCY] Update ctrl rcy point to [%u-%u/%u/%llu/%llu] for instance %u", ctrl->rcy_point.rst_id,
                   ctrl->rcy_point.asn, ctrl->rcy_point.block_id, (uint64)ctrl->rcy_point.lfn, ctrl->rcy_point.lsn,
                   rcy_log_point->node_id);

    if (dtc_save_ctrl(session, rcy_log_point->node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t dtc_rcy_update_ckpt_log_point(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *rcy_log_point = NULL;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_log_point = &dtc_rcy->rcy_log_points[i];
        if (dtc_rcy_update_node_info(session, rcy_log_point) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to update node info");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static void dtc_rcy_update_ckpt_prcy_info(knl_session_t *session)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;

    OG_LOG_RUN_INF("[DTC RCY] save ckpt end point, prcy_trunc_point.asn=%u, prcy_trunc_point.block_id=%u"
                   "prcy_trunc_point.rst_id=%d, prcy_trunc_point.lfn=%llu",
                   g_rc_ctx->prcy_trunc_point.asn, g_rc_ctx->prcy_trunc_point.block_id,
                   g_rc_ctx->prcy_trunc_point.rst_id, (uint64)g_rc_ctx->prcy_trunc_point.lfn);

    cm_spin_lock(&ogx->queue.lock, &session->stat->spin_stat.stat_ckpt_queue);
    g_rc_ctx->prcy_trunc_point = ogx->queue.trunc_point;
    cm_spin_unlock(&ogx->queue.lock);
}

static bool32 ckpt_prcy_flush_check(knl_session_t *session)
{
    if (!DB_IS_CLUSTER(session)) {
        return OG_TRUE;
    }

    if (rc_is_master() == OG_FALSE) {
        return OG_TRUE;
    }
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;

    if (ogx->queue.first != NULL && log_cmp_point(&ogx->queue.first->trunc_point, &g_rc_ctx->prcy_trunc_point) <= 0) {
        return OG_FALSE;
    }

    OG_LOG_DEBUG_INF("[CKPT] finish checkpoint");
    return OG_TRUE;
}

#define CHECK_INTERVAL 100
status_t dtc_update_ckpt_log_point(void)
{
    // wait prcy ckpt finish
    OG_LOG_RUN_INF("[RC][partial start] start waiting prcy ckpt done, session->kernel->lsn=%llu, "
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);
    SYNC_POINT_GLOBAL_START(OGRAC_PART_RECOVERY_BEFORE_CKPT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    uint32 loop = 0;
    for (;;) {
        OG_RETVALUE_IFTRUE(rc_reform_cancled(), OG_ERROR);
        if (loop % CHECK_INTERVAL == 0) {
            ckpt_trigger(g_rc_ctx->session, OG_FALSE, CKPT_TRIGGER_INC);
            if (ckpt_prcy_flush_check(g_rc_ctx->session)) {
                break;
            }
        }
        cm_sleep(DTC_REFORM_WAIT_TIME);
        loop++;
    }
    OG_LOG_RUN_INF("[RC][partial start] finish waiting prcy ckpt done, session->kernel->lsn=%llu, "
                   "g_rc_ctx->status=%u",
                   ((knl_session_t *)g_rc_ctx->session)->kernel->lsn, g_rc_ctx->status);

    return dtc_rcy_update_ckpt_log_point(g_rc_ctx->session);
}

static void dtc_rcy_set_num_stat(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools;

    while (pool != NULL) {
        for (int64 i = 0; i < pool->hwm; i++) {
            if (pool->items[i].need_replay) {
                dtc_rcy->rcy_stat.last_rcy_set_num++;
            }
        }
        pool = pool->next;
    }
}

static void dtc_rcy_wait_paral_replay_end(knl_session_t *session, bool32 close_workers)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    rcy_wait_replay_complete(session);
    if (close_workers) {
        rcy->rcy_end = OG_TRUE;
    }
}

static bool32 dtc_rcy_pitr_replay_end(rcy_context_t *rcy, log_batch_t *batch)
{
    if (batch->scn <= rcy->max_scn) {
        return OG_FALSE;
    }
    OG_LOG_RUN_INF("[DTC RCY] until time recover done");
    return OG_TRUE;
}

static bool32 dtc_rcy_full_recovery_replay_end(rcy_context_t *rcy, log_batch_t *batch)
{
    if (batch->lsn <= rcy->max_lrp_lsn) {
        return OG_FALSE;
    }
    OG_LOG_RUN_INF("[DTC RCY] until lrp[%llu] full_recover done", batch->lsn);
    return OG_TRUE;
}

static status_t dtc_rcy_process_batches(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    if (dtc_rcy->phase == PHASE_ANALYSIS) {
        dtc_rcy->pcn_diag_analyze_path = DTC_PCND_ANALYZE_SERIAL_BATCHES;
    }
    log_batch_t *batch = NULL;
    status_t status = OG_SUCCESS;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    timeval_t elapsed_begin;
    uint64 used_time;
    uint64 fetch_log_time = 0;
    uint64 replay_log_time = 0;
    uint32 curr_node_idx = 0;

    OG_LOG_DEBUG_INF("[DTC RCY] process_batches enter: phase=%u full_recovery=%u node_count=%u "
                   "paral_rcy=%u partial_rbp_collecting=%u",
                   (uint32)dtc_rcy->phase, (uint32)dtc_rcy->full_recovery, dtc_rcy->node_count,
                   (uint32)dtc_rcy->paral_rcy, (uint32)dtc_rcy_rbp_partial_collecting(session));

    ELAPSED_BEGIN(elapsed_begin);
    if (dtc_read_all_logs(session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to load log files");
        return OG_ERROR;
    }
    ELAPSED_END(elapsed_begin, used_time);
    OG_LOG_RUN_INF("[DTC RCY] dtc_read_all_logs used %llu", used_time);

    knl_session_t *ss = NULL;
    if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&ss) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] dtc rcy proc init failed as alloc session failed");
        return OG_ERROR;
    }
    if (OG_SUCCESS != cm_create_thread(dtc_rcy_read_node_log_proc, 0, ss, &dtc_rcy->read_log_thread)) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to create thread read node log proc");
        return OG_ERROR;
    }

    ELAPSED_BEGIN(elapsed_begin);
    if (dtc_rcy_fetch_log_batch(session, &batch, &curr_node_idx) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to extract log batch");
        return OG_ERROR;
    }
    ELAPSED_END(elapsed_begin, fetch_log_time);
    if (batch == NULL) {
        OG_LOG_RUN_WAR("[DTC RCY] process_batches first fetch returned NULL: phase=%u node_count=%u",
                       (uint32)dtc_rcy->phase, dtc_rcy->node_count);
    } else {
        OG_LOG_DEBUG_INF("[DTC RCY] process_batches first batch: phase=%u node_idx=%u node_id=%u "
                       "lfn=%llu lsn=%llu partial_rbp_collecting=%u",
                       (uint32)dtc_rcy->phase, curr_node_idx, dtc_rcy->rcy_nodes[curr_node_idx].node_id,
                       (uint64)batch->head.point.lfn, batch->lsn,
                       (uint32)dtc_rcy_rbp_partial_collecting(session));
    }

    while (batch != NULL) {
        if (session->canceled) {
            OG_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = OG_ERROR;
            break;
        }

        if (session->killed) {
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            status = OG_ERROR;
            break;
        }

        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            OG_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task");
            break;
        }

        if (dtc_rcy_pitr_replay_end(rcy, batch)) {
            break;
        }

        if (dtc_rcy_full_recovery_replay_end(rcy, batch)) {
            break;
        }

        // call batch process function
        ELAPSED_BEGIN(elapsed_begin);
        if (dtc_rcy_process_batch(session, batch) != OG_SUCCESS) {
            status = OG_ERROR;
            ELAPSED_END(elapsed_begin, used_time);
            break;
        }
        ELAPSED_END(elapsed_begin, used_time);
        replay_log_time += used_time;
        // fetch next batch
        ELAPSED_BEGIN(elapsed_begin);
        if (dtc_rcy_check_is_end_restore_recovery()) {
            break;
        }
        if (dtc_rcy_fetch_log_batch(session, &batch, &curr_node_idx) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to extract log batch");
            status = OG_ERROR;
            break;
        }
        ELAPSED_END(elapsed_begin, used_time);
        fetch_log_time += used_time;
    }
    OG_LOG_DEBUG_INF("[DTC RCY] process_batches leave: phase=%u status=%u partial_rbp_collecting=%u "
                   "redo_end_lfn=%llu rbp_aly_lsn=%llu rcy_with_rbp=%u",
                   (uint32)dtc_rcy->phase, (uint32)status, (uint32)dtc_rcy_rbp_partial_collecting(session),
                   (uint64)session->kernel->redo_ctx.redo_end_point.lfn,
                   session->kernel->redo_ctx.rbp_aly_lsn,
                   (uint32)KNL_RECOVERY_WITH_RBP(session->kernel));
    if (close_read_log_proc(&dtc_rcy->read_log_thread, ss) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] close read log proc time out");
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[DTC RCY] dtc_rcy_fetch_log_batch used=%llu", fetch_log_time);
    OG_LOG_RUN_INF("[DTC RCY] dtc_rcy_process_batch used=%llu", replay_log_time);
    return status;
}

static void dtc_rcy_atomic_list_init(dtc_rcy_atomic_list *list)
{
    list->begin = 0;
    list->end = 0;
    list->writed_end = 0;
    list->lock = 0;
}

static inline int64 dtc_rcy_atomic_list_count(dtc_rcy_atomic_list *list)
{
    return (int64)(list->writed_end - list->begin);
}

#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
static const char *dtc_rcy_analyze_stage_name(uint32 stage)
{
    switch (stage) {
        case DTC_RCY_ANALYZE_STAGE_MAIN_COPY:
            return "main_copy";
        case DTC_RCY_ANALYZE_STAGE_MAIN_PUSH_USED:
            return "main_push_used";
        case DTC_RCY_ANALYZE_STAGE_MAIN_FETCH_NEXT:
            return "main_fetch_next";
        case DTC_RCY_ANALYZE_STAGE_WORKER_BATCH:
            return "worker_batch";
        case DTC_RCY_ANALYZE_STAGE_WORKER_GROUP:
            return "worker_group";
        default:
            return "idle";
    }
}
#endif

static void dtc_rcy_analyze_diag_reset(void)
{
    g_dtc_rcy_analyze_main_stage = DTC_RCY_ANALYZE_STAGE_IDLE;
    g_dtc_rcy_analyze_main_idx = OG_INVALID_ID32;
    g_dtc_rcy_analyze_main_node = OG_INVALID_ID32;
    g_dtc_rcy_analyze_main_space = 0;
    g_dtc_rcy_analyze_main_lfn = 0;
    g_dtc_rcy_analyze_main_lsn = 0;
    g_dtc_rcy_analyze_main_start = 0;

    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        g_dtc_rcy_analyze_worker_stage[i] = DTC_RCY_ANALYZE_STAGE_IDLE;
        g_dtc_rcy_analyze_worker_idx[i] = OG_INVALID_ID32;
        g_dtc_rcy_analyze_worker_node[i] = OG_INVALID_ID32;
        g_dtc_rcy_analyze_worker_space[i] = 0;
        g_dtc_rcy_analyze_worker_rmid[i] = 0;
        g_dtc_rcy_analyze_worker_lfn[i] = 0;
        g_dtc_rcy_analyze_worker_lsn[i] = 0;
        g_dtc_rcy_analyze_worker_group_lsn[i] = 0;
        g_dtc_rcy_analyze_worker_start[i] = 0;
    }
}

static void dtc_rcy_analyze_diag_set_main(uint32 stage, uint32 idx, uint32 node_id, log_batch_t *batch)
{
#if !DTC_RCY_ANALYZE_INFLIGHT_DIAG
    (void)stage;
    (void)idx;
    (void)node_id;
    (void)batch;
    return;
#else
    g_dtc_rcy_analyze_main_stage = stage;
    g_dtc_rcy_analyze_main_idx = idx;
    g_dtc_rcy_analyze_main_node = node_id;
    if (batch != NULL) {
        g_dtc_rcy_analyze_main_lfn = (uint64)batch->head.point.lfn;
        g_dtc_rcy_analyze_main_lsn = batch->lsn;
        g_dtc_rcy_analyze_main_space = batch->space_size;
    } else {
        g_dtc_rcy_analyze_main_lfn = 0;
        g_dtc_rcy_analyze_main_lsn = 0;
        g_dtc_rcy_analyze_main_space = 0;
    }
    g_dtc_rcy_analyze_main_start = cm_now();
#endif
}

static uint32 dtc_rcy_analyze_worker_slot(thread_t *thread)
{
    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        if (&g_analyze_paral_mgr.thread[i] == thread) {
            return i;
        }
    }
    return OG_INVALID_ID32;
}

static void dtc_rcy_analyze_diag_set_worker(uint32 slot, uint32 stage, uint32 idx, uint32 node_id, log_batch_t *batch,
    log_group_t *group)
{
#if !DTC_RCY_ANALYZE_INFLIGHT_DIAG
    (void)slot;
    (void)stage;
    (void)idx;
    (void)node_id;
    (void)batch;
    (void)group;
    return;
#else
    if (slot >= PARAL_ANALYZE_THREAD_NUM) {
        return;
    }

    g_dtc_rcy_analyze_worker_stage[slot] = stage;
    g_dtc_rcy_analyze_worker_idx[slot] = idx;
    g_dtc_rcy_analyze_worker_node[slot] = node_id;
    if (batch != NULL) {
        g_dtc_rcy_analyze_worker_lfn[slot] = (uint64)batch->head.point.lfn;
        g_dtc_rcy_analyze_worker_lsn[slot] = batch->lsn;
        g_dtc_rcy_analyze_worker_space[slot] = batch->space_size;
    } else {
        g_dtc_rcy_analyze_worker_lfn[slot] = 0;
        g_dtc_rcy_analyze_worker_lsn[slot] = 0;
        g_dtc_rcy_analyze_worker_space[slot] = 0;
    }
    if (group != NULL) {
        g_dtc_rcy_analyze_worker_group_lsn[slot] = group->lsn;
        g_dtc_rcy_analyze_worker_rmid[slot] = group->rmid;
    } else {
        g_dtc_rcy_analyze_worker_group_lsn[slot] = 0;
        g_dtc_rcy_analyze_worker_rmid[slot] = 0;
    }
    g_dtc_rcy_analyze_worker_start[slot] = cm_now();
#endif
}

#if DTC_RCY_ANALYZE_HOT_DIAG
static void dtc_rcy_analyze_diag_set_worker_group(uint32 slot, log_group_t *group)
{
    if (slot >= PARAL_ANALYZE_THREAD_NUM || group == NULL) {
        return;
    }
    g_dtc_rcy_analyze_worker_stage[slot] = DTC_RCY_ANALYZE_STAGE_WORKER_GROUP;
    g_dtc_rcy_analyze_worker_group_lsn[slot] = group->lsn;
    g_dtc_rcy_analyze_worker_rmid[slot] = group->rmid;
}
#endif

static void dtc_rcy_analyze_diag_clear_worker(uint32 slot)
{
#if !DTC_RCY_ANALYZE_INFLIGHT_DIAG
    (void)slot;
    return;
#else
    if (slot >= PARAL_ANALYZE_THREAD_NUM) {
        return;
    }
    g_dtc_rcy_analyze_worker_stage[slot] = DTC_RCY_ANALYZE_STAGE_IDLE;
    g_dtc_rcy_analyze_worker_idx[slot] = OG_INVALID_ID32;
    g_dtc_rcy_analyze_worker_node[slot] = OG_INVALID_ID32;
    g_dtc_rcy_analyze_worker_space[slot] = 0;
    g_dtc_rcy_analyze_worker_rmid[slot] = 0;
    g_dtc_rcy_analyze_worker_lfn[slot] = 0;
    g_dtc_rcy_analyze_worker_lsn[slot] = 0;
    g_dtc_rcy_analyze_worker_group_lsn[slot] = 0;
    g_dtc_rcy_analyze_worker_start[slot] = 0;
#endif
}

#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
static void dtc_rcy_log_analyze_inflight(void)
{
    date_t now = cm_now();
    uint32 stage = g_dtc_rcy_analyze_main_stage;
    bool32 found = OG_FALSE;
    if (stage != DTC_RCY_ANALYZE_STAGE_IDLE) {
        uint64 elapsed = (g_dtc_rcy_analyze_main_start == 0) ? 0 :
            (uint64)(now - g_dtc_rcy_analyze_main_start);
        found = OG_TRUE;
        OG_LOG_RUN_WAR("[DTC RCY][analysis diag] inflight main: stage=%s idx=%u node_id=%u lfn=%llu "
                       "lsn=%llu space=%u elapsed_us=%llu",
                       dtc_rcy_analyze_stage_name(stage), g_dtc_rcy_analyze_main_idx,
                       g_dtc_rcy_analyze_main_node, g_dtc_rcy_analyze_main_lfn,
                       g_dtc_rcy_analyze_main_lsn, g_dtc_rcy_analyze_main_space, elapsed);
    }

    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        stage = g_dtc_rcy_analyze_worker_stage[i];
        if (stage == DTC_RCY_ANALYZE_STAGE_IDLE) {
            continue;
        }
        uint64 elapsed = (g_dtc_rcy_analyze_worker_start[i] == 0) ? 0 :
            (uint64)(now - g_dtc_rcy_analyze_worker_start[i]);
        found = OG_TRUE;
        OG_LOG_RUN_WAR("[DTC RCY][analysis diag] inflight worker: slot=%u stage=%s idx=%u node_id=%u "
                       "lfn=%llu lsn=%llu space=%u group_lsn=%llu rmid=%u elapsed_us=%llu",
                       i, dtc_rcy_analyze_stage_name(stage), g_dtc_rcy_analyze_worker_idx[i],
                       g_dtc_rcy_analyze_worker_node[i], g_dtc_rcy_analyze_worker_lfn[i],
                       g_dtc_rcy_analyze_worker_lsn[i], g_dtc_rcy_analyze_worker_space[i],
                       g_dtc_rcy_analyze_worker_group_lsn[i], g_dtc_rcy_analyze_worker_rmid[i], elapsed);
    }
    if (!found) {
        OG_LOG_RUN_WAR("[DTC RCY][analysis diag] inflight none: main_stage=%u worker_stages_empty=1",
                       g_dtc_rcy_analyze_main_stage);
    }
}
#endif

static void dtc_rcy_log_read_buffer_diag(dtc_rcy_context_t *dtc_rcy, const char *reason)
{
#if !DTC_RCY_ANALYZE_INFLIGHT_DIAG
    (void)dtc_rcy;
    (void)reason;
    return;
#else
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        dtc_rcy_node_t *node = &dtc_rcy->rcy_nodes[i];
        uint32 read_idx = node->read_buf_read_index;
        uint32 write_idx = node->read_buf_write_index;

        OG_LOG_RUN_WAR("[DTC RCY][analysis diag] %s node_idx=%u node_id=%u recover_done=%u "
                       "read_idx=%u write_idx=%u ready_r=%u ready_w=%u read_size_r=%u read_size_w=%u "
                       "read_pos_r=%u write_pos_r=%u",
                       reason, i, node->node_id, (uint32)node->recover_done, read_idx, write_idx,
                       (uint32)node->read_buf_ready[read_idx], (uint32)node->read_buf_ready[write_idx],
                       node->read_size[read_idx], node->read_size[write_idx], node->read_pos[read_idx],
                       node->write_pos[read_idx]);
    }
#endif
}

static uint32 dtc_rcy_atomic_list_pop(dtc_rcy_atomic_list *list)
{
    int64 begin;
    int64 end;
    uint32 val;
    uint32 prarl_buf_list_size = g_instance->kernel.attr.dtc_rcy_paral_buf_list_size;
    cm_spin_lock(&list->lock, NULL);
    do {
        begin = list->begin;
        end = list->writed_end;
        if (begin == end) {  // list is empty
            cm_spin_unlock(&list->lock);
            return OG_INVALID_INT32;
        }
        val = list->array[begin % prarl_buf_list_size];
    } while (!cm_atomic_cas(&list->begin, begin, begin + 1));
    cm_spin_unlock(&list->lock);
    return val;
}

static bool8 dtc_rcy_atomic_list_push(dtc_rcy_atomic_list *list, uint32 val)
{
    int64 begin;
    int64 end;
    cm_spin_lock(&list->lock, NULL);
    uint32 prarl_buf_list_size = g_instance->kernel.attr.dtc_rcy_paral_buf_list_size;
    do {
        begin = list->begin;
        end = list->end;
        if (begin + prarl_buf_list_size == end) {  // list is full
            cm_spin_unlock(&list->lock);
            return OG_FALSE;
        }
    } while (!cm_atomic_cas(&list->end, end, end + 1));        // placeholder
    list->array[end % prarl_buf_list_size] = val;
    while (!cm_atomic_cas(&list->writed_end, end, end + 1)) {  // update end
        // yield
        continue;
    }
    cm_spin_unlock(&list->lock);
    return OG_TRUE;
}

static void dtc_rcy_free_list_in_analyze_paral(aligned_buf_t *list, uint32 num)
{
    for (uint32 i = 0; i < num; i++) {
        cm_aligned_free(&list[i]);
    }
}

static void dtc_rcy_analyze_paral_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_cursor_t cursor;
    log_group_t *group = NULL;
    log_batch_t *batch = NULL;
    status_t ret;
    uint32 idx;
    log_context_t *ogx = &session->kernel->redo_ctx;
    uint64 processed_batches = 0;
    uint64 idle_loops = 0;
    uint32 worker_slot = dtc_rcy_analyze_worker_slot(thread);
    date_t stage_begin;
    uint64 stage_elapsed;
#if DTC_RCY_ANALYZE_HOT_DIAG
    dtc_rcy_analysis_worker_stat_t worker_stat = { 0 };
    date_t last_group_diag_time = 0;
#endif
    dtc_rcy_inc_rcy_set_ref_num();

    while (!g_analyze_paral_mgr.killed_flag) {
        idx = dtc_rcy_atomic_list_pop(&g_analyze_paral_mgr.used_list);
        if (idx == OG_INVALID_INT32) {
            if (g_analyze_paral_mgr.read_log_end_flag) {
                break;
            }
            idle_loops++;
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
            if ((idle_loops % DTC_RCY_ANALYZE_WORKER_IDLE_INTERVAL) == 1) {
                OG_LOG_RUN_WAR("[DTC RCY][analysis diag] analyze worker idle: session_id=%u idle_loops=%llu "
                               "used_count=%lld free_count=%lld running=%d read_end=%u killed=%u",
                               session->id, idle_loops,
                               dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list),
                               dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                               cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num),
                               (uint32)g_analyze_paral_mgr.read_log_end_flag,
                               (uint32)g_analyze_paral_mgr.killed_flag);
            }
#endif
            cm_sleep(1);
            continue;
        }
        idle_loops = 0;
        batch = (log_batch_t *)g_analyze_paral_mgr.buf_list[idx].aligned_buf;
        uint32 batch_node_id = g_analyze_paral_mgr.node_ids[idx];
        uint64 batch_lfn = (uint64)g_analyze_paral_mgr.batch_points[idx].lfn;
        dtc_rcy_analyze_diag_set_worker(worker_slot, DTC_RCY_ANALYZE_STAGE_WORKER_BATCH, idx, batch_node_id,
                                        batch, NULL);
        stage_begin = cm_now();
        OG_LOG_DEBUG_INF("[DTC RCY] log batch with lsn=%llu, lfn=%llu, rst_id=%u, asn=%u, block_id=%u, idx=%u, start "
                         "process for instance=%u",
                         batch->lsn, (uint64)batch->head.point.lfn, batch->head.point.rst_id, batch->head.point.asn,
                         batch->head.point.block_id, idx, batch_node_id);
        rcy_init_log_cursor(&cursor, batch);
        group = log_fetch_group(ogx, &cursor);
        while (group != NULL) {
#if DTC_RCY_ANALYZE_HOT_DIAG
            dtc_rcy_analysis_group_diag_t group_diag = { 0 };
            date_t group_begin = cm_now();
            uint64 group_elapsed;
            date_t diag_now;
            bool32 group_slow;

            dtc_rcy_analyze_diag_set_worker_group(worker_slot, group);
            if (dtc_rcy_analyze_group_ex_diag(session, group, batch_node_id, batch_lfn, worker_slot, &group_diag,
                NULL, OG_FALSE) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to analyze redo log group, lsn=%llu, rmid=%u", group->lsn,
                               group->rmid);
                dtc_rcy->failed = OG_TRUE;
                break;
            }
            group_elapsed = (uint64)(cm_now() - group_begin);
            worker_stat.groups++;
            worker_stat.entries += group_diag.entries;
            worker_stat.record_calls += group_diag.record_calls;
            worker_stat.record_new += group_diag.record_new;
            worker_stat.record_hit += group_diag.record_hit;
            worker_stat.partial_calls += group_diag.partial_calls;
            worker_stat.record_us += group_diag.record_us;
            worker_stat.partial_us += group_diag.partial_us;
            worker_stat.lock_us += group_diag.rcy_bucket_lock_us + group_diag.partial_bucket_lock_us +
                group_diag.partial_global_lock_us;
            worker_stat.alloc_us += group_diag.alloc_itempool_us + group_diag.partial_alloc_pool_us;
            worker_stat.drc_us += group_diag.drc_master_us;
            worker_stat.group_us += group_elapsed;
            worker_stat.max_group_us = MAX(worker_stat.max_group_us, group_elapsed);
            group_slow = (bool32)(group_elapsed >= DTC_RCY_ANALYZE_GROUP_SLOW_US ||
                group_diag.record_us >= DTC_RCY_ANALYZE_RECORD_SLOW_US ||
                group_diag.partial_us >= DTC_RCY_ANALYZE_PARTIAL_SLOW_US);
            if (group_slow) {
                worker_stat.slow_groups++;
                diag_now = cm_now();
                if (last_group_diag_time == 0 ||
                    (uint64)(diag_now - last_group_diag_time) >= DTC_RCY_ANALYZE_GROUP_DIAG_INTERVAL_US) {
                    OG_LOG_RUN_WAR("[DTC RCY][analysis group diag] slot=%u idx=%u node_id=%u lfn=%llu "
                                   "group_lsn=%llu rmid=%u elapsed_us=%llu entries=%llu enter=%llu leave=%llu "
                                   "changed_leave=%llu record_calls=%llu record_new=%llu record_hit=%llu "
                                   "record_us=%llu partial_calls=%llu partial_us=%llu lock_us=%llu alloc_us=%llu "
                                   "drc_us=%llu",
                                   worker_slot, idx, batch_node_id, (uint64)batch->head.point.lfn,
                                   group->lsn, group->rmid, group_elapsed, group_diag.entries,
                                   group_diag.enter_entries, group_diag.leave_entries,
                                   group_diag.changed_leave_entries, group_diag.record_calls,
                                   group_diag.record_new, group_diag.record_hit, group_diag.record_us,
                                   group_diag.partial_calls, group_diag.partial_us,
                                   group_diag.rcy_bucket_lock_us + group_diag.partial_bucket_lock_us +
                                       group_diag.partial_global_lock_us,
                                   group_diag.alloc_itempool_us + group_diag.partial_alloc_pool_us,
                                   group_diag.drc_master_us);
                    last_group_diag_time = diag_now;
                }
            }
#else
            if (dtc_rcy_analyze_group_ex_diag(session, group, batch_node_id, batch_lfn, worker_slot, NULL,
                NULL, OG_FALSE) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] failed to analyze redo log group, lsn=%llu, rmid=%u", group->lsn,
                               group->rmid);
                dtc_rcy->failed = OG_TRUE;
                break;
            }
#endif
            group = log_fetch_group(ogx, &cursor);
        }
        stage_elapsed = (uint64)(cm_now() - stage_begin);
        if (stage_elapsed > DTC_RCY_ANALYZE_SLOW_US) {
            OG_LOG_RUN_WAR("[DTC RCY][analysis diag] worker batch slow: slot=%u elapsed_us=%llu idx=%u "
                           "node_id=%u lfn=%llu lsn=%llu space=%u",
                           worker_slot, stage_elapsed, idx, batch_node_id,
                           (uint64)batch->head.point.lfn, batch->lsn, batch->space_size);
        }

        ret = dtc_rcy_atomic_list_push(&g_analyze_paral_mgr.free_list, idx);
        dtc_rcy_analyze_diag_clear_worker(worker_slot);
        OG_LOG_DEBUG_INF("[DTC RCY] log batch with lsn=%llu, lfn=%llu, rst_id=%u, asn=%u, block_id=%u, idx=%u has been"
                         " processed for instance=%u",
                         batch->lsn, (uint64)batch->head.point.lfn, batch->head.point.rst_id, batch->head.point.asn,
                         batch->head.point.block_id, idx, batch_node_id);
        knl_panic_log(ret == OG_TRUE, "[DTC RCY] paral redo log analyze, push used buffer=%u into free list error",
                      idx);
        processed_batches++;
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
        if (processed_batches == 1 || (processed_batches % DTC_RCY_ANALYZE_PROGRESS_INTERVAL) == 0) {
            OG_LOG_RUN_INF("[DTC RCY][analysis diag] analyze worker progress: session_id=%u processed=%llu "
                           "last_lfn=%llu last_lsn=%llu used_count=%lld free_count=%lld running=%d",
                           session->id, processed_batches, (uint64)batch->head.point.lfn, batch->lsn,
                           dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list),
                           dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                           cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num));
        }
#endif
    }
    dtc_rcy_analyze_diag_clear_worker(worker_slot);
    cm_atomic32_dec(&g_analyze_paral_mgr.running_thread_num);
    dtc_rcy_dec_rcy_set_ref_num();
#if DTC_RCY_ANALYZE_HOT_DIAG
    OG_LOG_DEBUG_INF("[DTC RCY][analysis worker summary] hot_diag=1 slot=%u processed_batches=%llu groups=%llu "
                     "entries=%llu record_calls=%llu record_new=%llu record_hit=%llu partial_calls=%llu "
                     "slow_groups=%llu max_group_us=%llu group_us=%llu record_us=%llu partial_us=%llu "
                     "alloc_us=%llu drc_us=%llu lock_us=%llu idle_loops=%llu",
                     worker_slot, processed_batches, worker_stat.groups, worker_stat.entries,
                     worker_stat.record_calls, worker_stat.record_new, worker_stat.record_hit,
                     worker_stat.partial_calls, worker_stat.slow_groups, worker_stat.max_group_us,
                     worker_stat.group_us, worker_stat.record_us, worker_stat.partial_us,
                     worker_stat.alloc_us, worker_stat.drc_us, worker_stat.lock_us, idle_loops);
#endif
    OG_LOG_DEBUG_INF("[DTC RCY] dtc_rcy_analyze_paral_proc finish, rcy_set ref num=%u processed=%llu idle_loops=%llu "
                     "read_end=%u killed=%u",
                     dtc_rcy->rcy_set_ref_num, processed_batches, idle_loops,
                     (uint32)g_analyze_paral_mgr.read_log_end_flag, (uint32)g_analyze_paral_mgr.killed_flag);
}

static bool32 is_min_batch_lsn(uint64 batch_lsn, knl_scn_t *batch_scn, bool32 *has_batch)
{
    log_batch_t *batch = NULL;
    uint32 prarl_buf_list_size = g_instance->kernel.attr.dtc_rcy_paral_buf_list_size;
    for (uint32 idx = 0; idx < prarl_buf_list_size; idx++) {
        *batch_scn = MAX(*batch_scn, g_replay_paral_mgr.batch_scn[idx]);
        if (g_replay_paral_mgr.group_num[idx] == 0) {
            continue;
        }
        *has_batch = OG_TRUE;
        batch = (log_batch_t *)g_replay_paral_mgr.buf_list[idx].aligned_buf;
        if (batch_lsn > batch->lsn) {
            OG_LOG_DEBUG_INF("batch_lsn %llu is not min, batch->lsn %llu", batch_lsn, batch->lsn);
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

void dtc_update_standby_cluster_scn(knl_session_t *session, uint32 idx)
{
    if (DB_IS_PRIMARY(&session->kernel->db) || OGRAC_PART_RECOVERY(session)) {
        return;
    }
    knl_scn_t batch_scn = 0;
    bool32 has_batch = OG_FALSE;
    lrpl_context_t *lrpl_ctx = &session->kernel->lrpl_ctx;
    log_batch_t *batch = (log_batch_t *)g_replay_paral_mgr.buf_list[idx].aligned_buf;
    uint32 node_id = g_replay_paral_mgr.node_id[idx];
    lrpl_ctx->dtc_curr_point[node_id] = batch->lsn > lrpl_ctx->dtc_curr_point[node_id].lsn
                                            ? batch->head.point
                                            : lrpl_ctx->dtc_curr_point[node_id];

    date_t rcy_time = cm_now() - g_replay_paral_mgr.batch_rpl_start_time[idx];
    if (rcy_time != 0) {
        lrpl_ctx->lrpl_speed = (double)(batch->space_size) * MICROSECS_PER_SECOND / SIZE_M(1) / ((double)rcy_time);
    }
    if (!is_min_batch_lsn(batch->lsn, &batch_scn, &has_batch)) {
        return;
    }
    batch_scn = has_batch ? g_replay_paral_mgr.batch_scn[idx] : batch_scn;
    OG_LOG_DEBUG_INF("update scn, old scn %llu, new scn %llu", session->kernel->scn, batch_scn);
    if (batch_scn > session->kernel->scn) {
        KNL_SET_SCN(&session->kernel->scn, batch_scn);
        if (session->kernel->attr.enable_boc) {
            tx_scn_broadcast(session);
        }
    }

    log_context_t *ogx = &session->kernel->redo_ctx;
    log_point_t curr_point = dtc_get_ctrl(session, g_replay_paral_mgr.node_id[idx])->rcy_point;
    log_point_t lrp_point = dtc_get_ctrl(session, g_replay_paral_mgr.node_id[idx])->lrp_point;
    OG_LOG_DEBUG_INF(
        "[YJJ DEBUG] dtc_update_standby_cluster_scn, node_id: %d, batch->head.point: lfn: %llu, lsn: %llu; redo_ctx.curr_point: lfn: %llu, lsn: %llu; ctrl.curr_point: lfn: %llu, lsn: %llu;  ctrl.curr_point: lfn: %llu, lsn: %llu",
        g_replay_paral_mgr.node_id[idx], (uint64)batch->head.point.lfn, batch->head.point.lsn,
        (uint64)ogx->curr_point.lfn, ogx->curr_point.lsn, (uint64)curr_point.lfn, curr_point.lsn, (uint64)lrp_point.lfn,
        lrp_point.lsn);

    ckpt_set_trunc_point_slave_role(session, &batch->head.point, g_replay_paral_mgr.node_id[idx]);
    return;
}

void dtc_rcy_atomic_dec_group_num(knl_session_t *session, uint32 idx, int32 val)
{
    status_t ret;
    if (cm_atomic32_add(&g_replay_paral_mgr.group_num[idx], -val) == 0) {
        dtc_update_standby_cluster_scn(session, idx);
        ret = dtc_rcy_atomic_list_push(&g_replay_paral_mgr.free_list, idx);
        knl_panic_log(ret == OG_TRUE, "[DTC RCY] push into free list error");
    }
}

static status_t dtc_rcy_paral_replay_batch(knl_session_t *session, log_cursor_t *cursor, uint32 idx,
    dtc_rcy_replay_batch_diag_t *diag)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    log_batch_t *batch = (log_batch_t *)g_replay_paral_mgr.buf_list[idx].aligned_buf;
    log_group_t *group = NULL;
    bool32 logic = OG_FALSE;
    rcy_paral_group_t *next_paral_group = NULL;
    log_context_t *ogx = &session->kernel->redo_ctx;
    uint32 group_slot = rcy->curr_group_id;
    knl_session_t *redo_ssesion = session->kernel->sessions[SESSION_ID_KERNEL];
    date_t batch_begin = DTC_RCY_REPLAY_BATCH_NOW();
    date_t step_begin;
    uint64 step_us;
    uint64 batch_fetch_group_us = 0;
    uint64 batch_pitr_check_us = 0;
    uint64 batch_add_pages_us = 0;
    uint64 batch_group_bookkeeping_us = 0;
    uint64 batch_normal_prepare_us = 0;
    uint64 batch_add_bucket_us = 0;
    uint64 batch_logic_group_us = 0;
    uint64 batch_update_lsn_us = 0;
    uint64 batch_debug_log_us = 0;
    uint64 batch_dec_group_us = 0;
    uint64 batch_groups = 0;
    uint64 batch_enter_pages = 0;
    uint64 batch_logic_groups = 0;
    uint64 batch_us;
    uint32 node_idx = g_replay_paral_mgr.node_id[idx];
    status_t status = OG_SUCCESS;
    redo_ssesion->dtc_session_type = session->dtc_session_type;

    if (diag != NULL) {
        diag->batch_count++;
    }
    rcy->curr_group = (rcy_paral_group_t *)g_replay_paral_mgr.group_list[idx].aligned_buf;
    g_replay_paral_mgr.group_num[idx] = DTC_RCY_GROUP_NUM_BASE;
    g_replay_paral_mgr.batch_scn[idx] = 0;
    g_replay_paral_mgr.batch_rpl_start_time[idx] = cm_now();
    for (;;) {
        if (KNL_RECOVERY_WITH_RBP(session->kernel) && rbp_knl_dtc_fallback_required(session)) {
            status = OG_ERROR;
            break;
        }
        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        group = log_fetch_group(ogx, cursor);
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_fetch_group_us += step_us;
        if (diag != NULL) {
            diag->fetch_group_us += step_us;
        }
        if (group == NULL) {
            OG_LOG_DEBUG_INF("paral redo replay, fetch current log group is NULL");
            break;
        }
        batch_groups++;
        if (diag != NULL) {
            diag->group_count++;
        }

        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        if (dtc_rcy_set_pitr_end_replay(session->kernel->db.recover_for_restore, group->lsn)) {
            step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
            batch_pitr_check_us += step_us;
            if (diag != NULL) {
                diag->pitr_check_us += step_us;
            }
            if (diag != NULL) {
                diag->pitr_end_count++;
            }
            OG_LOG_RUN_INF("[DTC RCY] pcn is invalide, lsn=%llu, rmid=%u", group->lsn, group->rmid);
            break;
        }
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_pitr_check_us += step_us;
        if (diag != NULL) {
            diag->pitr_check_us += step_us;
        }

        // record curr replay lsn in redo_ssesion when paral recovery, it will be used in rbp_page_verify
        // because redo_curr_lsn must >= page lsn during lrpl, if rbp_page_lsn > redo_curr_lsn, means rbp page can used
        redo_ssesion->curr_lsn = group->lsn;
        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        rcy_add_pages(rcy->curr_group, group, group_slot, rcy, &logic, &next_paral_group);
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_add_pages_us += step_us;
        if (diag != NULL) {
            diag->add_pages_us += step_us;
            diag->enter_page_count += rcy->curr_group->enter_count;
        }
        batch_enter_pages += rcy->curr_group->enter_count;
        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        g_replay_paral_mgr.batch_scn[idx] = MAX(g_replay_paral_mgr.batch_scn[idx], rcy->curr_group->group_scn);
        group_slot++;
        rcy->curr_group_id = group_slot;
        cm_atomic_set(&rcy->preload_hwm, (int64)rcy->page_list_count);
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_group_bookkeeping_us += step_us;
        if (diag != NULL) {
            diag->group_bookkeeping_us += step_us;
        }
        if (logic) {
            // redo log has logic log, must replay by order
            batch_logic_groups++;
            if (diag != NULL) {
                diag->logic_group_count++;
            }
            rcy->wait_stats_view[LOGIC_GROUP_COUNT]++;
            rcy->curr_group->ddl_lsn_pitr = dtc_rcy_get_ddl_lsn_pitr();
            step_begin = DTC_RCY_REPLAY_DIAG_NOW();
            if (rcy_replay_logic_group(session, rcy->curr_group) != OG_SUCCESS) {
                status = OG_ERROR;
            }
            step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
            batch_logic_group_us += step_us;
            if (diag != NULL) {
                diag->logic_group_us += step_us;
            }
            if (status != OG_SUCCESS) {
                break;
            }
        } else {
            step_begin = DTC_RCY_REPLAY_DIAG_NOW();
            if (diag != NULL) {
                diag->normal_group_count++;
            }
            cm_atomic32_inc(&g_replay_paral_mgr.group_num[idx]);
            rcy->curr_group->group_list_idx = idx;
            step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
            batch_normal_prepare_us += step_us;
            if (diag != NULL) {
                diag->normal_prepare_us += step_us;
            }
            step_begin = DTC_RCY_REPLAY_DIAG_NOW();
            rcy_add_replay_bucket(rcy->curr_group, rcy);
            step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
            batch_add_bucket_us += step_us;
            if (diag != NULL) {
                diag->add_bucket_us += step_us;
            }
        }

        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        OG_LOG_DEBUG_INF("[DTC RCY] redo replay log group lsn=%llu, rmid=%u, kernel lsn=%llu, "
                         "id=%u, group_tid=%u, inc_idx=%u, enter_cnt=%u",
                         group->lsn, group->rmid, session->kernel->lsn, rcy->curr_group->id, rcy->curr_group->tx_id,
                         rcy->curr_group->group_list_idx, rcy->curr_group->enter_count);
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_debug_log_us += step_us;
        if (diag != NULL) {
            diag->debug_log_us += step_us;
        }

        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        dtc_update_lsn(session, group->lsn);
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_update_lsn_us += step_us;
        if (diag != NULL) {
            diag->update_lsn_us += step_us;
        }
        step_begin = DTC_RCY_REPLAY_DIAG_NOW();
        OG_LOG_DEBUG_INF("[DTC RCY] updated kernel->session->lsn=%llu", session->kernel->lsn);
        step_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
        batch_debug_log_us += step_us;
        if (diag != NULL) {
            diag->debug_log_us += step_us;
        }
        rcy->curr_group = next_paral_group;
    }

    step_begin = DTC_RCY_REPLAY_DIAG_NOW();
    dtc_rcy_atomic_dec_group_num(session, idx, DTC_RCY_GROUP_NUM_BASE);
    batch_dec_group_us = (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - step_begin);
    if (diag != NULL) {
        diag->dec_group_us += batch_dec_group_us;
    }
    batch_us = (uint64)(DTC_RCY_REPLAY_BATCH_NOW() - batch_begin);
    if (diag != NULL && batch_us > diag->max_batch_us) {
        diag->max_batch_us = batch_us;
        diag->max_batch_lfn = (uint64)batch->head.point.lfn;
        diag->max_batch_lsn = batch->lsn;
        diag->max_batch_groups = batch_groups;
        diag->max_batch_enter_pages = batch_enter_pages;
        diag->max_batch_logic_groups = batch_logic_groups;
        diag->max_batch_idx = idx;
        diag->max_batch_node_idx = node_idx;
        diag->max_batch_space_size = batch->space_size;
    }
    if (batch_us >= DTC_RCY_REPLAY_BATCH_SLOW_US) {
#if DTC_RCY_REPLAY_HOT_DIAG
        OG_LOG_RUN_WAR("[DTC RCY] slow paral replay batch: idx=%u node_idx=%u lfn=%llu lsn=%llu "
                       "space_size=%u groups=%llu enter_pages=%llu logic_groups=%llu total_us=%llu "
                       "fetch_group_us=%llu pitr_check_us=%llu add_pages_us=%llu group_bookkeeping_us=%llu "
                       "normal_prepare_us=%llu add_bucket_us=%llu logic_group_us=%llu update_lsn_us=%llu "
                       "debug_log_us=%llu dec_group_us=%llu",
                       idx, node_idx, (uint64)batch->head.point.lfn, batch->lsn, batch->space_size,
                       batch_groups, batch_enter_pages, batch_logic_groups, batch_us, batch_fetch_group_us,
                       batch_pitr_check_us, batch_add_pages_us, batch_group_bookkeeping_us,
                       batch_normal_prepare_us, batch_add_bucket_us, batch_logic_group_us, batch_update_lsn_us,
                       batch_debug_log_us, batch_dec_group_us);
#else
        OG_LOG_RUN_WAR("[DTC RCY] slow paral replay batch: idx=%u node_idx=%u lfn=%llu lsn=%llu "
                       "space_size=%u groups=%llu enter_pages=%llu logic_groups=%llu total_us=%llu",
                       idx, node_idx, (uint64)batch->head.point.lfn, batch->lsn, batch->space_size,
                       batch_groups, batch_enter_pages, batch_logic_groups, batch_us);
#endif
    }
    OG_LOG_DEBUG_INF("[DTC RCY] finish paral redo replay of log batch=%u", idx);
    return status;
}

static void dtc_close_analyze_proc()
{
    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        cm_close_thread(&g_analyze_paral_mgr.thread[i]);
    }
}

static void dtc_rcy_reset_node_read_ring(dtc_rcy_node_t *rcy_node)
{
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;

    rcy_node->read_buf_read_index = 0;
    rcy_node->read_buf_write_index = 0;
    for (uint32 j = 0; j < read_buf_size; j++) {
        rcy_node->read_buf_ready[j] = OG_FALSE;
        rcy_node->read_pos[j] = 0;
        rcy_node->write_pos[j] = 0;
        rcy_node->read_size[j] = OG_INVALID_ID32;
        rcy_node->not_finished[j] = OG_TRUE;
    }
}

static void dtc_rcy_runtime_tail_set_start(knl_session_t *session, log_point_t *safe_point, log_point_t *next_point)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = &dtc_rcy->rcy_nodes[0];
    reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[0];

    /*
     * Fetch uses rcy_point both as the last analyzed LFN for continuity and as
     * the physical end of that batch. Runtime safe_point keeps the safe LFN,
     * while next_point keeps the physical end after the safe batch.
     */
    rcy_log_point->rcy_point = *next_point;
    rcy_log_point->rcy_point.lfn = safe_point->lfn;
    rcy_log_point->rcy_write_point = *next_point;
    rcy_node->analysis_read_end_point = *safe_point;
    rcy_node->recover_done = OG_FALSE;
    rcy_node->ulog_exist_data = OG_TRUE;
    rcy_node->latest_lsn = 0;
    rcy_node->latest_rcy_end_lsn = 0;
    dtc_rcy_reset_node_read_ring(rcy_node);
    if (cm_dbs_is_enable_dbs() && session->kernel->db.recover_for_restore) {
        rcy_log_point->rcy_point.asn = 0;
        rcy_log_point->rcy_point.block_id = OG_INFINITE32;
        rcy_log_point->rcy_write_point.asn = 0;
        rcy_log_point->rcy_write_point.block_id = OG_INFINITE32;
    }
}

static status_t dtc_rcy_analyze_batches_runtime(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_point_t runtime_safe;
    log_point_t runtime_next;
    log_point_t original_rcy_point;
    log_point_t original_write_point;
    log_point_t recover_lrp_point;
    log_point_t tail_end_point = { 0 };
    status_t status = OG_SUCCESS;
    status_t finish_status = OG_SUCCESS;
    bool32 runtime_prepared = OG_FALSE;

    if (!dtc_rbp_rt_aly_prepare_partial(session, &runtime_safe, &runtime_next)) {
        return OG_ERROR;
    }
    runtime_prepared = OG_TRUE;
    recover_lrp_point = dtc_rcy->rcy_stat.rcy_log_points[0].lrp_point;
    original_rcy_point = dtc_rcy->rcy_log_points[0].rcy_point;
    original_write_point = dtc_rcy->rcy_log_points[0].rcy_write_point;
    if (dtc_rcy_runtime_reset_result(session) != OG_SUCCESS) {
        status = OG_ERROR;
        goto cleanup;
    }
    dtc_rcy_runtime_tail_set_start(session, &runtime_safe, &runtime_next);
    OG_LOG_RUN_INF("[DTC RBP RT] runtime tail analyze start, peer=%u safe_lfn=%llu next_lfn=%llu "
                   "recover_lrp_lfn=%llu safe_lsn=%llu recover_lrp_lsn=%llu "
                   "merge_order=tail_global_then_rt_snapshot",
                   dtc_rcy->rcy_nodes[0].node_id, (uint64)runtime_safe.lfn, (uint64)runtime_next.lfn,
                   (uint64)recover_lrp_point.lfn, runtime_safe.lsn, (uint64)recover_lrp_point.lsn);
    status = dtc_rcy_analyze_batches_paral(session);
    if (status == OG_SUCCESS && log_cmp_point(&session->kernel->redo_ctx.redo_end_point, &runtime_safe) < 0) {
        session->kernel->redo_ctx.redo_end_point = runtime_safe;
        session->kernel->redo_ctx.rbp_aly_lsn = MAX(session->kernel->redo_ctx.rbp_aly_lsn, runtime_safe.lsn);
    }
    tail_end_point = session->kernel->redo_ctx.redo_end_point;

cleanup:
    dtc_rcy->rcy_log_points[0].rcy_point = original_rcy_point;
    dtc_rcy->rcy_log_points[0].rcy_write_point = original_write_point;
    dtc_rcy->rcy_nodes[0].recover_done = OG_FALSE;
    dtc_rcy_reset_node_read_ring(&dtc_rcy->rcy_nodes[0]);

    if (status == OG_SUCCESS) {
        finish_status = dtc_rbp_rt_aly_finish_partial(session);
    }
    if (status != OG_SUCCESS || finish_status != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[DTC RBP RT] runtime tail analyze failed, fallback to recovery analyzer, "
                       "tail_status=%d finish_status=%d safe_lfn=%llu tail_end_lfn=%llu",
                       (int32)status, (int32)finish_status, (uint64)runtime_safe.lfn,
                       (uint64)tail_end_point.lfn);
        if (runtime_prepared) {
            dtc_rbp_rt_aly_abort_partial(session);
        }
        (void)dtc_rcy_runtime_reset_result(session);
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[DTC RBP RT] runtime partial analyze finish, peer=%u safe_lfn=%llu next_lfn=%llu "
                   "tail_end_lfn=%llu final_redo_end_lfn=%llu merge_order=tail_global_then_rt_snapshot",
                   dtc_rcy->rcy_nodes[0].node_id, (uint64)runtime_safe.lfn, (uint64)runtime_next.lfn,
                   (uint64)tail_end_point.lfn,
                   (uint64)session->kernel->redo_ctx.redo_end_point.lfn);
    return OG_SUCCESS;
}

static status_t dtc_rcy_analyze_batches_paral(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    int64 lgwr_buf_size = (int64)LOG_LGWR_BUF_SIZE(session);
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_t *batch = NULL;
    status_t status = OG_SUCCESS;
    errno_t ret;
    uint32 idx;
    uint32 curr_node_idx = 0;
    uint64 fetch_count = 0;
    uint64 queued_count = 0;
    uint64 free_empty_count = 0;
    uint64 fetch_null_count = 0;
    date_t stage_begin;
    uint64 stage_elapsed;
    dtc_rcy_analysis_main_stat_t main_stat = { 0 };
    bool32 waiting_free = OG_FALSE;
    date_t wait_free_begin = 0;
    g_analyze_paral_mgr.killed_flag = OG_FALSE;
    g_analyze_paral_mgr.read_log_end_flag = OG_FALSE;
    g_analyze_paral_mgr.running_thread_num = 0;
    dtc_rcy_analyze_diag_reset();
    uint32 prarl_buf_list_size = g_instance->kernel.attr.dtc_rcy_paral_buf_list_size;

    OG_LOG_RUN_INF("[DTC RCY] paral redo log analyze start, dtc_rcy->phase=%u, session->id=%u node_count=%u "
                   "buf_slots=%u worker_num=%u partial_rbp_collecting=%u full_recovery=%u hot_diag=%u",
                   dtc_rcy->phase, session->id, dtc_rcy->node_count, prarl_buf_list_size,
                   (uint32)PARAL_ANALYZE_THREAD_NUM, (uint32)dtc_rcy_rbp_partial_collecting(session),
                   (uint32)dtc_rcy->full_recovery, (uint32)DTC_RCY_ANALYZE_HOT_DIAG);
    dtc_rcy_log_read_buffer_diag(dtc_rcy, "analyze-start");
    dtc_rcy->pcn_diag_analyze_path = DTC_PCND_ANALYZE_PARAL;
    if (dtc_rcy_rbp_partial_collecting(session)) {
        dtc_rcy_rbp_partial_reset_analyze_state(session);
        if (dtc_rcy_local_sets_init_all() != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] failed to initialize local recovery sets before analyze");
            return OG_ERROR;
        }
    }

    dtc_rcy_atomic_list_init(&g_analyze_paral_mgr.free_list);
    dtc_rcy_atomic_list_init(&g_analyze_paral_mgr.used_list);
    for (uint32 i = 0; i < prarl_buf_list_size; i++) {
        g_analyze_paral_mgr.free_list.array[i] = i;

        if (cm_aligned_malloc(lgwr_buf_size, "dtc rcy read buffer", &g_analyze_paral_mgr.buf_list[i]) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to alloc log read buffer in paral analyze, buffer list id=%u, "
                           "lgwr_buf_size=%llu",
                           i, lgwr_buf_size);
            dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, i);
            dtc_rcy_analyze_abort_local_sets();
            return OG_ERROR;
        }
    }
    g_analyze_paral_mgr.free_list.end = prarl_buf_list_size;
    g_analyze_paral_mgr.free_list.writed_end = prarl_buf_list_size;

    SYNC_POINT_GLOBAL_START(OGRAC_RECOVERY_ANAL_READ_LOG_FAIL, &status, OG_ERROR);
    status = dtc_read_all_logs(session);
    SYNC_POINT_GLOBAL_END;
    if (status != OG_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, prarl_buf_list_size);
        dtc_rcy_analyze_abort_local_sets();
        session->canceled = OG_TRUE;
        OG_LOG_RUN_ERR("[DTC RCY] failed to load first log file in paral analyze, dtc_rcy->failed=%u. "
                       "session->canceled=%u",
                       dtc_rcy->failed, session->canceled);
        return OG_ERROR;
    }

    knl_session_t *ss = NULL;
    if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&ss) != OG_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, prarl_buf_list_size);
        dtc_rcy_analyze_abort_local_sets();
        OG_LOG_RUN_ERR("[DTC RCY] dtc rcy proc init failed as alloc session failed");
        return OG_ERROR;
    }
    if (OG_SUCCESS != cm_create_thread(dtc_rcy_read_node_log_proc, 0, ss, &dtc_rcy->read_log_thread)) {
        dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, prarl_buf_list_size);
        dtc_rcy_analyze_abort_local_sets();
        OG_LOG_RUN_ERR("[DTC RCY] failed to create thread read node log proc");
        return OG_ERROR;
    }

    g_dtc_rcy_fetch_diag_active = &main_stat.fetch_diag;
    date_t fetch_begin;
    DTC_RCY_ANALYZE_MAIN_STEP_BEGIN(fetch_begin);
    if (dtc_rcy_fetch_log_batch(session, &batch, &curr_node_idx) != OG_SUCCESS) {
        DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(fetch_begin, main_stat.fetch_us);
        g_dtc_rcy_fetch_diag_active = NULL;
        dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, prarl_buf_list_size);
        dtc_rcy_analyze_abort_local_sets();
        OG_LOG_RUN_ERR("[DTC RCY] failed to extract first log batch in paral analyze, dtc_rcy->failed=%u. "
                       "session->canceled=%u",
                       dtc_rcy->failed, session->canceled);
        return OG_ERROR;
    }
    DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(fetch_begin, main_stat.fetch_us);
    if (batch == NULL) {
        fetch_null_count++;
        OG_LOG_RUN_WAR("[DTC RCY][analysis diag] first fetch returned NULL: phase=%u node_count=%u "
                       "free_count=%lld used_count=%lld",
                       (uint32)dtc_rcy->phase, dtc_rcy->node_count,
                       dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                       dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
        dtc_rcy_log_read_buffer_diag(dtc_rcy, "first-fetch-null");
    } else {
        fetch_count++;
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
        OG_LOG_DEBUG_INF("[DTC RCY][analysis diag] first fetch batch: node_idx=%u node_id=%u lfn=%llu lsn=%llu "
                         "space_size=%u free_count=%lld used_count=%lld",
                         curr_node_idx, dtc_rcy->rcy_nodes[curr_node_idx].node_id, (uint64)batch->head.point.lfn,
                         batch->lsn, batch->space_size, dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                         dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
#endif
    }
    for (uint32 i = 0; i < PARAL_ANALYZE_THREAD_NUM; i++) {
        // cpu_set_t cpuset;
        // CPU_ZERO(&cpuset);
        // CPU_SET(i + 20, &cpuset); // start from 20

        status = cm_create_thread(dtc_rcy_analyze_paral_proc, 0, (void *)session, &g_analyze_paral_mgr.thread[i]);
        if (status == OG_SUCCESS) {
            // pthread_setaffinity_np(g_analyze_paral_mgr.thread[i].id, sizeof(cpu_set_t), &cpuset);
            g_analyze_paral_mgr.running_thread_num++;
        } else {
            OG_LOG_RUN_ERR("[DTC RCY] failed to create paral analyze thread=%u", i);
            batch = NULL;
            g_analyze_paral_mgr.killed_flag = OG_TRUE;
            break;
        }
    }
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
    OG_LOG_DEBUG_INF("[DTC RCY][analysis diag] analyze workers created: running=%d free_count=%lld used_count=%lld "
                     "killed=%u",
                     cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num),
                     dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                     dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list),
                     (uint32)g_analyze_paral_mgr.killed_flag);
#endif
    while (batch != NULL) {
        if (session->canceled) {
            OG_LOG_RUN_ERR("[DTC RCY] rcy session is canceled, session->id=%u", session->id);
            OG_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = OG_ERROR;
            g_analyze_paral_mgr.killed_flag = OG_TRUE;
            break;
        }
        if (session->killed) {
            OG_LOG_RUN_ERR("[DTC RCY] rcy session is canceled, session->id=%u", session->id);
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            status = OG_ERROR;
            g_analyze_paral_mgr.killed_flag = OG_TRUE;
            break;
        }
        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            OG_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task");
            g_analyze_paral_mgr.killed_flag = OG_TRUE;
            break;
        }
        if (batch->scn > rcy->max_scn) {
            OG_LOG_RUN_INF("[DTC RCY] log batch->scn=%llu is larger than rcy->max_scn=%llu, recovery done", batch->scn,
                           rcy->max_scn);
            break;
        }
        idx = dtc_rcy_atomic_list_pop(&g_analyze_paral_mgr.free_list);
        if (idx == OG_INVALID_INT32) {  // free list is empty
            free_empty_count++;
            if (!waiting_free) {
                waiting_free = OG_TRUE;
                DTC_RCY_ANALYZE_MAIN_STEP_BEGIN(wait_free_begin);
            }
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
            if ((free_empty_count % DTC_RCY_ANALYZE_DIAG_INTERVAL) == 1) {
                OG_LOG_RUN_WAR("[DTC RCY][analysis diag] free list empty: free_empty=%llu fetched=%llu queued=%llu "
                               "running=%d read_end=%u killed=%u curr_node_idx=%u curr_node_id=%u "
                               "batch_lfn=%llu batch_lsn=%llu free_count=%lld used_count=%lld",
                               free_empty_count, fetch_count, queued_count,
                               cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num),
                               (uint32)g_analyze_paral_mgr.read_log_end_flag,
                               (uint32)g_analyze_paral_mgr.killed_flag, curr_node_idx,
                               dtc_rcy->rcy_nodes[curr_node_idx].node_id, (uint64)batch->head.point.lfn, batch->lsn,
                               dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                               dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
                dtc_rcy_log_read_buffer_diag(dtc_rcy, "free-list-empty");
            }
#endif
            cm_spin_sleep();
            continue;
        }
        if (waiting_free) {
            DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(wait_free_begin, main_stat.wait_free_us);
            waiting_free = OG_FALSE;
        }

        dtc_rcy_analyze_diag_set_main(DTC_RCY_ANALYZE_STAGE_MAIN_COPY, idx, dtc_rcy->rcy_nodes[curr_node_idx].node_id,
                                      batch);
        stage_begin = cm_now();
        date_t copy_begin;
        DTC_RCY_ANALYZE_MAIN_STEP_BEGIN(copy_begin);
        ret = memcpy_sp(g_analyze_paral_mgr.buf_list[idx].aligned_buf, lgwr_buf_size, (char *)batch, batch->space_size);
        knl_securec_check(ret);
        g_analyze_paral_mgr.node_ids[idx] = dtc_rcy->rcy_nodes[curr_node_idx].node_id;
        g_analyze_paral_mgr.batch_points[idx] = batch->head.point;
        if (dtc_rcy_rbp_partial_collecting(session)) {
            session->kernel->redo_ctx.rbp_aly_lsn = MAX(session->kernel->redo_ctx.rbp_aly_lsn, batch->lsn);
            session->kernel->redo_ctx.redo_end_point =
                dtc_rcy_make_batch_end_point(batch, dtc_rcy->rcy_nodes[curr_node_idx].blk_size);
        }
        DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(copy_begin, main_stat.copy_us);
        stage_elapsed = (uint64)(cm_now() - stage_begin);
        if (stage_elapsed > DTC_RCY_ANALYZE_SLOW_US) {
            OG_LOG_RUN_WAR("[DTC RCY][analysis diag] main prequeue slow: elapsed_us=%llu idx=%u node_id=%u "
                           "lfn=%llu lsn=%llu space=%u partial_rbp_collecting=%u",
                           stage_elapsed, idx, dtc_rcy->rcy_nodes[curr_node_idx].node_id,
                           (uint64)((log_batch_t *)g_analyze_paral_mgr.buf_list[idx].aligned_buf)->head.point.lfn,
                           ((log_batch_t *)g_analyze_paral_mgr.buf_list[idx].aligned_buf)->lsn,
                           ((log_batch_t *)g_analyze_paral_mgr.buf_list[idx].aligned_buf)->space_size,
                           (uint32)dtc_rcy_rbp_partial_collecting(session));
        }
        dtc_rcy_analyze_diag_set_main(DTC_RCY_ANALYZE_STAGE_MAIN_PUSH_USED, idx,
                                      dtc_rcy->rcy_nodes[curr_node_idx].node_id,
                                      (log_batch_t *)g_analyze_paral_mgr.buf_list[idx].aligned_buf);
        date_t push_begin;
        DTC_RCY_ANALYZE_MAIN_STEP_BEGIN(push_begin);
        knl_panic_log(dtc_rcy_atomic_list_push(&g_analyze_paral_mgr.used_list, idx),
                      "[DTC RCY] push buffer of idx %u from free list into used list error", idx);
        DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(push_begin, main_stat.push_used_us);
        queued_count++;
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
        if (queued_count == 1 || (queued_count % DTC_RCY_ANALYZE_PROGRESS_INTERVAL) == 0) {
            OG_LOG_DEBUG_INF("[DTC RCY][analysis diag] main queued batch: queued=%llu fetched=%llu node_idx=%u "
                             "node_id=%u lfn=%llu lsn=%llu free_count=%lld used_count=%lld",
                             queued_count, fetch_count, curr_node_idx, dtc_rcy->rcy_nodes[curr_node_idx].node_id,
                             (uint64)batch->head.point.lfn, batch->lsn,
                             dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                             dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
        }
#endif
        OG_LOG_DEBUG_INF("log batch [%llu/%llu/%u] push to idx=%u", batch->lsn, (uint64)batch->head.point.lfn,
                         batch->head.point.block_id, idx);
        dtc_rcy_analyze_diag_set_main(DTC_RCY_ANALYZE_STAGE_MAIN_FETCH_NEXT, idx,
                                      dtc_rcy->rcy_nodes[curr_node_idx].node_id, batch);
        DTC_RCY_ANALYZE_MAIN_STEP_BEGIN(fetch_begin);
        if (dtc_rcy_fetch_log_batch(session, &batch, &curr_node_idx) != OG_SUCCESS) {
            DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(fetch_begin, main_stat.fetch_us);
            OG_LOG_RUN_ERR("[DTC RCY] failed to extract log batch in paral analyze");
            status = OG_ERROR;
            g_analyze_paral_mgr.killed_flag = OG_TRUE;
            break;
        }
        DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(fetch_begin, main_stat.fetch_us);
        g_dtc_rcy_analyze_main_stage = DTC_RCY_ANALYZE_STAGE_IDLE;
        if (batch == NULL) {
            fetch_null_count++;
            OG_LOG_RUN_WAR("[DTC RCY][analysis diag] fetch returned NULL after queue: fetched=%llu queued=%llu "
                           "free_empty=%llu free_count=%lld used_count=%lld",
                           fetch_count, queued_count, free_empty_count,
                           dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                           dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
            dtc_rcy_log_read_buffer_diag(dtc_rcy, "fetch-null-after-queue");
        } else {
            fetch_count++;
        }
    }
    if (waiting_free) {
        DTC_RCY_ANALYZE_MAIN_STEP_ACCUM(wait_free_begin, main_stat.wait_free_us);
        waiting_free = OG_FALSE;
    }
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
    OG_LOG_DEBUG_INF("[DTC RCY][analysis diag] analyze main leave loop: status=%u fetched=%llu queued=%llu "
                     "fetch_null=%llu free_empty=%llu running=%d read_end=%u killed=%u free_count=%lld used_count=%lld",
                     (uint32)status, fetch_count, queued_count, fetch_null_count, free_empty_count,
                     cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num),
                     (uint32)g_analyze_paral_mgr.read_log_end_flag, (uint32)g_analyze_paral_mgr.killed_flag,
                     dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                     dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
#endif
    OG_LOG_RUN_INF("[DTC RCY][analysis main summary] fetch_us=%llu copy_us=%llu push_used_us=%llu "
                   "wait_free_us=%llu free_empty=%llu queued=%llu fetched=%llu fetch_null=%llu",
                   main_stat.fetch_us, main_stat.copy_us, main_stat.push_used_us, main_stat.wait_free_us,
                   free_empty_count, queued_count, fetch_count, fetch_null_count);
    dtc_rcy_log_fetch_diag_summary(&main_stat.fetch_diag, main_stat.fetch_us);
    g_dtc_rcy_fetch_diag_active = NULL;
    dtc_rcy_log_read_buffer_diag(dtc_rcy, "analyze-main-leave");
    if (close_read_log_proc(&dtc_rcy->read_log_thread, ss) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] close read log proc time out");
        status = OG_ERROR;
        g_analyze_paral_mgr.killed_flag = OG_TRUE;
    } else if (g_analyze_paral_mgr.killed_flag == OG_FALSE) {
        g_analyze_paral_mgr.read_log_end_flag = OG_TRUE;
    }
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
    OG_LOG_DEBUG_INF("[DTC RCY][analysis diag] read log closed, wait workers: running=%d read_end=%u killed=%u "
                     "free_count=%lld used_count=%lld",
                     cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num),
                     (uint32)g_analyze_paral_mgr.read_log_end_flag, (uint32)g_analyze_paral_mgr.killed_flag,
                     dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                     dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list));
#endif
    while (cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num) > 0) {
        cm_sleep(1);
    }
    if (status == OG_SUCCESS && g_analyze_paral_mgr.local_rcy_inited) {
        if (dtc_rcy_analyze_finalize_local(session, &main_stat) != OG_SUCCESS) {
            status = OG_ERROR;
        }
    }
    if (status != OG_SUCCESS) {
        dtc_rcy_analyze_abort_local_sets();
    }
    dtc_close_analyze_proc();
    dtc_rcy_free_list_in_analyze_paral(g_analyze_paral_mgr.buf_list, prarl_buf_list_size);
    session->canceled = dtc_rcy->canceled ? OG_TRUE : OG_FALSE;

    OG_LOG_RUN_INF("[DTC RCY] paral redo log analyze finish, dtc_rcy->phase=%u, session->id=%u, "
                   "need replay redo size total(M)=%llu fetched=%llu queued=%llu free_empty=%llu "
                   "partial_rbp_collecting=%u partial_items=%llu",
                   dtc_rcy->phase, session->id, stat->last_rcy_log_size / SIZE_M(1), fetch_count, queued_count,
                   free_empty_count, (uint32)dtc_rcy_rbp_partial_collecting(session),
                   dtc_rcy->rbp_partial_ctx.item_count);
    OG_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, session canceled=%u", dtc_rcy->canceled, session->canceled);
    g_dtc_rcy_fetch_diag_active = NULL;
    return status;
}

status_t dtc_lrpl_load_log_batch(knl_session_t *session, log_batch_t **batch, uint32 *curr_node_idx)
{
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    while (*batch == NULL) {
        if (dtc_rcy_fetch_log_batch(session, batch, curr_node_idx) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC LRPL] failed to extract log batch in paral replay");
            return OG_ERROR;
        }

        if (lrpl->is_closing && (*batch == NULL)) {
            OG_LOG_RUN_INF("[DTC LRPL] lrpl will be closed and cur log batch is null, retry fetch log batch");
            if (dtc_rcy_fetch_log_batch(session, batch, curr_node_idx) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC LRPL] failed to extract log batch in paral replay");
                return OG_ERROR;
            }
            if (*batch == NULL) {
                OG_LOG_RUN_INF("[DTC LRPL] lrpl replay end");
                return OG_SUCCESS;
            }
        }
    }
    return OG_SUCCESS;
}

void dtc_standby_reset_recovery_stat(knl_session_t *session)
{
    if (DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_node_t *rcy_node = NULL;
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_node = &dtc_rcy->rcy_nodes[i];
        if (rcy_node->recover_done == OG_TRUE) {
            continue;
        }

        if (rcy_node->read_pos[rcy_node->read_buf_read_index] != 0) {
            OG_LOG_DEBUG_INF("[DTC LRPL] no need reset node recovery_done, node %u read pos %u", i,
                             rcy_node->read_pos[rcy_node->read_buf_read_index]);
            return;
        }
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rcy_node = &dtc_rcy->rcy_nodes[i];
        rcy_node->recover_done = OG_FALSE;
        if (cm_dbs_is_enable_dbs() == OG_TRUE) {
            rcy_node->ulog_exist_data = OG_TRUE;
        }
    }
    OG_LOG_DEBUG_INF("[DTC LRPL] reset node recovery_done info to false");
    return;
}

bool32 dtc_rcy_need_continue(knl_session_t *session, log_batch_t **batch, uint32 *curr_node_idx)
{
    if (*batch != NULL) {
        return OG_TRUE;
    }
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        if ((DB_NOT_READY(session) || !dtc_rcy->full_recovery)) {
            return OG_FALSE;
        }
        if (dtc_lrpl_load_log_batch(session, batch, curr_node_idx) != OG_SUCCESS) {
            CM_ABORT_REASONABLE(0, "[DTC RCY] ABORT INFO:lrpl failed to load log batch in paral replay");
            return OG_FALSE;
        }
    }
    return (*batch != NULL);
}

static uint64 dtc_release_rcy_page_list(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    date_t begin_time;
    uint64 wait_us;
    uint32 page_list_count = rcy->page_list_count;

    if (rcy->page_list_count < RCY_PAGE_LIST_RELEASE_THRESHOLD) {
        return 0;
    }
    OG_LOG_RUN_INF("[DTC RCY] page_list count is %u, release threshold is %u, need to release", rcy->page_list_count,
                   RCY_PAGE_LIST_RELEASE_THRESHOLD);
    begin_time = cm_now();
    rcy_wait_replay_complete(session);
    wait_us = (uint64)(cm_now() - begin_time);
    OG_LOG_RUN_INF("[DTC RCY] page_list release wait done: page_list_count=%u threshold=%u wait_us=%llu",
                   page_list_count, RCY_PAGE_LIST_RELEASE_THRESHOLD, wait_us);
    return wait_us;
}

static void dtc_rcy_reset_rbp_tail_replay_stat(dtc_rcy_context_t *dtc_rcy)
{
    dtc_rcy->rbp_tail_find_max_invalid_count = 0;
    dtc_rcy->rbp_tail_find_max_invalid_bytes = 0;
    dtc_rcy->rbp_tail_find_max_invalid_first_lfn = 0;
    dtc_rcy->rbp_tail_find_max_invalid_last_lfn = 0;
    dtc_rcy->rbp_tail_invalid_cursor_count = 0;
}

static void dtc_rcy_log_rbp_tail_replay_summary(knl_session_t *session, uint64 submitted_batches,
    uint64 submitted_bytes, uint64 first_submit_lfn, uint64 last_submit_lfn, uint64 fetch_log_us,
    uint64 submit_replay_us, uint64 submit_loop_us, uint64 free_list_wait_us, uint64 free_list_wait_count,
    uint64 free_list_wait_spins, uint64 free_list_wait_max_us, uint64 page_list_release_us,
    uint64 page_list_release_waits, uint64 close_read_log_us, uint64 wait_replay_end_us)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 jump_nodes = 0;
    uint32 sample_node = OG_INVALID_ID32;
    uint64 tail_lfn_span_total = 0;
    uint64 tail_lfn_span_max = 0;
    uint64 skip_lfn_total = 0;
    uint64 sample_skip_lfn = 0;
    uint64 sample_rbp_rcy_lfn = 0;
    uint64 sample_analysis_end_lfn = 0;
    uint64 sample_recovery_end_lfn = 0;

    if (dtc_rcy->full_recovery || dtc_rcy->phase != PHASE_RECOVERY || !KNL_RECOVERY_WITH_RBP(session->kernel)) {
        return;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        uint64 span;

        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_jump_taken[node_id]) {
            continue;
        }

        jump_nodes++;
        span = (dtc_rcy->rcy_nodes[i].analysis_read_end_point.lfn > dtc_rcy->rbp_rcy_points[node_id].lfn) ?
            (uint64)(dtc_rcy->rcy_nodes[i].analysis_read_end_point.lfn - dtc_rcy->rbp_rcy_points[node_id].lfn) : 0;
        tail_lfn_span_total += span;
        tail_lfn_span_max = MAX(tail_lfn_span_max, span);
        if (dtc_rcy->rbp_rcy_points[node_id].lfn > dtc_rcy->rbp_skip_points[node_id].lfn) {
            skip_lfn_total += (uint64)(dtc_rcy->rbp_rcy_points[node_id].lfn -
                                       dtc_rcy->rbp_skip_points[node_id].lfn);
        }
        if (sample_node == OG_INVALID_ID32) {
            sample_node = node_id;
            sample_skip_lfn = (uint64)dtc_rcy->rbp_skip_points[node_id].lfn;
            sample_rbp_rcy_lfn = (uint64)dtc_rcy->rbp_rcy_points[node_id].lfn;
            sample_analysis_end_lfn = (uint64)dtc_rcy->rcy_nodes[i].analysis_read_end_point.lfn;
            sample_recovery_end_lfn = (uint64)dtc_rcy->rcy_nodes[i].recovery_read_end_point.lfn;
        }
    }

    OG_LOG_RUN_INF("[DTC RCY][RBP][partial] tail replay summary: jump_nodes=%u sample_node=%u "
                   "sample_skip_lfn=%llu sample_rbp_rcy_lfn=%llu sample_analysis_end_lfn=%llu "
                   "sample_recovery_end_lfn=%llu tail_lfn_span_total=%llu tail_lfn_span_max=%llu "
                   "skip_lfn_total=%llu submitted_batches=%llu submitted_bytes=%llu first_submit_lfn=%llu "
                   "last_submit_lfn=%llu fetch_log_us=%llu submit_replay_us=%llu submit_loop_us=%llu "
                   "free_list_wait_us=%llu free_list_wait_count=%llu free_list_wait_spins=%llu "
                   "free_list_wait_max_us=%llu page_list_release_us=%llu page_list_release_waits=%llu "
                   "close_read_log_us=%llu wait_replay_end_us=%llu find_max_invalid=%llu "
                   "find_max_invalid_bytes=%llu find_max_invalid_first_lfn=%llu find_max_invalid_last_lfn=%llu "
                   "invalid_cursor=%llu",
                   jump_nodes, sample_node, sample_skip_lfn, sample_rbp_rcy_lfn, sample_analysis_end_lfn,
                   sample_recovery_end_lfn, tail_lfn_span_total, tail_lfn_span_max,
                   skip_lfn_total, submitted_batches, submitted_bytes, first_submit_lfn, last_submit_lfn,
                   fetch_log_us, submit_replay_us, submit_loop_us, free_list_wait_us,
                   free_list_wait_count, free_list_wait_spins, free_list_wait_max_us, page_list_release_us,
                   page_list_release_waits, close_read_log_us, wait_replay_end_us,
                   dtc_rcy->rbp_tail_find_max_invalid_count, dtc_rcy->rbp_tail_find_max_invalid_bytes,
                   dtc_rcy->rbp_tail_find_max_invalid_first_lfn, dtc_rcy->rbp_tail_find_max_invalid_last_lfn,
                   dtc_rcy->rbp_tail_invalid_cursor_count);
}

static status_t dtc_rcy_replay_batches_paral(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    int64 lgwr_buf_size = (int64)LOG_LGWR_BUF_SIZE(session);
    log_batch_t *batch = NULL;
    log_cursor_t cursor;
    status_t status = OG_SUCCESS;
    errno_t ret;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    timeval_t elapsed_begin;
    uint32 idx;
    uint64 used_time;
    uint64 fetch_log_time = 0;
    uint64 replay_batch_time = 0;
    uint64 replay_submit_loop_us = 0;
    uint64 free_list_wait_us = 0;
    uint64 free_list_wait_max_us = 0;
    uint64 free_list_wait_count = 0;
    uint64 free_list_wait_spins = 0;
    uint64 release_page_list_us = 0;
    uint64 release_page_list_waits = 0;
    uint64 close_read_log_us = 0;
    uint64 wait_replay_end_us = 0;
    uint64 copy_batch_us = 0;
    uint64 init_cursor_us = 0;
    uint64 replay_accounted_us;
    uint64 replay_other_us;
    uint64 release_wait_us;
    uint64 submitted_batches = 0;
    uint64 submitted_bytes = 0;
    uint64 first_submit_lfn = 0;
    uint64 last_submit_lfn = 0;
    bool32 rbp_tail_replay_diag;
    date_t stage_begin;
    date_t replay_submit_begin = 0;
    date_t free_list_wait_begin = 0;
    uint32 curr_node_idx = 0;
    uint32 prarl_buf_list_size = g_instance->kernel.attr.dtc_rcy_paral_buf_list_size;
#if DTC_RCY_REPLAY_HOT_DIAG
    dtc_rcy_replay_batch_diag_t replay_diag = { 0 };
    dtc_rcy_replay_batch_diag_t *replay_diag_ptr = &replay_diag;
#else
    dtc_rcy_replay_batch_diag_t *replay_diag_ptr = NULL;
#endif

    rbp_tail_replay_diag =
        (bool32)(!dtc_rcy->full_recovery && dtc_rcy->phase == PHASE_RECOVERY && KNL_RECOVERY_WITH_RBP(session->kernel));
    OG_LOG_RUN_INF("[DTC RCY] start paral redo replay, dtc_rcy->phase=%u, session->kernel->lsn=%llu", dtc_rcy->phase,
                   session->kernel->lsn);
    if (rbp_tail_replay_diag) {
        dtc_rcy_reset_rbp_tail_replay_stat(dtc_rcy);
    }

    dtc_rcy_atomic_list_init(&g_replay_paral_mgr.free_list);
    for (uint32 i = 0; i < prarl_buf_list_size; i++) {
        g_replay_paral_mgr.free_list.array[i] = i;

        if (cm_aligned_malloc(lgwr_buf_size, "dtc rcy read buffer", &g_replay_paral_mgr.buf_list[i]) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to alloc log read buffer in paral replay for buf_list id=%u", i);
            dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, i);
            return OG_ERROR;
        }
    }
    for (uint32 i = 0; i < prarl_buf_list_size; i++) {
        if (cm_aligned_malloc(lgwr_buf_size, "dtc rcy paral group buffer", &g_replay_paral_mgr.group_list[i]) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to alloc paral group buffer in paral replay for group=%u", i);
            dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, i);
            dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, prarl_buf_list_size);
            return OG_ERROR;
        }
    }
    g_replay_paral_mgr.free_list.end = prarl_buf_list_size;
    g_replay_paral_mgr.free_list.writed_end = prarl_buf_list_size;

    ELAPSED_BEGIN(elapsed_begin);
    SYNC_POINT_GLOBAL_START(OGRAC_PARAL_REPLAY_READ_LOG_FAIL, &status, OG_ERROR);
    status = dtc_read_all_logs(session);
    SYNC_POINT_GLOBAL_END;
    if (status != OG_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, prarl_buf_list_size);
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, prarl_buf_list_size);
        OG_LOG_RUN_ERR("[DTC RCY] failed to read redo log files in paral replay");
        return OG_ERROR;
    }
    ELAPSED_END(elapsed_begin, used_time);
    OG_LOG_RUN_INF("[DTC RCY] read redo logs in paral replay used=%llu", used_time);

    knl_session_t *ss = NULL;
    if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&ss) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] dtc rcy proc init failed as alloc session failed");
        return OG_ERROR;
    }
    if (OG_SUCCESS != cm_create_thread(dtc_rcy_read_node_log_proc, 0, ss, &dtc_rcy->read_log_thread)) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to create thread read node log proc");
        return OG_ERROR;
    }

    ELAPSED_BEGIN(elapsed_begin);
    if (dtc_rcy_fetch_log_batch(session, &batch, &curr_node_idx) != OG_SUCCESS) {
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, prarl_buf_list_size);
        dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, prarl_buf_list_size);
        OG_LOG_RUN_ERR("[DTC RCY] failed to extract log batch in paral replay");
        return OG_ERROR;
    }
    ELAPSED_END(elapsed_begin, fetch_log_time);
    ELAPSED_BEGIN(rcy->paral_rcy_thread_start_work_time);
    if (rbp_tail_replay_diag) {
        replay_submit_begin = cm_now();
    }
    while (dtc_rcy_need_continue(session, &batch, &curr_node_idx)) {
        if (session->canceled) {
            OG_LOG_RUN_ERR("[DTC RCY] session is canceled, session->id=%u", session->id);
            OG_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = OG_ERROR;
            break;
        }

        if (session->killed) {
            OG_LOG_RUN_ERR("[DTC RCY] session is killed, session->id=%u", session->id);
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            status = OG_ERROR;
            break;
        }

        if (KNL_RECOVERY_WITH_RBP(session->kernel) && rbp_knl_dtc_fallback_required(session)) {
            status = OG_ERROR;
            break;
        }

        // check whether need to cancel this task
        if (DB_IS_PRIMARY(&session->kernel->db) && dtc_rcy->canceled) {
            OG_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task");
            break;
        }

        if (dtc_rcy_pitr_replay_end(rcy, batch)) {
            break;
        }

        if (DB_IS_PRIMARY(&session->kernel->db) && dtc_rcy_full_recovery_replay_end(rcy, batch)) {
            break;
        }

        idx = dtc_rcy_atomic_list_pop(&g_replay_paral_mgr.free_list);
        if (idx == OG_INVALID_INT32) {  // free list is empty
            if (rbp_tail_replay_diag && free_list_wait_begin == 0) {
                free_list_wait_begin = cm_now();
                free_list_wait_count++;
            }
            if (rbp_tail_replay_diag) {
                free_list_wait_spins++;
            }
            cm_spin_sleep();            // 100ns
            continue;
        }
        if (rbp_tail_replay_diag && free_list_wait_begin != 0) {
            uint64 wait_us = (uint64)(cm_now() - free_list_wait_begin);
            free_list_wait_us += wait_us;
            if (wait_us > free_list_wait_max_us) {
                free_list_wait_max_us = wait_us;
            }
            free_list_wait_begin = 0;
        }

        release_wait_us = dtc_release_rcy_page_list(session);
        if (release_wait_us > 0) {
            release_page_list_us += release_wait_us;
            release_page_list_waits++;
        }
        if (rbp_tail_replay_diag) {
            if (submitted_batches == 0) {
                first_submit_lfn = (uint64)batch->head.point.lfn;
            }
            submitted_batches++;
            submitted_bytes += batch->space_size;
            last_submit_lfn = (uint64)batch->head.point.lfn;
        }

#if DTC_RCY_REPLAY_HOT_DIAG
        stage_begin = DTC_RCY_REPLAY_DIAG_NOW();
        ret = memcpy_sp(g_replay_paral_mgr.buf_list[idx].aligned_buf, lgwr_buf_size, (char *)batch, batch->space_size);
        knl_securec_check(ret);
        copy_batch_us += (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - stage_begin);
#else
        ret = memcpy_sp(g_replay_paral_mgr.buf_list[idx].aligned_buf, lgwr_buf_size, (char *)batch, batch->space_size);
        knl_securec_check(ret);
#endif
        g_replay_paral_mgr.node_id[idx] = curr_node_idx;

        // call batch process function
#if DTC_RCY_REPLAY_HOT_DIAG
        stage_begin = DTC_RCY_REPLAY_DIAG_NOW();
        rcy_init_log_cursor(&cursor, (log_batch_t *)g_replay_paral_mgr.buf_list[idx].aligned_buf);
        init_cursor_us += (uint64)(DTC_RCY_REPLAY_DIAG_NOW() - stage_begin);
#else
        rcy_init_log_cursor(&cursor, (log_batch_t *)g_replay_paral_mgr.buf_list[idx].aligned_buf);
#endif
        ELAPSED_BEGIN(elapsed_begin);
        if (dtc_rcy_paral_replay_batch(session, &cursor, idx, replay_diag_ptr) != OG_SUCCESS) {
            status = OG_ERROR;
        }
        OG_LOG_DEBUG_INF("[DTC RCY] paral replay redo log batch lfn=%llu, lsn=%llu, point [%u-%u/%u] has been"
                         " processed for instance=%u, session lsn=%llu",
                         (uint64)batch->head.point.lfn, batch->lsn, batch->head.point.rst_id, batch->head.point.asn,
                         batch->head.point.block_id, dtc_rcy->curr_node, session->kernel->lsn);
        ELAPSED_END(elapsed_begin, used_time);
        replay_batch_time += used_time;
        if (status != OG_SUCCESS) {
            break;
        }
        // fetch next batch
        ELAPSED_BEGIN(elapsed_begin);

        if (dtc_rcy_check_is_end_restore_recovery()) {
            break;
        }
        if (dtc_rcy_fetch_log_batch(session, &batch, &curr_node_idx) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to extract log batch in paral replay");
            status = OG_ERROR;
            break;
        }
        ELAPSED_END(elapsed_begin, used_time);
        fetch_log_time += used_time;
    }
    if (rbp_tail_replay_diag && free_list_wait_begin != 0) {
        uint64 wait_us = (uint64)(cm_now() - free_list_wait_begin);
        free_list_wait_us += wait_us;
        if (wait_us > free_list_wait_max_us) {
            free_list_wait_max_us = wait_us;
        }
    }
    if (rbp_tail_replay_diag) {
        replay_submit_loop_us = (uint64)(cm_now() - replay_submit_begin);
    }
    stage_begin = cm_now();
    if (close_read_log_proc(&dtc_rcy->read_log_thread, ss) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] close read log proc time out");
        return OG_ERROR;
    }
    close_read_log_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();
    bool32 keep_workers_for_rbp_fallback = (bool32)(!dtc_rcy->full_recovery &&
        KNL_RECOVERY_WITH_RBP(session->kernel) && !dtc_rcy->rbp_redo_fallback_used &&
        (status == OG_SUCCESS || rbp_knl_dtc_fallback_required(session)));
    dtc_rcy_wait_paral_replay_end(session, (bool32)!keep_workers_for_rbp_fallback);
    wait_replay_end_us = (uint64)(cm_now() - stage_begin);
    if (rbp_tail_replay_diag) {
        dtc_rcy_log_rbp_tail_replay_summary(session, submitted_batches, submitted_bytes, first_submit_lfn,
            last_submit_lfn, fetch_log_time, replay_batch_time, replay_submit_loop_us, free_list_wait_us,
            free_list_wait_count, free_list_wait_spins, free_list_wait_max_us, release_page_list_us,
            release_page_list_waits, close_read_log_us, wait_replay_end_us);
    }
    dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.buf_list, prarl_buf_list_size);
    dtc_rcy_free_list_in_analyze_paral(g_replay_paral_mgr.group_list, prarl_buf_list_size);

    session->canceled = dtc_rcy->canceled ? OG_TRUE : OG_FALSE;
    OG_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, session canceled=%u", dtc_rcy->canceled, session->canceled);

#if DTC_RCY_REPLAY_HOT_DIAG
    replay_accounted_us = replay_diag.fetch_group_us + replay_diag.pitr_check_us + replay_diag.add_pages_us +
        replay_diag.group_bookkeeping_us + replay_diag.normal_prepare_us + replay_diag.add_bucket_us +
        replay_diag.logic_group_us + replay_diag.update_lsn_us + replay_diag.debug_log_us + replay_diag.dec_group_us;
    replay_other_us = (replay_batch_time > replay_accounted_us) ? (replay_batch_time - replay_accounted_us) : 0;
    OG_LOG_DEBUG_INF("[DTC RCY] paral replay timing detail: submit_loop_us=%llu free_list_wait_us=%llu "
                     "free_list_wait_count=%llu free_list_wait_spins=%llu free_list_wait_max_us=%llu "
                     "release_page_list_us=%llu release_page_list_waits=%llu close_read_log_us=%llu "
                     "wait_replay_end_us=%llu",
                     replay_submit_loop_us, free_list_wait_us, free_list_wait_count, free_list_wait_spins,
                     free_list_wait_max_us, release_page_list_us, release_page_list_waits, close_read_log_us,
                     wait_replay_end_us);
    OG_LOG_DEBUG_INF("[DTC RCY] paral replay submit detail: batches=%llu copy_batch_us=%llu init_cursor_us=%llu",
                     replay_diag.batch_count, copy_batch_us, init_cursor_us);
    OG_LOG_DEBUG_INF("[DTC RCY] paral replay batch breakdown: batches=%llu groups=%llu normal_groups=%llu "
                     "logic_groups=%llu enter_pages=%llu pitr_end=%llu fetch_group_us=%llu pitr_check_us=%llu "
                     "add_pages_us=%llu group_bookkeeping_us=%llu normal_prepare_us=%llu add_bucket_us=%llu "
                     "logic_group_us=%llu logic_wait_us=%llu logic_replay_us=%llu update_lsn_us=%llu "
                     "debug_log_us=%llu dec_group_us=%llu unaccounted_us=%llu",
                     replay_diag.batch_count, replay_diag.group_count, replay_diag.normal_group_count,
                     replay_diag.logic_group_count, replay_diag.enter_page_count, replay_diag.pitr_end_count,
                     replay_diag.fetch_group_us, replay_diag.pitr_check_us, replay_diag.add_pages_us,
                     replay_diag.group_bookkeeping_us, replay_diag.normal_prepare_us, replay_diag.add_bucket_us,
                     replay_diag.logic_group_us, dtc_rcy->rcy_stat.latc_rcy_logic_log_wait_time,
                     dtc_rcy->rcy_stat.last_rcy_logic_log_elapsed, replay_diag.update_lsn_us,
                     replay_diag.debug_log_us, replay_diag.dec_group_us, replay_other_us);
    OG_LOG_DEBUG_INF("[DTC RCY] paral replay max batch: idx=%u node_idx=%u lfn=%llu lsn=%llu space_size=%u "
                     "total_us=%llu groups=%llu enter_pages=%llu logic_groups=%llu",
                     replay_diag.max_batch_idx, replay_diag.max_batch_node_idx, replay_diag.max_batch_lfn,
                     replay_diag.max_batch_lsn, replay_diag.max_batch_space_size, replay_diag.max_batch_us,
                     replay_diag.max_batch_groups, replay_diag.max_batch_enter_pages,
                     replay_diag.max_batch_logic_groups);
#else
    (void)copy_batch_us;
    (void)init_cursor_us;
    (void)replay_accounted_us;
    (void)replay_other_us;
#endif
    OG_LOG_DEBUG_INF("[DTC RCY] finish paral redo replay, dtc_rcy->phase=%u, session->kernel->lsn=%llu, "
                     "fetch redo log used time=%llu replay_batch_time=%llu",
                     dtc_rcy->phase, session->kernel->lsn, fetch_log_time, replay_batch_time);
    return status;
}

static void try_to_read_no_log_node(thread_t *thread, uint32 *last_nod_log_buffer_index)
{
    OG_LOG_DEBUG_INF("[DTC RCY] dtc rcy try to read failed node");
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    knl_session_t *session = (knl_session_t *)thread->argument;
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    for (int j = 0; j < dtc_rcy->node_count; ++j) {
        dtc_rcy_node_t *node = &dtc_rcy->rcy_nodes[j];
        if (node->read_size[node->read_buf_write_index] != 0) {
            continue;
        }
        if (node->read_buf_ready[node->read_buf_write_index]) {
            cm_spin_sleep();
            OG_LOG_DEBUG_INF("[DTC RCY] read node read buffer is ready "
                             "node_id = %u read_buf_write_index=%u",
                             j, node->read_buf_write_index);
            continue;
        }
        if (last_nod_log_buffer_index[j] == OG_INVALID_ID32) {
            continue;
        }
        OG_LOG_DEBUG_INF("[DTC RCY] read node log proc read last failed node log last_failed_id=%u", j);
        uint32 read_size = 0;
        // try to read last failed node log
        node->read_size[node->read_buf_write_index] = OG_INVALID_ID32;
        if (dtc_read_node_log(dtc_rcy, session, j, &read_size) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] read node lod proc failed to load redo log of last failed node=%u", j);
            return;
        }
        node->read_size[node->read_buf_write_index] = read_size;
        if (read_size != 0) {
            last_nod_log_buffer_index[j] = OG_INVALID_ID32;
            node->read_buf_ready[node->read_buf_write_index] = OG_TRUE;
            node->read_buf_write_index = (node->read_buf_write_index + 1) % read_buf_size;
            OG_LOG_RUN_INF("[DTC RCY] read node lod proc last node log "
                           "success read_size = %u node=%u write_index=%u",
                           read_size, j, node->read_buf_write_index);
        }
    }
    OG_LOG_DEBUG_INF("[DTC RCY] dtc rcy finish try to read failed node");
}

void dtc_rcy_read_node_log_proc(thread_t *thread)
{
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    knl_session_t *session = (knl_session_t *)thread->argument;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 last_nod_log_buffer_index[read_buf_size];
    uint64 wait_ready_count[OG_MAX_INSTANCES] = { 0 };
    for (int i = 0; i < read_buf_size; ++i) {
        last_nod_log_buffer_index[i] = OG_INVALID_ID32;
    }
    OG_LOG_RUN_INF("[DTC RCY] rcy read node log thread start "
                   "closed = %d result = %d ",
                   thread->closed, thread->result);
    while (!thread->closed) {
        for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
            if (thread->closed) {
                break;
            }
            dtc_rcy_node_t *node = &dtc_rcy->rcy_nodes[i];
            if (node->read_buf_ready[node->read_buf_write_index]) {
                if (i < OG_MAX_INSTANCES && dtc_rcy->phase == PHASE_ANALYSIS) {
                    wait_ready_count[i]++;
#if DTC_RCY_ANALYZE_INFLIGHT_DIAG
                    if ((wait_ready_count[i] % DTC_RCY_READ_WAIT_DIAG_INTERVAL) == 1) {
                        OG_LOG_RUN_WAR("[DTC RCY][analysis diag] read thread blocked by full ring: idx=%u node_id=%u "
                                       "wait_count=%llu read_idx=%u write_idx=%u ready_r=%u ready_w=%u "
                                       "read_size_r=%u read_size_w=%u read_pos_r=%u write_pos_r=%u "
                                       "recover_done=%u free_count=%lld used_count=%lld running=%d read_end=%u",
                                       i, node->node_id, wait_ready_count[i], node->read_buf_read_index,
                                       node->read_buf_write_index,
                                       (uint32)node->read_buf_ready[node->read_buf_read_index],
                                       (uint32)node->read_buf_ready[node->read_buf_write_index],
                                       node->read_size[node->read_buf_read_index],
                                       node->read_size[node->read_buf_write_index],
                                       node->read_pos[node->read_buf_read_index],
                                       node->write_pos[node->read_buf_read_index],
                                       (uint32)node->recover_done,
                                       dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.free_list),
                                       dtc_rcy_atomic_list_count(&g_analyze_paral_mgr.used_list),
                                       cm_atomic32_get(&g_analyze_paral_mgr.running_thread_num),
                                       (uint32)g_analyze_paral_mgr.read_log_end_flag);
                        dtc_rcy_log_analyze_inflight();
                    }
#endif
                }
                continue;
            }
            if (i < OG_MAX_INSTANCES && dtc_rcy->phase == PHASE_ANALYSIS) {
                wait_ready_count[i] = 0;
            }
            uint32 read_size = 0;
            if (dtc_read_node_log(dtc_rcy, session, i, &read_size) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] read node log proc failed to "
                               "load redo log of crashed node=%u",
                               node->node_id);
                break;
            }
            if (read_size == 0) {
                node->read_size[node->read_buf_write_index] = read_size;
                last_nod_log_buffer_index[i] = node->read_buf_write_index;
                continue;
            }
            last_nod_log_buffer_index[i] = OG_INVALID_ID32;
            try_to_read_no_log_node(thread, last_nod_log_buffer_index);
            OG_LOG_DEBUG_INF("[DTC RCY] read node log proc finish read node "
                             "log node_id=%u read_buf_write_index=%u",
                             node->node_id, node->read_buf_write_index);
            node->read_buf_ready[node->read_buf_write_index] = OG_TRUE;
            node->read_size[node->read_buf_write_index] = read_size;
            node->read_buf_write_index = (node->read_buf_write_index + 1) % read_buf_size;
        }
    }
    thread->result = OG_TRUE;
    OG_LOG_RUN_INF("[DTC RCY] rcy read node log thread is closed, closed = %d result = %d ", thread->closed,
                   thread->result);
}

static inline void dtc_rcy_next_phase(knl_session_t *session)
{
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy->phase = PHASE_RECOVERY;
    dtc_rcy->curr_node_idx = OG_INVALID_ID8;
    dtc_rcy->curr_node = OG_INVALID_ID8;
    dtc_rcy->curr_blk_size = OG_INVALID_ID16;
    dtc_rcy->curr_batch_lsn = OG_INVALID_ID64;
    dtc_rcy->is_end_restore_recover = OG_FALSE;
    dtc_rcy->recovery_status = RECOVERY_REPLAY;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        dtc_rcy->rcy_log_points[i].rcy_point = dtc_rcy->rcy_log_points[i].rcy_point_saved;
        dtc_rcy->rcy_log_points[i].rcy_write_point = dtc_rcy->rcy_log_points[i].rcy_point_saved;
        dtc_rcy->rcy_nodes[i].recover_done = OG_FALSE;
        dtc_rcy->rcy_nodes[i].ulog_exist_data = OG_TRUE;
        /*
         * ANALYSIS and RECOVERY use separate read-log threads. The replay phase must start with an empty ring;
         * otherwise a stale ready bit from analysis can make the new reader wait forever while the consumer waits
         * for a freshly filled read_size.
         */
        dtc_rcy->rcy_nodes[i].read_buf_read_index = 0;
        dtc_rcy->rcy_nodes[i].read_buf_write_index = 0;
        for (int j = 0; j < read_buf_size; ++j) {
            dtc_rcy->rcy_nodes[i].read_buf_ready[j] = OG_FALSE;
            dtc_rcy->rcy_nodes[i].read_pos[j] = 0;
            dtc_rcy->rcy_nodes[i].write_pos[j] = 0;
            dtc_rcy->rcy_nodes[i].read_size[j] = OG_INVALID_ID32;
            dtc_rcy->rcy_nodes[i].not_finished[j] = OG_TRUE;
        }
        dtc_rcy->rcy_nodes[i].latest_lsn = 0;
        dtc_rcy->rcy_nodes[i].latest_rcy_end_lsn = 0;
        if (cm_dbs_is_enable_dbs() && session->kernel->db.recover_for_restore) {
            dtc_rcy->rcy_log_points[i].rcy_point.asn = 0;
            dtc_rcy->rcy_log_points[i].rcy_point.block_id = OG_INFINITE32;
            dtc_rcy->rcy_log_points[i].rcy_write_point.asn = 0;
            dtc_rcy->rcy_log_points[i].rcy_write_point.block_id = OG_INFINITE32;
            OG_LOG_RUN_INF("[DTC RCY] dtc_rcy_next_phase dtc_rcy->rcy_write_log_points[i].rcy_point.asn = %u",
                           dtc_rcy->rcy_log_points[i].rcy_point.asn);
        }
    }
}

static status_t dtc_rcy_full_recovery_replay(knl_session_t *session, dtc_rcy_stat_t *stat)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    timeval_t begin_time;
    ELAPSED_BEGIN(begin_time);
    if (dtc_rcy->paral_rcy) {
        if (dtc_rcy_replay_batches_paral(session) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        if (dtc_rcy_process_batches(session) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    ELAPSED_END(begin_time, stat->last_rcy_replay_elapsed);
    return OG_SUCCESS;
}

static void dtc_rcy_rbp_clear_lfn_point_maps(dtc_rcy_context_t *dtc_rcy)
{
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        CM_FREE_PTR(dtc_rcy->rbp_lfn_point_maps[i].entries);
        dtc_rcy->rbp_lfn_point_maps[i].count = 0;
        dtc_rcy->rbp_lfn_point_maps[i].capacity = 0;
    }
}

static void dtc_rcy_rbp_reset_lfn_point_maps(dtc_rcy_context_t *dtc_rcy)
{
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        dtc_rcy->rbp_lfn_point_maps[i].count = 0;
    }
}

static status_t dtc_rcy_rbp_ensure_lfn_point_capacity(dtc_rbp_lfn_point_map_t *map, uint32 required)
{
    uint32 new_capacity;
    uint64 old_size;
    uint64 new_size;
    dtc_rbp_lfn_point_entry_t *new_entries = NULL;

    if (required <= map->capacity) {
        return OG_SUCCESS;
    }

    new_capacity = (map->capacity == 0) ? 1024 : map->capacity;
    while (new_capacity < required) {
        if (new_capacity > (uint32)(OG_INVALID_ID32 / 2)) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)required * sizeof(dtc_rbp_lfn_point_entry_t),
                           "dtc rbp lfn point map");
            return OG_ERROR;
        }
        new_capacity *= 2;
    }

    old_size = (uint64)map->count * sizeof(dtc_rbp_lfn_point_entry_t);
    new_size = (uint64)new_capacity * sizeof(dtc_rbp_lfn_point_entry_t);
    new_entries = (dtc_rbp_lfn_point_entry_t *)malloc(new_size);
    if (new_entries == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, new_size, "dtc rbp lfn point map");
        return OG_ERROR;
    }

    if (map->count > 0) {
        errno_t err = memcpy_sp(new_entries, new_size, map->entries, old_size);
        knl_securec_check(err);
    }
    CM_FREE_PTR(map->entries);
    map->entries = new_entries;
    map->capacity = new_capacity;
    return OG_SUCCESS;
}

static bool32 dtc_rcy_get_point_bounds(knl_session_t *session, uint32 inst_node_id, const log_point_t *pt,
    dtc_rcy_point_bounds_t *bounds)
{
    logfile_set_t *log_set = NULL;
    log_file_t *file = NULL;
    errno_t err;

    if (bounds == NULL || pt == NULL || inst_node_id >= OG_MAX_INSTANCES) {
        return OG_FALSE;
    }

    err = memset_sp(bounds, sizeof(dtc_rcy_point_bounds_t), 0, sizeof(dtc_rcy_point_bounds_t));
    knl_securec_check(err);

    log_set = LOGFILE_SET(session, inst_node_id);
    for (uint32 i = 0; i < log_set->logfile_hwm; i++) {
        file = &log_set->items[i];
        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }
        if (file->head.rst_id != pt->rst_id || file->head.asn != pt->asn) {
            continue;
        }
        bounds->found = OG_TRUE;
        bounds->blk_size = file->ctrl->block_size;
        if (bounds->blk_size == 0) {
            bounds->blk_size = 512;
        }
        bounds->write_pos = file->head.write_pos;
        bounds->ctrl_size = (uint64)file->ctrl->size;
        bounds->max_blk_by_write_pos = bounds->write_pos / (uint64)bounds->blk_size;
        bounds->read_offset = (uint64)pt->block_id * (uint64)bounds->blk_size;
        bounds->use_logical_file_size = (file->ctrl->status == LOG_FILE_CURRENT) ? OG_TRUE : OG_FALSE;
        err = strncpy_s(bounds->file_name, OG_FILE_NAME_BUFFER_SIZE, file->ctrl->name, strlen(file->ctrl->name));
        knl_securec_check(err);
        bounds->offset_gt_write_pos = (bounds->read_offset >= bounds->write_pos) ? OG_TRUE : OG_FALSE;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void dtc_rcy_rbp_log_root_cause(knl_session_t *session, uint32 inst_node_id, const char *tag, const char *reason,
    const log_point_t *cursor, const log_batch_t *batch, const dtc_rcy_point_bounds_t *bounds, uint32 blk_before,
    uint32 blk_after)
{
#ifdef DTC_RCY_RBP_ROOT_TRACE
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint64 head_lfn = (batch != NULL) ? (uint64)batch->head.point.lfn : 0;
    uint32 head_blk = (batch != NULL) ? batch->head.point.block_id : 0;
    uint32 head_asn = (batch != NULL) ? batch->head.point.asn : 0;
    uint32 space_size = (batch != NULL) ? batch->space_size : 0;
    uint32 batch_size = (batch != NULL) ? batch->size : 0;

    if (dtc_rcy->full_recovery) {
        return;
    }

    OG_LOG_RUN_ERR("[DTC RCY][RBP][partial][ROOT] %s inst=%u phase=%u reason=%s "
                   "file=%s write_pos=%llu ctrl_size=%llu max_blk_by_write_pos=%llu use_logical_file_size=%u "
                   "cursor[rst%u asn%u blk%u lfn%llu lsn%llu] off=%llu off_gt_write_pos=%u "
                   "head[asn%u blk%u lfn%llu] batch_size=%u space_size=%u blk_before=%u blk_after=%u",
                   tag, inst_node_id, (uint32)dtc_rcy->phase, reason,
                   bounds != NULL && bounds->found ? bounds->file_name : "unknown",
                   bounds != NULL && bounds->found ? bounds->write_pos : 0,
                   bounds != NULL && bounds->found ? bounds->ctrl_size : 0,
                   bounds != NULL && bounds->found ? bounds->max_blk_by_write_pos : 0,
                   bounds != NULL && bounds->found ? (uint32)bounds->use_logical_file_size : 0,
                   cursor != NULL ? (uint32)cursor->rst_id : 0, cursor != NULL ? cursor->asn : 0,
                   cursor != NULL ? cursor->block_id : 0, cursor != NULL ? (uint64)cursor->lfn : 0,
                   cursor != NULL ? cursor->lsn : 0,
                   bounds != NULL && bounds->found ? bounds->read_offset : 0,
                   bounds != NULL && bounds->found ? (uint32)bounds->offset_gt_write_pos : 0,
                   head_asn, head_blk, head_lfn, batch_size, space_size, blk_before, blk_after);
#else
    (void)session;
    (void)inst_node_id;
    (void)tag;
    (void)reason;
    (void)cursor;
    (void)batch;
    (void)bounds;
    (void)blk_before;
    (void)blk_after;
#endif
}

static void dtc_rcy_rbp_check_point_root(knl_session_t *session, uint32 inst_node_id, const char *tag,
    const char *reason, const log_point_t *cursor, const log_batch_t *batch, uint32 blk_before, uint32 blk_after)
{
    dtc_rcy_point_bounds_t bounds;

    if (cursor == NULL || inst_node_id >= OG_MAX_INSTANCES || !dtc_rcy_get_point_bounds(session, inst_node_id, cursor,
        &bounds)) {
        return;
    }
    if (cursor->block_id <= bounds.max_blk_by_write_pos && bounds.max_blk_by_write_pos != 0) {
        return;
    }
    dtc_rcy_rbp_log_root_cause(session, inst_node_id, tag, reason, cursor, batch, &bounds, blk_before, blk_after);
}

static void dtc_rcy_rbp_check_cursor_fly_first(knl_session_t *session, uint32 inst_node_id, const char *tag,
    const char *reason, const log_point_t *cursor, const log_batch_t *batch, uint32 blk_before, uint32 blk_after)
{
    if (inst_node_id >= OG_MAX_INSTANCES || g_rbp_root_first_cursor_fly[inst_node_id]) {
        return;
    }
    dtc_rcy_point_bounds_t bounds;
    if (cursor == NULL || !dtc_rcy_get_point_bounds(session, inst_node_id, cursor, &bounds)) {
        return;
    }
    if (cursor->block_id <= bounds.max_blk_by_write_pos || bounds.max_blk_by_write_pos == 0) {
        return;
    }
    g_rbp_root_first_cursor_fly[inst_node_id] = OG_TRUE;
    dtc_rcy_rbp_log_root_cause(session, inst_node_id, tag, reason, cursor, batch, &bounds, blk_before, blk_after);
}

static void dtc_rcy_rbp_reset_root_diag(uint32 inst_node_id)
{
    if (inst_node_id < OG_MAX_INSTANCES) {
        g_rbp_root_first_cursor_fly[inst_node_id] = OG_FALSE;
    }
}

static status_t dtc_rcy_rbp_record_lfn_point(knl_session_t *session, uint32 node_id, log_batch_t *batch,
    log_point_t *point)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rbp_lfn_point_map_t *map = NULL;
    dtc_rcy_node_t *rcy_node = NULL;
    log_point_t mapped_point;
    dtc_rcy_point_bounds_t bounds;
    uint32 blk_size = 512;
    uint32 blk_before;
    uint32 blk_after;

    if (dtc_rcy->phase != PHASE_ANALYSIS || !dtc_rcy_rbp_partial_collecting(session) ||
        node_id >= OG_MAX_INSTANCES || batch == NULL || point == NULL || batch->head.point.lfn == 0) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        if ((uint32)dtc_rcy->rcy_log_points[i].node_id == node_id) {
            rcy_node = &dtc_rcy->rcy_nodes[i];
            break;
        }
    }
    if (rcy_node != NULL && rcy_node->blk_size != 0) {
        blk_size = rcy_node->blk_size;
    }
    if (batch->space_size < blk_size) {
        return OG_SUCCESS;
    }

    map = &dtc_rcy->rbp_lfn_point_maps[node_id];

    /* End-of-batch position from batch header; do not copy post-fetch rcy_point asn/block. */
    mapped_point = batch->head.point;
    mapped_point.lsn = batch->lsn;
    blk_before = mapped_point.block_id;
    mapped_point.block_id += batch->space_size / blk_size;
    blk_after = mapped_point.block_id;

    if (batch->head.point.asn != point->asn || batch->head.point.rst_id != point->rst_id) {
        if (dtc_rcy_get_point_bounds(session, node_id, &mapped_point, &bounds)) {
            dtc_rcy_rbp_log_root_cause(session, node_id, "map_record", "ASN_MISMATCH_USE_BATCH_HEAD", &mapped_point,
                batch, &bounds, blk_before, blk_after);
        }
    }

    if (dtc_rcy_get_point_bounds(session, node_id, &mapped_point, &bounds) &&
        mapped_point.block_id > bounds.max_blk_by_write_pos) {
        dtc_rcy_rbp_log_root_cause(session, node_id, "map_record",
            bounds.use_logical_file_size ? "BEYOND_WRITE_POS_CURRENT_DIAG" : "BEYOND_WRITE_POS_SKIP_MAP",
            &mapped_point, batch, &bounds, blk_before, blk_after);
        if (!bounds.use_logical_file_size) {
            return OG_SUCCESS;
        }
    }

    if (map->count > 0 && map->entries[map->count - 1].lfn == mapped_point.lfn) {
        map->entries[map->count - 1].point = mapped_point;
        return OG_SUCCESS;
    }

    if (dtc_rcy_rbp_ensure_lfn_point_capacity(map, map->count + 1) != OG_SUCCESS) {
        return OG_ERROR;
    }
    map->entries[map->count].lfn = mapped_point.lfn;
    map->entries[map->count].point = mapped_point;
    map->count++;
    return OG_SUCCESS;
}

static bool32 dtc_rcy_rbp_resolve_lfn_point(dtc_rcy_context_t *dtc_rcy, uint32 node_id, uint64 lfn,
    log_point_t *point)
{
    dtc_rbp_lfn_point_map_t *map = NULL;

    if (node_id >= OG_MAX_INSTANCES || lfn == 0 || point == NULL) {
        return OG_FALSE;
    }

    map = &dtc_rcy->rbp_lfn_point_maps[node_id];
    for (uint32 i = map->count; i > 0; i--) {
        if (map->entries[i - 1].lfn == lfn) {
            *point = map->entries[i - 1].point;
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t dtc_rcy_rbp_resolve_ckpt_resp(knl_session_t *session, uint32 node_id, rbp_read_ckpt_resp_t *resp)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_point_t point;

    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (resp->begin_point.lfn != 0 && dtc_rcy_rbp_resolve_lfn_point(dtc_rcy, node_id, resp->begin_point.lfn, &point)) {
        resp->begin_point = point;
    }

    if (resp->rcy_point.lfn != 0 &&
        !dtc_rcy_rbp_resolve_lfn_point(dtc_rcy, node_id, resp->rcy_point.lfn, &point)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] node %u cannot resolve rcy_lfn %llu from analysis map",
                       node_id, (uint64)resp->rcy_point.lfn);
        return OG_ERROR;
    }
    if (resp->rcy_point.lfn != 0) {
        resp->rcy_point = point;
        dtc_rcy_rbp_check_point_root(session, node_id, "resolve", "RESOLVE_RCY_POINT_BEYOND_WRITE_POS", &point, NULL,
            0, point.block_id);
    }

    if (resp->lrp_point.lfn != 0 &&
        !dtc_rcy_rbp_resolve_lfn_point(dtc_rcy, node_id, resp->lrp_point.lfn, &point)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] node %u cannot resolve lrp_lfn %llu from analysis map",
                       node_id, (uint64)resp->lrp_point.lfn);
        return OG_ERROR;
    }
    if (resp->lrp_point.lfn != 0) {
        resp->lrp_point = point;
    }

    return OG_SUCCESS;
}

static void dtc_rcy_rbp_update_global_lrp(knl_session_t *session, uint32 node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    uint64 lrp_lsn = MAX(dtc_rcy->rbp_lrp_points[node_id].lsn, dtc_rcy->rbp_max_lsns[node_id]);

    if (lrp_lsn > dtc_rcy->rbp_global_lrp_lsn) {
        dtc_rcy->rbp_global_lrp_lsn = lrp_lsn;
        redo_ctx->rbp_lrp_point = dtc_rcy->rbp_lrp_points[node_id];
        redo_ctx->rbp_lrp_point.lsn = lrp_lsn;
    }
}

/* Reset per-node RBP snapshot before each prepare so one recovery round does not leak state into the next one. */
static void dtc_rcy_rbp_reset_state(dtc_rcy_context_t *dtc_rcy)
{
    errno_t err;

    err = memset_sp(dtc_rcy->rbp_window_valid, sizeof(dtc_rcy->rbp_window_valid), 0, sizeof(dtc_rcy->rbp_window_valid));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_read_planned, sizeof(dtc_rcy->rbp_read_planned), 0,
                    sizeof(dtc_rcy->rbp_read_planned));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_jump_taken, sizeof(dtc_rcy->rbp_jump_taken), 0, sizeof(dtc_rcy->rbp_jump_taken));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_begin_points, sizeof(dtc_rcy->rbp_begin_points), 0, sizeof(dtc_rcy->rbp_begin_points));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_rcy_points, sizeof(dtc_rcy->rbp_rcy_points), 0, sizeof(dtc_rcy->rbp_rcy_points));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_lrp_points, sizeof(dtc_rcy->rbp_lrp_points), 0, sizeof(dtc_rcy->rbp_lrp_points));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_skip_points, sizeof(dtc_rcy->rbp_skip_points), 0, sizeof(dtc_rcy->rbp_skip_points));
    knl_securec_check(err);
    err = memset_sp(dtc_rcy->rbp_max_lsns, sizeof(dtc_rcy->rbp_max_lsns), 0, sizeof(dtc_rcy->rbp_max_lsns));
    knl_securec_check(err);
    dtc_rcy->rbp_global_lrp_lsn = 0;
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        dtc_rcy_rbp_reset_root_diag(i);
    }
}

static uint32 dtc_rcy_rbp_jump_count(dtc_rcy_context_t *dtc_rcy)
{
    uint32 count = 0;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id < OG_MAX_INSTANCES && dtc_rcy->rbp_jump_taken[node_id]) {
            count++;
        }
    }

    return count;
}

static uint64 dtc_rcy_get_global_local_lrp_lsn(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint64 max_lrp_lsn = 0;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);
        if (ctrl->lrp_point.lsn > max_lrp_lsn) {
            max_lrp_lsn = ctrl->lrp_point.lsn;
        }
    }

    return max_lrp_lsn;
}

/*
 * Multi-node v6 uses each node's RBP window as the upper bound of what that node can skip.
 * The window is usable only when:
 * - server-side window itself is valid;
 * - local merged analysis has already covered the newest page LSN returned by that server.
 *
 * DTC lfn is node-local, so redo_ctx->redo_end_point.lfn cannot be compared with a specific node server's lrp_lfn.
 * Use rbp_aly_lsn/max_lsn for cross-node WAL coverage; keep lfn comparisons only for per-node window membership.
 */
static bool32 dtc_rcy_rbp_window_usable(knl_session_t *session, rbp_read_ckpt_resp_t *resp)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    if (!KNL_RBP_SAFE(session->kernel) || redo_ctx->rbp_aly_result.rbp_unsafe ||
        resp->rbp_unsafe || resp->begin_point.lfn == 0 || resp->rcy_point.lfn == 0) {
        return OG_FALSE;
    }

    if (!LOG_LFN_LT(resp->begin_point, resp->rcy_point)) {
        return OG_FALSE;
    }

    if (redo_ctx->rbp_aly_lsn < resp->max_lsn) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 dtc_rcy_rbp_point_before_window(log_point_t *point, log_point_t *begin_point)
{
    return LOG_LFN_LT(*point, *begin_point);
}

static bool32 dtc_rcy_rbp_point_reach_window_end(log_point_t *point, log_point_t *rcy_point)
{
    return (bool32)!LOG_LFN_LT(*point, *rcy_point);
}

static uint32 dtc_rcy_rbp_candidate_count(dtc_rcy_context_t *dtc_rcy, bool8 *candidate_nodes)
{
    uint32 count = 0;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id < OG_MAX_INSTANCES && candidate_nodes[node_id]) {
            count++;
        }
    }
    return count;
}

static void dtc_rcy_rbp_set_candidate_planned(dtc_rcy_context_t *dtc_rcy, bool8 *candidate_nodes,
    bool8 planned)
{
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id < OG_MAX_INSTANCES && candidate_nodes[node_id]) {
            dtc_rcy->rbp_read_planned[node_id] = planned;
        }
    }
}

static uint32 dtc_rcy_rbp_planned_count(dtc_rcy_context_t *dtc_rcy)
{
    uint32 count = 0;

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id < OG_MAX_INSTANCES && dtc_rcy->rbp_read_planned[node_id]) {
            count++;
        }
    }

    return count;
}

static void dtc_rcy_rbp_disable_planned_nodes(dtc_rcy_context_t *dtc_rcy)
{
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id < OG_MAX_INSTANCES) {
            dtc_rcy->rbp_read_planned[node_id] = OG_FALSE;
        }
    }
}

static status_t dtc_rcy_rbp_query_and_cache_node_window(knl_session_t *session, uint32 node_id,
    rbp_read_ckpt_resp_t *resp, const char *stage)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    if (node_id >= OG_MAX_INSTANCES) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s: invalid node id %u", stage, node_id);
        return OG_ERROR;
    }

    dtc_rcy->rbp_window_valid[node_id] = OG_FALSE;
    for (uint32 retry = 0; retry < 3; retry++) {
        if (rbp_knl_query_rbp_point_by_node(session, node_id, resp, OG_TRUE) == OG_SUCCESS) {
            break;
        }
        if (retry == 2) {
            OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s: node %u READ_CKPT failed after 3 retries", stage, node_id);
            return OG_ERROR;
        }
        cm_sleep(10);
    }
    if (dtc_rcy_rbp_resolve_ckpt_resp(session, node_id, resp) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s: node %u READ_CKPT point resolve failed", stage, node_id);
        return OG_ERROR;
    }

    dtc_rcy->rbp_begin_points[node_id] = resp->begin_point;
    dtc_rcy->rbp_rcy_points[node_id] = resp->rcy_point;
    dtc_rcy->rbp_lrp_points[node_id] = resp->lrp_point;
    dtc_rcy->rbp_max_lsns[node_id] = resp->max_lsn;
    dtc_rcy->rbp_window_valid[node_id] = dtc_rcy_rbp_window_usable(session, resp);
    if (!dtc_rcy->rbp_window_valid[node_id]) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s: node %u window unusable begin_lfn=%llu rcy_lfn=%llu "
                       "lrp_lfn=%llu max_lsn=%llu rbp_aly_lsn=%llu",
                       stage, node_id, (uint64)resp->begin_point.lfn, (uint64)resp->rcy_point.lfn,
                       (uint64)resp->lrp_point.lfn, resp->max_lsn, redo_ctx->rbp_aly_lsn);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t dtc_rcy_rbp_begin_planned_read(knl_session_t *session, bool8 *candidate_nodes, const char *stage,
    bool32 *planned)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 candidate_count = dtc_rcy_rbp_candidate_count(dtc_rcy, candidate_nodes);

    if (planned != NULL) {
        *planned = OG_FALSE;
    }
    if (candidate_count == 0) {
        return OG_SUCCESS;
    }

    dtc_rcy_rbp_set_candidate_planned(dtc_rcy, candidate_nodes, OG_TRUE);
    if (rbp_knl_begin_dtc_read(session) != OG_SUCCESS) {
        dtc_rcy_rbp_set_candidate_planned(dtc_rcy, candidate_nodes, OG_FALSE);
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s READ_BEGIN failed for all candidate nodes, keep redo recovery",
                       stage);
        return OG_SUCCESS;
    }

    if (planned != NULL) {
        *planned = (bool32)(dtc_rcy_rbp_planned_count(dtc_rcy) > 0);
    }
    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s planned RBP read: planned_nodes=%u candidate_nodes=%u total_nodes=%u",
                   stage, dtc_rcy_rbp_planned_count(dtc_rcy), candidate_count, dtc_rcy->node_count);
    return OG_SUCCESS;
}

static void dtc_rcy_rbp_save_verify_node(knl_session_t *session, uint32 node_id)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 idx = rbp_context->dtc_verify_node_count;

    for (uint32 i = 0; i < rbp_context->dtc_verify_node_count; i++) {
        if (rbp_context->dtc_verify_nodes[i] == node_id) {
            idx = i;
            break;
        }
    }

    if (idx >= OG_MAX_INSTANCES) {
        return;
    }
    if (idx == rbp_context->dtc_verify_node_count) {
        rbp_context->dtc_verify_node_count++;
    }
    rbp_context->dtc_verify_nodes[idx] = node_id;
    rbp_context->dtc_verify_skip_points[idx] = dtc_rcy->rbp_skip_points[node_id];
    rbp_context->dtc_verify_rcy_points[idx] = dtc_rcy->rbp_rcy_points[node_id];
}

static void dtc_rcy_rbp_stage_jump_node(knl_session_t *session, uint32 node_idx, const char *stage)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    reform_rcy_node_t *node = &dtc_rcy->rcy_log_points[node_idx];
    uint32 node_id = (uint32)node->node_id;
    log_point_t skip_point = node->rcy_point;

    dtc_rcy->rbp_skip_points[node_id] = skip_point;
    dtc_rcy->rbp_jump_taken[node_id] = OG_TRUE;
    dtc_rcy_rbp_save_verify_node(session, node_id);
    node->rcy_point = dtc_rcy->rbp_rcy_points[node_id];
    node->rcy_write_point = dtc_rcy->rbp_rcy_points[node_id];
    dtc_rcy->rcy_nodes[node_idx].recovery_read_end_point = dtc_rcy->rbp_rcy_points[node_id];
    dtc_rcy_rbp_update_global_lrp(session, node_id);
    session->kernel->rcy_ctx.max_lrp_lsn = MAX(session->kernel->rcy_ctx.max_lrp_lsn,
                                               dtc_rcy->rbp_global_lrp_lsn);

    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] %s staged jump node %u from lfn %llu to lfn %llu, rbp_lrp_lsn=%llu",
                   stage, node_id, (uint64)skip_point.lfn, (uint64)dtc_rcy->rbp_rcy_points[node_id].lfn,
                   MAX(dtc_rcy->rbp_lrp_points[node_id].lsn, dtc_rcy->rbp_max_lsns[node_id]));
    dtc_rcy_rbp_check_point_root(session, node_id, "staged_jump", "JUMP_TARGET_BEYOND_WRITE_POS",
        &dtc_rcy->rbp_rcy_points[node_id], NULL, 0, dtc_rcy->rbp_rcy_points[node_id].block_id);
}

static status_t dtc_rcy_try_delayed_rbp_jump(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 jump_count = 0;

    if (dtc_rcy->full_recovery || dtc_rcy->phase != PHASE_RECOVERY || !KNL_RECOVERY_WITH_RBP(session->kernel) ||
        !KNL_RBP_ENABLE(session->kernel) || !KNL_RBP_FOR_RECOVERY(session->kernel) ||
        session->kernel->db.recover_for_restore || !KNL_RBP_SAFE(session->kernel)) {
        return OG_SUCCESS;
    }
    if (rbp_knl_dtc_read_failed(session)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] skip delayed jump because RBP read failed, "
                       "abort read phase and keep redo recovery");
        rbp_knl_abort_dtc_read(session);
        dtc_rcy_rbp_disable_planned_nodes(dtc_rcy);
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        log_point_t *point = &dtc_rcy->rcy_log_points[i].rcy_point;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_read_planned[node_id] ||
            dtc_rcy->rbp_jump_taken[node_id]) {
            continue;
        }
        if (!dtc_rcy->full_recovery && dtc_rcy->rbp_partial_jump_disabled[node_id]) {
            continue;
        }
        if (dtc_rcy_rbp_point_before_window(point, &dtc_rcy->rbp_begin_points[node_id])) {
            continue;
        }
        if (dtc_rcy_rbp_point_reach_window_end(point, &dtc_rcy->rbp_rcy_points[node_id])) {
            OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] staged jump invariant broken: node %u point lfn %llu reached rcy lfn %llu "
                           "before jump",
                           node_id, (uint64)point->lfn, (uint64)dtc_rcy->rbp_rcy_points[node_id].lfn);
            return OG_ERROR;
        }
        if (rbp_knl_dtc_read_failed(session)) {
            OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] skip delayed jump node %u because RBP read failed, "
                           "abort read phase and keep redo recovery", node_id);
            rbp_knl_abort_dtc_read(session);
            dtc_rcy_rbp_disable_planned_nodes(dtc_rcy);
            return OG_SUCCESS;
        }

        dtc_rcy_rbp_stage_jump_node(session, i, "staged");
        jump_count++;
    }

    if (jump_count == 0) {
        return OG_SUCCESS;
    }

    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] staged jump completed: jumped_now=%u total_jumped=%u planned=%u",
                   jump_count, dtc_rcy_rbp_jump_count(dtc_rcy), dtc_rcy_rbp_planned_count(dtc_rcy));
    return OG_SUCCESS;
}

bool32 dtc_rcy_rbp_partial_item_need_verify(knl_session_t *session, page_id_t page_id, uint32 node_id, uint64 lfn,
    uint64 expect_lsn)
{
    if (!OGRAC_PART_RECOVERY(session)) {
        return OG_TRUE;
    }

    rcy_set_item_t *rcy_item = dtc_rcy_get_item_internal(page_id);
    if (rcy_item == NULL) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] verify keeps page %u-%u required: node=%u lfn=%llu "
                       "expect_lsn=%llu is not in rcy_set",
                       page_id.file, page_id.page, node_id, (uint64)lfn, expect_lsn);
        return OG_TRUE;
    }
    if (!rcy_item->need_replay) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

uint64 dtc_rcy_rbp_partial_expect_lsn(knl_session_t *session, page_id_t page_id, uint64 item_lsn)
{
    rbp_partial_item_t *partial_item;

    if (!OGRAC_PART_RECOVERY(session)) {
        return item_lsn;
    }

    partial_item = dtc_rcy_rbp_partial_get_item(page_id);
    return dtc_rcy_rbp_partial_get_expect_lsn(partial_item);
}

void dtc_rcy_rbp_partial_mark_verified(knl_session_t *session, page_id_t page_id, uint32 node_id, uint64 lsn)
{
    rbp_partial_item_t *partial_item;

    (void)node_id;
    (void)lsn;

    if (!OGRAC_PART_RECOVERY(session)) {
        return;
    }

    partial_item = dtc_rcy_rbp_partial_get_item(page_id);
    if (partial_item != NULL) {
        dtc_rcy_rbp_partial_mark_item_verified(partial_item);
        return;
    }

    rcy_set_item_t *rcy_item = dtc_rcy_get_item_internal(page_id);
    if (rcy_item == NULL || !rcy_item->need_replay) {
        return;
    }

    rcy_item->rbp_verified = OG_TRUE;
}

uint64 dtc_rcy_rbp_partial_get_expect_lsn(rbp_partial_item_t *item)
{
    if (item == NULL || item->rcy_item == NULL || !item->rcy_item->need_replay) {
        return 0;
    }
    return item->expect_lsn;
}

void dtc_rcy_rbp_partial_update_candidate(rbp_partial_item_t *item, uint32 source_node, uint64 lsn)
{
    if (item == NULL) {
        return;
    }
    item->seen_node_bitmap |= ((uint64)1 << (source_node % 64));
    if (lsn > item->best_lsn) {
        item->best_lsn = lsn;
        item->best_source_node = source_node;
    }
}

void dtc_rcy_rbp_partial_update_selected(rbp_partial_item_t *item, uint32 source_node, uint64 lsn)
{
    if (item == NULL) {
        return;
    }
    item->seen_node_bitmap |= ((uint64)1 << (source_node % 64));
    if (!item->selected_valid || lsn > item->selected_lsn) {
        item->selected_valid = OG_TRUE;
        item->selected_pulled = OG_FALSE;
        item->selected_lsn = lsn;
        item->selected_node = source_node;
    }
    if (lsn > item->best_lsn) {
        item->best_lsn = lsn;
        item->best_source_node = source_node;
    }
}

bool32 dtc_rcy_rbp_partial_direct_selected_ready(uint32 node_id, uint32 *selected_count)
{
    rbp_partial_context_t *ctx = &DTC_RCY_CONTEXT->rbp_partial_ctx;

    if (selected_count != NULL) {
        *selected_count = ctx->direct_selected_count;
    }
    return (bool32)(ctx->direct_selected_ready && ctx->direct_selected_node == node_id);
}

void dtc_rcy_rbp_partial_mark_selected_pulled(rbp_partial_item_t *item, uint64 lsn)
{
    if (item == NULL) {
        return;
    }
    item->selected_pulled = OG_TRUE;
    if (lsn > item->best_lsn) {
        item->best_lsn = lsn;
        item->best_source_node = item->selected_node;
    }
}

void dtc_rcy_rbp_partial_mark_item_verified(rbp_partial_item_t *item)
{
    if (item == NULL || item->rcy_item == NULL || !item->rcy_item->need_replay) {
        return;
    }
    item->verified = OG_TRUE;
    item->rcy_item->rbp_verified = OG_TRUE;
}

bool32 dtc_rcy_rbp_partial_node_jump_disabled(uint32 node_id)
{
    if (node_id >= OG_MAX_INSTANCES) {
        return OG_TRUE;
    }
    return (bool32)DTC_RCY_CONTEXT->rbp_partial_jump_disabled[node_id];
}

static bool32 dtc_rcy_rbp_partial_touch_intersects(rbp_partial_touch_t *touch, log_point_t *skip_point,
    log_point_t *rcy_point)
{
    if (touch == NULL || !touch->used) {
        return OG_FALSE;
    }
    /*
     * A staged jump advances the redo cursor to rbp_rcy_point and the next replayed batch is rcy_lfn + 1.
     * Therefore the rcy_lfn boundary batch is part of the skipped window.
     */
    return (bool32)(touch->touch_max_lfn > skip_point->lfn && touch->touch_min_lfn <= rcy_point->lfn);
}

static status_t dtc_rcy_rbp_partial_append_required(rbp_partial_context_t *ctx, rbp_partial_item_t *item)
{
    uint32 new_capacity;
    rbp_partial_item_t **new_items = NULL;

    if (ctx->required_count < ctx->required_capacity) {
        ctx->required_items[ctx->required_count++] = item;
        return OG_SUCCESS;
    }

    new_capacity = (ctx->required_capacity == 0) ? 4096 : ctx->required_capacity * 2;
    if (new_capacity < ctx->required_capacity) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] required cache capacity overflow");
        return OG_ERROR;
    }

    size_t new_size = (size_t)new_capacity * sizeof(rbp_partial_item_t *);
    new_items = (rbp_partial_item_t **)malloc(new_size);
    if (new_items == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] failed to grow required cache: old=%u new=%u",
                       ctx->required_capacity, new_capacity);
        return OG_ERROR;
    }
    if (ctx->required_items != NULL && ctx->required_count > 0) {
        size_t old_size = (size_t)ctx->required_count * sizeof(rbp_partial_item_t *);
        errno_t err = memcpy_sp(new_items, new_size, ctx->required_items, old_size);
        if (err != EOK) {
            free(new_items);
            return OG_ERROR;
        }
    }
    CM_FREE_PTR(ctx->required_items);
    ctx->required_items = new_items;
    ctx->required_capacity = new_capacity;
    ctx->required_items[ctx->required_count++] = item;
    return OG_SUCCESS;
}

static void dtc_rcy_rbp_partial_reset_required_cache(rbp_partial_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    for (uint32 i = 0; i < ctx->required_count; i++) {
        rbp_partial_item_t *item = ctx->required_items[i];

        if (item == NULL) {
            continue;
        }
        item->required = OG_FALSE;
        item->verified = OG_FALSE;
        item->best_lsn = 0;
        item->best_source_node = OG_INVALID_ID32;
        item->selected_lsn = 0;
        item->selected_node = OG_INVALID_ID32;
        item->selected_valid = OG_FALSE;
        item->selected_pulled = OG_FALSE;
        item->seen_node_bitmap = 0;
    }
    ctx->required_count = 0;
    ctx->required_built = OG_TRUE;
    ctx->direct_selected_ready = OG_FALSE;
    ctx->direct_selected_node = OG_INVALID_ID32;
    ctx->direct_selected_count = 0;
}

status_t dtc_rcy_rbp_partial_build_required(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    rbp_partial_context_t *ctx = &dtc_rcy->rbp_partial_ctx;
#if DTC_RCY_ANALYZE_HOT_DIAG
    date_t begin_time = cm_now();
    uint64 append_us = 0;
    uint64 candidate_prepare_us = 0;
#endif
    uint32 planned_nodes = 0;
    uint32 disabled_nodes = 0;
    uint64 visited_items = 0;
    uint64 skip_no_rcy = 0;
    uint64 skip_no_need_replay = 0;
    uint64 skip_zero_expect = 0;
    uint64 touch_checked = 0;
    uint64 touch_intersect = 0;
    uint64 expect_behind_last_dirty = 0;
    uint32 expect_behind_sample = 0;

    if (!dtc_rcy_rbp_partial_enabled(session)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] required cache build skipped: side table disabled");
        return OG_ERROR;
    }

    dtc_rcy_rbp_partial_reset_required_cache(ctx);

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_read_planned[node_id]) {
            continue;
        }
        planned_nodes++;
        if (dtc_rcy->rbp_partial_jump_disabled[node_id]) {
            disabled_nodes++;
        }
    }

    for (rbp_partial_item_pool_t *pool = ctx->item_pools; pool != NULL; pool = pool->next) {
        for (int64 pool_idx = 0; pool_idx < pool->hwm; pool_idx++) {
            rbp_partial_item_t *item = &pool->items[pool_idx];
            bool32 required = OG_FALSE;

            visited_items++;
            if (item->rcy_item != NULL && item->rcy_item->last_dirty_lsn > item->expect_lsn) {
                expect_behind_last_dirty++;
                if (expect_behind_sample < 32) {
                    OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] build_required expect behind last_dirty sample[%u]: "
                                     "page %u-%u expect_lsn=%llu expect_lfn=%llu last_dirty_lsn=%llu need_replay=%u",
                                     expect_behind_sample, item->page_id.file, item->page_id.page,
                                     (uint64)item->expect_lsn, (uint64)item->expect_lfn,
                                     (uint64)item->rcy_item->last_dirty_lsn, (uint32)item->rcy_item->need_replay);
                    expect_behind_sample++;
                }
            }
            if (item->rcy_item == NULL) {
                skip_no_rcy++;
            } else if (!item->rcy_item->need_replay) {
                skip_no_need_replay++;
            } else if (item->expect_lsn == 0) {
                skip_zero_expect++;
            } else {
                for (uint32 i = 0; i < RBP_PARTIAL_TOUCH_SLOT_COUNT; i++) {
                    rbp_partial_touch_t *touch = &item->touches[i];
                    uint32 node_id = (uint32)touch->node_id;
                    if (!touch->used || node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_read_planned[node_id] ||
                        dtc_rcy->rbp_partial_jump_disabled[node_id]) {
                        continue;
                    }
                    touch_checked++;
                    if (dtc_rcy_rbp_partial_touch_intersects(touch, &dtc_rcy->rbp_begin_points[node_id],
                                                             &dtc_rcy->rbp_rcy_points[node_id])) {
                        touch_intersect++;
                        required = OG_TRUE;
                        break;
                    }
                }
            }
            if (required) {
#if DTC_RCY_ANALYZE_HOT_DIAG
                date_t append_begin = cm_now();
#endif
                item->required = OG_TRUE;
                item->verified = OG_FALSE;
                item->best_lsn = 0;
                item->best_source_node = OG_INVALID_ID32;
                item->selected_lsn = 0;
                item->selected_node = OG_INVALID_ID32;
                item->selected_valid = OG_FALSE;
                item->selected_pulled = OG_FALSE;
                item->seen_node_bitmap = 0;
                if (dtc_rcy_rbp_partial_append_required(ctx, item) != OG_SUCCESS) {
                    return OG_ERROR;
                }
#if DTC_RCY_ANALYZE_HOT_DIAG
                append_us += (uint64)(cm_now() - append_begin);
#endif
            }
        }
    }
    ctx->direct_selected_ready = OG_FALSE;
    ctx->direct_selected_node = OG_INVALID_ID32;
    ctx->direct_selected_count = 0;

#if DTC_RCY_ANALYZE_HOT_DIAG
    {
        date_t candidate_begin = cm_now();
        dtc_rcy_rbp_partial_free_candidate_cache(ctx);
        candidate_prepare_us = (uint64)(cm_now() - candidate_begin);
        OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial][required diag] required cache built: planned_nodes=%u "
                         "disabled_nodes=%u items=%llu visited_items=%llu required=%u overflow_items=%llu "
                         "skip_no_rcy=%llu skip_no_need_replay=%llu skip_zero_expect=%llu "
                         "expect_behind_last_dirty=%llu touch_checked=%llu touch_intersect=%llu "
                         "append_us=%llu candidate_prepare_us=%llu elapsed_us=%llu",
                         planned_nodes, disabled_nodes, ctx->item_count, visited_items, ctx->required_count,
                         ctx->overflow_items, skip_no_rcy, skip_no_need_replay, skip_zero_expect,
                         expect_behind_last_dirty, touch_checked, touch_intersect, append_us, candidate_prepare_us,
                         (uint64)(cm_now() - begin_time));
    }
#else
    dtc_rcy_rbp_partial_free_candidate_cache(ctx);
    OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial][required] built: planned_nodes=%u disabled_nodes=%u items=%llu "
                     "visited_items=%llu required=%u overflow_items=%llu skip_no_rcy=%llu "
                     "skip_no_need_replay=%llu skip_zero_expect=%llu touch_intersect=%llu",
                     planned_nodes, disabled_nodes, ctx->item_count, visited_items, ctx->required_count,
                     ctx->overflow_items, skip_no_rcy, skip_no_need_replay, skip_zero_expect, touch_intersect);
#endif
    return OG_SUCCESS;
}

uint32 dtc_rcy_rbp_partial_required_count(void)
{
    return DTC_RCY_CONTEXT->rbp_partial_ctx.required_count;
}

rbp_partial_item_t *dtc_rcy_rbp_partial_required_item(uint32 index)
{
    rbp_partial_context_t *ctx = &DTC_RCY_CONTEXT->rbp_partial_ctx;

    if (index >= ctx->required_count || ctx->required_items == NULL) {
        return NULL;
    }
    return ctx->required_items[index];
}

bool32 dtc_rcy_rbp_partial_item_in_jumped_window(knl_session_t *session, rbp_partial_item_t *item,
    uint32 *verify_node_id)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    (void)session;
    if (item == NULL || !item->required) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i < RBP_PARTIAL_TOUCH_SLOT_COUNT; i++) {
        rbp_partial_touch_t *touch = &item->touches[i];
        uint32 node_id = (uint32)touch->node_id;
        if (!touch->used || node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_jump_taken[node_id]) {
            continue;
        }
        if (dtc_rcy_rbp_partial_touch_intersects(touch, &dtc_rcy->rbp_skip_points[node_id],
                                                 &dtc_rcy->rbp_rcy_points[node_id])) {
            if (verify_node_id != NULL) {
                *verify_node_id = node_id;
            }
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t dtc_rcy_rbp_prepare_partial(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    bool8 candidate_nodes[OG_MAX_INSTANCES] = { 0 };
    uint32 candidate_count = 0;
    uint32 jump_allowed_count = 0;

    OG_LOG_DEBUG_INF("[DTC RCY][RBP][partial] prepare enter: phase=%u node_count=%u side_table=%u "
                     "redo_end_lfn=%llu rbp_aly_lsn=%llu rcy_with_rbp=%u safe=%u unsafe=%u",
                   (uint32)dtc_rcy->phase, dtc_rcy->node_count,
                   (uint32)dtc_rcy->rbp_partial_ctx.enabled,
                   (uint64)redo_ctx->redo_end_point.lfn, redo_ctx->rbp_aly_lsn,
                   (uint32)KNL_RECOVERY_WITH_RBP(session->kernel), (uint32)KNL_RBP_SAFE(session->kernel),
                   (uint32)redo_ctx->rbp_aly_result.rbp_unsafe);

    if (!dtc_rcy_rbp_partial_enabled(session)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare exit: partial RBP side table is not available");
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_UNAVAILABLE);
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        rbp_read_ckpt_resp_t resp;
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        log_point_t *point = &dtc_rcy->rcy_log_points[i].rcy_point_saved;
        if (node_id >= OG_MAX_INSTANCES) {
            continue;
        }
        if (dtc_rcy_rbp_query_and_cache_node_window(session, node_id, &resp, "partial prepare") != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] node %u disabled, keep redo recovery", node_id);
            continue;
        }
        if (dtc_rcy_rbp_point_reach_window_end(point, &resp.rcy_point)) {
            OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] node %u point lfn %llu reached/passed rcy %llu, keep redo",
                           node_id, (uint64)point->lfn, (uint64)resp.rcy_point.lfn);
            continue;
        }

        candidate_nodes[node_id] = OG_TRUE;
        candidate_count++;
        if (!dtc_rcy->rbp_partial_jump_disabled[node_id]) {
            jump_allowed_count++;
        }
    }

    if (candidate_count == 0) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare exit: no node satisfied RBP window");
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_CHECKED);
        return OG_SUCCESS;
    }
    if (jump_allowed_count == 0) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare exit: all %u candidate nodes are jump-disabled, "
                       "keep redo recovery",
                       candidate_count);
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_CHECKED);
        return OG_SUCCESS;
    }

    bool32 planned = OG_FALSE;
    if (dtc_rcy_rbp_begin_planned_read(session, candidate_nodes, "partial prepare", &planned) != OG_SUCCESS ||
        !planned) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] no planned node after READ_BEGIN, keep redo recovery");
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_CHECKED);
        return OG_SUCCESS;
    }

    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare planned: planned_nodes=%u candidate_nodes=%u jump_allowed=%u",
                   dtc_rcy_rbp_planned_count(dtc_rcy), candidate_count, jump_allowed_count);
    if (rbp_knl_dtc_read_failed(session)) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] RBP read failed before jump, abort read phase and keep redo recovery");
        rbp_knl_abort_dtc_read(session);
        dtc_rcy_rbp_set_candidate_planned(dtc_rcy, candidate_nodes, OG_FALSE);
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_CHECKED);
        return OG_SUCCESS;
    }
    if (dtc_rcy_try_delayed_rbp_jump(session) != OG_SUCCESS) {
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_CHECKED);
        return OG_ERROR;
    }
    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare immediate jump check done: jumped=%u planned=%u",
                   dtc_rcy_rbp_jump_count(dtc_rcy), dtc_rcy_rbp_planned_count(dtc_rcy));
    dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_PARTIAL_CHECKED);
    return OG_SUCCESS;
}

/*
 * RBP recovery acceleration is partial-recovery only. The partial analyzer records changed-page metadata in a side
 * table while building the recovery set; prepare only queries RBP windows and starts planned reads for those pages.
 */
static status_t dtc_rcy_rbp_prepare(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 rbp_conn = 0;
    uint64 global_local_lrp_lsn = 0;

    if (dtc_rcy->full_recovery) {
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_SKIP_NO_RBP);
        return OG_SUCCESS;
    }

    if (!dtc_rcy->rbp_saved_max_lrp_valid) {
        dtc_rcy->rbp_saved_max_lrp_lsn = session->kernel->rcy_ctx.max_lrp_lsn;
        dtc_rcy->rbp_saved_max_lrp_valid = OG_TRUE;
    }
    rbp_knl_clear_dtc_fallback(session);
    dtc_rcy_rbp_reset_state(dtc_rcy);
    global_local_lrp_lsn = dtc_rcy_get_global_local_lrp_lsn(session);
    if (session->kernel->rcy_ctx.max_lrp_lsn == OG_INVALID_ID64 ||
        global_local_lrp_lsn > session->kernel->rcy_ctx.max_lrp_lsn) {
        session->kernel->rcy_ctx.max_lrp_lsn = global_local_lrp_lsn;
    }

    if (KNL_RBP_ENABLE(session->kernel)) {
        for (uint32 i = 0; i < OG_RBP_SESSION_COUNT; i++) {
            if (session->kernel->rbp_context.rbp_buf_manager[i].is_connected) {
                rbp_conn++;
            }
        }
    }

    /* RUN_WAR is intentional here because default ogracd logs may hide RUN_INF during recovery. */
    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare enter inst=%u phase=%u node_count=%u USE_RBP=%u RBP_FOR_RECOVERY=%u "
                   "SAFE=%u rbp_unsafe=%u recover_for_restore=%u rbp_connected_queues=%u/%u "
                   "side_table=%u",
                   (uint32)session->kernel->id, (uint32)dtc_rcy->phase, dtc_rcy->node_count,
                   (uint32)KNL_RBP_ENABLE(session->kernel),
                   (uint32)KNL_RBP_FOR_RECOVERY(session->kernel), (uint32)KNL_RBP_SAFE(session->kernel),
                   (uint32)session->kernel->redo_ctx.rbp_aly_result.rbp_unsafe,
                   (uint32)session->kernel->db.recover_for_restore, rbp_conn, (uint32)OG_RBP_SESSION_COUNT,
                   (uint32)dtc_rcy->rbp_partial_ctx.enabled);

    if (!KNL_RBP_ENABLE(session->kernel) || !KNL_RBP_FOR_RECOVERY(session->kernel) ||
        session->kernel->db.recover_for_restore) {
        OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] prepare exit: skipped (need USE_RBP+RBP_FOR_RECOVERY and not recover_for_restore)");
        dtc_rcy_pcn_diag_finish_rbp_prepare(session, DTC_PCND_RBP_PREP_SKIP_NO_RBP);
        return OG_SUCCESS;
    }

    return dtc_rcy_rbp_prepare_partial(session);
}

static status_t dtc_rcy_full_recovery(knl_session_t *session)
{
    timeval_t begin_time;
    timeval_t total_begin_time;
    knl_session_t *se = session->kernel->sessions[SESSION_ID_KERNEL];
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    stat->last_rcy_is_full_recovery = OG_TRUE;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;
    uint64 rcy_disk_read_time = se->stat->disk_read_time;
    uint64 rcy_disk_read = se->stat->disk_reads;
    uint64 total_elapsed = 0;

    stat->last_rcy_analyze_elapsed = 0;
    ELAPSED_BEGIN(total_begin_time);

    OG_LOG_RUN_WAR("[DTC RCY] full_recovery begin phase=%u node_count=%u paral_rcy=%u",
                   (uint32)dtc_rcy->phase, dtc_rcy->node_count, (uint32)dtc_rcy->paral_rcy);

    if (dtc_rcy->phase == PHASE_ANALYSIS) {
        ELAPSED_BEGIN(begin_time);
        if (dtc_rcy_process_batches(session) != OG_SUCCESS) {
            return OG_ERROR;
        }
        ELAPSED_END(begin_time, stat->last_rcy_analyze_elapsed);
        dtc_rcy_next_phase(session);
        OG_LOG_RUN_INF("[DTC RCY][full recovery] finish redo analyze, pcn is equal num=%u, "
                       "analyze_time(us)=%llu",
                       dtc_rcy->pcn_is_equal_num, stat->last_rcy_analyze_elapsed);
    } else {
        OG_LOG_RUN_INF("[DTC RCY][full recovery] enter recovery phase without analysis phase");
    }

    RC_STEP_BEGIN(rf_detail->recovery_replay_elapsed);
    dtc_rcy->recovery_status = RECOVERY_REPLAY;
    if (dtc_rcy_full_recovery_replay(session, stat) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] redo replay failed");
        RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
        return OG_ERROR;
    }

    if (dtc_recover_check(session) != OG_SUCCESS) {
        if (!DB_IS_MAXFIX(session)) {
            RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
            return OG_ERROR;
        }
    }
    RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FINISH);

    OG_LOG_RUN_INF("[DTC RCY] finish redo replay, session lsn=%llu", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn);
    if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info), OG_TRUE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to broadcast reform status g_rc_ctx->status=%u", g_rc_ctx->status);
    }

    if (log_ddl_write_buffer(session) != OG_SUCCESS) {
        return OG_ERROR;
    }
    rcy_disk_read_time = se->stat->disk_read_time - rcy_disk_read_time;
    rcy_disk_read = se->stat->disk_reads - rcy_disk_read;

    OG_LOG_RUN_INF("[DTC RCY] kernel session read_page_num=%llu, total_time(us)=%llu, ave_time(us)=%llu", rcy_disk_read,
                   rcy_disk_read_time, (rcy_disk_read == 0 ? 0 : rcy_disk_read_time / rcy_disk_read));
    OG_LOG_RUN_INF("[DTC RCY] last_rcy_replay_elapsed_time=%llu", stat->last_rcy_replay_elapsed);
    OG_LOG_RUN_INF("[DTC RCY] last_rcy_replay_log_size=%llu", stat->last_rcy_log_size);
    ELAPSED_END(total_begin_time, total_elapsed);
    OG_LOG_RUN_INF("[DTC RCY][full recovery] recovery redo log size(M)=%llu, raw_bytes=%llu",
                   stat->last_rcy_log_size / SIZE_M(1), stat->last_rcy_log_size);
    OG_LOG_RUN_INF("[DTC RCY][full recovery] timing summary: analyze_time(us)=%llu, "
                   "replay_time(us)=%llu, total_time(us)=%llu",
                   stat->last_rcy_analyze_elapsed, stat->last_rcy_replay_elapsed, total_elapsed);

    // wait for all dirty pages to be flushed to disk
    ckpt_trigger(session, OG_TRUE, CKPT_TRIGGER_FULL);

    return dtc_rcy_update_ckpt_log_point(session);
}

static status_t dtc_rcy_partial_replay_once(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    dtc_rcy->recovery_status = RECOVERY_REPLAY;
    if (dtc_rcy->paral_rcy) {
        if (dtc_rcy_replay_batches_paral(session) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to do redo log batch replay in parallel");
            return OG_ERROR;
        }
    } else {
        if (dtc_rcy_process_batches(session) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to do redo log batch replay");
            return OG_ERROR;
        }
    }

    return dtc_rcy_rbp_check_tail_replay_complete(session, "RBP finish");
}

static void dtc_rcy_rbp_prepare_redo_fallback(knl_session_t *session, const char *reason)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    log_context_t *redo = &session->kernel->redo_ctx;

    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] fallback to ordinary redo: reason=%s used=%u saved_max_lrp_valid=%u "
                   "saved_max_lrp_lsn=%llu current_max_lrp_lsn=%llu",
                   (reason == NULL) ? "unknown" : reason, (uint32)dtc_rcy->rbp_redo_fallback_used,
                   (uint32)dtc_rcy->rbp_saved_max_lrp_valid, (uint64)dtc_rcy->rbp_saved_max_lrp_lsn,
                   (uint64)session->kernel->rcy_ctx.max_lrp_lsn);
    dtc_rcy->rbp_redo_fallback_used = OG_TRUE;

    rbp_knl_abort_dtc_read(session);
    redo->rcy_with_rbp = OG_FALSE;
    redo->last_rcy_with_rbp = OG_FALSE;
    if (dtc_rcy->rbp_saved_max_lrp_valid) {
        session->kernel->rcy_ctx.max_lrp_lsn = dtc_rcy->rbp_saved_max_lrp_lsn;
    }
    dtc_rcy_rbp_reset_state(dtc_rcy);
    dtc_rcy_rbp_partial_reset_required_cache(&dtc_rcy->rbp_partial_ctx);
    dtc_rcy_next_phase(session);
    rbp_knl_clear_dtc_fallback(session);
    cm_reset_error();
}

static status_t dtc_rcy_partial_recovery(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *stat = &dtc_rcy->rcy_stat;
    reform_detail_t *rf_detail = &g_dtc->rf_ctx.reform_detail;
    stat->last_rcy_is_full_recovery = OG_FALSE;
    knl_session_t *se = session->kernel->sessions[SESSION_ID_KERNEL];
    status_t replay_status;

    dtc_rcy->recovery_status = RECOVERY_ANALYSIS;
    RC_STEP_BEGIN(rf_detail->recovery_set_create_elapsed);
    if (dtc_rcy_analyze_batches_runtime(session) != OG_SUCCESS &&
        dtc_rcy_analyze_batches_paral(session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY][partial recovery] failed to paral analyze redo logs, dtc_rcy->failed=%u, "
                       "dtc_rcy->ss->canceled=%u",
                       dtc_rcy->failed, dtc_rcy->ss->canceled);
        RC_STEP_END(rf_detail->recovery_set_create_elapsed, RC_STEP_FAILED);
        return OG_ERROR;
    }
    RC_STEP_END(rf_detail->recovery_set_create_elapsed, RC_STEP_FINISH);

    dtc_rcy_set_num_stat();

    // send recovery set to each alive node and wait for response
    RC_STEP_BEGIN(rf_detail->recovery_set_revise_elapsed);
    if (dtc_send_rcy_set(session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY][partial recovery] failed to send rcy set to each master");
        RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
        return OG_ERROR;
    }

    // wait for response from alive nodes
    while (dtc_rcy->phase != PHASE_HANDLE_RCYSET_DONE) {
        if (dtc_rcy_check_rcyset_msg(session) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("DTC RCY] failed to check rcyset msg");
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            return OG_ERROR;
        }
        cm_sleep(10);
        if (session->canceled) {
            OG_LOG_RUN_ERR("[DTC RCY] rcy session is cancled, session->id=%u", session->id);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            OG_THROW_ERROR(ERR_OPERATION_CANCELED);
            return OG_ERROR;
        }

        if (session->killed) {
            OG_LOG_RUN_ERR("[DTC RCY] rcy session is cancled, session->id=%u", session->id);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }

        // check whether need to cancel this task
        if (dtc_rcy->canceled) {
            session->canceled = OG_TRUE;
            OG_LOG_RUN_ERR("[DTC RCY] required to cancel this dtc recovery task, session canceled=%u",
                           session->canceled);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            return OG_ERROR;
        }

        if (dtc_rcy->failed == OG_TRUE) {
            OG_LOG_RUN_ERR("[DTC RCY] check dtc_rcy->failed=%u", dtc_rcy->failed);
            RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FAILED);
            return OG_ERROR;
        }
    }
    RC_STEP_END(rf_detail->recovery_set_revise_elapsed, RC_STEP_FINISH);
    OG_LOG_RUN_INF("[DTC RCY][partial recovery] wait masters send rcy set results successfully, msg_sent=%u, "
                   "msg_recv=%u, dtc_rcy->phase=%u",
                   dtc_rcy->msg_sent, dtc_rcy->msg_recv, dtc_rcy->phase);

    // move partial recovery to next phase
    dtc_rcy_next_phase(session);

    OG_LOG_RUN_WAR("[DTC RCY][RBP][partial] call rbp prepare before replay: phase=%u node_count=%u "
                   "side_table=%u USE_RBP=%u RBP_FOR_RECOVERY=%u",
                   (uint32)dtc_rcy->phase, dtc_rcy->node_count,
                   (uint32)dtc_rcy->rbp_partial_ctx.enabled,
                   (uint32)KNL_RBP_ENABLE(session->kernel),
                   (uint32)KNL_RBP_FOR_RECOVERY(session->kernel));
    if (dtc_rcy_rbp_prepare(session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY][RBP][partial] rbp prepare failed before partial replay");
        rbp_knl_abort_dtc_read(session);
        return OG_ERROR;
    }

    uint64 rcy_disk_read_time = se->stat->disk_read_time;
    uint64 rcy_disk_read = se->stat->disk_reads;
    uint64 rcy_record_page = 0;
    rcy_set_t *rcy_set = &dtc_rcy->rcy_set;
    for (uint32 i = 0; i < rcy_set->bucket_num; i++) {
        rcy_record_page += rcy_set->buckets[i].count;
    }

    // start real recovery task using recovery set
    RC_STEP_BEGIN(rf_detail->recovery_replay_elapsed);
    for (;;) {
        replay_status = dtc_rcy_partial_replay_once(session);

        if (replay_status == OG_SUCCESS && KNL_RECOVERY_WITH_RBP(session->kernel)) {
            rbp_knl_finish_dtc_read(session);
            if (rbp_knl_dtc_fallback_required(session)) {
                replay_status = OG_ERROR;
            }
        }

        if (replay_status == OG_SUCCESS) {
            if (dtc_recover_check(session) == OG_SUCCESS) {
                break;
            }
            OG_LOG_RUN_ERR("[DTC RCY][partial recovery] failed to check dtc recovery rcy point");
            if (session->kernel->redo_ctx.last_rcy_with_rbp && !dtc_rcy->rbp_redo_fallback_used) {
                rbp_knl_mark_dtc_fallback(session, OG_INVALID_ID32, RBP_READ_RESULT_ERROR,
                                          RBP_DTC_FALLBACK_RECOVER_CHECK);
                replay_status = OG_ERROR;
            } else {
                RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
                return OG_ERROR;
            }
        }

        if (replay_status != OG_SUCCESS && rbp_knl_dtc_fallback_required(session) &&
            !dtc_rcy->rbp_redo_fallback_used) {
            dtc_rcy_rbp_prepare_redo_fallback(session, "RBP application failed");
            continue;
        }

        if (KNL_RECOVERY_WITH_RBP(session->kernel)) {
            rbp_knl_abort_dtc_read(session);
        }
        RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FAILED);
        return OG_ERROR;
    }
    RC_STEP_END(rf_detail->recovery_replay_elapsed, RC_STEP_FINISH);
    if (dtc_rcy->paral_rcy) {
        session->kernel->rcy_ctx.rcy_end = OG_TRUE;
    }

    OG_LOG_RUN_INF("[DTC RCY] finish redo replay, session lsn=%llu", ((knl_session_t *)g_rc_ctx->session)->kernel->lsn);

    if (rc_set_redo_replay_done(g_rc_ctx->session, &(g_rc_ctx->info), OG_FALSE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to broadcast reform status g_rc_ctx->status=%u", g_rc_ctx->status);
    }

    rcy_disk_read_time = se->stat->disk_read_time - rcy_disk_read_time;
    rcy_disk_read = se->stat->disk_reads - rcy_disk_read;

    OG_LOG_RUN_INF("[DTC RCY] kernel session read page num=%llu, total time(s)=%llu, ave_time(us)=%llu", rcy_disk_read,
                   rcy_disk_read_time / MICROSECS_PER_SECOND,
                   (rcy_disk_read == 0 ? 0 : rcy_disk_read_time / rcy_disk_read));
    OG_LOG_RUN_INF("[DTC RCY] recovery set create time(us)=%llu, recovery set revise time(us)=%llu. recovery replay "
                   "time(us)=%llu",
                   (uint64)rf_detail->recovery_set_create_elapsed.cost_time,
                   (uint64)rf_detail->recovery_set_revise_elapsed.cost_time,
                   (uint64)rf_detail->recovery_replay_elapsed.cost_time);
    OG_LOG_RUN_INF("[DTC RCY] recovery set record page=%llu, recovery redo log size(M)=%llu", rcy_record_page,
                   stat->last_rcy_log_size / SIZE_M(1));

    ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_INC);
    OG_LOG_RUN_INF("[DTC RCY][partial recovery] trigger inc ckpt");

    dtc_rcy_update_ckpt_prcy_info(session);

    return OG_SUCCESS;
}

static status_t dtc_rcy_proc(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    status_t status;

    OG_LOG_RUN_WAR("[DTC RCY] dtc_rcy_proc ENTER full_recovery=%u phase=%u node_count=%u clustered=%u",
                   (uint32)dtc_rcy->full_recovery, (uint32)dtc_rcy->phase, dtc_rcy->node_count,
                   (uint32)DB_IS_CLUSTER(session));

    if (dtc_rcy->full_recovery) {
        status = dtc_rcy_full_recovery(session);
    } else {
        status = dtc_rcy_partial_recovery(session);
    }

    OG_LOG_RUN_INF("[DTC RCY] dtc_rcy_proc, dtc_rcy->failed=%u, dtc_rcy->ss->canceled=%u, dtc_rcy->recovery_status=%u,"
                   "memory usage in bytes=%lu",
                   dtc_rcy->failed, dtc_rcy->ss->canceled, dtc_rcy->recovery_status, cm_print_memory_usage());
    dtc_rcy->failed = (bool32)(status == OG_ERROR);
    dtc_rcy->recovery_status = status == OG_ERROR ? dtc_rcy->recovery_status : RECOVERY_FINISH;
    dtc_rcy->ss->canceled = dtc_rcy->failed ? OG_TRUE : OG_FALSE;

    if (!DB_IS_PRIMARY(&session->kernel->db) && dtc_rcy->full_recovery && status == OG_SUCCESS) {
        lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
        lrpl->is_done = OG_TRUE;
    }

    dtc_recovery_close(session);
    OG_LOG_RUN_INF("[DTC RCY] dtc_rcy_proc, dtc_rcy->failed=%u, dtc_rcy->ss->canceled=%u, dtc_rcy->recovery_status=%u,"
                   "memory usage in bytes=%lu",
                   dtc_rcy->failed, dtc_rcy->ss->canceled, dtc_rcy->recovery_status, cm_print_memory_usage());
    return status;
}

static void dtc_rcy_thread_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    if (dtc_rcy_proc(session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] dtc_rcy_proc failed");
    }
}

dtc_rcy_phase_e dtc_rcy_get_recover_phase(knl_session_t *session, bool32 full_recovery)
{
    if (full_recovery) {
        if (session->kernel->db.recover_for_restore) {
            return PHASE_ANALYSIS;
        } else {
            return PHASE_RECOVERY;
        }
    } else {
        return PHASE_ANALYSIS;
    }
}

static status_t dtc_rcy_init_context(knl_session_t *session, dtc_rcy_context_t *dtc_rcy, uint32 count,
                                     bool32 full_recovery)
{
    errno_t ret;

    knl_panic(count <= OG_MAX_INSTANCES);
    dtc_rcy->curr_node_idx = OG_INVALID_ID8;
    dtc_rcy->curr_node = OG_INVALID_ID8;
    dtc_rcy->curr_blk_size = OG_INVALID_ID16;
    dtc_rcy->curr_batch_lsn = OG_INVALID_ID64;
    dtc_rcy->end_lsn_restore_recovery = OG_INVALID_ID64;
    dtc_rcy->full_recovery = full_recovery;
    dtc_rcy->phase = dtc_rcy_get_recover_phase(session, full_recovery);
    dtc_rcy->replay_thread_num = session->kernel->attr.log_replay_processes;
    dtc_rcy->canceled = OG_FALSE;
    dtc_rcy->failed = OG_FALSE;
    dtc_rcy->is_end_restore_recover = OG_FALSE;
    dtc_rcy->need_analysis_leave_page_cnt = 0;
    dtc_rcy->node_count = count;
    dtc_rcy->msg_sent = 0;
    dtc_rcy->msg_recv = 0;
    dtc_rcy->paral_rcy_size = 0;
    dtc_rcy->paral_rcy = (dtc_rcy->replay_thread_num > 1);
    dtc_rcy->rcy_set_ref_num = 0;
    dtc_rcy->pcn_is_equal_num = 0;
    dtc_rcy->pcn_diag_analyze_path = DTC_PCND_ANALYZE_NONE;
    dtc_rcy->pcn_diag_rbp_prepare = DTC_PCND_RBP_PREP_NONE;
    dtc_rcy->pcn_diag_redo_end_lfn_snapshot = 0;
    dtc_rcy->pcn_diag_rbp_rcy_lfn_snapshot = 0;
    dtc_rcy->pcn_diag_rcy_with_rbp_after_prepare = 0;
    dtc_rcy->rbp_redo_fallback_used = OG_FALSE;
    dtc_rcy->rbp_saved_max_lrp_valid = OG_FALSE;
    dtc_rcy->rbp_fallback_reserved = 0;
    dtc_rcy->rbp_saved_max_lrp_lsn = 0;
    session->kernel->redo_ctx.rcy_with_rbp = OG_FALSE;
    session->kernel->redo_ctx.last_rcy_with_rbp = OG_FALSE;
    rbp_knl_clear_dtc_fallback(session);
    ret = memset_sp(&dtc_rcy->rbp_partial_ctx, sizeof(dtc_rcy->rbp_partial_ctx), 0,
                    sizeof(dtc_rcy->rbp_partial_ctx));
    knl_securec_check(ret);
    ret = memset_sp(dtc_rcy->rbp_partial_jump_disabled, sizeof(dtc_rcy->rbp_partial_jump_disabled), 0,
                    sizeof(dtc_rcy->rbp_partial_jump_disabled));
    knl_securec_check(ret);
    dtc_rcy->rbp_partial_disabled_count = 0;
    dtc_rcy->rcy_nodes = (dtc_rcy_node_t *)malloc(count * sizeof(dtc_rcy_node_t));
    if (dtc_rcy->rcy_nodes == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, count * sizeof(dtc_rcy_node_t), "dtc recovery nodes");
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc memory for crashed nodes");
        // free memory in dtc_recovery_close
        return OG_ERROR;
    }
    ret = memset_sp(dtc_rcy->rcy_nodes, count * sizeof(dtc_rcy_node_t), 0, count * sizeof(dtc_rcy_node_t));
    knl_securec_check(ret);
    ret = memset_s(dtc_rcy->rcy_create_users, sizeof(dtc_rcy->rcy_create_users), 0, sizeof(dtc_rcy->rcy_create_users));
    knl_securec_check(ret);
    if (full_recovery) {
        session->dtc_session_type = dtc_rcy->paral_rcy ? DTC_FULL_RCY_PARAL : DTC_FULL_RCY;
    } else {
        session->dtc_session_type = dtc_rcy->paral_rcy ? DTC_PART_RCY_PARAL : DTC_PART_RCY;
    }

    return OG_SUCCESS;
}

static void dtc_rcy_update_rcy_stat(knl_session_t *session, instance_list_t *recover_list, uint32 idx, uint8 node_id,
                                    dtc_node_ctrl_t *node_ctrl)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy_stat_t *rcy_stat = &dtc_rcy->rcy_stat;

    rcy_stat->rcy_log_points[idx].node_id = node_id;
    rcy_stat->rcy_log_points[idx].rcy_point = node_ctrl->rcy_point;
    rcy_stat->rcy_log_points[idx].lrp_point = node_ctrl->lrp_point;
    rcy_stat->rcy_log_points[idx].curr_read_rcy_point = node_ctrl->rcy_point;
    return;
}

static void dtc_init_node(dtc_rcy_node_t *rcy_node, reform_rcy_node_t *rcy_log_point, dtc_node_ctrl_t *ctrl,
                          uint8 node_id)
{
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    rcy_node->node_id = node_id;
    rcy_node->pitr_lfn = ctrl->lrp_point.lfn;
    rcy_node->ddl_lsn_pitr = OG_INVALID_ID64;
    rcy_node->arch_file.handle = OG_INVALID_HANDLE;
    rcy_node->ulog_exist_data = OG_TRUE;
    rcy_node->curr_file_length = 0;
    rcy_node->latest_lsn = 0;
    rcy_node->latest_rcy_end_lsn = 0;

    rcy_log_point->node_id = node_id;
    rcy_log_point->lsn = ctrl->lsn;
    rcy_log_point->rcy_point = ctrl->rcy_point;
    rcy_log_point->rcy_point_saved = ctrl->rcy_point;
    rcy_log_point->rcy_write_point = ctrl->rcy_point;

    rcy_node->read_buf_read_index = 0;
    rcy_node->read_buf_write_index = 0;
    rcy_node->read_buf = (aligned_buf_t *)malloc(read_buf_size * sizeof(aligned_buf_t));
    rcy_node->read_pos = (uint32 *)malloc(read_buf_size * sizeof(uint32));
    rcy_node->write_pos = (uint32 *)malloc(read_buf_size * sizeof(uint32));
    rcy_node->read_buf_ready = (bool32 *)malloc(read_buf_size * sizeof(bool32));
    rcy_node->read_size = (uint32 *)malloc(read_buf_size * sizeof(uint32));
    rcy_node->not_finished = (bool32 *)malloc(read_buf_size * sizeof(bool32));
    if (rcy_node->read_buf == NULL || rcy_node->read_pos == NULL || rcy_node->write_pos == NULL ||
        rcy_node->read_buf_ready == NULL || rcy_node->read_size == NULL || rcy_node->not_finished == NULL) {
        CM_ABORT(0, "[DTC RCY] alloc memory failed");
    }
    for (int i = 0; i < read_buf_size; ++i) {
        rcy_node->write_pos[i] = 0;
        rcy_node->read_pos[i] = 0;
        rcy_node->read_buf_ready[i] = OG_FALSE;
        rcy_node->read_size[i] = OG_INVALID_ID32;
        rcy_node->not_finished[i] = OG_TRUE;
    }
}

static status_t dtc_rcy_init_rcynode(knl_session_t *session, instance_list_t *recover_list, uint32 idx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_node_ctrl_t *ctrl = NULL;
    dtc_rcy_node_t *rcy_node = NULL;
    reform_rcy_node_t *rcy_log_point = NULL;
    uint8 node_id = recover_list->inst_id_list[idx];
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    if (dtc_read_node_ctrl(session, node_id) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to read ctrl page for crashed node=%u", node_id);
        return OG_ERROR;
    }
    bool32 is_dbstor = cm_dbs_is_enable_dbs();
    ctrl = dtc_get_ctrl(session, node_id);
    rcy_log_point = &dtc_rcy->rcy_log_points[idx];
    rcy_node = &dtc_rcy->rcy_nodes[idx];
    dtc_init_node(rcy_node, rcy_log_point, ctrl, node_id);

    dtc_update_scn(session, ctrl->scn);
    dtc_update_lsn(session, ctrl->lsn);

    if (is_dbstor && session->kernel->db.recover_for_restore) {
        rcy_log_point->rcy_point.asn = 0;
        rcy_log_point->rcy_point.block_id = OG_INFINITE32;
        rcy_log_point->rcy_write_point.asn = 0;
        rcy_log_point->rcy_write_point.block_id = OG_INFINITE32;
    }

    int64 lgwr_buf_size = (int64)LOG_LGWR_BUF_SIZE(session);
    // 调整DBStor部署方式时备站点单次读写redo日志大小
    int64 size = (is_dbstor && !DB_IS_PRIMARY(&session->kernel->db)) ? MAX(DBSTOR_LOG_SEGMENT_SIZE, lgwr_buf_size)
                                                                     : lgwr_buf_size;
    for (int i = 0; i < read_buf_size; ++i) {
        if (cm_aligned_malloc(size, "dtc rcy read buffer", &rcy_node->read_buf[i]) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to alloc log read buffer for crashed node=%u", node_id);
            // free memory in dtc_recovery_close
            return OG_ERROR;
        }
    }

    errno_t ret = memset_sp(rcy_node->handle, sizeof(rcy_node->handle), OG_INVALID_HANDLE, sizeof(rcy_node->handle));
    knl_securec_check(ret);

    dtc_rcy_update_rcy_stat(session, recover_list, idx, node_id, ctrl);
    OG_LOG_RUN_INF("[DTC RCY] Recover instance=%u from point [%u-%u/%u/%llu/%llu/%llu][%u/%u/%llu/%llu]", node_id,
                   ctrl->rcy_point.rst_id, ctrl->rcy_point.asn, ctrl->rcy_point.block_id, (uint64)ctrl->rcy_point.lfn,
                   ctrl->rcy_point.lsn, ctrl->lsn, ctrl->lrp_point.asn, ctrl->lrp_point.block_id,
                   (uint64)ctrl->lrp_point.lfn, ctrl->lrp_point.lsn);
    return OG_SUCCESS;
}

static status_t dtc_rcy_init_rcyset(rcy_set_t *rcy_set)
{
    rcy_set->bucket_num = OG_RCY_SET_BUCKET;
    rcy_set->capacity = OG_RCY_SET_BUCKET * RCY_SET_BUCKET_TIMES;

    uint64 bucket_size = sizeof(rcy_set_bucket_t) * rcy_set->bucket_num;
    // free in dtc_rcy_close
    rcy_set->buckets = (rcy_set_bucket_t *)malloc(bucket_size);
    if (rcy_set->buckets == NULL) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc dtc recovery rcyset bucket");
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, bucket_size, "dtc recovery set bucket");
        return OG_ERROR;
    }
    errno_t ret = memset_sp(rcy_set->buckets, bucket_size, 0, bucket_size);
    knl_securec_check(ret);

    // free in dtc_rcy_close
    rcy_set->item_pools = dtc_rcy_alloc_itempool(rcy_set);
    if (rcy_set->item_pools == NULL) {
        CM_FREE_PTR(rcy_set->buckets);
        OG_LOG_RUN_ERR("[DTC RCY] failed to alloc dtc recovery rcyset itmepool");
        return OG_ERROR;
    }
    rcy_set->curr_item_pools = rcy_set->item_pools;
    ret = memset_sp(rcy_set->space_id_set, sizeof(rcy_set->space_id_set), OG_INVALID_ID32,
                    sizeof(rcy_set->space_id_set));
    knl_securec_check(ret);
    rcy_set->space_set_size = 0;
    return OG_SUCCESS;
}

static status_t dtc_rcy_init_replay_proc(knl_session_t *session, dtc_rcy_context_t *dtc_rcy)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    if (!dtc_rcy->paral_rcy) {
        OG_LOG_RUN_INF("[DTC RCY] use single thread to replay.");
        return OG_SUCCESS;
    }

    if (rcy_init_context(session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to init rcy context");
        return OG_ERROR;
    }

    rcy_init_proc(session);

    rcy->curr_group = rcy->group_list;
    if (rcy->paral_rcy == OG_FALSE) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to create paral replay thread");
        return OG_ERROR;
    } else {
        OG_LOG_RUN_INF("[DTC RCY] expected number of created threads=%u, actual number of created threads=%u",
                       dtc_rcy->replay_thread_num, rcy->capacity);
        dtc_rcy->replay_thread_num = rcy->capacity;
        return OG_SUCCESS;
    }
}

static inline void dtc_free_read_buf(uint32 index)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    for (int k = 0; k < read_buf_size; k++) {
        cm_aligned_free(&dtc_rcy->rcy_nodes[index].read_buf[k]);
    }
}

static status_t init_paral_mgr()
{
    uint32 prarl_buf_list_size = g_instance->kernel.attr.dtc_rcy_paral_buf_list_size;
    g_analyze_paral_mgr.free_list.array = (uint32 *)malloc(prarl_buf_list_size * sizeof(uint32));
    g_analyze_paral_mgr.used_list.array = (uint32 *)malloc(prarl_buf_list_size * sizeof(uint32));
    g_analyze_paral_mgr.buf_list = (aligned_buf_t *)malloc(prarl_buf_list_size * sizeof(aligned_buf_t));
    g_analyze_paral_mgr.node_ids = (uint32 *)malloc(prarl_buf_list_size * sizeof(uint32));
    g_analyze_paral_mgr.batch_points = (log_point_t *)malloc(prarl_buf_list_size * sizeof(log_point_t));
    g_replay_paral_mgr.buf_list = (aligned_buf_t *)malloc(prarl_buf_list_size * sizeof(aligned_buf_t));
    g_replay_paral_mgr.group_list = (aligned_buf_t *)malloc(prarl_buf_list_size * sizeof(aligned_buf_t));
    g_replay_paral_mgr.group_num = (atomic32_t *)malloc(prarl_buf_list_size * sizeof(atomic32_t));
    g_replay_paral_mgr.batch_scn = (knl_scn_t *)malloc(prarl_buf_list_size * sizeof(knl_scn_t));
    g_replay_paral_mgr.node_id = (uint32 *)malloc(prarl_buf_list_size * sizeof(uint32));
    g_replay_paral_mgr.batch_rpl_start_time = (date_t *)malloc(prarl_buf_list_size * sizeof(date_t));
    g_replay_paral_mgr.free_list.array = (uint32 *)malloc(prarl_buf_list_size * sizeof(uint32));
    if (g_analyze_paral_mgr.free_list.array == NULL || g_analyze_paral_mgr.buf_list == NULL ||
        g_analyze_paral_mgr.node_ids == NULL || g_analyze_paral_mgr.batch_points == NULL ||
        g_replay_paral_mgr.buf_list == NULL || g_replay_paral_mgr.group_list == NULL ||
        g_replay_paral_mgr.group_num == NULL || g_replay_paral_mgr.batch_scn == NULL ||
        g_replay_paral_mgr.node_id == NULL || g_replay_paral_mgr.batch_rpl_start_time == NULL ||
        g_replay_paral_mgr.free_list.array == NULL || g_analyze_paral_mgr.used_list.array == NULL) {
        CM_ABORT(0, "[DTC RCY] alloc memory failed");
    }
    MEMS_RETURN_IFERR(memset_sp(g_analyze_paral_mgr.free_list.array, prarl_buf_list_size * sizeof(uint32), 0,
                                prarl_buf_list_size * sizeof(uint32)));
    MEMS_RETURN_IFERR(memset_sp(g_analyze_paral_mgr.used_list.array, prarl_buf_list_size * sizeof(uint32), 0,
                                prarl_buf_list_size * sizeof(uint32)));
    MEMS_RETURN_IFERR(memset_sp(g_analyze_paral_mgr.buf_list, prarl_buf_list_size * sizeof(aligned_buf_t), 0,
                                prarl_buf_list_size * sizeof(aligned_buf_t)));
    MEMS_RETURN_IFERR(memset_sp(g_analyze_paral_mgr.node_ids, prarl_buf_list_size * sizeof(uint32), 0,
                                prarl_buf_list_size * sizeof(uint32)));
    MEMS_RETURN_IFERR(memset_sp(g_analyze_paral_mgr.batch_points, prarl_buf_list_size * sizeof(log_point_t), 0,
                                prarl_buf_list_size * sizeof(log_point_t)));
    MEMS_RETURN_IFERR(memset_sp(g_replay_paral_mgr.buf_list, prarl_buf_list_size * sizeof(aligned_buf_t), 0,
                                prarl_buf_list_size * sizeof(aligned_buf_t)));
    MEMS_RETURN_IFERR(memset_sp(g_replay_paral_mgr.group_list, prarl_buf_list_size * sizeof(aligned_buf_t), 0,
                                prarl_buf_list_size * sizeof(aligned_buf_t)));
    MEMS_RETURN_IFERR(memset_sp((void *)g_replay_paral_mgr.group_num, prarl_buf_list_size * sizeof(atomic32_t), 0,
                                prarl_buf_list_size * sizeof(atomic32_t)));
    MEMS_RETURN_IFERR(memset_sp(g_replay_paral_mgr.batch_scn, prarl_buf_list_size * sizeof(knl_scn_t), 0,
                                prarl_buf_list_size * sizeof(knl_scn_t)));
    MEMS_RETURN_IFERR(memset_sp(g_replay_paral_mgr.node_id, prarl_buf_list_size * sizeof(uint32), 0,
                                prarl_buf_list_size * sizeof(uint32)));
    MEMS_RETURN_IFERR(memset_sp(g_replay_paral_mgr.batch_rpl_start_time, prarl_buf_list_size * sizeof(date_t), 0,
                                prarl_buf_list_size * sizeof(date_t)));
    MEMS_RETURN_IFERR(memset_sp(g_replay_paral_mgr.free_list.array, prarl_buf_list_size * sizeof(uint32), 0,
                                prarl_buf_list_size * sizeof(uint32)));

    return OG_SUCCESS;
}

static status_t dtc_recovery_init(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    uint32 count = recover_list->inst_id_count;
    uint32 read_buf_size = g_instance->kernel.attr.rcy_node_read_buf_size;
    if (init_paral_mgr() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to init paral mgr");
        free_paral_mgr();
        return OG_ERROR;
    }

    dtc_rcy_init_last_recovery_stat(recover_list);
    cm_reset_error();
    if (dtc_rcy_init_context(session, dtc_rcy, count, full_recovery) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RCY] failed to init dtc recovery context");
        return OG_ERROR;
    }

    if (dtc_rcy_init_replay_proc(session, dtc_rcy) != OG_SUCCESS) {
        CM_FREE_PTR(dtc_rcy->rcy_nodes);  // free memory malloced in dtc_rcy_init_context
        OG_LOG_RUN_ERR("[DTC RCY] failed to init dtc recovery replay proc");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < count; i++) {
        if (dtc_rcy_init_rcynode(session, recover_list, i) != OG_SUCCESS) {
            // release memory malloced in dtc_rcy_init_rcynode
            for (uint32 j = 0; j < i; j++) {
                dtc_free_read_buf(j);
            }
            CM_FREE_PTR(dtc_rcy->rcy_nodes);  // free memory malloced in dtc_rcy_init_context
            // free memory and session malloced in dtc_rcy_init_replay_proc
            if (dtc_rcy->paral_rcy) {
                rcy_close_proc(session);
                rcy_free_buffer(&session->kernel->rcy_ctx);
            }

            OG_LOG_RUN_ERR("[DTC RCY] failed to init rcynode");
            return OG_ERROR;
        }
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, i);
            ckpt_set_trunc_point_slave_role(session, &ctrl->rcy_point, i);
        }
    }

    // init the recovery set
    if (dtc_rcy_init_rcyset(&dtc_rcy->rcy_set) != OG_SUCCESS) {
        // release memory malloced in dtc_rcy_init_rcynode
        for (uint32 i = 0; i < count; i++) {
            for (int k = 0; k < read_buf_size; k++) {
                cm_aligned_free(&dtc_rcy->rcy_nodes[i].read_buf[k]);
            }
        }
        CM_FREE_PTR(dtc_rcy->rcy_nodes);  // free memory malloced in dtc_rcy_init_context
        // free memory and session malloced in dtc_rcy_init_replay_proc
        if (dtc_rcy->paral_rcy) {
            rcy_close_proc(session);
            rcy_free_buffer(&session->kernel->rcy_ctx);
        }

        OG_LOG_RUN_ERR("[DTC RCY] failed to init recovery set");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static void dtc_recovery_from_double_write_area(knl_session_t *session, reform_info_t *reform_info)
{
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    if (ogx->double_write != OG_TRUE) {
        OG_LOG_RUN_INF("Double write is disabled(%u), do NOT recovery from double write area.", ogx->double_write);
        return;
    }
    ckpt_disable(session);
    for (uint32 i = 0; i < reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
        ckpt_recover_partial_write_node(session, reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list[i]);
    }
    ogx->dw_ckpt_start = dtc_my_ctrl(session)->dw_start;
    ogx->dw_ckpt_end = dtc_my_ctrl(session)->dw_end;
    ckpt_enable(session);
}

status_t dtc_recover_crashed_nodes(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rcy->ss = session;
    dtc_rcy->recovery_status = RECOVERY_INIT;
    if (!full_recovery) {
        if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&dtc_rcy->ss) != OG_SUCCESS) {
            dtc_rcy->in_progress = OG_FALSE;
            dtc_rcy->failed = OG_TRUE;
            OG_LOG_RUN_ERR("[DTC RCY] failed to alloc knernel session for partial recovery, "
                           "dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, dtc_rcy->in_progress=%u",
                           dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress);
            return OG_ERROR;
        }
    }

    status_t status = OG_SUCCESS;
    SYNC_POINT_GLOBAL_START(OGRAC_RECOVERY_INIT_FAIL, &status, OG_ERROR);
    status = dtc_recovery_init(dtc_rcy->ss, recover_list, full_recovery);
    SYNC_POINT_GLOBAL_END;
    if (status != OG_SUCCESS) {
        dtc_rcy->in_progress = OG_FALSE;
        dtc_rcy->failed = OG_TRUE;
        dtc_rcy->ss->dtc_session_type = DTC_TYPE_NONE;
        OG_LOG_RUN_ERR("[DTC RCY] failed to init dtc recovery. dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, "
                       "dtc_rcy->in_progress=%u",
                       dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress);
        return OG_ERROR;
    }
    if (!full_recovery) {
        rbp_suspend_page_write_for_partial_recovery(dtc_rcy->ss);
    }
    if (!DB_IS_PRIMARY(&session->kernel->db) && rc_is_master()) {
        ckpt_enable(session);
        OG_LOG_RUN_INF("ckpt enabled");
    }

    if (dtc_rcy->canceled) {
        dtc_recovery_close(session);
        dtc_rcy->failed = OG_TRUE;
        OG_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, "
                       "dtc_rcy->in_progress=%u",
                       dtc_rcy->canceled, dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress);
    }

    // recovery from doublewrite
    dtc_recovery_from_double_write_area(g_rc_ctx->session, &g_rc_ctx->info);

    if (dtc_rcy->canceled) {
        dtc_recovery_close(session);
        dtc_rcy->failed = OG_TRUE;
        OG_LOG_RUN_INF("[DTC RCY] dtc_rcy canceled=%u, dtc_rcy->recovery_status=%u, dtc_rcy->failed=%u, "
                       "dtc_rcy->in_progress=%u",
                       dtc_rcy->canceled, dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress);
    }

    if (full_recovery) {
        /* reform/crash 全量恢复同步执行 dtc_rcy_proc。 */
        OG_LOG_DEBUG_INF("[DTC RCY] dtc_recover_crashed_nodes calling dtc_rcy_proc (full_recovery=1)");
        // No need to start thread to execute the recovery task.
        status = dtc_rcy_proc(dtc_rcy->ss);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY] failed to do full recovery");
        }
    } else {
        OG_LOG_DEBUG_INF("[DTC RCY] dtc_recover_crashed_nodes starting thread dtc_rcy_proc (full_recovery=0) "
                       "node_count=%u",
                       DTC_RCY_CONTEXT->node_count);
        OG_LOG_RUN_INF("[DTC RCY][partial recovery] start paral redo replay, session->kernel->lsn=%llu",
                       session->kernel->lsn);
        status = cm_create_thread(dtc_rcy_thread_proc, 0, dtc_rcy->ss, &DTC_RCY_CONTEXT->thread);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RCY][partial recovery], failed to create rcy_thread_proc");
            dtc_rcy->failed = OG_TRUE;
            dtc_recovery_close(session);
        }
    }

    return status;
}

status_t dtc_start_recovery(knl_session_t *session, instance_list_t *recover_list, bool32 full_recovery)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    cm_spin_lock(&dtc_rcy->lock, NULL);
    if (dtc_rcy->in_progress) {
        cm_spin_unlock(&dtc_rcy->lock);
        OG_LOG_RUN_ERR("[DTC RCY] failed to start recovery task because another one is already in progress");
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ", another DTC recovery is already in progress");
        return OG_ERROR;
    }
    dtc_rcy->in_progress = OG_TRUE;
    cm_spin_unlock(&dtc_rcy->lock);

    return dtc_recover_crashed_nodes(session, recover_list, full_recovery);
}

bool32 dtc_recovery_in_progress(void)
{
    if (DTC_RCY_CONTEXT->failed) {
        return OG_FALSE;
    }
    return DTC_RCY_CONTEXT->in_progress;
}

bool32 dtc_recovery_need_stop(void)
{
    if (DTC_RCY_CONTEXT->failed || DTC_RCY_CONTEXT->in_progress) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

bool32 dtc_recovery_failed(void)
{
    return DTC_RCY_CONTEXT->failed;
}

void dtc_stop_recovery(void)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    OG_LOG_RUN_INF("[DTC RCY] last recovery status=%u, dtc_rcy->failed=%u, dtc_rcy->in_progress=%u, "
                   "dtc_rcy->canceled=%u, dtc_rcy->ss->canceled=%u, dtc_rcy->ss->killed=%u",
                   dtc_rcy->recovery_status, dtc_rcy->failed, dtc_rcy->in_progress, dtc_rcy->canceled,
                   dtc_rcy->ss->canceled, dtc_rcy->ss->killed);

    if (dtc_rcy->failed) {
        CM_ABORT(0, "[DTC RCY] DTC RCY failed");
    }

    dtc_rcy->canceled = OG_TRUE;
    OG_LOG_RUN_INF("[DTC RCY] stop current running thread, dtc_rcy->in_progress %u", dtc_rcy->in_progress);
    while (dtc_recovery_in_progress()) {
        cm_sleep(DTC_RCY_WAIT_STOP_SLEEP_TIME);
        if (dtc_rcy->ss->canceled || dtc_rcy->ss->killed) {
            if (rc_is_master() && !dtc_rcy->full_recovery) {
                g_knl_callback.release_knl_session(dtc_rcy->ss);  // release partial recovery alloc session
            }
            return;
        }
    }
}

status_t dtc_recover(knl_session_t *session)
{
    dtc_node_ctrl_t *curr_ctrl = dtc_my_ctrl(session);
    log_point_t curr_point = curr_ctrl->rcy_point;
    log_point_t lrp_point = curr_ctrl->lrp_point;
    log_context_t *log = &session->kernel->redo_ctx;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;
    status_t status = OG_SUCCESS;

    log_reset_point(session, &lrp_point);
    ckpt_set_trunc_point(session, &curr_point);
    session->kernel->redo_ctx.lfn = curr_point.lfn;
    session->kernel->ckpt_ctx.trunc_lsn = (uint64)session->kernel->lsn;

    if (rc_is_master() == OG_TRUE) {
        // only master node is allowed to execute dtc recovery
        if (DB_IS_PRIMARY(&session->kernel->db) || DB_NOT_READY(session)) {
            g_rc_ctx->status = REFORM_RECOVERING;
        }
        instance_list_t *rcy_list = (instance_list_t *)cm_push(session->stack, sizeof(instance_list_t));
        rcy_list->inst_id_count = session->kernel->db.ctrl.core.node_count;
        for (uint8 i = 0; i < rcy_list->inst_id_count; i++) {
            rcy_list->inst_id_list[i] = i;
        }
        RC_STEP_BEGIN(rf_detail->recovery_elapsed);
        status = dtc_start_recovery(session, rcy_list, OG_TRUE);
        RC_STEP_END(rf_detail->recovery_elapsed, RC_STEP_FINISH);
    }

    if (DB_CLUSTER_NO_CMS) {
        g_rc_ctx->status = REFORM_DONE;
    }
    if (!cm_dbs_is_enable_dbs() && session->kernel->db.recover_for_restore) {
        dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
        for (uint32_t i = 0; i < session->kernel->db.ctrl.core.node_count; i++) {
            reform_rcy_node_t *rcy_log_point = &dtc_rcy->rcy_log_points[i];
            log_point_t *point = &rcy_log_point->rcy_point;
            OG_LOG_RUN_ERR("[DTC RCY] set first redo asn %u for node %u.", point->asn + 1, i);
            if (dtc_bak_reset_logfile(session, point->asn + 1, OG_INVALID_ID32, i) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[DTC RCY] set first redo asn %u for node %u failed.", point->asn + 1, i);
                return OG_ERROR;
            }
        }
    }
    /* update current trunc point and current point */
    log_reset_point(session, &curr_ctrl->rcy_point);
    ckpt_set_trunc_point(session, &curr_ctrl->rcy_point);
    log_reset_file(session, &curr_ctrl->rcy_point);

    //    DB_SET_LSN(session->kernel->db.ctrl.core.lsn, curr_ctrl->lsn);
    DB_SET_LFN(&log->lfn, curr_ctrl->rcy_point.lfn);

    // set next generate lfn equal to the previous lfn plus 1
    log->buf_lfn[0] = log->lfn + 1;
    log->buf_lfn[1] = log->lfn + 2;

    if (rc_is_master() == OG_TRUE) {
        cm_pop(session->stack);
    }

    return status;
}

status_t dtc_add_dirtypage_for_recovery(knl_session_t *session, page_id_t page_id)
{
    /* if a shared copy is chosen as owner during recovery, it has to be marked dirty and be flushed to disk,
       otherwise the shared copy page can't be recovered in below scenario:
        1) the shared copy page is removed from recovery set
        2) after recovery the redo log of crashed node is truncated
        3) later the partial recovery node crash afterwards.
    */
    buf_bucket_t *bucket = buf_find_bucket(session, page_id);
    cm_spin_lock_bucket(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t *ctrl = buf_find_from_bucket(bucket, page_id);
    if (!ctrl || ctrl->lock_mode == DRC_LOCK_NULL) {
        /* If the page is not in memory or lock mode is null, the partial recovery for that page can't be skipped,
           as the page on disk may be not the latest one. */
        cm_spin_unlock_bucket(&bucket->lock);
        OG_LOG_RUN_WAR("[DTC RCY] can't skip enter page [%u-%u] due to it's not in memory or not usable", page_id.file,
                       page_id.page);
        return OG_ERROR;
    }

    if (!ctrl->is_dirty) {
        ctrl->is_dirty = OG_TRUE;
        ckpt_enque_one_page(session, ctrl);
    }
    cm_spin_unlock_bucket(&bucket->lock);
    return OG_SUCCESS;
}

status_t dtc_init_node_logset_for_backup(knl_session_t *session, uint32 node_id, dtc_rcy_node_t *rcy_node,
                                         logfile_set_t *file_set)
{
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, node_id);
    database_t *db = &session->kernel->db;
    log_file_t *file = NULL;
    char *buf = rcy_node->read_buf[rcy_node->read_buf_read_index].aligned_buf;

    file_set->logfile_hwm = ctrl->log_hwm;
    file_set->log_count = ctrl->log_count;

    for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
        file = &file_set->items[i];
        file->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                             db->ctrl.log_segment, rcy_node->node_id);
        rcy_node->handle[i] = -1;

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }

        if (dtc_log_file_not_used(ctrl, i)) {
            dtc_init_not_used_log_file(file, db);
            continue;
        }

        if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(session), &rcy_node->handle[i]) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DB] failed to open redo log file=%s ", file->ctrl->name);
            return OG_ERROR;
        }
        if (cm_read_device(file->ctrl->type, rcy_node->handle[i], 0, buf,
                           CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DB] failed to open redo log file=%s ", file->ctrl->name);
            return OG_ERROR;
        }

        if (log_verify_head_checksum(session, (log_file_head_t *)buf, file->ctrl->name) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[BACKUP] failed to verify head checksum of log file=%s", file->ctrl->name);
            return OG_ERROR;
        }

        errno_t ret = memcpy_sp(&file->head, sizeof(log_file_head_t), buf, sizeof(log_file_head_t));
        knl_securec_check(ret);
        OG_LOG_RUN_INF("[BACKUP] Init logfile=%s, handle=%d, point=[%u-%u] write_pos=%llu for instance=%u",
                       file->ctrl->name, rcy_node->handle[i], file->head.rst_id, file->head.asn, file->head.write_pos,
                       rcy_node->node_id);
    }

    return OG_SUCCESS;
}
