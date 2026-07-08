/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Cantian is licensed under Mulan PSL v2.
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
 * knl_rbp.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_rbp.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdlib.h>
#include <string.h>
#include "knl_replication_module.h"
#include "cm_log.h"
#include "cm_thread.h"
#include "cm_hash.h"
#include "cm_debug.h"
#include "cm_file.h"
#include "cm_atomic.h"
#include "cm_error.h"
#include "knl_buflatch.h"
#include "knl_database.h"
#include "knl_recovery.h"
#include "dtc_recovery.h"
#include "dtc_database.h"
#include "dtc_context.h"
#include "dtc_drc.h"
#include "knl_rbp.h"

#ifdef __cplusplus
extern "C" {
#endif

static rbp_queue_item_t *rbp_remove_queue_item(knl_session_t *session, rbp_queue_t *queue,
                                               rbp_queue_item_t *prev, rbp_queue_item_t *item);
static void rbp_refresh_rbp_window(knl_session_t *session, uint32 rbp_proc_id);
static bool32 rbp_is_multi_node_rcy(knl_session_t *session);
static uint32 rbp_collect_active_rcy_nodes(knl_session_t *session, uint32 *node_ids, uint32 max_nodes);
static status_t rbp_init_connection(knl_session_t *session, rbp_buf_manager_t *rbp_buf_manager, const char *host,
                                    uint16 port, bool32 is_temp);
static status_t rbp_ensure_temp_connection_by_node(knl_session_t *session, rbp_buf_manager_t *manager, uint32 node_id);
static rbp_page_status_e rbp_eval_page_candidate(knl_session_t *session, page_id_t page_id, uint64 rbp_page_lsn,
                                                uint64 curr_page_lsn, uint64 expect_lsn, bool32 log_ahead);
static void rbp_log_ahead_detail(knl_session_t *session, page_id_t page_id, uint32 source_node, uint64 rbp_page_lsn,
                                rbp_analyse_item_t *item, uint64 expect_lsn);
static uint32 rbp_knl_read_selected_pages(knl_session_t *session);
static rbp_page_status_e rbp_knl_pull_one_page(knl_session_t *session, buf_ctrl_t *ctrl);
static void rbp_clear_ctrl_pending(buf_ctrl_t *ctrl, rbp_queue_item_t *item, const char *reason, uint64 reset_lfn,
                                   uint64 gap_end_lfn);
static void rbp_queue_notify_reset_point_one(knl_session_t *session, uint32 queue_id, log_point_t *point,
                                            const char *reason, bool32 warn_log);

#define RBP_PAGE_WRITE_BACKLOG_WARN_COUNT 4096
#define RBP_PAGE_WRITE_ASSEMBLE_DIAG_US   1000000
#define RBP_PAGE_WRITE_ITEM_DIAG_US       100000
#define RBP_PAGE_WRITE_SEND_DIAG_US       500000
#define RBP_PAGE_WRITE_REDO_DIAG_US       500000
#define RBP_PAGE_WRITE_LOG_INTERVAL_US    (5 * MICROSECS_PER_SECOND)
#define RBP_ASSEMBLE_DIAG_INTERVAL_US     MICROSECS_PER_SECOND
#define RBP_READ_BATCH_SLOW_US            200000
#define RBP_READ_BATCH_SLOW_INTERVAL_US   (5 * MICROSECS_PER_SECOND)
#define RBP_READ_SAMPLE_LIMIT             5

#if RBP_READ_HOT_DIAG
#define RBP_READ_STEP_BEGIN(var)          ((var) = cm_now())
#define RBP_READ_STEP_ACCUM(var, acc)     ((acc) += (uint64)(cm_now() - (var)))
#else
#define RBP_READ_STEP_BEGIN(var)          ((void)sizeof(var))
#define RBP_READ_STEP_ACCUM(var, acc)     ((void)sizeof(var), (void)sizeof(acc))
#endif
#define RBP_CKPT_PURGE_INTERVAL_FACTOR    5
#define RBP_SEND_LATCH_WAIT               30
#define RBP_SEND_LATCH_TIMEOUT            3
#define RBP_ASSEMBLE_MAX_SCAN_DEFAULT     300
#define RBP_ASSEMBLE_MAX_SCAN_MIN         100
#define RBP_ASSEMBLE_MAX_SCAN_MAX         1000000
#define RBP_DTC_PLANNED_REQUIRED_INIT_CAPACITY 4096
#define RBP_DTC_PLANNED_REQUIRED_GROW_FACTOR   2
#define RBP_PARTIAL_VERIFY_SAMPLE_LIMIT        16
#define RBP_TOUCH_SAMPLE_SLOT0                 0
#define RBP_TOUCH_SAMPLE_SLOT1                 1
#define RBP_TOUCH_SAMPLE_SLOT2                 2
#define RBP_TOUCH_SAMPLE_SLOT3                 3
#define RBP_NODE_BITMAP_BITS                   64
#define RBP_LOG_FLUSH_WAIT_MS                  10
#define RBP_DISCONNECTED_SLEEP_MS              100
#define RBP_NOT_OPEN_SLEEP_MS                  10
#define RBP_SUSPEND_PAGE_WRITE_SLEEP_MS        10
#define RBP_NO_REMOTE_WRITE_SLEEP_MS           200
#define RBP_SHUTDOWN_WAIT_MS                   500
#define RBP_SELECTED_SCORE_SHIFT               32
#define RBP_SELECTED_WORKER_LOG_SLOT0          0
#define RBP_SELECTED_WORKER_LOG_SLOT1          1
#define RBP_SELECTED_WORKER_LOG_SLOT2          2
#define RBP_SELECTED_WORKER_LOG_SLOT3          3
#define RBP_SELECTED_WORKER_LOG_SLOT4          4
#define RBP_SELECTED_WORKER_LOG_SLOT5          5
#define RBP_SELECTED_WORKER_LOG_SLOT6          6
#define RBP_SELECTED_WORKER_LOG_SLOT7          7
#define RBP_META_AHEAD_SAMPLE_LIMIT            8
#define RBP_SELECTED_MISS_SAMPLE_LIMIT         8
#define RBP_ALY_PERCENT_BASE                   100
#define RBP_ALY_REDO_SLEEP_MS                  10
#define RBP_BUCKET_EMPTY_SLEEP_MS              10

typedef enum en_rbp_latch_result {
    RBP_LATCH_OK = 0,
    RBP_LATCH_BUSY,
    RBP_LATCH_ERROR
} rbp_latch_result_t;

typedef struct st_rbp_assemble_diag {
    uint32 live_num;
    uint32 snapshot_num;
    uint32 dropped_num;
    uint32 busy_num;
    uint32 scanned;
    uint32 max_scan;
    uint64 latch_us;
    uint64 first_latch_us;
    uint64 retry_latch_us;
    uint64 readonly_wait_us;
    uint64 need_load_wait_us;
    uint64 copy_us;
    uint64 pop_us;
    uint64 free_us;
    uint64 max_item_us;
    uint32 retry_latch_count;
    uint32 readonly_wait_count;
    uint32 need_load_wait_count;
    page_id_t max_item_page;
    uint32 max_item_source;
    uint32 max_item_load_status;
    uint32 max_item_is_readonly;
    uint32 max_item_latch_stat;
} rbp_assemble_diag_t;

static date_t g_rbp_backlog_last_log[OG_RBP_SESSION_COUNT] = { 0 };
static date_t g_rbp_queue_diag_last_log[OG_RBP_SESSION_COUNT] = { 0 };
#if RBP_PAGE_WRITE_HOT_DIAG
static date_t g_rbp_assemble_diag_last_log[OG_RBP_SESSION_COUNT] = { 0 };
#endif

static inline bool32 rbp_rate_loggable(date_t *last_log_time, date_t now, date_t interval_us)
{
    if (*last_log_time == 0 || now - *last_log_time >= interval_us) {
        *last_log_time = now;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static inline void rbp_assemble_diag_update_max_detail(rbp_assemble_diag_t *diag, uint64 item_us, page_id_t page_id,
                                                       uint32 source, uint32 load_status, uint32 is_readonly,
                                                       uint32 latch_stat)
{
    if (diag == NULL || item_us <= diag->max_item_us) {
        return;
    }

    diag->max_item_us = item_us;
    diag->max_item_page = page_id;
    diag->max_item_source = source;
    diag->max_item_load_status = load_status;
    diag->max_item_is_readonly = is_readonly;
    diag->max_item_latch_stat = latch_stat;
}

static inline bool32 rbp_snapshot_low_watermark_loggable(uint32 free_count)
{
    return (bool32)(free_count == 0 || (free_count & (free_count - 1)) == 0);
}

static inline bool32 rbp_queue_backlog_loggable(uint32 queue_id, uint32 count)
{
#ifdef RBP_VERBOSE_TRACE
    return (bool32)(count >= RBP_PAGE_WRITE_BACKLOG_WARN_COUNT &&
                    (count % RBP_PAGE_WRITE_BACKLOG_WARN_COUNT) == 0);
#else
    if (count < RBP_PAGE_WRITE_BACKLOG_WARN_COUNT) {
        return OG_FALSE;
    }
    return rbp_rate_loggable(&g_rbp_backlog_last_log[queue_id % OG_RBP_SESSION_COUNT], g_timer()->now,
                            RBP_PAGE_WRITE_LOG_INTERVAL_US);
#endif
}

static inline bool32 rbp_page_write_diag_loggable(uint32 queue_id, bool32 took_gap_reset, bool32 took_ckpt_reset,
                                                  uint32 queue_count_before, uint32 queue_count_after,
                                                  uint64 assemble_us, uint64 wait_redo_us, uint64 send_us)
{
    if (took_gap_reset) {
        return OG_TRUE;
    }
    if (assemble_us >= RBP_PAGE_WRITE_ASSEMBLE_DIAG_US || wait_redo_us >= RBP_PAGE_WRITE_REDO_DIAG_US ||
        send_us >= RBP_PAGE_WRITE_SEND_DIAG_US) {
        return OG_TRUE;
    }
    if (took_ckpt_reset || queue_count_before >= RBP_PAGE_WRITE_BACKLOG_WARN_COUNT ||
        queue_count_after >= RBP_PAGE_WRITE_BACKLOG_WARN_COUNT) {
        return rbp_rate_loggable(&g_rbp_queue_diag_last_log[queue_id % OG_RBP_SESSION_COUNT], g_timer()->now,
                                RBP_PAGE_WRITE_LOG_INTERVAL_US);
    }
    return OG_FALSE;
}

static inline uint32 rbp_get_assemble_max_scan(knl_session_t *session)
{
    uint32 max_scan = session->kernel->rbp_attr.assemble_max_scan;

    if (max_scan == 0) {
        return RBP_ASSEMBLE_MAX_SCAN_DEFAULT;
    }
    max_scan = MAX(max_scan, RBP_ASSEMBLE_MAX_SCAN_MIN);
    max_scan = MIN(max_scan, RBP_ASSEMBLE_MAX_SCAN_MAX);
    return MAX(max_scan, (uint32)RBP_BATCH_PAGE_NUM);
}

static rbp_queue_item_t *rbp_alloc_queue_item(void)
{
    rbp_queue_item_t *item = (rbp_queue_item_t *)malloc(sizeof(rbp_queue_item_t));
    errno_t ret;

    if (item == NULL) {
        return NULL;
    }

    ret = memset_sp(item, sizeof(rbp_queue_item_t), 0, sizeof(rbp_queue_item_t));
    knl_securec_check(ret);
    return item;
}

static rbp_snapshot_t *rbp_alloc_snapshot(knl_session_t *session)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_snapshot_t *snapshot = NULL;
    errno_t ret;
    bool32 log_low = OG_FALSE;
    uint32 low_free = 0;
    uint64 alloc_total = 0;
    uint64 free_total = 0;
    uint64 fail_total = 0;

    cm_spin_lock(&rbp_ctx->snapshot_lock, NULL);
    snapshot = rbp_ctx->snapshot_free;
    if (snapshot == NULL) {
        rbp_ctx->snapshot_alloc_fail_total++;
        low_free = rbp_ctx->snapshot_low_watermark;
        alloc_total = rbp_ctx->snapshot_alloc_total;
        free_total = rbp_ctx->snapshot_free_total;
        fail_total = rbp_ctx->snapshot_alloc_fail_total;
        cm_spin_unlock(&rbp_ctx->snapshot_lock);
        OG_LOG_RUN_WAR("[RBP] snapshot pool empty: free=0 low_watermark=%u alloc_total=%llu free_total=%llu "
                       "fail_total=%llu",
                       low_free, (uint64)alloc_total, (uint64)free_total, (uint64)fail_total);
        return NULL;
    }
    rbp_ctx->snapshot_free = snapshot->next;
    rbp_ctx->snapshot_free_count--;
    rbp_ctx->snapshot_alloc_total++;
    if (rbp_ctx->snapshot_free_count < rbp_ctx->snapshot_low_watermark) {
        rbp_ctx->snapshot_low_watermark = rbp_ctx->snapshot_free_count;
        log_low = rbp_snapshot_low_watermark_loggable(rbp_ctx->snapshot_free_count);
        low_free = rbp_ctx->snapshot_free_count;
        alloc_total = rbp_ctx->snapshot_alloc_total;
        free_total = rbp_ctx->snapshot_free_total;
        fail_total = rbp_ctx->snapshot_alloc_fail_total;
    }
    cm_spin_unlock(&rbp_ctx->snapshot_lock);

    if (log_low) {
        OG_LOG_RUN_WAR("[RBP] snapshot pool low watermark: free=%u/%u alloc_total=%llu free_total=%llu "
                       "fail_total=%llu",
                       low_free, (uint32)RBP_SNAPSHOT_POOL_SIZE, (uint64)alloc_total, (uint64)free_total,
                       (uint64)fail_total);
    }

    ret = memset_sp(snapshot, sizeof(rbp_snapshot_t), 0, sizeof(rbp_snapshot_t));
    knl_securec_check(ret);
    return snapshot;
}

static void rbp_free_snapshot(knl_session_t *session, rbp_snapshot_t *snapshot)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;

    if (snapshot == NULL) {
        return;
    }

    cm_spin_lock(&rbp_ctx->snapshot_lock, NULL);
    snapshot->next = rbp_ctx->snapshot_free;
    rbp_ctx->snapshot_free = snapshot;
    rbp_ctx->snapshot_free_count++;
    rbp_ctx->snapshot_free_total++;
    cm_spin_unlock(&rbp_ctx->snapshot_lock);
}

static void rbp_free_queue_item(knl_session_t *session, rbp_queue_item_t *item)
{
    if (item == NULL) {
        return;
    }

    rbp_free_snapshot(session, item->snapshot);
    item->snapshot = NULL;
    CM_FREE_PTR(item);
}

static status_t rbp_snapshot_pool_init(knl_session_t *session)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    int64 buf_size = (int64)RBP_SNAPSHOT_POOL_SIZE * (int64)sizeof(rbp_snapshot_t);
    rbp_snapshot_t *snapshot = NULL;
    errno_t ret;

    if (cm_aligned_malloc(buf_size, "rbp snapshot pool", &rbp_ctx->snapshot_buf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ret = memset_sp(rbp_ctx->snapshot_buf.aligned_buf, buf_size, 0, buf_size);
    knl_securec_check(ret);
    snapshot = (rbp_snapshot_t *)rbp_ctx->snapshot_buf.aligned_buf;
    rbp_ctx->snapshot_free = snapshot;
    rbp_ctx->snapshot_free_count = RBP_SNAPSHOT_POOL_SIZE;
    rbp_ctx->snapshot_low_watermark = RBP_SNAPSHOT_POOL_SIZE;
    rbp_ctx->snapshot_alloc_total = 0;
    rbp_ctx->snapshot_free_total = 0;
    rbp_ctx->snapshot_alloc_fail_total = 0;
    for (uint32 i = 0; i < RBP_SNAPSHOT_POOL_SIZE - 1; i++) {
        snapshot[i].next = &snapshot[i + 1];
    }
    snapshot[RBP_SNAPSHOT_POOL_SIZE - 1].next = NULL;
    return OG_SUCCESS;
}

static void rbp_snapshot_pool_free(knl_session_t *session)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;

    rbp_ctx->snapshot_free = NULL;
    rbp_ctx->snapshot_free_count = 0;
    rbp_ctx->snapshot_low_watermark = 0;
    rbp_ctx->snapshot_alloc_total = 0;
    rbp_ctx->snapshot_free_total = 0;
    rbp_ctx->snapshot_alloc_fail_total = 0;
    cm_aligned_free(&rbp_ctx->snapshot_buf);
}

static void rbp_drain_send_queues(knl_session_t *session)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_queue_t *queue = NULL;
    rbp_queue_item_t *item = NULL;
    rbp_queue_item_t *next = NULL;
    uint64 cleared_total = 0;

    for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        queue = &rbp_ctx->queue[id];
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
        item = queue->first;
        queue->first = NULL;
        queue->last = NULL;
        cleared_total += queue->count;
        queue->count = 0;
        queue->has_gap = OG_FALSE;
        queue->has_ckpt_reset = OG_FALSE;
        queue->ckpt_reset_point = (log_point_t){ 0 };
        queue->last_sent_ckpt_purge_point = (log_point_t){ 0 };
        queue->last_ckpt_purge_check_time = 0;
        cm_spin_unlock(&queue->lock);

        while (item != NULL) {
            next = item->next;
            if (item->source == RBP_QUEUE_ITEM_LIVE && item->ctrl != NULL && item->ctrl->rbp_ctrl != NULL) {
                rbp_clear_ctrl_pending(item->ctrl, item, "queue_clear", 0, 0);
            }
            item->next = NULL;
            rbp_free_queue_item(session, item);
            item = next;
        }
    }

    if (cleared_total > 0) {
        OG_LOG_RUN_WAR("[RBP] discarded local RBP write queues: pages=%llu", cleared_total);
    }
}

static inline bool32 rbp_clear_pending_loggable(const char *reason)
{
#ifdef RBP_VERBOSE_TRACE
    return OG_TRUE;
#else
    if (reason == NULL) {
        return OG_TRUE;
    }
    if (strcmp(reason, "sent") == 0 || strcmp(reason, "ckpt_reset") == 0 ||
        strcmp(reason, "gap_reset") == 0 || strcmp(reason, "snapshot_detach") == 0 ||
        strcmp(reason, "queue_clear") == 0) {
        return OG_FALSE;
    }
    return OG_TRUE;
#endif
}

static void rbp_clear_ctrl_pending(buf_ctrl_t *ctrl, rbp_queue_item_t *item, const char *reason, uint64 reset_lfn,
                                   uint64 gap_end_lfn)
{
    if (ctrl == NULL || ctrl->rbp_ctrl == NULL) {
        return;
    }

    if (ctrl->rbp_ctrl->pending_item == item) {
        if (rbp_clear_pending_loggable(reason)) {
            OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] CLEAR_PENDING reason=%s queue=%u page=%u-%u ctrl=%p item=%p "
                            "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                            "gap_end_lfn=%llu page_status=%u",
                            reason, item == NULL ? OG_INVALID_ID32 : item->queue_id, ctrl->page_id.file,
                            ctrl->page_id.page, (void *)ctrl, (void *)item, (uint64)ctrl->page->lsn,
                            (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                            (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)reset_lfn, (uint64)gap_end_lfn,
                            (uint32)ctrl->rbp_ctrl->page_status);
        }
        ctrl->rbp_ctrl->pending_item = NULL;
        ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
    }
}

static void rbp_drop_pending_item(knl_session_t *session, buf_ctrl_t *ctrl, const char *reason)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    uint32 queue_id;
    rbp_queue_t *queue = NULL;
    rbp_queue_item_t *item = NULL;
    page_id_t page_id;
    uint64 trunc_lfn = 0;
    uint64 lastest_lfn = 0;

    if (ctrl == NULL || ctrl->rbp_ctrl == NULL) {
        return;
    }

    page_id = ctrl->page_id;
    trunc_lfn = ctrl->rbp_ctrl->rbp_trunc_point.lfn;
    lastest_lfn = ctrl->lastest_lfn;
    queue_id = page_id.page % OG_RBP_SESSION_COUNT;
    queue = &rbp_ctx->queue[queue_id];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    item = ctrl->rbp_ctrl->pending_item;
    if (item != NULL && item->source == RBP_QUEUE_ITEM_LIVE && item->ctrl == ctrl) {
        item->source = RBP_QUEUE_ITEM_DROPPED;
        item->ctrl = NULL;
    }
    OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] DROP_PENDING reason=%s queue=%u page=%u-%u ctrl=%p item=%p "
                    "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                    "gap_end_lfn=%llu page_status=%u",
                    reason, queue_id, page_id.file, page_id.page, (void *)ctrl, (void *)item,
                    (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)lastest_lfn, (uint64)trunc_lfn,
                    (uint64)0, (uint64)0, (uint32)ctrl->rbp_ctrl->page_status);
    ctrl->rbp_ctrl->pending_item = NULL;
    ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
    queue->has_gap = OG_TRUE;
    cm_spin_unlock(&queue->lock);

    OG_LOG_RUN_WAR("[RBP] drop pending queue item: queue=%u page=%u-%u trunc_lfn=%llu lastest_lfn=%llu reason=%s",
                   queue_id, page_id.file, page_id.page, (uint64)trunc_lfn, (uint64)lastest_lfn, reason);
}

/*
* Multi-writer RBP placement:
* - In a cluster, each node writes local dirty pages to the peer RBP process.
* - Queueing and PAGE_WRITE are based on DRC exclusive page ownership, not DB_IS_PRIMARY.
* - Non-cluster primary/standby still only lets the primary enqueue RBP writes.
*/
bool32 rbp_ctrl_may_enqueue(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (!KNL_RBP_ENABLE(session->kernel)) {
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[RBP] skip enqueue page %u-%u: RBP disabled", ctrl->page_id.file, ctrl->page_id.page);
#endif
        return OG_FALSE;
    }
    if (DB_IS_CLUSTER(session)) {
        if (OGRAC_REPLAY_NODE(session)) {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_RUN_INF("[RBP] skip enqueue page %u-%u: replay node session type=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)session->dtc_session_type);
#endif
            return OG_FALSE;
        }
        if (ctrl->lock_mode != DRC_LOCK_EXCLUSIVE) {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_RUN_INF("[RBP] skip enqueue page %u-%u: lock_mode=%u is not DRC_LOCK_EXCLUSIVE",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)ctrl->lock_mode);
#endif
            return OG_FALSE;
        }
        return OG_TRUE;
    }
    if (!DB_IS_PRIMARY(&session->kernel->db)) {
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[RBP] skip enqueue page %u-%u: non-primary database role",
                       ctrl->page_id.file, ctrl->page_id.page);
#endif
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline bool32 rbp_should_suspend_page_write(knl_session_t *session)
{
    if (session == NULL || session->kernel == NULL) {
        return OG_FALSE;
    }

    return session->kernel->rbp_context.page_write_suspended;
}

void rbp_suspend_page_write_for_partial_recovery(knl_session_t *session)
{
    rbp_context_t *rbp_context = NULL;

    if (session == NULL || session->kernel == NULL || !KNL_RBP_ENABLE(session->kernel)) {
        return;
    }

    rbp_context = &session->kernel->rbp_context;
    if (!rbp_context->page_write_suspended) {
        OG_LOG_RUN_WAR("[RBP] PAGE_WRITE suspend enter partial_recovery");
    }
    rbp_context->page_write_suspended = OG_TRUE;
    rbp_context->clear_after_partial_recovery = OG_TRUE;
}

void rbp_finish_partial_recovery_page_write(knl_session_t *session)
{
    rbp_context_t *rbp_context = NULL;

    if (session == NULL || session->kernel == NULL || !KNL_RBP_ENABLE(session->kernel)) {
        return;
    }

    rbp_context = &session->kernel->rbp_context;
    if (rbp_context->clear_after_partial_recovery) {
        rbp_drain_send_queues(session);
        rbp_context->clear_after_partial_recovery = OG_FALSE;
    }
    if (rbp_context->page_write_suspended) {
        rbp_context->page_write_suspended = OG_FALSE;
        OG_LOG_RUN_WAR("[RBP] PAGE_WRITE suspend leave partial_recovery");
    }
}

bool32 rbp_instance_may_write_to_remote(knl_session_t *session)
{
    if (!KNL_RBP_ENABLE(session->kernel)) {
        return OG_FALSE;
    }
    if (DB_IS_CLUSTER(session)) {
        if (OGRAC_REPLAY_NODE(session)) {
            return OG_FALSE;
        }
        return OG_TRUE;
    }
    return (bool32)DB_IS_PRIMARY(&session->kernel->db);
}

bool32 rbp_db_enforce_primary_style_invariants(knl_session_t *session)
{
    if (OGRAC_REPLAY_NODE(session)) {
        return OG_FALSE;
    }
    if (DB_IS_CLUSTER(session)) {
        return OG_TRUE;
    }
    return (bool32)DB_IS_PRIMARY(&session->kernel->db);
}

void rbp_on_page_owner_migrate_or_invalidate(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (!KNL_RBP_ENABLE(session->kernel) || ctrl == NULL || ctrl->rbp_ctrl == NULL) {
        return;
    }

    /*
    * DRC owner migration does not destroy the local page image by itself. The RBP
    * send queue stores ctrl pointers, so the background writer can still copy the
    * EDP image after the owner has moved away. Only real ctrl reuse/recycle should
    * create a RBP gap; that path still calls rbp_queue_set_gap().
    */
    if (!ctrl->rbp_ctrl->is_rbpdirty) {
        OG_LOG_DEBUG_INF("[RBP] owner migrate/invalidate page %u-%u: no RBP gap, page is not pending",
                        ctrl->page_id.file, ctrl->page_id.page);
        return;
    }

    OG_LOG_DEBUG_INF("[RBP] owner migrate/invalidate page %u-%u: keep pending RBP page, "
                    "trunc_lfn=%llu lastest_lfn=%llu",
                    ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn,
                    (uint64)ctrl->lastest_lfn);
}

bool32 rbp_need_wait_before_remote_overwrite(knl_session_t *session, buf_ctrl_t *ctrl)
{
    return (bool32)(KNL_RBP_ENABLE(session->kernel) && ctrl != NULL && ctrl->rbp_ctrl != NULL &&
                    ctrl->is_edp && ctrl->rbp_ctrl->is_rbpdirty);
}

/*
* The caller must already hold the page X latch.  We copy the pending EDP image
* into a detached snapshot so DCS/buffer recycle can overwrite/reuse the live
* ctrl immediately without waiting for the RBP writer thread.
*/
bool32 rbp_try_detach_pending_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_snapshot_t *snapshot = NULL;
    rbp_queue_item_t *item = NULL;
    rbp_queue_t *queue = NULL;
    uint32 queue_id;
    uint32 snapshot_free_count = 0;
    uint32 snapshot_low_watermark = 0;
    uint64 snapshot_alloc_total = 0;
    uint64 snapshot_free_total = 0;
    uint64 snapshot_fail_total = 0;
    uint32 queue_count = 0;
    bool32 already_gap = OG_FALSE;
    errno_t ret;

    if (!KNL_RBP_ENABLE(session->kernel) || ctrl == NULL || ctrl->rbp_ctrl == NULL ||
        !ctrl->rbp_ctrl->is_rbpdirty) {
        return OG_TRUE;
    }

    snapshot = rbp_alloc_snapshot(session);
    queue_id = ctrl->page_id.page % OG_RBP_SESSION_COUNT;
    queue = &rbp_ctx->queue[queue_id];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    item = ctrl->rbp_ctrl->pending_item;
    if (item == NULL || item->source != RBP_QUEUE_ITEM_LIVE || item->ctrl != ctrl) {
        OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] DROP_PENDING reason=pending_lost queue=%u page=%u-%u ctrl=%p item=%p "
                        "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                        "gap_end_lfn=%llu page_status=%u",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                        (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                        (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn,
                        (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint64)0,
                        (uint32)ctrl->rbp_ctrl->page_status);
        ctrl->rbp_ctrl->pending_item = NULL;
        ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
        queue->has_gap = OG_TRUE;
        cm_spin_unlock(&queue->lock);
        rbp_free_snapshot(session, snapshot);
        rbp_queue_notify_reset_point_one(session, queue_id, &session->kernel->redo_ctx.curr_point, "pending_lost",
                                        OG_TRUE);
        OG_LOG_RUN_WAR("[RBP] pending dirty page has no live queue item, set gap: queue=%u page=%u-%u "
                       "lastest_lfn=%llu",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn);
        return OG_FALSE;
    }

    if (snapshot == NULL) {
        already_gap = queue->has_gap;
        item->source = RBP_QUEUE_ITEM_DROPPED;
        item->ctrl = NULL;
        OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] DROP_PENDING reason=snapshot_detach_failed queue=%u page=%u-%u "
                        "ctrl=%p item=%p page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu "
                        "reset_lfn=%llu gap_end_lfn=%llu page_status=%u",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                        (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                        (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn,
                        (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint64)0,
                        (uint32)ctrl->rbp_ctrl->page_status);
        ctrl->rbp_ctrl->pending_item = NULL;
        ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
        queue->has_gap = OG_TRUE;
        queue_count = queue->count;
        cm_spin_unlock(&queue->lock);

        cm_spin_lock(&rbp_ctx->snapshot_lock, NULL);
        snapshot_free_count = rbp_ctx->snapshot_free_count;
        snapshot_low_watermark = rbp_ctx->snapshot_low_watermark;
        snapshot_alloc_total = rbp_ctx->snapshot_alloc_total;
        snapshot_free_total = rbp_ctx->snapshot_free_total;
        snapshot_fail_total = rbp_ctx->snapshot_alloc_fail_total;
        cm_spin_unlock(&rbp_ctx->snapshot_lock);

        rbp_queue_notify_reset_point_one(session, queue_id, &session->kernel->redo_ctx.curr_point,
                                        "snapshot_detach_failed", OG_TRUE);
        OG_LOG_RUN_WAR("[RBP] snapshot detach failed, set gap: queue=%u page=%u-%u trunc_lfn=%llu lastest_lfn=%llu "
                       "queue_count=%u already_gap=%u connected=%u rcy_with_rbp=%u db_open=%u curr_lfn=%llu "
                       "snapshot_free=%u low_watermark=%u alloc_total=%llu free_total=%llu fail_total=%llu",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page,
                        (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn, queue_count,
                        (uint32)already_gap, (uint32)rbp_ctx->rbp_buf_manager[queue_id].is_connected,
                        (uint32)KNL_RECOVERY_WITH_RBP(session->kernel), (uint32)DB_IS_OPEN(session),
                        (uint64)session->kernel->redo_ctx.curr_point.lfn, snapshot_free_count, snapshot_low_watermark,
                        (uint64)snapshot_alloc_total, (uint64)snapshot_free_total, (uint64)snapshot_fail_total);
        return OG_FALSE;
    }

    snapshot->page_id = ctrl->page_id;
    snapshot->rbp_trunc_point = ctrl->rbp_ctrl->rbp_trunc_point;
    snapshot->lastest_lfn = ctrl->lastest_lfn;
    snapshot->writer_inst_id = (uint32)session->kernel->id;
    snapshot->writer_global_seq = ctrl->page->lsn;
    ret = memcpy_sp(snapshot->block, RBP_PAGE_SIZE, ctrl->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    item->source = RBP_QUEUE_ITEM_SNAPSHOT;
    item->ctrl = NULL;
    item->snapshot = snapshot;
    item->page_id = snapshot->page_id;
#ifdef RBP_VERBOSE_TRACE
    OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] CLEAR_PENDING reason=snapshot_detach queue=%u page=%u-%u ctrl=%p item=%p "
                    "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                    "gap_end_lfn=%llu page_status=%u",
                    queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                    (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                    (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)0, (uint64)0,
                    (uint32)ctrl->rbp_ctrl->page_status);
#endif
    ctrl->rbp_ctrl->pending_item = NULL;
    ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
    cm_spin_unlock(&queue->lock);

#ifdef RBP_VERBOSE_TRACE
    OG_LOG_DEBUG_INF("[RBP] detached pending page snapshot: queue=%u page=%u-%u trunc_lfn=%llu lastest_lfn=%llu "
                    "page_lsn=%llu",
                    queue_id, snapshot->page_id.file, snapshot->page_id.page,
                    (uint64)snapshot->rbp_trunc_point.lfn, (uint64)snapshot->lastest_lfn,
                    (uint64)snapshot->writer_global_seq);
#endif
    return OG_TRUE;
}

void rbp_wait_before_remote_overwrite(knl_session_t *session, buf_ctrl_t *ctrl)
{
    /*
    * Kept for old callers.  The new DCS/recycle path calls rbp_try_detach_pending_page()
    * while holding the X latch; if a legacy caller reaches here without that latch, do
    * not spin in foreground.  Drop the pending item and force a normal RBP gap instead.
    */
    if (rbp_need_wait_before_remote_overwrite(session, ctrl)) {
        rbp_drop_pending_item(session, ctrl, "legacy_remote_overwrite_without_snapshot");
    }
}

static cs_pipe_t *rbp_get_client_pipe(rbp_context_t *rbp_context, uint32 rbp_proc_id, bool32 is_temp)
{
    rbp_buf_manager_t *manager = &rbp_context->rbp_buf_manager[rbp_proc_id];

    return (is_temp) ? &manager->pipe_temp : &manager->pipe_const;
}

static cs_pipe_t *rbp_get_selected_temp_pipe(rbp_context_t *rbp_context, uint32 rbp_proc_id)
{
    rbp_buf_manager_t *manager = &rbp_context->rbp_buf_manager[rbp_proc_id];

    return &manager->pipe_selected_temp;
}

static void rbp_clear_dtc_planned_required_items(rbp_context_t *rbp_context)
{
    CM_FREE_PTR(rbp_context->dtc_planned_required_items);
    rbp_context->dtc_planned_required_built = OG_FALSE;
    rbp_context->dtc_planned_required_count = 0;
    rbp_context->dtc_planned_required_capacity = 0;
}

static void rbp_clear_dtc_read_epoch(rbp_context_t *rbp_context)
{
    rbp_context->dtc_read_active = OG_FALSE;
    rbp_context->dtc_read_workers_done = OG_FALSE;
    (void)cm_atomic_set(&rbp_context->dtc_read_failed, 0);
    rbp_context->dtc_read_failed_node = OG_INVALID_ID32;
    rbp_context->dtc_read_failed_result = RBP_READ_RESULT_OK;
    rbp_context->dtc_read_node_count = 0;
    rbp_context->dtc_use_selected_batch = OG_FALSE;
    rbp_context->dtc_need_selected_meta = OG_FALSE;
    rbp_context->dtc_sync_selected_pull_at_begin = OG_FALSE;
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        rbp_context->dtc_selected_cursor[i] = 0;
    }
    for (uint32 i = 0; i < OG_RBP_SESSION_COUNT; i++) {
        rbp_context->dtc_selected_worker_nodes[i] = OG_INVALID_ID32;
    }
    rbp_context->dtc_verify_node_count = 0;
    rbp_clear_dtc_planned_required_items(rbp_context);
}

static bool32 rbp_dtc_read_failed(rbp_context_t *rbp_context)
{
    return (bool32)(cm_atomic_get(&rbp_context->dtc_read_failed) != 0);
}

bool32 rbp_knl_dtc_fallback_required(knl_session_t *session)
{
    return (bool32)(cm_atomic_get(&session->kernel->rbp_context.dtc_rbp_fallback_required) != 0);
}

void rbp_knl_mark_dtc_fallback(knl_session_t *session, uint32 node_id, uint32 result, uint32 reason)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;

    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !OGRAC_PART_RECOVERY(session)) {
        return;
    }
    if (!cm_atomic_cas(&rbp_context->dtc_rbp_fallback_required, 0, 1)) {
        return;
    }

    rbp_context->dtc_rbp_fallback_node = node_id;
    rbp_context->dtc_rbp_fallback_result = result;
    rbp_context->dtc_rbp_fallback_reason = reason;
    OG_LOG_RUN_WAR("[RBP] DTC RBP fallback required: node=%u result=%u reason=%u",
                   node_id, result, reason);
}

void rbp_knl_clear_dtc_fallback(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;

    (void)cm_atomic_set(&rbp_context->dtc_rbp_fallback_required, 0);
    rbp_context->dtc_rbp_fallback_node = OG_INVALID_ID32;
    rbp_context->dtc_rbp_fallback_result = RBP_READ_RESULT_OK;
    rbp_context->dtc_rbp_fallback_reason = RBP_DTC_FALLBACK_NONE;
}

static bool32 rbp_dtc_has_jump_taken(knl_session_t *session)
{
    dtc_rcy_context_t *dtc_rcy = NULL;

    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return OG_FALSE;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id < OG_MAX_INSTANCES && dtc_rcy->rbp_jump_taken[node_id]) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

bool32 rbp_knl_dtc_read_failed(knl_session_t *session)
{
    return rbp_dtc_read_failed(&session->kernel->rbp_context);
}

static void rbp_mark_dtc_read_failed(rbp_context_t *rbp_context, uint32 node_id, uint32 result, const char *reason)
{
    if (!cm_atomic_cas(&rbp_context->dtc_read_failed, 0, 1)) {
        return;
    }

    rbp_context->dtc_read_failed_node = node_id;
    rbp_context->dtc_read_failed_result = result;
    OG_LOG_RUN_ERR("[RBP] DTC RBP read failed: node=%u result=%u reason=%s",
                   node_id, result, (reason == NULL) ? "unknown" : reason);
}

static void rbp_reset_read_stat(rbp_context_t *rbp_context)
{
    errno_t ret;

    (void)cm_atomic_set(&rbp_context->rbp_read_pages, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_errors, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_batch_elapsed, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_selected_mismatch, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_pull_miss_trace, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_partial_ahead_detail, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_ahead_detail, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_partial_disk_fallback, 0);
    (void)cm_atomic_set(&rbp_context->rbp_read_multi_disk_fallback, 0);
    rbp_context->rbp_read_workers_done_time = 0;
#if RBP_READ_HOT_DIAG
    ret = memset_sp(rbp_context->read_diag, sizeof(rbp_context->read_diag), 0, sizeof(rbp_context->read_diag));
    knl_securec_check(ret);
    ret = memset_sp(&rbp_context->read_skip_diag, sizeof(rbp_context->read_skip_diag), 0,
                    sizeof(rbp_context->read_skip_diag));
    knl_securec_check(ret);
#else
    ret = memset_sp(rbp_context->read_diag, sizeof(rbp_context->read_diag), 0, sizeof(rbp_context->read_diag));
    knl_securec_check(ret);
#endif
}

static void rbp_log_read_anomaly_summary(rbp_context_t *rbp_context)
{
    uint64 selected_mismatch = (uint64)cm_atomic_get(&rbp_context->rbp_read_selected_mismatch);
    uint64 pull_miss_trace = (uint64)cm_atomic_get(&rbp_context->rbp_read_pull_miss_trace);
    uint64 partial_ahead = (uint64)cm_atomic_get(&rbp_context->rbp_read_partial_ahead_detail);
    uint64 ahead = (uint64)cm_atomic_get(&rbp_context->rbp_read_ahead_detail);
    uint64 partial_fallback = (uint64)cm_atomic_get(&rbp_context->rbp_read_partial_disk_fallback);
    uint64 multi_fallback = (uint64)cm_atomic_get(&rbp_context->rbp_read_multi_disk_fallback);
    if (selected_mismatch == 0 && pull_miss_trace == 0 && partial_ahead == 0 && ahead == 0 &&
        partial_fallback == 0 && multi_fallback == 0) {
        return;
    }

    OG_LOG_RUN_INF("[RBP] read anomaly summary: selected_page_read_mismatch=%llu pull_miss_trace=%llu "
                   "partial_ahead_detail=%llu ahead_detail=%llu partial_disk_fallback=%llu "
                   "multi_disk_fallback=%llu sample_limit=%u",
                   selected_mismatch, pull_miss_trace, partial_ahead, ahead, partial_fallback, multi_fallback,
                   RBP_READ_SAMPLE_LIMIT);
}

static void rbp_record_read_skip_partial_no_expect(rbp_context_t *rbp_context, rbp_partial_item_t *partial_item)
{
#if !RBP_READ_HOT_DIAG
    (void)rbp_context;
    (void)partial_item;
    return;
#else
    (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_no_expect);
    if (partial_item == NULL) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_no_expect_no_item);
        return;
    }

    if (!partial_item->required) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_no_expect_not_required);
    }
#endif
}

static void rbp_record_read_skip_partial_selected_scope(rbp_context_t *rbp_context, rbp_partial_item_t *partial_item,
    buf_ctrl_t *ctrl)
{
#if !RBP_READ_HOT_DIAG
    (void)rbp_context;
    (void)partial_item;
    (void)ctrl;
    return;
#else
    (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_selected_scope);
    if (partial_item == NULL) {
        return;
    }

    if (partial_item->required) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_selected_scope_required);
    }
    if (partial_item->selected_valid) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_selected_scope_selected_valid);
    }
    if (partial_item->selected_pulled) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_selected_scope_selected_pulled);
    }
    if (partial_item->verified) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_selected_scope_verified);
    }
    if (ctrl != NULL && ctrl->load_status != 0) {
        (void)cm_atomic_inc(&rbp_context->read_skip_diag.partial_selected_scope_load_status);
    }
#endif
}

static void rbp_record_read_skip_no_expect_lsn(rbp_context_t *rbp_context)
{
#if RBP_READ_HOT_DIAG
    (void)cm_atomic_inc(&rbp_context->read_skip_diag.no_expect_lsn);
#else
    (void)rbp_context;
#endif
}

static void rbp_record_read_skip_nolog_space(rbp_context_t *rbp_context)
{
#if RBP_READ_HOT_DIAG
    (void)cm_atomic_inc(&rbp_context->read_skip_diag.nolog_space);
#else
    (void)rbp_context;
#endif
}

static void rbp_record_read_batch_stat(rbp_context_t *rbp_context, uint32 result, uint32 page_count, uint64 elapsed)
{
    (void)cm_atomic_add(&rbp_context->rbp_read_pages, (int64)page_count);
    (void)cm_atomic_add(&rbp_context->rbp_read_batch_elapsed, (int64)elapsed);
    if (result != RBP_READ_RESULT_OK && result != RBP_READ_RESULT_NOPAGE) {
        (void)cm_atomic_inc(&rbp_context->rbp_read_errors);
    }
}

#if RBP_READ_HOT_DIAG
static void rbp_add_apply_diag(rbp_read_apply_diag_t *dst, const rbp_read_apply_diag_t *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }

    dst->resp_pages += src->resp_pages;
    dst->not_required += src->not_required;
    dst->no_expect += src->no_expect;
    dst->ahead += src->ahead;
    dst->wrong_node += src->wrong_node;
    dst->selected += src->selected;
    dst->installed += src->installed;
    dst->hit += src->hit;
    dst->usable += src->usable;
    dst->old += src->old;
    dst->miss += src->miss;
    dst->other_status += src->other_status;
    dst->not_newer += src->not_newer;
    dst->select_update_us += src->select_update_us;
    dst->enter_page_us += src->enter_page_us;
    dst->eval_us += src->eval_us;
    dst->replace_us += src->replace_us;
    dst->replace_copy_us += src->replace_copy_us;
    dst->replace_disk_check_us += src->replace_disk_check_us;
    dst->replace_id_check_us += src->replace_id_check_us;
    dst->replace_pcn_check_us += src->replace_pcn_check_us;
    dst->replace_dirty_us += src->replace_dirty_us;
    dst->replace_ckpt_enque_us += src->replace_ckpt_enque_us;
    dst->replace_ckpt_enque += src->replace_ckpt_enque;
    dst->replace_already_dirty += src->replace_already_dirty;
    dst->mark_us += src->mark_us;
    dst->leave_page_us += src->leave_page_us;
    dst->selected_requested += src->selected_requested;
    dst->selected_verified += src->selected_verified;
    dst->selected_missing += src->selected_missing;
    dst->selected_mismatch += src->selected_mismatch;
}
#endif

static void rbp_record_read_diag(rbp_context_t *rbp_context, uint32 rbp_proc_id, uint32 result, uint32 page_count,
    uint64 total_us, uint64 pipe_lock_us, uint64 ensure_conn_us, uint64 send_us, uint64 wait_resp_us,
    uint64 process_us, const rbp_read_apply_diag_t *apply)
{
    rbp_read_worker_diag_t *diag;
    date_t now;
#if RBP_READ_HOT_DIAG
    uint64 connect_us = pipe_lock_us + ensure_conn_us;
    uint64 selected = (apply == NULL) ? 0 : apply->selected;
    uint64 installed = (apply == NULL) ? 0 : apply->installed;
    uint64 not_required = (apply == NULL) ? 0 : apply->not_required;
#endif

    if (rbp_proc_id >= OG_RBP_SESSION_COUNT) {
        return;
    }

    diag = &rbp_context->read_diag[rbp_proc_id];
    if (result == RBP_READ_RESULT_OK) {
        diag->ok_batches++;
    } else if (result == RBP_READ_RESULT_NOPAGE) {
        diag->nopage_batches++;
    } else {
        diag->error_batches++;
    }
    diag->pages += page_count;
    diag->total_us += total_us;
#if RBP_READ_HOT_DIAG
    diag->connect_us += connect_us;
    diag->pipe_lock_us += pipe_lock_us;
    diag->ensure_conn_us += ensure_conn_us;
    diag->send_us += send_us;
    diag->wait_resp_us += wait_resp_us;
    diag->process_us += process_us;
    rbp_add_apply_diag(&diag->apply, apply);
#endif

    if (total_us < RBP_READ_BATCH_SLOW_US) {
        return;
    }

    now = cm_now();
    if (diag->slow_last_log_time != 0 && (uint64)(now - diag->slow_last_log_time) < RBP_READ_BATCH_SLOW_INTERVAL_US) {
        return;
    }
    diag->slow_last_log_time = now;
#if RBP_READ_HOT_DIAG
    OG_LOG_RUN_WAR("[RBP] slow BATCH_READ: q=%u result=%u pages=%u total_us=%llu connect_us=%llu send_us=%llu "
                   "wait_resp_us=%llu process_us=%llu pipe_lock_us=%llu ensure_conn_us=%llu selected=%llu "
                   "installed=%llu not_required=%llu",
                   rbp_proc_id, result, page_count, total_us, connect_us, send_us, wait_resp_us, process_us,
                   pipe_lock_us, ensure_conn_us, selected, installed, not_required);
#else
    OG_LOG_RUN_WAR("[RBP] slow BATCH_READ: q=%u result=%u pages=%u total_us=%llu",
                   rbp_proc_id, result, page_count, total_us);
#endif
}

static void rbp_finish_read_batch_stat(knl_session_t *session, uint32 rbp_proc_id, uint32 result, uint32 page_count,
    date_t begin_time, uint64 pipe_lock_us, uint64 ensure_conn_us, uint64 send_us, uint64 wait_resp_us,
    uint64 process_us, const rbp_read_apply_diag_t *apply)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    date_t now = cm_now();
    uint64 total_us = (now > begin_time) ? (uint64)(now - begin_time) : 0;

    rbp_record_read_batch_stat(rbp_context, result, page_count, total_us);
    rbp_record_read_diag(rbp_context, rbp_proc_id, result, page_count, total_us, pipe_lock_us, ensure_conn_us,
                        send_us, wait_resp_us, process_us, apply);
}

static void rbp_log_read_diag_summary(rbp_context_t *rbp_context)
{
#if !RBP_READ_HOT_DIAG
    (void)rbp_context;
    return;
#else
    rbp_read_worker_diag_t total = { 0 };
    uint32 workers = 0;
    uint64 total_batches;
    uint64 avg_batch_us;
    uint64 avg_wait_us;
    uint64 avg_process_us;

    for (uint32 i = 0; i < OG_RBP_SESSION_COUNT; i++) {
        const rbp_read_worker_diag_t *diag = &rbp_context->read_diag[i];
        uint64 worker_batches = diag->ok_batches + diag->nopage_batches + diag->error_batches;

        if (worker_batches == 0 && diag->pages == 0 && diag->total_us == 0) {
            continue;
        }

        workers++;
        total.ok_batches += diag->ok_batches;
        total.nopage_batches += diag->nopage_batches;
        total.error_batches += diag->error_batches;
        total.pages += diag->pages;
        total.total_us += diag->total_us;
        total.connect_us += diag->connect_us;
        total.pipe_lock_us += diag->pipe_lock_us;
        total.ensure_conn_us += diag->ensure_conn_us;
        total.send_us += diag->send_us;
        total.wait_resp_us += diag->wait_resp_us;
        total.process_us += diag->process_us;
        rbp_add_apply_diag(&total.apply, &diag->apply);
    }

    total_batches = total.ok_batches + total.nopage_batches + total.error_batches;
    if (total_batches == 0) {
        return;
    }

    avg_batch_us = total.total_us / total_batches;
    avg_wait_us = total.wait_resp_us / total_batches;
    avg_process_us = total.process_us / total_batches;
    OG_LOG_RUN_INF("[RBP] read batch timing total: workers=%u ok=%llu nopage=%llu err=%llu pages=%llu "
                   "total_us=%llu connect_us=%llu send_us=%llu wait_resp_us=%llu process_us=%llu "
                   "pipe_lock_us=%llu ensure_conn_us=%llu avg_batch_us=%llu avg_wait_us=%llu avg_process_us=%llu",
                   workers, total.ok_batches, total.nopage_batches, total.error_batches, total.pages,
                   total.total_us, total.connect_us, total.send_us, total.wait_resp_us, total.process_us,
                   total.pipe_lock_us, total.ensure_conn_us, avg_batch_us, avg_wait_us, avg_process_us);

    for (uint32 i = 0; i < OG_RBP_SESSION_COUNT; i++) {
        const rbp_read_worker_diag_t *diag = &rbp_context->read_diag[i];
        uint64 worker_batches = diag->ok_batches + diag->nopage_batches + diag->error_batches;
        uint64 avg_total_us;

        if (worker_batches == 0 && diag->pages == 0 && diag->total_us == 0) {
            continue;
        }

        avg_total_us = (worker_batches == 0) ? 0 : diag->total_us / worker_batches;
        OG_LOG_RUN_INF("[RBP] read worker timing: q=%u ok=%llu nopage=%llu err=%llu pages=%llu "
                       "avg_total_us=%llu connect_us=%llu send_us=%llu wait_resp_us=%llu process_us=%llu "
                       "pipe_lock_us=%llu ensure_conn_us=%llu",
                       i, diag->ok_batches, diag->nopage_batches, diag->error_batches, diag->pages,
                       avg_total_us, diag->connect_us, diag->send_us, diag->wait_resp_us, diag->process_us,
                       diag->pipe_lock_us, diag->ensure_conn_us);
    }

    if (total.apply.resp_pages == 0 && total.apply.selected == 0 && total.apply.installed == 0 &&
        total.apply.not_required == 0) {
        return;
    }

    OG_LOG_RUN_INF("[RBP] partial apply total: resp=%llu not_required=%llu selected=%llu installed=%llu "
                   "no_expect=%llu ahead=%llu wrong_node=%llu hit=%llu usable=%llu old=%llu miss=%llu "
                   "other_status=%llu not_newer=%llu",
                   total.apply.resp_pages, total.apply.not_required, total.apply.selected, total.apply.installed,
                   total.apply.no_expect, total.apply.ahead, total.apply.wrong_node, total.apply.hit,
                   total.apply.usable, total.apply.old, total.apply.miss, total.apply.other_status,
                   total.apply.not_newer);
    OG_LOG_RUN_INF("[RBP] partial process total: select_update_us=%llu enter_page_us=%llu eval_us=%llu "
                   "replace_us=%llu mark_us=%llu leave_page_us=%llu",
                   total.apply.select_update_us, total.apply.enter_page_us, total.apply.eval_us,
                   total.apply.replace_us, total.apply.mark_us, total.apply.leave_page_us);
    OG_LOG_RUN_INF("[RBP] partial replace total: copy_us=%llu disk_check_us=%llu id_check_us=%llu pcn_check_us=%llu "
                   "dirty_us=%llu ckpt_enque_us=%llu ckpt_enque=%llu already_dirty=%llu",
                   total.apply.replace_copy_us, total.apply.replace_disk_check_us,
                   total.apply.replace_id_check_us, total.apply.replace_pcn_check_us,
                   total.apply.replace_dirty_us, total.apply.replace_ckpt_enque_us, total.apply.replace_ckpt_enque,
                   total.apply.replace_already_dirty);
    if (rbp_context->dtc_use_selected_batch && !rbp_context->dtc_need_selected_meta) {
        uint32 node_id = (rbp_context->dtc_read_node_count == 1) ?
            rbp_context->dtc_read_nodes[0] : OG_INVALID_ID32;
        OG_LOG_RUN_INF("[RBP] selected direct summary: node=%u required=%u requested=%llu returned=%llu "
                       "installed=%llu verified=%llu missing=%llu mismatch=%llu",
                       node_id, rbp_context->dtc_planned_required_count,
                       total.apply.selected_requested, total.apply.resp_pages, total.apply.installed,
                       total.apply.selected_verified, total.apply.selected_missing, total.apply.selected_mismatch);
    }
#endif
}

static void rbp_log_read_skip_summary(rbp_context_t *rbp_context)
{
#if !RBP_READ_HOT_DIAG
    (void)rbp_context;
    return;
#else
    rbp_read_skip_diag_t *diag = &rbp_context->read_skip_diag;
    uint64 partial_no_expect = (uint64)cm_atomic_get(&diag->partial_no_expect);
    uint64 partial_no_expect_no_item = (uint64)cm_atomic_get(&diag->partial_no_expect_no_item);
    uint64 partial_no_expect_not_required = (uint64)cm_atomic_get(&diag->partial_no_expect_not_required);
    uint64 partial_selected_scope = (uint64)cm_atomic_get(&diag->partial_selected_scope);
    uint64 partial_selected_scope_required = (uint64)cm_atomic_get(&diag->partial_selected_scope_required);
    uint64 partial_selected_scope_selected_valid =
        (uint64)cm_atomic_get(&diag->partial_selected_scope_selected_valid);
    uint64 partial_selected_scope_selected_pulled =
        (uint64)cm_atomic_get(&diag->partial_selected_scope_selected_pulled);
    uint64 partial_selected_scope_verified = (uint64)cm_atomic_get(&diag->partial_selected_scope_verified);
    uint64 partial_selected_scope_load_status =
        (uint64)cm_atomic_get(&diag->partial_selected_scope_load_status);
    uint64 no_expect_lsn = (uint64)cm_atomic_get(&diag->no_expect_lsn);
    uint64 nolog_space = (uint64)cm_atomic_get(&diag->nolog_space);
    uint64 total = partial_no_expect + partial_selected_scope + no_expect_lsn + nolog_space;

    if (total == 0) {
        return;
    }

    OG_LOG_RUN_INF("[RBP] read skip summary: total=%llu partial_no_expect=%llu no_item=%llu "
                   "not_required=%llu partial_selected_scope=%llu required=%llu selected_valid=%llu "
                   "selected_pulled=%llu verified=%llu load_status_nonzero=%llu no_expect_lsn=%llu "
                   "nolog_space=%llu",
                   total, partial_no_expect, partial_no_expect_no_item, partial_no_expect_not_required,
                   partial_selected_scope, partial_selected_scope_required, partial_selected_scope_selected_valid,
                   partial_selected_scope_selected_pulled, partial_selected_scope_verified,
                   partial_selected_scope_load_status, no_expect_lsn, nolog_space);
#endif
}

static uint64 rbp_dtc_read_skip_lfn_total(rbp_context_t *rbp_context)
{
    uint64 total = 0;
    uint16 node_count = (rbp_context->dtc_verify_node_count > 0) ?
        rbp_context->dtc_verify_node_count : rbp_context->dtc_read_node_count;

    for (uint32 i = 0; i < node_count; i++) {
        log_point_t *skip = (rbp_context->dtc_verify_node_count > 0) ?
            &rbp_context->dtc_verify_skip_points[i] : &rbp_context->dtc_read_skip_points[i];
        log_point_t *rcy = (rbp_context->dtc_verify_node_count > 0) ?
            &rbp_context->dtc_verify_rcy_points[i] : &rbp_context->dtc_read_rcy_points[i];
        if (rcy->lfn > skip->lfn) {
            total += (uint64)(rcy->lfn - skip->lfn);
        }
    }

    return total;
}

static int32 rbp_find_dtc_read_node(rbp_context_t *rbp_context, uint32 node_id)
{
    for (uint32 i = 0; i < rbp_context->dtc_read_node_count; i++) {
        if (rbp_context->dtc_read_nodes[i] == node_id) {
            return (int32)i;
        }
    }

    return -1;
}

static int32 rbp_find_dtc_verify_node(rbp_context_t *rbp_context, uint32 node_id)
{
    for (uint32 i = 0; i < rbp_context->dtc_verify_node_count; i++) {
        if (rbp_context->dtc_verify_nodes[i] == node_id) {
            return (int32)i;
        }
    }

    return -1;
}

static bool32 rbp_get_dtc_read_points(knl_session_t *session, uint32 node_id, log_point_t **skip_point,
                                      log_point_t **rcy_point, log_point_t **lrp_point)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    int32 idx = rbp_find_dtc_read_node(rbp_context, node_id);
    if (idx >= 0) {
        if (skip_point != NULL) {
            *skip_point = &rbp_context->dtc_read_skip_points[idx];
        }
        if (rcy_point != NULL) {
            *rcy_point = &rbp_context->dtc_read_rcy_points[idx];
        }
        if (lrp_point != NULL) {
            *lrp_point = &rbp_context->dtc_read_lrp_points[idx];
        }
        return OG_TRUE;
    }

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress || node_id >= OG_MAX_INSTANCES ||
        !DTC_RCY_CONTEXT->rbp_read_planned[node_id]) {
        return OG_FALSE;
    }

    if (skip_point != NULL) {
        *skip_point = &DTC_RCY_CONTEXT->rbp_begin_points[node_id];
    }
    if (rcy_point != NULL) {
        *rcy_point = &DTC_RCY_CONTEXT->rbp_rcy_points[node_id];
    }
    if (lrp_point != NULL) {
        *lrp_point = &DTC_RCY_CONTEXT->rbp_lrp_points[node_id];
    }
    return OG_TRUE;
}

static bool32 rbp_get_dtc_verify_points(knl_session_t *session, uint32 node_id, log_point_t **skip_point,
                                        log_point_t **rcy_point)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    int32 idx = rbp_find_dtc_verify_node(rbp_context, node_id);
    if (idx >= 0) {
        if (skip_point != NULL) {
            *skip_point = &rbp_context->dtc_verify_skip_points[idx];
        }
        if (rcy_point != NULL) {
            *rcy_point = &rbp_context->dtc_verify_rcy_points[idx];
        }
        return OG_TRUE;
    }

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress || node_id >= OG_MAX_INSTANCES ||
        !DTC_RCY_CONTEXT->rbp_jump_taken[node_id]) {
        return OG_FALSE;
    }

    if (skip_point != NULL) {
        *skip_point = &DTC_RCY_CONTEXT->rbp_skip_points[node_id];
    }
    if (rcy_point != NULL) {
        *rcy_point = &DTC_RCY_CONTEXT->rbp_rcy_points[node_id];
    }
    return OG_TRUE;
}

static void rbp_refresh_dtc_verify_epoch(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    dtc_rcy_context_t *dtc_rcy = NULL;
    uint32 count = 0;

    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return;
    }

    rbp_context->dtc_verify_node_count = 0;
    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < OG_MAX_INSTANCES; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_jump_taken[node_id]) {
            continue;
        }

        rbp_context->dtc_verify_nodes[count] = node_id;
        rbp_context->dtc_verify_skip_points[count] = dtc_rcy->rbp_skip_points[node_id];
        rbp_context->dtc_verify_rcy_points[count] = dtc_rcy->rbp_rcy_points[node_id];
        count++;
    }
    rbp_context->dtc_verify_node_count = (uint16)count;
}

static status_t rbp_save_dtc_read_epoch(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    dtc_rcy_context_t *dtc_rcy = NULL;
    uint32 count = 0;

    rbp_clear_dtc_read_epoch(rbp_context);
    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return OG_ERROR;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < OG_MAX_INSTANCES; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_window_valid[node_id] ||
            !dtc_rcy->rbp_read_planned[node_id]) {
            continue;
        }

        rbp_context->dtc_read_nodes[count] = node_id;
        rbp_context->dtc_read_skip_points[count] = dtc_rcy->rbp_begin_points[node_id];
        rbp_context->dtc_read_rcy_points[count] = dtc_rcy->rbp_rcy_points[node_id];
        rbp_context->dtc_read_lrp_points[count] = dtc_rcy->rbp_lrp_points[node_id];
        count++;
    }

    if (count == 0) {
        return OG_ERROR;
    }

    rbp_context->dtc_read_node_count = (uint16)count;
    rbp_context->dtc_read_active = OG_TRUE;
    OG_LOG_DEBUG_INF("[RBP] DTC partial read epoch saved: planned_nodes=%u planned_lfn_total=%llu",
                    (uint32)rbp_context->dtc_read_node_count,
                    rbp_dtc_read_skip_lfn_total(rbp_context));
    for (uint32 i = 0; i < rbp_context->dtc_read_node_count; i++) {
        OG_LOG_DEBUG_INF("[RBP] DTC read epoch node[%u]=%u begin_lfn=%llu rcy_lfn=%llu lrp_lfn=%llu",
                        i, rbp_context->dtc_read_nodes[i],
                        (uint64)rbp_context->dtc_read_skip_points[i].lfn,
                        (uint64)rbp_context->dtc_read_rcy_points[i].lfn,
                        (uint64)rbp_context->dtc_read_lrp_points[i].lfn);
    }
    return OG_SUCCESS;
}

static bool32 rbp_is_dtc_partial_read(knl_session_t *session)
{
    return (bool32)(DB_IS_CLUSTER(session) && g_dtc != NULL && OGRAC_PART_RECOVERY(session));
}

static uint64 rbp_get_item_expect_lsn(knl_session_t *session, rbp_analyse_item_t *item)
{
    if (item == NULL) {
        return 0;
    }
    if (rbp_is_dtc_partial_read(session) && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress) {
        return dtc_rcy_rbp_partial_expect_lsn(session, item->page_id, item->lsn);
    }
    return item->lsn;
}

/* v6 DTC recovery uses per-node RBP routing. Partial recovery needs it even when only one crashed node is recovered. */
static bool32 rbp_is_multi_node_rcy(knl_session_t *session)
{
    if (!DB_IS_CLUSTER(session) || g_dtc == NULL) {
        return OG_FALSE;
    }

    return OGRAC_PART_RECOVERY(session);
}

/*
* Background/page pull talks to planned nodes. They have entered READ_PHASE, so their page_cache is frozen even
* before their redo cursor reaches the actual jump point.
*/
static uint32 rbp_collect_active_rcy_nodes(knl_session_t *session, uint32 *node_ids, uint32 max_nodes)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 count = 0;
    dtc_rcy_context_t *dtc_rcy = NULL;

    if (!rbp_is_multi_node_rcy(session)) {
        return 0;
    }

    if (rbp_context->dtc_read_node_count > 0) {
        for (uint32 i = 0; i < rbp_context->dtc_read_node_count && count < max_nodes; i++) {
            node_ids[count++] = rbp_context->dtc_read_nodes[i];
        }
        return count;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < max_nodes; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES) {
            continue;
        }
        if (!dtc_rcy->rbp_window_valid[node_id] || !dtc_rcy->rbp_read_planned[node_id]) {
            continue;
        }
        node_ids[count++] = node_id;
    }
    return count;
}

static uint32 rbp_collect_verify_rcy_nodes(knl_session_t *session, uint32 *node_ids, uint32 max_nodes)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 count = 0;
    dtc_rcy_context_t *dtc_rcy = NULL;

    if (!rbp_is_multi_node_rcy(session)) {
        return 0;
    }

    rbp_refresh_dtc_verify_epoch(session);
    if (rbp_context->dtc_verify_node_count > 0) {
        for (uint32 i = 0; i < rbp_context->dtc_verify_node_count && count < max_nodes; i++) {
            node_ids[count++] = rbp_context->dtc_verify_nodes[i];
        }
        return count;
    }

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return 0;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < max_nodes; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->rbp_jump_taken[node_id]) {
            continue;
        }
        node_ids[count++] = node_id;
    }
    return count;
}

static inline bool32 rbp_aly_item_in_node_skip(rbp_analyse_item_t *item, uint32 node_id, log_point_t *skip_point,
                                               log_point_t *rcy_point)
{
    for (uint32 i = 0; i < RBP_ALY_TOUCH_SLOT_COUNT; i++) {
        if (item->touch_min[i] == 0 || RBP_ALY_TOUCH_NODE(item->touch_min[i]) != node_id) {
            continue;
        }

        /*
        * Verify if this page's touch range on the node intersects the skipped LFN window.
        * This is conservative and fixes the "first before skip, latest in tail, middle in skip" hole.
        */
        if (RBP_ALY_TOUCH_LFN(item->touch_max[i]) > skip_point->lfn &&
            RBP_ALY_TOUCH_LFN(item->touch_min[i]) <= rcy_point->lfn) {
            return OG_TRUE;
        }
    }

    /* Compatibility fallback for items created before touch ranges were populated. */
    if (item->node_id == node_id && item->lfn > skip_point->lfn && item->lfn <= rcy_point->lfn) {
        return OG_TRUE;
    }
    return (bool32)(item->first_node_id == node_id && item->first_lfn > skip_point->lfn &&
                    item->first_lfn <= rcy_point->lfn);
}

static inline bool32 rbp_aly_item_in_global_skip(rbp_analyse_item_t *item, uint64 skip_start, uint64 skip_end)
{
    for (uint32 i = 0; i < RBP_ALY_TOUCH_SLOT_COUNT; i++) {
        if (item->touch_min[i] == 0) {
            continue;
        }
        if (RBP_ALY_TOUCH_LFN(item->touch_max[i]) >= skip_start &&
            RBP_ALY_TOUCH_LFN(item->touch_min[i]) < skip_end) {
            return OG_TRUE;
        }
    }

    /* Compatibility fallback for items created before touch ranges were populated. */
    if (item->lfn > 0 && item->lfn >= skip_start && item->lfn < skip_end) {
        return OG_TRUE;
    }

    return (bool32)(item->first_lfn > 0 && item->first_lfn >= skip_start && item->first_lfn < skip_end);
}

static status_t rbp_append_dtc_planned_required_item(rbp_context_t *rbp_context, rbp_analyse_item_t *item)
{
    const uint32 max_capacity = (uint32)RBP_ALY_MAX_ITEM;
    uint32 new_capacity;
    rbp_analyse_item_t **new_items = NULL;

    if (rbp_context->dtc_planned_required_count < rbp_context->dtc_planned_required_capacity) {
        rbp_context->dtc_planned_required_items[rbp_context->dtc_planned_required_count++] = item;
        return OG_SUCCESS;
    }

    if (rbp_context->dtc_planned_required_capacity >= max_capacity) {
        OG_LOG_RUN_ERR("[RBP] planned required item cache is full: capacity=%u", max_capacity);
        return OG_ERROR;
    }

    new_capacity = (rbp_context->dtc_planned_required_capacity == 0) ? RBP_DTC_PLANNED_REQUIRED_INIT_CAPACITY :
        rbp_context->dtc_planned_required_capacity * RBP_DTC_PLANNED_REQUIRED_GROW_FACTOR;
    if (new_capacity < rbp_context->dtc_planned_required_capacity || new_capacity > max_capacity) {
        new_capacity = max_capacity;
    }

    size_t new_size = (size_t)new_capacity * sizeof(rbp_analyse_item_t *);
    new_items = (rbp_analyse_item_t **)malloc(new_size);
    if (new_items == NULL) {
        OG_LOG_RUN_ERR("[RBP] failed to grow planned required item cache: old_capacity=%u new_capacity=%u",
                       rbp_context->dtc_planned_required_capacity, new_capacity);
        return OG_ERROR;
    }
    if (rbp_context->dtc_planned_required_items != NULL && rbp_context->dtc_planned_required_count > 0) {
        size_t old_size = (size_t)rbp_context->dtc_planned_required_count * sizeof(rbp_analyse_item_t *);
        errno_t err = memcpy_sp(new_items, new_size, rbp_context->dtc_planned_required_items, old_size);
        if (err != EOK) {
            free(new_items);
            return OG_ERROR;
        }
    }
    CM_FREE_PTR(rbp_context->dtc_planned_required_items);
    rbp_context->dtc_planned_required_items = new_items;
    rbp_context->dtc_planned_required_capacity = new_capacity;
    rbp_context->dtc_planned_required_items[rbp_context->dtc_planned_required_count++] = item;
    return OG_SUCCESS;
}

static bool32 rbp_dtc_item_required_by_planned_nodes(knl_session_t *session, rbp_analyse_item_t *item,
    uint32 *node_ids, log_point_t **skip_points, log_point_t **rcy_points, uint32 node_count,
    bool32 partial_read, uint64 expect_lsn)
{
    for (uint32 i = 0; i < node_count; i++) {
        if (!rbp_aly_item_in_node_skip(item, node_ids[i], skip_points[i], rcy_points[i])) {
            continue;
        }

        if (partial_read && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress &&
            !dtc_rcy_rbp_partial_item_need_verify(session, item->page_id, node_ids[i], item->lfn, expect_lsn)) {
            continue;
        }
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t rbp_build_dtc_planned_required_items(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 node_ids[OG_MAX_INSTANCES];
    log_point_t *skip_points[OG_MAX_INSTANCES];
    log_point_t *rcy_points[OG_MAX_INSTANCES];
    uint32 node_count = rbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
    uint32 valid_count = 0;
    bool32 partial_read = rbp_is_dtc_partial_read(session);
    date_t begin_time = cm_now();

    rbp_clear_dtc_planned_required_items(rbp_context);
    rbp_context->dtc_planned_required_built = OG_TRUE;
    if (partial_read) {
        if (dtc_rcy_rbp_partial_build_required(session) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[RBP] partial planned required item cache build failed");
            return OG_ERROR;
        }
        rbp_context->dtc_planned_required_count = dtc_rcy_rbp_partial_required_count();
        OG_LOG_DEBUG_INF("[RBP] partial planned required item cache built: planned_nodes=%u required_items=%u "
                        "elapsed_us=%llu",
                        node_count, rbp_context->dtc_planned_required_count, (uint64)(cm_now() - begin_time));
        return OG_SUCCESS;
    }
    if (ctx->rbp_aly_items == NULL || node_count == 0) {
        OG_LOG_RUN_WAR("[RBP] planned required item cache is empty: aly_items=%p planned_nodes=%u",
                       (void *)ctx->rbp_aly_items, node_count);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < node_count; i++) {
        if (!rbp_get_dtc_read_points(session, node_ids[i], &skip_points[valid_count], &rcy_points[valid_count], NULL)) {
            continue;
        }
        node_ids[valid_count] = node_ids[i];
        valid_count++;
    }
    if (valid_count == 0) {
        OG_LOG_RUN_WAR("[RBP] planned required item cache is empty: no valid planned node points");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < RBP_ALY_MAX_ITEM; i++) {
        rbp_analyse_item_t *item = &ctx->rbp_aly_items[i];
        uint64 expect_lsn;

        if (item->lfn == 0 && item->first_lfn == 0) {
            continue;
        }

        expect_lsn = rbp_get_item_expect_lsn(session, item);
        if (!rbp_dtc_item_required_by_planned_nodes(session, item, node_ids, skip_points, rcy_points,
                                                   valid_count, partial_read, expect_lsn)) {
            continue;
        }

        if (rbp_append_dtc_planned_required_item(rbp_context, item) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    OG_LOG_RUN_INF("[RBP] planned required item cache built: planned_nodes=%u required_items=%u "
                   "capacity=%u elapsed_us=%llu",
                   valid_count, rbp_context->dtc_planned_required_count,
                   rbp_context->dtc_planned_required_capacity, (uint64)(cm_now() - begin_time));
    return OG_SUCCESS;
}

/* database send request to RBP */
static status_t rbp_knl_send_request_internal(cs_pipe_t *pipe, char *req_buf, rbp_buf_manager_t *manager,
                                              uint32 timeout)
{
    rbp_msg_hdr_t *request = (rbp_msg_hdr_t *)req_buf;
    status_t status;

    if (timeout == 0) {
        status = cs_write_stream(pipe, req_buf, request->msg_length, 0);
    } else {
        status = cs_write_stream_timeout(pipe, req_buf, request->msg_length, 0, timeout);
    }
    if (status == OG_SUCCESS) {
        return OG_SUCCESS;
    }

    OG_LOG_RUN_WAR("[RBP] failed to send request, type %u, fd %d timeout=%u",
                   request->msg_type, cs_get_socket_fd(pipe), timeout);
    if (manager != NULL) {
        cs_disconnect(pipe); // just close const pipe here, temp pipes are closed at rbp_stop_temp_connection
        manager->is_connected = OG_FALSE;
    }
    return OG_ERROR;
}

static status_t rbp_knl_send_request(cs_pipe_t *pipe, char *req_buf, rbp_buf_manager_t *manager)
{
    return rbp_knl_send_request_internal(pipe, req_buf, manager, 0);
}

static status_t rbp_knl_send_request_timeout(cs_pipe_t *pipe, char *req_buf, rbp_buf_manager_t *manager,
                                            uint32 timeout)
{
    return rbp_knl_send_request_internal(pipe, req_buf, manager, timeout);
}

/* database get reponse from RBP */
static status_t rbp_knl_wait_response(cs_pipe_t *pipe, char *resp_buf, int32 buf_size)
{
    int32 recv_size;
    int32 remain_size;
    rbp_msg_hdr_t msg;

    if (cs_read_stream(pipe, (char *)&msg, RBP_MAX_READ_WAIT_TIME, sizeof(rbp_msg_hdr_t), &recv_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[RBP] failed to receive message from RBP instance");
        return OG_ERROR;
    }

    if (sizeof(rbp_msg_hdr_t) != recv_size) {
        OG_LOG_RUN_ERR("[RBP] invalid recv_size %u received, expected size is %u",
                        recv_size, (int32)sizeof(rbp_msg_hdr_t));
        return OG_ERROR;
    }

    if (msg.msg_length < recv_size) {
        OG_LOG_RUN_ERR("[RBP] invalid message size %u received, which is smaller than %u",
                        msg.msg_length, recv_size);
        return OG_ERROR;
    }

    remain_size = msg.msg_length - recv_size;

    if (remain_size > (buf_size - sizeof(rbp_msg_hdr_t))) {
        OG_LOG_RUN_ERR("[RBP] invalid msg length size %u received", msg.msg_length);
        return OG_ERROR;
    }

    if (remain_size > 0) {
        if (cs_read_stream(pipe, resp_buf + sizeof(rbp_msg_hdr_t), RBP_MAX_READ_WAIT_TIME, remain_size,
                            &recv_size) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[RBP] failed to receive message type %u from RBP with size %u", msg.msg_type, remain_size);
            return OG_ERROR;
        }

        if (recv_size != (buf_size - sizeof(rbp_msg_hdr_t))) {
            OG_LOG_RUN_ERR("[RBP] invalid recv_size %u received, expected size is %u",
                            (uint32)recv_size, (uint32)(buf_size - sizeof(rbp_msg_hdr_t)));
            return OG_ERROR;
        }

        if (recv_size == 0) {
            OG_LOG_RUN_ERR("[RBP] peer close the connetion when read message body");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t rbp_notify_msg(knl_session_t *session, rbp_notify_msg_e msg, uint32 rbp_proc_id, rbp_msg_ack_t *ack)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_attr_t *rbp_attr = &session->kernel->rbp_attr;
    database_t *db = &session->kernel->db;
    bool32 temp_pipe = ((msg == MSG_RBP_READ_BEGIN) || (msg == MSG_RBP_READ_END));
    cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, temp_pipe);
    rbp_notify_req_t request;
    errno_t ret;

    // set msg header
    RBP_SET_MSG_HEADER(&request, RBP_REQ_NOTIFY_MSG, sizeof(rbp_notify_req_t), cs_get_socket_fd(pipe));
    // set msg body
    request.msg = msg;
    request.db_stat.db_role = db->ctrl.core.db_role;
    request.db_stat.db_open = db->status;
    ret = memcpy_sp(request.db_stat.local_host, CM_MAX_IP_LEN, rbp_attr->local_rbp_host, CM_MAX_IP_LEN);
    knl_securec_check(ret);

    if ((temp_pipe ?
        rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) :
        rbp_knl_send_request(pipe, (char *)&request, &rbp_context->rbp_buf_manager[rbp_proc_id])) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Demo / real RBP always sends rbp_msg_ack_t for NOTIFY; must drain or the next PAGE_READ wait sees 8-byte body. */
    rbp_msg_ack_t discard;
    return rbp_knl_wait_response(pipe, (char *)(ack != NULL ? ack : &discard), sizeof(rbp_msg_ack_t));
}

/* primary or statndy send heart beat to RBP */
static void rbp_timed_heart_beat(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    rbp_buf_manager_t *rbp_buf_manager = &rbp_context->rbp_buf_manager[rbp_proc_id];

    if (!KNL_RBP_ENABLE(session->kernel) || !rbp_buf_manager->is_connected) {
        return;
    }

    if (g_timer()->now - rbp_buf_manager->last_hb_time < RBP_HEARTBEAT_INTERVAL) {
        return;
    }

    cm_spin_lock(&rbp_buf_manager->fisrt_pipe_lock, NULL);
    if (rbp_notify_msg(session, MSG_RBP_HEART_BEAT, rbp_proc_id, NULL) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[RBP] heart beat with rbp failed");
    }
    cm_spin_unlock(&rbp_buf_manager->fisrt_pipe_lock);
    rbp_buf_manager->last_hb_time = g_timer()->now;
}

/* get page lsn record on disk */
static uint64 rbp_get_disk_lsn(knl_session_t *session, page_id_t page_id, bool32 ignore_crc)
{
    buf_ctrl_t ctrl;
    uint64 lsn;
    char *buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + OG_MAX_ALIGN_SIZE_4K);

    ctrl.page_id = page_id;
    ctrl.page = (page_head_t *)cm_aligned_buf(buf);

    if (buf_load_page_from_disk(session, &ctrl, page_id) != OG_SUCCESS) {
        if (ignore_crc) {
            /* Only verify disk lsn at rbp_replace_local_page in DEBUG mode, may be concurrent with ckpt */
            OG_LOG_RUN_WAR("[RBP] verify disk lsn failed because CRC failed");
            ctrl.page->lsn = OG_INVALID_LSN;
        } else {
            CM_ABORT(0, "[RBP] ABORT INFO: failed to load page %u-%u", page_id.file, page_id.page);
        }
    }

    lsn = ctrl.page->lsn;
    cm_pop(session->stack);
    return lsn;
}

/* replace database buffer page using RBP's page */
static void rbp_replace_local_page(knl_session_t *session, buf_ctrl_t *ctrl, page_head_t *rbp_page,
    rbp_read_apply_diag_t *diag)
{
    errno_t ret;
    date_t step_begin;

#if defined(LOG_DIAG) && defined(RBP_VERIFY_DISK_LSN_ON_REPLACE)
    step_begin = cm_now();
    uint64 disk_page_lsn = rbp_get_disk_lsn(session, ctrl->page_id, OG_TRUE);
    uint64 rbp_page_lsn = PAGE_GET_LSN(rbp_page);
    knl_panic_log(disk_page_lsn <= rbp_page_lsn, "disk_page_lsn is bigger than rbp_page_lsn, panic info: "
                   "ctrl_page %u-%u type %u, rbp_page %u-%u type %u disk_page_lsn %llu rbp_page_lsn %llu",
                   ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, AS_PAGID(rbp_page->id).file,
                   AS_PAGID(rbp_page->id).page, rbp_page->type, disk_page_lsn, rbp_page_lsn);
    if (diag != NULL) {
        diag->replace_disk_check_us += (uint64)(cm_now() - step_begin);
    }
#endif

    if (diag != NULL) {
        step_begin = cm_now();
    }
    ret = memcpy_sp(ctrl->page, DEFAULT_PAGE_SIZE(session), rbp_page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    if (diag != NULL) {
        diag->replace_copy_us += (uint64)(cm_now() - step_begin);
        step_begin = cm_now();
    }
    knl_panic_log(IS_SAME_PAGID(AS_PAGID(ctrl->page->id), ctrl->page_id), "ctrl page's id and ctrl's page_id are not "
                   "same, panic info: ctrl page's id %u-%u ctrl's page_id %u-%u type %u", AS_PAGID(ctrl->page->id).file,
                   AS_PAGID(ctrl->page->id).page, ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
    if (diag != NULL) {
        diag->replace_id_check_us += (uint64)(cm_now() - step_begin);
        step_begin = cm_now();
    }
    knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "page pcn is abnormal, panic info: page %u-%u type %u",
                   ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
    if (diag != NULL) {
        diag->replace_pcn_check_us += (uint64)(cm_now() - step_begin);
        step_begin = cm_now();
    }
    ctrl->rbp_ctrl->is_from_rbp = OG_TRUE;
    if (!ctrl->is_dirty) {
        ctrl->is_dirty = OG_TRUE;
        if (diag != NULL) {
            diag->replace_dirty_us += (uint64)(cm_now() - step_begin);
            diag->replace_ckpt_enque++;
            step_begin = cm_now();
        }
        ckpt_enque_one_page(session, ctrl);
        if (diag != NULL) {
            diag->replace_ckpt_enque_us += (uint64)(cm_now() - step_begin);
        }
    } else if (diag != NULL) {
        diag->replace_dirty_us += (uint64)(cm_now() - step_begin);
        diag->replace_already_dirty++;
    }
}

/*
  * process response for database read one page from RBP
  * if rbp page can be used, replace local page as rbp page
  */
static rbp_page_status_e rbp_process_read_resp(knl_session_t *session, rbp_read_resp_t *response, buf_ctrl_t *ctrl)
{
    uint64 rbp_page_lsn;
    uint64 curr_page_lsn;
    rbp_page_status_e page_status = RBP_PAGE_MISS;
    char *rbp_page = response->block;

    if (response->result == RBP_READ_RESULT_OK) {
        rbp_page_lsn = PAGE_GET_LSN(rbp_page);
        curr_page_lsn = PAGE_GET_LSN(ctrl->page);
#ifdef RBP_VERBOSE_TRACE
        {
            uint32 psz = DEFAULT_PAGE_SIZE(session);
            page_head_t *gh = (page_head_t *)rbp_page;
            uint16 cks = PAGE_CHECKSUM(rbp_page, psz);
            /* Avoid stale TCP/peer errors leaking from cm_get_error into INFO logs. */
            cm_reset_error();
            OG_LOG_RUN_INF(
                "[RBP] PAGE_READ recv from RBP: page %u-%u trunc_lfn %llu rbp_lsn %llu local_lsn %llu pcn %u checksum "
                "0x%04x | RBP-CORR fid=%u pn=%u seq=%llu lfn=%llu inst=0",
                ctrl->page_id.file, ctrl->page_id.page, (uint64)response->rbp_trunc_point.lfn, rbp_page_lsn,
                curr_page_lsn, gh->pcn, (uint32)cks, ctrl->page_id.file, ctrl->page_id.page, rbp_page_lsn,
                (uint64)response->rbp_trunc_point.lfn);
        }
#endif
        page_status = rbp_page_verify(session, response->pageid, rbp_page_lsn, curr_page_lsn);
        if (rbp_page_lsn > curr_page_lsn && (page_status == RBP_PAGE_HIT || page_status == RBP_PAGE_USABLE)) {
            rbp_replace_local_page(session, ctrl, (page_head_t *)rbp_page, NULL);
            ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
        }
    }

    if (response->result == RBP_READ_RESULT_ERROR) {
        rbp_page[RBP_MSG_LEN] = '\0'; // Write at most 64 byte of page head to run log
        page_status = RBP_PAGE_ERROR;
        OG_LOG_RUN_WAR("[RBP] failed to read page(%u, %u) from RBP, error: %s",
                        ctrl->page_id.file, ctrl->page_id.page, rbp_page);
    }

    return page_status;
}

/*
  * some rbp page can not be repalced as local page, inlcude
  * 1. rbp page is not in standby redo, mostly this rbp page too old and page lfn < standby rcy point
  * 2. rbp page has been verifyed, mostly means that has been relapced as local page
  * 3. space or datafile is not online
  * 4. page is nologging page, except space head page
  */
static bool32 rbp_need_skip(knl_session_t *session, rbp_page_item_t *page_item)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    rbp_analyse_item_t *item = NULL;

    item = rbp_aly_get_page_item(session, page_item->page_id);
    /* no redo log for the page, page can be discard */
    if (item == NULL) {
        return OG_TRUE;
    }
    knl_panic_log(item->lsn != OG_INVALID_LSN, "lsn is NULL.");
    if (item->is_verified == OG_TRUE && !rbp_is_multi_node_rcy(session)) {
        return OG_TRUE;
    }

    df = DATAFILE_GET(session, page_item->page_id.file);
    space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df) || !df->ctrl->used) {
        item->is_verified = OG_TRUE;
        return OG_TRUE;
    }

    if (SPACE_IS_NOLOGGING(space)) {
        item->is_verified = OG_TRUE;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static uint64 rbp_get_local_verify_lsn(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;
    uint64 local_lsn = 0;
    uint8 saved_queue_index = session->rbp_queue_index;

    /*
    * rbp_knl_end_read() holds buf_read_lock[] while verifying. Entering the page must not trigger
    * buf_check_page_version()->PAGE_READ, otherwise this session can self-deadlock on the same read lock.
    */
    session->rbp_queue_index = 1;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    session->rbp_queue_index = saved_queue_index;

    ctrl = session->curr_page_ctrl;
    if (ctrl != NULL && ctrl->page->lsn == OG_INVALID_LSN) {
        ctrl->rbp_ctrl->is_from_rbp = OG_FALSE;
        if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[RBP] verify failed to load local page %u-%u from disk", page_id.file, page_id.page);
        }
    }
    if (ctrl != NULL && ctrl->page->lsn != OG_INVALID_LSN) {
        local_lsn = ctrl->page->lsn;
    }
    buf_leave_page(session, OG_FALSE);
    return local_lsn;
}

static uint64 rbp_get_partial_verify_lsn(knl_session_t *session, rbp_partial_item_t *item, uint64 expect_lsn)
{
    buf_ctrl_t *ctrl = NULL;
    uint64 local_lsn = 0;
    uint8 saved_queue_index = session->rbp_queue_index;

    if (item == NULL || expect_lsn == 0) {
        return 0;
    }

    session->rbp_queue_index = 1;
    buf_enter_page(session, item->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    session->rbp_queue_index = saved_queue_index;

    ctrl = session->curr_page_ctrl;
    if (ctrl != NULL && ctrl->page->lsn == OG_INVALID_LSN) {
        ctrl->rbp_ctrl->is_from_rbp = OG_FALSE;
        if (buf_load_page_from_disk(session, ctrl, item->page_id) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[RBP] partial verify failed to load local page %u-%u from disk",
                           item->page_id.file, item->page_id.page);
        }
    }

    if (ctrl != NULL && ctrl->page->lsn != OG_INVALID_LSN) {
        local_lsn = PAGE_GET_LSN(ctrl->page);
    }

    buf_leave_page(session, OG_FALSE);
    return local_lsn;
}

static void rbp_verify_partial_skiped_redo_pages(knl_session_t *session, uint32 node_count, uint64 skipped_lfn_total)
{
    uint32 scan_count = dtc_rcy_rbp_partial_required_count();
    uint32 in_window = 0;
    uint32 miss_cnt = 0;
    uint32 sample = 0;

    if (node_count == 0) {
        OG_LOG_RUN_INF("[RBP] partial verify summary: no jumped RBP nodes, skip final verification, "
                       "required_items=%u skipped_lfn_total=%llu",
                       scan_count, skipped_lfn_total);
        return;
    }

    knl_panic_log(OGRAC_PART_RECOVERY(session) && OGRAC_SESSION_IN_RECOVERY(session),
                  "[RBP] partial verify must run on partial recovery session, dtc_session_type=%u",
                  (uint32)session->dtc_session_type);

    for (uint32 i = 0; i < scan_count; i++) {
        rbp_partial_item_t *item = dtc_rcy_rbp_partial_required_item(i);
        uint32 verify_node_id = OG_INVALID_ID32;
        uint64 expect_lsn;
        uint64 local_lsn = 0;
        bool32 verified;

        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            continue;
        }
        if (!dtc_rcy_rbp_partial_item_in_jumped_window(session, item, &verify_node_id)) {
            continue;
        }

        in_window++;
        expect_lsn = dtc_rcy_rbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            miss_cnt++;
            OG_LOG_RUN_WAR("[RBP] partial verify miss: page %u-%u has zero expect_lsn, expect_lfn=%llu "
                           "enter_upper_lsn=%llu best_lsn=%llu best_source_node=%u seen_bitmap=0x%llx",
                           item->page_id.file, item->page_id.page, (uint64)item->expect_lfn,
                           (uint64)item->rcy_item->last_dirty_lsn, (uint64)item->best_lsn,
                           (uint32)item->best_source_node, (uint64)item->seen_node_bitmap);
            continue;
        }
        verified = item->verified;
        if (!verified) {
            local_lsn = rbp_get_partial_verify_lsn(session, item, expect_lsn);
            verified = (bool32)(local_lsn >= expect_lsn);
        }
        if (verified) {
            dtc_rcy_rbp_partial_mark_item_verified(item);
        } else {
            miss_cnt++;
            if (sample < RBP_PARTIAL_VERIFY_SAMPLE_LIMIT) {
                OG_LOG_RUN_WAR("[RBP] partial verify miss sample[%u]: page %u-%u node=%u expect_lsn=%llu "
                               "expect_lfn=%llu enter_upper_lsn=%llu best_lsn=%llu best_source_node=%u "
                               "seen_bitmap=0x%llx local_lsn=%llu overflow=%u "
                               "touch0=%u:%llu-%llu touch1=%u:%llu-%llu touch2=%u:%llu-%llu touch3=%u:%llu-%llu",
                               sample, item->page_id.file, item->page_id.page, verify_node_id,
                               (uint64)expect_lsn, (uint64)item->expect_lfn,
                               (uint64)item->rcy_item->last_dirty_lsn,
                               (uint64)item->best_lsn, (uint32)item->best_source_node,
                               (uint64)item->seen_node_bitmap, (uint64)local_lsn, (uint32)item->touch_overflow,
                                (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT0].node_id,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT0].touch_min_lfn,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT0].touch_max_lfn,
                                (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT1].node_id,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT1].touch_min_lfn,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT1].touch_max_lfn,
                                (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT2].node_id,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT2].touch_min_lfn,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT2].touch_max_lfn,
                                (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT3].node_id,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT3].touch_min_lfn,
                                (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT3].touch_max_lfn);
                sample++;
            }
        }
    }

    OG_LOG_RUN_INF("[RBP] partial verify summary: skipped_lfn_total=%llu items=%u miss=%u scanned=%u",
                   skipped_lfn_total, in_window, miss_cnt, scan_count);
    if (miss_cnt != 0) {
        rbp_knl_mark_dtc_fallback(session, OG_INVALID_ID32, RBP_READ_RESULT_ERROR,
                                  RBP_DTC_FALLBACK_VERIFY_MISS);
        OG_LOG_RUN_ERR("[RBP] partial verify failed, fallback to redo: miss_cnt=%u in_window=%u scanned=%u "
                       "skipped_lfn_total=%llu",
                       miss_cnt, in_window, scan_count, skipped_lfn_total);
    }
}

static void rbp_log_partial_ahead_detail(knl_session_t *session, rbp_partial_item_t *item, uint32 source_node,
                                        uint64 rbp_page_lsn, uint64 expect_lsn)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint64 sample;

    if (item == NULL || rbp_page_lsn <= expect_lsn) {
        return;
    }

    sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_partial_ahead_detail);
    if (sample > RBP_READ_SAMPLE_LIMIT) {
        return;
    }

    OG_LOG_RUN_WAR("[RBP] partial ahead detail sample[%llu/%u]: page %u-%u source_node=%u rbp_lsn=%llu "
                   "expect_lsn=%llu "
                   "expect_lfn=%llu enter_upper_lsn=%llu seen_bitmap=0x%llx best_lsn=%llu "
                   "best_source_node=%u overflow=%u "
                   "touch0=%u:%llu-%llu touch1=%u:%llu-%llu touch2=%u:%llu-%llu touch3=%u:%llu-%llu "
                   "redo_end_lfn=%llu rbp_aly_lsn=%llu",
                   sample, RBP_READ_SAMPLE_LIMIT, item->page_id.file, item->page_id.page, source_node,
                   (uint64)rbp_page_lsn,
                   (uint64)expect_lsn, (uint64)item->expect_lfn,
                   (uint64)(item->rcy_item == NULL ? 0 : item->rcy_item->last_dirty_lsn),
                   (uint64)item->seen_node_bitmap, (uint64)item->best_lsn, (uint32)item->best_source_node,
                   (uint32)item->touch_overflow,
                    (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT0].node_id,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT0].touch_min_lfn,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT0].touch_max_lfn,
                    (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT1].node_id,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT1].touch_min_lfn,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT1].touch_max_lfn,
                    (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT2].node_id,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT2].touch_min_lfn,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT2].touch_max_lfn,
                    (uint32)item->touches[RBP_TOUCH_SAMPLE_SLOT3].node_id,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT3].touch_min_lfn,
                    (uint64)item->touches[RBP_TOUCH_SAMPLE_SLOT3].touch_max_lfn, (uint64)redo->redo_end_point.lfn,
                   (uint64)redo->rbp_aly_lsn);
}

/*
* Begin/end partial recovery session identity for rbp_bg only while touching DTC buffer/DCS paths.
* Callers must always pair begin with end (including after future early returns that skip buf_leave_page).
*/
static void rbp_partial_bg_identity_begin(knl_session_t *session, dtc_session_type_e *old_type, bool32 *patched)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    *old_type = session->dtc_session_type;
    *patched = (bool32)(SESSION_IS_RBP_BG(session) && KNL_RECOVERY_WITH_RBP(session->kernel) &&
        rbp_is_dtc_partial_read(session) && dtc_rcy->in_progress);
    if (*patched) {
        session->dtc_session_type = dtc_rcy->paral_rcy ? DTC_PART_RCY_PARAL : DTC_PART_RCY;
    }
}

static void rbp_partial_bg_identity_end(knl_session_t *session, dtc_session_type_e old_type, bool32 patched)
{
    if (patched) {
        session->dtc_session_type = old_type;
    }
}

static void rbp_count_partial_page_status(rbp_read_apply_diag_t *diag, rbp_page_status_e page_status,
    bool32 not_newer)
{
    if (diag == NULL) {
        return;
    }

    switch (page_status) {
        case RBP_PAGE_HIT:
            diag->hit++;
            break;
        case RBP_PAGE_USABLE:
            diag->usable++;
            break;
        case RBP_PAGE_OLD:
            diag->old++;
            break;
        case RBP_PAGE_MISS:
            diag->miss++;
            break;
        default:
            diag->other_status++;
            break;
    }

    if (not_newer) {
        diag->not_newer++;
    }
}

typedef struct st_rbp_partial_selected_baseline_decision {
    bool32 skip;
    bool32 ahead;
    bool32 install;
    bool32 mark_selected_pulled;
    bool32 mark_verified;
    rbp_page_status_e status;
} rbp_partial_selected_baseline_decision_t;

/*
* Partial selected baseline: rbp_lsn <= expect_lsn is a RBP baseline for skipped redo, not an OLD/USABLE
* disk comparison. Never returns RBP_PAGE_OLD.
*/
static void rbp_partial_selected_baseline_decide(rbp_partial_item_t *item, uint64 curr_lsn, uint64 rbp_lsn,
    uint64 expect_lsn, rbp_partial_selected_baseline_decision_t *decision)
{
    errno_t ret;

    knl_panic_log(decision != NULL, "partial selected baseline decision is NULL");
    ret = memset_sp(decision, sizeof(rbp_partial_selected_baseline_decision_t), 0,
                    sizeof(rbp_partial_selected_baseline_decision_t));
    knl_securec_check(ret);
    decision->status = RBP_PAGE_MISS;

    if (item == NULL || expect_lsn == 0) {
        decision->skip = OG_TRUE;
        return;
    }

    /*
    * selected_pulled is a barrier: never re-PAGE_READ or reinstall baseline.
    * If the page body was evicted (curr INVALID), return MISS so upper layers load disk
    * (tail redo may have advanced the on-disk image beyond the old RBP baseline).
    */
    if (item->verified || item->selected_pulled) {
        decision->skip = OG_TRUE;
        if (curr_lsn == OG_INVALID_LSN) {
            decision->status = RBP_PAGE_MISS;
            return;
        }
        if (curr_lsn >= expect_lsn) {
            if (!item->verified) {
                decision->mark_verified = OG_TRUE;
            }
            decision->status = RBP_PAGE_HIT;
            return;
        }
        decision->status = RBP_PAGE_USABLE;
        return;
    }

    if (rbp_lsn > expect_lsn) {
        decision->skip = OG_TRUE;
        decision->ahead = OG_TRUE;
        decision->status = RBP_PAGE_MISS;
        return;
    }

    decision->mark_selected_pulled = OG_TRUE;

    if (curr_lsn >= expect_lsn) {
        decision->mark_verified = OG_TRUE;
        decision->status = RBP_PAGE_HIT;
        return;
    }

    if (curr_lsn != OG_INVALID_LSN && curr_lsn >= rbp_lsn) {
        decision->status = RBP_PAGE_USABLE;
        return;
    }

    if (rbp_lsn <= expect_lsn) {
        decision->install = OG_TRUE;
        if (rbp_lsn == expect_lsn) {
            decision->mark_verified = OG_TRUE;
            decision->status = RBP_PAGE_HIT;
        } else {
            decision->status = RBP_PAGE_USABLE;
        }
    }
}

static rbp_page_status_e rbp_partial_selected_baseline_apply(knl_session_t *session, buf_ctrl_t *ctrl,
    rbp_partial_item_t *item, page_head_t *rbp_page, uint64 rbp_page_lsn, uint64 expect_lsn,
    rbp_read_apply_diag_t *diag, uint32 *installed, uint32 *verified_out, bool32 *not_newer)
{
    rbp_partial_selected_baseline_decision_t decision;
    uint64 curr_page_lsn = PAGE_GET_LSN(ctrl->page);
    date_t step_begin;
    bool32 replaced = OG_FALSE;

    rbp_partial_selected_baseline_decide(item, curr_page_lsn, rbp_page_lsn, expect_lsn, &decision);
    if (not_newer != NULL) {
        *not_newer = (bool32)(curr_page_lsn != OG_INVALID_LSN && rbp_page_lsn <= curr_page_lsn);
    }

    if (decision.skip) {
        ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
        if (!decision.ahead && decision.mark_verified) {
            dtc_rcy_rbp_partial_mark_item_verified(item);
            if (verified_out != NULL) {
                (*verified_out)++;
            }
        }
        ctrl->rbp_ctrl->page_status = decision.status;
        return decision.status;
    }

    if (decision.install && rbp_page != NULL &&
        (curr_page_lsn == OG_INVALID_LSN || rbp_page_lsn > curr_page_lsn)) {
        if (diag != NULL) {
            step_begin = cm_now();
        }
        rbp_replace_local_page(session, ctrl, rbp_page, diag);
        replaced = OG_TRUE;
        if (diag != NULL) {
            diag->replace_us += (uint64)(cm_now() - step_begin);
        }
        if (installed != NULL) {
            (*installed)++;
        }
    }

    if (diag != NULL) {
        step_begin = cm_now();
    }
    ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
    ctrl->rbp_ctrl->page_status = decision.status;
    if (decision.mark_selected_pulled) {
        dtc_rcy_rbp_partial_mark_selected_pulled(item, rbp_page_lsn);
    }
    if (decision.mark_verified) {
        dtc_rcy_rbp_partial_mark_item_verified(item);
        if (verified_out != NULL) {
            (*verified_out)++;
        }
    }
    if (diag != NULL) {
        diag->mark_us += (uint64)(cm_now() - step_begin);
    }

    (void)replaced;
    return decision.status;
}

/*
* Selected direct batch install: baseline decision only (no rbp_eval, no disk fallback on INVALID).
*/
static rbp_page_status_e rbp_partial_selected_batch_install_page(knl_session_t *session, page_id_t page_id,
    rbp_page_item_t *rbp_page, rbp_partial_item_t *item, uint64 expect_lsn, uint64 rbp_page_lsn, uint32 *installed,
    uint32 *verified_out, bool32 *not_newer, rbp_read_apply_diag_t *diag)
{
    buf_ctrl_t *ctrl = NULL;
    rbp_page_status_e page_status;
    dtc_session_type_e old_type;
    bool32 patched = OG_FALSE;
    date_t step_begin;

    rbp_partial_bg_identity_begin(session, &old_type, &patched);

    if (diag != NULL) {
        step_begin = cm_now();
    }
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    if (diag != NULL) {
        diag->enter_page_us += (uint64)(cm_now() - step_begin);
    }

    ctrl = session->curr_page_ctrl;
    page_status = rbp_partial_selected_baseline_apply(session, ctrl, item, (page_head_t *)rbp_page->block, rbp_page_lsn,
        expect_lsn, diag, installed, verified_out, not_newer);

    if (diag != NULL) {
        step_begin = cm_now();
    }
    buf_leave_page(session, OG_FALSE);
    if (diag != NULL) {
        diag->leave_page_us += (uint64)(cm_now() - step_begin);
    }

    rbp_partial_bg_identity_end(session, old_type, patched);
    return page_status;
}

/*
* Partial BATCH_READ installs page bodies on rbp_bg sessions. Temporarily use the same
* dtc_session_type as partial recovery workers so dtc_dcs_readable / DCS paths match recovery semantics.
* Scope is strictly buf_enter_page .. buf_leave_page for one page.
* installed: optional counter when a replace happened; verified_out: optional, incremented on RBP_PAGE_HIT.
*/
static rbp_page_status_e rbp_partial_batch_read_install_page(knl_session_t *session, page_id_t page_id,
    rbp_page_item_t *rbp_page, rbp_partial_item_t *item, uint64 expect_lsn, uint64 rbp_page_lsn, uint32 *installed,
    uint32 *verified_out, bool32 *not_newer, rbp_read_apply_diag_t *diag)
{
    buf_ctrl_t *ctrl = NULL;
    uint64 curr_page_lsn;
    rbp_page_status_e page_status;
    dtc_session_type_e old_type;
    bool32 patched = OG_FALSE;
    bool32 installed_from_rbp = OG_FALSE;
    date_t step_begin;

    rbp_partial_bg_identity_begin(session, &old_type, &patched);

    if (diag != NULL) {
        step_begin = cm_now();
    }
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    if (diag != NULL) {
        diag->enter_page_us += (uint64)(cm_now() - step_begin);
    }

    ctrl = session->curr_page_ctrl;
    curr_page_lsn = PAGE_GET_LSN(ctrl->page);
    if (diag != NULL) {
        step_begin = cm_now();
    }
    page_status = rbp_eval_page_candidate(session, page_id, rbp_page_lsn, curr_page_lsn, expect_lsn, OG_TRUE);
    if (diag != NULL) {
        diag->eval_us += (uint64)(cm_now() - step_begin);
    }
    if (not_newer != NULL) {
        *not_newer = (bool32)(curr_page_lsn != OG_INVALID_LSN && rbp_page_lsn <= curr_page_lsn);
    }
    if ((page_status == RBP_PAGE_HIT || page_status == RBP_PAGE_USABLE) && rbp_page_lsn > curr_page_lsn) {
        if (diag != NULL) {
            step_begin = cm_now();
        }
        rbp_replace_local_page(session, ctrl, (page_head_t *)rbp_page->block, diag);
        installed_from_rbp = OG_TRUE;
        if (diag != NULL) {
            diag->replace_us += (uint64)(cm_now() - step_begin);
        }
        if (installed != NULL) {
            (*installed)++;
        }
    }

    if (!installed_from_rbp && ctrl->page->lsn == OG_INVALID_LSN) {
        rbp_context_t *rbp_context = &session->kernel->rbp_context;
        uint64 sample;

        ctrl->rbp_ctrl->is_from_rbp = OG_FALSE;
        if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
            CM_ABORT(0, "[RBP] ABORT INFO: partial RBP background thread failed to load %u-%u from disk",
                    page_id.file, page_id.page);
        }
        sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_partial_disk_fallback);
        if (sample <= RBP_READ_SAMPLE_LIMIT) {
            OG_LOG_RUN_INF("[RBP] partial disk fallback sample[%llu/%u]: page=%u-%u when RBP page is not installed",
                           sample, RBP_READ_SAMPLE_LIMIT, page_id.file, page_id.page);
        }
    }

    if (diag != NULL) {
        step_begin = cm_now();
    }
    ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
    ctrl->rbp_ctrl->page_status = page_status;
    dtc_rcy_rbp_partial_mark_selected_pulled(item, rbp_page_lsn);
    if (page_status == RBP_PAGE_HIT) {
        dtc_rcy_rbp_partial_mark_item_verified(item);
        if (verified_out != NULL) {
            (*verified_out)++;
        }
    }
    if (diag != NULL) {
        diag->mark_us += (uint64)(cm_now() - step_begin);
        step_begin = cm_now();
    }
    buf_leave_page(session, OG_FALSE);
    if (diag != NULL) {
        diag->leave_page_us += (uint64)(cm_now() - step_begin);
    }

    rbp_partial_bg_identity_end(session, old_type, patched);
    return page_status;
}

static void rbp_process_batch_read_resp_partial(knl_session_t *session, rbp_batch_read_resp_t *resp,
                                                uint32 source_node, rbp_read_apply_diag_t *diag)
{
    rbp_page_item_t *rbp_batch = resp->pages;
    rbp_page_item_t *rbp_page = NULL;
    page_id_t page_id;
    uint64 rbp_page_lsn;
    uint64 expect_lsn;
    rbp_partial_item_t *item = NULL;
    uint32 node_ids[OG_MAX_INSTANCES];
    uint32 node_count = rbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
    uint32 installed = 0;

    if (diag != NULL) {
        diag->resp_pages += resp->count;
    }

    for (uint32 i = 0; i < resp->count; i++) {
        rbp_page = &rbp_batch[i];
        item = dtc_rcy_rbp_partial_get_item(rbp_page->page_id);
        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            if (diag != NULL) {
                diag->not_required++;
            }
            continue;
        }

        expect_lsn = dtc_rcy_rbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            if (diag != NULL) {
                diag->no_expect++;
            }
            continue;
        }

        page_id = AS_PAGID(((page_head_t *)rbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(rbp_page->page_id, page_id), "rbp_page's page_id and rbp_page block's id are not "
                      "same, panic info: rbp_page %u-%u, rbp_page block %u-%u", rbp_page->page_id.file,
                      rbp_page->page_id.page, page_id.file, page_id.page);

        rbp_page_lsn = PAGE_GET_LSN(rbp_page->block);
        item->seen_node_bitmap |= ((uint64)1 << (source_node % RBP_NODE_BITMAP_BITS));
        if (rbp_page_lsn > expect_lsn) {
            if (diag != NULL) {
                diag->ahead++;
            }
            rbp_log_partial_ahead_detail(session, item, source_node, rbp_page_lsn, expect_lsn);
            continue;
        }

        if (node_count > 1 && (!item->selected_valid || item->selected_node != source_node)) {
            if (diag != NULL) {
                diag->wrong_node++;
            }
            continue;
        }

        if (diag != NULL) {
            bool32 not_newer = OG_FALSE;
            rbp_page_status_e page_status;
            date_t step_begin = cm_now();

            dtc_rcy_rbp_partial_update_selected(item, source_node, rbp_page_lsn);
            diag->select_update_us += (uint64)(cm_now() - step_begin);
            diag->selected++;
            page_status = rbp_partial_batch_read_install_page(session, page_id, rbp_page, item, expect_lsn,
                rbp_page_lsn, &installed, NULL, &not_newer, diag);
            rbp_count_partial_page_status(diag, page_status, not_newer);
        } else {
            dtc_rcy_rbp_partial_update_selected(item, source_node, rbp_page_lsn);
            rbp_partial_batch_read_install_page(session, page_id, rbp_page, item, expect_lsn, rbp_page_lsn,
                &installed, NULL, NULL, NULL);
        }
    }

    if (diag != NULL) {
        diag->installed += installed;
    }
}

/* process response for background thread read page batch from RBP */
static void rbp_process_batch_read_resp(knl_session_t *session, rbp_batch_read_resp_t *resp)
{
    rbp_page_item_t *rbp_batch = resp->pages;
    rbp_page_item_t *rbp_page = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_id_t page_id;
    uint64 rbp_page_lsn;
    uint64 curr_page_lsn;
    uint32 skipped_cnt = 0;
    uint32 replace_cnt = 0;
    uint32 fallback_disk_cnt = 0;
    uint32 verify_before = 0;
    uint32 verify_after = 0;

    if (resp->result == RBP_READ_RESULT_ERROR) {
        resp->msg[RBP_MSG_LEN - 1] = '\0';
        OG_LOG_RUN_WAR("[RBP] kernel batch read rbp pages error: %s", resp->msg);
        return;
    }

    for (uint32 i = 0; i < resp->count; i++) {
        rbp_page = &rbp_batch[i];
        rbp_analyse_item_t *item = rbp_aly_get_page_item(session, rbp_page->page_id);
        if (item != NULL && item->is_verified) {
            verify_before++;
        }

        if (rbp_need_skip(session, rbp_page)) {
            skipped_cnt++;
            item = rbp_aly_get_page_item(session, rbp_page->page_id);
            if (item != NULL && item->is_verified) {
                verify_after++;
            }
            continue;
        }

        page_id = AS_PAGID(((page_head_t *)rbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(rbp_page->page_id, page_id), "rbp_page's page_id and rbp_page block's id are not "
                       "same, panic info: rbp_page %u-%u, rbp_page block %u-%u", rbp_page->page_id.file,
                       rbp_page->page_id.page, page_id.file, page_id.page);

#ifdef RBP_VERBOSE_TRACE
        {
            uint32 psz = DEFAULT_PAGE_SIZE(session);
            page_head_t *bh = (page_head_t *)rbp_page->block;
            uint16 cks = PAGE_CHECKSUM(rbp_page->block, psz);
            cm_reset_error();
            OG_LOG_RUN_INF("[RBP] BATCH_READ recv from RBP: page %u-%u item_lfn %llu rbp_lsn %llu pcn %u checksum "
                            "0x%04x writer_inst %u | RBP-CORR fid=%u pn=%u seq=%llu lfn=%llu inst=%u",
                            rbp_page->page_id.file, rbp_page->page_id.page, (uint64)rbp_page->rbp_lrp_point.lfn,
                            bh->lsn, bh->pcn, (uint32)cks, rbp_page->writer_inst_id, rbp_page->page_id.file,
                            rbp_page->page_id.page, bh->lsn, (uint64)rbp_page->rbp_lrp_point.lfn,
                            rbp_page->writer_inst_id);
        }
#endif

        /* use ENTER_PAGE_NO_READ to indicate it will not load page from local disk */
        buf_enter_page(session, rbp_page->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        ctrl = session->curr_page_ctrl;
        rbp_page_lsn = PAGE_GET_LSN(rbp_page->block);
        curr_page_lsn = ctrl->page->lsn;

        ctrl->rbp_ctrl->page_status = rbp_page_verify(session, page_id, rbp_page_lsn, curr_page_lsn);

        if ((rbp_page_lsn > curr_page_lsn) &&
            (ctrl->rbp_ctrl->page_status == RBP_PAGE_HIT || ctrl->rbp_ctrl->page_status == RBP_PAGE_USABLE)) {
            rbp_replace_local_page(session, ctrl, (page_head_t *)rbp_page->block, NULL);
            replace_cnt++;
        } else if (curr_page_lsn == OG_INVALID_LSN) {
            /* page is not load from disk or replace by rbp page, page in buffer is invalid, need load disk page */
            ctrl->rbp_ctrl->is_from_rbp = OG_FALSE;
            if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
                CM_ABORT(0, "[RBP] ABORT INFO: RBP background thread failed to load %u-%u", page_id.file, page_id.page);
            }
            fallback_disk_cnt++;
        }

        ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);

        if (PAGE_SIZE(*ctrl->page) == 0 && ctrl->page->lsn == 0) {
            /* extended page, must be load from disk */
            knl_panic_log(!ctrl->rbp_ctrl->is_from_rbp, "page is read from rbp, panic info: page %u-%u type %u",
                           ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        }

        /* treat page as loaded from disk, do not change it, do not generate redo */
        buf_leave_page(session, OG_FALSE);
        item = rbp_aly_get_page_item(session, rbp_page->page_id);
        if (item != NULL && item->is_verified) {
            verify_after++;
        }
    }
    if (fallback_disk_cnt > 0) {
        OG_LOG_RUN_INF("[RBP] BATCH_READ apply summary: resp_count=%u skipped=%u replaced=%u fallback_disk=%u "
                       "verify_before=%u verify_after=%u",
                       resp->count, skipped_cnt, replace_cnt, fallback_disk_cnt, verify_before, verify_after);
    }
}

static void rbp_process_batch_read_resp_multi(knl_session_t *session, rbp_batch_read_resp_t *resp,
                                              uint32 source_node, rbp_read_apply_diag_t *diag)
{
    rbp_page_item_t *rbp_batch = resp->pages;
    rbp_page_item_t *rbp_page = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_id_t page_id;
    uint64 rbp_page_lsn;
    uint64 curr_page_lsn;
    uint64 expect_lsn;
    rbp_page_status_e page_status;
    rbp_analyse_item_t *item = NULL;

    if (resp->result == RBP_READ_RESULT_ERROR) {
        resp->msg[RBP_MSG_LEN - 1] = '\0';
        OG_LOG_RUN_WAR("[RBP] kernel batch read rbp pages error from node %u: %s", source_node, resp->msg);
        return;
    }

    if (rbp_is_dtc_partial_read(session)) {
        rbp_process_batch_read_resp_partial(session, resp, source_node, diag);
        return;
    }

    for (uint32 i = 0; i < resp->count; i++) {
        rbp_page = &rbp_batch[i];
        item = rbp_aly_get_page_item(session, rbp_page->page_id);

        if (rbp_need_skip(session, rbp_page)) {
            continue;
        }
        if (item == NULL) {
            continue;
        }

        page_id = AS_PAGID(((page_head_t *)rbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(rbp_page->page_id, page_id), "rbp_page's page_id and rbp_page block's id are not "
                      "same, panic info: rbp_page %u-%u, rbp_page block %u-%u", rbp_page->page_id.file,
                      rbp_page->page_id.page, page_id.file, page_id.page);

        buf_enter_page(session, rbp_page->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        ctrl = session->curr_page_ctrl;
        rbp_page_lsn = PAGE_GET_LSN(rbp_page->block);
        curr_page_lsn = ctrl->page->lsn;
        expect_lsn = rbp_get_item_expect_lsn(session, item);
        page_status = rbp_eval_page_candidate(session, page_id, rbp_page_lsn, curr_page_lsn, expect_lsn, OG_TRUE);
        if (rbp_page_lsn > expect_lsn) {
            rbp_log_ahead_detail(session, page_id, source_node, rbp_page_lsn, item, expect_lsn);
        }

        if (item != NULL) {
            item->seen_node_bitmap |= ((uint64)1 << (source_node % RBP_NODE_BITMAP_BITS));
            if ((page_status == RBP_PAGE_HIT || page_status == RBP_PAGE_USABLE) && rbp_page_lsn > item->best_lsn) {
                item->best_lsn = rbp_page_lsn;
                item->best_source_node = source_node;
                if (rbp_page_lsn > curr_page_lsn) {
                    rbp_replace_local_page(session, ctrl, (page_head_t *)rbp_page->block, NULL);
                }
                /*
                * Multi-node recovery must see all node servers' candidates before deciding whether the page is
                * verified. Marking verified here would make rbp_need_skip() hide later node replies for the same page.
                */
            }
        }

        if (ctrl->page->lsn == OG_INVALID_LSN) {
            rbp_context_t *rbp_context = &session->kernel->rbp_context;
            uint64 sample;

            ctrl->rbp_ctrl->is_from_rbp = OG_FALSE;
            if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
                CM_ABORT(0, "[RBP] ABORT INFO: multi RBP background thread failed to load %u-%u from disk",
                        page_id.file, page_id.page);
            }
            sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_multi_disk_fallback);
            if (sample <= RBP_READ_SAMPLE_LIMIT) {
                OG_LOG_RUN_INF("[RBP] multi disk fallback sample[%llu/%u]: page=%u-%u when RBP page is not installed",
                               sample, RBP_READ_SAMPLE_LIMIT, page_id.file, page_id.page);
            }
        }

        ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
        ctrl->rbp_ctrl->page_status = page_status;

        buf_leave_page(session, OG_FALSE);
    }
}

/* background worker read pages from RBP, mostly running when standby failover */
static uint32 rbp_knl_read_pages(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_batch_read_req_t request;
    rbp_batch_read_resp_t *response = NULL;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    date_t begin_time = cm_now();

    if (rbp_context->dtc_use_selected_batch) {
        return rbp_knl_read_selected_pages(session);
    }

    if (rbp_is_multi_node_rcy(session)) {
        rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[rbp_proc_id];
        uint32 node_ids[OG_MAX_INSTANCES];
        uint32 node_count = rbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
        uint32 total_count = 0;
        uint32 overall_result = RBP_READ_RESULT_NOPAGE;
        log_point_t *skip_point = NULL;
        uint64 pipe_lock_us = 0;
        uint64 ensure_conn_us = 0;
        uint64 send_us = 0;
        uint64 wait_resp_us = 0;
        uint64 process_us = 0;
#if RBP_READ_HOT_DIAG
        rbp_read_apply_diag_t apply_diag = { 0 };
        rbp_read_apply_diag_t *apply_diag_ptr = &apply_diag;
#else
        rbp_read_apply_diag_t *apply_diag_ptr = NULL;
#endif
        date_t step_begin;

        /*
        * Query every jumped node's server with that node's own skip-begin point.
        * The demo/real server may evict by LRU, so the window decides which prefix can be skipped,
        * while recovery-side candidate arbitration decides which concrete page image is usable.
        */
        for (uint32 i = 0; i < node_count; i++) {
            uint32 node_id = node_ids[i];
            cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, OG_TRUE);
            if (!rbp_get_dtc_read_points(session, node_id, &skip_point, NULL, NULL)) {
                OG_LOG_RUN_WAR("[RBP] missing DTC read epoch point for node %u", node_id);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return RBP_READ_RESULT_ERROR;
            }
            RBP_READ_STEP_BEGIN(step_begin);
            cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
            RBP_READ_STEP_ACCUM(step_begin, pipe_lock_us);
            RBP_READ_STEP_BEGIN(step_begin);
            if (rbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                RBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return RBP_READ_RESULT_ERROR;
            }
            RBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);

            RBP_SET_MSG_HEADER(&request, RBP_REQ_BATCH_PAGE_READ, sizeof(rbp_batch_read_req_t), cs_get_socket_fd(pipe));
            request.rbp_skip_point = *skip_point;

            RBP_READ_STEP_BEGIN(step_begin);
            if (rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
                cs_disconnect(pipe);
                mgr->temp_connected_node = OG_INVALID_ID32;
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                RBP_READ_STEP_ACCUM(step_begin, send_us);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return RBP_READ_RESULT_ERROR;
            }
            RBP_READ_STEP_ACCUM(step_begin, send_us);

            response = (rbp_batch_read_resp_t *)rbp_context->batch_buf[rbp_proc_id];
            RBP_READ_STEP_BEGIN(step_begin);
            if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_batch_read_resp_t)) != OG_SUCCESS) {
                cs_disconnect(pipe);
                mgr->temp_connected_node = OG_INVALID_ID32;
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                RBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return RBP_READ_RESULT_ERROR;
            }
            RBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
            cm_spin_unlock(&mgr->fisrt_pipe_lock);

            if (response->result != RBP_READ_RESULT_OK && response->result != RBP_READ_RESULT_NOPAGE) {
                response->msg[RBP_MSG_LEN - 1] = '\0';
                OG_LOG_RUN_WAR("[RBP] DTC batch read error from node %u: result=%u msg=%s",
                               node_id, response->result, response->msg);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, total_count, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return RBP_READ_RESULT_ERROR;
            }
            if (response->result == RBP_READ_RESULT_OK && response->count > 0) {
                overall_result = RBP_READ_RESULT_OK;
                total_count += response->count;
                RBP_READ_STEP_BEGIN(step_begin);
                rbp_process_batch_read_resp_multi(session, response, node_id, apply_diag_ptr);
                RBP_READ_STEP_ACCUM(step_begin, process_us);
            }
        }

        session->stat->rbp_bg_read += total_count;
        session->stat->rbp_bg_read_time += (cm_now() - begin_time) / MICROSECS_PER_MILLISEC;
        rbp_finish_read_batch_stat(session, rbp_proc_id, overall_result, total_count, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return overall_result;
    }

    {
        log_context_t *redo_ctx = &session->kernel->redo_ctx;
        uint64 pipe_lock_us = 0;
        uint64 send_us = 0;
        uint64 wait_resp_us = 0;
        uint64 process_us = 0;
        date_t step_begin;
        /*
        * Recovery READ_BEGIN uses pipe_temp; batch read must follow same line to keep request/response pairing on
        * one connection. Non-recovery keeps using pipe_const.
        */
        cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, KNL_RECOVERY_WITH_RBP(session->kernel));

        /* set message header */
        RBP_SET_MSG_HEADER(&request, RBP_REQ_BATCH_PAGE_READ, sizeof(rbp_batch_read_req_t), cs_get_socket_fd(pipe));
        /* set message body */
        request.rbp_skip_point = redo_ctx->rbp_skip_point; // only read pages after rbp_skip_point

        {
            rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[rbp_proc_id];
            RBP_READ_STEP_BEGIN(step_begin);
            cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
            RBP_READ_STEP_ACCUM(step_begin, pipe_lock_us);
            RBP_READ_STEP_BEGIN(step_begin);
            if ((KNL_RECOVERY_WITH_RBP(session->kernel) ?
                rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) :
                rbp_knl_send_request(pipe, (char *)&request, mgr)) != OG_SUCCESS) {
                if (KNL_RECOVERY_WITH_RBP(session->kernel)) {
                    cs_disconnect(pipe);
                    mgr->temp_connected_node = OG_INVALID_ID32;
                }
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                RBP_READ_STEP_ACCUM(step_begin, send_us);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, 0, send_us, wait_resp_us, process_us, NULL);
                return RBP_READ_RESULT_ERROR;
            }
            RBP_READ_STEP_ACCUM(step_begin, send_us);

            response = (rbp_batch_read_resp_t *)rbp_context->batch_buf[rbp_proc_id];
            RBP_READ_STEP_BEGIN(step_begin);
            if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_batch_read_resp_t)) != OG_SUCCESS) {
                mgr->is_connected = OG_FALSE;
                cs_disconnect(pipe);
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                RBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
                rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, 0, send_us, wait_resp_us, process_us, NULL);
                return RBP_READ_RESULT_ERROR;
            }
            RBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
        }

        RBP_READ_STEP_BEGIN(step_begin);
        rbp_process_batch_read_resp(session, response);
        RBP_READ_STEP_ACCUM(step_begin, process_us);
        session->stat->rbp_bg_read += response->count;
        session->stat->rbp_bg_read_time += (cm_now() - begin_time) / MICROSECS_PER_MILLISEC;
        rbp_finish_read_batch_stat(session, rbp_proc_id, response->result, response->count, begin_time,
                                   pipe_lock_us, 0, send_us, wait_resp_us, process_us, NULL);
        return response->result;
    }
}

static rbp_latch_result_t rbp_buf_latch_timed_s(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_rbp_ctrl_t *rbp_ctrl = ctrl->rbp_ctrl;
    uint32 wait_ticks = 0;

    while (rbp_ctrl == NULL) {
        if (wait_ticks >= RBP_SEND_LATCH_WAIT) {
            return RBP_LATCH_BUSY;
        }
        cm_spin_sleep();
        wait_ticks++;
        rbp_ctrl = ctrl->rbp_ctrl;
    }

    wait_ticks = 0;
    cm_spin_lock(&rbp_ctrl->init_lock, NULL);
    while (ctrl->load_status == BUF_NEED_LOAD) {
        if (wait_ticks >= RBP_SEND_LATCH_WAIT) {
            cm_spin_unlock(&rbp_ctrl->init_lock);
            return RBP_LATCH_BUSY;
        }
        cm_spin_unlock(&rbp_ctrl->init_lock);
        cm_spin_sleep();
        wait_ticks++;
        cm_spin_lock(&rbp_ctrl->init_lock, NULL);
    }

    if (!buf_latch_timed_s(session, ctrl, RBP_SEND_LATCH_TIMEOUT, OG_FALSE)) {
        cm_spin_unlock(&rbp_ctrl->init_lock);
        return RBP_LATCH_BUSY;
    }
    cm_spin_unlock(&rbp_ctrl->init_lock);
    return RBP_LATCH_OK;
}

static rbp_latch_result_t rbp_try_buf_latch_ctrl_bounded(knl_session_t *session, thread_t *thread, buf_ctrl_t *ctrl,
                                                        bool32 wait_readonly, rbp_assemble_diag_t *diag)
{
    uint64 step_begin;
    uint64 step_us;
    uint32 wait_ticks = 0;
    bool32 wait_by_readonly;
    bool32 wait_by_need_load;
    rbp_latch_result_t result;

    if (diag != NULL) {
        step_begin = g_timer()->now;
    }
    result = rbp_buf_latch_timed_s(session, ctrl);
    if (diag != NULL) {
        diag->first_latch_us += (uint64)(g_timer()->now - step_begin);
    }
    if (result != RBP_LATCH_OK) {
        return result;
    }

    /*
    * CKPT-style send: a readonly/loading/busy page must not block the queue
    * scan. Keep the item in the list and let later pages warm the RBP cache;
    * queue frontier is still pinned by this item until it is sent or reset.
    */
    while ((wait_readonly && ctrl->is_readonly) || ctrl->load_status == BUF_NEED_LOAD) {
        wait_by_readonly = (bool32)(wait_readonly && ctrl->is_readonly);
        wait_by_need_load = (bool32)(ctrl->load_status == BUF_NEED_LOAD);
        buf_unlatch(session, ctrl, OG_FALSE);
        if (wait_ticks >= RBP_SEND_LATCH_WAIT) {
            return RBP_LATCH_BUSY;
        }

        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
        cm_spin_sleep();
        if (diag != NULL) {
            step_us = (uint64)(g_timer()->now - step_begin);
            if (wait_by_readonly) {
                diag->readonly_wait_us += step_us;
                diag->readonly_wait_count++;
            }
            if (wait_by_need_load) {
                diag->need_load_wait_us += step_us;
                diag->need_load_wait_count++;
            }
        }
        wait_ticks++;
        if (session->killed || thread->closed) {
            return RBP_LATCH_ERROR;
        }

        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
        result = rbp_buf_latch_timed_s(session, ctrl);
        if (diag != NULL) {
            diag->retry_latch_us += (uint64)(g_timer()->now - step_begin);
            diag->retry_latch_count++;
        }
        if (result != RBP_LATCH_OK) {
            return result;
        }
    }

    return RBP_LATCH_OK;
}

static rbp_queue_item_t *rbp_remove_queue_item(knl_session_t *session, rbp_queue_t *queue,
                                               rbp_queue_item_t *prev, rbp_queue_item_t *item)
{
    rbp_queue_item_t *real_prev = NULL;
    rbp_queue_item_t *iter = NULL;
    rbp_queue_item_t *next = NULL;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    if (prev != NULL && prev->next == item) {
        real_prev = prev;
    } else if (queue->first == item) {
        real_prev = NULL;
    } else {
        iter = queue->first;
        while (iter != NULL && iter->next != item) {
            iter = iter->next;
        }
        real_prev = iter;
    }

    knl_panic_log(queue->first == item || real_prev != NULL,
                  "RBP queue item is not found during remove, queue id %u", queue->id);

    next = item->next;
    if (real_prev == NULL) {
        queue->first = next;
    } else {
        real_prev->next = next;
    }
    if (queue->last == item) {
        queue->last = real_prev;
    }
    knl_panic_log(queue->count > 0, "RBP queue count is abnormal, queue id %u", queue->id);
    queue->count--;
    item->next = NULL;
    cm_spin_unlock(&queue->lock);
    return next;
}

/*
* When RBP queue has a gap, trim dirty intervals covered by gap_end_point.
* If the whole interval is before the reset point, remove it; otherwise advance
* the interval begin so the queue frontier matches the reset notified to RBPS.
*/
static uint32 rbp_queue_remove_gap_pages(knl_session_t *session, thread_t *thread, rbp_queue_t *rbp_queue,
                                        log_point_t gap_end_point)
{
    rbp_queue_item_t *item = rbp_queue->first;
    rbp_queue_item_t *prev = NULL;
    rbp_queue_item_t *item_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 remove_num = 0;
    uint32 scan_num = 0;
    uint32 keep_num = 0;
    uint32 trim_num = 0;
    uint32 latch_fail_num = 0;

    while (item != NULL && !session->killed && !thread->closed) {
        scan_num++;
        if (item->source == RBP_QUEUE_ITEM_DROPPED) {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_WAR("[RBP_ENQ_TRACE] drop queued item before PAGE_WRITE: reason=dropped_marker "
                           "queue=%u page=%u-%u gap_end_lfn=%llu scanned=%u remaining=%u",
                           rbp_queue->id, item->page_id.file, item->page_id.page,
                           (uint64)gap_end_point.lfn, scan_num, rbp_queue->count);
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
            rbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }

        if (item->source == RBP_QUEUE_ITEM_SNAPSHOT) {
            if (item->snapshot->lastest_lfn < gap_end_point.lfn) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_DEBUG_WAR("[RBP_ENQ_TRACE] drop snapshot before PAGE_WRITE: reason=gap_reset "
                               "queue=%u page=%u-%u gap_end_lfn=%llu item_trunc_lfn=%llu "
                               "lastest_lfn=%llu page_lsn=%llu scanned=%u remaining=%u",
                               rbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)gap_end_point.lfn, (uint64)item->snapshot->rbp_trunc_point.lfn,
                               (uint64)item->snapshot->lastest_lfn, (uint64)item->snapshot->writer_global_seq,
                               scan_num, rbp_queue->count);
#endif
                item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
                rbp_free_queue_item(session, item);
                item = item_next;
                remove_num++;
                continue;
            }
            if (LOG_LFN_LT(item->snapshot->rbp_trunc_point, gap_end_point)) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_RUN_WAR("[RBP] trim snapshot gap item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu",
                               rbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)item->snapshot->rbp_trunc_point.lfn,
                               (uint64)gap_end_point.lfn, (uint64)item->snapshot->lastest_lfn,
                               (uint64)item->snapshot->writer_global_seq);
#endif
                item->snapshot->rbp_trunc_point = gap_end_point;
                trim_num++;
            }
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        ctrl = item->ctrl;
        if (ctrl == NULL || ctrl->rbp_ctrl == NULL) {
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
            rbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }
        if (rbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_FALSE, NULL) != RBP_LATCH_OK) {
            latch_fail_num++;
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        if (ctrl->lastest_lfn < gap_end_point.lfn) {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_WAR("[RBP_ENQ_TRACE] drop live item before PAGE_WRITE: reason=gap_reset "
                           "queue=%u page=%u-%u gap_end_lfn=%llu item_trunc_lfn=%llu lastest_lfn=%llu "
                           "page_lsn=%llu page_pcn=%u page_status=%u scanned=%u remaining=%u",
                           rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (uint64)gap_end_point.lfn,
                           (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn,
                           (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn,
                           (uint32)ctrl->rbp_ctrl->page_status, scan_num, rbp_queue->count);
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
            rbp_clear_ctrl_pending(ctrl, item, "gap_reset", 0, gap_end_point.lfn);
            buf_unlatch(session, ctrl, OG_FALSE);
            rbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
        } else {
            if (LOG_LFN_LT(ctrl->rbp_ctrl->rbp_trunc_point, gap_end_point)) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_RUN_WAR("[RBP] trim live gap item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu page_status=%u",
                               rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page,
                               (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn,
                               (uint64)gap_end_point.lfn, (uint64)ctrl->lastest_lfn,
                               (uint64)ctrl->page->lsn, (uint32)ctrl->rbp_ctrl->page_status);
#endif
                ctrl->rbp_ctrl->rbp_trunc_point = gap_end_point;
                trim_num++;
            }
            buf_unlatch(session, ctrl, OG_FALSE);
            keep_num++;
            prev = item;
            item = item->next;
        }
    }
    if (remove_num > 0 || trim_num > 0 || latch_fail_num > 0) {
        OG_LOG_RUN_WAR("[RBP] gap cleanup summary: queue=%u gap_end_lfn=%llu scanned=%u removed=%u trimmed=%u "
                       "kept=%u latch_fail=%u remaining=%u",
                       rbp_queue->id, (uint64)gap_end_point.lfn, scan_num, remove_num, trim_num, keep_num,
                       latch_fail_num, rbp_queue->count);
    }
    return remove_num;
}

typedef struct st_rbp_ckpt_cleanup_diag {
    uint32 scanned;
    uint32 removed;
    uint32 trimmed;
    uint32 kept;
    uint32 latch_fail;
} rbp_ckpt_cleanup_diag_t;

static uint32 rbp_queue_remove_ckpt_covered_pages(knl_session_t *session, thread_t *thread, rbp_queue_t *rbp_queue,
                                                  log_point_t reset_point, rbp_ckpt_cleanup_diag_t *diag)
{
    rbp_queue_item_t *item = rbp_queue->first;
    rbp_queue_item_t *prev = NULL;
    rbp_queue_item_t *item_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 remove_num = 0;
    uint32 scan_num = 0;
    uint32 keep_num = 0;
    uint32 trim_num = 0;
    uint32 latch_fail_num = 0;

    while (item != NULL && !session->killed && !thread->closed) {
        scan_num++;
        if (item->source == RBP_QUEUE_ITEM_DROPPED) {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_WAR("[RBP_ENQ_TRACE] drop queued item before PAGE_WRITE: reason=ckpt_reset_dropped_marker "
                           "queue=%u page=%u-%u reset_lfn=%llu scanned=%u remaining=%u",
                           rbp_queue->id, item->page_id.file, item->page_id.page,
                           (uint64)reset_point.lfn, scan_num, rbp_queue->count);
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
            rbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }

        if (item->source == RBP_QUEUE_ITEM_SNAPSHOT) {
            if (item->snapshot->lastest_lfn < reset_point.lfn) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_DEBUG_INF("[RBP_ENQ_TRACE] drop snapshot before PAGE_WRITE: reason=ckpt_reset "
                               "queue=%u page=%u-%u reset_lfn=%llu item_trunc_lfn=%llu "
                               "lastest_lfn=%llu page_lsn=%llu scanned=%u remaining=%u",
                               rbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)reset_point.lfn, (uint64)item->snapshot->rbp_trunc_point.lfn,
                               (uint64)item->snapshot->lastest_lfn, (uint64)item->snapshot->writer_global_seq,
                               scan_num, rbp_queue->count);
#endif
                item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
                rbp_free_queue_item(session, item);
                item = item_next;
                remove_num++;
                continue;
            }
            if (LOG_LFN_LT(item->snapshot->rbp_trunc_point, reset_point)) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[RBP] trim snapshot ckpt item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu",
                               rbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)item->snapshot->rbp_trunc_point.lfn,
                               (uint64)reset_point.lfn, (uint64)item->snapshot->lastest_lfn,
                               (uint64)item->snapshot->writer_global_seq);
#endif
                item->snapshot->rbp_trunc_point = reset_point;
                trim_num++;
            }
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        ctrl = item->ctrl;
        if (ctrl == NULL || ctrl->rbp_ctrl == NULL) {
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
            rbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }
        if (rbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_FALSE, NULL) != RBP_LATCH_OK) {
            latch_fail_num++;
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        if (ctrl->lastest_lfn < reset_point.lfn) {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_INF("[RBP_ENQ_TRACE] drop live item before PAGE_WRITE: reason=ckpt_reset "
                           "queue=%u page=%u-%u reset_lfn=%llu item_trunc_lfn=%llu lastest_lfn=%llu "
                           "page_lsn=%llu page_pcn=%u page_status=%u scanned=%u remaining=%u",
                           rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (uint64)reset_point.lfn,
                           (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn,
                           (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn,
                           (uint32)ctrl->rbp_ctrl->page_status, scan_num, rbp_queue->count);
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
            rbp_clear_ctrl_pending(ctrl, item, "ckpt_reset", reset_point.lfn, 0);
            buf_unlatch(session, ctrl, OG_FALSE);
            rbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
        } else {
            if (LOG_LFN_LT(ctrl->rbp_ctrl->rbp_trunc_point, reset_point)) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[RBP] trim live ckpt item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu page_status=%u",
                               rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page,
                               (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn,
                               (uint64)reset_point.lfn, (uint64)ctrl->lastest_lfn,
                               (uint64)ctrl->page->lsn, (uint32)ctrl->rbp_ctrl->page_status);
#endif
                ctrl->rbp_ctrl->rbp_trunc_point = reset_point;
                trim_num++;
            }
            buf_unlatch(session, ctrl, OG_FALSE);
            keep_num++;
            prev = item;
            item = item->next;
        }
    }
    if (remove_num > 0 || trim_num > 0) {
        OG_LOG_RUN_INF("[RBP] ckpt reset cleanup summary: queue=%u reset_lfn=%llu scanned=%u removed=%u trimmed=%u "
                       "kept=%u latch_fail=%u remaining=%u",
                       rbp_queue->id, (uint64)reset_point.lfn, scan_num, remove_num, trim_num, keep_num,
                       latch_fail_num, rbp_queue->count);
    } else if (latch_fail_num > 0) {
        OG_LOG_DEBUG_INF("[RBP] ckpt reset cleanup summary: queue=%u reset_lfn=%llu scanned=%u removed=%u "
                        "trimmed=%u kept=%u latch_fail=%u remaining=%u",
                        rbp_queue->id, (uint64)reset_point.lfn, scan_num, remove_num, trim_num, keep_num,
                        latch_fail_num, rbp_queue->count);
    }
    if (diag != NULL) {
        diag->scanned = scan_num;
        diag->removed = remove_num;
        diag->trimmed = trim_num;
        diag->kept = keep_num;
        diag->latch_fail = latch_fail_num;
    }
    return remove_num;
}

static log_point_t rbp_max_log_point(log_point_t left, log_point_t right)
{
    return (log_cmp_point(&left, &right) >= 0) ? left : right;
}

static log_point_t rbp_queue_item_trunc_point(rbp_queue_item_t *item, log_point_t fallback)
{
    if (item == NULL) {
        return fallback;
    }

    if (item->source == RBP_QUEUE_ITEM_SNAPSHOT && item->snapshot != NULL) {
        return item->snapshot->rbp_trunc_point;
    }

    if (item->source == RBP_QUEUE_ITEM_LIVE && item->ctrl != NULL && item->ctrl->rbp_ctrl != NULL) {
        return item->ctrl->rbp_ctrl->rbp_trunc_point;
    }

    return fallback;
}

static log_point_t rbp_queue_get_frontier(knl_session_t *session, rbp_queue_t *rbp_queue)
{
    log_point_t frontier;

    cm_spin_lock(&rbp_queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    frontier = rbp_queue->trunc_point;
    if (rbp_queue->first != NULL) {
        frontier = rbp_queue_item_trunc_point(rbp_queue->first, frontier);
    }
    cm_spin_unlock(&rbp_queue->lock);
    return frontier;
}

/* copy 100 dirty pages to write request, record pages max lsn and max lastest lfn */
static void rbp_assemble_write_request(knl_session_t *session, thread_t *thread, rbp_write_req_t *request,
                                        rbp_queue_t *rbp_queue, uint64 *max_lsn, uint64 *max_lfn,
                                        rbp_assemble_diag_t *diag)
{
    rbp_queue_item_t *item = rbp_queue->first;
    rbp_queue_item_t *prev = NULL;
    rbp_queue_item_t *item_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    rbp_page_item_t *page_item = NULL;
    uint32 pop_num = 0;
    uint32 live_num = 0;
    uint32 snapshot_num = 0;
    uint32 dropped_num = 0;
    uint32 busy_num = 0;
    uint32 scanned = 0;
#if RBP_PAGE_WRITE_HOT_DIAG
    uint64 item_begin;
    uint64 step_begin;
    uint64 item_us;
    page_id_t diag_page;
    uint32 diag_source;
    uint32 diag_load_status;
    uint32 diag_is_readonly;
    uint32 diag_latch_stat;
#endif
    errno_t ret;
    rbp_latch_result_t latch_result;
    uint32 max_scan = rbp_get_assemble_max_scan(session);
    if (diag != NULL) {
        diag->max_scan = max_scan;
    }

    while (item != NULL && pop_num < RBP_BATCH_PAGE_NUM && !session->killed && !thread->closed) {
        scanned++;
        if (scanned > max_scan) {
            break;
        }
        if (diag != NULL) {
            diag->scanned = scanned;
        }
#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            item_begin = g_timer()->now;
        }
#endif
#if RBP_PAGE_WRITE_HOT_DIAG
        diag_page = item->page_id;
        diag_source = (uint32)item->source;
        diag_load_status = 0;
        diag_is_readonly = 0;
        diag_latch_stat = 0;
#endif
        if (item->source == RBP_QUEUE_ITEM_DROPPED) {
            rbp_queue->has_gap = OG_TRUE;
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_WAR("[RBP_ENQ_TRACE] drop queued item before PAGE_WRITE: reason=assemble_dropped_marker "
                           "queue=%u page=%u-%u queued_pages=%u popped=%u",
                           rbp_queue->id, item->page_id.file, item->page_id.page, rbp_queue->count, pop_num);
#endif
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->pop_us += (uint64)(g_timer()->now - step_begin);
                step_begin = g_timer()->now;
            }
#endif
            rbp_free_queue_item(session, item);
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->free_us += (uint64)(g_timer()->now - step_begin);
                item_us = (uint64)(g_timer()->now - item_begin);
                rbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            item = item_next;
            dropped_num++;
            continue;
        }

        if (item->source == RBP_QUEUE_ITEM_SNAPSHOT) {
#if RBP_PAGE_WRITE_HOT_DIAG
            diag_page = item->snapshot->page_id;
#endif
            page_item = &request->pages[pop_num];
            page_item->page_id = item->snapshot->page_id;
            page_item->session_id = 0;
            page_item->writer_inst_id = item->snapshot->writer_inst_id;
            page_item->writer_global_seq = item->snapshot->writer_global_seq;
            page_item->rbp_trunc_point = item->snapshot->rbp_trunc_point;
            page_item->rbp_lrp_point = (log_point_t){ 0 };
            page_item->rbp_lrp_point.lfn = item->snapshot->lastest_lfn;
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            ret = memcpy_sp(page_item->block, DEFAULT_PAGE_SIZE(session), item->snapshot->block,
                            DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            PAGE_CHECKSUM(page_item->block, DEFAULT_PAGE_SIZE(session)) = OG_INVALID_CHECKSUM;
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->copy_us += (uint64)(g_timer()->now - step_begin);
            }
#endif

            /* Batch frontier is filled after assemble from the current queue.first. */
            *max_lsn = MAX(*max_lsn, item->snapshot->writer_global_seq);
            *max_lfn = MAX(*max_lfn, item->snapshot->lastest_lfn);
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_INF("[RBP] PAGE_WRITE snapshot payload: queue=%u page=%u-%u lfn=%llu lsn=%llu",
                            rbp_queue->id, page_item->page_id.file, page_item->page_id.page,
                            (uint64)item->snapshot->lastest_lfn, (uint64)item->snapshot->writer_global_seq);
#endif

            pop_num++;
            snapshot_num++;
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->pop_us += (uint64)(g_timer()->now - step_begin);
                step_begin = g_timer()->now;
            }
#endif
            rbp_free_queue_item(session, item);
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->free_us += (uint64)(g_timer()->now - step_begin);
                item_us = (uint64)(g_timer()->now - item_begin);
                rbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            item = item_next;
            continue;
        }

        ctrl = item->ctrl;
        if (ctrl == NULL || ctrl->rbp_ctrl == NULL) {
            rbp_queue->has_gap = OG_TRUE;
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->pop_us += (uint64)(g_timer()->now - step_begin);
                step_begin = g_timer()->now;
            }
#endif
            rbp_free_queue_item(session, item);
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->free_us += (uint64)(g_timer()->now - step_begin);
                item_us = (uint64)(g_timer()->now - item_begin);
                rbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            item = item_next;
            dropped_num++;
            continue;
        }
#if RBP_PAGE_WRITE_HOT_DIAG
        diag_page = ctrl->page_id;
        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
        latch_result = rbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_TRUE, diag);
#else
        latch_result = rbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_TRUE, NULL);
#endif
#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->latch_us += (uint64)(g_timer()->now - step_begin);
        }
#endif
#if RBP_PAGE_WRITE_HOT_DIAG
        diag_load_status = (uint32)ctrl->load_status;
        diag_is_readonly = (uint32)ctrl->is_readonly;
        diag_latch_stat = (uint32)ctrl->latch.stat;
#endif
        if (latch_result == RBP_LATCH_BUSY) {
#if RBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                item_us = (uint64)(g_timer()->now - item_begin);
                rbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            busy_num++;
            prev = item;
            item = item->next;
            continue;
        }
        if (latch_result != RBP_LATCH_OK) {
            rbp_queue->has_gap = OG_TRUE;
            OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] SEND_PICK_LIVE_FAIL reason=latch_failed queue=%u page=%u-%u "
                            "ctrl=%p item=%p lastest_lfn=%llu item_trunc_lfn=%llu queued_pages=%u popped=%u "
                            "gap_end_lfn=%llu",
                            rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                            (uint64)ctrl->lastest_lfn, (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn,
                            rbp_queue->count, pop_num, (uint64)session->kernel->redo_ctx.curr_point.lfn);
            OG_LOG_DEBUG_INF("[RBP] set gap while assembling PAGE_WRITE: queue=%u page=%u-%u "
                            "reason=try_buf_latch_failed queued_pages=%u popped=%u trunc_lfn=%llu lastest_lfn=%llu",
                            rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, rbp_queue->count, pop_num,
                            (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn);
            if (diag != NULL) {
#if RBP_PAGE_WRITE_HOT_DIAG
                item_us = (uint64)(g_timer()->now - item_begin);
                rbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
#endif
                diag->live_num = live_num;
                diag->snapshot_num = snapshot_num;
                diag->dropped_num = dropped_num;
                diag->busy_num = busy_num;
            }
            request->page_num = pop_num;
            request->page_num_tail = pop_num;
            return;
        }

        if (ctrl->page->size_units != 0) {
            knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(ctrl->page->id)), "ctrl's page id and ctrl page's id "
                          "are not same, panic info: ctrl_page %u-%u type %u, ctrl page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, AS_PAGID(ctrl->page->id).file,
                          AS_PAGID(ctrl->page->id).page, ctrl->page->type);
            knl_panic_log(CHECK_PAGE_PCN(ctrl->page), "pcn of the page is abnormal, panic info: page %u-%u type %u",
                          ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
        }

        /* set page info */
        page_item = &request->pages[pop_num];
        page_item->page_id = ctrl->page_id;
        page_item->session_id = 0;
        page_item->writer_inst_id = (uint32)session->kernel->id;
        page_item->writer_global_seq = ctrl->page->lsn;
        page_item->rbp_trunc_point = ctrl->rbp_ctrl->rbp_trunc_point;
        /* Keep latest_lfn until rbp_wait_redo_visible; wire lrp is overwritten by batch_lrp_point. */
        page_item->rbp_lrp_point = (log_point_t){ 0 };
        page_item->rbp_lrp_point.lfn = ctrl->lastest_lfn;
        OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] SEND_PICK_LIVE queue=%u page=%u-%u ctrl=%p item=%p "
                        "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu queue_count=%u "
                        "popped=%u page_status=%u",
                        rbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                        (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                        (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, rbp_queue->count, pop_num,
                        (uint32)ctrl->rbp_ctrl->page_status);
#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
#endif
        ret = memcpy_sp(page_item->block, DEFAULT_PAGE_SIZE(session), ctrl->page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
#ifdef RBP_VERBOSE_TRACE
        {
            uint32 psz = DEFAULT_PAGE_SIZE(session);
            uint16 pre_wire_cks = PAGE_CHECKSUM(page_item->block, psz);
            cm_reset_error();
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE payload (pre-wire): page %u-%u lfn %llu lsn %llu pcn %u checksum 0x%04x "
                           "inst %u | RBP-CORR fid=%u pn=%u seq=%llu lfn=%llu inst=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn, (uint64)ctrl->page->lsn,
                           ctrl->page->pcn, (uint32)pre_wire_cks, (uint32)session->kernel->id, ctrl->page_id.file,
                           ctrl->page_id.page, (uint64)ctrl->page->lsn, (uint64)ctrl->lastest_lfn,
                           (uint32)session->kernel->id);
        }
#endif
        PAGE_CHECKSUM(page_item->block, DEFAULT_PAGE_SIZE(session)) = OG_INVALID_CHECKSUM; // set checksum to 0
#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->copy_us += (uint64)(g_timer()->now - step_begin);
        }
#endif
        pop_num++;

        /* Batch frontier is filled after assemble from the current queue.first. */
        *max_lsn = MAX(*max_lsn, ctrl->page->lsn);
        *max_lfn = MAX(*max_lfn, ctrl->lastest_lfn);

#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
#endif
        item_next = rbp_remove_queue_item(session, rbp_queue, prev, item);
        rbp_clear_ctrl_pending(ctrl, item, "sent", 0, 0);
        buf_unlatch(session, ctrl, OG_FALSE);
#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->pop_us += (uint64)(g_timer()->now - step_begin);
            step_begin = g_timer()->now;
        }
#endif
        rbp_free_queue_item(session, item);
#if RBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->free_us += (uint64)(g_timer()->now - step_begin);
            item_us = (uint64)(g_timer()->now - item_begin);
            rbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                diag_is_readonly, diag_latch_stat);
        }
#endif
        item = item_next;
        live_num++;
    }

    request->page_num = pop_num;
    request->page_num_tail = pop_num;
    if (diag != NULL) {
        diag->live_num = live_num;
        diag->snapshot_num = snapshot_num;
        diag->dropped_num = dropped_num;
        diag->busy_num = busy_num;
    }
    if (snapshot_num > 0 || dropped_num > 0) {
        uint32 snapshot_free_count;
        uint32 snapshot_low_watermark;
        uint64 snapshot_alloc_total;
        uint64 snapshot_free_total;
        uint64 snapshot_fail_total;
        bool32 log_snapshot_summary;
        rbp_context_t *rbp_ctx = &session->kernel->rbp_context;

        cm_spin_lock(&rbp_ctx->snapshot_lock, NULL);
        snapshot_free_count = rbp_ctx->snapshot_free_count;
        snapshot_low_watermark = rbp_ctx->snapshot_low_watermark;
        snapshot_alloc_total = rbp_ctx->snapshot_alloc_total;
        snapshot_free_total = rbp_ctx->snapshot_free_total;
        snapshot_fail_total = rbp_ctx->snapshot_alloc_fail_total;
        cm_spin_unlock(&rbp_ctx->snapshot_lock);

#ifdef RBP_VERBOSE_TRACE
        log_snapshot_summary = OG_TRUE;
#else
        log_snapshot_summary = (bool32)(dropped_num > 0 || snapshot_free_count == 0 ||
                                        snapshot_free_count < RBP_BATCH_PAGE_NUM || snapshot_fail_total > 0);
#endif
        if (log_snapshot_summary) {
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE assemble snapshot summary: queue=%u live=%u snapshot=%u dropped=%u "
                           "request_pages=%u queue_remaining=%u has_gap=%u snapshot_free=%u low_watermark=%u "
                           "alloc_total=%llu free_total=%llu fail_total=%llu",
                           rbp_queue->id, live_num, snapshot_num, dropped_num, request->page_num, rbp_queue->count,
                           (uint32)rbp_queue->has_gap, snapshot_free_count, snapshot_low_watermark,
                           (uint64)snapshot_alloc_total, (uint64)snapshot_free_total, (uint64)snapshot_fail_total);
        }
    }
}

static void rbp_complete_write_lrp_points(rbp_write_req_t *request)
{
    for (uint32 i = 0; i < request->page_num; i++) {
        request->pages[i].rbp_lrp_point = request->batch_lrp_point;
    }
}

/*
  * Visible redo / WAL lower bound before RBP PAGE_WRITE (rbp_wait_redo_visible):
  * min{local curr_point, peer flush point (if HA standby), and cluster quorum_lfn cap when applicable}.
  */
static void rbp_log_min_flush_point(knl_session_t *session, log_point_t *min_flush_point)
{
    log_point_t peer_max_point = { 0, 0, 0, 0 };
    uint64 quorum_lfn;

    *min_flush_point = session->kernel->redo_ctx.curr_point;  /* local flush point */

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        return; // log must flushed to peer in raft mode
    }

    /*
      * Non-DSS HA uses the minimum of local and peer flush points so RBP does not publish pages
      * that the standby cannot replay yet. With DSS, redo is shared after local log flush, and
      * peer-reported points may not describe the same shared redo progress, so keep local plus
      * the cluster quorum_lfn cap below.
      */
    if (session->kernel->lsnd_ctx.standby_num > 0 && !session->kernel->attr.enable_dss) {
        lsnd_get_max_flush_point(session, &peer_max_point, OG_FALSE);
        /*
        * Ignore an invalid peer point. Otherwise lsn-only comparisons could reduce the minimum
        * to zero and make rbp_wait_redo_visible wait forever on max_page_lfn > 0.
        */
        if (!log_point_is_invalid(&peer_max_point) &&
            (min_flush_point->asn == OG_INVALID_ASN || log_cmp_point(&peer_max_point, min_flush_point) < 0)) {
            *min_flush_point = peer_max_point;
        }
    }

    if (DB_IS_CLUSTER(session)) {
        quorum_lfn = (uint64)cm_atomic_get((atomic_t *)&session->kernel->redo_ctx.quorum_lfn);
        /*
        * quorum_lfn starts at zero and is written only after lsnd_wait observes a positive value.
        * Do not cap by zero; that has the same failure mode as an invalid peer point.
        */
        if (quorum_lfn != (uint64)OG_INVALID_INT64 && quorum_lfn > 0 &&
            min_flush_point->lfn > quorum_lfn) {
            min_flush_point->lfn = quorum_lfn;
        }
    }
}

/*
  * rbp_wait_redo_visible: wait until redo through max_page_lfn is durable enough for RBP PAGE_WRITE
* (local flush, lsnd quorum wait, then bottleneck from peers / cluster quorum_lfn; see rbp_log_min_flush_point).
  */
status_t rbp_wait_redo_visible(knl_session_t *session, thread_t *thread, uint64 max_page_lsn, uint64 max_page_lfn,
                                log_point_t *rbp_lrp_point)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t curr_point = { 0, 0, 0, 0 };
    log_point_t min_flush_point;
    uint64 quorum_out = 0;

    /* make sure log is flushed to local disk(primary DN disk) */
    if (max_page_lfn > redo_ctx->flushed_lfn && !rbp_context->log_flushing) {
        rbp_context->log_flushing = OG_TRUE;
        if (log_flush(session, &curr_point, NULL, NULL, NULL) != OG_SUCCESS) {
            return OG_ERROR;
        }

        /* wait log replicated / quorum (cluster passes quorum output to refresh redo_ctx.quorum_lfn) */
        if ((curr_point.asn != OG_INVALID_ASN) && !DB_IS_RAFT_ENABLED(session->kernel)) {
            if (DB_IS_CLUSTER(session)) {
                lsnd_wait(session, curr_point.lfn, &quorum_out);
            } else {
                lsnd_wait(session, curr_point.lfn, NULL);
            }
        }
        (void)quorum_out;

        rbp_context->log_flushing = OG_FALSE;
    }

    /* make sure log is flushed to at least one peer(standby DN) */
    rbp_log_min_flush_point(session, &min_flush_point);
    while (max_page_lfn > min_flush_point.lfn && !session->killed && !thread->closed) {
        cm_sleep(RBP_LOG_FLUSH_WAIT_MS);
        OG_LOG_DEBUG_INF("[RBP] wait log flushed before write page to RBP. "
                          "max_page_lfn[%llu], min_flush_lfn[%llu], max_page_lsn[%llu]",
                          max_page_lfn, (uint64)min_flush_point.lfn, max_page_lsn);
        rbp_log_min_flush_point(session, &min_flush_point);
    }
    *rbp_lrp_point = min_flush_point;
    return OG_SUCCESS;
}

/* if has gap, remove pages and just update begin_point, lrp_point */
static void rbp_knl_reset_queue(knl_session_t *session, thread_t *thread, rbp_write_req_t *request,
                                rbp_queue_t *rbp_queue)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    uint32 throw_num = request->page_num;
    log_point_t frontier_point;

    while (rbp_queue->has_gap) {
        rbp_queue->has_gap = OG_FALSE;
        throw_num += rbp_queue_remove_gap_pages(session, thread, rbp_queue, redo_ctx->curr_point);
    }

    request->page_num = 0;
    request->page_num_tail = 0;

    /* we read curr_point without lock */
    request->batch_begin_point = redo_ctx->curr_point;
    request->batch_lrp_point = request->batch_begin_point;
    frontier_point = rbp_queue_get_frontier(session, rbp_queue);
    request->batch_trunc_point = rbp_max_log_point(request->batch_begin_point, frontier_point);
    OG_LOG_RUN_WAR("[RBP] queue id %u, throw %u gap pages and send PAGE_WRITE reset: "
                   "reset_point=[%u-%u/%u/%llu/%llu] frontier=[%u-%u/%u/%llu/%llu] remaining_queue_pages=%u",
                   rbp_queue->id, throw_num, request->batch_begin_point.rst_id, request->batch_begin_point.asn,
                   request->batch_begin_point.block_id, (uint64)request->batch_begin_point.lfn,
                   (uint64)request->batch_begin_point.lsn, request->batch_trunc_point.rst_id,
                   request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                   (uint64)request->batch_trunc_point.lfn, (uint64)request->batch_trunc_point.lsn,
                   rbp_queue->count);
}

static bool32 rbp_take_ckpt_reset(rbp_queue_t *rbp_queue, log_point_t *reset_point)
{
    if (!rbp_queue->has_ckpt_reset) {
        return OG_FALSE;
    }

    cm_spin_lock(&rbp_queue->lock, NULL);
    if (!rbp_queue->has_ckpt_reset) {
        cm_spin_unlock(&rbp_queue->lock);
        return OG_FALSE;
    }

    *reset_point = rbp_queue->ckpt_reset_point;
    rbp_queue->has_ckpt_reset = OG_FALSE;
    cm_spin_unlock(&rbp_queue->lock);
    return OG_TRUE;
}

static void rbp_prepare_ckpt_reset_request(knl_session_t *session, rbp_write_req_t *request, rbp_queue_t *rbp_queue,
                                           log_point_t *reset_point)
{
    log_point_t frontier_point;

    request->page_num = 0;
    request->page_num_tail = 0;
    request->batch_begin_point = *reset_point;
    request->batch_lrp_point = *reset_point;
    frontier_point = rbp_queue_get_frontier(session, rbp_queue);
    request->batch_trunc_point = rbp_max_log_point(*reset_point, frontier_point);
    OG_LOG_DEBUG_INF("[RBP] queue id %u send PAGE_WRITE reset: reset_point=[%u-%u/%u/%llu/%llu] "
                    "frontier=[%u-%u/%u/%llu/%llu]",
                    rbp_queue->id, reset_point->rst_id, reset_point->asn, reset_point->block_id,
                    (uint64)reset_point->lfn, (uint64)reset_point->lsn, request->batch_trunc_point.rst_id,
                    request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                    (uint64)request->batch_trunc_point.lfn, (uint64)request->batch_trunc_point.lsn);
}

static void rbp_init_page_write_request(rbp_write_req_t *request, cs_pipe_t *pipe)
{
    log_point_t init_point = { 0, 0, 0, 0 };

    request->page_num = 0;
    request->page_num_tail = 0;
    request->batch_trunc_point = init_point;
    request->batch_begin_point = init_point;
    request->batch_lrp_point = init_point;
    RBP_SET_MSG_HEADER(request, RBP_REQ_PAGE_WRITE, sizeof(rbp_write_req_t), cs_get_socket_fd(pipe));
}

static status_t rbp_send_page_write_request(cs_pipe_t *pipe, rbp_buf_manager_t *rbp_mgr, rbp_write_req_t *request,
                                            uint64 *send_us, uint64 *send_lock_us, uint64 *send_stream_us)
{
    date_t step_begin;
    date_t lock_begin;
    date_t stream_begin;
    uint64 lock_us = 0;
    uint64 stream_us = 0;
    bool32 measure_timing = (bool32)(send_us != NULL || send_lock_us != NULL || send_stream_us != NULL);

    if (measure_timing) {
        step_begin = g_timer()->now;
        lock_begin = step_begin;
    }
    cm_spin_lock(&rbp_mgr->fisrt_pipe_lock, NULL);
    if (measure_timing) {
        lock_us = (uint64)(g_timer()->now - lock_begin);
        stream_begin = g_timer()->now;
    }
    if (rbp_knl_send_request(pipe, (char *)request, rbp_mgr) != OG_SUCCESS) {
        cm_spin_unlock(&rbp_mgr->fisrt_pipe_lock);
        return OG_ERROR;
    }
    if (measure_timing) {
        stream_us = (uint64)(g_timer()->now - stream_begin);
    }
    cm_reset_error();
    cm_spin_unlock(&rbp_mgr->fisrt_pipe_lock);

    if (send_us != NULL) {
        *send_us = (uint64)(g_timer()->now - step_begin);
    }
    if (send_lock_us != NULL) {
        *send_lock_us = lock_us;
    }
    if (send_stream_us != NULL) {
        *send_stream_us = stream_us;
    }
    return OG_SUCCESS;
}

static date_t rbp_ckpt_purge_interval_us(knl_session_t *session)
{
    uint64 ckpt_timeout = (uint64)session->kernel->attr.ckpt_timeout;

    if (ckpt_timeout == 0) {
        ckpt_timeout = 1;
    }
    return (date_t)(ckpt_timeout * RBP_CKPT_PURGE_INTERVAL_FACTOR * MICROSECS_PER_SECOND);
}

static status_t rbp_send_ckpt_purge_if_due(knl_session_t *session, thread_t *thread, rbp_write_req_t *request,
                                           rbp_queue_t *rbp_queue, rbp_buf_manager_t *rbp_mgr, cs_pipe_t *pipe)
{
    date_t now = g_timer()->now;
    date_t interval_us = rbp_ckpt_purge_interval_us(session);
    log_point_t latest_point = dtc_my_ctrl(session)->rcy_point;
    log_point_t last_sent_point = rbp_queue->last_sent_ckpt_purge_point;
    rbp_ckpt_cleanup_diag_t cleanup_diag = { 0 };
    date_t cleanup_begin;
    uint64 cleanup_us;
    uint32 covered_pages;
    uint64 send_us = 0;

    if (rbp_queue->last_ckpt_purge_check_time != 0 &&
        now - rbp_queue->last_ckpt_purge_check_time < interval_us) {
        return OG_SUCCESS;
    }
    rbp_queue->last_ckpt_purge_check_time = now;

    if (rbp_queue->has_gap) {
        OG_LOG_DEBUG_INF("[RBP] skip periodic ckpt purge: queue=%u reason=gap latest_lfn=%llu "
                        "last_sent_lfn=%llu interval_us=%lld remaining=%u",
                        rbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                        (long long)interval_us, rbp_queue->count);
        return OG_SUCCESS;
    }

    if (log_point_is_invalid(&latest_point)) {
        OG_LOG_DEBUG_INF("[RBP] skip periodic ckpt purge: queue=%u reason=invalid latest_lfn=%llu "
                        "last_sent_lfn=%llu interval_us=%lld remaining=%u",
                        rbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                        (long long)interval_us, rbp_queue->count);
        return OG_SUCCESS;
    }

    if (log_cmp_point(&latest_point, &last_sent_point) <= 0) {
        OG_LOG_DEBUG_INF("[RBP] skip periodic ckpt purge: queue=%u reason=not_advanced latest_lfn=%llu "
                        "last_sent_lfn=%llu interval_us=%lld remaining=%u",
                        rbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                        (long long)interval_us, rbp_queue->count);
        return OG_SUCCESS;
    }

    cleanup_begin = g_timer()->now;
    covered_pages = rbp_queue_remove_ckpt_covered_pages(session, thread, rbp_queue, latest_point, &cleanup_diag);
    cleanup_us = (uint64)(g_timer()->now - cleanup_begin);
    rbp_init_page_write_request(request, pipe);
    rbp_prepare_ckpt_reset_request(session, request, rbp_queue, &latest_point);
    if (rbp_send_page_write_request(pipe, rbp_mgr, request, &send_us, NULL, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }

    rbp_queue->last_sent_ckpt_purge_point = latest_point;
    OG_LOG_DEBUG_INF("[RBP] send periodic ckpt purge: queue=%u latest_lfn=%llu last_sent_lfn=%llu "
                    "interval_us=%lld covered=%u remaining=%u cleanup_us=%llu scanned=%u removed=%u "
                    "trimmed=%u kept=%u latch_fail=%u send_us=%llu",
                    rbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                    (long long)interval_us, covered_pages, rbp_queue->count, cleanup_us, cleanup_diag.scanned,
                    cleanup_diag.removed, cleanup_diag.trimmed, cleanup_diag.kept, cleanup_diag.latch_fail, send_us);
    return OG_SUCCESS;
}

/* background write pages to RBP */
static status_t rbp_knl_write_to_rbp(knl_session_t *session, thread_t *thread)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    rbp_write_req_t *request = (rbp_write_req_t *)rbp_context->batch_buf[rbp_proc_id];
    rbp_queue_t *rbp_queue = &rbp_context->queue[rbp_proc_id];
    rbp_buf_manager_t *rbp_mgr = &rbp_context->rbp_buf_manager[rbp_proc_id];
    cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, OG_FALSE);
    date_t begin_time = g_timer()->now;
    uint64 max_page_lsn = OG_INVALID_LSN;
    uint64 max_page_lfn = OG_INVALID_LSN;
    log_point_t ckpt_reset_point = { 0, 0, 0, 0 };
    date_t iter_begin;
    date_t step_begin;
    uint64 assemble_us;
    uint64 wait_redo_us;
    uint64 send_us;
    uint64 send_lock_us;
    uint64 send_stream_us;
    uint64 gap_reset_us;
    uint64 total_us;
    uint32 queue_count_before;
    uint32 queue_count_after_assemble;
    uint32 queue_count_after;
    uint32 covered_pages;
    bool32 has_gap_before;
    bool32 took_ckpt_reset;
    bool32 took_gap_reset;
    int64 enqueue_delta;
    rbp_assemble_diag_t assemble_diag;
    rbp_assemble_diag_t *assemble_diag_ptr = &assemble_diag;
    errno_t memset_ret;

    knl_panic(SESSION_IS_RBP_BG(session));
    if (rbp_should_suspend_page_write(session)) {
        return OG_SUCCESS;
    }
    if (DB_IS_CLUSTER(session) && rbp_mgr->connected_id != (uint32)session->kernel->id) {
        OG_LOG_RUN_WAR("[RBP] refuse PAGE_WRITE to nonlocal RBP server: queue=%u inst=%u connected_node=%u",
                        rbp_proc_id, (uint32)session->kernel->id, rbp_mgr->connected_id);
        cm_spin_lock(&rbp_mgr->fisrt_pipe_lock, NULL);
        rbp_mgr->is_connected = OG_FALSE;
        cs_disconnect(pipe);
        cm_spin_unlock(&rbp_mgr->fisrt_pipe_lock);
        return OG_ERROR;
    }

    for (;;) {
        if (session->killed || thread->closed) {
            return OG_ERROR;
        }
        if (rbp_should_suspend_page_write(session)) {
            return OG_SUCCESS;
        }
        /*
        * Network paths may leave stale peer-closed errors in TLS. Clear them before each batch
        * write so PAGE_WRITE INFO logs are not polluted by older errors.
        */
        cm_reset_error();
        iter_begin = g_timer()->now;
        assemble_us = 0;
        wait_redo_us = 0;
        send_us = 0;
        send_lock_us = 0;
        send_stream_us = 0;
        gap_reset_us = 0;
        covered_pages = 0;
        queue_count_before = rbp_queue->count;
        queue_count_after_assemble = queue_count_before;
        enqueue_delta = 0;
        has_gap_before = rbp_queue->has_gap;
        took_ckpt_reset = OG_FALSE;
        took_gap_reset = OG_FALSE;
        memset_ret = memset_sp(&assemble_diag, sizeof(rbp_assemble_diag_t), 0, sizeof(rbp_assemble_diag_t));
        knl_securec_check(memset_ret);

        rbp_init_page_write_request(request, pipe);
        max_page_lsn = OG_INVALID_LSN;
        max_page_lfn = OG_INVALID_LSN;

        if (rbp_queue->count > 0) {
            /* set msg body */
            step_begin = g_timer()->now;
            rbp_assemble_write_request(session, thread, request, rbp_queue, &max_page_lsn, &max_page_lfn,
                                        assemble_diag_ptr);
            assemble_us = (uint64)(g_timer()->now - step_begin);
            queue_count_after_assemble = rbp_queue->count;
            enqueue_delta = (int64)queue_count_after_assemble + (int64)request->page_num -
                            (int64)queue_count_before;
#if RBP_PAGE_WRITE_HOT_DIAG
            if ((assemble_us >= RBP_PAGE_WRITE_ASSEMBLE_DIAG_US ||
                assemble_diag.max_item_us >= RBP_PAGE_WRITE_ITEM_DIAG_US) &&
                rbp_rate_loggable(&g_rbp_assemble_diag_last_log[rbp_proc_id % OG_RBP_SESSION_COUNT],
                                  g_timer()->now, RBP_ASSEMBLE_DIAG_INTERVAL_US)) {
                OG_LOG_RUN_INF("[RBP] PAGE_WRITE assemble diag: queue=%u before=%u after_assemble=%u "
                                "pages=%u enqueue_delta=%lld scanned=%u scan_limit=%u live=%u snapshot=%u "
                                "dropped=%u busy=%u "
                                "latch_us=%llu first_latch_us=%llu retry_latch_us=%llu retry_latch_count=%u "
                                "readonly_wait_us=%llu readonly_wait_count=%u need_load_wait_us=%llu "
                                "need_load_wait_count=%u copy_us=%llu pop_us=%llu free_us=%llu max_item_us=%llu "
                                "max_item_page=%u-%u max_item_source=%u load_status=%u is_readonly=%u "
                                "latch_stat=%u",
                                rbp_proc_id, queue_count_before, queue_count_after_assemble, request->page_num,
                                (long long)enqueue_delta, assemble_diag.scanned, assemble_diag.max_scan,
                                assemble_diag.live_num, assemble_diag.snapshot_num, assemble_diag.dropped_num,
                                assemble_diag.busy_num, assemble_diag.latch_us,
                                assemble_diag.first_latch_us, assemble_diag.retry_latch_us,
                                assemble_diag.retry_latch_count, assemble_diag.readonly_wait_us,
                                assemble_diag.readonly_wait_count,
                                assemble_diag.need_load_wait_us, assemble_diag.need_load_wait_count,
                                assemble_diag.copy_us, assemble_diag.pop_us, assemble_diag.free_us,
                                assemble_diag.max_item_us,
                                assemble_diag.max_item_page.file, assemble_diag.max_item_page.page,
                                assemble_diag.max_item_source, assemble_diag.max_item_load_status,
                                assemble_diag.max_item_is_readonly, assemble_diag.max_item_latch_stat);
            }
            if (request->page_num == 0 && queue_count_before > 0) {
                OG_LOG_RUN_INF("[RBP] PAGE_WRITE assemble empty batch: queue=%u before=%u after_assemble=%u "
                                "busy=%u dropped=%u snapshot=%u live=%u assemble_us=%llu latch_us=%llu "
                                "has_gap=%u",
                                rbp_proc_id, queue_count_before, queue_count_after_assemble,
                                assemble_diag.busy_num, assemble_diag.dropped_num, assemble_diag.snapshot_num,
                                assemble_diag.live_num, assemble_us, assemble_diag.latch_us,
                                (uint32)rbp_queue->has_gap);
            }
#endif

            if (request->page_num > 0) {
                request->batch_trunc_point = rbp_queue_get_frontier(session, rbp_queue);
                step_begin = g_timer()->now;
                if (rbp_wait_redo_visible(session, thread, max_page_lsn, max_page_lfn, &request->batch_lrp_point) !=
                    OG_SUCCESS) {
                    return OG_ERROR;
                }
                wait_redo_us = (uint64)(g_timer()->now - step_begin);
                rbp_complete_write_lrp_points(request);
            }
        } else if (rbp_take_ckpt_reset(rbp_queue, &ckpt_reset_point)) {
            took_ckpt_reset = OG_TRUE;
            covered_pages = rbp_queue_remove_ckpt_covered_pages(session, thread, rbp_queue, ckpt_reset_point, NULL);
            rbp_prepare_ckpt_reset_request(session, request, rbp_queue, &ckpt_reset_point);
            if (covered_pages > 0) {
                OG_LOG_RUN_INF("[RBP] queue id %u drop %u local queued pages covered by reset lfn=%llu",
                                rbp_queue->id, covered_pages, (uint64)ckpt_reset_point.lfn);
            }
        } else {
            if (rbp_send_ckpt_purge_if_due(session, thread, request, rbp_queue, rbp_mgr, pipe) != OG_SUCCESS) {
                return OG_ERROR;
            }
            cm_spin_sleep();
            break;
        }

        if (rbp_queue->has_gap) {
            took_gap_reset = OG_TRUE;
            step_begin = g_timer()->now;
            rbp_knl_reset_queue(session, thread, request, rbp_queue);
            gap_reset_us = (uint64)(g_timer()->now - step_begin);
        }

#ifdef RBP_VERBOSE_TRACE
        if (request->page_num > 0) {
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE frontier-lrp semantics: pages=%u "
                            "frontier=[%u-%u/%u/%llu/%llu] batch_lrp=[%u-%u/%u/%llu/%llu] "
                            "first_page_lrp_lfn=%llu first_page_lsn=%llu max_latest_lfn=%llu",
                            request->page_num, (uint32)request->batch_trunc_point.rst_id,
                            request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                            (uint64)request->batch_trunc_point.lfn, request->batch_trunc_point.lsn,
                            (uint32)request->batch_lrp_point.rst_id, request->batch_lrp_point.asn,
                            request->batch_lrp_point.block_id, (uint64)request->batch_lrp_point.lfn,
                            request->batch_lrp_point.lsn, (uint64)request->pages[0].rbp_lrp_point.lfn,
                            (uint64)request->pages[0].writer_global_seq, max_page_lfn);
        }
#endif

        if (session->killed || thread->closed) {
            return OG_ERROR;
        }

        if (request->page_num == 0 && log_point_is_invalid(&request->batch_lrp_point)) {
#if RBP_PAGE_WRITE_HOT_DIAG
            if (queue_count_before > 0 || queue_count_after_assemble > 0) {
                OG_LOG_RUN_INF("[RBP] PAGE_WRITE skip send (no pages in batch): queue=%u before=%u "
                                  "after_assemble=%u after=%u busy=%u dropped=%u ckpt_reset=%u gap_reset=%u "
                                  "assemble_us=%llu",
                                  rbp_proc_id, queue_count_before, queue_count_after_assemble,
                                  rbp_queue->count, assemble_diag.busy_num, assemble_diag.dropped_num,
                                  (uint32)took_ckpt_reset, (uint32)took_gap_reset, assemble_us);
            }
#else
            if (rbp_page_write_diag_loggable(rbp_proc_id, took_gap_reset, took_ckpt_reset, queue_count_before,
                                               rbp_queue->count, assemble_us, wait_redo_us, send_us)) {
                OG_LOG_RUN_INF("[RBP] PAGE_WRITE empty batch: queue=%u before=%u after_assemble=%u after=%u "
                                "pages=%u enqueue_delta=%lld scanned=%u "
                                "scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u ckpt_reset=%u "
                                "gap_reset=%u gap_before=%u gap_after=%u assemble_us=%llu connected=%u",
                                rbp_proc_id, queue_count_before, queue_count_after_assemble, rbp_queue->count,
                                request->page_num, (long long)enqueue_delta, assemble_diag.scanned,
                                assemble_diag.max_scan, assemble_diag.live_num, assemble_diag.snapshot_num,
                                assemble_diag.dropped_num, assemble_diag.busy_num, (uint32)took_ckpt_reset,
                                (uint32)took_gap_reset, (uint32)has_gap_before, (uint32)rbp_queue->has_gap, assemble_us,
                                (uint32)rbp_mgr->is_connected);
            }
#endif
            break;
        }

        if (rbp_send_page_write_request(pipe, rbp_mgr, request, &send_us, &send_lock_us, &send_stream_us) !=
            OG_SUCCESS) {
            return OG_ERROR;
        }

#if RBP_PAGE_WRITE_HOT_DIAG
        if (request->page_num > 0) {
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE sent to remote RBP: queue=%u pages=%u "
                            "frontier=[%u-%u/%u/%llu/%llu] first_page_lrp_lfn=%llu first_page_lsn=%llu "
                            "batch_lrp=[%u-%u/%u/%llu/%llu] max_latest_lfn=%llu "
                            "(wire checksum cleared per page)",
                            rbp_proc_id, request->page_num, (uint32)request->batch_trunc_point.rst_id,
                            request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                            (uint64)request->batch_trunc_point.lfn, request->batch_trunc_point.lsn,
                            (uint64)request->pages[0].rbp_lrp_point.lfn,
                            (uint64)request->pages[0].writer_global_seq,
                            (uint32)request->batch_lrp_point.rst_id, request->batch_lrp_point.asn,
                            request->batch_lrp_point.block_id, (uint64)request->batch_lrp_point.lfn,
                            request->batch_lrp_point.lsn, max_page_lfn);
        } else {
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE sent to remote RBP: queue=%u pages=%u "
                            "begin=[%u-%u/%u/%llu/%llu] frontier=[%u-%u/%u/%llu/%llu] "
                            "batch_lrp=[%u-%u/%u/%llu/%llu] (wire checksum cleared per page)",
                            rbp_proc_id, request->page_num, request->batch_begin_point.rst_id,
                            request->batch_begin_point.asn, request->batch_begin_point.block_id,
                            (uint64)request->batch_begin_point.lfn, request->batch_begin_point.lsn,
                            request->batch_trunc_point.rst_id, request->batch_trunc_point.asn,
                            request->batch_trunc_point.block_id, (uint64)request->batch_trunc_point.lfn,
                            request->batch_trunc_point.lsn, request->batch_lrp_point.rst_id,
                            request->batch_lrp_point.asn, request->batch_lrp_point.block_id,
                            (uint64)request->batch_lrp_point.lfn, request->batch_lrp_point.lsn);
        }
#endif

        session->stat->rbp_page_write_time += (g_timer()->now - begin_time) / MICROSECS_PER_MILLISEC;
        session->stat->rbp_page_write += request->page_num;

        queue_count_after = rbp_queue->count;
        total_us = (uint64)(g_timer()->now - iter_begin);
#if RBP_PAGE_WRITE_HOT_DIAG
        if (rbp_page_write_diag_loggable(rbp_proc_id, took_gap_reset, took_ckpt_reset, queue_count_before,
                                        queue_count_after, assemble_us, wait_redo_us, send_us)) {
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE queue diag: queue=%u before=%u after_assemble=%u after=%u "
                            "pages=%u ckpt_reset=%u covered=%u gap_reset=%u gap_before=%u gap_after=%u "
                            "scanned=%u scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u "
                            "max_lfn=%llu max_lsn=%llu assemble_us=%llu wait_redo_us=%llu send_us=%llu "
                            "send_lock_us=%llu send_stream_us=%llu wire_bytes=%u gap_reset_us=%llu "
                            "assemble_copy_us=%llu assemble_latch_us=%llu assemble_busy=%u "
                            "total_us=%llu connected=%u dtc_read_active=%u",
                            rbp_proc_id, queue_count_before, queue_count_after_assemble, queue_count_after,
                            request->page_num, (uint32)took_ckpt_reset, covered_pages, (uint32)took_gap_reset,
                            (uint32)has_gap_before, (uint32)rbp_queue->has_gap, assemble_diag.scanned,
                            assemble_diag.max_scan, assemble_diag.live_num, assemble_diag.snapshot_num,
                            assemble_diag.dropped_num, assemble_diag.busy_num, max_page_lfn, max_page_lsn,
                            assemble_us, wait_redo_us, send_us, send_lock_us, send_stream_us,
                            (uint32)request->header.msg_length, gap_reset_us, assemble_diag.copy_us,
                            assemble_diag.latch_us, assemble_diag.busy_num, total_us,
                            (uint32)rbp_mgr->is_connected, (uint32)rbp_context->dtc_read_active);
        }
#else
        if (total_us >= RBP_PAGE_WRITE_ASSEMBLE_DIAG_US) {
            OG_LOG_RUN_WAR("[RBP] PAGE_WRITE slow batch: queue=%u before=%u after_assemble=%u after=%u "
                           "pages=%u enqueue_delta=%lld ckpt_reset=%u covered=%u gap_reset=%u gap_before=%u "
                           "gap_after=%u scanned=%u scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u "
                           "max_lfn=%llu max_lsn=%llu assemble_us=%llu wait_redo_us=%llu send_us=%llu "
                           "send_lock_us=%llu send_stream_us=%llu wire_bytes=%u gap_reset_us=%llu total_us=%llu "
                           "connected=%u dtc_read_active=%u",
                           rbp_proc_id, queue_count_before, queue_count_after_assemble, queue_count_after,
                           request->page_num, (long long)enqueue_delta, (uint32)took_ckpt_reset, covered_pages,
                           (uint32)took_gap_reset, (uint32)has_gap_before, (uint32)rbp_queue->has_gap,
                           assemble_diag.scanned, assemble_diag.max_scan, assemble_diag.live_num,
                           assemble_diag.snapshot_num, assemble_diag.dropped_num, assemble_diag.busy_num,
                           max_page_lfn, max_page_lsn, assemble_us, wait_redo_us, send_us, send_lock_us,
                           send_stream_us, (uint32)request->header.msg_length, gap_reset_us, total_us,
                           (uint32)rbp_mgr->is_connected, (uint32)rbp_context->dtc_read_active);
        } else if (rbp_page_write_diag_loggable(rbp_proc_id, took_gap_reset, took_ckpt_reset, queue_count_before,
                                                queue_count_after, assemble_us, wait_redo_us, send_us)) {
            OG_LOG_RUN_INF("[RBP] PAGE_WRITE queue diag: queue=%u before=%u after_assemble=%u after=%u "
                           "pages=%u enqueue_delta=%lld ckpt_reset=%u covered=%u gap_reset=%u gap_before=%u "
                           "gap_after=%u scanned=%u scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u "
                           "max_lfn=%llu max_lsn=%llu assemble_us=%llu wait_redo_us=%llu send_us=%llu "
                           "send_lock_us=%llu send_stream_us=%llu wire_bytes=%u gap_reset_us=%llu total_us=%llu "
                           "connected=%u dtc_read_active=%u",
                           rbp_proc_id, queue_count_before, queue_count_after_assemble, queue_count_after,
                           request->page_num, (long long)enqueue_delta, (uint32)took_ckpt_reset, covered_pages,
                           (uint32)took_gap_reset, (uint32)has_gap_before, (uint32)rbp_queue->has_gap,
                           assemble_diag.scanned, assemble_diag.max_scan, assemble_diag.live_num,
                           assemble_diag.snapshot_num, assemble_diag.dropped_num, assemble_diag.busy_num,
                           max_page_lfn, max_page_lsn, assemble_us, wait_redo_us, send_us, send_lock_us,
                           send_stream_us, (uint32)request->header.msg_length, gap_reset_us, total_us,
                           (uint32)rbp_mgr->is_connected, (uint32)rbp_context->dtc_read_active);
        }
#endif
        if (request->page_num > 0 &&
            rbp_send_ckpt_purge_if_due(session, thread, request, rbp_queue, rbp_mgr, pipe) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

/* check if pages on rbp satisfy WAL, rbp lrp point can not large than standby redo end point */
static void rbp_page_check_wal(knl_session_t *session, rbp_read_ckpt_resp_t *resp)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t redo_end_point = redo_ctx->redo_end_point;

    /* if end_point < rbp_lrp_point, it does not satisfy WAL */
    if (LOG_LFN_LT(redo_end_point, resp->lrp_point) || redo_ctx->rbp_aly_lsn < resp->max_lsn) {
        rbp_set_unsafe(session, RD_TYPE_END);

        OG_LOG_RUN_WAR("[RBP] rbp unsafe, redo end_point[%u-%u-%llu] less than rbp_lrp_point[%u-%u-%llu]"
                        "or redo max lsn[%llu] less than rbp page max lsn[%llu]",
                        redo_end_point.rst_id, redo_end_point.asn, (uint64)redo_end_point.lfn,
                        resp->lrp_point.rst_id, resp->lrp_point.asn, (uint64)resp->lrp_point.lfn,
                        redo_ctx->rbp_aly_lsn, resp->max_lsn);
    }
}

static void rbp_process_read_ckpt_resp(knl_session_t *session, rbp_read_ckpt_resp_t *resp, log_context_t *redo_ctx)
{
    // rbp_begin_point: lower bound of the server-side RBP window, raised by reset/gap barriers and cache holes.
    // If we use RBP pages to replace local pages, current replay point must already be inside this window.
    redo_ctx->rbp_begin_point = resp->begin_point;
    // rbp_rcy_point: min server queue_frontier. This mirrors CKPT rcy_point = queue.first->trunc_point.
    // After pulling RBP pages, recovery can resume redo from this point if the node point is within (begin, rcy].
    redo_ctx->rbp_rcy_point = resp->rcy_point;
    // rbp_lrp_point: max active cache coverage_lrp, at least rcy_point; WAL check requires redo to cover it.
    redo_ctx->rbp_lrp_point = resp->lrp_point;
    if (resp->rbp_unsafe) {
        rbp_set_unsafe(session, RD_TYPE_END);
        OG_LOG_RUN_WAR("[RBP] rbp unsafe reason: %s", resp->unsafe_reason);
    }

    OG_LOG_RUN_INF("[RBP] rbp_begin_point[%u-%u-%llu], rbp_lrp_point[%u-%u-%llu], format: [rst_id-asn-lfn]",
                   resp->begin_point.rst_id, resp->begin_point.asn, (uint64)resp->begin_point.lfn,
                   resp->lrp_point.rst_id, resp->lrp_point.asn, (uint64)resp->lrp_point.lfn);
    if (resp->begin_point.lfn == 0 && resp->rcy_point.lfn == 0) {
        OG_LOG_RUN_WAR("[RBP] READ_CKPT window empty: begin/rcy lfn both 0 - RBP has no usable checkpoint window "
                       "(server cold, no PAGE_WRITE yet, or demo/mismatch); redo replay still proceeds.");
    }

    rbp_page_check_wal(session, resp);
}

/* crash recovery or failover, read page from rbp */
static void rbp_try_pull_page_batch(knl_session_t *session, uint32 *last_result)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    uint32 result = *last_result;

    knl_panic(SESSION_IS_RBP_BG(session));
    /* last read status is RBP_READ_RESULT_OK, it means some rbp pages are not read, need continue read from RBP */
    if (rbp_dtc_read_failed(rbp_context)) {
        result = RBP_READ_RESULT_NOPAGE;
    } else if (result == RBP_READ_RESULT_OK) {
        result = rbp_knl_read_pages(session);
    }

    if (result == RBP_READ_RESULT_ERROR) {
        if (rbp_context->dtc_read_active || rbp_context->dtc_read_node_count > 0) {
            rbp_mark_dtc_read_failed(rbp_context, OG_INVALID_ID32, result, "background read failed");
            if (rbp_dtc_has_jump_taken(session)) {
                rbp_knl_mark_dtc_fallback(session, OG_INVALID_ID32, result, RBP_DTC_FALLBACK_READ_FAILED);
            }
            result = RBP_READ_RESULT_NOPAGE;
        } else {
            CM_ABORT(0, "[RBP] ABORT INFO: instance must exit beacause failed to read pages from RBP");
        }
    }

    /* no pages can read from RBP for current rbp_bg_proc, means all RBP pages in queue[rbp_proc_id] have been read */
    if (result == RBP_READ_RESULT_NOPAGE) {
        if (rbp_context->rbp_buf_manager[rbp_proc_id].rbp_reading) {
            atomic_t remaining;
            date_t done_time = cm_now();

            rbp_context->rbp_buf_manager[rbp_proc_id].rbp_reading = OG_FALSE;
            remaining = cm_atomic_dec(&rbp_context->rbp_read_thread_num);
            if (remaining == 0) {
                rbp_context->rbp_read_workers_done_time = done_time;
                if ((rbp_context->dtc_read_active || rbp_context->dtc_read_node_count > 0) &&
                    !rbp_context->dtc_read_workers_done) {
                    rbp_context->dtc_read_workers_done = OG_TRUE;
                    OG_LOG_RUN_INF("[RBP] DTC read workers completed; wait recovery owner for final verify and "
                                    "READ_END: worker_active_ms=%llu",
                                    (uint64)((done_time - rbp_context->rbp_begin_read_time) /
                                            MICROSECS_PER_MILLISEC));
                }
            }
        }

        if (rbp_context->rbp_read_thread_num == 0 && // all rbp_bg_proc read completed
            rbp_proc_id == 0 && // rbp_knl_end_read need only be called once, so just let rbp_bg_proc 0 call it
            DB_IS_OPEN(session) &&
            rbp_db_enforce_primary_style_invariants(session)) { /* cluster compute / classic primary after failover */
            if (rbp_context->dtc_read_active || rbp_context->dtc_read_node_count > 0) {
                rbp_context->dtc_read_workers_done = OG_TRUE;
            } else {
                rbp_knl_end_read(session);
            }
        }
        cm_sleep(1);
    }

    *last_result = result;
}

status_t rbp_alloc_bg_session(uint8 queue_index, knl_session_t **session)
{
    if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)session) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*session)->rbp_queue_index = queue_index; // for rbp bg session, rbp_queue_index > 0
    return OG_SUCCESS;
}

void rbp_release_bg_session(knl_session_t *session)
{
    session->rbp_queue_index = 0;
    g_knl_callback.release_knl_session(session);
}

/*
  * rbp_bg loop after connecting to the peer RBP:
  * 1. Writers send queued dirty page batches to the peer RBP and heartbeat periodically.
  * 2. Non-writers only refresh the window and do heartbeat/pull-page work.
  */
static void rbp_bg_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_buf_manager_t *rbp_buf_manager = rbp_context->rbp_buf_manager;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    uint32 pull_result = RBP_READ_RESULT_OK;

    cm_set_thread_name("rbp_bg");
    OG_LOG_RUN_INF("[RBP] rbp_bg_%u thread started", rbp_proc_id);
    knl_panic(SESSION_IS_RBP_BG(session));

    /* first start, treat it has gap, so that rbp begin point refresh as redo->curr_point */
    rbp_context->queue[rbp_proc_id].id = rbp_proc_id;
    rbp_context->queue[rbp_proc_id].has_gap = OG_TRUE;
    rbp_context->queue[rbp_proc_id].has_ckpt_reset = OG_FALSE;
    rbp_context->queue[rbp_proc_id].ckpt_reset_point = (log_point_t){ 0 };
    rbp_context->queue[rbp_proc_id].last_sent_ckpt_purge_point = (log_point_t){ 0 };
    rbp_context->queue[rbp_proc_id].last_ckpt_purge_check_time = g_timer()->now;
    rbp_buf_manager[rbp_proc_id].rbp_reading = OG_FALSE;
    rbp_buf_manager[rbp_proc_id].last_hb_time = g_timer()->now;

    /* loop forever when USE_RBP is TRUE */
    while (!thread->closed) {
        /* Recovery reads use temp/selected-temp pipes and must not depend on the PAGE_WRITE const pipe. */
        if (KNL_RECOVERY_WITH_RBP(session->kernel)) {
            rbp_try_pull_page_batch(session, &pull_result);
            continue;
        }

        if (!rbp_buf_manager[rbp_proc_id].is_connected) {
            cm_sleep(RBP_DISCONNECTED_SLEEP_MS);
            continue;
        }

        pull_result = RBP_READ_RESULT_OK; /* reset pull page result after recover end */

        if (!DB_IS_OPEN(session)) {
            cm_sleep(RBP_NOT_OPEN_SLEEP_MS);
            continue;
        }

        if (rbp_should_suspend_page_write(session)) {
            rbp_timed_heart_beat(session);
            cm_sleep(RBP_SUSPEND_PAGE_WRITE_SLEEP_MS);
            continue;
        }

        if (rbp_instance_may_write_to_remote(session)) {
            if (rbp_knl_write_to_rbp(session, thread) != OG_SUCCESS) {
                /* write page to rbp failed, set has gap, the RBP pages will be cleared */
                rbp_context->queue[rbp_proc_id].has_gap = OG_TRUE;
                OG_LOG_RUN_WAR("[RBP] set gap after PAGE_WRITE failure: queue=%u connected=%u queued_pages=%u",
                               rbp_proc_id, (uint32)rbp_buf_manager[rbp_proc_id].is_connected,
                               rbp_context->queue[rbp_proc_id].count);
            }
        } else {
            /* No remote PAGE_WRITE permission, so do not push local dirty pages to RBP. */
            if (!rbp_context->queue[rbp_proc_id].has_gap) {
                OG_LOG_RUN_WAR("[RBP] set gap because instance cannot write to remote RBP: queue=%u "
                               "cluster=%u replay_node=%u queued_pages=%u",
                               rbp_proc_id, (uint32)DB_IS_CLUSTER(session), (uint32)OGRAC_REPLAY_NODE(session),
                               rbp_context->queue[rbp_proc_id].count);
            }
            rbp_context->queue[rbp_proc_id].has_gap = OG_TRUE;
            rbp_refresh_rbp_window(session, rbp_proc_id);
            cm_sleep(RBP_NO_REMOTE_WRITE_SLEEP_MS);
        }

        rbp_timed_heart_beat(session); /* both primary and standby send heart beat to RBP */
    }
    OG_LOG_RUN_INF("[RBP] rbp_bg_%u thread stopped", rbp_proc_id);
    rbp_release_bg_session(session);
    KNL_SESSION_CLEAR_THREADID(session);
}

static void rbp_init_connect_pipe(rbp_buf_manager_t *rbp_buf_manager)
{
    rbp_buf_manager->is_connected = OG_FALSE;
    rbp_buf_manager->temp_connected_node = OG_INVALID_ID32;
    rbp_buf_manager->selected_temp_connected_node = OG_INVALID_ID32;
    rbp_buf_manager->pipe_const.link.tcp.sock = CS_INVALID_SOCKET;
    rbp_buf_manager->pipe_const.link.tcp.closed = OG_TRUE;
    rbp_buf_manager->pipe_temp.link.tcp.sock = CS_INVALID_SOCKET;
    rbp_buf_manager->pipe_temp.link.tcp.closed = OG_TRUE;
    rbp_buf_manager->pipe_selected_temp.link.tcp.sock = CS_INVALID_SOCKET;
    rbp_buf_manager->pipe_selected_temp.link.tcp.closed = OG_TRUE;

    rbp_buf_manager->pipe_const.link.rdma.sock = CS_INVALID_SOCKET;
    rbp_buf_manager->pipe_const.link.rdma.closed = OG_TRUE;
    rbp_buf_manager->pipe_temp.link.rdma.sock = CS_INVALID_SOCKET;
    rbp_buf_manager->pipe_temp.link.rdma.closed = OG_TRUE;
    rbp_buf_manager->pipe_selected_temp.link.rdma.sock = CS_INVALID_SOCKET;
    rbp_buf_manager->pipe_selected_temp.link.rdma.closed = OG_TRUE;
}

/* start kernel's background workers in kernel */
status_t rbp_agent_start_client(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_buf_manager_t *rbp_buf_manager = rbp_context->rbp_buf_manager;
    knl_session_t **rbp_bg_sessions = rbp_context->rbp_bg_sessions;
    uint32 id;
    uint32 buf_size = MAX(RBP_MAX_REQ_BUF_SIZE, RBP_MAX_RESP_BUF_SIZE);

    for (id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        rbp_init_connect_pipe(&rbp_buf_manager[id]);
        rbp_buf_manager[id].queue_id = id;
        rbp_bg_sessions[id] = NULL;
        rbp_context->batch_buf[id] = rbp_context->pipe_buf.aligned_buf + id * buf_size;
    }

    /* start rbp background threads */
    for (id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        if (rbp_alloc_bg_session(id + 1, &rbp_bg_sessions[id]) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[RBP] failed to alloc rbp background session for index %u", id);
            return OG_ERROR;
        }

        if (cm_create_thread(rbp_bg_proc, 0, rbp_bg_sessions[id], &rbp_buf_manager[id].thread) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[RBP] failed to create background thread for index %u", id);
            rbp_release_bg_session(rbp_bg_sessions[id]); // other sessions are closed when rbp_bg_proc closed
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

void rbp_agent_stop_client(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    knl_session_t **rbp_bg_sessions = rbp_context->rbp_bg_sessions;

    /* stop rbp bg proc threads */
    for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        rbp_bg_sessions[id]->killed = OG_TRUE;
        cm_close_thread(&rbp_context->rbp_buf_manager[id].thread);
        cs_disconnect(&rbp_context->rbp_buf_manager[id].pipe_const);
        cs_disconnect(&rbp_context->rbp_buf_manager[id].pipe_temp);
        cs_disconnect(&rbp_context->rbp_buf_manager[id].pipe_selected_temp);
        rbp_context->rbp_buf_manager[id].is_connected = OG_FALSE;
        rbp_context->rbp_buf_manager[id].temp_connected_node = OG_INVALID_ID32;
        rbp_context->rbp_buf_manager[id].selected_temp_connected_node = OG_INVALID_ID32;
        rbp_context->batch_buf[id] = NULL;
        OG_LOG_RUN_INF("[RBP] rbp bg proc %u closed", id);
    }
}

static status_t rbp_send_shake_hand(cs_pipe_t *pipe, uint32 queue_id, bool32 is_temp, bool32 is_standby)
{
    rbp_shake_hand_req_t req;
    rbp_shake_hand_resp_t resp;
    int32 recv_size;
    errno_t err;

    err = memset_sp(&resp, sizeof(resp), 0, sizeof(resp));
    knl_securec_check(err);

    req.header.msg_type = RBP_REQ_SHAKE_HAND;

    req.is_standby = is_standby;
    req.is_temp = is_temp;
    req.queue_id = queue_id;

    if (cs_write_stream_timeout(pipe, (char *)&req, sizeof(req), 0, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cs_read_stream(pipe, (char *)&resp, RBP_MAX_READ_WAIT_TIME, sizeof(resp), &recv_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (recv_size != sizeof(resp) ||
        RBP_MSG_TYPE(&resp.header) != RBP_REQ_SHAKE_HAND ||
        req.queue_id != resp.queue_id) {
        OG_LOG_RUN_ERR("[RBP] invalid shake hand response, fd %d type %u receive size %u expect size %u req_qid %u "
                       "resp_qid %u temp %u standby %u",
                       cs_get_socket_fd(pipe), RBP_MSG_TYPE(&resp.header), recv_size, (uint32)sizeof(resp),
                       req.queue_id, resp.queue_id, (uint32)is_temp, (uint32)is_standby);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t rbp_init_pipe_connection(knl_session_t *session, rbp_buf_manager_t *rbp_buf_manager, cs_pipe_t *pipe,
                                        const char *host, uint16 port, bool32 is_temp)
{
    char url[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE + OG_TCP_PORT_MAX_LENGTH] = { 0 };
    uint32 queue_id = rbp_buf_manager->queue_id;
    /* Nodes that may PAGE_WRITE shake as non-standby; pull/heartbeat-only nodes shake as standby. */
    bool32 is_standby = rbp_instance_may_write_to_remote(session) ? OG_FALSE : OG_TRUE;
    errno_t ret;

    ret = memset_sp(pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    knl_securec_check(ret);
    ret = snprintf_s(url, sizeof(url), sizeof(url) - 1, "%s:%u", host, port);
    if (ret >= sizeof(url) || ret == -1) {
        OG_LOG_RUN_ERR("[RBP] Url %s is truncated", url);
        return OG_ERROR;
    }

    pipe->connect_timeout = RBP_CONNEOG_TIMEOUT;
    if (cs_connect((const char *)url, pipe, NULL, NULL, NULL) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[RBP] failed to connect %s", url);
        return OG_ERROR;
    }

    if (rbp_send_shake_hand(pipe, queue_id, is_temp, is_standby) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[RBP] failed to send shake hand to %s", url);
        cs_disconnect(pipe);
        return OG_ERROR;
    }

    cm_reset_error();
    OG_LOG_RUN_INF("[RBP] connected to %s, queue id %u, is temp %d", url, queue_id, is_temp);
    return OG_SUCCESS;
}

static status_t rbp_init_connection(knl_session_t *session, rbp_buf_manager_t *rbp_buf_manager, const char *host,
                                    uint16 port, bool32 is_temp)
{
    cs_pipe_t *pipe = (is_temp) ? &rbp_buf_manager->pipe_temp : &rbp_buf_manager->pipe_const;

    return rbp_init_pipe_connection(session, rbp_buf_manager, pipe, host, port, is_temp);
}

static status_t rbp_build_server_host(knl_session_t *session, const char *ip_addr, char *host, uint32 buf_size)
{
    rbp_attr_t *rbp_attr = &session->kernel->rbp_attr;
    errno_t ret;

    if (ip_addr == NULL || ip_addr[0] == '\0') {
        return OG_ERROR;
    }

    if (cm_str_equal_ins(rbp_attr->trans_type, "rdma")) {
        ret = snprintf_s(host, buf_size, buf_size - 1, RDMA_HOST_PREFIX "%s", ip_addr);
    } else {
        ret = snprintf_s(host, buf_size, buf_size - 1, "%s", ip_addr);
    }
    knl_securec_check_ss(ret);
    return OG_SUCCESS;
}

/*
* Constant write/heartbeat path:
* always route by configured RBP_IP/server_addr[] instead of inferring a host from cluster node metadata.
* That keeps routing explicit so a RBPS can later move to peer/VIP/HA proxy without changing kernel logic.
*/
static status_t rbp_get_server_host(knl_session_t *session, char *host, uint32 buf_size, uint32 addr_id)
{
    rbp_attr_t *rbp_attr = &session->kernel->rbp_attr;
    const char *ip_addr = NULL;

    if (addr_id < rbp_attr->server_count && rbp_attr->server_addr[addr_id][0] != '\0') {
        ip_addr = rbp_attr->server_addr[addr_id];
    } else if (rbp_attr->server_count > 0) {
        ip_addr = rbp_attr->server_addr[addr_id % rbp_attr->server_count];
    } else {
        OG_LOG_RUN_WAR("[RBP] no configured RBP_IP target for addr slot %u", addr_id);
        return OG_ERROR;
    }

    return rbp_build_server_host(session, ip_addr, host, buf_size);
}

/*
* Per-node recovery path:
* server_addr[node_id] is treated as the explicit route target for that node's RBPS.
* The configured IP may be the node itself, its peer, a VIP, or any HA endpoint.
*/
static status_t rbp_get_server_host_by_node(knl_session_t *session, uint32 node_id, char *host, uint32 buf_size)
{
    rbp_attr_t *rbp_attr = &session->kernel->rbp_attr;
    const char *ip_addr = NULL;

    if (node_id < rbp_attr->server_count && rbp_attr->server_addr[node_id][0] != '\0') {
        ip_addr = rbp_attr->server_addr[node_id];
    } else if (rbp_attr->server_count > 0) {
        ip_addr = rbp_attr->server_addr[node_id % rbp_attr->server_count];
        OG_LOG_RUN_WAR("[RBP] node %u has no dedicated RBP_IP entry, fallback to slot %u",
                       node_id, node_id % rbp_attr->server_count);
    } else {
        OG_LOG_RUN_WAR("[RBP] no configured RBP_IP target for recovery node %u", node_id);
        return OG_ERROR;
    }

    return rbp_build_server_host(session, ip_addr, host, buf_size);
}

static bool32 rbp_pipe_valid(cs_pipe_t *pipe)
{
    return (bool32)!((pipe->type == CS_TYPE_NONE) ||
                    (pipe->type == CS_TYPE_TCP && pipe->link.tcp.sock == CS_INVALID_SOCKET) ||
                    (pipe->type == CS_TYPE_RSOCKET && pipe->link.rdma.sock == CS_INVALID_SOCKET));
}

static bool32 rbp_temp_pipe_valid(rbp_buf_manager_t *manager)
{
    return rbp_pipe_valid(&manager->pipe_temp);
}

static bool32 rbp_selected_temp_pipe_valid(rbp_buf_manager_t *manager)
{
    return rbp_pipe_valid(&manager->pipe_selected_temp);
}

/*
* pipe_temp is reused across nodes and across background/on-demand RBP readers.
* Re-bind/reconnect must therefore be serialized by fisrt_pipe_lock together with the
* following request/response exchange; otherwise another thread may close or reuse the same
* socket while this thread is still handshaking or waiting for a reply.
*/
static status_t rbp_ensure_temp_connection_by_node(knl_session_t *session, rbp_buf_manager_t *manager, uint32 node_id)
{
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    uint16 port = session->kernel->rbp_attr.lsnr_port;

    if (rbp_temp_pipe_valid(manager) && manager->temp_connected_node == node_id) {
        return OG_SUCCESS;
    }

    if (rbp_temp_pipe_valid(manager)) {
        cs_disconnect(&manager->pipe_temp);
    }

    if (rbp_get_server_host_by_node(session, node_id, host, sizeof(host)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (rbp_init_connection(session, manager, host, port, OG_TRUE) != OG_SUCCESS) {
        manager->temp_connected_node = OG_INVALID_ID32;
        return OG_ERROR;
    }

    manager->temp_connected_node = node_id;
    OG_LOG_RUN_INF("[RBP] PAGE_READ temp route connected: queue=%u read_node=%u host=%s",
                   manager->queue_id, node_id, host);
    return OG_SUCCESS;
}

/*
* Selected batch read owns a separate temp pipe. It must not share pipe_temp/fisrt_pipe_lock
* with on-demand PAGE_READ, otherwise a large selected response blocks latency-sensitive pulls.
*/
static status_t rbp_ensure_selected_temp_connection_by_node(knl_session_t *session, rbp_buf_manager_t *manager,
                                                           uint32 node_id)
{
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    uint16 port = session->kernel->rbp_attr.lsnr_port;

    if (rbp_selected_temp_pipe_valid(manager) && manager->selected_temp_connected_node == node_id) {
        return OG_SUCCESS;
    }

    if (rbp_selected_temp_pipe_valid(manager)) {
        cs_disconnect(&manager->pipe_selected_temp);
    }

    if (rbp_get_server_host_by_node(session, node_id, host, sizeof(host)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (rbp_init_pipe_connection(session, manager, &manager->pipe_selected_temp, host, port, OG_TRUE) != OG_SUCCESS) {
        manager->selected_temp_connected_node = OG_INVALID_ID32;
        return OG_ERROR;
    }

    manager->selected_temp_connected_node = node_id;
    OG_LOG_RUN_INF("[RBP] SELECTED_READ temp route connected: queue=%u read_node=%u host=%s",
                   manager->queue_id, node_id, host);
    return OG_SUCCESS;
}

/* One-shot READ_CKPT against a specific node's RBPS. Prepare uses this to build the per-node window table. */
status_t rbp_knl_query_rbp_point_by_node(knl_session_t *session, uint32 node_id, rbp_read_ckpt_resp_t *response,
                                        bool32 check_end_point)
{
    rbp_read_ckpt_req_t request;
    rbp_buf_manager_t manager;
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    uint16 port = session->kernel->rbp_attr.lsnr_port;
    errno_t err;

    if (rbp_get_server_host_by_node(session, node_id, host, sizeof(host)) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RBP] READ_CKPT node %u failed: cannot resolve RBP host", node_id);
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("[RBP] READ_CKPT node %u start: host=%s port=%u check_end=%u aly_end_lfn=%llu "
                    "aly_end_lsn=%llu",
                    node_id, host, (uint32)port, (uint32)check_end_point,
                    (uint64)session->kernel->redo_ctx.redo_end_point.lfn,
                    session->kernel->redo_ctx.redo_end_point.lsn);

    err = memset_sp(&manager, sizeof(manager), 0, sizeof(manager));
    knl_securec_check(err);
    manager.queue_id = 0;
    manager.temp_connected_node = OG_INVALID_ID32;

    if (rbp_init_connection(session, &manager, host, port, OG_TRUE) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RBP] READ_CKPT node %u failed: connect host=%s port=%u", node_id, host, (uint32)port);
        return OG_ERROR;
    }

    RBP_SET_MSG_HEADER(&request, RBP_REQ_READ_CKPT, sizeof(rbp_read_ckpt_req_t),
                       cs_get_socket_fd(&manager.pipe_temp));
    request.check_end_point = check_end_point;
    request.aly_end_point = session->kernel->redo_ctx.redo_end_point;

    if (rbp_knl_send_request_timeout(&manager.pipe_temp, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) !=
        OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RBP] READ_CKPT node %u failed: send request host=%s port=%u", node_id, host, (uint32)port);
        cs_disconnect(&manager.pipe_temp);
        return OG_ERROR;
    }

    if (rbp_knl_wait_response(&manager.pipe_temp, (char *)response, sizeof(rbp_read_ckpt_resp_t)) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RBP] READ_CKPT node %u failed: wait response host=%s port=%u", node_id, host,
                       (uint32)port);
        cs_disconnect(&manager.pipe_temp);
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[RBP] READ_CKPT node %u ok: host=%s begin_lfn=%llu rcy_lfn=%llu lrp_lfn=%llu "
                    "max_lsn=%llu unsafe=%u",
                    node_id, host, (uint64)response->begin_point.lfn, (uint64)response->rcy_point.lfn,
                    (uint64)response->lrp_point.lfn, response->max_lsn, (uint32)response->rbp_unsafe);
    cs_disconnect(&manager.pipe_temp);
    return OG_SUCCESS;
}

bool32 rbp_promote_triggered(knl_handle_t knl_handle)
{
    knl_instance_t *kernel = (knl_instance_t *)knl_handle;

    if (knl_failover_triggered(kernel)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void rbp_reset_server_hosts(knl_instance_t *kernel)
{
    rbp_attr_t *rbp_attr = &kernel->rbp_attr;
    errno_t ret;

    cm_spin_lock(&rbp_attr->addr_lock, NULL);
    if (!rbp_attr->server_addr_changed) {
        cm_spin_unlock(&rbp_attr->addr_lock);
        return;
    }

    for (uint32 i = 0; i < OG_MAX_LSNR_HOST_COUNT; i++) {
        ret = memcpy_sp(rbp_attr->server_addr[i], CM_MAX_IP_LEN,
                        rbp_attr->server_addr2[i], CM_MAX_IP_LEN);
        knl_securec_check(ret);
    }
    rbp_attr->server_count = rbp_attr->server_count2;
    rbp_attr->server_addr_changed = OG_FALSE;
    cm_spin_unlock(&rbp_attr->addr_lock);
}

static status_t rbp_get_write_server_host(knl_session_t *session, char *host, uint32 buf_size, uint32 *target_id)
{
    if (DB_IS_CLUSTER(session)) {
        uint32 node_id = (uint32)session->kernel->id;
        if (target_id != NULL) {
            *target_id = node_id;
        }
        return rbp_get_server_host_by_node(session, node_id, host, buf_size);
    }

    uint32 addr_id = (target_id == NULL) ? 0 : *target_id;
    if (target_id != NULL) {
        *target_id = addr_id;
    }
    return rbp_get_server_host(session, host, buf_size, addr_id);
}

/* Maintaining the connections between rbp backupground threads and RBP */
static void rbp_agent_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    knl_instance_t *kernel = session->kernel;
    rbp_context_t *rbp_context = &kernel->rbp_context;
    rbp_buf_manager_t *managers = rbp_context->rbp_buf_manager;
    uint32 err_conn_num = 0;
    uint16 port = kernel->rbp_attr.lsnr_port;
    uint32 target_id = 0;
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };

    cm_set_thread_name("rbp_agent");
    OG_LOG_RUN_INF("[RBP] rbp_agent thread started");

    while (!thread->closed) {
        /*
          * if alter system set USE_RBP = FALSE, we just set RBP_OFF_TRIGGERED = TRUE
          * after failover running end, exit all RBP threads, then set USE_RBP = TRUE
          */
        if (KNL_RBP_OFF_TRIGGERED(kernel) && !KNL_RECOVERY_WITH_RBP(kernel) && !rbp_promote_triggered(kernel)) {
            kernel->rbp_aly_ctx.is_closing = OG_TRUE;
            thread->closed = OG_TRUE;
            break;
        }

        /* get rbp buffer manager communication channel */
        for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
            if (managers[id].is_connected) {
                continue;
            }
            rbp_reset_server_hosts(kernel);
            uint32 try_count = DB_IS_CLUSTER(session) ? 1 : MAX(kernel->rbp_attr.server_count, 1);
            uint32 start_id = DB_IS_CLUSTER(session) ? (uint32)session->kernel->id : managers[id].connected_id;
            bool32 connected = OG_FALSE;
            for (uint32 try_id = 0; try_id < try_count; try_id++) {
                target_id = DB_IS_CLUSTER(session) ? start_id : (start_id + try_id) % try_count;
                if (rbp_get_write_server_host(session, host, RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE,
                                              &target_id) != OG_SUCCESS) {
                    break;
                }

                if (rbp_init_connection(session, &managers[id], host, port, OG_FALSE) == OG_SUCCESS) {
                    managers[id].is_connected = OG_TRUE;
                    managers[id].connected_id = target_id;
                    OG_LOG_RUN_INF("[RBP] PAGE_WRITE route connected: queue=%u inst=%u target_node=%u host=%s",
                                   id, (uint32)session->kernel->id, target_id, host);
                    err_conn_num = 0;
                    connected = OG_TRUE;
                    break;
                }

                managers[id].is_connected = OG_FALSE;
                if (err_conn_num < kernel->rbp_attr.server_count) {
                    err_conn_num++;
                    OG_LOG_RUN_ERR("[RBP] rbp connect failed, host %s", host);
                }
            }
            if (!connected) {
                if (!DB_IS_CLUSTER(session) && kernel->rbp_attr.server_count > 0) {
                    managers[id].connected_id = (start_id + 1) % kernel->rbp_attr.server_count;
                }
                break;
            }
        }
        cm_sleep(RBP_SHUTDOWN_WAIT_MS);
    }

    rbp_agent_stop_client(session);
    rbp_drain_send_queues(session);
    rbp_snapshot_pool_free(session);
    cm_aligned_free(&rbp_context->pipe_buf);
    rbp_aly_mem_free(session);
    if (KNL_RBP_OFF_TRIGGERED(kernel)) {
        kernel->rbp_attr.use_rbp = OG_FALSE; // after exit all RBP threads, then set USE_RBP to FALSE
    }
}

static bool32 rbp_page_is_usable(knl_session_t *session, page_id_t page_id, uint64 curr_page_lsn, uint64 rbp_page_lsn,
                                 uint64 expect_lsn)
{
    knl_session_t *redo_session = session->kernel->sessions[SESSION_ID_KERNEL];
    bool32 use_rbp_page = OG_FALSE;
    uint64 disk_page_lsn = OG_INVALID_LSN;
    uint64 redo_curr_lsn = redo_session->curr_lsn;

    if (curr_page_lsn != OG_INVALID_LSN) { /* page is loaded from disk */
        if (rbp_page_lsn > curr_page_lsn) {
            /* rbp page can be used if rbp_page_lsn > curr_page_lsn */
            use_rbp_page = OG_TRUE;
        }
    } else { /* page not loaded from disk */
        if (!DB_NOT_READY(session) && rbp_page_lsn > redo_curr_lsn) {
            /* before failover done, redo_curr_lsn always >= page's lsn,
              * rbp_page_lsn > page lsn, rbp page can be used. after failover done, redo_curr_lsn == lrpl_end_lsn
              * when failover done, redo_curr_lsn will not increase, rbp_page_lsn must <= redo_curr_lsn
              */
            use_rbp_page = OG_TRUE;
        } else {
            /* need compare with page disk lsn, rbp page can be used if rbp_page_lsn >= disk_page_lsn */
            disk_page_lsn = rbp_get_disk_lsn(session, page_id, OG_FALSE);
            use_rbp_page = (rbp_page_lsn >= disk_page_lsn);
        }
    }

    OG_LOG_DEBUG_WAR("[RBP] %s page:%u-%u expected LSN:%llu, rbp LSN:%llu,"
                      "redo current LSN:%llu, page current LSN:%llu, page disk LSN:%llu",
                      (use_rbp_page ? "usable" : "old"), page_id.file, page_id.page, expect_lsn, rbp_page_lsn,
                      redo_curr_lsn, curr_page_lsn, disk_page_lsn);

    return use_rbp_page;
}

/*
* latest-only RBPS does not mean "always choose the biggest page_lsn".
* Recovery is only allowed to consume the best candidate that is <= expect_lsn; ahead pages make RBP unsafe.
*/
static rbp_page_status_e rbp_eval_page_candidate(knl_session_t *session, page_id_t page_id, uint64 rbp_page_lsn,
                                                uint64 curr_page_lsn, uint64 expect_lsn, bool32 log_ahead)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    if (rbp_page_lsn == expect_lsn) {
        return RBP_PAGE_HIT;
    }

    if (rbp_page_lsn < expect_lsn) {
        return rbp_page_is_usable(session, page_id, curr_page_lsn, rbp_page_lsn, expect_lsn) ?
               RBP_PAGE_USABLE : RBP_PAGE_OLD;
    }

    if (DB_IS_CLUSTER(session)) {
        if (log_ahead && !redo_ctx->rbp_aly_result.rbp_unsafe) {
            OG_LOG_RUN_WAR("[RBP] page %u-%u ahead of analyze expect (expect %llu rbp %llu); mark unsafe, "
                           "skip rbp page",
                           page_id.file, page_id.page, expect_lsn, rbp_page_lsn);
        }
        rbp_set_unsafe(session, RD_TYPE_END);
        return RBP_PAGE_MISS;
    }

    knl_panic_log(0, "[RBP] ahead page:%u-%u expected LSN:%llu, rbp LSN:%llu, page current LSN:%llu",
                  page_id.file, page_id.page, expect_lsn, rbp_page_lsn, curr_page_lsn);
    return RBP_PAGE_AHEAD;
}

static void rbp_stat_page_result(knl_session_t *session, rbp_page_status_e page_status)
{
    switch (page_status) {
        case RBP_PAGE_HIT:
            session->stat->rbp_hit++;
            break;
        case RBP_PAGE_USABLE:
            session->stat->rbp_usable++;
            break;
        case RBP_PAGE_OLD:
            session->stat->rbp_old++;
            break;
        case RBP_PAGE_MISS:
            session->stat->rbp_miss++;
            break;
        default:
            break;
    }
}

static void rbp_log_ahead_detail(knl_session_t *session, page_id_t page_id, uint32 source_node, uint64 rbp_page_lsn,
                                rbp_analyse_item_t *item, uint64 expect_lsn)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint64 sample;

    if (item == NULL || rbp_page_lsn <= expect_lsn) {
        return;
    }

    sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_ahead_detail);
    if (sample > RBP_READ_SAMPLE_LIMIT) {
        return;
    }

    OG_LOG_RUN_WAR("[RBP] ahead detail sample[%llu/%u]: page %u-%u source_node=%u rbp_lsn=%llu expect_lsn=%llu "
                   "item_node=%u "
                   "item_lfn=%llu first_node=%u first_lfn=%llu touch0=%u:%llu-%llu touch1=%u:%llu-%llu "
                   "redo_end_lfn=%llu rbp_aly_lsn=%llu",
                   sample, RBP_READ_SAMPLE_LIMIT, page_id.file, page_id.page, source_node, (uint64)rbp_page_lsn,
                   (uint64)expect_lsn,
                   (uint32)item->node_id, (uint64)item->lfn, (uint32)item->first_node_id,
                   (uint64)item->first_lfn, (uint32)RBP_ALY_TOUCH_NODE(item->touch_min[0]),
                   (uint64)RBP_ALY_TOUCH_LFN(item->touch_min[0]),
                   (uint64)RBP_ALY_TOUCH_LFN(item->touch_max[0]),
                   (uint32)RBP_ALY_TOUCH_NODE(item->touch_min[1]),
                   (uint64)RBP_ALY_TOUCH_LFN(item->touch_min[1]),
                   (uint64)RBP_ALY_TOUCH_LFN(item->touch_max[1]), (uint64)redo->redo_end_point.lfn,
                   (uint64)redo->rbp_aly_lsn);
}

rbp_page_status_e rbp_page_verify(knl_session_t *session, page_id_t page_id, uint64 rbp_page_lsn,
                                  uint64 curr_page_lsn)
{
    rbp_analyse_item_t *item = rbp_aly_get_page_item(session, page_id);
    uint64 expect_lsn;
    rbp_page_status_e page_status;

    /* page is not in aly_items, that means between rbp_skip_point and lrpl_end_point, no redo about this page */
    if (item == NULL) {
        session->stat->rbp_miss++;
        return RBP_PAGE_MISS;
    }

    if (item->is_verified == OG_TRUE) {
        session->stat->rbp_old++; // ensure that page refreshed as rbp page at most once.
        return RBP_PAGE_OLD;
    }

    expect_lsn = rbp_get_item_expect_lsn(session, item);
    knl_panic_log(expect_lsn > 0, "expect_lsn is abnormal, panic info: page %u-%u expect_lsn %llu", page_id.file,
                  page_id.page, expect_lsn);

    page_status = rbp_eval_page_candidate(session, page_id, rbp_page_lsn, curr_page_lsn, expect_lsn, OG_TRUE);
    rbp_stat_page_result(session, page_status);
    if (page_status == RBP_PAGE_HIT) {
        item->best_lsn = rbp_page_lsn;
        if (!rbp_is_multi_node_rcy(session)) {
            item->is_verified = OG_TRUE;
        }
    } else if (page_status == RBP_PAGE_USABLE) {
        /*
        * In multi-node DTC recovery another node's server may still return a newer candidate for the same page.
        * Do not let a merely usable page lock the analysis item and hide a later HIT candidate.
        */
        if (rbp_page_lsn > item->best_lsn) {
            item->best_lsn = rbp_page_lsn;
        }
        if (!rbp_is_multi_node_rcy(session)) {
            item->is_verified = OG_TRUE;
        }
    }
    return page_status;
}

/* in recover or failover lrpl, if this page has not been pulled by rbp background thread, we pull it immediately */
static rbp_page_status_e rbp_knl_pull_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_read_req_t request;
    rbp_read_resp_t *response = NULL;
    uint32 rbp_proc_id = ctrl->page_id.page % OG_RBP_SESSION_COUNT;
    rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[rbp_proc_id];
    rbp_page_status_e page_status = RBP_PAGE_MISS;

    if (rbp_is_multi_node_rcy(session)) {
        uint32 node_ids[OG_MAX_INSTANCES];
        uint32 node_count = rbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
        bool32 partial_read = rbp_is_dtc_partial_read(session);
        rbp_analyse_item_t *item = partial_read ? NULL : rbp_aly_get_page_item(session, ctrl->page_id);
        rbp_partial_item_t *partial_item = partial_read ? dtc_rcy_rbp_partial_get_item(ctrl->page_id) : NULL;
        uint64 best_lsn = 0;
        uint64 expect_lsn = partial_read ? dtc_rcy_rbp_partial_get_expect_lsn(partial_item) :
            rbp_get_item_expect_lsn(session, item);
        uint64 expect_lfn = partial_read ? (partial_item == NULL ? 0 : partial_item->expect_lfn) :
            (item == NULL ? 0 : item->lfn);
        uint64 old_lsn = PAGE_GET_LSN(ctrl->page);
        uint32 old_pcn = ctrl->page->pcn;
        uint32 best_node = OG_INVALID_ID32;
        rbp_page_status_e best_status = RBP_PAGE_MISS;
        char *best_page_buf = NULL;
        uint32 verify_node_id = OG_INVALID_ID32;
        bool32 in_jumped_window = OG_FALSE;

        if (expect_lsn == 0 || (!partial_read && item == NULL) ||
            (partial_read && (partial_item == NULL || partial_item->rcy_item == NULL ||
                              !partial_item->rcy_item->need_replay))) {
            return RBP_PAGE_MISS;
        }

        if (partial_read) {
            in_jumped_window = dtc_rcy_rbp_partial_item_in_jumped_window(session, partial_item, &verify_node_id);
        }

        if (partial_read && partial_item->selected_valid && partial_item->selected_node != OG_INVALID_ID32) {
            node_ids[0] = partial_item->selected_node;
            node_count = 1;

            if (partial_item->selected_pulled || partial_item->verified) {
                uint64 curr_lsn = PAGE_GET_LSN(ctrl->page);

                ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
                if (curr_lsn == OG_INVALID_LSN) {
                    ctrl->rbp_ctrl->page_status = RBP_PAGE_MISS;
                    rbp_stat_page_result(session, RBP_PAGE_MISS);
                    return RBP_PAGE_MISS;
                }
                if (curr_lsn >= expect_lsn) {
                    if (!partial_item->verified) {
                        dtc_rcy_rbp_partial_mark_item_verified(partial_item);
                    }
                    ctrl->rbp_ctrl->page_status = RBP_PAGE_HIT;
                    rbp_stat_page_result(session, RBP_PAGE_HIT);
                    return RBP_PAGE_HIT;
                }
                ctrl->rbp_ctrl->page_status = RBP_PAGE_USABLE;
                rbp_stat_page_result(session, RBP_PAGE_USABLE);
                return RBP_PAGE_USABLE;
            }
        }

        CM_SAVE_STACK(session->stack);
        response = (rbp_read_resp_t *)cm_push(session->stack, sizeof(rbp_read_resp_t));
        knl_panic(response != NULL);
        best_page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
        knl_panic(best_page_buf != NULL);

        if (partial_read && !rbp_context->dtc_use_selected_batch &&
            dtc_rcy_rbp_partial_copy_candidate(session, partial_item, best_page_buf, DEFAULT_PAGE_SIZE(session),
                                               &best_lsn, &best_node)) {
            best_status = rbp_eval_page_candidate(session, ctrl->page_id, best_lsn, PAGE_GET_LSN(ctrl->page),
                                                  expect_lsn, OG_TRUE);
            if (best_status == RBP_PAGE_HIT) {
                if (best_lsn > PAGE_GET_LSN(ctrl->page)) {
                    rbp_replace_local_page(session, ctrl, (page_head_t *)best_page_buf, NULL);
                }
                dtc_rcy_rbp_partial_update_candidate(partial_item, best_node, best_lsn);
                ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
                ctrl->rbp_ctrl->page_status = best_status;
                rbp_stat_page_result(session, best_status);
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_DEBUG_INF("[RBP_READ_TRACE] PULL_RESULT page=%u-%u partial=%u status=%u expect_lsn=%llu "
                               "expect_lfn=%llu old_lsn=%llu old_pcn=%u returned_lsn=%llu returned_pcn=%u "
                               "read_node=%u best_lsn=%llu",
                               ctrl->page_id.file, ctrl->page_id.page, (uint32)partial_read, (uint32)best_status,
                               (uint64)expect_lsn, (uint64)expect_lfn, (uint64)old_lsn, old_pcn,
                               (uint64)PAGE_GET_LSN(ctrl->page), (uint32)ctrl->page->pcn, best_node,
                               (uint64)best_lsn);
#endif
                CM_RESTORE_STACK(session->stack);
                return best_status;
            }
            if (best_status != RBP_PAGE_USABLE) {
                best_lsn = 0;
                best_node = OG_INVALID_ID32;
                best_status = RBP_PAGE_MISS;
            }
        }

        /*
        * PAGE_READ follows the same rule as BATCH_READ: walk every jumped node server, then keep
        * max(page_lsn <= expect_lsn). This avoids taking an ahead page just because that node's server
        * flushed it later.
        */
        for (uint32 i = 0; i < node_count; i++) {
            uint32 node_id = node_ids[i];
            cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, OG_TRUE);
            cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
            if (rbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                rbp_mark_dtc_read_failed(rbp_context, node_id, RBP_READ_RESULT_ERROR,
                                        "on-demand connect failed");
                CM_RESTORE_STACK(session->stack);
                return RBP_PAGE_ERROR;
            }

            RBP_SET_MSG_HEADER(&request, RBP_REQ_PAGE_READ, sizeof(rbp_read_req_t), cs_get_socket_fd(pipe));
            request.page_id = ctrl->page_id;
            request.buf_pool_id = ctrl->buf_pool_id;

            if (rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
                cs_disconnect(pipe);
                mgr->temp_connected_node = OG_INVALID_ID32;
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                rbp_mark_dtc_read_failed(rbp_context, node_id, RBP_READ_RESULT_ERROR, "on-demand send failed");
                CM_RESTORE_STACK(session->stack);
                return RBP_PAGE_ERROR;
            }

            if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_read_resp_t)) != OG_SUCCESS) {
                cs_disconnect(pipe);
                mgr->temp_connected_node = OG_INVALID_ID32;
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                rbp_mark_dtc_read_failed(rbp_context, node_id, RBP_READ_RESULT_ERROR,
                                        "on-demand wait response failed");
                CM_RESTORE_STACK(session->stack);
                return RBP_PAGE_ERROR;
            }
            cm_spin_unlock(&mgr->fisrt_pipe_lock);

            if (response->result == RBP_READ_RESULT_NOPAGE) {
#ifdef RBP_VERBOSE_TRACE
                OG_LOG_DEBUG_INF("[RBP_READ_TRACE] PULL_CANDIDATE page=%u-%u partial=%u node=%u result=%u "
                               "expect_lsn=%llu expect_lfn=%llu old_lsn=%llu old_pcn=%u required=%u "
                               "selected_valid=%u selected_pulled=%u verified=%u in_jumped_window=%u "
                               "verify_node=%u selected_node=%u load_status=%u",
                               ctrl->page_id.file, ctrl->page_id.page, (uint32)partial_read, node_id,
                               (uint32)response->result, (uint64)expect_lsn, (uint64)expect_lfn, (uint64)old_lsn,
                               old_pcn, (uint32)(partial_read && partial_item->required),
                               (uint32)(partial_read && partial_item->selected_valid),
                               (uint32)(partial_read && partial_item->selected_pulled),
                               (uint32)(partial_read && partial_item->verified), (uint32)in_jumped_window,
                               verify_node_id,
                               (uint32)(partial_read ? partial_item->selected_node : OG_INVALID_ID32),
                               (uint32)ctrl->load_status);
#endif
                continue;
            }
            if (response->result != RBP_READ_RESULT_OK) {
                response->block[RBP_MSG_LEN - 1] = '\0';
                OG_LOG_RUN_WAR("[RBP] on-demand PAGE_READ error from node %u: page=%u-%u result=%u msg=%s",
                               node_id, ctrl->page_id.file, ctrl->page_id.page, response->result, response->block);
                rbp_mark_dtc_read_failed(rbp_context, node_id, response->result, "on-demand response error");
                CM_RESTORE_STACK(session->stack);
                return RBP_PAGE_ERROR;
            }

            if (partial_read && partial_item->selected_valid) {
                uint64 rbp_lsn = PAGE_GET_LSN(response->block);

                partial_item->seen_node_bitmap |= ((uint64)1 << (node_id % RBP_NODE_BITMAP_BITS));
                if (rbp_lsn != partial_item->selected_lsn) {
                    uint64 sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_selected_mismatch);
                    if (sample <= RBP_READ_SAMPLE_LIMIT) {
                        OG_LOG_RUN_WAR("[RBP] selected PAGE_READ lsn mismatch sample[%llu/%u]: page=%u-%u node=%u "
                                       "selected_lsn=%llu page_lsn=%llu expect_lsn=%llu required=%u "
                                       "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u "
                                       "load_status=%u",
                                       sample, RBP_READ_SAMPLE_LIMIT, ctrl->page_id.file, ctrl->page_id.page,
                                       node_id, (uint64)partial_item->selected_lsn, (uint64)rbp_lsn,
                                       (uint64)expect_lsn, (uint32)partial_item->required,
                                       (uint32)partial_item->selected_pulled, (uint32)partial_item->verified,
                                       (uint32)in_jumped_window, verify_node_id, (uint32)ctrl->load_status);
                    }
                }
                if (rbp_lsn > expect_lsn) {
                    rbp_log_partial_ahead_detail(session, partial_item, node_id, rbp_lsn, expect_lsn);
                    CM_RESTORE_STACK(session->stack);
                    return RBP_PAGE_MISS;
                }

                page_status = rbp_partial_selected_baseline_apply(session, ctrl, partial_item,
                    (page_head_t *)response->block, rbp_lsn, expect_lsn, NULL, NULL, NULL, NULL);
                rbp_stat_page_result(session, page_status);
                CM_RESTORE_STACK(session->stack);
                return page_status;
            }

            page_status = rbp_eval_page_candidate(session, ctrl->page_id, PAGE_GET_LSN(response->block),
                                                  PAGE_GET_LSN(ctrl->page), expect_lsn, OG_TRUE);
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_INF("[RBP_READ_TRACE] PULL_CANDIDATE page=%u-%u partial=%u node=%u result=%u status=%u "
                           "expect_lsn=%llu expect_lfn=%llu old_lsn=%llu old_pcn=%u candidate_lsn=%llu "
                           "candidate_pcn=%u curr_lsn=%llu curr_pcn=%u required=%u selected_valid=%u "
                           "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                           "load_status=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)partial_read, node_id,
                           (uint32)response->result, (uint32)page_status, (uint64)expect_lsn, (uint64)expect_lfn,
                           (uint64)old_lsn, old_pcn, (uint64)PAGE_GET_LSN(response->block),
                           (uint32)((page_head_t *)response->block)->pcn, (uint64)PAGE_GET_LSN(ctrl->page),
                           (uint32)ctrl->page->pcn, (uint32)(partial_read && partial_item->required),
                           (uint32)(partial_read && partial_item->selected_valid),
                           (uint32)(partial_read && partial_item->selected_pulled),
                           (uint32)(partial_read && partial_item->verified), (uint32)in_jumped_window,
                           verify_node_id, (uint32)(partial_read ? partial_item->selected_node : OG_INVALID_ID32),
                           (uint32)ctrl->load_status);
#endif
            if (partial_read) {
                partial_item->seen_node_bitmap |= ((uint64)1 << (node_id % RBP_NODE_BITMAP_BITS));
                if (partial_item->selected_valid && PAGE_GET_LSN(response->block) != partial_item->selected_lsn) {
                    uint64 sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_selected_mismatch);
                    if (sample <= RBP_READ_SAMPLE_LIMIT) {
                        OG_LOG_RUN_WAR("[RBP] selected PAGE_READ lsn mismatch sample[%llu/%u]: page=%u-%u node=%u "
                                       "selected_lsn=%llu page_lsn=%llu expect_lsn=%llu required=%u "
                                       "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u "
                                       "load_status=%u",
                                       sample, RBP_READ_SAMPLE_LIMIT, ctrl->page_id.file, ctrl->page_id.page,
                                       node_id, (uint64)partial_item->selected_lsn,
                                       (uint64)PAGE_GET_LSN(response->block), (uint64)expect_lsn,
                                       (uint32)partial_item->required, (uint32)partial_item->selected_pulled,
                                       (uint32)partial_item->verified, (uint32)in_jumped_window, verify_node_id,
                                       (uint32)ctrl->load_status);
                    }
                }
                if (PAGE_GET_LSN(response->block) > expect_lsn) {
                    rbp_log_partial_ahead_detail(session, partial_item, node_id, PAGE_GET_LSN(response->block),
                                                expect_lsn);
                }
            } else {
                item->seen_node_bitmap |= ((uint64)1 << (node_id % RBP_NODE_BITMAP_BITS));
                if (PAGE_GET_LSN(response->block) > expect_lsn) {
                    rbp_log_ahead_detail(session, ctrl->page_id, node_id, PAGE_GET_LSN(response->block), item,
                                        expect_lsn);
                }
            }
            if ((page_status == RBP_PAGE_HIT || page_status == RBP_PAGE_USABLE) &&
                PAGE_GET_LSN(response->block) > best_lsn) {
                errno_t ret = memcpy_sp(best_page_buf, DEFAULT_PAGE_SIZE(session), response->block,
                                        DEFAULT_PAGE_SIZE(session));
                knl_securec_check(ret);
                best_lsn = PAGE_GET_LSN(response->block);
                best_status = page_status;
                best_node = node_id;
            }
        }

        if (best_lsn > 0) {
            if (best_lsn > PAGE_GET_LSN(ctrl->page)) {
                rbp_replace_local_page(session, ctrl, (page_head_t *)best_page_buf, NULL);
            }
            if (partial_read) {
                dtc_rcy_rbp_partial_update_selected(partial_item, best_node, best_lsn);
                dtc_rcy_rbp_partial_mark_selected_pulled(partial_item, best_lsn);
                if (best_status == RBP_PAGE_HIT) {
                    dtc_rcy_rbp_partial_mark_item_verified(partial_item);
                }
            } else {
                item->best_lsn = best_lsn;
                item->best_source_node = best_node;
            }
            ctrl->rbp_ctrl->rbp_read_version = KNL_RBP_READ_VER(session->kernel);
            ctrl->rbp_ctrl->page_status = best_status;
            rbp_stat_page_result(session, best_status);
            page_status = best_status;
        }

        if (page_status == RBP_PAGE_MISS || page_status == RBP_PAGE_ERROR || best_lsn == 0) {
            uint64 sample = (uint64)cm_atomic_inc(&rbp_context->rbp_read_pull_miss_trace);
            if (sample <= RBP_READ_SAMPLE_LIMIT) {
                OG_LOG_DEBUG_INF("[RBP_READ_TRACE] PULL_RESULT sample[%llu/%u] page=%u-%u partial=%u status=%u "
                               "expect_lsn=%llu expect_lfn=%llu old_lsn=%llu old_pcn=%u returned_lsn=%llu "
                               "returned_pcn=%u read_node=%u best_lsn=%llu required=%u selected_valid=%u "
                               "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                               "load_status=%u",
                               sample, RBP_READ_SAMPLE_LIMIT, ctrl->page_id.file, ctrl->page_id.page,
                               (uint32)partial_read, (uint32)page_status, (uint64)expect_lsn, (uint64)expect_lfn,
                               (uint64)old_lsn, old_pcn, (uint64)PAGE_GET_LSN(ctrl->page),
                               (uint32)ctrl->page->pcn, best_node, (uint64)best_lsn,
                               (uint32)(partial_read && partial_item->required),
                               (uint32)(partial_read && partial_item->selected_valid),
                               (uint32)(partial_read && partial_item->selected_pulled),
                               (uint32)(partial_read && partial_item->verified), (uint32)in_jumped_window,
                               verify_node_id,
                               (uint32)(partial_read ? partial_item->selected_node : OG_INVALID_ID32),
                               (uint32)ctrl->load_status);
            }
        } else {
#ifdef RBP_VERBOSE_TRACE
            OG_LOG_DEBUG_INF("[RBP_READ_TRACE] PULL_RESULT page=%u-%u partial=%u status=%u expect_lsn=%llu "
                           "expect_lfn=%llu old_lsn=%llu old_pcn=%u returned_lsn=%llu returned_pcn=%u "
                           "read_node=%u best_lsn=%llu required=%u selected_valid=%u selected_pulled=%u "
                           "verified=%u in_jumped_window=%u verify_node=%u selected_node=%u load_status=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)partial_read, (uint32)page_status,
                           (uint64)expect_lsn, (uint64)expect_lfn, (uint64)old_lsn, old_pcn,
                           (uint64)PAGE_GET_LSN(ctrl->page),
                           (uint32)ctrl->page->pcn, best_node, (uint64)best_lsn,
                           (uint32)(partial_read && partial_item->required),
                           (uint32)(partial_read && partial_item->selected_valid),
                           (uint32)(partial_read && partial_item->selected_pulled),
                           (uint32)(partial_read && partial_item->verified), (uint32)in_jumped_window,
                           verify_node_id, (uint32)(partial_read ? partial_item->selected_node : OG_INVALID_ID32),
                           (uint32)ctrl->load_status);
#endif
        }
        CM_RESTORE_STACK(session->stack);
        return page_status;
    }

    {
        cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, OG_TRUE);
        RBP_SET_MSG_HEADER(&request, RBP_REQ_PAGE_READ, sizeof(rbp_read_req_t), cs_get_socket_fd(pipe));
        /* set message body */
        request.page_id = ctrl->page_id;
        request.buf_pool_id = ctrl->buf_pool_id;

        /* Same lock as rbp_knl_read_pages: one TCP byte stream per queue on pipe_temp; no interleave. */
        cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
        if (rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
            cs_disconnect(pipe);
            mgr->temp_connected_node = OG_INVALID_ID32;
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return RBP_PAGE_ERROR;
        }

        CM_SAVE_STACK(session->stack);
        response = (rbp_read_resp_t *)cm_push(session->stack, sizeof(rbp_read_resp_t));
        knl_panic(response != NULL);
        if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_read_resp_t)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[RBP] rbp wait response failed while send request rbp_read_req");
            CM_RESTORE_STACK(session->stack);
            cs_disconnect(pipe);
            mgr->temp_connected_node = OG_INVALID_ID32;
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return RBP_PAGE_ERROR;
        }
        cm_spin_unlock(&mgr->fisrt_pipe_lock);

        page_status = rbp_process_read_resp(session, response, ctrl);

        CM_RESTORE_STACK(session->stack);
    }
    return page_status;
}

static void rbp_stop_one_temp_pipe(rbp_buf_manager_t *manager, cs_pipe_t *pipe, spinlock_t *lock,
                                   uint32 *connected_node, const char *pipe_name)
{
    rbp_msg_hdr_t request;

    if (!rbp_pipe_valid(pipe)) {
        return;
    }

    cm_spin_lock(lock, NULL);
    if (!rbp_pipe_valid(pipe)) {
        cm_spin_unlock(lock);
        return;
    }

    RBP_SET_MSG_HEADER(&request, RBP_REQ_CLOSE_CONN, sizeof(rbp_msg_hdr_t), cs_get_socket_fd(pipe));
    request.queue_id = manager->queue_id;
    if (cs_write_stream_timeout(pipe, (char *)&request, request.msg_length, 0, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RBP] failed to send %s close request, queue=%u fd=%d",
                       pipe_name, manager->queue_id, request.msg_fd);
    }
    cm_sleep(1);
    cs_disconnect(pipe);
    *connected_node = OG_INVALID_ID32;
    cm_spin_unlock(lock);
}

static void rbp_stop_temp_connection(knl_session_t *session, rbp_context_t *rbp_context)
{
    rbp_buf_manager_t *manager = NULL;

    for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        manager = &rbp_context->rbp_buf_manager[id];
        rbp_stop_one_temp_pipe(manager, &manager->pipe_temp, &manager->fisrt_pipe_lock,
                               &manager->temp_connected_node, "temp");
        rbp_stop_one_temp_pipe(manager, &manager->pipe_selected_temp, &manager->selected_pipe_lock,
                               &manager->selected_temp_connected_node, "selected temp");
    }

    OG_LOG_RUN_INF("[RBP] rbp temp connections are closed");
}

static status_t rbp_notify_dtc_node_read_phase(knl_session_t *session, uint32 node_id, rbp_notify_msg_e msg)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[0];
    rbp_msg_ack_t ack;

    cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
    if (rbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
        cm_spin_unlock(&mgr->fisrt_pipe_lock);
        OG_LOG_RUN_WAR("[RBP] failed to connect node %u RBP for DTC read phase msg %u", node_id, (uint32)msg);
        return OG_ERROR;
    }
    if (rbp_notify_msg(session, msg, 0, &ack) != OG_SUCCESS) {
        cs_disconnect(&mgr->pipe_temp);
        mgr->temp_connected_node = OG_INVALID_ID32;
        cm_spin_unlock(&mgr->fisrt_pipe_lock);
        OG_LOG_RUN_WAR("[RBP] failed to notify node %u RBP read phase msg %u", node_id, (uint32)msg);
        return OG_ERROR;
    }
    cm_spin_unlock(&mgr->fisrt_pipe_lock);
    return OG_SUCCESS;
}

static status_t rbp_notify_dtc_read_phase(knl_session_t *session, rbp_notify_msg_e msg)
{
    uint32 node_ids[OG_MAX_INSTANCES];
    uint32 node_count = rbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
    dtc_rcy_context_t *dtc_rcy = (g_dtc != NULL) ? DTC_RCY_CONTEXT : NULL;

    /*
    * Multi-node RBP keeps the v4 read-window contract: each node's server receives
    * READ_BEGIN once, snapshots page_cache into batch_pending, then BATCH_READ only drains
    * that cursor until NOPAGE. This avoids re-seeding from page_cache on every pull.
    */
    if (node_count == 0 && msg == MSG_RBP_READ_BEGIN) {
        OG_LOG_RUN_WAR("[RBP] refuse DTC partial READ_BEGIN with no active RBP nodes: in_progress=%u node_count=%u",
                       (dtc_rcy == NULL) ? 0 : (uint32)dtc_rcy->in_progress,
                       (dtc_rcy == NULL) ? 0 : dtc_rcy->node_count);
        return OG_ERROR;
    }
    for (uint32 i = 0; i < node_count; i++) {
        if (rbp_notify_dtc_node_read_phase(session, node_ids[i], msg) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static void rbp_disable_dtc_planned_nodes(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return;
    }

    for (uint32 i = 0; i < rbp_context->dtc_read_node_count; i++) {
        uint32 node_id = rbp_context->dtc_read_nodes[i];
        if (node_id < OG_MAX_INSTANCES) {
            DTC_RCY_CONTEXT->rbp_read_planned[node_id] = OG_FALSE;
        }
    }
}

static status_t rbp_notify_dtc_read_begin_planned(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    dtc_rcy_context_t *dtc_rcy = (g_dtc != NULL) ? DTC_RCY_CONTEXT : NULL;
    uint32 original_count = rbp_context->dtc_read_node_count;
    uint32 kept = 0;

    OG_LOG_DEBUG_INF("[RBP] notify DTC READ_BEGIN to %u planned candidate nodes", original_count);
    for (uint32 i = 0; i < original_count; i++) {
        uint32 node_id = rbp_context->dtc_read_nodes[i];
        OG_LOG_DEBUG_INF("[RBP] notify DTC READ_BEGIN target[%u]=node%u", i, node_id);
        if (rbp_notify_dtc_node_read_phase(session, node_id, MSG_RBP_READ_BEGIN) != OG_SUCCESS) {
            if (dtc_rcy != NULL && node_id < OG_MAX_INSTANCES) {
                dtc_rcy->rbp_read_planned[node_id] = OG_FALSE;
            }
            OG_LOG_RUN_WAR("[RBP] DTC READ_BEGIN node %u failed, remove from planned read set", node_id);
            continue;
        }

        if (kept != i) {
            rbp_context->dtc_read_nodes[kept] = rbp_context->dtc_read_nodes[i];
            rbp_context->dtc_read_skip_points[kept] = rbp_context->dtc_read_skip_points[i];
            rbp_context->dtc_read_rcy_points[kept] = rbp_context->dtc_read_rcy_points[i];
            rbp_context->dtc_read_lrp_points[kept] = rbp_context->dtc_read_lrp_points[i];
        }
        kept++;
    }

    rbp_context->dtc_read_node_count = (uint16)kept;
    if (kept == 0) {
        OG_LOG_RUN_WAR("[RBP] DTC READ_BEGIN failed for all planned nodes");
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("[RBP] DTC READ_BEGIN success: planned_nodes=%u/%u", kept, original_count);
    return OG_SUCCESS;
}

typedef struct st_rbp_selected_pull_stat {
    uint32 selected;
    uint32 missing;
    uint32 ahead;
    uint32 requested;
    uint32 returned;
    uint32 installed;
    uint32 verified;
    uint32 mismatch;
} rbp_selected_pull_stat_t;

static void rbp_choose_dtc_selected_mode(knl_session_t *session, bool32 *use_selected_batch,
                                        bool32 *need_selected_meta, bool32 *sync_selected_pull_at_begin)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    bool32 use_selected = (bool32)(rbp_is_dtc_partial_read(session) && rbp_context->dtc_read_node_count > 0);
    bool32 need_meta = (bool32)(use_selected && rbp_context->dtc_read_node_count > 1);

    *use_selected_batch = use_selected;
    *need_selected_meta = need_meta;
    *sync_selected_pull_at_begin = need_meta;
}

static void rbp_assign_selected_workers(rbp_context_t *rbp_context, uint32 *selected_by_node)
{
    uint32 assigned[OG_MAX_INSTANCES] = { 0 };
    uint64 total = 0;

    for (uint32 i = 0; i < OG_RBP_SESSION_COUNT; i++) {
        rbp_context->dtc_selected_worker_nodes[i] = OG_INVALID_ID32;
    }

    for (uint32 i = 0; i < rbp_context->dtc_read_node_count; i++) {
        uint32 node_id = rbp_context->dtc_read_nodes[i];
        if (node_id < OG_MAX_INSTANCES) {
            total += selected_by_node[node_id];
        }
    }

    if (total == 0) {
        return;
    }

    for (uint32 worker = 0; worker < OG_RBP_SESSION_COUNT; worker++) {
        uint32 best_node = OG_INVALID_ID32;
        uint64 best_score = 0;

        for (uint32 i = 0; i < rbp_context->dtc_read_node_count; i++) {
            uint32 node_id = rbp_context->dtc_read_nodes[i];
            uint64 score;

            if (node_id >= OG_MAX_INSTANCES || selected_by_node[node_id] == 0) {
                continue;
            }
            score = ((uint64)selected_by_node[node_id] << RBP_SELECTED_SCORE_SHIFT) /
                (uint64)(assigned[node_id] + 1);
            if (best_node == OG_INVALID_ID32 || score > best_score) {
                best_node = node_id;
                best_score = score;
            }
        }

        if (best_node == OG_INVALID_ID32) {
            return;
        }
        rbp_context->dtc_selected_worker_nodes[worker] = best_node;
        assigned[best_node]++;
    }

    OG_LOG_RUN_INF("[RBP] selected worker assignment: w0=%u w1=%u w2=%u w3=%u w4=%u w5=%u w6=%u w7=%u",
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT0],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT1],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT2],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT3],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT4],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT5],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT6],
                   rbp_context->dtc_selected_worker_nodes[RBP_SELECTED_WORKER_LOG_SLOT7]);
}

static void rbp_process_meta_chunk_resp(knl_session_t *session, uint32 node_id, rbp_read_meta_resp_t *resp,
                                        rbp_selected_pull_stat_t *stat)
{
    for (uint32 i = 0; i < resp->count && i < RBP_META_CHUNK_NUM; i++) {
        rbp_meta_item_t *meta = &resp->items[i];
        rbp_partial_item_t *item = dtc_rcy_rbp_partial_get_item(meta->page_id);
        uint64 expect_lsn;

        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            continue;
        }
        expect_lsn = dtc_rcy_rbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0 || meta->page_lsn == 0) {
            continue;
        }
        if (meta->page_lsn > expect_lsn) {
            stat->ahead++;
            if (stat->ahead <= RBP_META_AHEAD_SAMPLE_LIMIT) {
                rbp_log_partial_ahead_detail(session, item, node_id, meta->page_lsn, expect_lsn);
            }
            continue;
        }
        dtc_rcy_rbp_partial_update_selected(item, node_id, meta->page_lsn);
    }
}

static status_t rbp_pull_selected_meta_from_node(knl_session_t *session, uint32 node_id,
                                                rbp_selected_pull_stat_t *stat)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[0];
    cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, 0, OG_TRUE);
    rbp_read_meta_req_t request;
    rbp_read_meta_resp_t *response = (rbp_read_meta_resp_t *)rbp_context->batch_buf[0];
    uint64 cursor = 0;
    uint64 epoch = 0;
    uint32 chunks = 0;
#if RBP_READ_HOT_DIAG
    date_t begin_time = cm_now();
#endif
    errno_t ret;

    for (;;) {
        ret = memset_sp(&request, sizeof(request), 0, sizeof(request));
        knl_securec_check(ret);
        request.epoch = epoch;
        request.cursor = cursor;
        request.max_count = RBP_META_CHUNK_NUM;

        cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
        if (rbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return OG_ERROR;
        }
        RBP_SET_MSG_HEADER(&request, RBP_REQ_READ_META_CHUNK, sizeof(rbp_read_meta_req_t),
                           cs_get_socket_fd(pipe));
        if (rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
            cs_disconnect(pipe);
            mgr->temp_connected_node = OG_INVALID_ID32;
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return OG_ERROR;
        }
        if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_read_meta_resp_t)) != OG_SUCCESS) {
            cs_disconnect(pipe);
            mgr->temp_connected_node = OG_INVALID_ID32;
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return OG_ERROR;
        }
        cm_spin_unlock(&mgr->fisrt_pipe_lock);

        if (response->result != RBP_READ_RESULT_OK && response->result != RBP_READ_RESULT_NOPAGE) {
            OG_LOG_RUN_WAR("[RBP] selected meta pull failed: node=%u result=%u cursor=%llu",
                           node_id, response->result, cursor);
            return OG_ERROR;
        }
        rbp_process_meta_chunk_resp(session, node_id, response, stat);
        chunks++;
        epoch = response->epoch;
        if (response->done) {
#if RBP_READ_HOT_DIAG
            OG_LOG_DEBUG_INF("[RBP] selected meta node summary: node=%u chunks=%u total=%llu elapsed_us=%llu",
                            node_id, chunks, (uint64)response->total_count,
                            (uint64)(cm_now() - begin_time));
#else
            OG_LOG_DEBUG_INF("[RBP] selected meta node summary: node=%u chunks=%u total=%llu",
                            node_id, chunks, (uint64)response->total_count);
#endif
            return OG_SUCCESS;
        }
        if (response->next_cursor <= cursor) {
            OG_LOG_RUN_WAR("[RBP] selected meta cursor stuck: node=%u cursor=%llu next=%llu total=%llu",
                           node_id, cursor, (uint64)response->next_cursor, (uint64)response->total_count);
            return OG_ERROR;
        }
        cursor = response->next_cursor;
    }
}

static status_t rbp_pull_selected_metadata(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_selected_pull_stat_t stat = { 0 };
    uint32 selected_by_node[OG_MAX_INSTANCES] = { 0 };
    uint32 required_count = dtc_rcy_rbp_partial_required_count();
#if RBP_READ_HOT_DIAG
    date_t begin_time = cm_now();
#endif

    for (uint32 i = 0; i < rbp_context->dtc_read_node_count; i++) {
        if (rbp_pull_selected_meta_from_node(session, rbp_context->dtc_read_nodes[i], &stat) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    for (uint32 i = 0; i < required_count; i++) {
        rbp_partial_item_t *item = dtc_rcy_rbp_partial_required_item(i);
        if (item == NULL || !item->required) {
            continue;
        }
        if (item->selected_valid) {
            stat.selected++;
            if (item->selected_node < OG_MAX_INSTANCES) {
                selected_by_node[item->selected_node]++;
            }
        } else {
            stat.missing++;
            if (stat.missing <= RBP_SELECTED_MISS_SAMPLE_LIMIT) {
                OG_LOG_RUN_WAR("[RBP] selected miss sample: page=%u-%u expect_lsn=%llu expect_lfn=%llu "
                               "seen_bitmap=0x%llx",
                               item->page_id.file, item->page_id.page, (uint64)item->expect_lsn,
                               (uint64)item->expect_lfn, (uint64)item->seen_node_bitmap);
            }
        }
    }

#if RBP_READ_HOT_DIAG
    OG_LOG_DEBUG_INF("[RBP] selected metadata summary: planned_nodes=%u required=%u selected=%u missing=%u ahead=%u "
                    "elapsed_us=%llu",
                    rbp_context->dtc_read_node_count, required_count, stat.selected, stat.missing, stat.ahead,
                    (uint64)(cm_now() - begin_time));
#else
    OG_LOG_DEBUG_INF("[RBP] selected metadata summary: planned_nodes=%u required=%u selected=%u missing=%u ahead=%u",
                    rbp_context->dtc_read_node_count, required_count, stat.selected, stat.missing, stat.ahead);
#endif
    rbp_assign_selected_workers(rbp_context, selected_by_node);
    return OG_SUCCESS;
}

static status_t rbp_prepare_single_node_direct_selected(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 required_count = dtc_rcy_rbp_partial_required_count();
    uint32 selected = 0;
    uint32 missing_expect = 0;
    uint32 node_id;
#if RBP_READ_HOT_DIAG
    date_t begin_time = cm_now();
#endif

    if (rbp_context->dtc_read_node_count != 1) {
        return OG_ERROR;
    }

    node_id = rbp_context->dtc_read_nodes[0];
    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < required_count; i++) {
        rbp_partial_item_t *item = dtc_rcy_rbp_partial_required_item(i);
        uint64 expect_lsn;

        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            continue;
        }
        expect_lsn = dtc_rcy_rbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            missing_expect++;
            continue;
        }
        dtc_rcy_rbp_partial_update_selected(item, node_id, expect_lsn);
        selected++;
    }

    for (uint32 worker = 0; worker < OG_RBP_SESSION_COUNT; worker++) {
        rbp_context->dtc_selected_worker_nodes[worker] = node_id;
    }
#if RBP_READ_HOT_DIAG
    OG_LOG_DEBUG_INF("[RBP] selected direct prepare summary: node=%u required=%u selected=%u missing_expect=%u "
                    "elapsed_us=%llu",
                    node_id, required_count, selected, missing_expect, (uint64)(cm_now() - begin_time));
#else
    OG_LOG_DEBUG_INF("[RBP] selected direct prepare summary: node=%u required=%u selected=%u missing_expect=%u",
                    node_id, required_count, selected, missing_expect);
#endif
    return OG_SUCCESS;
}

static uint32 rbp_fetch_selected_batch_for_node(knl_session_t *session, uint32 node_id,
                                                rbp_batch_selected_read_req_t *request)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 required_count = dtc_rcy_rbp_partial_required_count();
    uint32 count = 0;
    uint32 cursor;
    errno_t ret = memset_sp(request, sizeof(rbp_batch_selected_read_req_t), 0,
                            sizeof(rbp_batch_selected_read_req_t));
    knl_securec_check(ret);

    if (node_id >= OG_MAX_INSTANCES) {
        return 0;
    }

    cm_spin_lock(&rbp_context->dtc_selected_lock[node_id], NULL);
    cursor = rbp_context->dtc_selected_cursor[node_id];
    while (cursor < required_count && count < RBP_BATCH_PAGE_NUM) {
        rbp_partial_item_t *item = dtc_rcy_rbp_partial_required_item(cursor);
        cursor++;
        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay ||
            !item->selected_valid || item->selected_node != node_id || item->selected_pulled || item->verified) {
            continue;
        }
        request->pages[count].page_id = item->page_id;
        request->pages[count].selected_lsn = item->selected_lsn;
        count++;
    }
    rbp_context->dtc_selected_cursor[node_id] = cursor;
    cm_spin_unlock(&rbp_context->dtc_selected_lock[node_id]);
    return count;
}

static uint32 rbp_process_selected_batch_resp(knl_session_t *session, uint32 node_id, rbp_batch_read_resp_t *resp,
                                              uint32 requested, rbp_selected_pull_stat_t *stat,
                                              rbp_read_apply_diag_t *diag)
{
    if (resp->result != RBP_READ_RESULT_OK && resp->result != RBP_READ_RESULT_NOPAGE) {
        resp->msg[RBP_MSG_LEN - 1] = '\0';
        OG_LOG_RUN_WAR("[RBP] selected batch read error from node %u: result=%u msg=%s",
                       node_id, resp->result, resp->msg);
        return RBP_READ_RESULT_ERROR;
    }

    stat->requested += requested;
    stat->returned += resp->count;
    if (diag != NULL) {
        diag->resp_pages += resp->count;
        diag->selected_requested += requested;
    }
    if (resp->count < requested) {
        stat->missing += (requested - resp->count);
        if (diag != NULL) {
            diag->selected_missing += (requested - resp->count);
        }
    }

    for (uint32 i = 0; i < resp->count; i++) {
        rbp_page_item_t *rbp_page = &resp->pages[i];
        rbp_partial_item_t *item = dtc_rcy_rbp_partial_get_item(rbp_page->page_id);
        page_id_t page_id;
        uint64 expect_lsn;
        uint64 page_lsn;

        if (item == NULL || !item->required || !item->selected_valid || item->selected_node != node_id) {
            if (diag != NULL) {
                diag->not_required++;
            }
            continue;
        }
        expect_lsn = dtc_rcy_rbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            if (diag != NULL) {
                diag->no_expect++;
            }
            continue;
        }
        page_id = AS_PAGID(((page_head_t *)rbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(rbp_page->page_id, page_id), "selected rbp_page id mismatch, panic info: "
                      "rbp_page %u-%u block %u-%u", rbp_page->page_id.file, rbp_page->page_id.page,
                      page_id.file, page_id.page);

        page_lsn = PAGE_GET_LSN(rbp_page->block);
        if (page_lsn != item->selected_lsn) {
            stat->mismatch++;
            if (diag != NULL) {
                diag->selected_mismatch++;
            }
        }
        if (page_lsn > expect_lsn) {
            stat->ahead++;
            if (diag != NULL) {
                diag->ahead++;
            }
            rbp_log_partial_ahead_detail(session, item, node_id, page_lsn, expect_lsn);
            continue;
        }

        if (item->selected_pulled || item->verified) {
            if (diag != NULL) {
                diag->not_newer++;
            }
            continue;
        }

        if (diag != NULL) {
            bool32 not_newer = OG_FALSE;
            rbp_page_status_e page_status;
            uint32 installed_before = stat->installed;

            diag->selected++;
            page_status = rbp_partial_selected_batch_install_page(session, page_id, rbp_page, item, expect_lsn,
                page_lsn, &stat->installed, &stat->verified, &not_newer, diag);
            diag->installed += (stat->installed - installed_before);
            if (page_status == RBP_PAGE_HIT) {
                diag->selected_verified++;
            }
            rbp_count_partial_page_status(diag, page_status, not_newer);
        } else {
            (void)rbp_partial_selected_batch_install_page(session, page_id, rbp_page, item, expect_lsn, page_lsn,
                &stat->installed, &stat->verified, NULL, NULL);
        }
    }
    return RBP_READ_RESULT_OK;
}

static uint32 rbp_knl_read_selected_pages(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    uint32 node_id;
    uint32 count;
    rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[rbp_proc_id];
    cs_pipe_t *pipe = rbp_get_selected_temp_pipe(rbp_context, rbp_proc_id);
    rbp_batch_selected_read_req_t request;
    rbp_batch_read_resp_t *response = (rbp_batch_read_resp_t *)rbp_context->batch_buf[rbp_proc_id];
    rbp_selected_pull_stat_t stat = { 0 };
#if RBP_READ_HOT_DIAG
    rbp_read_apply_diag_t apply_diag = { 0 };
    rbp_read_apply_diag_t *apply_diag_ptr = &apply_diag;
#else
    rbp_read_apply_diag_t *apply_diag_ptr = NULL;
#endif
    date_t begin_time = cm_now();
    date_t step_begin;
    uint64 pipe_lock_us = 0;
    uint64 ensure_conn_us = 0;
    uint64 send_us = 0;
    uint64 wait_resp_us = 0;
    uint64 process_us = 0;
    uint32 process_result;

    if (rbp_context->dtc_read_node_count == 0) {
        rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_NOPAGE, 0, begin_time,
                                   0, 0, 0, 0, 0, NULL);
        return RBP_READ_RESULT_NOPAGE;
    }

    node_id = rbp_context->dtc_selected_worker_nodes[rbp_proc_id];
    if (node_id == OG_INVALID_ID32) {
        rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_NOPAGE, 0, begin_time,
                                   0, 0, 0, 0, 0, NULL);
        return RBP_READ_RESULT_NOPAGE;
    }
    count = rbp_fetch_selected_batch_for_node(session, node_id, &request);
    if (count == 0) {
        rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_NOPAGE, 0, begin_time,
                                   0, 0, 0, 0, 0, NULL);
        return RBP_READ_RESULT_NOPAGE;
    }

    RBP_READ_STEP_BEGIN(step_begin);
    cm_spin_lock(&mgr->selected_pipe_lock, NULL);
    RBP_READ_STEP_ACCUM(step_begin, pipe_lock_us);
    RBP_READ_STEP_BEGIN(step_begin);
    if (rbp_ensure_selected_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
        cm_spin_unlock(&mgr->selected_pipe_lock);
        RBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);
        rbp_mark_dtc_read_failed(rbp_context, node_id, RBP_READ_RESULT_ERROR, "selected connect failed");
        rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return RBP_READ_RESULT_ERROR;
    }
    RBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);
    request.count = count;
    RBP_SET_MSG_HEADER(&request, RBP_REQ_BATCH_PAGE_READ_SELECTED, sizeof(rbp_batch_selected_read_req_t),
                       cs_get_socket_fd(pipe));
    request.header.queue_id = rbp_proc_id;
    RBP_READ_STEP_BEGIN(step_begin);
    if (rbp_knl_send_request_timeout(pipe, (char *)&request, NULL, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
        cs_disconnect(pipe);
        mgr->selected_temp_connected_node = OG_INVALID_ID32;
        cm_spin_unlock(&mgr->selected_pipe_lock);
        RBP_READ_STEP_ACCUM(step_begin, send_us);
        rbp_mark_dtc_read_failed(rbp_context, node_id, RBP_READ_RESULT_ERROR, "selected send failed");
        rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return RBP_READ_RESULT_ERROR;
    }
    RBP_READ_STEP_ACCUM(step_begin, send_us);
    RBP_READ_STEP_BEGIN(step_begin);
    if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_batch_read_resp_t)) != OG_SUCCESS) {
        cs_disconnect(pipe);
        mgr->selected_temp_connected_node = OG_INVALID_ID32;
        cm_spin_unlock(&mgr->selected_pipe_lock);
        RBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
        rbp_mark_dtc_read_failed(rbp_context, node_id, RBP_READ_RESULT_ERROR, "selected wait response failed");
        rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_ERROR, 0, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return RBP_READ_RESULT_ERROR;
    }
    RBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
    cm_spin_unlock(&mgr->selected_pipe_lock);

    RBP_READ_STEP_BEGIN(step_begin);
    process_result = rbp_process_selected_batch_resp(session, node_id, response, count, &stat, apply_diag_ptr);
    RBP_READ_STEP_ACCUM(step_begin, process_us);
    if (process_result == RBP_READ_RESULT_ERROR) {
        rbp_mark_dtc_read_failed(rbp_context, node_id, process_result, "selected response error");
        rbp_finish_read_batch_stat(session, rbp_proc_id, process_result, stat.returned, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return process_result;
    }
    session->stat->rbp_bg_read += stat.returned;
    session->stat->rbp_bg_read_time += (cm_now() - begin_time) / MICROSECS_PER_MILLISEC;
    rbp_finish_read_batch_stat(session, rbp_proc_id, RBP_READ_RESULT_OK, stat.returned, begin_time,
                               pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
    if (stat.missing > 0) {
        OG_LOG_RUN_WAR("[RBP] selected pull worker batch: worker=%u node=%u requested=%u returned=%u installed=%u "
                       "verified=%u missing=%u elapsed_us=%llu",
                       rbp_proc_id, node_id, stat.requested, stat.returned, stat.installed, stat.verified,
                       stat.missing, (uint64)(cm_now() - begin_time));
    }
    return RBP_READ_RESULT_OK;
}

void rbp_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    uint32 queue_id = ctrl->page_id.page % OG_RBP_SESSION_COUNT;
    rbp_queue_t *queue = &rbp_ctx->queue[queue_id];
    rbp_queue_item_t *item = NULL;
    uint32 queue_count;
    bool32 queue_has_gap;
    uint64 queue_trunc_lfn;
    uint64 lastest_lfn;
    uint64 page_lsn;
    uint64 item_trunc_lfn;
    uint32 page_pcn;
    rbp_queue_item_t *pending_item = NULL;
#ifdef RBP_VERBOSE_TRACE
    uint32 pending_source = 0;
#endif
    uint64 curr_lfn;

    if (!ctrl->rbp_ctrl->is_rbpdirty) {
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[RBP_ENQ_TRACE] skip stale dirty-list entry: queue=%u page=%u-%u sid=%u dtc_type=%u "
                       "ctrl=%p pending=%p lastest_lfn=%llu page_lsn=%llu page_pcn=%u rbp_trunc_lfn=%llu "
                       "is_from_rbp=%u page_status=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, session->id,
                       (uint32)session->dtc_session_type, (void *)ctrl, (void *)ctrl->rbp_ctrl->pending_item,
                       (uint64)ctrl->lastest_lfn, (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn,
                       (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint32)ctrl->rbp_ctrl->is_from_rbp,
                       (uint32)ctrl->rbp_ctrl->page_status);
#endif
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[RBP] skip stale dirty-list entry: queue=%u page=%u-%u",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page);
#endif
        return;
    }

    item = rbp_alloc_queue_item();
    if (item == NULL) {
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
        OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] DROP_PENDING reason=alloc_failed queue=%u page=%u-%u ctrl=%p item=%p "
                        "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                        "gap_end_lfn=%llu page_status=%u",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl,
                        (void *)ctrl->rbp_ctrl->pending_item, (uint64)ctrl->page->lsn,
                        (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                        (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)0,
                        (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint32)ctrl->rbp_ctrl->page_status);
        ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
        ctrl->rbp_ctrl->pending_item = NULL;
        queue->has_gap = OG_TRUE;
        cm_spin_unlock(&queue->lock);
        OG_LOG_RUN_WAR("[RBP] failed to alloc queue item, set gap: queue=%u page=%u-%u lastest_lfn=%llu",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn);
        return;
    }

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    if (ctrl->rbp_ctrl->pending_item != NULL) {
#ifdef RBP_VERBOSE_TRACE
        pending_item = ctrl->rbp_ctrl->pending_item;
        pending_source = (uint32)pending_item->source;
        queue_count = queue->count;
        queue_has_gap = queue->has_gap;
        queue_trunc_lfn = queue->trunc_point.lfn;
        item_trunc_lfn = ctrl->rbp_ctrl->rbp_trunc_point.lfn;
        lastest_lfn = ctrl->lastest_lfn;
        page_lsn = ctrl->page->lsn;
        page_pcn = ctrl->page->pcn;
        curr_lfn = session->kernel->redo_ctx.curr_point.lfn;
#endif
        cm_spin_unlock(&queue->lock);
        rbp_free_queue_item(session, item);
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[RBP_ENQ_TRACE] merge duplicate pending live item: queue=%u page=%u-%u sid=%u dtc_type=%u "
                       "ctrl=%p pending=%p pending_source=%u count=%u queue_trunc_lfn=%llu item_trunc_lfn=%llu "
                       "lastest_lfn=%llu page_lsn=%llu page_pcn=%u has_gap=%u curr_lfn=%llu connected=%u "
                       "dtc_read_active=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, session->id,
                       (uint32)session->dtc_session_type, (void *)ctrl, (void *)pending_item, pending_source,
                       queue_count,
                       (uint64)queue_trunc_lfn, (uint64)item_trunc_lfn, (uint64)lastest_lfn, (uint64)page_lsn,
                       page_pcn, (uint32)queue_has_gap, (uint64)curr_lfn,
                       (uint32)rbp_ctx->rbp_buf_manager[queue_id].is_connected, (uint32)rbp_ctx->dtc_read_active);
#endif
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[RBP] skip duplicate live queue item: queue=%u page=%u-%u lastest_lfn=%llu",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn);
#endif
        return;
    }

    ctrl->rbp_ctrl->rbp_trunc_point = queue->trunc_point;

    item->source = RBP_QUEUE_ITEM_LIVE;
    item->ctrl = ctrl;
    item->page_id = ctrl->page_id;
    item->queue_id = queue_id;
    ctrl->rbp_ctrl->pending_item = item;

    if (queue->first == NULL) {
        queue->first = item;
        queue->last = item;
    } else {
        queue->last->next = item;
        queue->last = item;
    }
    queue->count++;
    queue_count = queue->count;
    queue_has_gap = queue->has_gap;
    queue_trunc_lfn = queue->trunc_point.lfn;
    lastest_lfn = ctrl->lastest_lfn;
    page_lsn = ctrl->page->lsn;
    item_trunc_lfn = ctrl->rbp_ctrl->rbp_trunc_point.lfn;
    page_pcn = ctrl->page->pcn;
    curr_lfn = session->kernel->redo_ctx.curr_point.lfn;
    pending_item = ctrl->rbp_ctrl->pending_item;

    cm_spin_unlock(&queue->lock);

    OG_LOG_DEBUG_INF("[RBP_ENQ_TRACE] enqueue live item: queue=%u page=%u-%u sid=%u dtc_type=%u ctrl=%p item=%p "
                    "pending=%p count=%u queue_trunc_lfn=%llu item_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu "
                    "page_pcn=%u has_gap=%u curr_lfn=%llu connected=%u dtc_read_active=%u",
                    queue_id, ctrl->page_id.file, ctrl->page_id.page, session->id,
                    (uint32)session->dtc_session_type, (void *)ctrl, (void *)item,
                    (void *)pending_item, queue_count, (uint64)queue_trunc_lfn,
                    (uint64)item_trunc_lfn, (uint64)lastest_lfn, (uint64)page_lsn, page_pcn,
                    (uint32)queue_has_gap, (uint64)curr_lfn,
                    (uint32)rbp_ctx->rbp_buf_manager[queue_id].is_connected, (uint32)rbp_ctx->dtc_read_active);

#if RBP_PAGE_WRITE_HOT_DIAG
    if (rbp_queue_backlog_loggable(queue_id, queue_count)) {
        OG_LOG_DEBUG_INF("[RBP] PAGE_WRITE queue backlog on enqueue: queue=%u count=%u page=%u-%u "
                        "queue_trunc_lfn=%llu item_latest_lfn=%llu page_lsn=%llu has_gap=%u connected=%u "
                        "dtc_read_active=%u",
                       queue_id, queue_count, ctrl->page_id.file, ctrl->page_id.page, (uint64)queue_trunc_lfn,
                       (uint64)lastest_lfn, (uint64)page_lsn, (uint32)queue_has_gap,
                       (uint32)rbp_ctx->rbp_buf_manager[queue_id].is_connected, (uint32)rbp_ctx->dtc_read_active);
    }
#endif
}

void rbp_enque_pages(knl_session_t *session)
{
    for (uint32 i = 0; i < session->rbp_dirty_count; i++) {
        rbp_enque_one_page(session, session->rbp_dirty_pages[i]);
    }

    session->rbp_dirty_count = 0;
}

void rbp_queue_set_gap(knl_session_t *session, buf_ctrl_t *ctrl)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    uint32 queue_id = ctrl->page_id.page % OG_RBP_SESSION_COUNT;
    rbp_queue_t *queue = &rbp_ctx->queue[queue_id];
    rbp_queue_item_t *item = NULL;
    bool32 already_gap;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    already_gap = queue->has_gap;
    queue->has_gap = OG_TRUE;
    item = ctrl->rbp_ctrl->pending_item;
    if (item != NULL && item->source == RBP_QUEUE_ITEM_LIVE && item->ctrl == ctrl) {
        item->source = RBP_QUEUE_ITEM_DROPPED;
        item->ctrl = NULL;
    }
#ifdef RBP_VERBOSE_TRACE
    OG_LOG_DEBUG_INF("[RBP_CTRL_TRACE] DROP_PENDING reason=queue_set_gap queue=%u page=%u-%u ctrl=%p item=%p "
                    "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                    "gap_end_lfn=%llu page_status=%u already_gap=%u",
                    queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                    (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                    (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)0,
                    (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint32)ctrl->rbp_ctrl->page_status,
                    (uint32)already_gap);
#endif
    ctrl->rbp_ctrl->pending_item = NULL;
    ctrl->rbp_ctrl->is_rbpdirty = OG_FALSE;
    cm_spin_unlock(&queue->lock);

    if (already_gap) {
        return;
    }

    OG_LOG_RUN_WAR("[RBP] rbp send queue: [%u] set gap by dirty page recycle page=%u-%u "
                   "trunc_lfn=%llu lastest_lfn=%llu queue_pages=%u page_status=%u",
                   queue_id, ctrl->page_id.file, ctrl->page_id.page,
                   (uint64)ctrl->rbp_ctrl->rbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn, queue->count,
                   (uint32)ctrl->rbp_ctrl->page_status);
}

void rbp_queue_set_trunc_point(knl_session_t *session, log_point_t *point)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_queue_t *queue = NULL;

    if (!KNL_RBP_ENABLE(session->kernel)) {
        return;
    }

    /* this is possible during recovery if we set _RBP_DEBUG_MODE=RCYCHK */
    if (!DB_IS_OPEN(session)) {
        if (log_cmp_point(point, &redo_ctx->rbp_rcy_point) < 0) {
            return;
        }
    }

    for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        queue = &rbp_ctx->queue[id];
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
        if (LOG_LFN_LT(queue->trunc_point, *point)) {
            queue->trunc_point = *point;
        }
        cm_spin_unlock(&queue->lock);
    }
}

static void rbp_queue_mark_reset_point(knl_session_t *session, uint32 queue_id, log_point_t *point)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_queue_t *queue = &rbp_ctx->queue[queue_id % OG_RBP_SESSION_COUNT];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
    if (queue->ckpt_reset_point.lfn == 0 || log_cmp_point(&queue->ckpt_reset_point, point) < 0) {
        queue->ckpt_reset_point = *point;
        queue->has_ckpt_reset = OG_TRUE;
    }
    cm_spin_unlock(&queue->lock);
}

static void rbp_queue_notify_reset_point_one(knl_session_t *session, uint32 queue_id, log_point_t *point,
                                            const char *reason, bool32 warn_log)
{
    const char *tag = (reason == NULL) ? "unknown" : reason;

    if (!KNL_RBP_ENABLE(session->kernel) || point == NULL || point->lfn == 0) {
        return;
    }

    rbp_queue_mark_reset_point(session, queue_id, point);

    if (warn_log) {
        OG_LOG_RUN_WAR("[RBP] notify %s reset to RBP queue %u: point=[%u-%u/%u/%llu/%llu]",
                       tag, queue_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn,
                       (uint64)point->lsn);
    } else {
        OG_LOG_RUN_INF("[RBP] notify %s reset to RBP queue %u: point=[%u-%u/%u/%llu/%llu]",
                       tag, queue_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn,
                       (uint64)point->lsn);
    }
}

void rbp_queue_notify_ckpt_point(knl_session_t *session, log_point_t *point)
{
    if (!KNL_RBP_ENABLE(session->kernel) || point == NULL || point->lfn == 0) {
        return;
    }

    (void)session;
    (void)point;
}

uint64 rbp_queue_get_page_count(knl_session_t *session)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_queue_t *queue = NULL;
    uint64 page_count = 0;

    for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        queue = &rbp_ctx->queue[id];
        page_count += queue->count;
    }

    return page_count;
}

log_point_t rbp_queue_get_trunc_point(knl_session_t *session)
{
    rbp_context_t *rbp_ctx = &session->kernel->rbp_context;
    rbp_queue_t *queue = NULL;
    rbp_queue_item_t *item = NULL;
    log_point_t item_trunc_point;
    log_point_t trunc_point = rbp_ctx->queue[0].trunc_point;

    for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
        queue = &rbp_ctx->queue[id];
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_rbp_queue);
        if (queue->count != 0) {
            item = queue->first;
            if (item->source == RBP_QUEUE_ITEM_SNAPSHOT) {
                item_trunc_point = item->snapshot->rbp_trunc_point;
            } else if (item->source == RBP_QUEUE_ITEM_LIVE && item->ctrl != NULL) {
                item_trunc_point = item->ctrl->rbp_ctrl->rbp_trunc_point;
            } else {
                item_trunc_point = queue->trunc_point;
            }
            if (log_cmp_point(&item_trunc_point, &trunc_point) < 0) {
                trunc_point = item_trunc_point;
            }
        }
        cm_spin_unlock(&queue->lock);
    }

    return trunc_point;
}

void rbp_set_unsafe(knl_session_t *session, log_type_t type)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    redo_ctx->rbp_aly_result.rbp_unsafe = OG_TRUE;
    redo_ctx->rbp_aly_result.unsafe_type = type;
}

void rbp_reset_unsafe(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    redo_ctx->rbp_aly_result.rbp_unsafe = OG_FALSE;
    OG_LOG_RUN_INF("[RBP] rbp reset to safe successfully");
}

/*
  * check if rbp can reset from unsafe to safe.
  * if replay beyond the unsafe redo and unsafe is caused by logic or space redo, rbp can reset to safe.
  */
void rbp_unsafe_redo_check(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    uint64 rcy_curr_lsn = session->kernel->sessions[SESSION_ID_KERNEL]->curr_lsn;

    if (!KNL_RBP_ENABLE(session->kernel)) {
        return;
    }

    // in paral recovery, each repaly session has its lsn, redo current lsn is the max lsn
    // paralle recover must be compeleted here
    if (rcy_ctx->paral_rcy) {
        rcy_curr_lsn = 0;
        for (uint32 i = 0; i < rcy_ctx->capacity; i++) {
            rcy_curr_lsn = MAX(rcy_ctx->bucket[i].session->curr_lsn, rcy_curr_lsn);
        }
    }

    /* if rbp unsafe caused by unsafe redo log, can reset rbp status to safe */
    if (redo_ctx->rbp_aly_result.rbp_unsafe && redo_ctx->rbp_aly_result.unsafe_type < RD_TYPE_END) {
        /* if replay beyond the unsafe redo, rbp can reset to safe */
        if (rcy_curr_lsn > redo_ctx->rbp_aly_result.unsafe_max_lsn) {
            OG_LOG_RUN_INF("[RBP] rbp reset to safe because of replay lsn [%llu] beyond max unsafe redo lsn[%llu]",
                            rcy_curr_lsn, redo_ctx->rbp_aly_result.unsafe_max_lsn);
            rbp_reset_unsafe(session);
        }
    }
}

/* check if rbp is safe, retrun true if rbp can be used for failover */
bool32 rbp_pre_check(knl_session_t *session, log_point_t aly_end_point)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t init_point = { 0, 0, 0, 0 };

    OG_LOG_RUN_WAR("[RBP] rbp_pre_check ENTER aly_end asn=%u block=%u lfn=%llu rst_id=%llu rcy_rst_id=%llu "
                   "SAFE=%u rbp_unsafe=%u",
                   aly_end_point.asn, aly_end_point.block_id, (uint64)aly_end_point.lfn, (uint64)aly_end_point.rst_id,
                   (uint64)dtc_my_ctrl(session)->rcy_point.rst_id, (uint32)KNL_RBP_SAFE(session->kernel),
                   (uint32)redo_ctx->rbp_aly_result.rbp_unsafe);

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(&session->kernel->db)) {
        OG_LOG_RUN_WAR("[RBP] rbp is unsafe because database is cascaded standby");
        return OG_FALSE;
    }

    redo_ctx->rbp_begin_point = init_point;
    redo_ctx->rbp_rcy_point = init_point;
    redo_ctx->rbp_lrp_point = init_point;

    rbp_unsafe_redo_check(session);
    if (!KNL_RBP_SAFE(session->kernel)) {
        OG_LOG_RUN_WAR("[RBP] rbp is unsafe");
        return OG_FALSE;
    }

    if (aly_end_point.rst_id != dtc_my_ctrl(session)->rcy_point.rst_id) {
        rbp_set_unsafe(session, RD_TYPE_END);
        OG_LOG_RUN_WAR("[RBP] rbp unsafe because of redo end_point rst_id[%u] is not equal to rcy_point rst_id[%u]",
                        aly_end_point.rst_id, dtc_my_ctrl(session)->rcy_point.rst_id);
        return OG_FALSE;
    }

    OG_LOG_RUN_INF("[RBP] rbp is safe");
    return OG_TRUE;
}

/* kernel read RBP checkpoints */
status_t rbp_knl_query_rbp_point(knl_session_t *session, rbp_read_ckpt_resp_t *response, bool32 check_end_point)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    rbp_read_ckpt_req_t request;
    rbp_buf_manager_t *manager = &rbp_context->rbp_buf_manager[0];
    cs_pipe_t *pipe = rbp_get_client_pipe(rbp_context, 0, OG_FALSE);

    cm_spin_lock(&manager->fisrt_pipe_lock, NULL); // concurrency with heart beat
    if (!manager->is_connected) {
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return OG_ERROR;
    }

    RBP_SET_MSG_HEADER(&request, RBP_REQ_READ_CKPT, sizeof(rbp_read_ckpt_req_t), cs_get_socket_fd(pipe));
    request.check_end_point = check_end_point;
    request.aly_end_point = redo_ctx->redo_end_point;

    if (rbp_knl_send_request_timeout(pipe, (char *)&request, manager, RBP_MAX_READ_WAIT_TIME) != OG_SUCCESS) {
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return OG_ERROR;
    }

    if (rbp_knl_wait_response(pipe, (char *)response, sizeof(rbp_read_ckpt_resp_t)) != OG_SUCCESS) {
        cs_disconnect(pipe);
        manager->is_connected = OG_FALSE;
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return OG_ERROR;
    }

    cm_spin_unlock(&manager->fisrt_pipe_lock);

    if (response->rbp_unsafe) {
        rbp_context->rbp_window_start = 0;
        rbp_context->rbp_window_end = 0;
    } else {
        rbp_context->rbp_window_start = response->begin_point.lfn;
        rbp_context->rbp_window_end = response->rcy_point.lfn;
    }

    return OG_SUCCESS;
}

/* kernel notify RBP check redo end point */
void rbp_knl_check_end_point(knl_session_t *session)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    rbp_read_ckpt_resp_t response;

    if (rbp_knl_query_rbp_point(session, &response, OG_TRUE) != OG_SUCCESS) {
        rbp_set_unsafe(session, RD_TYPE_END);
        OG_LOG_RUN_WAR("[RBP] rbp unsafe because failed to query rbp point");
        return;
    }

    rbp_process_read_ckpt_resp(session, &response, redo_ctx);
}

static void rbp_refresh_rbp_window(knl_session_t *session, uint32 rbp_proc_id)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_read_ckpt_resp_t response;

    if (rbp_proc_id != 0) {
        return;
    }

    if (rbp_knl_query_rbp_point(session, &response, OG_FALSE) != OG_SUCCESS) {
        rbp_context->rbp_window_start = 0;
        rbp_context->rbp_window_end = 0;
    }
}

/* kernel try read one page from RBP */
rbp_page_status_e knl_read_page_from_rbp(knl_session_t *session, buf_ctrl_t *ctrl)
{
    rbp_page_status_e page_status;
    datafile_t *df = DATAFILE_GET(session, ctrl->page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    bool32 partial_read = rbp_is_dtc_partial_read(session);
    rbp_partial_item_t *partial_item = NULL;
    rbp_analyse_item_t *aly_item = NULL;
    uint64 expect_lsn = 0;
    uint64 expect_lfn = 0;
#ifdef RBP_VERBOSE_TRACE
    uint32 rbp_proc_id = ctrl->page_id.page % OG_RBP_SESSION_COUNT;
    uint64 disk_lsn = PAGE_GET_LSN(ctrl->page);
    uint32 disk_pcn = ctrl->page->pcn;
    uint32 read_node = session->kernel->rbp_context.rbp_buf_manager[rbp_proc_id].temp_connected_node;
#endif
    uint32 verify_node_id = OG_INVALID_ID32;
    bool32 in_jumped_window = OG_FALSE;

    /* no redo log for the page, page would not exists on RBP */
    if (partial_read) {
        partial_item = dtc_rcy_rbp_partial_get_item(ctrl->page_id);
        expect_lsn = dtc_rcy_rbp_partial_get_expect_lsn(partial_item);
        expect_lfn = (partial_item == NULL) ? 0 : partial_item->expect_lfn;
        if (partial_item == NULL || partial_item->rcy_item == NULL ||
            !partial_item->rcy_item->need_replay || expect_lsn == 0) {
            rbp_record_read_skip_partial_no_expect(&session->kernel->rbp_context, partial_item);
            RBP_BUF_TRACE_LOG("[RBP_BUF_TRACE] knl_read_page_from_rbp MISS partial_no_expect page %u-%u "
                            "has_item=%u required=%u has_rcy_item=%u need_replay=%u expect_lsn=%llu "
                            "expect_lfn=%llu enter_upper_lsn=%llu",
                            ctrl->page_id.file, ctrl->page_id.page, (uint32)(partial_item != NULL),
                            (uint32)(partial_item != NULL && partial_item->required),
                            (uint32)(partial_item != NULL && partial_item->rcy_item != NULL),
                            (uint32)(partial_item != NULL && partial_item->rcy_item != NULL &&
                                      partial_item->rcy_item->need_replay),
                            (uint64)expect_lsn,
                            (uint64)(partial_item == NULL ? 0 : partial_item->expect_lfn),
                            (uint64)(partial_item == NULL || partial_item->rcy_item == NULL ? 0 :
                                      partial_item->rcy_item->last_dirty_lsn));
            return RBP_PAGE_MISS;
        }
        in_jumped_window = dtc_rcy_rbp_partial_item_in_jumped_window(session, partial_item, &verify_node_id);
        if (session->kernel->rbp_context.dtc_use_selected_batch && !in_jumped_window) {
            rbp_record_read_skip_partial_selected_scope(&session->kernel->rbp_context, partial_item, ctrl);
            return RBP_PAGE_MISS;
        }
    } else {
        expect_lsn = rbp_aly_get_page_lsn(session, ctrl->page_id);
        if (expect_lsn == OG_INVALID_LSN) {
            rbp_record_read_skip_no_expect_lsn(&session->kernel->rbp_context);
            RBP_BUF_TRACE_LOG("[RBP_BUF_TRACE] knl_read_page_from_rbp MISS no_expect_lsn page %u-%u",
                            ctrl->page_id.file, ctrl->page_id.page);
            return RBP_PAGE_MISS;
        }
        aly_item = rbp_aly_get_page_item(session, ctrl->page_id);
        if (aly_item != NULL) {
            expect_lsn = rbp_get_item_expect_lsn(session, aly_item);
            expect_lfn = aly_item->lfn;
        }
    }
#ifndef RBP_VERBOSE_TRACE
    (void)expect_lfn;
#endif
    if (SPACE_IS_NOLOGGING(space)) {
        rbp_record_read_skip_nolog_space(&session->kernel->rbp_context);
        RBP_BUF_TRACE_LOG("[RBP_BUF_TRACE] knl_read_page_from_rbp MISS nolog_space page %u-%u", ctrl->page_id.file,
                          ctrl->page_id.page);
        return RBP_PAGE_MISS;
    }

    session->stat->rbp_knl_read++;
    page_status = rbp_knl_pull_one_page(session, ctrl);
    if (page_status == RBP_PAGE_ERROR) {
        rbp_context_t *rbp_context = &session->kernel->rbp_context;

        if (rbp_context->dtc_read_active || rbp_context->dtc_read_node_count > 0 ||
            rbp_dtc_read_failed(rbp_context)) {
            rbp_mark_dtc_read_failed(rbp_context, OG_INVALID_ID32, RBP_READ_RESULT_ERROR,
                                    "on-demand read failed");
            if (rbp_dtc_has_jump_taken(session)) {
                rbp_knl_mark_dtc_fallback(session, OG_INVALID_ID32, RBP_READ_RESULT_ERROR,
                                          RBP_DTC_FALLBACK_PAGE_READ);
            }
            return page_status;
        }
        CM_ABORT(0, "[RBP] ABORT INFO: instance must exit beacause of failed to read page from RBP");
    }

    if (page_status == RBP_PAGE_MISS) {
#ifdef RBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[RBP_READ_TRACE] READ_RESULT page=%u-%u status=%u partial=%u expect_lsn=%llu "
                       "expect_lfn=%llu disk_lsn=%llu disk_pcn=%u returned_lsn=%llu returned_pcn=%u "
                       "read_node=%u is_from_rbp=%u page_status=%u required=%u selected_valid=%u "
                       "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                       "load_status=%u",
                       ctrl->page_id.file, ctrl->page_id.page, (uint32)page_status, (uint32)partial_read,
                       (uint64)expect_lsn, (uint64)expect_lfn, (uint64)disk_lsn, disk_pcn,
                       (uint64)PAGE_GET_LSN(ctrl->page), (uint32)ctrl->page->pcn, read_node,
                       (uint32)ctrl->rbp_ctrl->is_from_rbp, (uint32)ctrl->rbp_ctrl->page_status,
                       (uint32)(partial_read && partial_item != NULL && partial_item->required),
                       (uint32)(partial_read && partial_item != NULL && partial_item->selected_valid),
                       (uint32)(partial_read && partial_item != NULL && partial_item->selected_pulled),
                       (uint32)(partial_read && partial_item != NULL && partial_item->verified),
                       (uint32)in_jumped_window, verify_node_id,
                       (uint32)(partial_read && partial_item != NULL ? partial_item->selected_node :
                           OG_INVALID_ID32),
                       (uint32)ctrl->load_status);
#endif
        OG_LOG_DEBUG_INF("[RBP] kernel read page from RBP: page: %u-%u not found on RBP",
                        ctrl->page_id.file, ctrl->page_id.page);
        session->stat->rbp_miss++;
        return RBP_PAGE_MISS;
    }

#ifdef RBP_VERBOSE_TRACE
    OG_LOG_DEBUG_INF("[RBP_READ_TRACE] READ_RESULT page=%u-%u status=%u partial=%u expect_lsn=%llu "
                   "expect_lfn=%llu disk_lsn=%llu disk_pcn=%u returned_lsn=%llu returned_pcn=%u "
                   "read_node=%u is_from_rbp=%u page_status=%u required=%u selected_valid=%u "
                   "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                   "load_status=%u",
                   ctrl->page_id.file, ctrl->page_id.page, (uint32)page_status, (uint32)partial_read,
                   (uint64)expect_lsn, (uint64)expect_lfn, (uint64)disk_lsn, disk_pcn,
                   (uint64)PAGE_GET_LSN(ctrl->page), (uint32)ctrl->page->pcn, read_node,
                   (uint32)ctrl->rbp_ctrl->is_from_rbp, (uint32)ctrl->rbp_ctrl->page_status,
                   (uint32)(partial_read && partial_item != NULL && partial_item->required),
                   (uint32)(partial_read && partial_item != NULL && partial_item->selected_valid),
                   (uint32)(partial_read && partial_item != NULL && partial_item->selected_pulled),
                   (uint32)(partial_read && partial_item != NULL && partial_item->verified),
                   (uint32)in_jumped_window, verify_node_id,
                   (uint32)(partial_read && partial_item != NULL ? partial_item->selected_node : OG_INVALID_ID32),
                   (uint32)ctrl->load_status);
#endif
    RBP_BUF_TRACE_LOG("[RBP_BUF_TRACE] knl_read_page_from_rbp done page %u-%u status=%u page_lsn=%llu page_pcn=%u "
                      "is_from_rbp=%u",
                      ctrl->page_id.file, ctrl->page_id.page, (uint32)page_status, (uint64)ctrl->page->lsn,
                      (uint32)ctrl->page->pcn, (uint32)ctrl->rbp_ctrl->is_from_rbp);
    return page_status;
}

/*
* Multi-node recovery has already rewritten per-node rcy_point_saved[] during prepare,
* so begin_dtc_read only starts RBP background pulling and flips the shared recovery state.
* There is intentionally no single curr_point = rbp_rcy_point jump here.
*/
status_t rbp_knl_begin_dtc_read(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    date_t begin_time = cm_now();
    date_t stage_begin = cm_now();
    uint64 save_epoch_us;
    uint64 notify_begin_us;
    uint64 build_required_us;
    uint64 meta_us = 0;
    uint64 selected_pull_us = 0;
    bool32 use_selected_batch = OG_FALSE;
    bool32 need_selected_meta = OG_FALSE;
    bool32 sync_selected_pull_at_begin = OG_FALSE;

    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !OGRAC_PART_RECOVERY(session)) {
        OG_LOG_RUN_INF("[RBP] skip DTC RBP read: only partial recovery uses RBP acceleration");
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[RBP] begin multi-node RBP read start: current_version=%u rcy_with_rbp=%u",
                    rbp_context->rbp_read_version, (uint32)redo->rcy_with_rbp);
    rbp_knl_clear_dtc_fallback(session);
    if (rbp_save_dtc_read_epoch(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RBP] DTC RBP read epoch is empty, keep redo recovery");
        return OG_ERROR;
    }
    save_epoch_us = (uint64)(cm_now() - stage_begin);
    rbp_reset_read_stat(rbp_context);
    stage_begin = cm_now();
    if (rbp_notify_dtc_read_begin_planned(session) != OG_SUCCESS) {
        rbp_clear_dtc_read_epoch(rbp_context);
        rbp_stop_temp_connection(session, rbp_context);
        OG_LOG_RUN_WAR("[RBP] can not notify any DTC RBP READ_BEGIN node, keep redo recovery");
        return OG_ERROR;
    }
    notify_begin_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();
    if (rbp_build_dtc_planned_required_items(session) != OG_SUCCESS) {
        (void)rbp_notify_dtc_read_phase(session, MSG_RBP_READ_END);
        rbp_disable_dtc_planned_nodes(session);
        rbp_clear_dtc_read_epoch(rbp_context);
        rbp_stop_temp_connection(session, rbp_context);
        OG_LOG_RUN_WAR("[RBP] failed to build DTC planned required item cache, keep redo recovery");
        return OG_ERROR;
    }
    build_required_us = (uint64)(cm_now() - stage_begin);
    rbp_choose_dtc_selected_mode(session, &use_selected_batch, &need_selected_meta, &sync_selected_pull_at_begin);
    for (uint32 id = 0; id < OG_MAX_INSTANCES; id++) {
        rbp_context->dtc_selected_cursor[id] = 0;
    }
    if (need_selected_meta) {
        stage_begin = cm_now();
        if (rbp_pull_selected_metadata(session) != OG_SUCCESS) {
            (void)rbp_notify_dtc_read_phase(session, MSG_RBP_READ_END);
            rbp_disable_dtc_planned_nodes(session);
            rbp_clear_dtc_read_epoch(rbp_context);
            rbp_stop_temp_connection(session, rbp_context);
            OG_LOG_RUN_WAR("[RBP] failed to pull selected metadata, keep redo recovery");
            return OG_ERROR;
        }
        meta_us = (uint64)(cm_now() - stage_begin);
    } else if (use_selected_batch) {
        stage_begin = cm_now();
        if (rbp_prepare_single_node_direct_selected(session) != OG_SUCCESS) {
            (void)rbp_notify_dtc_read_phase(session, MSG_RBP_READ_END);
            rbp_disable_dtc_planned_nodes(session);
            rbp_clear_dtc_read_epoch(rbp_context);
            rbp_stop_temp_connection(session, rbp_context);
            OG_LOG_RUN_WAR("[RBP] failed to prepare direct selected pages, keep redo recovery");
            return OG_ERROR;
        }
        meta_us = (uint64)(cm_now() - stage_begin);
    }

    rbp_context->rbp_read_completed = OG_FALSE;
    rbp_context->dtc_read_workers_done = OG_FALSE;
    rbp_context->rbp_read_thread_num = OG_RBP_SESSION_COUNT;
    rbp_context->rbp_read_version++;
    rbp_context->rbp_begin_read_time = cm_now();
    rbp_context->dtc_use_selected_batch = use_selected_batch;
    rbp_context->dtc_need_selected_meta = need_selected_meta;
    rbp_context->dtc_sync_selected_pull_at_begin = sync_selected_pull_at_begin;
    if (!use_selected_batch) {
        for (uint32 id = 0; id < OG_RBP_SESSION_COUNT; id++) {
            rbp_context->dtc_selected_worker_nodes[id] = OG_INVALID_ID32;
        }
    }

    redo->last_rcy_with_rbp = OG_TRUE;
    redo->rcy_with_rbp = OG_TRUE;
    CM_MFENCE;

    for (uint32 id = 0; id < rbp_context->rbp_read_thread_num; id++) {
        rbp_context->rbp_buf_manager[id].rbp_reading = OG_TRUE;
    }

    if (sync_selected_pull_at_begin) {
        stage_begin = cm_now();
        while (rbp_context->rbp_read_thread_num > 0) {
            cm_sleep(1);
        }
        rbp_context->dtc_read_workers_done = OG_TRUE;
        rbp_context->rbp_read_workers_done_time = cm_now();
        selected_pull_us = (uint64)(cm_now() - stage_begin);
    }

    OG_LOG_RUN_INF("[RBP] begin multi-node RBP read, read_version=%u, save_epoch_us=%llu notify_begin_us=%llu "
                   "build_required_us=%llu use_selected_batch=%u need_selected_meta=%u sync_begin=%u "
                   "meta_us=%llu selected_pull_us=%llu required_items=%u total_begin_us=%llu skipped_lfn_total=%llu",
                   rbp_context->rbp_read_version, save_epoch_us, notify_begin_us, build_required_us,
                   (uint32)use_selected_batch, (uint32)need_selected_meta, (uint32)sync_selected_pull_at_begin,
                   meta_us, selected_pull_us,
                   rbp_context->dtc_planned_required_count,
                   (uint64)(cm_now() - begin_time), rbp_dtc_read_skip_lfn_total(rbp_context));
    return OG_SUCCESS;
}

static void rbp_verify_skiped_redo_pages(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    rbp_analyse_item_t *aly_items = ctx->rbp_aly_items;
    uint64 skip_start = ctx->rbp_skip_point.lfn;
    uint64 skip_end = ctx->rbp_rcy_point.lfn;
    uint32 in_window = 0;
    uint32 miss_cnt = 0;
    uint32 sample = 0;
    bool32 dtc_read = rbp_is_multi_node_rcy(session);
    bool32 partial_read = rbp_is_dtc_partial_read(session);
    uint32 node_ids[OG_MAX_INSTANCES];
    uint32 node_count = dtc_read ? rbp_collect_verify_rcy_nodes(session, node_ids, OG_MAX_INSTANCES) : 0;
    uint64 skipped_lfn_total = dtc_read ? rbp_dtc_read_skip_lfn_total(&session->kernel->rbp_context) :
        (skip_end > skip_start ? (skip_end - skip_start) : 0);
    bool32 use_required_cache = (bool32)(dtc_read && rbp_context->dtc_planned_required_built);
    uint32 scan_count = use_required_cache ? rbp_context->dtc_planned_required_count : (uint32)RBP_ALY_MAX_ITEM;

    if (dtc_read && partial_read) {
        rbp_verify_partial_skiped_redo_pages(session, node_count, skipped_lfn_total);
        return;
    }
    if (aly_items == NULL) {
        OG_LOG_RUN_WAR("[RBP] verify summary: skip because analysis items are NULL");
        return;
    }
    if (dtc_read && node_count == 0) {
        OG_LOG_RUN_INF("[RBP] verify summary: no jumped RBP nodes, skip final verification, "
                       "required_cache_built=%u required_cache_items=%u",
                       (uint32)rbp_context->dtc_planned_required_built,
                       rbp_context->dtc_planned_required_count);
        return;
    }
    for (uint32 i = 0; i < scan_count; i++) {
        rbp_analyse_item_t *aly_item = use_required_cache ? rbp_context->dtc_planned_required_items[i] : &aly_items[i];
        bool32 need_verify = OG_FALSE;
        bool32 verified = OG_FALSE;
        bool32 already_verified = OG_FALSE;
        uint32 verify_node_id;
        uint64 expect_lsn;
        uint64 local_lsn = 0;

        if (aly_item == NULL || (aly_item->lfn == 0 && aly_item->first_lfn == 0)) {
            continue;
        }

        verify_node_id = aly_item->node_id;
        expect_lsn = rbp_get_item_expect_lsn(session, aly_item);
        if (dtc_read) {
            /*
            * In v6 each node may skip a different prefix. Check every jumped node, because the latest
            * touch can belong to tail redo while the first touch is still inside another node's skipped prefix.
            */
            for (uint32 j = 0; j < node_count; j++) {
                uint32 node_id = node_ids[j];
                log_point_t *node_skip = NULL;
                log_point_t *node_rcy = NULL;
                if (!rbp_get_dtc_verify_points(session, node_id, &node_skip, &node_rcy)) {
                    continue;
                }
                if (rbp_aly_item_in_node_skip(aly_item, node_id, node_skip, node_rcy)) {
                    need_verify = OG_TRUE;
                    verify_node_id = node_id;
                    break;
                }
            }
        } else if (rbp_aly_item_in_global_skip(aly_item, skip_start, skip_end)) {
            need_verify = OG_TRUE;
        }

        if (!need_verify) {
            continue;
        }

        if (dtc_read && partial_read && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress &&
            !dtc_rcy_rbp_partial_item_need_verify(session, aly_item->page_id, verify_node_id,
                                                  aly_item->lfn, expect_lsn)) {
            continue;
        }

        in_window++;
        already_verified = (bool32)(!dtc_read && aly_item->is_verified > 0);
        verified = already_verified;
        if (!verified) {
            local_lsn = rbp_get_local_verify_lsn(session, aly_item->page_id);
            verified = (bool32)(aly_item->best_lsn >= expect_lsn || local_lsn >= expect_lsn);
            if (verified) {
                aly_item->is_verified = OG_TRUE;
            }
        }
        if (verified && dtc_read && partial_read && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress) {
            dtc_rcy_rbp_partial_mark_verified(session, aly_item->page_id, verify_node_id, aly_item->lsn);
        }
        if (!verified) {
            miss_cnt++;
            if (sample < RBP_PARTIAL_VERIFY_SAMPLE_LIMIT) {
                OG_LOG_RUN_WAR("[RBP] verify miss sample[%u]: page %u-%u node=%u lfn=%llu first_node=%u "
                               "first_lfn=%llu verified=%u best_lsn=%llu expect_lsn=%llu best_source_node=%u "
                               "seen_bitmap=0x%llx local_lsn=%llu touch0=%u:%llu-%llu touch1=%u:%llu-%llu",
                               sample, aly_item->page_id.file, aly_item->page_id.page,
                               verify_node_id, (uint64)aly_item->lfn, (uint32)aly_item->first_node_id,
                               (uint64)aly_item->first_lfn, (uint32)aly_item->is_verified,
                               (uint64)aly_item->best_lsn, (uint64)expect_lsn,
                               (uint32)aly_item->best_source_node, (uint64)aly_item->seen_node_bitmap,
                               (uint64)local_lsn,
                               (uint32)RBP_ALY_TOUCH_NODE(aly_item->touch_min[0]),
                               (uint64)RBP_ALY_TOUCH_LFN(aly_item->touch_min[0]),
                               (uint64)RBP_ALY_TOUCH_LFN(aly_item->touch_max[0]),
                               (uint32)RBP_ALY_TOUCH_NODE(aly_item->touch_min[1]),
                               (uint64)RBP_ALY_TOUCH_LFN(aly_item->touch_min[1]),
                               (uint64)RBP_ALY_TOUCH_LFN(aly_item->touch_max[1]));
                sample++;
            }
        }
        knl_panic_log(verified, "[RBP] page %u-%u is not pulled, instance must exit",
                       aly_item->page_id.file, aly_item->page_id.page);
    }
    OG_LOG_RUN_INF("[RBP] verify summary: skip_window=[%llu,%llu) skipped_lfn_total=%llu "
                   "items=%u miss=%u required_cache_built=%u required_cache_items=%u scanned=%u",
                   (uint64)skip_start, (uint64)skip_end, skipped_lfn_total, in_window, miss_cnt,
                   (uint32)rbp_context->dtc_planned_required_built,
                   rbp_context->dtc_planned_required_count, scan_count);
}

/*
  * after pull all RBP pages to local buffer or db start, kernel notify RBP server to stop send page.
  * then close all temp connections with RBP
  */
static void rbp_knl_end_read_internal(knl_session_t *session, bool32 verify_pages, const char *reason)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint32 rbp_proc_id = session->rbp_queue_index - 1;
    int32 lock_id;
    date_t stage_begin;
    uint64 worker_wall_ms;
    uint64 worker_active_ms;
    uint64 owner_gap_ms;
    uint64 total_us;
    uint64 lock_us;
    uint64 notify_end_us;
    uint64 verify_us;
    uint64 cleanup_us;
    date_t workers_done_time;
    bool32 read_failed;
    bool32 read_failed_after_jump;
    uint32 failed_node;
    uint32 failed_result;

    rbp_context->rbp_read_completed = OG_TRUE;
    rbp_context->rbp_end_read_time = cm_now();
    worker_wall_ms = (uint64)((rbp_context->rbp_end_read_time - rbp_context->rbp_begin_read_time) /
                              MICROSECS_PER_MILLISEC);
    workers_done_time = rbp_context->rbp_read_workers_done_time;
    if (workers_done_time == 0 || workers_done_time > rbp_context->rbp_end_read_time) {
        workers_done_time = rbp_context->rbp_end_read_time;
    }
    worker_active_ms = (uint64)((workers_done_time - rbp_context->rbp_begin_read_time) / MICROSECS_PER_MILLISEC);
    owner_gap_ms = (uint64)((rbp_context->rbp_end_read_time - workers_done_time) / MICROSECS_PER_MILLISEC);

    stage_begin = cm_now();
    for (lock_id = 0; lock_id < OG_RBP_RD_LOCK_COUNT; lock_id++) {
        cm_spin_lock(&rbp_context->buf_read_lock[lock_id], NULL); // lock 8 rbp read locks
    }
    lock_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();
    read_failed = rbp_dtc_read_failed(rbp_context);
    read_failed_after_jump = (bool32)(read_failed && rbp_dtc_has_jump_taken(session));
    failed_node = rbp_context->dtc_read_failed_node;
    failed_result = rbp_context->dtc_read_failed_result;

    /*
    * READ_END follows READ_BEGIN/PAGE_READ/BATCH_READ on pipe_temp. Hold buf_read_lock[] first, then fisrt_pipe_lock
    * Use the same order as buf_load_page_from_RBP (buf_read then pull_one_page) to avoid deadlock.
    */
    if (rbp_is_multi_node_rcy(session)) {
        if (rbp_notify_dtc_read_phase(session, MSG_RBP_READ_END) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[RBP] failed to notify DTC RBP read page end");
        }
    } else {
        rbp_buf_manager_t *mgr = &rbp_context->rbp_buf_manager[rbp_proc_id];
        cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
        if (rbp_notify_msg(session, MSG_RBP_READ_END, rbp_proc_id, NULL) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[RBP] failed to notify RBP read page end");
        }
        cm_spin_unlock(&mgr->fisrt_pipe_lock);
    }
    notify_end_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();

    /* concurrency with buf_load_page_from_RBP */
    redo->rcy_with_rbp = OG_FALSE;

    if (verify_pages && !read_failed) {
        rbp_verify_skiped_redo_pages(session);
    } else {
        OG_LOG_RUN_WAR("[RBP] skip final verify during read phase cleanup: reason=%s read_failed=%u",
                       (reason == NULL) ? "unknown" : reason, (uint32)read_failed);
    }
    verify_us = (uint64)(cm_now() - stage_begin);

    for (lock_id = OG_RBP_RD_LOCK_COUNT - 1; lock_id >= 0; lock_id--) {
        cm_spin_unlock(&rbp_context->buf_read_lock[lock_id]); // unlock 8 rbp read locks
    }

    /* when read from RBP end, stop temp connections */
    stage_begin = cm_now();
    rbp_stop_temp_connection(session, rbp_context);
    rbp_clear_dtc_read_epoch(rbp_context);
    cleanup_us = (uint64)(cm_now() - stage_begin);
    total_us = (uint64)(cm_now() - rbp_context->rbp_begin_read_time);
    rbp_log_read_skip_summary(rbp_context);
    rbp_log_read_diag_summary(rbp_context);
    rbp_log_read_anomaly_summary(rbp_context);
    OG_LOG_RUN_INF("[RBP] read phase summary: pages=%llu errors=%llu worker_active_ms=%llu owner_gap_ms=%llu "
                   "skipped_lfn_total=%llu lock_us=%llu verify_us=%llu verify_pages=%u read_end_notify_us=%llu "
                   "cleanup_us=%llu total_us=%llu reason=%s",
                   (uint64)cm_atomic_get(&rbp_context->rbp_read_pages),
                   (uint64)cm_atomic_get(&rbp_context->rbp_read_errors),
                   worker_active_ms, owner_gap_ms, rbp_dtc_read_skip_lfn_total(rbp_context),
                   lock_us, verify_us, (uint32)verify_pages, notify_end_us, cleanup_us, total_us,
                   (reason == NULL) ? "finish" : reason);
    (void)worker_wall_ms;

    if (read_failed_after_jump) {
        rbp_knl_mark_dtc_fallback(session, failed_node, failed_result, RBP_DTC_FALLBACK_READ_FAILED);
        OG_LOG_RUN_ERR("[RBP] DTC RBP read/apply failed after jump, READ_END sent and fallback to redo requested: "
                       "node=%u result=%u",
                       failed_node, failed_result);
    }
}

void rbp_knl_end_read(knl_session_t *session)
{
    rbp_knl_end_read_internal(session, OG_TRUE, "finish");
}

static void rbp_knl_finish_dtc_read_internal(knl_session_t *session, bool32 verify_pages, const char *reason)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    date_t begin_time;
    uint64 wait_us;

    if (!rbp_context->dtc_read_active && rbp_context->dtc_read_node_count == 0) {
        return;
    }

    begin_time = cm_now();
    while (rbp_context->rbp_read_thread_num > 0) {
        cm_sleep(1);
    }
    wait_us = (uint64)(cm_now() - begin_time);
    rbp_context->dtc_read_workers_done = OG_TRUE;
    if (rbp_context->rbp_read_workers_done_time == 0) {
        rbp_context->rbp_read_workers_done_time = cm_now();
    }
    OG_LOG_RUN_INF("[RBP] DTC recovery owner finishes read phase: wait_workers_us=%llu reason=%s",
                   wait_us, (reason == NULL) ? "finish" : reason);
    rbp_knl_end_read_internal(session, verify_pages, reason);
}

void rbp_knl_finish_dtc_read(knl_session_t *session)
{
    rbp_knl_finish_dtc_read_internal(session, OG_TRUE, "finish");
}

void rbp_knl_abort_dtc_read(knl_session_t *session)
{
    rbp_knl_finish_dtc_read_internal(session, OG_FALSE, "abort");
}

/*
  * init rbp process when db start
  * 1. start rbp background workers, which process dirty pages between kernel and RBP
  * 2. start rbp_agent_proc, which maintains the connections with RBP
  */
status_t rbp_agent_start(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;
    uint32 buf_size = MAX(RBP_MAX_REQ_BUF_SIZE, RBP_MAX_RESP_BUF_SIZE) * OG_RBP_SESSION_COUNT;
    errno_t ret;

    ret = memset_sp(rbp_context, sizeof(rbp_context_t), 0, sizeof(rbp_context_t));
    knl_securec_check(ret);

    rbp_context->rbp_read_completed = OG_TRUE;

    if (cm_aligned_malloc((int64)buf_size, "rbp pipe buffer", &rbp_context->pipe_buf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (rbp_snapshot_pool_init(session) != OG_SUCCESS) {
        cm_aligned_free(&rbp_context->pipe_buf);
        return OG_ERROR;
    }

    if (rbp_aly_mem_init(session) != OG_SUCCESS) { // redo analysis memory, free when rbp_agent_proc quit
        rbp_snapshot_pool_free(session);
        cm_aligned_free(&rbp_context->pipe_buf);
        return OG_ERROR;
    }

    if (rbp_agent_start_client(session) != OG_SUCCESS) {
        rbp_agent_stop_client(session); // release rbp_bg_procs which have been created
        rbp_drain_send_queues(session);
        rbp_snapshot_pool_free(session);
        cm_aligned_free(&rbp_context->pipe_buf);
        rbp_aly_mem_free(session);
        return OG_ERROR;
    }

    if (cm_create_thread(rbp_agent_proc, 0, session, &rbp_context->rbp_agent_thread) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[RBP] rbp agent thread create failed");
        rbp_agent_stop_client(session);
        rbp_drain_send_queues(session);
        rbp_snapshot_pool_free(session);
        cm_aligned_free(&rbp_context->pipe_buf);
        rbp_aly_mem_free(session);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void rbp_agent_close(knl_session_t *session)
{
    rbp_context_t *rbp_context = &session->kernel->rbp_context;

    cm_close_thread(&rbp_context->rbp_agent_thread);
}

/* ------------------------ Log analysis fuctions  ------------------------------- */
status_t rbp_aly_mem_init(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_analyse_bucket_t *free_list = &ctx->rbp_aly_free_list;
    int64 buf_size = RBP_ALY_MAX_ITEM_SIZE + RBP_ALY_MAX_BUCKET_SIZE; // 176M
    errno_t ret;

    if (!KNL_RBP_ENABLE(session->kernel)) {
        OG_LOG_RUN_INF("[RBP] rbp is off, log analysis memory will not malloc");
        return OG_SUCCESS;
    }

    if (ctx->rbp_aly_items == NULL) { // fisrt alloc memory at db_mount, free memory at db_close
        if (cm_aligned_malloc(buf_size, "log analysis", &ctx->rbp_aly_mem) != OG_SUCCESS) {
            return OG_ERROR;
        }
        ctx->rbp_aly_items = (rbp_analyse_item_t *)ctx->rbp_aly_mem.aligned_buf;
        ctx->rbp_aly_buckets = (rbp_analyse_bucket_t *)(ctx->rbp_aly_mem.aligned_buf + RBP_ALY_MAX_ITEM_SIZE);
    }

    ret = memset_sp(ctx->rbp_aly_items, RBP_ALY_MAX_ITEM_SIZE, 0, RBP_ALY_MAX_ITEM_SIZE); // 160M
    knl_securec_check(ret);
    ret = memset_sp(ctx->rbp_aly_buckets, RBP_ALY_MAX_BUCKET_SIZE, 0, RBP_ALY_MAX_BUCKET_SIZE); // 16M
    knl_securec_check(ret);

    free_list->count = RBP_ALY_MAX_ITEM;
    free_list->first = &ctx->rbp_aly_items[0];
    for (uint32 i = 0; i < RBP_ALY_MAX_ITEM - 1; i++) {
        ctx->rbp_aly_items[i].next = &ctx->rbp_aly_items[i + 1]; // init free list
    }

    return OG_SUCCESS;
}

/* free memory at db_close or alter system set USE_RBP = FALSE */
void rbp_aly_mem_free(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_aly_ctx_t *aly = &session->kernel->rbp_aly_ctx;

    while (aly->is_started && !aly->is_done) {
        cm_sleep(1); // wait rbp_aly_proc exit
    }

    aly->is_started = OG_FALSE;
    rbp_clear_dtc_planned_required_items(&session->kernel->rbp_context);
    cm_aligned_free(&ctx->rbp_aly_mem);
    ctx->rbp_aly_items = NULL;
    ctx->rbp_aly_buckets = NULL;
}

static rbp_analyse_item_t *rbp_aly_pop_free_item(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_analyse_bucket_t *free_list = &ctx->rbp_aly_free_list;
    rbp_analyse_item_t *item = NULL;

    if (free_list->first == NULL) {
        return NULL;
    }

    item = free_list->first;
    free_list->first = item->next;
    free_list->count--;
    item->next = NULL;

    return item;
}

/* if item.lfn < rcy_point.lfn, this item can be recycled, because this item page has been flush to disk */
static void rbp_aly_recycle_old_item(knl_session_t *session, rbp_analyse_bucket_t *bucket)
{
    rbp_analyse_bucket_t *free_list = &session->kernel->redo_ctx.rbp_aly_free_list;
    rbp_analyse_item_t *item = NULL;
    rbp_analyse_item_t *prev = NULL;
    rbp_analyse_item_t *next = NULL;

    item = bucket->first;
    while (item != NULL) {
        next = item->next;
        if ((uint64)item->lfn < dtc_my_ctrl(session)->rcy_point.lfn) { /* if this item can be reused */
            if (prev == NULL) {
                bucket->first = next;
            } else {
                prev->next = next;
            }
            item->is_verified = 0;
            item->page_id.file = 0;
            item->page_id.page = 0;
            item->lsn = 0;
            item->lfn = 0;
            item->best_lsn = 0;
            item->seen_node_bitmap = 0;
            item->best_source_node = OG_INVALID_ID32;
            item->node_id = OG_INVALID_ID32;
            for (uint32 i = 0; i < RBP_ALY_TOUCH_SLOT_COUNT; i++) {
                item->touch_min[i] = 0;
                item->touch_max[i] = 0;
            }

            item->next = free_list->first;
            free_list->first = item;
            free_list->count++;
            bucket->count--;
        } else {
            prev = item;
        }

        item = next;
    }
}

static void rbp_aly_do_recycle(knl_session_t *session, rbp_analyse_item_t **new_item)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_aly_ctx_t *aly = &session->kernel->rbp_aly_ctx;
    date_t now_time = g_timer()->now;
    date_t last_time = MIN(aly->last_recycle_time, now_time);
    if ((now_time - last_time) < RBP_RECYCLE_TIMEOUT) {
        return;
    }

    for (uint32 i = 0; i < RBP_ALY_MAX_FILE * RBP_ALY_MAX_BUCKET_PER_FILE; i++) {
        rbp_aly_recycle_old_item(session, &ctx->rbp_aly_buckets[i]); // try recycle all rbp aly buckets
    }
    aly->last_recycle_time = now_time;
    *new_item = rbp_aly_pop_free_item(session);
    OG_LOG_DEBUG_WAR("[RBP] free all rbp aly buckets");
}

static inline void rbp_aly_set_item(rbp_analyse_item_t *item, uint64 lsn, uint64 lfn)
{
    item->lsn = lsn;
    item->lfn = lfn;
    item->best_lsn = 0;
    item->seen_node_bitmap = 0;
    item->best_source_node = OG_INVALID_ID32;
    item->node_id = OG_INVALID_ID32;
}

static inline void rbp_aly_set_first_touch(rbp_analyse_item_t *item, uint64 lfn, uint32 node_id)
{
    item->first_lfn = lfn;
    item->first_node_id = node_id;
    item->first_reserved = 0;
}

static inline void rbp_aly_reset_touch(rbp_analyse_item_t *item)
{
    for (uint32 i = 0; i < RBP_ALY_TOUCH_SLOT_COUNT; i++) {
        item->touch_min[i] = 0;
        item->touch_max[i] = 0;
    }
}

static void rbp_aly_update_touch(knl_session_t *session, rbp_analyse_item_t *item, uint64 lfn, uint32 node_id,
    page_id_t page_id)
{
    uint32 empty_slot = OG_INVALID_ID32;

    for (uint32 i = 0; i < RBP_ALY_TOUCH_SLOT_COUNT; i++) {
        if (item->touch_min[i] == 0) {
            if (empty_slot == OG_INVALID_ID32) {
                empty_slot = i;
            }
            continue;
        }

        if (RBP_ALY_TOUCH_NODE(item->touch_min[i]) != node_id) {
            continue;
        }

        if (lfn < RBP_ALY_TOUCH_LFN(item->touch_min[i])) {
            item->touch_min[i] = RBP_ALY_PACK_TOUCH(node_id, lfn);
        }
        if (lfn > RBP_ALY_TOUCH_LFN(item->touch_max[i])) {
            item->touch_max[i] = RBP_ALY_PACK_TOUCH(node_id, lfn);
        }
        return;
    }

    if (empty_slot != OG_INVALID_ID32) {
        item->touch_min[empty_slot] = RBP_ALY_PACK_TOUCH(node_id, lfn);
        item->touch_max[empty_slot] = RBP_ALY_PACK_TOUCH(node_id, lfn);
        return;
    }

    if (!session->kernel->redo_ctx.rbp_aly_result.rbp_unsafe) {
        OG_LOG_RUN_WAR("[RBP] rbp unsafe: touch range slots overflow page %u-%u node=%u lfn=%llu",
                       page_id.file, page_id.page, node_id, lfn);
    }
    rbp_set_unsafe(session, RD_TYPE_END);
}

/* Tag every analyzed page with the redo stream that produced this touch. */
uint32 rbp_aly_curr_node_id(knl_session_t *session)
{
    if (DB_IS_CLUSTER(session) && g_dtc != NULL && DTC_RCY_CONTEXT->node_count > 0) {
        return (uint32)DTC_RCY_CONTEXT->curr_node;
    }
    return (uint32)session->kernel->id;
}

static void rbp_aly_set_page_lsn_with_node(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn,
    uint32 curr_node_id)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_analyse_item_t *item = NULL;
    rbp_analyse_item_t *reuse_item = NULL;
    rbp_analyse_item_t *new_item = NULL;
    uint32 file_hash = page_id.file % RBP_ALY_MAX_FILE;
    uint32 page_hash = page_id.page % RBP_ALY_MAX_BUCKET_PER_FILE;
    rbp_analyse_bucket_t *bucket = &ctx->rbp_aly_buckets[file_hash * RBP_ALY_MAX_BUCKET_PER_FILE + page_hash];

    item = bucket->first;
    while (item != NULL) {
        knl_panic_log(item->lsn != OG_INVALID_LSN, "lsn is invalid, panic info: page %u-%u lsn %llu", page_id.file,
                      page_id.page, item->lsn);
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            if (item->first_lfn == 0) {
                rbp_aly_set_first_touch(item, lfn, curr_node_id);
            }
            rbp_aly_update_touch(session, item, lfn, curr_node_id, page_id);
            /*
            * DTC merges multiple redo streams by global LSN, while each stream owns an independent LFN axis.
            * Keep expect_lsn in page-version order; lower-LSN touches still update per-node touch ranges only.
            */
            if (lsn >= item->lsn) {
                rbp_aly_set_item(item, lsn, lfn);
                item->node_id = curr_node_id;
            }
            return;
        }

        if (reuse_item == NULL && (uint64)item->lfn < dtc_my_ctrl(session)->rcy_point.lfn) { /* if this item can be
                                                                                                reused */
            reuse_item = item;
        }
        item = item->next;
    }

    /* if same page id item is not found, try reuse one item */
    if (reuse_item != NULL) {
        rbp_aly_set_item(reuse_item, lsn, lfn);
        reuse_item->page_id = page_id;
        rbp_aly_reset_touch(reuse_item);
        rbp_aly_set_first_touch(reuse_item, lfn, curr_node_id);
        rbp_aly_update_touch(session, reuse_item, lfn, curr_node_id, page_id);
        reuse_item->node_id = curr_node_id;
        ctx->replay_stat.analyze_new_pages++;
        return;
    }

    /* if same page id item or reuse item is not found, add one free item */
    new_item = rbp_aly_pop_free_item(session);
    if (new_item == NULL) {
        rbp_aly_do_recycle(session, &new_item);
    }

    if (new_item != NULL) {
        new_item->next = bucket->first;
        bucket->first = new_item;
        bucket->count++;
        rbp_aly_set_item(new_item, lsn, lfn);
        new_item->page_id = page_id;
        rbp_aly_reset_touch(new_item);
        rbp_aly_set_first_touch(new_item, lfn, curr_node_id);
        rbp_aly_update_touch(session, new_item, lfn, curr_node_id, page_id);
        new_item->node_id = curr_node_id;
        ctx->replay_stat.analyze_new_pages++;
        return;
    }

    if (!ctx->rbp_aly_result.rbp_unsafe) {
        OG_LOG_RUN_WAR("[RBP] rbp unsafe because of analyze overflow, page %u-%u", page_id.file, page_id.page);
    }
    rbp_set_unsafe(session, RD_TYPE_END);
}

void rbp_aly_set_page_lsn(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn)
{
    rbp_aly_set_page_lsn_with_node(session, page_id, lsn, lfn, rbp_aly_curr_node_id(session));
}

uint32 rbp_aly_free_space_percent(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (ctx->rbp_aly_items == NULL) {
        return 0;
    }

    return (ctx->rbp_aly_free_list.count * RBP_ALY_PERCENT_BASE / RBP_ALY_MAX_ITEM); // calculate percent
}

rbp_analyse_item_t *rbp_aly_get_page_item(knl_session_t *session, page_id_t page_id)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rbp_analyse_item_t *item = NULL;
    uint32 file_hash = page_id.file % RBP_ALY_MAX_FILE;
    uint32 page_hash = page_id.page % RBP_ALY_MAX_BUCKET_PER_FILE;
    rbp_analyse_bucket_t *bucket = &ctx->rbp_aly_buckets[file_hash * RBP_ALY_MAX_BUCKET_PER_FILE + page_hash];

    item = bucket->first;
    while (item != NULL) {
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            return item;
        }

        item = item->next;
    }

    return NULL;
}

uint64 rbp_aly_get_page_lsn(knl_session_t *session, page_id_t page_id)
{
    rbp_analyse_item_t *item = NULL;

    if (session->kernel->rbp_context.rbp_agent_thread.closed) {
        return OG_INVALID_LSN;
    }

    item = rbp_aly_get_page_item(session, page_id);
    return (item == NULL) ? OG_INVALID_LSN : item->lsn;
}

/*
  * analyze redo log, only running when RBP is enabled. it dose not replay redo expect txn page
  * it will record all page's latest lsn
  */
static status_t rbp_aly_analyze(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
                                uint32 block_size)
{
    bool32 need_more = OG_FALSE;

    if (rcy_analysis(session, point, data_size, batch, block_size, &need_more) != OG_SUCCESS) {
        OG_LOG_RUN_INF("[RBP] failed to analyze log at point [%u-%u/%u/%llu]",
                        point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
        return OG_ERROR;
    }

    if (!need_more) {
        OG_LOG_RUN_INF("[RBP] failed to analyze log at point [%u-%u/%u/%llu], no more log needed",
                        point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/* like lrpl, rbp analyze proc will read and analyze all standby redo log */
static status_t rbp_aly_perform(knl_session_t *session, log_point_t *point)
{
    rbp_aly_ctx_t *aly_ctx = &session->kernel->rbp_aly_ctx;
    log_context_t *log = &session->kernel->redo_ctx;
    uint32 data_size = 0;
    uint32 file_id;
    uint32 block_size;

    log_lock_logfile(session);
    file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn, &aly_ctx->loading_curr_file);
    log_unlock_logfile(session);

    if (file_id == OG_INVALID_ID32) {
        bool32 reset = OG_FALSE;
        if (lrpl_prepare_archfile(session, point, &reset) != OG_SUCCESS) {
            OG_LOG_RUN_INF("[RBP] failed to prepare archive log at point [%u-%u/%u/%llu]",
                            point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
            return OG_ERROR;
        }
        if (reset) {
            return OG_SUCCESS;
        }

        if (rcy_load_from_arch(session, point, &data_size, &aly_ctx->arch_file, &aly_ctx->read_buf) != OG_SUCCESS) {
            OG_LOG_RUN_INF("[RBP] failed to load archive log at point [%u-%u/%u/%llu]",
                            point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
            return OG_ERROR;
        }
        block_size = (uint32)aly_ctx->arch_file.head.block_size;
    } else {
        if (rcy_load_from_online(session, file_id, point, &data_size, aly_ctx->log_handle + file_id,
                                  &aly_ctx->read_buf) != OG_SUCCESS) {
            OG_LOG_RUN_INF("[RBP] failed to load online log[%u] at point [%u-%u/%u/%llu]",
                            file_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
            return OG_ERROR;
        }
        block_size = log->files[file_id].ctrl->block_size;
    }

    log_batch_t *batch = (log_batch_t *)aly_ctx->read_buf.aligned_buf;
    if (rbp_aly_analyze(session, point, data_size, batch, block_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void rbp_free_aly_proc_context(knl_session_t *aly_session, rbp_aly_ctx_t *aly_ctx)
{
    cm_close_file(aly_ctx->arch_file.handle);
    aly_ctx->arch_file.handle = INVALID_FILE_HANDLE;

    for (uint32 i = 0; i < OG_MAX_LOG_FILES; i++) {
        cm_close_file(aly_ctx->log_handle[i]);
        aly_ctx->log_handle[i] = INVALID_FILE_HANDLE;
    }

    cm_aligned_free(&aly_ctx->read_buf);
    cm_aligned_free(&aly_ctx->log_decrypt_buf);
    cm_aligned_free(&aly_ctx->bucket_buf);
    rbp_release_bg_session(aly_session);
    aly_ctx->sid = OG_INVALID_ID32;
}

/*
  * log analysis thread, run when rbp enabled on standby
  * like lrpl, it read and analyze redo log to get page latest lsn
  */
static void rbp_aly_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    rbp_aly_ctx_t *aly = &session->kernel->rbp_aly_ctx;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    bool32 sleep_needed = OG_FALSE;

    cm_set_thread_name("rbp_aly");
    OG_LOG_RUN_INF("[RBP] rbp aly thread started");
    KNL_SESSION_SET_CURR_THREADID(session, thread->id);

    aly->curr_point = redo_ctx->curr_point;
    aly->begin_point = aly->curr_point;
    aly->is_started = OG_TRUE;
    aly->is_done = OG_FALSE;
    redo_ctx->analysis_lfn = aly->curr_point.lfn;

    while (!thread->closed) {
        if (aly->is_closing) {
            break;
        }

        if (sleep_needed && rbp_promote_triggered(session->kernel)) {
            OG_LOG_RUN_INF("[RBP] log analysis failover triggered");

            redo_ctx->redo_end_point = aly->curr_point;
            if (rbp_pre_check(session, redo_ctx->redo_end_point)) {
                rbp_knl_check_end_point(session);
            }
            break;
        }
        if (sleep_needed) {
            cm_sleep(RBP_ALY_REDO_SLEEP_MS);
        }

        if (!lrpl_need_replay(session, &aly->curr_point)) {
            sleep_needed = OG_TRUE;
            continue;
        }

        if (rbp_aly_perform(session, &aly->curr_point) != OG_SUCCESS) {
            redo_ctx->redo_end_point = aly->curr_point;
            aly->has_gap = OG_TRUE;
            OG_LOG_RUN_WAR("[RBP] rbp analysis failed");
            break;
        }

        sleep_needed = OG_FALSE;
    }

    cm_close_thread(&aly->page_bucket.thread);
    aly->is_done = OG_TRUE;
    aly->end_time = cm_now();
    OG_LOG_RUN_INF("[RBP] log analysis end with log point: rst_id %u asn %u lfn %llu block_id %u",
                    aly->curr_point.rst_id, aly->curr_point.asn, (uint64)aly->curr_point.lfn,
                    aly->curr_point.block_id);

    rbp_free_aly_proc_context(session, aly);
    KNL_SESSION_CLEAR_THREADID(session);
    thread->closed = OG_TRUE;
}

static void rbp_aly_page_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    rbp_aly_ctx_t *aly = &session->kernel->rbp_aly_ctx;
    rbp_page_bucket_t *bucket = &aly->page_bucket;
    date_t last_time = g_timer()->now;
    rbp_aly_page_t ctrl;
    uint32 tail;

    cm_set_thread_name("rbp_page_proc");
    OG_LOG_RUN_INF("[RBP] rbp page thread started");
    for (;;) {
        if (bucket->head == bucket->tail) {
            if (thread->closed) {
                break;
            }

            if (g_timer()->now - last_time > RCY_SLEEP_TIME_THRESHOLD) {
                cm_sleep(RBP_BUCKET_EMPTY_SLEEP_MS);
            } else {
                cm_spin_sleep();
            }
            continue;
        }

        cm_spin_lock(&bucket->lock, NULL);
        tail = bucket->tail;
        cm_spin_unlock(&bucket->lock);

        if (bucket->head == tail) {
            cm_spin_sleep();
            continue;
        }
        last_time = g_timer()->now;

        while (bucket->head != tail) {
            ctrl = bucket->first[bucket->head];
            rbp_aly_set_page_lsn_with_node(session, ctrl.page_id, ctrl.lsn, ctrl.lfn, ctrl.node_id);
            bucket->head = (bucket->head + 1) % bucket->count;
        }
    }
    OG_LOG_RUN_INF("[RBP] rbp page thread closed");
}

/* init rbp analyze memory and start rbp analyze proc */
status_t rbp_aly_init(knl_session_t *session)
{
    rbp_aly_ctx_t *aly_ctx = &session->kernel->rbp_aly_ctx;
    knl_session_t *aly_session = NULL;

    errno_t ret = memset_sp(aly_ctx, sizeof(rbp_aly_ctx_t), 0, sizeof(rbp_aly_ctx_t));
    knl_securec_check(ret);

    aly_ctx->arch_file.handle = INVALID_FILE_HANDLE;
    for (uint32 i = 0; i < OG_MAX_LOG_FILES; i++) {
        aly_ctx->log_handle[i] = INVALID_FILE_HANDLE;
    }

    if (rbp_alloc_bg_session(0, &aly_session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* redo analysis memory is alloced in rbp_agent_start when db_mount, if switchover as standby, need reset memory */
    if (rbp_aly_mem_init(session) != OG_SUCCESS) {
        rbp_free_aly_proc_context(aly_session, aly_ctx);
        return OG_ERROR;
    }

    if (cm_aligned_malloc(OG_MAX_BATCH_SIZE, "log analysis read buffer", &aly_ctx->read_buf) != OG_SUCCESS) {
        rbp_free_aly_proc_context(aly_session, aly_ctx);
        return OG_ERROR;
    }

    if (cm_aligned_malloc((int64)session->kernel->attr.lgwr_cipher_buf_size, "log analysis decrypt buffer",
                           &aly_ctx->log_decrypt_buf) != OG_SUCCESS) {
        rbp_free_aly_proc_context(aly_session, aly_ctx);
        return OG_ERROR;
    }

    if (cm_aligned_malloc((int64)RBP_ALY_PAGE_BUCKET_SIZE, "log analysis bucket buffer",
                           &aly_ctx->bucket_buf) != OG_SUCCESS) {
        rbp_free_aly_proc_context(aly_session, aly_ctx);
        return OG_ERROR;
    }

    aly_ctx->sid = aly_session->id;
    aly_ctx->page_bucket.first = (rbp_aly_page_t *)aly_ctx->bucket_buf.aligned_buf;
    aly_ctx->page_bucket.count = RBP_ALY_PAGE_COUNT;
    aly_ctx->page_bucket.head = 0;
    aly_ctx->page_bucket.tail = 0;
    aly_ctx->page_bucket.lock = 0;
    aly_ctx->begin_time = cm_now();

    if (cm_create_thread(rbp_aly_page_proc, 0, aly_session, &aly_ctx->page_bucket.thread) != OG_SUCCESS) {
        rbp_free_aly_proc_context(aly_session, aly_ctx);
        return OG_ERROR;
    }

    if (cm_create_thread(rbp_aly_proc, 0, aly_session, &aly_ctx->thread) != OG_SUCCESS) {
        cm_close_thread(&aly_ctx->page_bucket.thread);
        rbp_free_aly_proc_context(aly_session, aly_ctx);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void rbp_aly_close(knl_session_t *session)
{
    rbp_aly_ctx_t *aly_ctx = &session->kernel->rbp_aly_ctx;

    aly_ctx->is_closing = OG_TRUE;
    cm_close_thread(&aly_ctx->thread);
    OG_LOG_RUN_INF("[RBP] rbp aly thread is closed successfully");
}

/* some redo type is unsafe to rbp, when find these redo, set rbp unsafe status and max unsafe lsn */
void rbp_aly_unsafe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    ctx->rbp_aly_result.unsafe_max_lsn = lsn;

    if (!ctx->rbp_aly_result.rbp_unsafe) {
        OG_LOG_RUN_WAR("[RBP] rbp unsafe because of redo log type: %u, lsn: %llu", log->type, lsn);
        if (log->type == RD_LOGIC_OPERATION) {
            OG_LOG_RUN_WAR("[RBP] unsafe logic type: %u", *((logic_op_t *)log->data));
        }
    }
    rbp_set_unsafe(session, log->type);
}

void rbp_aly_safe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    knl_panic(session->curr_page_ctrl == NULL || !BUF_IS_RESIDENT(session->curr_page_ctrl));
}

/* get last point of online redo */
status_t rbp_aly_get_file_end_point(knl_session_t *session, log_point_t *point, uint16 file_id)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t *file = NULL;

    if (file_id == OG_INVALID_ID16) {
        return OG_ERROR;
    }
    file = &redo_ctx->files[file_id];

    point->asn = file->head.asn;
    point->rst_id = file->head.rst_id;
    point->block_id = (uint32)(file->head.write_pos / file->head.block_size);
    point->lfn = 0; // do not need show lfn in rbp view dv_rbp_analyze_info
    return OG_SUCCESS;
}

void rbp_record_promote_time(knl_session_t *session, const char *stage, const char *promote_type)
{
    log_context_t *log = &session->kernel->redo_ctx;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    if (cm_str_equal_ins(stage, "log analyze")) {
        OG_LOG_RUN_INF("[RBP] [%s] Log analyze time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                        promote_type, (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                        (uint64)log->redo_end_point.rst_id, log->redo_end_point.asn,
                        (uint64)log->redo_end_point.lfn);
    } else {
        OG_LOG_RUN_INF("[RBP] [%s] LRPL replay used time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                        promote_type, (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                        (uint64)lrpl->curr_point.rst_id, lrpl->curr_point.asn, (uint64)lrpl->curr_point.lfn);
    }

    log->promote_temp_time = KNL_NOW(session);
}

/*
  * SQL DEBUG: raw PAGE_READ to RBP (verify demo / wire only; does not apply page to buffer pool).
  */
status_t knl_rbp_sql_demo_read_page(knl_session_t *session, uint16 file_no, uint32 page_no, uint32 *out_result)
{
    rbp_context_t *rbp_context = NULL;
    rbp_buf_manager_t *manager = NULL;
    rbp_read_req_t request;
    rbp_read_resp_t response;
    uint32 rbp_proc_id;
    cs_pipe_t *pipe = NULL;
    bool32 use_temp_pipe = OG_FALSE;
    errno_t err;

    if (session == NULL || out_result == NULL) {
        return OG_ERROR;
    }
    *out_result = RBP_READ_RESULT_ERROR;

    if (!KNL_RBP_ENABLE(session->kernel)) {
        return OG_ERROR;
    }

    rbp_context = &session->kernel->rbp_context;
    rbp_proc_id = page_no % OG_RBP_SESSION_COUNT;
    manager = &rbp_context->rbp_buf_manager[rbp_proc_id];

    cm_spin_lock(&manager->fisrt_pipe_lock, NULL);
    if (!manager->is_connected) {
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return OG_ERROR;
    }

    /*
    * Always use pipe_const for this SQL debug path. Preferring pipe_temp could pick a stale fd after pipe_const
    * reconnect (rbp_init_connection memsets only pipe_const; rbp_stop_temp_connection may not have run), so
    * send/wait fails while the new const is healthy; demo sees no PAGE_READ and pull_rbp_page_demo returns -1.
    * Same fisrt_pipe_lock as PAGE_WRITE / HB / recovery temp paths on this queue.
    */
    pipe = rbp_get_client_pipe(rbp_context, rbp_proc_id, OG_FALSE);
    use_temp_pipe = OG_FALSE;
    err = memset_sp(&request, sizeof(request), 0, sizeof(request));
    knl_securec_check(err);
    RBP_SET_MSG_HEADER(&request, RBP_REQ_PAGE_READ, sizeof(rbp_read_req_t), cs_get_socket_fd(pipe));
    request.header.queue_id = manager->queue_id;
    request.page_id = make_page_id(file_no, page_no);
    request.buf_pool_id = 0;

    if (rbp_knl_send_request(pipe, (char *)&request, use_temp_pipe ? NULL : manager) != OG_SUCCESS) {
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return OG_ERROR;
    }

    err = memset_sp(&response, sizeof(response), 0, sizeof(response));
    knl_securec_check(err);
    if (rbp_knl_wait_response(pipe, (char *)&response, sizeof(rbp_read_resp_t)) != OG_SUCCESS) {
        cs_disconnect(pipe);
        if (!use_temp_pipe) {
            manager->is_connected = OG_FALSE;
        }
        cm_spin_unlock(&manager->fisrt_pipe_lock);
        return OG_ERROR;
    }
    cm_spin_unlock(&manager->fisrt_pipe_lock);

    *out_result = response.result;
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
