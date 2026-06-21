/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * knl_gbp.c
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_gbp.c
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
#include "knl_gbp.h"
 #include "knl_database.h"
 #include "knl_recovery.h"
#include "dtc_recovery.h"
#include "dtc_database.h"
#include "dtc_context.h"
#include "dtc_drc.h"

 #ifdef __cplusplus
 extern "C"{
 #endif

static gbp_queue_item_t *gbp_remove_queue_item(knl_session_t *session, gbp_queue_t *queue,
                                               gbp_queue_item_t *prev, gbp_queue_item_t *item);
void gbp_refresh_gbp_window(knl_session_t *session, uint32 gbp_proc_id);
static bool32 gbp_is_multi_node_rcy(knl_session_t *session);
static uint32 gbp_collect_active_rcy_nodes(knl_session_t *session, uint32 *node_ids, uint32 max_nodes);
static status_t gbp_init_connection(knl_session_t *session, gbp_buf_manager_t *gbp_buf_manager, const char *host,
                                    uint16 port, bool32 is_temp);
static status_t gbp_ensure_temp_connection_by_node(knl_session_t *session, gbp_buf_manager_t *manager, uint32 node_id);
static gbp_page_status_e gbp_eval_page_candidate(knl_session_t *session, page_id_t page_id, uint64 gbp_page_lsn,
                                                 uint64 curr_page_lsn, uint64 expect_lsn, bool32 log_ahead);
static void gbp_log_ahead_detail(knl_session_t *session, page_id_t page_id, uint32 source_node, uint64 gbp_page_lsn,
                                 gbp_analyse_item_t *item, uint64 expect_lsn);
static uint32 gbp_knl_read_selected_pages(knl_session_t *session);
static gbp_page_status_e gbp_knl_pull_one_page(knl_session_t *session, buf_ctrl_t *ctrl);
static void gbp_clear_ctrl_pending(buf_ctrl_t *ctrl, gbp_queue_item_t *item, const char *reason, uint64 reset_lfn,
                                   uint64 gap_end_lfn);
static void gbp_queue_notify_reset_point_one(knl_session_t *session, uint32 queue_id, log_point_t *point,
                                             const char *reason, bool32 warn_log);

#define GBP_PAGE_WRITE_BACKLOG_WARN_COUNT 4096
#define GBP_PAGE_WRITE_ASSEMBLE_DIAG_US   1000000
#define GBP_PAGE_WRITE_ITEM_DIAG_US       100000
#define GBP_PAGE_WRITE_SEND_DIAG_US       500000
#define GBP_PAGE_WRITE_REDO_DIAG_US       500000
#define GBP_PAGE_WRITE_LOG_INTERVAL_US    (5 * MICROSECS_PER_SECOND)
#define GBP_ASSEMBLE_DIAG_INTERVAL_US     MICROSECS_PER_SECOND
#define GBP_READ_BATCH_SLOW_US            200000
#define GBP_READ_BATCH_SLOW_INTERVAL_US   (5 * MICROSECS_PER_SECOND)
#define GBP_READ_SAMPLE_LIMIT             5

#if GBP_READ_HOT_DIAG
#define GBP_READ_STEP_BEGIN(var)          ((var) = cm_now())
#define GBP_READ_STEP_ACCUM(var, acc)     ((acc) += (uint64)(cm_now() - (var)))
#else
#define GBP_READ_STEP_BEGIN(var)          ((void)sizeof(var))
#define GBP_READ_STEP_ACCUM(var, acc)     ((void)sizeof(var), (void)sizeof(acc))
#endif
#define GBP_CKPT_PURGE_INTERVAL_FACTOR    5
#define GBP_SEND_LATCH_WAIT               30
#define GBP_SEND_LATCH_TIMEOUT            3
#define GBP_ASSEMBLE_MAX_SCAN_DEFAULT     300
#define GBP_ASSEMBLE_MAX_SCAN_MIN         100
#define GBP_ASSEMBLE_MAX_SCAN_MAX         1000000

typedef enum en_gbp_latch_result {
    GBP_LATCH_OK = 0,
    GBP_LATCH_BUSY,
    GBP_LATCH_ERROR
} gbp_latch_result_t;

typedef struct st_gbp_assemble_diag {
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
} gbp_assemble_diag_t;

static date_t g_gbp_backlog_last_log[OG_GBP_SESSION_COUNT] = { 0 };
static date_t g_gbp_queue_diag_last_log[OG_GBP_SESSION_COUNT] = { 0 };
#if GBP_PAGE_WRITE_HOT_DIAG
static date_t g_gbp_assemble_diag_last_log[OG_GBP_SESSION_COUNT] = { 0 };
#endif

static inline bool32 gbp_rate_loggable(date_t *last_log_time, date_t now, date_t interval_us)
{
    if (*last_log_time == 0 || now - *last_log_time >= interval_us) {
        *last_log_time = now;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static inline void gbp_assemble_diag_update_max_detail(gbp_assemble_diag_t *diag, uint64 item_us, page_id_t page_id,
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

static inline bool32 gbp_snapshot_low_watermark_loggable(uint32 free_count)
{
    return (bool32)(free_count == 0 || (free_count & (free_count - 1)) == 0);
}

static inline bool32 gbp_queue_backlog_loggable(uint32 queue_id, uint32 count)
{
#ifdef GBP_VERBOSE_TRACE
    return (bool32)(count >= GBP_PAGE_WRITE_BACKLOG_WARN_COUNT &&
                    (count % GBP_PAGE_WRITE_BACKLOG_WARN_COUNT) == 0);
#else
    if (count < GBP_PAGE_WRITE_BACKLOG_WARN_COUNT) {
        return OG_FALSE;
    }
    return gbp_rate_loggable(&g_gbp_backlog_last_log[queue_id % OG_GBP_SESSION_COUNT], g_timer()->now,
                             GBP_PAGE_WRITE_LOG_INTERVAL_US);
#endif
}

static inline bool32 gbp_page_write_diag_loggable(uint32 queue_id, bool32 took_gap_reset, bool32 took_ckpt_reset,
                                                  uint32 queue_count_before, uint32 queue_count_after,
                                                  uint64 assemble_us, uint64 wait_redo_us, uint64 send_us)
{
    if (took_gap_reset) {
        return OG_TRUE;
    }
    if (assemble_us >= GBP_PAGE_WRITE_ASSEMBLE_DIAG_US || wait_redo_us >= GBP_PAGE_WRITE_REDO_DIAG_US ||
        send_us >= GBP_PAGE_WRITE_SEND_DIAG_US) {
        return OG_TRUE;
    }
    if (took_ckpt_reset || queue_count_before >= GBP_PAGE_WRITE_BACKLOG_WARN_COUNT ||
        queue_count_after >= GBP_PAGE_WRITE_BACKLOG_WARN_COUNT) {
        return gbp_rate_loggable(&g_gbp_queue_diag_last_log[queue_id % OG_GBP_SESSION_COUNT], g_timer()->now,
                                 GBP_PAGE_WRITE_LOG_INTERVAL_US);
    }
    return OG_FALSE;
}

static inline uint32 gbp_get_assemble_max_scan(knl_session_t *session)
{
    uint32 max_scan = session->kernel->gbp_attr.assemble_max_scan;

    if (max_scan == 0) {
        return GBP_ASSEMBLE_MAX_SCAN_DEFAULT;
    }
    max_scan = MAX(max_scan, GBP_ASSEMBLE_MAX_SCAN_MIN);
    max_scan = MIN(max_scan, GBP_ASSEMBLE_MAX_SCAN_MAX);
    return MAX(max_scan, (uint32)GBP_BATCH_PAGE_NUM);
}

static gbp_queue_item_t *gbp_alloc_queue_item(void)
{
    gbp_queue_item_t *item = (gbp_queue_item_t *)malloc(sizeof(gbp_queue_item_t));
    errno_t ret;

    if (item == NULL) {
        return NULL;
    }

    ret = memset_sp(item, sizeof(gbp_queue_item_t), 0, sizeof(gbp_queue_item_t));
    knl_securec_check(ret);
    return item;
}

static gbp_snapshot_t *gbp_alloc_snapshot(knl_session_t *session)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_snapshot_t *snapshot = NULL;
    errno_t ret;
    bool32 log_low = OG_FALSE;
    uint32 low_free = 0;
    uint64 alloc_total = 0;
    uint64 free_total = 0;
    uint64 fail_total = 0;

    cm_spin_lock(&gbp_ctx->snapshot_lock, NULL);
    snapshot = gbp_ctx->snapshot_free;
    if (snapshot == NULL) {
        gbp_ctx->snapshot_alloc_fail_total++;
        low_free = gbp_ctx->snapshot_low_watermark;
        alloc_total = gbp_ctx->snapshot_alloc_total;
        free_total = gbp_ctx->snapshot_free_total;
        fail_total = gbp_ctx->snapshot_alloc_fail_total;
        cm_spin_unlock(&gbp_ctx->snapshot_lock);
        OG_LOG_RUN_WAR("[GBP] snapshot pool empty: free=0 low_watermark=%u alloc_total=%llu free_total=%llu "
                       "fail_total=%llu",
                       low_free, (uint64)alloc_total, (uint64)free_total, (uint64)fail_total);
        return NULL;
    }
    gbp_ctx->snapshot_free = snapshot->next;
    gbp_ctx->snapshot_free_count--;
    gbp_ctx->snapshot_alloc_total++;
    if (gbp_ctx->snapshot_free_count < gbp_ctx->snapshot_low_watermark) {
        gbp_ctx->snapshot_low_watermark = gbp_ctx->snapshot_free_count;
        log_low = gbp_snapshot_low_watermark_loggable(gbp_ctx->snapshot_free_count);
        low_free = gbp_ctx->snapshot_free_count;
        alloc_total = gbp_ctx->snapshot_alloc_total;
        free_total = gbp_ctx->snapshot_free_total;
        fail_total = gbp_ctx->snapshot_alloc_fail_total;
    }
    cm_spin_unlock(&gbp_ctx->snapshot_lock);

    if (log_low) {
        OG_LOG_RUN_WAR("[GBP] snapshot pool low watermark: free=%u/%u alloc_total=%llu free_total=%llu "
                       "fail_total=%llu",
                       low_free, (uint32)GBP_SNAPSHOT_POOL_SIZE, (uint64)alloc_total, (uint64)free_total,
                       (uint64)fail_total);
    }

    ret = memset_sp(snapshot, sizeof(gbp_snapshot_t), 0, sizeof(gbp_snapshot_t));
    knl_securec_check(ret);
    return snapshot;
}

static void gbp_free_snapshot(knl_session_t *session, gbp_snapshot_t *snapshot)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;

    if (snapshot == NULL) {
        return;
    }

    cm_spin_lock(&gbp_ctx->snapshot_lock, NULL);
    snapshot->next = gbp_ctx->snapshot_free;
    gbp_ctx->snapshot_free = snapshot;
    gbp_ctx->snapshot_free_count++;
    gbp_ctx->snapshot_free_total++;
    cm_spin_unlock(&gbp_ctx->snapshot_lock);
}

static void gbp_free_queue_item(knl_session_t *session, gbp_queue_item_t *item)
{
    if (item == NULL) {
        return;
    }

    gbp_free_snapshot(session, item->snapshot);
    item->snapshot = NULL;
    CM_FREE_PTR(item);
}

static status_t gbp_snapshot_pool_init(knl_session_t *session)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    int64 buf_size = (int64)GBP_SNAPSHOT_POOL_SIZE * (int64)sizeof(gbp_snapshot_t);
    gbp_snapshot_t *snapshot = NULL;
    errno_t ret;

    if (cm_aligned_malloc(buf_size, "gbp snapshot pool", &gbp_ctx->snapshot_buf) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ret = memset_sp(gbp_ctx->snapshot_buf.aligned_buf, buf_size, 0, buf_size);
    knl_securec_check(ret);
    snapshot = (gbp_snapshot_t *)gbp_ctx->snapshot_buf.aligned_buf;
    gbp_ctx->snapshot_free = snapshot;
    gbp_ctx->snapshot_free_count = GBP_SNAPSHOT_POOL_SIZE;
    gbp_ctx->snapshot_low_watermark = GBP_SNAPSHOT_POOL_SIZE;
    gbp_ctx->snapshot_alloc_total = 0;
    gbp_ctx->snapshot_free_total = 0;
    gbp_ctx->snapshot_alloc_fail_total = 0;
    for (uint32 i = 0; i < GBP_SNAPSHOT_POOL_SIZE - 1; i++) {
        snapshot[i].next = &snapshot[i + 1];
    }
    snapshot[GBP_SNAPSHOT_POOL_SIZE - 1].next = NULL;
    return OG_SUCCESS;
}

static void gbp_snapshot_pool_free(knl_session_t *session)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;

    gbp_ctx->snapshot_free = NULL;
    gbp_ctx->snapshot_free_count = 0;
    gbp_ctx->snapshot_low_watermark = 0;
    gbp_ctx->snapshot_alloc_total = 0;
    gbp_ctx->snapshot_free_total = 0;
    gbp_ctx->snapshot_alloc_fail_total = 0;
    cm_aligned_free(&gbp_ctx->snapshot_buf);
}

static void gbp_drain_send_queues(knl_session_t *session)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_queue_t *queue = NULL;
    gbp_queue_item_t *item = NULL;
    gbp_queue_item_t *next = NULL;
    uint64 cleared_total = 0;

    for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
        queue = &gbp_ctx->queue[id];
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
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
            if (item->source == GBP_QUEUE_ITEM_LIVE && item->ctrl != NULL && item->ctrl->gbp_ctrl != NULL) {
                gbp_clear_ctrl_pending(item->ctrl, item, "queue_clear", 0, 0);
            }
            item->next = NULL;
            gbp_free_queue_item(session, item);
            item = next;
        }
    }

    if (cleared_total > 0) {
        OG_LOG_RUN_WAR("[GBP] discarded local GBP write queues: pages=%llu", cleared_total);
    }
}

static inline bool32 gbp_clear_pending_loggable(const char *reason)
{
#ifdef GBP_VERBOSE_TRACE
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

static void gbp_clear_ctrl_pending(buf_ctrl_t *ctrl, gbp_queue_item_t *item, const char *reason, uint64 reset_lfn,
                                   uint64 gap_end_lfn)
{
    if (ctrl == NULL || ctrl->gbp_ctrl == NULL) {
        return;
    }

    if (ctrl->gbp_ctrl->pending_item == item) {
        if (gbp_clear_pending_loggable(reason)) {
            OG_LOG_RUN_INF("[GBP_CTRL_TRACE] CLEAR_PENDING reason=%s queue=%u page=%u-%u ctrl=%p item=%p "
                           "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                           "gap_end_lfn=%llu page_status=%u",
                           reason, item == NULL ? OG_INVALID_ID32 : item->queue_id, ctrl->page_id.file,
                           ctrl->page_id.page, (void *)ctrl, (void *)item, (uint64)ctrl->page->lsn,
                           (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                           (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)reset_lfn, (uint64)gap_end_lfn,
                           (uint32)ctrl->gbp_ctrl->page_status);
        }
        ctrl->gbp_ctrl->pending_item = NULL;
        ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
    }
}

static void gbp_drop_pending_item(knl_session_t *session, buf_ctrl_t *ctrl, const char *reason)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    uint32 queue_id;
    gbp_queue_t *queue = NULL;
    gbp_queue_item_t *item = NULL;
    page_id_t page_id;
    uint64 trunc_lfn = 0;
    uint64 lastest_lfn = 0;

    if (ctrl == NULL || ctrl->gbp_ctrl == NULL) {
        return;
    }

    page_id = ctrl->page_id;
    trunc_lfn = ctrl->gbp_ctrl->gbp_trunc_point.lfn;
    lastest_lfn = ctrl->lastest_lfn;
    queue_id = page_id.page % OG_GBP_SESSION_COUNT;
    queue = &gbp_ctx->queue[queue_id];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    item = ctrl->gbp_ctrl->pending_item;
    if (item != NULL && item->source == GBP_QUEUE_ITEM_LIVE && item->ctrl == ctrl) {
        item->source = GBP_QUEUE_ITEM_DROPPED;
        item->ctrl = NULL;
    }
    OG_LOG_RUN_WAR("[GBP_CTRL_TRACE] DROP_PENDING reason=%s queue=%u page=%u-%u ctrl=%p item=%p "
                   "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu gap_end_lfn=%llu "
                   "page_status=%u",
                   reason, queue_id, page_id.file, page_id.page, (void *)ctrl, (void *)item,
                   (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)lastest_lfn, (uint64)trunc_lfn,
                   (uint64)0, (uint64)0, (uint32)ctrl->gbp_ctrl->page_status);
    ctrl->gbp_ctrl->pending_item = NULL;
    ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
    queue->has_gap = OG_TRUE;
    cm_spin_unlock(&queue->lock);

    OG_LOG_RUN_WAR("[GBP] drop pending queue item: queue=%u page=%u-%u trunc_lfn=%llu lastest_lfn=%llu reason=%s",
                   queue_id, page_id.file, page_id.page, (uint64)trunc_lfn, (uint64)lastest_lfn, reason);
}

/*
 * Multi-writer GBP placement:
 * - In a cluster, each node writes local dirty pages to the peer GBP process.
 * - Queueing and PAGE_WRITE are based on DRC exclusive page ownership, not DB_IS_PRIMARY.
 * - Non-cluster primary/standby still only lets the primary enqueue GBP writes.
 */
bool32 gbp_ctrl_may_enqueue(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (!KNL_GBP_ENABLE(session->kernel)) {
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[GBP] skip enqueue page %u-%u: GBP disabled", ctrl->page_id.file, ctrl->page_id.page);
#endif
        return OG_FALSE;
    }
    if (DB_IS_CLUSTER(session)) {
        if (OGRAC_REPLAY_NODE(session)) {
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_INF("[GBP] skip enqueue page %u-%u: replay node session type=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)session->dtc_session_type);
#endif
            return OG_FALSE;
        }
        if (ctrl->lock_mode != DRC_LOCK_EXCLUSIVE) {
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_INF("[GBP] skip enqueue page %u-%u: lock_mode=%u is not DRC_LOCK_EXCLUSIVE",
                           ctrl->page_id.file, ctrl->page_id.page, (uint32)ctrl->lock_mode);
#endif
            return OG_FALSE;
        }
        return OG_TRUE;
    }
    if (!DB_IS_PRIMARY(&session->kernel->db)) {
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[GBP] skip enqueue page %u-%u: non-primary database role",
                       ctrl->page_id.file, ctrl->page_id.page);
#endif
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline bool32 gbp_should_suspend_page_write(knl_session_t *session)
{
    if (session == NULL || session->kernel == NULL) {
        return OG_FALSE;
    }

    return session->kernel->gbp_context.page_write_suspended;
}

void gbp_suspend_page_write_for_partial_recovery(knl_session_t *session)
{
    gbp_context_t *gbp_context = NULL;

    if (session == NULL || session->kernel == NULL || !KNL_GBP_ENABLE(session->kernel)) {
        return;
    }

    gbp_context = &session->kernel->gbp_context;
    if (!gbp_context->page_write_suspended) {
        OG_LOG_RUN_WAR("[GBP] PAGE_WRITE suspend enter partial_recovery");
    }
    gbp_context->page_write_suspended = OG_TRUE;
    gbp_context->clear_after_partial_recovery = OG_TRUE;
}

void gbp_finish_partial_recovery_page_write(knl_session_t *session)
{
    gbp_context_t *gbp_context = NULL;

    if (session == NULL || session->kernel == NULL || !KNL_GBP_ENABLE(session->kernel)) {
        return;
    }

    gbp_context = &session->kernel->gbp_context;
    if (gbp_context->clear_after_partial_recovery) {
        gbp_drain_send_queues(session);
        gbp_context->clear_after_partial_recovery = OG_FALSE;
    }
    if (gbp_context->page_write_suspended) {
        gbp_context->page_write_suspended = OG_FALSE;
        OG_LOG_RUN_WAR("[GBP] PAGE_WRITE suspend leave partial_recovery");
    }
}

bool32 gbp_instance_may_write_to_remote(knl_session_t *session)
{
    if (!KNL_GBP_ENABLE(session->kernel)) {
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

bool32 gbp_db_enforce_primary_style_invariants(knl_session_t *session)
{
    if (OGRAC_REPLAY_NODE(session)) {
        return OG_FALSE;
    }
    if (DB_IS_CLUSTER(session)) {
        return OG_TRUE;
    }
    return (bool32)DB_IS_PRIMARY(&session->kernel->db);
}

void gbp_on_page_owner_migrate_or_invalidate(knl_session_t *session, buf_ctrl_t *ctrl)
{
    if (!KNL_GBP_ENABLE(session->kernel) || ctrl == NULL || ctrl->gbp_ctrl == NULL) {
        return;
    }

    /*
     * DRC owner migration does not destroy the local page image by itself. The GBP
     * send queue stores ctrl pointers, so the background writer can still copy the
     * EDP image after the owner has moved away. Only real ctrl reuse/recycle should
     * create a GBP gap; that path still calls gbp_queue_set_gap().
     */
    if (!ctrl->gbp_ctrl->is_gbpdirty) {
        OG_LOG_DEBUG_INF("[GBP] owner migrate/invalidate page %u-%u: no GBP gap, page is not pending",
                         ctrl->page_id.file, ctrl->page_id.page);
        return;
    }

    OG_LOG_DEBUG_INF("[GBP] owner migrate/invalidate page %u-%u: keep pending GBP page, "
                     "trunc_lfn=%llu lastest_lfn=%llu",
                     ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn,
                     (uint64)ctrl->lastest_lfn);
}

bool32 gbp_need_wait_before_remote_overwrite(knl_session_t *session, buf_ctrl_t *ctrl)
{
    return (bool32)(KNL_GBP_ENABLE(session->kernel) && ctrl != NULL && ctrl->gbp_ctrl != NULL &&
                    ctrl->is_edp && ctrl->gbp_ctrl->is_gbpdirty);
}

/*
 * The caller must already hold the page X latch.  We copy the pending EDP image
 * into a detached snapshot so DCS/buffer recycle can overwrite/reuse the live
 * ctrl immediately without waiting for the GBP writer thread.
 */
bool32 gbp_try_detach_pending_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_snapshot_t *snapshot = NULL;
    gbp_queue_item_t *item = NULL;
    gbp_queue_t *queue = NULL;
    uint32 queue_id;
    uint32 snapshot_free_count = 0;
    uint32 snapshot_low_watermark = 0;
    uint64 snapshot_alloc_total = 0;
    uint64 snapshot_free_total = 0;
    uint64 snapshot_fail_total = 0;
    uint32 queue_count = 0;
    bool32 already_gap = OG_FALSE;
    errno_t ret;

    if (!KNL_GBP_ENABLE(session->kernel) || ctrl == NULL || ctrl->gbp_ctrl == NULL ||
        !ctrl->gbp_ctrl->is_gbpdirty) {
        return OG_TRUE;
    }

    snapshot = gbp_alloc_snapshot(session);
    queue_id = ctrl->page_id.page % OG_GBP_SESSION_COUNT;
    queue = &gbp_ctx->queue[queue_id];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    item = ctrl->gbp_ctrl->pending_item;
    if (item == NULL || item->source != GBP_QUEUE_ITEM_LIVE || item->ctrl != ctrl) {
        OG_LOG_RUN_WAR("[GBP_CTRL_TRACE] DROP_PENDING reason=pending_lost queue=%u page=%u-%u ctrl=%p item=%p "
                       "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                       "gap_end_lfn=%llu page_status=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                       (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                       (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn,
                       (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint64)0,
                       (uint32)ctrl->gbp_ctrl->page_status);
        ctrl->gbp_ctrl->pending_item = NULL;
        ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
        queue->has_gap = OG_TRUE;
        cm_spin_unlock(&queue->lock);
        gbp_free_snapshot(session, snapshot);
        gbp_queue_notify_reset_point_one(session, queue_id, &session->kernel->redo_ctx.curr_point, "pending_lost",
                                         OG_TRUE);
        OG_LOG_RUN_WAR("[GBP] pending dirty page has no live queue item, set gap: queue=%u page=%u-%u "
                       "lastest_lfn=%llu",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn);
        return OG_FALSE;
    }

    if (snapshot == NULL) {
        already_gap = queue->has_gap;
        item->source = GBP_QUEUE_ITEM_DROPPED;
        item->ctrl = NULL;
        OG_LOG_RUN_WAR("[GBP_CTRL_TRACE] DROP_PENDING reason=snapshot_detach_failed queue=%u page=%u-%u "
                       "ctrl=%p item=%p page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu "
                       "reset_lfn=%llu gap_end_lfn=%llu page_status=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                       (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                       (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn,
                       (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint64)0,
                       (uint32)ctrl->gbp_ctrl->page_status);
        ctrl->gbp_ctrl->pending_item = NULL;
        ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
        queue->has_gap = OG_TRUE;
        queue_count = queue->count;
        cm_spin_unlock(&queue->lock);

        cm_spin_lock(&gbp_ctx->snapshot_lock, NULL);
        snapshot_free_count = gbp_ctx->snapshot_free_count;
        snapshot_low_watermark = gbp_ctx->snapshot_low_watermark;
        snapshot_alloc_total = gbp_ctx->snapshot_alloc_total;
        snapshot_free_total = gbp_ctx->snapshot_free_total;
        snapshot_fail_total = gbp_ctx->snapshot_alloc_fail_total;
        cm_spin_unlock(&gbp_ctx->snapshot_lock);

        gbp_queue_notify_reset_point_one(session, queue_id, &session->kernel->redo_ctx.curr_point,
                                         "snapshot_detach_failed", OG_TRUE);
        OG_LOG_RUN_WAR("[GBP] snapshot detach failed, set gap: queue=%u page=%u-%u trunc_lfn=%llu lastest_lfn=%llu "
                       "queue_count=%u already_gap=%u connected=%u rcy_with_gbp=%u db_open=%u curr_lfn=%llu "
                       "snapshot_free=%u low_watermark=%u alloc_total=%llu free_total=%llu fail_total=%llu",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page,
                        (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn, queue_count,
                        (uint32)already_gap, (uint32)gbp_ctx->gbp_buf_manager[queue_id].is_connected,
                        (uint32)KNL_RECOVERY_WITH_GBP(session->kernel), (uint32)DB_IS_OPEN(session),
                        (uint64)session->kernel->redo_ctx.curr_point.lfn, snapshot_free_count, snapshot_low_watermark,
                        (uint64)snapshot_alloc_total, (uint64)snapshot_free_total, (uint64)snapshot_fail_total);
        return OG_FALSE;
    }

    snapshot->page_id = ctrl->page_id;
    snapshot->gbp_trunc_point = ctrl->gbp_ctrl->gbp_trunc_point;
    snapshot->lastest_lfn = ctrl->lastest_lfn;
    snapshot->writer_inst_id = (uint32)session->kernel->id;
    snapshot->writer_global_seq = ctrl->page->lsn;
    ret = memcpy_sp(snapshot->block, GBP_PAGE_SIZE, ctrl->page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    item->source = GBP_QUEUE_ITEM_SNAPSHOT;
    item->ctrl = NULL;
    item->snapshot = snapshot;
    item->page_id = snapshot->page_id;
#ifdef GBP_VERBOSE_TRACE
    OG_LOG_RUN_INF("[GBP_CTRL_TRACE] CLEAR_PENDING reason=snapshot_detach queue=%u page=%u-%u ctrl=%p item=%p "
                   "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu gap_end_lfn=%llu "
                   "page_status=%u",
                   queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                   (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                   (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)0, (uint64)0,
                   (uint32)ctrl->gbp_ctrl->page_status);
#endif
    ctrl->gbp_ctrl->pending_item = NULL;
    ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
    cm_spin_unlock(&queue->lock);

#ifdef GBP_VERBOSE_TRACE
    OG_LOG_DEBUG_INF("[GBP] detached pending page snapshot: queue=%u page=%u-%u trunc_lfn=%llu lastest_lfn=%llu "
                     "page_lsn=%llu",
                     queue_id, snapshot->page_id.file, snapshot->page_id.page,
                     (uint64)snapshot->gbp_trunc_point.lfn, (uint64)snapshot->lastest_lfn,
                     (uint64)snapshot->writer_global_seq);
#endif
    return OG_TRUE;
}

void gbp_wait_before_remote_overwrite(knl_session_t *session, buf_ctrl_t *ctrl)
{
    /*
     * Kept for old callers.  The new DCS/recycle path calls gbp_try_detach_pending_page()
     * while holding the X latch; if a legacy caller reaches here without that latch, do
     * not spin in foreground.  Drop the pending item and force a normal GBP gap instead.
     */
    if (gbp_need_wait_before_remote_overwrite(session, ctrl)) {
        gbp_drop_pending_item(session, ctrl, "legacy_remote_overwrite_without_snapshot");
    }
}

static cs_pipe_t *gbp_get_client_pipe(gbp_context_t *gbp_context, uint32 gbp_proc_id, bool32 is_temp)
{
    gbp_buf_manager_t *manager = &gbp_context->gbp_buf_manager[gbp_proc_id];

    return (is_temp) ? &manager->pipe_temp : &manager->pipe_const;
}

static cs_pipe_t *gbp_get_selected_temp_pipe(gbp_context_t *gbp_context, uint32 gbp_proc_id)
{
    gbp_buf_manager_t *manager = &gbp_context->gbp_buf_manager[gbp_proc_id];

    return &manager->pipe_selected_temp;
}

static void gbp_clear_dtc_planned_required_items(gbp_context_t *gbp_context)
{
    CM_FREE_PTR(gbp_context->dtc_planned_required_items);
    gbp_context->dtc_planned_required_built = OG_FALSE;
    gbp_context->dtc_planned_required_count = 0;
    gbp_context->dtc_planned_required_capacity = 0;
}

static void gbp_clear_dtc_read_epoch(gbp_context_t *gbp_context)
{
    gbp_context->dtc_read_active = OG_FALSE;
    gbp_context->dtc_read_workers_done = OG_FALSE;
    gbp_context->dtc_read_node_count = 0;
    gbp_context->dtc_use_selected_batch = OG_FALSE;
    gbp_context->dtc_need_selected_meta = OG_FALSE;
    gbp_context->dtc_sync_selected_pull_at_begin = OG_FALSE;
    for (uint32 i = 0; i < OG_MAX_INSTANCES; i++) {
        gbp_context->dtc_selected_cursor[i] = 0;
    }
    for (uint32 i = 0; i < OG_GBP_SESSION_COUNT; i++) {
        gbp_context->dtc_selected_worker_nodes[i] = OG_INVALID_ID32;
    }
    gbp_context->dtc_verify_node_count = 0;
    gbp_clear_dtc_planned_required_items(gbp_context);
}

static void gbp_reset_read_stat(gbp_context_t *gbp_context)
{
    errno_t ret;

    (void)cm_atomic_set(&gbp_context->gbp_read_pages, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_errors, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_batch_elapsed, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_selected_mismatch, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_pull_miss_trace, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_partial_ahead_detail, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_ahead_detail, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_partial_disk_fallback, 0);
    (void)cm_atomic_set(&gbp_context->gbp_read_multi_disk_fallback, 0);
    gbp_context->gbp_read_workers_done_time = 0;
#if GBP_READ_HOT_DIAG
    ret = memset_sp(gbp_context->read_diag, sizeof(gbp_context->read_diag), 0, sizeof(gbp_context->read_diag));
    knl_securec_check(ret);
    ret = memset_sp(&gbp_context->read_skip_diag, sizeof(gbp_context->read_skip_diag), 0,
                    sizeof(gbp_context->read_skip_diag));
    knl_securec_check(ret);
#else
    ret = memset_sp(gbp_context->read_diag, sizeof(gbp_context->read_diag), 0, sizeof(gbp_context->read_diag));
    knl_securec_check(ret);
#endif
}

static void gbp_log_read_anomaly_summary(gbp_context_t *gbp_context)
{
    uint64 selected_mismatch = (uint64)cm_atomic_get(&gbp_context->gbp_read_selected_mismatch);
    uint64 pull_miss_trace = (uint64)cm_atomic_get(&gbp_context->gbp_read_pull_miss_trace);
    uint64 partial_ahead = (uint64)cm_atomic_get(&gbp_context->gbp_read_partial_ahead_detail);
    uint64 ahead = (uint64)cm_atomic_get(&gbp_context->gbp_read_ahead_detail);
    uint64 partial_fallback = (uint64)cm_atomic_get(&gbp_context->gbp_read_partial_disk_fallback);
    uint64 multi_fallback = (uint64)cm_atomic_get(&gbp_context->gbp_read_multi_disk_fallback);

    if (selected_mismatch == 0 && pull_miss_trace == 0 && partial_ahead == 0 && ahead == 0 &&
        partial_fallback == 0 && multi_fallback == 0) {
        return;
    }

    OG_LOG_RUN_INF("[GBP] read anomaly summary: selected_page_read_mismatch=%llu pull_miss_trace=%llu "
                   "partial_ahead_detail=%llu ahead_detail=%llu partial_disk_fallback=%llu "
                   "multi_disk_fallback=%llu sample_limit=%u",
                   selected_mismatch, pull_miss_trace, partial_ahead, ahead, partial_fallback, multi_fallback,
                   GBP_READ_SAMPLE_LIMIT);
}

static void gbp_record_read_skip_partial_no_expect(gbp_context_t *gbp_context, gbp_partial_item_t *partial_item)
{
#if !GBP_READ_HOT_DIAG
    (void)gbp_context;
    (void)partial_item;
    return;
#else
    (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_no_expect);
    if (partial_item == NULL) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_no_expect_no_item);
        return;
    }

    if (!partial_item->required) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_no_expect_not_required);
    }
#endif
}

static void gbp_record_read_skip_partial_selected_scope(gbp_context_t *gbp_context, gbp_partial_item_t *partial_item,
    buf_ctrl_t *ctrl)
{
#if !GBP_READ_HOT_DIAG
    (void)gbp_context;
    (void)partial_item;
    (void)ctrl;
    return;
#else
    (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_selected_scope);
    if (partial_item == NULL) {
        return;
    }

    if (partial_item->required) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_selected_scope_required);
    }
    if (partial_item->selected_valid) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_selected_scope_selected_valid);
    }
    if (partial_item->selected_pulled) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_selected_scope_selected_pulled);
    }
    if (partial_item->verified) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_selected_scope_verified);
    }
    if (ctrl != NULL && ctrl->load_status != 0) {
        (void)cm_atomic_inc(&gbp_context->read_skip_diag.partial_selected_scope_load_status);
    }
#endif
}

static void gbp_record_read_skip_no_expect_lsn(gbp_context_t *gbp_context)
{
#if GBP_READ_HOT_DIAG
    (void)cm_atomic_inc(&gbp_context->read_skip_diag.no_expect_lsn);
#else
    (void)gbp_context;
#endif
}

static void gbp_record_read_skip_nolog_space(gbp_context_t *gbp_context)
{
#if GBP_READ_HOT_DIAG
    (void)cm_atomic_inc(&gbp_context->read_skip_diag.nolog_space);
#else
    (void)gbp_context;
#endif
}

static void gbp_record_read_batch_stat(gbp_context_t *gbp_context, uint32 result, uint32 page_count, uint64 elapsed)
{
    (void)cm_atomic_add(&gbp_context->gbp_read_pages, (int64)page_count);
    (void)cm_atomic_add(&gbp_context->gbp_read_batch_elapsed, (int64)elapsed);
    if (result != GBP_READ_RESULT_OK && result != GBP_READ_RESULT_NOPAGE) {
        (void)cm_atomic_inc(&gbp_context->gbp_read_errors);
    }
}

#if GBP_READ_HOT_DIAG
static void gbp_add_apply_diag(gbp_read_apply_diag_t *dst, const gbp_read_apply_diag_t *src)
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

static void gbp_record_read_diag(gbp_context_t *gbp_context, uint32 gbp_proc_id, uint32 result, uint32 page_count,
    uint64 total_us, uint64 pipe_lock_us, uint64 ensure_conn_us, uint64 send_us, uint64 wait_resp_us,
    uint64 process_us, const gbp_read_apply_diag_t *apply)
{
    gbp_read_worker_diag_t *diag;
    date_t now;
#if GBP_READ_HOT_DIAG
    uint64 connect_us = pipe_lock_us + ensure_conn_us;
    uint64 selected = (apply == NULL) ? 0 : apply->selected;
    uint64 installed = (apply == NULL) ? 0 : apply->installed;
    uint64 not_required = (apply == NULL) ? 0 : apply->not_required;
#endif

    if (gbp_proc_id >= OG_GBP_SESSION_COUNT) {
        return;
    }

    diag = &gbp_context->read_diag[gbp_proc_id];
    if (result == GBP_READ_RESULT_OK) {
        diag->ok_batches++;
    } else if (result == GBP_READ_RESULT_NOPAGE) {
        diag->nopage_batches++;
    } else {
        diag->error_batches++;
    }
    diag->pages += page_count;
    diag->total_us += total_us;
#if GBP_READ_HOT_DIAG
    diag->connect_us += connect_us;
    diag->pipe_lock_us += pipe_lock_us;
    diag->ensure_conn_us += ensure_conn_us;
    diag->send_us += send_us;
    diag->wait_resp_us += wait_resp_us;
    diag->process_us += process_us;
    gbp_add_apply_diag(&diag->apply, apply);
#endif

    if (total_us < GBP_READ_BATCH_SLOW_US) {
        return;
    }

    now = cm_now();
    if (diag->slow_last_log_time != 0 && (uint64)(now - diag->slow_last_log_time) < GBP_READ_BATCH_SLOW_INTERVAL_US) {
        return;
    }
    diag->slow_last_log_time = now;
#if GBP_READ_HOT_DIAG
    OG_LOG_RUN_WAR("[GBP] slow BATCH_READ: q=%u result=%u pages=%u total_us=%llu connect_us=%llu send_us=%llu "
                   "wait_resp_us=%llu process_us=%llu pipe_lock_us=%llu ensure_conn_us=%llu selected=%llu "
                   "installed=%llu not_required=%llu",
                   gbp_proc_id, result, page_count, total_us, connect_us, send_us, wait_resp_us, process_us,
                   pipe_lock_us, ensure_conn_us, selected, installed, not_required);
#else
    OG_LOG_RUN_WAR("[GBP] slow BATCH_READ: q=%u result=%u pages=%u total_us=%llu",
                   gbp_proc_id, result, page_count, total_us);
#endif
}

static void gbp_finish_read_batch_stat(knl_session_t *session, uint32 gbp_proc_id, uint32 result, uint32 page_count,
    date_t begin_time, uint64 pipe_lock_us, uint64 ensure_conn_us, uint64 send_us, uint64 wait_resp_us,
    uint64 process_us, const gbp_read_apply_diag_t *apply)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    date_t now = cm_now();
    uint64 total_us = (now > begin_time) ? (uint64)(now - begin_time) : 0;

    gbp_record_read_batch_stat(gbp_context, result, page_count, total_us);
    gbp_record_read_diag(gbp_context, gbp_proc_id, result, page_count, total_us, pipe_lock_us, ensure_conn_us,
                         send_us, wait_resp_us, process_us, apply);
}

static void gbp_log_read_diag_summary(gbp_context_t *gbp_context)
{
#if !GBP_READ_HOT_DIAG
    (void)gbp_context;
    return;
#else
    gbp_read_worker_diag_t total = { 0 };
    uint32 workers = 0;
    uint64 total_batches;
    uint64 avg_batch_us;
    uint64 avg_wait_us;
    uint64 avg_process_us;

    for (uint32 i = 0; i < OG_GBP_SESSION_COUNT; i++) {
        const gbp_read_worker_diag_t *diag = &gbp_context->read_diag[i];
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
        gbp_add_apply_diag(&total.apply, &diag->apply);
    }

    total_batches = total.ok_batches + total.nopage_batches + total.error_batches;
    if (total_batches == 0) {
        return;
    }

    avg_batch_us = total.total_us / total_batches;
    avg_wait_us = total.wait_resp_us / total_batches;
    avg_process_us = total.process_us / total_batches;
    OG_LOG_RUN_INF("[GBP] read batch timing total: workers=%u ok=%llu nopage=%llu err=%llu pages=%llu "
                   "total_us=%llu connect_us=%llu send_us=%llu wait_resp_us=%llu process_us=%llu "
                   "pipe_lock_us=%llu ensure_conn_us=%llu avg_batch_us=%llu avg_wait_us=%llu avg_process_us=%llu",
                   workers, total.ok_batches, total.nopage_batches, total.error_batches, total.pages,
                   total.total_us, total.connect_us, total.send_us, total.wait_resp_us, total.process_us,
                   total.pipe_lock_us, total.ensure_conn_us, avg_batch_us, avg_wait_us, avg_process_us);

    for (uint32 i = 0; i < OG_GBP_SESSION_COUNT; i++) {
        const gbp_read_worker_diag_t *diag = &gbp_context->read_diag[i];
        uint64 worker_batches = diag->ok_batches + diag->nopage_batches + diag->error_batches;
        uint64 avg_total_us;

        if (worker_batches == 0 && diag->pages == 0 && diag->total_us == 0) {
            continue;
        }

        avg_total_us = (worker_batches == 0) ? 0 : diag->total_us / worker_batches;
        OG_LOG_RUN_INF("[GBP] read worker timing: q=%u ok=%llu nopage=%llu err=%llu pages=%llu "
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

    OG_LOG_RUN_INF("[GBP] partial apply total: resp=%llu not_required=%llu selected=%llu installed=%llu "
                   "no_expect=%llu ahead=%llu wrong_node=%llu hit=%llu usable=%llu old=%llu miss=%llu "
                   "other_status=%llu not_newer=%llu",
                   total.apply.resp_pages, total.apply.not_required, total.apply.selected, total.apply.installed,
                   total.apply.no_expect, total.apply.ahead, total.apply.wrong_node, total.apply.hit,
                   total.apply.usable, total.apply.old, total.apply.miss, total.apply.other_status,
                   total.apply.not_newer);
    OG_LOG_RUN_INF("[GBP] partial process total: select_update_us=%llu enter_page_us=%llu eval_us=%llu "
                   "replace_us=%llu mark_us=%llu leave_page_us=%llu",
                   total.apply.select_update_us, total.apply.enter_page_us, total.apply.eval_us,
                   total.apply.replace_us, total.apply.mark_us, total.apply.leave_page_us);
    OG_LOG_RUN_INF("[GBP] partial replace total: copy_us=%llu disk_check_us=%llu id_check_us=%llu pcn_check_us=%llu "
                   "dirty_us=%llu ckpt_enque_us=%llu ckpt_enque=%llu already_dirty=%llu",
                   total.apply.replace_copy_us, total.apply.replace_disk_check_us,
                   total.apply.replace_id_check_us, total.apply.replace_pcn_check_us,
                   total.apply.replace_dirty_us, total.apply.replace_ckpt_enque_us, total.apply.replace_ckpt_enque,
                   total.apply.replace_already_dirty);
    if (gbp_context->dtc_use_selected_batch && !gbp_context->dtc_need_selected_meta) {
        uint32 node_id = (gbp_context->dtc_read_node_count == 1) ?
            gbp_context->dtc_read_nodes[0] : OG_INVALID_ID32;
        OG_LOG_RUN_INF("[GBP] selected direct summary: node=%u required=%u requested=%llu returned=%llu "
                       "installed=%llu verified=%llu missing=%llu mismatch=%llu",
                       node_id, gbp_context->dtc_planned_required_count,
                       total.apply.selected_requested, total.apply.resp_pages, total.apply.installed,
                       total.apply.selected_verified, total.apply.selected_missing, total.apply.selected_mismatch);
    }
#endif
}

static void gbp_log_read_skip_summary(gbp_context_t *gbp_context)
{
#if !GBP_READ_HOT_DIAG
    (void)gbp_context;
    return;
#else
    gbp_read_skip_diag_t *diag = &gbp_context->read_skip_diag;
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

    OG_LOG_RUN_INF("[GBP] read skip summary: total=%llu partial_no_expect=%llu no_item=%llu "
                   "not_required=%llu partial_selected_scope=%llu required=%llu selected_valid=%llu "
                   "selected_pulled=%llu verified=%llu load_status_nonzero=%llu no_expect_lsn=%llu "
                   "nolog_space=%llu",
                   total, partial_no_expect, partial_no_expect_no_item, partial_no_expect_not_required,
                   partial_selected_scope, partial_selected_scope_required, partial_selected_scope_selected_valid,
                   partial_selected_scope_selected_pulled, partial_selected_scope_verified,
                   partial_selected_scope_load_status, no_expect_lsn, nolog_space);
#endif
}

static uint64 gbp_dtc_read_skip_lfn_total(gbp_context_t *gbp_context)
{
    uint64 total = 0;
    uint16 node_count = (gbp_context->dtc_verify_node_count > 0) ?
        gbp_context->dtc_verify_node_count : gbp_context->dtc_read_node_count;

    for (uint32 i = 0; i < node_count; i++) {
        log_point_t *skip = (gbp_context->dtc_verify_node_count > 0) ?
            &gbp_context->dtc_verify_skip_points[i] : &gbp_context->dtc_read_skip_points[i];
        log_point_t *rcy = (gbp_context->dtc_verify_node_count > 0) ?
            &gbp_context->dtc_verify_rcy_points[i] : &gbp_context->dtc_read_rcy_points[i];
        if (rcy->lfn > skip->lfn) {
            total += (uint64)(rcy->lfn - skip->lfn);
        }
    }

    return total;
}

static int32 gbp_find_dtc_read_node(gbp_context_t *gbp_context, uint32 node_id)
{
    for (uint32 i = 0; i < gbp_context->dtc_read_node_count; i++) {
        if (gbp_context->dtc_read_nodes[i] == node_id) {
            return (int32)i;
        }
    }

    return -1;
}

static int32 gbp_find_dtc_verify_node(gbp_context_t *gbp_context, uint32 node_id)
{
    for (uint32 i = 0; i < gbp_context->dtc_verify_node_count; i++) {
        if (gbp_context->dtc_verify_nodes[i] == node_id) {
            return (int32)i;
        }
    }

    return -1;
}

static bool32 gbp_get_dtc_read_points(knl_session_t *session, uint32 node_id, log_point_t **skip_point,
                                      log_point_t **rcy_point, log_point_t **lrp_point)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    int32 idx = gbp_find_dtc_read_node(gbp_context, node_id);

    if (idx >= 0) {
        if (skip_point != NULL) {
            *skip_point = &gbp_context->dtc_read_skip_points[idx];
        }
        if (rcy_point != NULL) {
            *rcy_point = &gbp_context->dtc_read_rcy_points[idx];
        }
        if (lrp_point != NULL) {
            *lrp_point = &gbp_context->dtc_read_lrp_points[idx];
        }
        return OG_TRUE;
    }

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress || node_id >= OG_MAX_INSTANCES ||
        !DTC_RCY_CONTEXT->gbp_read_planned[node_id]) {
        return OG_FALSE;
    }

    if (skip_point != NULL) {
        *skip_point = &DTC_RCY_CONTEXT->gbp_begin_points[node_id];
    }
    if (rcy_point != NULL) {
        *rcy_point = &DTC_RCY_CONTEXT->gbp_rcy_points[node_id];
    }
    if (lrp_point != NULL) {
        *lrp_point = &DTC_RCY_CONTEXT->gbp_lrp_points[node_id];
    }
    return OG_TRUE;
}

static bool32 gbp_get_dtc_verify_points(knl_session_t *session, uint32 node_id, log_point_t **skip_point,
                                        log_point_t **rcy_point)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    int32 idx = gbp_find_dtc_verify_node(gbp_context, node_id);

    if (idx >= 0) {
        if (skip_point != NULL) {
            *skip_point = &gbp_context->dtc_verify_skip_points[idx];
        }
        if (rcy_point != NULL) {
            *rcy_point = &gbp_context->dtc_verify_rcy_points[idx];
        }
        return OG_TRUE;
    }

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress || node_id >= OG_MAX_INSTANCES ||
        !DTC_RCY_CONTEXT->gbp_jump_taken[node_id]) {
        return OG_FALSE;
    }

    if (skip_point != NULL) {
        *skip_point = &DTC_RCY_CONTEXT->gbp_skip_points[node_id];
    }
    if (rcy_point != NULL) {
        *rcy_point = &DTC_RCY_CONTEXT->gbp_rcy_points[node_id];
    }
    return OG_TRUE;
}

static void gbp_refresh_dtc_verify_epoch(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    dtc_rcy_context_t *dtc_rcy = NULL;
    uint32 count = 0;

    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return;
    }

    gbp_context->dtc_verify_node_count = 0;
    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < OG_MAX_INSTANCES; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->gbp_jump_taken[node_id]) {
            continue;
        }

        gbp_context->dtc_verify_nodes[count] = node_id;
        gbp_context->dtc_verify_skip_points[count] = dtc_rcy->gbp_skip_points[node_id];
        gbp_context->dtc_verify_rcy_points[count] = dtc_rcy->gbp_rcy_points[node_id];
        count++;
    }
    gbp_context->dtc_verify_node_count = (uint16)count;
}

static status_t gbp_save_dtc_read_epoch(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    dtc_rcy_context_t *dtc_rcy = NULL;
    uint32 count = 0;

    gbp_clear_dtc_read_epoch(gbp_context);
    if (!DB_IS_CLUSTER(session) || g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return OG_ERROR;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < OG_MAX_INSTANCES; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->gbp_window_valid[node_id] ||
            !dtc_rcy->gbp_read_planned[node_id]) {
            continue;
        }

        gbp_context->dtc_read_nodes[count] = node_id;
        gbp_context->dtc_read_skip_points[count] = dtc_rcy->gbp_begin_points[node_id];
        gbp_context->dtc_read_rcy_points[count] = dtc_rcy->gbp_rcy_points[node_id];
        gbp_context->dtc_read_lrp_points[count] = dtc_rcy->gbp_lrp_points[node_id];
        count++;
    }

    if (count == 0) {
        return OG_ERROR;
    }

    gbp_context->dtc_read_node_count = (uint16)count;
    gbp_context->dtc_read_active = OG_TRUE;
    OG_LOG_DEBUG_INF("[GBP] DTC partial read epoch saved: planned_nodes=%u planned_lfn_total=%llu",
                     (uint32)gbp_context->dtc_read_node_count,
                     gbp_dtc_read_skip_lfn_total(gbp_context));
    for (uint32 i = 0; i < gbp_context->dtc_read_node_count; i++) {
        OG_LOG_DEBUG_INF("[GBP] DTC read epoch node[%u]=%u begin_lfn=%llu rcy_lfn=%llu lrp_lfn=%llu",
                         i, gbp_context->dtc_read_nodes[i],
                         (uint64)gbp_context->dtc_read_skip_points[i].lfn,
                         (uint64)gbp_context->dtc_read_rcy_points[i].lfn,
                         (uint64)gbp_context->dtc_read_lrp_points[i].lfn);
    }
    return OG_SUCCESS;
}

static bool32 gbp_is_dtc_partial_read(knl_session_t *session)
{
    return (bool32)(DB_IS_CLUSTER(session) && g_dtc != NULL && OGRAC_PART_RECOVERY(session));
}

static uint64 gbp_get_item_expect_lsn(knl_session_t *session, gbp_analyse_item_t *item)
{
    if (item == NULL) {
        return 0;
    }
    if (gbp_is_dtc_partial_read(session) && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress) {
        return dtc_rcy_gbp_partial_expect_lsn(session, item->page_id, item->lsn);
    }
    return item->lsn;
}

/* v6 DTC recovery uses per-node GBP routing. Partial recovery needs it even when only one crashed node is recovered. */
static bool32 gbp_is_multi_node_rcy(knl_session_t *session)
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
static uint32 gbp_collect_active_rcy_nodes(knl_session_t *session, uint32 *node_ids, uint32 max_nodes)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 count = 0;
    dtc_rcy_context_t *dtc_rcy = NULL;

    if (!gbp_is_multi_node_rcy(session)) {
        return 0;
    }

    if (gbp_context->dtc_read_node_count > 0) {
        for (uint32 i = 0; i < gbp_context->dtc_read_node_count && count < max_nodes; i++) {
            node_ids[count++] = gbp_context->dtc_read_nodes[i];
        }
        return count;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < max_nodes; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES) {
            continue;
        }
        if (!dtc_rcy->gbp_window_valid[node_id] || !dtc_rcy->gbp_read_planned[node_id]) {
            continue;
        }
        node_ids[count++] = node_id;
    }
    return count;
}

static uint32 gbp_collect_verify_rcy_nodes(knl_session_t *session, uint32 *node_ids, uint32 max_nodes)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 count = 0;
    dtc_rcy_context_t *dtc_rcy = NULL;

    if (!gbp_is_multi_node_rcy(session)) {
        return 0;
    }

    gbp_refresh_dtc_verify_epoch(session);
    if (gbp_context->dtc_verify_node_count > 0) {
        for (uint32 i = 0; i < gbp_context->dtc_verify_node_count && count < max_nodes; i++) {
            node_ids[count++] = gbp_context->dtc_verify_nodes[i];
        }
        return count;
    }

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return 0;
    }

    dtc_rcy = DTC_RCY_CONTEXT;
    for (uint32 i = 0; i < dtc_rcy->node_count && count < max_nodes; i++) {
        uint32 node_id = (uint32)dtc_rcy->rcy_log_points[i].node_id;
        if (node_id >= OG_MAX_INSTANCES || !dtc_rcy->gbp_jump_taken[node_id]) {
            continue;
        }
        node_ids[count++] = node_id;
    }
    return count;
}

static inline bool32 gbp_aly_item_in_node_skip(gbp_analyse_item_t *item, uint32 node_id, log_point_t *skip_point,
                                               log_point_t *rcy_point)
{
    for (uint32 i = 0; i < GBP_ALY_TOUCH_SLOT_COUNT; i++) {
        if (item->touch_min[i] == 0 || GBP_ALY_TOUCH_NODE(item->touch_min[i]) != node_id) {
            continue;
        }

        /*
         * Verify if this page's touch range on the node intersects the skipped LFN window.
         * This is conservative and fixes the "first before skip, latest in tail, middle in skip" hole.
         */
        if (GBP_ALY_TOUCH_LFN(item->touch_max[i]) > skip_point->lfn &&
            GBP_ALY_TOUCH_LFN(item->touch_min[i]) <= rcy_point->lfn) {
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

static inline bool32 gbp_aly_item_in_global_skip(gbp_analyse_item_t *item, uint64 skip_start, uint64 skip_end)
{
    for (uint32 i = 0; i < GBP_ALY_TOUCH_SLOT_COUNT; i++) {
        if (item->touch_min[i] == 0) {
            continue;
        }
        if (GBP_ALY_TOUCH_LFN(item->touch_max[i]) >= skip_start &&
            GBP_ALY_TOUCH_LFN(item->touch_min[i]) < skip_end) {
            return OG_TRUE;
        }
    }

    /* Compatibility fallback for items created before touch ranges were populated. */
    if (item->lfn > 0 && item->lfn >= skip_start && item->lfn < skip_end) {
        return OG_TRUE;
    }

    return (bool32)(item->first_lfn > 0 && item->first_lfn >= skip_start && item->first_lfn < skip_end);
}

static status_t gbp_append_dtc_planned_required_item(gbp_context_t *gbp_context, gbp_analyse_item_t *item)
{
    const uint32 max_capacity = (uint32)GBP_ALY_MAX_ITEM;
    uint32 new_capacity;
    gbp_analyse_item_t **new_items = NULL;

    if (gbp_context->dtc_planned_required_count < gbp_context->dtc_planned_required_capacity) {
        gbp_context->dtc_planned_required_items[gbp_context->dtc_planned_required_count++] = item;
        return OG_SUCCESS;
    }

    if (gbp_context->dtc_planned_required_capacity >= max_capacity) {
        OG_LOG_RUN_ERR("[GBP] planned required item cache is full: capacity=%u", max_capacity);
        return OG_ERROR;
    }

    new_capacity = (gbp_context->dtc_planned_required_capacity == 0) ? 4096 :
        gbp_context->dtc_planned_required_capacity * 2;
    if (new_capacity < gbp_context->dtc_planned_required_capacity || new_capacity > max_capacity) {
        new_capacity = max_capacity;
    }

    new_items = (gbp_analyse_item_t **)realloc(gbp_context->dtc_planned_required_items,
                                               (size_t)new_capacity * sizeof(gbp_analyse_item_t *));
    if (new_items == NULL) {
        OG_LOG_RUN_ERR("[GBP] failed to grow planned required item cache: old_capacity=%u new_capacity=%u",
                       gbp_context->dtc_planned_required_capacity, new_capacity);
        return OG_ERROR;
    }

    gbp_context->dtc_planned_required_items = new_items;
    gbp_context->dtc_planned_required_capacity = new_capacity;
    gbp_context->dtc_planned_required_items[gbp_context->dtc_planned_required_count++] = item;
    return OG_SUCCESS;
}

static bool32 gbp_dtc_item_required_by_planned_nodes(knl_session_t *session, gbp_analyse_item_t *item,
    uint32 *node_ids, log_point_t **skip_points, log_point_t **rcy_points, uint32 node_count,
    bool32 partial_read, uint64 expect_lsn)
{
    for (uint32 i = 0; i < node_count; i++) {
        if (!gbp_aly_item_in_node_skip(item, node_ids[i], skip_points[i], rcy_points[i])) {
            continue;
        }

        if (partial_read && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress &&
            !dtc_rcy_gbp_partial_item_need_verify(session, item->page_id, node_ids[i], item->lfn, expect_lsn)) {
            continue;
        }
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t gbp_build_dtc_planned_required_items(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 node_ids[OG_MAX_INSTANCES];
    log_point_t *skip_points[OG_MAX_INSTANCES];
    log_point_t *rcy_points[OG_MAX_INSTANCES];
    uint32 node_count = gbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
    uint32 valid_count = 0;
    bool32 partial_read = gbp_is_dtc_partial_read(session);
    date_t begin_time = cm_now();

    gbp_clear_dtc_planned_required_items(gbp_context);
    gbp_context->dtc_planned_required_built = OG_TRUE;
    if (partial_read) {
        if (dtc_rcy_gbp_partial_build_required(session) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[GBP] partial planned required item cache build failed");
            return OG_ERROR;
        }
        gbp_context->dtc_planned_required_count = dtc_rcy_gbp_partial_required_count();
        OG_LOG_DEBUG_INF("[GBP] partial planned required item cache built: planned_nodes=%u required_items=%u "
                         "elapsed_us=%llu",
                         node_count, gbp_context->dtc_planned_required_count, (uint64)(cm_now() - begin_time));
        return OG_SUCCESS;
    }
    if (ctx->gbp_aly_items == NULL || node_count == 0) {
        OG_LOG_RUN_WAR("[GBP] planned required item cache is empty: aly_items=%p planned_nodes=%u",
                       (void *)ctx->gbp_aly_items, node_count);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < node_count; i++) {
        if (!gbp_get_dtc_read_points(session, node_ids[i], &skip_points[valid_count], &rcy_points[valid_count], NULL)) {
            continue;
        }
        node_ids[valid_count] = node_ids[i];
        valid_count++;
    }
    if (valid_count == 0) {
        OG_LOG_RUN_WAR("[GBP] planned required item cache is empty: no valid planned node points");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < GBP_ALY_MAX_ITEM; i++) {
        gbp_analyse_item_t *item = &ctx->gbp_aly_items[i];
        uint64 expect_lsn;

        if (item->lfn == 0 && item->first_lfn == 0) {
            continue;
        }

        expect_lsn = gbp_get_item_expect_lsn(session, item);
        if (!gbp_dtc_item_required_by_planned_nodes(session, item, node_ids, skip_points, rcy_points,
                                                   valid_count, partial_read, expect_lsn)) {
            continue;
        }

        if (gbp_append_dtc_planned_required_item(gbp_context, item) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    OG_LOG_RUN_INF("[GBP] planned required item cache built: planned_nodes=%u required_items=%u "
                   "capacity=%u elapsed_us=%llu",
                   valid_count, gbp_context->dtc_planned_required_count,
                   gbp_context->dtc_planned_required_capacity, (uint64)(cm_now() - begin_time));
    return OG_SUCCESS;
}

/* database send request to GBP */
static status_t gbp_knl_send_request(cs_pipe_t *pipe, char *req_buf, gbp_buf_manager_t *manager)
 {
     gbp_msg_hdr_t *request = (gbp_msg_hdr_t *)req_buf;

     if (cs_write_stream(pipe, req_buf, request->msg_length, 0) == OG_SUCCESS) {
         return OG_SUCCESS;
     }

     OG_LOG_RUN_WAR("[GBP] failed to send request, type %u, fd %d", request->msg_type, cs_get_socket_fd(pipe));
     if (manager != NULL) {
         cs_disconnect(pipe); // just close const pipe here, temp pipes are closed at gbp_stop_temp_connection
         manager->is_connected = OG_FALSE;
     }
     return OG_ERROR;
 }

 /* database get reponse from GBP */
 static status_t gbp_knl_wait_response(cs_pipe_t *pipe, char *resp_buf, int32 buf_size)
 {
     int32 recv_size;
     int32 remain_size;
     gbp_msg_hdr_t msg;

     if (cs_read_stream(pipe, (char *)&msg, GBP_MAX_READ_WAIT_TIME, sizeof(gbp_msg_hdr_t), &recv_size) != OG_SUCCESS) {
         OG_LOG_RUN_ERR("[GBP] failed to receive message from GBP instance");
         return OG_ERROR;
     }

     if (sizeof(gbp_msg_hdr_t) != recv_size) {
         OG_LOG_RUN_ERR("[GBP] invalid recv_size %u received, expected size is %u",
                        recv_size, (int32)sizeof(gbp_msg_hdr_t));
         return OG_ERROR;
     }

     if (msg.msg_length < recv_size) {
         OG_LOG_RUN_ERR("[GBP] invalid message size %u received, which is smaller than %u",
                        msg.msg_length, recv_size);
         return OG_ERROR;
     }

     remain_size = msg.msg_length - recv_size;

     if (remain_size > (buf_size - sizeof(gbp_msg_hdr_t))) {
         OG_LOG_RUN_ERR("[GBP] invalid msg length size %u received", msg.msg_length);
         return OG_ERROR;
     }

     if (remain_size > 0) {
         if (cs_read_stream(pipe, resp_buf + sizeof(gbp_msg_hdr_t), GBP_MAX_READ_WAIT_TIME, remain_size,
                            &recv_size) != OG_SUCCESS) {
             OG_LOG_RUN_ERR("[GBP] failed to receive message type %u from GBP with size %u", msg.msg_type, remain_size);
             return OG_ERROR;
         }

         if (recv_size != (buf_size - sizeof(gbp_msg_hdr_t))) {
             OG_LOG_RUN_ERR("[GBP] invalid recv_size %u received, expected size is %u",
                            (uint32)recv_size, (uint32)(buf_size - sizeof(gbp_msg_hdr_t)));
             return OG_ERROR;
         }

         if (recv_size == 0) {
             OG_LOG_RUN_ERR("[GBP] peer close the connetion when read message body");
             return OG_ERROR;
         }
     }

     return OG_SUCCESS;
 }

 static status_t gbp_notify_msg(knl_session_t *session, gbp_notify_msg_e msg, uint32 gbp_proc_id, gbp_msg_ack_t *ack)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     gbp_attr_t *gbp_attr = &session->kernel->gbp_attr;
     database_t *db = &session->kernel->db;
    bool32 temp_pipe = ((msg == MSG_GBP_READ_BEGIN) || (msg == MSG_GBP_READ_END));
     cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, temp_pipe);
     gbp_notify_req_t request;
     errno_t ret;

     // set msg header
     GBP_SET_MSG_HEADER(&request, GBP_REQ_NOTIFY_MSG, sizeof(gbp_notify_req_t), cs_get_socket_fd(pipe));
     // set msg body
     request.msg = msg;
     request.db_stat.db_role = db->ctrl.core.db_role;
     request.db_stat.db_open = db->status;
     ret = memcpy_sp(request.db_stat.local_host, CM_MAX_IP_LEN, gbp_attr->local_gbp_host, CM_MAX_IP_LEN);
     knl_securec_check(ret);

   if (gbp_knl_send_request(pipe, (char *)&request,
                            temp_pipe ? NULL : &gbp_context->gbp_buf_manager[gbp_proc_id]) != OG_SUCCESS) {
        return OG_ERROR;
    }

    /* Demo / real GBP always sends gbp_msg_ack_t for NOTIFY; must drain or the next PAGE_READ wait sees 8-byte body. */
    gbp_msg_ack_t discard;
    return gbp_knl_wait_response(pipe, (char *)(ack != NULL ? ack : &discard), sizeof(gbp_msg_ack_t));
}

 /* primary or statndy send heart beat to GBP */
 static void gbp_timed_heart_beat(knl_session_t *session)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     uint32 gbp_proc_id = session->gbp_queue_index - 1;
     gbp_buf_manager_t *gbp_buf_manager = &gbp_context->gbp_buf_manager[gbp_proc_id];

     if (!KNL_GBP_ENABLE(session->kernel) || !gbp_buf_manager->is_connected) {
         return;
     }

     if (g_timer()->now - gbp_buf_manager->last_hb_time < GBP_HEARTBEAT_INTERVAL) {
         return;
     }

     cm_spin_lock(&gbp_buf_manager->fisrt_pipe_lock, NULL);
     if (gbp_notify_msg(session, MSG_GBP_HEART_BEAT, gbp_proc_id, NULL) != OG_SUCCESS) {
         OG_LOG_RUN_ERR("[GBP] heart beat with gbp failed");
     }
     cm_spin_unlock(&gbp_buf_manager->fisrt_pipe_lock);
     gbp_buf_manager->last_hb_time = g_timer()->now;
 }

 /* get page lsn record on disk */
 static uint64 gbp_get_disk_lsn(knl_session_t *session, page_id_t page_id, bool32 ignore_crc)
 {
     buf_ctrl_t ctrl;
     uint64 lsn;
     char *buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session) + OG_MAX_ALIGN_SIZE_4K);

     ctrl.page_id = page_id;
     ctrl.page = (page_head_t *)cm_aligned_buf(buf);

     if (buf_load_page_from_disk(session, &ctrl, page_id) != OG_SUCCESS) {
         if (ignore_crc) {
             /* Only verify disk lsn at gbp_replace_local_page in DEBUG mode, may be concurrent with ckpt */
             OG_LOG_RUN_WAR("[GBP] verify disk lsn failed because CRC failed");
             ctrl.page->lsn = OG_INVALID_LSN;
         } else {
             CM_ABORT(0, "[GBP] ABORT INFO: failed to load page %u-%u", page_id.file, page_id.page);
         }
     }

     lsn = ctrl.page->lsn;
     cm_pop(session->stack);
     return lsn;
 }

 /* replace database buffer page using GBP's page */
 static void gbp_replace_local_page(knl_session_t *session, buf_ctrl_t *ctrl, page_head_t *gbp_page,
     gbp_read_apply_diag_t *diag)
 {
     errno_t ret;
     date_t step_begin;

#if defined(LOG_DIAG) && defined(GBP_VERIFY_DISK_LSN_ON_REPLACE)
     step_begin = cm_now();
     uint64 disk_page_lsn = gbp_get_disk_lsn(session, ctrl->page_id, OG_TRUE);
     uint64 gbp_page_lsn = PAGE_GET_LSN(gbp_page);
     knl_panic_log(disk_page_lsn <= gbp_page_lsn, "disk_page_lsn is bigger than gbp_page_lsn, panic info: "
                   "ctrl_page %u-%u type %u, gbp_page %u-%u type %u disk_page_lsn %llu gbp_page_lsn %llu",
                   ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type, AS_PAGID(gbp_page->id).file,
                   AS_PAGID(gbp_page->id).page, gbp_page->type, disk_page_lsn, gbp_page_lsn);
     if (diag != NULL) {
         diag->replace_disk_check_us += (uint64)(cm_now() - step_begin);
     }
 #endif

     if (diag != NULL) {
         step_begin = cm_now();
     }
     ret = memcpy_sp(ctrl->page, DEFAULT_PAGE_SIZE(session), gbp_page, DEFAULT_PAGE_SIZE(session));
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
     ctrl->gbp_ctrl->is_from_gbp = OG_TRUE;
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
  * process response for database read one page from GBP
  * if gbp page can be used, replace local page as gbp page
  */
 static gbp_page_status_e gbp_process_read_resp(knl_session_t *session, gbp_read_resp_t *response, buf_ctrl_t *ctrl)
 {
     uint64 gbp_page_lsn;
     uint64 curr_page_lsn;
     gbp_page_status_e page_status = GBP_PAGE_MISS;
     char *gbp_page = response->block;

     if (response->result == GBP_READ_RESULT_OK) {
         gbp_page_lsn = PAGE_GET_LSN(gbp_page);
         curr_page_lsn = PAGE_GET_LSN(ctrl->page);
#ifdef GBP_VERBOSE_TRACE
         {
             uint32 psz = DEFAULT_PAGE_SIZE(session);
             page_head_t *gh = (page_head_t *)gbp_page;
             uint16 cks = PAGE_CHECKSUM(gbp_page, psz);
            /* Avoid stale TCP/peer errors leaking from cm_get_error into INFO logs. */
             cm_reset_error();
             OG_LOG_RUN_INF(
                 "[GBP] PAGE_READ recv from GBP: page %u-%u trunc_lfn %llu gbp_lsn %llu local_lsn %llu pcn %u checksum "
                 "0x%04x | GBP-CORR fid=%u pn=%u seq=%llu lfn=%llu inst=0",
                 ctrl->page_id.file, ctrl->page_id.page, (uint64)response->gbp_trunc_point.lfn, gbp_page_lsn,
                 curr_page_lsn, gh->pcn, (uint32)cks, ctrl->page_id.file, ctrl->page_id.page, gbp_page_lsn,
                 (uint64)response->gbp_trunc_point.lfn);
         }
#endif
         page_status = gbp_page_verify(session, response->pageid, gbp_page_lsn, curr_page_lsn);
         if (gbp_page_lsn > curr_page_lsn && (page_status == GBP_PAGE_HIT || page_status == GBP_PAGE_USABLE)) {
             gbp_replace_local_page(session, ctrl, (page_head_t *)gbp_page, NULL);
             ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
         }
     }

     if (response->result == GBP_READ_RESULT_ERROR) {
         gbp_page[GBP_MSG_LEN] = '\0'; // Write at most 64 byte of page head to run log
         page_status = GBP_PAGE_ERROR;
         OG_LOG_RUN_WAR("[GBP] failed to read page(%u, %u) from GBP, error: %s",
                        ctrl->page_id.file, ctrl->page_id.page, gbp_page);
     }

     return page_status;
 }

 /*
  * some gbp page can not be repalced as local page, inlcude
  * 1. gbp page is not in standby redo, mostly this gbp page too old and page lfn < standby rcy point
  * 2. gbp page has been verifyed, mostly means that has been relapced as local page
  * 3. space or datafile is not online
  * 4. page is nologging page, except space head page
  */
static bool32 gbp_need_skip(knl_session_t *session, gbp_page_item_t *page_item)
{
     datafile_t *df = NULL;
     space_t *space = NULL;
     gbp_analyse_item_t *item = NULL;

     item = gbp_aly_get_page_item(session, page_item->page_id);
     /* no redo log for the page, page can be discard */
     if (item == NULL) {
         return OG_TRUE;
     }
     knl_panic_log(item->lsn != OG_INVALID_LSN, "lsn is NULL.");
     if (item->is_verified == OG_TRUE && !gbp_is_multi_node_rcy(session)) {
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

static uint64 gbp_get_local_verify_lsn(knl_session_t *session, page_id_t page_id)
{
    buf_ctrl_t *ctrl = NULL;
    uint64 local_lsn = 0;
    uint8 saved_queue_index = session->gbp_queue_index;

    /*
     * gbp_knl_end_read() holds buf_read_lock[] while verifying. Entering the page must not trigger
     * buf_check_page_version()->PAGE_READ, otherwise this session can self-deadlock on the same read lock.
     */
    session->gbp_queue_index = 1;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    session->gbp_queue_index = saved_queue_index;

    ctrl = session->curr_page_ctrl;
    if (ctrl != NULL && ctrl->page->lsn == OG_INVALID_LSN) {
        ctrl->gbp_ctrl->is_from_gbp = OG_FALSE;
        if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[GBP] verify failed to load local page %u-%u from disk", page_id.file, page_id.page);
        }
    }
    if (ctrl != NULL && ctrl->page->lsn != OG_INVALID_LSN) {
        local_lsn = ctrl->page->lsn;
    }
    buf_leave_page(session, OG_FALSE);
    return local_lsn;
}

static uint64 gbp_get_partial_verify_lsn(knl_session_t *session, gbp_partial_item_t *item, uint64 expect_lsn)
{
    buf_ctrl_t *ctrl = NULL;
    uint64 local_lsn = 0;
    uint8 saved_queue_index = session->gbp_queue_index;

    if (item == NULL || expect_lsn == 0) {
        return 0;
    }

    session->gbp_queue_index = 1;
    buf_enter_page(session, item->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    session->gbp_queue_index = saved_queue_index;

    ctrl = session->curr_page_ctrl;
    if (ctrl != NULL && ctrl->page->lsn == OG_INVALID_LSN) {
        ctrl->gbp_ctrl->is_from_gbp = OG_FALSE;
        if (buf_load_page_from_disk(session, ctrl, item->page_id) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[GBP] partial verify failed to load local page %u-%u from disk",
                           item->page_id.file, item->page_id.page);
        }
    }

    if (ctrl != NULL && ctrl->page->lsn != OG_INVALID_LSN) {
        local_lsn = PAGE_GET_LSN(ctrl->page);
    }

    buf_leave_page(session, OG_FALSE);
    return local_lsn;
}

static void gbp_verify_partial_skiped_redo_pages(knl_session_t *session, uint32 node_count, uint64 skipped_lfn_total)
{
    uint32 scan_count = dtc_rcy_gbp_partial_required_count();
    uint32 in_window = 0;
    uint32 miss_cnt = 0;
    uint32 sample = 0;

    if (node_count == 0) {
        OG_LOG_RUN_INF("[GBP] partial verify summary: no jumped GBP nodes, skip final verification, "
                       "required_items=%u skipped_lfn_total=%llu",
                       scan_count, skipped_lfn_total);
        return;
    }

    knl_panic_log(OGRAC_PART_RECOVERY(session) && OGRAC_SESSION_IN_RECOVERY(session),
                  "[GBP] partial verify must run on partial recovery session, dtc_session_type=%u",
                  (uint32)session->dtc_session_type);

    for (uint32 i = 0; i < scan_count; i++) {
        gbp_partial_item_t *item = dtc_rcy_gbp_partial_required_item(i);
        uint32 verify_node_id = OG_INVALID_ID32;
        uint64 expect_lsn;
        uint64 local_lsn = 0;
        bool32 verified;

        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            continue;
        }
        if (!dtc_rcy_gbp_partial_item_in_jumped_window(session, item, &verify_node_id)) {
            continue;
        }

        in_window++;
        expect_lsn = dtc_rcy_gbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            miss_cnt++;
            OG_LOG_RUN_WAR("[GBP] partial verify miss: page %u-%u has zero expect_lsn, expect_lfn=%llu "
                           "enter_upper_lsn=%llu best_lsn=%llu best_source_node=%u seen_bitmap=0x%llx",
                           item->page_id.file, item->page_id.page, (uint64)item->expect_lfn,
                           (uint64)item->rcy_item->last_dirty_lsn, (uint64)item->best_lsn,
                           (uint32)item->best_source_node, (uint64)item->seen_node_bitmap);
            knl_panic_log(0, "[GBP] partial page %u-%u has zero expect_lsn", item->page_id.file, item->page_id.page);
            continue;
        }
        verified = item->verified;
        if (!verified) {
            local_lsn = gbp_get_partial_verify_lsn(session, item, expect_lsn);
            verified = (bool32)(local_lsn >= expect_lsn);
        }
        if (verified) {
            dtc_rcy_gbp_partial_mark_item_verified(item);
        } else {
            miss_cnt++;
            if (sample < 16) {
                OG_LOG_RUN_WAR("[GBP] partial verify miss sample[%u]: page %u-%u node=%u expect_lsn=%llu "
                               "expect_lfn=%llu enter_upper_lsn=%llu best_lsn=%llu best_source_node=%u "
                               "seen_bitmap=0x%llx local_lsn=%llu overflow=%u "
                               "touch0=%u:%llu-%llu touch1=%u:%llu-%llu touch2=%u:%llu-%llu touch3=%u:%llu-%llu",
                               sample, item->page_id.file, item->page_id.page, verify_node_id,
                               (uint64)expect_lsn, (uint64)item->expect_lfn,
                               (uint64)item->rcy_item->last_dirty_lsn,
                               (uint64)item->best_lsn, (uint32)item->best_source_node,
                               (uint64)item->seen_node_bitmap, (uint64)local_lsn, (uint32)item->touch_overflow,
                               (uint32)item->touches[0].node_id, (uint64)item->touches[0].touch_min_lfn,
                               (uint64)item->touches[0].touch_max_lfn,
                               (uint32)item->touches[1].node_id, (uint64)item->touches[1].touch_min_lfn,
                               (uint64)item->touches[1].touch_max_lfn,
                               (uint32)item->touches[2].node_id, (uint64)item->touches[2].touch_min_lfn,
                               (uint64)item->touches[2].touch_max_lfn,
                               (uint32)item->touches[3].node_id, (uint64)item->touches[3].touch_min_lfn,
                               (uint64)item->touches[3].touch_max_lfn);
                sample++;
            }
        }
    }

    OG_LOG_RUN_INF("[GBP] partial verify summary: skipped_lfn_total=%llu items=%u miss=%u scanned=%u",
                   skipped_lfn_total, in_window, miss_cnt, scan_count);
    knl_panic_log(miss_cnt == 0,
                  "[GBP] partial verify failed: miss_cnt=%u in_window=%u scanned=%u skipped_lfn_total=%llu",
                  miss_cnt, in_window, scan_count, skipped_lfn_total);
}

static void gbp_log_partial_ahead_detail(knl_session_t *session, gbp_partial_item_t *item, uint32 source_node,
                                         uint64 gbp_page_lsn, uint64 expect_lsn)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint64 sample;

    if (item == NULL || gbp_page_lsn <= expect_lsn) {
        return;
    }

    sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_partial_ahead_detail);
    if (sample > GBP_READ_SAMPLE_LIMIT) {
        return;
    }

    OG_LOG_RUN_WAR("[GBP] partial ahead detail sample[%llu/%u]: page %u-%u source_node=%u gbp_lsn=%llu "
                   "expect_lsn=%llu "
                   "expect_lfn=%llu enter_upper_lsn=%llu seen_bitmap=0x%llx best_lsn=%llu "
                   "best_source_node=%u overflow=%u "
                   "touch0=%u:%llu-%llu touch1=%u:%llu-%llu touch2=%u:%llu-%llu touch3=%u:%llu-%llu "
                   "redo_end_lfn=%llu gbp_aly_lsn=%llu",
                   sample, GBP_READ_SAMPLE_LIMIT, item->page_id.file, item->page_id.page, source_node,
                   (uint64)gbp_page_lsn,
                   (uint64)expect_lsn, (uint64)item->expect_lfn,
                   (uint64)(item->rcy_item == NULL ? 0 : item->rcy_item->last_dirty_lsn),
                   (uint64)item->seen_node_bitmap, (uint64)item->best_lsn, (uint32)item->best_source_node,
                   (uint32)item->touch_overflow,
                   (uint32)item->touches[0].node_id, (uint64)item->touches[0].touch_min_lfn,
                   (uint64)item->touches[0].touch_max_lfn,
                   (uint32)item->touches[1].node_id, (uint64)item->touches[1].touch_min_lfn,
                   (uint64)item->touches[1].touch_max_lfn,
                   (uint32)item->touches[2].node_id, (uint64)item->touches[2].touch_min_lfn,
                   (uint64)item->touches[2].touch_max_lfn,
                   (uint32)item->touches[3].node_id, (uint64)item->touches[3].touch_min_lfn,
                   (uint64)item->touches[3].touch_max_lfn, (uint64)redo->redo_end_point.lfn,
                   (uint64)redo->gbp_aly_lsn);
}

/*
 * Begin/end partial recovery session identity for gbp_bg only while touching DTC buffer/DCS paths.
 * Callers must always pair begin with end (including after future early returns that skip buf_leave_page).
 */
static void gbp_partial_bg_identity_begin(knl_session_t *session, dtc_session_type_e *old_type, bool32 *patched)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;

    *old_type = session->dtc_session_type;
    *patched = (bool32)(SESSION_IS_GBP_BG(session) && KNL_RECOVERY_WITH_GBP(session->kernel) &&
        gbp_is_dtc_partial_read(session) && dtc_rcy->in_progress);
    if (*patched) {
        session->dtc_session_type = dtc_rcy->paral_rcy ? DTC_PART_RCY_PARAL : DTC_PART_RCY;
    }
}

static void gbp_partial_bg_identity_end(knl_session_t *session, dtc_session_type_e old_type, bool32 patched)
{
    if (patched) {
        session->dtc_session_type = old_type;
    }
}

static void gbp_count_partial_page_status(gbp_read_apply_diag_t *diag, gbp_page_status_e page_status,
    bool32 not_newer)
{
    if (diag == NULL) {
        return;
    }

    switch (page_status) {
        case GBP_PAGE_HIT:
            diag->hit++;
            break;
        case GBP_PAGE_USABLE:
            diag->usable++;
            break;
        case GBP_PAGE_OLD:
            diag->old++;
            break;
        case GBP_PAGE_MISS:
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

typedef struct st_gbp_partial_selected_baseline_decision {
    bool32 skip;
    bool32 ahead;
    bool32 install;
    bool32 mark_selected_pulled;
    bool32 mark_verified;
    gbp_page_status_e status;
} gbp_partial_selected_baseline_decision_t;

/*
 * Partial selected baseline: gbp_lsn <= expect_lsn is a GBP baseline for skipped redo, not an OLD/USABLE
 * disk comparison. Never returns GBP_PAGE_OLD.
 */
static void gbp_partial_selected_baseline_decide(gbp_partial_item_t *item, uint64 curr_lsn, uint64 gbp_lsn,
    uint64 expect_lsn, gbp_partial_selected_baseline_decision_t *decision)
{
    errno_t ret;

    knl_panic_log(decision != NULL, "partial selected baseline decision is NULL");
    ret = memset_sp(decision, sizeof(gbp_partial_selected_baseline_decision_t), 0,
                    sizeof(gbp_partial_selected_baseline_decision_t));
    knl_securec_check(ret);
    decision->status = GBP_PAGE_MISS;

    if (item == NULL || expect_lsn == 0) {
        decision->skip = OG_TRUE;
        return;
    }

    /*
     * selected_pulled is a barrier: never re-PAGE_READ or reinstall baseline.
     * If the page body was evicted (curr INVALID), return MISS so upper layers load disk
     * (tail redo may have advanced the on-disk image beyond the old GBP baseline).
     */
    if (item->verified || item->selected_pulled) {
        decision->skip = OG_TRUE;
        if (curr_lsn == OG_INVALID_LSN) {
            decision->status = GBP_PAGE_MISS;
            return;
        }
        if (curr_lsn >= expect_lsn) {
            if (!item->verified) {
                decision->mark_verified = OG_TRUE;
            }
            decision->status = GBP_PAGE_HIT;
            return;
        }
        decision->status = GBP_PAGE_USABLE;
        return;
    }

    if (gbp_lsn > expect_lsn) {
        decision->skip = OG_TRUE;
        decision->ahead = OG_TRUE;
        decision->status = GBP_PAGE_MISS;
        return;
    }

    decision->mark_selected_pulled = OG_TRUE;

    if (curr_lsn >= expect_lsn) {
        decision->mark_verified = OG_TRUE;
        decision->status = GBP_PAGE_HIT;
        return;
    }

    if (curr_lsn != OG_INVALID_LSN && curr_lsn >= gbp_lsn) {
        decision->status = GBP_PAGE_USABLE;
        return;
    }

    if (gbp_lsn <= expect_lsn) {
        decision->install = OG_TRUE;
        if (gbp_lsn == expect_lsn) {
            decision->mark_verified = OG_TRUE;
            decision->status = GBP_PAGE_HIT;
        } else {
            decision->status = GBP_PAGE_USABLE;
        }
    }
}

static gbp_page_status_e gbp_partial_selected_baseline_apply(knl_session_t *session, buf_ctrl_t *ctrl,
    gbp_partial_item_t *item, page_head_t *gbp_page, uint64 gbp_page_lsn, uint64 expect_lsn,
    gbp_read_apply_diag_t *diag, uint32 *installed, uint32 *verified_out, bool32 *not_newer)
{
    gbp_partial_selected_baseline_decision_t decision;
    uint64 curr_page_lsn = PAGE_GET_LSN(ctrl->page);
    date_t step_begin;
    bool32 replaced = OG_FALSE;

    gbp_partial_selected_baseline_decide(item, curr_page_lsn, gbp_page_lsn, expect_lsn, &decision);
    if (not_newer != NULL) {
        *not_newer = (bool32)(curr_page_lsn != OG_INVALID_LSN && gbp_page_lsn <= curr_page_lsn);
    }

    if (decision.skip) {
        ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
        if (!decision.ahead && decision.mark_verified) {
            dtc_rcy_gbp_partial_mark_item_verified(item);
            if (verified_out != NULL) {
                (*verified_out)++;
            }
        }
        ctrl->gbp_ctrl->page_status = decision.status;
        return decision.status;
    }

    if (decision.install && gbp_page != NULL &&
        (curr_page_lsn == OG_INVALID_LSN || gbp_page_lsn > curr_page_lsn)) {
        if (diag != NULL) {
            step_begin = cm_now();
        }
        gbp_replace_local_page(session, ctrl, gbp_page, diag);
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
    ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
    ctrl->gbp_ctrl->page_status = decision.status;
    if (decision.mark_selected_pulled) {
        dtc_rcy_gbp_partial_mark_selected_pulled(item, gbp_page_lsn);
    }
    if (decision.mark_verified) {
        dtc_rcy_gbp_partial_mark_item_verified(item);
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
 * Selected direct batch install: baseline decision only (no gbp_eval, no disk fallback on INVALID).
 */
static gbp_page_status_e gbp_partial_selected_batch_install_page(knl_session_t *session, page_id_t page_id,
    gbp_page_item_t *gbp_page, gbp_partial_item_t *item, uint64 expect_lsn, uint64 gbp_page_lsn, uint32 *installed,
    uint32 *verified_out, bool32 *not_newer, gbp_read_apply_diag_t *diag)
{
    buf_ctrl_t *ctrl = NULL;
    gbp_page_status_e page_status;
    dtc_session_type_e old_type;
    bool32 patched = OG_FALSE;
    date_t step_begin;

    gbp_partial_bg_identity_begin(session, &old_type, &patched);

    if (diag != NULL) {
        step_begin = cm_now();
    }
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
    if (diag != NULL) {
        diag->enter_page_us += (uint64)(cm_now() - step_begin);
    }

    ctrl = session->curr_page_ctrl;
    page_status = gbp_partial_selected_baseline_apply(session, ctrl, item, (page_head_t *)gbp_page->block, gbp_page_lsn,
        expect_lsn, diag, installed, verified_out, not_newer);

    if (diag != NULL) {
        step_begin = cm_now();
    }
    buf_leave_page(session, OG_FALSE);
    if (diag != NULL) {
        diag->leave_page_us += (uint64)(cm_now() - step_begin);
    }

    gbp_partial_bg_identity_end(session, old_type, patched);
    return page_status;
}

/*
 * Partial BATCH_READ installs page bodies on gbp_bg sessions. Temporarily use the same
 * dtc_session_type as partial recovery workers so dtc_dcs_readable / DCS paths match recovery semantics.
 * Scope is strictly buf_enter_page .. buf_leave_page for one page.
 * installed: optional counter when a replace happened; verified_out: optional, incremented on GBP_PAGE_HIT.
 */
static gbp_page_status_e gbp_partial_batch_read_install_page(knl_session_t *session, page_id_t page_id,
    gbp_page_item_t *gbp_page, gbp_partial_item_t *item, uint64 expect_lsn, uint64 gbp_page_lsn, uint32 *installed,
    uint32 *verified_out, bool32 *not_newer, gbp_read_apply_diag_t *diag)
{
    buf_ctrl_t *ctrl = NULL;
    uint64 curr_page_lsn;
    gbp_page_status_e page_status;
    dtc_session_type_e old_type;
    bool32 patched = OG_FALSE;
    bool32 installed_from_gbp = OG_FALSE;
    date_t step_begin;

    gbp_partial_bg_identity_begin(session, &old_type, &patched);

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
    page_status = gbp_eval_page_candidate(session, page_id, gbp_page_lsn, curr_page_lsn, expect_lsn, OG_TRUE);
    if (diag != NULL) {
        diag->eval_us += (uint64)(cm_now() - step_begin);
    }
    if (not_newer != NULL) {
        *not_newer = (bool32)(curr_page_lsn != OG_INVALID_LSN && gbp_page_lsn <= curr_page_lsn);
    }
    if ((page_status == GBP_PAGE_HIT || page_status == GBP_PAGE_USABLE) && gbp_page_lsn > curr_page_lsn) {
        if (diag != NULL) {
            step_begin = cm_now();
        }
        gbp_replace_local_page(session, ctrl, (page_head_t *)gbp_page->block, diag);
        installed_from_gbp = OG_TRUE;
        if (diag != NULL) {
            diag->replace_us += (uint64)(cm_now() - step_begin);
        }
        if (installed != NULL) {
            (*installed)++;
        }
    }

    if (!installed_from_gbp && ctrl->page->lsn == OG_INVALID_LSN) {
        gbp_context_t *gbp_context = &session->kernel->gbp_context;
        uint64 sample;

        ctrl->gbp_ctrl->is_from_gbp = OG_FALSE;
        if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
            CM_ABORT(0, "[GBP] ABORT INFO: partial GBP background thread failed to load %u-%u from disk",
                     page_id.file, page_id.page);
        }
        sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_partial_disk_fallback);
        if (sample <= GBP_READ_SAMPLE_LIMIT) {
            OG_LOG_RUN_INF("[GBP] partial disk fallback sample[%llu/%u]: page=%u-%u when GBP page is not installed",
                           sample, GBP_READ_SAMPLE_LIMIT, page_id.file, page_id.page);
        }
    }

    if (diag != NULL) {
        step_begin = cm_now();
    }
    ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
    ctrl->gbp_ctrl->page_status = page_status;
    dtc_rcy_gbp_partial_mark_selected_pulled(item, gbp_page_lsn);
    if (page_status == GBP_PAGE_HIT) {
        dtc_rcy_gbp_partial_mark_item_verified(item);
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

    gbp_partial_bg_identity_end(session, old_type, patched);
    return page_status;
}

static void gbp_process_batch_read_resp_partial(knl_session_t *session, gbp_batch_read_resp_t *resp,
                                                uint32 source_node, gbp_read_apply_diag_t *diag)
{
    gbp_page_item_t *gbp_batch = resp->pages;
    gbp_page_item_t *gbp_page = NULL;
    page_id_t page_id;
    uint64 gbp_page_lsn;
    uint64 expect_lsn;
    gbp_partial_item_t *item = NULL;
    uint32 node_ids[OG_MAX_INSTANCES];
    uint32 node_count = gbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
    uint32 installed = 0;

    if (diag != NULL) {
        diag->resp_pages += resp->count;
    }

    for (uint32 i = 0; i < resp->count; i++) {
        gbp_page = &gbp_batch[i];
        item = dtc_rcy_gbp_partial_get_item(gbp_page->page_id);
        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            if (diag != NULL) {
                diag->not_required++;
            }
            continue;
        }

        expect_lsn = dtc_rcy_gbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            if (diag != NULL) {
                diag->no_expect++;
            }
            continue;
        }

        page_id = AS_PAGID(((page_head_t *)gbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(gbp_page->page_id, page_id), "gbp_page's page_id and gbp_page block's id are not "
                      "same, panic info: gbp_page %u-%u, gbp_page block %u-%u", gbp_page->page_id.file,
                      gbp_page->page_id.page, page_id.file, page_id.page);

        gbp_page_lsn = PAGE_GET_LSN(gbp_page->block);
        item->seen_node_bitmap |= ((uint64)1 << (source_node % 64));
        if (gbp_page_lsn > expect_lsn) {
            if (diag != NULL) {
                diag->ahead++;
            }
            gbp_log_partial_ahead_detail(session, item, source_node, gbp_page_lsn, expect_lsn);
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
            gbp_page_status_e page_status;
            date_t step_begin = cm_now();

            dtc_rcy_gbp_partial_update_selected(item, source_node, gbp_page_lsn);
            diag->select_update_us += (uint64)(cm_now() - step_begin);
            diag->selected++;
            page_status = gbp_partial_batch_read_install_page(session, page_id, gbp_page, item, expect_lsn,
                gbp_page_lsn, &installed, NULL, &not_newer, diag);
            gbp_count_partial_page_status(diag, page_status, not_newer);
        } else {
            dtc_rcy_gbp_partial_update_selected(item, source_node, gbp_page_lsn);
            gbp_partial_batch_read_install_page(session, page_id, gbp_page, item, expect_lsn, gbp_page_lsn,
                &installed, NULL, NULL, NULL);
        }
    }

    if (diag != NULL) {
        diag->installed += installed;
    }
}

 /* process response for background thread read page batch from GBP */
static void gbp_process_batch_read_resp(knl_session_t *session, gbp_batch_read_resp_t *resp)
{
     gbp_page_item_t *gbp_batch = resp->pages;
     gbp_page_item_t *gbp_page = NULL;
     buf_ctrl_t *ctrl = NULL;
     page_id_t page_id;
     uint64 gbp_page_lsn;
     uint64 curr_page_lsn;
    uint32 skipped_cnt = 0;
    uint32 replace_cnt = 0;
    uint32 fallback_disk_cnt = 0;
    uint32 verify_before = 0;
    uint32 verify_after = 0;

     if (resp->result == GBP_READ_RESULT_ERROR) {
         resp->msg[GBP_MSG_LEN - 1] = '\0';
         OG_LOG_RUN_WAR("[GBP] kernel batch read gbp pages error: %s", resp->msg);
         return;
     }

     for (uint32 i = 0; i < resp->count; i++) {
         gbp_page = &gbp_batch[i];
        gbp_analyse_item_t *item = gbp_aly_get_page_item(session, gbp_page->page_id);
        if (item != NULL && item->is_verified) {
            verify_before++;
        }

         if (gbp_need_skip(session, gbp_page)) {
            skipped_cnt++;
            item = gbp_aly_get_page_item(session, gbp_page->page_id);
            if (item != NULL && item->is_verified) {
                verify_after++;
            }
             continue;
         }

         page_id = AS_PAGID(((page_head_t *)gbp_page->block)->id);
         knl_panic_log(IS_SAME_PAGID(gbp_page->page_id, page_id), "gbp_page's page_id and gbp_page block's id are not "
                       "same, panic info: gbp_page %u-%u, gbp_page block %u-%u", gbp_page->page_id.file,
                       gbp_page->page_id.page, page_id.file, page_id.page);

#ifdef GBP_VERBOSE_TRACE
         {
             uint32 psz = DEFAULT_PAGE_SIZE(session);
             page_head_t *bh = (page_head_t *)gbp_page->block;
             uint16 cks = PAGE_CHECKSUM(gbp_page->block, psz);
             cm_reset_error();
             OG_LOG_RUN_INF("[GBP] BATCH_READ recv from GBP: page %u-%u item_lfn %llu gbp_lsn %llu pcn %u checksum "
                            "0x%04x writer_inst %u | GBP-CORR fid=%u pn=%u seq=%llu lfn=%llu inst=%u",
                            gbp_page->page_id.file, gbp_page->page_id.page, (uint64)gbp_page->gbp_lrp_point.lfn,
                            bh->lsn, bh->pcn, (uint32)cks, gbp_page->writer_inst_id, gbp_page->page_id.file,
                            gbp_page->page_id.page, bh->lsn, (uint64)gbp_page->gbp_lrp_point.lfn,
                            gbp_page->writer_inst_id);
         }
#endif

         /* use ENTER_PAGE_NO_READ to indicate it will not load page from local disk */
         buf_enter_page(session, gbp_page->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
         ctrl = session->curr_page_ctrl;
         gbp_page_lsn = PAGE_GET_LSN(gbp_page->block);
         curr_page_lsn = ctrl->page->lsn;

         ctrl->gbp_ctrl->page_status = gbp_page_verify(session, page_id, gbp_page_lsn, curr_page_lsn);

         if ((gbp_page_lsn > curr_page_lsn) &&
             (ctrl->gbp_ctrl->page_status == GBP_PAGE_HIT || ctrl->gbp_ctrl->page_status == GBP_PAGE_USABLE)) {
             gbp_replace_local_page(session, ctrl, (page_head_t *)gbp_page->block, NULL);
            replace_cnt++;
         } else if (curr_page_lsn == OG_INVALID_LSN) {
             /* page is not load from disk or replace by gbp page, page in buffer is invalid, need load disk page */
             ctrl->gbp_ctrl->is_from_gbp = OG_FALSE;
             if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
                 CM_ABORT(0, "[GBP] ABORT INFO: GBP background thread failed to load %u-%u", page_id.file, page_id.page);
             }
            fallback_disk_cnt++;
         }

         ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);

         if (PAGE_SIZE(*ctrl->page) == 0 && ctrl->page->lsn == 0) {
             /* extended page, must be load from disk */
             knl_panic_log(!ctrl->gbp_ctrl->is_from_gbp, "page is read from gbp, panic info: page %u-%u type %u",
                           ctrl->page_id.file, ctrl->page_id.page, ctrl->page->type);
         }

         /* treat page as loaded from disk, do not change it, do not generate redo */
         buf_leave_page(session, OG_FALSE);
        item = gbp_aly_get_page_item(session, gbp_page->page_id);
        if (item != NULL && item->is_verified) {
            verify_after++;
        }
     }
    if (fallback_disk_cnt > 0) {
        OG_LOG_RUN_INF("[GBP] BATCH_READ apply summary: resp_count=%u skipped=%u replaced=%u fallback_disk=%u "
                       "verify_before=%u verify_after=%u",
                       resp->count, skipped_cnt, replace_cnt, fallback_disk_cnt, verify_before, verify_after);
    }
}

static void gbp_process_batch_read_resp_multi(knl_session_t *session, gbp_batch_read_resp_t *resp,
                                              uint32 source_node, gbp_read_apply_diag_t *diag)
{
    gbp_page_item_t *gbp_batch = resp->pages;
    gbp_page_item_t *gbp_page = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_id_t page_id;
    uint64 gbp_page_lsn;
    uint64 curr_page_lsn;
    uint64 expect_lsn;
    gbp_page_status_e page_status;
    gbp_analyse_item_t *item = NULL;

    if (resp->result == GBP_READ_RESULT_ERROR) {
        resp->msg[GBP_MSG_LEN - 1] = '\0';
        OG_LOG_RUN_WAR("[GBP] kernel batch read gbp pages error from node %u: %s", source_node, resp->msg);
        return;
    }

    if (gbp_is_dtc_partial_read(session)) {
        gbp_process_batch_read_resp_partial(session, resp, source_node, diag);
        return;
    }

    for (uint32 i = 0; i < resp->count; i++) {
        gbp_page = &gbp_batch[i];
        item = gbp_aly_get_page_item(session, gbp_page->page_id);

        if (gbp_need_skip(session, gbp_page)) {
            continue;
        }
        if (item == NULL) {
            continue;
        }

        page_id = AS_PAGID(((page_head_t *)gbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(gbp_page->page_id, page_id), "gbp_page's page_id and gbp_page block's id are not "
                      "same, panic info: gbp_page %u-%u, gbp_page block %u-%u", gbp_page->page_id.file,
                      gbp_page->page_id.page, page_id.file, page_id.page);

        buf_enter_page(session, gbp_page->page_id, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        ctrl = session->curr_page_ctrl;
        gbp_page_lsn = PAGE_GET_LSN(gbp_page->block);
        curr_page_lsn = ctrl->page->lsn;
        expect_lsn = gbp_get_item_expect_lsn(session, item);
        page_status = gbp_eval_page_candidate(session, page_id, gbp_page_lsn, curr_page_lsn, expect_lsn, OG_TRUE);
        if (gbp_page_lsn > expect_lsn) {
            gbp_log_ahead_detail(session, page_id, source_node, gbp_page_lsn, item, expect_lsn);
        }

        if (item != NULL) {
            item->seen_node_bitmap |= ((uint64)1 << (source_node % 64));
            if ((page_status == GBP_PAGE_HIT || page_status == GBP_PAGE_USABLE) && gbp_page_lsn > item->best_lsn) {
                item->best_lsn = gbp_page_lsn;
                item->best_source_node = source_node;
                if (gbp_page_lsn > curr_page_lsn) {
                    gbp_replace_local_page(session, ctrl, (page_head_t *)gbp_page->block, NULL);
                }
                /*
                 * Multi-node recovery must see all node servers' candidates before deciding whether the page is
                 * verified. Marking verified here would make gbp_need_skip() hide later node replies for the same page.
                 */
            }
        }

        if (ctrl->page->lsn == OG_INVALID_LSN) {
            gbp_context_t *gbp_context = &session->kernel->gbp_context;
            uint64 sample;

            ctrl->gbp_ctrl->is_from_gbp = OG_FALSE;
            if (buf_load_page_from_disk(session, ctrl, page_id) != OG_SUCCESS) {
                CM_ABORT(0, "[GBP] ABORT INFO: multi GBP background thread failed to load %u-%u from disk",
                         page_id.file, page_id.page);
            }
            sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_multi_disk_fallback);
            if (sample <= GBP_READ_SAMPLE_LIMIT) {
                OG_LOG_RUN_INF("[GBP] multi disk fallback sample[%llu/%u]: page=%u-%u when GBP page is not installed",
                               sample, GBP_READ_SAMPLE_LIMIT, page_id.file, page_id.page);
            }
        }

        ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
        ctrl->gbp_ctrl->page_status = page_status;

        buf_leave_page(session, OG_FALSE);
    }
}

 /* background worker read pages from GBP, mostly running when standby failover */
static uint32 gbp_knl_read_pages(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_batch_read_req_t request;
    gbp_batch_read_resp_t *response = NULL;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    date_t begin_time = cm_now();

    if (gbp_context->dtc_use_selected_batch) {
        return gbp_knl_read_selected_pages(session);
    }

    if (gbp_is_multi_node_rcy(session)) {
        gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[gbp_proc_id];
        uint32 node_ids[OG_MAX_INSTANCES];
        uint32 node_count = gbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
        uint32 total_count = 0;
        uint32 overall_result = GBP_READ_RESULT_NOPAGE;
        log_point_t *skip_point = NULL;
        uint64 pipe_lock_us = 0;
        uint64 ensure_conn_us = 0;
        uint64 send_us = 0;
        uint64 wait_resp_us = 0;
        uint64 process_us = 0;
#if GBP_READ_HOT_DIAG
        gbp_read_apply_diag_t apply_diag = { 0 };
        gbp_read_apply_diag_t *apply_diag_ptr = &apply_diag;
#else
        gbp_read_apply_diag_t *apply_diag_ptr = NULL;
#endif
        date_t step_begin;

        /*
         * Query every jumped node's server with that node's own skip-begin point.
         * The demo/real server may evict by LRU, so the window decides which prefix can be skipped,
         * while recovery-side candidate arbitration decides which concrete page image is usable.
         */
        for (uint32 i = 0; i < node_count; i++) {
            uint32 node_id = node_ids[i];
            cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, OG_TRUE);
            if (!gbp_get_dtc_read_points(session, node_id, &skip_point, NULL, NULL)) {
                OG_LOG_RUN_WAR("[GBP] missing DTC read epoch point for node %u", node_id);
                gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return GBP_READ_RESULT_ERROR;
            }
            GBP_READ_STEP_BEGIN(step_begin);
            cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
            GBP_READ_STEP_ACCUM(step_begin, pipe_lock_us);
            GBP_READ_STEP_BEGIN(step_begin);
            if (gbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                GBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);
                gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return GBP_READ_RESULT_ERROR;
            }
            GBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);

            GBP_SET_MSG_HEADER(&request, GBP_REQ_BATCH_PAGE_READ, sizeof(gbp_batch_read_req_t), cs_get_socket_fd(pipe));
            request.gbp_skip_point = *skip_point;

            GBP_READ_STEP_BEGIN(step_begin);
            if (gbp_knl_send_request(pipe, (char *)&request, NULL) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                GBP_READ_STEP_ACCUM(step_begin, send_us);
                gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return GBP_READ_RESULT_ERROR;
            }
            GBP_READ_STEP_ACCUM(step_begin, send_us);

            response = (gbp_batch_read_resp_t *)gbp_context->batch_buf[gbp_proc_id];
            GBP_READ_STEP_BEGIN(step_begin);
            if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_batch_read_resp_t)) != OG_SUCCESS) {
                cs_disconnect(pipe);
                mgr->temp_connected_node = OG_INVALID_ID32;
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                GBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
                gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us,
                                           apply_diag_ptr);
                return GBP_READ_RESULT_ERROR;
            }
            GBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
            cm_spin_unlock(&mgr->fisrt_pipe_lock);

            if (response->result == GBP_READ_RESULT_OK && response->count > 0) {
                overall_result = GBP_READ_RESULT_OK;
                total_count += response->count;
                GBP_READ_STEP_BEGIN(step_begin);
                gbp_process_batch_read_resp_multi(session, response, node_id, apply_diag_ptr);
                GBP_READ_STEP_ACCUM(step_begin, process_us);
            }
        }

        session->stat->gbp_bg_read += total_count;
        session->stat->gbp_bg_read_time += (cm_now() - begin_time) / MICROSECS_PER_MILLISEC;
        gbp_finish_read_batch_stat(session, gbp_proc_id, overall_result, total_count, begin_time,
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
        cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, KNL_RECOVERY_WITH_GBP(session->kernel));

        /* set message header */
        GBP_SET_MSG_HEADER(&request, GBP_REQ_BATCH_PAGE_READ, sizeof(gbp_batch_read_req_t), cs_get_socket_fd(pipe));
        /* set message body */
        request.gbp_skip_point = redo_ctx->gbp_skip_point; // only read pages after gbp_skip_point

        {
            gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[gbp_proc_id];
            GBP_READ_STEP_BEGIN(step_begin);
            cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
            GBP_READ_STEP_ACCUM(step_begin, pipe_lock_us);
            GBP_READ_STEP_BEGIN(step_begin);
            if (gbp_knl_send_request(pipe, (char *)&request, mgr) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                GBP_READ_STEP_ACCUM(step_begin, send_us);
                gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, 0, send_us, wait_resp_us, process_us, NULL);
                return GBP_READ_RESULT_ERROR;
            }
            GBP_READ_STEP_ACCUM(step_begin, send_us);

            response = (gbp_batch_read_resp_t *)gbp_context->batch_buf[gbp_proc_id];
            GBP_READ_STEP_BEGIN(step_begin);
            if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_batch_read_resp_t)) != OG_SUCCESS) {
                mgr->is_connected = OG_FALSE;
                cs_disconnect(pipe);
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                GBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
                gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                           pipe_lock_us, 0, send_us, wait_resp_us, process_us, NULL);
                return GBP_READ_RESULT_ERROR;
            }
            GBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
        }

        GBP_READ_STEP_BEGIN(step_begin);
        gbp_process_batch_read_resp(session, response);
        GBP_READ_STEP_ACCUM(step_begin, process_us);
        session->stat->gbp_bg_read += response->count;
        session->stat->gbp_bg_read_time += (cm_now() - begin_time) / MICROSECS_PER_MILLISEC;
        gbp_finish_read_batch_stat(session, gbp_proc_id, response->result, response->count, begin_time,
                                   pipe_lock_us, 0, send_us, wait_resp_us, process_us, NULL);
        return response->result;
    }
}

static gbp_latch_result_t gbp_buf_latch_timed_s(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_gbp_ctrl_t *gbp_ctrl = ctrl->gbp_ctrl;
    uint32 wait_ticks = 0;

    while (gbp_ctrl == NULL) {
        if (wait_ticks >= GBP_SEND_LATCH_WAIT) {
            return GBP_LATCH_BUSY;
        }
        cm_spin_sleep();
        wait_ticks++;
        gbp_ctrl = ctrl->gbp_ctrl;
    }

    wait_ticks = 0;
    cm_spin_lock(&gbp_ctrl->init_lock, NULL);
    while (ctrl->load_status == BUF_NEED_LOAD) {
        if (wait_ticks >= GBP_SEND_LATCH_WAIT) {
            cm_spin_unlock(&gbp_ctrl->init_lock);
            return GBP_LATCH_BUSY;
        }
        cm_spin_unlock(&gbp_ctrl->init_lock);
        cm_spin_sleep();
        wait_ticks++;
        cm_spin_lock(&gbp_ctrl->init_lock, NULL);
    }

    if (!buf_latch_timed_s(session, ctrl, GBP_SEND_LATCH_TIMEOUT, OG_FALSE, OG_TRUE)) {
        cm_spin_unlock(&gbp_ctrl->init_lock);
        return GBP_LATCH_BUSY;
    }
    cm_spin_unlock(&gbp_ctrl->init_lock);
    return GBP_LATCH_OK;
}

static gbp_latch_result_t gbp_try_buf_latch_ctrl_bounded(knl_session_t *session, thread_t *thread, buf_ctrl_t *ctrl,
                                                         bool32 wait_readonly, gbp_assemble_diag_t *diag)
{
    uint64 step_begin;
    uint64 step_us;
    uint32 wait_ticks = 0;
    bool32 wait_by_readonly;
    bool32 wait_by_need_load;
    gbp_latch_result_t result;

    if (diag != NULL) {
        step_begin = g_timer()->now;
    }
    result = gbp_buf_latch_timed_s(session, ctrl);
    if (diag != NULL) {
        diag->first_latch_us += (uint64)(g_timer()->now - step_begin);
    }
    if (result != GBP_LATCH_OK) {
        return result;
    }

    /*
     * CKPT-style send: a readonly/loading/busy page must not block the queue
     * scan. Keep the item in the list and let later pages warm the GBP cache;
     * queue frontier is still pinned by this item until it is sent or reset.
     */
    while ((wait_readonly && ctrl->is_readonly) || ctrl->load_status == BUF_NEED_LOAD) {
        wait_by_readonly = (bool32)(wait_readonly && ctrl->is_readonly);
        wait_by_need_load = (bool32)(ctrl->load_status == BUF_NEED_LOAD);
        buf_unlatch(session, ctrl, OG_FALSE);
        if (wait_ticks >= GBP_SEND_LATCH_WAIT) {
            return GBP_LATCH_BUSY;
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
            return GBP_LATCH_ERROR;
        }

        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
        result = gbp_buf_latch_timed_s(session, ctrl);
        if (diag != NULL) {
            diag->retry_latch_us += (uint64)(g_timer()->now - step_begin);
            diag->retry_latch_count++;
        }
        if (result != GBP_LATCH_OK) {
            return result;
        }
    }

    return GBP_LATCH_OK;
}

static gbp_queue_item_t *gbp_remove_queue_item(knl_session_t *session, gbp_queue_t *queue,
                                               gbp_queue_item_t *prev, gbp_queue_item_t *item)
{
    gbp_queue_item_t *real_prev = NULL;
    gbp_queue_item_t *iter = NULL;
    gbp_queue_item_t *next = NULL;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
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
                  "GBP queue item is not found during remove, queue id %u", queue->id);

    next = item->next;
    if (real_prev == NULL) {
        queue->first = next;
    } else {
        real_prev->next = next;
    }
    if (queue->last == item) {
        queue->last = real_prev;
    }
    knl_panic_log(queue->count > 0, "GBP queue count is abnormal, queue id %u", queue->id);
    queue->count--;
    item->next = NULL;
    cm_spin_unlock(&queue->lock);
    return next;
}

/*
 * When GBP queue has a gap, trim dirty intervals covered by gap_end_point.
 * If the whole interval is before the reset point, remove it; otherwise advance
 * the interval begin so the queue frontier matches the reset notified to GBPS.
 */
static uint32 gbp_queue_remove_gap_pages(knl_session_t *session, thread_t *thread, gbp_queue_t *gbp_queue,
                                         log_point_t gap_end_point)
{
    gbp_queue_item_t *item = gbp_queue->first;
    gbp_queue_item_t *prev = NULL;
    gbp_queue_item_t *item_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 remove_num = 0;
    uint32 scan_num = 0;
    uint32 keep_num = 0;
    uint32 trim_num = 0;
    uint32 latch_fail_num = 0;

    while (item != NULL && !session->killed && !thread->closed) {
        scan_num++;
        if (item->source == GBP_QUEUE_ITEM_DROPPED) {
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_WAR("[GBP_ENQ_TRACE] drop queued item before PAGE_WRITE: reason=dropped_marker "
                           "queue=%u page=%u-%u gap_end_lfn=%llu scanned=%u remaining=%u",
                           gbp_queue->id, item->page_id.file, item->page_id.page,
                           (uint64)gap_end_point.lfn, scan_num, gbp_queue->count);
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
            gbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }

        if (item->source == GBP_QUEUE_ITEM_SNAPSHOT) {
            if (item->snapshot->lastest_lfn < gap_end_point.lfn) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_WAR("[GBP_ENQ_TRACE] drop snapshot before PAGE_WRITE: reason=gap_reset "
                               "queue=%u page=%u-%u gap_end_lfn=%llu item_trunc_lfn=%llu "
                               "lastest_lfn=%llu page_lsn=%llu scanned=%u remaining=%u",
                               gbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)gap_end_point.lfn, (uint64)item->snapshot->gbp_trunc_point.lfn,
                               (uint64)item->snapshot->lastest_lfn, (uint64)item->snapshot->writer_global_seq,
                               scan_num, gbp_queue->count);
#endif
                item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
                gbp_free_queue_item(session, item);
                item = item_next;
                remove_num++;
                continue;
            }
            if (LOG_LFN_LT(item->snapshot->gbp_trunc_point, gap_end_point)) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_WAR("[GBP] trim snapshot gap item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu",
                               gbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)item->snapshot->gbp_trunc_point.lfn,
                               (uint64)gap_end_point.lfn, (uint64)item->snapshot->lastest_lfn,
                               (uint64)item->snapshot->writer_global_seq);
#endif
                item->snapshot->gbp_trunc_point = gap_end_point;
                trim_num++;
            }
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        ctrl = item->ctrl;
        if (ctrl == NULL || ctrl->gbp_ctrl == NULL) {
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
            gbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }
        if (gbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_FALSE, NULL) != GBP_LATCH_OK) {
            latch_fail_num++;
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        if (ctrl->lastest_lfn < gap_end_point.lfn) {
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_WAR("[GBP_ENQ_TRACE] drop live item before PAGE_WRITE: reason=gap_reset "
                           "queue=%u page=%u-%u gap_end_lfn=%llu item_trunc_lfn=%llu lastest_lfn=%llu "
                           "page_lsn=%llu page_pcn=%u page_status=%u scanned=%u remaining=%u",
                           gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (uint64)gap_end_point.lfn,
                           (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn,
                           (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn,
                           (uint32)ctrl->gbp_ctrl->page_status, scan_num, gbp_queue->count);
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
            gbp_clear_ctrl_pending(ctrl, item, "gap_reset", 0, gap_end_point.lfn);
            buf_unlatch(session, ctrl, OG_FALSE);
            gbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
        } else {
            if (LOG_LFN_LT(ctrl->gbp_ctrl->gbp_trunc_point, gap_end_point)) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_WAR("[GBP] trim live gap item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu page_status=%u",
                               gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page,
                               (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn,
                               (uint64)gap_end_point.lfn, (uint64)ctrl->lastest_lfn,
                               (uint64)ctrl->page->lsn, (uint32)ctrl->gbp_ctrl->page_status);
#endif
                ctrl->gbp_ctrl->gbp_trunc_point = gap_end_point;
                trim_num++;
            }
            buf_unlatch(session, ctrl, OG_FALSE);
            keep_num++;
            prev = item;
            item = item->next;
        }
    }
    if (remove_num > 0 || trim_num > 0 || latch_fail_num > 0) {
        OG_LOG_RUN_WAR("[GBP] gap cleanup summary: queue=%u gap_end_lfn=%llu scanned=%u removed=%u trimmed=%u "
                       "kept=%u latch_fail=%u remaining=%u",
                       gbp_queue->id, (uint64)gap_end_point.lfn, scan_num, remove_num, trim_num, keep_num,
                       latch_fail_num, gbp_queue->count);
    }
    return remove_num;
}

typedef struct st_gbp_ckpt_cleanup_diag {
    uint32 scanned;
    uint32 removed;
    uint32 trimmed;
    uint32 kept;
    uint32 latch_fail;
} gbp_ckpt_cleanup_diag_t;

static uint32 gbp_queue_remove_ckpt_covered_pages(knl_session_t *session, thread_t *thread, gbp_queue_t *gbp_queue,
                                                  log_point_t reset_point, gbp_ckpt_cleanup_diag_t *diag)
{
    gbp_queue_item_t *item = gbp_queue->first;
    gbp_queue_item_t *prev = NULL;
    gbp_queue_item_t *item_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 remove_num = 0;
    uint32 scan_num = 0;
    uint32 keep_num = 0;
    uint32 trim_num = 0;
    uint32 latch_fail_num = 0;

    while (item != NULL && !session->killed && !thread->closed) {
        scan_num++;
        if (item->source == GBP_QUEUE_ITEM_DROPPED) {
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_WAR("[GBP_ENQ_TRACE] drop queued item before PAGE_WRITE: reason=ckpt_reset_dropped_marker "
                           "queue=%u page=%u-%u reset_lfn=%llu scanned=%u remaining=%u",
                           gbp_queue->id, item->page_id.file, item->page_id.page,
                           (uint64)reset_point.lfn, scan_num, gbp_queue->count);
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
            gbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }

        if (item->source == GBP_QUEUE_ITEM_SNAPSHOT) {
            if (item->snapshot->lastest_lfn < reset_point.lfn) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[GBP_ENQ_TRACE] drop snapshot before PAGE_WRITE: reason=ckpt_reset "
                               "queue=%u page=%u-%u reset_lfn=%llu item_trunc_lfn=%llu "
                               "lastest_lfn=%llu page_lsn=%llu scanned=%u remaining=%u",
                               gbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)reset_point.lfn, (uint64)item->snapshot->gbp_trunc_point.lfn,
                               (uint64)item->snapshot->lastest_lfn, (uint64)item->snapshot->writer_global_seq,
                               scan_num, gbp_queue->count);
#endif
                item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
                gbp_free_queue_item(session, item);
                item = item_next;
                remove_num++;
                continue;
            }
            if (LOG_LFN_LT(item->snapshot->gbp_trunc_point, reset_point)) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[GBP] trim snapshot ckpt item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu",
                               gbp_queue->id, item->snapshot->page_id.file, item->snapshot->page_id.page,
                               (uint64)item->snapshot->gbp_trunc_point.lfn,
                               (uint64)reset_point.lfn, (uint64)item->snapshot->lastest_lfn,
                               (uint64)item->snapshot->writer_global_seq);
#endif
                item->snapshot->gbp_trunc_point = reset_point;
                trim_num++;
            }
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        ctrl = item->ctrl;
        if (ctrl == NULL || ctrl->gbp_ctrl == NULL) {
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
            gbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
            continue;
        }
        if (gbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_FALSE, NULL) != GBP_LATCH_OK) {
            latch_fail_num++;
            keep_num++;
            prev = item;
            item = item->next;
            continue;
        }

        if (ctrl->lastest_lfn < reset_point.lfn) {
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_INF("[GBP_ENQ_TRACE] drop live item before PAGE_WRITE: reason=ckpt_reset "
                           "queue=%u page=%u-%u reset_lfn=%llu item_trunc_lfn=%llu lastest_lfn=%llu "
                           "page_lsn=%llu page_pcn=%u page_status=%u scanned=%u remaining=%u",
                           gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (uint64)reset_point.lfn,
                           (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn,
                           (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn,
                           (uint32)ctrl->gbp_ctrl->page_status, scan_num, gbp_queue->count);
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
            gbp_clear_ctrl_pending(ctrl, item, "ckpt_reset", reset_point.lfn, 0);
            buf_unlatch(session, ctrl, OG_FALSE);
            gbp_free_queue_item(session, item);
            item = item_next;
            remove_num++;
        } else {
            if (LOG_LFN_LT(ctrl->gbp_ctrl->gbp_trunc_point, reset_point)) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[GBP] trim live ckpt item interval: queue=%u page=%u-%u "
                               "old_trunc_lfn=%llu new_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu page_status=%u",
                               gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page,
                               (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn,
                               (uint64)reset_point.lfn, (uint64)ctrl->lastest_lfn,
                               (uint64)ctrl->page->lsn, (uint32)ctrl->gbp_ctrl->page_status);
#endif
                ctrl->gbp_ctrl->gbp_trunc_point = reset_point;
                trim_num++;
            }
            buf_unlatch(session, ctrl, OG_FALSE);
            keep_num++;
            prev = item;
            item = item->next;
        }
    }
    if (remove_num > 0 || trim_num > 0 || latch_fail_num > 0) {
        OG_LOG_RUN_INF("[GBP] ckpt reset cleanup summary: queue=%u reset_lfn=%llu scanned=%u removed=%u trimmed=%u "
                       "kept=%u latch_fail=%u remaining=%u",
                       gbp_queue->id, (uint64)reset_point.lfn, scan_num, remove_num, trim_num, keep_num,
                       latch_fail_num, gbp_queue->count);
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

static log_point_t gbp_max_log_point(log_point_t left, log_point_t right)
{
    return (log_cmp_point(&left, &right) >= 0) ? left : right;
}

static log_point_t gbp_queue_item_trunc_point(gbp_queue_item_t *item, log_point_t fallback)
{
    if (item == NULL) {
        return fallback;
    }

    if (item->source == GBP_QUEUE_ITEM_SNAPSHOT && item->snapshot != NULL) {
        return item->snapshot->gbp_trunc_point;
    }

    if (item->source == GBP_QUEUE_ITEM_LIVE && item->ctrl != NULL && item->ctrl->gbp_ctrl != NULL) {
        return item->ctrl->gbp_ctrl->gbp_trunc_point;
    }

    return fallback;
}

static log_point_t gbp_queue_get_frontier(knl_session_t *session, gbp_queue_t *gbp_queue)
{
    log_point_t frontier;

    cm_spin_lock(&gbp_queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    frontier = gbp_queue->trunc_point;
    if (gbp_queue->first != NULL) {
        frontier = gbp_queue_item_trunc_point(gbp_queue->first, frontier);
    }
    cm_spin_unlock(&gbp_queue->lock);
    return frontier;
}

/* copy 100 dirty pages to write request, record pages max lsn and max lastest lfn */
static void gbp_assemble_write_request(knl_session_t *session, thread_t *thread, gbp_write_req_t *request,
                                        gbp_queue_t *gbp_queue, uint64 *max_lsn, uint64 *max_lfn,
                                        gbp_assemble_diag_t *diag)
{
    gbp_queue_item_t *item = gbp_queue->first;
    gbp_queue_item_t *prev = NULL;
    gbp_queue_item_t *item_next = NULL;
    buf_ctrl_t *ctrl = NULL;
    gbp_page_item_t *page_item = NULL;
    uint32 pop_num = 0;
    uint32 live_num = 0;
    uint32 snapshot_num = 0;
    uint32 dropped_num = 0;
    uint32 busy_num = 0;
    uint32 scanned = 0;
#if GBP_PAGE_WRITE_HOT_DIAG
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
    gbp_latch_result_t latch_result;
    uint32 max_scan = gbp_get_assemble_max_scan(session);
    if (diag != NULL) {
        diag->max_scan = max_scan;
    }

    while (item != NULL && pop_num < GBP_BATCH_PAGE_NUM && !session->killed && !thread->closed) {
        scanned++;
        if (scanned > max_scan) {
            break;
        }
        if (diag != NULL) {
            diag->scanned = scanned;
        }
#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            item_begin = g_timer()->now;
        }
#endif
#if GBP_PAGE_WRITE_HOT_DIAG
        diag_page = item->page_id;
        diag_source = (uint32)item->source;
        diag_load_status = 0;
        diag_is_readonly = 0;
        diag_latch_stat = 0;
#endif
        if (item->source == GBP_QUEUE_ITEM_DROPPED) {
            gbp_queue->has_gap = OG_TRUE;
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_WAR("[GBP_ENQ_TRACE] drop queued item before PAGE_WRITE: reason=assemble_dropped_marker "
                           "queue=%u page=%u-%u queued_pages=%u popped=%u",
                           gbp_queue->id, item->page_id.file, item->page_id.page, gbp_queue->count, pop_num);
#endif
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->pop_us += (uint64)(g_timer()->now - step_begin);
                step_begin = g_timer()->now;
            }
#endif
            gbp_free_queue_item(session, item);
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->free_us += (uint64)(g_timer()->now - step_begin);
                item_us = (uint64)(g_timer()->now - item_begin);
                gbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            item = item_next;
            dropped_num++;
            continue;
        }

        if (item->source == GBP_QUEUE_ITEM_SNAPSHOT) {
#if GBP_PAGE_WRITE_HOT_DIAG
            diag_page = item->snapshot->page_id;
#endif
            page_item = &request->pages[pop_num];
            page_item->page_id = item->snapshot->page_id;
            page_item->session_id = 0;
            page_item->writer_inst_id = item->snapshot->writer_inst_id;
            page_item->writer_global_seq = item->snapshot->writer_global_seq;
            page_item->gbp_trunc_point = item->snapshot->gbp_trunc_point;
            page_item->gbp_lrp_point = (log_point_t){ 0 };
            page_item->gbp_lrp_point.lfn = item->snapshot->lastest_lfn;
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            ret = memcpy_sp(page_item->block, DEFAULT_PAGE_SIZE(session), item->snapshot->block,
                            DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);
            PAGE_CHECKSUM(page_item->block, DEFAULT_PAGE_SIZE(session)) = OG_INVALID_CHECKSUM;
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->copy_us += (uint64)(g_timer()->now - step_begin);
            }
#endif

            /* Batch frontier is filled after assemble from the current queue.first. */
            *max_lsn = MAX(*max_lsn, item->snapshot->writer_global_seq);
            *max_lfn = MAX(*max_lfn, item->snapshot->lastest_lfn);
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_DEBUG_INF("[GBP] PAGE_WRITE snapshot payload: queue=%u page=%u-%u lfn=%llu lsn=%llu",
                             gbp_queue->id, page_item->page_id.file, page_item->page_id.page,
                             (uint64)item->snapshot->lastest_lfn, (uint64)item->snapshot->writer_global_seq);
#endif

            pop_num++;
            snapshot_num++;
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->pop_us += (uint64)(g_timer()->now - step_begin);
                step_begin = g_timer()->now;
            }
#endif
            gbp_free_queue_item(session, item);
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->free_us += (uint64)(g_timer()->now - step_begin);
                item_us = (uint64)(g_timer()->now - item_begin);
                gbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            item = item_next;
            continue;
        }

        ctrl = item->ctrl;
        if (ctrl == NULL || ctrl->gbp_ctrl == NULL) {
            gbp_queue->has_gap = OG_TRUE;
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                step_begin = g_timer()->now;
            }
#endif
            item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->pop_us += (uint64)(g_timer()->now - step_begin);
                step_begin = g_timer()->now;
            }
#endif
            gbp_free_queue_item(session, item);
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                diag->free_us += (uint64)(g_timer()->now - step_begin);
                item_us = (uint64)(g_timer()->now - item_begin);
                gbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            item = item_next;
            dropped_num++;
            continue;
        }
#if GBP_PAGE_WRITE_HOT_DIAG
        diag_page = ctrl->page_id;
        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
        latch_result = gbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_TRUE, diag);
#else
        latch_result = gbp_try_buf_latch_ctrl_bounded(session, thread, ctrl, OG_TRUE, NULL);
#endif
#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->latch_us += (uint64)(g_timer()->now - step_begin);
        }
#endif
#if GBP_PAGE_WRITE_HOT_DIAG
        diag_load_status = (uint32)ctrl->load_status;
        diag_is_readonly = (uint32)ctrl->is_readonly;
        diag_latch_stat = (uint32)ctrl->latch.stat;
#endif
        if (latch_result == GBP_LATCH_BUSY) {
#if GBP_PAGE_WRITE_HOT_DIAG
            if (diag != NULL) {
                item_us = (uint64)(g_timer()->now - item_begin);
                gbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
                                                    diag_is_readonly, diag_latch_stat);
            }
#endif
            busy_num++;
            prev = item;
            item = item->next;
            continue;
        }
        if (latch_result != GBP_LATCH_OK) {
            gbp_queue->has_gap = OG_TRUE;
            OG_LOG_DEBUG_INF("[GBP_CTRL_TRACE] SEND_PICK_LIVE_FAIL reason=latch_failed queue=%u page=%u-%u "
                             "ctrl=%p item=%p lastest_lfn=%llu item_trunc_lfn=%llu queued_pages=%u popped=%u "
                             "gap_end_lfn=%llu",
                             gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                             (uint64)ctrl->lastest_lfn, (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn,
                             gbp_queue->count, pop_num, (uint64)session->kernel->redo_ctx.curr_point.lfn);
            OG_LOG_DEBUG_INF("[GBP] set gap while assembling PAGE_WRITE: queue=%u page=%u-%u "
                             "reason=try_buf_latch_failed queued_pages=%u popped=%u trunc_lfn=%llu lastest_lfn=%llu",
                             gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, gbp_queue->count, pop_num,
                             (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn);
            if (diag != NULL) {
#if GBP_PAGE_WRITE_HOT_DIAG
                item_us = (uint64)(g_timer()->now - item_begin);
                gbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
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
        page_item->gbp_trunc_point = ctrl->gbp_ctrl->gbp_trunc_point;
        /* Keep latest_lfn until gbp_wait_redo_visible; wire lrp is overwritten by batch_lrp_point. */
        page_item->gbp_lrp_point = (log_point_t){ 0 };
        page_item->gbp_lrp_point.lfn = ctrl->lastest_lfn;
        OG_LOG_DEBUG_INF("[GBP_CTRL_TRACE] SEND_PICK_LIVE queue=%u page=%u-%u ctrl=%p item=%p "
                         "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu queue_count=%u "
                         "popped=%u page_status=%u",
                         gbp_queue->id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                         (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                         (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, gbp_queue->count, pop_num,
                         (uint32)ctrl->gbp_ctrl->page_status);
#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
#endif
        ret = memcpy_sp(page_item->block, DEFAULT_PAGE_SIZE(session), ctrl->page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
#ifdef GBP_VERBOSE_TRACE
        {
            uint32 psz = DEFAULT_PAGE_SIZE(session);
            uint16 pre_wire_cks = PAGE_CHECKSUM(page_item->block, psz);
            cm_reset_error();
            OG_LOG_RUN_INF("[GBP] PAGE_WRITE payload (pre-wire): page %u-%u lfn %llu lsn %llu pcn %u checksum 0x%04x "
                           "inst %u | GBP-CORR fid=%u pn=%u seq=%llu lfn=%llu inst=%u",
                           ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn, (uint64)ctrl->page->lsn,
                           ctrl->page->pcn, (uint32)pre_wire_cks, (uint32)session->kernel->id, ctrl->page_id.file,
                           ctrl->page_id.page, (uint64)ctrl->page->lsn, (uint64)ctrl->lastest_lfn,
                           (uint32)session->kernel->id);
        }
#endif
        PAGE_CHECKSUM(page_item->block, DEFAULT_PAGE_SIZE(session)) = OG_INVALID_CHECKSUM; // set checksum to 0
#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->copy_us += (uint64)(g_timer()->now - step_begin);
        }
#endif
        pop_num++;

        /* Batch frontier is filled after assemble from the current queue.first. */
        *max_lsn = MAX(*max_lsn, ctrl->page->lsn);
        *max_lfn = MAX(*max_lfn, ctrl->lastest_lfn);

#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            step_begin = g_timer()->now;
        }
#endif
        item_next = gbp_remove_queue_item(session, gbp_queue, prev, item);
        gbp_clear_ctrl_pending(ctrl, item, "sent", 0, 0);
        buf_unlatch(session, ctrl, OG_FALSE);
#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->pop_us += (uint64)(g_timer()->now - step_begin);
            step_begin = g_timer()->now;
        }
#endif
        gbp_free_queue_item(session, item);
#if GBP_PAGE_WRITE_HOT_DIAG
        if (diag != NULL) {
            diag->free_us += (uint64)(g_timer()->now - step_begin);
            item_us = (uint64)(g_timer()->now - item_begin);
            gbp_assemble_diag_update_max_detail(diag, item_us, diag_page, diag_source, diag_load_status,
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
        gbp_context_t *gbp_ctx = &session->kernel->gbp_context;

        cm_spin_lock(&gbp_ctx->snapshot_lock, NULL);
        snapshot_free_count = gbp_ctx->snapshot_free_count;
        snapshot_low_watermark = gbp_ctx->snapshot_low_watermark;
        snapshot_alloc_total = gbp_ctx->snapshot_alloc_total;
        snapshot_free_total = gbp_ctx->snapshot_free_total;
        snapshot_fail_total = gbp_ctx->snapshot_alloc_fail_total;
        cm_spin_unlock(&gbp_ctx->snapshot_lock);

#ifdef GBP_VERBOSE_TRACE
        log_snapshot_summary = OG_TRUE;
#else
        log_snapshot_summary = (bool32)(dropped_num > 0 || snapshot_free_count == 0 ||
                                        snapshot_free_count < GBP_BATCH_PAGE_NUM || snapshot_fail_total > 0);
#endif
        if (log_snapshot_summary) {
            OG_LOG_RUN_INF("[GBP] PAGE_WRITE assemble snapshot summary: queue=%u live=%u snapshot=%u dropped=%u "
                           "request_pages=%u queue_remaining=%u has_gap=%u snapshot_free=%u low_watermark=%u "
                           "alloc_total=%llu free_total=%llu fail_total=%llu",
                           gbp_queue->id, live_num, snapshot_num, dropped_num, request->page_num, gbp_queue->count,
                           (uint32)gbp_queue->has_gap, snapshot_free_count, snapshot_low_watermark,
                           (uint64)snapshot_alloc_total, (uint64)snapshot_free_total, (uint64)snapshot_fail_total);
        }
    }
}

static void gbp_complete_write_lrp_points(gbp_write_req_t *request)
{
    for (uint32 i = 0; i < request->page_num; i++) {
        request->pages[i].gbp_lrp_point = request->batch_lrp_point;
    }
}

 /*
  * Visible redo / WAL lower bound before GBP PAGE_WRITE (gbp_wait_redo_visible):
  * min{local curr_point, peer flush point (if HA standby), and cluster quorum_lfn cap when applicable}.
  */
 static void gbp_log_min_flush_point(knl_session_t *session, log_point_t *min_flush_point)
 {
     log_point_t peer_max_point = { 0, 0, 0, 0 };
     uint64 quorum_lfn;

     *min_flush_point = session->kernel->redo_ctx.curr_point;  /* local flush point */

     if (DB_IS_RAFT_ENABLED(session->kernel)) {
         return; // log must flushed to peer in raft mode
     }

     /*
      * Non-DSS HA uses the minimum of local and peer flush points so GBP does not publish pages
      * that the standby cannot replay yet. With DSS, redo is shared after local log flush, and
      * peer-reported points may not describe the same shared redo progress, so keep local plus
      * the cluster quorum_lfn cap below.
      */
     if (session->kernel->lsnd_ctx.standby_num > 0 && !session->kernel->attr.enable_dss) {
         lsnd_get_max_flush_point(session, &peer_max_point, OG_FALSE);
        /*
         * Ignore an invalid peer point. Otherwise lsn-only comparisons could reduce the minimum
         * to zero and make gbp_wait_redo_visible wait forever on max_page_lfn > 0.
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
  * gbp_wait_redo_visible: wait until redo through max_page_lfn is durable enough for GBP PAGE_WRITE
 * (local flush, lsnd quorum wait, then bottleneck from peers / cluster quorum_lfn; see gbp_log_min_flush_point).
  */
 status_t gbp_wait_redo_visible(knl_session_t *session, thread_t *thread, uint64 max_page_lsn, uint64 max_page_lfn,
                                log_point_t *gbp_lrp_point)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     log_point_t curr_point = { 0, 0, 0, 0 };
     log_point_t min_flush_point;
     uint64 quorum_out = 0;

     /* make sure log is flushed to local disk(primary DN disk) */
     if (max_page_lfn > redo_ctx->flushed_lfn && !gbp_context->log_flushing) {
         gbp_context->log_flushing = OG_TRUE;
         if (log_flush(session, &curr_point, NULL, NULL) != OG_SUCCESS) {
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

         gbp_context->log_flushing = OG_FALSE;
     }

     /* make sure log is flushed to at least one peer(standby DN) */
     gbp_log_min_flush_point(session, &min_flush_point);
     while (max_page_lfn > min_flush_point.lfn && !session->killed && !thread->closed) {
         cm_sleep(10);
         OG_LOG_DEBUG_INF("[GBP] wait log flushed before write page to GBP. "
                          "max_page_lfn[%llu], min_flush_lfn[%llu], max_page_lsn[%llu]",
                          max_page_lfn, (uint64)min_flush_point.lfn, max_page_lsn);
         gbp_log_min_flush_point(session, &min_flush_point);
     }
     *gbp_lrp_point = min_flush_point;
     return OG_SUCCESS;
 }

 /* if has gap, remove pages and just update begin_point, lrp_point */
 static void gbp_knl_reset_queue(knl_session_t *session, thread_t *thread, gbp_write_req_t *request, gbp_queue_t *gbp_queue)
 {
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     uint32 throw_num = request->page_num;
     log_point_t frontier_point;

     while (gbp_queue->has_gap) {
         gbp_queue->has_gap = OG_FALSE;
         throw_num += gbp_queue_remove_gap_pages(session, thread, gbp_queue, redo_ctx->curr_point);
     }

     request->page_num = 0;
     request->page_num_tail = 0;

     /* we read curr_point without lock */
     request->batch_begin_point = redo_ctx->curr_point;
     request->batch_lrp_point = request->batch_begin_point;
     frontier_point = gbp_queue_get_frontier(session, gbp_queue);
     request->batch_trunc_point = gbp_max_log_point(request->batch_begin_point, frontier_point);
    OG_LOG_RUN_WAR("[GBP] queue id %u, throw %u gap pages and send PAGE_WRITE reset: "
                   "reset_point=[%u-%u/%u/%llu/%llu] frontier=[%u-%u/%u/%llu/%llu] remaining_queue_pages=%u",
                   gbp_queue->id, throw_num, request->batch_begin_point.rst_id, request->batch_begin_point.asn,
                   request->batch_begin_point.block_id, (uint64)request->batch_begin_point.lfn,
                   (uint64)request->batch_begin_point.lsn, request->batch_trunc_point.rst_id,
                   request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                   (uint64)request->batch_trunc_point.lfn, (uint64)request->batch_trunc_point.lsn,
                   gbp_queue->count);
}

static bool32 gbp_take_ckpt_reset(gbp_queue_t *gbp_queue, log_point_t *reset_point)
{
    if (!gbp_queue->has_ckpt_reset) {
        return OG_FALSE;
    }

    cm_spin_lock(&gbp_queue->lock, NULL);
    if (!gbp_queue->has_ckpt_reset) {
        cm_spin_unlock(&gbp_queue->lock);
        return OG_FALSE;
    }

    *reset_point = gbp_queue->ckpt_reset_point;
    gbp_queue->has_ckpt_reset = OG_FALSE;
    cm_spin_unlock(&gbp_queue->lock);
    return OG_TRUE;
}

static void gbp_prepare_ckpt_reset_request(knl_session_t *session, gbp_write_req_t *request, gbp_queue_t *gbp_queue,
                                           log_point_t *reset_point)
{
    log_point_t frontier_point;

    request->page_num = 0;
    request->page_num_tail = 0;
    request->batch_begin_point = *reset_point;
    request->batch_lrp_point = *reset_point;
    frontier_point = gbp_queue_get_frontier(session, gbp_queue);
    request->batch_trunc_point = gbp_max_log_point(*reset_point, frontier_point);
    OG_LOG_RUN_INF("[GBP] queue id %u send PAGE_WRITE reset: reset_point=[%u-%u/%u/%llu/%llu] "
                   "frontier=[%u-%u/%u/%llu/%llu]",
                   gbp_queue->id, reset_point->rst_id, reset_point->asn, reset_point->block_id,
                   (uint64)reset_point->lfn, (uint64)reset_point->lsn, request->batch_trunc_point.rst_id,
                   request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                   (uint64)request->batch_trunc_point.lfn, (uint64)request->batch_trunc_point.lsn);
}

static void gbp_init_page_write_request(gbp_write_req_t *request, cs_pipe_t *pipe)
{
    log_point_t init_point = { 0, 0, 0, 0 };

    request->page_num = 0;
    request->page_num_tail = 0;
    request->batch_trunc_point = init_point;
    request->batch_begin_point = init_point;
    request->batch_lrp_point = init_point;
    GBP_SET_MSG_HEADER(request, GBP_REQ_PAGE_WRITE, sizeof(gbp_write_req_t), cs_get_socket_fd(pipe));
}

static status_t gbp_send_page_write_request(cs_pipe_t *pipe, gbp_buf_manager_t *gbp_mgr, gbp_write_req_t *request,
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
    cm_spin_lock(&gbp_mgr->fisrt_pipe_lock, NULL);
    if (measure_timing) {
        lock_us = (uint64)(g_timer()->now - lock_begin);
        stream_begin = g_timer()->now;
    }
    if (gbp_knl_send_request(pipe, (char *)request, gbp_mgr) != OG_SUCCESS) {
        cm_spin_unlock(&gbp_mgr->fisrt_pipe_lock);
        return OG_ERROR;
    }
    if (measure_timing) {
        stream_us = (uint64)(g_timer()->now - stream_begin);
    }
    cm_reset_error();
    cm_spin_unlock(&gbp_mgr->fisrt_pipe_lock);

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

static date_t gbp_ckpt_purge_interval_us(knl_session_t *session)
{
    uint64 ckpt_timeout = (uint64)session->kernel->attr.ckpt_timeout;

    if (ckpt_timeout == 0) {
        ckpt_timeout = 1;
    }
    return (date_t)(ckpt_timeout * GBP_CKPT_PURGE_INTERVAL_FACTOR * MICROSECS_PER_SECOND);
}

static status_t gbp_send_ckpt_purge_if_due(knl_session_t *session, thread_t *thread, gbp_write_req_t *request,
                                           gbp_queue_t *gbp_queue, gbp_buf_manager_t *gbp_mgr, cs_pipe_t *pipe)
{
    date_t now = g_timer()->now;
    date_t interval_us = gbp_ckpt_purge_interval_us(session);
    log_point_t latest_point = dtc_my_ctrl(session)->rcy_point;
    log_point_t last_sent_point = gbp_queue->last_sent_ckpt_purge_point;
    gbp_ckpt_cleanup_diag_t cleanup_diag = { 0 };
    date_t cleanup_begin;
    uint64 cleanup_us;
    uint32 covered_pages;
    uint64 send_us = 0;

    if (gbp_queue->last_ckpt_purge_check_time != 0 &&
        now - gbp_queue->last_ckpt_purge_check_time < interval_us) {
        return OG_SUCCESS;
    }
    gbp_queue->last_ckpt_purge_check_time = now;

    if (gbp_queue->has_gap) {
        OG_LOG_RUN_INF("[GBP] skip periodic ckpt purge: queue=%u reason=gap latest_lfn=%llu "
                       "last_sent_lfn=%llu interval_us=%lld remaining=%u",
                       gbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                       (long long)interval_us, gbp_queue->count);
        return OG_SUCCESS;
    }

    if (log_point_is_invalid(&latest_point)) {
        OG_LOG_RUN_INF("[GBP] skip periodic ckpt purge: queue=%u reason=invalid latest_lfn=%llu "
                       "last_sent_lfn=%llu interval_us=%lld remaining=%u",
                       gbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                       (long long)interval_us, gbp_queue->count);
        return OG_SUCCESS;
    }

    if (log_cmp_point(&latest_point, &last_sent_point) <= 0) {
        OG_LOG_RUN_INF("[GBP] skip periodic ckpt purge: queue=%u reason=not_advanced latest_lfn=%llu "
                       "last_sent_lfn=%llu interval_us=%lld remaining=%u",
                       gbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                       (long long)interval_us, gbp_queue->count);
        return OG_SUCCESS;
    }

    cleanup_begin = g_timer()->now;
    covered_pages = gbp_queue_remove_ckpt_covered_pages(session, thread, gbp_queue, latest_point, &cleanup_diag);
    cleanup_us = (uint64)(g_timer()->now - cleanup_begin);
    gbp_init_page_write_request(request, pipe);
    gbp_prepare_ckpt_reset_request(session, request, gbp_queue, &latest_point);
    if (gbp_send_page_write_request(pipe, gbp_mgr, request, &send_us, NULL, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }

    gbp_queue->last_sent_ckpt_purge_point = latest_point;
    OG_LOG_RUN_INF("[GBP] send periodic ckpt purge: queue=%u latest_lfn=%llu last_sent_lfn=%llu "
                   "interval_us=%lld covered=%u remaining=%u cleanup_us=%llu scanned=%u removed=%u "
                   "trimmed=%u kept=%u latch_fail=%u send_us=%llu",
                   gbp_queue->id, (uint64)latest_point.lfn, (uint64)last_sent_point.lfn,
                   (long long)interval_us, covered_pages, gbp_queue->count, cleanup_us, cleanup_diag.scanned,
                   cleanup_diag.removed, cleanup_diag.trimmed, cleanup_diag.kept, cleanup_diag.latch_fail, send_us);
    return OG_SUCCESS;
}

/* background write pages to GBP */
static status_t gbp_knl_write_to_gbp(knl_session_t *session, thread_t *thread)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     uint32 gbp_proc_id = session->gbp_queue_index - 1;
     gbp_write_req_t *request = (gbp_write_req_t *)gbp_context->batch_buf[gbp_proc_id];
     gbp_queue_t *gbp_queue = &gbp_context->queue[gbp_proc_id];
     gbp_buf_manager_t *gbp_mgr = &gbp_context->gbp_buf_manager[gbp_proc_id];
     cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, OG_FALSE);
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
    gbp_assemble_diag_t assemble_diag;
    gbp_assemble_diag_t *assemble_diag_ptr = &assemble_diag;
    errno_t memset_ret;

     knl_panic(SESSION_IS_GBP_BG(session));
     if (gbp_should_suspend_page_write(session)) {
         return OG_SUCCESS;
     }
     if (DB_IS_CLUSTER(session) && gbp_mgr->connected_id != (uint32)session->kernel->id) {
         OG_LOG_RUN_WAR("[GBP] refuse PAGE_WRITE to nonlocal GBP server: queue=%u inst=%u connected_node=%u",
                        gbp_proc_id, (uint32)session->kernel->id, gbp_mgr->connected_id);
         cm_spin_lock(&gbp_mgr->fisrt_pipe_lock, NULL);
         gbp_mgr->is_connected = OG_FALSE;
         cs_disconnect(pipe);
         cm_spin_unlock(&gbp_mgr->fisrt_pipe_lock);
         return OG_ERROR;
     }

     for (;;) {
         if (session->killed || thread->closed) {
             return OG_ERROR;
         }
         if (gbp_should_suspend_page_write(session)) {
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
        queue_count_before = gbp_queue->count;
        queue_count_after_assemble = queue_count_before;
        enqueue_delta = 0;
        has_gap_before = gbp_queue->has_gap;
        took_ckpt_reset = OG_FALSE;
        took_gap_reset = OG_FALSE;
        memset_ret = memset_sp(&assemble_diag, sizeof(gbp_assemble_diag_t), 0, sizeof(gbp_assemble_diag_t));
        knl_securec_check(memset_ret);

         gbp_init_page_write_request(request, pipe);
         max_page_lsn = OG_INVALID_LSN;
         max_page_lfn = OG_INVALID_LSN;

         if (gbp_queue->count > 0) {
             /* set msg body */
            step_begin = g_timer()->now;
             gbp_assemble_write_request(session, thread, request, gbp_queue, &max_page_lsn, &max_page_lfn,
                                        assemble_diag_ptr);
            assemble_us = (uint64)(g_timer()->now - step_begin);
            queue_count_after_assemble = gbp_queue->count;
            enqueue_delta = (int64)queue_count_after_assemble + (int64)request->page_num -
                            (int64)queue_count_before;
#if GBP_PAGE_WRITE_HOT_DIAG
            if ((assemble_us >= GBP_PAGE_WRITE_ASSEMBLE_DIAG_US ||
                assemble_diag.max_item_us >= GBP_PAGE_WRITE_ITEM_DIAG_US) &&
                gbp_rate_loggable(&g_gbp_assemble_diag_last_log[gbp_proc_id % OG_GBP_SESSION_COUNT],
                                  g_timer()->now, GBP_ASSEMBLE_DIAG_INTERVAL_US)) {
                OG_LOG_RUN_INF("[GBP] PAGE_WRITE assemble diag: queue=%u before=%u after_assemble=%u "
                                 "pages=%u enqueue_delta=%lld scanned=%u scan_limit=%u live=%u snapshot=%u "
                                 "dropped=%u busy=%u "
                                 "latch_us=%llu first_latch_us=%llu retry_latch_us=%llu retry_latch_count=%u "
                                 "readonly_wait_us=%llu readonly_wait_count=%u need_load_wait_us=%llu "
                                 "need_load_wait_count=%u copy_us=%llu pop_us=%llu free_us=%llu max_item_us=%llu "
                                 "max_item_page=%u-%u max_item_source=%u load_status=%u is_readonly=%u "
                                 "latch_stat=%u",
                                 gbp_proc_id, queue_count_before, queue_count_after_assemble, request->page_num,
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
                OG_LOG_RUN_INF("[GBP] PAGE_WRITE assemble empty batch: queue=%u before=%u after_assemble=%u "
                                 "busy=%u dropped=%u snapshot=%u live=%u assemble_us=%llu latch_us=%llu "
                                 "has_gap=%u",
                                 gbp_proc_id, queue_count_before, queue_count_after_assemble,
                                 assemble_diag.busy_num, assemble_diag.dropped_num, assemble_diag.snapshot_num,
                                 assemble_diag.live_num, assemble_us, assemble_diag.latch_us,
                                 (uint32)gbp_queue->has_gap);
            }
#endif

             if (request->page_num > 0) {
                request->batch_trunc_point = gbp_queue_get_frontier(session, gbp_queue);
                step_begin = g_timer()->now;
                 if (gbp_wait_redo_visible(session, thread, max_page_lsn, max_page_lfn, &request->batch_lrp_point) !=
                     OG_SUCCESS) {
                     return OG_ERROR;
                 }
                 wait_redo_us = (uint64)(g_timer()->now - step_begin);
                 gbp_complete_write_lrp_points(request);
             }
         } else if (gbp_take_ckpt_reset(gbp_queue, &ckpt_reset_point)) {
            took_ckpt_reset = OG_TRUE;
             covered_pages = gbp_queue_remove_ckpt_covered_pages(session, thread, gbp_queue, ckpt_reset_point, NULL);
             gbp_prepare_ckpt_reset_request(session, request, gbp_queue, &ckpt_reset_point);
             if (covered_pages > 0) {
                 OG_LOG_RUN_INF("[GBP] queue id %u drop %u local queued pages covered by reset lfn=%llu",
                                gbp_queue->id, covered_pages, (uint64)ckpt_reset_point.lfn);
             }
         } else {
             if (gbp_send_ckpt_purge_if_due(session, thread, request, gbp_queue, gbp_mgr, pipe) != OG_SUCCESS) {
                 return OG_ERROR;
             }
             cm_spin_sleep();
             break;
         }

         if (gbp_queue->has_gap) {
            took_gap_reset = OG_TRUE;
             step_begin = g_timer()->now;
             gbp_knl_reset_queue(session, thread, request, gbp_queue);
             gap_reset_us = (uint64)(g_timer()->now - step_begin);
         }

#ifdef GBP_VERBOSE_TRACE
         if (request->page_num > 0) {
             OG_LOG_RUN_INF("[GBP] PAGE_WRITE frontier-lrp semantics: pages=%u "
                            "frontier=[%u-%u/%u/%llu/%llu] batch_lrp=[%u-%u/%u/%llu/%llu] "
                            "first_page_lrp_lfn=%llu first_page_lsn=%llu max_latest_lfn=%llu",
                            request->page_num, (uint32)request->batch_trunc_point.rst_id,
                            request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                            (uint64)request->batch_trunc_point.lfn, request->batch_trunc_point.lsn,
                            (uint32)request->batch_lrp_point.rst_id, request->batch_lrp_point.asn,
                            request->batch_lrp_point.block_id, (uint64)request->batch_lrp_point.lfn,
                            request->batch_lrp_point.lsn, (uint64)request->pages[0].gbp_lrp_point.lfn,
                            (uint64)request->pages[0].writer_global_seq, max_page_lfn);
         }
#endif

         if (session->killed || thread->closed) {
             return OG_ERROR;
         }

         if (request->page_num == 0 && log_point_is_invalid(&request->batch_lrp_point)) {
#if GBP_PAGE_WRITE_HOT_DIAG
             if (queue_count_before > 0 || queue_count_after_assemble > 0) {
                 OG_LOG_RUN_INF("[GBP] PAGE_WRITE skip send (no pages in batch): queue=%u before=%u "
                                  "after_assemble=%u after=%u busy=%u dropped=%u ckpt_reset=%u gap_reset=%u "
                                  "assemble_us=%llu",
                                  gbp_proc_id, queue_count_before, queue_count_after_assemble,
                                  gbp_queue->count, assemble_diag.busy_num, assemble_diag.dropped_num,
                                  (uint32)took_ckpt_reset, (uint32)took_gap_reset, assemble_us);
             }
#else
             if (gbp_page_write_diag_loggable(gbp_proc_id, took_gap_reset, took_ckpt_reset, queue_count_before,
                                               gbp_queue->count, assemble_us, wait_redo_us, send_us)) {
                 OG_LOG_RUN_INF("[GBP] PAGE_WRITE empty batch: queue=%u before=%u after_assemble=%u after=%u "
                                "pages=%u enqueue_delta=%lld scanned=%u "
                                "scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u ckpt_reset=%u "
                                "gap_reset=%u gap_before=%u gap_after=%u assemble_us=%llu connected=%u",
                                gbp_proc_id, queue_count_before, queue_count_after_assemble, gbp_queue->count,
                                request->page_num, (long long)enqueue_delta, assemble_diag.scanned,
                                assemble_diag.max_scan, assemble_diag.live_num, assemble_diag.snapshot_num,
                                assemble_diag.dropped_num, assemble_diag.busy_num, (uint32)took_ckpt_reset,
                                (uint32)took_gap_reset, (uint32)has_gap_before, (uint32)gbp_queue->has_gap, assemble_us,
                                (uint32)gbp_mgr->is_connected);
             }
#endif
             break;
         }

        if (gbp_send_page_write_request(pipe, gbp_mgr, request, &send_us, &send_lock_us, &send_stream_us) !=
            OG_SUCCESS) {
            return OG_ERROR;
        }

#if GBP_PAGE_WRITE_HOT_DIAG
        if (request->page_num > 0) {
            OG_LOG_RUN_INF("[GBP] PAGE_WRITE sent to remote GBP: queue=%u pages=%u "
                             "frontier=[%u-%u/%u/%llu/%llu] first_page_lrp_lfn=%llu first_page_lsn=%llu "
                             "batch_lrp=[%u-%u/%u/%llu/%llu] max_latest_lfn=%llu "
                             "(wire checksum cleared per page)",
                             gbp_proc_id, request->page_num, (uint32)request->batch_trunc_point.rst_id,
                             request->batch_trunc_point.asn, request->batch_trunc_point.block_id,
                             (uint64)request->batch_trunc_point.lfn, request->batch_trunc_point.lsn,
                             (uint64)request->pages[0].gbp_lrp_point.lfn,
                             (uint64)request->pages[0].writer_global_seq,
                             (uint32)request->batch_lrp_point.rst_id, request->batch_lrp_point.asn,
                             request->batch_lrp_point.block_id, (uint64)request->batch_lrp_point.lfn,
                             request->batch_lrp_point.lsn, max_page_lfn);
        } else {
            OG_LOG_RUN_INF("[GBP] PAGE_WRITE sent to remote GBP: queue=%u pages=%u "
                             "begin=[%u-%u/%u/%llu/%llu] frontier=[%u-%u/%u/%llu/%llu] "
                             "batch_lrp=[%u-%u/%u/%llu/%llu] (wire checksum cleared per page)",
                             gbp_proc_id, request->page_num, request->batch_begin_point.rst_id,
                             request->batch_begin_point.asn, request->batch_begin_point.block_id,
                             (uint64)request->batch_begin_point.lfn, request->batch_begin_point.lsn,
                             request->batch_trunc_point.rst_id, request->batch_trunc_point.asn,
                             request->batch_trunc_point.block_id, (uint64)request->batch_trunc_point.lfn,
                             request->batch_trunc_point.lsn, request->batch_lrp_point.rst_id,
                             request->batch_lrp_point.asn, request->batch_lrp_point.block_id,
                             (uint64)request->batch_lrp_point.lfn, request->batch_lrp_point.lsn);
        }
#endif

         session->stat->gbp_page_write_time += (g_timer()->now - begin_time) / MICROSECS_PER_MILLISEC;
         session->stat->gbp_page_write += request->page_num;

        queue_count_after = gbp_queue->count;
        total_us = (uint64)(g_timer()->now - iter_begin);
#if GBP_PAGE_WRITE_HOT_DIAG
        if (gbp_page_write_diag_loggable(gbp_proc_id, took_gap_reset, took_ckpt_reset, queue_count_before,
                                         queue_count_after, assemble_us, wait_redo_us, send_us)) {
            OG_LOG_RUN_INF("[GBP] PAGE_WRITE queue diag: queue=%u before=%u after_assemble=%u after=%u "
                             "pages=%u ckpt_reset=%u covered=%u gap_reset=%u gap_before=%u gap_after=%u "
                             "scanned=%u scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u "
                             "max_lfn=%llu max_lsn=%llu assemble_us=%llu wait_redo_us=%llu send_us=%llu "
                             "send_lock_us=%llu send_stream_us=%llu wire_bytes=%u gap_reset_us=%llu "
                             "assemble_copy_us=%llu assemble_latch_us=%llu assemble_busy=%u "
                             "total_us=%llu connected=%u dtc_read_active=%u",
                             gbp_proc_id, queue_count_before, queue_count_after_assemble, queue_count_after,
                             request->page_num, (uint32)took_ckpt_reset, covered_pages, (uint32)took_gap_reset,
                             (uint32)has_gap_before, (uint32)gbp_queue->has_gap, assemble_diag.scanned,
                             assemble_diag.max_scan, assemble_diag.live_num, assemble_diag.snapshot_num,
                             assemble_diag.dropped_num, assemble_diag.busy_num, max_page_lfn, max_page_lsn,
                             assemble_us, wait_redo_us, send_us, send_lock_us, send_stream_us,
                             (uint32)request->header.msg_length, gap_reset_us, assemble_diag.copy_us,
                             assemble_diag.latch_us, assemble_diag.busy_num, total_us,
                             (uint32)gbp_mgr->is_connected, (uint32)gbp_context->dtc_read_active);
        }
#else
        if (total_us >= GBP_PAGE_WRITE_ASSEMBLE_DIAG_US) {
            OG_LOG_RUN_WAR("[GBP] PAGE_WRITE slow batch: queue=%u before=%u after_assemble=%u after=%u "
                           "pages=%u enqueue_delta=%lld ckpt_reset=%u covered=%u gap_reset=%u gap_before=%u "
                           "gap_after=%u scanned=%u scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u "
                           "max_lfn=%llu max_lsn=%llu assemble_us=%llu wait_redo_us=%llu send_us=%llu "
                           "send_lock_us=%llu send_stream_us=%llu wire_bytes=%u gap_reset_us=%llu total_us=%llu "
                           "connected=%u dtc_read_active=%u",
                           gbp_proc_id, queue_count_before, queue_count_after_assemble, queue_count_after,
                           request->page_num, (long long)enqueue_delta, (uint32)took_ckpt_reset, covered_pages,
                           (uint32)took_gap_reset, (uint32)has_gap_before, (uint32)gbp_queue->has_gap,
                           assemble_diag.scanned, assemble_diag.max_scan, assemble_diag.live_num,
                           assemble_diag.snapshot_num, assemble_diag.dropped_num, assemble_diag.busy_num,
                           max_page_lfn, max_page_lsn, assemble_us, wait_redo_us, send_us, send_lock_us,
                           send_stream_us, (uint32)request->header.msg_length, gap_reset_us, total_us,
                           (uint32)gbp_mgr->is_connected, (uint32)gbp_context->dtc_read_active);
        } else if (gbp_page_write_diag_loggable(gbp_proc_id, took_gap_reset, took_ckpt_reset, queue_count_before,
                                                queue_count_after, assemble_us, wait_redo_us, send_us)) {
            OG_LOG_RUN_INF("[GBP] PAGE_WRITE queue diag: queue=%u before=%u after_assemble=%u after=%u "
                           "pages=%u enqueue_delta=%lld ckpt_reset=%u covered=%u gap_reset=%u gap_before=%u "
                           "gap_after=%u scanned=%u scan_limit=%u live=%u snapshot=%u dropped=%u busy=%u "
                           "max_lfn=%llu max_lsn=%llu assemble_us=%llu wait_redo_us=%llu send_us=%llu "
                           "send_lock_us=%llu send_stream_us=%llu wire_bytes=%u gap_reset_us=%llu total_us=%llu "
                           "connected=%u dtc_read_active=%u",
                           gbp_proc_id, queue_count_before, queue_count_after_assemble, queue_count_after,
                           request->page_num, (long long)enqueue_delta, (uint32)took_ckpt_reset, covered_pages,
                           (uint32)took_gap_reset, (uint32)has_gap_before, (uint32)gbp_queue->has_gap,
                           assemble_diag.scanned, assemble_diag.max_scan, assemble_diag.live_num,
                           assemble_diag.snapshot_num, assemble_diag.dropped_num, assemble_diag.busy_num,
                           max_page_lfn, max_page_lsn, assemble_us, wait_redo_us, send_us, send_lock_us,
                           send_stream_us, (uint32)request->header.msg_length, gap_reset_us, total_us,
                           (uint32)gbp_mgr->is_connected, (uint32)gbp_context->dtc_read_active);
        }
#endif
        if (request->page_num > 0 &&
            gbp_send_ckpt_purge_if_due(session, thread, request, gbp_queue, gbp_mgr, pipe) != OG_SUCCESS) {
            return OG_ERROR;
        }
     }
     return OG_SUCCESS;
 }

 /* check if pages on gbp satisfy WAL, gbp lrp point can not large than standby redo end point */
 static void gbp_page_check_wal(knl_session_t *session, gbp_read_ckpt_resp_t *resp)
 {
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     log_point_t redo_end_point = redo_ctx->redo_end_point;

     /* if end_point < gbp_lrp_point, it does not satisfy WAL */
     if (LOG_LFN_LT(redo_end_point, resp->lrp_point) || redo_ctx->gbp_aly_lsn < resp->max_lsn) {
         gbp_set_unsafe(session, RD_TYPE_END);

         OG_LOG_RUN_WAR("[GBP] gbp unsafe, redo end_point[%u-%u-%llu] less than gbp_lrp_point[%u-%u-%llu]"
                        "or redo max lsn[%llu] less than gbp page max lsn[%llu]",
                        redo_end_point.rst_id, redo_end_point.asn, (uint64)redo_end_point.lfn,
                        resp->lrp_point.rst_id, resp->lrp_point.asn, (uint64)resp->lrp_point.lfn,
                        redo_ctx->gbp_aly_lsn, resp->max_lsn);
     }
 }

static void gbp_process_read_ckpt_resp(knl_session_t *session, gbp_read_ckpt_resp_t *resp, log_context_t *redo_ctx)
{
    // gbp_begin_point: lower bound of the server-side GBP window, raised by reset/gap barriers and cache holes.
    // If we use GBP pages to replace local pages, current replay point must already be inside this window.
    redo_ctx->gbp_begin_point = resp->begin_point;
    // gbp_rcy_point: min server queue_frontier. This mirrors CKPT rcy_point = queue.first->trunc_point.
    // After pulling GBP pages, recovery can resume redo from this point if the node point is within (begin, rcy].
    redo_ctx->gbp_rcy_point = resp->rcy_point;
    // gbp_lrp_point: max active cache coverage_lrp, at least rcy_point; WAL check requires redo to cover it.
    redo_ctx->gbp_lrp_point = resp->lrp_point;
    if (resp->gbp_unsafe) {
        gbp_set_unsafe(session, RD_TYPE_END);
        OG_LOG_RUN_WAR("[GBP] gbp unsafe reason: %s", resp->unsafe_reason);
    }

    OG_LOG_RUN_INF("[GBP] gbp_begin_point[%u-%u-%llu], gbp_lrp_point[%u-%u-%llu], format: [rst_id-asn-lfn]",
                   resp->begin_point.rst_id, resp->begin_point.asn, (uint64)resp->begin_point.lfn,
                   resp->lrp_point.rst_id, resp->lrp_point.asn, (uint64)resp->lrp_point.lfn);
    if (resp->begin_point.lfn == 0 && resp->rcy_point.lfn == 0) {
        OG_LOG_RUN_WAR("[GBP] READ_CKPT window empty: begin/rcy lfn both 0 - GBP has no usable checkpoint window "
                       "(server cold, no PAGE_WRITE yet, or demo/mismatch); redo replay still proceeds.");
    }

    gbp_page_check_wal(session, resp);
 }

 /* crash recovery or failover, read page from gbp */
static void gbp_try_pull_page_batch(knl_session_t *session, uint32 *last_result)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    uint32 result = *last_result;

    knl_panic(SESSION_IS_GBP_BG(session));
    /* last read status is GBP_READ_RESULT_OK, it means some gbp pages are not read, need continue read from GBP */
    if (result == GBP_READ_RESULT_OK) {
        result = gbp_knl_read_pages(session);
    }

     if (result == GBP_READ_RESULT_ERROR) {
         CM_ABORT(0, "[GBP] ABORT INFO: instance must exit beacause failed to read pages from GBP");
     }

     /* no pages can read from GBP for current gbp_bg_proc, means all GBP pages in queue[gbp_proc_id] have been read */
     if (result == GBP_READ_RESULT_NOPAGE) {
         if (gbp_context->gbp_buf_manager[gbp_proc_id].gbp_reading) {
             atomic_t remaining;
             date_t done_time = cm_now();

             gbp_context->gbp_buf_manager[gbp_proc_id].gbp_reading = OG_FALSE;
             remaining = cm_atomic_dec(&gbp_context->gbp_read_thread_num);
             if (remaining == 0) {
                 gbp_context->gbp_read_workers_done_time = done_time;
                 if ((gbp_context->dtc_read_active || gbp_context->dtc_read_node_count > 0) &&
                     !gbp_context->dtc_read_workers_done) {
                     gbp_context->dtc_read_workers_done = OG_TRUE;
                     OG_LOG_RUN_INF("[GBP] DTC read workers completed; wait recovery owner for final verify and "
                                    "READ_END: worker_active_ms=%llu",
                                    (uint64)((done_time - gbp_context->gbp_begin_read_time) /
                                             MICROSECS_PER_MILLISEC));
                 }
             }
         }

        if (gbp_context->gbp_read_thread_num == 0 && // all gbp_bg_proc read completed
            gbp_proc_id == 0 && // gbp_knl_end_read need only be called once, so just let gbp_bg_proc 0 call it
            DB_IS_OPEN(session) &&
            gbp_db_enforce_primary_style_invariants(session)) { /* cluster compute / classic primary after failover */
            if (gbp_context->dtc_read_active || gbp_context->dtc_read_node_count > 0) {
                gbp_context->dtc_read_workers_done = OG_TRUE;
            } else {
                gbp_knl_end_read(session);
            }
        }
         cm_sleep(1);
     }

     *last_result = result;
 }

 status_t gbp_alloc_bg_session(uint8 queue_index, knl_session_t **session)
 {
     if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)session) != OG_SUCCESS) {
         return OG_ERROR;
     }
     (*session)->gbp_queue_index = queue_index; // for gbp bg session, gbp_queue_index > 0
     return OG_SUCCESS;
 }

 void gbp_release_bg_session(knl_session_t *session)
 {
     session->gbp_queue_index = 0;
     g_knl_callback.release_knl_session(session);
 }

 /*
  * gbp_bg loop after connecting to the peer GBP:
  * 1. Writers send queued dirty page batches to the peer GBP and heartbeat periodically.
  * 2. Non-writers only refresh the window and do heartbeat/pull-page work.
  */
 static void gbp_bg_proc(thread_t *thread)
 {
     knl_session_t *session = (knl_session_t *)thread->argument;
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     gbp_buf_manager_t *gbp_buf_manager = gbp_context->gbp_buf_manager;
     uint32 gbp_proc_id = session->gbp_queue_index - 1;
     uint32 pull_result = GBP_READ_RESULT_OK;

     cm_set_thread_name("gbp_bg");
     OG_LOG_RUN_INF("[GBP] gbp_bg_%u thread started", gbp_proc_id);
     knl_panic(SESSION_IS_GBP_BG(session));

     /* first start, treat it has gap, so that gbp begin point refresh as redo->curr_point */
     gbp_context->queue[gbp_proc_id].id = gbp_proc_id;
     gbp_context->queue[gbp_proc_id].has_gap = OG_TRUE;
     gbp_context->queue[gbp_proc_id].has_ckpt_reset = OG_FALSE;
     gbp_context->queue[gbp_proc_id].ckpt_reset_point = (log_point_t){ 0 };
     gbp_context->queue[gbp_proc_id].last_sent_ckpt_purge_point = (log_point_t){ 0 };
     gbp_context->queue[gbp_proc_id].last_ckpt_purge_check_time = g_timer()->now;
     gbp_buf_manager[gbp_proc_id].gbp_reading = OG_FALSE;
     gbp_buf_manager[gbp_proc_id].last_hb_time = g_timer()->now;

     /* loop forever when USE_GBP is TRUE */
     while (!thread->closed) {
         if (!gbp_buf_manager[gbp_proc_id].is_connected) {
             cm_sleep(100);
             continue;
         }

         /* only works during recover from GBP */
         if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
             gbp_try_pull_page_batch(session, &pull_result);
             continue;
         }
         pull_result = GBP_READ_RESULT_OK; /* reset pull page result after recover end */

         if (!DB_IS_OPEN(session)) {
             cm_sleep(10);
             continue;
         }

         if (gbp_should_suspend_page_write(session)) {
             gbp_timed_heart_beat(session);
             cm_sleep(10);
             continue;
         }

         if (gbp_instance_may_write_to_remote(session)) {
             if (gbp_knl_write_to_gbp(session, thread) != OG_SUCCESS) {
                 /* write page to gbp failed, set has gap, the GBP pages will be cleared */
                gbp_context->queue[gbp_proc_id].has_gap = OG_TRUE;
                OG_LOG_RUN_WAR("[GBP] set gap after PAGE_WRITE failure: queue=%u connected=%u queued_pages=%u",
                               gbp_proc_id, (uint32)gbp_buf_manager[gbp_proc_id].is_connected,
                               gbp_context->queue[gbp_proc_id].count);
            }
        } else {
            /* No remote PAGE_WRITE permission, so do not push local dirty pages to GBP. */
            if (!gbp_context->queue[gbp_proc_id].has_gap) {
                OG_LOG_RUN_WAR("[GBP] set gap because instance cannot write to remote GBP: queue=%u "
                               "cluster=%u replay_node=%u queued_pages=%u",
                               gbp_proc_id, (uint32)DB_IS_CLUSTER(session), (uint32)OGRAC_REPLAY_NODE(session),
                               gbp_context->queue[gbp_proc_id].count);
            }
            gbp_context->queue[gbp_proc_id].has_gap = OG_TRUE;
            gbp_refresh_gbp_window(session, gbp_proc_id);
             cm_sleep(200);
         }

         gbp_timed_heart_beat(session); /* both primary and standby send heart beat to GBP */
     }
     OG_LOG_RUN_INF("[GBP] gbp_bg_%u thread stopped", gbp_proc_id);
     gbp_release_bg_session(session);
     KNL_SESSION_CLEAR_THREADID(session);
 }

static void gbp_init_connect_pipe(gbp_buf_manager_t *gbp_buf_manager)
{
    gbp_buf_manager->is_connected = OG_FALSE;
    gbp_buf_manager->temp_connected_node = OG_INVALID_ID32;
    gbp_buf_manager->selected_temp_connected_node = OG_INVALID_ID32;
    gbp_buf_manager->pipe_const.link.tcp.sock = CS_INVALID_SOCKET;
     gbp_buf_manager->pipe_const.link.tcp.closed = OG_TRUE;
     gbp_buf_manager->pipe_temp.link.tcp.sock = CS_INVALID_SOCKET;
     gbp_buf_manager->pipe_temp.link.tcp.closed = OG_TRUE;
     gbp_buf_manager->pipe_selected_temp.link.tcp.sock = CS_INVALID_SOCKET;
     gbp_buf_manager->pipe_selected_temp.link.tcp.closed = OG_TRUE;

     gbp_buf_manager->pipe_const.link.rdma.sock = CS_INVALID_SOCKET;
     gbp_buf_manager->pipe_const.link.rdma.closed = OG_TRUE;
     gbp_buf_manager->pipe_temp.link.rdma.sock = CS_INVALID_SOCKET;
     gbp_buf_manager->pipe_temp.link.rdma.closed = OG_TRUE;
     gbp_buf_manager->pipe_selected_temp.link.rdma.sock = CS_INVALID_SOCKET;
     gbp_buf_manager->pipe_selected_temp.link.rdma.closed = OG_TRUE;
}

 /* start kernel's background workers in kernel */
 status_t gbp_agent_start_client(knl_session_t *session)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     gbp_buf_manager_t *gbp_buf_manager = gbp_context->gbp_buf_manager;
     knl_session_t **gbp_bg_sessions = gbp_context->gbp_bg_sessions;
     uint32 id;
     uint32 buf_size = MAX(GBP_MAX_REQ_BUF_SIZE, GBP_MAX_RESP_BUF_SIZE);

     for (id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         gbp_init_connect_pipe(&gbp_buf_manager[id]);
         gbp_buf_manager[id].queue_id = id;
         gbp_bg_sessions[id] = NULL;
         gbp_context->batch_buf[id] = gbp_context->pipe_buf.aligned_buf + id * buf_size;
     }

     /* start gbp background threads */
     for (id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         if (gbp_alloc_bg_session(id + 1, &gbp_bg_sessions[id]) != OG_SUCCESS) {
             OG_LOG_RUN_ERR("[GBP] failed to alloc gbp background session for index %u", id);
             return OG_ERROR;
         }

         if (cm_create_thread(gbp_bg_proc, 0, gbp_bg_sessions[id], &gbp_buf_manager[id].thread) != OG_SUCCESS) {
             OG_LOG_RUN_ERR("[GBP] failed to create background thread for index %u", id);
             gbp_release_bg_session(gbp_bg_sessions[id]); // other sessions are closed when gbp_bg_proc closed
             return OG_ERROR;
         }
     }

     return OG_SUCCESS;
 }

 void gbp_agent_stop_client(knl_session_t *session)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     knl_session_t **gbp_bg_sessions = gbp_context->gbp_bg_sessions;

     /* stop gbp bg proc threads */
     for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         gbp_bg_sessions[id]->killed = OG_TRUE;
        cm_close_thread(&gbp_context->gbp_buf_manager[id].thread);
        cs_disconnect(&gbp_context->gbp_buf_manager[id].pipe_const);
        cs_disconnect(&gbp_context->gbp_buf_manager[id].pipe_temp);
        cs_disconnect(&gbp_context->gbp_buf_manager[id].pipe_selected_temp);
        gbp_context->gbp_buf_manager[id].is_connected = OG_FALSE;
        gbp_context->gbp_buf_manager[id].temp_connected_node = OG_INVALID_ID32;
        gbp_context->gbp_buf_manager[id].selected_temp_connected_node = OG_INVALID_ID32;
        gbp_context->batch_buf[id] = NULL;
        OG_LOG_RUN_INF("[GBP] gbp bg proc %u closed", id);
    }
}

static status_t gbp_send_shake_hand(cs_pipe_t *pipe, uint32 queue_id, bool32 is_temp, bool32 is_standby)
{
    gbp_shake_hand_req_t req;
    gbp_shake_hand_resp_t resp;
    int32 recv_size;
    errno_t err;

    err = memset_sp(&resp, sizeof(resp), 0, sizeof(resp));
    knl_securec_check(err);

     req.header.msg_type = GBP_REQ_SHAKE_HAND;

     req.is_standby = is_standby;
     req.is_temp = is_temp;
     req.queue_id = queue_id;

     if (cs_write_stream(pipe, (char *)&req, sizeof(req), 0) != OG_SUCCESS) {
         return OG_ERROR;
     }
     if (cs_read_stream(pipe, (char *)&resp, OG_MAX_WAIT_TIME, sizeof(resp), &recv_size) != OG_SUCCESS) {
         return OG_ERROR;
     }

    if (recv_size != sizeof(resp) ||
        GBP_MSG_TYPE(&resp.header) != GBP_REQ_SHAKE_HAND ||
        req.queue_id != resp.queue_id) {
        OG_LOG_RUN_ERR("[GBP] invalid shake hand response, fd %d type %u receive size %u expect size %u req_qid %u "
                       "resp_qid %u temp %u standby %u",
                       cs_get_socket_fd(pipe), GBP_MSG_TYPE(&resp.header), recv_size, (uint32)sizeof(resp),
                       req.queue_id, resp.queue_id, (uint32)is_temp, (uint32)is_standby);
        return OG_ERROR;
    }

     return OG_SUCCESS;
 }

static status_t gbp_init_pipe_connection(knl_session_t *session, gbp_buf_manager_t *gbp_buf_manager, cs_pipe_t *pipe,
                                         const char *host, uint16 port, bool32 is_temp)
 {
     char url[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE + OG_TCP_PORT_MAX_LENGTH] = { 0 };
    uint32 queue_id = gbp_buf_manager->queue_id;
    /* Nodes that may PAGE_WRITE shake as non-standby; pull/heartbeat-only nodes shake as standby. */
    bool32 is_standby = gbp_instance_may_write_to_remote(session) ? OG_FALSE : OG_TRUE;
     errno_t ret;

     ret = memset_sp(pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
     knl_securec_check(ret);
     ret = snprintf_s(url, sizeof(url), sizeof(url) - 1, "%s:%u", host, port);
     if (ret >= sizeof(url) || ret == -1) {
         OG_LOG_RUN_ERR("[GBP] Url %s is truncated", url);
         return OG_ERROR;
     }

     pipe->connect_timeout = GBP_CONNEOG_TIMEOUT;
     if (cs_connect((const char *)url, pipe, NULL, NULL, NULL) != OG_SUCCESS) {
         OG_LOG_DEBUG_ERR("[GBP] failed to connect %s", url);
         return OG_ERROR;
     }

     if (gbp_send_shake_hand(pipe, queue_id, is_temp, is_standby) != OG_SUCCESS) {
         OG_LOG_RUN_ERR("[GBP] failed to send shake hand to %s", url);
         cs_disconnect(pipe);
         return OG_ERROR;
     }

     cm_reset_error();
     OG_LOG_RUN_INF("[GBP] connected to %s, queue id %u, is temp %d", url, queue_id, is_temp);
     return OG_SUCCESS;
 }

static status_t gbp_init_connection(knl_session_t *session, gbp_buf_manager_t *gbp_buf_manager, const char *host,
                                    uint16 port, bool32 is_temp)
{
    cs_pipe_t *pipe = (is_temp) ? &gbp_buf_manager->pipe_temp : &gbp_buf_manager->pipe_const;

    return gbp_init_pipe_connection(session, gbp_buf_manager, pipe, host, port, is_temp);
}

static status_t gbp_build_server_host(knl_session_t *session, const char *ip_addr, char *host, uint32 buf_size)
{
    gbp_attr_t *gbp_attr = &session->kernel->gbp_attr;
    errno_t ret;

    if (ip_addr == NULL || ip_addr[0] == '\0') {
        return OG_ERROR;
    }

    if (cm_str_equal_ins(gbp_attr->trans_type, "rdma")) {
        ret = snprintf_s(host, buf_size, buf_size - 1, RDMA_HOST_PREFIX "%s", ip_addr);
    } else {
        ret = snprintf_s(host, buf_size, buf_size - 1, "%s", ip_addr);
    }
    knl_securec_check_ss(ret);
    return OG_SUCCESS;
}

/*
 * Constant write/heartbeat path:
 * always route by configured GBP_IP/server_addr[] instead of inferring a host from cluster node metadata.
 * That keeps routing explicit so a GBPS can later move to peer/VIP/HA proxy without changing kernel logic.
 */
static status_t gbp_get_server_host(knl_session_t *session, char *host, uint32 buf_size, uint32 addr_id)
{
    gbp_attr_t *gbp_attr = &session->kernel->gbp_attr;
    const char *ip_addr = NULL;

    if (addr_id < gbp_attr->server_count && gbp_attr->server_addr[addr_id][0] != '\0') {
        ip_addr = gbp_attr->server_addr[addr_id];
    } else if (gbp_attr->server_count > 0) {
        ip_addr = gbp_attr->server_addr[addr_id % gbp_attr->server_count];
    } else {
        OG_LOG_RUN_WAR("[GBP] no configured GBP_IP target for addr slot %u", addr_id);
        return OG_ERROR;
    }

    return gbp_build_server_host(session, ip_addr, host, buf_size);
}

/*
 * Per-node recovery path:
 * server_addr[node_id] is treated as the explicit route target for that node's GBPS.
 * The configured IP may be the node itself, its peer, a VIP, or any HA endpoint.
 */
static status_t gbp_get_server_host_by_node(knl_session_t *session, uint32 node_id, char *host, uint32 buf_size)
{
    gbp_attr_t *gbp_attr = &session->kernel->gbp_attr;
    const char *ip_addr = NULL;

    if (node_id < gbp_attr->server_count && gbp_attr->server_addr[node_id][0] != '\0') {
        ip_addr = gbp_attr->server_addr[node_id];
    } else if (gbp_attr->server_count > 0) {
        ip_addr = gbp_attr->server_addr[node_id % gbp_attr->server_count];
        OG_LOG_RUN_WAR("[GBP] node %u has no dedicated GBP_IP entry, fallback to slot %u",
                       node_id, node_id % gbp_attr->server_count);
    } else {
        OG_LOG_RUN_WAR("[GBP] no configured GBP_IP target for recovery node %u", node_id);
        return OG_ERROR;
    }

    return gbp_build_server_host(session, ip_addr, host, buf_size);
}

static bool32 gbp_pipe_valid(cs_pipe_t *pipe)
{
    return (bool32)!((pipe->type == CS_TYPE_NONE) ||
                     (pipe->type == CS_TYPE_TCP && pipe->link.tcp.sock == CS_INVALID_SOCKET) ||
                     (pipe->type == CS_TYPE_RSOCKET && pipe->link.rdma.sock == CS_INVALID_SOCKET));
}

static bool32 gbp_temp_pipe_valid(gbp_buf_manager_t *manager)
{
    return gbp_pipe_valid(&manager->pipe_temp);
}

static bool32 gbp_selected_temp_pipe_valid(gbp_buf_manager_t *manager)
{
    return gbp_pipe_valid(&manager->pipe_selected_temp);
}

/*
 * pipe_temp is reused across nodes and across background/on-demand GBP readers.
 * Re-bind/reconnect must therefore be serialized by fisrt_pipe_lock together with the
 * following request/response exchange; otherwise another thread may close or reuse the same
 * socket while this thread is still handshaking or waiting for a reply.
 */
static status_t gbp_ensure_temp_connection_by_node(knl_session_t *session, gbp_buf_manager_t *manager, uint32 node_id)
{
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    uint16 port = session->kernel->gbp_attr.lsnr_port;

    if (gbp_temp_pipe_valid(manager) && manager->temp_connected_node == node_id) {
        return OG_SUCCESS;
    }

    if (gbp_temp_pipe_valid(manager)) {
        cs_disconnect(&manager->pipe_temp);
    }

    if (gbp_get_server_host_by_node(session, node_id, host, sizeof(host)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (gbp_init_connection(session, manager, host, port, OG_TRUE) != OG_SUCCESS) {
        manager->temp_connected_node = OG_INVALID_ID32;
        return OG_ERROR;
    }

    manager->temp_connected_node = node_id;
    OG_LOG_RUN_INF("[GBP] PAGE_READ temp route connected: queue=%u read_node=%u host=%s",
                   manager->queue_id, node_id, host);
    return OG_SUCCESS;
}

/*
 * Selected batch read owns a separate temp pipe. It must not share pipe_temp/fisrt_pipe_lock
 * with on-demand PAGE_READ, otherwise a large selected response blocks latency-sensitive pulls.
 */
static status_t gbp_ensure_selected_temp_connection_by_node(knl_session_t *session, gbp_buf_manager_t *manager,
                                                           uint32 node_id)
{
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    uint16 port = session->kernel->gbp_attr.lsnr_port;

    if (gbp_selected_temp_pipe_valid(manager) && manager->selected_temp_connected_node == node_id) {
        return OG_SUCCESS;
    }

    if (gbp_selected_temp_pipe_valid(manager)) {
        cs_disconnect(&manager->pipe_selected_temp);
    }

    if (gbp_get_server_host_by_node(session, node_id, host, sizeof(host)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (gbp_init_pipe_connection(session, manager, &manager->pipe_selected_temp, host, port, OG_TRUE) != OG_SUCCESS) {
        manager->selected_temp_connected_node = OG_INVALID_ID32;
        return OG_ERROR;
    }

    manager->selected_temp_connected_node = node_id;
    OG_LOG_RUN_INF("[GBP] SELECTED_READ temp route connected: queue=%u read_node=%u host=%s",
                   manager->queue_id, node_id, host);
    return OG_SUCCESS;
}

/* One-shot READ_CKPT against a specific node's GBPS. Prepare uses this to build the per-node window table. */
status_t gbp_knl_query_gbp_point_by_node(knl_session_t *session, uint32 node_id, gbp_read_ckpt_resp_t *response,
                                         bool32 check_end_point)
{
    gbp_read_ckpt_req_t request;
    gbp_buf_manager_t manager;
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };
    uint16 port = session->kernel->gbp_attr.lsnr_port;
    errno_t err;

    if (gbp_get_server_host_by_node(session, node_id, host, sizeof(host)) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[GBP] READ_CKPT node %u failed: cannot resolve GBP host", node_id);
        return OG_ERROR;
    }
    OG_LOG_RUN_WAR("[GBP] READ_CKPT node %u start: host=%s port=%u check_end=%u aly_end_lfn=%llu "
                   "aly_end_lsn=%llu",
                   node_id, host, (uint32)port, (uint32)check_end_point,
                   (uint64)session->kernel->redo_ctx.redo_end_point.lfn,
                   session->kernel->redo_ctx.redo_end_point.lsn);

    err = memset_sp(&manager, sizeof(manager), 0, sizeof(manager));
    knl_securec_check(err);
    manager.queue_id = 0;
    manager.temp_connected_node = OG_INVALID_ID32;

    if (gbp_init_connection(session, &manager, host, port, OG_TRUE) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[GBP] READ_CKPT node %u failed: connect host=%s port=%u", node_id, host, (uint32)port);
        return OG_ERROR;
    }

    GBP_SET_MSG_HEADER(&request, GBP_REQ_READ_CKPT, sizeof(gbp_read_ckpt_req_t),
                       cs_get_socket_fd(&manager.pipe_temp));
    request.check_end_point = check_end_point;
    request.aly_end_point = session->kernel->redo_ctx.redo_end_point;

    if (gbp_knl_send_request(&manager.pipe_temp, (char *)&request, NULL) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[GBP] READ_CKPT node %u failed: send request host=%s port=%u", node_id, host, (uint32)port);
        cs_disconnect(&manager.pipe_temp);
        return OG_ERROR;
    }

    if (gbp_knl_wait_response(&manager.pipe_temp, (char *)response, sizeof(gbp_read_ckpt_resp_t)) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[GBP] READ_CKPT node %u failed: wait response host=%s port=%u", node_id, host,
                       (uint32)port);
        cs_disconnect(&manager.pipe_temp);
        return OG_ERROR;
    }

    OG_LOG_RUN_WAR("[GBP] READ_CKPT node %u ok: host=%s begin_lfn=%llu rcy_lfn=%llu lrp_lfn=%llu "
                   "max_lsn=%llu unsafe=%u",
                   node_id, host, (uint64)response->begin_point.lfn, (uint64)response->rcy_point.lfn,
                   (uint64)response->lrp_point.lfn, response->max_lsn, (uint32)response->gbp_unsafe);
    cs_disconnect(&manager.pipe_temp);
    return OG_SUCCESS;
}

 bool32 gbp_promote_triggered(knl_handle_t knl_handle)
 {
     knl_instance_t *kernel = (knl_instance_t *)knl_handle;

     if (knl_failover_triggered(kernel)) {
         return OG_TRUE;
     }
     return OG_FALSE;
 }

 void gbp_reset_server_hosts(knl_instance_t *kernel)
 {
     gbp_attr_t *gbp_attr = &kernel->gbp_attr;
     errno_t ret;

     cm_spin_lock(&gbp_attr->addr_lock, NULL);
     if (!gbp_attr->server_addr_changed) {
         cm_spin_unlock(&gbp_attr->addr_lock);
         return;
     }

     for (uint32 i = 0; i < OG_MAX_LSNR_HOST_COUNT; i++) {
         ret = memcpy_sp(gbp_attr->server_addr[i], CM_MAX_IP_LEN,
                         gbp_attr->server_addr2[i], CM_MAX_IP_LEN);
         knl_securec_check(ret);
     }
     gbp_attr->server_count = gbp_attr->server_count2;
     gbp_attr->server_addr_changed = OG_FALSE;
     cm_spin_unlock(&gbp_attr->addr_lock);
 }

static status_t gbp_get_write_server_host(knl_session_t *session, char *host, uint32 buf_size, uint32 *target_id)
{
    if (DB_IS_CLUSTER(session)) {
        uint32 node_id = (uint32)session->kernel->id;
        if (target_id != NULL) {
            *target_id = node_id;
        }
        return gbp_get_server_host_by_node(session, node_id, host, buf_size);
    }

    uint32 addr_id = (target_id == NULL) ? 0 : *target_id;
    if (target_id != NULL) {
        *target_id = addr_id;
    }
    return gbp_get_server_host(session, host, buf_size, addr_id);
}

/* Maintaining the connections between gbp backupground threads and GBP */
static void gbp_agent_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    knl_instance_t *kernel = session->kernel;
    gbp_context_t *gbp_context = &kernel->gbp_context;
    gbp_buf_manager_t *managers = gbp_context->gbp_buf_manager;
    uint32 err_conn_num = 0;
    uint16 port = kernel->gbp_attr.lsnr_port;
    uint32 target_id = 0;
    char host[RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE] = { 0 };

    cm_set_thread_name("gbp_agent");
    OG_LOG_RUN_INF("[GBP] gbp_agent thread started");

    while (!thread->closed) {
         /*
          * if alter system set USE_GBP = FALSE, we just set GBP_OFF_TRIGGERED = TRUE
          * after failover running end, exit all GBP threads, then set USE_GBP = TRUE
          */
         if (KNL_GBP_OFF_TRIGGERED(kernel) && !KNL_RECOVERY_WITH_GBP(kernel) && !gbp_promote_triggered(kernel)) {
             kernel->gbp_aly_ctx.is_closing = OG_TRUE;
             thread->closed = OG_TRUE;
             break;
         }

        /* get gbp buffer manager communication channel */
        for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
            if (managers[id].is_connected) {
                continue;
            }
            gbp_reset_server_hosts(kernel);
            uint32 try_count = DB_IS_CLUSTER(session) ? 1 : MAX(kernel->gbp_attr.server_count, 1);
            uint32 start_id = DB_IS_CLUSTER(session) ? (uint32)session->kernel->id : managers[id].connected_id;
            bool32 connected = OG_FALSE;
            for (uint32 try_id = 0; try_id < try_count; try_id++) {
                target_id = DB_IS_CLUSTER(session) ? start_id : (start_id + try_id) % try_count;
                if (gbp_get_write_server_host(session, host, RDMA_HOST_PREFIX_LEN + OG_HOST_NAME_BUFFER_SIZE,
                                              &target_id) != OG_SUCCESS) {
                    break;
                }

                if (gbp_init_connection(session, &managers[id], host, port, OG_FALSE) == OG_SUCCESS) {
                    managers[id].is_connected = OG_TRUE;
                    managers[id].connected_id = target_id;
                    OG_LOG_RUN_INF("[GBP] PAGE_WRITE route connected: queue=%u inst=%u target_node=%u host=%s",
                                   id, (uint32)session->kernel->id, target_id, host);
                    err_conn_num = 0;
                    connected = OG_TRUE;
                    break;
                }

                managers[id].is_connected = OG_FALSE;
                if (err_conn_num < kernel->gbp_attr.server_count) {
                    err_conn_num++;
                    OG_LOG_RUN_ERR("[GBP] gbp connect failed, host %s", host);
                }
            }
            if (!connected) {
                if (!DB_IS_CLUSTER(session) && kernel->gbp_attr.server_count > 0) {
                    managers[id].connected_id = (start_id + 1) % kernel->gbp_attr.server_count;
                }
                break;
            }
        }
        cm_sleep(500);
    }

     gbp_agent_stop_client(session);
     gbp_drain_send_queues(session);
     gbp_snapshot_pool_free(session);
     cm_aligned_free(&gbp_context->pipe_buf);
     gbp_aly_mem_free(session);
     if (KNL_GBP_OFF_TRIGGERED(kernel)) {
         kernel->gbp_attr.use_gbp = OG_FALSE; // after exit all GBP threads, then set USE_GBP to FALSE
     }
 }

bool32 gbp_page_is_usable(knl_session_t *session, page_id_t page_id, uint64 curr_page_lsn, uint64 gbp_page_lsn,
                          uint64 expect_lsn)
{
     knl_session_t *redo_session = session->kernel->sessions[SESSION_ID_KERNEL];
     bool32 use_gbp_page = OG_FALSE;
     uint64 disk_page_lsn = OG_INVALID_LSN;
     uint64 redo_curr_lsn = redo_session->curr_lsn;

     if (curr_page_lsn != OG_INVALID_LSN) { /* page is loaded from disk */
         if (gbp_page_lsn > curr_page_lsn) {
             /* gbp page can be used if gbp_page_lsn > curr_page_lsn */
             use_gbp_page = OG_TRUE;
         }
     } else { /* page not loaded from disk */
         if (!DB_NOT_READY(session) && gbp_page_lsn > redo_curr_lsn) {
             /* before failover done, redo_curr_lsn always >= page's lsn,
              * gbp_page_lsn > page lsn, gbp page can be used. after failover done, redo_curr_lsn == lrpl_end_lsn
              * when failover done, redo_curr_lsn will not increase, gbp_page_lsn must <= redo_curr_lsn
              */
             use_gbp_page = OG_TRUE;
         } else {
             /* need compare with page disk lsn, gbp page can be used if gbp_page_lsn >= disk_page_lsn */
             disk_page_lsn = gbp_get_disk_lsn(session, page_id, OG_FALSE);
             use_gbp_page = (gbp_page_lsn >= disk_page_lsn);
         }
     }

     OG_LOG_DEBUG_WAR("[GBP] %s page:%u-%u expected LSN:%llu, gbp LSN:%llu,"
                      "redo current LSN:%llu, page current LSN:%llu, page disk LSN:%llu",
                      (use_gbp_page ? "usable" : "old"), page_id.file, page_id.page, expect_lsn, gbp_page_lsn,
                      redo_curr_lsn, curr_page_lsn, disk_page_lsn);

    return use_gbp_page;
}

/*
 * latest-only GBPS does not mean "always choose the biggest page_lsn".
 * Recovery is only allowed to consume the best candidate that is <= expect_lsn; ahead pages make GBP unsafe.
 */
static gbp_page_status_e gbp_eval_page_candidate(knl_session_t *session, page_id_t page_id, uint64 gbp_page_lsn,
                                                 uint64 curr_page_lsn, uint64 expect_lsn, bool32 log_ahead)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    if (gbp_page_lsn == expect_lsn) {
        return GBP_PAGE_HIT;
    }

    if (gbp_page_lsn < expect_lsn) {
        return gbp_page_is_usable(session, page_id, curr_page_lsn, gbp_page_lsn, expect_lsn) ?
               GBP_PAGE_USABLE : GBP_PAGE_OLD;
    }

    if (DB_IS_CLUSTER(session)) {
        if (log_ahead && !redo_ctx->gbp_aly_result.gbp_unsafe) {
            OG_LOG_RUN_WAR("[GBP] page %u-%u ahead of analyze expect (expect %llu gbp %llu); mark unsafe, skip gbp page",
                           page_id.file, page_id.page, expect_lsn, gbp_page_lsn);
        }
        gbp_set_unsafe(session, RD_TYPE_END);
        return GBP_PAGE_MISS;
    }

    knl_panic_log(0, "[GBP] ahead page:%u-%u expected LSN:%llu, gbp LSN:%llu, page current LSN:%llu",
                  page_id.file, page_id.page, expect_lsn, gbp_page_lsn, curr_page_lsn);
    return GBP_PAGE_AHEAD;
}

static void gbp_stat_page_result(knl_session_t *session, gbp_page_status_e page_status)
{
    switch (page_status) {
        case GBP_PAGE_HIT:
            session->stat->gbp_hit++;
            break;
        case GBP_PAGE_USABLE:
            session->stat->gbp_usable++;
            break;
        case GBP_PAGE_OLD:
            session->stat->gbp_old++;
            break;
        case GBP_PAGE_MISS:
            session->stat->gbp_miss++;
            break;
        default:
            break;
    }
}

static void gbp_log_ahead_detail(knl_session_t *session, page_id_t page_id, uint32 source_node, uint64 gbp_page_lsn,
                                 gbp_analyse_item_t *item, uint64 expect_lsn)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint64 sample;

    if (item == NULL || gbp_page_lsn <= expect_lsn) {
        return;
    }

    sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_ahead_detail);
    if (sample > GBP_READ_SAMPLE_LIMIT) {
        return;
    }

    OG_LOG_RUN_WAR("[GBP] ahead detail sample[%llu/%u]: page %u-%u source_node=%u gbp_lsn=%llu expect_lsn=%llu "
                   "item_node=%u "
                   "item_lfn=%llu first_node=%u first_lfn=%llu touch0=%u:%llu-%llu touch1=%u:%llu-%llu "
                   "redo_end_lfn=%llu gbp_aly_lsn=%llu",
                   sample, GBP_READ_SAMPLE_LIMIT, page_id.file, page_id.page, source_node, (uint64)gbp_page_lsn,
                   (uint64)expect_lsn,
                   (uint32)item->node_id, (uint64)item->lfn, (uint32)item->first_node_id,
                   (uint64)item->first_lfn, (uint32)GBP_ALY_TOUCH_NODE(item->touch_min[0]),
                   (uint64)GBP_ALY_TOUCH_LFN(item->touch_min[0]),
                   (uint64)GBP_ALY_TOUCH_LFN(item->touch_max[0]),
                   (uint32)GBP_ALY_TOUCH_NODE(item->touch_min[1]),
                   (uint64)GBP_ALY_TOUCH_LFN(item->touch_min[1]),
                   (uint64)GBP_ALY_TOUCH_LFN(item->touch_max[1]), (uint64)redo->redo_end_point.lfn,
                   (uint64)redo->gbp_aly_lsn);
}

gbp_page_status_e gbp_page_verify(knl_session_t *session, page_id_t page_id, uint64 gbp_page_lsn,
                                  uint64 curr_page_lsn)
{
    gbp_analyse_item_t *item = gbp_aly_get_page_item(session, page_id);
    uint64 expect_lsn;
    gbp_page_status_e page_status;

    /* page is not in aly_items, that means between gbp_skip_point and lrpl_end_point, no redo about this page */
    if (item == NULL) {
        session->stat->gbp_miss++;
        return GBP_PAGE_MISS;
     }

    if (item->is_verified == OG_TRUE) {
        session->stat->gbp_old++; // ensure that page refreshed as gbp page at most once.
        return GBP_PAGE_OLD;
    }

    expect_lsn = gbp_get_item_expect_lsn(session, item);
    knl_panic_log(expect_lsn > 0, "expect_lsn is abnormal, panic info: page %u-%u expect_lsn %llu", page_id.file,
                  page_id.page, expect_lsn);

    page_status = gbp_eval_page_candidate(session, page_id, gbp_page_lsn, curr_page_lsn, expect_lsn, OG_TRUE);
    gbp_stat_page_result(session, page_status);
    if (page_status == GBP_PAGE_HIT) {
        item->best_lsn = gbp_page_lsn;
        if (!gbp_is_multi_node_rcy(session)) {
            item->is_verified = OG_TRUE;
        }
    } else if (page_status == GBP_PAGE_USABLE) {
        /*
         * In multi-node DTC recovery another node's server may still return a newer candidate for the same page.
         * Do not let a merely usable page lock the analysis item and hide a later HIT candidate.
         */
        if (gbp_page_lsn > item->best_lsn) {
            item->best_lsn = gbp_page_lsn;
        }
        if (!gbp_is_multi_node_rcy(session)) {
            item->is_verified = OG_TRUE;
        }
    }
    return page_status;
}

 /* in recover or failover lrpl, if this page has not been pulled by gbp background thread, we pull it immediately */
static gbp_page_status_e gbp_knl_pull_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_read_req_t request;
    gbp_read_resp_t *response = NULL;
    uint32 gbp_proc_id = ctrl->page_id.page % OG_GBP_SESSION_COUNT;
    gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[gbp_proc_id];
    gbp_page_status_e page_status = GBP_PAGE_MISS;

    if (gbp_is_multi_node_rcy(session)) {
        uint32 node_ids[OG_MAX_INSTANCES];
        uint32 node_count = gbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
        bool32 partial_read = gbp_is_dtc_partial_read(session);
        gbp_analyse_item_t *item = partial_read ? NULL : gbp_aly_get_page_item(session, ctrl->page_id);
        gbp_partial_item_t *partial_item = partial_read ? dtc_rcy_gbp_partial_get_item(ctrl->page_id) : NULL;
        uint64 best_lsn = 0;
        uint64 expect_lsn = partial_read ? dtc_rcy_gbp_partial_get_expect_lsn(partial_item) :
            gbp_get_item_expect_lsn(session, item);
        uint64 expect_lfn = partial_read ? (partial_item == NULL ? 0 : partial_item->expect_lfn) :
            (item == NULL ? 0 : item->lfn);
        uint64 old_lsn = PAGE_GET_LSN(ctrl->page);
        uint32 old_pcn = ctrl->page->pcn;
        uint32 best_node = OG_INVALID_ID32;
        gbp_page_status_e best_status = GBP_PAGE_MISS;
        char *best_page_buf = NULL;
        uint32 verify_node_id = OG_INVALID_ID32;
        bool32 in_jumped_window = OG_FALSE;

        if (expect_lsn == 0 || (!partial_read && item == NULL) ||
            (partial_read && (partial_item == NULL || partial_item->rcy_item == NULL ||
                              !partial_item->rcy_item->need_replay))) {
            return GBP_PAGE_MISS;
        }

        if (partial_read) {
            in_jumped_window = dtc_rcy_gbp_partial_item_in_jumped_window(session, partial_item, &verify_node_id);
        }

        if (partial_read && partial_item->selected_valid && partial_item->selected_node != OG_INVALID_ID32) {
            node_ids[0] = partial_item->selected_node;
            node_count = 1;

            if (partial_item->selected_pulled || partial_item->verified) {
                uint64 curr_lsn = PAGE_GET_LSN(ctrl->page);

                ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
                if (curr_lsn == OG_INVALID_LSN) {
                    ctrl->gbp_ctrl->page_status = GBP_PAGE_MISS;
                    gbp_stat_page_result(session, GBP_PAGE_MISS);
                    return GBP_PAGE_MISS;
                }
                if (curr_lsn >= expect_lsn) {
                    if (!partial_item->verified) {
                        dtc_rcy_gbp_partial_mark_item_verified(partial_item);
                    }
                    ctrl->gbp_ctrl->page_status = GBP_PAGE_HIT;
                    gbp_stat_page_result(session, GBP_PAGE_HIT);
                    return GBP_PAGE_HIT;
                }
                ctrl->gbp_ctrl->page_status = GBP_PAGE_USABLE;
                gbp_stat_page_result(session, GBP_PAGE_USABLE);
                return GBP_PAGE_USABLE;
            }
        }

        CM_SAVE_STACK(session->stack);
        response = (gbp_read_resp_t *)cm_push(session->stack, sizeof(gbp_read_resp_t));
        knl_panic(response != NULL);
        best_page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
        knl_panic(best_page_buf != NULL);

        if (partial_read && !gbp_context->dtc_use_selected_batch &&
            dtc_rcy_gbp_partial_copy_candidate(session, partial_item, best_page_buf, DEFAULT_PAGE_SIZE(session),
                                               &best_lsn, &best_node)) {
            best_status = gbp_eval_page_candidate(session, ctrl->page_id, best_lsn, PAGE_GET_LSN(ctrl->page),
                                                  expect_lsn, OG_TRUE);
            if (best_status == GBP_PAGE_HIT) {
                if (best_lsn > PAGE_GET_LSN(ctrl->page)) {
                    gbp_replace_local_page(session, ctrl, (page_head_t *)best_page_buf, NULL);
                }
                dtc_rcy_gbp_partial_update_candidate(partial_item, best_node, best_lsn);
                ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
                ctrl->gbp_ctrl->page_status = best_status;
                gbp_stat_page_result(session, best_status);
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[GBP_READ_TRACE] PULL_RESULT page=%u-%u partial=%u status=%u expect_lsn=%llu "
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
            if (best_status != GBP_PAGE_USABLE) {
                best_lsn = 0;
                best_node = OG_INVALID_ID32;
                best_status = GBP_PAGE_MISS;
            }
        }

        /*
         * PAGE_READ follows the same rule as BATCH_READ: walk every jumped node server, then keep
         * max(page_lsn <= expect_lsn). This avoids taking an ahead page just because that node's server
         * flushed it later.
         */
        for (uint32 i = 0; i < node_count; i++) {
            uint32 node_id = node_ids[i];
            cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, OG_TRUE);
            cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
            if (gbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                CM_RESTORE_STACK(session->stack);
                return GBP_PAGE_ERROR;
            }

            GBP_SET_MSG_HEADER(&request, GBP_REQ_PAGE_READ, sizeof(gbp_read_req_t), cs_get_socket_fd(pipe));
            request.page_id = ctrl->page_id;
            request.buf_pool_id = ctrl->buf_pool_id;

            if (gbp_knl_send_request(pipe, (char *)&request, NULL) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                CM_RESTORE_STACK(session->stack);
                return GBP_PAGE_ERROR;
            }

            if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_read_resp_t)) != OG_SUCCESS) {
                cm_spin_unlock(&mgr->fisrt_pipe_lock);
                CM_RESTORE_STACK(session->stack);
                return GBP_PAGE_ERROR;
            }
            cm_spin_unlock(&mgr->fisrt_pipe_lock);

            if (response->result != GBP_READ_RESULT_OK) {
#ifdef GBP_VERBOSE_TRACE
                OG_LOG_RUN_INF("[GBP_READ_TRACE] PULL_CANDIDATE page=%u-%u partial=%u node=%u result=%u "
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

            if (partial_read && partial_item->selected_valid) {
                uint64 gbp_lsn = PAGE_GET_LSN(response->block);

                partial_item->seen_node_bitmap |= ((uint64)1 << (node_id % 64));
                if (gbp_lsn != partial_item->selected_lsn) {
                    uint64 sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_selected_mismatch);
                    if (sample <= GBP_READ_SAMPLE_LIMIT) {
                        OG_LOG_RUN_WAR("[GBP] selected PAGE_READ lsn mismatch sample[%llu/%u]: page=%u-%u node=%u "
                                       "selected_lsn=%llu page_lsn=%llu expect_lsn=%llu required=%u "
                                       "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u "
                                       "load_status=%u",
                                       sample, GBP_READ_SAMPLE_LIMIT, ctrl->page_id.file, ctrl->page_id.page,
                                       node_id, (uint64)partial_item->selected_lsn, (uint64)gbp_lsn,
                                       (uint64)expect_lsn, (uint32)partial_item->required,
                                       (uint32)partial_item->selected_pulled, (uint32)partial_item->verified,
                                       (uint32)in_jumped_window, verify_node_id, (uint32)ctrl->load_status);
                    }
                }
                if (gbp_lsn > expect_lsn) {
                    gbp_log_partial_ahead_detail(session, partial_item, node_id, gbp_lsn, expect_lsn);
                    CM_RESTORE_STACK(session->stack);
                    return GBP_PAGE_MISS;
                }

                page_status = gbp_partial_selected_baseline_apply(session, ctrl, partial_item,
                    (page_head_t *)response->block, gbp_lsn, expect_lsn, NULL, NULL, NULL, NULL);
                gbp_stat_page_result(session, page_status);
                CM_RESTORE_STACK(session->stack);
                return page_status;
            }

            page_status = gbp_eval_page_candidate(session, ctrl->page_id, PAGE_GET_LSN(response->block),
                                                  PAGE_GET_LSN(ctrl->page), expect_lsn, OG_TRUE);
#ifdef GBP_VERBOSE_TRACE
            OG_LOG_RUN_INF("[GBP_READ_TRACE] PULL_CANDIDATE page=%u-%u partial=%u node=%u result=%u status=%u "
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
                partial_item->seen_node_bitmap |= ((uint64)1 << (node_id % 64));
                if (partial_item->selected_valid && PAGE_GET_LSN(response->block) != partial_item->selected_lsn) {
                    uint64 sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_selected_mismatch);
                    if (sample <= GBP_READ_SAMPLE_LIMIT) {
                        OG_LOG_RUN_WAR("[GBP] selected PAGE_READ lsn mismatch sample[%llu/%u]: page=%u-%u node=%u "
                                       "selected_lsn=%llu page_lsn=%llu expect_lsn=%llu required=%u "
                                       "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u "
                                       "load_status=%u",
                                       sample, GBP_READ_SAMPLE_LIMIT, ctrl->page_id.file, ctrl->page_id.page,
                                       node_id, (uint64)partial_item->selected_lsn,
                                       (uint64)PAGE_GET_LSN(response->block), (uint64)expect_lsn,
                                       (uint32)partial_item->required, (uint32)partial_item->selected_pulled,
                                       (uint32)partial_item->verified, (uint32)in_jumped_window, verify_node_id,
                                       (uint32)ctrl->load_status);
                    }
                }
                if (PAGE_GET_LSN(response->block) > expect_lsn) {
                    gbp_log_partial_ahead_detail(session, partial_item, node_id, PAGE_GET_LSN(response->block),
                                                 expect_lsn);
                }
            } else {
                item->seen_node_bitmap |= ((uint64)1 << (node_id % 64));
                if (PAGE_GET_LSN(response->block) > expect_lsn) {
                    gbp_log_ahead_detail(session, ctrl->page_id, node_id, PAGE_GET_LSN(response->block), item,
                                         expect_lsn);
                }
            }
            if ((page_status == GBP_PAGE_HIT || page_status == GBP_PAGE_USABLE) &&
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
                gbp_replace_local_page(session, ctrl, (page_head_t *)best_page_buf, NULL);
            }
            if (partial_read) {
                dtc_rcy_gbp_partial_update_selected(partial_item, best_node, best_lsn);
                dtc_rcy_gbp_partial_mark_selected_pulled(partial_item, best_lsn);
                if (best_status == GBP_PAGE_HIT) {
                    dtc_rcy_gbp_partial_mark_item_verified(partial_item);
                }
            } else {
                item->best_lsn = best_lsn;
                item->best_source_node = best_node;
            }
            ctrl->gbp_ctrl->gbp_read_version = KNL_GBP_READ_VER(session->kernel);
            ctrl->gbp_ctrl->page_status = best_status;
            gbp_stat_page_result(session, best_status);
            page_status = best_status;
        }

        if (page_status == GBP_PAGE_MISS || page_status == GBP_PAGE_ERROR || best_lsn == 0) {
            uint64 sample = (uint64)cm_atomic_inc(&gbp_context->gbp_read_pull_miss_trace);
            if (sample <= GBP_READ_SAMPLE_LIMIT) {
                OG_LOG_RUN_INF("[GBP_READ_TRACE] PULL_RESULT sample[%llu/%u] page=%u-%u partial=%u status=%u "
                               "expect_lsn=%llu expect_lfn=%llu old_lsn=%llu old_pcn=%u returned_lsn=%llu "
                               "returned_pcn=%u read_node=%u best_lsn=%llu required=%u selected_valid=%u "
                               "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                               "load_status=%u",
                               sample, GBP_READ_SAMPLE_LIMIT, ctrl->page_id.file, ctrl->page_id.page,
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
        }
#ifdef GBP_VERBOSE_TRACE
        else {
            OG_LOG_RUN_INF("[GBP_READ_TRACE] PULL_RESULT page=%u-%u partial=%u status=%u expect_lsn=%llu "
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
        }
#endif
        CM_RESTORE_STACK(session->stack);
        return page_status;
    }

    {
        cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, OG_TRUE);
        GBP_SET_MSG_HEADER(&request, GBP_REQ_PAGE_READ, sizeof(gbp_read_req_t), cs_get_socket_fd(pipe));
        /* set message body */
        request.page_id = ctrl->page_id;
        request.buf_pool_id = ctrl->buf_pool_id;

        /* Same lock as gbp_knl_read_pages: one TCP byte stream per queue on pipe_temp; no interleave. */
        cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
        if (gbp_knl_send_request(pipe, (char *)&request, NULL) != OG_SUCCESS) {
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return GBP_PAGE_ERROR;
        }

        CM_SAVE_STACK(session->stack);
        response = (gbp_read_resp_t *)cm_push(session->stack, sizeof(gbp_read_resp_t));
        knl_panic(response != NULL);
        if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_read_resp_t)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[GBP] gbp wait response failed while send request gbp_read_req");
            CM_RESTORE_STACK(session->stack);
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return GBP_PAGE_ERROR;
        }
        cm_spin_unlock(&mgr->fisrt_pipe_lock);

        page_status = gbp_process_read_resp(session, response, ctrl);

        CM_RESTORE_STACK(session->stack);
    }
    return page_status;
}

static void gbp_stop_one_temp_pipe(gbp_buf_manager_t *manager, cs_pipe_t *pipe, spinlock_t *lock,
                                   uint32 *connected_node, const char *pipe_name)
{
    gbp_msg_hdr_t request;

    if (!gbp_pipe_valid(pipe)) {
        return;
    }

    cm_spin_lock(lock, NULL);
    if (!gbp_pipe_valid(pipe)) {
        cm_spin_unlock(lock);
        return;
    }

    GBP_SET_MSG_HEADER(&request, GBP_REQ_CLOSE_CONN, sizeof(gbp_msg_hdr_t), cs_get_socket_fd(pipe));
    request.queue_id = manager->queue_id;
    if (cs_write_stream(pipe, (char *)&request, request.msg_length, 0) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[GBP] failed to send %s close request, queue=%u fd=%d",
                       pipe_name, manager->queue_id, request.msg_fd);
    }
    cm_sleep(1);
    cs_disconnect(pipe);
    *connected_node = OG_INVALID_ID32;
    cm_spin_unlock(lock);
}

 static void gbp_stop_temp_connection(knl_session_t *session, gbp_context_t *gbp_context)
 {
     gbp_buf_manager_t *manager = NULL;

     for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         manager = &gbp_context->gbp_buf_manager[id];
        gbp_stop_one_temp_pipe(manager, &manager->pipe_temp, &manager->fisrt_pipe_lock,
                               &manager->temp_connected_node, "temp");
        gbp_stop_one_temp_pipe(manager, &manager->pipe_selected_temp, &manager->selected_pipe_lock,
                               &manager->selected_temp_connected_node, "selected temp");
    }

     OG_LOG_RUN_INF("[GBP] gbp temp connections are closed");
 }

static status_t gbp_notify_dtc_node_read_phase(knl_session_t *session, uint32 node_id, gbp_notify_msg_e msg)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[0];
    gbp_msg_ack_t ack;

    cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
    if (gbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
        cm_spin_unlock(&mgr->fisrt_pipe_lock);
        OG_LOG_RUN_WAR("[GBP] failed to connect node %u GBP for DTC read phase msg %u", node_id, (uint32)msg);
        return OG_ERROR;
    }
    if (gbp_notify_msg(session, msg, 0, &ack) != OG_SUCCESS) {
        cs_disconnect(&mgr->pipe_temp);
        mgr->temp_connected_node = OG_INVALID_ID32;
        cm_spin_unlock(&mgr->fisrt_pipe_lock);
        OG_LOG_RUN_WAR("[GBP] failed to notify node %u GBP read phase msg %u", node_id, (uint32)msg);
        return OG_ERROR;
    }
    cm_spin_unlock(&mgr->fisrt_pipe_lock);
    return OG_SUCCESS;
}

static status_t gbp_notify_dtc_read_phase(knl_session_t *session, gbp_notify_msg_e msg)
{
    uint32 node_ids[OG_MAX_INSTANCES];
    uint32 node_count = gbp_collect_active_rcy_nodes(session, node_ids, OG_MAX_INSTANCES);
    dtc_rcy_context_t *dtc_rcy = (g_dtc != NULL) ? DTC_RCY_CONTEXT : NULL;

    /*
     * Multi-node GBP keeps the v4 read-window contract: each node's server receives
     * READ_BEGIN once, snapshots page_cache into batch_pending, then BATCH_READ only drains
     * that cursor until NOPAGE. This avoids re-seeding from page_cache on every pull.
     */
    if (node_count == 0 && msg == MSG_GBP_READ_BEGIN) {
        OG_LOG_RUN_WAR("[GBP] refuse DTC partial READ_BEGIN with no active GBP nodes: in_progress=%u node_count=%u",
                       (dtc_rcy == NULL) ? 0 : (uint32)dtc_rcy->in_progress,
                       (dtc_rcy == NULL) ? 0 : dtc_rcy->node_count);
        return OG_ERROR;
    }
    for (uint32 i = 0; i < node_count; i++) {
        if (gbp_notify_dtc_node_read_phase(session, node_ids[i], msg) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static void gbp_disable_dtc_planned_nodes(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;

    if (g_dtc == NULL || !DTC_RCY_CONTEXT->in_progress) {
        return;
    }

    for (uint32 i = 0; i < gbp_context->dtc_read_node_count; i++) {
        uint32 node_id = gbp_context->dtc_read_nodes[i];
        if (node_id < OG_MAX_INSTANCES) {
            DTC_RCY_CONTEXT->gbp_read_planned[node_id] = OG_FALSE;
        }
    }
}

static status_t gbp_notify_dtc_read_begin_planned(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    dtc_rcy_context_t *dtc_rcy = (g_dtc != NULL) ? DTC_RCY_CONTEXT : NULL;
    uint32 original_count = gbp_context->dtc_read_node_count;
    uint32 kept = 0;

    OG_LOG_RUN_WAR("[GBP] notify DTC READ_BEGIN to %u planned candidate nodes", original_count);
    for (uint32 i = 0; i < original_count; i++) {
        uint32 node_id = gbp_context->dtc_read_nodes[i];
        OG_LOG_RUN_WAR("[GBP] notify DTC READ_BEGIN target[%u]=node%u", i, node_id);
        if (gbp_notify_dtc_node_read_phase(session, node_id, MSG_GBP_READ_BEGIN) != OG_SUCCESS) {
            if (dtc_rcy != NULL && node_id < OG_MAX_INSTANCES) {
                dtc_rcy->gbp_read_planned[node_id] = OG_FALSE;
            }
            OG_LOG_RUN_WAR("[GBP] DTC READ_BEGIN node %u failed, remove from planned read set", node_id);
            continue;
        }

        if (kept != i) {
            gbp_context->dtc_read_nodes[kept] = gbp_context->dtc_read_nodes[i];
            gbp_context->dtc_read_skip_points[kept] = gbp_context->dtc_read_skip_points[i];
            gbp_context->dtc_read_rcy_points[kept] = gbp_context->dtc_read_rcy_points[i];
            gbp_context->dtc_read_lrp_points[kept] = gbp_context->dtc_read_lrp_points[i];
        }
        kept++;
    }

    gbp_context->dtc_read_node_count = (uint16)kept;
    if (kept == 0) {
        OG_LOG_RUN_WAR("[GBP] DTC READ_BEGIN failed for all planned nodes");
        return OG_ERROR;
    }
    OG_LOG_RUN_WAR("[GBP] DTC READ_BEGIN success: planned_nodes=%u/%u", kept, original_count);
    return OG_SUCCESS;
}

typedef struct st_gbp_selected_pull_stat {
    uint32 selected;
    uint32 missing;
    uint32 ahead;
    uint32 requested;
    uint32 returned;
    uint32 installed;
    uint32 verified;
    uint32 mismatch;
} gbp_selected_pull_stat_t;

static void gbp_choose_dtc_selected_mode(knl_session_t *session, bool32 *use_selected_batch,
                                         bool32 *need_selected_meta, bool32 *sync_selected_pull_at_begin)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    bool32 use_selected = (bool32)(gbp_is_dtc_partial_read(session) && gbp_context->dtc_read_node_count > 0);
    bool32 need_meta = (bool32)(use_selected && gbp_context->dtc_read_node_count > 1);

    *use_selected_batch = use_selected;
    *need_selected_meta = need_meta;
    *sync_selected_pull_at_begin = need_meta;
}

static void gbp_assign_selected_workers(gbp_context_t *gbp_context, uint32 *selected_by_node)
{
    uint32 assigned[OG_MAX_INSTANCES] = { 0 };
    uint64 total = 0;

    for (uint32 i = 0; i < OG_GBP_SESSION_COUNT; i++) {
        gbp_context->dtc_selected_worker_nodes[i] = OG_INVALID_ID32;
    }

    for (uint32 i = 0; i < gbp_context->dtc_read_node_count; i++) {
        uint32 node_id = gbp_context->dtc_read_nodes[i];
        if (node_id < OG_MAX_INSTANCES) {
            total += selected_by_node[node_id];
        }
    }

    if (total == 0) {
        return;
    }

    for (uint32 worker = 0; worker < OG_GBP_SESSION_COUNT; worker++) {
        uint32 best_node = OG_INVALID_ID32;
        uint64 best_score = 0;

        for (uint32 i = 0; i < gbp_context->dtc_read_node_count; i++) {
            uint32 node_id = gbp_context->dtc_read_nodes[i];
            uint64 score;

            if (node_id >= OG_MAX_INSTANCES || selected_by_node[node_id] == 0) {
                continue;
            }
            score = ((uint64)selected_by_node[node_id] << 32) / (uint64)(assigned[node_id] + 1);
            if (best_node == OG_INVALID_ID32 || score > best_score) {
                best_node = node_id;
                best_score = score;
            }
        }

        if (best_node == OG_INVALID_ID32) {
            return;
        }
        gbp_context->dtc_selected_worker_nodes[worker] = best_node;
        assigned[best_node]++;
    }

    OG_LOG_RUN_INF("[GBP] selected worker assignment: w0=%u w1=%u w2=%u w3=%u w4=%u w5=%u w6=%u w7=%u",
                   gbp_context->dtc_selected_worker_nodes[0], gbp_context->dtc_selected_worker_nodes[1],
                   gbp_context->dtc_selected_worker_nodes[2], gbp_context->dtc_selected_worker_nodes[3],
                   gbp_context->dtc_selected_worker_nodes[4], gbp_context->dtc_selected_worker_nodes[5],
                   gbp_context->dtc_selected_worker_nodes[6], gbp_context->dtc_selected_worker_nodes[7]);
}

static void gbp_process_meta_chunk_resp(knl_session_t *session, uint32 node_id, gbp_read_meta_resp_t *resp,
                                        gbp_selected_pull_stat_t *stat)
{
    for (uint32 i = 0; i < resp->count && i < GBP_META_CHUNK_NUM; i++) {
        gbp_meta_item_t *meta = &resp->items[i];
        gbp_partial_item_t *item = dtc_rcy_gbp_partial_get_item(meta->page_id);
        uint64 expect_lsn;

        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            continue;
        }
        expect_lsn = dtc_rcy_gbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0 || meta->page_lsn == 0) {
            continue;
        }
        if (meta->page_lsn > expect_lsn) {
            stat->ahead++;
            if (stat->ahead <= 8) {
                gbp_log_partial_ahead_detail(session, item, node_id, meta->page_lsn, expect_lsn);
            }
            continue;
        }
        dtc_rcy_gbp_partial_update_selected(item, node_id, meta->page_lsn);
    }
}

static status_t gbp_pull_selected_meta_from_node(knl_session_t *session, uint32 node_id,
                                                 gbp_selected_pull_stat_t *stat)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[0];
    cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, 0, OG_TRUE);
    gbp_read_meta_req_t request;
    gbp_read_meta_resp_t *response = (gbp_read_meta_resp_t *)gbp_context->batch_buf[0];
    uint64 cursor = 0;
    uint64 epoch = 0;
    uint32 chunks = 0;
#if GBP_READ_HOT_DIAG
    date_t begin_time = cm_now();
#endif
    errno_t ret;

    for (;;) {
        ret = memset_sp(&request, sizeof(request), 0, sizeof(request));
        knl_securec_check(ret);
        request.epoch = epoch;
        request.cursor = cursor;
        request.max_count = GBP_META_CHUNK_NUM;

        cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
        if (gbp_ensure_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return OG_ERROR;
        }
        GBP_SET_MSG_HEADER(&request, GBP_REQ_READ_META_CHUNK, sizeof(gbp_read_meta_req_t),
                           cs_get_socket_fd(pipe));
        if (gbp_knl_send_request(pipe, (char *)&request, NULL) != OG_SUCCESS) {
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return OG_ERROR;
        }
        if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_read_meta_resp_t)) != OG_SUCCESS) {
            cs_disconnect(pipe);
            mgr->temp_connected_node = OG_INVALID_ID32;
            cm_spin_unlock(&mgr->fisrt_pipe_lock);
            return OG_ERROR;
        }
        cm_spin_unlock(&mgr->fisrt_pipe_lock);

        if (response->result != GBP_READ_RESULT_OK && response->result != GBP_READ_RESULT_NOPAGE) {
            OG_LOG_RUN_WAR("[GBP] selected meta pull failed: node=%u result=%u cursor=%llu",
                           node_id, response->result, cursor);
            return OG_ERROR;
        }
        gbp_process_meta_chunk_resp(session, node_id, response, stat);
        chunks++;
        epoch = response->epoch;
        if (response->done) {
#if GBP_READ_HOT_DIAG
            OG_LOG_DEBUG_INF("[GBP] selected meta node summary: node=%u chunks=%u total=%llu elapsed_us=%llu",
                             node_id, chunks, (uint64)response->total_count,
                             (uint64)(cm_now() - begin_time));
#else
            OG_LOG_DEBUG_INF("[GBP] selected meta node summary: node=%u chunks=%u total=%llu",
                             node_id, chunks, (uint64)response->total_count);
#endif
            return OG_SUCCESS;
        }
        if (response->next_cursor <= cursor) {
            OG_LOG_RUN_WAR("[GBP] selected meta cursor stuck: node=%u cursor=%llu next=%llu total=%llu",
                           node_id, cursor, (uint64)response->next_cursor, (uint64)response->total_count);
            return OG_ERROR;
        }
        cursor = response->next_cursor;
    }
}

static status_t gbp_pull_selected_metadata(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_selected_pull_stat_t stat = { 0 };
    uint32 selected_by_node[OG_MAX_INSTANCES] = { 0 };
    uint32 required_count = dtc_rcy_gbp_partial_required_count();
#if GBP_READ_HOT_DIAG
    date_t begin_time = cm_now();
#endif

    for (uint32 i = 0; i < gbp_context->dtc_read_node_count; i++) {
        if (gbp_pull_selected_meta_from_node(session, gbp_context->dtc_read_nodes[i], &stat) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    for (uint32 i = 0; i < required_count; i++) {
        gbp_partial_item_t *item = dtc_rcy_gbp_partial_required_item(i);
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
            if (stat.missing <= 8) {
                OG_LOG_RUN_WAR("[GBP] selected miss sample: page=%u-%u expect_lsn=%llu expect_lfn=%llu "
                               "seen_bitmap=0x%llx",
                               item->page_id.file, item->page_id.page, (uint64)item->expect_lsn,
                               (uint64)item->expect_lfn, (uint64)item->seen_node_bitmap);
            }
        }
    }

#if GBP_READ_HOT_DIAG
    OG_LOG_DEBUG_INF("[GBP] selected metadata summary: planned_nodes=%u required=%u selected=%u missing=%u ahead=%u "
                     "elapsed_us=%llu",
                     gbp_context->dtc_read_node_count, required_count, stat.selected, stat.missing, stat.ahead,
                     (uint64)(cm_now() - begin_time));
#else
    OG_LOG_DEBUG_INF("[GBP] selected metadata summary: planned_nodes=%u required=%u selected=%u missing=%u ahead=%u",
                     gbp_context->dtc_read_node_count, required_count, stat.selected, stat.missing, stat.ahead);
#endif
    gbp_assign_selected_workers(gbp_context, selected_by_node);
    return OG_SUCCESS;
}

static status_t gbp_prepare_single_node_direct_selected(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 required_count = dtc_rcy_gbp_partial_required_count();
    uint32 selected = 0;
    uint32 missing_expect = 0;
    uint32 node_id;
#if GBP_READ_HOT_DIAG
    date_t begin_time = cm_now();
#endif

    if (gbp_context->dtc_read_node_count != 1) {
        return OG_ERROR;
    }

    node_id = gbp_context->dtc_read_nodes[0];
    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < required_count; i++) {
        gbp_partial_item_t *item = dtc_rcy_gbp_partial_required_item(i);
        uint64 expect_lsn;

        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay) {
            continue;
        }
        expect_lsn = dtc_rcy_gbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            missing_expect++;
            continue;
        }
        dtc_rcy_gbp_partial_update_selected(item, node_id, expect_lsn);
        selected++;
    }

    for (uint32 worker = 0; worker < OG_GBP_SESSION_COUNT; worker++) {
        gbp_context->dtc_selected_worker_nodes[worker] = node_id;
    }
#if GBP_READ_HOT_DIAG
    OG_LOG_DEBUG_INF("[GBP] selected direct prepare summary: node=%u required=%u selected=%u missing_expect=%u "
                     "elapsed_us=%llu",
                     node_id, required_count, selected, missing_expect, (uint64)(cm_now() - begin_time));
#else
    OG_LOG_DEBUG_INF("[GBP] selected direct prepare summary: node=%u required=%u selected=%u missing_expect=%u",
                     node_id, required_count, selected, missing_expect);
#endif
    return OG_SUCCESS;
}

static uint32 gbp_fetch_selected_batch_for_node(knl_session_t *session, uint32 node_id,
                                                gbp_batch_selected_read_req_t *request)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 required_count = dtc_rcy_gbp_partial_required_count();
    uint32 count = 0;
    uint32 cursor;
    errno_t ret = memset_sp(request, sizeof(gbp_batch_selected_read_req_t), 0,
                            sizeof(gbp_batch_selected_read_req_t));
    knl_securec_check(ret);

    if (node_id >= OG_MAX_INSTANCES) {
        return 0;
    }

    cm_spin_lock(&gbp_context->dtc_selected_lock[node_id], NULL);
    cursor = gbp_context->dtc_selected_cursor[node_id];
    while (cursor < required_count && count < GBP_BATCH_PAGE_NUM) {
        gbp_partial_item_t *item = dtc_rcy_gbp_partial_required_item(cursor);
        cursor++;
        if (item == NULL || !item->required || item->rcy_item == NULL || !item->rcy_item->need_replay ||
            !item->selected_valid || item->selected_node != node_id || item->selected_pulled || item->verified) {
            continue;
        }
        request->pages[count].page_id = item->page_id;
        request->pages[count].selected_lsn = item->selected_lsn;
        count++;
    }
    gbp_context->dtc_selected_cursor[node_id] = cursor;
    cm_spin_unlock(&gbp_context->dtc_selected_lock[node_id]);
    return count;
}

static void gbp_process_selected_batch_resp(knl_session_t *session, uint32 node_id, gbp_batch_read_resp_t *resp,
                                            uint32 requested, gbp_selected_pull_stat_t *stat,
                                            gbp_read_apply_diag_t *diag)
{
    if (resp->result == GBP_READ_RESULT_ERROR) {
        resp->msg[GBP_MSG_LEN - 1] = '\0';
        OG_LOG_RUN_WAR("[GBP] selected batch read error from node %u: %s", node_id, resp->msg);
        return;
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
        gbp_page_item_t *gbp_page = &resp->pages[i];
        gbp_partial_item_t *item = dtc_rcy_gbp_partial_get_item(gbp_page->page_id);
        page_id_t page_id;
        uint64 expect_lsn;
        uint64 page_lsn;

        if (item == NULL || !item->required || !item->selected_valid || item->selected_node != node_id) {
            if (diag != NULL) {
                diag->not_required++;
            }
            continue;
        }
        expect_lsn = dtc_rcy_gbp_partial_get_expect_lsn(item);
        if (expect_lsn == 0) {
            if (diag != NULL) {
                diag->no_expect++;
            }
            continue;
        }
        page_id = AS_PAGID(((page_head_t *)gbp_page->block)->id);
        knl_panic_log(IS_SAME_PAGID(gbp_page->page_id, page_id), "selected gbp_page id mismatch, panic info: "
                      "gbp_page %u-%u block %u-%u", gbp_page->page_id.file, gbp_page->page_id.page,
                      page_id.file, page_id.page);

        page_lsn = PAGE_GET_LSN(gbp_page->block);
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
            gbp_log_partial_ahead_detail(session, item, node_id, page_lsn, expect_lsn);
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
            gbp_page_status_e page_status;
            uint32 installed_before = stat->installed;

            diag->selected++;
            page_status = gbp_partial_selected_batch_install_page(session, page_id, gbp_page, item, expect_lsn,
                page_lsn, &stat->installed, &stat->verified, &not_newer, diag);
            diag->installed += (stat->installed - installed_before);
            if (page_status == GBP_PAGE_HIT) {
                diag->selected_verified++;
            }
            gbp_count_partial_page_status(diag, page_status, not_newer);
        } else {
            (void)gbp_partial_selected_batch_install_page(session, page_id, gbp_page, item, expect_lsn, page_lsn,
                &stat->installed, &stat->verified, NULL, NULL);
        }
    }
}

static uint32 gbp_knl_read_selected_pages(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
    uint32 node_id;
    uint32 count;
    gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[gbp_proc_id];
    cs_pipe_t *pipe = gbp_get_selected_temp_pipe(gbp_context, gbp_proc_id);
    gbp_batch_selected_read_req_t request;
    gbp_batch_read_resp_t *response = (gbp_batch_read_resp_t *)gbp_context->batch_buf[gbp_proc_id];
    gbp_selected_pull_stat_t stat = { 0 };
#if GBP_READ_HOT_DIAG
    gbp_read_apply_diag_t apply_diag = { 0 };
    gbp_read_apply_diag_t *apply_diag_ptr = &apply_diag;
#else
    gbp_read_apply_diag_t *apply_diag_ptr = NULL;
#endif
    date_t begin_time = cm_now();
    date_t step_begin;
    uint64 pipe_lock_us = 0;
    uint64 ensure_conn_us = 0;
    uint64 send_us = 0;
    uint64 wait_resp_us = 0;
    uint64 process_us = 0;

    if (gbp_context->dtc_read_node_count == 0) {
        gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_NOPAGE, 0, begin_time,
                                   0, 0, 0, 0, 0, NULL);
        return GBP_READ_RESULT_NOPAGE;
    }

    node_id = gbp_context->dtc_selected_worker_nodes[gbp_proc_id];
    if (node_id == OG_INVALID_ID32) {
        gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_NOPAGE, 0, begin_time,
                                   0, 0, 0, 0, 0, NULL);
        return GBP_READ_RESULT_NOPAGE;
    }
    count = gbp_fetch_selected_batch_for_node(session, node_id, &request);
    if (count == 0) {
        gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_NOPAGE, 0, begin_time,
                                   0, 0, 0, 0, 0, NULL);
        return GBP_READ_RESULT_NOPAGE;
    }

    GBP_READ_STEP_BEGIN(step_begin);
    cm_spin_lock(&mgr->selected_pipe_lock, NULL);
    GBP_READ_STEP_ACCUM(step_begin, pipe_lock_us);
    GBP_READ_STEP_BEGIN(step_begin);
    if (gbp_ensure_selected_temp_connection_by_node(session, mgr, node_id) != OG_SUCCESS) {
        cm_spin_unlock(&mgr->selected_pipe_lock);
        GBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);
        gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return GBP_READ_RESULT_ERROR;
    }
    GBP_READ_STEP_ACCUM(step_begin, ensure_conn_us);
    request.count = count;
    GBP_SET_MSG_HEADER(&request, GBP_REQ_BATCH_PAGE_READ_SELECTED, sizeof(gbp_batch_selected_read_req_t),
                       cs_get_socket_fd(pipe));
    request.header.queue_id = gbp_proc_id;
    GBP_READ_STEP_BEGIN(step_begin);
    if (gbp_knl_send_request(pipe, (char *)&request, NULL) != OG_SUCCESS) {
        cm_spin_unlock(&mgr->selected_pipe_lock);
        GBP_READ_STEP_ACCUM(step_begin, send_us);
        gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return GBP_READ_RESULT_ERROR;
    }
    GBP_READ_STEP_ACCUM(step_begin, send_us);
    GBP_READ_STEP_BEGIN(step_begin);
    if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_batch_read_resp_t)) != OG_SUCCESS) {
        cs_disconnect(pipe);
        mgr->selected_temp_connected_node = OG_INVALID_ID32;
        cm_spin_unlock(&mgr->selected_pipe_lock);
        GBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
        gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_ERROR, 0, begin_time,
                                   pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
        return GBP_READ_RESULT_ERROR;
    }
    GBP_READ_STEP_ACCUM(step_begin, wait_resp_us);
    cm_spin_unlock(&mgr->selected_pipe_lock);

    GBP_READ_STEP_BEGIN(step_begin);
    gbp_process_selected_batch_resp(session, node_id, response, count, &stat, apply_diag_ptr);
    GBP_READ_STEP_ACCUM(step_begin, process_us);
    session->stat->gbp_bg_read += stat.returned;
    session->stat->gbp_bg_read_time += (cm_now() - begin_time) / MICROSECS_PER_MILLISEC;
    gbp_finish_read_batch_stat(session, gbp_proc_id, GBP_READ_RESULT_OK, stat.returned, begin_time,
                               pipe_lock_us, ensure_conn_us, send_us, wait_resp_us, process_us, apply_diag_ptr);
    if (stat.missing > 0) {
        OG_LOG_RUN_WAR("[GBP] selected pull worker batch: worker=%u node=%u requested=%u returned=%u installed=%u "
                       "verified=%u missing=%u elapsed_us=%llu",
                       gbp_proc_id, node_id, stat.requested, stat.returned, stat.installed, stat.verified,
                       stat.missing, (uint64)(cm_now() - begin_time));
    }
    return GBP_READ_RESULT_OK;
}

void gbp_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    uint32 queue_id = ctrl->page_id.page % OG_GBP_SESSION_COUNT;
    gbp_queue_t *queue = &gbp_ctx->queue[queue_id];
    gbp_queue_item_t *item = NULL;
    uint32 queue_count;
    bool32 queue_has_gap;
    uint64 queue_trunc_lfn;
    uint64 lastest_lfn;
    uint64 page_lsn;
    uint64 item_trunc_lfn;
    uint32 page_pcn;
    gbp_queue_item_t *pending_item = NULL;
#ifdef GBP_VERBOSE_TRACE
    uint32 pending_source = 0;
#endif
    uint64 curr_lfn;

    if (!ctrl->gbp_ctrl->is_gbpdirty) {
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[GBP_ENQ_TRACE] skip stale dirty-list entry: queue=%u page=%u-%u sid=%u dtc_type=%u "
                       "ctrl=%p pending=%p lastest_lfn=%llu page_lsn=%llu page_pcn=%u gbp_trunc_lfn=%llu "
                       "is_from_gbp=%u page_status=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, session->id,
                       (uint32)session->dtc_session_type, (void *)ctrl, (void *)ctrl->gbp_ctrl->pending_item,
                       (uint64)ctrl->lastest_lfn, (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn,
                       (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint32)ctrl->gbp_ctrl->is_from_gbp,
                       (uint32)ctrl->gbp_ctrl->page_status);
#endif
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[GBP] skip stale dirty-list entry: queue=%u page=%u-%u",
                         queue_id, ctrl->page_id.file, ctrl->page_id.page);
#endif
        return;
    }

    item = gbp_alloc_queue_item();

    if (item == NULL) {
        cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
        OG_LOG_RUN_WAR("[GBP_CTRL_TRACE] DROP_PENDING reason=alloc_failed queue=%u page=%u-%u ctrl=%p item=%p "
                       "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu "
                       "gap_end_lfn=%llu page_status=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl,
                       (void *)ctrl->gbp_ctrl->pending_item, (uint64)ctrl->page->lsn,
                       (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                       (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)0,
                       (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint32)ctrl->gbp_ctrl->page_status);
        ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
        ctrl->gbp_ctrl->pending_item = NULL;
        queue->has_gap = OG_TRUE;
        cm_spin_unlock(&queue->lock);
        OG_LOG_RUN_WAR("[GBP] failed to alloc queue item, set gap: queue=%u page=%u-%u lastest_lfn=%llu",
                        queue_id, ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn);
        return;
    }

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    if (ctrl->gbp_ctrl->pending_item != NULL) {
#ifdef GBP_VERBOSE_TRACE
        pending_item = ctrl->gbp_ctrl->pending_item;
        pending_source = (uint32)pending_item->source;
        queue_count = queue->count;
        queue_has_gap = queue->has_gap;
        queue_trunc_lfn = queue->trunc_point.lfn;
        item_trunc_lfn = ctrl->gbp_ctrl->gbp_trunc_point.lfn;
        lastest_lfn = ctrl->lastest_lfn;
        page_lsn = ctrl->page->lsn;
        page_pcn = ctrl->page->pcn;
        curr_lfn = session->kernel->redo_ctx.curr_point.lfn;
#endif
        cm_spin_unlock(&queue->lock);
        gbp_free_queue_item(session, item);
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[GBP_ENQ_TRACE] merge duplicate pending live item: queue=%u page=%u-%u sid=%u dtc_type=%u "
                       "ctrl=%p pending=%p pending_source=%u count=%u queue_trunc_lfn=%llu item_trunc_lfn=%llu "
                       "lastest_lfn=%llu page_lsn=%llu page_pcn=%u has_gap=%u curr_lfn=%llu connected=%u "
                       "dtc_read_active=%u",
                       queue_id, ctrl->page_id.file, ctrl->page_id.page, session->id,
                       (uint32)session->dtc_session_type, (void *)ctrl, (void *)pending_item, pending_source, queue_count,
                       (uint64)queue_trunc_lfn, (uint64)item_trunc_lfn, (uint64)lastest_lfn, (uint64)page_lsn,
                       page_pcn, (uint32)queue_has_gap, (uint64)curr_lfn,
                       (uint32)gbp_ctx->gbp_buf_manager[queue_id].is_connected, (uint32)gbp_ctx->dtc_read_active);
#endif
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_DEBUG_INF("[GBP] skip duplicate live queue item: queue=%u page=%u-%u lastest_lfn=%llu",
                         queue_id, ctrl->page_id.file, ctrl->page_id.page, (uint64)ctrl->lastest_lfn);
#endif
        return;
    }

    ctrl->gbp_ctrl->gbp_trunc_point = queue->trunc_point;

    item->source = GBP_QUEUE_ITEM_LIVE;
    item->ctrl = ctrl;
    item->page_id = ctrl->page_id;
    item->queue_id = queue_id;
    ctrl->gbp_ctrl->pending_item = item;

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
    item_trunc_lfn = ctrl->gbp_ctrl->gbp_trunc_point.lfn;
    page_pcn = ctrl->page->pcn;
    curr_lfn = session->kernel->redo_ctx.curr_point.lfn;
    pending_item = ctrl->gbp_ctrl->pending_item;

    cm_spin_unlock(&queue->lock);

    OG_LOG_DEBUG_INF("[GBP_ENQ_TRACE] enqueue live item: queue=%u page=%u-%u sid=%u dtc_type=%u ctrl=%p item=%p "
                     "pending=%p count=%u queue_trunc_lfn=%llu item_trunc_lfn=%llu lastest_lfn=%llu page_lsn=%llu "
                     "page_pcn=%u has_gap=%u curr_lfn=%llu connected=%u dtc_read_active=%u",
                     queue_id, ctrl->page_id.file, ctrl->page_id.page, session->id,
                     (uint32)session->dtc_session_type, (void *)ctrl, (void *)item,
                     (void *)pending_item, queue_count, (uint64)queue_trunc_lfn,
                     (uint64)item_trunc_lfn, (uint64)lastest_lfn, (uint64)page_lsn, page_pcn,
                     (uint32)queue_has_gap, (uint64)curr_lfn,
                     (uint32)gbp_ctx->gbp_buf_manager[queue_id].is_connected, (uint32)gbp_ctx->dtc_read_active);

#if GBP_PAGE_WRITE_HOT_DIAG
    if (gbp_queue_backlog_loggable(queue_id, queue_count)) {
        OG_LOG_DEBUG_INF("[GBP] PAGE_WRITE queue backlog on enqueue: queue=%u count=%u page=%u-%u "
                         "queue_trunc_lfn=%llu item_latest_lfn=%llu page_lsn=%llu has_gap=%u connected=%u "
                         "dtc_read_active=%u",
                       queue_id, queue_count, ctrl->page_id.file, ctrl->page_id.page, (uint64)queue_trunc_lfn,
                       (uint64)lastest_lfn, (uint64)page_lsn, (uint32)queue_has_gap,
                       (uint32)gbp_ctx->gbp_buf_manager[queue_id].is_connected, (uint32)gbp_ctx->dtc_read_active);
    }
#endif
}

 void gbp_enque_pages(knl_session_t *session)
 {
     for (uint32 i = 0; i < session->gbp_dirty_count; i++) {
         gbp_enque_one_page(session, session->gbp_dirty_pages[i]);
     }

     session->gbp_dirty_count = 0;
 }

void gbp_queue_set_gap(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    uint32 queue_id = ctrl->page_id.page % OG_GBP_SESSION_COUNT;
    gbp_queue_t *queue = &gbp_ctx->queue[queue_id];
    gbp_queue_item_t *item = NULL;
    bool32 already_gap;

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    already_gap = queue->has_gap;
    queue->has_gap = OG_TRUE;
    item = ctrl->gbp_ctrl->pending_item;
    if (item != NULL && item->source == GBP_QUEUE_ITEM_LIVE && item->ctrl == ctrl) {
        item->source = GBP_QUEUE_ITEM_DROPPED;
        item->ctrl = NULL;
    }
#ifdef GBP_VERBOSE_TRACE
    OG_LOG_RUN_WAR("[GBP_CTRL_TRACE] DROP_PENDING reason=queue_set_gap queue=%u page=%u-%u ctrl=%p item=%p "
                   "page_lsn=%llu page_pcn=%u lastest_lfn=%llu item_trunc_lfn=%llu reset_lfn=%llu gap_end_lfn=%llu "
                   "page_status=%u already_gap=%u",
                   queue_id, ctrl->page_id.file, ctrl->page_id.page, (void *)ctrl, (void *)item,
                   (uint64)ctrl->page->lsn, (uint32)ctrl->page->pcn, (uint64)ctrl->lastest_lfn,
                   (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)0,
                   (uint64)session->kernel->redo_ctx.curr_point.lfn, (uint32)ctrl->gbp_ctrl->page_status,
                   (uint32)already_gap);
#endif
    ctrl->gbp_ctrl->pending_item = NULL;
    ctrl->gbp_ctrl->is_gbpdirty = OG_FALSE;
    cm_spin_unlock(&queue->lock);

    if (already_gap) {
        return;
    }

    OG_LOG_RUN_WAR("[GBP] gbp send queue: [%u] set gap by dirty page recycle page=%u-%u "
                   "trunc_lfn=%llu lastest_lfn=%llu queue_pages=%u page_status=%u",
                   queue_id, ctrl->page_id.file, ctrl->page_id.page,
                   (uint64)ctrl->gbp_ctrl->gbp_trunc_point.lfn, (uint64)ctrl->lastest_lfn, queue->count,
                   (uint32)ctrl->gbp_ctrl->page_status);
}

void gbp_queue_set_trunc_point(knl_session_t *session, log_point_t *point)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
     gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
     gbp_queue_t *queue = NULL;

     if (!KNL_GBP_ENABLE(session->kernel)) {
         return;
     }

     /* this is possible during recovery if we set _GBP_DEBUG_MODE=RCYCHK */
     if (!DB_IS_OPEN(session)) {
         if (log_cmp_point(point, &redo_ctx->gbp_rcy_point) < 0) {
             return;
         }
     }

     for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         queue = &gbp_ctx->queue[id];
         cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
         if (LOG_LFN_LT(queue->trunc_point, *point)) {
             queue->trunc_point = *point;
         }
        cm_spin_unlock(&queue->lock);
    }
}

static void gbp_queue_mark_reset_point(knl_session_t *session, uint32 queue_id, log_point_t *point)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    gbp_queue_t *queue = &gbp_ctx->queue[queue_id % OG_GBP_SESSION_COUNT];

    cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
    if (queue->ckpt_reset_point.lfn == 0 || log_cmp_point(&queue->ckpt_reset_point, point) < 0) {
        queue->ckpt_reset_point = *point;
        queue->has_ckpt_reset = OG_TRUE;
    }
    cm_spin_unlock(&queue->lock);
}

static void gbp_queue_notify_reset_point_one(knl_session_t *session, uint32 queue_id, log_point_t *point,
                                             const char *reason, bool32 warn_log)
{
    const char *tag = (reason == NULL) ? "unknown" : reason;

    if (!KNL_GBP_ENABLE(session->kernel) || point == NULL || point->lfn == 0) {
        return;
    }

    gbp_queue_mark_reset_point(session, queue_id, point);

    if (warn_log) {
        OG_LOG_RUN_WAR("[GBP] notify %s reset to GBP queue %u: point=[%u-%u/%u/%llu/%llu]",
                       tag, queue_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn,
                       (uint64)point->lsn);
    } else {
        OG_LOG_RUN_INF("[GBP] notify %s reset to GBP queue %u: point=[%u-%u/%u/%llu/%llu]",
                       tag, queue_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn,
                       (uint64)point->lsn);
    }
}

void gbp_queue_notify_ckpt_point(knl_session_t *session, log_point_t *point)
{
    if (!KNL_GBP_ENABLE(session->kernel) || point == NULL || point->lfn == 0) {
        return;
    }

    (void)session;
    (void)point;
}

uint64 gbp_queue_get_page_count(knl_session_t *session)
{
     gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
     gbp_queue_t *queue = NULL;
     uint64 page_count = 0;

     for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         queue = &gbp_ctx->queue[id];
         page_count += queue->count;
     }

     return page_count;
 }

 log_point_t gbp_queue_get_trunc_point(knl_session_t *session)
 {
     gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
     gbp_queue_t *queue = NULL;
     gbp_queue_item_t *item = NULL;
     log_point_t item_trunc_point;
     log_point_t trunc_point = gbp_ctx->queue[0].trunc_point;

     for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
         queue = &gbp_ctx->queue[id];
         cm_spin_lock(&queue->lock, &session->stat->spin_stat.stat_gbp_queue);
         if (queue->count != 0) {
             item = queue->first;
             if (item->source == GBP_QUEUE_ITEM_SNAPSHOT) {
                 item_trunc_point = item->snapshot->gbp_trunc_point;
             } else if (item->source == GBP_QUEUE_ITEM_LIVE && item->ctrl != NULL) {
                 item_trunc_point = item->ctrl->gbp_ctrl->gbp_trunc_point;
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

 void gbp_set_unsafe(knl_session_t *session, log_type_t type)
 {
     log_context_t *redo_ctx = &session->kernel->redo_ctx;

     redo_ctx->gbp_aly_result.gbp_unsafe = OG_TRUE;
     redo_ctx->gbp_aly_result.unsafe_type = type;
 }

 void gbp_reset_unsafe(knl_session_t *session)
 {
     log_context_t *redo_ctx = &session->kernel->redo_ctx;

     redo_ctx->gbp_aly_result.gbp_unsafe = OG_FALSE;
     OG_LOG_RUN_INF("[GBP] gbp reset to safe successfully");
 }

 /*
  * check if gbp can reset from unsafe to safe.
  * if replay beyond the unsafe redo and unsafe is caused by logic or space redo, gbp can reset to safe.
  */
 void gbp_unsafe_redo_check(knl_session_t *session)
 {
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
     uint64 rcy_curr_lsn = session->kernel->sessions[SESSION_ID_KERNEL]->curr_lsn;

     if (!KNL_GBP_ENABLE(session->kernel)) {
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

     /* if gbp unsafe caused by unsafe redo log, can reset gbp status to safe */
     if (redo_ctx->gbp_aly_result.gbp_unsafe && redo_ctx->gbp_aly_result.unsafe_type < RD_TYPE_END) {
         /* if replay beyond the unsafe redo, gbp can reset to safe */
         if (rcy_curr_lsn > redo_ctx->gbp_aly_result.unsafe_max_lsn) {
             OG_LOG_RUN_INF("[GBP] gbp reset to safe because of replay lsn [%llu] beyond max unsafe redo lsn[%llu]",
                            rcy_curr_lsn, redo_ctx->gbp_aly_result.unsafe_max_lsn);
             gbp_reset_unsafe(session);
         }
     }
 }

 /* check if gbp is safe, retrun true if gbp can be used for failover */
bool32 gbp_pre_check(knl_session_t *session, log_point_t aly_end_point)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_point_t init_point = { 0, 0, 0, 0 };

    OG_LOG_RUN_WAR("[GBP] gbp_pre_check ENTER aly_end asn=%u block=%u lfn=%llu rst_id=%llu rcy_rst_id=%llu "
                   "SAFE=%u gbp_unsafe=%u",
                   aly_end_point.asn, aly_end_point.block_id, (uint64)aly_end_point.lfn, (uint64)aly_end_point.rst_id,
                   (uint64)dtc_my_ctrl(session)->rcy_point.rst_id, (uint32)KNL_GBP_SAFE(session->kernel),
                   (uint32)redo_ctx->gbp_aly_result.gbp_unsafe);

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(&session->kernel->db)) {
         OG_LOG_RUN_WAR("[GBP] gbp is unsafe because database is cascaded standby");
         return OG_FALSE;
     }

     redo_ctx->gbp_begin_point = init_point;
     redo_ctx->gbp_rcy_point = init_point;
     redo_ctx->gbp_lrp_point = init_point;

     gbp_unsafe_redo_check(session);
     if (!KNL_GBP_SAFE(session->kernel)) {
         OG_LOG_RUN_WAR("[GBP] gbp is unsafe");
         return OG_FALSE;
     }

     if (aly_end_point.rst_id != dtc_my_ctrl(session)->rcy_point.rst_id) {
         gbp_set_unsafe(session, RD_TYPE_END);
         OG_LOG_RUN_WAR("[GBP] gbp unsafe because of redo end_point rst_id[%u] is not equal to rcy_point rst_id[%u]",
                        aly_end_point.rst_id, dtc_my_ctrl(session)->rcy_point.rst_id);
         return OG_FALSE;
     }

     OG_LOG_RUN_INF("[GBP] gbp is safe");
     return OG_TRUE;
 }

/* kernel read GBP checkpoints */
status_t gbp_knl_query_gbp_point(knl_session_t *session, gbp_read_ckpt_resp_t *response, bool32 check_end_point)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     gbp_read_ckpt_req_t request;
     gbp_buf_manager_t *manager = &gbp_context->gbp_buf_manager[0];
     cs_pipe_t *pipe = gbp_get_client_pipe(gbp_context, 0, OG_FALSE);

     cm_spin_lock(&manager->fisrt_pipe_lock, NULL); // concurrency with heart beat
     if (!manager->is_connected) {
         cm_spin_unlock(&manager->fisrt_pipe_lock);
         return OG_ERROR;
     }

     GBP_SET_MSG_HEADER(&request, GBP_REQ_READ_CKPT, sizeof(gbp_read_ckpt_req_t), cs_get_socket_fd(pipe));
     request.check_end_point = check_end_point;
     request.aly_end_point = redo_ctx->redo_end_point;

     if (gbp_knl_send_request(pipe, (char *)&request, manager) != OG_SUCCESS) {
         cm_spin_unlock(&manager->fisrt_pipe_lock);
         return OG_ERROR;
     }

     if (gbp_knl_wait_response(pipe, (char *)response, sizeof(gbp_read_ckpt_resp_t)) != OG_SUCCESS) {
         cs_disconnect(pipe);
         manager->is_connected = OG_FALSE;
         cm_spin_unlock(&manager->fisrt_pipe_lock);
         return OG_ERROR;
     }

     cm_spin_unlock(&manager->fisrt_pipe_lock);

     if (response->gbp_unsafe) {
         gbp_context->gbp_window_start = 0;
         gbp_context->gbp_window_end = 0;
     } else {
         gbp_context->gbp_window_start = response->begin_point.lfn;
         gbp_context->gbp_window_end = response->rcy_point.lfn;
     }

     return OG_SUCCESS;
 }

 /* kernel notify GBP check redo end point */
 void gbp_knl_check_end_point(knl_session_t *session)
 {
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     gbp_read_ckpt_resp_t response;

     if (gbp_knl_query_gbp_point(session, &response, OG_TRUE) != OG_SUCCESS) {
         gbp_set_unsafe(session, RD_TYPE_END);
         OG_LOG_RUN_WAR("[GBP] gbp unsafe because failed to query gbp point");
         return;
     }

     gbp_process_read_ckpt_resp(session, &response, redo_ctx);
 }

 void gbp_refresh_gbp_window(knl_session_t *session, uint32 gbp_proc_id)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     gbp_read_ckpt_resp_t response;

     if (gbp_proc_id != 0) {
         return;
     }

     if (gbp_knl_query_gbp_point(session, &response, OG_FALSE) != OG_SUCCESS) {
         gbp_context->gbp_window_start = 0;
         gbp_context->gbp_window_end = 0;
     }
 }

 /* kernel try read one page from GBP */
gbp_page_status_e knl_read_page_from_gbp(knl_session_t *session, buf_ctrl_t *ctrl)
{
    gbp_page_status_e page_status;
    datafile_t *df = DATAFILE_GET(session, ctrl->page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    bool32 partial_read = gbp_is_dtc_partial_read(session);
    gbp_partial_item_t *partial_item = NULL;
    gbp_analyse_item_t *aly_item = NULL;
    uint64 expect_lsn = 0;
    uint64 expect_lfn = 0;
#ifdef GBP_VERBOSE_TRACE
    uint32 gbp_proc_id = ctrl->page_id.page % OG_GBP_SESSION_COUNT;
    uint64 disk_lsn = PAGE_GET_LSN(ctrl->page);
    uint32 disk_pcn = ctrl->page->pcn;
    uint32 read_node = session->kernel->gbp_context.gbp_buf_manager[gbp_proc_id].temp_connected_node;
#endif
    uint32 verify_node_id = OG_INVALID_ID32;
    bool32 in_jumped_window = OG_FALSE;

    /* no redo log for the page, page would not exists on GBP */
    if (partial_read) {
        partial_item = dtc_rcy_gbp_partial_get_item(ctrl->page_id);
        expect_lsn = dtc_rcy_gbp_partial_get_expect_lsn(partial_item);
        expect_lfn = (partial_item == NULL) ? 0 : partial_item->expect_lfn;
        if (partial_item == NULL || partial_item->rcy_item == NULL ||
            !partial_item->rcy_item->need_replay || expect_lsn == 0) {
            gbp_record_read_skip_partial_no_expect(&session->kernel->gbp_context, partial_item);
            GBP_BUF_TRACE_LOG("[GBP_BUF_TRACE] knl_read_page_from_gbp MISS partial_no_expect page %u-%u "
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
            return GBP_PAGE_MISS;
        }
        in_jumped_window = dtc_rcy_gbp_partial_item_in_jumped_window(session, partial_item, &verify_node_id);
        if (session->kernel->gbp_context.dtc_use_selected_batch && !in_jumped_window) {
            gbp_record_read_skip_partial_selected_scope(&session->kernel->gbp_context, partial_item, ctrl);
            return GBP_PAGE_MISS;
        }
    } else {
        expect_lsn = gbp_aly_get_page_lsn(session, ctrl->page_id);
        if (expect_lsn == OG_INVALID_LSN) {
            gbp_record_read_skip_no_expect_lsn(&session->kernel->gbp_context);
            GBP_BUF_TRACE_LOG("[GBP_BUF_TRACE] knl_read_page_from_gbp MISS no_expect_lsn page %u-%u",
                             ctrl->page_id.file, ctrl->page_id.page);
            return GBP_PAGE_MISS;
        }
        aly_item = gbp_aly_get_page_item(session, ctrl->page_id);
        if (aly_item != NULL) {
            expect_lsn = gbp_get_item_expect_lsn(session, aly_item);
            expect_lfn = aly_item->lfn;
        }
    }
#ifndef GBP_VERBOSE_TRACE
    (void)expect_lfn;
#endif
    if (SPACE_IS_NOLOGGING(space)) {
        gbp_record_read_skip_nolog_space(&session->kernel->gbp_context);
        GBP_BUF_TRACE_LOG("[GBP_BUF_TRACE] knl_read_page_from_gbp MISS nolog_space page %u-%u", ctrl->page_id.file,
                          ctrl->page_id.page);
        return GBP_PAGE_MISS;
    }

    session->stat->gbp_knl_read++;
    page_status = gbp_knl_pull_one_page(session, ctrl);
    if (page_status == GBP_PAGE_ERROR) {
        CM_ABORT(0, "[GBP] ABORT INFO: instance must exit beacause of failed to read page from GBP");
    }

    if (page_status == GBP_PAGE_MISS) {
#ifdef GBP_VERBOSE_TRACE
        OG_LOG_RUN_INF("[GBP_READ_TRACE] READ_RESULT page=%u-%u status=%u partial=%u expect_lsn=%llu "
                       "expect_lfn=%llu disk_lsn=%llu disk_pcn=%u returned_lsn=%llu returned_pcn=%u "
                       "read_node=%u is_from_gbp=%u page_status=%u required=%u selected_valid=%u "
                       "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                       "load_status=%u",
                       ctrl->page_id.file, ctrl->page_id.page, (uint32)page_status, (uint32)partial_read,
                       (uint64)expect_lsn, (uint64)expect_lfn, (uint64)disk_lsn, disk_pcn,
                       (uint64)PAGE_GET_LSN(ctrl->page), (uint32)ctrl->page->pcn, read_node,
                       (uint32)ctrl->gbp_ctrl->is_from_gbp, (uint32)ctrl->gbp_ctrl->page_status,
                       (uint32)(partial_read && partial_item != NULL && partial_item->required),
                       (uint32)(partial_read && partial_item != NULL && partial_item->selected_valid),
                       (uint32)(partial_read && partial_item != NULL && partial_item->selected_pulled),
                       (uint32)(partial_read && partial_item != NULL && partial_item->verified),
                       (uint32)in_jumped_window, verify_node_id,
                       (uint32)(partial_read && partial_item != NULL ? partial_item->selected_node :
                           OG_INVALID_ID32),
                       (uint32)ctrl->load_status);
#endif
        OG_LOG_DEBUG_INF("[GBP] kernel read page from GBP: page: %u-%u not found on GBP",
                         ctrl->page_id.file, ctrl->page_id.page);
        session->stat->gbp_miss++;
        return GBP_PAGE_MISS;
    }

#ifdef GBP_VERBOSE_TRACE
    OG_LOG_RUN_INF("[GBP_READ_TRACE] READ_RESULT page=%u-%u status=%u partial=%u expect_lsn=%llu "
                   "expect_lfn=%llu disk_lsn=%llu disk_pcn=%u returned_lsn=%llu returned_pcn=%u "
                   "read_node=%u is_from_gbp=%u page_status=%u required=%u selected_valid=%u "
                   "selected_pulled=%u verified=%u in_jumped_window=%u verify_node=%u selected_node=%u "
                   "load_status=%u",
                   ctrl->page_id.file, ctrl->page_id.page, (uint32)page_status, (uint32)partial_read,
                   (uint64)expect_lsn, (uint64)expect_lfn, (uint64)disk_lsn, disk_pcn,
                   (uint64)PAGE_GET_LSN(ctrl->page), (uint32)ctrl->page->pcn, read_node,
                   (uint32)ctrl->gbp_ctrl->is_from_gbp, (uint32)ctrl->gbp_ctrl->page_status,
                   (uint32)(partial_read && partial_item != NULL && partial_item->required),
                   (uint32)(partial_read && partial_item != NULL && partial_item->selected_valid),
                   (uint32)(partial_read && partial_item != NULL && partial_item->selected_pulled),
                   (uint32)(partial_read && partial_item != NULL && partial_item->verified),
                   (uint32)in_jumped_window, verify_node_id,
                   (uint32)(partial_read && partial_item != NULL ? partial_item->selected_node : OG_INVALID_ID32),
                   (uint32)ctrl->load_status);
#endif
    GBP_BUF_TRACE_LOG("[GBP_BUF_TRACE] knl_read_page_from_gbp done page %u-%u status=%u page_lsn=%llu page_pcn=%u "
                      "is_from_gbp=%u",
                      ctrl->page_id.file, ctrl->page_id.page, (uint32)page_status, (uint64)ctrl->page->lsn,
                      (uint32)ctrl->page->pcn, (uint32)ctrl->gbp_ctrl->is_from_gbp);
    return page_status;
}

/*
 * Multi-node recovery has already rewritten per-node rcy_point_saved[] during prepare,
 * so begin_dtc_read only starts GBP background pulling and flips the shared recovery state.
 * There is intentionally no single curr_point = gbp_rcy_point jump here.
 */
status_t gbp_knl_begin_dtc_read(knl_session_t *session)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
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
        OG_LOG_RUN_INF("[GBP] skip DTC GBP read: only partial recovery uses GBP acceleration");
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[GBP] begin multi-node GBP read start: current_version=%u rcy_with_gbp=%u",
                     gbp_context->gbp_read_version, (uint32)redo->rcy_with_gbp);
    if (gbp_save_dtc_read_epoch(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[GBP] DTC GBP read epoch is empty, keep redo recovery");
        return OG_ERROR;
    }
    save_epoch_us = (uint64)(cm_now() - stage_begin);
    gbp_reset_read_stat(gbp_context);
    stage_begin = cm_now();
    if (gbp_notify_dtc_read_begin_planned(session) != OG_SUCCESS) {
        gbp_clear_dtc_read_epoch(gbp_context);
        gbp_stop_temp_connection(session, gbp_context);
        OG_LOG_RUN_WAR("[GBP] can not notify any DTC GBP READ_BEGIN node, keep redo recovery");
        return OG_ERROR;
    }
    notify_begin_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();
    if (gbp_build_dtc_planned_required_items(session) != OG_SUCCESS) {
        (void)gbp_notify_dtc_read_phase(session, MSG_GBP_READ_END);
        gbp_disable_dtc_planned_nodes(session);
        gbp_clear_dtc_read_epoch(gbp_context);
        gbp_stop_temp_connection(session, gbp_context);
        OG_LOG_RUN_WAR("[GBP] failed to build DTC planned required item cache, keep redo recovery");
        return OG_ERROR;
    }
    build_required_us = (uint64)(cm_now() - stage_begin);
    gbp_choose_dtc_selected_mode(session, &use_selected_batch, &need_selected_meta, &sync_selected_pull_at_begin);
    for (uint32 id = 0; id < OG_MAX_INSTANCES; id++) {
        gbp_context->dtc_selected_cursor[id] = 0;
    }
    if (need_selected_meta) {
        stage_begin = cm_now();
        if (gbp_pull_selected_metadata(session) != OG_SUCCESS) {
            (void)gbp_notify_dtc_read_phase(session, MSG_GBP_READ_END);
            gbp_disable_dtc_planned_nodes(session);
            gbp_clear_dtc_read_epoch(gbp_context);
            gbp_stop_temp_connection(session, gbp_context);
            OG_LOG_RUN_WAR("[GBP] failed to pull selected metadata, keep redo recovery");
            return OG_ERROR;
        }
        meta_us = (uint64)(cm_now() - stage_begin);
    } else if (use_selected_batch) {
        stage_begin = cm_now();
        if (gbp_prepare_single_node_direct_selected(session) != OG_SUCCESS) {
            (void)gbp_notify_dtc_read_phase(session, MSG_GBP_READ_END);
            gbp_disable_dtc_planned_nodes(session);
            gbp_clear_dtc_read_epoch(gbp_context);
            gbp_stop_temp_connection(session, gbp_context);
            OG_LOG_RUN_WAR("[GBP] failed to prepare direct selected pages, keep redo recovery");
            return OG_ERROR;
        }
        meta_us = (uint64)(cm_now() - stage_begin);
    }

    gbp_context->gbp_read_completed = OG_FALSE;
    gbp_context->dtc_read_workers_done = OG_FALSE;
    gbp_context->gbp_read_thread_num = OG_GBP_SESSION_COUNT;
    gbp_context->gbp_read_version++;
    gbp_context->gbp_begin_read_time = cm_now();
    gbp_context->dtc_use_selected_batch = use_selected_batch;
    gbp_context->dtc_need_selected_meta = need_selected_meta;
    gbp_context->dtc_sync_selected_pull_at_begin = sync_selected_pull_at_begin;
    if (!use_selected_batch) {
        for (uint32 id = 0; id < OG_GBP_SESSION_COUNT; id++) {
            gbp_context->dtc_selected_worker_nodes[id] = OG_INVALID_ID32;
        }
    }

    redo->last_rcy_with_gbp = OG_TRUE;
    redo->rcy_with_gbp = OG_TRUE;
    CM_MFENCE;

    for (uint32 id = 0; id < gbp_context->gbp_read_thread_num; id++) {
        gbp_context->gbp_buf_manager[id].gbp_reading = OG_TRUE;
    }

    if (sync_selected_pull_at_begin) {
        stage_begin = cm_now();
        while (gbp_context->gbp_read_thread_num > 0) {
            cm_sleep(1);
        }
        gbp_context->dtc_read_workers_done = OG_TRUE;
        gbp_context->gbp_read_workers_done_time = cm_now();
        selected_pull_us = (uint64)(cm_now() - stage_begin);
    }

    OG_LOG_RUN_INF("[GBP] begin multi-node GBP read, read_version=%u, save_epoch_us=%llu notify_begin_us=%llu "
                   "build_required_us=%llu use_selected_batch=%u need_selected_meta=%u sync_begin=%u "
                   "meta_us=%llu selected_pull_us=%llu required_items=%u total_begin_us=%llu skipped_lfn_total=%llu",
                   gbp_context->gbp_read_version, save_epoch_us, notify_begin_us, build_required_us,
                   (uint32)use_selected_batch, (uint32)need_selected_meta, (uint32)sync_selected_pull_at_begin,
                   meta_us, selected_pull_us,
                   gbp_context->dtc_planned_required_count,
                   (uint64)(cm_now() - begin_time), gbp_dtc_read_skip_lfn_total(gbp_context));
    return OG_SUCCESS;
}

static void gbp_verify_skiped_redo_pages(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    gbp_analyse_item_t *aly_items = ctx->gbp_aly_items;
    uint64 skip_start = ctx->gbp_skip_point.lfn;
    uint64 skip_end = ctx->gbp_rcy_point.lfn;
    uint32 in_window = 0;
    uint32 miss_cnt = 0;
    uint32 sample = 0;
    bool32 dtc_read = gbp_is_multi_node_rcy(session);
    bool32 partial_read = gbp_is_dtc_partial_read(session);
    uint32 node_ids[OG_MAX_INSTANCES];
    uint32 node_count = dtc_read ? gbp_collect_verify_rcy_nodes(session, node_ids, OG_MAX_INSTANCES) : 0;
    uint64 skipped_lfn_total = dtc_read ? gbp_dtc_read_skip_lfn_total(&session->kernel->gbp_context) :
        (skip_end > skip_start ? (skip_end - skip_start) : 0);
    bool32 use_required_cache = (bool32)(dtc_read && gbp_context->dtc_planned_required_built);
    uint32 scan_count = use_required_cache ? gbp_context->dtc_planned_required_count : (uint32)GBP_ALY_MAX_ITEM;

    if (dtc_read && partial_read) {
        gbp_verify_partial_skiped_redo_pages(session, node_count, skipped_lfn_total);
        return;
    }
    if (aly_items == NULL) {
        OG_LOG_RUN_WAR("[GBP] verify summary: skip because analysis items are NULL");
        return;
    }
    if (dtc_read && node_count == 0) {
        OG_LOG_RUN_INF("[GBP] verify summary: no jumped GBP nodes, skip final verification, "
                       "required_cache_built=%u required_cache_items=%u",
                       (uint32)gbp_context->dtc_planned_required_built,
                       gbp_context->dtc_planned_required_count);
        return;
    }
    for (uint32 i = 0; i < scan_count; i++) {
        gbp_analyse_item_t *aly_item = use_required_cache ? gbp_context->dtc_planned_required_items[i] : &aly_items[i];
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
        expect_lsn = gbp_get_item_expect_lsn(session, aly_item);
        if (dtc_read) {
            /*
             * In v6 each node may skip a different prefix. Check every jumped node, because the latest
             * touch can belong to tail redo while the first touch is still inside another node's skipped prefix.
             */
            for (uint32 j = 0; j < node_count; j++) {
                uint32 node_id = node_ids[j];
                log_point_t *node_skip = NULL;
                log_point_t *node_rcy = NULL;
                if (!gbp_get_dtc_verify_points(session, node_id, &node_skip, &node_rcy)) {
                    continue;
                }
                if (gbp_aly_item_in_node_skip(aly_item, node_id, node_skip, node_rcy)) {
                    need_verify = OG_TRUE;
                    verify_node_id = node_id;
                    break;
                }
            }
        } else if (gbp_aly_item_in_global_skip(aly_item, skip_start, skip_end)) {
            need_verify = OG_TRUE;
        }

        if (!need_verify) {
            continue;
        }

        if (dtc_read && partial_read && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress &&
            !dtc_rcy_gbp_partial_item_need_verify(session, aly_item->page_id, verify_node_id,
                                                  aly_item->lfn, expect_lsn)) {
            continue;
        }

        in_window++;
        already_verified = (bool32)(!dtc_read && aly_item->is_verified > 0);
        verified = already_verified;
        if (!verified) {
            local_lsn = gbp_get_local_verify_lsn(session, aly_item->page_id);
            verified = (bool32)(aly_item->best_lsn >= expect_lsn || local_lsn >= expect_lsn);
            if (verified) {
                aly_item->is_verified = OG_TRUE;
            }
        }
        if (verified && dtc_read && partial_read && g_dtc != NULL && DTC_RCY_CONTEXT->in_progress) {
            dtc_rcy_gbp_partial_mark_verified(session, aly_item->page_id, verify_node_id, aly_item->lsn);
        }
        if (!verified) {
            miss_cnt++;
            if (sample < 16) {
                OG_LOG_RUN_WAR("[GBP] verify miss sample[%u]: page %u-%u node=%u lfn=%llu first_node=%u "
                               "first_lfn=%llu verified=%u best_lsn=%llu expect_lsn=%llu best_source_node=%u "
                               "seen_bitmap=0x%llx local_lsn=%llu touch0=%u:%llu-%llu touch1=%u:%llu-%llu",
                               sample, aly_item->page_id.file, aly_item->page_id.page,
                               verify_node_id, (uint64)aly_item->lfn, (uint32)aly_item->first_node_id,
                               (uint64)aly_item->first_lfn, (uint32)aly_item->is_verified,
                               (uint64)aly_item->best_lsn, (uint64)expect_lsn,
                               (uint32)aly_item->best_source_node, (uint64)aly_item->seen_node_bitmap,
                               (uint64)local_lsn,
                               (uint32)GBP_ALY_TOUCH_NODE(aly_item->touch_min[0]),
                               (uint64)GBP_ALY_TOUCH_LFN(aly_item->touch_min[0]),
                               (uint64)GBP_ALY_TOUCH_LFN(aly_item->touch_max[0]),
                               (uint32)GBP_ALY_TOUCH_NODE(aly_item->touch_min[1]),
                               (uint64)GBP_ALY_TOUCH_LFN(aly_item->touch_min[1]),
                               (uint64)GBP_ALY_TOUCH_LFN(aly_item->touch_max[1]));
                sample++;
            }
        }
         knl_panic_log(verified, "[GBP] page %u-%u is not pulled, instance must exit",
                       aly_item->page_id.file, aly_item->page_id.page);
     }
    OG_LOG_RUN_INF("[GBP] verify summary: skip_window=[%llu,%llu) skipped_lfn_total=%llu "
                   "items=%u miss=%u required_cache_built=%u required_cache_items=%u scanned=%u",
                   (uint64)skip_start, (uint64)skip_end, skipped_lfn_total, in_window, miss_cnt,
                   (uint32)gbp_context->dtc_planned_required_built,
                   gbp_context->dtc_planned_required_count, scan_count);
 }

 /*
  * after pull all GBP pages to local buffer or db start, kernel notify GBP server to stop send page.
  * then close all temp connections with GBP
  */
static void gbp_knl_end_read_internal(knl_session_t *session, bool32 verify_pages, const char *reason)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    log_context_t *redo = &session->kernel->redo_ctx;
    uint32 gbp_proc_id = session->gbp_queue_index - 1;
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

     gbp_context->gbp_read_completed = OG_TRUE;
     gbp_context->gbp_end_read_time = cm_now();
    worker_wall_ms = (uint64)((gbp_context->gbp_end_read_time - gbp_context->gbp_begin_read_time) /
                              MICROSECS_PER_MILLISEC);
    workers_done_time = gbp_context->gbp_read_workers_done_time;
    if (workers_done_time == 0 || workers_done_time > gbp_context->gbp_end_read_time) {
        workers_done_time = gbp_context->gbp_end_read_time;
    }
    worker_active_ms = (uint64)((workers_done_time - gbp_context->gbp_begin_read_time) / MICROSECS_PER_MILLISEC);
    owner_gap_ms = (uint64)((gbp_context->gbp_end_read_time - workers_done_time) / MICROSECS_PER_MILLISEC);

    stage_begin = cm_now();
    for (lock_id = 0; lock_id < OG_GBP_RD_LOCK_COUNT; lock_id++) {
        cm_spin_lock(&gbp_context->buf_read_lock[lock_id], NULL); // lock 8 gbp read locks
    }
    lock_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();

    if (verify_pages) {
        gbp_verify_skiped_redo_pages(session);
    } else {
        OG_LOG_RUN_WAR("[GBP] skip final verify during read phase cleanup: reason=%s",
                       (reason == NULL) ? "unknown" : reason);
    }
    verify_us = (uint64)(cm_now() - stage_begin);
    stage_begin = cm_now();

    /*
     * READ_END follows READ_BEGIN/PAGE_READ/BATCH_READ on pipe_temp. Hold buf_read_lock[] first, then fisrt_pipe_lock
     * Use the same order as buf_load_page_from_GBP (buf_read then pull_one_page) to avoid deadlock.
     */
    if (gbp_is_multi_node_rcy(session)) {
        if (gbp_notify_dtc_read_phase(session, MSG_GBP_READ_END) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[GBP] failed to notify DTC GBP read page end");
        }
    } else {
        gbp_buf_manager_t *mgr = &gbp_context->gbp_buf_manager[gbp_proc_id];
        cm_spin_lock(&mgr->fisrt_pipe_lock, NULL);
        if (gbp_notify_msg(session, MSG_GBP_READ_END, gbp_proc_id, NULL) != OG_SUCCESS) {
            OG_LOG_RUN_WAR("[GBP] failed to notify GBP read page end");
        }
        cm_spin_unlock(&mgr->fisrt_pipe_lock);
    }
    notify_end_us = (uint64)(cm_now() - stage_begin);

     /* concurrency with buf_load_page_from_GBP */
     redo->rcy_with_gbp = OG_FALSE;

     for (lock_id = OG_GBP_RD_LOCK_COUNT - 1; lock_id >= 0; lock_id--) {
         cm_spin_unlock(&gbp_context->buf_read_lock[lock_id]); // unlock 8 gbp read locks
     }

    /* when read from GBP end, stop temp connections */
    stage_begin = cm_now();
    gbp_stop_temp_connection(session, gbp_context);
    gbp_clear_dtc_read_epoch(gbp_context);
    cleanup_us = (uint64)(cm_now() - stage_begin);
    total_us = (uint64)(cm_now() - gbp_context->gbp_begin_read_time);
    gbp_log_read_skip_summary(gbp_context);
    gbp_log_read_diag_summary(gbp_context);
    gbp_log_read_anomaly_summary(gbp_context);
    OG_LOG_RUN_INF("[GBP] read phase summary: pages=%llu errors=%llu worker_active_ms=%llu owner_gap_ms=%llu "
                   "skipped_lfn_total=%llu lock_us=%llu verify_us=%llu verify_pages=%u read_end_notify_us=%llu "
                   "cleanup_us=%llu total_us=%llu reason=%s",
                   (uint64)cm_atomic_get(&gbp_context->gbp_read_pages),
                   (uint64)cm_atomic_get(&gbp_context->gbp_read_errors),
                   worker_active_ms, owner_gap_ms, gbp_dtc_read_skip_lfn_total(gbp_context),
                   lock_us, verify_us, (uint32)verify_pages, notify_end_us, cleanup_us, total_us,
                   (reason == NULL) ? "finish" : reason);
    (void)worker_wall_ms;
}

void gbp_knl_end_read(knl_session_t *session)
{
    gbp_knl_end_read_internal(session, OG_TRUE, "finish");
}

static void gbp_knl_finish_dtc_read_internal(knl_session_t *session, bool32 verify_pages, const char *reason)
{
    gbp_context_t *gbp_context = &session->kernel->gbp_context;
    date_t begin_time;
    uint64 wait_us;

    if (!gbp_context->dtc_read_active && gbp_context->dtc_read_node_count == 0) {
        return;
    }

    begin_time = cm_now();
    while (gbp_context->gbp_read_thread_num > 0) {
        cm_sleep(1);
    }
    wait_us = (uint64)(cm_now() - begin_time);
    gbp_context->dtc_read_workers_done = OG_TRUE;
    if (gbp_context->gbp_read_workers_done_time == 0) {
        gbp_context->gbp_read_workers_done_time = cm_now();
    }
    OG_LOG_RUN_INF("[GBP] DTC recovery owner finishes read phase: wait_workers_us=%llu reason=%s",
                   wait_us, (reason == NULL) ? "finish" : reason);
    gbp_knl_end_read_internal(session, verify_pages, reason);
}

void gbp_knl_finish_dtc_read(knl_session_t *session)
{
    gbp_knl_finish_dtc_read_internal(session, OG_TRUE, "finish");
}

void gbp_knl_abort_dtc_read(knl_session_t *session)
{
    gbp_knl_finish_dtc_read_internal(session, OG_FALSE, "abort");
}

 /*
  * init gbp process when db start
  * 1. start gbp background workers, which process dirty pages between kernel and GBP
  * 2. start gbp_agent_proc, which maintains the connections with GBP
  */
 status_t gbp_agent_start(knl_session_t *session)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;
     uint32 buf_size = MAX(GBP_MAX_REQ_BUF_SIZE, GBP_MAX_RESP_BUF_SIZE) * OG_GBP_SESSION_COUNT;
     errno_t ret;

     ret = memset_sp(gbp_context, sizeof(gbp_context_t), 0, sizeof(gbp_context_t));
     knl_securec_check(ret);

     gbp_context->gbp_read_completed = OG_TRUE;

     if (cm_aligned_malloc((int64)buf_size, "gbp pipe buffer", &gbp_context->pipe_buf) != OG_SUCCESS) {
         return OG_ERROR;
     }

     if (gbp_snapshot_pool_init(session) != OG_SUCCESS) {
         cm_aligned_free(&gbp_context->pipe_buf);
         return OG_ERROR;
     }

     if (gbp_aly_mem_init(session) != OG_SUCCESS) { // redo analysis memory, free when gbp_agent_proc quit
         gbp_snapshot_pool_free(session);
         cm_aligned_free(&gbp_context->pipe_buf);
         return OG_ERROR;
     }

     if (gbp_agent_start_client(session) != OG_SUCCESS) {
         gbp_agent_stop_client(session); // release gbp_bg_procs which have been created
         gbp_drain_send_queues(session);
         gbp_snapshot_pool_free(session);
         cm_aligned_free(&gbp_context->pipe_buf);
         gbp_aly_mem_free(session);
         return OG_ERROR;
     }

     if (cm_create_thread(gbp_agent_proc, 0, session, &gbp_context->gbp_agent_thread) != OG_SUCCESS) {
         OG_LOG_RUN_ERR("[GBP] gbp agent thread create failed");
         gbp_agent_stop_client(session);
         gbp_drain_send_queues(session);
         gbp_snapshot_pool_free(session);
         cm_aligned_free(&gbp_context->pipe_buf);
         gbp_aly_mem_free(session);
         return OG_ERROR;
     }

     return OG_SUCCESS;
 }

 void gbp_agent_close(knl_session_t *session)
 {
     gbp_context_t *gbp_context = &session->kernel->gbp_context;

     cm_close_thread(&gbp_context->gbp_agent_thread);
 }

 /* ------------------------ Log analysis fuctions  ------------------------------- */
 status_t gbp_aly_mem_init(knl_session_t *session)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;
     gbp_analyse_bucket_t *free_list = &ctx->gbp_aly_free_list;
     int64 buf_size = GBP_ALY_MAX_ITEM_SIZE + GBP_ALY_MAX_BUCKET_SIZE; // 176M
     errno_t ret;

     if (!KNL_GBP_ENABLE(session->kernel)) {
         OG_LOG_RUN_INF("[GBP] gbp is off, log analysis memory will not malloc");
         return OG_SUCCESS;
     }

     if (ctx->gbp_aly_items == NULL) { // fisrt alloc memory at db_mount, free memory at db_close
         if (cm_aligned_malloc(buf_size, "log analysis", &ctx->gbp_aly_mem) != OG_SUCCESS) {
             return OG_ERROR;
         }
         ctx->gbp_aly_items = (gbp_analyse_item_t *)ctx->gbp_aly_mem.aligned_buf;
         ctx->gbp_aly_buckets = (gbp_analyse_bucket_t *)(ctx->gbp_aly_mem.aligned_buf + GBP_ALY_MAX_ITEM_SIZE);
     }

     ret = memset_sp(ctx->gbp_aly_items, GBP_ALY_MAX_ITEM_SIZE, 0, GBP_ALY_MAX_ITEM_SIZE); // 160M
     knl_securec_check(ret);
     ret = memset_sp(ctx->gbp_aly_buckets, GBP_ALY_MAX_BUCKET_SIZE, 0, GBP_ALY_MAX_BUCKET_SIZE); // 16M
     knl_securec_check(ret);

     free_list->count = GBP_ALY_MAX_ITEM;
     free_list->first = &ctx->gbp_aly_items[0];
     for (uint32 i = 0; i < GBP_ALY_MAX_ITEM - 1; i++) {
         ctx->gbp_aly_items[i].next = &ctx->gbp_aly_items[i + 1]; // init free list
     }

     return OG_SUCCESS;
 }

 /* free memory at db_close or alter system set USE_GBP = FALSE */
 void gbp_aly_mem_free(knl_session_t *session)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;
     gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;

     while (aly->is_started && !aly->is_done) {
         cm_sleep(1); // wait gbp_aly_proc exit
     }

     aly->is_started = OG_FALSE;
     gbp_clear_dtc_planned_required_items(&session->kernel->gbp_context);
     cm_aligned_free(&ctx->gbp_aly_mem);
     ctx->gbp_aly_items = NULL;
     ctx->gbp_aly_buckets = NULL;
 }

 gbp_analyse_item_t *gbp_aly_pop_free_item(knl_session_t *session)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;
     gbp_analyse_bucket_t *free_list = &ctx->gbp_aly_free_list;
     gbp_analyse_item_t *item = NULL;

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
 void gbp_aly_recycle_old_item(knl_session_t *session, gbp_analyse_bucket_t *bucket)
 {
     gbp_analyse_bucket_t *free_list = &session->kernel->redo_ctx.gbp_aly_free_list;
     gbp_analyse_item_t *item = NULL;
     gbp_analyse_item_t *prev = NULL;
     gbp_analyse_item_t *next = NULL;

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
            for (uint32 i = 0; i < GBP_ALY_TOUCH_SLOT_COUNT; i++) {
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

 void gbp_aly_do_recycle(knl_session_t *session, gbp_analyse_item_t **new_item)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;
     gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;
     date_t now_time = g_timer()->now;
     date_t last_time = MIN(aly->last_recycle_time, now_time);
     if ((now_time - last_time) < GBP_RECYCLE_TIMEOUT) {
         return;
     }

     for (uint32 i = 0; i < GBP_ALY_MAX_FILE * GBP_ALY_MAX_BUCKET_PER_FILE; i++) {
         gbp_aly_recycle_old_item(session, &ctx->gbp_aly_buckets[i]); // try recycle all gbp aly buckets
     }
     aly->last_recycle_time = now_time;
     *new_item = gbp_aly_pop_free_item(session);
     OG_LOG_DEBUG_WAR("[GBP] free all gbp aly buckets");
 }

static inline void gbp_aly_set_item(gbp_analyse_item_t *item, uint64 lsn, uint64 lfn)
{
    item->lsn = lsn;
    item->lfn = lfn;
    item->best_lsn = 0;
    item->seen_node_bitmap = 0;
    item->best_source_node = OG_INVALID_ID32;
    item->node_id = OG_INVALID_ID32;
}

static inline void gbp_aly_set_first_touch(gbp_analyse_item_t *item, uint64 lfn, uint32 node_id)
{
    item->first_lfn = lfn;
    item->first_node_id = node_id;
    item->first_reserved = 0;
}

static inline void gbp_aly_reset_touch(gbp_analyse_item_t *item)
{
    for (uint32 i = 0; i < GBP_ALY_TOUCH_SLOT_COUNT; i++) {
        item->touch_min[i] = 0;
        item->touch_max[i] = 0;
    }
}

static void gbp_aly_update_touch(knl_session_t *session, gbp_analyse_item_t *item, uint64 lfn, uint32 node_id,
    page_id_t page_id)
{
    uint32 empty_slot = OG_INVALID_ID32;

    for (uint32 i = 0; i < GBP_ALY_TOUCH_SLOT_COUNT; i++) {
        if (item->touch_min[i] == 0) {
            if (empty_slot == OG_INVALID_ID32) {
                empty_slot = i;
            }
            continue;
        }

        if (GBP_ALY_TOUCH_NODE(item->touch_min[i]) != node_id) {
            continue;
        }

        if (lfn < GBP_ALY_TOUCH_LFN(item->touch_min[i])) {
            item->touch_min[i] = GBP_ALY_PACK_TOUCH(node_id, lfn);
        }
        if (lfn > GBP_ALY_TOUCH_LFN(item->touch_max[i])) {
            item->touch_max[i] = GBP_ALY_PACK_TOUCH(node_id, lfn);
        }
        return;
    }

    if (empty_slot != OG_INVALID_ID32) {
        item->touch_min[empty_slot] = GBP_ALY_PACK_TOUCH(node_id, lfn);
        item->touch_max[empty_slot] = GBP_ALY_PACK_TOUCH(node_id, lfn);
        return;
    }

    if (!session->kernel->redo_ctx.gbp_aly_result.gbp_unsafe) {
        OG_LOG_RUN_WAR("[GBP] gbp unsafe: touch range slots overflow page %u-%u node=%u lfn=%llu",
                       page_id.file, page_id.page, node_id, lfn);
    }
    gbp_set_unsafe(session, RD_TYPE_END);
}

/* Tag every analyzed page with the redo stream that produced this touch. */
uint32 gbp_aly_curr_node_id(knl_session_t *session)
{
    if (DB_IS_CLUSTER(session) && g_dtc != NULL && DTC_RCY_CONTEXT->node_count > 0) {
        return (uint32)DTC_RCY_CONTEXT->curr_node;
    }
    return (uint32)session->kernel->id;
}

static void gbp_aly_set_page_lsn_with_node(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn,
    uint32 curr_node_id)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    gbp_analyse_item_t *item = NULL;
    gbp_analyse_item_t *reuse_item = NULL;
    gbp_analyse_item_t *new_item = NULL;
    uint32 file_hash = page_id.file % GBP_ALY_MAX_FILE;
    uint32 page_hash = page_id.page % GBP_ALY_MAX_BUCKET_PER_FILE;
    gbp_analyse_bucket_t *bucket = &ctx->gbp_aly_buckets[file_hash * GBP_ALY_MAX_BUCKET_PER_FILE + page_hash];

    item = bucket->first;
    while (item != NULL) {
        knl_panic_log(item->lsn != OG_INVALID_LSN, "lsn is invalid, panic info: page %u-%u lsn %llu", page_id.file,
                      page_id.page, item->lsn);
        if (IS_SAME_PAGID(item->page_id, page_id)) {
            if (item->first_lfn == 0) {
                gbp_aly_set_first_touch(item, lfn, curr_node_id);
            }
            gbp_aly_update_touch(session, item, lfn, curr_node_id, page_id);
            /*
             * DTC merges multiple redo streams by global LSN, while each stream owns an independent LFN axis.
             * Keep expect_lsn in page-version order; lower-LSN touches still update per-node touch ranges only.
             */
            if (lsn >= item->lsn) {
                gbp_aly_set_item(item, lsn, lfn);
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
        gbp_aly_set_item(reuse_item, lsn, lfn);
        reuse_item->page_id = page_id;
        gbp_aly_reset_touch(reuse_item);
        gbp_aly_set_first_touch(reuse_item, lfn, curr_node_id);
        gbp_aly_update_touch(session, reuse_item, lfn, curr_node_id, page_id);
        reuse_item->node_id = curr_node_id;
        ctx->replay_stat.analyze_new_pages++;
        return;
    }

    /* if same page id item or reuse item is not found, add one free item */
    new_item = gbp_aly_pop_free_item(session);
    if (new_item == NULL) {
        gbp_aly_do_recycle(session, &new_item);
    }

    if (new_item != NULL) {
        new_item->next = bucket->first;
        bucket->first = new_item;
        bucket->count++;
        gbp_aly_set_item(new_item, lsn, lfn);
        new_item->page_id = page_id;
        gbp_aly_reset_touch(new_item);
        gbp_aly_set_first_touch(new_item, lfn, curr_node_id);
        gbp_aly_update_touch(session, new_item, lfn, curr_node_id, page_id);
        new_item->node_id = curr_node_id;
        ctx->replay_stat.analyze_new_pages++;
        return;
    }

    if (!ctx->gbp_aly_result.gbp_unsafe) {
        OG_LOG_RUN_WAR("[GBP] gbp unsafe because of analyze overflow, page %u-%u", page_id.file, page_id.page);
    }
    gbp_set_unsafe(session, RD_TYPE_END);
}

void gbp_aly_set_page_lsn(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn)
{
    gbp_aly_set_page_lsn_with_node(session, page_id, lsn, lfn, gbp_aly_curr_node_id(session));
}

uint32 gbp_aly_free_space_percent(knl_session_t *session)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;

     if (ctx->gbp_aly_items == NULL) {
         return 0;
     }

     return (ctx->gbp_aly_free_list.count * 100 / GBP_ALY_MAX_ITEM); // calculate percent
 }

 gbp_analyse_item_t *gbp_aly_get_page_item(knl_session_t *session, page_id_t page_id)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;
     gbp_analyse_item_t *item = NULL;
     uint32 file_hash = page_id.file % GBP_ALY_MAX_FILE;
     uint32 page_hash = page_id.page % GBP_ALY_MAX_BUCKET_PER_FILE;
     gbp_analyse_bucket_t *bucket = &ctx->gbp_aly_buckets[file_hash * GBP_ALY_MAX_BUCKET_PER_FILE + page_hash];

     item = bucket->first;
     while (item != NULL) {
         if (IS_SAME_PAGID(item->page_id, page_id)) {
             return item;
         }

         item = item->next;
     }

     return NULL;
 }

 uint64 gbp_aly_get_page_lsn(knl_session_t *session, page_id_t page_id)
 {
     gbp_analyse_item_t *item = NULL;

     if (session->kernel->gbp_context.gbp_agent_thread.closed) {
         return OG_INVALID_LSN;
     }

     item = gbp_aly_get_page_item(session, page_id);
     return (item == NULL) ? OG_INVALID_LSN : item->lsn;
 }

 /*
  * analyze redo log, only running when GBP is enabled. it dose not replay redo expect txn page
  * it will record all page's latest lsn
  */
 static status_t gbp_aly_analyze(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
                                 uint32 block_size)
 {
     bool32 need_more = OG_FALSE;

     if (rcy_analysis(session, point, data_size, batch, block_size, &need_more) != OG_SUCCESS) {
         OG_LOG_RUN_INF("[GBP] failed to analyze log at point [%u-%u/%u/%llu]",
                        point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
         return OG_ERROR;
     }

     if (!need_more) {
         OG_LOG_RUN_INF("[GBP] failed to analyze log at point [%u-%u/%u/%llu], no more log needed",
                        point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
         return OG_ERROR;
     }

     return OG_SUCCESS;
 }

 /* like lrpl, gbp analyze proc will read and analyze all standby redo log */
 status_t gbp_aly_perform(knl_session_t *session, log_point_t *point)
 {
     gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;
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
             OG_LOG_RUN_INF("[GBP] failed to prepare archive log at point [%u-%u/%u/%llu]",
                            point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
             return OG_ERROR;
         }
         if (reset) {
             return OG_SUCCESS;
         }

         if (rcy_load_from_arch(session, point, &data_size, &aly_ctx->arch_file, &aly_ctx->read_buf) != OG_SUCCESS) {
             OG_LOG_RUN_INF("[GBP] failed to load archive log at point [%u-%u/%u/%llu]",
                            point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
             return OG_ERROR;
         }
         block_size = (uint32)aly_ctx->arch_file.head.block_size;
     } else {
         if (rcy_load_from_online(session, file_id, point, &data_size, aly_ctx->log_handle + file_id,
                                  &aly_ctx->read_buf) != OG_SUCCESS) {
             OG_LOG_RUN_INF("[GBP] failed to load online log[%u] at point [%u-%u/%u/%llu]",
                            file_id, point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
             return OG_ERROR;
         }
         block_size = log->files[file_id].ctrl->block_size;
     }

     log_batch_t *batch = (log_batch_t *)aly_ctx->read_buf.aligned_buf;
     if (gbp_aly_analyze(session, point, data_size, batch, block_size) != OG_SUCCESS) {
         return OG_ERROR;
     }
     return OG_SUCCESS;
 }

 static void gbp_free_aly_proc_context(knl_session_t *aly_session, gbp_aly_ctx_t *aly_ctx)
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
     gbp_release_bg_session(aly_session);
     aly_ctx->sid = OG_INVALID_ID32;
 }

 /*
  * log analysis thread, run when gbp enabled on standby
  * like lrpl, it read and analyze redo log to get page latest lsn
  */
 static void gbp_aly_proc(thread_t *thread)
 {
     knl_session_t *session = (knl_session_t *)thread->argument;
     gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;
     log_context_t *redo_ctx = &session->kernel->redo_ctx;
     bool32 sleep_needed = OG_FALSE;

     cm_set_thread_name("gbp_aly");
     OG_LOG_RUN_INF("[GBP] gbp aly thread started");
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

         if (sleep_needed && gbp_promote_triggered(session->kernel)) {
             OG_LOG_RUN_INF("[GBP] log analysis failover triggered");

             redo_ctx->redo_end_point = aly->curr_point;
             if (gbp_pre_check(session, redo_ctx->redo_end_point)) {
                 gbp_knl_check_end_point(session);
             }
             break;
         }
         if (sleep_needed) {
             cm_sleep(10);
         }

         if (!lrpl_need_replay(session, &aly->curr_point)) {
             sleep_needed = OG_TRUE;
             continue;
         }

         if (gbp_aly_perform(session, &aly->curr_point) != OG_SUCCESS) {
             redo_ctx->redo_end_point = aly->curr_point;
             aly->has_gap = OG_TRUE;
             OG_LOG_RUN_WAR("[GBP] gbp analysis failed");
             break;
         }

         sleep_needed = OG_FALSE;
     }

     cm_close_thread(&aly->page_bucket.thread);
     aly->is_done = OG_TRUE;
     aly->end_time = cm_now();
     OG_LOG_RUN_INF("[GBP] log analysis end with log point: rst_id %u asn %u lfn %llu block_id %u",
                    aly->curr_point.rst_id, aly->curr_point.asn, (uint64)aly->curr_point.lfn,
                    aly->curr_point.block_id);

     gbp_free_aly_proc_context(session, aly);
     KNL_SESSION_CLEAR_THREADID(session);
     thread->closed = OG_TRUE;
 }

 void gbp_aly_page_proc(thread_t *thread)
 {
     knl_session_t *session = (knl_session_t *)thread->argument;
     gbp_aly_ctx_t *aly = &session->kernel->gbp_aly_ctx;
     gbp_page_bucket_t *bucket = &aly->page_bucket;
     date_t last_time = g_timer()->now;
     gbp_aly_page_t ctrl;
     uint32 tail;

     cm_set_thread_name("gbp_page_proc");
     OG_LOG_RUN_INF("[GBP] gbp page thread started");
     for (;;) {
         if (bucket->head == bucket->tail) {
             if (thread->closed) {
                 break;
             }

             if (g_timer()->now - last_time > RCY_SLEEP_TIME_THRESHOLD) {
                 cm_sleep(10);
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
            gbp_aly_set_page_lsn_with_node(session, ctrl.page_id, ctrl.lsn, ctrl.lfn, ctrl.node_id);
            bucket->head = (bucket->head + 1) % bucket->count;
        }
     }
     OG_LOG_RUN_INF("[GBP] gbp page thread closed");
 }

 /* init gbp analyze memory and start gbp analyze proc */
 status_t gbp_aly_init(knl_session_t *session)
 {
     gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;
     knl_session_t *aly_session = NULL;

     errno_t ret = memset_sp(aly_ctx, sizeof(gbp_aly_ctx_t), 0, sizeof(gbp_aly_ctx_t));
     knl_securec_check(ret);

     aly_ctx->arch_file.handle = INVALID_FILE_HANDLE;
     for (uint32 i = 0; i < OG_MAX_LOG_FILES; i++) {
         aly_ctx->log_handle[i] = INVALID_FILE_HANDLE;
     }

     if (gbp_alloc_bg_session(0, &aly_session) != OG_SUCCESS) {
         return OG_ERROR;
     }

     /* redo analysis memory is alloced in gbp_agent_start when db_mount, if switchover as standby, need reset memory */
     if (gbp_aly_mem_init(session) != OG_SUCCESS) {
         gbp_free_aly_proc_context(aly_session, aly_ctx);
         return OG_ERROR;
     }

     if (cm_aligned_malloc(OG_MAX_BATCH_SIZE, "log analysis read buffer", &aly_ctx->read_buf) != OG_SUCCESS) {
         gbp_free_aly_proc_context(aly_session, aly_ctx);
         return OG_ERROR;
     }

     if (cm_aligned_malloc((int64)session->kernel->attr.lgwr_cipher_buf_size, "log analysis decrypt buffer",
                           &aly_ctx->log_decrypt_buf) != OG_SUCCESS) {
         gbp_free_aly_proc_context(aly_session, aly_ctx);
         return OG_ERROR;
     }

     if (cm_aligned_malloc((int64)GBP_ALY_PAGE_BUCKET_SIZE, "log analysis bucket buffer",
                           &aly_ctx->bucket_buf) != OG_SUCCESS) {
         gbp_free_aly_proc_context(aly_session, aly_ctx);
         return OG_ERROR;
     }

     aly_ctx->sid = aly_session->id;
     aly_ctx->page_bucket.first = (gbp_aly_page_t *)aly_ctx->bucket_buf.aligned_buf;
     aly_ctx->page_bucket.count = GBP_ALY_PAGE_COUNT;
     aly_ctx->page_bucket.head = 0;
     aly_ctx->page_bucket.tail = 0;
     aly_ctx->page_bucket.lock = 0;
     aly_ctx->begin_time = cm_now();

     if (cm_create_thread(gbp_aly_page_proc, 0, aly_session, &aly_ctx->page_bucket.thread) != OG_SUCCESS) {
         gbp_free_aly_proc_context(aly_session, aly_ctx);
         return OG_ERROR;
     }

     if (cm_create_thread(gbp_aly_proc, 0, aly_session, &aly_ctx->thread) != OG_SUCCESS) {
         cm_close_thread(&aly_ctx->page_bucket.thread);
         gbp_free_aly_proc_context(aly_session, aly_ctx);
         return OG_ERROR;
     }

     return OG_SUCCESS;
 }

 void gbp_aly_close(knl_session_t *session)
 {
     gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;

     aly_ctx->is_closing = OG_TRUE;
     cm_close_thread(&aly_ctx->thread);
     OG_LOG_RUN_INF("[GBP] gbp aly thread is closed successfully");
 }

 /* some redo type is unsafe to gbp, when find these redo, set gbp unsafe status and max unsafe lsn */
 void gbp_aly_unsafe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn)
 {
     log_context_t *ctx = &session->kernel->redo_ctx;

     ctx->gbp_aly_result.unsafe_max_lsn = lsn;

     if (!ctx->gbp_aly_result.gbp_unsafe) {
         OG_LOG_RUN_WAR("[GBP] gbp unsafe because of redo log type: %u, lsn: %llu", log->type, lsn);
         if (log->type == RD_LOGIC_OPERATION) {
             OG_LOG_RUN_WAR("[GBP] unsafe logic type: %u", *((logic_op_t *)log->data));
         }
     }
     gbp_set_unsafe(session, log->type);
 }

 void gbp_aly_safe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn)
 {
     knl_panic(session->curr_page_ctrl == NULL || !BUF_IS_RESIDENT(session->curr_page_ctrl));
 }

 /* get last point of online redo */
 status_t gbp_aly_get_file_end_point(knl_session_t *session, log_point_t *point, uint16 file_id)
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
     point->lfn = 0; // do not need show lfn in gbp view dv_gbp_analyze_info
     return OG_SUCCESS;
 }

 void gbp_record_promote_time(knl_session_t *session, const char *stage, const char *promote_type)
 {
     log_context_t *log = &session->kernel->redo_ctx;
     lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

     if (cm_str_equal_ins(stage, "log analyze")) {
         OG_LOG_RUN_INF("[GBP] [%s] Log analyze time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                        promote_type, (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                        (uint64)log->redo_end_point.rst_id, log->redo_end_point.asn,
                        (uint64)log->redo_end_point.lfn);
     } else {
         OG_LOG_RUN_INF("[GBP] [%s] LRPL replay used time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                        promote_type, (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                        (uint64)lrpl->curr_point.rst_id, lrpl->curr_point.asn, (uint64)lrpl->curr_point.lfn);
     }

     log->promote_temp_time = KNL_NOW(session);
 }

 /*
  * SQL DEBUG: raw PAGE_READ to GBP (verify demo / wire only; does not apply page to buffer pool).
  */
 status_t knl_gbp_sql_demo_read_page(knl_session_t *session, uint16 file_no, uint32 page_no, uint32 *out_result)
 {
     gbp_context_t *gbp_context = NULL;
     gbp_buf_manager_t *manager = NULL;
     gbp_read_req_t request;
     gbp_read_resp_t response;
     uint32 gbp_proc_id;
     cs_pipe_t *pipe = NULL;
     bool32 use_temp_pipe = OG_FALSE;
     errno_t err;

     if (session == NULL || out_result == NULL) {
         return OG_ERROR;
     }
     *out_result = GBP_READ_RESULT_ERROR;

     if (!KNL_GBP_ENABLE(session->kernel)) {
         return OG_ERROR;
     }

     gbp_context = &session->kernel->gbp_context;
     gbp_proc_id = page_no % OG_GBP_SESSION_COUNT;
     manager = &gbp_context->gbp_buf_manager[gbp_proc_id];

     cm_spin_lock(&manager->fisrt_pipe_lock, NULL);
     if (!manager->is_connected) {
         cm_spin_unlock(&manager->fisrt_pipe_lock);
         return OG_ERROR;
     }

    /*
     * Always use pipe_const for this SQL debug path. Preferring pipe_temp could pick a stale fd after pipe_const
     * reconnect (gbp_init_connection memsets only pipe_const; gbp_stop_temp_connection may not have run), so
     * send/wait fails while the new const is healthy; demo sees no PAGE_READ and pull_gbp_page_demo returns -1.
     * Same fisrt_pipe_lock as PAGE_WRITE / HB / recovery temp paths on this queue.
     */
    pipe = gbp_get_client_pipe(gbp_context, gbp_proc_id, OG_FALSE);
    use_temp_pipe = OG_FALSE;
     err = memset_sp(&request, sizeof(request), 0, sizeof(request));
     knl_securec_check(err);
     GBP_SET_MSG_HEADER(&request, GBP_REQ_PAGE_READ, sizeof(gbp_read_req_t), cs_get_socket_fd(pipe));
     request.header.queue_id = manager->queue_id;
     request.page_id = make_page_id(file_no, page_no);
     request.buf_pool_id = 0;

     if (gbp_knl_send_request(pipe, (char *)&request, use_temp_pipe ? NULL : manager) != OG_SUCCESS) {
         cm_spin_unlock(&manager->fisrt_pipe_lock);
         return OG_ERROR;
     }

     err = memset_sp(&response, sizeof(response), 0, sizeof(response));
     knl_securec_check(err);
     if (gbp_knl_wait_response(pipe, (char *)&response, sizeof(gbp_read_resp_t)) != OG_SUCCESS) {
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
