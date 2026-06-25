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
 * dtc_rbp_rt_aly.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_rbp_rt_aly.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_cluster_module.h"
#include "dtc_context.h"
#include "dtc_database.h"
#include "dtc_drc.h"
#include "cm_dbs_intf.h"
#include "cm_hash.h"
#include "knl_db_ctrl.h"
#include "knl_datafile.h"
#include "knl_rbp.h"
#include "knl_recovery.h"
#include "knl_space_base.h"
#include "knl_space_log.h"
#include "knl_buffer_log.h"
#include "dtc_rbp_rt_aly.h"

typedef enum en_dtc_rbp_rt_read_result {
    DTC_RBP_RT_READ_OK = 0,
    DTC_RBP_RT_READ_RETRY,
    DTC_RBP_RT_READ_UNSAFE,
} dtc_rbp_rt_read_result_t;

static status_t dtc_rbp_rt_init_local_sets(dtc_rbp_rt_aly_ctx_t *ctx);
static void dtc_rbp_rt_clear_local_sets(dtc_rbp_rt_aly_ctx_t *ctx);

#define DTC_RBP_RT_LOG_SAMPLE_LIMIT 5
#define DTC_RBP_RT_RECOVERY_NODE_COUNT 2
#define DTC_RBP_RT_QUEUE_ARRAY_COUNT 2
#define DTC_RBP_RT_UNSAFE_BATCH_QUEUE_SLOT 32
#define DTC_RBP_RT_UNSAFE_INVALID_COMMIT_SLOT 29
#define DTC_RBP_RT_UNSAFE_READ_PEER_CTRL_PRUNE 5
#define DTC_RBP_RT_UNSAFE_INVALID_EVENT_CHUNK_BATCH 33
#define DTC_RBP_RT_UNSAFE_EVENT_CHUNK_BACKLOG_TIMEOUT 34
#define DTC_RBP_RT_UNSAFE_EVENT_CHUNK_PENDING_UNDERFLOW 35
#define DTC_RBP_RT_UNSAFE_EVENT_CHUNK_INVALID_BATCH 36
#define DTC_RBP_RT_UNSAFE_PARSER_ANALYZE_BATCH_FAILED 25
#define DTC_RBP_RT_UNSAFE_OWNER_RECORD_PAGE_FAILED 37
#define DTC_RBP_RT_UNSAFE_RUNTIME_RESET_DRAIN_TIMEOUT 30
#define DTC_RBP_RT_UNSAFE_RUNTIME_RESET_LOCAL_INIT_FAILED 31
#define DTC_RBP_RT_UNSAFE_PEER_REDO_GAP 7
#define DTC_RBP_RT_UNSAFE_INIT_PEER_LOGSET_FAILED 9
#define DTC_RBP_RT_UNSAFE_READ_PEER_CTRL_FAILED 10
#define DTC_RBP_RT_UNSAFE_REFRESH_CURRENT_FILE_HEAD_FAILED 15
#define DTC_RBP_RT_UNSAFE_REFRESH_FILE_HEADS_FAILED 16
#define DTC_RBP_RT_UNSAFE_PEER_REDO_FILE_NOT_FOUND 11
#define DTC_RBP_RT_UNSAFE_REFRESH_NON_CURRENT_FILE_HEAD_FAILED 20
#define DTC_RBP_RT_UNSAFE_READ_PEER_REDO_FAILED 12
#define DTC_RBP_RT_UNSAFE_DRAIN_RUNTIME_QUEUE_TIMEOUT 28
#define DTC_RBP_RT_UNSAFE_STOP_RELEASE 13

static inline bool32 dtc_rbp_rt_enabled(knl_session_t *session)
{
    if (session == NULL || g_dtc == NULL || !DB_IS_CLUSTER(session)) {
        return OG_FALSE;
    }
    return (bool32)(KNL_RBP_ENABLE(session->kernel) && KNL_RBP_FOR_RECOVERY(session->kernel) &&
                    KNL_RBP_RT_ANALYSIS(session->kernel) &&
                    g_dtc->profile.node_count == DTC_RBP_RT_RECOVERY_NODE_COUNT &&
                    !cm_dbs_is_enable_dbs());
}

static void dtc_rbp_rt_atomic_list_init(dtc_rcy_atomic_list *list)
{
    list->begin = 0;
    list->end = 0;
    list->writed_end = 0;
}

static uint32 dtc_rbp_rt_atomic_list_pop(dtc_rcy_atomic_list *list)
{
    uint32 idx;
    int64 end;

    cm_spin_lock(&list->lock, NULL);
    end = cm_atomic_get(&list->end);
    if (cm_atomic_get(&list->begin) == end) {
        cm_spin_unlock(&list->lock);
        return OG_INVALID_INT32;
    }
    idx = list->array[cm_atomic_get(&list->begin) % DTC_RBP_RT_BATCH_QUEUE_COUNT];
    cm_atomic_inc(&list->begin);
    cm_spin_unlock(&list->lock);
    return idx;
}

static bool8 dtc_rbp_rt_atomic_list_push(dtc_rcy_atomic_list *list, uint32 val)
{
    int64 end;

    cm_spin_lock(&list->lock, NULL);
    end = cm_atomic_get(&list->end);
    list->array[end % DTC_RBP_RT_BATCH_QUEUE_COUNT] = val;
    cm_atomic_inc(&list->end);
    cm_spin_unlock(&list->lock);
    return OG_TRUE;
}

static uint64 dtc_rbp_rt_atomic_list_count(dtc_rcy_atomic_list *list)
{
    int64 begin;
    int64 end;

    cm_spin_lock(&list->lock, NULL);
    begin = cm_atomic_get(&list->begin);
    end = cm_atomic_get(&list->end);
    cm_spin_unlock(&list->lock);
    return (uint64)((end >= begin) ? (end - begin) : 0);
}

static void dtc_rbp_rt_mark_unsafe(dtc_rbp_rt_aly_ctx_t *ctx, uint64 reason, const char *detail)
{
    ctx->unsafe = OG_TRUE;
    ctx->unsafe_reason = (ctx->unsafe_reason == 0) ? reason : ctx->unsafe_reason;
    ctx->status = DTC_RBP_RT_UNSAFE;
    OG_LOG_RUN_WAR("[DTC RBP RT] mark unsafe, peer=%u reason=%llu detail=%s safe_lfn=%llu curr_lfn=%llu",
                   ctx->peer_node, ctx->unsafe_reason, (detail == NULL) ? "" : detail,
                   (uint64)ctx->safe_analyzed_point.lfn, (uint64)ctx->curr_point.lfn);
}

static void dtc_rbp_rt_reset_lfn_points(dtc_rbp_rt_aly_ctx_t *ctx)
{
    ctx->lfn_point_start = 0;
    ctx->lfn_point_count = 0;
}

static void dtc_rbp_rt_free_lfn_points(dtc_rbp_rt_aly_ctx_t *ctx)
{
    CM_FREE_PTR(ctx->lfn_points);
    ctx->lfn_point_capacity = 0;
    dtc_rbp_rt_reset_lfn_points(ctx);
}

static status_t dtc_rbp_rt_alloc_lfn_points(dtc_rbp_rt_aly_ctx_t *ctx)
{
    uint64 size = (uint64)DTC_RBP_RT_LFN_POINT_COUNT * sizeof(dtc_rbp_rt_lfn_point_t);
    errno_t ret;

    ctx->lfn_points = (dtc_rbp_rt_lfn_point_t *)malloc(size);
    if (ctx->lfn_points == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, size, "dtc rbp runtime lfn point map");
        return OG_ERROR;
    }
    ret = memset_sp(ctx->lfn_points, size, 0, size);
    knl_securec_check(ret);
    ctx->lfn_point_capacity = DTC_RBP_RT_LFN_POINT_COUNT;
    dtc_rbp_rt_reset_lfn_points(ctx);
    return OG_SUCCESS;
}

static void dtc_rbp_rt_record_lfn_point(dtc_rbp_rt_aly_ctx_t *ctx, log_batch_t *batch, const log_point_t *end_point)
{
    uint32 slot;
    dtc_rbp_rt_lfn_point_t *entry;

    if (ctx->lfn_points == NULL || ctx->lfn_point_capacity == 0 || batch == NULL ||
        batch->head.point.lfn == 0 || end_point == NULL) {
        return;
    }
    if (ctx->lfn_point_count < ctx->lfn_point_capacity) {
        slot = (ctx->lfn_point_start + ctx->lfn_point_count) % ctx->lfn_point_capacity;
        ctx->lfn_point_count++;
    } else {
        slot = ctx->lfn_point_start;
        ctx->lfn_point_start = (ctx->lfn_point_start + 1) % ctx->lfn_point_capacity;
    }
    entry = &ctx->lfn_points[slot];
    entry->lfn = batch->head.point.lfn;
    entry->point = *end_point;
}

static void dtc_rbp_rt_prune_lfn_points(dtc_rbp_rt_aly_ctx_t *ctx, uint64 prune_lfn)
{
    while (ctx->lfn_point_count > 0 && ctx->lfn_points != NULL) {
        dtc_rbp_rt_lfn_point_t *entry = &ctx->lfn_points[ctx->lfn_point_start];

        if (entry->lfn >= prune_lfn) {
            break;
        }
        ctx->lfn_point_start = (ctx->lfn_point_start + 1) % ctx->lfn_point_capacity;
        ctx->lfn_point_count--;
    }
}

static status_t dtc_rbp_rt_export_lfn_points(dtc_rbp_rt_aly_ctx_t *ctx)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    dtc_rbp_lfn_point_map_t *map;
    uint32 old_count;
    uint32 rt_count;
    uint32 keep_count = 0;
    uint64 size;
    dtc_rbp_lfn_point_entry_t *new_entries = NULL;
    errno_t ret;

    if (ctx->peer_node >= OG_MAX_INSTANCES || ctx->lfn_point_count == 0) {
        return OG_SUCCESS;
    }
    map = &dtc_rcy->rbp_lfn_point_maps[ctx->peer_node];
    old_count = map->count;
    rt_count = ctx->lfn_point_count;
    if (rt_count > 0) {
        uint32 last_idx = (ctx->lfn_point_start + rt_count - 1) % ctx->lfn_point_capacity;
        uint64 last_rt_lfn = ctx->lfn_points[last_idx].lfn;

        while (keep_count < old_count && map->entries[keep_count].lfn <= last_rt_lfn) {
            keep_count++;
        }
    }
    if (map->capacity < rt_count + (old_count - keep_count)) {
        size = (uint64)(rt_count + (old_count - keep_count)) * sizeof(dtc_rbp_lfn_point_entry_t);
        new_entries = (dtc_rbp_lfn_point_entry_t *)malloc(size);
        if (new_entries == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, size, "dtc rbp runtime exported lfn point map");
            return OG_ERROR;
        }
        if (old_count > keep_count) {
            ret = memcpy_sp(&new_entries[rt_count], size - (uint64)rt_count * sizeof(dtc_rbp_lfn_point_entry_t),
                            &map->entries[keep_count],
                            (uint64)(old_count - keep_count) * sizeof(dtc_rbp_lfn_point_entry_t));
            knl_securec_check(ret);
        }
        CM_FREE_PTR(map->entries);
        map->entries = new_entries;
        map->capacity = rt_count + (old_count - keep_count);
    } else if (old_count > keep_count) {
        size = (uint64)(old_count - keep_count) * sizeof(dtc_rbp_lfn_point_entry_t);
        ret = memmove_s(&map->entries[rt_count], (uint64)(map->capacity - rt_count) * sizeof(dtc_rbp_lfn_point_entry_t),
                        &map->entries[keep_count], size);
        knl_securec_check(ret);
    }
    for (uint32 i = 0; i < rt_count; i++) {
        uint32 idx = (ctx->lfn_point_start + i) % ctx->lfn_point_capacity;

        map->entries[i].lfn = ctx->lfn_points[idx].lfn;
        map->entries[i].point = ctx->lfn_points[idx].point;
    }
    map->count = rt_count + (old_count - keep_count);
    return OG_SUCCESS;
}

static void dtc_rbp_rt_close_files(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < OG_MAX_LOG_FILES; i++) {
        if (ctx->log_handle[i] == OG_INVALID_HANDLE) {
            continue;
        }
        if (ctx->rt_session != NULL) {
            logfile_set_t *log_set = LOGFILE_SET(ctx->rt_session, ctx->peer_node);

            if (i < log_set->logfile_hwm && log_set->items[i].ctrl != NULL) {
                cm_close_device(log_set->items[i].ctrl->type, &ctx->log_handle[i]);
            }
        }
        ctx->log_handle[i] = OG_INVALID_HANDLE;
    }
}

static status_t dtc_rbp_rt_init_peer_logset(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx)
{
    dtc_node_ctrl_t *ctrl;
    logfile_set_t *file_set;
    database_t *db = &session->kernel->db;
    char *buf = ctx->read_buf.aligned_buf;
    errno_t ret;

    if (dtc_read_node_ctrl(session, (uint8)ctx->peer_node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ctrl = dtc_get_ctrl(session, ctx->peer_node);
    file_set = LOGFILE_SET(session, ctx->peer_node);
    file_set->logfile_hwm = ctrl->log_hwm;
    file_set->log_count = ctrl->log_count;

    for (uint32 i = 0; i < file_set->logfile_hwm; i++) {
        log_file_t *file = &file_set->items[i];

        file->ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                             db->ctrl.log_segment, ctx->peer_node);
        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }
        if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_io_flag(session), &ctx->log_handle[i]) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RBP RT] failed to open peer redo file=%s peer=%u", file->ctrl->name, ctx->peer_node);
            return OG_ERROR;
        }
        if (cm_read_device(file->ctrl->type, ctx->log_handle[i], 0, buf,
                           CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RBP RT] failed to read peer redo head file=%s peer=%u", file->ctrl->name,
                           ctx->peer_node);
            return OG_ERROR;
        }
        if (log_verify_head_checksum(session, (log_file_head_t *)buf, file->ctrl->name) != OG_SUCCESS) {
            return OG_ERROR;
        }
        ret = memcpy_sp(&file->head, sizeof(log_file_head_t), buf, sizeof(log_file_head_t));
        knl_securec_check(ret);
    }
    ctx->curr_point = ctrl->rcy_point;
    ctx->begin_point = ctx->curr_point;
    ctx->safe_analyzed_point = ctx->curr_point;
    ctx->peer_prune_point = ctrl->rcy_point;
    ctx->rt_start_lfn = ctrl->rcy_point.lfn;
    return OG_SUCCESS;
}

static status_t dtc_rbp_rt_refresh_file_head(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx, uint32 file_id)
{
    logfile_set_t *log_set = LOGFILE_SET(session, ctx->peer_node);
    log_file_t *file;
    char *buf = ctx->read_buf.aligned_buf;
    errno_t ret;

    if (file_id >= log_set->logfile_hwm) {
        return OG_ERROR;
    }
    file = &log_set->items[file_id];
    if (LOG_IS_DROPPED(file->ctrl->flg) || ctx->log_handle[file_id] == OG_INVALID_HANDLE) {
        return OG_SUCCESS;
    }
    if (cm_read_device(file->ctrl->type, ctx->log_handle[file_id], 0, buf,
                       CM_CALC_ALIGN(sizeof(log_file_head_t), file->ctrl->block_size)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RBP RT] failed to refresh peer redo head file=%s peer=%u", file->ctrl->name,
                       ctx->peer_node);
        return OG_ERROR;
    }
    if (log_verify_head_checksum(session, (log_file_head_t *)buf, file->ctrl->name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ret = memcpy_sp(&file->head, sizeof(log_file_head_t), buf, sizeof(log_file_head_t));
    knl_securec_check(ret);
    return OG_SUCCESS;
}

static uint32 dtc_rbp_rt_get_file_by_point(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx, bool32 *is_curr)
{
    logfile_set_t *log_set = LOGFILE_SET(session, ctx->peer_node);
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, ctx->peer_node);
    log_point_t *point = &ctx->curr_point;

    *is_curr = OG_FALSE;
    for (uint32 i = 0; i < log_set->logfile_hwm; i++) {
        log_file_t *file = &log_set->items[i];

        if (LOG_IS_DROPPED(file->ctrl->flg)) {
            continue;
        }
        if (file->head.rst_id == point->rst_id && file->head.asn == point->asn) {
            *is_curr = (bool32)(i == ctrl->log_last);
            return i;
        }
    }
    return OG_INVALID_ID32;
}

static void dtc_rbp_rt_next_file(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx)
{
    dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, ctx->peer_node);
    log_point_t *point = &ctx->curr_point;

    point->asn++;
    point->block_id = 0;
    if (point->rst_id < ctrl->lrp_point.rst_id && point->asn > ctrl->last_asn) {
        point->rst_id++;
    }
}

static uint64 dtc_rbp_rt_read_limit_by_lrp(log_file_t *file, const log_point_t *lrp_point)
{
    uint64 lrp_offset;

    if (LOG_POINT_FILE_EQUAL(*lrp_point, file->head)) {
        lrp_offset = (uint64)lrp_point->block_id * file->ctrl->block_size;
        return MIN(lrp_offset, (uint64)file->ctrl->size);
    }
    if (LOG_POINT_FILE_LT(file->head, *lrp_point)) {
        return file->head.write_pos;
    }
    return 0;
}

static status_t dtc_rbp_rt_read_online(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx, uint32 file_id,
    const log_point_t *lrp_point, uint32 *size_read)
{
    logfile_set_t *log_set = LOGFILE_SET(session, ctx->peer_node);
    log_file_t *file = &log_set->items[file_id];
    uint64 offset;
    uint64 size;

    *size_read = 0;
    if (ctx->curr_point.block_id == 0) {
        ctx->curr_point.block_id = 1;
    }
    offset = (uint64)ctx->curr_point.block_id * file->ctrl->block_size;
    size = dtc_rbp_rt_read_limit_by_lrp(file, lrp_point);
    if (offset >= size) {
        return OG_SUCCESS;
    }
    size -= offset;
    size = MIN(size, (uint64)ctx->read_buf.buf_size);
    if (cm_read_device(file->ctrl->type, ctx->log_handle[file_id], (int64)offset, ctx->read_buf.aligned_buf,
                       (uint32)size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RBP RT] failed to read peer redo file=%s offset=%llu", file->ctrl->name, offset);
        return OG_ERROR;
    }
    *size_read = (uint32)size;
    return OG_SUCCESS;
}

static bool32 dtc_rbp_rt_batch_header_ready(log_batch_t *batch, uint32 left_size)
{
    if (left_size < sizeof(log_batch_t)) {
        return OG_FALSE;
    }
    if (batch->head.magic_num != LOG_MAGIC_NUMBER || batch->space_size < sizeof(log_batch_t) ||
        batch->size < sizeof(log_batch_t) || batch->space_size < batch->size ||
        batch->space_size > OG_MAX_BATCH_SIZE) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 dtc_rbp_rt_validate_batch_quiet(log_batch_t *batch)
{
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));

    return (bool32)(batch->head.magic_num == LOG_MAGIC_NUMBER && tail->magic_num == LOG_MAGIC_NUMBER &&
                    batch->head.point.lfn == tail->point.lfn && batch->size != 0);
}

static bool32 dtc_rbp_rt_verify_checksum_quiet(knl_session_t *session, log_batch_t *batch)
{
    uint16 org_cks;
    uint32 new_cks;
    uint64 raft_index = 0;

    if (DB_IS_CHECKSUM_OFF(session) || batch->checksum == OG_INVALID_CHECKSUM) {
        return OG_TRUE;
    }
    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        raft_index = batch->raft_index;
        batch->raft_index = OG_INVALID_ID64;
    }
    org_cks = batch->checksum;
    batch->checksum = OG_INVALID_CHECKSUM;
    new_cks = cm_get_checksum(batch, batch->size);
    batch->checksum = org_cks;
    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        batch->raft_index = raft_index;
    }
    return (bool32)(org_cks == REDUCE_CKS2UINT16(new_cks));
}

static log_point_t dtc_rbp_rt_make_batch_end_point(log_batch_t *batch, uint32 block_size)
{
    log_point_t end_point = batch->head.point;

    end_point.lsn = batch->lsn;
    if (block_size != 0) {
        end_point.block_id += batch->space_size / block_size;
    }
    return end_point;
}

static uint32 dtc_rbp_rt_queue_depth(dtc_rbp_rt_aly_ctx_t *ctx)
{
    return (uint32)dtc_rbp_rt_atomic_list_count(&ctx->used_list);
}

static bool32 dtc_rbp_rt_has_uncommitted_batches(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        uint32 idx = ctx->commit_idx[i];
        dtc_rbp_rt_batch_slot_t *slot;

        if (idx == OG_INVALID_ID32) {
            continue;
        }
        if (idx >= DTC_RBP_RT_BATCH_QUEUE_COUNT) {
            return OG_TRUE;
        }
        slot = &ctx->batch_slots[idx];
        if (slot->state == DTC_RBP_RT_BATCH_READY || slot->state == DTC_RBP_RT_BATCH_WORKING ||
            slot->state == DTC_RBP_RT_BATCH_DONE) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t dtc_rbp_rt_enqueue_batch(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx, log_batch_t *batch,
    uint32 block_size)
{
    uint32 idx = OG_INVALID_INT32;
    dtc_rbp_rt_batch_slot_t *slot;
    errno_t ret;

    if (batch->space_size > ctx->batch_buf_size) {
        dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_BATCH_QUEUE_SLOT, "batch exceeds runtime queue slot");
        OG_LOG_RUN_ERR("[DTC RBP RT] batch exceeds runtime queue slot, peer=%u batch_size=%u slot_size=%llu "
                       "lfn=%llu",
                       ctx->peer_node, batch->space_size, ctx->batch_buf_size, (uint64)batch->head.point.lfn);
        return OG_ERROR;
    }

    while (!ctx->closing && !ctx->frozen && !ctx->unsafe && !ctx->reset_requested) {
        idx = dtc_rbp_rt_atomic_list_pop(&ctx->free_list);
        if (idx != OG_INVALID_INT32) {
            break;
        }
        ctx->queue_full_count++;
        if (ctx->queue_full_count <= DTC_RBP_RT_LOG_SAMPLE_LIMIT) {
            OG_LOG_DEBUG_INF("[DTC RBP RT] batch queue full sample[%llu/%u], throttle reader, peer=%u used=%u "
                             "safe_lfn=%llu curr_lfn=%llu",
                             ctx->queue_full_count, DTC_RBP_RT_LOG_SAMPLE_LIMIT, ctx->peer_node,
                             dtc_rbp_rt_queue_depth(ctx), (uint64)ctx->safe_analyzed_point.lfn,
                             (uint64)ctx->curr_point.lfn);
        }
        cm_sleep(1);
    }
    if (idx == OG_INVALID_INT32) {
        return OG_ERROR;
    }

    while (!ctx->closing && !ctx->frozen && !ctx->unsafe && !ctx->reset_requested) {
        bool32 commit_slot_free;

        cm_spin_lock(&ctx->state_lock, NULL);
        commit_slot_free =
            (bool32)(ctx->commit_idx[ctx->next_seq % DTC_RBP_RT_BATCH_QUEUE_COUNT] == OG_INVALID_ID32);
        cm_spin_unlock(&ctx->state_lock);
        if (commit_slot_free) {
            break;
        }
        if (ctx->closing || ctx->frozen || ctx->unsafe || ctx->reset_requested) {
            dtc_rbp_rt_atomic_list_push(&ctx->free_list, idx);
            return OG_ERROR;
        }
        ctx->commit_full_count++;
        if (ctx->commit_full_count <= DTC_RBP_RT_LOG_SAMPLE_LIMIT) {
            OG_LOG_DEBUG_INF("[DTC RBP RT] commit window full sample[%llu/%u], throttle reader, peer=%u next_seq=%llu "
                             "commit_seq=%llu queue_depth=%u",
                             ctx->commit_full_count, DTC_RBP_RT_LOG_SAMPLE_LIMIT, ctx->peer_node, ctx->next_seq,
                             ctx->commit_seq, dtc_rbp_rt_queue_depth(ctx));
        }
        cm_sleep(1);
    }
    if (ctx->closing || ctx->frozen || ctx->unsafe || ctx->reset_requested) {
        dtc_rbp_rt_atomic_list_push(&ctx->free_list, idx);
        return OG_ERROR;
    }
    slot = &ctx->batch_slots[idx];
    ret = memcpy_sp(slot->buf.aligned_buf, slot->buf.buf_size, batch, batch->space_size);
    if (ret != EOK) {
        dtc_rbp_rt_atomic_list_push(&ctx->free_list, idx);
        return OG_ERROR;
    }
    slot->begin_point = batch->head.point;
    slot->end_point = dtc_rbp_rt_make_batch_end_point(batch, block_size);
    slot->node_id = ctx->peer_node;
    slot->block_size = block_size;
    slot->size = batch->space_size;
    slot->pending_chunks = 0;
    slot->parse_done = OG_FALSE;
    cm_spin_lock(&ctx->state_lock, NULL);
    if (ctx->closing || ctx->frozen || ctx->unsafe || ctx->reset_requested) {
        cm_spin_unlock(&ctx->state_lock);
        dtc_rbp_rt_atomic_list_push(&ctx->free_list, idx);
        return OG_ERROR;
    }
    slot->seq = ctx->next_seq++;
    ctx->commit_idx[slot->seq % DTC_RBP_RT_BATCH_QUEUE_COUNT] = idx;
    slot->state = DTC_RBP_RT_BATCH_READY;
    cm_spin_unlock(&ctx->state_lock);
    (void)session;
    dtc_rbp_rt_atomic_list_push(&ctx->used_list, idx);
    return OG_SUCCESS;
}

static void dtc_rbp_rt_log_progress(dtc_rbp_rt_aly_ctx_t *ctx)
{
    OG_LOG_DEBUG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                           "[DTC RBP RT] analyze progress, peer=%u safe_lfn=%llu curr_lsn=%llu batches=%llu "
                           "groups=%llu pages=%llu queue_depth=%u unsafe=%u unsafe_reason=%llu pruned=%llu",
                           ctx->peer_node, (uint64)ctx->safe_analyzed_point.lfn, (uint64)ctx->curr_point.lsn,
                           ctx->analyzed_batches, ctx->analyzed_groups, ctx->analyzed_pages,
                           dtc_rbp_rt_queue_depth(ctx), (uint32)ctx->unsafe, ctx->unsafe_reason, ctx->pruned_items);
}

static void dtc_rbp_rt_commit_completed_batches_locked(dtc_rbp_rt_aly_ctx_t *ctx, uint32 *free_idx,
    uint32 *free_count)
{
    *free_count = 0;
    uint32 map_slot = (uint32)(ctx->commit_seq % DTC_RBP_RT_BATCH_QUEUE_COUNT);
    uint32 idx = ctx->commit_idx[map_slot];
    while (idx != OG_INVALID_ID32) {
        dtc_rbp_rt_batch_slot_t *slot;

        if (idx >= DTC_RBP_RT_BATCH_QUEUE_COUNT) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_INVALID_COMMIT_SLOT, "invalid commit slot index");
            break;
        }
        slot = &ctx->batch_slots[idx];
        if (slot->seq != ctx->commit_seq || slot->state != DTC_RBP_RT_BATCH_DONE) {
            break;
        }
        ctx->safe_analyzed_point = slot->end_point;
        ctx->safe_seq = slot->seq;
        ctx->analyzed_batches++;
        dtc_rbp_rt_record_lfn_point(ctx, (log_batch_t *)slot->buf.aligned_buf, &slot->end_point);
        slot->state = DTC_RBP_RT_BATCH_FREE;
        ctx->commit_idx[map_slot] = OG_INVALID_ID32;
        free_idx[(*free_count)++] = idx;
        ctx->commit_seq++;
        map_slot = (uint32)(ctx->commit_seq % DTC_RBP_RT_BATCH_QUEUE_COUNT);
        idx = ctx->commit_idx[map_slot];
    }
}

static void dtc_rbp_rt_push_committed_free(dtc_rbp_rt_aly_ctx_t *ctx, uint32 *free_idx, uint32 free_count)
{
    for (uint32 i = 0; i < free_count; i++) {
        dtc_rbp_rt_atomic_list_push(&ctx->free_list, free_idx[i]);
    }
}

static bool32 dtc_rbp_rt_touched_after_prune(rcy_set_analyze_rbp_t *meta, uint64 prune_lfn, uint64 *pruned)
{
    bool32 any = OG_FALSE;

    if (meta == NULL || !meta->touched || prune_lfn == 0) {
        return (bool32)(meta != NULL && meta->touched);
    }
    for (uint32 i = 0; i < RBP_PARTIAL_TOUCH_SLOT_COUNT; i++) {
        rbp_partial_touch_t *touch = &meta->touches[i];

        if (!touch->used) {
            continue;
        }
        if (touch->touch_max_lfn < prune_lfn) {
            touch->used = OG_FALSE;
            if (pruned != NULL) {
                (*pruned)++;
            }
            continue;
        }
        if (touch->touch_min_lfn < prune_lfn) {
            touch->touch_min_lfn = prune_lfn;
        }
        any = OG_TRUE;
    }
    meta->touched = (bool8)any;
    if (!any) {
        meta->expect_lsn = 0;
        meta->expect_lfn = 0;
        meta->touch_overflow = OG_FALSE;
        meta->overflow_disable_bitmap = 0;
    }
    return any;
}

static void dtc_rbp_rt_prune_local_set_stats(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rcy_local_set_t *local,
    uint64 prune_lfn, uint64 *active_before, uint64 *active_after)
{
    uint64 pruned_items = 0;
    uint64 pruned_touches = 0;

    if (local == NULL || !local->inited) {
        return;
    }
    for (rcy_set_item_pool_t *pool = local->item_pools; pool != NULL; pool = pool->next) {
        for (int64 i = 0; i < pool->hwm; i++) {
            rcy_set_item_t *item = &pool->items[i];

            if (active_before != NULL && item->need_replay) {
                (*active_before)++;
            }
            if (prune_lfn != 0) {
                (void)dtc_rbp_rt_touched_after_prune(&item->analyze_rbp, prune_lfn, &pruned_touches);
                if (item->dirty_max_lfn != 0 && item->dirty_max_lfn < prune_lfn) {
                    if (item->need_replay) {
                        item->need_replay = OG_FALSE;
                        pruned_items++;
                    }
                } else {
                    item->need_replay = OG_TRUE;
                    if (item->dirty_min_lfn != 0 && item->dirty_min_lfn < prune_lfn) {
                        item->dirty_min_lfn = prune_lfn;
                    }
                    if (item->analyze_rbp.expect_lfn != 0 && item->analyze_rbp.expect_lfn < prune_lfn) {
                        item->analyze_rbp.expect_lfn = 0;
                        item->analyze_rbp.expect_lsn = 0;
                    }
                }
            }
            if (active_after != NULL && item->need_replay) {
                (*active_after)++;
            }
        }
    }
    if (pruned_items != 0 || pruned_touches != 0) {
        cm_spin_lock(&ctx->state_lock, NULL);
        ctx->pruned_items += pruned_items;
        ctx->pruned_touches += pruned_touches;
        cm_spin_unlock(&ctx->state_lock);
    }
}

static void dtc_rbp_rt_prune_local_set(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rcy_local_set_t *local, uint64 prune_lfn)
{
    if (prune_lfn == 0) {
        return;
    }
    (void)ctx;
    dtc_rcy_local_set_begin_active_rebuild(local, prune_lfn);
}

static void dtc_rbp_rt_prune_metadata(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx)
{
    log_point_t prune_point;
    log_point_t old_prune_point;
    log_point_t safe_point;

    if (dtc_read_node_ctrl(session, (uint8)ctx->peer_node) != OG_SUCCESS) {
        dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_READ_PEER_CTRL_PRUNE, "read peer ctrl for prune failed");
        return;
    }
    prune_point = dtc_get_ctrl(session, ctx->peer_node)->rcy_point;
    cm_spin_lock(&ctx->state_lock, NULL);
    old_prune_point = ctx->peer_prune_point;
    safe_point = ctx->safe_analyzed_point;
    ctx->peer_prune_point = prune_point;
    if (prune_point.lfn > safe_point.lfn) {
        ctx->reset_requested = OG_TRUE;
        ctx->reset_point = prune_point;
        cm_spin_unlock(&ctx->state_lock);
        OG_LOG_RUN_WAR("[DTC RBP RT] checkpoint passed safe point, schedule runtime reset, peer=%u "
                       "prune_lfn=%llu safe_lfn=%llu curr_lfn=%llu queue_depth=%u",
                       ctx->peer_node, (uint64)prune_point.lfn, (uint64)safe_point.lfn,
                       (uint64)ctx->curr_point.lfn, dtc_rbp_rt_queue_depth(ctx));
        return;
    }
    dtc_rbp_rt_prune_lfn_points(ctx, prune_point.lfn);
    cm_spin_unlock(&ctx->state_lock);
    if (prune_point.lfn > old_prune_point.lfn) {
        OG_LOG_DEBUG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                               "[DTC RBP RT] prune watermark advanced, peer=%u prune_lfn=%llu safe_lfn=%llu "
                               "lfn_points=%u",
                               ctx->peer_node, (uint64)prune_point.lfn, (uint64)safe_point.lfn,
                               ctx->lfn_point_count);
    }
}

static void dtc_rbp_rt_maybe_prune_metadata(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx)
{
    uint64 analyzed_batches;
    bool32 need_prune = OG_FALSE;

    cm_spin_lock(&ctx->state_lock, NULL);
    analyzed_batches = ctx->analyzed_batches;
    if (analyzed_batches != 0 && (analyzed_batches % DTC_RBP_RT_PRUNE_INTERVAL) == 0 &&
        ctx->last_prune_batch_count != analyzed_batches) {
        ctx->last_prune_batch_count = analyzed_batches;
        need_prune = OG_TRUE;
    }
    cm_spin_unlock(&ctx->state_lock);
    if (need_prune) {
        dtc_rbp_rt_prune_metadata(session, ctx);
    }
}

static void dtc_rbp_rt_owner_prune_local(dtc_rbp_rt_aly_ctx_t *ctx, uint32 owner_id)
{
    uint64 prune_lfn;

    if (owner_id >= ctx->owner_worker_count) {
        return;
    }
    cm_spin_lock(&ctx->state_lock, NULL);
    prune_lfn = ctx->peer_prune_point.lfn;
    cm_spin_unlock(&ctx->state_lock);
    if (prune_lfn == 0 || ctx->owner_prune_lfn[owner_id] >= prune_lfn) {
        return;
    }
    dtc_rbp_rt_prune_local_set(ctx, &ctx->rt_owner_rcy[owner_id], prune_lfn);
    ctx->owner_prune_lfn[owner_id] = prune_lfn;
}

static inline uint32 dtc_rbp_rt_event_owner(dtc_rbp_rt_aly_ctx_t *ctx, page_id_t page_id)
{
    uint32 hash_id = (HASH_SEED * page_id.page + page_id.file) * HASH_SEED % OG_RCY_SET_BUCKET;

    return hash_id % ctx->owner_worker_count;
}

static bool32 dtc_rbp_rt_event_queues_drained(dtc_rbp_rt_aly_ctx_t *ctx)
{
    bool32 drained = OG_TRUE;

    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        dtc_rbp_rt_event_queue_t *queue = &ctx->owner_queues[i];

        cm_spin_lock(&queue->lock, NULL);
        if (queue->head != NULL || queue->depth != 0) {
            drained = OG_FALSE;
        }
        cm_spin_unlock(&queue->lock);
        if (!drained) {
            return OG_FALSE;
        }
    }
    cm_spin_lock(&ctx->state_lock, NULL);
    drained = (bool32)(ctx->outstanding_event_chunks == 0);
    cm_spin_unlock(&ctx->state_lock);
    return drained;
}

static status_t dtc_rbp_rt_reserve_event_chunk(dtc_rbp_rt_aly_ctx_t *ctx, uint32 batch_idx)
{
    uint32 wait_ms = 0;

    while (!ctx->closing && !ctx->unsafe) {
        if (batch_idx >= DTC_RBP_RT_BATCH_QUEUE_COUNT) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_INVALID_EVENT_CHUNK_BATCH,
                                   "invalid event chunk batch index");
            return OG_ERROR;
        }
        cm_spin_lock(&ctx->state_lock, NULL);
        if (ctx->outstanding_event_chunks < DTC_RBP_RT_EVENT_CHUNK_LIMIT) {
            dtc_rbp_rt_batch_slot_t *slot = &ctx->batch_slots[batch_idx];

            ctx->outstanding_event_chunks++;
            ctx->event_chunk_peak = MAX(ctx->event_chunk_peak, ctx->outstanding_event_chunks);
            slot->pending_chunks++;
            cm_spin_unlock(&ctx->state_lock);
            return OG_SUCCESS;
        }
        cm_spin_unlock(&ctx->state_lock);
        if (wait_ms >= DTC_RBP_RT_DRAIN_TIMEOUT_MS) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_EVENT_CHUNK_BACKLOG_TIMEOUT,
                                   "event chunk backlog timeout");
            return OG_ERROR;
        }
        OG_LOG_DEBUG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                               "[DTC RBP RT] event chunk backlog, peer=%u outstanding=%u limit=%u",
                               ctx->peer_node, ctx->outstanding_event_chunks, DTC_RBP_RT_EVENT_CHUNK_LIMIT);
        cm_sleep(1);
        wait_ms++;
    }
    return OG_ERROR;
}

static void dtc_rbp_rt_release_event_chunk_reservation(dtc_rbp_rt_aly_ctx_t *ctx, uint32 batch_idx)
{
    if (batch_idx >= DTC_RBP_RT_BATCH_QUEUE_COUNT) {
        return;
    }
    cm_spin_lock(&ctx->state_lock, NULL);
    if (ctx->outstanding_event_chunks > 0) {
        ctx->outstanding_event_chunks--;
    }
    if (ctx->batch_slots[batch_idx].pending_chunks > 0) {
        ctx->batch_slots[batch_idx].pending_chunks--;
    }
    cm_spin_unlock(&ctx->state_lock);
}

static status_t dtc_rbp_rt_alloc_event_chunk(dtc_rbp_rt_aly_ctx_t *ctx, uint32 owner_id, uint32 batch_idx,
    dtc_rbp_rt_event_chunk_t **chunk)
{
    if (dtc_rbp_rt_reserve_event_chunk(ctx, batch_idx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *chunk = (dtc_rbp_rt_event_chunk_t *)malloc(sizeof(dtc_rbp_rt_event_chunk_t));
    if (*chunk == NULL) {
        dtc_rbp_rt_release_event_chunk_reservation(ctx, batch_idx);
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(dtc_rbp_rt_event_chunk_t), "dtc rbp rt event chunk");
        return OG_ERROR;
    }
    (*chunk)->next = NULL;
    (*chunk)->owner_id = owner_id;
    (*chunk)->batch_idx = batch_idx;
    (*chunk)->count = 0;
    (*chunk)->reserved = 0;
    return OG_SUCCESS;
}

static void dtc_rbp_rt_enqueue_event_chunk(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_event_chunk_t *chunk)
{
    dtc_rbp_rt_event_queue_t *queue = &ctx->owner_queues[chunk->owner_id];

    chunk->next = NULL;
    cm_spin_lock(&queue->lock, NULL);
    if (queue->tail == NULL) {
        queue->head = chunk;
    } else {
        queue->tail->next = chunk;
    }
    queue->tail = chunk;
    queue->depth++;
    queue->peak_depth = MAX(queue->peak_depth, queue->depth);
    queue->pushed++;
    cm_spin_unlock(&queue->lock);
}

static dtc_rbp_rt_event_chunk_t *dtc_rbp_rt_dequeue_event_chunk(dtc_rbp_rt_aly_ctx_t *ctx, uint32 owner_id)
{
    dtc_rbp_rt_event_queue_t *queue = &ctx->owner_queues[owner_id];
    dtc_rbp_rt_event_chunk_t *chunk;

    cm_spin_lock(&queue->lock, NULL);
    chunk = queue->head;
    if (chunk != NULL) {
        queue->head = chunk->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
        }
        if (queue->depth > 0) {
            queue->depth--;
        }
        queue->popped++;
    }
    cm_spin_unlock(&queue->lock);
    return chunk;
}

static void dtc_rbp_rt_try_finish_batch_locked(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_batch_slot_t *slot,
    uint32 *free_idx, uint32 *free_count)
{
    if (slot->parse_done && slot->pending_chunks == 0 && slot->state == DTC_RBP_RT_BATCH_WORKING) {
        slot->state = DTC_RBP_RT_BATCH_DONE;
    }
    dtc_rbp_rt_commit_completed_batches_locked(ctx, free_idx, free_count);
}

static void dtc_rbp_rt_mark_batch_parse_done(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_batch_slot_t *slot)
{
    uint32 free_idx[DTC_RBP_RT_BATCH_QUEUE_COUNT];
    uint32 free_count;

    cm_spin_lock(&ctx->state_lock, NULL);
    slot->parse_done = OG_TRUE;
    dtc_rbp_rt_try_finish_batch_locked(ctx, slot, free_idx, &free_count);
    cm_spin_unlock(&ctx->state_lock);
    dtc_rbp_rt_push_committed_free(ctx, free_idx, free_count);
}

static void dtc_rbp_rt_finish_event_chunk(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_event_chunk_t *chunk)
{
    uint32 free_idx[DTC_RBP_RT_BATCH_QUEUE_COUNT];
    uint32 free_count;

    cm_spin_lock(&ctx->state_lock, NULL);
    if (ctx->outstanding_event_chunks > 0) {
        ctx->outstanding_event_chunks--;
    }
    if (chunk->batch_idx < DTC_RBP_RT_BATCH_QUEUE_COUNT) {
        dtc_rbp_rt_batch_slot_t *slot = &ctx->batch_slots[chunk->batch_idx];

        if (slot->pending_chunks > 0) {
            slot->pending_chunks--;
        } else {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_EVENT_CHUNK_PENDING_UNDERFLOW,
                                   "event chunk pending underflow");
        }
        dtc_rbp_rt_try_finish_batch_locked(ctx, slot, free_idx, &free_count);
    } else {
        free_count = 0;
        dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_EVENT_CHUNK_INVALID_BATCH,
                               "event chunk invalid batch index");
    }
    cm_spin_unlock(&ctx->state_lock);
    dtc_rbp_rt_push_committed_free(ctx, free_idx, free_count);
}

static void dtc_rbp_rt_free_unqueued_chunks(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_event_chunk_t **chunks,
    uint32 owner_count)
{
    for (uint32 i = 0; i < owner_count; i++) {
        if (chunks[i] == NULL) {
            continue;
        }
        dtc_rbp_rt_release_event_chunk_reservation(ctx, chunks[i]->batch_idx);
        CM_FREE_PTR(chunks[i]);
    }
}

static status_t dtc_rbp_rt_flush_event_chunks(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_event_chunk_t **chunks,
    uint32 owner_count)
{
    for (uint32 i = 0; i < owner_count; i++) {
        if (chunks[i] == NULL) {
            continue;
        }
        if (chunks[i]->count == 0) {
            dtc_rbp_rt_release_event_chunk_reservation(ctx, chunks[i]->batch_idx);
            CM_FREE_PTR(chunks[i]);
            continue;
        }
        dtc_rbp_rt_enqueue_event_chunk(ctx, chunks[i]);
        chunks[i] = NULL;
    }
    return OG_SUCCESS;
}

static status_t dtc_rbp_rt_emit_event(dtc_rbp_rt_aly_ctx_t *ctx, uint32 batch_idx,
    dtc_rbp_rt_event_chunk_t **chunks, const dtc_rbp_rt_page_event_t *event)
{
    uint32 owner_id = dtc_rbp_rt_event_owner(ctx, event->page_id);
    dtc_rbp_rt_event_chunk_t *chunk = chunks[owner_id];

    if (chunk == NULL) {
        if (dtc_rbp_rt_alloc_event_chunk(ctx, owner_id, batch_idx, &chunk) != OG_SUCCESS) {
            return OG_ERROR;
        }
        chunks[owner_id] = chunk;
    }
    chunk->events[chunk->count++] = *event;
    if (chunk->count >= DTC_RBP_RT_EVENT_CHUNK_SIZE) {
        dtc_rbp_rt_enqueue_event_chunk(ctx, chunk);
        chunks[owner_id] = NULL;
    }
    return OG_SUCCESS;
}

static status_t dtc_rbp_rt_analyze_group_to_owner_events(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx,
    uint32 batch_idx, log_group_t *group, uint32 node_id, uint64 batch_lfn,
    dtc_rbp_rt_event_chunk_t **chunks, uint64 *enter_count, uint64 *event_count)
{
    uint32 offset = sizeof(log_group_t);
    log_entry_t *log = NULL;
    bool32 is_create_df = OG_FALSE;
    page_id_t page_stack[KNL_MAX_PAGE_STACK_DEPTH];
    uint32 page_depth = 0;

    while (offset < LOG_GROUP_ACTUAL_SIZE(group)) {
        bool32 is_enter;
        bool32 is_leave;

        log = (log_entry_t *)((char *)group + offset);
        knl_panic(log->size > 0);
        is_enter = RD_TYPE_IS_ENTER_PAGE(log->type);
        is_leave = RD_TYPE_IS_LEAVE_PAGE(log->type);
        if (!is_create_df && log->type == RD_SPC_CREATE_DATAFILE) {
            is_create_df = OG_TRUE;
        }
        if (is_enter) {
            rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
            page_id_t page_id = MAKE_PAGID(redo->file, redo->page);
            datafile_t *df = DATAFILE_GET(session, redo->file);
            dtc_rbp_rt_page_event_t event = { 0 };

            knl_panic_log(page_depth < KNL_MAX_PAGE_STACK_DEPTH,
                          "[DTC RBP RT] page stack overflow in owner analyze, lfn=%llu lsn=%llu",
                          (uint64)batch_lfn, (uint64)group->lsn);
            page_stack[page_depth++] = page_id;
            if (!is_create_df && (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used || df->file_no == OG_INVALID_ID32)) {
                OG_LOG_RUN_ERR("[DTC RBP RT] failed to verify df for owner analyze, page=%u-%u",
                               page_id.file, page_id.page);
                return OG_ERROR;
            }
            space_t *space = SPACE_GET(session, df->space_id);
            if (!is_create_df && (!SPACE_IS_ONLINE(space) || !space->ctrl->used)) {
                OG_LOG_RUN_ERR("[DTC RBP RT] failed to verify space for owner analyze, page=%u-%u",
                               page_id.file, page_id.page);
                return OG_ERROR;
            }
            event.type = DTC_RBP_RT_EVENT_ENTER_PAGE;
            event.page_id = page_id;
            event.space_id = df->space_id;
            event.lsn = group->lsn;
            event.batch_lfn = batch_lfn;
            event.pcn = redo->pcn;
            event.node_id = node_id;
            if (dtc_rbp_rt_emit_event(ctx, batch_idx, chunks, &event) != OG_SUCCESS) {
                return OG_ERROR;
            }
            (*enter_count)++;
            (*event_count)++;
        } else if (is_leave) {
            bool32 changed = *((bool32 *)log->data);
            page_id_t page_id;

            knl_panic_log(page_depth > 0,
                          "[DTC RBP RT] page stack underflow in owner analyze, lfn=%llu lsn=%llu",
                          (uint64)batch_lfn, (uint64)group->lsn);
            page_id = page_stack[--page_depth];
            if (changed) {
                dtc_rbp_rt_page_event_t event = { 0 };

                event.type = DTC_RBP_RT_EVENT_LEAVE_CHANGED;
                event.page_id = page_id;
                event.lsn = group->lsn;
                event.batch_lfn = batch_lfn;
                event.node_id = node_id;
                if (dtc_rbp_rt_emit_event(ctx, batch_idx, chunks, &event) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                (*event_count)++;
            }
        }
        offset += log->size;
    }
    return OG_SUCCESS;
}

static status_t dtc_rbp_rt_process_batch_slot(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx, uint32 parser_id,
    uint32 batch_idx, dtc_rbp_rt_batch_slot_t *slot)
{
    log_batch_t *batch = (log_batch_t *)slot->buf.aligned_buf;
    dtc_rbp_rt_event_chunk_t *chunks[DTC_RBP_RT_MAX_OWNER_WORKERS] = { 0 };
    log_cursor_t cursor;
    log_group_t *group = NULL;
    log_context_t *ogx = &session->kernel->redo_ctx;
    uint64 groups = 0;
    uint64 pages = 0;
    uint64 events = 0;

    rcy_init_log_cursor(&cursor, batch);
    group = log_fetch_group(ogx, &cursor);
    while (group != NULL) {
        if (dtc_rbp_rt_analyze_group_to_owner_events(session, ctx, batch_idx, group, slot->node_id,
            batch->head.point.lfn, chunks, &pages, &events) != OG_SUCCESS) {
            dtc_rbp_rt_free_unqueued_chunks(ctx, chunks, ctx->owner_worker_count);
            return OG_ERROR;
        }
        groups++;
        group = log_fetch_group(ogx, &cursor);
    }
    if (dtc_rbp_rt_flush_event_chunks(ctx, chunks, ctx->owner_worker_count) != OG_SUCCESS) {
        dtc_rbp_rt_free_unqueued_chunks(ctx, chunks, ctx->owner_worker_count);
        return OG_ERROR;
    }
    cm_spin_lock(&ctx->state_lock, NULL);
    ctx->analyzed_groups += groups;
    ctx->analyzed_pages += pages;
    ctx->parsed_events += events;
    cm_spin_unlock(&ctx->state_lock);
    dtc_rbp_rt_mark_batch_parse_done(ctx, slot);
    dtc_rbp_rt_log_progress(ctx);
    dtc_rbp_rt_maybe_prune_metadata(session, ctx);
    (void)parser_id;
    return OG_SUCCESS;
}

static void dtc_rbp_rt_parser_proc(thread_t *thread)
{
    dtc_rbp_rt_worker_arg_t *arg = (dtc_rbp_rt_worker_arg_t *)thread->argument;
    knl_session_t *session = arg->session;
    dtc_rbp_rt_aly_ctx_t *ctx = &g_dtc->rbp_rt_aly_ctx;
    uint64 processed = 0;

    cm_set_thread_name("dtc_rbp_rt_parse");
    KNL_SESSION_SET_CURR_THREADID(session, thread->id);
    cm_atomic32_inc(&ctx->running_parser_num);
    OG_LOG_DEBUG_INF("[DTC RBP RT] parser started, parser=%u peer=%u", arg->worker_id, ctx->peer_node);
    while (!thread->closed && !ctx->closing && !ctx->unsafe) {
        uint32 idx = dtc_rbp_rt_atomic_list_pop(&ctx->used_list);
        dtc_rbp_rt_batch_slot_t *slot;

        if (idx == OG_INVALID_INT32) {
            if (ctx->frozen) {
                break;
            }
            cm_sleep(1);
            continue;
        }
        slot = &ctx->batch_slots[idx];
        cm_spin_lock(&ctx->state_lock, NULL);
        slot->state = DTC_RBP_RT_BATCH_WORKING;
        cm_spin_unlock(&ctx->state_lock);
        if (dtc_rbp_rt_process_batch_slot(session, ctx, arg->worker_id, idx, slot) != OG_SUCCESS) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_PARSER_ANALYZE_BATCH_FAILED,
                                   "parser analyze batch failed");
            break;
        }
        processed++;
    }
    cm_atomic32_dec(&ctx->running_parser_num);
    OG_LOG_DEBUG_INF("[DTC RBP RT] parser stopped, parser=%u processed=%llu unsafe=%u reason=%llu",
                     arg->worker_id, processed, (uint32)ctx->unsafe, ctx->unsafe_reason);
    KNL_SESSION_CLEAR_THREADID(session);
}

static void dtc_rbp_rt_apply_event(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx, uint32 owner_id,
    const dtc_rbp_rt_page_event_t *event)
{
    dtc_rcy_local_set_t *local = &ctx->rt_owner_rcy[owner_id];

    if (event->type == DTC_RBP_RT_EVENT_ENTER_PAGE) {
        dtc_rcy_record_space_id_into_local(local, event->space_id);
        if (dtc_rcy_record_page_into_local(session, local, event->page_id, event->lsn, event->batch_lfn,
            event->pcn, NULL, NULL) != OG_SUCCESS) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_OWNER_RECORD_PAGE_FAILED, "owner record page failed");
        }
        return;
    }
    if (event->type == DTC_RBP_RT_EVENT_LEAVE_CHANGED) {
        dtc_rcy_rbp_analyze_leave_into_local(local, event->page_id, event->node_id, event->batch_lfn,
            event->lsn, NULL, NULL);
    }
}

static void dtc_rbp_rt_owner_proc(thread_t *thread)
{
    dtc_rbp_rt_worker_arg_t *arg = (dtc_rbp_rt_worker_arg_t *)thread->argument;
    knl_session_t *session = arg->session;
    dtc_rbp_rt_aly_ctx_t *ctx = &g_dtc->rbp_rt_aly_ctx;
    uint32 owner_id = arg->worker_id;
    uint64 chunks = 0;
    uint64 events = 0;

    cm_set_thread_name("dtc_rbp_rt_owner");
    KNL_SESSION_SET_CURR_THREADID(session, thread->id);
    cm_atomic32_inc(&ctx->running_owner_num);
    OG_LOG_DEBUG_INF("[DTC RBP RT] owner started, owner=%u peer=%u", owner_id, ctx->peer_node);
    while (!thread->closed && !ctx->closing && !ctx->unsafe) {
        dtc_rbp_rt_event_chunk_t *chunk = dtc_rbp_rt_dequeue_event_chunk(ctx, owner_id);

        if (chunk == NULL) {
            dtc_rcy_local_set_rebuild_active_budget(&ctx->rt_owner_rcy[owner_id], DTC_RBP_RT_ACTIVE_REBUILD_BUDGET);
            cm_sleep(1);
            continue;
        }
        for (uint32 i = 0; i < chunk->count; i++) {
            dtc_rbp_rt_apply_event(session, ctx, owner_id, &chunk->events[i]);
            events++;
        }
        chunks++;
        cm_spin_lock(&ctx->state_lock, NULL);
        ctx->applied_events += chunk->count;
        cm_spin_unlock(&ctx->state_lock);
        dtc_rbp_rt_finish_event_chunk(ctx, chunk);
        CM_FREE_PTR(chunk);
        dtc_rbp_rt_owner_prune_local(ctx, owner_id);
        dtc_rcy_local_set_rebuild_active_budget(&ctx->rt_owner_rcy[owner_id], DTC_RBP_RT_ACTIVE_REBUILD_BUDGET);
    }
    cm_atomic32_dec(&ctx->running_owner_num);
    OG_LOG_DEBUG_INF("[DTC RBP RT] owner stopped, owner=%u chunks=%llu events=%llu unsafe=%u reason=%llu",
                     owner_id, chunks, events, (uint32)ctx->unsafe, ctx->unsafe_reason);
    KNL_SESSION_CLEAR_THREADID(session);
}

static void dtc_rbp_rt_reset_batch_queue(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        ctx->batch_slots[i].state = DTC_RBP_RT_BATCH_FREE;
        ctx->batch_slots[i].pending_chunks = 0;
        ctx->batch_slots[i].parse_done = OG_FALSE;
        ctx->commit_idx[i] = OG_INVALID_ID32;
    }

    cm_spin_lock(&ctx->free_list.lock, NULL);
    ctx->free_list.begin = 0;
    ctx->free_list.end = DTC_RBP_RT_BATCH_QUEUE_COUNT;
    ctx->free_list.writed_end = DTC_RBP_RT_BATCH_QUEUE_COUNT;
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        ctx->free_list.array[i] = i;
    }
    cm_spin_unlock(&ctx->free_list.lock);

    cm_spin_lock(&ctx->used_list.lock, NULL);
    ctx->used_list.begin = 0;
    ctx->used_list.end = 0;
    ctx->used_list.writed_end = 0;
    cm_spin_unlock(&ctx->used_list.lock);

    ctx->safe_seq = 0;
    ctx->next_seq = 0;
    ctx->commit_seq = 0;
    ctx->outstanding_event_chunks = 0;
    ctx->event_chunk_peak = 0;
}

static status_t dtc_rbp_rt_reinit_local_sets(dtc_rbp_rt_aly_ctx_t *ctx)
{
    dtc_rbp_rt_clear_local_sets(ctx);
    ctx->snapshot_valid = OG_FALSE;
    return dtc_rbp_rt_init_local_sets(ctx);
}

static status_t dtc_rbp_rt_reset_runtime_window(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx)
{
    uint32 wait_ms = 0;
    bool32 drained = OG_FALSE;
    log_point_t reset_point;

    while (wait_ms < DTC_RBP_RT_DRAIN_TIMEOUT_MS && !ctx->closing && !ctx->frozen && !ctx->unsafe) {
        uint32 queue_depth;
        bool32 has_uncommitted;
        uint32 free_idx[DTC_RBP_RT_BATCH_QUEUE_COUNT];
        uint32 free_count;

        cm_spin_lock(&ctx->state_lock, NULL);
        dtc_rbp_rt_commit_completed_batches_locked(ctx, free_idx, &free_count);
        has_uncommitted = dtc_rbp_rt_has_uncommitted_batches(ctx);
        cm_spin_unlock(&ctx->state_lock);
        dtc_rbp_rt_push_committed_free(ctx, free_idx, free_count);
        queue_depth = dtc_rbp_rt_queue_depth(ctx);
        drained = (bool32)(queue_depth == 0 && !has_uncommitted && dtc_rbp_rt_event_queues_drained(ctx));
        if (drained) {
            break;
        }
        cm_sleep(1);
        wait_ms++;
    }
    if (!drained) {
        dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_RUNTIME_RESET_DRAIN_TIMEOUT, "runtime reset drain timeout");
        return OG_ERROR;
    }

    if (dtc_rbp_rt_reinit_local_sets(ctx) != OG_SUCCESS) {
        dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_RUNTIME_RESET_LOCAL_INIT_FAILED,
                               "runtime reset local set init failed");
        return OG_ERROR;
    }

    cm_spin_lock(&ctx->state_lock, NULL);
    reset_point = ctx->reset_point;
    ctx->begin_point = reset_point;
    ctx->curr_point = reset_point;
    ctx->safe_analyzed_point = reset_point;
    ctx->peer_prune_point = reset_point;
    ctx->snapshot_safe_point = reset_point;
    ctx->snapshot_next_point = reset_point;
    ctx->rt_start_lfn = reset_point.lfn;
    ctx->snapshot_valid = OG_FALSE;
    ctx->reset_requested = OG_FALSE;
    dtc_rbp_rt_reset_lfn_points(ctx);
    ctx->last_prune_batch_count = ctx->analyzed_batches;
    ctx->queue_full_count = 0;
    ctx->commit_full_count = 0;
    ctx->tail_retry_count = 0;
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        ctx->owner_prune_lfn[i] = reset_point.lfn;
    }
    cm_spin_unlock(&ctx->state_lock);
    dtc_rbp_rt_reset_batch_queue(ctx);

    OG_LOG_RUN_WAR("[DTC RBP RT] runtime window reset, peer=%u restart_lfn=%llu restart_lsn=%llu "
                   "wait_ms=%u",
                   ctx->peer_node, (uint64)reset_point.lfn, reset_point.lsn, wait_ms);
    (void)session;
    return OG_SUCCESS;
}

static dtc_rbp_rt_read_result_t dtc_rbp_rt_read_retry(dtc_rbp_rt_aly_ctx_t *ctx, const char *reason,
    uint32 pos, uint32 size_read)
{
    ctx->tail_retry_count++;
    if (ctx->tail_retry_count <= DTC_RBP_RT_LOG_SAMPLE_LIMIT) {
        OG_LOG_DEBUG_INF("[DTC RBP RT] peer lrp tail not stable sample[%llu/%u], peer=%u reason=%s curr_lfn=%llu "
                         "curr_lsn=%llu safe_lfn=%llu pos=%u size_read=%u queue_depth=%u",
                         ctx->tail_retry_count, DTC_RBP_RT_LOG_SAMPLE_LIMIT, ctx->peer_node, reason,
                         (uint64)ctx->curr_point.lfn, (uint64)ctx->curr_point.lsn,
                         (uint64)ctx->safe_analyzed_point.lfn, pos, size_read, dtc_rbp_rt_queue_depth(ctx));
    }
    return DTC_RBP_RT_READ_RETRY;
}

static dtc_rbp_rt_read_result_t dtc_rbp_rt_read_unsafe(dtc_rbp_rt_aly_ctx_t *ctx, uint64 reason,
    const char *detail, log_batch_t *batch)
{
    ctx->unsafe = OG_TRUE;
    ctx->unsafe_reason = reason;
    if (batch == NULL) {
        OG_LOG_RUN_WAR("[DTC RBP RT] peer redo read unsafe, peer=%u reason=%s curr_lfn=%llu curr_lsn=%llu",
                       ctx->peer_node, detail, (uint64)ctx->curr_point.lfn, (uint64)ctx->curr_point.lsn);
    } else {
        OG_LOG_RUN_WAR("[DTC RBP RT] peer redo read unsafe, peer=%u reason=%s curr_lfn=%llu batch_lfn=%llu "
                       "batch_lsn=%llu",
                       ctx->peer_node, detail, (uint64)ctx->curr_point.lfn, (uint64)batch->head.point.lfn,
                       batch->lsn);
    }
    return DTC_RBP_RT_READ_UNSAFE;
}

static dtc_rbp_rt_read_result_t dtc_rbp_rt_analyze_buffer(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx,
    uint32 size_read, uint32 block_size, bool32 *advanced)
{
    uint32 pos = 0;

    if (advanced != NULL) {
        *advanced = OG_FALSE;
    }
    while (pos + sizeof(log_batch_t) <= size_read) {
        log_batch_t *batch = (log_batch_t *)(ctx->read_buf.aligned_buf + pos);
        uint32 left_size = size_read - pos;

        if (!dtc_rbp_rt_batch_header_ready(batch, left_size)) {
            return dtc_rbp_rt_read_retry(ctx, "batch header not ready", pos, size_read);
        }
        if (batch->space_size > left_size) {
            return dtc_rbp_rt_read_retry(ctx, "batch body not complete", pos, size_read);
        }
        if (!dtc_rbp_rt_validate_batch_quiet(batch)) {
            return dtc_rbp_rt_read_retry(ctx, "batch tail not stable", pos, size_read);
        }
        if (!LFN_IS_CONTINUOUS(batch->head.point.lfn, ctx->curr_point.lfn)) {
            ctx->has_gap = OG_TRUE;
            return dtc_rbp_rt_read_unsafe(ctx, DTC_RBP_RT_UNSAFE_PEER_REDO_GAP, "peer redo gap", batch);
        }
        if (!dtc_rbp_rt_verify_checksum_quiet(session, batch)) {
            return dtc_rbp_rt_read_retry(ctx, "batch checksum not stable", pos, size_read);
        }
        if (dtc_rbp_rt_enqueue_batch(session, ctx, batch, block_size) != OG_SUCCESS) {
            if (ctx->reset_requested || ctx->frozen || ctx->closing) {
                return DTC_RBP_RT_READ_OK;
            }
            return DTC_RBP_RT_READ_UNSAFE;
        }
        ctx->curr_point = dtc_rbp_rt_make_batch_end_point(batch, block_size);
        pos += batch->space_size;
        if (advanced != NULL) {
            *advanced = OG_TRUE;
        }
        if (ctx->closing || ctx->frozen || ctx->unsafe) {
            break;
        }
    }
    if (pos < size_read && size_read < (uint32)ctx->read_buf.buf_size) {
        return dtc_rbp_rt_read_retry(ctx, "batch header fragment at lrp tail", pos, size_read);
    }
    return ctx->unsafe ? DTC_RBP_RT_READ_UNSAFE : DTC_RBP_RT_READ_OK;
}

static void dtc_rbp_rt_log_caught_up_lrp(knl_session_t *session, dtc_rbp_rt_aly_ctx_t *ctx,
    const log_point_t *lrp_point)
{
    OG_LOG_DEBUG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_10,
                           "[DTC RBP RT] caught up peer lrp redo, peer=%u curr_lfn=%llu curr_lsn=%llu "
                           "safe_lfn=%llu lrp_lfn=%llu lrp_lsn=%llu batches=%llu queue_depth=%u unsafe=%u "
                           "unsafe_reason=%llu",
                           ctx->peer_node, (uint64)ctx->curr_point.lfn, (uint64)ctx->curr_point.lsn,
                           (uint64)ctx->safe_analyzed_point.lfn, (uint64)lrp_point->lfn, (uint64)lrp_point->lsn,
                           ctx->analyzed_batches, dtc_rbp_rt_queue_depth(ctx), (uint32)ctx->unsafe,
                           ctx->unsafe_reason);
    dtc_rbp_rt_prune_metadata(session, ctx);
}

static void dtc_rbp_rt_reader_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    dtc_rbp_rt_aly_ctx_t *ctx = &g_dtc->rbp_rt_aly_ctx;
    bool32 sleep_needed = OG_FALSE;

    cm_set_thread_name("dtc_rbp_rt_read");
    KNL_SESSION_SET_CURR_THREADID(session, thread->id);
    OG_LOG_DEBUG_INF("[DTC RBP RT] reader started, self=%u peer=%u", ctx->self_node, ctx->peer_node);

    if (dtc_rbp_rt_init_peer_logset(session, ctx) != OG_SUCCESS) {
        dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_INIT_PEER_LOGSET_FAILED, "init peer logset failed");
        thread->closed = OG_TRUE;
        KNL_SESSION_CLEAR_THREADID(session);
        return;
    }

    while (!thread->closed && !ctx->closing && !ctx->frozen && !ctx->unsafe) {
        uint32 file_id;
        uint32 size_read = 0;
        bool32 is_curr = OG_FALSE;
        log_point_t old_point;
        log_point_t peer_lrp_point;
        bool32 advanced = OG_FALSE;
        dtc_rbp_rt_read_result_t read_result;

        if (sleep_needed) {
            cm_sleep(DTC_RBP_RT_SLEEP_MS);
        }
        if (ctx->reset_requested) {
            if (dtc_rbp_rt_reset_runtime_window(session, ctx) != OG_SUCCESS) {
                break;
            }
            sleep_needed = OG_FALSE;
            continue;
        }
        if (dtc_read_node_ctrl(session, (uint8)ctx->peer_node) != OG_SUCCESS) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_READ_PEER_CTRL_FAILED, "read peer ctrl failed");
            break;
        }
        {
            dtc_node_ctrl_t *ctrl = dtc_get_ctrl(session, ctx->peer_node);

            peer_lrp_point = ctrl->lrp_point;
            if (log_cmp_point(&ctx->curr_point, &peer_lrp_point) >= 0) {
                sleep_needed = OG_TRUE;
                dtc_rbp_rt_log_caught_up_lrp(session, ctx, &peer_lrp_point);
                continue;
            }
            if (ctrl->log_last < LOGFILE_SET(session, ctx->peer_node)->logfile_hwm &&
                dtc_rbp_rt_refresh_file_head(session, ctx, ctrl->log_last) != OG_SUCCESS) {
                dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_REFRESH_CURRENT_FILE_HEAD_FAILED,
                                       "refresh current file head failed");
                break;
            }
        }
        file_id = dtc_rbp_rt_get_file_by_point(session, ctx, &is_curr);
        if (file_id == OG_INVALID_ID32) {
            logfile_set_t *log_set = LOGFILE_SET(session, ctx->peer_node);

            for (uint32 i = 0; i < log_set->logfile_hwm; i++) {
                if (dtc_rbp_rt_refresh_file_head(session, ctx, i) != OG_SUCCESS) {
                    dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_REFRESH_FILE_HEADS_FAILED,
                                           "refresh file heads failed");
                    break;
                }
            }
            if (ctx->unsafe) {
                break;
            }
            file_id = dtc_rbp_rt_get_file_by_point(session, ctx, &is_curr);
        }
        if (file_id == OG_INVALID_ID32) {
            ctx->has_gap = OG_TRUE;
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_PEER_REDO_FILE_NOT_FOUND, "peer redo file not found");
            break;
        }
        if (!is_curr && dtc_rbp_rt_refresh_file_head(session, ctx, file_id) != OG_SUCCESS) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_REFRESH_NON_CURRENT_FILE_HEAD_FAILED,
                                   "refresh non-current file head failed");
            break;
        }
        if (dtc_rbp_rt_read_online(session, ctx, file_id, &peer_lrp_point, &size_read) != OG_SUCCESS) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_READ_PEER_REDO_FAILED, "read peer redo failed");
            break;
        }
        if (size_read == 0) {
            if (is_curr) {
                sleep_needed = OG_TRUE;
                dtc_rbp_rt_log_caught_up_lrp(session, ctx, &peer_lrp_point);
                continue;
            }
            dtc_rbp_rt_next_file(session, ctx);
            sleep_needed = OG_FALSE;
            continue;
        }
        old_point = ctx->curr_point;
        read_result = dtc_rbp_rt_analyze_buffer(session, ctx, size_read,
            LOGFILE_SET(session, ctx->peer_node)->items[file_id].ctrl->block_size, &advanced);
        if (read_result == DTC_RBP_RT_READ_UNSAFE) {
            break;
        }
        if (read_result == DTC_RBP_RT_READ_RETRY) {
            sleep_needed = OG_TRUE;
            continue;
        }
        if (old_point.rst_id == ctx->curr_point.rst_id && old_point.asn == ctx->curr_point.asn &&
            old_point.block_id == ctx->curr_point.block_id && old_point.lfn == ctx->curr_point.lfn) {
            if (is_curr) {
                sleep_needed = OG_TRUE;
                dtc_rbp_rt_log_caught_up_lrp(session, ctx, &peer_lrp_point);
            } else {
                dtc_rbp_rt_next_file(session, ctx);
                sleep_needed = OG_FALSE;
            }
        } else {
            (void)advanced;
            sleep_needed = OG_FALSE;
        }
    }

    dtc_rbp_rt_close_files(ctx);
    OG_LOG_DEBUG_INF("[DTC RBP RT] reader stopped, peer=%u safe=[%u-%u/%u/%llu/%llu] curr_lfn=%llu curr_lsn=%llu "
                     "batches=%llu queue_depth=%u unsafe=%u unsafe_reason=%llu queue_full=%llu commit_full=%llu "
                     "tail_retry=%llu sample_limit=%u",
                     ctx->peer_node, ctx->safe_analyzed_point.rst_id, ctx->safe_analyzed_point.asn,
                     ctx->safe_analyzed_point.block_id, (uint64)ctx->safe_analyzed_point.lfn,
                     ctx->safe_analyzed_point.lsn, (uint64)ctx->curr_point.lfn, (uint64)ctx->curr_point.lsn,
                     ctx->analyzed_batches, dtc_rbp_rt_queue_depth(ctx), (uint32)ctx->unsafe, ctx->unsafe_reason,
                     ctx->queue_full_count, ctx->commit_full_count, ctx->tail_retry_count,
                     (uint32)DTC_RBP_RT_LOG_SAMPLE_LIMIT);
    KNL_SESSION_CLEAR_THREADID(session);
    thread->closed = OG_TRUE;
}

static status_t dtc_rbp_rt_init_local_sets(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        if (dtc_rcy_local_set_init(&ctx->rt_owner_rcy[i]) != OG_SUCCESS) {
            for (uint32 j = 0; j < i; j++) {
                dtc_rcy_local_set_clear(&ctx->rt_owner_rcy[j]);
            }
            return OG_ERROR;
        }
        dtc_rcy_local_set_enable_active_tracking(&ctx->rt_owner_rcy[i]);
    }
    ctx->local_inited = OG_TRUE;
    return OG_SUCCESS;
}

static void dtc_rbp_rt_clear_local_sets(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < DTC_RBP_RT_MAX_OWNER_WORKERS; i++) {
        dtc_rcy_local_set_clear(&ctx->rt_owner_rcy[i]);
        dtc_rcy_local_set_clear(&ctx->snapshot_owner_rcy[i]);
    }
    ctx->local_inited = OG_FALSE;
    ctx->snapshot_valid = OG_FALSE;
}

static status_t dtc_rbp_rt_alloc_batch_slots(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        if (cm_aligned_malloc((int64)ctx->batch_buf_size, "dtc rbp rt batch", &ctx->batch_slots[i].buf) !=
            OG_SUCCESS) {
            for (uint32 j = 0; j < i; j++) {
                cm_aligned_free(&ctx->batch_slots[j].buf);
            }
            return OG_ERROR;
        }
        ctx->batch_slots[i].state = DTC_RBP_RT_BATCH_FREE;
    }
    return OG_SUCCESS;
}

static void dtc_rbp_rt_free_batch_slots(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        cm_aligned_free(&ctx->batch_slots[i].buf);
        ctx->batch_slots[i].state = DTC_RBP_RT_BATCH_FREE;
    }
}

static status_t dtc_rbp_rt_init_queue(dtc_rbp_rt_aly_ctx_t *ctx)
{
    uint64 size = (uint64)DTC_RBP_RT_BATCH_QUEUE_COUNT * sizeof(uint32);
    errno_t ret;

    ctx->free_list.array = (uint32 *)malloc(size);
    ctx->used_list.array = (uint32 *)malloc(size);
    if (ctx->free_list.array == NULL || ctx->used_list.array == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, size * DTC_RBP_RT_QUEUE_ARRAY_COUNT, "dtc rbp rt batch queue");
        CM_FREE_PTR(ctx->free_list.array);
        CM_FREE_PTR(ctx->used_list.array);
        return OG_ERROR;
    }
    ret = memset_sp(ctx->free_list.array, size, 0, size);
    knl_securec_check(ret);
    ret = memset_sp(ctx->used_list.array, size, 0, size);
    knl_securec_check(ret);
    dtc_rbp_rt_atomic_list_init(&ctx->free_list);
    dtc_rbp_rt_atomic_list_init(&ctx->used_list);
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        ctx->free_list.array[i] = i;
    }
    ctx->free_list.end = DTC_RBP_RT_BATCH_QUEUE_COUNT;
    ctx->free_list.writed_end = DTC_RBP_RT_BATCH_QUEUE_COUNT;
    return OG_SUCCESS;
}

static void dtc_rbp_rt_free_queue(dtc_rbp_rt_aly_ctx_t *ctx)
{
    CM_FREE_PTR(ctx->free_list.array);
    CM_FREE_PTR(ctx->used_list.array);
    dtc_rbp_rt_atomic_list_init(&ctx->free_list);
    dtc_rbp_rt_atomic_list_init(&ctx->used_list);
}

static void dtc_rbp_rt_clear_event_queues(dtc_rbp_rt_aly_ctx_t *ctx)
{
    for (uint32 i = 0; i < DTC_RBP_RT_MAX_OWNER_WORKERS; i++) {
        dtc_rbp_rt_event_queue_t *queue = &ctx->owner_queues[i];
        dtc_rbp_rt_event_chunk_t *chunk;

        cm_spin_lock(&queue->lock, NULL);
        chunk = queue->head;
        queue->head = NULL;
        queue->tail = NULL;
        queue->depth = 0;
        cm_spin_unlock(&queue->lock);
        while (chunk != NULL) {
            dtc_rbp_rt_event_chunk_t *next = chunk->next;

            CM_FREE_PTR(chunk);
            chunk = next;
        }
    }
    ctx->outstanding_event_chunks = 0;
}

static void dtc_rbp_rt_release_resources(dtc_rbp_rt_aly_ctx_t *ctx, dtc_rbp_rt_status_t status)
{
    ctx->closing = OG_TRUE;
    cm_close_thread(&ctx->reader_thread);
    for (uint32 i = 0; i < ctx->parse_worker_count; i++) {
        cm_close_thread(&ctx->parser_threads[i]);
    }
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        cm_close_thread(&ctx->owner_threads[i]);
    }
    dtc_rbp_rt_close_files(ctx);
    dtc_rbp_rt_clear_event_queues(ctx);
    dtc_rbp_rt_clear_local_sets(ctx);
    dtc_rbp_rt_free_lfn_points(ctx);
    cm_aligned_free(&ctx->read_buf);
    dtc_rbp_rt_free_batch_slots(ctx);
    dtc_rbp_rt_free_queue(ctx);
    if (ctx->rt_session != NULL) {
        g_knl_callback.release_knl_session(ctx->rt_session);
        ctx->rt_session = NULL;
    }
    for (uint32 i = 0; i < DTC_RBP_RT_MAX_PARSE_WORKERS; i++) {
        if (ctx->parser_sessions[i] != NULL) {
            g_knl_callback.release_knl_session(ctx->parser_sessions[i]);
            ctx->parser_sessions[i] = NULL;
        }
    }
    for (uint32 i = 0; i < DTC_RBP_RT_MAX_OWNER_WORKERS; i++) {
        if (ctx->owner_sessions[i] != NULL) {
            g_knl_callback.release_knl_session(ctx->owner_sessions[i]);
            ctx->owner_sessions[i] = NULL;
        }
    }
    ctx->started = OG_FALSE;
    ctx->status = status;
}

void dtc_rbp_rt_aly_mark_unsafe(uint64 reason)
{
    if (g_dtc == NULL) {
        return;
    }
    dtc_rbp_rt_mark_unsafe(&g_dtc->rbp_rt_aly_ctx, reason, "external unsafe");
}

status_t dtc_rbp_rt_aly_start(knl_session_t *session)
{
    dtc_rbp_rt_aly_ctx_t *ctx;
    knl_session_t *rt_session = NULL;
    errno_t ret;

    if (!dtc_rbp_rt_enabled(session)) {
        if (session != NULL && g_dtc != NULL && DB_IS_CLUSTER(session)) {
            OG_LOG_DEBUG_INF("[DTC RBP RT] runtime analyzer disabled, use_rbp=%u rbp_for_recovery=%u "
                             "rbp_rt_analysis=%u node_count=%u dbstor=%u",
                             (uint32)KNL_RBP_ENABLE(session->kernel), (uint32)KNL_RBP_FOR_RECOVERY(session->kernel),
                             (uint32)KNL_RBP_RT_ANALYSIS(session->kernel), g_dtc->profile.node_count,
                             (uint32)cm_dbs_is_enable_dbs());
        }
        return OG_SUCCESS;
    }
    ctx = &g_dtc->rbp_rt_aly_ctx;
    if (ctx->started) {
        return OG_SUCCESS;
    }

    ret = memset_sp(ctx, sizeof(dtc_rbp_rt_aly_ctx_t), 0, sizeof(dtc_rbp_rt_aly_ctx_t));
    knl_securec_check(ret);
    for (uint32 i = 0; i < DTC_RBP_RT_BATCH_QUEUE_COUNT; i++) {
        ctx->commit_idx[i] = OG_INVALID_ID32;
    }
    ctx->self_node = session->kernel->id;
    ctx->peer_node = (ctx->self_node == 0) ? 1 : 0;
    ctx->parse_worker_count = session->kernel->rbp_attr.rbp_rt_parse_workers;
    ctx->owner_worker_count = session->kernel->rbp_attr.rbp_rt_page_owner_workers;
    if (ctx->parse_worker_count == 0 || ctx->parse_worker_count > DTC_RBP_RT_MAX_PARSE_WORKERS) {
        ctx->parse_worker_count = DTC_RBP_RT_DEFAULT_PARSE_WORKERS;
    }
    if (ctx->owner_worker_count == 0 || ctx->owner_worker_count > DTC_RBP_RT_MAX_OWNER_WORKERS) {
        ctx->owner_worker_count = DTC_RBP_RT_DEFAULT_OWNER_WORKERS;
    }
    ctx->status = DTC_RBP_RT_RUNNING;
    for (uint32 i = 0; i < OG_MAX_LOG_FILES; i++) {
        ctx->log_handle[i] = OG_INVALID_HANDLE;
    }
    ctx->batch_buf_size = LOG_LGWR_BUF_SIZE(session);

    if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&rt_session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DTC RBP RT] failed to alloc analyzer session");
        return OG_ERROR;
    }
    ctx->rt_session = rt_session;
    if (cm_aligned_malloc(DTC_RBP_RT_READ_BUF_SIZE, "dtc rbp rt read buffer", &ctx->read_buf) != OG_SUCCESS) {
        goto error;
    }
    if (dtc_rbp_rt_alloc_batch_slots(ctx) != OG_SUCCESS) {
        goto error;
    }
    if (dtc_rbp_rt_init_queue(ctx) != OG_SUCCESS) {
        goto error;
    }
    if (dtc_rbp_rt_alloc_lfn_points(ctx) != OG_SUCCESS) {
        goto error;
    }
    if (dtc_rbp_rt_init_local_sets(ctx) != OG_SUCCESS) {
        goto error;
    }
    ctx->started = OG_TRUE;
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&ctx->owner_sessions[i]) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RBP RT] failed to alloc owner session, owner=%u", i);
            ctx->started = OG_FALSE;
            goto error;
        }
        ctx->owner_args[i].session = ctx->owner_sessions[i];
        ctx->owner_args[i].worker_id = i;
        if (cm_create_thread(dtc_rbp_rt_owner_proc, 0, &ctx->owner_args[i], &ctx->owner_threads[i]) !=
            OG_SUCCESS) {
            ctx->started = OG_FALSE;
            goto error;
        }
    }
    for (uint32 i = 0; i < ctx->parse_worker_count; i++) {
        if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&ctx->parser_sessions[i]) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DTC RBP RT] failed to alloc parser session, parser=%u", i);
            ctx->started = OG_FALSE;
            goto error;
        }
        ctx->parser_args[i].session = ctx->parser_sessions[i];
        ctx->parser_args[i].worker_id = i;
        if (cm_create_thread(dtc_rbp_rt_parser_proc, 0, &ctx->parser_args[i], &ctx->parser_threads[i]) !=
            OG_SUCCESS) {
            ctx->started = OG_FALSE;
            goto error;
        }
    }
    if (cm_create_thread(dtc_rbp_rt_reader_proc, 0, rt_session, &ctx->reader_thread) != OG_SUCCESS) {
        ctx->started = OG_FALSE;
        goto error;
    }
    OG_LOG_RUN_INF("[DTC RBP RT] runtime analyzer init success, self=%u peer=%u parsers=%u owners=%u "
                   "batch_queue=%u event_chunk=%u/%u batch_buf_size=%llu",
                   ctx->self_node, ctx->peer_node, ctx->parse_worker_count, ctx->owner_worker_count,
                   (uint32)DTC_RBP_RT_BATCH_QUEUE_COUNT, (uint32)DTC_RBP_RT_EVENT_CHUNK_SIZE,
                   (uint32)DTC_RBP_RT_EVENT_CHUNK_LIMIT, ctx->batch_buf_size);
    return OG_SUCCESS;

error:
    dtc_rbp_rt_release_resources(ctx, DTC_RBP_RT_UNSAFE);
    return OG_ERROR;
}

void dtc_rbp_rt_aly_close(knl_session_t *session)
{
    dtc_rbp_rt_aly_ctx_t *ctx;

    if (g_dtc == NULL) {
        return;
    }
    ctx = &g_dtc->rbp_rt_aly_ctx;
    if (!ctx->started) {
        return;
    }
    dtc_rbp_rt_release_resources(ctx, DTC_RBP_RT_CLOSED);
    (void)session;
    OG_LOG_RUN_INF("[DTC RBP RT] runtime analyzer closed");
}

static bool32 dtc_rbp_rt_snapshot_usable(const dtc_rbp_rt_aly_ctx_t *ctx, dtc_rcy_context_t *dtc_rcy)
{
    if (!ctx->started || !ctx->snapshot_valid || ctx->unsafe || ctx->has_gap || ctx->reset_requested ||
        dtc_rcy->full_recovery || dtc_rcy->node_count != 1) {
        return OG_FALSE;
    }
    if (dtc_rcy->rcy_nodes[0].node_id != ctx->peer_node) {
        return OG_FALSE;
    }
    if (ctx->snapshot_safe_point.lfn < dtc_rcy->rcy_log_points[0].rcy_point.lfn) {
        return OG_FALSE;
    }
    if (ctx->rt_start_lfn > dtc_rcy->rcy_log_points[0].rcy_point.lfn) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static void dtc_rbp_rt_freeze_reader_workers(dtc_rbp_rt_aly_ctx_t *ctx)
{
    uint32 wait_ms = 0;

    ctx->frozen = OG_TRUE;
    ctx->status = DTC_RBP_RT_FROZEN;
    cm_close_thread(&ctx->reader_thread);

    while (wait_ms < DTC_RBP_RT_DRAIN_TIMEOUT_MS && !ctx->unsafe) {
        bool32 drained;
        bool32 has_uncommitted;
        uint32 queue_depth;
        uint32 free_idx[DTC_RBP_RT_BATCH_QUEUE_COUNT];
        uint32 free_count;

        cm_sleep(1);
        wait_ms++;
        cm_spin_lock(&ctx->state_lock, NULL);
        dtc_rbp_rt_commit_completed_batches_locked(ctx, free_idx, &free_count);
        has_uncommitted = dtc_rbp_rt_has_uncommitted_batches(ctx);
        cm_spin_unlock(&ctx->state_lock);
        dtc_rbp_rt_push_committed_free(ctx, free_idx, free_count);
        queue_depth = dtc_rbp_rt_queue_depth(ctx);
        drained = (bool32)(queue_depth == 0 && !has_uncommitted && dtc_rbp_rt_event_queues_drained(ctx));
        if (drained) {
            break;
        }
    }
    cm_spin_lock(&ctx->state_lock, NULL);
    {
        bool32 has_uncommitted = dtc_rbp_rt_has_uncommitted_batches(ctx);

        cm_spin_unlock(&ctx->state_lock);
        if (!ctx->unsafe &&
            (dtc_rbp_rt_queue_depth(ctx) != 0 || has_uncommitted || !dtc_rbp_rt_event_queues_drained(ctx))) {
            dtc_rbp_rt_mark_unsafe(ctx, DTC_RBP_RT_UNSAFE_DRAIN_RUNTIME_QUEUE_TIMEOUT,
                                   "drain runtime queue timeout");
        }
    }
    for (uint32 i = 0; i < ctx->parse_worker_count; i++) {
        cm_close_thread(&ctx->parser_threads[i]);
    }
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        cm_close_thread(&ctx->owner_threads[i]);
    }
    {
        uint32 free_idx[DTC_RBP_RT_BATCH_QUEUE_COUNT];
        uint32 free_count;

        cm_spin_lock(&ctx->state_lock, NULL);
        dtc_rbp_rt_commit_completed_batches_locked(ctx, free_idx, &free_count);
        cm_spin_unlock(&ctx->state_lock);
        dtc_rbp_rt_push_committed_free(ctx, free_idx, free_count);
    }
}

static void dtc_rbp_rt_snapshot_locals(dtc_rbp_rt_aly_ctx_t *ctx)
{
    errno_t ret;

    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        ret = memcpy_sp(&ctx->snapshot_owner_rcy[i], sizeof(dtc_rcy_local_set_t), &ctx->rt_owner_rcy[i],
                        sizeof(dtc_rcy_local_set_t));
        knl_securec_check(ret);
        ret = memset_sp(&ctx->rt_owner_rcy[i], sizeof(dtc_rcy_local_set_t), 0, sizeof(dtc_rcy_local_set_t));
        knl_securec_check(ret);
    }
    ctx->snapshot_safe_point = ctx->safe_analyzed_point;
    ctx->snapshot_next_point = ctx->safe_analyzed_point;
    ctx->snapshot_valid = OG_TRUE;
}

bool32 dtc_rbp_rt_aly_prepare_partial(knl_session_t *session, log_point_t *safe_point, log_point_t *next_point)
{
    dtc_rbp_rt_aly_ctx_t *ctx;
    dtc_rcy_context_t *dtc_rcy;

    if (g_dtc == NULL) {
        return OG_FALSE;
    }
    ctx = &g_dtc->rbp_rt_aly_ctx;
    dtc_rcy = DTC_RCY_CONTEXT;
    if (!ctx->started || dtc_rcy->full_recovery || session->kernel->db.recover_for_restore) {
        return OG_FALSE;
    }
    dtc_rbp_rt_freeze_reader_workers(ctx);
    if (!ctx->unsafe) {
        dtc_rbp_rt_snapshot_locals(ctx);
    }
    if (!dtc_rbp_rt_snapshot_usable(ctx, dtc_rcy)) {
        OG_LOG_RUN_WAR("[DTC RBP RT] runtime snapshot unusable, fallback: started=%u unsafe=%u reason=%llu gap=%u "
                       "node_count=%u full=%u peer=%u rcy_node=%u safe_lfn=%llu curr_lfn=%llu curr_lsn=%llu "
                       "rcy_lfn=%llu rt_start_lfn=%llu queue_depth=%u",
                       (uint32)ctx->started, (uint32)ctx->unsafe, ctx->unsafe_reason, (uint32)ctx->has_gap,
                       dtc_rcy->node_count, (uint32)dtc_rcy->full_recovery, ctx->peer_node,
                       dtc_rcy->rcy_nodes[0].node_id, (uint64)ctx->snapshot_safe_point.lfn,
                       (uint64)ctx->curr_point.lfn, (uint64)ctx->curr_point.lsn,
                       (uint64)dtc_rcy->rcy_log_points[0].rcy_point.lfn, ctx->rt_start_lfn,
                       dtc_rbp_rt_queue_depth(ctx));
        dtc_rbp_rt_release_resources(ctx, DTC_RBP_RT_UNSAFE);
        return OG_FALSE;
    }
    if (safe_point != NULL) {
        *safe_point = ctx->snapshot_safe_point;
    }
    if (next_point != NULL) {
        *next_point = ctx->snapshot_next_point;
    }
    uint64 active_items = 0;
    bool32 active_ready = OG_TRUE;
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        active_items += ctx->snapshot_owner_rcy[i].active_item_count;
        if (!dtc_rcy_local_set_active_ready(&ctx->snapshot_owner_rcy[i])) {
            active_ready = OG_FALSE;
        }
    }
    OG_LOG_RUN_INF("[DTC RBP RT] runtime snapshot accepted, peer=%u safe_lfn=%llu rcy_lfn=%llu "
                   "rt_start_lfn=%llu prune_lfn=%llu active_items=%llu active_ready=%u batches=%llu pages=%llu "
                   "parsed_events=%llu applied_events=%llu",
                   ctx->peer_node, (uint64)ctx->snapshot_safe_point.lfn,
                   (uint64)dtc_rcy->rcy_log_points[0].rcy_point.lfn, ctx->rt_start_lfn,
                   (uint64)ctx->peer_prune_point.lfn, active_items, (uint32)active_ready,
                   ctx->analyzed_batches, ctx->analyzed_pages, ctx->parsed_events, ctx->applied_events);
    return OG_TRUE;
}

static bool32 dtc_rbp_rt_active_item_filter(const rcy_set_item_t *item, void *arg)
{
    uint64 prune_lfn = *(uint64 *)arg;

    if (item == NULL || !item->need_replay) {
        return OG_FALSE;
    }
    if (prune_lfn == 0) {
        return OG_TRUE;
    }
    if (item->dirty_max_lfn != 0 && item->dirty_max_lfn < prune_lfn) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static status_t dtc_rbp_rt_reroute_recovery_masters(dtc_rbp_rt_aly_ctx_t *ctx, uint64 *checked, uint64 *changed,
    uint64 *invalid)
{
    dtc_rcy_context_t *dtc_rcy = DTC_RCY_CONTEXT;
    page_id_t bad_page = { 0 };
    uint8 bad_master = OG_INVALID_ID8;

    *checked = 0;
    *changed = 0;
    *invalid = 0;
    for (rcy_set_item_pool_t *pool = dtc_rcy->rcy_set.item_pools; pool != NULL; pool = pool->next) {
        for (int64 i = 0; i < pool->hwm; i++) {
            rcy_set_item_t *item = &pool->items[i];
            uint8 new_master = OG_INVALID_ID8;

            if (!item->need_replay) {
                continue;
            }
            (*checked)++;
            drc_get_page_remaster_id(item->page_id, &new_master);
            if (new_master >= OG_MAX_INSTANCES || new_master == ctx->peer_node) {
                if (*invalid == 0) {
                    bad_page = item->page_id;
                    bad_master = new_master;
                }
                (*invalid)++;
                continue;
            }
            if (item->master_id != new_master) {
                item->master_id = new_master;
                (*changed)++;
            }
        }
    }
    if (*invalid != 0) {
        OG_LOG_RUN_ERR("[DTC RBP RT] invalid remaster target for runtime recovery set, peer=%u checked=%llu "
                       "changed=%llu invalid=%llu first_bad_page=%u-%u bad_master=%u",
                       ctx->peer_node, *checked, *changed, *invalid, bad_page.file, bad_page.page, bad_master);
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[DTC RBP RT] reroute recovery masters, peer=%u checked=%llu changed=%llu invalid=%llu",
                   ctx->peer_node, *checked, *changed, *invalid);
    return OG_SUCCESS;
}

status_t dtc_rbp_rt_aly_finish_partial(knl_session_t *session)
{
    dtc_rbp_rt_aly_ctx_t *ctx;
    dtc_rcy_context_t *dtc_rcy;
    uint64 prune_lfn;
    uint64 snapshot_items_before = 0;
    uint64 snapshot_items_after = 0;
    uint64 reroute_checked;
    uint64 reroute_changed;
    uint64 reroute_invalid;
    uint32 queue_peak = 0;

    if (g_dtc == NULL) {
        return OG_ERROR;
    }
    ctx = &g_dtc->rbp_rt_aly_ctx;
    dtc_rcy = DTC_RCY_CONTEXT;
    if (!dtc_rbp_rt_snapshot_usable(ctx, dtc_rcy)) {
        return OG_ERROR;
    }
    prune_lfn = ctx->peer_prune_point.lfn;
    for (uint32 i = 0; i < ctx->owner_worker_count; i++) {
        dtc_rbp_rt_prune_local_set_stats(ctx, &ctx->snapshot_owner_rcy[i], prune_lfn, &snapshot_items_before,
            &snapshot_items_after);
        queue_peak = MAX(queue_peak, ctx->owner_queues[i].peak_depth);
    }
    if (dtc_rcy_merge_local_sets_to_recovery(session, ctx->snapshot_owner_rcy, ctx->owner_worker_count,
        dtc_rbp_rt_active_item_filter, &prune_lfn, OG_TRUE, "DTC RBP RT") != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (dtc_rbp_rt_reroute_recovery_masters(ctx, &reroute_checked, &reroute_changed, &reroute_invalid) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    if (dtc_rbp_rt_export_lfn_points(ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (log_cmp_point(&session->kernel->redo_ctx.redo_end_point, &ctx->snapshot_safe_point) < 0) {
        session->kernel->redo_ctx.redo_end_point = ctx->snapshot_safe_point;
    }
    session->kernel->redo_ctx.rbp_aly_lsn = MAX(session->kernel->redo_ctx.rbp_aly_lsn, ctx->snapshot_safe_point.lsn);
    rbp_reset_unsafe(session);
    OG_LOG_RUN_INF("[DTC RBP RT] runtime local finalized, peer=%u safe_lfn=%llu batches=%llu pages=%llu "
                   "snapshot_items=%llu/%llu rcy_items=%llu partial_items=%llu lfn_points=%u pruned_lfn=%llu "
                   "reroute_checked=%llu reroute_changed=%llu parsers=%u owners=%u event_peak=%u "
                   "queue_peak=%u queue_full=%llu commit_full=%llu tail_retry=%llu sample_limit=%u "
                   "active_merge=%u merge_order=tail_global_then_rt_snapshot",
                   ctx->peer_node, (uint64)ctx->snapshot_safe_point.lfn, ctx->analyzed_batches,
                   ctx->analyzed_pages, snapshot_items_after, snapshot_items_before,
                   dtc_rcy->rcy_set.size,
                   (uint64)dtc_rcy->rbp_partial_ctx.item_count,
                   dtc_rcy->rbp_lfn_point_maps[ctx->peer_node].count, prune_lfn, reroute_checked, reroute_changed,
                   ctx->parse_worker_count, ctx->owner_worker_count, ctx->event_chunk_peak,
                   queue_peak, ctx->queue_full_count, ctx->commit_full_count, ctx->tail_retry_count,
                   (uint32)DTC_RBP_RT_LOG_SAMPLE_LIMIT, 0);
    dtc_rbp_rt_release_resources(ctx, DTC_RBP_RT_CLOSED);
    return OG_SUCCESS;
}

void dtc_rbp_rt_aly_abort_partial(knl_session_t *session)
{
    dtc_rbp_rt_aly_ctx_t *ctx;

    if (g_dtc == NULL) {
        return;
    }
    ctx = &g_dtc->rbp_rt_aly_ctx;
    if (!ctx->started) {
        return;
    }
    ctx->unsafe = OG_TRUE;
    ctx->unsafe_reason = (ctx->unsafe_reason == 0) ? DTC_RBP_RT_UNSAFE_STOP_RELEASE : ctx->unsafe_reason;
    dtc_rbp_rt_release_resources(ctx, DTC_RBP_RT_UNSAFE);
    (void)session;
}

bool32 dtc_rbp_rt_aly_try_build_partial(knl_session_t *session)
{
    log_point_t safe_point;
    log_point_t next_point;

    if (!dtc_rbp_rt_aly_prepare_partial(session, &safe_point, &next_point)) {
        return OG_FALSE;
    }
    (void)next_point;
    if (dtc_rbp_rt_aly_finish_partial(session) != OG_SUCCESS) {
        dtc_rbp_rt_aly_abort_partial(session);
        return OG_FALSE;
    }
    return OG_TRUE;
}
