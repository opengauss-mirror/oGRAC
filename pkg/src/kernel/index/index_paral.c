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
 * index_paral.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/index_paral.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "index_common.h"
#include "knl_common.h"
#include "knl_context.h"
#include "knl_table.h"
#include "knl_index.h"

static inline void idx_set_err_msg(char *msg)
{
    int32 err_code;
    const char *err_msg = NULL;
    errno_t err;

    if (strlen(msg) > 0) {
        return;
    }

    cm_get_error(&err_code, &err_msg, NULL);
    size_t len = 0;
    if (cm_strstri(err_msg, "Index build failed: ") != NULL) {
        len = strlen("Index build failed: ");
        err_msg += len;
    }
    err = memcpy_sp(msg, OG_MESSAGE_BUFFER_SIZE, err_msg, OG_MESSAGE_BUFFER_SIZE - len);
    knl_securec_check(err);
}

static knl_part_locate_t idx_get_part_loc(spinlock_t *parl_lock, table_t *table, idx_part_info_t *part_info)
{
    knl_part_locate_t part_loc = { OG_INVALID_ID32, OG_INVALID_ID32 };
    table_part_t *table_subpart = NULL;

    for (;;) {
        cm_spin_lock(parl_lock, NULL);
        if (part_info->part_loc.part_no == table->part_table->desc.partcnt) {
            break;
        }

        table_part_t *table_part = TABLE_GET_PART(table, part_info->part_loc.part_no);
        if (table_part == NULL) {
            part_info->part_loc.part_no++;
            cm_spin_unlock(parl_lock);
            continue;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (part_info->part_loc.subpart_no == table_part->desc.subpart_cnt) {
                part_info->part_loc.subpart_no = 0;
                part_info->part_loc.part_no++;
            }

            if (part_info->part_loc.part_no == table->part_table->desc.partcnt) {
                break;
            }

            table_part = TABLE_GET_PART(table, part_info->part_loc.part_no);
            if (table_part == NULL) {
                part_info->part_loc.part_no++;
                cm_spin_unlock(parl_lock);
                continue;
            }

            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[part_info->part_loc.subpart_no]);
            if (table_subpart == NULL || table_subpart->heap.segment == NULL) {
                part_info->part_loc.subpart_no++;
                cm_spin_unlock(parl_lock);
                continue;
            }

            part_loc = part_info->part_loc;
            part_info->part_loc.subpart_no++;
            break;
        }

        if (table_part->heap.segment == NULL) {
            part_info->part_loc.part_no++;
            cm_spin_unlock(parl_lock);
            continue;
        }
        part_loc = part_info->part_loc;
        part_info->part_loc.part_no++;
        break;
    }
    cm_spin_unlock(parl_lock);
    return part_loc;
}

static void idx_part_paral_proc(thread_t *thread)
{
    idxpart_worker_t *worker = (idxpart_worker_t *)thread->argument;
    knl_part_locate_t part_loc;
    knl_session_t *session = worker->session;
    idxpart_paral_ctx_t *ogx = worker->ogx;
    knl_dictionary_t *dc = ogx->private_dc;
    table_t *table = DC_TABLE(dc);
    thread->result = OG_SUCCESS;

    while (!thread->closed) {
        part_loc = idx_get_part_loc(&ogx->parl_lock, table, &ogx->part_info);
        if (part_loc.part_no == OG_INVALID_ID32 && part_loc.subpart_no == OG_INVALID_ID32) {
            thread->result = OG_SUCCESS;
            break;
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            idx_set_err_msg(ogx->err_msg);
            thread->result = OG_ERROR;
            break;
        }

        if (ogx->index_cnt == 1) {
            if (db_fill_index_entity_paral(session, dc, ogx->indexes[0], part_loc, ogx->paral_count,
                ogx->nologging) != OG_SUCCESS) {
                idx_set_err_msg(ogx->err_msg);
                thread->result = OG_ERROR;
                break;
            }
        } else {
            if (db_fill_multi_indexes_paral(session, dc, ogx->indexes, ogx->index_cnt,
                ogx->paral_count, part_loc, ogx->nologging) != OG_SUCCESS) {
                idx_set_err_msg(ogx->err_msg);
                thread->result = OG_ERROR;
                break;
            }
        }
    }
    worker->is_working = OG_FALSE;
    return;
}

status_t idxpart_alloc_resource(knl_session_t *session, uint32 paral_no, idxpart_paral_ctx_t *paral_ctx)
{
    uint32 main_pool_id = session->id % session->kernel->temp_ctx_count;
    uint32 worker_pool_id;
    idxpart_worker_t *worker = NULL;

    for (uint32 i = 0; i < paral_no; i++) {
        worker = &paral_ctx->workers[i];
        if (g_knl_callback.alloc_knl_session(OG_FALSE, (knl_handle_t*)&worker->session) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_EXCEED_SESSIONS_PER_USER, session->kernel->attr.max_sessions);
            return OG_ERROR;
        }

        worker_pool_id = (main_pool_id + i) % session->kernel->temp_ctx_count;
        worker->session->temp_pool = &worker->session->kernel->temp_pool[worker_pool_id];
        worker->session->temp_mtrl->pool = worker->session->temp_pool;
        worker->ogx = paral_ctx;
        worker->is_working = OG_TRUE;
        if (cm_create_thread(idx_part_paral_proc, 0, &paral_ctx->workers[i], &worker->thread) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

void idxpart_release_resource(uint32 paral_no, idxpart_paral_ctx_t *paral_ctx)
{
    idxpart_worker_t *worker = NULL;

    for (uint32 i = 0; i < paral_no; i++) {
        worker = &paral_ctx->workers[i];
        worker->is_working = OG_FALSE;
        if (worker->session != NULL) {
            worker->session->canceled = OG_TRUE;
        }

        if (!worker->thread.closed) {
            cm_close_thread(&worker->thread);
        }
    }

    for (uint32 i = 0; i < paral_no; i++) {
        worker = &paral_ctx->workers[i];
        if (worker->session != NULL) {
            g_knl_callback.release_knl_session((knl_handle_t *)worker->session);
        }
    }
}

void idx_start_all_workers(idx_paral_sort_ctx_t *ogx, idx_sort_phase_t phase)
{
    ogx->phase = phase;

    for (uint32 i = 0; i < ogx->paral_count; i++) {
        ogx->workers[i].is_working = OG_TRUE;
        ogx->workers[i].phase = phase;
    }
    ogx->working_count = ogx->paral_count;
}

status_t idx_wait_all_workers(knl_session_t *session, idx_paral_sort_ctx_t *ogx)
{
    idx_sort_worker_t *worker = NULL;
    uint32 id;
    uint32 count;

    do {
        count = ogx->paral_count;
        for (id = 0; id < ogx->paral_count; id++) {
            worker = &ogx->workers[id];
            if (!worker->is_working) {
                count--;
            }

            if (worker->thread.result != OG_SUCCESS) {
                OG_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, ogx->err_msg);
                return OG_ERROR;
            }
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            return OG_ERROR;
        }
        cm_sleep(100);
    } while (count != 0);
    return OG_SUCCESS;
}

static status_t idx_fill_segments(knl_session_t *session, knl_cursor_t *cursor,
    mtrl_sort_ctrl_t *sort_ctrl, idx_sort_worker_t *worker)
{
    mtrl_context_t *mtrl_ctx = worker->mtrl_ctx;
    index_t *index = worker->ogx->btree[0]->index;
    char *key = NULL;
    mtrl_rowid_t rid;
    status_t status = OG_SUCCESS;

    sort_ctrl->ogx = mtrl_ctx;
    sort_ctrl->segment = mtrl_ctx->segments[worker->seg_id];
    key = (char *)cm_push(session->stack, OG_KEY_BUF_SIZE);
    for (;;) {
        if (knl_fetch(session, cursor) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (cursor->eof) {
            status = OG_SUCCESS;
            break;
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (knl_make_key(session, cursor, index, key) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (index->desc.cr_mode == CR_ROW) {
            ((btree_key_t *)key)->scn = cursor->scn;
        } else {
            ((pcrb_key_t *)key)->itl_id = OG_INVALID_ID8;
        }

        if (mtrl_insert_row_parallel(mtrl_ctx, worker->seg_id, key, sort_ctrl, &rid) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        worker->rows++;
    }
    cm_pop(session->stack);
    return status;
}

static status_t idx_fill_part_segments(knl_session_t *session, knl_cursor_t *cursor,
    mtrl_sort_ctrl_t *sort_ctrl, idx_sort_worker_t *worker)
{
    knl_part_locate_t part_loc;

    for (;;) {
        part_loc = idx_get_part_loc(&worker->ogx->parl_lock, cursor->table, &worker->ogx->part_info);
        if (part_loc.part_no == OG_INVALID_ID32 && part_loc.subpart_no == OG_INVALID_ID32) {
            break;
        }

        cursor->part_loc = part_loc;
        if (knl_reopen_cursor(session, cursor, worker->ogx->private_dc) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (idx_fill_segments(session, cursor, sort_ctrl, worker) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t idx_init_build_segment(knl_session_t *session, idx_sort_worker_t *worker,
    mtrl_sort_ctrl_t *sort_ctrl, knl_cursor_t *cursor)
{
    uint32 cpu_count = session->kernel->attr.cpu_count;

    errno_t err = memset_sp(sort_ctrl, sizeof(mtrl_sort_ctrl_t), 0, sizeof(mtrl_sort_ctrl_t));
    knl_securec_check(err);
    sort_ctrl->initialized = OG_TRUE;
    sort_ctrl->use_parallel = OG_TRUE;
    session->thread_shared = OG_TRUE;

    if (worker->ogx->is_global || !IS_PART_INDEX(worker->ogx->btree[0]->index)) {
        sort_ctrl->thread_count = MIN(cpu_count / worker->ogx->paral_count, MAX_SORT_THREADS);
    } else {
        sort_ctrl->thread_count = MIN_SORT_THREADS;
    }
    sort_ctrl->thread_count = MAX(MIN_SORT_THREADS, sort_ctrl->thread_count);

    for (uint32 i = 0; i < sort_ctrl->thread_count; i++) {
        if (cm_create_thread(mtrl_sort_proc, 0, sort_ctrl, &sort_ctrl->threads[i]) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    mtrl_set_sort_type(worker->mtrl_ctx->segments[worker->seg_id], MTRL_SORT_TYPE_QSORT);

    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->part_loc = worker->ogx->part_info.curr_part;
    if (knl_open_cursor(session, cursor, worker->ogx->private_dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    cursor->query_scn = DB_CURR_SCN(session);
    return OG_SUCCESS;
}

static status_t idx_build_segment(knl_session_t *session, idx_sort_worker_t *worker)
{
    mtrl_context_t *mtrl_ctx = worker->mtrl_ctx;
    status_t status;
    mtrl_sort_ctrl_t sort_ctrl;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    if (idx_init_build_segment(session, worker, &sort_ctrl, cursor) != OG_SUCCESS) {
        (void)mtrl_sort_clean(&sort_ctrl);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }
    
    // fetch + insert + sort_page phase
    if (worker->ogx->is_global) {
        status = idx_fill_part_segments(session, cursor, &sort_ctrl, worker);
    } else {
        cursor->scan_range = worker->scan_range;
        SET_ROWID_PAGE(&cursor->rowid, cursor->scan_range.l_page);
        cursor->rowid.slot = INVALID_SLOT;
        status = idx_fill_segments(session, cursor, &sort_ctrl, worker);
    }

    if (mtrl_sort_clean(&sort_ctrl) != OG_SUCCESS) {
        status = OG_ERROR;
    }

    mtrl_close_segment(mtrl_ctx, worker->seg_id);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    if (status == OG_ERROR) {
        return OG_ERROR;
    }

    // sort own segment
    if (worker->rows > 0) {
        if (mtrl_ctx->segments[worker->seg_id]->vm_list.count > MIN_MTRL_SORT_EXTENTS &&
            mtrl_ctx->segments[worker->seg_id]->vm_list.count < MAX_MTRL_SORT_EXTENTS) {
            status = mtrl_sort_segment_parallel(&sort_ctrl, mtrl_ctx, worker->seg_id);
        } else {
            status = mtrl_sort_segment(mtrl_ctx, worker->seg_id);
        }
    }

    return status;
}

static void idx_get_2segments(idx_sort_worker_t *worker, id_list_t *sort_info, uint32 *id1, uint32 *id2)
{
    idx_paral_sort_ctx_t *ogx = worker->ogx;

    cm_spin_lock(&ogx->parl_lock, NULL);
    if (sort_info->count > 1) {
        // 2 means at least 2 sub-sessions should be left in the list.
        if (!(sort_info->count == 2 && ogx->working_count == 1 && worker->ogx->index_count == 1)) {
            *id1 = sort_info->first;
            *id2 = ogx->workers[*id1].next_id;
            knl_panic(*id1 != OG_INVALID_ID32 && *id2 != OG_INVALID_ID32);
            sort_info->first = ogx->workers[*id2].next_id;
            // 2 means two ids are taken out from list, then list count need minus 2.
            sort_info->count = sort_info->count - 2;

            if (sort_info->count == 0) {
                sort_info->last = OG_INVALID_ID32;
            }
            cm_spin_unlock(&ogx->parl_lock);
            return;
        }
    }

    worker->is_working = OG_FALSE;
    ogx->working_count--;
    cm_spin_unlock(&ogx->parl_lock);
    return;
}

static void idx_seg_in_list(idx_paral_sort_ctx_t *ogx, id_list_t *sort_info, uint32 id)
{
    cm_spin_lock(&ogx->parl_lock, NULL);
    if (sort_info->count == 0) {
        sort_info->first = id;
        sort_info->last = id;
        sort_info->count++;
        cm_spin_unlock(&ogx->parl_lock);
        return;
    }

    ogx->workers[sort_info->last].next_id = id;
    sort_info->last = id;
    sort_info->count++;
    cm_spin_unlock(&ogx->parl_lock);
    return;
}

static status_t idx_merge_segments(idx_sort_worker_t *worker)
{
    uint32 id1 = 0;
    uint32 id2 = 0;
    id_list_t *sort_info = NULL;

    if (worker->ogx->index_count > 1) {
        sort_info = &worker->ogx->multi_sort_info[worker->index_id];
    } else {
        sort_info = &worker->ogx->sort_info;
    }

    for (;;) {
        if (worker->phase != MERGE_SEGMENT_PHASE) {
            break;
        }

        idx_get_2segments(worker, sort_info, &id1, &id2);
        if (!worker->is_working) {
            break;
        }

        if (worker->ogx->workers[id1].rows == 0 && worker->ogx->workers[id2].rows == 0) {
            continue;
        } else if (worker->ogx->workers[id1].rows == 0) {
            idx_seg_in_list(worker->ogx, sort_info, id2);
            continue;
        } else if (worker->ogx->workers[id2].rows == 0) {
            idx_seg_in_list(worker->ogx, sort_info, id1);
            continue;
        }

        if (mtrl_merge_2pools((knl_handle_t)worker->ogx, id1, id2) != OG_SUCCESS) {
            return OG_ERROR;
        }

        idx_seg_in_list(worker->ogx, sort_info, id1);
    }
    return OG_SUCCESS;
}

static status_t idx_init_sort_workers(idx_sort_worker_t *worker, btree_t *btree)
{
    mtrl_segment_type_t type;

    // pop stack when session released
    mtrl_context_t *mtrl_ctx = cm_push(worker->session->stack, sizeof(mtrl_context_t));

    worker->mtrl_ctx = mtrl_ctx;
    worker->mtrl_ctx->session = (handle_t)worker->session;
    mtrl_init_context(worker->mtrl_ctx, worker->session);
    worker->mtrl_ctx->pool = worker->session->temp_pool;

    if (btree->index->desc.cr_mode == CR_PAGE) {
        type = MTRL_SEGMENT_PCR_BTREE;
        worker->mtrl_ctx->sort_cmp = pcrb_compare_mtrl_key;
    } else {
        type = MTRL_SEGMENT_RCR_BTREE;
        worker->mtrl_ctx->sort_cmp = btree_compare_mtrl_key;
    }

    if (OG_SUCCESS != mtrl_create_segment(worker->mtrl_ctx, type, (handle_t)btree, &worker->seg_id)) {
        return OG_ERROR;
    }

    if (OG_SUCCESS != mtrl_open_segment(worker->mtrl_ctx, worker->seg_id)) {
        mtrl_release_context(worker->mtrl_ctx);
        return OG_ERROR;
    }

    worker->segment = worker->mtrl_ctx->segments[worker->seg_id];
    return OG_SUCCESS;
}

static void idx_fetch_paral_proc(thread_t *thread)
{
    idx_sort_worker_t *worker = (idx_sort_worker_t *)thread->argument;
    idx_paral_sort_ctx_t *ogx = worker->ogx;
    knl_session_t *session = worker->session;

    while (!thread->closed) {
        if (!worker->is_working || worker->ogx->phase != BUILD_SEGMENT_PHASE) {
            cm_sleep(10);
            continue;
        }

        if (idx_init_sort_workers(worker, ogx->btree[0]) != OG_SUCCESS) {
            idx_set_err_msg(ogx->err_msg);
            thread->result = OG_ERROR;
            break;
        }

        worker->mtrl_ctx->err_msg = g_tls_error.message;
        if (idx_build_segment(session, worker) != OG_SUCCESS) {
            idx_set_err_msg(ogx->err_msg);
            thread->result = OG_ERROR;
            break;
        }
        break;
    }

    worker->is_working = OG_FALSE;
    ogx->working_count--;
    if (thread->result != OG_SUCCESS) {
        return;
    }

    while (!thread->closed) {
        if (!worker->is_working || worker->ogx->phase != MERGE_SEGMENT_PHASE) {
            cm_sleep(100);
            continue;
        }

        if (idx_merge_segments(worker) != OG_SUCCESS) {
            idx_set_err_msg(ogx->err_msg);
            thread->result = OG_ERROR;
            worker->is_working = OG_FALSE;
            ogx->working_count--;
            return;
        }
        break;
    }
    worker->is_working = OG_FALSE;
    return;
}

void idx_fetch_release_resource(idx_paral_sort_ctx_t *sort_ctx)
{
    idx_sort_worker_t *worker = NULL;

    for (uint32 i = 0; i < sort_ctx->paral_count; i++) {
        worker = &sort_ctx->workers[i];
        worker->is_working = OG_FALSE;
        if (worker->session != NULL) {
            worker->session->canceled = OG_TRUE;
        }

        if (!worker->thread.closed) {
            cm_close_thread(&worker->thread);
        }
    }

    for (uint32 i = 0; i < sort_ctx->paral_count; i++) {
        worker = &sort_ctx->workers[i];
        mtrl_release_context(worker->mtrl_ctx);

        if (worker->session != NULL) {
            cm_pop(worker->session->stack);
            g_knl_callback.release_knl_session((knl_handle_t *)worker->session);
        }
    }
    return;
}

status_t idx_fetch_alloc_resource(knl_session_t *session, idx_paral_sort_ctx_t *sort_ctx)
{
    idx_sort_worker_t *worker = NULL;

    for (uint32 i = 0; i < sort_ctx->paral_count; i++) {
        worker = &sort_ctx->workers[i];
        if (g_knl_callback.alloc_knl_session(OG_FALSE, (knl_handle_t*)&worker->session) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_EXCEED_SESSIONS_PER_USER, session->kernel->attr.max_sessions);
            return OG_ERROR;
        }

        worker->session->temp_pool = &worker->session->kernel->temp_pool[worker->pool_id];
        worker->session->temp_mtrl->pool = worker->session->temp_pool;
        worker->ogx = sort_ctx;
        worker->id = i;

        if (cm_create_thread(idx_fetch_paral_proc, 0, worker, &worker->thread) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

void idx_start_build_workers(idx_paral_sort_ctx_t *ogx, idx_sort_phase_t phase)
{
    ogx->phase = phase;

    for (uint32 i = 0; i < ogx->build_count; i++) {
        ogx->build_workers[i].is_working = OG_TRUE;
    }
    ogx->working_count = ogx->build_count;
}

status_t idx_wait_build_workers(knl_session_t *session, idx_paral_sort_ctx_t *ogx)
{
    idx_build_worker_t *worker = NULL;
    uint32 id;
    uint32 count;

    do {
        count = ogx->build_count;
        for (id = 0; id < ogx->build_count; id++) {
            worker = &ogx->build_workers[id];
            if (!worker->is_working) {
                count--;
            }

            if (worker->thread.result != OG_SUCCESS) {
                OG_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, ogx->err_msg);
                return OG_ERROR;
            }
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            return OG_ERROR;
        }
        cm_sleep(100);
    } while (count != 0);
    return OG_SUCCESS;
}

static status_t idx_close_multi_segments(mtrl_sort_ctrl_t *sort_ctrl, idx_build_worker_t *build_worker)
{
    status_t status = OG_SUCCESS;
    idx_multi_info_t *curr_idx_info = NULL;

    for (uint32 i = 0; i < build_worker->index_count; i++) {
        curr_idx_info = &build_worker->idx_info[i];
        if (mtrl_sort_clean(&sort_ctrl[i]) != OG_SUCCESS) {
            status = OG_ERROR;
        }

        mtrl_close_segment(&curr_idx_info->mtrl_ctx, curr_idx_info->seg_id);
    }

    return status;
}

static status_t idx_fill_muti_segments(knl_session_t *session, knl_cursor_t *cursor,
    mtrl_sort_ctrl_t *sort_ctrl, idx_build_worker_t *build_worker)
{
    char *key = NULL;
    mtrl_rowid_t rid;
    status_t status = OG_SUCCESS;
    idx_multi_info_t *curr_idx_info = NULL;
    index_t *index = NULL;

    key = (char *)cm_push(session->stack, OG_KEY_BUF_SIZE);
    for (;;) {
        if (knl_fetch(session, cursor) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (cursor->eof) {
            status = OG_SUCCESS;
            break;
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        for (uint32 i = 0; i < build_worker->index_count; i++) {
            curr_idx_info = &build_worker->idx_info[i];
            index = curr_idx_info->btree->index;

            if (knl_make_key(session, cursor, index, key) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }

            if (index->desc.cr_mode == CR_ROW) {
                ((btree_key_t *)key)->scn = cursor->scn;
            } else {
                ((pcrb_key_t *)key)->itl_id = OG_INVALID_ID8;
            }

            if (mtrl_insert_row_parallel(&curr_idx_info->mtrl_ctx, curr_idx_info->seg_id,
                key, &sort_ctrl[i], &rid) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
        }

        if (status == OG_ERROR) {
            break;
        }

        build_worker->rows++;
    }

    cm_pop(session->stack);
    return status;
}

static status_t idx_init_multi_segment(knl_session_t *session, idx_build_worker_t *worker,
    mtrl_sort_ctrl_t *sort_ctrl, knl_cursor_t *cursor)
{
    for (uint32 i = 0; i < worker->index_count; i++) {
        sort_ctrl[i].initialized = OG_TRUE;
        sort_ctrl[i].use_parallel = OG_TRUE;
        session->thread_shared = OG_TRUE;
        sort_ctrl[i].thread_count = MIN_SORT_THREADS;
        sort_ctrl[i].ogx = &worker->idx_info[i].mtrl_ctx;
        sort_ctrl[i].segment = worker->idx_info[i].mtrl_ctx.segments[worker->idx_info[i].seg_id];

        for (uint32 j = 0; j < sort_ctrl[i].thread_count; j++) {
            if (cm_create_thread(mtrl_sort_proc, 0, &sort_ctrl[i], &sort_ctrl[i].threads[j]) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
        mtrl_set_sort_type(worker->idx_info[i].mtrl_ctx.segments[worker->idx_info[i].seg_id], MTRL_SORT_TYPE_QSORT);
    }

    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->part_loc = worker->ogx->part_info.curr_part;
    if (knl_open_cursor(session, cursor, worker->ogx->private_dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    cursor->query_scn = DB_CURR_SCN(session);
    return OG_SUCCESS;
}

static status_t idx_fill_multi_part_segments(knl_session_t *session, knl_cursor_t *cursor,
    mtrl_sort_ctrl_t *sort_ctrl, idx_build_worker_t *worker)
{
    knl_part_locate_t part_loc;

    for (;;) {
        part_loc = idx_get_part_loc(&worker->ogx->parl_lock, cursor->table, &worker->ogx->part_info);
        if (part_loc.part_no == OG_INVALID_ID32 && part_loc.subpart_no == OG_INVALID_ID32) {
            break;
        }

        cursor->part_loc = part_loc;
        if (knl_reopen_cursor(session, cursor, worker->ogx->private_dc) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (idx_fill_muti_segments(session, cursor, sort_ctrl, worker) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t idx_build_multi_segment(knl_session_t *session, idx_build_worker_t *build_worker)
{
    status_t status = OG_SUCCESS;
    
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    uint32 mem_size = build_worker->index_count * sizeof(mtrl_sort_ctrl_t);
    mtrl_sort_ctrl_t *sort_ctrl = (mtrl_sort_ctrl_t *)cm_push(session->stack, mem_size);
    errno_t ret = memset_sp(sort_ctrl, mem_size, 0, mem_size);
    knl_securec_check(ret);
    if (idx_init_multi_segment(session, build_worker, sort_ctrl, cursor) != OG_SUCCESS) {
        (void)idx_close_multi_segments(sort_ctrl, build_worker);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }
    if (build_worker->ogx->is_global) {
        status = idx_fill_multi_part_segments(session, cursor, sort_ctrl, build_worker);
    } else {
        // fetch + insert + sort_page phase
        cursor->scan_range = build_worker->scan_range;
        SET_ROWID_PAGE(&cursor->rowid, cursor->scan_range.l_page);
        cursor->rowid.slot = INVALID_SLOT;
        status = idx_fill_muti_segments(session, cursor, sort_ctrl, build_worker);
    }

    if (idx_close_multi_segments(sort_ctrl, build_worker) != OG_SUCCESS) {
        status = OG_ERROR;
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);

    return status;
}

static void idx_build_paral_proc(thread_t *thread)
{
    idx_build_worker_t *build_worker = (idx_build_worker_t *)thread->argument;
    idx_paral_sort_ctx_t *ogx = build_worker->ogx;
    knl_session_t *session = build_worker->session;

    while (!thread->closed) {
        if (!build_worker->is_working || build_worker->ogx->phase != BUILD_SEGMENT_PHASE) {
            cm_sleep(10);
            continue;
        }

        if (idx_build_multi_segment(session, build_worker) != OG_SUCCESS) {
            idx_set_err_msg(ogx->err_msg);
            thread->result = OG_ERROR;
            break;
        }
        break;
    }

    build_worker->is_working = OG_FALSE;
    return;
}

void idx_init_construct_ctx(idx_paral_sort_ctx_t *paral_ctx, uint32 id1, uint32 id2,
    btree_mt_context_t *ogx)
{
    errno_t err = memset_sp(ogx, sizeof(btree_mt_context_t), 0, sizeof(btree_mt_context_t));
    knl_securec_check(err);
    ogx->mtrl_ctx = *paral_ctx->workers[id1].mtrl_ctx;
    ogx->seg_id = paral_ctx->workers[id1].seg_id;
    ogx->initialized = OG_TRUE;
    ogx->is_parallel = OG_FALSE;
    ogx->nologging = paral_ctx->nologging;
    if (id2 != OG_INVALID_ID32 && paral_ctx->sort_info.count == 2) {
        // parallel construct index when index has 2 more mtrl segments
        ogx->is_parallel = OG_TRUE;
        ogx->mtrl_ctx_paral = *paral_ctx->workers[id2].mtrl_ctx;
    }
}

static status_t idx_construct_segment(idx_sort_worker_t *worker)
{
    idx_paral_sort_ctx_t *ogx = worker->ogx;

    cm_spin_lock(&ogx->parl_lock, NULL);
    if (ogx->multi_sort_info[worker->index_id].count == 0) {
        cm_spin_unlock(&ogx->parl_lock);
        return OG_SUCCESS;
    }

    uint32 id = ogx->multi_sort_info[worker->index_id].first;
    uint32 id2 = ogx->workers[id].next_id;
    cm_spin_unlock(&ogx->parl_lock);

    // construct index segment
    btree_mt_context_t btree_ctx;
    errno_t err = memset_sp(&btree_ctx, sizeof(btree_mt_context_t), 0, sizeof(btree_mt_context_t));
    knl_securec_check(err);
    btree_ctx.mtrl_ctx = *ogx->workers[id].mtrl_ctx;
    btree_ctx.seg_id = ogx->workers[id].seg_id;
    btree_ctx.initialized = OG_TRUE;
    btree_ctx.is_parallel = OG_FALSE;
    btree_ctx.nologging = ogx->nologging;

    if (id2 != OG_INVALID_ID32 && ogx->multi_sort_info[worker->index_id].count == 2) {
        // parallel construct index when index has 2 more mtrl segments
        btree_ctx.is_parallel = OG_TRUE;
        btree_ctx.mtrl_ctx_paral = *ogx->workers[id2].mtrl_ctx;
    }

    if (idx_construct(&btree_ctx) != OG_SUCCESS) {
        idx_set_err_msg(ogx->err_msg);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void idx_construct_paral_proc(thread_t *thread)
{
    idx_sort_worker_t *worker = (idx_sort_worker_t *)thread->argument;
    worker->mtrl_ctx->err_msg = g_tls_error.message;

    while (!thread->closed) {
        if (!worker->is_working || worker->phase != SORT_SEGMENT_PHASE) {
            cm_sleep(10);
            continue;
        }

        if (worker->rows > 0) {
            if (mtrl_sort_segment(worker->mtrl_ctx, worker->seg_id) != OG_SUCCESS) {
                idx_set_err_msg(worker->ogx->err_msg);
                thread->result = OG_ERROR;
                worker->is_working = OG_FALSE;
                return;
            }
        }
        worker->is_working = OG_FALSE;
        thread->result = OG_SUCCESS;
        break;
    }

    while (!thread->closed) {
        if (!worker->is_working || worker->phase != MERGE_SEGMENT_PHASE) {
            cm_sleep(100);
            continue;
        }

        thread->result = idx_merge_segments(worker);
        worker->is_working = OG_FALSE;
        if (thread->result != OG_SUCCESS) {
            idx_set_err_msg(worker->ogx->err_msg);
            worker->ogx->working_count--;
            return;
        }
        break;
    }

    while (!thread->closed) {
        if (!worker->is_working || worker->phase != CONSTRUCT_INDEX_PHASE) {
            cm_sleep(100);
            continue;
        }

        thread->result = idx_construct_segment(worker);
        worker->is_working = OG_FALSE;
        if (thread->result != OG_SUCCESS) {
            idx_set_err_msg(worker->ogx->err_msg);
            return;
        }
        break;
    }
    return;
}

static status_t idx_init_build_worker(idx_build_worker_t *worker, btree_t **btree)
{
    mtrl_segment_type_t type;
    idx_multi_info_t *idx_info = NULL;
    mtrl_context_t *mtrl_ctx = NULL;

    // pop stack before release session
    worker->idx_info = (idx_multi_info_t *)cm_push(worker->session->stack,
        worker->index_count * sizeof(idx_multi_info_t));

    for (uint32 i = 0; i < worker->index_count; i++) {
        idx_info = &worker->idx_info[i];
        idx_info->btree = btree[i];
        idx_info->ogx = worker;
        mtrl_ctx = &idx_info->mtrl_ctx;

        mtrl_ctx->session = (handle_t)worker->session;
        mtrl_init_context(mtrl_ctx, worker->session);
        mtrl_ctx->pool = worker->session->temp_pool;

        if (btree[i]->index->desc.cr_mode == CR_PAGE) {
            type = MTRL_SEGMENT_PCR_BTREE;
            mtrl_ctx->sort_cmp = pcrb_compare_mtrl_key;
        } else {
            type = MTRL_SEGMENT_RCR_BTREE;
            mtrl_ctx->sort_cmp = btree_compare_mtrl_key;
        }

        if (OG_SUCCESS != mtrl_create_segment(mtrl_ctx, type, (handle_t)btree[i], &idx_info->seg_id)) {
            return OG_ERROR;
        }

        if (OG_SUCCESS != mtrl_open_segment(mtrl_ctx, idx_info->seg_id)) {
            mtrl_release_context(mtrl_ctx);
            return OG_ERROR;
        }

        idx_info->segment = mtrl_ctx->segments[idx_info->seg_id];
    }

    return OG_SUCCESS;
}

/* alloc N build sessions, each build M mtrl_segments */
status_t idx_build_alloc_resource(knl_session_t *session, idx_paral_sort_ctx_t *sort_ctx)
{
    idx_build_worker_t *worker = NULL;

    for (uint32 i = 0; i < sort_ctx->build_count; i++) {
        worker = &sort_ctx->build_workers[i];
        worker->index_count = sort_ctx->index_count;
        if (g_knl_callback.alloc_knl_session(OG_FALSE, (knl_handle_t*)&worker->session) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_EXCEED_SESSIONS_PER_USER, session->kernel->attr.max_sessions);
            return OG_ERROR;
        }

        worker->session->temp_pool = &worker->session->kernel->temp_pool[worker->pool_id];
        worker->session->temp_mtrl->pool = worker->session->temp_pool;
        worker->ogx = sort_ctx;
        if (idx_init_build_worker(worker, sort_ctx->btree) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (cm_create_thread(idx_build_paral_proc, 0, worker, &worker->thread) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static void idx_init_construct_workers(idx_paral_sort_ctx_t *sort_ctx, idx_sort_worker_t *worker,
    uint32 index_id, uint32 paral_no)
{
    worker->index_id = index_id;
    worker->ogx = sort_ctx;
    worker->pool_id = sort_ctx->build_workers[paral_no].pool_id;
    worker->mtrl_ctx = &sort_ctx->build_workers[paral_no].idx_info[index_id].mtrl_ctx;
    worker->seg_id = sort_ctx->build_workers[paral_no].idx_info[index_id].seg_id;
    worker->segment = worker->mtrl_ctx->segments[worker->seg_id];
    worker->session->temp_pool = &worker->session->kernel->temp_pool[worker->pool_id];
    worker->session->temp_mtrl->pool = worker->session->temp_pool;
    worker->mtrl_ctx->session = worker->session;
    worker->mtrl_ctx->pool = worker->session->temp_pool;
    worker->rows = sort_ctx->build_workers[paral_no].rows;
}

/* alloc N * M construct sessions, each merge N mtrl_segments */
status_t idx_construct_alloc_resource(knl_session_t *session, idx_paral_sort_ctx_t *sort_ctx)
{
    idx_sort_worker_t *worker = NULL;
    uint32 thread_id = 0;

    sort_ctx->paral_count = sort_ctx->index_count * sort_ctx->build_count;
    sort_ctx->workers = (idx_sort_worker_t*)cm_push(session->stack, sizeof(idx_sort_worker_t) * sort_ctx->paral_count);
    errno_t err = memset_sp(sort_ctx->workers, sizeof(idx_sort_worker_t) * sort_ctx->paral_count,
        0, sizeof(idx_sort_worker_t) * sort_ctx->paral_count);
    knl_securec_check(err);
    for (uint32 i = 0; i < sort_ctx->index_count; i++) {
        for (uint32 j = 0; j < sort_ctx->build_count; j++) {
            worker = &sort_ctx->workers[thread_id];
            worker->id = thread_id;
            if (g_knl_callback.alloc_knl_session(OG_FALSE, (knl_handle_t*)&worker->session) != OG_SUCCESS) {
                OG_THROW_ERROR(ERR_EXCEED_SESSIONS_PER_USER, session->kernel->attr.max_sessions);
                return OG_ERROR;
            }

            idx_init_construct_workers(sort_ctx, worker, i, j);

            if (cm_create_thread(idx_construct_paral_proc, 0, worker, &worker->thread) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (sort_ctx->multi_sort_info[i].count == 0) {
                sort_ctx->multi_sort_info[i].first = thread_id;
                sort_ctx->multi_sort_info[i].last = thread_id;
                sort_ctx->multi_sort_info[i].count++;
            } else {
                sort_ctx->multi_sort_info[i].last = thread_id;
                sort_ctx->multi_sort_info[i].count++;
                sort_ctx->workers[thread_id - 1].next_id = thread_id;
            }
            thread_id = thread_id + 1;
        }
        sort_ctx->workers[thread_id].next_id = OG_INVALID_ID8;
    }

    return OG_SUCCESS;
}

void idx_close_build_thread(idx_paral_sort_ctx_t *sort_ctx)
{
    idx_build_worker_t *worker = NULL;

    for (uint32 i = 0; i < sort_ctx->build_count; i++) {
        worker = &sort_ctx->build_workers[i];
        worker->is_working = OG_FALSE;

        if (!worker->thread.closed) {
            cm_close_thread(&worker->thread);
        }
    }
}

static void idx_release_build_mtrl(idx_paral_sort_ctx_t *sort_ctx, idx_build_worker_t *worker)
{
    for (uint32 i = 0; i < sort_ctx->index_count; i++) {
        mtrl_release_context(&worker->idx_info[i].mtrl_ctx);
    }
}

void idx_build_release_resource(idx_paral_sort_ctx_t *sort_ctx, bool32 is_free)
{
    idx_build_worker_t *worker = NULL;

    for (uint32 i = 0; i < sort_ctx->build_count; i++) {
        worker = &sort_ctx->build_workers[i];
        worker->is_working = OG_FALSE;
        if (worker->session != NULL) {
            worker->session->canceled = OG_TRUE;
        }

        if (!worker->thread.closed) {
            cm_close_thread(&worker->thread);
        }
    }

    for (uint32 i = 0; i < sort_ctx->build_count; i++) {
        worker = &sort_ctx->build_workers[i];
        if (is_free) {
            idx_release_build_mtrl(sort_ctx, worker);
        }

        if (worker->session != NULL) {
            cm_pop(worker->session->stack);
            g_knl_callback.release_knl_session((knl_handle_t *)worker->session);
        }
    }
    return;
}

void idx_construct_release_resource(idx_paral_sort_ctx_t *sort_ctx)
{
    idx_sort_worker_t *worker = NULL;

    for (uint32 i = 0; i < sort_ctx->paral_count; i++) {
        worker = &sort_ctx->workers[i];
        worker->is_working = OG_FALSE;
        if (worker->session != NULL) {
            worker->session->canceled = OG_TRUE;
        }

        if (!worker->thread.closed) {
            cm_close_thread(&worker->thread);
        }
    }

    for (uint32 i = 0; i < sort_ctx->paral_count; i++) {
        worker = &sort_ctx->workers[i];
        mtrl_release_context(worker->mtrl_ctx);

        if (worker->session != NULL) {
            cm_pop(worker->session->stack);
            g_knl_callback.release_knl_session((knl_handle_t *)worker->session);
        }
    }
    return;
}

static void idx_start_group_workers(idx_paral_sort_ctx_t *ogx, uint8 index_id, idx_sort_phase_t phase)
{
    uint8 build_count;

    build_count = ogx->paral_count / ogx->index_count;

    for (uint32 i = (uint32)index_id * build_count; i < index_id * build_count + build_count; i++) {
        ogx->workers[i].is_working = OG_TRUE;
        ogx->workers[i].phase = phase;
        if (phase == CONSTRUCT_INDEX_PHASE) {
            break;
        }
    }
    ogx->working_count = ogx->paral_count;
}

static status_t idx_check_workers_status(idx_paral_sort_ctx_t *paral_ctx, uint8 index_id,
    uint8 build_count, idx_sort_phase_t phase1, uint8 *count)
{
    idx_sort_worker_t *worker = NULL;

    for (uint8 id = index_id * build_count; id < index_id * build_count + build_count; id++) {
        worker = &paral_ctx->workers[id];
        if (worker->phase != phase1) {
            break;
        }

        if (!worker->is_working) {
            (*count)--;
        }

        if (worker->thread.result != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, paral_ctx->err_msg);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t idx_switch_create_phase(knl_session_t *session, idx_paral_sort_ctx_t *paral_ctx,
    idx_sort_phase_t phase1, idx_sort_phase_t phase2)
{
    uint8 count;
    uint8 build_count;
    uint8 index_count;

    build_count = paral_ctx->paral_count / paral_ctx->index_count;
    index_count = paral_ctx->index_count;
    do {
        for (uint8 i = 0; i < paral_ctx->index_count; i++) {
            count = build_count;
            if (idx_check_workers_status(paral_ctx, i, build_count, phase1, &count) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (knl_check_session_status(session) != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (count == 0) {
                idx_start_group_workers(paral_ctx, i, phase2);
                index_count--;
            }
            cm_sleep(100);
        }
    } while (index_count != 0);

    return OG_SUCCESS;
}

static void idx_rebuild_list_add_worker(uint64 *list, uint32 index)
{
    *list |= (0x1LL << index);
}

static bool32 idx_rebuild_is_active_rebuild_worker(uint64 idle_list, uint32 index)
{
    return !(idle_list & (0x1LL << index));
}

static bool32 idx_acquire_idle_rebuild_worker(idx_paral_rebuild_ctx_t *ogx, uint32 *work_index)
{
    idx_paral_rebuild_worker_t *worker = NULL;
    *work_index = 0;

    for (uint32 i = 0; i < ogx->paral_cnt; i++) {
        worker = &ogx->workers[i];
        cm_spin_lock(&worker->parl_lock, NULL);

        if (worker->is_working) {
            cm_spin_unlock(&worker->parl_lock);
            continue;
        }

        *work_index = i;
        cm_spin_unlock(&worker->parl_lock);
        return OG_TRUE;
    }

    return OG_FALSE;
}

static void idx_active_rebuild_worker(idx_paral_rebuild_ctx_t *ogx, uint32 worker_index,
    knl_part_locate_t part_loc, uint32 split_cnt)
{
    idx_paral_rebuild_worker_t *worker = &ogx->workers[worker_index];

    cm_spin_lock(&worker->parl_lock, NULL);
    worker->part_loc = part_loc;
    worker->current_range_index = 0;
    worker->splited_cnt = split_cnt;

    worker->is_working = OG_TRUE;
    cm_spin_unlock(&worker->parl_lock);

    OG_LOG_DEBUG_INF("worker:%u, part start:%u", worker_index, part_loc.part_no);
}

static bool32 idx_split_overload_rebuild_worker(idx_paral_rebuild_ctx_t *ogx, uint32 overload_worker_index,
    uint32 idle_worker_index)
{
    int32 current_range_index;
    idx_paral_rebuild_worker_t *overload_worker = &ogx->workers[overload_worker_index];
    cm_spin_lock(&overload_worker->parl_lock, NULL);

    current_range_index = overload_worker->current_range_index;

    if (current_range_index < 1) { // overload_worker have one scan range, no need others help rebuild.
        cm_spin_unlock(&overload_worker->parl_lock);
        return OG_FALSE;
    }

    overload_worker->current_range_index--;

    idx_paral_rebuild_worker_t *idle_worker = &ogx->workers[idle_worker_index];
    errno_t ret = memcpy_sp(&idle_worker->range, sizeof(knl_scan_range_t),
        overload_worker->split_range[current_range_index], sizeof(knl_scan_range_t));
    knl_securec_check(ret);

    idle_worker->split_range[0] = &idle_worker->range; // help worker have only one scan range
    knl_part_locate_t part_loc = overload_worker->part_loc;

    idx_active_rebuild_worker(ogx, idle_worker_index, part_loc, 0);
    cm_spin_unlock(&overload_worker->parl_lock);

    OG_LOG_DEBUG_INF("active worker:%u, over worker:%u, part start:%u, last_range:%u", idle_worker_index,
        overload_worker_index, part_loc.part_no, current_range_index);

    return OG_TRUE;
}

index_t* idx_get_index_by_shadow(knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    shadow_index_t *shadow_index = entity->table.shadow_index;
    index_t *index = SHADOW_INDEX_ENTITY(shadow_index);
    text_t index_name;

    cm_str2text(index->desc.name, &index_name);
    return dc_find_index_by_name(DC_ENTITY(dc), &index_name);
}

static int64 idx_table_sub_part_traversal(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t *current_part_loc, table_part_t *table_part, knl_parts_locate_t parts_loc)
{
    uint32 last_part;
    int64 pages;
    part_segment_desc_t part_segment_desc;
    part_segment_desc.type = SEG_PAGES;

    last_part = table_part->desc.subpart_cnt;
    if (current_part_loc->subpart_no >= last_part) {
        current_part_loc->part_no++;
        current_part_loc->subpart_no = 0;
        return 0;
    }

    if (!is_idx_part_existed(current_part_loc, parts_loc, OG_TRUE)) {
        current_part_loc->subpart_no++;
        return 0;
    }

    part_segment_desc.part_start = current_part_loc->subpart_no;
    part_segment_desc.part_end = current_part_loc->subpart_no + 1;
    pages = part_get_heap_subsegment_size(session, dc, table_part, part_segment_desc);
    if (pages == 0) {
        current_part_loc->subpart_no++;
    }

    return pages;
}

static status_t idx_table_part_traversal(knl_session_t *session, knl_dictionary_t *dc,
    knl_part_locate_t *current_part_loc, bool32 *finish_stat, knl_parts_locate_t parts_loc)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;
    part_table_t *part_table = table->part_table;
    int64 pages;
    uint32 last_part;

    for (;;) {
        if (knl_check_session_status(session) != OG_SUCCESS) {
            return OG_ERROR;
        }

        last_part = part_table->desc.partcnt;
        if (current_part_loc->part_no >= last_part) {
            *finish_stat = OG_TRUE;
            break;
        }

        table_part = TABLE_GET_PART(table, current_part_loc->part_no);
        if (!IS_READY_PART(table_part) ||
            !is_idx_part_existed(current_part_loc, parts_loc, OG_FALSE)) {
            current_part_loc->part_no++;
            continue;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            pages = idx_table_sub_part_traversal(session, dc, current_part_loc, table_part, parts_loc);
            if (pages == 0) {
                continue;
            } else if (pages < 0) {
                return OG_ERROR;
            }
            break;
        }

        current_part_loc->subpart_no = OG_INVALID_ID32;
        if (part_get_heap_segment_size(session, dc, table_part, SEG_PAGES, &pages) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (pages == 0) {
            current_part_loc->part_no++;
            continue;
        }
        break;
    }

    return OG_SUCCESS;
}

static status_t idx_check_worker_status(idx_paral_rebuild_ctx_t *ogx)
{
    uint32 max_paral_worker = ogx->paral_cnt;
    idx_paral_rebuild_worker_t *worker = NULL;

    for (uint32 worker_index = 0; worker_index < max_paral_worker; worker_index++) {
        worker = &ogx->workers[worker_index];

        if (worker->thread.result != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, ogx->err_msg);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t idx_start_rebuild_workers(knl_session_t *session, idx_paral_rebuild_ctx_t *ogx, knl_parts_locate_t parts_loc)
{
    status_t ret;
    knl_dictionary_t *dc = ogx->dc;
    bool32 finish_stat = OG_FALSE;
    uint32 split_cnt = (parts_loc.specified_parts == 0) ? MAX_SPLIT_RANGE_CNT : 1;

    if (ogx->current_part.part_no == OG_INVALID_ID32) {
        ogx->current_part.part_no = 0;
    }

    if (ogx->current_part.subpart_no == OG_INVALID_ID32) {
        ogx->current_part.subpart_no = 0;
    }

    for (;;) {
        ret = idx_table_part_traversal(session, dc, &ogx->current_part, &finish_stat, parts_loc);
        if (ret != OG_SUCCESS || finish_stat) {
            break;
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            ret = OG_ERROR;
            break;
        }

        if (idx_check_worker_status(ogx) != OG_SUCCESS) {
            ret = OG_ERROR;
            break;
        }

        if (!idx_start_rebuild_worker(session, ogx, split_cnt)) {
            cm_sleep(REBUILD_WAIT_MSEC);
            continue;
        }

        if (ogx->current_part.subpart_no != OG_INVALID_ID32) {
            ogx->current_part.subpart_no++;
        } else {
            ogx->current_part.part_no++;
        }
    }

    return ret;
}

bool32 idx_start_rebuild_worker(knl_session_t *session, idx_paral_rebuild_ctx_t *ogx, uint32 split_cnt)
{
    uint32 worker_index = 0;
    knl_part_locate_t part_loc = ogx->current_part;

    if (!idx_acquire_idle_rebuild_worker(ogx, &worker_index)) {
        return OG_FALSE;
    }

    idx_active_rebuild_worker(ogx, worker_index, part_loc, split_cnt);
    return OG_TRUE;
}

static status_t idx_init_worker_pool(knl_session_t *session, idx_paral_rebuild_ctx_t *ogx, uint32 range_count)
{
    for (uint32 i = 0; i < range_count; i++) {
        idx_paral_rebuild_worker_t *worker = ogx->workers + i;
        if (g_knl_callback.alloc_knl_session(OG_FALSE, (knl_handle_t *)&worker->session) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_EXCEED_SESSIONS_PER_USER, session->kernel->attr.max_sessions);
            return OG_ERROR;
        }

        worker->id = i;
        worker->ogx = ogx;

        if (cm_create_thread(idx_rebuild_index_proc, 0, worker, &worker->thread) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t idx_alloc_parallel_rebuild_rsc(knl_session_t *session, knl_dictionary_t *dc, uint32 paral_count,
    idx_paral_rebuild_ctx_t **ogx)
{
    errno_t err;

    *ogx = (idx_paral_rebuild_ctx_t *)cm_push(session->stack, sizeof(idx_paral_rebuild_ctx_t));
    err = memset_sp(*ogx, sizeof(idx_paral_rebuild_ctx_t), 0, sizeof(idx_paral_rebuild_ctx_t));
    knl_securec_check(err);

    (*ogx)->dc = dc;
    (*ogx)->current_part.part_no = 0;
    (*ogx)->current_part.subpart_no = 0;
    (*ogx)->paral_cnt = paral_count;

    return idx_init_worker_pool(session, *ogx, paral_count);
}
/*
 * optimize overload worker if this worker scan range more than one
 */
static bool32 idx_optimize_rebuild_workers(idx_paral_rebuild_ctx_t *ogx, uint32 overload_worker_index,
    uint64 idle_worker_list)
{
    for (uint32 i = 0; i < ogx->paral_cnt; i++) {
        if (idx_rebuild_is_active_rebuild_worker(idle_worker_list, i)) {
            continue;
        }

        return idx_split_overload_rebuild_worker(ogx, overload_worker_index, i);
    }

    return OG_FALSE;
}

bool32 idx_is_multi_segments(idx_paral_rebuild_ctx_t *ogx, knl_parts_locate_t parts_loc,
    rebuild_index_def_t *rebuild_def)
{
    knl_dictionary_t *dc = ogx->dc;
    table_part_t *table_part = NULL;
    table_t* table = DC_TABLE(dc);
    
    if (rebuild_def->specified_parts) {
        return OG_TRUE;
    }

    if (parts_loc.part[0].part_no != OG_INVALID_ID32) {
        table_part = TABLE_GET_PART(table, parts_loc.part[0].part_no);
        if (IS_PARENT_TABPART(&table_part->desc)) {
            return parts_loc.part[0].subpart_no == OG_INVALID_ID32;
        }
        return OG_FALSE;
    }

    return IS_PART_TABLE(table);
}

status_t idx_wait_rebuild_workers(knl_session_t *session, idx_paral_rebuild_ctx_t *ogx)
{
    uint32 max_paral_worker = ogx->paral_cnt;
    uint32 over_load_worker_index = 0;
    idx_paral_rebuild_worker_t *overload_worker = NULL;
    idx_paral_rebuild_worker_t *worker = NULL;

    for (;;) {
        uint64 idle_worker_list = 0;
        uint32 idle_worker_cnt = 0;

        cm_sleep(REBUILD_WAIT_MSEC);

        if (idx_check_worker_status(ogx) != OG_SUCCESS) {
            return OG_ERROR;
        }

        for (uint32 worker_index = 0; worker_index < max_paral_worker; worker_index++) {
            worker = &ogx->workers[worker_index];

            if (!worker->is_working) {
                idx_rebuild_list_add_worker(&idle_worker_list, worker_index);
                idle_worker_cnt++;
            }

            overload_worker = &ogx->workers[over_load_worker_index];
            if (worker->current_range_index > overload_worker->current_range_index) {
                over_load_worker_index = worker_index;
            }
        }

        if (knl_check_session_status(session) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (idx_optimize_rebuild_workers(ogx, over_load_worker_index, idle_worker_list)) {
            continue;
        }

        if (idle_worker_cnt >= ogx->paral_cnt) {
            break;
        }
    }

    return OG_SUCCESS;
}

void idx_release_parallel_rebuild_rsc(knl_session_t *session, idx_paral_rebuild_ctx_t *ogx, uint32 workers)
{
    uint32 worker_index;
    idx_paral_rebuild_worker_t *worker = NULL;

    for (worker_index = 0; worker_index < workers; worker_index++) {
        worker = &ogx->workers[worker_index];
        worker->is_working = OG_FALSE;
        if (worker->session != NULL) {
            worker->session->canceled = OG_TRUE;
        }
        cm_close_thread(&worker->thread);

        if (worker->session != NULL) {
            g_knl_callback.release_knl_session((knl_handle_t *)worker->session);
        }
    }
}

static status_t idx_split_table_segment_range(idx_paral_rebuild_worker_t *worker,
    knl_scan_range_t *split_range[], uint32 *range_cnt)
{
    idx_paral_rebuild_ctx_t *ogx = worker->ogx;
    knl_session_t *session = worker->session;
    knl_dictionary_t *dc = ogx->dc;

    knl_paral_range_t paral_range;
    paral_range.workers = *range_cnt;

    if (knl_get_paral_schedule(session, dc, worker->part_loc, paral_range.workers, &paral_range) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < paral_range.workers; i++) {
        split_range[i]->l_page = paral_range.l_page[i];
        split_range[i]->r_page = paral_range.r_page[i];
    }

    *range_cnt = paral_range.workers;
    return OG_SUCCESS;
}

static bool32 idx_split_worker_range(idx_paral_rebuild_worker_t *worker, uint32 split_cnt)
{
    knl_session_t *session = worker->session;
    knl_scan_range_t *range[MAX_SPLIT_RANGE_CNT] = {0};
    uint32 range_index = 0;
    uint32 range_cnt = 0;

    for (; range_index < split_cnt; range_index++) {
        range[range_index] = (knl_scan_range_t *)cm_push(session->stack, sizeof(knl_scan_range_t));

        if (range[range_index]) {
            range_cnt++;
            errno_t err = memset_sp(range[range_index], sizeof(knl_scan_range_t),
                0, sizeof(knl_scan_range_t));
            knl_securec_check(err);
            continue;
        }

        break;
    }

    status_t status;
    if (range_cnt == 0) {
        range_cnt = 1;
        range[0] = &worker->range;
    }

    status = idx_split_table_segment_range(worker, range, &range_cnt);
    if (status == OG_SUCCESS) {
        cm_spin_lock(&worker->parl_lock, NULL);
        for (uint32 i = 0; i < range_cnt; i++) {
            worker->split_range[i] = range[i];
        }
        worker->current_range_index = range_cnt - 1;
        cm_spin_unlock(&worker->parl_lock);
    }

    return status == OG_SUCCESS;
}

static status_t idx_open_cursor(idx_paral_rebuild_worker_t *worker, knl_cursor_t *cursor, int32 range_index,
    bool32 reopen)
{
    idx_paral_rebuild_ctx_t *ogx = worker->ogx;
    knl_dictionary_t *dc = ogx->dc;
    knl_session_t *session = worker->session;
    index_t *old_index = idx_get_index_by_shadow(dc);
    knl_scan_range_t *range = worker->split_range[range_index];
    status_t ret;

    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->index_slot = old_index->desc.slot;
    cursor->index_only = OG_FALSE;
    cursor->part_loc = worker->part_loc;
    cursor->index_paral = OG_TRUE;
    cursor->index_dsc = OG_FALSE;

    if (cursor->part_loc.part_no == OG_INVALID_ID32) {
        cursor->part_loc.part_no = 0;
    }

    if (cursor->part_loc.subpart_no == OG_INVALID_ID32) {
        cursor->part_loc.subpart_no = 0;
    }

    for (;;) {
        if (reopen) {
            ret = knl_reopen_cursor(session, cursor, dc);
        } else {
            ret = knl_open_cursor(session, cursor, dc);
        }

        if (ret != OG_SUCCESS) {
            break;
        }

        knl_init_table_scan(session, cursor);
        knl_set_table_scan_range(session, cursor, range->l_page, range->r_page);

        OG_LOG_DEBUG_INF("lfile = %u, page= %u, vmid = %u", range->l_page.file, range->l_page.page,
            range->l_page.vmid);
        OG_LOG_DEBUG_INF("rfile = %u, page= %u, vmid = %u", range->r_page.file, range->r_page.page,
            range->r_page.vmid);

        break;
    }

    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    return ret;
}

static status_t idx_rebuild_index_range_proc_entity(idx_paral_rebuild_worker_t *worker,
    knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    knl_session_t *session = worker->session;
    int32 current_range_index;
    bool32 reopen = OG_FALSE;

    for (;;) {
        cm_spin_lock(&worker->parl_lock, NULL);
        if (worker->current_range_index < 0) {
            cm_spin_unlock(&worker->parl_lock);
            break;
        }

        current_range_index = worker->current_range_index;
        worker->current_range_index--;
        cm_spin_unlock(&worker->parl_lock);

        OG_LOG_DEBUG_INF("worker:%u,process part:%u-%u start,current_range_index:%d", worker->id,
            worker->part_loc.part_no, worker->part_loc.subpart_no, current_range_index);

        if (idx_open_cursor(worker, cursor, current_range_index, reopen) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (db_fill_shadow_index_parallel(session, cursor, dc, worker->part_loc, REBUILD_INDEX_PARALLEL) !=
            OG_SUCCESS) {
            return OG_ERROR;
        }
        reopen = OG_TRUE;
        OG_LOG_DEBUG_INF("worker:%u,process end:%u-%d, cnt:%d", worker->id, worker->part_loc.part_no,
            worker->part_loc.subpart_no, current_range_index);
    }

    return OG_SUCCESS;
}

void idx_rebuild_index_proc(thread_t *thread)
{
    cm_set_thread_name("idx_rebuilder.");

    idx_paral_rebuild_worker_t *worker = (idx_paral_rebuild_worker_t *)thread->argument;
    idx_paral_rebuild_ctx_t *ogx = worker->ogx;
    knl_session_t *session = worker->session;
    knl_dictionary_t *dc = ogx->dc;
    knl_cursor_t *cursor = NULL;
    uint32 splited_cnt;
    bool32 splited_result = OG_TRUE;

    for (;;) {
        cm_spin_lock(&worker->parl_lock, NULL);

        if (thread->closed) {
            worker->is_working = OG_FALSE;
            cm_spin_unlock(&worker->parl_lock);
            break;
        }

        if (!worker->is_working) {
            cm_spin_unlock(&worker->parl_lock);
            cm_spin_sleep();
            continue;
        }
        splited_cnt = worker->splited_cnt;
        cm_spin_unlock(&worker->parl_lock);

        CM_SAVE_STACK(session->stack);
        if (splited_cnt == 1) {
            index_t *index = &DC_TABLE(dc)->shadow_index->index;
            thread->result = db_fill_index_entity_paral(session, dc, index, worker->part_loc, worker->ogx->paral_cnt,
                OG_FALSE);
        } else {
            if (splited_cnt > 0 && splited_cnt <= MAX_SPLIT_RANGE_CNT) {
                splited_result = idx_split_worker_range(worker, splited_cnt);
            }

            cursor = knl_push_cursor(session);
            if (!splited_result || idx_rebuild_index_range_proc_entity(worker, cursor, dc) != OG_SUCCESS) {
                thread->result = OG_ERROR;
            }

            knl_close_cursor(session, cursor);
        }
        CM_RESTORE_STACK(session->stack);
        cm_spin_lock(&worker->parl_lock, NULL);
        worker->is_working = OG_FALSE;

        if (thread->result != OG_SUCCESS) {
            cm_spin_unlock(&worker->parl_lock);
            idx_set_err_msg(ogx->err_msg);
            continue;
        }

        thread->result = OG_SUCCESS;
        cm_spin_unlock(&worker->parl_lock);
    }
}

