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
 * dml_executor.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/dml_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml_executor.h"
#include "srv_instance.h"
#include "cm_file.h"
#include "ogsql_aggr.h"
#include "ogsql_group.h"
#include "ogsql_sort_group.h"
#include "ogsql_index_group.h"
#include "ogsql_sort.h"
#include "ogsql_distinct.h"
#include "ogsql_union.h"
#include "ogsql_select.h"
#include "ogsql_update.h"
#include "ogsql_insert.h"
#include "ogsql_delete.h"
#include "ogsql_limit.h"
#include "ogsql_merge.h"
#include "ogsql_replace.h"
#include "ogsql_mtrl.h"
#include "ogsql_minus.h"
#include "ogsql_winsort.h"
#include "ogsql_group_cube.h"
#include "ogsql_withas_mtrl.h"
#include "ogsql_proj.h"
#include "ogsql_concate.h"
#include "dml_parser.h"

#ifdef __cplusplus

extern "C" {
#endif

static void sql_reset_connect_data(sql_cursor_t *ogsql_cursor)
{
    ogsql_cursor->connect_data.next_level_cursor = NULL;
    ogsql_cursor->connect_data.last_level_cursor = NULL;
    ogsql_cursor->connect_data.first_level_cursor = NULL;
    ogsql_cursor->connect_data.cur_level_cursor = NULL;
    ogsql_cursor->connect_data.connect_by_isleaf = OG_FALSE;
    ogsql_cursor->connect_data.connect_by_iscycle = OG_FALSE;
    ogsql_cursor->connect_data.level = 0;
    ogsql_cursor->connect_data.first_level_rownum = 0;
    ogsql_cursor->connect_data.path_func_nodes = NULL;
    ogsql_cursor->connect_data.prior_exprs = NULL;
    ogsql_cursor->connect_data.path_stack = NULL;
}

static inline void sql_init_sql_cursor_mtrl(sql_mtrl_handler_t *ogsql_mtrl)
{
    ogsql_mtrl->cursor.sort.vmid = OG_INVALID_ID32;
    ogsql_mtrl->cursor.hash_group.aggrs = NULL;
    ogsql_mtrl->cursor.distinct.eof = OG_FALSE;
    ogsql_mtrl->cursor.distinct.row.lens = NULL;
    ogsql_mtrl->cursor.distinct.row.offsets = NULL;
    ogsql_mtrl->cursor.rs_vmid = OG_INVALID_ID32;
    ogsql_mtrl->cursor.rs_page = NULL;
    ogsql_mtrl->cursor.eof = OG_FALSE;
    ogsql_mtrl->cursor.slot = 0;
    ogsql_mtrl->cursor.count = 0;
    ogsql_mtrl->cursor.type = MTRL_CURSOR_OTHERS;
    mtrl_init_mtrl_rowid(&ogsql_mtrl->cursor.pre_cursor_rid);
    mtrl_init_mtrl_rowid(&ogsql_mtrl->cursor.next_cursor_rid);
    mtrl_init_mtrl_rowid(&ogsql_mtrl->cursor.curr_cursor_rid);
    ogsql_mtrl->rs.sid = OG_INVALID_ID32;
    ogsql_mtrl->rs.buf = NULL;
    ogsql_mtrl->predicate.sid = OG_INVALID_ID32;
    ogsql_mtrl->predicate.buf = NULL;
    ogsql_mtrl->query_block.sid = OG_INVALID_ID32;
    ogsql_mtrl->query_block.buf = NULL;
    ogsql_mtrl->outline.sid = OG_INVALID_ID32;
    ogsql_mtrl->outline.buf = NULL;
    ogsql_mtrl->sort.sid = OG_INVALID_ID32;
    ogsql_mtrl->sort.buf = NULL;
    ogsql_mtrl->sibl_sort.sid = OG_INVALID_ID32;
    ogsql_mtrl->sibl_sort.cursor_sid = OG_INVALID_ID32;
    ogsql_mtrl->aggr = OG_INVALID_ID32;
    ogsql_mtrl->aggr_str = OG_INVALID_ID32;
    ogsql_mtrl->sort_seg = OG_INVALID_ID32;
    ogsql_mtrl->group.sid = OG_INVALID_ID32;
    ogsql_mtrl->group.buf = NULL;
    ogsql_mtrl->group_index = OG_INVALID_ID32;
    ogsql_mtrl->distinct = OG_INVALID_ID32;
    ogsql_mtrl->index_distinct = OG_INVALID_ID32;
    ogsql_mtrl->aggr_fetched = OG_FALSE;
    ogsql_mtrl->winsort_rs.sid = OG_INVALID_ID32;
    ogsql_mtrl->winsort_aggr.sid = OG_INVALID_ID32;
    ogsql_mtrl->winsort_aggr_ext.sid = OG_INVALID_ID32;
    ogsql_mtrl->winsort_sort.sid = OG_INVALID_ID32;
    ogsql_mtrl->winsort_rs.buf = NULL;
    ogsql_mtrl->winsort_aggr.buf = NULL;
    ogsql_mtrl->winsort_aggr_ext.buf = NULL;
    ogsql_mtrl->winsort_sort.buf = NULL;
    ogsql_mtrl->hash_table_rs = OG_INVALID_ID32;
    ogsql_mtrl->for_update = OG_INVALID_ID32;
    ogsql_mtrl->save_point.vm_row_id.vmid = OG_INVALID_ID32;
}

static inline void sql_init_cur_exec_data(plan_exec_data_t *executor_data)
{
    executor_data->query_limit = NULL;
    executor_data->select_limit = NULL;
    executor_data->union_all = NULL;
    executor_data->minus.r_continue_fetch = OG_TRUE;
    executor_data->minus.rs_vmid = OG_INVALID_ID32;
    executor_data->minus.rnums = 0;
    executor_data->explain_col_max_size = NULL;
    executor_data->qb_col_max_size = NULL;
    executor_data->outer_join = NULL;
    executor_data->inner_join = NULL;
    executor_data->join = NULL;
    executor_data->aggr_dis = NULL;
    executor_data->select_view = NULL;
    executor_data->tab_parallel = NULL;
    executor_data->group = NULL;
    executor_data->group_cube = NULL;
    executor_data->nl_batch = NULL;
    executor_data->ext_knl_cur = NULL;
    executor_data->right_semi = NULL;
    executor_data->index_scan_range_ar = NULL;
    executor_data->part_scan_range_ar = NULL;
    executor_data->dv_plan_buf = NULL;
    CM_INIT_TEXTBUF(&executor_data->sort_concat, 0, NULL);
}

static inline void sql_init_cursor_hash_info(sql_cursor_t *ogsql_cursor)
{
    ogsql_cursor->merge_into_hash.already_update = OG_FALSE;
    ogsql_cursor->hash_seg.sess = NULL;
    ogsql_cursor->hash_table_entry.vmid = OG_INVALID_ID32;
    ogsql_cursor->hash_table_entry.offset = OG_INVALID_ID32;

    ogsql_cursor->hash_join_ctx = NULL;
    ogsql_cursor->hash_table_status = HASH_TABLE_STATUS_NOINIT;

    for (uint32 i = 0; i < OG_MAX_JOIN_TABLES; i++) {
        ogsql_cursor->hash_mtrl.hj_tables[i] = NULL;
    }
}

void sql_init_sql_cursor(sql_stmt_t *stmt, sql_cursor_t *ogsql_cursor)
{
    ogsql_cursor->stmt = stmt;
    ogsql_cursor->plan = NULL;
    ogsql_cursor->select_ctx = NULL;
    ogsql_cursor->cond = NULL;
    ogsql_cursor->query = NULL;
    ogsql_cursor->columns = NULL;
    ogsql_cursor->aggr_page = NULL;
    ogsql_cursor->eof = OG_FALSE;
    ogsql_cursor->total_rows = 0;
    ogsql_cursor->rownum = 0;
    ogsql_cursor->max_rownum = OG_INVALID_ID32;
    ogsql_cursor->last_table = 0;
    ogsql_cursor->table_count = 0;
    ogsql_cursor->tables = NULL;
    ogsql_cursor->scn = OG_INVALID_ID64;
    ogsql_cursor->is_mtrl_cursor = OG_FALSE;
    biqueue_init(&ogsql_cursor->ssa_cursors);

    // init mtrl exec data
    sql_init_sql_cursor_mtrl(&ogsql_cursor->mtrl);

    // init exec data of plan
    vmc_init(&stmt->session->vmp, &ogsql_cursor->vmc);
    sql_init_cur_exec_data(&ogsql_cursor->exec_data);

    // init connect by exec data
    sql_reset_connect_data(ogsql_cursor);

    // init hash clause exec data
    sql_init_cursor_hash_info(ogsql_cursor);

    ogsql_cursor->group_ctx = NULL;
    ogsql_cursor->cnct_ctx = NULL;
    ogsql_cursor->unpivot_ctx = NULL;
    ogsql_cursor->hash_mtrl_ctx = NULL;
    ogsql_cursor->distinct_ctx = NULL;
    ogsql_cursor->cb_mtrl_ctx = NULL;
    ogsql_cursor->m_join = NULL;

    ogsql_cursor->is_open = OG_FALSE;
    ogsql_cursor->is_result_cached = OG_FALSE;
    ogsql_cursor->exists_result = OG_FALSE;
    ogsql_cursor->left_cursor = NULL;
    ogsql_cursor->right_cursor = NULL;
    ogsql_cursor->ancestor_ref = NULL;
    ogsql_cursor->winsort_ready = OG_FALSE;
    ogsql_cursor->global_cached = OG_FALSE;
    ogsql_cursor->idx_func_cache = NULL;
    ogsql_cursor->is_group_insert = OG_FALSE;
}

static bool32 sql_try_extend_global_cursor(object_t **object)
{
    char *buffer = NULL;
    uint32 sql_cur_size = CM_ALIGN8(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
    uint32 ext_cnt;
    uint32 ext_buf_size;
    uint32 max_sql_cursors = g_instance->attr.reserved_sql_cursors +
        (g_instance->attr.sql_cursors_each_sess * g_instance->session_pool.max_sessions);
    object_pool_t extend_pool;
    errno_t rc_memzero;

    if (g_instance->sql_cur_pool.cnt >= max_sql_cursors) {
        return OG_FALSE;
    }

    cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
    if (g_instance->sql_cur_pool.cnt < max_sql_cursors) {
        ext_cnt = MIN(max_sql_cursors - g_instance->sql_cur_pool.cnt, EXTEND_SQL_CURS_EACH_TIME);
        ext_buf_size = ext_cnt * sql_cur_size;
        if (ext_buf_size == 0 || ext_buf_size / sql_cur_size != ext_cnt) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return OG_FALSE;
        }
        buffer = (char *)malloc(ext_buf_size);
        if (buffer == NULL) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return OG_FALSE;
        }
        rc_memzero = memset_s(buffer, ext_buf_size, 0, ext_buf_size);
        if (rc_memzero != EOK) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            CM_FREE_PTR(buffer);
            return OG_FALSE;
        }
        opool_attach(buffer, ext_buf_size, sql_cur_size, &extend_pool);
        olist_concat(&g_instance->sql_cur_pool.pool.free_objects, &extend_pool.free_objects);
        g_instance->sql_cur_pool.cnt += ext_cnt;
        *object = opool_alloc(&g_instance->sql_cur_pool.pool);
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
        return OG_TRUE;
    }
    cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    return OG_FALSE;
}

/**
1.apply sql cursor from global sql cursor pools,if not enough,go to step 2
2.try to extend the global sql cursor pools, and return one sql cursor.if the extension fails,go to step 3
3.apply sql cursor via malloc,if malloc fails, return NULL
* */
status_t sql_alloc_global_sql_cursor(object_t **object)
{
    sql_cursor_t *cursor = NULL;
    object_pool_t *pool = &g_instance->sql_cur_pool.pool;
    errno_t errcode;
    if (pool->free_objects.count > 0) {
        cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
        if (pool->free_objects.count > 0) {
            (*object) = opool_alloc(pool);
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return OG_SUCCESS;
        }
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    }

    if (!sql_try_extend_global_cursor(object)) {
        *object = (object_t *)malloc(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
        if ((*object) == NULL) {
            OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(sql_cursor_t), "creating sql cursor");
            return OG_ERROR;
        }
        errcode =
            memset_s(*object, OBJECT_HEAD_SIZE + sizeof(sql_cursor_t), 0, OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
        if (errcode != EOK) {
            CM_FREE_PTR(*object);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
        cursor = (sql_cursor_t *)(*object)->data;
        cursor->not_cache = OG_TRUE;
    }
    return OG_SUCCESS;
}

status_t sql_alloc_cursor(sql_stmt_t *ogsql_stmt, sql_cursor_t **cursor)
{
    object_t *object = NULL;
    object_pool_t *pool = &ogsql_stmt->session->sql_cur_pool;
    // apply preferentially from session. if not enough, apply from the global sql cursor pool.
    if (pool->free_objects.count > 0) {
        object = opool_alloc(pool);
    } else {
        OG_RETURN_IFERR(sql_alloc_global_sql_cursor(&object));
    }
    if (object == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t)), "creating sql cursor");
        return OG_ERROR;
    }

    *cursor = (sql_cursor_t *)object->data;
    sql_init_sql_cursor(ogsql_stmt, *cursor);
    olist_concat_single(&ogsql_stmt->sql_curs, object);
    return OG_SUCCESS;
}

status_t sql_alloc_knl_cursor(sql_stmt_t *ogsql_stmt, knl_cursor_t **cursor)
{
    object_pool_t *pool = &ogsql_stmt->session->knl_cur_pool;
    object_t *object = opool_alloc(pool);
    if (object == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + g_instance->kernel.attr.cursor_size),
            "creating kernel cursor");
        return OG_ERROR;
    }

    *cursor = (knl_cursor_t *)object->data;
    KNL_INIT_CURSOR(*cursor);
    (*cursor)->stmt = ogsql_stmt;
    knl_init_cursor_buf(&ogsql_stmt->session->knl_session, *cursor);

    (*cursor)->rowid = g_invalid_rowid;
    (*cursor)->scn = KNL_INVALID_SCN;
    olist_concat_single(&ogsql_stmt->knl_curs, object);
    return OG_SUCCESS;
}

static void sql_free_sql_cursor_by_type(sql_stmt_t *stmt, sql_cursor_t *ogsql_cursor)
{
    object_t *object = (object_t *)((char *)ogsql_cursor - OBJECT_HEAD_SIZE);
    object_pool_t *pool = &stmt->session->sql_cur_pool;
    if (ogsql_cursor->not_cache) {
        CM_FREE_PTR(object);
    } else if (pool->free_objects.count < g_instance->attr.sql_cursors_each_sess) {
        olist_concat_single(&pool->free_objects, object);
    } else {
        pool = &g_instance->sql_cur_pool.pool;
        cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
        olist_concat_single(&pool->free_objects, object);
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    }
}

void sql_free_cursor(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    if (ogsql_cursor == NULL) {
        return;
    }
    object_t *object = (object_t *)((char *)ogsql_cursor - OBJECT_HEAD_SIZE);

    if (ogsql_cursor->is_open) {
        sql_close_cursor(ogsql_stmt, ogsql_cursor);
    }

    ogsql_cursor->hash_mtrl_ctx = NULL;

    if (ogsql_cursor->connect_data.first_level_cursor != NULL) {
        sql_reset_connect_data(ogsql_cursor);
    }

    sql_reset_mtrl(ogsql_stmt, ogsql_cursor);

    olist_remove(&ogsql_stmt->sql_curs, object);
    sql_free_sql_cursor_by_type(ogsql_stmt, ogsql_cursor);
}

void sql_free_cursors(sql_stmt_t *ogsql_stmt)
{
    while (ogsql_stmt->sql_curs.first != NULL) {
        sql_free_cursor(ogsql_stmt, (sql_cursor_t *)ogsql_stmt->sql_curs.first->data);
    }
}

void sql_free_knl_cursor(sql_stmt_t *ogsql_stmt, knl_cursor_t *ogsql_cursor)
{
    object_pool_t *pool = &ogsql_stmt->session->knl_cur_pool;
    object_t *object = (object_t *)((char *)ogsql_cursor - OBJECT_HEAD_SIZE);

    if (ogsql_cursor->file != -1) {
        cm_close_file(ogsql_cursor->file);
    }
    knl_close_cursor(&ogsql_stmt->session->knl_session, ogsql_cursor);
    olist_remove(&ogsql_stmt->knl_curs, object);
    opool_free(pool, object);
}

void sql_release_multi_parts_resources(sql_stmt_t *ogsql_stmt, sql_table_cursor_t *tab_cur)
{
    if (tab_cur->multi_parts_info.knlcur_list == NULL || tab_cur->multi_parts_info.knlcur_list->count == 0) {
        tab_cur->multi_parts_info.knlcur_list = NULL;
        tab_cur->multi_parts_info.knlcur_id = 0;
        tab_cur->multi_parts_info.sort_info = NULL;
        return;
    }
    mps_knlcur_t *knlcur_info = (mps_knlcur_t *)cm_galist_get(tab_cur->multi_parts_info.knlcur_list, 0);
    tab_cur->knl_cur = knlcur_info->knl_cursor;

    uint32 count = tab_cur->multi_parts_info.knlcur_list->count;
    for (uint32 i = 1; i < count; i++) {
        knlcur_info = (mps_knlcur_t *)cm_galist_get(tab_cur->multi_parts_info.knlcur_list, i);
        knl_close_cursor(&ogsql_stmt->session->knl_session, knlcur_info->knl_cursor);
    }
    tab_cur->multi_parts_info.knlcur_list = NULL;
    tab_cur->multi_parts_info.knlcur_id = 0;
    tab_cur->multi_parts_info.sort_info = NULL;
}

static inline void sql_free_table_cursor(sql_stmt_t *ogsql_stmt, sql_table_cursor_t *ogsql_cursor)
{
    sql_release_multi_parts_resources(ogsql_stmt, ogsql_cursor);

    ogsql_cursor->scan_flag = SEQ_SQL_SCAN;

    if (OG_IS_SUBSELECT_TABLE(ogsql_cursor->table->type)) {
        if (ogsql_cursor->sql_cur != NULL) {
            if (ogsql_cursor->table->type == VIEW_AS_TABLE && ogsql_cursor->action == CURSOR_ACTION_INSERT) {
                sql_free_knl_cursor(ogsql_stmt, ogsql_cursor->knl_cur);
            } else {
                sql_free_cursor(ogsql_stmt, ogsql_cursor->sql_cur);
            }
        }
        return;
    }

    if (ogsql_cursor->table->type == JSON_TABLE) {
        sql_release_json_table(ogsql_cursor);
    } else {
        sql_free_varea_set(ogsql_cursor);
    }

    {
        sql_free_knl_cursor(ogsql_stmt, ogsql_cursor->knl_cur);
    }
}

void sql_free_merge_join_data(sql_stmt_t *ogsql_stmt, join_data_t *m_join)
{
    if (m_join->left != NULL) {
        sql_free_cursor(ogsql_stmt, m_join->left);
        m_join->left = NULL;
    }
    if (m_join->right != NULL) {
        sql_free_cursor(ogsql_stmt, m_join->right);
        m_join->right = NULL;
    }
}

static void sql_free_nl_batch_exec_data(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        if (ogsql_cursor->exec_data.nl_batch[i].cache_cur != NULL) {
            sql_free_cursor(ogsql_stmt, ogsql_cursor->exec_data.nl_batch[i].cache_cur);
            ogsql_cursor->exec_data.nl_batch[i].cache_cur = NULL;
        }
    }
}

void sql_free_va_set(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    hash_segment_t *hash_segment = NULL;

    ogsql_cursor->exec_data.query_limit = NULL;
    ogsql_cursor->exec_data.select_limit = NULL;
    ogsql_cursor->exec_data.union_all = NULL;
    ogsql_cursor->exec_data.minus.r_continue_fetch = OG_TRUE;
    ogsql_cursor->exec_data.minus.rnums = 0;
    ogsql_cursor->exec_data.explain_col_max_size = NULL;
    ogsql_cursor->exec_data.qb_col_max_size = NULL;
    ogsql_cursor->exec_data.outer_join = NULL;
    ogsql_cursor->exec_data.inner_join = NULL;
    ogsql_cursor->exec_data.join = NULL;
    ogsql_cursor->exec_data.select_view = NULL;
    ogsql_cursor->exec_data.tab_parallel = NULL;
    ogsql_cursor->exec_data.group = NULL;
    ogsql_cursor->exec_data.right_semi = NULL;
    ogsql_cursor->hash_join_ctx = NULL;
    CM_INIT_TEXTBUF(&ogsql_cursor->exec_data.sort_concat, 0, NULL);

    if (ogsql_cursor->exec_data.aggr_dis != NULL) {
        hash_segment = (hash_segment_t *)ogsql_cursor->exec_data.aggr_dis;
        vm_hash_segment_deinit(hash_segment);
        ogsql_cursor->exec_data.aggr_dis = NULL;
    }

    if (ogsql_cursor->exec_data.group_cube != NULL) {
        sql_free_group_cube(ogsql_stmt, ogsql_cursor);
        ogsql_cursor->exec_data.group_cube = NULL;
    }

    if (ogsql_cursor->exec_data.nl_batch != NULL) {
        sql_free_nl_batch_exec_data(ogsql_stmt, ogsql_cursor, ogsql_stmt->context->nl_batch_cnt);
        ogsql_cursor->exec_data.nl_batch = NULL;
    }

    if (ogsql_cursor->exec_data.minus.rs_vmid != OG_INVALID_ID32) {
        vm_free(ogsql_stmt->mtrl.session, ogsql_stmt->mtrl.pool, ogsql_cursor->exec_data.minus.rs_vmid);
        ogsql_cursor->exec_data.minus.rs_vmid = OG_INVALID_ID32;
    }

    ogsql_cursor->exec_data.index_scan_range_ar = NULL;
    ogsql_cursor->exec_data.part_scan_range_ar = NULL;
    ogsql_cursor->exec_data.dv_plan_buf = NULL;
}

static void sql_free_hash_join_data(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    for (uint32 i = 0; i < OG_MAX_JOIN_TABLES; i++) {
        if (ogsql_cursor->hash_mtrl.hj_tables[i] != NULL) {
            sql_free_cursor(ogsql_stmt, ogsql_cursor->hash_mtrl.hj_tables[i]);
            ogsql_cursor->hash_mtrl.hj_tables[i] = NULL;
        }
    }
}

static inline void sql_free_ssa_cursors(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    sql_cursor_t *ssa_cur = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;

    curr = biqueue_first(&ogsql_cursor->ssa_cursors);
    end = biqueue_end(&ogsql_cursor->ssa_cursors);

    while (curr != end) {
        ssa_cur = OBJECT_OF(sql_cursor_t, curr);
        curr = curr->next;
        sql_free_cursor(ogsql_cursor->stmt, ssa_cur);
    }
    biqueue_init(&ogsql_cursor->ssa_cursors);
}

static void sql_free_merge_join_resource(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    if (ogsql_cursor->m_join == NULL) {
        return;
    }
    uint32 mj_plan_count = ogsql_cursor->query->join_assist.mj_plan_count;
    if (ogsql_cursor->query->s_query != NULL) {
        mj_plan_count = MAX(mj_plan_count, ogsql_cursor->query->s_query->join_assist.mj_plan_count);
    }
    for (uint32 i = 0; i < mj_plan_count; i++) {
        sql_free_merge_join_data(ogsql_stmt, &ogsql_cursor->m_join[i]);
    }
    ogsql_cursor->m_join = NULL;
}

void sql_free_nl_full_opt_ctx(nl_full_opt_ctx_t *opt_ctx)
{
    if (opt_ctx->iter.hash_table != NULL) {
        vm_hash_close_page(&opt_ctx->hash_seg, &opt_ctx->hash_table_entry.page);
        opt_ctx->iter.hash_table = NULL;
    }
    vm_hash_segment_deinit(&opt_ctx->hash_seg);
    opt_ctx->iter.callback_ctx = NULL;
    opt_ctx->iter.curr_bucket = 0;
    opt_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
}

static void inline sql_free_nl_full_opt_ctx_list(sql_cursor_t *ogsql_cursor)
{
    nl_full_opt_ctx_t *opt_ctx = NULL;

    for (uint32 i = 0; i < ogsql_cursor->nl_full_ctx_list->count; i++) {
        opt_ctx = (nl_full_opt_ctx_t *)cm_galist_get(ogsql_cursor->nl_full_ctx_list, i);
        sql_free_nl_full_opt_ctx(opt_ctx);
    }
    ogsql_cursor->nl_full_ctx_list = NULL;
}

static inline void sql_free_cursor_tables(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    for (uint32 i = 0; i < ogsql_cursor->table_count; i++) {
        sql_free_table_cursor(ogsql_stmt, &ogsql_cursor->tables[ogsql_cursor->id_maps[i]]);
    }
    ogsql_cursor->table_count = 0;
    ogsql_cursor->tables = NULL;
}

void sql_close_cursor(sql_stmt_t *ogsql_stmt, sql_cursor_t *ogsql_cursor)
{
    OG_RETVOID_IFTRUE(!ogsql_cursor->is_open)
    ogsql_cursor->is_open = OG_FALSE;
    ogsql_cursor->idx_func_cache = NULL;

    if (ogsql_cursor->nl_full_ctx_list != NULL) {
        sql_free_nl_full_opt_ctx_list(ogsql_cursor);
    }

    if (ogsql_cursor->left_cursor != NULL) {
        sql_free_cursor(ogsql_stmt, ogsql_cursor->left_cursor);
        ogsql_cursor->left_cursor = NULL;
    }

    if (ogsql_cursor->right_cursor != NULL) {
        sql_free_cursor(ogsql_stmt, ogsql_cursor->right_cursor);
        ogsql_cursor->right_cursor = NULL;
    }

    sql_reset_mtrl(ogsql_stmt, ogsql_cursor);
    sql_free_hash_join_data(ogsql_stmt, ogsql_cursor);

    if (ogsql_cursor->exec_data.ext_knl_cur != NULL) {
        sql_free_knl_cursor(ogsql_stmt, ogsql_cursor->exec_data.ext_knl_cur);
        ogsql_cursor->exec_data.ext_knl_cur = NULL;
    }
    sql_free_cursor_tables(ogsql_stmt, ogsql_cursor);
    sql_free_ssa_cursors(ogsql_stmt, ogsql_cursor);

#ifdef OG_RAC_ING
    ogsql_cursor->do_sink_all = OG_FALSE;
    // ogsql_cursor->sink_all_list will be cleared again before execute
    (void)group_list_clear(&ogsql_cursor->sink_all_list);
#endif

    if (ogsql_cursor->query != NULL) {
        sql_free_merge_join_resource(ogsql_stmt, ogsql_cursor);
    }

    sql_free_va_set(ogsql_stmt, ogsql_cursor);

    if (ogsql_cursor->group_ctx != NULL) {
        sql_free_group_ctx(ogsql_stmt, ogsql_cursor->group_ctx);
        ogsql_cursor->group_ctx = NULL;
    }

    if (ogsql_cursor->cnct_ctx != NULL) {
        sql_free_concate_ctx(ogsql_stmt, ogsql_cursor->cnct_ctx);
        ogsql_cursor->cnct_ctx = NULL;
    }

    ogsql_cursor->unpivot_ctx = NULL;

    if (ogsql_cursor->distinct_ctx != NULL) {
        sql_free_distinct_ctx(ogsql_cursor->distinct_ctx);
        ogsql_cursor->distinct_ctx = NULL;
    }

    if (ogsql_cursor->connect_data.first_level_cursor != NULL) {
        sql_free_connect_cursor(ogsql_stmt, ogsql_cursor);
    }

    vmc_free(&ogsql_cursor->vmc);
}

static rs_fetch_func_tab_t g_rs_fetch_func_tab[] = {
    { RS_TYPE_NONE, sql_fetch_query },
    { RS_TYPE_NORMAL, sql_fetch_query },
    { RS_TYPE_SORT, sql_fetch_sort },
    { RS_TYPE_SORT_GROUP, sql_fetch_sort_group },
    { RS_TYPE_MERGE_SORT_GROUP, sql_fetch_merge_sort_group },
    { RS_TYPE_HASH_GROUP, sql_fetch_hash_group_new },
    { RS_TYPE_PAR_HASH_GROUP, sql_fetch_hash_group_new },
    { RS_TYPE_INDEX_GROUP, sql_fetch_index_group },
    { RS_TYPE_AGGR, sql_fetch_aggr },
    { RS_TYPE_SORT_DISTINCT, sql_fetch_sort_distinct },
    { RS_TYPE_HASH_DISTINCT, sql_fetch_hash_distinct },
    { RS_TYPE_INDEX_DISTINCT, sql_fetch_index_distinct },
    { RS_TYPE_UNION, sql_fetch_hash_union },
    { RS_TYPE_UNION_ALL, sql_fetch_union_all },
    { RS_TYPE_MINUS, sql_fetch_minus },
    { RS_TYPE_HASH_MINUS, NULL},
    { RS_TYPE_LIMIT, sql_fetch_limit },
    { RS_TYPE_HAVING, sql_fetch_having },
    { RS_TYPE_REMOTE, NULL},
    { RS_TYPE_GROUP_MERGE, NULL},
    { RS_TYPE_WINSORT, sql_fetch_winsort },
    { RS_TYPE_HASH_MTRL, sql_fetch_query },
    { RS_TYPE_ROW, sql_fetch_query },
    { RS_TYPE_SORT_PAR, NULL},
    { RS_TYPE_SIBL_SORT, sql_fetch_sibl_sort },
    { RS_TYPE_PAR_QUERY_JOIN, NULL},
    { RS_TYPE_GROUP_CUBE, sql_fetch_group_cube },
    { RS_TYPE_ROWNUM, sql_fetch_rownum },
    { RS_TYPE_FOR_UPDATE, sql_fetch_for_update },
    { RS_TYPE_WITHAS_MTRL, sql_fetch_withas_mtrl },
};

static inline sql_fetch_func_t sql_get_fetch_func(sql_stmt_t *ogsql_stmt, sql_cursor_t *cursor)
{
    if (SECUREC_UNLIKELY(ogsql_stmt->rs_type == RS_TYPE_SORT_PAR && cursor->par_ctx.par_mgr == NULL)) {
        return sql_fetch_sort;
    }
    return g_rs_fetch_func_tab[ogsql_stmt->rs_type].sql_fetch_func;
}

status_t sql_make_result_set(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status;

    if (cursor->eof) {
        sql_close_cursor(stmt, cursor);
        return OG_SUCCESS;
    }
    CM_TRACE_BEGIN;
    date_t rs_plan_time = AUTOTRACE_ON(stmt) ? stmt->plan_time[stmt->rs_plan->plan_id] : 0;

    sql_send_row_func_t sql_send_row_func = sql_get_send_row_func(stmt, stmt->rs_plan);
    sql_fetch_func_t sql_fetch_func = sql_get_fetch_func(stmt, cursor);
    stmt->need_send_ddm = OG_TRUE;
    status = sql_make_normal_rs(stmt, cursor, sql_fetch_func, sql_send_row_func);
    if (status != OG_SUCCESS) {
        sql_close_cursor(stmt, cursor);
    }
    if (AUTOTRACE_ON(stmt) && stmt->plan_time[stmt->rs_plan->plan_id] == rs_plan_time) {
        CM_TRACE_END(stmt, stmt->rs_plan->plan_id);
    }
    stmt->need_send_ddm = OG_FALSE;
    stmt->session->stat.fetch_count++;
    return status;
}

status_t sql_execute_single_dml(sql_stmt_t *ogsql_stmt, knl_savepoint_t *savepoint)
{
    status_t status;

    OG_RETURN_IFERR(sql_check_tables(ogsql_stmt, ogsql_stmt->context));

    sql_set_scn(ogsql_stmt);

    switch (ogsql_stmt->context->type) {
        case OGSQL_TYPE_SELECT:
            status = sql_execute_select(ogsql_stmt);
            break;

        case OGSQL_TYPE_UPDATE:
            status = sql_execute_update(ogsql_stmt);
            break;

        case OGSQL_TYPE_INSERT:
            status = sql_execute_insert(ogsql_stmt);
            break;

        case OGSQL_TYPE_DELETE:
            status = sql_execute_delete(ogsql_stmt);
            break;

        case OGSQL_TYPE_REPLACE:
            status = sql_execute_replace(ogsql_stmt);
            break;

        case OGSQL_TYPE_MERGE:
        default:
            status = sql_execute_merge(ogsql_stmt);
            break;
    }

    if (status != OG_SUCCESS) {
        do_rollback(ogsql_stmt->session, savepoint);
        knl_reset_index_conflicts(KNL_SESSION(ogsql_stmt));
    }

    return status;
}

status_t sql_try_put_dml_batch_error(sql_stmt_t *ogsql_stmt, uint32 row, int32 error_code, const char *message)
{
    cs_packet_t *send_pack = &ogsql_stmt->session->agent->send_pack;
    text_t errmsg_text = {
        .str = (char *)message,
        .len = (uint32)strlen(message)
    };

    if (ogsql_stmt->session->call_version >= CS_VERSION_10) {
        OG_RETURN_IFERR(cs_put_int32(send_pack, row));
        OG_RETURN_IFERR(cs_put_int32(send_pack, error_code));
        OG_RETURN_IFERR(cs_put_text(send_pack, &errmsg_text));
    } else {
        OG_RETURN_IFERR(cs_put_int32(send_pack, row));
        OG_RETURN_IFERR(cs_put_str(send_pack, message));
    }
    cm_reset_error();
    return OG_SUCCESS;
}

static status_t sql_proc_allow_errors(sql_stmt_t *ogsql_stmt, uint32 param_idx)
{
    int32 code;
    const char *message = NULL;

    cm_get_error(&code, &message, NULL);
    // dc invalid need to do reparse
    if (code == ERR_DC_INVALIDATED) {
        return OG_ERROR;
    }

    if (ogsql_stmt->actual_batch_errs + 1 > ogsql_stmt->allowed_batch_errs) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_try_put_dml_batch_error(ogsql_stmt, param_idx, code, message));
    ogsql_stmt->actual_batch_errs++;

    return OG_SUCCESS;
}

static bool32 sql_batch_paremeted_insert_enabled(sql_stmt_t *ogsql_stmt)
{
    if (ogsql_stmt->param_info.paramset_offset + 1 >= ogsql_stmt->param_info.paramset_size) {
        return OG_FALSE;
    }

    sql_insert_t *insert_ctx = (sql_insert_t *)ogsql_stmt->context->entry;
    if (insert_ctx->select_ctx != NULL) {
        return OG_FALSE;
    }

    /* insert with multi values and multi paramter set bind is not supported */
    if (insert_ctx->pairs_count > 1) {
        return OG_FALSE;
    }

    return sql_batch_insert_enable(ogsql_stmt, insert_ctx);
}

#define CHECK_IGNORE_BATCH_ERROR(ogsql_stmt, i, status)                                 \
    if ((status) != OG_SUCCESS) {                                                 \
        OG_LOG_DEBUG_ERR("error occurs when issue dml, paramset index: %u", (i)); \
        if ((ogsql_stmt)->allowed_batch_errs > 0) {                                     \
            if (sql_proc_allow_errors((ogsql_stmt), (i)) == OG_SUCCESS) {               \
                (status) = OG_SUCCESS;                                            \
                (ogsql_stmt)->param_info.paramset_offset++;                             \
                continue;                                                         \
            }                                                                     \
        }                                                                         \
        break;                                                                    \
    }


static status_t sql_issue_parametered_dml(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status = OG_SUCCESS;
    knl_savepoint_t savepoint;

    OGSQL_SAVE_STACK(stmt);

    for (uint32 i = stmt->param_info.paramset_offset; i < stmt->param_info.paramset_size; i++) {
        OGSQL_RESTORE_STACK(stmt);

        // do read params from req packet
        status = sql_read_params(stmt);
        // try allowed batch errors if execute error
        CHECK_IGNORE_BATCH_ERROR(stmt, i, status);

        if ((stmt->context->type == OGSQL_TYPE_SELECT && i != stmt->param_info.paramset_size - 1)) {
            // for select, only the last
            stmt->param_info.paramset_offset++;
            continue;
        }

        knl_savepoint(&stmt->session->knl_session, &savepoint);
        cursor->total_rows = 0;

        // need clean value with the previous parameters
        sql_reset_first_exec_vars(stmt);
        sql_reset_sequence(stmt);
        // the context may be changed in try_get_execute_context, and the context-related content in cursor will become
        // invalid, so cursor should be closed in advance
        sql_close_cursor(stmt, cursor);

        stmt->context->readonly = OG_TRUE;
        stmt->context->readonly = OG_TRUE;

        if (AUTOTRACE_ON(stmt)) {
            OG_RETURN_IFERR(sql_init_stmt_plan_time(stmt));
        }
        status = sql_execute_single_dml(stmt, &savepoint);

        // try allowed batch errors if execute error
        CHECK_IGNORE_BATCH_ERROR(stmt, i, status);

        stmt->param_info.paramset_offset++;
        stmt->eof = cursor->eof;
        // execute batch need to return total affected rows
        stmt->total_rows += cursor->total_rows;
    }

    return status;
}

static status_t sql_issue_dml(sql_stmt_t *stmt)
{
    sql_cursor_t *cursor = OGSQL_ROOT_CURSOR(stmt);
    status_t status = OG_SUCCESS;
    bool32 do_batch_insert = OG_FALSE;

    if ((stmt->param_info.paramset_size == 0 || stmt->context->rs_columns != NULL)) {
        stmt->param_info.paramset_size = 1;
    }

    stmt->param_info.param_strsize = 0;
    stmt->params_ready = OG_FALSE;

    if (stmt->context->type == OGSQL_TYPE_INSERT) {
        do_batch_insert = sql_batch_paremeted_insert_enabled(stmt);
    }

    if (do_batch_insert) {
        OG_RETURN_IFERR(sql_check_tables(stmt, stmt->context));
        sql_set_scn(stmt);
        if (AUTOTRACE_ON(stmt)) {
            OG_RETURN_IFERR(sql_init_stmt_plan_time(stmt));
        }
        cursor->total_rows = 0;
        stmt->is_batch_insert = OG_TRUE;
        status = sql_execute_insert(stmt);
        stmt->is_batch_insert = OG_FALSE;
        stmt->eof = cursor->eof;
        // execute batch need to return total affected rows
        stmt->total_rows += cursor->total_rows;
    } else {
        status = sql_issue_parametered_dml(stmt, cursor);
    }
    /*
     * if the "SQL_CALC_FOUND_ROWS" flag specified, the recent_foundrows should be calculated extra
     * otherwise it should be the same as the actually sent rows
     */
    stmt->session->recent_foundrows =
        cursor->total_rows + cursor->found_rows.limit_skipcount + cursor->found_rows.offset_skipcount;

    if (status != OG_SUCCESS) { // Error happens when executes DML
        return OG_ERROR;
    }

    if (stmt->context->type == OGSQL_TYPE_SELECT && !stmt->eof) {
        OG_RETURN_IFERR(sql_keep_params(stmt));
        OG_RETURN_IFERR(sql_keep_first_exec_vars(stmt));
    }

    return OG_SUCCESS;
}

status_t sql_begin_dml(sql_stmt_t *ogsql_stmt)
{
    sql_cursor_t *cursor = NULL;

    if (sql_alloc_cursor(ogsql_stmt, &cursor) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (SQL_CURSOR_PUSH(ogsql_stmt, cursor) != OG_SUCCESS) {
        sql_free_cursor(ogsql_stmt, cursor);
        return OG_ERROR;
    }
    ogsql_stmt->resource_inuse = OG_TRUE;
    return OG_SUCCESS;
}

status_t sql_try_execute_dml(sql_stmt_t *ogsql_stmt)
{
    int32 code;
    const char *message = NULL;

    if (ogsql_stmt->context == NULL) {
        OG_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "prepared.");
        return OG_ERROR;
    }

    if (!ogsql_stmt->context->ctrl.valid) {
        OG_THROW_ERROR(ERR_DC_INVALIDATED);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_check_ltt_dc(ogsql_stmt));

    if (sql_begin_dml(ogsql_stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    status_t status = sql_issue_dml(ogsql_stmt);

    if (status != OG_SUCCESS) {
        cm_get_error(&code, &message, NULL);
        ogsql_stmt->dc_invalid = (code == ERR_DC_INVALIDATED);
        sql_release_resource(ogsql_stmt, OG_TRUE);
        ogsql_stmt->dc_invalid = OG_FALSE;
        SQL_CURSOR_POP(ogsql_stmt);
        return OG_ERROR;
    }

    if (ogsql_stmt->auto_commit == OG_TRUE) {
        OG_RETURN_IFERR(do_commit(ogsql_stmt->session));
    }

    return OG_SUCCESS;
}

status_t sql_execute_fetch_medatata(sql_stmt_t *ogsql_stmt)
{
    if (ogsql_stmt->status < STMT_STATUS_PREPARED) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    return my_sender(ogsql_stmt)->send_parsed_stmt(ogsql_stmt);
}

static status_t sql_reload_text(sql_stmt_t *ogsql_stmt, sql_text_t *sql)
{
    if (ogx_read_text(sql_pool, &ogsql_stmt->context->ctrl, &sql->value, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    sql->implicit = OG_FALSE;
    sql->loc.line = 1;
    sql->loc.column = 1;
    return OG_SUCCESS;
}

static status_t sql_fork_stmt(sql_stmt_t *ogsql_stmt, sql_stmt_t **ret)
{
    sql_stmt_t *sub_stmt = NULL;
    // PUSH stack will release by ple_exec_dynamic_sql
    OG_RETURN_IFERR(sql_push(ogsql_stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

    sql_init_stmt(ogsql_stmt->session, sub_stmt, ogsql_stmt->id);
    SET_STMT_CONTEXT(sub_stmt, NULL);
    SET_STMT_PL_CONTEXT(sub_stmt, NULL);
    sub_stmt->status = STMT_STATUS_IDLE;
    sub_stmt->is_verifying = ogsql_stmt->is_verifying;
    sub_stmt->is_srvoutput_on = ogsql_stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = OG_TRUE;
    sub_stmt->parent_stmt = ogsql_stmt;
    sub_stmt->cursor_info.type = PL_FORK_CURSOR;
    sub_stmt->cursor_info.reverify_in_fetch = OG_TRUE;
    *ret = sub_stmt;
    return OG_SUCCESS;
}

// notice: only use in return result
status_t sql_execute_fetch_cursor_medatata(sql_stmt_t *ogsql_stmt)
{
    if (ogsql_stmt->status < STMT_STATUS_PREPARED || (ogsql_stmt->cursor_info.has_fetched && ogsql_stmt->eof)) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }

    sql_select_t *select_ctx = (sql_select_t *)ogsql_stmt->context->entry;
    if (select_ctx->pending_col_count == 0) {
        return my_sender(ogsql_stmt)->send_parsed_stmt(ogsql_stmt);
    }

    sql_text_t sql;
    sql_stmt_t *sub_stmt = NULL;
    vmc_t vmc;
    vmc_init(&ogsql_stmt->session->vmp, &vmc);
    OG_RETURN_IFERR(vmc_alloc(&vmc, ogsql_stmt->context->ctrl.text_size + 1, (void **)&sql.str));
    sql.len = ogsql_stmt->context->ctrl.text_size + 1;
    if (sql_reload_text(ogsql_stmt, &sql) != OG_SUCCESS) {
        vmc_free(&vmc);
        return OG_ERROR;
    }
    OGSQL_SAVE_STACK(ogsql_stmt);
    if (sql_fork_stmt(ogsql_stmt, &sub_stmt) != OG_SUCCESS) {
        vmc_free(&vmc);
        return OG_ERROR;
    }

    status_t status = OG_ERROR;
    do {
        lex_reset(ogsql_stmt->session->lex);
        OG_BREAK_IF_ERROR(sql_read_kept_params(ogsql_stmt));
        sub_stmt->param_info.params = ogsql_stmt->param_info.params;
        OG_BREAK_IF_ERROR(sql_parse_dml_directly(sub_stmt, KEY_WORD_SELECT, &sql));
        status = my_sender(ogsql_stmt)->send_parsed_stmt(sub_stmt);
    } while (0);

    sql_free_context(sub_stmt->context);
    sql_release_resource(sub_stmt, OG_TRUE);
    if (sub_stmt->stat != NULL) {
        free(sub_stmt->stat);
        sub_stmt->stat = NULL;
    }
    OGSQL_RESTORE_STACK(ogsql_stmt);
    vmc_free(&vmc);
    return status;
}


static void sql_init_pl_column_def(sql_stmt_t *ogsql_stmt)
{
    if (ogsql_stmt->plsql_mode == PLSQL_CURSOR) {
        // the type of pl-variant which in cursor query is unknown until calc.
        ogsql_stmt->mark_pending_done = OG_FALSE;
    }
}

static inline status_t sql_send_fetch_result(sql_stmt_t *ogsql_stmt, sql_cursor_t *cursor)
{
    if (cursor == NULL) {
        OG_THROW_ERROR(ERR_INVALID_CURSOR);
        return OG_ERROR;
    }
    {
        if (sql_make_result_set(ogsql_stmt, cursor) != OG_SUCCESS) {
            sql_release_resource(ogsql_stmt, OG_TRUE);
            return OG_ERROR;
        }
    }

    ogsql_stmt->total_rows = cursor->total_rows;
    ogsql_stmt->eof = cursor->eof;
    return OG_SUCCESS;
}

status_t sql_execute_fetch(sql_stmt_t *ogsql_stmt)
{
    sql_cursor_t *cursor = OGSQL_ROOT_CURSOR(ogsql_stmt);
    bool32 pre_eof = ogsql_stmt->eof;

    if (ogsql_stmt->status < STMT_STATUS_EXECUTED) {
        OG_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "executed.");
        return OG_ERROR;
    }

    if (ogsql_stmt->eof) {
        ogsql_stmt->total_rows = 0;
        ogsql_stmt->batch_rows = 0;
        OG_RETURN_IFERR(my_sender(ogsql_stmt)->send_fetch_begin(ogsql_stmt));
        my_sender(ogsql_stmt)->send_fetch_end(ogsql_stmt);
        return OG_SUCCESS;
    }

    if (!ogsql_stmt->resource_inuse) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",resource is already destroyed");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_read_kept_params(ogsql_stmt));
    OG_RETURN_IFERR(sql_init_sequence(ogsql_stmt));
    OG_RETURN_IFERR(sql_load_first_exec_vars(ogsql_stmt));
    OG_RETURN_IFERR(sql_init_trigger_list(ogsql_stmt));
    OG_RETURN_IFERR(sql_init_pl_ref_dc(ogsql_stmt));
    sql_init_pl_column_def(ogsql_stmt);

    ogsql_stmt->batch_rows = 0;

    OG_RETURN_IFERR(my_sender(ogsql_stmt)->send_fetch_begin(ogsql_stmt));
    OG_RETURN_IFERR(sql_send_fetch_result(ogsql_stmt, cursor));

    /*
     * if the "SQL_CALC_FOUND_ROWS" flag specified, the recent_foundrows should be calculated extra
     * otherwise it should be the same as the actually sent rows
     */
    ogsql_stmt->session->recent_foundrows =
        cursor->total_rows + cursor->found_rows.limit_skipcount + cursor->found_rows.offset_skipcount;

    my_sender(ogsql_stmt)->send_fetch_end(ogsql_stmt);
    ogsql_stmt->is_success = OG_TRUE;

    if (ogsql_stmt->eof) {
        sql_unlock_lnk_tabs(ogsql_stmt);
        if (ogsql_stmt->eof) {
            sql_release_resource(ogsql_stmt, OG_FALSE);
            if (!pre_eof) {
                sql_dec_active_stmts(ogsql_stmt);
            }
        }
    }

    return OG_SUCCESS;
}

void sql_init_varea_set(sql_stmt_t *ogsql_stmt, sql_table_cursor_t *table_cursor)
{
    vmc_init(&ogsql_stmt->session->vmp, &table_cursor->vmc);
    if (table_cursor->table != NULL && (table_cursor->table->type == JSON_TABLE)) {
        table_cursor->json_table_exec.json_assist = NULL;
        table_cursor->json_table_exec.json_value = NULL;
        table_cursor->json_table_exec.loc = NULL;
    } else {
        table_cursor->key_set.key_data = NULL;
        table_cursor->part_set.key_data = NULL;
        table_cursor->key_set.type = KEY_SET_FULL;
        table_cursor->part_set.type = KEY_SET_FULL;
    }
}

void sql_free_varea_set(sql_table_cursor_t *table_cursor)
{
    vmc_free(&table_cursor->vmc);
    table_cursor->key_set.key_data = NULL;
    table_cursor->part_set.key_data = NULL;
}

og_type_t sql_get_pending_type(char *pending_buf, uint32 id)
{
    uint32 count;
    og_type_t *types = NULL;

    if (pending_buf == NULL) {
        return OG_TYPE_VARCHAR;
    }

    count = (*(uint32 *)pending_buf - PENDING_HEAD_SIZE) / sizeof(og_type_t);
    if (id >= count) {
        return OG_TYPE_VARCHAR;
    }

    types = (og_type_t *)(pending_buf + PENDING_HEAD_SIZE);
    return types[id];
}

#ifdef __cplusplus
}
#endif
