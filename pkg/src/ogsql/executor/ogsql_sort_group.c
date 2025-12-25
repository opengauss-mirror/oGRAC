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
 * ogsql_sort_group.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_sort_group.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_sort_group.h"
#include "ogsql_btree.h"
#include "ogsql_group.h"
#include "ogsql_select.h"
#include "ogsql_aggr.h"

static inline og_type_t sql_get_group_expr_datatype(sql_cursor_t *cursor, uint32 col_id)
{
    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(cursor->group_ctx->group_p->exprs, col_id);

    if (expr->root->datatype != OG_TYPE_UNKNOWN) {
        return expr->root->datatype;
    } else {
        return sql_get_pending_type(cursor->mtrl.group.buf, col_id);
    }
}

static inline int32 sql_sort_group_cmp_g(sql_cursor_t *cursor, mtrl_row_t *row1, mtrl_row_t *row2, uint32 col_id,
    const order_mode_t *order_mode)
{
    og_type_t datatype = sql_get_group_expr_datatype(cursor, col_id);
    return sql_sort_mtrl_rows(row1, row2, col_id, datatype, order_mode);
}

static inline int32 sql_sort_group_cmp_i(sql_cursor_t *cursor, mtrl_row_t *row1, mtrl_row_t *row2, uint32 col_id)
{
    og_type_t datatype = sql_get_group_expr_datatype(cursor, col_id);

    return sql_compare_data_ex(MT_CDATA(row1, col_id), MT_CSIZE(row1, col_id), MT_CDATA(row2, col_id),
        MT_CSIZE(row2, col_id), datatype);
}

status_t sql_sort_group_cmp(int32 *result, void *callback_ctx, char *l_buf, uint32 lsize, char *r_buf,
    uint32 rsize)
{
    sql_cursor_t *cur = (sql_cursor_t *)callback_ctx;
    mtrl_row_t row1;
    mtrl_row_t row2;
    btree_sort_key_t *btree_sort_key = NULL;
    galist_t *sort_groups = cur->group_ctx->group_p->sort_groups;
    galist_t *group_exprs = cur->group_ctx->group_p->exprs;
    bool8 *already_cmp = NULL;
    uint32 need_size;

    row1.data = l_buf;
    cm_decode_row(l_buf, row1.offsets, row1.lens, NULL);
    row2.data = r_buf;
    cm_decode_row(r_buf, row2.offsets, row2.lens, NULL);

    need_size = group_exprs->count * sizeof(bool8);
    OG_RETURN_IFERR(sql_push(cur->stmt, need_size, (void **)&already_cmp));

    MEMS_RETURN_IFERR(memset_s(already_cmp, need_size, OG_FALSE, need_size));

    for (uint32 i = 0; i < sort_groups->count; ++i) {
        btree_sort_key = (btree_sort_key_t *)cm_galist_get(sort_groups, i);

        already_cmp[btree_sort_key->group_id] = OG_TRUE;
        *result = sql_sort_group_cmp_g(cur, &row1, &row2, btree_sort_key->group_id, &btree_sort_key->sort_mode);
        if (*result != 0) {
            OGSQL_POP(cur->stmt);
            return OG_SUCCESS;
        }
    }

    for (uint32 i = 0; i < group_exprs->count; ++i) {
        if (already_cmp[i]) {
            continue;
        }

        *result = sql_sort_group_cmp_i(cur, &row1, &row2, i);
        if (*result != 0) {
            OGSQL_POP(cur->stmt);
            return OG_SUCCESS;
        }
    }

    OGSQL_POP(cur->stmt);
    return OG_SUCCESS;
}

status_t sql_sort_group_calc(void *callback_ctx, const char *new_buf, uint32 new_size,
    const char *old_buf, uint32 old_size, bool32 found)
{
    sql_cursor_t *cur = (sql_cursor_t *)callback_ctx;
    return hash_group_i_operation_func(cur->group_ctx, new_buf, new_size, old_buf, old_size, found);
}

static status_t sql_mtrl_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = OG_FALSE;
    char *buf = NULL;
    status_t status;
    uint32 size;
    uint32 key_size;

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));

    OGSQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_fetch_query(stmt, cursor, plan->group.next, &eof) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (eof) {
            status = OG_SUCCESS;
            break;
        }

        if (sql_make_hash_group_row_new(stmt, cursor->group_ctx, 0, buf, &size, &key_size, cursor->mtrl.group.buf) !=
            OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        cursor->group_ctx->oper_type = OPER_TYPE_INSERT;
        if (sql_btree_insert(&cursor->group_ctx->btree_seg, buf, size, key_size)) {
            status = OG_ERROR;
            break;
        }

        OGSQL_RESTORE_STACK(stmt);
    }
    OGSQL_RESTORE_STACK(stmt);
    OGSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);
    OG_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->group.next));
    return status;
}

status_t sql_execute_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    OG_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->group.next));

    if (cursor->eof) {
        return OG_SUCCESS;
    }

    CM_ASSERT(cursor->group_ctx == NULL);
    OG_RETURN_IFERR(sql_alloc_hash_group_ctx(stmt, cursor, plan, SORT_GROUP_TYPE, 0));

    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        OG_RETURN_IFERR(sql_group_mtrl_record_types(cursor, plan, &cursor->mtrl.group.buf));
    }

    OG_RETURN_IFERR(sql_mtrl_sort_group(stmt, cursor, plan));

    if (cursor->eof) {
        return OG_SUCCESS;
    }

    cursor->group_ctx->oper_type = OPER_TYPE_FETCH;
    return sql_btree_open(&cursor->group_ctx->btree_seg, &cursor->group_ctx->btree_cursor);
}

status_t sql_fetch_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_btree_row_t *btree_row = NULL;
    mtrl_cursor_t *mtrl_cursor = NULL;

    OG_RETURN_IFERR(sql_btree_fetch(&cursor->group_ctx->btree_seg, &cursor->group_ctx->btree_cursor, eof));
    if (*eof) {
        return OG_SUCCESS;
    }

    btree_row = cursor->group_ctx->btree_cursor.btree_row;

    mtrl_cursor = &cursor->mtrl.cursor;
    mtrl_cursor->eof = OG_FALSE;
    mtrl_cursor->type = MTRL_CURSOR_SORT_GROUP;
    mtrl_cursor->row.data = btree_row->data;
    cm_decode_row(mtrl_cursor->row.data, mtrl_cursor->row.offsets, mtrl_cursor->row.lens, NULL);
    mtrl_cursor->hash_group.aggrs = mtrl_cursor->row.data + btree_row->key_size;
    OG_RETURN_IFERR(sql_hash_group_convert_rowid_to_str_row(cursor->group_ctx, cursor->stmt, cursor,
        cursor->group_ctx->group_p->aggrs));
    return sql_group_re_calu_aggr(cursor->group_ctx, plan->group.aggrs);
}

static status_t sql_mtrl_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *query_cursor,
    plan_node_t *plan)
{
    bool32 eof = OG_FALSE;
    char *buf = NULL;
    mtrl_rowid_t rid;
    status_t status;

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));

    OGSQL_SAVE_STACK(stmt);
    for (;;) {
        if (sql_fetch_query(stmt, query_cursor, plan->group.next, &eof) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }

        if (eof) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_SUCCESS;
            break;
        }

        if (sql_make_mtrl_group_row(stmt, cursor->mtrl.group.buf, &plan->group, buf) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.group.sid, buf, &rid) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }

        OGSQL_RESTORE_STACK(stmt);
    }
    OGSQL_POP(stmt);
    return status;
}

status_t sql_execute_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    status_t status = OG_ERROR;
    sql_cursor_t *query_cursor = NULL;
    OG_RETURN_IFERR(sql_init_group_exec_data(stmt, cursor, &plan->group));
    OG_RETURN_IFERR(sql_alloc_cursor(stmt, &query_cursor));
    OG_RETURN_IFERR(sql_open_cursors(stmt, query_cursor, cursor->query, CURSOR_ACTION_SELECT, OG_TRUE));
    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, query_cursor));

    do {
        OG_BREAK_IF_ERROR(sql_execute_query_plan(stmt, query_cursor, plan->group.next));
        if (query_cursor->eof) {
            cursor->eof = OG_TRUE;
            status = OG_SUCCESS;
            break;
        }

        OG_BREAK_IF_ERROR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr));

        OG_BREAK_IF_ERROR(
            mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_GROUP, (handle_t)plan->group.exprs, &cursor->mtrl.group.sid));

        if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
            OG_BREAK_IF_ERROR(sql_group_mtrl_record_types(cursor, plan, &cursor->mtrl.group.buf));
        }
        cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
        OG_BREAK_IF_ERROR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr));
        OG_BREAK_IF_ERROR(sql_init_aggr_page(stmt, cursor, plan->group.aggrs));

        if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.group.sid) != OG_SUCCESS) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = OG_INVALID_ID32;
            break;
        }

        if (sql_mtrl_merge_sort_group(stmt, cursor, query_cursor, plan) != OG_SUCCESS) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = OG_INVALID_ID32;
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.group.sid);
            break;
        }

        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.group.sid);

        OG_RETURN_IFERR(mtrl_sort_segment(&stmt->mtrl, cursor->mtrl.group.sid));

        if (mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.group.sid, &cursor->mtrl.cursor) != OG_SUCCESS) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = OG_INVALID_ID32;
            break;
        }
        status = OG_SUCCESS;
    } while (0);

    SQL_CURSOR_POP(stmt);
    sql_free_cursor(stmt, query_cursor);
    cursor->last_table = OG_INVALID_ID32;
    return status;
}

status_t sql_fetch_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    uint32 rows;
    uint32 avgs;
    bool32 group_changed = OG_FALSE;

    rows = 0;

    if (cursor->mtrl.cursor.eof) {
        *eof = OG_TRUE;
        return OG_SUCCESS;
    }

    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    OG_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->group.next, plan->group.aggrs, &avgs));

    while (!group_changed) {
        if (mtrl_fetch_group(&stmt->mtrl, &cursor->mtrl.cursor, &group_changed) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (cursor->mtrl.cursor.eof) {
            break;
        }
        rows++;
        if (sql_aggregate_group(stmt, cursor, plan) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (avgs > 0 && rows > 0) {
        OG_RETURN_IFERR(sql_exec_aggr(stmt, cursor, plan->group.aggrs, plan));
    }

    *eof = cursor->mtrl.cursor.eof;
    return sql_exec_aggr_extra(stmt, cursor, plan->group.aggrs, plan);
}
