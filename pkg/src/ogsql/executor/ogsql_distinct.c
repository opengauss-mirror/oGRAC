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
 * ogsql_distinct.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_distinct.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_distinct.h"
#include "ogsql_select.h"
#include "ogsql_mtrl.h"
#include "knl_mtrl.h"
#include "srv_instance.h"

static inline status_t distinct_hash_oper_func(void *callback_ctx, const char *new_buf, uint32 new_size,
    const char *old_buf, uint32 old_size, bool32 found)
{
    char *row_buf = NULL;
    sql_cursor_t *cursor = (sql_cursor_t *)callback_ctx;

    if (!found) {
        row_buf = cursor->mtrl.cursor.distinct.row.data;
        MEMS_RETURN_IFERR(memcpy_s(row_buf, OG_MAX_ROW_SIZE, old_buf, old_size));

        mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
        mtrl_cursor->distinct.eof = OG_FALSE;
        mtrl_cursor->eof = OG_FALSE;
        mtrl_hash_distinct_cursor_t *hash_distinct_cursor = &mtrl_cursor->distinct;
        cm_decode_row(hash_distinct_cursor->row.data, hash_distinct_cursor->row.offsets, hash_distinct_cursor->row.lens,
            NULL);
        mtrl_cursor->type = MTRL_CURSOR_HASH_DISTINCT;
    }
    return OG_SUCCESS;
}

status_t sql_execute_hash_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    status_t status = OG_ERROR;
#ifdef TIME_STATISTIC
    clock_t start;
    double timeuse;
    start = cm_cal_time_bengin();
#endif

    do {
        OG_BREAK_IF_ERROR(sql_execute_query_plan(stmt, cursor, plan->distinct.next));
        if (cursor->eof) {
            status = OG_SUCCESS;
            break;
        }

        OG_BREAK_IF_ERROR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_DISTINCT, NULL, &cursor->mtrl.distinct));
        OG_BREAK_IF_ERROR(sql_alloc_distinct_ctx(stmt, cursor, plan, HASH_DISTINCT));
        cursor->mtrl.cursor.distinct.eof = OG_FALSE;
        status = OG_SUCCESS;
    } while (0);

#ifdef TIME_STATISTIC
    timeuse = cm_cal_time_end(start);
    stmt->mt_time += timeuse;
#endif
    return status;
}

status_t sql_fetch_hash_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 exist_row = OG_FALSE;
    char *buf = NULL;
    hash_segment_t *hash_segment = NULL;
    hash_table_entry_t *hash_table_entry = NULL;

    if (cursor->eof) {
        *eof = OG_TRUE;
        cursor->mtrl.cursor.distinct.eof = OG_TRUE;
        cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_DISTINCT;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));

    for (;;) {
        OGSQL_SAVE_STACK(stmt);
        if (sql_fetch_query(stmt, cursor, plan->distinct.next, eof) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            OGSQL_POP(stmt);
            return OG_ERROR;
        }

        if (*eof) {
            OGSQL_RESTORE_STACK(stmt);
            OGSQL_POP(stmt);
            cursor->mtrl.cursor.distinct.eof = OG_TRUE;
            cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_DISTINCT;
            return OG_SUCCESS;
        }

        if (sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->distinct.columns, buf) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            OGSQL_POP(stmt);
            return OG_ERROR;
        }
        hash_segment = &cursor->distinct_ctx->hash_segment;
        hash_table_entry = &cursor->distinct_ctx->hash_table_entry;
        if (vm_hash_table_insert2(&exist_row, hash_segment, hash_table_entry, buf, ((row_head_t *)buf)->size) !=
            OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            OGSQL_POP(stmt);
            return OG_ERROR;
        }
        OGSQL_RESTORE_STACK(stmt);

        if (!exist_row) {
            break;
        }
    }

    OGSQL_POP(stmt);
    return OG_SUCCESS;
}

static status_t sql_get_distinct_index_row_buf(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof,
    char **next_row_buf)
{
    mtrl_segment_t *segment = stmt->mtrl.segments[cursor->mtrl.index_distinct];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;
    bool32 *flag = (bool32 *)((char *)page + page->free_begin);
    char *row_buf1 = (char *)page + page->free_begin + sizeof(bool32);
    char *row_buf2 = row_buf1 + OG_MAX_ROW_SIZE;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;

    if (*flag) {
        *flag = OG_FALSE;
        OG_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->distinct.next, eof));
        if (*eof) {
            return OG_SUCCESS;
        }
        OG_RETURN_IFERR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->distinct.columns, row_buf1));
        mtrl_cursor->row.data = row_buf1;
        *next_row_buf = row_buf2;
    } else {
        if (mtrl_cursor->row.data == row_buf1) {
            mtrl_cursor->row.data = row_buf2;
            *next_row_buf = row_buf1;
        } else {
            mtrl_cursor->row.data = row_buf1;
            *next_row_buf = row_buf2;
        }
        *eof = IS_INVALID_ROW(mtrl_cursor->row.data);
        if (*eof) {
            return OG_SUCCESS;
        }
    }
    cm_decode_row(mtrl_cursor->row.data, mtrl_cursor->row.offsets, mtrl_cursor->row.lens, NULL);
    return OG_SUCCESS;
}

status_t sql_fetch_index_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    int32 result;
    bool32 distinct_eof = OG_FALSE;
    char *next_row_buf = NULL;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    mtrl_segment_t *segment = stmt->mtrl.segments[cursor->mtrl.index_distinct];

    if (cursor->eof) {
        *eof = OG_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_get_distinct_index_row_buf(stmt, cursor, plan, eof, &next_row_buf));
    if (*eof) {
        return OG_SUCCESS;
    }

    for (;;) {
        OG_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->distinct.next, &distinct_eof));
        if (distinct_eof) {
            CM_SET_INVALID_ROW(next_row_buf);
            break;
        }
        OG_RETURN_IFERR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->distinct.columns, next_row_buf));
        OG_RETURN_IFERR(sql_mtrl_sort_cmp(segment, mtrl_cursor->row.data, next_row_buf, &result));
        if (result != 0) {
            break;
        }
    }
    return OG_SUCCESS;
}

status_t sql_execute_index_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    OG_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->distinct.next));
    if (cursor->eof) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(
        mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_DISTINCT, plan->distinct.columns, &cursor->mtrl.index_distinct));
    OG_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.index_distinct));

    mtrl_page_t *page = (mtrl_page_t *)stmt->mtrl.segments[cursor->mtrl.index_distinct]->curr_page->data;
    if (page->free_begin + 2 * OG_MAX_ROW_SIZE + sizeof(bool32) > OG_VMEM_PAGE_SIZE) {
        OG_THROW_ERROR(ERR_NO_FREE_VMEM, "one page free size is smaller than needed memory");
        return OG_ERROR;
    }
    *(bool32 *)((char *)page + page->free_begin) = OG_TRUE;
    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    return OG_SUCCESS;
}

static inline og_type_t sql_get_rs_col_datatype(galist_t *rs_columns, uint32 col_id, char *pending_buf)
{
    rs_column_t *rs_col = (rs_column_t *)cm_galist_get(rs_columns, col_id);

    if (rs_col->datatype != OG_TYPE_UNKNOWN) {
        return rs_col->datatype;
    }

    return sql_get_pending_type(pending_buf, col_id);
}

static inline int32 sql_sort_distinct_cmp_g(galist_t *rs_columns, mtrl_row_t *row1, mtrl_row_t *row2, uint32 col_id,
    char *pending_buf, const order_mode_t *order_mode)
{
    og_type_t datatype = sql_get_rs_col_datatype(rs_columns, col_id, pending_buf);
    return sql_sort_mtrl_rows(row1, row2, col_id, datatype, order_mode);
}

static inline int32 sql_sort_distinct_cmp_i(galist_t *rs_columns, mtrl_row_t *row1, mtrl_row_t *row2, uint32 col_id,
    char *pending_buf)
{
    og_type_t datatype = sql_get_rs_col_datatype(rs_columns, col_id, pending_buf);
    return sql_compare_data_ex(MT_CDATA(row1, col_id), MT_CSIZE(row1, col_id), MT_CDATA(row2, col_id),
        MT_CSIZE(row2, col_id), datatype);
}

static status_t sql_sort_distinct_cmp(int32 *result, void *callback_ctx, char *lbuf, uint32 lsize, char *rbuf,
    uint32 rsize)
{
    mtrl_row_t row1;
    mtrl_row_t row2;
    btree_cmp_key_t *btree_cmp_key = NULL;
    btree_sort_key_t *btree_sort_key = NULL;
    sql_cursor_t *cursor = (sql_cursor_t *)callback_ctx;
    distinct_ctx_t *distinct_ctx = cursor->distinct_ctx;
    galist_t *rs_columns = distinct_ctx->distinct_p->columns;
    btree_sort_t *btree_sort = distinct_ctx->distinct_p->btree_sort;

    row1.data = lbuf;
    cm_decode_row(lbuf, row1.offsets, row1.lens, NULL);
    row2.data = rbuf;
    cm_decode_row(rbuf, row2.offsets, row2.lens, NULL);

    for (uint32 i = 0; i < btree_sort->sort_key.count; ++i) {
        btree_sort_key = (btree_sort_key_t *)cm_galist_get(&btree_sort->sort_key, i);
        *result = sql_sort_distinct_cmp_g(rs_columns, &row1, &row2, btree_sort_key->group_id, cursor->mtrl.rs.buf,
            &btree_sort_key->sort_mode);
        if (*result != 0) {
            return OG_SUCCESS;
        }
    }

    for (uint32 i = 0; i < btree_sort->cmp_key.count; ++i) {
        btree_cmp_key = (btree_cmp_key_t *)cm_galist_get(&btree_sort->cmp_key, i);
        *result = sql_sort_distinct_cmp_i(rs_columns, &row1, &row2, btree_cmp_key->group_id, cursor->mtrl.rs.buf);
        if (*result != 0) {
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

void sql_free_distinct_ctx(distinct_ctx_t *distinct_ctx)
{
    if (distinct_ctx->type == SORT_DISTINCT) {
        sql_btree_deinit(&distinct_ctx->btree_seg);
    } else {
        vm_hash_segment_deinit(&distinct_ctx->hash_segment);
    }
}

status_t sql_alloc_distinct_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, distinct_type_t type)
{
    OG_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(distinct_ctx_t), (void **)&cursor->distinct_ctx));
    cursor->distinct_ctx->type = type;

    if (type == SORT_DISTINCT) {
        cursor->distinct_ctx->distinct_p = &plan->distinct;
        return sql_btree_init(&cursor->distinct_ctx->btree_seg, stmt->session, stmt->session->knl_session.temp_pool,
            cursor, sql_sort_distinct_cmp, NULL);
    }

    hash_segment_t *hash_segment = &cursor->distinct_ctx->hash_segment;
    vm_hash_segment_init(&stmt->session->knl_session, stmt->mtrl.pool, hash_segment, PMA_POOL, HASH_PAGES_HOLD,
        HASH_AREA_SIZE);

    hash_table_entry_t *hash_table_entry = &cursor->distinct_ctx->hash_table_entry;
    uint32 bucket_num = sql_get_plan_hash_rows(stmt, plan);
    if (stmt->context->hash_bucket_size != 0) {
        bucket_num = stmt->context->hash_bucket_size;
    }
    if (vm_hash_table_alloc(hash_table_entry, hash_segment, bucket_num) != OG_SUCCESS) {
        vm_hash_segment_deinit(hash_segment);
        return OG_ERROR;
    }

    if (vm_hash_table_init(hash_segment, hash_table_entry, distinct_hash_oper_func, NULL, cursor) != OG_SUCCESS) {
        vm_hash_segment_deinit(hash_segment);
        return OG_ERROR;
    }

    mtrl_segment_t *segment = stmt->mtrl.segments[cursor->mtrl.distinct];
    uint32 vm_id = segment->vm_list.last;
    if (mtrl_open_page(&stmt->mtrl, vm_id, &segment->curr_page) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 column_count = (type == HASH_DISTINCT) ? plan->distinct.columns->count : cursor->columns->count;
    OG_RETURN_IFERR(
        vmc_alloc(&cursor->vmc, column_count * sizeof(uint16), (void **)&cursor->mtrl.cursor.distinct.row.lens));
    OG_RETURN_IFERR(
        vmc_alloc(&cursor->vmc, column_count * sizeof(uint16), (void **)&cursor->mtrl.cursor.distinct.row.offsets));

    cursor->mtrl.cursor.distinct.row.data = segment->curr_page->data;
    return OG_SUCCESS;
}

static status_t sql_mtrl_sort_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    bool32 eof = OG_FALSE;
    char *buf = NULL;
    uint32 key_size;
    status_t status = OG_ERROR;
    distinct_ctx_t *distinct_ctx = cursor->distinct_ctx;

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));
    OGSQL_SAVE_STACK(stmt);

    for (;;) {
        OG_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan->distinct.next, &eof));
        if (eof) {
            status = OG_SUCCESS;
            break;
        }

        OG_BREAK_IF_ERROR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.rs.buf, plan->distinct.columns, buf));

        key_size = ((row_head_t *)buf)->size;
        OG_BREAK_IF_ERROR(sql_btree_insert(&distinct_ctx->btree_seg, buf, key_size, key_size));

        OGSQL_RESTORE_STACK(stmt);
    }
    OGSQL_RESTORE_STACK(stmt);
    OGSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);
    OG_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->distinct.next));
    return status;
}

status_t sql_execute_sort_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    OG_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->distinct.next));
    if (cursor->eof) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_alloc_distinct_ctx(stmt, cursor, plan, SORT_DISTINCT));
    OG_RETURN_IFERR(sql_mtrl_sort_distinct(stmt, cursor, plan));
    if (cursor->eof) {
        return OG_SUCCESS;
    }

    distinct_ctx_t *distinct_ctx = cursor->distinct_ctx;
    return sql_btree_open(&distinct_ctx->btree_seg, &distinct_ctx->btree_cursor);
}

status_t sql_fetch_sort_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    sql_btree_row_t *btree_row = NULL;
    mtrl_cursor_t *mtrl_cursor = &cursor->mtrl.cursor;
    distinct_ctx_t *distinct_ctx = cursor->distinct_ctx;

    OG_RETURN_IFERR(sql_btree_fetch(&distinct_ctx->btree_seg, &distinct_ctx->btree_cursor, eof));
    mtrl_cursor->type = MTRL_CURSOR_OTHERS;
    if (*eof) {
        return OG_SUCCESS;
    }

    btree_row = distinct_ctx->btree_cursor.btree_row;
    mtrl_cursor->eof = OG_FALSE;
    mtrl_cursor->row.data = btree_row->data;
    cm_decode_row(mtrl_cursor->row.data, mtrl_cursor->row.offsets, mtrl_cursor->row.lens, NULL);
    return OG_SUCCESS;
}
