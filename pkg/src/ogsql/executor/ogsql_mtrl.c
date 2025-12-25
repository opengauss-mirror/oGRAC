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
 * ogsql_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "ogsql_mtrl.h"
#include "ogsql_proj.h"
#include "ogsql_select.h"
#include "ogsql_func.h"
#include "ogsql_scan.h"
#include "var_defs.h"
#include "ogsql_expr_datatype.h"

static char g_null_row[OG_MAX_ROW_SIZE];
static rowid_t *g_null_rowid;

static spinlock_t g_null_row_lock;
static bool32 g_row_init = OG_FALSE;
static uint16 *g_null_row_offsets = NULL;
static uint16 *g_null_row_lens = NULL;
status_t init_null_row(void)
{
    status_t status = OG_SUCCESS;
    if (!g_row_init) {
        cm_spin_lock(&g_null_row_lock, NULL);
        while (!g_row_init) {
            row_assist_t ra;
            errno_t errcode;
            row_init(&ra, g_null_row, OG_MAX_ROW_SIZE, g_instance->kernel.attr.max_column_count - 1);
            g_null_rowid = (rowid_t *)(ra.buf + ra.head->size);
            *g_null_rowid = g_invalid_temp_rowid;
            uint32 alloc_size = sizeof(uint16) * OG_MAX_COLUMNS;
            g_null_row_offsets = (uint16 *)malloc(alloc_size);
            if (g_null_row_offsets == NULL) {
                OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc null row offsets");
                status = OG_ERROR;
                break;
            }
            g_null_row_lens = (uint16 *)malloc(alloc_size);
            if (g_null_row_lens == NULL) {
                OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc null row lens");
                status = OG_ERROR;
                break;
            }
            errcode = memset_s(g_null_row_offsets, alloc_size, 0, alloc_size);
            if (errcode != EOK) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                status = OG_ERROR;
                break;
            }
            errcode = memset_s(g_null_row_lens, alloc_size, 0, alloc_size);
            if (errcode != EOK) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                status = OG_ERROR;
                break;
            }
            cm_decode_row(g_null_row, g_null_row_offsets, g_null_row_lens, NULL);
            g_row_init = OG_TRUE;
        }
        if (status != OG_SUCCESS) {
            sql_free_null_row();
        }
        cm_spin_unlock(&g_null_row_lock);
    }
    return status;
}

status_t sql_make_mtrl_null_rs_row(mtrl_context_t *mtrl, uint32 seg_id, mtrl_rowid_t *rid)
{
    OG_RETURN_IFERR(init_null_row());
    return mtrl_insert_row(mtrl, seg_id, g_null_row, rid);
}

void sql_free_null_row(void)
{
    CM_FREE_PTR(g_null_row_offsets);
    CM_FREE_PTR(g_null_row_lens);
}

status_t sql_fetch_null_row(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    OG_RETURN_IFERR(init_null_row());
    row_addr_t *rows = cursor->exec_data.join;
    uint32 count = (g_instance->kernel.attr.max_column_count - 1) * sizeof(uint16);
    for (uint32 i = 0; i < cursor->table_count; i++) {
        *(rows[i].data) = g_null_row;
        if (rows[i].rowid != NULL) {
            *(rows[i].rowid) = *g_null_rowid;
        }
        MEMS_RETURN_IFERR(memcpy_sp(rows[i].offset, OG_MAX_COLUMNS * sizeof(uint16), g_null_row_offsets, count));
        MEMS_RETURN_IFERR(memcpy_sp(rows[i].len, OG_MAX_COLUMNS * sizeof(uint16), g_null_row_lens, count));
    }
    return OG_SUCCESS;
}

static inline int32 sql_compare_winsort_mtrl_row(mtrl_segment_t *seg, mtrl_row_t *row1, mtrl_row_t *row2)
{
    uint32 i;
    sort_item_t *sort_item = NULL;
    expr_tree_t *expr_tree = NULL;
    og_type_t datatype;
    winsort_args_t *args = (winsort_args_t *)seg->cmp_items;
    int32 result;

    if ((seg->cmp_flag & WINSORT_PART) && (args->group_exprs != NULL)) {
        for (i = 0; i < args->group_exprs->count; i++) {
            expr_tree = (expr_tree_t *)cm_galist_get(args->group_exprs, i);
            datatype = expr_tree->root->datatype;

            result = sql_compare_data_ex(MT_CDATA(row1, i), MT_CSIZE(row1, i), MT_CDATA(row2, i), MT_CSIZE(row2, i),
                datatype);
            if (result != 0) {
                return result;
            }
        }
    }

    if ((seg->cmp_flag & WINSORT_ORDER) && (args->sort_items != NULL)) {
        for (i = 0; i < args->sort_items->count; i++) {
            uint32 id = (args->group_exprs != NULL) ? (i + args->group_exprs->count) : i;
            sort_item = (sort_item_t *)cm_galist_get(args->sort_items, i);
            expr_tree = sort_item->expr;
            datatype = expr_tree->root->datatype;
            result = sql_sort_mtrl_rows(row1, row2, id, datatype, &sort_item->sort_mode);
            if (result != 0) {
                return result;
            }
        }
    }
    return 0;
}

static inline void sql_calc_pending_datatype(mtrl_segment_t *segment, uint32 id, og_type_t src_type,
    og_type_t *dts_type)
{
    og_type_t *types = NULL;
    if (src_type == OG_TYPE_UNKNOWN && segment->pending_type_buf != NULL) {
        types = (og_type_t *)(segment->pending_type_buf + PENDING_HEAD_SIZE);
        *dts_type = types[id];
    } else {
        *dts_type = src_type;
    }
}

static inline int32 sql_compare_mtrl_row(mtrl_segment_t *seg, mtrl_row_t *row1, mtrl_row_t *row2)
{
    uint32 i;
    sort_item_t *item = NULL;
    select_sort_item_t *select_sort_item = NULL;
    expr_tree_t *expr = NULL;
    rs_column_t *rs_col = NULL;
    order_mode_t order_mode = { SORT_MODE_NONE, SORT_NULLS_DEFAULT };
    og_type_t datatype;
    int32 result;

    if (seg->type == MTRL_SEGMENT_WINSORT) {
        return sql_compare_winsort_mtrl_row(seg, row1, row2);
    }

    for (i = 0; i < ((galist_t *)seg->cmp_items)->count; i++) {
        switch (seg->type) {
            case MTRL_SEGMENT_QUERY_SORT:
            case MTRL_SEGMENT_CONCAT_SORT:
            case MTRL_SEGMENT_SIBL_SORT:
                item = (sort_item_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                expr = item->expr;
                sql_calc_pending_datatype(seg, i, expr->root->datatype, &datatype);
                order_mode = item->sort_mode;
                break;

            case MTRL_SEGMENT_SELECT_SORT:
                select_sort_item = (select_sort_item_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                sql_calc_pending_datatype(seg, i, select_sort_item->datatype, &datatype);
                order_mode = select_sort_item->sort_mode;
                break;

            case MTRL_SEGMENT_DISTINCT:
            case MTRL_SEGMENT_RS:
                rs_col = (rs_column_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                sql_calc_pending_datatype(seg, i, rs_col->datatype, &datatype);
                order_mode.direction = SORT_MODE_ASC;
                order_mode.nulls_pos = DEFAULT_NULLS_SORTING_POSITION(SORT_MODE_ASC);
                break;

            default:
                expr = (expr_tree_t *)cm_galist_get((galist_t *)seg->cmp_items, i);
                sql_calc_pending_datatype(seg, i, expr->root->datatype, &datatype);
                order_mode.direction = SORT_MODE_ASC;
                order_mode.nulls_pos = DEFAULT_NULLS_SORTING_POSITION(SORT_MODE_ASC);
                break;
        }

        result = sql_sort_mtrl_rows(row1, row2, i, datatype, &order_mode);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

static inline void sql_decode_mtrl_row(mtrl_row_t *mtrl_row, char *data)
{
    mtrl_row->data = data;
    cm_decode_row(data, mtrl_row->offsets, mtrl_row->lens, NULL);
}

status_t sql_mtrl_sort_cmp(mtrl_segment_t *seg, char *data1, char *data2, int32 *result)
{
    mtrl_row_t mtrl_row1;
    mtrl_row_t mtrl_row2;
    sql_decode_mtrl_row(&mtrl_row1, data1);
    sql_decode_mtrl_row(&mtrl_row2, data2);
    *result = sql_compare_mtrl_row(seg, &mtrl_row1, &mtrl_row2);
    return OG_SUCCESS;
}

static inline status_t sql_mtrl_row_get_win_bor_value(mtrl_segment_t *seg, mtrl_row_t *row, uint32 *id,
    expr_tree_t *expr, variant_t *val)
{
    og_type_t datatype;
    if (expr != NULL) {
        if (TREE_IS_CONST(expr)) {
            *val = expr->root->value;
        } else {
            mtrl_row_assist_t row_ass;
            mtrl_row_init(&row_ass, row);
            sql_calc_pending_datatype(seg, *id, expr->root->datatype, &datatype);
            OG_RETURN_IFERR(mtrl_get_column_value(&row_ass, OG_FALSE, *id, datatype, OG_FALSE, val));
            (*id)++;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_mtrl_row_get_win_border(mtrl_cursor_t *cursor, mtrl_row_t *row, uint32 id, variant_t *l_val,
    variant_t *r_val)
{
    mtrl_segment_t *seg = cursor->sort.segment;
    winsort_args_t *args = (winsort_args_t *)seg->cmp_items;
    expr_tree_t *l_expr = args->windowing->l_expr;
    expr_tree_t *r_expr = args->windowing->r_expr;

    OG_RETURN_IFERR(sql_mtrl_row_get_win_bor_value(seg, row, &id, l_expr, l_val));
    return sql_mtrl_row_get_win_bor_value(seg, row, &id, r_expr, r_val);
}

status_t sql_mtrl_get_windowing_sort_val(mtrl_sort_cursor_t *sort, uint32 id, og_type_t datatype, variant_t *sort_val)
{
    mtrl_row_t mtrl_row;
    mtrl_row_assist_t row_assist;

    sql_decode_mtrl_row(&mtrl_row, sort->row);
    mtrl_row_init(&row_assist, &mtrl_row);
    return mtrl_get_column_value(&row_assist, OG_FALSE, id, datatype, OG_FALSE, sort_val);
}

status_t sql_mtrl_get_windowing_value(mtrl_cursor_t *cursor, variant_t *sort_val, variant_t *l_val, variant_t *r_val)
{
    winsort_args_t *winsort_args = (winsort_args_t *)cursor->sort.segment->cmp_items;
    uint32 id = (winsort_args->group_exprs != NULL) ? winsort_args->group_exprs->count : 0;
    sort_item_t *item = (sort_item_t *)cm_galist_get(winsort_args->sort_items, 0);
    mtrl_row_t mtrl_row;
    mtrl_row_assist_t row_assist;

    sql_decode_mtrl_row(&mtrl_row, cursor->sort.row);
    mtrl_row_init(&row_assist, &mtrl_row);
    OG_RETURN_IFERR(
        mtrl_get_column_value(&row_assist, cursor->eof, id, item->expr->root->datatype, OG_FALSE, sort_val));
    id += winsort_args->sort_items->count;
    return sql_mtrl_row_get_win_border(cursor, &mtrl_row, id, l_val, r_val);
}

status_t sql_mtrl_get_windowing_border(mtrl_cursor_t *cursor, variant_t *l_val, variant_t *r_val)
{
    winsort_args_t *winsort_args = (winsort_args_t *)cursor->sort.segment->cmp_items;
    uint32 id = (winsort_args->group_exprs != NULL) ? winsort_args->group_exprs->count : 0;
    mtrl_row_t mtrl_row;

    sql_decode_mtrl_row(&mtrl_row, cursor->sort.row);
    id += winsort_args->sort_items->count;
    return sql_mtrl_row_get_win_border(cursor, &mtrl_row, id, l_val, r_val);
}

void sql_init_mtrl(mtrl_context_t *mtrl_ctx, session_t *session)
{
    mtrl_init_context(mtrl_ctx, session);
    mtrl_ctx->sort_cmp = sql_mtrl_sort_cmp;
}

static void sql_free_sort(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.sort.sid);
    sql_cursor->mtrl.sort.buf = NULL;

    if (sql_cursor->mtrl.sort_seg != OG_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.sort_seg);
        sql_free_segment_in_vm(stmt, sql_cursor->mtrl.sort_seg);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.sort_seg);
        sql_cursor->mtrl.sort_seg = OG_INVALID_ID32;
    }
}

static void sql_free_aggr(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if (sql_cursor->mtrl.aggr != OG_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.aggr);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.aggr);
        sql_cursor->mtrl.aggr = OG_INVALID_ID32;
        sql_cursor->aggr_page = NULL;
    }

    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.aggr_str);
}

static void sql_free_winsort(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_rs.sid);
    cursor->mtrl.winsort_rs.buf = NULL;
    OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_aggr.sid);
    OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_aggr_ext.sid);
    OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.winsort_sort.sid);
    cursor->mtrl.winsort_sort.buf = NULL;
}

static inline void sql_free_connect_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t **cursor)
{
    sql_cursor_t *dst_cur = *cursor;
    if (dst_cur == NULL) {
        return;
    }
    dst_cur->connect_data.next_level_cursor = NULL;
    sql_free_cursor(stmt, dst_cur);
    (*cursor) = NULL;
}

static void sql_free_connect_mtrl_prior(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if (GET_VM_CTX(stmt) == NULL || sql_cursor->cb_mtrl_ctx->curr_level == 0) {
        return;
    }

    cb_mtrl_data_t *data = NULL;
    for (uint32 i = 0; i < sql_cursor->cb_mtrl_ctx->curr_level; i++) {
        data = (cb_mtrl_data_t *)(cm_galist_get(sql_cursor->cb_mtrl_ctx->cb_data, i));
        OG_CONTINUE_IFTRUE(IS_INVALID_MTRL_ROWID(data->prior_row));

        if (vmctx_free(GET_VM_CTX(stmt), &data->prior_row) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("failed to free row id vm id %u, vm slot %u", data->prior_row.vmid, data->prior_row.slot);
            return;
        }
        data->prior_row = g_invalid_entry;
    }
}

static void sql_free_connect_hash(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    sql_free_connect_mtrl_prior(stmt, sql_cursor);
    sql_free_connect_mtrl_cursor(stmt, &sql_cursor->cb_mtrl_ctx->last_cursor);
    sql_free_connect_mtrl_cursor(stmt, &sql_cursor->cb_mtrl_ctx->curr_cursor);
    sql_free_connect_mtrl_cursor(stmt, &sql_cursor->cb_mtrl_ctx->next_cursor);
    sql_cursor->connect_data.last_level_cursor = NULL;
    sql_cursor->connect_data.cur_level_cursor = NULL;
    sql_cursor->connect_data.next_level_cursor = NULL;
    sql_cursor->cb_mtrl_ctx->key_types = NULL;

    mtrl_close_cursor(&stmt->mtrl, &sql_cursor->mtrl.cursor);
    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->cb_mtrl_ctx->hash_table_rs);
    vm_hash_segment_deinit(&sql_cursor->cb_mtrl_ctx->hash_segment);
    vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, sql_cursor->cb_mtrl_ctx->vmid);
    sql_cursor->cb_mtrl_ctx = NULL;
}

static void sql_free_connect(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_cursor_t *curr_level_cur = cursor->connect_data.next_level_cursor;
    sql_cursor_t *next_level_cur = NULL;
    while (curr_level_cur != NULL) {
        next_level_cur = curr_level_cur->connect_data.next_level_cursor;
        curr_level_cur->connect_data.next_level_cursor = NULL;
        sql_free_cursor(stmt, curr_level_cur);
        curr_level_cur = next_level_cur;
    }

    cursor->connect_data.next_level_cursor = NULL;
    cursor->connect_data.cur_level_cursor = NULL;
}

void sql_free_connect_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->cb_mtrl_ctx != NULL) {
        sql_free_connect_hash(stmt, cursor);
    } else {
        sql_free_connect(stmt, cursor);
    }
}

static void sql_free_distinct(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    cursor->mtrl.cursor.distinct.row.lens = NULL;
    cursor->mtrl.cursor.distinct.row.offsets = NULL;
    OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.distinct);
    OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.index_distinct);
}

static void sql_free_hash_ctx(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if ((sql_cursor->hash_join_ctx != NULL) && (sql_cursor->hash_join_ctx->iter.hash_table != NULL)) {
        vm_hash_close_page(&sql_cursor->hash_seg, &sql_cursor->hash_table_entry.page);
        sql_cursor->hash_join_ctx->iter.hash_table = NULL;
    }

    if (sql_cursor->hash_table_status == HASH_TABLE_STATUS_CLONE) {
        mtrl_close_sort_cursor(&stmt->mtrl, &sql_cursor->mtrl.cursor.sort);
        sql_cursor->mtrl.cursor.rs_vmid = OG_INVALID_ID32;
    } else {
        mtrl_close_cursor(&stmt->mtrl, &sql_cursor->mtrl.cursor);
    }

    if ((sql_cursor->hash_seg.sess != NULL) && (sql_cursor->hash_table_status != HASH_TABLE_STATUS_CLONE)) {
        vm_hash_segment_deinit(&sql_cursor->hash_seg);
        sql_cursor->hash_seg.sess = NULL;
    }

    if (sql_cursor->hash_table_status != HASH_TABLE_STATUS_CLONE) {
        OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.hash_table_rs);
    }

    if (sql_cursor->hash_table_status == HASH_TABLE_STATUS_CLONE) {
        sql_cursor->hash_seg.sess = NULL;
        sql_cursor->mtrl.hash_table_rs = OG_INVALID_ID32;
    }

    sql_cursor->hash_table_status = HASH_TABLE_STATUS_NOINIT;
    if (sql_cursor->hash_join_ctx != NULL) {
        sql_cursor->hash_join_ctx->key_types = NULL;
        sql_cursor->hash_join_ctx->iter.callback_ctx = NULL;
        sql_cursor->hash_join_ctx->iter.curr_bucket = 0;
        sql_cursor->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
    }
}

void sql_reset_mtrl(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    sql_cursor->mtrl.cursor.rs_page = NULL;
    sql_cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    mtrl_init_mtrl_rowid(&sql_cursor->mtrl.cursor.next_cursor_rid);
    mtrl_init_mtrl_rowid(&sql_cursor->mtrl.cursor.pre_cursor_rid);
    mtrl_init_mtrl_rowid(&sql_cursor->mtrl.cursor.curr_cursor_rid);
    sql_cursor->mtrl.aggr_fetched = OG_FALSE;

    sql_free_hash_ctx(stmt, sql_cursor);

    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.rs.sid);
    sql_cursor->mtrl.rs.buf = NULL;
    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.predicate.sid);

    sql_free_aggr(stmt, sql_cursor);

    sql_free_sort(stmt, sql_cursor);

    sql_free_sibl_sort(stmt, sql_cursor);

    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.group.sid);
    sql_cursor->mtrl.group.buf = NULL;
    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.group_index);
    sql_free_distinct(stmt, sql_cursor);

    sql_free_winsort(stmt, sql_cursor);

    OGSQL_RELEASE_SEGMENT(stmt, sql_cursor->mtrl.for_update);
}

status_t sql_row_put_value(sql_stmt_t *stmt, row_assist_t *row_ass, variant_t *value)
{
    switch (value->type) {
        case OG_TYPE_UINT32:
            return row_put_uint32(row_ass, VALUE(uint32, value));

        case OG_TYPE_INTEGER:
            return row_put_int32(row_ass, VALUE(int32, value));

        case OG_TYPE_BOOLEAN:
            return row_put_bool(row_ass, value->v_bool);

        case OG_TYPE_BIGINT:
            return row_put_int64(row_ass, VALUE(int64, value));

        case OG_TYPE_REAL:
            return row_put_real(row_ass, VALUE(double, value));

        case OG_TYPE_DATE:
            return row_put_date(row_ass, VALUE(date_t, value));

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            return row_put_date(row_ass, VALUE(date_t, value));

        case OG_TYPE_TIMESTAMP_TZ:
            return row_put_timestamp_tz(row_ass, VALUE_PTR(timestamp_tz_t, value));

        case OG_TYPE_INTERVAL_DS:
            return row_put_dsinterval(row_ass, VALUE(interval_ds_t, value));

        case OG_TYPE_INTERVAL_YM:
            return row_put_yminterval(row_ass, VALUE(interval_ym_t, value));

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            return row_put_text(row_ass, VALUE_PTR(text_t, value));

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            return row_put_dec4(row_ass, VALUE_PTR(dec8_t, value));
        case OG_TYPE_NUMBER2:
            return row_put_dec2(row_ass, VALUE_PTR(dec8_t, value));

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            return sql_row_put_lob(stmt, row_ass, g_instance->sql.sql_lob_locator_size, VALUE_PTR(var_lob_t, value));

        case OG_TYPE_ARRAY:
            return sql_row_put_array(stmt, row_ass, &value->v_array);

        case OG_TYPE_BINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_VARBINARY:
            return row_put_bin(row_ass, VALUE_PTR(binary_t, value));
        default:
            OG_THROW_ERROR_EX(ERR_INVALID_DATA_TYPE, "put value, curr type is %s", get_datatype_name_str(value->type));
            return OG_ERROR;
    }
}

status_t sql_put_row_value(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, og_type_t temp_type, variant_t *value)
{
    og_type_t type = temp_type;
    // try make pending column definition when project column
    if (type == OG_TYPE_UNKNOWN) {
        type = sql_make_pending_column_def(stmt, pending_buf, type, ra->col_id, value);
    }

    if (value->is_null) {
        return row_put_null(ra);
    }

    if (value->type == OG_TYPE_VM_ROWID) {
        return row_put_vmid(ra, &value->v_vmid);
    }

    if (value->type != type && value->type != OG_TYPE_ARRAY) {
        OG_RETURN_IFERR(sql_convert_variant(stmt, value, type));
    }

    return sql_row_put_value(stmt, ra, value);
}

static inline status_t sql_convert_row_value(sql_stmt_t *stmt, variant_t *value, og_type_t type)
{
    if (value->type == type || value->type == OG_TYPE_ARRAY) {
        return OG_SUCCESS;
    }
    return sql_convert_variant(stmt, value, type);
}

status_t sql_set_row_value(sql_stmt_t *stmt, row_assist_t *row_ass, og_type_t type, variant_t *value, uint32 col_id)
{
    // The OG_TYPE_LOGIC_TRUE indicates that the result set is empty in ALL(xxx) conditon, which different from NULL.
    if (value->is_null || value->type == OG_TYPE_LOGIC_TRUE) {
        return row_set_null(row_ass, col_id);
    }

    OG_RETURN_IFERR(sql_convert_row_value(stmt, value, type));
    switch (value->type) {
        case OG_TYPE_UINT32:
            return row_set_uint32(row_ass, VALUE(uint32, value), col_id);

        case OG_TYPE_INTEGER:
            return row_set_int32(row_ass, VALUE(int32, value), col_id);

        case OG_TYPE_BOOLEAN:
            return row_set_bool(row_ass, value->v_bool, col_id);

        case OG_TYPE_BIGINT:
            return row_set_int64(row_ass, VALUE(int64, value), col_id);

        case OG_TYPE_REAL:
            return row_set_real(row_ass, VALUE(double, value), col_id);

        case OG_TYPE_DATE:
            return row_set_date(row_ass, VALUE(date_t, value), col_id);

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            return row_set_date(row_ass, VALUE(date_t, value), col_id);

        case OG_TYPE_TIMESTAMP_TZ:
            return row_set_timestamp_tz(row_ass, VALUE_PTR(timestamp_tz_t, value), col_id);

        case OG_TYPE_INTERVAL_DS:
            return row_set_dsinterval(row_ass, VALUE(interval_ds_t, value), col_id);

        case OG_TYPE_INTERVAL_YM:
            return row_set_yminterval(row_ass, VALUE(interval_ym_t, value), col_id);

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            return row_set_text(row_ass, VALUE_PTR(text_t, value), col_id);

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            return row_set_dec4(row_ass, VALUE_PTR(dec8_t, value), col_id);
        case OG_TYPE_NUMBER2:
            return row_set_dec2(row_ass, VALUE_PTR(dec8_t, value), col_id);
        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            return sql_row_set_lob(stmt, row_ass, g_instance->sql.sql_lob_locator_size, VALUE_PTR(var_lob_t, value),
                col_id);

        case OG_TYPE_ARRAY:
            return sql_row_set_array(stmt, row_ass, value, col_id);

        case OG_TYPE_BINARY:
        case OG_TYPE_RAW:
        default:
            return row_set_bin(row_ass, VALUE_PTR(binary_t, value), col_id);
    }
}

static inline void sql_set_table_rowid(sql_stmt_t *stmt, row_assist_t *ra, sql_table_t *table)
{
    sql_cursor_t *cursor = NULL;
    sql_table_cursor_t *tab_cursor = NULL;

    if (table->type != NORMAL_TABLE) {
        return;
    }
    cursor = OGSQL_CURR_CURSOR(stmt);
    tab_cursor = &cursor->tables[table->id];
    if (tab_cursor->knl_cur->eof) {
        tab_cursor->knl_cur->rowid = INVALID_ROWID;
    }
    *(rowid_t *)(ra->buf + ra->head->size) = tab_cursor->knl_cur->rowid;
    ra->head->size += KNL_ROWID_LEN;
}

static status_t sql_make_mtrl_rs_one_row(sql_stmt_t *stmt, char *pending_buf, row_assist_t *ra, rs_column_t *rs_col)
{
    variant_t value;

    switch (rs_col->type) {
        case RS_COL_COLUMN:
            if (sql_get_table_value(stmt, &rs_col->v_col, &value) != OG_SUCCESS) {
                return OG_ERROR;
            }
            return sql_put_row_value(stmt, pending_buf, ra, rs_col->datatype, &value);

        default:
            if (sql_exec_expr(stmt, rs_col->expr, &value) != OG_SUCCESS) {
                return OG_ERROR;
            }
            return sql_put_row_value(stmt, pending_buf, ra, rs_col->datatype, &value);
    }
}

static inline status_t sql_sql_exec_win_border_expr(sql_stmt_t *stmt, expr_tree_t *expr, og_type_t sort_type,
    variant_t *value, bool32 is_range)
{
    OG_RETURN_IFERR(sql_exec_expr(stmt, expr, value));
    if (value->is_null) {
        OG_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be NULL");
        return OG_ERROR;
    }
    if (!is_range || !OG_IS_DATETIME_TYPE(sort_type) ||
        (!OG_IS_DSITVL_TYPE(expr->root->datatype) && !OG_IS_YMITVL_TYPE(expr->root->datatype))) {
        OG_RETURN_IFERR(var_as_num(value));
    }
    if (var_is_negative(value)) {
        OG_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be negative");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_make_mtrl_winsort_row(sql_stmt_t *stmt, winsort_args_t *args, mtrl_rowid_t *rid, char *buf,
    char *pending_buf)
{
    uint32 i;
    expr_tree_t *expr = NULL;
    sort_item_t *item = NULL;
    variant_t value;
    row_assist_t ra;

    row_init(&ra, buf, OG_MAX_ROW_SIZE, args->sort_columns);

    if (args->group_exprs != NULL) {
        for (i = 0; i < args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(args->group_exprs, i);
            OG_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
            OG_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr->root->datatype, &value));
        }
    }

    if (args->sort_items != NULL) {
        OG_RETURN_IFERR(sql_make_mtrl_sort_row(stmt, pending_buf, args->sort_items, &ra));
        if (args->windowing != NULL) {
            item = (sort_item_t *)cm_galist_get(args->sort_items, args->sort_items->count - 1);
            if (args->windowing->l_expr != NULL && !TREE_IS_CONST(args->windowing->l_expr)) {
                OG_RETURN_IFERR(sql_sql_exec_win_border_expr(stmt, args->windowing->l_expr, item->expr->root->datatype,
                    &value, args->windowing->is_range));
                OG_RETURN_IFERR(
                    sql_put_row_value(stmt, pending_buf, &ra, args->windowing->l_expr->root->datatype, &value));
            }
            if (args->windowing->r_expr != NULL && !TREE_IS_CONST(args->windowing->r_expr)) {
                OG_RETURN_IFERR(sql_sql_exec_win_border_expr(stmt, args->windowing->r_expr, item->expr->root->datatype,
                    &value, args->windowing->is_range));
                OG_RETURN_IFERR(
                    sql_put_row_value(stmt, pending_buf, &ra, args->windowing->r_expr->root->datatype, &value));
            }
        }
    }

    if (ra.head->size + sizeof(mtrl_rowid_t) > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(mtrl_rowid_t), OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    *(mtrl_rowid_t *)(buf + ra.head->size) = *rid;
    ra.head->size += sizeof(mtrl_rowid_t);

    return OG_SUCCESS;
}

status_t sql_make_mtrl_rs_row(sql_stmt_t *stmt, char *pending_buf, galist_t *columns, char *buf)
{
    rs_column_t *rs_col = NULL;
    row_assist_t ra;

    row_init(&ra, buf, OG_MAX_ROW_SIZE, columns->count);

    for (uint32 i = 0; i < columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(columns, i);
        if (sql_make_mtrl_rs_one_row(stmt, pending_buf, &ra, rs_col) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static inline og_type_t og_convert_unknown_row(sql_stmt_t *statement, char *row_buf, og_type_t temp_type, uint32 col_id,
    variant_t *var)
{
    if (temp_type == OG_TYPE_UNKNOWN) {
        return sql_make_pending_column_def(statement, row_buf, temp_type, col_id, var);
    }
    return temp_type;
}

static inline og_type_t og_convert_lob_row(og_type_t temp_type)
{
    if (OG_IS_LOB_TYPE(temp_type)) {
        if (temp_type == OG_TYPE_BLOB) {
            return OG_TYPE_RAW;
        }
        return OG_TYPE_STRING;
    }
    return temp_type;
}

static inline status_t og_put_select_sort_row(sql_stmt_t *statement, char *row_buf, row_assist_t *row_ast,
    og_type_t temp_type, variant_t *var)
{
    CM_POINTER4(statement, row_buf, row_ast, var);
    if (OG_IS_LOB_TYPE(var->type) && sql_get_lob_value(statement, var) != OG_SUCCESS) {
        return OG_ERROR;
    }
    temp_type = og_convert_unknown_row(statement, row_buf, temp_type, row_ast->col_id, var);
    temp_type = og_convert_lob_row(temp_type);
    return sql_put_row_value(statement, row_buf, row_ast, temp_type, var);
}

status_t sql_make_mtrl_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, row_assist_t *ra)
{
    sort_item_t *item = NULL;
    variant_t value;
    expr_tree_t *expr = NULL;

    OGSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(sort_items, i);
        expr = item->expr;

        OG_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));

        if (!value.is_null && value.type >= OG_TYPE_OPERAND_CEIL) {
            OG_THROW_ERROR(ERR_INVALID_DATA_TYPE, "unexpected user define type");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(og_put_select_sort_row(stmt, pending_buf, ra, expr->root->datatype, &value));
        OGSQL_RESTORE_STACK(stmt);
    }
    return OG_SUCCESS;
}

status_t sql_make_mtrl_query_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, mtrl_rowid_t *rid,
    char *buf)
{
    row_assist_t ra;

    row_init(&ra, buf, OG_MAX_ROW_SIZE, sort_items->count);

    if (sql_make_mtrl_sort_row(stmt, pending_buf, sort_items, &ra) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ra.head->size + sizeof(mtrl_rowid_t) > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(mtrl_rowid_t), OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    *(mtrl_rowid_t *)(buf + ra.head->size) = *rid;
    ra.head->size += sizeof(mtrl_rowid_t);
    return OG_SUCCESS;
}

status_t sql_make_mtrl_select_sort_row(sql_stmt_t *stmt, char *pending_buf, sql_cursor_t *cursor, galist_t *sort_items,
    mtrl_rowid_t *rid, char *buf)
{
    uint32 i;
    select_sort_item_t *item = NULL;
    rs_column_t *rs_column = NULL;
    row_assist_t ra;
    variant_t value = {0};

    row_init(&ra, buf, OG_MAX_ROW_SIZE, sort_items->count);

    for (i = 0; i < sort_items->count; i++) {
        item = (select_sort_item_t *)cm_galist_get(sort_items, i);
        rs_column = (rs_column_t *)cm_galist_get(cursor->columns, item->rs_columns_id);
        if (rs_column->type == RS_COL_CALC) {
            OG_RETURN_IFERR(sql_exec_expr(stmt, rs_column->expr, &value));
        } else {
            OG_RETURN_IFERR(sql_get_table_value(stmt, &rs_column->v_col, &value));
        }
        OG_RETURN_IFERR(og_put_select_sort_row(stmt, pending_buf, &ra, rs_column->datatype, &value));
    }

    if (ra.head->size + sizeof(mtrl_rowid_t) > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(mtrl_rowid_t), OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    *(mtrl_rowid_t *)(buf + ra.head->size) = *rid;
    ra.head->size += sizeof(mtrl_rowid_t);

    return OG_SUCCESS;
}

status_t sql_make_mtrl_sibl_sort_row(sql_stmt_t *stmt, char *pending_buf, galist_t *sort_items, char *buf,
    sibl_sort_row_t *sibl_sort_row)
{
    row_assist_t ra;

    row_init(&ra, buf, OG_MAX_ROW_SIZE, sort_items->count);

    if (sql_make_mtrl_sort_row(stmt, pending_buf, sort_items, &ra) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ra.head->size + sizeof(sibl_sort_row_t) > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ra.head->size + sizeof(sibl_sort_row_t), OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    *(sibl_sort_row_t *)(buf + ra.head->size) = *sibl_sort_row;
    ra.head->size += sizeof(sibl_sort_row_t);
    return OG_SUCCESS;
}

status_t sql_make_mtrl_group_row(sql_stmt_t *stmt, char *pending_buf, group_plan_t *group_p, char *buf)
{
    uint32 i;
    expr_node_t *expr_node = NULL;
    variant_t value;
    variant_t var[FO_VAL_MAX - 1];
    row_assist_t ra;

    uint32 column_count =
        group_p->exprs->count + group_p->aggrs_args + group_p->cntdis_columns->count + group_p->aggrs_sorts;
    row_init(&ra, buf, OG_MAX_ROW_SIZE, column_count);

    for (i = 0; i < group_p->exprs->count; i++) {
        expr_tree_t *expr = (expr_tree_t *)cm_galist_get(group_p->exprs, i);
        OG_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        OG_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr->root->datatype, &value));
    }

    for (i = 0; i < group_p->aggrs->count; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_p->aggrs, i);
        const sql_func_t *func = sql_get_func(&expr_node->value.v_func);
        OG_RETURN_IFERR(sql_exec_expr_node(stmt, expr_node, var));
        for (uint32 j = 0; j < func->value_cnt; j++) {
            OG_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr_node->datatype, &var[j]));
        }
    }

    for (i = 0; i < group_p->cntdis_columns->count; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_p->cntdis_columns, i);
        OG_RETURN_IFERR(sql_exec_expr_node(stmt, expr_node, &value));
        OG_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr_node->datatype, &value));
    }

    for (i = 0; i < group_p->aggrs_sorts; i++) {
        expr_node = (expr_node_t *)cm_galist_get(group_p->sort_items, i);
        OG_RETURN_IFERR(sql_exec_expr_node(stmt, expr_node, &value));
        OG_RETURN_IFERR(sql_put_row_value(stmt, pending_buf, &ra, expr_node->datatype, &value));
    }

    return OG_SUCCESS;
}

status_t sql_inherit_pending_buf(sql_cursor_t *cursor, sql_cursor_t *sub_cursor)
{
    uint32 mem_size;
    if (cursor->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)cursor->mtrl.rs.buf;
        OG_RETURN_IFERR(vmc_alloc(&sub_cursor->vmc, mem_size, (void **)&sub_cursor->mtrl.rs.buf));
        MEMS_RETURN_IFERR(memcpy_s(sub_cursor->mtrl.rs.buf, mem_size, cursor->mtrl.rs.buf, mem_size));
    }
    return OG_SUCCESS;
}

status_t sql_revert_pending_buf(sql_cursor_t *cursor, sql_cursor_t *sub_cursor)
{
    uint32 mem_size;
    if (cursor->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)cursor->mtrl.rs.buf;
        MEMS_RETURN_IFERR(memcpy_s(cursor->mtrl.rs.buf, mem_size, sub_cursor->mtrl.rs.buf, mem_size));
    } else if (sub_cursor->mtrl.rs.buf != NULL) {
        mem_size = *(uint32 *)sub_cursor->mtrl.rs.buf;
        OG_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_size, (void **)&cursor->mtrl.rs.buf));
        MEMS_RETURN_IFERR(memcpy_s(cursor->mtrl.rs.buf, mem_size, sub_cursor->mtrl.rs.buf, mem_size));
    }
    return OG_SUCCESS;
}

status_t sql_materialize_base(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_cursor_t *sub_cursor = NULL;
    char *buf = NULL;
    mtrl_rowid_t rid;
    status_t ret = OG_SUCCESS;

    OG_RETURN_IFERR(sql_alloc_cursor(stmt, &sub_cursor));
    sub_cursor->scn = cursor->scn;
    sub_cursor->ancestor_ref = cursor->ancestor_ref;

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sub_cursor));

    if (sql_execute_select_plan(stmt, sub_cursor, plan) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        sql_free_cursor(stmt, sub_cursor);
        return OG_ERROR;
    }

    // rs datatype depends on the first query
    OG_RETURN_IFERR(sql_inherit_pending_buf(cursor, sub_cursor));

    if (sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        sql_free_cursor(stmt, sub_cursor);
        return OG_ERROR;
    }

    for (;;) {
        OGSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, plan, &sub_cursor->eof) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            ret = OG_ERROR;
            break;
        }

        if (sub_cursor->eof) {
            OGSQL_RESTORE_STACK(stmt);
            break;
        }

        if (sql_make_mtrl_rs_row(stmt, sub_cursor->mtrl.rs.buf, sub_cursor->columns, buf) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            ret = OG_ERROR;
            break;
        }

        if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &rid) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            ret = OG_ERROR;
            break;
        }
        OGSQL_RESTORE_STACK(stmt);
    }

    OGSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);

    OG_RETURN_IFERR(sql_revert_pending_buf(cursor, sub_cursor));

    sql_free_cursor(stmt, sub_cursor);
    return ret;
}

static void sql_set_col_info(var_column_t *var_col, query_field_t *query_field)
{
    var_col->col = query_field->col_id;
    var_col->col_info_ptr->col_pro_id = query_field->pro_id;
    var_col->datatype = query_field->datatype;
    if (!QUERY_FIELD_IS_ELEMENT(query_field)) {
        var_col->is_array = query_field->is_array;
        var_col->ss_start = query_field->start;
        var_col->ss_end = query_field->end;
    } else {
        var_col->is_array = OG_TRUE;
        var_col->ss_start = (int32)OG_INVALID_ID32;
        var_col->ss_end = (int32)OG_INVALID_ID32;
    }
}

static status_t sql_set_pending_buf_coltype(sql_stmt_t *stmt, sql_cursor_t *sql_cur, char **pending_buf,
    var_column_t v_col)
{
    uint32 mem_cost_size;
    og_type_t *types = NULL;

    if (*pending_buf == NULL) {
        mem_cost_size = PENDING_HEAD_SIZE + sql_cur->columns->count * sizeof(og_type_t);
        OG_RETURN_IFERR(vmc_alloc(&sql_cur->vmc, mem_cost_size, (void **)pending_buf));
        *(uint32 *)*pending_buf = mem_cost_size;
    }
    types = (og_type_t *)(*pending_buf + PENDING_HEAD_SIZE);
    types[v_col.col] = v_col.datatype;

    return OG_SUCCESS;
}

static status_t sql_make_mtrl_merge_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *table_curs,
    sql_table_t *table, char *buf, uint32 buf_size)
{
    variant_t value;
    row_assist_t row_ass;
    var_column_t var_col;
    column_info_t col_info;
    bilist_node_t *node = NULL;
    query_field_t *query_field = NULL;
    og_type_t rs_type;
    sql_cursor_t *sql_cur = NULL;
    char **pending_buf = NULL;

    var_col.tab = table->id;
    var_col.ancestor = 0;
    var_col.is_array = 0;
    var_col.col_info_ptr = &col_info;

    if (table->query_fields.count == 0) {
        row_init(&row_ass, buf, buf_size, 1);
    } else {
        node = cm_bilist_tail(&table->query_fields);
        query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
        row_init(&row_ass, buf, buf_size, query_field->col_id + 1);

        node = cm_bilist_head(&table->query_fields);
        for (; node != NULL; node = BINODE_NEXT(node)) {
            query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
            sql_set_col_info(&var_col, query_field);
            rs_type = (query_field->datatype == OG_TYPE_UNKNOWN) ? OG_TYPE_STRING : query_field->datatype;
            sql_cur = table_curs[table->id].sql_cur;

            if (table->type != FUNC_AS_TABLE) {
                OG_RETURN_IFERR(sql_get_table_value(stmt, &var_col, &value));
            } else {
                OG_RETURN_IFERR(sql_get_kernel_value(stmt, table, cursor->tables[table->id].knl_cur, &var_col, &value));
            }

            if (query_field->datatype == OG_TYPE_UNKNOWN && sql_cur != NULL &&
                (table->type == SUBSELECT_AS_TABLE || table->type == VIEW_AS_TABLE)) {
                pending_buf = &sql_cur->mtrl.rs.buf;
                OG_RETURN_IFERR(sql_set_pending_buf_coltype(stmt, sql_cur, pending_buf, var_col));
                rs_type = sql_make_pending_column_def(stmt, *pending_buf, rs_type, var_col.col, &value);
            }
            OG_RETURN_IFERR(sql_set_row_value(stmt, &row_ass, rs_type, &value, var_col.col));
        }
    }
    sql_set_table_rowid(stmt, &row_ass, table);
    return OG_SUCCESS;
}

static status_t sql_mtrl_insert_merge_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, join_info_t *merge_join,
    row_assist_t *key_ra, char *key_buf)
{
    char *buf = NULL;
    mtrl_rowid_t mtrl_rid;
    sql_table_t *table = NULL;

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE + KNL_ROWID_LEN + REMOTE_ROWNODEID_LEN, (void **)&buf));

    for (int32 i = (int32)merge_join->rs_tables.count - 1; i >= 0; --i) {
        table = (sql_table_t *)sql_array_get(&merge_join->rs_tables, i);
        if (table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
            if (sql_make_mtrl_merge_rs_row(stmt, cursor, cursor->tables, table, buf, OG_MAX_ROW_SIZE) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.rs.sid, buf, &mtrl_rid) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
        } else {
            if (sql_make_mtrl_null_rs_row(&stmt->mtrl, cursor->mtrl.rs.sid, &mtrl_rid) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
        }
        if (key_ra->head->size + sizeof(mtrl_rowid_t) > OG_MAX_ROW_SIZE) {
            OGSQL_POP(stmt);
            OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, key_ra->head->size + sizeof(mtrl_rowid_t), OG_MAX_ROW_SIZE);
            return OG_ERROR;
        }
        *(mtrl_rowid_t *)(key_buf + key_ra->head->size) = mtrl_rid;
        key_ra->head->size += sizeof(mtrl_rowid_t);
    }
    OGSQL_POP(stmt);
    return OG_SUCCESS;
}

status_t sql_mtrl_merge_sort_insert(sql_stmt_t *stmt, sql_cursor_t *cursor, join_info_t *merge_join)
{
    char *key_buffer = NULL;
    row_assist_t key_ra;
    mtrl_rowid_t mtrl_rid;
    status_t status = OG_ERROR;

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&key_buffer));
    row_init(&key_ra, key_buffer, OG_MAX_ROW_SIZE, merge_join->key_items->count);

    do {
        OG_BREAK_IF_ERROR(sql_make_mtrl_sort_row(stmt, NULL, merge_join->key_items, &key_ra));

        OG_BREAK_IF_ERROR(sql_mtrl_insert_merge_rs_row(stmt, cursor, merge_join, &key_ra, key_buffer));

        OG_BREAK_IF_ERROR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.sort.sid, key_buffer, &mtrl_rid));

        status = OG_SUCCESS;
    } while (OG_FALSE);
    OGSQL_POP(stmt);
    return status;
}

status_t sql_make_mtrl_table_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *table_curs,
    sql_table_t *table, char *buf, uint32 buf_size)
{
    return sql_make_mtrl_merge_rs_row(stmt, cursor, table_curs, table, buf, buf_size);
}

status_t sql_alloc_mem_from_seg(sql_stmt_t *stmt, mtrl_segment_t *seg, uint32 size, void **buf, mtrl_rowid_t *rid)
{
    mtrl_page_t *page = (mtrl_page_t *)seg->curr_page->data;

    if (page->id != seg->vm_list.last) {
        mtrl_close_segment2(&stmt->mtrl, seg);
        OG_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page));
        page = (mtrl_page_t *)seg->curr_page->data;
    }

    if (page->free_begin + size > OG_VMEM_PAGE_SIZE) {
        mtrl_close_segment2(&stmt->mtrl, seg);
        if (mtrl_extend_segment(&stmt->mtrl, seg) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (mtrl_open_page(&stmt->mtrl, seg->vm_list.last, &seg->curr_page) != OG_SUCCESS) {
            return OG_ERROR;
        }
        page = (mtrl_page_t *)seg->curr_page->data;
        mtrl_init_page(page, seg->vm_list.last);
    }
    rid->vmid = seg->vm_list.last;

    *buf = ((char *)page + page->free_begin);
    rid->slot = page->rows;
    page->rows++;
    page->free_begin += size;

    return OG_SUCCESS;
}

status_t sql_alloc_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_segment_t **seg, mtrl_rowid_t *mtrl_rid)
{
    return sql_alloc_mem_from_seg(stmt, stmt->mtrl.segments[seg_id], sizeof(mtrl_segment_t), (void **)seg, mtrl_rid);
}

static status_t sql_get_mem_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_rowid_t *rid, uint32 row_size, void **buf)
{
    uint32 offset;
    mtrl_segment_t *seg = stmt->mtrl.segments[seg_id];
    mtrl_page_t *page = NULL;

    if (rid->vmid != seg->curr_page->vmid) {
        mtrl_close_page(&stmt->mtrl, seg->curr_page->vmid);
        seg->curr_page = NULL;
        OG_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, rid->vmid, &seg->curr_page));
    }
    page = (mtrl_page_t *)seg->curr_page->data;
    offset = sizeof(mtrl_page_t) + rid->slot * row_size;
    *buf = (char *)page + offset;
    return OG_SUCCESS;
}

status_t sql_get_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id, mtrl_rowid_t *rid, mtrl_segment_t **mtrl_seg)
{
    return sql_get_mem_in_vm(stmt, seg_id, rid, sizeof(mtrl_segment_t), (void **)mtrl_seg);
}

status_t sql_get_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *rid, mtrl_cursor_t **mtrl_cursor)
{
    if (rid->vmid == OG_INVALID_ID32) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(
        sql_get_mem_in_vm(stmt, cursor->mtrl.sibl_sort.cursor_sid, rid, sizeof(mtrl_cursor_t), (void **)mtrl_cursor));
    return OG_SUCCESS;
}

static void sql_free_segment_in_page(mtrl_context_t *mtrl, uint32 vmid)
{
    uint32 free_begin;
    vm_page_t *curr_page = NULL;
    mtrl_page_t *mtrl_page = NULL;
    mtrl_segment_t *seg = NULL;

    if (mtrl_open_page(mtrl, vmid, &curr_page) != OG_SUCCESS) {
        return;
    }
    mtrl_page = (mtrl_page_t *)curr_page->data;

    if (mtrl_page->rows == 0) {
        mtrl_close_page(mtrl, vmid);
        return;
    }

    free_begin = sizeof(mtrl_page_t);
    for (uint32 i = 0; i < mtrl_page->rows; ++i) {
        seg = (mtrl_segment_t *)((char *)mtrl_page + free_begin);
        if (seg->vm_list.count != 0) {
            vm_free_list(mtrl->session, mtrl->pool, &seg->vm_list);
        }
        free_begin += sizeof(mtrl_segment_t);
    }
    mtrl_init_page(mtrl_page, vmid);
    mtrl_close_page(mtrl, vmid);
}

void sql_free_segment_in_vm(sql_stmt_t *stmt, uint32 seg_id)
{
    uint32 id;
    uint32 next;
    vm_ctrl_t *vm_ctrl = NULL;
    mtrl_segment_t *seg = stmt->mtrl.segments[seg_id];

    if (seg->vm_list.count == 0) {
        return;
    }

    id = seg->vm_list.first;

    while (id != OG_INVALID_ID32) {
        vm_ctrl = vm_get_ctrl(stmt->mtrl.pool, id);
        next = vm_ctrl->next;
        sql_free_segment_in_page(&stmt->mtrl, id);
        id = next;
    }
}

status_t sql_free_mtrl_cursor_in_vm(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    mtrl_cursor_t *curr_cur = NULL;
    mtrl_cursor_t *pre_cur = NULL;
    mtrl_cursor_t *next_cur = NULL;
    mtrl_rowid_t pre_rid;
    mtrl_rowid_t next_rid;
    OG_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &cursor->mtrl.cursor.curr_cursor_rid, &curr_cur));
    if (curr_cur != NULL) {
        next_rid = curr_cur->next_cursor_rid;
        pre_rid = curr_cur->pre_cursor_rid;
        OG_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &next_rid, &next_cur));
        OG_RETURN_IFERR(sql_get_mtrl_cursor(stmt, cursor, &pre_rid, &pre_cur));
        mtrl_close_cursor(&stmt->mtrl, curr_cur);
        if (next_cur != NULL) {
            mtrl_close_cursor(&stmt->mtrl, next_cur);
        }
        if (pre_cur != NULL) {
            mtrl_close_cursor(&stmt->mtrl, pre_cur);
        }
    }
    return OG_SUCCESS;
}

void sql_free_sibl_sort(sql_stmt_t *stmt, sql_cursor_t *sql_cursor)
{
    if (sql_cursor->mtrl.sibl_sort.cursor_sid != OG_INVALID_ID32) {
        (void)sql_free_mtrl_cursor_in_vm(stmt, sql_cursor);
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.cursor_sid);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.cursor_sid);
        sql_cursor->mtrl.sibl_sort.cursor_sid = OG_INVALID_ID32;
    }
    if (sql_cursor->mtrl.sibl_sort.sid != OG_INVALID_ID32) {
        mtrl_close_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.sid);
        sql_free_segment_in_vm(stmt, sql_cursor->mtrl.sibl_sort.sid);
        mtrl_release_segment(&stmt->mtrl, sql_cursor->mtrl.sibl_sort.sid);
        sql_cursor->mtrl.sibl_sort.sid = OG_INVALID_ID32;
    }
}

status_t sql_set_segment_pages_hold(mtrl_context_t *ogx, uint32 seg_id, uint32 pages_hold)
{
    vm_page_t *page = NULL;
    mtrl_segment_t *seg = ogx->segments[seg_id];

    seg->pages_hold = pages_hold;

    if (seg->vm_list.count < seg->pages_hold) {
        return vm_open(ogx->session, ogx->pool, seg->vm_list.last, &page);
    }
    return OG_SUCCESS;
}

static inline int32 sql_compare_expr_loc(source_location_t location1, source_location_t location2)
{
    if (location1.line != location2.line) {
        return (location1.line > location2.line) ? 1 : -1;
    } else {
        return (location1.column > location2.column) ? 1 : -1;
    }
}

status_t sql_get_hash_key_types(sql_stmt_t *stmt, sql_query_t *query, galist_t *local_keys, galist_t *peer_keys,
    og_type_t *key_types)
{
    expr_tree_t *local_expr = NULL;
    expr_tree_t *peer_expr = NULL;
    og_type_t local_type;
    og_type_t peer_type;
    og_type_t dst_type;

    CM_ASSERT(query != NULL);

    for (uint32 i = 0; i < local_keys->count; i++) {
        local_expr = (expr_tree_t *)cm_galist_get(local_keys, i);
        peer_expr = (expr_tree_t *)cm_galist_get(peer_keys, i);
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, local_expr->root, &local_type));
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, peer_expr->root, &peer_type));
        dst_type = get_cmp_datatype(local_type, peer_type);
        if (dst_type == INVALID_CMP_DATATYPE) {
            if (sql_compare_expr_loc(local_expr->root->loc, peer_expr->root->loc) < 0) {
                OG_SRC_ERROR_MISMATCH(peer_expr->root->loc, local_type, peer_type);
            } else {
                OG_SRC_ERROR_MISMATCH(local_expr->root->loc, peer_type, local_type);
            }
            return OG_ERROR;
        }
        key_types[i] = dst_type;
    }
    return OG_SUCCESS;
}

status_t sql_make_hash_key(sql_stmt_t *stmt, row_assist_t *ra, char *buf, galist_t *local_keys, og_type_t *types,
    bool32 *has_null)
{
    variant_t value;
    expr_tree_t *local_expr = NULL;

    row_init(ra, buf, OG_MAX_ROW_SIZE, local_keys->count);

    for (uint32 i = 0; i < local_keys->count; i++) {
        local_expr = (expr_tree_t *)cm_galist_get(local_keys, i);
        OG_RETURN_IFERR(sql_exec_expr(stmt, local_expr, &value));
        if (OG_IS_LOB_TYPE(value.type)) {
            OG_RETURN_IFERR(sql_get_lob_value(stmt, &value));
        }
        if (value.is_null) {
            *has_null = OG_TRUE;
            return OG_SUCCESS;
        }
        if (types[i] == OG_TYPE_CHAR) {
            cm_rtrim_text(&value.v_text);
        }
        OG_RETURN_IFERR(sql_put_row_value(stmt, NULL, ra, types[i], &value));
    }

    *has_null = OG_FALSE;
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
