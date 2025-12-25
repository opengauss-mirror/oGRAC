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
 * ogsql_aggr.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_aggr.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_aggr.h"
#include "ogsql_select.h"
#include "ogsql_proj.h"
#include "ogsql_mtrl.h"
#include "ogsql_group.h"
#include "knl_mtrl.h"
#include "ogsql_scan.h"
#include "ogsql_sort.h"

#ifdef OG_RAC_ING
#include "srv_instance.h"
#include "shd_group.h"
#endif // OG_RAC_ING

static status_t sql_mtrl_aggr_page_alloc(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 size, void **result);


static inline status_t sql_aggr_alloc(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 size, char **buffer)
{
    mtrl_context_t *ogx = &stmt->mtrl;
    mtrl_segment_t *segment = ogx->segments[cursor->mtrl.aggr];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (size > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, size, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    if (page->free_begin + size + sizeof(uint32) > OG_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        if (mtrl_extend_segment(ogx, segment) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (mtrl_open_page(ogx, segment->vm_list.last, &segment->curr_page) != OG_SUCCESS) {
            return OG_ERROR;
        }

        page = (mtrl_page_t *)segment->curr_page->data;
        mtrl_init_page(page, segment->vm_list.last);
    }

    *buffer = (char *)page + page->free_begin;
    page->free_begin += size;

    return OG_SUCCESS;
}

static inline status_t sql_copy_aggr_value_by_string(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *value,
    aggr_var_t *result)
{
    if (value->v_text.len == 0) {
        return OG_SUCCESS;
    }

    if (value->v_text.len > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, value->v_text.len, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(result);

    if (value->v_text.len > aggr_str->aggr_bufsize) {
        aggr_str->aggr_bufsize = MAX(aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR, value->v_text.len);
        OG_RETURN_IFERR(sql_aggr_alloc(stmt, cursor, aggr_str->aggr_bufsize, &result->var.v_text.str));
    }
    MEMS_RETURN_IFERR(memcpy_s(result->var.v_text.str, aggr_str->aggr_bufsize, value->v_text.str, value->v_text.len));
    result->var.v_text.len = value->v_text.len;

    return OG_SUCCESS;
}

static inline status_t sql_copy_aggr_value_by_binary(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *value,
    aggr_var_t *result)
{
    if (value->v_bin.size == 0) {
        return OG_SUCCESS;
    }

    if (value->v_bin.size > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, value->v_bin.size, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(result);

    if (aggr_str == NULL) {
        OG_THROW_ERROR(ERR_ASSERT_ERROR, "aggr_str != NULL");
        return OG_ERROR;
    }

    if (value->v_bin.size > aggr_str->aggr_bufsize) {
        aggr_str->aggr_bufsize = MAX(aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR, value->v_bin.size);
        OG_RETURN_IFERR(sql_aggr_alloc(stmt, cursor, aggr_str->aggr_bufsize, (char **)&result->var.v_bin.bytes));
    }
    MEMS_RETURN_IFERR(memcpy_s(result->var.v_bin.bytes, aggr_str->aggr_bufsize, value->v_bin.bytes, value->v_bin.size));
    result->var.v_bin.size = value->v_bin.size;

    return OG_SUCCESS;
}

static inline status_t sql_copy_aggr_value(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *value, aggr_var_t *result)
{
    switch (result->var.type) {
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
            result->var.ctrl = value->ctrl;
            cm_dec_copy(&result->var.v_dec, &value->v_dec);
            return OG_SUCCESS;
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_REAL:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_BOOLEAN:
            var_copy(value, &result->var);
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            return sql_copy_aggr_value_by_string(stmt, cursor, value, result);

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            return sql_copy_aggr_value_by_binary(stmt, cursor, value, result);

        default:
            OG_SET_ERROR_MISMATCH_EX(result->var.type);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_aggr_get_value_from_vm(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    bool32 keep_old_open)
{
    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);
    mtrl_rowid_t *rid = &aggr_str->str_result;
    mtrl_segment_t *segment = stmt->mtrl.segments[cursor->mtrl.aggr_str];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (rid->vmid != OG_INVALID_ID32) {
        if (page != NULL && page->id != rid->vmid) {
            if (!keep_old_open) {
                mtrl_close_page(&stmt->mtrl, page->id);
                segment->curr_page = NULL;
            }
            page = NULL;
        }
        if (page == NULL) {
            OG_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, rid->vmid, &segment->curr_page));
            page = (mtrl_page_t *)segment->curr_page->data;
        }
        aggr_var->var.v_text.str = MTRL_GET_ROW(page, rid->slot) + sizeof(row_head_t) + sizeof(uint16);
    }
    return OG_SUCCESS;
}

static status_t sql_aggr_ensure_str_buf(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    uint32 ensure_size, bool32 keep_value)
{
    char *buf = NULL;
    mtrl_rowid_t rid;
    uint32 rsv_size;
    uint32 row_size;

    if (ensure_size > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ensure_size, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);

    if (ensure_size <= aggr_str->aggr_bufsize) {
        return OG_SUCCESS;
    }

    if (cursor->mtrl.aggr_str == OG_INVALID_ID32) {
        OG_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_EXTRA_DATA, NULL, &cursor->mtrl.aggr_str));
        OG_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr_str));
    }

    rsv_size = MAX(SQL_GROUP_CONCAT_STR_LEN, aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR);
    rsv_size = MAX(rsv_size, ensure_size);
    rsv_size = MIN(rsv_size, OG_MAX_ROW_SIZE);

    OG_RETURN_IFERR(sql_push(stmt, (uint32)(OG_MAX_ROW_SIZE + sizeof(row_head_t) + sizeof(uint16)), (void **)&buf));
    row_head_t *head = (row_head_t *)buf;
    head->flags = 0;
    head->itl_id = OG_INVALID_ID8;
    head->column_count = (uint16)1;
    row_size = rsv_size + sizeof(row_head_t) + sizeof(uint16);
    head->size = row_size;

    if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.aggr_str, buf, &rid) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    OGSQL_POP(stmt);

    if (keep_value && !aggr_var->var.is_null && aggr_var->var.v_text.len > 0) {
        // read old value from vm
        uint32 old_vmid = aggr_str->str_result.vmid;
        OG_RETURN_IFERR(sql_aggr_get_value_from_vm(stmt, cursor, aggr_var, OG_FALSE));
        variant_t old_var = aggr_var->var;
        // save new value to vm, keep the old page open
        aggr_str->str_result = rid;
        OG_RETURN_IFERR(sql_aggr_get_value_from_vm(stmt, cursor, aggr_var, OG_TRUE));
        MEMS_RETURN_IFERR(memcpy_s(aggr_var->var.v_text.str, rsv_size, old_var.v_text.str, old_var.v_text.len));
        if (old_vmid != rid.vmid && old_vmid != OG_INVALID_ID32) {
            mtrl_close_page(&stmt->mtrl, old_vmid);
        }
    } else {
        aggr_str->str_result = rid;
    }
    aggr_str->aggr_bufsize = rsv_size;
    return OG_SUCCESS;
}

static status_t sql_aggr_save_aggr_str_value(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    variant_t *value)
{
    if (value->is_null) {
        return OG_SUCCESS;
    }

    if (value->v_text.len != 0) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);

        OG_RETURN_IFERR(sql_aggr_ensure_str_buf(stmt, cursor, aggr_var, value->v_text.len, OG_FALSE));
        OG_RETURN_IFERR(sql_aggr_get_value_from_vm(stmt, cursor, aggr_var, OG_FALSE));
        MEMS_RETURN_IFERR(
            memcpy_s(aggr_var->var.v_text.str, aggr_str->aggr_bufsize, value->v_text.str, value->v_text.len));
    }

    aggr_var->var.v_text.len = value->v_text.len;
    aggr_var->var.is_null = OG_FALSE;
    return OG_SUCCESS;
}


static inline status_t sql_aggr_none(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    OG_THROW_ERROR(ERR_UNKNOWN_ARRG_OPER);
    return OG_ERROR;
}

static inline status_t sql_aggr_count(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    VALUE(int64, &aggr_var->var) += VALUE(int64, value);
    return OG_SUCCESS;
}

static inline status_t sql_aggr_cume_dist(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count += ogsql_stmt->avg_count;
    if (SECUREC_LIKELY(!aggr_var->var.is_null)) {
        return sql_aggr_sum_value(ogsql_stmt->stmt, &aggr_var->var, value);
    }
    var_copy(value, &aggr_var->var);
    return OG_SUCCESS;
}

static inline status_t sql_aggr_sum(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    if (SECUREC_LIKELY(!aggr_var->var.is_null)) {
        return sql_aggr_sum_value(ogsql_stmt->stmt, &aggr_var->var, value);
    }
    if (value->type != aggr_var->var.type) {
        // avg/sum are used for numeric data types, which are non-buffer consuming data types
        // thus directory applying var_convert is more efficient.
        if (aggr_var->var.type != OG_TYPE_UNKNOWN) {
            OG_RETURN_IFERR(var_convert(SESSION_NLS(ogsql_stmt->stmt), value, aggr_var->var.type, NULL));
        }
    }
    var_copy(value, &aggr_var->var);
    return OG_SUCCESS;
}

static inline status_t sql_aggr_avg(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count += ogsql_stmt->avg_count;
    return sql_aggr_sum(ogsql_stmt, aggr_var, value);
}

static status_t sql_aggr_min_max(aggr_assist_t *ass, aggr_var_t *var, variant_t *value)
{
    if (value->type != var->var.type) {
        if (var->var.type == OG_TYPE_UNKNOWN) {
            var->var.type = value->type;
            if (OG_IS_VARLEN_TYPE(var->var.type)) {
                aggr_str_t *aggr_str = NULL;
                OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_str_t), (void
                    **)&aggr_str));
                var->extra_offset = (uint32)((char *)aggr_str - (char *)var);
                var->extra_size = sizeof(aggr_str_t);
                aggr_str->aggr_bufsize = 0;
                aggr_str->str_result.vmid = OG_INVALID_ID32;
                aggr_str->str_result.slot = OG_INVALID_ID32;
            }
        } else {
            OG_RETURN_IFERR(sql_convert_variant(ass->stmt, value, var->var.type));
        }
    }
    int32 cmp_result;

    if (var->var.is_null) {
        var->var.is_null = OG_FALSE;
        return sql_copy_aggr_value(ass->stmt, ass->cursor, value, var);
    }

    OG_RETURN_IFERR(sql_compare_variant(ass->stmt, &var->var, value, &cmp_result));

    if ((ass->aggr_type == AGGR_TYPE_MIN && cmp_result > 0) || (ass->aggr_type == AGGR_TYPE_MAX && cmp_result < 0)) {
        return sql_copy_aggr_value(ass->stmt, ass->cursor, value, var);
    }

    return OG_SUCCESS;
}

static status_t sql_aggr_listagg_sort(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    status_t status = OG_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    uint32 seg_id = ogsql_stmt->cursor->mtrl.sort_seg;

    if (value->is_null) {
        return OG_SUCCESS;
    }

    OGSQL_SAVE_STACK(ogsql_stmt->stmt);
    sql_keep_stack_variant(ogsql_stmt->stmt, value);
    if (sql_push(ogsql_stmt->stmt, OG_MAX_ROW_SIZE, (void **)&buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(ogsql_stmt->stmt);
        return OG_ERROR;
    }
    row_init(&ra, buf, OG_MAX_ROW_SIZE, ogsql_stmt->aggr_node->sort_items->count + 1);

    do {
        // make sort rows
        aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
        char* type_buf = aggr_group->type_buf;
        OG_BREAK_IF_ERROR(sql_hash_group_make_sort_row(ogsql_stmt->stmt, ogsql_stmt->aggr_node, &ra,
                                                       type_buf, value, ogsql_stmt->cursor));

        // the separator is stored in aggr_var->extra
        if (aggr_group->total_len != 0 && !aggr_group->extra.is_null) {
            aggr_group->total_len += aggr_group->extra.v_text.len;
        }
        aggr_group->total_len += value->v_text.len;

        if (aggr_group->total_len > OG_MAX_ROW_SIZE) {
            OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, aggr_group->total_len, OG_MAX_ROW_SIZE);
            break;
        }
        status = sql_hash_group_mtrl_insert_row(ogsql_stmt->stmt, seg_id, ogsql_stmt->aggr_node, aggr_var, buf);
        aggr_var->var.is_null = OG_FALSE;
    } while (0);

    OGSQL_RESTORE_STACK(ogsql_stmt->stmt);
    return status;
}

static status_t sql_aggr_listagg(aggr_assist_t *ass, aggr_var_t *aggr_var, variant_t *val)
{
    if (ass->aggr_node->sort_items != NULL) {
        return sql_aggr_listagg_sort(ass, aggr_var, val);
    }
    status_t status = OG_ERROR;
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    variant_t *sep_var = &aggr_group->extra;
    bool32 has_sep = (bool32)(!sep_var->is_null && sep_var->v_text.len > 0);

    if (val->is_null) {
        return OG_SUCCESS;
    }

    OGSQL_SAVE_STACK(ass->stmt);
    sql_keep_stack_variant(ass->stmt, val);

    do {
        if (aggr_var->var.is_null) {
            status = sql_aggr_save_aggr_str_value(ass->stmt, ass->cursor, aggr_var, val);
            break;
        }
        uint32 len = aggr_var->var.v_text.len + val->v_text.len;
        if (has_sep) {
            len += sep_var->v_text.len;
        }
        OG_BREAK_IF_ERROR(sql_aggr_ensure_str_buf(ass->stmt, ass->cursor, aggr_var, len, OG_TRUE));
        OG_BREAK_IF_ERROR(sql_aggr_get_value_from_vm(ass->stmt, ass->cursor, aggr_var, OG_FALSE));
        char *cur_buffer = aggr_var->var.v_text.str + aggr_var->var.v_text.len;
        uint32 remain_len = len - aggr_var->var.v_text.len;

        if (has_sep) {
            MEMS_RETURN_IFERR(memcpy_sp(cur_buffer, remain_len, sep_var->v_text.str, sep_var->v_text.len));
            cur_buffer += sep_var->v_text.len;
            remain_len -= sep_var->v_text.len;
        }
        if (val->v_text.len != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(cur_buffer, remain_len, val->v_text.str, val->v_text.len));
        }
        status = OG_SUCCESS;
        aggr_var->var.v_text.len = len;
    } while (0);

    OGSQL_RESTORE_STACK(ass->stmt);
    return status;
}

static status_t sql_get_compare_res4rank(sql_stmt_t *sql_statement, sort_item_t *sort_item, variant_t *cst_var,
                                         variant_t *sort_var, int32 *compare_res)
{
    bool32 nvl_first = sort_item->nulls_pos == SORT_NULLS_FIRST || sort_item->nulls_pos == SORT_NULLS_DEFAULT;

    if (cst_var->is_null && sort_var->is_null) {
        *compare_res = 0;
        return OG_SUCCESS;
    }

    if (cst_var->is_null) {
        *compare_res = nvl_first ? -1 : 1;
        return OG_SUCCESS;
    }

    if (sort_var->is_null) {
        *compare_res = -1;
        if (nvl_first) {
            *compare_res = 1;
        }
        return OG_SUCCESS;
    }

    status_t status;

    if (!OG_IS_NUMERIC_TYPE(sort_var->type)) {
        status = sql_convert_variant(sql_statement, cst_var, sort_var->type);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("func:%s revoke func:%s failed.", "sql_get_compare_res4rank", "sql_convert_variant");
            return status;
        }
        sql_keep_stack_variant(sql_statement, cst_var);
    }

    status = sql_compare_variant(sql_statement, cst_var, sort_var, compare_res);
    if (status != OG_SUCCESS) {
        OG_LOG_RUN_ERR("func:%s revoke func:%s failed.", "sql_get_compare_res4rank", "sql_compare_variant");
        return status;
    }

    if (sort_item->direction == SORT_MODE_DESC) {
        *compare_res *= -1;
    }

    return OG_SUCCESS;
}

status_t sql_compare_sort_row_for_rank(sql_stmt_t *ogsql_stmt, expr_node_t *aggr_node, bool32 *flag)
{
    int32 cmp_result = 0;
    variant_t sort_var;
    variant_t constant;
    sort_item_t *sort_item = NULL;
    expr_tree_t *arg = NULL;

    arg = aggr_node->argument;
    OGSQL_SAVE_STACK(ogsql_stmt);
    for (uint32 i = 0; i < aggr_node->sort_items->count; ++i) {
        OGSQL_RESTORE_STACK(ogsql_stmt);
        sort_item = (sort_item_t *)cm_galist_get(aggr_node->sort_items, i);

        OG_RETURN_IFERR(sql_exec_expr(ogsql_stmt, sort_item->expr, &sort_var));
        sql_keep_stack_variant(ogsql_stmt, &sort_var);
        OG_RETURN_IFERR(sql_exec_expr(ogsql_stmt, arg, &constant));
        sql_keep_stack_variant(ogsql_stmt, &constant);
        
        OG_RETURN_IFERR(sql_get_compare_res4rank(ogsql_stmt, sort_item, &constant, &sort_var, &cmp_result));

        if (cmp_result < 0) {
            *flag = OG_FALSE;
            return OG_SUCCESS;
        } else if (cmp_result > 0) {
            return OG_SUCCESS;
        } else {
            arg = arg->next;
        }
    }
    *flag = OG_FALSE;
    return OG_SUCCESS;
}

static status_t sql_aggr_make_sort_row(sql_stmt_t *stmt, expr_node_t *aggr_node, row_assist_t *ra)
{
    uint32 i;
    variant_t sort_var;
    sort_item_t *sort_item = NULL;

    for (i = 0; i < aggr_node->sort_items->count; ++i) {
        sort_item = (sort_item_t *)cm_galist_get(aggr_node->sort_items, i);
        OG_RETURN_IFERR(sql_exec_expr(stmt, sort_item->expr, &sort_var));
        OG_RETURN_IFERR(sql_put_row_value(stmt, NULL, ra, sort_var.type, &sort_var));
    }

    return OG_SUCCESS;
}

static status_t sql_aggr_init_hash_tbl(aggr_assist_t *aggr_ass, aggr_var_t *aggr_var,
    aggr_dense_rank_t *aggr_dense_rank)
{
    CM_POINTER3(aggr_ass, aggr_var, aggr_dense_rank);
    aggr_var->var.is_null = OG_FALSE;
    vm_hash_segment_init(KNL_SESSION(aggr_ass->stmt), aggr_ass->stmt->mtrl.pool,
        &aggr_dense_rank->hash_segment, PMA_POOL, HASH_PAGES_HOLD, HASH_AREA_SIZE);
    OG_RETURN_IFERR(vm_hash_table_alloc(&aggr_dense_rank->table_entry, &aggr_dense_rank->hash_segment, 0));
    return vm_hash_table_init(&aggr_dense_rank->hash_segment, &aggr_dense_rank->table_entry,
        NULL, NULL, NULL);
}

// For DENSE_RANK func, same value has same rank, and the next value has next rank
static status_t sql_aggr_dense_rank(aggr_assist_t *aggr_ast, aggr_var_t *aggr_var, variant_t *var)
{
    char *row_buf = NULL;
    row_assist_t row_asst = {0};
    bool32 match_found = OG_FALSE;
    aggr_dense_rank_t *aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
    if (aggr_var->var.is_null) {
        // Initialize the hash table
        OG_RETURN_IFERR(sql_aggr_init_hash_tbl(aggr_ast, aggr_var, aggr_dense_rank));
    }

    OG_RETURN_IFERR(ogsql_func_rank(aggr_ast->stmt, aggr_ast->aggr_node, var));
    // 0 represetns none rank update
    OG_RETSUC_IFTRUE(var->v_int == 0);
    // Construct the row data
    OGSQL_SAVE_STACK(aggr_ast->stmt);
    OG_RETURN_IFERR(sql_push(aggr_ast->stmt, OG_MAX_ROW_SIZE, (void **)&row_buf));
    row_init(&row_asst, row_buf, OG_MAX_ROW_SIZE, aggr_ast->aggr_node->sort_items->count);
    status_t ret = OG_ERROR;
    do {
        OG_BREAK_IF_ERROR(sql_aggr_make_sort_row(aggr_ast->stmt, aggr_ast->aggr_node, &row_asst));
        // If current row not in hash table, Rank + 1
        OG_BREAK_IF_ERROR(vm_hash_table_insert2(&match_found, &aggr_dense_rank->hash_segment,
        &aggr_dense_rank->table_entry, row_buf, row_asst.head->size));
        ret = OG_SUCCESS;
    } while (OG_FALSE);
    if (ret != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(aggr_ast->stmt);
        return OG_ERROR;
    }
    if (match_found == OG_FALSE) {
        VALUE(uint32, &aggr_var->var) += VALUE(uint32, var);
    }
    OGSQL_RESTORE_STACK(aggr_ast->stmt);
    return OG_SUCCESS;
}

// For RANK func, same value has same rank, but the next value has skip rank
static status_t sql_aggr_rank(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_val, variant_t *var)
{
    aggr_val->var.is_null = OG_FALSE;
    // For RANK func, no need hash table for unique operator,
    // it accumulates the count of rows (including duplicates) as the rank result
    VALUE(uint32, &aggr_val->var) += VALUE(uint32, var);
    return OG_SUCCESS;
}

static inline status_t sql_aggr_calc_group_concat_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    return sql_hash_group_calc_listagg(stmt, cursor, aggr_node, aggr_var, &cursor->exec_data.sort_concat);
}

static status_t sql_aggr_median(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    status_t status = OG_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    uint32 seg_id = ogsql_stmt->cursor->mtrl.sort_seg;
    og_type_t type = TREE_DATATYPE(ogsql_stmt->aggr_node->argument);

    GET_AGGR_VAR_MEDIAN(aggr_var)->median_count += ogsql_stmt->avg_count;

    if (value->is_null) {
        return OG_SUCCESS;
    }
    if (aggr_var->var.is_null) {
        if (!OG_IS_NUMERIC_TYPE(value->type) && !OG_IS_DATETIME_TYPE(value->type)) {
            OG_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC OR DATETIME", get_datatype_name_str(value->type));
            return OG_ERROR;
        }
        var_copy(value, &aggr_var->var);
    }
    if (type == OG_TYPE_UNKNOWN) {
        type = aggr_var->var.type;
    }

    OGSQL_SAVE_STACK(ogsql_stmt->stmt);
    sql_keep_stack_variant(ogsql_stmt->stmt, value);
    if (sql_push(ogsql_stmt->stmt, OG_MAX_ROW_SIZE, (void **)&buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(ogsql_stmt->stmt);
        return OG_ERROR;
    }
    row_init(&ra, buf, OG_MAX_ROW_SIZE, 1);

    do {
        // make sort rows
        OG_BREAK_IF_ERROR(sql_put_row_value(ogsql_stmt->stmt, NULL, &ra, type, value));
        status = sql_hash_group_mtrl_insert_row(ogsql_stmt->stmt, seg_id, ogsql_stmt->aggr_node, aggr_var, buf);
    } while (0);

    OGSQL_RESTORE_STACK(ogsql_stmt->stmt);
    return status;
}

static status_t sql_aggr_stddev(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);

    // First calculation
    if (aggr_var->var.is_null == OG_TRUE) {
        aggr_var->var.is_null = OG_FALSE;
        aggr_var->var.type = OG_TYPE_NUMBER;
        cm_zero_dec(&aggr_var->var.v_dec);
        aggr_stddev->extra.is_null = OG_FALSE;
        aggr_stddev->extra.type = OG_TYPE_NUMBER;
        cm_zero_dec(&aggr_stddev->extra.v_dec);
    }

    variant_t tmp_square_var;
    tmp_square_var.is_null = OG_FALSE;
    tmp_square_var.type = OG_TYPE_NUMBER;
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(ogsql_stmt->stmt), value, value,
        &tmp_square_var)); // Xi^2
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(ogsql_stmt->stmt), &aggr_var->var, &tmp_square_var,
        &aggr_var->var)); // sum(Xi^2)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(ogsql_stmt->stmt), &aggr_stddev->extra, value,
        &aggr_stddev->extra)); // sum(Xi)

    aggr_stddev->ex_count++;
    return OG_SUCCESS;
}

static status_t sql_aggr_corr(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *values)
{
    sql_stmt_t *stmt = ogsql_stmt->stmt;
    variant_t *value = &values[0];
    variant_t *value_extra = &values[1];
    variant_t tmp_square_var;
    tmp_square_var.is_null = OG_FALSE;
    tmp_square_var.type = OG_TYPE_NUMBER;
    aggr_corr_t *a_corr = GET_AGGR_VAR_CORR(aggr_var);

    if (aggr_var->var.is_null == OG_TRUE) {
        aggr_var->var.is_null = OG_FALSE;
        aggr_var->var.type = OG_TYPE_NUMBER;
        a_corr->extra[CORR_VAR_SUM_X].is_null = OG_FALSE;
        a_corr->extra[CORR_VAR_SUM_Y].is_null = OG_FALSE;
        a_corr->extra[CORR_VAR_SUM_XX].is_null = OG_FALSE;
        a_corr->extra[CORR_VAR_SUM_YY].is_null = OG_FALSE;
        a_corr->extra[CORR_VAR_SUM_X].type = OG_TYPE_NUMBER;  // extra : sum(Xi)
        a_corr->extra[CORR_VAR_SUM_Y].type = OG_TYPE_NUMBER;  // extra_1 : sum(Yi)
        a_corr->extra[CORR_VAR_SUM_XX].type = OG_TYPE_NUMBER; // extra_2 : sum(Xi*Xi)
        a_corr->extra[CORR_VAR_SUM_YY].type = OG_TYPE_NUMBER; // extra_3 : sum(Yi*Yi)
        cm_zero_dec(&aggr_var->var.v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_X].v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_Y].v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_XX].v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_YY].v_dec);
    }
    if (value->is_null || value_extra->is_null) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value, value_extra, &tmp_square_var)); // Xi*Yi
    OG_RETURN_IFERR(
        opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &aggr_var->var, &tmp_square_var, &aggr_var->var)); // sum(Xi*Yi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_X], value,
        &a_corr->extra[CORR_VAR_SUM_X])); // sum(Xi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_Y], value_extra,
        &a_corr->extra[CORR_VAR_SUM_Y]));                                                    // sum(Yi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value, value, &tmp_square_var)); // Xi*Xi
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_XX], &tmp_square_var,
        &a_corr->extra[CORR_VAR_SUM_XX])); // sum(Xi*Xi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value_extra, value_extra, &tmp_square_var)); // Yi*Yi
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_YY], &tmp_square_var,
        &a_corr->extra[CORR_VAR_SUM_YY])); // sum(Yi*Yi)
    a_corr->ex_count++;
    return OG_SUCCESS;
}

static status_t sql_aggr_covar(aggr_assist_t *ass, aggr_var_t *v_aggr, variant_t *values)
{
    sql_stmt_t *stmt = ass->stmt;
    variant_t *value = &values[0];
    variant_t *value_extra = &values[1];
    variant_t tmp_square_var;
    tmp_square_var.is_null = OG_FALSE;
    tmp_square_var.type = OG_TYPE_NUMBER;
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(v_aggr);
    if (value->is_null || value_extra->is_null) {
        return OG_SUCCESS;
    }

    if (v_aggr->var.is_null == OG_TRUE) {
        v_aggr->var.is_null = OG_FALSE;
        v_aggr->var.type = OG_TYPE_NUMBER; // var   : sum(Xi*Yi)
        aggr_covar->extra.is_null = OG_FALSE;
        aggr_covar->extra.type = OG_TYPE_NUMBER; // extra : sum(Xi)
        aggr_covar->extra_1.is_null = OG_FALSE;
        aggr_covar->extra_1.type = OG_TYPE_NUMBER; // extra_1 : sum(Yi)
        cm_zero_dec(&v_aggr->var.v_dec);
        cm_zero_dec(&aggr_covar->extra.v_dec);
        cm_zero_dec(&aggr_covar->extra_1.v_dec);
    }

    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value, value_extra,
        &tmp_square_var)); // Xi*Yi
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &v_aggr->var, &tmp_square_var,
        &v_aggr->var)); // sum(Xi*Yi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &aggr_covar->extra, value,
        &aggr_covar->extra)); // sum(Xi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &aggr_covar->extra_1, value_extra,
        &aggr_covar->extra_1)); // sum(Yi)
    aggr_covar->ex_count++;

    return OG_SUCCESS;
}

static status_t sql_aggr_array_agg(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    var_array_t *varray = &aggr_var->var.v_array;
    array_assist_t array_a;

    if (SECUREC_UNLIKELY(varray->type == OG_TYPE_UNKNOWN)) {
        varray->type = value->type;
        if (!cm_datatype_arrayable(value->type)) {
            OG_SRC_THROW_ERROR(ogsql_stmt->aggr_node->argument->root->loc, ERR_INVALID_ARG_TYPE);
            return OG_ERROR;
        }
    }
    OG_RETURN_IFERR(sql_convert_variant(ogsql_stmt->stmt, value, varray->type));

    if (varray->value.type == OG_LOB_FROM_KERNEL) {
        vm_lob_t vlob;
        vlob.node_id = 0;
        vlob.unused = 0;
        OG_RETURN_IFERR(sql_get_array_from_knl_lob(ogsql_stmt->stmt, (knl_handle_t)(varray->value.knl_lob.bytes),
            &vlob));
        varray->value.vm_lob = vlob;
        varray->value.type = OG_LOB_FROM_VMPOOL;
    }

    varray->count++;
    ARRAY_INIT_ASSIST_INFO(&array_a, ogsql_stmt->stmt);

    OG_RETURN_IFERR(sql_exec_array_element(ogsql_stmt->stmt, &array_a, varray->count, value, OG_TRUE,
        &varray->value.vm_lob));
    return array_update_head_datatype(&array_a, &varray->value.vm_lob, value->type);
}

static status_t sql_aggr_distinct_value(aggr_assist_t *ass, variant_t *value, bool32 *var_exist)
{
    char *buf = NULL;
    row_assist_t ra;
    hash_segment_t *hash_segment = NULL;
    hash_table_entry_t *hash_table_entry = NULL;
    sql_stmt_t *stmt = ass->stmt;

    OGSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, value);
    if (sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    row_init(&ra, buf, OG_MAX_ROW_SIZE, 1);
    if (sql_put_row_value(stmt, NULL, &ra, value->type, value) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    /* it was asserted that cursor->va_set.aggr_dis.vid not being OG_INVALID_ID32,
       so we won't guard the case that varea_read() returned a NULL
       we'd rather it cored if that really has happened.
     */
    hash_segment = (hash_segment_t *)ass->cursor->exec_data.aggr_dis;
    hash_table_entry = (hash_table_entry_t *)((char *)hash_segment + sizeof(hash_segment_t));
    if (vm_hash_table_insert2(var_exist, hash_segment, &hash_table_entry[ass->aggr_node->dis_info.idx], buf,
        ra.head->size) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    return OG_SUCCESS;
}


status_t sql_aggr_value(aggr_assist_t *aggr_ass, uint32 aggr_idx, variant_t *value)
{
    aggr_var_t *aggr_var = NULL;
    if (value->is_null && value->type != OG_TYPE_ARRAY) {
        // MIN or MAX func && nullaware, the result is NULL
        if (aggr_ass->aggr_node->nullaware &&
           (aggr_ass->aggr_type == AGGR_TYPE_MIN || aggr_ass->aggr_type == AGGR_TYPE_MAX)) {
            aggr_var = sql_get_aggr_addr(aggr_ass->cursor, aggr_idx);
            aggr_var->var.is_null = OG_TRUE;
            aggr_ass->cursor->eof = OG_TRUE;
        }

        if (aggr_ass->aggr_type != AGGR_TYPE_ARRAY_AGG) {
            return OG_SUCCESS;
        }
    }

    if (aggr_ass->aggr_node->dis_info.need_distinct) {
        bool32 var_exist = OG_FALSE;
        OG_RETURN_IFERR(sql_aggr_distinct_value(aggr_ass, value, &var_exist));
        if (var_exist) {
            return OG_SUCCESS;
        }

        if (aggr_ass->aggr_type == AGGR_TYPE_COUNT) {
            value->type = OG_TYPE_BIGINT;
            value->v_bigint = 1;
        }
    }

    aggr_var = sql_get_aggr_addr(aggr_ass->cursor, aggr_idx);
    if (aggr_ass->aggr_type == AGGR_TYPE_SUM &&
        SECUREC_LIKELY(!aggr_var->var.is_null) && VAR_IS_NUMBERIC_ZERO(value)) {
        return OG_SUCCESS;
    }
    return sql_get_aggr_func(aggr_ass->aggr_type)->invoke(aggr_ass, aggr_var, value);
}

static inline status_t sql_aggr_calc_none(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    return OG_SUCCESS;
}

// for avg/avg_collect
static inline status_t sql_aggr_calc_avg(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    variant_t v_rows;
    v_rows.type = OG_TYPE_BIGINT;
    v_rows.is_null = OG_FALSE;
    v_rows.v_bigint = (int64)GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count;
    return opr_exec(OPER_TYPE_DIV, SESSION_NLS(ogsql_stmt->stmt), &aggr_var->var, &v_rows, &aggr_var->var);
}

static inline status_t sql_aggr_calc_cume_dist(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    variant_t v_rows;
    v_rows.type = OG_TYPE_BIGINT;
    v_rows.is_null = OG_FALSE;
    // as if this param is been inserted
    v_rows.v_bigint = (int64)GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count + 1;
    OG_RETURN_IFERR(var_as_bigint(&aggr_var->var));
    aggr_var->var.v_bigint += 1;
    return opr_exec(OPER_TYPE_DIV, SESSION_NLS(ogsql_stmt->stmt), &aggr_var->var, &v_rows, &aggr_var->var);
}

static inline status_t sql_aggr_calc_listagg(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    if (ogsql_stmt->aggr_node->sort_items != NULL) {
        return sql_hash_group_calc_listagg(ogsql_stmt->stmt, ogsql_stmt->cursor, ogsql_stmt->aggr_node, aggr_var,
            &ogsql_stmt->cursor->exec_data.sort_concat);
    }
    return OG_SUCCESS;
}

static inline status_t sql_aggr_calc_median(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    return sql_hash_group_calc_median(ogsql_stmt->stmt, ogsql_stmt->cursor, ogsql_stmt->aggr_node, aggr_var);
}

static status_t sql_aggr_calc_stddev(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);

    if (aggr_stddev->ex_count == 0) {
        aggr_var->var.is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    if (aggr_stddev->ex_count == 1) {
        switch (ogsql_stmt->aggr_type) {
            case AGGR_TYPE_STDDEV:
            case AGGR_TYPE_STDDEV_POP:
            case AGGR_TYPE_VARIANCE:
            case AGGR_TYPE_VAR_POP:
                aggr_var->var.v_bigint = 0;
                aggr_var->var.type = OG_TYPE_BIGINT;
                break;
            case AGGR_TYPE_STDDEV_SAMP:
            case AGGR_TYPE_VAR_SAMP:
            default:
                aggr_var->var.is_null = OG_TRUE;
                break;
        }
        return OG_SUCCESS;
    }

    variant_t v_rows;   // N
    variant_t v_rows_m; // N-1
    variant_t tmp_result;
    tmp_result.type = OG_TYPE_NUMBER;
    tmp_result.is_null = OG_FALSE;
    v_rows.type = OG_TYPE_BIGINT;
    v_rows.is_null = OG_FALSE;
    v_rows.v_bigint = (int64)aggr_stddev->ex_count;
    v_rows_m.type = OG_TYPE_BIGINT;
    v_rows_m.is_null = OG_FALSE;
    v_rows_m.v_bigint = v_rows.v_bigint - 1;
    /*
     * STDDEV:
     * S = sqrt[ 1/(N-1) * ( sum(Xi^2) - 1/N * sum(Xi)^2 ) ]
     */
    (void)opr_exec(OPER_TYPE_MUL, SESSION_NLS(ogsql_stmt->stmt), &aggr_stddev->extra, &aggr_stddev->extra,
        &aggr_stddev->extra); // sum(Xi)^2
    (void)opr_exec(OPER_TYPE_DIV, SESSION_NLS(ogsql_stmt->stmt), &aggr_stddev->extra, &v_rows,
        &aggr_stddev->extra); // 1/N * sum(Xi)^2
    (void)opr_exec(OPER_TYPE_SUB, SESSION_NLS(ogsql_stmt->stmt), &aggr_var->var, &aggr_stddev->extra,
        &aggr_var->var); // (sum(Xi^2) - 1/N * sum(Xi)^2)
    switch (ogsql_stmt->aggr_type) {
        /* 1/(N-1)  or 1/N */
        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_SAMP:
            OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(ogsql_stmt->stmt), &aggr_var->var, &v_rows_m,
                &tmp_result));
            break;
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_VAR_POP:
            OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(ogsql_stmt->stmt), &aggr_var->var, &v_rows,
                &tmp_result));
            break;
        default:
            break;
    }
    OG_RETURN_IFERR(var_as_decimal(&aggr_var->var));
    OG_RETURN_IFERR(var_as_decimal(&tmp_result));
    if (IS_DEC8_NEG(&tmp_result.v_dec)) {
        aggr_var->var.v_bigint = 0;
        aggr_var->var.type = OG_TYPE_BIGINT;
        return OG_SUCCESS;
    }

    if (ogsql_stmt->aggr_type == AGGR_TYPE_VARIANCE || ogsql_stmt->aggr_type == AGGR_TYPE_VAR_POP ||
        ogsql_stmt->aggr_type == AGGR_TYPE_VAR_SAMP) {
        aggr_var->var.v_dec = tmp_result.v_dec;
        return OG_SUCCESS;
    }

    return cm_dec_sqrt(&tmp_result.v_dec, &aggr_var->var.v_dec);
}

static status_t sql_aggr_calc_corr(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    sql_stmt_t *stmt = ogsql_stmt->stmt;
    aggr_corr_t *aggr_corr = GET_AGGR_VAR_CORR(aggr_var);

    if (aggr_corr->ex_count == 0 || aggr_corr->ex_count == 1) {
        aggr_var->var.is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    variant_t v_rows;
    variant_t tmp_result;
    tmp_result.type = OG_TYPE_NUMBER;
    tmp_result.is_null = OG_FALSE;
    variant_t tmp_result_1;
    tmp_result_1.type = OG_TYPE_NUMBER;
    tmp_result_1.is_null = OG_FALSE;
    variant_t tmp_result_2;
    tmp_result_2.type = OG_TYPE_NUMBER;
    tmp_result_2.is_null = OG_FALSE;
    v_rows.type = OG_TYPE_BIGINT;
    v_rows.is_null = OG_FALSE;
    v_rows.v_bigint = (int64)aggr_corr->ex_count;

    // COVAR_POP: S = 1/N * ( sum(Xi*Yi) - 1/N * sum(Xi)*sun(Yi) )
    // STDDEV_pop:  S = sqrt[ 1/N * ( sum(Xi^2) - 1/N * sum(Xi)^2 ) ]
    // CORR: S = COVAR_POP(Xi, Yi) / (STDDEV_POP(Xi) * STDDEV_POP(Yi))
    // COVAR_POP(Xi, Yi):
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_X],
        &aggr_corr->extra[CORR_VAR_SUM_Y], &tmp_result)); // sum(Xi)*sum(Yi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result, &v_rows,
        &tmp_result)); // 1/N * sum(Xi)*sum(Yi)
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_var->var, &tmp_result,
        &aggr_var->var)); // (sum(Xi*Yi) - 1/N * sum(Xi)*sum(Yi))
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &tmp_result));

    // STDDEV_pop(Xi):
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_X],
        &aggr_corr->extra[CORR_VAR_SUM_X], &tmp_result_1)); // sum(Xi)^2
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result_1, &v_rows,
        &tmp_result_1)); // 1/N * sum(Xi)^2
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_XX], &tmp_result_1,
        &aggr_var->var)); // (sum(Xi^2) - 1/N * sum(Xi)^2)
    if (IS_DEC8_NEG(&aggr_var->var.v_dec)) { // Negative number loose precision
        aggr_var->var.is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &aggr_var->var));
    OG_RETURN_IFERR(cm_dec_sqrt(&aggr_var->var.v_dec, &tmp_result_1.v_dec));

    // STDDEV_pop(Yi):
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_Y],
        &aggr_corr->extra[CORR_VAR_SUM_Y], &tmp_result_2)); // sum(Yi)^2
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result_2, &v_rows,
        &tmp_result_2)); // 1/N * sum(Yi)^2
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_YY], &tmp_result_2,
        &aggr_var->var)); // (sum(Yi^2) - 1/N * sum(Yi)^2)
    if (IS_DEC8_NEG(&aggr_var->var.v_dec)) {
        aggr_var->var.is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &aggr_var->var));
    OG_RETURN_IFERR(cm_dec_sqrt(&aggr_var->var.v_dec, &tmp_result_2.v_dec));

    // the divisor was zero
    if (DECIMAL8_IS_ZERO(&tmp_result_1.v_dec) || DECIMAL8_IS_ZERO(&tmp_result_2.v_dec)) {
        aggr_var->var.is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &tmp_result_1, &tmp_result_2,
        &tmp_result_2)); // (STDDEV_POP(Xi) * STDDEV_POP(Yi))

    OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result, &tmp_result_2,
        &tmp_result)); // COVAR_POP(Xi, Yi) / (STDDEV_POP(Xi) * STDDEV_POP(Yi))

    OG_RETURN_IFERR(var_as_decimal(&aggr_var->var));
    OG_RETURN_IFERR(var_as_decimal(&tmp_result));
    aggr_var->var.v_dec = tmp_result.v_dec;

    return OG_SUCCESS;
}

static status_t sql_aggr_calc_covar(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    sql_stmt_t *stmt = ogsql_stmt->stmt;
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(aggr_var);

    if (aggr_covar->ex_count == 0) {
        aggr_var->var.is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    if (aggr_covar->ex_count == 1) {
        switch (ogsql_stmt->aggr_type) {
            case AGGR_TYPE_COVAR_POP:
                aggr_var->var.v_bigint = 0;
                aggr_var->var.type = OG_TYPE_BIGINT;
                return OG_SUCCESS;
            case AGGR_TYPE_COVAR_SAMP:
            default:
                aggr_var->var.is_null = OG_TRUE;
                return OG_SUCCESS;
        }
    }

    variant_t v_rows, v_rows_m, tmp_result; // v_rows : N, v_rows_m : N-1
    tmp_result.type = OG_TYPE_NUMBER;
    tmp_result.is_null = OG_FALSE;
    v_rows.type = OG_TYPE_BIGINT;
    v_rows.is_null = OG_FALSE;
    v_rows.v_bigint = (int64)aggr_covar->ex_count;
    v_rows_m.type = OG_TYPE_BIGINT;
    v_rows_m.is_null = OG_FALSE;
    v_rows_m.v_bigint = v_rows.v_bigint - 1;
    /*
     * COVAR_POP:
     * S = 1/N * ( sum(Xi*Yi) - 1/N * sum(Xi)*sun(Yi) )
     * COVAR_SAMP:
     * S = 1/(N-1) * ( sum(Xi*Yi) - 1/N * sum(Xi)*sun(Yi) )
     */
    (void)opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_covar->extra, &aggr_covar->extra_1,
        &aggr_covar->extra); // sum(Xi)*sum(Yi)
    (void)opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_covar->extra, &v_rows,
        &aggr_covar->extra); // 1/N * sum(Xi)*sum(Yi)
    (void)opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_var->var, &aggr_covar->extra,
        &aggr_var->var); // (sum(Xi*Yi) - 1/N * sum(Xi)*sum(Yi))

    switch (ogsql_stmt->aggr_type) {
        /* 1/(N-1)  or 1/N */
        case AGGR_TYPE_COVAR_SAMP:
            OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows_m, &tmp_result));
            break;
        case AGGR_TYPE_COVAR_POP:
            OG_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &tmp_result));
            break;
        default:
            break;
    }
    aggr_var->var.v_dec = tmp_result.v_dec;
    return OG_SUCCESS;
}

status_t sql_exec_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs, plan_node_t *plan)
{
    const sql_func_t *func = NULL;
    aggr_var_t *aggr_var = NULL;
    aggr_assist_t ogsql_stmt;
    SQL_INIT_AGGR_ASSIST(&ogsql_stmt, stmt, cursor);

    /* init the sort concat data buf */
    cursor->exec_data.sort_concat.len = 0;

    for (uint32 i = 0; i < aggrs->count; i++) {
        ogsql_stmt.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = GET_AGGR_FUNC(ogsql_stmt.aggr_node);
        /* modified by OG_RAC_ING, add AGGR_TYPE_AVG_COLLECT for sharding */
        if (func->aggr_type == AGGR_TYPE_SUM || func->aggr_type == AGGR_TYPE_COUNT ||
            func->aggr_type == AGGR_TYPE_MIN || func->aggr_type == AGGR_TYPE_MAX ||
            func->aggr_type == AGGR_TYPE_ARRAY_AGG || func->aggr_type == AGGR_TYPE_RANK) {
            continue;
        }

        aggr_var = sql_get_aggr_addr(cursor, i);
        if (aggr_var->var.is_null) {
            continue;
        }
        ogsql_stmt.aggr_type = func->aggr_type;
        OG_RETURN_IFERR(sql_aggr_calc_value(&ogsql_stmt, aggr_var));
    }
    return OG_SUCCESS;
}

status_t sql_exec_aggr_extra(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs, plan_node_t *plan)
{
    uint32 i;
    expr_node_t *aggr_node = NULL;
    const sql_func_t *func = NULL;
    aggr_var_t *aggr_var = NULL;
    aggr_dense_rank_t *aggr_dense_rank = NULL;

    for (i = 0; i < aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = GET_AGGR_FUNC(aggr_node);
        sql_aggr_type_t func_type = func->aggr_type;
        aggr_var = sql_get_aggr_addr(cursor, i);

        switch (func_type) {
            case AGGR_TYPE_DENSE_RANK:
                if (!aggr_var->var.is_null) {
                    aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
                    vm_hash_segment_deinit(&aggr_dense_rank->hash_segment);
                    aggr_dense_rank->table_entry.vmid = OG_INVALID_ID32;
                    aggr_dense_rank->table_entry.offset = OG_INVALID_ID32;
                }
            /* fall-through */
            case AGGR_TYPE_RANK:
            case AGGR_TYPE_CUME_DIST:
                aggr_var->var.is_null = OG_FALSE;
                break;
            default:
                break;
        }
    }
    return OG_SUCCESS;
}

status_t sql_aggr_get_cntdis_value(sql_stmt_t *stmt, galist_t *cntdis_columns, expr_node_t *aggr_node, variant_t *value)
{
    expr_node_t *cntdis_column = NULL;
    uint32 group_id = aggr_node->dis_info.group_id;

    if (value->v_bigint == 0 || group_id == OG_INVALID_ID32) {
        value->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    cntdis_column = (expr_node_t *)cm_galist_get(cntdis_columns, group_id);
    OG_RETURN_IFERR(sql_exec_expr_node(stmt, cntdis_column, value));
    if (!value->is_null && OG_IS_LOB_TYPE(value->type)) {
        OG_SRC_THROW_ERROR(aggr_node->argument->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline bool32 sql_aggr_is_nullaware(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    expr_node_t *aggr_node = NULL;
    sql_func_t *func = NULL;

    if (plan->aggr.items->count == 1) {
        aggr_node = (expr_node_t *)cm_galist_get(plan->aggr.items, 0);
        func = sql_get_func(&aggr_node->value.v_func);
        if (aggr_node->nullaware && (func->aggr_type == AGGR_TYPE_MIN || func->aggr_type == AGGR_TYPE_MAX)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

status_t sql_mtrl_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 par_exe_flag)
{
    uint32 i;
    uint32 avgs;
    uint32 rows;
    variant_t *value = NULL;
    const sql_func_t *func = NULL;
    uint32 aggr_cnt = plan->aggr.items->count;
    aggr_assist_t ogsql_stmt;
    SQL_INIT_AGGR_ASSIST(&ogsql_stmt, stmt, cursor);

    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    OG_RETURN_IFERR(sql_init_aggr_page(stmt, cursor, plan->aggr.items));
    OG_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->aggr.next, plan->aggr.items, &avgs));
    OG_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->aggr.next));

    if (cursor->eof) {
        // signed aggr_fetched to make cursor eof, thus, compare ALL will always returns TRUE
        if (sql_aggr_is_nullaware(stmt, cursor, plan)) {
            cursor->mtrl.aggr_fetched = OG_TRUE;
        }
        return OG_SUCCESS;
    }

    /* prepare value and aggr_nodes */
    uint32 alloc_size = sizeof(variant_t) * (FO_VAL_MAX - 1) + sizeof(expr_node_t *) * aggr_cnt;
    OG_RETURN_IFERR(sql_push(stmt, alloc_size, (void **)&value));
    expr_node_t **aggr_nodes = (expr_node_t **)((char *)value + sizeof(variant_t) * (FO_VAL_MAX - 1));
    for (i = 0; i < aggr_cnt; i++) {
        aggr_nodes[i] = (expr_node_t *)cm_galist_get(plan->aggr.items, i);
    }

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->aggr.next, &cursor->eof));

    rows = 0;
    while (!cursor->eof) {
        rows++;

        for (i = 0; i < aggr_cnt; i++) {
            ogsql_stmt.avg_count = 1;
            ogsql_stmt.aggr_node = aggr_nodes[i];
            func = GET_AGGR_FUNC(ogsql_stmt.aggr_node);
            OG_RETURN_IFERR(sql_exec_expr_node(stmt, AGGR_VALUE_NODE(func, ogsql_stmt.aggr_node), value));
            if (OG_IS_LOB_TYPE(value->type)) {
                OG_RETURN_IFERR(sql_get_lob_value(stmt, value));
            }

            if (ogsql_stmt.aggr_node->dis_info.need_distinct && func->aggr_type == AGGR_TYPE_COUNT) {
                OG_RETURN_IFERR(sql_aggr_get_cntdis_value(stmt, plan->aggr.cntdis_columns, ogsql_stmt.aggr_node,
                    value));
            }

            ogsql_stmt.aggr_type = func->aggr_type;
            OG_RETURN_IFERR(sql_aggr_value(&ogsql_stmt, i, value));
        }

        OGSQL_RESTORE_STACK(stmt);
        OG_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->aggr.next, &cursor->eof));
    }

    OGSQL_RESTORE_STACK(stmt);
    OGSQL_POP(stmt);

    // release next query mtrl
    OG_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->aggr.next));

    if ((avgs > 0 && rows > 0) && (par_exe_flag == OG_FALSE)) {
        OG_RETURN_IFERR(sql_exec_aggr(stmt, cursor, plan->aggr.items, plan));
    }
    if (rows == 0 && sql_aggr_is_nullaware(stmt, cursor, plan)) {
        // signed aggr_fetched to make cursor eof, thus, compare ALL will always returns TRUE
        cursor->mtrl.aggr_fetched = OG_TRUE;
    }

    // Include table with only 0 row.
    return sql_exec_aggr_extra(stmt, cursor, plan->aggr.items, plan);
}

// Only get the maximum through index can invoke this function
static status_t sql_mtrl_index_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 avgs;
    uint32 rows = 0;
    bool32 result = OG_FALSE;
    variant_t *value = NULL;
    const sql_func_t *func = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);

    if (plan->aggr.next->type != PLAN_NODE_SCAN) {
        return OG_ERROR;
    }

    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    OG_RETURN_IFERR(sql_init_aggr_page(stmt, cursor, plan->aggr.items));
    OG_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->aggr.next, plan->aggr.items, &avgs));
    OG_RETURN_IFERR(sql_execute_scan(stmt, cursor, plan->aggr.next));

    sql_table_t *table = plan->aggr.next->scan_p.table;
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];

    for (;;) {
        OG_RETURN_IFERR(sql_fetch_one_part(stmt, tab_cur, table));
        if (!tab_cur->knl_cur->eof) {
            rows++;
            ass.aggr_node = (expr_node_t *)cm_galist_get(plan->aggr.items, 0);
            func = GET_AGGR_FUNC(ass.aggr_node);
            OG_RETURN_IFERR(sql_push(stmt, func->value_cnt * sizeof(variant_t), (void **)&value));
            if (sql_exec_expr_node(stmt, AGGR_VALUE_NODE(func, ass.aggr_node), value) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            ass.aggr_type = func->aggr_type;
            ass.avg_count = 0;
            if (sql_aggr_value(&ass, (uint32)0, value) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            OGSQL_POP(stmt);
        }
        OG_RETURN_IFERR(sql_try_switch_part(stmt, tab_cur, table, &result));
        if (!result) {
            break;
        }
    }
    if (rows == 0 && sql_aggr_is_nullaware(stmt, cursor, plan)) {
        cursor->mtrl.aggr_fetched = OG_TRUE;
    }
    return OG_SUCCESS;
}

void clean_mtrl_seg(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
    mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
    cursor->mtrl.aggr = OG_INVALID_ID32;
}

status_t sql_execute_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
#ifdef TIME_STATISTIC
    clock_t start;
    double timeuse;
    start = cm_cal_time_bengin();
#endif

    OG_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr));

    OG_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr));

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    if (sql_mtrl_aggr(stmt, cursor, plan, cursor->par_ctx.par_exe_flag) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        clean_mtrl_seg(stmt, cursor);
        return OG_ERROR;
    }
    SQL_CURSOR_POP(stmt);

    cursor->eof = OG_FALSE;
#ifdef TIME_STATISTIC
    timeuse = cm_cal_time_end(start);
    stmt->mt_time += timeuse;
#endif
    return OG_SUCCESS;
}

status_t sql_execute_index_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    if (sql_mtrl_index_aggr(stmt, cursor, plan) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        return OG_ERROR;
    }
    SQL_CURSOR_POP(stmt);
    cursor->eof = OG_FALSE;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_reset_default(aggr_var_t *aggr_var)
{
    if (!OG_IS_VARLEN_TYPE(aggr_var->var.type)) {
        MEMS_RETURN_IFERR(memset_s(&aggr_var->var, sizeof(variant_t), 0, sizeof(variant_t)));
    } else {
        // don't reset aggr_var->var.v_text.str and aggr_var->var.v_bin.bytes
        aggr_var->var.type = 0;
        aggr_var->var.is_null = OG_FALSE;
        aggr_var->var.v_text.len = 0;
        aggr_var->var.v_bin.size = 0;
    }
    return OG_SUCCESS;
}

static inline status_t sql_aggr_reset_median(aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = OG_TRUE;
    GET_AGGR_VAR_MEDIAN(aggr_var)->median_count = 0;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.vmid = OG_INVALID_ID32;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.slot = OG_INVALID_ID32;
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_avg(aggr_var_t *aggr_var)
{
    aggr_var->var.v_bigint = 0;
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 0;
    return sql_aggr_reset_default(aggr_var);
}

// for rank/dense_rank
static inline status_t sql_aggr_reset_rank(aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.type = OG_TYPE_INTEGER;
    VALUE(uint32, &aggr_var->var) = 1;
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_min_max(aggr_var_t *aggr_var)
{
    if (OG_IS_VARLEN_TYPE(aggr_var->var.type)) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR(aggr_var);
        aggr_str->str_result.vmid = OG_INVALID_ID32;
        aggr_str->str_result.slot = OG_INVALID_ID32;
    }
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_listagg(aggr_var_t *aggr_var)
{
    /* no need to reset aggr_var->extra  because the possible separator would be calculate only once */
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    aggr_group->total_len = 0;
    aggr_group->aggr_str.str_result.vmid = OG_INVALID_ID32;
    aggr_group->aggr_str.str_result.slot = OG_INVALID_ID32;
    aggr_group->sort_rid.vmid = OG_INVALID_ID32;
    aggr_group->sort_rid.slot = OG_INVALID_ID32;
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_array_agg(aggr_var_t *aggr_var)
{
    aggr_var->var.type = OG_TYPE_ARRAY;
    cm_reset_vm_lob(&aggr_var->var.v_array.value.vm_lob);
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_covar(aggr_var_t *aggr_var)
{
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(aggr_var);
    aggr_covar->ex_count = 0;
    MEMS_RETURN_IFERR(memset_s(&aggr_covar->extra, sizeof(variant_t), 0, sizeof(variant_t)));
    MEMS_RETURN_IFERR(memset_s(&aggr_covar->extra_1, sizeof(variant_t), 0, sizeof(variant_t)));
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_corr(aggr_var_t *aggr_var)
{
    aggr_corr_t *corr = GET_AGGR_VAR_CORR(aggr_var);
    MEMS_RETURN_IFERR(memset_s(&corr->extra, sizeof(corr->extra), 0, sizeof(corr->extra)));
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_stddev(aggr_var_t *aggr_var)
{
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);
    aggr_stddev->ex_count = 0;
    MEMS_RETURN_IFERR(memset_s(&aggr_stddev->extra, sizeof(variant_t), 0, sizeof(variant_t)));
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_init_count(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    aggr_var->var.type = OG_TYPE_BIGINT;
    aggr_var->var.is_null = OG_FALSE;
    aggr_var->var.v_bigint = 0;
    return OG_SUCCESS;
}

static status_t ogsql_aggr_init_type_buf(vmc_t *vmc, galist_t *sort_items, char **type_buf)
{
    if (sort_items == NULL || *type_buf != NULL) {
        return OG_SUCCESS;
    }
    return sql_sort_mtrl_record_types(vmc, MTRL_SEGMENT_CONCAT_SORT, sort_items, type_buf);
}

static inline status_t sql_aggr_init_median(aggr_assist_t *ogsql_stmt, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.type = ogsql_stmt->aggr_node->datatype;
    GET_AGGR_VAR_MEDIAN(aggr_var)->median_count = 0;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.vmid = OG_INVALID_ID32;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.slot = OG_INVALID_ID32;
    ogsql_stmt->avg_count++;
    return ogsql_aggr_init_type_buf(&ogsql_stmt->cursor->vmc, ogsql_stmt->aggr_node->sort_items,
        &(GET_AGGR_VAR_MEDIAN(aggr_var)->type_buf));
}

// for rank/dense_rank
static status_t sql_aggr_init_rank(aggr_assist_t *aggr_ass, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.type = OG_TYPE_INTEGER;
    VALUE(uint32, &aggr_var->var) = 1;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_init_gc_sort_data(sql_cursor_t *cursor)
{
    text_buf_t *sort_concat = &cursor->exec_data.sort_concat;

    /* allocate from vmc if not initialized before */
    if (cursor->exec_data.sort_concat.str == NULL) {
        OG_RETURN_IFERR(vmc_alloc(&cursor->vmc, OG_MAX_ROW_SIZE, (void **)&sort_concat->str));
        sort_concat->max_size = OG_MAX_ROW_SIZE;
        sort_concat->len = 0;
    }

    return OG_SUCCESS;
}

static status_t sql_aggr_init_listagg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    aggr_group->sort_rid.slot = OG_INVALID_ID32;
    aggr_group->sort_rid.vmid = OG_INVALID_ID32;
    aggr_group->total_len = 0;
    aggr_group->aggr_str.str_result.vmid = OG_INVALID_ID32;
    aggr_group->aggr_str.str_result.slot = OG_INVALID_ID32;
    aggr_var->var.type = OG_TYPE_STRING;
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.v_text.len = 0;
    if (ass->aggr_node->sort_items != NULL) {
        ass->avg_count++;
    }
    OG_RETURN_IFERR(ogsql_aggr_init_type_buf(&ass->cursor->vmc, ass->aggr_node->sort_items, &aggr_group->type_buf));
    return sql_aggr_init_gc_sort_data(ass->cursor);
}

static inline status_t sql_aggr_init_array_agg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    array_assist_t array_a;
    id_list_t *vm_list = sql_get_exec_lob_list(ass->stmt);
    aggr_var->var.is_null = OG_FALSE;
    aggr_var->var.type = OG_TYPE_ARRAY;
    aggr_var->var.v_array.count = 0;
    aggr_var->var.v_array.value.type = OG_LOB_FROM_VMPOOL;
    aggr_var->var.v_array.type = ass->aggr_node->typmod.datatype;
    return array_init(&array_a, KNL_SESSION(ass->stmt), ass->stmt->mtrl.pool, vm_list,
        &aggr_var->var.v_array.value.vm_lob);
}

static inline status_t sql_aggr_init_stddev(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.type = ass->aggr_node->datatype;
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);
    aggr_stddev->extra.is_null = OG_TRUE;
    aggr_stddev->ex_count = 0;
    ass->avg_count++;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_init_covar(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(aggr_var);
    aggr_covar->extra.is_null = OG_TRUE;
    aggr_covar->extra_1.is_null = OG_TRUE;
    aggr_covar->ex_count = 0;
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.type = OG_TYPE_NUMBER;
    ass->avg_count++;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_init_corr(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = OG_TRUE;
    aggr_var->var.type = ass->aggr_node->datatype;
    aggr_corr_t *aggr_corr = GET_AGGR_VAR_CORR(aggr_var);
    aggr_corr->extra[CORR_VAR_SUM_X].is_null = OG_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_Y].is_null = OG_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_XX].is_null = OG_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_YY].is_null = OG_TRUE;
    aggr_corr->ex_count = 0;
    ass->avg_count++;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_init_cume_dist(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 0;
    aggr_var->var.type = OG_TYPE_REAL;
    aggr_var->var.is_null = OG_TRUE;
    VALUE(double, &aggr_var->var) = 1;
    ass->avg_count++;
    return OG_SUCCESS;
}

static status_t sql_aggr_init_default(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    expr_node_t *aggr_node = ass->aggr_node;

    if (OG_IS_VARLEN_TYPE(aggr_node->datatype)) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR(aggr_var);
        aggr_str->str_result.vmid = OG_INVALID_ID32;
        aggr_str->str_result.slot = OG_INVALID_ID32;
    }

    if (SECUREC_UNLIKELY(ass->aggr_type == AGGR_TYPE_SUM &&
        aggr_node->value.v_func.orig_func_id == ID_FUNC_ITEM_COUNT)) {
        aggr_var->var.type = OG_TYPE_BIGINT;
        aggr_var->var.is_null = OG_FALSE;
        aggr_var->var.v_bigint = 0;
    } else {
        aggr_var->var.type = aggr_node->datatype;
        aggr_var->var.is_null = OG_TRUE;
        /* modified by OG_RAC_ING, add AGGR_TYPE_AVG_COLLECT for sharding */
        if (ass->aggr_type == AGGR_TYPE_AVG || ass->aggr_type == AGGR_TYPE_AVG_COLLECT) {
            GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 0;
            ass->avg_count++;
            if (aggr_node->datatype <= OG_TYPE_REAL) {
                aggr_var->var.type = OG_TYPE_REAL;
            } else {
                aggr_var->var.type = OG_TYPE_NUMBER;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t sql_reset_sort_segment(sql_stmt_t *ogsql_stmt, sql_cursor_t *cursor)
{
    mtrl_page_t *page = NULL;
    mtrl_segment_t *segment = NULL;

    if (cursor->mtrl.sort_seg == OG_INVALID_ID32) {
        return OG_SUCCESS;
    }
    segment = ogsql_stmt->mtrl.segments[cursor->mtrl.sort_seg];
    if (segment->vm_list.count == 0 || segment->curr_page == NULL) {
        return OG_SUCCESS;
    }
    page = (mtrl_page_t *)segment->curr_page->data;
    if (segment->vm_list.count == 1 && page->rows == 0) {
        return OG_SUCCESS;
    }
    mtrl_close_segment2(&ogsql_stmt->mtrl, segment);
    sql_free_segment_in_vm(ogsql_stmt, cursor->mtrl.sort_seg);
    vm_free_list(ogsql_stmt->mtrl.session, ogsql_stmt->mtrl.pool, &segment->vm_list);
    OG_RETURN_IFERR(mtrl_extend_segment(&ogsql_stmt->mtrl, segment));
    return mtrl_open_segment2(&ogsql_stmt->mtrl, segment);
}

static status_t sql_aggr_init_distinct(aggr_assist_t *ass, plan_node_t *plan)
{
    if (ass->aggr_node->dis_info.need_distinct) {
        hash_segment_t *hash_segment = (hash_segment_t *)ass->cursor->exec_data.aggr_dis;
        hash_table_entry_t *hash_table_entry = (hash_table_entry_t *)((char *)hash_segment + sizeof(hash_segment_t));
        // estimate hash distinct rows
        uint32 bucket_num = sql_get_plan_hash_rows(ass->stmt, plan);
        OG_RETURN_IFERR(vm_hash_table_alloc(&hash_table_entry[ass->aggr_node->dis_info.idx], hash_segment, bucket_num));
        OG_RETURN_IFERR(
            vm_hash_table_init(hash_segment, &hash_table_entry[ass->aggr_node->dis_info.idx], NULL, NULL, NULL));
    }
    return OG_SUCCESS;
}


/*
 * this function is called every time the calculation of one group of rows is done.
 */
status_t sql_init_aggr_values(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, galist_t *aggrs, uint32 *avgs)
{
    const aggr_func_t *aggr_func = NULL;
    aggr_var_t *aggr_var = NULL;
    hash_segment_t *hash_segment = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);

    if (cursor->exec_data.aggr_dis != NULL) {
        hash_segment = (hash_segment_t *)cursor->exec_data.aggr_dis;
        vm_hash_segment_deinit(hash_segment);
        vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, hash_segment, PMA_POOL, HASH_PAGES_HOLD,
            HASH_AREA_SIZE);
    }

    for (uint32 i = 0; i < aggrs->count; i++) {
        ass.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        ass.aggr_type = GET_AGGR_FUNC(ass.aggr_node)->aggr_type;
        aggr_var = sql_get_aggr_addr(cursor, i);
        aggr_func = sql_get_aggr_func(ass.aggr_type);
        OG_RETURN_IFERR(aggr_func->reset(aggr_var));
        OG_RETURN_IFERR(aggr_func->init(&ass, aggr_var));
        OG_RETURN_IFERR(sql_aggr_init_distinct(&ass, plan));
    }

    OG_RETURN_IFERR(sql_reset_sort_segment(stmt, cursor));

    (*avgs) = (uint32)ass.avg_count;
    return OG_SUCCESS;
}

static status_t sql_mtrl_aggr_page_alloc(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 size, void **result)
{
    CM_POINTER4(stmt, cursor, cursor->aggr_page, result);

    /* currently we use only one page(64K) */
    if (cursor->aggr_page->free_begin + size > OG_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) {
        OG_THROW_ERROR(ERR_NO_FREE_VMEM, "one page free size is smaller than needed memory");
        return OG_ERROR;
    }

    *result = sql_get_aggr_free_start_addr(cursor);
    cursor->aggr_page->free_begin += size;

    return OG_SUCCESS;
}

static bool32 sql_judge_func_arg_type(sql_stmt_t *stmt, expr_node_t *aggr_node, variant_t *sep_val)
{
    const sql_func_t *func = GET_AGGR_FUNC(aggr_node);
    OGSQL_SAVE_STACK(stmt);
    if (func->builtin_func_id == ID_FUNC_ITEM_GROUP_CONCAT) {
        if (!OG_IS_STRING_TYPE(sep_val->type)) {
            OG_THROW_ERROR(ERR_INVALID_SEPARATOR, T2S(&func->name));
            return OG_ERROR;
        }
    }
    if (func->builtin_func_id == ID_FUNC_ITEM_LISTAGG) {
        if (!OG_IS_STRING_TYPE(sep_val->type) && !OG_IS_NUMERIC_TYPE(sep_val->type) &&
            !OG_IS_DATETIME_TYPE(sep_val->type)) {
            OG_SRC_THROW_ERROR(aggr_node->loc, ERR_SQL_SYNTAX_ERROR,
                "the separator argument of listagg must be a string or number or date variant.");
            return OG_ERROR;
        }
        if (!OG_IS_STRING_TYPE(sep_val->type)) {
            if (sql_var_as_string(stmt, sep_val) != OG_SUCCESS) {
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
        }
    }
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t if_sepvar_exprn_is_certain(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_t *ori_exprn = sql_get_origin_ref(*exprn);
    
    if (ori_exprn->type == EXPR_NODE_RESERVED) {
        // Non-const reserved words and ROWID not from the curr-query level are not allowed as separator.
        if (!(chk_if_reserved_word_constant(ori_exprn->value.v_res.res_id) || is_ancestor_res_rowid(ori_exprn))) {
            v_ast->result0 = OG_FALSE;
        }
        return OG_SUCCESS;
    }

    if (ori_exprn->type == EXPR_NODE_COLUMN || ori_exprn->type == EXPR_NODE_TRANS_COLUMN) {
        // Column or trans-column from the ancestor-query level are not allowed as separator.
        if (NODE_ANCESTOR(ori_exprn) == 0) {
            v_ast->result0 = OG_FALSE;
        }
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t sql_init_group_concat_sepvar(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_group_concat_t *aggr_group)
{
    expr_tree_t *sep = NULL;
    variant_t sep_val;
    variant_t *sep_cpy = NULL;

    // the first argument is separator, in a SQL, which must be certain value
    sep = aggr_node->argument; /* get the optional argument "separator" */
    sep_cpy = &aggr_group->extra;
    if (sep != NULL) {
        OG_RETURN_IFERR(sql_exec_expr_node(stmt, sep->root, &sep_val));
        OG_RETURN_IFERR(sql_judge_func_arg_type(stmt, aggr_node, &sep_val));

        sep_cpy->type = sep_val.type;
        sep_cpy->is_null = sep_val.is_null;
        if (sep_cpy->is_null == OG_FALSE) {
            expr_node_t *sepvar_exprn = sep->root;
            visit_assist_t v_ast = {0};
            sql_init_visit_assist(&v_ast, NULL, NULL);
            v_ast.result0 = OG_TRUE;
            OG_RETURN_IFERR(visit_expr_node(&v_ast, &sepvar_exprn, if_sepvar_exprn_is_certain));
            if (v_ast.result0 == OG_FALSE) {
                OG_SRC_THROW_ERROR(sep->loc, ERR_SQL_SYNTAX_ERROR, "Argument should be constant.");
                return OG_ERROR;
            }
            /* make the buffer for storing separator in mtrl page, too */
            OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(stmt, cursor, sep_val.v_text.len, (void **)&sep_cpy->v_text.str));
            sep_cpy->v_text.len = sep_val.v_text.len;
            if (sep_val.v_text.len != 0) {
                MEMS_RETURN_IFERR(
                    memcpy_s(sep_cpy->v_text.str, sep_val.v_text.len, sep_val.v_text.str, sep_val.v_text.len));
            }
        }
    } else {
        sep_cpy->is_null = OG_TRUE;
        sep_cpy->type = OG_TYPE_STRING;
        sep_cpy->v_text.len = OG_INVALID_ID32;
        sep_cpy->v_text.str = NULL;
    }
    return OG_SUCCESS;
}

static status_t sql_init_sort_4_listagg(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    OG_RETURN_IFERR(sql_init_group_concat_sepvar(stmt, cursor, aggr_node, aggr_group));
    aggr_var->var.type = aggr_node->datatype;

    if (aggr_node->sort_items != NULL && cursor->mtrl.sort_seg == OG_INVALID_ID32) {
        OG_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_SORT_SEG, NULL, &cursor->mtrl.sort_seg));
        OG_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sort_seg));
    }

    return OG_SUCCESS;
}

static status_t sql_init_sort_4_median(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    if (cursor->mtrl.sort_seg == OG_INVALID_ID32) {
        OG_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_SORT_SEG, NULL, &cursor->mtrl.sort_seg));
        OG_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sort_seg));
    }

    return OG_SUCCESS;
}

static status_t sql_aggr_alloc_listagg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_group_concat_t *aggr_group = NULL;
    OG_RETURN_IFERR(
        sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_group_concat_t), (void **)&aggr_group));
    aggr_var->extra_offset = (uint32)((char *)aggr_group - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_group_concat_t);
    aggr_group->aggr_str.aggr_bufsize = 0;
    aggr_group->total_len = 0;
    aggr_group->aggr_str.str_result.vmid = OG_INVALID_ID32;
    aggr_group->aggr_str.str_result.slot = OG_INVALID_ID32;
    aggr_group->sort_rid.slot = OG_INVALID_ID32;
    aggr_group->type_buf = NULL;

    /*
     * if the aggr function is group_concat, we need to create two buffers for it in the mtrl page.
     * one is for the possible separator, the other for the temporary result for string concat
     */
    return sql_init_sort_4_listagg(ass->stmt, ass->cursor, ass->aggr_node, aggr_var);
}

static status_t sql_aggr_alloc_min_max(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_str_t *aggr_str = NULL;
    if (OG_IS_VARLEN_TYPE(ass->aggr_node->datatype)) {
        OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_str_t), (void **)&aggr_str));
        aggr_var->extra_offset = (uint32)((char *)aggr_str - (char *)aggr_var);
        aggr_var->extra_size = sizeof(aggr_str_t);
        aggr_str->aggr_bufsize = 0;
        aggr_str->str_result.vmid = OG_INVALID_ID32;
        aggr_str->str_result.slot = OG_INVALID_ID32;
    } else {
        aggr_var->extra_offset = 0;
        aggr_var->extra_size = 0;
    }
    return OG_SUCCESS;
}

static inline status_t sql_aggr_alloc_stddev(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_stddev_t *aggr_stddev = NULL;
    OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_stddev_t), (void **)&aggr_stddev));
    aggr_var->extra_offset = (uint32)((char *)aggr_stddev - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_stddev_t);
    aggr_stddev->extra.is_null = OG_TRUE;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_alloc_covar(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_covar_t *aggr_covar = NULL;
    OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_covar_t), (void **)&aggr_covar));
    aggr_var->extra_offset = (uint32)((char *)aggr_covar - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_covar_t);
    aggr_covar->extra.is_null = OG_TRUE;
    aggr_covar->extra_1.is_null = OG_TRUE;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_alloc_corr(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_corr_t *aggr_corr = NULL;
    OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_corr_t), (void **)&aggr_corr));
    aggr_var->extra_offset = (uint32)((char *)aggr_corr - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_corr_t);
    return OG_SUCCESS;
}

// for avg/cume_dist/avg_collect
static inline status_t sql_aggr_alloc_avg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_avg_t *aggr_avg = NULL;
    OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_avg_t), (void **)&aggr_avg));
    aggr_var->extra_offset = (uint32)((char *)aggr_avg - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_avg_t);
    aggr_avg->ex_avg_count = 0;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_alloc_median(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_median_t *aggr_median = NULL;
    OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_median_t), (void **)&aggr_median));
    aggr_var->extra_offset = (uint32)((char *)aggr_median - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_median_t);
    aggr_median->median_count = 0;
    aggr_median->sort_rid.vmid = OG_INVALID_ID32;
    aggr_median->sort_rid.slot = OG_INVALID_ID32;
    aggr_median->type_buf = NULL;
    /* allocate sort segment for median sort */
    return sql_init_sort_4_median(ass->stmt, ass->cursor, ass->aggr_node, aggr_var);
}

static inline status_t sql_aggr_alloc_dense_rank(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_dense_rank_t *aggr_dense_rank = NULL;
    OG_RETURN_IFERR(
        sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_dense_rank_t), (void **)&aggr_dense_rank));
    aggr_var->extra_offset = (uint32)((char *)aggr_dense_rank - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_dense_rank_t);
    return OG_SUCCESS;
}

static inline status_t sql_aggr_alloc_default(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->extra_size = 0;
    aggr_var->extra_offset = 0;
    return OG_SUCCESS;
}

/*
 * aggr_var_t for the aggregate function such as group_concat needs to store the
 * intermediate result in a buffer. as the aggr_var_t itself is allocated in the
 * mtrl page, so we can create the buffer in the mtrl page, too.
 *
 * @Note
 * this function is called only once after the mtrl page created.
 * pay attention to the difference from the timing of sql_init_aggr_values()
 */
status_t sql_init_aggr_page(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs)
{
    const sql_func_t *func = NULL;
    char *aggr_vars_start = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);

    cursor->aggr_page = mtrl_curr_page(&stmt->mtrl, cursor->mtrl.aggr);

    if (cursor->aggr_page->free_begin + aggrs->count * sizeof(aggr_var_t) > OG_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) {
        OG_THROW_ERROR(ERR_TOO_MANY_ARRG);
        return OG_ERROR;
    }
    cursor->aggr_page->free_begin += aggrs->count * sizeof(aggr_var_t);
    cursor->aggr_page->rows = 0;
    aggr_vars_start = ((char *)cursor->aggr_page + sizeof(mtrl_page_t));
    MEMS_RETURN_IFERR(
        memset_s((void *)aggr_vars_start, aggrs->count * sizeof(aggr_var_t), 0, aggrs->count * sizeof(aggr_var_t)));

    for (uint32 i = 0; i < aggrs->count; i++) {
        aggr_var_t *aggr_var = sql_get_aggr_addr(cursor, i);
        ass.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = GET_AGGR_FUNC(ass.aggr_node);
        aggr_var->aggr_type = func->aggr_type;
        ass.aggr_type = func->aggr_type;
        OG_RETURN_IFERR(sql_aggr_alloc_buf(&ass, aggr_var));
    }

    return OG_SUCCESS;
}

status_t sql_fetch_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (cursor->mtrl.aggr_fetched) {
        if (cursor->mtrl.aggr != OG_INVALID_ID32) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = OG_INVALID_ID32;
            cursor->aggr_page = NULL;
        }

        OGSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.aggr_str);

        if (cursor->mtrl.sort_seg != OG_INVALID_ID32) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.sort_seg);
            sql_free_segment_in_vm(stmt, cursor->mtrl.sort_seg);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.sort_seg);
            cursor->mtrl.sort_seg = OG_INVALID_ID32;
        }
        *eof = OG_TRUE;
        return OG_SUCCESS;
    }
    *eof = OG_FALSE;
    cursor->mtrl.aggr_fetched = OG_TRUE;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_alloc_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_appx_cntdis_t *appx_cdist = NULL;
    OG_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_appx_cntdis_t), (void **)&appx_cdist));
    OG_RETURN_IFERR(vmc_alloc_mem(&ass->cursor->vmc, APPX_MAP_SIZE, (void **)&appx_cdist->bitmap));

    aggr_var->extra_offset = (uint32)((char *)appx_cdist - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_appx_cntdis_t);
    return OG_SUCCESS;
}

static inline status_t sql_aggr_init_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->var.type = OG_TYPE_BIGINT;
    aggr_var->var.is_null = OG_FALSE;
    aggr_var->var.v_bigint = 0;
    ass->avg_count++;
    return OG_SUCCESS;
}

static inline status_t sql_aggr_reset_appx_cntdis(aggr_var_t *aggr_var)
{
    aggr_appx_cntdis_t *aggr_appx = GET_AGGR_VAR_APPX_CDIST(aggr_var);
    MEMS_RETURN_IFERR(memset_sp(aggr_appx->bitmap, APPX_MAP_SIZE, 0, APPX_MAP_SIZE));
    return sql_aggr_reset_default(aggr_var);
}

static status_t sql_aggr_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var, variant_t *value)
{
    if (value->is_null) {
        return OG_SUCCESS;
    }

    // 1) calc hash value
    uint32 hashval = value->v_bigint;

    // 2) calc bitmap bucket
    uint32 bucket = hashval & (APPX_MAP_SIZE - 1);

    // 3) calc first non-zero position
    uint8 bits = 0;
    hashval >>= APPX_BITS;
    while (bits < (UINT32_BITS - APPX_BITS) && OG_BIT_TEST(hashval, OG_GET_MASK(bits)) == 0) {
        bits++;
    }
    aggr_appx_cntdis_t *appx = GET_AGGR_VAR_APPX_CDIST(aggr_var);
    appx->bitmap[bucket] = MAX(appx->bitmap[bucket], bits + 1);

    aggr_var->var.is_null = OG_FALSE;
    return OG_SUCCESS;
}

static status_t sql_aggr_calc_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    uint32 eblocks = 0;
    double appx_sum = 0;
    double appx_value = 0;
    aggr_appx_cntdis_t *appx = GET_AGGR_VAR_APPX_CDIST(aggr_var);

    for (uint32 i = 0; i < APPX_MAP_SIZE; ++i) {
        appx_sum += 1.0 / ((uint32)1 << appx->bitmap[i]);
        eblocks += (appx->bitmap[i] == 0) ? 1 : 0;
    }

    if (appx_sum > 0) {
        appx_value = APPX_ALPHA_MM / appx_sum;
        if (appx_value <= APPX_MIN_VAL && eblocks > 0) {
            appx_value = APPX_MAP_SIZE * log((double)APPX_MAP_SIZE / eblocks);
        } else if (appx_value > APPX_MAX_VAL) {
            appx_value = -log(1 - appx_value / ((uint64)1 << UINT32_BITS)) * ((uint64)1 << UINT32_BITS);
        }
    }
    aggr_var->var.v_bigint = (int64)appx_value;
    aggr_var->var.type = OG_TYPE_BIGINT;
    aggr_var->var.is_null = OG_FALSE;
    return OG_SUCCESS;
}


/*
 * **NOTE:**
 * 1. The function must be arranged by alphabetical ascending order.
 * 2. An enum stands for function index was added in ogsql_func.h.
 * if any built-in function added or removed from the following array,
 * please modify the enum definition, too.
 * 3. add function should add the define id in en_sql_aggr_type at ogsql_func.h.
 */
/* **NOTE:** The function must be arranged as the same order of en_sql_aggr_type. */
aggr_func_t g_aggr_func_tab[] = {
    { AGGR_TYPE_NONE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none,
        sql_aggr_calc_none },
    { AGGR_TYPE_AVG, sql_aggr_alloc_avg, sql_aggr_init_default, sql_aggr_reset_avg, sql_aggr_avg, sql_aggr_calc_avg },
    { AGGR_TYPE_SUM, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_sum,
        sql_aggr_calc_none },
    { AGGR_TYPE_MIN, sql_aggr_alloc_min_max, sql_aggr_init_default, sql_aggr_reset_min_max, sql_aggr_min_max,
        sql_aggr_calc_none },
    { AGGR_TYPE_MAX, sql_aggr_alloc_min_max, sql_aggr_init_default, sql_aggr_reset_min_max, sql_aggr_min_max,
        sql_aggr_calc_none },
    { AGGR_TYPE_COUNT, sql_aggr_alloc_default, sql_aggr_init_count, sql_aggr_reset_default, sql_aggr_count,
        sql_aggr_calc_none },
    { AGGR_TYPE_AVG_COLLECT, sql_aggr_alloc_avg, sql_aggr_init_default, sql_aggr_reset_avg, sql_aggr_avg,
        sql_aggr_calc_avg },
    { AGGR_TYPE_GROUP_CONCAT, sql_aggr_alloc_listagg, sql_aggr_init_listagg, sql_aggr_reset_listagg, sql_aggr_listagg,
        sql_aggr_calc_listagg },
    { AGGR_TYPE_STDDEV, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev,
        sql_aggr_calc_stddev },
    { AGGR_TYPE_STDDEV_POP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev,
        sql_aggr_calc_stddev },
    { AGGR_TYPE_STDDEV_SAMP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev,
        sql_aggr_calc_stddev },
    { AGGR_TYPE_LAG, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none,
        sql_aggr_calc_none },
    { AGGR_TYPE_ARRAY_AGG, sql_aggr_alloc_default, sql_aggr_init_array_agg, sql_aggr_reset_array_agg,
        sql_aggr_array_agg, sql_aggr_calc_none },
    { AGGR_TYPE_NTILE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none,
        sql_aggr_calc_none },
    { AGGR_TYPE_MEDIAN, sql_aggr_alloc_median, sql_aggr_init_median, sql_aggr_reset_median, sql_aggr_median,
        sql_aggr_calc_median },
    { AGGR_TYPE_CUME_DIST, sql_aggr_alloc_avg, sql_aggr_init_cume_dist, sql_aggr_reset_avg, sql_aggr_cume_dist,
        sql_aggr_calc_cume_dist },
    { AGGR_TYPE_VARIANCE, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev,
        sql_aggr_calc_stddev },
    { AGGR_TYPE_VAR_POP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev,
        sql_aggr_calc_stddev },
    { AGGR_TYPE_VAR_SAMP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev,
        sql_aggr_calc_stddev },
    { AGGR_TYPE_COVAR_POP, sql_aggr_alloc_covar, sql_aggr_init_covar, sql_aggr_reset_covar, sql_aggr_covar,
        sql_aggr_calc_covar },
    { AGGR_TYPE_COVAR_SAMP, sql_aggr_alloc_covar, sql_aggr_init_covar, sql_aggr_reset_covar, sql_aggr_covar,
        sql_aggr_calc_covar },
    { AGGR_TYPE_CORR, sql_aggr_alloc_corr, sql_aggr_init_corr, sql_aggr_reset_corr, sql_aggr_corr, sql_aggr_calc_corr },
    { AGGR_TYPE_DENSE_RANK, sql_aggr_alloc_dense_rank, sql_aggr_init_rank, sql_aggr_reset_rank, sql_aggr_dense_rank,
        sql_aggr_calc_none },
    { AGGR_TYPE_FIRST_VALUE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none,
        sql_aggr_calc_none },
    { AGGR_TYPE_LAST_VALUE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none,
        sql_aggr_calc_none },
    { AGGR_TYPE_RANK, sql_aggr_alloc_default, sql_aggr_init_rank, sql_aggr_reset_rank, sql_aggr_rank,
        sql_aggr_calc_none },
    { AGGR_TYPE_APPX_CNTDIS, sql_aggr_alloc_appx_cntdis, sql_aggr_init_appx_cntdis, sql_aggr_reset_appx_cntdis,
        sql_aggr_appx_cntdis, sql_aggr_calc_appx_cntdis },
};
