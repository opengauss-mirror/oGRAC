/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "ogsql_merge_join.h"
#include "plan_rbo.h"

#define CMP_GREAT 1
#define CMP_EQUAL 0
#define CMP_LESS (-1)

static inline status_t og_get_merge_col(sql_stmt_t *statement, expr_tree_t *exprtr,
    variant_t *col, int32 *result, int32 default_val)
{
    OG_RETURN_IFERR(sql_exec_expr(statement, exprtr, col));
    if (!col->is_null) {
        sql_keep_stack_variant(statement, col);
        if (OG_IS_LOB_TYPE((col)->type)) {
            return sql_get_lob_value(statement, col);
        }
        return OG_SUCCESS;
    }
    *(result) = default_val;
    return OG_SUCCESS;
}

/*
 * Determine whether sorting is required by analyzing table scan methods in the execution plan
 * Index Scan, ORDER BY, and Merge Join can all produce ordered output, consider only base table index scan.
 * For composite indexes,the sorting columns must indeed adhere to the leftmost prefix rule.
 *
 */
static bool32 og_requires_explicit_sort(plan_node_t *plan_node, galist_t *key_item_lst)
{
    // consider only base tbl scans
    OG_RETVALUE_IFTRUE(plan_node->type != PLAN_NODE_SCAN, OG_TRUE);

    sql_table_t *tbl = plan_node->scan_p.table;
    OG_RETVALUE_IFTRUE(tbl->type != NORMAL_TABLE, OG_TRUE);

    // require index scan
    if (tbl->index == NULL || tbl->index_ffs || tbl->index_skip_scan || tbl->index->parted ||
        IS_REVERSE_INDEX(tbl->index)) {
        return OG_TRUE;
    }

    if (key_item_lst->count > tbl->index->column_count) {
        return OG_TRUE;
    }
    
    var_column_t var_col;
    expr_node_t *exprn = NULL;
    sort_item_t *sort_key = NULL;
    sort_direction_t idx_dir = (tbl->index_dsc ? SORT_MODE_DESC : SORT_MODE_ASC);
    for (uint32 i = 0; i < key_item_lst->count; ++i) {
        sort_key = (sort_item_t *)cm_galist_get(key_item_lst, i);
        exprn = sort_key->expr->root;
        // consider original column
        OG_RETVALUE_IFTRUE(exprn->type != EXPR_NODE_COLUMN, OG_TRUE);
        var_col = exprn->value.v_col;
        OG_RETVALUE_IFTRUE(var_col.ancestor > 0, OG_TRUE);
        OG_RETVALUE_IFTRUE(var_col.tab != tbl->id || var_col.col != tbl->index->columns[i], OG_TRUE);

        // the sort direction must match the index scan direction.
        OG_RETVALUE_IFTRUE(sort_key->direction != idx_dir, OG_TRUE);
    }
 
    return OG_FALSE;
}

static status_t og_mtrl_sort_for_merge(sql_stmt_t *statement, sql_cursor_t *sql_cur, join_info_t *join_info,
                                          plan_node_t *plan_node, uint32 batch_size)
{
    if (batch_size == 0) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "merge_sort_batch_size is invalid");
        return OG_ERROR;
    }
    uint32 row_num = 0;
    bool32 end = OG_FALSE;
    status_t status = OG_SUCCESS;
    OG_RETURN_IFERR(SQL_CURSOR_PUSH(statement, sql_cur));
    OGSQL_SAVE_STACK(statement);

    while (row_num < batch_size) {
        status = sql_fetch_for_join(statement, sql_cur, plan_node, &end);
        OG_BREAK_IF_TRUE(status != OG_SUCCESS);
        OG_BREAK_IF_TRUE(end);
        row_num++;

        status = sql_mtrl_merge_sort_insert(statement, sql_cur, join_info);
        OG_BREAK_IF_TRUE(status != OG_SUCCESS);

        OGSQL_RESTORE_STACK(statement);
    }
    
    OGSQL_RESTORE_STACK(statement);
    SQL_CURSOR_POP(statement);
    return status;
}

static status_t og_calc_sort_cursor_rows(mtrl_context_t *mtrl_ctx, mtrl_sort_cursor_t *mtrl_cur)
{
    OG_RETVALUE_IFTRUE(mtrl_cur->segment->vm_list.count == 1 || mtrl_cur->segment->level != 0, OG_SUCCESS);

    uint32 next_page_id = 0;
    uint64 row_count = 0;
    vm_page_t *current_valid_page = NULL;
    vm_ctrl_t *vm_ctrl = NULL;
    mtrl_page_t *mtrl_page = NULL;

    for (uint32 vm_page_id = mtrl_cur->segment->vm_list.first; vm_page_id != OG_INVALID_ID32;
            vm_page_id = next_page_id) {
        OG_RETURN_IFERR(vm_open(mtrl_ctx->session, mtrl_ctx->pool, vm_page_id, &current_valid_page));
        mtrl_page = (mtrl_page_t *)current_valid_page->data;
        row_count += mtrl_page->rows;
        vm_ctrl = vm_get_ctrl(mtrl_ctx->pool, vm_page_id);
        next_page_id = vm_ctrl->next;
        vm_close(mtrl_ctx->session, mtrl_ctx->pool, vm_page_id, VM_ENQUE_TAIL);
    }
    // fix the cursor rows so that fetch across page rows
    mtrl_cur->part.rows = row_count;
    return OG_SUCCESS;
}

static status_t og_prepare_sort_for_merge(sql_stmt_t *statement, sql_cursor_t *sql_cur, join_info_t *join_info)
{
    sql_reset_mtrl(statement, sql_cur);
    return sql_sort_mtrl_open_segment(statement, sql_cur, MTRL_SEGMENT_QUERY_SORT, join_info->key_items);
}

static status_t og_sort_process_remaining_page(sql_stmt_t *statement, sql_cursor_t *sql_cur)
{
    return mtrl_sort_segment(&statement->mtrl, sql_cur->mtrl.sort.sid);
}

static void og_disable_seg_sort(sql_stmt_t *statement, sql_cursor_t *sql_cur)
{
    mtrl_segment_t *mtrl_seg = statement->mtrl.segments[sql_cur->mtrl.sort.sid];
    mtrl_seg->cmp_items = NULL;
}

static status_t og_fetch_first_sorted_row(sql_stmt_t *statement, sql_cursor_t *sql_cur, bool32 *end)
{
    OG_RETURN_IFERR(mtrl_open_cursor(&statement->mtrl, sql_cur->mtrl.sort.sid, &sql_cur->mtrl.cursor));
    OG_RETURN_IFERR(og_calc_sort_cursor_rows(&statement->mtrl, &sql_cur->mtrl.cursor.sort));
    row_addr_t *rows = sql_cur->exec_data.join;
    return mtrl_fetch_merge_sort_row(&statement->mtrl, &sql_cur->mtrl.cursor, rows, sql_cur->table_count, end);
}

static status_t og_prepare_sorted_input(sql_stmt_t *statement, join_sort_input_t *sort_input, bool32 *end)
{
    sql_cursor_t *sql_cur = sort_input->sql_cur;
    join_info_t *join_info = sort_input->join_info;
    plan_node_t *plan_node = sort_input->plan_node;
    uint32 merge_batch_size = sort_input->batch_size;
    if (plan_node == NULL || join_info->key_items == NULL) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(og_prepare_sort_for_merge(statement, sql_cur, join_info));

    bool32 need_sort = og_requires_explicit_sort(plan_node, join_info->key_items);
    if (!need_sort) {
        og_disable_seg_sort(statement, sql_cur);
    }

    status_t ret = og_mtrl_sort_for_merge(statement, sql_cur, join_info, plan_node, merge_batch_size);
    sql_sort_mtrl_close_segment(statement, sql_cur);
    OG_RETURN_IFERR(ret);

    if (need_sort) {
        OG_RETURN_IFERR(og_sort_process_remaining_page(statement, sql_cur));
    }
    
    return og_fetch_first_sorted_row(statement, sql_cur, end);
}

static status_t og_prepare_merge_inputs(sql_stmt_t *statement, join_plan_t *join_p, join_data_t *m_join, bool32 *end)
{
    uint32 batch_size = join_p->batch_size;
    join_sort_input_t l_join_sort_input = {
        .sql_cur = m_join->left,
        .join_info = &join_p->left_merge,
        .plan_node = join_p->left,
        .batch_size = batch_size
    };

    if (og_prepare_sorted_input(statement, &l_join_sort_input, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: sort join->left error", __func__);
        return OG_ERROR;
    }
    if (*end) {
        m_join->left->eof = OG_TRUE;
        return OG_SUCCESS;
    }

    if (sql_execute_for_join(statement, m_join->right, join_p->right) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: exec join->right error", __func__);
        return OG_ERROR;
    }

    join_sort_input_t r_join_sort_input = {
        .sql_cur = m_join->right,
        .join_info = &join_p->right_merge,
        .plan_node = join_p->right,
        .batch_size = batch_size
    };
    return og_prepare_sorted_input(statement, &r_join_sort_input, end);
}

status_t og_merge_join_execute(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    join_plan_t *join_p = &plan_node->join_p;
    join_data_t *m_join = &sql_cur->m_join[join_p->mj_pos];

    OG_RETURN_IFERR(sql_mtrl_alloc_cursor(statement, sql_cur, &m_join->left, &join_p->left_merge, join_p->left));
    OG_RETURN_IFERR(sql_mtrl_alloc_cursor(statement, sql_cur, &m_join->right, &join_p->right_merge, join_p->right));
    sql_reset_cursor_eof(sql_cur, &join_p->left_merge, OG_FALSE);
    sql_reset_cursor_eof(sql_cur, &join_p->right_merge, OG_FALSE);

    if (sql_execute_for_join(statement, m_join->left, join_p->left) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: exec join->left error", __func__);
        return OG_ERROR;
    }
    return og_prepare_merge_inputs(statement, join_p, m_join, end);
}

static inline int32 og_get_merge_cmp_res(cmp_node_t *cmp, int32 cmp_result)
{
    bool32 conv_result = OG_FALSE;
    sql_convert_match_result(cmp->type, cmp_result, &conv_result);

    OG_RETVALUE_IFTRUE(conv_result, CMP_EQUAL);

    if (cmp->type != CMP_TYPE_EQUAL) {
        return CMP_LESS;
    }

    if (cmp_result > 0) {
        return CMP_GREAT;
    }
    return CMP_LESS;
}

static status_t og_match_merge_cmp_list(sql_stmt_t *statement, join_plan_t *join_plan, int32 *res)
{
    *res = CMP_EQUAL;
    int32 cmp_result;
    variant_t left_var;
    variant_t right_var;
    uint32 cmp_idx = 0;
    status_t status = OG_SUCCESS;

    OGSQL_SAVE_STACK(statement);
    while (cmp_idx < join_plan->cmp_list->count) {
        cmp_node_t *cmp = (cmp_node_t *)cm_galist_get(join_plan->cmp_list, cmp_idx++);
        status = og_get_merge_col(statement, cmp->left, &left_var, res, CMP_LESS);
        OG_BREAK_IF_ERROR(status);
        OG_BREAK_IF_TRUE(left_var.is_null);
        status = og_get_merge_col(statement, cmp->right, &right_var, res, CMP_GREAT);
        OG_BREAK_IF_ERROR(status);
        OG_BREAK_IF_TRUE(right_var.is_null);
        if (sql_compare_variant(statement, &left_var, &right_var, &cmp_result) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }
        *res = og_get_merge_cmp_res(cmp, cmp_result);
        OG_BREAK_IF_TRUE(*res != CMP_EQUAL);
    }
    OGSQL_RESTORE_STACK(statement);
    return status;
}

static void og_save_savepoint_on_match(mtrl_cursor_t *mtrl_cur, mtrl_savepoint_t *savepoint)
{
    if (mtrl_cur->sort.slot > 0) {
        savepoint->rownum = mtrl_cur->sort.rownum;
        savepoint->vm_row_id.vmid = mtrl_cur->sort.vmid;
        savepoint->vm_row_id.slot = mtrl_cur->sort.slot - 1;
        return;
    }
    OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "invalid mtrl sort slot");
}

static status_t og_seek_savepoint_on_match(sql_stmt_t *statement, join_data_t *m_join,
    join_plan_t *join_plan, bool32 *end)
{
    sql_cursor_t *l_sql_cur = m_join->left;
    sql_cursor_t *r_sql_cur = m_join->right;
    row_addr_t *rows = NULL;
    int32 res;
    
    while (OG_TRUE) {
        OG_RETURN_IFERR(og_match_merge_cmp_list(statement, join_plan, &res));
        if (res == CMP_LESS) {
            rows = l_sql_cur->exec_data.join;
            OG_RETURN_IFERR(mtrl_fetch_merge_sort_row(&statement->mtrl, &l_sql_cur->mtrl.cursor,
                rows, l_sql_cur->table_count, end));
        } else if (res == CMP_GREAT) {
            rows = r_sql_cur->exec_data.join;
            OG_RETURN_IFERR(mtrl_fetch_merge_sort_row(&statement->mtrl, &r_sql_cur->mtrl.cursor,
                rows, r_sql_cur->table_count, end));
        } else {
            og_save_savepoint_on_match(&r_sql_cur->mtrl.cursor, &r_sql_cur->mtrl.save_point);
            *end = OG_FALSE;
            break;
        }
        OG_BREAK_IF_TRUE(*end);
    }

    return OG_SUCCESS;
}

static status_t og_merge_join_advance(sql_stmt_t *statement, join_data_t *m_join, join_plan_t *join_plan,
                                                  bool32 *end, bool32 r_end)
{
    sql_cursor_t *l_sql_cur = m_join->left;
    row_addr_t *rows = l_sql_cur->exec_data.join;

    if (mtrl_fetch_merge_sort_row(&statement->mtrl, &l_sql_cur->mtrl.cursor,
        rows, l_sql_cur->table_count, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: fetch join->left mtrl row error", __func__);
        return OG_ERROR;
    }
    OG_RETVALUE_IFTRUE(*end, OG_SUCCESS);

    mtrl_savepoint_t curr_save;
    sql_cursor_t *r_sql_cur = m_join->right;
    og_save_savepoint_on_match(&r_sql_cur->mtrl.cursor, &curr_save);
    rows = r_sql_cur->exec_data.join;

    if (mtrl_fetch_savepoint(&statement->mtrl, r_sql_cur->mtrl.sort.sid, &r_sql_cur->mtrl.save_point,
        &r_sql_cur->mtrl.cursor, rows, r_sql_cur->table_count) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: fetch join->right mtrl save_point row error", __func__);
        return OG_ERROR;
    }

    int32 res;
    OG_RETURN_IFERR(og_match_merge_cmp_list(statement, join_plan, &res));
    if (res == CMP_EQUAL) {
        *end = OG_FALSE;
        return OG_SUCCESS;
    }
    if (r_end) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }

    if (mtrl_fetch_savepoint(&statement->mtrl, r_sql_cur->mtrl.sort.sid, &curr_save,
        &r_sql_cur->mtrl.cursor, rows, r_sql_cur->table_count) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: fetch join->right mtrl curr_save row error", __func__);
        return OG_ERROR;
    }

    return og_seek_savepoint_on_match(statement, m_join, join_plan, end);
}

static status_t og_merge_join_match_next(sql_stmt_t *statement, sql_cursor_t *sql_cur,
    join_plan_t *join_plan, bool32 *end)
{
    join_data_t *join_data = &sql_cur->m_join[join_plan->mj_pos];
    sql_cursor_t *r_sql_cur = join_data->right;
    if (r_sql_cur->mtrl.save_point.vm_row_id.vmid == OG_INVALID_ID32) {
        return og_seek_savepoint_on_match(statement, join_data, join_plan, end);
    }

    if (mtrl_fetch_merge_sort_row(&statement->mtrl, &r_sql_cur->mtrl.cursor,
        r_sql_cur->exec_data.join, r_sql_cur->table_count, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: fetch right mtrl row error", __func__);
        return OG_ERROR;
    }
    if (*end) {
        return og_merge_join_advance(statement, join_data, join_plan, end, OG_TRUE);
    }

    int32 cmp_res;
    if (og_match_merge_cmp_list(statement, join_plan, &cmp_res) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: match mergejoin cond error", __func__);
        return OG_ERROR;
    }
    OG_RETSUC_IFTRUE(cmp_res == CMP_EQUAL);

    return og_merge_join_advance(statement, join_data, join_plan, end, OG_FALSE);
}

static status_t og_merge_join_find_match(sql_stmt_t *statement, sql_cursor_t *sql_cur,
    join_plan_t *join_plan, bool32 *end)
{
    bool32 match_found = OG_FALSE;

    while (!match_found) {
        if (og_merge_join_match_next(statement, sql_cur, join_plan, end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[%s]: og_merge_join_match_next error", __func__);
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(*end);
        if (match_merge_join_final_cond(statement, sql_cur->cond, join_plan->filter,
            &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[%s]: match_merge_join_final_cond error", __func__);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t og_reset_cursor_for_merge(sql_stmt_t *statement, sql_cursor_t *sql_cur)
{
    mtrl_close_cursor(&statement->mtrl, &sql_cur->mtrl.cursor);
    if (sql_cur->mtrl.sort.sid == OG_INVALID_ID32) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "sql_cur->mtrl.sort.sid(%u) != OG_INVALID_ID32(%u)",
            sql_cur->mtrl.sort.sid, OG_INVALID_ID32);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(mtrl_open_cursor(&statement->mtrl, sql_cur->mtrl.sort.sid, &sql_cur->mtrl.cursor));
    if (og_calc_sort_cursor_rows(&statement->mtrl, &sql_cur->mtrl.cursor.sort) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: og_calc_sort_cursor_rows error", __func__);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_prepare_fetch_next(sql_stmt_t *statement, join_data_t *m_join)
{
    if (og_reset_cursor_for_merge(statement, m_join->left) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: og_reset_cursor_for_merge error", __func__);
        return OG_ERROR;
    }

    bool32 tmp_end = OG_FALSE;
    if (mtrl_fetch_merge_sort_row(&statement->mtrl, &m_join->left->mtrl.cursor,
        m_join->left->exec_data.join, m_join->left->table_count, &tmp_end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[%s]: mtrl_fetch_merge_sort_row error", __func__);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t og_merge_join_fetch(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    join_plan_t *join_plan = &plan_node->join_p;
    join_data_t *m_join = &sql_cur->m_join[join_plan->mj_pos];
    if (sql_cur->eof || !m_join->left || !m_join->right || m_join->left->eof) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    sql_cur->last_table = get_last_table_id(plan_node);
    join_sort_input_t r_join_sort_input = {
        .sql_cur = m_join->right,
        .join_info = &join_plan->right_merge,
        .plan_node = join_plan->right,
        .batch_size = join_plan->batch_size
    };
    bool32 any_end = OG_FALSE;
    while (OG_TRUE) {
        if (og_merge_join_find_match(statement, sql_cur, join_plan, &any_end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[%s]: og_merge_join_find_match error", __func__);
            return OG_ERROR;
        }
        if (!any_end) {
            *end = OG_FALSE;
            break;
        }
        
        if (og_prepare_sorted_input(statement, &r_join_sort_input, &any_end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[%s]: og_prepare_sorted_input error", __func__);
            return OG_ERROR;
        }
        if (!any_end) {
            if (og_prepare_fetch_next(statement, m_join) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[%s]: og_prepare_fetch_next error", __func__);
                return OG_ERROR;
            }
        } else {
            if (og_prepare_merge_inputs(statement, join_plan, m_join, end) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[%s]: og_prepare_merge_inputs error", __func__);
                return OG_ERROR;
            }
            OG_BREAK_IF_TRUE(*end);
        }
        sql_mtrl_init_savepoint(m_join->right);
    }
    return OG_SUCCESS;
}

void og_merge_join_free(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node)
{
    join_data_t *join_data = &sql_cur->m_join[plan_node->join_p.mj_pos];
    sql_free_merge_join_data(statement, join_data);
}
