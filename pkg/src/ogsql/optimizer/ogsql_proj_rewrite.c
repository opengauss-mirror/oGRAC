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
#include "ogsql_proj_rewrite.h"
#include "ogsql_hint_verifier.h"
#include "ogsql_optim_common.h"
#include "dml_parser.h"

#define PROJ_REWRITE_MAX_TREE_DEPTH 256

static bool32 check_select_type_4_elimination_impl(select_node_t *node, uint32 depth)
{
    if (depth > PROJ_REWRITE_MAX_TREE_DEPTH) {
        return OG_FALSE;
    }
    if (node->type == SELECT_NODE_QUERY) {
        return OG_TRUE;
    } else if (node->type == SELECT_NODE_UNION_ALL) {
        return (check_select_type_4_elimination_impl(node->left, depth + 1) &&
            check_select_type_4_elimination_impl(node->right, depth + 1));
    }
    return OG_FALSE;
}

static bool32 check_select_type_4_elimination(select_node_t *node)
{
    return check_select_type_4_elimination_impl(node, 0);
}

static bool32 is_can_proj_eliminate(sql_table_t *tbl)
{
    if (tbl->view_dml ||
        (tbl->type != SUBSELECT_AS_TABLE && tbl->type != VIEW_AS_TABLE) ||
        tbl->subslct_tab_usage != SUBSELECT_4_NORMAL_JOIN) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] The table does not support proj elimination,"
            "type: %d, subslct_tab_usage: %d", tbl->type, tbl->subslct_tab_usage);
        return OG_FALSE;
    }

    select_node_t *node = tbl->select_ctx->root;
    if (!check_select_type_4_elimination(node)) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] The node does not support proj elimination,"
            "type: %d", node->type);
        return OG_FALSE;
    }

    return OG_TRUE;
}

static inline bool32 has_window_func_in_order_by(sql_query_t *qry)
{
    uint32 i = 0;
    while (i < qry->sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(qry->sort_items, i);
        if (item->expr->root->type == EXPR_NODE_OVER) {
            return OG_TRUE;
        }
        i++;
    }

    return OG_FALSE;
}

static bool32 check_if_support_eliminate4proj(sql_query_t *qry)
{
    if (NO_NEED_ELIMINATE(qry)) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] The subquery does not support proj elimination,"
            "group sets: %d, has_distinct: %d, winsort_count: %d, ssa_count: %d",
            qry->group_sets->count, qry->has_distinct, qry->winsort_list->count, qry->ssa.count);
        return OG_FALSE;
    }

    if (has_window_func_in_order_by(qry)) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] The window function is referenced by ORDER BY,"
            "not support proj elimination.");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 query_contains_rs_column(sql_table_t *tbl, uint32 col_id)
{
    bilist_node_t *node = cm_bilist_head(&tbl->query_fields);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        query_field_t *qry_fld = BILIST_NODE_OF(query_field_t, node, bilist_node);
        if (qry_fld->col_id < col_id) {
            continue;
        }
        return qry_fld->col_id == col_id;
    }

    return OG_FALSE;
}

static bool32 is_reserved_field(rs_column_t *rs_column)
{
    if (rs_column->type == RS_COL_COLUMN &&
        (rs_column->v_col.is_rowid || rs_column->v_col.is_rownodeid)) {
        return OG_TRUE;
    }

    if (rs_column->type == RS_COL_CALC) {
        if (NODE_IS_RES_ROWID(rs_column->expr->root) || NODE_IS_RES_ROWNODEID(rs_column->expr->root) ||
            NODE_IS_RES_ROWNUM(rs_column->expr->root)) {
            return OG_TRUE;
        }
    }

    if (!OG_BIT_TEST(rs_column->rs_flag, RS_EXIST_ALIAS)) {
        if (cm_text_str_equal(&rs_column->name, "ROWID") || cm_text_str_equal(&rs_column->name, "ROWNODEID") ||
            cm_text_str_equal(&rs_column->name, "ROWSCN")) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static status_t replace_rs_col_with_null(sql_stmt_t *statement, rs_column_t *rs_column)
{
    if (sql_create_expr(statement, &rs_column->expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    expr_node_t *root = NULL;
    if (sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    root->owner = rs_column->expr;
    root->value.v_res.res_id = RES_WORD_NULL;
    root->datatype = OG_DATATYPE_OF_NULL;
    root->type = EXPR_NODE_RESERVED;
    rs_column->expr->root = root;
    rs_column->datatype = OG_DATATYPE_OF_NULL;
    rs_column->type = RS_COL_CALC;
    return OG_SUCCESS;
}

static status_t eliminate_proj_in_expr(visit_assist_t *v_ast, expr_node_t **exprn);
static status_t handle_column_proj_elimination(visit_assist_t *v_ast, expr_node_t **exprn)
{
    var_column_t *var_col = &(*exprn)->value.v_col;
    if (var_col->ancestor != 0) {
        v_ast->result0 = OG_FALSE;
        return OG_ERROR;
    }

    bool32 is_valid_table = (v_ast->result1 == OG_INVALID_ID32 || v_ast->result1 == var_col->tab);
    if (!v_ast->result0 && !is_valid_table) {
        v_ast->result0 = OG_FALSE;
    }
    v_ast->result1 = var_col->tab;
    og_sql_table_release_query_field(v_ast->param0, var_col);
    return OG_SUCCESS;
}

static status_t eliminate_winsort_rs_col(visit_assist_t *v_ast, sql_query_t *qry, expr_node_t **exprn)
{
    uint32 node_id = VALUE_PTR(var_vm_col_t, &(*exprn)->value)->id;
    rs_column_t *rs_column_ws = (rs_column_t *)cm_galist_get(qry->winsort_rs_columns, node_id);

    if (rs_column_ws->type == RS_COL_COLUMN && rs_column_ws->v_col.ancestor > 0) {
        return OG_SUCCESS;
    }

    if (rs_column_ws->type == RS_COL_COLUMN) {
        og_sql_table_release_query_field(qry, &rs_column_ws->v_col);
        rs_column_ws->win_rs_refs--;
        if (rs_column_ws->win_rs_refs == 0) {
            OG_RETURN_IFERR(replace_rs_col_with_null(v_ast->stmt, rs_column_ws));
        }
    } else if (rs_column_ws->expr && rs_column_ws->expr->root) {
        OG_RETURN_IFERR(visit_expr_node(v_ast, &rs_column_ws->expr->root, eliminate_proj_in_expr));
    }

    return OG_SUCCESS;
}

static status_t handle_group_proj_elimination(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if (NODE_VM_ANCESTOR(*exprn)) {
        return OG_SUCCESS;
    }

    sql_query_t *qry = (sql_query_t *)v_ast->param0;
    if (QUERY_HAS_SINGLE_GROUP_BY(qry)) {
        expr_node_t *origin_ref = sql_get_origin_ref(*exprn);
        return visit_expr_node(v_ast, &origin_ref, eliminate_proj_in_expr);
    }

    return eliminate_winsort_rs_col(v_ast, qry, exprn);
}

static void set_expr_node_as_int_const(expr_node_t *exprn, int32 value)
{
    exprn->type = EXPR_NODE_CONST;
    exprn->datatype = OG_TYPE_INTEGER;
    exprn->value.type = OG_TYPE_INTEGER;
    exprn->value.is_null = OG_FALSE;
    exprn->value.v_int = value;
    exprn->optmz_info.idx = 0;
    exprn->optmz_info.mode = OPTIMIZE_AS_CONST;
}

static void set_aggr_node_as_min(expr_node_t *exprn)
{
    set_expr_node_as_int_const(exprn->argument->root, 0);
    exprn->argument->next = NULL;
    exprn->value.v_func.func_id = ID_FUNC_ITEM_MIN;
    exprn->value.v_func.orig_func_id = ID_FUNC_ITEM_MIN;
    exprn->value.v_func.pack_id = OG_INVALID_ID32;
    exprn->dis_info.need_distinct = OG_FALSE;
    exprn->datatype = OG_TYPE_INTEGER;
    exprn->sort_items = NULL;
}

static status_t handle_aggr_proj_elimination(visit_assist_t *v_ast, expr_node_t **exprn)
{
    sql_query_t *qry = (sql_query_t *)v_ast->param0;
    uint32 node_id = NODE_VALUE(uint32, *exprn);
    expr_node_t *aggr_exprn = (expr_node_t *)cm_galist_get(qry->aggrs, node_id);
    int32 ref_count = aggr_exprn->value.v_func.aggr_ref_count;

    ref_count--;
    if (ref_count == 0) {
        OG_RETURN_IFERR(visit_expr_node(v_ast, &aggr_exprn, eliminate_proj_in_expr));
        set_aggr_node_as_min(aggr_exprn);
    }

    return OG_SUCCESS;
}

static status_t process_winsort_deletion(visit_assist_t *v_ast, sql_query_t *qry, expr_node_t *exprn, uint32 i)
{
    uint32 ori_flag = v_ast->excl_flags;
    CM_CLEAN_FLAG(v_ast->excl_flags, VA_EXCL_WIN_SORT);
    OG_RETURN_IFERR(visit_expr_node(v_ast, &exprn, eliminate_proj_in_expr));
    v_ast->excl_flags = ori_flag;
    cm_galist_delete(qry->winsort_list, i);
    if (qry->winsort_list->count > 0 && exprn->win_args->is_rs_node) {
        set_winsort_rs_node_flag(qry);
    }
    return OG_SUCCESS;
}

static status_t handle_winsort_proj_elimination(visit_assist_t *v_ast, expr_node_t **exprn)
{
    sql_query_t *qry = (sql_query_t *)v_ast->param0;
    expr_node_t *win_exprn = NULL;
    uint32 win_count = qry->winsort_list->count;
    uint32 i = 0;

    while (i < win_count) {
        win_exprn = (expr_node_t *)cm_galist_get(qry->winsort_list, i);
        if (*exprn!= win_exprn) {
            i++;
            continue;
        }
        OG_RETURN_IFERR(process_winsort_deletion(v_ast, qry, win_exprn, i));
        break;
    }

    uint32 node_id = VALUE_PTR(var_vm_col_t, &(*exprn)->value)->id;
    rs_column_t *rs_column_ws = (rs_column_t *)cm_galist_get(qry->winsort_rs_columns, node_id);
    return replace_rs_col_with_null(v_ast->stmt, rs_column_ws);
}

static void delete_func_expr_from_table(visit_assist_t *v_ast, expr_node_t **func_node)
{
    sql_query_t *qry = (sql_query_t *)v_ast->param0;
    sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, v_ast->result1);
    bilist_node_t *node = cm_bilist_head(&tbl->func_expr);

    for (; node!= NULL; node = BINODE_NEXT(node)) {
        func_expr_t *func = BILIST_NODE_OF(func_expr_t, node, bilist_node);
        if (sql_expr_node_equal(v_ast->stmt, func->expr, *func_node, NULL)) {
            cm_bilist_del(node, &tbl->func_expr);
            break;
        }
    }
}

static void update_result_value(visit_assist_t *v_ast, bool32 ori_result0, uint32 table_id)
{
    v_ast->result0 = ori_result0 && v_ast->result0;
    bool32 is_same_table = (v_ast->result1 == OG_INVALID_ID32 || table_id == OG_INVALID_ID32 ||
        v_ast->result1 == table_id);
    if (!v_ast->result0 || !is_same_table) {
        v_ast->result0 = OG_FALSE;
    }
}

static status_t handle_func_proj_elimination(visit_assist_t *v_ast, expr_node_t **exprn)
{
    const bool32 func_initial_result = (bool32)v_ast->result0;
    const uint32 func_initial_table_id = v_ast->result1;
    
    v_ast->result0 = OG_TRUE;
    v_ast->result1 = OG_INVALID_ID32;
    
    const status_t func_process_status = visit_func_node(v_ast, *exprn, eliminate_proj_in_expr);
    if (func_process_status != OG_SUCCESS) {
        return func_process_status;
    }
    
    sql_func_t *current_func = sql_get_func(&(*exprn)->value.v_func);
    if (v_ast->result0 && v_ast->result1 != OG_INVALID_ID32 && current_func->indexable) {
        delete_func_expr_from_table(v_ast, exprn);
    }
    
    update_result_value(v_ast, func_initial_result, func_initial_table_id);
    
    return OG_SUCCESS;
}

static status_t handle_case_proj_elimination(visit_assist_t *v_ast, expr_node_t **exprn)
{
    const bool32 case_result_before = (bool32)v_ast->result0;
    const uint32 case_table_before = v_ast->result1;
    
    v_ast->result0 = OG_TRUE;
    v_ast->result1 = OG_INVALID_ID32;
    
    const status_t func_process_status = visit_case_node(v_ast, *exprn, eliminate_proj_in_expr);
    if (func_process_status != OG_SUCCESS) {
        return func_process_status;
    }
    
    const bool32 case_should_eliminate = (v_ast->result0 != 0) && (v_ast->result1 != OG_INVALID_ID32);
    if (case_should_eliminate) {
        delete_func_expr_from_table(v_ast, exprn);
    }
    
    update_result_value(v_ast, case_result_before, case_table_before);
    
    return OG_SUCCESS;
}

static status_t eliminate_proj_in_expr(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_type_t type = (*exprn)->type;
    if (type == EXPR_NODE_COLUMN || type == EXPR_NODE_TRANS_COLUMN) {
        return handle_column_proj_elimination(v_ast, exprn);
    } else if (type == EXPR_NODE_GROUP) {
        return handle_group_proj_elimination(v_ast, exprn);
    } else if (type == EXPR_NODE_OVER) {
        return handle_winsort_proj_elimination(v_ast, exprn);
    } else if (type == EXPR_NODE_FUNC) {
        return handle_func_proj_elimination(v_ast, exprn);
    } else if (type == EXPR_NODE_AGGR) {
        return handle_aggr_proj_elimination(v_ast, exprn);
    } else if (type == EXPR_NODE_CASE) {
        return handle_case_proj_elimination(v_ast, exprn);
    }

    return OG_SUCCESS;
}

static status_t process_rs_col_elimination(sql_stmt_t *statement, sql_query_t *qry, rs_column_t *rs_column)
{
    if (rs_column->type == RS_COL_COLUMN) {
        if (rs_column->v_col.ancestor == 0) {
            og_sql_table_release_query_field(qry, &rs_column->v_col);
        }
        return OG_SUCCESS;
    }

    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.param0 = (void *)qry;
    v_ast.result0 = OG_TRUE;
    v_ast.excl_flags |= (VA_EXCL_WIN_SORT | VA_EXCL_FUNC | VA_EXCL_CASE);
    return visit_expr_tree(&v_ast, rs_column->expr, eliminate_proj_in_expr);
}

static inline status_t if_rs_col_has_winsort(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_OVER) {
        v_ast->result0 = OG_TRUE;
    }
    return OG_SUCCESS;
}

static inline bool32 if_need_verify_winsort(sql_query_t *qry, rs_column_t *rs_column)
{
    return (rs_column->type == RS_COL_CALC &&
        LIMIT_CLAUSE_OCCUR(&qry->limit) && qry->sort_items != NULL && qry->sort_items->count == 0);
}

static inline status_t if_expr_ref_rs_column(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_RS_COLUMN) {
        uint32 col_id = (uint32)(uintptr_t)v_ast->param0;
        uint32 expr_col_id = NODE_VALUE(uint32, *exprn);
        if (expr_col_id == col_id) {
            v_ast->result0 = OG_TRUE;
        }
    }
    return OG_SUCCESS;
}

static status_t check_rs_column_referenced_by_sort(sql_stmt_t *statement, sql_query_t *qry, rs_column_t *rs_column,
    uint32 col_id, bool32 *is_ref)
{
    *is_ref = OG_FALSE;
    if (qry->sort_items == NULL || qry->sort_items->count == 0) {
        return OG_SUCCESS;
    }

    uint32 i = 0;
    while (i < qry->sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(qry->sort_items, i++);
        if (item == NULL || item->expr == NULL || item->expr->root == NULL) {
            continue;
        }

        expr_node_t *sort_root = item->expr->root;
        expr_node_t *rs_root = NULL;
        if (rs_column->type == RS_COL_CALC && rs_column->expr != NULL) {
            rs_root = rs_column->expr->root;
        }
        if (rs_root != NULL && sort_root == rs_root) {
            *is_ref = OG_TRUE;
            return OG_SUCCESS;
        }

        if (sort_root->type == EXPR_NODE_CONST && sort_root->value.is_null == OG_FALSE) {
            if (sort_root->value.type == OG_TYPE_INTEGER && sort_root->value.v_int > 0 &&
                (uint32)sort_root->value.v_int == (col_id + 1)) {
                *is_ref = OG_TRUE;
                return OG_SUCCESS;
            }
            if (sort_root->value.type == OG_TYPE_BIGINT && sort_root->value.v_bigint > 0 &&
                (uint32)sort_root->value.v_bigint == (col_id + 1)) {
                *is_ref = OG_TRUE;
                return OG_SUCCESS;
            }
        }

        if (rs_column->type == RS_COL_COLUMN && sort_root->type == EXPR_NODE_COLUMN &&
            rs_column->v_col.ancestor == 0 && rs_column->v_col.tab == VAR_TAB(&sort_root->value) &&
            rs_column->v_col.col == VAR_COL(&sort_root->value)) {
            *is_ref = OG_TRUE;
            return OG_SUCCESS;
        }

        visit_assist_t v_ast = {0};
        sql_init_visit_assist(&v_ast, statement, NULL);
        v_ast.param0 = (void *)(uintptr_t)col_id;
        v_ast.result0 = OG_FALSE;
        OG_RETURN_IFERR(visit_expr_tree(&v_ast, item->expr, if_expr_ref_rs_column));
        if (v_ast.result0) {
            *is_ref = OG_TRUE;
            return OG_SUCCESS;
        }
    }

    return OG_SUCCESS;
}

static status_t eliminate_rs_column(sql_stmt_t *statement, sql_query_t *qry, uint32 col_id)
{
    rs_column_t *rs_column = (rs_column_t *)cm_galist_get(qry->rs_columns, col_id);
    if (is_reserved_field(rs_column)) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] The rs_column is reserved field,"
            "not support proj elimination.");
        return OG_SUCCESS;
    }

    /*
    * When a projected column containing a window function in a subquery is eliminated,
    * the result order within the subquery may change before and after elimination.
    * If the subquery also contains a LIMIT clause, this could lead to incorrect query results.
    * Therefore, in such cases, if there are no other sorting columns available to reconstruct the sort order,
    * the projected window function column must not be eliminated.
    * For example:
    * select col1, col2 from (select col1, col2, count(1) over(partiition by xxx) as cnt from table limit 10);
    * has different result set -->
    * select col1, col2 from (select col1, col2 from table limit 10);
    */
    if (if_need_verify_winsort(qry, rs_column)) {
        bool32 found_winsort = OG_FALSE;
        visit_assist_t v_ast = {0};
        sql_init_visit_assist(&v_ast, statement, NULL);
        v_ast.result0 = found_winsort;
        v_ast.excl_flags |= VA_EXCL_WIN_SORT;
        OG_RETURN_IFERR(visit_expr_tree(&v_ast, rs_column->expr, if_rs_col_has_winsort));
        OG_RETVALUE_IFTRUE(v_ast.result0, OG_SUCCESS);
    }

    bool32 is_ref_by_sort = OG_FALSE;
    OG_RETURN_IFERR(check_rs_column_referenced_by_sort(statement, qry, rs_column, col_id, &is_ref_by_sort));
    if (is_ref_by_sort) {
        return OG_SUCCESS;
    }

    if (process_rs_col_elimination(statement, qry, rs_column) != OG_SUCCESS) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] Failed to process expr tree.");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(replace_rs_col_with_null(statement, rs_column));
    OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] The result set column is eliminated, col_id: %d", col_id);
    return OG_SUCCESS;
}

// After the window function projection column is identified as eliminable,
// perform validity rewriting and checking on the remaining(order and group) exprs.
static status_t rewrite_group_related_columns(sql_stmt_t *statement, sql_query_t *qry)
{
    // Only all win sort func exprs are eliminated, then rewrite group exprs.
    if (qry->winsort_list->count > 0) {
        return OG_SUCCESS;
    }

    uint32 i = 0;
    rs_column_t *rs_column = NULL;
    while (i < qry->rs_columns->count) {
        rs_column = (rs_column_t *)cm_galist_get(qry->rs_columns, i++);
        if (rs_column->type == RS_COL_CALC && rs_column->expr->root->type != EXPR_NODE_RESERVED) {
            OG_RETURN_IFERR(replace_group_expr_node(statement, &rs_column->expr->root));
        }
        if (qry->group_sets != NULL && QUERY_HAS_SINGLE_GROUP_BY(qry) &&
            rs_column->expr->root->type != EXPR_NODE_RESERVED) {
            OG_RETURN_IFERR(sql_match_group_expr(statement, qry, rs_column->expr));
        }
    }

    uint32 id = 0;
    sort_item_t *sort_item = NULL;
    while (id < qry->sort_items->count) {
        sort_item = (sort_item_t *)cm_galist_get(qry->sort_items, id++);
        OG_RETURN_IFERR(replace_group_expr_node(statement, &sort_item->expr->root));
        if (qry->group_sets != NULL && QUERY_HAS_SINGLE_GROUP_BY(qry)) {
            OG_RETURN_IFERR(sql_match_group_expr(statement, qry, sort_item->expr));
        }
    }

    cm_galist_reset(qry->winsort_rs_columns);
    return OG_SUCCESS;
}

static status_t eliminate_proj_col_in_query(sql_stmt_t *statement, sql_table_t *tbl, select_node_t *node)
{
    sql_query_t *subquery = node->query;
    if (!check_if_support_eliminate4proj(subquery)) {
        return OG_SUCCESS;
    }

    uint32 old_winsort_cnt = subquery->winsort_list->count;
    uint32 col_id = 0;
    while (col_id < subquery->rs_columns->count) {
        if (!query_contains_rs_column(tbl, col_id)) {
            OG_RETURN_IFERR(eliminate_rs_column(statement, subquery, col_id));
        }
        col_id++;
    }

    if (old_winsort_cnt > 0) {
        OG_RETURN_IFERR(rewrite_group_related_columns(statement, subquery));
    }
    return OG_SUCCESS;
}

static status_t process_proj_columns_elimination_impl(sql_stmt_t *statement, sql_table_t *tbl, select_node_t *node,
    uint32 depth)
{
    if (depth > PROJ_REWRITE_MAX_TREE_DEPTH) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        return OG_ERROR;
    }
    switch (node->type) {
        case SELECT_NODE_QUERY:
            return eliminate_proj_col_in_query(statement, tbl, node);
        case SELECT_NODE_UNION_ALL:
            OG_RETURN_IFERR(process_proj_columns_elimination_impl(statement, tbl, node->left, depth + 1));
            OG_RETURN_IFERR(process_proj_columns_elimination_impl(statement, tbl, node->right, depth + 1));
            break;
        default:
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t process_proj_columns_elimination(sql_stmt_t *statement, sql_table_t *tbl, select_node_t *node)
{
    return process_proj_columns_elimination_impl(statement, tbl, node, 0);
}

status_t og_transf_eliminate_proj_col(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_project_list_pruning,
        PARAM_OPTIM_PROJECT_LIST_PRUNING)) {
        OG_LOG_DEBUG_INF("[PROJ_ELIMINATE] _OPTIM_PROJECT_LIST_PRUNING has been shutted");
        return OG_SUCCESS;
    }

    sql_table_t *tbl;
    uint32 tbl_idx = 0;
    uint32 tables_count = qry->tables.count;
    while (tbl_idx < tables_count) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, tbl_idx++);
        if (is_can_proj_eliminate(tbl)) {
            select_node_t *root = tbl->select_ctx->root;
            OG_RETURN_IFERR(process_proj_columns_elimination(statement, tbl, root));
        }
    }

    return OG_SUCCESS;
}
