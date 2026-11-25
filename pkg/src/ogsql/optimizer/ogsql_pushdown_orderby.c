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

#include "ogsql_pushdown_orderby.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "ogsql_optim_common.h"
#include "ogsql_cond_rewrite.h"

static bool32 check_opt_param_4_pushdown_orderby(sql_stmt_t *statement)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_order_by_placement, OPT_ORDER_BY_PLACEMENT)) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] _OPTIM_ORDER_BY_PLACEMENT has been shutted");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 check_query_cond_valid_4_pushdown_orderby(sql_query_t *qry)
{
    if (qry->sort_items->count == 0) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry must be orderby.");
        return OG_FALSE;
    }

    if (qry->owner == NULL || qry->tables.count > 1) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry must be single-table qry.");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_query_clause_valid_4_pushdown_orderby(sql_query_t *qry)
{
    if (qry->has_distinct) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry has distinct.");
        return OG_FALSE;
    }

    if (qry->group_sets != NULL && qry->group_sets->count > 0) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry has group by.");
        return OG_FALSE;
    }

    if (qry->winsort_list != NULL && qry->winsort_list->count > 0) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry has winsort.");
        return OG_FALSE;
    }

    if (qry->connect_by_cond != NULL) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry has connect_by.");
        return OG_FALSE;
    }

    if (qry->pivot_items != NULL) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry has pivot.");
        return OG_FALSE;
    }

    if (qry->group_cubes != NULL) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry has cube.");
        return OG_FALSE;
    }

    if (qry->cond != NULL && qry->cond->root != NULL &&
        qry->cond->root->type != COND_NODE_TRUE) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry where condition must be empty or TRUE.");
        return OG_FALSE;
    }

    if (qry->having_cond != NULL && qry->having_cond->root != NULL &&
        qry->having_cond->root->type != COND_NODE_TRUE) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Parent qry having condition must be empty or TRUE.");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_table_valid_4_pushdown_orderby(sql_table_t *tbl)
{
    if (tbl->type != SUBSELECT_AS_TABLE && tbl->type != VIEW_AS_TABLE) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Invalid tbl type: %u.", tbl->type);
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_subquery_valid_4_pushdown_orderby(sql_select_t *slct, sql_query_t *sub_qry)
{
    if (slct->root->type != SELECT_NODE_QUERY) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Subquery check failed, sub-select type: %d.", slct->root->type);
        return OG_FALSE;
    }

    if (LIMIT_CLAUSE_OCCUR(&sub_qry->limit)) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Subquery check failed, sub-select limit");
        return OG_FALSE;
    }

    if (sub_qry->pivot_items != NULL) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Subquery check failed, sub-select pivot");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static void check_orderby_var_col(visit_assist_t *v_ast, var_column_t *var_col)
{
    if (var_col->ancestor > 0) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] var_col has ancestor");
        v_ast->result0 = OG_TRUE;
    }
}

static void check_orderby_rs_col(visit_assist_t *v_ast, var_column_t *var_col)
{
    sql_query_t *sub_qry = (sql_query_t *)v_ast->param0;
    rs_column_t *rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, var_col->col);

    if (((rs_column->type == RS_COL_COLUMN && rs_column->v_col.is_array)) ||
        OG_BIT_TEST(rs_column->rs_flag, RS_COND_UNABLE)) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] array rs col or RS_COND_UNABLE");
        v_ast->result0 = OG_TRUE;
    }
}

static status_t check_orderby_pushdown_conditions(visit_assist_t *v_ast, expr_node_t **exprn)
{
    switch ((*exprn)->type) {
        case EXPR_NODE_CONST:
            break;

        case EXPR_NODE_COLUMN: {
            var_column_t *var_col = VALUE_PTR(var_column_t, &(*exprn)->value);
            check_orderby_var_col(v_ast, var_col);
            OG_BREAK_IF_TRUE(var_col->ancestor > 0);
            check_orderby_rs_col(v_ast, var_col);
            break;
        }

        default:
            v_ast->result0 = OG_TRUE;
            break;
    }
    return OG_SUCCESS;
}

static void init_v_ast_4_pushdown(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry, visit_assist_t *v_ast)
{
    sql_init_visit_assist(v_ast, statement, qry);
    v_ast->param0 = (void *)sub_qry;
}

static bool32 check_orderby_valid_4_pushdown(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry)
{
    visit_assist_t v_ast = { 0 };
    init_v_ast_4_pushdown(statement, NULL, sub_qry, &v_ast);
    v_ast.result0 = OG_FALSE;

    uint32 idx = 0;
    sort_item_t *sort_item = NULL;
    while (idx < qry->sort_items->count) {
        sort_item = (sort_item_t *)cm_galist_get(qry->sort_items, idx++);
        if (visit_expr_tree(&v_ast, sort_item->expr, check_orderby_pushdown_conditions) != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("[ORDERBY_PUSHDOWN] check_orderby_pushdown_conditions err.");
        }
        if (v_ast.result0) {
            OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Sort item can't be pushed down.");
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 og_validate_orderby_pushdown(sql_stmt_t *statement, sql_query_t *qry)
{
    OG_RETVALUE_IFTRUE(!check_opt_param_4_pushdown_orderby(statement), OG_FALSE);

    OG_RETVALUE_IFTRUE(!check_query_cond_valid_4_pushdown_orderby(qry), OG_FALSE);

    OG_RETVALUE_IFTRUE(!check_query_clause_valid_4_pushdown_orderby(qry), OG_FALSE);

    sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
    OG_RETVALUE_IFTRUE(!check_table_valid_4_pushdown_orderby(tbl), OG_FALSE);

    OG_RETVALUE_IFTRUE(!check_subquery_valid_4_pushdown_orderby(tbl->select_ctx,
        tbl->select_ctx->first_query), OG_FALSE);

    return check_orderby_valid_4_pushdown(statement, qry, tbl->select_ctx->first_query);
}

static status_t sql_copy_rs_col(var_column_t *src, var_column_t *dst)
{
    if (src == NULL || dst == NULL) {
        return OG_ERROR;
    }
    dst->tab = src->tab;
    dst->col = src->col;
    dst->ss_start = src->ss_start;
    dst->ss_end = src->ss_end;
    dst->ancestor = src->ancestor;
    dst->datatype = src->datatype;
    return OG_SUCCESS;
}

static status_t sql_handle_select_node(sql_stmt_t *statement, sql_query_t *qry, expr_node_t **exprn,
                                       sql_query_t *sub_qry)
{
    sql_select_t *slct = (sql_select_t *)VALUE_PTR(var_object_t, &(*exprn)->value)->ptr;

    if (sql_array_delete(&qry->ssa, (*exprn)->value.v_obj.id) != OG_SUCCESS) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Failed to delete SSA entry.");
        return OG_ERROR;
    }

    if (qry->ssa.count > 0 && sql_update_query_ssa(statement, qry) != OG_SUCCESS) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Failed to update SSA.");
        return OG_ERROR;
    }

    slct->parent = sub_qry;
    (*exprn)->value.v_obj.id = sub_qry->ssa.count;

    if (sql_array_put(&sub_qry->ssa, slct) != OG_SUCCESS) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Failed to add SSA entry.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_handle_column_node(sql_stmt_t *statement, expr_node_t **exprn, sql_query_t *sub_qry)
{
    variant_t *val = &(*exprn)->value;
    var_column_t *var_column = VALUE_PTR(var_column_t, val);
    uint16 rs_col_id = var_column->col;
    rs_column_t *rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, rs_col_id);
    if (rs_column->type == RS_COL_CALC) {
        return sql_clone_expr_node(statement->context, rs_column->expr->root, exprn, sql_alloc_mem);
    }
    return sql_copy_rs_col(&rs_column->v_col, var_column);
}

status_t og_handle_pushdown_col(visit_assist_t *v_ast, expr_node_t **exprn)
{
    sql_query_t *sub_qry = (sql_query_t *)v_ast->param0;

    switch ((*exprn)->type) {
        case EXPR_NODE_SELECT:
            return sql_handle_select_node(v_ast->stmt, v_ast->query, exprn, sub_qry);

        case EXPR_NODE_COLUMN:
            return sql_handle_column_node(v_ast->stmt, exprn, sub_qry);

        default:
            return OG_SUCCESS;
    }
}

static void og_pushdown_sort_items(sql_query_t *qry, sql_query_t *sub_qry)
{
    sub_qry->sort_items = qry->sort_items;
    sub_qry->order_siblings = qry->order_siblings;
}

static status_t og_pushdown_orderby_col(visit_assist_t *v_ast, galist_t *sort_items)
{
    uint32 idx = 0;
    sort_item_t *sort_item = NULL;
    while (idx < sort_items->count) {
        sort_item = (sort_item_t *)cm_galist_get(sort_items, idx++);
        if (visit_expr_tree(v_ast, sort_item->expr, og_handle_pushdown_col) != OG_SUCCESS) {
            OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Column modification failed.");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_perform_pushdown_orderby(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry)
{
    visit_assist_t v_ast = { 0 };
    init_v_ast_4_pushdown(statement, qry, sub_qry, &v_ast);
    galist_t *sort_items = qry->sort_items;
    OG_RETURN_IFERR(og_pushdown_orderby_col(&v_ast, sort_items));
    og_pushdown_sort_items(qry, sub_qry);
    return sql_create_list(statement, &qry->sort_items);
}

status_t og_transf_pushdown_orderby(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!og_validate_orderby_pushdown(statement, qry)) {
        OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] ORDER BY can't be pushed down.");
        return OG_SUCCESS;
    }

    sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
    OG_LOG_DEBUG_INF("[ORDERBY_PUSHDOWN] Pushing down order by to sub_qry, tbl[%s].", T2S(&(tbl->name)));

    sql_query_t *sub_qry = tbl->select_ctx->first_query;
    return og_perform_pushdown_orderby(statement, qry, sub_qry);
}