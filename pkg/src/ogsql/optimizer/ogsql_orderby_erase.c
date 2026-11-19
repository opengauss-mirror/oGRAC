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
#include "ogsql_orderby_erase.h"
#include "srv_instance.h"
#include "ogsql_func.h"
#include "table_parser.h"
#include "ogsql_aggr.h"
#include "ogsql_optim_common.h"

#ifdef __cplusplus
extern "C" {
#endif

static parent_ancestor_flag_t g_parent_pairs[] = { { PARENT_IDX, FLAG_HAS_PARENT_COLS },
                                                   { ANCESTOR_IDX, FLAG_HAS_ANCESTOR_COLS } };

static bool32 check_subquery_sort_elimination(sql_query_t *qry)
{
    return qry->tables.count > 1 || qry->group_sets->count != 0 || qry->aggrs->count != 0 ||
           qry->winsort_list->count != 0 || qry->has_distinct || qry->connect_by_cond != NULL ||
           qry->sort_items->count != 0;
}

static void sql_set_ctx_level(sql_select_t *slct_ctx, uint32 temp_level)
{
    OG_RETVOID_IFTRUE(slct_ctx == NULL);
    sql_select_t *curr_ctx = slct_ctx;
    for (uint32 level = temp_level; level > 0; level--) {
        OG_RETVOID_IFTRUE(curr_ctx->parent == NULL);
        RESET_ANCESTOR_LEVEL(curr_ctx, level);
        curr_ctx = curr_ctx->parent->owner;
    }
}

static void remove_parent_references(sql_query_t *qry, sql_select_t *curr_select, uint32 table_ref, expr_node_t *expr)
{
    sql_del_parent_refs(curr_select->parent_refs, table_ref, expr);
    if (curr_select->parent_refs->count == 0) {
        sql_set_ctx_level(qry->owner, ANCESTOR_OF_NODE(expr));
    }
    return;
}

static void remove_expr_node_from_parent(sql_query_t *qry, biqueue_t *cols_bq)
{
    biqueue_node_t *bq_iter = biqueue_first(cols_bq);
    biqueue_node_t *bq_last = biqueue_end(cols_bq);
    sql_select_t *cur_slct = NULL;
    for (; bq_iter != bq_last; bq_iter = bq_iter->next) {
        cur_slct = qry->owner;
        expr_node_t *expr = OBJECT_OF(expr_node_t, bq_iter);
        bool32 is_column = (NODE_EXPR_TYPE(expr) == EXPR_NODE_COLUMN);
        uint32 level = is_column ? NODE_ANCESTOR(expr) : ROWID_NODE_ANCESTOR(expr);
        while (level > 1 && cur_slct) {
            cur_slct = cur_slct->parent ? cur_slct->parent->owner : NULL;
            level--;
        }
        if (cur_slct) {
            uint32 table_ref = is_column ? NODE_TAB(expr) : ROWID_NODE_TAB(expr);
            remove_parent_references(qry, cur_slct, table_ref, expr);
        }
    }
    return;
}

static void remove_parent_expr_references(sql_query_t *qry, expr_tree_t *exprtr)
{
    cols_used_t cols;
    init_cols_used(&cols);
    sql_collect_cols_in_expr_tree(exprtr, &cols);
    uint32 arr_size = sizeof(g_parent_pairs) / sizeof(parent_ancestor_flag_t);
    uint32 pair_idx = 0;
    while (pair_idx < arr_size) {
        if (cols.flags & g_parent_pairs[pair_idx].flag) {
            uint8 bq_idx = g_parent_pairs[pair_idx].idx;
            biqueue_t *cols_bq = &cols.cols_que[bq_idx];
            remove_expr_node_from_parent(qry, cols_bq);
        }
        pair_idx++;
    }
    return;
}

static void reset_qry_sort(sql_query_t *qry)
{
    cm_galist_reset(qry->sort_items);
    qry->order_siblings = OG_FALSE;
}

static void execute_sort_elimination(sql_query_t *qry)
{
    uint32 item_idx = 0;
    while (item_idx < qry->sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(qry->sort_items, item_idx++);
        expr_tree_t *exprtr = item->expr;
        remove_parent_expr_references(qry, exprtr);
    }
    reset_qry_sort(qry);
    return;
}

static bool32 is_aggr_order_sensitive(const sql_func_t *func)
{
    return func->aggr_type == AGGR_TYPE_GROUP_CONCAT || func->aggr_type == AGGR_TYPE_ARRAY_AGG;
}

static bool32 if_aggr_func_depend_subqry_order(sql_query_t *qry)
{
    if (qry->aggrs == NULL || qry->aggrs->count == 0) {
        return OG_FALSE;
    }

    for (uint32 idx = 0; idx < qry->aggrs->count; idx++) {
        expr_node_t *aggr_node = (expr_node_t *)cm_galist_get(qry->aggrs, idx);
        const sql_func_t *func = GET_AGGR_FUNC(aggr_node);
        if (is_aggr_order_sensitive(func)) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static status_t og_orderby_earse_chk_tbl(sql_table_t *tbl)
{
    OG_RETVALUE_IFTRUE(tbl->type != SUBSELECT_AS_TABLE && tbl->type != VIEW_AS_TABLE, OG_FALSE);
    OG_RETVALUE_IFTRUE(tbl->select_ctx->root->type != SELECT_NODE_QUERY, OG_FALSE);
    return OG_TRUE;
}

static status_t og_orderby_earse_chk_qry(sql_query_t *qry)
{
    if (QUERY_HAS_ROWNUM(qry)) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static status_t og_orderby_earse_chk_subqry(sql_query_t *sub_qry)
{
    if (sub_qry->sort_items == NULL || sub_qry->sort_items->count == 0) {
        return OG_FALSE;
    }
    if (QUERY_HAS_ROWNUM(sub_qry) || LIMIT_CLAUSE_OCCUR(&sub_qry->limit)) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static void try_eliminate_subquery_sort(sql_table_t *tbl, sql_query_t *qry)
{
    OG_RETVOID_IFTRUE(!og_orderby_earse_chk_tbl(tbl));
    sql_query_t *sub_qry = tbl->select_ctx->first_query;
    OG_RETVOID_IFTRUE(!og_orderby_earse_chk_subqry(sub_qry));
    OG_RETVOID_IFTRUE(!og_orderby_earse_chk_qry(qry));
    if (check_subquery_sort_elimination(qry) && !if_aggr_func_depend_subqry_order(qry)) {
        execute_sort_elimination(sub_qry);
    }
    return;
}

status_t og_transf_eliminate_orderby(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_order_by_elimination, OPT_ORDER_BY_ELIMINATION)) {
        return OG_SUCCESS;
    }
    uint32 table_idx = 0;
    while (table_idx < qry->tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, table_idx++);
        try_eliminate_subquery_sort(tbl, qry);
    }
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
