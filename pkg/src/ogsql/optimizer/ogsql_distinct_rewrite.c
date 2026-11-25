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

#include "ogsql_distinct_rewrite.h"
#include "srv_instance.h"
#include "ogsql_hint_verifier.h"
#include "dml_parser.h"
#include "ogsql_optim_common.h"
#include "ogsql_stmt.h"
#include "ogsql_cond_rewrite.h"

static bool32 check_query_distinct_eliminated(sql_stmt_t *statement, sql_query_t *qry)
{
    OG_RETVALUE_IFTRUE(!qry->has_distinct && !(qry->owner != NULL && qry->owner->type == SELECT_AS_LIST), OG_FALSE);
    OG_RETVALUE_IFTRUE(ROWNUM_COND_OCCUR(qry->cond), OG_FALSE);

    galist_t *rs_columns = NULL;
    if (qry->has_distinct) {
        OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] Parent query has distinct.");
        rs_columns = qry->distinct_columns;
    } else {
        rs_columns = qry->rs_columns;
    }

    uint32 idx = 0;
    while (idx < rs_columns->count) {
        rs_column_t *rs_column = (rs_column_t *)cm_galist_get(rs_columns, idx++);
        // 查询列必须是 RS_COL_COLUMN类型（普通表字段）
        if (rs_column->type == RS_COL_COLUMN) {
            OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] The query column must be RS_COL_COLUMN.");
            continue;
        }

        // 如果查询列为 RS_COL_CALCL 类型, 必须为常量或者常量表达式、绑定参数
        if (!sql_is_const_expr_tree(rs_column->expr) && !TREE_IS_BINDING_PARAM(rs_column->expr)) {
            OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] RS_COL_CALC is not const or binding param.");
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

typedef struct {
    int (*check_func)(const sql_query_t *sub_qry);
    const char *err_msg;
} DistinctElimCheckItem;

static int check_has_distinct(const sql_query_t *sub_qry)
{
    return !sub_qry->has_distinct;
}

static int check_group_sets(const sql_query_t *sub_qry)
{
    return sub_qry->group_sets->count != 0;
}

static int check_winsort_list(const sql_query_t *sub_qry)
{
    return sub_qry->winsort_list->count != 0;
}

static int check_limit_clause(const sql_query_t *sub_qry)
{
    return LIMIT_CLAUSE_OCCUR(&sub_qry->limit);
}

static int check_rownum_cond(const sql_query_t *sub_qry)
{
    return ROWNUM_COND_OCCUR(sub_qry->cond);
}

static bool32 check_subquery_distinct_eliminatable(sql_query_t *sub_qry)
{
    const DistinctElimCheckItem check_items[] = {
        {check_has_distinct,    "[DISTINCT_ELIMATE] Subquery have no distinct."},
        {check_group_sets,      "[DISTINCT_ELIMATE] Subquery can't have group sets."},
        {check_winsort_list,    "[DISTINCT_ELIMATE] Subquery can't have window sort."},
        {check_limit_clause,    "[DISTINCT_ELIMATE] Subquery can't have limit."},
        {check_rownum_cond,     "[DISTINCT_ELIMATE] Subquery can't have rownum condition."}
    };

    const int item_count = sizeof(check_items) / sizeof(check_items[0]);
    for (int i = 0; i < item_count; ++i) {
        const DistinctElimCheckItem *item = &check_items[i];
        if (item->check_func(sub_qry)) { // 校验失败
            OG_LOG_DEBUG_INF("%s", item->err_msg);
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static inline status_t check_failed_handler(bool32 check_result, const char *err_msg)
{
    if (!check_result) {
        OG_LOG_DEBUG_INF("%s", err_msg);
        return OG_SUCCESS;
    }
    return OG_ERROR;
}

static status_t process_subquery_sort_items(sql_stmt_t *statement, sql_query_t *sub_qry)
{
    SET_NODE_STACK_CURR_QUERY(statement, sub_qry);

    uint32 idx = 0;
    while (idx < sub_qry->sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(sub_qry->sort_items, idx++);
        if (replace_group_expr_node(statement, &item->expr->root) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DISTINCT_ELIMATE] replace_group_expr_node failed.");
            SQL_RESTORE_NODE_STACK(statement);
            return OG_ERROR;
        }
    }

    SQL_RESTORE_NODE_STACK(statement);
    return OG_SUCCESS;
}

static void do_eliminate_subquery_distinct(sql_query_t *sub_qry)
{
    SWAP(galist_t *, sub_qry->rs_columns, sub_qry->distinct_columns);
    cm_galist_reset(sub_qry->distinct_columns);
    sub_qry->has_distinct = OG_FALSE;
    OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] Success on sub query %p", sub_qry);
}

static status_t og_eliminate_query_distinct(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry)
{
    status_t ret = check_failed_handler(check_query_distinct_eliminated(statement, qry),
                                        "[DISTINCT_ELIMATE] Query is not eliminatable.");
    if (ret == OG_SUCCESS) {
        return OG_SUCCESS;
    }

    ret = check_failed_handler(check_subquery_distinct_eliminatable(sub_qry),
                               "[DISTINCT_ELIMATE] Subquery is not eliminatable.");
    if (ret == OG_SUCCESS) {
        return OG_SUCCESS;
    }

    if (process_subquery_sort_items(statement, sub_qry) != OG_SUCCESS) {
        return OG_ERROR;
    }

    do_eliminate_subquery_distinct(sub_qry);

    return OG_SUCCESS;
}

status_t og_transf_eliminate_distinct(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_distinct_elimination, OPT_DISTINCT_ELIMINATION)) {
        OG_LOG_DEBUG_INF("_OPTIM_DISTINCT_ELIMINATION has been shutted");
        return OG_SUCCESS;
    }
    
    if (sql_stack_safe(statement) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DISTINCT_ELIMATE] sql_stack_safe failed.");
        return OG_ERROR;
    }

    uint32 idx = 0;
    while (idx < qry->tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, idx++);
        if (tbl == NULL) {
            OG_LOG_RUN_ERR("[DISTINCT_ELIMATE] table is NULL.");
            return OG_ERROR;
        }
        if (tbl->type != VIEW_AS_TABLE && tbl->type != SUBSELECT_AS_TABLE) {  // 表类型为子查询表或视图
            OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] Skip tables[%s] type:%d, not view/sub query.", T2S(&(tbl->name)),
                             tbl->type);
            continue;
        }
        if (tbl->subslct_tab_usage != SUBSELECT_4_NORMAL_JOIN) {  // 表用于 NORMAL JOIN
            OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] Skip tables[%s] sub_usage:%d, not normal join.", T2S(&(tbl->name)),
                             tbl->subslct_tab_usage);
            continue;
        }
        if (tbl->select_ctx->root->type != SELECT_NODE_QUERY) {  // 子查询表中不能是集合类型的查询
            OG_LOG_DEBUG_INF("[DISTINCT_ELIMATE] Skip tables[%s] root_type:%d, not plain query.", T2S(&(tbl->name)),
                             tbl->select_ctx->root->type);
            continue;
        }

        sql_query_t *sub_qry = tbl->select_ctx->first_query;

        if (og_transf_eliminate_distinct(statement, sub_qry) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DISTINCT_ELIMATE] og_transf_eliminate_distinct failed.");
            return OG_ERROR;
        }

        if (og_eliminate_query_distinct(statement, qry, sub_qry) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[DISTINCT_ELIMATE] og_eliminate_query_distinct failed.");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}