/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
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
 * ogsql_unparser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_unparser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_unparser.h"
#include "var_cast.h"
#include "cm_text.h"
#include "cm_word.h"

// keep the order consistent with expr_node_type_t
static const char* g_expr_oper[] = { " * ", " / ", " % ", " + ", " - ", " << ", " >> ", " & ", " ^ ", " | ", " || " };

// keep the order consistent with reserved_wid_t
static const char* g_reserved_word[] = {
    "CONNECT_BY_ISCYCLE",
    "CONNECT_BY_ISLEAF",
    "",
    "DEFAULT",
    "DELETING",
    "FALSE",
    "INSERTING",
    "LEVEL",
    "NULL",
    "ROWID",
    "ROWNUM",
    "ROWSCN",
    "SESSIONTIMEZONE",
    "SYSDATE",
    "SYSTIMESTAMP",
    "TRUE",
    "UPDATING",
    "USER",
    "DBTIMEZONE",
    "CURRENT_DATE",
    "CURRENT_TIMESTAMP",
    "LOCALTIMESTAMP",
    "DUMMY",
    "UTC_TIMESTAMP",
    "",
    "ROWNODEID",
};

static const char *g_cmp_symbols[] = {
    " = ",              // CMP_TYPE_EQUAL
    " >= ",             // CMP_TYPE_GREAT_EQUAL
    " > ",              // CMP_TYPE_GREAT
    " < ",              // CMP_TYPE_LESS
    " <= ",             // CMP_TYPE_LESS_EQUAL
    " != ",             // CMP_TYPE_NOT_EQUAL
    " = ANY",           // CMP_TYPE_EQUAL_ANY
    " != ANY",          // CMP_TYPE_NOT_EQUAL_ANY
    " IN ",             // CMP_TYPE_IN
    " NOT IN ",         // CMP_TYPE_NOT_IN
    " IS NULL ",        // CMP_TYPE_IS_NULL
    " IS NOT NULL ",    // CMP_TYPE_IS_NOT_NULL
    " LIKE ",           // CMP_TYPE_LIKE
    " NOT LIKE ",       // CMP_TYPE_NOT_LIKE
    " REGEXP ",         // CMP_TYPE_REGEXP
    " NOT REGEXP ",     // CMP_TYPE_NOT_REGEXP
    " BETWEEN ",        // CMP_TYPE_BETWEEN
    " NOT BETWEEN ",    // CMP_TYPE_NOT_BETWEEN
    "EXISTS",           // CMP_TYPE_EXISTS
    "NOT EXISTS",       // CMP_TYPE_NOT_EXISTS
    "REGEXP_LIKE",      // CMP_TYPE_REGEXP_LIKE
    "NOT REGEXP_LIKE",  // CMP_TYPE_NOT_REGEXP_LIKE
    " >= ANY",          // CMP_TYPE_GREAT_EQUAL_ANY
    " > ANY",           // CMP_TYPE_GREAT_ANY
    " < ANY",           // CMP_TYPE_LESS_ANY
    " <= ANY",          // CMP_TYPE_LESS_EQUAL_ANY
    " = ALL",           // CMP_TYPE_EQUAL_ALL
    " != ALL",          // CMP_TYPE_NOT_EQUAL_ALL
    " >= ALL",          // CMP_TYPE_GREAT_EQUAL_ALL
    " > ALL",           // CMP_TYPE_GREAT_ALL
    " < ALL",           // CMP_TYPE_LESS_ALL
    " <= ALL",          // CMP_TYPE_LESS_EQUAL_ALL
    " IS JSON",         // CMP_TYPE_IS_JSON
    " IS NOT JSON"      // CMP_TYPE_IS_NOT_JSON
};

typedef status_t (*ogsql_unparse_query)(sql_query_t *qry, var_text_t *result);
static status_t ogsql_unparse_expr_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result,
    bool32 table_unparsed);
static status_t ogsql_unparse_expr_tree(sql_query_t *qry, expr_tree_t *exprtr, var_text_t *result);
static status_t ogsql_unparse_expr_tree_list(sql_query_t *qry, galist_t *lst, var_text_t *result);
static status_t ogsql_unparse_node_func_args(sql_query_t *qry, expr_tree_t *exprtr, uint32 func_id, var_text_t *result);
static status_t ogsql_unparse_node_func(sql_query_t *qry, expr_node_t *exprn, var_text_t *result,
    bool32 table_unparsed);
static status_t ogsql_unparse_join_tree(sql_query_t *qry, sql_join_node_t *jnode, var_text_t *result);
static status_t ogsql_unparse_column_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result,
    bool32 table_unparsed);
static status_t ogsql_unparse_in_expr(sql_query_t *qry, expr_tree_t *exprtr, uint32 len, var_text_t *result);
static status_t ogsql_unparse_table_info(sql_query_t *qry, sql_table_t *tbl, var_text_t *result);

static inline status_t ogsql_unparse_cond_need(cond_tree_t *cond)
{
    return cond != NULL && cond->root != NULL && 
        cond->root->type != COND_NODE_TRUE && cond->root->type != COND_NODE_FALSE;
}

status_t ogsql_unparse_expr_operation(sql_query_t *qry, expr_node_t *exprn, var_text_t *result, bool32 table_unparsed)
{
    OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, exprn->left, result, table_unparsed));
    OG_RETURN_IFERR(cm_concat_var_string(result, g_expr_oper[exprn->type - EXPR_NODE_MUL]));
    return ogsql_unparse_expr_node(qry, exprn->right, result, table_unparsed);
}

status_t ogsql_unparse_prior_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result, bool32 table_unparsed)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "PRIOR "));
    return ogsql_unparse_expr_node(qry, exprn->right, result, table_unparsed);
}

status_t ogsql_unparse_reserved_node(expr_node_t *exprn, var_text_t *result)
{
    reserved_wid_t res_id = VAR_RES_ID(&exprn->value);
    if (res_id >= RES_WORD_CONNECT_BY_ISCYCLE && res_id <= RES_WORD_ROWNODEID) {
        return cm_concat_var_string(result, g_reserved_word[res_id - RES_WORD_CONNECT_BY_ISCYCLE]);
    }
    OG_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "reserved", (((expr_node_t *)exprn)->value).v_int);
    return OG_ERROR;
}

status_t ogsql_unparse_query_cols(sql_query_t *qry, var_text_t *result)
{
    if (qry->is_exists_query) {
        return cm_concat_var_string(result, " 1");
    }
    galist_t *col_lst = NULL;
    if (qry->has_distinct) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " DISTINCT"));
        col_lst = qry->distinct_columns;
    } else {
        col_lst = qry->rs_columns;
    }

    if (col_lst->count == 0) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " "));

    uint32 i = 0;
    while (i < col_lst->count) {
        rs_column_t *rs_column = (rs_column_t *)cm_galist_get(col_lst, i);
        if (rs_column->type == RS_COL_CALC) {
            OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, rs_column->expr, result));
            if (OG_BIT_TEST(rs_column->rs_flag, RS_EXIST_ALIAS)) {
                OG_RETURN_IFERR(cm_concat_var_string(result, " AS "));
                OG_RETURN_IFERR(cm_concat_n_var_string(result, rs_column->name.str, rs_column->name.len));
            }
        } else {
            OG_RETURN_IFERR(cm_concat_n_var_string(result, rs_column->name.str, rs_column->name.len));
        }
        if (i < col_lst->count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ", "));
        }
        i++;
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_pivot_table(sql_query_t *qry, pivot_items_t *items, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, " PIVOT("));
    OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, items->aggr_expr, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, " FOR ("));
    OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, items->for_expr, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ") IN("));
    OG_RETURN_IFERR(ogsql_unparse_in_expr(qry, items->in_expr, sql_expr_list_len(items->for_expr), result));
    return cm_concat_var_string(result, "))");
}

static status_t ogsql_unparse_unpivot_name(galist_t *lst, var_text_t *result)
{
    uint32 i = 0;
    while (i < lst->count) {
        text_t *name = (text_t *)cm_galist_get(lst, i);
        OG_RETURN_IFERR(cm_concat_n_var_string(result, name->str, name->len));
        if (i < lst->count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ","));
        }
        i++;
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_unpivot_column(pivot_items_t *items, var_text_t *result)
{
    uint32 data_count = items->unpivot_data_rs->count;
    for(uint32 i = 0; i < items->column_name->count; i++) {
        if (i % data_count == 0) {
            OG_RETURN_IFERR(cm_concat_var_string(result, "("));
        }
        text_t *name = (text_t *)cm_galist_get(items->column_name, i);
        OG_RETURN_IFERR(cm_concat_n_var_string(result, name->str, name->len));
        if (i % data_count == data_count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
        }
        if (i < items->column_name->count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ","));
        }
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_unpivot_table(sql_query_t *qry, pivot_items_t *items, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, " UNPIVOT"));
    if (items->include_nulls) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " INCLUDE NULLS(("));
    } else {
        OG_RETURN_IFERR(cm_concat_var_string(result, " EXCLUDE NULLS(("));
    }
    OG_RETURN_IFERR(ogsql_unparse_unpivot_name(items->unpivot_data_rs, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ") FOR ("));
    OG_RETURN_IFERR(ogsql_unparse_unpivot_name(items->unpivot_alias_rs, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ") IN("));
    OG_RETURN_IFERR(ogsql_unparse_unpivot_column(items, result));
    return cm_concat_var_string(result, "))");
}

static status_t ogsql_unparse_pivot_or_unpivot_table(sql_table_t *tbl, sql_query_t *qry, var_text_t *result)
{
    if (qry->tables.count > 1) {
        OG_RETURN_IFERR(ogsql_unparse_join_tree(qry, qry->join_assist.join_node, result));
    } else {
        sql_table_t *sub_tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
        OG_RETURN_IFERR(ogsql_unparse_table_info(qry, sub_tbl, result));
    }

    pivot_items_t *items = qry->pivot_items;
    if (qry->pivot_items->type == PIVOT_TYPE) {
        OG_RETURN_IFERR(ogsql_unparse_pivot_table(qry, items, result));
    } else {
        OG_RETURN_IFERR(ogsql_unparse_unpivot_table(qry, items, result));
    }

    if (tbl->alias.implicit || tbl->alias.len == 0) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " "));
    return cm_concat_n_var_string(result, tbl->alias.str, tbl->alias.len);
}

static status_t ogsql_unparse_subselect_table(select_node_t *node, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, " ("));
    OG_RETURN_IFERR(ogsql_unparse_select_info(node, result, OG_FALSE));
    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_func_table(sql_query_t *qry, table_func_t *func, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "TABLE("));
    if (cm_text_str_equal(&func->name, "CAST")) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "CAST("));
        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, func->args->root, result, OG_FALSE));
        OG_RETURN_IFERR(cm_concat_var_string(result, " AS "));
        text_t target_name = func->args->next->root->word.func.name.value;
        OG_RETURN_IFERR(cm_concat_n_var_string(result, target_name.str, target_name.len));
    } else {
        OG_RETURN_IFERR(cm_concat_n_var_string(result, func->name.str, func->name.len));
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
        OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, func->args, result));
    }
    return cm_concat_var_string(result, "))");
}

static status_t ogsql_unparse_user_table_name(sql_query_t *qry, sql_table_t *tbl, var_text_t *result)
{
    if (!tbl->user.implicit && tbl->user.len > 0) {
        OG_RETURN_IFERR(cm_concat_n_var_string(result, tbl->user.str, tbl->user.len));
    }
    if (tbl->type == FUNC_AS_TABLE) {
        return ogsql_unparse_func_table(qry, &tbl->func, result);
    }
    return cm_concat_n_var_string(result, tbl->name.str, tbl->name.len);
}

static status_t ogsql_unparse_partition_info(specify_part_info_t *part, var_text_t *result)
{
    if (part->type == SPECIFY_PART_NONE || part->type == SPECIFY_PART_VALUE) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " PARTITION("));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, part->part_name.str, part->part_name.len));
    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_table_info(sql_query_t *qry, sql_table_t *tbl, var_text_t *result)
{
    if (tbl->type == SUBSELECT_AS_TABLE) {
        select_node_t *root = tbl->select_ctx->root;
        if (root->type == SELECT_NODE_QUERY && root->query->pivot_items != NULL) {
            return ogsql_unparse_pivot_or_unpivot_table(tbl, root->query, result);
        }
        OG_RETURN_IFERR(ogsql_unparse_subselect_table(root, result));
    } else {
        OG_RETURN_IFERR(cm_concat_var_string(result, " "));
        OG_RETURN_IFERR(ogsql_unparse_user_table_name(qry, tbl, result));
    }
    OG_RETURN_IFERR(ogsql_unparse_partition_info(&tbl->part_info, result));

    if (tbl->alias.implicit || tbl->alias.len == 0) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " "));
    return cm_concat_n_var_string(result, tbl->alias.str, tbl->alias.len);
}

static status_t ogsql_unparse_join_type(sql_join_type_t jtype, var_text_t *result)
{
    char *str = NULL;
    if (jtype == JOIN_TYPE_INNER) {
        str = " INNER JOIN ";
    } else if (jtype == JOIN_TYPE_LEFT) {
        str = " LEFT JOIN ";
    } else if (jtype == JOIN_TYPE_RIGHT) {
        str = " RIGHT JOIN ";
    } else if (jtype == JOIN_TYPE_FULL) {
        str = " FULL JOIN ";
    } else if (jtype == JOIN_TYPE_CROSS) {
        str = " CROSS JOIN ";
    } else if (jtype == JOIN_TYPE_COMMA) {
        str = ",";
    } else {
        OG_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "join", jtype);
        return OG_ERROR;
    }
    return cm_concat_var_string(result, str);
}

static status_t ogsql_unparse_join_cond(sql_query_t *qry, sql_join_node_t *jnode, var_text_t *result)
{
    if (IS_INNER_JOIN(jnode) || !ogsql_unparse_cond_need(jnode->join_cond)) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " ON "));
    return ogsql_unparse_cond_node(qry, jnode->join_cond->root, OG_FALSE, result);
}

static status_t ogsql_unparse_join_tree(sql_query_t *qry, sql_join_node_t *jnode, var_text_t *result)
{    
    if (jnode->left->type != JOIN_TYPE_NONE && jnode->right->type != JOIN_TYPE_NONE) {
        OG_RETURN_IFERR(ogsql_unparse_join_tree(qry, jnode->left, result));
        return ogsql_unparse_join_tree(qry, jnode->right, result);
    }

    if (jnode->left->type == JOIN_TYPE_NONE) {
        sql_table_t *left_tbl = TABLE_OF_JOIN_LEAF(jnode->left);
        OG_RETURN_IFERR(ogsql_unparse_table_info(qry, left_tbl, result));
    } else {
        OG_RETURN_IFERR(ogsql_unparse_join_tree(qry, jnode->left, result));
    }

    OG_RETURN_IFERR(ogsql_unparse_join_type(jnode->type, result));
    
    if (jnode->right->type == JOIN_TYPE_NONE) {
        sql_table_t *right_tbl = TABLE_OF_JOIN_LEAF(jnode->right);
        OG_RETURN_IFERR(ogsql_unparse_table_info(qry, right_tbl, result));
        return ogsql_unparse_join_cond(qry, jnode, result);
    } else {
        return ogsql_unparse_join_tree(qry, jnode->right, result);
    }
}

static status_t ogsql_unparse_query_from(sql_query_t *qry, var_text_t *result)
{
    sql_table_t *tbl = NULL;
    OG_RETURN_IFERR(cm_concat_var_string(result, " FROM"));
    if (qry->join_root == NULL) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
        return ogsql_unparse_table_info(qry, tbl, result);
    } else {
        return ogsql_unparse_join_tree(qry, qry->join_assist.join_node, result);
    }
}

static status_t ogsql_unparse_query_where(sql_query_t *qry, var_text_t *result)
{
    if (ogsql_unparse_cond_need(qry->cond)) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " WHERE "));
        return ogsql_unparse_cond_node(qry, qry->cond->root, OG_FALSE, result);
    }
    if (qry->join_root != NULL && ogsql_unparse_cond_need(qry->join_root->filter)) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " WHERE "));
        return ogsql_unparse_cond_node(qry, qry->join_root->filter->root, OG_FALSE, result);
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_query_group(sql_query_t *qry, var_text_t *result)
{
    if (qry->group_sets == NULL || qry->group_sets->count == 0) {
        return OG_SUCCESS;
    }
    group_set_t *group_set = NULL;
    OG_RETURN_IFERR(cm_concat_var_string(result, " GROUP BY "));
    if (qry->group_sets->count == 1) {
        group_set = (group_set_t *)cm_galist_get(qry->group_sets, 0);
        return ogsql_unparse_expr_tree_list(qry, group_set->items, result);
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, "GROUPING SETS("));
    uint32 i = 0;
    while (i < qry->group_sets->count) {
        group_set = (group_set_t *)cm_galist_get(qry->group_sets, i);
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
        OG_RETURN_IFERR(ogsql_unparse_expr_tree_list(qry, group_set->items, result));
        OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
        if (i < qry->group_sets->count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ","));
        }
        i++;
    }
    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_query_having(sql_query_t *qry, var_text_t *result)
{
    if (qry->having_cond == NULL) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " HAVING "));
    return ogsql_unparse_cond_node(qry, qry->having_cond->root, OG_FALSE, result);
}

static status_t ogsql_unparse_query_sort(sql_query_t *qry, var_text_t *result)
{
    if (qry->sort_items == NULL || qry->sort_items->count == 0) {
        return OG_SUCCESS;
    }
    sort_item_t *item = NULL;
    OG_RETURN_IFERR(cm_concat_var_string(result, " ORDER BY "));
    uint32 i = 0;
    while (i < qry->sort_items->count) {
        item = (sort_item_t *)cm_galist_get(qry->sort_items, i);
        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, item->expr->root, result, OG_FALSE));
        if (item->direction == SORT_MODE_DESC) {
            OG_RETURN_IFERR(cm_concat_var_string(result, " DESC"));
        }
        if (i < qry->sort_items->count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ","));
        }
        i++;
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_query_limit(sql_query_t *qry, var_text_t *result)
{
    if (qry->limit.count == NULL) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " LIMIT "));
    expr_tree_t *count_exprtr = (expr_tree_t *)qry->limit.count;
    expr_tree_t *offset_exprtr = (expr_tree_t *)qry->limit.offset;
    OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, count_exprtr, result));
    if (offset_exprtr == NULL) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " OFFSET "));
    return ogsql_unparse_expr_tree(qry, offset_exprtr, result);
}

static ogsql_unparse_query g_unparse_query[] = {
    ogsql_unparse_query_cols,
    ogsql_unparse_query_from,
    ogsql_unparse_query_where,
    ogsql_unparse_query_group,
    ogsql_unparse_query_having,
    ogsql_unparse_query_sort,
    ogsql_unparse_query_limit
};

static status_t ogsql_unparse_query_info(sql_query_t *qry, var_text_t *result)
{
    if (qry == NULL) {
        OG_LOG_RUN_ERR("[UNPARSE] the qry is null");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, "SELECT"));
    uint32 count = sizeof(g_unparse_query) / sizeof(ogsql_unparse_query);
    uint32 i = 0;
    while (i < count) {
        OG_RETURN_IFERR(g_unparse_query[i++](qry, result));
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_select_type(select_node_type_t slct_type, var_text_t *result)
{
    char *str = NULL;
    if (slct_type == SELECT_NODE_UNION) {
        str = " UNION ";
    } else if (slct_type == SELECT_NODE_UNION_ALL) {
        str = " UNION ALL ";
    } else if (slct_type == SELECT_NODE_MINUS) {
        str = " MINUS ";
    } else if (slct_type == SELECT_NODE_INTERSECT) {
        str = " INTERSECT ";
    } else if (slct_type == SELECT_NODE_INTERSECT_ALL) {
        str = " INTERSECT ALL ";
    } else if (slct_type == SELECT_NODE_EXCEPT) {
        str = " EXCEPT ";
    } else if (slct_type == SELECT_NODE_EXCEPT_ALL) {
        str = " EXCEPT ALL ";
    } else {
        OG_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "set", slct_type);
        return OG_ERROR;
    }
    return cm_concat_var_string(result, str);
}

static status_t ogsql_unparse_opt_info(select_node_t *node, var_text_t *result)
{
    OG_RETURN_IFERR(ogsql_unparse_select_info(node->left, result, OG_TRUE));
    OG_RETURN_IFERR(ogsql_unparse_select_type(node->type, result));
    return ogsql_unparse_select_info(node->right, result, OG_TRUE);
}

status_t ogsql_unparse_select_info(select_node_t *node, var_text_t *result, bool32 add_brkt)
{
    if (node->type == SELECT_NODE_QUERY) {
        if (!add_brkt) {
            return ogsql_unparse_query_info(node->query, result);
        }
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
        OG_RETURN_IFERR(ogsql_unparse_query_info(node->query, result));
        return cm_concat_var_string(result, ")");
    }
    return ogsql_unparse_opt_info(node, result);
}

static status_t ogsql_unparse_select_node(expr_node_t *exprn, var_text_t *result)
{
    sql_select_t *slct = (sql_select_t *)exprn->value.v_obj.ptr;
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_select_info(slct->root, result, OG_FALSE));
    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_seq_mode(seq_mode_t mode, var_text_t *result)
{
    if (mode == SEQ_CURR_VALUE) {
        return cm_concat_var_string(result, "CURRVAL");
    } else if (mode == SEQ_NEXT_VALUE) {
        return cm_concat_var_string(result, "NEXTVAL");
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_seq_node(expr_node_t *exprn, var_text_t *result)
{
    var_seq_t *seq_var = &exprn->value.v_seq;
    if (seq_var->user.len != 0) {
        OG_RETURN_IFERR(cm_concat_n_var_string(result, seq_var->user.str, seq_var->user.len));
        OG_RETURN_IFERR(cm_concat_var_string(result, "."));
    }
    OG_RETURN_IFERR(cm_concat_n_var_string(result, seq_var->name.str, seq_var->name.len));
    OG_RETURN_IFERR(cm_concat_var_string(result, "."));
    return ogsql_unparse_seq_mode(seq_var->mode, result);
}

static status_t ogsql_unparse_case_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result)
{
    case_expr_t *case_expr = (case_expr_t *)(VALUE(pointer_t, &exprn->value));
    if (case_expr == NULL) {
        return OG_SUCCESS;
    }
    case_pair_t *case_pair = NULL;
    OG_RETURN_IFERR(cm_concat_var_string(result, "CASE "));
    if (!case_expr->is_cond) {
        OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, case_expr->expr, result));
    }

    uint32 i = 0;
    while (i < case_expr->pairs.count) {
        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i++);
        OG_RETURN_IFERR(cm_concat_var_string(result, " WHEN "));
        
        if (case_expr->is_cond) {
            if (ogsql_unparse_cond_node(qry, case_pair->when_cond->root, OG_FALSE, result) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[EXPLAIN] Failed to unparse case when condition.");
                return OG_ERROR;
            }
        } else {
            if (ogsql_unparse_expr_tree(qry, case_pair->when_expr, result) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[EXPLAIN] Failed to unparse case when expression.");
                return OG_ERROR;
            }
        }

        OG_RETURN_IFERR(cm_concat_var_string(result, " THEN "));
        OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, case_pair->value, result));
    }
    
    if (case_expr->default_expr == NULL) {
        return cm_concat_var_string(result, " END");
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " ELSE "));
    if (ogsql_unparse_expr_tree(qry, case_expr->default_expr, result) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[EXPLAIN] Failed to unparse case default expression.");
        return OG_ERROR;
    }
    return cm_concat_var_string(result, " END");
}

static status_t ogsql_unparse_negative_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result, bool32 table_unparsed)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "-"));
    return ogsql_unparse_expr_node(qry, exprn->right, result, table_unparsed);
}

static status_t ogsql_unparse_array_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "ARRAY["));
    OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, exprn->argument, result));
    return cm_concat_var_string(result, "]");
}

static status_t ogsql_unparse_user_func_args(sql_query_t *qry, expr_node_t *exprn, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_node_func_args(qry, exprn->argument, OG_INVALID_ID32, result));
    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_user_func_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result)
{
    func_word_t *func = &exprn->word.func;
    if (func->user.len != 0) {
        OG_RETURN_IFERR(cm_concat_n_var_string(result, func->user.str, func->user.len));
        OG_RETURN_IFERR(cm_concat_var_string(result, "."));
    }
    if (func->pack.len != 0) {
        OG_RETURN_IFERR(cm_concat_n_var_string(result, func->pack.str, func->pack.len));
        OG_RETURN_IFERR(cm_concat_var_string(result, "."));
    }
    OG_RETURN_IFERR(cm_concat_n_var_string(result, func->name.str, func->name.len));
    return ogsql_unparse_user_func_args(qry, exprn, result);
}

static inline status_t modify_overlong_var(text_t *var_str)
{
    if (var_str->len <= MAX_CONST_LEN) {
        return OG_SUCCESS;
    }
    var_str->len = MAX_CONST_LEN - sizeof(OUT_LINE_STRING) + 1;
    return cm_concat_n_string(var_str, MAX_CONST_LEN, OUT_LINE_STRING, sizeof(OUT_LINE_STRING) - 1);
}

static status_t ogsql_make_const_uint32(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_uint32_to_text(VALUE(uint32, var), var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_int(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_int2text(VALUE(int32, var), var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_bigint(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_bigint2text(VALUE(int64, var), var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_uint64(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_uint64_to_text(VALUE(uint32, var), var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_real(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_real2text(VALUE(double, var), var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_number(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_dec_to_text(VALUE_PTR(dec8_t, var), OG_MAX_DEC_OUTPUT_PREC, var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_bool(variant_t *var, text_t *var_str, var_text_t *result)
{
    cm_bool2text(VALUE(bool32, var), var_str);
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_char(variant_t *var, text_t *var_str, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "\'"));
    OG_RETURN_IFERR(cm_concat_n_string(var_str, DEFAULT_UNPARSE_STR_LEN, var->v_text.str,
        MIN(var->v_text.len, DEFAULT_UNPARSE_STR_LEN)));
    OG_RETURN_IFERR(modify_overlong_var(var_str));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));
    return cm_concat_var_string(result, "\'");
}

static status_t ogsql_make_const_date(variant_t *var, const nlsparams_t *nls, text_t *fmt_text, text_t *var_str, var_text_t *result)
{
    nls->param_geter(nls, NLS_DATE_FORMAT, fmt_text);
    OG_RETURN_IFERR(cm_date2text(VALUE(date_t, var), fmt_text, var_str, DEFAULT_UNPARSE_STR_LEN));

    OG_RETURN_IFERR(cm_concat_var_string(result, "TO_DATE(\'"));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));
    OG_RETURN_IFERR(cm_concat_var_string(result, ", "));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, fmt_text->str, fmt_text->len));

    return cm_concat_var_string(result, "\')");
}

static status_t ogsql_make_const_timestamp(variant_t *var, const nlsparams_t *nls, text_t *fmt_text, text_t *var_str, var_text_t *result)
{
    nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, fmt_text);
    OG_RETURN_IFERR(cm_date2text(VALUE(timestamp_t, var), fmt_text, var_str, DEFAULT_UNPARSE_STR_LEN));
    
    OG_RETURN_IFERR(cm_concat_var_string(result, "TIMESTAMP \'"));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));
    
    return cm_concat_var_string(result, "\'");
}

static status_t ogsql_make_const_timestamp_tz(variant_t *var, const nlsparams_t *nls, text_t *fmt_text, text_t *var_str, var_text_t *result)
{
    nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, fmt_text);
    OG_RETURN_IFERR(cm_date2text(VALUE(date_t, var), fmt_text, var_str, DEFAULT_UNPARSE_STR_LEN));
    
    OG_RETURN_IFERR(cm_concat_var_string(result, "TIMESTAMP \'"));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));
    
    return cm_concat_var_string(result, "\'");
}

static status_t ogsql_make_const_timestamp_ltz(variant_t *var, const nlsparams_t *nls, text_t *fmt_text, text_t *var_str, var_text_t *result)
{
    nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, fmt_text);

    /* convert from dbtimezone to sessiontimezone */
    var->v_tstamp_ltz = cm_adjust_date_between_two_tzs(var->v_tstamp_ltz, cm_get_db_timezone(),
        cm_get_session_time_zone(nls));
    OG_RETURN_IFERR(cm_timestamp2text(VALUE(timestamp_ltz_t, var), fmt_text, var_str, DEFAULT_UNPARSE_STR_LEN));
    
    OG_RETURN_IFERR(cm_concat_var_string(result, "TIMESTAMP \'"));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));
    
    return cm_concat_var_string(result, "\'");
}

static status_t ogsql_make_const_bin(variant_t *var, text_t *var_str, var_text_t *result)
{    
    OG_RETURN_IFERR(cm_concat_var_string(result, "0x"));
    binary_t *bin = VALUE_PTR(binary_t, var);
    uint32 bin_len = bin->size;
    // for print long bin
    if (bin_len * 2 >= DEFAULT_UNPARSE_STR_LEN) {
        bin->size = DEFAULT_UNPARSE_STR_LEN / 2;
    }
    var_str->len = DEFAULT_UNPARSE_STR_LEN;
    OG_RETURN_IFERR(cm_bin2text(bin, OG_FALSE, var_str));
    bin->size = bin_len;
    OG_RETURN_IFERR(modify_overlong_var(var_str));
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_make_const_interval_ds(variant_t *var, text_t *var_str, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "INTERVAL \'"));
    cm_yminterval2text(var->v_itvl_ym, var_str);
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));

    return cm_concat_var_string(result, "\' DAY(7) TO SECOND(6)");
}

static status_t ogsql_make_const_interval_ym(variant_t *var, text_t *var_str, var_text_t *result)
{
    OG_RETURN_IFERR(cm_concat_var_string(result, "INTERVAL \'"));
    cm_yminterval2text(var->v_itvl_ym, var_str);
    OG_RETURN_IFERR(cm_concat_n_var_string(result, var_str->str, var_str->len));

    return cm_concat_var_string(result, "\' YEAR(4) TO MONTH");
}

static status_t ogsql_make_const_time(interval_unit_t time_type, var_text_t *result) 
{
    switch (time_type) {
        case IU_DAY:
            OG_RETURN_IFERR(cm_concat_var_string(result, "DAY"));
            break;
        case IU_WEEK:
            OG_RETURN_IFERR(cm_concat_var_string(result, "WEEK"));
            break;
        case IU_MONTH:
            OG_RETURN_IFERR(cm_concat_var_string(result, "MONTH"));
            break;
        case IU_QUARTER:
            OG_RETURN_IFERR(cm_concat_var_string(result, "QUARTER"));
            break;
        case IU_MICROSECOND:
            OG_RETURN_IFERR(cm_concat_var_string(result, "MICROSECOND"));
            break;
        case IU_MILLISECOND:
            OG_RETURN_IFERR(cm_concat_var_string(result, "MILLISECOND"));
            break;
        case IU_SECOND:
            OG_RETURN_IFERR(cm_concat_var_string(result, "SECOND"));
            break;
        case IU_MINUTE:
            OG_RETURN_IFERR(cm_concat_var_string(result, "MINUTE"));
            break;
        case IU_HOUR:
            OG_RETURN_IFERR(cm_concat_var_string(result, "HOUR"));
            break;
        case IU_YEAR:
            OG_RETURN_IFERR(cm_concat_var_string(result, "YEAR"));
            break;
        default:
            OG_RETURN_IFERR(cm_concat_var_string(result, "UNSUPPORT TYPE"));
            return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static status_t ogsql_make_const_typmode(variant_t *var, text_t *var_str, var_text_t *result)
{
    OG_RETURN_IFERR(cm_typmode2text(&var->v_type, var_str, DEFAULT_UNPARSE_STR_LEN));
    return cm_concat_n_var_string(result, var_str->str, var_str->len);
}

static status_t ogsql_concat_var2text(variant_t *var, var_text_t *result)
{
    text_t fmt_text;
    const nlsparams_t *nls = OG_DEFALUT_SESSION_NLS_PARAMS;
    text_t var_str = { 0 };
    char buf[DEFAULT_UNPARSE_STR_LEN] = { 0 };
    bool32 is_negative = var_is_negative(var);
    var_str.str = buf;

    if (is_negative && var->type != OG_TYPE_INTERVAL_DS &&
        var->type != OG_TYPE_INTERVAL_YM) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    }

    switch (var->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_USMALLINT:
        case OG_TYPE_UTINYINT:
            OG_RETURN_IFERR(ogsql_make_const_uint32(var, &var_str, result));
            break;
        case OG_TYPE_INTEGER:
        case OG_TYPE_SMALLINT:
        case OG_TYPE_TINYINT:
            OG_RETURN_IFERR(ogsql_make_const_int(var, &var_str, result));
            break;
        case OG_TYPE_BOOLEAN:
            OG_RETURN_IFERR(ogsql_make_const_bool(var, &var_str, result));
            break;
        case OG_TYPE_BIGINT:
            OG_RETURN_IFERR(ogsql_make_const_bigint(var, &var_str, result));
            break;
        case OG_TYPE_UINT64:
            OG_RETURN_IFERR(ogsql_make_const_uint64(var, &var_str, result));
            break;
        case OG_TYPE_REAL:
        case OG_TYPE_FLOAT:
            OG_RETURN_IFERR(ogsql_make_const_real(var, &var_str, result));
            break;
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
            OG_RETURN_IFERR(ogsql_make_const_number(var, &var_str, result));
            break;
        case OG_TYPE_TYPMODE:
            OG_RETURN_IFERR(ogsql_make_const_typmode(var, &var_str, result));
            break;
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
            return ogsql_make_const_char(var, &var_str, result);
        case OG_TYPE_DATE:
            return ogsql_make_const_date(var, nls, &fmt_text, &var_str, result);
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            return ogsql_make_const_timestamp(var, nls, &fmt_text, &var_str, result);
        case OG_TYPE_TIMESTAMP_TZ:
            return ogsql_make_const_timestamp_tz(var, nls, &fmt_text, &var_str, result);
        case OG_TYPE_TIMESTAMP_LTZ:
            return ogsql_make_const_timestamp_ltz(var, nls, &fmt_text, &var_str, result);
        case OG_TYPE_RAW:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
            return ogsql_make_const_bin(var, &var_str, result);
        case OG_TYPE_INTERVAL_DS:
            return ogsql_make_const_interval_ds(var, &var_str, result);
        case OG_TYPE_INTERVAL_YM:
            return ogsql_make_const_interval_ym(var, &var_str, result);
        case OG_TYPE_ITVL_UNIT:
            return ogsql_make_const_time(var->v_itvl_unit_id, result);
        default:
            OG_THROW_ERROR(ERR_CONVERT_TYPE, get_datatype_name_str((int32)var->type), "string");
            return OG_ERROR;
    }

    return is_negative ? cm_concat_var_string(result, ")") : OG_SUCCESS;
}

status_t ogsql_unparse_const_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result)
{
    variant_t *var = &exprn->value;
    if (var->is_null) {
        return OG_SUCCESS;
    }

    return ogsql_concat_var2text(var, result);
}

status_t ogsql_unparse_column_prefix(sql_table_t *tbl, expr_node_t *node, var_text_t *result, bool32 table_unparsed)
{
    OG_RETSUC_IFTRUE(table_unparsed);
    if (node->word.column.user.len > 0) {
        OG_RETURN_IFERR(cm_concat_n_var_string(result, tbl->user.str, tbl->user.len));
        OG_RETURN_IFERR(cm_concat_var_string(result, ".")); 
    }

    bool32 is_alias_valid = (tbl->alias.len > 0 && !tbl->alias.implicit);
    if ((node->word.column.table.len == 0 && node->word.column.name.len != 0) ||
        (tbl->name.len == 0 && !is_alias_valid)) {
        return OG_SUCCESS;
    }

    const char *table_name = is_alias_valid ? tbl->alias.str : tbl->name.str;
    uint32 table_name_len = is_alias_valid ? tbl->alias.len : tbl->name.len;
    OG_RETURN_IFERR(cm_concat_n_var_string(result, table_name, table_name_len));
    return cm_concat_var_string(result, ".");
}

status_t ogsql_unparse_col_by_normal_table(sql_table_t *tbl, expr_node_t *node, var_text_t *result,
    bool32 table_unparsed)
{
    OG_RETURN_IFERR(ogsql_unparse_column_prefix(tbl, node, result, table_unparsed));
    knl_column_t *column = knl_get_column(tbl->entry->dc.handle, NODE_COL(node));
    OG_RETURN_IFERR(cm_concat_n_var_string(result, column->name, (uint32)strlen(column->name)));
    
    int32 sub_start = node->value.v_col.ss_start;
    int32 sub_end = node->value.v_col.ss_end;
    if (sub_start == OG_INVALID_ID32 && sub_end == OG_INVALID_ID32) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(cm_concat_var_string(result, "["));
    char buf[OG_MAX_INT32_STRLEN] = { 0 };
    text_t text = { buf, 0 };
    cm_int2text(sub_start, &text);
    OG_RETURN_IFERR(cm_concat_var_string(result, text.str));

    if (sub_end != OG_INVALID_ID32 && sub_start != sub_end) {
        MEMS_RETURN_IFERR(memset_sp(text.str, OG_MAX_INT32_STRLEN, 0, OG_MAX_INT32_STRLEN));
        text.len = 0;
        OG_RETURN_IFERR(cm_concat_var_string(result, ":"));
        cm_int2text(sub_end, &text);
        OG_RETURN_IFERR(cm_concat_var_string(result, text.str));
    }

    return cm_concat_var_string(result, "]");
}

static status_t ogsql_unparse_col_by_func_table(sql_table_t *tbl, expr_node_t *node,
                                         var_text_t *result, bool32 table_unparsed)
{
    OG_RETURN_IFERR(ogsql_unparse_column_prefix(tbl, node, result, table_unparsed));
    bool32 is_cast_func = cm_text_str_equal(&tbl->func.name, "CAST");
    if (is_cast_func) {
        plv_collection_t *collection = (plv_collection_t *)tbl->func.args->next->root->udt_type;
        if (collection != NULL && collection->attr_type == UDT_OBJECT) {
            plv_object_attr_t *attr = udt_seek_obj_field_byid(&collection->elmt_type->typdef.object, NODE_COL(node));
            return cm_concat_n_var_string(result, attr->name.str, attr->name.len);
        }
    }
    
    knl_column_t *column = &tbl->func.desc->columns[NODE_COL(node)];
    return cm_concat_n_var_string(result, column->name, (uint32)strlen(column->name));
}

static status_t ogsql_unparse_col_by_json_table(sql_table_t *tbl, expr_node_t *node, var_text_t *result, bool32 table_unparsed)
{
    rs_column_t *rs_column = (rs_column_t *)cm_galist_get(&tbl->json_table_info->columns, COL_OF_NODE(node));
    OG_RETURN_IFERR(ogsql_unparse_column_prefix(tbl, node, result, table_unparsed));
    return cm_concat_n_var_string(result, rs_column->name.str, rs_column->name.len);
}

static status_t ogsql_unparse_rs_column(sql_table_t *tbl, expr_node_t *node, var_text_t *result, bool32 table_unparsed)
{
    sql_query_t *qry = tbl->select_ctx->first_query;
    rs_column_t *rs_column = (rs_column_t *)cm_galist_get(qry->rs_columns, NODE_COL(node));
    uint32 ori_len = result->len;

    OG_RETURN_IFERR(ogsql_unparse_column_prefix(tbl, node, result, table_unparsed));
    if (result->len > ori_len) {
        table_unparsed = OG_TRUE;
    }

    if (rs_column->rs_flag & RS_EXIST_ALIAS) {
        return cm_concat_n_var_string(result, rs_column->name.str, rs_column->name.len);
    }

    if (rs_column->type == RS_COL_COLUMN && (rs_column->rs_flag & RS_IS_REWRITE)) {
        expr_node_t column = { 0 };
        column.type = EXPR_NODE_COLUMN;
        column.value.v_col = rs_column->v_col;
        return ogsql_unparse_column_node(qry, &column, result, table_unparsed);
    }

    if (rs_column->type == RS_COL_COLUMN || qry->pivot_items != NULL) {
        return cm_concat_n_var_string(result, rs_column->name.str, rs_column->name.len);
    }

    return ogsql_unparse_expr_node(qry, rs_column->expr->root, result, table_unparsed);
}

static status_t ogsql_unparse_column_inner(sql_query_t *qry, expr_node_t *node, var_text_t *result, bool32 table_unparsed)
{
    sql_array_t *tbl_ary = &qry->tables;
    if (tbl_ary->count <= NODE_TAB(node) && qry->s_query != NULL) {
        return ogsql_unparse_column_inner(qry->s_query, node, result, table_unparsed);
    }

    sql_table_t *tbl = (sql_table_t *)sql_array_get(tbl_ary, NODE_TAB(node));

    if (tbl->type == NORMAL_TABLE) {
        return ogsql_unparse_col_by_normal_table(tbl, node, result, table_unparsed);
    } else if (tbl->type == FUNC_AS_TABLE) {
        return ogsql_unparse_col_by_func_table(tbl, node, result, table_unparsed);
    } else if (tbl->type == JSON_TABLE) {
        return ogsql_unparse_col_by_json_table(tbl, node, result, table_unparsed);
    } else {
        return ogsql_unparse_rs_column(tbl, node, result, table_unparsed);
    }
}

static status_t ogsql_unparse_column_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result, bool32 table_unparsed)
{
    uint32 i = 0;
    while (i++ < NODE_ANCESTOR(exprn)) {
        qry = qry->owner->parent;
    }
    return ogsql_unparse_column_inner(qry, exprn, result, table_unparsed);
}

static status_t ogsql_unparse_group_node(sql_query_t *qry, expr_node_t *node, var_text_t *result, bool32 table_unparsed)
{
    expr_node_t *origin_ref = (expr_node_t *)VALUE_PTR(var_vm_col_t, &node->value)->origin_ref;
    if (NODE_EXPR_TYPE(origin_ref) != EXPR_NODE_COLUMN) {
        return ogsql_unparse_expr_node(qry, origin_ref, result, table_unparsed);
    }

    if (!NODE_VM_ANCESTOR(node)) {
        return ogsql_unparse_column_node(qry, origin_ref, result, table_unparsed);
    }

    uint32 i = 0;
    while (i++ < NODE_VM_ANCESTOR(node)) {
        qry = qry->owner->parent;
    }
    return ogsql_unparse_column_inner(qry, origin_ref, result, table_unparsed);
}

static status_t ogsql_unparse_aggr_node(sql_query_t *qry, expr_node_t *node, var_text_t *result)
{
    uint32 id = node->value.v_uint32;
    if (id < qry->aggrs->count) {
        expr_node_t *aggr = (expr_node_t *)cm_galist_get(qry->aggrs, id);
        return ogsql_unparse_node_func(qry, aggr, result, OG_FALSE);
    }

    OG_THROW_ERROR(ERR_ASSERT_ERROR, "aggr_id < qry->aggrs->count");
    return OG_ERROR;
}

static status_t ogsql_unparse_over_func(sql_query_t *qry, expr_node_t *node, var_text_t *result)
{
    OG_RETURN_IFERR(sql_get_winsort_func_id(&node->word.func.name, &node->value.v_func));
    winsort_func_t *win_func = sql_get_winsort_func(&node->value.v_func);
    OG_RETURN_IFERR(cm_concat_var_string(result, win_func->name.str));
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    uint32 func_id = sql_get_func_id(&win_func->name);
    OG_RETURN_IFERR(ogsql_unparse_node_func_args(qry, node->argument, func_id, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
    return OG_SUCCESS;
}

static status_t ogsql_unparse_over_broder(sql_query_t *qry, windowing_args_t *windowing, var_text_t *result)
{
    const char *frame_type = windowing->is_range ? " RANGE BETWEEN " : " ROWS BETWEEN ";
    OG_RETURN_IFERR(cm_concat_var_string(result, frame_type));

    OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, windowing->l_expr, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, sql_get_winsort_border_name(windowing->l_type)));
    OG_RETURN_IFERR(cm_concat_var_string(result, " AND "));
    OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, windowing->r_expr, result));
    return cm_concat_var_string(result, sql_get_winsort_border_name(windowing->r_type));
}

static status_t ogsql_unparse_over_partition_clause(sql_query_t *qry, expr_node_t *node, var_text_t *result)
{
    galist_t *expr_lst = node->win_args->group_exprs;
    if (expr_lst == NULL || expr_lst->count == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(cm_concat_var_string(result, "PARTITION BY "));
 
    return ogsql_unparse_expr_tree_list(qry, expr_lst, result);
}

static status_t ogsql_unparse_sort_args(sort_item_t *sort_item, var_text_t *result)
{
    if (sort_item->direction == SORT_MODE_DESC) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " DESC "));
    } else if (sort_item->direction == SORT_MODE_ASC) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " ASC "));
    }

    if (sort_item->nulls_pos == SORT_NULLS_FIRST) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "NULLS FIRST")); 
    } else if (sort_item->nulls_pos == SORT_NULLS_LAST) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "NULLS LAST"));
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_sort_items(sql_query_t *qry, galist_t *sort_item_lst, var_text_t *result)
{
    sort_item_t *sort_item = NULL;
    uint32 count = sort_item_lst->count;
    uint32 i = 0;

    while (i < count) {
        sort_item = (sort_item_t *)cm_galist_get(sort_item_lst, i);
        OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, sort_item->expr, result));
        OG_RETURN_IFERR(ogsql_unparse_sort_args(sort_item, result));

        if (i == count - 1) {
            break;
        }

        OG_RETURN_IFERR(cm_concat_var_string(result, ", "));
        i++;
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_over_order_clause(sql_query_t *qry, expr_node_t *node, var_text_t *result)
{
    galist_t *sort_item_lst = node->win_args->sort_items;
    if (sort_item_lst == NULL || sort_item_lst->count == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(cm_concat_var_string(result, " ORDER BY "));
    OG_RETURN_IFERR(ogsql_unparse_sort_items(qry, sort_item_lst, result));
    
    if (node->win_args->windowing != NULL) {
        OG_RETURN_IFERR(ogsql_unparse_over_broder(qry, node->win_args->windowing, result));
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_over_node(sql_query_t *qry, expr_node_t *node, var_text_t *result)
{
    expr_node_t *over_func = node->argument->root;
    if (ogsql_unparse_over_func(qry, over_func, result) != OG_SUCCESS) {
        return OG_ERROR; 
    }

    OG_RETURN_IFERR(cm_concat_var_string(result, " OVER ("));

    if (ogsql_unparse_over_partition_clause(qry, node, result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogsql_unparse_over_order_clause(qry, node, result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_expr_not_operation(sql_query_t *qry, expr_node_t *exprn, var_text_t *result,
                                          bool32 table_unparsed)
{
    switch (exprn->type) {
        case EXPR_NODE_PRIOR:
            return ogsql_unparse_prior_node(qry, exprn, result, table_unparsed);
        case EXPR_NODE_CONST:
            return ogsql_unparse_const_node(qry, exprn, result);
        case EXPR_NODE_FUNC:
        case EXPR_NODE_PROC:
            return ogsql_unparse_node_func(qry, exprn, result, table_unparsed);
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
            return cm_concat_var_string(result, "?");
        case EXPR_NODE_COLUMN:
            return ogsql_unparse_column_node(qry, exprn, result, table_unparsed);
        case EXPR_NODE_STAR:
            return cm_concat_var_string(result, "*");
        case EXPR_NODE_RESERVED:
            return ogsql_unparse_reserved_node(exprn, result);
        case EXPR_NODE_SELECT:
            return ogsql_unparse_select_node(exprn, result);
        case EXPR_NODE_SEQUENCE:
            return ogsql_unparse_seq_node(exprn, result);
        case EXPR_NODE_CASE:
            return ogsql_unparse_case_node(qry, exprn, result);
        case EXPR_NODE_GROUP:
            return ogsql_unparse_group_node(qry, exprn, result, table_unparsed);
        case EXPR_NODE_AGGR:
            return ogsql_unparse_aggr_node(qry, exprn, result);
        case EXPR_NODE_USER_FUNC:
            return ogsql_unparse_user_func_node(qry, exprn, result);
        case EXPR_NODE_OVER:
            return ogsql_unparse_over_node(qry, exprn, result);
        case EXPR_NODE_TRANS_COLUMN:
            return OG_SUCCESS;
        case EXPR_NODE_NEGATIVE:
            return ogsql_unparse_negative_node(qry, exprn, result, table_unparsed);
        case EXPR_NODE_ARRAY:
            return ogsql_unparse_array_node(qry, exprn, result);
        default:
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "expression not in type list");
            return OG_ERROR;
    }
}

static status_t ogsql_unparse_expr_node(sql_query_t *qry, expr_node_t *exprn, var_text_t *result, bool32 table_unparsed)
{
    if (exprn->type >= EXPR_NODE_MUL && exprn->type <= EXPR_NODE_CAT) {
        return ogsql_unparse_expr_operation(qry, exprn, result, table_unparsed);
    }
    return ogsql_unparse_expr_not_operation(qry, exprn, result, table_unparsed);
}

static status_t ogsql_unparse_expr_tree(sql_query_t *qry, expr_tree_t *exprtr, var_text_t *result)
{
    // the first exprtr node
    OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, exprtr->root, result, OG_FALSE));
    exprtr = exprtr->next;
    // the next exprtr nodes
    while (exprtr != NULL) {
        OG_RETURN_IFERR(cm_concat_var_string(result, ","));
        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, exprtr->root, result, OG_FALSE));
        exprtr = exprtr->next;
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_expr_tree_list(sql_query_t *qry, galist_t *lst, var_text_t *result)
{   
    uint32 i = 0;
    while (i < lst->count) {
        expr_tree_t *exprtr = (expr_tree_t *)cm_galist_get(lst, i);
        if (NODE_IS_RES_NULL(exprtr->root)) {
            continue;
        }
        OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, exprtr, result));
        if (i < lst->count - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ","));
        }
        i++;
    }
    return OG_SUCCESS;
}

static const char *ogsql_get_args_devider(uint32 func_id)
{
    if (func_id == ID_FUNC_ITEM_EXTRACT) {
        return " FROM ";
    } else if (func_id == ID_FUNC_ITEM_CAST) {
        return " AS ";
    } else {
        return ", ";
    }
}

static status_t ogsql_unparse_node_func_args(sql_query_t *qry, expr_tree_t *exprtr, uint32 func_id, var_text_t *result)
{
    while (exprtr != NULL) {
        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, exprtr->root, result, OG_FALSE));
        if (exprtr->next != NULL) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ogsql_get_args_devider(func_id)));
        }
        exprtr = exprtr->next;
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_func_if(sql_query_t *qry, expr_node_t *node, sql_func_t *function, var_text_t *result)
{
    char func_name[OG_NAME_BUFFER_SIZE] = {0};
    cm_str_to_upper(function->name.str, func_name);
    OG_RETURN_IFERR(cm_concat_var_string(result, func_name));
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, node->cond_arg->root, OG_FALSE, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ", "));
    OG_RETURN_IFERR(ogsql_unparse_node_func_args(qry, node->argument, function->builtin_func_id, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ")"));

    return OG_SUCCESS;
}

static status_t ogsql_unparse_func_lnnvl(sql_query_t *qry, expr_node_t *node, sql_func_t *function, var_text_t *result)
{
    char func_name[OG_NAME_BUFFER_SIZE] = {0};
    cm_str_to_upper(function->name.str, func_name);
    OG_RETURN_IFERR(cm_concat_var_string(result, func_name));
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, node->cond_arg->root, OG_FALSE, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ")"));

    return OG_SUCCESS;
}

static status_t ogsql_unparse_func_group_concat(sql_query_t *qry, expr_node_t *node, sql_func_t *function,
                                                var_text_t *result)
{
    char func_name[OG_NAME_BUFFER_SIZE] = {0};
    cm_str_to_upper(function->name.str, func_name);
    OG_RETURN_IFERR(cm_concat_var_string(result, func_name));
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_node_func_args(qry, node->argument->next, function->builtin_func_id, result));
    if (node->sort_items != NULL) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " ORDER BY "));
        OG_RETURN_IFERR(ogsql_unparse_sort_items(qry, node->sort_items, result));
    }

    OG_RETURN_IFERR(cm_concat_var_string(result, " SEPARATOR "));
    OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, node->argument->root, result, function->builtin_func_id));

    OG_RETURN_IFERR(cm_concat_var_string(result, ")"));

    return OG_SUCCESS;
}

static status_t ogsql_unparse_func_default(sql_query_t *qry, expr_node_t *node, sql_func_t *function,
    var_text_t *result)
{
    char func_name[OG_NAME_BUFFER_SIZE] = {0};
    cm_str_to_upper(function->name.str, func_name);
    OG_RETURN_IFERR(cm_concat_var_string(result, func_name));
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_node_func_args(qry, node->argument, function->builtin_func_id, result));
    OG_RETURN_IFERR(cm_concat_var_string(result, ")"));

    return OG_SUCCESS;
}

static status_t ogsql_unparse_node_func(sql_query_t *qry, expr_node_t *node, var_text_t *result, bool32 table_unparsed)
{
    sql_func_t *function = sql_get_func(&node->value.v_func);
    switch (function->builtin_func_id) {
        case ID_FUNC_ITEM_IF:
            return ogsql_unparse_func_if(qry, node, function, result);
        case ID_FUNC_ITEM_LNNVL:
            return ogsql_unparse_func_lnnvl(qry, node, function, result);
        case ID_FUNC_ITEM_GROUP_CONCAT:
            return ogsql_unparse_func_group_concat(qry, node, function, result);
        default:
            return ogsql_unparse_func_default(qry, node, function, result);
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_hash_exprs(sql_query_t *qry, galist_t *l_expr_lst, galist_t *r_expr_lst, var_text_t *result)
{
    uint32 id = 0;
    const char *prefix = "";
    expr_tree_t *left_exprtr = NULL;
    expr_tree_t *right_exprtr = NULL;

    while (id < l_expr_lst->count) {
        OG_RETURN_IFERR(cm_concat_var_string(result, prefix));
        left_exprtr = (expr_tree_t *)cm_galist_get(l_expr_lst, id);
        right_exprtr = (expr_tree_t *)cm_galist_get(r_expr_lst, id);
        if (TREE_EXPR_TYPE(left_exprtr) != EXPR_NODE_TRANS_COLUMN &&
        TREE_EXPR_TYPE(right_exprtr) != EXPR_NODE_TRANS_COLUMN) {
            OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, left_exprtr->root, result, OG_FALSE));
            OG_RETURN_IFERR(cm_concat_var_string(result, " = "));
            OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, right_exprtr->root, result, OG_FALSE));
        } else {
            OG_RETURN_IFERR(cm_concat_var_string(result, "NA = NA"));
        }
        prefix = " AND ";
        id++;
    }

    return OG_SUCCESS;
}

status_t ogsql_unparse_connect_mtrl_join_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result)
{
    galist_t *p_expr_lst = plan->cb_mtrl.prior_exprs;
    galist_t *k_expr_lst = plan->cb_mtrl.key_exprs;

    if (p_expr_lst != NULL) {
        OG_RETURN_IFERR(ogsql_unparse_hash_exprs(qry, p_expr_lst, k_expr_lst, result));
    }

    cond_tree_t *tree = plan->cb_mtrl.connect_by_cond;
    if (tree == NULL || tree->root->type == COND_NODE_TRUE) {
        return OG_SUCCESS;
    }

    if (p_expr_lst != NULL && p_expr_lst->count > 0) {
        OG_RETURN_IFERR(cm_concat_var_string(result, " AND "));
    }
    return ogsql_unparse_cond_node(qry, tree->root, OG_FALSE, result);
}

status_t ogsql_unparse_hash_mtrl_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result)
{
    galist_t *l_expr_lst = plan->hash_mtrl.group.exprs;
    galist_t *r_expr_lst = plan->hash_mtrl.remote_keys;

    return ogsql_unparse_hash_exprs(qry, l_expr_lst, r_expr_lst, result);
}

static status_t ogsql_unparse_cond_unknown(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    return OG_SUCCESS;
}

static status_t ogsql_unparse_basic_compare(sql_query_t *qry, cmp_node_t *cmp, var_text_t *result)
{
    return ogsql_unparse_expr_node(qry, cmp->right->root, result, OG_FALSE);
}

static status_t ogsql_unparse_match_compare(sql_query_t *qry, cmp_node_t *cmp, var_text_t *result)
{
    expr_tree_t *exprtr = cmp->right;
    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    const char *separator = "";
    for (; exprtr != NULL; exprtr = exprtr->next) {
        OG_RETURN_IFERR(cm_concat_var_string(result, separator));
        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, exprtr->root, result, OG_FALSE));
        separator = ", ";
    }

    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_in_expr(sql_query_t *qry, expr_tree_t *exprtr, uint32 len, var_text_t *result)
{
    uint32 index = 0;
    for (; exprtr != NULL; exprtr = exprtr->next) {
        if (index > 0) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ", "));
        }

        if (index % len == 0) {
            OG_RETURN_IFERR(cm_concat_var_string(result, "("));
        }

        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, exprtr->root, result, OG_FALSE));

        if (index % len == len - 1) {
            OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
        }

        index++;
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_in_compare(sql_query_t *qry, cmp_node_t *cmp, var_text_t *result)
{
    uint32 len = sql_expr_list_len(cmp->left);
    if (len == 1 || TREE_EXPR_TYPE(cmp->right) == EXPR_NODE_SELECT) {
        return ogsql_unparse_match_compare(qry, cmp, result);
    }

    OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    OG_RETURN_IFERR(ogsql_unparse_in_expr(qry, cmp->right, len, result));
    return cm_concat_var_string(result, ")");
}

static status_t ogsql_unparse_like_compare(sql_query_t *qry, cmp_node_t *cmp, var_text_t *result)
{
    OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, cmp->right->root, result, OG_FALSE));
    if (cmp->right->next == NULL) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(cm_concat_var_string(result, " ESCAPE "));
    return ogsql_unparse_expr_node(qry, cmp->right->next->root, result, OG_FALSE);
}

static status_t ogsql_unparse_between_compare(sql_query_t *qry, cmp_node_t *cmp, var_text_t *result)
{
    OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, cmp->right->root, result, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(result, " AND "));
    return ogsql_unparse_expr_node(qry, cmp->right->next->root, result, OG_FALSE);
}

static const char* get_cmp_symbols(cmp_type_t cmp_type)
{
    if (cmp_type >= CMP_TYPE_EQUAL && cmp_type <= CMP_TYPE_IS_NOT_JSON) {
        return g_cmp_symbols[cmp_type - CMP_TYPE_EQUAL];
    }
    return "";
}

static status_t ogsql_unparse_compare_left(sql_query_t *qry, cmp_node_t *cmp, var_text_t *result)
{
    if (cmp->left == NULL) {
        return cm_concat_var_string(result, get_cmp_symbols(cmp->type));
    }

    if (cmp->left->next != NULL) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
        OG_RETURN_IFERR(ogsql_unparse_expr_tree(qry, cmp->left, result));
        OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
    } else {
        OG_RETURN_IFERR(ogsql_unparse_expr_node(qry, cmp->left->root, result, OG_FALSE));
    }

    if (TREE_EXPR_TYPE(cmp->left) != EXPR_NODE_TRANS_COLUMN) {
        return cm_concat_var_string(result, get_cmp_symbols(cmp->type));
    }

    return OG_SUCCESS;
}

static status_t ogsql_unparse_cond_compare(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    cmp_node_t *cmp = (cmp_node_t *)cond->cmp;
    OG_RETURN_IFERR(ogsql_unparse_compare_left(qry, cmp, result));

    switch (cmp->type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
            return ogsql_unparse_basic_compare(qry, cmp, result);
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
            return ogsql_unparse_match_compare(qry, cmp, result);
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
            return ogsql_unparse_in_compare(qry, cmp, result);
        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            return ogsql_unparse_like_compare(qry, cmp, result);
        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
            return ogsql_unparse_between_compare(qry, cmp, result);
        default:
            return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_cond_or(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    // left round brackets
    if (add_rnd_brkt) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    }
    // left node
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, cond->left, (cond->left->type == COND_NODE_AND), result));
    // OR symbol
    OG_RETURN_IFERR(cm_concat_var_string(result, " OR "));
    // right node
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, cond->right, (cond->right->type == COND_NODE_AND), result));
    // right round brackets
    if (add_rnd_brkt) {
        OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_cond_and(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    // left round brackets
    if (add_rnd_brkt) {
        OG_RETURN_IFERR(cm_concat_var_string(result, "("));
    }
    // left node
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, cond->left, (cond->left->type == COND_NODE_OR), result));
    // OR symbol
    OG_RETURN_IFERR(cm_concat_var_string(result, " AND "));
    // right node
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, cond->right, (cond->right->type == COND_NODE_OR), result));
    // right round brackets
    if (add_rnd_brkt) {
        OG_RETURN_IFERR(cm_concat_var_string(result, ")"));
    }
    return OG_SUCCESS;
}

static status_t ogsql_unparse_cond_not(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    return OG_SUCCESS;
}

static status_t ogsql_unparse_cond_true(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    return cm_concat_var_string(result, "TRUE");
}

static status_t ogsql_unparse_cond_false(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    return cm_concat_var_string(result, "NULL IS NOT NULL");
}

static cond_unparser_t g_unparse_conds[] = {{COND_NODE_UNKNOWN, ogsql_unparse_cond_unknown},
                                            {COND_NODE_COMPARE, ogsql_unparse_cond_compare},
                                            {COND_NODE_OR, ogsql_unparse_cond_or},
                                            {COND_NODE_AND, ogsql_unparse_cond_and},
                                            {COND_NODE_NOT, ogsql_unparse_cond_not},
                                            {COND_NODE_TRUE, ogsql_unparse_cond_true},
                                            {COND_NODE_FALSE, ogsql_unparse_cond_false}};

status_t ogsql_unparse_cond_node(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result)
{
    if (cond == NULL || result == NULL) {
        return OG_ERROR;
    }
    if (cond->type >= sizeof(g_unparse_conds) / sizeof(cond_unparser_t)) {
        OG_LOG_RUN_ERR("[UNPARSE] the type of condition %d is not in the supported list.", cond->type);
        return OG_ERROR;
    }
    CM_ASSERT(cond->type == g_unparse_conds[cond->type].type);
    return g_unparse_conds[cond->type].cond_unparse_func(qry, cond, add_rnd_brkt, result);
}

status_t ogsql_unparse_merge_hash_cond_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result)
{
    galist_t *l_expr_lst = plan->merge_p.merge_keys;
    galist_t *r_expr_lst = plan->merge_p.using_keys;

    return ogsql_unparse_hash_exprs(qry, l_expr_lst, r_expr_lst, result);
}

status_t ogsql_unparse_hash_join_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result)
{
    galist_t *l_expr_lst = plan->join_p.left_hash.key_items;
    galist_t *r_expr_lst = plan->join_p.right_hash.key_items;

    return ogsql_unparse_hash_exprs(qry, l_expr_lst, r_expr_lst, result);
}

status_t ogsql_unparse_merge_join_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result)
{
    cond_node_t cond = {
        .cmp = (cmp_node_t *)cm_galist_get(plan->join_p.cmp_list, 0)
    };
    return ogsql_unparse_cond_compare(qry, &cond, OG_FALSE, result);
}
