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
* ogsql_verifier_common.c
*
*
* IDENTIFICATION
* src/ogsql/verifier/ogsql_verifier_common.c
*
* -------------------------------------------------------------------------
*/
#include "ogsql_update_verifier.h"
#include "ogsql_select_verifier.h"
#include "ogsql_table_verifier.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "base_compiler.h"
#include "expr_parser.h"
#include "ogsql_plan.h"
#include "ogsql_winsort.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 check_column_nullable(sql_query_t *sql_query, var_column_t *var_col)
{
    sql_table_t *table;
    OG_RETVALUE_IFTRUE((var_col->tab >= sql_query->tables.count), OG_FALSE);
    table = (sql_table_t *)sql_array_get(&sql_query->tables, var_col->tab);
    OG_RETVALUE_IFTRUE((table == NULL), OG_FALSE);
    OG_RETVALUE_IFTRUE((table->rs_nullable == OG_TRUE), OG_TRUE);

    rs_column_t *rs_col = NULL;
    knl_column_t *knl_col = NULL;
    if (table->type == VIEW_AS_TABLE || table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE) {
        rs_col = (rs_column_t *)cm_galist_get(table->select_ctx->first_query->rs_columns, var_col->col);
        return OG_BIT_TEST(rs_col->rs_flag, RS_STRICT_NULLABLE) != 0;
    }

    if (table->type == FUNC_AS_TABLE) {
        knl_col = &table->func.desc->columns[var_col->col];
        return knl_col->nullable;
    }

    if (table->type == JSON_TABLE) {
        rs_col = (rs_column_t *)cm_galist_get(&table->json_table_info->columns, var_col->col);
        return OG_BIT_TEST(rs_col->rs_flag, RS_STRICT_NULLABLE) != 0;
    }

    knl_col = knl_get_column(table->entry->dc.handle, var_col->col);
    return knl_col->nullable;
}

static bool32 rsnode_nullablechk_column(visit_assist_t *visit_assist, expr_node_t *expr_node)
{
    bool32 ret;
    sql_query_t *sql_query = sql_get_ancestor_query(visit_assist->query, NODE_ANCESTOR(expr_node));
    OG_RETVALUE_IFTRUE((sql_query == NULL), OG_TRUE);

    if ((sql_query->owner != NULL && sql_query->owner->root->type != SELECT_NODE_QUERY) ||
         sql_query->group_sets->count > 1) {
        return OG_TRUE;
    }

    ret = check_column_nullable(sql_query, &expr_node->value.v_col);
    return ret;
}

static bool32 rsnode_nullablechk_reserved_word(visit_assist_t *visit_assist, expr_node_t *expr_node)
{
    OG_RETVALUE_IFTRUE((NODE_IS_RES_NULL(expr_node)), OG_TRUE);
    if (!NODE_IS_RES_ROWID(expr_node)) {
        return OG_FALSE;
    }
    sql_query_t *sql_query = sql_get_ancestor_query(visit_assist->query, ROWID_NODE_ANCESTOR(expr_node));
    OG_RETVALUE_IFTRUE((sql_query == NULL), OG_TRUE);
    if ((sql_query->owner != NULL && sql_query->owner->root->type != SELECT_NODE_QUERY) ||
        sql_query->group_sets->count > 1) {
        return OG_TRUE;
    }

    OG_RETVALUE_IFTRUE((ROWID_NODE_TAB(expr_node) >= sql_query->tables.count), OG_FALSE);
    sql_table_t *sql_table = (sql_table_t *)sql_array_get(&sql_query->tables, ROWID_NODE_TAB(expr_node));
    OG_RETVALUE_IFTRUE((sql_table == NULL), OG_FALSE);
    return sql_table->rs_nullable;
}

static bool32 rsnode_nullablechk_subselect(expr_node_t *expr_node)
{
    sql_select_t *ctx = (sql_select_t *)expr_node->value.v_obj.ptr;
    OG_RETVALUE_IFTRUE((ctx->root->type != SELECT_NODE_QUERY), OG_TRUE);

    rs_column_t *rs_columns = (rs_column_t *)cm_galist_get(ctx->first_query->rs_columns, 0);
    return OG_BIT_TEST(rs_columns->rs_flag, RS_NULLABLE) != 0;
}

static status_t rsnode_nullablechk(visit_assist_t *visit_assist, expr_node_t **expr_node);

static status_t rsnode_nullablechk_case(visit_assist_t *visit_assist, expr_node_t *expr_node)
{
    case_pair_t *pair = NULL;
    case_expr_t *expr = (case_expr_t *)expr_node->value.v_pointer;
    
    uint32 i = 0;
    while (i < expr->pairs.count) {
        pair = (case_pair_t *)cm_galist_get(&expr->pairs, i);
        OG_RETURN_IFERR(visit_expr_tree(visit_assist, pair->value, rsnode_nullablechk));
        i++;
    }

    if (expr->default_expr != NULL &&
        visit_expr_tree(visit_assist, expr->default_expr, rsnode_nullablechk) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline bool32 is_buildin_func_with_cond(uint32 func_id)
{
    return (func_id == ID_FUNC_ITEM_LNNVL) || (func_id == ID_FUNC_ITEM_IF);
}

static status_t rsnode_nullablechk_func(visit_assist_t *visit_assist, expr_node_t *expr_node)
{
    if (expr_node->value.v_func.pack_id == OG_INVALID_ID32) {
        sql_func_t *func = sql_get_func(&expr_node->value.v_func);
        OG_RETSUC_IFTRUE((func->builtin_func_id == ID_FUNC_ITEM_COUNT));
        if (func->builtin_func_id != ID_FUNC_ITEM_NULLIF) {
            if (is_buildin_func_with_cond(func->builtin_func_id) || check_func_with_sort_items(expr_node)) {
                return visit_expr_tree(visit_assist, expr_node->argument, rsnode_nullablechk);
            } else {
                return visit_func_node(visit_assist, expr_node, rsnode_nullablechk);
            }
        }
    }

    visit_assist->result0 = OG_TRUE;
    return OG_SUCCESS;
}

static status_t rsnode_nullablechk_winsort(visit_assist_t *visit_assist, expr_node_t *expr_node)
{
    expr_node_t *func = expr_node->argument->root;
    winsort_func_t *winsort_func = sql_get_winsort_func(&func->value.v_func);
    OG_RETSUC_IFTRUE(cm_text_str_equal_ins(&winsort_func->name, "COUNT"));
    return visit_expr_tree(visit_assist, func->argument, rsnode_nullablechk);
}

static status_t rsnode_nullablechk(visit_assist_t *visit_assist, expr_node_t **expr_node)
{
    OG_RETSUC_IFTRUE((visit_assist->result0));
    expr_node_type_t type = (*expr_node)->type;
    
    if (type == EXPR_NODE_COLUMN) {
        visit_assist->result0 = rsnode_nullablechk_column(visit_assist, *expr_node);
        return OG_SUCCESS;
    }
    if (type == EXPR_NODE_RESERVED) {
        visit_assist->result0 = rsnode_nullablechk_reserved_word(visit_assist, *expr_node);
        return OG_SUCCESS;
    }
    if (type == EXPR_NODE_SELECT) {
        visit_assist->result0 = rsnode_nullablechk_subselect(*expr_node);
        return OG_SUCCESS;
    }
    if (type == EXPR_NODE_CASE) {
        return rsnode_nullablechk_case(visit_assist, *expr_node);
    }
    if (type == EXPR_NODE_FUNC) {
        return rsnode_nullablechk_func(visit_assist, *expr_node);
    }
    if (type == EXPR_NODE_AGGR) {
        return rsnode_nullablechk_func(visit_assist,
                                       (expr_node_t *)cm_galist_get(visit_assist->query->aggrs,
                                       (*expr_node)->value.v_uint32));
    }
    if (type == EXPR_NODE_OVER) {
        return rsnode_nullablechk_winsort(visit_assist, *expr_node);
    }
    if (type == EXPR_NODE_CONST) {
        OG_RETSUC_IFTRUE((!(*expr_node)->value.is_null));
        visit_assist->result0 = OG_TRUE;
        return OG_SUCCESS;
    }
    if (type == EXPR_NODE_ARRAY || type == EXPR_NODE_STAR) {
        return OG_SUCCESS;
    }
    visit_assist->result0 = OG_TRUE;
    return OG_SUCCESS;
}

status_t ogsql_set_rs_strict_null_flag(sql_verifier_t *verf, rs_column_t *rs_col)
{
    if (verf->curr_query == NULL) {
        OG_BIT_SET(rs_col->rs_flag, RS_STRICT_NULLABLE);
        return OG_SUCCESS;
    }
    visit_assist_t visit_assist = { 0 };
    sql_init_visit_assist(&visit_assist, verf->stmt, verf->curr_query);
    visit_assist.result0 = OG_FALSE;
    visit_assist.excl_flags = VA_EXCL_WIN_SORT | VA_EXCL_FUNC | VA_EXCL_PROC | VA_EXCL_ARRAY | VA_EXCL_CASE;

    OG_RETURN_IFERR(visit_expr_tree(&visit_assist, rs_col->expr, rsnode_nullablechk));

    if (visit_assist.result0) {
        OG_BIT_SET(rs_col->rs_flag, RS_STRICT_NULLABLE);
    }
    return OG_SUCCESS;
}

// modify is_cond_col for dynamic qry
status_t og_modify_query_cond_col(visit_assist_t *v_ast, expr_node_t **exprn)
{
    sql_table_t *tbl = NULL;
    query_field_t *field = NULL;
    bilist_node_t *blst_cur = NULL;
    OG_RETSUC_IFTRUE(NODE_EXPR_TYPE(*exprn) != EXPR_NODE_COLUMN || NODE_ANCESTOR(*exprn) > 0)
    tbl = (sql_table_t *)sql_array_get(&v_ast->query->tables, (*exprn)->value.v_col.tab);
    blst_cur = cm_bilist_head(&tbl->query_fields);
    while (blst_cur != NULL) {
        field = BILIST_NODE_OF(query_field_t, blst_cur, bilist_node);
        if (field->col_id == NODE_COL(*exprn)) {
            field->is_cond_col = OG_TRUE;
            return OG_SUCCESS;
        }
        blst_cur = blst_cur->next;
    }
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
