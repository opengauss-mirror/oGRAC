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
 * ogsql_connect_rewrite.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_connect_rewrite.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_connect_rewrite.h"
#include "ogsql_transform.h"
#include "ogsql_plan.h"
#include "ogsql_select_parser.h"
#include "srv_instance.h"
#include "ogsql_cond_rewrite.h"
#include "ogsql_optim_common.h"

status_t sql_generate_start_query(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_query_t *s_query = NULL;
    sql_table_t *table = NULL;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&s_query));
    OG_RETURN_IFERR(sql_init_query(stmt, query->owner, query->loc, s_query));

    /* clone join tables */
    OG_RETURN_IFERR(clone_tables_4_subqry(stmt, query, s_query));
    for (uint32 i = 0; i < s_query->tables.count; ++i) {
        table = (sql_table_t *)sql_array_get(&s_query->tables, i);
        table->plan_id = (query->tables.count > 1) ? OG_INVALID_ID32 : 0;
    }

    /* clone join assist */
    if (query->join_assist.join_node != NULL) {
        OG_RETURN_IFERR(sql_clone_join_root(stmt, stmt->context, query->join_assist.join_node,
            &s_query->join_assist.join_node, &s_query->tables, sql_alloc_mem));
    }
    s_query->join_assist.outer_node_count = query->join_assist.outer_node_count;
    s_query->cond = query->start_with_cond;
    s_query->is_s_query = OG_TRUE;
    s_query->cond_has_acstor_col = sql_cond_has_acstor_col(stmt, s_query->cond, s_query);
    query->s_query = s_query;
    return OG_SUCCESS;
}

static inline bool32 if_cmp_used_by_connect_mtrl(cols_used_t *prior_cols_used, cols_used_t *key_cols_used)
{
    // Only PRIOR expr can probe the materialized hash table; dynamic subqueries may depend on recursive rows.
    if (!HAS_PRIOR(prior_cols_used) || !HAS_NO_COLS(prior_cols_used->flags) ||
        HAS_DYNAMIC_SUBSLCT(prior_cols_used) || HAS_ROWNUM(prior_cols_used)) {
        return OG_FALSE;
    }

    if (HAS_DYNAMIC_SUBSLCT(key_cols_used) || HAS_ROWNUM(key_cols_used) || HAS_PRIOR(key_cols_used)) {
        return OG_FALSE;
    }

    /*
     * A normal key is a same-level column expression. A static no-column expression, for example
     * PRIOR col = ANY (SELECT MIN(col) FROM ...), is also safe: every materialized row shares the
     * same hash key and only the matching PRIOR value opens that bucket.
     */
    if (HAS_NO_COLS(key_cols_used->flags)) {
        return OG_TRUE;
    }
    return (bool32)(HAS_ONLY_SELF_COLS(key_cols_used->flags) && !HAS_DIFF_TABS(key_cols_used, SELF_IDX));
}

static inline void clear_table_cbo_filter(sql_query_t *query)
{
    sql_table_t *table = NULL;
    query->join_root = NULL;
    for (uint32 i = 0; i < query->tables.count; ++i) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        TABLE_CBO_FILTER(table) = NULL;
        TABLE_CBO_SAVE_TABLES(table) = NULL;
        TABLE_CBO_SUBGRP_TABLES(table) = NULL;
        TABLE_CBO_IDX_REF_COLS(table) = NULL;
        TABLE_CBO_FILTER_COLS(table) = NULL;
        TABLE_CBO_DRV_INFOS(table) = NULL;
        TABLE_CBO_IS_DEAL(table) = OG_FALSE;
        table->cost = (double)0;
    }
    query->filter_infos = NULL;
    vmc_free(query->vmc);
}

static status_t handle_sub_qry_ssa(sql_query_t *qry, sql_query_t *sub_qry)
{
    CM_POINTER2(qry, sub_qry);
    OG_RETURN_IFERR(sql_array_concat(&qry->ssa, &sub_qry->ssa));
    sql_array_reset(&sub_qry->ssa);
    return OG_SUCCESS;
}

static status_t og_tranforms_query_4_connectby(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER(qry);
    if (sql_generate_start_query(statement, qry) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("generate start query failed");
        return OG_ERROR;
    }
    sql_query_t *sub_qry = qry->s_query;
    // handle ssa
    OG_RETURN_IFERR(handle_sub_qry_ssa(sub_qry, qry));
    uint32 ssa_cnt = sub_qry->ssa.count;
    if (ogsql_apply_rule_set_2(statement, sub_qry) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("transform phase 2 for sub_qry failed");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(handle_sub_qry_ssa(qry, sub_qry));
    if (sub_qry->ssa.count < ssa_cnt) {
        OG_RETURN_IFERR(sql_update_query_ssa(statement, qry));
    }

    qry->start_with_cond = sub_qry->join_assist.outer_node_count == 0 ? sub_qry->cond : sub_qry->filter_cond;
    sub_qry->cond_has_acstor_col = sql_cond_has_acstor_col(statement, sub_qry->cond, sub_qry);

    return OG_SUCCESS;
}

static status_t push_start_with_cond(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    cond_node_t *tmp_cond = NULL;
    OG_RETURN_IFERR(sql_clone_cond_node(statement->context, qry->cond->root, &tmp_cond, sql_alloc_mem));
    OG_RETURN_IFERR(sql_add_cond_node(qry->start_with_cond, tmp_cond));
    try_eval_logic_and(qry->start_with_cond->root);
    return OG_SUCCESS;
}

static status_t push_connect_by_cond(sql_query_t *qry)
{
    CM_POINTER(qry);
    OG_RETURN_IFERR(sql_add_cond_node(qry->connect_by_cond, qry->cond->root));
    try_eval_logic_and(qry->connect_by_cond->root);
    qry->cond = NULL;
    return OG_SUCCESS;
}

static status_t og_push_cond_2_connect_by(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER(qry);
    OG_RETSUC_IFTRUE(qry->cond == NULL || qry->cond->root == NULL);
    OG_RETSUC_IFTRUE(qry->cond->root->type == COND_NODE_TRUE);

    if (qry->start_with_cond == NULL) {
        OG_RETURN_IFERR(sql_create_cond_tree(statement->context, &qry->start_with_cond));
    }

    OG_RETURN_IFERR(push_start_with_cond(statement, qry));

    OG_RETURN_IFERR(push_connect_by_cond(qry));

    return OG_SUCCESS;
}

static status_t og_handle_subslect_in_start_with(sql_stmt_t *statement, sql_query_t *qry)
{
    cols_used_t cols_used;
    init_cols_used(&cols_used);
    OG_RETSUC_IFTRUE(qry->start_with_cond == NULL);
    sql_collect_cols_in_cond(qry->start_with_cond, &cols_used);
    // if trees has subselect ,need ssa tranform early for connect by
    if (HAS_SUBSLCT(&cols_used)) {
        OG_RETURN_IFERR(og_tranforms_query_4_connectby(statement, qry));
    }

    return OG_SUCCESS;
}

static inline bool32 sql_cmp_type_support_connect_mtrl(cmp_type_t type)
{
    return (bool32)(type == CMP_TYPE_EQUAL || type == CMP_TYPE_EQUAL_ANY);
}

static bool32 sql_is_scalar_aggr_subquery(expr_tree_t *expr)
{
    if (expr == NULL || expr->next != NULL || expr->root->type != EXPR_NODE_SELECT) {
        return OG_FALSE;
    }

    sql_select_t *select_ctx = (sql_select_t *)VALUE_PTR(var_object_t, &expr->root->value)->ptr;
    if (select_ctx == NULL) {
        return OG_FALSE;
    }

    sql_query_t *query = select_ctx->first_query;
    return (bool32)(query != NULL && query->aggrs != NULL && query->aggrs->count > 0 &&
        query->group_sets != NULL && query->group_sets->count == 0);
}

static status_t sql_alloc_connect_mtrl_info(sql_stmt_t *stmt, cb_mtrl_info_t **info)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cb_mtrl_info_t), (void **)info));
    MEMS_RETURN_IFERR(memset_s(*info, sizeof(cb_mtrl_info_t), 0, sizeof(cb_mtrl_info_t)));
    OG_RETURN_IFERR(sql_create_list(stmt, &(*info)->prior_exprs));
    OG_RETURN_IFERR(sql_create_list(stmt, &(*info)->key_exprs));
    (*info)->combine_sw = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_add_connect_mtrl_key(sql_stmt_t *stmt, cb_mtrl_info_t *info, expr_tree_t *prior_src,
    expr_tree_t *key_src)
{
    expr_tree_t *prior_expr = NULL;
    expr_tree_t *key_expr = NULL;

    OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, prior_src, &prior_expr, sql_alloc_mem));
    OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, key_src, &key_expr, sql_alloc_mem));
    OG_RETURN_IFERR(cm_galist_insert(info->prior_exprs, prior_expr));
    return cm_galist_insert(info->key_exprs, key_expr);
}

static status_t sql_try_add_connect_mtrl_cmp(sql_stmt_t *stmt, cmp_node_t *cmp, cb_mtrl_info_t *info, bool32 *matched)
{
    cols_used_t left_cols_used;
    cols_used_t right_cols_used;

    OG_RETSUC_IFTRUE(!sql_cmp_type_support_connect_mtrl(cmp->type));
    // Only scalar aggregate ANY subqueries can be used as a single materialized hash key.
    OG_RETSUC_IFTRUE(cmp->type == CMP_TYPE_EQUAL_ANY && !sql_is_scalar_aggr_subquery(cmp->right));

    init_cols_used(&left_cols_used);
    init_cols_used(&right_cols_used);
    sql_collect_cols_in_expr_tree(cmp->left, &left_cols_used);
    sql_collect_cols_in_expr_tree(cmp->right, &right_cols_used);

    if (if_cmp_used_by_connect_mtrl(&left_cols_used, &right_cols_used)) {
        OG_RETURN_IFERR(sql_add_connect_mtrl_key(stmt, info, cmp->left, cmp->right));
        *matched = OG_TRUE;
        return OG_SUCCESS;
    }

    if (cmp->type == CMP_TYPE_EQUAL && if_cmp_used_by_connect_mtrl(&right_cols_used, &left_cols_used)) {
        OG_RETURN_IFERR(sql_add_connect_mtrl_key(stmt, info, cmp->right, cmp->left));
        *matched = OG_TRUE;
    }
    return OG_SUCCESS;
}

static status_t sql_collect_connect_mtrl_keys(sql_stmt_t *stmt, cond_node_t *cond_node, cb_mtrl_info_t *info,
    bool32 *matched)
{
    if (cond_node == NULL) {
        return OG_SUCCESS;
    }

    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_collect_connect_mtrl_keys(stmt, cond_node->left, info, matched));
            return sql_collect_connect_mtrl_keys(stmt, cond_node->right, info, matched);

        case COND_NODE_COMPARE:
            return sql_try_add_connect_mtrl_cmp(stmt, cond_node->cmp, info, matched);

        default:
            return OG_SUCCESS;
    }
}

static status_t sql_try_transform_connect_mtrl(sql_stmt_t *statement, sql_query_t *qry)
{
    cb_mtrl_info_t *info = NULL;
    bool32 matched = OG_FALSE;

    if (!g_instance->sql.enable_cb_mtrl || !is_query_tables_all_normal(qry)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_alloc_connect_mtrl_info(statement, &info));
    OG_RETURN_IFERR(sql_collect_connect_mtrl_keys(statement, qry->connect_by_cond->root, info, &matched));
    if (matched) {
        qry->cb_mtrl_info = info;
    }
    return OG_SUCCESS;
}

status_t og_transf_connect_by_cond(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER(qry);
    OG_RETSUC_IFTRUE(qry->connect_by_cond == NULL);
    OG_RETSUC_IFTRUE(qry->cb_mtrl_info != NULL);
    // must let start_with_cond and connect_by_cond has query->cond
    if (og_push_cond_2_connect_by(statement, qry) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_try_transform_connect_mtrl(statement, qry));

    if (is_query_tables_all_normal(qry)) {
        OG_RETURN_IFERR(og_handle_subslect_in_start_with(statement, qry));
    }
    return OG_SUCCESS;
}
