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
#include "ogsql_hash_mtrl_rewrite.h"
#include "ogsql_verifier.h"
#include "ogsql_aggr.h"
#include "ogsql_transform.h"
#include "dml_parser.h"
#include "ogsql_context.h"
#include "ogsql_optim_common.h"
#include "ogsql_cond.h"

static bool32 is_simple_aggregate(const expr_node_t *aggr_exprn);
static bool32 check_and_hash_condition(cond_node_t *node, bool32 *join_cond);
static bool32 check_or_hash_condition(cond_node_t *node, bool32 *join_cond);
static bool32 check_compare_hash_condition(cond_node_t *node, bool32 *join_cond);


cond_check_strategy cond_check_strategies[] = { [COND_NODE_AND] = check_and_hash_condition,
                                                [COND_NODE_OR] = check_or_hash_condition,
                                                [COND_NODE_COMPARE] = check_compare_hash_condition };

static column_flags_t analyze_columns(cols_used_t *col_used)
{
    CM_POINTER(col_used);
    return (column_flags_t){ .has_ancestor = HAS_PRNT_OR_ANCSTR_COLS(col_used->flags),
                             .has_self = HAS_SELF_COLS(col_used->flags),
                             .has_subquery = HAS_SUBSLCT(col_used) };
}

static bool32 hash_group_or_window(sql_query_t *qry)
{
    CM_POINTER(qry);
    return qry->group_sets->count > 0 || qry->winsort_list->count > 0;
}

static bool32 validate_column_mixing(column_flags_t left, column_flags_t right)
{
    // Both sides contain ancestor columns or neither side contains ancestor columns
    if ((left.has_ancestor && right.has_ancestor) || (!left.has_ancestor && !right.has_ancestor)) {
        return OG_FALSE;
    }
    // Subquery and ancestor columns are mixed
    if ((left.has_ancestor && left.has_subquery) || (right.has_ancestor && right.has_subquery)) {
        return OG_FALSE;
    }
    // One side contains both its own columns and ancestor columns
    return !((left.has_ancestor && left.has_self) || (right.has_ancestor && right.has_self));
}

static bool32 og_can_hash_mtrl_aggreation_support(galist_t *qry_aggrs)
{
    CM_POINTER(qry_aggrs);
    uint32 aggr_idx = 0;
    while (aggr_idx < qry_aggrs->count) {
        expr_node_t *aggr_exprn = (expr_node_t *)cm_galist_get(qry_aggrs, aggr_idx++);
        if (!is_simple_aggregate(aggr_exprn)) {
            OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry appr support failed, "
                "hash mtrl cannot be rewritten.");
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 og_can_hash_mtrl_group_support(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    return sql_get_group_plan_type(statement, qry) == PLAN_NODE_HASH_GROUP;
}

static bool32 validate_subq_owner(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if (s_qry->owner->type != SELECT_AS_VARIANT || s_qry->owner->parent_refs->count == 0) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry owner failed, "
            "hash mtrl cannot be rewritten.");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 validate_subq_aggr_func(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if (s_qry->aggrs->count == 0 || hash_group_or_window(s_qry)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry aggr func failed, "
            "hash mtrl cannot be rewritten.");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 validate_subq_conditional(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if (s_qry->cond == NULL || (s_qry->cond->incl_flags & SQL_INCL_ROWNUM)) {
            OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry cond failed, "
                "hash mtrl cannot be rewritten.");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 validate_subq_hierarchical(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if (s_qry->connect_by_cond != NULL) {
            OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry connect by cond failed, "
                "hash mtrl cannot be rewritten.");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 validate_subq_incl_flags(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if ((s_qry->incl_flags & EXPR_INCL_ROWNUM) || (s_qry->incl_flags & RS_INCL_PRNT_OR_ANCSTR) ||
        (s_qry->incl_flags & RS_INCL_GROUPING)) {
            OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry incl_flags failed, "
                "hash mtrl cannot be rewritten.");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 validate_subq_join_cond(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if (s_qry->join_assist.outer_node_count > 0 &&
        !validate_outer_join_conditions(s_qry->join_assist.join_node)) {
            OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry cond failed, "
                "hash mtrl cannot be rewritten.");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 validate_subquery_for_hash_mtrl(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    // Ensure the subquery is a variant and contains parent columns
    OG_RETVALUE_IFTRUE(!validate_subq_owner(s_qry), OG_FALSE);

    // Check for aggregate functions and grouping
    OG_RETVALUE_IFTRUE(!validate_subq_aggr_func(s_qry), OG_FALSE);

    // conditional query
    OG_RETVALUE_IFTRUE(!validate_subq_conditional(s_qry), OG_FALSE);

    // Hierarchical query
    OG_RETVALUE_IFTRUE(!validate_subq_hierarchical(s_qry), OG_FALSE);
    
    OG_RETVALUE_IFTRUE(!validate_subq_incl_flags(s_qry), OG_FALSE);
    
    OG_RETVALUE_IFTRUE(!validate_subq_join_cond(s_qry), OG_FALSE);

    return OG_TRUE;
}

static bool32 has_basic_hash_rewrite_obstacles(sql_query_t *s_qry)
{
    CM_POINTER(s_qry);
    if (!validate_subquery_for_hash_mtrl(s_qry)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  validate_subquery_for_hash_mtrl not passed");
        return OG_TRUE;
    }

    if (og_query_contains_table_ancestor(s_qry)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  og_query_contains_table_ancestor not passed");
        return OG_TRUE;
    }

    if (detect_cross_level_dependency(s_qry)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  detect_cross_level_dependency not passed");
        return OG_TRUE;
    }
    
    return OG_FALSE;
}

static bool32 validate_subq_filter_cond_type(const cond_node_t *cond)
{
    CM_POINTER(cond);
    switch (cond->type) {
        case COND_NODE_UNKNOWN:
        case COND_NODE_NOT:
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            return OG_TRUE;
        default:
            return OG_FALSE;;
    }
}

static bool32 validate_hash_filter_conditions(cond_node_t *cond, bool32 *match_join_cond)
{
    CM_POINTER(match_join_cond);
    OG_RETVALUE_IFTRUE(cond == NULL, OG_TRUE);
    OG_RETVALUE_IFTRUE(validate_subq_filter_cond_type(cond), OG_TRUE);
    
    if (cond_check_strategies[cond->type]) {
        if (!cond_check_strategies[cond->type](cond, match_join_cond)) {
            OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]: validate subqry filter cond failed, "
                "hash mtrl cannot be rewritten.");
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 og_can_hash_mtrl_filter_support(cond_node_t *cond)
{
    bool32 match_join_cond = OG_FALSE;
    if (!validate_hash_filter_conditions(cond, &match_join_cond)) {
        return OG_FALSE;
    }

    if (!match_join_cond) {
        return OG_FALSE;
    }
    
    return OG_TRUE;
}

static status_t qry_hash_group_set(sql_query_t *qry)
{
    CM_POINTER(qry);
    return qry->group_sets->count > 0;
}

static status_t check_hash_mtrl_rewritable(sql_stmt_t *statement, select_node_t *select_node, bool32 *is_rewritable)
{
    CM_POINTER3(statement, select_node, is_rewritable);
    OG_RETSUC_IFTRUE(select_node == NULL || select_node->type != SELECT_NODE_QUERY);
    sql_query_t *s_qry = select_node->query;
    OG_RETSUC_IFTRUE(s_qry == NULL || s_qry->cond == NULL);
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_hash_mtrl, OPT_HASH_MATERIALIZE)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  opt_param check not passed");
        return OG_SUCCESS;
    }

    if (HAS_SPEC_TYPE_HINT(s_qry->hint_info, OPTIM_HINT, HINT_KEY_WORD_UNNEST | HINT_KEY_WORD_NO_UNNEST)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  OPTIM_HINT check not passed");
        return OG_SUCCESS;
    }

    if (has_basic_hash_rewrite_obstacles(s_qry)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  basic check not passed");
        return OG_SUCCESS;
    }

    if (!og_can_hash_mtrl_group_support(statement, s_qry)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  group type check not passed");
        return OG_SUCCESS;
    }

    if (!og_can_hash_mtrl_filter_support(s_qry->cond->root)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  filter check not passed");
        return OG_SUCCESS;
    }

    if (!og_can_hash_mtrl_aggreation_support(s_qry->aggrs)) {
        OG_LOG_DEBUG_INF("[HASH_MTRL_REWRITE]:  aggr func check not passed");
        return OG_SUCCESS;
    }

    return og_check_index_4_rewrite(statement, s_qry, CK_FOR_HASH_MTRL, is_rewritable);
}

static status_t manage_expr_addition_for_hash(sql_stmt_t *statement, sql_query_t *qry, expr_tree_t *parent,
                                              expr_tree_t *child)
{
    CM_POINTER4(statement, qry, parent, child);
    OG_RETURN_IFERR(cm_galist_insert(qry->remote_keys, parent));
    group_set_t *g_set = NULL;
    if (qry_hash_group_set(qry)) {
        g_set = (group_set_t *)cm_galist_get(qry->group_sets, 0);
    } else {
        OG_RETURN_IFERR(cm_galist_new(qry->group_sets, sizeof(group_set_t), (void **)&g_set));
        OG_RETURN_IFERR(sql_create_list(statement, &g_set->items));
    }
    OG_RETURN_IFERR(cm_galist_insert(g_set->items, child));
    return OG_SUCCESS;
}

static void collect_cols_for_hash_mtrl(expr_tree_t *tree, cols_used_t *cols)
{
    CM_POINTER2(tree, cols);
    init_cols_used(cols);
    sql_collect_cols_in_expr_tree(tree, cols);
}

static bool32 hash_mtrl_chk_ancstr_col(cmp_node_t *cmp_node, cols_used_t *col_l, cols_used_t *col_r)
{
    CM_POINTER3(cmp_node, col_l, col_r);
    collect_cols_for_hash_mtrl(cmp_node->left, col_l);
    collect_cols_for_hash_mtrl(cmp_node->right, col_r);
    return HAS_PRNT_OR_ANCSTR_COLS(col_l->flags) || HAS_PRNT_OR_ANCSTR_COLS(col_r->flags);
}

static status_t collect_hash_mtrl_keys_from_cmp(cond_collect_helper_t *cond_collector, cond_node_t *cond)
{
    CM_POINTER2(cond_collector, cond);
    cmp_node_t *cmp_node = cond->cmp;
    OG_RETSUC_IFTRUE(!cmp_node && cmp_node->type != CMP_TYPE_EQUAL);
    
    cols_used_t col_used_right;
    cols_used_t col_used_left;
    OG_RETSUC_IFTRUE(!hash_mtrl_chk_ancstr_col(cmp_node, &col_used_left, &col_used_right));

    cond->type = COND_NODE_TRUE;
    cond_collector->arg0 = OG_TRUE;
    expr_tree_t *parent = cmp_node->right;
    expr_tree_t *child = cmp_node->left;
    sql_query_t *qry = (sql_query_t *)cond_collector->p_arg0;
    if (HAS_PRNT_OR_ANCSTR_COLS(col_used_left.flags)) {
        parent = cmp_node->left;
        child = cmp_node->right;
    }
    return manage_expr_addition_for_hash(cond_collector->statement, qry, parent, child);
}

static status_t collect_hash_mtrl_keys(sql_stmt_t *statement, cond_node_t *cond, sql_query_t *qry)
{
    CM_POINTER3(statement, cond, qry);
    cond_collect_helper_t cond_collector;
    OGSQL_SAVE_STACK(statement);
    OG_RETURN_IFERR(cond_collector_init(&cond_collector, statement, sql_stack_alloc));
    cond_collector.p_arg0 = (void *)qry;
    cond_collector.arg0 = OG_FALSE;
    cond_collector.type = COLL_TYPE_IGNORE;
    cond_node_type_t orign_cond_type = cond->type;
    OG_RETURN_IFERR(traverse_and_collect_conds(&cond_collector, cond));
    if (!cond_collector.cond) {
        return OG_SUCCESS;
    }
    for (uint32 i = 0; i < cond_collector.cond->count; i++) {
        cond_node_t *curr_cond = (cond_node_t *)cm_galist_get(cond_collector.cond, i);
        OG_RETURN_IFERR(collect_hash_mtrl_keys_from_cmp(&cond_collector, curr_cond));
        OG_BREAK_IF_TRUE(cond_collector.is_stoped);
    }
    if (orign_cond_type == COND_NODE_AND && cond_collector.arg0) {
        OG_RETURN_IFERR(try_eval_logic_cond(statement, cond));
    }
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static status_t finalize_query_rewrite_state(sql_query_t *qry)
{
    CM_POINTER(qry);
    cm_galist_reset(qry->sort_items);
    qry->cond_has_acstor_col = OG_FALSE;
    if (qry->has_distinct) {
        SWAP(galist_t *, qry->rs_columns, qry->distinct_columns);
        cm_galist_reset(qry->distinct_columns);
    }
    qry->has_distinct = OG_FALSE;
    return OG_SUCCESS;
}

static status_t rewrite_subquery_for_hash_processing(sql_stmt_t *statement, sql_select_t *slct)
{
    CM_POINTER2(statement, slct);
    select_node_t *select_node = slct->root;
    bool32 is_rewritable = OG_FALSE;
    if (check_hash_mtrl_rewritable(statement, select_node, &is_rewritable) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[HASH_MTRL_REWRITE]: check_hash_mtrl_rewritable error");
        return OG_ERROR;
    }
    if (is_rewritable) {
        sql_query_t *qry = select_node->query;
        OG_RETURN_IFERR(sql_create_list(statement, &qry->remote_keys));
        OG_RETURN_IFERR(collect_hash_mtrl_keys(statement, qry->cond->root, qry));
        return finalize_query_rewrite_state(qry);
    }
    make_subqry_without_join(statement, select_node, OG_FALSE);
    return OG_SUCCESS;
}

static bool32 check_and_hash_condition(cond_node_t *cond, bool32 *match_join_cond)
{
    CM_POINTER2(cond, match_join_cond);
    return validate_hash_filter_conditions(cond->left, match_join_cond) &&
           validate_hash_filter_conditions(cond->right, match_join_cond);
}

static bool32 check_or_hash_condition(cond_node_t *cond, bool32 *match_join_cond)
{
    CM_POINTER2(cond, match_join_cond);
    cols_used_t col_used;
    init_cols_used(&col_used);
    sql_collect_cols_in_cond(cond, &col_used);
    return !HAS_PRNT_OR_ANCSTR_COLS(col_used.flags);
}

static bool32 check_compare_hash_condition(cond_node_t *cond, bool32 *match_join_cond)
{
    CM_POINTER2(cond, match_join_cond);
    cols_used_t left_col_used;
    cols_used_t right_col_used;
    collect_cols_for_hash_mtrl(cond->cmp->left, &left_col_used);
    collect_cols_for_hash_mtrl(cond->cmp->right, &right_col_used);
    if (cond->cmp->type != CMP_TYPE_EQUAL) {
        return OG_FALSE;
    }
    bool32 vaild = validate_column_mixing(analyze_columns(&left_col_used), analyze_columns(&right_col_used));
    if (vaild) {
        *match_join_cond = OG_TRUE;
    }
    return vaild;
}

static status_t og_rewrite_subquery_using_hash(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    sql_array_t *slct_array = &(qry->ssa);
    OG_RETSUC_IFTRUE(slct_array == NULL || slct_array->count == 0);
    uint32 slct_idx = 0;
    while (slct_idx < slct_array->count) {
        sql_select_t *slct = (sql_select_t *)sql_array_get(slct_array, slct_idx++);
        OG_CONTINUE_IFTRUE(slct == NULL);
        OG_RETURN_IFERR(rewrite_subquery_for_hash_processing(statement, slct));
    }
    return OG_SUCCESS;
}

status_t og_transf_var_subquery_rewrite(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER(statement);
    OG_RETSUC_IFTRUE(qry == NULL);
    return og_rewrite_subquery_using_hash(statement, qry);
}

static bool32 is_simple_aggregate(const expr_node_t *aggr_exprn)
{
    const sql_func_t *aggr_func = GET_AGGR_FUNC(aggr_exprn);
    switch (aggr_func->aggr_type) {
        case AGGR_TYPE_SUM:
        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
        case AGGR_TYPE_COUNT:
        case AGGR_TYPE_AVG:
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
    return OG_FALSE;
}