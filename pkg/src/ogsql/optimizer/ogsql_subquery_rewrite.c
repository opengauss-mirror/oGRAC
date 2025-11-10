/* -------------------------------------------------------------------------
 * This file is part of the oGRAC project.
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
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
 * ogsql_subquery_rewrite.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_subquery_rewrite.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_subquery_rewrite.h"
#include "ogsql_transform.h"
#include "ogsql_optim_common.h"
#include "ogsql_expr_def.h"

static void optim_subqry_rewrite_support(rewrite_helper_t *helper)
{
    sql_query_t *qry = helper->query;

    // Rule 1: Check query condition existence
    if (qry->cond == NULL) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] Rule 1: Query condition missing");
        helper->state = REWRITE_UNSUPPORT;
        return;
    }

    /* Pending implementation for hint checking */

    sql_table_t *first_table = (sql_table_t *)sql_array_get(&qry->tables, 0);
    uint32 table_cnt = qry->tables.count;

    // Rule 3: Single dual table check
    if (table_cnt == 1 && og_check_if_dual(first_table)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] Rule 3: Single dual table restriction");
        helper->state = REWRITE_UNSUPPORT;
        return;
    }

    // Rule 4: Hash join flag verification
    if (TABLE_CBO_HAS_FLAG(first_table, SELTION_NO_HASH_JOIN)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] Rule 4: Hash join disabled");
        helper->state = REWRITE_UNSUPPORT;
    }
}

status_t get_all_and_cmp_conds(sql_stmt_t *statement, galist_t *cond_lst, cond_node_t *cond, bool32 need_or_conds)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));

    cond_node_type_t cond_type = cond->type;
    switch (cond_type) {
        case COND_NODE_OR:
            OG_BREAK_IF_TRUE(!need_or_conds);
            /* fall-through */
        case COND_NODE_COMPARE:
            return cm_galist_insert(cond_lst, cond);
        case COND_NODE_AND:
            OG_RETURN_IFERR(get_all_and_cmp_conds(statement, cond_lst, cond->left, need_or_conds));
            OG_RETURN_IFERR(get_all_and_cmp_conds(statement, cond_lst, cond->right, need_or_conds));
            break;
        default:
            break;
    }

    return OG_SUCCESS;
}

static void check_cond_left_4_subquery_2_table(expr_tree_t *l_exprtr, rewrite_state_e *can_rewrite)
{
    if (l_exprtr && l_exprtr->root->type == EXPR_NODE_SELECT) {
        *can_rewrite = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 6. left cond is subquery(EXPR_NODE_SELECT), "
                         "subquery cannot be rewritten.");
        return;
    }

    cols_used_t col_used_left;
    expr_tree_t *exprtr = l_exprtr;
    while (exprtr) {
        init_cols_used(&col_used_left);
        sql_collect_cols_in_expr_node(exprtr->root, &col_used_left);
        if (!HAS_ONLY_SELF_COLS(col_used_left.flags)) {
            *can_rewrite = REWRITE_UNSUPPORT;
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 12.1 The cols on the left cond side is not only from "
                             "self level, subquery cannot be rewritten.");
            return;
        }

        if (HAS_ROWNUM(&col_used_left)) {
            *can_rewrite = REWRITE_UNSUPPORT;
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 12.2 There is rownum on the left cond side, "
                             "subquery cannot be rewritten.");
            return;
        }

        if (HAS_SUBSLCT(&col_used_left)) {
            *can_rewrite = REWRITE_UNSUPPORT;
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 12.3 There is subquery on the left cond side, "
                             "subquery cannot be rewritten.");
            return;
        }
        exprtr = exprtr->next;
    }
    return;
}

static void check_cond_right_4_subquery_2_table(expr_tree_t *r_exprtr, rewrite_state_e *can_rewrite)
{
    if (r_exprtr && r_exprtr->root->type != EXPR_NODE_SELECT) {
        *can_rewrite = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 7. cond right is not subquery(EXPR_NODE_SELECT): "
                         "subquery cannot be rewritten.");
    }
    return;
}

static status_t check_subquery2table_query_cond(rewrite_helper_t *helper)
{
    cmp_type_t cmp_type = helper->curr_cond->cmp->type;
    expr_tree_t *l_exprtr = helper->curr_cond->cmp->left;
    expr_tree_t *r_exprtr = helper->curr_cond->cmp->right;

    switch (cmp_type) {
        case CMP_TYPE_NOT_IN:
            if (l_exprtr->next) {
                helper->state = REWRITE_UNSUPPORT;
                OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 9. not in: There is more than one element "
                                 "on the left cond side, subquery cannot be rewritten.");
                return OG_SUCCESS;
            }
            /* fall-through */
        case CMP_TYPE_IN:
        case CMP_TYPE_EQUAL_ANY:
            check_cond_right_4_subquery_2_table(r_exprtr, &helper->state);
            OG_RETVALUE_IFTRUE((helper->state != REWRITE_UNCERTAINLY), OG_SUCCESS);
            if (r_exprtr->next) {
                helper->state = REWRITE_UNSUPPORT;
                OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 8. in/not in/=any: There is more than one element "
                                 "on the right cond side, subquery cannot be rewritten.");
                return OG_SUCCESS;
            }
            break;
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS: {
            check_cond_right_4_subquery_2_table(r_exprtr, &helper->state);
            OG_RETVALUE_IFTRUE((helper->state != REWRITE_UNCERTAINLY), OG_SUCCESS);
            sql_select_t *slct = GET_SELECT_CTX(helper->curr_cond);
            if (slct->root->type != SELECT_NODE_QUERY) {
                helper->state = REWRITE_UNSUPPORT;
                OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 11. (not) exists: select type is not SELECT_NODE_QUERY, "
                                 "subquery cannot be rewritten.");
                return OG_SUCCESS;
            }
            break;
        }
        default:
            helper->state = REWRITE_UNSUPPORT;
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 5. query cond type is not in (in, not in, =any, "
                             "exists, not exists)subquery cannot be rewritten.");
            return OG_SUCCESS;
    }

    check_cond_left_4_subquery_2_table(l_exprtr, &helper->state);
    OG_RETVALUE_IFTRUE((helper->state != REWRITE_UNCERTAINLY), OG_SUCCESS);

    sql_select_t *slct = GET_SELECT_CTX(helper->curr_cond);
    helper->curr_sub_query = slct->first_query;

    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_hint(rewrite_helper_t *helper)
{
    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_tables(rewrite_helper_t *helper)
{
    bool32 has_json_table = OG_FALSE;
    uint32 m = 0;
    while (m < helper->curr_sub_query->tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&helper->curr_sub_query->tables, m);
        if (tbl->type == JSON_TABLE) {
            has_json_table = OG_TRUE;
            break;
        }
        m++;
    }

    if (has_json_table) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 10. subquery has json table, subquery cannot be rewritten.");
    }
    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_hash_semi(rewrite_helper_t *helper)
{
    expr_tree_t *left_exprtr = helper->curr_cond->cmp->left;
    cmp_type_t cmp_type = helper->curr_cond->cmp->type;
    if (cmp_type == CMP_TYPE_EXISTS || cmp_type == CMP_TYPE_NOT_EXISTS) {
        return OG_SUCCESS;
    }

    cols_used_t col_used_left;
    init_cols_used(&col_used_left);
    sql_collect_cols_in_expr_tree(left_exprtr, &col_used_left);
    bool32 cols_from_multi_table = HAS_DIFF_TABS(&col_used_left, SELF_IDX);
    if (cols_from_multi_table) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 12.4 cond left has cols from different tables, "
                         "subquery cannot be rewritten.");
        return OG_SUCCESS;
    }

    bool32 subquery_has_limit = LIMIT_CLAUSE_OCCUR(&helper->curr_sub_query->limit);
    bool32 subquery_has_distinct = helper->curr_sub_query->has_distinct;
    bool32 cols_has_rowid = HAS_ROWID_COLUMN(&col_used_left, SELF_IDX);
    if (cols_has_rowid && subquery_has_limit && !subquery_has_distinct) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 12.5 cond left has rowid, subquery has limit but not has distinct, "
                         "subquery cannot be rewritten.");
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t check_subquery2table_cond_pushdown(rewrite_helper_t *helper)
{
    sql_select_t *slct = GET_SELECT_CTX(helper->curr_cond);
    if (check_cond_push2subslct_table(helper->stmt, helper->query, slct, helper->curr_cond->cmp)) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 13. cond can be pushed down, subquery cannot be rewritten.");
    }
    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_cols(rewrite_helper_t *helper)
{
    bool32 use_parent_cols = og_check_if_ref_parent_columns(helper->curr_sub_query->owner);
    if (!use_parent_cols) {
        helper->state = REWRITE_SUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 15. not use parent cols in subquery, "
                         "subquery can be rewritten.");
        return OG_SUCCESS;
    }

    // in/not in/=any
    if (helper->curr_cond->cmp->left) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 16. in/not in/=any: use parent cols in subquery, "
                         "subquery cannot be rewritten.");
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static bool32 check_exists_subquery_clauses_valid(sql_query_t *sub_qry)
{
    if (!sub_qry->cond) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.1 (not) exists: no cond in subquery"
                         "subquery cannot be rewritten.");
        return OG_FALSE;
    }

    if (sub_qry->aggrs->count > 0 || sub_qry->winsort_list->count > 0 || sub_qry->group_sets->count > 0 ||
        sub_qry->having_cond || sub_qry->connect_by_cond || sub_qry->pivot_items || sub_qry->has_distinct ||
        LIMIT_CLAUSE_OCCUR(&sub_qry->limit) || ROWNUM_COND_OCCUR(sub_qry->cond)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.2 (not) exists: subquery contains "
                         "aggrs/winsort_list/group/having/connect_by/pivot/distinct/limit/rownum, "
                         "subquery cannot be rewritten.");
        return OG_FALSE;
    }

    if (sub_qry->join_assist.outer_node_count > 0 && !validate_outer_join_conditions(sub_qry->join_assist.join_node)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.3 (not) exists: outer join in subquery do not "
                         "meet the rewrite criteria, subquery cannot be rewritten.");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_exists_subquery_cols_valid(sql_query_t *sub_qry)
{
    if (og_query_contains_table_ancestor(sub_qry)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.4 (not) exists: use parent cols in subquery, "
                         "subquery cannot be rewritten.");
        return OG_FALSE;
    }
    if (detect_cross_level_dependency(sub_qry)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.5 (not) exists: use ancestor cols in subquery, "
                         "subquery cannot be rewritten.");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_exists_subquery_or_cond_valid(cond_node_t *or_cond, cmp_type_t cmp_type)
{
    cols_used_t col_used_or;
    init_cols_used(&col_used_or);
    sql_collect_cols_in_cond(or_cond, &col_used_or);
    uint8 flags = col_used_or.flags;
    bool32 has_parent_or_ancestor_cols = HAS_PRNT_OR_ANCSTR_COLS(flags);
    bool32 has_self_cols = HAS_SELF_COLS(flags);

    if (cmp_type == CMP_TYPE_EXISTS && has_parent_or_ancestor_cols) {
        if (has_self_cols) {
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.6 exists: or comparison condition in subquery: "
                             "use parent/ancestor cols and self level cols, subquery cannot be rewritten.");
            return OG_FALSE;
        }
        if (HAS_DYNAMIC_SUBSLCT(&col_used_or)) {
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.7 exists: or comparison condition in subquery: "
                             "use parent/ancestor cols and contains dynamic subselect, subquery cannot be rewritten.");
            return OG_FALSE;
        }
    } else if (cmp_type == CMP_TYPE_NOT_EXISTS) {
        if (has_parent_or_ancestor_cols) {
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.8 not exists: or comparison condition in subquery: "
                             "use parent/ancestor cols, subquery cannot be rewritten.");
        }
        return !has_parent_or_ancestor_cols;
    }

    return OG_TRUE;
}

static bool32 check_exists_equal_cmp_cond_valid(cols_used_t *col_used_cmp_l, cols_used_t *col_used_cmp_r,
                                                bool32 *has_join_cond)
{
    uint8 flags_l = col_used_cmp_l->flags;
    uint8 flags_r = col_used_cmp_r->flags;
    bool32 has_diff_level_cols = has_only_diff_level_columns(flags_l, flags_r);
    if (!has_diff_level_cols) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.10 (not) exists: equal comparison condition in subquery: "
                         "the conditions on both sides belong to the same layer, continue check current cond..");
        return OG_FALSE;
    }

    uint8 has_diff_table_l = HAS_DIFF_TABS(col_used_cmp_l, HAS_ONLY_SELF_COLS(flags_l) ? SELF_IDX : PARENT_IDX);
    uint8 has_diff_table_r = HAS_DIFF_TABS(col_used_cmp_r, HAS_ONLY_SELF_COLS(flags_r) ? SELF_IDX : PARENT_IDX);
    bool32 has_diff_table = (bool32)(has_diff_table_l || has_diff_table_r);
    if (has_diff_table) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.11 (not) exists: equal comparison condition in subquery: "
                         "used cols on the same side come from different tables, continue check current cond.");
        return OG_FALSE;
    }

    *has_join_cond = OG_TRUE;
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.12 (not) exists: equal comparison condition in subquery: "
                     "one side of the condition contains only cols from the left layer table, "
                     "and the other side contains only cols from the parent layer table, "
                     "and cols on the same side come from the same table, continue check next cond.");
    return OG_TRUE;
}

static bool32 check_exists_subquery_cmp_cond_valid(cond_node_t *cmp_cond, cmp_type_t cmp_type, bool32 *has_join_cond)
{
    cols_used_t col_used_cmp_l;
    cols_used_t col_used_cmp_r;
    init_cols_used(&col_used_cmp_l);
    init_cols_used(&col_used_cmp_r);
    sql_collect_cols_in_expr_tree(cmp_cond->cmp->left, &col_used_cmp_l);
    sql_collect_cols_in_expr_tree(cmp_cond->cmp->right, &col_used_cmp_r);
    uint8 flags_l = col_used_cmp_l.flags;
    uint8 flags_r = col_used_cmp_r.flags;

    bool32 has_dynamic_subselect = (HAS_DYNAMIC_SUBSLCT(&col_used_cmp_l) || HAS_DYNAMIC_SUBSLCT(&col_used_cmp_r));
    bool32 has_parent_or_ancestor_cols = (HAS_PRNT_OR_ANCSTR_COLS(flags_l) || HAS_PRNT_OR_ANCSTR_COLS(flags_r));
    bool32 has_self_cols = (HAS_SELF_COLS(flags_l) || HAS_SELF_COLS(flags_r));

    if (has_dynamic_subselect && has_parent_or_ancestor_cols) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.9 (not) exists: comparison condition in subquery: "
                         "use parent/ancestor cols and contains dynamic subselect, subquery cannot be rewritten.");
        return OG_FALSE;
    }

    if (cmp_cond->cmp->type == CMP_TYPE_EQUAL) {
        if (check_exists_equal_cmp_cond_valid(&col_used_cmp_l, &col_used_cmp_r, has_join_cond)) {
            return OG_TRUE;
        }
    }

    if (cmp_type == CMP_TYPE_EXISTS) {
        if (!has_self_cols) {
            return OG_TRUE;
        }
        if (!has_parent_or_ancestor_cols) {
            return OG_TRUE;
        }
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.13 exists: comparison condition in subquery: "
                         "use parent/ancestor cols and self cols, subquery cannot be rewritten.");
    } else if (cmp_type == CMP_TYPE_NOT_EXISTS) {
        if (has_parent_or_ancestor_cols) {
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.14 not exists: The comparison condition in subquery "
                             "use parent/ancestor cols, subquery cannot be rewritten.");
        }
        return !has_parent_or_ancestor_cols;
    }
    return OG_FALSE;
}

static bool32 check_exists_subquery_filter_conds_valid(rewrite_helper_t *helper)
{
    cmp_type_t cmp_type = helper->curr_cond->cmp->type;
    cond_node_t *cond = helper->curr_sub_query->cond->root;
    OG_RETURN_IFERR(try_eval_logic_cond(helper->stmt, cond));
    if (cond->type == COND_NODE_TRUE) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.15 (not) exists: subquery condition is always true, "
                         "subquery cannot be rewritten.");
        return OG_FALSE;
    }

    reorganize_cond_tree(cond);
    cond_node_t *curr_cond = FIRST_NOT_AND_NODE(cond);
    for (; curr_cond != NULL; curr_cond = curr_cond->next) {
        if (curr_cond->type == COND_NODE_OR) {
            OG_RETVALUE_IFTRUE(!check_exists_subquery_or_cond_valid(curr_cond, cmp_type), OG_FALSE);
        } else if (curr_cond->type == COND_NODE_COMPARE) {
            OG_RETVALUE_IFTRUE(!check_exists_subquery_cmp_cond_valid(curr_cond, cmp_type, &helper->has_join_cond),
                               OG_FALSE);
        }
    }
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17.16 (not) exists: filter cond check valid, continue check.");
    return OG_TRUE;
}

static status_t check_subquery2table_subquery_exists(rewrite_helper_t *helper)
{
    if (!check_exists_subquery_clauses_valid(helper->curr_sub_query)) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17 (not) exists: The subclauses in subquery "
                         "do not meet the rewrite criteria, subquery cannot be rewritten.");
        return OG_SUCCESS;
    }

    if (!check_exists_subquery_cols_valid(helper->curr_sub_query)) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17 (not) exists: "
                         "the parent/ancestor columns are used in subquery, subquery cannot be rewritten.");
        return OG_SUCCESS;
    }

    if (!check_exists_subquery_filter_conds_valid(helper)) {
        helper->state = REWRITE_UNSUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 17 (not) exists: subquery cannot be rewritten.");
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_join_hint(rewrite_helper_t *helper)
{
    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_cbo(rewrite_helper_t *helper)
{
    if (CBO_ON) {
        helper->state = REWRITE_SUPPORT;
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 19.1 (not) exists: CBO open, subquery can be rewritten.");
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static status_t check_subquery2table_subquery_rbo(rewrite_helper_t *helper)
{
    return OG_SUCCESS;
}

static check_subquery2table_t check_subquery2table_items[] = {
    check_subquery2table_query_cond,      check_subquery2table_subquery_hint,
    check_subquery2table_subquery_tables, check_subquery2table_subquery_hash_semi,
    check_subquery2table_cond_pushdown,   check_subquery2table_subquery_cols,
    check_subquery2table_subquery_exists, check_subquery2table_subquery_join_hint,
    check_subquery2table_subquery_cbo,    check_subquery2table_subquery_rbo,
};

bool32 check_subquery_can_be_pulled_up_normal(rewrite_helper_t *helper)
{
    expr_tree_t *right_exprtr = helper->curr_cond->cmp->right;
    if (!right_exprtr || right_exprtr->root->type != EXPR_NODE_SELECT) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.1 query cond right is not EXPR_NODE_SELECT, "
                         "subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    sql_select_t *slct = GET_SELECT_CTX(helper->curr_cond);
    sql_query_t *sub_qry = slct->root->query;
    if (slct->root->type != SELECT_NODE_QUERY) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.2 query cond type is not SELECT_NODE_QUERY, "
                         "subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    if (!sub_qry->cond) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.3 subquery cond is null, no cond can be pulled up");
        return OG_FALSE;
    }

    if (!og_check_if_ref_parent_columns(sub_qry->owner)) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.4 There is no parent col in subquery, "
                         "subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    if (sub_qry->aggrs->count > 0 && sub_qry->group_sets->count == 0) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.5 subquery has aggrs but not has group_sets, "
                         "subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_cmp_cond_can_be_pulled_up_normal(cond_node_t *cmp_cond)
{
    cols_used_t col_used_cmp_l;
    cols_used_t col_used_cmp_r;
    init_cols_used(&col_used_cmp_l);
    init_cols_used(&col_used_cmp_r);
    sql_collect_cols_in_expr_tree(cmp_cond->cmp->left, &col_used_cmp_l);
    sql_collect_cols_in_expr_tree(cmp_cond->cmp->right, &col_used_cmp_r);
    uint8 flags_l = col_used_cmp_l.flags;
    uint8 flags_r = col_used_cmp_r.flags;

    bool32 has_self_cols = (HAS_SELF_COLS(flags_l) || HAS_SELF_COLS(flags_r));
    if (has_self_cols) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.6 There are self cols on either side of the subquery "
                         "comparison condition, subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    bool32 has_parent_cols = (HAS_PARENT_COLS(flags_l) || HAS_PARENT_COLS(flags_r));
    if (!has_parent_cols) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.7 There are no parent cols on either side of the subquery "
                         "comparison condition, subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    bool32 has_subselect = (HAS_SUBSLCT(&col_used_cmp_l) || HAS_SUBSLCT(&col_used_cmp_r));
    if (has_subselect) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.8 There is subquery on either side of the subquery "
                         "comparison condition, subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    bool32 has_rownum = (HAS_ROWNUM(&col_used_cmp_l) || HAS_ROWNUM(&col_used_cmp_r));
    if (has_rownum) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.9 There is rownum on either side of the subquery "
                         "comparison condition, subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_conds_can_be_pulled_up_normal(sql_stmt_t *statement, cond_node_t *cond)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));
    switch (cond->type) {
        case COND_NODE_COMPARE:
            return check_cmp_cond_can_be_pulled_up_normal(cond);
        case COND_NODE_OR:
        case COND_NODE_AND:
            return check_conds_can_be_pulled_up_normal(statement, cond->left) &&
                   check_conds_can_be_pulled_up_normal(statement, cond->right);
        default:
            return OG_FALSE;
    }
}

static status_t merge_cond_into_tree(sql_stmt_t *statement, cond_tree_t **dest_tree, cond_node_t *cond)
{
    if (!*dest_tree) {
        OG_RETURN_IFERR(sql_create_cond_tree(statement->context, dest_tree));
    }

    SAVE_AND_RESET_NODE_STACK(statement);
    OG_RETURN_IFERR(sql_merge_cond_tree(*dest_tree, cond));
    SQL_RESTORE_NODE_STACK(statement);
    return OG_SUCCESS;
}

status_t try_pull_up_subquery_conds_normal(sql_stmt_t *statement, cond_tree_t **pulled_up_tree, cond_node_t *cond)
{
    OGSQL_SAVE_STACK(statement);

    galist_t *pullup_cond_lst = NULL;
    OG_RETURN_IFERR(sql_push(statement, sizeof(galist_t), (void **)&pullup_cond_lst));
    cm_galist_init(pullup_cond_lst, statement, (ga_alloc_func_t)sql_push);
    status_t status = get_all_and_cmp_conds(statement, pullup_cond_lst, cond, OG_TRUE);
    if (status != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        return status;
    }

    for (uint32 i = 0; i < pullup_cond_lst->count; i++) {
        cond_node_t *curr_cond = (cond_node_t *)cm_galist_get(pullup_cond_lst, i);
        if (!check_conds_can_be_pulled_up_normal(statement, curr_cond)) {
            continue;
        }
        status = merge_cond_into_tree(statement, pulled_up_tree, curr_cond);
        if (status != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(statement);
            return status;
        }
    }

    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static status_t process_ancestor_column_info(sql_stmt_t *statement, expr_node_t *exprn, uint32 *ancestor, uint32 *flags,
                                             uint32 *ref_tab_id)
{
    switch (*ancestor) {
        case OG_SELF_COLUMN:
            *flags |= FLAG_HAS_SELF_COLS;
            break;
        case OG_PARENT_COLUMN:
            *flags |= FLAG_HAS_PARENT_COLS;
            (*ancestor)--;
            *ref_tab_id = NODE_TAB(exprn);
            break;
        default:
            *flags |= FLAG_HAS_ANCESTOR_COLS;
            (*ancestor)--;
            OG_RETURN_IFERR(add_node_2_parent_ref_core(statement, OGSQL_CURR_NODE(statement), exprn, NODE_TAB(exprn),
                                                       NODE_ANCESTOR(exprn)));
            break;
    }
    return OG_SUCCESS;
}

static status_t process_ancestor_group_info(sql_stmt_t *statement, sql_query_t *sub_qry, expr_node_t *exprn,
                                            uint32 *ancestor, uint32 *flags)
{
    if (*ancestor == OG_SELF_COLUMN) {
        *flags |= FLAG_HAS_SELF_COLS;
        return OG_SUCCESS;
    }

    expr_node_t *orig_exprn = sql_get_origin_ref(exprn);
    expr_node_t *new_exprn = NULL;
    SET_NODE_STACK_CURR_QUERY(statement, sub_qry);
    OG_RETURN_IFERR(sql_clone_expr_node(statement->context, orig_exprn, &new_exprn, sql_alloc_mem));
    SQL_RESTORE_NODE_STACK(statement);

    if (new_exprn->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(new_exprn) > 0) {
        new_exprn->value.v_col.ancestor--;
    } else if (NODE_IS_RES_ROWID(new_exprn) && ROWID_NODE_ANCESTOR(new_exprn) > 0) {
        new_exprn->value.v_rid.ancestor--;
    }
    *flags |= ((*ancestor) == OG_PARENT_COLUMN) ? FLAG_HAS_PARENT_COLS : FLAG_HAS_ANCESTOR_COLS;
    (*ancestor)--;
    return OG_SUCCESS;
}

static status_t process_ancestor_reserved_info(sql_stmt_t *statement, expr_node_t *exprn, uint32 *ancestor,
                                               uint32 *flags, uint32 *ref_tab_id)
{
    OG_RETVALUE_IFTRUE((exprn->value.v_int != RES_WORD_ROWID), OG_SUCCESS);
    switch (*ancestor) {
        case OG_SELF_COLUMN:
            *flags |= FLAG_HAS_SELF_COLS;
            break;
        case OG_PARENT_COLUMN:
            *flags |= FLAG_HAS_PARENT_COLS;
            (*ancestor)--;
            *ref_tab_id = ROWID_NODE_TAB(exprn);
            break;
        default:
            *flags |= FLAG_HAS_ANCESTOR_COLS;
            (*ancestor)--;
            OG_RETURN_IFERR(add_node_2_parent_ref_core(statement, OGSQL_CURR_NODE(statement), exprn,
                                                       exprn->value.v_rid.tab_id, (*ancestor)));
            break;
    }
    return OG_SUCCESS;
}

static status_t process_ancestor_info(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_type_t expr_type = (*exprn)->type;
    sql_stmt_t *statement = v_ast->stmt;
    uint32 *flags = &v_ast->result0;
    uint32 *ref_tab_id = &v_ast->result1;
    uint32 *ancestor = NULL;
    switch (expr_type) {
        case EXPR_NODE_COLUMN:
            ancestor = &(*exprn)->value.v_col.ancestor;
            return process_ancestor_column_info(statement, *exprn, ancestor, flags, ref_tab_id);
        case EXPR_NODE_RESERVED:
            ancestor = &(*exprn)->value.v_rid.ancestor;
            return process_ancestor_reserved_info(statement, *exprn, ancestor, flags, ref_tab_id);
        case EXPR_NODE_GROUP: {
            ancestor = &(*exprn)->value.v_vm_col.ancestor;
            sql_query_t *sub_qry = (sql_query_t *)v_ast->param0;
            return process_ancestor_group_info(statement, sub_qry, *exprn, ancestor, flags);
        }
        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t process_ancestor_info_in_cmp_expr_normal(sql_stmt_t *statement, sql_query_t *sub_qry,
                                                         expr_tree_t *cmp_exprtr)
{
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.param0 = sub_qry;
    v_ast.result0 = 0;
    v_ast.result1 = OG_INVALID_ID32;
    v_ast.excl_flags |= VA_EXCL_PRIOR;
    return visit_expr_tree(&v_ast, cmp_exprtr, process_ancestor_info);
}

static status_t process_ancestor_info_after_cond_pullup_normal(sql_stmt_t *statement, sql_query_t *sub_qry,
                                                               cond_node_t *cond)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));
    switch (cond->type) {
        case COND_NODE_COMPARE:
            OG_RETURN_IFERR(process_ancestor_info_in_cmp_expr_normal(statement, sub_qry, cond->cmp->left));
            OG_RETURN_IFERR(process_ancestor_info_in_cmp_expr_normal(statement, sub_qry, cond->cmp->right));
            break;
        case COND_NODE_OR:
        case COND_NODE_AND:
            OG_RETURN_IFERR(process_ancestor_info_after_cond_pullup_normal(statement, sub_qry, cond->left));
            OG_RETURN_IFERR(process_ancestor_info_after_cond_pullup_normal(statement, sub_qry, cond->right));
        default:
            break;
    }
    return OG_SUCCESS;
}

status_t post_process_pull_up_cond_normal(rewrite_helper_t *helper, sql_query_t *sub_qry, cond_tree_t *pulled_up_tree)
{
    if (helper->pullup_cond) {
        OG_RETURN_IFERR(process_ancestor_info_after_cond_pullup_normal(helper->stmt, sub_qry, pulled_up_tree->root));
        if (helper->query->cond) {
            OG_RETURN_IFERR(sql_add_cond_node_left(helper->query->cond, pulled_up_tree->root));
        } else {
            helper->query->cond = pulled_up_tree;
        }
    }

    OG_RETURN_IFERR(try_eval_logic_cond(helper->stmt, sub_qry->cond->root));
    if (sub_qry->cond->root->type == COND_NODE_TRUE) {
        sub_qry->cond = NULL;
    }
    return OG_SUCCESS;
}

static bool32 cmp_type_can_pullup(cmp_node_t *cmp)
{
    if (cmp->type == CMP_TYPE_LESS_ALL ||
        cmp->type == CMP_TYPE_GREAT_ALL ||
        cmp->type == CMP_TYPE_EQUAL_ALL ||
        cmp->type == CMP_TYPE_LESS_EQUAL_ALL ||
        cmp->type == CMP_TYPE_GREAT_EQUAL_ALL ||
        cmp->type == CMP_TYPE_NOT_EQUAL_ALL ||
        cmp->type == CMP_TYPE_NOT_IN ||
        cmp->type == CMP_TYPE_NOT_EXISTS) {
        return OG_FALSE;
    }
    
    return OG_TRUE;
}

status_t check_and_pull_up_subquery_conds_normal(rewrite_helper_t *helper)
{
    sql_select_t *slct = GET_SELECT_CTX(helper->curr_cond);
    sql_query_t *sub_qry = slct->root->query;
    cond_tree_t *pulled_up_tree = NULL;

    OG_RETURN_IFERR(try_pull_up_subquery_conds_normal(helper->stmt, &pulled_up_tree, sub_qry->cond->root));
    helper->pullup_cond = (pulled_up_tree != NULL && cmp_type_can_pullup(helper->curr_cond->cmp));
    if (!pulled_up_tree) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 20.10 pulled_up_conds is null after pullup");
        return OG_SUCCESS;
    }

    return post_process_pull_up_cond_normal(helper, sub_qry, pulled_up_tree);
}

status_t pull_up_subquery_conds_normal(rewrite_helper_t *helper)
{
    OG_RETVALUE_IFTRUE(!check_subquery_can_be_pulled_up_normal(helper), OG_SUCCESS);

    return check_and_pull_up_subquery_conds_normal(helper);
}

bool32 check_subquery_can_be_pulled_up(rewrite_helper_t *helper)
{
    helper->curr_sub_query->cond_has_acstor_col = OG_FALSE;
    helper->curr_cond->type = COND_NODE_TRUE;
    if (!helper->curr_sub_query->cond) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 21.2 subquery cond is null, no cond can be pullup");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 check_cmp_cond_can_be_pulled_up(cond_node_t *cmp_cond, bool32 *has_join_cond)
{
    cols_used_t col_used_cmp_l;
    cols_used_t col_used_cmp_r;
    init_cols_used(&col_used_cmp_l);
    init_cols_used(&col_used_cmp_r);
    sql_collect_cols_in_expr_tree(cmp_cond->cmp->left, &col_used_cmp_l);
    sql_collect_cols_in_expr_tree(cmp_cond->cmp->right, &col_used_cmp_r);
    uint8 flags_l = col_used_cmp_l.flags;
    uint8 flags_r = col_used_cmp_r.flags;

    bool32 has_parent_or_ancestor = (HAS_PRNT_OR_ANCSTR_COLS(flags_l) || HAS_PRNT_OR_ANCSTR_COLS(flags_r));
    if (!has_parent_or_ancestor) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 21.3 exists/not exists: There are no parent/ancestor cols "
                         "on either side of the subquery comparison condition, subquery cond cannot be pulled up");
        return OG_FALSE;
    }

    if (cmp_cond->cmp->type == CMP_TYPE_EQUAL) {
        bool32 has_diff_level_cols = has_diff_level_columns(flags_l, flags_r);
        if (has_diff_level_cols) {
            OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 21.4 exists/not exists: equal comparison condition in subquery "
                             "has different layer cond in different sides, subquery cond can be pulled up");
            *has_join_cond = OG_TRUE;
            return OG_TRUE;
        }
    }

    return OG_TRUE;
}

static bool32 check_or_cond_can_be_pulled_up(cond_node_t *or_cond)
{
    cols_used_t col_used_or;
    init_cols_used(&col_used_or);
    sql_collect_cols_in_cond(or_cond, &col_used_or);
    uint8 flags = col_used_or.flags;
    bool32 has_parent_or_ancestor_cols = HAS_PRNT_OR_ANCSTR_COLS(flags);
    if (!has_parent_or_ancestor_cols) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 21.5 exists: or comparison condition in subquery: "
                         "no parent/ancestor cols, subquery cond cannot be pulled up");
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 check_conds_can_be_pulled_up(sql_stmt_t *statement, cond_node_t *cond, bool32 *has_join_cond)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));
    switch (cond->type) {
        case COND_NODE_COMPARE:
            return check_cmp_cond_can_be_pulled_up(cond, has_join_cond);
        case COND_NODE_OR:
            return check_or_cond_can_be_pulled_up(cond);
        case COND_NODE_AND:
            return check_conds_can_be_pulled_up(statement, cond->left, has_join_cond) &&
                   check_conds_can_be_pulled_up(statement, cond->right, has_join_cond);
        default:
            return OG_FALSE;
    }
    return OG_FALSE;
}

static status_t merge_cond_into_tree_shallow(sql_stmt_t *statement, cond_tree_t **dest_tree, cond_node_t *cond)
{
    if (!*dest_tree) {
        OG_RETURN_IFERR(sql_create_cond_tree(statement->context, dest_tree));
    }

    OG_RETURN_IFERR(sql_merge_cond_tree_shallow(*dest_tree, cond));
    cond->type = COND_NODE_TRUE;
    return OG_SUCCESS;
}

status_t try_pull_up_subquery_conds(sql_stmt_t *statement, cond_tree_t **pulled_up_tree, cond_node_t *cond,
                                    bool32 *has_join_cond)
{
    OGSQL_SAVE_STACK(statement);

    galist_t *pullup_cond_lst = NULL;
    OG_RETURN_IFERR(sql_push(statement, sizeof(galist_t), (void **)&pullup_cond_lst));
    cm_galist_init(pullup_cond_lst, statement, (ga_alloc_func_t)sql_push);
    status_t status = get_all_and_cmp_conds(statement, pullup_cond_lst, cond, OG_TRUE);
    if (status != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        return status;
    }

    for (uint32 i = 0; i < pullup_cond_lst->count; i++) {
        cond_node_t *curr_cond = (cond_node_t *)cm_galist_get(pullup_cond_lst, i);
        if (!check_conds_can_be_pulled_up(statement, curr_cond, has_join_cond)) {
            continue;
        }
        status = merge_cond_into_tree_shallow(statement, pulled_up_tree, curr_cond);
        if (status != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(statement);
            return status;
        }
    }

    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static void reset_subquery_clauses_after_pullup(sql_stmt_t *statement, sql_query_t *sub_qry)
{
    cm_galist_init(sub_qry->group_sets, sub_qry->group_sets->owner, sql_alloc_mem);
    cm_galist_init(sub_qry->sort_items, sub_qry->sort_items->owner, sql_alloc_mem);
    cm_galist_init(sub_qry->distinct_columns, sub_qry->distinct_columns->owner, sql_alloc_mem);
    
    uint32 count = sub_qry->rs_columns->count;
    uint32 index = 0;
    rs_column_t *cur_rs_column = NULL;
    
    while (index < count) {
        cur_rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, index);
        if (cur_rs_column->type == RS_COL_CALC && cur_rs_column->expr != NULL) {
            og_del_parent_refs_in_expr_tree(sub_qry, cur_rs_column->expr);
        }
        index++;
    }
    
    cm_galist_reset(sub_qry->rs_columns);
    sub_qry->has_distinct = OG_FALSE;
}

static status_t set_rs_column_info_4_rewrite(sql_stmt_t *statement, rs_column_t *rs_column, rs_column_type_t col_type,
                                             expr_tree_t *cmp_exprtr, typmode_t *typmod, uint32 rs_col_id)
{
    rs_column->type = col_type;
    if (col_type == RS_COL_CALC) {
        rs_column->expr = cmp_exprtr;
    }
    rs_column->typmod = *typmod;
    OG_BIT_SET(rs_column->rs_flag, RS_IS_REWRITE);
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, OG_MAX_NAME_LEN, (void **)&rs_column->name.str));
    PRTS_RETURN_IFERR(snprintf_s(rs_column->name.str, OG_MAX_NAME_LEN, OG_MAX_NAME_LEN - 1, "COL_%u", rs_col_id));
    rs_column->name.len = (uint32)strlen(rs_column->name.str);
    return OG_SUCCESS;
}

static status_t create_rs_column_in_process_cmp_expr(sql_stmt_t *statement, sql_query_t *sub_qry,
                                                     expr_tree_t *cmp_exprtr)
{
    rs_column_t *rs_column = NULL;
    OG_RETURN_IFERR(cm_galist_new(sub_qry->rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_column));
    uint32 rs_col_id = sub_qry->rs_columns->count - 1;
    return set_rs_column_info_4_rewrite(statement, rs_column, RS_COL_CALC, cmp_exprtr, &cmp_exprtr->root->typmod,
                                        rs_col_id);
}

static inline void set_var_column_info(var_column_t *var_col, og_type_t og_type, uint16 tab_no, uint16 col_no,
                                       uint32 ancest, int32 start, int32 end)
{
    var_col->datatype = og_type;
    var_col->tab = tab_no;
    var_col->col = col_no;
    var_col->ancestor = ancest;
    var_col->ss_start = start;
    var_col->ss_end = end;
}

static status_t rebuild_join_cond_in_process_cmp_expr(sql_stmt_t *statement, sql_query_t *sub_qry,
                                                      expr_tree_t *cmp_exprtr, expr_tree_t **rebuild_tree,
                                                      sql_table_t *semi_tbl)
{
    OG_RETURN_IFERR(sql_create_expr(statement, rebuild_tree));
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&(*rebuild_tree)->root));
    expr_node_t *rebuild_exprn = (*rebuild_tree)->root;
    var_column_t *var_col = &rebuild_exprn->value.v_col;
    og_type_t og_type = cmp_exprtr->root->datatype;
    rebuild_exprn->type = EXPR_NODE_COLUMN;
    rebuild_exprn->datatype = og_type;
    rebuild_exprn->typmod = cmp_exprtr->root->typmod;
    rebuild_exprn->left = NULL;
    rebuild_exprn->right = NULL;
    set_var_column_info(var_col, og_type, semi_tbl->id, sub_qry->rs_columns->count - 1, 0, OG_INVALID_ID32,
                        OG_INVALID_ID32);

    query_field_t qry_fld;
    SQL_SET_QUERY_FIELD_INFO(&qry_fld, rebuild_exprn->datatype, var_col->col, OG_FALSE, OG_INVALID_ID32,
                             OG_INVALID_ID32);
    return sql_table_cache_cond_query_field(statement, semi_tbl, &qry_fld);
}

static status_t collect_ssa_node(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_SELECT) {
        biqueue_add_tail((biqueue_t *)v_ast->param0, QUEUE_NODE_OF(*exprn));
    }
    return OG_SUCCESS;
}

static status_t pullup_ssa_from_subselect(sql_stmt_t *statement, sql_query_t *sub_qry, expr_node_t *select_exprn)
{
    sql_query_t *parent_qry = sub_qry->owner->parent;
    select_exprn->value.v_obj.id = parent_qry->ssa.count;
    return sql_array_put(&parent_qry->ssa, select_exprn->value.v_obj.ptr);
}

static status_t update_query_ssa_in_process_cmp_expr(sql_stmt_t *statement, sql_query_t *sub_qry,
                                                     expr_node_t *cmp_exprn)
{
    visit_assist_t v_ast;
    biqueue_t bque;
    biqueue_init(&bque);
    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.param0 = (void *)&bque;
    OG_RETURN_IFERR(visit_expr_node(&v_ast, &cmp_exprn, collect_ssa_node));
    biqueue_node_t *bque_curr = NULL;
    biqueue_node_t *bque_end = biqueue_end(&bque);

    for (bque_curr = biqueue_first(&bque); bque_curr != bque_end; bque_curr = bque_curr->next) {
        expr_node_t *select_exprn = OBJECT_OF(expr_node_t, bque_curr);
        OG_RETURN_IFERR(pullup_ssa_from_subselect(statement, sub_qry, select_exprn));
    }
    return OG_SUCCESS;
}

static status_t process_cols_in_cmp_expr(sql_stmt_t *statement, sql_query_t *sub_qry, expr_tree_t **cmp_exprtr,
                                         sql_table_t *semi_tbl, uint32 *flags, uint32 *ref_tab_id)
{
    visit_assist_t v_ast;
    status_t ret = OG_SUCCESS;
    expr_tree_t **cur_expr = NULL;

    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.param0 = sub_qry;
    v_ast.result0 = 0;
    v_ast.result1 = OG_INVALID_ID32;
    v_ast.excl_flags |= VA_EXCL_PRIOR;

    for (cur_expr = cmp_exprtr; *cur_expr != NULL && ret == OG_SUCCESS; cur_expr = &(*cur_expr)->next) {
        // 先保存当前表达式节点的引用，减少重复解引用
        expr_tree_t *exprtr_val = *cur_expr;
        ret = visit_expr_node(&v_ast, &exprtr_val->root, process_ancestor_info);
        if (ret != OG_SUCCESS) {
            break;
        }

        *flags |= v_ast.result0;
        if (HAS_SELF_COLS(*flags)) {
            ret = create_rs_column_in_process_cmp_expr(statement, sub_qry, exprtr_val);
            if (ret == OG_SUCCESS) {
                ret = rebuild_join_cond_in_process_cmp_expr(statement, sub_qry, exprtr_val, cur_expr, semi_tbl);
            }
            if (ret != OG_SUCCESS) {
                break;
            }
        }

        ret = update_query_ssa_in_process_cmp_expr(statement, sub_qry, exprtr_val->root);
        if (ret != OG_SUCCESS) {
            break;
        }
    }
    
    if (ret == OG_SUCCESS) {
        *ref_tab_id = v_ast.result1;
    } else {
        OG_LOG_DEBUG_INF("process_cols_in_cmp_expr failed");
        cm_set_error_pos(__FILE__, __LINE__);
    }
    
    return ret;
}

static bool32 check_if_contains_table(galist_t *tbl_lst, uint32 tbl_id)
{
    for (uint32 i = 0; i < tbl_lst->count; i++) {
        uint32 *id = (uint32 *)cm_galist_get(tbl_lst, i);
        if (*id == tbl_id) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t add_to_cbo_depend_tables(sql_stmt_t *statement, sql_table_t *tbl, uint32 tbl_id)
{
    galist_t *tbl_lst = TABLE_CBO_DEP_TABLES(tbl);
    if (tbl_lst == NULL) {
        OG_RETURN_IFERR(sql_create_list(statement, &tbl_lst));
        TABLE_CBO_DEP_TABLES(tbl) = tbl_lst;
    }

    if (check_if_contains_table(tbl_lst, tbl_id)) {
        return OG_SUCCESS;
    }

    uint32 *new_id = NULL;
    OG_RETURN_IFERR(cm_galist_new(tbl_lst, sizeof(uint32), (void **)&new_id));
    *new_id = tbl_id;
    return OG_SUCCESS;
}

static bool32 check_if_add_to_cbo_depend_tables(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl)
{
    if (TABLE_CBO_DEP_TABLES(tbl) != NULL && TABLE_CBO_DEP_TABLES(tbl)->count > 1) {
        return OG_TRUE;
    }

    // anti join: t1 anti join t2, t2 cannot drive t1 to select
    if (tbl->subslct_tab_usage >= SUBSELECT_4_ANTI_JOIN) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t process_cols_after_pullup(sql_stmt_t *statement, sql_query_t *sub_qry, cond_node_t *cond,
                                          sql_table_t *semi_tbl)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));
    uint32 flags_l = 0;
    uint32 flags_r = 0;
    uint32 ref_tab_id = OG_INVALID_ID32;
    switch (cond->type) {
        case COND_NODE_COMPARE: {
            OG_RETURN_IFERR(
                process_cols_in_cmp_expr(statement, sub_qry, &cond->cmp->left, semi_tbl, &flags_l, &ref_tab_id));
            OG_RETURN_IFERR(
                process_cols_in_cmp_expr(statement, sub_qry, &cond->cmp->right, semi_tbl, &flags_r, &ref_tab_id));
            OG_RETSUC_IFTRUE(semi_tbl->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN);
            bool32 has_diff_level_cols = has_diff_level_columns(flags_l, flags_r);
            if (has_diff_level_cols) {
                OG_RETURN_IFERR(add_to_cbo_depend_tables(statement, semi_tbl, ref_tab_id));
                if (check_if_add_to_cbo_depend_tables(statement, sub_qry, semi_tbl)) {
                    TABLE_CBO_SET_FLAG(semi_tbl, (SELTION_DEPD_TABLES | SELTION_NO_DRIVER));
                }
            }
            break;
        }
        case COND_NODE_OR:
        case COND_NODE_AND:
            OG_RETURN_IFERR(process_cols_after_pullup(statement, sub_qry, cond->left, semi_tbl));
            OG_RETURN_IFERR(process_cols_after_pullup(statement, sub_qry, cond->right, semi_tbl));
        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t rebuild_ssa_after_pullup(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_type_t expr_type = (*exprn)->type;
    switch (expr_type) {
        case EXPR_NODE_GROUP: {
            expr_node_t *orig_exprn = (expr_node_t *)sql_get_origin_ref(*exprn);
            OG_RETURN_IFERR(visit_expr_node(v_ast, &orig_exprn, rebuild_ssa_after_pullup));
        }
        case EXPR_NODE_SELECT:
            (*exprn)->value.v_obj.id = v_ast->query->ssa.count;
            OG_RETURN_IFERR(sql_array_put(&v_ast->query->ssa, (*exprn)->value.v_obj.ptr));
        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_cond(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->cond) {
        return OG_SUCCESS;
    }
    return visit_cond_node(v_ast, sub_qry->cond->root, v_function);
}

static status_t subquery_oper_join_node(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->join_assist.join_node) {
        return OG_SUCCESS;
    }
    return visit_join_node_cond(v_ast, sub_qry->join_assist.join_node, v_function);
}

static status_t subquery_oper_start_with_cond(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->start_with_cond) {
        return OG_SUCCESS;
    }
    return visit_cond_node(v_ast, sub_qry->start_with_cond->root, v_function);
}

static status_t subquery_oper_connect_by_cond(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->connect_by_cond) {
        return OG_SUCCESS;
    }
    return visit_cond_node(v_ast, sub_qry->connect_by_cond->root, v_function);
}

static status_t subquery_oper_having_cond(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->having_cond) {
        return OG_SUCCESS;
    }
    return visit_cond_node(v_ast, sub_qry->having_cond->root, v_function);
}

static status_t subquery_oper_sorts(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    for (uint32 i = 0; i < sub_qry->sort_items->count; i++) {
        sort_item_t *sort_item = (sort_item_t *)cm_galist_get(sub_qry->sort_items, i);
        OG_RETURN_IFERR(visit_expr_tree(v_ast, sort_item->expr, v_function));
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_aggrs(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    for (uint32 i = 0; i < sub_qry->aggrs->count; i++) {
        expr_node_t *aggr_exprn = (expr_node_t *)cm_galist_get(sub_qry->aggrs, i);
        OG_RETURN_IFERR(visit_expr_node(v_ast, &aggr_exprn, v_function));
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_tables_ssa(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    sql_table_t *tbl = NULL;
    uint32 count = sub_qry->tables.count;
    uint32 current = 0;
    status_t ret = OG_SUCCESS;
    
    while (current < count && ret == OG_SUCCESS) {
        tbl = (sql_table_t *)sql_array_get(&sub_qry->tables, current);
        if (tbl->type == FUNC_AS_TABLE || tbl->type == JSON_TABLE) {
            if (tbl->type == FUNC_AS_TABLE) {
                ret = visit_expr_tree(v_ast, tbl->func.args, v_function);
            } else {
                ret = visit_expr_tree(v_ast, tbl->json_table_info->data_expr, v_function);
            }
        }
        
        current++;
    }
    
    return ret;
}

static status_t subquery_oper_rs_cols_ssa(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    for (uint32 i = 0; i < sub_qry->rs_columns->count; i++) {
        rs_column_t *rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, i);
        if (rs_column->type == RS_COL_CALC) {
            OG_RETURN_IFERR(visit_expr_tree(v_ast, rs_column->expr, v_function));
        }
    }
    return OG_SUCCESS;
}

static rebuild_subquery_ssa_t rebuild_subquery_ssa_items[] = {
    subquery_oper_cond,
    subquery_oper_join_node,
    subquery_oper_start_with_cond,
    subquery_oper_connect_by_cond,
    subquery_oper_having_cond,
    subquery_oper_sorts,
    subquery_oper_aggrs,
    subquery_oper_tables_ssa,
    subquery_oper_rs_cols_ssa,
};

static status_t rebuild_subquery_ssa_after_pullup(sql_stmt_t *statement, sql_query_t *sub_qry)
{
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, sub_qry);
    sub_qry->ssa.count = 0;

    uint32 rebuild_count = sizeof(rebuild_subquery_ssa_items) / sizeof(rebuild_subquery_ssa_t);
    for (uint32 i = 0; i < rebuild_count; i++) {
        OG_RETURN_IFERR(rebuild_subquery_ssa_items[i](&v_ast, sub_qry, rebuild_ssa_after_pullup));
    }

    return OG_SUCCESS;
}

static status_t process_ancestor_info_after_cond_pullup(sql_stmt_t *statement, sql_query_t *sub_qry, cond_node_t *cond,
                                                 sql_table_t *semi_tbl)
{
    sql_query_t *qry = sub_qry->owner->parent;
    uint32 query_ssa_count = qry->ssa.count;
    reset_subquery_clauses_after_pullup(statement, sub_qry);
    OG_RETURN_IFERR(process_cols_after_pullup(statement, sub_qry, cond, semi_tbl));
    if (sub_qry->rs_columns->count == 0) {
        OG_RETURN_IFERR(og_modify_rs_cols2const(statement, sub_qry));
    }

    if (query_ssa_count != qry->ssa.count) {
        OG_RETURN_IFERR(rebuild_subquery_ssa_after_pullup(statement, sub_qry));
    }
    return OG_SUCCESS;
}

status_t post_process_pull_up_cond(rewrite_helper_t *helper, cond_tree_t *pulled_up_tree)
{
    sql_query_t *qry = helper->query;
    sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&qry->tables, qry->tables.count - 1);
    OG_RETURN_IFERR(
        process_ancestor_info_after_cond_pullup(helper->stmt, helper->curr_sub_query, pulled_up_tree->root, semi_tbl));
    OG_RETURN_IFERR(sql_add_cond_node(qry->cond, pulled_up_tree->root));
    OG_RETURN_IFERR(try_eval_logic_cond(helper->stmt, helper->curr_sub_query->cond->root));
    if (helper->curr_sub_query->cond->root->type == COND_NODE_TRUE) {
        helper->curr_sub_query->cond = NULL;
    }
    return OG_SUCCESS;
}

status_t check_and_pull_up_subquery_conds(rewrite_helper_t *helper)
{
    cond_tree_t *pulled_up_tree = NULL;

    OG_RETURN_IFERR(try_pull_up_subquery_conds(helper->stmt, &pulled_up_tree, helper->curr_sub_query->cond->root,
                                               &helper->has_join_cond));
    helper->pullup_cond = (pulled_up_tree != NULL);
    if (!pulled_up_tree) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 21.6 There are no conditions can be pulled up in the subquery.");
        return OG_SUCCESS;
    }

    return post_process_pull_up_cond(helper, pulled_up_tree);
}

status_t pull_up_subquery_conds(rewrite_helper_t *helper)
{
    OG_RETVALUE_IFTRUE(!check_subquery_can_be_pulled_up(helper), OG_SUCCESS);

    return check_and_pull_up_subquery_conds(helper);
}

static status_t create_new_table_4_join(sql_stmt_t *statement, sql_query_t *qry, sql_table_t **new_tbl,
                                        sql_select_t *slct, subslct_table_usage_t sub_slct_tbl_usg)
{
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_table_t), (void **)&(*new_tbl)));
    (*new_tbl)->type = SUBSELECT_AS_TABLE;
    (*new_tbl)->id = qry->tables.count;
    (*new_tbl)->subslct_tab_usage = sub_slct_tbl_usg;
    (*new_tbl)->select_ctx = slct;
    (*new_tbl)->select_ctx->type = SELECT_AS_TABLE;
    (*new_tbl)->select_ctx->parent = qry;
    OG_RETURN_IFERR(sql_generate_unnamed_table_name(statement, (*new_tbl), TAB_TYPE_SUBQRY_TO_TAB));
    (*new_tbl)->qb_name = qry->block_info->transformed ? qry->block_info->changed_name : qry->block_info->origin_name;
    TABLE_CBO_ATTR_OWNER((*new_tbl)) = qry->vmc;
    return sql_array_put(&qry->tables, (*new_tbl));
}

static status_t create_stable_4_join(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond)
{
    sql_table_t *semi_tbl = NULL;
    sql_select_t *sub_slct = GET_SELECT_CTX(cond);
    subslct_table_usage_t sub_slct_tbl_usg = SUBSELECT_4_NL_JOIN;
    switch (cond->cmp->type) {
        case CMP_TYPE_IN:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_EQUAL_ANY:
            sub_slct_tbl_usg = SUBSELECT_4_SEMI_JOIN;
            break;
        case CMP_TYPE_NOT_IN:
            sub_slct_tbl_usg = SUBSELECT_4_ANTI_JOIN_NA;
            break;
        case CMP_TYPE_NOT_EXISTS:
            sub_slct_tbl_usg = SUBSELECT_4_ANTI_JOIN;
            break;
        default:
            sub_slct_tbl_usg = SUBSELECT_4_NL_JOIN;
            break;
    }
    return create_new_table_4_join(statement, qry, &semi_tbl, sub_slct, sub_slct_tbl_usg);
}

static status_t set_table_cbo_flag(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry, sql_table_t *tbl,
                                   bool32 has_join_cond)
{
    if (has_join_cond) {
        if (check_if_add_to_cbo_depend_tables(statement, qry, tbl)) {
            TABLE_CBO_SET_FLAG(tbl, (SELTION_DEPD_TABLES | SELTION_NO_DRIVER));
        }
        return OG_SUCCESS;
    }

    if (tbl->subslct_tab_usage >= SUBSELECT_4_SEMI_JOIN) {
        TABLE_CBO_SET_FLAG(tbl, (SELTION_DEPD_TABLES | SELTION_NO_DRIVER));
        OG_RETURN_IFERR(add_to_cbo_depend_tables(statement, tbl, 0));
    }

    if (sub_qry->tables.count <= 1) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < sub_qry->tables.count; i++) {
        sql_table_t *sql_table = (sql_table_t *)sql_array_get(&sub_qry->tables, i);
        TABLE_CBO_SET_FLAG(sql_table, SELTION_NL_PRIORITY);
    }
    return OG_SUCCESS;
}

static status_t create_cmp_cond_replace_curr_cond(rewrite_helper_t *helper, cmp_node_t *curr_cmp,
                                                  cond_node_t **new_cond)
{
    OG_RETURN_IFERR(sql_alloc_mem(helper->stmt->context, sizeof(cond_node_t), (void **)&(*new_cond)));
    (*new_cond)->cmp = curr_cmp;
    (*new_cond)->type = COND_NODE_COMPARE;
    OG_RETURN_IFERR(sql_add_cond_node(helper->query->cond, (*new_cond)));
    return OG_SUCCESS;
}

static status_t modify_cond_right_node_to_column(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond)
{
    expr_node_t *right_exprn = cond->cmp->right->root;
    sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&qry->tables, qry->tables.count - 1);
    if (right_exprn->type == EXPR_NODE_SELECT) {
        sql_slct_del_ref_node(statement, right_exprn);
    }
    right_exprn->type = EXPR_NODE_COLUMN;
    right_exprn->value.v_col.col_info_ptr = NULL;
    right_exprn->value.v_col.tab = semi_tbl->id;
    right_exprn->value.v_col.col = 0;
    right_exprn->value.v_col.ancestor = 0;
    return OG_SUCCESS;
}

static status_t create_left_cond_node_for_exists_join(sql_stmt_t *statement, cond_node_t *cond)
{
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_tree_t), (void **)&cond->cmp->left));
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&cond->cmp->left->root));
    expr_node_t *left_exprn = cond->cmp->left->root;
    left_exprn->type = EXPR_NODE_TRANS_COLUMN;
    left_exprn->value.v_col.tab = 0;
    left_exprn->value.v_col.col = OG_INVALID_ID16;
    left_exprn->value.v_col.ancestor = 0;
    left_exprn->value.v_col.datatype = OG_TYPE_STRING;
    left_exprn->value.type = OG_TYPE_COLUMN;
    left_exprn->datatype = OG_TYPE_STRING;
    return OG_SUCCESS;
}

static status_t transform_into_join_cond_for_exists(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry,
                                                    cond_node_t *cond, sql_table_t *semi_tbl)
{
    expr_node_t *right_exprn = cond->cmp->right->root;
    right_exprn->value.v_col.datatype = OG_TYPE_STRING;

    query_field_t qry_fld;
    OG_RETURN_IFERR(set_table_cbo_flag(statement, qry, sub_qry, semi_tbl, OG_FALSE));

    // column id hwm
    SQL_SET_QUERY_FIELD_INFO(&qry_fld, OG_TYPE_STRING, 0, OG_FALSE, OG_INVALID_ID32, OG_INVALID_ID32);
    return sql_table_cache_cond_query_field(statement, semi_tbl, &qry_fld);
}

static void add_to_cbo_depend_tables_4_not_in(sql_stmt_t *statement, sql_table_t *tbl, expr_tree_t *expr)
{
    cols_used_t col_used;
    init_cols_used(&col_used);
    sql_collect_cols_in_expr_tree(expr, &col_used);
    biqueue_t *bque = &col_used.cols_que[SELF_IDX];
    biqueue_node_t *bque_curr = NULL;
    biqueue_node_t *bque_end = biqueue_end(bque);
    for (bque_curr = biqueue_first(bque); bque_curr != bque_end; bque_curr = bque_curr->next) {
        expr_node_t *col_exprn = OBJECT_OF(expr_node_t, bque_curr);
        if (col_exprn->type == EXPR_NODE_COLUMN) {
            add_to_cbo_depend_tables(statement, tbl, NODE_TAB(col_exprn));
        }
    }
    return;
}

static void proccess_cbo_depend_tables(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *semi_tbl,
                                       expr_tree_t *left_exprtr)
{
    if (check_if_add_to_cbo_depend_tables(statement, qry, semi_tbl)) {
        // SUBSELECT_4_ANTI_JOIN, SUBSELECT_4_ANTI_JOIN_NA
        TABLE_CBO_SET_FLAG(semi_tbl, (SELTION_DEPD_TABLES | SELTION_NO_DRIVER));
        add_to_cbo_depend_tables_4_not_in(statement, semi_tbl, left_exprtr);
    }
    return;
}

static status_t update_cond_node_chain(sql_stmt_t *statement, sql_table_t *semi_tbl, cond_node_t *cond,
                                       expr_node_t **right_exprn, expr_tree_t *l_cmp_exprtr, uint32 id)
{
    // create new left_cond, and set to origin cond_node values: left = cond
    cond_node_t *new_left_cond = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)&new_left_cond));
    new_left_cond->type = cond->type;
    new_left_cond->left = cond->left;
    new_left_cond->right = cond->right;
    new_left_cond->cmp = cond->cmp;

    // create new right_cond, and set to cond left: right = left
    cond_node_t *new_right_cond = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)&new_right_cond));
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(cmp_node_t), (void **)&new_right_cond->cmp));
    OG_RETURN_IFERR(sql_create_expr(statement, &new_right_cond->cmp->right));
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&new_right_cond->cmp->right->root));
    new_right_cond->type = COND_NODE_COMPARE;
    new_right_cond->cmp->type = CMP_TYPE_EQUAL;
    new_right_cond->cmp->left = l_cmp_exprtr;
    new_right_cond->cmp->right->root->owner = new_right_cond->cmp->right;
    new_right_cond->cmp->right->root->type = EXPR_NODE_COLUMN;
    new_right_cond->cmp->right->root->value.v_col.tab = semi_tbl->id;
    new_right_cond->cmp->right->root->value.v_col.col = id;
    new_right_cond->cmp->right->root->value.v_col.ancestor = 0;
    (*right_exprn) = new_right_cond->cmp->right->root;

    // change new conds as left/right node of origin cond_node: cond = (left, right)
    cond->type = COND_NODE_AND;
    cond->left = new_left_cond;
    cond->right = new_right_cond;
    cond->cmp = NULL;

    return OG_SUCCESS;
}

static status_t transform_into_join_cond_for_in(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry,
                                                cond_node_t *cond, sql_table_t *semi_tbl)
{
    expr_tree_t *left_tree = cond->cmp->left;
    expr_node_t *right_node = cond->cmp->right->root;
    query_field_t query_field;
    for (uint32 i = 0; left_tree != NULL; i++) {
        expr_tree_t *cmp_left = left_tree;
        left_tree = left_tree->next;
        proccess_cbo_depend_tables(statement, qry, semi_tbl, cmp_left);
        if (i != 0) {
            OG_RETURN_IFERR(update_cond_node_chain(statement, semi_tbl, cond, &right_node, cmp_left, i));
        }
        rs_column_t *rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, i);
        right_node->value.v_col.datatype = rs_column->datatype;
        right_node->typmod = rs_column->typmod;
        if (RS_COL_CALC == rs_column->type) {
            right_node->typmod.is_array = TREE_TYPMODE(rs_column->expr).is_array;
            SQL_SET_QUERY_FIELD_INFO(&query_field, rs_column->datatype, i, rs_column->expr->root->typmod.is_array,
                                     OG_INVALID_ID32, OG_INVALID_ID32);
        } else {
            right_node->typmod.is_array = rs_column->v_col.is_array;
            SQL_SET_QUERY_FIELD_INFO(&query_field, rs_column->datatype, i, rs_column->v_col.is_array,
                                     rs_column->v_col.ss_start, rs_column->v_col.ss_start);
        }
        OG_RETURN_IFERR(sql_table_cache_cond_query_field(statement, semi_tbl, &query_field));
        cmp_left->next = NULL;
    }
    return set_table_cbo_flag(statement, qry, sub_qry, semi_tbl, OG_TRUE);
}

static status_t transform_current_cond_into_join(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry,
                                                 cond_node_t *cond)
{
    sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&qry->tables, qry->tables.count - 1);
    cond->cmp->type = CMP_TYPE_EQUAL;
    modify_cond_right_node_to_column(statement, qry, cond);

    if (!cond->cmp->left) {
        // exists, not exists
        OG_RETURN_IFERR(create_left_cond_node_for_exists_join(statement, cond));
        return transform_into_join_cond_for_exists(statement, qry, sub_qry, cond, semi_tbl);
    } else {
        // in, not in, =any
        return transform_into_join_cond_for_in(statement, qry, sub_qry, cond, semi_tbl);
    }
}

status_t prepare_join_cond(rewrite_helper_t *helper)
{
    cmp_node_t *curr_cmp = helper->curr_cond->cmp;
    expr_tree_t *left_cond_exprtr = helper->curr_cond->cmp->left;
    helper->curr_sub_query->cond_has_acstor_col = OG_FALSE;
    helper->has_join_cond = OG_FALSE;
    bool32 need_pullup = (left_cond_exprtr == NULL && og_check_if_ref_parent_columns(helper->curr_sub_query->owner));
    if (need_pullup) {
        // select * from t1 where exists (select c1 from t2 where t1.c1 = t2.c1);
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.2.1 subquery cond pull up");
        OG_RETURN_IFERR(pull_up_subquery_conds(helper));
    } else {
        // select * from t1 where exists (select c1 from t2 where t2.c1 = 3);
        // select * from t1 where c1 in (select c1 from t2);
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] rule 21.1 subquery type is not `exists/not exists` or"
                         " not use parent cols, subquery cond cannot be pulled up");
    }

    if (need_pullup && helper->has_join_cond) {
        // select * from t1 where exists (select c1 from t2 where t1.c1 = t2.c1);
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.2.2 after pullup, if subquery table can join with query table,"
                         " no need to create join cond");
        sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&helper->query->tables, helper->query->tables.count - 1);
        return set_table_cbo_flag(helper->stmt, helper->query, helper->curr_sub_query, semi_tbl, OG_TRUE);
    }

    cond_node_t *cond = helper->curr_cond;
    if (need_pullup) {
        // select * from t1 where exists (select c1 from t2 where t1.c1 = 1);
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.2.3 after pullup, if not has join cond, "
                         "add subquery cmp cond to query cond list");
        cond_node_t *new_cond = NULL;
        OG_RETURN_IFERR(create_cmp_cond_replace_curr_cond(helper, curr_cmp, &new_cond));
        cond = new_cond;
    }

    // in, not in, =any, pull up but not has join cond
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.2.4 transform current cond to join cond");
    return transform_current_cond_into_join(helper->stmt, helper->query, helper->curr_sub_query, cond);
}

static status_t semi2inner_create_rs_column(sql_stmt_t *statement, galist_t *rs_col_lst, sql_query_t *new_qry)
{
    status_t ret = OG_SUCCESS;
    uint32 count = rs_col_lst->count;
    rs_column_t *rs_column = NULL;
    rs_column_t *rs_column_new = NULL;
    uint32 i = 0;
    
    while (i < count && ret == OG_SUCCESS) {
        rs_column = (rs_column_t *)(rs_column_t *)cm_galist_get(rs_col_lst, i);
        ret = cm_galist_new(new_qry->rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_column_new);
        if (ret == OG_SUCCESS) {
            ret = set_rs_column_info_4_rewrite(statement, rs_column_new, RS_COL_COLUMN, NULL, &rs_column->typmod, i);
            if (ret == OG_SUCCESS) {
                set_var_column_info(&rs_column_new->v_col, rs_column->typmod.datatype, 0, i, 0, OG_INVALID_ID32,
                                    OG_INVALID_ID32);
            }
        }
        i++;
    }
    
    return ret;
}

static status_t semi2inner_verify_query_distinct(sql_stmt_t *statement, sql_query_t *qry)
{
    if (qry->has_distinct) {
        return OG_SUCCESS;
    }
    qry->has_distinct = OG_TRUE;
    sql_verifier_t verifier = { 0 };
    verifier.stmt = statement;
    verifier.context = statement->context;
    SET_NODE_STACK_CURR_QUERY(statement, qry);
    OG_RETURN_IFERR(sql_verify_query_distinct(&verifier, qry));
    SQL_RESTORE_NODE_STACK(statement);
    return OG_SUCCESS;
}

static status_t add_node_to_ancestor_list(galist_t *ancestor_lst, expr_node_t *node)
{
    for (uint32 i = 0; i < ancestor_lst->count; i++) {
        expr_node_t *ancestor_pxprn = (expr_node_t *)cm_galist_get(ancestor_lst, i);
        if (node == ancestor_pxprn) {
            return OG_SUCCESS;
        }
    }
    return cm_galist_insert(ancestor_lst, node);
}

static status_t semi2inner_collect_sub_select(visit_assist_t *v_ast, select_node_t *node)
{
    if (node->type != SELECT_NODE_QUERY) {
        OG_RETURN_IFERR(semi2inner_collect_sub_select(v_ast, node->left));
        OG_RETURN_IFERR(semi2inner_collect_sub_select(v_ast, node->right));
    } else {
        uint32 ancestor = v_ast->result0 + 1;
        semi2inner_collect_ancestor_info(v_ast, node->query, ancestor);
    }
    return OG_SUCCESS;
}

static status_t semi2inner_collect_ancestor_expr(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_type_t expr_type = (*exprn)->type;
    switch (expr_type) {
        case EXPR_NODE_GROUP: {
            expr_node_t *orig_exprn = (expr_node_t *)sql_get_origin_ref(*exprn);
            return visit_expr_node(v_ast, &orig_exprn, semi2inner_collect_ancestor_expr);
        }
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN: {
            uint32 ancestor = v_ast->result0;
            if (NODE_ANCESTOR(*exprn) > ancestor) {
                galist_t *ancestor_lst = (galist_t *)v_ast->param0;
                OG_RETURN_IFERR(add_node_to_ancestor_list(ancestor_lst, *exprn));
            }
            break;
        }
        case EXPR_NODE_RESERVED: {
            uint32 ancestor = v_ast->result0;
            if ((*exprn)->value.v_int == RES_WORD_ROWID && ROWID_NODE_ANCESTOR(*exprn) > ancestor) {
                galist_t *ancestor_lst = (galist_t *)v_ast->param0;
                OG_RETURN_IFERR(add_node_to_ancestor_list(ancestor_lst, *exprn));
            }
            break;
        }
        case EXPR_NODE_SELECT: {
            sql_select_t *slct = (sql_select_t *)VALUE_PTR(var_object_t, &(*exprn)->value)->ptr;
            (*exprn)->value.v_obj.id = v_ast->query->ssa.count;
            OG_RETURN_IFERR(sql_array_put(&v_ast->query->ssa, slct));
            if (slct->has_ancestor > 0) {
                OG_RETURN_IFERR(semi2inner_collect_sub_select(v_ast, slct->root));
            }
            break;
        }
        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_filter_cond(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->filter_cond) {
        return OG_SUCCESS;
    }
    return visit_cond_node(v_ast, sub_qry->filter_cond->root, v_function);
}

static status_t subquery_oper_group_set(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (sub_qry->group_sets == NULL || sub_qry->group_sets->count == 0) {
        return OG_SUCCESS;
    }
    group_set_t *group_set = (group_set_t *)cm_galist_get(sub_qry->group_sets, 0);
    for (uint32 i = 0; i < sub_qry->tables.count; i++) {
        expr_tree_t *group_exprtr = (expr_tree_t *)cm_galist_get(group_set->items, i);
        OG_RETURN_IFERR(visit_expr_tree(v_ast, group_exprtr, v_function));
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_path_func(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    for (uint32 i = 0; i < sub_qry->path_func_nodes->count; i++) {
        expr_node_t *path_func_exprn = (expr_node_t *)cm_galist_get(sub_qry->path_func_nodes, i);
        OG_RETURN_IFERR(visit_expr_node(v_ast, &path_func_exprn, v_function));
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_pivot_items(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (!sub_qry->pivot_items) {
        return OG_SUCCESS;
    }
    pivot_items_t *pivot_item = sub_qry->pivot_items;
    if (pivot_item->type != PIVOT_TYPE) {
        return OG_SUCCESS;
    }
    return visit_expr_tree(v_ast, pivot_item->for_expr, v_function);
}

static status_t subquery_oper_tables_expr(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    for (uint32 i = 0; i < sub_qry->tables.count; i++) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&sub_qry->tables, i);
        if (tbl->type == FUNC_AS_TABLE) {
            OG_RETURN_IFERR(visit_expr_tree(v_ast, tbl->func.args, v_function));
        } else if (tbl->type == SUBSELECT_AS_TABLE) {
            sql_select_t *slct = tbl->select_ctx;
            if (slct->has_ancestor > 0) {
                OG_RETURN_IFERR(semi2inner_collect_sub_select(v_ast, slct->root));
            }
        }
    }
    return OG_SUCCESS;
}

static status_t collect_rs_columns_list(visit_assist_t *v_ast, galist_t *rs_col_lst, visit_func_t v_function)
{
    for (uint32 i = 0; i < rs_col_lst->count; i++) {
        rs_column_t *rs_column = (rs_column_t *)cm_galist_get(rs_col_lst, i);
        if (rs_column->type == RS_COL_CALC) {
            OG_RETURN_IFERR(visit_expr_tree(v_ast, rs_column->expr, v_function));
        } else if (rs_column->type == RS_COL_COLUMN && rs_column->v_col.ancestor > v_ast->result0) {
            rs_column->v_col.ancestor++;
        }
    }
    return OG_SUCCESS;
}

static status_t subquery_oper_rs_cols_collect(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t v_function)
{
    if (sub_qry->has_distinct) {
        galist_t *distinct_columns = sub_qry->distinct_columns;
        OG_RETURN_IFERR(collect_rs_columns_list(v_ast, distinct_columns, v_function));
    }

    if (sub_qry->winsort_list->count > 0) {
        galist_t *winsort_rs_columns = sub_qry->winsort_rs_columns;
        OG_RETURN_IFERR(collect_rs_columns_list(v_ast, winsort_rs_columns, v_function));
    }

    galist_t *rs_columns = sub_qry->rs_columns;
    return collect_rs_columns_list(v_ast, rs_columns, v_function);
}

static collect_subquery_expr_t collect_subquery_expr_items[] = {
    subquery_oper_cond,
    subquery_oper_join_node,
    subquery_oper_start_with_cond,
    subquery_oper_connect_by_cond,
    subquery_oper_having_cond,
    subquery_oper_filter_cond,
    subquery_oper_sorts,
    subquery_oper_aggrs,
    subquery_oper_group_set,
    subquery_oper_path_func,
    subquery_oper_pivot_items,
    subquery_oper_tables_expr,
    subquery_oper_rs_cols_collect,
};

status_t semi2inner_collect_ancestor_info(visit_assist_t *v_ast, sql_query_t *sub_qry, uint32 ancestor)
{
    sql_query_t *save_qry = v_ast->query;
    uint32 save_ancestor = v_ast->result0;
    v_ast->query = sub_qry;
    v_ast->result0 = ancestor;
    uint32 collect_count = sizeof(collect_subquery_expr_items) / sizeof(collect_subquery_expr_t);
    for (uint32 i = 0; i < collect_count; i++) {
        OG_RETURN_IFERR(collect_subquery_expr_items[i](v_ast, sub_qry, semi2inner_collect_ancestor_expr));
    }
    v_ast->query = save_qry;
    v_ast->result0 = save_ancestor;
    return OG_SUCCESS;
}

static void semi2inner_modify_ancestor(galist_t *ancestor_lst)
{
    for (uint32 i = 0; i < ancestor_lst->count; i++) {
        expr_node_t *exprn = (expr_node_t *)cm_galist_get(ancestor_lst, i);
        switch (exprn->type) {
            case EXPR_NODE_COLUMN:
                exprn->value.v_col.ancestor++;
                break;
            case EXPR_NODE_RESERVED:
                exprn->value.v_rid.ancestor++;
                break;
            default:
                break;
        }
    }
    return;
}

static status_t semi2inner_modify_ancestors(sql_stmt_t *statement, sql_query_t *qry)
{
    visit_assist_t v_ast;
    galist_t ancestor_lst;
    cm_galist_init(&ancestor_lst, statement->session->stack, cm_stack_alloc);
    sql_init_visit_assist(&v_ast, statement, qry);
    v_ast.param0 = (void *)&ancestor_lst;

    OGSQL_SAVE_STACK(statement);
    status_t status = semi2inner_collect_ancestor_info(&v_ast, qry, 0);
    if (status != OG_SUCCESS) {
        CM_RESTORE_STACK(statement->session->stack);
        return status;
    }
    semi2inner_modify_ancestor(&ancestor_lst);
    OGSQL_RESTORE_STACK(statement);

    return OG_SUCCESS;
}

static status_t semi2inner_modify_select_node(sql_stmt_t *statement, select_node_t *node)
{
    if (node->type != SELECT_NODE_QUERY) {
        OG_RETURN_IFERR(semi2inner_modify_select_node(statement, node->left));
        OG_RETURN_IFERR(semi2inner_modify_select_node(statement, node->right));
    } else {
        return semi2inner_modify_ancestors(statement, node->query);
    }
    return OG_SUCCESS;
}

static status_t semi2inner_modify_parent_refs(sql_stmt_t *statement, sql_select_t *new_slct, sql_select_t *orig_slct)
{
    if (orig_slct->parent_refs->count > 0) {
        OG_RETURN_IFERR(cm_galist_copy(new_slct->parent_refs, orig_slct->parent_refs));
        cm_galist_reset(orig_slct->parent_refs);
    }
    return OG_SUCCESS;
}

static status_t semi2inner_create_select_ctx(sql_stmt_t *statement, sql_select_t *sub_slct, sql_select_t **slct)
{
    OG_RETURN_IFERR(sql_alloc_select_context(statement, SELECT_AS_TABLE, slct));
    sql_select_t *new_slct = (*slct);
    OG_RETURN_IFERR(sql_create_list(statement, &new_slct->select_sort_items));
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(select_node_t), (void **)&new_slct->root));
    new_slct->root->type = SELECT_NODE_QUERY;
    new_slct->parent = sub_slct->parent;

    sql_query_t *new_qry = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_query_t), (void **)&new_qry));
    OG_RETURN_IFERR(sql_init_query(statement, NULL, sub_slct->first_query->loc, new_qry));

    new_qry->owner = *slct;

    sql_table_t *new_tbl = NULL;
    OG_RETURN_IFERR(create_new_table_4_join(statement, new_qry, &new_tbl, sub_slct, SUBSELECT_4_NL_JOIN));

    galist_t *rs_columns = sub_slct->first_query->rs_columns;
    OG_RETURN_IFERR(semi2inner_create_rs_column(statement, rs_columns, new_qry));
    OG_RETURN_IFERR(semi2inner_verify_query_distinct(statement, new_qry));

    new_slct->root->query = new_qry;
    sub_slct->parent = new_qry;
    new_slct->first_query = new_qry;

    OG_RETURN_IFERR(semi2inner_modify_select_node(statement, sub_slct->root));
    return semi2inner_modify_parent_refs(statement, new_slct, sub_slct);
}

static status_t semi2inner_verify_subselect_table(sql_stmt_t *statement, sql_select_t *sub_slct, sql_select_t **slct)
{
    switch (sub_slct->root->type) {
        case SELECT_NODE_UNION:
        case SELECT_NODE_MINUS:
        case SELECT_NODE_INTERSECT:
        case SELECT_NODE_EXCEPT:
            return OG_SUCCESS;
        case SELECT_NODE_UNION_ALL: {
            if (!LIMIT_CLAUSE_OCCUR(&sub_slct->limit)) {
                sub_slct->root->type = SELECT_NODE_UNION;
                return OG_SUCCESS;
            }
            break;
        }
        case SELECT_NODE_INTERSECT_ALL: {
            if (!LIMIT_CLAUSE_OCCUR(&sub_slct->limit)) {
                sub_slct->root->type = SELECT_NODE_INTERSECT;
                return OG_SUCCESS;
            }
            break;
        }
        case SELECT_NODE_QUERY: {
            sql_query_t *query = sub_slct->root->query;
            if (query->has_distinct) {
                return OG_SUCCESS;
            }
            if (!LIMIT_CLAUSE_OCCUR(&query->limit)) {
                cm_galist_reset(query->sort_items);
                return semi2inner_verify_query_distinct(statement, query);
            }
            break;
        }
        case SELECT_NODE_EXCEPT_ALL:
        default:
            break;
    }
    return semi2inner_create_select_ctx(statement, sub_slct, slct);
}

static status_t choose_semi_to_inner_join_mode(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry)
{
    sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&qry->tables, qry->tables.count - 1);
    subslct_table_usage_t sub_slct_tbl_usg = semi_tbl->subslct_tab_usage;
    if (sub_slct_tbl_usg != SUBSELECT_4_SEMI_JOIN) {
        return OG_SUCCESS;
    }

    bool32 has_semi_to_inner_hint = OG_FALSE;
    if (qry->connect_by_cond || has_semi_to_inner_hint || g_instance->sql.enable_semi2inner) {
        semi_tbl->subslct_tab_usage = SUBSELECT_4_NL_JOIN;
        return semi2inner_verify_subselect_table(statement, semi_tbl->select_ctx, &semi_tbl->select_ctx);
    }
    return OG_SUCCESS;
}

static status_t process_join_hint_4_subquery(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry)
{
    if (HAS_SPEC_TYPE_HINT(sub_qry->hint_info, OPTIM_HINT, (HINT_KEY_WORD_HASH_SJ | HINT_KEY_WORD_HASH_AJ))) {
        return OG_SUCCESS;
    }
    if (sub_qry->hint_info == NULL) {
        // alloc hint if hint is null
        return OG_SUCCESS;
    }
    sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&qry->tables, qry->tables.count - 1);
    subslct_table_usage_t sub_slct_tbl_usg = semi_tbl->subslct_tab_usage;
    switch (sub_slct_tbl_usg) {
        case SUBSELECT_4_SEMI_JOIN:
            sub_qry->hint_info->mask[OPTIM_HINT] |= HINT_KEY_WORD_HASH_SJ;
            break;
        case SUBSELECT_4_ANTI_JOIN:
            sub_qry->hint_info->mask[OPTIM_HINT] |= HINT_KEY_WORD_HASH_AJ;
            break;
        default:
            return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

status_t decide_join_mode(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry, bool32 has_inner_join_cond)
{
    if (has_inner_join_cond) {
        return choose_semi_to_inner_join_mode(statement, qry, sub_qry);
    } else {
        return process_join_hint_4_subquery(statement, qry, sub_qry);
    }
}

static void update_join_node_oper(sql_join_node_t *jnode, subslct_table_usage_t sub_slct_tbl_usg)
{
    switch (sub_slct_tbl_usg) {
        case SUBSELECT_4_SEMI_JOIN:
            jnode->oper = JOIN_OPER_HASH_SEMI;
            return;
        case SUBSELECT_4_ANTI_JOIN:
            jnode->oper = JOIN_OPER_HASH_ANTI;
            return;
        case SUBSELECT_4_ANTI_JOIN_NA:
            jnode->oper = JOIN_OPER_HASH_ANTI_NA;
            return;
        default:
            jnode->oper = JOIN_OPER_NONE;
            sql_join_set_default_oper(jnode);
            return;
    }
}

static status_t update_join_node_tables(sql_stmt_t *statement, sql_join_node_t *new_jnode, sql_join_node_t *orig_jnode,
                                        sql_table_t *semi_tbl)
{
    OG_RETURN_IFERR(sql_create_array(statement->context, &new_jnode->tables, "JOIN TABLES", OG_MAX_JOIN_TABLES));
    OG_RETURN_IFERR(sql_array_concat(&new_jnode->tables, &orig_jnode->tables));
    OG_RETURN_IFERR(sql_array_put(&new_jnode->tables, semi_tbl));
    return OG_SUCCESS;
}

// static status_t init_new_join_node(sql_stmt_t *statement, )
status_t update_query_join_chain(sql_stmt_t *statement, sql_join_node_t **jnode, sql_join_type_t jtype,
                                 sql_table_t *semi_tbl)
{
    sql_join_node_t *orig_jnode = *jnode;
    sql_join_node_t *new_jnode = NULL;
    sql_join_node_t *new_right_jnode = NULL;

    // init new right node
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_join_node_t), (void **)&new_right_jnode));
    OG_RETURN_IFERR(sql_create_array(statement->context, &new_right_jnode->tables, "JOIN TABLES", OG_MAX_JOIN_TABLES));
    SET_TABLE_OF_JOIN_LEAF(new_right_jnode, semi_tbl);
    new_right_jnode->type = JOIN_TYPE_NONE;

    // init new join node
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_join_node_t), (void **)&new_jnode));
    OG_RETURN_IFERR(update_join_node_tables(statement, new_jnode, orig_jnode, semi_tbl));
    new_jnode->type = jtype;
    new_jnode->join_cond = NULL;
    new_jnode->left = orig_jnode;
    new_jnode->right = new_right_jnode;
    update_join_node_oper(new_jnode, semi_tbl->subslct_tab_usage);

    // update origin join node
    *jnode = new_jnode;
    return OG_SUCCESS;
}

status_t create_query_join_node(sql_stmt_t *statement, sql_query_t *qry)
{
    sql_join_chain_t jchain = { 0 };
    if (!qry->join_assist.join_node) {
        sql_table_t *tbl = (sql_table_t *)qry->tables.items[0];
        OG_RETURN_IFERR(sql_generate_join_node(statement, &jchain, JOIN_TYPE_NONE, tbl, NULL));
        qry->join_assist.join_node = jchain.first;
    }
    return OG_SUCCESS;
}

static status_t merge_query_conds_into_tree_shallow(sql_stmt_t *statement, cond_node_t *cond, uint32 table_id,
                                                    cond_tree_t **filter_tree)
{
    OGSQL_SAVE_STACK(statement);
    galist_t *cond_lst;
    OG_RETURN_IFERR(sql_push(statement, sizeof(galist_t), (void **)&cond_lst));
    cm_galist_init(cond_lst, statement, (ga_alloc_func_t)sql_push);
    status_t status = get_all_and_cmp_conds(statement, cond_lst, cond, OG_TRUE);
    if (status != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        return status;
    }
    for (uint32 i = 0; i < cond_lst->count; i++) {
        cond_node_t *curr_cond = (cond_node_t *)cm_galist_get(cond_lst, i);
        if (!sql_cond_node_exist_table(curr_cond, table_id)) {
            continue;
        }
        status = merge_cond_into_tree_shallow(statement, filter_tree, curr_cond);
        if (status != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(statement);
            return status;
        }
    }
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static void set_anti_join_cond_flag(cond_node_t *cond)
{
    if (cond->type == COND_NODE_COMPARE) {
        cond->cmp->anti_join_cond = OG_TRUE;
    }
    if (cond->type == COND_NODE_AND || cond->type == COND_NODE_OR) {
        set_anti_join_cond_flag(cond->left);
        set_anti_join_cond_flag(cond->right);
    }
}

static status_t update_query_join_filter_cond(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond,
                                              sql_table_t *semi_tbl, bool32 has_join_cond)
{
    OG_RETSUC_IFTRUE(0 == qry->join_assist.outer_node_count);

    cond_tree_t *stbl_cond_tree = NULL;
    if (has_join_cond) {
        OG_RETURN_IFERR(merge_query_conds_into_tree_shallow(statement, qry->cond->root, semi_tbl->id, &stbl_cond_tree));
    } else {
        OG_RETURN_IFERR(merge_cond_into_tree_shallow(statement, &stbl_cond_tree, cond));
    }

    if (stbl_cond_tree && semi_tbl->subslct_tab_usage > SUBSELECT_4_SEMI_JOIN) {
        set_anti_join_cond_flag(stbl_cond_tree->root);
    }
    
    qry->join_assist.join_node->filter = stbl_cond_tree;
    return OG_SUCCESS;
}

static status_t process_query_join_node(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond,
                                        bool32 has_join_cond)
{
    sql_table_t *semi_tbl = (sql_table_t *)sql_array_get(&qry->tables, qry->tables.count - 1);
    OG_RETURN_IFERR(create_query_join_node(statement, qry));
    OG_RETURN_IFERR(update_query_join_chain(statement, &qry->join_assist.join_node, JOIN_TYPE_INNER, semi_tbl));
    return update_query_join_filter_cond(statement, qry, cond, semi_tbl, has_join_cond);
}

status_t delete_select_node_from_query_ssa(sql_stmt_t *statement, sql_query_t *qry, uint32 id)
{
    OG_RETURN_IFERR(sql_array_delete(&qry->ssa, id));
    if (qry->ssa.count) {
        OG_RETURN_IFERR(sql_update_query_ssa(qry));
    }
    return OG_SUCCESS;
}

status_t subquery_rewrite_2_table(rewrite_helper_t *helper)
{
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.1 create table for join(SUBSELECT_AS_TABLE)");
    bool32 has_left_cond = (helper->curr_cond->cmp->left != NULL);
    OG_RETURN_IFERR(create_stable_4_join(helper->stmt, helper->query, helper->curr_cond));

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.2 prepare join cond");
    uint32 query_id = SELECT_ID(helper->curr_cond);
    OG_RETURN_IFERR(prepare_join_cond(helper));

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.4 decide join mode: semi2inner / hash join");
    bool32 has_inner_join_cond = (helper->has_join_cond || has_left_cond);
    OG_RETURN_IFERR(decide_join_mode(helper->stmt, helper->query, helper->curr_sub_query, has_inner_join_cond));

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.5 create query join node and update");
    OG_RETURN_IFERR(process_query_join_node(helper->stmt, helper->query, helper->curr_cond, helper->has_join_cond));

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2.6 process ssa");
    OG_RETURN_IFERR(delete_select_node_from_query_ssa(helper->stmt, helper->query, query_id));

    return OG_SUCCESS;
}

static void set_query_without_join(rewrite_helper_t *helper)
{
    expr_tree_t *r_cond_exprtr = helper->curr_cond->cmp->right;
    if (r_cond_exprtr && r_cond_exprtr->root->type == EXPR_NODE_SELECT) {  // make sure select node
        make_subqry_without_join(helper->stmt, (GET_SELECT_CTX(helper->curr_cond))->root, OG_FALSE);
    }
}

status_t pullup_or_rewrite_subquery_cond(rewrite_helper_t *helper)
{
    if (helper->state != REWRITE_SUPPORT) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.1 subquery cannot rewrite: pull up subquery conds");
        set_query_without_join(helper);
        return pull_up_subquery_conds_normal(helper);
    }

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4.2 subquery can rewrite: rewrite subquery to table");
    return subquery_rewrite_2_table(helper);
}

// Process single condition with validation rules
static status_t optim_process_condition(rewrite_helper_t *helper, uint32 idx, uint32 total_conds)
{
    uint32 optim_rules_cnt = 0;
    helper->state = REWRITE_UNCERTAINLY;
    helper->curr_cond = (cond_node_t *)cm_galist_get(helper->cond_list, idx);

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.3 validating condition %u/%u", idx + 1, total_conds);

    // Apply all validation rules until state is determined
    optim_rules_cnt = sizeof(check_subquery2table_items) / sizeof(check_subquery2table_t);
    for (uint32 rule_idx = 0; rule_idx < optim_rules_cnt && helper->state == REWRITE_UNCERTAINLY; ++rule_idx) {
        OG_RETURN_IFERR(check_subquery2table_items[rule_idx](helper));
    }

    // Log validation result
    const char *result = (helper->state == REWRITE_UNSUPPORT) ? "failed" : "passed";
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.4 condition %u/%u %s validation", idx + 1, total_conds, result);
    return pullup_or_rewrite_subquery_cond(helper);
}

// Process all collected conditions
static status_t optim_process_conditions(rewrite_helper_t *helper)
{
    const uint32 total_conds = helper->cond_list->count;

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.2 traverse all 'and' conditions to rewrite");
    for (uint32 i = 0; i < total_conds; i++) {
        OG_RETURN_IFERR(optim_process_condition(helper, i, total_conds));
    }
    return OG_SUCCESS;
}

// Main optimization entry point
static status_t optim_rewrite_subqry_conds(rewrite_helper_t *helper)
{
    OGSQL_SAVE_STACK(helper->stmt);

    // Initialize condition list
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3.1 collect all 'and' conditions");
    OG_RETURN_IFERR(sql_push(helper->stmt, sizeof(galist_t), (void **)&helper->cond_list));
    cm_galist_init(helper->cond_list, helper->stmt, (ga_alloc_func_t)sql_push);

    // Collect AND-connected conditions
    status_t status = get_all_and_cmp_conds(helper->stmt, helper->cond_list, helper->query->cond->root, OG_FALSE);
    if (status != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(helper->stmt);
        return status;
    }

    // Process collected conditions
    status = optim_process_conditions(helper);
    OGSQL_RESTORE_STACK(helper->stmt);

    return status;
}

static void reset_query_after_rewrite(sql_query_t *qry, uint32 origin_table_count, sql_join_node_t *jnode)
{
    if (qry->cond && qry->cond->root->type == COND_NODE_FALSE) {
        qry->tables.count = origin_table_count;
        qry->join_assist.join_node = jnode;
    }
}

static void optim_init_rewrite_helper(rewrite_helper_t *helper, sql_stmt_t *statement, sql_query_t *qry)
{
    helper->stmt = statement;
    helper->query = qry;
    helper->cond_list = NULL;
    helper->curr_cond = NULL;
    helper->curr_sub_query = NULL;
    helper->state = REWRITE_UNCERTAINLY;
    helper->pullup_cond = OG_FALSE;
    helper->has_join_cond = OG_FALSE;
}

status_t og_transf_subquery_rewrite(sql_stmt_t *statement, sql_query_t *qry)
{
    rewrite_helper_t helper;
    optim_init_rewrite_helper(&helper, statement, qry);

    if (!g_instance->sql.enable_subquery_rewrite) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] _OPTIM_SUBQUERY_REWRITE has been shutted");
        return OG_SUCCESS;
    }

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] begin. current sql = %s", T2S(&(statement->session->current_sql)));
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 1. check if sql supports subquery rewrite");

    optim_subqry_rewrite_support(&helper);
    if (helper.state == REWRITE_UNSUPPORT) {
        return OG_SUCCESS;
    }

    OG_RETVALUE_IFTRUE((helper.state == REWRITE_UNSUPPORT), OG_SUCCESS);

    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 2. record initial state");
    uint32 origin_table_count = qry->tables.count;
    sql_join_node_t *jnode = qry->join_assist.join_node;

    // missing step 2 processing
    OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 3. check and rewrite subquery");
    OG_RETURN_IFERR(optim_rewrite_subqry_conds(&helper));

    bool32 rewrite_success = (qry->tables.count > origin_table_count);
    if (rewrite_success) {
        OG_LOG_DEBUG_INF("[SUBQUERY_REWRITE] step 4. modify query block name after rewrite subquery");
    }

    if (rewrite_success) {
        reset_query_after_rewrite(qry, origin_table_count, jnode);
    }

    OG_LOG_DEBUG_INF("-------------------- [SUBQUERY_REWRITE] end.");
    return OG_SUCCESS;
}