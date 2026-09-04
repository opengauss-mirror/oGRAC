/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
 * This file is part of the oGRAC project.
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
 * ogsql_join_elimination.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_join_elimination.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_join_elimination.h"
#include "cbo_join.h"
#include "ogsql_winsort.h"
#include "plan_rbo.h"
#include "dml_parser.h"
#include "ogsql_cond_rewrite.h"
#include "ogsql_optim_common.h"
#include "ogsql_predicate_deliver.h"
#include "ogsql_func.h"

static inline bool32 is_arithmetic_op(expr_node_type_t node_type)
{
    return node_type == EXPR_NODE_ADD || node_type == EXPR_NODE_SUB || node_type == EXPR_NODE_MUL ||
        node_type == EXPR_NODE_DIV || node_type == EXPR_NODE_MOD || node_type == EXPR_NODE_CAT ||
        node_type == EXPR_NODE_BITAND || node_type == EXPR_NODE_BITOR || node_type == EXPR_NODE_BITXOR ||
        node_type == EXPR_NODE_LSHIFT || node_type == EXPR_NODE_RSHIFT;
}

static inline bool32 is_arithmetic_or_bitwise_op(expr_node_type_t node_type)
{
    return node_type == EXPR_NODE_ADD || node_type == EXPR_NODE_SUB || node_type == EXPR_NODE_MUL ||
        node_type == EXPR_NODE_DIV || node_type == EXPR_NODE_MOD || node_type == EXPR_NODE_BITAND ||
        node_type == EXPR_NODE_BITOR || node_type == EXPR_NODE_BITXOR || node_type == EXPR_NODE_LSHIFT ||
        node_type == EXPR_NODE_RSHIFT;
}

typedef struct st_join_filter_helper {
    sql_join_node_t *join_node;
    bool32 is_right;
    bool32 right_in_outer;
    bool32 l_reject_null;
    bool32 r_reject_null;
} join_filter_helper_t;

static inline bool32 og_is_buildin_cond_func(uint32 builtin_func_id)
{
    return builtin_func_id== ID_FUNC_ITEM_IF || builtin_func_id == ID_FUNC_ITEM_LNNVL;
}

static inline bool32 og_is_true_cond(struct st_cond_tree *cond_tree)
{
    return cond_tree == NULL || cond_tree->root == NULL || cond_tree->root->type == COND_NODE_TRUE;
}

static void init_col_check_visit_assist(column_check_helper_t *col_chk_helper, sql_array_t *l_tbls, bool32 *exists_col,
                                 bool32 is_right)
{
    CM_POINTER2(l_tbls, exists_col);
    if (col_chk_helper == NULL) {
        return;
    }

    col_chk_helper->l_tbls = l_tbls;
    col_chk_helper->exists_col = exists_col;
    col_chk_helper->is_right = is_right;
}

static void init_value_check_visit_assist(value_check_helper_t *val_chk_helper, sql_array_t *l_tbls,
    sql_array_t *p_tbls, sql_join_type_t join_type, bool32 is_right)
{
    CM_POINTER2(l_tbls, p_tbls);
    if (val_chk_helper == NULL) {
        return;
    }

    val_chk_helper->l_tbls = l_tbls;
    val_chk_helper->p_tbls = p_tbls;
    val_chk_helper->join_type = join_type;
    val_chk_helper->is_right = is_right;
}

static inline bool32 check_expr_tree_is_filter_col(expr_tree_t *exprtr, column_check_helper_t *col_chk_helper);
static inline bool32 check_expr_tree_is_filter_value(expr_tree_t *exprtr, value_check_helper_t *val_chk_helper);
static status_t og_update_col_in_exprn(visit_assist_t *v_ast, expr_node_t **exprn);

static bool32 check_cond_is_filter_col(cond_node_t *cond, column_check_helper_t *col_chk_helper)
{
    CM_POINTER(col_chk_helper);
    if (cond == NULL) {
        return OG_TRUE;
    }

    if (cond->type == COND_NODE_COMPARE) {
        if (cond->cmp->type != CMP_TYPE_IS_NULL) {
            return (check_expr_tree_is_filter_col(cond->cmp->left, col_chk_helper) &&
                check_expr_tree_is_filter_col(cond->cmp->right, col_chk_helper));
        }
        return OG_FALSE;
    }

    if (cond->type == COND_NODE_OR || COND_NODE_AND) {
        return (check_cond_is_filter_col(cond->left, col_chk_helper) &&
                check_cond_is_filter_col(cond->right, col_chk_helper));
    }

    return OG_FALSE;
}

static bool32 check_reserved_is_filter_col(expr_node_t *exprn, column_check_helper_t *col_chk_helper)
{
    CM_POINTER2(col_chk_helper, exprn);
    if (NODE_IS_RES_ROWID(exprn) && ROWID_NODE_ANCESTOR(exprn) == 0) {
        OG_RETVALUE_IFTRUE(!sql_table_in_list(col_chk_helper->l_tbls, ROWID_NODE_TAB(exprn)), OG_FALSE);
        *col_chk_helper->exists_col = OG_TRUE;
    }
    return OG_TRUE;
}

static bool32 check_column_is_filter_col(expr_node_t *exprn, column_check_helper_t *col_chk_helper)
{
    CM_POINTER2(col_chk_helper, exprn);
    if (NODE_ANCESTOR(exprn) == 0) {
        OG_RETVALUE_IFTRUE(!sql_table_in_list(col_chk_helper->l_tbls, NODE_TAB(exprn)), OG_FALSE);
        *col_chk_helper->exists_col = OG_TRUE;
    }
    return OG_TRUE;
}

static bool32 check_case_pair_constraint(case_expr_t *expr, column_check_helper_t *col_chk_helper, uint32 index)
{
    CM_POINTER2(col_chk_helper, expr);
    case_pair_t *pair = (case_pair_t *)cm_galist_get(&expr->pairs, index);
    if (expr->is_cond) {
        OG_RETVALUE_IFTRUE(!check_cond_is_filter_col(pair->when_cond->root, col_chk_helper), OG_FALSE);
    } else {
        OG_RETVALUE_IFTRUE(!check_expr_tree_is_filter_col(pair->when_expr, col_chk_helper), OG_FALSE);
    }
    OG_RETVALUE_IFTRUE(!check_expr_tree_is_filter_col(pair->value, col_chk_helper), OG_FALSE);
    return OG_TRUE;
}

static bool32 check_case_is_filter_col(expr_node_t *exprn, column_check_helper_t *col_chk_helper)
{
    CM_POINTER2(col_chk_helper, exprn);

    OG_RETVALUE_IFTRUE(col_chk_helper->is_right, OG_FALSE);

    case_expr_t *case_item = (case_expr_t *)exprn->value.v_pointer;
    if (!case_item->is_cond && !check_expr_tree_is_filter_col(case_item->expr, col_chk_helper)) {
        return OG_FALSE;
    }

    for (uint32 pair_idx = 0; pair_idx < case_item->pairs.count; pair_idx++) {
        OG_RETVALUE_IFTRUE(!check_case_pair_constraint(case_item, col_chk_helper, pair_idx), OG_FALSE);
    }

    OG_RETVALUE_IFTRUE(case_item->default_expr == NULL, OG_TRUE);
    return check_expr_tree_is_filter_col(case_item->default_expr, col_chk_helper);
}

static bool32 check_filter_col_func_rule1(sql_func_t *sql_func, expr_node_t *exprn,
    column_check_helper_t *col_chk_helper)
{
    CM_POINTER3(col_chk_helper, exprn, sql_func);
    OG_RETVALUE_IFTRUE(exprn->cond_arg == NULL, OG_TRUE);
    OG_RETVALUE_IFTRUE(sql_func->builtin_func_id != ID_FUNC_ITEM_IF &&
        sql_func->builtin_func_id != ID_FUNC_ITEM_LNNVL, OG_TRUE);
    return check_cond_is_filter_col(exprn->cond_arg->root, col_chk_helper);
}

static bool32 check_filter_col_func_rule2(expr_node_t *exprn, column_check_helper_t *col_chk_helper)
{
    CM_POINTER2(col_chk_helper, exprn);
    OG_RETVALUE_IFTRUE(!check_func_with_sort_items(exprn), OG_TRUE);
    
    sort_item_t *item = NULL;
    uint32 item_idx = 0;
    while (item_idx < exprn->sort_items->count) {
        item = (sort_item_t *)cm_galist_get(exprn->sort_items, item_idx++);
        OG_RETVALUE_IFTRUE(!check_expr_tree_is_filter_col(item->expr, col_chk_helper), OG_FALSE);
    }
    return OG_TRUE;
}

static bool32 check_expr_node_is_filter_col(expr_node_t *exprn, column_check_helper_t *col_chk_helper);
static bool32 check_func_is_filter_col(expr_node_t *exprn, column_check_helper_t *col_chk_helper)
{
    CM_POINTER2(col_chk_helper, exprn);
    OG_RETVALUE_IFTRUE(col_chk_helper->is_right, OG_FALSE);
    sql_func_t *sql_func = sql_get_func(&exprn->value.v_func);
    for (expr_tree_t *arg_exprtr = exprn->argument;
        arg_exprtr != NULL;
        arg_exprtr = arg_exprtr->next) {
        OG_RETVALUE_IFTRUE(!check_expr_node_is_filter_col(arg_exprtr->root, col_chk_helper), OG_FALSE);
    }
    OG_RETVALUE_IFTRUE(!check_filter_col_func_rule1(sql_func, exprn, col_chk_helper), OG_FALSE);
    OG_RETVALUE_IFTRUE(!check_filter_col_func_rule2(exprn, col_chk_helper), OG_FALSE);
    return OG_TRUE;
}

static bool32 check_expr_node_is_filter_col(expr_node_t *exprn, column_check_helper_t *col_chk_helper)
{
    CM_POINTER2(col_chk_helper, exprn);
    if (is_arithmetic_or_bitwise_op(exprn->type)) {
        return (check_expr_node_is_filter_col(exprn->left, col_chk_helper) &&
                check_expr_node_is_filter_col(exprn->right, col_chk_helper));
    }

    if (exprn->type == EXPR_NODE_COLUMN || exprn->type == EXPR_NODE_TRANS_COLUMN) {
        return check_column_is_filter_col(exprn, col_chk_helper);
    }

    if (exprn->type == EXPR_NODE_CASE) {
        return check_case_is_filter_col(exprn, col_chk_helper);
    }

    if (exprn->type == EXPR_NODE_FUNC) {
        return check_func_is_filter_col(exprn, col_chk_helper);
    }

    if (exprn->type == EXPR_NODE_RESERVED) {
        return check_reserved_is_filter_col(exprn, col_chk_helper);
    }

    if (exprn->type == EXPR_NODE_NEGATIVE) {
        return check_expr_node_is_filter_col(exprn->right, col_chk_helper);
    }

    if (exprn->type == EXPR_NODE_V_METHOD ||
        exprn->type == EXPR_NODE_USER_FUNC ||
        exprn->type == EXPR_NODE_V_CONSTRUCT ||
        exprn->type == EXPR_NODE_PRIOR ||
        exprn->type == EXPR_NODE_SELECT ||
        exprn->type == EXPR_NODE_ARRAY ||
        exprn->type == EXPR_NODE_CAT) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_expr_tree_is_filter_col(expr_tree_t *exprtr, column_check_helper_t *col_chk_helper)
{
    CM_POINTER(col_chk_helper);
    for (expr_tree_t *current = exprtr; current != NULL; current = current->next) {
        if (!check_expr_node_is_filter_col(current->root, col_chk_helper)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static inline bool32 check_filter_col_node(expr_tree_t *exprtr, sql_array_t *l_tbls, bool32 is_right)
{
    CM_POINTER2(exprtr, l_tbls);
    bool32 exists_col = OG_FALSE;
    column_check_helper_t col_chk_helper;
    init_col_check_visit_assist(&col_chk_helper, l_tbls, &exists_col, is_right);
    return (check_expr_tree_is_filter_col(exprtr, &col_chk_helper) && exists_col);
}

static bool32 check_filter_value_column(expr_node_t *exprn, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(exprn, val_chk_helper);
    OG_RETVALUE_IFTRUE(NODE_ANCESTOR(exprn) > 0, OG_TRUE);
    OG_RETVALUE_IFTRUE(sql_table_in_list(val_chk_helper->l_tbls, NODE_TAB(exprn)), OG_TRUE);
    OG_RETVALUE_IFTRUE(!val_chk_helper->is_right, OG_FALSE);
    OG_RETVALUE_IFTRUE(val_chk_helper->join_type == JOIN_TYPE_FULL, OG_FALSE);
    return sql_table_in_list(val_chk_helper->p_tbls, NODE_TAB(exprn));
}

static bool32 check_filter_value_reserved(expr_node_t *exprn, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(exprn, val_chk_helper);
    OG_RETVALUE_IFTRUE(chk_if_reserved_word_constant(exprn->value.v_res.res_id), OG_TRUE);
    OG_RETVALUE_IFTRUE(exprn->value.v_res.res_id != RES_WORD_ROWID, OG_FALSE);
    OG_RETVALUE_IFTRUE(ROWID_NODE_ANCESTOR(exprn) > 0, OG_TRUE);
    OG_RETVALUE_IFTRUE(sql_table_in_list(val_chk_helper->l_tbls, ROWID_NODE_TAB(exprn)), OG_TRUE);
    OG_RETVALUE_IFTRUE(!val_chk_helper->is_right, OG_FALSE);
    OG_RETVALUE_IFTRUE(val_chk_helper->join_type == JOIN_TYPE_FULL, OG_FALSE);
    return sql_table_in_list(val_chk_helper->p_tbls, ROWID_NODE_TAB(exprn));
}

static bool32 check_cond_is_filter_value(cond_node_t *cond, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(cond, val_chk_helper);

    if (cond->type == COND_NODE_COMPARE) {
        cmp_node_t *cmp = cond->cmp;
        OG_RETVALUE_IFTRUE(cmp->type == CMP_TYPE_IS_NULL, OG_FALSE);
        return (check_expr_tree_is_filter_value(cmp->left, val_chk_helper) &&
                check_expr_tree_is_filter_value(cmp->right, val_chk_helper));
    }

    if (cond->type == COND_NODE_AND || cond->type == COND_NODE_OR) {
        return (check_cond_is_filter_value(cond->left, val_chk_helper) &&
                check_cond_is_filter_value(cond->right, val_chk_helper));
    }
    return OG_TRUE;
}

static bool32 check_filter_value_func(expr_node_t *exprn, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(exprn, val_chk_helper);
    OG_RETVALUE_IFTRUE(!check_expr_tree_is_filter_value(exprn->argument, val_chk_helper), OG_FALSE);
    sql_func_t *sql_func = sql_get_func(&exprn->value.v_func);
    OG_RETVALUE_IFTRUE(!og_is_buildin_cond_func(sql_func->builtin_func_id) || exprn->cond_arg == NULL, OG_TRUE);
    return check_cond_is_filter_value(exprn->cond_arg->root, val_chk_helper);
}

static inline bool32 check_filter_value_subslct(expr_node_t *exprn)
{
    CM_POINTER(exprn);
    sql_select_t *slct = (sql_select_t *)VALUE_PTR(var_object_t, &exprn->value)->ptr;
    select_type_t type = slct->type;
    if (type != SELECT_AS_VARIANT && type != SELECT_AS_LIST) {
        return OG_FALSE;
    }
    return slct->parent_refs->count == 0;
}

static bool32 check_value_case_constraint(case_expr_t *case_item, uint32 i, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(case_item, val_chk_helper);
    case_pair_t *c_pair = (case_pair_t *)cm_galist_get(&case_item->pairs, i);
    if (!case_item->is_cond) {
        return check_expr_tree_is_filter_value(c_pair->when_expr, val_chk_helper) &&
            check_expr_tree_is_filter_value(c_pair->value, val_chk_helper);
    }
    return check_cond_is_filter_value(c_pair->when_cond->root, val_chk_helper) &&
        check_expr_tree_is_filter_value(c_pair->value, val_chk_helper);
}

static bool32 check_filter_value_case(expr_node_t *exprn, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(exprn, val_chk_helper);
    case_expr_t *case_item = (case_expr_t *)exprn->value.v_pointer;
    if (!case_item->is_cond && !check_expr_tree_is_filter_value(case_item->expr, val_chk_helper)) {
        return OG_FALSE;
    }

    uint32 idx = 0;
    while (idx < case_item->pairs.count) {
        OG_RETVALUE_IFTRUE(!check_value_case_constraint(case_item, idx++, val_chk_helper), OG_FALSE);
    }

    return case_item->default_expr == NULL ||
        check_expr_tree_is_filter_value(case_item->default_expr, val_chk_helper);
}

static bool32 check_filter_value_expr_node(expr_node_t *exprn, value_check_helper_t *val_chk_helper)
{
    CM_POINTER2(exprn, val_chk_helper);
    if (is_arithmetic_op(exprn->type)) {
        return (check_filter_value_expr_node(exprn->left, val_chk_helper) &&
                check_filter_value_expr_node(exprn->right, val_chk_helper));
    }

    if (exprn->type == EXPR_NODE_NEGATIVE) {
        return check_filter_value_expr_node(exprn->right, val_chk_helper);
    }

    if (exprn->type == EXPR_NODE_RESERVED) {
        return check_filter_value_reserved(exprn, val_chk_helper);
    }

    if (exprn->type == EXPR_NODE_COLUMN || exprn->type == EXPR_NODE_TRANS_COLUMN) {
        return check_filter_value_column(exprn, val_chk_helper);
    }

    if (exprn->type == EXPR_NODE_SELECT) {
        return check_filter_value_subslct(exprn);
    }

    if (exprn->type == EXPR_NODE_FUNC) {
        return check_filter_value_func(exprn, val_chk_helper);
    }

    if (exprn->type == EXPR_NODE_CASE) {
        return check_filter_value_case(exprn, val_chk_helper);
    }

    if (exprn->type == EXPR_NODE_V_ADDR) {
        return sql_pair_type_is_plvar(exprn);
    }

    if (exprn->type == EXPR_NODE_PL_ATTR ||
        exprn->type == EXPR_NODE_CONST ||
        exprn->type == EXPR_NODE_CSR_PARAM ||
        exprn->type == EXPR_NODE_SEQUENCE ||
        exprn->type == EXPR_NODE_PARAM ||
        exprn->type == EXPR_NODE_PRIOR) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 check_expr_tree_is_filter_value(expr_tree_t *exprtr, value_check_helper_t *val_chk_helper)
{
    CM_POINTER(val_chk_helper);
    for (expr_tree_t *node = exprtr; node != NULL; node = node->next) {
        if (!check_filter_value_expr_node(node->root, val_chk_helper)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

typedef struct st_cmp_chk_input {
    cmp_node_t *cmp;
    expr_tree_t *target_expr;
    expr_tree_t *opposite;
    sql_array_t *l_tbls;
    sql_array_t *p_tbls;
} cmp_chk_input_t;

static void check_cmp_node_reject_null(cmp_node_t *node, expr_tree_t *target_expr,
    expr_tree_t *opposite, bool32 *reject_null)
{
    if (!node->anti_join_cond && target_expr->root->type != EXPR_NODE_TRANS_COLUMN &&
        opposite->root->type != EXPR_NODE_SELECT) {
        *reject_null = OG_TRUE;
    }
}

static bool32 check_cmp_node_col_constraint(expr_tree_t *opposite, sql_array_t *l_tbls, sql_array_t *p_tbls,
    sql_join_type_t join_type, bool32 is_right)
{
    value_check_helper_t val_chk_helper = { 0 };
    init_value_check_visit_assist(&val_chk_helper, l_tbls, p_tbls, join_type, is_right);
    return check_expr_tree_is_filter_value(opposite, &val_chk_helper);
}

static bool32 check_is_filter_cmp_node(cmp_node_t *cmp, join_filter_helper_t *jf_helper, bool32 *reject_null)
{
    CM_POINTER3(cmp, jf_helper, reject_null);
    sql_join_node_t *jnode = jf_helper->join_node;
    bool32 is_rnode = jf_helper->is_right;
    sql_array_t *l_tbls = &jnode->right->tables;
    sql_array_t *p_tbls = &jnode->left->tables;
    if (!is_rnode) {
        l_tbls = &jnode->left->tables;
        p_tbls = &jnode->right->tables;
    }

    sql_join_type_t join_type = jnode->type;
    if (check_filter_col_node(cmp->left, l_tbls, jf_helper->right_in_outer)) {
        check_cmp_node_reject_null(cmp, cmp->left, cmp->right, reject_null);
        return check_cmp_node_col_constraint(cmp->right, l_tbls, p_tbls, join_type,
                                             is_rnode);
    }

    if (cmp->type <= CMP_TYPE_NOT_EQUAL) {
        if (check_filter_col_node(cmp->right, l_tbls, jf_helper->right_in_outer)) {
            check_cmp_node_reject_null(cmp, cmp->right, cmp->left, reject_null);
            return check_cmp_node_col_constraint(cmp->left, l_tbls, p_tbls, join_type,
                                                is_rnode);
        }
    }
    return OG_FALSE;
}

static bool32 og_check_cmp_reject_null(cmp_node_t *cmp_node, join_filter_helper_t *jf_helper, bool32 *reject_null)
{
    CM_POINTER3(cmp_node, jf_helper, reject_null);
    sql_array_t *l_tbls = &jf_helper->join_node->left->tables;
    bool32 exists_col = OG_FALSE;
    bool32 is_expr_node = OG_FALSE;
    if (jf_helper->is_right) {
        l_tbls = &jf_helper->join_node->right->tables;
    }

    if (cmp_node->type == CMP_TYPE_IS_NULL && jf_helper->right_in_outer) {
        return OG_FALSE;
    }

    if (cmp_node->type == CMP_TYPE_IS_NULL || cmp_node->type == CMP_TYPE_IS_NOT_NULL) {
        // Check whether left of compare node exists in join node
        column_check_helper_t col_chk_helper;
        init_col_check_visit_assist(&col_chk_helper, l_tbls, &exists_col, jf_helper->right_in_outer);
        is_expr_node = check_expr_tree_is_filter_col(cmp_node->left, &col_chk_helper);
        return is_expr_node && exists_col;
    }

    if (cmp_node->type == CMP_TYPE_LESS_ALL ||
        cmp_node->type == CMP_TYPE_LESS_EQUAL_ALL ||
        cmp_node->type == CMP_TYPE_EQUAL_ALL ||
        cmp_node->type == CMP_TYPE_NOT_EQUAL_ALL ||
        cmp_node->type == CMP_TYPE_GREAT_ALL ||
        cmp_node->type == CMP_TYPE_GREAT_EQUAL_ALL ||
        cmp_node->type == CMP_TYPE_IS_JSON ||
        cmp_node->type == CMP_TYPE_IS_NOT_JSON ||
        cmp_node->type == CMP_TYPE_EXISTS ||
        cmp_node->type == CMP_TYPE_NOT_EXISTS) {
        return OG_FALSE;
    }

    if (cmp_node->type == CMP_TYPE_NOT_IN) {
        if (TREE_EXPR_TYPE(cmp_node->right) == EXPR_NODE_SELECT && cmp_node->right->next == NULL) {
            return OG_FALSE;
        }
    }

    return check_is_filter_cmp_node(cmp_node, jf_helper, reject_null);
}

static bool32 check_single_cond_reject_null(sql_stmt_t *statement, cond_node_t *cond_node,
    join_filter_helper_t *jf_helper, bool32 *reject_null)
{
    CM_POINTER4(statement, cond_node, jf_helper, reject_null);
    OG_RETURN_IFERR(sql_stack_safe(statement));

    if (cond_node->type == COND_NODE_COMPARE) {
        return og_check_cmp_reject_null(cond_node->cmp, jf_helper, reject_null);
    }

    if (cond_node->type == COND_NODE_OR || cond_node->type == COND_NODE_AND) {
        bool32 l_reject_null = OG_FALSE;
        bool32 left_cond_result = check_single_cond_reject_null(statement,
            cond_node->left, jf_helper, &l_reject_null);
        bool32 r_reject_null = OG_FALSE;
        bool32 right_cond_result = check_single_cond_reject_null(statement,
            cond_node->right, jf_helper, &r_reject_null);
        if (cond_node->type == COND_NODE_AND) {
            *reject_null = l_reject_null || r_reject_null;
        } else {
            *reject_null = l_reject_null && r_reject_null;
        }
        return (left_cond_result && right_cond_result);
    }

    return OG_FALSE;
}

static status_t check_null_reject_on_cond_tree(sql_stmt_t *statement, cond_node_t *cond_node, bool32 *reject_null,
                                             join_filter_helper_t *jf_helper)
{
    CM_POINTER4(statement, cond_node, jf_helper, reject_null);
    OG_RETURN_IFERR(sql_stack_safe(statement));
    if (cond_node->type == COND_NODE_AND) {
        bool32 l_reject_null = OG_FALSE;
        bool32 r_reject_null = OG_FALSE;
        OG_RETURN_IFERR(check_null_reject_on_cond_tree(statement, cond_node->left, &l_reject_null, jf_helper));
        OG_RETURN_IFERR(check_null_reject_on_cond_tree(statement, cond_node->right, &r_reject_null, jf_helper));
        if (l_reject_null || r_reject_null) {
            *reject_null = OG_TRUE;
        } else {
            *reject_null = OG_FALSE;
        }
        try_eval_logic_and(cond_node);
        return OG_SUCCESS;
    }

    if (cond_node->type == COND_NODE_OR || cond_node->type == COND_NODE_COMPARE) {
        if (!check_single_cond_reject_null(statement, cond_node, jf_helper, reject_null)) {
            return OG_SUCCESS;
        }

        *reject_null = OG_TRUE;
        cond_node->reject_null = OG_TRUE;

        if (jf_helper->join_node->filter == NULL) {
            OG_RETURN_IFERR(sql_create_cond_tree(statement->context, &jf_helper->join_node->filter));
        }
        OG_RETURN_IFERR(sql_merge_cond_tree_shallow(jf_helper->join_node->filter, cond_node));
        cond_node->type = COND_NODE_TRUE;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t try_check_null_reject_on_cond_tree(sql_stmt_t *statement, cond_tree_t *src,
                                                   join_filter_helper_t *jf_helper, bool32 outer_join_right)
{
    CM_POINTER3(statement, src, jf_helper);
    bool32 l_outer_join_right = jf_helper->join_node->type == JOIN_TYPE_FULL ? OG_TRUE : outer_join_right;
    bool32 r_outer_join_right = jf_helper->join_node->type >= JOIN_TYPE_LEFT ? OG_TRUE : outer_join_right;
    jf_helper->is_right = OG_FALSE;
    jf_helper->right_in_outer = l_outer_join_right;
    OG_RETURN_IFERR(check_null_reject_on_cond_tree(statement, src->root, &jf_helper->l_reject_null, jf_helper));
    jf_helper->is_right = OG_TRUE;
    jf_helper->right_in_outer = r_outer_join_right;
    return check_null_reject_on_cond_tree(statement, src->root, &jf_helper->r_reject_null, jf_helper);
}

static status_t check_null_reject_and_transform(sql_stmt_t *statement, cond_tree_t *tree, sql_join_node_t *jnode,
                                                sql_join_assist_t *j_ast, bool32 outer_join_right)
{
    CM_POINTER4(statement, tree, jnode, j_ast);
    join_filter_helper_t jf_helper;
    jf_helper.join_node = jnode;
    jf_helper.l_reject_null = OG_FALSE; // join node on left will not complete null value
    jf_helper.r_reject_null = OG_FALSE; // join node on left will not complete null value

    if (tree != NULL) {
        OG_RETURN_IFERR(try_check_null_reject_on_cond_tree(statement, tree, &jf_helper, outer_join_right));
    }
    // try convert right or full to left
    if (jf_helper.l_reject_null && jnode->type > JOIN_TYPE_LEFT) {
        jnode->type = JOIN_TYPE_LEFT;
        if (jnode->oper == JOIN_OPER_HASH_FULL) {
            jnode->oper = JOIN_OPER_HASH_LEFT;
        } else {
            jnode->oper = JOIN_OPER_NL_LEFT;
        }
    }
    // try convert left to inner
    if (jf_helper.r_reject_null && jnode->type == JOIN_TYPE_LEFT) {
        jnode->type = JOIN_TYPE_INNER;
        if (jnode->oper == JOIN_OPER_HASH_LEFT) {
            jnode->oper = JOIN_OPER_HASH;
        } else {
            jnode->oper = JOIN_OPER_NL;
        }
        j_ast->outer_node_count--;
    }

    if (jf_helper.r_reject_null && jnode->type > JOIN_TYPE_LEFT) {
        jnode->type = JOIN_TYPE_LEFT;
        if (jnode->oper == JOIN_OPER_HASH_FULL) {
            jnode->oper = JOIN_OPER_HASH_LEFT;
        } else {
            jnode->oper = JOIN_OPER_NL_LEFT;
        }
        SWAP(sql_join_node_t *, jnode->left, jnode->right);
    }

    return OG_SUCCESS;
}

static status_t og_adjust_cond_when_has_out_join(sql_stmt_t *statement, sql_query_t *qry, sql_join_assist_t *j_ast)
{
    CM_POINTER3(statement, qry, j_ast);

    OG_RETSUC_IFTRUE(qry->tables.count <= 1);
    OG_RETSUC_IFTRUE(qry->cond == NULL);
    OG_RETSUC_IFTRUE(qry->join_assist.outer_node_count == 0);

    if (qry->cond->root->type == COND_NODE_TRUE) {
        qry->cond = NULL;
        return OG_SUCCESS;
    }

    if (qry->filter_cond == NULL) {
        qry->filter_cond = qry->cond;
    } else {
        OG_RETURN_IFERR(sql_add_cond_node(qry->filter_cond, qry->cond->root));
    }
    qry->cond = NULL;
    return OG_SUCCESS;
}

static bool32 winsort_has_dedup(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    winsort_func_t *w_func = NULL;
    expr_node_t *exprn = NULL;
    expr_node_t *func_exprn = NULL;
    uint32 winsort_idx = 0;
    while (winsort_idx < qry->winsort_list->count) {
        exprn = (expr_node_t *)cm_galist_get(qry->winsort_list, winsort_idx++);
        // Ordered or framed windows are sensitive to the number of input rows.
        OG_RETVALUE_IFTRUE(exprn->win_args->sort_items != NULL || exprn->win_args->windowing != NULL, OG_FALSE);
        func_exprn = exprn->argument->root;
        w_func = sql_get_winsort_func(&func_exprn->value.v_func);
        OG_CONTINUE_IFTRUE(func_exprn->dis_info.need_distinct);
        OG_CONTINUE_IFTRUE(cm_text_str_equal_ins(&w_func->name, "MAX"));
        OG_CONTINUE_IFTRUE(cm_text_str_equal_ins(&w_func->name, "MIN"));
        return OG_FALSE;
    }
    return OG_TRUE;
}

static status_t check_volatile_expr_node(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_t *origin_exprn = sql_get_origin_ref(*exprn);
    if (origin_exprn != *exprn) {
        return visit_expr_node(v_ast, &origin_exprn, check_volatile_expr_node);
    }

    if (origin_exprn->type == EXPR_NODE_FUNC) {
        sql_func_t *sql_func = sql_get_func(&origin_exprn->value.v_func);
        // Only ordinary built-ins are repeatable from their arguments; RAND is evaluated per row.
        if (origin_exprn->value.v_func.pack_id == OG_INVALID_ID32 && sql_func->options == FO_NORMAL &&
            sql_func->builtin_func_id != ID_FUNC_ITEM_RAND) {
            return visit_func_node(v_ast, origin_exprn, check_volatile_expr_node);
        }
    } else if (origin_exprn->type == EXPR_NODE_CONST || origin_exprn->type == EXPR_NODE_PARAM ||
               origin_exprn->type == EXPR_NODE_COLUMN || origin_exprn->type == EXPR_NODE_TRANS_COLUMN ||
               origin_exprn->type == EXPR_NODE_DIRECT_COLUMN || origin_exprn->type == EXPR_NODE_RESERVED) {
        return OG_SUCCESS;
    }

    v_ast->result0 = OG_TRUE;
    return OG_SUCCESS;
}

static bool32 check_distinct_volatile_args(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, qry);
    v_ast.excl_flags = VA_EXCL_FUNC | VA_EXCL_PROC | VA_EXCL_PRIOR | VA_EXCL_ARRAY;
    rs_column_t *col = NULL;
    galist_t *col_lst = qry->rs_columns;
    if (qry->has_distinct) {
        col_lst = qry->distinct_columns;
    }
    uint32 col_idx = 0;
    while (col_idx < col_lst->count) {
        col = (rs_column_t *)cm_galist_get(col_lst, col_idx++);
        OG_CONTINUE_IFTRUE(col->type != RS_COL_CALC);
        v_ast.result0 = OG_FALSE;
        OG_RETVALUE_IFTRUE(visit_expr_tree(&v_ast, col->expr, check_volatile_expr_node) != OG_SUCCESS ||
            v_ast.result0, OG_TRUE);
    }
    return OG_FALSE;
}

static bool32 aggr_has_dedup(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    sql_func_t *sql_func = NULL;
    expr_node_t *exprn = NULL;
    uint32 aggr_idx = 0;
    while (aggr_idx < qry->aggrs->count) {
        exprn = (expr_node_t *)cm_galist_get(qry->aggrs, aggr_idx++);
        sql_func = sql_get_func(&exprn->value.v_func);
        OG_CONTINUE_IFTRUE(exprn->dis_info.need_distinct);
        OG_CONTINUE_IFTRUE(sql_func->builtin_func_id == ID_FUNC_ITEM_MAX);
        OG_CONTINUE_IFTRUE(sql_func->builtin_func_id == ID_FUNC_ITEM_MIN);
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 qry_has_dedup(sql_stmt_t *statement, sql_query_t *qry, bool32 has_dist)
{
    CM_POINTER2(statement, qry);

    OG_RETVALUE_IFTRUE(QUERY_HAS_ROWNUM(qry), OG_FALSE);
    OG_RETVALUE_IFTRUE(qry->group_sets->count > 1, OG_FALSE);
    OG_RETVALUE_IFTRUE(qry->aggrs->count > 0 && !aggr_has_dedup(statement, qry), OG_FALSE);
    OG_RETVALUE_IFTRUE(qry->group_sets->count > 0, OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->aggrs->count > 0, OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->winsort_list->count > 0 && !winsort_has_dedup(statement, qry), OG_FALSE);
    OG_RETVALUE_IFTRUE(!has_dist, OG_FALSE);
    return !check_distinct_volatile_args(statement, qry);
}

static inline bool32 is_simp_slct(select_node_t *slct_node)
{
    return slct_node->type == SELECT_NODE_QUERY;
}

static inline bool32 slct_has_dedup(select_node_t *slct_node)
{
    return slct_node->type == SELECT_NODE_UNION ||
        slct_node->type == SELECT_NODE_MINUS ||
        slct_node->type == SELECT_NODE_EXCEPT ||
        slct_node->type == SELECT_NODE_INTERSECT;
}

static bool32 og_check_elimination_by_distinct(sql_stmt_t *statement, select_node_t *slct_node, sql_query_t *qry,
                                                  bool32 has_dup)
{
    CM_POINTER3(statement, slct_node, qry);
    if (is_simp_slct(slct_node)) {
        bool32 has_distinct = slct_node->query == qry && (qry->has_distinct || has_dup);
        return qry_has_dedup(statement, qry, has_distinct);
    }

    if (slct_has_dedup(slct_node)) {
        has_dup = OG_TRUE;
    }

    return og_check_elimination_by_distinct(statement, slct_node->left, qry, has_dup) ||
            og_check_elimination_by_distinct(statement, slct_node->right, qry, has_dup);
}

static status_t og_visit_update_pairs(visit_assist_t *v_ast, visit_func_t visit_func)
{
    CM_POINTER2(v_ast, visit_func);
    column_value_pair_t *col_pair = NULL;
    expr_tree_t *exprtr = NULL;
    sql_update_t *sql_update = NULL;

    if (v_ast->stmt->context->type != OGSQL_TYPE_UPDATE) {
        return OG_SUCCESS;
    }
    sql_update = (sql_update_t *)v_ast->stmt->context->entry;
    if (v_ast->query != sql_update->query) {
        return OG_SUCCESS;
    }

    col_pair = cm_galist_get(sql_update->pairs, 0);
    if (PAIR_IN_MULTI_SET(col_pair)) {
        exprtr = (expr_tree_t *)cm_galist_get(col_pair->exprs, 0);
        return visit_expr_node(v_ast, &exprtr->root, visit_func);
    }

    for (uint32 i = 0; i < sql_update->pairs->count; i++) {
        col_pair = (column_value_pair_t *)cm_galist_get(sql_update->pairs, i);
        for (uint32 j = 0; j < col_pair->exprs->count; j++) {
            exprtr = (expr_tree_t *)cm_galist_get(col_pair->exprs, j);
            OG_RETURN_IFERR(visit_expr_node(v_ast, &exprtr->root, visit_func));
        }
    }
    return OG_SUCCESS;
}

static void try_del_qry_col(query_field_t *qry_col, bilist_node_t *blst_node, bilist_t *blst)
{
    CM_POINTER(qry_col);
    qry_col->ref_count--;
    if (qry_col->ref_count == 0) {
        cm_bilist_del(blst_node, blst);
    }
}

static void og_uncache_qry_col(sql_query_t *qry, var_column_t *var_col)
{
    CM_POINTER2(var_col, qry);
    query_field_t *qry_col = NULL;
    sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, var_col->tab);
    bilist_node_t *blst_node = cm_bilist_head(&tbl->query_fields);
    do {
        OG_BREAK_IF_TRUE(blst_node == NULL);
        qry_col = BILIST_NODE_OF(query_field_t, blst_node, bilist_node);
        if (qry_col->col_id == var_col->col) {
            try_del_qry_col(qry_col, blst_node, &tbl->query_fields);
            break;
        }
        blst_node = blst_node->next;
    } while (OG_TRUE);
}

static status_t og_uncache_qry_flds(visit_assist_t *v_ast, expr_node_t **exprn)
{
    CM_POINTER2(v_ast, exprn);
    OG_RETSUC_IFTRUE(NODE_ANCESTOR(*exprn) > 0);
    OG_RETSUC_IFTRUE((*exprn)->type != EXPR_NODE_COLUMN);
    OG_RETSUC_IFTRUE(NODE_TAB(*exprn) == v_ast->result0);
    og_uncache_qry_col(v_ast->query, &(*exprn)->value.v_col);
    return OG_SUCCESS;
}

static bool32 is_same_table(biqueue_node_t *blst_node, uint32 tbl_id)
{
    CM_POINTER(blst_node);
    expr_node_t *exprn = OBJECT_OF(expr_node_t, blst_node);
    return TAB_OF_NODE(exprn) == tbl_id;
}

static bool32 is_same_column(biqueue_node_t *blst_node, uint32 tbl_id, uint32 col_id)
{
    CM_POINTER(blst_node);
    expr_node_t *exprn = OBJECT_OF(expr_node_t, blst_node);
    return TAB_OF_NODE(exprn) == tbl_id && COL_OF_NODE(exprn) == col_id;
}

static status_t og_delete_table_from_join_node(sql_join_node_t *jnode, uint32 del_tbl_id)
{
    CM_POINTER(jnode);
    OG_RETSUC_IFTRUE(jnode->type == JOIN_TYPE_NONE);

    OG_RETURN_IFERR(og_delete_table_from_join_node(jnode->left, del_tbl_id));
    OG_RETURN_IFERR(og_delete_table_from_join_node(jnode->right, del_tbl_id));

    uint32 tbl_idx = 0;
    while (tbl_idx < jnode->tables.count) {
        sql_table_t *tbl = (sql_table_t *)jnode->tables.items[tbl_idx++];
        OG_CONTINUE_IFTRUE(tbl->id != del_tbl_id);
        return sql_array_delete(&jnode->tables, tbl_idx-1);
    }
    return OG_SUCCESS;
}

static status_t og_update_node_group(visit_assist_t *v_ast, expr_node_t **exprn)
{
    CM_POINTER2(v_ast, exprn);
    OG_RETSUC_IFTRUE((*exprn)->value.v_vm_col.ancestor > 0);

    expr_node_t *origin_exprn = sql_get_origin_ref(*exprn);
    galist_t *lst = (galist_t *)v_ast->param0;

    uint32 exprn_idx = 0;
    expr_node_t *modified_node = NULL;
    while (exprn_idx < lst->count) {
        modified_node = (expr_node_t *)cm_galist_get(lst, exprn_idx++);
        OG_RETSUC_IFTRUE(modified_node == origin_exprn);
    }

    OG_RETURN_IFERR(cm_galist_insert(lst, origin_exprn));
    return visit_expr_node(v_ast, &origin_exprn, og_update_col_in_exprn);
}

static status_t og_update_col_in_exprn(visit_assist_t *v_ast, expr_node_t **exprn)
{
    CM_POINTER2(v_ast, exprn);
    if ((*exprn)->type == EXPR_NODE_COLUMN) {
        OG_RETSUC_IFTRUE(NODE_ANCESTOR(*exprn) > 0);
        OG_RETSUC_IFTRUE(NODE_TAB(*exprn) <= v_ast->result0);
        (*exprn)->value.v_col.tab--;
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_RESERVED) {
        OG_RETSUC_IFTRUE((*exprn)->value.v_int != RES_WORD_ROWID);
        OG_RETSUC_IFTRUE(ROWID_NODE_ANCESTOR(*exprn) > 0);
        OG_RETSUC_IFTRUE(ROWID_NODE_TAB(*exprn) <= v_ast->result0);
        (*exprn)->value.v_rid.tab_id--;
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_GROUP) {
        og_update_node_group(v_ast, exprn);
    }

    return OG_SUCCESS;
}

static status_t og_update_rs_column(visit_assist_t *v_ast, galist_t *col_lst)
{
    CM_POINTER2(v_ast, col_lst);
    rs_column_t *rs_col = NULL;
    uint32 col_idx = 0;
    while (col_idx < col_lst->count) {
        rs_col = (rs_column_t *)cm_galist_get(col_lst, col_idx++);
        if (rs_col->type == RS_COL_CALC) {
            OG_RETURN_IFERR(visit_expr_node(v_ast, &rs_col->expr->root, og_update_col_in_exprn));
            continue;
        }
        if (rs_col->v_col.tab > v_ast->result0) {
            rs_col->v_col.tab--;
        }
    }
    return OG_SUCCESS;
}

static status_t og_update_col_in_cond(visit_assist_t *v_ast, struct st_cond_tree *tree)
{
    OG_RETSUC_IFTRUE(tree == NULL);
    return visit_cond_node(v_ast, tree->root, og_update_col_in_exprn);
}

static status_t og_update_col_in_join_cond(visit_assist_t *v_ast, sql_join_node_t *join_node)
{
    OG_RETSUC_IFTRUE(join_node == NULL);
    return visit_join_node_cond(v_ast, join_node, og_update_col_in_exprn);
}

static status_t og_update_sort_item(visit_assist_t *v_ast, galist_t *sort_items)
{
    uint32 i = 0;
    while (i < sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(sort_items, i++);
        OG_RETURN_IFERR(visit_expr_node(v_ast, &item->expr->root, og_update_col_in_exprn));
    }
    return OG_SUCCESS;
}

static status_t og_update_aggr_col(visit_assist_t *v_ast, galist_t *aggrs)
{
    uint32 i = 0;
    while (i < aggrs->count) {
        expr_node_t *exprn = (expr_node_t *)cm_galist_get(aggrs, i++);
        OG_RETURN_IFERR(visit_expr_node(v_ast, &exprn, og_update_col_in_exprn));
    }
    return OG_SUCCESS;
}

static status_t og_update_table_id_in_columns(sql_query_t *qry, visit_assist_t *v_ast)
{
    CM_POINTER2(v_ast, qry);
    if (qry->has_distinct) {
        OG_RETURN_IFERR(og_update_rs_column(v_ast, qry->distinct_columns));
    }
    if (og_update_rs_column(v_ast, qry->rs_columns) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update rs_columns");
        return OG_ERROR;
    }

    if (og_update_col_in_cond(v_ast, qry->cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update cond");
        return OG_ERROR;
    }

    if (og_update_col_in_cond(v_ast, qry->filter_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update filter_cond");
        return OG_ERROR;
    }

    if (og_update_col_in_join_cond(v_ast, qry->join_assist.join_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update join_cond");
        return OG_ERROR;
    }

    if (og_update_col_in_cond(v_ast, qry->having_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update having_cond");
        return OG_ERROR;
    }

    if (og_update_col_in_cond(v_ast, qry->start_with_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update start_with_cond");
        return OG_ERROR;
    }

    if (og_update_col_in_cond(v_ast, qry->connect_by_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update connect_by_cond");
        return OG_ERROR;
    }

    if (og_update_sort_item(v_ast, qry->sort_items) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update sort_items");
        return OG_ERROR;
    }

    if (og_update_aggr_col(v_ast, qry->aggrs) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] failed to update aggrs");
        return OG_ERROR;
    }
    
    return og_visit_update_pairs(v_ast, og_update_col_in_exprn);
}

static status_t og_update_query_tables(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast, uint32 tbl_id)
{
    CM_POINTER3(v_ast, statement, qry);
    OG_RETSUC_IFTRUE(tbl_id == qry->tables.count);
    sql_table_t *tbl = NULL;
    uint32 tbl_idx = 0;
    while (tbl_idx < qry->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, tbl_idx++);
        if (tbl->id > tbl_id) {
            tbl->id--;
        }
    }
    return og_update_table_id_in_columns(qry, v_ast);
}

static status_t og_update_table_id(sql_query_t *qry, uint32 tbl_id, sql_join_node_t *jnode)
{
    CM_POINTER2(qry, jnode);
    sql_table_t *tbl = NULL;
    sql_table_t *dep_tbl = NULL;
    galist_t *deptbl_lst = NULL;
    
    uint32 i = 0;
    while (i < qry->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, i++);
        deptbl_lst = TABLE_CBO_DEP_TABLES(tbl);
        if (deptbl_lst == NULL || deptbl_lst->count == 0) {
            continue;
        }
        
        cm_galist_delete(deptbl_lst, tbl_id);
        uint32 j = tbl_id;
        while (j < deptbl_lst->count) {
            dep_tbl = (sql_table_t *)cm_galist_get(deptbl_lst, j++);
            dep_tbl->id--;
        }
    }
    *jnode = *jnode->left;
    qry->join_assist.outer_node_count--;
    return OG_SUCCESS;
}

static bool32 chk_all_conds_type_is_equal(cond_node_t *cond)
{
    CM_POINTER(cond);
    if (cond->type == COND_NODE_AND || cond->type == COND_NODE_OR) {
        return chk_all_conds_type_is_equal(cond->left) && chk_all_conds_type_is_equal(cond->right);
    }
    if (cond->type == COND_NODE_COMPARE) {
        return cond->cmp->type == CMP_TYPE_EQUAL;
    }
    return OG_FALSE;
}

static void collect_cols_in_cond(cond_node_t *cond, cols_used_t *cols)
{
    init_cols_used(cols);
    sql_collect_cols_in_cond(cond, cols);
}

static bool32 chk_tbl_uinq_idx_usable(sql_table_t *tbl, sql_join_node_t *jnode)
{
    CM_POINTER2(tbl, jnode);
    sql_init_table_indexable(tbl, NULL);

    uint32 idx_count = knl_get_index_count(tbl->entry->dc.handle);
    OG_RETVALUE_IFTRUE(idx_count == 0, OG_FALSE);

    cols_used_t cols;
    collect_cols_in_cond(jnode->join_cond->root, &cols);

    biqueue_t *cols_que = &cols.cols_que[SELF_IDX];
    biqueue_node_t *head = biqueue_first(cols_que);
    biqueue_node_t *end_node = biqueue_end(cols_que);
    biqueue_node_t *curr_node;
    if (head == NULL || head->next == NULL || head->next->next != end_node) {
        return OG_FALSE;
    }

    if (!chk_all_conds_type_is_equal(jnode->join_cond->root)) {
        return OG_FALSE;
    }

    if (is_same_table(head, tbl->id)) {
        curr_node = head;
    } else if (is_same_table(head->next, tbl->id)) {
        curr_node = head->next;
    } else {
        return OG_FALSE;
    }

    knl_index_desc_t *index = NULL;
    for (uint32 i = 0; i < idx_count; i++) {
        index = knl_get_index(tbl->entry->dc.handle, i);
        if (index->column_count != 1) {
            continue;
        }
        if (is_same_column(curr_node, tbl->id, index->columns[0]) &&
            (index->unique || index->primary)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static bool32 is_all_qry_col_in_cond(sql_join_node_t *jnode, sql_table_t *tbl)
{
    CM_POINTER2(tbl, jnode);
    cols_used_t cols;
    collect_cols_in_cond(jnode->join_cond->root, &cols);
    OG_RETVALUE_IFTRUE(HAS_SUBSLCT(&cols), OG_FALSE);

    query_field_t *field = NULL;
    knl_column_t *col;
    uint32 ref_count;
    dc_entity_t *tbl_ent = DC_ENTITY(&tbl->entry->dc);
    biqueue_t *cols_que = &cols.cols_que[SELF_IDX];
    biqueue_node_t *head_node = biqueue_first(cols_que);
    biqueue_node_t *end_node = biqueue_end(cols_que);
    bilist_node_t *field_node = NULL;
    biqueue_node_t *cur_node = NULL;
    for (field_node = cm_bilist_head(&tbl->query_fields); field_node != NULL; field_node = field_node->next) {
        field = BILIST_NODE_OF(query_field_t, field_node, bilist_node);
        col = dc_get_column(tbl_ent, field->col_id);
        ref_count = field->ref_count;
        for (cur_node = head_node; cur_node != end_node; cur_node = cur_node->next) {
            if (is_same_column(cur_node, tbl->id, col->id)) {
                ref_count--;
            }
            OG_BREAK_IF_TRUE(ref_count == 0);
        }
        OG_RETVALUE_IFTRUE(ref_count > 0, OG_FALSE);
    }
    return OG_TRUE;
}

static bool32 og_check_sub_tbl(sql_table_t *tbl)
{
    return tbl->type != SUBSELECT_AS_TABLE || tbl->select_ctx->parent_refs->count == 0;
}

static bool32 og_check_left_join_elimination_constraint(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode)
{
    CM_POINTER3(statement, qry, jnode);
    sql_table_t *r_tbl = TABLE_OF_JOIN_LEAF(jnode->right);

    OG_RETVALUE_IFTRUE(r_tbl->type != NORMAL_TABLE, OG_FALSE);
    OG_RETVALUE_IFTRUE(r_tbl->rowid_exists, OG_FALSE);

    if (qry->winsort_list != NULL && qry->winsort_list->count > 0) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (qry->pivot_items != NULL) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (qry->ssa.count > 0) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (qry->group_sets != NULL && qry->group_sets->count > 0) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (qry->for_update) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (LIMIT_CLAUSE_OCCUR(&qry->limit)) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (QUERY_HAS_ROWNUM(qry)) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (qry->path_func_nodes != NULL && qry->path_func_nodes->count > 0) {
        OG_RETVALUE_IFTRUE(r_tbl->id != qry->tables.count - 1, OG_FALSE);
    }

    if (r_tbl->query_fields.count != 0) {
        OG_RETVALUE_IFTRUE(!is_all_qry_col_in_cond(jnode, r_tbl), OG_FALSE);
    }

    uint32 idx = 0;
    sql_table_t *tbl = NULL;
    while (idx < qry->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, idx++);
        OG_RETVALUE_IFTRUE(!og_check_sub_tbl(tbl), OG_FALSE);
    }

    return OG_TRUE;
}

static uint32 find_tbl_idx_in_hint(galist_t *hint_tbls, uint32 tbl_id)
{
    uint32 tbl_idx = 0;
    sql_table_t *tbl = NULL;
    while (tbl_idx < hint_tbls->count) {
        tbl = (sql_table_t *)(((sql_table_hint_t *)cm_galist_get(hint_tbls, tbl_idx))->table);
        if (tbl->id == tbl_id) {
            return tbl_idx;
        }
        tbl_idx++;
    }
    return OG_INVALID_ID32;
}

static void remove_table_from_leading_hint(galist_t *hint_tbls, uint32 tbl_id)
{
    uint32 tbl_idx = find_tbl_idx_in_hint(hint_tbls, tbl_id);
    if (tbl_idx != OG_INVALID_ID32) {
        cm_galist_delete(hint_tbls, tbl_idx);
    }
}

static status_t og_remove_right_table_from_join_tree(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode,
                                              uint32 tbl_id)
{
    CM_POINTER3(statement, qry, jnode);
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, qry);
    OGSQL_SAVE_STACK(statement);
    galist_t lst;
    cm_galist_init(&lst, statement->session->stack, cm_stack_alloc);
    v_ast.result0 = tbl_id;
    v_ast.param0 = (void *)&lst;

    if (jnode->join_cond != NULL) {
        OG_RETURN_IFERR(visit_cond_node(&v_ast, jnode->join_cond->root, og_uncache_qry_flds));
    }

    if (HAS_SPEC_TYPE_HINT(qry->hint_info, JOIN_HINT, HINT_KEY_WORD_LEADING)) {
        galist_t *hint_tbls = (galist_t *)(qry->hint_info->args[ID_HINT_LEADING]);
        remove_table_from_leading_hint(hint_tbls, tbl_id);
        if (hint_tbls->count == 0) {
            HINT_JOIN_ORDER_CLEAR(qry->hint_info);
        }
    }

    OG_RETURN_IFERR(og_delete_table_from_join_node(qry->join_assist.join_node, tbl_id));
    OG_RETURN_IFERR(sql_array_delete(&qry->tables, tbl_id));
    OG_RETURN_IFERR(og_update_query_tables(statement, qry, &v_ast, tbl_id));
    OGSQL_RESTORE_STACK(statement);
    return og_update_table_id(qry, tbl_id, jnode);
}

static status_t og_try_eliminate_right_table(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode,
                                     bool32 *is_eliminated)
{
    CM_POINTER4(statement, qry, jnode, is_eliminated);
    sql_table_t *tbl = TABLE_OF_JOIN_LEAF(jnode->right);
    // use unique index to remove right table
    if (chk_tbl_uinq_idx_usable(tbl, jnode)) {
        *is_eliminated = OG_TRUE;
        tbl->index = NULL;
        return og_remove_right_table_from_join_tree(statement, qry, jnode, tbl->id);
    }

    OG_RETSUC_IFTRUE(qry->owner == NULL);
    // use duplication to remove right table
    OG_RETSUC_IFTRUE(!og_check_elimination_by_distinct(statement, qry->owner->root, qry, OG_FALSE));
    *is_eliminated = OG_TRUE;
    return og_remove_right_table_from_join_tree(statement, qry, jnode, tbl->id);
}

static status_t og_try_eliminate_left_join_node(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode,
                                     bool32 *is_eliminated)
{
    CM_POINTER4(statement, qry, jnode, is_eliminated);
    *is_eliminated = OG_FALSE;
    OG_RETSUC_IFTRUE(jnode->type != JOIN_TYPE_LEFT || jnode->join_cond == NULL);

    OG_RETSUC_IFTRUE(jnode->right->type != JOIN_TYPE_NONE || jnode->filter != NULL);

    OG_RETSUC_IFTRUE(!og_check_left_join_elimination_constraint(statement, qry, jnode));

    return og_try_eliminate_right_table(statement, qry, jnode, is_eliminated);
}

static status_t og_eliminate_left_join_in_join_tree(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode)
{
    CM_POINTER3(statement, qry, jnode);
    OG_RETURN_IFERR(sql_stack_safe(statement));

    bool32 is_eliminated = OG_FALSE;
    while (OG_TRUE) {
        OG_RETSUC_IFTRUE(jnode->type == JOIN_TYPE_NONE);
        if (og_try_eliminate_left_join_node(statement, qry, jnode, &is_eliminated) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[JOIN_ELIMINATION] eliminate jnode error");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(!is_eliminated);
    }

    if (og_eliminate_left_join_in_join_tree(statement, qry, jnode->right) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] eliminate right jnode error");
        return OG_ERROR;
    }
    if (og_eliminate_left_join_in_join_tree(statement, qry, jnode->left) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] eliminate left jnode error");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_eliminate_left_outer_join(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_join_elimination, OPT_JOIN_ELIMINATION)) {
        return OG_SUCCESS;
    }

    if (qry->is_s_query) {
        OG_LOG_DEBUG_INF("[JOIN_ELIMINATION] ignore sub qry");
        return OG_SUCCESS;
    }
    if (statement->context->type == OGSQL_TYPE_DELETE) {
        OG_LOG_DEBUG_INF("[JOIN_ELIMINATION] ignore delete join");
        return OG_SUCCESS;
    }
    // Recursive Call
    return og_eliminate_left_join_in_join_tree(statement, qry, qry->join_assist.join_node);
}

static status_t try_move_join_cond_to_filter(sql_stmt_t *statement, sql_join_node_t *jnode)
{
    CM_POINTER2(statement, jnode);
    OG_RETSUC_IFTRUE(jnode->type >= JOIN_TYPE_LEFT);
    OG_RETSUC_IFTRUE(og_is_true_cond(jnode->join_cond));

    if (jnode->filter == NULL) {
        OG_RETURN_IFERR(sql_create_cond_tree(statement->context, &jnode->filter));
    }

    OG_RETURN_IFERR(sql_add_cond_node(jnode->filter, jnode->join_cond->root));
    jnode->join_cond = NULL;

    return OG_SUCCESS;
}

static status_t mv_jnode_filter_to_conds(galist_t *conds, sql_join_node_t *jnode, uint32 *filter_idx)
{
    CM_POINTER3(jnode, conds, filter_idx);
    OG_RETSUC_IFTRUE(jnode->filter == NULL);
    // conds in join_node->filter all from qry->cond
    *filter_idx = conds->count;
    return cm_galist_insert(conds, jnode->filter);
}

static status_t check_and_transf_null_reject_jnode(sql_stmt_t *statement, galist_t *conds, sql_join_node_t *jnode,
                                                 sql_join_assist_t *j_ast, bool32 outer_join_right)
{
    uint32 cond_idx = 0;
    cond_tree_t *filter_tree = NULL;
    while (cond_idx < conds->count) {
        filter_tree = (cond_tree_t *)cm_galist_get(conds, cond_idx++);
        // trans outer join oer here
        OG_RETURN_IFERR(check_null_reject_and_transform(statement, filter_tree, jnode, j_ast, outer_join_right));
    }
    return OG_SUCCESS;
}

static void og_handle_mix_join_tree_cond(galist_t *conds, uint32 filter_idx, uint32 jnode_idx)
{
    if (filter_idx != OG_INVALID_ID32) {
        cm_galist_delete(conds, filter_idx);
    }

    if (jnode_idx != OG_INVALID_ID32) {
        cm_galist_delete(conds, jnode_idx);
    }
}

/* In a LEFT JOIN scenario, if the parent node’s join condition involves columns from the left (outer) table,
 * it cannot be pushed down into the right subtree.
 * Therefore, the optimizer only considers pushing conditions that reference only the right subtree.
 */
static bool32 og_push_mix_join_tree_cond(sql_join_node_t *jnode)
{
    OG_RETVALUE_IFTRUE(jnode->type != JOIN_TYPE_LEFT, OG_FALSE);
    OG_RETVALUE_IFTRUE(jnode->right->tables.count <= 1, OG_FALSE);
    OG_RETVALUE_IFTRUE(jnode->join_cond == NULL, OG_FALSE);
    return OG_TRUE;
}

static status_t og_optimize_mix_join_tree_cond(sql_stmt_t *statement, galist_t *conds, sql_join_node_t *jnode,
                                            sql_join_assist_t *j_ast, bool32 outer_join_right)
{
    CM_POINTER4(statement, conds, jnode, j_ast);
    OG_RETSUC_IFTRUE(jnode->type == JOIN_TYPE_NONE);

    uint32 filter_idx = OG_INVALID_ID32;
    
    /* outer_join_right :Identify whether the join node is the right table of the outer join (
     * needs to complete null) */
    OG_RETURN_IFERR(check_and_transf_null_reject_jnode(statement, conds, jnode, j_ast, outer_join_right));
    OG_RETURN_IFERR(try_move_join_cond_to_filter(statement, jnode));
    OG_RETURN_IFERR(mv_jnode_filter_to_conds(conds, jnode, &filter_idx));

    bool32 l_outer_join_right = jnode->type == JOIN_TYPE_FULL ? OG_TRUE : outer_join_right;
    bool32 r_outer_join_right = jnode->type >= JOIN_TYPE_LEFT ? OG_TRUE : outer_join_right;

    if (og_optimize_mix_join_tree_cond(statement, conds, jnode->left, j_ast, l_outer_join_right) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 jnode_idx = OG_INVALID_ID32;
    if (og_push_mix_join_tree_cond(jnode)) {
        jnode_idx = conds->count;
        OG_RETURN_IFERR(cm_galist_insert(conds, jnode->join_cond));
    }

    if (og_optimize_mix_join_tree_cond(statement, conds, jnode->right, j_ast, r_outer_join_right) != OG_SUCCESS) {
        return OG_ERROR;
    }

    og_handle_mix_join_tree_cond(conds, filter_idx, jnode_idx);
    return OG_SUCCESS;
}

static status_t og_optimize_mix_join_tree(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    cond_tree_t *root_cond = qry->cond;
    sql_join_assist_t *j_ast = &qry->join_assist;
    // conds in the cond_list can be used to trans outer join
    galist_t conds;
    cm_galist_init(&conds, statement->session->stack, cm_stack_alloc);
    OGSQL_SAVE_STACK(statement);
    // qry->cond is orgin conds in join trans, it will be sperated into related join node
    if (root_cond != NULL && root_cond->root->type != COND_NODE_TRUE) {
        cm_galist_insert(&conds, root_cond);
    }

    status_t ret = og_optimize_mix_join_tree_cond(statement, &conds, j_ast->join_node, j_ast, OG_FALSE);
    OGSQL_RESTORE_STACK(statement);
    return ret;
}

static inline bool32 has_outer_join_to_optimize(sql_join_assist_t *j_ast)
{
    CM_POINTER(j_ast);
    return j_ast->outer_node_count > 0;
}

static inline bool32 has_qry_cond_to_optimize(sql_query_t *qry)
{
    CM_POINTER(qry);
    return qry->cond != NULL;
}

status_t og_transf_optimize_outer_join(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    OG_RETSUC_IFTRUE(!has_outer_join_to_optimize(&qry->join_assist));

    // try eliminate left join
    if (og_eliminate_left_outer_join(statement, qry) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] eliminate left join error");
        return OG_ERROR;
    }
    sql_join_assist_t *j_ast = &qry->join_assist;
    if (has_qry_cond_to_optimize(qry)) {
        // Devliver conds from qry->cond to jnode->join_cond
        if (og_dlvr_predicates_on_join_iter(statement, qry, j_ast->join_node) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[JOIN_ELIMINATION] dlvr cond -> jnode error");
            return OG_ERROR;
        }
    }

    // try trans full join => left join and left join => inner join and
    // decompose the conditions in qry->cond into each join node for early filter
    if (og_optimize_mix_join_tree(statement, qry) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] optimize mix join error");
        return OG_ERROR;
    }

    // If there are still outer joins in the join exprtr,
    // all remaining conditions in the qry conditions will be used to generate the filter plan.
    if (has_outer_join_to_optimize(j_ast)) {
        if (og_adjust_cond_when_has_out_join(statement, qry, j_ast) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[JOIN_ELIMINATION] adjust out join cond error");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (sql_adjust_inner_join_cond(statement, j_ast->join_node, &qry->cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[JOIN_ELIMINATION] adjust inner join cond error");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}
