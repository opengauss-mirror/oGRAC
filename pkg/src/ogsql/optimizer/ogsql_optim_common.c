/* -------------------------------------------------------------------------
 * This file is part of the oGRAC project.
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
 * ogsql_common.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_optim_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_optim_common.h"
#include "ogsql_stmt.h"
#include "ogsql_expr_def.h"
#include "ogsql_cond.h"
#include "ogsql_expr.h"
#include "ogsql_transform.h"
#include "ogsql_verifier.h"

static bool32 check_outer_join_node_cond(cond_tree_t *cond_tree)
{
    OG_RETVALUE_IFTRUE(!cond_tree, OG_TRUE);
    cols_used_t col_used = { 0 };
    init_cols_used(&col_used);
    sql_collect_cols_in_cond(cond_tree->root, &col_used);

    bool32 has_subslct = HAS_SUBSLCT(&col_used);
    bool32 has_parrent_or_ancestor_cols = HAS_PRNT_OR_ANCSTR_COLS(col_used.flags);

    return !has_subslct && !has_parrent_or_ancestor_cols;
}

bool32 validate_outer_join_conditions(sql_join_node_t *jnode)
{
    OG_RETVALUE_IFTRUE(!jnode || jnode->type == JOIN_TYPE_NONE, OG_TRUE);

    if (!check_outer_join_node_cond(jnode->filter) || !check_outer_join_node_cond(jnode->join_cond)) {
        return OG_FALSE;
    }

    return validate_outer_join_conditions(jnode->left) && validate_outer_join_conditions(jnode->right);
}

static inline status_t chk_tbl_has_ancestor_cols(visit_assist_t *v_ast, expr_node_t **exprn)
{
    CM_POINTER2(exprn, (*exprn));
    if (((*exprn)->type == EXPR_NODE_GROUP && NODE_VM_ANCESTOR(*exprn) > 0) ||
        ((*exprn)->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(*exprn) > 0)) {
        v_ast->result0 = OG_TRUE;
    }
    return OG_SUCCESS;
}

bool32 og_query_contains_table_ancestor(sql_query_t *qry)
{
    CM_POINTER(qry);

    visit_assist_t v_ast = { 0 };
    sql_init_visit_assist(&v_ast, NULL, qry);
    sql_table_t *tbl = NULL;

    uint32 count = 0;
    while (count < qry->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, count++);
        expr_tree_t *exprtr = NULL;
        if (tbl->type == FUNC_AS_TABLE) {
            exprtr = tbl->func.args;
        } else if (tbl->type == JSON_TABLE) {
            exprtr = tbl->json_table_info->data_expr;
        } else {
            continue;
        }
        (void)visit_expr_tree(&v_ast, exprtr, chk_tbl_has_ancestor_cols);
        if (v_ast.result0 != OG_INVALID_ID32) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static bool32 has_higher_ancestor_ref(parent_ref_t *ref)
{
    CM_POINTER(ref);

    galist_t *ref_columns = ref->ref_columns;
    if (ref_columns == NULL || ref_columns->count == 0) {
        return OG_FALSE;
    }

    uint32 i = 0;
    while (i < ref_columns->count) {
        expr_node_t *col_ref_exprn = (expr_node_t *)cm_galist_get(ref_columns, i++);
        col_ref_exprn = sql_get_origin_ref(col_ref_exprn);
        OG_RETVALUE_IFTRUE(ANCESTOR_OF_NODE(col_ref_exprn) > 1, OG_TRUE);
    }
    
    return OG_FALSE;
}

bool32 detect_cross_level_dependency(sql_query_t *qry)
{
    CM_POINTER(qry);

    galist_t *parent_refs = NULL;
    if (qry->owner == NULL || qry->owner->parent_refs == NULL) {
        return OG_FALSE;
    }

    parent_refs = qry->owner->parent_refs;

    uint32 i = 0;
    while (i < parent_refs->count) {
        parent_ref_t *current_ref = (parent_ref_t *)cm_galist_get(parent_refs, i++);
        OG_RETVALUE_IFTRUE(has_higher_ancestor_ref(current_ref), OG_TRUE);
    }

    return OG_FALSE;
}

static inline void og_reset_ancestor_level(sql_select_t *select, uint32 level)
{
    CM_POINTER(select);
    OG_RETVOID_IFTRUE(level <= 0);

    sql_select_t *curslct = select;
    while (level > 0 && curslct != NULL) {
        RESET_ANCESTOR_LEVEL(curslct, level);
        curslct = (curslct->parent != NULL) ? curslct->parent->owner : NULL;
        level--;
    }
    return;
}

static void og_del_parent_refs(sql_query_t *qry, cols_used_t *cols_record)
{
    CM_POINTER2(qry, cols_record);
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr_entry = NULL;
    biqueue_node_t *end_entry = NULL;
    sql_select_t *curslct = NULL;
    expr_node_t *node = NULL;
    uint32 ancestor = 0;
    // del PARENT_IDX and ANCESTOR_IDX level parent refs
    for (uint32 i = 0; i < SELF_IDX; i++) {
        cols_que = &cols_record->cols_que[i];
        curr_entry = biqueue_first(cols_que);
        end_entry = biqueue_end(cols_que);
        while (curr_entry != end_entry) {
            // find subselect of the ancestor level
            curslct = qry->owner;
            node = OBJECT_OF(expr_node_t, curr_entry);
            ancestor = ANCESTOR_OF_NODE(node);
            while (ancestor > 1 && curslct != NULL) {
                curslct = (curslct->parent != NULL) ? curslct->parent->owner : NULL;
                ancestor--;
            }

            if (curslct != NULL) {
                sql_del_parent_refs(curslct->parent_refs, TAB_OF_NODE(node), node);
            }
            if (curslct != NULL && curslct->parent_refs->count == 0) {
                og_reset_ancestor_level(qry->owner, ANCESTOR_OF_NODE(node));
            }
            curr_entry = curr_entry->next;
        }
    }
}

void og_del_parent_refs_in_expr_tree(sql_query_t *qry, expr_tree_t *expr)
{
    cols_used_t cols_record = { 0 };
    init_cols_used(&cols_record);
    sql_collect_cols_in_expr_tree(expr, &cols_record);
    og_del_parent_refs(qry, &cols_record);
    return;
}

status_t og_modify_rs_cols2const(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    cm_galist_reset(qry->rs_columns);

    expr_node_t *exprn = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&exprn));

    expr_tree_t *exprtr = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_tree_t), (void **)&exprtr));

    rs_column_t *rs_col = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(rs_column_t), (void **)&rs_col));

    exprn->type        = EXPR_NODE_CONST;
    exprn->datatype    = OG_TYPE_INTEGER;
    exprn->value.type  = OG_TYPE_INTEGER;
    exprn->value.v_int = 1;
    exprn->owner       = exprtr;

    exprtr->root       = exprn;
    exprtr->owner      = statement->context;
    exprtr->next       = NULL;

    rs_col->expr       = exprtr;
    rs_col->type       = RS_COL_CALC;
    rs_col->datatype   = OG_TYPE_INTEGER;

    return cm_galist_insert(qry->rs_columns, rs_col);
}

static void disable_join4table(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    uint32 i = 0;
    while (i < qry->tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, i++);
        OG_CONTINUE_IFTRUE(tbl == NULL);
        TABLE_CBO_SET_FLAG(tbl, SELTION_NO_HASH_JOIN);
        if (tbl->type == SUBSELECT_AS_TABLE || tbl->type == VIEW_AS_TABLE) {
            make_subqry_without_join(statement, tbl->select_ctx->root, OG_TRUE);
        }
    }
}

void make_subqry_without_join(sql_stmt_t *statement, select_node_t *select_node, bool32 is_var)
{
    OG_RETVOID_IFTRUE(select_node == NULL);
    if (select_node->type != SELECT_NODE_QUERY) {
        make_subqry_without_join(statement, select_node->left, is_var);
        make_subqry_without_join(statement, select_node->right, is_var);
        return;
    }

    sql_query_t *qry = select_node->query;
    if (is_var || 
        ((qry->owner->type == SELECT_AS_VARIANT || qry->owner->type == SELECT_AS_LIST) &&
        og_check_if_ref_parent_columns(qry->owner))) {
        disable_join4table(statement, qry);
    }
    return;
}

static inline bool32 is_valid_owner_and_table_name(const text_t *owner_name, const text_t *table_name)
{
    return (owner_name != NULL && owner_name->len > 0 && table_name != NULL && table_name->len > 0);
}

static bool32 get_and_chk_tbl_owner(sql_table_t *tbl, text_t *owner_name)
{
    text_t tbl_name = { 0 };
    if (tbl == NULL || tbl->entry == NULL) {
        return OG_FALSE;
    }

    if (tbl->entry->dc.is_sysnonym) {
        knl_get_link_name(&tbl->entry->dc, owner_name, &tbl_name);
    } else {
        *owner_name = tbl->user.value;
        tbl_name = tbl->name.value;
    }

    return is_valid_owner_and_table_name(owner_name, &tbl_name);
}

static bool32 chk_slct_qry_priv_access(select_node_t *slct_node, text_t *user)
{
    CM_POINTER(slct_node);
    if (slct_node->type != SELECT_NODE_QUERY) {
        return chk_slct_qry_priv_access(slct_node->left, user) &&
               chk_slct_qry_priv_access(slct_node->right, user);
    }

    sql_table_t *tbl = NULL;
    text_t owner_name = { 0 };
    sql_query_t *query = slct_node->query;
    sql_select_t *subslct_ctx = NULL;
    uint32 i = 0;
    while (i < query->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&query->tables, i++);
        if ((tbl->type == SUBSELECT_AS_TABLE || tbl->type == WITH_AS_TABLE) &&
            !chk_slct_qry_priv_access(tbl->select_ctx->root, user)) {
            return OG_FALSE;
        }
        if (tbl->entry != NULL) {
            if (!get_and_chk_tbl_owner(tbl, &owner_name)) {
                OG_LOG_DEBUG_INF("tbl owner name is not valid");
                return OG_FALSE;
            }
            if (!cm_text_equal(&owner_name, user)) {
                OG_LOG_DEBUG_INF("table owner name %.*s is not equal to user %.*s",
                                  owner_name.len, owner_name.str, user->len, user->str);
                return OG_FALSE;
            }
        }
    }

    uint32 j = 0;
    while (j < query->ssa.count) {
        subslct_ctx = (sql_select_t *)sql_array_get(&query->ssa, j++);
        if (!chk_slct_qry_priv_access(subslct_ctx->root, user)) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 chk_slct_node_for_subqry_pushdown(sql_stmt_t *statement, select_node_t *slct_node, sql_table_t *tbl)
{
    CM_POINTER(statement);
    text_t owner_name = { 0 };
    text_t *cur_user = NULL;
    if (!get_and_chk_tbl_owner(tbl, &owner_name)) {
        OG_LOG_DEBUG_INF("table owner name is not valid");
        return OG_FALSE;
    }
    cur_user = &statement->session->curr_user;
    if (cm_text_equal(cur_user, &owner_name)) {
        return OG_TRUE;
    }

    return chk_slct_qry_priv_access(slct_node, &owner_name);
}

bool32 check_cond_push2subslct_table(sql_stmt_t *statement, sql_query_t *qry, sql_select_t *slct_node, cmp_node_t *cmp)
{
    CM_POINTER3(statement, qry, slct_node);
    cols_used_t col_used_l = { 0 };
    cols_used_t col_used_r = { 0 };
    expr_node_t *col_exprn = NULL;
    sql_table_t *tbl = NULL;
    init_cols_used(&col_used_l);
    init_cols_used(&col_used_r);
    sql_collect_cols_in_expr_tree(cmp->left, &col_used_l);
    sql_collect_cols_in_expr_tree(cmp->right, &col_used_r);

    if (HAS_DYNAMIC_SUBSLCT(&col_used_r) || !HAS_ONLY_SELF_COLS(col_used_l.flags) ||
        HAS_DIFF_TABS(&col_used_l, SELF_IDX)) {
        return OG_FALSE;
    }

    col_exprn = sql_any_self_col_node(&col_used_l);
    tbl = (sql_table_t *)sql_array_get(&qry->tables, TAB_OF_NODE(col_exprn));
    if (tbl->type == SUBSELECT_AS_TABLE) {
        return tbl->select_ctx->root->type == SELECT_NODE_QUERY;
    }

    if (tbl->type == VIEW_AS_TABLE && tbl->select_ctx->root->type == SELECT_NODE_QUERY) {
        return chk_slct_node_for_subqry_pushdown(statement, slct_node->root, tbl);
    }

    return OG_FALSE;
}