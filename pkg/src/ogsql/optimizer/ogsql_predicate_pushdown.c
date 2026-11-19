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

#include "ogsql_predicate_pushdown.h"
#include "srv_instance.h"
#include "ogsql_func.h"
#include "ogsql_cond_rewrite.h"
#include "ogsql_expr.h"
#include "ogsql_plan.h"
#include "ogsql_transform.h"
#include "ogsql_plan_defs.h"
#include "dml_parser.h"
#include "ogsql_optim_common.h"
#include "ogsql_cond_rewrite.h"

static inline sql_query_t* sql_curr_qry(sql_stmt_t *statement)
{
    CM_POINTER(statement);
    OG_RETVALUE_IFTRUE(statement->node_stack.depth == 0, NULL);
    return OBJ_STACK_CURR(&(statement)->node_stack);
}

static inline status_t og_transf_slct_exprn(visit_assist_t *v_ast, expr_node_t *exprn)
{
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: transf slct exprn");
    CM_POINTER2(v_ast, exprn);
    pred_pushdown_helper_t *helper = (pred_pushdown_helper_t *)v_ast->param2;
    helper->ssa_nodes[helper->ssa_count++] = exprn;
    return OG_SUCCESS;
}

static void og_copy_col_info(column_info_t *col_info_orig, column_info_t *col_info_dest)
{
    OG_RETVOID_IFTRUE(col_info_orig == NULL || col_info_dest == NULL);
    col_info_dest->col_pro_id = col_info_orig->col_pro_id;
    col_info_dest->org_tab = col_info_orig->org_tab;
    col_info_dest->org_col = col_info_orig->org_col;
    col_info_dest->col_name_has_quote = col_info_orig->col_name_has_quote;
    col_info_dest->col_name = col_info_orig->col_name;
    col_info_dest->tab_alias_name = col_info_orig->tab_alias_name;
    col_info_dest->tab_name = col_info_orig->tab_name;
    col_info_dest->user_name = col_info_orig->user_name;
}

static void og_copy_var_column(var_column_t *var_col_orig, var_column_t *var_col_dest)
{
    CM_POINTER2(var_col_orig, var_col_dest);
    var_col_dest->datatype = var_col_orig->datatype;
    var_col_dest->tab = var_col_orig->tab;
    var_col_dest->col = var_col_orig->col;
    var_col_dest->ancestor = var_col_orig->ancestor;
    var_col_dest->ss_start = var_col_orig->ss_start;
    var_col_dest->ss_end = var_col_orig->ss_end;

    var_col_dest->is_ddm_col = var_col_orig->is_ddm_col;
    var_col_dest->is_rowid = var_col_orig->is_rowid;
    var_col_dest->is_rownodeid = var_col_orig->is_rownodeid;
    var_col_dest->is_array = var_col_orig->is_array;
    var_col_dest->is_jsonb = var_col_orig->is_jsonb;
    var_col_dest->adjusted = var_col_orig->adjusted;
    var_col_dest->has_adjusted = var_col_orig->has_adjusted;

    og_copy_col_info(var_col_orig->col_info_ptr, var_col_dest->col_info_ptr);
}

static void og_copy_array_column(var_column_t *var_col, rs_column_t *rs_column)
{
    CM_POINTER2(var_col, rs_column);
    var_col->ancestor = rs_column->v_col.ancestor;
    var_col->datatype = rs_column->v_col.datatype;
    var_col->tab = rs_column->v_col.tab;
    var_col->col = rs_column->v_col.col;
}

// Add anc level; if anc info is newly added, add parent reference
static status_t og_pred_down_process_ancestor_info(uint32 *anc_lev, visit_assist_t *v_ast,
    sql_query_t *sub_qry, uint16 tab_id, expr_node_t **exprn)
{
    uint32 parent_col_lev = 1;
    CM_POINTER4(anc_lev, v_ast, sub_qry, exprn);
    (*anc_lev)++;
    SET_ANCESTOR_LEVEL(sub_qry->owner, *anc_lev);
    OG_RETSUC_IFTRUE(*anc_lev > parent_col_lev);
    sql_query_t *qry = (sql_query_t *)v_ast->param0;
    return qry->owner == NULL ? OG_SUCCESS:
        sql_add_parent_refs(v_ast->stmt, qry->owner->parent_refs, tab_id, *exprn);
}

static status_t og_pred_down_process_calc_expr(sql_stmt_t *statement, sql_query_t *sub_qry,
    expr_node_t *src_exprn, expr_node_t **dst_exprn)
{
    SET_NODE_STACK_CURR_QUERY(statement, sub_qry);
    if (sql_clone_expr_node(statement->context, src_exprn, dst_exprn, sql_alloc_mem) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: sql_clone_expr_node failed");
        return OG_ERROR;
    }
    if (replace_group_expr_node(statement, dst_exprn) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: replace_group_expr_node failed");
        return OG_ERROR;
    }
    SQL_RESTORE_NODE_STACK(statement);
    return OG_SUCCESS;
}

static void og_pred_down_process_col_expr(var_column_t *var_col, rs_column_t *rs_col)
{
    CM_POINTER2(var_col, rs_col);
    if (VAR_COL_IS_ARRAY_ELEMENT(var_col)) {
        og_copy_array_column(var_col, rs_col);
    } else {
        og_copy_var_column(&rs_col->v_col, var_col);
    }
}

static status_t og_transf_col_exprn(visit_assist_t *v_ast, expr_node_t **exprn)
{
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: transf col exprn");
    CM_POINTER2(v_ast, exprn);
    var_column_t *var_column = VALUE_PTR(var_column_t, &(*exprn)->value);
    sql_query_t *sub_qry = (sql_query_t *)v_ast->param0;
    sql_table_t *tbl = (sql_table_t *)v_ast->param1;

    if (var_column->ancestor > 0 || tbl->id != var_column->tab) {
        return og_pred_down_process_ancestor_info(&var_column->ancestor, v_ast, sub_qry, var_column->tab, exprn);
    }

    galist_t *rs_col_lst = NULL;
    if (sub_qry->has_distinct) {
        rs_col_lst = sub_qry->distinct_columns;
    } else {
        rs_col_lst = sub_qry->rs_columns;
    }

    rs_column_t *rs_column = (rs_column_t *)cm_galist_get(rs_col_lst, var_column->col);
    if (rs_column->type == RS_COL_CALC) {
        return og_pred_down_process_calc_expr(v_ast->stmt, sub_qry, rs_column->expr->root, exprn);
    }
    og_pred_down_process_col_expr(var_column, rs_column);
    return OG_SUCCESS;
}

static inline bool32 og_if_reset_ref_col(parent_ref_t *parent, uint32 tgt_tbl)
{
    return parent->tab == tgt_tbl && parent->ref_columns->count > 0;
}

static void og_reset_ref_col(parent_ref_t *parent, expr_node_t *src_exprn, expr_node_t *dst_exprn)
{
    uint32 ref_column_it = 0;
    expr_node_t *ref_col_exprn = NULL;
    ref_column_it = (int32)(parent->ref_columns->count - 1);
    while (ref_column_it >= 0) {
        ref_col_exprn = (expr_node_t *)cm_galist_get(parent->ref_columns, (uint32)ref_column_it);
        if (ref_col_exprn == src_exprn) {
            cm_galist_set(parent->ref_columns, (uint32)ref_column_it, dst_exprn);
            return;
        }
        ref_column_it--;
    }
}

// To fix the problem that parent ref array would wrongly include group_node->origin_ref
static void og_reset_node_parent_ref(sql_stmt_t *statement, expr_node_t *src_exprn, expr_node_t *dst_exprn)
{
    CM_POINTER3(statement, src_exprn, dst_exprn);
    OG_RETVOID_IFTRUE(!src_exprn->parent_ref);
    sql_query_t *qry = sql_curr_qry(statement);
    uint32 anc = ANCESTOR_OF_NODE(src_exprn);
    for (; anc > 1; anc--) {
        qry = qry->owner->parent;
    }

    parent_ref_t *parent = NULL;
    uint32 query_parent_ref_it = 0;
    while (query_parent_ref_it < qry->owner->parent_refs->count) {
        parent = (parent_ref_t *)cm_galist_get(qry->owner->parent_refs, query_parent_ref_it++);
        if (og_if_reset_ref_col(parent, TAB_OF_NODE(src_exprn))) {
            og_reset_ref_col(parent, src_exprn, dst_exprn);
            return;
        }
    }
}

static inline void og_try_handle_col_anc(expr_node_t *exprn)
{
    CM_POINTER(exprn);
    OG_RETVOID_IFTRUE(exprn->type != EXPR_NODE_COLUMN);
    OG_RETVOID_IFTRUE(NODE_ANCESTOR(exprn) == 0);
    exprn->value.v_col.ancestor++;
}

static inline void og_try_handle_rowid_col_anc(expr_node_t *exprn)
{
    CM_POINTER(exprn);
    OG_RETVOID_IFTRUE(!NODE_IS_RES_ROWID(exprn));
    OG_RETVOID_IFTRUE(ROWID_NODE_ANCESTOR(exprn) == 0);
    exprn->value.v_rid.ancestor++;
}

static status_t og_transf_group_exprn(visit_assist_t *v_ast, expr_node_t *exprn)
{
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: transf group exprn");
    CM_POINTER2(v_ast, exprn);
    sql_query_t *sub_qry = (sql_query_t *)v_ast->param0;
    exprn->value.v_vm_col.ancestor++;
    SET_ANCESTOR_LEVEL(sub_qry->owner, exprn->value.v_vm_col.ancestor);
    expr_node_t *orig_exprn = sql_get_origin_ref(exprn);
    expr_node_t *new_ref_exprn = NULL;
    if (sql_clone_expr_node(v_ast->stmt->context, orig_exprn, &new_ref_exprn, sql_alloc_mem) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: sql_clone_expr_node failed");
        return OG_ERROR;
    }
    og_reset_node_parent_ref(v_ast->stmt, new_ref_exprn, exprn);
    og_try_handle_col_anc(new_ref_exprn);
    og_try_handle_rowid_col_anc(new_ref_exprn);
    VALUE_PTR(var_vm_col_t, &exprn->value)->origin_ref = new_ref_exprn;

    return OG_SUCCESS;
}

static status_t og_transf_reserved_exprn(visit_assist_t *v_ast, expr_node_t *exprn)
{
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: transf reserved exprn");
    CM_POINTER2(v_ast, exprn);
    OG_RETSUC_IFTRUE(exprn->value.v_int != RES_WORD_ROWID);
    sql_query_t *sub_qry = (sql_query_t *)v_ast->param0;
    var_rowid_t *rid = VALUE_PTR(var_rowid_t, &exprn->value);
    return og_pred_down_process_ancestor_info(&rid->ancestor, v_ast,
                                                       sub_qry, rid->tab_id, &exprn);
}

static status_t og_transf_expr_node(visit_assist_t *v_ast, expr_node_t **exprn)
{
    CM_POINTER2(v_ast, exprn);
    expr_node_type_t expr_node_type = (*exprn)->type;
    status_t ret = OG_SUCCESS;
    if (expr_node_type == EXPR_NODE_RESERVED) {
        ret = og_transf_reserved_exprn(v_ast, *exprn);
        if (ret != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: transf reserved exprn error");
        }
        return ret;
    }

    if (expr_node_type == EXPR_NODE_SELECT) {
        ret = og_transf_slct_exprn(v_ast, *exprn);
        if (ret != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: transf slct exprn error");
        }
        return ret;
    }

    if (expr_node_type == EXPR_NODE_GROUP) {
        ret = og_transf_group_exprn(v_ast, *exprn);
        if (ret != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: transf group exprn error");
        }
        return ret;
    }
        
    if (expr_node_type == EXPR_NODE_COLUMN) {
        ret = og_transf_col_exprn(v_ast, exprn);
        if (ret != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: transf col exprn error");
        }
        return ret;
    }
    
    return ret;
}

static status_t og_transf_condn(sql_stmt_t *statement, cond_node_t *condn, sql_table_t *tbl,
                                    sql_query_t *qry, pred_pushdown_helper_t *helper)
{
    CM_POINTER5(statement, condn, tbl, qry, helper);
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, NULL);
    sql_set_vst_param(&v_ast, qry, tbl, helper);
    status_t ret = visit_cond_node(&v_ast, condn, og_transf_expr_node);
    if (ret != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: og_transf_condn failed");
    }
    return ret;
}

static bool32 match_group_expr(expr_tree_t *group_exprtr, sql_stmt_t *statement, expr_node_t *tgt_exprn)
{
    CM_POINTER3(group_exprtr, statement, tgt_exprn);
    expr_node_t *orig_ref_exprn = sql_get_origin_ref(group_exprtr->root);
    return orig_ref_exprn != NULL && sql_expr_node_equal(statement, tgt_exprn, orig_ref_exprn, NULL);
}

static bool32 find_matched_window_groups(sql_stmt_t *statement, expr_node_t *exprn, expr_node_t *ws_exprn)
{
    CM_POINTER3(statement, exprn, ws_exprn);
    winsort_args_t *ws_args = ws_exprn->win_args;
    if (ws_args->group_exprs == NULL) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: ws_args->group_exprs is NULL");
        return OG_FALSE;
    }

    uint32 group_expr_iter = 0;
    expr_tree_t *group_exprtr = NULL;
    while (group_expr_iter < ws_args->group_exprs->count) {
        group_exprtr = (expr_tree_t *)cm_galist_get(ws_args->group_exprs, group_expr_iter++);
        if (match_group_expr(group_exprtr, statement, exprn)) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: find matched window groups");
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static inline bool32 qry_has_winsort(sql_query_t *qry)
{
    return qry->winsort_list->count > 0;
}

static bool32 pred_down_chk_winsort(sql_stmt_t *statement, rs_column_t *rs_column, sql_query_t *qry)
{
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: pred down chk_winsort");
    CM_POINTER3(statement, rs_column, qry);
    OG_RETVALUE_IFTRUE(!qry_has_winsort(qry), OG_TRUE);

    // When using window sort functions, the rs_column type should not be treated as an ordinary column
    expr_node_t *origin_ref_exprn = sql_get_origin_ref(rs_column->expr->root);
    OG_RETVALUE_IFTRUE(origin_ref_exprn == NULL, OG_FALSE);

    uint32 winsort_expr_node_idx = 0;
    expr_node_t *winsort_expr_node = NULL;
    while (winsort_expr_node_idx < qry->winsort_list->count) {
        winsort_expr_node = (expr_node_t *)cm_galist_get(qry->winsort_list, winsort_expr_node_idx++);
        // can push down only when the origin_ref_exprn of rs_column is the same as origin_ref of win_args
        OG_RETVALUE_IFTRUE(!find_matched_window_groups(statement, origin_ref_exprn, winsort_expr_node), OG_FALSE);
    }
    return OG_TRUE;
}

static inline bool32 og_pred_down_is_transf_col(expr_node_t *exprn)
{
    return exprn->type == EXPR_NODE_TRANS_COLUMN;
}

static inline bool32 og_pred_down_chk_unmatched_tbl(sql_table_t *tbl, expr_node_t *exprn)
{
    return tbl == NULL || tbl->id == TAB_OF_NODE(exprn);
}

static inline bool32 og_pred_down_chk_unable_cond(rs_column_t *rs_column)
{
    return !OG_BIT_TEST(rs_column->rs_flag, RS_COND_UNABLE);
}

static bool32 og_pred_down_chk_cols_used(sql_stmt_t *statement, cols_used_t *col_used,
    sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER3(statement, col_used, qry);
    biqueue_t *bq = &col_used->cols_que[SELF_IDX];
    expr_node_t *exprn = NULL;
    rs_column_t *rs_column = NULL;
    var_column_t *var_column = NULL;

    biqueue_node_t *bq_end = biqueue_end(bq);
    for (biqueue_node_t *bq_cur = biqueue_first(bq); bq_cur != bq_end; bq_cur = bq_cur->next) {
        exprn = OBJECT_OF(expr_node_t, bq_cur);
        if (og_pred_down_is_transf_col(exprn)) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: node type is EXPR_NODE_TRANS_COLUMN");
            return OG_FALSE;
        }

        if (!og_pred_down_chk_unmatched_tbl(tbl, exprn)) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: table id not match, tbl->id: %u, TAB_OF_NODE: %u",
                             tbl->id, TAB_OF_NODE(exprn));
            continue;
        }

        var_column = VALUE_PTR(var_column_t, &exprn->value);
        rs_column = (rs_column_t *)cm_galist_get(qry->rs_columns, var_column->col);
        if (!og_pred_down_chk_unable_cond(rs_column)) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: rs_column->rs_flag has RS_COND_UNABLE, rs_column name: %s",
                rs_column->name.str);
            return OG_FALSE;
        }

        if (!pred_down_chk_winsort(statement, rs_column, qry)) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: winsort check failed");
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static inline bool32 check_self_cols(cols_used_t *col_used)
{
    return HAS_SELF_COLS(col_used->flags);
}

static inline bool32 check_diff_tbl(cols_used_t *col_used)
{
    return !HAS_DIFF_TABS(col_used, SELF_IDX);
}

static inline bool32 check_match_tbl(expr_node_t *exprn, sql_table_t *tbl)
{
    return tbl->id == TAB_OF_NODE(exprn);
}

static bool32 og_pred_down_chk_cols(sql_stmt_t *statement, sql_query_t *qry,
                                                cols_used_t *col_used, sql_table_t *tbl)
{
    CM_POINTER4(statement, col_used, qry, tbl);
    if (!check_self_cols(col_used)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: no self cols");
        return OG_FALSE;
    }

    if (!check_diff_tbl(col_used)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: has diff tabs");
        return OG_FALSE;
    }

    expr_node_t *exprn = sql_any_self_col_node(col_used);
    if (!check_match_tbl(exprn, tbl)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: table id not match, tbl->id: %u, exprn->tab: %u",
                         tbl->id, TAB_OF_NODE(exprn));
        return OG_FALSE;
    }

    if (!og_pred_down_chk_cols_used(statement, col_used, qry, NULL)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: col used chk failed");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static inline bool32 og_pred_down_chk_node(sql_stmt_t *statement, sql_query_t *qry,
    cols_used_t *col_used_l, cols_used_t *col_used_r, sql_table_t *tbl)
{
    CM_POINTER5(statement, col_used_l, col_used_r, qry, tbl);
    if (og_pred_down_chk_cols(statement, qry, col_used_l, tbl)) {
        OG_RETVALUE_IFTRUE(!check_self_cols(col_used_l), OG_TRUE);
        return og_pred_down_chk_cols_used(statement, col_used_r, qry, tbl);
    }
    if (og_pred_down_chk_cols(statement, qry, col_used_r, tbl)) {
        OG_RETVALUE_IFTRUE(!check_self_cols(col_used_r), OG_TRUE);
        return og_pred_down_chk_cols_used(statement, col_used_l, qry, tbl);
    }
    return OG_FALSE;
}

static inline void init_and_collect_cols(expr_tree_t *exprtr, cols_used_t *col_used)
{
    CM_POINTER(col_used);
    init_cols_used(col_used);
    sql_collect_cols_in_expr_tree(exprtr, col_used);
}

static bool32 sql_cols_is_same_table(uint32 tbl, cols_used_t *col_used)
{
    CM_POINTER(col_used);
    OG_RETVALUE_IFTRUE(col_used->flags == 0, OG_TRUE);
 
    OG_RETVALUE_IFTRUE(OG_BIT_TEST(col_used->flags, (FLAG_HAS_PARENT_COLS | FLAG_HAS_ANCESTOR_COLS)), OG_FALSE);
    
    OG_RETVALUE_IFTRUE(OG_BIT_TEST(col_used->level_flags[SELF_IDX], LEVEL_HAS_DIFF_TABS), OG_FALSE);

    biqueue_node_t *bq = biqueue_first(&col_used->cols_que[SELF_IDX]);
    expr_node_t *exprn = OBJECT_OF(expr_node_t, bq);
    return (tbl == TAB_OF_NODE(exprn));
}

static status_t og_del_slct_node_from_parent_qry(pred_pushdown_helper_t *helper,
    sql_select_t *slct)
{
    CM_POINTER2(helper, slct);
    uint32 p_qry_slct_idx = 0;
    sql_select_t *p_qry_slct = NULL;
    while (p_qry_slct_idx < helper->p_query->ssa.count) {
        p_qry_slct = (sql_select_t *)sql_array_get(&helper->p_query->ssa, p_qry_slct_idx);
        if (p_qry_slct != slct) {
            ++p_qry_slct_idx;
            continue;
        }
        return sql_array_delete(&helper->p_query->ssa, p_qry_slct_idx);
    }
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Select ctx does not exist in parent query");
    return OG_SUCCESS;
}

// Push down predicates to sub query stored in helper, and then
// delete the select node with is_del=true mark from the parent query.
// Afterwards, update the parent query's ssa array
static status_t og_pred_down_sub_slct_qry(sql_stmt_t *statement, sql_query_t *qry,
                                                       pred_pushdown_helper_t *helper)
{
    CM_POINTER3(statement, qry, helper);
    expr_node_t *exprn = NULL;
    sql_select_t *slct = NULL;

    uint32 pred_pushdown_helper_ssa_it = 0;
    while (pred_pushdown_helper_ssa_it < helper->ssa_count) {
        exprn = helper->ssa_nodes[pred_pushdown_helper_ssa_it];
        slct = (sql_select_t *)VALUE_PTR(var_object_t, &exprn->value)->ptr;
        slct->parent = qry;
        exprn->value.v_obj.id = qry->ssa.count;
        OG_RETURN_IFERR(sql_array_put(&qry->ssa, slct));
        OG_CONTINUE_IFTRUE(!helper->is_del[pred_pushdown_helper_ssa_it++]);
        OG_RETURN_IFERR(og_del_slct_node_from_parent_qry(helper, slct));
    }

    OG_RETSUC_IFTRUE(helper->p_query->ssa.count == 0);
    return sql_update_query_ssa(statement, helper->p_query);
}

static status_t pred_down_check_select(visit_assist_t *v_ast, expr_node_t **exprn)
{
    CM_POINTER2(v_ast, exprn);

    OG_RETVALUE_IFTRUE(!v_ast->result0, OG_SUCCESS);
    
    OG_RETVALUE_IFTRUE((*exprn)->type != EXPR_NODE_SELECT, OG_SUCCESS);
    
    sql_select_t *slct = (sql_select_t *)VALUE_PTR(var_object_t, &(*exprn)->value)->ptr;
    sql_table_t *tbl = (sql_table_t *)v_ast->param0;
    v_ast->result0 = chk_slct_node_for_subqry_pushdown(v_ast->stmt, slct->root, tbl);

    return OG_SUCCESS;
}

static void og_pred_down_pre_chk_slct(visit_assist_t *v_ast, sql_stmt_t *statement,
    sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER4(v_ast, statement, qry, tbl);
    sql_init_visit_assist(v_ast, statement, qry);
    v_ast->param0 = (void *)tbl;
    v_ast->result0 = OG_TRUE;
}

static bool32 og_pred_down_check_priv(sql_stmt_t *statement, sql_query_t *qry,
                                                  cmp_node_t *cmp, sql_table_t *tbl)
{
    CM_POINTER4(statement, qry, cmp, tbl);
    visit_assist_t v_ast;
    og_pred_down_pre_chk_slct(&v_ast, statement, qry, tbl);

    (void)visit_cmp_node(&v_ast, cmp, pred_down_check_select);

    return v_ast.result0;
}

static bool32 og_pred_down_chk_filter_down(sql_stmt_t *statement, bool32 is_same_table)
{
    return ogsql_opt_param_is_enable(statement, g_instance->sql.enable_filter_pushdown, OPT_FILTER_PUSHDOWN) ||
            !is_same_table;
}

static bool32 og_pred_down_chk_join_down(sql_stmt_t *statement, bool32 is_same_table)
{
    return ogsql_opt_param_is_enable(statement, g_instance->sql.enable_join_pred_pushdown, OPT_JOIN_PRED_PUSHDOWN) ||
        is_same_table;
}

static bool32 og_pred_down_chk_subslct(cols_used_t *col_used_l, cols_used_t *col_used_r,
    select_node_type_t sub_slct_node_type, bool32 is_same_table)
{
    CM_POINTER2(col_used_l, col_used_r);
    return (!HAS_SUBSLCT(col_used_l) && !HAS_SUBSLCT(col_used_r)) ||
        (sub_slct_node_type == SELECT_NODE_QUERY && is_same_table);
}

static inline bool32 og_pred_down_chk_cmp_rule1(cols_used_t *col_used_l, cols_used_t *col_used_r)
{
    return !HAS_DYNAMIC_SUBSLCT(col_used_l) && !HAS_DYNAMIC_SUBSLCT(col_used_r);
}

static inline bool32 og_pred_down_chk_cmp_rule2(cols_used_t *col_used_l, cols_used_t *col_used_r)
{
    return !HAS_ROWNUM(col_used_l) && !HAS_ROWNUM(col_used_r);
}

// Check whether a compare node can be pushed down
static bool32 og_pred_down_chk_cmp_node(pred_down_common_input_t *input, select_node_type_t sub_slct_node_type,
    bool32 *is_same_table)
{
    sql_stmt_t *statement = input->statement;
    sql_query_t *qry = input->qry;
    cond_node_t *cond = input->cond;
    sql_table_t *tbl = input->tbl;
    CM_POINTER5(statement, qry, cond, tbl, is_same_table);
    cols_used_t col_used_l;
    cols_used_t col_used_r;
    cmp_node_t *cmp = cond->cmp;

    init_and_collect_cols(cmp->left, &col_used_l);
    init_and_collect_cols(cmp->right, &col_used_r);

    if (!og_pred_down_chk_cmp_rule1(&col_used_l, &col_used_r)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: cmp node has dynamic subselect, cannot pushdown");
        return OG_FALSE;
    }

    if (!(og_pred_down_chk_cmp_rule2(&col_used_l, &col_used_r))) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: cmp node has rownum, cannot pushdown");
        return OG_FALSE;
    }

    if (!sql_cols_is_same_table(tbl->id, &col_used_l) ||
        !sql_cols_is_same_table(tbl->id, &col_used_r)) {
        *is_same_table = OG_FALSE;
    }

    if (!og_pred_down_chk_filter_down(statement, *is_same_table)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: filter pushdown is disabled or not same table");
        return OG_FALSE;
    }

    if (!og_pred_down_chk_join_down(statement, *is_same_table)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: join pred pushdown is disabled or is same table");
        tbl->no_join_push = OG_TRUE;
        return OG_FALSE;
    }

    if (!og_pred_down_chk_subslct(&col_used_l, &col_used_r, sub_slct_node_type, *is_same_table)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: cmp node has subselect, but pushdown target subselect is %u, "
            "is_same_table is %u, cannot pushdown, ", sub_slct_node_type, *is_same_table);
        return OG_FALSE;
    }

    if (!og_pred_down_chk_node(statement, qry, &col_used_l, &col_used_r, tbl)) {
        return OG_FALSE;
    }

    if (tbl->type == VIEW_AS_TABLE) {
        bool32 has_priv = og_pred_down_check_priv(statement, qry, cmp, tbl);
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: check select privilege %d", has_priv);
        return has_priv;
    }

    return OG_TRUE;
}

static bool32 og_pred_down_check_cond_node(pred_down_common_input_t *input, select_node_type_t sub_slct_node_type,
    bool32 *is_same_table)
{
    sql_stmt_t *statement = input->statement;
    sql_query_t *qry = input->qry;
    cond_node_t *cond_nd = input->cond;
    sql_table_t *tbl = input->tbl;
    CM_POINTER5(statement, qry, cond_nd, tbl, is_same_table);

    if (sql_stack_safe(statement) != OG_SUCCESS) {
        cm_reset_error();
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: Stack is not safe.");
        return OG_FALSE;
    }

    if (cond_nd->type == COND_NODE_COMPARE) {
        pred_down_common_input_t input = {
            .cond = cond_nd,
            .qry = qry,
            .statement = statement,
            .tbl = tbl
        };
        return og_pred_down_chk_cmp_node(&input, sub_slct_node_type, is_same_table);
    }

    pred_down_common_input_t l_input = {
        .cond = cond_nd->left,
        .qry = qry,
        .statement = statement,
        .tbl = tbl
    };
    pred_down_common_input_t r_input = {
        .cond = cond_nd->right,
        .qry = qry,
        .statement = statement,
        .tbl = tbl
    };

    if (cond_nd->type == COND_NODE_OR || cond_nd->type == COND_NODE_AND) {
        return og_pred_down_check_cond_node(&l_input, sub_slct_node_type, is_same_table) &&
               og_pred_down_check_cond_node(&r_input, sub_slct_node_type, is_same_table);
    }
    
    return OG_TRUE;
}

static inline bool32 og_pred_down_can_simplify_cond(sql_table_t *tbl)
{
    return tbl->subslct_tab_usage != SUBSELECT_4_ANTI_JOIN;
}

static inline void og_pred_down_set_del(pred_pushdown_helper_t *helper, uint32 original_ssa_count, bool32 is_del)
{
    while (original_ssa_count < helper->ssa_count) {
        helper->is_del[original_ssa_count] = is_del;
        original_ssa_count++;
    }
}

static inline void og_pred_down_handle_same_tbl(bool32 *is_del, bool32 *has_need_del, cond_node_t *cond,
    pred_pushdown_helper_t *helper, bool32 is_same_table)
{
    if (is_same_table && helper->subslct_type == SELECT_NODE_QUERY) {
        *is_del = OG_TRUE;
        *has_need_del = OG_TRUE;
        cond->type = COND_NODE_TRUE;
    }
}

static inline status_t og_pred_down_pre_add_cond(sql_stmt_t *statement, cond_tree_t **push_down_cond_tree)
{
    OG_RETSUC_IFTRUE(*push_down_cond_tree != NULL);
    return sql_create_cond_tree(statement->context, push_down_cond_tree);
}

// Core process of pushing down conditions
static status_t og_pred_down_cond_node(pred_down_common_input_t *input, pred_pushdown_helper_t* helper,
    cond_tree_t **push_down_cond_tree, bool32 *has_need_del, bool32 is_same_table)
{
    sql_stmt_t *statement = input->statement;
    sql_table_t *tbl = input->tbl;
    sql_query_t *qry = input->qry;
    cond_node_t *cond = input->cond;
    CM_POINTER4(statement, helper, has_need_del, tbl);
    cond_node_t *new_cond = NULL;
    OG_RETURN_IFERR(sql_clone_cond_node(statement->context, cond, &new_cond, sql_alloc_mem));
    uint32 original_ssa_count = helper->ssa_count;

    OG_RETURN_IFERR(og_transf_condn(statement, new_cond, tbl, qry, helper));

    if (og_pred_down_can_simplify_cond(tbl)) {
        OG_RETURN_IFERR(sql_try_simplify_new_cond(statement, new_cond));
    }

    bool32 is_del = OG_FALSE;
    og_pred_down_handle_same_tbl(&is_del, has_need_del, cond, helper, is_same_table);

    cond->join_pushed = !is_same_table;
    og_pred_down_set_del(helper, original_ssa_count, is_del);

    OG_RETURN_IFERR(og_pred_down_pre_add_cond(statement, push_down_cond_tree));
    return sql_add_cond_node(*push_down_cond_tree, new_cond);
}

static status_t og_pred_down_gen_cond(pred_down_common_input_t *input, pred_pushdown_helper_t* helper,
    cond_tree_t **push_down_cond_tree, bool32 *has_need_del)
{
    CM_POINTER(helper);
    bool32 is_same_table = OG_TRUE;
    if (og_pred_down_check_cond_node(input, helper->subslct_type, &is_same_table)) {
        return og_pred_down_cond_node(input, helper, push_down_cond_tree,
            has_need_del, is_same_table);
    }
    return OG_SUCCESS;
}

static status_t og_collect_conds(sql_stmt_t *statement, galist_t *cond_lst, cond_node_t *cond)
{
    CM_POINTER(cond);
    if (sql_stack_safe(statement) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: Stack is not safe.");
        return OG_ERROR;
    }
    if (cond->type == COND_NODE_AND) {
        if (og_collect_conds(statement, cond_lst, cond->left) == OG_SUCCESS &&
            og_collect_conds(statement, cond_lst, cond->right) == OG_SUCCESS) {
            return OG_SUCCESS;
        }
        return OG_ERROR;
    }
    
    if (cond->type == COND_NODE_OR || cond->type == COND_NODE_COMPARE) {
        OG_RETURN_IFERR(cm_galist_insert(cond_lst, cond));
    }
    return OG_SUCCESS;
}

// Collect and traverse all conditions to extract those that can be pushed down.
static status_t og_pred_down_extract_cond(pred_down_common_input_t *input,
    pred_pushdown_helper_t *helper, cond_tree_t **tgt_cond_tree)
{
    sql_stmt_t *statement = input->statement;
    sql_table_t *tbl = input->tbl;
    sql_query_t *qry = input->qry;
    cond_node_t *orig_cond = input->cond;

    CM_POINTER2(orig_cond, statement);
    bool32 is_and_node = orig_cond->type == COND_NODE_AND;

    if (sql_stack_safe(statement) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: Stack is not safe.");
        return OG_ERROR;
    }
    OGSQL_SAVE_STACK(statement);
    galist_t *cond_lst = NULL;
    if (sql_stack_alloc(statement, sizeof(galist_t), (void **)&cond_lst) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: Stack allocation failed.");
        return OG_ERROR;
    };
    cm_galist_init(cond_lst, statement, sql_stack_alloc);
    OG_RETURN_IFERR(og_collect_conds(statement, cond_lst, orig_cond));

    bool32 has_need_del = OG_FALSE;
    cond_node_t *cond = NULL;

    int cond_node_it = 0;
    while (cond_node_it < cond_lst->count) {
        cond = (cond_node_t *)cm_galist_get(cond_lst, cond_node_it++);
        pred_down_common_input_t tmp_input = {
            .cond = cond,
            .qry = qry,
            .statement = statement,
            .tbl = tbl
        };
        OG_RETURN_IFERR(og_pred_down_gen_cond(&tmp_input, helper, tgt_cond_tree, &has_need_del));
    }

    if (is_and_node && has_need_del) {
        OG_RETURN_IFERR(try_eval_logic_cond(statement, orig_cond));
    }

    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

// Collect all conditions that can be pushed down and push them down to the target query.
static status_t og_predicate_push_down_to_query(sql_stmt_t *statement, cond_node_t *cond_nd, sql_table_t *tbl,
    sql_query_t *sub_qry, pred_pushdown_helper_t *helper)
{
    CM_POINTER3(statement, sub_qry, helper);
    cond_tree_t *tgt_cond_tree = NULL;

    helper->ssa_count = 0;
    pred_down_common_input_t input = {
        .cond = cond_nd,
        .qry = sub_qry,
        .statement = statement,
        .tbl = tbl
    };
    OG_RETURN_IFERR(og_pred_down_extract_cond(&input, helper, &tgt_cond_tree));

    if (tgt_cond_tree == NULL) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: tgt_cond_tree is NULL, no possible predicates to push down");
        return OG_SUCCESS;
    }

    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Starting to push down predicates");
    
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: helper->ssa_count: %u", helper->ssa_count);
    if (helper->ssa_count > 0 &&
        og_pred_down_sub_slct_qry(statement, sub_qry, helper) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sub_qry->cond == NULL) {
        sub_qry->cond = tgt_cond_tree;
    } else {
        OG_RETURN_IFERR(sql_add_cond_node(sub_qry->cond, tgt_cond_tree->root));
    }

    sub_qry->cond_has_acstor_col = sql_cond_has_acstor_col(statement, tgt_cond_tree, sub_qry);
    if (sub_qry->cond_has_acstor_col) {
        TABLE_CBO_SET_FLAG(tbl, SELTION_PUSH_DOWN_JOIN);
    }
    return OG_SUCCESS;
}

// Check if target subquery meets the conditions for predicate pushdown
static bool32 og_predicate_push_down_check_target_query(sql_query_t *qry)
{
    CM_POINTER(qry);
    if (LIMIT_CLAUSE_OCCUR(&qry->limit)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Query starting from location line = %hu, column = %hu has LIMIT clause, "
            "cannot push down predicate to it", qry->loc.line, qry->loc.column);
        return OG_FALSE;
    }

    if (qry->group_sets->count > 1) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Query starting from location line = %hu, column = %hu "
            "has advanced usage of GROUP BY, cannot push down predicate to it", qry->loc.line, qry->loc.column);
        return OG_FALSE;
    }

    if (qry->connect_by_cond != NULL) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Query starting from location line = %hu, column = %hu "
            "has CONNECT BY clause, cannot push down predicate to it", qry->loc.line, qry->loc.column);
        return OG_FALSE;
    }

    if (qry->aggrs->count > 0 && qry->group_sets->count == 0) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Query starting from location line = %hu, column = %hu "
            "has aggregation without GROUP BY, cannot push down predicate to it", qry->loc.line, qry->loc.column);
        return OG_FALSE;
    }

    if (QUERY_HAS_ROWNUM(qry)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Query starting from location line = %hu, column = %hu has ROWNUM, "
            "cannot push down predicate to it", qry->loc.line, qry->loc.column);
        return OG_FALSE;
    }

    if (qry->pivot_items != NULL) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Query starting from location line = %hu, column = %hu has PIVOT/UNPIVOT, "
            "cannot push down predicate to it", qry->loc.line, qry->loc.column);
        return OG_FALSE;
    }

    // HINT: Check if target query has HINT_KEY_WORD_NO_PUSH_PRED

    return OG_TRUE;
}

static status_t og_try_pred_push_down_to_qry(sql_stmt_t *statement, cond_tree_t *cond_tree, sql_table_t *tbl,
    pred_pushdown_helper_t *helper, select_node_t *slct_node)
{
    OG_RETSUC_IFTRUE(!og_predicate_push_down_check_target_query(slct_node->query));
    return og_predicate_push_down_to_query(statement, cond_tree->root, tbl, slct_node->query, helper);
}

static inline void init_and_collect_slct(biqueue_t *bque, select_node_t *slct_node)
{
    biqueue_init(bque);
    sql_collect_select_nodes(bque, slct_node);
}

static status_t og_pred_down_subslct_node(sql_stmt_t *statement, cond_tree_t *cond_tree, sql_table_t *tbl,
    pred_pushdown_helper_t *helper)
{
    CM_POINTER3(statement, tbl, helper);
    select_node_t *slct_node = tbl->select_ctx->root;
    helper->subslct_type = tbl->select_ctx->root->type;
    OG_RETVALUE_IFTRUE(cond_tree == NULL, OG_SUCCESS);

    // If the current select node is a query node, attempt to directly push down predicate to its query
    if (slct_node->type == SELECT_NODE_QUERY) {
        return og_try_pred_push_down_to_qry(statement, cond_tree, tbl, helper, slct_node);
    }

    // Otherwise, collect all the query nodes in the select node and attempt to push down predicate to each of them
    biqueue_t bque;
    init_and_collect_slct(&bque, slct_node);
    biqueue_node_t *bq_end = biqueue_end(&bque);
    select_node_t *curr_slct_node = NULL;
    for (biqueue_node_t *bq_cur = biqueue_first(&bque); bq_cur != bq_end; bq_cur = BINODE_NEXT(bq_cur)) {
        curr_slct_node = OBJECT_OF(select_node_t, bq_cur);
        OG_CONTINUE_IFTRUE(curr_slct_node == NULL || curr_slct_node->query == NULL);
        OG_RETURN_IFERR(og_try_pred_push_down_to_qry(statement, cond_tree, tbl, helper, curr_slct_node));
    }
    return OG_SUCCESS;
}

// check whether subselect table meets to requirement for predicate pushdown
static bool32 og_pred_down_chk_slct_tbl(sql_stmt_t *statement, sql_table_t *tbl)
{
    CM_POINTER2(statement, tbl);
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Subselect table subslct_tab_usage is %d", tbl->subslct_tab_usage);
    switch (tbl->subslct_tab_usage) {
        case SUBSELECT_4_NORMAL_JOIN:
            return OG_TRUE;
        case SUBSELECT_4_ANTI_JOIN:
        case SUBSELECT_4_NL_JOIN:
        case SUBSELECT_4_SEMI_JOIN:
            break;
        default:
            return OG_FALSE;
    }

    // to do: Hint check
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: CBO is %s for the stmt, ", CBO_ON ? "on" : "off");
    return CBO_ON;
}

static status_t og_pred_down_join_node(sql_stmt_t *statement, sql_join_node_t *parent_jnode,
    sql_join_node_t *jnode, bool32 is_left_node, pred_pushdown_helper_t *helper)
{
    CM_POINTER3(statement, jnode, helper);
    if (sql_stack_safe(statement) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[PRED_PUSH_DOWN]: Stack is not safe.");
        return OG_ERROR;
    }

    // if exists outer join, recursively attempt to push down predicate to left and right nodes
    if (jnode->type != JOIN_TYPE_NONE) {
        if (og_pred_down_join_node(statement, jnode, jnode->left, OG_TRUE,
                                            helper) != OG_SUCCESS ||
            og_pred_down_join_node(statement, jnode, jnode->right, OG_FALSE,
                                            helper) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    // if parent join type is full join, predicate cannot be pushed down
    if (parent_jnode->type == JOIN_TYPE_FULL) {
        return OG_SUCCESS;
    }

    sql_table_t *tbl = TABLE_OF_JOIN_LEAF(jnode);

    // subselect must be table or view
    if (tbl->type != SUBSELECT_AS_TABLE && tbl->type != VIEW_AS_TABLE) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Subselect table type is %u, not SUBSELECT_AS_TABLE or VIEW_AS_TABLE",
            tbl->type);
        return OG_SUCCESS;
    }

    if (tbl->subslct_tab_usage != SUBSELECT_4_NORMAL_JOIN &&
        !og_pred_down_chk_slct_tbl(statement, tbl)) {
        return OG_SUCCESS;
    }

    // if parent is a node of an inner join, or the current node is left node of a left join, push down filter cond
    // otherwise, push down join cond
    bool32 do_push_down_filter = IS_INNER_TYPE(parent_jnode->type) || is_left_node;
    return og_pred_down_subslct_node(statement, do_push_down_filter ?
                                                parent_jnode->filter : parent_jnode->join_cond,
                                                tbl, helper);
}

static inline status_t og_pred_down_join_tree(sql_stmt_t *statement, pred_pushdown_helper_t *helper)
{
    CM_POINTER2(statement, helper);
    sql_join_node_t *jnode = helper->p_query->join_assist.join_node;
    // push down predicate to left and right ndoes
    if (og_pred_down_join_node(statement, jnode, jnode->left, OG_TRUE,
                                        helper) == OG_SUCCESS &&
        og_pred_down_join_node(statement, jnode, jnode->right, OG_FALSE,
                                        helper) == OG_SUCCESS) {
        return OG_SUCCESS;
    }
    return OG_ERROR;
}

static bool32 is_simple_qry(sql_query_t *qry)
{
    return qry->join_assist.outer_node_count == 0;
}

static status_t og_pred_down_tables(sql_stmt_t *statement, pred_pushdown_helper_t *helper)
{
    CM_POINTER2(statement, helper);
    sql_query_t *qry = helper->p_query;

    uint32 query_table_it = 0;
    while (query_table_it < qry->tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, query_table_it++);
        // subselect must be table or view
        if (tbl->type != SUBSELECT_AS_TABLE && tbl->type != VIEW_AS_TABLE) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Subselect table type is %u, not SUBSELECT_AS_TABLE or VIEW_AS_TABLE",
                             tbl->type);
            continue;
        }
        if (!og_pred_down_chk_slct_tbl(statement, tbl)) {
            OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Subslct tab usage check failed, skip.");
            continue;
        }
        OG_RETURN_IFERR(og_pred_down_subslct_node(statement, qry->cond, tbl, helper));
    }
    return OG_SUCCESS;
}

status_t og_transf_predicate_pushdown(sql_stmt_t *statement, sql_query_t *qry)
{
    CM_POINTER2(statement, qry);
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_pred_pushdown, OPT_JOIN_PRED_PUSHDOWN)) {
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Predicate pushdown is disabled.");
        return OG_SUCCESS;
    }
    pred_pushdown_helper_t helper = {
        .p_query = qry
    };
    if (is_simple_qry(qry)) {
        // If there is no condition in the query, there is no predicate for pushing down.
        OG_RETVALUE_IFTRUE(qry->cond == NULL, OG_SUCCESS);
        // Attempt to push down predicate along each table
        OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Push down predicate along tables");
        status_t ret = og_pred_down_tables(statement, &helper);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[PRED_PUSH_DOWN]: Push down predicate along tables error");
        }
        return ret;
    }

    sql_join_assist_t join_assist = qry->join_assist;
    // if outer join nodes exist, check whether predicate can be pushed down along join tree
    OG_LOG_DEBUG_INF("[PRED_PUSH_DOWN]: Outer join nodes count %u, push down predicate along join tree.",
        join_assist.outer_node_count);
    status_t ret = og_pred_down_join_tree(statement, &helper);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PRED_PUSH_DOWN]: Push down predicate along join tree error");
    }
    return ret;
}
