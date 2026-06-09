/* -------------------------------------------------------------------------
*  This file is part of the oGRAC project.
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
* ogsql_in2exists.c
*
*
* IDENTIFICATION
* src/ogsql/optimizer/ogsql_in2exists.c
*
* -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "ogsql_table_func.h"
#include "ogsql_stmt.h"
#include "ogsql_cond.h"
#include "ogsql_transform.h"
#include "ogsql_verifier.h"
#include "ogsql_hint_verifier.h"
#include "ogsql_optim_common.h"
#include "ogsql_verifier_common.h"
#include "ogsql_in2exists.h"

static bool32 validate_in_expr_candidate(expr_tree_t *target_expr)
{
    expr_tree_t *current = target_expr;
    while (current != NULL) {
        bool32 is_col_or_rowid = (current->root->type == EXPR_NODE_COLUMN) || NODE_IS_RES_ROWID(current->root);
        bool32 has_ancestor = ANCESTOR_OF_NODE(current->root) > 0;
        if (!is_col_or_rowid || has_ancestor) {
            return OG_FALSE;
        }
        
        current = current->next;
    }
    
    return OG_TRUE;
}

static bool32 check_subslct_4_in2exists(sql_select_t *sub_slct)
{
    if (sub_slct->root->type != SELECT_NODE_QUERY) {
        OG_LOG_DEBUG_INF("[IN2EXISTS]subselect has set operation");
        return OG_FALSE;
    }
    sql_query_t *qry = sub_slct->first_query;
    // this options need the whole result set, can't rewrite to exists
    if (qry->aggrs->count > 0 || qry->group_sets->count != 0 || qry->winsort_list->count != 0 ||
        qry->connect_by_cond != NULL || qry->has_distinct || qry->having_cond != NULL) {
        OG_LOG_DEBUG_INF(
            "[IN2EXISTS]subselect has group by, order by, distinct, connect by, having or aggregate function");
        return OG_FALSE;
    }
    if ((qry->limit.count != NULL || qry->limit.offset != NULL) ||
        (qry->cond != NULL && (qry->cond->incl_flags & SQL_INCL_ROWNUM))) {
        OG_LOG_DEBUG_INF("[IN2EXISTS]subselect has limit or rownum");
        return OG_FALSE;
    }

    if (qry->rs_columns->count > MAX_IN2EXISTS_ELEM_COUNT) {
        OG_LOG_DEBUG_INF("[IN2EXISTS]subselect has too many columns");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 check_need_generate_cmp(expr_node_t *l_exprn, rs_column_t *rs_col)
{
    var_column_t *l_column = NULL;
    var_column_t *r_column = NULL;
    var_rowid_t *l_rowid = NULL;
    var_rowid_t *r_rowid = NULL;
    expr_node_t *rs_expr = NULL;

    if (rs_col->type != RS_COL_CALC) {
        return OG_TRUE;
    }
    rs_expr = rs_col->expr->root;
    if (l_exprn->type == EXPR_NODE_COLUMN && rs_expr->type == EXPR_NODE_COLUMN) {
        l_column = &l_exprn->value.v_col;
        r_column = &rs_expr->value.v_col;
        if (l_column->tab == r_column->tab && l_column->col == r_column->col &&
            l_column->ancestor == r_column->ancestor - 1) {
            return OG_FALSE;
        }
    }
    if (NODE_IS_RES_ROWID(l_exprn) && NODE_IS_RES_ROWID(rs_expr)) {
        l_rowid = &l_exprn->value.v_rid;
        r_rowid = &rs_expr->value.v_rid;
        if (l_rowid->tab_id == r_rowid->tab_id && l_rowid->ancestor == r_rowid->ancestor - 1) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static void collect_columns_usage(expr_tree_t *expr, cols_used_t *col_usage)
{
    if (col_usage == NULL) {
        return;
    }

    init_cols_used(col_usage);
    sql_collect_cols_in_expr_tree(expr, col_usage);
}

static bool32 og_verify_computed_columns(sql_query_t *subq, rs_column_t *calc_col, cmp_type_t cmp_type)
{
    cols_used_t col_usage;
    collect_columns_usage(calc_col->expr, &col_usage);

    bool32 has_subslct = HAS_SUBSLCT(&col_usage);
    if (has_subslct) {
        return OG_FALSE;
    }

    if (cmp_type != CMP_TYPE_IN) {
        if (HAS_PRNT_OR_ANCSTR_COLS(col_usage.flags)) {
            return OG_FALSE;
        }

        biqueue_t *col_queue = &col_usage.cols_que[SELF_IDX];
        biqueue_node_t *q_node = biqueue_first(col_queue);
        biqueue_node_t *q_end = biqueue_end(col_queue);
        
        while (q_node != q_end) {
            expr_node_t *curr_expr = OBJECT_OF(expr_node_t, q_node);
            if (curr_expr->type == EXPR_NODE_COLUMN &&
                check_column_nullable(subq, &curr_expr->value.v_col) == OG_TRUE) {
                return OG_FALSE;
            }
            q_node = q_node->next;
        }
    }

    return OG_TRUE;
}

static bool32 check_cmp_trans2exists(sql_stmt_t *statement, sql_query_t *qry, cmp_node_t *cmp)
{
    expr_tree_t *l_exprtr = cmp->left;
    expr_tree_t *r_exprtr = cmp->right;
    sql_select_t *sub_slct = NULL;

    if (cmp->type != CMP_TYPE_IN && cmp->type != CMP_TYPE_NOT_IN) {
        return OG_FALSE;
    }
    // right cond has more than one element
    if (r_exprtr->root->type != EXPR_NODE_SELECT || r_exprtr->next != NULL) {
        OG_LOG_DEBUG_INF("[IN2EXISTS]the left expr has more than one subselect or has set operation");
        return OG_FALSE;
    }

    sub_slct = (sql_select_t *)r_exprtr->root->value.v_obj.ptr;
    if (!check_subslct_4_in2exists(sub_slct) || !validate_in_expr_candidate(l_exprtr)) {
        return OG_FALSE;
    }

    // if current cond can be push into sub_slct ,it's better than use exists
    if (check_cond_push2subslct_table(statement, qry, sub_slct, cmp)) {
        OG_LOG_DEBUG_INF("[IN2EXISTS]current condtion can be push into subselect tbl");
        return OG_FALSE;
    }

    return OG_TRUE;
}

static status_t og_build_column_reference(sql_stmt_t *query_stmt, rs_column_t *result_col, expr_tree_t **output_expr)
{
    expr_tree_t *col_expr = NULL;
    expr_node_t *col_node = NULL;
    
    status_t ret = sql_alloc_mem(query_stmt->context, sizeof(expr_tree_t), (void **)&col_expr);
    if (ret != OG_SUCCESS) {
        return ret;
    }
    
    ret = sql_alloc_mem(query_stmt->context, sizeof(expr_node_t), (void **)&col_node);
    if (ret != OG_SUCCESS) {
        return ret;
    }
    
    col_expr->owner = query_stmt->context;
    col_expr->next = NULL;
    col_expr->root = col_node;
    
    col_node->owner = col_expr;
    col_node->type = EXPR_NODE_COLUMN;
    col_node->value.v_col = result_col->v_col;
    col_node->value.type = OG_TYPE_COLUMN;
    col_node->typmod = result_col->typmod;
    
    *output_expr = col_expr;
    return OG_SUCCESS;
}

static status_t og_init_equality_cmp(sql_stmt_t *stmt, expr_tree_t *left_expr, cmp_node_t **cmp_out)
{
    cmp_node_t *cmp = NULL;
    
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&cmp));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&cmp->left));
    
    cmp->type = CMP_TYPE_EQUAL;
    cmp->left->owner = stmt->context;
    cmp->left->next = NULL;
    cmp->left->root = left_expr->root;
    
    *cmp_out = cmp;
    return OG_SUCCESS;
}

static status_t og_create_and_insert_equal_cond(sql_stmt_t *statement, sql_query_t *sub_qry, expr_tree_t *l_exprtr,
                                                rs_column_t *rs_col)
{
    cmp_node_t *equal_cmp = NULL;
    if (og_init_equality_cmp(statement, l_exprtr, &equal_cmp) != OG_SUCCESS) {
        return OG_ERROR;
    }
    
    expr_tree_t *right_expr = NULL;
    if (rs_col->type == RS_COL_COLUMN) {
        if (og_build_column_reference(statement, rs_col, &right_expr) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        right_expr = rs_col->expr;
    }
    equal_cmp->right = right_expr;
    
    visit_assist_t visit_ctx;
    sql_init_visit_assist(&visit_ctx, NULL, sub_qry);
    if (visit_expr_tree(&visit_ctx, right_expr, og_modify_query_cond_col) != OG_SUCCESS) {
        return OG_ERROR;
    }
    
    cond_node_t *equality_cond = NULL;
    if (sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)&equality_cond) != OG_SUCCESS) {
        return OG_ERROR;
    }
    equality_cond->type = COND_NODE_COMPARE;
    equality_cond->cmp = equal_cmp;
    
    if (sub_qry->cond == NULL) {
        if (sql_create_cond_tree(statement->context, &sub_qry->cond) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    
    return sql_add_cond_node(sub_qry->cond, equality_cond);
}

static status_t og_in2exists_inter(sql_stmt_t *statement, sql_query_t *sub_qry, cmp_node_t *cmp, bool32 *is_gen_cmp)
{
    uint32_t m = 0;
    rs_column_t *rs_col = NULL;
    expr_node_t *l_exprn = NULL;
    expr_node_t *rs_exprn = NULL;
    expr_tree_t *l_exprtr = cmp->left;
    galist_t *parent_refs = sub_qry->owner->parent_refs;

    while (l_exprtr != NULL) {
        rs_col = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, m);
        l_exprn = l_exprtr->root;
        if (is_gen_cmp[m]) {
            // adjust parent refs
            if (l_exprn->type == EXPR_NODE_COLUMN) {
                l_exprn->value.v_col.ancestor += 1;
                OG_RETURN_IFERR(sql_add_parent_refs(statement, parent_refs, l_exprn->value.v_col.tab, l_exprn));
            } else {
                l_exprn->value.v_rid.ancestor += 1;
                OG_RETURN_IFERR(sql_add_parent_refs(statement, parent_refs, l_exprn->value.v_rid.tab_id, l_exprn));
            }
            SET_ANCESTOR_LEVEL(sub_qry->owner, l_exprn->value.v_col.ancestor);
            OG_RETURN_IFERR(og_create_and_insert_equal_cond(statement, sub_qry, l_exprtr, rs_col));
        } else {
            rs_exprn = rs_col->expr->root;
            if (rs_exprn->type == EXPR_NODE_COLUMN) {
                sql_del_parent_refs(parent_refs, rs_exprn->value.v_col.tab, rs_exprn);
            } else {
                sql_del_parent_refs(parent_refs, rs_exprn->value.v_rid.tab_id, rs_exprn);
            }
            if (parent_refs->count == 0) {
                RESET_ANCESTOR_LEVEL(sub_qry->owner, PARENT_IDX);
            }
        }
        m++;
        l_exprtr = l_exprtr->next;
    }
    // modify rs columns to 1
    OG_RETURN_IFERR(og_modify_rs_cols2const(statement, sub_qry));
    sql_set_exists_query_flag(statement, sub_qry->owner->root);
    // change IN / NOT IN to EXISTS / NOT EXISTS
    if (cmp->type == CMP_TYPE_IN) {
        cmp->type = CMP_TYPE_EXISTS;
    } else {
        cmp->type = CMP_TYPE_NOT_EXISTS;
    }
    cmp->left = NULL;
    sub_qry->cond_has_acstor_col = OG_TRUE;

    return OG_SUCCESS;
}

static bool32 check_subqry_rs_col(sql_query_t *sub_qry, rs_column_t *column, cmp_type_t type)
{
    bool32 result = OG_TRUE;
    cols_used_t expr_cols;
    bool32 need_check_nullable = OG_FALSE;

    // 首先检查无法处理的条件
    if (OG_BIT_TEST(column->rs_flag, RS_COND_UNABLE)) {
        result = OG_FALSE;
    } else if (RS_COL_CALC == column->type) {
        // 处理计算列的情况
        init_cols_used(&expr_cols);
        sql_collect_cols_in_expr_tree(column->expr, &expr_cols);

        // 检查是否包含子查询
        if (HAS_SUBSLCT(&expr_cols)) {
            result = OG_FALSE;
        } else if (CMP_TYPE_IN == type) {
            // IN类型比较时，计算列直接返回true
            result = OG_TRUE;
        } else {
            // 非IN类型比较时，继续检查父查询引用和严格非空性
            result = !HAS_PRNT_OR_ANCSTR_COLS(expr_cols.flags);
            need_check_nullable = OG_TRUE;
        }
    } else if (CMP_TYPE_IN == type) {
        // 非计算列但为IN类型比较时，直接返回true
        result = OG_TRUE;
    } else {
        // 非计算列且非IN类型比较时，需要检查严格非空性
        need_check_nullable = OG_TRUE;
    }

    // 统一处理严格非空性检查
    if (need_check_nullable) {
        result = result && !OG_BIT_TEST(column->rs_flag, RS_STRICT_NULLABLE);
    }

    return result;
}

static status_t og_in2exists(sql_stmt_t *statement, sql_query_t *qry, cmp_node_t *cmp)
{
    int32 m = 0;
    bool32 is_gen_cmp[MAX_IN2EXISTS_ELEM_COUNT] = { 0 };

    OG_RETSUC_IFTRUE(!check_cmp_trans2exists(statement, qry, cmp));

    sql_select_t *slct = (sql_select_t *)cmp->right->root->value.v_obj.ptr;
    sql_query_t *sub_qry = slct->first_query;
    expr_tree_t *l_exprtr = cmp->left;
    // check is cur rs column need generate an new condition
    while (l_exprtr != NULL) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, m);
        bool32 left_null = (bool32)(l_exprtr->root->type == EXPR_NODE_COLUMN &&
                                    check_column_nullable(qry, &l_exprtr->root->value.v_col));
        bool32 right_null = (bool32)!check_subqry_rs_col(sub_qry, col, cmp->type);
        // if this col-rs_col need generate equal condtion, maybe let whole condition not equal
        if (check_need_generate_cmp(l_exprtr->root, col)) {
            // when condition is NOT IN, col's nullable transform maybe not equal
            OG_RETSUC_IFTRUE(cmp->type == CMP_TYPE_NOT_IN && (left_null || right_null));
            OG_RETSUC_IFTRUE(OG_BIT_TEST(col->rs_flag, RS_COND_UNABLE));
            OG_RETSUC_IFTRUE(NODE_IS_RES_ROWID(l_exprtr->root) || NODE_IS_COLUMN_ROWID(l_exprtr->root));
            OG_RETSUC_IFTRUE(col->type == RS_COL_CALC && !og_verify_computed_columns(sub_qry, col, cmp->type));
            is_gen_cmp[m] = OG_TRUE;
        }
        if (cmp->type == CMP_TYPE_IN && left_null) {
            is_gen_cmp[m] = OG_TRUE;
        }
        m++;
        l_exprtr = l_exprtr->next;
    }

    return og_in2exists_inter(statement, sub_qry, cmp, is_gen_cmp);
}

static inline void og_reset_ancestor_level(sql_select_t *select, uint32 level)
{
    sql_select_t *curslct = select;
    while (level > 0 && curslct != NULL) {
        RESET_ANCESTOR_LEVEL(curslct, level);
        curslct = (curslct->parent != NULL) ? curslct->parent->owner : NULL;
        level--;
    }
}

static void og_del_parent_refs(sql_query_t *qry, cols_used_t *cols_record)
{
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

void og_del_parent_refs_in_cond(sql_query_t *qry, cond_node_t *cond)
{
    cols_used_t cols_record;
    init_cols_used(&cols_record);
    sql_collect_cols_in_cond(cond, &cols_record);
    og_del_parent_refs(qry, &cols_record);
}

static void og_del_parent_refs_in_expr_node(sql_query_t *qry, expr_node_t *exprn)
{
    cols_used_t cols_record;
    init_cols_used(&cols_record);
    sql_collect_cols_in_expr_node(exprn, &cols_record);
    og_del_parent_refs(qry, &cols_record);
}

static inline void og_exists_remove_connect_by(sql_query_t *qry)
{
    if (qry->connect_by_cond == NULL || qry->having_cond != NULL || qry->filter_cond != NULL || qry->cond != NULL) {
        return;
    }
    og_del_parent_refs_in_cond(qry, qry->connect_by_cond->root);
    qry->connect_by_cond = NULL;
    qry->cond = qry->start_with_cond;
    qry->start_with_cond = NULL;
}

static void og_exists_remove_group_by(sql_query_t *qry)
{
    if (qry->group_sets->count != 1 || qry->having_cond != NULL) {
        return;
    }

    uint32 i = 0;
    group_set_t *group = NULL;
    group = (group_set_t *)cm_galist_get(qry->group_sets, 0);
    while (i < group->count) {
        expr_tree_t *expr = (expr_tree_t *)cm_galist_get(group->items, i++);
        og_del_parent_refs_in_expr_tree(qry, expr);
    }
    cm_galist_reset(qry->group_sets);
}

static void og_exists_remove_order_by(sql_query_t *qry)
{
    if (qry->sort_items->count == 0) {
        return;
    }
    uint32 i = 0;
    sort_item_t *sort_item = NULL;

    while (i < qry->sort_items->count) {
        sort_item = (sort_item_t *)cm_galist_get(qry->sort_items, i++);
        og_del_parent_refs_in_expr_tree(qry, sort_item->expr);
    }
    qry->order_siblings = OG_FALSE;
    cm_galist_reset(qry->sort_items);
}

static void og_exists_remove_winsort(sql_query_t *qry)
{
    if (qry->winsort_list->count == 0) {
        return;
    }
    uint32 i = 0;
    rs_column_t *rs_col = NULL;

    while (i < qry->winsort_rs_columns->count) {
        rs_col = (rs_column_t *)cm_galist_get(qry->winsort_rs_columns, i++);
        if (rs_col->type == RS_COL_CALC && rs_col->expr != NULL) {
            og_del_parent_refs_in_expr_tree(qry, rs_col->expr);
        }
    }

    cm_galist_reset(qry->winsort_rs_columns);
    cm_galist_reset(qry->winsort_list);
}

static status_t og_exists_remove_rs_columns(sql_stmt_t *statement, sql_query_t *qry)
{
    uint32 i = 0;
    galist_t *rs_cols = NULL;
    rs_column_t *rs_col = NULL;

    rs_cols = qry->rs_columns;
    while (i < rs_cols->count) {
        rs_col = (rs_column_t *)cm_galist_get(rs_cols, i++);
        if (rs_col->type == RS_COL_CALC && rs_col->expr != NULL) {
            og_del_parent_refs_in_expr_tree(qry, rs_col->expr);
        }
    }
    OG_RETURN_IFERR(og_modify_rs_cols2const(statement, qry));
    OG_BIT_RESET(rs_col->rs_flag, RS_SINGLE_COL);

    return OG_SUCCESS;
}

static status_t collect_and_update_aggr_inter(visit_assist_t *visit, expr_node_t **node)
{
    OG_RETSUC_IFTRUE((*node)->type != EXPR_NODE_AGGR);
    galist_t *aggrs = visit->query->aggrs;
    expr_node_t *aggr_node = (expr_node_t *)cm_galist_get(aggrs, (*node)->value.v_int);
    galist_t *dst = (galist_t *)visit->param0;
    // only in having aggr will be reservered ,so we need adjust idx of than exprn
    (*node)->value.v_int = dst->count;
    return cm_galist_insert(dst, aggr_node);
}

static status_t og_collect_aggrs(sql_query_t *qry, galist_t *aggrs)
{
    visit_assist_t visit;
    sql_init_visit_assist(&visit, NULL, qry);
    visit.param0 = (void *)aggrs;
    return visit_cond_node(&visit, qry->having_cond->root, collect_and_update_aggr_inter);
}

static status_t og_delete_aggrs(sql_stmt_t *statement, sql_query_t *qry)
{
    OG_RETSUC_IFTRUE(qry->aggrs->count == 0 || (qry->having_cond != NULL && qry->group_sets->count == 0));
    uint32 m = 0;
    galist_t having_aggrs;
    expr_node_t *exprn = NULL;
    expr_node_t *aggr_exprn = NULL;
    cm_galist_init(&having_aggrs, statement, sql_stack_alloc);

    if (qry->having_cond != NULL && (qry->having_cond->incl_flags & SQL_INCL_AGGR)) {
        OG_RETURN_IFERR(og_collect_aggrs(qry, &having_aggrs));
    }
    // erase aggrs which are not in having
    while (m < qry->aggrs->count) {
        bool32 is_found = OG_FALSE;
        aggr_exprn = (expr_node_t *)cm_galist_get(qry->aggrs, m++);
        for (uint32 n = 0; n < having_aggrs.count; n++) {
            exprn = (expr_node_t *)cm_galist_get(&having_aggrs, n);
            if (exprn == aggr_exprn) {
                is_found = OG_TRUE;
                break;
            }
        }
        if (!is_found) {
            og_del_parent_refs_in_expr_node(qry, aggr_exprn);
        }
    }
    cm_galist_reset(qry->aggrs);
    return cm_galist_copy(qry->aggrs, &having_aggrs);
}

status_t og_transf_optimize_exists(sql_stmt_t *statement, cond_node_t *cond)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_exists_transform, OG_INVALID_ID32)) {
        OG_LOG_DEBUG_INF("_OPTIM_SIMPLIFY_EXISTS_SUBQ has been shutted");
        return OG_SUCCESS;
    }

    OG_RETSUC_IFTRUE(cond == NULL || cond->cmp == NULL);
    sql_select_t *sub_slct = NULL;
    sql_query_t *sub_qry = NULL;
    cmp_node_t *cmp = cond->cmp;

    OG_RETSUC_IFTRUE(cmp->type != CMP_TYPE_EXISTS && cmp->type != CMP_TYPE_NOT_EXISTS);

    sub_slct = (sql_select_t *)cmp->right->root->value.v_obj.ptr;
    // has more than one element or set operation will not trans
    OG_RETSUC_IFTRUE(sub_slct->root->type != SELECT_NODE_QUERY || cmp->right->next != NULL);

    sub_qry = sub_slct->first_query;
    OG_RETSUC_IFTRUE(QUERY_HAS_ROWNUM(sub_qry) || sub_qry->group_sets->count > 1 ||
                     (sub_qry->limit.count != NULL || sub_qry->limit.offset != NULL));

    // rs column has aggr , sub_slct always return one row
    if (sub_qry->group_sets->count == 0 && sub_qry->having_cond == NULL && sub_qry->aggrs->count > 0) {
        cond->type = (cmp->type == CMP_TYPE_EXISTS) ? COND_NODE_TRUE : COND_NODE_FALSE;
        return OG_SUCCESS;
    }

    // erase distinct
    if (sub_qry->has_distinct) {
        cm_galist_reset(sub_qry->distinct_columns);
        sub_qry->has_distinct = OG_FALSE;
    }
    // erase aggr which not in having condition
    OG_RETURN_IFERR(og_delete_aggrs(statement, sub_qry));

    og_exists_remove_connect_by(sub_qry);

    og_exists_remove_group_by(sub_qry);

    og_exists_remove_order_by(sub_qry);

    og_exists_remove_winsort(sub_qry);

    return og_exists_remove_rs_columns(statement, sub_qry);
}

static status_t og_process_exists_conditions_recursive(sql_stmt_t *sql_stmt, sql_query_t *query, cond_node_t *cond_node)
{
    status_t result = OG_SUCCESS;

    switch (cond_node->type) {
        case COND_NODE_COMPARE:
            return og_transf_optimize_exists(sql_stmt, cond_node);

        case COND_NODE_AND:
        case COND_NODE_OR:
            result = og_process_exists_conditions_recursive(sql_stmt, query, cond_node->left);
            if (result != OG_SUCCESS) {
                return result;
            }
            result = og_process_exists_conditions_recursive(sql_stmt, query, cond_node->right);
            if (result != OG_SUCCESS) {
                return result;
            }
            try_eval_logic_cond(sql_stmt, cond_node);
            return OG_SUCCESS;

        default:
            break;
    }

    return result;
}

static status_t og_process_in_conditions_recursive(sql_stmt_t *sql_stmt, sql_query_t *query, cond_node_t *cond_node)
{
    status_t result = OG_SUCCESS;

    switch (cond_node->type) {
        case COND_NODE_COMPARE:
            result = og_in2exists(sql_stmt, query, cond_node->cmp);
            if (result != OG_SUCCESS) {
                return result;
            }
            return og_transf_optimize_exists(sql_stmt, cond_node);

        case COND_NODE_AND:
            result = og_process_in_conditions_recursive(sql_stmt, query, cond_node->left);
            if (result != OG_SUCCESS) {
                return result;
            }
            result = og_process_in_conditions_recursive(sql_stmt, query, cond_node->right);
            if (result != OG_SUCCESS) {
                return result;
            }
            try_eval_logic_cond(sql_stmt, cond_node);
            return OG_SUCCESS;

        case COND_NODE_OR:
            result = og_process_exists_conditions_recursive(sql_stmt, query, cond_node->left);
            if (result != OG_SUCCESS) {
                return result;
            }
            result = og_process_exists_conditions_recursive(sql_stmt, query, cond_node->right);
            if (result != OG_SUCCESS) {
                return result;
            }
            try_eval_logic_cond(sql_stmt, cond_node);
            return OG_SUCCESS;

        default:
            break;
    }

    return result;
}

status_t og_transf_in2exists(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_in_transform, OG_INVALID_ID32)) {
        OG_LOG_DEBUG_INF("_OPTIM_IN_TRANSFORM has been shutted");
        return OG_SUCCESS;
    }

    cond_tree_t *cond = qry->cond;
    if (cond == NULL) {
        OG_LOG_DEBUG_INF("[IN2EXISTS]no condition in qry");
        return OG_SUCCESS;
    }

    return og_process_in_conditions_recursive(statement, qry, cond->root);
}