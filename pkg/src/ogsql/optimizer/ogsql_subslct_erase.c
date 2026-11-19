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
#include "ogsql_subslct_erase.h"
#include "ogsql_verifier.h"
#include "ogsql_transform.h"
#include "knl_database.h"
#include "srv_instance.h"

static bool32 og_check_if_parent_ref_level_meet(galist_t *refs, uint32 ancestor_level)
{
    // meet
    if (!refs) {
        return OG_TRUE;
    }

    parent_ref_t *ref = NULL;
    expr_node_t *expr_node = NULL;
    uint32 i = 0;
    while (i < refs->count) {
        ref = (parent_ref_t *)cm_galist_get(refs, i++);
        uint32 j = 0;
        while (j < ref->ref_columns->count) {
            expr_node = (expr_node_t *)cm_galist_get(ref->ref_columns, j++);
            expr_node = sql_get_origin_ref(expr_node);
            if (ANCESTOR_OF_NODE(expr_node) >= ancestor_level) {
                return OG_FALSE;
            }
        }
    }
    return OG_TRUE;
}

static bool32 og_check_if_subselect_level_meet(sql_query_t *qry)
{
    uint32 i = 0;
    sql_select_t *select = NULL;
    sql_array_t *array = &qry->ssa;
    while (i < array->count) {
        select = (sql_select_t *)sql_array_get(array, i++);
        if (!og_check_if_parent_ref_level_meet(select->parent_refs, OG_GENERATIONS_1)) {
            return OG_FALSE;
        }
    }

    i = 0;
    sql_table_t *table = NULL;
    array = &qry->tables;
    while (i < array->count) {
        table = (sql_table_t *)sql_array_get(array, i++);
        if ((og_subslct_is_subtbl(table)) &&
            !og_check_if_parent_ref_level_meet(table->select_ctx->parent_refs, OG_GENERATIONS_1)) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

// check column reference in the subselect in ssa.
static bool32 og_check_column_ref_ssa(sql_stmt_t *statement, sql_query_t *qry)
{
    uint32 i = 0;
    sql_select_t *select = NULL;
    sql_array_t *array = &qry->ssa;
    while (i < array->count) {
        select = (sql_select_t *)sql_array_get(array, i++);
        if (select->has_ancestor) {
            // select (select a from t2 where t2.b=t1.b) from t1; the second select has ancestor.
            return OG_FALSE;
        }
        // the subselect of ssa column ref is over the level
        if (!og_check_if_subselect_level_meet(select->first_query)) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 og_check_column_ref_subtable(sql_stmt_t *statement, sql_query_t *qry)
{
    uint32 i = 0;
    sql_table_t *table = NULL;
    sql_select_t *select = NULL;
    sql_array_t *array = &qry->tables;
    while (i < array->count) {
        table = (sql_table_t *)sql_array_get(array, i++);
        if (og_subslct_is_subtbl(table)) {
            select = table->select_ctx;
            if (!og_check_if_parent_ref_level_meet(select->parent_refs, OG_GENERATIONS_2)) {
                return OG_FALSE;
            }
            // the subselect of subtable column ref is over the level
            if (!og_check_if_subselect_level_meet(select->first_query)) {
                return OG_FALSE;
            }
        }
    }

    return OG_TRUE;
}

static bool32 og_check_column_ref_owner(sql_stmt_t *statement, sql_query_t *qry)
{
    uint32 generations = OG_GENERATIONS_2 + 1;
    for (sql_query_t *cur = qry; cur && cur->owner; cur = cur->owner->parent) {
        if (!og_check_if_parent_ref_level_meet(cur->owner->parent_refs, generations++)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 og_check_column_ref(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!og_check_column_ref_ssa(statement, qry)) {
        return OG_FALSE;
    }

    if (!og_check_column_ref_subtable(statement, qry)) {
        return OG_FALSE;
    }

    if (!og_check_column_ref_owner(statement, qry)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 og_check_query_if_subselect_can_erase(sql_stmt_t *statement, sql_query_t *qry)
{
    // no pivot
    if (qry->pivot_items != NULL) {
        return OG_FALSE;
    }

    // no windown function
    if (qry->winsort_list->count > 0) {
        return OG_FALSE;
    }

    // no group advanced usage:cube .etc
    if (qry->group_sets->count > 1) {
        return OG_FALSE;
    }

    if (!og_check_column_ref(statement, qry)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 og_check_query_if_complex_sql(sql_query_t *qry, uint32 flag)
{
    if (qry->has_distinct) {
        return OG_TRUE;
    }

    if (!(flag & OG_COMPLEX_SQL_FLAG_IGNORE_GROUP) && qry->group_sets->count > 0) {
        return OG_TRUE;
    }

    if (!(flag & OG_COMPLEX_SQL_FLAG_IGNORE_AGGR) && qry->aggrs->count > 0) {
        return OG_TRUE;
    }

    if (qry->connect_by_cond || qry->pivot_items || qry->winsort_list->count > 0) {
        return OG_TRUE;
    }

    if (qry->limit.count || qry->limit.offset) {
        return OG_TRUE;
    }

    if (!(flag & OG_COMPLEX_SQL_FLAG_IGNORE_ORDER) && qry->sort_items->count > 0) {
        return OG_TRUE;
    }

    if (ROWNUM_COND_OCCUR(qry->cond)) {
        return OG_TRUE;
    }

    if (HAS_HINT(qry->hint_info)) {
        return OG_TRUE;
    }

    if (!(flag & OG_COMPLEX_SQL_FLAG_IGNORE_RMKYE) && qry->remote_keys) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 og_check_table_if_complex_sql(sql_query_t *qry, sql_table_t *tbl)
{
    sql_query_t *subq = tbl->select_ctx->first_query;
    if (og_check_query_if_complex_sql(subq, OG_COMPLEX_SQL_FLAG_IGNORE_RMKYE)) {
        return OG_TRUE;
    }

    if (qry->connect_by_cond && subq->cond && subq->cond->root->type != COND_NODE_TRUE) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 og_check_table_if_ref_ssa(sql_query_t *qry)
{
    uint32 i = 0;
    sql_select_t *select = NULL;
    sql_array_t *array = &qry->ssa;
    while (i < array->count) {
        select = (sql_select_t *)sql_array_get(array, i++);
        if (select->has_ancestor) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static inline bool32 og_check_table_if_dummy_table(sql_table_t *tbl)
{
    sql_query_t *qry = tbl->select_ctx->first_query;
    sql_table_t *tab = (sql_table_t *)sql_array_get(&qry->tables, 0);
    return og_check_if_dual(tab);
}

static bool32 og_check_right_tab_recursion(sql_stmt_t *statement, sql_join_node_t *jnode, uint32 tabid)
{
    if (jnode->type == JOIN_TYPE_FULL) {
        return OG_TRUE;
    }
    if (jnode->type == JOIN_TYPE_NONE) {
        return OG_FALSE;
    }

    if (sql_stack_safe(statement)) {
        return OG_TRUE;
    }

    if (jnode->type == JOIN_TYPE_LEFT && sql_table_in_list(&jnode->right->tables, tabid)) {
        return OG_TRUE;
    }

    if (jnode->type == JOIN_TYPE_RIGHT && sql_table_in_list(&jnode->left->tables, tabid)) {
        return OG_TRUE;
    }

    if (og_check_right_tab_recursion(statement, jnode->left, tabid)) {
        return OG_TRUE;
    }

    return og_check_right_tab_recursion(statement, jnode->right, tabid);
}

// can not do if subselect is right table of outer join and has condition.
// for example: select * from t left join (select a,b from t2 where b > 2) subselect on 1=1; for now it can not be
// rewrite. in the future, we maybe support this case. ==> SELECT t.*, t2.a, t2.b FROM t LEFT JOIN t2 ON t2.b > 2; if
// fail return true
static inline bool32 og_check_table_if_right_table_fail(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl)
{
    if (tbl->select_ctx->first_query->cond && qry->join_assist.outer_node_count) {
        return og_check_right_tab_recursion(statement, qry->join_assist.join_node, tbl->id);
    }
    return OG_FALSE;
}

// return true if can not rewrite.
// check result colunms is simple enough.
static bool32 og_check_table_if_result_cols(sql_table_t *tbl)
{
    sql_query_t *q = tbl->select_ctx->first_query;
    rs_column_t *col = NULL;
    uint32 m = 0;
    while (m < q->rs_columns->count) {
        col = (rs_column_t *)cm_galist_get(q->rs_columns, m++);
        if (col->datatype == OG_TYPE_ARRAY) {
            return OG_TRUE;
        }

        if (col->type == RS_COL_COLUMN && col->v_col.is_array) {
            return OG_TRUE;
        }

        if (col->type == RS_COL_CALC && (!TREE_IS_RES_NULL(col->expr)) && (!TREE_IS_CONST(col->expr)) &&
            (!TREE_IS_BINDING_PARAM(col->expr))) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static inline bool32 og_check_one_view_if_erase(text_t *user, sql_table_t *tbl, sql_table_t *sub_tbl)
{
    if (tbl->version.type == CURR_VERSION && (tbl->entry->dc.oid >= MAX_SYS_OBJECTS || tbl->entry->dc.uid) &&
        cm_text_equal(&tbl->user.value, &sub_tbl->user.value) && cm_text_equal(&tbl->user.value, user)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}
// check whether current user has privilege of the view
static bool32 og_check_view_if_erase(sql_stmt_t *statement, sql_query_t *subq, sql_table_t *tbl)
{
    if (tbl->type != VIEW_AS_TABLE) {
        return OG_TRUE;
    }

    uint32 m = 0;
    while (m < subq->tables.count) {
        sql_table_t *sub_tab = (sql_table_t *)sql_array_get(&subq->tables, m++);
        if (!og_check_one_view_if_erase(&statement->session->curr_user, tbl, sub_tab)) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

typedef bool32 (*subselect_erase_check_func_t)(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl);

static bool32 check_is_valid_subselect_type(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER(tbl);
    return (og_subslct_is_subtbl(tbl) &&
            !tbl->ineliminable &&
            !tbl->view_dml &&
            tbl->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN);
}

static bool32 check_references_in_ssa(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER3(tbl, tbl->select_ctx, tbl->select_ctx->first_query);
    return og_check_table_if_ref_ssa(tbl->select_ctx->first_query);
}

static bool32 check_view_eligibility(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER3(tbl, tbl->select_ctx, tbl->select_ctx->first_query);
    return og_check_view_if_erase(stmt, tbl->select_ctx->first_query, tbl);
}

static bool32 check_complexity(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER2(tbl, qry);
    return !og_check_table_if_complex_sql(qry, tbl);
}

static bool32 check_single_query_node(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER2(tbl, tbl->select_ctx);
    return (tbl->select_ctx->root->type == SELECT_NODE_QUERY);
}

static bool32 check_single_table_in_subquery(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER3(tbl, tbl->select_ctx, tbl->select_ctx->first_query);
    return (tbl->select_ctx->first_query->tables.count == 1);
}

static bool32 check_dummy_table(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER(tbl);
    return !og_check_table_if_dummy_table(tbl);
}

static bool32 check_result_columns(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER(tbl);
    return !og_check_table_if_result_cols(tbl);
}

static bool32 check_right_table_conditions(sql_stmt_t *stmt, sql_query_t *qry, sql_table_t *tbl)
{
    CM_POINTER3(stmt, qry, tbl);
    return !og_check_table_if_right_table_fail(stmt, qry, tbl);
}
static const struct {
    subselect_erase_check_func_t func;
    const char* brief;
} g_subselect_erase_checks[] = {
    {check_is_valid_subselect_type,     "Check Valid Subselect Type"},
    {check_references_in_ssa,           "Check References In SSA"},
    {check_view_eligibility,            "Check View Eligibility"},
    {check_complexity,                  "Check Query Complexity"},
    {check_single_query_node,           "Check Single Query Node"},
    {check_single_table_in_subquery,    "Check Single Table In Subquery"},
    {check_dummy_table,                 "Check if Dummy Table"},
    {check_result_columns,              "Check Result Columns"},
    {check_right_table_conditions,      "Check Right Table Conditions"},
};

#define NUM_CHECKS (sizeof(g_subselect_erase_checks) / sizeof(g_subselect_erase_checks[0]))

// check table of subselect
static bool32 og_check_table_if_subselect_can_erase(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl)
{
    for (uint32 i = 0; i < NUM_CHECKS; i++) {
        if (!g_subselect_erase_checks[i].func(statement, qry, tbl)) {
            OG_LOG_DEBUG_INF("[SUBSLCT_ERASE]: Subselect elimination not pass at step [%u : %s]",
                i, g_subselect_erase_checks[i].brief);
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static status_t og_modify_expr_col_4_child(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_COLUMN || (*exprn)->type == EXPR_NODE_TRANS_COLUMN) {
        if ((*exprn)->value.v_col.ancestor) {
            (*exprn)->value.v_col.ancestor--;
        } else {
            sql_query_t *qry = (sql_query_t *)v_ast->param0;
            sql_table_t *tab = (sql_table_t *)sql_array_get(&qry->tables, 0);
            var_column_t *vcol = &(*exprn)->value.v_col;
            query_field_t field;
            (*exprn)->value.v_col.tab = v_ast->result0;
            SQL_SET_QUERY_FIELD_INFO(&field, vcol->datatype, vcol->col, vcol->is_array, vcol->ss_start, vcol->ss_end);
            if (sql_table_cache_cond_query_field(v_ast->stmt, tab, &field)) {
                OG_LOG_DEBUG_ERR("Failed to cache condition query field, tabid=%u", v_ast->result0);
                return OG_ERROR;
            }
        }
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_RESERVED && NODE_IS_RES_ROWID((*exprn))) {
        if ((*exprn)->value.v_rid.ancestor) {
            (*exprn)->value.v_rid.ancestor--;
        } else {
            sql_query_t *qry = (sql_query_t *)v_ast->param0;
            sql_table_t *tab = (sql_table_t *)sql_array_get(&qry->tables, 0);
            (*exprn)->value.v_rid.tab_id = tab->id;
        }
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_GROUP && (*exprn)->value.v_vm_col.ancestor) {
        (*exprn)->value.v_vm_col.ancestor--;
        expr_node_t *origin = sql_get_origin_ref(*exprn);
        if (NODE_IS_RES_ROWID(origin) && ROWID_NODE_ANCESTOR(origin)) {
            origin->value.v_rid.ancestor--;
        } else if (origin->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(origin)) {
            origin->value.v_col.ancestor--;
        }
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_SELECT) {
        uint32 i = 0;
        while (i < v_ast->query->ssa.count) {
            pointer_t p = sql_array_get(&v_ast->query->ssa, i);
            if ((*exprn)->value.v_obj.ptr == p) {
                (*exprn)->value.v_obj.id = i;
            }
            i++;
        }
    }

    return OG_SUCCESS;
}

static status_t og_modify_special_table(visit_assist_t *v_ast, sql_query_t *subqry)
{
    sql_table_t *tab = (sql_table_t *)sql_array_get(&subqry->tables, 0);
    expr_tree_t *tree = NULL;
    if (tab->type == FUNC_AS_TABLE) {
        tree = tab->func.args;
    } else if (tab->type == JSON_TABLE) {
        tree = tab->json_table_info->data_expr;
    }

    if (tree && visit_expr_tree(v_ast, tree, og_modify_expr_col_4_child)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t og_erase_subselect_modify_child(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl)
{
    sql_query_t *subq = tbl->select_ctx->first_query;
    rs_column_t *col = NULL;
    uint32 m = 0;
    visit_assist_t va;
    sql_init_visit_assist(&va, statement, qry);
    va.result0 = tbl->id;
    va.param0 = subq;

    // modify result columns
    while (m < subq->rs_columns->count) {
        col = (rs_column_t *)cm_galist_get(subq->rs_columns, m++);
        if (col->type != RS_COL_COLUMN) {
            if (visit_expr_tree(&va, col->expr, og_modify_expr_col_4_child)) {
                OG_LOG_DEBUG_ERR("Failed to visit expr tree.");
                return OG_ERROR;
            }
        } else if (col->v_col.ancestor) {
            col->v_col.ancestor--;
        } else {
            col->v_col.tab = tbl->id;
        }
    }

    // pull up subquery ssa
    m = 0;
    sql_select_t *select;
    while (m < subq->ssa.count) {
        select = (sql_select_t *)sql_array_get(&subq->ssa, m++);
        if (sql_array_put(&qry->ssa, select)) {
            return OG_ERROR;
        }
        select->parent = qry;
    }
    subq->ssa.count = 0;

    // process subquery condition
    if (subq->cond && visit_cond_node(&va, subq->cond->root, og_modify_expr_col_4_child)) {
        return OG_ERROR;
    }

    return og_modify_special_table(&va, subq);
}

static status_t setup_query_field(visit_assist_t *v_ast, sql_table_t *tbl, expr_node_t *exprn, rs_column_t *col)
{
    query_field_t qry_field = { 0 };
    qry_field.datatype = exprn->datatype;
    qry_field.col_id = col->v_col.col;
    qry_field.is_array = col->v_col.is_array;
    qry_field.start = col->v_col.ss_start;
    qry_field.end = col->v_col.ss_end;

    exprn->value.v_col = col->v_col;
    exprn->value.v_col.tab = v_ast->result0;

    return sql_table_cache_cond_query_field(v_ast->stmt, tbl, &qry_field);
}

static status_t og_modify_expr_col_4_parent(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expr_node_t *node = *exprn;

    if (node->type != EXPR_NODE_COLUMN && node->type != EXPR_NODE_TRANS_COLUMN) {
        return OG_SUCCESS;
    }

    sql_query_t *subq = (sql_query_t *)v_ast->param0;
    sql_table_t *tbl = (sql_table_t *)sql_array_get(&subq->tables, 0);

    if (v_ast->result0 != NODE_TAB(node) || NODE_ANCESTOR(node) != 0) {
        return OG_SUCCESS;
    }

    rs_column_t *col = cm_galist_get(subq->rs_columns, NODE_COL(node));

    if (col->type != RS_COL_COLUMN) {
        node->type = col->expr->root->type;
        node->typmod = col->typmod;
        var_copy(&col->expr->root->value, &node->value);
        return OG_SUCCESS;
    }

    return setup_query_field(v_ast, tbl, node, col);
}

static status_t og_modify_parent_group(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    if (qry->group_sets->count == 0) {
        return OG_SUCCESS;
    }

    group_set_t *group_set = (group_set_t *)cm_galist_get(qry->group_sets, 0);
    uint32 m = 0;
    while (m < group_set->items->count) {
        expr_tree_t *expr = (expr_tree_t *)cm_galist_get(group_set->items, m++);
        if (visit_expr_tree(v_ast, expr, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static inline status_t og_modify_and_cache_col(sql_stmt_t *statement, sql_table_t *tbl, rs_column_t *trg_col,
                                               var_column_t *src_col, uint16 tabid)
{
    trg_col->v_col = *src_col;
    trg_col->v_col.tab = tabid;
    query_field_t field = { 0 };
    field.is_array = trg_col->v_col.is_array;
    field.start = trg_col->v_col.ss_start;
    field.end = trg_col->v_col.ss_end;
    field.datatype = trg_col->datatype;
    field.col_id = trg_col->v_col.col;
    return sql_table_cache_query_field(statement, tbl, &field);
}

static status_t og_modify_parent_rs_cols_in_list(visit_assist_t *v_ast, galist_t *rs_cols)
{
    uint32 i = 0;
    while (i < rs_cols->count) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(rs_cols, i++);
        if (col->type != RS_COL_COLUMN) {
            if (visit_expr_tree(v_ast, col->expr, og_modify_expr_col_4_parent)) {
                return OG_ERROR;
            }
            continue;
        }

        if (v_ast->result0 != col->v_col.tab || col->v_col.ancestor != 0) {
            continue;
        }

        sql_query_t *subq = (sql_query_t *)v_ast->param0;
        rs_column_t *sub_col = (rs_column_t *)cm_galist_get(subq->rs_columns, col->v_col.col);
        if (sub_col->type != RS_COL_COLUMN) {
            col->type = RS_COL_CALC;
            col->expr = sub_col->expr;
        } else {
            sql_table_t *tab = (sql_table_t *)sql_array_get(&subq->tables, 0);
            OG_RETURN_IFERR(og_modify_and_cache_col(v_ast->stmt, tab, col, &sub_col->v_col, v_ast->result0));
        }
        col->rs_flag = sub_col->rs_flag;
    }

    return OG_SUCCESS;
}

static status_t og_modify_parent_rs_cols_path_nodes(visit_assist_t *v_ast)
{
    uint32 i = 0;
    galist_t *nodes = v_ast->query->path_func_nodes;
    while (i < nodes->count) {
        expr_node_t *f = (expr_node_t *)cm_galist_get(nodes, i++);
        if (visit_expr_node(v_ast, &f, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t og_modify_parent_rs_cols_group_origin(sql_query_t *qry, visit_assist_t *v_ast)
{
    if (!qry->has_distinct || qry->group_sets->count) {
        return OG_SUCCESS;
    }

    uint32 i = 0;
    while (i < qry->rs_columns->count) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(qry->rs_columns, i++);
        if (col->type != RS_COL_CALC || col->expr->root->type != EXPR_NODE_GROUP) {
            continue;
        }

        expr_node_t *ori_node = sql_get_origin_ref(col->expr->root);
        if (visit_expr_node(v_ast, &ori_node, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t og_modify_parent_rs_cols_exists_dist_cols(sql_query_t *qry, visit_assist_t *v_ast)
{
    if (!qry->exists_dist_columns) {
        return OG_SUCCESS;
    }

    uint32 i = 0;
    while (i < qry->exists_dist_columns->count) {
        expr_node_t *col_expr = (expr_node_t *)cm_galist_get(qry->exists_dist_columns, i++);
        if (visit_expr_node(v_ast, &col_expr, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t og_modify_parent_rs_cols(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    galist_t *rs_cols = v_ast->query->has_distinct ? v_ast->query->distinct_columns : v_ast->query->rs_columns;
    OG_RETURN_IFERR(og_modify_parent_rs_cols_in_list(v_ast, rs_cols));
    OG_RETURN_IFERR(og_modify_parent_rs_cols_path_nodes(v_ast));
    OG_RETURN_IFERR(og_modify_parent_rs_cols_group_origin(qry, v_ast));
    OG_RETURN_IFERR(og_modify_parent_rs_cols_exists_dist_cols(qry, v_ast));
    return OG_SUCCESS;
}

static status_t og_modify_parent_sort_items(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    uint32 m = 0;
    while (m < qry->sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(qry->sort_items, m++);
        if (visit_expr_tree(v_ast, item->expr, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_modify_parent_aggrs(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    uint32 i = 0;
    while (i < qry->aggrs->count) {
        expr_node_t *item = (expr_node_t *)cm_galist_get(qry->aggrs, i++);
        if (visit_expr_node(v_ast, &item, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_modify_parent_json_tab(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    uint32 m = 0;
    while (m < qry->tables.count) {
        sql_table_t *item = (sql_table_t *)sql_array_get(&qry->tables, m++);
        if (item->type == JSON_TABLE &&
            visit_expr_tree(v_ast, item->json_table_info->data_expr, og_modify_expr_col_4_parent)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static inline void og_collect_cmp_cond_node(biqueue_t *bque, cond_node_t *condn)
{
    for (biqueue_node_t *t = biqueue_first(bque); t != biqueue_end(bque); t = t->next) {
        if (condn->cmp == (OBJECT_OF(cond_node_t, t))->cmp) {
            return;
        }
    }
    biqueue_add_tail(bque, QUEUE_NODE_OF(condn));
}

static status_t og_collect_cond_nodes(sql_stmt_t *statement, cond_node_t *condn, biqueue_t *bque)
{
    if (sql_stack_safe(statement)) {
        return OG_ERROR;
    }

    if (condn->type == COND_NODE_COMPARE) {
        og_collect_cmp_cond_node(bque, condn);
        return OG_SUCCESS;
    }

    if (condn->type == COND_NODE_AND || condn->type == COND_NODE_OR) {
        if (og_collect_cond_nodes(statement, condn->left, bque) ||
            og_collect_cond_nodes(statement, condn->right, bque)) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t og_modify_conditions(biqueue_t *bque, visit_assist_t *v_ast, visit_func_t func)
{
    for (biqueue_node_t *t = biqueue_first(bque); t != biqueue_end(bque); t = t->next) {
        if (visit_cond_node(v_ast, OBJECT_OF(cond_node_t, t), func)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_modify_condition_node(cond_tree_t *ctree, visit_assist_t *v_ast, visit_func_t func)
{
    biqueue_t conds;
    if (!ctree || !ctree->root) {
        return OG_SUCCESS;
    }

    biqueue_init(&conds);
    if (og_collect_cond_nodes(v_ast->stmt, ctree->root, &conds)) {
        return OG_ERROR;
    }

    if (biqueue_empty(&conds)) {
        return OG_SUCCESS;
    }

    if (og_modify_conditions(&conds, v_ast, func)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t og_modify_join_condition(sql_join_node_t *jnode, visit_assist_t *v_ast, visit_func_t func)
{
    if (JOIN_TYPE_NONE == jnode->type) {
        return OG_SUCCESS;
    }

    if (og_modify_condition_node(jnode->filter, v_ast, func) ||
        og_modify_condition_node(jnode->join_cond, v_ast, func)) {
        return OG_ERROR;
    }

    if (og_modify_join_condition(jnode->left, v_ast, func) || og_modify_join_condition(jnode->right, v_ast, func)) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_modify_query_condition(sql_query_t *qry, visit_assist_t *v_ast, visit_func_t func)
{
    if (og_modify_condition_node(qry->filter_cond, v_ast, func)) {
        return OG_ERROR;
    }

    if (og_modify_condition_node(qry->cond, v_ast, func)) {
        return OG_ERROR;
    }

    if (og_modify_condition_node(qry->connect_by_cond, v_ast, func)) {
        return OG_ERROR;
    }

    if (og_modify_condition_node(qry->start_with_cond, v_ast, func)) {
        return OG_ERROR;
    }

    if (qry->join_assist.outer_node_count && og_modify_join_condition(qry->join_assist.join_node, v_ast, func)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t og_modify_having_condition(sql_query_t *qry, visit_assist_t *v_ast)
{
    cond_tree_t *ctree = qry->having_cond;
    if (!ctree) {
        return OG_SUCCESS;
    }

    return visit_cond_node(v_ast, ctree->root, og_modify_expr_col_4_parent);
}

static status_t og_modify_limit(sql_query_t *qry, visit_assist_t *v_ast)
{
    limit_item_t *limit = &qry->limit;
    if (limit->offset && visit_expr_tree(v_ast, (expr_tree_t *)limit->offset, og_modify_expr_col_4_parent)) {
        return OG_ERROR;
    }

    if (limit->count && visit_expr_tree(v_ast, (expr_tree_t *)limit->count, og_modify_expr_col_4_parent)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

typedef status_t (*subselect_modify_parent_func_t)(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast);

static status_t modify_parent_condition(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_query_condition(qry, v_ast, og_modify_expr_col_4_parent);
}

static status_t modify_parent_group_by(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_parent_group(statement, qry, v_ast);
}

static status_t modify_parent_result_columns(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_parent_rs_cols(statement, qry, v_ast);
}

static status_t modify_parent_aggregates(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_parent_aggrs(statement, qry, v_ast);
}

static status_t modify_parent_order_by(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_parent_sort_items(statement, qry, v_ast);
}

static status_t modify_parent_json_table(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_parent_json_tab(statement, qry, v_ast);
}

static status_t modify_parent_limit(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_limit(qry, v_ast);
}

static status_t modify_parent_having(sql_stmt_t *statement, sql_query_t *qry, visit_assist_t *v_ast)
{
    return og_modify_having_condition(qry, v_ast);
}

static const struct {
    subselect_modify_parent_func_t func;
    const char* brief;
} g_subselect_modify_parent_steps[] = {
    {modify_parent_condition,        "Modify Parent Conditions"},
    {modify_parent_group_by,         "Modify Parent Group By"},
    {modify_parent_result_columns,   "Modify Parent Result Columns"},
    {modify_parent_aggregates,       "Modify Parent Aggregates"},
    {modify_parent_order_by,         "Modify Parent Order By"},
    {modify_parent_json_table,       "Modify Parent JSON Table"},
    {modify_parent_limit,            "Modify Parent Limit"},
    {modify_parent_having,           "Modify Parent Having"},
};

#define NUM_MODIFY_STEPS (sizeof(g_subselect_modify_parent_steps) / sizeof(g_subselect_modify_parent_steps[0]))

static status_t og_erase_subselect_modify_parent(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl)
{
    visit_assist_t v_ast = { 0 };
    sql_init_visit_assist(&v_ast, statement, qry);
    sql_query_t *subqry = tbl->select_ctx->first_query;
    v_ast.param0 = (void *)subqry;
    v_ast.result0 = tbl->id;
    status_t status = OG_SUCCESS;

    for (uint32 i = 0; i < NUM_MODIFY_STEPS; i++) {
        status = g_subselect_modify_parent_steps[i].func(statement, qry, &v_ast);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[SUBSLCT_ERASE]: Subselect elimination modification error at step [%u: %s].",
                            i, g_subselect_modify_parent_steps[i].brief);
            return status;
        }
    }

    return status;
}

static status_t og_erase_subselect_pull_up_cond(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *subqry)
{
    if (!subqry->cond) {
        return OG_SUCCESS;
    }

    if (!qry->cond && sql_create_cond_tree(statement->context, &qry->cond)) {
        return OG_ERROR;
    }

    if (sql_add_cond_node_left(qry->cond, subqry->cond->root)) {
        return OG_ERROR;
    }

    if (qry->connect_by_cond && sql_split_filter_cond(statement, subqry->cond->root, &qry->filter_cond)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

void og_erase_subselect_remove_sel_ctx(sql_stmt_t *statement, sql_select_t *slct)
{
    sql_select_t *cur_slct = NULL;
    uint32 m = 0;
    galist_t *list = statement->context->selects;
    while (m < list->count) {
        cur_slct = (sql_select_t *)cm_galist_get(list, m);
        if (cur_slct == slct) {
            cm_galist_delete(list, m);
            return;
        }
        m++;
    }
}

static status_t og_erase_subselect_modify_table(sql_table_t *sub_tbl, sql_table_t *tbl)
{
    sub_tbl->id = tbl->id;
    return memcpy_sp(tbl, sizeof(sql_table_t), sub_tbl, sizeof(sql_table_t));
}

static inline void og_erase_subselect_modify_table_attr(sql_query_t *qry, sql_table_t *tbl)
{
    TABLE_CBO_ATTR_OWNER(tbl) = qry->vmc;

    if (OG_IS_SUBSELECT_TABLE(tbl->type)) {
        tbl->select_ctx->parent = qry;
    }
}

typedef status_t (*subselect_erase_step_func_t)(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    sql_query_t *sub_q, sql_table_t *sub_tab);

static status_t modify_child_query(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl, sql_query_t *sub_q,
    sql_table_t *sub_tab)
{
    return og_erase_subselect_modify_child(statement, qry, tbl);
}

static status_t modify_parent_query(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl, sql_query_t *sub_q,
    sql_table_t *sub_tab)
{
    return og_erase_subselect_modify_parent(statement, qry, tbl);
}

static status_t pull_up_subquery_conditions(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    sql_query_t *sub_q, sql_table_t *sub_tab)
{
    return og_erase_subselect_pull_up_cond(statement, qry, sub_q);
}

static status_t remove_subselect_context(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    sql_query_t *sub_q, sql_table_t *sub_tab)
{
    if (statement == NULL || tbl == NULL) {
        return OG_ERROR;
    }
    (void)og_erase_subselect_remove_sel_ctx(statement, tbl->select_ctx);
    return OG_SUCCESS;
}

static status_t modify_promoted_table_metadata(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    sql_query_t *sub_q, sql_table_t *sub_tab)
{
    return og_erase_subselect_modify_table(sub_tab, tbl);
}

static status_t modify_parent_query_attributes(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    sql_query_t *sub_q, sql_table_t *sub_tab)
{
    (void)og_erase_subselect_modify_table_attr(qry, tbl);
    return OG_SUCCESS;
}

static const struct {
    subselect_erase_step_func_t func;
    const char* brief;
} g_subselect_erase_core_steps[] = {
    {modify_child_query,              "Modify Child Query",             },
    {modify_parent_query,             "Modify Parent Query",            },
    {pull_up_subquery_conditions,     "Pull Up Subquery Conditions",    },
    {remove_subselect_context,        "Remove Subselect Context",       },
    {modify_promoted_table_metadata,  "Modify Promoted Table Metadata", },
    {modify_parent_query_attributes,  "Modify Parent Query Attributes", },
};

#define NUM_ERASE_CORE_STEPS (sizeof(g_subselect_erase_core_steps) / sizeof(g_subselect_erase_core_steps[0]))

static status_t og_erase_subselect_table_really(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl)
{
    sql_query_t *sub_qry = tbl->select_ctx->first_query;
    sql_table_t *sub_tbl = (sql_table_t *)sql_array_get(&sub_qry->tables, 0);
    cm_bilist_init(&sub_tbl->query_fields);

    status_t status = OG_SUCCESS;
    for (uint32 i = 0; i < NUM_ERASE_CORE_STEPS; i++) {
        status = g_subselect_erase_core_steps[i].func(statement, qry, tbl, sub_qry, sub_tbl);
        if (status != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Subselect elimination core step failed at [%u: %s].",
                            i, g_subselect_erase_core_steps[i].brief);
            return status;
        }
    }

    return status;
}

// when the subselect is simple, replace the subselect in subselect table.
static status_t og_subselect_erase(sql_stmt_t *statement, sql_query_t *qry, bool32 *check_result)
{
    *check_result = OG_FALSE;
    if (!og_check_query_if_subselect_can_erase(statement, qry)) {
        OG_LOG_DEBUG_INF("Failed to check subselect erase.");
        return OG_SUCCESS;
    }

    uint32 m = 0;
    sql_table_t *table = NULL;
    sql_array_t *array = &qry->tables;
    while (m < array->count) {
        table = (sql_table_t *)sql_array_get(array, m++);
        if (og_check_table_if_subselect_can_erase(statement, qry, table)) {
            if (og_erase_subselect_table_really(statement, qry, table) != OG_SUCCESS) {
                OG_LOG_DEBUG_ERR("Failed to erase the table of subselect.");
                return OG_ERROR;
            }
            *check_result = OG_TRUE;

            text_t *name = statement->session->current_sql.len != 0 ? &statement->session->current_sql
                                                                    : &table->qb_name;
            OG_LOG_DEBUG_INF("Succeed to erase subselect child, name=%s.", T2S(name));
        }
    }

    return OG_SUCCESS;
}

static bool32 og_check_rs_columns(sql_stmt_t *statement, sql_query_t *qry)
{
    uint32 m = 0;
    galist_t *list = qry->rs_columns;
    while (m < list->count) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(list, m++);
        if (col->type == RS_COL_COLUMN) {
            if (col->v_col.ss_start > 0) {
                return OG_FALSE;
            }
        } else {
            if (!TREE_IS_RES_NULL(col->expr) && !TREE_IS_BINDING_PARAM(col->expr) && !TREE_IS_CONST(col->expr)) {
                return OG_FALSE;
            }
        }
    }
    return OG_TRUE;
}

static status_t og_collect_cond_cols(sql_stmt_t *statement, cond_node_t *cnode, cols_used_t *cols)
{
    if (sql_stack_safe(statement)) {
        OG_LOG_RUN_ERR("sql stack is full.");
        return OG_ERROR;
    }

    if (cnode->type == COND_NODE_COMPARE) {
        sql_collect_cols_in_expr_tree(cnode->cmp->left, cols);
        sql_collect_cols_in_expr_tree(cnode->cmp->right, cols);
        return OG_SUCCESS;
    }

    if (cnode->type == COND_NODE_AND || cnode->type == COND_NODE_OR) {
        OG_RETURN_IFERR(og_collect_cond_cols(statement, cnode->left, cols));
        OG_RETURN_IFERR(og_collect_cond_cols(statement, cnode->right, cols));
    }
    return OG_SUCCESS;
}

static bool32 og_check_cols_is_simple(sql_query_t *subq, cols_used_t *cols)
{
    biqueue_t *q = &cols->cols_que[SELF_IDX];
    for (biqueue_node_t *n = biqueue_first(q); n != biqueue_end(q); n = n->next) {
        expr_node_t *col = OBJECT_OF(expr_node_t, n);
        if (col->type != EXPR_NODE_COLUMN) {
            continue;
        }

        galist_t *rs_cols = subq->rs_columns;
        rs_column_t *sub_col = (rs_column_t *)cm_galist_get(rs_cols, NODE_COL(col));
        if (sub_col->rs_flag & RS_COND_UNABLE) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 og_check_parent_one_cond(sql_stmt_t *statement, cond_tree_t *ctree, sql_query_t *subq)
{
    cols_used_t cols;
    if (ctree) {
        init_cols_used(&cols);
        if (og_collect_cond_cols(statement, ctree->root, &cols)) {
            OG_LOG_DEBUG_ERR("Failed to collect condition columns.");
            return OG_FALSE;
        }

        if (!og_check_cols_is_simple(subq, &cols)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 og_check_parent_cond(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *subq)
{
    if (!og_check_parent_one_cond(statement, qry->cond, subq)) {
        return OG_FALSE;
    }

    if (!og_check_parent_one_cond(statement, qry->filter_cond, subq)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 og_check_orderby(sql_query_t *subq, galist_t *orderby_list)
{
    cols_used_t cols;
    if (orderby_list->count) {
        init_cols_used(&cols);
        uint32 m = 0;
        sort_item_t *item = NULL;
        while (m < orderby_list->count) {
            item = (sort_item_t *)cm_galist_get(orderby_list, m++);
            sql_collect_cols_in_expr_tree(item->expr, &cols);
        }

        if (!og_check_cols_is_simple(subq, &cols)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 og_check_parent_erase_table(sql_query_t *qry, sql_table_t **tbl)
{
    if (qry->tables.count > 1) {
        return OG_FALSE;
    }

    *tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
    if (!(og_subslct_is_normal_subtbl(*tbl) && !(*tbl)->ineliminable)) {
        return OG_FALSE;
    }

    if ((*tbl)->version.type != CURR_VERSION) {
        return OG_FALSE;
    }

    if (HAS_HINT((*tbl)->hint_info)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 og_check_parent_erase_parent_query(sql_query_t *qry)
{
    if (og_check_query_if_complex_sql(qry, OG_COMPLEX_SQL_FLAG_IGNORE_ORDER)) {
        return OG_FALSE;
    }

    if (qry->s_query) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 og_check_parent_erase_child_query(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
                                                sql_query_t **subq_out)
{
    sql_select_t *select = tbl->select_ctx;
    if (select->root->type != SELECT_NODE_QUERY) {
        return OG_FALSE;
    }

    sql_query_t *subq = select->first_query;
    uint32 flag = OG_COMPLEX_SQL_FLAG_IGNORE_GROUP + OG_COMPLEX_SQL_FLAG_IGNORE_AGGR + OG_COMPLEX_SQL_FLAG_IGNORE_ORDER;
    if (og_check_query_if_complex_sql(subq, flag)) {
        return OG_FALSE;
    }

    if (subq->group_sets->count > 1 || QUERY_HAS_ROWNUM(subq)) {
        return OG_FALSE;
    }

    if (subq->aggrs->count && subq->group_sets->count == 0) {
        return OG_FALSE;
    }

    if (select->has_ancestor) {
        return OG_FALSE;
    }

    if (qry->sort_items->count && subq->sort_items->count) {
        return OG_FALSE;
    }

    if (!og_check_view_if_erase(statement, subq, tbl)) {
        return OG_FALSE;
    }

    *subq_out = subq;
    return OG_TRUE;
}

static bool32 og_check_parent_erase_ssa(sql_query_t *qry)
{
    uint32 i = 0;
    while (i < qry->ssa.count) {
        sql_select_t *sel = (sql_select_t *)sql_array_get(&qry->ssa, i++);
        if (sel->has_ancestor) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 og_check_parent_if_erase(sql_stmt_t *statement, sql_query_t *qry)
{
    sql_table_t *tbl = NULL;
    sql_query_t *subq = NULL;

    if (!og_check_parent_erase_table(qry, &tbl)) {
        return OG_FALSE;
    }

    if (!og_check_parent_erase_parent_query(qry)) {
        return OG_FALSE;
    }

    if (!og_check_parent_erase_child_query(statement, qry, tbl, &subq)) {
        return OG_FALSE;
    }

    if (!og_check_parent_erase_ssa(qry)) {
        return OG_FALSE;
    }

    if (!og_check_rs_columns(statement, qry)) {
        return OG_FALSE;
    }

    if (!og_check_parent_cond(statement, qry, subq)) {
        return OG_FALSE;
    }

    if (!og_check_orderby(subq, qry->sort_items)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static status_t og_modify_rscols_4_parent_sel_erase(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *subq)
{
    galist_t *sub_cols = subq->rs_columns;
    galist_t *cols = qry->rs_columns;
    uint32 m = 0;
    while (m < cols->count) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(cols, m++);
        if (!(col->type == RS_COL_COLUMN && !col->v_col.ancestor)) {
            continue;
        }

        rs_column_t *sub_col = (rs_column_t *)cm_galist_get(sub_cols, col->v_col.col);
        rs_column_t temp_col = *sub_col;
        if (sub_col->type == RS_COL_CALC &&
            sql_clone_expr_tree(statement->context, sub_col->expr, &temp_col.expr, sql_alloc_mem)) {
            return OG_ERROR;
        }

        temp_col.typmod = col->typmod;
        temp_col.name = col->name;
        *col = temp_col;
    }
    return OG_SUCCESS;
}

static status_t og_modify_group_node(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if ((*exprn)->type != EXPR_NODE_GROUP) {
        return OG_SUCCESS;
    }

    if (NODE_VM_ANCESTOR(*exprn)) {
        return OG_SUCCESS;
    }

    expr_node_t *ref = sql_get_origin_ref(*exprn);
    sql_context_t *ctx = v_ast->stmt->context;
    if (sql_clone_expr_node(ctx, ref, exprn, sql_alloc_mem)) {
        return OG_ERROR;
    }

    return visit_expr_node(v_ast, exprn, og_modify_group_node);
}

static status_t og_modify_group_node_4_parent_sel_erase(sql_stmt_t *statement, expr_node_t **exprn)
{
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, NULL);
    return visit_expr_node(&v_ast, exprn, og_modify_group_node);
}

static status_t og_modify_cols_4_parent_sel_erase(visit_assist_t *v_ast, expr_node_t **exprn)
{
    sql_query_t *subq = (sql_query_t *)v_ast->param0;
    rs_column_t *col = (rs_column_t *)cm_galist_get(subq->rs_columns, NODE_COL(*exprn));
    if (col->type == RS_COL_CALC) {
        // using OGSQL_CURR_NODE in add_node_2_parent_ref in sql_clone_expr_node,
        // so need to SET_NODE_STACK_CURR_QUERY.
        SET_NODE_STACK_CURR_QUERY(v_ast->stmt, subq);
        if (sql_clone_expr_node(v_ast->stmt->context, col->expr->root, exprn, sql_alloc_mem)) {
            SQL_RESTORE_NODE_STACK(v_ast->stmt);
            return OG_ERROR;
        }
        if (og_modify_group_node_4_parent_sel_erase(v_ast->stmt, exprn)) {
            SQL_RESTORE_NODE_STACK(v_ast->stmt);
            return OG_ERROR;
        }
        SQL_RESTORE_NODE_STACK(v_ast->stmt);
    } else {
        (*exprn)->value.v_col = col->v_col;
        (*exprn)->typmod = col->typmod;
    }
    return OG_SUCCESS;
}

// modify expr nodes when erase parent select context.
static status_t og_modify_nodes_4_parent_sel_erase(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_SELECT) {
        uint32 m = 0;
        sql_query_t *qry = (sql_query_t *)v_ast->param0;
        while (m < qry->ssa.count) {
            if (sql_array_get(&qry->ssa, m) == (*exprn)->value.v_obj.ptr) {
                (*exprn)->value.v_obj.id = m++;
                return OG_SUCCESS;
            }
            m++;
        }
        // can not be here
        OG_LOG_RUN_ERR("Failed to find sub select in query ssa.");
        return OG_ERROR;
    }

    if ((*exprn)->type == EXPR_NODE_COLUMN && !NODE_ANCESTOR(*exprn)) {
        return og_modify_cols_4_parent_sel_erase(v_ast, exprn);
    }

    return OG_SUCCESS;
}

static status_t og_modify_order_4_parent_sel_erase(sql_query_t *qry, visit_assist_t *v_ast, visit_func_t func)
{
    sort_item_t *sort_item = NULL;
    uint32 i = 0;
    while (i < qry->sort_items->count) {
        sort_item = (sort_item_t *)cm_galist_get(qry->sort_items, i++);
        if (visit_expr_tree(v_ast, sort_item->expr, func)) {
            return OG_ERROR;
        }

        sql_query_t *subq = (sql_query_t *)v_ast->param0;
        if (subq->group_sets->count && sql_match_group_expr(v_ast->stmt, subq, sort_item->expr)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_replace_query_4_parent_sel_erase(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *subq)
{
    subq->filter_cond = qry->filter_cond;
    subq->for_update = qry->for_update;
    subq->owner = qry->owner;
    subq->rs_columns = qry->rs_columns;
    cond_tree_t *ctree = qry->cond;
    galist_t *sort_list = qry->sort_items;
    subq->cond_has_acstor_col = qry->cond_has_acstor_col;

    MEMS_RETURN_IFERR(memcpy_sp(qry, sizeof(sql_query_t), subq, sizeof(sql_query_t)));

    if (sort_list->count) {
        qry->sort_items = sort_list;
    }

    // append query condition.
    qry->cond = ctree;
    if (og_erase_subselect_pull_up_cond(statement, qry, subq)) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static void og_update_ssa_parent(sql_query_t *qry)
{
    uint32 m = 0;
    sql_select_t *slct = NULL;
    sql_array_t *ssa = &qry->ssa;
    while (m < ssa->count) {
        slct = (sql_select_t *)sql_array_get(ssa, m++);
        slct->parent = qry;
    }
}

static void og_update_sub_table_parent(sql_query_t *qry)
{
    uint32 m = 0;
    sql_table_t *table = NULL;
    sql_array_t *tables = &qry->tables;
    while (m < tables->count) {
        table = (sql_table_t *)sql_array_get(tables, m++);
        TABLE_CBO_ATTR_OWNER(table) = qry->vmc;
        if (OG_IS_SUBSELECT_TABLE(table->type)) {
            table->select_ctx->parent = qry;
        }
    }
}

// where the parent select is simple, replace the parent select in parent select table name.
static status_t og_parent_select_erase(sql_stmt_t *statement, sql_query_t *qry, bool32 *check_result)
{
    if (!og_check_parent_if_erase(statement, qry)) {
        *check_result = OG_FALSE;
        return OG_SUCCESS;
    }

    // only one sub table
    sql_query_t *subq = ((sql_table_t *)sql_array_get(&qry->tables, 0))->select_ctx->first_query;

    // modify parent rs columns.
    if (og_modify_rscols_4_parent_sel_erase(statement, qry, subq)) {
        return OG_ERROR;
    }

    // combine parent query ssa to subquery
    if (sql_array_concat(&subq->ssa, &qry->ssa)) {
        OG_LOG_RUN_ERR("Failed to concat query ssa.");
        return OG_ERROR;
    }
    qry->ssa.count = 0;

    visit_assist_t ctva;
    sql_init_visit_assist(&ctva, statement, qry);
    ctva.param0 = (void *)subq;
    if (og_modify_query_condition(qry, &ctva, og_modify_nodes_4_parent_sel_erase)) {
        return OG_ERROR;
    }

    if (og_modify_order_4_parent_sel_erase(qry, &ctva, og_modify_nodes_4_parent_sel_erase)) {
        return OG_ERROR;
    }

    // replace query
    if (og_replace_query_4_parent_sel_erase(statement, qry, subq)) {
        return OG_ERROR;
    }

    sql_table_t *tab = (sql_table_t *)sql_array_get(&qry->tables, 0);
    og_erase_subselect_remove_sel_ctx(statement, tab->select_ctx);

    // update ssa parent
    og_update_ssa_parent(qry);

    // update sub table parent.
    og_update_sub_table_parent(qry);

    text_t *name = statement->session->current_sql.len != 0 ? &statement->session->current_sql : &tab->qb_name;
    OG_LOG_DEBUG_INF("Succeed to erase subselect parent, name=%s.", T2S(name));

    // 调用谓词传递
    *check_result = OG_TRUE;

    return OG_SUCCESS;
}

// when the subselect is simple, replace the subselect in subselect table name,
// where the parent select is simple, replace the parent select in parent select table name.
status_t og_transf_select_erase(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!qry->owner && OGSQL_TYPE_SELECT != statement->context->type) {
        return OG_SUCCESS;
    }

    if (statement->context->has_dblink) {
        return OG_SUCCESS;
    }

    if (!g_instance->sql.enable_subquery_elimination) {
        return OG_SUCCESS;
    }

    bool32 check_result = OG_FALSE;
    do {
        check_result = OG_FALSE;
        if (og_subselect_erase(statement, qry, &check_result)) {
            OG_LOG_DEBUG_ERR("Failed to erase subselect when transforming.");
            return OG_ERROR;
        }

        if (!check_result) {
            if (og_parent_select_erase(statement, qry, &check_result)) {
                OG_LOG_DEBUG_ERR("Failed to erase parent select when transforming.");
                return OG_ERROR;
            }
        }
    } while (check_result);
    return OG_SUCCESS;
}
