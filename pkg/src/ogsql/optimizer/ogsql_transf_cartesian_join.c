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
 * ogsql_transf_cartesian_join.c
 *
 *
 * IDENTIFICATION
 *      src/ogsql/optimizer/ogsql_transf_cartesian_join.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_transf_cartesian_join.h"
#include "ogsql_table_func.h"
#include "ogsql_func.h"
#include "srv_instance.h"
#include "ogsql_select_parser.h"
#include "ogsql_transform.h"
#include "ogsql_optim_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GENERATE_SERIES_STR "GENERATE_SERIES"
#define GENERATE_SERIES_LEN 15

static inline bool32 og_is_node_type(expr_node_t *exprn, expr_node_type_t type)
{
    return exprn->type == type;
}

static inline void og_set_new_ancestor(uint32 *ancestor, struct st_sql_select *owner, uint32 new_ancestor)
{
    (*ancestor)++;
    SET_ANCESTOR_LEVEL(owner, new_ancestor);
}

static inline bool32 og_is_complex_qry(sql_query_t *qry)
{
    OG_RETVALUE_IFTRUE(qry->has_distinct || qry->aggr_dis_count != 0, OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->pivot_items != NULL, OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->group_sets != NULL && qry->group_sets->count > 1, OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->connect_by_cond != NULL, OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->winsort_list != NULL && qry->winsort_list->count > 0, OG_TRUE);
    OG_RETVALUE_IFTRUE(LIMIT_CLAUSE_OCCUR(&qry->limit), OG_TRUE);
    OG_RETVALUE_IFTRUE(qry->ssa.count > 0, OG_TRUE);
    return OG_FALSE;
}

static bool32 has_cur_tbl_in_cols(cols_used_t *cols, uint32 current_table_id)
{
    biqueue_t *columns_bque = &cols->cols_que[SELF_IDX];
    expr_node_t *column = NULL;
    for (biqueue_node_t *bque_curr = biqueue_first(columns_bque);
        bque_curr != biqueue_end(columns_bque);
        bque_curr = bque_curr->next) {
        column = OBJECT_OF(expr_node_t, bque_curr);
        OG_RETVALUE_IFTRUE(current_table_id == TAB_OF_NODE(column), OG_TRUE);
    }
    return OG_FALSE;
}

static bool32 og_check_join_cond_compare_or(cond_node_t *cond, uint32 current_table_id)
{
    cols_used_t cols = { 0 };
    init_cols_used(&cols);
    sql_collect_cols_in_cond(cond, &cols);
    if (!has_cur_tbl_in_cols(&cols, current_table_id)) {
        return OG_FALSE;
    }
    // check other tables at same cond
    if (HAS_DIFF_TABS(&cols, SELF_IDX)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

// Skip related table constraints
static bool32 og_check_join_cond(cond_node_t *cond, uint32 tbl_id)
{
    if (cond == NULL) {
        return OG_TRUE;
    }
    if (cond->type == COND_NODE_COMPARE || cond->type == COND_NODE_OR) {
        return og_check_join_cond_compare_or(cond, tbl_id);
    }
    if (cond->type == COND_NODE_AND) {
        return og_check_join_cond(cond->right, tbl_id) ||
            og_check_join_cond(cond->left, tbl_id);
    }
    return OG_FALSE;
}

static bool32 find_tbl_in_join_cond(sql_join_node_t *jnode, uint32 tbl_id)
{
    OG_RETVALUE_IFTRUE(!jnode, OG_FALSE);
    OG_RETVALUE_IFTRUE(jnode->type == JOIN_TYPE_NONE || jnode->join_cond == NULL, OG_FALSE);
    OG_RETVALUE_IFTRUE(sql_cond_node_exist_table(jnode->join_cond->root, tbl_id), OG_TRUE);
    return find_tbl_in_join_cond(jnode->left, tbl_id) || find_tbl_in_join_cond(jnode->right, tbl_id);
}

static status_t og_adjust_ancestor_level(visit_assist_t *v_ast, expr_node_t **exprn)
{
    OG_RETURN_IFERR(sql_stack_safe(v_ast->stmt));

    if (og_is_node_type(*exprn, EXPR_NODE_GROUP)) {
        OG_RETSUC_IFTRUE((*exprn)->value.v_vm_col.ancestor == 0);
        (*exprn)->value.v_vm_col.ancestor++;
        expr_node_t *orig_ref_exprn = sql_get_origin_ref(*exprn);
        if (og_is_node_type(orig_ref_exprn, EXPR_NODE_COLUMN) && NODE_ANCESTOR(orig_ref_exprn) > 0) {
            og_set_new_ancestor(&orig_ref_exprn->value.v_col.ancestor, v_ast->query->owner,
                (*exprn)->value.v_col.ancestor);
        } else if (NODE_IS_RES_ROWID(orig_ref_exprn) && ROWID_NODE_ANCESTOR(orig_ref_exprn) > 0) {
            og_set_new_ancestor(&orig_ref_exprn->value.v_rid.ancestor, v_ast->query->owner,
                (*exprn)->value.v_rid.ancestor);
        }
        return OG_SUCCESS;
    }

    if (og_is_node_type(*exprn, EXPR_NODE_RESERVED)) {
        if (NODE_IS_RES_ROWID(*exprn) && (*exprn)->value.v_rid.ancestor > 0) {
            og_set_new_ancestor(&(*exprn)->value.v_rid.ancestor, v_ast->query->owner, (*exprn)->value.v_rid.ancestor);
        }
        return OG_SUCCESS;
    }

    if (og_is_node_type(*exprn, EXPR_NODE_COLUMN)) {
        if ((*exprn)->value.v_col.ancestor == 0) {
            NODE_TAB(*exprn) = 0;
        } else {
            og_set_new_ancestor(&(*exprn)->value.v_col.ancestor, v_ast->query->owner, (*exprn)->value.v_col.ancestor);
        }
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static void build_down_tbl_map(uint32 tbl_cnt, cond_tree_t *condtr, bool8 *tbl_maps)
{
    OG_RETVOID_IFTRUE(condtr == NULL);
    cond_node_t *cond = condtr->root;
    uint32 tbl_idx = 0;
    while (tbl_idx < tbl_cnt) {
        if (tbl_maps[tbl_idx] && og_check_join_cond(cond, tbl_idx)) {
            tbl_maps[tbl_idx] = OG_FALSE;
        }
        tbl_idx++;
    }
}

static inline bool32 is_pushdownable_aggr_func(expr_node_t *exprn)
{
    sql_func_t *function = sql_get_func(&exprn->value.v_func);
    return function->aggr_type == AGGR_TYPE_MAX || function->aggr_type == AGGR_TYPE_MIN;
}

static inline bool32 is_sort_aggr_expr(expr_node_t *exprn)
{
    return exprn->sort_items != NULL && exprn->sort_items->count > 0;
}

static bool32 og_aggr_pushdown_chk_aggr(sql_query_t *qry, bool8 *tbl_maps)
{
    OG_RETVALUE_IFTRUE(qry->aggrs->count == 0, OG_FALSE);
    expr_node_t *exprn = NULL;
    expr_node_t *arg = NULL;
    uint32 idx = 0;
    while (idx < qry->aggrs->count) {
        exprn = (expr_node_t *) cm_galist_get(qry->aggrs, idx++);
        OG_RETVALUE_IFTRUE(!is_pushdownable_aggr_func(exprn), OG_FALSE);
        OG_RETVALUE_IFTRUE(is_sort_aggr_expr(exprn), OG_FALSE);

        arg = exprn->argument->root;
        OG_RETVALUE_IFTRUE(!og_is_node_type(arg, EXPR_NODE_COLUMN) || NODE_ANCESTOR(arg) > 0, OG_FALSE);
        tbl_maps[NODE_TAB(arg)] = OG_TRUE;
    }
    return OG_TRUE;
}

static bool32 og_aggr_pushdown_chk_cond(sql_query_t *qry, bool8 *tbl_maps)
{
    sql_table_t *tbl = NULL;
    bool32 ret = OG_FALSE;
    // Pre-validated: Non-aggregation scenarios already filtered
    uint32 tbl_id = 0;
    while (tbl_id < qry->tables.count) {
        if (!tbl_maps[tbl_id]) {
            tbl_id++;
            continue;
        }
        
        // Ignore subquery temp tables
        tbl = (sql_table_t *) sql_array_get(&qry->tables, tbl_id);
        if (tbl->type != NORMAL_TABLE || tbl->rowid_exists ||
            find_tbl_in_join_cond(qry->join_assist.join_node, tbl_id)) {
            tbl_maps[tbl_id] = OG_FALSE;
            tbl_id++;
            continue;
        }
        
        ret = OG_TRUE;
        tbl_id++;
    }
    return ret;
}

static bool32 og_aggr_pushdown_chk_group(sql_query_t *qry)
{
    if (qry->group_sets->count == 0) {
        return OG_TRUE;
    }
    group_set_t *g_set = (group_set_t *) cm_galist_get(qry->group_sets, 0);
    expr_tree_t *exprtr = NULL;
    uint32 idx = 0;
    while (idx < g_set->items->count) {
        exprtr = (expr_tree_t *) cm_galist_get(g_set->items, idx++);
        OG_CONTINUE_IFTRUE(TREE_EXPR_TYPE(exprtr) == EXPR_NODE_COLUMN && NODE_ANCESTOR(exprtr->root) == 0);
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 og_chk_aggr_grp(sql_stmt_t *statement, sql_query_t *qry, uint8 *tbl_maps)
{
    OG_RETVALUE_IFTRUE(!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_aggr_placement,
        OPT_AGGR_PLACEMENT), OG_FALSE);

    // ignore query with single table or without aggr
    OG_RETVALUE_IFTRUE(qry->tables.count == 1 || qry->aggrs->count == 0, OG_FALSE);

    // ignore complex query
    OG_RETVALUE_IFTRUE(og_is_complex_qry(qry), OG_FALSE);

    // ignore rownum
    OG_RETVALUE_IFTRUE(ROWNUM_COND_OCCUR(qry->cond) || QUERY_HAS_ROWNODEID(qry) ||
        (qry->incl_flags & RS_INCL_GROUPING), OG_FALSE);

    // ignore query with outer join
    OG_RETVALUE_IFTRUE(qry->join_assist.outer_node_count > 0, OG_FALSE);

    // ignore json_table or function
    sql_table_t *tbl = NULL;
    uint32 idx = 0;
    while (idx < qry->tables.count) {
        tbl = (sql_table_t *) sql_array_get(&qry->tables, idx++);
        
        OG_RETVALUE_IFTRUE(tbl->type == JSON_TABLE, OG_FALSE);
        OG_CONTINUE_IFTRUE(tbl->type != FUNC_AS_TABLE);
        
        text_t generate_series = { GENERATE_SERIES_STR, GENERATE_SERIES_LEN };
        OG_RETVALUE_IFTRUE(cm_compare_text_ins(&tbl->func.name, &generate_series) == 0, OG_FALSE);
    }

    OG_RETVALUE_IFTRUE(!og_aggr_pushdown_chk_group(qry), OG_FALSE);

    OG_RETVALUE_IFTRUE(!og_aggr_pushdown_chk_aggr(qry, tbl_maps), OG_FALSE);

    // Filtering query_cond
    build_down_tbl_map(qry->tables.count, qry->cond, tbl_maps);
    // Filtering having_cond
    build_down_tbl_map(qry->tables.count, qry->having_cond, tbl_maps);
    // check cond(query\having\join)
    OG_RETVALUE_IFTRUE(!og_aggr_pushdown_chk_cond(qry, tbl_maps), OG_FALSE);

    return OG_TRUE;
}

static void og_modify_rewrite_tbl(sql_table_t *rewrite_tbl, sql_select_t *sub_slct)
{
    rewrite_tbl->select_ctx = sub_slct;
    rewrite_tbl->entry = NULL;
    rewrite_tbl->type = SUBSELECT_AS_TABLE;
    rewrite_tbl->subslct_tab_usage = SUBSELECT_4_NORMAL_JOIN;
    rewrite_tbl->dblink.len = 0;
    rewrite_tbl->ineliminable = OG_TRUE;
    rewrite_tbl->sub_tables = NULL;
}

status_t og_rewrite_tbl_as_slct(sql_table_t *rewrite_tbl, sql_stmt_t *statement)
{
    sql_table_t *new_tbl = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_table_t), (void **)&new_tbl));
    MEMS_RETURN_IFERR(memcpy_s(new_tbl, sizeof(sql_table_t), rewrite_tbl, sizeof(sql_table_t)));

    sql_select_t *sub_slct = NULL;
    OG_RETURN_IFERR(sql_alloc_select_context(statement, SELECT_AS_TABLE, &sub_slct));
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(select_node_t), (void **)&sub_slct->root));
    sub_slct->root->type = SELECT_NODE_QUERY;
    APPEND_CHAIN(&sub_slct->chain, sub_slct->root);

    sql_query_t *s_qry = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_query_t), (void**)&s_qry));
    OG_RETURN_IFERR(sql_init_query(statement, sub_slct, rewrite_tbl->name.loc, s_qry));
    
    sub_slct->root->query = s_qry;
    sub_slct->first_query = s_qry;
    sub_slct->rs_columns = s_qry->rs_columns;
    new_tbl->id = 0;
    TABLE_CBO_ATTR_OWNER(new_tbl) = s_qry->vmc;
    OG_RETURN_IFERR(sql_create_list(statement, &sub_slct->select_sort_items));
    og_modify_rewrite_tbl(rewrite_tbl, sub_slct);
    OG_RETURN_IFERR(sql_array_put(&s_qry->tables, new_tbl));
    return OG_SUCCESS;
}

static status_t og_clone_group(sql_stmt_t *statement, sql_query_t *qry, uint32 tbl_id, sql_query_t *sub_qry)
{
    group_set_t *group = NULL;
    galist_t *group_lst = NULL;
    group = (group_set_t *)cm_galist_get(qry->group_sets, 0);

    expr_tree_t *group_exprtr = NULL;
    expr_tree_t *sub_group_exprtr = NULL;
    uint32 ga_counts = 0;
    rs_column_t *rs_column = NULL;
    uint32 gs_index = 0;
    while (gs_index < group->items->count) {
        group_exprtr = (expr_tree_t *)cm_galist_get(group->items, gs_index++);
        if (TREE_EXPR_TYPE(group_exprtr) != EXPR_NODE_COLUMN) {
            continue;
        }
        if (EXPR_TAB(group_exprtr) != tbl_id) {
            continue;
        }

        OG_RETURN_IFERR(sql_clone_expr_tree(statement->context, group_exprtr, &sub_group_exprtr, sql_alloc_mem));
        if (ga_counts == 0) {
            OG_RETURN_IFERR(sql_create_list(statement, &group_lst));
        }
        NODE_TAB(sub_group_exprtr->root) = 0;
        OG_RETURN_IFERR(cm_galist_insert(group_lst, sub_group_exprtr));
        ga_counts++;
        rs_column = NULL;
        OG_RETURN_IFERR(cm_galist_new(sub_qry->rs_columns, sizeof(rs_column_t), (void **)&rs_column));
        rs_column->type = RS_COL_CALC;
        rs_column->typmod = sub_group_exprtr->root->typmod;
        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_tree_t), (void **)&rs_column->expr));
        rs_column->expr->owner = statement->context;
        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&rs_column->expr->root));
        rs_column->expr->root->typmod = sub_group_exprtr->root->typmod;
        OG_RETURN_IFERR(sql_set_group_expr_node(statement, rs_column->expr->root, group_lst->count - 1, 0, 0,
                                                sub_group_exprtr->root));
        NODE_COL(group_exprtr->root) = sub_qry->rs_columns->count - 1;
    }
    if (ga_counts > 0) {
        OG_RETURN_IFERR(cm_galist_new(sub_qry->group_sets, sizeof(group_set_t), (void **)&group));
        group->items = group_lst;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t og_clone_aggr(sql_query_t *qry, uint32 tbl_id, sql_stmt_t *statement, sql_query_t *sub_qry)
{
    expr_node_t *aggr_rewrite_exprn = NULL;
    expr_node_t *sub_aggr_exprn = NULL;
    rs_column_t *rs_column = NULL;

    uint32 query_index = 0;
    while (query_index < qry->aggrs->count) {
        aggr_rewrite_exprn = (expr_node_t *)cm_galist_get(qry->aggrs, query_index++);
        if (TREE_EXPR_TYPE(aggr_rewrite_exprn->argument) != EXPR_NODE_COLUMN) {
            continue;
        }
        if (EXPR_TAB(aggr_rewrite_exprn->argument) != tbl_id) {
            continue;
        }

        OG_RETURN_IFERR(sql_clone_expr_node(statement->context, aggr_rewrite_exprn, &sub_aggr_exprn, sql_alloc_mem));
        OG_RETURN_IFERR(cm_galist_insert(sub_qry->aggrs, sub_aggr_exprn));
        EXPR_TAB(sub_aggr_exprn->argument) = 0;
        rs_column = NULL;
        OG_RETURN_IFERR(cm_galist_new(sub_qry->rs_columns, sizeof(rs_column_t), (void **)&rs_column));
        rs_column->type = RS_COL_CALC;
        rs_column->typmod = aggr_rewrite_exprn->typmod;

        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_tree_t), (void **)&rs_column->expr));
        rs_column->expr->owner = statement->context;
    
        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&rs_column->expr->root));
        rs_column->expr->root->typmod = aggr_rewrite_exprn->typmod;
        rs_column->expr->root->value.v_int = (int32)(sub_qry->aggrs->count - 1);
        rs_column->expr->root->value.type = OG_TYPE_INTEGER;
        rs_column->expr->root->type = EXPR_NODE_AGGR;
        NODE_COL(aggr_rewrite_exprn->argument->root) = sub_qry->rs_columns->count - 1;
    }
    return OG_SUCCESS;
}

static status_t og_clone_sub_query(sql_stmt_t *statement, sql_query_t *s_qry, sql_query_t *qry, uint32 tbl_id)
{
    visit_assist_t v_ast = { 0 };
    sql_init_visit_assist(&v_ast, statement, s_qry);
    if (qry->group_sets->count == 1) {
        OG_RETURN_IFERR(og_clone_group(statement, qry, tbl_id, s_qry));
    }
    return og_clone_aggr(qry, tbl_id, statement, s_qry);
}

static status_t og_pushdown_query_cond(sql_query_t *qry, sql_query_t *sub_qry, uint32 tbl_id, sql_stmt_t *statement)
{
    OG_RETSUC_IFTRUE(qry->cond == NULL);
    sql_table_t *tbl = NULL;
    tbl = (sql_table_t *)sql_array_get(&sub_qry->tables, 0);
    tbl->id = tbl_id;
    OG_RETURN_IFERR(sql_extract_filter_cond(statement, &sub_qry->tables, &sub_qry->cond, qry->cond->root));
    tbl->id = 0;
    OG_RETSUC_IFTRUE(sub_qry->cond == NULL);
    visit_assist_t v_ast = { 0 };
    sql_init_visit_assist(&v_ast, statement, sub_qry);
    return visit_cond_node(&v_ast, sub_qry->cond->root, og_adjust_ancestor_level);
}

static status_t og_cache_parent_query(sql_query_t *qry, uint32 tbl_id, sql_stmt_t *statement, sql_query_t *sub_qry)
{
    rs_column_t *rs_column = NULL;
    sql_table_t *tbl = NULL;
    query_field_t qry_fld = { 0 };
    tbl = (sql_table_t *)sql_array_get(&qry->tables, tbl_id);
    cm_bilist_init(&(tbl)->query_fields);
    uint32 rs_column_index = 0;
    while (rs_column_index < sub_qry->rs_columns->count) {
        rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, rs_column_index);
        qry_fld.datatype = rs_column->datatype;
        qry_fld.col_id = rs_column_index;
        qry_fld.is_array = rs_column->v_col.is_array;
        qry_fld.start = rs_column->v_col.ss_start;
        qry_fld.end = rs_column->v_col.ss_end;
        OG_RETURN_IFERR(sql_table_cache_query_field(statement, tbl, &qry_fld));
        rs_column_index++;
    }
    return OG_SUCCESS;
}

static status_t og_pushdown_aggr_grp(sql_stmt_t *statement, sql_query_t *qry, bool8* tbl_maps)
{
    sql_table_t *rewrite_tbl = NULL;
    sql_query_t *sub_qry = NULL;
    int32 tbl_id = 0;
    while (tbl_id < qry->tables.count) {
        if (!tbl_maps[tbl_id]) {
            tbl_id++;
            continue;
        }
        
        rewrite_tbl = (sql_table_t *)sql_array_get(&qry->tables, tbl_id);
        OG_RETURN_IFERR(og_rewrite_tbl_as_slct(rewrite_tbl, statement));
        rewrite_tbl->select_ctx->parent = qry;
        sub_qry = rewrite_tbl->select_ctx->root->query;
        OG_RETURN_IFERR(og_clone_sub_query(statement, sub_qry, qry, tbl_id));
        OG_RETURN_IFERR(og_pushdown_query_cond(qry, sub_qry, tbl_id, statement));
        OG_RETURN_IFERR(og_cache_parent_query(qry, tbl_id, statement, sub_qry));
        tbl_id++;
    }
    return OG_SUCCESS;
}

status_t og_transf_cartesian_join(sql_stmt_t *statement, sql_query_t *qry)
{
    bool8 tbl_maps[OG_MAX_JOIN_TABLES] = { 0 };
    OG_RETSUC_IFTRUE(!og_chk_aggr_grp(statement, qry, tbl_maps));
    return og_pushdown_aggr_grp(statement, qry, tbl_maps);
}