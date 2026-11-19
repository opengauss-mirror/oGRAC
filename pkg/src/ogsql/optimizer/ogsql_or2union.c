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

#include "ogsql_or2union.h"
#include "ogsql_transform.h"
#include "ogsql_verifier.h"
#include "ogsql_func.h"
#include "ogsql_plan.h"
#include "srv_instance.h"
#include "ogsql_table_func.h"
#include "cond_parser.h"
#include "func_convert.h"
#include "ogsql_select_parser.h"
#include "plan_range.h"
#include "plan_assist.h"
#include "ogsql_plan_defs.h"
#include "ogsql_cond.h"
#include "cbo_base.h"
#include "cbo_join.h"
#include "ogsql_expr_verifier.h"
#include "ogsql_table_verifier.h"
#include "ogsql_expr_def.h"
#include "plan_scan.h"
#include "ogsql_optim_common.h"

status_t clone_tables_4_subqry(sql_stmt_t *statement, sql_query_t *sql_qry, sql_query_t *sub_qry)
{
    sql_table_t *tbl = NULL;
    sql_table_t *new_tbl = NULL;
    bilist_node_t *node = NULL;
    query_field_t *qry_fld = NULL;
    for (uint32 i = 0; i < sql_qry->tables.count; i++) {
        tbl = (sql_table_t *)sql_array_get(&sql_qry->tables, i);
        OG_RETURN_IFERR(sql_array_new(&sub_qry->tables, sizeof(sql_table_t), (void **)&new_tbl));
        *new_tbl = *tbl;
        cm_bilist_init(&new_tbl->query_fields);
        node = cm_bilist_head(&tbl->query_fields);
        for (; node != NULL; node = BINODE_NEXT(node)) {
            qry_fld = BILIST_NODE_OF(query_field_t, node, bilist_node);
            OG_RETURN_IFERR(sql_table_cache_query_field_impl(statement, new_tbl, qry_fld, qry_fld->is_cond_col));
        }
    }
    return OG_SUCCESS;
}

static inline void add_ele_to_bitmaps(bitmapset_t *bms, uint32 ele_id)
{
    if (ele_id >= OG_MAX_JOIN_TABLES) {
        return;
    }

    if (ele_id >= UINT64_BITS) {
        OG_BIT_SET(bms->map_high, OG_GET_MASK(ele_id - UINT64_BITS));
        return;
    }

    if (ele_id < UINT64_BITS) {
        OG_BIT_SET(bms->map_low, OG_GET_MASK(ele_id));
    }
}

static inline uint32 get_ele_cnt_from_bitmaps(bitmapset_t *bms)
{
    return __builtin_popcountll(bms->map_low) + __builtin_popcountll(bms->map_high);
}

// Generate a subquery table from the UNION-associated subqueries and replace the original query's table.
static status_t og_replace_query_table(sql_query_t *sql_qry, sql_stmt_t *statement, sql_select_t *sub_select_ctx)
{
    sql_table_t *tbl = NULL;
    if (og_create_sqltable(statement, sql_qry, sub_select_ctx) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] rewrite step3, create union derived table failed");
        return OG_ERROR;
    }
    tbl = (sql_table_t *)sql_array_get(&sql_qry->tables, 0);
    if (sql_generate_unnamed_table_name(statement, tbl, TAB_TYPE_OR_EXPAND) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] rewrite step3, generate derived table name failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static bool32 is_cmp_type_support_lnnvl(cond_node_t *cond)
{
    if (cond == NULL || cond->cmp == NULL) {
        return OG_FALSE;
    }
    cmp_type_t cmp_type = cond->cmp->type;
    return (cmp_type == CMP_TYPE_EQUAL || cmp_type == CMP_TYPE_GREAT || cmp_type == CMP_TYPE_LESS ||
            cmp_type == CMP_TYPE_IS_NULL || cmp_type == CMP_TYPE_LIKE || cmp_type == CMP_TYPE_REGEXP ||
            cmp_type == CMP_TYPE_EXISTS || cmp_type == CMP_TYPE_REGEXP_LIKE || cmp_type == CMP_TYPE_IS_JSON ||
            cmp_type == CMP_TYPE_NOT_EQUAL || cmp_type == CMP_TYPE_GREAT_EQUAL || cmp_type == CMP_TYPE_LESS_EQUAL ||
            cmp_type == CMP_TYPE_IS_NOT_NULL || cmp_type == CMP_TYPE_NOT_LIKE || cmp_type == CMP_TYPE_NOT_REGEXP ||
            cmp_type == CMP_TYPE_NOT_EXISTS || cmp_type == CMP_TYPE_NOT_REGEXP_LIKE ||
            cmp_type == CMP_TYPE_IS_NOT_JSON);
}

static bool32 if_or_cond_support_lnnvl(cond_node_t *or_node)
{
    if (or_node->type == COND_NODE_COMPARE) {
        return is_cmp_type_support_lnnvl(or_node);
    }

    if (or_node->type == COND_NODE_AND) {
        return if_or_cond_support_lnnvl(or_node->left) && if_or_cond_support_lnnvl(or_node->right);
    }

    return OG_FALSE;
}

static bool32 if_support_union_all(galist_t *or_conds)
{
    cond_node_t *or_node = NULL;
    cols_used_t col_used;
    uint32 i = 0;
    while (i < or_conds->count) {
        or_node = (cond_node_t *)cm_galist_get(or_conds, i++);

        init_cols_used(&col_used);
        sql_collect_cols_in_cond(or_node, &col_used);
        bool32 has_subslct = HAS_SUBSLCT(&col_used);
        OG_RETVALUE_IFTRUE(has_subslct == OG_TRUE, OG_FALSE);

        bool32 sup_lnnvl = if_or_cond_support_lnnvl(or_node);
        OG_RETVALUE_IFTRUE(sup_lnnvl == OG_FALSE, OG_FALSE);
    }
    return OG_TRUE;
}

static status_t og_build_const_false_expr_left(sql_stmt_t *statement, expr_tree_t **exprtr)
{
    expr_node_t *exprn = NULL;
    if (sql_create_expr(statement, exprtr)) {
        return OG_ERROR;
    }
    if (sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&exprn) != OG_SUCCESS) {
        return OG_ERROR;
    }
    exprn->owner = (*exprtr);
    exprn->argument = NULL;
    exprn->type = EXPR_NODE_CONST;
    exprn->value.type = OG_TYPE_BOOLEAN;
    exprn->value.v_int = 0;
    exprn->left = NULL;
    exprn->right = NULL;
    (*exprtr)->owner = statement->context;
    (*exprtr)->root = exprn;
    (*exprtr)->next = NULL;
    return OG_SUCCESS;
}

static status_t og_build_lnnvl_func_cond_right(sql_stmt_t *statement, cond_node_t *src_cond, expr_tree_t **exprtr)
{
    expr_node_t *exprn = NULL;
    if (sql_create_expr(statement, exprtr)) {
        return OG_ERROR;
    }
    if (sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&exprn) != OG_SUCCESS) {
        return OG_ERROR;
    }
    // build lnnvl func expression node
    (*exprtr)->root = exprn;
    exprn->datatype = OG_TYPE_BOOLEAN;
    exprn->size = OG_BOOLEAN_SIZE;
    exprn->value.v_func.func_id = ID_FUNC_ITEM_LNNVL;
    exprn->value.v_func.pack_id = OG_INVALID_ID32;
    exprn->type = EXPR_NODE_FUNC;
    // associated with the func node
    cond_tree_t *arg_cond = NULL;
    if (sql_create_cond_tree(statement->context, &arg_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, construct lnnv right func cond failed");
        return OG_ERROR;
    }
    arg_cond->root = src_cond;
    exprn->cond_arg = arg_cond;
    return OG_SUCCESS;
}

// The left expression is const false, the right expression is lnnvl_fuc, the cmp_type is not_equal
// lnnvl_func(cond): if cond == true, lnnvl_func(cond) == false; if cond == false, lnnvl_func(cond) == true;
static status_t og_construct_lnnvl_func_compare(sql_stmt_t *statement, cond_node_t *src_cond, cmp_node_t *lnnvl_cmp)
{
    OG_RETURN_IFERR(og_build_const_false_expr_left(statement, &lnnvl_cmp->left));
    cond_node_t *arg_cond = NULL;
    OG_RETURN_IFERR(sql_clone_cond_node(statement->context, src_cond, &arg_cond, sql_alloc_mem));
    return og_build_lnnvl_func_cond_right(statement, arg_cond, &lnnvl_cmp->right);
}

static status_t og_build_lnnvl_cond_impl(sql_stmt_t *statement, cond_node_t *src_cond, cond_node_t **lnnvl_cond)
{
    if (sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)lnnvl_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step, alloc memory for construct lnnv cond failed");
        return OG_ERROR;
    }
    (*lnnvl_cond)->type = COND_NODE_COMPARE;

    cmp_node_t *lnnvl_cmp = NULL;
    if (sql_alloc_mem(statement->context, sizeof(cmp_node_t), (void **)&lnnvl_cmp) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step, alloc memory for construct lnnv cmp failed");
        return OG_ERROR;
    }
    lnnvl_cmp->type = CMP_TYPE_NOT_EQUAL;

    if (og_construct_lnnvl_func_compare(statement, src_cond, lnnvl_cmp) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, construct lnnv cond failed");
        return OG_ERROR;
    }

    (*lnnvl_cond)->cmp = lnnvl_cmp;
    return OG_SUCCESS;
}

// Bulid lnnvl_cond for union all to removing duplicate data
static status_t og_build_lnnvl_cond_for_union_all(sql_stmt_t *statement, cond_node_t *tmp_cond,
                                                  cond_node_t **lnnvl_cond)
{
    if (tmp_cond->type == COND_NODE_COMPARE) {
        return og_build_lnnvl_cond_impl(statement, tmp_cond, lnnvl_cond);
    }

    if (tmp_cond->type == COND_NODE_AND) {
        cond_node_t *or_cond = NULL;
        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)&or_cond));
        or_cond->type = COND_NODE_OR;
        OG_RETURN_IFERR(og_build_lnnvl_cond_for_union_all(statement, tmp_cond->left, &or_cond->left));
        OG_RETURN_IFERR(og_build_lnnvl_cond_for_union_all(statement, tmp_cond->right, &or_cond->right));
        *lnnvl_cond = or_cond;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

// Generate the or_cond and lnnvl_condtree for the UNION ALL
static status_t og_build_or_conds_for_union_all(sql_stmt_t *statement, bool32 union_all_support, galist_t *or_conds,
                                                uint32 start_id, cond_tree_t **cond_tree)
{
    cond_node_t *or_cond = NULL;
    if (sql_create_cond_tree(statement->context, cond_tree) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!union_all_support) {
        or_cond = (cond_node_t *)cm_galist_get(or_conds, start_id);
        return sql_add_cond_node(*cond_tree, or_cond);
    }

    // When use union all, we need build the lnnvl cond to remove duplicate rows
    int32 i = start_id - 1;
    cond_node_t *tmp_cond = NULL;
    while (i >= 0) {
        cond_node_t *lnnvl_cond = NULL;
        tmp_cond = (cond_node_t *)cm_galist_get(or_conds, i--);
        if (og_build_lnnvl_cond_for_union_all(statement, tmp_cond, &lnnvl_cond) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, construct lnnvl cond for UNION ALL failed");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_add_cond_node(*cond_tree, lnnvl_cond));
    }

    or_cond = (cond_node_t *)cm_galist_get(or_conds, start_id);
    return sql_add_cond_node(*cond_tree, or_cond);
}

static void og_set_rs_column(rs_column_t *rs_column, knl_column_t *knl_col, sql_table_t *tbl,
                                    query_field_t *qry_fld)
{
    rs_column->type = RS_COL_COLUMN;
    rs_column->datatype = knl_col->datatype;
    rs_column->v_col.ss_start = qry_fld->start;
    rs_column->v_col.ss_end = qry_fld->end;
    rs_column->v_col.col = knl_col->id;
    rs_column->v_col.tab = tbl->id;
    rs_column->v_col.ancestor = 0;
    rs_column->v_col.is_array = qry_fld->is_array;
    rs_column->v_col.datatype = knl_col->datatype;
    if (OG_IS_LOB_TYPE(rs_column->datatype)) {
        rs_column->datatype = (rs_column->datatype != OG_TYPE_BLOB) ? OG_TYPE_STRING : OG_TYPE_RAW;
    }
    rs_column->size = knl_col->size;
    rs_column->precision = knl_col->precision;
    rs_column->scale = knl_col->scale;
    return;
}

static status_t og_update_ssa_and_ancestor(visit_assist_t *visit_assist, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_PARAM || (*exprn)->type == EXPR_NODE_CSR_PARAM) {
        ((sql_query_t *)visit_assist->param0)->incl_flags |= COND_INCL_PARAM;
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_RESERVED) {
        if ((*exprn)->value.v_int == RES_WORD_ROWID && (*exprn)->value.v_rid.ancestor > 0) {
            (*exprn)->value.v_rid.ancestor++;
        }
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_GROUP) {
        OG_RETVALUE_IFTRUE((*exprn)->value.v_vm_col.ancestor == 0, OG_SUCCESS);
        (*exprn)->value.v_vm_col.ancestor++;
        expr_node_t *ori_ref_exprn = sql_get_origin_ref(*exprn);
        if (NODE_IS_RES_ROWID(ori_ref_exprn) && ROWID_NODE_ANCESTOR(ori_ref_exprn) > 0) {
            ori_ref_exprn->value.v_rid.ancestor++;
        } else if (ori_ref_exprn->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(ori_ref_exprn) > 0) {
            ori_ref_exprn->value.v_col.ancestor++;
        }
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_COLUMN) {
        OG_RETVALUE_IFTRUE(NODE_ANCESTOR(*exprn) == 0, OG_SUCCESS);
        (*exprn)->value.v_col.ancestor++;
        return OG_SUCCESS;
    }

    sql_select_t *select_ctx = NULL;
    sql_query_t *sub_qry = NULL;
    if ((*exprn)->type == EXPR_NODE_SELECT) {
        select_ctx = (sql_select_t *)VALUE_PTR(var_object_t, &(*exprn)->value)->ptr;
        sub_qry = (sql_query_t *)visit_assist->param0;
        select_ctx->parent = sub_qry;
        (*exprn)->value.v_obj.id = sub_qry->ssa.count;
        return sql_array_put(&sub_qry->ssa, select_ctx);
    }

    return OG_SUCCESS;
}

static status_t og_build_rs_cols4union(sql_stmt_t *statement, sql_table_t *tbl, query_field_t *qry_fld,
                                       galist_t *rs_cols)
{
    rs_column_t *rs_column = NULL;
    knl_column_t *knl_col = NULL;
    OG_RETURN_IFERR(cm_galist_new(rs_cols, sizeof(rs_column_t), (void **)&rs_column));
    knl_col = knl_get_column(tbl->entry->dc.handle, qry_fld->col_id);
    og_set_rs_column(rs_column, knl_col, tbl, qry_fld);
    return sql_copy_str(statement->context, knl_col->name, &rs_column->name);
}

static status_t og_create_rowid_rs_col4union(sql_stmt_t *statement, uint32 tbl_id, sql_table_type_t type,
                                             galist_t *rs_cols)
{
    rs_column_t *rs_column = NULL;
    if (cm_galist_new(rs_cols, sizeof(rs_column_t), (pointer_t *)&rs_column) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_alloc_mem(statement->context, sizeof(expr_tree_t), (void **)&rs_column->expr) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_alloc_mem(statement->context, sizeof(expr_node_t), (void **)&rs_column->expr->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    rs_column->type = RS_COL_CALC;
    rs_column->expr->owner = statement->context;
    if (type == NORMAL_TABLE) {
        rs_column->expr->root->value.v_rid.ancestor = 0;
        rs_column->expr->root->value.type = OG_TYPE_INTEGER;
        rs_column->expr->root->size = ROWID_LENGTH;
        rs_column->expr->root->type = EXPR_NODE_RESERVED;
        rs_column->expr->root->value.v_rid.res_id = RES_WORD_ROWID;
        rs_column->expr->root->datatype = OG_TYPE_STRING;
    } else {
        rs_column->expr->root->value.v_int = 0;
        rs_column->expr->root->size = sizeof(uint32);
        rs_column->expr->root->datatype = OG_TYPE_INTEGER;
        rs_column->expr->root->type = EXPR_NODE_CONST;
        rs_column->expr->root->value.type = OG_TYPE_INTEGER;
    }
    rs_column->datatype = rs_column->expr->root->datatype;
    rs_column->size = rs_column->expr->root->size;
    rs_column->expr->root->value.v_rid.tab_id = tbl_id;
    return OG_SUCCESS;
}

static status_t og_gen_rs_cols_4_union_qry(sql_query_t *sql_qry, sql_query_t *for_union_qry, sql_stmt_t *statement)
{
    uint32 i = 0;
    sql_table_t *tbl = NULL;
    bilist_node_t *node_list = NULL;
    query_field_t *qry_fld = NULL;
    while (i < sql_qry->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&sql_qry->tables, i++);
        node_list = cm_bilist_head(&tbl->query_fields);
        while (node_list != NULL) {
            qry_fld = BILIST_NODE_OF(query_field_t, node_list, bilist_node);
            if (og_build_rs_cols4union(statement, tbl, qry_fld, for_union_qry->rs_columns) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, build rs_columns for union failed");
                return OG_ERROR;
            }
            node_list = BINODE_NEXT(node_list);
        }
        if (og_create_rowid_rs_col4union(statement, tbl->id, tbl->type, for_union_qry->rs_columns) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, build rowid rs_columns for union failed");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_copy_join_ast_4_union_qry(sql_query_t *sql_qry, sql_query_t *for_union_qry, sql_stmt_t *statement)
{
    sql_init_join_assist(statement, &for_union_qry->join_assist);
    OG_RETVALUE_IFTRUE(sql_qry->join_assist.join_node == NULL, OG_SUCCESS);
    for_union_qry->join_assist.outer_node_count = sql_qry->join_assist.outer_node_count;
    sql_join_node_t *src_join_node = sql_qry->join_assist.join_node;
    return sql_clone_join_root(statement, statement->context, src_join_node, &for_union_qry->join_assist.join_node,
                               &for_union_qry->tables, sql_alloc_mem);
}

static status_t og_process_union_query(sql_query_t *sql_qry, sql_query_t *for_union_qry, sql_stmt_t *statement)
{
    // 1) generate rs columns from origin select query
    if (og_gen_rs_cols_4_union_qry(sql_qry, for_union_qry, statement) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, generate rs_columns for union subquery failed");
        return OG_ERROR;
    }
    // 2) clone tables that used in from
    if (clone_tables_4_subqry(statement, sql_qry, for_union_qry) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, clone table for union subquery failed");
        return OG_ERROR;
    }
    // 3) clone join assist info
    if (og_copy_join_ast_4_union_qry(sql_qry, for_union_qry, statement) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, clone join assist for union subquery failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

// Create the basic structure of the UNION-optimized subquery.
static status_t og_build_union_query(sql_query_t *sql_qry, sql_query_t **union_sub_qry, sql_stmt_t *statement)
{
    sql_query_t *res_qry = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_query_t), (void **)&res_qry));
    if (sql_init_query(statement, NULL, sql_qry->loc, res_qry) != OG_SUCCESS) {
        return OG_ERROR;
    }
    res_qry->block_info->origin_id = ++statement->context->query_count;
    res_qry->block_info->transformed = OG_TRUE;

    // FOR_OR_2_UNION
    if (og_process_union_query(sql_qry, res_qry, statement) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, process union subquery failed");
        return OG_ERROR;
    }

    res_qry->has_no_or_expand = OG_TRUE;
    *union_sub_qry = res_qry;
    return OG_SUCCESS;
}

// Generate the corresponding filter conditions for the UNION subsql_qry,
// need combine the or_conds and remianing conds
static status_t og_build_filter_cond4union(sql_query_t *union_sub_qry, sql_stmt_t *statement, cond_node_t *or_cond,
                                           cond_tree_t *remain_conds)
{
    or_cond->processed = OG_FALSE;
    if (remain_conds != NULL) {
        OG_RETURN_IFERR(sql_clone_cond_tree(statement->context, remain_conds, &union_sub_qry->cond, sql_alloc_mem));
        return sql_add_cond_node(union_sub_qry->cond, or_cond);
    }

    OG_RETURN_IFERR(sql_create_cond_tree(statement->context, &union_sub_qry->cond));
    return sql_add_cond_node(union_sub_qry->cond, or_cond);
}

// Edit the ssa and ancestor columns
static status_t og_update_filter_cond4union(sql_query_t *union_sub_qry, sql_query_t *sql_qry, sql_stmt_t *statement,
                                            cond_node_t *or_cond_node)
{
    visit_assist_t visit_assist = { 0 };
    sql_init_visit_assist(&visit_assist, statement, sql_qry);
    visit_assist.param0 = (void *)union_sub_qry;
    return visit_cond_node(&visit_assist, or_cond_node, og_update_ssa_and_ancestor);
}

static status_t og_build_union_slct_node(sql_stmt_t *statement, select_node_t **select_node,
    sql_query_t *union_sub_qry)
{
    if (sql_alloc_mem(statement->context, sizeof(select_node_t), (void **)select_node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*select_node)->type = SELECT_NODE_QUERY;
    (*select_node)->query = union_sub_qry;
    return OG_SUCCESS;
}

// Generate the select nodes associated with the UNION.
static status_t og_build_union_qry_filter(sql_query_t *sql_qry, sql_stmt_t *statement, sql_query_t *union_sub_qry,
                                       cond_tree_t *remain_conds, cond_node_t *cond_node)
{
    // construct the where filtr conditions, including the remain_conds, or_conds, lnnvl_conds
    if (og_build_filter_cond4union(union_sub_qry, statement, cond_node, remain_conds) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, generate filter_conds for union subquery failed");
        return OG_ERROR;
    }

    // update ssa and column ancestor for union_query
    if (og_update_filter_cond4union(union_sub_qry, sql_qry, statement, union_sub_qry->cond->root) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, edit ssa and col ancestor for union subquery failed");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

// Generate the corresponding number of select_nodes based on the number of conditions in or_conds.
static status_t og_gen_slct_nodes_by_or_conds(sql_query_t *sql_qry, sql_stmt_t *statement, galist_t *or_conds,
                                              sql_select_t **sub_select_ctx, cond_tree_t *remain_conds)
{
    cond_tree_t *cond_tree = NULL;
    select_node_t *select_node = NULL;
    select_node_t *union_node = NULL;
    bool32 union_all_support = if_support_union_all(or_conds);

    for (uint32 i = 0; i < or_conds->count; i++) {
        if (og_build_or_conds_for_union_all(statement, union_all_support, or_conds, i, &cond_tree) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, build filter | lnnvl cond for UNION ALL failed");
            return OG_ERROR;
        }

        sql_query_t *union_sub_qry = NULL;
        if (og_build_union_query(sql_qry, &union_sub_qry, statement) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, build union as subquery failed");
            return OG_ERROR;
        }
        union_sub_qry->owner = *sub_select_ctx;

        if (og_build_union_slct_node(statement, &select_node, union_sub_qry) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, build union as subquery failed");
            return OG_ERROR;
        }

        if (og_build_union_qry_filter(sql_qry, statement, union_sub_qry, remain_conds, cond_tree->root) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, Generate the select nodes associated with the UNION. failed");
            return OG_ERROR;
        }

        // Use union to associate the select nodes of each OR filter condition.
        if ((*sub_select_ctx)->root != NULL) {
            OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(select_node_t), (void **)&(union_node)));
            union_node->left = (*sub_select_ctx)->root;
            union_node->right = select_node;
            union_node->type = ((i != or_conds->count - 1) || union_all_support)
                                ? SELECT_NODE_UNION_ALL
                                : SELECT_NODE_UNION;
            (*sub_select_ctx)->root = union_node;
        } else {
            (*sub_select_ctx)->root = select_node;
            (*sub_select_ctx)->first_query = select_node->query;
        }
    }

    (*sub_select_ctx)->rs_columns = (*sub_select_ctx)->first_query->rs_columns;
    return OG_SUCCESS;
}

// when sets is not null, meaning that there are some or_conds need to be combined, only used in Scen3
static status_t og_combine_or_cond_branches(galist_t *or_conds, uint32 *sets, sql_stmt_t *statement,
                                            cond_node_t *opt_node)
{
    uint32 or_branch_cnt = 0; // final or cond branch count after merge
    for (uint32 idx = 0; idx < or_conds->count; idx++) {
        cond_node_t *node_prev = (cond_node_t *)cm_galist_get(or_conds, idx);
        // Group adjacent or_cond into one SELECT_NODE under UNION structure as specified.
        // For example: {{A} OR {B} OR {C} OR {D}}, SETS = {0, 0, 1, 2},
        // which means the plan is {{{A} OR {B}} UNION {C} UNION {D}}
        while (idx < or_conds->count - 1 && sets[idx] == sets[idx + 1]) {
            cond_node_t *node_next = (cond_node_t *)cm_galist_get(or_conds, idx + 1);

            if (sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)&opt_node) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[OR2UNION]: Rewrite step, alloc opt_node memory for merge union node failed");
                return OG_ERROR;
            }

            OG_LOG_DEBUG_INF("[OR2UNION]: merge or cond branch %d and %d into one union cond branch", idx, idx + 1);
            merge_or_cond(node_prev, node_next, opt_node);
            node_prev = opt_node;
            idx++;
        }
        cm_galist_set(or_conds, or_branch_cnt, node_prev);
        or_branch_cnt++;
    }
    or_conds->count = or_branch_cnt;
    return OG_SUCCESS;
}

// Generate subqueries for each OR filter condition and associate them using UNION to construct the UNION subquery.
static status_t og_gen_union_sub_slct(sql_query_t *sql_qry, sql_stmt_t *statement, galist_t *or_conds,
                                      sql_select_t **sub_select_ctx, cond_tree_t *remain_conds)
{
    // Initialize a new sub_select_ctx as the derived table for the UNION subquery.
    if (sql_alloc_select_context(statement, SELECT_AS_TABLE, sub_select_ctx) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, alloc new sub_select for union failed");
        return OG_ERROR;
    }
    // union_query as the sub_qry from origin query
    (*sub_select_ctx)->parent = sql_qry;
    OG_RETURN_IFERR(sql_create_list(statement, &(*sub_select_ctx)->select_sort_items));

    return og_gen_slct_nodes_by_or_conds(sql_qry, statement, or_conds, sub_select_ctx, remain_conds);
}

// For the already identified OR conditions (temporarily stored in or_conds),
// remove the corresponding OR conditions from the original query.
static status_t og_remove_or_conds_in_qry(sql_query_t *sql_qry, sql_stmt_t *statement, galist_t *or_conds, uint32 *sets,
                                          cond_tree_t **remain_conds)
{
    cond_node_t *ori_node = NULL;
    cond_node_t *opt_node = NULL;

    uint32 id = 0;
    while (id < or_conds->count) {
        ori_node = (cond_node_t *)cm_galist_get(or_conds, id);
        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(cond_node_t), (void **)&opt_node));
        *opt_node = *ori_node;
        cm_galist_set(or_conds, id, opt_node);
        ori_node->type = COND_NODE_TRUE;
        id++;
    }

    OG_RETURN_IFERR(try_eval_logic_cond(statement, sql_qry->cond->root));
    // The remaining filter conditions of the original sql_qry, excluding the conditions in or_conds.
    *remain_conds = sql_qry->cond->root->type != COND_NODE_TRUE ? sql_qry->cond : NULL;
    sql_qry->cond = NULL;
    OG_RETVALUE_IFTRUE(sets == NULL, OG_SUCCESS);

    return og_combine_or_cond_branches(or_conds, sets, statement, opt_node);
}

// During the UNION optimization process, adjust the rowid column references in the parent sql_qry,
// to ensure they map to the correct columns in the subquery.
static status_t og_edit_rowid4union(expr_node_t *exprn, sql_query_t *sub_qry)
{
    uint16 i = 0;
    rs_column_t *rs_column = NULL;
    galist_t *rs_columns = sub_qry->rs_columns;
    while (i < rs_columns->count) {
        rs_column = (rs_column_t *)cm_galist_get(rs_columns, i);
        if (rs_column->type == RS_COL_CALC && TREE_IS_RES_ROWID(rs_column->expr) &&
            ROWID_NODE_TAB(exprn) == ROWID_EXPR_TAB(rs_column->expr)) {
            // Map the rowid node of parent query to the i-th column in the subquery result set.
            sql_make_rowid_column_node(exprn, i, 0, 0);
            return OG_SUCCESS;
        }
        i++;
    }
    OG_THROW_ERROR(ERR_INVOKE_FUNC_FAIL, "Change the rowid column of parent query for union convert error");
    return OG_ERROR;
}

static uint16 og_get_column_id4union(var_column_t *var_col, sql_query_t *sub_qry)
{
    uint16 id = 0;
    rs_column_t *rs_column = NULL;
    while (id < sub_qry->rs_columns->count) {
        rs_column = (rs_column_t *)cm_galist_get(sub_qry->rs_columns, id);
        if (rs_column->type == RS_COL_COLUMN && var_col->tab == rs_column->v_col.tab &&
            var_col->col == rs_column->v_col.col) {
            return id;
        }
        id++;
    }
    return OG_INVALID_ID16;
}

static status_t og_update_rs_cols4union(var_column_t *var_col, sql_query_t *sub_qry)
{
    var_col->col = og_get_column_id4union(var_col, sub_qry);
    var_col->tab = 0;
    OG_RETVALUE_IFTRUE(var_col->col != OG_INVALID_ID16, OG_SUCCESS);
    OG_THROW_ERROR(ERR_INVOKE_FUNC_FAIL, "Change the rs_column of parent query for union convert error");
    return OG_ERROR;
}

static status_t og_edit_expr_node4union(visit_assist_t *visit_ass, expr_node_t **exprn)
{
    if ((*exprn)->type == EXPR_NODE_COLUMN) {
        if (og_update_rs_cols4union(&(*exprn)->value.v_col, (sql_query_t *)visit_ass->param0) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step4, handle the rs_column failed");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (NODE_IS_RES_ROWID(*exprn)) {
        if (og_edit_rowid4union(*exprn, (sql_query_t *)visit_ass->param0) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite step4, handle the rowid columns failed");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if ((*exprn)->type == EXPR_NODE_GROUP) {
        expr_node_t *ori_exprn = sql_get_origin_ref(*exprn);
        galist_t *edit_list = (galist_t *)visit_ass->param1;
        uint32 i = 0;
        expr_node_t *edit_exprn = NULL;
        while (i < edit_list->count) {
            edit_exprn = (expr_node_t *)cm_galist_get(edit_list, i++);
            OG_RETVALUE_IFTRUE(ori_exprn == edit_exprn, OG_SUCCESS);
        }
        if (cm_galist_insert(edit_list, ori_exprn) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return visit_expr_node(visit_ass, &ori_exprn, og_edit_expr_node4union);
    }

    return OG_SUCCESS;
}

static status_t og_rewrite_sort_items_union(visit_assist_t *visit_ass, galist_t *sort_items)
{
    uint32 i = 0;
    while (i < sort_items->count) {
        sort_item_t *item = (sort_item_t *)cm_galist_get(sort_items, i++);
        OG_RETURN_IFERR(visit_expr_tree(visit_ass, item->expr, og_edit_expr_node4union));
    }
    return OG_SUCCESS;
}

static status_t og_update_order_by_union(visit_assist_t *visit_ass)
{
    if (!visit_ass->query->has_distinct && visit_ass->query->group_sets->count == 0) {
        return og_rewrite_sort_items_union(visit_ass, visit_ass->query->sort_items);
    }
    return OG_SUCCESS;
}

static status_t og_update_aggr_cond_node(galist_t *aggrs, visit_assist_t *visit_ass)
{
    expr_node_t *exprn = NULL;
    uint32 i = 0;
    while (i < aggrs->count) {
        exprn = (expr_node_t *)cm_galist_get(aggrs, i++);
        OG_RETURN_IFERR(visit_expr_node(visit_ass, &exprn, og_edit_expr_node4union));
    }
    return OG_SUCCESS;
}

static status_t og_update_group_by_union(galist_t *group_sets, visit_assist_t *visit_ass)
{
    group_set_t *group = (group_set_t *)cm_galist_get(group_sets, 0);
    expr_tree_t *expr = NULL;
    uint32 i = 0;
    while (i < group->items->count) {
        expr = (expr_tree_t *)cm_galist_get(group->items, i++);
        OG_RETURN_IFERR(visit_expr_tree(visit_ass, expr, og_edit_expr_node4union));
    }
    return OG_SUCCESS;
}

static status_t og_update_rs_column_list(visit_assist_t *visit_ass, galist_t *edit_rs_cols)
{
    uint32 i = 0;
    while (i < edit_rs_cols->count) {
        rs_column_t *rs_col = (rs_column_t *)cm_galist_get(edit_rs_cols, i++);
        if (rs_col->type != RS_COL_COLUMN) {
            OG_RETURN_IFERR(visit_expr_tree(visit_ass, rs_col->expr, og_edit_expr_node4union));
        } else {
            if (og_update_rs_cols4union(&rs_col->v_col, visit_ass->param0) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, edit rs_columns failed");
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t og_update_rs_cols_union(visit_assist_t *visit_ass)
{
    OG_RETVALUE_IFTRUE(visit_ass->query->group_sets->count > 0, OG_SUCCESS);
    if (visit_ass->query->has_distinct &&
        og_update_rs_column_list(visit_ass, visit_ass->query->distinct_columns) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, update distinct cols failed");
        return OG_ERROR;
    }

    if (visit_ass->query->winsort_list->count > 0 &&
        og_update_rs_column_list(visit_ass, visit_ass->query->winsort_rs_columns) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, update winsort rs_columns failed");
        return OG_ERROR;
    }

    return og_update_rs_column_list(visit_ass, visit_ass->query->rs_columns);
}

static status_t og_update_associated_cols_info(sql_query_t *sql_qry, sql_stmt_t *statement,
                                               sql_select_t *sub_select_ctx)
{
    visit_assist_t visit_ass;
    galist_t modify_list;
    sql_init_visit_assist(&visit_ass, statement, sql_qry);
    OGSQL_SAVE_STACK(statement);
    cm_galist_init(&modify_list, statement->session->stack, cm_stack_alloc);
    visit_ass.param0 = (void *)sub_select_ctx->first_query;
    visit_ass.param1 = (void *)&modify_list;

    if (sql_qry->aggrs->count > 0 && og_update_aggr_cond_node(sql_qry->aggrs, &visit_ass) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, edit aggr cond node for union failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    if (sql_qry->group_sets->count > 0 && og_update_group_by_union(sql_qry->group_sets, &visit_ass) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, edit group by for union failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    if (sql_qry->sort_items->count > 0 && og_update_order_by_union(&visit_ass) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, edit order by for union failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    if (og_update_rs_cols_union(&visit_ass) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 4, update rs_columns for union failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static status_t og_rewrite_or_query2union(sql_query_t *sql_qry, sql_stmt_t *statement, galist_t *or_conds, uint32 *sets)
{
    cond_tree_t *remain_conds = NULL;
    sql_select_t *sub_select_ctx = NULL;

    if (og_remove_or_conds_in_qry(sql_qry, statement, or_conds, sets, &remain_conds) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 1, remove or conds failed");
        return OG_ERROR;
    }

    if (og_gen_union_sub_slct(sql_qry, statement, or_conds, &sub_select_ctx, remain_conds) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 2, generate union sub select failed");
        return OG_ERROR;
    }

    if (og_replace_query_table(sql_qry, statement, sub_select_ctx) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Rewrite step 3, replace union query table failed");
        return OG_ERROR;
    }

    sql_array_reset(&sql_qry->ssa);
    return og_update_associated_cols_info(sql_qry, statement, sub_select_ctx);
}

static bool32 og_or2union_verify_datatype(sql_query_t *sql_qry)
{
    if (sql_qry->has_distinct) {
        return OG_TRUE;
    }
    rs_column_t *rs_column = NULL;
    uint32 id = 0;
    while (id < sql_qry->rs_columns->count) {
        rs_column = (rs_column_t *)cm_galist_get(sql_qry->rs_columns, id++);
        if (rs_column->typmod.is_array) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 og_is_contains_or_cond(cond_node_t *node)
{
    if (node == NULL) {
        return OG_FALSE;
    }

    if (node->type == COND_NODE_OR) {
        return OG_TRUE;
    }

    if (node->type == COND_NODE_AND) {
        return og_is_contains_or_cond(node->left) || og_is_contains_or_cond(node->right);
    }

    return OG_FALSE;
}

static bool32 og_is_only_normal_table(sql_query_t *sql_qry)
{
    if (sql_qry->tables.count > OR2UNION_MAX_TABLES) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for public, table cnt > 32, no rewrite, query_table_cnt = %d",
                         sql_qry->tables.count);
        return OG_FALSE;
    }

    return is_query_tables_all_normal(sql_qry);
}

static bool32 og_is_valid_for_or2union(sql_query_t *sql_qry)
{
    if (!og_is_only_normal_table(sql_qry)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for public, query tables has no_normal_table, no rewrite");
        return OG_TRUE;
    }

    if (!og_is_contains_or_cond(sql_qry->cond->root)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for public, query has no or_cond, no rewrite");
        return OG_TRUE;
    }

    if (!og_or2union_verify_datatype(sql_qry)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for public, the column is array, no rewrite");
        return OG_TRUE;
    }

    return OG_FALSE;
}

// Ensure there are no semantic conflicts for or2union,
// and converted union_scope is isolated from the outer query
static bool32 og_has_semantic_conflicts(sql_query_t *sql_qry)
{
    return sql_qry->owner == NULL || sql_qry->owner->has_ancestor > 0 || sql_qry->group_sets->count > 1 ||
           sql_qry->join_assist.outer_node_count > 0 || sql_qry->cond == NULL ||
           (sql_qry->cond->incl_flags & SQL_INCL_ROWNUM) || sql_qry->connect_by_cond != NULL;
}

static bool32 og_or2union_can_not_apply(sql_stmt_t *statement, sql_query_t *sql_qry)
{
    if (HAS_SPEC_TYPE_HINT(sql_qry->hint_info, OPTIM_HINT, HINT_KEY_WORD_NO_OR_EXPAND)) {
        return OG_TRUE;
    }

    if (og_has_semantic_conflicts(sql_qry)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for public, there are semantic_conflicts, no rewrite");
        return OG_TRUE;
    }

    if (og_is_valid_for_or2union(sql_qry)) {
        return OG_TRUE;
    }

    if (!HAS_SPEC_TYPE_HINT(sql_qry->hint_info, OPTIM_HINT, HINT_KEY_WORD_OR_EXPAND) &&
        !ogsql_opt_param_is_enable(statement, g_instance->sql.enable_or_expand, OPT_OR_EXPANSION)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline void og_collect_expr_columns(cols_used_t *left_col, cols_used_t *right_col, cmp_node_t *cmp_node)
{
    init_cols_used(left_col);
    init_cols_used(right_col);
    sql_collect_cols_in_expr_tree(cmp_node->left, left_col);
    sql_collect_cols_in_expr_tree(cmp_node->right, right_col);
    return;
}

static bool32 og_check_hash_cond_exist(cmp_node_t *cmp_node, uint32 *tbl1_id, uint32 *tbl2_id)
{
    if (cmp_node->type != CMP_TYPE_EQUAL) {
        return OG_FALSE;
    }

    cols_used_t left_col = { 0 };
    cols_used_t right_col = { 0 };
    og_collect_expr_columns(&left_col, &right_col, cmp_node);
    return sql_can_equal_used_by_hash(&left_col, &right_col, tbl1_id, tbl2_id);
}

static void og_update_bitmap_by_hash_cond(cond_node_t *node, bitmapset_t *bit_map)
{
    if (node->type != COND_NODE_COMPARE || node->cmp->has_conflict_chain) {
        return;
    }

    uint32 tbl1_id = 0;
    uint32 tbl2_id = 0;

    if (!og_check_hash_cond_exist(node->cmp, &tbl1_id, &tbl2_id)) {
        return;
    }

    add_ele_to_bitmaps(bit_map, tbl1_id);
    add_ele_to_bitmaps(bit_map, tbl2_id);
    return;
}

static void og_init_or_expand_info(sql_query_t *sql_qry, sql_stmt_t *statement, or_expand_helper_t *ex_helper)
{
    ex_helper->has_nested_or_cond = OG_FALSE;
    ex_helper->opt_subselect_count = 0;
    ex_helper->or_conds = NULL;
    ex_helper->query = sql_qry;
    ex_helper->stmt = statement;
    set_no_or2u_flag(ex_helper);
    // When single table sql_qry, expand_helper->table_bit_cnt = 0
    // When non-single table sql_qry, the expand_helper->table_bit_cnt is count of query tables
    ex_helper->table_bit_cnt = sql_qry->tables.count <= 1 ? 0 : sql_qry->tables.count;
    ex_helper->table_bitmap.map_low = 0;
    ex_helper->table_bitmap.map_high = 0;

    cond_node_t *cond_node = FIRST_NOT_AND_NODE(sql_qry->cond->root);
    for (; cond_node != NULL; cond_node = cond_node->next) {
        og_update_bitmap_by_hash_cond(cond_node, &ex_helper->table_bitmap);
    }
    return;
}

static bool32 og_check_in_exist_subslct_invalid(sql_select_t *sub_select, sql_query_t *sub_slct_qry)
{
    if (sub_slct_qry->ssa.count > 0) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for scen1, the sub_select has sub_select, no rewrite");
        return OG_TRUE;
    }

    if (og_check_query_has_sets(sub_select->root->type)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for scen1, the sub_select is sets type, no rewrite");
        return OG_TRUE;
    }

    return (sub_slct_qry->cond != NULL && (sub_slct_qry->cond->incl_flags & SQL_INCL_ROWNUM));
}

static status_t og_deal_exists_or_cond_subslct(or_expand_helper_t *ex_helper, sql_query_t *sub_sql_qry)
{
    bool32 can_rewrite = OG_FALSE;
    // Check if the index can be used at the correlated col, and compare the cost of hash-join-semi and nested-loops.
    if (og_check_index_4_rewrite(ex_helper->stmt, sub_sql_qry, CK_FOR_OR2UNION, &can_rewrite) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen1, check exists cond (rbo or cbo) failed");
        return OG_ERROR;
    }

    if (can_rewrite) {
        set_high_or2u_flag(ex_helper);
    } else {
        set_no_or2u_flag(ex_helper);
    }

    return OG_SUCCESS;
}

// In this func, OR conditions must be IN, NOT IN, EXISTS, or NOT EXISTS,
// because we need use hash-join-semi for opt sub-query
static status_t og_check_in_exist_sub_slct(or_expand_helper_t *ex_helper, cmp_node_t *cmp, bool32 *has_exist_cmp,
                                           bool32 *has_in_cmp)
{
    // right of IN | NOT IN must be single child_select
    if (has_in_cmp != NULL && *has_in_cmp == OG_TRUE &&
        (cmp->right->next != NULL || TREE_EXPR_TYPE(cmp->right) != EXPR_NODE_SELECT)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for scen1, the cond type in or not_in not a single sub_select, no rewrite");
        set_no_or2u_flag(ex_helper);
        return OG_SUCCESS;
    }

    sql_select_t *sub_select = (sql_select_t *)EXPR_VALUE_PTR(var_object_t, cmp->right)->ptr;
    sql_query_t *sub_slct_qry = sub_select->first_query;
    if (og_check_in_exist_subslct_invalid(sub_select, sub_slct_qry)) {
        set_no_or2u_flag(ex_helper);
        OG_LOG_DEBUG_INF("[OR2UNION] Check for scen1, the sub select not meet the requirements, no rewrite");
        return OG_SUCCESS;
    }

    ex_helper->opt_subselect_count++;

    if (has_in_cmp != NULL && *has_in_cmp == OG_TRUE) {
        set_high_or2u_flag(ex_helper);
        return OG_SUCCESS;
    }

    // For exist compare cond, there must have ancestor col,
    // since the sub-query not correlated with the parent table would be precomputed by the optimizer.
    if (sub_select->has_ancestor == 0) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for scen1, exists subslct without ancestor col, low rewrite");
        set_low_or2u_flag(ex_helper);
        return OG_SUCCESS;
    }

    return og_deal_exists_or_cond_subslct(ex_helper, sub_slct_qry);
}

// Check for Scenario 2,
// Check if it is possible to use hash join to associate the parent table with the child table. Requirements:
// 1). No dynamic subqueries are allowed.
// 2). The equality condition must have fields from the parent table on one side and fields from the child table on the
// other side.
static status_t og_handle_or_cond_equal(or_expand_helper_t *ex_helper, cond_node_t *cond_node)
{
    uint32 tbl1_id = 0;
    uint32 tbl2_id = 0;
    if (og_check_hash_cond_exist(cond_node->cmp, &tbl1_id, &tbl2_id)) {
        set_high_or2u_flag(ex_helper);
        add_ele_to_bitmaps(&ex_helper->table_bitmap, tbl1_id);
        add_ele_to_bitmaps(&ex_helper->table_bitmap, tbl2_id);
        return OG_SUCCESS;
    }
    set_no_or2u_flag(ex_helper);
    OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen2, can not construct hash cond, no rewrite");
    return OG_SUCCESS;
}

static status_t og_or2union_check_cond(or_expand_helper_t *ex_helper, cond_node_t *cond_node)
{
    if (cond_node->type == COND_NODE_OR) {
        // If OR node appears again under AND node or COMPARE node, this is nested OR conditions.
        ex_helper->has_nested_or_cond = OG_TRUE;
        set_no_or2u_flag(ex_helper);
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen1-2, there has nested or cond");
        return OG_SUCCESS;
    }

    if (cond_node->type == COND_NODE_AND) {
        OG_RETURN_IFERR(og_or2union_check_cond(ex_helper, cond_node->left));
        rewrite_level_t left_level = ex_helper->rewrite_level;

        OG_RETURN_IFERR(og_or2union_check_cond(ex_helper, cond_node->right));
        rewrite_level_t right_level = ex_helper->rewrite_level;
        // For the compare-expr under AND node that under an OR node, only one side meet the rewrite requirement is ok,
        // The others not meet the requirement will be treated as auxiliary filter condition.
        ex_helper->rewrite_level = MAX(left_level, right_level);
        return OG_SUCCESS;
    }

    if (cond_node->type == COND_NODE_COMPARE) {
        // Scenario 2 : or cond must be equal type
        // Check if both sides of the OR condition can independently construct hash join for query optimization.
        if (cond_node->cmp->type == CMP_TYPE_EQUAL) {
            return og_handle_or_cond_equal(ex_helper, cond_node);
        }
        // Scenario 1 : or cond type must be in | not in | exist | not exist
        // Check if both sides of the OR condition can independently use hash join semi for query optimization.
        bool32 has_exist_cmp = cond_has_exist_cmp(cond_node->cmp->type);
        bool32 has_in_cmp = cond_has_in_cmp(cond_node->cmp->type);
        if (has_exist_cmp || has_in_cmp) {
            return og_check_in_exist_sub_slct(ex_helper, cond_node->cmp, &has_exist_cmp, &has_in_cmp);
        }

        OG_LOG_DEBUG_INF(
            "[OR2UNION] Check for Scen1, the or cond must be in | not in | exist | not exist, no rewrite");
    }

    set_no_or2u_flag(ex_helper);
    return OG_SUCCESS;
}

static status_t og_or2union_process_conds(or_expand_helper_t *ex_helper, cond_node_t *cond_node)
{
    uint32 sub_select_count = ex_helper->opt_subselect_count;
    ex_helper->opt_subselect_count = 0;
    bitmapset_t tab_bitmap = ex_helper->table_bitmap;

    if (og_or2union_check_cond(ex_helper, cond_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen1-2, check or cond failed");
        return OG_ERROR;
    }

    if (has_no_or2u_flag(ex_helper) || ex_helper->has_nested_or_cond ||
        (get_ele_cnt_from_bitmaps(&ex_helper->table_bitmap) != ex_helper->table_bit_cnt &&
         ex_helper->opt_subselect_count == 0)) {
        ex_helper->table_bitmap = tab_bitmap;
        ex_helper->opt_subselect_count = sub_select_count;
        set_no_or2u_flag(ex_helper);
        return OG_SUCCESS;
    }

    ex_helper->table_bitmap = tab_bitmap;
    ex_helper->opt_subselect_count += sub_select_count;
    return cm_galist_insert(ex_helper->or_conds, cond_node);
}

static status_t og_evaluate_or2union_conver(or_expand_helper_t *ex_helper, cond_node_t *cond_node)
{
    OG_RETURN_IFERR(sql_stack_safe(ex_helper->stmt));

    if (cond_node->type == COND_NODE_OR) {
        OG_RETURN_IFERR(og_evaluate_or2union_conver(ex_helper, cond_node->left));
        OG_RETVALUE_IFTRUE(has_no_or2u_flag(ex_helper), OG_SUCCESS);
        rewrite_level_t left_cond_level = ex_helper->rewrite_level;

        OG_RETURN_IFERR(og_evaluate_or2union_conver(ex_helper, cond_node->right));
        OG_RETVALUE_IFTRUE(has_no_or2u_flag(ex_helper), OG_SUCCESS);
        rewrite_level_t right_cond_level = ex_helper->rewrite_level;

        ex_helper->rewrite_level = MAX(left_cond_level, right_cond_level);
        return OG_SUCCESS;
    }

    if (cond_node->type == COND_NODE_AND || cond_node->type == COND_NODE_COMPARE) {
        return og_or2union_process_conds(ex_helper, cond_node);
    }

    set_no_or2u_flag(ex_helper);
    return OG_SUCCESS;
}

// Traverse all nodes on both sides of the OR condition until the compare node,
// then check if the hash-opt (hash-join or hash-join-semi) can be applied under the compare node.
static status_t og_traverse_process_or_cond(sql_stmt_t *statement, cond_node_t *node,
    or_expand_helper_t *expand_helper, galist_t *opt_or_conds)
{
    while (node != NULL) {
        OG_BREAK_IF_TRUE(expand_helper->opt_subselect_count > 0);

        if (node->type != COND_NODE_OR) {
            node = node->next;
            continue;
        }

        galist_t sub_conds;
        cm_galist_init(&sub_conds, statement->session->stack, cm_stack_alloc);
        expand_helper->or_conds = &sub_conds;

        if (og_evaluate_or2union_conver(expand_helper, node) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen1-2, collect or_cond info failed");
            return OG_ERROR;
        }

        if (has_high_or2u_flag(expand_helper)) {
            *opt_or_conds = sub_conds;
        } else if (expand_helper->opt_subselect_count > 0) {
            return OG_SUCCESS;
        }
        node = node->next;
    }
    return OG_SUCCESS;
}

static status_t og_determine_final_result(or_expand_helper_t *expand_helper, sql_query_t *sql_qry,
                                          galist_t *opt_or_conds, bool32 *need_rewrite)
{
    if (opt_or_conds->count == 0) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen1-2, there is no opt_sub_select, no rewrite");
        *need_rewrite = OG_FALSE;
        return OG_SUCCESS;
    }

    if (expand_helper->opt_subselect_count != sql_qry->ssa.count) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen1-2, the opt_sub_select != query_sub_select_cnt, no rewrite");
        *need_rewrite = OG_FALSE;
        return OG_SUCCESS;
    }

    // In Scen 1, the used_table_cnt = 0, expand_helper->table_bit_cnt = 0
    // the expand_helper->opt_subselect_count is count of sub-query can be opt
    bool32 all_or_cond_hash_join = OG_FALSE;
    uint32 used_table_cnt = get_ele_cnt_from_bitmaps(&expand_helper->table_bitmap);
    all_or_cond_hash_join = (expand_helper->table_bit_cnt == used_table_cnt);
    *need_rewrite = expand_helper->opt_subselect_count > 0 ? all_or_cond_hash_join : !all_or_cond_hash_join;
    return OG_SUCCESS;
}

// Check for Scenario 1 and 2
// for Scenario 1, check if both sides of the OR condition can independently use hash join semi for query optimization.
// for Scenario 2, check if both sides of the OR condition can independently use hash join for query optimization.
static status_t og_check_cond_rewrite_hash(sql_query_t *sql_qry, sql_stmt_t *statement, galist_t *opt_or_conds,
                                           bool32 *need_rewrite)
{
    // Check for scenario 1: in single-table sql_qry, ssa.count must > 1
    if (sql_qry->tables.count == 1 && sql_qry->ssa.count <= 1) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen1, single table sql_qry, the sub select cnt must > 1, no rewrite");
        *need_rewrite = OG_FALSE;
        return OG_SUCCESS;
    }

    reorganize_cond_tree(sql_qry->cond->root);
    or_expand_helper_t expand_helper = { 0 };
    og_init_or_expand_info(sql_qry, statement, &expand_helper);
    cond_node_t *node = FIRST_NOT_AND_NODE(sql_qry->cond->root);

    if (og_traverse_process_or_cond(statement, node, &expand_helper, opt_or_conds) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen1-2, traverse or cond tree failed");
        return OG_ERROR;
    }

    return og_determine_final_result(&expand_helper, sql_qry, opt_or_conds, need_rewrite);
}

static double og_or2union_calc_addition_cost(sql_join_node_t *join_node, uint32 tbl_id)
{
    if (join_node == NULL || join_node->type == JOIN_TYPE_NONE) {
        return CBO_MIN_COST;
    }

    bool32 is_nest_loop = (join_node->oper < JOIN_OPER_HASH);
    double left_cost = og_or2union_calc_addition_cost(join_node->left, tbl_id);
    double right_cost = og_or2union_calc_addition_cost(join_node->right, tbl_id);
    double ex_cost = CBO_MIN_COST;

    if (!is_nest_loop) {
        bool32 right_in_list = sql_table_in_list(&join_node->right->tables, tbl_id);
        ex_cost = right_in_list ? join_node->left->cost.cost + right_cost : join_node->right->cost.cost + left_cost;
    } else {
        ex_cost = left_cost + right_cost;
    }
    return CBO_COST_SAFETY_RET(ex_cost);
}

static status_t og_check_driver_tbl_index_impl(sql_table_t *tbl, knl_index_desc_t *index, or2union_info_t *info,
                                               bool32 *need_rewrite, double *additional_cost)
{
    // For the following scenario, rewriting with UNION will result in duplicate scans.
    if (index == NULL || HAS_SPEC_TYPE_HINT(tbl->hint_info, OPTIM_HINT, HINT_KEY_WORD_NO_OR_EXPAND)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen3, the selected index is null, no rewrite");
        *need_rewrite = OG_FALSE;
        return OG_SUCCESS;
    }

    if (tbl->index_full_scan || index->column_count == 1) {
        OG_LOG_DEBUG_INF(
            "[OR2UNION] Check for Scen3, the selected index is single column index or index full scan, no rewrite");
        *need_rewrite = OG_FALSE;
        return OG_SUCCESS;
    }

    *need_rewrite = OG_TRUE;
    set_or2u_cbo_info(info, tbl, index, *additional_cost);
    return OG_SUCCESS;
}

// Check if the query table can use an index scan,
// and calculate the scan cost excluding the filtering conditions on the OR branch.
static status_t og_check_driver_tbl_index(sql_query_t *sql_qry, sql_stmt_t *statement, or2union_info_t *info,
                                          bool32 *need_rewrite)
{
    // Addition_cost represents the cost of the table-join under the current sql_qry,
    // but excluding the filtering conditions.
    double additional_cost = CBO_DEFAULT_RANDOM_PAGE_COST;
    sql_table_t *tbl = NULL;
    knl_index_desc_t *driver_tbl_index = NULL;

    OG_RETURN_IFERR(og_create_qry_jtree_4_rewrite(statement, sql_qry, &sql_qry->join_root));
    if (sql_qry->tables.count != 1) {
        uint32 id = 0;
        while (id < sql_qry->tables.count) {
            tbl = (sql_table_t *)sql_array_get(&sql_qry->tables, id++);
            OG_BREAK_IF_TRUE(tbl->is_join_driver);
        }
        info->current_cost = sql_qry->join_root->cost.card * CBO_DEFAULT_CPU_HASH_BUILD_COST;
        additional_cost += og_or2union_calc_addition_cost(sql_qry->join_root, tbl->id);
    } else {
        tbl = (sql_table_t *)sql_array_get(&sql_qry->tables, 0);
        info->current_cost = tbl->card * CBO_DEFAULT_CPU_HASH_BUILD_COST;
    }

    driver_tbl_index = tbl->index;
    og_free_query_vmc(sql_qry);
    return og_check_driver_tbl_index_impl(tbl, driver_tbl_index, info, need_rewrite, &additional_cost);
}

static status_t og_init_or2union_info(or2union_info_t *info, sql_stmt_t *statement, expr_node_t *col_exprn,
                                      uint32 sub_cond_cnt)
{
    uint32 cache_cnt = ((sub_cond_cnt + 1) * sub_cond_cnt) >> 1;
    info->is_merge_or_cond = OG_FALSE;
    info->current_cost = 0.0;
    info->optimal_cost = 0.0;
    info->additional_cost = 0.0;
    if (sql_stack_alloc(statement, sizeof(double) * cache_cnt, (void **)&info->cost_cache) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < cache_cnt; i++) {
        info->cost_cache[i] = CBO_MIN_COST;
    }

    info->or_branch_count = sub_cond_cnt;
    info->set_id = 0;
    if (sql_stack_alloc(statement, sizeof(uint32) * info->or_branch_count, (void **)&info->sets) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_stack_alloc(statement, sizeof(uint32) * info->or_branch_count, (void **)&info->optimal_set) != OG_SUCCESS) {
        return OG_ERROR;
    }
    info->start_id = 0;
    info->iteration_count = 0;
    info->target_column = col_exprn;
    return OG_SUCCESS;
}

static void og_construct_expr_col_node(expr_node_t *exprn, uint32 type, uint32 tbl_id, uint32 column_id)
{
    exprn->left = NULL;
    exprn->right = NULL;
    exprn->datatype = type;
    exprn->type = EXPR_NODE_COLUMN;
    exprn->value.v_col.datatype = type;
    exprn->value.v_col.tab = tbl_id;
    exprn->value.v_col.col = column_id;
    exprn->value.v_col.ss_start = OG_INVALID_ID32;
    exprn->value.v_col.ss_end = OG_INVALID_ID32;
    exprn->value.v_col.ancestor = 0;
    return;
}

static status_t og_non_leading_col_in_index(sql_table_t *tbl, knl_index_desc_t *index_desc, expr_node_t *col_exprn,
                                            uint16 column_id, bool32 *need_rewrite)
{
    uint32 start_id = 1;
    knl_column_t *column = NULL;
    // Both sides of the OR condition must be non-leading columns of the selected index.
    while (start_id < index_desc->column_count) {
        if (index_desc->columns[start_id] == column_id) {
            column = knl_get_column(tbl->entry->dc.handle, column_id);
            if (KNL_COLUMN_IS_ARRAY(column)) {
                OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen3, the column is array type, no rewrite");
                *need_rewrite = OG_FALSE;
                break;
            }
            og_construct_expr_col_node(col_exprn, column->datatype, tbl->id, column_id);
            *need_rewrite = OG_TRUE;
            return OG_SUCCESS;
        }
        start_id++;
    }

    if (!(*need_rewrite)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen3, the or_cond col index leading col, no rewrite");
    }

    return OG_SUCCESS;
}

static bool32 og_check_index_cmp_type(cmp_type_t type)
{
    if (type == CMP_TYPE_IN || type == CMP_TYPE_BETWEEN || type == CMP_TYPE_EQUAL || type == CMP_TYPE_LESS_EQUAL ||
        type == CMP_TYPE_IS_NULL || type == CMP_TYPE_GREAT_EQUAL || type == CMP_TYPE_LESS || type == CMP_TYPE_GREAT) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 og_is_single_local_col(expr_tree_t *expr)
{
    return expr != NULL && IS_LOCAL_COLUMN(expr) && expr->next == NULL;
}

// Check if the conditions on both sides of the OR condition meet the following criteria:
// 1. One side of the comparison expression must be a single table field, and the other side must be a constant value.
// 2. The fields involved in comparison must belong to the same table and be the same field within the current layer.
// 3. The comparison must be of a specific comparison type, see @og_check_index_cmp_type.
static bool32 og_check_cmp_cond_info(cmp_node_t *cmp_node, uint32 tbl_id, uint16 *column_id)
{
    if (cmp_node == NULL || !og_check_index_cmp_type(cmp_node->type)) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen3, or_cond com_type not meet the requirements, no rewrite");
        return OG_FALSE;
    }

    // One side is a single local column, and the other is a constant value expr.
    expr_node_t *col_exprn = NULL;
    bool32 left_is_col = og_is_single_local_col(cmp_node->left) && sql_is_const_expr_tree(cmp_node->right);
    bool32 right_is_col = og_is_single_local_col(cmp_node->right) && sql_is_const_expr_tree(cmp_node->left);

    if (left_is_col) {
        col_exprn = cmp_node->left->root;
    } else if (right_is_col) {
        col_exprn = cmp_node->right->root;
    } else {
        OG_LOG_DEBUG_INF(
            "[OR2UNION] Check for Scen3, requiring or_cond one side is single col, another side is const_val");
        return OG_FALSE;
    }

    if (col_exprn != NULL && NODE_TAB(col_exprn) == tbl_id) {
        *column_id = NODE_COL(col_exprn);
        return OG_TRUE;
    }

    return OG_FALSE;
}

static bool32 og_check_sub_or_cond_info_impl(cond_node_t *node, uint32 tbl_id, uint16 *column_id)
{
    uint16 left_col_id = OG_INVALID_ID16;
    uint16 right_col_id = OG_INVALID_ID16;

    if (node->type == COND_NODE_OR || node->type == COND_NODE_AND) {
        if (og_check_sub_or_cond_info_impl(node->left, tbl_id, &left_col_id) &&
            og_check_sub_or_cond_info_impl(node->right, tbl_id, &right_col_id)) {
            *column_id = (left_col_id == right_col_id) ? left_col_id : OG_INVALID_ID16;
            return OG_TRUE;
        }
        return OG_FALSE;
    }

    if (node->type == COND_NODE_COMPARE) {
        return og_check_cmp_cond_info(node->cmp, tbl_id, column_id);
    }

    return OG_FALSE;
}

static status_t og_check_sub_or_conds_info(cond_node_t *node, galist_t *sub_conds, uint32 tbl_id, uint16 *column_id)
{
    uint16 left_col_id = OG_INVALID_ID16;
    uint16 right_col_id = OG_INVALID_ID16;

    if (node->type == COND_NODE_OR) {
        OG_RETURN_IFERR(og_check_sub_or_conds_info(node->left, sub_conds, tbl_id, &left_col_id));
        OG_RETURN_IFERR(og_check_sub_or_conds_info(node->right, sub_conds, tbl_id, &right_col_id));
        // If cols on both sides of or_cond are not same, unsupport UNION rewrite.
        if (left_col_id == right_col_id && left_col_id != OG_INVALID_ID16) {
            *column_id = left_col_id;
            return OG_SUCCESS;
        }
        return OG_SUCCESS;
    }

    if (node->type == COND_NODE_AND || node->type == COND_NODE_COMPARE) {
        if (og_check_sub_or_cond_info_impl(node, tbl_id, column_id)) {
            return cm_galist_insert(sub_conds, node);
        }
    }

    return OG_SUCCESS;
}

static status_t og_check_index_or_conds(cond_node_t *node, or2union_info_t *o2u_info, galist_t *sub_conds,
                                        expr_node_t *col_exprn, bool32 *need_rewrite)
{
    *need_rewrite = OG_FALSE;
    if (node->type != COND_NODE_OR) {
        return OG_SUCCESS;
    }

    uint16 column_id = OG_INVALID_ID16;
    if (og_check_sub_or_conds_info(node, sub_conds, o2u_info->target_table->id, &column_id) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen2, collect sub or cond info failed");
        return OG_ERROR;
    }

    if (column_id == OG_INVALID_ID16) {
        return OG_SUCCESS;
    }

    return og_non_leading_col_in_index(o2u_info->target_table, o2u_info->index_desc, col_exprn, column_id,
                                       need_rewrite);
}

// Scenario 3: get the filter conds except or_cond
static status_t og_or2union_get_additional_conds(sql_stmt_t *statement, cond_tree_t *cond_tree, cond_node_t *cond_node,
                                                 cond_node_t **remaining_conditions)
{
    cond_node_type_t tmp_node_type = cond_node->type;
    cond_node_t *root_node = cond_tree->root;

    cond_node->type = COND_NODE_TRUE;
    OG_RETURN_IFERR(try_eval_logic_cond(statement, root_node));
    if (root_node->type != COND_NODE_TRUE) {
        OG_RETURN_IFERR(sql_clone_cond_node(statement, root_node, remaining_conditions, sql_stack_alloc));
    }

    cond_node->type = tmp_node_type;
    return sql_add_cond_node(cond_tree, cond_node);
}

static status_t og_compare_or_sub_ranges_left(const scan_border_t new_left, const scan_border_t cmp_left,
    compare_result_t *cmp_ret)
{
    if (is_border_null(new_left.type)) {
        *cmp_ret = GREATER_RES;
        return OG_SUCCESS;
    }

    if (is_border_infinite_left(cmp_left.type)) {
        *cmp_ret = GREATER_RES;
        return OG_SUCCESS;
    }

    if (is_border_null(cmp_left.type)) {
        *cmp_ret = LESS_RES;
        return OG_SUCCESS;
    }

    if (is_border_infinite_left(new_left.type)) {
        *cmp_ret = LESS_RES;
        return OG_SUCCESS;
    }

    if (var_compare_same_type(&new_left.var, &cmp_left.var, cmp_ret) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Compare or sub ranges left failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline void og_or2union_init_plan_ast(sql_query_t *sql_qry, sql_stmt_t *statement, plan_assist_t *plan_ast)
{
    sql_init_plan_assist(statement, plan_ast, sql_qry, SQL_QUERY_NODE, NULL);
    CBO_SET_FLAGS(plan_ast, CBO_CHECK_JOIN_IDX | CBO_CHECK_FILTER_IDX);
    return;
}

static status_t og_compare_or_sub_ranges_right(const scan_border_t new_right, const scan_border_t cmp_right,
    compare_result_t *cmp_ret)
{
    if (is_border_infinite_right(new_right.type)) {
        *cmp_ret = GREATER_RES;
        return OG_SUCCESS;
    }

    if (is_border_null(new_right.type)) {
        *cmp_ret = GREATER_RES;
        return OG_SUCCESS;
    }

    if (is_border_null(cmp_right.type)) {
        *cmp_ret = LESS_RES;
        return OG_SUCCESS;
    }

    if (is_border_infinite_right(cmp_right.type)) {
        *cmp_ret = LESS_RES;
        return OG_SUCCESS;
    }

    if (var_compare_same_type(&new_right.var, &cmp_right.var, cmp_ret) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Compare or sub ranges right failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

// Based on the filter conditions under the current OR node, construct the largest possible scan range.
static void og_construct_max_match_range(scan_range_list_t *match_range, scan_range_t *range)
{
    if (match_range->type == RANGE_LIST_FULL) {
        range_set_full(range);
    } else if (match_range->type == RANGE_LIST_EMPTY) {
        range->type = RANGE_EMPTY;
    } else if (match_range->count != 1) {
        // if the cond is col in (5, 10, 20) the match_range is [5, 20]
        range->type = RANGE_SECTION;
        range->left = match_range->ranges[0]->left;
        range->right = match_range->ranges[match_range->count - 1]->right;
    } else {
        *range = *match_range->ranges[0];
    }
    return;
}

static status_t og_compare_or_sub_ranges(scan_range_t *new_range, scan_range_t *cmp_range, compare_result_t *cmp_ret)
{
    if (chk_if_any_range_empty(new_range->type, cmp_range->type)) {
        *cmp_ret = (new_range->type == RANGE_EMPTY) ? GREATER_RES : LESS_RES;
        return OG_SUCCESS;
    }

    const scan_border_t new_left = new_range->left;
    const scan_border_t cmp_left = cmp_range->left;

    if (og_compare_or_sub_ranges_left(new_left, cmp_left, cmp_ret) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Compare or sub ranges left failed");
        return OG_ERROR;
    }

    OG_RETVALUE_IFTRUE(*cmp_ret != EQUAL_RES, OG_SUCCESS);

    const scan_border_t new_right = new_range->right;
    const scan_border_t cmp_right = cmp_range->right;

    if (og_compare_or_sub_ranges_right(new_right, cmp_right, cmp_ret) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Compare or sub ranges right failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

// Sort all the scan ranges under the OR condition in ASC order,
// then handle subsequent range merging and analyze the optimal UNION association method.
static status_t og_insert_match_ranges_by_order(galist_t *sub_match_ranges, uint32 *ids, scan_range_t *new_range,
                                                uint32 max_cnt)
{
    // no need sort when only one range
    uint32 range_count = sub_match_ranges->count;
    if (range_count == 1) {
        ids[0] = 0;
        return OG_SUCCESS;
    }

    uint32 left = 0;
    uint32 right = range_count - 1;
    uint32 insert_pos = 0;
    compare_result_t cmp_ret = EQUAL_RES;
    uint32 mid;
    scan_range_t *curr_range = NULL;

    // bindary search find the insert pos
    while (left < right) {
        mid = (left + right) >> 1;
        curr_range = cm_galist_get(sub_match_ranges, ids[mid]);
        if (og_compare_or_sub_ranges(new_range, curr_range, &cmp_ret) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3: sort the or_con ranges");
            return OG_ERROR;
        }
        if (cmp_ret == EQUAL_RES) {
            break;
        } else if (cmp_ret == LESS_RES) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    insert_pos = cmp_ret >= EQUAL_RES ? mid + 1 : mid;
    uint32 move_size = (range_count - insert_pos - 1) * sizeof(uint32);
    if (move_size != 0) {
        OG_RETURN_IFERR(
            memmove_s(&ids[insert_pos + 1], (max_cnt - insert_pos - 1) * sizeof(uint32), &ids[insert_pos], move_size));
    }

    ids[insert_pos] = range_count - 1;
    return OG_SUCCESS;
}

// Scenario 3: Sort and reorganize the sub_conds and sub_match_ranges,
// maintain the correspondence between sub_conds and sub_ranges.
static status_t og_sync_sort_conds_and_ranges(uint32 *ids, galist_t *sub_conds, galist_t *sub_match_ranges,
                                              sql_stmt_t *statement, or2union_info_t *or2u_info)
{
    galist_t tmp_sub_conds = { 0 };
    galist_t tmp_sub_match_ranges = { 0 };
    cm_galist_init(&tmp_sub_match_ranges, statement->session->stack, cm_stack_alloc);
    cm_galist_init(&tmp_sub_conds, statement->session->stack, cm_stack_alloc);
    OG_RETURN_IFERR(cm_galist_copy(&tmp_sub_match_ranges, sub_match_ranges));
    OG_RETURN_IFERR(cm_galist_copy(&tmp_sub_conds, sub_conds));

    scan_range_t *tmp_range = NULL;
    cond_node_t *tmp_cond = NULL;

    uint32 id = 0;
    while (id < or2u_info->or_branch_count) {
        uint32 i = ids[id];
        tmp_range = (scan_range_t *)cm_galist_get(&tmp_sub_match_ranges, i);
        tmp_cond = (cond_node_t *)cm_galist_get(&tmp_sub_conds, i);
        cm_galist_set(sub_match_ranges, id, tmp_range);
        cm_galist_set(sub_conds, id, tmp_cond);
        id++;
    }

    return OG_SUCCESS;
}

// Scenario 3: Based on the filter conditions under the current OR node, construct the largest scan range.
// Then, sort all the scan ranges in ASC order.
static status_t og_or2union_generate_match_range(galist_t *sub_conds, plan_assist_t *plan_ast,
                                                 or2union_info_t *or2u_info, galist_t *sub_match_ranges, uint32 *ids)
{
    plan_range_list_t *plan_range = NULL;
    scan_range_list_t *match_range = NULL;
    OG_RETURN_IFERR(sql_stack_alloc(plan_ast->stmt, sizeof(scan_range_list_t), (void **)&match_range));
    scan_range_t *range = NULL;

    knl_column_t *or_cond_col = NULL;
    or_cond_col = knl_get_column(or2u_info->target_table->entry->dc.handle, NODE_COL(or2u_info->target_column));
    bool32 index_reverse = or2u_info->index_desc->is_reverse;

    uint32 id = 0;
    cond_node_t *or_cond = NULL;
    // Build matching interval for each or_cond.
    while (id < sub_conds->count) {
        or_cond = (cond_node_t *)cm_galist_get(sub_conds, id++);
        uint32 list_flag = RANGE_EMPTY;
        bool32 enable_cache = OG_FALSE;
        // QC_Mark: func sql_cmp_range_usable is not ready, current is null considered as full-scan
        if (sql_create_range_list(plan_ast->stmt, plan_ast, or2u_info->target_column, or_cond_col, or_cond,
            &plan_range, index_reverse, OG_FALSE) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, create range list through or conditions");
            return OG_ERROR;
        }
        if (sql_finalize_range_list(plan_ast->stmt, plan_range, match_range, &list_flag, CALC_IN_PLAN,
            &enable_cache) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, finalize range list through or conditions");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(cm_galist_new(sub_match_ranges, sizeof(scan_range_t), (void **)&range));
        og_construct_max_match_range(match_range, range);
        OG_RETURN_IFERR(og_insert_match_ranges_by_order(sub_match_ranges, ids, range, or2u_info->or_branch_count));
    }

    return OG_SUCCESS;
}

// For right border compare, If any is null, the result is null; If any is non-border, the result is non-border.
static status_t og_merge_right_ranges(scan_border_t merge_right, scan_border_t *curr_right)
{
    if (is_any_border_infinite_right(merge_right.type, curr_right->type)) {
        curr_right->type = BORDER_INFINITE_RIGHT;
        return OG_SUCCESS;
    }

    if (is_border_any_null(merge_right.type, curr_right->type)) {
        // For example, range1 = [a, b], range2 = is null,
        // the merge range is [a, b], but the right border type is BORDER_IS_NULL
        curr_right->type = BORDER_IS_NULL;
        return OG_SUCCESS;
    }

    int32 cmp_ret = 0;
    OG_RETURN_IFERR(var_compare_same_type(&merge_right.var, &curr_right->var, &cmp_ret));

    if ((cmp_ret == EQUAL_RES && merge_right.closed) || cmp_ret == GREATER_RES) {
        *curr_right = merge_right;
    }

    return OG_SUCCESS;
}

// Scenario 3: construct the or_cond intervals and sort.
static status_t og_get_or_subcond_match_range(galist_t *sub_conds, galist_t *sub_match_ranges, plan_assist_t *plan_ast,
                                              or2union_info_t *or2u_info)
{
    uint32 *ids = NULL;
    OG_RETURN_IFERR(sql_stack_alloc(plan_ast->stmt, sizeof(uint32) * or2u_info->or_branch_count, (void **)&ids));
    if (og_or2union_generate_match_range(sub_conds, plan_ast, or2u_info, sub_match_ranges, ids) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, construct the or_cond match intervals failed");
        return OG_ERROR;
    }
    if (og_sync_sort_conds_and_ranges(ids, sub_conds, sub_match_ranges, plan_ast->stmt, or2u_info) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, Sort and reorganize the sub_conds and sub_ranges failed");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

// For left border compare, If any is non-border, the result is non-border.
// If merge_left type is null, no change. If curr_left type is null, use merge.
static status_t og_merge_left_ranges(scan_border_t merge_left, scan_border_t *curr_left)
{
    if (is_border_null(merge_left.type) || is_border_infinite_left(curr_left->type)) {
        return OG_SUCCESS;
    }

    if (is_border_null(curr_left->type) || is_border_infinite_left(merge_left.type)) {
        *curr_left = merge_left;
        return OG_SUCCESS;
    }

    int32 cmp_ret = 0;
    OG_RETURN_IFERR(var_compare_same_type(&merge_left.var, &curr_left->var, &cmp_ret));
    if ((cmp_ret == EQUAL_RES && merge_left.closed) || cmp_ret == LESS_RES) {
        *curr_left = merge_left;
    }

    return OG_SUCCESS;
}

static status_t og_merge_match_ranges(scan_range_t *merge_range, scan_range_t *curr_range)
{
    if (curr_range->type == RANGE_EMPTY || merge_range->type == RANGE_FULL) {
        *curr_range = *merge_range;
        return OG_SUCCESS;
    }

    if (merge_range->type == RANGE_EMPTY || curr_range->type == RANGE_FULL) {
        return OG_SUCCESS;
    }

    // Handle two equal point ranges
    int32 cmp_ret = 0;
    if (is_both_range_point(merge_range->type, curr_range->type)) {
        if (var_compare_same_type(&merge_range->left.var, &curr_range->left.var, &cmp_ret) != OG_SUCCESS) {
            return OG_ERROR;
        }
        OG_RETVALUE_IFTRUE(cmp_ret == EQUAL_RES, OG_SUCCESS);
    }

    // Merge the scan range
    curr_range->type = RANGE_SECTION;
    if (og_merge_left_ranges(merge_range->left, &curr_range->left) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] merge left sub ranges failed");
        return OG_ERROR;
    }

    if (og_merge_right_ranges(merge_range->right, &curr_range->right) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] merge right sub ranges failed");
        return OG_ERROR;
    }

    // Check if the merged range is full scan
    if (is_border_infinite_left(curr_range->left.type) && is_border_infinite_right(curr_range->right.type)) {
        curr_range->type = RANGE_FULL;
    }

    return OG_SUCCESS;
}

static status_t og_build_const_val_expr_node(sql_stmt_t *statement, cond_node_t **cond, expr_node_t *val_exprn,
                                             scan_border_t border)
{
    if (sql_stack_alloc(statement, sizeof(expr_tree_t), (void **)&(*cond)->cmp->right) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_stack_alloc(statement, sizeof(expr_node_t), (void **)&(*cond)->cmp->right->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    val_exprn = (*cond)->cmp->right->root;
    var_copy(&border.var, &val_exprn->value);
    val_exprn->datatype = border.var.type;
    val_exprn->owner = (*cond)->cmp->right;
    val_exprn->type = EXPR_NODE_CONST;
    (*cond)->cmp->right->next = NULL;
    return OG_SUCCESS;
}

static status_t og_build_col_expr_node(sql_stmt_t *statement, expr_node_t *column, cond_node_t **cond,
                                       expr_node_t *col_expr)
{
    if (sql_stack_alloc(statement, sizeof(expr_tree_t), (void **)&(*cond)->cmp->left) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_stack_alloc(statement, sizeof(expr_node_t), (void **)&(*cond)->cmp->left->root) != OG_SUCCESS) {
        return OG_ERROR;
    }
    col_expr = (*cond)->cmp->left->root;
    col_expr->owner = (*cond)->cmp->left;
    col_expr->value.v_col.is_array = 0;
    og_construct_expr_col_node(col_expr, column->datatype, NODE_TAB(column), NODE_COL(column));
    (*cond)->cmp->left->next = NULL;
    return OG_SUCCESS;
}

static status_t og_get_range_cmp_type(sql_stmt_t *statement, expr_node_t *column, scan_border_t border,
                                      cond_node_t **cond, cmp_type_t cmp_type)
{
    if (cond == NULL || (*cond) == NULL) {
        return OG_SUCCESS;
    }

    expr_node_t *col_expr = NULL;
    expr_node_t *val_expr = NULL;

    (*cond)->type = COND_NODE_COMPARE;
    OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(cmp_node_t), (void **)&(*cond)->cmp));
    // Create column expr node
    if (og_build_col_expr_node(statement, column, cond, col_expr) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, Create column expr node failed");
        return OG_ERROR;
    }

    if (is_cmp_type_has_null(cmp_type)) {
        (*cond)->cmp->type = cmp_type;
        OG_LOG_DEBUG_INF(
            "[OR2UNION] The compare type is set as %s", cmp_type == CMP_TYPE_IS_NULL ? "TYPE_NULL" : "TYPE_NOT_NULL");
        (*cond)->cmp->right = NULL;
        return OG_SUCCESS;
    }

    // If the scan_range is [1, 10], the right border has const val,
    // but the right_border_type is BORDER_IS_NULL,
    // the cmp_type is CMP_TYPE_IS_NULL, the right const val is null
    if (is_border_null(border.type)) {
        (*cond)->cmp->type = CMP_TYPE_IS_NULL;
        OG_LOG_DEBUG_INF("[OR2UNION] The compare type is set as CMP_TYPE_IS_NULL");
        (*cond)->cmp->right = NULL;
        return OG_SUCCESS;
    }

    // Create const value expr node
    if (og_build_const_val_expr_node(statement, cond, val_expr, border) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, Create const value expr node failed");
        return OG_ERROR;
    }

    (*cond)->cmp->type = cmp_type;
    return OG_SUCCESS;
}

static status_t og_handle_both_side_border(sql_stmt_t *statement, expr_node_t *column, scan_range_t scan_range,
                                           cond_node_t **range_cond)
{
    cmp_type_t cmp_type;
    // For example: the filter cond is col in (a, b, c), the scan range cond is [a, c]
    // the range_cond left is col >= a, cond_not_type is AND, the range_cond right is col <= c
    (*range_cond)->type = COND_NODE_AND;

    // Create left border
    OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(cond_node_t), (void **)&(*range_cond)->left));
    cmp_type = scan_range.left.closed ? CMP_TYPE_GREAT_EQUAL : CMP_TYPE_GREAT;
    if (og_get_range_cmp_type(statement, column, scan_range.left, &(*range_cond)->left, cmp_type) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Create left border failed!");
        return OG_ERROR;
    }

    // Create right border
    OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(cond_node_t), (void **)&(*range_cond)->right));
    cmp_type = scan_range.right.closed ? CMP_TYPE_LESS_EQUAL : CMP_TYPE_LESS;
    if (og_get_range_cmp_type(statement, column, scan_range.right, &(*range_cond)->right, cmp_type) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Create right border failed!");
        return OG_ERROR;
    }

    // If the create range cond is [val, is null] --> col >= val OR col is null
    // If the create range cond is [is null, val] --> col <= val OR col is null
    // For example, the scan_range is [1, 3], but the right border is null,
    // the range_cond is col >= 1 OR col is null
    if (is_cmp_type_has_is_null((*range_cond)->left->cmp->type, (*range_cond)->right->cmp->type)) {
        (*range_cond)->type = COND_NODE_OR;
    }
    return OG_SUCCESS;
}

static status_t og_get_range_cond_section(sql_stmt_t *statement, expr_node_t *column, scan_range_t scan_range,
                                          cond_node_t **range_cond)
{
    cmp_type_t cmp_type;
    // Left boundary not exist, process right
    if (is_border_infinite_left(scan_range.left.type)) {
        cmp_type = scan_range.right.closed ? CMP_TYPE_LESS_EQUAL : CMP_TYPE_LESS;
        return og_get_range_cmp_type(statement, column, scan_range.right, range_cond, cmp_type);
    }

    // Right boundary not exist, process left
    if (is_border_infinite_right(scan_range.right.type)) {
        cmp_type = scan_range.left.closed ? CMP_TYPE_GREAT_EQUAL : CMP_TYPE_GREAT;
        return og_get_range_cmp_type(statement, column, scan_range.left, range_cond, cmp_type);
    }

    // The scan range is only NULL value
    if (is_border_both_null(scan_range.left.type, scan_range.right.type)) {
        return og_get_range_cmp_type(statement, column, scan_range.left, range_cond, CMP_TYPE_IS_NULL);
    }

    return og_handle_both_side_border(statement, column, scan_range, range_cond);
}

static status_t og_build_scan_range_conds(sql_stmt_t *statement, expr_node_t *column, scan_range_t scan_range,
                                          cond_node_t **range_cond)
{
    OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(cond_node_t), (void **)range_cond));
    if (scan_range.type == RANGE_EMPTY) {
        (*range_cond)->type = COND_NODE_FALSE;
        return OG_SUCCESS;
    }

    if (scan_range.type == RANGE_FULL) {  // indicating is not null
        return og_get_range_cmp_type(statement, column, scan_range.left, range_cond, CMP_TYPE_IS_NOT_NULL);
    }

    if (scan_range.type == RANGE_POINT) {
        return og_get_range_cmp_type(statement, column, scan_range.left, range_cond, CMP_TYPE_EQUAL);
    }

    if (is_border_null(scan_range.right.type) && is_border_infinite_left(scan_range.left.type)) {
        (*range_cond)->type = COND_NODE_TRUE;
        return OG_SUCCESS;
    }

    return og_get_range_cond_section(statement, column, scan_range, range_cond);
}

static status_t og_handle_remaining_conds(or2union_info_t *or2u_info, sql_stmt_t *statement, cond_tree_t *temp_tree,
                                          cond_node_t *range_cond)
{
    if (or2u_info->remaining_conditions == NULL) {
        temp_tree->root = range_cond;
        return OG_SUCCESS;
    }

    // The left is remain conds, the right is the processed or_conds, the cond_node type is and
    // For example, select * from t1 where c1 > 5 and (c2 in (1,2,3) and c2 > 10000),
    // if we calculate the max_or_cond_scan_range: c1 is (5, ∞] and c2 is [1, 10000]
    // if we calculate the union_cond_scan_range: (1) c1 is (5, ∞] and c2 = 1 (2) c1 is (5, ∞] and c2 = 10000
    OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(cond_tree_t), (void **)&temp_tree->root));
    temp_tree->root->type = COND_NODE_AND;
    temp_tree->root->left = or2u_info->remaining_conditions;
    temp_tree->root->right = range_cond;
    return OG_SUCCESS;
}

// Calculate the cost of the given scan range.
static status_t og_calc_cost_by_cond_ranges(or2union_info_t *or2u_info, plan_assist_t *plan_ast,
                                            scan_range_t scan_range, double *cost)
{
    cond_node_t *range_cond = NULL;
    cond_tree_t temp_tree = { 0 };
    sql_stmt_t *statement = plan_ast->stmt;
    OGSQL_SAVE_STACK(statement);

    if (og_build_scan_range_conds(statement, or2u_info->target_column, scan_range, &range_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, before cal cost, construct range cond failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }
    if (og_handle_remaining_conds(or2u_info, statement, &temp_tree, range_cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, before cal cost, handle remaining conds failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }
    try_eval_logic_and(temp_tree.root);

    if (temp_tree.root->type == COND_NODE_FALSE) {
        *cost = CBO_MIN_COST;
        OGSQL_RESTORE_STACK(statement);
        return OG_SUCCESS;
    }

    plan_ast->cond = &temp_tree;

    dc_entity_t *entity = DC_ENTITY(&or2u_info->target_table->entry->dc);
    if (or2u_info->index_desc->id >= entity->table.desc.index_count) {
        OG_THROW_ERROR(ERR_INVALID_NUMBER, "index id is invalid");
        return OG_ERROR;
    }
    index_t *index = DC_TABLE_INDEX(&entity->table, or2u_info->index_desc->id);

    or2u_info->target_table->cost = CBO_MAX_COST;
    or2u_info->target_table->index = NULL;
    cbo_try_choose_index(statement, plan_ast, or2u_info->target_table, index);
    OGSQL_RESTORE_STACK(statement);
    *cost = or2u_info->target_table->cost;
    return OG_SUCCESS;
}

static status_t og_calc_cost_with_or_cond_ranges(or2union_info_t *or2u_info, plan_assist_t *plan_ast,
                                                 galist_t *sub_match_ranges)
{
    double or_cond_cost = CBO_MIN_COST;
    scan_range_t *range = NULL;
    // or_cond_range indicate the max range need to scan in filter of or_cond
    scan_range_t or_cond_range;
    or_cond_range = *(scan_range_t *)cm_galist_get(sub_match_ranges, 0);

    // Merge all scan ranges under OR conditions
    uint32 start = 1;
    while (start < sub_match_ranges->count) {
        range = (scan_range_t *)cm_galist_get(sub_match_ranges, start++);
        if (og_merge_match_ranges(range, &or_cond_range) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, merge the sub ranges for max or scan range failed");
            return OG_ERROR;
        }
    }

    if (og_calc_cost_by_cond_ranges(or2u_info, plan_ast, or_cond_range, &or_cond_cost) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, calculate the cost of or filter conditions failed");
        return OG_ERROR;
    }

    or2u_info->optimal_cost = or_cond_cost;
    return OG_SUCCESS;
}

static bool32 og_or2union_check_hint_valid(or2union_info_t *or2u_info)
{
    hint_info_t *hint_info = or2u_info->target_table->hint_info;
    if (!HAS_SPEC_TYPE_HINT(hint_info, OPTIM_HINT, HINT_KEY_WORD_OR_EXPAND)) {
        return OG_FALSE;
    }

    galist_t *hint = (galist_t *)(hint_info->args[HINT_ID_OR_EXPAND]);
    // Check the hint is validate
    if (hint == NULL || or2u_info->or_branch_count != hint->count) {
        hint_or2u_key_clear(hint_info);
        return OG_FALSE;
    }

    uint32 id = 0;
    while (id < or2u_info->or_branch_count) {
        uint32 set_id = *(uint32 *)cm_galist_get(hint, id++);
        if (set_id >= hint->count) {
            hint_or2u_key_clear(hint_info);
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static status_t og_or2union_apply_hint(sql_stmt_t *statement, or2union_info_t *or2u_info, uint32 **sets,
                                       bool32 *need_rewrite)
{
    galist_t *hint_list = (galist_t *)(or2u_info->target_table->hint_info->args[HINT_ID_OR_EXPAND]);
    if (or2u_info->or_branch_count == 0 || *(uint32 *)cm_galist_get(hint_list, or2u_info->or_branch_count - 1) == 0) {
        *need_rewrite = OG_FALSE;
        hint_or2u_key_clear(or2u_info->target_table->hint_info);
        hint_no_or2u_set_key(or2u_info->target_table->hint_info);
        return OG_SUCCESS;
    }

    *need_rewrite = OG_TRUE;
    OG_RETURN_IFERR(
        cm_stack_alloc(statement->session->stack, sizeof(uint32) * or2u_info->or_branch_count, (void **)sets));
    uint32 i = 0;
    while (i < or2u_info->or_branch_count) {
        sets[0][i] = *(uint32 *)cm_galist_get(hint_list, i);
        i++;
    }

    hint_or2u_key_clear(or2u_info->target_table->hint_info);
    hint_no_or2u_set_key(or2u_info->target_table->hint_info);
    return OG_SUCCESS;
}

// Optimize the cost calculation of range queries through caching.
static status_t og_calc_union_range_cost(plan_assist_t *plan_ast, or2union_info_t *or2u_info, scan_range_t merge_range,
                                         uint32 end_pos, double *curr_cost)
{
    // For different range combinations, calculate the corresponding cache positions.
    uint32 pos = or2u_info->start_id;
    uint32 i = 0;

    if (end_pos < or2u_info->start_id) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, get cost from cache failed, end_pos = %u, start_id = %u", end_pos,
                       or2u_info->start_id);
        return OG_ERROR;
    }

    /*
    * range_list = {[a], [b], [c], [d]} count = 4, the range_pos are
    * [a] --> 0; [b] --> 1; [c] --> 2; [d] --> 3;
    * {[a], [b]} --> (0 + count); {[b], [c]} --> (1 + count); {[c], [d]} --> (2 + count);
    * {[a], [b], [c]} --> (0 + count + (count - 1)); {[b], [c], [d]} --> (1 + count + (count - 1))
    */

    while (i < (end_pos - or2u_info->start_id)) {
        pos += (or2u_info->or_branch_count - i);
        i++;
    }

    if (cm_compare_double(or2u_info->cost_cache[pos], CBO_MIN_COST) != EQUAL_RES) {
        *curr_cost = or2u_info->cost_cache[pos];
        return OG_SUCCESS;
    }

    if (og_calc_cost_by_cond_ranges(or2u_info, plan_ast, merge_range, curr_cost) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, calculate the cost for union plan failed, iteration = %u",
                       or2u_info->iteration_count);
        return OG_ERROR;
    }

    *curr_cost = CBO_COST_SAFETY_RET(*curr_cost + or2u_info->additional_cost);
    or2u_info->cost_cache[pos] = *curr_cost;
    return OG_SUCCESS;
}

static inline void og_set_or2union_info(const or2union_info_t *or2u_info, or2union_info_t *info)
{
    info->current_cost = or2u_info->current_cost;
    info->set_id = or2u_info->set_id;
    info->start_id = or2u_info->start_id;
    return;
}

static status_t og_handle_union_iteration(or2union_info_t *or2u_info, bool32 *is_end_iter)
{
    if (or2u_info->start_id < or2u_info->or_branch_count) {
        return OG_SUCCESS;
    }

    *is_end_iter = OG_TRUE;
    or2u_info->optimal_cost = or2u_info->current_cost;
    or2u_info->is_merge_or_cond = !(or2u_info->set_id == or2u_info->or_branch_count);
    MEMS_RETURN_IFERR(memcpy_s(or2u_info->optimal_set, sizeof(uint32) * or2u_info->or_branch_count, or2u_info->sets,
                               sizeof(uint32) * or2u_info->or_branch_count));
    return OG_SUCCESS;
}

// Process sub-ranges, merge sub-ranges, Then calculate the current scan_range cost,
// and determine whether stop further exploration based on the current_cost and or_scan_cost * 0.5.
static status_t og_process_sub_union_scan_cost(bool32 *early_stop, plan_assist_t *plan_ast, galist_t *sub_match_ranges,
                                               or2union_info_t *or2u_info, uint32 id)
{
    scan_range_t merge_range;
    if (id == or2u_info->start_id) {
        merge_range = *(scan_range_t *)cm_galist_get(sub_match_ranges, id);
    } else {
        scan_range_t *sub_range = (scan_range_t *)cm_galist_get(sub_match_ranges, id);
        if (og_merge_match_ranges(sub_range, &merge_range) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, merge sub or_cond ranges for union plan filed, iteration = %u",
                           or2u_info->iteration_count);
        }
    }

    // Try different split combinations of sub_or_cond, find the lowest-cost UNION solution.
    // Try merging adjacent filter ranges to reduce the number of subqueries,
    // thereby reducing the cost of querying and merging result sets.
    // for example, range_cond is {D} AND {{A} OR {B} OR {C}},
    // the union solutions are (1): {{D} AND {A}} UNION {{D} AND {B}} UNION {{D} AND {C}}},
    // (2): {{D AND {A, B}} UNION {{D} AND {C}}}, (3): {{{D} AND {A}} UNION {{D} AND {B, C}}
    double cost = CBO_MIN_COST;
    if (og_calc_union_range_cost(plan_ast, or2u_info, merge_range, id, &cost) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, calculate the cost of union plan filed, iteration = %u",
                       or2u_info->iteration_count);
        return OG_ERROR;
    }
    or2u_info->current_cost = CBO_COST_SAFETY_RET(or2u_info->current_cost + cost);

    // The curr cost has exceeded cost of OR condition. Stop further exploration.
    if (or2u_info->current_cost >= or2u_info->optimal_cost) {
        *early_stop = OG_TRUE;
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t og_calc_optim_union_scan_cost(plan_assist_t *plan_ast, or2union_info_t *or2u_info,
                                              galist_t *sub_match_ranges)
{
    or2union_info_t snapshot;
    bool32 is_end_iter = OG_FALSE;
    OG_RETURN_IFERR(og_handle_union_iteration(or2u_info, &is_end_iter));
    OG_RETVALUE_IFTRUE(is_end_iter, OG_SUCCESS);
    // Save the current state for backtracking
    og_set_or2union_info(or2u_info, &snapshot);

    for (uint32 i = or2u_info->start_id; i < or2u_info->or_branch_count; i++) {
        bool32 early_stop = OG_FALSE;
        // Process the curr sub range, calculate its cost and judge if early stop
        if (og_process_sub_union_scan_cost(&early_stop, plan_ast, sub_match_ranges, or2u_info, i) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, process sub or_cond ranges failed when cal cost");
            return OG_ERROR;
        }
        OG_RETVALUE_IFTRUE(early_stop, OG_SUCCESS);
        // Recursively explore subsequent scan ranges
        or2u_info->sets[i] = or2u_info->set_id++;
        or2u_info->start_id = i + 1;
        OG_RETURN_IFERR(og_calc_optim_union_scan_cost(plan_ast, or2u_info, sub_match_ranges));
        OG_RETVALUE_IFTRUE(i == or2u_info->or_branch_count - 1, OG_SUCCESS);
        // Restore the auxiliary information of the previous state
        og_set_or2union_info(&snapshot, or2u_info);
        or2u_info->iteration_count++;
    }

    return OG_SUCCESS;
}

// Scenario 3 : compare cost of or_cond scan and union_cond scan
static status_t og_calc_optim_union_plan(or2union_info_t *or2u_info, plan_assist_t *plan_ast,
                                         galist_t *sub_match_ranges, bool32 *need_rewrite, uint32 **sets)
{
    double or_scan_cost = CBO_MIN_COST;
    double union_scan_cost = CBO_MIN_COST;

    if (og_or2union_check_hint_valid(or2u_info)) {
        if (og_or2union_apply_hint(plan_ast->stmt, or2u_info, sets, need_rewrite) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, Check for Scen3, apply or expand hint failed");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    // Calculate the max scan range and the cost with or_cond and addition_cond
    if (og_calc_cost_with_or_cond_ranges(or2u_info, plan_ast, sub_match_ranges) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, when merge sub ranges of or_cond and cal cost failed");
        return OG_ERROR;
    }
    or_scan_cost = or2u_info->optimal_cost;

    // Start iteration, calculate the scan range and the cost with union_cond, find the best union plan
    if (og_calc_optim_union_scan_cost(plan_ast, or2u_info, sub_match_ranges) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, merge sub ranges of union_cond and cal cost failed");
        return OG_ERROR;
    }
    union_scan_cost = or2u_info->optimal_cost;

    if (union_scan_cost >= or_scan_cost) {
        *need_rewrite = OG_FALSE;
        OG_LOG_DEBUG_INF(
            "[OR2UNION] Check for Scen3, the union cost > or cost, no rewrite, union_cost = %f, or_cost = %f",
            union_scan_cost, or_scan_cost);
        return OG_SUCCESS;
    }

    *need_rewrite = OG_TRUE;
    if (or2u_info->is_merge_or_cond) {
        OG_RETURN_IFERR(
            cm_stack_alloc(plan_ast->stmt->session->stack, sizeof(uint32) * or2u_info->or_branch_count, (void **)sets));
        MEMS_RETURN_IFERR(memcpy_s(*sets, sizeof(uint32) * or2u_info->or_branch_count, or2u_info->optimal_set,
                                   sizeof(uint32) * or2u_info->or_branch_count));
    }

    return OG_SUCCESS;
}

static status_t og_or2union_check_index_scan_cost(sql_query_t *sql_qry, sql_stmt_t *statement, galist_t *opt_conds,
                                                  uint32 **sets, bool32 *need_rewrite)
{
    or2union_info_t or2u_info;
    plan_assist_t plan_ast;
    if (og_check_driver_tbl_index(sql_qry, statement, &or2u_info, need_rewrite) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, check the index used failed");
        return OG_ERROR;
    }
    OG_RETVALUE_IFTRUE(!(*need_rewrite), OG_SUCCESS);

    galist_t sub_conds;
    expr_node_t col_exprn = { 0 };
    cm_galist_init(&sub_conds, statement->session->stack, cm_stack_alloc);
    reorganize_cond_tree(sql_qry->cond->root);
    // Collect all or_cond from the query conds.
    cond_node_t *cond_node = FIRST_NOT_AND_NODE(sql_qry->cond->root);
    for (; cond_node != NULL; cond_node = cond_node->next) {
        OG_RETURN_IFERR(og_check_index_or_conds(cond_node, &or2u_info, &sub_conds, &col_exprn, need_rewrite));
        OG_BREAK_IF_TRUE(*need_rewrite);
        cm_galist_reset(&sub_conds);
    }

    if (sub_conds.count > OR_EXPAND_MAX_CONDS || sub_conds.count == 0) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen3, the or_cond cnt is %u, no rewrite", sub_conds.count);
        *need_rewrite = OG_FALSE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(og_init_or2union_info(&or2u_info, statement, &col_exprn, sub_conds.count));
    if (og_or2union_get_additional_conds(statement, sql_qry->cond, cond_node, &or2u_info.remaining_conditions) !=
        OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, get the conditions excepted or conds faild");
        return OG_ERROR;
    }

    og_or2union_init_plan_ast(sql_qry, statement, &plan_ast);
    galist_t sub_match_ranges = { 0 };
    cm_galist_init(&sub_match_ranges, statement->session->stack, cm_stack_alloc);
    if (og_get_or_subcond_match_range(&sub_conds, &sub_match_ranges, &plan_ast, &or2u_info) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, generate or conditions failed");
        return OG_ERROR;
    }
    *opt_conds = sub_conds;

    // Compare the cost of or_plan and union_plan
    return og_calc_optim_union_plan(&or2u_info, &plan_ast, &sub_match_ranges, need_rewrite, sets);
}

// Check for Scenario 3
static status_t og_query_index_rewrite_union(sql_query_t *sql_qry, sql_stmt_t *statement, bool32 *need_rewrite)
{
    // There must be no sub_select in Scenario 3
    if (sql_qry->ssa.count != 0 || sql_qry->has_no_or_expand) {
        OG_LOG_DEBUG_INF("[OR2UNION] Check for Scen3, the sub_select is %u, no rewrite", sql_qry->ssa.count);
        return OG_SUCCESS;
    }

    galist_t or_conds;
    uint32 *sets = NULL;
    cm_galist_init(&or_conds, statement->session->stack, cm_stack_alloc);
    if (og_or2union_check_index_scan_cost(sql_qry, statement, &or_conds, &sets, need_rewrite) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3, check if rewrite is needed failed");
        return OG_ERROR;
    }

    OG_RETVALUE_IFTRUE(!(*need_rewrite), OG_SUCCESS);

    return og_rewrite_or_query2union(sql_qry, statement, &or_conds, sets);
}

status_t og_transf_or2union_rewrite(sql_stmt_t *statement, sql_query_t *sql_qry)
{
    if (statement == NULL || sql_qry == NULL) {
        return OG_SUCCESS;
    }
    bool32 need_rewrite = OG_FALSE;
    if (og_or2union_can_not_apply(statement, sql_qry)) {
        OG_LOG_DEBUG_INF("[OR2UNION] this optim can not apply.");
        return OG_SUCCESS;
    }
    OGSQL_SAVE_STACK(statement);
    galist_t opt_or_conds = { 0 };
    cm_galist_init(&opt_or_conds, statement->session->stack, cm_stack_alloc);
    if (og_check_cond_rewrite_hash(sql_qry, statement, &opt_or_conds, &need_rewrite) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen1-2 failed");
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }
    if (need_rewrite) {
        if (og_rewrite_or_query2union(sql_qry, statement, &opt_or_conds, NULL) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[OR2UNION] Rewrite for Scen1-2 failed");
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }
        OGSQL_RESTORE_STACK(statement);
        return OG_SUCCESS;
    }
    if (!CBO_ON) {
        OGSQL_RESTORE_STACK(statement);
        return OG_SUCCESS;
    }
    if (og_query_index_rewrite_union(sql_qry, statement, &need_rewrite) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        OG_LOG_RUN_ERR("[OR2UNION] Check for Scen3 failed");
        return OG_ERROR;
    }
    if (!need_rewrite && !sql_qry->block_info->has_no_or2union_flag) {
        OGSQL_RESTORE_STACK(statement);
        return OG_SUCCESS;
    }
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}