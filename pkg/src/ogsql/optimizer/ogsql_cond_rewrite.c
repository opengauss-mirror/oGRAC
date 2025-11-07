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
 * ogsql_cond_rewrite.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_cond_rewrite.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_table_func.h"
#include "ogsql_func.h"
#include "ogsql_cond_rewrite.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "plan_rbo.h"
#include "plan_range.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline status_t replace_group_node(visit_assist_t *visit_ass, expr_node_t **node)
{
    if ((*node)->type != EXPR_NODE_GROUP || NODE_VM_ANCESTOR(*node) > 0) {
        return OG_SUCCESS;
    }

    expr_node_t *origin_ref = sql_get_origin_ref(*node);
    OG_RETURN_IFERR(sql_clone_expr_node(visit_ass->stmt->context, origin_ref, node, sql_alloc_mem));
    return visit_expr_node(visit_ass, node, replace_group_node);
}

status_t replace_group_expr_node(sql_stmt_t *stmt, expr_node_t **node)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    return visit_expr_node(&visit_ass, node, replace_group_node);
}

static inline bool32 sql_cols_is_same_tab(uint32 tab, cols_used_t *cols_used)
{
    if (cols_used->flags == 0) {
        return OG_TRUE;
    }

    if ((cols_used->flags & (FLAG_HAS_PARENT_COLS | FLAG_HAS_ANCESTOR_COLS)) != 0) {
        return OG_FALSE;
    }

    if ((cols_used->level_flags[SELF_IDX] & LEVEL_HAS_DIFF_TABS) != 0) {
        return OG_FALSE;
    }

    expr_node_t *first_node = OBJECT_OF(expr_node_t, biqueue_first(&cols_used->cols_que[SELF_IDX]));
    return (tab == TAB_OF_NODE(first_node));
}

static status_t sql_try_simplify_cond(sql_stmt_t *stmt, cond_node_t *cond, uint32 *rnum_upper, bool8 *rnum_pending)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    switch (cond->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_try_simplify_cond(stmt, cond->left, rnum_upper, rnum_pending));
            OG_RETURN_IFERR(sql_try_simplify_cond(stmt, cond->right, rnum_upper, rnum_pending));
            try_eval_logic_and(cond);
            return OG_SUCCESS;
        case COND_NODE_OR:
            OG_RETURN_IFERR(sql_try_simplify_cond(stmt, cond->left, rnum_upper, rnum_pending));
            OG_RETURN_IFERR(sql_try_simplify_cond(stmt, cond->right, rnum_upper, rnum_pending));
            try_eval_logic_or(cond);
            return OG_SUCCESS;
        case COND_NODE_COMPARE:
            return try_eval_compare_node(stmt, cond, rnum_upper, rnum_pending);
        default:
            return OG_SUCCESS;
    }
}

status_t sql_try_simplify_new_cond(sql_stmt_t *stmt, cond_node_t *cond)
{
    if (IS_COORDINATOR || stmt->context->has_dblink) {
        return OG_SUCCESS;
    }
    uint32 rnum_upper = OG_INVALID_ID32;
    bool8 rnum_pending = OG_FALSE;
    return sql_try_simplify_cond(stmt, cond, &rnum_upper, &rnum_pending);
}

static status_t update_select_node_object(visit_assist_t *visit_ass, expr_node_t **node)
{
    if ((*node)->type != EXPR_NODE_SELECT) {
        return OG_SUCCESS;
    }
    sql_select_t *select = (sql_select_t *)VALUE_PTR(var_object_t, &(*node)->value)->ptr;
    sql_select_t *ssa = NULL;
    for (uint32 i = 0; i < visit_ass->query->ssa.count; i++) {
        ssa = (sql_select_t *)sql_array_get(&visit_ass->query->ssa, i);
        if (ssa == select) {
            (*node)->value.v_obj.id = i;
            break;
        }
    }
    return OG_SUCCESS;
}

status_t sql_update_query_ssa(sql_query_t *query)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, NULL, query);
    if (query->cond != NULL) {
        OG_RETURN_IFERR(visit_cond_node(&visit_ass, query->cond->root, update_select_node_object));
    }
    if (query->having_cond != NULL) {
        OG_RETURN_IFERR(visit_cond_node(&visit_ass, query->having_cond->root, update_select_node_object));
    }
    if (query->start_with_cond != NULL) {
        OG_RETURN_IFERR(visit_cond_node(&visit_ass, query->start_with_cond->root, update_select_node_object));
    }
    if (query->connect_by_cond != NULL) {
        OG_RETURN_IFERR(visit_cond_node(&visit_ass, query->connect_by_cond->root, update_select_node_object));
    }
    if (query->filter_cond != NULL) {
        OG_RETURN_IFERR(visit_cond_node(&visit_ass, query->filter_cond->root, update_select_node_object));
    }
    if (query->join_assist.join_node != NULL) {
        OG_RETURN_IFERR(visit_join_node_cond(&visit_ass, query->join_assist.join_node, update_select_node_object));
    }
    for (uint32 i = 0; i < query->sort_items->count; i++) {
        sort_item_t *sort_item = (sort_item_t *)cm_galist_get(query->sort_items, i);
        OG_RETURN_IFERR(visit_expr_tree(&visit_ass, sort_item->expr, update_select_node_object));
    }
    for (uint32 i = 0; i < query->aggrs->count; i++) {
        expr_node_t *node = (expr_node_t *)cm_galist_get(query->aggrs, i);
        OG_RETURN_IFERR(visit_expr_node(&visit_ass, &node, update_select_node_object));
    }
    return OG_SUCCESS;
}

static inline uint32 sql_get_func_table_column_count(sql_stmt_t *stmt, sql_table_t *table)
{
    plv_collection_t *plv_coll = NULL;
    if (cm_text_str_equal(&table->func.name, "CAST")) {
        plv_coll = (plv_collection_t *)table->func.args->next->root->udt_type;
        return plv_coll->attr_type == UDT_OBJECT ? UDT_GET_TYPE_DEF_OBJECT(plv_coll->elmt_type)->count :
                                                     table->func.desc->column_count;
    } else {
        return table->func.desc->column_count;
    }
}

static uint32 sql_get_table_column_count(sql_stmt_t *stmt, sql_table_t *table)
{
    switch (table->type) {
        case VIEW_AS_TABLE:
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
            return table->select_ctx->first_query->rs_columns->count;
        case FUNC_AS_TABLE:
            return sql_get_func_table_column_count(stmt, table);
        case JSON_TABLE:
            return table->json_table_info->columns.count;
        default:
            return knl_get_column_count(table->entry->dc.handle);
    }
}
/* *******************predicate deliver************************ */
static inline status_t sql_init_dlvr_pair(sql_stmt_t *stmt, sql_query_t *query, dlvr_pair_t **dlvr_pair,
                                          galist_t *pairs)
{
    uint32 mem_size;
    sql_table_t *table = NULL;

    OG_RETURN_IFERR(cm_galist_new(pairs, sizeof(dlvr_pair_t), (void **)dlvr_pair));
    cm_galist_init(&(*dlvr_pair)->cols, stmt->session->stack, cm_stack_alloc);
    cm_galist_init(&(*dlvr_pair)->values, stmt->session->stack, cm_stack_alloc);

    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        mem_size = sql_get_table_column_count(stmt, table) * sizeof(uint32);
        OG_RETURN_IFERR(cm_stack_alloc(stmt->session->stack, mem_size, (void **)&(*dlvr_pair)->col_map[i]));
        MEMS_RETURN_IFERR(memset_s((*dlvr_pair)->col_map[i], mem_size, 0, mem_size));
    }
    return OG_SUCCESS;
}

static inline bool32 if_dlvr_border_equal(sql_stmt_t *stmt, plan_border_t *border1, plan_border_t *border2)
{
    if (border1->type != border2->type || border1->closed != border2->closed) {
        return OG_FALSE;
    }
    return sql_expr_tree_equal(stmt, border1->expr, border2->expr, NULL);
}

static bool32 if_dlvr_range_equal(sql_stmt_t *stmt, plan_range_t *range1, plan_range_t *range2)
{
    if (range1->type != range2->type) {
        return OG_FALSE;
    }

    switch (range1->type) {
        case RANGE_LIST:
        case RANGE_POINT:
        case RANGE_LIKE:
            // left border is the same as the right, so we just need to compare the left border
            return if_dlvr_border_equal(stmt, &range1->left, &range2->left);
        case RANGE_SECTION:
            if (!if_dlvr_border_equal(stmt, &range1->left, &range2->left)) {
                return OG_FALSE;
            }
            return if_dlvr_border_equal(stmt, &range1->right, &range2->right);
        default:
            break;
    }
    return OG_FALSE;
}

static inline bool32 sql_dlvr_pair_exists_col(expr_tree_t *col, dlvr_pair_t *dlvr_pair)
{
    return dlvr_pair->col_map[EXPR_TAB(col)][EXPR_COL(col)];
}

static inline status_t sql_dlvr_pair_add_col(expr_tree_t *column, dlvr_pair_t *dlvr_pair)
{
    uint16 tab = EXPR_TAB(column);
    uint16 col = EXPR_COL(column);
    if (dlvr_pair->col_map[tab][col]) {
        return OG_SUCCESS;
    }
    dlvr_pair->col_map[tab][col] = OG_TRUE;
    return cm_galist_insert(&dlvr_pair->cols, column);
}

static status_t sql_dlvr_pair_try_add_ff(expr_tree_t *left, expr_tree_t *right, dlvr_pair_t *dlvr_pair, bool32
    *is_found)
{
    if (sql_dlvr_pair_exists_col(left, dlvr_pair)) {
        *is_found = OG_TRUE;
        return sql_dlvr_pair_add_col(right, dlvr_pair);
    }

    if (sql_dlvr_pair_exists_col(right, dlvr_pair)) {
        *is_found = OG_TRUE;
        return sql_dlvr_pair_add_col(left, dlvr_pair);
    }
    return OG_SUCCESS;
}

static status_t sql_dlvr_pairs_add_ff_pair(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *left, expr_tree_t *right,
    galist_t *pairs)
{
    dlvr_pair_t *dlvr_pair = NULL;
    OG_RETURN_IFERR(sql_init_dlvr_pair(stmt, query, &dlvr_pair, pairs));
    OG_RETURN_IFERR(sql_dlvr_pair_add_col(left, dlvr_pair));
    return sql_dlvr_pair_add_col(right, dlvr_pair);
}

bool32 get_specified_level_query(sql_query_t *curr_query, uint32 level, sql_query_t **query, sql_select_t **subslct)
{
    uint32 depth = 0;
    sql_select_t *first_level_subslct = NULL;

    while (depth < level) {
        if (curr_query->owner == NULL || curr_query->owner->parent == NULL) {
            return OG_FALSE;
        }
        first_level_subslct = curr_query->owner;
        curr_query = curr_query->owner->parent;
        depth++;
    }
    *query = curr_query;
    if (subslct != NULL) {
        *subslct = first_level_subslct;
    }
    return OG_TRUE;
}

static inline bool32 if_cond_can_be_pulled(expr_node_t *node)
{
    switch (node->type) {
        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
        case EXPR_NODE_PL_ATTR:
            return OG_TRUE;
        case EXPR_NODE_V_ADDR:
            return sql_pair_type_is_plvar(node);
        default:
            // If want to support parent or ancestor columns, cannot include pushed-down ones
            return OG_FALSE;
    }
}

static inline bool32 if_range_need_merge(plan_range_t *range)
{
    if (range->type != RANGE_SECTION && range->type != RANGE_POINT) {
        return OG_FALSE;
    }

    if ((range->left.type != BORDER_CONST && range->left.type != BORDER_INFINITE_LEFT) ||
        (range->right.type != BORDER_CONST && range->right.type != BORDER_INFINITE_RIGHT)) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline bool32 sql_dlvr_inter_border(sql_stmt_t *stmt, plan_border_t *border1, plan_border_t *border2,
    uint32 ref_val, plan_border_t *result, bool32 is_left)
{
    if (border1->type == ref_val) {
        *result = *border2;
        return OG_TRUE;
    }

    if (border2->type == ref_val) {
        *result = *border1;
        return OG_TRUE;
    }
    return sql_inter_const_range(stmt, border1, border2, is_left, result);
}

static inline bool32 sql_dlvr_inter_range(sql_stmt_t *stmt, plan_range_t *range1, plan_range_t *range2,
    plan_range_t *result)
{
    if (!sql_dlvr_inter_border(stmt, &range1->left, &range2->left, BORDER_INFINITE_LEFT, &result->left, OG_TRUE)) {
        return OG_FALSE;
    }

    if (!sql_dlvr_inter_border(stmt, &range1->right, &range2->right, BORDER_INFINITE_RIGHT, &result->right, OG_FALSE)) {
        return OG_FALSE;
    }

    result->type = RANGE_SECTION;
    result->datatype = range1->datatype;
    if (result->left.type == BORDER_CONST && result->right.type == BORDER_CONST &&
        sql_verify_const_range(stmt, result) != OG_SUCCESS) {
        cm_reset_error();
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline status_t sql_dlvr_pair_add_range(sql_stmt_t *stmt, dlvr_pair_t *pair, plan_range_t *new_range,
    bool32 *is_false)
{
    plan_range_t result;
    plan_range_t *range = NULL;

    for (uint32 i = 0; i < pair->values.count; i++) {
        range = (plan_range_t *)cm_galist_get(&pair->values, i);
        if (if_range_need_merge(range) && if_range_need_merge(new_range) &&
            sql_dlvr_inter_range(stmt, range, new_range, &result)) {
            if (result.type == RANGE_EMPTY) {
                *is_false = OG_TRUE;
            } else {
                *range = result;
            }
            return OG_SUCCESS;
        }
        if (if_dlvr_range_equal(stmt, range, new_range)) {
            return OG_SUCCESS;
        }
    }
    return cm_galist_insert(&pair->values, new_range);
}

static inline bool32 sql_dlvr_pair_exists_value(sql_stmt_t *stmt, plan_range_t *new_range, dlvr_pair_t *pair)
{
    for (uint32 i = 0; i < pair->values.count; i++) {
        plan_range_t *range = (plan_range_t *)cm_galist_get(&pair->values, i);
        if (range->type == RANGE_POINT && if_dlvr_range_equal(stmt, range, new_range)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static inline status_t sql_dlvr_make_range(sql_stmt_t *stmt, og_type_t col_datatype, cmp_type_t cmp_type,
    expr_tree_t *val, plan_range_t **range)
{
    if (cm_stack_alloc(stmt->session->stack, sizeof(plan_range_t), (void **)range) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*range)->datatype = col_datatype;
    sql_make_range(cmp_type, val, *range);
    return OG_SUCCESS;
}

static inline bool32 if_cond_num_exceed_max(sql_query_t *query, galist_t *pairs)
{
    dlvr_pair_t *dlvr_pair = NULL;

    for (uint32 i = 0; i < pairs->count; i++) {
        dlvr_pair = (dlvr_pair_t *)cm_galist_get(pairs, i);
        if (dlvr_pair->cols.count > OG_MAX_DLVR_COLS_COUNT) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static inline bool32 if_cond_dlvr_support(cond_node_t *cond)
{
    cols_used_t cols_used;

    init_cols_used(&cols_used);
    sql_collect_cols_in_cond(cond, &cols_used);
    if (HAS_SUBSLCT(&cols_used)) {
        return OG_FALSE;
    }
    return (cond->cmp->type == CMP_TYPE_EQUAL);
}

static status_t dlvr_pull_range_with_cmp(sql_stmt_t *stmt, cond_node_t *cond, dlvr_pair_t *dlvr_pair,
    expr_tree_t *ancestor_col, bool32 *is_false)
{
    expr_tree_t *val = NULL;
    expr_tree_t *col = NULL;
    cmp_node_t *cmp = cond->cmp;
    plan_range_t *new_range = NULL;
    cmp_type_t cmp_type = cmp->type;

    if (!if_cond_dlvr_support(cond)) {
        return OG_SUCCESS;
    }

    if (IS_LOCAL_COLUMN(cmp->left) && EXPR_TAB(cmp->left) == EXPR_TAB(ancestor_col) &&
        EXPR_COL(cmp->left) == EXPR_COL(ancestor_col)) {
        col = cmp->left;
        val = cmp->right;
    } else if (IS_LOCAL_COLUMN(cmp->right) && EXPR_TAB(cmp->right) == EXPR_TAB(ancestor_col) &&
        EXPR_COL(cmp->right) == EXPR_COL(ancestor_col)) {
        col = cmp->right;
        val = cmp->left;
        // for 'in', 'like', 'between', column must be the left operand of comparison
        // so cmp_node->type is reversible
        cmp_type = sql_reverse_cmp(cmp_type);
    } else {
        return OG_SUCCESS;
    }

    if (!if_cond_can_be_pulled(val->root)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_dlvr_make_range(stmt, TREE_DATATYPE(col), cmp_type, val, &new_range));
    return sql_dlvr_pair_add_range(stmt, dlvr_pair, new_range, is_false);
}

static status_t dlvr_pull_ancestor_range(sql_stmt_t *stmt, cond_node_t *cond, dlvr_pair_t *dlvr_pair,
    expr_tree_t *ancestor_col, bool32 *is_false)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    switch (cond->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(dlvr_pull_ancestor_range(stmt, cond->left, dlvr_pair, ancestor_col, is_false));
            if (*is_false) {
                return OG_SUCCESS;
            }
            return dlvr_pull_ancestor_range(stmt, cond->right, dlvr_pair, ancestor_col, is_false);

        case COND_NODE_COMPARE:
            return dlvr_pull_range_with_cmp(stmt, cond, dlvr_pair, ancestor_col, is_false);

        default:
            return OG_SUCCESS;
    }
}

static inline status_t sql_dlvr_pull_ancestor_cond(sql_stmt_t *stmt, sql_query_t *query, dlvr_pair_t *dlvr_pair,
    plan_range_t *range, bool32 *is_false)
{
    if (range->type != RANGE_POINT) {
        return OG_SUCCESS;
    }

    expr_tree_t *val = range->left.expr;
    uint32 ancestor = EXPR_ANCESTOR(val);
    sql_query_t *ancestor_query = NULL;

    if (IS_COORDINATOR || stmt->context->has_dblink || !IS_NORMAL_COLUMN(val) || ancestor == 0 ||
        !get_specified_level_query(query, ancestor, &ancestor_query, NULL)) {
        return OG_SUCCESS;
    }

    if (ancestor_query->cond == NULL || ancestor_query->cond->root == NULL) {
        return OG_SUCCESS;
    }

    return dlvr_pull_ancestor_range(stmt, ancestor_query->cond->root, dlvr_pair, val, is_false);
}

static inline status_t sql_dlvr_pair_add_values(sql_stmt_t *stmt, sql_query_t *query, dlvr_pair_t *dlvr_pair,
    plan_range_t *new_range, bool32 *is_false)
{
    OG_RETURN_IFERR(sql_dlvr_pair_add_range(stmt, dlvr_pair, new_range, is_false));
    if (*is_false) {
        return OG_SUCCESS;
    }
    return sql_dlvr_pull_ancestor_cond(stmt, query, dlvr_pair, new_range, is_false);
}

static inline status_t sql_dlvr_merge_pair_values(sql_stmt_t *stmt, dlvr_pair_t *src, dlvr_pair_t *dst,
    bool32 *is_false)
{
    for (uint32 i = 0; i < src->values.count; i++) {
        plan_range_t *range = (plan_range_t *)cm_galist_get(&src->values, i);
        OG_RETURN_IFERR(sql_dlvr_pair_add_range(stmt, dst, range, is_false));
        if (*is_false) {
            break;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_dlvr_merge_pair_columns(dlvr_pair_t *src, dlvr_pair_t *dst)
{
    for (uint32 i = 0; i < src->cols.count; i++) {
        expr_tree_t *col = (expr_tree_t *)cm_galist_get(&src->cols, i);
        OG_RETURN_IFERR(sql_dlvr_pair_add_col(col, dst));
    }
    return OG_SUCCESS;
}

static inline status_t sql_dlvr_merge_pair(sql_stmt_t *stmt, dlvr_pair_t *src, dlvr_pair_t *dst, bool32 *is_false)
{
    OG_RETURN_IFERR(sql_dlvr_merge_pair_values(stmt, src, dst, is_false));
    if (*is_false) {
        return OG_SUCCESS;
    }
    return sql_dlvr_merge_pair_columns(src, dst);
}

static inline status_t sql_dlvr_try_merge_pairs(sql_stmt_t *stmt, uint32 start_pos, expr_tree_t *left,
    expr_tree_t *right, dlvr_pair_t *merge_pair, galist_t *pairs, bool32 *is_false)
{
    dlvr_pair_t *dlvr_pair = NULL;

    for (uint32 i = start_pos; i < pairs->count;) {
        dlvr_pair = (dlvr_pair_t *)cm_galist_get(pairs, i);
        if (sql_dlvr_pair_exists_col(left, dlvr_pair) || (right != NULL &&
                                                          sql_dlvr_pair_exists_col(right, dlvr_pair))) {
            OG_RETURN_IFERR(sql_dlvr_merge_pair(stmt, dlvr_pair, merge_pair, is_false));
            if (*is_false) {
                break;
            }
            cm_galist_delete(pairs, i);
            continue;
        }
        i++;
    }
    return OG_SUCCESS;
}

static inline status_t sql_dlvr_pairs_add_ff(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *left,
    expr_tree_t *right, galist_t *pairs, bool32 *is_false)
{
    bool32 is_found = OG_FALSE;
    dlvr_pair_t *pair = NULL;

    for (uint32 i = 0; i < pairs->count; i++) {
        pair = (dlvr_pair_t *)cm_galist_get(pairs, i);
        OG_RETURN_IFERR(sql_dlvr_pair_try_add_ff(left, right, pair, &is_found));
        if (is_found) {
            return sql_dlvr_try_merge_pairs(stmt, i + 1, left, right, pair, pairs, is_false);
        }
    }
    return sql_dlvr_pairs_add_ff_pair(stmt, query, left, right, pairs);
}

static inline status_t sql_dlvr_pairs_add_fv_pair(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *col,
    plan_range_t *new_range, galist_t *pairs)
{
    bool32 is_false = OG_FALSE;
    dlvr_pair_t *pair = NULL;

    OG_RETURN_IFERR(sql_init_dlvr_pair(stmt, query, &pair, pairs));
    OG_RETURN_IFERR(sql_dlvr_pair_add_col(col, pair));
    OG_RETURN_IFERR(cm_galist_insert(&pair->values, new_range));
    return sql_dlvr_pull_ancestor_cond(stmt, query, pair, new_range, &is_false);
}

static inline bool32 has_semi_in_expr(sql_query_t *query, expr_tree_t *expr)
{
    if (!IS_LOCAL_COLUMN(expr)) {
        return OG_FALSE;
    }
    sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, expr->root->value.v_col.tab);
    if (table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline bool32 has_semi_in_cmp_node(sql_query_t *query, cmp_node_t *cmp)
{
    return (bool32)(has_semi_in_expr(query, cmp->left) || has_semi_in_expr(query, cmp->right));
}

static status_t expr_node_is_dlvr_value(visit_assist_t *visit_ass, expr_node_t **node)
{
    switch ((*node)->type) {
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
        case EXPR_NODE_CONST:
            return OG_SUCCESS;

        case EXPR_NODE_RESERVED:
            if ((*node)->value.v_int == RES_WORD_SYSDATE || (*node)->value.v_int == RES_WORD_SYSTIMESTAMP ||
                ((*node)->value.v_int == RES_WORD_ROWID && (*node)->value.v_rid.ancestor > 0)) {
                return OG_SUCCESS;
            }
            break;

        case EXPR_NODE_COLUMN:
            if (NODE_ANCESTOR(*node) > 0) {
                return OG_SUCCESS;
            }
            break;
        case EXPR_NODE_V_ADDR:
            if (sql_pair_type_is_plvar(*node)) {
                return OG_SUCCESS;
            }
            break;
        default:
            break;
    }
    visit_ass->result0 = OG_FALSE;
    return OG_SUCCESS;
}

static inline status_t expr_tree_is_dlvr_value(sql_stmt_t *stmt, expr_tree_t *expr_tree, bool32 *is_dlvr)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.result0 = OG_TRUE;
    OG_RETURN_IFERR(visit_expr_tree(&visit_ass, expr_tree, expr_node_is_dlvr_value));
    *is_dlvr = (bool32)visit_ass.result0;
    return OG_SUCCESS;
}

static inline status_t pre_generate_dlvr_cond(sql_stmt_t *stmt, expr_tree_t *column, cond_node_t **node)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)node));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&(*node)->cmp));
    (*node)->type = COND_NODE_COMPARE;
    return sql_clone_expr_tree(stmt->context, column, &(*node)->cmp->left, sql_alloc_mem);
}

static inline status_t sql_generate_ff_cond(sql_stmt_t *stmt, expr_tree_t *left, expr_tree_t *right, cond_tree_t *cond,
    bool32 has_filter_cond)
{
    cond_node_t *node = NULL;
    OG_RETURN_IFERR(pre_generate_dlvr_cond(stmt, left, &node));
    node->cmp->type = CMP_TYPE_EQUAL;
    node->cmp->has_conflict_chain = has_filter_cond;
    OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, right, &node->cmp->right, sql_alloc_mem));
    return sql_add_cond_node_left(cond, node);
}

static inline status_t generate_range_list_cond(sql_stmt_t *stmt, expr_tree_t *left, plan_range_t *range,
    cond_tree_t *cond)
{
    cond_node_t *node = NULL;
    expr_tree_t **next = NULL;
    expr_tree_t *arg = range->left.expr;

    OG_RETURN_IFERR(pre_generate_dlvr_cond(stmt, left, &node));
    node->cmp->type = CMP_TYPE_IN;
    next = &node->cmp->right;
    while (arg) {
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, arg, next, sql_alloc_mem));
        arg = arg->next;
        next = &(*next)->next;
    }
    return sql_add_cond_node_left(cond, node);
}

static inline status_t generate_range_like_cond(sql_stmt_t *stmt, expr_tree_t *left, plan_range_t *range,
    cond_tree_t *cond)
{
    cond_node_t *node = NULL;

    OG_RETURN_IFERR(pre_generate_dlvr_cond(stmt, left, &node));
    node->cmp->type = CMP_TYPE_LIKE;
    OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->left.expr, &node->cmp->right, sql_alloc_mem));
    return sql_add_cond_node_left(cond, node);
}

static inline status_t generate_range_point_cond(sql_stmt_t *stmt, expr_tree_t *left, plan_range_t *range,
    cond_tree_t *cond)
{
    cond_node_t *node = NULL;

    OG_RETURN_IFERR(pre_generate_dlvr_cond(stmt, left, &node));
    node->cmp->type = CMP_TYPE_EQUAL;
    OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->left.expr, &node->cmp->right, sql_alloc_mem));
    return sql_add_cond_node_left(cond, node);
}

static inline status_t generate_range_section_cond(sql_stmt_t *stmt, expr_tree_t *left, plan_range_t *range,
    cond_tree_t *cond)
{
    cond_node_t *node = NULL;
    OG_RETURN_IFERR(pre_generate_dlvr_cond(stmt, left, &node));

    if (range->left.type == BORDER_INFINITE_LEFT) {
        node->cmp->type = range->right.closed ? CMP_TYPE_LESS_EQUAL : CMP_TYPE_LESS;
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->right.expr, &node->cmp->right, sql_alloc_mem));
    } else if (range->right.type == BORDER_INFINITE_RIGHT) {
        node->cmp->type = range->left.closed ? CMP_TYPE_GREAT_EQUAL : CMP_TYPE_GREAT;
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->left.expr, &node->cmp->right, sql_alloc_mem));
    } else if (range->left.closed && range->right.closed) {
        node->cmp->type = CMP_TYPE_BETWEEN;
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->left.expr, &node->cmp->right, sql_alloc_mem));
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->right.expr, &node->cmp->right->next, sql_alloc_mem));
    } else {
        node->cmp->type = range->right.closed ? CMP_TYPE_LESS_EQUAL : CMP_TYPE_LESS;
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->right.expr, &node->cmp->right, sql_alloc_mem));
        OG_RETURN_IFERR(sql_add_cond_node_left(cond, node));

        OG_RETURN_IFERR(pre_generate_dlvr_cond(stmt, left, &node));
        node->cmp->type = range->left.closed ? CMP_TYPE_GREAT_EQUAL : CMP_TYPE_GREAT;
        OG_RETURN_IFERR(sql_clone_expr_tree(stmt->context, range->left.expr, &node->cmp->right, sql_alloc_mem));
    }
    return sql_add_cond_node_left(cond, node);
}

static inline status_t sql_generate_fv_cond(sql_stmt_t *stmt, expr_tree_t *left, plan_range_t *range, cond_tree_t *cond)
{
    switch (range->type) {
        case RANGE_LIST:
            return generate_range_list_cond(stmt, left, range, cond);

        case RANGE_LIKE:
            return generate_range_like_cond(stmt, left, range, cond);

        case RANGE_POINT:
            return generate_range_point_cond(stmt, left, range, cond);

        case RANGE_SECTION:
            return generate_range_section_cond(stmt, left, range, cond);

        default:
            OG_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, (int32)range->type);
            return OG_ERROR;
    }
}

static inline status_t sql_generate_fv_dlvr_conds(sql_stmt_t *stmt, cond_tree_t *cond, dlvr_pair_t *dlvr_pair)
{
    expr_tree_t *col = NULL;
    plan_range_t *range = NULL;

    for (uint32 i = 0; i < dlvr_pair->cols.count; i++) {
        col = (expr_tree_t *)cm_galist_get(&dlvr_pair->cols, i);
        for (uint32 j = 0; j < dlvr_pair->values.count; j++) {
            range = (plan_range_t *)cm_galist_get(&dlvr_pair->values, j);
            OG_RETURN_IFERR(sql_generate_fv_cond(stmt, col, range, cond));
        }
    }
    return OG_SUCCESS;
}

static status_t sql_generate_ff_dlvr_conds(sql_stmt_t *stmt, cond_tree_t *cond, dlvr_pair_t *dlvr_pair)
{
    expr_tree_t *left = NULL;
    expr_tree_t *right = NULL;
    plan_range_t *range = NULL;
    bool32 has_filter_cond = OG_FALSE;
    for (uint32 j = 0; j < dlvr_pair->values.count; j++) {
        range = (plan_range_t *)cm_galist_get(&dlvr_pair->values, j);
        if (range->type == RANGE_POINT) {
            has_filter_cond = OG_TRUE;
            break;
        }
    }
    for (uint32 i = 0; i < dlvr_pair->cols.count - 1; i++) {
        left = (expr_tree_t *)cm_galist_get(&dlvr_pair->cols, i);
        for (uint32 j = i + 1; j < dlvr_pair->cols.count; j++) {
            right = (expr_tree_t *)cm_galist_get(&dlvr_pair->cols, j);
            OG_RETURN_IFERR(sql_generate_ff_cond(stmt, left, right, cond, has_filter_cond));
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_generate_dlvr_cond(sql_stmt_t *stmt, cond_tree_t *cond, dlvr_pair_t *dlvr_pair)
{
    // generate join condition
    OG_RETURN_IFERR(sql_generate_ff_dlvr_conds(stmt, cond, dlvr_pair));
    // generate filter condition
    return sql_generate_fv_dlvr_conds(stmt, cond, dlvr_pair);
}

static inline status_t sql_generate_dlvr_conds(sql_stmt_t *stmt, cond_tree_t *cond, galist_t *pairs)
{
    dlvr_pair_t *dlvr_pair = NULL;

    for (uint32 i = 0; i < pairs->count; i++) {
        dlvr_pair = (dlvr_pair_t *)cm_galist_get(pairs, i);
        OG_RETURN_IFERR(sql_generate_dlvr_cond(stmt, cond, dlvr_pair));
    }
    return OG_SUCCESS;
}

static status_t sql_generate_dlvr_pairs(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *l_col, galist_t *values,
    galist_t *ff_pairs, galist_t *dlvr_pairs)
{
    bool32 is_found = OG_FALSE;
    dlvr_pair_t *ff_pair = NULL;
    dlvr_pair_t *dlvr_pair = NULL;

    for (uint32 i = 0; i < ff_pairs->count; i++) {
        ff_pair = (dlvr_pair_t *)cm_galist_get(ff_pairs, i);
        if (sql_dlvr_pair_exists_col(l_col, ff_pair)) {
            is_found = OG_TRUE;
            break;
        }
    }

    if (!is_found) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_init_dlvr_pair(stmt, query, &dlvr_pair, dlvr_pairs));

    for (uint32 i = 0; i < ff_pair->cols.count; i++) {
        expr_tree_t *r_col = (expr_tree_t *)cm_galist_get(&ff_pair->cols, i);
        if (EXPR_TAB(r_col) == EXPR_TAB(l_col) && EXPR_COL(r_col) == EXPR_COL(l_col)) {
            continue;
        }
        OG_RETURN_IFERR(sql_dlvr_pair_add_col(r_col, dlvr_pair));
    }

    for (uint32 i = 0; i < values->count; i++) {
        plan_range_t *range = (plan_range_t *)cm_galist_get(values, i);
        OG_RETURN_IFERR(cm_galist_insert(&dlvr_pair->values, range));
    }
    return OG_SUCCESS;
}

static inline status_t sql_try_generate_dlvr_pairs(sql_stmt_t *stmt, sql_query_t *query, galist_t *ff_pairs,
    galist_t *fv_pairs, galist_t *dlvr_pairs)
{
    for (uint32 i = 0; i < fv_pairs->count; i++) {
        dlvr_pair_t *pair = (dlvr_pair_t *)cm_galist_get(fv_pairs, i);
        if (pair->values.count == 0) {
            continue;
        }

        for (uint32 j = 0; j < pair->cols.count; j++) {
            expr_tree_t *col = (expr_tree_t *)cm_galist_get(&pair->cols, j);
            OG_RETURN_IFERR(sql_generate_dlvr_pairs(stmt, query, col, &pair->values, ff_pairs, dlvr_pairs));
        }
    }
    return OG_SUCCESS;
}

static inline bool32 sink_oper_remove_node(sql_stmt_t *stmt, cond_node_t *cond, biqueue_t *cond_que)
{
    biqueue_node_t *curr = biqueue_first(cond_que);
    biqueue_node_t *end = biqueue_end(cond_que);

    while (curr != end) {
        cond_node_t *cond_node = OBJECT_OF(cond_node_t, curr);
        if (sql_cond_node_equal(stmt, cond_node, cond, NULL)) {
            biqueue_del_node(curr);
            return OG_TRUE;
        }
        curr = curr->next;
    }
    return OG_FALSE;
}

static void sink_oper_collect_node(cond_node_t *cond_node, biqueue_t *cond_que)
{
    if (cond_node->type == COND_NODE_AND) {
        sink_oper_collect_node(cond_node->left, cond_que);
        sink_oper_collect_node(cond_node->right, cond_que);
        return;
    }
    biqueue_add_tail(cond_que, QUEUE_NODE_OF(cond_node));
}

static inline status_t sink_oper_add_cond(sql_stmt_t *stmt, cond_node_t **dst, cond_node_t *src)
{
    if (*dst == NULL) {
        *dst = src;
        return OG_SUCCESS;
    }

    cond_node_t *cond_node = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&cond_node));
    cond_node->type = COND_NODE_AND;
    cond_node->left = *dst;
    cond_node->right = src;
    *dst = cond_node;
    return OG_SUCCESS;
}

static inline status_t sink_oper_generate_remain_cond(sql_stmt_t *stmt, biqueue_t *cond_que, cond_node_t **cond)
{
    biqueue_node_t *curr_que = biqueue_first(cond_que);
    biqueue_node_t *end_que = biqueue_end(cond_que);

    while (curr_que != end_que) {
        cond_node_t *cond_node = OBJECT_OF(cond_node_t, curr_que);
        if (sink_oper_add_cond(stmt, cond, cond_node) != OG_SUCCESS) {
            return OG_ERROR;
        }
        curr_que = curr_que->next;
    }
    return OG_SUCCESS;
}

static inline status_t sink_oper_remove_same_cond(sql_stmt_t *stmt, biqueue_t *l_que, biqueue_t *r_que,
    cond_node_t **same_cond)
{
    biqueue_node_t *del_node = NULL;
    biqueue_node_t *curr_node = biqueue_first(l_que);
    biqueue_node_t *end_node = biqueue_end(l_que);

    while (curr_node != end_node) {
        cond_node_t *cond = OBJECT_OF(cond_node_t, curr_node);
        if (!sink_oper_remove_node(stmt, cond, r_que)) {
            curr_node = curr_node->next;
            continue;
        }
        OG_RETURN_IFERR(sink_oper_add_cond(stmt, same_cond, cond));
        del_node = curr_node;
        curr_node = curr_node->next;
        biqueue_del_node(del_node);
    }
    return OG_SUCCESS;
}

static inline status_t sink_oper_regenerate_cond(sql_stmt_t *stmt, cond_node_t *same_cond, cond_node_t *l_remain,
    cond_node_t *r_remain, cond_node_t **cond)
{
    cond_node_t *or_cond = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&or_cond));
    or_cond->type = COND_NODE_OR;
    or_cond->left = l_remain;
    or_cond->right = r_remain;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)cond));
    (*cond)->type = COND_NODE_AND;
    (*cond)->left = same_cond;
    (*cond)->right = or_cond;
    return OG_SUCCESS;
}

static status_t remove_winsort_node(visit_assist_t *visit_ass, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_OVER) {
        sql_query_t *query = visit_ass->query;
        expr_node_t *winsort_node = NULL;
        for (uint32 i = query->winsort_list->count; i > 0; i--) {
            winsort_node = (expr_node_t *)cm_galist_get(query->winsort_list, i - 1);
            if (winsort_node == *node) {
                cm_galist_delete(query->winsort_list, i - 1);
                break;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t deal_removed_cond(sql_stmt_t *stmt, cond_node_t *removed_cond)
{
    visit_assist_t visit_ass;
    sql_query_t *query = OGSQL_CURR_NODE(stmt);
    sql_init_visit_assist(&visit_ass, stmt, query);
    visit_ass.excl_flags |= VA_EXCL_WIN_SORT;
    return visit_cond_node(&visit_ass, removed_cond, remove_winsort_node);
}

static status_t sql_oper_or_sink(sql_stmt_t *stmt, cond_node_t **cond)
{
    biqueue_t left_que;
    biqueue_t right_que;
    cond_node_t *l_remain = NULL;
    cond_node_t *r_remain = NULL;
    cond_node_t *same_cond = NULL;

    biqueue_init(&left_que);
    biqueue_init(&right_que);

    sink_oper_collect_node((*cond)->left, &left_que);
    sink_oper_collect_node((*cond)->right, &right_que);

    // remove the same cond on both sides
    OG_RETURN_IFERR(sink_oper_remove_same_cond(stmt, &left_que, &right_que, &same_cond));
    // if no same cond, then no need rewrite cond node
    if (same_cond == NULL) {
        return OG_SUCCESS;
    }
    // construct left remain cond
    OG_RETURN_IFERR(sink_oper_generate_remain_cond(stmt, &left_que, &l_remain));
    // construct right remain cond
    OG_RETURN_IFERR(sink_oper_generate_remain_cond(stmt, &right_que, &r_remain));
    if (l_remain == NULL || r_remain == NULL) {
        *cond = same_cond;
        if (l_remain != NULL) {
            OG_RETURN_IFERR(deal_removed_cond(stmt, l_remain));
        }
        if (r_remain != NULL) {
            OG_RETURN_IFERR(deal_removed_cond(stmt, r_remain));
        }
        return OG_SUCCESS;
    }
    return sink_oper_regenerate_cond(stmt, same_cond, l_remain, r_remain, cond);
}

status_t sql_process_oper_or_sink(sql_stmt_t *stmt, cond_node_t **cond)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    if ((*cond)->type != COND_NODE_AND && (*cond)->type != COND_NODE_OR) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_process_oper_or_sink(stmt, &(*cond)->left));
    OG_RETURN_IFERR(sql_process_oper_or_sink(stmt, &(*cond)->right));

    if ((*cond)->type == COND_NODE_OR) {
        return sql_oper_or_sink(stmt, cond);
    }
    return OG_SUCCESS;
}

static inline status_t sql_flatten_cond_node(sql_stmt_t *stmt, cond_node_t *cond, galist_t *cond_list,
    galist_t *and_list)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));

    if (cond->type == COND_NODE_AND) {
        if (cm_galist_insert(and_list, cond) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (sql_flatten_cond_node(stmt, cond->left, cond_list, and_list) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return sql_flatten_cond_node(stmt, cond->right, cond_list, and_list);
    }
    return cm_galist_insert(cond_list, cond);
}

static inline bool32 sql_query_is_index_scan(sql_query_t *query)
{
    if (query->tables.count > 1) {
        return OG_FALSE;
    }
    sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, 0);
    if (table->index != NULL && (INDEX_ONLY_SCAN(table->scan_flag) ||
        ((table->index->primary || table->index->unique) && table->idx_equal_to == table->index->column_count))) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 sql_is_simple_expr_node(expr_node_t *node, uint32 level);
static inline bool32 sql_is_simple_func(expr_node_t *func, uint32 level)
{
    expr_tree_t *arg = func->argument;

    while (arg != NULL) {
        if (!sql_is_simple_expr_node(arg->root, level + 1)) {
            return OG_FALSE;
        }
        arg = arg->next;
    }
    return OG_TRUE;
}

#define SIMPLE_EXPR_MAX_LEVEL 3

static bool32 sql_is_simple_expr_node(expr_node_t *node, uint32 level)
{
    if (level > SIMPLE_EXPR_MAX_LEVEL) {
        return OG_FALSE;
    }

    switch (node->type) {
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
        case EXPR_NODE_RESERVED:
        case EXPR_NODE_SEQUENCE:
        case EXPR_NODE_TRANS_COLUMN:
            return OG_TRUE;

        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(sql_is_simple_expr_node(node->left, level + 1) &&
                sql_is_simple_expr_node(node->right, level + 1));

        case EXPR_NODE_FUNC:
            return sql_is_simple_func(node, level);

        default:
            return OG_FALSE;
    }
}

static inline bool32 sql_is_simple_expr(expr_tree_t *expr)
{
    if (expr->next != NULL) {
        return OG_FALSE;
    }
    return sql_is_simple_expr_node(expr->root, 0);
}

static inline bool32 check_single_col_filter_cond(const cmp_node_t *cmp1, const cmp_node_t *cmp2, const expr_tree_t *r1,
    const expr_tree_t *r2, int32 *result)
{
    if (cmp1->left != NULL && sql_is_simple_expr(cmp1->left) &&
        (r1 == NULL || sql_is_single_const_or_param(r1->root))) {
        *result = 0;
        return OG_TRUE;
    }
    if (cmp2->left != NULL && sql_is_simple_expr(cmp2->left) &&
        (r2 == NULL || sql_is_single_const_or_param(r2->root))) {
        *result = 1;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 check_cmp_join_cond(const cmp_node_t *cmp1, const cmp_node_t *cmp2, const expr_tree_t *r1,
    const expr_tree_t *r2, int32 *result)
{
    if (cmp1->type == CMP_TYPE_EQUAL && sql_is_single_column(cmp1->left->root) && sql_is_single_column(r1->root)) {
        *result = 0;
        return OG_TRUE;
    }
    if (cmp2->type == CMP_TYPE_EQUAL && sql_is_single_column(cmp2->left->root) && sql_is_single_column(r2->root)) {
        *result = 1;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 check_exists_subslct_with_index(const cmp_node_t *cmp, const expr_tree_t *r_expr, int32 *result)
{
    if (cmp->left == NULL && r_expr->root->type == EXPR_NODE_SELECT && r_expr->next == NULL) {
        sql_select_t *subslct = (sql_select_t *)r_expr->root->value.v_obj.ptr;
        if (subslct->root->type == SELECT_NODE_QUERY && sql_query_is_index_scan(subslct->first_query)) {
            *result = 1;
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

#ifdef __cplusplus
}
#endif
