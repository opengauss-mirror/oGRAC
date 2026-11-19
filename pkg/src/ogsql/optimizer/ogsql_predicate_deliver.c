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
#include "ogsql_predicate_deliver.h"
#include "ogsql_table_func.h"
#include "ogsql_func.h"
#include "ogsql_cond_rewrite.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "plan_rbo.h"
#include "plan_range.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 is_same_col(expr_tree_t *l_col, expr_tree_t *r_col)
{
    return EXPR_TAB(l_col) == EXPR_TAB(r_col) && EXPR_COL(l_col) == EXPR_COL(r_col);
}

static uint32 og_get_table_column_count(sql_stmt_t *statement, sql_table_t *tbl)
{
    if (tbl->type == FUNC_AS_TABLE) {
        return sql_get_func_table_column_count(statement, tbl);
    }
    if (tbl->type == VIEW_AS_TABLE || tbl->type == SUBSELECT_AS_TABLE || tbl->type == WITH_AS_TABLE) {
        return tbl->select_ctx->first_query->rs_columns->count;
    }
    if (tbl->type == JSON_TABLE) {
        return tbl->json_table_info->columns.count;
    }
    return knl_get_column_count(tbl->entry->dc.handle);
}

static bool32 if_expr_node_can_be_pulled(expr_node_t *node)
{
    if (node->type == EXPR_NODE_CONST || node->type == EXPR_NODE_PARAM || node->type == EXPR_NODE_CSR_PARAM ||
        node->type == EXPR_NODE_PL_ATTR) {
        return OG_TRUE;
    }
    if (node->type == EXPR_NODE_V_ADDR) {
        return sql_pair_type_is_plvar(node);
    }
    // If want to support parent or ancestor columns, cannot include pushed-down ones
    return OG_FALSE;
}

static inline bool32 if_value_can_be_pulled(expr_tree_t *val)
{
    while (val != NULL) {
        if (!if_expr_node_can_be_pulled(val->root)) {
            return OG_FALSE;
        }
        val = val->next;
    }

    return OG_TRUE;
}

static inline bool32 is_range_mergeable(plan_range_t *range)
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

static inline status_t og_dlvr_make_range(sql_stmt_t *statement, og_type_t col_datatype, cmp_type_t cmp_type,
                                          expr_tree_t *val_exprtr, plan_range_t **range)
{
    if (cm_stack_alloc(statement->session->stack, sizeof(plan_range_t), (void **)range) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*range)->datatype = col_datatype;
    sql_make_range(cmp_type, val_exprtr, *range);
    return OG_SUCCESS;
}

static inline bool32 if_cmp_can_dlvr(cond_node_t *cmp_cond)
{
    cols_used_t cols_used;

    init_cols_used(&cols_used);
    sql_collect_cols_in_cond(cmp_cond, &cols_used);
    if (HAS_SUBSLCT(&cols_used)) {
        return OG_FALSE;
    }
    return (cmp_cond->cmp->type == CMP_TYPE_EQUAL);
}

static status_t og_pred_add_value(sql_stmt_t *statement, pred_node_t *pred, plan_range_t *new_range,
    bool32 *is_conflict)
{
    plan_range_t result = { 0 };
    plan_range_t *range = NULL;

    uint32 i = 0;
    while (i < pred->values.count) {
        range = (plan_range_t *)cm_galist_get(&pred->values, i++);
        if (is_range_mergeable(range) && is_range_mergeable(new_range) &&
            sql_dlvr_inter_range(statement, range, new_range, &result)) {
            if (result.type == RANGE_EMPTY) {
                *is_conflict = OG_TRUE;
            } else {
                *range = result;
            }
            return OG_SUCCESS;
        }
        OG_RETSUC_IFTRUE(if_dlvr_range_equal(statement, range, new_range));
    }

    return cm_galist_insert(&pred->values, new_range);
}

static void og_get_value_col_from_cmp(cmp_node_t *cmp, cmp_type_t* cmp_type, expr_tree_t **col_exprtr,
                                             expr_tree_t **val_exprtr)
{
    if (IS_LOCAL_COLUMN(cmp->left)) {
        *col_exprtr = cmp->left;
        *val_exprtr = cmp->right;
        return;
    }
    
    if (IS_LOCAL_COLUMN(cmp->right)) {
        *col_exprtr = cmp->right;
        *val_exprtr = cmp->left;
        // for 'in', 'like', 'between', column must be the left operand of comparison
        // so cmp_node->type is reversible
        *cmp_type = sql_reverse_cmp(cmp->type);
        return;
    }
}

static status_t og_try_pull_value_in_cmp(sql_stmt_t *statement, cond_node_t *cmp_cond, pred_node_t *pred,
                                         expr_tree_t *ancestor_col, bool32 *is_conflict)
{
    OG_RETSUC_IFTRUE(!if_cmp_can_dlvr(cmp_cond));

    expr_tree_t *val_exprtr = NULL;
    expr_tree_t *col_exprtr = NULL;
    cmp_node_t *cmp = cmp_cond->cmp;
    plan_range_t *new_range = NULL;
    cmp_type_t cmp_type = cmp->type;

    og_get_value_col_from_cmp(cmp, &cmp_type, &col_exprtr, &val_exprtr);
    OG_RETSUC_IFTRUE(col_exprtr == NULL || val_exprtr == NULL);
    OG_RETSUC_IFTRUE(!is_same_col(col_exprtr, ancestor_col));
    OG_RETSUC_IFTRUE(!if_value_can_be_pulled(val_exprtr));

    OG_RETURN_IFERR(og_dlvr_make_range(statement, TREE_DATATYPE(col_exprtr), cmp_type, val_exprtr, &new_range));
    return og_pred_add_value(statement, pred, new_range, is_conflict);
}

static status_t og_try_pull_ancestor_value(sql_stmt_t *statement, cond_node_t *cmp_cond, pred_node_t *pred,
                                         expr_tree_t *ancestor_col, bool32 *is_conflict)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));
    cond_node_type_t cond_type = cmp_cond->type;
    if (cond_type == COND_NODE_AND) {
        OG_RETURN_IFERR(og_try_pull_ancestor_value(statement, cmp_cond->left, pred, ancestor_col, is_conflict));
        if (*is_conflict) {
            return OG_SUCCESS;
        }
        return og_try_pull_ancestor_value(statement, cmp_cond->right, pred, ancestor_col, is_conflict);
    } else if (cond_type == COND_NODE_COMPARE) {
        return og_try_pull_value_in_cmp(statement, cmp_cond, pred, ancestor_col, is_conflict);
    }

    return OG_SUCCESS;
}

static status_t og_dlvr_pull_ancestor_conds(sql_stmt_t *statement, sql_query_t *qry, pred_node_t *pred,
                                            plan_range_t *range, bool32 *is_conflict)
{
    if (range->type != RANGE_POINT) {
        return OG_SUCCESS;
    }

    expr_tree_t *val_exprtr = range->left.expr;
    uint32 ancestor = EXPR_ANCESTOR(val_exprtr);
    sql_query_t *ancestor_qry = NULL;

    if (IS_COORDINATOR || statement->context->has_dblink || !IS_NORMAL_COLUMN(val_exprtr) || ancestor == 0 ||
        !get_specified_level_query(qry, ancestor, &ancestor_qry, NULL)) {
        return OG_SUCCESS;
    }

    if (ancestor_qry == NULL) {
        return OG_SUCCESS;
    }

    if (ancestor_qry->cond == NULL || ancestor_qry->cond->root == NULL) {
        return OG_SUCCESS;
    }

    return og_try_pull_ancestor_value(statement, ancestor_qry->cond->root, pred, val_exprtr, is_conflict);
}

static inline status_t og_generate_join_cond(sql_stmt_t *statement, expr_tree_t *left, expr_tree_t *right,
                                             cond_tree_t *cmp_cond, bool32 has_filter_cond)
{
    cond_node_t *node = NULL;
    OG_RETURN_IFERR(pre_generate_dlvr_cond(statement, left, &node));
    node->cmp->type = CMP_TYPE_EQUAL;
    node->cmp->has_conflict_chain = has_filter_cond;
    OG_RETURN_IFERR(sql_clone_expr_tree(statement->context, right, &node->cmp->right, sql_alloc_mem));
    return sql_add_cond_node_left(cmp_cond, node);
}

static status_t og_pred_rebuild_filter_conds(sql_stmt_t *statement, cond_tree_t *cmp_cond, pred_node_t *pred)
{
    expr_tree_t *col_exprtr = NULL;
    plan_range_t *range = NULL;

    uint32 i = 0;
    while (i < pred->cols.count) {
        col_exprtr = (expr_tree_t *)cm_galist_get(&pred->cols, i++);
        uint32 j = 0;
        while (j < pred->values.count) {
            range = (plan_range_t *)cm_galist_get(&pred->values, j++);
            if (sql_generate_fv_cond(statement, col_exprtr, range, cmp_cond) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[PRED_DLVR] failed to generate filter cond");
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static void try_remove_unused_join_cols(galist_t *join_cols_lst)
{
    expr_tree_t *col1 = NULL;
    expr_tree_t *col2 = NULL;

    uint32 i = join_cols_lst->count - 1;
    while (i > 0) {
        col1 = (expr_tree_t *)cm_galist_get(join_cols_lst, i);
        uint32 j = 0;
        while (j < i) {
            col2 = (expr_tree_t *)cm_galist_get(join_cols_lst, j);
            if (col1->root->value.v_col.tab == col2->root->value.v_col.tab) {
                cm_galist_delete(join_cols_lst, j);
                break;
            }
            j += 1;
        }
        i -= 1;
    }

    return;
}

static bool32 is_dlvr_value_const_reserved(uint32 type)
{
    switch (type) {
        case RES_WORD_SYSDATE:
        case RES_WORD_SYSTIMESTAMP:
        case RES_WORD_CURDATE:
        case RES_WORD_CURTIMESTAMP:
        case RES_WORD_LOCALTIMESTAMP:
        case RES_WORD_UTCTIMESTAMP:
        case RES_WORD_NULL:
        case RES_WORD_TRUE:
        case RES_WORD_FALSE:
        case RES_WORD_DATABASETZ:
        case RES_WORD_SESSIONTZ:
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
}

static bool32 check_dlvr_value_is_const(expr_tree_t *val)
{
    expr_node_type_t type = val->root->type;
    if (type == EXPR_NODE_RESERVED) {
        return is_dlvr_value_const_reserved(type);
    }
    return type == EXPR_NODE_PARAM || type == EXPR_NODE_CSR_PARAM || type == EXPR_NODE_CONST;
}

static bool32 is_pred_has_const_value(galist_t *values)
{
    plan_range_t *range = NULL;
    uint32 i = 0;
    while (i < values->count) {
        range = (plan_range_t *)cm_galist_get(values, i++);
        if (range->type == RANGE_POINT && check_dlvr_value_is_const(range->left.expr)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t og_pred_rebuild_join_conds(sql_stmt_t *statement, cond_tree_t *cmp_cond, pred_node_t *pred)
{
    plan_range_t *range = NULL;
    bool32 has_filter_cond = OG_FALSE;

    uint32 k = 0;
    while (k < pred->values.count) {
        range = (plan_range_t *)cm_galist_get(&pred->values, k++);
        if (range->type == RANGE_POINT) {
            has_filter_cond = OG_TRUE;
            break;
        }
    }

    // if has cmp_cond (a = 1 and b = 1) and a,b is same tab's col,we don't need to generate a = b
    OGSQL_SAVE_STACK(statement);
    galist_t join_cols_lst;
    cm_galist_init(&join_cols_lst, statement->session->stack, cm_stack_alloc);
    OG_RETURN_IFERR(cm_galist_copy(&join_cols_lst, &pred->cols));
    if (pred->values.count != 0 && is_pred_has_const_value(&pred->values)) {
        try_remove_unused_join_cols(&join_cols_lst);
    }

    expr_tree_t *l_exprtr = NULL;
    expr_tree_t *r_exprtr = NULL;

    uint32 i = 0;
    while (i < join_cols_lst.count - 1) {
        l_exprtr = (expr_tree_t *)cm_galist_get(&join_cols_lst, i);
        uint32 j = i + 1;
        while (j < join_cols_lst.count) {
            r_exprtr = (expr_tree_t *)cm_galist_get(&join_cols_lst, j++);
            if (og_generate_join_cond(statement, l_exprtr, r_exprtr, cmp_cond, has_filter_cond) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[PRED_DLVR] Failed to generate join condition.");
                return OG_ERROR;
            }
        }
        i += 1;
    }

    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static inline status_t og_pred_rebuild_conds(sql_stmt_t *statement, cond_tree_t *cmp_cond, pred_node_t *pred)
{
    // generate join condition
    if (og_pred_rebuild_join_conds(statement, cmp_cond, pred) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PRED_DLVR] Failed to rebuild join condition.");
        return OG_ERROR;
    }

    // generate filter condition
    if (og_pred_rebuild_filter_conds(statement, cmp_cond, pred) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PRED_DLVR] Failed to generate filter condition.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline bool32 is_index_scan_query(sql_query_t *qry)
{
    if (qry->tables.count > 1) {
        return OG_FALSE;
    }
    sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
    if (tbl->index != NULL &&
        (INDEX_ONLY_SCAN(tbl->scan_flag) ||
         ((tbl->index->primary || tbl->index->unique) && tbl->idx_equal_to == tbl->index->column_count))) {
        return OG_TRUE;
    }
    return OG_FALSE;
}
static inline bool32 is_simple_function_args(expr_node_t *func, uint32 level)
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

static inline bool32 og_check_subslct_with_index(const cmp_node_t *cmp, const expr_tree_t *r_exprtr, int32 *result)
{
    if (cmp->left == NULL && r_exprtr->root->type == EXPR_NODE_SELECT && r_exprtr->next == NULL) {
        sql_select_t *sub_slct = (sql_select_t *)r_exprtr->root->value.v_obj.ptr;
        if (sub_slct->root->type == SELECT_NODE_QUERY && is_index_scan_query(sub_slct->first_query)) {
            *result = 1;
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static bool32 is_expr_node_reorderable(expr_node_t *exprn)
{
    if (exprn->type == EXPR_NODE_COLUMN || exprn->type == EXPR_NODE_TRANS_COLUMN || exprn->type == EXPR_NODE_CONST ||
        exprn->type == EXPR_NODE_PARAM || exprn->type == EXPR_NODE_CSR_PARAM || exprn->type == EXPR_NODE_RESERVED ||
        exprn->type == EXPR_NODE_SELECT || exprn->type == EXPR_NODE_PL_ATTR) {
        return OG_TRUE;
    }
    if (exprn->type == EXPR_NODE_V_ADDR) {
        return sql_pair_type_is_plvar(exprn);
    }
    return OG_FALSE;
}

static bool32 is_expr_tree_reorderable(expr_tree_t *exprtr)
{
    for (; exprtr != NULL; exprtr = exprtr->next) {
        if (!is_expr_node_reorderable(exprtr->root)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static inline bool32 check_cond_node(const cond_node_t *cmp_cond)
{
    if (cmp_cond->type != COND_NODE_COMPARE) {
        return OG_FALSE;
    }
    if (is_expr_tree_reorderable(cmp_cond->cmp->left) == OG_TRUE &&
        is_expr_tree_reorderable(cmp_cond->cmp->right) == OG_TRUE) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline bool32 is_simple_expr_tree(expr_tree_t *expr)
{
    if (expr->next != NULL) {
        return OG_FALSE;
    }

    if (expr->root->type == EXPR_NODE_COLUMN || expr->root->type == EXPR_NODE_CONST ||
        expr->root->type == EXPR_NODE_PARAM || expr->root->type == EXPR_NODE_CSR_PARAM ||
        expr->root->type == EXPR_NODE_RESERVED || expr->root->type == EXPR_NODE_TRANS_COLUMN) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

// Check if left side is a simple expression and right side is NULL or constant/bound parameter
static inline bool32 check_single_col(const cmp_node_t *cmp_node, const expr_tree_t *l_exprtr,
                                      const expr_tree_t *r_exprtr)
{
    if (l_exprtr == NULL) {
        return OG_FALSE;
    }
    if (!is_simple_expr_tree(cmp_node->left)) {
        return OG_FALSE;
    }
    return r_exprtr == NULL || sql_is_single_const_or_param(r_exprtr->root);
}

typedef struct {
    const cmp_node_t *cmp1;
    const cmp_node_t *cmp2;
    const expr_tree_t *l1;
    const expr_tree_t *l2;
    const expr_tree_t *r1;
    const expr_tree_t *r2;
} og_cmp_check_ctx_t;

static inline bool32 is_simple_join_cond(const cmp_node_t *cmp, const expr_tree_t *l, const expr_tree_t *r)
{
    return cmp->type == CMP_TYPE_EQUAL && l->root->type == EXPR_NODE_COLUMN &&
           r->root->type == EXPR_NODE_COLUMN;
}

static inline bool32 og_check_single_col_filter_cond(const og_cmp_check_ctx_t *ctx, int32 *result)
{
    if (check_single_col(ctx->cmp1, ctx->l1, ctx->r1)) {
        *result = 0;
        return OG_TRUE;
    }
    return check_single_col(ctx->cmp2, ctx->l2, ctx->r2) ? (*result = 1, OG_TRUE) : OG_FALSE;
}

// Equality condition with both sides as simple columns
static inline bool32 og_check_cmp_join_cond(const og_cmp_check_ctx_t *ctx, int32 *result)
{
    if (is_simple_join_cond(ctx->cmp1, ctx->l1, ctx->r1)) {
        *result = 0;
        return OG_TRUE;
    }
    return is_simple_join_cond(ctx->cmp2, ctx->l2, ctx->r2) ? (*result = 1, OG_TRUE) : OG_FALSE;
}

// create a new predicates node in list
static status_t og_init_pred_node(sql_stmt_t *statement, sql_query_t *qry, pred_node_t **node, galist_t *nodes)
{
    uint32 col_size = 0;
    sql_table_t *tbl = NULL;
    uint32 tab_count = qry->tables.count;

    if (cm_galist_new(nodes, sizeof(pred_node_t), (void **)node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cm_galist_init(&(*node)->cols, statement->session->stack, cm_stack_alloc);
    cm_galist_init(&(*node)->values, statement->session->stack, cm_stack_alloc);
    if (sql_stack_alloc(statement, tab_count * sizeof(int16 *), (void **)&(*node)->col_map) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 i = 0;
    while (i < tab_count) {
        tbl = (sql_table_t *)sql_array_get(&qry->tables, i);
        col_size = og_get_table_column_count(statement, tbl) * sizeof(int16);
        if (sql_stack_alloc(statement, col_size, (void **)&(*node)->col_map[i]) != OG_SUCCESS) {
            return OG_ERROR;
        }
        MEMS_RETURN_IFERR(memset_s((*node)->col_map[i], col_size, 0, col_size));
        i += 1;
    }

    return OG_SUCCESS;
}

static inline status_t og_pred_add_col(pred_node_t *pred, expr_tree_t *col_exprtr)
{
    int16 tab_id = EXPR_TAB(col_exprtr);
    int16 col_id = EXPR_COL(col_exprtr);
    OG_RETSUC_IFTRUE(pred->col_map[tab_id][col_id] == 1);

    pred->col_map[tab_id][col_id] = 1;
    if (cm_galist_insert(&pred->cols, col_exprtr) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[PRED_DLVR] Add column to predicate failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline bool32 check_pred_exist_col(pred_node_t *pred, expr_tree_t *col_exprtr)
{
    return pred->col_map[EXPR_TAB(col_exprtr)][EXPR_COL(col_exprtr)] == 1;
}

static bool32 og_pred_exist_range(sql_stmt_t *statement, pred_node_t *pred, plan_range_t *new_range)
{
    plan_range_t *range = NULL;
    if (new_range->type != RANGE_POINT) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i < pred->values.count; i++) {
        range = (plan_range_t *)cm_galist_get(&pred->values, i);
        if (range->type == RANGE_POINT && if_dlvr_border_equal(statement, &range->left, &new_range->left)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t og_pred_merge_two(sql_stmt_t *statement, pred_node_t *src_pred, pred_node_t *dst_pred,
    bool32 *is_conflict)
{
    plan_range_t *range = NULL;
    expr_tree_t *col_exprtr = NULL;

    for (uint32 i = 0; i < src_pred->values.count; i++) {
        range = (plan_range_t *)cm_galist_get(&src_pred->values, i);
        OG_RETURN_IFERR(og_pred_add_value(statement, dst_pred, range, is_conflict));
        if (*is_conflict) {
            return OG_SUCCESS;
        }
    }

    for (uint32 i = 0; i < src_pred->cols.count; i++) {
        col_exprtr = (expr_tree_t *)cm_galist_get(&src_pred->cols, i);
        OG_RETURN_IFERR(og_pred_add_col(dst_pred, col_exprtr));
    }

    return OG_SUCCESS;
}

typedef struct st_og_try_dlvr_preds_args {
    sql_stmt_t *statement;
    sql_query_t *qry;
    expr_tree_t *l_exprtr;
    expr_tree_t *r_exprtr;
    pred_node_t *dst_pred;
    galist_t *preds_lst;
    plan_range_t *new_range;
    uint32 start;
    bool32 *is_conflict;
} og_try_dlvr_preds_args_t;

static inline bool32 og_try_dlvr_need_merge(const og_try_dlvr_preds_args_t *args, pred_node_t *pred)
{
    if (check_pred_exist_col(pred, args->l_exprtr)) {
        return OG_TRUE;
    }
    if (args->r_exprtr != NULL && check_pred_exist_col(pred, args->r_exprtr)) {
        return OG_TRUE;
    }
    if (args->new_range != NULL && og_pred_exist_range(args->statement, pred, args->new_range)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static status_t og_try_dlvr_preds(const og_try_dlvr_preds_args_t *args)
{
    pred_node_t *pred = NULL;
    uint32 start = args->start;

    while (start < args->preds_lst->count) {
        pred = (pred_node_t *)cm_galist_get(args->preds_lst, start);
        if (og_try_dlvr_need_merge(args, pred)) {
            OG_RETURN_IFERR(og_pred_merge_two(args->statement, pred, args->dst_pred, args->is_conflict));
            if (*args->is_conflict) {
                return OG_SUCCESS;
            }
            cm_galist_delete(args->preds_lst, start);
            continue;
        }
        start++;
    }
    return OG_SUCCESS;
}

static inline bool32 check_col_is_array(expr_node_t *col_exprn)
{
    var_column_t *var_col = &(col_exprn->value.v_col);
    return var_col->is_array || VAR_COL_IS_ARRAY_ELEMENT(var_col);
}

static status_t og_collect_join_preds(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cmp_cond,
    dlvr_info_t *dlvr_info, bool32 *is_conflict)
{
    galist_t *preds_lst = &dlvr_info->pred_nodes;
    expr_tree_t *l_exprtr = cmp_cond->cmp->left;
    expr_tree_t *r_exprtr = cmp_cond->cmp->right;
    pred_node_t *pred = NULL;

    if (!var_datatype_is_compatible(TREE_DATATYPE(cmp_cond->cmp->left), TREE_DATATYPE(cmp_cond->cmp->right))) {
        return cm_galist_insert(&dlvr_info->graft_nodes, cmp_cond);
    }

    if (check_col_is_array(l_exprtr->root) || check_col_is_array(r_exprtr->root)) {
        return cm_galist_insert(&dlvr_info->graft_nodes, cmp_cond);
    }
    // t1.a = t1.a  =>  t1.a IS NOT NULL
    if (EXPR_TAB(l_exprtr) == EXPR_TAB(r_exprtr) && EXPR_COL(l_exprtr) == EXPR_COL(r_exprtr)) {
        cmp_cond->cmp->type = CMP_TYPE_IS_NOT_NULL;
        cmp_cond->cmp->right = NULL;
        return cm_galist_insert(&dlvr_info->graft_nodes, cmp_cond);
    }
    /*
    If the current condition can be merged into the current node, then this condition may cause all
    the subsequent nodes to be merged. Therefore, after inserting the current condition into the
    current node, it will iterate through the conditions in the subsequent nodes and attempt to merge them.
    */
    for (uint32 i = 0; i < preds_lst->count; ++i) {
        pred = (pred_node_t *)cm_galist_get(preds_lst, i);
        if (check_pred_exist_col(pred, l_exprtr) || check_pred_exist_col(pred, r_exprtr)) {
            OG_RETURN_IFERR(og_pred_add_col(pred, l_exprtr));
            OG_RETURN_IFERR(og_pred_add_col(pred, r_exprtr));
            og_try_dlvr_preds_args_t args = {
                statement, qry, l_exprtr, r_exprtr,
                pred, preds_lst,
                NULL, i + 1, is_conflict
            };
            return og_try_dlvr_preds(&args);
        }
    }
    // add new pred node
    pred = NULL;
    OG_RETURN_IFERR(og_init_pred_node(statement, qry, &pred, preds_lst));
    OG_RETURN_IFERR(og_pred_add_col(pred, l_exprtr));
    return og_pred_add_col(pred, r_exprtr);
}

static bool32 check_filter_preds_datatype(og_type_t col_type, og_type_t val_type)
{
    if (OG_IS_UNKNOWN_TYPE(val_type)) {
        return OG_TRUE;
    }

    if (var_datatype_is_compatible(col_type, val_type)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static status_t check_is_filter_cond_can_dlvr(sql_stmt_t *statement, expr_tree_t *col_exprtr, expr_tree_t *val_exprtr,
                                              bool32 *can_dlvr)
{
    // a[1] = 1 and a[2] = 2 will generate confilict,so we can't deliver array column
    if (check_col_is_array(col_exprtr->root)) {
        *can_dlvr = OG_FALSE;
        return OG_SUCCESS;
    }
    if (!check_filter_preds_datatype(TREE_DATATYPE(col_exprtr), TREE_DATATYPE(val_exprtr))) {
        *can_dlvr = OG_FALSE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(expr_tree_is_dlvr_value(statement, val_exprtr, can_dlvr));
    return OG_SUCCESS;
}

typedef struct st_og_add_filter_on_preds_args {
    sql_stmt_t *statement;
    sql_query_t *qry;
    galist_t *preds_lst;
    expr_tree_t *col_exprtr;
    plan_range_t *new_range;
    bool32 *need_new_pred;
    bool32 *is_conflict;
} og_add_filter_on_preds_args_t;

static inline void og_get_pred_exist_flags(const og_add_filter_on_preds_args_t *args, pred_node_t *pred,
                                          bool32 *is_col_exist, bool32 *is_range_exist)
{
    *is_col_exist = check_pred_exist_col(pred, args->col_exprtr);
    *is_range_exist = og_pred_exist_range(args->statement, pred, args->new_range);
}

static status_t og_add_filter_on_preds(const og_add_filter_on_preds_args_t *args)
{
    pred_node_t *pred = NULL;
    bool32 is_merge = OG_FALSE;
    bool32 is_col_exist;
    bool32 is_range_exist;
    for (uint32 i = 0; i < args->preds_lst->count; ++i) {
        pred = (pred_node_t *)cm_galist_get(args->preds_lst, i);
        og_get_pred_exist_flags(args, pred, &is_col_exist, &is_range_exist);
        // current cmp_cond already exist in pred_node, do nothing
        if (is_col_exist && is_range_exist) {
            return OG_SUCCESS;
        } else if (is_col_exist) {
            is_merge = OG_TRUE;
            OG_RETURN_IFERR(og_pred_add_value(args->statement, pred, args->new_range, args->is_conflict));
            if (*args->is_conflict) {
                return OG_SUCCESS;
            }
            // have repeat pull a = c and a = 1 and b = c , c is ancestor column
            OG_RETURN_IFERR(og_dlvr_pull_ancestor_conds(
                args->statement, args->qry, pred, args->new_range, args->is_conflict));
            if (*args->is_conflict) {
                return OG_SUCCESS;
            }
        } else if (is_range_exist) {
            is_merge = OG_TRUE;
            OG_RETURN_IFERR(og_pred_add_col(pred, args->col_exprtr));
        }
        if (is_merge) {
            og_try_dlvr_preds_args_t try_args = {
                args->statement, args->qry, args->col_exprtr, NULL,
                pred, args->preds_lst,
                args->new_range, i + 1, args->is_conflict
            };
            OG_RETURN_IFERR(og_try_dlvr_preds(&try_args));
            return OG_SUCCESS;
        }
    }
    *args->need_new_pred = OG_TRUE;
    return OG_SUCCESS;
}

// filter condition
static status_t og_collect_filter_preds(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cmp_cond,
    dlvr_info_t *dlvr_info, bool32 *is_conflict)
{
    galist_t *preds_lst = &dlvr_info->pred_nodes;
    expr_tree_t *col_exprtr = NULL;
    expr_tree_t *val_exprtr = NULL;
    plan_range_t *new_range = NULL;
    cmp_type_t cmp_type = cmp_cond->cmp->type;
    og_get_value_col_from_cmp(cmp_cond->cmp, &cmp_type, &col_exprtr, &val_exprtr);

    bool32 can_dlvr = OG_TRUE;
    OG_RETURN_IFERR(check_is_filter_cond_can_dlvr(statement, col_exprtr, val_exprtr, &can_dlvr));
    if (!can_dlvr) {
        return cm_galist_insert(&dlvr_info->graft_nodes, cmp_cond);
    }

    OG_RETURN_IFERR(
        og_dlvr_make_range(statement, TREE_DATATYPE(col_exprtr), cmp_type, val_exprtr, &new_range));
    bool32 need_new_pred = OG_FALSE;
    og_add_filter_on_preds_args_t args = {
        statement, qry, preds_lst,
        col_exprtr, new_range,
        &need_new_pred, is_conflict
    };
    OG_RETURN_IFERR(og_add_filter_on_preds(&args));
    // add new pred node
    if (!need_new_pred) {
        return OG_SUCCESS;
    }
    pred_node_t *pred = NULL;
    OG_RETURN_IFERR(og_init_pred_node(statement, qry, &pred, preds_lst));
    OG_RETURN_IFERR(cm_galist_insert(&pred->values, new_range));
    OG_RETURN_IFERR(og_pred_add_col(pred, col_exprtr));

    return og_dlvr_pull_ancestor_conds(statement, qry, pred, new_range, is_conflict);
}

static bool32 is_support_dlvr_cmp_node(sql_query_t *qry, cmp_node_t *cmp_cond)
{
    cols_used_t col_used_l;
    cols_used_t col_used_r;
    if (cmp_cond->left == NULL || cmp_cond->right == NULL) {
        return OG_FALSE;
    }
    // left and right nodes both have ancestor column
    if (!IS_LOCAL_COLUMN(cmp_cond->left) && !IS_LOCAL_COLUMN(cmp_cond->right)) {
        return OG_FALSE;
    }

    // a = b and a LIKE "%f" x=> b = LIKE "%f"
    if ((IS_LOCAL_COLUMN(cmp_cond->left) && TREE_DATATYPE(cmp_cond->left) == OG_TYPE_CHAR) ||
        (IS_LOCAL_COLUMN(cmp_cond->right) && TREE_DATATYPE(cmp_cond->right) == OG_TYPE_CHAR)) {
        return OG_FALSE;
    }

    if (has_semi_in_cmp_node(qry, cmp_cond)) {
        return OG_FALSE;
    }
    init_cols_used(&col_used_l);
    init_cols_used(&col_used_r);
    sql_collect_cols_in_expr_tree(cmp_cond->left, &col_used_l);
    sql_collect_cols_in_expr_tree(cmp_cond->right, &col_used_r);
    // subselect can't be deliver
    if (HAS_SUBSLCT(&col_used_l) || HAS_SUBSLCT(&col_used_r)) {
        return OG_FALSE;
    }

    return cmp_cond->type == CMP_TYPE_EQUAL;
}

static status_t og_collect_preds_in_cmp(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cmp_cond,
    dlvr_info_t *dlvr_info, bool32 *is_conflict)
{
    if (!is_support_dlvr_cmp_node(qry, cmp_cond->cmp)) {
        return cm_galist_insert(&dlvr_info->graft_nodes, cmp_cond);
    }
    // at least one expr is LOCAL_COLUMN
    if (IS_LOCAL_COLUMN(cmp_cond->cmp->left) && IS_LOCAL_COLUMN(cmp_cond->cmp->right)) {
        OG_RETSUC_IFTRUE(dlvr_info->dlvr_mode == DLVR_FILTER_COND);
        return og_collect_join_preds(statement, qry, cmp_cond, dlvr_info, is_conflict);
    } else {
        OG_RETSUC_IFTRUE(dlvr_info->dlvr_mode == DLVR_JOIN_COND);
        return og_collect_filter_preds(statement, qry, cmp_cond, dlvr_info, is_conflict);
    }

    return OG_SUCCESS;
}

static status_t og_get_pred_dlvr_info(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond,
    dlvr_info_t *dlvr_info, bool32 *is_conflict)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));

    if (cond->type == COND_NODE_AND) {
        OG_RETURN_IFERR(og_get_pred_dlvr_info(statement, qry, cond->left, dlvr_info, is_conflict));
        // if current cmp_cond is conflict means whole condition is FALSE.
        if (*is_conflict) {
            return OG_SUCCESS;
        }
        return og_get_pred_dlvr_info(statement, qry, cond->right, dlvr_info, is_conflict);
    }

    if (cond->type == COND_NODE_OR) {
        return cm_galist_insert(&dlvr_info->graft_nodes, cond);
    }
    
    if (cond->type == COND_NODE_COMPARE) {
        return og_collect_preds_in_cmp(statement, qry, cond, dlvr_info, is_conflict);
    }
    
    return OG_SUCCESS;
}

static status_t og_preds_rebuild_cond_tree(sql_stmt_t *statement, sql_query_t *qry, cond_tree_t *cmp_cond,
                                    dlvr_info_t *dlvr_info)
{
    galist_t *preds_lst = &dlvr_info->pred_nodes;
    galist_t *graft_lst = &dlvr_info->graft_nodes;
    pred_node_t *pred = NULL;
    cond_node_t *node = NULL;

    if (preds_lst->count == 0) {
        return OG_SUCCESS;
    }
    cmp_cond->root = NULL;
    // rebuild cmp_cond tree
    for (uint32 i = 0; i < preds_lst->count; i++) {
        pred = (pred_node_t *)cm_galist_get(preds_lst, i);
        OG_RETURN_IFERR(og_pred_rebuild_conds(statement, cmp_cond, pred));
    }
    // graft to current tree
    for (uint32 i = 0; i < graft_lst->count; ++i) {
        node = (cond_node_t *)cm_galist_get(graft_lst, i);
        OG_RETURN_IFERR(sql_add_cond_node(cmp_cond, node));
    }
    return OG_SUCCESS;
}

static inline void og_init_dlvr_info(sql_stmt_t *statement, dlvr_info_t *dlvr_info, dlvr_mode_t mode)
{
    cm_galist_init(&dlvr_info->pred_nodes, statement->session->stack, cm_stack_alloc);
    cm_galist_init(&dlvr_info->graft_nodes, statement->session->stack, cm_stack_alloc);
    dlvr_info->dlvr_mode = mode;
    return;
}

static status_t og_add_filter_cond_on_join_cond(sql_stmt_t *statement, cond_tree_t *dst_tree, galist_t *filter_preds)
{
    pred_node_t *pred = NULL;
    for (uint32 i = 0; i < filter_preds->count; i++) {
        pred = (pred_node_t *)cm_galist_get(filter_preds, i);
        OG_RETURN_IFERR(og_pred_rebuild_filter_conds(statement, dst_tree, pred));
    }
    return OG_SUCCESS;
}

typedef struct st_og_generate_dlvr_info_args {
    sql_stmt_t *statement;
    sql_query_t *query;
    expr_tree_t *col;
    galist_t *values;
    dlvr_info_t *join_info;
    galist_t *dlvr_info;
} og_generate_dlvr_info_args_t;

static pred_node_t *og_find_pred_by_col(galist_t *preds_lst, expr_tree_t *col)
{
    pred_node_t *pred = NULL;
    for (uint32 i = 0; i < preds_lst->count; i++) {
        pred = (pred_node_t *)cm_galist_get(preds_lst, i);
        if (check_pred_exist_col(pred, col)) {
            return pred;
        }
    }
    return NULL;
}

static status_t og_generate_dlvr_info(const og_generate_dlvr_info_args_t *args)
{
    pred_node_t *filter_pred = og_find_pred_by_col(&args->join_info->pred_nodes, args->col);
    OG_RETSUC_IFTRUE(filter_pred == NULL);

    pred_node_t *pred = NULL;
    OG_RETURN_IFERR(og_init_pred_node(args->statement, args->query, &pred, args->dlvr_info));
    // only deliver the column not exist in filter condition
    uint32 j = 0;
    while (j < filter_pred->cols.count) {
        expr_tree_t *cur_col = (expr_tree_t *)cm_galist_get(&filter_pred->cols, j++);
        if (!is_same_col(cur_col, args->col)) {
            OG_RETURN_IFERR(og_pred_add_col(pred, cur_col));
        }
    }
    // add all value in pred
    uint32 k = 0;
    while (k < args->values->count) {
        plan_range_t *val = (plan_range_t *)cm_galist_get(args->values, k++);
        OG_RETURN_IFERR(cm_galist_insert(&pred->values, val));
    }

    return OG_SUCCESS;
}

static status_t og_dlvr_predicates_on_join_inter(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode)
{
    OG_RETSUC_IFTRUE(jnode->join_cond == NULL || qry->cond == NULL);
    dlvr_info_t filter_info;
    cond_tree_t *src_cond = NULL;
    pred_node_t *pred;
    bool32 is_conflict = OG_FALSE;

    OGSQL_SAVE_STACK(statement);
    og_init_dlvr_info(statement, &filter_info, DLVR_FILTER_COND);
    src_cond = qry->cond;
    OG_RETURN_IFERR(og_get_pred_dlvr_info(statement, qry, src_cond->root, &filter_info, &is_conflict));
    if (jnode->filter != NULL) {
        src_cond = jnode->filter;
        OG_RETURN_IFERR(og_get_pred_dlvr_info(statement, qry, src_cond->root, &filter_info, &is_conflict));
    }
    // if there has no filter, nothing could de delivered
    if (filter_info.pred_nodes.count == 0) {
        OGSQL_RESTORE_STACK(statement);
        return OG_SUCCESS;
    }

    dlvr_info_t join_info;  // collect all join col
    og_init_dlvr_info(statement, &join_info, DLVR_JOIN_COND);
    src_cond = jnode->join_cond;
    OG_RETURN_IFERR(og_get_pred_dlvr_info(statement, qry, src_cond->root, &join_info, &is_conflict));

    galist_t dlvr_info;  // final deliver info to generate filter condtion
    cm_galist_init(&dlvr_info, statement->session->stack, cm_stack_alloc);
    // move all connection filter condition in join pred
    for (uint32 i = 0; i < filter_info.pred_nodes.count; i++) {
        pred = (pred_node_t *)cm_galist_get(&filter_info.pred_nodes, i);
        if (pred->values.count == 0) {
            continue;
        }
        for (uint32 j = 0; j < pred->cols.count; j++) {
            expr_tree_t *col_exprtr = (expr_tree_t *)cm_galist_get(&pred->cols, j);
            og_generate_dlvr_info_args_t args = { statement, qry, col_exprtr, &pred->values, &join_info, &dlvr_info };
            OG_RETURN_IFERR(og_generate_dlvr_info(&args));
        }
    }

    OG_RETURN_IFERR(og_add_filter_cond_on_join_cond(statement, jnode->join_cond, &dlvr_info));

    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

status_t og_dlvr_predicates_on_join_iter(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t *jnode)
{
    if (!g_instance->sql.enable_pred_delivery) {
        OG_LOG_DEBUG_INF("_OPTIM_PRED_DELIVERY has been shutted");
        return OG_SUCCESS;
    }

    OG_RETSUC_IFTRUE(jnode->type == JOIN_TYPE_NONE);

    OG_RETURN_IFERR(og_dlvr_predicates_on_join_iter(statement, qry, jnode->left));
    OG_RETURN_IFERR(og_dlvr_predicates_on_join_iter(statement, qry, jnode->right));

    return og_dlvr_predicates_on_join_inter(statement, qry, jnode);
}

status_t og_transf_predicate_delivery(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!g_instance->sql.enable_pred_delivery) {
        OG_LOG_DEBUG_INF("_OPTIM_PRED_DELIVERY has been shutted");
        return OG_SUCCESS;
    }

    OG_LOG_DEBUG_INF("start predicates delivery.");
    dlvr_info_t dlvr_info;
    bool32 is_conflict = OG_FALSE;
    cond_tree_t *root_cond = qry->cond;
    // The CONNECT BY statement has a hierarchical qry relationship ,can't deliver
    if (root_cond == NULL || qry->connect_by_cond != NULL) {
        return OG_SUCCESS;
    }
    OGSQL_SAVE_STACK(statement);
    SET_NODE_STACK_CURR_QUERY(statement, qry);
    og_init_dlvr_info(statement, &dlvr_info, DLVR_ALL);
    OG_RETURN_IFERR(og_get_pred_dlvr_info(statement, qry, root_cond->root, &dlvr_info, &is_conflict));
    // all collected cmp_cond is AND, if has confilict condition means the whole tree is FALSE
    if (is_conflict) {
        OG_LOG_DEBUG_INF("current condition is confilict.line:%d, column:%d", qry->loc.line, qry->loc.column);
        root_cond->root->type = COND_NODE_FALSE;
        root_cond->rownum_upper = 0;
        SQL_RESTORE_NODE_STACK(statement);
        OGSQL_RESTORE_STACK(statement);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(og_preds_rebuild_cond_tree(statement, qry, root_cond, &dlvr_info));

    SQL_RESTORE_NODE_STACK(statement);
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
