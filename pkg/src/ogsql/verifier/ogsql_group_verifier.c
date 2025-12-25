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
 * ogsql_group_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/verifier/ogsql_group_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_select_verifier.h"
#include "srv_instance.h"
#include "ogsql_func.h"
#include "expr_parser.h"
#include "dml_parser.h"


#ifdef __cplusplus
extern "C" {
#endif


static status_t sql_match_group_node(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node);

status_t sql_match_group_expr(sql_stmt_t *stmt, sql_query_t *query, expr_tree_t *expr)
{
    while (expr != NULL) {
        if (sql_match_group_node(stmt, query, expr->root) != OG_SUCCESS) {
            return OG_ERROR;
        }
        expr = expr->next;
    }

    return OG_SUCCESS;
}

static inline status_t sql_match_group_cond_node(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *cond)
{
    if (sql_stack_safe(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cond == NULL) {
        return OG_SUCCESS;
    }

    switch (cond->type) {
        case COND_NODE_COMPARE:
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, cond->cmp->left));
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, cond->cmp->right));
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        default:
            OG_RETURN_IFERR(sql_match_group_cond_node(stmt, query, cond->left));
            OG_RETURN_IFERR(sql_match_group_cond_node(stmt, query, cond->right));
            break;
    }

    return OG_SUCCESS;
}

static status_t sql_match_group_node_by_winsort(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *winsort)
{
    sort_item_t *item = NULL;
    expr_tree_t *expr = NULL;
    expr_node_t *func_node = winsort->argument->root;

    if (winsort->win_args->group_exprs != NULL) {
        for (uint32 i = 0; i < winsort->win_args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(winsort->win_args->group_exprs, i);
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, expr));
        }
    }
    if (winsort->win_args->sort_items != NULL) {
        for (uint32 i = 0; i < winsort->win_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(winsort->win_args->sort_items, i);
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, item->expr));
        }
        if (winsort->win_args->windowing != NULL) {
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, winsort->win_args->windowing->l_expr));
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, winsort->win_args->windowing->r_expr));
        }
    }

    return sql_match_group_expr(stmt, query, func_node->argument);
}

static inline bool32 sql_group_expr_node_equal(sql_stmt_t *stmt, expr_node_t *node, expr_node_t *group_node)
{
    if (group_node->type != node->type) {
        return OG_FALSE;
    }

    switch (group_node->type) {
        case EXPR_NODE_COLUMN:
            if (VAR_ANCESTOR(&group_node->value) > 0) {
                return OG_FALSE;
            }
            return (bool32)(VAR_TAB(&group_node->value) == VAR_TAB(&node->value) &&
                VAR_COL(&group_node->value) == VAR_COL(&node->value));

        case EXPR_NODE_RESERVED:
            if (VALUE(uint32, &group_node->value) != RES_WORD_ROWID || ROWID_NODE_ANCESTOR(group_node) > 0 ||
                VALUE(uint32, &group_node->value) != VALUE(uint32, &node->value)) {
                return OG_FALSE;
            }
            return (bool32)(ROWID_NODE_TAB(group_node) == ROWID_NODE_TAB(node));

        default:
            return OG_FALSE;
    }
}

static inline status_t sql_find_in_parent_group_exprs(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    uint32 i;
    uint32 j;
    expr_tree_t *group_expr = NULL;
    group_set_t *group_set = NULL;

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            group_expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            if (sql_group_expr_node_equal(stmt, node, group_expr->root)) {
                return sql_set_group_expr_node(stmt, node, j, i, ANCESTOR_OF_NODE(node), NULL);
            }
        }
    }
    OG_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
    return OG_ERROR;
}

static inline status_t sql_match_group_parent_ref_columns(sql_stmt_t *stmt, sql_query_t *query, galist_t *ref_columns)
{
    expr_node_t *col = NULL;
    uint32 ref_count = ref_columns->count;

    for (uint32 i = 0; i < ref_count; i++) {
        col = (expr_node_t *)cm_galist_get(ref_columns, i);
        if (col->type == EXPR_NODE_GROUP) {
            continue;
        }
        OG_RETURN_IFERR(sql_find_in_parent_group_exprs(stmt, query, col));
    }
    return OG_SUCCESS;
}

static inline status_t sql_match_group_subselect(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    parent_ref_t *parent_ref = NULL;
    sql_select_t *select_ctx = NULL;
    select_ctx = (sql_select_t *)node->value.v_obj.ptr;

#ifdef OG_RAC_ING
    if (IS_SHARD && stmt->context->has_sharding_tab) {
        if (select_ctx->has_ancestor > 0) {
            OG_SRC_THROW_ERROR(node->loc, ERR_CAPABILITY_NOT_SUPPORT, "subquery contain group by column");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
#endif

    SET_NODE_STACK_CURR_QUERY(stmt, select_ctx->first_query);
    for (uint32 i = 0; i < select_ctx->parent_refs->count; i++) {
        parent_ref = (parent_ref_t *)cm_galist_get(select_ctx->parent_refs, i);
        OG_RETURN_IFERR(sql_match_group_parent_ref_columns(stmt, query, parent_ref->ref_columns));
    }
    SQL_RESTORE_NODE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t sql_match_node_in_group_sets(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, bool32 *matched)
{
    uint32 i;
    uint32 j;
    group_set_t *group_set = NULL;
    expr_tree_t *group_expr = NULL;

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            group_expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            if (NODE_IS_RES_DUMMY(group_expr->root)) {
                continue;
            }
            if (sql_expr_node_equal(stmt, node, group_expr->root, NULL)) {
                *matched = OG_TRUE;
                return sql_set_group_expr_node(stmt, node, j, i, 0, group_expr->root);
            }
        }
    }
    *matched = OG_FALSE;
    return OG_SUCCESS;
}

static status_t sql_match_group_grouping(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    bool32 matched = OG_FALSE;
    expr_tree_t *arg = node->argument;

    while (arg != NULL) {
        if (sql_match_node_in_group_sets(stmt, query, arg->root, &matched) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (!matched) {
            OG_SRC_THROW_ERROR(arg->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
            return OG_ERROR;
        }
        arg = arg->next;
        matched = OG_FALSE;
    }
    return OG_SUCCESS;
}

static status_t sql_match_group_func(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    sql_func_t *func = sql_get_func(&node->value.v_func);
    if (func->aggr_type != AGGR_TYPE_NONE) {
        return OG_SUCCESS;
    }

    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_GROUPING:
        case ID_FUNC_ITEM_GROUPING_ID:
            return sql_match_group_grouping(stmt, query, node);
        case ID_FUNC_ITEM_SYS_CONNECT_BY_PATH:
            OG_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                "sys_connect_by_path was not allowed in query containing group by clause");
            return OG_ERROR;
        case ID_FUNC_ITEM_IF:
        case ID_FUNC_ITEM_LNNVL:
            if (node->cond_arg != NULL) {
                OG_RETURN_IFERR(sql_match_group_cond_node(stmt, query, node->cond_arg->root));
            }
            // fall through
        default:
            break;
    }

    return sql_match_group_expr(stmt, query, node->argument);
}

static status_t sql_match_group_case(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    case_expr_t *case_expr = NULL;
    case_pair_t *pair = NULL;
    case_expr = (case_expr_t *)VALUE(pointer_t, &node->value);
    if (!case_expr->is_cond) {
        OG_RETURN_IFERR(sql_match_group_expr(stmt, query, case_expr->expr));
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, pair->when_expr));
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, pair->value));
        }
    } else {
        for (uint32 i = 0; i < case_expr->pairs.count; i++) {
            pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
            OG_RETURN_IFERR(sql_match_group_cond_node(stmt, query, pair->when_cond->root));
            OG_RETURN_IFERR(sql_match_group_expr(stmt, query, pair->value));
        }
    }
    return sql_match_group_expr(stmt, query, case_expr->default_expr);
}

bool32 sql_check_reserved_is_const(expr_node_t *node)
{
    switch (VALUE(uint32, &node->value)) {
        case RES_WORD_ROWNUM:
        case RES_WORD_ROWID:
        case RES_WORD_ROWSCN:
        case RES_WORD_LEVEL:
        case RES_WORD_CONNECT_BY_ISCYCLE:
        case RES_WORD_CONNECT_BY_ISLEAF:
        case RES_WORD_ROWNODEID:
            return OG_FALSE;
        default:
            return OG_TRUE;
    }
}

static status_t sql_match_group_reserved(expr_node_t *node)
{
    if (!sql_check_reserved_is_const(node)) {
        OG_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_match_group_column(expr_node_t *node)
{
    if (VAR_ANCESTOR(&node->value) > 0) {
        return OG_SUCCESS;
    }
    OG_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
    return OG_ERROR;
}

static status_t sql_match_group_node_by_node_type(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    // if modify this function, do modify sql_check_table_column_exists at the same time
    switch (node->type) {
        case EXPR_NODE_FUNC:
            return sql_match_group_func(stmt, query, node);
        case EXPR_NODE_USER_FUNC:
            return sql_match_group_expr(stmt, query, node->argument);
        case EXPR_NODE_SELECT:
            return sql_match_group_subselect(stmt, query, node);
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CONST:
        case EXPR_NODE_V_ADDR: // deal same as pl-variant
        case EXPR_NODE_USER_PROC:
        case EXPR_NODE_PROC:
        case EXPR_NODE_NEW_COL:
        case EXPR_NODE_OLD_COL:
        case EXPR_NODE_PL_ATTR:
            return OG_SUCCESS;
        case EXPR_NODE_RESERVED:
            return sql_match_group_reserved(node);
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            OG_RETURN_IFERR(sql_match_group_node(stmt, query, node->left));
            return sql_match_group_node(stmt, query, node->right);
        case EXPR_NODE_NEGATIVE:
            return sql_match_group_node(stmt, query, node->right);
        case EXPR_NODE_CASE:
            return sql_match_group_case(stmt, query, node);
        case EXPR_NODE_OVER:
            return sql_match_group_node_by_winsort(stmt, query, node);
        case EXPR_NODE_COLUMN:
            return sql_match_group_column(node);
        case EXPR_NODE_ARRAY:
            return sql_match_group_expr(stmt, query, node->argument);
        default:
            break;
    }

    OG_SRC_THROW_ERROR(node->loc, ERR_EXPR_NOT_IN_GROUP_LIST);
    return OG_ERROR;
}

static inline status_t sql_match_group_node(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    bool32 matched = OG_FALSE;
    if (node->type == EXPR_NODE_AGGR || NODE_IS_CONST(node) || node->type == EXPR_NODE_GROUP) {
        return OG_SUCCESS;
    }
    if (node->type == EXPR_NODE_COLUMN && NODE_ANCESTOR(node) > 0) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(sql_match_node_in_group_sets(stmt, query, node, &matched));
    if (!matched) {
        return sql_match_group_node_by_node_type(stmt, query, node);
    }
    return OG_SUCCESS;
}

static status_t sql_group_set_cmp_func(const void *str1, const void *str2, int32 *result)
{
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;
    group_set_t *group_set1 = (group_set_t *)str1;
    group_set_t *group_set2 = (group_set_t *)str2;

    if (group_set1->count != group_set2->count) {
        *result = (group_set1->count < group_set2->count) ? 1 : -1;
        return OG_SUCCESS;
    }
    for (uint32 i = 0; i < group_set1->items->count; i++) {
        expr1 = (expr_tree_t *)cm_galist_get(group_set1->items, i);
        expr2 = (expr_tree_t *)cm_galist_get(group_set2->items, i);
        // keep the dummy expr to the last
        if (NODE_IS_RES_DUMMY(expr1->root) && !NODE_IS_RES_DUMMY(expr2->root)) {
            *result = 1;
            return OG_SUCCESS;
        }
        if (!NODE_IS_RES_DUMMY(expr1->root) && NODE_IS_RES_DUMMY(expr2->root)) {
            *result = -1;
            return OG_SUCCESS;
        }
    }
    *result = 0;
    return OG_SUCCESS;
}

static inline bool32 sql_list_has_expr(sql_stmt_t *stmt, galist_t *items, expr_tree_t *expr)
{
    expr_tree_t *item = NULL;

    for (uint32 i = 0; i < items->count; i++) {
        item = (expr_tree_t *)cm_galist_get(items, i);
        if (sql_expr_node_equal(stmt, item->root, expr->root, NULL)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static inline status_t sql_create_dummy_expr(sql_stmt_t *stmt, expr_tree_t **null_expr)
{
    expr_node_t *node = NULL;
    OG_RETURN_IFERR(sql_create_expr(stmt, null_expr));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node));
    node->owner = (*null_expr);
    node->type = EXPR_NODE_RESERVED;
    node->datatype = OG_DATATYPE_OF_NULL;
    node->value.v_res.res_id = RES_WORD_DUMMY;
    (*null_expr)->root = node;
    return OG_SUCCESS;
}

static status_t sql_normalize_group_set(sql_stmt_t *stmt, galist_t *s_items, expr_tree_t *dummy_expr,
    group_set_t *group_set)
{
    uint32 i;
    galist_t *group_exprs = NULL;
    expr_tree_t *expr = NULL;

    OG_RETURN_IFERR(sql_create_list(stmt, &group_exprs));
    group_set->count = 0;

    for (i = 0; i < s_items->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(s_items, i);
        if (sql_list_has_expr(stmt, group_set->items, expr)) {
            OG_RETURN_IFERR(cm_galist_insert(group_exprs, expr));
            group_set->count++;
        } else {
            OG_RETURN_IFERR(cm_galist_insert(group_exprs, dummy_expr));
        }
    }
    group_set->items = group_exprs;
    return OG_SUCCESS;
}

status_t sql_normalize_group_sets(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i;
    uint32 j;
    expr_tree_t *expr = NULL;
    expr_tree_t *dummy = NULL;
    group_set_t *group_set = NULL;
    galist_t *full_items = NULL;

    OG_RETURN_IFERR(sql_create_dummy_expr(stmt, &dummy));

    OGSQL_SAVE_STACK(stmt);
    if (sql_push(stmt, sizeof(galist_t), (void **)&full_items) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    cm_galist_init(full_items, stmt, sql_stack_alloc);

    // gather full group exprs
    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        for (j = 0; j < group_set->items->count; j++) {
            expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            // skip bind parameter
            if (expr->root->type == EXPR_NODE_PARAM) {
                continue;
            }
            if (sql_list_has_expr(stmt, full_items, expr)) {
                continue;
            }
            if (cm_galist_insert(full_items, expr) != OG_SUCCESS) {
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
        }
    }

    // insert dummy expr
    if (full_items->count == 0 && cm_galist_insert(full_items, dummy) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    // normalize all group sets
    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        if (sql_normalize_group_set(stmt, full_items, dummy, group_set) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
    }

    OGSQL_RESTORE_STACK(stmt);
    (void)cm_galist_sort(query->group_sets, sql_group_set_cmp_func);
    return OG_SUCCESS;
}

status_t sql_verify_query_group(sql_verifier_t *verif, sql_query_t *query)
{
    uint32 i;
    uint32 j;
    expr_tree_t *expr = NULL;
    group_set_t *group_set = NULL;

    if (query->group_sets->count == 0) {
        return OG_SUCCESS;
    }

    verif->excl_flags = SQL_GROUP_BY_EXCL;
    verif->tables = &query->tables;
    verif->aggrs = query->aggrs;
    verif->cntdis_columns = query->cntdis_columns;
    verif->incl_flags = 0;
    verif->curr_query = query;

    for (i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);

        for (j = 0; j < group_set->items->count; j++) {
            expr = (expr_tree_t *)cm_galist_get(group_set->items, j);
            verif->has_ddm_col = OG_FALSE;
            if (sql_verify_expr(verif, expr) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (verif->has_ddm_col == OG_TRUE) {
                if (expr->root->type != EXPR_NODE_COLUMN) {
                    OG_THROW_ERROR(ERR_INVALID_OPERATION,
                        ", ddm col expr is not allowed in group clause, only support single col");
                    return OG_ERROR;
                }
                verif->has_ddm_col = OG_FALSE;
            }
            expr->root->has_verified = OG_TRUE;
        }
    }

    if (query->group_sets->count > 1) {
#ifdef OG_RAC_ING
        // not support multiple grouping sets in OG_RAC_ING
        if (IS_COORDINATOR) {
            OG_THROW_ERROR(ERR_COORD_NOT_SUPPORT, "GROUPING SETS/CUBE/ROLLUP");
            return OG_ERROR;
        }
#endif // OG_RAC_ING
    }
    return sql_normalize_group_sets(verif->stmt, query);
}

static status_t sql_check_having_compare(sql_stmt_t *stmt, sql_query_t *query, cmp_node_t *node)
{
    if (node->left != NULL) {
        OG_RETURN_IFERR(sql_match_group_expr(stmt, query, node->left));
    }

    if (node->right != NULL) {
        OG_RETURN_IFERR(sql_match_group_expr(stmt, query, node->right));
    }

    return OG_SUCCESS;
}

static status_t sql_check_having_cond_node(sql_stmt_t *stmt, sql_query_t *query, cond_node_t *node)
{
    if (sql_stack_safe(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }
    switch (node->type) {
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        case COND_NODE_COMPARE:
            OG_RETURN_IFERR(sql_check_having_compare(stmt, query, node->cmp));
            break;
        default:
            OG_RETURN_IFERR(sql_check_having_cond_node(stmt, query, node->left));
            OG_RETURN_IFERR(sql_check_having_cond_node(stmt, query, node->right));
            break;
    }

    return OG_SUCCESS;
}

status_t sql_verify_query_having(sql_verifier_t *verif, sql_query_t *query)
{
    bool32 allowed_aggr = OG_FALSE;

    if (query->having_cond == NULL) {
        return OG_SUCCESS;
    }

    verif->tables = &query->tables;
    verif->aggrs = query->aggrs;
    verif->cntdis_columns = query->cntdis_columns;
    verif->curr_query = query;
    verif->excl_flags = SQL_HAVING_EXCL;
    verif->incl_flags = 0;
    verif->aggr_flags = SQL_GEN_AGGR_FROM_HAVING;

    /* ok:  select count(f1) from t1 having max(f1)=1
           ok:  select f1 from t1 group by f1 having max(f1)=1
           nok: select f1 from t1 having max(f1)=1
           ok:  select 1  from t1 having max(f1)=1
        */
    allowed_aggr = ((query->aggrs->count > 0 || query->group_sets->count > 0) || !verif->has_excl_const);
    if (!allowed_aggr) {
        verif->excl_flags |= SQL_EXCL_AGGR;
    }

    OG_RETURN_IFERR(sql_verify_cond(verif, query->having_cond));
    OG_RETURN_IFERR(sql_check_having_cond_node(verif->stmt, query, query->having_cond->root));

    verif->aggr_flags = 0;
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
