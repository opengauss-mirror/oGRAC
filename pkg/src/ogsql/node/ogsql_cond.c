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
 * ogsql_cond.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/node/ogsql_cond.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "ogsql_cond.h"
#include "ogsql_select.h"
#include "ogsql_proj.h"
#include "ogsql_mtrl.h"
#include "cm_regexp.h"
#include "expr_parser.h"
#include "json/ogsql_json.h"
#include "srv_instance.h"
#include "ogsql_func.h"
#include "ogsql_cbo_cost.h"

#ifdef __cplusplus
extern "C" {
#endif

static cond_result_t g_and_true_table[COND_END][COND_END] = {
    { COND_FALSE, COND_FALSE,   COND_FALSE },
    { COND_FALSE, COND_TRUE,    COND_UNKNOWN },
    { COND_FALSE, COND_UNKNOWN, COND_UNKNOWN }
};

static cond_result_t g_or_true_table[COND_END][COND_END] = {
    { COND_FALSE,   COND_TRUE, COND_UNKNOWN },
    { COND_TRUE,    COND_TRUE, COND_TRUE },
    { COND_UNKNOWN, COND_TRUE, COND_UNKNOWN }
};

static cond_result_t g_not_true_table[COND_END] = {
    COND_TRUE, COND_FALSE, COND_UNKNOWN
};

static bool32 sql_exist_multi_table_in_expr_tree(expr_tree_t *expr, uint32 *last_table_id);
static bool32 sql_exist_multi_table_in_expr_node(expr_node_t *expr_node, uint32 *last_table_id);
static bool32 sql_exist_multi_table_in_expr_node(expr_node_t *expr_node, uint32 *last_table_id)
{
    var_column_t *var_column = NULL;
    switch (expr_node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(sql_exist_multi_table_in_expr_node(expr_node->left, last_table_id) ||
                sql_exist_multi_table_in_expr_node(expr_node->right, last_table_id));

        case EXPR_NODE_NEGATIVE:
            return sql_exist_multi_table_in_expr_node(expr_node->right, last_table_id);

        case EXPR_NODE_JOIN:
            return OG_TRUE;

        case EXPR_NODE_COLUMN:
            var_column = VALUE_PTR(var_column_t, &expr_node->value);

            if (*last_table_id == (uint32)-1) {
                *last_table_id = var_column->tab;
                return OG_FALSE;
            }

            return *last_table_id != var_column->tab;

        case EXPR_NODE_FUNC:
            return sql_exist_multi_table_in_expr_tree(expr_node->argument, last_table_id);

        default:
            return OG_FALSE;
    }
}

static bool32 sql_exist_multi_table_in_expr_tree(expr_tree_t *expr, uint32 *last_table_id)
{
    expr_tree_t *curr_expr = expr;

    // The expr_tree may be a expr tree list
    while (curr_expr != NULL) {
        if (sql_exist_multi_table_in_expr_node(curr_expr->root, last_table_id)) {
            return OG_TRUE;
        }

        curr_expr = curr_expr->next;
    }

    return OG_FALSE;
}

static bool32 sql_cols_is_join_cond(cols_used_t *cols_used)
{
    if (HAS_SUBSLCT(cols_used)) {
        return OG_FALSE;
    }

    if (HAS_DIFF_TABS(cols_used, SELF_IDX)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static bool32 sql_cond_is_join_cond(cond_node_t *cond_node)
{
    cols_used_t used_cols;
    init_cols_used(&used_cols);

    sql_collect_cols_in_cond(cond_node, &used_cols);
    return sql_cols_is_join_cond(&used_cols);
}

/* split filter cond for connect by */
status_t sql_split_filter_cond(sql_stmt_t *stmt, cond_node_t *src, cond_tree_t **dst_tree)
{
    cond_node_t *new_node = NULL;

    switch (src->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_split_filter_cond(stmt, src->left, dst_tree));
            OG_RETURN_IFERR(sql_split_filter_cond(stmt, src->right, dst_tree));
            try_eval_logic_and(src);
            break;
        case COND_NODE_COMPARE:
            if (sql_cond_is_join_cond(src)) {
                break;
            }
            /* fall-through */
        case COND_NODE_OR:
            OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&new_node));
            (*new_node) = (*src);
            if (*dst_tree == NULL) {
                OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, dst_tree));
            }
            OG_RETURN_IFERR(sql_add_cond_node(*dst_tree, new_node));
            src->type = COND_NODE_TRUE;
            break;

        case COND_NODE_FALSE:
            if (*dst_tree == NULL) {
                OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, dst_tree));
            }
            OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)&new_node));
            new_node->type = COND_NODE_FALSE;
            OG_RETURN_IFERR(sql_add_cond_node(*dst_tree, new_node));
            break;

        case COND_NODE_TRUE:
        default:
            break;
    }
    return OG_SUCCESS;
}

status_t sql_create_cond_tree(sql_context_t *context, cond_tree_t **cond)
{
    CM_POINTER2(context, cond);

    if (sql_alloc_mem(context, sizeof(cond_tree_t), (void **)cond) != OG_SUCCESS) {
        return OG_ERROR;
    }

    sql_init_cond_tree(context, *cond, sql_alloc_mem);
    return OG_SUCCESS;
}

typedef struct st_parent_node {
    uint32 depth;
    cond_node_t *cond_node;
    cond_node_t *parent_node;
} insert_node_t;

static status_t sql_get_insert_pos(cond_node_t *cond_node, cond_node_t *parent_cond, cond_node_t *node,
    insert_node_t *insert_node, uint32 temp_depth, bool32 *is_exist)
{
    uint32 depth = temp_depth;
    if (cond_node == node || *is_exist) {
        *is_exist = OG_TRUE;
        return OG_SUCCESS;
    }

    session_t *sess = (session_t *)knl_get_curr_sess();
    OG_RETURN_IFERR(sql_stack_safe(sess->current_stmt));
    depth++;
    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_get_insert_pos(cond_node->left, cond_node, node, insert_node, depth, is_exist));
            OG_RETURN_IFERR(sql_get_insert_pos(cond_node->right, cond_node, node, insert_node, depth, is_exist));
            break;

        case COND_NODE_OR:
            break;
        case COND_NODE_COMPARE:
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            if (depth < insert_node->depth || insert_node->cond_node == NULL) {
                insert_node->cond_node = cond_node;
                insert_node->depth = depth;
                insert_node->parent_node = parent_cond;
            }
            break;
        default:
            break;
    }

    return OG_SUCCESS;
}

/* add_left : new node added to cond_tree_t left child or right child. */
status_t sql_add_cond_node_core(cond_tree_t *orign_cond, cond_node_t *node, bool8 add_left)
{
    insert_node_t insert_node;
    cond_node_t *cond_node = NULL;
    uint32 depth = 0;
    bool32 is_exist = OG_FALSE;

    if (orign_cond->root == NULL || orign_cond->root->type == COND_NODE_TRUE) {
        orign_cond->root = node;
        return OG_SUCCESS;
    }

    if (orign_cond->root->type == COND_NODE_FALSE || node->type == COND_NODE_TRUE) {
        return OG_SUCCESS;
    }

    if (node->type == COND_NODE_FALSE) {
        orign_cond->rownum_upper = 0;
        orign_cond->root->type = COND_NODE_FALSE;
        return OG_SUCCESS;
    }

    insert_node.cond_node = NULL;
    insert_node.depth = 0;
    insert_node.parent_node = NULL;
    OG_RETURN_IFERR(sql_get_insert_pos(orign_cond->root, NULL, node, &insert_node, depth, &is_exist));
    if (is_exist) {
        // do nothing if new node to add already in cond_tree_t
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(orign_cond->alloc_func(orign_cond->owner, sizeof(cond_node_t), (void **)&cond_node));
    MEMS_RETURN_IFERR(memset_sp(cond_node, sizeof(cond_node_t), 0, sizeof(cond_node_t)));

    cond_node->type = COND_NODE_AND;
    if (insert_node.cond_node == NULL || insert_node.parent_node == NULL) {
        // no COND_NODE_NAD node, need split from root node
        CONSTRUCT_COND_TREE(cond_node, add_left, orign_cond->root, node);
        orign_cond->root = cond_node;
    } else {
        CONSTRUCT_COND_TREE(cond_node, add_left, insert_node.cond_node, node);
        if (insert_node.parent_node->left == insert_node.cond_node) {
            insert_node.parent_node->left = cond_node;
        } else {
            insert_node.parent_node->right = cond_node;
        }
    }
    return OG_SUCCESS;
}

status_t sql_add_cond_node_left(cond_tree_t *orign_cond, cond_node_t *node)
{
    return sql_add_cond_node_core(orign_cond, node, OG_TRUE);
}

status_t sql_add_cond_node(cond_tree_t *orign_cond, cond_node_t *node)
{
    return sql_add_cond_node_core(orign_cond, node, OG_FALSE);
}

status_t sql_get_cond_node_pos(cond_node_t *root_cond, cmp_node_t *cmp_node, cond_node_t **node_pos)
{
    switch (root_cond->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            OG_RETURN_IFERR(sql_get_cond_node_pos(root_cond->left, cmp_node, node_pos));
            if (*node_pos != NULL) {
                return OG_SUCCESS;
            }
            return sql_get_cond_node_pos(root_cond->right, cmp_node, node_pos);

        case COND_NODE_COMPARE:
            if (root_cond->cmp == cmp_node) {
                *node_pos = root_cond;
                return OG_SUCCESS;
            }
            break;

        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
        default:
            break;
    }
    return OG_SUCCESS;
}

status_t sql_clone_cmp_node(void *ogx, cmp_node_t *src, cmp_node_t **dst, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        *dst = NULL;
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(alloc_mem_func(ogx, sizeof(cmp_node_t), (void **)dst));
    **dst = *src;
    OG_RETURN_IFERR(sql_clone_expr_tree(ogx, src->left, &(*dst)->left, alloc_mem_func));
    OG_RETURN_IFERR(sql_clone_expr_tree(ogx, src->right, &(*dst)->right, alloc_mem_func));
    return OG_SUCCESS;
}

status_t sql_clone_cond_tree(void *ogx, cond_tree_t *src, cond_tree_t **dst, ga_alloc_func_t alloc_mem_func)
{
    if (src == NULL) {
        *dst = NULL;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(alloc_mem_func(ogx, sizeof(cond_tree_t), (void **)dst));
    (*dst)->owner = ogx;
    (*dst)->alloc_func = alloc_mem_func;
    (*dst)->loc = src->loc;
    (*dst)->rownum_upper = src->rownum_upper;
    OG_RETURN_IFERR(sql_clone_cond_node(ogx, src->root, &(*dst)->root, alloc_mem_func));
    return OG_SUCCESS;
}

status_t sql_clone_cond_node(void *ogx, cond_node_t *src, cond_node_t **dst, ga_alloc_func_t alloc_mem_func)
{
    cond_node_t *new_node = NULL;

    OG_RETURN_IFERR(alloc_mem_func(ogx, sizeof(cond_node_t), (void **)&new_node));
    new_node->type = src->type;
    switch (new_node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            OG_RETURN_IFERR(sql_clone_cond_node(ogx, src->left, &new_node->left, alloc_mem_func));
            OG_RETURN_IFERR(sql_clone_cond_node(ogx, src->right, &new_node->right, alloc_mem_func));
            break;
        case COND_NODE_COMPARE:
            OG_RETURN_IFERR(sql_clone_cmp_node(ogx, src->cmp, &new_node->cmp, alloc_mem_func));
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            *new_node = *src;
            break;
        default:
            *dst = NULL;
            return OG_ERROR;
    }
    *dst = new_node;
    return OG_SUCCESS;
}

// deep clone
status_t sql_merge_cond_tree(cond_tree_t *orign_cond, cond_node_t *from_node)
{
    cond_node_t *cond_node = NULL;

    OG_RETURN_IFERR(sql_clone_cond_node(orign_cond->owner, from_node, &cond_node, orign_cond->alloc_func));
    return sql_add_cond_node(orign_cond, cond_node);
}

// shallow clone
status_t sql_merge_cond_tree_shallow(cond_tree_t *orign_cond, cond_node_t *from_node)
{
    cond_node_t *cond_node = NULL;

    OG_RETURN_IFERR(orign_cond->alloc_func(orign_cond->owner, sizeof(cond_node_t), (void **)&cond_node));
    *cond_node = *from_node;
    return sql_add_cond_node(orign_cond, cond_node);
}

status_t sql_union_cond_node(sql_context_t *context, cond_tree_t **dst, cond_node_t *from_node)
{
    cond_node_t *node = NULL;

    if (*dst == NULL) {
        OG_RETURN_IFERR(sql_create_cond_tree(context, dst));
        (*dst)->root = from_node;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_alloc_mem(context, sizeof(cond_node_t), (void **)&node));
    node->type = COND_NODE_OR;
    node->left = (*dst)->root;
    node->right = from_node;
    (*dst)->root = node;
    return OG_SUCCESS;
}
#ifdef OG_RAC_ING

static bool32 sql_ancestor_tables_in_cmp_node(sql_array_t *tables, cmp_node_t *cmp_node, bool32 use_remote_id)
{
    bool32 l_exist_col = OG_FALSE;
    bool32 r_exist_col = OG_FALSE;

    if (cmp_node->left != NULL) {
        if (sql_expr_tree_in_tab_list(tables, cmp_node->left, use_remote_id, &l_exist_col)) {
            return OG_TRUE;
        }
    }

    if (cmp_node->right != NULL) {
        return sql_expr_tree_in_tab_list(tables, cmp_node->right, use_remote_id, &r_exist_col);
    }

    return OG_FALSE;
}

bool32 sql_ancestor_tables_in_cond_node(sql_array_t *tables, cond_node_t *cond_node)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            return sql_ancestor_tables_in_cond_node(tables, cond_node->left) ||
                sql_ancestor_tables_in_cond_node(tables, cond_node->right);

        case COND_NODE_COMPARE:
            return sql_ancestor_tables_in_cmp_node(tables, cond_node->cmp, OG_FALSE);
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
        default:
            return OG_FALSE;
    }
}

static bool32 shd_sql_check_where_cmp_expr_has_subquery(expr_node_t *expr)
{
    switch (expr->type) {
        case EXPR_NODE_SELECT:
            return OG_TRUE;

        default:
            return OG_FALSE;
    }
}

static bool32 shd_sql_check_where_cmp_cond_expr_has_subquery(cmp_node_t *cmp_node)
{
    switch (cmp_node->type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
            return (bool32)((shd_sql_check_where_cmp_expr_has_subquery(cmp_node->left->root) ||
                shd_sql_check_where_cmp_expr_has_subquery(cmp_node->right->root)));

        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
            return (shd_sql_check_where_cmp_expr_has_subquery(cmp_node->right->root));

        default:
            return OG_FALSE;
    }
}

bool32 sql_check_where_cond_has_subquery(cond_node_t *cond)
{
    switch (cond->type) {
        case COND_NODE_AND:
            return (bool32)(
                (sql_check_where_cond_has_subquery(cond->left) || sql_check_where_cond_has_subquery(cond->right)));

        case COND_NODE_OR:
            return OG_FALSE;

        case COND_NODE_COMPARE:
            return (shd_sql_check_where_cmp_cond_expr_has_subquery(cond->cmp));

        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            return OG_FALSE;

        default:
            return OG_FALSE;
    }
}

#endif

bool32 sql_is_join_node(cond_node_t *cond_node, uint32 table1, uint32 table2)
{
    cols_used_t l_cols_used;
    cols_used_t r_cols_used;
    uint32 l_tab_id;
    uint32 r_tab_id;

    cmp_node_t *cmp_node = cond_node->cmp;
    if (cmp_node->type > CMP_TYPE_NOT_IN) {
        return OG_FALSE;
    }

    init_cols_used(&l_cols_used);
    init_cols_used(&r_cols_used);
    sql_collect_cols_in_expr_tree(cmp_node->left, &l_cols_used);
    sql_collect_cols_in_expr_tree(cmp_node->right, &r_cols_used);

    // Both sides of cmp node must have self columns
    if (!HAS_SELF_COLS(l_cols_used.flags) || !HAS_SELF_COLS(r_cols_used.flags)) {
        return OG_FALSE;
    }

    // left(right) can only have the same table
    if (HAS_DIFF_TABS(&l_cols_used, SELF_IDX) || HAS_DIFF_TABS(&r_cols_used, SELF_IDX)) {
        return OG_FALSE;
    }

    expr_node_t *l_col = sql_any_self_col_node(&l_cols_used);
    expr_node_t *r_col = sql_any_self_col_node(&r_cols_used);
    l_tab_id = TAB_OF_NODE(l_col);
    r_tab_id = TAB_OF_NODE(r_col);
    if ((table1 == l_tab_id && table2 == r_tab_id) || (table1 == r_tab_id && table2 == l_tab_id)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 sql_is_join_cond(cond_node_t *cond_node, uint32 table1, uint32 table2)
{
    bool32 has_join_cond = OG_FALSE;

    switch (cond_node->type) {
        case COND_NODE_OR:
            OG_RETVALUE_IFTRUE(!sql_is_join_cond(cond_node->left, table1, table2), OG_FALSE);
            OG_RETVALUE_IFTRUE(!sql_is_join_cond(cond_node->right, table1, table2), OG_FALSE);
            break;
        case COND_NODE_AND:
            has_join_cond =
                sql_is_join_cond(cond_node->left, table1, table2) || sql_is_join_cond(cond_node->right, table1, table2);
            if (!has_join_cond) {
                return OG_FALSE;
            }
            break;
        case COND_NODE_COMPARE:
            if (!sql_is_join_node(cond_node, table1, table2)) {
                return OG_FALSE;
            }
            break;
        default:
            break;
    }
    return OG_TRUE;
}

// get join condition in side a query
status_t sql_extract_join_from_cond(cond_node_t *cond_node, uint32 table1, uint32 table2, galist_t *join_nodes,
    bool32 *has_join_cond)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_extract_join_from_cond(cond_node->left, table1, table2, join_nodes, has_join_cond));
            return sql_extract_join_from_cond(cond_node->right, table1, table2, join_nodes, has_join_cond);

        case COND_NODE_OR:
            if (sql_is_join_cond(cond_node, table1, table2)) {
                *has_join_cond = OG_TRUE;
            }
            break;

        case COND_NODE_COMPARE:
            if (sql_is_join_node(cond_node, table1, table2)) {
                *has_join_cond = OG_TRUE;
                return cm_galist_insert(join_nodes, cond_node->cmp);
            }
            break;

        default:
            break;
    }
    return OG_SUCCESS;
}

bool32 sql_cond_node_exist_table(cond_node_t *cond_node, uint32 table_id)
{
    cols_used_t used_cols;
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;
    expr_node_t *col = NULL;

    init_cols_used(&used_cols);
    sql_collect_cols_in_cond(cond_node, &used_cols);

    cols_que = &used_cols.cols_que[SELF_IDX];
    curr = biqueue_first(cols_que);
    end = biqueue_end(cols_que);

    while (curr != end) {
        col = OBJECT_OF(expr_node_t, curr);
        if (table_id == TAB_OF_NODE(col)) {
            return OG_TRUE;
        }
        curr = curr->next;
    }
    return OG_FALSE;
}

static inline bool32 sql_cmp_is_var_eq_var(cmp_node_t *cmp)
{
    return (cmp->type == CMP_TYPE_EQUAL && cmp->left->root->type == EXPR_NODE_COLUMN &&
            cmp->right->root->type == EXPR_NODE_COLUMN);
}

join_tbl_bitmap_t sql_collect_table_ids_in_expr(expr_tree_t *expr, galist_t *outer_rels_list, uint8 *check)
{
    cols_used_t used_cols;
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;
    expr_node_t *col = NULL;
    join_tbl_bitmap_t table_ids;

    init_cols_used(&used_cols);
    sql_bitmap_init(&table_ids);
    sql_collect_cols_in_expr_tree(expr, &used_cols);

    if (check != NULL) {
        if (outer_rels_list == NULL) {
            *check |= COND_HAS_OUTER_RELS;
        } else if (if_table_in_outer_rels_list(&used_cols, PARENT_IDX, outer_rels_list) &&
            if_table_in_outer_rels_list(&used_cols, ANCESTOR_IDX, outer_rels_list)) {
            *check |= COND_HAS_OUTER_RELS;
        }
    }

    if (HAS_ROWNUM(&used_cols)) {
        *check |= COND_HAS_ROWNUM;
    }

    if (HAS_DYNAMIC_SUBSLCT(&used_cols)) {
        *check |= COND_HAS_DYNAMIC_SUBSEL;
    }

    cols_que = &used_cols.cols_que[SELF_IDX];
    curr = biqueue_first(cols_que);
    end = biqueue_end(cols_que);

    while (curr != end) {
        col = OBJECT_OF(expr_node_t, curr);
        uint32 table_id = TAB_OF_NODE(col);
        sql_bitmap_add_member(table_id, &table_ids);
        curr = curr->next;
    }

    return table_ids;
}

join_tbl_bitmap_t sql_collect_table_ids_in_cond(cond_node_t *cond_node, galist_t *outer_rels_list, uint8 *check)
{
    cols_used_t used_cols;
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;
    expr_node_t *col = NULL;
    join_tbl_bitmap_t table_ids;

    init_cols_used(&used_cols);
    sql_bitmap_init(&table_ids);
    sql_collect_cols_in_cond(cond_node, &used_cols);

    if (check != NULL) {
        if (outer_rels_list == NULL) {
            *check |= COND_HAS_OUTER_RELS;
        } else if (if_table_in_outer_rels_list(&used_cols, PARENT_IDX, outer_rels_list) &&
            if_table_in_outer_rels_list(&used_cols, ANCESTOR_IDX, outer_rels_list)) {
            *check |= COND_HAS_OUTER_RELS;
        }
    }

    if (HAS_DYNAMIC_SUBSLCT(&used_cols)) {
        *check |= COND_HAS_DYNAMIC_SUBSEL;
    }

    cols_que = &used_cols.cols_que[SELF_IDX];
    curr = biqueue_first(cols_que);
    end = biqueue_end(cols_que);

    while (curr != end) {
        col = OBJECT_OF(expr_node_t, curr);
        uint32 table_id = TAB_OF_NODE(col);
        sql_bitmap_add_member(table_id, &table_ids);
        curr = curr->next;
    }

    return table_ids;
}

void sql_convert_match_result(cmp_type_t cmp_type, int32 cmp_result, bool32 *res)
{
    switch (cmp_type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_IN:
        case CMP_TYPE_EQUAL_ALL:
            *res = (cmp_result == 0);
            break;

        case CMP_TYPE_GREAT:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_GREAT_ALL:
            *res = (cmp_result > 0);
            break;

        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ALL:
            *res = (cmp_result >= 0);
            break;

        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_ALL:
            *res = (cmp_result < 0);
            break;

        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_LESS_EQUAL_ALL:
            *res = (cmp_result <= 0);
            break;

        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_NOT_IN:
        case CMP_TYPE_NOT_EQUAL_ALL:
            *res = (cmp_result != 0);
            break;

        default:
            *res = OG_TRUE;
            break;
    }
}

status_t sql_exec_expr_list(sql_stmt_t *stmt, expr_tree_t *list, uint32 count, variant_t *vars, bool32 *pending,
    expr_tree_t **last)
{
    expr_tree_t *expr = list;

    for (uint32 i = 0; i < count; i++) {
        if (expr == NULL) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "no enough variants for comparision");
            return OG_ERROR;
        }

        SQL_EXEC_CMP_OPERAND_EX(expr, &vars[i], pending, pending, stmt);

        expr = expr->next;
    }

    if (last != NULL) {
        *last = expr;
    }

    return OG_SUCCESS;
}

static status_t sql_match_variant_list(sql_stmt_t *stmt, cmp_node_t *node, cmp_type_t type, variant_t *list1,
    variant_t *list2, uint32 count, cond_result_t *cond_ret)
{
    bool32 exist_null = OG_FALSE;
    int32 cmp_result;

    for (uint32 i = 0; i < count; i++) {
        if (list1[i].is_null || list2[i].is_null) {
            if (node != NULL && node->type == CMP_TYPE_NOT_IN && !stmt->is_check) {
                continue;
            }
            exist_null = OG_TRUE;
            *cond_ret = COND_UNKNOWN;
            continue;
        }

        /* expr1 == expr11 and expr2 == expr21 and ... */
        if (sql_compare_variant(stmt, &list1[i], &list2[i], &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        sql_convert_match_result(type, cmp_result, (bool32 *)cond_ret);
        if (*cond_ret == COND_FALSE) {
            return OG_SUCCESS;
        }
    }

    if (exist_null) {
        *cond_ret = COND_UNKNOWN;
    } else {
        *cond_ret = COND_TRUE;
    }

    return OG_SUCCESS;
}

static status_t sql_match_in_list(sql_stmt_t *stmt, cmp_node_t *node, cmp_type_t type, bool32 *pending,
    cond_result_t *cond_ret)
{
    variant_t *l_vars = NULL; // vars of the left IN list
    variant_t *r_vars = NULL; // vars of the right IN list
    expr_tree_t *right_exprs = NULL;
    uint32 len;
    bool32 exist_unknown = OG_FALSE;

    len = sql_expr_list_len(node->left);
    // evaluate the list at the left of IN
    if (sql_push(stmt, len * sizeof(variant_t), (void **)&l_vars) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_exec_expr_list(stmt, node->left, len, l_vars, pending, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (*pending) {
        return OG_SUCCESS;
    }

    if (len == 1 && l_vars[0].is_null) {
        /* expr in (expr1, expr2, expr3, ...)
          is equal expr == expr1 or expr == expr2 or expr == expr3 ...
          if expr is null no need to calc the whole cond, the result must be COND_UNKNOWN
        */
        *cond_ret = COND_UNKNOWN;
        return OG_SUCCESS;
    }

    // evaluate the list at the right of IN
    if (sql_push(stmt, len * sizeof(variant_t), (void **)&r_vars) != OG_SUCCESS) {
        return OG_ERROR;
    }

    right_exprs = node->right;
    while (right_exprs != NULL) {
        if (sql_exec_expr_list(stmt, right_exprs, len, r_vars, pending, &right_exprs) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (*pending) {
            return OG_SUCCESS;
        }

        if (sql_match_variant_list(stmt, node, type, l_vars, r_vars, len, cond_ret) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (*cond_ret == COND_UNKNOWN) {
            exist_unknown = OG_TRUE;
        }
        // according g_or_true_table, if first expr node is true then the cond is true,
        // no need to calc another expr node
        if (*cond_ret == COND_TRUE) {
            return OG_SUCCESS;
        }
    }

    if (exist_unknown) {
        *cond_ret = COND_UNKNOWN;
    } else {
        *cond_ret = COND_FALSE;
    }

    return OG_SUCCESS;
}

status_t sql_match_pivot_list(sql_stmt_t *stmt, expr_tree_t *for_expr, expr_tree_t *in_expr, int32 *index)
{
    uint32 len = sql_expr_list_len(for_expr);
    uint32 group_count = sql_expr_list_len(in_expr) / len;
    variant_t *l_vars = NULL;
    variant_t *r_vars = NULL;
    expr_tree_t *in_exprs = NULL;
    bool32 pending = OG_FALSE;
    cond_result_t cond_ret;
    status_t status = OG_ERROR;

    OGSQL_SAVE_STACK(stmt);
    *index = -1;
    do {
        OG_BREAK_IF_ERROR(sql_push(stmt, len * sizeof(variant_t), (void **)&l_vars));
        OG_BREAK_IF_ERROR(sql_exec_expr_list(stmt, for_expr, len, l_vars, &pending, NULL));
        if (len == 1 && l_vars[0].is_null) {
            OGSQL_POP(stmt);
            return OG_SUCCESS;
        }
        OG_BREAK_IF_ERROR(sql_push(stmt, len * sizeof(variant_t), (void **)&r_vars));
        in_exprs = in_expr;
        for (int32 i = 0; i < (int32)group_count; i++) {
            if (sql_exec_expr_list(stmt, in_exprs, len, r_vars, &pending, &in_exprs) != OG_SUCCESS) {
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
            if (sql_match_variant_list(stmt, NULL, CMP_TYPE_IN, l_vars, r_vars, len, &cond_ret) != OG_SUCCESS) {
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
            if (cond_ret == COND_TRUE) {
                *index = i;
                break;
            }
        }

        status = OG_SUCCESS;
    } while (0);

    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static inline bool32 variant_list_has_null(variant_t *vars, uint32 key_count, bool32 *is_null)
{
    bool32 has_null = OG_FALSE;

    if (is_null != NULL) {
        *is_null = OG_TRUE;
    }

    for (uint32 i = 0; i < key_count; ++i) {
        if (vars[i].is_null) {
            has_null = OG_TRUE;
        } else if (is_null != NULL) {
            *is_null = OG_FALSE;
        }

        if (has_null && (is_null == NULL || !(*is_null))) {
            return OG_TRUE;
        }
    }
    return has_null;
}

static inline status_t sql_make_mtrl_in_row(sql_stmt_t *stmt, row_assist_t *ra, og_type_t *types, variant_t *r_vars)
{
    for (uint32 i = 0; i < ra->head->column_count; ++i) {
        variant_t *v = &r_vars[i];
        if (!v->is_null && types[i] == OG_TYPE_CHAR && OG_IS_STRING_TYPE(v->type)) {
            cm_rtrim_text(&v->v_text);
        }
        OG_RETURN_IFERR(sql_put_row_value(stmt, NULL, ra, types[i], v));
    }
    return OG_SUCCESS;
}

static status_t sql_check_hash_key_types(hash_view_ctx_t *hash_ctx, variant_t *r_vars, og_type_t *r_types,
    bool32 is_first)
{
    og_type_t cmp_type;

    for (uint32 i = 0; i < hash_ctx->key_count; ++i) {
        if (is_first) {
            r_types[i] = r_vars[i].type;
        } else if (r_types[i] != r_vars[i].type) {
            hash_ctx->unavailable = OG_TRUE;
            break;
        }
        if (hash_ctx->types[i] == r_vars[i].type) {
            continue;
        }
        if (is_first) {
            cmp_type = get_cmp_datatype(hash_ctx->types[i], r_vars[i].type);
            if (cmp_type == INVALID_CMP_DATATYPE) {
                OG_SET_ERROR_MISMATCH(hash_ctx->types[i], r_vars[i].type);
                return OG_ERROR;
            }
            hash_ctx->types[i] = cmp_type;
        }
    }
    return OG_SUCCESS;
}

static status_t build_hash_table_from_list(sql_stmt_t *stmt, hash_view_ctx_t *hash_ctx, expr_tree_t *right_exprs)
{
    status_t status = OG_ERROR;
    row_assist_t ra;
    char *row_buf = NULL;
    uint32 row_size;
    variant_t *r_vars = NULL;
    bool32 pending = OG_FALSE;
    bool32 found = OG_FALSE;
    bool32 is_null = OG_FALSE;
    bool32 is_first = OG_TRUE;
    og_type_t r_types[SQL_MAX_HASH_OPTM_KEYS];
    uint32 key_count = hash_ctx->key_count;

    OGSQL_SAVE_STACK(stmt);
    while (right_exprs != NULL) {
        OG_BREAK_IF_ERROR(sql_push(stmt, key_count * sizeof(variant_t), (void **)&r_vars));
        OG_BREAK_IF_ERROR(sql_exec_expr_list(stmt, right_exprs, key_count, r_vars, &pending, &right_exprs));

        if (!variant_list_has_null(r_vars, key_count, &is_null)) {
            OG_BREAK_IF_ERROR(sql_check_hash_key_types(hash_ctx, r_vars, r_types, is_first));
            is_first = OG_FALSE;
            if (hash_ctx->unavailable) {
                vm_hash_segment_deinit(&hash_ctx->hash_seg);
                status = OG_SUCCESS;
                break;
            }
            OG_BREAK_IF_ERROR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&row_buf));
            row_init(&ra, row_buf, OG_MAX_ROW_SIZE, key_count);
            OG_BREAK_IF_ERROR(sql_make_mtrl_in_row(stmt, &ra, hash_ctx->types, r_vars));
            row_size = ra.head->size;
        } else {
            row_buf = NULL;
            row_size = 0;
        }

        if (is_null) {
            hash_ctx->has_null_key = OG_TRUE;
        }

        OG_BREAK_IF_ERROR(vm_hash_table_insert2(&found, &hash_ctx->hash_seg, &hash_ctx->hash_table, row_buf, row_size));

        OGSQL_RESTORE_STACK(stmt);

        if (right_exprs == NULL) {
            status = OG_SUCCESS;
            break;
        }
    }

    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t prepare_hash_join_keys(sql_cursor_t *cursor, expr_tree_t *l_expr, galist_t *columns,
    galist_t *local_keys, galist_t *peer_keys)
{
    expr_tree_t *r_expr = NULL;
    rs_column_t *rs_col = NULL;
    cm_galist_init(local_keys, &cursor->vmc, vmc_alloc_mem);
    cm_galist_init(peer_keys, &cursor->vmc, vmc_alloc_mem);

    for (uint32 i = 0; i < columns->count; ++i) {
        rs_col = (rs_column_t *)cm_galist_get(columns, i);
        if (rs_col->type == RS_COL_COLUMN) {
            OG_RETURN_IFERR(vmc_alloc_mem(&cursor->vmc, sizeof(expr_tree_t), (void **)&r_expr));
            OG_RETURN_IFERR(vmc_alloc_mem(&cursor->vmc, sizeof(expr_node_t), (void **)&(r_expr->root)));
            r_expr->root->value.v_col = rs_col->v_col;
            r_expr->root->typmod = rs_col->typmod;
            r_expr->root->type = EXPR_NODE_COLUMN;
        } else {
            r_expr = rs_col->expr;
        }
        OG_RETURN_IFERR(cm_galist_insert(local_keys, r_expr));
        OG_RETURN_IFERR(cm_galist_insert(peer_keys, l_expr));
        l_expr = l_expr->next;
    }
    return OG_SUCCESS;
}

static status_t build_hash_table_from_subselect(sql_stmt_t *stmt, hash_view_ctx_t *hash_ctx, cmp_node_t *node)
{
    status_t status = OG_ERROR;
    bool32 has_null = OG_FALSE;
    bool32 found = OG_FALSE;
    row_assist_t ra;
    char *buf = NULL;
    galist_t *columns = NULL;
    uint32 size;
    galist_t local_keys;
    galist_t peer_keys;
    sql_cursor_t *cursor = NULL;
    sql_cursor_t *parent_cur = OGSQL_CURR_CURSOR(stmt);
    var_object_t *v_obj = EXPR_VALUE_PTR(var_object_t, node->right);
    hash_ctx->empty_table = OG_TRUE;

    OG_RETURN_IFERR(sql_get_ssa_cursor(parent_cur, (sql_select_t *)v_obj->ptr, v_obj->id, &cursor));
    stmt = parent_cur->stmt;
    OG_RETURN_IFERR(sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next));
    OG_RETURN_IFERR(prepare_hash_join_keys(cursor, node->left, cursor->columns, &local_keys, &peer_keys));
    columns = cursor->columns;

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    OG_RETURN_IFERR(
        sql_get_hash_key_types(stmt, cursor->select_ctx->first_query, &local_keys, &peer_keys, hash_ctx->types));

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));
    OGSQL_SAVE_STACK(stmt);
    for (;;) {
        OG_BREAK_IF_ERROR(sql_fetch_cursor(stmt, cursor, cursor->plan->select_p.next, &cursor->eof));

        if (cursor->eof) {
            status = OG_SUCCESS;
            break;
        }
        if (columns != cursor->columns) {
            columns = cursor->columns;
            OG_BREAK_IF_ERROR(prepare_hash_join_keys(cursor, node->left, cursor->columns, &local_keys, &peer_keys));
        }

        OG_BREAK_IF_ERROR(sql_make_hash_key(stmt, &ra, buf, &local_keys, hash_ctx->types, &has_null));

        if (!has_null) {
            size = ra.head->size;
            OG_BREAK_IF_ERROR(vm_hash_table_insert2(&found, &hash_ctx->hash_seg, &hash_ctx->hash_table, buf, size));
        } else {
            hash_ctx->has_null_key = OG_TRUE;
            OG_BREAK_IF_ERROR(vm_hash_table_insert2(&found, &hash_ctx->hash_seg, &hash_ctx->hash_table, NULL, 0));
        }
        hash_ctx->empty_table = OG_FALSE;
        OGSQL_RESTORE_STACK(stmt);
    }
    OGSQL_RESTORE_STACK(stmt);
    SQL_CURSOR_POP(stmt);
    OGSQL_POP(stmt);
    return status;
}

static status_t sql_build_in_hash_table(sql_stmt_t *stmt, cmp_node_t *node, uint32 key_count, hash_view_ctx_t *hash_ctx)
{
    status_t status;
    hash_ctx->key_count = key_count;
    hash_ctx->has_null_key = OG_FALSE;
    hash_ctx->unavailable = OG_FALSE;
    hash_ctx->empty_table = OG_FALSE;
    expr_tree_t *left_expr = node->left;

    for (uint32 i = 0; i < key_count; ++i) {
        OG_RETURN_IFERR(sql_get_expr_datatype(stmt, left_expr, &hash_ctx->types[i]));
        left_expr = left_expr->next;
    }

    vm_hash_segment_init(&stmt->session->knl_session, stmt->mtrl.pool, &hash_ctx->hash_seg, PMA_POOL, HASH_PAGES_HOLD,
        HASH_AREA_SIZE);
    if (vm_hash_table_alloc(&hash_ctx->hash_table, &hash_ctx->hash_seg, 0) != OG_SUCCESS) {
        vm_hash_segment_deinit(&hash_ctx->hash_seg);
        return OG_ERROR;
    }
    if (vm_hash_table_init(&hash_ctx->hash_seg, &hash_ctx->hash_table, NULL, NULL, NULL) != OG_SUCCESS) {
        vm_hash_segment_deinit(&hash_ctx->hash_seg);
        return OG_ERROR;
    }

    OGSQL_SAVE_STACK(stmt);
    if (TREE_EXPR_TYPE(node->right) == EXPR_NODE_SELECT) {
        status = build_hash_table_from_subselect(stmt, hash_ctx, node);
    } else {
        status = build_hash_table_from_list(stmt, hash_ctx, node->right);
    }
    OGSQL_RESTORE_STACK(stmt);

    if (status != OG_SUCCESS) {
        vm_hash_segment_deinit(&hash_ctx->hash_seg);
        return OG_ERROR;
    }

    hash_ctx->initialized = OG_TRUE;
    return OG_SUCCESS;
}

static inline status_t sql_init_hash_optm_data(sql_stmt_t *stmt)
{
    uint32 buf_size = sizeof(hash_view_ctx_t) * stmt->context->hash_optm_count;
    OG_RETURN_IFERR(vmc_alloc(&stmt->vmc, buf_size, (void **)&stmt->hash_views));
    hash_view_ctx_t *hvs = (hash_view_ctx_t *)stmt->hash_views;
    for (uint32 i = 0; i < stmt->context->hash_optm_count; ++i) {
        hvs[i].initialized = OG_FALSE;
        hvs[i].unavailable = OG_FALSE;
    }
    stmt->resource_inuse = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_match_in_hash_table(sql_stmt_t *stmt, cmp_node_t *node, cmp_type_t cmp_type, bool32 *pending,
    cond_result_t *result)
{
    char *row_buf = NULL;
    row_assist_t ra;
    hash_scan_assist_t sa;
    hash_view_ctx_t *hash_ctx = NULL;
    bool32 right_eof = OG_FALSE;
    row_head_t *row_head = NULL;
    variant_t *l_vars = NULL;
    uint32 key_count = sql_expr_list_len(node->left);

    if (stmt->hash_views == NULL) {
        OG_RETURN_IFERR(sql_init_hash_optm_data(stmt));
    }

    hash_ctx = &((hash_view_ctx_t *)stmt->hash_views)[NODE_OPTMZ_IDX(node->left->root)];
    if (!hash_ctx->initialized) {
        OG_RETURN_IFERR(sql_build_in_hash_table(stmt, node, key_count, hash_ctx));
    }

    // if hash table is unavailable, use normal in match method
    if (hash_ctx->unavailable) {
        return sql_match_in_list(stmt, node, cmp_type, pending, result);
    }

    // evaluate the list at the left of IN
    OG_RETURN_IFERR(sql_push(stmt, key_count * sizeof(variant_t), (void **)&l_vars));

    OG_RETURN_IFERR(sql_exec_expr_list(stmt, node->left, key_count, l_vars, pending, NULL));
    if (*pending) {
        return OG_SUCCESS;
    }

    if (node->type == CMP_TYPE_NOT_IN && hash_ctx->has_null_key) {
        // not in (null) ==> false
        *result = OG_TRUE;
        return OG_SUCCESS;
    }

    if (node->type == CMP_TYPE_NOT_IN && hash_ctx->empty_table) {
        // not in (empty) ==> true
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    // check null key
    if (variant_list_has_null(l_vars, key_count, NULL)) {
        // null in compare always means false/unknown
        *result = (node->type == CMP_TYPE_NOT_IN) ? OG_TRUE : OG_FALSE;
        return OG_SUCCESS;
    }

    // make hash key
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&row_buf));
    row_init(&ra, row_buf, OG_MAX_ROW_SIZE, key_count);
    OG_RETURN_IFERR(sql_make_mtrl_in_row(stmt, &ra, hash_ctx->types, l_vars));

    row_head = (row_head_t *)row_buf;
    sa.scan_mode = HASH_KEY_SCAN;
    sa.buf = row_buf;
    sa.size = row_head->size;
    OG_RETURN_IFERR(vm_hash_table_probe(&right_eof, &hash_ctx->hash_seg, &hash_ctx->hash_table, &sa));

    *result = (right_eof ? OG_FALSE : OG_TRUE);
    return OG_SUCCESS;
}

static status_t sql_matched_with_rs(sql_stmt_t *stmt, cmp_node_t *node, cmp_type_t type, sql_cursor_t *cursor,
    variant_t *vars, uint32 count, cond_result_t *cond_ret)
{
    bool32 exist_null = OG_FALSE;
    int32 cmp_result;
    variant_t rs_var;

    for (uint32 i = 0; i < count; i++) {
        if (sql_get_rs_value(stmt, cursor, i, &rs_var) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (vars[i].is_null || rs_var.is_null) {
            if (node->type == CMP_TYPE_NOT_IN && !stmt->is_check) {
                continue;
            }

            exist_null = OG_TRUE;
            *cond_ret = COND_UNKNOWN;
            continue;
        }

        if (OG_IS_LOB_TYPE(rs_var.type)) {
            OG_RETURN_IFERR(sql_get_lob_value(stmt, &rs_var));
        }
        if (sql_compare_variant(stmt, &vars[i], &rs_var, &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        sql_convert_match_result(type, cmp_result, (bool32 *)cond_ret);

        if (*cond_ret == COND_FALSE) {
            return OG_SUCCESS;
        }
    }

    if (exist_null) {
        *cond_ret = COND_UNKNOWN;
    } else {
        *cond_ret = COND_TRUE;
    }

    return OG_SUCCESS;
}

static status_t sql_match_in_subselect(sql_stmt_t *stmt, cmp_node_t *node, cmp_type_t type, bool32 *pending,
    cond_result_t *result)
{
    sql_cursor_t *cursor = NULL;
    sql_cursor_t *parent_cur = NULL;
    variant_t *left_vars = NULL;
    var_object_t *v_obj = EXPR_VALUE_PTR(var_object_t, node->right);
    uint32 count;
    status_t status;
    sql_select_t *select_ctx = (sql_select_t *)v_obj->ptr;
    bool32 exist_unknown = OG_FALSE;

    *result = COND_FALSE;
    count = sql_expr_list_len(node->left);

    OG_RETURN_IFERR(sql_push(stmt, count * sizeof(variant_t), (void **)&left_vars));

    OG_RETURN_IFERR(sql_exec_expr_list(stmt, node->left, count, left_vars, pending, NULL));

    if (*pending) {
        return OG_SUCCESS;
    }

    if (count == 1 && left_vars[0].is_null) {
        /* expr in (select COL from xxx)
          is equal expr == expr1 or expr == expr2 or expr == expr3 ...
          if expr is null no need to calc the whole cond, the result must be COND_UNKNOWN, but not in or != all cond
          if the ssa cursor eof is true, the result is true
        */
        *result = COND_UNKNOWN;
        if (node->type != CMP_TYPE_NOT_IN) {
            return OG_SUCCESS;
        }
    }

    parent_cur = OGSQL_CURR_CURSOR(stmt);
    OG_RETURN_IFERR(sql_check_sub_select_pending(parent_cur, select_ctx, pending));
    if (*pending) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_get_ssa_cursor(parent_cur, select_ctx, v_obj->id, &cursor));
    stmt = parent_cur->stmt;
    OG_RETURN_IFERR(sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next));

    if (cursor->columns->count != count) {
        OG_THROW_ERROR((cursor->columns->count > count) ? ERR_TOO_MANY_VALUES : ERR_NOT_ENOUGH_VALUES);
        return OG_ERROR;
    }

    status = OG_SUCCESS;
    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    for (;;) {
        OGSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, cursor, cursor->plan->select_p.next, &cursor->eof) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }

        if (cursor->eof) {
            OGSQL_RESTORE_STACK(stmt);
            break;
        }

        /* not in or != all cond, if the ssa cursor eof is FALSE, the result is COND_UNKNOWN */
        if (*result == COND_UNKNOWN && node->type == CMP_TYPE_NOT_IN) {
            OGSQL_RESTORE_STACK(stmt);
            SQL_CURSOR_POP(stmt);
            sql_close_cursor(stmt, cursor);
            return OG_SUCCESS;
        }

        if (sql_matched_with_rs(stmt, node, type, cursor, left_vars, count, result) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }
        OGSQL_RESTORE_STACK(stmt);

        if (*result == COND_TRUE) {
            SQL_CURSOR_POP(stmt);
            sql_close_cursor(stmt, cursor);
            return OG_SUCCESS;
        }

        if (*result == COND_UNKNOWN) {
            exist_unknown = OG_TRUE;
        }
    }
    SQL_CURSOR_POP(stmt);

    sql_close_cursor(stmt, cursor);

    if (exist_unknown) {
        *result = COND_UNKNOWN;
    } else {
        *result = COND_FALSE;
    }

    return status;
}

static status_t sql_match_in(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *cond_ret)
{
    cmp_type_t type = node->type;

    if (type == CMP_TYPE_NOT_IN) {
        type = CMP_TYPE_IN;
    }

    /* (expr1, expr2, ...) in (select col1, col2, ... from table)  */
    if (NODE_OPTIMIZE_MODE(node->left->root) == OPTMZ_AS_HASH_TABLE) {
        OG_RETURN_IFERR(sql_match_in_hash_table(stmt, node, type, pending, cond_ret));
    } else if (node->right->root->type == EXPR_NODE_SELECT && node->right->next == NULL) {
        OG_RETURN_IFERR(sql_match_in_subselect(stmt, node, type, pending, cond_ret));
    } else {
        OG_RETURN_IFERR(sql_match_in_list(stmt, node, type, pending, cond_ret));
    }

    if (*pending) {
        *cond_ret = COND_TRUE;
        return OG_SUCCESS;
    }

    if (node->type == CMP_TYPE_NOT_IN) {
        *cond_ret = g_not_true_table[*cond_ret];
    }
    return OG_SUCCESS;
}

static status_t sql_match_is(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *cond_ret)
{
    variant_t var;
    if (node->type == CMP_TYPE_IS_JSON || node->type == CMP_TYPE_IS_NOT_JSON) {
        OG_RETURN_IFERR(sql_func_is_json(stmt, node->left, &var));
        if (var.type == OG_TYPE_COLUMN) {
            *cond_ret = COND_TRUE;
            *pending = OG_TRUE;
            return OG_SUCCESS;
        }
        *cond_ret = var.is_null ? COND_UNKNOWN : (node->type == CMP_TYPE_IS_JSON) ? var.v_bool : !var.v_bool;
        return OG_SUCCESS;
    }

    if (sql_exec_expr(stmt, node->left, &var) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (var.type == OG_TYPE_COLUMN) {
        *cond_ret = COND_TRUE;
        *pending = OG_TRUE;
        return OG_SUCCESS;
    }

    *cond_ret = (node->type == CMP_TYPE_IS_NULL) ? var.is_null : !var.is_null;
    return OG_SUCCESS;
}

static status_t sql_compare_var_all(sql_stmt_t *stmt, cmp_type_t cmp_type, variant_t *l_var, variant_t *r_var,
    variant_t *result)
{
    int32 cmp_result;

    if (sql_compare_variant(stmt, l_var, r_var, &cmp_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch (cmp_type) {
        case CMP_TYPE_EQUAL_ALL:
            if (cmp_result != 0) {
                result->is_null = OG_TRUE;
            }
            break;

        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
            if (cmp_result < 0) {
                var_copy(r_var, result);
            }
            break;

        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
            if (cmp_result > 0) {
                var_copy(r_var, result);
            }
            break;

        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t sql_match_subselect(sql_stmt_t *stmt, sql_cursor_t *cursor, cmp_node_t *node, variant_t *l_var,
    variant_t *r_var, bool32 *exist_null, cond_result_t *result)
{
    status_t status = OG_SUCCESS;
    int32 cmp_result;

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    OGSQL_SAVE_STACK(stmt);

    // if sub-select has no record, the result is true
    r_var->is_null = OG_FALSE;
    r_var->type = OG_TYPE_LOGIC_TRUE;

    for (;;) {
        if (sql_fetch_cursor(stmt, cursor, cursor->plan->select_p.next, &cursor->eof) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (cursor->eof) {
            break;
        }

        if (sql_get_rs_value(stmt, cursor, 0, r_var) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (NODE_IS_FIRST_EXECUTABLE(node->right->root) && F_EXEC_VARS(stmt) != NULL) {
            sql_copy_first_exec_var(stmt, r_var, F_EXEC_VALUE(stmt, node->right->root));
        }

        if (l_var->is_null) {
            *result = COND_UNKNOWN;
            break;
        }

        if (r_var->is_null) {
            *exist_null = OG_TRUE;
            continue;
        }
        if (OG_IS_LOB_TYPE(r_var->type) && sql_get_lob_value(stmt, r_var) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (sql_compare_variant(stmt, l_var, r_var, &cmp_result) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
        if (*result == COND_FALSE) {
            break;
        }
        OGSQL_RESTORE_STACK(stmt);
    }
    OGSQL_RESTORE_STACK(stmt);
    SQL_CURSOR_POP(stmt);
    return status;
}

static status_t sql_match_cached_subselect(sql_stmt_t *stmt, cmp_node_t *node, expr_node_t *r_node, variant_t l_var,
    cond_result_t *result)
{
    int32 cmp_result;
    variant_t r_var;
    var_copy(F_EXEC_VALUE(stmt, r_node), &r_var);
    if (r_var.is_null) {
        *result = COND_UNKNOWN;
        return OG_SUCCESS;
    }
    if (r_var.type == OG_TYPE_LOGIC_TRUE) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }

    if (l_var.is_null) {
        *result = COND_UNKNOWN;
        return OG_SUCCESS;
    }

    if (sql_compare_variant(stmt, &l_var, &r_var, &cmp_result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
    return OG_SUCCESS;
}

static status_t sql_match_all_subselect(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    bool32 exist_null = OG_FALSE;
    variant_t l_var;
    variant_t r_var;
    sql_cursor_t *cursor = NULL;
    sql_cursor_t *parent_cur = NULL;
    expr_node_t *r_node = node->right->root;
    var_object_t *v_obj = NODE_VALUE_PTR(var_object_t, r_node);
    sql_select_t *select_ctx = (sql_select_t *)v_obj->ptr;

    *result = COND_TRUE;

    // evaluate the variant at the left of ALL
    SQL_EXEC_CMP_OPERAND_EX(node->left, &l_var, result, pending, stmt);

    if (*pending) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }
    if (NODE_IS_FIRST_EXECUTABLE(r_node) && F_EXEC_VARS(stmt) != NULL &&
        F_EXEC_VALUE(stmt, r_node)->type != OG_TYPE_UNINITIALIZED) {
        return sql_match_cached_subselect(stmt, node, r_node, l_var, result);
    }

    parent_cur = OGSQL_CURR_CURSOR(stmt);
    OG_RETURN_IFERR(sql_check_sub_select_pending(parent_cur, select_ctx, pending));
    if (*pending) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_get_ssa_cursor(parent_cur, select_ctx, v_obj->id, &cursor));
    stmt = parent_cur->stmt;
    OG_RETURN_IFERR(sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next));

    if (cursor->columns->count != 1) {
        sql_close_cursor(stmt, cursor);
        OG_THROW_ERROR(ERR_TOO_MANY_VALUES);
        return OG_ERROR;
    }

    if (sql_match_subselect(stmt, cursor, node, &l_var, &r_var, &exist_null, result) != OG_SUCCESS) {
        sql_close_cursor(stmt, cursor);
        return OG_ERROR;
    }

    if (exist_null && *result == COND_TRUE) {
        *result = COND_UNKNOWN;
    }

    if (NODE_IS_FIRST_EXECUTABLE(r_node) && F_EXEC_VARS(stmt) != NULL && !r_var.is_null &&
        r_var.type == OG_TYPE_LOGIC_TRUE) {
        sql_copy_first_exec_var(stmt, &r_var, F_EXEC_VALUE(stmt, r_node));
    }
    sql_close_cursor(stmt, cursor);
    return OG_SUCCESS;
}

static status_t sql_optmz_all_list(sql_stmt_t *stmt, cmp_node_t *node, variant_t *l_var, bool32 *pending,
    cond_result_t *result)
{
    int32 cmp_result;
    variant_t r_var;
    variant_t var;
    expr_tree_t *l_expr = node->left;
    expr_tree_t *r_expr = node->right;
    bool32 exist_null = OG_FALSE;

    if (F_EXEC_VARS(stmt) != NULL && F_EXEC_VALUE(stmt, l_expr->root)->type != OG_TYPE_UNINITIALIZED) {
        var_copy(F_EXEC_VALUE(stmt, l_expr->root), &var);
        if (sql_compare_variant(stmt, l_var, &var, &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
        return OG_SUCCESS;
    }

    var.is_null = OG_TRUE;
    // evaluate the variant at the right of ALL
    while (r_expr != NULL) {
        SQL_EXEC_CMP_OPERAND(r_expr, &r_var, result, pending, stmt);

        if (r_var.is_null) {
            exist_null = OG_TRUE;
            r_expr = r_expr->next;
            continue;
        }

        if (var.is_null) {
            var = r_var;
        } else {
            if (sql_compare_var_all(stmt, node->type, &var, &r_var, &var) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (var.is_null) {
                *result = COND_FALSE;
                return OG_SUCCESS;
            }
            sql_keep_stack_variant(stmt, &var);
        }

        r_expr = r_expr->next;
    }

    if (!var.is_null) {
        if (sql_compare_variant(stmt, l_var, &var, &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
    } else {
        *result = COND_UNKNOWN;
    }

    if (exist_null) {
        if (*result == COND_TRUE) {
            *result = COND_UNKNOWN;
        }
        return OG_SUCCESS;
    }

    if (F_EXEC_VARS(stmt) != NULL) {
        sql_copy_first_exec_var(stmt, &var, F_EXEC_VALUE(stmt, l_expr->root));
    }

    return OG_SUCCESS;
}

static status_t sql_non_optmz_all_list(sql_stmt_t *stmt, cmp_node_t *node, variant_t *l_var, bool32 *pending,
    cond_result_t *result)
{
    int32 cmp_result;
    variant_t r_var;
    expr_tree_t *r_expr = node->right;
    bool32 exist_null = OG_FALSE;

    // evaluate the variant at the right of ALL
    while (r_expr != NULL) {
        SQL_EXEC_CMP_OPERAND(r_expr, &r_var, result, pending, stmt);

        if (r_var.is_null) {
            exist_null = OG_TRUE;
            r_expr = r_expr->next;
            continue;
        }

        if (sql_compare_variant(stmt, l_var, &r_var, &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
        if (*result == COND_FALSE) {
            return OG_SUCCESS;
        }
        r_expr = r_expr->next;
    }

    if (exist_null) {
        *result = COND_UNKNOWN;
    }

    return OG_SUCCESS;
}

static status_t sql_match_all_list(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    variant_t l_var;
    expr_tree_t *l_expr = node->left;
    // evaluate the variant at the left of ALL
    SQL_EXEC_CMP_OPERAND_EX(l_expr, &l_var, result, pending, stmt);

    *result = COND_END;

    if (*pending) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }

    if (l_var.is_null) {
        /* match all list
          is equal expr == expr1 and expr == expr2 and expr == expr3 ...
          if expr is null no need to calc the whole cond, the result must be COND_UNKNOWN
        */
        *result = COND_UNKNOWN;
        return OG_SUCCESS;
    }

    if (NODE_IS_OPTMZ_ALL(l_expr->root)) {
        return sql_optmz_all_list(stmt, node, &l_var, pending, result);
    }

    return sql_non_optmz_all_list(stmt, node, &l_var, pending, result);
}

static status_t sql_match_all(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    /*
    CMP_TYPE_EQUAL_ALL        expr = all (expr1, expr2,...,exprn) equal  expr == expr1 and  expr == expr2 and ... and
    expr == exprn CMP_TYPE_NOT_EQUAL_ALL    expr != all (expr1, expr2,...,exprn) equal  expr != expr1 and  expr != expr2
    and ... and expr != exprn CMP_TYPE_GREAT_ALL        expr > all (expr1, expr2,...,exprn) equal  expr > expr1 and expr
    > expr2 and ... and expr > exprn CMP_TYPE_GREAT_EQUAL_ALL  expr >= all (expr1, expr2,...,exprn) equal  expr >= expr1
    and  expr >= expr2 and ... and expr >= exprn CMP_TYPE_LESS_ALL         expr < all (expr1, expr2,...,exprn) equal
    expr < expr1 and  expr < expr2 and ... and expr < exprn CMP_TYPE_LESS_EQUAL_ALL   expr <= all (expr1,
    expr2,...,exprn) equal  expr <= expr1 and  expr <= expr2 and ... and expr <= exprn

    */
    if (TREE_EXPR_TYPE(node->right) == EXPR_NODE_SELECT && node->right->next == NULL) {
        if (sql_match_all_subselect(stmt, node, pending, result) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        if (sql_match_all_list(stmt, node, pending, result) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (*pending) {
        *result = COND_TRUE;
    }
    return OG_SUCCESS;
}

typedef struct st_cmp_assist {
    variant_t l_var;
    variant_t r_var;
    bool32 pending;
} cmp_assist_t;

status_t sql_exec_escape_character(expr_tree_t *expr, variant_t *var, char *escape)
{
    do {
        if (var->is_null || !OG_IS_STRING_TYPE(var->type)) {
            break;
        }
        OG_BREAK_IF_ERROR(lex_check_asciichar(&var->v_text, &expr->loc, escape, OG_FALSE));
        return OG_SUCCESS;
    } while (0);

    OG_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "invalid escape character");
    return OG_ERROR;
}

static status_t sql_match_like(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *cond_ret)
{
    variant_t l_var;
    variant_t r_var;
    variant_t escape_var;
    bool8 has_escape = (node->right->next != NULL);
    char escape = OG_INVALID_INT8;

    SQL_EXEC_CMP_OPERAND_EX(node->left, &l_var, cond_ret, pending, stmt);
    SQL_EXEC_CMP_OPERAND_EX(node->right, &r_var, cond_ret, pending, stmt);
    if (has_escape) {
        SQL_EXEC_CMP_OPERAND_EX(node->right->next, &escape_var, cond_ret, pending, stmt);
        OG_RETURN_IFERR(sql_exec_escape_character(node->right->next, &escape_var, &escape));
    }

    /* character. If any of char1, char2, or esc_char is null, then the result is unknown */
    if (l_var.is_null || r_var.is_null) {
        *cond_ret = COND_UNKNOWN;
    } else {
        OGSQL_SAVE_STACK(stmt);

        if (!OG_IS_STRING_TYPE(l_var.type)) {
            if (sql_convert_variant(stmt, &l_var, OG_TYPE_STRING) != OG_SUCCESS) {
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
            sql_keep_stack_variant(stmt, &l_var);
        }
        if (!OG_IS_STRING_TYPE(r_var.type)) {
            if (sql_convert_variant(stmt, &r_var, OG_TYPE_STRING) != OG_SUCCESS) {
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
            sql_keep_stack_variant(stmt, &r_var);
        }

        if (var_like(&l_var, &r_var, (bool32 *)cond_ret, has_escape, escape, GET_CHARSET_ID) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
        OGSQL_RESTORE_STACK(stmt);
    }

    if (node->type == CMP_TYPE_NOT_LIKE) {
        *cond_ret = g_not_true_table[*cond_ret];
    }
    return OG_SUCCESS;
}

static inline status_t sql_match_regular_expression(sql_stmt_t *stmt, text_t *src, text_t *pattern, text_t *match_param,
    bool32 *result)
{
    void *code = NULL;
    char *psz = NULL;
    status_t ret;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, pattern->len * 2 + 1, (void **)&psz));
    if (OG_SUCCESS != cm_replace_regexp_spec_chars(pattern, psz, pattern->len * 2 + 1)) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("regular expression is: %s", psz);

    if (OG_SUCCESS != cm_regexp_compile(&code, psz, match_param, GET_CHARSET_ID)) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    ret = cm_regexp_match(result, code, src);
    cm_regexp_free(code);
    code = NULL;
    OGSQL_RESTORE_STACK(stmt);
    return ret;
}

static status_t sql_match_regexp(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *cond_ret)
{
    variant_t var_src;
    variant_t var_pattern;
    text_t *src = NULL;
    text_t *pattern = NULL;
    text_t match_param = {
        .len = 2,
        .str = (char *)"in"
    };

    SQL_EXEC_CMP_OPERAND_EX(node->left, &var_src, cond_ret, pending, stmt);
    SQL_EXEC_CMP_OPERAND_EX(node->right, &var_pattern, cond_ret, pending, stmt);
    if (var_src.is_null || var_pattern.is_null) {
        *cond_ret = COND_UNKNOWN;
        return OG_SUCCESS;
    }

    if (!OG_IS_STRING_TYPE(var_src.type)) {
        if (sql_convert_variant(stmt, &var_src, OG_TYPE_STRING) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_keep_stack_variant(stmt, &var_src);
    }
    if (!OG_IS_STRING_TYPE(var_pattern.type)) {
        if (sql_convert_variant(stmt, &var_pattern, OG_TYPE_STRING) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_keep_stack_variant(stmt, &var_pattern);
    }

    src = VALUE_PTR(text_t, &var_src);
    pattern = VALUE_PTR(text_t, &var_pattern);

    OG_RETURN_IFERR(sql_match_regular_expression(stmt, src, pattern, &match_param, (bool32 *)cond_ret));

    if (node->type == CMP_TYPE_NOT_REGEXP) {
        *cond_ret = g_not_true_table[*cond_ret];
    }

    return OG_SUCCESS;
}

static status_t sql_match_normal(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    variant_t l_var;
    variant_t r_var;
    int32 cmp_result;

    // evaluate the left node
    SQL_EXEC_CMP_OPERAND_EX(node->left, &l_var, result, pending, stmt);

    // evaluate the right node
    SQL_EXEC_CMP_OPERAND_EX(node->right, &r_var, result, pending, stmt);

    if (l_var.is_null || r_var.is_null) {
        if (stmt->is_check) {
            *result = COND_UNKNOWN;
        } else {
            *result = COND_FALSE;
        }
        return OG_SUCCESS;
    }

    if (sql_compare_variant(stmt, &l_var, &r_var, &cmp_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    sql_convert_match_result(node->type, cmp_result, (bool32 *)result);
    return OG_SUCCESS;
}

static status_t sql_match_between_range(sql_stmt_t *stmt, variant_t *l_var, variant_t *r_var_l, variant_t *r_var_r,
    cond_result_t *result)
{
    int32 cmp_result;

    if (!r_var_l->is_null && !r_var_r->is_null) {
        if (sql_compare_variant(stmt, l_var, r_var_l, &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }
        /* according the g_and_true_table, if left node is false, no need to process right node */
        if (cmp_result < 0) {
            *result = COND_FALSE;
            return OG_SUCCESS;
        }

        if (sql_compare_variant(stmt, l_var, r_var_r, &cmp_result) != OG_SUCCESS) {
            return OG_ERROR;
        }
        *result = (cmp_result <= 0) ? COND_TRUE : COND_FALSE;
    } else {
        if (!r_var_l->is_null) {
            if (sql_compare_variant(stmt, l_var, r_var_l, &cmp_result) != OG_SUCCESS) {
                return OG_ERROR;
            }
            /* according the g_and_true_table, if left node is false, no need to process right node */
            if (cmp_result < 0) {
                *result = COND_FALSE;
                return OG_SUCCESS;
            }
        }

        if (!r_var_r->is_null) {
            if (sql_compare_variant(stmt, l_var, r_var_r, &cmp_result) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (cmp_result > 0) {
                *result = COND_FALSE;
                return OG_SUCCESS;
            }
        }
        *result = COND_UNKNOWN;
    }

    return OG_SUCCESS;
}

static status_t sql_match_between(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    status_t status;
    variant_t l_var;
    variant_t r_var_l;
    variant_t r_var_r;

    CM_POINTER2(node->right, node->right->next);

    SQL_EXEC_CMP_OPERAND_EX(node->left, &l_var, result, pending, stmt);

    SQL_EXEC_CMP_OPERAND_EX(node->right, &r_var_l, result, pending, stmt);

    SQL_EXEC_CMP_OPERAND_EX(node->right->next, &r_var_r, result, pending, stmt);

    /* If expr3 < expr2, then the interval is empty. If expr1 is NULL, then the result is NULL. If
       expr1 is not NULL, then the value is FALSE in the ordinary case and TRUE when the
       keyword NOT is used */
    if (l_var.is_null) {
        *result = COND_UNKNOWN;
        return OG_SUCCESS;
    }

    /* expr1 between expr2 and expr3 is equal expr2 <= expr1 and expr1 <= expr3 */
    status = sql_match_between_range(stmt, &l_var, &r_var_l, &r_var_r, result);
    if (status == OG_SUCCESS && node->type == CMP_TYPE_NOT_BETWEEN) {
        *result = g_not_true_table[*result];
    }
    return status;
}

static status_t sql_match_exists(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *result)
{
    sql_cursor_t *cursor = NULL;
    sql_cursor_t *parent_cur = NULL;
    var_object_t *v_obj = EXPR_VALUE_PTR(var_object_t, node->right);
    sql_select_t *select_ctx = (sql_select_t *)v_obj->ptr;

    if (node->right->root->type != EXPR_NODE_SELECT) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "node->right->root->type(%u) == EXPR_NODE_SELECT(%u)",
            (uint32)node->right->root->type, (uint32)EXPR_NODE_SELECT);
        return OG_ERROR;
    }

    parent_cur = OGSQL_CURR_CURSOR(stmt);
    OG_RETURN_IFERR(sql_check_sub_select_pending(parent_cur, select_ctx, pending));
    if (*pending) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_get_ssa_cursor(parent_cur, select_ctx, v_obj->id, &cursor));
    stmt = parent_cur->stmt;
    sql_init_ssa_cursor_maps(cursor, select_ctx->first_query->ssa.count);

    if (cursor->is_result_cached) {
        *result = (cond_result_t)cursor->exists_result;
        return OG_SUCCESS;
    }

    if (OG_SUCCESS != sql_execute_select_plan(stmt, cursor, cursor->plan->select_p.next)) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    if (sql_fetch_cursor(stmt, cursor, cursor->plan->select_p.next, &cursor->eof) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        return OG_ERROR;
    }

    if (cursor->eof) {
        *result = (cond_result_t)((node->type == CMP_TYPE_EXISTS) ? OG_FALSE : OG_TRUE);
    } else {
        *result = (cond_result_t)((node->type == CMP_TYPE_NOT_EXISTS) ? OG_FALSE : OG_TRUE);
    }

    if (select_ctx->has_ancestor == 0) {
        sql_cursor_cache_result(cursor, (bool32)*result);
    }
    SQL_CURSOR_POP(stmt);
    sql_close_cursor(stmt, cursor);
    return OG_SUCCESS;
}

static status_t sql_match_regexp_like(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *cond_ret)
{
    variant_t var_src;
    variant_t var_pattern;
    variant_t var_match_param;
    text_t *src = NULL;
    text_t *pattern = NULL;
    text_t *match_param = NULL;

    SQL_EXEC_CMP_OPERAND_EX(node->right, &var_src, cond_ret, pending, stmt);
    SQL_EXEC_CMP_OPERAND_EX(node->right->next, &var_pattern, cond_ret, pending, stmt);
    if (var_pattern.is_null) {
        *cond_ret = COND_UNKNOWN;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_convert_variant(stmt, &var_src, OG_TYPE_STRING));
    sql_keep_stack_variant(stmt, &var_src);
    OG_RETURN_IFERR(sql_convert_variant(stmt, &var_pattern, OG_TYPE_STRING));
    sql_keep_stack_variant(stmt, &var_pattern);

    src = VALUE_PTR(text_t, &var_src);
    if (var_src.is_null) {
        src->str = NULL;
        src->len = 0;
    }
    pattern = VALUE_PTR(text_t, &var_pattern);
    if (node->right->next->next != NULL) {
        SQL_EXEC_CMP_OPERAND_EX(node->right->next->next, &var_match_param, cond_ret, pending, stmt);

        OG_RETURN_IFERR(sql_convert_variant(stmt, &var_match_param, OG_TYPE_STRING));
        match_param = VALUE_PTR(text_t, &var_match_param);
        if (var_match_param.is_null) {
            match_param->str = NULL;
            match_param->len = 0;
        }
    }
    OG_RETURN_IFERR(sql_match_regular_expression(stmt, src, pattern, match_param, (bool32 *)cond_ret));

    if (var_src.is_null) {
        *cond_ret = COND_UNKNOWN;
        return OG_SUCCESS;
    }
    if (node->type == CMP_TYPE_NOT_REGEXP_LIKE) {
        *cond_ret = g_not_true_table[*cond_ret];
    }

    return OG_SUCCESS;
}

static status_t sql_match_compare_node(sql_stmt_t *stmt, cmp_node_t *node, bool32 *pending, cond_result_t *res)
{
    status_t status;
    bool32 cmp_pending = OG_FALSE;

    OGSQL_SAVE_STACK(stmt);
    switch (node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
            status = sql_match_in(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
            status = sql_match_all(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
            status = sql_match_is(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            status = sql_match_like(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
            status = sql_match_regexp(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
            status = sql_match_between(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
            status = sql_match_exists(stmt, node, &cmp_pending, res);
            break;

        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
            status = sql_match_regexp_like(stmt, node, &cmp_pending, res);
            break;

        default:
            status = sql_match_normal(stmt, node, &cmp_pending, res);
            break;
    }

    if (cmp_pending) {
        *pending = OG_TRUE;
    }
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_match_cond_argument(sql_stmt_t *stmt, cond_node_t *node, bool32 *pending, cond_result_t *res)
{
    cond_result_t l_result;
    cond_result_t r_result;
    if (node->type == COND_NODE_COMPARE) {
        return sql_match_compare_node(stmt, node->cmp, pending, res);
    }
    if (node->type == COND_NODE_TRUE) {
        *res = COND_TRUE;
        return OG_SUCCESS;
    }
    if (node->type == COND_NODE_FALSE) {
        *res = COND_FALSE;
        return OG_SUCCESS;
    }

    if (sql_match_cond_argument(stmt, node->left, pending, &l_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // ignore cond node not, it will be converted in parsing phase
    if (node->type == COND_NODE_AND && l_result == COND_FALSE) {
        *res = COND_FALSE;
        return OG_SUCCESS;
    }

    if (node->type == COND_NODE_OR && l_result == COND_TRUE) {
        *res = COND_TRUE;
        return OG_SUCCESS;
    }

    if (sql_match_cond_argument(stmt, node->right, pending, &r_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (node->type == COND_NODE_AND) {
        *res = g_and_true_table[l_result][r_result];
    }
    if (node->type == COND_NODE_OR) {
        *res = g_or_true_table[l_result][r_result];
    }
    return OG_SUCCESS;
}

status_t sql_match_cond_node(sql_stmt_t *stmt, cond_node_t *node, bool32 *result)
{
    cond_result_t cond_ret;
    bool32 pending = OG_FALSE;
    if (sql_match_cond_argument(stmt, node, &pending, &cond_ret)) {
        return OG_ERROR;
    }
    *result = (cond_ret == COND_TRUE);
    return OG_SUCCESS;
}

status_t sql_match_cond_tree(void *stmt, void *node, cond_result_t *result)
{
    bool32 pending = OG_FALSE;
    return sql_match_cond_argument((sql_stmt_t *)stmt, ((cond_tree_t *)node)->root, &pending, result);
}

status_t sql_match_cond(void *arg, bool32 *result)
{
    sql_stmt_t *stmt = (sql_stmt_t *)arg;

    if (stmt == NULL) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }

    cond_tree_t *cond = OGSQL_CURR_CURSOR(stmt)->cond;
    if (cond == NULL || cond->root == NULL) {
        *result = COND_TRUE;
        return OG_SUCCESS;
    }

    *result = COND_FALSE;
    return sql_match_cond_node(stmt, cond->root, result);
}

/* !
 * \brief To check whether a comparison cmpnode is constant.
 *
 */
static bool32 sql_is_const_cmp_node(const cmp_node_t *cmpnode)
{
    if (cmpnode->left != NULL && !sql_is_const_expr_tree(cmpnode->left)) {
        return OG_FALSE;
    }

    if (cmpnode->right != NULL && !sql_is_const_expr_tree(cmpnode->right)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

/* !
 * \brief Try to evaluate a constant comparison node. The parameter *node* must be
 * a comparison node.
 *
 */
status_t try_eval_compare_node(sql_stmt_t *stmt, cond_node_t *node, uint32 *rnum_upper, bool8 *rnum_pending)
{
    cond_result_t result;
    bool32 pending = OG_FALSE;

    if (sql_is_const_cmp_node(node->cmp)) {
        OG_RETURN_IFERR(sql_match_compare_node(stmt, node->cmp, &pending, &result));

        if (result == COND_TRUE) {
            node->type = COND_NODE_TRUE;
            *rnum_upper = OG_INFINITE32;
            *rnum_pending = OG_FALSE;
        } else {
            node->type = COND_NODE_FALSE;
            *rnum_upper = 0U;
            *rnum_pending = OG_FALSE;
        }

        return OG_SUCCESS;
    }

    *rnum_upper = OG_INFINITE32;
    *rnum_pending = OG_FALSE;
    return rbo_try_rownum_optmz(stmt, node, rnum_upper, rnum_pending);
}

/* !
 * \brief Try to evaluate an AND condition node.
 *
 */
void try_eval_logic_and(cond_node_t *cond_node)
{
    if (cond_node->type != COND_NODE_AND) {
        return;
    }

    /* If one of the two child nodes is false, then the node is false */
    if (cond_node->left->type == COND_NODE_FALSE || cond_node->right->type == COND_NODE_FALSE) {
        cond_node->type = COND_NODE_FALSE;
        return;
    }

    if (cond_node->left->type == COND_NODE_TRUE) {
        if (cond_node->right->type == COND_NODE_TRUE) {
            cond_node->type = COND_NODE_TRUE;
        } else {
            *cond_node = *cond_node->right;
        }
        return;
    }

    if (cond_node->right->type == COND_NODE_TRUE) {
        *cond_node = *cond_node->left;
    }
}

/* !
 * \brief Try to evaluate an OR condition node.
 *
 */
void try_eval_logic_or(cond_node_t *cond_node)
{
    if (cond_node->type != COND_NODE_OR) {
        return;
    }

    /* If one of the two child nodes is true, then the node is true */
    if (cond_node->left->type == COND_NODE_TRUE || cond_node->right->type == COND_NODE_TRUE) {
        cond_node->type = COND_NODE_TRUE;
        return;
    }

    if (cond_node->left->type == COND_NODE_FALSE) {
        if (cond_node->right->type == COND_NODE_FALSE) {
            cond_node->type = COND_NODE_FALSE;
            return;
        } else {
            *cond_node = *cond_node->right;
            return;
        }
    }

    if (cond_node->right->type == COND_NODE_FALSE) {
        *cond_node = *cond_node->left;
        return;
    }

    return;
}

static bool32 sql_cmp_node_in_tab_list(sql_array_t *tables, cmp_node_t *cmp_node, bool32 use_remote_id,
    bool32 *exist_col)
{
    if (cmp_node->left != NULL) {
        if (OG_FALSE == sql_expr_tree_in_tab_list(tables, cmp_node->left, use_remote_id, exist_col)) {
            return OG_FALSE;
        }
    }
    if (cmp_node->right == NULL) {
        return OG_TRUE;
    }
    return sql_expr_tree_in_tab_list(tables, cmp_node->right, use_remote_id, exist_col);
}

bool32 sql_cond_node_in_tab_list(sql_array_t *tables, cond_node_t *cond_node, bool32 use_remote_id, bool32 *exist_col)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            return (bool32)(sql_cond_node_in_tab_list(tables, cond_node->left, use_remote_id, exist_col) &&
                sql_cond_node_in_tab_list(tables, cond_node->right, use_remote_id, exist_col));

        case COND_NODE_COMPARE:
            return sql_cmp_node_in_tab_list(tables, cond_node->cmp, use_remote_id, exist_col);

        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
        default:
            return OG_FALSE;
    }
}

static status_t sql_split_cond_node(sql_array_t *tables, cond_tree_t *cond_tree_result, cond_node_t *cond_node,
    bool32 use_remote_id)
{
    bool32 exist_col = OG_FALSE;

    if (cond_node->processed) {
        return OG_SUCCESS;
    }

    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_split_cond_node(tables, cond_tree_result, cond_node->left, use_remote_id));
            OG_RETURN_IFERR(sql_split_cond_node(tables, cond_tree_result, cond_node->right, use_remote_id));
            break;

        case COND_NODE_OR:
        case COND_NODE_COMPARE:
            if (!sql_cond_node_in_tab_list(tables, cond_node, use_remote_id, &exist_col)) {
                break;
            }
            OG_RETURN_IFERR(sql_add_cond_node(cond_tree_result, cond_node));
            cond_node->processed = OG_TRUE;
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
        default:
            break;
    }

    return OG_SUCCESS;
}

static bool32 is_filter_col_column(expr_node_t *expr_node, sql_array_t *l_table, bool32 *exists_col)
{
    if (NODE_ANCESTOR(expr_node) > 0) {
        return OG_TRUE;
    }

    if (!sql_table_in_list(l_table, NODE_TAB(expr_node))) {
        return OG_FALSE;
    }

    *exists_col = OG_TRUE;
    return OG_TRUE;
}

static bool32 is_filter_col_reserved(expr_node_t *expr_node, sql_array_t *l_table, bool32 *exists_col)
{
    if (!NODE_IS_RES_ROWID(expr_node) || ROWID_NODE_ANCESTOR(expr_node) > 0) {
        return OG_TRUE;
    }

    if (!sql_table_in_list(l_table, ROWID_NODE_TAB(expr_node))) {
        return OG_FALSE;
    }

    *exists_col = OG_TRUE;
    return OG_TRUE;
}

static inline bool32 is_filter_col_expr_tree(expr_tree_t *tree, sql_array_t *l_table, bool32 *exists_col,
    bool32 is_right_node);
static bool32 is_filter_col_expr_node(expr_node_t *expr_node, sql_array_t *l_table, bool32 *exists_col,
    bool32 is_right_node);

static bool32 is_filter_col_cond(cond_node_t *cond_node, sql_array_t *l_table, bool32 *exists_col, bool32 is_right_node)
{
    if (cond_node == NULL) {
        return OG_TRUE;
    }

    switch (cond_node->type) {
        case COND_NODE_OR:
        case COND_NODE_AND:
            return (bool32)(is_filter_col_cond(cond_node->left, l_table, exists_col, is_right_node) &&
                is_filter_col_cond(cond_node->right, l_table, exists_col, is_right_node));

        case COND_NODE_COMPARE:
            if (cond_node->cmp->type == CMP_TYPE_IS_NULL) {
                return OG_FALSE;
            }
            return (bool32)(is_filter_col_expr_tree(cond_node->cmp->left, l_table, exists_col, is_right_node) &&
                is_filter_col_expr_tree(cond_node->cmp->right, l_table, exists_col, is_right_node));

        default:
            return OG_TRUE;
    }
}

static bool32 is_filter_col_case(expr_node_t *expr_node, sql_array_t *l_table, bool32 *exists_col, bool32 is_right_node)
{
    if (is_right_node) {
        return OG_FALSE;
    }

    case_expr_t *case_expr = (case_expr_t *)expr_node->value.v_pointer;
    if (!case_expr->is_cond) {
        if (!is_filter_col_expr_tree(case_expr->expr, l_table, exists_col, is_right_node)) {
            return OG_FALSE;
        }
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair_t *case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            if (!is_filter_col_cond(case_pair->when_cond->root, l_table, exists_col, is_right_node)) {
                return OG_FALSE;
            }
        } else {
            if (!is_filter_col_expr_tree(case_pair->when_expr, l_table, exists_col, is_right_node)) {
                return OG_FALSE;
            }
        }
        if (!is_filter_col_expr_tree(case_pair->value, l_table, exists_col, is_right_node)) {
            return OG_FALSE;
        }
    }

    if (case_expr->default_expr != NULL) {
        if (!is_filter_col_expr_tree(case_expr->default_expr, l_table, exists_col, is_right_node)) {
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static bool32 is_filter_col_func(expr_node_t *expr_node, sql_array_t *l_table, bool32 *exists_col, bool32 is_right_node)
{
    expr_tree_t *arg = expr_node->argument;

    if (is_right_node) {
        return OG_FALSE;
    }

    while (arg != NULL) {
        if (!is_filter_col_expr_node(arg->root, l_table, exists_col, is_right_node)) {
            return OG_FALSE;
        }
        arg = arg->next;
    }

    sql_func_t *func = sql_get_func(&expr_node->value.v_func);
    if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
        expr_node->cond_arg != NULL) {
        if (!is_filter_col_cond(expr_node->cond_arg->root, l_table, exists_col, is_right_node)) {
            return OG_FALSE;
        }
    }

    if ((func->aggr_type == AGGR_TYPE_GROUP_CONCAT || func->aggr_type == AGGR_TYPE_MEDIAN) &&
        expr_node->sort_items != NULL) {
        for (uint32 i = 0; i < expr_node->sort_items->count; i++) {
            sort_item_t *sort_item = (sort_item_t *)cm_galist_get(expr_node->sort_items, i);
            if (!is_filter_col_expr_tree(sort_item->expr, l_table, exists_col, is_right_node)) {
                return OG_FALSE;
            }
        }
    }

    return OG_TRUE;
}

static bool32 is_filter_col_expr_node(expr_node_t *expr_node, sql_array_t *l_table, bool32 *exists_col,
    bool32 is_right_node)
{
    switch (expr_node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(is_filter_col_expr_node(expr_node->left, l_table, exists_col, is_right_node) &&
                is_filter_col_expr_node(expr_node->right, l_table, exists_col, is_right_node));

        case EXPR_NODE_NEGATIVE:
            return (bool32)(is_filter_col_expr_node(expr_node->right, l_table, exists_col, is_right_node));

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            return is_filter_col_column(expr_node, l_table, exists_col);

        case EXPR_NODE_CASE:
            return is_filter_col_case(expr_node, l_table, exists_col, is_right_node);

        case EXPR_NODE_FUNC:
            return is_filter_col_func(expr_node, l_table, exists_col, is_right_node);

        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_CONSTRUCT:
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_SELECT:
        case EXPR_NODE_PRIOR:
        case EXPR_NODE_CAT:
        case EXPR_NODE_ARRAY:
            return OG_FALSE;

        case EXPR_NODE_RESERVED:
            return is_filter_col_reserved(expr_node, l_table, exists_col);

        default:
            return OG_TRUE;
    }
}

static inline bool32 is_filter_col_expr_tree(expr_tree_t *tree, sql_array_t *l_table, bool32 *exists_col,
    bool32 is_right_node)
{
    while (tree != NULL) {
        OG_RETVALUE_IFTRUE(!is_filter_col_expr_node(tree->root, l_table, exists_col, is_right_node), OG_FALSE);
        tree = tree->next;
    }
    return OG_TRUE;
}

static inline bool32 is_filter_col_node(expr_tree_t *tree, sql_array_t *l_table, bool32 is_right_node)
{
    bool32 exists_col = OG_FALSE;
    return (bool32)(is_filter_col_expr_tree(tree, l_table, &exists_col, is_right_node) && exists_col);
}

static bool32 is_filter_value_column(expr_node_t *node, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    if (NODE_ANCESTOR(node) > 0) {
        return OG_TRUE;
    }
    if (sql_table_in_list(l_table, NODE_TAB(node))) {
        return OG_TRUE;
    }
    if (!is_right_node || join_type == JOIN_TYPE_FULL) {
        return OG_FALSE;
    }
    return sql_table_in_list(p_tabs, NODE_TAB(node));
}

static bool32 is_filter_value_reserved(expr_node_t *node, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    if (VALUE(int32, &node->value) == RES_WORD_SYSDATE || VALUE(int32, &node->value) == RES_WORD_SYSTIMESTAMP) {
        return OG_TRUE;
    }

    if (VALUE(int32, &node->value) == RES_WORD_ROWID) {
        if (ROWID_NODE_ANCESTOR(node) > 0) {
            return OG_TRUE;
        }

        if (sql_table_in_list(l_table, ROWID_NODE_TAB(node))) {
            return OG_TRUE;
        }

        if (!is_right_node || join_type == JOIN_TYPE_FULL) {
            return OG_FALSE;
        }
        return sql_table_in_list(p_tabs, ROWID_NODE_TAB(node));
    }
    return OG_FALSE;
}

static inline bool32 is_filter_value_expr_tree(expr_tree_t *expr, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node);
static bool32 is_filter_value_cond(cond_node_t *node, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    cmp_node_t *cmp_node = NULL;
    switch (node->type) {
        case COND_NODE_AND:
        case COND_NODE_OR:
            return (bool32)(is_filter_value_cond(node->left, l_table, p_tabs, join_type, is_right_node) &&
                is_filter_value_cond(node->right, l_table, p_tabs, join_type, is_right_node));
        case COND_NODE_COMPARE:
            cmp_node = node->cmp;
            if (cmp_node->type == CMP_TYPE_IS_NULL) {
                return OG_FALSE;
            }
            return (bool32)(is_filter_value_expr_tree(cmp_node->left, l_table, p_tabs, join_type, is_right_node) &&
                is_filter_value_expr_tree(cmp_node->right, l_table, p_tabs, join_type, is_right_node));
        default:
            return OG_TRUE;
    }
}

static bool32 is_filter_value_func(expr_node_t *node, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    sql_func_t *func = NULL;
    if (!is_filter_value_expr_tree(node->argument, l_table, p_tabs, join_type, is_right_node)) {
        return OG_FALSE;
    }
    func = sql_get_func(&node->value.v_func);
    if ((func->builtin_func_id == ID_FUNC_ITEM_IF || func->builtin_func_id == ID_FUNC_ITEM_LNNVL) &&
        node->cond_arg != NULL) {
        return is_filter_value_cond(node->cond_arg->root, l_table, p_tabs, join_type, is_right_node);
    }
    return OG_TRUE;
}

static inline bool32 is_filter_value_subslct(expr_node_t *node)
{
    sql_select_t *select_ctx = (sql_select_t *)VALUE_PTR(var_object_t, &node->value)->ptr;
    return (bool32)((select_ctx->type == SELECT_AS_VARIANT || select_ctx->type == SELECT_AS_LIST) &&
        select_ctx->parent_refs->count == 0);
}

static bool32 is_filter_value_case(expr_node_t *node, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    case_pair_t *case_pair = NULL;
    case_expr_t *case_expr = NULL;

    case_expr = (case_expr_t *)node->value.v_pointer;
    if (!case_expr->is_cond) {
        OG_RETVALUE_IFTRUE(!is_filter_value_expr_tree(case_expr->expr, l_table, p_tabs, join_type, is_right_node),
            OG_FALSE);
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            OG_RETVALUE_IFTRUE(
                !is_filter_value_cond(case_pair->when_cond->root, l_table, p_tabs, join_type, is_right_node), OG_FALSE);
        } else {
            OG_RETVALUE_IFTRUE(
                !is_filter_value_expr_tree(case_pair->when_expr, l_table, p_tabs, join_type, is_right_node), OG_FALSE);
        }
        OG_RETVALUE_IFTRUE(!is_filter_value_expr_tree(case_pair->value, l_table, p_tabs, join_type, is_right_node),
            OG_FALSE);
    }

    if (case_expr->default_expr == NULL) {
        return OG_TRUE;
    }
    return is_filter_value_expr_tree(case_expr->default_expr, l_table, p_tabs, join_type, is_right_node);
}

static bool32 is_filter_value_expr_node(expr_node_t *node, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(is_filter_value_expr_node(node->left, l_table, p_tabs, join_type, is_right_node) &&
                is_filter_value_expr_node(node->right, l_table, p_tabs, join_type, is_right_node));

        case EXPR_NODE_NEGATIVE:
            return is_filter_value_expr_node(node->right, l_table, p_tabs, join_type, is_right_node);

        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
        case EXPR_NODE_SEQUENCE:
        case EXPR_NODE_PL_ATTR:
        case EXPR_NODE_PRIOR:
            return OG_TRUE;

        case EXPR_NODE_RESERVED:
            return is_filter_value_reserved(node, l_table, p_tabs, join_type, is_right_node);

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            return is_filter_value_column(node, l_table, p_tabs, join_type, is_right_node);

        case EXPR_NODE_SELECT:
            return is_filter_value_subslct(node);

        case EXPR_NODE_FUNC:
            return is_filter_value_func(node, l_table, p_tabs, join_type, is_right_node);

        case EXPR_NODE_CASE:
            return is_filter_value_case(node, l_table, p_tabs, join_type, is_right_node);

        case EXPR_NODE_V_ADDR:
            return sql_pair_type_is_plvar(node);
        default:
            return OG_FALSE;
    }
}

static inline bool32 is_filter_value_expr_tree(expr_tree_t *expr, sql_array_t *l_table, sql_array_t *p_tabs,
    sql_join_type_t join_type, bool32 is_right_node)
{
    while (expr != NULL) {
        OG_RETVALUE_IFTRUE(!is_filter_value_expr_node(expr->root, l_table, p_tabs, join_type, is_right_node), OG_FALSE);
        expr = expr->next;
    }
    return OG_TRUE;
}

static bool32 is_filter_cmp_node(cmp_node_t *cmp_node, sql_join_node_t *join_node, bool32 is_right_node,
    bool32 is_outer_right, bool32 *not_null)
{
    sql_array_t *l_table = is_right_node ? &join_node->right->tables : &join_node->left->tables;
    sql_array_t *p_tabs = is_right_node ? &join_node->left->tables : &join_node->right->tables;

    if (is_filter_col_node(cmp_node->left, l_table, is_outer_right)) {
        if (is_filter_value_expr_tree(cmp_node->right, l_table, p_tabs, join_node->type, is_right_node)) {
            return OG_TRUE;
        }
        if (!cmp_node->anti_join_cond && TREE_EXPR_TYPE(cmp_node->right) != EXPR_NODE_SELECT &&
            cmp_node->left->root->type != EXPR_NODE_TRANS_COLUMN) {
            *not_null = OG_TRUE;
        }
        return OG_FALSE;
    }
    if (cmp_node->type > CMP_TYPE_NOT_EQUAL) {
        return OG_FALSE;
    }
    if (is_filter_col_node(cmp_node->right, l_table, is_outer_right)) {
        if (is_filter_value_expr_tree(cmp_node->left, l_table, p_tabs, join_node->type, is_right_node)) {
            return OG_TRUE;
        }
        if (!cmp_node->anti_join_cond && TREE_EXPR_TYPE(cmp_node->left) != EXPR_NODE_SELECT &&
            cmp_node->right->root->type != EXPR_NODE_TRANS_COLUMN) {
            *not_null = OG_TRUE;
        }
        return OG_FALSE;
    }
    return OG_FALSE;
}

static bool32 chk_cmp_node_degrade_join(cmp_node_t *cmp_node, sql_join_node_t *join_node, bool32 is_right_node,
    bool32 is_outer_right, bool32 *not_null)
{
    sql_array_t *l_table = is_right_node ? &join_node->right->tables : &join_node->left->tables;

    switch (cmp_node->type) {
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:
            return OG_FALSE;

        case CMP_TYPE_IS_NULL:
            if (!is_outer_right) {
                return is_filter_col_node(cmp_node->left, l_table, is_outer_right);
            }
            return OG_FALSE;

        case CMP_TYPE_IS_NOT_NULL:
            return is_filter_col_node(cmp_node->left, l_table, is_outer_right);
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
            if (TREE_EXPR_TYPE(cmp_node->right) == EXPR_NODE_SELECT) {
                return OG_FALSE;
            }
            // fall through
        default:
            return is_filter_cmp_node(cmp_node, join_node, is_right_node, is_outer_right, not_null);
    }
    return OG_FALSE;
}

bool32 sql_chk_cond_degrade_join(cond_node_t *cond, sql_join_node_t *join_node, bool32 is_right_node,
    bool32 is_outer_right, bool32 *not_null)
{
    bool32 l_not_null = OG_FALSE;
    bool32 r_not_null = OG_FALSE;
    bool32 result = OG_FALSE;

    switch (cond->type) {
        case COND_NODE_OR:
            result =
                (bool32)(sql_chk_cond_degrade_join(cond->left, join_node, is_right_node, is_outer_right, &l_not_null) &&
                sql_chk_cond_degrade_join(cond->right, join_node, is_right_node, is_outer_right, &r_not_null));
            *not_null = (bool32)(l_not_null && r_not_null);
            break;
        case COND_NODE_AND:
            result =
                (bool32)(sql_chk_cond_degrade_join(cond->left, join_node, is_right_node, is_outer_right, &l_not_null) &&
                sql_chk_cond_degrade_join(cond->right, join_node, is_right_node, is_outer_right, &r_not_null));
            *not_null = (bool32)(l_not_null || r_not_null);
            break;
        case COND_NODE_COMPARE:
            result = chk_cmp_node_degrade_join(cond->cmp, join_node, is_right_node, is_outer_right, not_null);
            break;
        default:
            break;
    }
    return result;
}

status_t sql_adjust_inner_join_cond(sql_stmt_t *stmt, sql_join_node_t *join_node, cond_tree_t **cond_tree)
{
    switch (join_node->type) {
        case JOIN_TYPE_NONE:
            return OG_SUCCESS;

        case JOIN_TYPE_COMMA:
        case JOIN_TYPE_CROSS:
        case JOIN_TYPE_INNER:
            if (join_node->filter != NULL) {
                if (*cond_tree == NULL) {
                    OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, cond_tree));
                }
                OG_RETURN_IFERR(sql_add_cond_node(*cond_tree, join_node->filter->root));
                join_node->filter = NULL;
            }
            if (join_node->join_cond != NULL) {
                if (*cond_tree == NULL) {
                    OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, cond_tree));
                }
                OG_RETURN_IFERR(sql_add_cond_node(*cond_tree, join_node->join_cond->root));
                join_node->join_cond = NULL;
            }
            break;

        default:
            OG_THROW_ERROR(ERR_ASSERT_ERROR, "join_node->type == JOIN_TYPE_INNER");
            return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_adjust_inner_join_cond(stmt, join_node->left, cond_tree));
    return sql_adjust_inner_join_cond(stmt, join_node->right, cond_tree);
}

bool32 sql_cond_node_has_prior(cond_node_t *cond_node)
{
    cols_used_t used_cols;
    init_cols_used(&used_cols);
    sql_collect_cols_in_cond(cond_node, &used_cols);
    return HAS_PRIOR(&used_cols);
}

status_t sql_extract_filter_cond(sql_stmt_t *stmt, sql_array_t *tables, cond_tree_t **dst_tree, cond_node_t *cond_node)
{
    bool32 exist_col = OG_FALSE;

    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_extract_filter_cond(stmt, tables, dst_tree, cond_node->left));
            OG_RETURN_IFERR(sql_extract_filter_cond(stmt, tables, dst_tree, cond_node->right));
            try_eval_logic_and(cond_node);
            break;

        case COND_NODE_OR:
        case COND_NODE_COMPARE:
            if (!sql_cond_node_in_tab_list(tables, cond_node, OG_FALSE, &exist_col)) {
                break;
            }
            /* filter cond with PRIOR cannot pushdown to table */
            if (sql_cond_node_has_prior(cond_node)) {
                break;
            }
            if (*dst_tree == NULL) {
                OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, dst_tree));
            }

            OG_RETURN_IFERR(sql_merge_cond_tree_shallow(*dst_tree, cond_node));
            cond_node->type = COND_NODE_TRUE;
            break;

        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
        default:
            break;
    }
    return OG_SUCCESS;
}

status_t sql_split_cond(sql_stmt_t *stmt, sql_array_t *tables, cond_tree_t **cond_tree_result, cond_tree_t *cond_tree,
    bool32 use_remote_id)
{
    OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, cond_tree_result));

    return sql_split_cond_node(tables, *cond_tree_result, cond_tree->root, use_remote_id);
}

static status_t sql_rebuild_cond_node(sql_stmt_t *stmt, cond_node_t **cond_node_result, cond_node_t *cond_node,
    bool32 *ignore)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)cond_node_result));

    if (cond_node->processed) {
        (*cond_node_result)->type = COND_NODE_TRUE;
        return OG_SUCCESS;
    }

    switch (cond_node->type) {
        case COND_NODE_AND:
            (*cond_node_result)->type = COND_NODE_AND;
            OG_RETURN_IFERR(sql_rebuild_cond_node(stmt, &(*cond_node_result)->left, cond_node->left, ignore));
            OG_RETURN_IFERR(sql_rebuild_cond_node(stmt, &(*cond_node_result)->right, cond_node->right, ignore));
            try_eval_logic_and(*cond_node_result);
            break;

        case COND_NODE_OR:
            (*cond_node_result)->type = COND_NODE_OR;
            OG_RETURN_IFERR(sql_rebuild_cond_node(stmt, &(*cond_node_result)->left, cond_node->left, ignore));
            OG_RETURN_IFERR(sql_rebuild_cond_node(stmt, &(*cond_node_result)->right, cond_node->right, ignore));
            try_eval_logic_or(*cond_node_result);
            break;

        case COND_NODE_COMPARE:
            (*cond_node_result)->type = COND_NODE_COMPARE;
            (*cond_node_result)->cmp = cond_node->cmp;
            *ignore = OG_FALSE;
            break;

        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            (*cond_node_result)->type = cond_node->type;
            *ignore = OG_FALSE;
            break;

        default:
            break;
    }

    return OG_SUCCESS;
}

status_t sql_rebuild_cond(sql_stmt_t *stmt, cond_tree_t **cond_tree_result, cond_tree_t *cond_tree, bool32 *ignore)
{
    OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, cond_tree_result));

    return sql_rebuild_cond_node(stmt, &(*cond_tree_result)->root, cond_tree->root, ignore);
}

static status_t sql_cmp_node_walker(sql_stmt_t *stmt, cmp_node_t *node,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context)
{
    if (node == NULL) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_expr_tree_walker(stmt, node->left, fetch, context));

    return sql_expr_tree_walker(stmt, node->right, fetch, context);
}

static status_t sql_cond_node_walker(sql_stmt_t *stmt, cond_node_t *node,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context)
{
    if (node == NULL) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_cond_node_walker(stmt, node->left, fetch, context));
    OG_RETURN_IFERR(sql_cond_node_walker(stmt, node->right, fetch, context));

    return sql_cmp_node_walker(stmt, node->cmp, fetch, context);
}

status_t sql_cond_tree_walker(sql_stmt_t *stmt, cond_tree_t *cond_tree,
    status_t (*fetch)(sql_stmt_t *stmt, expr_node_t *node, void *context), void *context)
{
    cond_node_t *node = cond_tree->root;

    if (node == NULL) {
        return OG_SUCCESS;
    }

    return sql_cond_node_walker(stmt, node, fetch, context);
}

bool32 sql_cmp_node_equal(sql_stmt_t *stmt, cmp_node_t *cmp1, cmp_node_t *cmp2, uint32 *tab_map)
{
    if ((uint32)cmp1->join_type ^ (uint32)cmp2->join_type) {
        return OG_FALSE;
    }

    if (cmp1->type ^ cmp2->type) {
        return OG_FALSE;
    }

    if (sql_expr_tree_equal(stmt, cmp1->left, cmp2->left, tab_map) &&
        sql_expr_tree_equal(stmt, cmp1->right, cmp2->right, tab_map)) {
        return OG_TRUE;
    }

    if (cmp1->type != CMP_TYPE_EQUAL) {
        return OG_FALSE;
    }

    if (sql_expr_tree_equal(stmt, cmp1->left, cmp2->right, tab_map) &&
        sql_expr_tree_equal(stmt, cmp1->right, cmp2->left, tab_map)) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

bool32 sql_cond_node_equal(sql_stmt_t *stmt, cond_node_t *cond1, cond_node_t *cond2, uint32 *tab_map)
{
    if (cond1->type ^ cond2->type) {
        return OG_FALSE;
    }

    if (!((cond1->cmp == NULL && cond2->cmp == NULL) || (cond1->cmp != NULL && cond2->cmp != NULL)) ||
        !((cond1->left == NULL && cond2->left == NULL) || (cond1->left != NULL && cond2->left != NULL)) ||
        !((cond1->right == NULL && cond2->right == NULL) || (cond1->right != NULL && cond2->right != NULL))) {
        return OG_FALSE;
    }

    if (cond1->left != NULL) {
        if (!sql_cond_node_equal(stmt, cond1->left, cond2->left, tab_map)) {
            return OG_FALSE;
        }
    }
    if (cond1->right != NULL) {
        if (!sql_cond_node_equal(stmt, cond1->right, cond2->right, tab_map)) {
            return OG_FALSE;
        }
    }
    if (cond1->cmp != NULL) {
        if (!sql_cmp_node_equal(stmt, cond1->cmp, cond2->cmp, tab_map)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

void sql_set_exists_query_flag(sql_stmt_t *stmt, select_node_t *select_node)
{
    switch (select_node->type) {
        case SELECT_NODE_QUERY:
            select_node->query->is_exists_query = OG_TRUE;
            break;
        default:
            sql_set_exists_query_flag(stmt, select_node->left);
            sql_set_exists_query_flag(stmt, select_node->right);
            break;
    }
}

status_t visit_join_node_cond(visit_assist_t *va, sql_join_node_t *join_node, visit_func_t visit_func)
{
    if (join_node->type != JOIN_TYPE_NONE) {
        if (join_node->filter != NULL) {
            OG_RETURN_IFERR(visit_cond_node(va, join_node->filter->root, visit_func));
        }
        if (join_node->join_cond != NULL) {
            OG_RETURN_IFERR(visit_cond_node(va, join_node->join_cond->root, visit_func));
        }
        OG_RETURN_IFERR(visit_join_node_cond(va, join_node->left, visit_func));
        return visit_join_node_cond(va, join_node->right, visit_func);
    }
    return OG_SUCCESS;
}

status_t visit_cond_node(visit_assist_t *va, cond_node_t *cond, visit_func_t visit_func)
{
    switch (cond->type) {
        case COND_NODE_OR:
        case COND_NODE_AND:
            OG_RETURN_IFERR(visit_cond_node(va, cond->left, visit_func));
            return visit_cond_node(va, cond->right, visit_func);

        case COND_NODE_COMPARE:
            return visit_cmp_node(va, cond->cmp, visit_func);
        default:
            return OG_SUCCESS;
    }
}

bool32 sql_cond_has_acstor_col(sql_stmt_t *stmt, cond_tree_t *cond, sql_query_t *subqry)
{
    if (subqry->cond_has_acstor_col || cond == NULL) {
        return subqry->cond_has_acstor_col;
    }
    cols_used_t used_cols;
    init_cols_used(&used_cols);
    sql_collect_cols_in_cond(cond->root, &used_cols);
    if (HAS_PRNT_OR_ANCSTR_COLS(used_cols.flags) || HAS_DYNAMIC_SUBSLCT(&used_cols)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

#ifdef __cplusplus
}
#endif
