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
#include "ogsql_table_func.h"
#include "ogsql_func.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "plan_rbo.h"
#include "plan_range.h"
#include "cm_log.h"
#include "ogsql_hint_verifier.h"
#include "ogsql_optim_common.h"
#include "ogsql_cond_reorganise.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COND_PRIORITY_UNKNOWN 6
#define COND_PRIORITY_COMPARE 1
#define COND_PRIORITY_OR 3
#define COND_PRIORITY_AND 2
#define COND_PRIORITY_NOT 5
#define COND_PRIORITY_TRUE 4
#define COND_PRIORITY_FALSE 0

#define STACK_INIT_CAPACITY 32
#define STACK_EXPAND_FACTOR 2
#define STACK_LEVEL_NODES 2
#define STACK_EXPAND_THRESHOLD 0.8f  // stack expand threshold

typedef struct {
    cond_node_t **conds;
    size_t capacity;
    size_t top;
} dynamic_stack_t;

// Used for conditional reorganisation sorting.
// FALSE > CMP > AND > OR > TRUE > NOT > UNKNOWN
static const int32 g_cond_priority[] = {
    COND_PRIORITY_UNKNOWN,  // COND_NODE_UNKNOWN
    COND_PRIORITY_COMPARE,  // COND_NODE_COMPARE
    COND_PRIORITY_OR,       // COND_NODE_OR
    COND_PRIORITY_AND,      // COND_NODE_AND
    COND_PRIORITY_NOT,      // COND_NODE_NOT
    COND_PRIORITY_TRUE,     // COND_NODE_TRUE
    COND_PRIORITY_FALSE,    // COND_NODE_FALSE
};

static bool32 og_is_elementary_expr_node(expr_node_t *node, uint32 level);
static bool32 og_validate_simple_func(expr_node_t *func, uint32 level)
{
    expr_tree_t *current_arg_node = func->argument;
    bool32 is_all_args_simple = OG_TRUE;
    uint32 next_recur_level = level + 1;

    while (current_arg_node != NULL && is_all_args_simple) {
        bool32 arg_is_simple = og_is_elementary_expr_node(current_arg_node->root, next_recur_level);
        if (!arg_is_simple) {
            is_all_args_simple = OG_FALSE;
        }
        current_arg_node = current_arg_node->next;
    }

    return is_all_args_simple;
}

#define EXPR_NESTING_MAX_DEPTH 3

static bool32 og_is_elementary_expr_node(expr_node_t *node, uint32 level)
{
    bool32 level_exceed = (level > EXPR_NESTING_MAX_DEPTH);
    if (level_exceed) {
        return OG_FALSE;
    }

    expr_node_type_t node_type = node->type;
    bool32 is_simple_node = OG_FALSE;
    uint32 next_level = level + 1;

    if (node_type == EXPR_NODE_COLUMN || node_type == EXPR_NODE_CONST || node_type == EXPR_NODE_PARAM ||
        node_type == EXPR_NODE_CSR_PARAM || node_type == EXPR_NODE_RESERVED || node_type == EXPR_NODE_SEQUENCE ||
        node_type == EXPR_NODE_TRANS_COLUMN) {
        is_simple_node = OG_TRUE;
    } else if (node_type == EXPR_NODE_ADD || node_type == EXPR_NODE_SUB || node_type == EXPR_NODE_MUL ||
               node_type == EXPR_NODE_DIV || node_type == EXPR_NODE_BITAND || node_type == EXPR_NODE_BITOR ||
               node_type == EXPR_NODE_BITXOR || node_type == EXPR_NODE_MOD || node_type == EXPR_NODE_CAT ||
               node_type == EXPR_NODE_LSHIFT || node_type == EXPR_NODE_RSHIFT) {
        bool32 left_simple = og_is_elementary_expr_node(node->left, next_level);
        bool32 right_simple = og_is_elementary_expr_node(node->right, next_level);
        is_simple_node = (left_simple && right_simple);
    } else if (node_type == EXPR_NODE_FUNC) {
        is_simple_node = og_validate_simple_func(node, level);
    }

    return is_simple_node;
}

static bool32 og_validate_expr_tree_is_simple(expr_tree_t *expr)
{
    bool32 has_next_expr = (expr->next != NULL);
    if (has_next_expr) {
        return OG_FALSE;
    }

    uint32 init_recur_level = 0;
    bool32 is_simple_node = og_is_elementary_expr_node(expr->root, init_recur_level);
    return is_simple_node;
}

static bool32 check_single_col(const cmp_node_t *cmp_node, const expr_tree_t *l_exprtr,
                                      const expr_tree_t *r_exprtr)
{
    if (l_exprtr == NULL) {
        return OG_FALSE;
    }
    if (!og_validate_expr_tree_is_simple(cmp_node->left)) {
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
} cond_check_ctx_t;

static bool32 og_check_single_col_filter_cond(const cond_check_ctx_t *ctx, int32 *result)
{
    bool32 cmp1_single_col = check_single_col(ctx->cmp1, ctx->l1, ctx->r1);
    if (cmp1_single_col) {
        *result = 0;
        return OG_TRUE;
    }

    bool32 cmp2_single_col = check_single_col(ctx->cmp2, ctx->l2, ctx->r2);
    if (cmp2_single_col) {
        *result = 1;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static inline bool32 is_single_select_expr(const expr_tree_t *expr)
{
    return (expr != NULL) && (expr->root->type == EXPR_NODE_SELECT) && (expr->next == NULL);
}

static inline bool32 is_valid_index_condition(sql_table_t *tbl)
{
    return (INDEX_ONLY_SCAN(tbl->scan_flag) ||
            ((tbl->index->primary || tbl->index->unique) && tbl->idx_equal_to == tbl->index->column_count));
}

static bool32 og_check_exists_subslct_with_index(const expr_tree_t *l_exprtr, const expr_tree_t *r_exprtr,
                                                 int32 *result)
{
    bool32 l_expr_has_value = (l_exprtr != NULL);
    bool32 single_select_check_pass = is_single_select_expr(r_exprtr);
    bool32 single_select_check_fail = !single_select_check_pass;
    bool32 early_return_condition = (l_expr_has_value || single_select_check_fail);

    if (early_return_condition) {
        return OG_FALSE;
    }

    sql_select_t *sub_select = (sql_select_t *)r_exprtr->root->value.v_obj.ptr;
    
    const select_node_t *select_stmt_root = sub_select->root;
    bool32 root_is_query_node = (select_stmt_root->type == SELECT_NODE_QUERY);
    bool32 root_not_query_node = !root_is_query_node;

    if (root_not_query_node) {
        return OG_FALSE;
    }

    const sql_query_t *first_sub_query = sub_select->first_query;
    const sql_array_t *query_tables_array = &first_sub_query->tables;
    uint32 sub_query_table_num = query_tables_array->count;
    bool32 more_than_one_table = (sub_query_table_num > 1);

    if (more_than_one_table) {
        return OG_FALSE;
    }

    sql_table_t *table = (sql_table_t *)sql_array_get(&sub_select->first_query->tables, 0);
    bool32 has_valid_index = (table->index != NULL && is_valid_index_condition(table));
    if (has_valid_index) {
        *result = 1;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static bool32 og_validate_basic_expr_node_for_reorder(expr_node_t *exprn)
{
    bool32 is_basic_expr_type = OG_FALSE;
    expr_node_type_t node_type = exprn->type;

    if (node_type == EXPR_NODE_COLUMN || node_type == EXPR_NODE_TRANS_COLUMN || node_type == EXPR_NODE_CONST ||
        node_type == EXPR_NODE_PARAM || node_type == EXPR_NODE_CSR_PARAM || node_type == EXPR_NODE_RESERVED ||
        node_type == EXPR_NODE_SELECT || node_type == EXPR_NODE_PL_ATTR) {
        is_basic_expr_type = OG_TRUE;
    } else if (node_type == EXPR_NODE_V_ADDR) {
        return sql_pair_type_is_plvar(exprn);
    }

    return is_basic_expr_type;
}

static bool32 og_validate_basic_expr_tree_for_reorder(expr_tree_t *exprtr)
{
    for (; exprtr != NULL; exprtr = exprtr->next) {
        if (!og_validate_basic_expr_node_for_reorder(exprtr->root)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 check_cond_node(const cond_node_t *cmp_cond)
{
    bool32 is_compare_node = (cmp_cond->type == COND_NODE_COMPARE);
    if (!is_compare_node) {
        return OG_FALSE;
    }

    const cmp_node_t *target_cmp_node = cmp_cond->cmp;
    bool32 left_expr_valid = og_validate_basic_expr_tree_for_reorder(target_cmp_node->left);
    bool32 right_expr_valid = og_validate_basic_expr_tree_for_reorder(target_cmp_node->right);
    bool32 both_expr_valid = (left_expr_valid && right_expr_valid);

    if (both_expr_valid) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static bool32 og_compare_cond_types(const cond_node_t *cond1, const cond_node_t *cond2, int32 *result)
{
    const cond_node_t *first_cond_node = cond1;
    bool32 first_node_check_pass = check_cond_node(first_cond_node);
    if (first_node_check_pass) {
        int32 *res_buffer = result;
        *res_buffer = 0;
        return OG_TRUE;
    }
    const cond_node_t *second_cond_node = cond2;
    bool32 second_node_check_pass = check_cond_node(second_cond_node);
    if (second_node_check_pass) {
        *result = 0;
        return OG_TRUE;
    }
    const cond_node_type_t type_cond_first = first_cond_node->type;
    const cond_node_type_t type_cond_second = second_cond_node->type;
    bool32 cond_types_match = (type_cond_first == type_cond_second);
    bool32 cond_types_mismatch = !cond_types_match;
    if (cond_types_mismatch) {
        const uint32 priority_idx_1 = (uint32)type_cond_first;
        const uint32 priority_idx_2 = (uint32)type_cond_second;
        const int32 priority_delta = g_cond_priority[priority_idx_1] - g_cond_priority[priority_idx_2];
        *result = priority_delta;
        return OG_TRUE;
    }
    bool32 is_cmp_node_type = (type_cond_first == COND_NODE_COMPARE);
    bool32 is_non_cmp_node = !is_cmp_node_type;
    if (is_non_cmp_node) {
        *result = 0;
        OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] Same condition types(Non-CMP)");
        return OG_TRUE;
    }
    return OG_FALSE;
}

// Equality condition with both sides as simple columns
static bool32 og_check_cmp_join_cond(const cond_check_ctx_t *ctx, int32 *result)
{
    bool32 cmp1_is_equal = (ctx->cmp1->type == CMP_TYPE_EQUAL);
    bool32 l1_nonnull = (ctx->l1 != NULL);
    bool32 r1_nonnull = (ctx->r1 != NULL);
    bool32 l1_is_col_node = (l1_nonnull && ctx->l1->root->type == EXPR_NODE_COLUMN);
    bool32 r1_is_col_node = (r1_nonnull && ctx->r1->root->type == EXPR_NODE_COLUMN);
    bool32 cmp1_join_cond_valid = (cmp1_is_equal && l1_is_col_node && r1_is_col_node);

    if (cmp1_join_cond_valid) {
        *result = 0;
        return OG_TRUE;
    }

    bool32 cmp2_is_equal = (ctx->cmp2->type == CMP_TYPE_EQUAL);
    bool32 l2_nonnull = (ctx->l2 != NULL);
    bool32 r2_nonnull = (ctx->r2 != NULL);
    bool32 l2_is_col_node = (l2_nonnull && ctx->l2->root->type == EXPR_NODE_COLUMN);
    bool32 r2_is_col_node = (r2_nonnull && ctx->r2->root->type == EXPR_NODE_COLUMN);
    bool32 cmp2_join_cond_valid = (cmp2_is_equal && l2_is_col_node && r2_is_col_node);

    if (cmp2_join_cond_valid) {
        *result = 1;
        return OG_TRUE;
    }

    return OG_FALSE;
}

typedef bool32 (*cond_check_func_t)(const cond_check_ctx_t *, int32 *);

static bool32 og_check_exists_subslct_adapter(const cond_check_ctx_t *ctx, int32 *res)
{
    return og_check_exists_subslct_with_index(ctx->l2, ctx->r2, res);
}

static cond_check_func_t s_check_funcs[] = {
    og_check_single_col_filter_cond,  // Single-column filter condition check
    og_check_cmp_join_cond,           // Join condition check
    og_check_exists_subslct_adapter   // Subquery index scan check
};

static bool32 og_compare_cmp_nodes(const cmp_node_t *cmp1, const cmp_node_t *cmp2, int32 *result)
{
    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] Same condition types(CMP)");

    const expr_tree_t *l1 = cmp1->left;
    const expr_tree_t *l2 = cmp2->left;
    const expr_tree_t *r1 = cmp1->right;
    const expr_tree_t *r2 = cmp2->right;

    cond_check_ctx_t ctx = { cmp1, cmp2, l1, l2, r1, r2 };

    for (uint32 i = 0; i < sizeof(s_check_funcs) / sizeof(s_check_funcs[0]); ++i) {
        if (s_check_funcs[i](&ctx, result) == OG_TRUE) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t og_cond_list_init(sql_stmt_t *statement, galist_t **cmp_lst, galist_t **and_lst)
{
    if (cmp_lst == NULL || and_lst == NULL) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] cmp_lst or and_lst is invalid.");
        return OG_ERROR;
    }
    if (sql_push(statement, sizeof(galist_t), (void **)cmp_lst) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Cmp_list push failed.");
        return OG_ERROR;
    }
    cm_galist_init(*cmp_lst, statement, sql_stack_alloc);

    if (sql_push(statement, sizeof(galist_t), (void **)and_lst) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] And_list push failed.");
        return OG_ERROR;
    }
    cm_galist_init(*and_lst, statement, sql_stack_alloc);
    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] Cond_list init success.");
    return OG_SUCCESS;
}

// stack dynamic expansion
static status_t og_dynamic_stack_expand(sql_stmt_t *statement, dynamic_stack_t *stack)
{
    bool32 stack_is_null = (stack == NULL);
    if (stack_is_null) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Stack is NULL.");
        return OG_ERROR;
    }

    size_t expand_factor = STACK_EXPAND_FACTOR;
    size_t new_stack_cap = stack->capacity * expand_factor;
    cond_node_t **new_cond_nodes = NULL;
    cond_node_t **old_cond_nodes = stack->conds;

    size_t new_mem_size = sizeof(cond_node_t *) * new_stack_cap;
    new_cond_nodes = (cond_node_t **)malloc(new_mem_size);
    bool32 malloc_failed = (new_cond_nodes == NULL);
    if (malloc_failed) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Stack malloc failed.");
        free(old_cond_nodes);
        return OG_ERROR;
    }

    size_t copy_src_size = sizeof(cond_node_t *) * stack->top;
    status_t memcpy_ret = memcpy_s(new_cond_nodes, new_mem_size, stack->conds, copy_src_size);
    if (memcpy_ret != EOK) {
        free(new_cond_nodes);
        MEMS_RETURN_IFERR(memcpy_ret);
    }

    stack->conds = new_cond_nodes;
    stack->capacity = new_stack_cap;

    bool32 old_conds_valid = (old_cond_nodes != NULL);
    if (old_conds_valid) {
        free(old_cond_nodes);
    }

    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] Stack expanded to capacity:%zu", new_stack_cap);
    return OG_SUCCESS;
}

// flatten the condition tree to a list(Preorder traversal)
static status_t og_flatten_cond_node(sql_stmt_t *statement, cond_node_t *root_cond, galist_t *cmp_lst,
                                     galist_t *and_lst)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));

    // Initialize queue
    dynamic_stack_t stack = { 0 };
    stack.capacity = STACK_INIT_CAPACITY;

    stack.conds = (cond_node_t **)malloc(sizeof(cond_node_t *) * stack.capacity);
    if (stack.conds == NULL) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Stack malloc failed.");
        return OG_ERROR;
    }

    if (root_cond == NULL) {
        OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] NULL condition, condition flatten is invalid.");
        free(stack.conds);
        return OG_SUCCESS;
    }

    // Enqueue initial condition
    stack.conds[stack.top++] = root_cond;

    while (stack.top > 0) {
        if (stack.top > stack.capacity) {
            OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Condition stack out of range.");
            return OG_ERROR;
        }
        --stack.top;
        cond_node_t *curr_cond = stack.conds[stack.top];

        if (curr_cond->type == COND_NODE_AND) {
            // Process AND node
            if ((cm_galist_insert(and_lst, curr_cond)) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[CONDITION_REORGANISE] AND list insert error.");
                free(stack.conds);
                return OG_ERROR;
            }
            // Expand queue capacity(reserve 20% free space)
            if ((float)stack.top + STACK_LEVEL_NODES > (float)stack.capacity * STACK_EXPAND_THRESHOLD) {
                OG_RETURN_IFERR(og_dynamic_stack_expand(statement, &stack));
            }

            if (curr_cond->right != NULL) {
                stack.conds[stack.top++] = curr_cond->right;
            }
            if (curr_cond->left != NULL) {
                stack.conds[stack.top++] = curr_cond->left;
            }
        } else {
            if (cm_galist_insert(cmp_lst, curr_cond) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Condition list insert error.");
                free(stack.conds);
                return OG_ERROR;
            }
        }
    }

    if (stack.conds != NULL) {
        free(stack.conds);
    }
    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] Flattened condition tree SUCCESS");
    return OG_SUCCESS;
}

// Condition priority comparison function
typedef void (*reorder_cmp_func_t)(const cond_node_t *, const cond_node_t *, int32 *);
static void og_reorder_cond_func(const cond_node_t *condition1, const cond_node_t *condition2, int32 *result)
{
    bool32 cond_type_cmp_done = og_compare_cond_types(condition1, condition2, result);
    if (cond_type_cmp_done) {
        return;
    }

    const cmp_node_t *cmp_node1 = condition1->cmp;
    const cmp_node_t *cmp_node2 = condition2->cmp;
    bool32 cmp_node_cmp_done = og_compare_cmp_nodes(cmp_node1, cmp_node2, result);
    if (cmp_node_cmp_done) {
        return;
    }

    *result = 0;
}

typedef struct {
    sql_stmt_t *statement;
    galist_t *cmp_lst;
    reorder_cmp_func_t cmp_func;
} merge_sort_ctx_t;

static void og_merge_arrays_to_temp(merge_sort_ctx_t *ctx, cond_node_t **temp_array, int32 l, int32 mid_idx, int32 r)
{
    int32 tmp_arr_idx = 0;
    int32 left_cursor = l;
    int32 right_cursor = mid_idx + 1;

    while (left_cursor <= mid_idx && right_cursor <= r) {
        cond_node_t *list_item1 = (cond_node_t *)cm_galist_get(ctx->cmp_lst, left_cursor);
        cond_node_t *list_item2 = (cond_node_t *)cm_galist_get(ctx->cmp_lst, right_cursor);
        int32 compare_result = 0;

        ctx->cmp_func(list_item1, list_item2, &compare_result);

        if (compare_result <= 0) {
            temp_array[tmp_arr_idx++] = list_item1;
            left_cursor++;
        } else {
            temp_array[tmp_arr_idx++] = list_item2;
            right_cursor++;
        }
    }

    while (left_cursor <= mid_idx) {
        temp_array[tmp_arr_idx++] = (cond_node_t *)cm_galist_get(ctx->cmp_lst, left_cursor++);
    }
    while (right_cursor <= r) {
        temp_array[tmp_arr_idx++] = (cond_node_t *)cm_galist_get(ctx->cmp_lst, right_cursor++);
    }
}

static status_t og_merge_cmp_list(merge_sort_ctx_t *ctx, int32 l, int32 mid_idx, int32 r)
{
    int32 array_length = r - l + 1;
    size_t temp_mem_size = sizeof(cond_node_t *) * array_length;
    cond_node_t **temp_array = (cond_node_t **)malloc(temp_mem_size);

    if (temp_array == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, temp_mem_size, "merge sort temp array");
        return OG_ERROR;
    }

    og_merge_arrays_to_temp(ctx, temp_array, l, mid_idx, r);

    for (int32 write_idx = 0; write_idx < array_length; write_idx++) {
        int32 target_pos = l + write_idx;
        cm_galist_set(ctx->cmp_lst, target_pos, temp_array[write_idx]);
    }

    free(temp_array);
    return OG_SUCCESS;
}

// Merge sort implementation for condition ordering
static status_t og_sort_cmp_list(merge_sort_ctx_t *ctx, int32 l, int32 r)
{
    const int32 sort_range_start = l;
    const int32 sort_range_end = r;
    bool32 need_recursive_sort = OG_TRUE;

    if (sort_range_start >= sort_range_end) {
        need_recursive_sort = OG_FALSE;
    }

    if (!need_recursive_sort) {
        return OG_SUCCESS;
    }

    int32 mid_idx = l + (r - l) / 2;
    const int32 range_length = sort_range_end - sort_range_start;
    const int32 half_range_len = range_length / 2;
    const int32 partition_index = sort_range_start + half_range_len;

    status_t sort_left_segment = og_sort_cmp_list(ctx, sort_range_start, partition_index);
    bool32 left_sort_failed = (sort_left_segment != OG_SUCCESS);
    if (left_sort_failed) {
        OG_LOG_RUN_WAR("Left segment sort failed (range: %d-%d)", sort_range_start, partition_index);
        return OG_ERROR;
    }

    const int32 right_segment_start = partition_index + 1;
    status_t sort_right_segment = og_sort_cmp_list(ctx, right_segment_start, sort_range_end);
    bool32 right_sort_failed = (sort_right_segment != OG_SUCCESS);
    if (right_sort_failed) {
        OG_LOG_RUN_WAR("Right segment sort failed (range: %d-%d)", right_segment_start, sort_range_end);
        return OG_ERROR;
    }

    return og_merge_cmp_list(ctx, l, mid_idx, r);
}

// Condition sorting (merge sort)
static status_t og_reorder_cmp_list(sql_stmt_t *statement, galist_t *cmp_lst, reorder_cmp_func_t cmp_func)
{
    if (cmp_lst->count <= 1) {
        return OG_SUCCESS;
    }

    int32 l = 0;
    int32 r = (int32)cmp_lst->count - 1;
    merge_sort_ctx_t ctx = { statement, cmp_lst, cmp_func };

    if (og_sort_cmp_list(&ctx, l, r) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Merge sort failed.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

typedef struct {
    cond_tree_t *cond_tree;
    galist_t *cmp_lst;
    galist_t *and_lst;
    cond_node_t *prev_and_cond;
    cond_node_t *prev_cmp_cond;
} reorg_ctx_t;

static status_t og_reorganise_recursive(uint32 index, reorg_ctx_t *ctx)
{
    bool32 index_out_of_range = (index >= ctx->cmp_lst->count);
    if (index_out_of_range) {
        return OG_SUCCESS;
    }

    cond_node_t *current_cmp_cond = (cond_node_t *)cm_galist_get(ctx->cmp_lst, index);
    int32 and_list_idx = (int32)index - 1;
    cond_node_t *current_and_cond = (cond_node_t *)cm_galist_get(ctx->and_lst, and_list_idx);

    current_and_cond->left = ctx->prev_cmp_cond;
    current_and_cond->right = current_cmp_cond;

    bool32 has_prev_and_cond = (ctx->prev_and_cond != NULL);
    if (has_prev_and_cond) {
        ctx->prev_and_cond->right = current_and_cond;
    } else {
        ctx->cond_tree->root = current_and_cond;
    }

    ctx->prev_and_cond = current_and_cond;
    ctx->prev_cmp_cond = current_cmp_cond;

    uint32 next_recur_index = index + 1;
    return og_reorganise_recursive(next_recur_index, ctx);
}

// Condition tree reorganization
static status_t og_reorganise_cond_tree(sql_stmt_t *statement, galist_t *cmp_lst, galist_t *and_lst,
                                        cond_tree_t *cond_tree)
{
    OG_RETURN_IFERR(sql_stack_safe(statement));

    if (cmp_lst->count == 0) {
        cond_tree->root = NULL;
        return OG_SUCCESS;
    }

    cond_node_t *first_cmp_cond = (cond_node_t *)cm_galist_get(cmp_lst, 0);
    cond_tree->root = first_cmp_cond;

    if (cmp_lst->count == 1) {
        return OG_SUCCESS;
    }

    uint32 index = 1;
    reorg_ctx_t ctx = { cond_tree, cmp_lst, and_lst, NULL, first_cmp_cond };
    return og_reorganise_recursive(index, &ctx);
}

static void print_cond_list(galist_t *cond_list, const char *flag)
{
    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] %s reorganise, the order of conditions is:", flag);
    for (uint32 i = 0; i < cond_list->count; i++) {
        cond_node_t *node = (cond_node_t *)cm_galist_get(cond_list, i);
        OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] condition type: %d, condition ptr: %p", node->type, (void *)node);
    }
}

// Condition tree processing: flatten -> sort -> reorganize
static status_t og_cond_reorganise(sql_stmt_t *statement, sql_query_t *qry, galist_t *cmp_lst, galist_t *and_lst)
{
    status_t flatten_ret = og_flatten_cond_node(statement, qry->cond->root, cmp_lst, and_lst);
    bool32 flatten_failed = (flatten_ret != OG_SUCCESS);
    if (flatten_failed) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Condition tree flatten failed.");
        return OG_ERROR;
    }
    print_cond_list(cmp_lst, "Before");  // for debug

    reorder_cmp_func_t condition_sort_func = og_reorder_cond_func;
    status_t cond_list_sort_status = og_reorder_cmp_list(statement, cmp_lst, condition_sort_func);

    bool32 cond_sort_failure = (cond_list_sort_status != OG_SUCCESS);
    if (cond_sort_failure) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Condition tree sort failed.");
        return OG_ERROR;
    }

    cond_tree_t *final_cond_tree = qry->cond;
    galist_t *reorg_cmp_list = cmp_lst;
    galist_t *reorg_and_list = and_lst;

    status_t reorg_exec_status = og_reorganise_cond_tree(statement, reorg_cmp_list, reorg_and_list, final_cond_tree);

    bool32 reorg_succeed = (reorg_exec_status == OG_SUCCESS);
    bool32 reorg_failed = !reorg_succeed;

    if (reorg_failed) {
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] %s", "Condition tree reorganise failed.");
        return OG_ERROR;
    }
    print_cond_list(cmp_lst, "After");

    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] %s", "Condition reorganise success.");

    return OG_SUCCESS;
}

status_t og_transf_cond_reorder(sql_stmt_t *statement, sql_query_t *qry)
{
    if (!ogsql_opt_param_is_enable(statement, g_instance->sql.enable_pred_reorder, OPT_PRED_REORDER)) {
        return OG_SUCCESS;
    }

    OG_RETSUC_IFTRUE(qry->cond == NULL || qry->cond->root->type != COND_NODE_AND);

    galist_t *cmp_lst = NULL;
    galist_t *and_lst = NULL;

    OGSQL_SAVE_STACK(statement);

    if (og_cond_list_init(statement, &cmp_lst, &and_lst) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Condition list init failed.");
        return OG_ERROR;
    }

    if (og_cond_reorganise(statement, qry, cmp_lst, and_lst) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(statement);
        OG_LOG_RUN_ERR("[CONDITION_REORGANISE] Condition reorganise failed.");
        return OG_ERROR;
    }

    OGSQL_RESTORE_STACK(statement);
    OG_LOG_DEBUG_INF("[CONDITION_REORGANISE] Condition reorganise for change order success.");
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
