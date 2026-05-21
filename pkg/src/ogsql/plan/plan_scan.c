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
 * plan_scan.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/plan_scan.c
 *
 * -------------------------------------------------------------------------
 */
#include "cbo_base.h"
#include "plan_scan.h"
#include "plan_query.h"
#include "cbo_join.h"
#include "srv_instance.h"
#include "table_parser.h"
#include "ogsql_table_func.h"
#include "plan_rbo.h"
#include "plan_range.h"
#include "ogsql_scan.h"
#include "ogsql_cbo_cost.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline status_t sql_set_mapped_table_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));

    if (table->type == FUNC_AS_TABLE) {
        table->cost = FUNC_TABLE_COST;
        return OG_SUCCESS;
    }

    if (table->subslct_tab_usage == SUBSELECT_4_ANTI_JOIN || table->subslct_tab_usage == SUBSELECT_4_ANTI_JOIN_NA) {
        table->cost = RBO_COST_FULL_TABLE_SCAN;
        return OG_SUCCESS;
    }

    table->cost = RBO_COST_SUB_QUERY_SCAN;
    return OG_SUCCESS;
}

static inline status_t sql_get_index_cond(sql_stmt_t *stmt, cond_tree_t *and_cond, cond_node_t *cond_node,
    cond_node_t **index_cond)
{
    if (and_cond == NULL) {
        *index_cond = cond_node;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(cm_stack_alloc(stmt->session->stack, sizeof(cond_node_t), (void **)index_cond));
    MEMS_RETURN_IFERR(memset_sp(*index_cond, sizeof(cond_node_t), 0, sizeof(cond_node_t)));

    (*index_cond)->type = COND_NODE_AND;
    (*index_cond)->left = and_cond->root;
    (*index_cond)->right = cond_node;
    return OG_SUCCESS;
}

static inline bool32 judge_sort_items(plan_assist_t *pa)
{
    if (pa->query->sort_items->count == 0) {
        return OG_TRUE;
    }

    sort_item_t *sort_item = NULL;
    uint32 i = 0;
    sort_direction_t direction;
    sort_item = (sort_item_t *)cm_galist_get(pa->query->sort_items, 0);
    direction = sort_item->direction;
    for (i = 1; i < pa->query->sort_items->count; i++) {
        sort_item = (sort_item_t *)cm_galist_get(pa->query->sort_items, i);
        if (direction != sort_item->direction) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static inline bool32 if_need_get_sort_index(plan_assist_t *pa, sql_table_t *table)
{
    if (!LIMIT_CLAUSE_OCCUR(&pa->query->limit) || table->equal_cols > 0 || INDEX_SORT_SCAN(table->scan_flag) ||
        judge_sort_items(pa) || table->cost <= RBO_COST_INDEX_LIST_SCAN ||
        table->opt_match_mode <= COLUMN_MATCH_2_BORDER_RANGE) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static inline bool32 check_apply_table_index(plan_assist_t *pa, sql_table_t *table)
{
    if (HAS_SPEC_TYPE_HINT(table->hint_info, INDEX_HINT, HINT_KEY_WORD_FULL)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

typedef struct st_rowid_scan_ctx {
    sql_stmt_t *stmt;
    plan_assist_t *pa;
    sql_table_t *table;
    bool32 is_temp;
} rowid_scan_ctx_t;

typedef struct st_certainty_check_ctx {
    plan_assist_t *pa;
    var_column_t *v_col;
} certainty_check_ctx_t;

typedef status_t (*rowid_set_binary_op_t)(sql_stmt_t*, plan_rowid_set_t*, plan_rowid_set_t*, 
                                           plan_rowid_set_t*, bool32);

static status_t alloc_rowid_array(sql_stmt_t *stmt, sql_array_t *arr, bool32 is_temp, char *name)
{
    return is_temp ? sql_array_init(arr, KNL_ROWID_ARRAY_SIZE, stmt, sql_stack_alloc)
                   : sql_create_array(stmt->context, arr, name, KNL_ROWID_ARRAY_SIZE);
}

static void copy_rowid_items(plan_rowid_set_t *dst, plan_rowid_set_t *src, uint32 offset)
{
    size_t byte_count;
    if (src->array.count == 0) {
        return;
    }
    byte_count = src->array.count * sizeof(pointer_t);
    (void)memcpy_s(dst->array.items + offset, byte_count, src->array.items, byte_count);
}

static status_t merge_rowid_arrays(sql_stmt_t *stmt, plan_rowid_set_t *left, plan_rowid_set_t *right,
                                    plan_rowid_set_t *out, bool32 is_temp)
{
    OG_RETURN_IFERR(alloc_rowid_array(stmt, &out->array, is_temp, NULL));
    copy_rowid_items(out, left, 0);
    copy_rowid_items(out, right, left->array.count);
    out->type = RANGE_LIST_NORMAL;
    out->array.count = left->array.count + right->array.count;
    return OG_SUCCESS;
}

static bool32 handle_union_special_cases(plan_rowid_set_t *left, plan_rowid_set_t *right, 
                                          plan_rowid_set_t *out, bool32 *done)
{
    *done = OG_TRUE;
    if (left->type == RANGE_LIST_FULL || right->type == RANGE_LIST_FULL) {
        out->type = RANGE_LIST_FULL;
        return OG_TRUE;
    }
    if (left->type == RANGE_LIST_EMPTY) {
        *out = *right;
        return OG_TRUE;
    }
    if (right->type == RANGE_LIST_EMPTY) {
        *out = *left;
        return OG_TRUE;
    }
    if (left->array.count + right->array.count > KNL_ROWID_ARRAY_SIZE) {
        out->type = RANGE_LIST_FULL;
        return OG_TRUE;
    }
    *done = OG_FALSE;
    return OG_FALSE;
}

status_t sql_union_rowid_set(sql_stmt_t *stmt, plan_rowid_set_t *l_set, plan_rowid_set_t *r_set,
                             plan_rowid_set_t *rowid_set, bool32 is_temp)
{
    bool32 handled;
    if (handle_union_special_cases(l_set, r_set, rowid_set, &handled)) {
        return OG_SUCCESS;
    }
    return merge_rowid_arrays(stmt, l_set, r_set, rowid_set, is_temp);
}

static bool32 handle_intersect_special_cases(plan_rowid_set_t *left, plan_rowid_set_t *right,
                                              plan_rowid_set_t *out, bool32 *done)
{
    *done = OG_TRUE;
    if (left->type == RANGE_LIST_EMPTY || right->type == RANGE_LIST_EMPTY) {
        out->type = RANGE_LIST_EMPTY;
        return OG_TRUE;
    }
    if (left->type == RANGE_LIST_FULL) {
        *out = *right;
        return OG_TRUE;
    }
    if (right->type == RANGE_LIST_FULL) {
        *out = *left;
        return OG_TRUE;
    }
    *done = OG_FALSE;
    return OG_FALSE;
}

status_t sql_intersect_rowid_set(sql_stmt_t *stmt, plan_rowid_set_t *l_set, plan_rowid_set_t *r_set,
                                 plan_rowid_set_t *rowid_set)
{
    bool32 handled;
    if (handle_intersect_special_cases(l_set, r_set, rowid_set, &handled)) {
        return OG_SUCCESS;
    }
    *rowid_set = (l_set->array.count > r_set->array.count) ? *r_set : *l_set;
    return OG_SUCCESS;
}

status_t sql_init_plan_rowid_set(sql_stmt_t *stmt, plan_rowid_set_t **rowid_set, bool32 is_temp)
{
    OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(plan_rowid_set_t), (void **)rowid_set));
    return alloc_rowid_array(stmt, &((*rowid_set)->array), is_temp, "ROWID set");
}

static bool32 verify_ancestor_column(plan_assist_t *pa, expr_node_t *node, uint32 tab)
{
    plan_assist_t *ancestor_pa;
    if (CBO_HAS_ONLY_FLAG(pa, CBO_CHECK_FILTER_IDX | CBO_CHECK_ANCESTOR_DRIVER)) {
        return OG_FALSE;
    }
    ancestor_pa = sql_get_ancestor_pa(pa, NODE_ANCESTOR(node));
    if (ancestor_pa != NULL && get_pa_table_by_id(ancestor_pa, tab)->plan_id == OG_INVALID_ID32) {
        return OG_FALSE;
    }
    pa->col_use_flag |= USE_ANCESTOR_COL;
    pa->max_ancestor = MAX(NODE_ANCESTOR(node), pa->max_ancestor);
    return OG_TRUE;
}

static bool32 verify_join_column(plan_assist_t *pa, uint32 col_tab, uint32 ref_tab)
{
    if (CBO_HAS_FLAG(pa, CBO_CHECK_FILTER_IDX)) {
        return OG_FALSE;
    }
    if (pa->tables[col_tab]->plan_id >= pa->tables[ref_tab]->plan_id) {
        return OG_FALSE;
    }
    if (!chk_tab_with_oper_map(pa, col_tab, ref_tab)) {
        return OG_FALSE;
    }
    pa->col_use_flag |= USE_SELF_JOIN_COL;
    return OG_TRUE;
}

static bool32 check_column_certain(certainty_check_ctx_t *ctx, expr_node_t *node)
{
    uint32 tab = NODE_TAB(node);
    return (NODE_ANCESTOR(node) > 0) ? verify_ancestor_column(ctx->pa, node, tab)
                                     : verify_join_column(ctx->pa, tab, ctx->v_col->tab);
}

static bool32 check_group_certain(plan_assist_t *pa, expr_node_t *node)
{
    if (NODE_VM_ANCESTOR(node) == 0) {
        return OG_FALSE;
    }
    pa->col_use_flag |= USE_ANCESTOR_COL;
    pa->max_ancestor = MAX(NODE_VM_ANCESTOR(node), pa->max_ancestor);
    return OG_TRUE;
}

static bool32 check_select_certain(expr_node_t *node)
{
    sql_select_t *sel = (sql_select_t *)VALUE_PTR(var_object_t, &node->value)->ptr;
    return (sel->type == SELECT_AS_VARIANT) && (sel->parent_refs->count == 0);
}

static bool32 is_always_certain_type(expr_node_type_t t)
{
    return (t == EXPR_NODE_CONST) || (t == EXPR_NODE_PARAM) || (t == EXPR_NODE_CSR_PARAM) ||
           (t == EXPR_NODE_PL_ATTR) || (t == EXPR_NODE_SEQUENCE) || (t == EXPR_NODE_PRIOR);
}

static status_t certainty_visitor(visit_assist_t *va, expr_node_t **node)
{
    certainty_check_ctx_t ctx;
    expr_node_type_t t;
    if (!va->result0) {
        return OG_SUCCESS;
    }
    ctx.pa = (plan_assist_t *)va->param0;
    ctx.v_col = (var_column_t *)va->param1;
    t = (*node)->type;
    if (is_always_certain_type(t)) {
        return OG_SUCCESS;
    }
    if (t == EXPR_NODE_COLUMN) {
        va->result0 = check_column_certain(&ctx, *node);
    } else if (t == EXPR_NODE_RESERVED) {
        va->result0 = sql_reserved_word_indexable(ctx.pa, *node, ctx.v_col->tab);
    } else if (t == EXPR_NODE_GROUP) {
        va->result0 = check_group_certain(ctx.pa, *node);
    } else if (t == EXPR_NODE_SELECT) {
        va->result0 = check_select_certain(*node);
    } else if (t == EXPR_NODE_V_ADDR) {
        va->result0 = sql_pair_type_is_plvar(*node);
    } else {
        va->result0 = OG_FALSE;
    }
    return OG_SUCCESS;
}

bool32 sql_expr_is_certain(plan_assist_t *pa, expr_tree_t *expr, var_column_t *v_col)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, NULL, NULL);
    va.param0 = pa;
    va.param1 = v_col;
    va.result0 = OG_TRUE;
    va.excl_flags = VA_EXCL_PRIOR;
    (void)visit_expr_tree(&va, expr, certainty_visitor);
    return va.result0;
}

static bool32 is_rowid_ref(expr_tree_t *e, uint32 tid)
{
    expr_node_t *r = e->root;
    return (r->type == EXPR_NODE_RESERVED) && (r->value.v_rid.res_id == RES_WORD_ROWID) && 
           (r->value.v_rid.tab_id == tid);
}

bool32 sql_rowid_expr_matched(expr_tree_t *expr, uint32 table_id)
{
    return is_rowid_ref(expr, table_id);
}

bool32 sql_rowid_cmp_matched(plan_assist_t *pa, sql_table_t *table, var_column_t *v_col,
                             expr_tree_t *l_expr, expr_tree_t *r_expr)
{
    return is_rowid_ref(l_expr, table->id) && sql_expr_is_certain(pa, r_expr, v_col);
}

status_t sql_fetch_expr_rowids(expr_tree_t *expr, plan_rowid_set_t *rid_set)
{
    expr_tree_t *cur;
    for (cur = expr; cur != NULL; cur = cur->next) {
        OG_RETURN_IFERR(sql_array_put(&rid_set->array, cur));
    }
    return OG_SUCCESS;
}

static bool32 is_rowid_in_cmp(cmp_type_t t)
{
    return (t == CMP_TYPE_IN) || (t == CMP_TYPE_EQUAL_ANY) || (t == CMP_TYPE_EQUAL_ALL);
}

static expr_tree_t *extract_rowid_expr(plan_assist_t *pa, sql_table_t *tbl, var_column_t *vc, cmp_node_t *cmp)
{
    expr_tree_t *l = cmp->left;
    expr_tree_t *r = cmp->right;
    if (is_rowid_in_cmp(cmp->type) || cmp->type == CMP_TYPE_EQUAL) {
        if (sql_rowid_cmp_matched(pa, tbl, vc, l, r)) {
            return r;
        }
    }
    if (cmp->type == CMP_TYPE_EQUAL) {
        if (sql_rowid_cmp_matched(pa, tbl, vc, r, l)) {
            return l;
        }
    }
    return NULL;
}

status_t sql_try_fetch_expr_rowid(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
                                  cmp_node_t *node, plan_rowid_set_t *rid_set)
{
    var_column_t vc;
    expr_tree_t *rid_expr;
    CM_POINTER2(node, rid_set);
    vc.tab = table->id;
    vc.col = OG_INVALID_ID16;
    vc.datatype = OG_TYPE_STRING;
    rid_expr = extract_rowid_expr(pa, table, &vc, node);
    if (rid_expr == NULL) {
        rid_set->type = RANGE_LIST_FULL;
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(sql_fetch_expr_rowids(rid_expr, rid_set));
    rid_set->type = RANGE_LIST_NORMAL;
    return OG_SUCCESS;
}

static status_t intersect_wrapper_fn(sql_stmt_t *s, plan_rowid_set_t *l, plan_rowid_set_t *r,
                                      plan_rowid_set_t *o, bool32 temp)
{
    return sql_intersect_rowid_set(s, l, r, o);
}

static status_t process_binary_node(rowid_scan_ctx_t *c, cond_node_t *n, plan_rowid_set_t *out,
                                     rowid_set_binary_op_t op)
{
    plan_rowid_set_t *ls = NULL;
    plan_rowid_set_t *rs = NULL;
    OG_RETURN_IFERR(sql_create_rowid_set(c->stmt, c->pa, c->table, n->left, &ls, c->is_temp));
    OG_RETURN_IFERR(sql_create_rowid_set(c->stmt, c->pa, c->table, n->right, &rs, c->is_temp));
    return op(c->stmt, ls, rs, out, c->is_temp);
}

static status_t create_rowid_set_impl(rowid_scan_ctx_t *ctx, cond_node_t *node, plan_rowid_set_t *result)
{
    if (node->type == COND_NODE_AND) {
        return process_binary_node(ctx, node, result, intersect_wrapper_fn);
    }
    if (node->type == COND_NODE_OR) {
        return process_binary_node(ctx, node, result, sql_union_rowid_set);
    }
    if (node->type == COND_NODE_TRUE) {
        result->type = RANGE_LIST_FULL;
        return OG_SUCCESS;
    }
    if (node->type == COND_NODE_FALSE) {
        result->type = RANGE_LIST_EMPTY;
        return OG_SUCCESS;
    }
    if (node->type == COND_NODE_COMPARE) {
        return sql_try_fetch_expr_rowid(ctx->stmt, ctx->pa, ctx->table, node->cmp, result);
    }
    return OG_SUCCESS;
}

status_t sql_create_rowid_set(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
                              cond_node_t *node, plan_rowid_set_t **plan_rid_set, bool32 is_temp)
{
    rowid_scan_ctx_t ctx;
    OG_RETURN_IFERR(sql_init_plan_rowid_set(stmt, plan_rid_set, is_temp));
    ctx.stmt = stmt;
    ctx.pa = pa;
    ctx.table = table;
    ctx.is_temp = is_temp;
    return create_rowid_set_impl(&ctx, node, *plan_rid_set);
}

static void set_rowid_scan_mode(sql_table_t *tbl, plan_rowid_set_t *set, bool32 is_temp)
{
    tbl->cost = RBO_COST_ROWID_SCAN;
    tbl->scan_mode = SCAN_MODE_ROWID;
    tbl->rowid_usable = OG_TRUE;
    tbl->rowid_set = is_temp ? NULL : (void *)set;
}

status_t sql_get_rowid_cost(sql_stmt_t *stmt, plan_assist_t *pa, cond_node_t *cond,
                            sql_table_t *table, bool32 is_temp)
{
    plan_rowid_set_t *set = NULL;
    OG_RETURN_IFERR(sql_create_rowid_set(stmt, pa, table, cond, &set, is_temp));
    if (set->type != RANGE_LIST_FULL) {
        set_rowid_scan_mode(table, set, is_temp);
    }
    return OG_SUCCESS;
}

static bool32 compare_plan_order(plan_assist_t *pa, uint32 src, uint32 dst)
{
    uint32 src_pid = pa->tables[src]->plan_id;
    uint32 dst_pid = pa->tables[dst]->plan_id;
    if (src_pid == dst_pid) {
        return OG_TRUE;
    }
    return (src_pid < dst_pid) && chk_tab_with_oper_map(pa, src, dst);
}

bool32 check_rowid_certain(plan_assist_t *pa, expr_node_t *node, uint32 table_id)
{
    uint32 tab = ROWID_NODE_TAB(node);
    if (ROWID_NODE_ANCESTOR(node) > 0) {
        return !CBO_HAS_ONLY_FLAG(pa, CBO_CHECK_FILTER_IDX | CBO_CHECK_ANCESTOR_DRIVER);
    }
    if (CBO_HAS_FLAG(pa, CBO_CHECK_FILTER_IDX)) {
        return OG_FALSE;
    }
    return compare_plan_order(pa, tab, table_id);
}

static expr_tree_t *find_rowid_peer(cmp_node_t *cmp, uint32 tid)
{
    expr_tree_t *l = cmp->left;
    expr_tree_t *r = cmp->right;
    if (!TREE_IS_RES_ROWID(l) || !TREE_IS_RES_ROWID(r)) {
        return NULL;
    }
    if (ROWID_EXPR_TAB(l) == tid) {
        return r;
    }
    if (ROWID_EXPR_TAB(r) == tid) {
        return l;
    }
    return NULL;
}

bool32 check_rowid_cmp_certain(plan_assist_t *pa, cmp_node_t *cmp, uint32 tab_id)
{
    expr_tree_t *peer = find_rowid_peer(cmp, tab_id);
    return (peer == NULL) ? OG_TRUE : check_rowid_certain(pa, peer->root, tab_id);
}

bool32 check_rowid_cond_certain(plan_assist_t *pa, cond_node_t *cond_node, uint32 tab_id)
{
    if (cond_node->type == COND_NODE_AND) {
        return check_rowid_cond_certain(pa, cond_node->left, tab_id) &&
               check_rowid_cond_certain(pa, cond_node->right, tab_id);
    }
    if (cond_node->type == COND_NODE_COMPARE && cond_node->cmp->type == CMP_TYPE_EQUAL) {
        return check_rowid_cmp_certain(pa, cond_node->cmp, tab_id);
    }
    return OG_TRUE;
}

bool32 check_rowid_join_for_hash(plan_assist_t *pa, uint32 tab_id)
{
    return (pa->table_count == 1) || check_rowid_cond_certain(pa, pa->cond->root, tab_id);
}

static bool32 is_cbo_disabled(sql_stmt_t *stmt, sql_query_t *query)
{
    if (stmt->context->opt_by_rbo) {
        return OG_TRUE;
    }
    if (!CBO_ON) {
        stmt->context->opt_by_rbo = OG_TRUE;
        return OG_TRUE;
    }
    if (HAS_SPEC_TYPE_HINT(query->hint_info, OPTIM_HINT, HINT_KEY_WORD_RULE)) {
        stmt->context->opt_by_rbo = OG_TRUE;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 verify_table_stats(sql_stmt_t *stmt, sql_table_t *tbl)
{
    if (!is_analyzed_table(stmt, tbl)) {
        stmt->context->opt_by_rbo = OG_TRUE;
        return OG_FALSE;
    }
    return OG_TRUE;
}

static bool32 verify_all_tables_stats(sql_stmt_t *stmt, sql_query_t *query)
{
    uint32 i;
    for (i = 0; i < query->tables.count; i++) {
        if (!verify_table_stats(stmt, (sql_table_t *)sql_array_get(&query->tables, i))) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

bool32 sql_match_cbo_cond(sql_stmt_t *stmt, sql_table_t *table, sql_query_t *query)
{
    if (is_cbo_disabled(stmt, query)) {
        return OG_FALSE;
    }
    if (table != NULL) {
        (void)verify_table_stats(stmt, table);
        return !stmt->context->opt_by_rbo;
    }
    return verify_all_tables_stats(stmt, query);
}

#define CBO_DEFAULT_INDEX_ROWID_PAGE_COST (double)0.20

void cbo_check_rowid_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table)
{
    if (!sql_match_cbo_cond(stmt, table, pa->query)) {
        return;
    }
    table->cost = CBO_DEFAULT_INDEX_ROWID_PAGE_COST;
    table->card = 1;
}

static bool32 check_rowid_hint(sql_table_t *tbl)
{
    if (!TABLE_HAS_ACCESS_METHOD_HINT(tbl)) {
        return OG_TRUE;
    }
    return HAS_SPEC_TYPE_HINT(tbl->hint_info, INDEX_HINT, HINT_KEY_WORD_ROWID);
}

bool32 cbo_can_rowid_scan(plan_assist_t *pa, sql_table_t *table)
{
    if (pa->cond == NULL || !table->rowid_exists) {
        return OG_FALSE;
    }
    if (!check_rowid_join_for_hash(pa, table->id)) {
        return OG_FALSE;
    }
    return check_rowid_hint(table);
}

bool32 sql_try_choose_rowid_scan(plan_assist_t *pa, sql_table_t *table)
{
    if (!cbo_can_rowid_scan(pa, table)) {
        return OG_FALSE;
    }
    if (sql_get_rowid_cost(pa->stmt, pa, pa->cond->root, table, OG_TRUE) != OG_SUCCESS) {
        cm_reset_error();
        return OG_FALSE;
    }
    if (table->scan_mode != SCAN_MODE_ROWID) {
        return OG_FALSE;
    }
    cbo_check_rowid_cost(pa->stmt, pa, table);
    return OG_TRUE;
}

static inline bool32 check_apply_table_full_scan(plan_assist_t *pa, sql_table_t *table)
{
    if (HAS_SPEC_TYPE_HINT(table->hint_info, INDEX_HINT, HINT_KEY_WORD_FULL)) {
        return OG_TRUE;
    }

    if (table->index == NULL) {
        return OG_TRUE;
    }

    if (TABLE_HAS_INDEX_HINT(table)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

status_t sql_check_table_indexable(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_tree_t *cond)
{
    if (pa->top_pa != NULL) {
        pa = pa->top_pa;
    }
    
    if (table->type != NORMAL_TABLE) {
        return sql_set_mapped_table_cost(stmt, pa, table);
    }

    OG_RETSUC_IFTRUE(table->remote_type != REMOTE_TYPE_LOCAL);

    if (pa->table_count == 1) {
        OG_RETSUC_IFTRUE(sql_try_choose_rowid_scan(pa, table));
    }

    sql_init_table_indexable(table, NULL);

    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    pa->cond = cond;

    if (!is_analyzed_table(stmt, table) || entity->cbo_table_stats == NULL ||
        !entity->cbo_table_stats->global_stats_exist) {
        return OG_SUCCESS;
    }
        
    OG_RETURN_IFERR(sql_init_table_scan_partition_info(stmt, pa, table));

    table->card = sql_estimate_table_card(pa, entity, table, cond);

    if (check_apply_table_index(pa, table)) {
        for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
            index_t *index = DC_TABLE_INDEX(&entity->table, idx_id);
            OG_CONTINUE_IFTRUE(index->desc.is_invalid);
            OG_CONTINUE_IFTRUE(TABLE_HAS_ACCESS_METHOD_HINT(table) &&
                               index_skip_in_hints(table, index->desc.slot));
            cbo_try_choose_index(stmt, pa, table, index);
        }
    }

    /* try multi index scan */
    cbo_try_choose_multi_index(stmt, pa, table, false);

    /* try seq scan */
    double seq_cost = CBO_MAX_COST;
    if (check_apply_table_full_scan(pa, table)) {
        seq_cost = sql_seq_scan_cost(stmt, pa, entity, table);

        sql_debug_scan_cost_info(stmt, table, "SEQ", NULL, seq_cost, NULL, NULL);
    }

    /*
     * If no index is selected, a seqscan is chosen.
     * Otherwise, compares the cost of index scan versus seqscan, selecting
     * the cheaper one, unless index is a unique index with full equality
     * predicates, in which case the index scan is prioritized regardless
     * of cost estimation.
     */
    if (table->index == NULL || prefer_table_scan(stmt, pa, table, seq_cost)) {
        sql_init_table_indexable(table, NULL);
        table->cost = seq_cost;
    }

    if (table->index != NULL && table->sub_tables == NULL) {
        /* for create proper scan range for index scan */
        table->cond = cond;
    }

    if (INDEX_ONLY_SCAN(table->scan_flag)) {
        OG_RETURN_IFERR(sql_make_index_col_map(pa, stmt, table));
    }

    return OG_SUCCESS;
}

static status_t sql_create_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
    plan_node_t **plan)
{
    plan_node_t *scan_plan = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&scan_plan) != OG_SUCCESS) {
        return OG_ERROR;
    }

    *plan = scan_plan;
    pa->cond = cond;
    scan_plan->type = PLAN_NODE_SCAN;
    scan_plan->plan_id = stmt->context->plan_count++;
    scan_plan->scan_p.table = table;
    scan_plan->scan_p.par_exec = OG_FALSE;
    scan_plan->scan_p.sort_items = pa->sort_items;
    scan_plan->cost = table->cost;
    scan_plan->start_cost = table->startup_cost;
    scan_plan->rows = table->card;
    if (table->rowid_usable) {
        if (table->rowid_set == NULL) {
            OG_RETURN_IFERR(sql_create_rowid_set(stmt, pa, table, cond->root, (plan_rowid_set_t**)&table->rowid_set, OG_FALSE));
        }
        scan_plan->scan_p.rowid_set = (plan_rowid_set_t*)table->rowid_set;
        return OG_SUCCESS;
    }
    return sql_create_scan_ranges(stmt, pa, table, &scan_plan->scan_p);
}

static bool32 check_expr_datatype_for_pruning(expr_node_t *col_node, expr_node_t *val_node)
{
    if (OG_IS_UNKNOWN_TYPE(val_node->datatype)) {
        return OG_FALSE;
    }
    if (NODE_DATATYPE(col_node) == NODE_DATATYPE(val_node)) {
        return OG_TRUE;
    }
    if (OG_IS_NUMERIC_TYPE2(col_node->datatype, val_node->datatype)) {
        if (OG_IS_INTEGER_TYPE(col_node->datatype)) {
            if (val_node->scale != 0 || col_node->size < val_node->size) {
                return OG_FALSE;
            }
            // "int32 = uint32" needs to return false, such as "where 1 = 2147483648"
            if (col_node->size == val_node->size &&
                ((OG_IS_UNSIGNED_INTEGER_TYPE(col_node->datatype) && OG_IS_SIGNED_INTEGER_TYPE(val_node->datatype)) ||
                (OG_IS_SIGNED_INTEGER_TYPE(col_node->datatype) && OG_IS_UNSIGNED_INTEGER_TYPE(val_node->datatype)))) {
                return OG_FALSE;
            }
            return OG_TRUE;
        }
        return OG_TRUE;
    }
    if (OG_IS_DATETIME_TYPE2(col_node->datatype, val_node->datatype)) {
        if (NODE_DATATYPE(col_node) == OG_TYPE_TIMESTAMP_TZ || NODE_DATATYPE(col_node) == OG_TYPE_TIMESTAMP_LTZ ||
            NODE_DATATYPE(col_node) == OG_TYPE_TIMESTAMP_TZ_FAKE) {
            return OG_FALSE;
        }
        return (bool32)(col_node->size >= val_node->size && col_node->precision >= val_node->precision);
    }
    if (OG_IS_VARLEN_TYPE(col_node->datatype)) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 sql_expr_in_index_range(sql_stmt_t *stmt, cmp_node_t *cmp_node, sql_array_t *index_array)
{
    plan_range_list_t *range_list = NULL;
    plan_range_t *plan_range = NULL;

    for (uint32 i = 0; i < index_array->count; i++) {
        range_list = (plan_range_list_t *)sql_array_get(index_array, i);
        if (range_list->type == RANGE_LIST_FULL) {
            continue;
        }
        for (uint32 j = 0; j < range_list->items->count; j++) {
            plan_range = (plan_range_t *)cm_galist_get(range_list->items, j);
            if (cmp_node->right == plan_range->left.expr) {
                return check_expr_datatype_for_pruning(cmp_node->left->root, cmp_node->right->root);
            }
            if (cmp_node->left == plan_range->left.expr) {
                return check_expr_datatype_for_pruning(cmp_node->right->root, cmp_node->left->root);
            }
        }
    }

    return OG_FALSE;
}

static bool32 is_equal_index_leading_column(sql_stmt_t *stmt, sql_table_t *table, cmp_node_t *cmp_node)
{
    uint32 col_id;
    expr_node_t *node = NULL;
    expr_node_t col_node;
    knl_column_t *knl_col = NULL;
    bool32 result = OG_FALSE;
    OGSQL_SAVE_STACK(stmt);
    for (uint16 i = 0; i < table->idx_equal_to; i++) {
        col_id = table->index->columns[i];
        knl_col = knl_get_column(table->entry->dc.handle, col_id);
        if (sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id, col_id) != OG_SUCCESS) {
            break;
        }
        if (sql_expr_node_equal(stmt, node, cmp_node->left->root, NULL) ||
            sql_expr_node_equal(stmt, node, cmp_node->right->root, NULL)) {
            result = OG_TRUE;
            break;
        }
    }
    OGSQL_RESTORE_STACK(stmt);
    return result;
}

static status_t sql_pruning_index_cond(sql_stmt_t *stmt, sql_table_t *table, cond_node_t *cond_node,
    cond_tree_t **index_cond, sql_array_t *index_array)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_pruning_index_cond(stmt, table, cond_node->left, index_cond, index_array));
            OG_RETURN_IFERR(sql_pruning_index_cond(stmt, table, cond_node->right, index_cond, index_array));
            break;
        case COND_NODE_COMPARE:
            if (cond_node->cmp->type != CMP_TYPE_EQUAL || !sql_expr_in_index_range(stmt, cond_node->cmp, index_array)) {
                return OG_SUCCESS;
            }
            // index on (c1,c2,c3), c1 = ? and c2 = ? and c3 = ?, optimize all
            // index on (c1,c2,c3), c1 = ? and c2 > ? and c3 = ?, only optimize c1 = ?
            if (table->idx_equal_to != table->index->column_count &&
                !is_equal_index_leading_column(stmt, table, cond_node->cmp)) {
                return OG_SUCCESS;
            }
            if (*index_cond == NULL) {
                OG_RETURN_IFERR(sql_create_cond_tree(stmt->context, index_cond));
            }
            OG_RETURN_IFERR(sql_merge_cond_tree_shallow(*index_cond, cond_node));
            cond_node->type = COND_NODE_TRUE;
            // fall through
        case COND_NODE_OR:
        default:
            break;
    }
    return OG_SUCCESS;
}

static bool32 cmp_node_in_cond(sql_stmt_t *stmt, cmp_node_t *cmp_node, cond_node_t *cond)
{
    switch (cond->type) {
        case COND_NODE_AND:
            return (bool32)(cmp_node_in_cond(stmt, cmp_node, cond->left) ||
                cmp_node_in_cond(stmt, cmp_node, cond->right));
        case COND_NODE_COMPARE:
            return sql_cmp_node_equal(stmt, cmp_node, cond->cmp, NULL);
        case COND_NODE_OR:
        default:
            return OG_FALSE;
    }
}

static void eliminate_index_cond_in_query_cond(sql_stmt_t *stmt, cond_node_t *query_node, cond_node_t *index_cond)
{
    switch (query_node->type) {
        case COND_NODE_AND:
            eliminate_index_cond_in_query_cond(stmt, query_node->left, index_cond);
            eliminate_index_cond_in_query_cond(stmt, query_node->right, index_cond);
            break;
        case COND_NODE_COMPARE:
            if (cmp_node_in_cond(stmt, query_node->cmp, index_cond)) {
                query_node->type = COND_NODE_TRUE;
            }
            break;
        case COND_NODE_OR:
        default:
            break;
    }
}

static status_t sql_pruning_single_index_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    plan_node_t *plan)
{
    sql_array_t *index_array = &plan->scan_p.index_array;
    cond_tree_t *index_cond = NULL;

    OG_RETURN_IFERR(sql_pruning_index_cond(stmt, table, table->cond->root, &index_cond, index_array));
    if (index_cond == NULL) {
        return OG_SUCCESS;
    }
    // CBO outer join optimize, pa->cond may be cloned from original cond
    if (table->cond->root != pa->cond->root) {
        table->cond = index_cond;
        eliminate_index_cond_in_query_cond(stmt, pa->cond->root, table->cond->root);
        OG_RETURN_IFERR(try_eval_logic_cond(stmt, pa->cond->root));
    } else {
        OG_RETURN_IFERR(try_eval_logic_cond(stmt, table->cond->root));
        table->cond = index_cond;
    }
    table->index_cond_pruning = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_try_pruning_single_index_cond(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    plan_node_t *plan)
{
    if (table->scan_mode != SCAN_MODE_INDEX || table->cond == NULL || pa->cond == NULL ||
        stmt->context->parallel != 0 || !g_instance->sql.enable_index_cond_pruning ||
        stmt->context->type != OGSQL_TYPE_SELECT || pa->query->for_update) {
        return OG_SUCCESS;
    }

    if (table->idx_equal_to == 0) {
        return OG_SUCCESS;
    }

    return sql_pruning_single_index_cond(stmt, pa, table, plan);
}

status_t sql_create_table_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, cond_tree_t *cond, sql_table_t *table,
    plan_node_t **plan)
{
    sql_table_t *sub_table = NULL;
    plan_node_t *scan_plan = NULL;

    OG_RETURN_IFERR(sql_create_scan_plan(stmt, pa, cond, table, &scan_plan));
    if (table->sub_tables == NULL) {
        *plan = scan_plan;
        return sql_try_pruning_single_index_cond(stmt, pa, table, scan_plan);
    }

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)plan));
    (*plan)->type = PLAN_NODE_CONCATE;
    (*plan)->plan_id = stmt->context->plan_count++;

    OG_RETURN_IFERR(sql_create_list(stmt, &(*plan)->cnct_p.keys));
    OG_RETURN_IFERR(sql_create_concate_key(stmt, (*plan)->cnct_p.keys, table));

    OG_RETURN_IFERR(sql_create_list(stmt, &(*plan)->cnct_p.plans));
    OG_RETURN_IFERR(cm_galist_insert((*plan)->cnct_p.plans, scan_plan));

    for (uint32 i = 0; i < table->sub_tables->count; i++) {
        sub_table = (sql_table_t *)cm_galist_get(table->sub_tables, i);
        OG_RETURN_IFERR(sql_create_scan_plan(stmt, pa, cond, sub_table, &scan_plan));
        OG_RETURN_IFERR(cm_galist_insert((*plan)->cnct_p.plans, scan_plan));
    }
    return OG_SUCCESS;
}

static inline bool32 sql_chk_need_remove(cols_used_t *cols_used, uint32 ancestor, uint32 tab)
{
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr_node = NULL;
    biqueue_node_t *end_node = NULL;
    expr_node_t *node = NULL;
    uint32 id = (ancestor == 1) ? PARENT_IDX : ANCESTOR_IDX;

    cols_que = &cols_used->cols_que[id];
    curr_node = biqueue_first(cols_que);
    end_node = biqueue_end(cols_que);

    while (curr_node != end_node) {
        node = OBJECT_OF(expr_node_t, curr_node);
        if (tab == TAB_OF_NODE(node) && ancestor == ANCESTOR_OF_NODE(node)) {
            return OG_TRUE;
        }
        curr_node = curr_node->next;
    }
    return OG_FALSE;
}

static inline bool32 if_need_remove(cmp_node_t *cmp_node, uint32 ancestor, uint32 tab)
{
    cols_used_t left_cols_used;
    cols_used_t right_cols_used;

    init_cols_used(&left_cols_used);
    init_cols_used(&right_cols_used);
    sql_collect_cols_in_expr_tree(cmp_node->left, &left_cols_used);
    sql_collect_cols_in_expr_tree(cmp_node->right, &right_cols_used);

    return (bool32)(sql_chk_need_remove(&left_cols_used, ancestor, tab) ||
        sql_chk_need_remove(&right_cols_used, ancestor, tab));
}

static inline status_t sql_remove_join_cond_node(sql_stmt_t *stmt, cond_node_t *cond_node, uint32 ancestor, uint32 tab)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));

    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->left, ancestor, tab));
            OG_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->right, ancestor, tab));
            try_eval_logic_and(cond_node);
            break;

        case COND_NODE_OR:
            OG_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->left, ancestor, tab));
            OG_RETURN_IFERR(sql_remove_join_cond_node(stmt, cond_node->right, ancestor, tab));
            try_eval_logic_or(cond_node);
            break;

        case COND_NODE_COMPARE:
            if (if_need_remove(cond_node->cmp, ancestor, tab)) {
                cond_node->type = COND_NODE_TRUE;
            }
            break;
        default:
            break;
    }

    return OG_SUCCESS;
}

static inline status_t sql_remove_join_cond(sql_stmt_t *stmt, cond_tree_t **cond_tree, uint32 ancestor, uint32 tab)
{
    if (*cond_tree == NULL) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_remove_join_cond_node(stmt, (*cond_tree)->root, ancestor, tab));

    return OG_SUCCESS;
}

static inline status_t remove_join_cond_4_join_node(sql_stmt_t *stmt, sql_join_node_t *join_node, uint32 ancestor,
    uint32 tab)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(remove_join_cond_4_join_node(stmt, join_node->left, ancestor, tab));
    OG_RETURN_IFERR(remove_join_cond_4_join_node(stmt, join_node->right, ancestor, tab));

    OG_RETURN_IFERR(sql_remove_join_cond(stmt, &join_node->filter, ancestor, tab));

    if (IS_INNER_JOIN(join_node)) {
        return OG_SUCCESS;
    }
    return sql_remove_join_cond(stmt, &join_node->join_cond, ancestor, tab);
}

static inline bool32 chk_remove_table_push_down_join(select_node_t *node)
{
    if (node->type == SELECT_NODE_QUERY) {
        return (node->query->cond_has_acstor_col ? OG_FALSE : OG_TRUE);
    }
    if (chk_remove_table_push_down_join(node->left)) {
        return OG_TRUE;
    }
    return chk_remove_table_push_down_join(node->right);
}

static inline status_t remove_join_cond_4_slct_node(sql_stmt_t *stmt, select_node_t *select_node,
                                                    uint32 ancestor, uint32 tab);
static inline status_t remove_join_cond_4_query(sql_stmt_t *stmt, sql_query_t *sub_query, uint32 ancestor, uint32 tab)
{
    OG_RETURN_IFERR(sql_remove_join_cond(stmt, &sub_query->cond, ancestor, tab));

    if (sub_query->join_assist.outer_node_count > 0) {
        OG_RETURN_IFERR(remove_join_cond_4_join_node(stmt, sub_query->join_assist.join_node, ancestor, tab));
        OG_RETURN_IFERR(sql_remove_join_cond(stmt, &sub_query->filter_cond, ancestor, tab));
    }

    // pushed-down column can not be pushed down to sub select in ssa again
    for (uint32 loop = 0; loop < sub_query->tables.count; ++loop) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&sub_query->tables, loop);
        if (table->type != SUBSELECT_AS_TABLE && table->type != VIEW_AS_TABLE) {
            continue;
        }
        OG_RETURN_IFERR(remove_join_cond_4_slct_node(stmt, table->select_ctx->root, ancestor + 1, tab));
        if (chk_remove_table_push_down_join(table->select_ctx->root)) {
            TABLE_CBO_UNSET_FLAG(table, SELTION_PUSH_DOWN_JOIN);
        }
    }

    // check if query cond still has ancstor col
    if (sub_query->cond_has_acstor_col) {
        if (sub_query->cond != NULL) {
            cols_used_t cols_used;
            init_cols_used(&cols_used);
            sql_collect_cols_in_cond(sub_query->cond->root, &cols_used);
            if (!(HAS_PRNT_OR_ANCSTR_COLS(cols_used.flags) || HAS_DYNAMIC_SUBSLCT(&cols_used))) {
                sub_query->cond_has_acstor_col = OG_FALSE;
            }
        } else {
            sub_query->cond_has_acstor_col = OG_FALSE;
        }
    }
    return OG_SUCCESS;
}

static inline status_t remove_join_cond_4_slct_node(sql_stmt_t *stmt, select_node_t *select_node,
                                                    uint32 ancestor, uint32 tab)
{
    // The query node is processed separately to avoid the scenario where the node is already in queue.
    if (select_node->type == SELECT_NODE_QUERY) {
        return remove_join_cond_4_query(stmt, select_node->query, ancestor, tab);
    }
    biqueue_t que;
    biqueue_init(&que);
    sql_collect_select_nodes(&que, select_node);

    select_node_t *obj = NULL;
    biqueue_node_t *curr_node = biqueue_first(&que);
    biqueue_node_t *end_node = biqueue_end(&que);

    while (curr_node != end_node) {
        obj = OBJECT_OF(select_node_t, curr_node);
        if (obj != NULL && obj->query != NULL) {
            OG_RETURN_IFERR(remove_join_cond_4_query(stmt, obj->query, ancestor, tab));
        }
        curr_node = BINODE_NEXT(curr_node);
    }
    return OG_SUCCESS;
}

void reset_select_node_cbo_status(select_node_t *node);
void cbo_unset_select_node_table_flag(select_node_t *select_node, uint32 cbo_flag, bool32 recurs);

static inline status_t replace_table_in_array(sql_array_t *tables, sql_table_t *old_table, sql_table_t *new_table)
{
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        if (table->id == old_table->id) {
            return sql_array_set(tables, i, new_table);
        }
    }
    return OG_SUCCESS;
}

static inline status_t replace_table_id_4_split_nl(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type != EXPR_NODE_COLUMN || NODE_ANCESTOR(*node) > 0 || va->result1 != NODE_TAB(*node)) {
        return OG_SUCCESS;
    }
    (*node)->value.v_col.tab = va->result0;
    return OG_SUCCESS;
}

static inline status_t convert_node_to_nl_batch(sql_stmt_t *stmt, sql_join_node_t *join_node, sql_table_t *old_table,
    sql_table_t *new_table)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.result0 = new_table->id;
    visit_ass.result1 = old_table->id;
    visit_ass.excl_flags = SQL_EXCL_NONE;
    join_node->oper = JOIN_OPER_NL_BATCH;
    OG_RETURN_IFERR(replace_table_in_array(&join_node->tables, old_table, new_table));
    OG_RETURN_IFERR(replace_table_in_array(&join_node->right->tables, old_table, new_table));
    return visit_cond_node(&visit_ass, join_node->filter->root, replace_table_id_4_split_nl);
}

static inline status_t gen_rowid_scan_nl_node(sql_stmt_t *stmt, sql_join_node_t *sub_node, sql_table_t *table,
    sql_join_node_t **join_node)
{
    sql_join_node_t *tab_node = NULL;
    OG_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &tab_node));
    OG_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_INNER, NULL, NULL, sub_node, tab_node, join_node));
    (*join_node)->oper = JOIN_OPER_NL;
    (*join_node)->cost = sub_node->cost;
    return OG_SUCCESS;
}

static bool32 if_subslct_has_drive(visit_assist_t *va, expr_node_t *node)
{
    sql_select_t *select_ctx = (sql_select_t *)node->value.v_obj.ptr;
    if (select_ctx->parent_refs->count == 0) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i < select_ctx->parent_refs->count; i++) {
        parent_ref_t *parent_ref = (parent_ref_t *)cm_galist_get(select_ctx->parent_refs, i);
        if (parent_ref->tab == va->result1) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t chk_drive_in_expr_node(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_COLUMN || (*node)->type == EXPR_NODE_TRANS_COLUMN) {
        if (NODE_ANCESTOR(*node) == 0 && va->result1 == NODE_TAB(*node)) {
            va->result0 = OG_TRUE;
        }
        return OG_SUCCESS;
    }

    if (NODE_IS_RES_ROWID(*node)) {
        if (ROWID_NODE_ANCESTOR(*node) == 0 && va->result1 == ROWID_NODE_TAB(*node)) {
            va->result0 = OG_TRUE;
        }
        return OG_SUCCESS;
    }

    if ((*node)->type == EXPR_NODE_SELECT && if_subslct_has_drive(va, *node)) {
        va->result0 = OG_TRUE;
    }
    return OG_SUCCESS;
}

static inline bool32 if_expr_has_drive(visit_assist_t *visit_ass, expr_tree_t *expr)
{
    (void)visit_expr_tree(visit_ass, expr, chk_drive_in_expr_node);
    return (bool32)visit_ass->result0;
}

static inline bool32 if_aggr_node_has_drive(visit_assist_t *visit_ass, galist_t *aggrs)
{
    expr_node_t *func_node = NULL;
    for (uint32 i = 0; i < aggrs->count; i++) {
        func_node = (expr_node_t *)cm_galist_get(aggrs, i);
        OG_RETVALUE_IFTRUE(if_expr_has_drive(visit_ass, func_node->argument), OG_TRUE);
    }
    return OG_FALSE;
}

static inline bool32 if_group_exprs_has_drive(visit_assist_t *visit_ass, galist_t *group_exprs)
{
    expr_tree_t *expr = NULL;
    for (uint32 i = 0; i < group_exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(group_exprs, i);
        OG_RETVALUE_IFTRUE(if_expr_has_drive(visit_ass, expr), OG_TRUE);
    }
    return OG_FALSE;
}

static inline bool32 if_groupby_has_drive(visit_assist_t *visit_ass, galist_t *group_sets)
{
    group_set_t *group_set = NULL;
    for (uint32 i = 0; i < group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(group_sets, i);
        OG_RETVALUE_IFTRUE(if_group_exprs_has_drive(visit_ass, group_set->items), OG_TRUE);
    }
    return OG_FALSE;
}

static inline bool32 if_sort_items_has_drive(visit_assist_t *visit_ass, galist_t *sort_items)
{
    sort_item_t *item = NULL;
    for (uint32 i = 0; i < sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(sort_items, i);
        OG_RETVALUE_IFTRUE(if_expr_has_drive(visit_ass, item->expr), OG_TRUE);
    }
    return OG_FALSE;
}

static inline bool32 if_orderby_has_drive(visit_assist_t *visit_ass)
{
    sql_query_t *query = visit_ass->query;
    if (query->has_distinct || query->group_sets->count > 0 || query->winsort_list->count > 0) {
        return OG_FALSE;
    }
    return if_sort_items_has_drive(visit_ass, query->sort_items);
}


#define SPLIT_TABLE_COUNT 2
static status_t try_split_nl_node(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t **join_root)
{
    return OG_SUCCESS;
}

bool32 sql_has_hash_join_oper(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return OG_FALSE;
    }
    if (join_node->oper >= JOIN_OPER_HASH) {
        return OG_TRUE;
    }
    if (sql_has_hash_join_oper(join_node->left)) {
        return OG_TRUE;
    }
    return sql_has_hash_join_oper(join_node->right);
}

static status_t sql_finalize_join_tree(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t **join_root)
{
    uint32 step = pa->query->tables.count;
    pa->is_final_plan = OG_TRUE;

    OG_RETURN_IFERR(sql_build_join_tree(stmt, pa, join_root));

    OG_RETURN_IFERR(try_split_nl_node(stmt, pa, join_root));

    pa->query->join_root = *join_root;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, step * step * sizeof(uint8), (void **)&pa->join_oper_map));

    OG_RETURN_IFERR(perfect_tree_and_gen_oper_map(pa, step, *join_root));

    return OG_SUCCESS;
}

static status_t remove_push_down_cond_4_slct(sql_stmt_t *statement, plan_assist_t *plan_ass, sql_select_t *slct,
                                                uint32 cur_tab)
{
    OG_RETSUC_IFTRUE(slct->parent_refs->count == 0);
    galist_t *ref_lst = slct->parent_refs;
    OG_RETURN_IFERR(sql_create_list(statement, &slct->parent_refs));

    int32_t idx = 0;
    while (idx < ref_lst->count) {
        parent_ref_t *ref = (parent_ref_t *)cm_galist_get(ref_lst, idx++);
        uint32 ref_tab = ref->tab;
        /*
         * need remove pushed down join cond if current tab planId < ref tab planId when two table join as NL
         * need remove all pushed down join cond when two table join as others type.
         */
        if (chk_tab_with_oper_map(plan_ass, cur_tab, ref_tab) &&
            plan_ass->tables[cur_tab]->plan_id >= plan_ass->tables[ref_tab]->plan_id) {
            OG_RETURN_IFERR(cm_galist_insert(slct->parent_refs, ref));
        } else {
            OG_RETURN_IFERR(remove_join_cond_4_slct_node(statement, slct->root, PARENT_IDX, ref_tab));
        }
    }

    return OG_SUCCESS;
}

static status_t remove_pushed_down_cond_4_subslct_table(sql_stmt_t *statement, plan_assist_t *plan_ass,
    sql_array_t *tbl_arr)
{
    int32_t idx = 0;
    while (idx < tbl_arr->count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(tbl_arr, idx++);
        sql_select_t *tab_slct = tbl->select_ctx;
        if (tbl->type == SUBSELECT_AS_TABLE || tbl->type == VIEW_AS_TABLE) {
            OG_RETURN_IFERR(remove_push_down_cond_4_slct(statement, plan_ass, tab_slct, tbl->id));
        }
    }

    return OG_SUCCESS;
}

static status_t optimized_with_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_root)
{
    OG_RETURN_IFERR(sql_finalize_join_tree(stmt, plan_ass, join_root));
    OG_RETURN_IFERR(remove_pushed_down_cond_4_subslct_table(stmt, plan_ass, &plan_ass->query->tables));
    return OG_SUCCESS;
}

status_t sql_create_query_scan_plan(sql_stmt_t *stmt, plan_assist_t *plan_ass, plan_node_t **plan)
{
    if (plan_ass->table_count > 1) {
        sql_join_node_t *join_root = NULL;
        OG_RETURN_IFERR(optimized_with_join_tree(stmt, plan_ass, &join_root));
        plan_ass->query->cost = join_root->cost;
        plan_ass->cbo_flags = CBO_NONE_FLAG;
        return sql_create_join_plan(stmt, plan_ass, join_root, join_root->filter, plan);
    }

    if (sql_dynamic_sampling_table_stats(stmt, plan_ass) != OG_SUCCESS) {
        cm_reset_error();
    }

    plan_ass->has_parent_join = (bool8)plan_ass->query->cond_has_acstor_col;
    CBO_SET_FLAGS(plan_ass, CBO_CHECK_FILTER_IDX | CBO_CHECK_JOIN_IDX);
    OG_RETURN_IFERR(sql_check_table_indexable(stmt, plan_ass, plan_ass->tables[0], plan_ass->cond));
    plan_ass->query->cost.card = plan_ass->tables[0]->card;
    plan_ass->query->cost.cost = plan_ass->tables[0]->cost;
    plan_ass->query->cost.startup_cost = plan_ass->tables[0]->startup_cost;
    if (plan_ass->query->join_card == OG_INVALID_INT64) {
        plan_ass->query->join_card = TABLE_CBO_FILTER_ROWS(plan_ass->tables[0]);
    }

    plan_ass->cbo_flags = CBO_NONE_FLAG;
    return sql_create_table_scan_plan(stmt, plan_ass, plan_ass->cond, plan_ass->tables[0], plan);
}

#ifdef __cplusplus
}
#endif
