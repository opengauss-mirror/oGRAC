/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * expl_plan.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_plan.h
 *
 * -------------------------------------------------------------------------
 */
#include "expl_plan.h"
#include "cm_row.h"
#include "cm_text.h"
#include "ogsql_scan.h"
#include "ogsql_insert.h"
#include "expl_predicate.h"
#include "plan_rbo.h"

#define EXPL_SGL_INDENT_SIZE 2
#define EXPL_DEPTH_CALC_LEVEL 2
static inline bool32 sort_order_by_rownum(plan_node_t *plan)
{
    return (g_instance->sql.topn_threshold != 0 &&
            plan->query_sort.rownum_upper <= g_instance->sql.topn_threshold);
}

typedef enum {
    INDEX_MODE_MULTI_PARTS_SCAN = 0,
    INDEX_MODE_FAST_FULL_SCAN,
    INDEX_MODE_FULL_SCAN,
    INDEX_MODE_OPTIMIZED_RANGE_SCAN,
    INDEX_MODE_UNIQUE_SCAN,
    INDEX_MODE_SKIP_SCAN,
    INDEX_MODE_RANGE_SCAN
} index_mode_type_t;

typedef struct {
    bool32 idx_cond;
    index_mode_type_t idx_mode;
} index_mode_t;

static char* g_index_mode_oper[] = {
    "INDEX MULTI PARTS SCAN",
    "INDEX FAST FULL SCAN",
    "INDEX FULL SCAN",
    "OPTIMIZED INDEX RANGE SCAN",
    "INDEX UNIQUE SCAN",
    "INDEX SKIP SCAN",
    "INDEX RANGE SCAN"
};

static char* g_minus_names[] = {
    "MINUS",
    "INTERSECT",
    "INTERSECT ALL",
    "EXCEPT ALL"
};

static char* g_group_by_names[] = {
    "SORT GROUP BY",
    "MERGE SORT GROUP BY",
    "HASH GROUP BY",
    "INDEX GROUP BY"
};

static char *g_distinct_names[] = {
    "SORT DISTINCT",
    "HASH DISTINCT",
    "INDEX DISTINCT"
};

static char* g_join_oper[][2] = {
    { "",                           "" },
    { "NESTED LOOPS",               "NESTED LOOPS" },
    { "NESTED LOOPS",               "NESTED LOOPS" },
    { "NESTED LOOPS OUTER",         "NESTED LOOPS OUTER ANTI" },
    { "NESTED LOOPS FULL",          "NESTED LOOPS FULL" },
    { "HASH JOIN(R)",               "HASH JOIN(L)" },
    { "HASH JOIN OUTER(R)",         "HASH JOIN OUTER(L)" },
    { "HASH JOIN FULL(R)",          "HASH JOIN FULL(L)" },
    { "HASH JOIN OUTER(R)",         "HASH JOIN OUTER(L)" },
    { "MERGE JOIN",                 "MERGE JOIN" },
    { "MERGE JOIN OUTER",           "MERGE JOIN OUTER" },
    { "MERGE JOIN FULL",            "MERGE JOIN FULL" },
    { "HASH JOIN SEMI(R)",          "HASH JOIN SEMI(L)" },
    { "HASH JOIN ANTI(R)",          "HASH JOIN ANTI(L)" },
    { "HASH JOIN ANTI NA(R)",       "HASH JOIN ANTI NA(L)" },
    { "HASH JOIN RIGHT SEMI(R)",    "HASH JOIN RIGHT SEMI(L)" },
    { "HASH JOIN RIGHT ANTI(R)",    "HASH JOIN RIGHT ANTI(L)" },
    { "HASH JOIN RIGHT ANTI NA(R)", "HASH JOIN RIGHT ANTI NA(L)" },
    { "HASH JOIN PAR(R)",           "HASH JOIN PAR(L)" },
};

status_t expl_format_plan_node(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan, uint32 depth);
static status_t expl_format_join_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan, uint32 depth);

static inline status_t expl_row_put_text_data(expl_helper_t *helper, expl_col_type_t type, text_t *row_data)
{
    helper->fmt_sizes[type] = MAX(helper->fmt_sizes[type], row_data->len);
    return row_put_text(&helper->ra, row_data);
}

static status_t expl_format_plan_id(expl_helper_t *helper)
{
    char buff[OG_MAX_INT32_STRLEN + 1] = {0};
    int32 row_id = helper->row_helper.id++;
    int32 len = snprintf_s(buff, OG_MAX_INT32_STRLEN + 1, OG_MAX_INT32_STRLEN, "%lld", row_id);
    if (SECUREC_UNLIKELY(len == -1)) {
        return OG_ERROR;
    }

    text_t rowid_str = {buff, len};
    return expl_row_put_text_data(helper, EXPL_COL_TYPE_ID, &rowid_str);
}

static status_t expl_expand_text(text_t *in, text_t *out, uint32 depth)
{
    uint32 indent_size = MIN(OG_MAX_DFLT_VALUE_LEN - 1, depth * EXPL_SGL_INDENT_SIZE);
    if (indent_size != 0) {
        (void)memset_s(out->str, OG_MAX_DFLT_VALUE_LEN - 1, ' ', indent_size);
    }

    uint32 text_size = MIN(OG_MAX_DFLT_VALUE_LEN - indent_size - 1, in->len);
    if (text_size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(out->str + indent_size, OG_MAX_DFLT_VALUE_LEN - indent_size - 1,
                                   in->str, text_size));
    }

    out->len = indent_size + text_size;

    return OG_SUCCESS;
}

static status_t expl_format_plan_operation(expl_helper_t *helper)
{
    status_t ret = expl_expand_text(helper->row_helper.operation, &helper->content, helper->depth);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[EXPLAIN] Failed to extend the operation of the plan.");
        return ret;
    }

    return expl_row_put_text_data(helper, EXPL_COL_TYPE_OPERATION, &helper->content);
}

static status_t expl_format_plan_owner(expl_helper_t *helper)
{
    if (helper->row_helper.owner == NULL) {
        return row_put_null(&helper->ra);
    }

    return expl_row_put_text_data(helper, EXPL_COL_TYPE_OWNER, helper->row_helper.owner);
}

static status_t expl_format_plan_name(expl_helper_t *helper)
{
    row_helper_t *row_helper = &helper->row_helper;
    if (row_helper->name == NULL && row_helper->alias == NULL) {
        return row_put_null(&helper->ra);
    }

    char buff[OG_MAX_DFLT_VALUE_LEN] = {0};
    text_t *name = row_helper->name;
    uint32 offset = 0;
    if (name != NULL && name->str != NULL && name->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buff, OG_MAX_DFLT_VALUE_LEN, name->str, name->len));
        offset = name->len;
    }

    text_t *alias = row_helper->alias;
    if (alias != NULL && alias->str != NULL && alias->len > 0) {
        if (offset != 0) {
            MEMS_RETURN_IFERR(memcpy_s(buff + offset, OG_MAX_DFLT_VALUE_LEN - offset, " ", 1));
            offset++;
        }
        MEMS_RETURN_IFERR(memcpy_s(buff + offset, OG_MAX_DFLT_VALUE_LEN - offset, alias->str, alias->len));
        offset += alias->len;
    }

    text_t new_name = {buff, offset};
    return expl_row_put_text_data(helper, EXPL_COL_TYPE_TABLE, &new_name);
}

static status_t expl_format_plan_rows(expl_helper_t *helper)
{
    if (!(CBO_ON)) {
        return row_put_null(&helper->ra);
    }

    char buff[OG_MAX_INT64_STRLEN + 1] = {0};
    int32 len = snprintf_s(buff, OG_MAX_INT64_STRLEN + 1, OG_MAX_INT64_STRLEN, "%lld", helper->row_helper.rows);
    if (SECUREC_UNLIKELY(len == -1)) {
        return OG_ERROR;
    }

    text_t rows_str = {buff, len};
    return expl_row_put_text_data(helper, EXPL_COL_TYPE_ROWS, &rows_str);
}

static status_t expl_format_plan_cost(expl_helper_t *helper)
{
    if (!(CBO_ON)) {
        return row_put_null(&helper->ra);
    }

    char buff[OG_MAX_INT64_STRLEN + 1] = {0};
    int64 cost = (int64)helper->row_helper.cost;
    int32 len = snprintf_s(buff, OG_MAX_INT64_STRLEN + 1, OG_MAX_INT64_STRLEN, "%lld", cost);
    if (SECUREC_UNLIKELY(len == -1)) {
        return OG_ERROR;
    }

    text_t cost_str = {buff, len};
    return expl_row_put_text_data(helper, EXPL_COL_TYPE_COST, &cost_str);
}

static status_t expl_format_plan_start_cost(expl_helper_t *helper)
{
    if (!(CBO_ON)) {
        return row_put_null(&helper->ra);
    }

    char buff[OG_MAX_INT64_STRLEN + 1] = {0};
    int64 start_cost = (int64)helper->row_helper.start_cost;
    int32 len = snprintf_s(buff, OG_MAX_INT64_STRLEN + 1, OG_MAX_INT64_STRLEN, "%lld", start_cost);
    if (SECUREC_UNLIKELY(len == -1)) {
        return OG_ERROR;
    }

    text_t start_cost_str = {buff, len};
    return expl_row_put_text_data(helper, EXPL_COL_TYPE_START_COST, &start_cost_str);
}

static status_t expl_format_plan_bytes(expl_helper_t *helper)
{
    return row_put_null(&helper->ra);
}

static status_t expl_format_plan_remarks(expl_helper_t *helper)
{
    return row_put_null(&helper->ra);
}

expl_column_t g_expl_columns[] = {{EXPL_COL_TYPE_ID, {"Id", 2}, expl_format_plan_id},
                                  {EXPL_COL_TYPE_OPERATION, {"Operation", 9}, expl_format_plan_operation},
                                  {EXPL_COL_TYPE_OWNER, {"Owner", 5}, expl_format_plan_owner},
                                  {EXPL_COL_TYPE_TABLE, {"Name", 4}, expl_format_plan_name},
                                  {EXPL_COL_TYPE_ROWS, {"Rows", 4}, expl_format_plan_rows},
                                  {EXPL_COL_TYPE_COST, {"Cost", 4}, expl_format_plan_cost},
                                  {EXPL_COL_TYPE_START_COST, {"StartCost", 9}, expl_format_plan_start_cost},
                                  {EXPL_COL_TYPE_BYTES, {"Bytes", 5}, expl_format_plan_bytes},
                                  {EXPL_COL_TYPE_REMARK, {"Remark", 6}, expl_format_plan_remarks}};

void expl_row_helper_init(row_helper_t *helper, plan_node_t *plan_node, text_t *operation, text_t *owner, text_t *name,
                          text_t *alias)
{
    helper->operation = operation;
    helper->owner = owner;
    helper->name = name;
    helper->alias = alias;

    if (plan_node != NULL) {
        helper->rows = plan_node->rows;
        helper->cost = plan_node->cost;
        helper->start_cost = plan_node->start_cost;
    }
}

static void expl_init_display_column(sql_stmt_t *statement, expl_helper_t *helper)
{
    helper->display_option = FORMAT_MASK_BASIC;
    uint32 display_param = statement->session->plan_display_format == 0 ?
                           g_instance->sql.plan_display_format : statement->session->plan_display_format;
    helper->display_option &= display_param;
    return;
}

status_t expl_helper_init(sql_stmt_t *statement, expl_helper_t *helper, uint32 mtrl_id, text_t *plan_text)
{
    (void)memset_s(helper, sizeof(expl_helper_t), 0, sizeof(expl_helper_t));
    for (int32 i = 0; i < EXPL_COL_TYPE_MAX; i++) {
        helper->fmt_sizes[i] = g_expl_columns[i].name.len;
    }

    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&(helper->row_buf)));
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&(helper->content.str)));
    helper->mtrl_id = mtrl_id;
    helper->plan_output = plan_text;
    helper->first_fetch = OG_TRUE;

    // init display column
    expl_init_display_column(statement, helper);

    return OG_SUCCESS;
}

text_t *expl_get_explcol_name(uint32 idx)
{
    if (idx >= EXPL_COL_TYPE_MAX) {
        return NULL;
    }
    return &g_expl_columns[idx].name;
}

status_t expl_format_plan_node_row(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
    uint32 depth, char *oper_str, text_t *owner, text_t *name, text_t *alias)
{
    text_t oper = { oper_str, strlen(oper_str) };
    helper->depth = depth;
    expl_row_helper_init(&helper->row_helper, plan_node, &oper, owner, name, alias);
    row_init(&helper->ra, helper->row_buf, OG_MAX_ROW_SIZE, EXPL_COL_TYPE_MAX);

    for (int32 i = 0; i < EXPL_COL_TYPE_MAX; i++) {
        expl_column_func_t expl_column_func = g_expl_columns[i].expl_column_func;
        OG_RETURN_IFERR(expl_column_func(helper));
    }
    return mtrl_insert_row(&statement->mtrl, helper->mtrl_id, helper->row_buf, &helper->row_id);
}

static status_t expl_format_expr_node_plan(visit_assist_t *v_ast, expr_node_t **exprn)
{
    expl_helper_t *helper = (expl_helper_t *)v_ast->param0;
    if ((*exprn)->type != EXPR_NODE_SELECT) {
        return OG_SUCCESS;
    }

    v_ast->result0 = OG_TRUE;
    // Just to obtain whether there is a selectstatement in the expr
    if (v_ast->result1 == OG_FALSE) {
        return OG_SUCCESS;
    }
    uint32 ssa_id = (*exprn)->value.v_obj.id;
    sql_select_t *select = (sql_select_t *)sql_array_get(helper->ssa, ssa_id);
    plan_node_t *plan_node = select->plan;

    if (plan_node->type != PLAN_NODE_SELECT || plan_node == sql_get_plan(v_ast->stmt)) {
        return OG_SUCCESS;
    }
    return expl_format_plan_node(v_ast->stmt, helper, plan_node->select_p.next, v_ast->result2);
}

static status_t expl_format_aggr_node_plan(sql_stmt_t *statement, expl_helper_t *helper, expr_node_t *exprn,
                                           uint32 depth)
{
    visit_assist_t v_ast = {0};
    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.excl_flags = VA_EXCL_PRIOR;
    v_ast.param0 = (void *)helper;
    v_ast.result0 = OG_FALSE;
    v_ast.result1 = OG_TRUE;
    v_ast.result2 = depth;
    return visit_expr_node(&v_ast, &exprn, expl_format_expr_node_plan);
}

static status_t expl_format_expr_tree_plan(sql_stmt_t *statement, expl_helper_t *helper, expr_tree_t *exprt,
                                           uint32 depth)
{
    visit_assist_t v_ast = {0};
    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.excl_flags = VA_EXCL_PRIOR;
    v_ast.param0 = (void *)helper;
    v_ast.result0 = OG_FALSE;  // selectstatement in the expr
    v_ast.result1 = OG_TRUE;   // TRUE: execute, FALSE: not execute
    v_ast.result2 = depth;

    return visit_expr_tree(&v_ast, exprt, expl_format_expr_node_plan);
}

static status_t expl_format_cond_node_plan(sql_stmt_t *statement, expl_helper_t *helper, cond_node_t *cond,
    uint32 depth, bool32 *has_select)
{
    visit_assist_t v_ast = {0};
    sql_init_visit_assist(&v_ast, statement, NULL);
    v_ast.excl_flags = VA_EXCL_PRIOR;
    v_ast.param0 = (void *)helper;
    v_ast.result0 = OG_FALSE;              // selectstatement in the expr
    v_ast.result1 = (has_select == NULL);  // TRUE: execute, FALSE: not execute;
    v_ast.result2 = depth;

    OG_RETURN_IFERR(visit_cond_node(&v_ast, cond, expl_format_expr_node_plan));
    if (has_select != NULL) {
        *has_select = v_ast.result0;
    }

    return OG_SUCCESS;
}

static status_t expl_format_default_plan_node(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                              uint32 depth)
{
    return OG_SUCCESS;
}

static status_t expl_format_rs_col_plan(sql_stmt_t *statement, expl_helper_t *helper, sql_query_t *query, uint32 depth)
{
    rs_column_t *rs_col = NULL;
    uint32 i = 0;
    while (i < query->rs_columns->count) {
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i++);
        if (rs_col->type != RS_COL_CALC) {
            continue;
        }
        OG_RETURN_IFERR(expl_format_expr_tree_plan(statement, helper, rs_col->expr, depth));
    }
    return OG_SUCCESS;
}

static status_t expl_format_query_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                       uint32 depth)
{
    // store
    sql_query_t *query = helper->query;
    sql_array_t *ssa = helper->ssa;
    cond_tree_t *cond = helper->pred_helper.cond;

    // current node iter info
    helper->query = plan_node->query.ref;
    helper->ssa = &plan_node->query.ref->ssa;
    helper->pred_helper.cond = NULL;

    cond_tree_t *l_hash_filter = helper->pred_helper.l_hash_filter;
    cond_tree_t *r_hash_filter = helper->pred_helper.r_hash_filter;
    cond_tree_t *nl_filter = helper->pred_helper.nl_filter;
    cond_tree_t *outer_cond = helper->pred_helper.outer_cond;

    helper->pred_helper.l_hash_filter = NULL;
    helper->pred_helper.r_hash_filter = NULL;
    helper->pred_helper.nl_filter = NULL;
    helper->pred_helper.outer_cond = NULL;

    OG_RETURN_IFERR(expl_format_rs_col_plan(statement, helper, plan_node->query.ref, depth));
    OG_RETURN_IFERR(expl_format_plan_node(statement, helper, plan_node->query.next, depth));

    // restore
    helper->ssa = ssa;
    helper->query = query;
    helper->pred_helper.cond = cond;

    helper->pred_helper.l_hash_filter = l_hash_filter;
    helper->pred_helper.r_hash_filter = r_hash_filter;
    helper->pred_helper.nl_filter = nl_filter;
    helper->pred_helper.outer_cond = outer_cond;

    return OG_SUCCESS;
}

static inline bool32 expl_format_withas_has_mtrl(sql_withas_t *withas_plan)
{
    if (withas_plan == NULL || withas_plan->withas_factors->count == 0) return OG_FALSE;
    for (uint32 i = 0; i < withas_plan->withas_factors->count; i++) {
        sql_withas_factor_t *factor = (sql_withas_factor_t *)cm_galist_get(withas_plan->withas_factors, i);
        if (factor->is_mtrl) return OG_TRUE;
    }
    return OG_FALSE;
}

status_t expl_format_withas_plan_node(sql_stmt_t *statement, expl_helper_t *helper, sql_withas_t *withas_plan,
                                             uint32 depth)
{
    uint32 i = 0;
    sql_withas_factor_t *factor = NULL;
    while (i < withas_plan->withas_factors->count) {
        factor = (sql_withas_factor_t *)cm_galist_get(withas_plan->withas_factors, i++);
        if (!factor->is_mtrl) {
            continue;
        }
        plan_node_t *ws_plan = ((sql_select_t *)factor->subquery_ctx)->plan->select_p.next;
        OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, ws_plan, depth, "LOAD AS SELECT",
                                                  NULL, &ws_plan->withas_p.name, NULL));
        OG_RETURN_IFERR(expl_format_plan_node(statement, helper, ws_plan->withas_p.next, depth + 1));
    }
    return OG_SUCCESS;
}

status_t expl_format_withas_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    sql_withas_t *withas_plan = (sql_withas_t *)statement->context->withas_entry;
    if (!expl_format_withas_has_mtrl(withas_plan)) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "TEMP TABLE TRANSFORMATION",
                                              NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_withas_plan_node(statement, helper, withas_plan, depth + 1));
    return OG_SUCCESS;
}

static status_t expl_format_select_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    bool32 is_subselect = (sql_get_plan(statement) != plan_node);
    char *oper = is_subselect ? "SUBSELECT" : "SELECT STATEMENT";
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    if (!is_subselect) {
        OG_RETURN_IFERR(expl_format_withas_plan(statement, helper, plan_node, depth + 1));
    }

    return expl_format_plan_node(statement, helper, plan_node->select_p.next, depth + 1);
}

static status_t expl_format_user_rowid_scan_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                                 uint32 depth)
{
    sql_table_t *tbl = plan_node->scan_p.table;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "TABLE ACCESS BY ROWID",
        &tbl->user.value, &tbl->name.value, &tbl->alias.value));
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth + 1, "ROWID SCAN", &tbl->user.value,
                                              &tbl->name.value, &tbl->alias.value));
    helper->pred_helper.type = PREDICATE_ACCESS;
    OG_RETURN_IFERR(expl_format_predicate_row(statement, &helper->pred_helper, plan_node));
    helper->pred_helper.type = PREDICATE_FILTER;

    return OG_SUCCESS;
}

static bool32 expl_format_has_optimize(scan_list_array_t *arr)
{
    if (!can_use_point_scan(arr)) {
        return OG_FALSE;
    }
    uint32 i = 0;
    while (i < arr->count) {
        if (arr->items[i].count > 1) {
            return OG_TRUE;
        }
        if (arr->items[i].type == RANGE_LIST_FULL) {
            return OG_FALSE;
        }
        i++;
    }
    return OG_FALSE;
}

static index_mode_type_t expl_format_get_index_mode(sql_table_t *tbl, scan_list_array_t *arr)
{
    knl_index_desc_t *index = tbl->index;
    index_mode_type_t index_mode = INDEX_MODE_RANGE_SCAN;
    const index_mode_t g_index_mode[] = {
        { tbl->multi_parts_scan, INDEX_MODE_MULTI_PARTS_SCAN },
        { tbl->index_ffs, INDEX_MODE_FAST_FULL_SCAN },
        { tbl->index_full_scan, INDEX_MODE_FULL_SCAN },
        { expl_format_has_optimize(arr), INDEX_MODE_OPTIMIZED_RANGE_SCAN },
        { tbl->idx_equal_to == index->column_count && (index->primary || index->unique), INDEX_MODE_UNIQUE_SCAN },
        { tbl->index_skip_scan, INDEX_MODE_SKIP_SCAN }
    };
    for (uint32 i = 0; i < sizeof(g_index_mode) / sizeof(g_index_mode[0]); i++) {
        if (g_index_mode[i].idx_cond) {
            index_mode = g_index_mode[i].idx_mode;
            break;
        }
    }
    return index_mode;
}

static status_t expl_format_index_scan_mode(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                            uint32 depth)
{
    char oper[OG_MAX_DFLT_VALUE_LEN] = { 0 };
    sql_table_t *scan_tbl = plan_node->scan_p.table;
    sql_array_t *index_arr = &plan_node->scan_p.index_array;
    scan_list_array_t arr = { 0 };
    arr.count = scan_tbl->index->column_count;
    OG_RETURN_IFERR(sql_finalize_scan_range(statement, index_arr, &arr, scan_tbl, NULL, NULL, CALC_IN_PLAN));

    index_mode_type_t idx_mode = expl_format_get_index_mode(scan_tbl, &arr);
    char *idx_oper = g_index_mode_oper[idx_mode];
    MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, idx_oper, strlen(idx_oper)));
    uint32 offset = (uint32)strlen(idx_oper);
    text_t idx_name = { .str = scan_tbl->index->name, .len = (uint32)strlen(scan_tbl->index->name) };
    if (scan_tbl->index_dsc) {
        MEMS_RETURN_IFERR(memcpy_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, " DESCENDING",
                                   strlen(" DESCENDING")));
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, &scan_tbl->user.value,
        &idx_name, NULL));
    if (scan_tbl->index_full_scan || helper->pred_helper.idx_cond == NULL ||
        helper->pred_helper.idx_cond->root == NULL) {
        return OG_SUCCESS;
    }
    return expl_format_pred_index_cond(statement, &helper->pred_helper, plan_node);
}

static status_t expl_format_user_index_scan_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                                 uint32 depth)
{
    char oper[OG_MAX_DFLT_VALUE_LEN] = { 0 };
    int len = 0;
    sql_table_t *scan_tbl = plan_node->scan_p.table;
    if (!INDEX_ONLY_SCAN(scan_tbl->scan_flag)) {
        len = snprintf_s(oper, OG_MAX_DFLT_VALUE_LEN, OG_MAX_DFLT_VALUE_LEN -1, "TABLE ACCESS BY INDEX ROWID ");
    } else {
        len = snprintf_s(oper, OG_MAX_DFLT_VALUE_LEN, OG_MAX_DFLT_VALUE_LEN -1, "TABLE ACCESS BY INDEX ONLY ");
    }
    if (SECUREC_UNLIKELY(len == -1)) {
        return OG_ERROR;
    }
    uint32 offset = (uint32)len;
    if (knl_is_part_table(scan_tbl->entry->dc.handle)) {
        sql_part_get_print(statement, &plan_node->scan_p, oper + offset, OG_MAX_DFLT_VALUE_LEN - offset);
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, &scan_tbl->user.value,
                                              &scan_tbl->name.value, &scan_tbl->alias.value));
    
    OG_RETURN_IFERR(expl_format_predicate_row(statement, &helper->pred_helper, plan_node));
    return expl_format_index_scan_mode(statement, helper, plan_node, depth + 1);
}

static status_t expl_format_normal_table_scan_plan(sql_stmt_t *statement, expl_helper_t *helper,
                                                   plan_node_t *plan_node, uint32 depth)
{
    text_t owner_text = {0};
    text_t name_text = {0};
    sql_table_t *tbl = plan_node->scan_p.table;
    knl_dictionary_t *knl_dic = &tbl->entry->dc;

    if ((knl_dic->is_sysnonym == OG_TRUE) &&
        (knl_dic->type == DICT_TYPE_TABLE || knl_dic->type == DICT_TYPE_TEMP_TABLE_TRANS ||
         knl_dic->type == DICT_TYPE_TEMP_TABLE_SESSION || knl_dic->type == DICT_TYPE_TABLE_NOLOGGING)) {
        dc_entry_t *knl_entry = DC_ENTRY(knl_dic);
        owner_text.str = knl_entry->user->desc.name;
        owner_text.len = (uint32)strlen(owner_text.str);
        name_text.str = knl_entry->name;
        name_text.len = (uint32)strlen(name_text.str);
    } else {
        owner_text = *(text_t *)&plan_node->scan_p.table->user;
        name_text = *(text_t *)&plan_node->scan_p.table->name;
    }

    char oper[OG_MAX_DFLT_VALUE_LEN] = "TABLE ACCESS FULL";
    int len = 0;
    if (knl_is_part_table(knl_dic->handle)) {
        len = snprintf_s(oper, OG_MAX_DFLT_VALUE_LEN, OG_MAX_DFLT_VALUE_LEN - 1, "TABLE ACCESS FULL ");
        if (SECUREC_UNLIKELY(len == -1)) {
            return OG_ERROR;
        }
        uint32 offset = (uint32)len;
        sql_part_get_print(statement, &plan_node->scan_p, oper + offset, OG_MAX_DFLT_VALUE_LEN - offset);
    }
    
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, &tbl->user.value,
                                              &tbl->name.value, &tbl->alias.value));

    return expl_format_predicate_row(statement, &helper->pred_helper, plan_node);
}

static status_t expl_format_view_as_table_scan_plan(sql_stmt_t *statement, expl_helper_t *helper,
                                                    plan_node_t *plan_node, uint32 depth)
{
    sql_table_t *tbl = plan_node->scan_p.table;
    plan_node_t *slct_plan_node = tbl->select_ctx->plan;
    plan_node_t *next_plan_node = slct_plan_node->select_p.next;

    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "VIEW", &tbl->user.value,
        &tbl->name.value, &tbl->alias.value));
    OG_RETURN_IFERR(expl_format_predicate_row(statement, &helper->pred_helper, plan_node));

    return expl_format_plan_node(statement, helper, next_plan_node, depth + 1);
}

static status_t expl_format_subselect_as_table_scan_plan(
    sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                                  uint32 depth)
{
    char *oper = NULL;
    plan_node_t *next_plan_node = NULL;
    sql_table_t *tbl = plan_node->scan_p.table;
    plan_node_t *slct_plan_node = tbl->select_ctx->plan;

    if (slct_plan_node->select_p.next->type == PLAN_NODE_VM_VIEW_MTRL) {
        oper = "VN VIEW";
        next_plan_node = slct_plan_node->select_p.next->vm_view_p.next;
    } else {
        oper = "SUBSELECT";
        next_plan_node = slct_plan_node->select_p.next;
    }

    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, &tbl->user.value,
        &tbl->name.value, &tbl->alias.value));
    OG_RETURN_IFERR(expl_format_predicate_row(statement, &helper->pred_helper, plan_node));
    
    return expl_format_plan_node(statement, helper, next_plan_node, depth + 1);
}

static status_t expl_format_func_as_table_scan_plan(sql_stmt_t *statement, expl_helper_t *helper,
                                                    plan_node_t *plan_node, uint32 depth)
{
    sql_table_t *tbl = plan_node->scan_p.table;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "TABLE ACCESS FULL",
        &tbl->user.value, &tbl->name.value, &tbl->alias.value));
                                            
    return expl_format_predicate_row(statement, &helper->pred_helper, plan_node);
}

static status_t expl_format_with_as_table_scan_plan(sql_stmt_t *statement, expl_helper_t *helper,
                                                    plan_node_t *plan_node, uint32 depth)
{
    sql_table_t *tbl = plan_node->scan_p.table;
    plan_node_t *slct_plan_node = tbl->select_ctx->plan;

    if (slct_plan_node->select_p.next->type == PLAN_NODE_WITHAS_MTRL) {
        withas_mtrl_plan_t *withas_p = &slct_plan_node->select_p.next->withas_p;
        return expl_format_plan_node_row(statement, helper, plan_node, depth, "TABLE ACCESS FULL", NULL,
            &withas_p->name, &tbl->alias.value);
    }

    return expl_format_subselect_as_table_scan_plan(statement, helper, plan_node, depth);
}

static status_t expl_format_scan_plan_deep(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                           uint32 depth)
{
    sql_table_t *tbl = plan_node->scan_p.table;

    if (plan_node->scan_p.rowid_set != NULL && plan_node->scan_p.rowid_set->type == RANGE_LIST_NORMAL) {
        return expl_format_user_rowid_scan_plan(statement, helper, plan_node, depth);
    } else if (plan_node->scan_p.table->index != NULL) {
        return expl_format_user_index_scan_plan(statement, helper, plan_node, depth);
    }

    sql_table_type_t type = tbl->type;
    switch (type) {
        case NORMAL_TABLE:
            return expl_format_normal_table_scan_plan(statement, helper, plan_node, depth);
        case VIEW_AS_TABLE:
            return expl_format_view_as_table_scan_plan(statement, helper, plan_node, depth);
        case SUBSELECT_AS_TABLE:
            return expl_format_subselect_as_table_scan_plan(statement, helper, plan_node, depth);
        case FUNC_AS_TABLE:
            return expl_format_func_as_table_scan_plan(statement, helper, plan_node, depth);
        case JOIN_AS_TABLE:
            return expl_format_normal_table_scan_plan(statement, helper, plan_node, depth);
        case WITH_AS_TABLE:
            return expl_format_with_as_table_scan_plan(statement, helper, plan_node, depth);
        case JSON_TABLE:
            return expl_format_func_as_table_scan_plan(statement, helper, plan_node, depth);
    }
    return OG_SUCCESS;
}

static status_t format_kernel_filter_if_needed(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *node,
                                               uint32 depth, bool32 has_subselect, bool32 has_index_subselect)
{
    if (!has_subselect && !has_index_subselect) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, node, depth, "KERNEL FILTER", NULL, NULL, NULL));

    return OG_SUCCESS;
}

static status_t format_subselect_conditions(sql_stmt_t *statement, expl_helper_t *helper,
                                            sql_query_t *qry, sql_table_t *tbl,
                                            uint32 depth, bool32 has_subselect, bool32 has_index_subselect)
{
    if (has_subselect && expl_format_cond_node_plan(statement, helper, qry->cond->root, depth, NULL) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[EXPLAIN] Failed to format subselect condition plan.");
        return OG_ERROR;
    }

    if (has_index_subselect && expl_format_cond_node_plan(
                                   statement, helper, tbl->cond->root, depth, NULL) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("[EXPLAIN] Failed to format index subselect condition plan.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t check_for_subselects(sql_stmt_t *statement, expl_helper_t *helper,
                                     sql_query_t *query, sql_table_t *table,
                                     bool32 *has_subselect_out, bool32 *has_index_subselect_out)
{
    bool32 has_subselect = OG_FALSE;
    bool32 has_index_subselect = OG_FALSE;

    if (query != NULL && query->cond != NULL) {
        OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, query->cond->root, 0, &has_subselect));
    }

    if (table != NULL && table->index_cond_pruning) {
        OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, table->cond->root, 0, &has_index_subselect));
    }

    *has_subselect_out = has_subselect;
    *has_index_subselect_out = has_index_subselect;

    return OG_SUCCESS;
}


static status_t expl_format_scan_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                      uint32 depth)
{
    sql_query_t *query = helper->query;
    sql_table_t *tbl = plan_node->scan_p.table;
    bool32 has_subselect = OG_FALSE;
    bool32 has_index_subselect = OG_FALSE;

    // Check for subqueries that affect kernel filtering
    OG_RETURN_IFERR(check_for_subselects(statement, helper, query, tbl, &has_subselect, &has_index_subselect));

    // Format kernel filter row if needed
    OG_RETURN_IFERR(format_kernel_filter_if_needed(statement, helper, plan_node, depth, has_subselect,
        has_index_subselect));

    // Recursively format deeper scan plan nodes
    OG_RETURN_IFERR(expl_format_scan_plan_deep(statement, helper, plan_node, depth + 1));

    // Format actual condition trees of subqueries after deep formatting
    OG_RETURN_IFERR(format_subselect_conditions(statement, helper, query, tbl, depth + 1, has_subselect,
        has_index_subselect));

    return OG_SUCCESS;
}

static status_t expl_format_union_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                       uint32 depth)
{
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "HASH UNION", NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_plan_node(statement, helper, plan_node->set_p.left, depth + 1));
    return expl_format_plan_node(statement, helper, plan_node->set_p.right, depth + 1);
}

static status_t expl_format_union_all_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                           uint32 depth)
{
    plan_node_t *sub_plan_node = NULL;
    char oper[OG_MAX_DFLT_VALUE_LEN] = {0};
    uint32 offset = 0;
    int32 len = 0;
    MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, "UNION ALL", strlen("UNION ALL")));
    if (g_instance->sql.parallel_policy && plan_node->set_p.union_all_p.par_exec) {
        offset = (uint32)strlen("UNION ALL");
        len = snprintf_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, OG_MAX_DFLT_VALUE_LEN - offset- 1,
                         "(p %3u)", statement->context->parallel);
    }
    if (SECUREC_UNLIKELY(len == -1)) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    uint32 i = 0;
    while (i < plan_node->set_p.list->count) {
        sub_plan_node = (plan_node_t *)cm_galist_get(plan_node->set_p.list, i++);
        OG_RETURN_IFERR(expl_format_plan_node(statement, helper, sub_plan_node, depth + 1));
    }
    return OG_SUCCESS;
}

static status_t expl_format_minus_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                       uint32 depth)
{
    char oper[OG_MAX_DFLT_VALUE_LEN] = {0};
    uint32 offset = 0;
    char *name = g_minus_names[plan_node->set_p.minus_p.minus_type];
    if (plan_node->type == PLAN_NODE_HASH_MINUS) {
        MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, "HASH ", strlen("HASH ")));
        offset = (uint32)strlen("HASH ");
    }
    MEMS_RETURN_IFERR(memcpy_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, name, strlen(name)));
    offset += (uint32)strlen(name);
    char *build_side = plan_node->set_p.minus_p.minus_left ? "(L)" : "(R)";
    MEMS_RETURN_IFERR(memcpy_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, build_side, strlen(build_side)));
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_plan_node(statement, helper, plan_node->set_p.left, depth + 1));
    return expl_format_plan_node(statement, helper, plan_node->set_p.right, depth + 1);
}

static status_t expl_format_aggr_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                      uint32 depth)
{
    char oper[OG_MAX_DFLT_VALUE_LEN] = {0};
    uint32 offset = 0;
    expr_node_t *aggr_exprn = NULL;
    if (plan_node->type == PLAN_NODE_INDEX_AGGR) {
        MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, "INDEX ", strlen("INDEX ")));
        offset = (uint32)strlen("INDEX ");
    }
    MEMS_RETURN_IFERR(memcpy_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, "AGGR", strlen("AGGR")));
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    uint32 i = 0;
    while (i < plan_node->aggr.items->count) {
        aggr_exprn = (expr_node_t *)cm_galist_get(plan_node->aggr.items, i++);
        OG_RETURN_IFERR(expl_format_aggr_node_plan(statement, helper, aggr_exprn, depth + 1));
    }
    return expl_format_plan_node(statement, helper, plan_node->aggr.next, depth + 1);
}

static status_t expl_format_nl_full_opt_row(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                            uint32 depth)
{
    plan_node_t l_drive_plan = *plan_node;
    l_drive_plan.join_p.oper = JOIN_OPER_NL_LEFT;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "UNION ALL", NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_join_plan(statement, helper, &l_drive_plan, depth + 1));
    return expl_format_plan_node(statement, helper, plan_node->join_p.r_drive_plan, depth + 1);
}

static status_t expl_format_join_exists_subselect(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                                  uint32 depth, cond_node_t **subselect_cond)
{
    bool32 has_subselect = OG_FALSE;
    if (plan_node->join_p.filter != NULL) {
        OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, plan_node->join_p.filter->root,
                                                   depth + 1, &has_subselect));
        if (has_subselect) {
            *subselect_cond = plan_node->join_p.filter->root;
        }
        return OG_SUCCESS;
    }
    if (plan_node->join_p.cond != NULL) {
        OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, plan_node->join_p.cond->root,
                                                   depth + 1, &has_subselect));
        if (has_subselect) {
            *subselect_cond = plan_node->join_p.cond->root;
        }
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static status_t expl_format_join_fill_oper(plan_node_t *plan_node, char *oper)
{
    char *join_oper = NULL;
    if (plan_node->join_p.oper != JOIN_OPER_NL_LEFT) {
        join_oper = g_join_oper[plan_node->join_p.oper][plan_node->join_p.hash_left];
    } else {
        join_oper = g_join_oper[plan_node->join_p.oper][plan_node->join_p.nl_full_r_drive];
    }
    MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, join_oper, strlen(join_oper)));
    return OG_SUCCESS;
}

static status_t set_helper_cond(plan_node_t *plan_node, pred_helper_t *helper, bool32 right)
{
    if (plan_node->join_p.oper != JOIN_OPER_HASH_FULL && plan_node->join_p.oper != JOIN_OPER_HASH_LEFT &&
        plan_node->join_p.oper != JOIN_OPER_HASH_RIGHT_LEFT) {
        cond_tree_t *cond = plan_node->join_p.cond;
        bool32 is_valid_cond = (cond && cond->root->type != COND_NODE_TRUE);
        bool32 is_right_scan = (plan_node->join_p.right->type == PLAN_NODE_SCAN);
        if (is_valid_cond && ((right && is_right_scan) || (!right && !is_right_scan))) {
            helper->outer_cond = cond;
        }
    }

    if (!right && plan_node->join_p.left->type == PLAN_NODE_JOIN) {
        return OG_SUCCESS;
    }

    if (right && plan_node->join_p.left->type == PLAN_NODE_SCAN &&
        plan_node->join_p.right->type != PLAN_NODE_SCAN) {
        helper->nl_filter = NULL;
        return OG_SUCCESS;
    }

    if (helper->nl_filter &&
        ((helper->nl_filter->root->type == COND_NODE_TRUE) ||
        chk_if_hash_join(plan_node->join_p.oper))) {
        helper->nl_filter = NULL;
        return OG_SUCCESS;
    }

    cond_tree_t *filter = plan_node->join_p.filter;
    bool32 is_valid_filter = (filter && filter->root->type != COND_NODE_TRUE);
    if (is_valid_filter && helper->nl_filter == NULL) {
        OG_RETURN_IFERR(sql_clone_cond_tree(&helper->vmc, filter, &helper->nl_filter, vmc_alloc_mem));
    }
    return OG_SUCCESS;
}

static void reset_helper_cond(plan_node_t *plan_node, pred_helper_t *helper)
{
    if (chk_if_hash_join(plan_node->join_p.oper) || plan_node->join_p.oper == JOIN_OPER_MERGE) {
        helper->l_hash_filter = NULL;
        helper->r_hash_filter = NULL;
    }
    helper->outer_cond = NULL;
    helper->nl_filter = NULL;
}

static status_t expl_format_join_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                      uint32 depth)
{
    if (plan_node->join_p.oper == JOIN_OPER_NL_FULL && plan_node->join_p.nl_full_opt_type != NL_FULL_OPT_NONE) {
        return expl_format_nl_full_opt_row(statement, helper, plan_node, depth);
    }

    cond_node_t *subselect_cond = NULL;
    char oper[OG_MAX_DFLT_VALUE_LEN] = {0};
    OG_RETURN_IFERR(expl_format_join_exists_subselect(statement, helper, plan_node, depth, &subselect_cond));
    if (subselect_cond != NULL) {
        OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth++, "KERNEL FILTER",
            NULL, NULL, NULL));
    }
    OG_RETURN_IFERR(expl_format_join_fill_oper(plan_node, oper));
    OG_RETURN_IFERR(set_helper_cond(plan_node, &helper->pred_helper, OG_FALSE));
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_predicate_row(statement, &helper->pred_helper, plan_node));

    cond_tree_t *lcond = plan_node->join_p.left_hash.filter_cond;
    if (lcond && lcond->root->type != COND_NODE_TRUE) {
        OG_RETURN_IFERR(sql_clone_cond_tree(&helper->pred_helper.vmc, lcond,
            &helper->pred_helper.l_hash_filter, vmc_alloc_mem));
    }
    OG_RETURN_IFERR(expl_format_plan_node(statement, helper, plan_node->join_p.left, depth + 1));

    OG_RETURN_IFERR(set_helper_cond(plan_node, &helper->pred_helper, OG_TRUE));
    cond_tree_t *rcond = plan_node->join_p.right_hash.filter_cond;
    if (rcond && rcond->root->type != COND_NODE_TRUE) {
        OG_RETURN_IFERR(sql_clone_cond_tree(&helper->pred_helper.vmc, rcond,
            &helper->pred_helper.r_hash_filter, vmc_alloc_mem));
    }
    if (helper->pred_helper.concate_type == TABLE_CONCATE) {
        helper->pred_helper.l_hash_filter = NULL;
    }
    OG_RETURN_IFERR(expl_format_plan_node(statement, helper, plan_node->join_p.right, depth + 1));
    reset_helper_cond(plan_node, &helper->pred_helper);

    if (subselect_cond == NULL) {
        return OG_SUCCESS;
    }
    return expl_format_cond_node_plan(statement, helper, subselect_cond, depth, NULL);
}

static status_t expl_format_insert_print_oper(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                              uint32 depth, bool32 insert_all)
{
    char oper[OG_MAX_DFLT_VALUE_LEN] = {0};
    sql_table_t *tbl = plan_node->insert_p.table;
    if (insert_all) {
        MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, "MULTI TABLE INSERT", strlen("MULTI TABLE INSERT")));
        OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
        return OG_SUCCESS;
    }
    uint32 offset = (uint32)strlen("LOAD TABLE CONVENTIONAL ");
    MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, "LOAD TABLE CONVENTIONAL ", offset));
    if (statement->context->type != OGSQL_TYPE_REPLACE && knl_is_part_table(tbl->entry->dc.handle)) {
        OG_RETURN_IFERR(sql_calc_part_print(statement, oper + offset, OG_MAX_DFLT_VALUE_LEN - offset));
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper,
                                              &tbl->user.value, &tbl->name.value,
                                              &tbl->alias.value));
    return OG_SUCCESS;
}

static status_t expl_format_insert_expr_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                             uint32 depth, sql_insert_t *insert_ctx, bool32 insert_all)
{
    uint32 i = 0;
    column_value_pair_t *pair = NULL;
    expr_tree_t *exprt = NULL;
    sql_table_t *tbl = plan_node->insert_p.table;
    if (insert_all) {
        while (i < insert_ctx->pairs_count) {
            OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "INTO",
                                                      &tbl->user.value, &tbl->name.value,
                                                      &tbl->alias.value));
            i++;
        }
        return OG_SUCCESS;
    }
    while (i < insert_ctx->pairs->count) {
        pair = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, i++);
        if (pair->exprs == NULL) {
            continue;
        }
        for (uint32 j = 0; j < pair->exprs->count; j++) {
            exprt = (expr_tree_t *)cm_galist_get(pair->exprs, j);
            OG_RETURN_IFERR(expl_format_expr_tree_plan(statement, helper, exprt, depth));
        }
    }
    return OG_SUCCESS;
}

static status_t expl_format_insert_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    sql_insert_t *insert_ctx = NULL;
    sql_array_t *ssa = helper->ssa;
    char *oper = NULL;
    if (statement->context->type != OGSQL_TYPE_REPLACE) {
        insert_ctx = (sql_insert_t *)statement->context->entry;
        oper = "INSERT STATEMENT";
    } else {
        insert_ctx = &((sql_replace_t *)statement->context->entry)->insert_ctx;
        oper = "REPLACE STATEMENT";
    }
    helper->ssa = &insert_ctx->ssa;
    bool32 insert_all = OG_BIT_TEST(insert_ctx->syntax_flag, INSERT_IS_ALL);
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    if (sql_get_plan(statement) == plan_node) {
        OG_RETURN_IFERR(expl_format_withas_plan(statement, helper, plan_node, depth + 1));
    }
    OG_RETURN_IFERR(expl_format_insert_print_oper(statement, helper, plan_node, depth + 1, insert_all));
    if (insert_ctx->select_ctx != NULL) {
        OG_RETURN_IFERR(expl_format_plan_node(statement, helper, insert_ctx->select_ctx->plan,
                                              depth + EXPL_DEPTH_CALC_LEVEL));
    }
    OG_RETURN_IFERR(expl_format_insert_expr_plan(statement, helper, plan_node, depth + EXPL_DEPTH_CALC_LEVEL,
                                                 insert_ctx, insert_all));
    helper->ssa = ssa;
    return OG_SUCCESS;
}

static status_t expl_format_merge_insert_plan(sql_stmt_t *statement, expl_helper_t *helper, uint32 depth)
{
    sql_merge_t *merge_ctx = (sql_merge_t *)statement->context->entry;
    if (merge_ctx->insert_ctx == NULL) {
        return OG_SUCCESS;
    }
    if (merge_ctx->insert_filter_cond == NULL) {
        OG_RETURN_IFERR(expl_format_plan_node_row(
            statement, helper, merge_ctx->insert_ctx->plan, depth, "INSERT STATEMENT",
                                                  NULL, NULL, NULL));
        return OG_SUCCESS;
    }
    sql_array_t *ssa = helper->ssa;
    helper->ssa = &merge_ctx->query->ssa;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, NULL, depth, "FILTER", NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_put_pred_info(statement, merge_ctx->query, &helper->pred_helper,
        merge_ctx->insert_filter_cond));
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, merge_ctx->insert_ctx->plan, depth + 1,
        "INSERT STATEMENT", NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, merge_ctx->insert_filter_cond->root,
                                               depth + EXPL_DEPTH_CALC_LEVEL, NULL));
    helper->ssa = ssa;
    return OG_SUCCESS;
}

static status_t expl_format_merge_update_expr_plan(sql_stmt_t *statement, expl_helper_t *helper, uint32 depth)
{
    sql_merge_t *merge_ctx = (sql_merge_t *)statement->context->entry;
    galist_t *update_pairs = merge_ctx->update_ctx->pairs;
    expr_tree_t *exprt = NULL;
    column_value_pair_t *update_pair = NULL;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, merge_ctx->update_ctx->plan, depth, "UPDATE STATEMENT",
                                              NULL, NULL, NULL));
    uint32 i = 0;
    while (i < update_pairs->count) {
        update_pair = (column_value_pair_t *)cm_galist_get(update_pairs, i++);
        exprt = (expr_tree_t *)cm_galist_get(update_pair->exprs, 0);
        OG_RETURN_IFERR(expl_format_expr_tree_plan(statement, helper, exprt, depth + 1));
    }
    
    return OG_SUCCESS;
}

static status_t expl_format_merge_update_plan(sql_stmt_t *statement, expl_helper_t *helper, uint32 depth)
{
    sql_merge_t *merge_ctx = (sql_merge_t *)statement->context->entry;
    if (merge_ctx->update_ctx == NULL) {
        return OG_SUCCESS;
    }
    sql_array_t *ssa = helper->ssa;
    helper->ssa = &merge_ctx->query->ssa;
    if (merge_ctx->update_filter_cond == NULL) {
        OG_RETURN_IFERR(expl_format_merge_update_expr_plan(statement, helper, depth));
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, NULL, depth, "FILTER", NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_put_pred_info(statement, merge_ctx->query, &helper->pred_helper,
        merge_ctx->update_filter_cond));
    OG_RETURN_IFERR(expl_format_merge_update_expr_plan(statement, helper, depth + 1));
    OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, merge_ctx->update_filter_cond->root,
                                               depth + EXPL_DEPTH_CALC_LEVEL, NULL));
    helper->ssa = ssa;
    return OG_SUCCESS;
}

static status_t expl_format_merge_using_table(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                              uint32 depth)
{
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node->merge_p.using_table_scan_p, depth + 1,
                                              "USING TABLE", NULL, NULL, NULL));
    helper->pred_helper.merge_cond = plan_node->merge_p.remain_on_cond;
    return expl_format_plan_node(statement, helper, plan_node->merge_p.using_table_scan_p,
        depth + EXPL_DEPTH_CALC_LEVEL);
}

static status_t expl_format_merge_into_table(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                             uint32 depth)
{
    helper->query = NULL;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node->merge_p.merge_into_scan_p, depth + 1,
                                              "MERGE TABLE", NULL, NULL, NULL));
    helper->pred_helper.merge_cond = plan_node->merge_p.merge_table_filter_cond;
    return expl_format_plan_node(statement, helper, plan_node->merge_p.merge_into_scan_p,
        depth + EXPL_DEPTH_CALC_LEVEL);
}

static status_t expl_format_merge_on_condition(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                               uint32 depth)
{
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, NULL, depth + 1, "ON CONDITION", NULL, NULL, NULL));
    if (!helper->pred_helper.is_merge_hash) {
        return OG_SUCCESS;
    }
    return expl_format_merge_hash_cond(statement, &helper->pred_helper, plan_node);
}

static status_t expl_format_merge_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                       uint32 depth)
{
    char oper[OG_MAX_DFLT_VALUE_LEN] = {0};
    uint32 offset = (uint32)strlen("MERGE STATEMENT");
    MEMS_RETURN_IFERR(memcpy_s(oper, OG_MAX_DFLT_VALUE_LEN, "MERGE STATEMENT", offset));
    if (plan_node->merge_p.merge_keys == NULL || plan_node->merge_p.merge_keys->count == 0) {
        MEMS_RETURN_IFERR(memcpy_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, "(NESTED LOOPS)",
                                   strlen("(NESTED LOOPS)")));
    } else {
        MEMS_RETURN_IFERR(memcpy_s(oper + offset, OG_MAX_DFLT_VALUE_LEN - offset, "(HASH JOIN)",
                                   strlen("(HASH JOIN)")));
        helper->pred_helper.is_merge_hash = OG_TRUE;
    }

    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    if (sql_get_plan(statement) == plan_node) {
        OG_RETURN_IFERR(expl_format_withas_plan(statement, helper, plan_node, depth + 1));
    }

    OG_RETURN_IFERR(expl_format_merge_using_table(statement, helper, plan_node, depth));
    OG_RETURN_IFERR(expl_format_merge_into_table(statement, helper, plan_node, depth));
    OG_RETURN_IFERR(expl_format_merge_on_condition(statement, helper, plan_node, depth));

    helper->pred_helper.is_merge_hash = OG_FALSE;
    OG_RETURN_IFERR(expl_format_merge_insert_plan(statement, helper, depth + EXPL_DEPTH_CALC_LEVEL));
    return expl_format_merge_update_plan(statement, helper, depth +EXPL_DEPTH_CALC_LEVEL);
}

static status_t expl_format_delete_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "DELETE STATEMENT",
        NULL, NULL, NULL));
    if (sql_get_plan(statement) == plan_node) {
        OG_RETURN_IFERR(expl_format_withas_plan(statement, helper, plan_node, depth + 1));
    }
    return expl_format_plan_node(statement, helper, plan_node->delete_p.next, depth + 1);
}

static bool32 expl_format_update_expr_exists(expr_tree_t **exprt_arr, expr_tree_t *exprt, uint32 count)
{
    uint32 idx = 0;
    while (idx < count) {
        if (exprt_arr[idx++] == exprt) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t expl_format_update_expr_plan(sql_stmt_t *statement, expl_helper_t *helper, update_plan_t *upd_plan_node,
                                             uint32 depth)
{
    sql_update_t *update_ctx = (sql_update_t *)statement->context->entry;
    sql_array_t *sub_slct_arr = helper->ssa;
    expr_tree_t **exprt_arr;
    upd_object_t *update_obj = NULL;
    column_value_pair_t *col_val_pair = NULL;
    expr_tree_t *exprt = NULL;
    uint32 i = 0;
    while (i < upd_plan_node->objects->count) {
        update_obj = (upd_object_t *)cm_galist_get(upd_plan_node->objects, i++);
        if (update_obj->pairs->count == 0) {
            continue;
        }
        OG_RETURN_IFERR(sql_push(statement, update_obj->pairs->count * sizeof(pointer_t), (void **)&exprt_arr));
        uint32 expr_count = 0;
        uint32 j = 0;
        while (j < update_obj->pairs->count) {
            col_val_pair = (column_value_pair_t *)cm_galist_get(update_obj->pairs, j++);
            exprt = (expr_tree_t *)cm_galist_get(col_val_pair->exprs, 0);
            if (expr_count == 0 || !expl_format_update_expr_exists(exprt_arr, exprt, expr_count)) {
                exprt_arr[expr_count] = exprt;
                expr_count++;
            } else {
                continue;
            }
            helper->ssa = &update_ctx->query->ssa;
            if (expl_format_expr_tree_plan(statement, helper, exprt, depth) != OG_SUCCESS) {
                OGSQL_POP(statement);
                return OG_ERROR;
            }
        }
        OGSQL_POP(statement);
    }
    helper->ssa = sub_slct_arr;
    return OG_SUCCESS;
}

static status_t expl_format_update_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "UPDATE STATEMENT",
        NULL, NULL, NULL));
    if (sql_get_plan(statement) == plan_node) {
        OG_RETURN_IFERR(expl_format_withas_plan(statement, helper, plan_node, depth + 1));
    }
    OG_RETURN_IFERR(expl_format_plan_node(statement, helper, plan_node->update_p.next, depth + 1));
    return expl_format_update_expr_plan(statement, helper, &plan_node->update_p, depth + 1);
}

static status_t expl_format_sort_expr(sql_stmt_t *statement, expl_helper_t *helper, galist_t *columns, uint32 depth)
{
    rs_column_t *col = NULL;
    uint32 i = 0;
    while (i < columns->count) {
        col = (rs_column_t *)cm_galist_get(columns, i++);
        if (col->type == RS_COL_CALC) {
            OG_RETURN_IFERR(expl_format_expr_tree_plan(statement, helper, col->expr, depth));
        }
    }
    return OG_SUCCESS;
}

static status_t expl_format_sort_plan_data(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                           uint32 depth, char *oper)
{
    galist_t *columns = plan_node->query_sort.select_columns;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_sort_expr(statement, helper, columns, depth + 1));
    return expl_format_plan_node(statement, helper, plan_node->query_sort.next, depth + 1);
}

static status_t expl_format_sort_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                      uint32 depth)
{
    char *oper = NULL;
    if (plan_node->type == PLAN_NODE_QUERY_SORT_PAR) {
        oper = "PAR QUERY SORT ORDER BY";
    } else if (plan_node->type == PLAN_NODE_QUERY_SIBL_SORT) {
        oper = "QUERY SORT SIBLINGS ORDER BY";
    } else if (sort_order_by_rownum(plan_node)) {
        oper = "QUERY SORT ORDER BY ROWNUM";
    } else {
        oper = "QUERY SORT ORDER BY";
    }
    return expl_format_sort_plan_data(statement, helper, plan_node, depth, oper);
}

static status_t expl_format_distinct_plan_data(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                               uint32 depth, char *oper)
{
    galist_t *columns = plan_node->distinct.columns;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_sort_expr(statement, helper, columns, depth + 1));
    return expl_format_plan_node(statement, helper, plan_node->distinct.next, depth + 1);
}

static status_t expl_format_distinct_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan, uint32 depth)
{
    char *oper = g_distinct_names[plan->type - PLAN_NODE_SORT_DISTINCT];
    return expl_format_distinct_plan_data(statement, helper, plan, depth, oper);
}

static status_t expl_format_next_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                      plan_node_t *next_plan_node, uint32 depth, char *oper)
{
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, oper, NULL, NULL, NULL));
    OG_RETURN_IFERR(expl_format_predicate_row(statement, &helper->pred_helper, plan_node));
    return expl_format_plan_node(statement, helper, next_plan_node, depth + 1);
}

static status_t expl_format_group_by_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                          uint32 depth)
{
    char *oper = g_group_by_names[plan_node->type - PLAN_NODE_SORT_GROUP];
    return expl_format_next_plan(statement, helper, plan_node, plan_node->group.next, depth, oper);
}

static status_t expl_format_select_sort_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                             uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->select_sort.next, depth,
        "SELECT SORT ORDER BY");
}

static status_t expl_format_having_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    OG_RETURN_IFERR(expl_format_next_plan(statement, helper, plan_node, plan_node->having.next, depth, "HAVING"));
    if (plan_node->having.cond == NULL) {
        return OG_SUCCESS;
    }
    return expl_format_cond_node_plan(statement, helper, plan_node->having.cond->root, depth, NULL);
}

static status_t expl_format_query_limit_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                             uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->limit.next, depth, "QUERY LIMIT");
}

static status_t expl_format_select_limit_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                              uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->limit.next, depth, "SELECT LIMIT");
}

static status_t expl_format_connect_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                         uint32 depth)
{
    connect_plan_t *connect_by_plan = &plan_node->connect;
    bool32 is_next_cb_type_mtrl = (connect_by_plan->next_connect_by->type == PLAN_NODE_CONNECT_MTRL);

    // start with condition
    cond_tree_t *start_with_cond = (connect_by_plan->s_query != NULL) ? connect_by_plan->s_query->cond :
                           (is_next_cb_type_mtrl ? NULL : connect_by_plan->start_with_cond);
    if (connect_by_plan->s_query || (!is_next_cb_type_mtrl && connect_by_plan->start_with_cond)) {
        helper->pred_helper.is_start_with = OG_TRUE;
        OG_RETURN_IFERR(expl_format_next_plan(statement, helper, plan_node, connect_by_plan->next_start_with, depth,
            "START WITH"));
        if (start_with_cond) {
            OG_RETURN_IFERR(expl_format_cond_node_plan(statement, helper, start_with_cond->root, depth, NULL));
        }
        helper->pred_helper.is_start_with = OG_FALSE;
    }

    // connect by condition
    if (is_next_cb_type_mtrl) {
        return expl_format_plan_node(statement, helper, connect_by_plan->next_connect_by, depth);
    }
    if (connect_by_plan->connect_by_cond == NULL) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(expl_format_next_plan(statement, helper, plan_node, connect_by_plan->next_connect_by, depth,
        "CONNECT BY"));
    return expl_format_cond_node_plan(statement, helper, connect_by_plan->connect_by_cond->root, depth, NULL);
}

static status_t expl_format_filter_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    OG_RETURN_IFERR(expl_format_next_plan(statement, helper, plan_node, plan_node->filter.next, depth, "FILTER"));
    if (plan_node->filter.cond == NULL) {
        return OG_SUCCESS;
    }
    return expl_format_cond_node_plan(statement, helper, plan_node->filter.cond->root, depth, NULL);
}

static status_t expl_format_window_sort_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                             uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->winsort_p.next, depth, "WINDOW SORT");
}

static status_t expl_format_group_merge_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                             uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->group.next, depth, "MERGE GROUP BY");
}

static status_t expl_format_parallel_group_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                                uint32 depth)
{
    group_plan_t group = plan_node->group;
    if (group.multi_prod) {
        return expl_format_next_plan(statement, helper, plan_node, group.next, depth, "PARALLEL HASH GROUP BY (M-M)");
    }
    return expl_format_next_plan(statement, helper, plan_node, group.next, depth, "PARALLEL HASH GROUP BY (S-S)");
}

static status_t expl_format_hash_mtrl_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                           uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->hash_mtrl.group.next, depth,
                                 "HASH MATERIALIZE");
}

static status_t expl_format_concate_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                         uint32 depth)
{
    uint32 i = 0;
    plan_node_t *sub_plan = NULL;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth, "CONCATENATION", NULL, NULL, NULL));
    while (i < plan_node->cnct_p.plans->count) {
        sub_plan = (plan_node_t *)cm_galist_get(plan_node->cnct_p.plans, i++);
        if (i == 1) {
            if (sub_plan->type == PLAN_NODE_SCAN) {
                helper->pred_helper.concate_type = TABLE_CONCATE;
            } else {
                helper->pred_helper.concate_type = JOIN_CONCATE;
            }
        }
        OG_RETURN_IFERR(expl_format_plan_node(statement, helper, sub_plan, depth + 1));
    }
    helper->pred_helper.concate_type = NO_CONCATE;
    return OG_SUCCESS;
}

static status_t expl_format_cube_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                      uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->cube.next, depth, "GENERATE CUBE");
}

static status_t expl_format_pivot_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                       uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->group.next, depth, "HASH GROUP PIVOT");
}

static status_t expl_format_unpivot_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                         uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->unpivot_p.next, depth, "UNPIVOT");
}

static status_t expl_format_rownum_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                        uint32 depth)
{
    if (helper->query->incl_flags & COND_INCL_ROWNUM) {
        return expl_format_next_plan(statement, helper, plan_node, plan_node->rownum_p.next, depth, "ROWNUM FILTER");
    }
    return expl_format_next_plan(statement, helper, plan_node, plan_node->rownum_p.next, depth, "ROWNUM COUNT");
}

static status_t expl_format_for_update_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                            uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->for_update.next, depth, "FOR UPDATE");
}

static status_t expl_format_connect_mtrl_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                              uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->cb_mtrl.next, depth,
                                 "CONNECT BY MATERIALIZE");
}

static status_t expl_format_vm_view_mtrl_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
                                              uint32 depth)
{
    return expl_format_next_plan(statement, helper, plan_node, plan_node->vm_view_p.next, depth, "VM VIEW");
}

static expl_plan_t g_expl_plan_funcs[] = {{PLAN_NODE_QUERY, expl_format_query_plan},
                                          {PLAN_NODE_UNION, expl_format_union_plan},
                                          {PLAN_NODE_UNION_ALL, expl_format_union_all_plan},
                                          {PLAN_NODE_MINUS, expl_format_minus_plan},
                                          {PLAN_NODE_HASH_MINUS, expl_format_minus_plan},
                                          {PLAN_NODE_MERGE, expl_format_merge_plan},
                                          {PLAN_NODE_INSERT, expl_format_insert_plan},
                                          {PLAN_NODE_DELETE, expl_format_delete_plan},
                                          {PLAN_NODE_UPDATE, expl_format_update_plan},
                                          {PLAN_NODE_SELECT, expl_format_select_plan},
                                          {PLAN_NODE_JOIN, expl_format_join_plan},
                                          {PLAN_NODE_SORT_GROUP, expl_format_group_by_plan},
                                          {PLAN_NODE_MERGE_SORT_GROUP, expl_format_group_by_plan},
                                          {PLAN_NODE_HASH_GROUP, expl_format_group_by_plan},
                                          {PLAN_NODE_INDEX_GROUP, expl_format_group_by_plan},
                                          {PLAN_NODE_QUERY_SORT, expl_format_sort_plan},
                                          {PLAN_NODE_SELECT_SORT, expl_format_select_sort_plan},
                                          {PLAN_NODE_AGGR, expl_format_aggr_plan},
                                          {PLAN_NODE_INDEX_AGGR, expl_format_aggr_plan},
                                          {PLAN_NODE_SORT_DISTINCT, expl_format_distinct_plan},
                                          {PLAN_NODE_HASH_DISTINCT, expl_format_distinct_plan},
                                          {PLAN_NODE_INDEX_DISTINCT, expl_format_distinct_plan},
                                          {PLAN_NODE_HAVING, expl_format_having_plan},
                                          {PLAN_NODE_SCAN, expl_format_scan_plan},
                                          {PLAN_NODE_QUERY_LIMIT, expl_format_query_limit_plan},
                                          {PLAN_NODE_SELECT_LIMIT, expl_format_select_limit_plan},
                                          {PLAN_NODE_CONNECT, expl_format_connect_plan},
                                          {PLAN_NODE_FILTER, expl_format_filter_plan},
                                          {PLAN_NODE_WINDOW_SORT, expl_format_window_sort_plan},
                                          {PLAN_NODE_REMOTE_SCAN, expl_format_default_plan_node},
                                          {PLAN_NODE_GROUP_MERGE, expl_format_group_merge_plan},
                                          {PLAN_NODE_HASH_GROUP_PAR, expl_format_parallel_group_plan},
                                          {PLAN_NODE_HASH_MTRL, expl_format_hash_mtrl_plan},
                                          {PLAN_NODE_CONCATE, expl_format_concate_plan},
                                          {PLAN_NODE_QUERY_SORT_PAR, expl_format_sort_plan},
                                          {PLAN_NODE_QUERY_SIBL_SORT, expl_format_sort_plan},
                                          {PLAN_NODE_GROUP_CUBE, expl_format_cube_plan},
                                          {PLAN_NODE_HASH_GROUP_PIVOT, expl_format_pivot_plan},
                                          {PLAN_NODE_UNPIVOT, expl_format_unpivot_plan},
                                          {PLAN_NODE_ROWNUM, expl_format_rownum_plan},
                                          {PLAN_NODE_FOR_UPDATE, expl_format_for_update_plan},
                                          {PLAN_NODE_WITHAS_MTRL, expl_format_default_plan_node},
                                          {PLAN_NODE_CONNECT_MTRL, expl_format_connect_mtrl_plan},
                                          {PLAN_NODE_CONNECT_HASH, expl_format_connect_plan},
                                          {PLAN_NODE_VM_VIEW_MTRL, expl_format_vm_view_mtrl_plan}};

status_t expl_format_plan_node(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node, uint32 depth)
{
    CM_ASSERT(plan_node->type <= sizeof(g_expl_plan_funcs) / sizeof(expl_plan_t));
    CM_ASSERT(plan_node->type == g_expl_plan_funcs[plan_node->type - PLAN_NODE_QUERY].type);
    CM_ASSERT(g_expl_plan_funcs[plan_node->type - PLAN_NODE_QUERY].explain_plan_func != NULL);

    return g_expl_plan_funcs[plan_node->type - PLAN_NODE_QUERY].explain_plan_func(statement, helper, plan_node, depth);
}
