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
 * func_datatype.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/function/func_datatype.c
 *
 * -------------------------------------------------------------------------
 */

#include "func_datatype.h"
#include "func_calculate.h"
#include "func_convert.h"
#include "ogsql_expr_datatype.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_infer_round_trunc_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node,
    og_type_t *type)
{
    og_type_t arg_type;
    expr_tree_t *arg = func_node->argument;

    OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg->root, &arg_type));

    if (OG_IS_DATETIME_TYPE(arg_type)) {
        *type = OG_TYPE_DATE;
    } else {
        *type = OG_TYPE_NUMBER;
    }

    return OG_SUCCESS;
}

/* Infer the COSH/SINH result type from the argument type. */
static status_t sql_infer_hyperbolic_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node,
    og_type_t *type)
{
    og_type_t arg_type;

    OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, func_node->argument->root, &arg_type));
    if (arg_type == OG_TYPE_REAL) {
        *type = OG_TYPE_REAL;
        return OG_SUCCESS;
    }
    if (sql_match_numeric_type(arg_type) || arg_type == OG_TYPE_BOOLEAN) {
        *type = OG_TYPE_NUMBER;
        return OG_SUCCESS;
    }

    OG_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str(arg_type));
    return OG_ERROR;
}

/* Infer the common NUMBER or REAL result type while preserving typed NULL bind information. */
static status_t sql_infer_nanvl_remainder_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node,
    og_type_t *type)
{
    og_type_t arg_type;
    status_t status = OG_SUCCESS;
    bool32 saved_preserve_null_type = stmt->preserve_bind_null_type;

    *type = OG_TYPE_NUMBER;
    /* Inspect types only: NANVL must not evaluate its unused replacement. */
    stmt->preserve_bind_null_type = OG_TRUE;
    for (expr_tree_t *arg = func_node->argument; arg != NULL; arg = arg->next) {
        status = sql_infer_expr_node_datatype(stmt, query, arg->root, &arg_type);
        if (status != OG_SUCCESS) {
            break;
        }
        if (!sql_match_numeric_type(arg_type) && arg_type != OG_TYPE_BOOLEAN) {
            OG_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, arg_type);
            status = OG_ERROR;
            break;
        }
        if (arg_type == OG_TYPE_REAL || arg_type == OG_TYPE_FLOAT) {
            *type = OG_TYPE_REAL;
        }
    }
    stmt->preserve_bind_null_type = saved_preserve_null_type;
    return status;
}

static status_t sql_infer_coalesce_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node,
    og_type_t *type)
{
    expr_tree_t *arg = func_node->argument;
    expr_tree_t *first_arg = func_node->argument;

    typmode_t typmode_pre;
    typmode_t typmode_curr;
    typmode_t typmode_combine;

    while (arg != NULL) {
        typmode_curr = TREE_TYPMODE(arg);
        if (typmode_curr.datatype == OG_TYPE_UNKNOWN) {
            OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg->root, &typmode_curr.datatype));
        }

        if (arg == first_arg) {
            typmode_pre = typmode_curr;
        }

        if (cm_combine_typmode(typmode_pre, OG_FALSE, typmode_curr, OG_FALSE, &typmode_combine) != OG_SUCCESS) {
            cm_reset_error();
            *type = OG_TYPE_VARCHAR;
            return OG_SUCCESS;
        }

        if (get_datatype_weight(typmode_combine.datatype) > get_datatype_weight(typmode_curr.datatype)) {
            typmode_curr.datatype = typmode_combine.datatype;
        }
        typmode_pre = typmode_curr;
        arg = arg->next;
    }
    *type = typmode_curr.datatype;
    return OG_SUCCESS;
}

static status_t sql_infer_decode_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *type)
{
    expr_tree_t *result_expr = func_node->argument->next->next;
    og_type_t result_type;
    bool32 first = OG_TRUE;

    while (result_expr != NULL) {
        result_type = TREE_DATATYPE(result_expr);
        if (result_type == OG_TYPE_UNKNOWN) {
            OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, result_expr->root, &result_type));
        }

        if (first) {
            *type = result_type;
            first = OG_FALSE;
        }

        *type = decode_compatible_datatype(func_node, result_expr->root, *type, result_type);

        result_expr = result_expr->next;

        if (result_expr != NULL && result_expr->next != NULL) {
            result_expr = result_expr->next;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_infer_if_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *type)
{
    expr_tree_t *arg1 = func_node->argument;
    expr_tree_t *arg2 = arg1->next;
    og_type_t type1 = TREE_DATATYPE(arg1);
    og_type_t type2 = TREE_DATATYPE(arg2);

    if (type1 == OG_TYPE_UNKNOWN) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg1->root, &type1));
    }
    if (type2 == OG_TYPE_UNKNOWN) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg2->root, &type2));
    }

    return sql_adjust_if_type(type1, type2, type);
}

static status_t sql_infer_ifnull_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *type)
{
    expr_tree_t *arg1 = func_node->argument;
    expr_tree_t *arg2 = arg1->next;

    if (TREE_IS_RES_NULL(arg1)) {
        return sql_infer_expr_node_datatype(stmt, query, arg2->root, type);
    }
    if (TREE_IS_RES_NULL(arg2)) {
        return sql_infer_expr_node_datatype(stmt, query, arg1->root, type);
    }

    og_type_t type1 = TREE_DATATYPE(arg1);
    og_type_t type2 = TREE_DATATYPE(arg2);

    if (type1 == OG_TYPE_UNKNOWN) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg1->root, &type1));
    }
    if (type2 == OG_TYPE_UNKNOWN) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg2->root, &type2));
    }

    *type = sql_get_ifnull_compatible_datatype(type1, type2);

    return OG_SUCCESS;
}

static status_t sql_infer_nullif_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *type)
{
    expr_tree_t *arg1 = func_node->argument;
    expr_tree_t *arg2 = arg1->next;
    typmode_t typmode1 = TREE_TYPMODE(arg1);
    typmode_t typmode2 = TREE_TYPMODE(arg2);
    typmode_t typmode;

    if (typmode1.datatype == OG_TYPE_UNKNOWN) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg1->root, &typmode1.datatype));
    }
    if (typmode2.datatype == OG_TYPE_UNKNOWN) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, arg2->root, &typmode2.datatype));
    }

    OG_RETURN_IFERR(cm_combine_typmode(typmode1, OG_FALSE, typmode2, OG_FALSE, &typmode));
    *type = OG_IS_NUMERIC_TYPE(typmode.datatype) ? typmode.datatype : typmode1.datatype;

    return OG_SUCCESS;
}

static status_t sql_infer_nvl_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *type)
{
    expr_tree_t *arg1 = func_node->argument;
    expr_tree_t *arg2 = arg1->next;

    if (TREE_IS_RES_NULL(arg1)) {
        return sql_infer_expr_node_datatype(stmt, query, arg2->root, type);
    }

    return sql_infer_expr_node_datatype(stmt, query, arg1->root, type);
}

static status_t sql_infer_nvl2_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *type)
{
    expr_tree_t *arg2 = func_node->argument->next;
    expr_tree_t *arg3 = arg2->next;

    if (TREE_IS_RES_NULL(arg2)) {
        return sql_infer_expr_node_datatype(stmt, query, arg3->root, type);
    }

    return sql_infer_expr_node_datatype(stmt, query, arg2->root, type);
}

static status_t og_get_avg_median_argtype(bool32 is_median_func, og_type_t infer_type, og_type_t *output_type)
{
    if (infer_type == OG_TYPE_UNKNOWN) {
        *output_type = OG_TYPE_UNKNOWN;
    } else if (OG_IS_NUMERIC_TYPE(infer_type)) {
        *output_type = (infer_type == OG_TYPE_NUMBER2 || infer_type == OG_TYPE_REAL) ? infer_type : OG_TYPE_NUMBER;
    } else if (OG_IS_STRING_TYPE(infer_type) && !is_median_func) {
        *output_type = OG_TYPE_NUMBER;
    } else if (OG_IS_DATETIME_TYPE(infer_type) && is_median_func) {
        *output_type = infer_type;
    } else {
        OG_THROW_ERROR(ERR_TYPE_MISMATCH, is_median_func ? "NUMERIC OR DATETIME" : "NUMERIC",
            get_datatype_name_str(infer_type));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t og_infer_avg_median_datatype(sql_stmt_t *statement, sql_query_t *sql_qry, expr_node_t *func_exprn,
    og_type_t *output_type)
{
    og_type_t argument_type = OG_TYPE_UNKNOWN;
    bool32 is_median_func = func_exprn->value.v_func.func_id == ID_FUNC_ITEM_MEDIAN;

    if (sql_infer_expr_node_datatype(statement, sql_qry, func_exprn->argument->root, &argument_type) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to infer argument datatype of func %s", is_median_func ? "MEDIAN" : "AVG");
        return OG_ERROR;
    }

    if (og_get_avg_median_argtype(is_median_func, argument_type, output_type) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to get the argument datatype of func %s", is_median_func ? "MEDIAN" : "AVG");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/* Follow result-column references to infer the NANVL/REMAINDER result type. */
status_t sql_infer_pending_numeric_datatype(sql_stmt_t *stmt, sql_query_t *query, rs_column_t *rs_col,
    og_type_t *type)
{
    expr_node_t *node = NULL;
    var_column_t *v_col = NULL;
    sql_table_t *table = NULL;

    /* Only follow result-column wrappers; do not change empty-result inference for unrelated functions. */
    while (rs_col != NULL || node != NULL || v_col != NULL) {
        if (rs_col != NULL) {
            node = (rs_col->type == RS_COL_CALC) ? rs_col->expr->root : NULL;
            v_col = (rs_col->type == RS_COL_COLUMN) ? &rs_col->v_col : NULL;
            rs_col = NULL;
        }
        if (node != NULL) {
            switch (node->type) {
                case EXPR_NODE_FUNC:
                    if (sql_get_func(&node->value.v_func)->verify == sql_verify_nanvl_remainder) {
                        return sql_infer_expr_node_datatype(stmt, query, node, type);
                    }
                    return OG_SUCCESS;
                case EXPR_NODE_GROUP:
                    node = (expr_node_t *)node->value.v_vm_col.origin_ref;
                    continue;
                case EXPR_NODE_SELECT:
                    query = ((sql_select_t *)node->value.v_obj.ptr)->first_query;
                    rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, 0);
                    continue;
                case EXPR_NODE_COLUMN:
                case EXPR_NODE_TRANS_COLUMN:
                    v_col = &node->value.v_col;
                    break;
                default:
                    return OG_SUCCESS;
            }
        }
        if (v_col == NULL || query == NULL) {
            return OG_SUCCESS;
        }
        for (uint32 ancestor = v_col->ancestor; ancestor > 0 && query != NULL; ancestor--) {
            query = query->owner->parent;
        }
        if (query == NULL) {
            return OG_SUCCESS;
        }
        table = (sql_table_t *)sql_array_get(&query->tables, v_col->tab);
        if (table->type != SUBSELECT_AS_TABLE && table->type != WITH_AS_TABLE) {
            return OG_SUCCESS;
        }
        query = table->select_ctx->first_query;
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, v_col->col);
    }
    return OG_SUCCESS;
}

/* Infer the result type of an A-compatible function and report whether its ID is handled. */
static status_t sql_infer_func_node_datatype_compatibility_a(sql_stmt_t *stmt, sql_query_t *query,
    expr_node_t *func_node, og_type_t *og_type, bool32 *matched)
{
    *matched = OG_FALSE;
    if (func_node->value.v_func.pack_id != OG_INVALID_ID32) {
        return OG_SUCCESS;
    }

    switch (func_node->value.v_func.func_id) {
        case ID_FUNC_ITEM_A_COSH:
        case ID_FUNC_ITEM_A_SINH:
            *matched = OG_TRUE;
            return sql_infer_hyperbolic_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_A_NANVL:
        case ID_FUNC_ITEM_A_REMAINDER:
            *matched = OG_TRUE;
            return sql_infer_nanvl_remainder_datatype(stmt, query, func_node, og_type);
        default:
            return OG_SUCCESS;
    }
}

status_t sql_infer_func_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *og_type)
{
    sql_func_t *func = sql_get_func(&func_node->value.v_func);

    if (stmt->session->dbcompatibility == 'A') {
        bool32 matched = OG_FALSE;
        OG_RETURN_IFERR(sql_infer_func_node_datatype_compatibility_a(stmt, query, func_node, og_type, &matched));
        if (matched) {
            return OG_SUCCESS;
        }
    }
    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_GREATEST:
        case ID_FUNC_ITEM_LEAST:
        case ID_FUNC_ITEM_MIN:
        case ID_FUNC_ITEM_MAX:
            return sql_infer_expr_node_datatype(stmt, query, func_node->argument->root, og_type);
        case ID_FUNC_ITEM_AVG:
        case ID_FUNC_ITEM_MEDIAN:
            return og_infer_avg_median_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_ROUND:
        case ID_FUNC_ITEM_TRUNC:
            return sql_infer_round_trunc_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_COALESCE:
            return sql_infer_coalesce_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_DECODE:
            return sql_infer_decode_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_IF:
            return sql_infer_if_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_IFNULL:
            return sql_infer_ifnull_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_NULLIF:
            return sql_infer_nullif_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_NVL:
            return sql_infer_nvl_datatype(stmt, query, func_node, og_type);
        case ID_FUNC_ITEM_NVL2:
            return sql_infer_nvl2_datatype(stmt, query, func_node, og_type);
        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the datatype of %s cannnot be unknown", T2S(&func->name));
            return OG_ERROR;
    }
}

#ifdef __cplusplus
}
#endif
