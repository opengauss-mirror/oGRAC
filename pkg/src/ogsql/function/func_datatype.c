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

status_t sql_infer_func_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *func_node, og_type_t *og_type)
{
    sql_func_t *func = sql_get_func(&func_node->value.v_func);
    switch (func->builtin_func_id) {
        case ID_FUNC_ITEM_AVG:
        case ID_FUNC_ITEM_GREATEST:
        case ID_FUNC_ITEM_LEAST:
        case ID_FUNC_ITEM_MIN:
        case ID_FUNC_ITEM_MAX:
        case ID_FUNC_ITEM_MEDIAN:
            return sql_infer_expr_node_datatype(stmt, query, func_node->argument->root, og_type);
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
