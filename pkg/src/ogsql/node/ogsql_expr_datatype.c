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
 * ogsql_expr_datatype.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/node/ogsql_expr_datatype.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_expr_datatype.h"
#include "func_datatype.h"
#include "ogsql_expr_verifier.h"
#include "dml_executor.h"
#include "ogsql_winsort.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_infer_column_datatype(sql_stmt_t *stmt, sql_query_t *query, var_column_t *v_col, og_type_t *type);

static status_t sql_infer_rs_column_datatype(sql_stmt_t *stmt, sql_query_t *query, uint32 col_id, og_type_t *type)
{
    rs_column_t *rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, col_id);
    if (rs_col->type == RS_COL_CALC) {
        return sql_infer_expr_node_datatype(stmt, query, rs_col->expr->root, type);
    }

    return sql_infer_column_datatype(stmt, query, &rs_col->v_col, type);
}

static status_t sql_infer_column_datatype(sql_stmt_t *stmt, sql_query_t *query, var_column_t *v_col, og_type_t *type)
{
    uint32 ancestor = v_col->ancestor;

    while (ancestor > 0) {
        query = query->owner->parent;
        ancestor--;
    }

    sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, v_col->tab);
    // if expr_node is EXPR_NODE_COLUMN and datatype is UNKNOWN, it must be rs_column of subselect
    CM_ASSERT(table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE);

    return sql_infer_rs_column_datatype(stmt, table->select_ctx->first_query, v_col->col, type);
}

static inline status_t sql_infer_group_expr_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node,
    og_type_t *type)
{
    expr_node_t *origin_node = (expr_node_t *)node->value.v_vm_col.origin_ref;
    return sql_infer_expr_node_datatype(stmt, query, origin_node, type);
}

static status_t sql_infer_bind_param_datatype(sql_stmt_t *stmt, expr_node_t *node, og_type_t *type)
{
    variant_t var;
    OG_RETURN_IFERR(sql_get_expr_node_value(stmt, node, &var));
    if (var.is_null) {
        *type = OG_DATATYPE_OF_NULL;
    } else {
        *type = var.type;
    }
    return OG_SUCCESS;
}

static inline status_t sql_infer_oper_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node,
    og_type_t *type)
{
    og_type_t l_type;
    og_type_t r_type;
    OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, node->left, &l_type));
    OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, node->right, &r_type));
    return opr_infer_type((operator_type_t)node->type, l_type, r_type, type);
}

static status_t sql_infer_case_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, og_type_t *type)
{
    case_expr_t *case_expr = (case_expr_t *)node->value.v_pointer;
    case_pair_t *case_pair = NULL;
    og_type_t temp_type;

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, case_pair->value->root, &temp_type));
        if (i == 0) {
            *type = temp_type;
            continue;
        }
        if (*type == temp_type) {
            continue;
        }
        *type = sql_get_case_expr_compatible_datatype(*type, temp_type);
    }

    if (case_expr->default_expr != NULL) {
        OG_RETURN_IFERR(sql_infer_expr_node_datatype(stmt, query, case_expr->default_expr->root, &temp_type));
        if (*type != temp_type) {
            *type = sql_get_case_expr_compatible_datatype(*type, temp_type);
        }
    }

    return OG_SUCCESS;
}

static inline status_t sql_infer_select_node_datatype(sql_stmt_t *stmt, expr_node_t *node, og_type_t *type)
{
    sql_select_t *select_ctx = (sql_select_t *)node->value.v_obj.ptr;

    return sql_infer_rs_column_datatype(stmt, select_ctx->first_query, 0, type);
}

static inline status_t sql_infer_aggr_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node,
    og_type_t *type)
{
    uint32 aggr_id = node->value.v_func.func_id;
    expr_node_t *aggr_node = (expr_node_t *)cm_galist_get(query->aggrs, aggr_id);
    return sql_infer_func_node_datatype(stmt, query, aggr_node, type);
}

static inline status_t sql_infer_winsort_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node,
    og_type_t *type)
{
    expr_node_t *func_node = node->argument->root;
    return sql_infer_expr_node_datatype(stmt, query, func_node->argument->root, type);
}

status_t sql_infer_expr_node_datatype(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node, og_type_t *og_type)
{
    if (node->datatype != OG_TYPE_UNKNOWN) {
        *og_type = node->datatype;
        return OG_SUCCESS;
    }
    switch (node->type) {
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_TRANS_COLUMN:
            return sql_infer_column_datatype(stmt, query, &node->value.v_col, og_type);
        case EXPR_NODE_GROUP:
            return sql_infer_group_expr_datatype(stmt, query, node, og_type);
        case EXPR_NODE_PARAM:
            return sql_infer_bind_param_datatype(stmt, node, og_type);
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
            return sql_infer_oper_node_datatype(stmt, query, node, og_type);
        case EXPR_NODE_NEGATIVE:
        case EXPR_NODE_PRIOR:
            return sql_infer_expr_node_datatype(stmt, query, node->right, og_type);
        case EXPR_NODE_CASE:
            return sql_infer_case_node_datatype(stmt, query, node, og_type);
        case EXPR_NODE_SELECT:
            return sql_infer_select_node_datatype(stmt, node, og_type);
        case EXPR_NODE_PROC:
        case EXPR_NODE_FUNC:
            return sql_infer_func_node_datatype(stmt, query, node, og_type);
        case EXPR_NODE_AGGR:
            return sql_infer_aggr_node_datatype(stmt, query, node, og_type);
        case EXPR_NODE_OVER:
            return sql_infer_winsort_node_datatype(stmt, query, node, og_type);
        default:
            OG_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "expr node type is not supported here");
            return OG_ERROR;
    }
}

#ifdef __cplusplus
}
#endif
