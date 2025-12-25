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
 * plan_rbo.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/plan_rbo.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_rbo.h"
#include "ogsql_verifier.h"
#include "ogsql_func.h"
#include "dml_parser.h"
#include "knl_dc.h"
#include "cbo_base.h"
#include "ogsql_scan.h"
#include "srv_instance.h"
#include "plan_query.h"

#ifdef __cplusplus
extern "C" {
#endif
static inline void sql_set_func_arg_name(expr_node_t *column, expr_node_t *func)
{
    expr_tree_t *arg = func->argument;

    while (arg != NULL) {
        if (arg->root != NULL && arg->root->type == EXPR_NODE_COLUMN &&
            arg->root->value.v_col.col == column->value.v_col.col) {
            arg->root->word = column->word;
            break;
        }
        arg = arg->next;
    }
}

static bool32 rbo_find_column_in_func_args(query_field_t *query_field, knl_index_desc_t *index, uint16 idx_id)
{
    knl_icol_info_t *col_info = &index->columns_info[idx_id];
    for (uint16 j = 0; j < col_info->arg_count; j++) {
        if (col_info->arg_cols[j] == query_field->col_id) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

bool32 rbo_find_column_in_func_index(query_field_t *query_field, knl_index_desc_t *index, sql_table_t *table)
{
    for (uint16 i = 0; i < index->column_count; i++) {
        if (index->columns[i] < DC_VIRTUAL_COL_START) {
            if (index->columns[i] == query_field->col_id) {
                return OG_TRUE;
            }
        } else if (rbo_find_column_in_func_args(query_field, index, i)) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

bool32 chk_part_key_match_index(dc_entity_t *entity, uint32 part_key_count, knl_index_desc_t *index, uint16 equal_to)
{
    for (uint16 i = 0; i < part_key_count; ++i) {
        uint16 part_key_col = knl_part_key_column_id(entity, i);
        uint16 idx_id = OG_INVALID_ID16;
        for (uint16 j = 0; j < index->column_count; j++) {
            if (index->columns[j] == part_key_col) {
                idx_id = j;
                break;
            }
        }
        if (idx_id == OG_INVALID_ID16) {
            return OG_FALSE;
        }
        if (idx_id < equal_to) {
            continue;
        }
        if (equal_to + i != idx_id) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static inline status_t sql_de_adjust_node_type(visit_assist_t *visit_ass, expr_node_t **node)
{
    if ((*node)->type == EXPR_NODE_DIRECT_COLUMN) {
        (*node)->value.v_col.tab = (uint16)visit_ass->result0;
        (*node)->type = EXPR_NODE_COLUMN;
    }

    return OG_SUCCESS;
}

void rbo_update_column_in_func(sql_stmt_t *stmt, expr_node_t **node, uint32 table_id)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, NULL);
    visit_ass.result0 = table_id;
    (void)visit_expr_node(&visit_ass, node, sql_de_adjust_node_type);
}

status_t sql_get_index_col_node(sql_stmt_t *stmt, knl_column_t *knl_col, expr_node_t *column_node, expr_node_t **node,
    uint32 table_id, uint32 col_id)
{
    if (!KNL_COLUMN_IS_VIRTUAL(knl_col)) {
        column_node->value.v_col.ancestor = 0;
        column_node->value.v_col.tab = table_id;
        column_node->value.v_col.col = (uint16)col_id;
        column_node->value.v_col.datatype = knl_col->datatype;
        column_node->datatype = knl_col->datatype;
        column_node->type = EXPR_NODE_COLUMN;
        column_node->unary = UNARY_OPER_NONE;
        *node = column_node;
    } else {
        OG_RETURN_IFERR(
            sql_clone_expr_node((void *)stmt, ((expr_tree_t *)knl_col->default_expr)->root, node, sql_stack_alloc));
        rbo_update_column_in_func(stmt, node, table_id);
    }
    return OG_SUCCESS;
}

/* !
 * \brief Covert a variant into ROWNUM type. When a ROWNUM is in comparison operation,
 * we need to convert another operand into rownum type. The default ROWNUM type is
 * INT32, however, some users may provides a double type for ROWNUM comparison.
 *
 */
static inline status_t var_as_rownum(variant_t *var, og_type_t type)
{
    if (type == OG_TYPE_REAL) {
        return var_as_real(var);
    } else {
        return var_as_integer(var);
    }
}

#define CONVER_VAR_TO_ROWNUM_TYPE(var, type)      \
    if (var_as_rownum(var, type) != OG_SUCCESS) { \
        return OG_ERROR;                          \
    }

status_t rbo_try_rownum_optmz(sql_stmt_t *stmt, cond_node_t *node, uint32 *max_rownum, bool8 *rnum_pending)
{
    return OG_SUCCESS;
}

static inline void rbo_get_opt_full_scan_flag(plan_assist_t *pa, sql_table_t *table, knl_index_desc_t **opt_index,
    uint16 *opt_scan_flag, uint8 *opt_index_dsc)
{
    *opt_index = NULL;
    *opt_scan_flag = *opt_index_dsc = 0;
}


#ifdef __cplusplus
}
#endif
