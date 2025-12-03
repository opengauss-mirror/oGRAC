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
 * pl_base.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/type/pl_base.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_base.h"

status_t udt_verify_construct_base(sql_verifier_t *verif, expr_node_t *node, uint32 min_args, uint32 max_args,
    text_t *name, verify_elemt_t verify)
{
    uint32 arg_count = 0;
    udt_constructor_t *v_construct = &node->value.v_construct;
    expr_tree_t *expr = node->argument;
    uint32 excl_flags = verif->excl_flags;
    verif->excl_flags |= PL_UDT_EXCL;

    while (expr != NULL) {
        OG_RETURN_IFERR(sql_verify_expr_node(verif, expr->root));
        if (sql_is_skipped_expr(expr)) {
            arg_count++;
            expr = expr->next;
            continue;
        }

        if (verify(verif, arg_count, v_construct->meta, expr) != OG_SUCCESS) {
            cm_reset_error();
            OG_SRC_THROW_ERROR(node->loc, ERR_PL_WRONG_ARG_METHOD_INVOKE, T2S(name));
            return OG_ERROR;
        }

        arg_count++;

        expr = expr->next;
    }

    if (arg_count < min_args || arg_count > max_args) {
        OG_SRC_THROW_ERROR(node->loc, ERR_PL_WRONG_ARG_METHOD_INVOKE, T2S(name));
        return OG_ERROR;
    }

    v_construct->arg_cnt = arg_count;
    verif->excl_flags = excl_flags;
    return OG_SUCCESS;
}


status_t udt_verify_method_node(sql_verifier_t *verif, expr_node_t *node, uint32 min_args, uint32 max_args)
{
    uint32 arg_count = 0;
    udt_method_t *method = &node->value.v_method;

    CM_POINTER2(verif, node);
    expr_tree_t *expr = node->argument;
    while (expr != NULL) {
        arg_count++;
        if (expr->root->type == EXPR_NODE_PRIOR) {
            OG_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
            return OG_ERROR;
        }

        if (sql_verify_expr_node(verif, expr->root) != OG_SUCCESS) {
            return OG_ERROR;
        }

        expr = expr->next;
    }

    if (arg_count < min_args || arg_count > max_args) {
        OG_SRC_THROW_ERROR(node->loc, ERR_PL_WRONG_ARG_METHOD_INVOKE, GET_COLL_METHOD_DESC(method->id));
        return OG_ERROR;
    }

    method->arg_cnt = arg_count;

    return OG_SUCCESS;
}
