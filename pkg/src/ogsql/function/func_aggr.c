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
 * func_aggr.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/function/func_aggr.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_aggr.h"
#include "ogsql_table_func.h"
#include "srv_instance.h"
#include "ogsql_cond_rewrite.h"
#include "func_parser.h"
#include "ogsql_mtrl.h"
#include "ogsql_aggr.h"

/* ******************************************************************************
Function       : count aggregate function
Output         : None
Return         : OG_SUCCESS or OG_ERROR
Modification   : Create function
****************************************************************************** */
status_t sql_func_array_agg(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_exec_expr_node(stmt, func->argument->root, res);
}

status_t sql_verify_array_agg(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *arg = NULL;

    if (sql_verify_func_node(verif, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    arg = func->argument;
    if (arg->root->typmod.is_array == OG_TRUE ||
        (arg->root->type == EXPR_NODE_COLUMN && !cm_datatype_arrayable(arg->root->value.v_col.datatype))) {
        OG_SRC_THROW_ERROR(arg->root->loc, ERR_INVALID_ARG_TYPE);
        return OG_ERROR;
    }

    verif->incl_flags |= SQL_INCL_ARRAY;

    /* elements' datatype */
    func->typmod = func->argument->root->typmod;
    func->typmod.is_array = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_verify_avg_median_core(expr_node_t *func, bool32 is_avg)
{
    og_type_t arg_type = func->argument->root->datatype;
    switch (arg_type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            func->datatype = OG_TYPE_NUMBER;
            func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
            return OG_SUCCESS;
        case OG_TYPE_NUMBER2:
            func->datatype = OG_TYPE_NUMBER2;
            func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
            return OG_SUCCESS;

        case OG_TYPE_REAL:
            func->datatype = OG_TYPE_REAL;
            func->size = OG_REAL_SIZE;
            return OG_SUCCESS;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            if (is_avg) {
                func->datatype = OG_TYPE_NUMBER;
                func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
                return OG_SUCCESS;
            }
            break;

        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            if (!is_avg) {
                func->datatype = arg_type;
                func->typmod = func->argument->root->typmod;
                return OG_SUCCESS;
            }
            break;

        case OG_TYPE_UNKNOWN:
            func->datatype = OG_TYPE_UNKNOWN;
            func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
            return OG_SUCCESS;

        default:
            break;
    }

    OG_THROW_ERROR(ERR_TYPE_MISMATCH, is_avg ? "NUMERIC" : "NUMERIC OR DATETIME", get_datatype_name_str(arg_type));
    return OG_ERROR;
}

static status_t sql_verify_avg_median(sql_verifier_t *verif, expr_node_t *func, bool32 is_avg)
{
    CM_POINTER2(verif, func);

    uint32 excl_flags = verif->excl_flags | SQL_EXCL_STAR;
    verif->excl_flags = excl_flags | SQL_EXCL_PARENT;
    OG_RETURN_IFERR(sql_verify_func_node(verif, func, 1, 1, OG_INVALID_ID32));
    verif->excl_flags = excl_flags;
    return sql_verify_avg_median_core(func, is_avg);
}

status_t sql_verify_avg(sql_verifier_t *verif, expr_node_t *func)
{
    return sql_verify_avg_median(verif, func, OG_TRUE);
}

status_t sql_verify_covar_or_corr(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    uint32 excl_flags = verif->excl_flags;
    OG_BIT_SET(verif->excl_flags, SQL_EXCL_AGGR);

    OG_RETURN_IFERR(sql_verify_func_node(verif, func, 2, 2, OG_INVALID_ID32));
    if (func->dis_info.need_distinct) {
        OG_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR,
            "DISTINCT option not allowed for this function");
        return OG_ERROR;
    }

    expr_tree_t *arg = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return OG_ERROR;
    }

    arg = arg->next;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, TREE_DATATYPE(arg));
        return OG_ERROR;
    }

    verif->excl_flags = excl_flags;
    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    if (verif->curr_query != NULL) {
        verif->curr_query->exists_covar = OG_TRUE;
    }
    return OG_SUCCESS;
}

status_t sql_func_covar_or_corr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    if (sql_exec_expr_node(stmt, func->argument->root, &result[0]) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_exec_expr_node(stmt, func->argument->next->root, &result[1]) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_func_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t value;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    res->is_null = OG_FALSE;
    res->type = OG_TYPE_BIGINT;

    if (arg->root->type == EXPR_NODE_STAR) {
        res->v_bigint = 1;
    } else {
        OG_RETURN_IFERR(sql_exec_expr(stmt, arg, &value));
        res->v_bigint = value.is_null ? 0 : 1;
    }

    return OG_SUCCESS;
}

status_t sql_verify_count(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    // explicit allow count(*) usage
    uint32 excl_flags = verif->excl_flags;
    OG_BIT_RESET(verif->excl_flags, SQL_EXCL_STAR);

    if (func->argument == NULL || func->argument->next != NULL) {
        OG_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), 1, 1);
        return OG_ERROR;
    }

    expr_node_t *node = func->argument->root;

    if (node->type == EXPR_NODE_STAR) {
        if (node->word.column.table.len != 0) {
            OG_SRC_THROW_ERROR(node->word.column.table.loc, ERR_INVALID_FUNC_PARAMS,
                "user.table.column or table.column or column is invalid");
            return OG_ERROR;
        }

        if (func->dis_info.need_distinct) {
            OG_SRC_THROW_ERROR(node->word.column.table.loc, ERR_INVALID_FUNC_PARAMS, "missing expression");
            return OG_ERROR;
        }
    } else {
        OG_RETURN_IFERR(sql_verify_expr(verif, func->argument));
    }

    if ((verif->incl_flags & SQL_INCL_WINSORT) && (node->type == EXPR_NODE_STAR)) {
        node->type = EXPR_NODE_CONST;
        node->value.v_bigint = 1;
        node->value.type = OG_TYPE_BIGINT;
        node->value.is_null = OG_FALSE;
    }

    func->datatype = OG_TYPE_BIGINT;
    func->size = OG_BIGINT_SIZE;
    verif->excl_flags = excl_flags;
    return OG_SUCCESS;
}

static status_t sql_calc_cume_dist_satisfy(sql_stmt_t *stmt, expr_tree_t *arg_expr, sort_item_t *item, bool32 *satisfy,
    bool32 *continus)
{
    variant_t constant;
    variant_t val_order;
    int32 result = 0;

    CM_POINTER3(stmt, arg_expr, item);

    // if the position of contant is behind of val_order, it will be true. as if all data has been sorted
    *satisfy = OG_FALSE;
    *continus = OG_FALSE;

    OG_RETURN_IFERR(sql_exec_expr(stmt, arg_expr, &constant));
    OG_RETURN_IFERR(sql_exec_expr(stmt, item->expr, &val_order));
    
    if (constant.is_null && val_order.is_null) {
        *satisfy = OG_TRUE;
        *continus = OG_TRUE;
    } else if (constant.is_null) {
        if (item->nulls_pos == SORT_NULLS_LAST) {
            *satisfy = OG_TRUE;
        }
    } else if (val_order.is_null) {
        if (item->nulls_pos == SORT_NULLS_FIRST || item->nulls_pos == SORT_NULLS_DEFAULT) {
            *satisfy = OG_TRUE;
        }
    } else {
        if (!(OG_IS_NUMERIC_TYPE(val_order.type))) {
            OG_RETURN_IFERR(sql_convert_variant2(stmt, &constant, &val_order));
        }
        OG_RETURN_IFERR(var_compare(SESSION_NLS(stmt), &constant, &val_order, &result));
        if (item->direction == SORT_MODE_ASC || item->direction == SORT_MODE_NONE) {
            if (result >= 0) {
                *satisfy = OG_TRUE;
                *continus = (result == 0) ? OG_TRUE : OG_FALSE;
            }
        } else {
            if (result <= 0) {
                *satisfy = OG_TRUE;
                *continus = (result == 0) ? OG_TRUE : OG_FALSE;
            }
        }
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

status_t sql_func_cume_dist(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);
    uint32 i = 0;
    sort_item_t *item = NULL;
    expr_tree_t *arg = NULL;
    bool32 satisfy = OG_FALSE;
    bool32 continus = OG_FALSE;

    res->type = OG_TYPE_BIGINT;
    res->is_null = OG_FALSE;
    res->v_bigint = 0;

    /*
     * actually , there is no need to do sort, you could only fetch all the data,
     * and just compare according to the sort_item's order mode
     */
    arg = func->argument;
    for (; i < func->sort_items->count; i++) {
        item = (sort_item_t *)cm_galist_get(func->sort_items, i);
        OG_RETURN_IFERR(sql_calc_cume_dist_satisfy(stmt, arg, item, &satisfy, &continus));

        if (!satisfy) {
            return OG_SUCCESS;
        }
        if (!continus) {
            break;
        }

        arg = arg->next;
    }

    res->v_bigint = 1;
    return OG_SUCCESS;
}

static status_t sql_verify_order_by_expr(sql_verifier_t *verf, expr_tree_t *arg_expr, sort_item_t *item, og_type_t type)
{
    variant_t *pvar;
    variant_t constant;

    constant = arg_expr->root->value;
    pvar = &constant;

    OG_RETURN_IFERR(sql_convert_variant(verf->stmt, pvar, type));
    if (OG_IS_LOB_TYPE(pvar->type)) {
        OG_SRC_THROW_ERROR_EX(item->expr->loc, ERR_SQL_SYNTAX_ERROR, "unexpected LOB datatype occurs");
        return OG_ERROR;
    }

    // copy string, binary, and raw datatype into SQL context
    if ((!pvar->is_null) && OG_IS_VARLEN_TYPE(pvar->type)) {
        text_t text_bak = pvar->v_text;
        OG_RETURN_IFERR(sql_copy_text(verf->stmt->context, &text_bak, &pvar->v_text));
    }

    return OG_SUCCESS;
}

static status_t sql_verify_sort_param(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 i;
    sort_item_t *item = NULL;
    expr_tree_t *arg = NULL;
    CM_POINTER2(verif, func);

    uint32 ori_excl_flags = verif->excl_flags;
    OG_BIT_SET(verif->excl_flags, SQL_EXCL_WIN_SORT | SQL_EXCL_AGGR | SQL_EXCL_SEQUENCE |
        SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_ARRAY | SQL_EXCL_UNNEST);
    if (sql_verify_func_node(verif, func, 1, OG_MAX_FUNC_ARGUMENTS, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (func->value.v_func.arg_cnt != func->sort_items->count) {
        OG_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR, "invalid number of arguments");
        return OG_ERROR;
    }

    arg = func->argument;
    for (i = 0; i < func->sort_items->count; i++) {
        // param must be constant, include null
        if (!NODE_IS_OPTMZ_CONST(arg->root) && TREE_DATATYPE(arg) != OG_TYPE_UNKNOWN && !NODE_IS_RES_NULL(arg->root) &&
            !NODE_IS_RES_TRUE(arg->root) && !NODE_IS_RES_FALSE(arg->root)) {
            if (arg->root->argument != NULL) {
                if (!NODE_IS_OPTMZ_CONST(arg->root->argument->root)) {
                    OG_SRC_THROW_ERROR_EX(arg->root->argument->loc, ERR_SQL_SYNTAX_ERROR,
                        "Argument should be a constant");
                    return OG_ERROR;
                }
            } else {
                OG_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "Argument should be a constant");
                return OG_ERROR;
            }
        }

        if (OG_IS_LOB_TYPE(TREE_DATATYPE(arg))) {
            OG_SRC_THROW_ERROR_EX(arg->loc, ERR_SQL_SYNTAX_ERROR, "unexpected LOB datatype occurs");
            return OG_ERROR;
        }

        // verify the sort expr tree
        item = (sort_item_t *)cm_galist_get(func->sort_items, i);
        OG_RETURN_IFERR(sql_verify_expr_node(verif, item->expr->root));

        if (arg->root->type == EXPR_NODE_CONST && TREE_DATATYPE(item->expr) != OG_TYPE_UNKNOWN) {
            // param must can be convert to the sort item type
            OG_RETURN_IFERR(sql_verify_order_by_expr(verif, arg, item, item->expr->root->datatype));
        }

        arg = arg->next;
    }
    verif->excl_flags = ori_excl_flags;
    return OG_SUCCESS;
}

status_t sql_verify_cume_dist(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    OG_RETURN_IFERR(sql_verify_sort_param(verif, func));
    func->datatype = OG_TYPE_REAL;
    func->size = OG_REAL_SIZE;
    return OG_SUCCESS;
}

status_t ogsql_func_rank(sql_stmt_t *statement, expr_node_t *exprn, variant_t *var)
{
    CM_POINTER3(statement, exprn, var);
    bool32 cmp_great = OG_TRUE;
    var_set_not_null(var, OG_TYPE_INTEGER);
    OGSQL_SAVE_STACK(statement);
    if (OG_SUCCESS != sql_compare_sort_row_for_rank(statement, exprn, &cmp_great)) {
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }
    var->v_int = cmp_great ? 1 : 0;
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

status_t sql_func_dense_rank(sql_stmt_t *statement, expr_node_t *exprn, variant_t *var)
{
    CM_POINTER(var);
    var_set_not_null(var, OG_TYPE_INTEGER);
    var->v_int = 0;
    return OG_SUCCESS;
}

status_t sql_verify_dense_rank(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    OG_RETURN_IFERR(sql_verify_sort_param(verif, func));
    func->datatype = OG_TYPE_INTEGER;
    func->size = OG_INTEGER_SIZE;
    return OG_SUCCESS;
}

// swap the position of the first and second parameters
static status_t sql_adjust_args_pos(sql_stmt_t *stmt, expr_node_t *func)
{
    expr_tree_t *sep = NULL;
    expr_tree_t *arg = NULL;

    arg = func->argument;
    if (arg->next == NULL) {
        OG_RETURN_IFERR(sql_create_const_string_expr(stmt, &sep, ""));
    } else {
        sep = arg->next;
        arg->next = sep->next;
    }
    sep->next = arg;
    func->argument = sep;
    return OG_SUCCESS;
}

status_t sql_verify_listagg(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 1, 2, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // the first arg is delimiter, the second arg is column
    OG_RETURN_IFERR(sql_adjust_args_pos(verif->stmt, func));

    // verify within group(order by expr)
    OG_RETURN_IFERR(sql_verify_listagg_order(verif, func->sort_items));

    func->datatype = OG_TYPE_STRING;
    func->size = OG_MAX_ROW_SIZE;
    return OG_SUCCESS;
}

status_t sql_verify_min_max(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    uint32 excl_flags = verif->excl_flags;
    OG_BIT_SET(verif->excl_flags, SQL_EXCL_AGGR);

    if (sql_verify_func_node(verif, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }
    verif->excl_flags = excl_flags;
    func->typmod = TREE_TYPMODE(func->argument);
    sql_convert_lob_type(func, TREE_DATATYPE(func->argument));
    // min/max do not need distinct
    func->dis_info.need_distinct = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_verify_median(sql_verifier_t *verif, expr_node_t *func)
{
    expr_node_t *node = NULL;
    sort_item_t *sort_item = NULL;
    galist_t *cmp_list = NULL;
    sql_context_t *ogx = verif->stmt->context;
    OG_RETURN_IFERR(sql_verify_avg_median(verif, func, OG_FALSE));

    OG_RETURN_IFERR(sql_alloc_mem(ogx, sizeof(galist_t), (void **)&cmp_list));
    cm_galist_init(cmp_list, ogx, sql_alloc_mem);
    OG_RETURN_IFERR(cm_galist_new(cmp_list, sizeof(sort_item_t), (void **)&sort_item));
    OG_RETURN_IFERR(sql_clone_expr_node(ogx, func->argument->root, &node, sql_alloc_mem));
    OG_RETURN_IFERR(sql_alloc_mem(ogx, sizeof(expr_tree_t), (void **)&sort_item->expr));
    sort_item->expr->owner = ogx;
    sort_item->expr->root = node;
    sort_item->sort_mode.direction = SORT_MODE_ASC;
    sort_item->sort_mode.nulls_pos = SORT_NULLS_LAST;
    func->sort_items = cmp_list;
    return OG_SUCCESS;
}

status_t sql_verify_stddev_intern(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);
    uint32 excl_flags = verif->excl_flags;
    OG_BIT_SET(verif->excl_flags, SQL_EXCL_AGGR);

    OG_RETURN_IFERR(sql_verify_func_node(verif, func, 1, 1, OG_INVALID_ID32));

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return OG_ERROR;
    }

    verif->excl_flags = excl_flags;
    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    return OG_SUCCESS;
}

status_t sql_verify_sum(sql_verifier_t *verif, expr_node_t *func)
{
    CM_POINTER2(verif, func);

    if (sql_verify_func_node(verif, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return opr_infer_type_sum(func->argument->root->datatype, &func->typmod);
}

status_t sql_verify_approx_count_distinct(sql_verifier_t *verif, expr_node_t *func)
{
    uint32 excl_flags = verif->excl_flags;
    OG_BIT_SET(verif->excl_flags, SQL_EXCL_AGGR);

    if (sql_verify_func_node(verif, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    verif->excl_flags = excl_flags;

    func->size = OG_BIGINT_SIZE;
    func->datatype = OG_TYPE_BIGINT;
    func->dis_info.need_distinct = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_func_approx_count_distinct(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    char *buf = NULL;
    row_assist_t row_ass;

    result->type = OG_TYPE_BIGINT;
    result->is_null = OG_FALSE;

    CM_POINTER3(stmt, func, result);
    SQL_EXEC_FUNC_ARG_EX(func->argument, &var, result);

    OGSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, &var);

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));
    row_init(&row_ass, buf, OG_MAX_ROW_SIZE, 1);
    OG_RETURN_IFERR(sql_put_row_value(stmt, NULL, &row_ass, var.type, &var));
    result->v_bigint = sql_hash_func(buf);
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

status_t sql_func_normal_aggr(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);
    expr_node_t *arg_node = func->argument->root;
    return sql_exec_expr_node(stmt, arg_node, res);
}
