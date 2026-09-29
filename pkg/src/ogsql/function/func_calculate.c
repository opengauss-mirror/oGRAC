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
 * func_calculate.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/function/func_calculate.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_calculate.h"
#include "func_convert.h"
#include "func_datatype.h"
#include "func_hex.h"
#include "dml_executor.h"
#include "srv_instance.h"

status_t sql_func_abs(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument; // the first argument
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, res, res);

    if (OG_SUCCESS != var_as_decimal(res)) {
        return OG_ERROR;
    }

    res->is_null = OG_FALSE;
    cm_dec_abs(&res->v_dec);
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_verify_abs(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = (uint16)OG_MAX_DEC_OUTPUT_ALL_PREC;
    return OG_SUCCESS;
}

status_t sql_func_sin(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_sin(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

/* trigonometric functions' verification, such as sin(x), cos(x), tan(x), asin(x) */
status_t sql_verify_trigonometric(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

status_t sql_verify_radians(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

status_t sql_func_cos(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_cos(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

typedef enum en_sql_hyperbolic_type {
    SQL_HYPERBOLIC_COSH = 0,
    SQL_HYPERBOLIC_SINH = 1,
    SQL_HYPERBOLIC_MAX = 2,
} sql_hyperbolic_type_t;

#define SQL_HYPERBOLIC_SERIES_MAX_ITERATIONS 64
#define SQL_HYPERBOLIC_EXP_DIVISOR 2
#define SQL_REMAINDER_HALF_SCALE 2
#define SQL_NANVL_REMAINDER_ARG_COUNT 2
/* Oracle 26ai SQL NUMBER path overflows at the immediately tested values above these limits. */
#define SQL_ORACLE_NUMBER_COSH_MAX_INPUT "282.57858863455690819872393985054486897"
#define SQL_ORACLE_NUMBER_SINH_MAX_INPUT "282.58006617333443970665056803202391465"

/* Validate the COSH/SINH operation type. */
static status_t sql_check_hyperbolic_type(sql_hyperbolic_type_t type)
{
    if ((uint32)type >= (uint32)SQL_HYPERBOLIC_MAX) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "invalid hyperbolic type: %d", (int32)type);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* Compute COSH/SINH with a dec8 Taylor series for |x| <= 1. */
static status_t sql_calc_hyperbolic_series(const dec8_t *value, sql_hyperbolic_type_t type, dec8_t *result)
{
    dec8_t square;
    dec8_t term;
    dec8_t sum;
    dec8_t next_term;
    dec8_t next_sum;
    uint32 i;

    OG_RETURN_IFERR(cm_dec_mul(value, value, &square));
    if (type == SQL_HYPERBOLIC_COSH) {
        cm_int32_to_dec(1, &term);
    } else {
        cm_dec_copy(&term, value);
    }
    cm_dec_copy(&sum, &term);

    for (i = 1; i <= SQL_HYPERBOLIC_SERIES_MAX_ITERATIONS; i++) {
        int64 left = (type == SQL_HYPERBOLIC_COSH) ? (int64)(2 * i - 1) : (int64)(2 * i);
        int64 right = left + 1;

        OG_RETURN_IFERR(cm_dec_mul(&term, &square, &next_term));
        OG_RETURN_IFERR(cm_dec_div_int64(&next_term, left * right, &next_term));
        if (DECIMAL8_IS_ZERO(&next_term)) {
            break;
        }

        OG_RETURN_IFERR(cm_dec_add(&sum, &next_term, &next_sum));
        if (cm_dec_cmp(&sum, &next_sum) == 0) {
            break;
        }
        cm_dec_copy(&term, &next_term);
        cm_dec_copy(&sum, &next_sum);
    }

    cm_dec_copy(result, &sum);
    return OG_SUCCESS;
}

/* Check the NUMBER input against the Oracle-compatible COSH/SINH limits. */
static status_t sql_check_hyperbolic_number_range(const dec8_t *value, sql_hyperbolic_type_t type)
{
    dec8_t abs_value;
    dec8_t max_input;
    const char *max_input_text = (type == SQL_HYPERBOLIC_COSH) ? SQL_ORACLE_NUMBER_COSH_MAX_INPUT :
        SQL_ORACLE_NUMBER_SINH_MAX_INPUT;

    cm_dec_copy(&abs_value, value);
    cm_dec_abs(&abs_value);
    OG_RETURN_IFERR(cm_str_to_dec8(max_input_text, &max_input));
    if (cm_dec_cmp(&abs_value, &max_input) > 0) {
        OG_THROW_ERROR(ERR_NUM_OVERFLOW);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* Compute NUMBER COSH/SINH using a Taylor series or exponential formula. */
static status_t sql_calc_hyperbolic_number(variant_t *value, sql_hyperbolic_type_t type, variant_t *result)
{
    dec8_t abs_value;
    dec8_t exp_value;
    dec8_t inv_exp_value;
    dec8_t combined;
    dec8_t one;
    bool32 negative;

    OG_RETURN_IFERR(var_as_decimal(value));
    OG_RETURN_IFERR(sql_check_hyperbolic_number_range(&value->v_dec, type));

    cm_dec_copy(&abs_value, &value->v_dec);
    negative = IS_DEC8_NEG(&abs_value);
    cm_dec_abs(&abs_value);

    cm_int32_to_dec(1, &one);
    if (cm_dec_cmp(&abs_value, &one) <= 0) {
        OG_RETURN_IFERR(sql_calc_hyperbolic_series(&value->v_dec, type, &result->v_dec));
    } else {
        OG_RETURN_IFERR(cm_dec_exp(&abs_value, &exp_value));
        OG_RETURN_IFERR(cm_dec_divide(&one, &exp_value, &inv_exp_value));
        if (type == SQL_HYPERBOLIC_COSH) {
            OG_RETURN_IFERR(cm_dec_add(&exp_value, &inv_exp_value, &combined));
        } else {
            OG_RETURN_IFERR(cm_dec_subtract(&exp_value, &inv_exp_value, &combined));
        }
        OG_RETURN_IFERR(cm_dec_div_int64(&combined, SQL_HYPERBOLIC_EXP_DIVISOR, &result->v_dec));
        if (type == SQL_HYPERBOLIC_SINH && negative) {
            cm_dec_negate(&result->v_dec);
        }
    }

    result->type = OG_TYPE_NUMBER;
    result->is_null = OG_FALSE;
    return OG_SUCCESS;
}

/* Dispatch COSH/SINH to REAL or NUMBER computation according to the runtime argument type. */
static status_t sql_func_hyperbolic(sql_stmt_t *stmt, expr_node_t *func, variant_t *res,
    sql_hyperbolic_type_t type)
{
    variant_t value;
    expr_tree_t *arg = NULL;

    CM_POINTER3(stmt, func, res);
    LOC_RETURN_IFERR(sql_check_hyperbolic_type(type), func->loc);
    arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &value, res);
    if (value.type == OG_TYPE_REAL) {
        res->v_real = (type == SQL_HYPERBOLIC_COSH) ? cosh(value.v_real) : sinh(value.v_real);
        res->type = OG_TYPE_REAL;
        res->is_null = OG_FALSE;
        return OG_SUCCESS;
    }

    LOC_RETURN_IFERR(sql_calc_hyperbolic_number(&value, type, res), arg->loc);
    return OG_SUCCESS;
}

/* Compute the hyperbolic cosine of the input. */
status_t sql_func_cosh(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_hyperbolic(stmt, func, res, SQL_HYPERBOLIC_COSH);
}

/* Compute the hyperbolic sine of the input. */
status_t sql_func_sinh(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_hyperbolic(stmt, func, res, SQL_HYPERBOLIC_SINH);
}

/* Validate the COSH/SINH argument and infer its result type, preserving UNKNOWN. */
status_t sql_verify_hyperbolic(sql_verifier_t *verifier, expr_node_t *func)
{
    og_type_t arg_type;

    CM_POINTER2(verifier, func);
    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    arg_type = TREE_DATATYPE(func->argument);
    /* check if arg_type can change to numeric */
    if (!sql_match_numeric_type(arg_type) && arg_type != OG_TYPE_BOOLEAN) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, arg_type);
        return OG_ERROR;
    }

    if (arg_type == OG_TYPE_UNKNOWN) {
        func->datatype = OG_TYPE_UNKNOWN;
        func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    } else if (arg_type == OG_TYPE_REAL) {
        func->datatype = OG_TYPE_REAL;
        func->size = sizeof(double);
    } else {
        func->datatype = OG_TYPE_NUMBER;
        func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    }
    return OG_SUCCESS;
}

/* Convert the input value to the specified NUMBER or REAL type. */
static status_t sql_convert_numeric_func_arg(variant_t *value, og_type_t result_type)
{
    double real_value;
    og_type_t source_type = value->type;

    if (result_type == OG_TYPE_NUMBER) {
        return var_as_decimal(value);
    }

    OG_RETURN_IFERR(sql_variant_to_binary_double_value(value, &real_value));
    // set -0.0 to 0.0.
    if (source_type != OG_TYPE_REAL && real_value == 0.0) {
        real_value = 0.0;
    }
    value->v_real = real_value;
    value->type = OG_TYPE_REAL;
    return OG_SUCCESS;
}

/* Determine the result type, inferring it at runtime when it is UNKNOWN. */
static status_t sql_resolve_numeric_func_type(sql_stmt_t *stmt, expr_node_t *func, og_type_t *type)
{
    *type = func->datatype;
    if (*type != OG_TYPE_UNKNOWN) {
        return OG_SUCCESS;
    }

    sql_cursor_t *cursor = SQL_CURSOR_STACK_DEPTH(stmt) == 0 ? NULL : OGSQL_CURR_CURSOR(stmt);
    return sql_infer_func_node_datatype(stmt, cursor == NULL ? NULL : cursor->query, func, type);
}

/* Return the input value, evaluating the replacement only when the input is NaN. */
status_t sql_func_nanvl(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *value_arg = NULL;
    expr_tree_t *replacement_arg = NULL;
    variant_t value;
    variant_t replacement;
    og_type_t result_type;

    CM_POINTER3(stmt, func, res);
    value_arg = func->argument;
    CM_POINTER(value_arg);

    LOC_RETURN_IFERR(sql_resolve_numeric_func_type(stmt, func, &result_type), func->loc);
    SQL_EXEC_FUNC_ARG(value_arg, &value, res, stmt);
    if (value.is_null) {
        VAR_SET_NULL(res, result_type);
        return OG_SUCCESS;
    }

    LOC_RETURN_IFERR(sql_convert_numeric_func_arg(&value, result_type), value_arg->loc);
    /* only REAL can be NAN and INF */
    if (result_type != OG_TYPE_REAL || !isnan(value.v_real)) {
        var_copy(&value, res);
        return OG_SUCCESS;
    }

    replacement_arg = value_arg->next;
    CM_POINTER(replacement_arg);
    SQL_EXEC_FUNC_ARG(replacement_arg, &replacement, res, stmt);
    if (replacement.is_null) {
        VAR_SET_NULL(res, result_type);
        return OG_SUCCESS;
    }
    LOC_RETURN_IFERR(sql_convert_numeric_func_arg(&replacement, result_type), replacement_arg->loc);
    var_copy(&replacement, res);
    return OG_SUCCESS;
}

/* Check whether a dec8 integer is odd. */
static bool32 sql_dec_integer_is_odd(const dec8_t *integer)
{
    int32 expn;

    if (DECIMAL8_IS_ZERO(integer)) {
        return OG_FALSE;
    }
    expn = GET_DEC8_EXPN(integer);
    if (expn < 0 || (uint32)expn >= GET_CELLS8_SIZE(integer)) {
        return OG_FALSE;
    }
    return (bool32)(integer->cells[expn] & 1);
}

/* Compute NUMBER remainder using the nearest integer quotient, with ties rounded to even. */
static status_t sql_calc_number_remainder(const dec8_t *dividend, const dec8_t *divisor, dec8_t *result)
{
    dec8_t quotient;
    dec8_t nearest_integer;
    dec8_t fraction;
    dec8_t abs_fraction;
    dec8_t twice_fraction;
    dec8_t one;
    dec8_t adjusted_integer;
    dec8_t product;
    bool32 adjust_result = OG_FALSE;
    int32 cmp;
    uint32 quotient_prec;

    if (DECIMAL8_IS_ZERO(divisor)) {
        OG_THROW_ERROR(ERR_ZERO_DIVIDE);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_dec_divide(dividend, divisor, &quotient));
    /* Oracle NUMBER uses base-100 cells, so an even scientific exponent has one fewer guard digit. */
    quotient_prec = MAX_NUMERIC_BUFF - (cm_is_even(DEC8_GET_SEXP(&quotient)) ? 1 : 0);
    OG_RETURN_IFERR(cm_dec8_finalise(&quotient, quotient_prec, OG_FALSE));
    cm_dec_copy(&nearest_integer, &quotient);
    OG_RETURN_IFERR(cm_dec_scale(&nearest_integer, 0, ROUND_TRUNC));
    OG_RETURN_IFERR(cm_dec_subtract(&quotient, &nearest_integer, &fraction));

    cm_dec_copy(&abs_fraction, &fraction);
    cm_dec_abs(&abs_fraction);
    OG_RETURN_IFERR(cm_int64_mul_dec(SQL_REMAINDER_HALF_SCALE, &abs_fraction, &twice_fraction));
    cm_int32_to_dec(1, &one);
    cmp = cm_dec_cmp(&twice_fraction, &one);
    if (cmp > 0) {
        adjust_result = OG_TRUE;
    } else if (cmp == 0) {
        adjust_result = sql_dec_integer_is_odd(&nearest_integer);
    }

    if (adjust_result) {
        int64 adjustment = IS_DEC8_NEG(&quotient) ? -1 : 1;
        OG_RETURN_IFERR(cm_dec_add_int64(&nearest_integer, adjustment, &adjusted_integer));
        cm_dec_copy(&nearest_integer, &adjusted_integer);
    }

    OG_RETURN_IFERR(cm_dec_mul(divisor, &nearest_integer, &product));
    return cm_dec_subtract(dividend, &product, result);
}

/* Evaluate REMAINDER using the selected REAL or NUMBER type, returning NULL for NULL inputs. */
status_t sql_func_remainder(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *dividend_arg = NULL;
    expr_tree_t *divisor_arg = NULL;
    variant_t dividend;
    variant_t divisor;
    og_type_t result_type;

    CM_POINTER3(stmt, func, res);
    dividend_arg = func->argument;
    CM_POINTER(dividend_arg);

    LOC_RETURN_IFERR(sql_resolve_numeric_func_type(stmt, func, &result_type), func->loc);
    SQL_EXEC_FUNC_ARG(dividend_arg, &dividend, res, stmt);
    if (dividend.is_null) {
        VAR_SET_NULL(res, result_type);
        return OG_SUCCESS;
    }

    divisor_arg = dividend_arg->next;
    CM_POINTER(divisor_arg);
    /* Preserve temporary text while evaluating the divisor, as in MOD. */
    sql_keep_stack_variant(stmt, &dividend);
    SQL_EXEC_FUNC_ARG(divisor_arg, &divisor, res, stmt);
    if (divisor.is_null) {
        VAR_SET_NULL(res, result_type);
        return OG_SUCCESS;
    }
    sql_keep_stack_variant(stmt, &divisor);

    LOC_RETURN_IFERR(sql_convert_numeric_func_arg(&dividend, result_type), dividend_arg->loc);
    LOC_RETURN_IFERR(sql_convert_numeric_func_arg(&divisor, result_type), divisor_arg->loc);

    res->is_null = OG_FALSE;
    res->type = result_type;
    if (result_type == OG_TYPE_REAL) {
        res->v_real = remainder(dividend.v_real, divisor.v_real);
        if (res->v_real == 0.0) {
            res->v_real = 0.0;
        }
        return OG_SUCCESS;
    }

    LOC_RETURN_IFERR(sql_calc_number_remainder(&dividend.v_dec, &divisor.v_dec, &res->v_dec), func->loc);
    return OG_SUCCESS;
}

/* Validate both arguments and infer the result type while preserving runtime short-circuit evaluation. */
status_t sql_verify_nanvl_remainder(sql_verifier_t *verifier, expr_node_t *func)
{
    expr_tree_t *arg = NULL;
    bool32 has_real = OG_FALSE;
    bool32 has_unknown = OG_FALSE;
    uint32 saved_excl_flags;
    status_t status;

    CM_POINTER2(verifier, func);
    arg = func->argument;

    /* NANVL and REMAINDER both require exactly two arguments. */
    if (arg == NULL || arg->next == NULL || arg->next->next != NULL) {
        OG_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name),
            SQL_NANVL_REMAINDER_ARG_COUNT, SQL_NANVL_REMAINDER_ARG_COUNT);
        return OG_ERROR;
    }

    /* Verify the first argument's expr node. */
    OG_RETURN_IFERR(sql_verify_expr_node(verifier, arg->root));

    /* Disable constant folding of the second argument; evaluate it at runtime only when needed. */
    saved_excl_flags = verifier->excl_flags;
    verifier->excl_flags |= SQL_EXCL_CONST_FOLD;
    status = sql_verify_expr_node(verifier, arg->next->root);

    verifier->excl_flags = saved_excl_flags;
    OG_RETURN_IFERR(status);

    /* Record the number of function arguments. */
    func->value.v_func.arg_cnt = SQL_NANVL_REMAINDER_ARG_COUNT;

    /* Validate numeric-compatible argument types and inspect their verified static types. */
    for (arg = func->argument; arg != NULL; arg = arg->next) {
        og_type_t arg_type = TREE_DATATYPE(arg);
        if (!sql_match_numeric_type(arg_type) && arg_type != OG_TYPE_BOOLEAN) {
            OG_SRC_ERROR_REQUIRE_NUMERIC(arg->loc, arg_type);
            return OG_ERROR;
        }

        has_real = has_real || arg_type == OG_TYPE_REAL || arg_type == OG_TYPE_FLOAT;
        has_unknown = has_unknown || arg_type == OG_TYPE_UNKNOWN;
    }

    /* Set the result datatype and size metadata. */
    func->datatype = has_real ? OG_TYPE_REAL : (has_unknown ? OG_TYPE_UNKNOWN : OG_TYPE_NUMBER);
    func->size = has_real ? sizeof(double) : OG_MAX_DEC_OUTPUT_ALL_PREC;

    /* Prevent pre-evaluation of the entire function node; evaluate it at runtime. */
    SQL_SET_OPTMZ_MODE(func, OPTIMIZE_NONE);
    return OG_SUCCESS;
}

status_t sql_func_tan(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_tan(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_func_asin(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_asin(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_func_acos(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_acos(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_func_atan(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;

    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);
    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
    LOC_RETURN_IFERR(cm_dec_atan(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_func_atan2(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t var1;
    variant_t var2;

    CM_POINTER3(stmt, func, res);

    arg1 = func->argument;

    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var1, OG_TYPE_NUMBER), arg1->loc);

    arg2 = arg1->next;

    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var2, OG_TYPE_NUMBER), arg2->loc);

    OG_RETURN_IFERR(cm_dec_atan2(&var1.v_dec, &var2.v_dec, &res->v_dec));

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_verify_atan2(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32));

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

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    return OG_SUCCESS;
}

status_t sql_func_tanh(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = NULL;
    variant_t var;

    CM_POINTER3(stmt, func, res);

    arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    LOC_RETURN_IFERR(sql_convert_variant(stmt, &var, OG_TYPE_NUMBER), arg->loc);

    LOC_RETURN_IFERR(cm_dec_tanh(&var.v_dec, &res->v_dec), arg->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_verify_tanh(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (OG_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32)) {
        return OG_ERROR;
    }

    if (!sql_match_numeric_type(TREE_DATATYPE(func->argument))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(func->argument->loc, TREE_DATATYPE(func->argument));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

static status_t sql_func_bit_oper(sql_stmt_t *stmt, expr_node_t *func, bit_operation_t op, variant_t *res)
{
    variant_t l_var, r_var; // left and right variants

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, res);
    if (var_as_floor_bigint(&l_var) != OG_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return OG_ERROR;
    }

    expr_tree_t *arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, res);
    if (var_as_floor_bigint(&r_var) != OG_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return OG_ERROR;
    }

    switch (op) {
        case BIT_OPER_AND:
            res->v_bigint = (uint64)l_var.v_bigint & (uint64)r_var.v_bigint;
            break;

        case BIT_OPER_OR:
            res->v_bigint = (uint64)l_var.v_bigint | (uint64)r_var.v_bigint;
            break;

        case BIT_OPER_XOR:
            res->v_bigint = (uint64)l_var.v_bigint ^ (uint64)r_var.v_bigint;
            break;

        default:
            OG_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "bit operation", op);
            return OG_ERROR;
    }
    res->type = OG_TYPE_BIGINT;
    res->is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_func_bit_and(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_AND, res);
}

status_t sql_verify_bit_func(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_BIGINT;
    func->size = OG_BIGINT_SIZE;

    return OG_SUCCESS;
}

status_t sql_func_bit_or(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_OR, res);
}

status_t sql_func_bit_xor(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_bit_oper(stmt, func, BIT_OPER_XOR, res);
}

status_t sql_func_ceil(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, res, res);

    OG_RETURN_IFERR(var_as_decimal(res));

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return cm_dec_ceil(&res->v_dec);
}

status_t sql_verify_ceil(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (OG_SUCCESS != sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32)) {
        return OG_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

status_t sql_func_exp(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t e;
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &e, res);

    if (OG_SUCCESS != var_as_decimal(&e)) {
        cm_set_error_loc(arg->loc);
        return OG_ERROR;
    }

    res->is_null = OG_FALSE;
    if (OG_SUCCESS != cm_dec_exp(&e.v_dec, &res->v_dec)) {
        cm_set_error_loc(arg->loc);
        return OG_ERROR;
    }
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_verify_exp(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

status_t sql_func_floor(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, res, res);

    if (var_as_decimal(res) != OG_SUCCESS) {
        return OG_ERROR;
    }

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;
    return cm_dec_floor(&res->v_dec);
}

status_t sql_verify_floor(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

static void sql_func_inet_ntoa_core(sql_stmt_t *stmt, variant_t *var, variant_t *res)
{
    uint32 byte1;
    uint32 byte2;
    uint32 byte3;
    uint32 byte4;

    byte1 = ((uint64)var->v_bigint & 0xFF000000) >> 24;
    byte2 = ((uint64)var->v_bigint & 0x00FF0000) >> 16;
    byte3 = ((uint64)var->v_bigint & 0x0000FF00) >> 8;
    byte4 = ((uint64)var->v_bigint & 0x000000FF);

    PRTS_RETVOID_IFERR(snprintf_s(res->v_text.str, OG_STRING_BUFFER_SIZE, OG_STRING_BUFFER_SIZE - 1, "%u.%u.%u.%u",
        byte1, byte2, byte3, byte4));

    res->v_text.len = (uint32)strlen(res->v_text.str);
    res->type = OG_TYPE_STRING;
    res->is_null = OG_FALSE;
}

status_t sql_func_inet_ntoa(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t arg;
    char *buf = NULL;

    CM_POINTER3(stmt, func, res);
    CM_POINTER(func->argument);

    SQL_EXEC_FUNC_ARG_EX(func->argument, &arg, res);
    if (var_as_bigint(&arg) != OG_SUCCESS) {
        cm_set_error_loc(func->loc);
        return OG_ERROR;
    }
    if (arg.is_null || arg.v_bigint < 0 || arg.v_bigint > (int64)0xFFFFFFFF) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, OG_STRING_BUFFER_SIZE, (void **)&buf));
    res->v_text.str = buf;
    res->v_text.len = 0;

    sql_func_inet_ntoa_core(stmt, &arg, res);
    return OG_SUCCESS;
}

status_t sql_verify_inet_ntoa(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    return OG_SUCCESS;
}

status_t sql_func_ln(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;
    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    if (OG_SUCCESS != var_as_decimal(&var)) {
        cm_set_error_loc(arg->loc);
        return OG_ERROR;
    }

    res->is_null = OG_FALSE;
    if (OG_SUCCESS != cm_dec_ln(&var.v_dec, &res->v_dec)) {
        cm_set_error_loc(arg->loc);
        return OG_ERROR;
    }
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_verify_ln(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32));

    expr_tree_t *arg1 = func->argument;
    if (!sql_match_numeric_type(TREE_DATATYPE(arg1))) {
        OG_SRC_ERROR_REQUIRE_NUMERIC(arg1->loc, TREE_DATATYPE(arg1));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    return OG_SUCCESS;
}

status_t sql_func_log(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t l_var;
    variant_t r_var;

    arg1 = func->argument;

    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, res);
    LOC_RETURN_IFERR(var_as_decimal(&l_var), arg1->loc);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    // 1. log(a) = ln(a), where a > 0
    arg2 = arg1->next;
    if (arg2 == NULL) {
        LOC_RETURN_IFERR(cm_dec_ln(&l_var.v_dec, &res->v_dec), arg1->loc);
        return OG_SUCCESS;
    }

    // 2. log(a, b) = ln(b) / ln(a), where a > 0 && a != 1 && b > 0
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, res);
    LOC_RETURN_IFERR(var_as_decimal(&r_var), arg2->loc);

    LOC_RETURN_IFERR(cm_dec_log(&l_var.v_dec, &r_var.v_dec, &res->v_dec), func->loc);
    return OG_SUCCESS;
}

status_t sql_verify_log(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return OG_SUCCESS;
}

status_t sql_func_mod(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t l_var;
    variant_t r_var;

    CM_POINTER3(stmt, func, res);

    res->is_null = OG_FALSE;

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &l_var, res);
    sql_keep_stack_variant(stmt, &l_var);

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &r_var, res);
    sql_keep_stack_variant(stmt, &r_var);

    if (l_var.type == OG_TYPE_INTEGER && r_var.type == OG_TYPE_INTEGER) {
        res->type = OG_TYPE_INTEGER;
        res->v_int = r_var.v_int == 0 ? l_var.v_int : l_var.v_int % r_var.v_int;
        OG_RETURN_IFERR(var_as_decimal(res));
        return OG_SUCCESS;
    }

    if (l_var.type == OG_TYPE_BIGINT && r_var.type == OG_TYPE_BIGINT) {
        res->type = OG_TYPE_BIGINT;
        res->v_bigint = r_var.v_bigint == 0 ? l_var.v_bigint : l_var.v_bigint % r_var.v_bigint;
        OG_RETURN_IFERR(var_as_decimal(res));
        return OG_SUCCESS;
    }

    if (l_var.type == OG_TYPE_BIGINT && r_var.type == OG_TYPE_INTEGER) {
        res->type = OG_TYPE_BIGINT;
        res->v_bigint = r_var.v_int == 0 ? l_var.v_bigint : l_var.v_bigint % r_var.v_int;
        OG_RETURN_IFERR(var_as_decimal(res));
        return OG_SUCCESS;
    }

    if (l_var.type == OG_TYPE_INTEGER && r_var.type == OG_TYPE_BIGINT) {
        res->type = OG_TYPE_BIGINT;
        res->v_bigint = r_var.v_bigint == 0 ? l_var.v_int : l_var.v_int % r_var.v_bigint;
        OG_RETURN_IFERR(var_as_decimal(res));
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(var_as_decimal(&l_var));
    OG_RETURN_IFERR(var_as_decimal(&r_var));

    res->type = OG_TYPE_NUMBER;
    return cm_dec_mod(&l_var.v_dec, &r_var.v_dec, &res->v_dec);
}

status_t sql_verify_mod(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;
    return OG_SUCCESS;
}

#define POWER_AS_SHIFT_BASE 2
#define POWER_AS_SHIFT_MIN_EXPN 0
#define POWER_AS_SHIFT_MAX_EXPN 30
static inline bool32 if_power_as_shift(variant_t *base, variant_t *expn)
{
    if (base->type == OG_TYPE_INTEGER && base->v_int == POWER_AS_SHIFT_BASE && expn->type == OG_TYPE_INTEGER &&
        expn->v_int >= POWER_AS_SHIFT_MIN_EXPN && expn->v_int <= POWER_AS_SHIFT_MAX_EXPN) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

status_t sql_func_pi(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    CM_POINTER3(stmt, func, res);

    cm_dec8_pi(&res->v_dec);
    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;
    
    return OG_SUCCESS;
}

status_t sql_verify_pi(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return OG_SUCCESS;
}

status_t sql_func_power(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    variant_t base;
    variant_t expn;

    CM_POINTER3(stmt, func, res);

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &base, res);
    sql_keep_stack_variant(stmt, &base);

    arg2 = arg1->next;
    CM_POINTER(arg2);
    SQL_EXEC_FUNC_ARG_EX(arg2, &expn, res);
    sql_keep_stack_variant(stmt, &expn);

    if (if_power_as_shift(&base, &expn)) {
        res->v_int = 1 << expn.v_int;
        cm_int32_to_dec8(res->v_int, VALUE_PTR(dec8_t, res));
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(var_as_decimal(&base));
    OG_RETURN_IFERR(var_as_decimal(&expn));
    return cm_dec_power(&base.v_dec, &expn.v_dec, &res->v_dec);
}

status_t sql_verify_power(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32));

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

    func->datatype = OG_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    return OG_SUCCESS;
}

status_t sql_func_radians(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    if (OG_IS_LOB_TYPE(TREE_DATATYPE(func->argument)) || OG_IS_STRING_TYPE(TREE_DATATYPE(func->argument))) {
        num_errno_t nerr_no = cm_text2real_ex_no_check_err(&var.v_text, &var.v_real);
        var.type = OG_TYPE_REAL;
        CM_TRY_THROW_NUM_ERR(nerr_no);
        res->v_real = var.v_real * (OG_PI / OG_180_DEGREE);
        res->type = OG_TYPE_REAL;
        OG_RETURN_IFERR(cm_real_to_dec8_prec17(res->v_real, VALUE_PTR(dec8_t, res)));
    } else {
        LOC_RETURN_IFERR(var_as_decimal(&var), arg->loc);
        LOC_RETURN_IFERR(cm_dec8_radians(&var.v_dec, &res->v_dec), arg->loc);
    }
    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    return OG_SUCCESS;
}

status_t sql_func_rand(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = NULL;
    uint32 randvalue;
    variant_t var_seed;
    int64 seed;

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    if (func->argument != NULL) {
        arg = func->argument;

        /* get the seed value */
        if (sql_exec_expr(stmt, arg, &var_seed) != OG_SUCCESS) {
            return OG_ERROR;
        }
        SQL_CHECK_COLUMN_VAR(&var_seed, res);
        if (!(var_seed.is_null == OG_FALSE && OG_IS_NUMERIC_TYPE(var_seed.type))) {
            OG_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                               "the seed of rand is incorrect");
            return OG_ERROR;
        }

        /* convert to uint64 */
        OG_RETURN_IFERR(var_to_round_bigint(&var_seed, ROUND_TRUNC, &seed, NULL));
        randvalue = cm_rand_int32(&seed, OG_MAX_RAND_RANGE);
    } else {
        randvalue = cm_random(OG_MAX_RAND_RANGE);
    }
    cm_uint32_to_dec(randvalue, &res->v_dec);
    OG_RETURN_IFERR(cm_dec_div_int64(&res->v_dec, OG_MAX_RAND_RANGE, &res->v_dec));

    return OG_SUCCESS;
}

status_t sql_verify_rand(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, OG_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (arg != NULL) {
        /* param must be one char or null */
        if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
            OG_SRC_THROW_ERROR(func->argument->root->loc, ERR_INVALID_FUNC_PARAMS,
                               "the argument of rand is incorrect");
            return OG_ERROR;
        }
    }

    func->datatype = OG_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = OG_UNSPECIFIED_NUM_SCALE;
    func->precision = OG_UNSPECIFIED_NUM_PREC;
    return OG_SUCCESS;
}

status_t sql_func_rawtohex(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_bin2hex(stmt, func, OG_FALSE, res);
}

status_t sql_verify_rawtohex(sql_verifier_t *verf, expr_node_t *func)
{
    return sql_verify_bin2hex(verf, func);
}

static status_t sql_func_round_trunc_date(sql_stmt_t *stmt, variant_t *var1, expr_tree_t *arg1, variant_t *res,
    bool32 is_round)
{
    variant_t var2;
    char *fmt = (char *)"DD";
    text_t fmt_text;

    // param format
    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        fmt_text.str = fmt;
        fmt_text.len = (uint32)strlen(fmt);
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
        if (var2.type != OG_TYPE_CHAR && var2.type != OG_TYPE_STRING && var2.type != OG_TYPE_VARCHAR) {
            OG_THROW_ERROR(ERR_UNEXPECTED_KEY, "a string value.");
            return OG_ERROR;
        }

        fmt_text = var2.v_text;
    }

    if (is_round) {
        return cm_round_date(var1->v_date, &fmt_text, &res->v_date);
    } else {
        return cm_trunc_date(var1->v_date, &fmt_text, &res->v_date);
    }
}

static status_t sql_func_round_trunc_decimal(sql_stmt_t *stmt, variant_t *var1, expr_tree_t *arg1, variant_t *res,
    bool32 is_round)
{
    variant_t var2;
    int32 scale;

    // param number
    OG_RETURN_IFERR(var_as_decimal(var1));

    // param scale
    expr_tree_t *arg2 = arg1->next;
    if (arg2 == NULL) {
        scale = 0;
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
        OG_RETURN_IFERR(var_as_floor_integer(&var2));
        scale = var2.v_int;
    }

    OG_RETURN_IFERR(cm_dec_scale(&var1->v_dec, scale, is_round ? ROUND_HALF_UP : ROUND_TRUNC));
    cm_dec_copy(&res->v_dec, &var1->v_dec);
    return OG_SUCCESS;
}

static status_t sql_func_round_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *res, bool32 is_round)
{
    variant_t var1;

    CM_POINTER3(stmt, func, res);

    res->is_null = OG_FALSE;

    // param date or number
    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);

    if (OG_IS_DATETIME_TYPE(var1.type)) {
        res->type = OG_TYPE_DATE;
        OG_RETURN_IFERR(sql_convert_variant(stmt, &var1, OG_TYPE_DATE));
        return sql_func_round_trunc_date(stmt, &var1, arg1, res, is_round);
    } else {
        res->type = OG_TYPE_NUMBER;
        return sql_func_round_trunc_decimal(stmt, &var1, arg1, res, is_round);
    }
}

status_t sql_func_round(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_round_trunc(stmt, func, res, OG_TRUE);
}

status_t sql_func_trunc(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_round_trunc(stmt, func, res, OG_FALSE);
}

status_t sql_verify_round_trunc(sql_verifier_t *verf, expr_node_t *func)
{
    /* syntax:
    round(number[,scale) round(date[,fmt)
    trunc(number[,scale) trunc(date[,fmt)
    */
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 2, OG_INVALID_ID32));

    expr_tree_t *arg = func->argument;
    if (!sql_match_num_and_datetime_type(TREE_DATATYPE(arg))) {
        OG_SRC_ERROR_REQUIRE_NUM_OR_DATETIME(TREE_LOC(arg), TREE_DATATYPE(arg));
        return OG_ERROR;
    }

    if (OG_IS_DATETIME_TYPE(TREE_DATATYPE(arg))) {
        func->datatype = OG_TYPE_DATE;
        func->precision = 0;
    } else if (OG_IS_NUMERIC_TYPE(TREE_DATATYPE(arg)) || OG_IS_STRING_TYPE(TREE_DATATYPE(arg))) {
        func->datatype = OG_TYPE_NUMBER;
        func->precision = OG_UNSPECIFIED_NUM_PREC;
        func->scale = OG_UNSPECIFIED_NUM_SCALE;
    } else {
        func->datatype = OG_TYPE_UNKNOWN;
        func->precision = 0;
    }

    if (arg->next != NULL) {
        arg = arg->next;
        if (OG_IS_DATETIME_TYPE(func->datatype)) {
            if (!sql_match_string_type(TREE_DATATYPE(arg))) {
                OG_SRC_ERROR_REQUIRE_STRING(TREE_LOC(arg), TREE_DATATYPE(arg));
                return OG_ERROR;
            }
        } else {
            if (!sql_match_numeric_type(TREE_DATATYPE(arg))) {
                OG_SRC_ERROR_REQUIRE_NUMERIC(TREE_LOC(arg), TREE_DATATYPE(arg));
                return OG_ERROR;
            }
        }
    }

    func->size = cm_get_datatype_strlen(func->datatype, func->argument->root->size);
    return OG_SUCCESS;
}

status_t sql_func_sign(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    if (OG_SUCCESS != var_as_decimal(&var)) {
        cm_set_error_loc(arg->loc);
        return OG_ERROR;
    }

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;

    cm_dec_sign(&var.v_dec, &res->v_dec);
    return OG_SUCCESS;
}

status_t sql_verify_sign(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

status_t sql_func_sqrt(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg = func->argument;
    CM_POINTER(arg);

    SQL_EXEC_FUNC_ARG_EX(arg, &var, res);

    OG_RETURN_IFERR(var_as_decimal(&var));

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;
    return cm_dec_sqrt(&var.v_dec, &res->v_dec);
}

status_t sql_verify_sqrt(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = OG_MAX_DEC_OUTPUT_ALL_PREC;

    return OG_SUCCESS;
}

status_t sql_func_random(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    uint32 randvalue;
    res->is_null = OG_FALSE;
    res->type = OG_TYPE_NUMBER;
    randvalue = cm_random(OG_MAX_RAND_RANGE);
    cm_uint32_to_dec(randvalue, &res->v_dec);
    OG_RETURN_IFERR(cm_dec_div_int64(&res->v_dec, OG_MAX_RAND_RANGE, &res->v_dec));
    return OG_SUCCESS;
}

status_t sql_verify_random(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);
    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 1, OG_INVALID_ID32));

    func->datatype = OG_TYPE_NUMBER;
    func->size = MAX_DEC_BYTE_SZ;
    func->scale = OG_UNSPECIFIED_NUM_SCALE;
    func->precision = OG_UNSPECIFIED_NUM_PREC;
    return OG_SUCCESS;
}
