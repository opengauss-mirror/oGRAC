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
 * opr_div.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_div.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_div.h"

static inline status_t div_anytype_binary(opr_operand_set_t *op_set)
{
    OPR_ANYTYPE_BINARY(div, op_set);
}

static inline status_t div_binary_anytype(opr_operand_set_t *op_set)
{
    OPR_BINARY_ANYTYPE(div, op_set);
}

static inline status_t opr_double_div(double a, double b, double *res)
{
    bool32 inf_is_valid = isinf(a) || isinf(b);
    *res = a / b;
    CHECK_REAL_OVERFLOW(*res, inf_is_valid, VAR_DOUBLE_IS_ZERO(a));
    return OG_SUCCESS;
}

#define OPR_CHECK_ZERO_DIVISION(v, rst)         \
    do {                                        \
        if (SECUREC_UNLIKELY((v) == 0)) {       \
            if (g_opr_options.div0_accepted) { \
                (rst)->is_null = OG_TRUE;       \
                return OG_SUCCESS;              \
            }                                   \
            OG_THROW_ERROR(ERR_ZERO_DIVIDE);    \
            return OG_ERROR;                    \
        }                                       \
    } while (0)

#define OPR_CHECK_REAL_ZERO_DIVISION(v, rst)                      \
    do {                                                          \
        if (SECUREC_UNLIKELY((fabs(v)) < OG_REAL_PRECISION)) {       \
            if (g_opr_options.div0_accepted) {                    \
                (rst)->is_null = OG_TRUE;                         \
                return OG_SUCCESS;                                \
            }                                                     \
            OG_THROW_ERROR(ERR_ZERO_DIVIDE);                      \
            return OG_ERROR;                                      \
        }                                                         \
    } while (0)

static inline status_t opr_dsitvl_div_real(interval_ds_t dsitvl, double num, interval_ds_t *res)
{
    static double INV_MAX_DSITVL = 1.0 / (double)(OG_MAX_DSINTERVAL);
    double mul_res;
    
    do {
        if (dsitvl != 0 && INV_MAX_DSITVL > fabs(num)) {
            break;
        }
        if (fabs(num) < OG_REAL_PRECISION) {
            OG_THROW_ERROR(ERR_ZERO_DIVIDE);
            return OG_ERROR;
        }
        mul_res = dsitvl / num;
        if (fabs(mul_res) > OG_MAX_DSINTERVAL) {
            break;
        }
        *res = (interval_ds_t)mul_res;
        return OG_SUCCESS;
    } while (0);

    OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTERVAL DAY TO SECOND");
    return OG_ERROR;
}

static inline status_t opr_dsitvl_div_dec(interval_ds_t dsitvl, const dec8_t *dec, interval_ds_t *result)
{
    double num = cm_dec_to_real(dec);
    return opr_dsitvl_div_real(dsitvl, num, result);
}

static inline status_t opr_ymitvl_div_real(interval_ym_t ymitvl, double num, interval_ym_t *res)
{
    static double INV_MAX_YMITVL = 1.0 / (double)(OG_MAX_YMINTERVAL);
    double mul_res;
    
    do {
        if (ymitvl != 0 && INV_MAX_YMITVL > fabs(num)) {
            break;
        }
        if (fabs(num) < OG_REAL_PRECISION) {
            OG_THROW_ERROR(ERR_ZERO_DIVIDE);
            return OG_ERROR;
        }
        mul_res = ymitvl / num;
        if (fabs(mul_res) > OG_MAX_YMINTERVAL) {
            break;
        }
        *res = (interval_ym_t)mul_res;
        return OG_SUCCESS;
    } while (0);

    OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTERVAL YEAR TO MONTH");
    return OG_ERROR;
}

static inline status_t opr_ymitvl_div_dec(interval_ym_t ymitvl, const dec8_t *dec, interval_ym_t *result)
{
    double num = cm_dec_to_real(dec);
    return opr_ymitvl_div_real(ymitvl, num, result);
}

static inline status_t div_uint_uint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_uint32 / (double)OP_RIGHT(op_set)->v_uint32;
    return OG_SUCCESS;
}

static inline status_t div_uint_int(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_uint32 / (double)OP_RIGHT(op_set)->v_int;
    return OG_SUCCESS;
}

static inline status_t div_uint_bigint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_uint32 / (double)OP_RIGHT(op_set)->v_bigint;
    return OG_SUCCESS;
}

static inline status_t div_uint_real(opr_operand_set_t *op_set)
{
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return opr_double_div((double)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_uint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_int64_div_dec((int64)OP_LEFT(op_set)->v_uint32, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_uint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_int64_div_dec((int64)OP_LEFT(op_set)->v_uint32, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define div_uint_decimal div_uint_number

static inline status_t div_anytype_string(opr_operand_set_t *op_set)
{
    variant_t var;
    variant_t *old_right = OP_RIGHT(op_set);
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RIGHT(op_set) = &var;
    status_t status = opr_exec_div(op_set);
    OP_RIGHT(op_set) = old_right;
    return status;
}

#define div_uint_char      div_anytype_string
#define div_uint_varchar   div_anytype_string
#define div_uint_string    div_anytype_string
#define div_uint_binary    div_anytype_binary
#define div_uint_varbinary div_anytype_string

OPR_DECL(div_uint_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_uint_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_uint_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_uint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_uint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_uint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_uint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_uint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_uint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_uint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_uint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_uint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t div_int_uint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_int / (double)OP_RIGHT(op_set)->v_uint32;
    return OG_SUCCESS;
}

static inline status_t div_int_int(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_int / (double)OP_RIGHT(op_set)->v_int;
    return OG_SUCCESS;
}

static inline status_t div_int_bigint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_int / (double)OP_RIGHT(op_set)->v_bigint;
    return OG_SUCCESS;
}

static inline status_t div_int_real(opr_operand_set_t *op_set)
{
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return opr_double_div((double)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_int_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_int64_div_dec((int64)OP_LEFT(op_set)->v_int, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_int_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_int64_div_dec((int64)OP_LEFT(op_set)->v_int, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define div_int_decimal    div_int_number
#define div_int_char       div_anytype_string
#define div_int_varchar    div_anytype_string
#define div_int_string     div_anytype_string
#define div_int_binary     div_anytype_binary
#define div_int_varbinary  div_anytype_string

OPR_DECL(div_int_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_int_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_int_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_int_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_int_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_int_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_int_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_int_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_int_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_int_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_int_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_int_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t div_bigint_uint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_bigint / (double)OP_RIGHT(op_set)->v_uint32;
    return OG_SUCCESS;
}

static inline status_t div_bigint_int(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_bigint / (double)OP_RIGHT(op_set)->v_int;
    return OG_SUCCESS;
}

static inline status_t div_bigint_bigint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_bigint / (double)OP_RIGHT(op_set)->v_bigint;
    return OG_SUCCESS;
}

static inline status_t div_bigint_real(opr_operand_set_t *op_set)
{
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return opr_double_div((double)OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_bigint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_int64_div_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_bigint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_int64_div_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define div_bigint_decimal    div_bigint_number
#define div_bigint_char       div_anytype_string
#define div_bigint_varchar    div_anytype_string
#define div_bigint_string     div_anytype_string
#define div_bigint_binary     div_anytype_binary
#define div_bigint_varbinary  div_anytype_string

OPR_DECL(div_bigint_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_bigint_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_bigint_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_bigint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_bigint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_bigint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_bigint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_bigint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_bigint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_bigint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_bigint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_bigint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t div_real_uint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    return opr_double_div(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_real_int(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    return opr_double_div(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_real_bigint(opr_operand_set_t *op_set)
{
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    return opr_double_div(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_real_real(opr_operand_set_t *op_set)
{
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return opr_double_div(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t div_real_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_real_div_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_real_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_real_div_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define div_real_decimal    div_real_number
#define div_real_char       div_anytype_string
#define div_real_varchar    div_anytype_string
#define div_real_string     div_anytype_string
#define div_real_binary     div_anytype_binary
#define div_real_varbinary  div_anytype_string

OPR_DECL(div_real_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_real_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_real_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_real_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(div_real_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_real_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_real_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_real_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_real_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_real_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_real_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_real_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t div_number_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    return cm_dec_div_int64(&OP_LEFT(op_set)->v_dec, (int64)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    return cm_dec_div_int64(&OP_LEFT(op_set)->v_dec, (int64)OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    return cm_dec_div_int64(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return cm_dec_div_real(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_dec_divide(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define div_number_decimal      div_number_number

static inline status_t div_number_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_dec_divide(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}
#define div_number_char         div_anytype_string
#define div_number_varchar      div_anytype_string
#define div_number_string       div_anytype_string
#define div_number_binary       div_anytype_binary
#define div_number_varbinary    div_anytype_string

OPR_DECL(div_number_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_number2, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER2);
OPR_DECL(div_number_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_number_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_number_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t div_number2_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    return cm_dec_div_int64(&OP_LEFT(op_set)->v_dec, (int64)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number2_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    return cm_dec_div_int64(&OP_LEFT(op_set)->v_dec, (int64)OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number2_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    return cm_dec_div_int64(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number2_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return cm_dec_div_real(&OP_LEFT(op_set)->v_dec, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_dec);
}

static inline status_t div_number2_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return cm_dec_divide(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define div_number2_decimal      div_number2_number
#define div_number2_number2      div_number2_number
#define div_number2_char         div_anytype_string
#define div_number2_varchar      div_anytype_string
#define div_number2_string       div_anytype_string
#define div_number2_binary       div_anytype_binary
#define div_number2_varbinary    div_anytype_string

OPR_DECL(div_number2_uint, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_int, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_bigint, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_real, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_number, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_decimal, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_char, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_varchar, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_string, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_binary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_number2_varbinary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);

static inline status_t div_string_anytype(opr_operand_set_t *op_set)
{
    variant_t var;
    variant_t *old_left = OP_LEFT(op_set);
    OG_RETURN_IFERR(opr_text2dec(OP_LEFT(op_set), &var));
    OP_LEFT(op_set) = &var;
    status_t status = opr_exec_div(op_set);
    OP_LEFT(op_set) = old_left;
    return status;
}

#define div_string_uint        div_string_anytype
#define div_string_int         div_string_anytype
#define div_string_bigint      div_string_anytype
#define div_string_real        div_string_anytype
#define div_string_number      div_string_anytype
#define div_string_number2     div_string_anytype
#define div_string_decimal     div_string_anytype
#define div_string_char        div_string_anytype
#define div_string_varchar     div_string_anytype
#define div_string_string      div_string_anytype
#define div_string_binary      div_anytype_binary
#define div_string_varbinary   div_string_anytype

OPR_DECL(div_string_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_string_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_string_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_string_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define div_binary_uint        div_binary_anytype
#define div_binary_int         div_binary_anytype
#define div_binary_bigint      div_binary_anytype
#define div_binary_real        div_binary_anytype
#define div_binary_number      div_binary_anytype
#define div_binary_number2     div_binary_anytype
#define div_binary_decimal     div_binary_anytype
#define div_binary_char        div_binary_anytype
#define div_binary_varchar     div_binary_anytype
#define div_binary_string      div_binary_anytype
#define div_binary_binary      div_binary_anytype
#define div_binary_varbinary   div_binary_anytype

OPR_DECL(div_binary_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(div_binary_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(div_binary_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(div_binary_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t div_interval_ym_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    return opr_ymitvl_div_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_uint32,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t div_interval_ym_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    return opr_ymitvl_div_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_int,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t div_interval_ym_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    return opr_ymitvl_div_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_bigint,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t div_interval_ym_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return opr_ymitvl_div_real(OP_LEFT(op_set)->v_itvl_ym, (double)OP_RIGHT(op_set)->v_real,
        &OP_RESULT(op_set)->v_itvl_ym);
}

static inline status_t div_interval_ym_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return opr_ymitvl_div_dec(OP_LEFT(op_set)->v_itvl_ym, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_itvl_ym);
}

#define div_interval_ym_decimal      div_interval_ym_number
#define div_interval_ym_number2      div_interval_ym_number
#define div_interval_ym_char         div_anytype_string
#define div_interval_ym_varchar      div_anytype_string
#define div_interval_ym_string       div_anytype_string
#define div_interval_ym_binary       div_anytype_binary
#define div_interval_ym_varbinary    div_anytype_string

OPR_DECL(div_interval_ym_uint, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_int, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_bigint, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_real, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_number, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_number2, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_decimal, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_char, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_varchar, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_string, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_binary, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);
OPR_DECL(div_interval_ym_varbinary, OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, OG_TYPE_INTERVAL_YM);


static inline status_t div_interval_ds_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
    return opr_dsitvl_div_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_uint32,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t div_interval_ds_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
    return opr_dsitvl_div_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_int,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t div_interval_ds_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OPR_CHECK_ZERO_DIVISION(OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
    return opr_dsitvl_div_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_bigint,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t div_interval_ds_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OPR_CHECK_REAL_ZERO_DIVISION(OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
    return opr_dsitvl_div_real(OP_LEFT(op_set)->v_itvl_ds, (double)OP_RIGHT(op_set)->v_real,
        &OP_RESULT(op_set)->v_itvl_ds);
}

static inline status_t div_interval_ds_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    if (g_opr_options.div0_accepted && DECIMAL8_IS_ZERO(&OP_RIGHT(op_set)->v_dec)) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    return opr_dsitvl_div_dec(OP_LEFT(op_set)->v_itvl_ds, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_itvl_ds);
}

#define div_interval_ds_decimal      div_interval_ds_number
#define div_interval_ds_number2      div_interval_ds_number
#define div_interval_ds_char         div_anytype_string
#define div_interval_ds_varchar      div_anytype_string
#define div_interval_ds_string       div_anytype_string
#define div_interval_ds_binary       div_anytype_binary
#define div_interval_ds_varbinary    div_anytype_string

OPR_DECL(div_interval_ds_uint, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_int, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_bigint, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_real, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_number, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_number2, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_decimal, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_char, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_varchar, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_string, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_binary, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);
OPR_DECL(div_interval_ds_varbinary, OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, OG_TYPE_INTERVAL_DS);

static opr_rule_t *g_div_oprs[VAR_TYPE_ARRAY_SIZE][VAR_TYPE_ARRAY_SIZE] = {
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_UINT32,            div_uint_uint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_INTEGER,           div_uint_int),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BIGINT,            div_uint_bigint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_REAL,              div_uint_real),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER,            div_uint_number),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER2,           div_uint_number2),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_DECIMAL,           div_uint_decimal),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_CHAR,              div_uint_char),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARCHAR,           div_uint_varchar),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_STRING,            div_uint_string),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BINARY,            div_uint_binary),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARBINARY,         div_uint_varbinary),

    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_UINT32,            div_int_uint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_INTEGER,           div_int_int),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BIGINT,            div_int_bigint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_REAL,              div_int_real),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER,            div_int_number),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER2,           div_int_number2),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_DECIMAL,           div_int_decimal),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_CHAR,              div_int_char),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARCHAR,           div_int_varchar),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_STRING,            div_int_string),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BINARY,            div_int_binary),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARBINARY,         div_int_varbinary),

    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_UINT32,            div_bigint_uint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_INTEGER,           div_bigint_int),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BIGINT,            div_bigint_bigint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_REAL,              div_bigint_real),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER,            div_bigint_number),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER2,           div_bigint_number2),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_DECIMAL,           div_bigint_decimal),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_CHAR,              div_bigint_char),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARCHAR,           div_bigint_varchar),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_STRING,            div_bigint_string),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BINARY,            div_bigint_binary),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARBINARY,         div_bigint_varbinary),

    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_UINT32,            div_real_uint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_INTEGER,           div_real_int),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BIGINT,            div_real_bigint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_REAL,              div_real_real),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER,            div_real_number),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER2,           div_real_number2),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_DECIMAL,           div_real_decimal),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_CHAR,              div_real_char),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARCHAR,           div_real_varchar),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_STRING,            div_real_string),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BINARY,            div_real_binary),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARBINARY,         div_real_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_UINT32,            div_number_uint),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_INTEGER,           div_number_int),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BIGINT,            div_number_bigint),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_REAL,              div_number_real),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER,            div_number_number),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER2,           div_number_number2),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_DECIMAL,           div_number_decimal),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_CHAR,              div_number_char),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARCHAR,           div_number_varchar),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_STRING,            div_number_string),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BINARY,            div_number_binary),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARBINARY,         div_number_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_UINT32,            div_number2_uint),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_INTEGER,           div_number2_int),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BIGINT,            div_number2_bigint),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_REAL,              div_number2_real),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER,            div_number2_number),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER2,           div_number2_number2),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_DECIMAL,           div_number2_decimal),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_CHAR,              div_number2_char),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARCHAR,           div_number2_varchar),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_STRING,            div_number2_string),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BINARY,            div_number2_binary),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARBINARY,         div_number2_varbinary),

    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_UINT32,            div_number_uint),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_INTEGER,           div_number_int),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BIGINT,            div_number_bigint),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_REAL,              div_number_real),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER,            div_number_number),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER2,           div_number_number2),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_DECIMAL,           div_number_decimal),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_CHAR,              div_number_char),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARCHAR,           div_number_varchar),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_STRING,            div_number_string),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BINARY,            div_number_binary),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARBINARY,         div_number_varbinary),

    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_UINT32,            div_string_uint),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_INTEGER,           div_string_int),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BIGINT,            div_string_bigint),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_REAL,              div_string_real),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER,            div_string_number),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER2,           div_string_number2),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_DECIMAL,           div_string_decimal),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_CHAR,              div_string_char),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARCHAR,           div_string_varchar),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_STRING,            div_string_string),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BINARY,            div_string_binary),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARBINARY,         div_string_varbinary),

    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_UINT32,            div_string_uint),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_INTEGER,           div_string_int),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BIGINT,            div_string_bigint),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_REAL,              div_string_real),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER,            div_string_number),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER2,           div_string_number2),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_DECIMAL,           div_string_decimal),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_CHAR,              div_string_char),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARCHAR,           div_string_varchar),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_STRING,            div_string_string),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BINARY,            div_string_binary),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARBINARY,         div_string_varbinary),

    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_UINT32,            div_string_uint),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_INTEGER,           div_string_int),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BIGINT,            div_string_bigint),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_REAL,              div_string_real),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER,            div_string_number),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER2,           div_string_number2),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_DECIMAL,           div_string_decimal),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_CHAR,              div_string_char),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARCHAR,           div_string_varchar),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_STRING,            div_string_string),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BINARY,            div_string_binary),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARBINARY,         div_string_varbinary),

    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_UINT32,            div_binary_uint),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_INTEGER,           div_binary_int),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BIGINT,            div_binary_bigint),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_REAL,              div_binary_real),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER,            div_binary_number),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER2,           div_binary_number2),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_DECIMAL,           div_binary_decimal),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_CHAR,              div_binary_char),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARCHAR,           div_binary_varchar),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_STRING,            div_binary_string),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BINARY,            div_binary_binary),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARBINARY,         div_binary_varbinary),

    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_UINT32,            div_string_uint),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_INTEGER,           div_string_int),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BIGINT,            div_string_bigint),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_REAL,              div_string_real),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER,            div_string_number),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER2,           div_string_number2),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_DECIMAL,           div_string_decimal),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_CHAR,              div_string_char),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARCHAR,           div_string_varchar),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_STRING,            div_string_string),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BINARY,            div_string_binary),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARBINARY,         div_string_varbinary),

    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_UINT32, div_interval_ym_uint),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_INTEGER, div_interval_ym_int),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_BIGINT, div_interval_ym_bigint),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_REAL, div_interval_ym_real),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_NUMBER, div_interval_ym_number),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_NUMBER2, div_interval_ym_number2),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_DECIMAL, div_interval_ym_decimal),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_CHAR, div_interval_ym_char),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_VARCHAR, div_interval_ym_varchar),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_STRING, div_interval_ym_string),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_BINARY, div_interval_ym_binary),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_VARBINARY, div_interval_ym_varbinary),

    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_UINT32, div_interval_ds_uint),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_INTEGER, div_interval_ds_int),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_BIGINT, div_interval_ds_bigint),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_REAL, div_interval_ds_real),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_NUMBER, div_interval_ds_number),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_NUMBER2, div_interval_ds_number2),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_DECIMAL, div_interval_ds_decimal),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_CHAR, div_interval_ds_char),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_VARCHAR, div_interval_ds_varchar),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_STRING, div_interval_ds_string),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_BINARY, div_interval_ds_binary),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_VARBINARY, div_interval_ds_varbinary),

};

status_t opr_exec_div(opr_operand_set_t *op_set)
{
    opr_rule_t *rule = g_div_oprs[OG_TYPE_I(OP_LEFT(op_set)->type)][OG_TYPE_I(OP_RIGHT(op_set)->type)];

    if (SECUREC_UNLIKELY(rule == NULL)) {
        OPR_THROW_ERROR("/", OP_LEFT(op_set)->type, OP_RIGHT(op_set)->type);
        return OG_ERROR;
    }
    
    OP_RESULT(op_set)->type = OG_TYPE_REAL; // default OP_RESULT type
    return rule->exec(op_set);
}

status_t opr_type_infer_div(og_type_t left, og_type_t right, og_type_t *result)
{
    opr_rule_t *rule = g_div_oprs[OG_TYPE_I(left)][OG_TYPE_I(right)];

    if (rule != NULL) {
        *result = rule->rs_type;
        return OG_SUCCESS;
    }

    OPR_THROW_ERROR("/", left, right);
    return OG_ERROR;
}