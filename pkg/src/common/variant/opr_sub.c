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
 * opr_sub.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_sub.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_sub.h"
#include "opr_add.h"

static inline status_t opr_bigint_sub(int64 a, int64 b, int64 *res)
{
    if (SECUREC_UNLIKELY(opr_int64sub_overflow(a, b, res))) {
        OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/**
* Subtraction between two DATE types, return a number that represents
* the number of days
*/
static inline void opr_date_sub(date_t dt1, date_t dt2, dec8_t *res)
{
    /* 1 / UNITS_PER_DAY  @see cm_date.h
    = 0.00000000001157407407407407407407407407407407407407407407407407407407407407407407407407407407407407407407
    4074074074074 */
    static const dec8_t INV_UNITS_PER_DAY = {
        .len = DEC8_MAX_LEN,
        .head = CONVERT_D8EXPN(-16, OG_FALSE),
        .cells = { 115740, 74074074, 7407407, 40740740, 74074074, 7407407, 40740741 }
    };

    dec8_t diff;
    cm_int64_to_dec((int64)(dt1 - dt2), &diff);
    (void)cm_dec_mul(&diff, &INV_UNITS_PER_DAY, res);
}

static inline status_t sub_anytype_binary(opr_operand_set_t *op_set)
{
    OPR_ANYTYPE_BINARY(sub, op_set);
}

static inline status_t sub_binary_anytype(opr_operand_set_t *op_set)
{
    OPR_BINARY_ANYTYPE(sub, op_set);
}

/**
* Subtraction between two TIMESTAMP types, return a DSINTERVAL
*/
static inline interval_ds_t opr_timestamp_sub(timestamp_t ts1, timestamp_t ts2)
{
    return (interval_ds_t)(ts1 - ts2);
}

static inline interval_ds_t opr_tstamp_sub_date(timestamp_t ts, date_t dt)
{
    return opr_timestamp_sub(ts, (timestamp_t)dt);
}

static inline interval_ds_t opr_date_sub_tstamp(date_t dt, timestamp_t ts)
{
    return opr_timestamp_sub((timestamp_t)dt, ts);
}

static inline status_t opr_date_sub_dsinterval(date_t date, interval_ds_t dsitvl, date_t *res)
{
    return cm_date_add_dsinterval(date, -dsitvl, res);
}

static inline status_t sub_uint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_uint32 - (int64)OP_RIGHT(op_set)->v_uint32;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t sub_uint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_uint32 - (int64)OP_RIGHT(op_set)->v_int;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t sub_uint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    if (OP_RIGHT(op_set)->v_bigint == OG_MIN_INT64) {
        OG_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return OG_ERROR;
    }
    return opr_bigint_add((int64)OP_LEFT(op_set)->v_uint32, -OP_RIGHT(op_set)->v_bigint,
        &OP_RESULT(op_set)->v_bigint);
}

static inline status_t sub_uint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add((double)OP_LEFT(op_set)->v_uint32, -OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_uint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_sub_dec((int64)OP_LEFT(op_set)->v_uint32, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_uint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_sub_dec((int64)OP_LEFT(op_set)->v_uint32, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_uint_decimal sub_uint_number

static inline status_t sub_anytype_string(opr_operand_set_t *op_set)
{
    variant_t var;
    variant_t *old_right = OP_RIGHT(op_set);
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RIGHT(op_set) = &var;
    status_t status = opr_exec_sub(op_set);
    OP_RIGHT(op_set) = old_right;
    return status;
}

#define sub_uint_string        sub_anytype_string
#define sub_uint_char          sub_uint_string
#define sub_uint_varchar       sub_uint_string
#define sub_uint_binary        sub_anytype_binary
#define sub_uint_varbinary     sub_uint_string

OPR_DECL(sub_uint_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_uint_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_uint_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_uint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_uint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_uint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_uint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_uint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_uint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_uint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_uint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_uint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t sub_int_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_int - (int64)OP_RIGHT(op_set)->v_uint32;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t sub_int_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_int - (int64)OP_RIGHT(op_set)->v_int;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t sub_int_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_sub((int64)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t sub_int_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add((double)OP_LEFT(op_set)->v_int, -OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_int_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_sub_dec((int64)OP_LEFT(op_set)->v_int, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_int_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_sub_dec((int64)OP_LEFT(op_set)->v_int, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_int_decimal sub_int_number

#define sub_int_string        sub_anytype_string
#define sub_int_char          sub_int_string
#define sub_int_varchar       sub_int_string
#define sub_int_binary        sub_anytype_binary
#define sub_int_varbinary     sub_int_string

OPR_DECL(sub_int_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_int_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_int_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_int_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_int_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_int_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_int_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_int_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_int_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_int_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_int_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_int_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t sub_bigint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_add(OP_LEFT(op_set)->v_bigint, -((int64)OP_RIGHT(op_set)->v_uint32),
        &OP_RESULT(op_set)->v_bigint);
}

static inline status_t sub_bigint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_sub(OP_LEFT(op_set)->v_bigint, ((int64)OP_RIGHT(op_set)->v_int), &OP_RESULT(op_set)->v_bigint);
}

static inline status_t sub_bigint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_sub(OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t sub_bigint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add((double)OP_LEFT(op_set)->v_bigint, -OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_bigint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_sub_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_bigint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_sub_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}


#define sub_bigint_decimal sub_bigint_number

#define sub_bigint_string         sub_anytype_string
#define sub_bigint_char           sub_bigint_string
#define sub_bigint_varchar        sub_bigint_string
#define sub_bigint_binary         sub_anytype_binary
#define sub_bigint_varbinary      sub_bigint_string

OPR_DECL(sub_bigint_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_bigint_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_bigint_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(sub_bigint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_bigint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_bigint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_bigint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_bigint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_bigint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_bigint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_bigint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_bigint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t sub_real_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, -(double)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_real_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, -OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_real_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    if (OP_RIGHT(op_set)->v_bigint == OG_MIN_INT64) {
        return opr_double_add(OP_LEFT(op_set)->v_real, (double)OG_MAX_INT64 + 1, &OP_RESULT(op_set)->v_real);
    }
    return opr_double_add(OP_LEFT(op_set)->v_real, (double)-OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_real_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, -OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t sub_real_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_real_sub_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_real_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_real_sub_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_real_decimal   sub_real_number

#define sub_real_string        sub_anytype_string
#define sub_real_char          sub_real_string
#define sub_real_varchar       sub_real_string
#define sub_real_binary        sub_anytype_binary
#define sub_real_varbinary     sub_real_string

OPR_DECL(sub_real_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_real_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_real_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_real_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(sub_real_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_real_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_real_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_real_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_real_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_real_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_real_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_real_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t sub_number_uint(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    cm_uint32_to_dec(OP_RIGHT(op_set)->v_uint32, &r_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number_int(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    cm_int32_to_dec(OP_RIGHT(op_set)->v_int, &r_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number_bigint(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    cm_int64_to_dec(OP_RIGHT(op_set)->v_bigint, &r_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number_real(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    OG_RETURN_IFERR(cm_real_to_dec(OP_RIGHT(op_set)->v_real, &r_dec));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_number_decimal sub_number_number

static inline status_t sub_number_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number_string(opr_operand_set_t *op_set)
{
    variant_t var;
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &var.v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_number_char         sub_number_string
#define sub_number_varchar      sub_number_string
#define sub_number_binary       sub_anytype_binary
#define sub_number_varbinary    sub_number_string

OPR_DECL(sub_number_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_number2, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER2);
OPR_DECL(sub_number_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_number_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_number_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t sub_number2_uint(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    cm_uint32_to_dec(OP_RIGHT(op_set)->v_uint32, &r_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number2_int(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    cm_int32_to_dec(OP_RIGHT(op_set)->v_int, &r_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number2_bigint(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    cm_int64_to_dec(OP_RIGHT(op_set)->v_bigint, &r_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number2_real(opr_operand_set_t *op_set)
{
    dec8_t r_dec;
    OG_RETURN_IFERR(cm_real_to_dec(OP_RIGHT(op_set)->v_real, &r_dec));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &r_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t sub_number2_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_number2_decimal sub_number2_number
#define sub_number2_number2 sub_number2_number

static inline status_t sub_number2_string(opr_operand_set_t *op_set)
{
    variant_t var;
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_subtract(&OP_LEFT(op_set)->v_dec, &var.v_dec, &OP_RESULT(op_set)->v_dec);
}

#define sub_number2_char         sub_number2_string
#define sub_number2_varchar      sub_number2_string
#define sub_number2_binary       sub_anytype_binary
#define sub_number2_varbinary    sub_number2_string

OPR_DECL(sub_number2_uint, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_int, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_bigint, OG_TYPE_NUMBER2, OG_TYPE_NUMBER, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_real, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_number, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_decimal, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_char, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_varchar, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_string, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_binary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_number2_varbinary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);

static inline status_t sub_string_anytype(opr_operand_set_t *op_set)
{
    variant_t var;
    variant_t *old_left = OP_LEFT(op_set);
    OG_RETURN_IFERR(opr_text2dec(OP_LEFT(op_set), &var));
    OP_LEFT(op_set) = &var;
    status_t status = opr_exec_sub(op_set);
    OP_LEFT(op_set) = old_left;
    return status;
}

#define sub_string_uint       sub_string_anytype
#define sub_string_int        sub_string_anytype
#define sub_string_bigint     sub_string_anytype
#define sub_string_real       sub_string_anytype
#define sub_string_number     sub_string_anytype
#define sub_string_number2    sub_string_anytype
#define sub_string_decimal    sub_string_anytype
#define sub_string_char       sub_string_anytype
#define sub_string_varchar    sub_string_anytype
#define sub_string_string     sub_string_anytype
#define sub_string_binary     sub_anytype_binary
#define sub_string_varbinary  sub_string_anytype

OPR_DECL(sub_string_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_string_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_string_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_string_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define sub_binary_uint       sub_binary_anytype
#define sub_binary_int        sub_binary_anytype
#define sub_binary_bigint     sub_binary_anytype
#define sub_binary_real       sub_binary_anytype
#define sub_binary_number     sub_binary_anytype
#define sub_binary_number2    sub_binary_anytype
#define sub_binary_decimal    sub_binary_anytype
#define sub_binary_char       sub_binary_anytype
#define sub_binary_varchar    sub_binary_anytype
#define sub_binary_string     sub_binary_anytype
#define sub_binary_binary     sub_binary_anytype
#define sub_binary_varbinary  sub_binary_anytype

OPR_DECL(sub_binary_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(sub_binary_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(sub_binary_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(sub_binary_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t sub_date_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_days(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_date);
}

static inline status_t sub_date_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_days(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_date);
}

static inline status_t sub_date_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_days(OP_LEFT(op_set)->v_date, (double)(OP_RIGHT(op_set)->v_bigint),
        &OP_RESULT(op_set)->v_date);
}

static inline status_t sub_date_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_days(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_date);
}

static inline status_t sub_date_number(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_RIGHT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_days(OP_LEFT(op_set)->v_date, real, &OP_RESULT(op_set)->v_date);
}

#define sub_date_decimal sub_date_number
#define sub_date_number2 sub_date_number

static inline status_t sub_date_string(opr_operand_set_t *op_set)
{
    double var;
    if (cm_text2real(VALUE_PTR(text_t, OP_RIGHT(op_set)), &var) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_days(OP_LEFT(op_set)->v_date, var, &OP_RESULT(op_set)->v_date);
}

#define sub_date_char         sub_date_string
#define sub_date_varchar      sub_date_string
#define sub_date_binary       sub_anytype_binary
#define sub_date_varbinary    sub_date_string

static inline status_t sub_date_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return opr_date_sub_dsinterval(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_date);
}

static inline status_t sub_date_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_sub_yminterval(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_date);
}

static inline status_t sub_date_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    opr_date_sub(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_date, &OP_RESULT(op_set)->v_dec);
    return OG_SUCCESS;
}

static inline status_t sub_date_timestamp(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_date_sub_tstamp(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_tstamp);
    return OG_SUCCESS;
}
#define sub_date_timestamp_tz_fake sub_date_timestamp

static inline status_t sub_date_timestamp_tz(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_date,
        cm_get_session_time_zone(op_set->nls),
        OP_RIGHT(op_set)->v_tstamp_tz.tz_offset);

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_date_sub_tstamp(date_left_conv, OP_RIGHT(op_set)->v_tstamp_tz.tstamp);
    return OG_SUCCESS;
}

static inline status_t sub_date_timestamp_ltz(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_date,
        cm_get_session_time_zone(op_set->nls),
        cm_get_db_timezone());

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_date_sub_tstamp(date_left_conv, OP_RIGHT(op_set)->v_tstamp_ltz);
    return OG_SUCCESS;
}

OPR_DECL(sub_date_uint, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_int, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_bigint, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_real, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_number, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_number2, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_decimal, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_char, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_varchar, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_string, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_date, OG_TYPE_DATE, OG_TYPE_DATE, OG_TYPE_NUMBER);
OPR_DECL(sub_date_timestamp, OG_TYPE_DATE, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_date_timestamp_tz_fake, OG_TYPE_DATE, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_date_timestamp_tz, OG_TYPE_DATE, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_date_timestamp_ltz, OG_TYPE_DATE, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_date_interval_ym, OG_TYPE_DATE, OG_TYPE_INTERVAL_YM, OG_TYPE_DATE);
OPR_DECL(sub_date_interval_ds, OG_TYPE_DATE, OG_TYPE_INTERVAL_DS, OG_TYPE_DATE);
OPR_DECL(sub_date_binary, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(sub_date_varbinary, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);

static inline status_t sub_timestamp_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tstamp_sub_days(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_tstamp);
}

static inline status_t sub_timestamp_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tstamp_sub_days(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_tstamp);
}

static inline status_t sub_timestamp_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tstamp_sub_days(OP_LEFT(op_set)->v_tstamp, (double)(OP_RIGHT(op_set)->v_bigint),
        &OP_RESULT(op_set)->v_tstamp);
}

static inline status_t sub_timestamp_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tstamp_sub_days(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_tstamp);
}

static inline status_t sub_timestamp_number(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_RIGHT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tstamp_sub_days(OP_LEFT(op_set)->v_tstamp, real, &OP_RESULT(op_set)->v_tstamp);
}

#define sub_timestamp_decimal sub_timestamp_number
#define sub_timestamp_number2 sub_timestamp_number

static inline status_t sub_timestamp_string(opr_operand_set_t *op_set)
{
    double var;
    if (cm_text2real(VALUE_PTR(text_t, OP_RIGHT(op_set)), &var) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tstamp_sub_days(OP_LEFT(op_set)->v_tstamp, var, &OP_RESULT(op_set)->v_tstamp);
}

#define sub_timestamp_char      sub_timestamp_string
#define sub_timestamp_varchar   sub_timestamp_string
#define sub_timestamp_binary    sub_anytype_binary
#define sub_timestamp_varbinary sub_timestamp_string

static inline status_t sub_timestamp_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tmstamp_sub_dsinterval(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_itvl_ds,
        &OP_RESULT(op_set)->v_tstamp);
}

static inline status_t sub_timestamp_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_LEFT(op_set)->type;
    return cm_tmstamp_sub_yminterval(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_itvl_ym,
        &OP_RESULT(op_set)->v_tstamp);
}

static inline status_t sub_timestamp_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_tstamp_sub_date(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_date);
    return OG_SUCCESS;
}

static inline status_t sub_timestamp_timestamp(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(OP_LEFT(op_set)->v_tstamp, OP_RIGHT(op_set)->v_tstamp);
    return OG_SUCCESS;
}

#define sub_timestamp_timestamp_tz_fake sub_timestamp_timestamp

static inline status_t sub_timestamp_timestamp_ltz(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_tstamp,
        cm_get_session_time_zone(op_set->nls),
        cm_get_db_timezone());

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(date_left_conv, OP_RIGHT(op_set)->v_tstamp_ltz);
    return OG_SUCCESS;
}

static inline status_t sub_timestamp_timestamp_tz(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_tstamp,
        cm_get_session_time_zone(op_set->nls),
        OP_RIGHT(op_set)->v_tstamp_tz.tz_offset);

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(date_left_conv, OP_RIGHT(op_set)->v_tstamp_tz.tstamp);
    return OG_SUCCESS;
}

OPR_DECL(sub_timestamp_uint, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_int, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_bigint, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_real, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_number, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_number2, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_decimal, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_char, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_varchar, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_string, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_date, OG_TYPE_TIMESTAMP, OG_TYPE_DATE, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_timestamp, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_timestamp_tz_fake, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_timestamp_tz, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_timestamp_ltz, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_interval_ym, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_interval_ds, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_binary, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(sub_timestamp_varbinary, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);


static inline status_t sub_timestamp_tz_date(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_tstamp_tz.tstamp,
        OP_LEFT(op_set)->v_tstamp_tz.tz_offset, cm_get_session_time_zone(op_set->nls));

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(date_left_conv, OP_RIGHT(op_set)->v_tstamp);
    return OG_SUCCESS;
}

#define sub_timestamp_tz_timestamp         sub_timestamp_tz_date
#define sub_timestamp_tz_timestamp_tz_fake sub_timestamp_tz_date

static inline status_t sub_timestamp_tz_timestamp_tz(opr_operand_set_t *op_set)
{
    /* adjust tz */
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = cm_tstz_sub(&OP_LEFT(op_set)->v_tstamp_tz, &OP_RIGHT(op_set)->v_tstamp_tz);
    return OG_SUCCESS;
}

static inline status_t sub_timestamp_tz_timestamp_ltz(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_tstamp_tz.tstamp,
        OP_LEFT(op_set)->v_tstamp_tz.tz_offset, cm_get_db_timezone());

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(date_left_conv, OP_RIGHT(op_set)->v_tstamp_ltz);
    return OG_SUCCESS;
}

static inline status_t sub_timestamp_tz_others(opr_operand_set_t *op_set)
{
    status_t status;
    /* treated as OG_TYPE_TIMESTAMP */
    OP_LEFT(op_set)->type = OG_TYPE_TIMESTAMP;
    status = opr_exec_sub(op_set);
    OP_LEFT(op_set)->type = OG_TYPE_TIMESTAMP_TZ; // restore
    OP_RESULT(op_set)->type = (OP_RESULT(op_set)->type == OG_TYPE_TIMESTAMP) ? OG_TYPE_TIMESTAMP_TZ :
        OP_RESULT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_LEFT(op_set)->v_tstamp_tz.tz_offset;
    return status;
}

#define sub_timestamp_tz_uint sub_timestamp_tz_others
#define sub_timestamp_tz_int sub_timestamp_tz_others
#define sub_timestamp_tz_bigint sub_timestamp_tz_others
#define sub_timestamp_tz_real sub_timestamp_tz_others
#define sub_timestamp_tz_number sub_timestamp_tz_others
#define sub_timestamp_tz_number2 sub_timestamp_tz_others
#define sub_timestamp_tz_decimal sub_timestamp_tz_others
#define sub_timestamp_tz_char sub_timestamp_tz_others
#define sub_timestamp_tz_varchar sub_timestamp_tz_others
#define sub_timestamp_tz_string sub_timestamp_tz_others
#define sub_timestamp_tz_binary sub_anytype_binary
#define sub_timestamp_tz_varbinary sub_timestamp_tz_others
#define sub_timestamp_tz_interval_ds sub_timestamp_tz_others
#define sub_timestamp_tz_interval_ym sub_timestamp_tz_others

OPR_DECL(sub_timestamp_tz_uint, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_int, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_bigint, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_real, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_number, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_number2, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_decimal, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_char, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_varchar, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_string, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_date, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_DATE, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_tz_timestamp, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_tz_timestamp_tz, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_tz_timestamp_ltz, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_tz_interval_ym, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_interval_ds, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_binary, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(sub_timestamp_tz_varbinary, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);


static inline status_t sub_timestamp_ltz_date(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_date, cm_get_db_timezone(),
        cm_get_session_time_zone(op_set->nls));

    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(date_left_conv, OP_RIGHT(op_set)->v_tstamp_ltz);
    return OG_SUCCESS;
}

#define sub_timestamp_ltz_timestamp sub_timestamp_ltz_date
#define sub_timestamp_ltz_timestamp_tz_fake sub_timestamp_ltz_date

static inline status_t sub_timestamp_ltz_timestamp_tz(opr_operand_set_t *op_set)
{
    /* adjust to the same tz whith OP_RIGHT var */
    date_t date_left_conv = cm_adjust_date_between_two_tzs(OP_LEFT(op_set)->v_date, cm_get_db_timezone(),
        OP_RIGHT(op_set)->v_tstamp_tz.tz_offset);

    /* adjust tz */
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(date_left_conv, OP_RIGHT(op_set)->v_tstamp_ltz);
    return OG_SUCCESS;
}

static inline status_t sub_timestamp_ltz_timestamp_ltz(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    OP_RESULT(op_set)->v_itvl_ds = opr_timestamp_sub(OP_LEFT(op_set)->v_tstamp_ltz, OP_RIGHT(op_set)->v_tstamp_ltz);
    return OG_SUCCESS;
}

static inline status_t sub_timestamp_ltz_others(opr_operand_set_t *op_set)
{
    status_t status;
    // treated as OG_TYPE_TIMESTAMP
    OP_LEFT(op_set)->type = OG_TYPE_TIMESTAMP;
    status = opr_exec_sub(op_set);
    OP_LEFT(op_set)->type = OG_TYPE_TIMESTAMP_LTZ; // restore LEFT's datatype
    OP_RESULT(op_set)->type = (OP_RESULT(op_set)->type == OG_TYPE_TIMESTAMP) ? OG_TYPE_TIMESTAMP_LTZ :
        OP_RESULT(op_set)->type;
    return status;
}

#define sub_timestamp_ltz_uint sub_timestamp_ltz_others
#define sub_timestamp_ltz_int sub_timestamp_ltz_others
#define sub_timestamp_ltz_bigint sub_timestamp_ltz_others
#define sub_timestamp_ltz_real sub_timestamp_ltz_others
#define sub_timestamp_ltz_number sub_timestamp_ltz_others
#define sub_timestamp_ltz_number2 sub_timestamp_ltz_others
#define sub_timestamp_ltz_decimal sub_timestamp_ltz_others
#define sub_timestamp_ltz_char sub_timestamp_ltz_others
#define sub_timestamp_ltz_varchar sub_timestamp_ltz_others
#define sub_timestamp_ltz_string sub_timestamp_ltz_others
#define sub_timestamp_ltz_binary sub_anytype_binary
#define sub_timestamp_ltz_varbinary sub_timestamp_ltz_others
#define sub_timestamp_ltz_interval_ds sub_timestamp_ltz_others
#define sub_timestamp_ltz_interval_ym sub_timestamp_ltz_others

OPR_DECL(sub_timestamp_ltz_uint, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_int, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_bigint, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_real, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_number, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_number2, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_decimal, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_char, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_varchar, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_string, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_date, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_DATE, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_ltz_timestamp, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_ltz_timestamp_tz, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_ltz_timestamp_ltz, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS);
OPR_DECL(sub_timestamp_ltz_interval_ym, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_interval_ds, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_binary, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(sub_timestamp_ltz_varbinary, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);


static inline status_t sub_interval_ds_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    return cm_dsinterval_sub(OP_LEFT(op_set)->v_itvl_ds, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_itvl_ds);
}

OPR_DECL(sub_interval_ds_interval_ds, OG_TYPE_INTERVAL_DS, OG_TYPE_INTERVAL_DS, OG_TYPE_INTERVAL_DS);

static inline status_t sub_interval_ym_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    return cm_yminterval_sub(OP_LEFT(op_set)->v_itvl_ym, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_itvl_ym);
}


OPR_DECL(sub_interval_ym_interval_ym, OG_TYPE_INTERVAL_YM, OG_TYPE_INTERVAL_YM, OG_TYPE_INTERVAL_YM);

static opr_rule_t *g_sub_oprs[VAR_TYPE_ARRAY_SIZE][VAR_TYPE_ARRAY_SIZE] = {
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_UINT32,                 sub_uint_uint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_INTEGER,                sub_uint_int),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BIGINT,                 sub_uint_bigint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_REAL,                   sub_uint_real),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER,                 sub_uint_number),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER2,                sub_uint_number2),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_DECIMAL,                sub_uint_decimal),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_CHAR,                   sub_uint_char),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARCHAR,                sub_uint_varchar),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_STRING,                 sub_uint_string),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BINARY,                 sub_uint_binary),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARBINARY,              sub_uint_varbinary),

    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_UINT32,                sub_int_uint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_INTEGER,               sub_int_int),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BIGINT,                sub_int_bigint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_REAL,                  sub_int_real),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER,                sub_int_number),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER2,               sub_int_number2),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_DECIMAL,               sub_int_decimal),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_CHAR,                  sub_int_char),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARCHAR,               sub_int_varchar),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_STRING,                sub_int_string),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BINARY,                sub_int_binary),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARBINARY,             sub_int_varbinary),

    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_UINT32,                 sub_bigint_uint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_INTEGER,                sub_bigint_int),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BIGINT,                 sub_bigint_bigint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_REAL,                   sub_bigint_real),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER,                 sub_bigint_number),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER2,                sub_bigint_number2),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_DECIMAL,                sub_bigint_decimal),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_CHAR,                   sub_bigint_char),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARCHAR,                sub_bigint_varchar),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_STRING,                 sub_bigint_string),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BINARY,                 sub_bigint_binary),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARBINARY,              sub_bigint_varbinary),

    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_UINT32,                   sub_real_uint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_INTEGER,                  sub_real_int),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BIGINT,                   sub_real_bigint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_REAL,                     sub_real_real),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER,                   sub_real_number),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER2,                  sub_real_number2),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_DECIMAL,                  sub_real_decimal),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_CHAR,                     sub_real_char),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARCHAR,                  sub_real_varchar),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_STRING,                   sub_real_string),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BINARY,                   sub_real_binary),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARBINARY,                sub_real_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_UINT32,                 sub_number_uint),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_INTEGER,                sub_number_int),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BIGINT,                 sub_number_bigint),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_REAL,                   sub_number_real),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER,                 sub_number_number),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER2,                sub_number_number2),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_DECIMAL,                sub_number_decimal),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_CHAR,                   sub_number_char),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARCHAR,                sub_number_varchar),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_STRING,                 sub_number_string),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BINARY,                 sub_number_binary),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARBINARY,              sub_number_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_UINT32,                 sub_number2_uint),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_INTEGER,                sub_number2_int),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BIGINT,                 sub_number2_bigint),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_REAL,                   sub_number2_real),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER,                 sub_number2_number),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER2,                sub_number2_number2),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_DECIMAL,                sub_number2_decimal),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_CHAR,                   sub_number2_char),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARCHAR,                sub_number2_varchar),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_STRING,                 sub_number2_string),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BINARY,                 sub_number2_binary),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARBINARY,              sub_number2_varbinary),

    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_UINT32,                sub_number_uint),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_INTEGER,               sub_number_int),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BIGINT,                sub_number_bigint),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_REAL,                  sub_number_real),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER,                sub_number_number),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER2,               sub_number_number2),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_DECIMAL,               sub_number_decimal),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_CHAR,                  sub_number_char),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARCHAR,               sub_number_varchar),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_STRING,                sub_number_string),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BINARY,                sub_number_binary),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARBINARY,             sub_number_varbinary),

    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_UINT32,                   sub_string_uint),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_INTEGER,                  sub_string_int),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BIGINT,                   sub_string_bigint),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_REAL,                     sub_string_real),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER,                   sub_string_number),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER2,                  sub_string_number2),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_DECIMAL,                  sub_string_decimal),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_CHAR,                     sub_string_char),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARCHAR,                  sub_string_varchar),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_STRING,                   sub_string_string),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BINARY,                   sub_string_binary),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARBINARY,                sub_string_varbinary),

    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_UINT32,                sub_string_uint),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_INTEGER,               sub_string_int),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BIGINT,                sub_string_bigint),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_REAL,                  sub_string_real),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER,                sub_string_number),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER2,               sub_string_number2),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_DECIMAL,               sub_string_decimal),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_CHAR,                  sub_string_char),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARCHAR,               sub_string_varchar),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_STRING,                sub_string_string),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BINARY,                sub_string_binary),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARBINARY,             sub_string_varbinary),

    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_UINT32,                 sub_string_uint),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_INTEGER,                sub_string_int),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BIGINT,                 sub_string_bigint),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_REAL,                   sub_string_real),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER,                 sub_string_number),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER2,                sub_string_number2),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_DECIMAL,                sub_string_decimal),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_CHAR,                   sub_string_char),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARCHAR,                sub_string_varchar),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_STRING,                 sub_string_string),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BINARY,                 sub_string_binary),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARBINARY,              sub_string_varbinary),

    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_UINT32,                 sub_binary_uint),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_INTEGER,                sub_binary_int),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BIGINT,                 sub_binary_bigint),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_REAL,                   sub_binary_real),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER,                 sub_binary_number),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER2,                sub_binary_number2),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_DECIMAL,                sub_binary_decimal),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_CHAR,                   sub_binary_char),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARCHAR,                sub_binary_varchar),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_STRING,                 sub_binary_string),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BINARY,                 sub_binary_binary),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARBINARY,              sub_binary_varbinary),

    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_UINT32,              sub_string_uint),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_INTEGER,             sub_string_int),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BIGINT,              sub_string_bigint),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_REAL,                sub_string_real),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER,              sub_string_number),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER2,             sub_string_number2),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_DECIMAL,             sub_string_decimal),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_CHAR,                sub_string_char),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARCHAR,             sub_string_varchar),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_STRING,              sub_string_string),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BINARY,              sub_string_binary),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARBINARY,           sub_string_varbinary),

    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_UINT32,                   sub_date_uint),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_INTEGER,                  sub_date_int),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_BIGINT,                   sub_date_bigint),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_REAL,                     sub_date_real),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_NUMBER,                   sub_date_number),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_NUMBER2,                  sub_date_number2),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_DECIMAL,                  sub_date_decimal),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_CHAR,                     sub_date_char),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_VARCHAR,                  sub_date_varchar),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_STRING,                   sub_date_string),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_DATE,                     sub_date_date),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_TIMESTAMP,                sub_date_timestamp),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_TIMESTAMP_TZ_FAKE,        sub_date_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_TIMESTAMP_TZ,             sub_date_timestamp_tz),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_TIMESTAMP_LTZ,            sub_date_timestamp_ltz),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_INTERVAL_YM,              sub_date_interval_ym),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_INTERVAL_DS,              sub_date_interval_ds),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_BINARY,                   sub_date_binary),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_VARBINARY,                sub_date_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_UINT32,                  sub_timestamp_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_INTEGER,                 sub_timestamp_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_BIGINT,                  sub_timestamp_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_REAL,                    sub_timestamp_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_NUMBER,                  sub_timestamp_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_NUMBER2,                 sub_timestamp_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_DECIMAL,                 sub_timestamp_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_CHAR,                    sub_timestamp_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_VARCHAR,                 sub_timestamp_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_STRING,                  sub_timestamp_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_DATE,                    sub_timestamp_date),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP,               sub_timestamp_timestamp),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP_TZ_FAKE,       sub_timestamp_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP_TZ,            sub_timestamp_timestamp_tz),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP_LTZ,           sub_timestamp_timestamp_ltz),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_YM,             sub_timestamp_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS,             sub_timestamp_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_BINARY,                  sub_timestamp_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_VARBINARY,               sub_timestamp_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_UINT32,                  sub_timestamp_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTEGER,                 sub_timestamp_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_BIGINT,                  sub_timestamp_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_REAL,                    sub_timestamp_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_NUMBER,                  sub_timestamp_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_NUMBER2,                 sub_timestamp_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_DECIMAL,                 sub_timestamp_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_CHAR,                    sub_timestamp_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_VARCHAR,                 sub_timestamp_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_STRING,                  sub_timestamp_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_DATE,                    sub_timestamp_date),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP,               sub_timestamp_timestamp),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP_TZ_FAKE,       sub_timestamp_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP_TZ,            sub_timestamp_timestamp_tz),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP_LTZ,           sub_timestamp_timestamp_ltz),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTERVAL_YM,             sub_timestamp_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTERVAL_DS,             sub_timestamp_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_BINARY,                  sub_timestamp_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_VARBINARY,               sub_timestamp_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_UINT32,                       sub_timestamp_tz_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTEGER,                      sub_timestamp_tz_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_BIGINT,                       sub_timestamp_tz_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL,                         sub_timestamp_tz_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_NUMBER,                       sub_timestamp_tz_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_NUMBER2,                      sub_timestamp_tz_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_DECIMAL,                      sub_timestamp_tz_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_CHAR,                         sub_timestamp_tz_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_VARCHAR,                      sub_timestamp_tz_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_STRING,                       sub_timestamp_tz_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_DATE,                         sub_timestamp_tz_date),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP,                    sub_timestamp_tz_timestamp),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ,                 sub_timestamp_tz_timestamp_tz),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_LTZ,                sub_timestamp_tz_timestamp_ltz),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_YM,                  sub_timestamp_tz_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS,                  sub_timestamp_tz_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_BINARY,                       sub_timestamp_tz_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_VARBINARY,                    sub_timestamp_tz_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_UINT32,                            sub_timestamp_ltz_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTEGER,                           sub_timestamp_ltz_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_BIGINT,                            sub_timestamp_ltz_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL,                              sub_timestamp_ltz_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_NUMBER,                            sub_timestamp_ltz_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_NUMBER2,                           sub_timestamp_ltz_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_DECIMAL,                           sub_timestamp_ltz_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_CHAR,                              sub_timestamp_ltz_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_VARCHAR,                           sub_timestamp_ltz_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_STRING,                            sub_timestamp_ltz_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_DATE,                              sub_timestamp_ltz_date),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP,                         sub_timestamp_ltz_timestamp),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_TZ,                      sub_timestamp_ltz_timestamp_tz),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ,                     sub_timestamp_ltz_timestamp_ltz),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_YM,                       sub_timestamp_ltz_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS,                       sub_timestamp_ltz_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_BINARY,                            sub_timestamp_ltz_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_VARBINARY,                         sub_timestamp_ltz_varbinary),

    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_INTERVAL_YM,                         sub_interval_ym_interval_ym),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_INTERVAL_DS,                         sub_interval_ds_interval_ds),
};  // end g_subtraction_rules


status_t opr_exec_sub(opr_operand_set_t *op_set)
{
    opr_rule_t *rule = g_sub_oprs[OG_TYPE_I(OP_LEFT(op_set)->type)][OG_TYPE_I(OP_RIGHT(op_set)->type)];

    if (SECUREC_UNLIKELY(rule == NULL)) {
        OPR_THROW_ERROR("-", OP_LEFT(op_set)->type, OP_RIGHT(op_set)->type);
        return OG_ERROR;
    }
    return rule->exec(op_set);
}

status_t opr_type_infer_sub(og_type_t left, og_type_t right, og_type_t *result)
{
    opr_rule_t *rule = g_sub_oprs[OG_TYPE_I(left)][OG_TYPE_I(right)];

    if (rule != NULL) {
        *result = rule->rs_type;
        return OG_SUCCESS;
    }

    OPR_THROW_ERROR("-", left, right);
    return OG_ERROR;
}