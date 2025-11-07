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
 * opr_mod.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_mod.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_mod.h"

static inline status_t mod_anytype_binary(opr_operand_set_t *op_set)
{
    OPR_ANYTYPE_BINARY(mod, op_set);
}

static inline status_t mod_binary_anytype(opr_operand_set_t *op_set)
{
    OPR_BINARY_ANYTYPE(mod, op_set);
}

static inline status_t opr_int32_mod(int32 a, int32 b, variant_t *result)
{
    // Oracle returns a when b = 0.
    if (b == 0) {
        result->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    /*
    * Some machines throw a floating-point exception for INT_MIN % -1, which
    * is a bit silly since the correct answer is perfectly well-defined,
    * namely zero.
    */
    if (b == -1) {
        result->v_int = 0;
        return OG_SUCCESS;
    }

    /* No overflow is possible */
    result->v_int = a % b;
    return OG_SUCCESS;
}

static inline status_t opr_uint32_mod(uint32 a, uint32 b, variant_t *result)
{
    // Oracle returns a when b = 0.
    if (b == 0) {
        result->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    /* No overflow is possible */
    result->v_uint32 = a % b;
    return OG_SUCCESS;
}

static inline status_t opr_bigint_mod(int64 a, int64 b, variant_t *result)
{
    // Oracle returns a when b = 0.
    if (b == 0) {
        result->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    /*
    * Some machines throw a floating-point exception for INT_MIN % -1, which
    * is a bit silly since the correct answer is perfectly well-defined,
    * namely zero.
    */
    if (b == -1) {
        result->v_bigint = 0;
        return OG_SUCCESS;
    }

    /* No overflow is possible */
    result->v_bigint = a % b;
    return OG_SUCCESS;
}

static inline status_t opr_double_mod(double a, double b, variant_t *result)
{
    // whether b is equal to 0
    if (fabs(b) < OG_REAL_PRECISION) {
        result->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    result->v_real = fmod(a, b);
    result->is_null = OG_FALSE;
    return OG_SUCCESS;
}

static inline status_t mod_uint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_UINT32;
    return opr_uint32_mod(OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
}

static inline status_t mod_uint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod((int64)OP_LEFT(op_set)->v_uint32, (int64)OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
}

static inline status_t mod_uint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod((int64)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
}

static inline status_t mod_uint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod((double)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
}

static inline status_t mod_anytype_dec(opr_operand_set_t *op_set)
{
    dec8_t tmp_dec;
    variant_t l;
    variant_t r;

    if (var_num_is_zero(OP_RIGHT(op_set))) {
        OP_RESULT(op_set)->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    l = *OP_LEFT(op_set);
    r = *OP_RIGHT(op_set);

    OG_RETURN_IFERR(var_as_decimal(&l));
    OG_RETURN_IFERR(var_as_decimal(&r));

    OG_RETURN_IFERR(cm_dec_divide(&l.v_dec, &r.v_dec, &OP_RESULT(op_set)->v_dec));
    OG_RETURN_IFERR(cm_dec_scale(&OP_RESULT(op_set)->v_dec, 0, ROUND_TRUNC));
    OG_RETURN_IFERR(cm_dec_mul(&r.v_dec, &OP_RESULT(op_set)->v_dec, &tmp_dec));
    OG_RETURN_IFERR(cm_dec_subtract(&l.v_dec, &tmp_dec, &OP_RESULT(op_set)->v_dec));
    return OG_SUCCESS;
}

static inline status_t mod_anytype_number(opr_operand_set_t *op_set)
{
    OG_RETURN_IFERR(mod_anytype_dec(op_set));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return OG_SUCCESS;
}

static inline status_t mod_anytype_number2(opr_operand_set_t *op_set)
{
    OG_RETURN_IFERR(mod_anytype_dec(op_set));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return OG_SUCCESS;
}

#define mod_anytype_string     mod_anytype_number // convert string to number

#define mod_uint_number        mod_anytype_number
#define mod_uint_number2       mod_anytype_number2
#define mod_uint_decimal       mod_anytype_number
#define mod_uint_char          mod_anytype_string
#define mod_uint_varchar       mod_anytype_string
#define mod_uint_string        mod_anytype_string
#define mod_uint_binary        mod_anytype_binary
#define mod_uint_varbinary     mod_anytype_string

OPR_DECL(mod_uint_uint, OG_TYPE_UINT32, OG_TYPE_UINT32, OG_TYPE_UINT32);
OPR_DECL(mod_uint_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_uint_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_uint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_uint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_uint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(mod_uint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(mod_uint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_uint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_uint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_uint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_uint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t mod_int_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod((int64)OP_LEFT(op_set)->v_int, (int64)OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
}

static inline status_t mod_int_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTEGER;
    return opr_int32_mod(OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
}

static inline status_t mod_int_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod((int64)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
}

static inline status_t mod_int_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod((double)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
}

#define mod_int_number        mod_anytype_number
#define mod_int_number2       mod_anytype_number2
#define mod_int_decimal       mod_anytype_number
#define mod_int_char          mod_anytype_string
#define mod_int_varchar       mod_anytype_string
#define mod_int_string        mod_anytype_string
#define mod_int_binary        mod_anytype_binary
#define mod_int_varbinary     mod_anytype_string

OPR_DECL(mod_int_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_int_int, OG_TYPE_INTEGER, OG_TYPE_INTEGER, OG_TYPE_INTEGER);
OPR_DECL(mod_int_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_int_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_int_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_int_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(mod_int_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(mod_int_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_int_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_int_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_int_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_int_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t mod_bigint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod(OP_LEFT(op_set)->v_bigint, (int64)OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
}

static inline status_t mod_bigint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod(OP_LEFT(op_set)->v_bigint, (int64)OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
}

static inline status_t mod_bigint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_mod(OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
}

static inline status_t mod_bigint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod((double)OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
}

#define mod_bigint_number        mod_anytype_number
#define mod_bigint_number2       mod_anytype_number2
#define mod_bigint_decimal       mod_anytype_number
#define mod_bigint_char          mod_anytype_string
#define mod_bigint_varchar       mod_anytype_string
#define mod_bigint_string        mod_anytype_string
#define mod_bigint_binary        mod_anytype_binary
#define mod_bigint_varbinary     mod_anytype_string

OPR_DECL(mod_bigint_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_bigint_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_bigint_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(mod_bigint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_bigint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_bigint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(mod_bigint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(mod_bigint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_bigint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_bigint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_bigint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_bigint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t mod_real_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_uint32, OP_RESULT(op_set));
}

static inline status_t mod_real_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_int, OP_RESULT(op_set));
}

static inline status_t mod_real_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_bigint, OP_RESULT(op_set));
}

static inline status_t mod_real_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_mod(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_real, OP_RESULT(op_set));
}

#define mod_real_number        mod_anytype_number
#define mod_real_number2       mod_anytype_number2
#define mod_real_decimal       mod_anytype_number
#define mod_real_char          mod_anytype_string
#define mod_real_varchar       mod_anytype_string
#define mod_real_string        mod_anytype_string
#define mod_real_binary        mod_anytype_binary
#define mod_real_varbinary     mod_anytype_string

OPR_DECL(mod_real_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_real_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_real_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_real_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(mod_real_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_real_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(mod_real_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(mod_real_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_real_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_real_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_real_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_real_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define mod_number_anytype mod_anytype_number
OPR_DECL(mod_number_anytype, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define mod_number2_anytype mod_anytype_number2
OPR_DECL(mod_number2_anytype, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);

#define mod_string_anytype  mod_anytype_number
OPR_DECL(mod_string_anytype, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define mod_string_binary   mod_anytype_binary
#define mod_number_binary   mod_anytype_binary
OPR_DECL(mod_string_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(mod_number_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define mod_number2_binary   mod_anytype_binary
OPR_DECL(mod_number2_binary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);

OPR_DECL(mod_binary_anytype, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


/** The rules for modulus of two database */
static opr_rule_t *g_mod_oprs[VAR_TYPE_ARRAY_SIZE][VAR_TYPE_ARRAY_SIZE] = {
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_UINT32,             mod_uint_uint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_INTEGER,            mod_uint_int),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BIGINT,             mod_uint_bigint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_REAL,               mod_uint_real),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER,             mod_uint_number),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER2,            mod_uint_number2),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_DECIMAL,            mod_uint_decimal),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_CHAR,               mod_uint_char),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARCHAR,            mod_uint_varchar),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_STRING,             mod_uint_string),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BINARY,             mod_uint_binary),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARBINARY,          mod_uint_varbinary),

    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_UINT32,             mod_int_uint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_INTEGER,            mod_int_int),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BIGINT,             mod_int_bigint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_REAL,               mod_int_real),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER,             mod_int_number),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER2,            mod_int_number2),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_DECIMAL,            mod_int_decimal),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_CHAR,               mod_int_char),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARCHAR,            mod_int_varchar),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_STRING,             mod_int_string),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BINARY,             mod_int_binary),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARBINARY,          mod_int_varbinary),

    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_UINT32,             mod_bigint_uint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_INTEGER,            mod_bigint_int),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BIGINT,             mod_bigint_bigint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_REAL,               mod_bigint_real),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER,             mod_bigint_number),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER2,            mod_bigint_number2),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_DECIMAL,            mod_bigint_decimal),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_CHAR,               mod_bigint_char),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARCHAR,            mod_bigint_varchar),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_STRING,             mod_bigint_string),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BINARY,             mod_bigint_binary),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARBINARY,          mod_bigint_varbinary),

    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_UINT32,             mod_real_uint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_INTEGER,            mod_real_int),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BIGINT,             mod_real_bigint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_REAL,               mod_real_real),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER,             mod_real_number),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER2,            mod_real_number2),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_DECIMAL,            mod_real_decimal),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_CHAR,               mod_real_char),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARCHAR,            mod_real_varchar),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_STRING,             mod_real_string),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BINARY,             mod_real_binary),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARBINARY,          mod_real_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_UINT32,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_INTEGER,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BIGINT,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_REAL,               mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER2,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_DECIMAL,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_CHAR,               mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARCHAR,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_STRING,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BINARY,             mod_number_binary),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARBINARY,          mod_number_anytype),

    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_UINT32,             mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_INTEGER,            mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BIGINT,             mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_REAL,               mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER,             mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER2,            mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_DECIMAL,            mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_CHAR,               mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARCHAR,            mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_STRING,             mod_number2_anytype),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BINARY,             mod_number2_binary),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARBINARY,          mod_number2_anytype),

    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_UINT32,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_INTEGER,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BIGINT,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_REAL,               mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER2,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_DECIMAL,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_CHAR,               mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARCHAR,            mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_STRING,             mod_number_anytype),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BINARY,             mod_number_binary),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARBINARY,          mod_number_anytype),

    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_UINT32,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_INTEGER,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BIGINT,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_REAL,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER2,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_DECIMAL,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_CHAR,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARCHAR,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_STRING,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BINARY,             mod_string_binary),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARBINARY,          mod_string_anytype),

    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_UINT32,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_INTEGER,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BIGINT,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_REAL,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER2,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_DECIMAL,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_CHAR,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARCHAR,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_STRING,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BINARY,             mod_string_binary),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARBINARY,          mod_string_anytype),

    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_UINT32,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_INTEGER,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BIGINT,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_REAL,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER2,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_DECIMAL,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_CHAR,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARCHAR,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_STRING,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BINARY,             mod_string_binary),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARBINARY,          mod_string_anytype),

    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_UINT32,             mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_INTEGER,            mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BIGINT,             mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_REAL,               mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER,             mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER2,            mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_DECIMAL,            mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_CHAR,               mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARCHAR,            mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_STRING,             mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BINARY,             mod_binary_anytype),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARBINARY,          mod_binary_anytype),

    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_UINT32,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_INTEGER,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BIGINT,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_REAL,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER2,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_DECIMAL,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_CHAR,               mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARCHAR,            mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_STRING,             mod_string_anytype),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BINARY,             mod_string_binary),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARBINARY,          mod_string_anytype),
};


status_t opr_exec_mod(opr_operand_set_t *op_set)
{
    opr_rule_t *rule = g_mod_oprs[OG_TYPE_I(OP_LEFT(op_set)->type)][OG_TYPE_I(OP_RIGHT(op_set)->type)];

    if (SECUREC_UNLIKELY(rule == NULL)) {
        OPR_THROW_ERROR("/", OP_LEFT(op_set)->type, OP_RIGHT(op_set)->type);
        return OG_ERROR;
    }

    OP_RESULT(op_set)->type = OG_TYPE_REAL; // default OP_RESULT type
    return rule->exec(op_set);
}

status_t opr_type_infer_mod(og_type_t left, og_type_t right, og_type_t *result)
{
    opr_rule_t *rule = g_mod_oprs[OG_TYPE_I(left)][OG_TYPE_I(right)];

    if (rule != NULL) {
        *result = rule->rs_type;
        return OG_SUCCESS;
    }

    OPR_THROW_ERROR("%", left, right);
    return OG_ERROR;
}
