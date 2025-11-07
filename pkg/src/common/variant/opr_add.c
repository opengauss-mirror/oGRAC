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
 * opr_add.c
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_add.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_add.h"

static inline status_t add_anytype_binary(opr_operand_set_t *op_set)
{
    OPR_ANYTYPE_BINARY(add, op_set);
}

static inline status_t add_binary_anytype(opr_operand_set_t *op_set)
{
    OPR_BINARY_ANYTYPE(add, op_set);
}

static inline status_t add_int_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_int + (int64)OP_RIGHT(op_set)->v_int;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t add_int_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_int + (int64)OP_RIGHT(op_set)->v_uint32;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t add_int_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_add((int64)OP_LEFT(op_set)->v_int, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t add_int_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_int + OP_RIGHT(op_set)->v_real;
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return OG_SUCCESS;
}

static inline status_t add_int_decimal(opr_operand_set_t *op_set)
{
    dec8_t l_dec;
    cm_int32_to_dec(OP_LEFT(op_set)->v_int, &l_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_add(&l_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_int_number add_int_decimal

static inline status_t add_int_number2(opr_operand_set_t *op_set)
{
    dec8_t l_dec;
    cm_int32_to_dec(OP_LEFT(op_set)->v_int, &l_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_add(&l_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_int_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, (double)OP_LEFT(op_set)->v_int, &OP_RESULT(op_set)->v_date);
}

#define add_int_timestamp         add_int_date
#define add_int_timestamp_tz_fake add_int_date
#define add_int_timestamp_ltz     add_int_date

static inline status_t add_int_timestamp_tz(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_RIGHT(op_set)->v_tstamp_tz.tz_offset;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, (double)OP_LEFT(op_set)->v_int, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_anytype_string(opr_operand_set_t *op_set)
{
    variant_t var;
    variant_t *old_right = OP_RIGHT(op_set);
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RIGHT(op_set) = &var;
    status_t status = opr_exec_add(op_set);
    OP_RIGHT(op_set) = old_right;
    return status;
}

#define add_int_string     add_anytype_string
#define add_int_char       add_int_string
#define add_int_varchar    add_int_string
#define add_int_binary     add_anytype_binary
#define add_int_varbinary  add_int_string // varbinary bytes as string directly

OPR_DECL(add_int_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_int_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_int_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_int_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_int_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_int_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_int_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_int_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_int_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_int_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_int_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_int_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_int_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_int_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_int_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_int_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);  // binary bytes as string directly
OPR_DECL(add_int_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER); // binary bytes as string directly

static inline status_t add_uint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_uint32 + (int64)OP_RIGHT(op_set)->v_uint32;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t add_uint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_bigint = (int64)OP_LEFT(op_set)->v_uint32 + (int64)OP_RIGHT(op_set)->v_int;
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return OG_SUCCESS;
}

static inline status_t add_uint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_add((int64)OP_LEFT(op_set)->v_uint32, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t add_uint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->v_real = (double)OP_LEFT(op_set)->v_uint32 + OP_RIGHT(op_set)->v_real;
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return OG_SUCCESS;
}

static inline status_t add_uint_number(opr_operand_set_t *op_set)
{
    dec8_t l_dec;
    cm_uint32_to_dec(OP_LEFT(op_set)->v_uint32, &l_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_add(&l_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_uint_decimal add_uint_number

static inline status_t add_uint_number2(opr_operand_set_t *op_set)
{
    dec8_t l_dec;
    cm_uint32_to_dec(OP_LEFT(op_set)->v_uint32, &l_dec);
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_add(&l_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_uint_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, (double)OP_LEFT(op_set)->v_uint32, &OP_RESULT(op_set)->v_date);
}

#define add_uint_timestamp         add_uint_date
#define add_uint_timestamp_tz_fake add_uint_date
#define add_uint_timestamp_ltz     add_uint_date

static inline status_t add_uint_timestamp_tz(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_RIGHT(op_set)->v_tstamp_tz.tz_offset;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, (double)OP_LEFT(op_set)->v_uint32, &OP_RESULT(op_set)->v_date);
}

#define add_uint_string     add_anytype_string
#define add_uint_char       add_uint_string
#define add_uint_varchar    add_uint_string
#define add_uint_binary     add_anytype_binary
#define add_uint_varbinary  add_uint_string // binary bytes as string directly

OPR_DECL(add_uint_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_uint_int, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_uint_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_uint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_uint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_uint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_uint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_uint_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_uint_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_uint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_uint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_uint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_uint_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_uint_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_uint_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_uint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_uint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t add_bigint_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_add(OP_LEFT(op_set)->v_bigint, (int64)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t add_bigint_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_add(OP_LEFT(op_set)->v_bigint, (int64)OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t add_bigint_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_BIGINT;
    return opr_bigint_add(OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_bigint);
}

static inline status_t add_bigint_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add((double)OP_LEFT(op_set)->v_bigint, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t add_bigint_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_add_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_bigint_decimal add_bigint_number

static inline status_t add_bigint_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_add_dec(OP_LEFT(op_set)->v_bigint, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_bigint_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, (double)OP_LEFT(op_set)->v_bigint, &OP_RESULT(op_set)->v_date);
}

#define add_bigint_timestamp         add_bigint_date
#define add_bigint_timestamp_tz_fake add_bigint_date
#define add_bigint_timestamp_ltz     add_bigint_date

static inline status_t add_bigint_timestamp_tz(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_RIGHT(op_set)->v_tstamp_tz.tz_offset;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, (double)OP_LEFT(op_set)->v_bigint, &OP_RESULT(op_set)->v_date);
}


#define add_bigint_string    add_anytype_string
#define add_bigint_char      add_bigint_string
#define add_bigint_varchar   add_bigint_string
#define add_bigint_binary    add_anytype_binary
#define add_bigint_varbinary add_bigint_string

OPR_DECL(add_bigint_uint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_bigint_int,  OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_bigint_bigint, OG_TYPE_BIGINT, OG_TYPE_BIGINT, OG_TYPE_BIGINT);
OPR_DECL(add_bigint_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_bigint_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_bigint_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_bigint_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_bigint_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_bigint_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_bigint_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_bigint_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_bigint_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_bigint_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_bigint_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_bigint_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_bigint_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_bigint_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t add_real_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_real);
}

static inline status_t add_real_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_real);
}

static inline status_t add_real_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, (double)OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_real);
}

static inline status_t add_real_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_REAL;
    return opr_double_add(OP_LEFT(op_set)->v_real, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_real);
}

static inline status_t add_real_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_real_add_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_real_decimal add_real_number

static inline status_t add_real_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_real_add_dec(OP_LEFT(op_set)->v_real, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_real_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, OP_LEFT(op_set)->v_real, &OP_RESULT(op_set)->v_date);
}

#define add_real_timestamp         add_real_date
#define add_real_timestamp_tz_fake add_real_date
#define add_real_timestamp_ltz     add_real_date

static inline status_t add_real_timestamp_tz(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_RIGHT(op_set)->v_tstamp_tz.tz_offset;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, OP_LEFT(op_set)->v_real, &OP_RESULT(op_set)->v_date);
}

#define add_real_string    add_anytype_string
#define add_real_char      add_real_string
#define add_real_varchar   add_real_string
#define add_real_binary    add_anytype_binary
#define add_real_varbinary add_real_string

OPR_DECL(add_real_uint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_real_int, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_real_bigint, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_real_real, OG_TYPE_REAL, OG_TYPE_REAL, OG_TYPE_REAL);
OPR_DECL(add_real_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_real_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_real_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_real_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_real_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_real_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_real_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_real_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_real_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_real_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_real_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_real_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_real_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t add_number_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_add_dec((int64)OP_RIGHT(op_set)->v_uint32, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_add_dec((int64)OP_RIGHT(op_set)->v_int, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_int64_add_dec(OP_RIGHT(op_set)->v_bigint, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_real_add_dec(OP_RIGHT(op_set)->v_real, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number_number(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_add(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_number_decimal add_number_number

static inline status_t add_number_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_add(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number_date(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_LEFT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, real, &OP_RESULT(op_set)->v_date);
}

#define add_number_timestamp         add_number_date
#define add_number_timestamp_tz_fake add_number_date
#define add_number_timestamp_ltz     add_number_date

static inline status_t add_number_string(opr_operand_set_t *op_set)
{
    variant_t var;
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER;
    return cm_dec_add(&OP_LEFT(op_set)->v_dec, &var.v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_number_char       add_number_string
#define add_number_varchar    add_number_string
#define add_number_binary     add_anytype_binary
#define add_number_varbinary  add_number_string

static inline status_t add_number_timestamp_tz(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_LEFT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_RIGHT(op_set)->v_tstamp_tz.tz_offset;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, real, &OP_RESULT(op_set)->v_date);
}

OPR_DECL(add_number_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_number2, OG_TYPE_NUMBER, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_number_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_number_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_number_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_number_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_number_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_number_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_number_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);


static inline status_t add_number2_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_add_dec((int64)OP_RIGHT(op_set)->v_uint32, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number2_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_add_dec((int64)OP_RIGHT(op_set)->v_int, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number2_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_int64_add_dec(OP_RIGHT(op_set)->v_bigint, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number2_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_real_add_dec(OP_RIGHT(op_set)->v_real, &OP_LEFT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}

static inline status_t add_number2_number2(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_add(&OP_LEFT(op_set)->v_dec, &OP_RIGHT(op_set)->v_dec, &OP_RESULT(op_set)->v_dec);
}


#define add_number2_number add_number2_number2
#define add_number2_decimal add_number2_number

static inline status_t add_number2_date(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_LEFT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, real, &OP_RESULT(op_set)->v_date);
}

#define add_number2_timestamp         add_number2_date
#define add_number2_timestamp_tz_fake add_number2_date
#define add_number2_timestamp_ltz     add_number2_date

static inline status_t add_number2_string(opr_operand_set_t *op_set)
{
    variant_t var;
    OG_RETURN_IFERR(opr_text2dec(OP_RIGHT(op_set), &var));
    OP_RESULT(op_set)->type = OG_TYPE_NUMBER2;
    return cm_dec_add(&OP_LEFT(op_set)->v_dec, &var.v_dec, &OP_RESULT(op_set)->v_dec);
}

#define add_number2_char       add_number2_string
#define add_number2_varchar    add_number2_string
#define add_number2_binary     add_anytype_binary
#define add_number2_varbinary  add_number2_string

static inline status_t add_number2_timestamp_tz(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_LEFT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_RIGHT(op_set)->v_tstamp_tz.tz_offset;
    return cm_date_add_days(OP_RIGHT(op_set)->v_date, real, &OP_RESULT(op_set)->v_date);
}

OPR_DECL(add_number2_uint, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_int, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_bigint, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_real, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_number, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_number2_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_number2_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_number2_char, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_varchar, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_string, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_number2_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_number2_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_number2_binary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_number2_varbinary, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);


static inline status_t add_string_anytype(opr_operand_set_t *op_set)
{
    variant_t var = *OP_LEFT(op_set);
    variant_t *old_left = OP_LEFT(op_set);
    OG_RETURN_IFERR(var_as_decimal(&var));
    OP_LEFT(op_set) = &var;
    status_t status = opr_exec_add(op_set);
    OP_LEFT(op_set) = old_left;
    return status;
}

#define add_string_uint              add_string_anytype
#define add_string_int               add_string_anytype
#define add_string_bigint            add_string_anytype
#define add_string_real              add_string_anytype
#define add_string_number            add_string_anytype
#define add_string_number2           add_string_anytype
#define add_string_decimal           add_string_anytype
#define add_string_char              add_string_anytype
#define add_string_varchar           add_string_anytype
#define add_string_string            add_string_anytype
#define add_string_date              add_string_anytype
#define add_string_timestamp         add_string_anytype
#define add_string_timestamp_tz      add_string_anytype
#define add_string_timestamp_tz_fake add_string_anytype
#define add_string_timestamp_ltz     add_string_anytype
#define add_string_binary            add_anytype_binary
#define add_string_varbinary         add_string_anytype

OPR_DECL(add_string_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_string_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_string_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_string_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_string_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_string_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_string_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_string_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_string_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

#define add_binary_uint              add_binary_anytype
#define add_binary_int               add_binary_anytype
#define add_binary_bigint            add_binary_anytype
#define add_binary_real              add_binary_anytype
#define add_binary_number            add_binary_anytype
#define add_binary_number2           add_binary_anytype
#define add_binary_decimal           add_binary_anytype
#define add_binary_char              add_binary_anytype
#define add_binary_varchar           add_binary_anytype
#define add_binary_string            add_binary_anytype
#define add_binary_date              add_binary_anytype
#define add_binary_timestamp         add_binary_anytype
#define add_binary_timestamp_tz      add_binary_anytype
#define add_binary_timestamp_tz_fake add_binary_anytype
#define add_binary_timestamp_ltz     add_binary_anytype
#define add_binary_binary            add_binary_anytype
#define add_binary_varbinary         add_binary_anytype

OPR_DECL(add_binary_uint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_int, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_bigint, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_real, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_number, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_number2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2, OG_TYPE_NUMBER2);
OPR_DECL(add_binary_decimal, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL, OG_TYPE_DECIMAL);
OPR_DECL(add_binary_char, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_varchar, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_string, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_date, OG_TYPE_REAL, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_binary_timestamp, OG_TYPE_REAL, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_binary_timestamp_tz_fake, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_binary_timestamp_tz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_binary_timestamp_ltz, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_binary_binary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);
OPR_DECL(add_binary_varbinary, OG_TYPE_NUMBER, OG_TYPE_NUMBER, OG_TYPE_NUMBER);

static inline status_t add_date_uint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_days(OP_LEFT(op_set)->v_date, (double)OP_RIGHT(op_set)->v_uint32, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_date_int(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_days(OP_LEFT(op_set)->v_date, (double)OP_RIGHT(op_set)->v_int, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_date_bigint(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_days(OP_LEFT(op_set)->v_date, (double)OP_RIGHT(op_set)->v_bigint, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_date_real(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_days(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_real, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_date_number(opr_operand_set_t *op_set)
{
    double real = cm_dec_to_real(&OP_RIGHT(op_set)->v_dec);
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_days(OP_LEFT(op_set)->v_date, real, &OP_RESULT(op_set)->v_date);
}

#define add_date_decimal add_date_number
#define add_date_number2 add_date_number
#define add_date_string  add_anytype_string

#define add_date_char        add_date_string
#define add_date_varchar     add_date_string
#define add_date_binary      add_anytype_binary
#define add_date_varbinary   add_date_string

static inline status_t add_date_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_dsinterval(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_date_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_date_add_yminterval(OP_LEFT(op_set)->v_date, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_date);
}

OPR_DECL(add_date_uint, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_int, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_bigint, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_real, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_number, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_number2, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_decimal, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_char, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_varchar, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_string, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_interval_ym, OG_TYPE_DATE, OG_TYPE_INTERVAL_YM, OG_TYPE_DATE);
OPR_DECL(add_date_interval_ds, OG_TYPE_DATE, OG_TYPE_INTERVAL_DS, OG_TYPE_DATE);
OPR_DECL(add_date_binary, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);
OPR_DECL(add_date_varbinary, OG_TYPE_DATE, OG_TYPE_REAL, OG_TYPE_DATE);

static inline status_t add_timestamp_anytype(opr_operand_set_t *op_set)
{
    // set OP_LEFT variant's type to OG_TYPE_DATE, use operator functions of the type OG_TYPE_DATE
    OP_LEFT(op_set)->type = OG_TYPE_DATE;
    if (opr_exec_add(op_set) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // restore OP_LEFT variant's type
    OP_LEFT(op_set)->type   = OG_TYPE_TIMESTAMP;
    OP_RESULT(op_set)->type = OG_TYPE_TIMESTAMP;
    return OG_SUCCESS;
}

#define add_timestamp_uint         add_timestamp_anytype
#define add_timestamp_int          add_timestamp_anytype
#define add_timestamp_bigint       add_timestamp_anytype
#define add_timestamp_real         add_timestamp_anytype
#define add_timestamp_number       add_timestamp_anytype
#define add_timestamp_number2      add_timestamp_anytype
#define add_timestamp_decimal      add_timestamp_anytype
#define add_timestamp_char         add_timestamp_anytype
#define add_timestamp_varchar      add_timestamp_anytype
#define add_timestamp_string       add_timestamp_anytype
#define add_timestamp_interval_ym  add_timestamp_anytype
#define add_timestamp_interval_ds  add_timestamp_anytype
#define add_timestamp_binary       add_anytype_binary
#define add_timestamp_varbinary    add_timestamp_anytype

OPR_DECL(add_timestamp_uint, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_int, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_bigint, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_real, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_number, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_number2, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_decimal, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_char, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_varchar, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_string, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_interval_ym, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_interval_ds, OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_binary, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);
OPR_DECL(add_timestamp_varbinary, OG_TYPE_TIMESTAMP, OG_TYPE_REAL, OG_TYPE_TIMESTAMP);


static inline status_t add_timestamp_tz_anytype(opr_operand_set_t *op_set)
{
    // set OP_LEFT variant's type to OG_TYPE_DATE, use operator functions of the type OG_TYPE_DATE
    OP_LEFT(op_set)->type = OG_TYPE_DATE;
    if (opr_exec_add(op_set) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // restore OP_LEFT variant's type
    OP_LEFT(op_set)->type = OG_TYPE_TIMESTAMP_TZ;
    OP_RESULT(op_set)->type = OG_TYPE_TIMESTAMP_TZ;
    OP_RESULT(op_set)->v_tstamp_tz.tz_offset = OP_LEFT(op_set)->v_tstamp_tz.tz_offset;
    return OG_SUCCESS;
}

#define add_timestamp_tz_uint         add_timestamp_tz_anytype
#define add_timestamp_tz_int          add_timestamp_tz_anytype
#define add_timestamp_tz_bigint       add_timestamp_tz_anytype
#define add_timestamp_tz_real         add_timestamp_tz_anytype
#define add_timestamp_tz_number       add_timestamp_tz_anytype
#define add_timestamp_tz_number2      add_timestamp_tz_anytype
#define add_timestamp_tz_decimal      add_timestamp_tz_anytype
#define add_timestamp_tz_char         add_timestamp_tz_anytype
#define add_timestamp_tz_varchar      add_timestamp_tz_anytype
#define add_timestamp_tz_string       add_timestamp_tz_anytype
#define add_timestamp_tz_interval_ym  add_timestamp_tz_anytype
#define add_timestamp_tz_interval_ds  add_timestamp_tz_anytype
#define add_timestamp_tz_binary       add_anytype_binary
#define add_timestamp_tz_varbinary    add_timestamp_tz_anytype

OPR_DECL(add_timestamp_tz_uint, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_int, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_bigint, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_real, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_number, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_number2, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_decimal, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_char, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_varchar, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_string, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_interval_ym, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_interval_ds, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_binary, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_timestamp_tz_varbinary, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ);

static inline status_t add_timestamp_ltz_anytype(opr_operand_set_t *op_set)
{
    // set OP_LEFT variant's type to OG_TYPE_DATE, use operator functions of the type OG_TYPE_DATE
    OP_LEFT(op_set)->type = OG_TYPE_DATE;
    if (opr_exec_add(op_set) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // restore OP_LEFT variant's type
    OP_LEFT(op_set)->type = OG_TYPE_TIMESTAMP_LTZ;
    OP_RESULT(op_set)->type = OG_TYPE_TIMESTAMP_LTZ;
    return OG_SUCCESS;
}

#define add_timestamp_ltz_uint         add_timestamp_ltz_anytype
#define add_timestamp_ltz_int          add_timestamp_ltz_anytype
#define add_timestamp_ltz_bigint       add_timestamp_ltz_anytype
#define add_timestamp_ltz_real         add_timestamp_ltz_anytype
#define add_timestamp_ltz_number       add_timestamp_ltz_anytype
#define add_timestamp_ltz_number2      add_timestamp_ltz_anytype
#define add_timestamp_ltz_decimal      add_timestamp_ltz_anytype
#define add_timestamp_ltz_char         add_timestamp_ltz_anytype
#define add_timestamp_ltz_varchar      add_timestamp_ltz_anytype
#define add_timestamp_ltz_string       add_timestamp_ltz_anytype
#define add_timestamp_ltz_interval_ym  add_timestamp_ltz_anytype
#define add_timestamp_ltz_interval_ds  add_timestamp_ltz_anytype
#define add_timestamp_ltz_binary       add_anytype_binary
#define add_timestamp_ltz_varbinary    add_timestamp_ltz_anytype

OPR_DECL(add_timestamp_ltz_uint, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_int, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_bigint, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_real, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_number, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_number2, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_decimal, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_char, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_varchar, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_string, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_interval_ym, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_interval_ds, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_binary, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_timestamp_ltz_varbinary, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ);

static inline status_t add_interval_ds_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_dsinterval_add_date(OP_LEFT(op_set)->v_itvl_ds, OP_RIGHT(op_set)->v_date, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_interval_ds_timestamp(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_dsinterval_add_tmstamp(OP_LEFT(op_set)->v_itvl_ds, OP_RIGHT(op_set)->v_tstamp,
        &OP_RESULT(op_set)->v_tstamp);
}

#define add_interval_ds_timestamp_tz_fake    add_interval_ds_timestamp
#define add_interval_ds_timestamp_tz         add_interval_ds_timestamp
#define add_interval_ds_timestamp_ltz        add_interval_ds_timestamp

static inline status_t add_interval_ds_interval_ds(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_DS;
    return cm_dsinterval_add(OP_LEFT(op_set)->v_itvl_ds, OP_RIGHT(op_set)->v_itvl_ds, &OP_RESULT(op_set)->v_itvl_ds);
}

OPR_DECL(add_interval_ds_date, OG_TYPE_INTERVAL_DS, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_interval_ds_timestamp, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_interval_ds_timestamp_tz_fake, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_interval_ds_timestamp_tz, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_interval_ds_timestamp_ltz, OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_interval_ds_interval_ds, OG_TYPE_INTERVAL_DS, OG_TYPE_INTERVAL_DS, OG_TYPE_INTERVAL_DS);

static inline status_t add_interval_ym_date(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_DATE;
    return cm_yminterval_add_date(OP_LEFT(op_set)->v_itvl_ym, OP_RIGHT(op_set)->v_date, &OP_RESULT(op_set)->v_date);
}

static inline status_t add_interval_ym_timestamp(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OP_RIGHT(op_set)->type;
    return cm_yminterval_add_tmstamp(OP_LEFT(op_set)->v_itvl_ym, OP_RIGHT(op_set)->v_tstamp,
        &OP_RESULT(op_set)->v_tstamp);
}

#define add_interval_ym_timestamp_tz_fake add_interval_ym_timestamp
#define add_interval_ym_timestamp_tz      add_interval_ym_timestamp
#define add_interval_ym_timestamp_ltz     add_interval_ym_timestamp

static inline status_t add_interval_ym_interval_ym(opr_operand_set_t *op_set)
{
    OP_RESULT(op_set)->type = OG_TYPE_INTERVAL_YM;
    return cm_yminterval_add(OP_LEFT(op_set)->v_itvl_ym, OP_RIGHT(op_set)->v_itvl_ym, &OP_RESULT(op_set)->v_itvl_ym);
}

OPR_DECL(add_interval_ym_date, OG_TYPE_INTERVAL_YM, OG_TYPE_DATE, OG_TYPE_DATE);
OPR_DECL(add_interval_ym_timestamp, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP, OG_TYPE_TIMESTAMP);
OPR_DECL(add_interval_ym_timestamp_tz_fake, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_TIMESTAMP);
OPR_DECL(add_interval_ym_timestamp_tz, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_TZ, OG_TYPE_TIMESTAMP_TZ);
OPR_DECL(add_interval_ym_timestamp_ltz, OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_TIMESTAMP_LTZ);
OPR_DECL(add_interval_ym_interval_ym, OG_TYPE_INTERVAL_YM, OG_TYPE_INTERVAL_YM, OG_TYPE_INTERVAL_YM);

static opr_rule_t *g_add_oprs[VAR_TYPE_ARRAY_SIZE][VAR_TYPE_ARRAY_SIZE] = {
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_UINT32,            add_int_uint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_INTEGER,           add_int_int),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BIGINT,            add_int_bigint),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_REAL,              add_int_real),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER,            add_int_number),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_NUMBER2,           add_int_number2),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_DECIMAL,           add_int_decimal),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_DATE,              add_int_date),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_TIMESTAMP,         add_int_timestamp),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_CHAR,              add_int_char),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARCHAR,           add_int_varchar),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_STRING,            add_int_string),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_TIMESTAMP_TZ_FAKE, add_int_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_TIMESTAMP_TZ,      add_int_timestamp_tz),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_TIMESTAMP_LTZ,     add_int_timestamp_ltz),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_BINARY,            add_int_binary),
    __OPR_DEF(OG_TYPE_INTEGER, OG_TYPE_VARBINARY,         add_int_varbinary),

    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_UINT32,             add_uint_uint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_INTEGER,            add_uint_int),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BIGINT,             add_uint_bigint),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_REAL,               add_uint_real),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER,             add_uint_number),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_NUMBER2,            add_uint_number2),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_DECIMAL,            add_uint_decimal),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_DATE,               add_uint_date),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_TIMESTAMP,          add_uint_timestamp),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_CHAR,               add_uint_char),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARCHAR,            add_uint_varchar),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_STRING,             add_uint_string),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_uint_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_TIMESTAMP_TZ,       add_uint_timestamp_tz),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_TIMESTAMP_LTZ,      add_uint_timestamp_ltz),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_BINARY,             add_uint_binary),
    __OPR_DEF(OG_TYPE_UINT32, OG_TYPE_VARBINARY,          add_uint_varbinary),

    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_UINT32,             add_bigint_uint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_INTEGER,            add_bigint_int),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BIGINT,             add_bigint_bigint),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_REAL,               add_bigint_real),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER,             add_bigint_number),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_NUMBER2,            add_bigint_number2),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_DECIMAL,            add_bigint_decimal),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_DATE,               add_bigint_date),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_TIMESTAMP,          add_bigint_timestamp),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_CHAR,               add_bigint_char),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARCHAR,            add_bigint_varchar),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_STRING,             add_bigint_string),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_bigint_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_TIMESTAMP_TZ,       add_bigint_timestamp_tz),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_TIMESTAMP_LTZ,      add_bigint_timestamp_ltz),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_BINARY,             add_bigint_binary),
    __OPR_DEF(OG_TYPE_BIGINT, OG_TYPE_VARBINARY,          add_bigint_varbinary),

    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_UINT32,               add_real_uint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_INTEGER,              add_real_int),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BIGINT,               add_real_bigint),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_REAL,                 add_real_real),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER,               add_real_number),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_NUMBER2,              add_real_number2),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_DECIMAL,              add_real_decimal),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_DATE,                 add_real_date),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_TIMESTAMP,            add_real_timestamp),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_CHAR,                 add_real_char),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARCHAR,              add_real_varchar),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_STRING,               add_real_string),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ_FAKE,    add_real_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_TIMESTAMP_TZ,         add_real_timestamp_tz),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_TIMESTAMP_LTZ,        add_real_timestamp_ltz),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_BINARY,               add_real_binary),
    __OPR_DEF(OG_TYPE_REAL, OG_TYPE_VARBINARY,            add_real_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_UINT32,             add_number_uint),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_INTEGER,            add_number_int),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BIGINT,             add_number_bigint),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_REAL,               add_number_real),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER,             add_number_number),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_NUMBER2,            add_number_number2),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_DECIMAL,            add_number_decimal),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_DATE,               add_number_date),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_TIMESTAMP,          add_number_timestamp),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_CHAR,               add_number_char),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARCHAR,            add_number_varchar),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_STRING,             add_number_string),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_number_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_TIMESTAMP_TZ,       add_number_timestamp_tz),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_TIMESTAMP_LTZ,      add_number_timestamp_ltz),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_BINARY,             add_number_binary),
    __OPR_DEF(OG_TYPE_NUMBER, OG_TYPE_VARBINARY,          add_number_varbinary),

    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_UINT32,             add_number2_uint),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_INTEGER,            add_number2_int),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BIGINT,             add_number2_bigint),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_REAL,               add_number2_real),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER,             add_number2_number),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_NUMBER2,            add_number2_number2),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_DECIMAL,            add_number2_decimal),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_DATE,               add_number2_date),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_TIMESTAMP,          add_number2_timestamp),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_CHAR,               add_number2_char),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARCHAR,            add_number2_varchar),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_STRING,             add_number2_string),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_number2_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_TIMESTAMP_TZ,       add_number2_timestamp_tz),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_TIMESTAMP_LTZ,      add_number2_timestamp_ltz),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_BINARY,             add_number2_binary),
    __OPR_DEF(OG_TYPE_NUMBER2, OG_TYPE_VARBINARY,          add_number2_varbinary),

    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_UINT32,            add_number_uint),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_INTEGER,           add_number_int),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BIGINT,            add_number_bigint),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_REAL,              add_number_real),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER,            add_number_number),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_NUMBER2,           add_number_number2),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_DECIMAL,           add_number_decimal),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_DATE,              add_number_date),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_TIMESTAMP,         add_number_timestamp),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_CHAR,              add_number_char),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARCHAR,           add_number_varchar),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_STRING,            add_number_string),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_TIMESTAMP_TZ_FAKE, add_number_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_TIMESTAMP_TZ,      add_number_timestamp_tz),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_TIMESTAMP_LTZ,     add_number_timestamp_ltz),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_BINARY,            add_number_binary),
    __OPR_DEF(OG_TYPE_DECIMAL, OG_TYPE_VARBINARY,         add_number_varbinary),

    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_UINT32,               add_string_uint),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_INTEGER,              add_string_int),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BIGINT,               add_string_bigint),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_REAL,                 add_string_real),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER,               add_string_number),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_NUMBER2,              add_string_number2),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_DECIMAL,              add_string_decimal),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_CHAR,                 add_string_char),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARCHAR,              add_string_varchar),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_STRING,               add_string_string),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_DATE,                 add_string_date),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_TIMESTAMP,            add_string_timestamp),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_TIMESTAMP_TZ_FAKE,    add_string_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_TIMESTAMP_TZ,         add_string_timestamp_tz),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_TIMESTAMP_LTZ,        add_string_timestamp_ltz),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_BINARY,               add_string_binary),
    __OPR_DEF(OG_TYPE_CHAR, OG_TYPE_VARBINARY,            add_string_varbinary),

    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_UINT32,            add_string_uint),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_INTEGER,           add_string_int),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BIGINT,            add_string_bigint),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_REAL,              add_string_real),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER,            add_string_number),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_NUMBER2,           add_string_number2),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_DECIMAL,           add_string_decimal),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_CHAR,              add_string_char),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARCHAR,           add_string_varchar),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_STRING,            add_string_string),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_DATE,              add_string_date),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_TIMESTAMP,         add_string_timestamp),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_TIMESTAMP_TZ_FAKE, add_string_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_TIMESTAMP_TZ,      add_string_timestamp_tz),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_TIMESTAMP_LTZ,     add_string_timestamp_ltz),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_BINARY,            add_string_binary),
    __OPR_DEF(OG_TYPE_VARCHAR, OG_TYPE_VARBINARY,         add_string_varbinary),

    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_UINT32,             add_string_uint),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_INTEGER,            add_string_int),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BIGINT,             add_string_bigint),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_REAL,               add_string_real),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER,             add_string_number),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_NUMBER2,            add_string_number2),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_DECIMAL,            add_string_decimal),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_CHAR,               add_string_char),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARCHAR,            add_string_varchar),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_STRING,             add_string_string),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_DATE,               add_string_date),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_TIMESTAMP,          add_string_timestamp),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_string_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_TIMESTAMP_TZ,       add_string_timestamp_tz),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_TIMESTAMP_LTZ,      add_string_timestamp_ltz),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_BINARY,             add_string_binary),
    __OPR_DEF(OG_TYPE_STRING, OG_TYPE_VARBINARY,          add_string_varbinary),

    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_UINT32,             add_binary_uint),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_INTEGER,            add_binary_int),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BIGINT,             add_binary_bigint),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_REAL,               add_binary_real),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER,             add_binary_number),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_NUMBER2,            add_binary_number2),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_DECIMAL,            add_binary_decimal),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_CHAR,               add_binary_char),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARCHAR,            add_binary_varchar),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_STRING,             add_binary_string),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_DATE,               add_binary_date),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_TIMESTAMP,          add_binary_timestamp),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_binary_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_TIMESTAMP_TZ,       add_binary_timestamp_tz),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_TIMESTAMP_LTZ,      add_binary_timestamp_ltz),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_BINARY,             add_binary_binary),
    __OPR_DEF(OG_TYPE_BINARY, OG_TYPE_VARBINARY,          add_binary_varbinary),

    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_UINT32,             add_string_uint),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_INTEGER,            add_string_int),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BIGINT,             add_string_bigint),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_REAL,               add_string_real),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER,             add_string_number),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_NUMBER2,            add_string_number2),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_DECIMAL,            add_string_decimal),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_CHAR,               add_string_char),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARCHAR,            add_string_varchar),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_STRING,             add_string_string),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_DATE,               add_string_date),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_TIMESTAMP,          add_string_timestamp),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_string_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_TIMESTAMP_TZ,       add_string_timestamp_tz),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_TIMESTAMP_LTZ,      add_string_timestamp_ltz),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_BINARY,             add_string_binary),
    __OPR_DEF(OG_TYPE_VARBINARY, OG_TYPE_VARBINARY,          add_string_varbinary),

    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_UINT32,                  add_date_uint),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_INTEGER,                 add_date_int),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_BIGINT,                  add_date_bigint),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_REAL,                    add_date_real),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_NUMBER,                  add_date_number),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_NUMBER2,                 add_date_number2),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_DECIMAL,                 add_date_decimal),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_CHAR,                    add_date_char),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_VARCHAR,                 add_date_varchar),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_STRING,                  add_date_string),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_INTERVAL_YM,             add_date_interval_ym),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_INTERVAL_DS,             add_date_interval_ds),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_BINARY,                  add_date_binary),
    __OPR_DEF(OG_TYPE_DATE, OG_TYPE_VARBINARY,               add_date_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_UINT32,             add_timestamp_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_INTEGER,            add_timestamp_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_BIGINT,             add_timestamp_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_REAL,               add_timestamp_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_NUMBER,             add_timestamp_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_NUMBER2,            add_timestamp_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_DECIMAL,            add_timestamp_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_CHAR,               add_timestamp_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_VARCHAR,            add_timestamp_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_STRING,             add_timestamp_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_YM,        add_timestamp_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_INTERVAL_DS,        add_timestamp_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_BINARY,             add_timestamp_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP, OG_TYPE_VARBINARY,          add_timestamp_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_UINT32,      add_timestamp_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTEGER,     add_timestamp_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_BIGINT,      add_timestamp_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_REAL,        add_timestamp_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_NUMBER,      add_timestamp_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_NUMBER2,     add_timestamp_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_DECIMAL,     add_timestamp_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_CHAR,        add_timestamp_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_VARCHAR,     add_timestamp_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_STRING,      add_timestamp_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTERVAL_YM, add_timestamp_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_INTERVAL_DS, add_timestamp_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_BINARY,      add_timestamp_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ_FAKE, OG_TYPE_VARBINARY,   add_timestamp_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_UINT32,      add_timestamp_tz_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTEGER,     add_timestamp_tz_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_BIGINT,      add_timestamp_tz_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_REAL,        add_timestamp_tz_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_NUMBER,      add_timestamp_tz_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_NUMBER2,     add_timestamp_tz_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_DECIMAL,     add_timestamp_tz_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_CHAR,        add_timestamp_tz_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_VARCHAR,     add_timestamp_tz_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_STRING,      add_timestamp_tz_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_YM, add_timestamp_tz_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_INTERVAL_DS, add_timestamp_tz_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_BINARY,      add_timestamp_tz_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP_TZ, OG_TYPE_VARBINARY,   add_timestamp_tz_varbinary),

    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_UINT32,      add_timestamp_ltz_uint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTEGER,     add_timestamp_ltz_int),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_BIGINT,      add_timestamp_ltz_bigint),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_REAL,        add_timestamp_ltz_real),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_NUMBER,      add_timestamp_ltz_number),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_NUMBER2,     add_timestamp_ltz_number2),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_DECIMAL,     add_timestamp_ltz_decimal),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_CHAR,        add_timestamp_ltz_char),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_VARCHAR,     add_timestamp_ltz_varchar),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_STRING,      add_timestamp_ltz_string),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_YM, add_timestamp_ltz_interval_ym),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_INTERVAL_DS, add_timestamp_ltz_interval_ds),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_BINARY,      add_timestamp_ltz_binary),
    __OPR_DEF(OG_TYPE_TIMESTAMP_LTZ, OG_TYPE_VARBINARY,   add_timestamp_ltz_varbinary),

    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_DATE,               add_interval_ym_date),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP,          add_interval_ym_timestamp),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_interval_ym_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_TZ,       add_interval_ym_timestamp_tz),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_TIMESTAMP_LTZ,      add_interval_ym_timestamp_ltz),
    __OPR_DEF(OG_TYPE_INTERVAL_YM, OG_TYPE_INTERVAL_YM,        add_interval_ym_interval_ym),

    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_DATE,               add_interval_ds_date),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP,          add_interval_ds_timestamp),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_TZ_FAKE,  add_interval_ds_timestamp_tz_fake),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_TZ,       add_interval_ds_timestamp_tz),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_TIMESTAMP_LTZ,      add_interval_ds_timestamp_ltz),
    __OPR_DEF(OG_TYPE_INTERVAL_DS, OG_TYPE_INTERVAL_DS,        add_interval_ds_interval_ds),

};  // end g_addition_rules


status_t opr_exec_add(opr_operand_set_t *op_set)
{
    opr_rule_t *rule = g_add_oprs[OG_TYPE_I(OP_LEFT(op_set)->type)][OG_TYPE_I(OP_RIGHT(op_set)->type)];

    if (SECUREC_UNLIKELY(rule == NULL)) {
        OPR_THROW_ERROR("+", OP_LEFT(op_set)->type, OP_RIGHT(op_set)->type);
        return OG_ERROR;
    }

    return rule->exec(op_set);
}

status_t opr_type_infer_add(og_type_t left, og_type_t right, og_type_t *result)
{
    opr_rule_t *rule = g_add_oprs[OG_TYPE_I(left)][OG_TYPE_I(right)];

    if (rule != NULL) {
        *result = rule->rs_type;
        return OG_SUCCESS;
    }

    OPR_THROW_ERROR("+", left, right);
    return OG_ERROR;
}