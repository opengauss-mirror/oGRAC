/*
 * This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * convert.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/convert.c
 */
#include "convert.h"

static SQLRETURN handle_fetch_param(og_generate_result *generate_result, bind_input_param *input_param)
{
    generate_result->is_recieved = OG_TRUE;
    if (input_param->size != NULL) {
        *input_param->size = (SQLLEN)generate_result->result_size;
    }
    return SQL_SUCCESS;
}

static SQLRETURN handle_fetch_err(statement *stmt)
{
    stmt->conn->err_sign = 1;
    stmt->conn->error_msg = "Invalid string or buffer length";
    return SQL_ERROR;
}

static SQLRETURN handle_convert_err(statement *stmt)
{
    stmt->conn->err_sign = 1;
    stmt->conn->error_msg = "Failed to convert datatype";
    return SQL_ERROR;
}

static SQLRETURN get_c_char_type_param(statement *stmt,
                                       og_generate_result *generate_result,
                                       bind_input_param *input_param)
{
    status_t status;

    if (input_param->param_len <= 0) {
        return handle_fetch_err(stmt);
    }
    generate_result->is_str = OG_TRUE;
    if (generate_result->is_col) {
        status = ogconn_column_as_string(stmt->ctconn_stmt,
                                         generate_result->ptr,
                                         (char *)input_param->param_value,
                                         input_param->param_len);
    } else {
        status = ogconn_outparam_as_string_by_id(stmt->ctconn_stmt,
                                                 generate_result->ptr,
                                                 (char *)input_param->param_value,
                                                 input_param->param_len);
    }
    if (status == OG_SUCCESS) {
        generate_result->result_size = (uint32)strlen((char *)input_param->param_value);
        handle_fetch_param(generate_result, input_param);
    }
    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

static SQLRETURN get_db_lob_param(statement *stmt,
                                  og_generate_result *generate_result,
                                  bind_input_param *input_param,
                                  og_fetch_data_result *data_result)
{
    unsigned int param_buf;
    unsigned int nchars = 0;
    unsigned int nbytes = 0;
    status_t status;
    unsigned int flag = 0;
    unsigned int data_size;

    if (input_param->param_len <= 0) {
        return handle_fetch_err(stmt);
    }
    data_size = input_param->param_len;
    if (generate_result->is_str) {
        data_size = data_size - 1;
    }
    switch (data_result->og_type) {
        case OGCONN_TYPE_BLOB:
        case OGCONN_TYPE_IMAGE:
            status = ogconn_read_blob_by_id(stmt->ctconn_stmt, generate_result->ptr,
                                            generate_result->result_size,
                                            input_param->param_value, data_size,
                                            &nbytes, &flag);
            param_buf = nbytes;
            break;
        case OGCONN_TYPE_CLOB:
            status = ogconn_read_clob_by_id(stmt->ctconn_stmt, generate_result->ptr,
                                            generate_result->result_size,
                                            input_param->param_value, data_size,
                                            &nchars, &nbytes, &flag);
            param_buf = nchars;
            break;
        default:
            stmt->conn->err_sign = 1;
            stmt->conn->error_msg = "db data type decoding failed";
            return SQL_ERROR;
    }

    generate_result->result_size += nbytes;
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    if (param_buf < input_param->param_len && generate_result->is_str) {
        ((char *)input_param->param_value)[param_buf] = '\0';
    }
    if (input_param->size != NULL) {
        *input_param->size = (SQLLEN)param_buf;
    }
    if (flag) {
        generate_result->is_recieved = OG_TRUE;
        return SQL_SUCCESS;
    }
    if (input_param->size != NULL) {
        *input_param->size = (SQLLEN)SQL_NO_TOTAL;
    }
    return SQL_SUCCESS_WITH_INFO;
}

static SQLRETURN get_str_param(statement *stmt,
                               og_generate_result *generate_result,
                               bind_input_param *input_param,
                               og_fetch_data_result *data_result)
{
    unsigned int remaining_len;
    unsigned int actual_len;

    if (input_param->param_len <= 0) {
        return handle_fetch_err(stmt);
    }
    generate_result->is_str = OG_TRUE;
    remaining_len = data_result->len - generate_result->result_size;
    if (remaining_len >= input_param->param_len && generate_result->is_str) {
        actual_len = input_param->param_len - 1;
    } else if (remaining_len > input_param->param_len && !generate_result->is_str) {
        actual_len = input_param->param_len;
    } else {
        actual_len = remaining_len;
        generate_result->is_recieved = OG_TRUE;
    }

    if (actual_len > 0) {
        if (memcpy_s(input_param->param_value, input_param->param_len,
                    data_result->value + generate_result->result_size, actual_len) != 0) {
            stmt->conn->err_sign = 1;
            stmt->conn->error_msg = "secure C lib has throw an error.";
            return SQL_ERROR;
        }
    }

    if (input_param->size != NULL) {
        if (generate_result->is_recieved) {
            *input_param->size = (SQLLEN)actual_len;
        } else {
            *input_param->size = remaining_len;
        }
    }

    if (generate_result->is_str && input_param->param_len > actual_len) {
        ((char *)input_param->param_value)[actual_len] = 0;
    }
    generate_result->result_size = generate_result->result_size + actual_len;
    return SQL_SUCCESS;
}

static SQLRETURN get_c_wchar_type_param(statement *stmt,
                                    og_generate_result *generate_result,
                                    bind_input_param *input_param,
                                    og_fetch_data_result *data_result)
{
    char value[DECIMAL_MOD];
    unsigned int end = OG_FALSE;
    status_t status;
    int value_len;
    char *data = (char *)input_param->param_value;
    unsigned int input_size = (unsigned int)strlen((const char *)input_param->param_value);
    int param_size;

    generate_result->is_str = OG_TRUE;
    if (input_param->param_len <= sizeof(WCHAR)) {
        return handle_fetch_err(stmt);
    }
    if (generate_result->is_col) {
        status = ogconn_column_as_string(stmt->ctconn_stmt, generate_result->ptr, data,
                                      input_param->param_len);
    } else {
        status = ogconn_outparam_as_string_by_id(stmt->ctconn_stmt, generate_result->ptr,
                                              data, input_param->param_len);
    }
    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }

    param_size = ogconn_transcode_ucs2(stmt->ctconn_stmt, (void *)input_param->param_value,
                                     &input_size, (void *)value, DECIMAL_MOD, &end);
    if (param_size < 0) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }

    value_len = input_param->param_len - sizeof(SQLWCHAR);
    if (value_len < param_size) {
        param_size = value_len;
    }

    generate_result->result_size = param_size;
    if (memcpy_s(input_param->param_value, value_len, value, param_size) != 0) {
        stmt->conn->err_sign = 1;
        stmt->conn->error_msg = "secure C lib has throw an error.";
        return SQL_ERROR;
    }

    data[param_size] = '\0';
    data[param_size + 1] = '\0';
    handle_fetch_param(generate_result, input_param);
    return SQL_SUCCESS;
}

static SQLRETURN get_c_date_param(og_generate_result *generate_result,
                                  bind_input_param *input_param,
                                  og_fetch_data_result *data_result)
{
    date_detail_t detail;
    date_t date_input = *(date_t *)data_result->value;

    cm_decode_date(date_input, &detail);
    if (input_param->sql_type == SQL_C_TIME || input_param->sql_type == SQL_C_TYPE_TIME) {
        TIME_STRUCT *time_param = (TIME_STRUCT *)input_param->param_value;
        generate_result->result_size = (unsigned int)sizeof(TIME_STRUCT);
        time_param->hour = detail.hour;
        time_param->minute = detail.min;
        time_param->second = detail.sec;
    } else if (input_param->sql_type == SQL_C_DATE || input_param->sql_type == SQL_C_TYPE_DATE) {
        DATE_STRUCT *date_param = (DATE_STRUCT *)input_param->param_value;
        generate_result->result_size = (unsigned int)sizeof(DATE_STRUCT);
        date_param->year = detail.year;
        date_param->month = detail.mon;
        date_param->day = detail.day;
    } else {
        TIMESTAMP_STRUCT *timestamp_param = (TIMESTAMP_STRUCT *)input_param->param_value;
        generate_result->result_size = (unsigned int)sizeof(TIMESTAMP_STRUCT);
        timestamp_param->year = detail.year;
        timestamp_param->month = detail.mon;
        timestamp_param->day = detail.day;
        timestamp_param->hour = detail.hour;
        timestamp_param->minute = detail.min;
        timestamp_param->second = detail.sec;
        timestamp_param->fraction = ((SQLUINTEGER)detail.millisec) * NANOSECS_PER_MILLISEC
                                + ((SQLUINTEGER)detail.microsec) * NANOSECS_PER_MICROSEC;
    }
    return handle_fetch_param(generate_result, input_param);
}

static SQLRETURN handle_decimal_param_scale(dec8_t *param_t, SQL_NUMERIC_STRUCT *param_value)
{
    errno_t errcode;
    status_t power_status;
    status_t mul_status;
    status_t mod_status;
    status_t divide_status;
    status_t floor_status;
    dec8_t dec;
    dec8_t precision;
    dec8_t dec_fac;
    dec8_t mul_result;
    dec8_t dec_mod;
    dec8_t left_v;
    dec8_t ratio;
    SQLCHAR val;
    uint32 radix = 10;
    uint32 max_zero_num = 16;
    uint32 p = 0;

    errcode = memset_s(param_value->val, sizeof(param_value->val), 0, sizeof(param_value->val));
    if (errcode != 0) {
        return SQL_ERROR;
    }

    cm_uint32_to_dec8(param_value->scale, &precision);
    cm_uint32_to_dec8(radix, &dec);
    power_status = cm_dec8_power(&dec, &precision, &dec_fac);
    cm_dec8_abs(param_t);
    cm_uint32_to_dec8(DECIMAL_MOD, &dec_mod);
    mul_status = cm_dec8_multiply(param_t, &dec_fac, &mul_result);
    if (power_status != OG_SUCCESS || mul_status != OG_SUCCESS) {
        return SQL_ERROR;
    }
    while (mul_result.len != 1) {
        if (mul_result.head == ZERO_D8EXPN ||
            mul_result.head == NON_NEG_ZERO_D8EXPN ||
            mul_result.head == NEG_ZERO_D8EXPN) {
            break;
        }
        if (p >= max_zero_num) {
            break;
        }
        mod_status = cm_dec8_mod(&mul_result, &dec_mod, &left_v);
        divide_status = cm_dec8_divide(&mul_result, &dec_mod, &ratio);
        floor_status = cm_dec8_floor(&ratio);
        if (mod_status != OG_SUCCESS || divide_status != OG_SUCCESS || floor_status != OG_SUCCESS) {
            return SQL_ERROR;
        }
        mul_result = ratio;
        if (left_v.len == 1) {
            val = (SQLCHAR)0;
        } else {
            val = (SQLCHAR)left_v.cells[0];
        }
        param_value->val[p] = val;
        p++;
    }
    if (mul_result.len == 1 && (mul_result.head == ZERO_D8EXPN
                            || mul_result.head == NON_NEG_ZERO_D8EXPN
                            || mul_result.head == NEG_ZERO_D8EXPN)) {
        return SQL_SUCCESS;
    }
    return SQL_SUCCESS_WITH_INFO;
}

static SQLRETURN get_c_numeric_value(statement *stmt,
                                     og_generate_result *generate_result,
                                     dec8_t *numeric_value,
                                     bind_input_param *input_param)
{
    SQLRETURN ret;
    int32 num_count = 0;
    int8 dec_exp;
    int8 sign;
    int32 prec_count;
    SQL_NUMERIC_STRUCT *param_value;
    int32 prec_num = 10;
    int32 prec_val = CALC_PREC_SINGAL;
    uint8 dec_mod = numeric_value->len - 1;
    dec8_t param_t;
    cm_dec8_copy(&param_t, numeric_value);
    uint8 max_check = 10;
    uint8 expn_num = 8;
    uint8 len_offset = 2;

    param_value = input_param->param_value;
    param_value->scale = 0;
    param_value->sign = numeric_value->sign;
    param_value->precision = 0;
    if (dec_mod > 0) {
        while (prec_val >= max_check) {
            if (numeric_value->cells[0] / prec_val > 0) {
                break;
            }
            prec_val = prec_val / max_check;
            num_count++;
        }

        dec_exp = (!numeric_value->sign ? (NEG_ZERO_D8EXPN - numeric_value->head)
                                             : (numeric_value->head - NON_NEG_ZERO_D8EXPN));
        sign = dec_exp + 1;
        if (sign <= 0) {
            param_value->scale = param_value->precision;
        }
        while (prec_num <= CALC_PREC_SINGAL) {
            if (numeric_value->cells[numeric_value->len - len_offset] % prec_num > 0) {
                break;
            }
            prec_num = prec_num * max_check;
            prec_count++;
        }
        if (sign > 0 && sign < dec_mod) {
            param_value->scale = dec_mod * expn_num - prec_count - sign * expn_num;
        }
        if (sign > 0 && sign < dec_mod) {
            param_value->precision = dec_mod * expn_num - num_count - prec_count;
        } else if (sign <= 0) {
            param_value->precision = dec_mod * expn_num - prec_count + sign * (-1) * expn_num;
        } else {
            param_value->precision = sign * expn_num - num_count;
        }
    }

    ret = handle_decimal_param_scale(&param_t, param_value);
    if (ret != SQL_SUCCESS) {
        return handle_convert_err(stmt);
    }
    generate_result->result_size = (unsigned int)sizeof(SQL_NUMERIC_STRUCT);
    return handle_fetch_param(generate_result, input_param);
}

static SQLRETURN get_c_float_by_db_str(statement *stmt,
                                       og_generate_result *generate_result,
                                       bind_input_param *input_param,
                                       og_fetch_data_result *data_result)
{
    text_t src_data;
    src_data.str = data_result->value;
    src_data.len = data_result->len;
    double ex_data;
    double round_data;

    if (cm_text2real_ex(&src_data, &ex_data) != NERR_SUCCESS) {
        return handle_convert_err(stmt);
    }
    if (input_param->sql_type == SQL_C_FLOAT) {
        *(float *)input_param->param_value = (float)ex_data;
        generate_result->result_size = (uint32)sizeof(float);
    } else if (input_param->sql_type == SQL_C_LONG || input_param->sql_type == SQL_C_SLONG) {
        round_data = cm_round_real(ex_data, ROUND_HALF_UP);
        if (round_data > OG_MAX_INT32 || round_data < OG_MIN_INT32) {
            return handle_convert_err(stmt);
        }
        *(int *)input_param->param_value = (int)round_data;
        generate_result->result_size = (uint32)sizeof(int);
    } else {
        round_data = cm_round_real(ex_data, ROUND_HALF_UP);
        if (round_data > OG_MAX_INT16 || round_data < OG_MIN_INT16) {
            return handle_convert_err(stmt);
        }
        *(short *)input_param->param_value = (short)round_data;
        generate_result->result_size = (uint32)sizeof(short);
    }
    return handle_fetch_param(generate_result, input_param);
}

static SQLRETURN get_db_int_value(statement *stmt,
                                  og_generate_result *generate_result,
                                  bind_input_param *input_param,
                                  og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    int32 value;

    switch (input_param->sql_type) {
        case SQL_C_LONG:
        case SQL_C_SBIGINT:
        case SQL_C_SLONG:
            *(int *)input_param->param_value = *(int *)data_result->value;
            generate_result->result_size = (uint32)sizeof(int);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        case SQL_C_SHORT:
        case SQL_C_SSHORT:
        case SQL_C_TINYINT:
        case SQL_C_STINYINT:
            value = *(int *)data_result->value;
            if (value > OG_MAX_INT16 || value < OG_MIN_INT16) {
                return handle_convert_err(stmt);
            }
            *(short *)input_param->param_value = (short)value;
            generate_result->result_size = (uint32)sizeof(short);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_NUMERIC:
        case SQL_C_DOUBLE:
            *(double *)input_param->param_value = (double)(*(int *)data_result->value);
            generate_result->result_size = (uint32)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_FLOAT:
            *(float *)input_param->param_value = (float)(*(int *)data_result->value);
            generate_result->result_size = (uint32)sizeof(float);
            return handle_fetch_param(generate_result, input_param);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from int is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_uint_value(statement *stmt,
                                   og_generate_result *generate_result,
                                   bind_input_param *input_param,
                                   og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    uint32 value;

    switch (input_param->sql_type) {
        case SQL_C_LONG:
        case SQL_C_SBIGINT:
        case SQL_C_SLONG:
            value = *(uint32 *)data_result->value;
            if (value > OG_MAX_INT32) {
                return handle_convert_err(stmt);
            }
            *(int *)input_param->param_value = (int)value;
            generate_result->result_size = (uint32)sizeof(int);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        case SQL_C_SHORT:
        case SQL_C_SSHORT:
        case SQL_C_TINYINT:
        case SQL_C_STINYINT:
            value = *(uint32 *)data_result->value;
            if (value > OG_MAX_INT16) {
                return handle_convert_err(stmt);
            }
            *(short *)input_param->param_value = (short)value;
            generate_result->result_size = (uint32)sizeof(short);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_NUMERIC:
        case SQL_C_DOUBLE:
            *(double *)input_param->param_value = (double)(*(uint32 *)data_result->value);
            generate_result->result_size = (uint32)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_FLOAT:
            *(float *)input_param->param_value = (float)(*(uint32 *)data_result->value);
            generate_result->result_size = (uint32)sizeof(float);
            return handle_fetch_param(generate_result, input_param);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from uint is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_bool_value(statement *stmt,
                                   og_generate_result *generate_result,
                                   bind_input_param *input_param,
                                   og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    uint32 value;

    switch (input_param->sql_type) {
        case SQL_C_LONG:
        case SQL_C_SBIGINT:
        case SQL_C_SLONG:
            *(int *)input_param->param_value = (int)*(uint32 *)data_result->value;
            generate_result->result_size = (uint32)sizeof(int);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        case SQL_C_SHORT:
        case SQL_C_SSHORT:
        case SQL_C_TINYINT:
        case SQL_C_STINYINT:
            value = *(uint32 *)data_result->value;
            if (value > OG_MAX_INT16) {
                return handle_convert_err(stmt);
            }
            *(short *)input_param->param_value = (short)value;
            generate_result->result_size = (uint32)sizeof(short);
            return handle_fetch_param(generate_result, input_param);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from bool is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_bigint_value(statement *stmt,
                                     og_generate_result *generate_result,
                                     bind_input_param *input_param,
                                     og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    int64 value = *(int64 *)data_result->value;

    switch (input_param->sql_type) {
        case SQL_C_LONG:
        case SQL_C_SBIGINT:
        case SQL_C_SLONG:
            if (value > OG_MAX_INT32 || value < OG_MIN_INT32) {
                return handle_convert_err(stmt);
            }
            *(int *)(input_param->param_value)  = (int)value;
            generate_result->result_size = (uint32)sizeof(int);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        case SQL_C_SHORT:
        case SQL_C_SSHORT:
        case SQL_C_TINYINT:
        case SQL_C_STINYINT:
            if (value > OG_MAX_INT16 || value < OG_MIN_INT16) {
                return handle_convert_err(stmt);
            }
            *(short *)(input_param->param_value) = (short)value;
            generate_result->result_size = (uint32)sizeof(short);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_NUMERIC:
        case SQL_C_DOUBLE:
            *(double *)input_param->param_value = (double)(*(int64 *)data_result->value);
            generate_result->result_size = (uint32)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_FLOAT:
            *(float *)input_param->param_value = (float)(*(int64 *)data_result->value);
            generate_result->result_size = (uint32)sizeof(float);
            return handle_fetch_param(generate_result, input_param);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from bigint is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_real_value(statement *stmt,
                                   og_generate_result *generate_result,
                                   bind_input_param *input_param,
                                   og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;

    switch (input_param->sql_type) {
        case SQL_C_NUMERIC:
        case SQL_C_DOUBLE:
            *(double *)input_param->param_value = *(double *)data_result->value;
            generate_result->result_size = (uint32)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_FLOAT:
            *(float *)input_param->param_value = (float)*(double *)data_result->value;
            generate_result->result_size = (uint32)sizeof(float);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from real is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_number2_value(statement *stmt,
                                      og_generate_result *generate_result,
                                      bind_input_param *input_param,
                                      og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    dec2_t dec2;
    status_t status;
    dec8_t numeric_value;

    switch (input_param->sql_type) {
        case SQL_C_NUMERIC:
            status = cm_dec_2_to_8(&numeric_value, (const payload_t *)data_result->value, (uint8)data_result->len);
            if (status != OG_SUCCESS) {
                return SQL_ERROR;
            }
            return get_c_numeric_value(stmt, generate_result, &numeric_value, input_param);
        case SQL_C_FLOAT:
            cm_dec2_copy_ex(&dec2, (const payload_t *)data_result->value, (uint8)data_result->len);
            *(float *)input_param->param_value = (float)cm_dec2_to_real(&dec2);
            generate_result->result_size = (unsigned int)sizeof(float);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_DOUBLE:
            cm_dec2_copy_ex(&dec2, (const payload_t *)data_result->value, (uint8)data_result->len);
            *(double *)input_param->param_value = cm_dec2_to_real(&dec2);
            generate_result->result_size = (unsigned int)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from number2 is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_number_value(statement *stmt,
                                     og_generate_result *generate_result,
                                     bind_input_param *input_param,
                                     og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    dec4_t *number_value = (dec4_t *)data_result->value;
    status_t status;
    dec8_t number_value8;
    uint32 byte;

    switch (input_param->sql_type) {
        case SQL_C_NUMERIC:
            byte = ((uint32)(1 + number_value->ncells)) * sizeof(c4typ_t);
            status = cm_dec_4_to_8(&number_value8, number_value, byte);
            if (status != OG_SUCCESS) {
                return SQL_ERROR;
            }
            return get_c_numeric_value(stmt, generate_result, &number_value8, input_param);
        case SQL_C_FLOAT:
            *(float *)input_param->param_value = (float)cm_dec4_to_real((dec4_t *)data_result->value);
            generate_result->result_size = (unsigned int)sizeof(float);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_DOUBLE:
            *(double *)input_param->param_value = cm_dec4_to_real((dec4_t *)data_result->value);
            generate_result->result_size = (unsigned int)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from number is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_date_value(statement *stmt,
                                   og_generate_result *generate_result,
                                   bind_input_param *input_param,
                                   og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;

    switch (input_param->sql_type) {
        case SQL_C_DATE:
        case SQL_C_TYPE_DATE:
        case SQL_C_TIMESTAMP:
        case SQL_C_TYPE_TIMESTAMP:
        case SQL_C_TIME:
        case SQL_C_TYPE_TIME:
            return get_c_date_param(generate_result, input_param, data_result);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from date is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_raw_value(statement *stmt,
                                  og_generate_result *generate_result,
                                  bind_input_param *input_param,
                                  og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;

    switch (input_param->sql_type) {
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from raw is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_timestamp_value(statement *stmt,
                                        og_generate_result *generate_result,
                                        bind_input_param *input_param,
                                        og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;

    switch (input_param->sql_type) {
        case SQL_C_DATE:
        case SQL_C_TYPE_DATE:
        case SQL_C_TIMESTAMP:
        case SQL_C_TYPE_TIMESTAMP:
        case SQL_C_TIME:
        case SQL_C_TYPE_TIME:
            return get_c_date_param(generate_result, input_param, data_result);
        case SQL_C_CHAR:
            return get_c_char_type_param(stmt, generate_result, input_param);
        case SQL_C_WCHAR:
            return get_c_wchar_type_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from timestamp is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_clob_value(statement *stmt,
                                   og_generate_result *generate_result,
                                   bind_input_param *input_param,
                                   og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;

    switch (input_param->sql_type) {
        case SQL_C_CHAR:
        case SQL_C_WCHAR:
            generate_result->is_str = OG_TRUE;
            return get_db_lob_param(stmt, generate_result, input_param, data_result);
        case SQL_C_BINARY:
            return get_db_lob_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from clob is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_default_value(statement *stmt,
                                      og_generate_result *generate_result,
                                      bind_input_param *input_param,
                                      og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;

    switch (input_param->sql_type) {
        case SQL_C_CHAR:
        case SQL_C_WCHAR:
            return get_str_param(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_db_string_value(statement *stmt,
                                     og_generate_result *generate_result,
                                     bind_input_param *input_param,
                                     og_fetch_data_result *data_result)
{
    connection_class *conn = stmt->conn;
    text_t result_data;

    switch (input_param->sql_type) {
        case SQL_C_CHAR:
        case SQL_C_WCHAR:
            return get_str_param(stmt, generate_result, input_param, data_result);
        case SQL_C_DOUBLE:
            result_data.str = (char *)data_result->value;
            result_data.len = data_result->len;
            if (cm_text2real_ex(&result_data, (double *)input_param->param_value) != NERR_SUCCESS) {
                return handle_convert_err(stmt);
            }
            generate_result->result_size = (uint32)sizeof(double);
            return handle_fetch_param(generate_result, input_param);
        case SQL_C_LONG:
        case SQL_C_SLONG:
        case SQL_C_SHORT:
        case SQL_C_SSHORT:
        case SQL_C_FLOAT:
            return get_c_float_by_db_str(stmt, generate_result, input_param, data_result);
        default:
            conn->err_sign = 1;
            conn->error_msg = "conversion type from char is not supported.";
            return SQL_ERROR;
    }
}

static SQLRETURN get_fetch_param(statement *stmt,
                                 og_generate_result *generate_result,
                                 bind_input_param *input_param,
                                 og_fetch_data_result *data_result)
{
    generate_result->sql_type = input_param->sql_type;
    data_result->og_type = generate_result->og_type;

    switch (generate_result->og_type) {
        case OGCONN_TYPE_INTEGER:
            return get_db_int_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_UINT32:
            return get_db_uint_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_BOOLEAN:
            return get_db_bool_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_BIGINT:
            return get_db_bigint_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_REAL:
            return get_db_real_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_NUMBER2:
            return get_db_number2_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER:
            return get_db_number_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_RAW:
            return get_db_raw_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_DATE:
            return get_db_date_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_TIMESTAMP:
        case OGCONN_TYPE_TIMESTAMP_TZ_FAKE:
        case OGCONN_TYPE_TIMESTAMP_TZ:
        case OGCONN_TYPE_TIMESTAMP_LTZ:
            return get_db_timestamp_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_CLOB:
        case OGCONN_TYPE_BLOB:
            return get_db_clob_value(stmt, generate_result, input_param, data_result);
        case OGCONN_TYPE_CHAR:
        case OGCONN_TYPE_VARCHAR:
        case OGCONN_TYPE_STRING:
            return get_db_string_value(stmt, generate_result, input_param, data_result);
        default:
            return get_db_default_value(stmt, generate_result, input_param, data_result);
    }
    return SQL_SUCCESS;
}

SQLRETURN build_fetch_param(statement *stmt, uint32 total_param)
{
    uint32 param_len;
    char *fetch_value = NULL;
    sql_input_data *input_data = NULL;
    int32 index = 0;
    og_generate_result generate_result;
    bind_input_param input_param;
    og_fetch_data_result fetch_result;
    ogconn_outparam_desc_t outparam_info;
    bilist_t *params = &stmt->params;
    SQLRETURN ret;
    uint32 has_param;
    uint32 p = 0;
    status_t status;

    while (p < stmt->params.count) {
        input_data = generate_bind_param_instance(params->head, p);
        if (input_data == NULL || input_data->param_type == OGCONN_INPUT) {
            continue;
        }
        if (total_param <= index) {
            break;
        }
        input_param.sql_type = input_data->sql_type;
        input_param.param_value = input_data->param_value;
        input_param.param_len = input_data->param_len;
        input_param.size = input_data->size;
        status = ogconn_desc_outparam_by_id(stmt->ctconn_stmt, index, &outparam_info);
        if (status != OGCONN_SUCCESS) {
            get_err(stmt->conn);
            return SQL_ERROR;
        }
        status = ogconn_get_outparam_by_id(stmt->ctconn_stmt, index, (void **)&fetch_value, &param_len, &has_param);
        if (status != OGCONN_SUCCESS) {
            get_err(stmt->conn);
            return SQL_ERROR;
        }
        index = index + 1;
        if (has_param || param_len == 0) {
            continue;
        }
        fetch_result.value = fetch_value;
        fetch_result.len = param_len;
        generate_result.ptr = input_data->index;
        generate_result.result_size = 0;
        generate_result.sql_type = SQL_C_CHAR;
        generate_result.is_recieved = OG_FALSE;
        generate_result.is_str = OG_FALSE;
        generate_result.field_name = outparam_info.name;
        generate_result.og_type = outparam_info.type;
        generate_result.is_col = OG_FALSE;
        ret = get_fetch_param(stmt, &generate_result, &input_param, &fetch_result);
        if (ret != SQL_SUCCESS) {
            return ret;
        }
        p++;
    }

    return SQL_SUCCESS;
}

SQLRETURN ograc_sql_bind_param(statement *stmt,
                               SQLUSMALLINT param_num,
                               SQLSMALLINT input_type,
                               SQLSMALLINT value_type,
                               SQLSMALLINT param_type,
                               SQLULEN column_len,
                               SQLSMALLINT dec_number,
                               SQLPOINTER value_ptr,
                               SQLLEN buf_size,
                               SQLLEN *str_size)
{
    sql_input_data *input_data = NULL;
    uint32 data_len = 0;
    uint32 data_total = 0;
    SQLULEN param_len = 0;
    status_t status;
    ogconn_type_t og_type;
    uint32 size;

    if (param_num <= 0 || (value_ptr == NULL && str_size == NULL)) {
        return SQL_ERROR;
    }

    input_data = build_bind_param(&(stmt->params), (param_num - 1));
    if (input_data == NULL) {
        return SQL_INVALID_HANDLE;
    }

    input_data->param_value = value_ptr;
    input_data->size = str_size;
    input_data->number = dec_number;
    og_type = sql_type_map_to_db_type(param_type);
    if (og_type == OGCONN_TYPE_UNKNOWN) {
        return SQL_ERROR;
    }

    input_data->og_type = og_type;
    if (value_type == SQL_C_DEFAULT) {
        value_type = db_type_map_to_c_type(og_type);
    }
    input_data->sql_type = value_type;
    switch (input_type) {
        case SQL_PARAM_INPUT:
            input_data->param_type = OGCONN_INPUT;
            break;
        case SQL_PARAM_OUTPUT:
            input_data->param_type = OGCONN_OUTPUT;
            break;
        case SQL_PARAM_INPUT_OUTPUT:
            input_data->param_type = OGCONN_INOUT;
            break;
        default:
            return SQL_ERROR;
    }
    if (stmt->stmt_flag == INIT_STMT) {
        input_data->param_flag = INIT_PARAM;
    } else if (stmt->stmt_flag == NOT_EXEC_STMT) {
        input_data->param_flag = NOT_EXEC_PARAM;
    } else {
        input_data->param_flag = FREE_PARAM;
    }

    size = (uint32)sizeof(int);
    status = ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_PARAMSET_SIZE, &data_len, size, &size);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    if (data_len == 0) {
        return SQL_ERROR;
    }

    input_data->param_count = data_len;
    param_len = cal_column_len(value_type, column_len, buf_size, value_ptr, str_size);
    input_data->param_len = param_len;
    input_data->is_convert = OG_FALSE;
    input_data->is_process = OG_FALSE;
    input_data->is_binded = OG_FALSE;
    if (value_ptr == NULL) {
        for (uint32 i = 0; i < data_len; i++) {
            if (str_size[i] != SQL_NULL_DATA && str_size[i] != SQL_DATA_AT_EXEC
                && str_size[i] != SQL_DEFAULT_PARAM) {
                return SQL_ERROR;
            }
        }
    }

    input_data->param_stream = NULL;
    input_data->param_offset = 0;
    status = ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_PARAM_COUNT, &data_total, sizeof(data_total), NULL);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    if (input_data->index >= data_total) {
        return SQL_SUCCESS;
    }
    if (bind_param_by_c_type(stmt, input_data) != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

static SQLRETURN get_fetch_data(statement *stmt,
                                og_generate_result *generate_result,
                                bind_input_param *input_param)
{
    uint32 data_len;
    uint32 has_data;
    og_fetch_data_result data_result;
    void *value = NULL;
    ogconn_inner_column_desc_t column_info;
    status_t status;

    if (ogconn_get_column_by_id(stmt->ctconn_stmt, generate_result->ptr,
                                &value, &data_len, &has_data) != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    if (has_data || data_len <= 0) {
        if (input_param->size != NULL) {
            *(input_param->size) = has_data ? SQL_NULL_DATA : 0;
        }
        if (input_param->param_value != NULL) {
            *(char*)input_param->param_value = 0;
        }
        generate_result->is_recieved = OG_TRUE;
        return SQL_SUCCESS;
    }
    if (generate_result->og_type == OGCONN_TYPE_UNKNOWN) {
        status = ogconn_desc_inner_column_by_id(stmt->ctconn_stmt, generate_result->ptr, &column_info);
        if (status != OG_SUCCESS) {
            get_err(stmt->conn);
            return SQL_ERROR;
        }
        generate_result->col_label = column_info.name;
        generate_result->og_type = column_info.type;
    }

    data_result.value = value;
    data_result.len = data_len;
    return get_fetch_param(stmt, generate_result, input_param, &data_result);
}

static SQLRETURN fetch_data_and_bind_col(statement *stmt, SQLULEN fetch_pos)
{
    column_param *col_param;
    char *item_buf;
    pointer_t ptr;
    bind_input_param input_param;
    uint32 p = 0;
    SQLRETURN ret;
    list_t *param_list = &(stmt->param);

    while (p < param_list->count) {
        item_buf = (char *)param_list->extents[p / param_list->extent_step];
        ptr = item_buf + (p % param_list->extent_step) * param_list->item_size;
        col_param = (column_param *)ptr;

        if (col_param->value != NULL) {
            input_param.sql_type = col_param->sql_type;
            input_param.param_value = col_param->value + col_param->col_len * fetch_pos;
            input_param.param_len = col_param->col_len;
            input_param.size = col_param->size + fetch_pos;
            col_param->generate_result.is_recieved = OG_FALSE;
            col_param->generate_result.result_size = 0;
            ret = get_fetch_data(stmt, &col_param->generate_result, &input_param);
            if (ret != SQL_SUCCESS) {
                return ret;
            }
        }
        p++;
    }
    return SQL_SUCCESS;
}

SQLRETURN ograc_fetch_data(statement *stmt)
{
    uint32 num;
    uint32 param_count;
    int32 status;
    SQLRETURN ret;
    uint32 total_param = 0;
    uint32 p = 0;
    uint32 fetch_num = stmt->data_num;

    cm_reset_list(&(stmt->data_rows));
    stmt->rows = 0;
    ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_OUTPARAM_COUNT, &total_param, sizeof(uint32), NULL);
    if (total_param != 0) {
        ogconn_fetch_outparam(stmt->ctconn_stmt, &param_count);
        ret = build_fetch_param(stmt, total_param);
        if (ret != SQL_SUCCESS) {
            return ret;
        }
    }

    while (p < fetch_num) {
        status = ogconn_fetch(stmt->ctconn_stmt, &num);
        stmt->rows += num;
        if (status != OG_SUCCESS) {
            get_err(stmt->conn);
            return SQL_ERROR;
        }
        if (num == 0) {
            ret = SQL_NO_DATA;
        } else {
            ret = fetch_data_and_bind_col(stmt, p);
        }
        if (p != 0 && ret == SQL_NO_DATA) {
            break;
        }
        if (ret != SQL_SUCCESS) {
            return ret;
        }
        p++;
    }
    return SQL_SUCCESS;
}

SQLRETURN ograc_get_data(statement *stmt,
                         SQLUSMALLINT col_num,
                         SQLSMALLINT ctype,
                         SQLPOINTER data,
                         SQLLEN buf_size,
                         SQLLEN *strlen)
{
    bind_input_param input_param;
    og_generate_result *generate_result = NULL;
    og_generate_result *generate_result_temp = NULL;
    uint32 p = 0;
    uint32 data_num = stmt->data_rows.count;

    if (data == NULL || col_num == 0) {
        return SQL_ERROR;
    }
    while (p < data_num) {
        generate_result_temp = (og_generate_result *)cm_list_get(&stmt->data_rows, p);
        if (generate_result_temp->ptr == (uint32)(col_num - 1)) {
            generate_result = generate_result_temp;
            break;
        }
        p++;
    }
    if (generate_result == NULL) {
        if (cm_list_new(&(stmt->data_rows), (void **)&generate_result) != OG_ERROR) {
            generate_result->ptr = (uint32)(col_num - 1);
            generate_result->og_type = OGCONN_TYPE_CHAR;
            generate_result->sql_type = SQL_C_CHAR;
            generate_result->is_recieved = OG_FALSE;
            generate_result->result_size = 0;
            generate_result->is_str = OG_FALSE;
            generate_result->is_col = OG_TRUE;
        }
    }

    input_param.size = strlen;
    input_param.param_value = data;
    input_param.sql_type = ctype;
    input_param.param_len = buf_size;
    if (generate_result == NULL) {
        return SQL_INVALID_HANDLE;
    }
    if (generate_result->is_recieved == OG_TRUE) {
        return SQL_NO_DATA;
    }
    return get_fetch_data(stmt, generate_result, &input_param);
}

static status_t write_data(statement *stmt, sql_input_data *input_data, SQLPOINTER data, SQLLEN size)
{
    status_t status;
    uint32 remain_len = (unsigned int)size;
    uint32 nchars = 0;
    uint32 os_len = 0;

    switch (input_data->og_type) {
        case OGCONN_TYPE_CLOB:
            status = ogconn_write_clob(stmt->ctconn_stmt, input_data->index, data, remain_len, &nchars);
            if (status != OG_SUCCESS) {
                return status;
            }
            os_len = nchars;
        default:
            if (size == 0 || input_data->param_stream == NULL) {
                return OG_SUCCESS;
            }
            if (memcpy_s(input_data->param_stream + input_data->param_offset, remain_len, data, remain_len) != 0) {
                stmt->conn->err_sign = 1;
                stmt->conn->error_msg = "secure C lib has throw an error.";
                return SQL_ERROR;
            }
            os_len = remain_len;
    }
    input_data->param_offset += os_len;
    return OG_SUCCESS;
}

SQLRETURN ograc_put_data(statement *stmt, SQLPOINTER data, SQLLEN size)
{
    sql_input_data *input_data = NULL;
    bilist_t *datas = &(stmt->params);
    uint32 index = 0;
    uint32 param_num = datas->count;
    status_t status = OG_SUCCESS;

    while (index < param_num) {
        input_data = generate_bind_param_instance(datas->head, index);
        if (input_data == NULL) {
            continue;
        }
        if (input_data->param_value == data || input_data->is_process == SQL_TRUE) {
            break;
        }
        index++;
    }
    
    if (input_data == NULL) {
        return SQL_ERROR;
    }
    if (data != NULL && size != 0) {
        status = write_data(stmt, input_data, data, size);
    }
    if (status == OG_SUCCESS) {
        input_data->is_binded = SQL_TRUE;
    }
    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}