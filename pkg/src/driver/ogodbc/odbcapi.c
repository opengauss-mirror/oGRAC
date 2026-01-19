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
 * odbcapi.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/odbcapi.c
 */
#include "statement.h"
#include "cm_spinlock.h"
#include "cm_date.h"

static SQLRETURN ograc_execute(statement *stmt);

static void __attribute__((constructor)) load_config(void)
{
    (void)load_odbc_config();
}

static void clean_env_handle(SQLHENV henv)
{
    environment_class *env = (environment_class *)henv;
    env->error_code = 0;
    env->error_msg = NULL;
    env->err_sign = 0;
}

static void clean_conn_handle(SQLHDBC hdbc)
{
    connection_class *conn = (connection_class *)hdbc;
    conn->error_msg = NULL;
    conn->error_code = 0;
    conn->err_sign = 0;
}

SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT HandleType, SQLHANDLE InputHandle, SQLHANDLE *OutputHandle)
{
    switch (HandleType) {
        case SQL_HANDLE_ENV:
            return ograc_AllocEnv(OutputHandle);
        case SQL_HANDLE_DBC:
            clean_env_handle(InputHandle);
            return ograc_AllocConnect(InputHandle, OutputHandle);
        case SQL_HANDLE_STMT:
            clean_conn_handle(InputHandle);
            return ograc_AllocStmt(InputHandle, OutputHandle);
        default:
            return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLAllocEnv(SQLHANDLE *phenv)
{
    return ograc_AllocEnv(phenv);
}

SQLRETURN SQL_API SQLAllocConnect(SQLHENV henv, SQLHDBC *phdbc)
{
    clean_env_handle(henv);
    return ograc_AllocConnect(henv, phdbc);
}

SQLRETURN SQL_API SQLAllocStmt(SQLHDBC hdbc, SQLHSTMT *phstmt)
{
    clean_conn_handle(hdbc);
    return ograc_AllocStmt(hdbc, phstmt);
}

SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV henv,
                                SQLINTEGER Attribute, SQLPOINTER ValuePtr,
                                SQLINTEGER StringLength)
{
    if (henv == NULL) {
        return SQL_INVALID_HANDLE;
    }
    clean_env_handle(henv);
    SQLRETURN ret;
    environment_class *env = (environment_class *)henv;
    switch (Attribute) {
        case SQL_ATTR_OUTPUT_NTS: {
            SQLINTEGER output_nts = (SQLINTEGER)(SQLLEN)ValuePtr;
            if (SQL_TRUE == output_nts) {
                ret = SQL_SUCCESS;
            } else {
                env->err_sign = ENV_ERROR;
                env->error_msg = "unsupported output nts version";
                return SQL_ERROR;
            }
            break;
        }
        case SQL_ATTR_ODBC_VERSION: {
            SQLINTEGER odbc_version = (SQLINTEGER)(SQLLEN)ValuePtr;
            if (odbc_version == SQL_OV_ODBC2) {
                env->version = odbc_version;
            } else {
                env->version = SQL_OV_ODBC3;
            }
            ret = SQL_SUCCESS;
            break;
        }
        default:
            env->err_sign = 1;
            env->error_msg = "SQLSetEnvAttr Attribute is not supported yet.";
            return SQL_ERROR;
    }
    return ret;
}

SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle)
{
    if (Handle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    switch (HandleType) {
        case SQL_HANDLE_ENV:
            clean_env_handle(Handle);
            environment_class *env = (environment_class *)Handle;
            free(env);
            env = NULL;
            break;
        case SQL_HANDLE_DBC:
            clean_conn_handle(Handle);
            connection_class *conn = (connection_class *)Handle;
            ogconn_free_conn(conn->ctconn_conn);
            free(conn);
            conn = NULL;
            break;
        case SQL_HANDLE_STMT: {
            statement *stmt = (statement *)Handle;
            connection_class *conn = stmt->conn;
            clean_conn_handle(conn);
            ograc_free_stmt(stmt);
            break;
        }
        default:
            return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLFreeConnect(SQLHDBC hdbc)
{
    connection_class *conn = (connection_class *)hdbc;

    if (hdbc == NULL) {
        return SQL_INVALID_HANDLE;
    }
    clean_conn_handle(hdbc);
    ogconn_free_conn(conn->ctconn_conn);
    free(conn);
    conn = NULL;
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLFreeEnv(SQLHENV henv)
{
    environment_class *env = (environment_class *)henv;

    if (henv == NULL) {
        return SQL_INVALID_HANDLE;
    }
    clean_env_handle(henv);
    free(env);
    env = NULL;
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLFreeStmt(SQLHSTMT StatementHandle, SQLUSMALLINT Option)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    ograc_free_stmt(stmt);
    return SQL_SUCCESS;
}

static void __attribute__((destructor)) close_config(void)
{
    close_odbc_config();
}

status_t set_conn_attr(connection_class *conn, SQLPOINTER Value, SQLINTEGER StringLength, int32 attr)
{
    int newValue = (SQLINTEGER)(SQLULEN)Value;
    if (newValue < 0) {
        return SQL_ERROR;
    } else if (newValue == 0) {
        newValue = -1;
    }
    return ogconn_set_conn_attr(conn->ctconn_conn, attr, &newValue, StringLength);
}

SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC ConnectionHandle,
                                    SQLINTEGER Attribute,
                                    SQLPOINTER ValuePtr,
                                    SQLINTEGER StringLength)
{
    connection_class *conn = (connection_class *)ConnectionHandle;
    if (ConnectionHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    clean_conn_handle(ConnectionHandle);
    int32 newValue;
    int32 ret;

    switch (Attribute) {
        case SQL_ATTR_AUTOCOMMIT:
            newValue = (SQLINTEGER)(SQLULEN)ValuePtr;
            ret = ogconn_set_conn_attr(conn->ctconn_conn, OGCONN_ATTR_AUTO_COMMIT, &newValue, StringLength);
            break;
        case SQL_ATTR_QUERY_TIMEOUT:
            ret = set_conn_attr(conn, ValuePtr, StringLength, OGCONN_ATTR_SOCKET_TIMEOUT);
            break;
        case SQL_ATTR_LOGIN_TIMEOUT:
            ret = set_conn_attr(conn, ValuePtr, StringLength, OGCONN_ATTR_CONNECT_TIMEOUT);
            break;
        case SQL_ATTR_CONNECTION_TIMEOUT:
            ret = set_conn_attr(conn, ValuePtr, StringLength, OGCONN_ATTR_SOCKET_TIMEOUT);
            break;
        default:
            CLT_THROW_ERROR((clt_conn_t *)(conn->ctconn_conn), ERR_CLT_INVALID_VALUE,
                             "connection attribute", Attribute);
            return SQL_ERROR;
    }

    if (ret != OG_SUCCESS) {
        get_err(conn);
        return SQL_ERROR;
    }
    return ret;
}

SQLRETURN SQL_API SQLConnect(SQLHDBC        ConnectionHandle,
                             SQLCHAR        *ServerName,
                             SQLSMALLINT    NameLength1,
                             SQLCHAR        *UserName,
                             SQLSMALLINT    NameLength2,
                             SQLCHAR        *Authentication,
                             SQLSMALLINT    NameLength3)
{
    if (ConnectionHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    clean_conn_handle(ConnectionHandle);
    return ograc_connect(ConnectionHandle, ServerName, NameLength1, UserName, NameLength2, Authentication, NameLength3);
}

SQLRETURN SQL_API SQLSetStmtAttr(SQLHSTMT StatementHandle,
                                 SQLINTEGER Attribute,
                                 SQLPOINTER ValuePtr,
                                 SQLINTEGER StringLength)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    return ograc_set_stmt_attr((statement *)StatementHandle, Attribute, ValuePtr, StringLength);
}

SQLRETURN ograc_prepare(statement *stmt, const SQLCHAR *text)
{
    status_t status;

    del_stmt_param(&stmt->params, SQL_TRUE);
    cm_reset_list(&(stmt->param));
    status = ogconn_prepare(stmt->ctconn_stmt, (const char *)text);
    if (status == OGCONN_SUCCESS) {
        stmt->stmt_flag = NOT_EXEC_STMT;
    }
    del_stmt_param(&stmt->params, SQL_FALSE);
    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

SQLLEN get_param_size(sql_input_data *input_data, uint32 offset)
{
    SQLLEN param_ptr = *(input_data->size + offset);

    if (param_ptr == SQL_DATA_AT_EXEC) {
        input_data->is_process = SQL_TRUE;
        return input_data->param_len;
    }
    if (param_ptr == SQL_NTS) {
        return strlen((const char *)input_data->param_value + input_data->param_len * offset);
    }

    if (param_ptr == SQL_DEFAULT_PARAM || param_ptr == SQL_NULL_DATA) {
        return OGCONN_NULL;
    }
    return param_ptr;
}

static SQLRETURN verify_param_ptr(statement *stmt, sql_input_data *input_data)
{
    uint32 index = 0;

    while (index < stmt->param_count) {
        input_data->param_size[index] = (unsigned short)get_param_size(input_data, index);
        index++;
    }
    return SQL_SUCCESS;
}

SQLRETURN set_sql_params(statement *stmt)
{
    bilist_t *param_list = &stmt->params;
    bilist_node_t *param = param_list->head;
    uint32 param_count;
    sql_input_data *input_data = NULL;
    SQLRETURN ret;

    int attr_res = ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_PARAMSET_SIZE,
                                        &param_count, sizeof(uint32), NULL);
    if (attr_res != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    
    stmt->param_count = param_count;
    while (param != NULL) {
        input_data = (sql_input_data *)((char *)param - OFFSET_OF(sql_input_data, data_list));
        param = param->next;
        if (input_data->param_flag != EXEC_PARAM || param_count != input_data->param_count) {
            clean_up_bind_param(input_data);
            input_data->param_count = param_count;
            ret = malloc_bind_param(input_data);
            if (ret != SQL_SUCCESS) {
                stmt->conn->err_sign = 1;
                stmt->conn->error_msg = "Couldn't allocate memory for stmt object.";
                return ret;
            }
            if (input_data->size != NULL) {
                ret = verify_param_ptr(stmt, input_data);
            }
            if (ret != SQL_SUCCESS) {
                return ret;
            }
            ret = bind_param_by_c_type(stmt, input_data);
            if (ret != SQL_SUCCESS) {
                return ret;
            }
            input_data->param_flag = EXEC_PARAM;
        }
    }
    return SQL_SUCCESS;
}

static void get_data_result(statement *stmt, SQLPOINTER *value, unsigned int col_num)
{
    uint32 index = 0;
    uint32 col_count = 0;
    og_generate_result *generate_result = NULL;

    while (col_count < col_num) {
        while (index < stmt->data_rows.count) {
            generate_result = (og_generate_result *)cm_list_get(&(stmt->data_rows), index);
            if (generate_result->ptr == col_count) {
                break;
            }
            index++;
        }
        
        if (stmt->data_rows.count != index) {
            col_count++;
            continue;
        }
        if (value != NULL) {
            *(unsigned int *)value = col_count + 1;
        }
        return;
    }
}

static SQLRETURN og_bind_param_execute(statement *stmt, SQLPOINTER *value)
{
    uint32 col_num;
    uint32 col_num_len = sizeof(col_num);
    og_generate_result *generate_result = NULL;
    status_t status;
    uint32 rows = stmt->data_rows.count;
    uint32 index = 0;

    while (index < rows) {
        generate_result = (og_generate_result *)cm_list_get(&(stmt->data_rows), index);
        if (generate_result->is_recieved == OG_TRUE) {
            index++;
            continue;
        }
        if (value != NULL) {
            *(unsigned int *)value = generate_result->ptr + 1;
        }
        return SQL_PARAM_DATA_AVAILABLE;
    }
    
    status = ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_COLUMN_COUNT, &col_num, sizeof(col_num), &col_num_len);
    if (status != OG_SUCCESS) {
        col_num = 0;
    }

    if (col_num > rows) {
        get_data_result(stmt, value, col_num);
        return SQL_PARAM_DATA_AVAILABLE;
    }
    return SQL_SUCCESS;
}

static SQLRETURN set_param_value(statement *stmt, bilist_t *params, SQLPOINTER *value, uint32 index)
{
    sql_input_data *input_data;

    input_data = generate_bind_param_instance(params->head, index);
    if (input_data == NULL) {
        stmt->conn->err_sign = 1;
        stmt->conn->error_msg = "the parameter value is NULL";
        return SQL_ERROR;
    }
    if (input_data->is_binded) {
        input_data->is_process = SQL_FALSE;
    }
    if (input_data->is_process == SQL_TRUE) {
        if (value != NULL) {
            *value = input_data->param_value;
        }
        return SQL_NEED_DATA;
    }
    return SQL_SUCCESS;
}

static SQLRETURN bind_param_value(statement *stmt, SQLPOINTER *value, uint32 process)
{
    uint32 index = 0;
    bilist_t *params = &(stmt->params);
    SQLRETURN ret;

    if (stmt->stmt_flag == NOT_EXEC_STMT) {
        while (index < stmt->params.count) {
            ret = set_param_value(stmt, params, value, index);
            if (ret != SQL_SUCCESS) {
                return ret;
            }
            index++;
        }
        if (process) {
            return ograc_execute(stmt);
        }
        return SQL_SUCCESS;
    }

    if (stmt->stmt_flag == EXEC_STMT) {
        return og_bind_param_execute(stmt, value);
    }
    return SQL_SUCCESS;
}

static SQLRETURN handle_number_convert_err(statement *stmt)
{
    stmt->conn->err_sign = 1;
    stmt->conn->error_msg = "failed to convert number to decimal type.";
    return SQL_ERROR;
}

static SQLRETURN transfer_dec_type(statement *stmt, SQL_NUMERIC_STRUCT *value, dec8_t *dec_value)
{
    dec8_t dec;
    dec8_t precision;
    dec8_t dec_fac;
    dec8_t dec_num;
    dec8_t num_mod;
    dec8_t dec_add;
    dec8_t suffix;
    dec8_t data_dec;
    dec8_t data_num;
    uint32 index = 0;
    uint8 radix = 10;
    int32 scale = (int32)value->scale;

    cm_zero_dec8(dec_value);
    if (value->precision == 0) {
        return SQL_SUCCESS;
    }
    cm_uint32_to_dec8(radix, &dec);
    cm_uint32_to_dec8(DECIMAL_MOD, &num_mod);
    cm_uint32_to_dec8(0, &dec_add);
    while (index < DECIMAL_SIZE) {
        if (value->val[index] != '\0') {
            cm_uint32_to_dec8(index, &suffix);
            cm_uint32_to_dec8((uint32)(value->val[index]), &data_dec);
            if (cm_dec8_power(&num_mod, &suffix, &precision) != OG_SUCCESS) {
                return handle_number_convert_err(stmt);
            }
            if (cm_dec8_multiply(&data_dec, &precision, &data_num) != OG_SUCCESS) {
                return handle_number_convert_err(stmt);
            }
            if (cm_dec8_add(&data_num, &dec_add, dec_value) != OG_SUCCESS) {
                return handle_number_convert_err(stmt);
            }
            dec_add = *dec_value;
        }
        index++;
    }

    cm_int32_to_dec8(-1 * scale, &dec_fac);
    if (cm_dec8_power(&dec, &dec_fac, &precision) != OG_SUCCESS) {
        return handle_number_convert_err(stmt);
    }

    if (cm_dec8_multiply(&dec_num, &precision, dec_value) != OG_SUCCESS) {
        return handle_number_convert_err(stmt);
    }

    if (value->sign == 0) {
        cm_dec8_negate(dec_value);
    }
    return SQL_SUCCESS;
}

typedef SQLRETURN (*transfer_number_func)(statement *stmt,
                                          sql_input_data *input_data,
                                          char *value,
                                          variant_t *data_struct);

typedef struct type_transfer_num_map {
    uint32 sql_c_type;
    transfer_number_func trans_func;
} transfer_num_map;

static SQLRETURN numeric_type_transfer(statement *stmt, sql_input_data *input_data,
                                       char *value, variant_t *data_struct)
{
    status_t status;
    dec8_t dec_data;
    SQLRETURN ret;

    ret = transfer_dec_type(stmt, (SQL_NUMERIC_STRUCT *)value, &dec_data);
    if (ret != SQL_SUCCESS) {
        stmt->conn->err_sign = 1;
        stmt->conn->error_msg = "invalid input numeric2 type.";
        return ret;
    }
    status = cm_dec8_scale(&dec_data, input_data->number, ROUND_TRUNC);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    cm_dec8_copy(&data_struct->v_dec, &dec_data);
    data_struct->type = OG_TYPE_NUMBER2;
    return SQL_SUCCESS;
}

static SQLRETURN float_type_transfer(statement *stmt, sql_input_data *input_data,
                                     char *value, variant_t *data_struct)
{
    status_t status;

    status = cm_real_to_dec8((double)*(float *)value, &data_struct->v_dec);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    data_struct->type = OG_TYPE_NUMBER2;

    status = cm_dec8_scale(&data_struct->v_dec, input_data->number, ROUND_TRUNC);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

static SQLRETURN int_type_transfer(statement *stmt, sql_input_data *input_data,
                                   char *value, variant_t *data_struct)
{
    data_struct->v_bigint = (int64) * (SQLINTEGER *)value;
    data_struct->type = OG_TYPE_BIGINT;
    return SQL_SUCCESS;
}

static SQLRETURN double_type_transfer(statement *stmt, sql_input_data *input_data,
                                      char *value, variant_t *data_struct)
{
    status_t status;

    status = cm_real_to_dec8(*(double *)value, &data_struct->v_dec);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    data_struct->type = OG_TYPE_NUMBER2;

    status = cm_dec8_scale(&data_struct->v_dec, input_data->number, ROUND_TRUNC);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

static SQLRETURN smallint_type_transfer(statement *stmt, sql_input_data *input_data,
                                        char *value, variant_t *data_struct)
{
    data_struct->v_int = (int32) * (short *)value;
    data_struct->type = OG_TYPE_INTEGER;
    return SQL_SUCCESS;
}

static SQLRETURN unsigned_tinyint_type_transfer(statement *stmt, sql_input_data *input_data,
                                                char *value, variant_t *data_struct)
{
    data_struct->v_int = (int32) * (unsigned char *)value;
    data_struct->type = OG_TYPE_INTEGER;
    return SQL_SUCCESS;
}

static SQLRETURN signed_bigint_type_transfer(statement *stmt, sql_input_data *input_data,
                                             char *value, variant_t *data_struct)
{
    data_struct->v_bigint = *(int64 *)value;
    data_struct->type = OG_TYPE_BIGINT;
    return SQL_SUCCESS;
}

static SQLRETURN unsigned_int_type_transfer(statement *stmt, sql_input_data *input_data,
                                            char *value, variant_t *data_struct)
{
    cm_uint64_to_dec8((uint64) * (SQLUINTEGER *)value, &data_struct->v_dec);
    data_struct->type = OG_TYPE_NUMBER2;
    return SQL_SUCCESS;
}

static SQLRETURN unsigned_bigint_type_transfer(statement *stmt, sql_input_data *input_data,
                                               char *value, variant_t *data_struct)
{
    cm_uint64_to_dec8(*(uint64 *)value, &data_struct->v_dec);
    data_struct->type = OG_TYPE_NUMBER2;
    return SQL_SUCCESS;
}

static SQLRETURN unsigned_smallint_type_transfer(statement *stmt, sql_input_data *input_data,
                                          char *value, variant_t *data_struct)
{
    data_struct->v_int = (int32) * (unsigned short *)value;
    data_struct->type = OG_TYPE_INTEGER;
    return SQL_SUCCESS;
}

static SQLRETURN tinyint_type_transfer(statement *stmt, sql_input_data *input_data,
                                char *value, variant_t *data_struct)
{
    data_struct->v_int = (int32) * (char *)value;
    data_struct->type = OG_TYPE_INTEGER;
    return SQL_SUCCESS;
}

transfer_num_map trans_map[] = {
    {SQL_C_NUMERIC, numeric_type_transfer},
    {SQL_C_LONG, int_type_transfer},
    {SQL_C_SLONG, int_type_transfer},
    {SQL_C_SHORT, smallint_type_transfer},
    {SQL_C_SSHORT, smallint_type_transfer},
    {SQL_C_FLOAT, float_type_transfer},
    {SQL_C_DOUBLE, double_type_transfer},
    {SQL_C_SBIGINT, signed_bigint_type_transfer},
    {SQL_C_UBIGINT, unsigned_bigint_type_transfer},
    {SQL_C_UTINYINT, unsigned_tinyint_type_transfer},
    {SQL_C_TINYINT, tinyint_type_transfer},
    {SQL_C_STINYINT, tinyint_type_transfer},
    {SQL_C_ULONG, unsigned_int_type_transfer},
    {SQL_C_USHORT, unsigned_smallint_type_transfer}
};

static SQLRETURN convert_param_to_decimal(statement *stmt, sql_input_data *input_data, uint32 pos)
{
    text_buf_t str;
    connection_class *conn = stmt->conn;
    str.max_size = OG_BUFF_SIZE;
    str.str = input_data->input_param[pos];
    str.len = 0;
    char *value = input_data->param_value + input_data->param_len * pos;
    SQLRETURN ret = SQL_ERROR;
    uint8 is_bind = OG_FALSE;
    variant_t *data_struct;
    data_struct = (variant_t *)malloc(sizeof(variant_t));
    int32 trans_map_count = sizeof(trans_map) / sizeof(transfer_num_map);
    transfer_number_func trans_func;

    for (int32 i = 0; i < trans_map_count; i++) {
        if (input_data->sql_type == trans_map[i].sql_c_type) {
            trans_func = trans_map[i].trans_func;
            is_bind = OG_TRUE;
            break;
        }
    }
    if (!is_bind) {
        stmt->conn->err_sign = 1;
        stmt->conn->error_msg = "bind C type is not supported yet.";
        return SQL_ERROR;
    }
    ret = trans_func(stmt, input_data, value, data_struct);
    if (ret != SQL_SUCCESS) {
        return ret;
    }
    if (var_as_string(NULL, data_struct, &str) != OG_SUCCESS) {
        conn->err_sign = 1;
        conn->error_msg = "failed to transfer variant to string";
        return SQL_ERROR;
    }
    uint32 text_len = data_struct->v_text.len;
    data_struct->v_text.str[text_len] = '\0';
    data_struct->is_null = SQL_FALSE;
    input_data->param_size[pos] = text_len;
    return ret;
}

static SQLRETURN get_date_err(statement *stmt)
{
    stmt->conn->err_sign = 1;
    stmt->conn->error_msg = "The value related to the date type is invalid.";
    return SQL_ERROR;
}

static SQLRETURN convert_sql_timestamp_to_ogdate(statement *stmt,
                                                 date_detail_t *value_detail,
                                                 sql_input_data *input_data,
                                                 char *value,
                                                 uint32 *fraction)
{
    TIMESTAMP_STRUCT *ts;
    uint32 frac_digits;
    uint8 pow_base = 10;
    uint8 digits_base = 9;
    uint32 digit_pow = (uint32)pow(pow_base, (digits_base - input_data->number));
    ts = (TIMESTAMP_STRUCT *)value;
    uint16 year = (uint16)ts->year;
    uint8 max_mon = 12;
    uint8 max_day = 31;
    uint8 max_hour = 23;
    uint8 max_min = 59;
    uint8 max_sec = 59;

    if (year < CM_MIN_YEAR || year > CM_MAX_YEAR) {
        return get_date_err(stmt);
    }
    value_detail->year = (uint16)ts->year;

    if (ts->month <= 0 || ts->month > max_mon) {
        return get_date_err(stmt);
    }
    value_detail->mon = (uint8)ts->month;

    if (ts->day <= 0 || ts->day > max_day) {
        return get_date_err(stmt);
    }
    value_detail->day = (uint8)ts->day;

    if (ts->hour < 0 || ts->hour > max_hour) {
        return get_date_err(stmt);
    }
    value_detail->hour = (uint8)ts->hour;

    if (ts->minute < 0 || ts->minute > max_min) {
        return get_date_err(stmt);
    }
    value_detail->min = (uint8)ts->minute;

    if (ts->second < 0 || ts->second > max_sec) {
        return get_date_err(stmt);
    }
    value_detail->sec = (uint8)ts->second;

    frac_digits = ts->fraction - ts->fraction % digit_pow;
    fraction = &frac_digits;
    return SQL_SUCCESS;
}

static SQLRETURN convert_sql_date_to_ogdate(statement *stmt, date_detail_t *value_detail, char *value)
{
    DATE_STRUCT *dt;
    dt = (DATE_STRUCT *)value;
    uint16 year = (uint16)dt->year;
    uint8 max_mon = 12;
    uint8 max_day = 31;

    if (year < CM_MIN_YEAR || year > CM_MAX_YEAR) {
        return get_date_err(stmt);
    }
    value_detail->year = (uint16)dt->year;

    if (dt->month <= 0 || dt->month > max_mon) {
        return get_date_err(stmt);
    }
    value_detail->mon = (uint8)dt->month;

    if (dt->day <= 0 || dt->day > max_day) {
        return get_date_err(stmt);
    }
    value_detail->day = (uint8)dt->day;
    return SQL_SUCCESS;
}

static SQLRETURN convert_param_to_timestamp(statement *stmt, sql_input_data *input_data, uint32 pos)
{
    char *value = input_data->param_value + input_data->param_len * pos;
    uint32 data_len = 0;
    uint32 fraction = 0;
    SQLRETURN ret = SQL_SUCCESS;
    status_t status;
    date_detail_t value_detail = {0};

    status_t attr = ogconn_get_conn_attr(stmt->conn->ctconn_conn,
                                         OGCONN_ATTR_TIMESTAMP_SIZE,
                                         &data_len,
                                         sizeof(data_len),
                                         NULL);
    if (attr != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    if (input_data->sql_type == SQL_C_DATE) {
        ret = convert_sql_date_to_ogdate(stmt, &value_detail, value);
    } else if (input_data->sql_type == SQL_C_TYPE_TIMESTAMP ||  input_data->sql_type == SQL_C_TIMESTAMP) {
        ret = convert_sql_timestamp_to_ogdate(stmt, &value_detail, input_data, value, &fraction);
    } else if (input_data->sql_type == SQL_C_ULONG) {
        cm_decode_time(*(time_t *)value, &value_detail);
    } else {
        stmt->conn->err_sign = 1;
        stmt->conn->error_msg = "bind c type is not supported yet.";
        return SQL_ERROR;
    }
    if (ret != SQL_SUCCESS) {
        return ret;
    }
    status = ogconn_datetime_construct(stmt->ctconn_stmt,
                                        (ogconn_datetime_t)&input_data->input_param[pos],
                                        OGCONN_TYPE_TIMESTAMP,
                                        value_detail.year,
                                        value_detail.mon,
                                        value_detail.day,
                                        value_detail.hour,
                                        value_detail.min,
                                        value_detail.sec,
                                        fraction,
                                        NULL,
                                        0);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    input_data->param_size[pos] = (uint16)data_len;
    return SQL_SUCCESS;
}

static SQLRETURN convert_db_type_data(statement *stmt, sql_input_data *input_data, uint32 pos)
{
    SQLRETURN ret = SQL_SUCCESS;

    switch (input_data->og_type) {
        case OGCONN_TYPE_DATE:
        case OGCONN_TYPE_TIMESTAMP:
        case OGCONN_TYPE_TIMESTAMP_TZ:
        case OGCONN_TYPE_TIMESTAMP_LTZ:
            ret = convert_param_to_timestamp(stmt, input_data, pos);
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_NUMBER2:
            ret = convert_param_to_decimal(stmt, input_data, pos);
        default:
            return SQL_SUCCESS;
    }
    return ret;
}

static SQLRETURN bind_param_convert(statement *stmt, sql_input_data *input_data)
{
    uint32 pos = 0;
    char *param;
    SQLLEN *param_ptr;

    while (pos < input_data->param_count) {
        if (input_data->param_type == OGCONN_OUTPUT) {
            continue;
        }
        SQLRETURN ret;
        if (input_data->size != NULL) {
            param = input_data->param_value + input_data->param_len * pos;
            param_ptr = input_data->size + pos;
            if (param == NULL || *param_ptr == SQL_NULL_DATA || *param_ptr == SQL_DEFAULT_PARAM) {
                ret = SQL_SUCCESS;
            }
        }
        if (ret != SQL_SUCCESS) {
            ret = convert_db_type_data(stmt, input_data, pos);
            if (ret != SQL_SUCCESS) {
                return ret;
            }
        }
        pos++;
    }
    return SQL_SUCCESS;
}

static SQLRETURN input_params_convert(statement *stmt)
{
    bilist_node_t *item_data = (&stmt->params)->head;
    SQLRETURN ret;
    sql_input_data *input_data = NULL;

    while (item_data != NULL) {
        input_data = (sql_input_data *)((char *)item_data - OFFSET_OF(sql_input_data, data_list));
        if (input_data->is_convert) {
            ret = bind_param_convert(stmt, input_data);
            if (ret != SQL_SUCCESS) {
                return ret;
            }
        }
        item_data = item_data->next;
    }
    return SQL_SUCCESS;
}

static SQLRETURN ograc_execute(statement *stmt)
{
    SQLRETURN ret;
    status_t status;
    uint32 input_num;
    uint32 row_count;
    uint32 total_param = 0;
    uint32 execute_flag = OGCONN_STMT_NONE;

    status = ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_STMT_TYPE, &execute_flag, sizeof(execute_flag), 0);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    status = ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_PARAM_COUNT, &input_num, sizeof(input_num), 0);
    if (status != OGCONN_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    if (execute_flag != OGCONN_STMT_EXPLAIN && input_num != stmt->params.count) {
        stmt->conn->err_sign = 1;
        stmt->conn->error_msg = "failed to execute because there are some parameters not binded";
        return SQL_ERROR;
    }

    ret = set_sql_params(stmt);
    if (ret != SQL_SUCCESS) {
        return ret;
    }
    if (SQL_NEED_DATA == bind_param_value(stmt, NULL, SQL_FALSE)) {
        return SQL_NEED_DATA;
    }
    ret = input_params_convert(stmt);
    if (ret != SQL_SUCCESS) {
        return ret;
    }

    status = ogconn_execute(stmt->ctconn_stmt);
    if (status == OGCONN_SUCCESS) {
        stmt->stmt_flag = EXEC_STMT;
        ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_OUTPARAM_COUNT, &total_param, sizeof(uint32), NULL);
        if (total_param != 0) {
            if (ogconn_fetch_outparam(stmt->ctconn_stmt, &row_count) == OG_SUCCESS) {
                ret = build_fetch_param(stmt, total_param);
            }
        }
        if (ret != SQL_SUCCESS) {
            return ret;
        }
    }
    if (status != OG_SUCCESS) {
        get_err(stmt->conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    SQLRETURN ret;

    clean_conn_handle(conn);
    ret = ograc_prepare(stmt, StatementText);
    if (ret != SQL_SUCCESS) {
        return ret;
    }
    return ograc_execute(stmt);
}

SQLRETURN SQL_API SQLPrepare(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength)
{
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;

    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    if (StatementText == NULL) {
        return SQL_ERROR;
    }
    clean_conn_handle(conn);
    return ograc_prepare(stmt, StatementText);
}

SQLRETURN SQL_API SQLExecute(SQLHSTMT StatementHandle)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    return ograc_execute(stmt);
}

SQLRETURN SQL_API SQLBindParameter(SQLHSTMT StatementHandle,
                                SQLUSMALLINT ParameterNumber,
                                SQLSMALLINT InputOutputType,
                                SQLSMALLINT ValueType,
                                SQLSMALLINT ParameterType,
                                SQLULEN ColumnSize,
                                SQLSMALLINT DecimalDigits,
                                SQLPOINTER ParameterValuePtr,
                                SQLLEN BufferLength,
                                SQLLEN *Strlen_or_IndPtr)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    SQLRETURN ret = ograc_sql_bind_param(stmt, ParameterNumber, InputOutputType, ValueType, ParameterType,
                                   ColumnSize, DecimalDigits, ParameterValuePtr, BufferLength, Strlen_or_IndPtr);
    return ret;
}

SQLRETURN SQL_API SQLDisconnect(SQLHDBC ConnectionHandle)
{
    if (ConnectionHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    clean_conn_handle(ConnectionHandle);
    return ograc_disconnect(ConnectionHandle);
}

SQLRETURN SQL_API SQLFetch(SQLHSTMT StatementHandle)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    return ograc_fetch_data(stmt);
}

SQLRETURN SQL_API SQLGetData(SQLHSTMT StatementHandle,
                             SQLUSMALLINT ColumnNumber,
                             SQLSMALLINT TargetType,
                             SQLPOINTER TargetValuePtr,
                             SQLLEN BufferLength,
                             SQLLEN *StrLen_or_IndPtr)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    return ograc_get_data(stmt, ColumnNumber, TargetType, TargetValuePtr, BufferLength, StrLen_or_IndPtr);
}

SQLRETURN SQL_API SQLBindCol(SQLHSTMT StatementHandle,
                             SQLUSMALLINT ColumnNumber,
                             SQLSMALLINT TargetType,
                             SQLPOINTER TargetValuePtr,
                             SQLLEN BufferLength,
                             SQLLEN *StrLen_or_Ind)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    if (ColumnNumber == 0) {
        return SQL_ERROR;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    return ograc_bind_col(stmt, ColumnNumber, TargetType, TargetValuePtr, BufferLength, StrLen_or_Ind);
}

SQLRETURN SQL_API SQLRowCount(SQLHSTMT StatementHandle, SQLLEN *RowCountPtr)
{
    int32 has_result = 0;
    uint32 count = 0;

    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    if (RowCountPtr == NULL) {
        return SQL_ERROR;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_RESULTSET_EXISTS, &has_result, sizeof(uint32), NULL);

    if (has_result) {
        ogconn_get_stmt_attr(stmt->ctconn_stmt, OGCONN_ATTR_FETCHED_ROWS, &count, sizeof(uint32), NULL);
    } else {
        count = ogconn_get_affected_rows(stmt->ctconn_stmt);
    }

    (*RowCountPtr) = (SQLLEN)count;
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLPutData(SQLHSTMT StatementHandle, SQLPOINTER DataPtr, SQLLEN StrLen_or_Ind)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    clean_conn_handle(conn);
    return ograc_put_data(stmt, DataPtr, StrLen_or_Ind);
}