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
 * ogsql_input_bind_param.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql_input_bind_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "ogsql.h"
#include "ogsql_input_bind_param.h"

static char **g_bind_param = NULL;

status_t ogsql_bind_param_init(uint32 param_count)
{
    uint32 i;

    if (param_count == 0) {
        return OG_SUCCESS;
    }

    if (param_count > OG_MAX_UINT32 / sizeof(char *)) {
        ogsql_printf("Bind params failed, ErrMsg: params count is too large.\n");
        return OG_ERROR;
    }

    g_bind_param = (char **)malloc(sizeof(char *) * param_count);
    if (g_bind_param == NULL) {
        ogsql_printf("Bind params failed, ErrMsg:Alloc memory for params failed.\n");
        return OG_ERROR;
    }

    for (i = 0; i < param_count; i++) {
        g_bind_param[i] = NULL;
    }
    return OG_SUCCESS;
}

void ogsql_bind_param_uninit(uint32 param_count)
{
    uint32 i;

    if (g_bind_param != NULL) {
        for (i = 0; i < param_count; i++) {
            if (g_bind_param[i] != NULL) {
                free(g_bind_param[i]);
                g_bind_param[i] = NULL;
            }
        }

        free(g_bind_param);
        g_bind_param = NULL;
    }
}

static uint32 ogsql_sql_get_bind_direction(text_t *confirm_text)
{
    if (cm_text_str_equal_ins(confirm_text, "in")) {
        return OGCONN_INPUT;
    } else if (cm_text_str_equal_ins(confirm_text, "out")) {
        return OGCONN_OUTPUT;
    } else if (cm_text_str_equal_ins(confirm_text, "in out")) {
        return OGCONN_INOUT;
    }

    return 0;
}

static ogconn_type_t ogsql_sql_get_bind_data_type(text_t *confirm_text)
{
    uint32 i;
    uint32 size;
    struct st_ctconn_datatype {
        char *name;
        ogconn_type_t type;
    } type_table[] = {
        { "CHAR",             OGCONN_TYPE_CHAR },
        { "VARCHAR",          OGCONN_TYPE_VARCHAR },
        { "STRING",           OGCONN_TYPE_STRING },
        { "INT",              OGCONN_TYPE_INTEGER },
        { "INTEGER",          OGCONN_TYPE_INTEGER },
        { "UINT32",           OGCONN_TYPE_UINT32 },
        { "INTEGER UNSIGNED", OGCONN_TYPE_UINT32 },
        { "BIGINT",           OGCONN_TYPE_BIGINT },
        { "REAL",             OGCONN_TYPE_REAL },
        { "DOUBLE",           OGCONN_TYPE_REAL },
        { "DATE",             OGCONN_TYPE_DATE },
        { "TIMESTAMP",        OGCONN_TYPE_TIMESTAMP },
        { "BLOB",             OGCONN_TYPE_STRING },
        { "CLOB",             OGCONN_TYPE_STRING },
        { "DECIMAL",          OGCONN_TYPE_DECIMAL },
        { "NUMBER",           OGCONN_TYPE_NUMBER },
        { "NUMBER2",          OGCONN_TYPE_NUMBER2 },
        { "BOOLEAN",          OGCONN_TYPE_BOOLEAN },
        { "BOOL",             OGCONN_TYPE_BOOLEAN },
        { "BINARY",           OGCONN_TYPE_BINARY },
        { "VARBINARY",        OGCONN_TYPE_VARBINARY },
        { "TEXT",             OGCONN_TYPE_STRING },
        { "LONGTEXT",         OGCONN_TYPE_STRING },
        { "LONG",             OGCONN_TYPE_STRING },
        { "BYTEA",            OGCONN_TYPE_STRING }
    };

    size = sizeof(type_table) / sizeof(struct st_ctconn_datatype);
    for (i = 0; i < size; i++) {
        if (cm_text_str_equal_ins(confirm_text, type_table[i].name)) {
            return type_table[i].type;
        }
    }

    return OGCONN_TYPE_UNKNOWN;
}

static status_t transform_hex(const unsigned char *str, uint64 *iret, uint32 len)
{
    unsigned char *ptr = (unsigned char *)str;
    for (uint32 i = 0; i < len; i++) {
        if (*ptr >= '0' && *ptr <= '9') {
            *iret = ((*iret) << 4) + ((*ptr) - '0');
        } else if (*ptr >= 'A' && *ptr <= 'F') {
            *iret = ((*iret) << 4) + (((*ptr) - 'A') + 10);
        } else if (*ptr >= 'a' && *ptr <= 'f') {
            *iret = ((*iret) << 4) + (((*ptr) - 'a') + 10);
        } else {
            return OG_ERROR;
        }
        ++ptr;
    }
    return OG_SUCCESS;
}

static status_t hex2int64(const unsigned char *str, int64 *res, uint32 len)
{
    uint64 iret = 0;
    OG_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (int64)iret;
    return OG_SUCCESS;
}

static status_t hex2uint32(const unsigned char *str, uint32 *res, uint32 len)
{
    uint64 iret = 0;
    OG_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (uint32)iret;
    return OG_SUCCESS;
}

static status_t hex2int32(const unsigned char *str, int32 *res, uint32 len)
{
    uint64 iret = 0;
    OG_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (int32)iret;
    return OG_SUCCESS;
}

static status_t hex2double(const unsigned char *str, double *res, uint32 len)
{
    uint64 iret = 0;
    OG_RETURN_IFERR(transform_hex(str, &iret, len));
    *res = (double)iret;
    return OG_SUCCESS;
}

static status_t is_hex_string(text_t *confirm_text, bool32 *isHex)
{
    *isHex = OG_FALSE;
    if (confirm_text->len < 3) {
        return OG_SUCCESS;
    }
    uint32 len = confirm_text->len;
    if (confirm_text->str[0] == 'X' && confirm_text->str[1] == '\'' && confirm_text->str[len - 1] == '\'') {
        len = len - 1;
    }

    if ((confirm_text->str[0] == '0' && confirm_text->str[1] == 'x') ||
        (confirm_text->str[0] == 'X' && confirm_text->str[1] == '\'' && confirm_text->str[len - 1] == '\'')) {
        uint32 i = 2;
        for (; i < len; i++) {
            if (!((confirm_text->str[i] >= '0' && confirm_text->str[i] <= '9') ||
                (confirm_text->str[i] >= 'a' && confirm_text->str[i] <= 'f') ||
                (confirm_text->str[i] >= 'A' && confirm_text->str[i] <= 'F'))) {
                ogsql_printf("Bind params failed, this param value format is not hexadecimal\n");
                return OG_ERROR;
            }
        }
        if (i == len) {
            *isHex = OG_TRUE;
        }
    }
    return OG_SUCCESS;
}

static void get_hex_string(text_t *confirm_text, unsigned char *res, uint32 res_len, uint32 *lenth)
{
    uint32 len = confirm_text->len;
    if ((confirm_text->str[0] == 'X' && confirm_text->str[1] == '\'' && confirm_text->str[len - 1] == '\'')) {
        len = confirm_text->len - 1;
    }

    uint32 pos = 0;
    for (uint32 i = 2; i < len && i - 2 < res_len; i++) {
        res[i - 2] = confirm_text->str[i];
        pos++;
    }
    *lenth = pos;
    return;
}

static status_t ogsql_bind_hex_number_value(ogconn_type_t data_type,
    text_t *confirm_text, char* bind_buffer, uint32 buff_size)
{
    unsigned char temp[OG_MAX_PARAM_LEN] = { 0 };
    uint32 len = 0;
    int64 res = 0;
    text_t text_value;

    switch (data_type) {
        case OGCONN_TYPE_BOOLEAN:
        case OGCONN_TYPE_INTEGER: {
            get_hex_string(confirm_text, temp, OG_MAX_PARAM_LEN, &len);
            return hex2int32(temp, (int32 *)bind_buffer, len);
        }
        case OGCONN_TYPE_UINT32: {
            get_hex_string(confirm_text, temp, OG_MAX_PARAM_LEN, &len);
            return hex2uint32(temp, (uint32 *)bind_buffer, len);
        }
        case OGCONN_TYPE_BIGINT: {
            get_hex_string(confirm_text, temp, OG_MAX_PARAM_LEN, &len);
            return hex2int64(temp, (int64 *)bind_buffer, len);
        }
        case OGCONN_TYPE_REAL: {
            get_hex_string(confirm_text, temp, OG_MAX_PARAM_LEN, &len);
            return hex2double(temp, (double *)bind_buffer, len);
        }
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_NUMBER2:
        default: {
            get_hex_string(confirm_text, temp, OG_MAX_PARAM_LEN, &len);
            OG_RETURN_IFERR(hex2int64(temp, &res, len));
        
            text_value.str = (char*)temp;
            text_value.len = 0;
            cm_bigint2text(res, &text_value);
            if (text_value.len <= 0) {
                return OG_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_s(bind_buffer, buff_size, text_value.str, text_value.len));
            bind_buffer[text_value.len] = '\0';
            return OG_SUCCESS;
        }
    }
}

static status_t ogsql_bind_check_boolean(text_t *confirm_text, char* bind_buffer, uint32 buff_size)
{
    if (cm_text_str_equal_ins(confirm_text, "TRUE")) {
        confirm_text->len = 1;
        confirm_text->str[confirm_text->len - 1] = '1';
        confirm_text->str[confirm_text->len] = '\0';
    }
    if (cm_text_str_equal_ins(confirm_text, "FALSE")) {
        confirm_text->len = 1;
        confirm_text->str[confirm_text->len - 1] = '0';
        confirm_text->str[confirm_text->len] = '\0';
    }
    num_errno_t err_no = cm_text2int_ex(confirm_text, (int32 *)bind_buffer);
    if (err_no != NERR_SUCCESS) {
        ogsql_printf("Convert text into boolean failed %s \n", cm_get_num_errinfo(err_no));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogsql_bind_normal_number_value(ogconn_type_t data_type,
    text_t *confirm_text, char* bind_buffer, uint32 buff_size)
{
    num_errno_t err_no;

    switch (data_type) {
        case OGCONN_TYPE_BOOLEAN:
            return ogsql_bind_check_boolean(confirm_text, bind_buffer, buff_size);
        case OGCONN_TYPE_INTEGER: {
            err_no = cm_text2int_ex(confirm_text, (int32 *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                ogsql_printf("Convert text into int failed %s \n", cm_get_num_errinfo(err_no));
                return OG_ERROR;
            }
            return OG_SUCCESS;
        }
        case OGCONN_TYPE_UINT32: {
            err_no = cm_text2uint32_ex(confirm_text, (uint32 *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                ogsql_printf("Convert text into uint32 failed %s \n", cm_get_num_errinfo(err_no));
                return OG_ERROR;
            }
            return OG_SUCCESS;
        }
        case OGCONN_TYPE_BIGINT: {
            err_no = cm_text2bigint_ex(confirm_text, (int64 *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                ogsql_printf("Convert text into bigint failed %s \n", cm_get_num_errinfo(err_no));
                return OG_ERROR;
            }
            return OG_SUCCESS;
        }
        case OGCONN_TYPE_REAL: {
            err_no = cm_text2real_ex(confirm_text, (double *)bind_buffer);
            if (err_no != NERR_SUCCESS) {
                ogsql_printf("Convert text into real failed %s \n", cm_get_num_errinfo(err_no));
                return OG_ERROR;
            }
            return OG_SUCCESS;
        }
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_NUMBER2:
        default: {
            if (buff_size < confirm_text->len) {
                return OG_ERROR;
            }
            MEMS_RETURN_IFERR(memcpy_s(bind_buffer, buff_size, confirm_text->str, confirm_text->len));
            bind_buffer[confirm_text->len] = '\0';
            return OG_SUCCESS;
        }
    }
}

static status_t ogsql_bind_one_param_number(ogconn_stmt_t stmt, uint32 i, ogconn_type_t data_type, text_t *confirm_text,
    uint32 direction)
{
    bool32 isHex = OG_FALSE;
    int32 bind_size = 0;

    OG_RETURN_IFERR(is_hex_string(confirm_text, &isHex));

    switch (data_type) {
        case OGCONN_TYPE_BOOLEAN:
        case OGCONN_TYPE_INTEGER:
            bind_size = sizeof(int32);
            break;
        case OGCONN_TYPE_UINT32:
            bind_size = sizeof(uint32);
            break;
        case OGCONN_TYPE_BIGINT:
            bind_size = sizeof(int64);
            break;
        case OGCONN_TYPE_REAL:
            bind_size = sizeof(double);
            break;
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_NUMBER2:
        default:
            bind_size = isHex ? OG_MAX_PARAM_LEN : (confirm_text->len + 1);
            break;
    }

    g_bind_param[i] = (char *)malloc(bind_size);
    OG_RETVALUE_IFTRUE(g_bind_param[i] == NULL, OG_ERROR);

    MEMS_RETURN_IFERR(memset_s(g_bind_param[i], bind_size, 0, bind_size));

    if (isHex) {
        OG_RETURN_IFERR(ogsql_bind_hex_number_value(data_type, confirm_text, g_bind_param[i], bind_size));
    } else {
        OG_RETURN_IFERR(ogsql_bind_normal_number_value(data_type, confirm_text, g_bind_param[i], bind_size));
    }

    return ogconn_bind_by_pos2(stmt, i, data_type, (void *)g_bind_param[i], bind_size, NULL, direction);
}

static status_t ogsql_bind_one_param_time(ogconn_stmt_t stmt, uint32 i, ogconn_type_t p_data_type, text_t *confirm_text,
                                         uint32 direction)
{
    status_t ret = OG_ERROR;
    char nlsbuf[MAX_NLS_PARAM_LENGTH];
    text_t fmt;
    ogconn_type_t data_type = p_data_type;

    switch (data_type) {
        case OGCONN_TYPE_DATE:
        case OGCONN_TYPE_TIMESTAMP:
            if (data_type == OGCONN_TYPE_DATE) {
                data_type = OGCONN_TYPE_NATIVE_DATE;
                ret = ogsql_nlsparam_geter(nlsbuf, NLS_DATE_FORMAT, &fmt);
                OG_RETURN_IFERR(ret);
            } else if (data_type == OGCONN_TYPE_TIMESTAMP) {
                ret = ogsql_nlsparam_geter(nlsbuf, NLS_TIMESTAMP_FORMAT, &fmt);
                OG_RETURN_IFERR(ret);
            }

            g_bind_param[i] = (char *)malloc(sizeof(date_t));
            if (g_bind_param[i] == NULL) {
                return OG_ERROR;
            }

            MEMS_RETURN_IFERR(memset_s(g_bind_param[i], sizeof(date_t), 0, sizeof(date_t)));

            if (cm_text2date(confirm_text, &fmt, (date_t *)g_bind_param[i]) != OG_SUCCESS) {
                ogsql_printf("Bind params[%u] failed, ErrMsg = date format is error, format must be %s.\n", i + 1,
                            fmt.str);  // because fmt.str is a const str
                return OG_ERROR;
            }

            if (ogconn_bind_by_pos2(stmt, i, data_type, (void *)g_bind_param[i], sizeof(date_t), NULL,
                                 direction) != OGCONN_SUCCESS) {
                ogsql_print_error(CONN);
                return OG_ERROR;
            }
            return OG_SUCCESS;
        default:
            return OG_ERROR;
    }
}

static status_t ogsql_bind_one_param_core(ogconn_stmt_t stmt, uint32 i, text_t *confirm_text, ogconn_type_t data_type,
                                         uint32 direction)
{
    status_t ret = OG_ERROR;

    switch (data_type) {
        case OGCONN_TYPE_CHAR:
        case OGCONN_TYPE_VARCHAR:
        case OGCONN_TYPE_BINARY:
        case OGCONN_TYPE_VARBINARY:
        case OGCONN_TYPE_STRING:  // end with '\0': paramLen=strlen(value)+1
            g_bind_param[i] = (char *)malloc(confirm_text->len + 1);
            if (g_bind_param[i] == NULL) {
                return OG_ERROR;
            }
            if (confirm_text->len != 0) {
                MEMS_RETURN_IFERR(memcpy_s(g_bind_param[i], confirm_text->len + 1, confirm_text->str,
                    confirm_text->len));
            }
            g_bind_param[i][confirm_text->len] = '\0';
            ret = ogconn_bind_by_pos2(stmt, i, data_type, (void *)g_bind_param[i], confirm_text->len + 1, NULL,
                direction);
            break;
        case OGCONN_TYPE_BLOB:
        case OGCONN_TYPE_CLOB:
        case OGCONN_TYPE_IMAGE:
            break;
        case OGCONN_TYPE_BOOLEAN:
        case OGCONN_TYPE_INTEGER:
        case OGCONN_TYPE_UINT32:
        case OGCONN_TYPE_BIGINT:
        case OGCONN_TYPE_REAL:
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_NUMBER2:
            ret = ogsql_bind_one_param_number(stmt, i, data_type, confirm_text, direction);
            break;
        case OGCONN_TYPE_DATE:
        case OGCONN_TYPE_TIMESTAMP:
            ret = ogsql_bind_one_param_time(stmt, i, data_type, confirm_text, direction);
            break;
        default:
            break;
    }
    
    return ret;
}

static status_t ogsql_bind_one_param(ogconn_stmt_t stmt, uint32 param_count)
{
    uint32 i;

    for (i = 0; i < param_count; i++) {
        char confirm[OG_MAX_PARAM_LEN + 1] = { 0 };
        text_t confirm_text;
        ogconn_type_t data_type = OGCONN_TYPE_UNKNOWN;
        int32 direction = OGCONN_INPUT;

        ogsql_printf("The %uth param:\n", i + 1);

        /* get parameter direction */
        ogsql_printf("Direction : ");
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Get parameter direction failed");
            return OG_ERROR;
        }

        cm_str2text_safe(confirm, (uint32)strlen(confirm), &confirm_text);
        cm_trim_text(&confirm_text);

        direction = ogsql_sql_get_bind_direction(&confirm_text);
        if (direction == OGCONN_TYPE_UNKNOWN) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Unknown parameter direction, must be in/out/in out");
            return OG_ERROR;
        }

        /* get parameter datatype */
        ogsql_printf("DataType : ");
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Get parameter DataType failed");
            return OG_ERROR;
        }

        cm_str2text_safe(confirm, (uint32)strlen(confirm), &confirm_text);
        cm_trim_text(&confirm_text);

        data_type = ogsql_sql_get_bind_data_type(&confirm_text);
        if (data_type == OGCONN_TYPE_UNKNOWN) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Don't support the input datatype");
            return OG_ERROR;
        }

        /* get parameter bind value */
        ogsql_printf("BindValue: ");
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "Get parameter BindValue failed");
            return OG_ERROR;
        }

        cm_str2text_safe(confirm, (uint32)strlen(confirm), &confirm_text);
        if (confirm_text.len >= OG_MAX_PARAM_LEN) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "BindVaule len must less than 128");
            return OG_ERROR;
        }

        if (confirm_text.len > 0) {
            confirm_text.len = confirm_text.len > 0 ? confirm_text.len - 1 : confirm_text.len;
            confirm_text.str[confirm_text.len] = '\0';
        }
        if (confirm_text.len == 0) {
            ogsql_printf("Bind params[%u] failed, ErrMsg = %s.\n", i + 1, "BindVaule len must more than 1");
            return OG_ERROR;
        }

        if (ogsql_bind_one_param_core(stmt, i, &confirm_text, data_type, direction) != OG_SUCCESS) {
            ogsql_printf("Bind params[%u] failed.\n", i + 1);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t ogsql_bind_params(ogconn_stmt_t stmt, uint32 param_count /* , uint32 *batch_count */)
{
    int32 ret;
    if (param_count == 0) {
        return OG_SUCCESS;
    }

    ogsql_printf("+-------------------------------------------------+\n");
    ogsql_printf("|                OGSQL Bind Param                  |\n");
    ogsql_printf("+-------------------------------------------------+\n");

    ret = ogsql_bind_one_param(stmt, param_count);
    if (ret != OG_SUCCESS) {
        ogsql_printf("Bind params failed.\n");
        return ret;
    }

    ogsql_printf("Bind params successfully.\n");
    return ret;
}

static bool32 ogsql_try_skip_comment(text_t *sql_text)
{
    char c1;
    char c2;

    if (sql_text->len <= 2) {
        return OG_FALSE;
    }

    if (sql_text->str[0] == '-' && sql_text->str[1] == '-') {
        sql_text->str += 2;
        sql_text->len -= 2;

        while (sql_text->len > 0) {
            c1 = *sql_text->str;
            sql_text->str++;
            sql_text->len--;
            if (c1 == '\n') {
                return OG_TRUE;
            }
        }

        return OG_TRUE;
    }

    if (sql_text->str[0] == '/' && sql_text->str[1] == '*') {
        sql_text->str += 2;
        sql_text->len -= 2;

        while (sql_text->len >= 2) {
            c1 = sql_text->str[0];
            c2 = sql_text->str[1];

            if (c1 == '*' && c2 == '/') {
                sql_text->str += 2;
                sql_text->len -= 2;
                return OG_TRUE;
            }

            sql_text->str++;
            sql_text->len--;
        }

        sql_text->len = 0;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static bool32 ogsql_try_skip_string(text_t *sql_text)
{
    char c;

    if (sql_text->str[0] != '\'') {
        return OG_FALSE;
    }

    sql_text->str++;
    sql_text->len--;

    while (sql_text->len > 0) {
        c = sql_text->str[0];
        sql_text->str++;
        sql_text->len--;
        if (c == '\'') {
            return OG_TRUE;
        }
    }

    return OG_TRUE;
}

uint32 ogsql_get_param_count(const char *sql)
{
    text_t sql_text;
    uint32 param_count = 0;

    cm_str2text((char *)sql, &sql_text);
    while (sql_text.len > 0) {
        if (ogsql_try_skip_comment(&sql_text)) {
            continue;
        }

        if (ogsql_try_skip_string(&sql_text)) {
            continue;
        }

        if (sql_text.str[0] != ':' && sql_text.str[0] != '?') {
            sql_text.str++;
            sql_text.len--;
            continue;
        }

        sql_text.str++;
        sql_text.len--;
        while (sql_text.len > 0) {
            if (!CM_IS_NAMING_LETER(*sql_text.str)) {
                break;
            }

            sql_text.str++;
            sql_text.len--;
        }

        ++param_count;
    }

    return param_count;
}

