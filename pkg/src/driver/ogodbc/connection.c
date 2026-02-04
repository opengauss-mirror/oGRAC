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
 * connection.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/connection.c
 */
#include "connection.h"
#include "cm_error.h"

static SQLRETURN handle_conn_error(HDBC *phdbc,
               environment_class *env,
               connection_class *conn,
               char	*msg)
{
    *phdbc = SQL_NULL_HDBC;
    env->error_msg = msg;
    env->err_sign = ENV_ERROR;
    free(conn);
    conn = NULL;
    return SQL_ERROR;
}

static void init_conn_info(connection_class *conn, environment_class *environment)
{
    conn->error_msg = NULL;
    conn->environment = environment;
    conn->err_sign = 0;
    conn->error_code = 0;
    conn->flag = 1;
}

SQLRETURN ograc_AllocConnect(SQLHENV henv, SQLHDBC *phdbc)
{
    ogconn_conn_t ctconn_conn;
    environment_class *environment = (environment_class *)henv;
    connection_class *conn = NULL;
    conn = (connection_class *)malloc(sizeof(connection_class));
    status_t status;

    if (henv == NULL || phdbc == NULL) {
        return SQL_INVALID_HANDLE;
    }
    if (!conn) {
        *phdbc = SQL_NULL_HDBC;
        environment->error_msg = "Couldn't allocate memory for connection object.";
        environment->err_sign = ENV_ERROR;
        return SQL_ERROR;
    }

    status = ogconn_alloc_conn(&ctconn_conn);
    if (status != OG_SUCCESS) {
        char *msg = "alloc connection handle error.";
        return handle_conn_error(phdbc, environment, conn, msg);
    }

    if (memset_s(&conn->connInfo, sizeof(ConnInfo), 0, sizeof(ConnInfo)) != 0) {
        char *msg = "clean up database info failed.";
        ogconn_free_conn(ctconn_conn);
        return handle_conn_error(phdbc, environment, conn, msg);
    }

    int is_autocommit = AUTO_COMMIT;
    status = ogconn_set_conn_attr(ctconn_conn, OGCONN_ATTR_AUTO_COMMIT, &is_autocommit, sizeof(int));
    if (status != OG_SUCCESS) {
        char *msg = "set autoCommit attribute failed.";
        ogconn_free_conn(ctconn_conn);
        return handle_conn_error(phdbc, environment, conn, msg);
    }

    init_conn_info(conn, environment);
    conn->ctconn_conn = ctconn_conn;
    *phdbc = conn;
    return SQL_SUCCESS;
}

static SQLRETURN set_conn_info(connection_class *conn, const SQLCHAR *name,
                        SQLSMALLINT nameLength, char *buf, size_t size)
{
    errno_t code;
    uint32 len = 0;

    if (name != NULL && name[0] != '\0') {
        len = (nameLength == SQL_NTS) ? (uint32)strlen((const char *)name) : nameLength;
        if (len >= size) {
            conn->err_sign = 1;
            conn->error_msg = "value is too long, create connection failed.";
            return SQL_ERROR;
        }

        code = memcpy_s(buf, len, name, len);
        if (code != 0) {
            conn->err_sign = 1;
            conn->error_msg = "secure C lib has throw an error.";
            return SQL_ERROR;
        }
        buf[len] = '\0';
    }
    return SQL_SUCCESS;
}

SQLRETURN ograc_connect(SQLHDBC ConnectionHandle,
                        const SQLCHAR *ServerName, SQLSMALLINT NameLength1,
                        const SQLCHAR *UserName, SQLSMALLINT NameLength2,
                        const SQLCHAR *Authentication, SQLSMALLINT NameLength3)
{
    connection_class *conn = (connection_class *)ConnectionHandle;
    ConnInfo *info = NULL;
    SQLRETURN retcode;

    if (ServerName == NULL) {
        conn->err_sign = 1;
        conn->error_msg = "The ServerName is NULL";
        return SQL_ERROR;
    }

    info = &conn->connInfo;
    if (memset_s(info, sizeof(ConnInfo), 0, sizeof(ConnInfo)) != 0) {
        conn->err_sign = 1;
        conn->error_msg = "secure C lib has throw an error.";
        return SQL_ERROR;
    }

    retcode = set_conn_info(conn, ServerName, NameLength1, info->dsn, sizeof(info->dsn));
    if (retcode != SQL_SUCCESS) {
        return retcode;
    }

    if (init_odbc_dsn(conn, info) != SQL_SUCCESS) {
        return SQL_ERROR;
    }

    retcode = set_conn_info(conn, UserName, NameLength2, info->username, sizeof(info->username));
    if (retcode != SQL_SUCCESS) {
        return retcode;
    }

    retcode = set_conn_info(conn, Authentication, NameLength3, info->password, sizeof(info->password));
    if (retcode != SQL_SUCCESS) {
        return retcode;
    }

    retcode = og_db_connect(conn, info);
    if (NULL != info->password) {
        memset_s(info->password, strlen(info->password), 0, strlen(info->password));
    }
    return retcode;
}

static SQLRETURN clean_up_info(connection_class *conn, size_t len)
{
    if (memset_s(&conn->connInfo, len, 0, len) != 0) {
        conn->err_sign = 1;
        conn->error_msg = "secure C lib has throw an error.";
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
}

SQLRETURN ograc_disconnect(connection_class *conn)
{
    ogconn_conn_t pconn;

    if (!conn) {
        conn->err_sign = 1;
        conn->error_msg = "Connection handle is invalid";
        return SQL_INVALID_HANDLE;
    }
    pconn = conn->ctconn_conn;
    ogconn_disconnect(pconn);
    conn->flag = 1;
    return clean_up_info(conn, sizeof(ConnInfo));
}

static column_param *get_col_param(statement *stmt, uint32 index, SQLPOINTER TargetValue)
{
    uint32 p = 0;
    column_param *col_param_temp = NULL;
    column_param *col_param = NULL;
    status_t status;

    while (p < stmt->param.count) {
        col_param_temp = (column_param *)cm_list_get(&stmt->param, p);
        if (col_param_temp->ptr == index) {
            return col_param_temp;
        }
        p++;
    }

    if (TargetValue != NULL) {
        status = cm_list_new(&stmt->param, (void **)&col_param);
        if (status != OGCONN_ERROR && col_param != NULL) {
            col_param->ptr = index;
        }
    }
    return col_param;
}

SQLRETURN ograc_bind_col(statement *stmt,
                         SQLUSMALLINT colIndex,
                         SQLSMALLINT ctype,
                         PTR dataPtr,
                         SQLLEN dataSize,
                         SQLLEN *buffPtr)
{
    column_param *col_param = NULL;
    uint32 index = colIndex - 1;
    uint32 ptr = 0;
    SQLLEN cal_len = 0;

    col_param = get_col_param(stmt, index, dataPtr);
    if (col_param != NULL) {
        if (dataPtr != NULL) {
            col_param->sql_type = ctype;
            col_param->value = dataPtr;
            col_param->size = buffPtr;
            cal_len = cal_len_of_sql_type(ctype);
            if (cal_len == 0) {
                col_param->col_len = dataSize;
            } else {
                col_param->col_len = cal_len;
            }
            ptr = colIndex - 1;
        } else {
            col_param->sql_type = SQL_C_CHAR;
            col_param->value = NULL;
            *(col_param->size) = 0;
            col_param->col_len = 0;
            ptr = col_param->ptr;
        }
        col_param->generate_result.result_size = 0;
        col_param->generate_result.sql_type = SQL_C_DEFAULT;
        col_param->generate_result.is_str = OG_FALSE;
        col_param->generate_result.is_col = OG_TRUE;
        col_param->generate_result.ptr = ptr;
        col_param->generate_result.is_recieved = OG_FALSE;
        col_param->generate_result.og_type = OGCONN_TYPE_UNKNOWN;
    }
    return SQL_SUCCESS;
}