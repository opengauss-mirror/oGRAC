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

#include "cm_spinlock.h"
#include "cm_date.h"
#include "execute.h"

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
        case SQL_HANDLE_ENV: {
            environment_class *env = (environment_class *)Handle;
            clean_env_handle(Handle);
            free(env);
            env = NULL;
            break;
        }
        case SQL_HANDLE_DBC: {
            connection_class *conn = (connection_class *)Handle;
            clean_conn_handle(Handle);
            ogconn_free_conn(conn->ctconn_conn);
            free(conn);
            conn = NULL;
            break;
        }
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

SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC ConnectionHandle,
                                    SQLINTEGER Attribute,
                                    SQLPOINTER ValuePtr,
                                    SQLINTEGER StringLength)
{
    if (ConnectionHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    connection_class *conn = (connection_class *)ConnectionHandle;
    clean_conn_handle(ConnectionHandle);
    int32 newValue = 0;
    status_t status;

    switch (Attribute) {
        case SQL_ATTR_AUTOCOMMIT:
            newValue = (SQLINTEGER)(SQLULEN)ValuePtr;
            status = ogconn_set_conn_attr(conn->ctconn_conn, OGCONN_ATTR_AUTO_COMMIT, &newValue, StringLength);
            break;
        case SQL_ATTR_QUERY_TIMEOUT:
            status = set_conn_attr(conn, ValuePtr, StringLength, OGCONN_ATTR_SOCKET_TIMEOUT);
            break;
        case SQL_ATTR_LOGIN_TIMEOUT:
            status = set_conn_attr(conn, ValuePtr, StringLength, OGCONN_ATTR_CONNECT_TIMEOUT);
            break;
        case SQL_ATTR_CONNECTION_TIMEOUT:
            status = set_conn_attr(conn, ValuePtr, StringLength, OGCONN_ATTR_SOCKET_TIMEOUT);
            break;
        default:
            CLT_THROW_ERROR((clt_conn_t *)(conn->ctconn_conn), ERR_CLT_INVALID_VALUE,
                             "connection attribute", Attribute);
            return SQL_ERROR;
    }

    if (status != OG_SUCCESS) {
        get_err(conn);
        return SQL_ERROR;
    }
    return SQL_SUCCESS;
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

SQLRETURN SQL_API SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
    SQLRETURN retcode;

    clean_conn_handle(conn);
    retcode = ograc_prepare(stmt, StatementText);
    if (retcode != SQL_SUCCESS) {
        return retcode;
    }
    return ograc_execute(stmt);
}

SQLRETURN SQL_API SQLPrepare(SQLHSTMT StatementHandle, SQLCHAR *StatementText, SQLINTEGER TextLength)
{
    if (StatementHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    if (StatementText == NULL) {
        return SQL_ERROR;
    }
    statement *stmt = (statement *)StatementHandle;
    connection_class *conn = stmt->conn;
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
    return ograc_sql_bind_param(stmt, ParameterNumber, InputOutputType, ValueType, ParameterType,
                                ColumnSize, DecimalDigits, ParameterValuePtr, BufferLength, Strlen_or_IndPtr);
}

SQLRETURN SQL_API SQLDisconnect(SQLHDBC ConnectionHandle)
{
    if (ConnectionHandle == NULL) {
        return SQL_INVALID_HANDLE;
    }
    connection_class *conn = (connection_class *)ConnectionHandle;
    clean_conn_handle(ConnectionHandle);
    return ograc_disconnect(conn);
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