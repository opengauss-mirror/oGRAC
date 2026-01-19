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
 * statement.c
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/statement.c
 */
#include "statement.h"

static statement *stmt_constructor(connection_class *conn)
{
    statement *stmt;
    stmt = (statement *)malloc(sizeof(statement));
    if (stmt) {
        stmt->conn = conn;
        stmt->data_num = 1;
        stmt->rows = 0;
        stmt->param_count = 1;
    }
    return stmt;
}

static void init_column(list_t *list, uint32 item_size)
{
    list->extent_step = LIST_STEP;
    list->max_extents = LIST_RANGE;
    list->item_size = item_size;
    list->extent_count = 0;
    list->capacity = 0;
    list->count = 0;
    list->extents = NULL;
}

SQLRETURN ograc_AllocStmt(SQLHDBC hdbc, SQLHSTMT *phstmt)
{
    connection_class *conn = (connection_class *)hdbc;
    ogconn_conn_t ctconn_conn = conn->ctconn_conn;
    uint32 col_size = sizeof(column_param);
    uint32 generate_result_size = sizeof(og_generate_result);
    bilist_t *param_list;
    ogconn_stmt_t ctconn_stmt;
    statement *stmt;

    if (hdbc == NULL || phstmt == NULL) {
        return SQL_INVALID_HANDLE;
    }

    stmt = stmt_constructor(conn);
    if (!stmt) {
        *phstmt = SQL_NULL_HSTMT;
        conn->error_msg = "Couldn't allocate memory for statement object.";
        conn->err_sign = STMT_ERROR;
        return SQL_ERROR;
    }

    status_t alloc_stmt_ret = ogconn_alloc_stmt(ctconn_conn, &ctconn_stmt);
    stmt->ctconn_stmt = ctconn_stmt;
    if (alloc_stmt_ret != OG_SUCCESS) {
        *phstmt = SQL_NULL_HSTMT;
        conn->error_msg = "alloc statement failed.";
        conn->err_sign = STMT_ERROR;
        free(stmt);
        stmt = NULL;
        return SQL_ERROR;
    }

    *phstmt = (HSTMT)stmt;
    param_list = &stmt->params;
    param_list->count = 0;
    param_list->head = param_list->tail = NULL;
    init_column(&stmt->param, col_size);
    init_column(&stmt->data_rows, generate_result_size);
    return SQL_SUCCESS;
}

void ograc_free_stmt(statement *stmt)
{
    sql_input_data *input_data = NULL;
    bilist_t *params = &stmt->params;
    bilist_node_t *item_param = NULL;

    ogconn_free_stmt(stmt->ctconn_stmt);
    cm_reset_list(&stmt->data_rows);
    while (params->count != 0) {
        item_param = stmt->params.head;
        input_data = (sql_input_data *)((char *)item_param - OFFSET_OF(sql_input_data, data_list));
        clean_up_param(item_param, &stmt->params, input_data);
    }
    cm_reset_list(&stmt->param);
    stmt->ctconn_stmt = NULL;
    free(stmt);
    stmt = NULL;
}

SQLRETURN ograc_set_stmt_attr(statement *stmt,
                              SQLINTEGER    attr,
                              SQLPOINTER    value,
                              SQLINTEGER    strlen)
{
    SQLULEN newvalue = (SQLULEN)value;

    switch (attr) {
        case SQL_ATTR_QUERY_TIMEOUT:
            if (newvalue == 0) {
                newvalue = -1;
            }
            connection_class *conn = stmt->conn;
            return ogconn_set_conn_attr(conn->ctconn_conn, OGCONN_ATTR_SOCKET_TIMEOUT, &newvalue, strlen);
        case SQL_ATTR_PARAMSET_SIZE:
            return ogconn_set_stmt_attr(stmt->ctconn_stmt,
                                        OGCONN_ATTR_PARAMSET_SIZE,
                                        &newvalue,
                                        strlen);
        case SQL_ATTR_ROWS_FETCHED_PTR:
            stmt->rows = (uint32)newvalue;
            break;
        case SQL_ROWSET_SIZE:
        case SQL_ATTR_ROW_ARRAY_SIZE:
            stmt->data_num = (uint32)newvalue;
            break;
        default:
            OG_THROW_ERROR(ERR_CLT_API_NOT_SUPPORTED, "Attribute");
            return SQL_ERROR;
    }
    return SQL_SUCCESS;
}