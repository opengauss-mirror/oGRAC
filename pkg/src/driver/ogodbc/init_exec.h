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
 * init_exec.h
 *
 *
 * IDENTIFICATION
 * src/driver/ogodbc/init_exec.h
 */
#ifndef INIT_EXEC_H
#define INIT_EXEC_H

#include "cm_types.h"
#include "ogconn_stmt.h"
#include "cm_bilist.h"
#include "sqlext.h"
#include "environment.h"
#include "odbcinst.h"
#include "ogconn_inner.h"

#define DSN   "DSN"
#define DRIVER   "Driver"    /* driver */
#define SERVERNAME   "Servername"    /* server name */
#define SERVER   "server"    /* server */
#define DATABASE   "Database"    /* database name */
#define USERNAME   "Username"    /* user name */
#define PASSWORD   "Password"    /* password */
#define PORT   "Port"    /* port */
#define CHARSET   "Charset"    /* character set */
#define TENANTNAME   "Tenantname"    /* tenantname */
#define LOGDIR   "logdir"    /* log directory */

#define LARGE_PARAM_LEN          256
#define SMALL_PARAM_LEN          10
#define MAX_NUMBER_LEN           128
#define MAX_VALUE_BUFF_LEN       4096
#define AUTO_COMMIT              1
#define ODBC_INI           ".odbc.ini"
#define ODBCINST_INI       "odbcinst.ini"

#define DECIMAL_SIZE   16
#define OG_BUFF_SIZE    256
#define CALC_PREC_SINGAL    10000000
#define DECIMAL_MOD     256
#define INIT_STMT       1
#define DEL_STMT        2
#define NOT_EXEC_STMT   3
#define EXEC_STMT       4
#define USED_STMT       5

#define INIT_PARAM      1
#define NOT_EXEC_PARAM  2
#define EXEC_PARAM      3
#define FREE_PARAM      4

typedef struct {
    unsigned short *param_size;
    unsigned int is_convert;
    long param_offset;
    char *param_stream;
    long *size;
    unsigned char param_type;
    char (*input_param)[OG_BUFF_SIZE];
    ogconn_type_t og_type;
    void *param_value;
    int sql_type;
    int param_len;
    unsigned int index;
    bilist_node_t data_list;
    unsigned int is_process;
    unsigned int is_binded;
    unsigned int param_flag;
    unsigned int param_count;
    int number;
} sql_input_data;

typedef struct type_map {
    uint32 sql_Type;
    uint32 db_Type;
} db_type_map;

typedef struct sql_c_type_map {
    uint32 db_Type;
    uint32 sql_Type;
} c_type_map;

typedef struct type_size {
    uint32 sql_Type;
    uint32 size;
} type_size_map;

typedef struct {
    ogconn_type_t og_type;
    int sql_type;
    unsigned int ptr;
    unsigned char is_str;
    char *col_label;
    unsigned char is_recieved;
    unsigned int result_size;
    char *field_name;
    unsigned char is_col;
} og_generate_result;

typedef struct {
    int sql_type;
    void *value;
    SQLLEN col_len;
    unsigned int ptr;
    SQLLEN *size;
    og_generate_result generate_result;
} column_param;

typedef struct {
    char          dsn[LARGE_PARAM_LEN];
    char          database[LARGE_PARAM_LEN];
    char          password[LARGE_PARAM_LEN];
    char          port[SMALL_PARAM_LEN];
    char          server[LARGE_PARAM_LEN];
    char          drivername[LARGE_PARAM_LEN];
    char          username[LARGE_PARAM_LEN];
    char          charset[LARGE_PARAM_LEN];
} ConnInfo;

typedef int(INSTAPI * SQLGetPrivateProfileStringFunc) (
    const char *section,
    const char *entry,
    const char *default_value,
    char *ret_buffer,
    int    buffer_size,
    const char *filename
);

/*******	The Connection handle	************/
typedef struct ConnectionHandle {
    environment_class   *environment;
    int              error_code;
    ConnInfo           connInfo;
    char               *error_msg;
    ogconn_conn_t      ctconn_conn;
    unsigned char      flag;
    int              err_sign;
} connection_class;

/********	Statement Handle	***********/
typedef struct StatementHandle {
    unsigned int param_count;
    unsigned int rows;
    bilist_t params;   /* bind params */
    connection_class *conn;
    list_t param;   /* bind param */
    ogconn_stmt_t ctconn_stmt;
    list_t data_rows;
    unsigned int data_num;
    unsigned int stmt_flag;
} statement;

typedef struct {
    char *value;
    int len;
    ogconn_type_t og_type;
} og_fetch_data_result;

typedef struct {
    unsigned int param_len;
    void *param_value;
    long *size;
    int sql_type;
} bind_input_param;

typedef char paramData[OG_BUFF_SIZE];

SQLRETURN init_odbc_dsn(connection_class *conn, ConnInfo *info);
SQLRETURN og_db_connect(connection_class *conn, ConnInfo *info);
SQLRETURN bind_param_by_c_type(statement *stmt, sql_input_data *input_data);
void clean_up_param(bilist_node_t *node, bilist_t *params, sql_input_data *input_data);
sql_input_data *generate_bind_param_instance(bilist_node_t *node, uint32 pos);
void get_err(HDBC conn);
ogconn_type_t sql_type_map_to_db_type(SQLSMALLINT type);
SQLSMALLINT db_type_map_to_c_type(uint16 type);
sql_input_data *build_bind_param(bilist_t *param_list, uint32 pos);
SQLULEN cal_column_len(SQLSMALLINT ValueType, SQLULEN ColumnSize, SQLLEN BufferLength,
                       const SQLPOINTER ValuePtr, SQLLEN *StrLen_or_IndPtr);
SQLULEN cal_len_of_sql_type(SQLSMALLINT sql_c_type);
void del_stmt_param(bilist_t *params, bool8 is_init);
void load_odbc_config();
void close_odbc_config();
void clean_up_bind_param(sql_input_data *input_data);
SQLRETURN malloc_bind_param(sql_input_data *input_data);
#endif