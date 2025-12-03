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
 * ogconn.h
 *
 *
 * IDENTIFICATION
 * src/driver/ogconn/ogconn.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTCONN_H__
#define __CTCONN_H__

#include <stdio.h>
#include <stdlib.h>
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* handle */
struct __ctconn_conn;
struct __ctconn_stmt;
struct __ctconn_desc;
struct __ctconn_datetime;
typedef struct __ctconn_conn *ogconn_conn_t;         /* type of connection handle */
typedef struct __ctconn_stmt *ogconn_stmt_t;         /* type of statement handle */
typedef struct __ctconn_desc *ogconn_desc_t;         /* type of description handle */
typedef struct __ctconn_datetime *ogconn_datetime_t; /* type of dateime handle */

/* data types */
typedef enum en_ctconn_type {
    OGCONN_TYPE_UNKNOWN = 0,            /* invalid value */
    OGCONN_TYPE_INTEGER = 1,            /* native 32 bits integer */
    OGCONN_TYPE_BIGINT = 2,             /* native 64 bits integer */
    OGCONN_TYPE_REAL = 3,               /* native float */
    OGCONN_TYPE_NUMBER = 4,             /* number */
    OGCONN_TYPE_DECIMAL = 5,            /* decimal, internal used */
    OGCONN_TYPE_DATE = 6,               /* datetime, 7 bytes */
    OGCONN_TYPE_TIMESTAMP = 7,          /* timestamp */
    OGCONN_TYPE_CHAR = 8,               /* char(n) */
    OGCONN_TYPE_VARCHAR = 9,            /* varchar, varchar2 */
    OGCONN_TYPE_STRING = 10,            /* native char * */
    OGCONN_TYPE_BINARY = 11,            /* binary */
    OGCONN_TYPE_VARBINARY = 12,         /* varbinary */
    OGCONN_TYPE_CLOB = 13,              /* clob */
    OGCONN_TYPE_BLOB = 14,              /* blob */
    OGCONN_TYPE_CURSOR = 15,            /* resultset, for procedure */
    OGCONN_TYPE_COLUMN = 16,            /* column type, internal used */
    OGCONN_TYPE_BOOLEAN = 17,           /* bool, value can be 1 or 0 */
    OGCONN_TYPE_TIMESTAMP_TZ_FAKE = 18, /* fake, equals to timestamp */
    OGCONN_TYPE_TIMESTAMP_LTZ = 19,     /* timestamp with local time zone */
    OGCONN_TYPE_INTERVAL = 20,          /* interval of pg style */
    OGCONN_TYPE_INTERVAL_YM = 21,       /* interval YEAR TO MONTH */
    OGCONN_TYPE_INTERVAL_DS = 22,       /* interval DAY TO SECOND */
    OGCONN_TYPE_RAW = 23,
    OGCONN_TYPE_IMAGE = 24,        /* image, equals to longblob */
    OGCONN_TYPE_UINT32 = 25,       /* unsigned integer */
    OGCONN_TYPE_TIMESTAMP_TZ = 32, /* timestamp with time zone */
    OGCONN_TYPE_ARRAY = 33,        /* array */
    OGCONN_TYPE_NUMBER2 = 34,      /* number2 */
    OGCONN_TYPE_RECORD = 101,      /* record */
    OGCONN_TYPE_COLLECTION = 102,  /* collection */
    OGCONN_TYPE_OBJECT = 103,      /* object */
    OGCONN_TYPE_NATIVE_DATE = 205, /* native datetime, internal used */
} ogconn_type_t;

/* bound size of special data type needs convert to string buffer */
#define OGCONN_NUMBER_BOUND_SIZE (int)50
#define OGCONN_TIME_BOUND_SIZE (int)60
#define OGCONN_BOOL_BOUND_SIZE (int)6
#define OGCONN_YM_INTERVAL_BOUND_SIZE (int)10
#define OGCONN_DS_INTERVAL_BOUND_SIZE (int)24

/* stmt types */
typedef enum en_ctconn_stmt_type {
    OGCONN_STMT_NONE = 0,
    OGCONN_STMT_DML = 1, /* select/insert/delete/update/merge/replace, etc */
    OGCONN_STMT_DCL = 2,
    OGCONN_STMT_DDL = 3,
    OGCONN_STMT_PL = 4,
    OGCONN_STMT_EXPLAIN = 5, /* explain [plan for] + DML */
} ogconn_stmt_type_t;

/* null value */
#define OGCONN_NULL (unsigned short)0xFFFF

/* direction of bind, default is OGCONN_INPUT */
#define OGCONN_INPUT (unsigned char)1
#define OGCONN_OUTPUT (unsigned char)2
#define OGCONN_INOUT (unsigned char)3

/* description of column */
/* users can use 'ogconn_get_desc_attr' instead of 'ogconn_desc_column_by_id' */
typedef struct st_ctconn_column_desc {
    char *name;
    unsigned short size;
    unsigned char precision;
    char scale;
    unsigned short type;
    unsigned char nullable;
    unsigned char is_character;
} ogconn_column_desc_t;

/* description of output in procedure */
typedef struct st_ctconn_output_desc {
    char *name;
    unsigned short size;
    unsigned char direction;
    unsigned char type;
} ogconn_outparam_desc_t;

/* lob bind value */
typedef struct st_ctconn_lob {
    unsigned int size;
    unsigned int type;
    unsigned int entry_vmid;
    unsigned int last_vmid;
} ogconn_lob_t;

typedef struct st_ctconn_sequence {
    unsigned int group_order;
    unsigned int group_cnt;
    unsigned int size;
#ifdef WIN32
    __int64 start_val;
    __int64 step;
    __int64 end_val;
#else
    long long start_val;
    long long step;
    long long end_val;
#endif
} ogconn_sequence_t;

typedef enum en_ctconn_ssl_mode {
    OGCONN_SSL_DISABLED = 0,
    OGCONN_SSL_PREFERRED,
    OGCONN_SSL_REQUIRED,
    OGCONN_SSL_VERIFY_CA,
    OGCONN_SSL_VERIFY_FULL
} ogconn_ssl_mode_t;

/* description type */
typedef enum en_ctconn_desc_type {
    OGCONN_DESC_OBJ = 0,
    OGCONN_DESC_TABLE,
    OGCONN_DESC_VIEW,
    OGCONN_DESC_SYN,   /* synonym */
    OGCONN_DESC_QUERY, /* query */
    OGCONN_DESC_PROC,  /* procedure */
    OGCONN_DESC_FUNC,  /* function */
    OGCONN_DESC_PKG,   /* package */
    OGCONN_DESC_SEQ,   /* sequence */
} ogconn_desc_type_t;

typedef enum en_ctconn_shd_rw_split {
    OGCONN_SHD_RW_SPLIT_NONE = 0, // shard rw split not set
    OGCONN_SHD_RW_SPLIT_RW,       // read and write
    OGCONN_SHD_RW_SPLIT_ROS,      // read on slave dn
    OGCONN_SHD_RW_SPLIT_ROA       // read on master dn or slave dn
} ogconn_shd_rw_split_t;

/* connection attributes */
#define OGCONN_ATTR_AUTO_COMMIT \
    (int)101 /* specifies auto commit after execute, default is auto commit off , Attribute Datatype: unsigned int */
#define OGCONN_ATTR_XACT_STATUS (int)102 /* currently not enabled */
#define OGCONN_ATTR_EXIT_COMMIT                                                                                      \
    (int)103 /* enable for ogsql, for whether do commit when ogsql is quit, default is enable , Attribute Datatype: \
                unsigned int */
#define OGCONN_ATTR_SERVEROUTPUT                                                                                      \
    (int)104 /* whether enable returns dbe_output.print_line in procedure, default is disable, Attribute Datatype: \
                unsigned int */
#define OGCONN_ATTR_CHARSET_TYPE                                                                                     \
    (int)105 /* set charset type of client, currently supports UTF8 or GBK, default is UTF8 , Attribute Datatype: \
                char*, Length: unsigned int */
#define OGCONN_ATTR_NUM_WIDTH (int)106 /* enable for ogsql, for display numeric value , Attribute Datatype: unsigned int \
                                     */
#define OGCONN_ATTR_INTERACTIVE_MODE                                                                    \
    (int)107 /* whether enable interactive timeout, default is disable. timeout depends on parameter \
                INTERACTIVE_TIMEOUT , Attribute Datatype: unsigned char */
#define OGCONN_ATTR_LOB_LOCATOR_SIZE (int)108 /* specifies the size of LOB locator , Attribute Datatype: unsigned int */
#define OGCONN_ATTR_SSL_CA                                                                                            \
    (int)109 /* file that contains list of trusted SSL Certificate Authorities, Attribute Datatype: char*, Length: \
                unsigned int */
#define OGCONN_ATTR_SSL_CERT \
    (int)110 /* file that contains X.509 certificate, Attribute Datatype: char*, Length: unsigned int */
#define OGCONN_ATTR_SSL_KEY (int)111  /* file that contains X.509 key, Attribute Datatype: char*, Length: unsigned int */
#define OGCONN_ATTR_SSL_MODE (int)112 /* security state of connection to server, Attribute Datatype: unsigned int */
#define OGCONN_ATTR_SSL_CRL \
    (int)113 /* file that contains certificate revocation lists, Attribute Datatype: char*, Length: unsigned int */
#define OGCONN_ATTR_SSL_KEYPWD                                                                                       \
    (int)114 /* the pwd for SSL key file. If the SSL key file is protected by a pass phrase, use the attribute to \
                specify the pwd, Attribute Datatype: char*, Length: unsigned int */
#define OGCONN_ATTR_SSL_CIPHER                                                                                          \
    (int)115 /* list of permitted ciphers for connection encryption, Attribute Datatype: char*, Length: unsigned int \
              */
#define OGCONN_ATTR_CONNECT_TIMEOUT                                                                                       \
    (int)116 /* connection timeout when create socket to server, unit is second, default is 10, -1 means not timeout , \
                Attribute Datatype: int */
#define OGCONN_ATTR_SOCKET_TIMEOUT                                                                                 \
    (int)117 /* socket timeout when execute sql, unit is second, default is -1, -1 means not timeout, Attribute \
                Datatype: int */
#define OGCONN_ATTR_APP_KIND (int)118        /* specifies client type of client, default is 1, Attribute Datatype: short */
#define OGCONN_ATTR_DBTIMEZONE (int)119      /* DBTIMEZONE, Attribute Datatype: short */
#define OGCONN_ATTR_UDS_SERVER_PATH (int)120 /* specifies unix domain socket server file path */
#define OGCONN_ATTR_UDS_CLIENT_PATH (int)121 /* specifies unix domain socket client file path */
#define OGCONN_ATTR_TIMESTAMP_SIZE (int)122  /* get inner timestamp bind size */
#define OGCONN_ATTR_TIMESTAMP_TZ_SIZE (int)123  /* get inner timestamp_tz bind size */
#define OGCONN_ATTR_TIMESTAMP_LTZ_SIZE (int)124 /* get inner timestamp_ltz bind size */
#define OGCONN_ATTR_FLAG_WITH_TS (int)125
#define OGCONN_ATTR_REMOTE_AS_SYSDBA (int)126
#define OGCONN_ATTR_SHD_RW_FLAG (int)127 /* flag of CN rw split, 0:not split,1:on master,2:on slave,3:on master or slave \
                                       */
#define OGCONN_ATTR_LAST_INSERT_ID                                                                                      \
    (int)128 /* the value generated by the AUTO INCREMENT column of the last INSERT statement in the current session \
              */
#define OGCONN_ATTR_SOCKET_L_ONOFF (int)129  /* SO_LINGER l_onoff value */
#define OGCONN_ATTR_SOCKET_L_LINGER (int)130 /* SO_LINGER l_linger value */
#define OGCONN_ATTR_AUTOTRACE (int)131       /* enable autotrace */

/* The order of NLS can not be changed */
#define OGCONN_ATTR_NLS_CALENDAR (int)160
#define OGCONN_ATTR_NLS_CHARACTERSET (int)161
#define OGCONN_ATTR_NLS_COMP (int)162
#define OGCONN_ATTR_NLS_CURRENCY (int)163
#define OGCONN_ATTR_NLS_DATE_FORMAT (int)164
#define OGCONN_ATTR_NLS_DATE_LANGUAGE (int)165
#define OGCONN_ATTR_NLS_DUAL_CURRENCY (int)166
#define OGCONN_ATTR_NLS_ISO_CURRENCY (int)167
#define OGCONN_ATTR_NLS_LANGUAGE (int)168
#define OGCONN_ATTR_NLS_LENGTH_SEMANTICS (int)169
#define OGCONN_ATTR_NLS_NCHAR_CHARACTERSET (int)170
#define OGCONN_ATTR_NLS_NCHAR_CONV_EXCP (int)171
#define OGCONN_ATTR_NLS_NUMERIC_CHARACTERS (int)172
#define OGCONN_ATTR_NLS_RDBMS_VERSION (int)173
#define OGCONN_ATTR_NLS_SORT (int)174
#define OGCONN_ATTR_NLS_TERRITORY (int)175
#define OGCONN_ATTR_NLS_TIMESTAMP_FORMAT (int)176
#define OGCONN_ATTR_NLS_TIMESTAMP_TZ_FORMAT (int)177
#define OGCONN_ATTR_NLS_TIME_FORMAT (int)178
#define OGCONN_ATTR_NLS_TIME_TZ_FORMAT (int)179

/* statement attributes */
#define OGCONN_ATTR_PREFETCH_ROWS (int)201   /* number of top level rows to be prefetched */
#define OGCONN_ATTR_PREFETCH_BUFFER (int)202 /* memory level for top level rows to be prefetched (useless) */
#define OGCONN_ATTR_PARAMSET_SIZE (int)203   /* number of array bind data for batch bind, default is 1 */
#define OGCONN_ATTR_FETCHED_ROWS                                                                                         \
    (int)204 /* indicates the number of rows that were successfully fetched into the user's buffers in the last fetch \
              */
#define OGCONN_ATTR_AFFECTED_ROWS                                                                                     \
    (int)205 /* returns the number of rows processed so far after SELECT statements. For INSERT, UPDATE and DELETE \
                statements, it is the number of rows processed by the most recent statement */
#define OGCONN_ATTR_RESULTSET_EXISTS (int)206 /* returns whether has query result */
#define OGCONN_ATTR_COLUMN_COUNT (int)207     /* returns the columns count of query */
#define OGCONN_ATTR_STMT_TYPE \
    (int)208 /* the type of statement associated with the handle, valid values defined in ogconn_stmt_type_t */
#define OGCONN_ATTR_PARAM_COUNT (int)209 /* returns the params count */
#define OGCONN_ATTR_MORE_ROWS (int)210 /* whether has more query rows or not, 0 means has no more rows, 1 means has more \
                                     */
#define OGCONN_ATTR_STMT_EOF (int)211  /* specifies whether stmt is fetch over or not */
#define OGCONN_ATTR_OUTPARAM_COUNT (int)212 /* count of outparams in procedure */
#define OGCONN_ATTR_SEROUTPUT_EXISTS                                                                                    \
    (int)213 /* whether returns dbe_output.print_line or not, used in procedure. default is disable returns and need \
                use OGCONN_ATTR_SERVEROUTPUT to enable returns */
#define OGCONN_ATTR_RETURNRESULT_EXISTS (int)214 /* whether returns dbe_sql.return_cursor or not, used in procedure */
#define OGCONN_ATTR_ALLOWED_BATCH_ERRS (int)215  /* allowed batch errors when do execute batch */
#define OGCONN_ATTR_ACTUAL_BATCH_ERRS (int)216   /* returns the actual batch errors after execute batch */
#define OGCONN_ATTR_FETCH_SIZE \
    (int)217 /* number of rows to be fetched from the current position for batch fetch, default is 1 */
#define OGCONN_ATTR_SHARD_DML_ID (int)218 /* id of cn dispatch dml to dn */

/* describe attributes */
#define OGCONN_ATTR_NAME (int)301       // column name ,Attribute Datatype: char*, Length: int
#define OGCONN_ATTR_DATA_SIZE (int)302  /* column size ,Attribute Datatype: unsigned short */
#define OGCONN_ATTR_PRECISION (int)303  /* column precision ,Attribute Datatype: unsigned char */
#define OGCONN_ATTR_SCALE (int)304      /* column scale ,Attribute Datatype: unsigned char */
#define OGCONN_ATTR_DATA_TYPE (int)305  /* column data type ,Attribute Datatype: unsigned short */
#define OGCONN_ATTR_NULLABLE (int)306   /* column is nullable ,Attribute Datatype: unsigned char */
#define OGCONN_ATTR_CHAR_USED (int)307  /* column is character ,Attribute Datatype: unsigned char */
#define OGCONN_ATTR_ARRAY_USED (int)308 /* column is array ,Attribute Datatype: unsigned char */

/* return code */
#define OGCONN_SUCCESS (int)0
#define OGCONN_SUCCESS_WITH_INFO (int)1
#define OGCONN_ERROR (int)(-1)

/*
    Definition: create a connection object
    Input_param:
        conn: connection object
    Output_param:
        conn: connection object
    Return value:
        0:   success
        !=0: failed
    Description: Creates a connection object and use it to invoke ogconn_connect to connect to the database
*/
int ogconn_alloc_conn(ogconn_conn_t *pconn);

/*
    Definition: release the connection object
    Input_param:
        conn: connection object
    Return value:
    Description: Releases a connection object. This API is invoked after the ogconn_disconnect (database disconnection)
   operation is performed
*/
void ogconn_free_conn(ogconn_conn_t pconn);

/*
    Definition: set connection attributes
    Input_param:
        conn: connection object
        attr: connection attributes
        data: attribute value
        len:  attribute size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to set the connection attribute,
                 such as: OGCONN_ATTR_AUTO_COMMIT-transaction commit method (1 means automatic commit, 0 means manual
   commit)
*/
int ogconn_set_conn_attr(ogconn_conn_t pconn, int32 attr, const void *data, uint32 len);

/*
    Definition: get connection attributes
    Input_param:
        conn: connection object
        attr:connection attribute
    Output parameter:
        data: attribute value
        len : attribute size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the connection attribute,
                 such as: OGCONN_ATTR_AUTO_COMMIT-transaction commit method (1 indicates automatic commit, 0 indicates
   manual commit)
*/
int ogconn_get_conn_attr(ogconn_conn_t pconn, int32 attr, void *data, uint32 len, uint32 *attr_len);

/*
    Definition: Get error code and error message through connection
    Input_param:
        conn: connection object
    Output parameters:
        code: error code
        message: error message
    Return value:
    Description: Interface used to obtain error codes and error messages by the connection
*/
void ogconn_get_error(ogconn_conn_t pconn, int32 *code, const char **message);

/*
    Definition: Get the location and column information of an error in the execution SQL through a connection
    Input_param:
        conn: connection object
    Output:
        line: error location information
        column: error column information
    Return value:
    Description: interface is used to obtain the location and column information of the error in the execution SQL
   through the connection, used to locate the reason of the SQL error
*/
void ogconn_get_error_position(ogconn_conn_t pconn, uint16 *line, uint16 *column);

/*
    Definition: get error message through connection
    Input_param:
        conn: connection object
    Return value:
        message: error message
    Description: interface is used to obtain the error message by conn. If the passed conn is NULL, the returned message
   is NULL.
*/
char *ogconn_get_message(ogconn_conn_t pconn);

/*
    Definition: Connect to the database
    Input_param:
        conn: connection object
        url:  connection address information
        user: connection username
        pwd:  connection pwd
    Return value:
        0:   success
        !=0: failed
    Description: Connects to the database. The URL format is ip:port and only supports TCP connections
*/
int ogconn_connect(ogconn_conn_t pconn, const char *url, const char *user, const char *password);

/*
    Definition: disconnect the database
    Input_param:
        conn: connection object
    Return value:
    Description: Interface used to disconnect the database
*/
void ogconn_disconnect(ogconn_conn_t pconn);

/*
    Definition: get session ID
    Input_param:
        conn: connection object
    Return value: session ID
    Description: interface is used to obtain the session ID which uniquely identifies a connection. If the conn is NULL,
   returns invalid sid
*/
unsigned int ogconn_get_sid(ogconn_conn_t pconn);

/*
    Definition: cancel the statement being executed
    Input_param:
        conn: connection object
        Sid: session ID
    Return value:
        0 success
        !=0 failed
    Description: interface is used to cancel operations on the connection for the specified session ID
*/
int ogconn_cancel(ogconn_conn_t pconn, uint32 sid);

/*
    Definition: apply handle object
    Input_param:
        conn: connection object
    Output parameter:
        stmt: handle object
    Return value:
        0:  success
        !=0: failed
    Description: interface is used to create a handle object, and then use the handle object to execute SQL.
*/
int ogconn_alloc_stmt(ogconn_conn_t pconn, ogconn_stmt_t *pstmt);

/*
    Definition: release handle object
    Input_param:
        stmt: handle object
    Return value:
    Description: interface is used to release the handle object
*/
void ogconn_free_stmt(ogconn_stmt_t pstmt);

/*
    Definition: Set the handle attribute
    Input_param:
        stmt: handle object
        attr: handle attribute
        data: attribute value
        len:  attribute size
    Return value:
         0: success
        !0: failed
    Description: interface is used to set the handle attribute,
                 such as: OGCONN_ATTR_PREFETCH_ROWS--->number of prefetch records,
                          OGCONN_ATTR_PREFETCH_BUFFER--->prefetch record size,
                          OGCONN_ATTR_PARAMSET_SIZE--->Batch Parameter Bindings
*/
int ogconn_set_stmt_attr(ogconn_stmt_t pstmt, int attr, const void *data, uint32 len);

/*
    Definition: get the handle attribute
    Input_param:
        stmt: handle object
        attr: handle attribute
        data: attribute value
        len:  attribute size
    Return value:
         0: success
        !0: failed
    Description: interface is used to set the handle attribute,
                 such as: OGCONN_ATTR_PREFETCH_ROWS--->number of prefetch records,
                          OGCONN_ATTR_PREFETCH_BUFFER--->prefetch record size,
                          OGCONN_ATTR_PARAMSET_SIZE--->Batch Parameter Bindings
*/
int ogconn_get_stmt_attr(ogconn_stmt_t pstmt, int attr, const void *data, uint32 buf_len, uint32 *len);

/*
    Definition: Preprocessing SQL statements
    Input_param:
        stmt: handle object
         Sql: SQL statement
    Return value:
        0:   success
        !=0: failed
    Description: Interface for preprocessing SQL statements
*/
int ogconn_prepare(ogconn_stmt_t pstmt, const char *sql);

/*
     Definition: parameter binding by parameter position
     Input_param:
        stmt: handle object
        pos:  The position number of the parameter, starting from 0
        type: data type, from type definition ogconn_type_t except OGCONN_TYPE_TIMESTAMP which will be added in next
            version
        data: Address of data value or address of data array
        size: buffer length
        ind:  length address or length array address
        direction: direction of bind parameter
     Return value:
        0: success
        !=0: failed
     Description: interface is used for parameter binding through the parameter location. The usage of
         ogconn_bind_by_name
   and ogconn_bind_by_pos is basically the same, but there are some differences. For parameters of the same parameter
       name,
   you can use ogconn_bind_by_name to bind once, and ogconn_bind_by_pos must bind every parameter. If use
       ogconn_bind_by_pos,
   default direction is 1(input parameter). If need bind parameter with direction, need use ogconn_bind_by_pos2. Value
       of
   direction can be 1(input parameter), 2(outut parameter) or 3(inout parameter).
*/
int ogconn_bind_by_pos(ogconn_stmt_t pstmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind);
int ogconn_bind_by_pos2(ogconn_stmt_t pstmt, uint32 pos, int type, const void *data, int32 size, uint16 *ind,
                     int32 direction);

/*
     Definition: parameter binding by parameter position
     Input_param:
        stmt: handle object
        pos:  The position number of the parameter, starting from 0
        type: data type, from type definition ogconn_type_t
        data: Address of data value or address of data array
        size: buffer length
        ind:  length address or length array address
        direction: direction of bind
     Return value:
        0: success
        !=0: failed
    Description: interface is used for parameter binding by parameter name. If NULL is bound, the corresponding ind[i]
   of the data needs to be set to OGCONN_NULL.
*/
int ogconn_bind_by_name(ogconn_stmt_t pstmt, const char *name, int type, const void *data, int32 size, uint16 *ind);
int ogconn_bind_by_name2(ogconn_stmt_t pstmt, const char *name, int type, const void *data, int32 size, uint16 *ind,
                      int32 direction);

/*
    Definition: Get the number of query columns
    Input_param:
        stmt: handle object
    Output_param:
        column_count: the number of query columns
    Return value:
        0: success
        !=0: failed
    Description: interface is used to get the number of query columns, only valid for the query
*/
int ogconn_get_column_count(ogconn_stmt_t pstmt, uint32 *column_count);

/*
    Definition: Get query column description information according to query column serial number
    Input_param:
        stmt: handle object
        Id:   query column serial number, starting from 0
    Output:
        desc: query column description
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain query column description information (column name, column data type, column
   size, etc.) based on the query column ordinal number, valid only for the query.
*/
int ogconn_desc_column_by_id(ogconn_stmt_t pstmt, uint32 id, ogconn_column_desc_t *desc);

/*
    Definition: Get the query column description based on the query name
    Input_param:
        stmt: handle object
        col_name: query column name
    Output:
        desc: query column description
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain query column description information (column name, column data type, column
   size, etc.) based on the query name, only valid for the query.
*/
int ogconn_desc_column_by_name(ogconn_stmt_t pstmt, const char *col_name, ogconn_column_desc_t *desc);

/*
    Definition: Get the query column description based on the query attribute
    Input_param:
        stmt: handle object
        id: query column id
        attr: query attribute
    Output:
        data: query data buffer pointer
        len: query data actual length (OGCONN_ATTR_NAME, it means name length)
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain query column description information
        (column name, column data type, column size, etc.) based on the query attribute,
        only valid for the query.
*/
int ogconn_get_desc_attr(ogconn_stmt_t pstmt, uint32 id, int32 attr, void *data, uint32 *len);

/*
    Definition: Get the value of a specific query column based on the query column ordinal
    Input_param:
        stmt: handle object
        id: query column serial number, starting from 0
    Output_param:
        data: query column data
        size: query column size
        is_null: query column value is NULL
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain the value of a specific query column based on the query column ordinal. It
   is valid only for queries. Size is determined by the column data type. For example, int is 4 bytes, bigint is 8
   bytes, and string is variable length.
*/
int ogconn_get_column_by_id(ogconn_stmt_t pstmt, unsigned int id, void **data, unsigned int *size, bool32 *is_null);

/*
    Definition: Get the value of a specific query column based on the query column name
    Input_param:
        stmt: handle object
        id: query column serial number, starting from 0
    Output_param:
        data: query column data
        size: query column size
        is_null: query column value is NULL
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain the value of a specific query column based on the query column ordinal. It
   is valid only for queries.
*/
int ogconn_get_column_by_name(ogconn_stmt_t pstmt, const char *col_name, void **data, uint32 *size, uint32 *is_null);

/*
    Definition: Get the number of rows affected
    Input_param:
        stmt: handle object
    Return value:
        The number of rows affected
    Description: interface is used to obtain the number of rows affected. For insert, delete, and update, affect_rows
   indicates the number of rows inserted, deleted, and updated. For select and explain plan statements, affect_rows
   indicates the number of rows in the current fetch, not the number of rows that can eventually be fetched.
*/
unsigned int ogconn_get_affected_rows(ogconn_stmt_t pstmt);

/*
    Definition: Get the query column value obtained from the query column serial number as a string
    Input_param:
        stmt: handle object
        id: query column serial number, starting from 0
        format: string output format, only for the date and time type query column
        str: store query column value memory address
        buf_size: store query column value memory size
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain the query column value obtained from the query column serial number in a
   string manner. For the date and time type column, the output format can also be executed. If not specified, the
   default date_format="YYYY-MM-DD HH24:MI:SS",timestamp_format="YYYY-MM-DD HH24:MI:SS.FF"
*/
int ogconn_column_as_string(ogconn_stmt_t pstmt, uint32 id, char *str, uint32 buf_size);

/*
    Definition: This call specifies additional attributes necessary for a static array define, used in an array of
   structures (multi-row, multi-column) fetch Input_param: stmt: handle object id: query column serial number, starting
   from 0 bind_type: data type expected to get column value bind_size: size of one item of array bind_ptr:  address of
   memory to store query column value ind_ptr:   length address or length array address Return value: 0: success
        !=0: failed
    Description: interface is used to multi-row or multi-column fetch. Number of array of bind_ptr or ind_ptr depends on
   attr OGCONN_ATTR_FETCH_SIZE. Bind_type can be same with data type of column definition or likely, such as number or
       date
   or string.
*/
int ogconn_bind_column(ogconn_stmt_t pstmt, uint32 id, uint16 bind_type, uint16 bind_size, void *bind_ptr,
                    uint16 *ind_ptr);

/*
    Definition: Execute SQL statement
    Input_param:
        stmt: handle object
    Return value:
        0: success
        !=0: failed
    Description: interface is used to execute the SQL statement. If the connection is an automatic commit method, the
   transaction is committed or rolled back immediately after the operations of inserting, deleting, and updating are
   performed. No need to commit or rollback manually.
*/
int ogconn_execute(ogconn_stmt_t pstmt);

/*
    Definition: Get a query record row
    Input_param:
        stmt: handle object
    The parameter:
        rows: Returns the number of query records
    Return value:
        0: success
        !=0: failed
    Description: interface is used to obtain a query record row, rows value is>=0
*/
int ogconn_fetch(ogconn_stmt_t pstmt, uint32 *rows);

/*
    Definition: Submit a transaction that has not ended
    Input_param:
        conn: connection object
    Return value:
        0: success
        !=0: failed
    Description: Interface used to commit transactions that have not yet ended
*/
int ogconn_commit(ogconn_conn_t pconn);

/*
    Definition: rollback a transaction that has not ended
    Input_param:
        conn: connection object
    Return value:
        0: success
        !=0: failed
    Description: Interface used to rollback transactions that have not yet ended
*/
int ogconn_rollback(ogconn_conn_t pconn);

/*
    Definition: Set whether to automatically commit the transaction after the current operation
    Input_param:
    conn: connection object
    auto_commit: is or not auto
    Return value:
    Description: interface is used to set whether the transaction is committed automatically after the current
   operation. Usage is equivalent to ogconn_set_conn_attr setting OGCONN_ATTR_AUTO_COMMIT
*/
void ogconn_set_autocommit(ogconn_conn_t pconn, bool32 auto_commit);

/*
    Definition: Set batch parameter binding number
    Input_param:
    stmt: handle object
    sz: batch parameter binding number
    Return value:
    Description: interface is used to set the number of batch parameter bindings, usage is equivalent to
   ogconn_set_stmt_attr set OGCONN_ATTR_PARAMSET_SIZE
*/
void ogconn_set_paramset_size(ogconn_stmt_t pstmt, uint32 sz);

/*
    Definition: Query series interface
    Input_param: conn handle object
    Return value:
    Description: interface is used to use connection handle object to execute sql, can use ogconn_get_query_stmt to get
   stmt and get more result
*/
int ogconn_query(ogconn_conn_t pconn, const char *sql);
unsigned int ogconn_query_get_affected_rows(ogconn_conn_t pconn);
unsigned int ogconn_query_get_column_count(ogconn_conn_t pconn);
int ogconn_query_fetch(ogconn_conn_t pconn, uint32 *rows);
int ogconn_query_describe_column(ogconn_conn_t pconn, uint32 id, ogconn_column_desc_t *desc);
int ogconn_query_get_column(ogconn_conn_t pconn, uint32 id, void **data, uint32 *size, uint32 *is_null);
ogconn_stmt_t ogconn_get_query_stmt(ogconn_conn_t pconn);

/*
    Definition: blob or clob or image read and write series interface
    Input_param:
    Return value:
    Description: interface is used to read and write blob or clob or image data
*/
int ogconn_write_blob(ogconn_stmt_t pstmt, uint32 id, const void *data, uint32 size);
int ogconn_write_clob(ogconn_stmt_t pstmt, uint32 id, const void *data, uint32 size, uint32 *nchars);

int ogconn_write_batch_blob(ogconn_stmt_t pstmt, uint32 id, uint32 piece, const void *data, uint32 size);
int ogconn_write_batch_clob(ogconn_stmt_t pstmt, uint32 id, uint32 piece, const void *data, uint32 size, uint32
    *nchars);

int ogconn_read_blob_by_id(ogconn_stmt_t pstmt, uint32 id, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
                        uint32 *eof);
int ogconn_read_blob(ogconn_stmt_t pstmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nbytes,
                  uint32 *eof);

int ogconn_read_clob_by_id(ogconn_stmt_t pstmt, uint32 id, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
                        uint32 *nbytes, uint32 *eof);
int ogconn_read_clob(ogconn_stmt_t pstmt, void *locator, uint32 offset, void *buffer, uint32 size, uint32 *nchars,
                  uint32 *nbytes, uint32 *eof);

/*
    Definition: Get serveroutput information
    Input_param:
        stmt: handle object
    Output parameter:
        data: serveroutput data information
        len:  serveroutput length information
    Return Value:
        0: No server output information
        1: has serveroutput information
    Description: interface is used to obtain the serveroutput information. If and only if the client sets the server
   output switch and the server has serveroutput content output, it will obtain the content.
*/
int ogconn_fetch_serveroutput(ogconn_stmt_t pstmt, char **data, uint32 *len);

/*
    Definition: Get implicit resultset of procedure
    Input_param:
        stmt: handle object
    Output parameter:
        resultset: handle object
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get implicit resultset of procedure with one by one mode. If resultset is null
   means has no more return result.
*/
int ogconn_get_implicit_resultset(ogconn_stmt_t pstmt, ogconn_stmt_t *resultset);

/*
    Definition: Get the outparam column description information according to outparam column serial number
    Input_param:
        stmt: handle object
        Id:   outparam column serial number, starting from 0
    Output:
        desc: outparam column description
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain outparam column description information (outparam name, outparam data type,
   outparam size, etc.) based on the outparam column ordinal number, valid only for the procedure.
*/
int ogconn_desc_outparam_by_id(ogconn_stmt_t pstmt, uint32 id, ogconn_outparam_desc_t *desc);

/*
    Definition: Get the outparam column description based on the outparam name
    Input_param:
        stmt: handle object
        name: outparam column name
    Output:
        desc: outparam column description
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain outparam column description information (outparam name, outparam data type,
   outparam size, etc.) based on the outparam name, only valid for the procedure.
*/
int ogconn_desc_outparam_by_name(ogconn_stmt_t pstmt, const char *name, ogconn_outparam_desc_t *desc);

/*
    Definition: Get an outparam record row
    Input_param:
        stmt: handle object
    The parameter:
        rows: Returns the number of outparam records
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain a outparam record row, rows value is>=0
*/
int ogconn_fetch_outparam(ogconn_stmt_t pstmt, uint32 *rows);

/*
    Definition: Get the value of a specific outparam column based on the outparam column ordinal
    Input_param:
        stmt: handle object
        id:   outparam column serial number, starting from 0
    Output_param:
        data: outparam column data
        size: outparam column size
        is_null: outparam column value is NULL
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the value of a specific outparam column based on the outparam column
   ordinal. It is valid only for procedure. If datatype of desc is OGCONN_TYPE_CURSOR, data is handle object of
   sys_refcursor. Size is determined by the column data type. For example, int is 4 bytes, bigint is 8 bytes, and string
   is variable length.
*/
int ogconn_get_outparam_by_id(ogconn_stmt_t pstmt, uint32 id, void **data, uint32 *size, bool32 *is_null);

/*
    Definition: Get the value of a specific outparam column based on the outparam column name
    Input_param:
        stmt: handle object
        name: outparam column name
    Output_param:
        data: outparam column data
        size: outparam column size
        is_null: outparam column value is NULL
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the value of a specific outparam column based on the outparam column
   ordinal. It is valid only for procedure.
*/
int ogconn_get_outparam_by_name(ogconn_stmt_t pstmt, const char *name, void **data, uint32 *size, uint32 *is_null);

/*
    Definition: Get the outparam column value obtained from the outparam column serial number as a string
    Input_param:
        stmt: handle object
        id:   outparam column serial number, starting from 0
        str:  store outparam column value memory address
        buf_size: store outparam column value memory size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the outparam column value obtained from the outparam column serial number
   in a string manner. If datatype of desc is OGCONN_TYPE_CURSOR, must use ogconn_get_outparam_by_id or
   ogconn_get_outparam_by_name to obtain;
*/
int ogconn_outparam_as_string_by_id(ogconn_stmt_t pstmt, uint32 id, char *str, uint32 buf_size);

/*
    Definition: Get the outparam column value obtained from the outparam column based on the outparam name as a string
    Input_param:
        stmt: handle object
        name: outparam column name
        str:  store outparam column value memory address
        buf_size: store outparam column value memory size
    Return value:
        0:   success
        !=0: failed
    Description: interface is used to obtain the outparam column value obtained from the outparam column serial number
   in a string manner. If datatype of desc is OGCONN_TYPE_CURSOR, must use ogconn_get_outparam_by_id or
   ogconn_get_outparam_by_name to obtain;
*/
int ogconn_outparam_as_string_by_name(ogconn_stmt_t pstmt, const char *name, char *str, uint32 buf_size);

/*
    Definition: Convert time information to ogconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ogconn_datetime_t should be OGCONN_TYPE_TIMESTAMP_TZ_FAKE or OGCONN_TYPE_TIMESTAMP_TZ
        year:  year
        mon: month
        day: day
        hour: hour
        min: minute
        sec: second
        fsec: nanosecond
        timezone: timezone
        timezone_len: length of timezone
    Output_param:
        datetime: ogconn_datetime_t struct
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert time information to ogconn_datetime_t construct.
*/
status_t ogconn_datetime_construct(ogconn_stmt_t pstmt, ogconn_datetime_t datetime, int32 datatype, uint16 year, uint8
    mon,
    uint8 day, uint8 hour, uint8 min, uint8 sec, uint32 fsec, char *timezone, uint32 timezone_len);

/*
    Definition: Get time information from ogconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ogconn_datetime_t should be OGCONN_TYPE_TIMESTAMP_TZ_FAKE or OGCONN_TYPE_TIMESTAMP_TZ
        datetime: ogconn_datetime_t struct
    Output_param:
        year:  year
        mon: month
        day: day
        hour: hour
        min: minute
        sec: second
        fsec: nanosecond
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get time information from ogconn_datetime_t construct.
*/
int ogconn_datetime_deconstruct(ogconn_stmt_t pstmt, ogconn_datetime_t datetime, int32 datatype, uint16 *year, uint8
    *mon,
                             uint8 *day, uint8 *hour, uint8 *min, uint8 *sec, uint32 *fsec);

/*
    Definition: Get string timezone information from ogconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ogconn_datetime_t should be OGCONN_TYPE_TIMESTAMP_TZ_FAKE or OGCONN_TYPE_TIMESTAMP_TZ
        datetime: ogconn_datetime_t struct
        buf_len: buffer length
    Output_param:
        buf: buffer pointer
        buf_len: timezone actual length
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get string timezone information from ogconn_datetime_t construct.
*/
int ogconn_datetime_get_timezone_name(ogconn_stmt_t pstmt, ogconn_datetime_t datetime, int32 datatype, char *buf,
                                   uint32 *buf_len);

/*
    Definition: Get timezone information from ogconn_datetime_t construct
    Input_param:
        stmt:      handle object
        datatype:  type of ogconn_datetime_t should be OGCONN_TYPE_TIMESTAMP_TZ_FAKE or OGCONN_TYPE_TIMESTAMP_TZ
        datetime: ogconn_datetime_t struct
    Output_param:
        hour: timezone offset hour
        min: timezone offset minute
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get timezone information from ogconn_datetime_t construct.
*/
int ogconn_datetime_get_timezone_offset(ogconn_stmt_t pstmt, ogconn_datetime_t datetime, int32 datatype, int8 *hour,
                                     int8 *min);

/*
    Definition: Get the description of object
    Input_param:
        stmt:      handle object
        object:    object to desc
        desc_type: type of object
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to desc object, such as table, view, synonym, query, etc.
*/
int ogconn_describle(ogconn_stmt_t pstmt, char *objptr, ogconn_desc_type_t dtype);

/*
    Definition: Get batch error info
    Input_param:
        stmt: handle object
    Output parameter:
        line: pos in batch execute
        err_message: error message
        rows: rows of current batch error
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get batch error info one by one mode. If rows = 0 means has no more batch error to
   get.
*/
int ogconn_get_batch_error(ogconn_stmt_t pstmt, uint32 *line, char **err_message, uint32 *rows);

/*
    Definition: Get batch error info
    Input_param:
        stmt: handle object
    Output parameter:
        line: pos in batch execute
        code: error code
        err_message: error message
        rows: rows of current batch error
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get batch error info one by one mode. If rows = 0 means has no more batch error to
   get.
*/
int ogconn_get_batch_error2(ogconn_stmt_t pstmt, unsigned int *line, int *code, char **err_message, unsigned int *rows);

/*
    Definition: Execute multiple sql
    Input_param:
        conn: connection object
        sql:  multiple sql
    Output parameter:
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to execute multiple sql. Do not supports procedure yet and need use comma between
   every sql
*/
int ogconn_query_multiple(ogconn_conn_t pconn, const char *sql);

/*
    Definition: Get multiple resultset of query
    Input_param:
        stmt: handle object
    Output parameter:
        resultset: handle object
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to get multiple resultset of query with one by one mode. If resultset is null means
   has no more resultset.
*/
int ogconn_get_query_resultset(ogconn_conn_t pconn, ogconn_stmt_t *resultset);

/* sign flag of number */
#define OGCONN_NUMBER_SIGNED 0
#define OGCONN_NUMBER_UNSIGNED 1

/*
    Definition: Convert an dec4_t NUMBER type value to integer
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        sign_flag: Sign of the output, set OGCONN_NUMBER_SIGNED or OGCONN_NUMBER_UNSIGNED.
        rsl_length: Size of the output, set to 2 or 4 or 8.
    Output parameter:
        rsl: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to short(len = 2),int(len = 4),bigint(len = 8).
*/
int ogconn_number_to_int(ogconn_stmt_t pstmt, void *number, unsigned int sign_flag, unsigned int rsl_length, void *rsl);

/*
    Definition: Convert an dec4_t NUMBER type value to real
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        rsl_length: Size of the output, set to 4 or 8.
    Output parameter:
        rsl: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to float(len = 4) or double(len = 8).
*/
int ogconn_number_to_real(ogconn_stmt_t pstmt, void *number, unsigned int rsl_length, void *rsl);

/*
    Definition: Convert an dec4_t NUMBER type value to string
    Input_param:
        stmt: handle object
        number: dec4_t value to be converted
        buf_size: Size of the output,it can be fetched by OGCONN_ATTR_DATA_SIZE.
    Output parameter:
        buf: Buffer point to the output.
    Return Value:
        0:   success
        !=0: failed
    Description: interface is used to convert NUMBER to string.
*/
int ogconn_number_to_string(ogconn_stmt_t pstmt, void *number, char *buf, unsigned int buf_size);


typedef struct st_ctconn_xid {
#ifdef WIN32
    unsigned __int64 fmt_id;
#else
    unsigned long long fmt_id;
#endif
    unsigned char gtrid_len; // 1~64 bytes
    unsigned char bqual_len; // 1~64 bytes
    char data[1];            // for VS warning, data[0] not used
} ogconn_xid_t;

typedef enum en_ctconn_xact_status {
    OGCONN_XACT_END = 0,
    OGCONN_XACT_OPEN = 1,
    OGCONN_XACT_PHASE1 = 2,
    OGCONN_XACT_PHASE2 = 3,
} ogconn_xact_status_t;

#define OGCONN_XA_DEFAULT 0x0000
#define OGCONN_XA_NEW 0x0001
#define OGCONN_XA_NOMIGRATE 0x0002
#define OGCONN_XA_SUSPEND 0x0004
#define OGCONN_XA_RESUME 0x0010
#define OGCONN_XA_ONEPHASE 0x0020
#define OGCONN_XA_LGWR_BATCH 0x0040
#define OGCONN_XA_LGWR_IMMED 0x0080
#define OGCONN_XA_LGWR_WAIT 0x0100
#define OGCONN_XA_LGWR_NOWAIT 0x0200

/*
    Definition: start a new or resume an existing global transaction branch
    Input param:
        conn : connection object
        xid : global transaction branch ID
        timeout:
            when OGCONN_XA_RESUME is specified, it is the number of seconds to wait for the transaction branch to be
   available. when OGCONN_XA_NEW is specified, it is the number of seconds the branch can be inactive before it is
   automatically destroyed. flags: OGCONN_XA_NEW : start a new transaction branch OGCONN_XA_RESUME : resume an existing
   transaction branch OGCONN_XA_NOMIGRATE : the transaction branch can not be ended in one session, but resumed in
       another
   one OGCONN_XA_DEFAULT : OGCONN_XA_NEW|OGCONN_XA_NOMIGRATE Return Value: 0 : success
        !=0 : failed. use ogconn_get_error get latest error information. Typical errors are :
            ERR_XA_ALREADY_IN_LOCAL_TRANS : doing work in a local transaction
            ERR_XA_RESUME_TIMEOUT : timeout when waiting for the transaction branch to be available
            ERR_XA_BRANCH_NOT_EXISTS: specified branch does not exists
    Description: when resume an existing global transaction branch, it must have been ended using ogconn_xa_end.
*/
#ifdef WIN32
int ogconn_xa_start(ogconn_conn_t conn, ogconn_xid_t *xid, unsigned __int64 timeout, unsigned __int64 flags);
#else
int ogconn_xa_start(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 timeout, uint64 flags);
#endif

/*
    Definition: end an global transaction branch
    Input param:
        conn: connection object
        flags:
            OGCONN_XA_DEFAULT
    Return Value:
        0 : success
        !=0 : failed. use ogconn_get_error get latest error information. Typical errors are :
            ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
    Description: the ended branch can be resumed by calling ogconn_xa_start, specifying flags with OGCONN_XA_RESUME
*/
#ifdef WIN32
int ogconn_xa_end(ogconn_conn_t conn, unsigned __int64 flags);
#else
int ogconn_xa_end(ogconn_conn_t conn, uint64 flags);
#endif

/*
    Definition: prepare a transaction branch for commit
    Input param:
        conn : connection object
        xid : global transaction branch ID
        flags:
            OGCONN_XA_DEFAULT
        timestamp : current timestamp of TM, used for consistent read
            0 : consistent read not concerned
            !0 : consistent read concerned
    Return Value:
        0 : success
        !=0 : failed. use ogconn_get_error get latest error information. Typical errors are :
            ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
            ERR_XA_RDONLY : there is no local transaction, in other words there are no written operations between
   xa_start and xa_end Description: NA
*/
#ifdef WIN32
int ogconn_xa_prepare(ogconn_conn_t conn, ogconn_xid_t *xid, unsigned __int64 flags, struct timeval *timestamp);
#else
int ogconn_xa_prepare(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct timeval *ts);
#endif

/*
Definition: commit a transaction branch
Input param:
    conn : connection object
    xid : global transaction branch ID
    flags:
        OGCONN_XA_ONEPHASE : do one-phase commit
        OGCONN_XA_LGWR_BATCH : before being flushed to online redo log files, redo log of current branch is batched with
other branch's. OGCONN_XA_LGWR_WAIT : wait until redo log of current branch is flushed to online redo log files.
        OGCONN_XA_LGWR_NOWAIT : returns without waiting for redo log of current branch flushed to online redo log files.
        OGCONN_XA_LGWR_IMMED : redo log flush is triggered immediately.
        OGCONN_XA_DEFAULT : OGCONN_XA_LGWR_WAIT|OGCONN_XA_LGWR_IMMED and two phase commit
    timestamp : current timestamp of TM, used for consistent read
        0 : consistent read not concerned
        !0 : consistent read concerned
Return Value:
    0 : success
    !=0 : failed. use ogconn_get_error get latest error information. Typical errors are :
        ERR_XA_BRANCH_NOT_EXISTS : specified branch does not exists
Description: NA
*/
#ifdef WIN32
int ogconn_xa_commit(ogconn_conn_t conn, ogconn_xid_t *xid, unsigned __int64 flags, struct timeval *timestamp);
#else
int ogconn_xa_commit(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags, struct timeval *ts);
#endif

/*
    Definition: rollback a transaction branch
    Input param:
        conn : connection object
        xid : global transaction branch ID
        flags:
            OGCONN_XA_DEFAULT
    Return Value:
        0 : success
        !=0 : failed. use ogconn_get_error get latest error information.
    Description: NA
*/
#ifdef WIN32
int ogconn_xa_rollback(ogconn_conn_t conn, ogconn_xid_t *xid, unsigned __int64 flags);
#else
int ogconn_xa_rollback(ogconn_conn_t conn, ogconn_xid_t *xid, uint64 flags);
#endif

/*
    Definition: get status of a global transaction branch
    Input_param:
        conn : connection object
        xid : global transaction branch ID
    Output param:
        status : status of the specified transaction branch
    Return Value:
        0 : success
        !=0 : failed. use ogconn_get_error get latest error information.
    Description: NA
*/
int ogconn_xact_status(ogconn_conn_t conn, ogconn_xid_t *xid, ogconn_xact_status_t *status);
char *ogconn_get_typename_by_id(ogconn_type_t ogconn_type);
#ifdef __cplusplus
}
#endif

#endif
