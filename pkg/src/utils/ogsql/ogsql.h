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
 * ogsql.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGSQL_CMD_H
#define OGSQL_CMD_H

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_binary.h"
#include "cm_decimal.h"
#include "cm_encrypt.h"
#include "ogconn.h"
#include "ogconn_inner.h"
#include "ogconn_client.h"
#include "var_inc.h"
#include "cm_list.h"
#include "cm_charset.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup OGSQL_CMD
* @brief The API of `ogsql` command interface
* @{ */
#define MAX_ENTITY_LEN                   256
#define MAX_CMD_LEN                      65536
#define SPOOL_BUFFER_SIZE                SIZE_M(1)
#define MAX_COLUMN_WIDTH                 1024
#define MAX_SQL_SIZE                     SIZE_M(1)
#define FILE_BUFFER_SIZE                 SIZE_M(1)
#define OG_MIN_PAGESIZE                  (uint32)4
#define OGSQL_INTERACTION_DEFAULT_TIMEOUT (uint32)5
#define OGSQL_HISTORY_BUF_SIZE            4096
#define OGSQL_MAX_HISTORY_SIZE            20
#define OGSQL_UTF8_CHR_SIZE               6

#define CMD_KEY_ASCII_BS                 8
#define CMD_KEY_ASCII_DEL                127
#define CMD_KEY_ASCII_LF                 10
#define CMD_KEY_ASCII_CR                 13

#define CMD_KEY_ESCAPE                   27
#define CMD_KEY_UP                       65
#define CMD_KEY_DOWN                     66
#define CMD_KEY_DEL                      51

#define OGSQL_IS_STRING_TYPE_EX(type) (OG_IS_STRING_TYPE((type) + OG_TYPE_BASE))
#define OGSQL_IS_BINARY_TYPE_EX(type) (OG_IS_BINARY_TYPE((type) + OG_TYPE_BASE))
#define OGSQL_IS_LOB_TYPE(type)       (OG_IS_LOB_TYPE((type) + OG_TYPE_BASE))
#define OGSQL_IS_ENCLOSED_TYPE(type)  (OG_IS_VARLEN_TYPE((type) + OG_TYPE_BASE) || OGSQL_IS_LOB_TYPE(type))
#define OGSQL_IS_NUMBER_TYPE(type)    (OG_IS_NUMERIC_TYPE((type) + OG_TYPE_BASE))

#define OGSQL_SEC_FILE_NAME "data"
#define OGSQL_COPYRIGHT_VERSION 8

#define OGSQL_CONN_PARAM_COUNT 7
/* The OGSQL cmd-interface may use some function in common and lex module,
 * the error info need to separately process, its errmsg should be printed
 * by ogsql_print_error(NULL) */
typedef enum en_zs_errno {
    ZSERR_ERRNO_DEF = 0,
    ZSERR_OGSQL = 1,
    ZSERR_DUMP = 2,
    ZSERR_LOAD = 3,
    ZSERR_EXPORT = 4,
    ZSERR_IMPORT = 5,
    ZSERR_MAIN = 6,
    ZSERR_WSR = 7,
} zs_errno_t;

typedef enum en_ogsql_cmd {
    CMD_NONE = 0,
    CMD_SQL = 1,
    CMD_EXIT = 2,
    CMD_SHOW = 3,
    CMD_CONN = 4,
    CMD_EXEC = 5,
    CMD_SQLFILE = 8,  // @sqlfile
    CMD_CLEAR = 9,
    CMD_SET = 10,
    CMD_SPOOL = 11,
    CMD_COMMENT = 12,
    CMD_DESC = 13,
    CMD_DUMP = 14,
    CMD_LOAD = 15,
    CMD_COMMAND = 16,  // external cmd must be defined after CMD_LOAD
    CMD_FILE = 17,
    CMD_QUIT = 18,
    CMD_COLUMN = 19,
    CMD_SILENT = 20,
    CMD_SHELL = 21,
    CMD_EXPORT = 22,
    CMD_WHENEVER = 23,
    CMD_PROMPT = 24,
    CMD_AWR = 25,
    CMD_IMPORT = 27,
    CMD_SQLFILE2 = 28,  // @@ sqlfile
    CMD_LIST = 29,
    CMD_MONITOR = 30,
} ogsql_cmd_t;

typedef enum en_ogsql_cmd_mode {
    MODE_SINGLE_LINE,
    MODE_MULTI_LINE,
    MODE_NONE
} ogsql_cmd_mode;

typedef enum en_ogsql_line_tag {
    OGSQL_SINGLE_TAG = 0x0,
    OGSQL_BLOCK_TAG = 0x1,
    OGSQL_BLOCK_END_TAG = 0x2,
    OGSQL_MULTI_TAG = 0x4,
    OGSQL_MULTI_END_TAG = 0x8,
    OGSQL_COMMENT_TAG = 0x10,
    OGSQL_COMMENT_END_TAG = 0x20,
    OGSQL_EMPTY_TAG = 0x40,
} ogsql_line_tag_t;

typedef enum en_ogsql_trace_mode {
    OGSQL_TRACE_OFF = 0,
    OGSQL_TRACE_ON,
    OGSQL_TRACE_ONLY
} ogsql_trace_mode_t;

typedef struct st_ogsql_cmd_def {
    ogsql_cmd_t cmd;
    ogsql_cmd_mode mode;
    char *str;
} ogsql_cmd_def_t;

typedef struct st_ogsql_cmd_history_list {
    uint32 nbytes;
    uint32 nwidths;
    char hist_buf[OGSQL_HISTORY_BUF_SIZE];
} ogsql_cmd_history_list_t;

typedef struct st_ogsql_conn_info_t {
    ogconn_conn_t conn;
    ogconn_stmt_t stmt;
    char username[OG_NAME_BUFFER_SIZE + OG_STR_RESERVED_LEN];
    char schemaname[OG_NAME_BUFFER_SIZE + OG_STR_RESERVED_LEN];
    SENSI_INFO char passwd[OG_PASSWORD_BUFFER_SIZE + OG_STR_RESERVED_LEN];
    char server_url[CM_UNIX_DOMAIN_PATH_LEN + OG_TENANT_BUFFER_SIZE + OG_STR_RESERVED_LEN];
    char home[OG_MAX_PATH_BUFFER_SIZE];
    bool8 connect_by_install_user;
    bool8 is_conn;
    bool8 is_clsmgr;
    bool8 is_working;
} ogsql_conn_info_t;

typedef struct st_ogsql_timing_t {
    bool32 timing_on;
    date_t consumed_time;
} ogsql_timing_t;

typedef struct st_ogsql_feedback_t {
    bool32 feedback_on;
    uint32 feedback_rows;
} ogsql_feedback_t;

typedef struct st_ogsql_column_format_attr_t {
    bool32 is_on;
    uint32 col_width;
    char col_name[OG_MAX_NAME_LEN + 1];
} ogsql_column_format_attr_t;

typedef struct st_whenever_t {
    uint8 is_on;
    uint8 error_type;     // 0:SQLERROR 1:OSERROR
    uint8 continue_type;  // 0:EXIT     1:CONTINUE
    uint8 commit_type;    // 0:ROLLBACK 1:COMMIT
} whenever_t;

#define MAX_COLSEP_NAME_LEN 256
typedef struct st_ogsql_colsep_t {
    char colsep_name[MAX_COLSEP_NAME_LEN];
    uint32 colsep_len;
} ogsql_colsep_t;

typedef struct st_ogsql_local_info_t {
    bool32 auto_commit;  // attention: need add to connection
    bool32 exit_commit;  // attention: need add to connection
    uint32 charset_id;   // attention: need add to connection
    bool32 heading_on;
    bool32 server_ouput;  // attention: need add to connection
    bool32 trim_spool;
    bool32 spool_on;
    uint32 line_size;
    uint32 page_size;
    ogsql_timing_t timer;
    ogsql_feedback_t feedback;
    list_t column_formats;
    bool32 silent_on;
    bool32 print_on;
    whenever_t whenever;
    uint32 long_size;
    ogsql_colsep_t colsep;
    uint32 newpage;
    bool32 verify_on;
    bool32 termout_on;
    bool32 script_output;
    bool32 define_on;
    ogconn_ssl_mode_t ssl_mode;
    char ssl_ca[OG_FILE_NAME_BUFFER_SIZE];   /* PEM CA file */
    char ssl_cert[OG_FILE_NAME_BUFFER_SIZE]; /* PEM cert file */
    char ssl_key[OG_FILE_NAME_BUFFER_SIZE];  /* PEM key file */
    SENSI_INFO char ssl_keypwd[OG_MAX_CIPHER_LEN + 4];  /* PSWD cipher for private key */
    char ssl_crl[OG_FILE_NAME_BUFFER_SIZE];  /* SSL CRL */
    char ssl_cipher[OG_PARAM_BUFFER_SIZE];   /* Algorithm cipher */
    bool32 is_cancel;
    bool32 OGSQL_SSL_QUIET;
    uint32 OGSQL_INTERACTION_TIMEOUT;
    int32 connect_timeout;
    int32 socket_timeout;
    char  server_path[OG_UNIX_PATH_MAX];
    char  client_path[OG_UNIX_PATH_MAX];
    bool32 bindparam_force_on;
    uint8 shd_rw_split;  // attention: need add to connection
    bool32 history_on;
    uint32 trace_mode;
} ogsql_local_config_t;

extern ogsql_local_config_t g_local_config;
extern ogsql_conn_info_t g_conn_info;
extern ogconn_inner_column_desc_t g_columns[OG_MAX_COLUMNS];
extern char g_cmd_buf[MAX_CMD_LEN + 2];
extern char g_sql_buf[MAX_SQL_SIZE + 4];
extern char g_str_buf[OG_MAX_PACKET_SIZE + 1];  // for print a column data
extern char g_replace_mark;
extern bool32 g_is_print;

#define IS_CONN   g_conn_info.is_conn
#define IS_WORKING g_conn_info.is_working
#define OGSQL_CANCELING g_local_config.is_cancel
#define CONN      g_conn_info.conn
#define STMT      g_conn_info.stmt
#define OG_HOME   g_conn_info.home
#define USER_NAME g_conn_info.schemaname
#define STDOUT    1

/* For sharing global memory when data dumping and loading */
#define USE_OGSQL_COLUMN_DESC

extern status_t ogsql_alloc_conn(ogconn_conn_t *pconn);
extern void ogsql_print_error(ogconn_conn_t conn);
extern void ogsql_try_spool_put(const char *fmt, ...);
extern void ogsql_init(int32 argc, char *argv[]);
extern void ogsql_run(FILE *in, bool32 is_file, char *cmd_buf, uint32 max_len);
extern void ogsql_exit(bool32 from_whenever, status_t status);
extern status_t ogsql_connect(text_t *conn_text);
extern uint32 ogsql_print_welcome(uint32 multi_line, uint32 line_no);
extern status_t ogsql_conn_to_server(ogsql_conn_info_t *conn_info, bool8 print_conn, bool8 is_background);
extern void ogsql_free_config(void);
void ogsql_print_result(void);
void ogsql_get_error(ogconn_conn_t conn, int *code, const char **message, source_location_t *loc);
void ogsql_set_error(const char *file, uint32 line, zs_errno_t code, const char *format, ...) OG_CHECK_FMT(4, 5);
status_t ogsql_set_trx_iso_level(text_t *line);
status_t ogsql_execute_sql(void);

#define ogsql_printf(fmt, ...)                   \
    do {                                        \
        if (!g_local_config.silent_on) {        \
            printf(fmt, ##__VA_ARGS__);         \
            fflush(stdout);                     \
        }                                       \
        ogsql_try_spool_put(fmt, ##__VA_ARGS__); \
    } while (0)

#define ogsql_write(len, fmt, ...)                                      \
    do {                                                               \
        if (!g_local_config.silent_on) {                               \
            int ret __attribute__((unused)) = write(STDOUT, fmt, len); \
        }                                                              \
        ogsql_try_spool_put(fmt, ##__VA_ARGS__);                        \
    } while (0)

#define OGSQL_PRINTF(err_no, fmt, ...)                                                   \
    {                                                                                   \
        ogsql_set_error((char *)__FILE__, (uint32)__LINE__, err_no, fmt, ##__VA_ARGS__); \
    }

#define OGSQL_CHECK_MEMS_SECURE(ret)                    \
    do {                                               \
        int32 __code__ = (ret);                        \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                    \
        }                                              \
    } while (0)

static inline void ogsql_print_disconn_error(void)
{
    ogsql_printf("OG-%05d, %s\n", ERR_CLT_CONN_CLOSE, "connect is not established");
}
#define OGSQL_MAX_HIDED_PWD_LEN 1u
/**
 * Erase the from the connection string, and substitute it by
 * stars. Here, pwd_text contains the position and the length of the
 * pswd. It is a part of conn_text.

 */
static inline void ogsql_erase_pwd(text_t *conn_text, text_t *pwd_text)
{
    text_t remain;
    size_t offset;
    errno_t errcode;
    errno_t rc_memmove;

    if (pwd_text->len <= OGSQL_MAX_HIDED_PWD_LEN) {
        (void)cm_text_set(pwd_text, pwd_text->len, '*');
        return;
    }

    (void)cm_text_set(pwd_text, OGSQL_MAX_HIDED_PWD_LEN, '*');

    /* obtain the text after @ip:port */
    remain.str = pwd_text->str + pwd_text->len;
    remain.len = conn_text->len - (uint32)(remain.str - conn_text->str);
    offset = conn_text->len - (pwd_text->str + OGSQL_MAX_HIDED_PWD_LEN - conn_text->str);
    rc_memmove = memmove_s(pwd_text->str + OGSQL_MAX_HIDED_PWD_LEN, offset, remain.str, remain.len);
    if (rc_memmove != EOK) {
        ogsql_printf("Moving remain.str has thrown an error %d", rc_memmove);
        return;
    }
    /* obtain the unused text, reset them to 0 */
    remain.len = pwd_text->len - OGSQL_MAX_HIDED_PWD_LEN;
    remain.str = conn_text->str + conn_text->len - remain.len;
    offset = conn_text->len - (remain.str - conn_text->str);
    if (remain.len != 0) {
        errcode = memset_s(remain.str, offset, 0, remain.len);
        if (errcode != EOK) {
            ogsql_printf("Secure C lib has thrown an error %d", errcode);
            return;
        }
    }
    pwd_text->len = OGSQL_MAX_HIDED_PWD_LEN;
    conn_text->len -= remain.len;
}
/** @} */  // end group OGSQL_CMD

static inline int ogsql_nlsparam_geter(char *nlsbuf, int nls_id, text_t *text)
{
    uint32 fmtlen;
    if (ogconn_get_conn_attr(CONN, ((nls_id) + OGCONN_ATTR_NLS_CALENDAR),
                          (nlsbuf), MAX_NLS_PARAM_LENGTH, &fmtlen) != OGCONN_SUCCESS) {
        ogsql_print_error(CONN);
        return OGCONN_ERROR;
    }
    text->str = nlsbuf;
    text->len = fmtlen;
    return OGCONN_SUCCESS;
}

/* Used to inspect whether the input text is too long  */
#define OGSQL_BUF_RESET_CHAR EOF

/* Reset the single-line command buffer */
static inline void ogsql_reset_cmd_buf(char *cmd_buf, uint32 max_len)
{
    cmd_buf[max_len - 1] = OGSQL_BUF_RESET_CHAR;
    cmd_buf[max_len - 2] = OGSQL_BUF_RESET_CHAR;
    if (memset_s(cmd_buf, max_len, 0, MAX_CMD_LEN) != EOK) {
        return;
    }
}

EXTER_ATTACK status_t ogsql_process_cmd(text_t *line);
EXTER_ATTACK status_t ogsql_execute(text_t *line);
void ogsql_silent(text_t *line);
status_t ogsql_cancel(void);
status_t ogsql_conn_cancel(ogsql_conn_info_t *conn_info);
status_t ogsql_recv_passwd_from_terminal(char *buff, int32 buff_size);
static inline status_t ogsql_reset_charset(uint32 charset_id, uint32 curr_charset_id)
{
    if (charset_id == curr_charset_id) {
        return OG_SUCCESS;
    }
    const char *pcharset_name = cm_get_charset_name((charset_type_t)charset_id);
    if (pcharset_name == NULL) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return OG_ERROR;
    }

    (void)ogconn_set_conn_attr(CONN, OGCONN_ATTR_CHARSET_TYPE, pcharset_name, (uint32)strlen(pcharset_name));

    return OG_SUCCESS;
}

status_t ogsql_get_local_server_kmc_privilege(char *home, char *passwd, uint32 pwd_len, bool32 is_ztrst);

#ifdef __cplusplus
}
#endif

#endif  // end OGSQL_CMD_H
