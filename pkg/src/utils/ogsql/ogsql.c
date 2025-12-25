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
 * ogsql.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql.c
 *
 * -------------------------------------------------------------------------
 */
#include <locale.h>
#include "cm_kmc.h"
#include "cm_base.h"
#include "cm_encrypt.h"
#include "ogsql_common.h"
#include "ogsql.h"
#include "ogsql_dump.h"
#include "ogsql_wsr.h"
#include "ogsql_export.h"
#include "ogsql_import.h"
#include "ogsql_input_bind_param.h"
#include "ogsql_load.h"
#include "ogsql_option.h"
#include "cm_config.h"
#include "cm_log.h"
#include "cm_timer.h"
#include "cm_system.h"
#include "cm_utils.h"
#include "cm_util.h"
#include "cm_hash.h"
#include "ogsql_wsr_monitor.h"
#include "cm_encrypt.h"

#ifdef WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
extern char **environ;
#endif
#include "cm_lex.h"

static const ogsql_cmd_def_t g_cmd_defs[] = {
    { CMD_EXEC,     MODE_SINGLE_LINE, "/" },
    { CMD_CLEAR,    MODE_SINGLE_LINE, "clear" },
    { CMD_COLUMN,   MODE_SINGLE_LINE, "col" },
    { CMD_COLUMN,   MODE_SINGLE_LINE, "column" },
    { CMD_CONN,     MODE_SINGLE_LINE, "conn" },
    { CMD_CONN,     MODE_SINGLE_LINE, "connect" },
    { CMD_DESC,     MODE_SINGLE_LINE, "desc" },
    { CMD_DESC,     MODE_SINGLE_LINE, "describe" },
    { CMD_DUMP,     MODE_MULTI_LINE,  "dump" },
    { CMD_EXIT,     MODE_SINGLE_LINE, "exit" },
    { CMD_EXPORT,   MODE_MULTI_LINE,  "exp" },
    { CMD_EXPORT,   MODE_MULTI_LINE,  "export" },
    { CMD_IMPORT,   MODE_MULTI_LINE,  "imp" },
    { CMD_IMPORT,   MODE_MULTI_LINE,  "import" },
    { CMD_LOAD,     MODE_MULTI_LINE,  "load" },
    { CMD_MONITOR,  MODE_SINGLE_LINE, "monitor" },
    { CMD_PROMPT,   MODE_SINGLE_LINE, "pro" },
    { CMD_PROMPT,   MODE_SINGLE_LINE, "prompt" },
    { CMD_EXIT,     MODE_SINGLE_LINE, "quit" },
    { CMD_SET,      MODE_SINGLE_LINE, "set" },
    { CMD_SHOW,     MODE_SINGLE_LINE, "show" },
    { CMD_SPOOL,    MODE_SINGLE_LINE, "spool" },
    { CMD_SQLFILE,  MODE_SINGLE_LINE, "start" },  // start sqlfile is same as @sqlfile
    { CMD_WHENEVER, MODE_SINGLE_LINE, "whenever" },
    { CMD_AWR,      MODE_SINGLE_LINE, "wsr" },
};
#define OGSQL_CMD_COUNT (sizeof(g_cmd_defs) / sizeof(ogsql_cmd_def_t))

/* Three immediate command */
static const ogsql_cmd_def_t CMD_NONE_TYPE = { CMD_NONE,     MODE_NONE,        NULL };
static const ogsql_cmd_def_t CMD_COMMENT_TYPE = { CMD_COMMENT,  MODE_NONE,        "--" };
static const ogsql_cmd_def_t CMD_SQLFILE_TYPE = { CMD_SQLFILE,  MODE_SINGLE_LINE, NULL };
static const ogsql_cmd_def_t CMD_SQLFILE_TYPE2 = { CMD_SQLFILE2, MODE_SINGLE_LINE, NULL };
static const ogsql_cmd_def_t CMD_SQL_TYPE = { CMD_SQL,      MODE_MULTI_LINE,  NULL };
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static const ogsql_cmd_def_t CMD_SHELL_TYPE = { CMD_SHELL, MODE_SINGLE_LINE, "\\!" };
#endif

#define OGSQL_RESET_CMD_TYPE(cmd_type) ((*(cmd_type)) = CMD_NONE_TYPE)

/* Stores the history when the 'HISTORY' is turned on */
static ogsql_cmd_history_list_t g_hist_list[OGSQL_MAX_HISTORY_SIZE];

config_item_t g_ogsql_parameters[] = {
    // name (30B)                     isdefault readonly  defaultvalue value runtime_value description range  datatype comment
    // -------------                  --------- --------  ------------ ----- ------------- ----------- -----  --------- -----
    { "OGSQL_SSL_QUIET", OG_TRUE, OG_TRUE, "FALSE", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "OGSQL_INTERACTION_TIMEOUT", OG_TRUE, OG_TRUE, "5", NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 1, EFFECT_REBOOT, CFG_INS, NULL, NULL },
};

config_item_t g_client_parameters[] = {
    // name (30B)                     isdefault readonly  defaultvalue value runtime_value description range  datatype comment
    // -------------                  --------- --------  ------------ ----- ------------- ----------- -----  -------------
    { "LSNR_ADDR", OG_TRUE, OG_TRUE, "127.0.0.1",          NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "LSNR_PORT", OG_TRUE, OG_TRUE, "1611",               NULL, NULL, "-", "-", "OG_TYPE_INTEGER", NULL, 1, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "LOCAL_KEY", OG_TRUE, OG_TRUE, "", NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, 2, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "KMC_KEY_FILES", OG_TRUE, OG_TRUE, "",               NULL, NULL, "-", "-", "OG_TYPE_VARCHAR", NULL, 2, EFFECT_REBOOT, CFG_INS, NULL, NULL },
    /* operation log */
    { "LOG_HOME",               OG_TRUE, OG_TRUE,  "",    NULL, NULL, "-", "-",          "OG_TYPE_VARCHAR", NULL, 3, EFFECT_REBOOT,      CFG_INS, NULL, NULL },
    { "_LOG_BACKUP_FILE_COUNT", OG_TRUE, OG_FALSE, "10",  NULL, NULL, "-", "[0,1024]", "OG_TYPE_INTEGER", NULL, 4, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
    { "_LOG_MAX_FILE_SIZE",     OG_TRUE, OG_FALSE, "10M", NULL, NULL, "-", "(0,-)",    "OG_TYPE_INTEGER", NULL, 5, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
    { "_LOG_FILE_PERMISSIONS",  OG_TRUE, OG_FALSE, "640", NULL, NULL, "-", "-",          "OG_TYPE_INTEGER", NULL, 6, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
    { "_LOG_PATH_PERMISSIONS",  OG_TRUE, OG_FALSE, "750", NULL, NULL, "-", "-",          "OG_TYPE_INTEGER", NULL, 7, EFFECT_IMMEDIATELY, CFG_INS, NULL, NULL },
};
#define OGSQL_PARAMS_COUNT (sizeof(g_ogsql_parameters) / sizeof(config_item_t))
#define OGSQL_PARAMS_COUNT1 (sizeof(g_client_parameters) / sizeof(config_item_t))

spinlock_t g_client_parameters_lock = 0;
spinlock_t g_server_config_lock = 0;
config_t *g_ogsql_config = NULL;
config_t *g_server_config = NULL;

ogsql_local_config_t g_local_config;
ogsql_conn_info_t g_conn_info;
const char *g_env_data = "OGDB_DATA";

const char *g_ogsql_config_file = "ogsql.ini";
const char *g_config_file = "ogracd.ini";
bool32 g_is_print = OG_FALSE;  // Output sql command of executing sql file
char g_replace_mark = '&';

/* Output the results into file, which can be specified by SPOOL command */
static file_t g_spool_file = OG_NULL_FILE;
static char g_spool_buf[SPOOL_BUFFER_SIZE];
/* The maximal single line cmd is MAX_CMD_LEN. Here, the extra two bytes
 * used to reject too long inputs */
char g_cmd_buf[MAX_CMD_LEN + 2];
static uint32 g_column_count = 0;
static uint32 g_display_widths[OG_MAX_COLUMNS];
static bool32 g_col_display[OG_MAX_COLUMNS];
static text_t g_sql_text;
static ogsql_cmd_def_t g_cmd_type;
ogconn_inner_column_desc_t g_columns[OG_MAX_COLUMNS];
char g_str_buf[OG_MAX_PACKET_SIZE + 1] = { 0 };
char g_array_buf[OG_MAX_PACKET_SIZE + 1] = { 0 };
char g_sql_buf[MAX_SQL_SIZE + 4];
spinlock_t g_cancel_lock = 0;
static int32 g_in_enclosed_char = -1;
static int32 g_in_comment_count = 0;

extern char g_load_pswd[];
extern status_t loader_save_pswd(char *orig_pswd, uint32 orig_len);
extern void loader_save_user(char *orig_user, uint32 orig_len);
extern void ogsql_free_user_pswd(void);

static void ogsql_print_resultset(void);
static void ogsql_describe_columns(void);
static void ogsql_print_column_data(void);
static bool32 ogsql_fetch_cmd(text_t *line, text_t *sub_cmd);
static void ogsql_print_serveroutput(void);
static status_t ogsql_process_autotrace_cmd(void);
/* the definition should be the same as the CLIENT_KIND_OGSQL of client_kind_t(cs_protocol.h) */
#define CLIENT_KIND_OGSQL ((int16)3)

#define OGSQL_MAX_LONG_SIZE    80
#define OGSQL_MAX_LOGFILE_SIZE 10000
#define OGSQL_LOG_LEVEL        512

static inline void ogsql_reset_in_enclosed_char(void)
{
    g_in_enclosed_char = -1;
}

/* Spool */
static void ogsql_spool_off(void)
{
    if (g_spool_file == OG_NULL_FILE) {
        ogsql_printf("not spooling currently");
        return;
    }

    cm_close_file(g_spool_file);
    g_spool_file = OG_NULL_FILE;
    g_local_config.spool_on = OG_FALSE;
}

static status_t ogsql_spool_on(const char *file_name)
{
    if (g_spool_file != OG_NULL_FILE) {
        ogsql_spool_off();
    }

    if (file_name != NULL) {
        return cm_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, &g_spool_file);
    }

    return OG_SUCCESS;
}

static inline void ogsql_try_spool_directly_put(const char *str)
{
    text_t output_sql;

    if (g_local_config.silent_on) {
        return;
    }

    if (g_spool_file == OG_NULL_FILE) {
        return;
    }

    ogsql_regular_match_sensitive(str, strlen(str), &output_sql);
    (void)cm_write_str(g_spool_file, output_sql.str);
}

void ogsql_try_spool_put(const char *fmt, ...)
{
    va_list var_list;
    int32 len;
    if (g_spool_file == OG_NULL_FILE) {
        return;
    }

    va_start(var_list, fmt);
    len = vsnprintf_s(g_spool_buf, SPOOL_BUFFER_SIZE, SPOOL_BUFFER_SIZE - 1, fmt, var_list);
    PRTS_RETVOID_IFERR(len);
    va_end(var_list);
    if (len <= 0) {
        return;
    }

    if (g_local_config.trim_spool && g_spool_buf[len - 1] != '\n') {
        text_t trim_spool = { g_spool_buf, len };
        cm_trim_text(&trim_spool);
        len = trim_spool.len;
        (void)cm_write_file(g_spool_file, g_spool_buf, (uint32)len);
    } else {
        (void)cm_write_file(g_spool_file, g_spool_buf, (uint32)len);
    }
}

void ogsql_set_error(const char *file, uint32 line, zs_errno_t code, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    int iret;
    char log_msg[OG_MESSAGE_BUFFER_SIZE];

    iret = vsnprintf_s(log_msg, OG_MESSAGE_BUFFER_SIZE, OG_MESSAGE_BUFFER_SIZE - 1, format, args);
    PRTS_RETVOID_IFERR(iret);

    ogsql_printf("ZS-%05d: %s\n", code, log_msg);

    va_end(args);
}

void ogsql_get_error(ogconn_conn_t conn, int *code, const char **message, source_location_t *loc)
{
    if (g_tls_error.code != OG_SUCCESS) {
        cm_get_error(code, message, loc);
        return;
    }

    ogconn_get_error(conn, code, message);
    if (loc != NULL) {
        ogconn_get_error_position(conn, &loc->line, &loc->column);
    }
}

/**
 * Print the error into OGSQL client, if conn is null, the error may occur
 * from OGSQL tools, otherwise we get the error message from conn.
 */
void ogsql_print_error(ogconn_conn_t conn)
{
    int code = 0;
    const char *message = "";
    source_location_t loc;

    ogsql_get_error(conn, &code, &message, &loc);

    if (code == OG_SUCCESS) {
        return;
    }

    if (loc.line == 0) {
        ogsql_printf("OG-%05d, %s\n", code, message);
    } else {
        ogsql_printf("OG-%05d, [%d:%d]%s\n", code, (int)loc.line, (int)loc.column, message);
    }

    cm_reset_error();
}

static bool32 ogsql_find_cmd(text_t *line_text, ogsql_cmd_def_t *cmdtype)
{
    text_t cmd_text;
    int32 begin_pos;
    int32 end_pos;
    int32 mid_pos;
    int32 cmp_result;
    const ogsql_cmd_def_t *def = NULL;

    if (!cm_fetch_text(line_text, ' ', 0, &cmd_text)) {
        return OG_FALSE;
    }
    begin_pos = 0;
    end_pos = OGSQL_CMD_COUNT - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        def = &g_cmd_defs[mid_pos];

        cmp_result = cm_compare_text_str_ins(&cmd_text, def->str);
        if (cmp_result == 0) {
            if (def->cmd == CMD_EXEC && line_text->len > 0) {
                break;
            }
            *cmdtype = *def;
            return OG_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    *cmdtype = CMD_SQL_TYPE;  // the default is SQL_TYPE
    return OG_TRUE;
}

static int32 ogsql_get_one_char()
{
#ifdef WIN32
    return _getch();
#else
    int32 char_ascii;
    struct termios oldt;
    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, &oldt);
    MEMS_RETURN_IFERR(memcpy_s(&newt, sizeof(newt), &oldt, sizeof(oldt)));
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    char_ascii = getchar();

    /* Restore the old setting of terminal */
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return char_ascii;
#endif
}

status_t ogsql_recv_passwd_from_terminal(char *buff, int32 buff_size)
{
    int32 pos = 0;
    char char_ascii;
    int32 key = 0;

    if (buff == NULL) {
        return OG_ERROR;
    }
    do {
        key = ogsql_get_one_char();
#ifndef WIN32
        if (key == EOF) {
            OGSQL_PRINTF(ZSERR_OGSQL, "ogsql_get_one_char return -1 \n");
            return OG_ERROR;
        }
#endif
        char_ascii = (char)key;

#ifdef WIN32
        if (char_ascii == KEY_BS) {
#else
        if (char_ascii == KEY_BS || char_ascii == KEY_BS_LNX) {
#endif
            if (pos > 0) {
                buff[pos] = '\0';
                pos--;

                /*
                 * Recv a key of backspace, print a '\b' backing a char
                   and printing
                 * a space replacing the char displayed to screen
                   with the space.
                 */
                ogsql_printf("\b");
                ogsql_printf(" ");
                ogsql_printf("\b");
            } else {
                continue;
            }
        } else if (char_ascii == KEY_LF || char_ascii == KEY_CR) {
            break;
        } else {
            /*
             * Only recv the limited length of pswd characters, on beyond,
             * contine to get a next char entered by user.
             */
            if (pos >= buff_size) {
                continue;
            }

            /* Faking a mask star * */
            ogsql_printf("*");
            buff[pos] = char_ascii;
            pos++;
        }
    } while (OG_TRUE);

    buff[pos < buff_size ? pos : buff_size - 1] = '\0';
    ogsql_printf("\n");
    return OG_SUCCESS;
}

static status_t ogsql_fetch_user_with_quot(text_t *user, text_t *password)
{
    uint32 i;
    uint32 next;
    char quot = password->str[0];  // get double or single quotation marks
    // "@url, connection string only one quot; ""/pwd@url ---username expected at connection string
    if (password->len <= 2 || password->str[1] == quot) {
        OGSQL_PRINTF(ZSERR_OGSQL, "username expect");
        return OG_ERROR;
    }

    for (i = 1; i < password->len; i++) {
        if (password->str[i] != quot) {
            continue;
        } else {
            user->str = password->str + 1;
            user->len = i - 1;
            break;
        }
    }

    if (i == password->len) {  // "XXXXXX@url, only one quot find from connection string
        OGSQL_PRINTF(ZSERR_OGSQL, "quotation need to be used in pairs");
        return OG_ERROR;
    }

    next = i + 1;

    // fetch pwd
    if (next == password->len) {  // "user"@url, need input pwd later
        password->len = 0;
        password->str = NULL;
    } else if ((password->str[next]) != '/') {
        // "user"pwd@url, no '/' find after right quot
        OGSQL_PRINTF(ZSERR_OGSQL, "'/' expect between username and password");
        return OG_ERROR;
    } else {
        if ((i + 2) == password->len) {  // "user"/@url, pwd expected  at connection string
            OGSQL_PRINTF(ZSERR_OGSQL, "password expect");
            return OG_ERROR;
        } else {  // "user"/pwd@url  get pwd
            password->len = password->len - i - 2;
            password->str = password->str + i + 2;
        }
    }
    return OG_SUCCESS;
}

/* ogsql support interactive and command mode to  input pwd */
static int32 ogsql_try_fetch_user_pwd(char **sql_tmp, ogsql_conn_info_t *conn_info)
{
    text_t user;
    text_t password;
    uint32 quot_tag = OG_FALSE;  // if username  with quot or not
    errno_t errcode = 0;

    cm_str2text(sql_tmp[1], &password);
    /* fetch username */
    // if username with quot or not,if username with quot,may be have '/', can not direct split by '/'
    if (password.str[0] == '\"' || password.str[0] == '\'') {
        quot_tag = OG_TRUE;
        if (ogsql_fetch_user_with_quot(&user, &password) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        (void)cm_fetch_text(&password, '/', 0, &user);
    }

    if (password.len != 0) {
        cm_text2str_with_upper(&user, conn_info->username, sizeof(conn_info->username));
        /* fetch pswd */
        OG_RETURN_IFERR(cm_text2str(&password, conn_info->passwd, sizeof(conn_info->passwd)));
        /* ignore the pswd */
        OG_RETURN_IFERR(cm_text_set(&password, password.len, '*'));
    } else {
        // if quot_tag is true ,need get name  after trim quot,else direct copy from sql_temp
        if (quot_tag == OG_TRUE) {
            cm_text2str_with_upper(&user, conn_info->username, sizeof(conn_info->username));
        } else {
            errcode = strncpy_s(conn_info->username, sizeof(conn_info->username), sql_tmp[1], strlen(sql_tmp[1]));
            if (errcode != EOK) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                return OG_ERROR;
            }
            cm_str_upper(conn_info->username);
        }

        /* fetch pswd */
        ogsql_printf("Please enter password: \n");
        if (ogsql_recv_passwd_from_terminal(conn_info->passwd, sizeof(conn_info->passwd)) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (user.len > OG_NAME_BUFFER_SIZE || password.len > OG_PASSWORD_BUFFER_SIZE) {
        OGSQL_PRINTF(ZSERR_OGSQL, "user, password or URL overlength");
        return OG_ERROR;
    }
    if (strlen(conn_info->passwd) == 0 && password.len == 0) {
        OGSQL_PRINTF(ZSERR_OGSQL, "no password supplied");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogsql_init_home(void)
{
    char *home = NULL;
    bool32 is_home_exist = OG_FALSE;

    char path[OG_MAX_PATH_BUFFER_SIZE] = { 0x00 };
    if (0 == strlen(OG_HOME)) {
        home = getenv(g_env_data);
        if (home == NULL) {
            OG_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, g_env_data);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(realpath_file(home, path, OG_MAX_PATH_BUFFER_SIZE));
        if (cm_check_exist_special_char(path, (uint32)strlen(path))) {
            OG_THROW_ERROR(ERR_INVALID_DIR, home);
            return OG_ERROR;
        }
        PRTS_RETURN_IFERR(snprintf_s(OG_HOME, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s", home));
    }
    is_home_exist = cm_dir_exist(OG_HOME);
    if (is_home_exist == OG_FALSE) {
        OG_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, OG_ENV_HOME);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogsql_get_home(void)
{
    OG_RETURN_IFERR(ogsql_init_home());
    if (strlen(OG_HOME) != 0) {
        PRTS_RETURN_IFERR(snprintf_s(g_local_config.server_path, OG_UNIX_PATH_MAX, OG_UNIX_PATH_MAX - 1,
            "%s/protect/%s", OG_HOME, OGDB_UDS_EMERG_SERVER));
    }

    return OG_SUCCESS;
}

static status_t ogsql_try_parse_cmd_split_normal(char **sql_tmp, int32 split_num, ogsql_conn_info_t *conn_info)
{
    bool32 is_has_sysdba = OG_FALSE;
    bool32 is_has_datadir = OG_FALSE;
    if (split_num == 2) {
        OGSQL_PRINTF(ZSERR_OGSQL, "DB url is expected");
        return OG_ERROR;
    }

    /* "connect .../... ipc|ip:port|direct [AS SYSDBA]" */
    if (split_num == 4 || split_num >= 8) {
        OGSQL_PRINTF(ZSERR_OGSQL, "String \"%s\" is redundant", sql_tmp[split_num - 1]);
        return OG_ERROR;
    }

    for (int32 i = 3; i < split_num; i += 2) {
        if ((sql_tmp[i] != NULL) && (sql_tmp[i + 1] != NULL)) {
            if (cm_compare_str_ins(sql_tmp[i], (const char *)"AS") == 0) {
                if (cm_compare_str_ins(sql_tmp[i + 1], (const char *)"SYSDBA") != 0) {
                    OGSQL_PRINTF(ZSERR_OGSQL, "cmd error, please check cmd after url.");
                    return OG_ERROR;
                }
                if (is_has_sysdba == OG_FALSE) {
                    is_has_sysdba = OG_TRUE;
                } else {
                    OGSQL_PRINTF(ZSERR_OGSQL, "cmd error, please check cmd after url.");
                    return OG_ERROR;
                }
            } else if (cm_compare_str_ins(sql_tmp[i], (const char *)"-D") == 0) {
                if (!cm_dir_exist(sql_tmp[i + 1])) {
                    OGSQL_PRINTF(ZSERR_OGSQL, "cmd error, please check cmd after url.");
                    return OG_ERROR;
                }
                if (is_has_datadir == OG_FALSE) {
                    is_has_datadir = OG_TRUE;
                } else {
                    OGSQL_PRINTF(ZSERR_OGSQL, "cmd error, please check cmd after url.");
                    return OG_ERROR;
                }
            } else {
                OGSQL_PRINTF(ZSERR_OGSQL, "cmd error, please check cmd after url.");
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

/* check login by install user.
* "conn / as sysdba [host:port] [-D data_dir]"
*/
static status_t ogsql_try_parse_cmd_split_dba(char **sql_tmp, int32 split_num, ogsql_conn_info_t *conn_info)
{
    text_t text;
    text_t part1;
    text_t part2;
    if (split_num <= 3) {
        OGSQL_PRINTF(ZSERR_OGSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return OG_ERROR;
    }

    if (!cm_str_equal_ins(sql_tmp[1], "/")) {
        OGSQL_PRINTF(ZSERR_OGSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return OG_ERROR;
    }

    if (!cm_str_equal_ins(sql_tmp[2], "as")) {
        OGSQL_PRINTF(ZSERR_OGSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return OG_ERROR;
    }

    if (cm_str_equal_ins(sql_tmp[3], CM_SYSDBA_USER_NAME)) {
        MEMS_RETURN_IFERR(strncpy_s(conn_info->username, sizeof(conn_info->username), CM_SYSDBA_USER_NAME,
            strlen(CM_SYSDBA_USER_NAME)));
    } else if (cm_str_equal_ins(sql_tmp[3], CM_CLSMGR_USER_NAME)) {
        MEMS_RETURN_IFERR(strncpy_s(conn_info->username, sizeof(conn_info->username), CM_CLSMGR_USER_NAME,
            strlen(CM_SYSDBA_USER_NAME)));
    } else {
        OGSQL_PRINTF(ZSERR_OGSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return OG_ERROR;
    }

    conn_info->connect_by_install_user = OG_TRUE;

    for (int32 i = 4; i < split_num; i++) {
        if (cm_str_equal(sql_tmp[i], "-D")) {
            if ((i != split_num - 2) || (sql_tmp[i + 1] == NULL)) {
                OGSQL_PRINTF(ZSERR_OGSQL,
                    "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
                return OG_ERROR;
            }
            MEMS_RETURN_IFERR(strncpy_s(conn_info->home, sizeof(conn_info->home),
                sql_tmp[i + 1], strlen(sql_tmp[i + 1])));
            break;
        } else if (cm_utf8_str_like(sql_tmp[i], "%:%")) {
            cm_str2text(sql_tmp[i], &text);
            (void)cm_split_rtext(&text, ':', '\0', &part1, &part2);
            if (part1.len > CM_MAX_IP_LEN || !cm_is_short(&part2)) {
                OGSQL_PRINTF(ZSERR_OGSQL, "Invalid URL : %s", sql_tmp[i]);
                return OG_ERROR;
            }
        } else {
            OGSQL_PRINTF(ZSERR_OGSQL,
                "\"/ AS SYSDBA [host:port] [-D data_dir] \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
            return OG_ERROR;
        }
    }
    
    return OG_SUCCESS;
}

static status_t ogsql_try_parse_cmd_split(char **sql_tmp, int32 split_num, ogsql_conn_info_t *conn_info)
{
    if (split_num == 0 || (cm_strcmpni(sql_tmp[0], "conn", strlen("conn")) != 0 &&
        cm_strcmpni(sql_tmp[0], "connect", strlen("connect")) != 0)) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Keyword \"CONNECT\" is expected");
        return OG_ERROR;
    }

    if (split_num == 1) {
        OGSQL_PRINTF(ZSERR_OGSQL,
            "\"/ AS SYSDBA [host:port] [-D data_dir] \", \"username@ip:port \", \"username/password@ip:port \", or \"/ AS CLSMGR [host:port] [-D data_dir] \" is expected");
        return OG_ERROR;
    }
    /* check login by install user.
    * "conn / as sysdba [host:port] [-D data_dir]"
    */
    if (sql_tmp[1][0] == '/') {
        return ogsql_try_parse_cmd_split_dba(sql_tmp, split_num, conn_info);
    } else {
        return ogsql_try_parse_cmd_split_normal(sql_tmp, split_num, conn_info);
    }
}

/************************************************************************/
/* devide sql command by character blank ' ', '\t' or '\n', words in "" */
/* are regard as one word                                               */
/************************************************************************/
static status_t ogsql_local_cmd_split(text_t *conn_text,
                                     bool32 enable_mark,
                                     char **sql_split,
                                     int32 max_split_num,
                                     int32 *split_num)
{
    text_t sql_tmp;
    int32 idx = 0;

    if (sql_split == NULL || split_num == NULL) {
        return OG_ERROR;
    }

    for (idx = 0, *split_num = 0; idx < max_split_num; idx++) {
        if (!cm_fetch_text(conn_text, ' ', 0, &sql_tmp)) {
            break;
        }

        CM_NULL_TERM(&sql_tmp);
        sql_split[idx] = sql_tmp.str;

        /* trim the excrescent blank */
        cm_trim_text(conn_text);
    }

    *split_num = idx;
    if (!CM_IS_EMPTY(conn_text)) {
        OGSQL_PRINTF(ZSERR_OGSQL, "String \"%s\" is redundant", conn_text->str);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogsql_split_url(text_t *conn_text, text_t *url_text, bool32 *bATFound)
{
    text_t sub_text;
    text_t sub_text1;
    if (cm_fetch_rtext(conn_text, '@', '\0', &sub_text)) {
        if (conn_text->len == 0) {
            OGSQL_PRINTF(ZSERR_OGSQL, "no URL found after '@'");
            return OG_ERROR;
        }
        for (uint32 i = 0; i < conn_text->len; i++) {
            if (conn_text->str[i] == '-' && i + 1 <= conn_text->len && conn_text->str[i + 1] == '-') {
                url_text->len -= (conn_text->len - i);
                break;
            }
        }
        *bATFound = OG_TRUE;
        *CM_GET_TAIL(&sub_text) = ' ';
        if (cm_fetch_rtext(&sub_text, ' ', 0, &sub_text1)) {
            if (sub_text.len == 0) {
                ogsql_printf("incorrect user or passwd");
                return OG_ERROR;
            }
        } else {
            ogsql_printf("incorrect user or passwd");
            return OG_ERROR;
        }
    } else {
        for (uint32 i = 0; i < url_text->len; i++) {
            if (url_text->str[i] == '-' && i + 1 <= url_text->len && url_text->str[i + 1] == '-') {
                url_text->len -= (url_text->len - i);
                break;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t ogsql_parse_conn_sql(text_t *conn_text, ogsql_conn_info_t *conn_info)
{
    char *sql_tmp[OGSQL_CONN_PARAM_COUNT] = { 0 };
    int32 split_num = 0;
    status_t ret;
    bool32 bATFound = OG_FALSE;
    text_t url_text;
    int32 remote_as_sysdba = 0;
    CM_POINTER2(conn_text, conn_info);
    // get full text because it may be truncated in ogsql_fetch_cmd() if including "--"
    conn_text->len = (uint32)strlen(conn_text->str);
    cm_trim_text(conn_text);
    url_text = *conn_text;
    if (!CM_IS_EMPTY(conn_text)) {
        OG_RETURN_IFERR(ogsql_split_url(conn_text, &url_text, &bATFound));
    } else {
        OGSQL_PRINTF(ZSERR_OGSQL, "invalid connection string");
        return OG_ERROR;
    }

    ret = ogsql_local_cmd_split(&url_text, OG_FALSE, sql_tmp, ELEMENT_COUNT(sql_tmp), &split_num);
    if (ret != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "invalid connection string");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(ogsql_try_parse_cmd_split(sql_tmp, split_num, conn_info));

    if (conn_info->connect_by_install_user) {
        if (cm_str_equal_ins(conn_info->username, CM_CLSMGR_USER_NAME)) {
            conn_info->is_clsmgr = OG_TRUE;
        } else {
            conn_info->is_clsmgr = OG_FALSE;
        }
        (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));
        return OG_SUCCESS;
    }

    if (!bATFound) {
        OGSQL_PRINTF(ZSERR_OGSQL, "\"/AS SYSDBA\", \"/ AS SYSDBA\", \"username@ip:port\", or \"/ AS CLSMGR\" is expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(ogsql_try_fetch_user_pwd(sql_tmp, conn_info));

    /* Get db connection URL */
    if (strlen(sql_tmp[2]) > sizeof(conn_info->server_url)) {
        OGSQL_PRINTF(ZSERR_OGSQL, "DB URL overlength");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(strncpy_s(conn_info->server_url, sizeof(conn_info->server_url), sql_tmp[2], strlen(sql_tmp[2])));

    conn_info->connect_by_install_user = OG_FALSE;
    if ((sql_tmp[3] != NULL) && (sql_tmp[4] != NULL)) {
        if (cm_compare_str_ins(sql_tmp[3], (const char *)"AS") == 0 &&
            cm_compare_str_ins(sql_tmp[4], (const char *)"SYSDBA") == 0) {
            remote_as_sysdba = OG_TRUE;
        }
    }
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));
    return OG_SUCCESS;
}

static status_t ogsql_load_local_server_config(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE];
    status_t res;

    cm_spin_lock(&g_server_config_lock, NULL);
    if (g_server_config == NULL) {
        g_server_config = (config_t *)malloc(sizeof(config_t));
        if (g_server_config == NULL) {
            cm_spin_unlock(&g_server_config_lock);
            return OG_ERROR;
        }
    }
    errno_t errcode = snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        OG_HOME, g_config_file);
    if (errcode == -1) {
        cm_spin_unlock(&g_server_config_lock);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }

    cm_init_config(g_client_parameters, OGSQL_PARAMS_COUNT1, g_server_config);
    g_server_config->ignore = OG_TRUE; /* ignore unknown parameters */
    if (!cm_file_exist((const char *)file_name)) {
        cm_spin_unlock(&g_server_config_lock);
        return OG_SUCCESS;
    }
    res = cm_read_config((const char *)file_name, g_server_config);
    cm_spin_unlock(&g_server_config_lock);

    return res;
}

static void ogsql_load_ogsql_config()
{
    uint32 i;
    uint32 count = 0;
    int32 iret_snprintf = -1;
    char app_path[OG_MAX_PATH_BUFFER_SIZE];
    char file_name[OG_FILE_NAME_BUFFER_SIZE];

    if (g_ogsql_config == NULL) {
        // if ogsql in /opt/app/bin/ogsql, try load ogsql.ini from /opt/app/cfg/
        text_t text;
        cm_str2text(cm_sys_program_name(), &text);
        for (i = text.len; i > 0 && count < 2; i--) {
            if (text.str[i - 1] == OS_DIRECTORY_SEPARATOR) {
                count++;
            }
        }
        if (count != 2) {
            return;
        }
        text.len = i;
        (void)cm_text2str(&text, app_path, OG_MAX_PATH_BUFFER_SIZE);
        iret_snprintf = snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/cfg/%s", app_path,
                                   g_ogsql_config_file);
        if (iret_snprintf == -1 || !cm_file_exist((const char *)file_name)) {
            return;
        }

        g_ogsql_config = (config_t *)malloc(sizeof(config_t));
        OG_RETVOID_IFERR(g_ogsql_config == NULL);
        cm_init_config(g_ogsql_parameters, OGSQL_PARAMS_COUNT, g_ogsql_config);
        g_ogsql_config->ignore = OG_TRUE; /* ignore unknown parameters */

        if (OG_SUCCESS != cm_read_config((const char *)file_name, g_ogsql_config)) {
            cm_free_config_buf(g_ogsql_config);
            free(g_ogsql_config);
            g_ogsql_config = NULL;
        }
    }
}

static void ogsql_init_ogsql_config(void)
{
    uint32 val_uint32;
    bool32 val_bool32 = OG_FALSE;
    char *env_val = NULL;

    // load ogsql config from env or ogsql.ini
    if (g_ogsql_config != NULL) {
        env_val = cm_get_config_value(g_ogsql_config, "OGSQL_SSL_QUIET");
    }
    if (env_val == NULL) {
        env_val = getenv("OGSQL_SSL_QUIET");
    }
    if (env_val != NULL && cm_str2bool(env_val, &val_bool32) == OG_SUCCESS) {
        g_local_config.OGSQL_SSL_QUIET = val_bool32;
    }

    if (g_ogsql_config != NULL) {
        env_val = cm_get_config_value(g_ogsql_config, "OGSQL_INTERACTION_TIMEOUT");
    }
    if (env_val == NULL) {
        env_val = getenv("OGSQL_INTERACTION_TIMEOUT");
    }
    if (env_val != NULL && cm_str2uint32(env_val, &val_uint32) == OG_SUCCESS) {
        g_local_config.OGSQL_INTERACTION_TIMEOUT = val_uint32;
    }
}

static status_t ogsql_read_factor_key_file(const char *name, char *key_buf, uint32 key_len)
{
    status_t ret;
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 handle;
    int32 file_size;
    uchar file_buf[OG_AESBLOCKSIZE];

    PRTS_RETURN_IFERR(snprintf_s(file_name,
        OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s", OG_HOME, name));

    OG_RETURN_IFERR(cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    ret = cm_read_file(handle, file_buf, sizeof(file_buf), &file_size);
    cm_close_file(handle);
    OG_RETURN_IFERR(ret);

    return cm_base64_encode((uchar *)file_buf, OG_AESBLOCKSIZE, key_buf, &key_len);
}

status_t ogsql_get_local_server_kmc_privilege(char *home, char *passwd, uint32 pwd_len, bool32 is_ztrst)
{
    int iret_snprintf;
    status_t ret;
    char file_name_priv[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 handle = OG_INVALID_HANDLE;

    iret_snprintf = snprintf_s(file_name_priv, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/%s",
        home, OG_PRIVILEGE_FILENAME);
    if (iret_snprintf == -1) {
        OGSQL_PRINTF(ZSERR_OGSQL, "sysdba login failed, get priv file failed");
        return OG_ERROR;
    }
    if (!cm_file_exist((const char *)file_name_priv)) {
        OGSQL_PRINTF(ZSERR_OGSQL, "sysdba login failed, the priv file does not exist or login as sysdba is prohibited.");
        return OG_ERROR;
    }
    if (cm_open_file_ex(file_name_priv, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle) != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "sysdba login failed, open priv failed");
        return OG_ERROR;
    }
    ret = cm_read_file(handle, passwd, pwd_len, NULL);
    cm_close_file(handle);
    OG_RETURN_IFERR(ret);
    return OG_SUCCESS;
}
/* statistic consumed time of sql execute */
static void ogsql_reset_timer(void)
{
    g_local_config.timer.consumed_time = 0;
}

static void ogsql_get_start_time_for_timer(date_t *start_time)
{
    if (g_local_config.timer.timing_on) {
        *start_time = cm_now();
    }
}

static void ogsql_get_consumed_time_for_timer(date_t start_time)
{
    if (g_local_config.timer.timing_on) {
        g_local_config.timer.consumed_time += (cm_now() - start_time);
    }
}

static void ogsql_print_timer(void)
{
    if (g_local_config.timer.timing_on) {
        ogsql_printf("Elapsed: %0.3f sec\n",
                    (double)g_local_config.timer.consumed_time / (OG_TIME_THOUSAND_UN * OG_TIME_THOUSAND_UN));
    }
}

static status_t ogsql_decrypt_ssl_key_passwd(char *cipher, uint32 cipher_len, char *plain, uint32 *plain_len)
{
    char *local_key = NULL;
    char factor_key[OG_MAX_LOCAL_KEY_STR_LEN + 4];

    if (g_server_config == NULL) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Load LOCAL_KEY failed");
        return OG_ERROR;
    }
    local_key = cm_get_config_value(g_server_config, "LOCAL_KEY");
    if (CM_IS_EMPTY_STR(local_key)) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Load LOCAL_KEY failed");
        return OG_ERROR;
    }

    if (ogsql_read_factor_key_file(OG_FKEY_FILENAME1, factor_key, sizeof(factor_key)) != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Load _FACTOR_KEY failed");
        return OG_ERROR;
    }

    if (cm_decrypt_passwd(OG_TRUE, cipher, cipher_len, plain, plain_len, local_key, factor_key) != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Decrypt ssl key password failed");
        return OG_ERROR;
    }
    plain[*plain_len] = '\0';
    return OG_SUCCESS;
}

static status_t ogsql_deal_local_srv(ogsql_conn_info_t *conn_info, bool8 is_background)
{
    if ((conn_info->connect_by_install_user == OG_TRUE) && (is_background == OG_FALSE)) {
        if (ogsql_get_home() != OG_SUCCESS) {
            if (cm_str_equal_ins(conn_info->username, CM_CLSMGR_USER_NAME)) {
                OGSQL_PRINTF(ZSERR_OGSQL, "\"%s\" login failed, please check -D data_dir", conn_info->username);
            } else {
                OGSQL_PRINTF(ZSERR_OGSQL, "\"%s\" login failed, please check OGDB_DATA environment variable or -D data_dir",
                             conn_info->username);
            }
            return OG_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s(conn_info->server_url, sizeof(conn_info->server_url), "uds", strlen("uds")));

        if (ogsql_get_local_server_kmc_privilege(OG_HOME, conn_info->passwd,
                                                 OG_PASSWORD_BUFFER_SIZE + OG_STR_RESERVED_LEN, OG_FALSE) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogsql_set_conn_attr(ogsql_conn_info_t *conn_info, bool8 is_background)
{
    /* set ssl attributes */
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_MODE, &g_local_config.ssl_mode,
        sizeof(ogconn_ssl_mode_t));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_CA, g_local_config.ssl_ca,
                            (uint32)strlen(g_local_config.ssl_ca));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_CERT, g_local_config.ssl_cert,
                            (uint32)strlen(g_local_config.ssl_cert));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_KEY, g_local_config.ssl_key,
                            (uint32)strlen(g_local_config.ssl_key));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_CRL, g_local_config.ssl_crl,
                            (uint32)strlen(g_local_config.ssl_crl));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_CIPHER, g_local_config.ssl_cipher,
                            (uint32)strlen(g_local_config.ssl_cipher));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_CONNECT_TIMEOUT, (void *)&g_local_config.connect_timeout,
                            sizeof(int32));
    (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SOCKET_TIMEOUT, (void *)&g_local_config.socket_timeout,
                            sizeof(int32));

    /* set uds server path, mandatory */
    if (!CM_IS_EMPTY_STR(g_local_config.server_path)) {
        (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_UDS_SERVER_PATH,
                                g_local_config.server_path, (uint32)strlen(g_local_config.server_path));
    }
    /* set uds client path, optional */
    if (!CM_IS_EMPTY_STR(g_local_config.client_path) && !is_background) {
        (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_UDS_CLIENT_PATH,
                                g_local_config.client_path, (uint32)strlen(g_local_config.client_path));
    }

    if (!CM_IS_EMPTY_STR(g_local_config.ssl_keypwd) && !CM_IS_EMPTY_STR(g_local_config.ssl_key)) {
        // only decrypt the cipher when needed
        char plain[OG_PASSWORD_BUFFER_SIZE];
        uint32 plain_len = OG_PASSWORD_BUFFER_SIZE - 1;
        OG_RETURN_IFERR(ogsql_decrypt_ssl_key_passwd(g_local_config.ssl_keypwd,
            (uint32)strlen(g_local_config.ssl_keypwd), plain, &plain_len));
        (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_KEYPWD, plain, plain_len);
        MEMS_RETURN_IFERR(memset_s(plain, OG_PASSWORD_BUFFER_SIZE, 0, OG_PASSWORD_BUFFER_SIZE));
    } else {
        (void)ogconn_set_conn_attr(conn_info->conn, OGCONN_ATTR_SSL_KEYPWD, "", 0);
    }
    return OG_SUCCESS;
}

static void ogsql_conn_ssl_interaction()
{
    char confirm[OG_MAX_CMD_LEN];
    confirm[0] = '\0';

    while (OG_TRUE) {
        printf("Warning: SSL connection to server without CA certificate is insecure. Continue anyway? (y/n):");
        (void)fflush(stdout);

        timeval_t tv_begin;
        timeval_t tv_end;
        (void)cm_gettimeofday(&tv_begin);

        while (NULL == cm_fgets_nonblock(confirm, sizeof(confirm), stdin)) {
            (void)cm_gettimeofday(&tv_end);
            if (tv_end.tv_sec - tv_begin.tv_sec > (long)g_local_config.OGSQL_INTERACTION_TIMEOUT) {
                printf("\nConfirming SSL connection without CA certificate has timed out.\r\n");
                exit(EXIT_FAILURE);
            }
        }

        if (0 == cm_strcmpni(confirm, "y\n", sizeof("y\n")) ||
            0 == cm_strcmpni(confirm, "yes\n", sizeof("yes\n"))) {
            break;
        } else if (0 == cm_strcmpni(confirm, "n\n", sizeof("n\n")) ||
            0 == cm_strcmpni(confirm, "no\n", sizeof("no\n"))) {
            exit(EXIT_FAILURE);
        } else {
            printf("\n");
        }
    }

    return;
}

static status_t ogsql_chk_pwd(char *input)
{
    char  plain_out[OG_ENCRYPTION_SIZE + OG_AESBLOCKSIZE];
    uchar cipher[OG_ENCRYPTION_SIZE] = { 0 };
    /* generate factor_key and work_key */
    char factor_key[OG_MAX_FACTOR_KEY_STR_LEN + 1];
    char work_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];
    uint32 flen = OG_MAX_FACTOR_KEY_STR_LEN + 1;
    char rand_buf[OG_AESBLOCKSIZE + 1];
    OG_RETURN_IFERR(cm_rand((uchar *)rand_buf, OG_AESBLOCKSIZE));
    OG_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, OG_AESBLOCKSIZE, factor_key, &flen));
    OG_RETURN_IFERR(cm_generate_work_key(factor_key, work_key, sizeof(work_key)));

    /* if the password has expired, fetch the new password */
    OG_RETURN_IFERR(ogsql_recv_passwd_from_terminal(input, OG_PASSWORD_BUFFER_SIZE + 1));
    
    if (strlen(input) == 0) {
        ogsql_printf("missing or invalid password \n");
        return OG_ERROR;
    }
    uint32 cipher_len = OG_ENCRYPTION_SIZE - 1;
    if (cm_encrypt_passwd(OG_TRUE, input, (uint32)strlen(input), (char *)cipher, &cipher_len, (char *)work_key,
        (char *)factor_key) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));

    ogsql_printf("Retype new password: \n");
    OG_RETURN_IFERR(ogsql_recv_passwd_from_terminal(input, OG_PASSWORD_BUFFER_SIZE + 1));

    uint32 plain_len = (uint32)strlen(input) + OG_AESBLOCKSIZE;
    if (cm_decrypt_passwd(OG_TRUE, (char *)cipher, cipher_len, plain_out, &plain_len, (char*)work_key,
        (char*)factor_key) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
        return OG_ERROR;
    }

    plain_out[plain_len] = '\0';
    if (!cm_str_equal(input, (const char *)plain_out)) {
        MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
        MEMS_RETURN_IFERR(memset_s(plain_out, OG_ENCRYPTION_SIZE, 0, OG_ENCRYPTION_SIZE));
        ogsql_printf("Passwords do not match \n");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(plain_out, OG_ENCRYPTION_SIZE, 0, OG_ENCRYPTION_SIZE));
    if (cm_verify_password_str(g_conn_info.username, input, OG_PASSWD_MIN_LEN) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
        ogsql_printf("missing or invalid password \n");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogsql_alt_expire_pwd(clt_conn_t *conn)
{
    text_t line;
    char cmd_sql[OG_MAX_CMD_LEN];
    char input[OG_PASSWORD_BUFFER_SIZE + 1];
    int ret_sprintf;

    ogsql_printf("The user password has expired\n");
    ogsql_printf("New password : \n");
    if (ogsql_chk_pwd((char *)input) != OG_SUCCESS) {
        ogsql_printf("Password unchanged \n");
        return OG_ERROR;
    }
    ret_sprintf = snprintf_s(cmd_sql, OG_MAX_CMD_LEN, OG_MAX_CMD_LEN - 1, "%s%s%s%s%s", "ALTER USER ",
        g_conn_info.username, " IDENTIFIED BY ", input, ";");
    if (ret_sprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret_sprintf);
        MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(input, OG_PASSWORD_BUFFER_SIZE + 1, 0, OG_PASSWORD_BUFFER_SIZE + 1));
    cm_str2text((char *)cmd_sql, &line);
    conn->ogsql_in_altpwd = OG_TRUE;
    if (ogsql_process_cmd(&line) != OG_SUCCESS) {
        conn->ogsql_in_altpwd = OG_FALSE;
        return OG_ERROR;
    }

    conn->ogsql_in_altpwd = OG_FALSE;
    return OG_SUCCESS;
}

/************************************************************************/
/* ogsql connect to server of database                                   */
/* conn_info : connection info                                          */
/* print_conn : OG_TRUE  -- print ssl interaction info and connection   */
/*                          failure error info                          */
/*              OG_FALSE -- not print                                   */
/************************************************************************/
status_t ogsql_conn_to_server(ogsql_conn_info_t *conn_info, bool8 print_conn, bool8 is_background)
{
    uint32 remote_as_sysdba = OG_FALSE;
    text_t sys_user_name = { .str = SYS_USER_NAME, .len = SYS_USER_NAME_LEN };
    CM_POINTER(conn_info);

    OG_RETURN_IFERR(ogsql_deal_local_srv(conn_info, is_background));
    OG_RETURN_IFERR(ogsql_set_conn_attr(conn_info, is_background));

    if (print_conn && g_local_config.ssl_mode != OGCONN_SSL_DISABLED &&
        g_local_config.ssl_ca[0] == '\0' && g_local_config.OGSQL_SSL_QUIET == OG_FALSE) {
        ogsql_conn_ssl_interaction();
    }

    if (ogconn_connect(conn_info->conn, conn_info->server_url, conn_info->username, conn_info->passwd) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(conn_info->passwd, OG_PASSWORD_BUFFER_SIZE + 4, 0, OG_PASSWORD_BUFFER_SIZE + 4));
        ogsql_print_error(conn_info->conn);
        return OG_ERROR;
    }

    status_t ret = loader_save_pswd(conn_info->passwd, (uint32)strlen(conn_info->passwd));
    MEMS_RETURN_IFERR(memset_s(conn_info->passwd, OG_PASSWORD_BUFFER_SIZE + 4, 0, OG_PASSWORD_BUFFER_SIZE + 4));
    OG_RETURN_IFERR(ret);

    // if the sysdba is connectted successfully, DN reset the username as sys
    if (OG_TRUE == conn_info->connect_by_install_user) {
        PRTS_RETURN_IFERR(sprintf_s(conn_info->username, OG_NAME_BUFFER_SIZE, "%s", "SYS"));
    }
    MEMS_RETURN_IFERR(memcpy_s(conn_info->schemaname, OG_NAME_BUFFER_SIZE + OG_STR_RESERVED_LEN,
        conn_info->username, OG_NAME_BUFFER_SIZE + OG_STR_RESERVED_LEN));
    (void)ogconn_get_conn_attr(conn_info->conn, OGCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(uint32), NULL);
    if (remote_as_sysdba) {
        (void)cm_text2str(&sys_user_name, conn_info->schemaname, OG_NAME_BUFFER_SIZE + OG_STR_RESERVED_LEN);
    }
    loader_save_user(conn_info->username, (uint32)strlen(conn_info->username));

    if (ogconn_alloc_stmt(conn_info->conn, &conn_info->stmt) != OG_SUCCESS) {
        ogsql_print_error(conn_info->conn);
        ogconn_disconnect(conn_info->conn);
        return OG_ERROR;
    }

    conn_info->is_conn = OG_TRUE;

    clt_conn_t *conn = (clt_conn_t *)conn_info->conn;
    if (conn->pack.head->flags & CS_FLAG_OGSQL_IN_ALTPWD) {
        OGSQL_RESET_CMD_TYPE(&g_cmd_type);
        if (ogsql_alt_expire_pwd(conn) != OG_SUCCESS) {
            ogconn_disconnect(conn_info->conn);
            conn_info->is_conn = OG_FALSE;
            return OG_ERROR;
        }
    } else {
        if (print_conn) {
            ogsql_printf("%s\n", ogconn_get_message(conn_info->conn));
        }
    }

    (void)ogconn_get_conn_attr(conn_info->conn, OGCONN_ATTR_DBTIMEZONE, "DBTIMEZONE", 11, NULL);
    
    return OG_SUCCESS;
}

status_t ogsql_connect(text_t *conn_text)
{
    status_t ret;
    ogsql_conn_info_t *conn_info = NULL;

    /* 1. get the connect information */
    conn_info = &g_conn_info;
    conn_info->server_url[0] = '\0';
    conn_info->connect_by_install_user = OG_FALSE;
    
    if (IS_CONN) {
        ogconn_free_stmt(STMT);
        STMT = NULL;
        ogconn_disconnect(CONN);
        IS_CONN = OG_FALSE;
    }

    ret = ogsql_parse_conn_sql(conn_text, conn_info);
    OG_RETURN_IFERR(ret);

    ret = ogsql_conn_to_server(conn_info, OG_TRUE, OG_FALSE);
    OG_RETURN_IFERR(ret);

    return OG_SUCCESS;
}

static void ogsql_get_cmd(text_t line, ogsql_cmd_def_t *cmd_type, text_t *params)
{
    cm_trim_text(&line);

    if (CM_TEXT_FIRST(&line) == '-' && CM_TEXT_SECOND(&line) == '-') {
        *cmd_type = CMD_COMMENT_TYPE;
        *params = line;
        return;
    }

    if (CM_TEXT_BEGIN(&line) == '@') {
        if (CM_TEXT_SECOND(&line) == '@') {
            *cmd_type = CMD_SQLFILE_TYPE2;
            CM_REMOVE_FIRST_N(&line, 2);
            cm_trim_text(&line);
        } else {
            *cmd_type = CMD_SQLFILE_TYPE;
            CM_REMOVE_FIRST(&line);
        }

        *params = line;
        return;
    }
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (CM_TEXT_BEGIN(&line) == '\\' && CM_TEXT_SECOND(&line) == '!') {
        *cmd_type = CMD_SHELL_TYPE;
        CM_REMOVE_FIRST_N(&line, 2);
        *params = line;
        return;
    }
#endif
    if (CM_TEXT_END(&line) == ';' && g_in_comment_count == 0) {
        if (line.len <= 1) {
            cmd_type->cmd = CMD_EXEC;
            cmd_type->mode = MODE_NONE;
            return;
        } else {
            CM_REMOVE_LAST(&line);
        }
    }

    if (!ogsql_find_cmd(&line, cmd_type)) {
        *cmd_type = CMD_NONE_TYPE;
        return;
    }
    *params = line;
}

void ogsql_exit(bool32 from_whenever, status_t status)
{
    uint32 exitcommit = OG_FALSE;
    uint32 attr_len = 0;

    if (IS_CONN) {
        (void)ogconn_get_conn_attr(CONN, OGCONN_ATTR_EXIT_COMMIT, &exitcommit, sizeof(int), &attr_len);

        if (exitcommit && !from_whenever) {
            (void)ogconn_commit(CONN);
        }

        ogconn_free_stmt(STMT);
        ogconn_disconnect(CONN);
        ogconn_free_conn(CONN);
    }

    if (g_spool_file != OG_NULL_FILE) {
        ogsql_spool_off();
    }

    ogsql_free_user_pswd();
    exit(status);
}

static void ogsql_coldesc2typmode(ogconn_inner_column_desc_t *dsc, typmode_t *typmod)
{
    typmod->datatype = dsc->type + OG_TYPE_BASE;
    typmod->size = dsc->size;
    typmod->precision = (int8)dsc->precision;
    typmod->scale = (int8)dsc->scale;
    typmod->is_array = dsc->is_array;
    if (OG_IS_STRING_TYPE(typmod->datatype)) {
        typmod->is_char = (uint8)dsc->is_character;
    }
}

static status_t ogsql_desc_print(void)
{
    uint32 i;
    uint32 col_name_len;
    typmode_t typmod;

    g_display_widths[0] = 32;  // max column length

    OG_RETURN_IFERR(ogconn_get_stmt_attr(STMT, OGCONN_ATTR_COLUMN_COUNT, &g_column_count, sizeof(uint32), NULL));

    if (g_column_count == 0) {
        OG_THROW_ERROR(ERR_CLT_INVALID_VALUE, "number of columns", g_column_count);
        return OG_ERROR;
    }

    for (i = 0; i < g_column_count; i++) {
        OG_RETURN_IFERR(ogconn_desc_inner_column_by_id(STMT, i, &g_columns[i]));
        col_name_len = (uint32)strlen(g_columns[i].name);
        if (g_display_widths[0] < col_name_len) {
            g_display_widths[0] = col_name_len;
        }
    }
    g_display_widths[0] += 3;

    // Step2: print title
    g_display_widths[1] = 8;
    g_display_widths[2] = 36;
    ogsql_printf("%-*s%s", g_display_widths[0], "Name", g_local_config.colsep.colsep_name);
    ogsql_printf("%-*s%s", g_display_widths[1], "Null?", g_local_config.colsep.colsep_name);
    ogsql_printf("%-*s", g_display_widths[2], "Type");
    ogsql_printf("\n");

    MEMS_RETURN_IFERR(memset_s(g_str_buf, MAX_COLUMN_WIDTH, '-', g_display_widths[0]));
    g_str_buf[g_display_widths[0]] = '\0';
    ogsql_printf("%s%s", g_str_buf, g_local_config.colsep.colsep_name);

    MEMS_RETURN_IFERR(memset_s(g_str_buf, MAX_COLUMN_WIDTH, '-', g_display_widths[1]));
    g_str_buf[g_display_widths[1]] = '\0';
    ogsql_printf("%s%s", g_str_buf, g_local_config.colsep.colsep_name);

    MEMS_RETURN_IFERR(memset_s(g_str_buf, MAX_COLUMN_WIDTH, '-', g_display_widths[2]));
    g_str_buf[g_display_widths[2]] = '\0';
    ogsql_printf("%s\n", g_str_buf);

    // Step3: print column definition
    for (i = 0; i < g_column_count; i++) {
        ogsql_coldesc2typmode(&g_columns[i], &typmod);
        ogsql_printf("%-*s%s", g_display_widths[0], g_columns[i].name, g_local_config.colsep.colsep_name);
        ogsql_printf("%-*s%s", g_display_widths[1], g_columns[i].nullable ? "" : "NOT NULL",
                    g_local_config.colsep.colsep_name);
        OG_RETURN_IFERR(cm_typmode2str(&typmod, g_columns[i].is_array, g_str_buf, OG_MAX_PACKET_SIZE));
        ogsql_printf("%-*s\n", g_display_widths[2], g_str_buf);
    }

    return OG_SUCCESS;
}

typedef struct st_describer {
    ogconn_desc_type_t type;
    char *objptr;
} describer_t;

static status_t ogsql_parse_describer(text_t *params, describer_t *dsber)
{
    lex_t lex;
    sql_text_t sql_text;
    uint32 match_id;
    sql_text.value = *params;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_init(&lex, &sql_text);
    CM_NULL_TERM(params);
    // the options corresponding to ogconn_desc_type_t
    if (lex_try_fetch_1ofn(&lex, &match_id, 2, "-o", "-q") != OG_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }

    if (match_id == OG_INVALID_ID32 || match_id == 0) {
        word_t word;
        text_buf_t tbl_name_buf;
        tbl_name_buf.max_size = MAX_ENTITY_LEN;
        tbl_name_buf.str = g_str_buf;
        tbl_name_buf.len = 0;

        if (lex_expected_fetch_tblname(&lex, &word, &tbl_name_buf) != OG_SUCCESS ||
            lex_expected_end(&lex) != OG_SUCCESS) {
            g_tls_error.loc.line = 0;
            ogsql_print_error(NULL);
            ogsql_printf("Usage: DESCRIBE [schema.]object\n");
            return OG_ERROR;
        }

        CM_NULL_TERM(&tbl_name_buf);
        dsber->objptr = tbl_name_buf.str;
        dsber->type = OGCONN_DESC_OBJ;
        return OG_SUCCESS;
    }

    if (match_id == 1) {
        dsber->objptr = lex.curr_text->str;
        dsber->type = OGCONN_DESC_QUERY;
    }

    return OG_SUCCESS;
}

static status_t ogsql_desc(text_t *params)
{
    int status;
    describer_t describer;

    if (!IS_CONN) {
        OGSQL_PRINTF(ZSERR_OGSQL, "connection is not established");
        return OG_ERROR;
    }

    cm_trim_text(params);

    if (CM_IS_EMPTY(params)) {
        ogsql_printf("Usage: DESCRIBE [schema.]object\n");
        return OG_ERROR;
    }

    if (ogsql_parse_describer(params, &describer) != OG_SUCCESS) {
        return OG_ERROR;
    }

    status = ogconn_describle(STMT, describer.objptr, describer.type);
    if (status != OGCONN_SUCCESS) {
        ogsql_print_error(CONN);
        return OGCONN_ERROR;
    }

    status = ogsql_desc_print();
    if (status != OGCONN_SUCCESS) {
        ogsql_print_error(CONN);
    }

    return status;
}

static status_t ogsql_spool(text_t *params)
{
    cm_trim_text(params);
    if (cm_compare_text_str_ins(params, "OFF") == 0) {
        ogsql_spool_off();
    } else {
        char buf[MAX_ENTITY_LEN];
        OG_RETURN_IFERR(cm_text2str(params, buf, MAX_ENTITY_LEN));
        if (ogsql_spool_on(buf) != OG_SUCCESS) {
            ogsql_print_error(NULL);
            return OG_ERROR;
        } else {
            g_local_config.spool_on = OG_TRUE;
        }
    }
    return OG_SUCCESS;
}

static uint32 ogsql_get_print_column_cost(uint32 col_id, uint32 display_len)
{
    if (!g_col_display[col_id]) {
        if (display_len < g_display_widths[col_id]) {
            return g_display_widths[col_id];
        } else {
            return display_len;
        }
    } else {
        return g_display_widths[col_id];
    }
}

static void ogsql_print_column_titles_ex_deal(char *temp_name, uint32 p_cost_size, uint32 p_left_size)
{
    errno_t errcode = 0;
    uint32 left_size = p_left_size;
    uint32 cost_size = p_cost_size;
    for (uint32 i = 0; i < g_column_count; i++) {
        cost_size = ogsql_get_print_column_cost(i, (uint32)strlen(g_columns[i].name));
        cost_size = MIN(cost_size, left_size - 1);

        if (!g_col_display[i]) {
            MEMS_RETVOID_IFERR(memset_s(temp_name, OG_NAME_BUFFER_SIZE + 1, 0, OG_NAME_BUFFER_SIZE + 1));
            errcode = memcpy_s(temp_name, OG_NAME_BUFFER_SIZE, g_columns[i].name,
                (uint32)strlen(g_columns[i].name));
            if (errcode != EOK) {
                ogsql_printf("Copying g_columns[%u].name has thrown an error %d", i, errcode);
                return;
            }
            if (cost_size < strlen(temp_name)) {
                temp_name[cost_size] = '\0';
            }

            if (i == g_column_count - 1) {
                ogsql_printf("%-*s", cost_size, temp_name);
            } else {
                ogsql_printf("%-*s%s", cost_size, temp_name, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_columns[i].name) < cost_size) {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-*s", cost_size, g_columns[i].name);
                } else {
                    ogsql_printf("%-*s%s", cost_size, g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-.*s", cost_size, g_columns[i].name);
                } else {
                    ogsql_printf("%-.*s%s", cost_size, g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            }
        }

        if (left_size <= (cost_size + 1)) {
            break;
        }
        left_size -= (cost_size + 1);
    }
}

static void ogsql_print_column_titles_ex(void)
{
    uint32 cost_size;
    uint32 left_size;
    cost_size = 0;
    char str[MAX_COLUMN_WIDTH + 1];
    char temp_name[OG_NAME_BUFFER_SIZE + 1];
    errno_t errcode = 0;
    left_size = g_local_config.line_size + 1;

    ogsql_print_column_titles_ex_deal(temp_name, cost_size, left_size);

    ogsql_printf("\n");

    left_size = g_local_config.line_size + 1;

    for (uint32 i = 0; i < g_column_count; i++) {
        if (g_display_widths[i] != 0) {
            errcode = memset_s(str, MAX_COLUMN_WIDTH + 1, '-', g_display_widths[i]);
            if (errcode != EOK) {
                ogsql_printf("Secure C lib has thrown an error %d", errcode);
                return;
            }
        }
        str[g_display_widths[i]] = '\0';

        cost_size = MIN(g_display_widths[i], left_size - 1);
        if (cost_size < strlen(str)) {
            str[cost_size] = '\0';
        }

        if (i == g_column_count - 1) {
            ogsql_printf("%s", str);
        } else {
            ogsql_printf("%s%s", str, g_local_config.colsep.colsep_name);
        }

        if (left_size <= (cost_size + 1)) {
            break;
        }
        left_size -= (cost_size + 1);
    }
}

static void ogsql_print_column_titles(void)
{
    uint32 i;
    char str[MAX_COLUMN_WIDTH + 1];
    errno_t errcode;

    if (g_local_config.line_size != 0) {
        ogsql_print_column_titles_ex();
        return;
    }

    for (i = 0; i < g_column_count; i++) {
        if (!g_col_display[i]) {
            if (i == g_column_count - 1) {
                ogsql_printf("%-*s", g_display_widths[i], g_columns[i].name);
            } else {
                ogsql_printf("%-*s%s", g_display_widths[i], g_columns[i].name, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_columns[i].name) < g_display_widths[i]) {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-*s", g_display_widths[i], g_columns[i].name);
                } else {
                    ogsql_printf("%-*s%s", g_display_widths[i], g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-.*s", g_display_widths[i], g_columns[i].name);
                } else {
                    ogsql_printf("%-.*s%s", g_display_widths[i], g_columns[i].name, g_local_config.colsep.colsep_name);
                }
            }
        }
    }

    ogsql_printf("\n");

    for (i = 0; i < g_column_count; i++) {
        if (g_display_widths[i] != 0) {
            errcode = memset_s(str, MAX_COLUMN_WIDTH + 1, '-', g_display_widths[i]);
            if (errcode != EOK) {
                ogsql_printf("Secure C lib has thrown an error %d", errcode);
                return;
            }
        }
        str[g_display_widths[i]] = '\0';
        if (i == g_column_count - 1) {
            ogsql_printf("%s", str);
        } else {
            ogsql_printf("%s%s", str, g_local_config.colsep.colsep_name);
        }
    }
}

static ogsql_column_format_attr_t *ogsql_get_column_attr(text_t *column);

static void ogsql_describe_columns_type(uint32 name_len, uint32 p_byte_ratio, uint32 index)
{
    uint32 byte_ratio = p_byte_ratio;
    switch (g_columns[index].type) {
        case OGCONN_TYPE_BIGINT:
        case OGCONN_TYPE_REAL:
            g_display_widths[index] = MAX(OG_MAX_UINT64_STRLEN, name_len);
            break;

            // for the case var + null
        case OGCONN_TYPE_UNKNOWN:
            g_display_widths[index] = MAX(OG_MAX_UINT32_STRLEN, name_len);
            break;

        case OGCONN_TYPE_INTEGER:
            g_display_widths[index] = MAX(OG_MAX_INT32_STRLEN + 1, name_len);
            break;

        case OGCONN_TYPE_UINT32:
            g_display_widths[index] = MAX(12, name_len);
            break;
        case OGCONN_TYPE_BOOLEAN:
            g_display_widths[index] = MAX(OG_MAX_BOOL_STRLEN + 1, name_len);
            break;

        case OGCONN_TYPE_NUMBER:
        case OGCONN_TYPE_DECIMAL:
        case OGCONN_TYPE_NUMBER2: {
            uint32 num_width = OG_MAX_DEC_OUTPUT_PREC;
            (void)ogconn_get_conn_attr(CONN, OGCONN_ATTR_NUM_WIDTH, &num_width, sizeof(uint32), NULL);
            g_display_widths[index] = MAX(num_width, name_len);
            break;
        }

        case OGCONN_TYPE_DATE:
            g_display_widths[index] = MAX(OG_MAX_DATE_STRLEN, name_len);
            break;

        case OGCONN_TYPE_TIMESTAMP:
        case OGCONN_TYPE_TIMESTAMP_TZ_FAKE:
        case OGCONN_TYPE_TIMESTAMP_LTZ:
            g_display_widths[index] = MAX(OG_MAX_TIMESTAMP_STRLEN, name_len);
            break;

        case OGCONN_TYPE_INTERVAL_YM:
            g_display_widths[index] = MAX(OG_MAX_YM_INTERVAL_STRLEN, name_len);
            break;

        case OGCONN_TYPE_INTERVAL_DS:
            g_display_widths[index] = MAX(OG_MAX_DS_INTERVAL_STRLEN, name_len);
            break;

        case OGCONN_TYPE_TIMESTAMP_TZ:
            g_display_widths[index] = MAX(OG_MAX_TZ_STRLEN, name_len);
            break;

        case OGCONN_TYPE_VARCHAR:
        case OGCONN_TYPE_CHAR:
        case OGCONN_TYPE_STRING:
            byte_ratio = g_columns[index].is_character ? OG_CHAR_TO_BYTES_RATIO : 1;
            g_display_widths[index] = (g_columns[index].size * byte_ratio > OG_MAX_MIN_VALUE_SIZE) ?
                OG_MAX_MIN_VALUE_SIZE :
                (g_columns[index].size * byte_ratio < name_len) ? name_len : g_columns[index].size * byte_ratio;
            break;

        default:
            g_display_widths[index] = OG_MAX_MIN_VALUE_SIZE;
            break;
    }
}

static void ogsql_describe_columns(void)
{
    uint32 i;
    uint32 name_len;
    uint32 byte_ratio = 0;
    text_t column_name;
    ogsql_column_format_attr_t *col_attr = NULL;

    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_COLUMN_COUNT, &g_column_count, sizeof(uint32), NULL);
    if (g_column_count > OG_MAX_COLUMNS) {
        return;
    }
    for (i = 0; i < g_column_count; i++) {
        (void)ogconn_desc_inner_column_by_id(STMT, i, &g_columns[i]);

        name_len = (uint32)strlen(g_columns[i].name);

        // set display widths if set column info(col column_name for aN)
        column_name.str = g_columns[i].name;
        column_name.len = name_len;
        col_attr = ogsql_get_column_attr(&column_name);
        if (col_attr != NULL && col_attr->is_on) {
            g_col_display[i] = OG_TRUE;
            g_display_widths[i] = col_attr->col_width;
            continue;
        } else {
            g_col_display[i] = OG_FALSE;
        }

        if (g_columns[i].is_array) {
            g_display_widths[i] = OG_MAX_MIN_VALUE_SIZE;
            continue;
        }

        ogsql_describe_columns_type(name_len, byte_ratio, i);
    }

    if (g_local_config.heading_on) {
        ogsql_print_column_titles();
        ogsql_printf("\n");
    }
}

static status_t ogsql_get_column_as_string(ogconn_stmt_t stmt, uint32 col, char *buf, uint32 buf_len)
{
    uint32 i;
    uint32 size;
    void *data = NULL;
    bool32 is_null = OG_FALSE;
    ogconn_inner_column_desc_t col_info;

    OG_RETURN_IFERR(ogconn_desc_inner_column_by_id(stmt, col, &col_info));

    // binary will be converted to string
    if (col_info.type != OGCONN_TYPE_STRING || col_info.is_array) {
        return ogconn_column_as_string(stmt, col, buf, buf_len);
    }
    OG_RETURN_IFERR(ogconn_get_column_by_id(stmt, col, &data, &size, &is_null));

    if (is_null) {
        buf[0] = '\0';
        return OG_SUCCESS;
    }

    size = (size >= buf_len - 1) ? buf_len - 1 : size;
    if (size > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, buf_len, data, size));
    }
    buf[size] = '\0';

    for (i = 0; i < size; ++i) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    return OG_SUCCESS;
}

static void ogsql_print_column_data_ex(void)
{
    uint32 i;
    uint32 cost_size;
    uint32 left_size = g_local_config.line_size + 1;

    for (i = 0; i < g_column_count; i++) {
        if (ogsql_get_column_as_string(STMT, i, g_str_buf, OG_MAX_PACKET_SIZE) != OG_SUCCESS) {
            OGSQL_PRINTF(ZSERR_OGSQL, "the %d column print failed", i);
            continue;
        }

        cost_size = ogsql_get_print_column_cost(i, (uint32)strlen(g_str_buf));
        cost_size = MIN(cost_size, left_size - 1);

        if (!g_col_display[i]) {
            if (cost_size < strlen(g_str_buf)) {
                g_str_buf[cost_size] = '\0';
            }

            if (i == g_column_count - 1) {
                ogsql_printf("%-*s", cost_size, g_str_buf);
            } else {
                ogsql_printf("%-*s%s", cost_size, g_str_buf, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_str_buf) < cost_size) {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-*s", cost_size, g_str_buf);
                } else {
                    ogsql_printf("%-*s%s", cost_size, g_str_buf, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-.*s", cost_size, g_str_buf);
                } else {
                    ogsql_printf("%-.*s%s", cost_size, g_str_buf, g_local_config.colsep.colsep_name);
                }
            }
        }

        if (left_size <= (cost_size + 1)) {
            break;
        }
        left_size -= (cost_size + 1);
    }

    ogsql_printf("\n");
}

static void ogsql_print_column_data(void)
{
    uint32 i;

    if (g_local_config.line_size != 0) {
        ogsql_print_column_data_ex();
        return;
    }

    for (i = 0; i < g_column_count; i++) {
        (void)ogsql_get_column_as_string(STMT, i, g_str_buf, OG_MAX_PACKET_SIZE);

        if (!g_col_display[i]) {
            if (i == g_column_count - 1) {
                ogsql_printf("%-*s", g_display_widths[i], g_str_buf);
            } else {
                ogsql_printf("%-*s%s", g_display_widths[i], g_str_buf, g_local_config.colsep.colsep_name);
            }
        } else {
            if (strlen(g_str_buf) < g_display_widths[i]) {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-*s", g_display_widths[i], g_str_buf);
                } else {
                    ogsql_printf("%-*s%s", g_display_widths[i], g_str_buf, g_local_config.colsep.colsep_name);
                }
            } else {
                if (i == g_column_count - 1) {
                    ogsql_printf("%-.*s", g_display_widths[i], g_str_buf);
                } else {
                    ogsql_printf("%-.*s%s", g_display_widths[i], g_str_buf, g_local_config.colsep.colsep_name);
                }
            }
        }
    }

    ogsql_printf("\n");
}

static void ogsql_print_resultset(void)
{
    uint32 rows;
    uint32 rows_print;
    uint32 rows_one_page;
    uint32 newpage = 0;
    date_t start_time = 0;

    rows_print = 0;
    rows_one_page = g_local_config.page_size - OG_MIN_PAGESIZE + 1;

    ogsql_describe_columns();

    ogsql_get_start_time_for_timer(&start_time);
    if (ogconn_fetch(STMT, &rows) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return;
    }
    ogsql_get_consumed_time_for_timer(start_time);

    while (rows > 0) {
        if (OGSQL_CANCELING) {
            return;
        }

        ogsql_print_column_data();
        rows_print++;

        ogsql_get_start_time_for_timer(&start_time);
        if (ogconn_fetch(STMT, &rows) != OG_SUCCESS) {
            ogsql_print_error(CONN);
            return;
        }
        ogsql_get_consumed_time_for_timer(start_time);

        if (rows > 0 && rows_print == rows_one_page) {
            for (newpage = 0; newpage < g_local_config.newpage; newpage++) {
                ogsql_printf("\n");
            }

            // already set g_display_widths[OG_MAX_COLUMNS] in ogsql_describe_columns
            if (g_local_config.heading_on) {
                ogsql_print_column_titles();
                ogsql_printf("\n");
            }

            rows_print = 0;
        }
    }
}

#define SQL_COMMAND_LENGTH (MAX_CMD_LEN + 2)
static status_t check_first_character(char input)
{
    if ((input >= 'a' && input <= 'z') ||
        (input >= 'A' && input <= 'Z') ||
        (input >= '0' && input <= '9') ||
        (input == '_')) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static void ogsql_replace_function(text_t *line)
{
    text_t *input = line;
    uint32 i = 0;
    uint32 is_first_mark = 1;
    char replace_info[OG_BUFLEN_128] = { 0 };
    char variable_info[OG_BUFLEN_128] = { 0 };
    char remain[SQL_COMMAND_LENGTH + 1] = { 0 };
    char oldsql[SQL_COMMAND_LENGTH + 1] = { 0 };
    uint32 beg = 0;
    uint32 beg1 = 0;
    uint32 end = 0;
    uint32 copy_len = 0;
    uint32 is_print_old_new = 0;
    errno_t tmp;

    if (input->len > SQL_COMMAND_LENGTH) {
        printf("The length [%u] of the input sql is out of range", input->len);
        return;
    }
    tmp = strncpy_s(oldsql, SQL_COMMAND_LENGTH + 1, input->str, input->len);
    if (tmp != EOK) {
        ogsql_printf("Error [%d], max length is [%d], and input length is [%u]",
            tmp, SQL_COMMAND_LENGTH, input->len);
        return;
    }
    oldsql[input->len] = '\0';

    for (i = 0; i < input->len; i++) {
        if ((input->str[i] == g_replace_mark) && (is_first_mark == 1)) {  // find g_replace_mark ,if not match ,continue
            is_first_mark = 0;
            is_print_old_new = 1;
            ++i;
            beg1 = i;
            while (input->str[i] == ' ') {
                i++;
            }
            if (i == input->len || input->str[i] == '\n') {  // protect
                ogsql_printf("sql is:%s\n", input->str);
                OGSQL_PRINTF(ZSERR_OGSQL, "Invalid variable, Replace mark '%c' cannot be at the end of every line", g_replace_mark);
                return;
            }
            if (check_first_character(input->str[i]) == OG_FALSE) {
                OGSQL_PRINTF(ZSERR_OGSQL, "Invalid variable, variable should be a~z, A~Z, 0~9 or _");
                return;
            }
            beg = i;
        }

        if ((is_first_mark == 0) &&
            (check_first_character(input->str[i]) == OG_FALSE || i == input->len - 1)) {
            if (i == input->len - 1) {
                end = i + 1;
            } else {
                end = i;
            }
            is_first_mark = 1;

            // first
            tmp = memset_s(remain, sizeof(remain), 0, sizeof(remain));
            if (tmp != EOK) {
                ogsql_printf("An error [%d] occurred when memset remainning old sql.", tmp);
                return;
            }
            copy_len = input->len - end;
            if (copy_len > SQL_COMMAND_LENGTH) {
                ogsql_printf("The length [%u] of the remainning old sql is out of range.", copy_len);
                return;
            }

            if (copy_len > 0) {
                tmp = strncpy_s(remain, sizeof(remain), input->str + end, copy_len);
                if (tmp != EOK) {
                    ogsql_printf("Error [%d], max length is [%d], and the length of remainning old sql is [%u].",
                        tmp, SQL_COMMAND_LENGTH, copy_len);
                    return;
                }
            }
            remain[copy_len] = '\0';
            input->len = beg1 - 1;

            // second, show the variable_info
            tmp = memset_s(variable_info, sizeof(variable_info), 0, sizeof(variable_info));
            if (tmp != EOK) {
                ogsql_printf("An error occurred when memset variable, error [%d]", tmp);
                return;
            }
            copy_len = end - beg;
            if (copy_len >= OG_BUFLEN_128) {
                ogsql_printf("The length [%u] of variable to be replaced is out of range.", copy_len);
                return;
            }

            if (copy_len > 0) {
                tmp = strncpy_s(variable_info, sizeof(variable_info), input->str + beg, copy_len);
                if (tmp != EOK) {
                    ogsql_printf("Error [%d], max length is [%d], and the length of the variable being replaced "
                        "is [%u].", tmp, OG_BUFLEN_128 - 1, copy_len);
                    return;
                }
            }
            variable_info[copy_len] = '\0';
            ogsql_printf("Enter value for %s:", variable_info);

            // third, waiting for user input
            (void)fflush(stdout);
            if (NULL == fgets(replace_info, sizeof(replace_info), stdin)) {
                return;
            }

            copy_len = (uint32)strlen(replace_info);
            if (copy_len == 0) {
                ogsql_printf("The length of the replacement variable cannot be 0.");
                return;
            }

            ogsql_printf("\n");
            replace_info[copy_len - 1] = '\0';

            // fourth
            copy_len = (uint32)strlen(replace_info);
            if (copy_len > SQL_COMMAND_LENGTH - input->len) {
                ogsql_printf("The length [%u] of the replacement variable is is out of range.", copy_len);
                return;
            }

            if (copy_len != 0) {
                tmp = strncpy_s(input->str + input->len, SQL_COMMAND_LENGTH - input->len, replace_info, copy_len);
                if (tmp != EOK) {
                    ogsql_printf("Error %d, the remaining length is [%u], and the actual input length is [%u].",
                        tmp, SQL_COMMAND_LENGTH - input->len, copy_len);
                    return;
                }
            }
            input->len += copy_len;

            // fifth
            i = input->len;
            beg = input->len;
            end = input->len;

            // sixth
            copy_len = (uint32)strlen(remain);
            if (copy_len > SQL_COMMAND_LENGTH - input->len) {
                ogsql_printf("The length of the new sql is [%u], which is out of range.", copy_len);
                return;
            }

            if (copy_len != 0) {
                tmp = strncpy_s(input->str + input->len, SQL_COMMAND_LENGTH - input->len, remain, copy_len);
                if (tmp != EOK) {
                    ogsql_printf("Error %d, max lenght is [%d], and the length of the new sql is[%u].",
                        tmp, SQL_COMMAND_LENGTH, input->len + copy_len);
                    return;
                }
            }
            input->len += copy_len;
            input->str[input->len] = '\0';
            i--;
        }
    }

    if (is_print_old_new == 1 && g_local_config.verify_on == OG_TRUE) {
        ogsql_printf("old sql is : %s\n", oldsql);
        ogsql_printf("new sql is : %s\n", line->str);
    }
    return;
}

status_t ogsql_execute_sql(void)
{
    uint32 param_count = 0;
    date_t start_time = 0;
    text_t sql_text;
    bool32 seroutput_exists = OG_FALSE;
    uint32 stmt_type = OGCONN_STMT_NONE;

    if (!IS_CONN) {
        OGSQL_PRINTF(ZSERR_OGSQL, "connection is not established");
        return OG_ERROR;
    }

    cm_str2text(g_sql_buf, &sql_text);

    if (g_local_config.define_on == OG_TRUE) {
        ogsql_replace_function(&sql_text);  // replace function. IforNot OG_RETURN_IFERR
    }

    ogsql_get_start_time_for_timer(&start_time);
    if (ogconn_prepare(STMT, g_sql_buf) != OG_SUCCESS) {
        ogsql_get_consumed_time_for_timer(start_time);
        ogsql_print_error(CONN);
        return OG_ERROR;
    }

    ogsql_get_consumed_time_for_timer(start_time);

    OG_RETURN_IFERR(ogconn_get_stmt_attr(STMT, OGCONN_ATTR_STMT_TYPE, (const void *)&stmt_type, sizeof(uint32), NULL));

    /* explain stmt do not handle binding parameters */
    if (stmt_type != OGCONN_STMT_EXPLAIN  || g_local_config.bindparam_force_on) {
        OG_RETURN_IFERR(ogconn_get_stmt_attr(STMT, OGCONN_ATTR_PARAM_COUNT, (const void *)&param_count, sizeof(uint32),
                                          NULL));

        OG_RETURN_IFERR(ogsql_bind_param_init(param_count));

        if (ogsql_bind_params(STMT, param_count) != OG_SUCCESS) {
            ogsql_bind_param_uninit(param_count);
            return OG_ERROR;
        }
    }

    ogsql_get_start_time_for_timer(&start_time);
    if (ogconn_execute(STMT) != OG_SUCCESS) {
        (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_SEROUTPUT_EXISTS, &seroutput_exists, sizeof(uint32), NULL);
        if (seroutput_exists) {
            ogsql_print_serveroutput();
        }

        ogsql_get_consumed_time_for_timer(start_time);
        ogsql_bind_param_uninit(param_count);
        ogsql_print_error(CONN);
        return OG_ERROR;
    }
    ogsql_get_consumed_time_for_timer(start_time);
    ogsql_bind_param_uninit(param_count);
    return OG_SUCCESS;
}

static void ogsql_print_serveroutput(void)
{
    char *output_str = NULL;
    uint32 output_len;
    int32 rows;

    rows = ogconn_fetch_serveroutput(STMT, &output_str, &output_len);
    while (rows == 1) {
        ogsql_printf("%s\n", output_str);

        rows = ogconn_fetch_serveroutput(STMT, &output_str, &output_len);
    }
}

static void ogsql_print_returnresult(void)
{
    ogconn_stmt_t resultset = NULL;
    ogconn_stmt_t org_stmt = NULL;
    uint32 pos = 0;

    if (ogconn_get_implicit_resultset(STMT, &resultset) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return;
    }

    while (resultset != NULL) {
        pos++;
        ogsql_printf("ResultSet #%u\n", pos);
        ogsql_printf("\n");

        org_stmt = g_conn_info.stmt;
        g_conn_info.stmt = resultset;
        ogsql_print_result();
        g_conn_info.stmt = org_stmt;

        if (ogconn_get_implicit_resultset(STMT, &resultset) != OG_SUCCESS) {
            ogsql_print_error(CONN);
            return;
        }

        if (resultset != NULL) {
            ogsql_printf("\n");
        }
    }
}

static void ogsql_print_outparams()
{
    uint32 outparam_count = 0;
    uint32 rows;
    uint32 i;
    ogconn_outparam_desc_t def;
    char *data = NULL;
    uint32 size;
    uint32 is_null;
    ogconn_stmt_t org_stmt;

    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_OUTPARAM_COUNT, &outparam_count, sizeof(uint32), NULL);
    if (outparam_count == 0) {
        return;
    }

    if (ogconn_fetch_outparam(STMT, &rows) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return;
    }

    for (i = 0; i < outparam_count; i++) {
        if (ogconn_desc_outparam_by_id(STMT, i, &def) != OGCONN_SUCCESS ||
            ogconn_get_outparam_by_id(STMT, i, (void **)&data, &size, &is_null) != OGCONN_SUCCESS) {
            ogsql_print_error(CONN);
            return;
        }

        ogsql_printf("OutParam #%u\n", i + 1);
        ogsql_printf("\n");
        ogsql_printf("name=[%s]\n", def.name);
        ogsql_printf("direction=[%u]\n", def.direction);
        ogsql_printf("type=[%s]\n", get_datatype_name_str(def.type + OG_TYPE_BASE));

        if (size == OGCONN_NULL) {
            ogsql_printf("value=[%s]\n", "NULL");
            continue;
        }

        g_str_buf[0] = '\0';
        if (ogconn_outparam_as_string_by_id(STMT, i, g_str_buf, OG_MAX_PACKET_SIZE) != OG_SUCCESS) {
            ogsql_print_error(CONN);
            return;
        }
        ogsql_printf("value=[%s]\n", g_str_buf);

        if (def.type == OGCONN_TYPE_CURSOR) {
            org_stmt = g_conn_info.stmt;
            g_conn_info.stmt = (ogconn_stmt_t)data;
            ogsql_print_result();
            g_conn_info.stmt = org_stmt;
        }

        if (i < outparam_count - 1) {
            ogsql_printf("\n");
        }
    }
}

static inline void ogsql_print_result_DML(bool32 seroutput_exists, bool32 returnresult_exists)
{
    uint32 rows = 0;

    if (seroutput_exists) {
        ogsql_print_serveroutput();
        ogsql_printf("\n");
    }

    if (returnresult_exists) {
        ogsql_print_returnresult();
        ogsql_printf("\n");
    }

    if (g_local_config.feedback.feedback_on) {
        (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_AFFECTED_ROWS, &rows, sizeof(uint32), NULL);
        ogsql_printf("%u rows affected.\n", rows);
        ogsql_printf("\n");
    }
}

static inline void ogsql_print_result_PL(bool32 seroutput_exists, bool32 returnresult_exists)
{
    uint32 outparam_count = 0;

    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_OUTPARAM_COUNT, &outparam_count, sizeof(uint32), NULL);

    if (seroutput_exists) {
        ogsql_print_serveroutput();
        ogsql_printf("\n");
    }

    if (g_local_config.feedback.feedback_on) {
        ogsql_printf("PL/SQL procedure successfully completed.\n");
        ogsql_printf("\n");
    }

    if (outparam_count > 0) {
        ogsql_print_outparams();
        ogsql_printf("\n");
    }

    if (returnresult_exists) {
        ogsql_print_returnresult();
        ogsql_printf("\n");
    }
}

static void ogsql_no_print_result()
{
    bool32 rs_exists = OG_FALSE;
    date_t start_time = 0;
    uint32 rows;

    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_RESULTSET_EXISTS, &rs_exists, sizeof(uint32), NULL);

    if (rs_exists) {
        ogsql_get_start_time_for_timer(&start_time);
        if (ogconn_fetch(STMT, &rows) != OG_SUCCESS) {
            ogsql_print_error(CONN);
            return;
        }
        ogsql_get_consumed_time_for_timer(start_time);

        while (rows > 0) {
            if (OGSQL_CANCELING) {
                return;
            }

            ogsql_get_start_time_for_timer(&start_time);
            if (ogconn_fetch(STMT, &rows) != OG_SUCCESS) {
                ogsql_print_error(CONN);
                return;
            }
            ogsql_get_consumed_time_for_timer(start_time);
        }
    }
}

static void ogsql_print_backup_result(uint32 stmt_type, char *message)
{
    if (stmt_type == OGCONN_STMT_DCL && message != NULL && message[0] != '\0' &&
        ((strncmp(message, "[BACKUP]", strlen("[BACKUP]")) == 0) ||
        (strncmp(message, "[RESTORE]", strlen("[RESTORE]")) == 0))) {
            ogsql_printf("Warning:\n");
            ogsql_printf("%s\n", message);
    }
}

void ogsql_print_result(void)
{
    bool32 rs_exists = OG_FALSE;
    bool32 seroutput_exists = OG_FALSE;
    bool32 returnresult_exists = OG_FALSE;
    uint32 rows = 0;
    uint32 stmt_type = OGCONN_STMT_NONE;
    char *message = NULL;

    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_RESULTSET_EXISTS, &rs_exists, sizeof(uint32), NULL);
    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_SEROUTPUT_EXISTS, &seroutput_exists, sizeof(uint32), NULL);
    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_RETURNRESULT_EXISTS, &returnresult_exists, sizeof(uint32), NULL);
    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_STMT_TYPE, &stmt_type, sizeof(uint32), NULL);

    if (rs_exists) {
        ogsql_print_resultset();
        ogsql_printf("\n");
        if (g_local_config.feedback.feedback_on) {
            (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_FETCHED_ROWS, &rows, sizeof(uint32), NULL);
            if (g_local_config.feedback.feedback_rows == 1 || rows >= g_local_config.feedback.feedback_rows) {
                ogsql_printf("%u rows fetched.\n", rows);
                ogsql_printf("\n");
            }
        }
        if (seroutput_exists) {
            ogsql_print_serveroutput();
            ogsql_printf("\n");
        }
        if (returnresult_exists) {
            ogsql_print_returnresult();
            ogsql_printf("\n");
        }
    } else if (stmt_type == OGCONN_STMT_DML) {
        ogsql_print_result_DML(seroutput_exists, returnresult_exists);
    } else if (stmt_type == OGCONN_STMT_PL) {
        ogsql_print_result_PL(seroutput_exists, returnresult_exists);
    } else {
        if (g_local_config.feedback.feedback_on) {
            ogsql_printf("Succeed.\n");

            message = ogconn_get_message(CONN);
            if (stmt_type == OGCONN_STMT_DDL && message != NULL && message[0] != '\0') {
                ogsql_printf("Warning:\n");
                ogsql_printf("%s\n", message);
            }
            ogsql_print_backup_result(stmt_type, message);

            ogsql_printf("\n");
        }
    }
}

static void ogsql_exec_whenever()
{
    if (g_local_config.whenever.commit_type == 0) {
        (void)ogconn_rollback(CONN);
    } else {
        (void)ogconn_commit(CONN);
    }

    if (g_local_config.whenever.continue_type == 0) {
        ogsql_exit(OG_TRUE, 0);
    }

    g_local_config.whenever.is_on = OG_FALSE;
}

static inline status_t ogsql_concat(text_t *line);

static bool32 ogconn_if_need_trace()
{
    uint32 stmt_type = OGCONN_STMT_NONE;
    bool32 seroutput_exists = OG_FALSE;
    bool32 returnresult_exists = OG_FALSE;

    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_STMT_TYPE, (const void *)&stmt_type, sizeof(uint32), NULL);
    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_SEROUTPUT_EXISTS, &seroutput_exists, sizeof(uint32), NULL);
    (void)ogconn_get_stmt_attr(STMT, OGCONN_ATTR_RETURNRESULT_EXISTS, &returnresult_exists, sizeof(uint32), NULL);

    if (stmt_type != OGCONN_STMT_DML || seroutput_exists || returnresult_exists) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

status_t ogsql_execute(text_t *line)
{
    text_t output_sql;

    if (line != NULL) {
        (void)cm_text_set(&g_sql_text, g_sql_text.len, '\0');
        CM_TEXT_CLEAR(&g_sql_text);
        OG_RETURN_IFERR(ogsql_concat(line));
    }

    if (cm_abs64(g_sql_text.str + g_sql_text.len - g_sql_buf) > MAX_SQL_SIZE) {
        OGSQL_PRINTF(ZSERR_OGSQL, "execute sql length exceed maxsize(%u)", MAX_SQL_SIZE);
        return OG_ERROR;
    }

    CM_NULL_TERM(&g_sql_text);

    if (g_local_config.print_on) {
        ogsql_regular_match_sensitive(g_sql_buf, strlen(g_sql_buf), &output_sql);
        ogsql_printf("%s;", output_sql.str);
    }

    ogsql_printf("\n");
    status_t ret = OG_SUCCESS;

    do {
        if (!IS_CONN) {
            OGSQL_PRINTF(ZSERR_OGSQL, "connection is not established");
            ret = OG_ERROR;
            break;
        }

        /* execute sql and print result */
        ogsql_reset_timer();

        if (ogsql_execute_sql() != OG_SUCCESS) {
            ogsql_print_timer();

            if (g_local_config.whenever.is_on) {
                ogsql_exec_whenever();
            }
            ret = OG_ERROR;
            break;
        }
    } while (0);
    
    MEMS_RETURN_IFERR(memset_s(g_sql_buf, sizeof(g_sql_buf), 0, g_sql_text.len));
    CM_TEXT_CLEAR(&g_sql_text);
    OG_RETURN_IFERR(ret);

    if (g_local_config.trace_mode == OGSQL_TRACE_ONLY && ogconn_if_need_trace()) {
        ogsql_no_print_result();
    } else {
        ogsql_print_result();
    }

    ogsql_print_timer();
    return OG_SUCCESS;
}

static inline status_t ogsql_concat(text_t *line)
{
    if (line->len + g_sql_text.len + 1 > MAX_SQL_SIZE) {
        OGSQL_PRINTF(ZSERR_OGSQL, "the SQL size too long ( > %u characters)", MAX_SQL_SIZE);
        return OG_ERROR;
    }

    cm_concat_text(&g_sql_text, MAX_SQL_SIZE, line);
    return OG_SUCCESS;
}
static inline status_t ogsql_concat_appendlf(text_t *line)
{
    if (line->len + g_sql_text.len + 1 > MAX_SQL_SIZE) {
        OGSQL_PRINTF(ZSERR_OGSQL, "the SQL size too long ( > %u characters)", MAX_SQL_SIZE);
        return OG_ERROR;
    }

    if (!CM_IS_EMPTY(&g_sql_text)) {
        CM_TEXT_APPEND(&g_sql_text, '\n');
    }

    cm_concat_text(&g_sql_text, MAX_SQL_SIZE, line);
    return OG_SUCCESS;
}

status_t ogsql_set_trx_iso_level(text_t *line)
{
    cm_trim_text(line);
    if (CM_TEXT_END(line) == ';') {
        line->len--;
    }

    if (line->len >= MAX_SQL_SIZE) {
        ogsql_printf("set content exceed maxsize(%u).\n", MAX_SQL_SIZE);
        return OG_ERROR;
    }

    CM_TEXT_CLEAR(&g_sql_text);
    cm_concat_text(&g_sql_text, MAX_SQL_SIZE, line);
    CM_NULL_TERM(&g_sql_text);

    return ogsql_execute(NULL);
}

static void ogsql_display_column_usage(void)
{
    ogsql_printf("Usage:\n");
    ogsql_printf("COL|COLUMN clear\n");
    ogsql_printf("COL|COLUMN [{column|expr} [option ...]]\n");
    ogsql_printf("where option represents one of the following clauses:\n");
    ogsql_printf("ON|OFF\n");
    ogsql_printf("FOR[MAT] a|ACOLUMN_WIDTH(example: column F1 for a10)\n");
}

static ogsql_column_format_attr_t *ogsql_get_column_attr(text_t *column)
{
    uint32 i;
    ogsql_column_format_attr_t *col_format = NULL;

    for (i = 0; i < g_local_config.column_formats.count; i++) {
        col_format = (ogsql_column_format_attr_t *)cm_list_get(&g_local_config.column_formats, i);
        if (cm_text_str_equal_ins(column, col_format->col_name)) {
            return col_format;
        }
    }

    return NULL;
}

static status_t ogsql_column_on_off(text_t *params, text_t *column, bool32 is_on,
                                   ogsql_column_format_attr_t *col_attr)
{
    if (col_attr == NULL) {
        column->str[column->len] = '\0';
        ogsql_printf("COLUMN '%s' not defined.\n", column->str);
        return OG_ERROR;
    }

    col_attr->is_on = is_on;

    // expect end
    cm_trim_text(params);
    if (params->len != 0) {
        ogsql_printf("Column failed.\n\n");
        ogsql_display_column_usage();
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogsql_column_format(text_t *params, text_t *column, ogsql_column_format_attr_t *col_format)
{
    ogsql_column_format_attr_t *new_col_format = NULL;
    text_t option;
    uint32 col_width;

    cm_trim_text(params);
    if (params->len == 0 || !cm_fetch_text(params, ' ', '\0', &option) || option.len < 1 || (option.str[0] != 'a' &&
            option.str[0] != 'A')) {
        ogsql_printf("Column failed.\n\n");
        ogsql_display_column_usage();
        return OG_ERROR;
    }

    option.str++;
    option.len--;

    if (option.len == 0 || cm_text2uint32(&option, &col_width) != OG_SUCCESS || col_width == 0) {
        ogsql_printf("Illegal FORMAT string.\n");
        return OG_ERROR;
    }

    // expect end
    cm_trim_text(params);
    if (params->len != 0) {
        ogsql_printf("unknown COLUMN option, expect end.\n");
        return OG_ERROR;
    }

    if (col_format == NULL) {
        if (cm_list_new(&g_local_config.column_formats, (void **)&new_col_format) != OG_SUCCESS) {
            ogsql_printf("alloc space for add column format failed.\n");
            return OG_ERROR;
        }
        col_format = new_col_format;
        if (column->len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(col_format->col_name, OG_MAX_NAME_LEN, column->str, column->len));
        }
    }

    col_format->is_on = OG_TRUE;
    col_format->col_width = col_width;
    return OG_SUCCESS;
}

static status_t ogsql_column(text_t *params)
{
    text_t option;
    text_t column;
    bool32 is_clear = OG_FALSE;
    ogsql_column_format_attr_t *col_attr;

    col_attr = NULL;

    cm_trim_text(params);
    if (params->len == 0) {
        ogsql_printf("Column failed.\n\n");
        ogsql_display_column_usage();
        return OG_ERROR;
    }

    if (!cm_fetch_text(params, ' ', '\0', &option)) {
        ogsql_printf("Column failed.\n\n");
        ogsql_display_column_usage();
        return OG_ERROR;
    }

    // column clear
    if (cm_text_str_equal_ins(&option, "CLEAR")) {
        is_clear = OG_TRUE;
    }

    cm_trim_text(params);
    if (params->len == 0) {
        if (is_clear) {
            cm_reset_list(&g_local_config.column_formats);
            ogsql_printf("Column format cleared.\n\n");
            return OG_SUCCESS;
        } else {
            ogsql_printf("Column failed.\n\n");
            ogsql_display_column_usage();
            return OG_ERROR;
        }
    }

    // get column name
    column = option;
    col_attr = ogsql_get_column_attr(&column);

    // column column_name on|off|format
    if (!cm_fetch_text(params, ' ', '\0', &option)) {
        ogsql_printf("Column failed.\n\n");
        ogsql_display_column_usage();
        return OG_ERROR;
    }

    if (cm_text_str_equal_ins(&option, "ON")) {
        return ogsql_column_on_off(params, &column, OG_TRUE, col_attr);
    } else if (cm_text_str_equal_ins(&option, "OFF")) {
        return ogsql_column_on_off(params, &column, OG_FALSE, col_attr);
    } else if (cm_text_str_less_equal_ins(&option, "FORMAT", 3)) {
        return ogsql_column_format(params, &column, col_attr);
    } else {
        ogsql_printf("Column failed.\n\n");
        ogsql_display_column_usage();
        return OG_ERROR;
    }
}

static void ogsql_display_whenever_usage(void)
{
    ogsql_printf("Usage:\n");
    ogsql_printf("WHENEVER SQLERROR\n");
    ogsql_printf("{ CONTINUE [ COMMIT | ROLLBACK ]\n");
    ogsql_printf("| EXIT [ COMMIT | ROLLBACK ] }\n");
}

static status_t ogsql_parse_whenever(text_t *params, whenever_t *whenever)
{
    text_t option;

    // try get sqlerror
    cm_trim_text(params);
    if (params->len == 0 || !cm_fetch_text(params, ' ', '\0', &option) ||
        !cm_text_str_equal_ins(&option, "SQLERROR")) {
        return OG_ERROR;
    }
    whenever->error_type = 0;

    // try get continue|exit
    cm_trim_text(params);
    if (params->len == 0 || !cm_fetch_text(params, ' ', '\0', &option)) {
        return OG_ERROR;
    }

    if (cm_text_str_equal_ins(&option, "CONTINUE")) {
        whenever->continue_type = 1;
    } else if (cm_text_str_equal_ins(&option, "EXIT")) {
        whenever->continue_type = 0;
    } else {
        return OG_ERROR;
    }

    // try get commit|rollback
    cm_trim_text(params);
    if (params->len == 0) {
        whenever->commit_type = 0;
    } else {
        (void)cm_fetch_text(params, ' ', '\0', &option);
        if (cm_text_str_equal_ins(&option, "COMMIT")) {
            whenever->commit_type = 1;
        } else if (cm_text_str_equal_ins(&option, "ROLLBACK")) {
            whenever->commit_type = 0;
        } else {
            return OG_ERROR;
        }
    }

    // expect end
    cm_trim_text(params);
    if (params->len != 0) {
        return OG_ERROR;
    }

    whenever->is_on = OG_TRUE;
    return OG_SUCCESS;
}

static status_t ogsql_whenever(text_t *params)
{
    whenever_t whenever;

    if (ogsql_parse_whenever(params, &whenever) != OG_SUCCESS) {
        ogsql_printf("Whenever failed.\n\n");
        ogsql_display_whenever_usage();
        return OG_ERROR;
    }

    g_local_config.whenever = whenever;

    return OG_SUCCESS;
}

static status_t ogsql_prompt(text_t *params)
{
    if (params->str == NULL) {
        ogsql_printf("%s", "");
        return OG_SUCCESS;
    }

    if (strlen(params->str) > MAX_CMD_LEN) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Input is too long (> %d characters) - line ignored", MAX_CMD_LEN);
        return OG_ERROR;
    }

    cm_trim_text(params);
    char buf[MAX_CMD_LEN];
    OG_RETURN_IFERR(cm_text2str(params, buf, MAX_CMD_LEN));
    ogsql_printf("%s", buf);
    return OG_SUCCESS;
}

static void ogsql_replace_LF_with_space(char *buf)
{
    uint32 len = (uint32)strlen(buf);
    uint32 i = 0;

    for (; i < len; i++) {
        if (buf[i] == '\n') {
            buf[i] = ' ';
        }
    }
}

static void ogsql_oper_log(char *buf, uint32 len)
{
    char date[OG_MAX_TIME_STRLEN];
    char *log_buf = NULL;
    uint32 log_buf_len;
    uint32 offset;
    text_t oper_log;
    errno_t errcode;
    int32 mattch_type;
    bool32 mattched = OG_FALSE;

    OG_RETVOID_IFTRUE(!LOG_OPER_ON);

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, OG_MAX_TIME_STRLEN);
    ogsql_replace_LF_with_space(buf);

    oper_log.str = buf;
    oper_log.len = len;

    cm_text_try_map_key2type(&oper_log, &mattch_type, &mattched);
    if (mattched == OG_TRUE) {
        oper_log.str = g_key_pattern[mattch_type].type_desc;
        oper_log.len = (uint32)strlen(g_key_pattern[mattch_type].type_desc);
    }

    offset = (uint32)strlen(date);
    log_buf_len = offset + 7 + oper_log.len + 1;  // date|ogsql|cmd

    log_buf = (char *)malloc(log_buf_len);
    OG_RETVOID_IFTRUE(log_buf == NULL);

    do {
        errcode = memcpy_s(log_buf, log_buf_len, date, offset);
        if (errcode != EOK) {
            ogsql_printf("Copying date to log_buf failed");
            break;
        }

        errcode = memcpy_s(log_buf + offset, log_buf_len - offset, "|ogsql|", strlen("|ogsql|"));
        if (errcode != EOK) {
            ogsql_printf("Copying string '|ogsql|' failed");
            break;
        }

        offset += (uint32)strlen("|ogsql|");
        errcode = memcpy_s(log_buf + offset, log_buf_len - offset, oper_log.str, oper_log.len);
        if (errcode != EOK) {
            ogsql_printf("Copying message '%s' from oper_log failed", oper_log.str);
            break;
        }

        log_buf[log_buf_len - 1] = '\0';
        cm_write_oper_log(log_buf, log_buf_len - 1);
    } while (0);
    
    CM_FREE_PTR(log_buf);
}

static void print_sql_command(const char *sql_buf, uint32 len)
{
    char *temp = NULL;
    errno_t errcode;
    text_t output_sql;

    if (len == 0) {
        return;
    }

    temp = (char *)malloc(len + 1);
    if (temp == NULL) {
        return;
    }

    errcode = memcpy_s(temp, len + 1, sql_buf, len);
    if (errcode != EOK) {
        CM_FREE_PTR(temp);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    temp[len] = '\0';

    if (g_is_print == OG_TRUE && g_local_config.script_output == OG_TRUE) {
        ogsql_regular_match_sensitive(temp, len, &output_sql);
        ogsql_printf("%s\n", output_sql.str);
    }

    ogsql_oper_log(temp, len);
    (void)memset_s(temp, len + 1, 0, len + 1);
    CM_FREE_PTR(temp);
    return;
}

static inline void cm_text_append_text_head(text_t *text, uint32 len, const text_t head)
{
    uint32 index = len;
    while (index-- > 0) {
        text->str[index + head.len] = text->str[index];
    }
    for (uint32 i = 0; i < head.len; i++) {
        text->str[i] = head.str[i];
    }
    text->len = len + head.len;
}

static status_t ogsql_process_autotrace_cmd(void)
{
    if (!ogconn_if_need_trace()) {
        return OG_SUCCESS;
    }
    if (ogconn_get_autotrace_result(STMT) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    }
    ogsql_print_result();
    return OG_SUCCESS;
}

static status_t ogsql_exec_multiline_cmd()
{
    text_t sql_text;
    status_t status = OG_SUCCESS;

    sql_text = g_sql_text;
    print_sql_command(g_sql_text.str, g_sql_text.len);
    ogsql_reset_in_enclosed_char();

    cm_trim_text(&sql_text);
    if (CM_IS_EMPTY(&sql_text)) {
        OGSQL_RESET_CMD_TYPE(&g_cmd_type);
        OGSQL_PRINTF(ZSERR_OGSQL, "Nothing in SQL buffer to run");
        return status;
    }

    /* Step 1: Re-fetch the type of the command in SQL buffer */
    if (!ogsql_find_cmd(&sql_text, &g_cmd_type)) {
        OGSQL_RESET_CMD_TYPE(&g_cmd_type);
        OGSQL_PRINTF(ZSERR_OGSQL, "Nothing in SQL buffer to run");
        return status;
    }

    /* Step 2: Execute multi-line command  */
    sql_text = g_sql_text;

    if (g_cmd_type.cmd == CMD_LOAD) {
        date_t start_time = 0;
        ogsql_get_start_time_for_timer(&start_time);
        ogsql_reset_timer();

        status = ogsql_load(&sql_text);

        ogsql_get_consumed_time_for_timer(start_time);
        ogsql_print_timer();
    } else if (g_cmd_type.cmd == CMD_DUMP) {
        date_t start_time = 0;
        ogsql_get_start_time_for_timer(&start_time);
        ogsql_reset_timer();

        status = ogsql_dump(&sql_text);

        ogsql_get_consumed_time_for_timer(start_time);
        ogsql_print_timer();
    } else if (g_cmd_type.cmd == CMD_EXPORT) {
        status = ogsql_export(&sql_text, OG_TRUE);
    } else if (g_cmd_type.cmd == CMD_IMPORT) {
        status = ogsql_import(&sql_text);
    } else {
        (void)ogconn_set_conn_attr(CONN, OGCONN_ATTR_AUTOTRACE, &g_local_config.trace_mode, sizeof(uint32));
        status = ogsql_execute(NULL);
        if (status == OG_SUCCESS && !OGSQL_CANCELING && g_local_config.trace_mode) {
            status = ogsql_process_autotrace_cmd();
        }
        uint32 trace_off = OGSQL_TRACE_OFF;
        (void)ogconn_set_conn_attr(CONN, OGCONN_ATTR_AUTOTRACE, &trace_off, sizeof(uint32));
    }
    /* Step 3: Clear the SQL buffer and reset the command type */
    OGSQL_RESET_CMD_TYPE(&g_cmd_type);
    (void)cm_text_set(&g_sql_text, g_sql_text.len, '\0');
    CM_TEXT_CLEAR(&g_sql_text);
    return status;
}

static status_t ogsql_process_multiline_cmd(text_t *line)
{
    bool32 is_end = OG_FALSE;

    cm_trim_text(line);
    if (CM_TEXT_END(line) == ';' && g_in_comment_count == 0) {
        is_end = OG_TRUE;
        line->len--;
    }

    if (ogsql_concat_appendlf(line) != OG_SUCCESS) {
        if (is_end) {
            (void)cm_text_set(&g_sql_text, g_sql_text.len, '\0');
            CM_TEXT_CLEAR(&g_sql_text);
        }
        return OG_ERROR;
    }

    /* If the multi-line command terminates */
    if (is_end) {
        if (ogsql_exec_multiline_cmd() != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

#ifndef WIN32
#define DEFAULT_SHELL "/bin/sh"
#else
#define DEFAULT_SHELL "cmd.exe"
#endif

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static bool32 is_match_white_list(const char *shell_name)
{
#ifdef WIN32
    uint32 len = (uint32)strlen(shell_name);
    const char *matcher = "cmd.exe";
    int32 offset = len - (int32)strlen(matcher);
    if (offset < 0) {
        return OG_FALSE;
    }
    if (cm_strcmpi(shell_name + offset, matcher) != 0) {
        return OG_FALSE;
    }
    for (uint32 i = 0; i < len; i++) {
        if (shell_name[i] == ';') {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
#else
    if (cm_strcmpi(shell_name, "/bin/sh") == 0 ||
        cm_strcmpi(shell_name, "/bin/bash") == 0 ||
        cm_strcmpi(shell_name, "/sbin/nologin") == 0 ||
        cm_strcmpi(shell_name, "/usr/bin/sh") == 0 ||
        cm_strcmpi(shell_name, "/usr/bin/bash") == 0 ||
        cm_strcmpi(shell_name, "/usr/sbin/nologin") == 0 ||
        cm_strcmpi(shell_name, "/bin/tcsh") == 0 ||
        cm_strcmpi(shell_name, "/bin/csh") == 0) {
        return OG_TRUE;
    }
    return OG_FALSE;
#endif
}
#endif

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static status_t ogsql_do_shell(text_t *command)
{
    const char *shell_name = NULL;
    char path[OG_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    if (CM_IS_EMPTY(command)) {
        OGSQL_PRINTF(ZSERR_OGSQL, "shell context is empty");
        return OG_ERROR;
    } else {
        char *cmd = NULL;
#ifdef WIN32
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        shell_name = getenv("COMSPEC");
        if (shell_name == NULL) {
            shell_name = DEFAULT_SHELL;
        }

        OG_RETURN_IFERR(realpath_file(shell_name, path, OG_FILE_NAME_BUFFER_SIZE));
        // white list
        if (!is_match_white_list(path)) {
            OG_THROW_ERROR(ERR_CMD_NOT_ALLOWED_TO_EXEC, path);
            return OG_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(&si, sizeof(STARTUPINFO), 0, sizeof(STARTUPINFO)));
        MEMS_RETURN_IFERR(memset_s(&pi, sizeof(PROCESS_INFORMATION), 0, sizeof(PROCESS_INFORMATION)));
        si.cb = sizeof(si);

        size_t len = strlen("/c ") + command->len;
        cmd = (char *)malloc(len + 1);
        if (cmd == NULL) {
            OGSQL_PRINTF(ZSERR_OGSQL, "failed to alloc memory for tmp cmd");
            return OG_ERROR;
        }

        if (snprintf_s(cmd, len + 1, len, "/c %s", command->str) == -1) {
            CM_FREE_PTR(cmd);
            OGSQL_PRINTF(ZSERR_OGSQL, "failed to snprintf cmd");
            return OG_ERROR;
        }

        cmd[len] = '\0';

        if (!CreateProcess(path, cmd, NULL, NULL,
                           FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi)) {
            CM_FREE_PTR(cmd);
            OGSQL_PRINTF(ZSERR_OGSQL, "\\!: failed, reason %d", GetLastError());
            return OG_ERROR;
        }
        (void)WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
#else
        int status;
        char *args[OG_MAX_CMD_ARGS + 1];
        pid_t child;
        shell_name = getenv("SHELL");
        if (shell_name == NULL) {
            shell_name = DEFAULT_SHELL;
        }

        OG_RETURN_IFERR(realpath_file(shell_name, path, OG_FILE_NAME_BUFFER_SIZE));
        // white list
        if (!is_match_white_list(path)) {
            OG_THROW_ERROR(ERR_CMD_NOT_ALLOWED_TO_EXEC, path);
            return OG_ERROR;
        }

        cmd = (char *)malloc(command->len + 1);
        if (cmd == NULL) {
            OGSQL_PRINTF(ZSERR_OGSQL, "failed to alloc memory for tmp cmd");
            return OG_ERROR;
        }

        errno_t errcode = memcpy_s(cmd, command->len + 1, command->str, command->len);
        if (errcode != EOK) {
            CM_FREE_PTR(cmd);
            OGSQL_PRINTF(ZSERR_OGSQL, "failed to copy command to tmp cmd");
            return OG_ERROR;
        }
        cmd[command->len] = '\0';
        args[0] = path;
        args[1] = "-c";
        args[2] = cmd;
        args[3] = NULL;

        child = fork();
        if (child == 0) {
            int ret = execve(path, args, environ);
            if (-1 == ret) {
                CM_FREE_PTR(cmd);
                OGSQL_PRINTF(ZSERR_OGSQL, "exec %s failed, reason %d", cmd, errno);
                return OG_ERROR;
            }
            CM_FREE_PTR(cmd);
            return OG_SUCCESS;
        } else if (child < 0) {
            CM_FREE_PTR(cmd);
            OGSQL_PRINTF(ZSERR_OGSQL, "fork child process failed");
            exit(OG_ERROR);
        }

        if (waitpid(child, &status, 0) != child) {
            CM_FREE_PTR(cmd);
            OGSQL_PRINTF(ZSERR_OGSQL, "wait child process (%d) failed", child);
            exit(OG_ERROR);
        }
#endif
        CM_FREE_PTR(cmd);
    }

    return OG_SUCCESS;
}
#endif

static status_t ogsql_run_normal_sqlfile(text_t *file_name);
static status_t ogsql_run_nested_sqlfile(text_t *file_name);

static status_t ogsql_exec_singline_cmd(ogsql_cmd_def_t *cmdtype, text_t *line, text_t *params)
{
    status_t status = OG_SUCCESS;

    print_sql_command(line->str, line->len);
    ogsql_reset_in_enclosed_char();
    ogsql_printf("\n");
    switch (cmdtype->cmd) {
        case CMD_NONE:
            break;

        case CMD_EXIT:
            ogsql_exit(OG_FALSE, 0);

        case CMD_SHOW:
            ogsql_show(params);
            break;

        case CMD_EXEC:
            status = ogsql_exec_multiline_cmd();
            break;

        case CMD_CONN:
            g_in_comment_count = 0;
            status = ogsql_connect(line);
            break;

        case CMD_DESC:
            status = ogsql_desc(params);
            break;

        case CMD_SQLFILE:
            status = ogsql_run_normal_sqlfile(params);
            break;

        case CMD_SQLFILE2:
            status = ogsql_run_nested_sqlfile(params);
            break;

        case CMD_SPOOL:
            status = ogsql_spool(params);
            break;

        case CMD_CLEAR:
#ifdef WIN32
            system("cls");
#else
            ogsql_printf("\033[H\033[J");
#endif
            break;

        case CMD_SET:
            status = ogsql_set(line, params);
            break;

        case CMD_COLUMN:
            status = ogsql_column(params);
            break;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        case CMD_SHELL:
            status = ogsql_do_shell(params);
            break;
#endif

        case CMD_WHENEVER:
            status = ogsql_whenever(params);
            break;

        case CMD_PROMPT:
            status = ogsql_prompt(params);
            break;

        case CMD_AWR:
            status = ogsql_wsr(params);
            break;

        case CMD_MONITOR:
            status = ogsql_monitor(params);
            break;

        default:
            break;
    }
    ogsql_printf("\n");
    return status;
}

static status_t encounter_prompt_cmd(const text_t *line)
{
    text_t left;
    text_t right;
    cm_split_text(line, ' ', 0, &left, &right);

    if (0 == cm_compare_text_str_ins(&left, "prompt") || 0 == cm_compare_text_str_ins(&left, "pro")) {
        return OG_TRUE;
    } else {
        return OG_FALSE;
    }
}

#define OGSQL_IS_ENCLOSED_CHAR(c) ((c) == '\'' || (c) == '"' || (c) == '`')
#define OGSQL_IS_SPLIT_CHAR(c)    ((c) == ';')

static bool32 ogsql_fetch_cmd(text_t *line, text_t *sub_cmd)
{
    uint32 i;
    char c;

    if (CM_IS_EMPTY(line)) {
        CM_TEXT_CLEAR(sub_cmd);
        return OG_FALSE;
    }

    sub_cmd->str = line->str;
    for (i = 0; i < line->len; i++) {
        c = line->str[i];
        /* enclosed char not in comment. */
        if (!g_in_comment_count && OGSQL_IS_ENCLOSED_CHAR(c)) {
            if (g_in_enclosed_char < 0) {
                g_in_enclosed_char = c;
            } else if (g_in_enclosed_char == c) {
                g_in_enclosed_char = -1;
            }
            continue;
        }

        if (g_in_enclosed_char > 0) {
            continue;
        }

        if (c == '/' && (i + 1 < line->len) && line->str[i + 1] == '*') {
            g_in_comment_count++;
            i = i + 1;
            continue;
        }

        if (c == '*' && (i + 1 < line->len) && line->str[i + 1] == '/') {
            if (g_in_comment_count > 0) {
                g_in_comment_count = 0;
            }
            i = i + 1;
            continue;
        }

        if (c == '-') {  // if line comment(--) is scanned
            if (!g_in_comment_count && ((i + 1 < line->len) && line->str[i + 1] == '-')) {
                sub_cmd->len = i;
                line->len = 0;
                line->str = NULL;
                return OG_TRUE;
            }
        }

        if (encounter_prompt_cmd(line)) {
            sub_cmd->len = line->len;
            line->len = 0;
            line->str = NULL;
            return OG_TRUE;
        }

        if (!g_in_comment_count && OGSQL_IS_SPLIT_CHAR(c)) {  // encounter split CHAR
            sub_cmd->len = i + 1;                            // include the split char
            line->str += i + 1;
            line->len -= (i + 1);
            return OG_TRUE;
        }
    }

    sub_cmd->len = line->len;
    line->len = 0;
    line->str = NULL;
    return OG_TRUE;
}

status_t ogsql_process_cmd(text_t *line)
{
    text_t params;
    text_t sub_cmd;
    ogsql_cmd_def_t cmdtype;

    cm_reset_error();

    cm_trim_text(line);
    while (ogsql_fetch_cmd(line, &sub_cmd)) {
        // handle multiple cmds in One line
        ogsql_get_cmd(sub_cmd, &cmdtype, &params);

        if (cmdtype.cmd == CMD_COMMENT) {  // if fetched the line comment
            return OG_SUCCESS;
        } else if (cmdtype.cmd == CMD_EXEC) {
            // the `/` merely used for multi-line cmd
            return ogsql_exec_multiline_cmd();
        } else if (cmdtype.cmd == CMD_NONE) {
            return OG_SUCCESS;
        }

        if (g_cmd_type.mode == MODE_NONE) {
            if (cmdtype.mode == MODE_SINGLE_LINE) {
                if (ogsql_exec_singline_cmd(&cmdtype, &sub_cmd, &params) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                continue;
            } else {
                g_cmd_type = cmdtype;
            }
        }

        if (ogsql_process_multiline_cmd(&sub_cmd) != OG_SUCCESS) {
            return OG_ERROR;
        }

        (void)cm_text_set(&sub_cmd, sub_cmd.len, '\0');
        continue;
    }
    return OG_SUCCESS;
}

static inline void ogsql_print_blank_line(void)
{
    ogsql_try_spool_directly_put("\n");
}

static text_t *g_curr_sql_dir = NULL;

static status_t ogsql_make_nested_filepath(const text_t *txt_fpath, char **str_realpath)
{
    uint32 path_len = 0;
    text_t filepath;
    char pathbuf[OG_MAX_FILE_PATH_LENGH];

    if (g_curr_sql_dir != NULL) {
        path_len += g_curr_sql_dir->len;
    }
    path_len += txt_fpath->len;

    if ((path_len >= OG_MAX_FILE_PATH_LENGH) || (path_len == 0)) {
        OG_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, OG_MAX_FILE_PATH_LENGH);
        return OG_ERROR;
    }

    // Step 1: get the (relative) filepath of nested file
    filepath.str = pathbuf;
    filepath.len = 0;

    if (g_curr_sql_dir != NULL) {
        cm_concat_text(&filepath, MAX_SQL_SIZE, g_curr_sql_dir);
    }
    cm_concat_text(&filepath, MAX_SQL_SIZE, txt_fpath);
    CM_NULL_TERM(&filepath);

    // Step 2: Alloc memory for the absolute filepath of nested file
    *str_realpath = (char *)malloc(OG_MAX_FILE_PATH_LENGH);
    if (*str_realpath == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)OG_MAX_FILE_PATH_LENGH, "make nested file path");
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(*str_realpath, OG_MAX_FILE_PATH_LENGH, 0, OG_MAX_FILE_PATH_LENGH));

    // Step 3: Get the absolute Path
    OG_RETURN_IFERR(realpath_file(pathbuf, *str_realpath, OG_MAX_FILE_PATH_LENGH));

    return OG_SUCCESS;
}

static status_t ogsql_make_normal_filepath(text_t *file_name, char **str_fpath)
{
    char file_name2[OG_MAX_FILE_PATH_LENGH];

    if ((file_name->len >= OG_MAX_FILE_PATH_LENGH) || (file_name->len <= 0)) {
        OG_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, OG_MAX_FILE_PATH_LENGH);
        return OG_ERROR;
    }

    *str_fpath = (char *)malloc(OG_MAX_FILE_PATH_LENGH);
    if (*str_fpath == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)OG_MAX_FILE_PATH_LENGH, "make normal file path");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(*str_fpath, OG_MAX_FILE_PATH_LENGH, 0, OG_MAX_FILE_PATH_LENGH));
    OG_RETURN_IFERR(cm_text2str(file_name, file_name2, OG_MAX_FILE_PATH_LENGH));
    OG_RETURN_IFERR(realpath_file(file_name2, *str_fpath, OG_MAX_FILE_PATH_LENGH));

    file_name->str = *str_fpath;
    file_name->len = (uint32)strlen(*str_fpath);

    return OG_SUCCESS;
}

static inline status_t ogsql_set_curr_sql_work_dir(text_t *file_name, text_t **last_sql_dir)
{
    int32 pos = cm_text_rchr2(file_name, "\\/");

    *last_sql_dir = g_curr_sql_dir;
    if (pos < 0) {
        g_curr_sql_dir = NULL;
        return OG_SUCCESS;
    }

    file_name->len = (uint32)pos + 1;
    OG_RETURN_IFERR(cm_text_dup(file_name, &g_curr_sql_dir));
    cm_convert_os_path(g_curr_sql_dir);
    return OG_SUCCESS;
}

static inline void ogsql_reset_curr_sql_work_dir(text_t *last_sql_dir)
{
    cm_free_text(g_curr_sql_dir);
    g_curr_sql_dir = last_sql_dir;
}

static inline void ogsql_run_sqlfile(FILE *file)
{
    bool32 temp_slient_on = g_local_config.silent_on;
    char cmd_buf[MAX_CMD_LEN + 2];

    g_is_print = OG_TRUE;
    g_local_config.silent_on = g_local_config.termout_on;

    ogsql_reset_cmd_buf(cmd_buf, sizeof(cmd_buf));
    ogsql_run(file, OG_TRUE, cmd_buf, sizeof(cmd_buf));

    g_local_config.silent_on = temp_slient_on;
    g_is_print = OG_FALSE;
}

static status_t ogsql_run_normal_sqlfile(text_t *file_name)
{
    FILE *file = NULL;
    char *str_realpath = NULL;

    text_t *last_sql_dir = NULL;

    cm_trim_text(file_name);
    if (file_name->len > 0 && CM_TEXT_END(file_name) == ';') {
        CM_REMOVE_LAST(file_name);
        if (CM_IS_EMPTY(file_name)) {
            OGSQL_PRINTF(ZSERR_OGSQL, "File name expected\n");
            return OG_ERROR;
        }
    }

    if (file_name->len == 0) {
        OGSQL_PRINTF(ZSERR_OGSQL, "START, @ or @@ command has no arguments");
        return OG_ERROR;
    }

    if (ogsql_make_normal_filepath(file_name, &str_realpath) != OG_SUCCESS) {
        if (str_realpath != NULL) {
            CM_FREE_PTR(str_realpath);
        }
        return OG_ERROR;
    }

    if (ogsql_set_curr_sql_work_dir(file_name, &last_sql_dir) != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "Not expected file path");
        CM_FREE_PTR(str_realpath);
        return OG_ERROR;
    }

    file = fopen(str_realpath, "r");
    if (file == NULL) {
        OGSQL_PRINTF(ZSERR_OGSQL, "fail to open file '%s'", str_realpath);
        CM_FREE_PTR(str_realpath);
        ogsql_reset_curr_sql_work_dir(last_sql_dir);
        return OG_ERROR;
    }
    ogsql_run_sqlfile(file);
    ogsql_printf("\n");
    (void)fclose(file);
    CM_FREE_PTR(str_realpath);
    ogsql_reset_curr_sql_work_dir(last_sql_dir);
    return OG_SUCCESS;
}

static status_t ogsql_run_nested_sqlfile(text_t *file_name)
{
    FILE *file = NULL;
    char *str_realpath = NULL;

    cm_trim_text(file_name);
    if (file_name->len > 0 && CM_TEXT_END(file_name) == ';') {
        CM_REMOVE_LAST(file_name);
        if (CM_IS_EMPTY(file_name)) {
            OGSQL_PRINTF(ZSERR_OGSQL, "File name expected");
            return OG_ERROR;
        }
    }
    if (file_name->len == 0) {
        OGSQL_PRINTF(ZSERR_OGSQL, "START, @ or @@ command has no arguments");
        return OG_ERROR;
    }
    // search the file from g_curr_sql_dir
    if (ogsql_make_nested_filepath(file_name, &str_realpath) != OG_SUCCESS) {
        if (str_realpath != NULL) {
            CM_FREE_PTR(str_realpath);
        }
        OGSQL_PRINTF(ZSERR_OGSQL, "Not expected file path");
        return OG_ERROR;
    }

    file = fopen(str_realpath, "r");
    if (file == NULL) {
        OGSQL_PRINTF(ZSERR_OGSQL, "fail to open file '%s'", str_realpath);
        CM_FREE_PTR(str_realpath);
        return OG_ERROR;
    }
    ogsql_run_sqlfile(file);
    ogsql_printf("\n");
    (void)fclose(file);
    CM_FREE_PTR(str_realpath);
    return OG_SUCCESS;
}

static void ogsql_init_local_config(void)
{
    g_local_config.auto_commit = OG_FALSE;
    g_local_config.exit_commit = OG_TRUE;
    g_local_config.charset_id = CHARSET_UTF8;
    g_local_config.heading_on = OG_TRUE;
    g_local_config.server_ouput = OG_FALSE;
    g_local_config.trim_spool = OG_FALSE;
    g_local_config.spool_on = OG_FALSE;
    g_local_config.line_size = 0;
    g_local_config.page_size = 0;
    g_local_config.timer.timing_on = OG_FALSE;
    g_local_config.timer.consumed_time = 0;
    g_local_config.feedback.feedback_on = OG_TRUE;
    g_local_config.feedback.feedback_rows = 1;
    g_local_config.trace_mode = OGSQL_TRACE_OFF;
    cm_create_list(&g_local_config.column_formats, sizeof(ogsql_column_format_attr_t));
    g_local_config.silent_on = OG_FALSE;
    g_local_config.print_on = OG_FALSE;
    MEMS_RETVOID_IFERR(memset_s(&g_local_config.whenever, sizeof(whenever_t), 0, sizeof(whenever_t)));
    g_local_config.long_size = OGSQL_MAX_LONG_SIZE;
    MEMS_RETVOID_IFERR(memcpy_s(g_local_config.colsep.colsep_name, MAX_COLSEP_NAME_LEN, " ", 1));
    g_local_config.colsep.colsep_len = 1;
    g_local_config.newpage = 1;
    g_local_config.verify_on = OG_TRUE;
    g_local_config.termout_on = OG_FALSE;  // reuse g_local_config.slient_on, OG_FALSE means on
    g_local_config.script_output = OG_FALSE;
    g_local_config.define_on = OG_FALSE;
    g_local_config.ssl_ca[0] = '\0';
    g_local_config.ssl_cert[0] = '\0';
    g_local_config.ssl_key[0] = '\0';
    g_local_config.ssl_mode = OGCONN_SSL_PREFERRED;
    g_local_config.is_cancel = OG_FALSE;
    g_local_config.OGSQL_SSL_QUIET = OG_FALSE;
    g_local_config.OGSQL_INTERACTION_TIMEOUT = OGSQL_INTERACTION_DEFAULT_TIMEOUT;
    g_local_config.connect_timeout = (int32)OG_CONNECT_TIMEOUT / OG_TIME_THOUSAND_UN;
    g_local_config.socket_timeout = -1;
    g_local_config.server_path[0] = '\0';
    g_local_config.client_path[0] = '\0';
    g_local_config.bindparam_force_on  = OG_FALSE;
    g_local_config.shd_rw_split = OGCONN_SHD_RW_SPLIT_NONE;
}

static inline void ogsql_init_backup_file_count(char *value, log_param_t *log_param)
{
    uint32 val_uint32;
    /* parse and check _LOG_BACKUP_FILE_COUNT */
    value = cm_get_config_value(g_server_config, "_LOG_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != OG_SUCCESS) {
        log_param->log_backup_file_count = 2;
    } else if (val_uint32 > OG_MAX_LOG_FILE_COUNT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)OG_MAX_LOG_FILE_COUNT);
        return;
    } else {
        log_param->log_backup_file_count = val_uint32;
    }

    /* parse and check _AUDIT_BACKUP_FILE_COUNT */
    value = cm_get_config_value(g_server_config, "_AUDIT_BACKUP_FILE_COUNT");
    if (value == NULL || cm_str2uint32(value, &val_uint32) != OG_SUCCESS) {
        log_param->audit_backup_file_count = 2;
    } else if (val_uint32 > OG_MAX_LOG_FILE_COUNT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_AUDIT_BACKUP_FILE_COUNT", (int64)OG_MAX_LOG_FILE_COUNT);
        return;
    } else {
        log_param->audit_backup_file_count = val_uint32;
    }
}

static inline void ogsql_init_max_file_size(char *value, log_param_t *log_param)
{
    int64 val_int64;
    /* parse and check _LOG_MAX_FILE_SIZE */
    log_param->max_log_file_size = OGSQL_MAX_LOGFILE_SIZE;
    value = cm_get_config_value(g_server_config, "_LOG_MAX_FILE_SIZE");
    if (value != NULL && cm_str2size(value, &val_int64) == OG_SUCCESS && val_int64 >= 0) {
        log_param->max_log_file_size = (uint64)val_int64;
    }

    /* parse and check _AUDIT_MAX_FILE_SIZE */
    log_param->max_audit_file_size = OGSQL_MAX_LOGFILE_SIZE;
    value = cm_get_config_value(g_server_config, "_AUDIT_MAX_FILE_SIZE");
    if (value != NULL && cm_str2size(value, &val_int64) == OG_SUCCESS && val_int64 >= 0) {
        log_param->max_audit_file_size = (uint64)val_int64;
    }
}

static inline void ogsql_init_log_permission(char *value)
{
    uint16 val_uint16;
    /* parse and check _LOG_FILE_PERMISSIONS */
    value = cm_get_config_value(g_server_config, "_LOG_FILE_PERMISSIONS");
    if (value == NULL || cm_str2uint16(value, &val_uint16) != OG_SUCCESS) {
        val_uint16 = OG_DEF_LOG_FILE_PERMISSIONS;
    }
    cm_log_set_file_permissions(val_uint16);

    /* parse and check _LOG_PATH_PERMISSIONS */
    value = cm_get_config_value(g_server_config, "_LOG_PATH_PERMISSIONS");
    if (value == NULL || cm_str2uint16(value, &val_uint16) != OG_SUCCESS) {
        val_uint16 = OG_DEF_LOG_PATH_PERMISSIONS;
    }
    cm_log_set_path_permissions(val_uint16);
}

static void ogsql_init_loggers(void)
{
    uint32 val_len;
    char *value = NULL;
    char file_name[OG_FILE_NAME_BUFFER_SIZE];
    log_param_t *log_param = cm_log_param_instance();

    /* not record oper log if OGDB_HOME not exist */
    OG_RETVOID_IFERR(ogsql_get_home());

    if (ogsql_load_local_server_config() != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "load local server config failed during init loggers");
        return;
    }

    /* parse and check LOG_HOME */
    value = cm_get_config_value(g_server_config, "LOG_HOME");
    val_len = (value == NULL) ? 0 : (uint32)strlen(value);
    if (val_len >= OG_MAX_LOG_HOME_LEN) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LOG_HOME", (int64)OG_MAX_LOG_HOME_LEN - 1);
        return;
    } else if (val_len > 0) {
        MEMS_RETVOID_IFERR(strncpy_s(log_param->log_home, OG_MAX_PATH_BUFFER_SIZE, value, val_len));
    } else {
        PRTS_RETVOID_IFERR(snprintf_s(log_param->log_home, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_LEN,
            "%s/log", OG_HOME));
    }

    if (!cm_dir_exist(log_param->log_home) || 0 != access(log_param->log_home, W_OK | R_OK)) {
        OG_THROW_ERROR(ERR_INVALID_DIR, log_param->log_home);
        return;
    }

    ogsql_init_backup_file_count(value, log_param);
    ogsql_init_max_file_size(value, log_param);
    ogsql_init_log_permission(value);

    /* set log_level, set logname. */
    log_param->log_level = OGSQL_LOG_LEVEL;
    PRTS_RETVOID_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/oper/ogsql.olog",
        log_param->log_home));

    cm_log_init(LOG_OPER, (const char *)file_name);
}

static int ogsql_find_arg(int argc, char *argv[], const char *find_arg)
{
    for (int i = 1; i < argc; i++) {
        if (cm_str_equal_ins(argv[i], find_arg)) {
            return i;
        }
    }
    return 0;
}

status_t ogsql_alloc_conn(ogconn_conn_t *pconn)
{
    int16 ogsql_kind = CLIENT_KIND_OGSQL;
    OG_RETURN_IFERR(ogconn_alloc_conn(pconn));
    OG_RETURN_IFERR(ogconn_set_conn_attr((*pconn), OGCONN_ATTR_APP_KIND, &ogsql_kind, sizeof(int16)));
    return OG_SUCCESS;
}

void ogsql_init(int32 argc, char *argv[])
{
    int pos;
    errno_t errcode;
    bool32 interactive_clt = OG_TRUE;
    char home[OG_MAX_PATH_BUFFER_SIZE] = { 0x00 };

    // init global conn info
    errcode = memset_s(&g_conn_info, sizeof(ogsql_conn_info_t), 0, sizeof(ogsql_conn_info_t));
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        exit(EXIT_FAILURE);
    }

    pos = ogsql_find_arg(argc, argv, "-D");
    if (pos) {
        if (pos + 1 >= argc) {
            OGSQL_PRINTF(ZSERR_OGSQL, "The specified directory is missing.");
            exit(EXIT_FAILURE);
        }

        if (realpath_file(argv[pos + 1], (char *)home, OG_MAX_PATH_LEN) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            exit(EXIT_FAILURE);
        }
        if (cm_check_exist_special_char(home, (uint32)strlen(home))) {
            OG_THROW_ERROR(ERR_INVALID_DIR, argv[pos + 1]);
            exit(EXIT_FAILURE);
        }
        errcode = strncpy_s(OG_HOME, OG_MAX_PATH_BUFFER_SIZE, argv[pos + 1], OG_MAX_PATH_LEN);
        if (errcode != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            exit(EXIT_FAILURE);
        }
    }

    // start timer thread
    if (cm_start_timer(g_timer()) != OG_SUCCESS) {
        OGSQL_PRINTF(ZSERR_OGSQL, "aborted due to starting timer thread");
        exit(EXIT_FAILURE);
    }

    // init local config
    ogsql_init_local_config();
    // load ogsql config
    ogsql_load_ogsql_config();
    // load ogsql config
    ogsql_init_ogsql_config();
    // init ssl config
    ogsql_init_ssl_config();
    // init loggers
    ogsql_init_loggers();

    // alloc global conn
    if (ogsql_alloc_conn(&CONN) != OG_SUCCESS) {
        ogsql_print_error(NULL);
        exit(EXIT_FAILURE);
    }
    (void)ogconn_set_conn_attr(CONN, OGCONN_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
    (void)ogconn_set_conn_attr(CONN, OGCONN_ATTR_CONNECT_TIMEOUT, (void *)&g_local_config.connect_timeout,
        sizeof(int32));
    (void)ogconn_set_conn_attr(CONN, OGCONN_ATTR_SOCKET_TIMEOUT, (void *)&g_local_config.socket_timeout, sizeof(int32));

    g_sql_text.str = g_sql_buf;
    g_sql_text.len = 0;

    OGSQL_RESET_CMD_TYPE(&g_cmd_type);
    ogsql_reset_cmd_buf(g_cmd_buf, sizeof(g_cmd_buf));
}

void ogsql_silent(text_t *line)
{
    g_local_config.silent_on = OG_TRUE;

    if (line->len != 0) {
        cm_trim_text(line);
        char buf[MAX_ENTITY_LEN];
        (void)cm_text2str(line, buf, MAX_ENTITY_LEN);
        if (cm_open_file((const char *)buf, O_CREAT | O_TRUNC | O_RDWR, &g_spool_file) == OG_SUCCESS) {
            g_local_config.spool_on = OG_TRUE;
        }
    }
}

static void ogsql_search_comment_begin(const char *str, int32 p_pos, int32 *ret)
{
    bool32 is_comment_begin = OG_FALSE;
    int32 pos = p_pos;
    /* search comment begin */
    while (pos > 0) {
        is_comment_begin = (str[pos] == '*' && str[pos - 1] == '/');
        if (is_comment_begin) {
            *ret = pos - 2;
            return;
        }
        pos--;
    }
    *ret = -1;
}

#define QUATO_FlAG  0x1
#define DQUATO_FLAG 0x2

static void ogsql_skip_comment_line(text_t *line, int32 *pos, int32 end)
{
    int32 check_p = (int32)(line->len - 1);
    while (check_p > end) {
        if (line->str[check_p] <= ' ') {
            check_p--;
            continue;
        }
        break;
    }

    bool32 is_comment_flag;
    int32 ahead_p;
    int32 tmp_p;
    for (ahead_p = check_p; ahead_p > 0; ahead_p--) {
        if (line->str[ahead_p] == ';' && g_in_comment_count == 0) {
            *pos = ahead_p;
            return;
        }

        is_comment_flag = (line->str[ahead_p] == '-' && line->str[ahead_p - 1] == '-');
        if (is_comment_flag) {
            /* comment need skip */
            ahead_p = ahead_p - 2;
            check_p = ahead_p;
            // if end symbol encounted in comment line, it's fake
            continue;
        }

        is_comment_flag = (line->str[ahead_p] == '/' && line->str[ahead_p - 1] == '*');
        if (is_comment_flag) {
            ogsql_search_comment_begin(line->str, ahead_p - 2, &tmp_p);
            if (tmp_p == -1 || g_in_comment_count == 1) {
                // check_p dedicate a valid begin, if it equal ahead_p, this is only a comment line.
                *pos = (ahead_p == check_p) ? tmp_p : check_p;
                return;
            } else {
                ahead_p = tmp_p;
                check_p = ahead_p;
                continue;
            }
        }
        // only get a begin comment
        is_comment_flag = (line->str[ahead_p] == '*' && line->str[ahead_p - 1] == '/');
        if (is_comment_flag) {
            check_p = ahead_p - 2;
        }
    }

    while (check_p > 0) {
        if (line->str[check_p] <= ' ') {
            check_p--;
            continue;
        }
        break;
    }

    *pos = check_p;
}

static void ogsql_if_block(text_t *line, uint32 *flag)
{
    bool32 result = OG_FALSE;
    uint32 matched_id;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *line;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_init(&lex, &sql_text);

    OG_RETVOID_IFTRUE(lex_try_fetch_1of3(&lex, "DECLARE", "BEGIN", "CREATE", &matched_id) != OG_SUCCESS);

    // devil number '0' here means matched "DECLARE"
    if (matched_id == 0) {
        *flag = OGSQL_BLOCK_TAG;
        return;
    }

    // devil number '1' here means matched "BEGIN"
    if (matched_id == 1) {
        OG_RETVOID_IFTRUE(lex_try_fetch_char(&lex, ';', &result) != OG_SUCCESS || result == OG_TRUE);

        OG_RETVOID_IFTRUE(lex_try_fetch(&lex, "transaction", &result) != OG_SUCCESS || result == OG_TRUE);

        *flag = OGSQL_BLOCK_TAG;
        return;
    }

    // devil number '2' here means matched "CREATE"
    OG_RETVOID_IFTRUE(matched_id != 2);

    // devil number '6' here means behind 6 string match
    OG_RETVOID_IFTRUE(lex_try_fetch_1ofn(&lex, &matched_id, 6,
        "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE", "OR") != OG_SUCCESS);    // number of words behind

    // devil number '4' here means matched "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE"
    if (matched_id <= 4) {    // match the id of the word
        *flag = OGSQL_BLOCK_TAG;
        return;
    }

    // devil number '5' here means matched "OR"
    OG_RETVOID_IFTRUE(matched_id != 5);    // match the id of the word

    OG_RETVOID_IFTRUE(lex_try_fetch(&lex, "REPLACE", &result) != OG_SUCCESS || result == OG_FALSE);

    OG_RETVOID_IFTRUE(lex_try_fetch_1ofn(&lex, &matched_id, 5,
        "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE") != OG_SUCCESS);    // number of words behind
        
    // devil number '4' here means matched "PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "TYPE"
    if (matched_id <= 4) {    // match the id of the word
        *flag = OGSQL_BLOCK_TAG;
    }
}

static void ogsql_if_block_end(text_t *line, uint32 *flag)
{
    int32 count = 0;

    for (uint32 i = 0; i < line->len; i++) {
        if ((line->str[i] > ' ' && line->str[i] != '/') || count > 1) {
            return;
        }
        if (line->str[i] == '/') {
            count++;
        }
    }
    if (count == 1) {
        *flag = OGSQL_BLOCK_END_TAG;
    }
}

static void ogsql_if_comment_end(text_t *line, uint32 *flag)
{
    uint32 pos;

    for (pos = 0; pos < line->len - 1; pos++) {
        if (line->str[pos] == '*' && line->str[pos + 1] == '/' &&
            (pos == 0 || line->str[pos - 1] != '/')) {
            *flag = OGSQL_COMMENT_END_TAG;
            return;
        }
    }
}

uint32 ogsql_print_welcome(uint32 multi_line, uint32 line_no)
{
    uint32 nchars = 0;
    if (g_is_print == OG_TRUE &&
        g_local_config.script_output == OG_FALSE &&
        g_local_config.feedback.feedback_on == OG_FALSE) {
        return nchars;
    }

    if (!g_local_config.silent_on) {
        if (multi_line == OGSQL_SINGLE_TAG) {
            if (!g_local_config.silent_on) {
                nchars = printf("SQL> ");
                fflush(stdout);
            }
            ogsql_try_spool_put("SQL> ");
        } else {
            if (!g_local_config.silent_on) {
                nchars = printf("%3u ", line_no);
                fflush(stdout);
            }
            ogsql_try_spool_put("%3d ", line_no);
        }
    }
    return nchars;
}

static bool32 ogsql_if_illega_line(FILE *in, char *cmd_buf, uint32 max_len)
{
    char err_info[OG_MAX_CMD_LEN] = { 0 };
    int iret_snprintf = 0;
    int iret_fscanf = 0;

    /* If the single cmd is too long */
    if (cmd_buf[max_len - 1] != OGSQL_BUF_RESET_CHAR) {
        iret_fscanf = fscanf_s(in, "%*[^\n]%*c");
        if (iret_fscanf == -1) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_FALSE;
        }
        iret_snprintf = snprintf_s(err_info, OG_MAX_CMD_LEN, OG_MAX_CMD_LEN - 1,
                                   "Error: Input is too long (> %d characters) - line ignored.\n", MAX_CMD_LEN);
        if (iret_snprintf == -1) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_FALSE;
        } else {
            ogsql_printf("%s", err_info);
            ogsql_oper_log(err_info, (uint32)strlen(err_info) - 1);  // record oper log, '\n' no need
        }

        ogsql_reset_cmd_buf(cmd_buf, max_len);
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void ogsql_if_skip_line(text_t *line, int32 pos, bool32 *is_skip_line)
{
    ogsql_cmd_def_t cmdtype;
    text_t line_deal;

    int32 right_trim = line->len - 1;
    while (right_trim > pos) {
        if (line->str[pos] <= ' ') {
            right_trim--;
            continue;
        }
        break;
    }

    line_deal.str = line->str + pos;
    line_deal.len = right_trim - pos;

    // attention : now try twice, check line need to be skipped
    if (CM_TEXT_FIRST(&line_deal) == '-' && CM_TEXT_SECOND(&line_deal) == '-') {
        *is_skip_line = OG_TRUE;
        return;
    }

    if (CM_TEXT_FIRST(&line_deal) == '@') {
        *is_skip_line = OG_TRUE;
        return;
    }

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    if (CM_TEXT_FIRST(&line_deal) == '\\' && CM_TEXT_SECOND(&line_deal) == '!') {
        *is_skip_line = OG_TRUE;
        return;
    }
#endif

    if (!ogsql_find_cmd(&line_deal, &cmdtype)) {
        *is_skip_line = OG_TRUE;
        return;
    }

    if (cmdtype.mode != MODE_MULTI_LINE) {
        *is_skip_line = OG_TRUE;
    } else {
        *is_skip_line = OG_FALSE;
    }
}

static void ogsql_if_multi_line(text_t *line, uint32 *flag)
{
    bool32 is_pl_label = OG_FALSE;
    bool32 is_begin_comment;
    bool32 is_skip_line;
    int32 pos = 0;
    while (pos < (int32)line->len) {
        if (line->str[pos] <= ' ') {
            pos++;
            continue;
        }
        break;
    }

    if (pos == (int32)line->len) {
        *flag = OGSQL_EMPTY_TAG;
        return;
    }
    int32 len = (int32)line->len;
    if ((len - pos) > 4) {
        // attention 1: PL LABEL start with <<, check first
        is_pl_label = (line->str[pos] == '<') && (line->str[pos + 1] == '<');
    }
    if (is_pl_label) {
        *flag = OGSQL_BLOCK_TAG;
        return;
    }

    // attention 2: some single line command doesn't have semicolon, need skip.
    ogsql_if_skip_line(line, pos, &is_skip_line);
    if (is_skip_line) {
        return;
    }

    int32 end_chk;
    // attention 3: skip the comment line, then check line end
    is_begin_comment = pos + 1 < (int32)line->len && line->str[pos] == '/' && line->str[pos + 1] == '*';
    ogsql_skip_comment_line(line, &end_chk, pos);
    if (end_chk < 0 && !is_begin_comment) {
        return;
    }

    if (is_begin_comment) {
        *flag = OGSQL_COMMENT_TAG;
        return;
    }

    if (line->str[end_chk] == ';' && g_in_comment_count == 0) {
        return;
    }

    *flag = OGSQL_MULTI_TAG;
    return;
}

static void ogsql_if_multi_line_end(text_t *line, uint32 *flag)
{
    int32 pos;
    ogsql_skip_comment_line(line, &pos, 0);
    if (pos < 0) {
        return;
    }
 
    text_t temp_line = { line->str, line->len };
    cm_trim_text(&temp_line);

    if (line->str[pos] == ';' || (temp_line.len == 1 && CM_TEXT_FIRST(&temp_line) == '/')) {
        *flag = OGSQL_MULTI_END_TAG;
        return;
    }
}

void ogsql_free_config(void)
{
    uint32 i;
    config_item_t *item = NULL;
    
    if (g_server_config != NULL) {
        cm_spin_lock(&g_server_config_lock, NULL);
        cm_free_config_buf(g_server_config);
        free(g_server_config);
        g_server_config = NULL;
        cm_spin_unlock(&g_server_config_lock);
    }

    if (g_ogsql_config != NULL) {
        cm_free_config_buf(g_ogsql_config);
        free(g_ogsql_config);
        g_ogsql_config = NULL;
    }

    cm_spin_lock(&g_client_parameters_lock, NULL);
    for (i = 0; i < OGSQL_PARAMS_COUNT1; i++) {
        item = &g_client_parameters[i];
        item->is_default = OG_TRUE;
        item->value = NULL;
    }
    cm_spin_unlock(&g_client_parameters_lock);
}

static void ogsql_if_not_enclosed(text_t *line)
{
    uint32 i;
    char c;
    text_t sub_line;

    if (g_in_enclosed_char == -1) {
        return;
    }

    for (i = 0; i < line->len; i++) {
        c = line->str[i];
        if (g_in_enclosed_char == c) {
            if (c == '\'' && (i + 1 < line->len) && line->str[i + 1] == '\'') {
                // consider c&c+1 as '', then skip them
                i++;
                continue;
            }
            g_in_enclosed_char = -1;
            i++;
            break;
        }
    }

    if (i > 0) {
        sub_line.str = line->str;
        sub_line.len = i;

        if (g_in_enclosed_char > 0 && sub_line.str[i - 1] == '\n') {
            // not enclosed yet, remove last LF
            CM_REMOVE_LAST(&sub_line);
        }

        if (OG_SUCCESS != ogsql_concat_appendlf(&sub_line)) {
            return;
        }

        CM_REMOVE_FIRST_N(line, i);
    }
}

static uint32 ogsql_utf8_chr_widths(char *chr, uint32 c_bytes)
{
    wchar_t wchr;
    uint32 c_widths = 0;
    (void)mbtowc(&wchr, chr, c_bytes);
#ifndef WIN32
    c_widths = (uint32)wcwidth(wchr);
#endif
    return c_widths;
}

static void ogsql_push_history(uint32 cmd_bytes, uint32 cmd_width, int *hist_count, char *cmd_buf, uint32 max_len)
{
    text_t ignore_passwd_text;
    int32 mattch_type;
    bool32 mattched = OG_FALSE;
    
    if (cmd_bytes == 0) {
        return;
    }

    cm_str2text(cmd_buf, &ignore_passwd_text);
    cm_text_try_map_key2type(&ignore_passwd_text, &mattch_type, &mattched);

    if (mattched == OG_TRUE) {
        return;
    }
    
    if (*hist_count < OGSQL_MAX_HISTORY_SIZE - 1) {
        *hist_count += 1;
    }
    for (int i = *hist_count; i > 1; i--) {
        OGSQL_CHECK_MEMS_SECURE(memcpy_s(&g_hist_list[i], sizeof(ogsql_cmd_history_list_t),
                                        &g_hist_list[i - 1], sizeof(ogsql_cmd_history_list_t)));
    }
    OGSQL_CHECK_MEMS_SECURE(memcpy_s(g_hist_list[1].hist_buf, OGSQL_HISTORY_BUF_SIZE, cmd_buf, OGSQL_HISTORY_BUF_SIZE));
    g_hist_list[1].nbytes = cmd_bytes;
    g_hist_list[1].nwidths = cmd_width;
    return;
}

static void ogsql_cmd_clean_line(uint32 line_widths)
{
    uint32 line_wid = line_widths;
    while (line_wid--) {
        ogsql_write(3, "\b \b");
    }
}

/* Calculate the position and total number of spaces used to space at the end of a line */
static void ogsql_set_endspace(ogsql_cmd_history_list_t hist_list, uint32 ws_col, uint32 welcome_width,
                       uint32 *spacenum, bool8 *endspace)
{
    uint32 offset = 0;
    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 nwidths = 0;
    uint32 space_num = 0;

    OGSQL_CHECK_MEMS_SECURE(memset_s(endspace, OGSQL_HISTORY_BUF_SIZE, 0, OGSQL_HISTORY_BUF_SIZE));
    while (offset < hist_list.nbytes) {
        (void)cm_utf8_chr_bytes(hist_list.hist_buf[offset], &c_bytes);
        c_widths = ogsql_utf8_chr_widths(hist_list.hist_buf + offset, c_bytes);
        offset += c_bytes;

        if (c_widths == 2 && (nwidths + space_num + welcome_width + 1) % ws_col == 0) {
            space_num++;
            endspace[(nwidths + space_num + welcome_width + 1) / ws_col] = OG_TRUE;
        }
        nwidths += c_widths;
    }
    *spacenum = space_num;
}

static void ogsql_hist_turn_up(const int *hist_count, int *list_num, uint32 *nbytes, uint32 *nwidths, uint32 ws_col,
                       uint32 welcome_width, uint32 *spacenum, bool8 *endspace, char *cmd_buf, uint32 max_len)
{
    if (*list_num > *hist_count - 1) {
        return;
    }
    if (*list_num == 0) {
        OGSQL_CHECK_MEMS_SECURE(memcpy_s(g_hist_list[0].hist_buf, OGSQL_HISTORY_BUF_SIZE, cmd_buf, *nbytes));
        g_hist_list[0].nbytes = *nbytes;
        g_hist_list[0].nwidths = *nwidths;
    }
    ogsql_cmd_clean_line(*nwidths + *spacenum);
    (*list_num)++;

    *nbytes = g_hist_list[*list_num].nbytes;
    *nwidths = g_hist_list[*list_num].nwidths;

    OGSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf, max_len, g_hist_list[*list_num].hist_buf, *nbytes));
    ogsql_write(*nbytes, g_hist_list[*list_num].hist_buf);
    ogsql_write(2, " \b");
    ogsql_set_endspace(g_hist_list[*list_num], ws_col, welcome_width, spacenum, endspace);
}

static void ogsql_hist_turn_down(int *list_num, uint32 *nbytes, uint32 *nwidths, uint32 ws_col, uint32 welcome_width,
                         uint32 *spacenum, bool8 *endspace, char *cmd_buf, uint32 max_len)
{
    if (*list_num < 1) {
        return;
    }
    ogsql_cmd_clean_line(*nwidths + *spacenum);
    (*list_num)--;
        
    *nbytes = g_hist_list[*list_num].nbytes;
    *nwidths = g_hist_list[*list_num].nwidths;

    OGSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf, max_len, g_hist_list[*list_num].hist_buf, *nbytes));
    ogsql_write(*nbytes, g_hist_list[*list_num].hist_buf);
    ogsql_write(2, " \b");
    ogsql_set_endspace(g_hist_list[*list_num], ws_col, welcome_width, spacenum, endspace);
}

static void ogsql_fgets_with_history(int *hist_count, int *list_num, uint32 welcome_width, char *cmd_buf, uint32 max_len)
{
    int32 key_char = 0;
    int32 direction_key = 0;

    uint32 c_bytes = 0;
    uint32 c_widths = 0;
    uint32 nbytes = 0;
    uint32 nwidths = 0;
    uint32 spacenum = 0; /* Record the number of spaces filled at the end of the line. */
    bool8 endspace[OGSQL_HISTORY_BUF_SIZE]; /* Record the line number with space at the end of the line. */
    char chr[OGSQL_UTF8_CHR_SIZE];
    uint32 ws_col = 0;
#ifndef WIN32
    struct winsize size;
    (void)ioctl(0, TIOCGWINSZ, &size);
    ws_col = size.ws_col;
    struct termios oldt;
    struct termios newt;
    (void)tcgetattr(STDIN_FILENO, &oldt);
    OGSQL_CHECK_MEMS_SECURE(memcpy_s(&newt, sizeof(newt), &oldt, sizeof(oldt)));
    newt.c_lflag &= ~(ECHO | ICANON | ECHOE | ECHOK | ECHONL | ICRNL);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &newt); /* Set terminal input echo off */
#endif
    OGSQL_CHECK_MEMS_SECURE(memset_s(endspace, OGSQL_HISTORY_BUF_SIZE, 0, OGSQL_HISTORY_BUF_SIZE));
    while (key_char != CMD_KEY_ASCII_LF && key_char != CMD_KEY_ASCII_CR) {
        key_char = getchar();
        switch (key_char) {
            case CMD_KEY_ESCAPE:
                (void)getchar(); // '['
                direction_key = getchar();
                if (direction_key == CMD_KEY_UP) {
                    ogsql_hist_turn_up(hist_count, list_num, &nbytes, &nwidths, ws_col, welcome_width, &spacenum,
                                      endspace, cmd_buf, max_len);
                    continue;
                } else if (direction_key == CMD_KEY_DOWN) {
                    ogsql_hist_turn_down(list_num, &nbytes, &nwidths, ws_col, welcome_width, &spacenum, endspace,
                                        cmd_buf, max_len);
                    continue;
                } else if (direction_key == CMD_KEY_DEL) {
                    (void)getchar(); // '~'
                } else {
                    continue;
                }
            case CMD_KEY_ASCII_DEL:
            case CMD_KEY_ASCII_BS:
                if (nbytes == 0) {
                    continue;
                }
                (void)cm_utf8_reverse_str_bytes(cmd_buf + nbytes - 1, nbytes, &c_bytes);
                nbytes -= c_bytes;
                OGSQL_CHECK_MEMS_SECURE(memcpy_s(chr, OGSQL_UTF8_CHR_SIZE, cmd_buf + nbytes, c_bytes));
 
                c_widths = ogsql_utf8_chr_widths(chr, c_bytes);
                for (int i = c_widths; i > 0; i--) {
                    ogsql_write(3, "\b \b");
                }
                nwidths -= c_widths;
                /* When there is a filled in space at the end of the line, one more space should be deleted. */
                if ((nwidths + spacenum + welcome_width) % ws_col == 0 && c_widths == 2 &&
                    endspace[(nwidths + spacenum + welcome_width) / ws_col] == OG_TRUE) {
                    endspace[(nwidths + spacenum + welcome_width) / ws_col] = OG_FALSE;
                    spacenum--;
                    ogsql_write(3, "\b \b");
                }
                continue;

            case CMD_KEY_ASCII_CR:
            case CMD_KEY_ASCII_LF:
                *list_num = 0;
                ogsql_write(1, "\n");
                continue;

            default:
                (void)cm_utf8_chr_bytes((uint8)key_char, &c_bytes);
                if (nbytes + c_bytes > OGSQL_HISTORY_BUF_SIZE - 2) {
                    continue;
                }
                OGSQL_CHECK_MEMS_SECURE(memset_s(chr, OGSQL_UTF8_CHR_SIZE, key_char, 1));
                for (uint32 i = 1; i < c_bytes; i++) {
                    key_char = getchar();
                    OGSQL_CHECK_MEMS_SECURE(memset_s(chr + i, OGSQL_UTF8_CHR_SIZE - i, key_char, 1));
                }
                c_widths = ogsql_utf8_chr_widths(chr, c_bytes);
                /* If the char is invisible, skip */
                if (c_widths == -1) {
                    continue;
                }
                OGSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf + nbytes, MAX_CMD_LEN + 2 - nbytes, chr, c_bytes));
                nbytes += c_bytes;
                ogsql_write(c_bytes, chr);
                /* UNIX console standard output requires special handling when the cursor is at the end of the line.
                   When the end of the line is exactly full of characters, the cursor needs to jump to the next line.
                   When there is only one space at the end of the line and the next character is full width, a space
                   needs to be filled in. */
                if (((nwidths + spacenum + welcome_width + 1) % ws_col == 0 && c_widths == 1) ||
                    ((nwidths + spacenum + welcome_width + 2) % ws_col == 0 && c_widths == 2)) {
                    ogsql_write(2, " \b");
                } else if ((nwidths + spacenum + welcome_width + 1) % ws_col == 0 && c_widths == 2) {
                    spacenum++;
                    endspace[(nwidths + spacenum + welcome_width + 1) / ws_col] = OG_TRUE;
                }
                nwidths += c_widths;
                continue;
        }
    }
    ogsql_push_history(nbytes, nwidths, hist_count, cmd_buf, max_len);
    OGSQL_CHECK_MEMS_SECURE(memcpy_s(cmd_buf + nbytes, max_len - nbytes, "\n", 2));
#ifndef WIN32
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldt); /* Set terminal input echo on */
#endif
    return;
}

EXTER_ATTACK void ogsql_run(FILE *in, bool32 is_file, char *cmd_buf, uint32 max_len)
{
    text_t line;

    uint32 flag = OGSQL_SINGLE_TAG;
    uint32 line_no = 0;

    uint32 welcome_width = 0;
    int hist_count = 0;
    int list_num = 0;

    if (is_file == OG_FALSE) {
        for (int i = 0; i < OGSQL_MAX_HISTORY_SIZE; i++) {
            OGSQL_CHECK_MEMS_SECURE(memset_s(g_hist_list[i].hist_buf, OGSQL_HISTORY_BUF_SIZE, 0,
                OGSQL_HISTORY_BUF_SIZE));
        }
    }

    (void)setlocale(LC_CTYPE, "");
#ifndef WIN32
    // Set setvbuf to no buffer to prevent plaintext passwords in Linux.
    (void)setvbuf(in, NULL, _IONBF, 0);
#endif
    while (!feof(in)) {
        welcome_width = ogsql_print_welcome(flag & (OGSQL_BLOCK_TAG | OGSQL_MULTI_TAG | OGSQL_COMMENT_TAG), line_no);

        IS_WORKING = OG_FALSE;

#ifndef WIN32
        if (g_local_config.history_on == OG_TRUE && is_file == OG_FALSE) {
            ogsql_fgets_with_history(&hist_count, &list_num, welcome_width, cmd_buf, max_len);
        } else {
            if (fgets(cmd_buf, max_len, in) == NULL) {
                break;
            }
        }
#else
        if (fgets(cmd_buf, max_len, in) == NULL) {
            break;
        }
#endif
        IS_WORKING = OG_TRUE;
        g_local_config.is_cancel = OG_FALSE;

        /* If the single cmd is too long */
        if (ogsql_if_illega_line(in, cmd_buf, max_len)) {
            continue;
        }

        cm_str2text(cmd_buf, &line);

        /* if got empty line */
        if (line.len == 0) {
            continue;
        }

        if (flag == OGSQL_SINGLE_TAG) {
            // Attention: avoid trim input string, since the line-no dedicate in server will mismatch with client.
            ogsql_if_multi_line(&line, &flag);
            if (flag == OGSQL_EMPTY_TAG) {
                ogsql_print_blank_line();
                flag = OGSQL_SINGLE_TAG;
                continue;
            }

            // Attention: block input pri higher than multi-line, need check if block
            if (flag != OGSQL_BLOCK_TAG && flag != OGSQL_COMMENT_TAG) {
                ogsql_if_block(&line, &flag);
            }

            if (flag & (OGSQL_BLOCK_TAG | OGSQL_MULTI_TAG | OGSQL_COMMENT_TAG)) {
                line_no = 1;
            }
        }

        ogsql_try_spool_directly_put(cmd_buf);
        if (flag == OGSQL_SINGLE_TAG) {
            (void)ogsql_process_cmd(&line);
        } else if (flag == OGSQL_COMMENT_TAG) {
            ogsql_if_comment_end(&line, &flag);
            (void)ogsql_concat(&line);
            if (flag == OGSQL_COMMENT_END_TAG) {
                flag = OGSQL_SINGLE_TAG;
            } else {
                line_no++;
            }
        } else if (flag == OGSQL_BLOCK_TAG) {
            ogsql_if_block_end(&line, &flag);
            (void)ogsql_concat(&line);
            if (flag == OGSQL_BLOCK_END_TAG) {
                print_sql_command(g_sql_text.str, g_sql_text.len);
                ogsql_reset_in_enclosed_char();
                (void)ogsql_execute(NULL);
                OGSQL_RESET_CMD_TYPE(&g_cmd_type);
                CM_TEXT_CLEAR(&g_sql_text);
                flag = OGSQL_SINGLE_TAG;
            } else {
                line_no++;
            }
        } else {
            ogsql_if_not_enclosed(&line);
            ogsql_if_multi_line_end(&line, &flag);
            (void)ogsql_process_cmd(&line);

            if (flag == OGSQL_MULTI_END_TAG) {
                flag = OGSQL_SINGLE_TAG;
            } else {
                line_no++;
            }
        }

        ogsql_reset_cmd_buf(cmd_buf, max_len);
    }
}

status_t ogsql_conn_cancel(ogsql_conn_info_t *conn_info)
{
    ogsql_conn_info_t cancel_conn_info;

    cancel_conn_info = *conn_info;
    cancel_conn_info.stmt = NULL;
    cancel_conn_info.conn = NULL;
    if (ogsql_alloc_conn(&cancel_conn_info.conn) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cancel_conn_info.is_conn = OG_FALSE;
    if (ogsql_get_saved_pswd(cancel_conn_info.passwd, sizeof(cancel_conn_info.passwd)) != OG_SUCCESS) {
        ogconn_free_conn(cancel_conn_info.conn);
        return OG_ERROR;
    }
    cancel_conn_info.connect_by_install_user = conn_info->connect_by_install_user;
    cancel_conn_info.is_clsmgr = conn_info->is_clsmgr;
    (void)ogsql_switch_user(&cancel_conn_info);

    if (ogsql_conn_to_server(&cancel_conn_info, OG_FALSE, OG_TRUE) != OG_SUCCESS) {
        ogconn_free_conn(cancel_conn_info.conn);
        return OG_ERROR;
    }

    if (ogconn_cancel(cancel_conn_info.conn, ogconn_get_sid(conn_info->conn)) != OGCONN_SUCCESS) {
        ogconn_free_conn(cancel_conn_info.conn);
        return OG_ERROR;
    }

    ogconn_free_conn(cancel_conn_info.conn);
    return OGCONN_SUCCESS;
}

status_t ogsql_cancel(void)
{
    status_t ret = OG_SUCCESS;

    g_local_config.is_cancel = OG_TRUE;

    cm_spin_lock(&g_cancel_lock, NULL);
    ret = ogsql_conn_cancel(&g_conn_info);
    cm_spin_unlock(&g_cancel_lock);

    return ret;
}
