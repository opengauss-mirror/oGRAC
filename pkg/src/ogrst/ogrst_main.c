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
 * ogrst_main.c
 *
 *
 * IDENTIFICATION
 * src/ogrst/ogrst_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cm_kmc.h"
#include "srv_instance.h"
#include "ogsql.h"
#include "cm_lex.h"
#include "ogconn.h"
#include "ogsql.h"
#include "ogsql_export.h"
#include "ogsql_import.h"
#include <malloc.h>
#include "knl_user.h"
#include "dtc_database.h"
#ifndef WIN32
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#endif

#define MAX_HIDED_PWD_LEN 1u
#define MAX_SQL_LEN 1024
#define URL_BUF_SIZE 128
#define MAX_PORT_LEN 6
#define HELP_ARGS_LENTH 2
#define ARGS_NO_CONFIG 13
#define ARGS_HAS_CONFIG 17
#define REPAIR_ARGS_WITHOUT_KEYFILE_LENTH 11
#define REPAIR_ARGS_WITH_KEYFILE_LENTH 12
#define EXPORT_PATH_SET_BITMAP 1
#define BACKUP_PATH_SET_BITMAP 2
#define SCHEMA_SET_BITMAP 4
#define TABLESPACE_SET_BITMAP 8
#define DB_IPPORT_SET_BITMAP 16
#define PAGE_ID_SET_BITMAP 32
#define PORT_SET_BITMAP 64
#define MAX_READ_RETRY_TIMES 10
#define OGRST_PAGE_SIZE 8192
#define OGRST_KEY_NUM 4
#define OGRST_DIR_LEVEL 2u
#define OGRST_INTERACTION_TIMEOUT 10
#define CONFIG_ITEM_MAX_SIZE 512
#define OGRST_WAIT_DDL_ENABLE_TIME 10000  // 10s
#define IMPORT_CONFIG_NUM 6
#define IMPORT_MAX_PARALLEL_WORKERS 32
#define IMPORT_DEFAULT_PARALLEL_WORKERS 16
#define IMPORT_MAX_BATCH_COUNT 10000
#define DEFAULT_ENCRYPT_ITERATION_COUNT 2000

// snprintf_s/sprintf_s... check, call the hook function and return OG_ERROR if error occurs
#define PRTS_RETURN_IFERR2(func, hook)                 \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            hook;                                      \
            OG_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return OG_ERROR;                           \
        }                                              \
    } while (0)

typedef enum en_ogrst_imp_items {
    IMP_PARALLEL = 0,
    IMP_DDL_PARALLEL = 1,
    IMP_BATCH_COUNT = 2,
    IMP_NOLOGGING = 3,
    IMP_KMC_KEY_FILE_A = 4,
    IMP_KMC_KEY_FILE_B = 5,
} ogrst_import_config_type;

const char *g_import_config_items[IMPORT_CONFIG_NUM] = { "PARALLEL",  "DDL_PARALLEL",   "BATCH_COUNT",
                                                         "NOLOGGING", "KMC_KEY_FILE_A", "KMC_KEY_FILE_B" };

typedef struct st_ogrst_conn_params {
    SENSI_INFO char passwd[OG_PASSWD_MAX_LEN];  // sys user passwd
    char encrypt_passwd[OG_PASSWORD_BUFFER_SIZE];
    char export_path[OG_MAX_PATH_LEN];
    char backup_path[OG_MAX_PATH_LEN];
    char log_path[OG_MAX_PATH_LEN];
    char db_home[OG_MAX_PATH_LEN];
    char ifile_path[OG_MAX_PATH_LEN];
    char schema[OG_NAME_BUFFER_SIZE];
    SENSI_INFO char user_passwd[OG_PASSWD_MAX_LEN];
    char tablespace[OG_NAME_BUFFER_SIZE];
    char port[MAX_PORT_LEN];
    char url[URL_BUF_SIZE];      // ogrst client connect to server of ogrst
    char imp_url[URL_BUF_SIZE];  // ogrst client connect to server of database
    char max_column_count[OG_PARAM_BUFFER_SIZE];
    char undo_segments[OG_PARAM_BUFFER_SIZE];
    page_id_t page_id;
    uint64 lfn;
    db_status_t db_status;
    SENSI_INFO char backup_set_passwd[OG_PASSWD_MAX_LEN];
    bool32 is_set_passwd;
} ogrst_conn_params_t;

typedef struct st_ogrst_import_params {
    char nologgine;
    uint16 parallel;
    uint16 ddl_parallel;
    uint32 batch_count;
    char kmc_keyfile_a[OG_FILE_NAME_BUFFER_SIZE];
    char kmc_keyfile_b[OG_FILE_NAME_BUFFER_SIZE];
} ogrst_import_params_t;

typedef struct st_ogrst_ssl_params {
    bool32 have_ssl;
    char work_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];
    char keypwd_cipher[OG_MAX_SSL_CIPHER_LEN + 1];
    char ssl_cert[OG_FILE_NAME_BUFFER_SIZE];
    char ssl_key[OG_FILE_NAME_BUFFER_SIZE];
    char factor_key[OG_MAX_FACTOR_KEY_STR_LEN + 1];
} ogrst_ssl_params_t;

ogrst_conn_params_t g_conn_params;
static bool32 g_is_page_repair;
ogrst_import_params_t g_imp_params;
ogrst_ssl_params_t g_ssl_params;
static uint32 g_node_count = 2;
int32 g_gm_optopt;
int32 g_gm_optind = 1;
char *g_gm_optarg = NULL;
static status_t ogrst_is_enable_dbs(bool32 *is_enable_db);

static void ogrst_usage()
{
    (void)printf("Usage: ogrst [-h|-H|-v|-V]\n"
                 "   1. restore tablespace : ogrst -p [sys_pwd:]port -D export_data_path -B backup_file_path \
-U schema[/pwd] -T tablespace -S ip:port [-C PARALLEL=8, DDL_PARALLEL=8, NOLOGGING=1]\n"
                 "      support interactive password input: ogrst -p port -D export_data_path -B backup_file_path \
-U schema -T tablespace -S ip:port [-C PARALLEL=8, DDL_PARALLEL=8, NOLOGGING=1]\n"
                 "   2. repair corrupted page : ogrst -p [sys_pwd:]port -D temp_db_path -B backup_file_path \
-P page_id -S ip:port\n"
                 "      support interactive password input: ogrst -p port -D temp_db_path -B backup_file_path \
-P page_id -S ip:port\n"
                 "Option:\n"
                 "\t -h/-H                 show the help information.\n"
                 "\t -v/-V                 show the version information.\n"
                 "\t -p                    [sys password and ]temp db instance port.\n"
                 "\t -D                    export data and temp db instance home path.\n"
                 "\t -B                    backup file path.\n"
                 "\t -E                    backup set password, interactive password input.\n"
                 "\t -U                    schema[ and password] for export data.\n"
                 "\t -T                    tablespace of schema.\n"
                 "\t -S                    db instance ip and port for import data.\n"
                 "\t -P                    corrupted page id.\n"
                 "\t -C                    import data parameters(PARALLEL/DDL_PARALLEL/BATCH_COUNT/NOLOGGING).\n"
                 "\t                       PARALLEL: DML parallel range 1~32, default values is 16\n"
                 "\t                       DDL_PARALLEL: DDL parallel range 1~32, default value is 16\n"
                 "\t                       BATCH_COUNT: batch rows range 1~10000, default value is 10000\n"
                 "\t                       KMC_KEY_FILE_A: first kmc keyfile\n"
                 "\t                       KMC_KEY_FILE_B: second kmc keyfile\n"
                 "\t                       NOLOGGING: insert data without redo log, 0 is disable 1 is enable, \
default value is 0\n");
}

static void ogrst_log_print(const char *format, ...)
{
    char buf[OG_MAX_LOG_CONTENT_LENGTH] = { 0 };
    int32 tz_hour;
    int32 tz_min;
    char date[OG_MAX_TIME_STRLEN] = { 0 };
    errno_t errcode;
    if (g_timer()->now != 0) {
        (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, OG_MAX_TIME_STRLEN);
        tz_hour = TIMEZONE_GET_HOUR(g_timer()->tz);
        tz_min = TIMEZONE_GET_MINUTE(g_timer()->tz);
        if (tz_hour >= 0) {
            errcode = snprintf_s(buf, OG_MAX_LOG_CONTENT_LENGTH, OG_MAX_LOG_HEAD_LENGTH - 1,
                                 "UTC+%02d:%02d %s:", tz_hour, tz_min, date);
        } else {
            errcode = snprintf_s(buf, OG_MAX_LOG_CONTENT_LENGTH, OG_MAX_LOG_HEAD_LENGTH - 1,
                                 "UTC%02d:%02d %s:", tz_hour, tz_min, date);
        }
        if (errcode == -1) {
            return;
        }
    }
    va_list args;
    va_start(args, format);
    errcode = vsnprintf_s(buf + strlen(buf), OG_MAX_LOG_CONTENT_LENGTH - strlen(buf),
                          OG_MAX_LOG_CONTENT_LENGTH - strlen(buf) - 1, format, args);
    va_end(args);
    if (errcode == -1) {
        return;
    }
    (void)printf("%s", buf);
}

static status_t ogrst_erase_pwd(char *arg, text_t *pwd)
{
    text_t conn_text;
    text_t remain;
    size_t offset;
    errno_t errcode;

    cm_str2text(arg, &conn_text);
    if (pwd->len <= MAX_HIDED_PWD_LEN) {
        OG_RETURN_IFERR(cm_text_set(pwd, pwd->len, '*'));
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(cm_text_set(pwd, MAX_HIDED_PWD_LEN, '*'));

    remain.str = pwd->str + pwd->len;
    remain.len = conn_text.len - (uint32)(remain.str - conn_text.str);
    offset = conn_text.len - (uint32)(pwd->str + MAX_HIDED_PWD_LEN - conn_text.str);
    MEMS_RETURN_IFERR(memmove_s(pwd->str + MAX_HIDED_PWD_LEN, offset, remain.str, remain.len));
    remain.len = pwd->len - MAX_HIDED_PWD_LEN;
    remain.str = conn_text.str + conn_text.len - remain.len;
    offset = conn_text.len - (uint32)(remain.str - conn_text.str);
    if (remain.len != 0) {
        errcode = memset_s(remain.str, offset, 0, remain.len);
        if (errcode != EOK) {
            ogrst_log_print("Secure C lib has thrown an error %d\n", errcode);
            return OG_ERROR;
        }
    }
    pwd->len = MAX_HIDED_PWD_LEN;
    conn_text.len -= remain.len;
    return OG_SUCCESS;
}

/* validate path string */
static status_t ogrst_check_path(const char *cmd_str, const char *input_str, uint32 str_len, uint32 max_len)
{
    const char *danger_char_list[] = { "|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}",
                                       "(", ")", "[", "]", "~", "*", "?", "!",  "%", "\n", NULL };

    if (str_len == 0 || str_len >= (max_len - 1)) {
        (void)printf("invalid argument: %s %s\n", cmd_str, input_str);
        return OG_ERROR;
    }

    for (uint32 i = 0; danger_char_list[i] != NULL; i++) {
        if (strstr(input_str, danger_char_list[i]) != NULL) {
            (void)printf("failed to check string : invalid token \"%s\" for %s.\n", danger_char_list[i], cmd_str);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

/* validate tablespace name string, using sql interface */
static status_t ogrst_check_name(const char *cmd_str, const char *input_str, uint32 str_len, uint32 max_len)
{
    char c;

    if (str_len == 0 || str_len >= (max_len - 1)) {
        (void)printf("invalid argument: %s %s\n", cmd_str, input_str);
        return OG_ERROR;
    }

    for (uint32 pos = 0; pos < str_len; pos++) {
        c = input_str[pos];
        if (c == LEX_END) {
            (void)printf("invalid string length %u, expected length %u for %s.\n", pos, str_len, cmd_str);
            return OG_ERROR;
        }
        if (!is_nameble(c)) {
            (void)printf("failed to check string : invalid token %c for %s.\n", c, cmd_str);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogrst_set_imp_config_internal(const char *config_value, uint32 *config)
{
    if (cm_str2uint32(config_value, config) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (*config < 1 || *config > IMPORT_MAX_PARALLEL_WORKERS) {
        return OG_ERROR;
    }
    g_imp_params.parallel = *config;
    return OG_SUCCESS;
}

static status_t ogrst_set_imp_config(text_t *name, text_t *value)
{
    uint32 config;
    char config_name[CONFIG_ITEM_MAX_SIZE] = { 0 };
    char config_value[CONFIG_ITEM_MAX_SIZE] = { 0 };

    MEMS_RETURN_IFERR(strncpy_s(config_name, CONFIG_ITEM_MAX_SIZE, name->str, name->len));
    MEMS_RETURN_IFERR(strncpy_s(config_value, CONFIG_ITEM_MAX_SIZE, value->str, value->len));
    if (strcmp(config_name, g_import_config_items[IMP_PARALLEL]) == 0) {
        if (ogrst_set_imp_config_internal(config_value, &config) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (strcmp(config_name, g_import_config_items[IMP_DDL_PARALLEL]) == 0) {
        if (ogrst_set_imp_config_internal(config_value, &config) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (strcmp(config_name, g_import_config_items[IMP_BATCH_COUNT]) == 0) {
        if (cm_str2uint32(config_value, &config) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (config < 1 || config > IMPORT_MAX_BATCH_COUNT) {
            return OG_ERROR;
        }
        g_imp_params.batch_count = config;
    } else if (strcmp(config_name, g_import_config_items[IMP_NOLOGGING]) == 0) {
        if (cm_str2uint32(config_value, &config) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (config != 0 && config != 1) {
            return OG_ERROR;
        }
        g_imp_params.nologgine = (config == 0 ? 'N' : 'Y');
    } else if (strcmp(config_name, g_import_config_items[IMP_KMC_KEY_FILE_A]) == 0) {
        MEMS_RETURN_IFERR(strncpy_s(g_imp_params.kmc_keyfile_a, OG_FILE_NAME_BUFFER_SIZE, value->str, value->len));
    } else if (strcmp(config_name, g_import_config_items[IMP_KMC_KEY_FILE_B]) == 0) {
        MEMS_RETURN_IFERR(strncpy_s(g_imp_params.kmc_keyfile_b, OG_FILE_NAME_BUFFER_SIZE, value->str, value->len));
    } else {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogrst_parse_imp_params(char *params)
{
    text_t text;
    text_t line;
    text_t name;
    text_t value;
    CM_POINTER(params);
    cm_str2text(params, &text);
    if (text.len == 0 || text.len >= CONFIG_ITEM_MAX_SIZE) {
        return OG_ERROR;
    }

    while (cm_fetch_text(&text, ',', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }
        cm_trim_text(&line);
        if (line.len == 0) {
            continue;
        }
        cm_split_text(&line, '=', '\0', &name, &value);
        cm_text_upper(&name);
        cm_trim_text(&name);
        cm_trim_text(&value);
        if (name.len == 0 || value.len == 0) {
            (void)printf("import params invalid \"%s\"\n", params);
            return OG_ERROR;
        }
        if (ogrst_set_imp_config(&name, &value) != OG_SUCCESS) {
            (void)printf("import params invalid \"%s\"\n", params);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t ogrst_parse_port_passwd(char *input, uint8 *ret)
{
    text_t text;
    text_t passwd;
    text_t port;
    uint16 port_value;

    cm_str2text(input, &text);
    cm_split_text(&text, ':', '\0', &passwd, &port);
    if (passwd.len >= OG_PASSWD_MAX_LEN - 1) {
        (void)printf("invalid argument password\n");
        return OG_ERROR;
    }
    if (passwd.len != 0 && port.len == 0) {
        port.str = passwd.str;
        port.len = passwd.len;
        passwd.len = 0;
    }

    if (ogrst_check_path("port", port.str, port.len, MAX_PORT_LEN + 1) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_str2uint16(port.str, &port_value) != OG_SUCCESS || port_value < OG_MIN_PORT) {
        (void)printf("invalid argument port: %s\n", port.str);
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(g_conn_params.url, URL_BUF_SIZE, URL_BUF_SIZE - 1, "127.0.0.1:%s", port.str));
    MEMS_RETURN_IFERR(strncpy_s(g_conn_params.port, MAX_PORT_LEN, port.str, port.len));
    if (passwd.len == 0) {
        (void)printf("Please enter sys password: \n");
        if (ogsql_recv_passwd_from_terminal(g_conn_params.passwd, OG_PASSWD_MAX_LEN) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(strncpy_s(g_conn_params.passwd, OG_PASSWD_MAX_LEN, passwd.str, passwd.len));
        if (ogrst_erase_pwd(input, &passwd) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    if (user_encrypt_password("SCRAM_SHA256", DEFAULT_ENCRYPT_ITERATION_COUNT, g_conn_params.passwd,
                              (uint32)strlen(g_conn_params.passwd), g_conn_params.encrypt_passwd,
                              OG_PASSWORD_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*ret) += PORT_SET_BITMAP;
    return OG_SUCCESS;
}

static status_t ogrst_parse_backup_passwd()
{
    (void)printf("Please enter backupset password: \n");
    if (ogsql_recv_passwd_from_terminal(g_conn_params.backup_set_passwd, OG_PASSWD_MAX_LEN) != OG_SUCCESS) {
        return OG_ERROR;
    }
    g_conn_params.is_set_passwd = OG_TRUE;

    return OG_SUCCESS;
}

static status_t ogrst_parse_schema_passwd(char *input, uint8 *ret)
{
    text_t text;
    text_t user;
    text_t passwd;

    cm_str2text(input, &text);
    cm_split_text(&text, '/', '\0', &user, &passwd);
    if (user.len == 0 || user.len >= OG_NAME_BUFFER_SIZE - 1) {
        (void)printf("invalid argument: -U\n");
        return OG_ERROR;
    }
    if (passwd.len >= OG_PASSWD_MAX_LEN - 1) {
        (void)printf("invalid argument: -U\n");
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(strncpy_s(g_conn_params.schema, OG_NAME_BUFFER_SIZE, user.str, user.len));
    if (passwd.len == 0) {
        (void)printf("Please enter %s password: \n", g_conn_params.schema);
        if (ogsql_recv_passwd_from_terminal(g_conn_params.user_passwd, OG_PASSWD_MAX_LEN) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(strncpy_s(g_conn_params.user_passwd, OG_PASSWD_MAX_LEN, passwd.str, passwd.len));
        if (ogrst_erase_pwd(input, &passwd) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    (*ret) += SCHEMA_SET_BITMAP;
    return OG_SUCCESS;
}

static int32 ogrst_getopt(int nargc, char *nargv[], const char *ostr)
{
    static char *place_str = "";
    char place_c;
#ifdef WIN32
    const char *oc = NULL;
#else
    char *oc = NULL;
#endif

    if (!*place_str) {
        if (g_gm_optind >= nargc || *(nargv[g_gm_optind]) != '-') {
            place_str = "";
            return -1;
        }

        place_str = nargv[g_gm_optind];
        place_c = place_str[1];
        ++place_str;

        if (place_c && *place_str == '-' && place_str[1] == '\0') {
            ++g_gm_optind;
            place_str = "";
            return -1;
        }
    }

    g_gm_optopt = (int32)*place_str;
    place_str++;

    if (g_gm_optopt != (int32)':') {
        oc = strchr(ostr, g_gm_optopt);
    }

    if (g_gm_optopt == (int32)':' || oc == NULL) {
        if (g_gm_optopt == (int32)'-') {
            place_str = "";
            return -1;
        }

        if (!*place_str) {
            ++g_gm_optind;
        }

        if (*ostr != ':') {
            (void)printf("invalid argument -- %d\n", g_gm_optopt);
        }
        return (int32)'?';
    }

    ++oc;

    if (*oc != ':') {
        g_gm_optarg = NULL;
        if (!*place_str) {
            ++g_gm_optind;
        }
    } else {
        if (*place_str) {
            g_gm_optarg = place_str;
        } else if (nargc <= ++g_gm_optind) {
            place_str = "";
            if (*ostr == ':') {
                return (int32)':';
            }

            (void)printf("option requires an argument -- %c\n", g_gm_optopt);
            return (int32)'?';
        } else {
            g_gm_optarg = nargv[g_gm_optind];
        }

        place_str = "";
        ++g_gm_optind;
    }

    return g_gm_optopt;
}

static status_t ogrst_parse_data_path(const char *input, uint8 *ret)
{
    size_t len;

    len = strlen(input);
    if (ogrst_check_path("-D", input, (uint32)len, OG_MAX_PATH_LEN - sizeof("/ogrst_ifile.ini")) != OG_SUCCESS) {
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR(
        snprintf_s(g_conn_params.export_path, OG_MAX_PATH_LEN, OG_MAX_PATH_LEN - 1, "%s/export_data", input));
    PRTS_RETURN_IFERR(snprintf_s(g_conn_params.db_home, OG_MAX_PATH_LEN, OG_MAX_PATH_LEN - 1, "%s/tmp_data", input));
    PRTS_RETURN_IFERR(snprintf_s(g_conn_params.log_path, OG_MAX_PATH_LEN, OG_MAX_PATH_LEN - 1, "%s/log", input));
    PRTS_RETURN_IFERR(
        snprintf_s(g_conn_params.ifile_path, OG_MAX_PATH_LEN, OG_MAX_PATH_LEN - 1, "%s/ogrst_ifile.ini", input));
    g_database_home = g_conn_params.db_home;

    (*ret) += EXPORT_PATH_SET_BITMAP;
    return OG_SUCCESS;
}

static status_t ogrst_parse_backup_path(const char *input, uint8 *ret)
{
    size_t len;

    len = strlen(input);
    if (ogrst_check_path("-B", input, (uint32)len, OG_MAX_PATH_LEN) != OG_SUCCESS) {
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(g_conn_params.backup_path, OG_MAX_PATH_LEN, OG_MAX_PATH_LEN - 1, "%s", input));

    (*ret) += BACKUP_PATH_SET_BITMAP;
    return OG_SUCCESS;
}

static status_t ogrst_parse_space_name(const char *input, uint8 *ret)
{
    size_t len;

    len = strlen(input);
    if (ogrst_check_name("-T", input, (uint32)len, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(g_conn_params.tablespace, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "%s", input));

    (*ret) += TABLESPACE_SET_BITMAP;
    return OG_SUCCESS;
}

static status_t ogrst_parse_address(const char *input, uint8 *ret)
{
    // parse ip and port of database instance, format: "ip:port"
    size_t len;

    len = strlen(input);
    if (ogrst_check_path("-S", input, (uint32)len, URL_BUF_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(g_conn_params.imp_url, URL_BUF_SIZE, URL_BUF_SIZE - 1, "%s", input));

    (*ret) += DB_IPPORT_SET_BITMAP;
    return OG_SUCCESS;
}

static status_t ogrst_parse_pageid(char *input, uint8 *ret)
{
    size_t len;

    len = strlen(input);
    if (ogrst_check_path("-P", input, (uint32)len, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    text_t pagid_text;
    text_t left;
    text_t right;
    pagid_text.str = (char *)input;
    pagid_text.len = (uint32)len;
    cm_split_text(&pagid_text, '_', '\0', &left, &right);

    if (cm_text2uint16(&left, &g_conn_params.page_id.file) != OG_SUCCESS) {
        (void)printf("invalid argument: P %s, convert uint16 failed\n", g_gm_optarg);
        return OG_ERROR;
    }
    if (cm_text2uint32(&right, &g_conn_params.page_id.page) != OG_SUCCESS) {
        (void)printf("invalid argument: P %s, convert uint32 failed\n", g_gm_optarg);
        return OG_ERROR;
    }

    (*ret) += PAGE_ID_SET_BITMAP;
    return OG_SUCCESS;
}

static status_t ogrst_do_parse(int32 c, uint8 *ret)
{
    status_t status = OG_ERROR;
    switch (c) {
        case 'E':
            status = ogrst_parse_backup_passwd();
            break;
        case 'p':
            status = ogrst_parse_port_passwd(g_gm_optarg, ret);
            break;
        case 'D':
            status = ogrst_parse_data_path(g_gm_optarg, ret);
            break;
        case 'B':
            status = ogrst_parse_backup_path(g_gm_optarg, ret);
            break;
        case 'U':
            status = ogrst_parse_schema_passwd(g_gm_optarg, ret);
            break;
        case 'T':
            status = ogrst_parse_space_name(g_gm_optarg, ret);
            break;
        case 'S':
            status = ogrst_parse_address(g_gm_optarg, ret);
            break;
        case 'P':
            status = ogrst_parse_pageid(g_gm_optarg, ret);
            break;
        case 'C':
            status = ogrst_parse_imp_params(g_gm_optarg);
            break;
        default:
            ogrst_usage();
            status = OG_ERROR;
    }

    return status;
}

static status_t ogrst_parse_args(int argc, char *argv[], bool32 is_repair)
{
    uint8 ret = 0;
    const uint32 check_restore = EXPORT_PATH_SET_BITMAP + BACKUP_PATH_SET_BITMAP + SCHEMA_SET_BITMAP +
                                 TABLESPACE_SET_BITMAP + DB_IPPORT_SET_BITMAP + PORT_SET_BITMAP;
    const uint32 check_repair = EXPORT_PATH_SET_BITMAP + BACKUP_PATH_SET_BITMAP + PAGE_ID_SET_BITMAP +
                                DB_IPPORT_SET_BITMAP + PORT_SET_BITMAP;
    g_conn_params.is_set_passwd = OG_FALSE;
    int32 c;

    do {
        c = ogrst_getopt(argc, argv, "Ep:D:B:U:T:S:P:C:");
        if (c == -1) {
            break;
        }
        if (ogrst_do_parse(c, &ret) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } while (c != -1);

    if (!is_repair && ret == check_restore) {
        return OG_SUCCESS;
    }
    if (is_repair && ret == check_repair) {
        return OG_SUCCESS;
    }
    (void)printf("invalid argument: missing paramters\n");
    return OG_ERROR;
}

static status_t ogrst_check_config(char *buf, uint32 buf_len, bool32 *is_found, const char *item)
{
    text_t text;
    text_t line;
    text_t comment;
    text_t item_name;
    text_t value;

    text.len = buf_len;
    text.str = buf;

    comment.str = text.str;
    comment.len = 0;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        cm_trim_text(&line);
        if (line.len >= OG_MAX_CONFIG_LINE_SIZE) {
            return OG_ERROR;
        }

        if (line.len == 0 || *line.str == '#') {
            continue;
        }

        comment.len = (uint32)(line.str - comment.str);

        cm_split_text(&line, '=', '\0', &item_name, &value);
        cm_text_upper(&item_name);
        cm_trim_text(&item_name);
        cm_trim_text(&value);
        cm_trim_text(&comment);

        if (item_name.len == (uint32)strlen(item) && strncmp(item_name.str, item, strlen(item)) == 0) {
            *is_found = OG_TRUE;
            return OG_SUCCESS;
        }

        comment.str = text.str;
        comment.len = 0;
    }

    return OG_SUCCESS;
}

static status_t ogrst_have_ssl_quite(const char *file_name, bool32 *is_found)
{
    int32 file_fd;
    char *buf = NULL;
    status_t ret = OG_ERROR;
    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &file_fd) != OG_SUCCESS) {
        return OG_ERROR;
    }

    int64 size = cm_file_size(file_fd);
    if (size == -1 || size > (int64)(OG_MAX_CONFIG_FILE_SIZE)) {
        cm_close_file(file_fd);
        return OG_ERROR;
    }

    if (cm_seek_file(file_fd, 0, SEEK_SET) != 0) {
        cm_close_file(file_fd);
        return OG_ERROR;
    }

    buf = (char *)malloc((size_t)size);
    if (buf == NULL) {
        cm_close_file(file_fd);
        return OG_ERROR;
    }

    if (cm_read_file(file_fd, buf, (int32)size, NULL) == OG_SUCCESS) {
        ret = ogrst_check_config(buf, (uint32)size, is_found, "OGSQL_SSL_QUIET");
    }
    cm_close_file(file_fd);
    free(buf);
    return ret;
}

static status_t ogrst_make_ogsql_file(char *file_name, uint32 name_size, const char *app_path)
{
    char param[OG_PARAM_BUFFER_SIZE] = { 0 };
    int32 file = OG_INVALID_HANDLE;
    bool32 is_found = OG_FALSE;

    if (!cm_dir_exist(file_name)) {
        if (cm_create_dir(file_name) != OG_SUCCESS) {
            ogrst_log_print("create dir %s fail, errno=%d\n", file_name, errno);
            return OG_ERROR;
        }
    }
    PRTS_RETURN_IFERR(snprintf_s(file_name, name_size, name_size - 1, "%s/cfg/ogsql.ini", app_path));
    PRTS_RETURN_IFERR(snprintf_s(param, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "OGSQL_SSL_QUIET=TRUE"));
    if (cm_file_exist(file_name)) {
        if (ogrst_have_ssl_quite(file_name, &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (is_found) {
            return OG_SUCCESS;
        }
        if (cm_open_file(file_name, O_RDWR | O_BINARY | O_SYNC | O_APPEND, &file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        if (cm_create_file(file_name, O_RDWR | O_BINARY | O_SYNC | O_EXCL, &file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    if (cm_write_file(file, param, (int32)strlen(param)) != OG_SUCCESS) {
        cm_close_file(file);
        return OG_ERROR;
    }
    cm_close_file(file);

    return OG_SUCCESS;
}

static status_t ogrst_write_ogsql_file(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    char app_path[OG_MAX_PATH_BUFFER_SIZE];
    text_t text;
    uint32 i;
    uint32 count = 0;

    cm_str2text(cm_sys_program_name(), &text);
    // find app path for example: /opt/app/bin/ogrst, result is /opt/app
    for (i = text.len; i > 0 && count < OGRST_DIR_LEVEL; i--) {
        if (text.str[i - 1] == OS_DIRECTORY_SEPARATOR) {
            count++;
        }
    }
    if (count != OGRST_DIR_LEVEL) {
        return OG_ERROR;
    }
    text.len = i;
    OG_RETURN_IFERR(cm_text2str(&text, app_path, OG_MAX_PATH_BUFFER_SIZE));
    PRTS_RETURN_IFERR(
        snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg", app_path));
    if (ogrst_make_ogsql_file(file_name, OG_FILE_NAME_BUFFER_SIZE, app_path) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogrst_tryload_ifile(int32 file)
{
    char param[OG_PARAM_BUFFER_SIZE] = { 0 };

    ogrst_log_print("try load ogrst config file: %s\n", g_conn_params.ifile_path);
    if (!cm_file_exist(g_conn_params.ifile_path)) {
        ogrst_log_print("ogrst config file is not found, default parameters will be used\n");
        return OG_SUCCESS;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(param, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "IFILE=%s\n", g_conn_params.ifile_path));
    if (cm_write_file(file, param, (int32)strlen(param)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ogrst_log_print("ogrst config file is found\n");
    return OG_SUCCESS;
}

static status_t ogrst_generate_config_file(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    char param[OG_PARAM_BUFFER_SIZE] = { 0 };
    int32 file = OG_INVALID_HANDLE;

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1,
                                 "%s/cfg/ogracd.ini", g_conn_params.db_home));
    PRTS_RETURN_IFERR(snprintf_s(param, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1,
                                 "LSNR_PORT=%s\n"
                                 "DB_BLOCK_CHECKSUM=TYPICAL\n"
                                 "CONTROL_FILES=(%s/data/ctrl1)\n"
                                 "LOG_HOME=%s\n"
                                 "_SYS_PASSWORD=%s\n"
                                 "INSTANCE_ID = 0\n"
                                 "INTERCONNECT_PORT = 65535\n"
                                 "CLUSTER_NO_CMS = TRUE\n"
                                 "CLUSTER_DATABASE = TRUE\n"
                                 "_UNDO_SEGMENTS=%s\n"
                                 "MAX_COLUMN_COUNT=%s\n",
                                 g_conn_params.port, g_conn_params.db_home, g_conn_params.log_path,
                                 g_conn_params.encrypt_passwd, g_conn_params.undo_segments,
                                 g_conn_params.max_column_count));

    if (strlen(g_imp_params.kmc_keyfile_a) > 0 && strlen(g_imp_params.kmc_keyfile_b) > 0) {
        PRTS_RETURN_IFERR(snprintf_s(param + strlen(param), OG_PARAM_BUFFER_SIZE - strlen(param),
                                     OG_PARAM_BUFFER_SIZE - strlen(param) - 1, "KMC_KEY_FILES=(%s,%s)\n",
                                     g_imp_params.kmc_keyfile_a, g_imp_params.kmc_keyfile_b));
    }

    if (g_ssl_params.have_ssl) {
        PRTS_RETURN_IFERR(snprintf_s(param + strlen(param), OG_PARAM_BUFFER_SIZE - strlen(param),
                                     OG_PARAM_BUFFER_SIZE - strlen(param) - 1,
                                     "LOCAL_KEY = %s\n"
                                     "SSL_KEY_PASSWORD = %s\n"
                                     "SSL_CERT = %s\n"
                                     "SSL_KEY = %s\n",
                                     g_ssl_params.work_key, g_ssl_params.keypwd_cipher, g_ssl_params.ssl_cert,
                                     g_ssl_params.ssl_key));
    }

    if (cm_file_exist((const char *)file_name)) {
        if (cm_open_file(file_name, O_RDWR | O_BINARY | O_SYNC, &file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        if (cm_create_file(file_name, O_RDWR | O_BINARY | O_SYNC | O_EXCL, &file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (ogrst_tryload_ifile(file) != OG_SUCCESS) {
        cm_close_file(file);
        return OG_ERROR;
    }

    if (cm_write_file(file, param, (int32)strlen(param)) != OG_SUCCESS) {
        cm_close_file(file);
        return OG_ERROR;
    }
    cm_close_file(file);
    return OG_SUCCESS;
}

static status_t ogrst_make_dir(const char *path, bool32 force)
{
    if (!cm_dir_exist(path)) {
        if (cm_create_dir(path) != OG_SUCCESS) {
            ogrst_log_print("create dir %s fail, errno=%d\n", path, errno);
            return OG_ERROR;
        }
    } else {
        if (force) {
            ogrst_log_print("%s is already exist, please delete it firstly\n", path);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t ogrst_generate_factor_key_file(void)
{
    char mkdir[OG_MAX_PATH_BUFFER_SIZE] = { 0 };
    char file_name1[OG_FILE_NAME_BUFFER_SIZE];
    char file_name2[OG_FILE_NAME_BUFFER_SIZE];

    if (!g_ssl_params.have_ssl) {
        return OG_SUCCESS;
    }

    errno_t ret = snprintf_s(mkdir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s/dbs",
                             g_conn_params.db_home);
    if (ret == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return OG_ERROR;
    }

    ret = snprintf_s(file_name1, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
                     g_conn_params.db_home, OG_FKEY_FILENAME1);
    if (ret == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return OG_ERROR;
    }

    ret = snprintf_s(file_name2, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
                     g_conn_params.db_home, OG_FKEY_FILENAME2);
    if (ret == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return OG_ERROR;
    }

    if (ogrst_make_dir(mkdir, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (srv_save_factor_key_file((const char *)file_name1, g_ssl_params.factor_key) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return (srv_save_factor_key_file((const char *)file_name2, g_ssl_params.factor_key));
}

#ifndef WIN32
static void ogrst_clear_temp_files(void)
{
    if (cm_remove_dir(g_conn_params.export_path) != OG_SUCCESS) {
        ogrst_log_print("clear temp files fail\n");
    }

    if (g_is_page_repair) {
        return;
    }

    if (cm_remove_dir(g_conn_params.db_home) != OG_SUCCESS) {
        ogrst_log_print("clear temp files fail\n");
    }
}
#endif

static void ogrst_print_error(ogconn_conn_t conn)
{
    int code;
    const char *message = NULL;
    ogconn_get_error(conn, &code, &message);
    ogrst_log_print("GS-%05d %s\r\n", code, message);
}

static void ogrst_clear_passwd(void)
{
    MEMS_RETVOID_IFERR(memset_sp(g_conn_params.passwd, OG_PASSWD_MAX_LEN, 0, OG_PASSWD_MAX_LEN));
    MEMS_RETVOID_IFERR(memset_sp(g_conn_params.encrypt_passwd, OG_PASSWORD_BUFFER_SIZE, 0, OG_PASSWORD_BUFFER_SIZE));
    MEMS_RETVOID_IFERR(memset_sp(g_conn_params.user_passwd, OG_PASSWD_MAX_LEN, 0, OG_PASSWD_MAX_LEN));
    MEMS_RETVOID_IFERR(memset_sp(g_conn_params.backup_set_passwd, OG_PASSWD_MAX_LEN, 0, OG_PASSWD_MAX_LEN));
}

static status_t ogrst_init_conn(const char *user, const char *user_pwd, const char *url)
{
    text_t line;
    char sql[MAX_SQL_LEN] = { 0 };

    ogsql_init(1, NULL);
    cm_reset_error();
    g_local_config.OGSQL_SSL_QUIET = OG_TRUE;
    PRTS_RETURN_IFERR(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "conn %s/%s@%s", user, user_pwd, url));
    cm_str2text_safe(sql, (uint32)strlen(sql), &line);
    if (ogsql_connect(&line) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void ogrst_free_conn(void)
{
    if (IS_CONN) {
        ogconn_free_stmt(STMT);
        ogconn_disconnect(CONN);
        ogconn_free_conn(CONN);
    }
}

/* Please use uppercase SQL statements to solve the problem of case sensitivity */
static status_t ogrst_execute_sql(const char *sql, bool32 free_conn)
{
    if (ogconn_prepare(STMT, sql) != OG_SUCCESS) {
        ogrst_log_print("ogrst execute sql conn prepare failed\n");
        ogrst_print_error(CONN);
    } else {
        if (ogconn_execute(STMT) != OG_SUCCESS) {
            ogrst_print_error(CONN);
        } else {
            if (free_conn) {
                ogrst_free_conn();
            }
            return OG_SUCCESS;
        }
    }

    if (free_conn) {
        ogrst_free_conn();
    }
    return OG_ERROR;
}

/* Please use uppercase SQL statements to solve the problem of case sensitivity */
static status_t ogrst_execute_sql_get_string(const char *sql, char *str_buf, uint32 buf_size, bool32 free_conn)
{
    uint32 rows;
    status_t status = OG_SUCCESS;
    do {
        if (ogrst_execute_sql(sql, OG_FALSE) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (ogconn_fetch(STMT, &rows) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (rows == 0) {
            status = OG_ERROR;
            break;
        }

        if (ogconn_column_as_string(STMT, 0, str_buf, buf_size) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }
    } while (0);

    if (free_conn) {
        ogrst_free_conn();
    }
    return status;
}

static status_t ogrst_restore_tablespace(void)
{
    char sql[MAX_SQL_LEN] = { 0 };

    ogrst_log_print("begin restore tablespace\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    if (g_conn_params.is_set_passwd) {
        PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                      "RESTORE DATABASE FROM \'%s\' TABLESPACE %s PASSWORD %s",
                                      g_conn_params.backup_path, g_conn_params.tablespace,
                                      g_conn_params.backup_set_passwd),
                           ogrst_free_conn());
    } else {
        PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "RESTORE DATABASE FROM \'%s\' TABLESPACE %s",
                                      g_conn_params.backup_path, g_conn_params.tablespace),
                           ogrst_free_conn());
    }

    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        MEMS_RETURN_IFERR(memset_sp(sql, MAX_SQL_LEN, 0, MAX_SQL_LEN)); /* clear password in sql */
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memset_sp(sql, MAX_SQL_LEN, 0, MAX_SQL_LEN)); /* clear password in sql */
    ogrst_log_print("end restore tablespace\n");
    return OG_SUCCESS;
}

static status_t ogrst_recover_database(void)
{
    char sql[MAX_SQL_LEN] = { 0 };

    ogrst_log_print("begin recover database\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "RECOVER DATABASE"), ogrst_free_conn());

    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ogrst_log_print("end recover database\n");
    return OG_SUCCESS;
}

static status_t ogrst_modify_sys_user_passwd(void)
{
    char sql[MAX_SQL_LEN] = { 0 };
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "SELECT PROFILE FROM ADM_USERS WHERE USERNAME = \'SYS\'"),
                       ogrst_free_conn());
    if (ogrst_execute_sql_get_string(sql, str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_FALSE) != OG_SUCCESS) {
        ogrst_free_conn();
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "ALTER PROFILE \"%s\" LIMIT PASSWORD_REUSE_TIME UNLIMITED", str_buf),
                       ogrst_free_conn());
    if (ogrst_execute_sql(sql, OG_FALSE) != OG_SUCCESS) {
        ogrst_free_conn();
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "ALTER PROFILE \"%s\" LIMIT PASSWORD_REUSE_MAX UNLIMITED", str_buf),
                       ogrst_free_conn());
    if (ogrst_execute_sql(sql, OG_FALSE) != OG_SUCCESS) {
        ogrst_free_conn();
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "ALTER USER SYS IDENTIFIED BY \'%s\'",
                                  g_conn_params.passwd),
                       ogrst_free_conn());
    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogrst_open_database(void)
{
    char sql[MAX_SQL_LEN] = { 0 };
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    uint32 retry_times = 0;

    ogrst_log_print("begin open database\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "ALTER DATABASE OPEN"), ogrst_free_conn());
    if (ogrst_execute_sql(sql, OG_FALSE) != OG_SUCCESS) {
        ogrst_free_conn();
        return OG_ERROR;
    }

    ogrst_log_print("begin wait ddl enable\n");
    for (;;) {
        PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                      "SELECT ROLLBACK_STATUS FROM DB_ROLLBACK_STATUS"),
                           ogrst_free_conn());

        if (ogrst_execute_sql_get_string(sql, str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_FALSE) != OG_SUCCESS) {
            ogrst_free_conn();
            return OG_ERROR;
        }

        if (cm_strcmpni(str_buf, "FALSE", strlen("FALSE")) == 0) {
            cm_sleep(OGRST_WAIT_DDL_ENABLE_TIME);
            break;
        }
        cm_sleep(MILLISECS_PER_SECOND);
        retry_times++;
        if (retry_times % SECONDS_PER_MIN == 0) {
            ogrst_log_print("wait ddl enable spend %u minutes\n", retry_times / SECONDS_PER_MIN);
        }
    }
    ogrst_log_print("end wait ddl enable\n");

    ogrst_modify_sys_user_passwd();

    ogrst_log_print("end open database\n");
    return OG_SUCCESS;
}

static status_t ogrst_change_database_readonly(void)
{
    char sql[MAX_SQL_LEN] = { 0 };

    ogrst_log_print("begin change database readonly\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "ALTER DATABASE CONVERT TO READONLY"),
                       ogrst_free_conn());
    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ogrst_log_print("end change database readonly\n");
    return OG_SUCCESS;
}

static status_t ogrst_export_schema_data(void)
{
    text_t line;
    char sql[MAX_SQL_LEN] = { 0 };

    ogrst_log_print("begin export schema data\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "EXP USERS=%s FILE=\'%s/%s.dmp\' FILETYPE=bin LOG=\"%s/exp.log\" PARALLEL = 16",
                                  g_conn_params.schema, g_conn_params.export_path, g_conn_params.schema,
                                  g_conn_params.log_path),
                       ogrst_free_conn());
    cm_str2text_safe(sql, (uint32)strlen(sql), &line);
    if (ogsql_export(&line, OG_TRUE) != OG_SUCCESS) {
        ogrst_log_print("export schema data failed\n");
        ogrst_free_conn();
        return OG_ERROR;
    }
    ogrst_free_conn();

    ogrst_log_print("end export schema data\n");
    return OG_SUCCESS;
}

static status_t ogrst_import_schema_data(void)
{
    text_t line;
    char sql[MAX_SQL_LEN] = { 0 };

    ogrst_log_print("begin import schema data\n");

    if (ogrst_init_conn(g_conn_params.schema, g_conn_params.user_passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "IMP USERS=%s FILE=\'%s/%s.dmp\' FILETYPE=bin LOG=\"%s/imp.log\" DDL_PARALLEL=%hu \
        PARALLEL=%hu NOLOGGING=%c BATCH_COUNT=%hu TIMING=ON",
                                  g_conn_params.schema, g_conn_params.export_path, g_conn_params.schema,
                                  g_conn_params.log_path, g_imp_params.ddl_parallel, g_imp_params.parallel,
                                  g_imp_params.nologgine, g_imp_params.batch_count),
                       ogrst_free_conn());
    ogrst_log_print("import command is \"%s\"\n", sql);
    cm_str2text_safe(sql, (uint32)strlen(sql), &line);
    if (ogsql_import(&line) != OG_SUCCESS) {
        ogrst_log_print("import schema data failed\n");
        ogrst_free_conn();
        return OG_ERROR;
    }
    ogrst_free_conn();

    ogrst_log_print("end import schema data\n");
    return OG_SUCCESS;
}

static status_t ogrst_block_recover(void)
{
    char sql[MAX_SQL_LEN] = { 0 };

    ogrst_log_print("begin block recover\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    if (g_conn_params.db_status == DB_STATUS_OPEN) {
        PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                      "RESTORE BLOCKRECOVER DATAFILE %u PAGE %u FROM \'%s\' UNTIL LFN %llu",
                                      g_conn_params.page_id.file, g_conn_params.page_id.page, g_conn_params.backup_path,
                                      g_conn_params.lfn),
                           ogrst_free_conn());
    } else {
        PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                      "RESTORE BLOCKRECOVER DATAFILE %u PAGE %u FROM \'%s\'",
                                      g_conn_params.page_id.file, g_conn_params.page_id.page,
                                      g_conn_params.backup_path),
                           ogrst_free_conn());
    }

    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        ogrst_log_print("ERROR: block recover failed\n");
        return OG_ERROR;
    }

    ogrst_log_print("end block recover\n");
    return OG_SUCCESS;
}

static status_t ogrst_query_param(const char *param, char *str_buf, uint32 buf_size)
{
    char sql[MAX_SQL_LEN] = { 0 };
    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }

    errno_t ret = snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "SELECT VALUE FROM DV_PARAMETERS WHERE NAME = \'%s\'",
                             param);
    if (ret == -1) {
        ogrst_free_conn();
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return OG_ERROR;
    }

    if (ogrst_execute_sql_get_string(sql, str_buf, buf_size, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogrst_init_ssl_params(void)
{
    char str_buf[OG_PARAM_BUFFER_SIZE] = { 0 };

    if (ogrst_query_param("HAVE_SSL", str_buf, OG_PARAM_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    g_ssl_params.have_ssl = cm_strcmpni(str_buf, "TRUE", strlen("TRUE")) == 0 ? OG_TRUE : OG_FALSE;
    if (!g_ssl_params.have_ssl) {
        return OG_SUCCESS;
    }

    ogrst_log_print("begin query database ssl configuration\n");

    if (ogrst_query_param("LOCAL_KEY", g_ssl_params.work_key, OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_query_param("SSL_KEY_PASSWORD", g_ssl_params.keypwd_cipher, OG_MAX_SSL_CIPHER_LEN + 1) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (ogrst_query_param("SSL_CERT", g_ssl_params.ssl_cert, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_query_param("SSL_KEY", g_ssl_params.ssl_key, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_query_param("_FACTOR_KEY", g_ssl_params.factor_key, OG_MAX_FACTOR_KEY_STR_LEN + 1) != OG_SUCCESS) {
        return OG_ERROR;
    }
    ogrst_log_print("end query database ssl configuration\n");
    return OG_SUCCESS;
}

static status_t ogrst_init_instance(void)
{
    char mkdir[OG_MAX_PATH_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(
        snprintf_s(mkdir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s", g_conn_params.db_home));
    if (ogrst_make_dir(mkdir, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(mkdir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s/cfg", g_conn_params.db_home));
    if (ogrst_make_dir(mkdir, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(mkdir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s/data", g_conn_params.db_home));
    if (ogrst_make_dir(mkdir, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(mkdir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s", g_conn_params.export_path));
    if (ogrst_make_dir(mkdir, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(mkdir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_BUFFER_SIZE - 1, "%s", g_conn_params.log_path));
    if (ogrst_make_dir(mkdir, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_init_ssl_params() != OG_SUCCESS) {
        ogrst_log_print("init ssl parameters failed\n");
        return OG_ERROR;
    }

    if (ogrst_query_param("MAX_COLUMN_COUNT", g_conn_params.max_column_count, OG_PARAM_BUFFER_SIZE) != OG_SUCCESS) {
        ogrst_log_print("query MAX_COLUMN_COUNT failed\n");
        return OG_ERROR;
    }
    if (ogrst_query_param("_UNDO_SEGMENTS", g_conn_params.undo_segments, OG_PARAM_BUFFER_SIZE) != OG_SUCCESS) {
        ogrst_log_print("query _UNDO_SEGMENTS failed\n");
        return OG_ERROR;
    }
    ogrst_log_print("MAX_COLUMN_COUNT: '%s'\n", g_conn_params.max_column_count);
    ogrst_log_print("_UNDO_SEGMENTS: '%s'\n", g_conn_params.undo_segments);

    if (ogrst_generate_config_file() != OG_SUCCESS) {
        ogrst_log_print("init database config file failed\n");
        return OG_ERROR;
    }
    if (ogrst_write_ogsql_file() != OG_SUCCESS) {
        ogrst_log_print("init ogsql config file failed\n");
        return OG_ERROR;
    }
    if (ogrst_generate_factor_key_file() != OG_SUCCESS) {
        ogrst_log_print("init database factor key file failed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogrst_query_db_status(void)
{
    char sql[MAX_SQL_LEN] = { 0 };
    char str_buf[OG_MAX_NAME_LEN] = { 0 };

    ogrst_log_print("begin query database status\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "SELECT STATUS FROM DV_DATABASE"),
                       ogrst_free_conn());

    if (ogrst_execute_sql_get_string(sql, str_buf, OG_MAX_NAME_LEN, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_strcmpni(str_buf, "mount", strlen("mount")) == 0) {
        g_conn_params.db_status = DB_STATUS_MOUNT;
        ogrst_log_print("database status is mount\n");
    } else if (cm_strcmpni(str_buf, "open", strlen("open")) == 0) {
        g_conn_params.db_status = DB_STATUS_OPEN;
        ogrst_log_print("database status is open\n");
    } else {
        ogrst_log_print("database status is not open or mount\n");
        return OG_ERROR;
    }

    ogrst_log_print("end query database status\n");
    return OG_SUCCESS;
}

static status_t ogrst_validate_page(void)
{
    char sql[MAX_SQL_LEN] = { 0 };
    status_t status;
    int err_code;
    const char *message = NULL;

    ogrst_log_print("begin validate page\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "VALIDATE DATAFILE %u PAGE %u",
                                  g_conn_params.page_id.file, g_conn_params.page_id.page),
                       ogrst_free_conn());

    status = ogrst_execute_sql(sql, OG_FALSE);
    ogconn_get_error(CONN, &err_code, &message);
    ogrst_free_conn();

    if (status == OG_SUCCESS) { /* we expect failed, because page is corrupted */
        ogrst_log_print("page (%u, %u) is not corrupted, repair can not continue\n", g_conn_params.page_id.file,
                        g_conn_params.page_id.page);
        return OG_ERROR;
    }

    if (err_code != ERR_PAGE_CORRUPTED) {
        ogrst_log_print("page repair stop, expected error code %d, but get %d\n", ERR_PAGE_CORRUPTED, err_code);
        return OG_ERROR;
    }

    ogrst_log_print("end validate page\n");
    return OG_SUCCESS;
}

static status_t ogrst_current_point(uint32 *asn)
{
    char sql[MAX_SQL_LEN] = { 0 };
    char str_buf[OG_MAX_NAME_LEN] = { 0 };
    int64 lfn;

    ogrst_log_print("begin fetch current point\n");

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "SELECT CURRENT_POINT FROM DV_LOG_FILES WHERE STATUS=\'CURRENT\'"),
                       ogrst_free_conn(););

    if (ogrst_execute_sql_get_string(sql, str_buf, OG_MAX_NAME_LEN, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    text_t text;
    text_t left;
    text_t right;
    text.str = str_buf;
    text.len = (uint32)strlen(str_buf);

    ogrst_log_print("current point is %s\n", text.str);
    cm_split_text(&text, '-', '\0', &left, &right);

    text = right;
    cm_split_text(&text, '/', '\0', &left, &right);
    (void)cm_text2uint32(&left, asn);

    text = right;
    cm_split_text(&text, '/', '\0', &left, &right);
    (void)cm_text2bigint(&right, &lfn);

    ogrst_log_print("asn %u, lfn %lld \n", *asn, lfn);
    g_conn_params.lfn = (uint64)lfn;

    ogrst_log_print("end fetch current point\n");
    return OG_SUCCESS;
}

static status_t ogrst_wait_archive_flush(uint32 asn)
{
    char sql[MAX_SQL_LEN] = { 0 };
    uint32 rows;
    uint32 retry_times = 0;
    bool32 is_enable_dbs;

    ogrst_log_print("begin wait archive flush\n");
    if (ogrst_is_enable_dbs(&is_enable_dbs) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "ALTER SYSTEM SWITCH LOGFILE"), ogrst_free_conn());

    if (ogrst_execute_sql(sql, OG_FALSE) != OG_SUCCESS) {
        ogrst_free_conn();
        return OG_ERROR;
    }
    if (!is_enable_dbs) {
        for (;;) {
            PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                          "SELECT NAME FROM DV_ARCHIVED_LOGS WHERE SEQUENCE#=%u", asn),
                               ogrst_free_conn());

            if (ogrst_execute_sql(sql, OG_FALSE) != OG_SUCCESS) {
                ogrst_free_conn();
                return OG_ERROR;
            }

            if (ogconn_fetch(STMT, &rows) != OG_SUCCESS) {
                ogrst_free_conn();
                return OG_ERROR;
            }

            if (rows > 0) {
                break;
            }
            cm_sleep(MILLISECS_PER_SECOND);
            retry_times++;
            if (retry_times % SECONDS_PER_MIN == 0) {
                ogrst_log_print("wait archive flush spend %u minutes\n", retry_times / SECONDS_PER_MIN);
            }
        }
    }

    ogrst_free_conn();
    cm_sleep(MILLISECS_PER_SECOND);
    ogrst_log_print("end wait archive flush\n");
    return OG_SUCCESS;
}

static status_t ogrst_read_ctrlfile(char *buf, const char *src_name, bool32 *retry)
{
    int32 handle = OG_INVALID_HANDLE;
    ctrl_page_t *pages = (ctrl_page_t *)buf;
    device_type_t type = cm_device_type(src_name);
    if (cm_open_device(src_name, type, O_RDONLY | O_BINARY, &handle) != OG_SUCCESS) {
        ogrst_log_print("failed to open control file %s\n", src_name);
        return OG_ERROR;
    }

    /* CODE_REVIEW muting 00198166 2019-8-14: fix me, temp use CTRL_MAX_PAGES_CLUSTERED instead of CTRL_MAX_PAGES */
    if (cm_read_device(type, handle, 0, buf, CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE) != OG_SUCCESS) {
        ogrst_log_print("failed to read control file %s, size %u\n", src_name,
                        CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE);
        cm_close_device(type, &handle);
        return OG_ERROR;
    }
    cm_close_device(type, &handle);

    for (uint32 i = 0; i < CTRL_MAX_PAGES_CLUSTERED; i++) {
        if (pages[i].tail.checksum == OG_INVALID_CHECKSUM) {
            continue;
        }

        if (!page_verify_checksum((page_head_t *)&pages[i], OG_DFLT_CTRL_BLOCK_SIZE)) {
            *retry = OG_TRUE;
            return OG_SUCCESS;
        }
    }

    *retry = OG_FALSE;
    return OG_SUCCESS;
}

/*
 * invalid datafiles name in ctrlfile which is copied from main database instance
 * prevent datafiles from being modified incorrectly by ogrst instance when repairing corrupted page
 * Note: do not invalid logfile ctrl, because auto block recover will read database's logfile
 */
static void ogrst_invalid_ctrlfile_dataitem(ctrl_page_t *ctrl_pages)
{
    datafile_ctrl_t *df_ctrl = NULL;
    uint32 offset = CTRL_LOG_SEGMENT;
    uint32 id;

    offset += (OG_MAX_LOG_FILES - 1) / (CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t)) + 1;
    offset += (OG_MAX_SPACES - 1) / (CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t)) + 1;

    for (id = 0; id < OG_MAX_DATA_FILES; id++) {
        df_ctrl = (datafile_ctrl_t *)db_get_ctrl_item(ctrl_pages, id, sizeof(datafile_ctrl_t), offset);
        df_ctrl->name[0] = '\0';
        df_ctrl->used = OG_FALSE;
    }

    for (id = 0; id < CTRL_MAX_PAGES_CLUSTERED; id++) {
        page_calc_checksum((page_head_t *)&ctrl_pages[id], OG_DFLT_CTRL_BLOCK_SIZE);
    }
}

static void ogrst_init_ctrlfile(database_ctrl_t *ctrl)
{
    ctrl->core = *(core_ctrl_t *)&ctrl->pages[1].buf[0];
    uint32 inst_count = ctrl->core.clustered ? OG_MAX_INSTANCES : 1;
    uint32 offset = ctrl->core.clustered ? (OG_MAX_INSTANCES + CTRL_LOG_SEGMENT) : CTRL_LOG_SEGMENT + 1;
    uint32 count;

    ctrl->log_segment = offset;
    count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pages_per_inst = (OG_MAX_LOG_FILES - 1) / count + 1;
    offset = offset + pages_per_inst * inst_count;

    ctrl->space_segment = offset;
    count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    pages_per_inst = (OG_MAX_SPACES - 1) / count + 1;
    offset = offset + pages_per_inst;

    ctrl->datafile_segment = offset;
    count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    pages_per_inst = (OG_MAX_DATA_FILES - 1) / count + 1;
    offset = offset + pages_per_inst;

    ctrl->arch_segment = offset;
}

static void ogrst_calc_ctrlfile_checksum(database_ctrl_t *ctrl)
{
    uint32 i;
    ctrl_page_t *pages = ctrl->pages;
    uint32 max_pages = ctrl->core.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;

    for (i = 1; i < max_pages; i++) {
        page_calc_checksum((page_head_t *)&pages[i], OG_DFLT_CTRL_BLOCK_SIZE);
    }
}

/* reset redo logs, spaces and datafiles to invalid, as they are not used in page recovery */
static void ogrst_reset_ctrlfile_storages(ctrl_page_t *ctrl_pages)
{
    database_ctrl_t ctrl;
    ctrl.pages = ctrl_pages;

    ogrst_init_ctrlfile(&ctrl);

    uint32 i;
    uint32 j;
    space_ctrl_t *space = NULL;
    for (i = 0; i < OG_MAX_SPACES; i++) {
        space = (space_ctrl_t *)db_get_ctrl_item(ctrl.pages, i, sizeof(space_ctrl_t), ctrl.space_segment);
        space->file_hwm = 0;
        space->used = OG_FALSE;
        space->flag = 0;
    }

    datafile_ctrl_t *datafile = NULL;
    for (i = 0; i < OG_MAX_DATA_FILES; i++) {
        datafile = (datafile_ctrl_t *)db_get_ctrl_item(ctrl.pages, i, sizeof(datafile_ctrl_t), ctrl.datafile_segment);
        datafile->used = OG_FALSE;
        datafile->flag = 0;
    }

    log_file_ctrl_t *logfile = NULL;
    g_node_count = ctrl.core.node_count;
    for (i = 0; i < ctrl.core.node_count; i++) {
        for (j = 0; j < OG_MAX_LOG_FILES; j++) {
            logfile = (log_file_ctrl_t *)db_get_log_ctrl_item(ctrl.pages, j, sizeof(log_file_ctrl_t), ctrl.log_segment,
                                                              i);
            if (logfile->name == NULL || (*(char *)(logfile->name)) == '\0') {
                continue;
            }
            logfile->flg = LOG_FLAG_DROPPED;
            logfile->status = LOG_FILE_UNUSED;
        }
    }

    ogrst_calc_ctrlfile_checksum(&ctrl);
}

static status_t ogrst_make_ctrlfile(char *str_buf, uint32 buf_size)
{
    ogrst_log_print("start make ctrl file\n");
    int32 dst_file;
    aligned_buf_t buf;
    aligned_buf_t buf_current;
    char sql[MAX_SQL_LEN] = { 0 };
    bool32 retry = OG_TRUE;
    uint32 retry_times = 0;
    dtc_node_ctrl_t *node_ctrl = NULL;
    dtc_node_ctrl_t *node_ctrl_current = NULL;
    ctrl_page_t *ctrl_page = NULL;
    ctrl_page_t *ctrl_page_current = NULL;
    char name_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(name_buf, buf_size, buf_size - 1, "%s/data/ctrl1_current", g_conn_params.db_home),
                       ogrst_free_conn());
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "RESTORE COPYCTRL to \'%s\'", name_buf),
                       ogrst_free_conn());
    ogrst_log_print("begin copy ctrl file:%s name%s sql:%s\n", name_buf, str_buf, sql);

    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        ogrst_log_print("failed to flush repaired page\n");
        return OG_ERROR;
    }

    /* CODE_REVIEW muting 00198166 2019-8-14: fix me, temp use CTRL_MAX_PAGES_CLUSTERED instead of CTRL_MAX_PAGES */
    if (cm_aligned_malloc((int64)(CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE), "ogrst ctrl", &buf) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_aligned_malloc((int64)(CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE), "ogrst ctrl_bak",
                          &buf_current) != OG_SUCCESS) {
        cm_aligned_free(&buf);
        return OG_ERROR;
    }

    while (retry) {
        if (retry_times > MAX_READ_RETRY_TIMES) {
            ogrst_log_print("read ctrl file failed, exceed max retry times %d \n", MAX_READ_RETRY_TIMES);
            cm_aligned_free(&buf);
            cm_aligned_free(&buf_current);
            return OG_ERROR;
        }
        if (cm_file_exist(name_buf)) {
            ogrst_log_print("read ctrl file success, retry times %d \n", retry_times);
            retry_times = 0;
            break;
        }
        retry_times++;
        cm_sleep(MILLISECS_PER_SECOND);
    }

    while (retry) {
        if (retry_times > MAX_READ_RETRY_TIMES) {
            ogrst_log_print("read ctrl file failed, exceed max retry times %n \n", MAX_READ_RETRY_TIMES);
            cm_aligned_free(&buf);
            cm_aligned_free(&buf_current);
            return OG_ERROR;
        }
        if (ogrst_read_ctrlfile(buf.aligned_buf, str_buf, &retry) != OG_SUCCESS) {
            ogrst_log_print("read ctrl file failed, path %s \n", str_buf);
            cm_aligned_free(&buf);
            cm_aligned_free(&buf_current);
            return OG_ERROR;
        }
        if (ogrst_read_ctrlfile(buf_current.aligned_buf, name_buf, &retry) != OG_SUCCESS) {
            ogrst_log_print("read ctrl file failed, path %s \n", name_buf);
            cm_aligned_free(&buf);
            cm_aligned_free(&buf_current);
            return OG_ERROR;
        }
        retry_times++;
    }

    ctrl_page = (ctrl_page_t *)buf.aligned_buf;
    ctrl_page_current = (ctrl_page_t *)buf_current.aligned_buf;
    ogrst_invalid_ctrlfile_dataitem((ctrl_page_t *)buf.aligned_buf);
    ogrst_reset_ctrlfile_storages((ctrl_page_t *)buf.aligned_buf);

    for (uint32 i = 0; i < g_node_count; ++i) {
        node_ctrl = (dtc_node_ctrl_t *)ctrl_page[CTRL_LOG_SEGMENT + i].buf;
        node_ctrl_current = (dtc_node_ctrl_t *)ctrl_page_current[CTRL_LOG_SEGMENT + i].buf;
        ogrst_log_print("node_id:%u before rcy lfn:[%llu-%llu] node_count:%u\n", i, node_ctrl->rcy_point.lfn,
                        node_ctrl_current->rcy_point.lfn, g_node_count);
        node_ctrl_current->rcy_point = node_ctrl->rcy_point;
        node_ctrl_current->lsn = node_ctrl->lsn;
        node_ctrl_current->lfn = node_ctrl->lfn;
        node_ctrl_current->consistent_lfn = node_ctrl->consistent_lfn;
        ogrst_log_print("node_id:%u after rcy lfn:[%llu-%llu] node_count:%u\n", i, node_ctrl->rcy_point.lfn,
                        node_ctrl_current->rcy_point.lfn, g_node_count);
    }

    ogrst_invalid_ctrlfile_dataitem((ctrl_page_t *)buf_current.aligned_buf);
    ogrst_reset_ctrlfile_storages((ctrl_page_t *)buf_current.aligned_buf);
    PRTS_RETURN_IFERR2(snprintf_s(str_buf, buf_size, buf_size - 1, "%s/data/ctrl1", g_conn_params.db_home),
                       cm_aligned_free(&buf));
    ogrst_log_print("rcy lfn:[%llu-%llu]\n", node_ctrl->lrp_point.lfn, node_ctrl_current->lrp_point.lfn);

    if (cm_create_file(str_buf, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &dst_file) != OG_SUCCESS) {
        ogrst_log_print("failed to create control file %s\n", str_buf);
        cm_aligned_free(&buf);
        cm_aligned_free(&buf_current);
        return OG_ERROR;
    }

    /* CODE_REVIEW muting 00198166 2019-8-14: fix me, temp use CTRL_MAX_PAGES_CLUSTERED instead of CTRL_MAX_PAGES */
    if (cm_write_file(dst_file, buf_current.aligned_buf, CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE) !=
        OG_SUCCESS) {
        ogrst_log_print("failed to write size %u\n", CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE);
        cm_close_file(dst_file);
        cm_aligned_free(&buf);
        cm_aligned_free(&buf_current);
        return OG_ERROR;
    }

    cm_close_file(dst_file);
    cm_aligned_free(&buf);
    cm_aligned_free(&buf_current);
    return OG_SUCCESS;
}

static status_t ogrst_copy_ctrlfile(void)
{
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };

    ogrst_log_print("begin copy control file\n");

    /* ctrl name convention must follow that in function: bak_generate_bak_file */
    status_t ret = snprintf_s(str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/ctrl_%d_%d.bak",
                              g_conn_params.backup_path, 0, 0);
    knl_securec_check_ss(ret);

    ogrst_log_print("ctrl file path %s \n", str_buf);

    if (ogrst_make_ctrlfile(str_buf, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ogrst_log_print("end copy control file\n");
    return OG_SUCCESS;
}

static status_t ogrst_backup_corrupted_page(int32 datafile)
{
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 page_bakfile;
    int32 read_size;
    int64 offset = (int64)OGRST_PAGE_SIZE * g_conn_params.page_id.page;
    char *buf = NULL;

    PRTS_RETURN_IFERR(snprintf_s(str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1,
                                 "%s/data/page_%u_%u_corrupt", g_conn_params.db_home, g_conn_params.page_id.file,
                                 g_conn_params.page_id.page));
    ogrst_log_print("backup corrupted page\n");
    buf = (char *)malloc(OGRST_PAGE_SIZE);
    if (buf == NULL) {
        ogrst_log_print("failed to malloc buffer size %u\n", OGRST_PAGE_SIZE);
        return OG_ERROR;
    }

    if (cm_create_file(str_buf, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &page_bakfile) != OG_SUCCESS) {
        ogrst_log_print("failed to page backup file %s\n", str_buf);
        free(buf);
        return OG_ERROR;
    }

    if (cm_seek_file(datafile, offset, SEEK_SET) != offset) {
        ogrst_log_print("failed to seek data file offset %lld", offset);
        cm_close_file(page_bakfile);
        free(buf);
        return OG_ERROR;
    }

    if (cm_read_file(datafile, buf, OGRST_PAGE_SIZE, &read_size) != OG_SUCCESS) {
        cm_close_file(page_bakfile);
        free(buf);
        return OG_ERROR;
    }

    if (read_size != OGRST_PAGE_SIZE) {
        ogrst_log_print("failed to read size %u\n", OGRST_PAGE_SIZE);
        cm_close_file(page_bakfile);
        free(buf);
        return OG_ERROR;
    }

    if (cm_write_file(page_bakfile, buf, OGRST_PAGE_SIZE) != OG_SUCCESS) {
        cm_close_file(page_bakfile);
        free(buf);
        return OG_ERROR;
    }
    cm_close_file(page_bakfile);
    free(buf);

    return OG_SUCCESS;
}

static status_t ogrst_read_repaired_page(char *buf, int32 buf_len)
{
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 handle = OG_INVALID_HANDLE;
    int32 read_size;

    PRTS_RETURN_IFERR(snprintf_s(str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/data/page_%u_%u",
                                 g_conn_params.db_home, g_conn_params.page_id.file, g_conn_params.page_id.page));

    if (cm_open_file(str_buf, O_RDONLY | O_BINARY, &handle) != OG_SUCCESS) {
        ogrst_log_print("failed to open pege file %s\n", str_buf);
        return OG_ERROR;
    }

    if (cm_read_file(handle, buf, buf_len, &read_size) != OG_SUCCESS) {
        cm_close_file(handle);
        return OG_ERROR;
    }
    cm_close_file(handle);

    if (read_size != buf_len) {
        ogrst_log_print("failed to read size %u\n", read_size);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogrst_flush_repaired_page(const char *page, int32 page_size, page_id_t page_id)
{
    char sql[MAX_SQL_LEN] = { 0 };
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 handle = OG_INVALID_HANDLE;
    bool32 is_enable_dbs;

    ogrst_log_print("begin flush repaired page\n");
    if (ogrst_is_enable_dbs(&is_enable_dbs) != OG_SUCCESS) {
        ogrst_log_print("get ogrst is enable dbs failed");
        return OG_ERROR;
    }

    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "SELECT FILE_NAME FROM DV_DATA_FILES WHERE ID=%u",
                                  page_id.file),
                       ogrst_free_conn());

    if (ogrst_execute_sql_get_string(sql, str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ogrst_log_print("data file path %s\n", str_buf);
    if (!is_enable_dbs) {
        if (cm_open_file(str_buf, O_SYNC | O_RDWR | O_BINARY, &handle) != OG_SUCCESS) {
            ogrst_log_print("failed to open data file %s\n", str_buf);
            return OG_ERROR;
        }

        if (ogrst_backup_corrupted_page(handle) != OG_SUCCESS) {
            ogrst_log_print("failed to backup corrupted page\n");
            cm_close_file(handle);
            return OG_ERROR;
        }
        cm_close_file(handle);
    }

    PRTS_RETURN_IFERR2(snprintf_s(str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/data/page_%u_%u",
                                  g_conn_params.db_home, g_conn_params.page_id.file, g_conn_params.page_id.page),
                       ogrst_free_conn());
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1, "RESTORE flushpage from \'%s\'", str_buf),
                       ogrst_free_conn());
    ogrst_log_print("begin flush repaired page:%s sql:%s\n", str_buf, sql);

    if (ogrst_execute_sql(sql, OG_TRUE) != OG_SUCCESS) {
        ogrst_log_print("failed to flush repaired page\n");
        return OG_ERROR;
    }

    ogrst_log_print("end flush repaired page\n");
    return OG_SUCCESS;
}

static status_t ogrst_client_proc(void)
{
    if (cm_start_timer(g_timer()) != OG_SUCCESS) {
        ogrst_log_print("start timer failed");
        return OG_ERROR;
    }

    if (ogrst_restore_tablespace() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_recover_database() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_open_database() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_change_database_readonly() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_export_schema_data() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogrst_import_schema_data() != OG_SUCCESS) {
        return OG_ERROR;
    }
    cm_close_timer(g_timer());
    return OG_SUCCESS;
}

static status_t ogrst_repair_proc(void)
{
    char *buf = NULL;

    if (cm_start_timer(g_timer()) != OG_SUCCESS) {
        ogrst_log_print("start timer failed");
        return OG_ERROR;
    }

    /* block recover */
    if (ogrst_block_recover() != OG_SUCCESS) {
        return OG_ERROR;
    }

    buf = (char *)malloc(OGRST_PAGE_SIZE);
    if (buf == NULL) {
        ogrst_log_print("failed to malloc buffer size %u\n", OGRST_PAGE_SIZE);
        return OG_ERROR;
    }

    if (ogrst_read_repaired_page(buf, OGRST_PAGE_SIZE) != OG_SUCCESS) {
        ogrst_log_print("failed to read repaired pege file\n");
        free(buf);
        return OG_ERROR;
    }

    if (ogrst_validate_page() != OG_SUCCESS) {
        free(buf);
        return OG_ERROR;
    }

    if (ogrst_flush_repaired_page(buf, OGRST_PAGE_SIZE, g_conn_params.page_id) != OG_SUCCESS) {
        free(buf);
        return OG_ERROR;
    }

    free(buf);
    cm_close_timer(g_timer());
    return OG_SUCCESS;
}

static void ogrst_loop_proc(thread_t *thread)
{
    if (srv_instance_loop() != OG_SUCCESS) {
        ogrst_log_print("%s\n", "instance exit");
        (void)fflush(stdout);
    }
#ifndef WIN32
    ogrst_clear_temp_files();
#endif
}

static status_t ogrst_startup_instance(bool32 is_page_repair)
{
    db_startup_phase_t startup_phase = STARTUP_NOMOUNT;

    if (is_page_repair) {
        if (ogrst_query_db_status() != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (ogrst_validate_page() != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (ogrst_init_instance() != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (is_page_repair) {
        if (g_conn_params.db_status == DB_STATUS_OPEN) {
            uint32 asn;
            if (ogrst_current_point(&asn) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (ogrst_wait_archive_flush(asn) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
        if (ogrst_copy_ctrlfile() != OG_SUCCESS) {
            return OG_ERROR;
        }
        startup_phase = STARTUP_MOUNT;
    }

    if (srv_instance_startup(startup_phase, OG_FALSE, OG_FALSE, OG_FALSE) != OG_SUCCESS) {
        (void)printf("instance startup failed, please check log at %s\n", g_conn_params.log_path);
        (void)fflush(stdout);
        return OG_ERROR;
    }
    g_instance->is_ogrst_instance = OG_TRUE;
    return OG_SUCCESS;
}

#ifdef WIN32
char *oGRACd_get_dbversion()
{
    return "NONE";
}
#else
extern char *oGRACd_get_dbversion(void);
#endif

static void ogrst_init_imp_params(void)
{
    g_imp_params.batch_count = IMPORT_MAX_BATCH_COUNT;
    g_imp_params.ddl_parallel = IMPORT_DEFAULT_PARALLEL_WORKERS;
    g_imp_params.parallel = IMPORT_DEFAULT_PARALLEL_WORKERS;
    g_imp_params.nologgine = 'N';
    g_imp_params.kmc_keyfile_a[0] = '\0';
    g_imp_params.kmc_keyfile_b[0] = '\0';
}

static bool32 ogrst_confirm_risk()
{
    char confirm[OG_MAX_CMD_LEN] = { 0 };
    char *env_val = getenv("OGRST_CONFIRM_QUIET");
    bool32 val_bool32 = OG_FALSE;

    if (env_val != NULL && cm_str2bool(env_val, &val_bool32) == OG_SUCCESS) {
        if (val_bool32) {
            return OG_TRUE;
        }
    }

    for (;;) {
        (void)printf("Warning: ogrst tool is a database repair tool only for emergencies. "
                     "Data consistency may be damaged after using this tool to recover "
                     "a single tablespace in a distributed database. "
                     "It is strongly recommended do not use this tool in non-emergency situations.\n");
        (void)printf("Continue anyway? (yes/no):");
        (void)fflush(stdout);
        timeval_t tv_begin;
        timeval_t tv_end;
        (void)cm_gettimeofday(&tv_begin);
        while (NULL == cm_fgets_nonblock(confirm, sizeof(confirm), stdin)) {
            (void)cm_gettimeofday(&tv_end);
            if (tv_end.tv_sec - tv_begin.tv_sec > (long)OGRST_INTERACTION_TIMEOUT) {
                (void)printf("\nRisk Confirming operation has timed out.\n");
                return OG_FALSE;
            }
        }
        if (cm_strcmpni(confirm, "yes\n", sizeof("yes\n")) == 0) {
            return OG_TRUE;
        } else if (cm_strcmpni(confirm, "no\n", sizeof("no\n")) == 0) {
            printf("\nogrst risks were not confirmed.\n");
            return OG_FALSE;
        } else {
            printf("\n");
        }
    }
    return OG_FALSE;
}

static status_t ogrst_is_enable_dbs(bool32 *is_enable_db)
{
    ogrst_log_print("begin get is enable dbs\n");
    char sql[MAX_SQL_LEN] = { 0 };
    char str_buf[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
    if (ogrst_init_conn("sys", g_conn_params.passwd, g_conn_params.imp_url) != OG_SUCCESS) {
        ogrst_log_print("ogrst init conn failed\n");
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR2(snprintf_s(sql, MAX_SQL_LEN, MAX_SQL_LEN - 1,
                                  "SELECT FILE_NAME FROM DV_LOG_FILES WHERE STATUS=\'CURRENT\'"),
                       ogrst_free_conn());
    if (ogrst_execute_sql_get_string(sql, str_buf, OG_FILE_NAME_BUFFER_SIZE, OG_TRUE) != OG_SUCCESS) {
        ogrst_log_print("ogrst get is enable dbs failed\n");
        return OG_ERROR;
    }
    *is_enable_db = cm_device_type(str_buf) == DEV_TYPE_ULOG;
    ogrst_log_print("end get is enable dbs\n");
    return OG_SUCCESS;
}

static status_t ogrst_start(thread_t *thread)
{
#ifdef WIN32
    return OG_SUCCESS;
#else
    int status;
    pid_t fpid;
    status_t ret = OG_ERROR;
    if (ogrst_startup_instance(g_is_page_repair) != OG_SUCCESS) {
        ogrst_clear_passwd();
        return OG_ERROR;
    }

    if (cm_create_thread(ogrst_loop_proc, 0, NULL, thread) != OG_SUCCESS) {
        ogrst_clear_passwd();
        return OG_ERROR;
    }
    cm_pause_timer(g_timer());
    fpid = fork();
    if (fpid < 0) {
        cm_resume_timer(g_timer());
        ogrst_log_print("start client fail\n");
        cm_close_thread(thread);
        srv_instance_abort();
    } else if (fpid == 0) {
        if (g_is_page_repair) {
            ret = ogrst_repair_proc();
        } else {
            ret = ogrst_client_proc();
        }
    } else {
        cm_resume_timer(g_timer());
        if (waitpid(fpid, &status, 0) != fpid) {
            ogrst_log_print("wait client process (%d) failed\n", fpid);
        }
        if (WIFEXITED((uint)status) && WEXITSTATUS((uint)status) == OG_SUCCESS) {
            ret = OG_SUCCESS;
        }
        g_instance->lsnr_abort_status = OG_TRUE;
        cm_close_thread(thread);
    }
    ogrst_clear_passwd();
    return ret;
#endif
}

EXTER_ATTACK int32 main(int argc, char *argv[])
{
#ifdef WIN32
    (void)printf("%s\n", "not support windows");
    return OG_SUCCESS;
#else
    thread_t thread;
    errno_t errcode;

    g_is_page_repair = OG_FALSE;
    errcode = memset_s(&g_conn_params, sizeof(ogrst_conn_params_t), 0, sizeof(ogrst_conn_params_t));
    if (errcode != EOK) {
        (void)printf("init fail\n");
        return OG_ERROR;
    }
    ogrst_init_imp_params();
    if (argc == HELP_ARGS_LENTH) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-H") == 0) {
            ogrst_usage();
            return OG_SUCCESS;
        } else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "-V") == 0) {
            printf("%s\n", oGRACd_get_dbversion());
            return OG_SUCCESS;
        } else {
            (void)printf("invalid argument\n");
            ogrst_usage();
            return OG_ERROR;
        }
    } else if (argc >= ARGS_NO_CONFIG && argc <= ARGS_HAS_CONFIG) {
        if (ogrst_parse_args(argc, argv, OG_FALSE) != OG_SUCCESS) {
            ogrst_clear_passwd();
            return OG_ERROR;
        }
    } else if (argc >= REPAIR_ARGS_WITHOUT_KEYFILE_LENTH && argc <= REPAIR_ARGS_WITH_KEYFILE_LENTH) {
        if (ogrst_parse_args(argc, argv, OG_TRUE) != OG_SUCCESS) {
            ogrst_clear_passwd();
            return OG_ERROR;
        }
        g_is_page_repair = OG_TRUE;
    } else {
        (void)printf("invalid argument\n");
        ogrst_usage();
        return OG_ERROR;
    }

    if (!ogrst_confirm_risk()) {
        ogrst_clear_passwd();
        return OG_ERROR;
    }

    return ogrst_start(&thread);
#endif
}
