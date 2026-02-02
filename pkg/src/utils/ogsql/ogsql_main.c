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
 * ogsql_main.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "ogsql.h"
#include "cm_signal.h"
#include "cm_coredump.h"
#include "cm_log.h"
#include "ogsql_common.h"

#define PRODUCT_NAME "oGRAC"
#define OGSQL_NAME    "OGSQL"
#define OGSQL_MAX_PARAMETER_CNT   (uint32)10

#ifdef WIN32
const char *ogsql_get_dbversion()
{
    return "NONE";
}
#else
extern const char *ogsql_get_dbversion(void);
#endif

static void ogsql_show_version(void)
{
    ogsql_printf("%s\n", ogsql_get_dbversion());
}

static void ogsql_show_usage(void)
{
    ogsql_printf(PRODUCT_NAME " SQL Developer Command - Line(" OGSQL_NAME ") help\n\n");
    ogsql_printf("Usage 1: ogsql -h | -v \n\n");
    ogsql_printf("    -h, -help     Shows help information.\n");
    ogsql_printf("    -v, -version  Shows version information.\n\n\n");

    ogsql_printf("Usage 2: ogsql \n\n");
    ogsql_printf("    Run ogsql without any parameter to enter the interactive mode,\n");
    ogsql_printf("    Then, run the 'conn user/password@host:port[/tenant]' command to connect to the database.\n\n\n");

    ogsql_printf("Usage 3: ogsql [ <logon> [<options>] [<start>] ] \n\n");
    ogsql_printf("  <logon> allows [ user [ /password ] @{host:port}[,...] [ /tenant ] ] [as sysdba] and [ / as { sysdba | clsmgr } [ host:port ] ]\n");
    ogsql_printf("    user: Name of the user for logging in.\n");
    ogsql_printf("    password: Password of the login user. Enter interactive mode if no password provided.\n"
                "              It is recommended for the reason of security to input password interactively.\n");
    ogsql_printf("    host: IP address for logging in to the database. Currently, IPv4 and IPv6 are both supported.\n");
    ogsql_printf("    port: Port for logging in to the database.\n");
    ogsql_printf("    tenant: Name of the tenant which the user belongs to.The default value is TENANT$ROOT.\n");
    ogsql_printf("    sysdba: Database administrator.\n");
    ogsql_printf("    clsmgr: Cluster administrator.\n");
    ogsql_printf("\n");
    ogsql_printf("  <options> is [-q] [-w <timeout>] [-a] [-D \"data_home_path\"]\n");
    ogsql_printf("    -q: Cancels the SSL login authentication. \n");
    ogsql_printf("    -w: Timeout interval for the client to connect to the database.\n");
    ogsql_printf("    <timeout>: Timeout interval (unit: second). The default value is 60s.\n"
                "               There are also special values. Value -1 indicates that the timeout interval is infinite,\n"
                "               and value 0 indicates no wait.\n");
    ogsql_printf("    -a: Prints an executed SQL statement.\n"
                "        This parameter can be used together with -f, indicating to print and execute the\n"
                "        SQL statements in an SQL script file.\n");
    ogsql_printf("    -D: Specify data home path.\n");
    ogsql_printf("        Connect to cluster node must specify data home path.\n");
    ogsql_printf("\n");
    ogsql_printf("  <start> allows [-c \"execute-sql-command\"], [-f \"execute-sql-file\"], and [-s \"destination-file\"]\n");
    ogsql_printf("          start options can only exists one case at the same time.\n");
    ogsql_printf("    -c: Executes an SQL statement.\n");
    ogsql_printf("    -f: Executes an SQL script file.\n");
    ogsql_printf("    -s: Redirects command prompt and output to a specified file.\n");
    ogsql_printf("\n");
    ogsql_printf("  For example\n");
    ogsql_printf("     ogsql / as sysdba\n"
                "                               Log in to a database as user sys in password-free mode.\n");
    ogsql_printf("     ogsql user/user_pwd@127.0.0.1:1611\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611(default port).\n");
    ogsql_printf("     ogsql user/user_pwd@127.0.0.1:1611/tenant\n"
                "                               Log in to the database as the specified user in the specified tenant through the IP address 127.0.0.1 and port 1611(default port).\n");
    ogsql_printf("     ogsql user/user_pwd@127.0.0.1:1611 -c \"SELECT 1 FROM SYS_DUMMY\"\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611(default port), \n"
                "                               and then execute the SQL statement \"SELECT 1 FROM SYS_DUMMY\".\n");
    ogsql_printf("     ogsql user/user_pwd@127.0.0.1:1611 -f \"/home/user/example.sql\"\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611(default port),\n"
                "                               and then execute the \"/home/user/example.sql\".\n");
    ogsql_printf("     ogsql user/user_pwd@127.0.0.1:1611,127.0.0.1:1612\n"
                "                               Log in to the database as the specified user through the IP address 127.0.0.1 and port 1611(default port) \n"
                "                               or IP address 127.0.0.1 and port 1612.\n");
    ogsql_printf("\n");
}

static void ogsql_show_help(void)
{
    ogsql_show_version();
    ogsql_show_usage();
}

static void ogsql_erase_argv_pwd(char *arg)
{
    text_t conn_text;
    text_t user_text;
    text_t pwd_text;
    cm_str2text(arg, &conn_text);

    if (!cm_fetch_text(&conn_text, '/', 0, &user_text)) {
        return;
    }

    if (!cm_fetch_rtext(&conn_text, '@', 0, &pwd_text)) {
        return;
    }
    cm_str2text(arg, &conn_text);
    ogsql_erase_pwd(&conn_text, &pwd_text);
}

static status_t ogsql_execute_cmd(ogsql_cmd_t type, text_t *conn, text_t *cmd)
{
    status_t status = ogsql_process_cmd(conn);
    if (status != OG_SUCCESS) {
        ogconn_disconnect(CONN);
        exit(status);
    }

    ogsql_printf("\n");

    switch (type) {
        case CMD_COMMAND:
            (void)ogsql_print_welcome(OGSQL_SINGLE_TAG, 0);

            if (CM_TEXT_END(cmd) == '/') {
                status = ogsql_execute(cmd);
            } else {
                if (CM_TEXT_END(cmd) != ';') {
                    PRTS_RETURN_IFERR(sprintf_s(g_cmd_buf, MAX_CMD_LEN, "%s;", cmd->str));
                    (void)cm_text_set(cmd, cmd->len, '\0');
                    cm_str2text(g_cmd_buf, cmd);
                }
                status = ogsql_process_cmd(cmd);
            }
            ogsql_exit(OG_FALSE, status);

        case CMD_FILE:
            PRTS_RETURN_IFERR(sprintf_s(g_cmd_buf, MAX_CMD_LEN, "@%s", cmd->str));
            (void)cm_text_set(cmd, cmd->len, '\0');
            cm_str2text(g_cmd_buf, cmd);
            status = ogsql_process_cmd(cmd);
            ogsql_exit(OG_FALSE, status);

        case CMD_SILENT:
            ogsql_silent(cmd);
            break;

        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t ogsql_parse_timeout(int32 argc, char *argv[], uint32 index)
{
    if (index >= (uint32)argc || strlen(argv[index]) == 0) {
        OGSQL_PRINTF(ZSERR_MAIN, "Input connect timeout value is invalid: %s", argv[index]);
        return OG_ERROR;
    }

    if (cm_str2int(argv[index], &g_local_config.connect_timeout) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (g_local_config.connect_timeout < -1) {
        OGSQL_PRINTF(ZSERR_MAIN, "Input connect timeout value is invalid: %s", argv[index]);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogsql_parse_conn_args(int32 argc, char *argv[], text_t *conn_text, text_t *cmd, ogsql_cmd_t *cmd_type)
{
    for (uint32 loop = 1; loop < (uint32)argc; ++loop) {
        if (conn_text->len + strlen(argv[loop]) + 1 > MAX_CMD_LEN) {
            OGSQL_PRINTF(ZSERR_MAIN, "Input is too long (> %d characters) - line ignored", MAX_CMD_LEN);
            return OG_ERROR;
        }

        if (cm_str_equal(argv[loop], "-c")) {
            *cmd_type = CMD_COMMAND;
        }

        if (cm_str_equal(argv[loop], "-f")) {
            *cmd_type = CMD_FILE;
        }

        if (cm_str_equal(argv[loop], "-s")) {
            *cmd_type = CMD_SILENT;
        }

        if (cm_str_equal(argv[loop], "-a")) {
            if (loop == 1) {
                return OG_ERROR;
            }
            g_local_config.print_on = OG_TRUE;
            continue;
        }

        if (cm_str_equal(argv[loop], "-q")) {
            if (loop == 1) {
                return OG_ERROR;
            }
            g_local_config.OGSQL_SSL_QUIET = OG_TRUE;
            continue;
        }

        if (cm_str_equal(argv[loop], "-w")) {
            if (loop == 1) {
                return OG_ERROR;
            }
            OG_RETURN_IFERR(ogsql_parse_timeout(argc, argv, ++loop));
            continue;
        }

        if (*cmd_type != CMD_NONE) {
            if (loop != argc - 2) {
                return OG_ERROR;
            }

            cm_str2text(argv[++loop], cmd);
            if (CM_IS_EMPTY(cmd)) {
                return OG_ERROR;
            }

            break;
        }

        OG_RETURN_IFERR(cm_concat_string(conn_text, MAX_CMD_LEN + 2, " "));
        OG_RETURN_IFERR(cm_concat_string(conn_text, MAX_CMD_LEN + 2, argv[loop]));
    }

    return OG_SUCCESS;
}

static status_t ogsql_clone_argv(const text_t *src, char **dest)
{
    status_t errcode;
    *dest = (char *)malloc(sizeof(char) * (src->len + 1));
    if (*dest == NULL) {
        return OG_ERROR;
    }

    errcode = strncpy_s(*dest, src->len + 1, src->str, src->len);
    if (errcode != EOK) {
        CM_FREE_PTR(*dest);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t ogsql_fetch_and_exec_connect(int32 argc, char *argv[])
{
    text_t conn_text = { .str = g_cmd_buf, .len = 0 }, cmd = { 0 };
    ogsql_cmd_t exter_cmd = CMD_NONE;
    status_t ret;
    char *cmd_str = NULL;

    OG_RETURN_IFERR(cm_concat_string(&conn_text, MAX_CMD_LEN + 2, "conn"));
    OG_RETURN_IFERR(ogsql_parse_conn_args(argc, argv, &conn_text, &cmd, &exter_cmd));

    if (exter_cmd == CMD_COMMAND) {
        OG_RETURN_IFERR(ogsql_clone_argv(&cmd, &cmd_str));
        cmd.str = cmd_str;
        ogsql_erase_string(argv[argc - 1]);
        argv[argc - 1][0] = '*';
    }
    
    ogsql_erase_argv_pwd(argv[1]);

    IS_WORKING = OG_TRUE;
    ret = ogsql_execute_cmd(exter_cmd, &conn_text, &cmd);
    IS_WORKING = OG_FALSE;
    (void)cm_text_set(&cmd, cmd.len, '\0');
    ogsql_erase_string(cmd_str);
    CM_FREE_PTR(cmd_str);
    return ret;
}

static EXTER_ATTACK status_t ogsql_process_args(int32 argc, char *argv[])
{
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "-version")) {
        ogsql_show_version();
        exit(EXIT_SUCCESS);
    }

    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "-help")) {
        ogsql_show_help();
        exit(EXIT_SUCCESS);
    }

    if (argc > OGSQL_MAX_PARAMETER_CNT) {
        ogsql_printf("The current number of ogsql parameters is exceeds %u\n", OGSQL_MAX_PARAMETER_CNT);
        ogsql_show_help();
        exit(EXIT_FAILURE);
    }

    return ogsql_fetch_and_exec_connect(argc, argv);
}

#ifndef WIN32
static void ogsql_handle_sigint(int32 signo)
{
    if (IS_CONN && IS_WORKING) {
        (void)ogsql_cancel();
    }
}
#else

BOOL ogsql_handle_sigint(DWORD fdwCtrlType)
{
    if (IS_CONN && IS_WORKING) {
        if (fdwCtrlType == CTRL_C_EVENT) {
            (void)ogsql_cancel();
        }
    }

    return TRUE;
}
#endif

int32 main(int32 argc, char *argv[])
{
    SET_UNHANDLED_EXECEPTION_FILTER("ogsql");

    cm_init_error_handler(cm_set_clt_error);

    OG_RETURN_IFERR(cm_regist_signal(SIGQUIT, SIG_IGN));
#ifndef WIN32
    OG_RETURN_IFERR(cm_regist_signal(SIGINT, ogsql_handle_sigint));
#else
    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ogsql_handle_sigint, TRUE)) {
        return OG_ERROR;
    }
#endif

    ogsql_init(argc, argv);

    if (argc > 1) {
        if (ogsql_process_args(argc, argv) != OG_SUCCESS) {
            ogsql_show_usage();
            exit(EXIT_FAILURE);
        }
    }

    /* run OGSQL from standard input stream */
    ogsql_run(stdin, OG_FALSE, g_cmd_buf, sizeof(g_cmd_buf));
    ogsql_free_config();
    ogsql_exit(OG_FALSE, 0);
}
