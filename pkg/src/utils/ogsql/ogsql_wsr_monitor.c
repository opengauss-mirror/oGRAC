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
 * ogsql_wsr_monitor.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogsql/ogsql_wsr_monitor.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_wsr_head.h"
#include "ogsql_wsr_monitor.h"

#define OG_MONITOR_LINE_LEN                  (uint32)1000
#define OG_MONITOR_TIME_CONVERT              (uint32)1000
#define OG_MONITOR_DEFAULT_TIMES             (uint32)100

typedef enum {
    EMONITOR_TIMES,
    EMONITOR_FILE,
    EMONITOR_TYPE,
    EMONITOR_INTERVAL
} monitor_item_t;

static const word_record_t g_monitor_records[] = {
    { .id = EMONITOR_TIMES,
      .tuple = { 1, { "TIMES" } }
    },
    { .id = EMONITOR_FILE,
      .tuple = { 1, { "FILE" } }
    },
    { .id = EMONITOR_TYPE,
      .tuple = { 1, { "TYPE" } }
    },
    { .id = EMONITOR_INTERVAL,
      .tuple = { 1, { "INTERVAL" } }
    },
};

#define MONITOR_OPT_SIZE ELEMENT_COUNT(g_monitor_records)

typedef enum {
    MONITOR_ALL = 0,
    MONITOR_HOST,
    MONITOR_SESSION,
    MONITOR_MEMORY,
    MONITOR_APP,
    MONITOR_SYNC,
    MONITOR_TABLESPACE,
    MONITOR_EVENT
} export_type_t;

typedef struct st_monitor_options {
    uint32 times;
    char dump_file[OG_MAX_FILE_PATH_LENGH];
    uint32 type;
    uint32 interval;
} monitor_options_t;

static FILE *g_monitor_logfile = (FILE *)NULL;

#define monitor_log(fmt, ...)                               \
    do {                                                \
        ogsql_printf(fmt, ##__VA_ARGS__);                \
        if (g_monitor_logfile != NULL) {                    \
            fprintf(g_monitor_logfile, fmt, ##__VA_ARGS__); \
        }                                               \
    } while (0)

static void ogsql_display_wsr_monitor_host(void)
{
    ogsql_printf("                        1: Host\n");
    ogsql_printf("                            %%user: %s\n", g_wsritemdesc[WSR_ITEM_CPU_USER]);
    ogsql_printf("                            %%system: %s\n", g_wsritemdesc[WSR_ITEM_CPU_SYSTEM]);
    ogsql_printf("                            %%iowait: %s\n", g_wsritemdesc[WSR_ITEM_IOWAIT]);
    ogsql_printf("                            %%idle: %s\n", g_wsritemdesc[WSR_ITEM_IDLE]);
}

static void ogsql_display_wsr_monitor_session(void)
{
    ogsql_printf("                        2: Session & Transaction\n");
    ogsql_printf("                            Sessions: %s\n", g_wsritemdesc[WSR_ITEM_SESSIONS]);
    ogsql_printf("                            ActiveSess: %s\n", g_wsritemdesc[WSR_ITEM_ACTIVE_SESSIONS]);
    ogsql_printf("                            Trans: %s\n", g_wsritemdesc[WSR_ITEM_TRANSACTIONS]);
    ogsql_printf("                            LongSQL: %s\n", g_wsritemdesc[WSR_ITEM_LONG_SQL]);
    ogsql_printf("                            LongTrans: %s\n", g_wsritemdesc[WSR_ITEM_LONG_TRANS]);
}

static void ogsql_display_wsr_monitor_memory(void)
{
    ogsql_printf("                        3. Memory\n");
    ogsql_printf("                            DataDirty :%s\n", g_wsritemdesc[WSR_ITEM_DIRTY_DATA]);
    ogsql_printf("                            DataPin: %s\n", g_wsritemdesc[WSR_ITEM_PIN_DATA]);
    ogsql_printf("                            DataFree: %s\n", g_wsritemdesc[WSR_ITEM_FREE_DATA]);
    ogsql_printf("                            TempFree: %s\n", g_wsritemdesc[WSR_ITEM_FREE_TEMP]);
    ogsql_printf("                            TempHWM: %s\n", g_wsritemdesc[WSR_ITEM_TEMP_HWM]);
    ogsql_printf("                            TempSwap: %s\n", g_wsritemdesc[WSR_ITEM_TEMP_SWAP]);
}

static void ogsql_display_wsr_monitor_performance(void)
{
    ogsql_printf("                        4. Performance\n");
    ogsql_printf("                            Physical: %s\n", g_wsritemdesc[WSR_ITEM_PHYSICAL_READ]);
    ogsql_printf("                            Logical: %s\n", g_wsritemdesc[WSR_ITEM_LOGICAL_READ]);
    ogsql_printf("                            Commit: %s\n", g_wsritemdesc[WSR_ITEM_COMMITS]);
    ogsql_printf("                            Rollback: %s\n", g_wsritemdesc[WSR_ITEM_ROLLBACKS]);
    ogsql_printf("                            RedoSize: %s\n", g_wsritemdesc[WSR_ITEM_REDO_SIZE]);
    ogsql_printf("                            Execute: %s\n", g_wsritemdesc[WSR_ITEM_EXECUTIONS]);
    ogsql_printf("                            Fetch: %s\n", g_wsritemdesc[WSR_ITEM_FETCHS]);
    ogsql_printf("                            Login: %s\n", g_wsritemdesc[WSR_ITEM_LOGINS]);
    ogsql_printf("                            HardParse: %s\n", g_wsritemdesc[WSR_ITEM_HARD_PARSES]);
    ogsql_printf("                            DBWRPages: %s\n", g_wsritemdesc[WSR_ITEM_DBWR_PAGES]);
    ogsql_printf("                            DBWRTIME: %s\n", g_wsritemdesc[WSR_ITEM_DBWR_TIME]);
}

static void ogsql_display_wsr_monitor_sync(void)
{
    ogsql_printf("                        5. SYNC\n");
    ogsql_printf("                            MinLog: %s\n", g_wsritemdesc[WSR_ITEM_MIN_REDO_SYNC]);
    ogsql_printf("                            MinSyReply: %s\n", g_wsritemdesc[WSR_ITEM_MIN_REDO_REPLY]);
    ogsql_printf("                            MaxLog: %s\n", g_wsritemdesc[WSR_ITEM_MAX_REDO_SYNC]);
    ogsql_printf("                            MaxSyReply: %s\n", g_wsritemdesc[WSR_ITEM_MAX_REDO_REPLY]);
    ogsql_printf("                            MinLgReply: %s\n", g_wsritemdesc[WSR_ITEM_MIN_LOGICAL_DELAY]);
    ogsql_printf("                            MaxLgReply: %s\n", g_wsritemdesc[WSR_ITEM_MAX_LOGICAL_DELAY]);
}

static void ogsql_display_wsr_monitor_tablespace(void)
{
    ogsql_printf("                        6. Tablespace\n");
    ogsql_printf("                            TXN_Pages: %s\n", g_wsritemdesc[WSR_ITEM_TXN_PAGES]);
    ogsql_printf("                            Undo_Pages: %s\n", g_wsritemdesc[WSR_ITEM_UNDO_PAGES]);
    ogsql_printf("                            System: %s\n", g_wsritemdesc[WSR_ITEM_SYSTEM_TABLESPACE]);
    ogsql_printf("                            Sysaux: %s\n", g_wsritemdesc[WSR_ITEM_SYSAUX_TABLESPACE]);
    ogsql_printf("                            Users: %s\n", g_wsritemdesc[WSR_ITEM_USER_TABLESPACE]);
    ogsql_printf("                            ArchLogs: %s\n", g_wsritemdesc[WSR_ITEM_ARCH_LOGS]);
}

static void ogsql_display_wsr_monitor_event(void)
{
    ogsql_printf("                        7. Event\n");
    ogsql_printf("                            Latch_Data: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_LATCH_DATA]);
    ogsql_printf("                            FileSync: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_FILE_SYNC]);
    ogsql_printf("                            BusyWaits: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_BUFFER_BUSY]);
    ogsql_printf("                            TXRowLock: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_TX_LOCK]);
    ogsql_printf("                            Scattered: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_SCATTER_READ]);
    ogsql_printf("                            Sequential: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_SEQ_READ]);
    ogsql_printf("                            ReadOther: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_READ_BY_OTHER]);
    ogsql_printf("                            ArchNeeded: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_ARCH_NEEDED]);
    ogsql_printf("                            AdLock: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_ADVISE_LOCK]);
    ogsql_printf("                            TableSLock: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_TABLE_S_LOCK]);
    ogsql_printf("                            SwitchIn: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_REDO_SWITCH]);
    ogsql_printf("                            ITL_Enq: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_ITL_ENQ]);
}

static void ogsql_display_wsr_monitor_h(void)
{
    ogsql_printf("The syntax of monitor is: \n\n");
    ogsql_printf("     Format:  monitor [KEYWORD=value]\n");
    ogsql_printf("     Example: monitor\n");
    ogsql_printf("              or monitor type=2\n");
    ogsql_printf("              or monitor file=""abc.txt"" type=3\n\n");
    ogsql_printf("Keyword                 Description (Default)\n");
    ogsql_printf("------------------------------------------------------------------------------------------"
        "---------------------------------\n");
    ogsql_printf("FILE                    Log file of screen output, using double quotes.\n");
    ogsql_printf("TYPE                    Data type, default is 0.\n");
    ogsql_printf("                        0: ALL\n");
    
    ogsql_display_wsr_monitor_host();
    ogsql_display_wsr_monitor_session();
    ogsql_display_wsr_monitor_memory();
    ogsql_display_wsr_monitor_performance();
    ogsql_display_wsr_monitor_sync();
    ogsql_display_wsr_monitor_tablespace();
    ogsql_display_wsr_monitor_event();

    ogsql_printf("TIMES                   Times to loop, default is 50.\n");
    ogsql_printf("INTERVAL                Query and print interval. The default value is the same as that of the "
        "WSR$CREATE_SESSION_SNAPSHOT task.\n\n");
    ogsql_printf("Note: To change the data generation interval, call WSR$MODIFY_SETTING interface using SYS.\n");
    ogsql_printf("      For example, change the interval to 5s:\n");
    ogsql_printf("          call WSR$MODIFY_SETTING(I_IN_SESSION_INTERVAL => 5); \n");
    ogsql_printf("\n");
}

static int monitor_parse_opts_file(lex_t *lex, monitor_options_t *monitor_opts)
{
    word_t word;

    if (lex_expected_fetch_dqstring(lex, &word) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for FILE!");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str(&word.text.value, monitor_opts->dump_file, OG_MAX_FILE_PATH_LENGH));

    char path[OG_MAX_FILE_PATH_LENGH] = { 0x00 };
    char file_name[OG_MAX_FILE_PATH_LENGH] = { 0x00 };
    cm_trim_filename(monitor_opts->dump_file, OG_MAX_FILE_PATH_LENGH, path);
    cm_trim_dir(monitor_opts->dump_file, sizeof(file_name), file_name);
    if (strlen(path) != strlen(monitor_opts->dump_file) && !cm_dir_exist((const char *)path)) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_PATH_NOT_EXIST, "File path not exists!");
        return OG_ERROR;
    } else if (file_name[0] == '\0') {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_CLT_INVALID_ATTR, "Wrong file name!");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(realpath_file(monitor_opts->dump_file, path, OG_MAX_FILE_PATH_LENGH));

    if (cm_fopen(path, "w+", FILE_PERM_OF_DATA, &g_monitor_logfile) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static int monitor_parse_opts(lex_t *lex, monitor_options_t *monitor_opts)
{
    uint32 matched_id;

    g_monitor_logfile = NULL;

    while (!lex_eof(lex)) {
        OG_RETURN_IFERR(lex_try_match_records(lex, g_monitor_records, MONITOR_OPT_SIZE, (uint32 *)&matched_id));

        if (matched_id == OG_INVALID_ID32) {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invaid input!");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "="));

        switch (matched_id) {
            case EMONITOR_TIMES:
                OG_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(monitor_opts->times)));
                break;

            case EMONITOR_FILE:

                OG_RETURN_IFERR(monitor_parse_opts_file(lex, monitor_opts));
                break;

            case EMONITOR_TYPE:
                OG_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(monitor_opts->type)));
                if (monitor_opts->type > MONITOR_EVENT) {
                    OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "type should between 0 and 7.");
                    return OG_ERROR;
                }

                break;

            case EMONITOR_INTERVAL:
                OG_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(monitor_opts->interval)));
                break;

            default:
                break;
        }
        OG_RETURN_IFERR(lex_skip_comments(lex, NULL));
    }

    return lex_expected_end(lex);
}

static status_t monitor_get_head(monitor_options_t *monitor_opts, char* data_head)
{
    char host[OG_MONITOR_LINE_LEN] = "        %%user      %%system      %%iowait        %%idle";
    char session[OG_MONITOR_LINE_LEN] = "     Sessions   ActiveSess        Trans      LongSQL    LongTrans";
    char memory[OG_MONITOR_LINE_LEN] = "    DataDirty      DataPin     DataFree     TempFree      TempHWM     TempSwap";
    char app[OG_MONITOR_LINE_LEN] = "     Physical      Logical       Commit     Rollback     RedoSize      Execute"
        "        Fetch        Login    HardParse    DBWRPages     DBWRTime";
    char sync[OG_MONITOR_LINE_LEN] = "       MinLog   MinSyReply       MaxLog   MaxSyReply             MinLgReply             MaxLgReply";
    char tablespace[OG_MONITOR_LINE_LEN] = "    TXN_Pages   Undo_Pages       System       Sysaux        Users     "
        "ArchLogs";
    char event[OG_MONITOR_LINE_LEN] = "   Latch_Data     FileSync    BusyWaits    TXRowLock    Scattered   Sequential"
        "    ReadOther   ArchNeeded       AdLock   TableSLock     SwitchIn      ITL_Enq";

    MEMS_RETURN_IFERR(strcpy_s(data_head, OG_MONITOR_LINE_LEN, "SNAP_TIME"));

    switch (monitor_opts->type) {
        case MONITOR_HOST:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, host));
            break;
        case MONITOR_SESSION:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, session));
            break;
        case MONITOR_MEMORY:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, memory));
            break;
        case MONITOR_APP:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, app));
            break;
        case MONITOR_SYNC:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, sync));
            break;
        case MONITOR_TABLESPACE:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, tablespace));
            break;
        case MONITOR_EVENT:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, event));
            break;
        default:
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, host));
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, session));
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, memory));
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, app));
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, sync));
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, tablespace));
            MEMS_RETURN_IFERR(strcat_s(data_head, OG_MONITOR_LINE_LEN, event));
            break;
    }

    return OG_SUCCESS;
}

static status_t monitor_get_interval(monitor_options_t *monitor_opts)
{
    ogconn_stmt_t resultset;
    uint32 rows;
    uint32 *data = NULL;
    char cmd_buf[MAX_CMD_LEN + 1];
    bool32 is_null = OG_FALSE;
    uint32 size;

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$GETINTERVAL"));

    if (ogconn_prepare(STMT, (const char *)cmd_buf) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    }

    if (ogconn_execute(STMT) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(ogconn_get_implicit_resultset(STMT, &resultset));
    OG_RETURN_IFERR(ogconn_fetch(resultset, &rows));

    if (rows == 0) {
        return OG_ERROR;
    }

    if (ogconn_get_column_by_id(resultset, 0, (void **)&data, &size, &is_null) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    } else {
        monitor_opts->interval = is_null ? 0 : *data;
    }
    
    return OG_SUCCESS;
}

static void monitor_close_logger(void)
{
    if (g_monitor_logfile != NULL) {
        fclose(g_monitor_logfile);
        g_monitor_logfile = NULL;
    }
}

static status_t monitor_print_content(monitor_options_t *monitor_opts, char* data_head)
{
    char content[OG_MONITOR_LINE_LEN];
    ogconn_stmt_t resultset;
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$GETCONTENT(%u)", monitor_opts->type));

    if (ogconn_prepare(STMT, (const char *)cmd_buf) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    }

    if (ogconn_execute(STMT) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(ogconn_get_implicit_resultset(STMT, &resultset));
    OG_RETURN_IFERR(ogconn_fetch(resultset, &rows));
    
    if (rows == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(ogconn_column_as_string(resultset, 0, content, OG_MONITOR_LINE_LEN));

    monitor_log(data_head);
    monitor_log("\n");
    monitor_log(content);
    monitor_log("\n\n");
    return OG_SUCCESS;
}

static status_t ogsql_monitor_deal(monitor_options_t* monitor_opts)
{
    char head[OG_MONITOR_LINE_LEN] = {'\0'};
    OG_RETURN_IFERR(monitor_get_head(monitor_opts, (char *)head));

    if (monitor_opts->interval == 0) {
        OG_RETURN_IFERR(monitor_get_interval(monitor_opts));
    }

    for (uint32 i = 0; i < monitor_opts->times; i++) {
        if (i != 0) {
            cm_sleep(monitor_opts->interval * OG_MONITOR_TIME_CONVERT);
        }
        OG_RETURN_IFERR(monitor_print_content(monitor_opts, (char *)head));
    }

    monitor_close_logger();
    return OGCONN_SUCCESS;
}

status_t ogsql_monitor(text_t *cmd_text)
{
    uint32 matched_id;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    
    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    lex_init_keywords();

    monitor_options_t monitor_opts = {
        .times = OG_MONITOR_DEFAULT_TIMES,
        .dump_file = "\0",
        .type = MONITOR_ALL,
        .interval = 0,
    };

    if (lex_try_fetch_1ofn(&lex, &matched_id, 3, "help", "usage", "option") != OG_SUCCESS) {
        ogsql_print_error(NULL);
        return OG_ERROR;
    }

    if (matched_id != OG_INVALID_ID32) {
        ogsql_display_wsr_monitor_h();
        return OG_SUCCESS;
    }
    
    if (monitor_parse_opts(&lex, &monitor_opts) != OG_SUCCESS) {
        ogsql_print_error(CONN);
        return OG_ERROR;
    }

    return ogsql_monitor_deal(&monitor_opts);
}