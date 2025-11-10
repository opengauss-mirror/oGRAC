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
 * ogbackup_common.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_COMMON_H
#define OGRACDB_OGBACKUP_COMMON_H

#include "dirent.h"
#include "cm_defs.h"
#include "cm_file.h"
#include "ogbackup_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OGBACKUP_MAX_PARAMETER_CNT   (uint32)16
#define OGSQL_MAX_PARAMETER_CNT   (uint32)3

// Parent directory to store the backup files
#define TARGET_DIR_PARAM_OPTION "--target-dir="
#define PARALLEL_PARAM_OPTION "--parallel="
#define COMPRESS_ALGO_OPTION "--compress="
#define DATABASESEXCLUDE_PARAM_OPTION "--databases-exclude="
#define OGBAK_SHORT_OPTION_EXP "u:p:P:h"
#define START_INDEX_FOR_PARSE_PARAM 1
#define OGSQL_STATEMENT_INDEX 4
#define SKIP_LOCK_DDL "--skip-lock-ddl"
#define FORCE_DDL_IGNORE_ERROR "--force"
#define SKIP_BADBLOCK "--skip-badblock"
#define REPAIR_TYPE "--repair-type="
// LEVEL 0 indicates the baseline incremental backup, equals full backup
#define OGSQL_FULL_BACKUP_STATEMENT_PREFIX "BACKUP DATABASE INCREMENTAL LEVEL 0 FORMAT \'"
#define OGSQL_INCREMENT_BACKUP_STATEMENT_PREFIX "BACKUP DATABASE INCREMENTAL LEVEL 1 FORMAT \'"
#define OGSQL_INCREMENT_CUMULATIVE_BACKUP_STATEMENT_PREFIX "BACKUP DATABASE INCREMENTAL LEVEL 1 CUMULATIVE FORMAT \'"
#define OGSQL_STATEMENT_QUOTE "\'"
#define OGSQL_PARALLELISM_OPTION " PARALLELISM "
#define OGSQL_BUFFER_OPTION " BUFFER SIZE "
#define OGSQL_COMPRESS_OPTION_PREFIX " as "
#define OGSQL_COMPRESS_OPTION_SUFFIX " compressed backupset "
#define OGSQL_STATEMENT_END_CHARACTER ";"
#define OGSQL_EXCLUDE_OPTION " EXCLUDE FOR TABLESPACE "
#define OGSQL_EXCLUDE_SUFFIX "_DB"
#define OGSQL_SKIP_BADBLOCK " SKIP BADBLOCK"
// TARGET_DIR_PARAM_OPTION's next level dir, for store oGRAC backup files
#define OGRAC_BACKUP_DIR "/oGRAC"
#define OGRAC_BACKUP_BACKUPSET "/backupset"
#define DECRYPT_CMD_ECHO "echo "
#define DECRYPT_CMD_BASE64 " | openssl base64 -d"
#define OGRAC_BACKUP_FILE_LENGTH 129
#define MAX_TARGET_DIR_LENGTH 120
#define MAX_PARALLELISM_COUNT 16
#define MAX_STATEMENT_LENGTH 512
#define MAX_DATABASE_LENGTH 2048
#define MAX_DATABASE_NAME_LENGTH 128
#define MAX_PASSWORD_LENGTH 1024
#define MAX_SHELL_CMD_LENGTH (MAX_PASSWORD_LENGTH + 512)

#define OGSQL_CHECK_CONN_MAX_TIME_S 300
#define OGSQL_CHECK_CONN_SLEEP_TIME_MS 1000

#define CHILD_ID 1
#define PARENT_ID 0
#define STD_IN_ID 0
#define STD_OUT_ID 1

// TRUE or FALSE
#define MAX_BOOL_STR_LENGTH 6
#define SINGLE_QUOTE "\'"

#define OGSQL_RESTORE_STATEMENT_PREFIX "RESTORE DATABASE FROM \'"
#define OGSQL_RESTORE_REPAIR_TYPE " REPAIR TYPE "
#define OGSQL_RESTORE_REPAIR_TYPE_RETURN_ERROR "RETURN_ERROR"
#define OGSQL_RESTORE_REPAIR_TYPE_REPLACE_CHECKUSM "REPLACE_CHECKSUM"
#define OGSQL_RESTORE_REPAIR_TYPE_DISCARD_BADBLOCK "DISCARD_BADBLOCK"
#define OGSQL_RESTORE_BAD_BLOCK_FILE "/backupset_bad_block_record"
#define OGSQL_RECOVER_STATEMENT_PREFIX "RECOVER DATABASE "
#define OGSQL_PITR_TIME_OPTION "UNTIL TIME \'"
#define OGSQL_PITR_SCN_OPTION "UNTIL SCN "
#define OGSQL_PITR_CANCEL_OPTION "UNTIL CANCEL "

#define OGSQL_ARCHIVELOG_STATEMENT_PREFIX "alter system switch logfile"
#define OGSQL_GET_LRP_LSN_STATEMENT "SELECT LRP_LSN FROM SYS_BACKUP_SETS"
#define OGSQL_RECOVER_RESET_LOG "ALTER DATABASE OPEN RESETLOGS"
#define OGSQL_PURGE_LOGS "ALTER DATABASE DELETE ARCHIVELOG ABNORMAL"

#define DEFAULT_SHELL "/bin/sh"
#define DEFAULT_OGSQL_PATH "/bin/ogsql"

#define START_OGRACD_SERVER_CMD "installdb.sh -P tempstartogracd"
#define CHECK_CANTAIND_STATUS_CMD "installdb.sh -P checkogracdstatus"
#define STOP_OGRACD_SERVER_CMD "installdb.sh -P stopogracd"
#define TRY_CONN_OGSQL_CMD "installdb.sh -P tryconnogsql"

#define OGSQL_QUERY_OGRAC_PARAMETERS "'SHOW PARAMETERS'"
#define SCN_MAX "18446744073709551615"

#define OGSQL_FILE_NAME_BUFFER_SIZE   OG_FILE_NAME_BUFFER_SIZE
#define OGSQL_CMD_BUFFER_SIZE         (OGSQL_FILE_NAME_BUFFER_SIZE + MAX_STATEMENT_LENGTH)
#define OGSQL_CMD_OUT_BUFFER_SIZE     (OG_MAX_CMD_LEN + 1)
#define OGSQL_CMD_IN_BUFFER_SIZE      (OG_MAX_CMD_LEN + 1)

#ifndef WIFEXITED
#define WIFEXITED(w)	(((w) & 0XFFFFFF00) == 0)
#define WIFSIGNALED(w)	(!WIFEXITED(w))
#define WEXITSTATUS(w)	(w)
#define WTERMSIG(w)		(w)
#endif // WIFEXITED

#define FREE_AND_RETURN_ERROR_IF_SNPRINTF_FAILED(ret, statement) \
    if ((ret) == -1) {                                           \
        CM_FREE_PTR(statement);                                  \
        return OG_ERROR;                                         \
    }

#define OGBAK_RETURN_ERROR_IF_NULL(ret) \
    do {                                \
        if ((ret) == NULL) {            \
            OG_LOG_DEBUG_INF("RETURN_IF_ERROR[%s,%d]", __FILE__, __LINE__); \
            return OG_ERROR;            \
        }                               \
    } while (0)

typedef enum en_ogbak_ogsql_exec_mode {
    OGBAK_OGSQL_EXECV_MODE,
    OGBAK_OGSQL_SHELL_MODE,
} ogbak_ogsql_exec_mode_t;

typedef struct ogbak_child_info {
    pid_t child_pid;
    int from_child;
    int to_child;
} ogbak_child_info_t;

status_t ogbak_system_call(char *path, char *params[], char *operation);

status_t ogbak_system_popen(char *path, char *params[], char *cmd_out, char* operation);

status_t ogbak_do_shell_background(text_t* command, int* child_pid, int exec_mode);

void free_system_call_params(char *params[], int start_index, int end_index);

void free_input_params(ogbak_param_t* ogbak_param);

status_t fill_params_for_ogsql_login(char *og_params[], int* param_index, ogbak_ogsql_exec_mode_t ogsql_exec_mode);

status_t ogbak_parse_single_arg(char *optarg_local, text_t *ogbak_param_option);

status_t check_pitr_params(ogbak_param_t* ogbak_param);

status_t check_common_params(ogbak_param_t* ogbak_param);

status_t start_ogracd_server(void);

status_t check_ogracd_status(void);

status_t stop_ogracd_server(void);

status_t get_ogsql_binary_path(char** ogsql_binary_path);

status_t check_ogsql_online(void);

status_t check_input_params(char *params);

status_t ogbak_check_ogsql_online(uint32 retry_time);

status_t ogbak_check_data_dir(const char *path);

status_t ogbak_clear_data_dir(const char *sub_path, const char *src_path);

status_t ogbak_change_work_dir(const char *path);

status_t ogbak_get_ogsql_output_by_shell(char *ogsql_cmd[], char *cmd_out);

status_t ogbak_check_dir_access(const char *path);

status_t ogbak_do_shell_get_output(text_t *command, char *cmd_out,
    status_t (*ogback_read_output_from_pipe_fun)(ogbak_child_info_t, char*));

status_t get_cfg_ini_file_name(char *ogsql_ini_file_name, char *oGRACd_ini_file_path);

#ifdef __cplusplus
}
#endif

#endif // OGRACDB_OGBACKUP_COMMON_H