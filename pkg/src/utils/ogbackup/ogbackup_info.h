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
 * ogbackup_info.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_info.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_INFO_H
#define OGRACDB_OGBACKUP_INFO_H

#include "cm_defs.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define OGBAK_CMD_NAME_LENGTH  16
#define OGBAK_ARG_BACKUP  "--backup"
#define OGBAK_ARG_PREPARE  "--prepare"
#define OGBAK_ARG_DECOMPRESS "--decompress"
#define OGBAK_ARG_REMOVE_ORIGINAL "--remove-original"
#define OGBAK_ARG_ARCHIVELOG "--archivelog"
#define OGBAK_ARG_QUERY_INCREMENTAL_MODE "--query-incremental-mode"
#define OGBAK_ARG_PURGE_LOGS "--purge-logs"

#define OGBAK_PARSE_OPTION_COMMON 0
#define OGBAK_PARSE_OPTION_ERR (-1)

// long options for ogbackup
#define OGBAK_LONG_OPTION_BACKUP "backup"
#define OGBAK_LONG_OPTION_PREPARE "prepare"
#define OGBAK_LONG_OPTION_ARCHIVELOG "archivelog"
#define OGBAK_LONG_OPTION_QUERY "query-incremental-mode"
#define OGBAK_LONG_OPTION_PURGE_LOGS "purge-logs"
#define OGBAK_LONG_OPTION_TARGET_DIR "target-dir"
#define OGBAK_LONG_OPTION_DEFAULTS_FILE "defaults-file"
#define OGBAK_LONG_OPTION_SOCKET "socket"
#define OGBAK_LONG_OPTION_DATA_DIR "datadir"
#define OGBAK_LONG_OPTION_INCREMENTAL "incremental"
#define OGBAK_LONG_OPTION_INCREMENTAL_CUMULATIVE "cumulative"
#define OGBAK_LONG_OPTION_PARALLEL "parallel"
#define OGBAK_LONG_OPTION_COMPRESS "compress"
#define OGBAK_LONG_OPTION_DECOMPRESS "decompress"
#define OGBAK_LONG_OPTION_BUFFER "buffer"
#define OGBAK_LONG_OPTION_DATABASESEXCLUDE "databases-exclude"
#define OGBAK_LONG_OPTION_PITR_TIME "pitr-time"
#define OGBAK_LONG_OPTION_PITR_SCN "pitr-scn"
#define OGBAK_LONG_OPTION_PITR_CANCEL "until-cancel"
#define OGBAK_LONG_OPTION_PITR_RESTORE "restore"
#define OGBAK_LONG_OPTION_PITR_RECOVER "recover"
#define OGBAK_LONG_OPTION_LRP_LSN "lrp-lsn"
#define OGBAK_LONG_OPTION_FORCE "force"
#define OGBAK_LONG_OPTION_FORCE_DDL "force-ddl"
#define OGBAK_LONG_OPTION_SKIP_BADBLOCK "skip-badblock"
#define OGBAK_LONG_OPTION_REPAIR_TYPE "repair-type"
// long options
#define OGBAK_LONG_OPTION_USER "user"
#define OGBAK_LONG_OPTION_PASSWORD "password"
#define OGBAK_LONG_OPTION_HOST "host"
#define OGBAK_LONG_OPTION_PORT "port"
#define OGBAK_LONG_OPTION_EXEC "execute"

// short options
#define OGBAK_SHORT_OPTION_UNRECOGNIZED '?'
#define OGBAK_SHORT_OPTION_NO_ARG ':'
#define OGBAK_SHORT_OPTION_USER 'u'
#define OGBAK_SHORT_OPTION_PASSWORD 'p'
#define OGBAK_SHORT_OPTION_HOST 'h'
#define OGBAK_SHORT_OPTION_PORT 'P'
#define OGBAK_SHORT_OPTION_TARGET_DIR 't'
#define OGBAK_SHORT_OPTION_DEFAULTS_FILE 'd'
#define OGBAK_SHORT_OPTION_SOCKET 's'
#define OGBAK_SHORT_OPTION_EXEC 'e'
#define OGBAK_SHORT_OPTION_DATA_DIR 'D'
#define OGBAK_SHORT_OPTION_INCREMENTAL 'i'
#define OGBAK_SHORT_OPTION_INCREMENTAL_CUMULATIVE 'j'
#define OGBAK_SHORT_OPTION_PARALLEL 'L'
#define OGBAK_SHORT_OPTION_COMPRESS 'c'
#define OGBAK_SHORT_OPTION_DECOMPRESS 'E'
#define OGBAK_SHORT_OPTION_DATABASES_EXCLUDE 'x'
#define OGBAK_SHORT_OPTION_BUFFER 'b'
#define OGBAK_SHORT_OPTION_PITR_TIME 'T'
#define OGBAK_SHORT_OPTION_PITR_SCN 'S'
#define OGBAK_SHORT_OPTION_PITR_CANCEL 'C'
#define OGBAK_SHORT_OPTION_PITR_RESTORE 'r'
#define OGBAK_SHORT_OPTION_PITR_RECOVER 'R'
#define OGBAK_SHORT_OPTION_LRP_LSN 'l'
#define OGBAK_SHORT_OPTION_FORCE 'f'
#define OGBAK_SHORT_OPTION_FORCE_DDL 'F'
#define OGBAK_SHORT_OPTION_SKIP_BADBLOCK 'k'
#define OGBAK_SHORT_OPTION_REPAIR_TYPE 'a'

typedef enum en_ogbak_topic {
    OGBAK_INVALID,
    OGBAK_VERSION,
    OGBAK_HELP,
    OGBAK_BACKUP,
    OGBAK_PREPARE,
    OGBAK_ARCHIVE_LOG,
    OGBAK_QUERY_INCREMENTAL_MODE,
    OGBAK_PURGE_LOGS,
} ogbak_topic_t;

typedef struct ogbak_param {
    text_t host;
    text_t user;
    SENSI_INFO text_t password;
    text_t port;
    text_t target_dir;
    text_t defaults_file;
    text_t socket;
    text_t execute;
    text_t data_dir;
    text_t parallelism;
    text_t pitr_time;
    text_t pitr_scn;
    text_t compress_algo;
    text_t buffer_size;
    text_t repair_type;
    text_t databases_exclude;
    uint8  is_decompress;
    uint8  is_pitr_cancel;
    uint8  is_restore;
    uint8  is_recover;
    uint8  is_incremental;
    uint8  is_incremental_cumulative;
    uint8  is_get_lrp;
    uint8  is_force_archive;
    uint8  is_force_ddl;
    uint8  skip_badblock;
} ogbak_param_t;

typedef status_t (* ogbak_execute_t)(ogbak_param_t* ogbak_param);

typedef status_t (* ogbak_parse_args_t)(int32 argc, char** argv, ogbak_param_t* ogbak_param);

typedef struct ogbak_cmd {
    ogbak_topic_t ogbak_topic;
    const char* cmd_name;
    ogbak_execute_t do_exec;
    ogbak_parse_args_t parse_args;
    ogbak_param_t* ogbak_param;
} ogbak_cmd_t;

#ifdef __cplusplus
}
#endif

#endif // OGRACDB_OGBACKUP_INFO_H
