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
 * dcl_database_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/dcl_database_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCL_DB_PARSER_H__
#define __DCL_DB_PARSER_H__

#include "ogsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_backup(sql_stmt_t *stmt);
status_t sql_parse_restore(sql_stmt_t *stmt);
status_t sql_parse_recover(sql_stmt_t *stmt);
status_t sql_parse_shutdown(sql_stmt_t *stmt);
status_t sql_parse_backup_tag(sql_stmt_t *stmt, word_t *word, char *tag);
status_t sql_parse_ograc(sql_stmt_t *stmt);
status_t sql_parse_backup_arch_from(sql_stmt_t *stmt, knl_backup_t *param);
status_t sql_check_backup_param(sql_stmt_t *stmt, knl_backup_t *param);

status_t sql_parse_restore_from_bison(sql_stmt_t *stmt,
    char *str, source_location_t loc, knl_restore_t *param, bool32 block_recover);
status_t sql_parse_restore_blockrecover_bison(sql_stmt_t *stmt, int32 file, int32 page, knl_restore_t *param);

typedef enum backup_opt_type {
    BACKUP_FORMAT_OPT,
    BACKUP_AS_OPT,
    BACKUP_TAG_OPT,
    BACKUP_BUFFER_OPT,
    BACKUP_FULL_OPT,
    BACKUP_PARALLELISM_OPT,
    BACKUP_SECTION_OPT,
    BACKUP_EXCLUDE_OPT,
    BACKUP_PASSWORD_OPT,
    BACKUP_COPY_OPT,
    BACKUP_PREPARE_OPT,
    BACKUP_INCREMENTAL_OPT,
    BACKUP_FINISH_OPT,
    BACKUP_CUMULATIVE_OPT,
    BACKUP_SKIP_BADBLOCK_OPT,
    BACKUP_DISCONNET_OPT,
    BACKUP_TABLESPACE_OPT,
    BACKUP_REPAIR_OPT,
    BACKUP_COMPRESS_OPT,
    BACKUP_INCREMENTAL_NO_LEVEL_OPT
} backup_opt_type;

typedef struct backup_opt {
    backup_opt_type type;
    source_location_t loc;
    union {
        char *dest_format;
        struct {
            int32 compress_algo;
            int32 compress_level;
        };
        char *tag;
        char *passwd;
        char *space_name; /* for BACKUP_TABLESPACE_OPT */
        char *repair_type;
        int64 size;
        uint64 scn;
        uint32 parallelism;
        int32 incremental_level;
        galist_t *space_list; /* for BACKUP_COPY_OPT */
    };
} backup_opt;

status_t og_parse_backup_buffer(sql_stmt_t *stmt, uint32 *buffer_size, backup_opt *opt);
status_t og_parse_backup_archivelog(sql_stmt_t *stmt, knl_backup_t *param, galist_t *backup_opts);
status_t og_parse_backup_database(sql_stmt_t *stmt, knl_backup_t *param, galist_t *backup_opts);
status_t og_parse_restore(sql_stmt_t *stmt, knl_restore_t *param, galist_t *backup_opts, source_location_t loc);
status_t og_parse_build(sql_stmt_t *stmt, knl_build_def_t *param, galist_t *backup_opts);
status_t sql_parse_table_defs_bison(sql_stmt_t *stmt, lock_tables_def_t *def, galist_t *table_list);

#ifdef __cplusplus
}
#endif

#endif
