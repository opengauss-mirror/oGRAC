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
 * ddl_space_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_space_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_SPACE_PARSER_H__
#define __DDL_SPACE_PARSER_H__

#include "cm_defs.h"
#include "ogsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum alterts_opt_type {
    ALTERTS_ADD_DATAFILE_OPT,
    ALTERTS_DROP_DATAFILE_OPT,
    ALTERTS_AUTOEXTEND_OFF_OPT,
    ALTERTS_AUTOEXTEND_ON_OPT,
    ALTERTS_AUTOOFFLINE_OPT,
    ALTERTS_RENAME_OPT,
    ALTERTS_RENAME_DATAFILE_OPT,
    ALTERTS_OFFLINE_DATAFILE_OPT,
    ALTERTS_AUTOPURGE_OPT,
    ALTERTS_SHRINK_SPACE_OPT,
    ALTERTS_PUNCH_OPT
} alterts_opt_type;

typedef struct alterts_opt {
    alterts_opt_type type;
    union {
        galist_t *datafiles;       /* for ADD DATAFILE */
        struct {
            int64 next_size;       /* for AUTOEXTEND ON */
            int64 max_size;
        } autoextend;
        bool on_off;               /* for AUTOOFFLINE, AUTOPURGE */
        char *new_name; /* for RENAME TO */
        struct {
            galist_t *old_files;   /* for RENAME DATAFILE */
            galist_t *new_files;
        } rename_datafiles;
        int64 size;
    };
} alterts_opt;

status_t sql_parse_datafile(sql_stmt_t *stmt, knl_device_def_t *dev_def, word_t *word, bool32 *isRelative);
status_t sql_parse_autoextend_clause_core(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def,
    word_t *next_word);

status_t sql_parse_create_space(sql_stmt_t *stmt, bool32 is_temp, bool32 is_undo);
status_t sql_parse_create_undo_space(sql_stmt_t *stmt);
status_t sql_parse_alter_space(sql_stmt_t *stmt);
status_t sql_parse_drop_tablespace(sql_stmt_t *stmt);
status_t sql_parse_purge_tablespace(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_create_ctrlfiles(sql_stmt_t *stmt);
status_t og_parse_create_space(sql_stmt_t *stmt, knl_space_def_t **ts_def, bool is_undo, char *space_name,
    uint32 extentsize, galist_t *datafiles, galist_t *ts_opts);
status_t og_parse_create_ctrlfile(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t **def, galist_t *ctrlfile_opts);
status_t og_parse_alter_tablespace(sql_stmt_t *stmt, knl_altspace_def_t **def, bool32 is_for_create_db,
    char *tablespace_name, alterts_opt *opt, int64 segments_num);
#ifdef __cplusplus
}
#endif

#endif
