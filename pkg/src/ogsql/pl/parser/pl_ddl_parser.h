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
 * pl_ddl_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/pl_ddl_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_DDL_PARSER_H__
#define __PL_DDL_PARSER_H__

#include "ogsql_stmt.h"
#include "scanner.h"
#include "expr_parser.h"
#include "pl_trigger.h"

typedef struct st_pl_bison_trigger_def {
    trigger_type_t type;
    uint16 events;
    galist_t *columns;
    name_with_owner *table_name;
    text_t *body;
    source_location_t trigger_loc;
    source_location_t table_loc;
    source_location_t action_loc;
} pl_bison_trigger_def_t;

#ifdef __cplusplus
extern "C" {
#endif

status_t pl_parse_name(sql_stmt_t *stmt, word_t *word, var_udo_t *obj, bool32 need_single);
status_t pl_parse_create_trigger(sql_stmt_t *stmt, bool32 replace, word_t *word);
status_t pl_parse_create(sql_stmt_t *stmt, bool32 replace, word_t *word);
status_t pl_parse_drop_procedure(sql_stmt_t *stmt, word_t *word);
status_t pl_parse_drop_trigger(sql_stmt_t *stmt, word_t *word);
status_t pl_parse_drop_type(sql_stmt_t *stmt, word_t *word);
status_t pl_parse_drop_package(sql_stmt_t *stmt, word_t *word);
status_t plc_parse_trigger_desc_core(sql_stmt_t *stmt, word_t *word, bool32 is_upgrade);
status_t pl_parse_trigger_desc(sql_stmt_t *stmt, var_udo_t *obj, word_t *word);
status_t pl_bison_parse_create_procedure(sql_stmt_t *stmt, bool32 replace, bool32 if_not_exists,
    name_with_owner *proc_name, galist_t *args, text_t *body, text_t *source);
status_t pl_bison_parse_create_function(sql_stmt_t *stmt, bool32 replace, bool32 if_not_exists,
    name_with_owner *func_name, galist_t *args, type_word_t *ret_type, text_t *body, text_t *source);
status_t pl_bison_parse_create_package(sql_stmt_t *stmt, bool32 replace, bool32 is_body, bool32 if_not_exists,
    name_with_owner *pkg_name, text_t *body, text_t *source);
status_t pl_bison_parse_create_type(sql_stmt_t *stmt, bool32 replace, bool32 is_body, bool32 if_not_exists,
    name_with_owner *type_name, bool32 force, text_t *body, text_t *source);
status_t pl_bison_parse_create_trigger(sql_stmt_t *stmt, bool32 replace, bool32 if_not_exists,
    name_with_owner *trig_name, pl_bison_trigger_def_t *trigger_def, text_t *source);
status_t pl_bison_compile_function_source(sql_stmt_t *stmt, galist_t *args, type_word_t *ret_type, text_t *body);
status_t pl_bison_compile_procedure_source(sql_stmt_t *stmt, galist_t *args, text_t *body);
status_t pl_bison_compile_stored_body_source(sql_stmt_t *stmt, text_t *program_body, text_t *stored_body);
status_t pl_bison_compile_stored_trigger_body_source(sql_stmt_t *stmt, pl_bison_trigger_def_t *trigger_def);
status_t pl_init_compiler(sql_stmt_t *stmt);

#ifdef __cplusplus
}
#endif

#endif
