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
 * ogsql_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_PARSER_H__
#define __SQL_PARSER_H__

#include "cm_defs.h"
#include "ogsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_sql_parser {
    memory_context_t *context;
    text_t user;
    lex_t lex;
} sql_parser_t;

status_t sql_parse(sql_stmt_t *stmt, text_t *sql, source_location_t *loc);
lang_type_t sql_diag_lang_type(sql_stmt_t *stmt, sql_text_t *sql, word_t *leader_word);

#ifdef __cplusplus
}
#endif

#endif
