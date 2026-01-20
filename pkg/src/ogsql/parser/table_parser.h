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
 * table_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/table_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TABLE_PARSER_H__
#define __TABLE_PARSER_H__

#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word);
status_t sql_parse_query_tables(sql_stmt_t *stmt, sql_query_t *sql_query, word_t *word);
status_t sql_parse_join_entry(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_generate_join_node(sql_stmt_t *stmt, sql_join_chain_t *join_chain, sql_join_type_t join_type,
    sql_table_t *table, cond_tree_t *cond);
status_t sql_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name);
status_t sql_try_parse_table_alias(sql_stmt_t *stmt, sql_text_t *alias, word_t *word);
status_t sql_regist_table(sql_stmt_t *stmt, sql_table_t *table);
status_t sql_create_join_node(sql_stmt_t *stmt, sql_join_type_t join_type, sql_table_t *table, cond_tree_t *cond,
    sql_join_node_t *left, sql_join_node_t *right, sql_join_node_t **join_node);
status_t sql_parse_comma_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word);
status_t sql_form_table_join_with_opers(sql_join_chain_t *chain, uint32 opers);
status_t sql_set_table_qb_name(sql_stmt_t *stmt, sql_query_t *query);
status_t sql_create_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
                                       sql_table_t *query_table, word_t *word);
void sql_parse_join_set_table_nullable(sql_join_node_t *node);
uint32 sql_outer_join_count(sql_join_node_t *join_node);
status_t sql_remove_join_table(sql_stmt_t *stmt, sql_query_t *query);
void sql_init_json_table_info(sql_stmt_t *stmt, json_table_info_t *json_info);
status_t sql_try_match_withas_table(sql_stmt_t *stmt, sql_table_t *query_table, bool32 *is_withas_table);

#endif
