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
 * pivot_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/pivot_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PIVOT_PARSER_H__
#define __PIVOT_PARSER_H__

#include "ogsql_expr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct expr_with_alias {
    expr_tree_t *expr;
    text_t alias;
} expr_with_alias;

typedef struct expr_with_as_expr {
    expr_with_alias *expr_alias;
    expr_tree_t *as_expr;
} expr_with_as_expr;

status_t sql_create_pivot(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_create_unpivot(sql_stmt_t *stmt, sql_query_t *query, word_t *word);
status_t sql_try_create_pivot_unpivot_table(sql_stmt_t *stmt, sql_table_t *query_table, word_t *word, bool32 *is_pivot);
status_t sql_create_pivot_sub_select(sql_stmt_t *stmt, sql_table_t *query_table, sql_query_t *query,
    pivot_items_t *pivot_items);
status_t sql_create_pivot_items(sql_stmt_t *stmt, pivot_items_t **pivot_items, source_location_t loc,
    pivot_type_t type);
status_t sql_parse_pivot_aggr_list(galist_t *query_column, expr_tree_t **expr, galist_t *expr_alias,
    bool32 need_filling);
status_t sql_parse_pivot_in_list(pivot_items_t *pivot_items, galist_t *in_list);
status_t sql_parse_pivot_clause_list(sql_stmt_t *stmt, sql_query_t *query, galist_t *pivot_list);
status_t sql_parse_unpivot_in_list(sql_stmt_t *stmt, pivot_items_t *pivot_items, galist_t *in_list);
status_t sql_parse_unpivot_data_rs(sql_stmt_t *stmt, galist_t *unpivot_rs, expr_tree_t *expr);

#endif
