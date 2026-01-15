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
 * func_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/func_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __FUNC_PARSER_H__
#define __FUNC_PARSER_H__

#include "ogsql_expr.h"
#include "expr_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_windowing_border {
    expr_tree_t *expr;
    uint32 border_type;
} windowing_border_t;

typedef struct st_trim_list {
    expr_tree_t *first_expr;
    expr_tree_t *second_expr;
    bool8 reverse;
} trim_list_t;

typedef struct st_extract_list {
    expr_tree_t *arg;
    char *extract_type;
} extract_list_t;

status_t sql_convert_to_cast(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word);
status_t sql_build_func_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_build_func_over(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t **node);
status_t sql_try_fetch_func_arg(sql_stmt_t *stmt, text_t *arg_name);
status_t sql_create_const_string_expr(sql_stmt_t *stmt, expr_tree_t **new_expr, const char *char_str);
status_t sql_build_cast_expr(sql_stmt_t *stmt, source_location_t loc, expr_tree_t *expr, typmode_t *type,
                             expr_tree_t **res);
status_t sql_create_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, galist_t *func_name,
    expr_tree_t *arg_list, source_location_t loc);
status_t sql_build_winsort_node_bison(sql_stmt_t *stmt, winsort_args_t **winsort_args, galist_t* group_exprs,
    galist_t *sort_items, windowing_args_t *windowing, source_location_t loc);
status_t sql_create_winsort_node_bison(sql_stmt_t *stmt, expr_tree_t *func_expr, expr_node_t *func_node,
    winsort_args_t *winsort_args, source_location_t loc);
status_t sql_create_windowing_arg(sql_stmt_t *stmt, windowing_args_t **windowing_args,
    windowing_border_t *l_border, windowing_border_t *r_border);
status_t sql_create_cast_convert_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *arg, type_word_t *type,
    char *func_name, source_location_t loc);
status_t sql_create_if_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, cond_tree_t *cond_tree,
    expr_tree_t *first_arg, expr_tree_t *second_arg, source_location_t loc);
status_t sql_create_lnnvl_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, cond_tree_t *cond_tree,
    source_location_t loc);
status_t sql_create_trim_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, trim_list_t *trim,
    func_trim_type_t trim_type, source_location_t loc);
status_t sql_create_groupconcat_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *expr_list,
     galist_t *sort_list, char *separator, source_location_t loc);
status_t sql_create_substr_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *arg_list,
    char *func_name, source_location_t loc);
status_t sql_create_extract_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, extract_list_t *extract_list,
    source_location_t loc);

#ifdef __cplusplus
}
#endif

#endif
