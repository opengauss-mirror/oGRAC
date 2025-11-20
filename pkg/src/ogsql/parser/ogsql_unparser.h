/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
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
 * ogsql_unparser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_unparser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OGSQL_UNPARSER_H__
#define __OGSQL_UNPARSER_H__

#include "cm_defs.h"
#include "cm_lex.h"
#include "ogsql_cond.h"
#include "ogsql_stmt.h"
#include "ogsql_expr_def.h"
#include "ogsql_winsort.h"
#include "ogsql_plan.h"
#include "pl_udt.h"

#define DEFAULT_UNPARSE_STR_LEN 1024
#define MAX_CONST_LEN 100
#define OUT_LINE_STRING "..."

typedef status_t (*cond_unparse_func_t)(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result);

typedef struct st_cond_unparser {
    cond_node_type_t type;
    cond_unparse_func_t cond_unparse_func;
} cond_unparser_t;

typedef status_t (*ogsql_unparse_stmt)(sql_stmt_t *stmt, var_text_t *result);

typedef struct st_ogsql_unparser {
    lang_type_t type;
    ogsql_unparse_stmt unparse_stmt_func;
} ogsql_unparser_t;

status_t ogsql_unparse_select_info(select_node_t *node, var_text_t *result, bool32 add_brkt);
status_t ogsql_unparse_hash_mtrl_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result);
status_t ogsql_unparse_connect_mtrl_join_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result);
status_t ogsql_unparse_cond_node(sql_query_t *qry, cond_node_t *cond, bool32 add_rnd_brkt, var_text_t *result);
status_t ogsql_unparse_merge_hash_cond_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result);
status_t ogsql_unparse_hash_join_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result);
status_t ogsql_unparse_merge_join_node(sql_query_t *qry, plan_node_t *plan, var_text_t *result);

#endif
