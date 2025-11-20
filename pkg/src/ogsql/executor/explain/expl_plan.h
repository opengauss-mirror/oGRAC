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
 * expl_plan.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_plan.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __EXPL_PLAN_H__
#define __EXPL_PLAN_H__

#include "expl_common.h"
#include "expl_predicate.h"

typedef status_t (*expl_column_func_t)(expl_helper_t *helper);

typedef struct st_expl_column {
    expl_col_type_t type;
    text_t name;
    expl_column_func_t expl_column_func;
} expl_column_t;

typedef status_t (*expl_plan_func_t)(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan, uint32 depth);

typedef struct st_expl_plan {
    plan_node_type_t type;
    expl_plan_func_t explain_plan_func;
} expl_plan_t;

typedef status_t (*expl_fmt_func_t)(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper, char *content);

void expl_row_helper_init(row_helper_t *helper, plan_node_t *plan, text_t *operation, text_t *owner, text_t *name,
                          text_t *alias);
status_t expl_helper_init(sql_stmt_t *statement, expl_helper_t *helper, uint32 mtrl_id, text_t *plan_text);
text_t *expl_get_explcol_name(uint32 idx);
status_t expl_format_plan_node(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan, uint32 depth);
status_t expl_format_plan_node_row(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node, uint32 depth,
                                   char *oper_str, text_t *owner, text_t *name, text_t *alias);
status_t expl_format_withas_plan_node(sql_stmt_t *statement, expl_helper_t *helper, sql_withas_t *withas_plan,
                                             uint32 depth);
status_t expl_format_withas_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node, uint32 depth);
#endif
