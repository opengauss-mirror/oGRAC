/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * expl_executor.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_executor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __EXPL_EXECUTOR_H__
#define __EXPL_EXECUTOR_H__

#include "cm_defs.h"
#include "cm_memory.h"
#include "cm_row.h"

#include "cm_list.h"
#include "expl_plan.h"

status_t expl_execute(sql_stmt_t *statement);
status_t expl_get_explain_text(sql_stmt_t *statement, text_t *plan_text);
status_t expl_send_fetch_result(sql_stmt_t *statement, sql_cursor_t *cursor, text_t *plan_text);
status_t expl_init_executors(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper, text_t *explain_text);
status_t expl_execute_executors(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan);
void expl_release_executors(expl_helper_t *helper);
void expl_close_segment(sql_stmt_t *statement, sql_cursor_t *cursor);
status_t expl_record_fmt_sizes(sql_cursor_t *cursor, expl_helper_t *helper);
status_t expl_send_explain_rows(sql_stmt_t *statement, sql_cursor_t *cursor, expl_helper_t *helper);
status_t expl_pre_execute(sql_stmt_t *statement, sql_cursor_t **cursor);

static inline bool32 is_explain_create_type(sql_stmt_t *statement)
{
    if (SQL_TYPE(statement) == OGSQL_TYPE_CREATE_TABLE || SQL_TYPE(statement) == OGSQL_TYPE_CREATE_INDEX ||
        SQL_TYPE(statement) == OGSQL_TYPE_CREATE_INDEXES) {
            return OG_TRUE;
        }
    return OG_FALSE;
}
#endif
