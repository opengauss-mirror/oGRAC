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
 * ogsql_filter.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_filter.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_filter.h"
#include "ogsql_select.h"

status_t sql_execute_filter(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (IS_COND_FALSE(plan->filter.cond)) {
        cursor->eof = OG_TRUE;
        return OG_SUCCESS;
    }
    return sql_execute_query_plan(stmt, cursor, plan->filter.next);
}

status_t sql_fetch_filter(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (IS_COND_FALSE(plan->filter.cond)) {
        *eof = OG_TRUE;
        return OG_SUCCESS;
    }
    bool32 is_found = OG_FALSE;

    for (;;) {
        OGSQL_SAVE_STACK(stmt);
        if (sql_fetch_query(stmt, cursor, plan->filter.next, eof) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }

        if (*eof) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_SUCCESS;
        }
        if (plan->filter.next->type == PLAN_NODE_QUERY_SIBL_SORT) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_SUCCESS;
        }
        if (sql_match_cond_node(stmt, plan->filter.cond->root, &is_found) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }

        if (is_found) {
            return OG_SUCCESS; // should not invoke OGSQL_RESTORE_STACK
        }
        OGSQL_RESTORE_STACK(stmt);
    }
}
