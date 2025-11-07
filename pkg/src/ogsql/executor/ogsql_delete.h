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
 * ogsql_delete.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_delete.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_DELETE_H__
#define __SQL_DELETE_H__

#include "dml_executor.h"

status_t sql_execute_delete(sql_stmt_t *stmt);
status_t sql_open_delete_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_delete_t *ogx);
status_t sql_execute_single_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, sql_delete_t *del_ctx);
status_t sql_execute_delete_triggers(sql_stmt_t *stmt, sql_table_t *table, uint32 type, void *knl_cur);
status_t sql_execute_delete_view_insteadof(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur);

static inline status_t sql_execute_del_stmt_trigs(sql_stmt_t *stmt, delete_plan_t *delete_p, uint32 type)
{
    del_object_t *object = NULL;
    uint32 i;

    for (i = 0; i < delete_p->objects->count; i++) {
        object = (del_object_t *)cm_galist_get(delete_p->objects, i);
        OG_RETURN_IFERR(sql_execute_delete_triggers(stmt, object->table, type, NULL));
    }

    return OG_SUCCESS;
}

#endif