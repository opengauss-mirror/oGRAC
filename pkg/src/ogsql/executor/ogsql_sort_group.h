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
 * ogsql_sort_group.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_sort_group.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SORT_GROUP_H__
#define __SQL_SORT_GROUP_H__

#include "dml_executor.h"

status_t sql_execute_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);

status_t sql_execute_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_merge_sort_group(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_sort_group_calc(void *callback_ctx, const char *new_buf, uint32 new_size,
                             const char *old_buf, uint32 old_size, bool32 found);
status_t sql_sort_group_cmp(int32 *result, void *callback_ctx, char *l_buf, uint32 lsize, char *r_buf, uint32 rsize);
#endif
