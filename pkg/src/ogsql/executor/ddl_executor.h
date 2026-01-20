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
 * ddl_executor.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ddl_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_EXECUTOR_H__
#define __DDL_EXECUTOR_H__

#include "cm_defs.h"
#include "ogsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_execute_ddl(sql_stmt_t *ogsql_stmt);
status_t sql_execute_ddl_with_count(sql_stmt_t *ogsql_stmt);
status_t sql_try_import_rows(void *sql_stmt, uint32 count);
status_t sql_get_ddl_sql(void *sql_stmt, text_t *sql, vmc_t *vmc, bool8 *need_free);

status_t sql_execute_alter_index(sql_stmt_t *ogsql_stmt);
status_t sql_execute_create_index(sql_stmt_t *ogsql_stmt);
status_t sql_execute_drop_index(sql_stmt_t *ogsql_stmt);
status_t sql_init_withas_vmc(sql_stmt_t *ogsql_stmt, sql_withas_t *withas_ctx);
status_t sql_init_select_vmc(sql_stmt_t *ogsql_stmt, select_node_t *select_node);
#ifdef __cplusplus
}
#endif

#endif
