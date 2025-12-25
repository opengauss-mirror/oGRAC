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
 * dcl_executor.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/dcl_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCL_EXECUTOR_H__
#define __DCL_EXECUTOR_H__

#include "cm_defs.h"
#include "ogsql_stmt.h"
#include "cm_lex.h"
#ifdef OG_RAC_ING
extern status_t shd_calc_direct_route_for_value(sql_stmt_t *ogsql_stmt, sql_route_t *route_rule, group_list_t *groups);
#endif
#ifdef __cplusplus
extern "C" {
#endif

status_t sql_execute_dcl(sql_stmt_t *ogsql_stmt);
bool32 sql_check_effective_in_shard(uint32 id);
status_t sql_execute_commit_phase1(sql_stmt_t *ogsql_stmt);
status_t sql_execute_end_phase2(sql_stmt_t *ogsql_stmt);
status_t sql_execute_commit(sql_stmt_t *ogsql_stmt);
status_t sql_execute_rollback(sql_stmt_t *ogsql_stmt);
status_t sql_execute_rollback_to(sql_stmt_t *ogsql_stmt);
status_t sql_execute_savepoint(sql_stmt_t *ogsql_stmt);

#ifdef __cplusplus
}
#endif

#endif
