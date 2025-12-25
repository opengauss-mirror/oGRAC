/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
 * This file is part of the oGRAC project.
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
 * ogsql_transform_assist.h
 *
 *
 * IDENTIFICATION
 *      src/ograc/optimizer/ogsql_transform_assist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGSQL_TRANSFORM_ASSIST_H
#define OGSQL_TRANSFORM_ASSIST_H

#include "ogsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*sql_tranform_rule_func_t)(sql_stmt_t *statement, sql_query_t *query);
status_t ogsql_transform_one_rule(sql_stmt_t *statement, sql_query_t *query, const char *rule_name,
                                  sql_tranform_rule_func_t proc);

#define OGSQL_RETURN_IF_APPLY_RULE_ERR(s, q, p)                      \
    do {                                                             \
        status_t _status_ = (ogsql_transform_one_rule(s, q, #p, p)); \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) {              \
            OG_LOG_DEBUG_ERR("Failed to transform one rule=%s", #p); \
            cm_set_error_pos(__FILE__, __LINE__);                    \
            return _status_;                                         \
        }                                                            \
    } while (0)

typedef status_t (*sql_tranform_func_t)(sql_stmt_t *statement, void *entry);
status_t ogsql_transform_dummy(sql_stmt_t *statement, void *entry);
typedef struct st_transform_sql {
    sql_type_t type;
    sql_tranform_func_t tranform;
} transform_sql_t;

status_t ogsql_transform_query(sql_stmt_t *statement, sql_query_t *query, bool32 is_phase_1);
status_t ogsql_optimize_logically(sql_stmt_t *statement);
status_t ogsql_optimize_logic_select(sql_stmt_t *statement, void *entry);
status_t ogsql_optimize_logic_insert(sql_stmt_t *statement, void *entry);
status_t ogsql_optimize_logic_replace(sql_stmt_t *statement, void *entry);
status_t ogsql_optimize_logic_delete(sql_stmt_t *statement, void *entry);
status_t ogsql_optimize_logic_update(sql_stmt_t *statement, void *entry);
status_t ogsql_optimize_logic_withas(sql_stmt_t *statement, void *entry);
status_t ogsql_optimize_logic_merge(sql_stmt_t *statement, void *entry);
status_t ogsql_apply_rule_set_2(sql_stmt_t *statement, sql_query_t *query);
#ifdef __cplusplus
}
#endif
#endif