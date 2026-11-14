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
 * ogsql_join_elimination.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_join_elimination.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __OGSQL_JOIN_ELIM_H__
#define __OGSQL_JOIN_ELIM_H__

#include "ogsql_expr.h"
#include "ogsql_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_col_check_visit_helper {
    sql_array_t *l_tbls;
    bool32 *exists_col;
    bool32 is_right;
} column_check_helper_t;

typedef struct st_value_check_visit_helper {
    sql_array_t *l_tbls;
    sql_array_t *p_tbls;
    sql_join_type_t join_type;
    bool32 is_right;
} value_check_helper_t;


status_t og_transf_optimize_outer_join(sql_stmt_t *statement, sql_query_t *qry);

status_t og_transf_cartesian_probe(sql_stmt_t *statement, sql_query_t *qry);

#ifdef __cplusplus
}
#endif

#endif