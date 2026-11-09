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
 * ogsql_transf_cartesian_join.h
 *
 *
 * IDENTIFICATION
 *      src/ogsql/optimizer/ogsql_transf_cartesian_join.h
 *
 * -------------------------------------------------------------------------
 */


#ifndef __OGSQL_TRANSF_CARTESIAN_JOIN_H__
#define __OGSQL_TRANSF_CARTESIAN_JOIN_H__

#include "ogsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t og_transf_cartesian_join(sql_stmt_t *statement, sql_query_t *qry);

status_t og_rewrite_tbl_as_slct(sql_table_t *rewrite_tbl, sql_stmt_t *statement);

#ifdef __cplusplus
}
#endif


#endif