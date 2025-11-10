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
 * ogsql_transform.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_transform.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_TRANSFORM_H__
#define __SQL_TRANSFORM_H__

#include "ogsql_stmt.h"
#include "ogsql_expr.h"
#include "ogsql_cond.h"
#include "ogsql_transform_assist.h"

/*
Implement logically optimize, in some cases, we can rewrite the original SQL into
a semantically equivalent SQL with a lower cost.
see ogsql_apply_rule_set_1 and ogsql_apply_rule_set_2 in detail.
*/
#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 og_check_if_ref_parent_columns(sql_select_t *slct)
{
    // Only parent's, no ancestor's !!!
    return slct->parent_refs->count > 0;
}

#define OG_OID_DUAL_TABLE 10
#define OG_UID_DUAL_TABLE 0
static inline bool32 og_check_if_dual(sql_table_t *table)
{
    return table->type == NORMAL_TABLE && table->entry->dc.oid == OG_OID_DUAL_TABLE &&
           table->entry->dc.uid == OG_UID_DUAL_TABLE;
}

status_t og_get_join_cond_from_table_cond(sql_stmt_t *statement, sql_array_t *l_tbls, sql_array_t *r_tbls,
                                          cond_tree_t *ctree, bilist_t *jcond_blst);
status_t ogsql_optimize_logically(sql_stmt_t *statement);
status_t og_create_sqltable(sql_stmt_t *statement, sql_query_t *qry, sql_select_t *select);

#ifdef __cplusplus
}
#endif

#endif