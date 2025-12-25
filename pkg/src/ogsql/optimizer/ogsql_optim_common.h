/* -------------------------------------------------------------------------
 * This file is part of the oGRAC project.
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
 * ogsql_common.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_optim_common.h
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_stmt.h"
#include "ogsql_expr_def.h"
#include "ogsql_cond.h"
#include "ogsql_expr.h"

#ifndef __OGSQL_OPTIM_COMMON_H__
#define __OGSQL_OPTIM_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#define OG_SELF_COLUMN    0
#define OG_PARENT_COLUMN  1

static inline bool32 has_diff_level_columns(uint32 flags_l, uint32 flags_r)
{
    return (HAS_SELF_COLS(flags_l) && HAS_PARENT_COLS(flags_r)) ||
           (HAS_SELF_COLS(flags_r) && HAS_PARENT_COLS(flags_l));
}

static inline bool32 has_only_diff_level_columns(uint32 flags_l, uint32 flags_r)
{
    return (HAS_ONLY_SELF_COLS(flags_l) && HAS_ONLY_PARENT_COLS(flags_r)) ||
           (HAS_ONLY_SELF_COLS(flags_r) && HAS_ONLY_PARENT_COLS(flags_l));
}

bool32 validate_outer_join_conditions(sql_join_node_t *jnode);
bool32 og_query_contains_table_ancestor(sql_query_t *qry);
bool32 detect_cross_level_dependency(sql_query_t *qry);
void og_del_parent_refs_in_expr_tree(sql_query_t *qry, expr_tree_t *expr);
status_t og_modify_rs_cols2const(sql_stmt_t *statement, sql_query_t *qry);
void make_subqry_without_join(sql_stmt_t *statement, select_node_t *select_node, bool32 is_var);
bool32 check_cond_push2subslct_table(sql_stmt_t *statement, sql_query_t *qry, sql_select_t *slct_node, cmp_node_t *cmp);

#ifdef __cplusplus
}
#endif

#endif