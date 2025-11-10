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
 * plan_join.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/plan_join.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_JOIN_H__
#define __PLAN_JOIN_H__

#include "ogsql_plan.h"
#include "cbo_base.h"
#include "ogsql_join_path.h"

bool32 need_adjust_hash_order(sql_join_node_t *join_root);
status_t sql_build_join_tree(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_root);
status_t sql_create_join_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_join_node_t *join_node, cond_tree_t *cond,
    plan_node_t **plan);
void sql_generate_join_assist(plan_assist_t *pa, sql_join_node_t *join_node, join_assist_t *join_ass);
bool32 sql_cmp_can_used_by_hash(cmp_node_t *cmp_node);
bool32 sql_get_cmp_join_column(cmp_node_t *cmp_node, expr_node_t **left_column, expr_node_t **right_column);
bool32 sql_check_hash_join(cmp_node_t *cmp_node, double base, double *rate);
bool32 check_and_get_join_column(cmp_node_t *cmp_node, cols_used_t *l_cols_used, cols_used_t *r_cols_used);
bool32 sql_get_cmp_join_tab_id(cmp_node_t *cmp_node, uint16 *l_tab_id, uint16 *r_tab_id, join_oper_t oper);

#endif