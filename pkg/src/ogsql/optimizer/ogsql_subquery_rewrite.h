/* -------------------------------------------------------------------------
 * This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * ogsql_subquery_rewrite.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_subquery_rewrite.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __OGSQL_SUBQUERY_REWRITE_H__
#define __OGSQL_SUBQUERY_REWRITE_H__

#include "ogsql_stmt.h"
#include "ogsql_cond.h"
#include "dml_parser.h"
#include "ogsql_verifier.h"
#include "ogsql_plan_defs.h"
#include "srv_instance.h"
#include "ogsql_select_parser.h"
#include "plan_join.h"
#include "ogsql_cond_rewrite.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_rewrite_state {
    REWRITE_UNSUPPORT = 0,
    REWRITE_SUPPORT,
    REWRITE_UNCERTAINLY,
} rewrite_state_e;

typedef struct st_rewrite_helper {
    // sql general info
    sql_stmt_t *stmt;
    sql_query_t *query;
    galist_t *cond_list;

    // single cond info
    cond_node_t *curr_cond;
    sql_query_t *curr_sub_query;

    // operation step helper
    rewrite_state_e state;  // Rewrite feasibility state
    bool32 pullup_cond;     // Flag for pulled-up conditions
    bool32 has_join_cond;       // Join condition presence flag
} rewrite_helper_t;

#define SELECT_ID(cond) ((cond)->cmp->right->root->value.v_obj.id)
#define GET_SELECT_CTX(cond) ((sql_select_t *)(cond)->cmp->right->root->value.v_obj.ptr)

typedef status_t (*check_subquery2table_t)(rewrite_helper_t *helper);
typedef status_t (*rebuild_subquery_ssa_t)(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t visit_func);
typedef status_t (*collect_subquery_expr_t)(visit_assist_t *v_ast, sql_query_t *sub_qry, visit_func_t visit_func);

status_t og_transf_subquery_rewrite(sql_stmt_t *statement, sql_query_t *qry);

status_t get_all_and_cmp_conds(sql_stmt_t *statement, galist_t *cond_lst, cond_node_t *cond, bool32 need_or_conds);

// pull up conds no rewrite
status_t pull_up_subquery_conds_normal(rewrite_helper_t *helper);
bool32 check_subquery_can_be_pulled_up_normal(rewrite_helper_t *helper);
status_t check_and_pull_up_subquery_conds_normal(rewrite_helper_t *helper);
status_t try_pull_up_subquery_conds_normal(sql_stmt_t *statement, cond_tree_t **pulled_up_tree,
                                           cond_node_t *cond);
status_t post_process_pull_up_cond_normal(rewrite_helper_t *helper, sql_query_t *sub_qry,
                                          cond_tree_t *pulled_up_tree);

// pull up conds in rewrite
status_t pull_up_subquery_conds(rewrite_helper_t *helper);
bool32 check_subquery_can_be_pulled_up(rewrite_helper_t *helper);
status_t check_and_pull_up_subquery_conds(rewrite_helper_t *helper);
status_t try_pull_up_subquery_conds(sql_stmt_t *statement, cond_tree_t **pulled_up_tree,
                                    cond_node_t *cond, bool32 *has_join_cond);
status_t post_process_pull_up_cond(rewrite_helper_t *helper, cond_tree_t *pulled_up_tree);

status_t pullup_or_rewrite_subquery_cond(rewrite_helper_t *helper);
status_t subquery_rewrite_2_table(rewrite_helper_t *helper);
status_t create_subselect_table_4_join(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond);
status_t prepare_join_cond(rewrite_helper_t *helper);
status_t decide_join_mode(sql_stmt_t *statement, sql_query_t *qry, sql_query_t *sub_qry, bool32 has_inner_join_cond);
status_t create_query_join_node(sql_stmt_t *statement, sql_query_t *qry);
status_t update_query_join_chain(sql_stmt_t *statement, sql_join_node_t **jnode,
                                 sql_join_type_t jtype, sql_table_t *stable);
status_t semi2inner_collect_ancestor_info(visit_assist_t *v_ast, sql_query_t *sub_qry, uint32 ancestor);
status_t delete_select_node_from_query_ssa(sql_stmt_t *statement, sql_query_t *qry, uint32 id);

#ifdef __cplusplus
}
#endif

#endif