/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
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
 * expl_predicate.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_predicate.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __EXPL_PREDICATE_H__
#define __EXPL_PREDICATE_H__

#include "expl_common.h"
#include "ogsql_unparser.h"

#define EXPL_PRED_COL_NUM 1

static inline bool32 chk_if_hash_join(join_oper_t oper)
{
    return (oper >= JOIN_OPER_HASH && oper <= JOIN_OPER_HASH_RIGHT_LEFT) ||
           (oper >= JOIN_OPER_HASH_SEMI && oper <= JOIN_OPER_HASH_PAR);
}

static inline bool32 chk_if_nl_join(join_oper_t oper)
{
    return (oper >= JOIN_OPER_NL && oper <= JOIN_OPER_NL_FULL);
}

typedef status_t (*expl_pred_func_t)(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper, plan_node_t *plan);

typedef struct st_expl_pred {
    plan_node_type_t type;
    expl_pred_func_t expl_pred_func;
} expl_pred_t;

status_t expl_pred_helper_init(sql_stmt_t *statement, pred_helper_t *helper, uint32 mtrl_id);
void expl_pred_helper_release(pred_helper_t *helper);
status_t expl_format_predicate_row(sql_stmt_t *statement, pred_helper_t *helper, plan_node_t *plan);
status_t expl_put_pred_info(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper, cond_tree_t *tree);
status_t expl_format_merge_hash_cond(sql_stmt_t *statement, pred_helper_t *helper, plan_node_t *plan);
status_t expl_format_pred_index_cond(sql_stmt_t *statement, pred_helper_t *helper, plan_node_t *plan);

#endif