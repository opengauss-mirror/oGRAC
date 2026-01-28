/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * OGRAC is licensed under Mulan PSL v2.
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
 * plan_hint.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_hint.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_HINT_H__
#define __PLAN_HINT_H__

#include "ogsql_context.h"
#include "ogsql_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 og_hint_choose_join_way(sql_join_node_t *join_node, join_cond_t *join_cond, bool32 is_select,
                               join_oper_t *jop);

#ifdef __cplusplus
}
#endif

#endif