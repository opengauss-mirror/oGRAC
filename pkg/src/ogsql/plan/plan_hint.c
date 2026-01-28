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
* plan_hint.c
*
*
* IDENTIFICATION
* src/ctsql/plan/plan_hint.c
*
* -------------------------------------------------------------------------
*/
#include "plan_hint.h"
#include "ogsql_context.h"
#include "ogsql_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

static bool32 og_hint_apply_merge(sql_join_node_t *jnode, join_cond_t *jcond,
                                  sql_join_type_t jtype, bool32 is_slct, join_oper_t *jop)
{
    if (!is_slct || jcond == NULL) {
        return OG_FALSE;
    }

    if (jtype == JOIN_TYPE_LEFT || jtype == JOIN_TYPE_RIGHT || jtype == JOIN_TYPE_FULL) {
        return OG_FALSE;
    }

    *jop = JOIN_OPER_MERGE;
    return OG_TRUE;
}

bool32 og_hint_choose_join_way(sql_join_node_t *jnode, join_cond_t *jcond, bool32 is_slct,
                               join_oper_t *jop)
{
    sql_table_t *tbl = NULL;
    sql_join_node_t *right_jnode = jnode->right;
    sql_join_type_t jtype = jnode->type;

    if (right_jnode->type != JOIN_TYPE_NONE) {
        return OG_FALSE;
    }

    tbl = TABLE_OF_JOIN_LEAF(right_jnode);
    if (tbl->hint_info == NULL) {
        return OG_FALSE;
    }

    switch (HINT_JOIN_METHOD_GET(tbl->hint_info)) {
        case HINT_KEY_WORD_USE_NL:
        case HINT_KEY_WORD_USE_HASH:
        case HINT_KEY_WORD_NL_FULL_MTRL:
        case HINT_KEY_WORD_NL_FULL_OPT:
            return OG_FALSE;

        case HINT_KEY_WORD_USE_MERGE:
            return og_hint_apply_merge(jnode, jcond, jtype, is_slct, jop);

        default:
            return OG_FALSE;
    }
}

#ifdef __cplusplus
}
#endif