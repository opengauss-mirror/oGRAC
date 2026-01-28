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
* ogsql_hint_verifier.h
*
*
* IDENTIFICATION
* src/ctsql/verifier/ogsql_hint_verifier.h
*
* -------------------------------------------------------------------------
*/
#ifndef __SQL_HINT_VERIFIER_H__
#define __SQL_HINT_VERIFIER_H__

#include "ogsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RBO_NOT_SUPPORT_INDEX_HINT (HINT_KEY_WORD_NO_INDEX_SS | HINT_KEY_WORD_USE_CONCAT | HINT_KEY_WORD_INDEX_SS)
#define EXPR_IS_CONST_CHAR(expr)  \
   (((expr)->root->type == EXPR_NODE_CONST) && ((expr)->root->value.type == OG_TYPE_CHAR))
#define EXPR_IS_CONST_INTEGER(expr)  \
   (((expr)->root->type == EXPR_NODE_CONST) && ((expr)->root->value.type == OG_TYPE_INTEGER))
#define SET_HINT_MASK(mask, hint_type, key) (((mask)[(hint_type)] |= ((key))))
#define UNSET_HINT_MASK(mask, hint_type, key) (((mask)[(hint_type)] &= ~((key))))

typedef status_t (*sql_hint_verifier_func)(sql_hint_verifier_t *verif, hint_item_t *hint_item,
                                          hint_info_t *query_hint_info);

typedef enum en_opt_param_id {
    OPT_DYNAMIC_SAMPLING,
    OPT_PARAM_COUNT,
} opt_param_id_t;

typedef enum en_hint_force_key {
    HINT_FORCE_INVALID = 0,
    HINT_FORCE_ORDERED = 0x00000001,
    HINT_FORCE_NL = 0x00000002,
    HINT_FORCE_MERGE = 0x00000004,
    HINT_FORCE_HASH = 0x00000008,
} hint_force_key_t;

typedef struct st_sql_opt_param {
    text_t text;
    opt_param_id_t id;
} sql_opt_param_t;

typedef void (*sql_opt_param_verifier_func_t)(
    sql_hint_verifier_t *verif, hint_item_t *hint_item, hint_info_t *hint_info,
                                             opt_param_id_t id);

typedef struct st_sql_hint {
    hint_id_t hint_id;
    hint_type_t hint_type;
    uint64 hint_key;
    sql_hint_verifier_func hint_verify_func;
} sql_hint_t;

void og_hint_verify(sql_stmt_t *stmt, sql_type_t sql_type, void *ctx_entry);

static inline void sql_init_hint_verf(sql_hint_verifier_t *verif, sql_stmt_t *statement, sql_array_t *tables,
                                     sql_table_t *table)
{
    verif->statement = statement;
    verif->tables = tables;
    verif->table = table;
}

#ifdef __cplusplus
}
#endif

#endif
