/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __DTC_PARSER_H__
#define __DTC_PARSER_H__


#include "cm_defs.h"
#include "ogsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dtc_parse_create_database(sql_stmt_t *stmt);
status_t dtc_verify_database_def(sql_stmt_t *stmt, knl_database_def_t *def);
status_t dtc_parse_instance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word);
status_t dtc_parse_maxinstance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word);

#ifdef __cplusplus
}
#endif


#endif
