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
 * ogsql_hint_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_hint_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __HINT_PARSER_H__
#define __HINT_PARSER_H__

#include "dml_parser.h"
#include "expr_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HINT_START "/*+"

status_t og_alloc_hint(sql_stmt_t *stmt, hint_info_t **hint_info);
void og_get_hint_info(sql_stmt_t *stmt, const char* hints, hint_info_t **hint_info);

#ifdef __cplusplus
}
#endif

#endif