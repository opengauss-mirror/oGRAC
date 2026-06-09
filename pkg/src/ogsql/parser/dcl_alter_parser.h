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
 * dcl_alter_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/dcl_alter_parser.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCL_ALTER_PARSER_H__
#define __DCL_ALTER_PARSER_H__

#include "ogsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_dcl_alter(sql_stmt_t *stmt);
status_t sql_bison_verify_sys_param(sql_stmt_t *stmt, knl_alter_sys_def_t *def);
status_t sql_parse_sid_serial_bison(text_t *src, source_location_t loc, uint32 *sid, uint32 *serial, uint32 *nodeid);
status_t sql_parse_altses_set_bison(sql_stmt_t *stmt, altset_def_t *def, const char *key, const char *value,
    source_location_t loc);

#ifdef __cplusplus
}
#endif

#endif
