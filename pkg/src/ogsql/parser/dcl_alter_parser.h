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
#include "srv_param_common.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_parse_dcl_alter(sql_stmt_t *stmt);
status_t sql_bison_make_sys_param_value(sql_stmt_t *stmt, const char *source, uint32 start, uint32 end,
    const char *decoded_string, bool32 is_string, source_location_t loc, source_location_t extra_token_loc,
    uint32 token_count, bison_sys_param_value_t **result);
status_t sql_bison_verify_sys_param(sql_stmt_t *stmt, knl_alter_sys_def_t *def,
    bison_sys_param_value_t *value);
status_t sql_bison_verify_debug_param(sql_stmt_t *stmt, knl_alter_sys_def_t *def,
    bison_sys_param_value_t *value);
status_t sql_parse_sid_serial_bison(text_t *src, source_location_t loc, uint32 *sid, uint32 *serial, uint32 *nodeid);
status_t sql_parse_altses_set_bison(sql_stmt_t *stmt, altset_def_t *def, const char *key,
    const bison_sys_param_value_t *value);

#ifdef __cplusplus
}
#endif

#endif
