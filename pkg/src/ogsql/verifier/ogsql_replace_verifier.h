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
 * ogsql_replace_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/verifier/ogsql_replace_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_REPLACE_VERIFIER_H__
#define __SQL_REPLACE_VERIFIER_H__

#include "ogsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_replace_into(sql_stmt_t *stmt, sql_replace_t *replace_ctx);

#ifdef __cplusplus
}
#endif

#endif