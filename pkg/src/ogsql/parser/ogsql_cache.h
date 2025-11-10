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
 * ogsql_cache.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_cache.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_OGSQL_CACHE_H__
#define __SQL_OGSQL_CACHE_H__
#include "cm_defs.h"
#include "ogsql_stmt.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 og_check_sql_ctx_valid(sql_stmt_t *statement, sql_context_t *ogx);
status_t og_cache_sql_context(sql_stmt_t *statement, context_bucket_t *ctx_bucket, sql_text_t *ogsql, uint32 hash_val);
status_t og_get_context_from_cache(sql_stmt_t *statement, text_t *ogsql, uint32 *ogsql_id, context_bucket_t **bucketid,
                                      ogx_stat_t *stat);
void og_update_context_stat_uncached(sql_stmt_t *statement, timeval_t *timeval_begin);
status_t og_find_then_parse_dml(sql_stmt_t *statement, key_wid_t key_wid, uint32 special_word);
void og_update_context_stat_cached(sql_stmt_t *statement, timeval_t *tv_beg, ogx_stat_t *old_stat);

#ifdef __cplusplus
}
#endif

#endif