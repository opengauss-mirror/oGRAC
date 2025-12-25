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
 * ogsql_cache.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_cache.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_cache.h"
#include "cm_timer.h"
#include "srv_instance.h"
#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif
void og_update_context_stat_uncached(sql_stmt_t *statement, timeval_t *timeval_begin)
{
    timeval_t timeval_end;
    sql_context_t *ogx = statement->context;
    sql_init_context_stat(&ogx->stat);
    ogx->stat.parse_calls = 1;
    statement->session->stat.hard_parses++;

    ogx->stat.last_load_time = g_timer()->now;
    (void)cm_gettimeofday(&timeval_end);
    ogx->stat.parse_time = (uint64)TIMEVAL_DIFF_US(timeval_begin, &timeval_end);
    ogx->stat.last_active_time = ogx->stat.last_load_time;
    ogx->module_kind = SESSION_CLIENT_KIND(statement->session);
    ogx->ctrl.ref_count = 0;
    ogx->ctrl.uid = statement->session->curr_schema_id;
    sql_parse_set_context_procinfo(statement);
}

static inline void og_set_ctx_ctrl_after_check(sql_context_t *ogx, uint8 type)
{
    if (ogx->in_sql_pool) {
        ogx_pool_lru_move_to_head(sql_pool, &ogx->ctrl);
    }
}

static bool32 og_check_sequences(sql_stmt_t *statement)
{
    sql_context_t *ogx = statement->context;
    galist_t *sequences = ogx->sequences;
    galist_t *objs = ogx->ref_objects;
    if (!sequences || sequences->count == 0 || !objs) {
        return OG_TRUE;
    }

    uint32 i = 0;
    object_address_t *obj;
    while (i < objs->count) {
        obj = (object_address_t *)cm_galist_get(objs, i++);
        if (obj->tid != OBJ_TYPE_SEQUENCE) {
            continue;
        }

        if (!knl_chk_seq_entry(KNL_SESSION(statement), obj->scn, obj->uid, obj->oid)) {
            OG_LOG_DEBUG_INF("Failed to check seq, oid=%llu, name=%s, stmtid=%u.",
                obj->oid, obj->name, statement->id);
            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

bool32 og_check_sql_ctx_valid(sql_stmt_t *statement, sql_context_t *ogx)
{
    OG_LOG_DEBUG_INF("Validating SQL context, stmtid=%u", statement->id);
    
    OG_RETVALUE_IFTRUE(ogx->policy_used, OG_FALSE);
    OG_RETVALUE_IFTRUE(!og_check_sequences(statement), OG_FALSE);
    
    // return OG_SUCCESS if check successfully.
    if (sql_check_tables(statement, ogx)) {
        OG_LOG_DEBUG_INF("Cannot soft parse because failed to check table, stmtid=%u.", statement->id);
        cm_reset_error();
        return OG_FALSE;
    }

    OG_RETVALUE_IFTRUE(!sql_check_procedures(statement, ogx->dc_lst), OG_FALSE);

    OG_LOG_DEBUG_INF("SQL context validation passed, stmtid=%u", statement->id);
    return OG_TRUE;
}

status_t og_get_context_from_cache(sql_stmt_t *statement, text_t *ogsql, uint32 *ogsql_hash,
    context_bucket_t **bucketid, ogx_stat_t *stat)
{
    OG_LOG_DEBUG_INF("Start getting SQL context from cache, stmtid=%u", statement->id);
    uint32 hash_val = cm_hash_text(ogsql, INFINITE_HASH_RANGE);
    context_bucket_t *ogx_bucket = &sql_pool->buckets[hash_val % OG_SQL_BUCKETS];
    uint16 sid = (uint16)KNL_SESSION(statement)->id;

    OG_LOG_DEBUG_INF("Acquiring bucket lock, bucket=%u, stmtid=%u.",
                     hash_val % OG_SQL_BUCKETS, statement->id);
    cm_recursive_lock(sid, &ogx_bucket->parsing_lock, NULL);
    uint32 schemaid = statement->session->curr_schema_id;
    sql_context_t *ogx = (sql_context_t *)ogx_pool_find(sql_pool, ogsql, hash_val, schemaid);
    SET_STMT_CONTEXT(statement, ogx);

    if (ogx) {
        if (og_check_sql_ctx_valid(statement, statement->context)) {
            ogx->module_kind = SESSION_CLIENT_KIND(statement->session);
            ogx->stat.parse_calls++;
            cm_recursive_unlock(&ogx_bucket->parsing_lock);
            og_set_ctx_ctrl_after_check(ogx, statement->lang_type);
            OG_LOG_DEBUG_INF("Get SQL context cache successfully, stmtid=%u", statement->id);
            return OG_SUCCESS;
        }
        if (ogx->ctrl.ref_count == 1) {
            // continue to use old stat because it is the same sql.
            *stat = ogx->stat;
        }
        ogx->ctrl.valid = OG_FALSE;
        sql_release_context(statement);
        OG_LOG_DEBUG_INF("Invalid SQL context released, stmtid=%u", statement->id);
    }
    OG_LOG_DEBUG_INF("Cache miss for SQL context, stmtid=%u", statement->id);
    cm_recursive_unlock(&ogx_bucket->parsing_lock);
    *bucketid = ogx_bucket;
    *ogsql_hash = hash_val;
    return OG_ERROR;
}

static inline void ogsql_update_stat_reload(sql_stmt_t *statement)
{
    statement->session->stat.hard_parses++;
}

static inline void ogsql_cache_sql_ctx_final_proc(sql_stmt_t *statement)
{
    sql_context_t *ogx = statement->context;
    ogx_insert(sql_pool, (context_ctrl_t *)ogx);
    ogx->in_sql_pool = OG_TRUE;
    ogsql_update_stat_reload(statement);
}

status_t og_cache_sql_context(sql_stmt_t *statement, context_bucket_t *ogx_bucket, sql_text_t *ogsql, uint32 hash_val)
{
    OG_LOG_DEBUG_INF("Start caching SQL context, stmtid=%u", statement->id);
    uint16 sid = (uint16)KNL_SESSION(statement)->id;
    sql_context_t *new_ogx = statement->context;

    OG_LOG_DEBUG_INF("Acquiring bucket lock for caching, stmtid=%u", statement->id);
    cm_recursive_lock(sid, &ogx_bucket->parsing_lock, NULL);
    uint32 schemaid = statement->session->curr_schema_id;
    sql_context_t *ogx = (sql_context_t *)ogx_pool_find(sql_pool, (text_t *)ogsql, hash_val, schemaid);
    if (ogx) {
        SET_STMT_CONTEXT(statement, ogx);
        OG_LOG_DEBUG_INF("Duplicate SQL context found during caching, stmtid=%u", statement->id);
        if (og_check_sql_ctx_valid(statement, statement->context)) {
            ogx->module_kind = SESSION_CLIENT_KIND(statement->session);
            ogx->stat.parse_calls++;
            sql_free_context(new_ogx);
            cm_recursive_unlock(&ogx_bucket->parsing_lock);
            OG_LOG_DEBUG_INF("Using existing valid context, skipping cache, stmtid=%u", statement->id);
            return OG_SUCCESS;
        }
        OG_LOG_DEBUG_INF("Existing context is invalid, replacing with new one, stmtid=%u", statement->id);
        // the old context is invalid, should be released.
        ogx->ctrl.valid = OG_FALSE;
        sql_release_context(statement);
        SET_STMT_CONTEXT(statement, new_ogx);
    }
    ogx = statement->context;
    ogx->ctrl.ref_count = 1;
    ogx_bucket_insert(ogx_bucket, (context_ctrl_t *)ogx);
    cm_recursive_unlock(&ogx_bucket->parsing_lock);

    ogsql_cache_sql_ctx_final_proc(statement);
    OG_LOG_DEBUG_INF("SQL context cached successfully, stmtid=%u", statement->id);
    return OG_SUCCESS;
}

void og_update_context_stat_cached(sql_stmt_t *statement, timeval_t *tv_beg, ogx_stat_t *old_stat)
{
    timeval_t timeval_end;
    sql_context_t *ogx = statement->context;
    sql_init_context_stat(&ogx->stat);
    sql_parse_set_context_procinfo(statement);
    // check if can inherit
    if (old_stat->parse_calls) {
        ogx->stat = *old_stat;
    }
    ogx->stat.parse_calls = 1;

    ogx->stat.last_load_time = g_timer()->now;
    (void)cm_gettimeofday(&timeval_end);
    ogx->stat.parse_time = (uint64)TIMEVAL_DIFF_US(tv_beg, &timeval_end);
    ogx->module_kind = SESSION_CLIENT_KIND(statement->session);
}

status_t og_find_then_parse_dml(sql_stmt_t *statement, key_wid_t key_wid, uint32 special_word)
{
    OG_LOG_DEBUG_INF("Starting SQL soft parse process, stmtid=%u", statement->id);
    // 先从缓存中查找.
    uint32 hash;
    context_bucket_t *ctx_bucket = NULL;
    ogx_stat_t stat;
    stat.parse_calls = 0;  // check if resue the stat.
    text_t *ogsql = (text_t *)&statement->session->lex->text;
    if (og_get_context_from_cache(statement, ogsql, &hash, &ctx_bucket, &stat) == OG_SUCCESS) {
        statement->context->has_ltt = (special_word & SQL_HAS_LTT);
        return OG_SUCCESS;
    }
    OG_LOG_DEBUG_INF("Cache miss, proceeding with hard parse, stmtid=%u", statement->id);
    // can not find sql from sql cache, so parse sql.
    status_t ret;
    SYNC_POINT_GLOBAL_START(CTC_SQL_ALLOC_CONTEXT_FAIL, &ret, OG_ERROR);
    ret = sql_alloc_context(statement);
    SYNC_POINT_GLOBAL_END;
    if (ret != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to alloc sql context, SQL = %s.", T2S(ogsql));
        return OG_ERROR;
    }

    sql_context_t *ogx = statement->context;
    ogx->ctrl.uid = statement->session->curr_schema_id;
    ogx->ctrl.hash_value = hash;
    ogx->ctrl.bucket = ctx_bucket;
    statement->context->clause_info.union_all_count = 0;

    timeval_t begin_time;
    (void)cm_gettimeofday(&begin_time);
    if (sql_create_dml_currently(statement, (sql_text_t *)ogsql, key_wid)) {
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("DML hard parsing completed successfully, stmtid=%u", statement->id);
    CM_ASSERT(ogx->cacheable);
    og_update_context_stat_cached(statement, &begin_time, &stat);
    ret = og_cache_sql_context(statement, ctx_bucket, (sql_text_t *)ogsql, hash);
    if (ret != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to cache sql context, SQL = %s.", T2S(ogsql));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif