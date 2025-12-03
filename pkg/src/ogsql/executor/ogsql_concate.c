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
 * ogsql_concate.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_concate.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_concate.h"
#include "ogsql_select.h"
#include "ogsql_mtrl.h"
#include "ogsql_scan.h"
#include "srv_instance.h"

static inline status_t sql_alloc_concate_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 vmid;
    vm_page_t *vm_page = NULL;
    concate_ctx_t *concate_ctx = NULL;
    plan_node_t *sub_plan = NULL;
    uint32 bucket_num;

    OG_RETURN_IFERR(vm_alloc(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, &vmid));

    if (vm_open(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid, &vm_page) != OG_SUCCESS) {
        vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid);
        return OG_ERROR;
    }

    concate_ctx = (concate_ctx_t *)vm_page->data;
    concate_ctx->id = 0;
    concate_ctx->vmid = vmid;
    concate_ctx->curr_plan = NULL;
    concate_ctx->keys = plan->cnct_p.keys;
    concate_ctx->sub_plans = plan->cnct_p.plans;
    concate_ctx->buf = (char *)vm_page->data + sizeof(concate_ctx_t);
    sql_init_hash_iter(&concate_ctx->iter, NULL);
    cursor->cnct_ctx = concate_ctx;

    bucket_num = 0;
    for (uint32 i = 0; i < concate_ctx->sub_plans->count; ++i) {
        sub_plan = (plan_node_t *)cm_galist_get(concate_ctx->sub_plans, i);
        bucket_num += sql_get_plan_hash_rows(stmt, sub_plan);
    }
    bucket_num = MIN(bucket_num, OG_HASH_JOIN_COUNT);

    vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, &concate_ctx->hash_segment, PMA_POOL, HASH_PAGES_HOLD,
        HASH_AREA_SIZE);
    OG_RETURN_IFERR(vm_hash_table_alloc(&concate_ctx->hash_table, &concate_ctx->hash_segment, bucket_num));
    OG_RETURN_IFERR(vm_hash_table_init(&concate_ctx->hash_segment, &concate_ctx->hash_table, NULL, NULL, NULL));
    return OG_SUCCESS;
}

void sql_free_concate_ctx(sql_stmt_t *ogsql_stmt, concate_ctx_t *ogx)
{
    vm_hash_segment_deinit(&ogx->hash_segment);
    vm_free(KNL_SESSION(ogsql_stmt), KNL_SESSION(ogsql_stmt)->temp_pool, ogx->vmid);
}

static inline status_t sql_execute_child_plan(sql_stmt_t *ogsql_stmt, sql_cursor_t *cursor, plan_node_t *sub_plan,
    bool32 *eof)
{
    switch (sub_plan->type) {
        case PLAN_NODE_SCAN:
            return sql_execute_scan(ogsql_stmt, cursor, sub_plan);

        case PLAN_NODE_JOIN:
            return sql_execute_join(ogsql_stmt, cursor, sub_plan, eof);

        default:
            break;
    }

    OG_THROW_ERROR(ERR_SQL_PLAN_ERROR, "not support plan type for concate", sub_plan->type);
    return OG_ERROR;
}

static inline status_t sql_execute_for_concate(sql_stmt_t *ogsql_stmt, sql_cursor_t *cursor, concate_ctx_t *ogx,
    bool32 switch_plan, bool32 *eof)
{
    bool32 sub_eof = OG_FALSE;

    ogx->id = switch_plan ? ogx->id + 1 : ogx->id;

    while (ogx->id < ogx->sub_plans->count) {
        ogx->curr_plan = (plan_node_t *)cm_galist_get(ogx->sub_plans, ogx->id);
        OG_RETURN_IFERR(sql_execute_child_plan(ogsql_stmt, cursor, ogx->curr_plan, &sub_eof));
        if (!sub_eof) {
            return OG_SUCCESS;
        }
        ++ogx->id;
    }
    *eof = OG_TRUE;
    return OG_SUCCESS;
}

static inline status_t sql_fetch_sub_plan(sql_stmt_t *ogsql_stmt, sql_cursor_t *cursor, plan_node_t *sub_plan, bool32
    *eof)
{
    switch (sub_plan->type) {
        case PLAN_NODE_JOIN:
            return sql_fetch_join(ogsql_stmt, cursor, sub_plan, eof);

        case PLAN_NODE_SCAN:
            cursor->last_table = sub_plan->scan_p.table->plan_id;
            return sql_fetch_scan(ogsql_stmt, cursor, sub_plan, eof);

        default:
            break;
    }
    OG_THROW_ERROR(ERR_SQL_PLAN_ERROR, "not support plan type for concate", sub_plan->type);
    return OG_ERROR;
}

static status_t sql_fetch_for_concate(sql_stmt_t *stmt, sql_cursor_t *cursor, concate_ctx_t *ogx, bool32 *eof)
{
    bool32 sub_eof = OG_FALSE;

    *eof = OG_FALSE;

    while (OG_TRUE) {
        OG_RETURN_IFERR(sql_fetch_sub_plan(stmt, cursor, ogx->curr_plan, &sub_eof));
        if (!sub_eof) {
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(sql_execute_for_concate(stmt, cursor, ogx, OG_TRUE, eof));
        if (*eof) {
            return OG_SUCCESS;
        }
        sub_eof = OG_FALSE;
    }
}

static inline status_t make_concate_hash_key(sql_stmt_t *stmt, galist_t *keys, char *buf)
{
    variant_t value;
    expr_tree_t *key = NULL;
    row_assist_t ra;

    row_init(&ra, buf, OG_MAX_ROW_SIZE, keys->count);
    for (uint32 i = 0; i < keys->count; i++) {
        key = (expr_tree_t *)cm_galist_get(keys, i);

        OG_RETURN_IFERR(sql_exec_expr(stmt, key, &value));
        OG_RETURN_IFERR(sql_put_row_value(stmt, NULL, &ra, key->root->datatype, &value));
    }
    return OG_SUCCESS;
}

status_t sql_execute_concate(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CM_TRACE_BEGIN;
    if (cursor->cnct_ctx != NULL) {
        sql_free_concate_ctx(stmt, cursor->cnct_ctx);
        cursor->cnct_ctx = NULL;
    }

    OG_RETURN_IFERR(sql_alloc_concate_ctx(stmt, cursor, plan));
    OG_RETURN_IFERR(sql_execute_for_concate(stmt, cursor, cursor->cnct_ctx, OG_FALSE, &cursor->eof));
    CM_TRACE_END(stmt, plan->plan_id);
    return OG_SUCCESS;
}

status_t sql_fetch_concate(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    bool32 exist_row = OG_FALSE;
    concate_ctx_t *ogx = cursor->cnct_ctx;
    CM_TRACE_BEGIN;

    if (cursor->eof) {
        *eof = OG_TRUE;
        return OG_SUCCESS;
    }

    for (;;) {
        OGSQL_SAVE_STACK(stmt);
        OG_RETURN_IFERR(sql_fetch_for_concate(stmt, cursor, ogx, eof));

        if (*eof) {
            OGSQL_RESTORE_STACK(stmt);
            CM_TRACE_END(stmt, plan->plan_id);
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(make_concate_hash_key(stmt, ogx->keys, ogx->buf));
        OG_RETURN_IFERR(vm_hash_table_insert2(&exist_row, &ogx->hash_segment, &ogx->hash_table, ogx->buf,
            ((row_head_t *)ogx->buf)->size));
        OGSQL_RESTORE_STACK(stmt);

        if (!exist_row) {
            break;
        }
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return OG_SUCCESS;
}
