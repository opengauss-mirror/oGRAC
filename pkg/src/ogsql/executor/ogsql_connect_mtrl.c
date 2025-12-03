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
 * ogsql_connect_mtrl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_connect_mtrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_connect_mtrl.h"
#include "ogsql_select.h"
#include "ogsql_mtrl.h"
#include "ogsql_join_comm.h"
#include "srv_instance.h"

#define CB_MTRL_CONTEXT(cursor) ((cursor)->connect_data.first_level_cursor->cb_mtrl_ctx)
#define CB_MTRL_PLAN (CB_MTRL_CONTEXT(cursor)->cb_mtrl_p)
#define CB_MTRL_SEGMENT (&CB_MTRL_CONTEXT(cursor)->hash_segment)
#define CB_MTRL_TABLE_ENTRY (&CB_MTRL_CONTEXT(cursor)->hash_table)

#define CB_MTRL_LAST_CURSOR (CB_MTRL_CONTEXT(cursor)->last_cursor)
#define CB_MTRL_CURR_CURSOR (CB_MTRL_CONTEXT(cursor)->curr_cursor)
#define CB_MTRL_NEXT_CURSOR (CB_MTRL_CONTEXT(cursor)->next_cursor)
#define CB_MTRL_TEMP_ITER (&CB_MTRL_CONTEXT(cursor)->iter)
#define CB_MTRL_SECOND_LEVEL 2

static status_t sql_connect_mtrl_get_first_entry(sql_stmt_t *stmt, sql_cursor_t *cursor, hash_table_iter_t *iter);

static inline uint32 sql_connect_mtrl_get_level(sql_cursor_t *cursor)
{
    return CB_MTRL_CONTEXT(cursor)->curr_level;
}

static inline cb_mtrl_data_t *sql_connect_mtrl_get_cb_data(sql_cursor_t *cursor, uint32 level)
{
    CM_ASSERT(level <= CB_MTRL_CONTEXT(cursor)->cb_data->count);
    return (cb_mtrl_data_t *)(cm_galist_get(CB_MTRL_CONTEXT(cursor)->cb_data, level - 1));
}

static inline hash_table_iter_t *sql_connect_mtrl_get_iter(sql_cursor_t *cursor, uint32 level)
{
    return &(sql_connect_mtrl_get_cb_data(cursor, level)->iter);
}

static inline mtrl_rowid_t *sql_connect_mtrl_get_prior_row(sql_cursor_t *cursor, uint32 level)
{
    return &(sql_connect_mtrl_get_cb_data(cursor, level)->prior_row);
}

static inline status_t sql_connect_mtrl_alloc_cb_data(sql_cursor_t *cursor, uint32 level, cb_mtrl_data_t **cb_mtrl_data)
{
    if (level > CB_MTRL_CONTEXT(cursor)->cb_data->count) {
        return cm_galist_new(CB_MTRL_CONTEXT(cursor)->cb_data, sizeof(cb_mtrl_data_t), (pointer_t *)cb_mtrl_data);
    }
    *cb_mtrl_data = sql_connect_mtrl_get_cb_data(cursor, level);
    return OG_SUCCESS;
}

static inline void sql_connect_mtrl_add_level(sql_cursor_t *cursor)
{
    CB_MTRL_CONTEXT(cursor)->curr_level++;
}

static inline status_t sql_connect_mtrl_delete_level(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level)
{
    mtrl_rowid_t *rowid = sql_connect_mtrl_get_prior_row(cursor, level);
    if (IS_VALID_MTRL_ROWID(*rowid)) {
        OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), rowid));
        *rowid = g_invalid_entry;
    }
    CB_MTRL_CONTEXT(cursor)->curr_level--;
    return OG_SUCCESS;
}

static inline status_t sql_connect_mtrl_push_cursor(sql_stmt_t *stmt, sql_cursor_t *dst_cursor)
{
    if (dst_cursor->connect_data.last_level_cursor != NULL) {
        OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, dst_cursor->connect_data.last_level_cursor));
    }
    return SQL_CURSOR_PUSH(stmt, dst_cursor);
}

static inline void sql_connect_mtrl_pop_cursor(sql_stmt_t *ogsql_stmt, sql_cursor_t *dst_cursor)
{
    SQL_CURSOR_POP(ogsql_stmt);
    if (dst_cursor->connect_data.last_level_cursor != NULL) {
        SQL_CURSOR_POP(ogsql_stmt);
    }
}

static status_t sql_fetch_vm_row(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *rids)
{
    row_addr_t *rows = cursor->exec_data.join;
    mtrl_context_t *mtrl_ctx = ((cursor->hash_join_ctx != NULL) && (cursor->hash_join_ctx->mtrl_ctx != NULL)) ?
        (cursor->hash_join_ctx->mtrl_ctx) :
        (&stmt->mtrl);
    return sql_mtrl_fetch_tables_row(mtrl_ctx, &cursor->mtrl.cursor, rows, rids, cursor->table_count);
}

static status_t sql_get_one_row(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf, uint32 old_size,
    bool32 found)
{
    mtrl_rowid_t *vmids = NULL;
    row_head_t *row_head = NULL;
    sql_cursor_t *hash_cursor = (sql_cursor_t *)callback_ctx;
    sql_stmt_t *stmt = hash_cursor->stmt;

    row_head = (row_head_t *)old_buf;
    vmids = (mtrl_rowid_t *)(old_buf + row_head->size);
    return sql_fetch_vm_row(stmt, hash_cursor, vmids);
}

static inline status_t sql_connect_mtrl_init_table(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    cb_mtrl_ctx_t *ogx)
{
    uint32 bucket_num = sql_get_plan_hash_rows(stmt, plan);
    OG_RETURN_IFERR(vm_hash_table_alloc(&ogx->hash_table, &ogx->hash_segment, bucket_num));
    return vm_hash_table_init(&ogx->hash_segment, &ogx->hash_table, NULL, sql_get_one_row, cursor);
}

static status_t sql_alloc_connect_mtrl_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 vmid;
    vm_page_t *page = NULL;
    cb_mtrl_ctx_t *mtrl_ctx = NULL;

    OG_RETURN_IFERR(vm_alloc(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, &vmid));
    if (vm_open(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid, &page) != OG_SUCCESS) {
        vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid);
        return OG_ERROR;
    }
    mtrl_ctx = (cb_mtrl_ctx_t *)page->data;
    mtrl_ctx->cb_mtrl_p = &plan->cb_mtrl;
    mtrl_ctx->vmid = vmid;
    mtrl_ctx->hash_table_rs = OG_INVALID_ID32;
    mtrl_ctx->empty = OG_TRUE;
    mtrl_ctx->curr_cursor = NULL;
    mtrl_ctx->last_cursor = NULL;
    mtrl_ctx->next_cursor = NULL;
    mtrl_ctx->key_types = NULL;
    mtrl_ctx->curr_level = 0;

    if (vmc_alloc(&cursor->vmc, sizeof(galist_t), (void **)&mtrl_ctx->cb_data) != OG_SUCCESS) {
        vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid);
        return OG_ERROR;
    }
    cm_galist_init(mtrl_ctx->cb_data, &cursor->vmc, vmc_alloc);

    vm_hash_segment_init(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, &mtrl_ctx->hash_segment, PMA_POOL,
        HASH_PAGES_HOLD,
        HASH_AREA_SIZE);

    if (sql_connect_mtrl_init_table(stmt, cursor, plan, mtrl_ctx) != OG_SUCCESS) {
        vm_hash_segment_deinit(&mtrl_ctx->hash_segment);
        vm_free(KNL_SESSION(stmt), KNL_SESSION(stmt)->temp_pool, vmid);
        return OG_ERROR;
    }
    cursor->cb_mtrl_ctx = mtrl_ctx;
    return OG_SUCCESS;
}

static status_t sql_make_connect_mtrl_rs_row(sql_stmt_t *stmt, sql_cursor_t *cursor, cb_mtrl_ctx_t *ogx,
    mtrl_rowid_t *rids, uint32 rids_count)
{
    char *buf = NULL;
    sql_table_t *table = NULL;
    sql_array_t *rs_tables = ogx->cb_mtrl_p->rs_tables;

    if (SECUREC_UNLIKELY(rs_tables->count > rids_count)) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "Join table count <= %u", rids_count);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));
    for (uint32 i = 0; i < rs_tables->count; ++i) {
        table = (sql_table_t *)sql_array_get(rs_tables, i);
        if (table->subslct_tab_usage != SUBSELECT_4_NORMAL_JOIN) {
            OG_RETURN_IFERR(sql_make_mtrl_null_rs_row(&stmt->mtrl, ogx->hash_table_rs, &rids[i]));
        } else {
            OG_RETURN_IFERR(sql_make_mtrl_table_rs_row(stmt, cursor, cursor->tables, table, buf, OG_MAX_ROW_SIZE));
            OG_RETURN_IFERR(mtrl_insert_row(&stmt->mtrl, ogx->hash_table_rs, buf, &rids[i]));
        }
    }
    OGSQL_POP(stmt);
    return OG_SUCCESS;
}

static inline status_t sql_mtrl_row_append_data(char *row_buf, uint32 *size, const char *in_buf, uint32 buf_size)
{
    row_head_t *row_head = (row_head_t *)row_buf;
    if (buf_size + row_head->size > OG_MAX_ROW_SIZE) {
        OG_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, buf_size + row_head->size, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_sp(row_buf + row_head->size, OG_MAX_ROW_SIZE - row_head->size, in_buf, buf_size));
    *size = buf_size + row_head->size;
    return OG_SUCCESS;
}

static inline status_t sql_init_connect_mtrl_cursor(sql_stmt_t *stmt, sql_cursor_t *query_cur, sql_cursor_t *cursor)
{
    status_t status;
    query_cur->connect_data.last_level_cursor = cursor;
    status = sql_open_cursors(stmt, query_cur, cursor->query, CURSOR_ACTION_SELECT, OG_TRUE);
    query_cur->connect_data.last_level_cursor = NULL;
    query_cur->cond = cursor->query->cond;
    return status;
}

static inline status_t sql_make_null_hash_key(char *buf, uint32 key_count)
{
    row_assist_t ra;
    row_init(&ra, buf, OG_MAX_ROW_SIZE, key_count);
    for (uint32 i = 0; i < key_count; ++i) {
        OG_RETURN_IFERR(row_put_null(&ra));
    }
    return OG_SUCCESS;
}

static status_t sql_connect_mtrl_build(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *query_cur,
    plan_node_t *plan)
{
    row_assist_t ra;
    bool32 found = OG_FALSE, has_null = OG_FALSE, eof = OG_FALSE;
    mtrl_rowid_t rids[OG_MAX_JOIN_TABLES];
    char *row_buf = NULL;
    uint32 row_size;
    status_t status = OG_ERROR;
    cb_mtrl_plan_t *cb_mtrl_p = &plan->cb_mtrl;

    // hash table rs
    OG_RETURN_IFERR(
        mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_HASHMAP_RS, NULL, &CB_MTRL_CONTEXT(cursor)->hash_table_rs));
    OG_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, CB_MTRL_CONTEXT(cursor)->hash_table_rs));
    OG_RETURN_IFERR(sql_init_connect_mtrl_cursor(stmt, query_cur, cursor));

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, query_cur));
    if (sql_execute_query_plan(stmt, query_cur, cb_mtrl_p->next) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(og_type_t) * cb_mtrl_p->key_exprs->count,
        (void **)&CB_MTRL_CONTEXT(cursor)->key_types));
    OG_RETURN_IFERR(sql_get_hash_key_types(stmt, query_cur->query, cb_mtrl_p->key_exprs, cb_mtrl_p->prior_exprs,
        CB_MTRL_CONTEXT(cursor)->key_types));

    if (sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&row_buf) != OG_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        return OG_ERROR;
    }
    OGSQL_SAVE_STACK(stmt);

    for (;;) {
        OG_BREAK_IF_ERROR(sql_fetch_query(stmt, query_cur, cb_mtrl_p->next, &eof));
        if (eof) {
            status = OG_SUCCESS;
            break;
        }

        OG_BREAK_IF_ERROR(
            sql_make_connect_mtrl_rs_row(stmt, query_cur, CB_MTRL_CONTEXT(cursor), rids, OG_MAX_JOIN_TABLES));
        OG_BREAK_IF_ERROR(
            sql_make_hash_key(stmt, &ra, row_buf, cb_mtrl_p->key_exprs, CB_MTRL_CONTEXT(cursor)->key_types, &has_null));
        if (has_null) {
            OG_BREAK_IF_ERROR(sql_make_null_hash_key(row_buf, cb_mtrl_p->key_exprs->count));
        }
        OG_BREAK_IF_ERROR(sql_mtrl_row_append_data(row_buf, &row_size, (const char *)rids,
            cb_mtrl_p->rs_tables->count * sizeof(mtrl_rowid_t)));
        OG_BREAK_IF_ERROR(vm_hash_table_insert(&found, CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, row_buf, row_size));
        CB_MTRL_CONTEXT(cursor)->empty = OG_FALSE;
        OGSQL_RESTORE_STACK(stmt);
    }
    OGSQL_RESTORE_STACK(stmt);
    OGSQL_POP(stmt);
    SQL_CURSOR_POP(stmt);
    mtrl_close_segment(&stmt->mtrl, CB_MTRL_CONTEXT(cursor)->hash_table_rs);
    return status;
}

static status_t sql_connect_mtrl_init_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->exec_data.join != NULL) {
        return OG_SUCCESS;
    }

    uint32 table_count = CB_MTRL_CONTEXT(cursor)->cb_mtrl_p->rs_tables->count;
    mtrl_row_t *row = NULL;
    sql_table_cursor_t *tab_cur = NULL;
    cursor->last_table = OG_INVALID_ID32; // for join clause
    OG_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(row_addr_t) * table_count, (void **)&cursor->exec_data.join));

    for (uint32 i = 0; i < table_count; ++i) {
        tab_cur = &cursor->tables[i];
        if (OG_IS_SUBSELECT_TABLE(tab_cur->table->type)) {
            row = &tab_cur->sql_cur->mtrl.cursor.row;
            sql_init_row_addr(stmt, cursor, &row->data, row->offsets, row->lens, NULL, NULL, i);
            sql_open_select_cursor(stmt, tab_cur->sql_cur, tab_cur->sql_cur->plan->select_p.rs_columns);
        } else if (tab_cur->table->remote_type == REMOTE_TYPE_LOCAL) {
            sql_init_row_addr(stmt, cursor, (char **)&tab_cur->knl_cur->row, tab_cur->knl_cur->offsets,
                tab_cur->knl_cur->lens, &tab_cur->knl_cur->rowid, NULL, i);
        } else {
		knl_panic(0);
        }
    }
    return OG_SUCCESS;
}

static status_t sql_connect_mtrl_get_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t **dst_cursor)
{
    if (*dst_cursor != NULL) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_alloc_cursor(stmt, dst_cursor));
    (*dst_cursor)->eof = OG_TRUE;
    (*dst_cursor)->scn = cursor->scn;
    (*dst_cursor)->ancestor_ref = cursor->ancestor_ref;
    (*dst_cursor)->connect_data.last_level_cursor = cursor->connect_data.first_level_cursor;
    (*dst_cursor)->connect_data.next_level_cursor = NULL;
    (*dst_cursor)->connect_data.first_level_cursor = cursor->connect_data.first_level_cursor;

    OG_RETURN_IFERR(sql_open_cursors(stmt, *dst_cursor, cursor->query, CURSOR_ACTION_SELECT, OG_TRUE));

    return sql_connect_mtrl_init_cursor(stmt, *dst_cursor);
}

static inline void sql_connect_mtrl_init_next_data(sql_cursor_t *cursor, cb_mtrl_data_t *level_data)
{
    cb_mtrl_data_t *first_level_data = sql_connect_mtrl_get_cb_data(cursor, 1);

    sql_init_hash_iter(&level_data->iter, CB_MTRL_NEXT_CURSOR);
    level_data->iter.hash_table = first_level_data->iter.hash_table;
    level_data->iter.scan_mode = HASH_KEY_SCAN;
    level_data->level_entry.vmid = OG_INVALID_ID32;
    level_data->prior_row = g_invalid_entry;
}

static inline status_t sql_connect_mtrl_build_cursor(sql_cursor_t *cursor, sql_cursor_t *dst_cursor,
    hash_entry_t *entry)
{
    bool32 level_eof = OG_FALSE;
    CB_MTRL_TEMP_ITER->callback_ctx = dst_cursor;
    CB_MTRL_TEMP_ITER->curr_match = *entry;
    return vm_hash_table_fetch(&level_eof, CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, CB_MTRL_TEMP_ITER);
}

static status_t sql_connect_mtrl_make_prior_row(sql_stmt_t *stmt, sql_cursor_t *dst_cursor, char *buf, row_assist_t *ra)
{
    galist_t *prior_exprs = dst_cursor->connect_data.first_level_cursor->connect_data.prior_exprs;
    expr_node_t *node = NULL;
    status_t status;
    variant_t value;

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, dst_cursor));
    row_init(ra, buf, OG_MAX_ROW_SIZE, prior_exprs->count);
    for (uint32 i = 0; i < prior_exprs->count; i++) {
        node = (expr_node_t *)cm_galist_get(prior_exprs, i);
        status = sql_exec_expr_node(stmt, node, &value);
        OG_BREAK_IF_ERROR(status);
        if (OG_IS_LOB_TYPE(value.type)) {
            status = sql_get_lob_value(stmt, &value);
            OG_BREAK_IF_ERROR(status);
        }
        status = sql_put_row_value(stmt, NULL, ra, value.type, &value);
        OG_BREAK_IF_ERROR(status);
    }
    SQL_CURSOR_POP(stmt);
    return status;
}

static status_t sql_connect_mtrl_insert_prior_row(sql_stmt_t *stmt, sql_cursor_t *dst_cursor, uint32 level)
{
    mtrl_rowid_t *prior_row = sql_connect_mtrl_get_prior_row(dst_cursor, level);
    char *buf = NULL;
    row_assist_t ra;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&buf));
    if (sql_connect_mtrl_make_prior_row(stmt, dst_cursor, buf, &ra) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (IS_VALID_MTRL_ROWID(*prior_row)) { // When traversing to the sibling node, prior_row needs to be released.
        if (vmctx_free(GET_VM_CTX(stmt), prior_row) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
        *prior_row = g_invalid_entry;
    }
    status_t status = vmctx_insert(GET_VM_CTX(stmt), (const char *)buf, ra.head->size, prior_row);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static inline void sql_connect_mtrl_close_vmctx_page(sql_stmt_t *stmt, mtrl_rowid_t *mtrl_rowid)
{
    if (mtrl_rowid->vmid != OG_INVALID_ID32) {
        vmctx_close_row_id(GET_VM_CTX(stmt), mtrl_rowid);
    }
}

static status_t sql_connect_mtrl_check_iscycle(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_cursor_t *dst_cursor,
    bool32 *is_cycle)
{
    char *lbuf = NULL;
    char *rbuf = NULL;
    uint32 level = sql_connect_mtrl_get_level(cursor);
    row_assist_t ra;
    mtrl_rowid_t cur_mtrl_rowid = g_invalid_entry;
    vm_page_t *opened_page = NULL;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&lbuf));
    if (sql_connect_mtrl_make_prior_row(stmt, dst_cursor, lbuf, &ra) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    for (uint32 i = level - 1; i > 0; i--) {
        mtrl_rowid_t *rowid = sql_connect_mtrl_get_prior_row(cursor, i);
        if (cur_mtrl_rowid.vmid != rowid->vmid) {
            sql_connect_mtrl_close_vmctx_page(stmt, &cur_mtrl_rowid);
            cur_mtrl_rowid.vmid = rowid->vmid;
            if (vm_open(GET_VM_CTX(stmt)->session, GET_VM_CTX(stmt)->pool, rowid->vmid, &opened_page) != OG_SUCCESS) {
                OG_THROW_ERROR_EX(ERR_VM, "failed to open row id vm id %u, vm slot %u", rowid->vmid, rowid->slot);
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
        }

        rbuf = VMCTX_GET_DATA(opened_page, rowid);
        *is_cycle = cm_row_equal(lbuf, rbuf);
        if (*is_cycle) {
            if (!cursor->query->connect_by_nocycle) {
                sql_connect_mtrl_close_vmctx_page(stmt, &cur_mtrl_rowid);
                OG_THROW_ERROR(ERR_CONNECT_BY_LOOP);
                OGSQL_RESTORE_STACK(stmt);
                return OG_ERROR;
            }
            break;
        }
    }
    sql_connect_mtrl_close_vmctx_page(stmt, &cur_mtrl_rowid);
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static inline status_t sql_connect_mtrl_fetch_data(sql_stmt_t *stmt, sql_cursor_t *cursor, hash_table_iter_t *iter,
    bool32 *result, bool32 *eof)
{
    *result = OG_FALSE;
    *eof = OG_FALSE;
    OG_RETURN_IFERR(vm_hash_table_fetch(eof, CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, iter));

    if (*eof || CB_MTRL_PLAN->connect_by_cond == NULL) {
        return OG_SUCCESS;
    }
    return sql_match_cond_node(stmt, CB_MTRL_PLAN->connect_by_cond->root, result);
}

static inline void sql_connect_mtrl_init_next_cursor(sql_cursor_t *cursor, sql_cursor_t *curr_cursor, uint32 level)
{
    curr_cursor->connect_data.next_level_cursor = CB_MTRL_NEXT_CURSOR;
    CB_MTRL_NEXT_CURSOR->connect_data.last_level_cursor = curr_cursor;
    CB_MTRL_NEXT_CURSOR->connect_data.level = level;
    CB_MTRL_NEXT_CURSOR->rownum = curr_cursor->rownum + 1;
}

static status_t sql_connect_mtrl_get_next_level(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level, bool32 *eof,
    bool32 *last_is_cycle)
{
    bool32 result = OG_FALSE;
    bool32 is_cycle = OG_FALSE;
    cb_mtrl_data_t *cb_mtrl_data = sql_connect_mtrl_get_cb_data(cursor, level);
    hash_table_iter_t *iter_next = sql_connect_mtrl_get_iter(cursor, level);

    OG_RETURN_IFERR(sql_connect_mtrl_get_first_entry(stmt, cursor, iter_next));
    do {
        cb_mtrl_data->level_entry = iter_next->curr_match;
        OG_RETURN_IFERR(sql_connect_mtrl_fetch_data(stmt, cursor, iter_next, &result, eof));

        if (*eof) {
            return OG_SUCCESS;
        }

        if (!result) {
            continue;
        }
        OG_RETURN_IFERR(sql_connect_mtrl_check_iscycle(stmt, cursor, CB_MTRL_NEXT_CURSOR, &is_cycle));

        if (!is_cycle) {
            break;
        }
        *last_is_cycle = OG_TRUE;
    } while (1);
    return OG_SUCCESS;
}

static status_t sql_connect_mtrl_execute_next_level(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level)
{
    cb_mtrl_data_t *cb_mtrl_data = NULL;
    bool32 eof = OG_FALSE;
    hash_table_iter_t *iter_next = NULL;
    bool32 is_cycle = OG_FALSE;
    sql_cursor_t *curr_cursor = cursor->connect_data.cur_level_cursor;
    OG_RETURN_IFERR(sql_connect_mtrl_get_cursor(stmt, cursor, &CB_MTRL_NEXT_CURSOR));
    sql_connect_mtrl_init_next_cursor(cursor, curr_cursor, level);

    sql_connect_mtrl_add_level(cursor);
    OG_RETURN_IFERR(sql_connect_mtrl_alloc_cb_data(cursor, level, &cb_mtrl_data));
    sql_connect_mtrl_init_next_data(cursor, cb_mtrl_data);
    iter_next = &(cb_mtrl_data->iter);
    iter_next->callback_ctx = CB_MTRL_NEXT_CURSOR;

    OG_RETURN_IFERR(sql_connect_mtrl_insert_prior_row(stmt, curr_cursor, level - 1));
    OG_RETURN_IFERR(sql_connect_mtrl_push_cursor(stmt, CB_MTRL_NEXT_CURSOR));
    if (sql_connect_mtrl_get_next_level(stmt, cursor, level, &eof, &is_cycle) != OG_SUCCESS) {
        sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_NEXT_CURSOR);
        return OG_ERROR;
    }
    sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_NEXT_CURSOR);
    if (is_cycle) {
        curr_cursor->connect_data.connect_by_iscycle = OG_TRUE;
    }

    if (eof) {
        OG_RETURN_IFERR(sql_connect_mtrl_delete_level(stmt, cursor, level));
        curr_cursor->connect_data.next_level_cursor = NULL;
        curr_cursor->connect_data.connect_by_isleaf = OG_TRUE;
        return OG_SUCCESS;
    }

    iter_next->curr_match = cb_mtrl_data->level_entry;
    cb_mtrl_data->level_entry.vmid = OG_INVALID_ID32;
    curr_cursor->connect_data.connect_by_isleaf = OG_FALSE;
    return OG_SUCCESS;
}

static status_t sql_connect_mtrl_open_first_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    bool32 found = OG_FALSE;
    hash_scan_assist_t scan_assist = { HASH_FULL_SCAN, NULL, 0 };
    cb_mtrl_data_t *cb_mtrl_data = NULL;
    hash_table_iter_t *iter = NULL;

    OG_RETURN_IFERR(sql_connect_mtrl_init_cursor(stmt, cursor));
    sql_connect_mtrl_add_level(cursor);
    OG_RETURN_IFERR(sql_connect_mtrl_alloc_cb_data(cursor, 1, &cb_mtrl_data));
    cb_mtrl_data->level_entry.vmid = OG_INVALID_ID32;
    cb_mtrl_data->prior_row = g_invalid_entry;

    iter = &(cb_mtrl_data->iter);
    sql_init_hash_iter(iter, cursor);
    OG_RETURN_IFERR(vm_hash_table_open(CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, &scan_assist, &found, iter));
    MEMS_RETURN_IFERR(memcpy_sp(CB_MTRL_TEMP_ITER, sizeof(hash_table_iter_t), iter, sizeof(hash_table_iter_t)));
    CB_MTRL_TEMP_ITER->scan_mode = HASH_KEY_SCAN;
    return OG_SUCCESS;
}

static inline status_t sql_connect_mtrl_open_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    if (cursor->connect_data.cur_level_cursor == NULL) {
        return sql_connect_mtrl_open_first_cursor(stmt, cursor);
    }
    return sql_connect_mtrl_execute_next_level(stmt, cursor, CB_MTRL_SECOND_LEVEL);
}

status_t sql_execute_connect_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    sql_cursor_t *query_cur = NULL;
    if (cursor->cb_mtrl_ctx == NULL) {
        OG_RETURN_IFERR(sql_alloc_connect_mtrl_ctx(stmt, cursor, plan));
        OG_RETURN_IFERR(sql_alloc_cursor(stmt, &query_cur));
        if (sql_connect_mtrl_build(stmt, cursor, query_cur, plan) != OG_SUCCESS) {
            sql_free_cursor(stmt, query_cur);
            return OG_ERROR;
        }
        sql_free_cursor(stmt, query_cur);
        if (cursor->connect_data.cur_level_cursor != NULL) {
            OG_RETURN_IFERR(sql_connect_mtrl_open_first_cursor(stmt, cursor));
        }
    }
    return sql_connect_mtrl_open_cursor(stmt, cursor);
}

static status_t sql_connect_mtrl_fetch_first_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *eof)
{
    bool32 result = OG_FALSE;
    hash_table_iter_t *iter = sql_connect_mtrl_get_iter(cursor, 1);

    if (CB_MTRL_CONTEXT(cursor)->empty) {
        *eof = OG_TRUE;
        return OG_SUCCESS;
    }

    for (;;) {
        if (vm_hash_table_fetch(eof, CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, iter) != OG_SUCCESS) {
            iter->curr_match.vmid = OG_INVALID_ID32;
            return OG_ERROR;
        }
        if (*eof || CB_MTRL_PLAN->start_with_cond == NULL) {
            break;
        }
        OG_RETURN_IFERR(sql_match_cond_node(stmt, CB_MTRL_PLAN->start_with_cond->root, &result));
        if (result) {
            break;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_make_connect_mtrl_scan_key(sql_stmt_t *stmt, sql_cursor_t *cursor, cb_mtrl_plan_t *cb_mtrl,
    char *buf, bool32 *has_null)
{
    row_assist_t ra;
    return sql_make_hash_key(stmt, &ra, buf, cb_mtrl->prior_exprs, CB_MTRL_CONTEXT(cursor)->key_types, has_null);
}

static status_t sql_connect_mtrl_build_last_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level)
{
    if (level == CB_MTRL_SECOND_LEVEL) {
        // the last cursor is first cursor, do not need build
        return OG_SUCCESS;
    }
    cb_mtrl_data_t *cb_data = sql_connect_mtrl_get_cb_data(cursor, level - 1);
    hash_entry_t *entry = &cb_data->level_entry;
    OG_RETURN_IFERR(sql_connect_mtrl_get_cursor(stmt, cursor, &CB_MTRL_LAST_CURSOR));
    return sql_connect_mtrl_build_cursor(cursor, CB_MTRL_LAST_CURSOR, entry);
}

static status_t sql_connect_mtrl_fetch_curr_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level, bool32 *eof)
{
    bool32 is_cycle = OG_FALSE;
    bool32 result = OG_FALSE;
    hash_entry_t *entry = &(sql_connect_mtrl_get_cb_data(cursor, level))->level_entry;
    hash_entry_t tmp_entry = *entry;
    hash_table_iter_t *iter = sql_connect_mtrl_get_iter(cursor, level);
    iter->callback_ctx = CB_MTRL_CURR_CURSOR;

    OG_RETURN_IFERR(sql_connect_mtrl_push_cursor(stmt, CB_MTRL_CURR_CURSOR));
    do {
        *entry = iter->curr_match;
        if (sql_connect_mtrl_fetch_data(stmt, cursor, iter, &result, eof) != OG_SUCCESS) {
            sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_CURR_CURSOR);
            return OG_ERROR;
        }

        if (*eof) {
            sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_CURR_CURSOR);
            return OG_SUCCESS;
        }
        if (!result) {
            continue;
        }

        // the first iter data has been checked in sql_connect_mtrl_execute_next_level.
        if (tmp_entry.vmid != OG_INVALID_ID32 &&
            sql_connect_mtrl_check_iscycle(stmt, cursor, CB_MTRL_CURR_CURSOR, &is_cycle) != OG_SUCCESS) {
            sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_CURR_CURSOR);
            return OG_ERROR;
        }
        if (!is_cycle) {
            break;
        }
    } while (1);
    sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_CURR_CURSOR);
    return OG_SUCCESS;
}

static status_t sql_connect_mtrl_set_iscycle(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level)
{
    sql_cursor_t *curr_cursor = cursor->connect_data.cur_level_cursor;
    if (curr_cursor->connect_data.connect_by_isleaf || curr_cursor->connect_data.connect_by_iscycle) {
        return OG_SUCCESS;
    }

    bool32 is_cycle = OG_FALSE;
    bool32 result = OG_FALSE;
    bool32 level_eof = OG_FALSE;
    OG_RETURN_IFERR(sql_connect_mtrl_get_cursor(stmt, cursor, &CB_MTRL_NEXT_CURSOR));
    sql_connect_mtrl_init_next_cursor(cursor, curr_cursor, level);
    cb_mtrl_data_t *cb_data = sql_connect_mtrl_get_cb_data(cursor, level);
    hash_table_iter_t *iter_next = &cb_data->iter;
    hash_table_iter_t iter_save = *iter_next;
    iter_next->callback_ctx = CB_MTRL_NEXT_CURSOR;

    OG_RETURN_IFERR(sql_connect_mtrl_push_cursor(stmt, CB_MTRL_NEXT_CURSOR));
    // the first iter data has been checked in sql_connect_mtrl_execute_next_level.
    if (vm_hash_table_fetch(&level_eof, CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, iter_next) != OG_SUCCESS) {
        sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_NEXT_CURSOR);
        return OG_ERROR;
    }

    do {
        if (sql_connect_mtrl_fetch_data(stmt, cursor, iter_next, &result, &level_eof) != OG_SUCCESS) {
            sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_NEXT_CURSOR);
            return OG_ERROR;
        }

        if (level_eof) {
            break;
        }

        if (!result) {
            continue;
        }

        if (sql_connect_mtrl_check_iscycle(stmt, cursor, CB_MTRL_NEXT_CURSOR, &is_cycle) != OG_SUCCESS) {
            sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_NEXT_CURSOR);
            return OG_ERROR;
        }

        if (is_cycle) {
            curr_cursor->connect_data.connect_by_iscycle = OG_TRUE;
            break;
        }
    } while (1);

    cb_data->iter = iter_save;
    sql_connect_mtrl_pop_cursor(stmt, CB_MTRL_NEXT_CURSOR);
    return OG_SUCCESS;
}

static inline void sql_connect_mtrl_init_curr_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level)
{
    sql_cursor_t *last_cursor = (level > CB_MTRL_SECOND_LEVEL) ? CB_MTRL_LAST_CURSOR : cursor;
    last_cursor->connect_data.next_level_cursor = CB_MTRL_CURR_CURSOR;

    CB_MTRL_CURR_CURSOR->connect_data.last_level_cursor = last_cursor;
    CB_MTRL_CURR_CURSOR->connect_data.connect_by_isleaf = OG_FALSE;
    CB_MTRL_CURR_CURSOR->connect_data.connect_by_iscycle = OG_FALSE;
    CB_MTRL_CURR_CURSOR->connect_data.level = level;
    CB_MTRL_CURR_CURSOR->rownum = cursor->rownum;
}

static status_t sql_connect_mtrl_get_curr_data(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level, bool32 *level_eof)
{
    if (sql_connect_mtrl_get_iter(cursor, level)->curr_match.vmid == OG_INVALID_ID32) {
        *level_eof = OG_TRUE;
        return OG_SUCCESS;
    }

    if (CB_MTRL_CURR_CURSOR->connect_data.level != level || !CB_MTRL_CURR_CURSOR->connect_data.connect_by_isleaf) {
        OG_RETURN_IFERR(sql_connect_mtrl_build_last_cursor(stmt, cursor, level));
    }
    cursor->connect_data.cur_level_cursor = NULL;
    sql_connect_mtrl_init_curr_cursor(stmt, cursor, level);
    return sql_connect_mtrl_fetch_curr_cursor(stmt, cursor, level, level_eof);
}

static inline void sql_connect_mtrl_reset_path(sql_cursor_t *cursor)
{
    for (uint32 i = 0; i < cursor->connect_data.path_func_nodes->count; i++) {
        cm_pop(cursor->connect_data.path_stack + i); // reset sys_connect_by_path
    }
}

static status_t sql_connect_mtrl_fetch_next_level(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 level, bool32 *eof)
{
    bool32 level_eof = OG_FALSE;
    // Multiple recursion, cannot use OG_RETURN_IFERR().
    if (sql_stack_safe(stmt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_connect_mtrl_get_curr_data(stmt, cursor, level, &level_eof) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!level_eof) {
        cursor->connect_data.cur_level_cursor = CB_MTRL_CURR_CURSOR;
        if (sql_connect_mtrl_execute_next_level(stmt, cursor, level + 1) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (cursor->query->connect_by_iscycle && cursor->query->connect_by_prior) {
            if (sql_connect_mtrl_set_iscycle(stmt, cursor, level + 1) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    } else {
        if (sql_connect_mtrl_delete_level(stmt, cursor, level) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_connect_mtrl_reset_path(cursor);

        if (level == CB_MTRL_SECOND_LEVEL) {
            *eof = OG_TRUE;
        } else if (level > CB_MTRL_SECOND_LEVEL) {
            return sql_connect_mtrl_fetch_next_level(stmt, cursor, level - 1, eof);
        }
    }

    return OG_SUCCESS;
}

static status_t sql_connect_mtrl_get_first_entry(sql_stmt_t *stmt, sql_cursor_t *cursor, hash_table_iter_t *iter)
{
    char *key_buf = NULL;
    bool32 found = OG_FALSE;
    bool32 has_null = OG_FALSE;
    hash_scan_assist_t scan_assist;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&key_buf));
    if (sql_make_connect_mtrl_scan_key(stmt, cursor, CB_MTRL_PLAN, key_buf, &has_null) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (has_null) {
        OGSQL_RESTORE_STACK(stmt);
        iter->curr_match.vmid = OG_INVALID_ID32;
        return OG_SUCCESS;
    }

    scan_assist.scan_mode = HASH_KEY_SCAN;
    scan_assist.buf = key_buf;
    scan_assist.size = ((row_head_t *)key_buf)->size;
    if (vm_hash_table_open(CB_MTRL_SEGMENT, CB_MTRL_TABLE_ENTRY, &scan_assist, &found, iter) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    if (!found) {
        iter->curr_match.vmid = OG_INVALID_ID32;
    }
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

status_t sql_fetch_connect_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    status_t status;
    CM_TRACE_BEGIN;
    uint32 level = sql_connect_mtrl_get_level(cursor);
    if (level == 1) {
        status = sql_connect_mtrl_fetch_first_cursor(stmt, cursor, eof);
    } else {
        OG_RETURN_IFERR(sql_connect_mtrl_get_cursor(stmt, cursor, &CB_MTRL_CURR_CURSOR));
        status = sql_connect_mtrl_fetch_next_level(stmt, cursor, level, eof);
    }
    CM_TRACE_END(stmt, plan->plan_id);
    return status;
}
