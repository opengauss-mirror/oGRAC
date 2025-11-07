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
 * ogsql_delete.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_delete.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_scan.h"
#include "ogsql_delete.h"
#include "ogsql_update.h"
#include "ogsql_select.h"
#include "ogsql_insert.h"
#include "ogsql_proj.h"

status_t sql_open_delete_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_delete_t *ogx)
{
    knl_cursor_action_t cursor_action;

    cursor_action = ogx->query->tables.count > 1 ? CURSOR_ACTION_FOR_UPDATE_SCAN : CURSOR_ACTION_DELETE;

    if (sql_open_cursors(stmt, cursor, ogx->query, cursor_action, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cursor->scn = OG_INVALID_ID64;
    cursor->plan = ogx->plan;
    cursor->delete_ctx = ogx;
    return OG_SUCCESS;
}

static status_t sql_execute_delete_trigs(sql_stmt_t *stmt, trig_set_t *set, uint32 type, void *knl_cur)
{
    pl_dc_t pl_dc;
    trig_item_t *trig_item = NULL;

    OGSQL_SAVE_STACK(stmt);
    for (uint32 i = 0; i < set->trig_count; ++i) {
        trig_item = &set->items[i];
        if (!trig_item->trig_enable) {
            continue;
        }

        if ((uint32)trig_item->trig_type != type || (trig_item->trig_event & TRIG_EVENT_DELETE) == 0) {
            continue;
        }

        if (pl_dc_open_trig_by_entry(stmt, &pl_dc, trig_item) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }

        if (ple_exec_trigger(stmt, pl_dc.entity, TRIG_EVENT_DELETE, knl_cur, NULL) != OG_SUCCESS) {
            ple_check_exec_trigger_error(stmt, pl_dc.entity);
            pl_dc_close(&pl_dc);
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }

        pl_dc_close(&pl_dc);
    }

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

status_t sql_execute_delete_triggers(sql_stmt_t *stmt, sql_table_t *table, uint32 type, void *knl_cur)
{
    knl_dictionary_t *dc = &table->entry->dc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;

    if (dc->type == DICT_TYPE_VIEW) {
        return OG_SUCCESS;
    }

    if (stmt->session->triggers_disable) {
        return OG_SUCCESS;
    }

    if (dc_entity->trig_set.trig_count == 0) {
        return OG_SUCCESS;
    }

    /* add TS lock, controls trigger concurrency */
    if (lock_table_shared(KNL_SESSION(stmt), dc_entity, LOCK_INF_WAIT) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_execute_delete_trigs(stmt, &dc_entity->trig_set, type, knl_cur);
}

static inline status_t sql_execute_delete_table(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *tab_cur)
{
    if (tab_cur->table->type == VIEW_AS_TABLE) {
        OG_RETURN_IFERR(sql_execute_delete_view_insteadof(stmt, tab_cur));
        cursor->total_rows++;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_execute_delete_triggers(stmt, tab_cur->table, TRIG_BEFORE_EACH_ROW, tab_cur->knl_cur));
    OG_RETURN_IFERR(knl_delete(&stmt->session->knl_session, tab_cur->knl_cur));

    /* if row is not found while delete, do not execute after trigger and foreign key check */
    if (tab_cur->knl_cur->is_found) {
        OG_RETURN_IFERR(sql_execute_delete_triggers(stmt, tab_cur->table, TRIG_AFTER_EACH_ROW, tab_cur->knl_cur));
        OG_RETURN_IFERR(knl_verify_children_dependency(&stmt->session->knl_session, tab_cur->knl_cur, false, 0, false));
        cursor->total_rows++;
    }

    return OG_SUCCESS;
}

static inline status_t sql_execute_delete_tables(sql_stmt_t *stmt, sql_cursor_t *cursor, delete_plan_t *del_plan,
    knl_cursor_t **knl_curs)
{
    status_t status;
    del_object_t *object = NULL;
    sql_table_cursor_t *tab_cursor = NULL;
    knl_cursor_t *knl_cursor = NULL;
    knl_savepoint_t savepoint;

    for (uint32 i = 0; i < del_plan->objects->count; i++) {
        object = (del_object_t *)cm_galist_get(del_plan->objects, i);
        tab_cursor = &cursor->tables[object->table->id];

        if (tab_cursor->knl_cur->eof || sql_is_invalid_rowid(&tab_cursor->knl_cur->rowid,
            tab_cursor->table->entry->dc.type)) {
            continue;
        }
        // for before row trigger
        knl_savepoint(KNL_SESSION(stmt), &savepoint);
        // update tab_cursor->knl_cur for function based index
        knl_cursor = tab_cursor->knl_cur;
        tab_cursor->knl_cur = (tab_cursor->hash_table ? knl_curs[object->table->id] : tab_cursor->knl_cur);
        status = sql_execute_delete_table(stmt, cursor, tab_cursor);
        if (status == OG_SUCCESS && !tab_cursor->knl_cur->is_found) {
            knl_rollback(KNL_SESSION(stmt), &savepoint);
            tab_cursor->knl_cur->is_found = OG_TRUE;
        }

        tab_cursor->knl_cur = knl_cursor;
        if (status == OG_ERROR) {
            return status;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_execute_rowid_delete_table(sql_stmt_t *stmt, sql_cursor_t *cursor, delete_plan_t *del_plan)
{
    bool32 is_found = OG_FALSE;
    variant_t value;
    rs_column_t *rs_col = NULL;
    sql_table_cursor_t *tab_cur = &cursor->tables[0];

    rs_col = (rs_column_t *)cm_galist_get(del_plan->rowid, 0);

    OG_RETURN_IFERR(sql_exec_expr(stmt, rs_col->expr, &value));

    OG_RETURN_IFERR(sql_var2rowid(&value, &tab_cur->knl_cur->rowid, tab_cur->knl_cur->dc_type));

    OG_RETURN_IFERR(knl_fetch_by_rowid(KNL_SESSION(stmt), tab_cur->knl_cur, &is_found));

    if (is_found) {
        OG_RETURN_IFERR(sql_execute_delete_table(stmt, cursor, tab_cur));
    }
    return OG_SUCCESS;
}


status_t sql_execute_delete_view_insteadof(sql_stmt_t *stmt, sql_table_cursor_t *tab_cur)
{
    knl_cursor_t *knl_cur = NULL;
    status_t status = OG_ERROR;

    CM_SAVE_STACK(stmt->session->stack);
    if (sql_alloc_knl_cursor(stmt, &knl_cur) != OG_SUCCESS) {
        CM_RESTORE_STACK(stmt->session->stack);
        return OG_ERROR;
    }
    if (sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&knl_cur->row) != OG_SUCCESS) {
        CM_RESTORE_STACK(stmt->session->stack);
        return OG_ERROR;
    }
    if (SQL_CURSOR_PUSH(stmt, tab_cur->sql_cur) != OG_SUCCESS) {
        CM_RESTORE_STACK(stmt->session->stack);
        return OG_ERROR;
    }
    do {
        OG_BREAK_IF_ERROR(sql_prepare_view_row_insteadof(stmt, tab_cur, knl_cur));
        OG_BREAK_IF_ERROR(sql_insteadof_triggers(stmt, tab_cur->table, knl_cur, NULL, TRIG_EVENT_DELETE));
        status = OG_SUCCESS;
    } while (0);

    sql_free_knl_cursor(stmt, knl_cur);
    SQL_CURSOR_POP(stmt);
    CM_RESTORE_STACK(stmt->session->stack);

    return status;
}

status_t sql_execute_single_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, sql_delete_t *del_ctx)
{
    sql_table_cursor_t *tab_cursor = &cursor->tables[0];
    knl_dictionary_t *dc = &tab_cursor->table->entry->dc;
    knl_session_t *knl_session = NULL;
    knl_handle_t knl_temp_cache = NULL;

    do {
        OG_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));
        if (cursor->eof) {
            /* return columns need has one row in PL */
            if (del_ctx->ret_columns != NULL && stmt->batch_rows == 0) {
                OG_RETURN_IFERR(sql_send_return_row(stmt, del_ctx->ret_columns, OG_TRUE));
            }
            break;
        }
        OG_RETURN_IFERR(sql_execute_delete_table(stmt, cursor, tab_cursor));
        /* gen return values if has return columns */
        if (del_ctx->ret_columns != NULL) {
            OG_RETURN_IFERR(sql_send_return_row(stmt, del_ctx->ret_columns, OG_FALSE));
        }
    } while (OG_TRUE);

    // free temp table vm after delete, because there may be row trigger
    if (cursor->total_rows > 0 && cursor->cond == NULL && dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_session = &stmt->session->knl_session;
        knl_temp_cache = knl_get_temp_cache(knl_session, dc->uid, dc->oid);
        if (knl_temp_cache != NULL) {
            knl_free_temp_vm(knl_session, knl_temp_cache);
        }
    }

    return OG_SUCCESS;
}

static status_t sql_execute_multi_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, cond_tree_t *cond, plan_node_t *plan,
    delete_plan_t *del_plan)
{
    status_t status = OG_ERROR;
    bool32 is_found = OG_FALSE;
    cond_tree_t *saved_cond = cursor->cond;
    knl_cursor_t *knl_curs[OG_MAX_JOIN_TABLES] = { 0 };

    OGSQL_SAVE_STACK(stmt);

    if (sql_init_multi_update(stmt, cursor, CURSOR_ACTION_DELETE, knl_curs) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));
        if (cursor->eof) {
            status = OG_SUCCESS;
            break;
        }
        cursor->cond = cond;
        OG_BREAK_IF_ERROR(sql_lock_row(stmt, cursor, knl_curs, CURSOR_ACTION_DELETE, &is_found));
        if (is_found) {
            OG_BREAK_IF_ERROR(sql_execute_delete_tables(stmt, cursor, del_plan, knl_curs));
        }
        sql_reset_cursor_action(cursor, CURSOR_ACTION_FOR_UPDATE_SCAN);
        cursor->cond = saved_cond;
    } while (OG_TRUE);

    cursor->cond = saved_cond;
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t sql_execute_rowid_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    delete_plan_t *del_plan)
{
    do {
        OG_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan, &cursor->eof));
        if (cursor->eof) {
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(sql_execute_rowid_delete_table(stmt, cursor, del_plan));
    } while (OG_TRUE);
}

static inline status_t sql_execute_delete_restart_core(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_delete_t *del_ctx,
    plan_node_t *plan)
{
    sql_set_scn(stmt);
    sql_set_ssn(stmt);

    OG_RETURN_IFERR(sql_open_delete_cursor(stmt, cursor, del_ctx));

    OG_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan));

    return sql_execute_lock_row(stmt, cursor, del_ctx->cond, plan, del_ctx->query);
}


static status_t sql_execute_delete_restart(sql_stmt_t *stmt)
{
    status_t status = OG_ERROR;
    uint32 count = 0;
    sql_cursor_t *cursor = OGSQL_ROOT_CURSOR(stmt);
    sql_delete_t *del_ctx = (sql_delete_t *)stmt->context->entry;
    delete_plan_t *del_plan = &del_ctx->plan->delete_p;
    plan_node_t *plan = del_plan->next->query.next;

    OGSQL_SAVE_STACK(stmt);

    for (;;) {
        OGSQL_RESTORE_STACK(stmt);
        count++;

        status = sql_execute_delete_restart_core(stmt, cursor, del_ctx, plan);
        if (status == OG_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            cm_reset_error();
            OG_LOG_DEBUG_INF("delete lock row failed, lock row restart %u time(s), sid[%u] rmid[%u]", count,
                stmt->session->knl_session.id, stmt->session->knl_session.rmid);
            continue;
        } else {
            break;
        }
    }

    OGSQL_RESTORE_STACK(stmt);

    return status;
}


static status_t sql_execute_delete_core(sql_stmt_t *stmt)
{
    plan_node_t *plan = NULL;
    sql_delete_t *del_ctx = NULL;
    sql_cursor_t *cursor = OGSQL_ROOT_CURSOR(stmt);
    delete_plan_t *del_plan = NULL;
    uint64 conflicts = 0;

    cursor->total_rows = 0;

    del_ctx = (sql_delete_t *)stmt->context->entry;
    del_plan = &del_ctx->plan->delete_p;
    plan = del_plan->next->query.next;

    knl_init_index_conflicts(KNL_SESSION(stmt), &conflicts);
    OG_RETURN_IFERR(sql_execute_del_stmt_trigs(stmt, del_plan, TRIG_BEFORE_STATEMENT));

    // set statement ssn after the before statement triggers executed
    sql_set_scn(stmt);
    sql_set_ssn(stmt);

    OG_RETURN_IFERR(sql_open_delete_cursor(stmt, cursor, del_ctx));

    OG_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan));

    if (del_plan->rowid->count > 0) {
        cursor->cond = NULL;                                    // reset cursor->cond
        cursor->tables[0].knl_cur->scan_mode = SCAN_MODE_ROWID; // reset scan_mode
        cursor->tables[0].knl_cur->eof = OG_FALSE;              // reset eof flag
        cursor->tables[0].knl_cur->is_valid = OG_TRUE;
        cursor->tables[0].knl_cur->action = CURSOR_ACTION_DELETE;
        OG_RETURN_IFERR(sql_execute_rowid_delete(stmt, cursor, plan, del_plan));
    } else if (del_ctx->query->tables.count > 1) {
        OG_RETURN_IFERR(sql_execute_multi_delete(stmt, cursor, del_ctx->cond, plan, del_plan));
    } else {
        OG_RETURN_IFERR(sql_execute_single_delete(stmt, cursor, plan, del_ctx));
    }
    OG_RETURN_IFERR(sql_execute_del_stmt_trigs(stmt, del_plan, TRIG_AFTER_STATEMENT));
    OG_RETURN_IFERR(knl_check_index_conflicts(KNL_SESSION(stmt), conflicts));
    stmt->eof = OG_TRUE;
    return OG_SUCCESS;
}


status_t sql_execute_delete(sql_stmt_t *stmt)
{
    status_t status = OG_ERROR;
    knl_savepoint_t sp;

    do {
        knl_savepoint(KNL_SESSION(stmt), &sp);
        status = sql_execute_delete_core(stmt);
        // execute delete failed when shrink table, need restart
        if (status == OG_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            cm_reset_error();
            OG_LOG_RUN_INF("delete failed when shrink table, delete restart, sid[%u] rmid[%u]",
                stmt->session->knl_session.id, stmt->session->knl_session.rmid);
            knl_rollback(KNL_SESSION(stmt), &sp);
            OG_BREAK_IF_ERROR(sql_execute_delete_restart(stmt));
            sql_set_scn(stmt);
            continue;
        } else {
            break;
        }
    } while (OG_TRUE);

    return status;
}
