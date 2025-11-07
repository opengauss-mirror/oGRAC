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
 * ogsql_replace.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/ogsql_replace.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "ogsql_insert.h"
#include "ogsql_update.h"
#include "ogsql_select.h"
#include "ogsql_proj.h"
#include "srv_instance.h"
#include "ogsql_scan.h"
#include "ogsql_replace.h"
#include "ogsql_delete.h"

static status_t sql_fetch_replace_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_cursor_t *knl_cur, bool32 *is_found)
{
    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    OG_RETURN_IFERR(knl_fetch_by_rowid(KNL_SESSION(stmt), knl_cur, is_found));

    if (!(*is_found)) {
        SQL_CURSOR_POP(stmt);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(knl_delete(&stmt->session->knl_session, knl_cur));

    cursor->total_rows++;
    SQL_CURSOR_POP(stmt);
    return OG_SUCCESS;
}

static status_t sql_execute_replace_delete(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
                                           knl_dictionary_t *dc, bool32 *is_found)
{
    knl_cursor_t *insert_cursor = cursor->tables[0].knl_cur;
    knl_cursor_t *delete_knl_cur = cursor->exec_data.ext_knl_cur;
    status_t status;
    errno_t ret;

    OG_RETURN_IFERR(sql_execute_delete_triggers(stmt, insert_ctx->table, TRIG_BEFORE_EACH_ROW, insert_cursor));

    delete_knl_cur->action = CURSOR_ACTION_DELETE;
    OG_RETURN_IFERR(knl_open_cursor(KNL_SESSION(stmt), delete_knl_cur, dc));
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&delete_knl_cur->row));
    ret = memset_sp(delete_knl_cur->row, OG_MAX_ROW_SIZE, 0, OG_MAX_ROW_SIZE);
    if (ret != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    // set statement ssn when replace and before do delete
    sql_set_ssn(stmt);

    // replace delete set ssn
    delete_knl_cur->query_scn = insert_cursor->query_scn;
    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        delete_knl_cur->ssn = stmt->ssn;
    } else {
        delete_knl_cur->ssn = stmt->xact_ssn;
    }

    ROWID_COPY(delete_knl_cur->rowid, insert_cursor->conflict_rid);
    // may call sql_match_cond in knl_match_cond, need used current cursor in sql_match_cond
    status = sql_fetch_replace_delete(stmt, cursor, insert_ctx, delete_knl_cur, is_found);
    /* if row is not found while delete, do not execute after trigger and foreign key check */
    if (*is_found && status == OG_SUCCESS) {
        OG_RETURN_IFERR(sql_execute_delete_triggers(stmt, insert_ctx->table, TRIG_AFTER_EACH_ROW, delete_knl_cur));
        OG_RETURN_IFERR(knl_verify_children_dependency(&stmt->session->knl_session, delete_knl_cur, false, 0, false));
    }

    OGSQL_POP(stmt);
    return status;
}

static status_t sql_replace_single_row(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur, sql_cursor_t *cur_select)
{
    char *buffer = NULL;
    status_t status;
    bool32 is_found = OG_FALSE;
    insert_assist_t assist;
    insert_data_t insert_data = {
        .cur_select = cur_select,
        .row_modify = OG_FALSE
    };

    sql_init_insert_assist(&assist, &insert_data, insert_ctx, cur_select);
    OG_RETURN_IFERR(sql_generate_insert_data(stmt, knl_cur, &assist));

    if (insert_ctx->table->type == VIEW_AS_TABLE) {
        return sql_insteadof_triggers(stmt, insert_ctx->table, knl_cur, &insert_data, TRIG_EVENT_INSERT);
    }
    OG_RETURN_IFERR(sql_execute_insert_triggers(stmt, insert_ctx->table, TRIG_BEFORE_EACH_ROW, knl_cur, &insert_data));
    OG_RETURN_IFERR(sql_push(stmt, g_instance->kernel.attr.max_row_size, (void **)&buffer));

    do {
        OG_BREAK_IF_ERROR(sql_insert_inner(stmt, cursor, knl_cur, &assist, &status));

        // knl_insert return success
        if (status == OG_SUCCESS) {
            OGSQL_POP(stmt);
            return OG_SUCCESS;
        }

        // for on duplicate key update
        OG_BREAK_IF_TRUE(OG_ERRNO != ERR_DUPLICATE_KEY);

        // to release lob insert page when  insert failed result from primary key
        // or unique key  violation using sql "on duplicate key"
        OG_BREAK_IF_ERROR(knl_recycle_lob_insert_pages(&stmt->session->knl_session, knl_cur));

        if (HAS_SPEC_TYPE_HINT(insert_ctx->hint_info, OPTIM_HINT, HINT_KEY_WORD_THROW_DUPLICATE)) {
            break;
        }

        // row has been modified by trigger, store it
        OG_BREAK_IF_ERROR(sql_store_row_if_trigger_modify(&insert_data, knl_cur, buffer));

        // execute insert update
        cm_reset_error();

        // delete + insert
        OG_BREAK_IF_ERROR(sql_execute_replace_delete(stmt, cursor, insert_ctx, dc, &is_found));

        if (is_found) {
            sql_reset_insert_assist(&assist);
            OG_BREAK_IF_ERROR(sql_generate_insert_data(stmt, knl_cur, &assist));

            OG_BREAK_IF_ERROR(sql_insert_inner(stmt, cursor, knl_cur, &assist, &status));

            if (status == OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_SUCCESS;
            }

            // for on duplicate key update
            OG_BREAK_IF_TRUE(OG_ERRNO != ERR_DUPLICATE_KEY);
        }

        // row has been modified by trigger, restore it
        OG_BREAK_IF_ERROR(sql_restore_row_if_trigger_modify(&insert_data, knl_cur, buffer, stmt, &assist));

        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    } while (OG_TRUE);

    OGSQL_POP(stmt);
    return OG_ERROR;
}

static status_t sql_execute_replace_select_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    sql_cursor_t *sub_cursor = NULL;
    bool32 eof = OG_FALSE;
    plan_node_t *plan = insert_ctx->select_ctx->plan;
    status_t status = OG_SUCCESS;

    if (sql_alloc_cursor(stmt, &sub_cursor) != OG_SUCCESS) {
        return OG_ERROR;
    }
    sub_cursor->plan = plan;
    sub_cursor->select_ctx = insert_ctx->select_ctx;
    sub_cursor->scn = OG_INVALID_ID64;
    if (sql_execute_select_plan(stmt, sub_cursor, sub_cursor->plan->select_p.next) != OG_SUCCESS) {
        sql_free_cursor(stmt, sub_cursor);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sub_cursor));

    for (;;) {
        OGSQL_SAVE_STACK(stmt);
        if (sql_fetch_cursor(stmt, sub_cursor, sub_cursor->plan->select_p.next, &eof) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }

        if (eof) {
            OGSQL_RESTORE_STACK(stmt);
            break;
        }

        if (sql_replace_single_row(stmt, cursor, insert_ctx, dc, knl_cur, sub_cursor) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            status = OG_ERROR;
            break;
        }
        OGSQL_RESTORE_STACK(stmt);
        cursor->total_rows++;
    }

    SQL_CURSOR_POP(stmt);
    sql_free_cursor(stmt, sub_cursor);
    return status;
}

static status_t sql_execute_replace_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx)
{
    uint32 i;
    status_t status = OG_SUCCESS;
    knl_dictionary_t *dc = &cursor->tables[0].table->entry->dc;
    knl_cursor_t *knl_cursor = cursor->tables[0].knl_cur;
    bool32 table_nologging_enabled = knl_table_nologging_enabled(dc->handle);
    if (stmt->context->type == OGSQL_TYPE_INSERT && !stmt->is_sub_stmt &&
        (stmt->session->nologging_enable || table_nologging_enabled)) {
        if (!DB_IS_SINGLE(&stmt->session->knl_session) ||
            (DB_IS_RCY_CHECK_PCN(&stmt->session->knl_session) && stmt->session->nologging_enable)) {
            OG_LOG_DEBUG_WAR("forbid to nologging load when database in HA mode or \
                when _RCY_CHECK_PCN is TRUE on session_level nologging insert");
            knl_cursor->logging = OG_TRUE;
            knl_cursor->nologging_type = LOGGING_LEVEL;
            stmt->session->knl_session.rm->logging = OG_TRUE;
            knl_cursor->nologging_type = LOGGING_LEVEL;
            stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
        } else {
            knl_cursor->logging = OG_FALSE;
            stmt->session->knl_session.rm->logging = OG_FALSE;
            knl_cursor->nologging_type = knl_table_nologging_enabled(dc->handle) ? TABLE_LEVEL : SESSION_LEVEL;
            stmt->session->knl_session.rm->nolog_type = knl_cursor->nologging_type;
        }
    }

    if (knl_open_cursor(&stmt->session->knl_session, knl_cursor, dc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&knl_cursor->row) != OG_SUCCESS) {
        return OG_ERROR;
    }

    sql_prepare_scan(stmt, dc, knl_cursor);

    if (insert_ctx->select_ctx != NULL) {
        status = sql_execute_replace_select_plan(stmt, cursor, insert_ctx, dc, knl_cursor);
    } else {
        for (i = 0; i < insert_ctx->pairs_count; i++) {
            stmt->pairs_pos = i;
            OGSQL_SAVE_STACK(stmt);
            status = sql_replace_single_row(stmt, cursor, insert_ctx, dc, knl_cursor, NULL);
            OGSQL_RESTORE_STACK(stmt);
            if (status != OG_SUCCESS) {
                break;
            }

            cursor->total_rows++;
        }
    }

    OGSQL_POP(stmt);

    stmt->default_column = NULL;
    return status;
}

status_t sql_execute_replace_with_ctx(sql_stmt_t *stmt, sql_replace_t *replace_ctx)
{
    sql_cursor_t *cursor = OGSQL_ROOT_CURSOR(stmt);
    status_t status;

    cursor->scn = OG_INVALID_ID64;

    OG_RETURN_IFERR(
        sql_execute_insert_triggers(stmt, replace_ctx->insert_ctx.table, TRIG_BEFORE_STATEMENT, NULL, NULL));

    // set statement ssn after the before statement triggers executed
    sql_set_scn(stmt);
    sql_set_ssn(stmt);
    OG_RETURN_IFERR(sql_open_insert_cursor(stmt, cursor, &replace_ctx->insert_ctx));

    status = sql_execute_replace_plan(stmt, cursor, &replace_ctx->insert_ctx);

    stmt->session->knl_session.rm->logging = OG_TRUE;
    OG_RETURN_IFERR(status);
    OG_RETURN_IFERR(sql_execute_insert_triggers(stmt, replace_ctx->insert_ctx.table, TRIG_AFTER_STATEMENT, NULL, NULL));

    stmt->eof = OG_TRUE;
    cursor->eof = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_execute_replace_core(sql_stmt_t *stmt)
{
    uint64 conflicts = 0;
    /*
     * reset index conflicts to 0, and check it after stmt
     * to see if unique constraints violated.
     */
    knl_init_index_conflicts(KNL_SESSION(stmt), &conflicts);
    OG_RETURN_IFERR(sql_execute_replace_with_ctx(stmt, (sql_replace_t *)stmt->context->entry));
    return knl_check_index_conflicts(KNL_SESSION(stmt), conflicts);
}

status_t sql_execute_replace(sql_stmt_t *stmt)
{
    status_t status = OG_ERROR;
    knl_savepoint_t sp;

    do {
        knl_savepoint(KNL_SESSION(stmt), &sp);
        status = sql_execute_replace_core(stmt);
        // execute replace failed when shrink table, need restart
        if (status == OG_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            OG_LOG_RUN_INF("replace failed when shrink table, replace restart");
            cm_reset_error();
            knl_rollback(KNL_SESSION(stmt), &sp);
            sql_set_scn(stmt);
            continue;
        } else {
            break;
        }
    } while (OG_TRUE);

    return status;
}