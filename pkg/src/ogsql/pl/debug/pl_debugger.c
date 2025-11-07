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
 * pl_debugger.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/debug/pl_debugger.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_debugger.h"
#include "pl_executor.h"
#include "srv_instance.h"
#include "pl_scalar.h"

#define PLD_IS_PL_TYPE(type)                                                                                   \
    ((type) == OGSQL_TYPE_ANONYMOUS_BLOCK || (type) == OGSQL_TYPE_CREATE_PROC || (type) == OGSQL_TYPE_CREATE_FUNC || \
        (type) == OGSQL_TYPE_CREATE_TRIG)
static bool32 pld_is_proc_entry(const session_t *session, const pl_executor_t *exec)
{
    sql_stmt_t *stmt = session->current_stmt;
    if (exec->stack_base != 0) {
        return OG_FALSE;
    }
    while (stmt->is_sub_stmt) {
        stmt = (sql_stmt_t *)stmt->parent_stmt;
        if (stmt->pl_context != NULL) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

/*
 * check current user is dba or not
 */
static bool32 pld_debug_user_is_dba(session_t *session, text_t *debug_user)
{
    text_t role = {
        .str = DBA_ROLE,
        .len = 3
    };

    if (cm_text_str_equal_ins(debug_user, "SYS")) {
        return OG_TRUE;
    }

    return knl_grant_role_with_option(&session->knl_session, debug_user, &role, OG_FALSE);
}

bool32 pld_has_privilege(session_t *session, text_t *debug_user, const void *exec)
{
    debug_control_t *dbg_ctl = session->dbg_ctl;
    text_t *user = NULL;

    user = dbg_ctl->type == TARGET_SESSION ? &dbg_ctl->target_user : debug_user;
    if (!cm_text_equal(&session->curr_user, user)) {
        return OG_FALSE;
    }

    if (exec == NULL || ((pl_executor_t *)exec)->entity->def.user.len == 0) {
        return OG_TRUE;
    }

    if (cm_text_equal(debug_user, &((pl_executor_t *)exec)->entity->def.user)) {
        return OG_TRUE;
    }
    return pld_debug_user_is_dba(session, debug_user);
}

static void pld_try_init_callstack_info(session_t *session, debug_control_t *debug_ctl, bool32 *is_init)
{
    pl_executor_t *exec = (pl_executor_t *)session->current_stmt->pl_exec;
    dbg_callstack_info_t *callstack_info = debug_ctl->callstack_info;
    sql_stmt_t *stmt = NULL;
    sql_stmt_t *pl_stmts[PL_MAX_BLOCK_DEPTH] = { NULL };
    *is_init = OG_FALSE;

    if (debug_ctl->max_stack_id != 0) {
        return;
    }

    *is_init = OG_TRUE;
    stmt = session->current_stmt;
    while (stmt != NULL) {
        if (stmt->pl_context != NULL) {
            pl_stmts[debug_ctl->max_stack_id] = stmt;
            debug_ctl->max_stack_id++;
        }
        if (!stmt->is_sub_stmt) {
            break;
        }
        stmt = (sql_stmt_t *)stmt->parent_stmt;
    }

    for (uint32 i = 0; i < debug_ctl->max_stack_id; i++) {
        exec = (pl_executor_t *)pl_stmts[debug_ctl->max_stack_id - 1 - i]->pl_exec;
        if (cm_text2str(&exec->entity->def.user, callstack_info[i].owner, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
            callstack_info[i].owner[0] = '\0';
            callstack_info[i].owner_len = 0;
        } else {
            callstack_info[i].owner_len = exec->entity->def.user.len;
        }
        if (cm_text2str(&exec->entity->def.name, callstack_info[i].object, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
            callstack_info[i].object[0] = '\0';
            callstack_info[i].object_len = 0;
        } else {
            callstack_info[i].object_len = exec->entity->def.name.len;
        }
        callstack_info[i].exec = (void *)exec;
        callstack_info[i].stmt = pl_stmts[debug_ctl->max_stack_id - 1 - i];
    }
}

static void pld_update_callstack_info(session_t *session, pl_executor_t *exec, debug_control_t *debug_ctl)
{
    dbg_callstack_info_t *callstack_info = debug_ctl->callstack_info;
    uint32 curr_stack_id;

    if (callstack_info == NULL) {
        return;
    }

    // proc entry no need init
    if (pld_is_proc_entry((session_t *)session, (pl_executor_t *)exec)) {
        debug_ctl->max_stack_id = 0;
    } else {
        bool32 is_init = OG_TRUE;
        pld_try_init_callstack_info(session, debug_ctl, &is_init);
        if (is_init) {
            return;
        }
    }

    curr_stack_id = debug_ctl->max_stack_id;
    if (cm_text2str(&exec->entity->def.user, callstack_info[curr_stack_id].owner, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        callstack_info[curr_stack_id].owner[0] = '\0';
        callstack_info[curr_stack_id].owner_len = 0;
    } else {
        callstack_info[curr_stack_id].owner_len = exec->entity->def.user.len;
    }
    if (cm_text2str(&exec->entity->def.name, callstack_info[curr_stack_id].object, OG_NAME_BUFFER_SIZE) != OG_SUCCESS) {
        callstack_info[curr_stack_id].object[0] = '\0';
        callstack_info[curr_stack_id].object_len = 0;
    } else {
        callstack_info[curr_stack_id].object_len = exec->entity->def.name.len;
    }
    callstack_info[curr_stack_id].exec = (void *)exec;
    callstack_info[curr_stack_id].stmt = session->current_stmt;
    debug_ctl->max_stack_id++;
}

static inline void pld_try_init_pl_entries(session_t *session, debug_control_t *debug_ctl)
{
    if (debug_ctl->max_stack_id != 0 && debug_ctl->pl_ref_entry == NULL) {
        debug_ctl->pl_ref_entry = session->current_stmt->pl_ref_entry;
    }
}

static inline void pld_try_set_pl_entries_null(debug_control_t *debug_ctl)
{
    if (debug_ctl->max_stack_id == 0 && debug_ctl->pl_ref_entry != NULL) {
        debug_ctl->pl_ref_entry = NULL;
    }
}

static bool32 pld_isin_package_subproc(session_t *session)
{
    pl_executor_t *exec = NULL;
    sql_stmt_t *stmt = session->current_stmt;

    while (stmt != NULL) {
        exec = (pl_executor_t *)stmt->pl_exec;
        if (exec != NULL && exec->entity->pl_type == PL_PACKAGE_BODY) {
            return OG_TRUE;
        }
        if (!stmt->is_sub_stmt) {
            break;
        }
        stmt = stmt->parent_stmt;
    }
    return OG_FALSE;
}

static void pld_proc_start(void *session, void *exec, status_t *status)
{
    debug_control_t *debug_ctl = ((session_t *)session)->dbg_ctl;

    OG_RETVOID_IFTRUE(pld_isin_package_subproc(session));
    cm_spin_lock_if_exists(&((session_t *)session)->dbg_ctl_lock, NULL);
    cm_spin_lock_if_exists(debug_ctl->debug_lock, NULL);
    do {
        OG_BREAK_IF_TRUE(!debug_ctl->is_attached);

        pld_update_callstack_info((session_t *)session, (pl_executor_t *)exec, debug_ctl);
        pld_try_init_pl_entries((session_t *)session, debug_ctl);

        OG_BREAK_IF_TRUE(!pld_has_privilege((session_t *)session, &debug_ctl->debug_user, (pl_executor_t *)exec));

        // debug entry must pause
        if (pld_is_proc_entry((session_t *)session, (pl_executor_t *)exec)) {
            debug_ctl->is_force_terminate = OG_FALSE;
            debug_ctl->is_force_pause = OG_FALSE;
            debug_ctl->status = DBG_PRE_WAIT;
            break;
        }

        if (debug_ctl->brk_flag == BRK_ANY_CALL) {
            debug_ctl->status = DBG_PRE_WAIT;
            break;
        }
    } while (0);
    cm_spin_unlock_if_exists(debug_ctl->debug_lock);
    cm_spin_unlock_if_exists(&((session_t *)session)->dbg_ctl_lock);
}

static bool32 pld_is_brk_point_in_proc(knl_session_t *sess, pl_executor_t *exec, dbg_break_info_t *brk_info)
{
    pl_entry_t *pl_entry = exec->entity->entry;

    if (!brk_info->is_using || !brk_info->is_enabled || exec->curr_line->loc.line != brk_info->loc.line ||
        pl_entry == NULL || pl_entry->desc.type != brk_info->pl_type || pl_entry->desc.org_scn != brk_info->scn ||
        !cm_str_equal(pl_entry->desc.name, brk_info->object)) {
        return OG_FALSE;
    }

    dc_user_t *dc_user = NULL;
    if (dc_open_user_by_id(sess, pl_entry->desc.uid, &dc_user) != OG_SUCCESS) {
        cm_reset_error();
        return OG_FALSE;
    }

    return cm_str_equal(dc_user->desc.name, brk_info->owner);
}

static bool32 pld_is_breakpoint_match(knl_session_t *sess, pl_executor_t *exec, debug_control_t *dbg_ctl)
{
    dbg_break_info_t *break_info = dbg_ctl->brk_info;
    bool32 is_match = OG_FALSE;

    for (uint32 i = 0; i < dbg_ctl->max_break_id; i++) {
        if (!pld_is_brk_point_in_proc(sess, exec, &break_info[i])) {
            continue;
        }

        if (break_info[i].skipped_times < break_info[i].max_skip_times) {
            break_info[i].skipped_times++;
            continue;
        }
        break_info[i].skipped_times = 0;
        is_match = OG_TRUE;
        break;
    }
    return is_match;
}

static void pld_stmt_start(void *session, void *exec, status_t *status)
{
    debug_control_t *debug_ctl = ((session_t *)session)->dbg_ctl;

    OG_RETVOID_IFTRUE(pld_isin_package_subproc(session));
    cm_spin_lock_if_exists(&((session_t *)session)->dbg_ctl_lock, NULL);
    cm_spin_lock_if_exists(debug_ctl->debug_lock, NULL);
    pl_executor_t *pl_exec = (pl_executor_t *)exec;
    bool32 is_init = OG_TRUE;
    *status = OG_SUCCESS;
    do {
        OG_BREAK_IF_TRUE(!debug_ctl->is_attached);

        pld_try_init_callstack_info((session_t *)session, debug_ctl, &is_init);
        pld_try_init_pl_entries((session_t *)session, debug_ctl);
        debug_ctl->stmts = &((session_t *)session)->stmts;

        OG_BREAK_IF_TRUE(!pld_has_privilege((session_t *)session, &debug_ctl->debug_user, (pl_executor_t *)exec));

        if (pld_is_breakpoint_match((knl_session_t *)session, pl_exec, debug_ctl)) {
            debug_ctl->status = DBG_PRE_WAIT;
        }

        while (((debug_ctl->status == DBG_WAITING) || (debug_ctl->status == DBG_PRE_WAIT)) &&
            (debug_ctl->curr_count < debug_ctl->timeout)) {
            if (((session_t *)session)->knl_session.canceled || ((session_t *)session)->knl_session.killed) {
                OG_THROW_ERROR(ERR_OPERATION_CANCELED);
                *status = OG_ERROR;
                break;
            }

            debug_ctl->status = DBG_WAITING;
            cm_spin_unlock_if_exists(debug_ctl->debug_lock);
            cm_spin_unlock_if_exists(&((session_t *)session)->dbg_ctl_lock);
            cm_sleep(100);
            cm_spin_lock_if_exists(&((session_t *)session)->dbg_ctl_lock, NULL);
            cm_spin_lock_if_exists(debug_ctl->debug_lock, NULL);

            debug_ctl->curr_count++;
        }
        OG_BREAK_IF_TRUE(*status);

        if ((debug_ctl->is_force_terminate) || (debug_ctl->brk_flag == BRK_ABORT)) {
            debug_ctl->is_force_terminate = OG_FALSE;
            debug_ctl->status = DBG_IDLE;
            *status = OG_ERROR;
            break;
        }
    } while (0);
    cm_spin_unlock_if_exists(debug_ctl->debug_lock);
    cm_spin_unlock_if_exists(&((session_t *)session)->dbg_ctl_lock);
}

static bool32 pld_is_exception_handling(const pl_executor_t *exec)
{
    pl_line_ctrl_t *except = exec->body->except;
    if (except == NULL) {
        return OG_FALSE;
    } else if (except->loc.line < exec->curr_line->loc.line) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static inline void pld_stmt_end_brk_flag_check(const session_t *session, const pl_executor_t *exec, status_t *status)
{
    debug_control_t *debug_ctl = session->dbg_ctl;
    pl_line_ctrl_t *curr_line = exec->curr_line;

    switch (debug_ctl->brk_flag) {
        case BRK_NEXT_LINE:
            if ((debug_ctl->brk_flag_stack_id == debug_ctl->max_stack_id) &&
                ((curr_line->next == NULL) || (curr_line->loc.line != curr_line->next->loc.line))) {
                debug_ctl->status = DBG_PRE_WAIT;
            }
            break;
        case BRK_ANY_CALL:
            debug_ctl->status = DBG_PRE_WAIT;
            break;
        case BRK_EXCEPTION:
            if (*status == OG_ERROR) {
                debug_ctl->status = DBG_PRE_WAIT;
            }
            break;
        case BRK_HANDLER:
            if ((curr_line->type == LINE_END_EXCEPTION) ||
                (curr_line->type == LINE_RETURN && pld_is_exception_handling(exec))) {
                debug_ctl->status = DBG_PRE_WAIT;
            }
            break;
        default:
            break;
    }
}

static void pld_stmt_end(void *session, void *exec, status_t *status)
{
    debug_control_t *debug_ctl = ((session_t *)session)->dbg_ctl;

    OG_RETVOID_IFTRUE(pld_isin_package_subproc(session));
    cm_spin_lock_if_exists(&((session_t *)session)->dbg_ctl_lock, NULL);
    cm_spin_lock_if_exists(debug_ctl->debug_lock, NULL);
    bool32 is_init = OG_TRUE;
    do {
        OG_BREAK_IF_TRUE(!debug_ctl->is_attached);

        pld_try_init_callstack_info((session_t *)session, debug_ctl, &is_init);
        pld_try_init_pl_entries((session_t *)session, debug_ctl);

        OG_BREAK_IF_TRUE(!pld_has_privilege((session_t *)session, &debug_ctl->debug_user, (pl_executor_t *)exec));

        if (debug_ctl->is_force_pause) {
            debug_ctl->is_force_pause = OG_FALSE;
            debug_ctl->status = DBG_PRE_WAIT;
            break;
        }
        pld_stmt_end_brk_flag_check((session_t *)session, (pl_executor_t *)exec, status);
    } while (0);
    cm_spin_unlock_if_exists(debug_ctl->debug_lock);
    cm_spin_unlock_if_exists(&((session_t *)session)->dbg_ctl_lock);
}

static void pld_proc_end(void *session, void *exec, status_t *status)
{
    debug_control_t *debug_ctl = ((session_t *)session)->dbg_ctl;

    OG_RETVOID_IFTRUE(pld_isin_package_subproc(session));
    cm_spin_lock_if_exists(&((session_t *)session)->dbg_ctl_lock, NULL);
    cm_spin_lock_if_exists(debug_ctl->debug_lock, NULL);
    bool32 is_init = OG_TRUE;
    do {
        OG_BREAK_IF_TRUE(!debug_ctl->is_attached);

        pld_try_init_callstack_info((session_t *)session, debug_ctl, &is_init);
        pld_try_init_pl_entries((session_t *)session, debug_ctl);

        OG_BREAK_IF_TRUE(!pld_has_privilege((session_t *)session, &debug_ctl->debug_user, (pl_executor_t *)exec));

        switch (debug_ctl->brk_flag) {
            case BRK_RETURN:
                debug_ctl->status = DBG_PRE_WAIT;
                break;
            case BRK_ANY_RETURN:
                if (debug_ctl->brk_flag_stack_id == debug_ctl->max_stack_id) {
                    debug_ctl->status = DBG_PRE_WAIT;
                }
                break;
            default:
                break;
        }
    } while (0);
    if (debug_ctl->max_stack_id <= 1) {
        debug_ctl->status = DBG_IDLE;
    } else {
        debug_ctl->max_stack_id--;
    }
    pld_try_set_pl_entries_null(debug_ctl);
    cm_spin_unlock_if_exists(debug_ctl->debug_lock);
    cm_spin_unlock_if_exists(&((session_t *)session)->dbg_ctl_lock);
}

status_t pld_parse_exec_info(const debug_control_t *debug_ctl, pld_exec_info_t *exec_info)
{
    pl_executor_t *exec = (pl_executor_t *)debug_ctl->callstack_info[exec_info->stack_id - 1].exec;
    exec_info->curr_line = exec->curr_line;
    return OG_SUCCESS;
}

status_t pld_parse_block_info(const debug_control_t *debug_ctl, pld_block_info_t *block_info)
{
    pl_executor_t *exec = (pl_executor_t *)debug_ctl->callstack_info[block_info->stack_id - 1].exec;
    pl_executor_t *next_exec = NULL;
    block_info->curr_stack_start = exec->stack_base;

    if (block_info->stack_id == debug_ctl->max_stack_id) {
        block_info->next_stack_start = exec->block_stack.depth;
    } else {
        next_exec = (pl_executor_t *)debug_ctl->callstack_info[block_info->stack_id].exec;
        if (exec != next_exec) {
            block_info->next_stack_start = exec->block_stack.depth;
        } else {
            block_info->next_stack_start = next_exec->stack_base;
        }
    }

    if (block_info->next_stack_start >= block_info->max_depth) {
        OG_THROW_ERROR(ERR_PL_INDEX_ID_OVERFLOW, block_info->next_stack_start, "block_id", block_info->max_depth);
        return OG_ERROR;
    }

    for (uint32 i = block_info->curr_stack_start; i < block_info->next_stack_start; i++) {
        block_info->var_count[i] = exec->block_stack.items[i]->var_map.count;
    }
    return OG_SUCCESS;
}

static void pld_get_block_name(const pl_executor_t *exec, uint32 block_id, text_t *block_name)
{
    pl_line_ctrl_t *line_ctrl = exec->block_stack.items[block_id]->entry;
    text_t *name = NULL;

    if (line_ctrl->type == LINE_FOR) {
        name = ((pl_line_for_t *)line_ctrl)->name;
    } else if (line_ctrl->type == LINE_BEGIN) {
        name = ((pl_line_begin_t *)line_ctrl)->name;
    }
    *block_name = (name != NULL) ? *name : CM_NULL_TEXT;
}

static inline sql_stmt_t *pld_ref_cursor_get(const debug_control_t *debug_ctl, const pl_cursor_slot_t *ref_cursor)
{
    if (ref_cursor == NULL || ref_cursor->state == CUR_RES_FREE) {
        return NULL;
    }
    return (ref_cursor->stmt_id == OG_INVALID_ID16) ? NULL :
                                                      (sql_stmt_t *)cm_list_get(debug_ctl->stmts, ref_cursor->stmt_id);
}

static void pld_prepare_cursor_info(debug_control_t *debug_ctl, variant_t *value, pld_cursor_info_t *cur_info)
{
    pl_cursor_slot_t *ref_cursor = (pl_cursor_slot_t *)value->v_cursor.ref_cursor;
    sql_stmt_t *cur_stmt = value->is_null ? NULL : pld_ref_cursor_get(debug_ctl, ref_cursor);
    if (cur_stmt == NULL) {
        cur_info->is_open = OG_FALSE;
        cur_info->has_fetched = OG_FALSE;
        cur_info->is_found = OG_FALSE;
        cur_info->rows = 0;
    } else {
        cur_info->is_open = OG_TRUE;
        cur_info->has_fetched = cur_stmt->cursor_info.has_fetched;
        cur_info->is_found = !cur_stmt->eof;
        cur_info->rows = cur_stmt->total_rows;
    }
}

static uint32 pld_get_record_total_count(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, const variant_t *val, uint32 *count)
{
    plv_record_t *record = (plv_record_t *)val->v_record.record_meta;
    uint32 curr_count = *count;
    plv_record_attr_t *attr = NULL;
    variant_t result;
    pvm_context_t vm_context = GET_VM_CTX(vm_stmt);
    OPEN_VM_PTR(&val->v_record.value, vm_context);
    udt_mtrl_record_head_t *record_head = NULL;
    record_head = (udt_mtrl_record_head_t *)d_ptr;
    for (uint32 i = 0; i < record->count; i++) {
        attr = udt_seek_field_by_id(record, i);
        curr_count++;
        if ((attr->type == UDT_RECORD || attr->type == UDT_OBJECT) &&
            IS_VALID_MTRL_ROWID(record_head->field[i].rowid)) {
            if (pld_record_field_read(stmt, vm_stmt, attr, &record_head->field[i], &result) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(&val->v_record.value, vm_context);
                return OG_ERROR;
            }
            if (pld_get_record_total_count(stmt, vm_stmt, &result, &curr_count) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(&val->v_record.value, vm_context);
                return OG_ERROR;
            }
        }
    }
    CLOSE_VM_PTR(&val->v_record.value, vm_context);
    *count = curr_count;
    return OG_SUCCESS;
}


static status_t pld_get_record_total_value(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, const variant_t *value,
    const text_t *parent_name, pld_var_info_t *pld_var_info, uint32 *index)
{
    udt_mtrl_record_head_t *record_head = NULL;
    uint32 curr_index = *index;
    plv_record_attr_t *attr = NULL;
    variant_t result;
    pvm_context_t vm_context = GET_VM_CTX(vm_stmt);
    status_t status = OG_SUCCESS;

    OPEN_VM_PTR(&value->v_record.value, vm_context);
    record_head = (udt_mtrl_record_head_t *)d_ptr;

    for (uint32 i = 0; i < record_head->count; i++) {
        attr = udt_seek_field_by_id((plv_record_t *)value->v_record.record_meta, i);
        pld_var_info->total_field[curr_index] = record_head->field[i];
        pld_var_info->total_attr[curr_index] = attr;
        pld_var_info->total_parent_name[curr_index] = *parent_name;
        curr_index++;
        if ((attr->type == UDT_RECORD || attr->type == UDT_OBJECT) &&
            IS_VALID_MTRL_ROWID(record_head->field[i].rowid)) {
            if (pld_record_field_read(stmt, vm_stmt, attr, &record_head->field[i], &result) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
            if (pld_get_record_total_value(stmt, vm_stmt, &result, &attr->name, pld_var_info, &curr_index) !=
                OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
        }
    }

    CLOSE_VM_PTR(&value->v_record.value, vm_context);
    *index = curr_index;
    return status;
}

static status_t pld_prepare_record_attr(sql_stmt_t *stmt, debug_control_t *debug_ctl, pld_var_info_t *pld_var_info,
    const ple_var_t *var, bool32 *eof)
{
    sql_stmt_t *curr_stmt = (sql_stmt_t *)debug_ctl->callstack_info[pld_var_info->stack_id - 1].stmt;
    uint32 index = 0;
    errno_t err;
    uint32 count = 0;
    OG_RETURN_IFERR(pld_get_record_total_count(stmt, curr_stmt, &var->value, &count));

    if (pld_var_info->m_offset > count) {
        OG_THROW_ERROR(ERR_PL_INDEX_ID_OVERFLOW, pld_var_info->m_offset, "m_offset", count);
        return OG_ERROR;
    }

    if (pld_var_info->total_field == NULL) {
        OG_RETURN_IFERR(sql_push(stmt, count * sizeof(udt_mtrl_record_field_t), (void **)&pld_var_info->total_field));
        err = memset_sp(pld_var_info->total_field, count * sizeof(udt_mtrl_record_field_t), 0xFF,
            count * sizeof(udt_mtrl_record_field_t));
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_push(stmt, count * sizeof(pointer_t), (void **)&pld_var_info->total_attr));
        err = memset_sp(pld_var_info->total_attr, count * sizeof(pointer_t), 0, count * sizeof(pointer_t));
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_push(stmt, count * sizeof(text_t), (void **)&pld_var_info->total_parent_name));
        err = memset_sp(pld_var_info->total_parent_name, count * sizeof(text_t), 0, count * sizeof(text_t));
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(pld_get_record_total_value(stmt, curr_stmt, &var->value, &var->decl->name, pld_var_info,
            &index));
    }

    pld_var_info->is_attr_in_vm = OG_TRUE;
    pld_var_info->is_obj = OG_FALSE;
    pld_var_info->name = pld_var_info->total_attr[pld_var_info->m_offset - 1]->name;
    pld_var_info->parent_name = pld_var_info->total_parent_name[pld_var_info->m_offset - 1];
    pld_var_info->field = pld_var_info->total_field[pld_var_info->m_offset - 1];
    pld_var_info->attr = pld_var_info->total_attr[pld_var_info->m_offset - 1];
    pld_var_info->curr_stmt = curr_stmt;

    if (pld_var_info->m_offset == count) {
        *eof = OG_TRUE;
    } else {
        *eof = OG_FALSE;
    }
    return OG_SUCCESS;
}

static uint32 pld_get_object_total_count(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, const variant_t *value, uint32 *count)
{
    plv_object_t *object = (plv_object_t *)value->v_object.object_meta;
    uint32 curr_count = *count;
    plv_object_attr_t *attr = NULL;
    variant_t result;
    pvm_context_t vm_context = GET_VM_CTX(vm_stmt);
    if (IS_INVALID_MTRL_ROWID(value->v_object.value)) {
        return OG_SUCCESS;
    }
    OPEN_VM_PTR(&value->v_object.value, vm_context);
    udt_mtrl_object_head_t *object_head = NULL;
    object_head = (udt_mtrl_object_head_t *)d_ptr;
    for (uint32 i = 0; i < object->count; i++) {
        attr = udt_seek_obj_field_byid(object, i);
        curr_count++;
        if (attr->type == UDT_OBJECT && IS_VALID_MTRL_ROWID(object_head->field[i].rowid)) {
            if (pld_object_field_read(stmt, vm_stmt, attr, &object_head->field[i], &result) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(&value->v_object.value, vm_context);
                return OG_ERROR;
            }
            if (pld_get_object_total_count(stmt, vm_stmt, &result, &curr_count) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(&value->v_object.value, vm_context);
                return OG_ERROR;
            }
        }
    }
    CLOSE_VM_PTR(&value->v_object.value, vm_context);
    *count = curr_count;
    return OG_SUCCESS;
}

static status_t pld_get_object_total_value(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, const variant_t *value,
    const text_t *parent_name, pld_var_info_t *pld_var_info, uint32 *index)
{
    udt_mtrl_object_head_t *object_head = NULL;
    uint32 curr_index = *index;
    plv_object_attr_t *attr = NULL;
    variant_t result;
    pvm_context_t vm_context = GET_VM_CTX(vm_stmt);
    status_t status = OG_SUCCESS;

    OPEN_VM_PTR(&value->v_object.value, vm_context);
    object_head = (udt_mtrl_object_head_t *)d_ptr;

    for (uint32 i = 0; i < object_head->count; i++) {
        attr = udt_seek_obj_field_byid((plv_object_t *)value->v_object.object_meta, i);
        pld_var_info->obj_total_field[curr_index] = object_head->field[i];
        pld_var_info->obj_total_attr[curr_index] = attr;
        pld_var_info->total_parent_name[curr_index] = *parent_name;
        curr_index++;
        if (attr->type == UDT_OBJECT && IS_VALID_MTRL_ROWID(object_head->field[i].rowid)) {
            if (pld_object_field_read(stmt, vm_stmt, attr, &object_head->field[i], &result) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
            if (pld_get_object_total_value(stmt, vm_stmt, &result, &attr->name, pld_var_info, &curr_index) !=
                OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
        }
    }

    CLOSE_VM_PTR(&value->v_object.value, vm_context);
    *index = curr_index;
    return status;
}

static status_t pld_prepare_object_attr(sql_stmt_t *stmt, debug_control_t *debug_ctl, pld_var_info_t *pld_var_info,
    const ple_var_t *var, bool32 *eof)
{
    sql_stmt_t *curr_stmt = (sql_stmt_t *)debug_ctl->callstack_info[pld_var_info->stack_id - 1].stmt;
    uint32 index = 0;
    errno_t err;
    uint32 count = 0;
    OG_RETURN_IFERR(pld_get_object_total_count(stmt, curr_stmt, &var->value, &count));

    if (pld_var_info->m_offset > count) {
        OG_THROW_ERROR(ERR_PL_INDEX_ID_OVERFLOW, pld_var_info->m_offset, "m_offset", count);
        return OG_ERROR;
    }

    if (pld_var_info->obj_total_field == NULL) {
        OG_RETURN_IFERR(sql_push(stmt, count * sizeof(udt_mtrl_object_field_t), (void
            **)&pld_var_info->obj_total_field));
        err = memset_sp(pld_var_info->obj_total_field, count * sizeof(udt_mtrl_object_field_t), 0xFF,
            count * sizeof(udt_mtrl_object_field_t));
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_push(stmt, count * sizeof(pointer_t), (void **)&pld_var_info->obj_total_attr));
        err = memset_sp(pld_var_info->obj_total_attr, count * sizeof(pointer_t), 0, count * sizeof(pointer_t));
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_push(stmt, count * sizeof(text_t), (void **)&pld_var_info->total_parent_name));
        err = memset_sp(pld_var_info->total_parent_name, count * sizeof(text_t), 0, count * sizeof(text_t));
        if (err != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(pld_get_object_total_value(stmt, curr_stmt, &var->value, &var->decl->name, pld_var_info,
            &index));
    }

    pld_var_info->is_attr_in_vm = OG_TRUE;
    pld_var_info->is_obj = OG_TRUE;
    pld_var_info->name = pld_var_info->obj_total_attr[pld_var_info->m_offset - 1]->name;
    pld_var_info->parent_name = pld_var_info->total_parent_name[pld_var_info->m_offset - 1];
    pld_var_info->obj_field = pld_var_info->obj_total_field[pld_var_info->m_offset - 1];
    pld_var_info->obj_attr = pld_var_info->obj_total_attr[pld_var_info->m_offset - 1];
    pld_var_info->obj_curr_stmt = curr_stmt;

    *eof = (pld_var_info->m_offset == count) ? OG_TRUE : OG_FALSE;
    return OG_SUCCESS;
}

static status_t pld_check_var_info(pl_executor_t *exec, pld_var_info_t *pld_var_info, uint32 block_id)
{
    if (block_id >= exec->block_stack.depth) {
        OG_THROW_ERROR(ERR_PL_INDEX_ID_OVERFLOW, block_id, "block_id", exec->block_stack.depth);
        return OG_ERROR;
    }
    if (pld_var_info->id >= exec->block_stack.items[block_id]->var_map.count) {
        OG_THROW_ERROR(ERR_PL_INDEX_ID_OVERFLOW, pld_var_info->id, "id", exec->block_stack.items[block_id]->var_map.count);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t pld_get_var_info(sql_stmt_t *stmt, debug_control_t *debug_ctl, pld_var_info_t *pld_var_info, bool32 *is_found,
    bool32 *eof)
{
    pl_executor_t *exec = (pl_executor_t *)debug_ctl->callstack_info[pld_var_info->stack_id - 1].exec;
    uint32 block_id = exec->stack_base + pld_var_info->block_id;
    ple_var_t *var = NULL;

    OG_RETURN_IFERR(pld_check_var_info(exec, pld_var_info, block_id));

    pld_get_block_name(exec, block_id, &pld_var_info->block_name);
    var = exec->block_stack.items[block_id]->var_map.items[pld_var_info->id];
    if (var == NULL) {
        *is_found = OG_FALSE;
        return OG_SUCCESS;
    }
    *is_found = OG_TRUE;
    pld_var_info->name = var->decl->name;
    var_copy(&var->value, &pld_var_info->get_value);
    pld_var_info->set_value = &var->value;
    pld_var_info->type = var->exec_type;
    pld_var_info->is_attr_in_vm = OG_FALSE;
    pld_var_info->is_obj = OG_FALSE;

    // cursor
    if (var->value.type == OG_TYPE_CURSOR) {
        pld_prepare_cursor_info(debug_ctl, &var->value, &pld_var_info->cur_info);
    }

    if (var->decl->type & PLV_RECORD) {
        // top record
        if (pld_var_info->m_offset == PLD_INVALID_M_OFFSET) {
            pld_var_info->get_value.is_null = OG_TRUE;
            pld_var_info->type.datatype = OG_TYPE_RECORD;
            pld_var_info->parent_name.str = NULL;
            pld_var_info->parent_name.len = 0;
            *eof = IS_INVALID_MTRL_ROWID(var->value.v_record.value) ? OG_TRUE : OG_FALSE;
            return OG_SUCCESS;
        }

        // record attr
        return pld_prepare_record_attr(stmt, debug_ctl, pld_var_info, var, eof);
    } else if (var->decl->type & PLV_OBJECT) {
        // top object
        if (pld_var_info->m_offset == PLD_INVALID_M_OFFSET) {
            pld_var_info->get_value.is_null = OG_TRUE;
            pld_var_info->type.datatype = OG_TYPE_OBJECT;
            pld_var_info->parent_name.str = NULL;
            pld_var_info->parent_name.len = 0;
            *eof = IS_INVALID_MTRL_ROWID(var->value.v_object.value) ? OG_TRUE : OG_FALSE;
            return OG_SUCCESS;
        }

        return pld_prepare_object_attr(stmt, debug_ctl, pld_var_info, var, eof);
    }

    // not record/object
    pld_var_info->parent_name.str = NULL;
    pld_var_info->parent_name.len = 0;
    *eof = OG_TRUE;
    return OG_SUCCESS;
}

status_t pld_get_cursor_buf(char *cursor_buf, uint32 buf_len, uint32 *using_len, const pld_cursor_info_t *cursor_info)
{
    int iret_snprintf = 0;
    if (!cursor_info->is_open) {
        iret_snprintf = snprintf_s(cursor_buf, buf_len, buf_len - 1, "");
        if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_ERROR;
        }
    } else if (!cursor_info->has_fetched) {
        iret_snprintf = snprintf_s(cursor_buf, buf_len, buf_len - 1, "open");
        if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_ERROR;
        }
    } else if (cursor_info->is_found) {
        iret_snprintf = snprintf_s(cursor_buf, buf_len, buf_len - 1, "rowcount=%u, open, found", cursor_info->rows);
        if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_ERROR;
        }
    } else {
        iret_snprintf = snprintf_s(cursor_buf, buf_len, buf_len - 1, "rowcount=0, open, notfound");
    }
    PRTS_RETURN_IFERR(iret_snprintf);
    if (using_len != NULL) {
        *using_len = (uint32)iret_snprintf;
    }
    return OG_SUCCESS;
}

status_t pld_record_field_read(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, plv_record_attr_t *attr,
    udt_mtrl_record_field_t *field, variant_t *result)
{
    variant_t src;
    status_t status = OG_ERROR;
    char *org_base = NULL;
    /* hit scenario: debugger session set/read complex type var, switch to running session stmt,
       in debugging session invoke address function, need to check stack safe, so running session agent stack_base
       need switch to debugger session agent stack_base
    */
    cm_switch_stack_base(&vm_stmt->session->agent->thread, stmt->session->agent->thread.stack_base, &org_base);
    OGSQL_SAVE_STACK(vm_stmt);
    do {
        OG_BREAK_IF_ERROR(udt_record_field_addr_read(vm_stmt, attr, &src, field));
        if (attr->type == UDT_SCALAR) {
            OG_BREAK_IF_ERROR(udt_copy_scalar_element(stmt, attr->scalar_field->type_mode, &src, result));
        } else {
            var_copy(&src, result);
        }
        status = OG_SUCCESS;
    } while (0);
    OGSQL_RESTORE_STACK(vm_stmt);
    cm_switch_stack_base(&vm_stmt->session->agent->thread, org_base, &org_base);
    return status;
}

static status_t pld_record_field_rec_write(sql_stmt_t *stmt, pld_var_info_t *var_info, uint32 field_id,
    variant_t *right, udt_mtrl_record_field_t *parent)
{
    status_t status;
    char *org_base = NULL;
    udt_mtrl_record_head_t *mtrl_head = NULL;
    pvm_context_t vm_context = GET_VM_CTX(var_info->curr_stmt);

    cm_switch_stack_base(&var_info->curr_stmt->session->agent->thread, stmt->session->agent->thread.stack_base,
        &org_base);
    OGSQL_SAVE_STACK(var_info->curr_stmt);
    OPEN_VM_PTR(&parent->rowid, vm_context);
    mtrl_head = (udt_mtrl_record_head_t *)d_ptr;
    status = udt_record_field_addr_write(var_info->curr_stmt, var_info->attr, &mtrl_head->field[field_id], right);
    CLOSE_VM_PTR(&parent->rowid, vm_context);
    OGSQL_RESTORE_STACK(var_info->curr_stmt);
    cm_switch_stack_base(&var_info->curr_stmt->session->agent->thread, org_base, &org_base);
    return status;
}

static status_t pld_record_field_obj_write(sql_stmt_t *stmt, pld_var_info_t *var_info, uint32 field_id,
    variant_t *right, udt_mtrl_object_field_t *obj_parent)
{
    status_t status;
    char *org_base = NULL;
    udt_mtrl_object_head_t *obj_head = NULL;
    pvm_context_t vm_context = GET_VM_CTX(var_info->obj_curr_stmt);

    cm_switch_stack_base(&var_info->obj_curr_stmt->session->agent->thread, stmt->session->agent->thread.stack_base,
        &org_base);
    OGSQL_SAVE_STACK(var_info->obj_curr_stmt);
    OPEN_VM_PTR(&obj_parent->rowid, vm_context);
    obj_head = (udt_mtrl_object_head_t *)d_ptr;
    status =
        udt_object_field_addr_write(var_info->obj_curr_stmt, var_info->obj_attr, &obj_head->field[field_id], right);
    CLOSE_VM_PTR(&obj_parent->rowid, vm_context);
    OGSQL_RESTORE_STACK(var_info->obj_curr_stmt);
    cm_switch_stack_base(&var_info->obj_curr_stmt->session->agent->thread, org_base, &org_base);
    return status;
}

status_t pld_record_field_write(sql_stmt_t *stmt, debug_control_t *debug_ctl, pld_var_info_t *var_info, variant_t
    *right)
{
    status_t status;
    pld_var_info_t top_record_info;
    udt_mtrl_record_field_t record_parent;
    udt_mtrl_object_field_t obj_parent;
    bool8 is_obj = OG_FALSE;
    uint32 field_id;

    for (uint32 i = var_info->m_offset; i >= PLD_INVALID_M_OFFSET; i--) {
        if (i == PLD_INVALID_M_OFFSET) {
            bool32 is_found = OG_FALSE;
            bool32 eof = OG_FALSE;
            top_record_info.stack_id = var_info->stack_id;
            top_record_info.block_id = var_info->block_id;
            top_record_info.id = var_info->id;
            top_record_info.m_offset = PLD_INVALID_M_OFFSET;
            top_record_info.total_field = NULL;
            top_record_info.total_attr = NULL;
            top_record_info.total_parent_name = NULL;
            OG_RETURN_IFERR(pld_get_var_info(stmt, debug_ctl, &top_record_info, &is_found, &eof));
            record_parent.rowid = top_record_info.get_value.v_record.value;
            record_parent.type = OG_TYPE_RECORD;
            field_id = (uint32)(var_info->m_offset - 1);
            break;
        }
        if (var_info->total_attr[i - 1]->type == UDT_RECORD) {
            record_parent = var_info->total_field[i - 1];
            field_id = var_info->m_offset - 1 - i;
            break;
        }
        if (var_info->obj_total_attr[i - 1]->type == UDT_OBJECT) {
            obj_parent = var_info->obj_total_field[i - 1];
            field_id = var_info->m_offset - 1 - i;
            is_obj = OG_TRUE;
            break;
        }
    }
    /* hit scenario: debugger session set/read complex type var, switch to running session stmt,
       in debugging session invoke address function, need to check stack safe, so running session agent stack_base
       need switch to debugger session agent stack_base
    */
    if (!is_obj) {
        status = pld_record_field_rec_write(stmt, var_info, field_id, right, &record_parent);
    } else {
        status = pld_record_field_obj_write(stmt, var_info, field_id, right, &obj_parent);
    }
    return status;
}

status_t pld_object_field_read(sql_stmt_t *stmt, sql_stmt_t *vm_stmt, plv_object_attr_t *attr,
    udt_mtrl_object_field_t *field, variant_t *result)
{
    variant_t src;
    status_t status = OG_ERROR;
    char *org_base = NULL;
    /* hit scenario: debugger session set/read complex type var, switch to running session stmt,
    in debugging session invoke address function, need to check stack safe, so running session agent stack_base
    need switch to debugger session agent stack_base
    */
    cm_switch_stack_base(&vm_stmt->session->agent->thread, stmt->session->agent->thread.stack_base, &org_base);
    OGSQL_SAVE_STACK(vm_stmt);
    do {
        OG_BREAK_IF_ERROR(udt_object_field_addr_read(vm_stmt, attr, &src, field));
        if (attr->type == UDT_SCALAR) {
            OG_BREAK_IF_ERROR(udt_copy_scalar_element(stmt, attr->scalar_field->type_mode, &src, result));
        } else {
            var_copy(&src, result);
        }
        status = OG_SUCCESS;
    } while (0);
    OGSQL_RESTORE_STACK(vm_stmt);
    cm_switch_stack_base(&vm_stmt->session->agent->thread, org_base, &org_base);
    return status;
}

status_t pld_object_field_write(sql_stmt_t *stmt, debug_control_t *debug_ctl,
                                pld_var_info_t *var_info, variant_t *right)
{
    status_t status;
    pld_var_info_t top_object_info;
    udt_mtrl_object_field_t parent;
    char *org_base = NULL;
    pvm_context_t vm_context = GET_VM_CTX(var_info->obj_curr_stmt);
    udt_mtrl_object_head_t *mtrl_head = NULL;
    uint32 field_id;

    for (uint32 i = var_info->m_offset; i >= PLD_INVALID_M_OFFSET; i--) {
        if (i == PLD_INVALID_M_OFFSET) {
            bool32 is_found = OG_FALSE;
            bool32 eof = OG_FALSE;
            top_object_info.stack_id = var_info->stack_id;
            top_object_info.block_id = var_info->block_id;
            top_object_info.id = var_info->id;
            top_object_info.m_offset = PLD_INVALID_M_OFFSET;
            top_object_info.obj_total_field = NULL;
            top_object_info.obj_total_attr = NULL;
            top_object_info.total_parent_name = NULL;
            OG_RETURN_IFERR(pld_get_var_info(stmt, debug_ctl, &top_object_info, &is_found, &eof));
            parent.rowid = top_object_info.get_value.v_object.value;
            parent.type = OG_TYPE_OBJECT;
            field_id = (uint32)(var_info->m_offset - 1);
            break;
        }
        if (var_info->obj_total_attr[i - 1]->type == UDT_OBJECT) {
            parent = var_info->obj_total_field[i - 1];
            field_id = var_info->m_offset - 1 - i;
            break;
        }
    }
    /* hit scenario: debugger session set/read complex type var, switch to running session stmt,
    in debugging session invoke address function, need to check stack safe, so running session agent stack_base
    need switch to debugger session agent stack_base
    */
    cm_switch_stack_base(&var_info->obj_curr_stmt->session->agent->thread, stmt->session->agent->thread.stack_base,
        &org_base);
    OGSQL_SAVE_STACK(var_info->obj_curr_stmt);
    OPEN_VM_PTR(&parent.rowid, vm_context);
    mtrl_head = (udt_mtrl_object_head_t *)d_ptr;
    status =
        udt_object_field_addr_write(var_info->obj_curr_stmt, var_info->obj_attr, &mtrl_head->field[field_id], right);
    CLOSE_VM_PTR(&parent.rowid, vm_context);
    OGSQL_RESTORE_STACK(var_info->obj_curr_stmt);

    cm_switch_stack_base(&var_info->obj_curr_stmt->session->agent->thread, org_base, &org_base);
    return status;
}

status_t pld_set_var(sql_stmt_t *stmt, const pld_set_var_t *set_var)
{
    return ple_copy_variant(stmt, set_var->src, set_var->dst, set_var->type);
}

status_t pld_open_proc_dc(sql_stmt_t *stmt, debug_control_t *debug_ctl, plm_find_pldesc_t *plm_find_pldesc,
    pl_dc_t *pl_dc)
{
    bool32 exist = OG_FALSE;
    sql_stmt_t *target_stmt = NULL;
    var_udo_t *obj = &plm_find_pldesc->v_udo;
    pl_dc_t *dc = NULL;
    source_location_t loc = { 1, 1 };
    pl_dc_assist_t assist = { 0 };

    for (uint32 i = 0; i < debug_ctl->max_stack_id; i++) {
        target_stmt = debug_ctl->callstack_info[i].stmt;
        dc = pl_get_regist_dc(target_stmt, obj, plm_find_pldesc->type);
        if (dc != NULL) {
            pl_dc_reopen(dc);
            *pl_dc = *dc;
            return OG_SUCCESS;
        }
    }
    uint32 type = (uint32)plm_find_pldesc->type;
    pl_dc_open_prepare_for_ignore_priv(&assist, stmt, &obj->user, &obj->name, type);
    if (pl_dc_open(&assist, pl_dc, &exist) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!exist) {
        return pl_unfound_error(stmt, obj, &loc, type);
    }

    return OG_SUCCESS;
}

void pld_register_debug_callbacks(dbg_callback_t *dbg_callback)
{
    dbg_callback->proc_start = (dbg_callback_func_t)pld_proc_start;
    dbg_callback->proc_end = (dbg_callback_func_t)pld_proc_end;
    dbg_callback->stmt_start = (dbg_callback_func_t)pld_stmt_start;
    dbg_callback->stmt_end = (dbg_callback_func_t)pld_stmt_end;
}

#define DECODE_PL_TYPE_NUM 8
text_t g_object_type_name[DECODE_PL_TYPE_NUM] = {
    { "PROCEDURE",     9 },
    { "FUNCTION",      8 },
    { "PACKAGE_SPEC", 12 },
    { "PACKAGE_BODY", 12 },
    { "TYPE_SPEC",     9 },
    { "TYPE_BODY",     9 },
    { "TRIGGER",       7 },
    { "",              0 }, // PL_ANONYMOUS_BLOCK not support
};
status_t pld_get_pl_type(text_t *type, uint32 *pl_type)
{
    if (cm_text_str_equal(type, "PROCEDURE")) {
        *pl_type = PL_PROCEDURE;
        return OG_SUCCESS;
    }

    if (cm_text_str_equal(type, "FUNCTION")) {
        *pl_type = PL_FUNCTION;
        return OG_SUCCESS;
    }

    if (cm_text_str_equal(type, "TRIGGER")) {
        *pl_type = PL_TRIGGER;
        return OG_SUCCESS;
    }

    OG_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, T2S(type), "need be [PROCEDURE|FUNCTION|TRIGGER]");
    return OG_ERROR;
}

status_t pld_get_pl_type_text(uint32 temp_pl_type, text_t *type)
{
    uint32 pl_type = temp_pl_type;
    if (pl_type < PL_PROCEDURE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "pl_type", PL_PROCEDURE);
        return OG_ERROR;
    }
    if (pl_type >= PL_ANONYMOUS_BLOCK) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "pl_type", PL_TRIGGER);
        return OG_ERROR;
    }

    uint32 i = 0;
    while (pl_type != 0) {
        pl_type = (pl_type >> 1);
        i++;
    }

    *type = g_object_type_name[i - 1];
    return OG_SUCCESS;
}

status_t pld_get_target_session_debug_info(sql_stmt_t *stmt, uint32 session_id, debug_control_t **debug_ctl,
    spinlock_t **dbg_ctl_lock)
{
    session_t *session = stmt->session;
    if (!srv_get_debug_info(session_id, debug_ctl, dbg_ctl_lock) || (*debug_ctl)->type != TARGET_SESSION ||
        session->knl_session.id != (*debug_ctl)->debug_id) {
        OG_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "target session", session_id);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 text_is_dq_string(text_t *txt)
{
    char c1;
    char c2;
    if (txt == NULL || txt->len < 2) { // smaller than 2 since the quotation mark occupies two characters.
        return OG_FALSE;
    }

    c1 = txt->str[0];
    c2 = txt->str[txt->len - 1];

    if (c1 == c2 && (c1 == '\"' || c1 == '`')) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

void process_name_case_sensitive(text_t *name)
{
    if (text_is_dq_string(name)) {
        name->len = name->len - 2; // minus 2 since the quotation mark occupies two characters.
        name->str = name->str + 1;
    } else if (IS_CASE_INSENSITIVE) {
        cm_text_upper(name);
    }
}
