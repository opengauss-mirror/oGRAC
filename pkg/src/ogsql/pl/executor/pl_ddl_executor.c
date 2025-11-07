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
 * pl_ddl_executor.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/executor/pl_ddl_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_ddl_executor.h"
#include "ogsql_dependency.h"
#include "srv_instance.h"
#include "knl_interface.h"
#include "pl_logic.h"
#include "pl_synonym.h"
#include "pl_common.h"
#include "dtc_dls.h"

typedef status_t (*pl_ddl_func_t)(sql_stmt_t *stmt, dc_user_t *dc_user);
static status_t pl_execute_ddl(pl_ddl_func_t ddl_dunc, sql_stmt_t *stmt, dc_user_t *dc_user)
{
    status_t status = OG_ERROR;

    dls_latch_x(KNL_SESSION(stmt), &dc_user->user_latch, KNL_SESSION(stmt)->id, NULL);

    while (OG_TRUE) {
        if (ddl_dunc(stmt, dc_user) == OG_SUCCESS) {
            status = OG_SUCCESS;
            break;
        }

        if (cm_get_error_code() != ERR_DC_INVALIDATED) {
            break;
        }

        cm_reset_error();
    }

    dls_unlatch(KNL_SESSION(stmt), &dc_user->user_latch, NULL);
    return status;
}

static status_t pl_init_entry_desc(sql_stmt_t *stmt, dc_user_t *dc_user, pl_desc_t *pl_desc)
{
    pl_entity_t *pl_ctx = stmt->pl_context;

    pl_desc->uid = dc_user->desc.id;
    pl_desc->type = pl_ctx->pl_type;
    pl_desc->org_scn = db_inc_scn(KNL_SESSION(stmt));
    pl_desc->chg_scn = pl_desc->org_scn;
    pl_desc->status = pl_ctx->create_def->compl_result ? OBJ_STATUS_VALID : OBJ_STATUS_INVALID;
    pl_desc->flags = 0;
    return cm_text2str(&pl_ctx->def.name, pl_desc->name, OG_NAME_BUFFER_SIZE);
}

static status_t pl_init_entry_new_desc(sql_stmt_t *stmt, pl_entry_t *entry, pl_desc_t *pl_desc)
{
    pl_entity_t *pl_ctx = stmt->pl_context;
    pl_desc->uid = entry->desc.uid;
    pl_desc->oid = entry->desc.oid;
    pl_desc->type = entry->desc.type;
    pl_desc->org_scn = entry->desc.org_scn;
    pl_desc->chg_scn = db_inc_scn(KNL_SESSION(stmt));
    pl_desc->status = pl_ctx->create_def->compl_result ? OBJ_STATUS_VALID : OBJ_STATUS_INVALID;
    pl_desc->flags = 0;
    MEMS_RETURN_IFERR(strcpy_s(pl_desc->name, OG_NAME_BUFFER_SIZE, entry->desc.name));

    return OG_SUCCESS;
}

static void pl_free_create_source(sql_stmt_t *stmt)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    if (pl_ctx->create_def != NULL && pl_ctx->create_def->large_page_id != OG_INVALID_ID32) {
        mpool_free_page(&g_instance->sga.large_pool, pl_ctx->create_def->large_page_id);
        pl_ctx->create_def->large_page_id = OG_INVALID_ID32;
    }
}

static status_t pl_execute_replace_procedrue(sql_stmt_t *stmt, pl_entry_info_t *entry_info)
{
    bool32 ret_ok = OG_FALSE;
    object_address_t curr_obj;
    pl_desc_t desc;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entry_t *entry = entry_info->entry;

    OG_RETURN_IFERR(pl_lock_entry_exclusive(knl_session, entry_info));
    if (pl_init_entry_new_desc(stmt, entry, &desc) != OG_SUCCESS) {
        pl_unlock_exclusive(KNL_SESSION(stmt), entry);
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&curr_obj, &desc));
        OG_BREAK_IF_ERROR(pl_update_sys_proc_source(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_language(knl_session, &desc, pl_ctx));
        pl_free_create_source(stmt);
        OG_BREAK_IF_ERROR(pl_delete_sys_argument(knl_session, &entry->desc));
        OG_BREAK_IF_ERROR(pl_delete_dependency(knl_session, &curr_obj));

        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_insert_proc_arg(knl_session, &desc, pl_ctx));
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(knl_session, &curr_obj, &pl_ctx->ref_list));
        }

        /* update the status of depender objects which has used this pl object to unknown */
        OG_BREAK_IF_ERROR(sql_update_depender_status(knl_session, (obj_info_t *)&curr_obj));

        // send a logic log sync standby
        pl_logic_log_put(knl_session, RD_PLM_REPLACE, entry->desc.uid, entry->desc.oid, entry->desc.type);

        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(KNL_SESSION(stmt), NULL);
        pl_unlock_exclusive(KNL_SESSION(stmt), entry);
        return OG_ERROR;
    }

    knl_commit(KNL_SESSION(stmt));
    pl_entity_invalidate_by_entry(entry);
    pl_update_entry_desc(entry, &desc);
    pl_unlock_exclusive(KNL_SESSION(stmt), entry);
    return OG_SUCCESS;
}

static status_t pl_execute_create_procedrue(sql_stmt_t *stmt, pl_entry_t *entry)
{
    bool32 ret_ok = OG_FALSE;
    object_address_t obj_addr;
    pl_entity_t *pl_ctx = stmt->pl_context;
    pl_desc_t desc = entry->desc;
    knl_session_t *session = KNL_SESSION(stmt);

    do {
        OG_BREAK_IF_ERROR(pl_write_sys_proc(session, &desc, pl_ctx));
        pl_free_create_source(stmt);
        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_insert_proc_arg(session, &desc, pl_ctx));
            OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &entry->desc));
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(session, &obj_addr, &pl_ctx->ref_list));
        }

        // standby logic log
        pl_logic_log_put(session, RD_PLM_CREATE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }
    knl_commit(session);
    pl_set_entry_status(entry, OG_TRUE);
    return OG_SUCCESS;
}

static status_t pl_execute_create_replace_procedure_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    var_udo_t *obj = &pl_ctx->def;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;
    pl_desc_t desc = { 0 };

    OG_RETURN_IFERR(pl_init_entry_desc(stmt, dc_user, &desc));
    OG_RETURN_IFERR(pl_find_or_create_entry(stmt, dc_user, &desc, &entry_info, &found));

    if (!found) {
        status = pl_execute_create_procedrue(stmt, entry_info.entry);
    } else {
        if (pl_ctx->create_def->create_option & CREATE_IF_NOT_EXISTS) {
            status = OG_SUCCESS;
        } else if (pl_ctx->create_def->create_option & CREATE_OR_REPLACE) {
            status = pl_execute_replace_procedrue(stmt, &entry_info);
        } else {
            OG_THROW_ERROR(ERR_DUPLICATE_NAME, "object", T2S(&obj->name));
            status = OG_ERROR;
        }
    }
    return status;
}

static status_t pl_create_synonym_check(knl_session_t *knl_session, knl_synonym_def_t *def, uint32 *syn_uid,
    uint32 *pl_uid)
{
    if (DB_NOT_READY(knl_session)) {
        OG_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return OG_ERROR;
    }

    if (!knl_get_user_id(knl_session, &def->owner, syn_uid)) {
        OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->owner));
        return OG_ERROR;
    }

    if (!knl_get_user_id(knl_session, &def->table_owner, pl_uid)) {
        OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "The object", T2S(&def->table_owner), T2S_EX(&def->table_name));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t pl_init_entry_desc_for_synonym(sql_stmt_t *stmt, pl_desc_t *desc)
{
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;
    uint32 syn_uid;
    uint32 pl_uid;

    MEMS_RETURN_IFERR(memset_s(desc, sizeof(pl_desc_t), 0, sizeof(pl_desc_t)));
    OG_RETURN_IFERR(pl_create_synonym_check(KNL_SESSION(stmt), def, &syn_uid, &pl_uid));
    desc->uid = syn_uid;
    desc->type = PL_SYNONYM;
    desc->status = OBJ_STATUS_VALID;
    desc->org_scn = db_inc_scn(KNL_SESSION(stmt));
    desc->chg_scn = desc->org_scn;
    OG_RETURN_IFERR(cm_text2str(&def->name, desc->name, OG_NAME_BUFFER_SIZE));
    OG_RETURN_IFERR(cm_text2str(&def->table_owner, desc->link_user, OG_NAME_BUFFER_SIZE));
    OG_RETURN_IFERR(cm_text2str(&def->table_name, desc->link_name, OG_NAME_BUFFER_SIZE));

    return OG_SUCCESS;
}

static status_t pl_execute_create_synonym(sql_stmt_t *stmt, pl_entry_t *entry)
{
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;
    knl_session_t *sess = (knl_session_t *)KNL_SESSION(stmt);
    bool32 ret_ok = OG_FALSE;

    do {
        OG_BREAK_IF_ERROR(pl_write_pl_synonym(sess, def, &entry->desc));
        OG_BREAK_IF_ERROR(pl_write_syn_dep(sess, def, &entry->desc));
        pl_logic_log_put(sess, RD_PLM_CREATE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (OG_FALSE);

    if (!ret_ok) {
        knl_rollback(sess, NULL);
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }

    knl_commit(KNL_SESSION(stmt));
    pl_set_entry_status(entry, OG_TRUE);
    return OG_SUCCESS;
}

static status_t pl_init_entry_new_desc_for_synonym(sql_stmt_t *stmt, pl_entry_t *entry, pl_desc_t *desc)
{
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;
    desc->uid = entry->desc.uid;
    desc->oid = entry->desc.oid;
    desc->type = entry->desc.type;
    desc->org_scn = entry->desc.org_scn;
    desc->chg_scn = db_inc_scn(KNL_SESSION(stmt));
    OG_RETURN_IFERR(cm_text2str(&def->name, desc->name, OG_NAME_BUFFER_SIZE));
    OG_RETURN_IFERR(cm_text2str(&def->table_owner, desc->link_user, OG_NAME_BUFFER_SIZE));
    OG_RETURN_IFERR(cm_text2str(&def->table_name, desc->link_name, OG_NAME_BUFFER_SIZE));
    return OG_SUCCESS;
}

static status_t pl_execute_replace_synonym(sql_stmt_t *stmt, pl_entry_info_t *entry_info)
{
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;
    knl_session_t *sess = KNL_SESSION(stmt);
    pl_desc_t desc = { 0 };
    bool32 ret_ok = OG_FALSE;
    pl_entry_t *entry = entry_info->entry;

    OG_RETURN_IFERR(pl_lock_entry_exclusive(sess, entry_info));
    obj_info_t obj_addr = { OBJ_TYPE_PL_SYNONYM, entry->desc.uid, entry->desc.oid };
    do {
        OG_BREAK_IF_ERROR(pl_init_entry_new_desc_for_synonym(stmt, entry, &desc));
        OG_BREAK_IF_ERROR(knl_delete_syssyn_by_name(sess, entry->desc.uid, entry->desc.name));
        OG_BREAK_IF_ERROR(knl_delete_dependency(sess, entry->desc.uid, entry->desc.oid, OBJ_TYPE_PL_SYNONYM));
        OG_BREAK_IF_ERROR(pl_write_pl_synonym(sess, def, &entry->desc));
        OG_BREAK_IF_ERROR(pl_write_syn_dep(sess, def, &entry->desc));
        OG_BREAK_IF_ERROR(sql_update_depender_status(sess, &obj_addr));
        pl_logic_log_put(sess, RD_PLM_REPLACE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (OG_FALSE);

    if (!ret_ok) {
        knl_rollback(sess, NULL);
        pl_unlock_exclusive(sess, entry);
        return OG_ERROR;
    }

    knl_commit(KNL_SESSION(stmt));
    entry->desc = desc;
    pl_unlock_exclusive(KNL_SESSION(stmt), entry);
    return OG_SUCCESS;
}


static inline void pl_get_syn_ref_def(knl_synonym_def_t *def, pl_entry_t *entry)
{
    pl_entry_lock(entry);
    def->ref_uid = entry->desc.uid;
    def->ref_oid = (uint32)entry->desc.oid;
    def->ref_dc_type = entry->desc.type;
    def->ref_chg_scn = entry->desc.chg_scn;
    pl_entry_unlock(entry);
}

static status_t pl_execute_create_replace_synonym_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;
    pl_entry_info_t entry_info;
    pl_entry_info_t link_info;
    dc_user_t *link_user = NULL;
    pl_desc_t desc;
    bool32 found = OG_FALSE;
    status_t status;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(pl_init_entry_desc_for_synonym(stmt, &desc));
    OG_RETURN_IFERR(dc_open_user(knl_session, &def->table_owner, &link_user));
    pl_find_entry_for_desc(link_user, &def->table_name, PL_SYN_LINK_TYPE, &link_info, &found);
    if (!found) {
        OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "The object", T2S(&def->table_owner), T2S_EX(&def->table_name));
        return OG_ERROR;
    }

    pl_get_syn_ref_def(def, link_info.entry);
    if (pl_find_or_create_entry(stmt, dc_user, &desc, &entry_info, &found) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!found) {
        status = pl_execute_create_synonym(stmt, entry_info.entry);
    } else {
        if (SYNONYM_IS_REPLACE & def->flags) {
            status = pl_execute_replace_synonym(stmt, &entry_info);
        } else {
            OG_THROW_ERROR(ERR_DUPLICATE_NAME, "object", T2S(&def->name));
            status = OG_ERROR;
        }
    }

    return status;
}

status_t pl_execute_create_replace_synonym(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    knl_synonym_def_t *def = (knl_synonym_def_t *)stmt->context->entry;
    dc_user_t *dc_user = NULL;

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &def->owner, &dc_user));
    return pl_execute_ddl(pl_execute_create_replace_synonym_core, stmt, dc_user);
}

status_t pl_execute_create_replace_procedure(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    dc_user_t *dc_user = NULL;

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &pl_ctx->def.user, &dc_user));
    return pl_execute_ddl(pl_execute_create_replace_procedure_core, stmt, dc_user);
}

static status_t pl_process_drop_procedure(knl_session_t *session, pl_entry_info_t *entry_info)
{
    obj_info_t obj_addr;
    bool32 ret_ok = OG_FALSE;
    pl_entry_t *entry = entry_info->entry;
    if (pl_lock_entry_exclusive(session, entry_info) != OG_SUCCESS) {
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_delete_sys_proc(session, entry->desc.oid, entry->desc.uid));
        OG_BREAK_IF_ERROR(pl_delete_sys_argument(session, &entry->desc));

        obj_addr.uid = entry->desc.uid;
        obj_addr.oid = entry->desc.oid;
        obj_addr.tid = pltype_to_objtype(entry->desc.type);

        OG_BREAK_IF_ERROR(knl_delete_dependency(session, obj_addr.uid, obj_addr.oid, obj_addr.tid));
        OG_BREAK_IF_ERROR(sql_update_depender_status(session, &obj_addr));

        // handle obj_priv
        OG_BREAK_IF_ERROR(pl_delete_obj_priv(session, entry, OBJ_TYPE_PROCEDURE));

        // time to send a logic log sync standby
        pl_logic_log_put(session, RD_PLM_DROP, entry->desc.uid, entry->desc.oid, entry->desc.type);

        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_unlock_exclusive(session, entry);
        return OG_ERROR;
    }

    knl_commit(session);
    pl_entity_invalidate_by_entry(entry);
    pl_entry_drop(entry);
    pl_unlock_exclusive(session, entry);
    pl_free_entry(entry);
    return OG_SUCCESS;
}

static status_t pl_execute_drop_procedure_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;

    pl_find_entry_for_desc(dc_user, &obj->name, drop_def->type, &entry_info, &found);
    if (found) {
        status = pl_process_drop_procedure(knl_session, &entry_info);
    } else {
        if (drop_def->option & DROP_IF_EXISTS) {
            status = OG_SUCCESS;
        } else {
            OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(&obj->user), T2S_EX(&obj->name));
            status = OG_ERROR;
        }
    }

    return status;
}

status_t pl_execute_drop_synonym(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    knl_drop_def_t *drop_def = (knl_drop_def_t *)stmt->context->entry;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &drop_def->owner, &dc_user));

    return pl_execute_ddl(pl_execute_drop_synonym_core, stmt, dc_user);
}

status_t pl_execute_drop_procedure(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    if (dc_open_user(knl_session, &obj->user, &dc_user) != OG_SUCCESS) {
        cm_reset_error_user(ERR_USER_OBJECT_NOT_EXISTS, T2S(&obj->user), T2S_EX(&obj->name), ERR_TYPE_PROCEDURE);
        return OG_ERROR;
    }

    return pl_execute_ddl(pl_execute_drop_procedure_core, stmt, dc_user);
}

static void pl_set_trig_def(pl_entry_t *entry, trig_desc_t *desc)
{
    entry->desc.trig_def.obj_oid = desc->base_obj;
    entry->desc.trig_def.obj_uid = desc->obj_uid;
}

static status_t pl_update_sysproc_trigger_desc(knl_session_t *knl_session, trig_desc_t *trig, pl_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_update_info_t *update_info = NULL;
    status_t status = OG_ERROR;

    CM_SAVE_STACK(knl_session->stack);

    if (sql_push_knl_cursor(knl_session, &cursor) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(knl_session->stack);
        return OG_ERROR;
    }

    do {
        knl_set_session_scn(knl_session, OG_INVALID_ID64);

        knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_003_ID);

        knl_init_index_scan(cursor, OG_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_INTEGER, &desc->uid,
            sizeof(int32), 0);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_BIGINT, &desc->oid,
            sizeof(desc->oid), 1);

        OG_BREAK_IF_ERROR(knl_fetch(knl_session, cursor));

        if (cursor->eof) {
            break;
        }

        update_info = &cursor->update_info;
        row_init(&ra, update_info->data, OG_MAX_ROW_SIZE, 3);
        // The current application scenario will not return a failure
        (void)row_put_text(&ra, &trig->real_user);
        (void)row_put_text(&ra, &trig->real_table);
        (void)row_put_str(&ra, "ENABLED");
        update_info->count = 3;
        update_info->columns[0] = SYS_PROC_TRIG_TABLE_USER_COL;
        update_info->columns[1] = SYS_PROC_TRIG_TABLE_COL;
        update_info->columns[2] = SYS_PROC_TRIG_STATUS_COL;
        cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
        OG_BREAK_IF_ERROR(knl_internal_update(knl_session, cursor));
        status = OG_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(knl_session->stack);
    return status;
}

static status_t pl_execute_create_trigger(sql_stmt_t *stmt, knl_dictionary_t *dc, pl_entry_t *entry)
{
    bool32 ret_ok = OG_FALSE;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    object_address_t obj_addr;
    trig_desc_t *trig_desc = &pl_ctx->trigger->desc;
    pl_desc_t *desc = &entry->desc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;
    knl_session_t *session = KNL_SESSION(stmt);

    if (dc_entity->trig_set.trig_count >= OG_MAX_TRIGGER_COUNT) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, OG_MAX_TRIGGER_COUNT, "triggers in a table");
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }

    trig_desc->enable = OG_TRUE;
    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, desc));
        OG_BREAK_IF_ERROR(pl_write_sys_proc(session, desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_sysproc_trigger_desc(session, trig_desc, desc));
        pl_free_create_source(stmt);
        OG_BREAK_IF_ERROR(pl_write_systrigger(session, desc->oid, trig_desc));
        if (dc->type != DICT_TYPE_VIEW && !dc_entity->table.desc.has_trig) {
            OG_BREAK_IF_ERROR(knl_update_trig_table_flag(session, &dc_entity->table.desc, OG_TRUE));
        }

        if (desc->status == OBJ_STATUS_VALID) {
            /* record the referenced object info */
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(session, &obj_addr, &pl_ctx->ref_list));
        }

        pl_set_trig_def(entry, trig_desc);

        // time to send a logic log sync standby
        pl_logic_log_put(session, RD_PLM_CREATE, desc->uid, desc->oid, desc->type);

        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }

    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc->handle);
    pl_set_entry_status(entry, OG_TRUE);
    return OG_SUCCESS;
}


static status_t pl_execute_replace_trigger(sql_stmt_t *stmt, knl_dictionary_t *dc, pl_entry_t *entry)
{
    bool32 ret_ok = OG_FALSE;
    object_address_t obj_addr;
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    trig_desc_t trig_desc = pl_ctx->trigger->desc;
    trig_def_t trig_def = entry->desc.trig_def;
    var_udo_t *obj = &pl_ctx->def;
    pl_desc_t desc;

    if (trig_def.obj_uid != trig_desc.obj_uid || trig_def.obj_oid != trig_desc.base_obj) {
        OG_THROW_ERROR(ERR_TRIG_ALREADY_IN_TAB_FMT, T2S(&obj->user), T2S_EX(&obj->name));
        return OG_ERROR;
    }

    trig_desc.enable = OG_TRUE;
    if (pl_init_entry_new_desc(stmt, entry, &desc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &desc));
        OG_BREAK_IF_ERROR(pl_update_sys_proc_source(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_language(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_sysproc_trigger_enable(knl_session, &entry->desc, OG_TRUE));
        pl_free_create_source(stmt);
        OG_BREAK_IF_ERROR(pl_delete_systriger(knl_session, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_write_systrigger(knl_session, entry->desc.oid, &trig_desc));
        OG_BREAK_IF_ERROR(pl_delete_dependency(knl_session, &obj_addr));

        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(knl_session, &obj_addr, &pl_ctx->ref_list));
        }
        // time to send a logic log sync standby
        pl_logic_log_put(knl_session, RD_PLM_REPLACE, entry->desc.uid, entry->desc.oid, entry->desc.type);

        ret_ok = OG_TRUE;
    } while (OG_FALSE);

    if (!ret_ok) {
        // dedicate entry version is changed, and excl_count should be set to zero.
        knl_rollback(stmt->session, NULL);
        return OG_ERROR;
    }
    knl_commit(knl_session);
    pl_entity_invalidate_by_entry(entry);
    pl_desc_set_trig_def(&desc, &trig_desc);
    dc_invalidate(knl_session, (dc_entity_t *)dc->handle);
    pl_update_entry_desc(entry, &desc);

    return OG_SUCCESS;
}

static status_t pl_execute_create_replace_trigger_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *sess = KNL_SESSION(stmt);
    knl_dictionary_t dc;
    pl_entry_info_t entry_info;
    status_t status;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    trig_desc_t *trig_desc = &pl_ctx->trigger->desc;
    var_udo_t *obj = &pl_ctx->def;
    bool32 exists = OG_FALSE;
    pl_desc_t desc;

    OG_RETURN_IFERR(pl_init_entry_desc(stmt, dc_user, &desc));
    OG_RETURN_IFERR(knl_open_dc_by_id(sess, trig_desc->obj_uid, (uint32)trig_desc->base_obj, &dc, OG_FALSE));
    if (lock_table_directly(sess, &dc, sess->kernel->attr.ddl_lock_timeout) != OG_SUCCESS) {
        dc_close(&dc);
        return OG_ERROR;
    }

    // must be set after locking table
    if (pl_find_or_create_entry(stmt, dc_user, &desc, &entry_info, &exists) != OG_SUCCESS) {
        unlock_tables_directly(sess);
        dc_close(&dc);
        return OG_ERROR;
    }

    if (!exists) {
        status = pl_execute_create_trigger(stmt, &dc, entry_info.entry);
    } else {
        if (pl_ctx->create_def->create_option & CREATE_IF_NOT_EXISTS) {
            status = OG_SUCCESS;
        } else if (pl_ctx->create_def->create_option & CREATE_OR_REPLACE) {
            status = pl_execute_replace_trigger(stmt, &dc, entry_info.entry);
        } else {
            OG_THROW_ERROR(ERR_DUPLICATE_NAME, "object", T2S(&obj->name));
            status = OG_ERROR;
        }
    }

    unlock_tables_directly(KNL_SESSION(stmt));
    dc_close(&dc);
    return status;
}

status_t pl_execute_create_replace_trigger(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    dc_user_t *dc_user = NULL;

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &pl_ctx->def.user, &dc_user));

    return pl_execute_ddl(pl_execute_create_replace_trigger_core, stmt, dc_user);
}

static status_t pl_db_drop_trigger(knl_session_t *session, pl_entry_t *entry)
{
    uint32 uid = entry->desc.uid;
    uint64 oid = entry->desc.oid;

    OG_RETURN_IFERR(pl_delete_sys_proc(session, oid, uid));
    OG_RETURN_IFERR(pl_delete_systriger(session, oid));
    OG_RETURN_IFERR(knl_delete_dependency(session, uid, oid, OBJ_TYPE_TRIGGER));
    return OG_SUCCESS;
}

// table lock prevent concurrent access, no need to lock entry
static void pl_drop_trigger_entry(knl_session_t *session, pl_entry_t *entry)
{
    pl_entity_invalidate_by_entry(entry);
    pl_entry_drop(entry);
    pl_free_entry(entry);
}

static status_t pl_process_drop_trigger(knl_session_t *session, pl_entry_info_t *entry_info, knl_dictionary_t *dc)
{
    obj_info_t obj_addr;
    bool32 ret_ok = OG_FALSE;
    uint32 trig_count;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;
    pl_entry_t *entry = entry_info->entry;

    if (pl_lock_entry_exclusive(session, entry_info) != OG_SUCCESS) {
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_delete_sys_proc(session, entry->desc.oid, entry->desc.uid));
        OG_BREAK_IF_ERROR(pl_delete_systriger(session, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_get_table_trigger_count(session, &entry->desc.trig_def, &trig_count));

        if (trig_count == 0 && dc->type != DICT_TYPE_VIEW) {
            OG_BREAK_IF_ERROR(knl_update_trig_table_flag(session, &dc_entity->table.desc, OG_FALSE));
        }

        obj_addr.uid = entry->desc.uid;
        obj_addr.oid = entry->desc.oid;
        obj_addr.tid = pltype_to_objtype(entry->desc.type);

        OG_BREAK_IF_ERROR(knl_delete_dependency(session, obj_addr.uid, obj_addr.oid, obj_addr.tid));
        pl_logic_log_put(session, RD_PLM_DROP, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_unlock_exclusive(session, entry);
        return OG_ERROR;
    }

    knl_commit(session);
    pl_entity_invalidate_by_entry(entry);
    pl_entry_drop(entry);
    pl_unlock_exclusive(session, entry);
    pl_free_entry(entry);
    dc_invalidate(session, (dc_entity_t *)dc->handle);
    return OG_SUCCESS;
}

static status_t pl_drop_nolog_trig_tab(knl_session_t *session, uint64 trig_oid, text_t *tab_user, text_t *tab_name)
{
    uint32 uid;
    bool32 exists = OG_FALSE;
    obj_info_t obj_addr;

    OG_RETURN_IFERR(pl_delete_sysproc_by_trig(session, tab_user, tab_name, trig_oid, &uid, &exists));
    if (!exists) {
        OG_LOG_RUN_ERR("trigger not found in SYS_PROCS, trigger id %lld", trig_oid);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(pl_delete_systriger(session, trig_oid));
    obj_addr.uid = uid;
    obj_addr.oid = trig_oid;
    obj_addr.tid = pltype_to_objtype(PL_TRIGGER);
    OG_RETURN_IFERR(knl_delete_dependency(session, obj_addr.uid, obj_addr.oid, obj_addr.tid));

    return OG_SUCCESS;
}


static status_t pl_drop_nolog_trigger(knl_session_t *session, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    trig_set_t *trig_set = &entity->trig_set;
    trig_item_t *trig_item = NULL;
    text_t tab_user;
    text_t tab_name;
    table_t *table = DC_TABLE(dc);

    OG_RETURN_IFERR(knl_get_user_name(session, table->desc.uid, &tab_user));
    cm_str2text(table->desc.name, &tab_name);

    for (uint32 i = 0; i < trig_set->trig_count; i++) {
        trig_item = &trig_set->items[i];
        OG_RETURN_IFERR(pl_drop_nolog_trig_tab(session, trig_item->oid, &tab_user, &tab_name));
    }

    return OG_SUCCESS;
}

// callback function, already lock table
status_t pl_db_drop_triggers(knl_handle_t knl_session, knl_dictionary_t *dc)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    dc_entity_t *entity = DC_ENTITY(dc);
    trig_set_t *trig_set = &entity->trig_set;
    trig_item_t *trig_item = NULL;
    pl_entry_info_t entry_info;

    // in WAIT_CLEAN mode, drop nologging table should drop trigger
    if (db->status == DB_STATUS_WAIT_CLEAN && dc->type == DICT_TYPE_TABLE_NOLOGGING) {
        OG_RETURN_IFERR(pl_drop_nolog_trigger(session, dc));
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < trig_set->trig_count; i++) {
        trig_item = &trig_set->items[i];
        pl_find_entry_by_oid(trig_item->oid, PL_TRIGGER, &entry_info);
        CM_ASSERT(entry_info.entry != NULL);
        if (pl_db_drop_trigger(session, entry_info.entry) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

void pl_drop_triggers_entry(knl_handle_t knl_session, knl_dictionary_t *dc)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    dc_entity_t *dc_entity = DC_ENTITY(dc);
    database_t *db = &kernel->db;
    trig_set_t *trig_set = &dc_entity->trig_set;
    trig_item_t *trig_item = NULL;
    pl_entry_info_t entry_info;

    // in WAIT_CLEAN mode, the entry of the trigger has not been initialized and does not need to drop
    if (db->status == DB_STATUS_WAIT_CLEAN) {
        return;
    }

    for (uint32 i = 0; i < trig_set->trig_count; i++) {
        trig_item = &trig_set->items[i];
        pl_find_entry_by_oid(trig_item->oid, PL_TRIGGER, &entry_info);
        CM_ASSERT(entry_info.entry != NULL);
        pl_drop_trigger_entry(session, entry_info.entry);
        pl_logic_log_put(session, RD_PLM_DROP, OG_INVALID_INT32, trig_item->oid, PL_TRIGGER);
    }
}

static status_t pl_free_trigger_by_name(knl_session_t *session, pl_entry_info_t *entry_info)
{
    status_t status;
    knl_dictionary_t dc;
    trig_def_t trig_def = entry_info->entry->desc.trig_def;

    if (knl_open_dc_by_id(session, trig_def.obj_uid, (uint32)trig_def.obj_oid, &dc, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout) != OG_SUCCESS) {
        dc_close(&dc);
        return OG_ERROR;
    }

    status = pl_process_drop_trigger(session, entry_info, &dc);
    unlock_tables_directly(session);
    dc_close(&dc);
    return status;
}

static status_t pl_execute_drop_trigger_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *session = KNL_SESSION(stmt);
    status_t status;
    knl_dictionary_t dc;
    bool32 found = OG_FALSE;
    pl_entry_info_t entry_info;
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t obj = drop_def->obj;
    trig_def_t trig_def;

    // 1.check if exist or not and get trigger desc
    pl_find_entry_for_desc(dc_user, &obj.name, PL_TRIGGER, &entry_info, &found);
    if (!found) {
        if (drop_def->option & DROP_IF_EXISTS) {
            return OG_SUCCESS;
        } else {
            OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "trigger", T2S(&obj.user), T2S_EX(&obj.name));
            return OG_ERROR;
        }
    }

    // 2.find table dc and lock
    trig_def = entry_info.entry->desc.trig_def;
    if (knl_open_dc_by_id(session, trig_def.obj_uid, (uint32)trig_def.obj_oid, &dc, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout) != OG_SUCCESS) {
        dc_close(&dc);
        return OG_ERROR;
    }

    status = pl_process_drop_trigger(session, &entry_info, &dc);

    unlock_tables_directly(session);
    dc_close(&dc);
    return status;
}

status_t pl_execute_drop_trigger(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    if (dc_open_user(knl_session, &obj->user, &dc_user) != OG_SUCCESS) {
        cm_reset_error_user(ERR_USER_OBJECT_NOT_EXISTS, T2S(&obj->user), T2S_EX(&obj->name), ERR_TYPE_TRIGGER);
        return OG_ERROR;
    }

    return pl_execute_ddl(pl_execute_drop_trigger_core, stmt, dc_user);
}

static status_t pl_execute_replace_type_spec(sql_stmt_t *stmt, pl_entry_info_t *entry_info)
{
    bool32 ret_ok = OG_FALSE;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    type_spec_t *type = pl_ctx->type_spec;
    knl_session_t *knl_session = KNL_SESSION(stmt);
    object_address_t obj_addr;
    pl_desc_t desc;
    pl_entry_t *entry = entry_info->entry;

    OG_RETURN_IFERR(pl_lock_entry_exclusive(knl_session, entry_info));
    if (pl_init_entry_new_desc(stmt, entry, &desc) != OG_SUCCESS) {
        pl_unlock_exclusive(knl_session, entry);
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &desc));
        OG_BREAK_IF_ERROR(pl_update_sys_proc_source(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_language(knl_session, &desc, pl_ctx));
        pl_free_create_source(stmt);
        OG_BREAK_IF_ERROR(pl_delete_sys_types(knl_session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_sys_type_attrs(knl_session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_sys_type_methods(knl_session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_sys_coll_types(knl_session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_dependency(knl_session, &obj_addr));
        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_write_sys_types(knl_session, type, &desc));
            if (type->decl->typdef.type == PLV_COLLECTION) {
                OG_BREAK_IF_ERROR(pl_write_sys_coll_types(knl_session, type, &desc));
            } else {
                OG_BREAK_IF_ERROR(pl_write_sys_type_attrs(knl_session, type, &desc));
            }
            /* insert reference info in dependency table */
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(knl_session, &obj_addr, &pl_ctx->ref_list));
        } else {
            pl_init_sys_types(knl_session, &desc);
        }

        /* update the status of depender objects which has used this pl object to unknown */
        OG_BREAK_IF_ERROR(sql_update_depender_status(knl_session, (obj_info_t *)&obj_addr));

        // time to send a logic log sync standby
        pl_logic_log_put(knl_session, RD_PLM_REPLACE, entry->desc.uid, entry->desc.oid, entry->desc.type);

        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(knl_session, NULL);
        pl_unlock_exclusive(knl_session, entry);
        return OG_ERROR;
    }

    knl_commit(knl_session);
    pl_entity_invalidate_by_entry(entry);
    pl_update_entry_desc(entry, &desc);
    pl_unlock_exclusive(knl_session, entry);
    return OG_SUCCESS;
}

static status_t pl_execute_create_type_spec(sql_stmt_t *stmt, pl_entry_t *entry)
{
    bool32 ret_ok = OG_FALSE;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    object_address_t obj_addr;
    type_spec_t *type = pl_ctx->type_spec;
    pl_desc_t desc = entry->desc;
    knl_session_t *session = KNL_SESSION(stmt);

    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &entry->desc));
        OG_BREAK_IF_ERROR(pl_write_sys_proc(session, &desc, pl_ctx));
        pl_free_create_source(stmt);
        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_write_sys_types(session, type, &desc));
            if (type->decl->typdef.type == PLV_COLLECTION) {
                OG_BREAK_IF_ERROR(pl_write_sys_coll_types(session, type, &desc));
            } else {
                OG_BREAK_IF_ERROR(pl_write_sys_type_attrs(session, type, &desc));
            }
            /* record the referenced object info */
            OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &entry->desc));
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(session, &obj_addr, &pl_ctx->ref_list));
        } else {
            OG_BREAK_IF_ERROR(pl_init_sys_types(session, &desc));
        }

        // time to send a logic log sync standby
        pl_logic_log_put(session, RD_PLM_CREATE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }

    knl_commit(session);
    pl_set_entry_status(entry, OG_TRUE);
    return OG_SUCCESS;
}

static status_t pl_check_type_replace(sql_stmt_t *stmt, pl_entry_t *entry)
{
    bool32 in_table = OG_FALSE;
    bool32 in_other_type = OG_FALSE;
    obj_info_t obj_addr;

    if (entry->desc.type != PL_TYPE_SPEC) {
        return OG_SUCCESS;
    }

    obj_addr.uid = entry->desc.uid;
    obj_addr.oid = (uint64)entry->desc.oid;
    obj_addr.tid = OBJ_TYPE_TYPE_SPEC;
    OG_RETURN_IFERR(pl_check_type_dependency(stmt, &obj_addr, &in_table, &in_other_type));
    if (in_table) {
        OG_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "type is used in table");
        return OG_ERROR;
    }

    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    bool32 force_flag = (pl_ctx->create_def->create_option & CREATE_TYPE_FORCE);

    if (force_flag || !in_other_type) {
        return OG_SUCCESS;
    }
    OG_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "type is used in other type, expect FORCE");
    return OG_ERROR;
}

static status_t pl_execute_create_replace_type_spec_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    var_udo_t *obj = &pl_ctx->def;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;
    pl_desc_t desc = { 0 };

    OG_RETURN_IFERR(pl_init_entry_desc(stmt, dc_user, &desc));
    OG_RETURN_IFERR(pl_find_or_create_entry(stmt, dc_user, &desc, &entry_info, &found));

    if (!found) {
        status = pl_execute_create_type_spec(stmt, entry_info.entry);
    } else {
        if (pl_ctx->create_def->create_option & CREATE_IF_NOT_EXISTS) {
            status = OG_SUCCESS;
        } else if (pl_ctx->create_def->create_option & CREATE_OR_REPLACE) {
            status = pl_check_type_replace(stmt, entry_info.entry);
            if (status == OG_SUCCESS) {
                status = pl_execute_replace_type_spec(stmt, &entry_info);
            }
        } else {
            OG_THROW_ERROR(ERR_DUPLICATE_NAME, "object", T2S(&obj->name));
            status = OG_ERROR;
        }
    }
    return status;
}

status_t pl_execute_create_replace_type_spec(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    dc_user_t *dc_user = NULL;

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &pl_ctx->def.user, &dc_user));

    return pl_execute_ddl(pl_execute_create_replace_type_spec_core, stmt, dc_user);
}

static status_t pl_process_drop_type_spec(knl_session_t *session, pl_entry_info_t *entry_info)
{
    obj_info_t obj_addr;
    bool32 ret_ok = OG_FALSE;
    pl_entry_t *entry = entry_info->entry;

    if (pl_lock_entry_exclusive(session, entry_info) != OG_SUCCESS) {
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_delete_sys_proc(session, entry->desc.oid, entry->desc.uid));
        OG_BREAK_IF_ERROR(pl_delete_sys_types(session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_sys_type_attrs(session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_sys_type_methods(session, entry->desc.uid, entry->desc.oid));
        OG_BREAK_IF_ERROR(pl_delete_sys_coll_types(session, entry->desc.uid, entry->desc.oid));

        obj_addr.uid = entry->desc.uid;
        obj_addr.oid = entry->desc.oid;
        obj_addr.tid = pltype_to_objtype(entry->desc.type);

        OG_BREAK_IF_ERROR(knl_delete_dependency(session, obj_addr.uid, obj_addr.oid, obj_addr.tid));
        OG_BREAK_IF_ERROR(sql_update_depender_status(session, &obj_addr));
        OG_BREAK_IF_ERROR(pl_delete_obj_priv(session, entry, OBJ_TYPE_PROCEDURE));
        pl_logic_log_put(session, RD_PLM_DROP, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_unlock_exclusive(session, entry);
        return OG_ERROR;
    }

    knl_commit(session);
    pl_entity_invalidate_by_entry(entry);
    pl_entry_drop(entry);
    pl_unlock_exclusive(session, entry);
    pl_free_entry(entry);
    return OG_SUCCESS;
}

static status_t pl_check_type_drop(sql_stmt_t *stmt, pl_entry_t *entry, uint32 option)
{
    bool32 in_table = OG_FALSE;
    bool32 in_other_type = OG_FALSE;
    obj_info_t obj_addr;

    if (entry->desc.type != PL_TYPE_SPEC) {
        return OG_SUCCESS;
    }

    obj_addr.uid = entry->desc.uid;
    obj_addr.oid = (uint64)entry->desc.oid;
    obj_addr.tid = OBJ_TYPE_TYPE_SPEC;
    OG_RETURN_IFERR(pl_check_type_dependency(stmt, &obj_addr, &in_table, &in_other_type));
    if (in_table) {
        OG_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "type is used in table");
        return OG_ERROR;
    }
    if ((option & DROP_TYPE_FORCE) || !in_other_type) {
        return OG_SUCCESS;
    }
    OG_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "type is used in other type, expect FORCE");
    return OG_ERROR;
}

static status_t pl_execute_drop_type_spec_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;

    pl_find_entry_for_desc(dc_user, &obj->name, drop_def->type, &entry_info, &found);
    if (found) {
        status = pl_check_type_drop(stmt, entry_info.entry, drop_def->option);
        if (status == OG_SUCCESS) {
            status = pl_process_drop_type_spec(knl_session, &entry_info);
        }
    } else {
        if (drop_def->option & DROP_IF_EXISTS) {
            status = OG_SUCCESS;
        } else {
            OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "type spec", T2S(&obj->user), T2S_EX(&obj->name));
            status = OG_ERROR;
        }
    }
    return status;
}

status_t pl_execute_drop_type_spec(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    if (dc_open_user(knl_session, &obj->user, &dc_user) != OG_SUCCESS) {
        cm_reset_error_user(ERR_USER_OBJECT_NOT_EXISTS, T2S(&obj->user), T2S_EX(&obj->name), ERR_TYPE_TYPE);
        return OG_ERROR;
    }

    return pl_execute_ddl(pl_execute_drop_type_spec_core, stmt, dc_user);
}

status_t pl_execute_create_replace_type_body(sql_stmt_t *stmt)
{
    OG_THROW_ERROR(ERR_PL_UNSUPPORT);
    return OG_ERROR;
}

status_t pl_execute_drop_type_body(sql_stmt_t *stmt)
{
    OG_THROW_ERROR(ERR_PL_UNSUPPORT);
    return OG_ERROR;
}

static status_t pl_execute_replace_package_spec(sql_stmt_t *stmt, pl_entry_info_t *entry_info)
{
    bool32 ret_ok = OG_FALSE;
    pl_entry_t *entry = entry_info->entry;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_desc_t desc;
    object_address_t obj_addr;

    OG_RETURN_IFERR(pl_lock_entry_exclusive(knl_session, entry_info));
    if (pl_init_entry_new_desc(stmt, entry, &desc) != OG_SUCCESS) {
        pl_unlock_exclusive(knl_session, entry);
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &desc));
        OG_BREAK_IF_ERROR(pl_update_sys_proc_source(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_language(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_delete_sys_argument(knl_session, &desc));
        OG_BREAK_IF_ERROR(pl_delete_dependency(knl_session, &obj_addr));

        pl_free_create_source(stmt);
        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_insert_package_proc_args(knl_session, &desc, pl_ctx));
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(knl_session, &obj_addr, &pl_ctx->ref_list));
        }

        OG_BREAK_IF_ERROR(sql_update_depender_status(knl_session, (obj_info_t *)&obj_addr));
        pl_logic_log_put(knl_session, RD_PLM_REPLACE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(knl_session, NULL);
        pl_unlock_exclusive(knl_session, entry);
        return OG_ERROR;
    }

    knl_commit(knl_session);
    pl_entity_invalidate_by_entry(entry);
    pl_update_entry_desc(entry, &desc);
    // handle package_body_entity
    pl_unlock_exclusive(KNL_SESSION(stmt), entry);
    return OG_SUCCESS;
}

static status_t pl_execute_create_package_spec(sql_stmt_t *stmt, pl_entry_t *entry)
{
    bool32 ret_ok = OG_FALSE;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    pl_desc_t desc = entry->desc;
    object_address_t obj_addr;
    knl_session_t *knl_session = KNL_SESSION(stmt);

    do {
        OG_BREAK_IF_ERROR(pl_write_sys_proc(knl_session, &desc, pl_ctx));

        pl_free_create_source(stmt);
        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_insert_package_proc_args(knl_session, &desc, pl_ctx));
            /* record the referenced object info */
            OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&obj_addr, &entry->desc));
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(knl_session, &obj_addr, &pl_ctx->ref_list));
        }

        // standby logic log
        pl_logic_log_put(knl_session, RD_PLM_CREATE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(knl_session, NULL);
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }

    knl_commit(knl_session);
    pl_set_entry_status(entry, OG_TRUE);
    return OG_SUCCESS;
}

static status_t pl_execute_create_replace_package_spec_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    var_udo_t *obj = &pl_ctx->def;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;
    pl_desc_t desc = { 0 };
    OG_RETURN_IFERR(pl_init_entry_desc(stmt, dc_user, &desc));
    OG_RETURN_IFERR(pl_find_or_create_entry(stmt, dc_user, &desc, &entry_info, &found));

    if (!found) {
        status = pl_execute_create_package_spec(stmt, entry_info.entry);
    } else {
        if (pl_ctx->create_def->create_option & CREATE_IF_NOT_EXISTS) {
            status = OG_SUCCESS;
        } else if (pl_ctx->create_def->create_option & CREATE_OR_REPLACE) {
            status = pl_execute_replace_package_spec(stmt, &entry_info);
        } else {
            OG_THROW_ERROR(ERR_DUPLICATE_NAME, "object", T2S(&obj->name));
            status = OG_ERROR;
        }
    }
    return status;
}

status_t pl_execute_create_replace_package_spec(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    dc_user_t *dc_user = NULL;

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &pl_ctx->def.user, &dc_user));

    return pl_execute_ddl(pl_execute_create_replace_package_spec_core, stmt, dc_user);
}

static status_t pl_process_drop_package_body(knl_session_t *session, pl_entry_info_t *entry_info)
{
    obj_info_t obj_addr;
    bool32 ret_ok = OG_FALSE;
    pl_entry_t *entry = entry_info->entry;

    if (pl_lock_entry_exclusive(session, entry_info) != OG_SUCCESS) {
        return OG_ERROR;
    }

    do {
        OG_BREAK_IF_ERROR(pl_delete_sys_proc(session, entry->desc.oid, entry->desc.uid));

        obj_addr.uid = entry->desc.uid;
        obj_addr.oid = entry->desc.oid;
        obj_addr.tid = pltype_to_objtype(entry->desc.type);

        OG_BREAK_IF_ERROR(knl_delete_dependency(session, obj_addr.uid, obj_addr.oid, obj_addr.tid));
        OG_BREAK_IF_ERROR(sql_update_depender_status(session, &obj_addr));

        pl_entity_invalidate_by_entry(entry);
        pl_entry_drop(entry);
        pl_logic_log_put(session, RD_PLM_DROP, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_unlock_exclusive(session, entry);
        return OG_ERROR;
    }
    knl_commit(session);
    pl_unlock_exclusive(session, entry);
    pl_free_entry(entry);
    return OG_SUCCESS;
}

static status_t pl_process_drop_package_spec(knl_session_t *session, pl_entry_info_t *entry_info)
{
    bool32 found = OG_FALSE;
    obj_info_t obj_addr;
    bool32 ret_ok = OG_FALSE;
    text_t pkg_name;
    dc_user_t *dc_user = NULL;
    pl_entry_t *spec_entry = entry_info->entry;
    pl_entry_info_t body_entry_info;

    if (dc_open_user_by_id(session, spec_entry->desc.uid, &dc_user) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (pl_lock_entry_exclusive(session, entry_info) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cm_str2text(spec_entry->desc.name, &pkg_name);
    pl_find_entry_for_desc(dc_user, &pkg_name, PL_PACKAGE_BODY, &body_entry_info, &found);
    if (found) {
        if (pl_process_drop_package_body(session, &body_entry_info) != OG_SUCCESS) {
            pl_unlock_exclusive(session, spec_entry);
            return OG_ERROR;
        }
    }

    do {
        OG_BREAK_IF_ERROR(pl_delete_sys_proc(session, spec_entry->desc.oid, spec_entry->desc.uid));
        OG_BREAK_IF_ERROR(pl_delete_sys_argument(session, &spec_entry->desc));

        obj_addr.uid = spec_entry->desc.uid;
        obj_addr.oid = spec_entry->desc.oid;
        obj_addr.tid = pltype_to_objtype(spec_entry->desc.type);

        OG_BREAK_IF_ERROR(knl_delete_dependency(session, obj_addr.uid, obj_addr.oid, obj_addr.tid));
        OG_BREAK_IF_ERROR(sql_update_depender_status(session, &obj_addr));
        OG_BREAK_IF_ERROR(pl_delete_obj_priv(session, spec_entry, OBJ_TYPE_PROCEDURE));

        pl_entity_invalidate_by_entry(spec_entry);
        pl_entry_drop(spec_entry);
        pl_logic_log_put(session, RD_PLM_DROP, spec_entry->desc.uid, spec_entry->desc.oid, spec_entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_unlock_exclusive(session, spec_entry);
        return OG_ERROR;
    }

    knl_commit(session);
    pl_unlock_exclusive(session, spec_entry);
    pl_free_entry(spec_entry);
    return OG_SUCCESS;
}

static status_t pl_drop_package_cascade(knl_session_t *session, pl_entry_info_t *entry_info)
{
    pl_entry_info_t spec_entry_info;
    dc_user_t *dc_user = NULL;
    bool32 found;
    text_t object_name;
    pl_entry_t *entry = entry_info->entry;
    if (entry->desc.type == PL_PACKAGE_BODY) {
        dc_open_user_by_id(session, entry->desc.uid, &dc_user);
        cm_str2text(entry->desc.name, &object_name);
        pl_find_entry_for_desc(dc_user, &object_name, PL_PACKAGE_SPEC, &spec_entry_info, &found);
        if (found) {
            return pl_process_drop_package_spec(session, &spec_entry_info);
        } else {
            return pl_process_drop_package_body(session, entry_info);
        }
    } else {
        return pl_process_drop_package_spec(session, entry_info);
    }

    return OG_SUCCESS;
}

static status_t pl_execute_drop_package_spec_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;

    pl_find_entry_for_desc(dc_user, &obj->name, PL_PACKAGE_SPEC, &entry_info, &found);
    if (found) {
        status = pl_process_drop_package_spec(knl_session, &entry_info);
    } else {
        if (drop_def->option & DROP_IF_EXISTS) {
            status = OG_SUCCESS;
        } else {
            OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "package spec", T2S(&obj->user), T2S_EX(&obj->name));
            status = OG_ERROR;
        }
    }

    return status;
}

status_t pl_execute_drop_package_spec(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &obj->user, &dc_user));

    return pl_execute_ddl(pl_execute_drop_package_spec_core, stmt, dc_user);
}

static status_t pl_execute_create_package_body(sql_stmt_t *stmt, pl_entry_t *entry)
{
    bool32 ret_ok = OG_FALSE;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    pl_desc_t desc = entry->desc;
    object_address_t curr_obj;
    knl_session_t *session = KNL_SESSION(stmt);

    do {
        /* record the referenced object info */
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&curr_obj, &entry->desc));
        OG_BREAK_IF_ERROR(pl_write_sys_proc(session, &desc, pl_ctx));
        pl_free_create_source(stmt);
        if (entry->desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&curr_obj, &entry->desc));
            OG_BREAK_IF_ERROR(knl_insert_dependency_list(session, &curr_obj, &pl_ctx->ref_list));
        }

        pl_logic_log_put(session, RD_PLM_CREATE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(session, NULL);
        pl_free_broken_entry(entry);
        return OG_ERROR;
    }

    knl_commit(session);
    pl_set_entry_status(entry, OG_TRUE);
    return OG_SUCCESS;
}

static status_t pl_execute_replace_package_body(sql_stmt_t *stmt, pl_entry_info_t *entry_info)
{
    bool32 ret_ok = OG_FALSE;
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    pl_entry_t *entry = entry_info->entry;
    knl_session_t *knl_session = KNL_SESSION(stmt);
    object_address_t curr_obj;
    pl_desc_t desc;

    if (pl_init_entry_new_desc(stmt, entry, &desc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(pl_lock_entry_exclusive(knl_session, entry_info));

    do {
        OG_BREAK_IF_ERROR(pl_get_desc_objaddr(&curr_obj, &desc));
        OG_BREAK_IF_ERROR(pl_update_sys_proc_source(knl_session, &desc, pl_ctx));
        OG_BREAK_IF_ERROR(pl_update_language(knl_session, &desc, pl_ctx));
        pl_free_create_source(stmt);
        OG_BREAK_IF_ERROR(pl_delete_dependency(knl_session, &curr_obj));

        if (desc.status == OBJ_STATUS_VALID) {
            OG_BREAK_IF_ERROR(pl_insert_dependency_list(knl_session, &curr_obj, &pl_ctx->ref_list));
        }
        pl_logic_log_put(knl_session, RD_PLM_REPLACE, entry->desc.uid, entry->desc.oid, entry->desc.type);
        ret_ok = OG_TRUE;
    } while (0);

    if (!ret_ok) {
        knl_rollback(knl_session, NULL);
        pl_unlock_exclusive(KNL_SESSION(stmt), entry);
        return OG_ERROR;
    }

    knl_commit(knl_session);
    pl_entity_invalidate_by_entry(entry);
    pl_update_entry_desc(entry, &desc);
    pl_unlock_exclusive(KNL_SESSION(stmt), entry);
    return OG_SUCCESS;
}

static status_t pl_execute_create_replace_package_body_in(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    var_udo_t *obj = &pl_ctx->def;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;
    pl_desc_t desc = { 0 };

    OG_RETURN_IFERR(pl_init_entry_desc(stmt, dc_user, &desc));
    if (pl_find_or_create_entry(stmt, dc_user, &desc, &entry_info, &found) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!found) {
        status = pl_execute_create_package_body(stmt, entry_info.entry);
    } else {
        if (pl_ctx->create_def->create_option & CREATE_IF_NOT_EXISTS) {
            status = OG_SUCCESS;
        } else if (pl_ctx->create_def->create_option & CREATE_OR_REPLACE) {
            status = pl_execute_replace_package_body(stmt, &entry_info);
        } else {
            OG_THROW_ERROR(ERR_DUPLICATE_NAME, "object", T2S(&obj->name));
            status = OG_ERROR;
        }
    }

    return status;
}

static status_t pl_execute_create_replace_package_body_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    var_udo_t *obj = &pl_ctx->def;
    pl_entry_info_t entry_info;
    pl_entry_t *spec_entry = NULL;
    bool32 spec_found = OG_FALSE;

    // before create/replace package_body, lock package_spec
    pl_find_entry_for_desc(dc_user, &obj->name, PL_PACKAGE_SPEC | PL_SYS_PACKAGE, &entry_info, &spec_found);
    spec_entry = entry_info.entry;
    if (spec_found && spec_entry->desc.type == PL_SYS_PACKAGE) {
        OG_THROW_ERROR(ERR_OBJECT_EXISTS, "built-in package", T2S(&obj->name));
        return OG_ERROR;
    }

    if (spec_found) {
        if (pl_lock_entry_exclusive(KNL_SESSION(stmt), &entry_info) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    status_t status = pl_execute_create_replace_package_body_in(stmt, dc_user);
    if (spec_found) {
        pl_unlock_exclusive(KNL_SESSION(stmt), spec_entry);
    }
    return status;
}

status_t pl_execute_create_replace_package_body(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *pl_ctx = (pl_entity_t *)stmt->pl_context;
    dc_user_t *dc_user = NULL;

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_FALSE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &pl_ctx->def.user, &dc_user));

    return pl_execute_ddl(pl_execute_create_replace_package_body_core, stmt, dc_user);
}

static status_t pl_execute_drop_package_body_in(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    pl_entry_info_t entry_info;
    bool32 found = OG_FALSE;
    status_t status;

    pl_find_entry_for_desc(dc_user, &obj->name, PL_PACKAGE_BODY, &entry_info, &found);
    if (found) {
        status = pl_process_drop_package_body(knl_session, &entry_info);
    } else {
        if (drop_def->option & DROP_IF_EXISTS) {
            status = OG_SUCCESS;
        } else {
            OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "package body", T2S(&obj->user), T2S_EX(&obj->name));
            status = OG_ERROR;
        }
    }

    return status;
}

static status_t pl_execute_drop_package_body_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    pl_entry_info_t entry_info;
    bool32 spec_found = OG_FALSE;

    pl_find_entry_for_desc(dc_user, &obj->name, PL_PACKAGE_SPEC, &entry_info, &spec_found);
    if (spec_found) {
        if (pl_lock_entry_exclusive(knl_session, &entry_info) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    status_t status = pl_execute_drop_package_body_in(stmt, dc_user);
    if (spec_found) {
        pl_unlock_exclusive(knl_session, entry_info.entry);
    }
    return status;
}

status_t pl_execute_drop_package_body(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_drop_def_t *drop_def = (pl_drop_def_t *)stmt->context->entry;
    var_udo_t *obj = &drop_def->obj;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    OG_RETURN_IFERR(dc_open_user(knl_session, &obj->user, &dc_user));

    return pl_execute_ddl(pl_execute_drop_package_body_core, stmt, dc_user);
}

static status_t pl_drop_table_cascade(knl_session_t *session, pl_desc_t *pl_desc)
{
    pl_entry_info_t entry_info;
    pl_find_entry_by_oid(pl_desc->oid, pl_desc->type, &entry_info);
    CM_ASSERT(entry_info.entry != NULL);
    switch (pl_desc->type) {
        case PL_PROCEDURE:
        case PL_FUNCTION:
            OG_RETURN_IFERR(pl_process_drop_procedure(session, &entry_info));
            break;
        case PL_TRIGGER:
            OG_RETURN_IFERR(pl_free_trigger_by_name(session, &entry_info));
            break;
        case PL_PACKAGE_BODY:
        case PL_PACKAGE_SPEC:
            OG_RETURN_IFERR(pl_drop_package_cascade(session, &entry_info));
            break;
        case PL_TYPE_SPEC:
            OG_RETURN_IFERR(pl_process_drop_type_spec(session, &entry_info));
            break;
        case PL_TYPE_BODY:
            break;
        default:
            OG_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "objects", pl_desc->oid);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t pl_drop_object_by_user(knl_handle_t knl_session, uint32 uid)
{
    knl_session_t *session = (knl_session_t *)knl_session;
    bool32 found = OG_FALSE;
    pl_desc_t desc;

    knl_set_session_scn(session, OG_INVALID_ID64);
    if (pl_fetch_obj_by_uid(session, uid, &desc, &found) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (found) {
        if (pl_drop_table_cascade(session, &desc) != OG_SUCCESS) {
            return OG_ERROR;
        }

        knl_set_session_scn(session, OG_INVALID_ID64);
        if (pl_fetch_obj_by_uid(session, uid, &desc, &found) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t pl_process_alter_trigger(knl_session_t *session, knl_dictionary_t *dc, pl_entry_info_t *entry_info,
    bool32 enable)
{
    pl_entry_t *entry = entry_info->entry;
    if (pl_lock_entry_exclusive(session, entry_info) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (pl_update_trigger_enable_status(session, entry->desc.oid, enable) != OG_SUCCESS) {
        pl_unlock_exclusive(session, entry);
        knl_rollback(session, NULL);
        return OG_ERROR;
    }

    if (pl_update_sysproc_trigger_enable(session, &entry->desc, enable) != OG_SUCCESS) {
        pl_unlock_exclusive(session, entry);
        knl_rollback(session, NULL);
        return OG_ERROR;
    }

    pl_logic_log_put(session, RD_PLM_UPDATE_TRIG_STATUS, entry->desc.uid, entry->desc.oid, entry->desc.type);

    dc_invalidate(session, (dc_entity_t *)dc->handle);
    pl_unlock_exclusive(session, entry);

    return OG_SUCCESS;
}


static status_t pl_execute_alter_trigger_core(sql_stmt_t *stmt, dc_user_t *dc_user)
{
    knl_session_t *session = KNL_SESSION(stmt);
    knl_alttrig_def_t *trigger_def = (knl_alttrig_def_t *)stmt->context->entry;
    status_t status;
    knl_dictionary_t dc;
    bool32 found = OG_FALSE;
    pl_entry_info_t entry_info;
    trig_def_t trig_def;

    // 1.check if exist or not and get trigger desc
    pl_find_entry_for_desc(dc_user, &trigger_def->name, PL_TRIGGER, &entry_info, &found);
    if (!found) {
        OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "trigger", T2S(&trigger_def->user), T2S_EX(&trigger_def->name));
        return OG_ERROR;
    }

    // 2.find table dc and lock
    trig_def = entry_info.entry->desc.trig_def;
    if (knl_open_dc_by_id(session, trig_def.obj_uid, (uint32)trig_def.obj_oid, &dc, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout) != OG_SUCCESS) {
        dc_close(&dc);
        return OG_ERROR;
    }

    status = pl_process_alter_trigger(session, &dc, &entry_info, trigger_def->enable);

    unlock_tables_directly(session);
    dc_close(&dc);
    return status;
}

status_t pl_execute_alter_trigger(sql_stmt_t *stmt)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    knl_alttrig_def_t *trigger_def = (knl_alttrig_def_t *)stmt->context->entry;
    dc_user_t *dc_user = NULL;

    OG_RETURN_IFERR(knl_ddl_enabled(knl_session, OG_TRUE));
    if (dc_open_user(knl_session, &trigger_def->user, &dc_user) != OG_SUCCESS) {
        cm_reset_error_user(ERR_USER_OBJECT_NOT_EXISTS, T2S(&trigger_def->user), T2S_EX(&trigger_def->name),
            ERR_TYPE_TRIGGER);
        return OG_ERROR;
    }

    dls_latch_x(knl_session, &dc_user->user_latch, knl_session->id, NULL);
    status_t status = pl_execute_alter_trigger_core(stmt, dc_user);
    dls_unlatch(knl_session, &dc_user->user_latch, NULL);
    return status;
}
