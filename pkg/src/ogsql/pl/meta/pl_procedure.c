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
 * pl_procedure.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/meta/pl_procedure.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_procedure.h"
#include "srv_instance.h"
#include "pl_meta_common.h"

#ifdef Z_SHARDING
status_t shd_pre_execute_ddl(sql_stmt_t *stmt, bool32 multi_ddl, bool32 need_encrypt);
status_t shd_trigger_check_for_rebalance(sql_stmt_t *stmt, text_t *user, text_t *tab);
#endif

static inline status_t pl_set_complex_type_arg_old(row_assist_t *ra, og_type_t dtype, plv_direction_t drct,
    expr_tree_t *default_expr)
{
    OG_RETURN_IFERR(row_put_int32(ra, dtype));                  // data_type
    OG_RETURN_IFERR(row_put_int32(ra, (default_expr) ? 1 : 0)); // defaulted
    OG_RETURN_IFERR(row_put_null(ra));                          // default_value , reserved for future use
    OG_RETURN_IFERR(row_put_null(ra));                          // default_length, reserved for future use
    OG_RETURN_IFERR(row_put_int32(ra, drct));                   // in_out
    OG_RETURN_IFERR(row_put_null(ra));                          // data_length
    OG_RETURN_IFERR(row_put_null(ra));                          // data_precision
    return row_put_null(ra);                                    // data_scale
}

#define SET_SCALAR_TYPE_ARG_RET_OLD(ra, ptypmd, drct, default_expr)                                   \
    do {                                                                                              \
        OG_RETURN_IFERR(row_put_int32(ra, (int32)(ptypmd)->datatype));                                \
        OG_RETURN_IFERR(row_put_int32(ra, (default_expr) ? 1 : 0));                                   \
        OG_RETURN_IFERR(row_put_null(ra));                                                            \
        OG_RETURN_IFERR(row_put_null(ra));                                                            \
        OG_RETURN_IFERR(row_put_int32(ra, drct));                                                     \
        OG_RETURN_IFERR(row_put_int32(ra, (int32)(ptypmd)->size));                                    \
        row_put_prec_and_scale(ra, (uint32)(ptypmd)->datatype, (ptypmd)->precision, (ptypmd)->scale); \
    } while (0)


static status_t pl_prepare_row_desc_old(row_assist_t *ra, pl_desc_t *desc, procedure_desc_t *proc_desc, plv_decl_t *arg,
    uint32 pos, uint32 seq)
{
    // The current application scenario will not return a failure
    OG_RETURN_IFERR(row_put_int32(ra, (int32)desc->uid)); // user_id
    if (desc->type == PL_PACKAGE_SPEC) {
        OG_RETURN_IFERR(row_put_str(ra, proc_desc->name)); // object_name
    } else {
        OG_RETURN_IFERR(row_put_str(ra, desc->name)); // object_name
    }

    if (pos == 0 && proc_desc->is_function) {
        OG_RETURN_IFERR(row_put_null(ra)); // return argument_name
    } else {
        OG_RETURN_IFERR(row_put_text(ra, &arg->name)); // argument_name
    }

    OG_RETURN_IFERR(row_put_int32(ra, (int32)pos)); // position

    OG_RETURN_IFERR(row_put_int32(ra, (int32)seq)); // sequence
    OG_RETURN_IFERR(row_put_int32(ra, 0));          // data_level

    switch (arg->type) {
        case PLV_VAR:
            SET_SCALAR_TYPE_ARG_RET_OLD(ra, &arg->variant.type, arg->drct, arg->default_expr);
            break;
        case PLV_ARRAY:
            SET_SCALAR_TYPE_ARG_RET_OLD(ra, &arg->array.type, arg->drct, arg->default_expr);
            break;
        case PLV_CUR:
            OG_RETURN_IFERR(pl_set_complex_type_arg_old(ra, OG_TYPE_CURSOR, arg->drct, arg->default_expr));
            break;
        case PLV_RECORD:
            OG_RETURN_IFERR(pl_set_complex_type_arg_old(ra, OG_TYPE_RECORD, arg->drct, arg->default_expr));
            break;
        case PLV_OBJECT:
            OG_RETURN_IFERR(pl_set_complex_type_arg_old(ra, OG_TYPE_OBJECT, arg->drct, arg->default_expr));
            break;
        case PLV_COLLECTION:
            OG_RETURN_IFERR(pl_set_complex_type_arg_old(ra, OG_TYPE_COLLECTION, arg->drct, arg->default_expr));
            break;
        default:
            return OG_ERROR;
    }

    OG_RETURN_IFERR(row_put_null(ra)); // type#, reserved for future use
    OG_RETURN_IFERR(row_put_null(ra)); // reserved for future use
    if (desc->type == PL_PACKAGE_SPEC) {
        OG_RETURN_IFERR(row_put_str(ra, desc->name)); // PACKAGE
    } else {
        OG_RETURN_IFERR(row_put_null(ra)); // PACKAGE
    }
    OG_RETURN_IFERR(row_put_int32(ra, (int32)proc_desc->proc_id)); // PROC_SEQ
    OG_RETURN_IFERR(row_put_int32(ra, 0));                         // OVERLOAD
    return OG_SUCCESS;
}

static status_t pl_write_sys_arguments(knl_session_t *knl_session, pl_desc_t *desc, procedure_desc_t *proc_desc)
{
    row_assist_t ra;
    galist_t *args = proc_desc->params;
    uint32 arg_count = proc_desc->arg_count;
    plv_decl_t *arg = NULL;
    knl_cursor_t *cursor = NULL;
    uint32 column_count;
    uint32 pos;
    uint32 seq;

    if (args == NULL || args->count == 0) {
        return OG_SUCCESS;
    }

    CM_SAVE_STACK(knl_session->stack);

    if (sql_push_knl_cursor(knl_session, &cursor) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_STACK_OVERFLOW);
        CM_RESTORE_STACK(knl_session->stack);
        return OG_ERROR;
    }

    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_INSERT, SYS_PROC_ARGS_ID, OG_INVALID_ID32);
    column_count = knl_get_column_count(cursor->dc_entity);

    seq = 1;
    pos = 0;

    for (uint32 id = 0; id < arg_count; id++) {
        arg = (plv_decl_t *)cm_galist_get(args, id);
        if (!(arg->type == PLV_CUR || arg->type == PLV_VAR || arg->type == PLV_ARRAY ||
            CM_IS_PLV_UDT_DATATYPE(arg->type))) {
            continue;
        }

        row_init(&ra, cursor->buf, g_instance->kernel.attr.max_row_size, column_count);

        if (pl_prepare_row_desc_old(&ra, desc, proc_desc, arg, pos, seq) != OG_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return OG_ERROR;
        }

        pos++;
        seq++;

        if (knl_internal_insert(knl_session, cursor) != OG_SUCCESS) {
            CM_RESTORE_STACK(knl_session->stack);
            return OG_ERROR;
        }
    }

    CM_RESTORE_STACK(knl_session->stack);

    return OG_SUCCESS;
}

status_t pl_insert_proc_arg(knl_session_t *session, void *desc_in, void *pl_ctx_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *pl_ctx = (pl_entity_t *)pl_ctx_in;
    procedure_desc_t *proc_desc = NULL;

    proc_desc = &pl_ctx->procedure->desc;
    proc_desc->oid = desc->oid;
    OG_RETURN_IFERR(pl_write_sys_arguments(session, desc, proc_desc));
    return OG_SUCCESS;
}

status_t pl_insert_package_proc_args(knl_session_t *session, void *desc_in, void *pl_ctx_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *pl_ctx = (pl_entity_t *)pl_ctx_in;
    plv_decl_t *proc_decl = NULL;
    package_spec_t *pack_def = NULL;
    procedure_desc_t *proc_desc = NULL;

    pack_def = pl_ctx->package_spec;
    for (uint32 id = 0; id < pack_def->defs->count; id++) {
        proc_decl = (plv_decl_t *)cm_galist_get(pack_def->defs, id);
        proc_desc = &proc_decl->func->desc;
        proc_desc->oid = desc->oid;
        OG_RETURN_IFERR(pl_write_sys_arguments(session, desc, proc_desc));
    }

    return OG_SUCCESS;
}

status_t pl_delete_sys_argument(knl_session_t *session, void *desc_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    knl_cursor_t *cursor = NULL;
    uint32 index_id;

    knl_set_session_scn(session, OG_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    if (sql_push_knl_cursor(session, &cursor) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    index_id = (desc->type == PL_PACKAGE_SPEC) ? IX_PROCARGU_002_ID : IX_PROCARGU_001_ID;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PROC_ARGS_ID, index_id);
    knl_init_index_scan(cursor, OG_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_INTEGER, &desc->uid, sizeof(int32),
        0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, OG_TYPE_VARCHAR, desc->name,
        (uint16)strlen(desc->name), 1);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, OG_TYPE_INTEGER, &desc->uid, sizeof(int32),
        0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, OG_TYPE_STRING, desc->name,
        (uint16)strlen(desc->name), 1);
    if (index_id == IX_PROCARGU_001_ID) {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_PROCARGU_001_PACKAGE);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_PROCARGU_001_SEQUENCE);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_PROCARGU_001_OVERLOAD);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_PROCARGU_001_PACKAGE);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_PROCARGU_001_SEQUENCE);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_PROCARGU_001_OVERLOAD);
    }

    if (knl_fetch(session, cursor) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != OG_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return OG_ERROR;
        }

        if (knl_fetch(session, cursor) != OG_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return OG_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return OG_SUCCESS;
}


status_t pl_load_entity_update_proc_table(knl_session_t *session, void *desc_in, void *entity_in)
{
    pl_desc_t *desc = (pl_desc_t *)desc_in;
    pl_entity_t *entity = (pl_entity_t *)entity_in;
    object_address_t obj_addr;
    pl_entry_t *entry = entity->entry;

    OG_RETURN_IFERR(pl_get_desc_objaddr(&obj_addr, desc));
    OG_RETURN_IFERR(pl_update_sysproc_status(session, desc));
    OG_RETURN_IFERR(pl_delete_sys_argument(session, desc));
    OG_RETURN_IFERR(pl_delete_dependency(session, &obj_addr));
    if (desc->status == OBJ_STATUS_VALID) {
        OG_RETURN_IFERR(pl_insert_proc_arg(session, desc, entity));
        OG_RETURN_IFERR(pl_insert_dependency_list(session, &obj_addr, &entity->ref_list));
    }

    // old status : OBJ_STATUS_VALID, new status : OBJ_STATUS_INVALID
    if (entry->desc.status == OBJ_STATUS_VALID && desc->status != OBJ_STATUS_VALID) {
        OG_RETURN_IFERR(pl_update_depender_status(session, &obj_addr));
    }

    return OG_SUCCESS;
}

static status_t pl_fetch_from_sysproc_by_name(knl_session_t *knl_session, knl_cursor_t *proc_cursor, text_t *user,
    text_t *object)
{
    uint32 uid;
    knl_set_session_scn(knl_session, OG_INVALID_ID64);
    if (!knl_get_user_id(knl_session, user, &uid)) {
        OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(user));
        return OG_ERROR;
    }
    knl_open_sys_cursor(knl_session, proc_cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, 0);
    knl_init_index_scan(proc_cursor, OG_FALSE);
    knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.l_key, OG_TYPE_STRING, object->str,
        object->len, IX_COL_PROC_001_NAME);
    knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.l_key, OG_TYPE_INTEGER, &uid,
        sizeof(int32), IX_COL_PROC_001_USER_ID);
    knl_set_key_flag(&proc_cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_PROC_001_CLASS);
    knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.r_key, OG_TYPE_STRING, object->str,
        object->len, IX_COL_PROC_001_NAME);
    knl_set_scan_key(INDEX_DESC(proc_cursor->index), &proc_cursor->scan_range.r_key, OG_TYPE_INTEGER, &uid,
        sizeof(int32), IX_COL_PROC_001_USER_ID);
    knl_set_key_flag(&proc_cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_PROC_001_CLASS);
    if (knl_fetch(knl_session, proc_cursor) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (proc_cursor->eof) {
        OG_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "object", T2S(user), T2S_EX(object));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t pl_get_proc_id_by_name(sql_stmt_t *stmt, text_t *user, text_t *object, uint32 *uid, uint64 *oid)
{
    knl_cursor_t *proc_cursor = NULL;
    knl_session_t *knl_session = &stmt->session->knl_session;

    OGSQL_SAVE_STACK(stmt);
    if (sql_push_knl_cursor(knl_session, &proc_cursor) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (pl_fetch_from_sysproc_by_name(knl_session, proc_cursor, user, object) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    *uid = *(uint32 *)CURSOR_COLUMN_DATA(proc_cursor, SYS_PROC_USER_COL);
    *oid = *(uint64 *)CURSOR_COLUMN_DATA(proc_cursor, SYS_PROC_OBJ_ID_COL);
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}
