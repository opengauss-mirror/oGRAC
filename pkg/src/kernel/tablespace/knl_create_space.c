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
 * knl_create_space.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_create_space.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space_module.h"
#include "knl_create_space.h"
#include "knl_context.h"
#include "knl_punch_space.h"
#include "dtc_dc.h"
#include "dtc_dls.h"
#include "dtc_database.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPC_CLEAN_OPTION (TABALESPACE_INCLUDE | TABALESPACE_DFS_AND | TABALESPACE_CASCADE)

// record and set in memory, do not record redo
static inline void spc_try_set_swap_bitmap(knl_session_t *session, space_t *space)
{
    space->swap_bitmap = (IS_SWAP_SPACE(space) && SPACE_ATTR_SWAP_BITMAP(session));
}

static inline void spc_init_punch_head(knl_session_t *session, space_t *space)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    spc_init_page_list(&punch_head->punching_exts);
    spc_init_page_list(&punch_head->punched_exts);
}

bool32 spc_try_init_punch_head(knl_session_t *session, space_t *space)
{
    if (!spc_punch_check_normalspc_invaild(session, space)) {
        return OG_FALSE;
    }

    spc_init_punch_head(session, space);
    return OG_TRUE;
}

static void spc_update_head(knl_session_t *session, space_t *space, datafile_t *df)
{
    bool32 need_init_punch = OG_FALSE;

    /* if this is the first datafile in space , we need to initialize space head */
    if (df->file_no == 0) {
        buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
        knl_panic(space->ctrl->file_hwm == 1);
        space->head = SPACE_HEAD(session);
        page_init(session, (page_head_t *)CURR_PAGE(session), space->entry, PAGE_TYPE_SPACE_HEAD);
        errno_t ret = memset_sp(space->head, sizeof(space_head_t), 0, sizeof(space_head_t));
        knl_securec_check(ret);
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
        need_init_punch = spc_try_init_punch_head(session, space);
    } else {
        buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    }
    /* double write will init dbc_init_doublewrite() */
    space->head->hwms[df->file_no] = spc_get_hwm_start(session, space, df);

    space->head->datafile_count++;

    spc_try_set_swap_bitmap(session, space);

    if (!IS_SWAP_SPACE(space)) {
        rd_update_head_t redo;
        redo.entry = space->entry;
        redo.space_id = (uint16)df->space_id;  // max space_id is 1023
        redo.file_no = (uint16)df->file_no;    // max file_no is 1022
        log_put(session, RD_SPC_UPDATE_HEAD, &redo, sizeof(rd_update_head_t), LOG_ENTRY_FLAG_NONE);
        if (need_init_punch) {
            log_put(session, RD_SPC_PUNCH_EXTENTS, &SPACE_PUNCH_HEAD_PTR(space)->punching_exts,
                sizeof(rd_punch_extents_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    buf_leave_page(session, OG_TRUE);
}

static status_t spc_create_datafile_precheck(knl_session_t *session, space_t *space, knl_device_def_t *def)
{
    uint32 i;
    uint32 used_count = 0;
    datafile_t *df = NULL;
    datafile_t *new_df = NULL;
    char buf[OG_MAX_FILE_NAME_LEN];

    (void)cm_text2str(&def->name, buf, OG_MAX_FILE_NAME_LEN - 1);
    device_type_t type = cm_device_type(buf);
    if (!cm_dbs_is_enable_dbs() && (type == DEV_TYPE_PGPOOL || type == DEV_TYPE_ULOG)) {
        OG_THROW_ERROR(ERR_SPACE_NAME_INVALID, "name cannot start with - or * using non-dbstore mode");
        return OG_ERROR;
    }

    if (cm_exist_device(type, buf)) {
        OG_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, buf);
        return OG_ERROR;
    }

    for (i = 0; i < OG_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (df->ctrl->used) {
            if (cm_text_str_equal(&def->name, df->ctrl->name)) {
                OG_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, df->ctrl->name);
                return OG_ERROR;
            }
            used_count++;
            continue;
        }

        if (new_df == NULL) {
            new_df = df;
        }
    }

    if (used_count >= OG_MAX_DATA_FILES) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, OG_MAX_DATA_FILES, "datafiles");
        return OG_ERROR;
    }

    for (i = 0; i < OG_MAX_SPACE_FILES; i++) {
        if (space->ctrl->files[i] == OG_INVALID_ID32) {
            break;
        }
    }

    if (i >= OG_MAX_SPACE_FILES || new_df == NULL) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, OG_MAX_SPACE_FILES, "space");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t spc_precheck_create_parameter(knl_session_t *session, space_t *space,
    knl_device_def_t *def, int64 max_file_size)
{
    if (def->compress) {
        if (!IS_USER_SPACE(space)) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "non user tablespace");
            return OG_ERROR;
        }

        if (!SPACE_IS_BITMAPMANAGED(space)) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "normal tablespace");
            return OG_ERROR;
        }

        if (IS_TEMP_SPACE(space)) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "temp tablespace");
            return OG_ERROR;
        }

        if (SPACE_IS_NOLOGGING(space)) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "nologging tablespace");
            return OG_ERROR;
        }

        if (SPACE_IS_ENCRYPT(space)) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "encrypt tablespace");
            return OG_ERROR;
        }
    }

    if (def->size > max_file_size) {
        OG_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "SIZE", T2S(&(def->name)));
        return OG_ERROR;
    }

    if (!def->autoextend.enabled) {
        return OG_SUCCESS;
    }

    if (def->autoextend.nextsize > max_file_size) {
        OG_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "NEXT SIZE", T2S(&(def->name)));
        return OG_ERROR;
    }

    if (def->autoextend.maxsize > max_file_size) {
        OG_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", T2S(&(def->name)));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline void spc_clean_untraced_datafile(knl_session_t *session, char *file_name)
{
    device_type_t type = cm_device_type(file_name);
    if (cm_exist_device(type, file_name)) {
        if (cm_remove_device(type, file_name) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[SPACE] failed to remove datafile %s", file_name);
        }
    }
}

static status_t spc_extend_undo_segments(knl_session_t *session, uint32 count, datafile_t *df)
{
    uint32 space_id = dtc_my_ctrl(session)->undo_space;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    uint32 undo_segments = core_ctrl->undo_segments;
    char seg_count[OG_MAX_UINT32_STRLEN] = { 0 };
    rd_extend_undo_segments_t rd;
    errno_t ret;

    if (undo_df_create(session, space_id, undo_segments, undo_segments + count, df) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ckpt_trigger(session, OG_TRUE, CKPT_TRIGGER_FULL);

    rd.old_undo_segments = undo_segments;
    rd.undo_segments = undo_segments + count;
    core_ctrl->undo_segments = rd.undo_segments;
    core_ctrl->undo_segments_extended = OG_TRUE;

    log_atomic_op_begin(session);
    log_put(session, RD_SPC_EXTEND_UNDO_SEGMENTS, &rd, sizeof(rd_extend_undo_segments_t), LOG_ENTRY_FLAG_NONE);
    log_atomic_op_end(session);
    log_commit(session);

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ret = sprintf_s(seg_count, OG_MAX_UINT32_STRLEN, "%u", core_ctrl->undo_segments);
    knl_securec_check_ss(ret);
    if (cm_alter_config(session->kernel->attr.config, "_UNDO_SEGMENTS", seg_count,
        CONFIG_SCOPE_BOTH, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[SPACE] extend undo segments from %u to %u completed", rd.old_undo_segments, rd.undo_segments);

    return OG_SUCCESS;
}

static void spc_put_create_redo(knl_session_t *session, space_t *space)
{
    rd_create_space_ograc_t *oGRAC_redo = (rd_create_space_ograc_t *)cm_push(session->stack,
                                                                          sizeof(rd_create_space_ograc_t));
    knl_panic(oGRAC_redo != NULL);
    rd_create_space_t *redo = &(oGRAC_redo->space);

    oGRAC_redo->op_type = RD_SPC_CREATE_SPACE_OGRAC;
    redo->space_id = space->ctrl->id;
    redo->flags = space->ctrl->flag;
    redo->extent_size = space->ctrl->extent_size;
    redo->block_size = space->ctrl->block_size;
    redo->org_scn = space->ctrl->org_scn;
    redo->type = space->ctrl->type;
    redo->encrypt_version = space->ctrl->encrypt_version;
    redo->cipher_reserve_size = space->ctrl->cipher_reserve_size;
    redo->is_for_create_db = space->ctrl->is_for_create_db;
    knl_securec_check(memset_sp(redo->reserved2, sizeof(redo->reserved2), 0, sizeof(redo->reserved2)));

    errno_t ret = memcpy_sp(redo->name, OG_NAME_BUFFER_SIZE, space->ctrl->name, OG_NAME_BUFFER_SIZE);
    knl_securec_check(ret);
    if (SPACE_IS_ENCRYPT(space)) {
        log_encrypt_prepare(session, OG_INVALID_ID8, OG_TRUE);
    }
    log_put(session, RD_SPC_CREATE_SPACE, redo, sizeof(rd_create_space_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, oGRAC_redo, sizeof(rd_create_space_ograc_t), LOG_ENTRY_FLAG_NONE);
    }

    cm_pop(session->stack);
}

static status_t spc_create_datafile(knl_session_t *session, space_t *space, knl_device_def_t *def, uint32 *file_no)
{
    rd_create_datafile_t *redo = NULL;
    rd_create_datafile_ograc_t *oGRAC_redo = NULL;
    uint32 i;
    uint32 used_count = 0;
    datafile_t *new_df = NULL;
    database_t *db = &session->kernel->db;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    uint64 min_file_size = spc_get_datafile_minsize_byspace(session, space);
    if ((uint64)def->size < min_file_size) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum(%llu) required", min_file_size);
        return OG_ERROR;
    }

    if (cm_dbs_is_enable_dbs() && def->name.str[0] != '-') {
        OG_THROW_ERROR(ERR_SPACE_NAME_INVALID, "need add - before the name using dbstor");
        return OG_ERROR;
    }

    // Acquire a free slot in database datafile list.
    for (i = 0; i < OG_MAX_DATA_FILES; i++) {
        datafile_t *df = DATAFILE_GET(session, i);
        if (df->ctrl->used) {
            if (cm_text_str_equal(&def->name, df->ctrl->name)) {
                OG_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, df->ctrl->name);
                return OG_ERROR;
            }
            used_count++;
            continue;
        }

        if (new_df == NULL) {
            new_df = df;
            new_df->ctrl->id = i;
        }
    }

    if (used_count >= OG_MAX_DATA_FILES) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, OG_MAX_DATA_FILES, "datafiles");
        return OG_ERROR;
    }

    // Acquire a free slot in current space datafile list.
    for (i = 0; i < OG_MAX_SPACE_FILES; i++) {
        if (space->ctrl->files[i] == OG_INVALID_ID32) {
            break;
        }
    }

    if (i >= OG_MAX_SPACE_FILES || new_df == NULL) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, OG_MAX_SPACE_FILES, "space");
        return OG_ERROR;
    }

    // max_file_size is less than 2^30 * 2^13
    uint64 max_file_size = (uint64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE(session);
    if (spc_precheck_create_parameter(session, space, def, (int64)max_file_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (i >= space->ctrl->file_hwm) {
        space->ctrl->file_hwm++;
    }

    log_atomic_op_begin(session);

    new_df->ctrl->block_size = space->ctrl->block_size;
    knl_panic(new_df->ctrl->block_size != 0);
    new_df->ctrl->size = def->size;
    (void)cm_text2str(&def->name, new_df->ctrl->name, OG_FILE_NAME_BUFFER_SIZE);
    new_df->space_id = space->ctrl->id;
    new_df->ctrl->type = cm_device_type(new_df->ctrl->name);

    // reset df autoextend and max size to avoid get deleted info
    new_df->ctrl->auto_extend_size = 0;
    new_df->ctrl->auto_extend_maxsize = 0;
    spc_set_datafile_autoextend(session, new_df, &def->autoextend);

    if (cm_exist_device(new_df->ctrl->type, new_df->ctrl->name)) {
        log_atomic_op_end(session);
        OG_THROW_ERROR(ERR_FILE_HAS_EXIST, new_df->ctrl->name);
        OG_LOG_RUN_ERR("[SPACE] failed to build datafile %s, file is already existed.", new_df->ctrl->name);
        return OG_ERROR;
    }

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_BEFORE_CREATE_DF_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t sp_ret = OG_SUCCESS;
    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_FAIL, &sp_ret, OG_ERROR);
    sp_ret = spc_build_datafile(session, new_df, DATAFILE_FD(session, new_df->ctrl->id));
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != OG_SUCCESS) {
        log_atomic_op_end(session);
        spc_clean_untraced_datafile(session, new_df->ctrl->name);
        OG_LOG_RUN_ERR("[SPACE] failed to build datafile %s", new_df->ctrl->name);
        return OG_ERROR;
    }

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_AFTER_CREATE_DF_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (spc_open_datafile(session, new_df, DATAFILE_FD(session, new_df->ctrl->id)) != OG_SUCCESS) {
        log_atomic_op_end(session);
        spc_clean_untraced_datafile(session, new_df->ctrl->name);
        OG_LOG_RUN_ERR("[SPACE] datafile %s break down, try to offline it in MOUNT mode", new_df->ctrl->name);
        return OG_ERROR;
    }

    if (spc_init_datafile_head(session, new_df) != OG_SUCCESS) {
        log_atomic_op_end(session);
        spc_clean_untraced_datafile(session, new_df->ctrl->name);
        cm_close_device(new_df->ctrl->type, DATAFILE_FD(session, new_df->ctrl->id));
        return OG_ERROR;
    }

    if (session->kernel->db.status >= DB_STATUS_MOUNT) {
        if (cm_add_device_watch(new_df->ctrl->type, rmon_ctx->watch_fd, new_df->ctrl->name, &new_df->wd) !=
            OG_SUCCESS) {
            OG_LOG_RUN_WAR("[RMON]: failed to add monitor of datafile %s", new_df->ctrl->name);
        }
    }

    new_df->file_no = i;
    new_df->ctrl->used = OG_TRUE;
    new_df->ctrl->create_version++;
    new_df->ctrl->punched = OG_FALSE;
    new_df->ctrl->unused = 0;
    if (def->compress) {
        DATAFILE_SET_COMPRESS(new_df);
    } else {
        DATAFILE_UNSET_COMPRESS(new_df);
    }
    DATAFILE_SET_ONLINE(new_df);

    space->ctrl->files[i] = new_df->ctrl->id;
    *file_no = new_df->ctrl->id;
    if (i == 0) {
        spc_put_create_redo(session, space);

        space->entry.file = space->ctrl->files[0];
        space->entry.page = SPACE_ENTRY_PAGE;
    }
    db->ctrl.core.device_count++;

    oGRAC_redo = (rd_create_datafile_ograc_t *)cm_push(session->stack, sizeof(rd_create_datafile_ograc_t));
    oGRAC_redo->op_type = RD_SPC_CREATE_DATAFILE_OGRAC;
    redo = &(oGRAC_redo->datafile);
    redo->id = new_df->ctrl->id;
    redo->space_id = new_df->space_id;
    redo->file_no = new_df->file_no;
    redo->size = (uint64)new_df->ctrl->size;
    redo->auto_extend_size = new_df->ctrl->auto_extend_size;
    errno_t ret = strcpy_sp(redo->name, OG_FILE_NAME_BUFFER_SIZE, new_df->ctrl->name);
    knl_securec_check(ret);
    redo->auto_extend_maxsize = new_df->ctrl->auto_extend_maxsize;
    redo->flags = new_df->ctrl->flag;
    redo->type = new_df->ctrl->type;
    redo->reserve = 0;

    log_put(session, RD_SPC_CREATE_DATAFILE, redo, sizeof(rd_create_datafile_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, oGRAC_redo, sizeof(rd_create_datafile_ograc_t), LOG_ENTRY_FLAG_NONE);
    }

    cm_pop(session->stack);

    if (SECUREC_UNLIKELY(IS_SWAP_SPACE(space))) {
        if (SPACE_ATTR_SWAP_BITMAP(session)) {
            df_init_swap_map_head(session, new_df);
        }
    } else if (SPACE_CTRL_IS_BITMAPMANAGED(space)) {
        df_init_map_head(session, new_df);
    }

    spc_update_head(session, space, new_df);
    ckpt_disable_update_point(session);
    log_atomic_op_end(session);

    log_commit(session);

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_BEFORE_SAVE_CTRL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_SAVE_DF_CTRL_FAIL, &sp_ret, OG_ERROR);
    sp_ret = db_save_datafile_ctrl(session, new_df->ctrl->id);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != OG_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save datafile %u: %s control file when create datafile of space %u",
            new_df->ctrl->id, new_df->ctrl->name, space->ctrl->id);
    }

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_SAVE_SPC_CTRL_FAIL, &sp_ret, OG_ERROR);
    sp_ret = db_save_space_ctrl(session, space->ctrl->id);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != OG_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save space %u control file when create datafile %u: %s",
            space->ctrl->id, new_df->ctrl->id, new_df->ctrl->name);
    }

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (DB_IS_CLUSTER(session)) {
        tx_copy_logic_log(session);
        if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
            dtc_sync_ddl(session);
        }
    }

    SYNC_POINT_GLOBAL_START(OGRAC_DDL_CREATE_DATAFILE_AFTER_SYNC_DDL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    ckpt_enable_update_point(session);
    OG_LOG_RUN_INF("[SPACE] space %s add datafile %s success", space->ctrl->name, new_df->ctrl->name);
 
    return OG_SUCCESS;
}

status_t spc_create_datafiles(knl_session_t *session, space_t *space, knl_altspace_def_t *def)
{
    galist_t *datafiles = &def->datafiles;
    knl_device_def_t *file = NULL;
    uint32 file_no;
    bool32 need_extend_undo = OG_FALSE;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "create datafile");
        return OG_ERROR;
    }

    if (def->undo_segments > 0) {
        if (!DB_IS_RESTRICT(session)) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
            return OG_ERROR;
        }
        if (space->ctrl->id != dtc_my_ctrl(session)->undo_space) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in current undo space");
            return OG_ERROR;
        }

        need_extend_undo = OG_TRUE;
    }

    if (!SPACE_IS_ONLINE(space)) {
        OG_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "add datafile failed");
        return OG_ERROR;
    }

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        if (spc_create_datafile(session, space, file, &file_no) != OG_SUCCESS) {
            dls_spin_unlock(session, &space->lock);
            return OG_ERROR;
        }
    }
    dls_spin_unlock(session, &space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (DB_TO_RECOVERY(session) && IS_USER_SPACE(space)) {
        ckpt_trigger(session, OG_TRUE, CKPT_TRIGGER_FULL);
    }

    if (need_extend_undo) {
        datafile_t *new_df = DATAFILE_GET(session, file_no);

        knl_panic(datafiles->count == 1);

        if (spc_extend_undo_segments(session, def->undo_segments, new_df) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t spc_prepare_swap_encrypt(knl_session_t *session, space_t *space)
{
    uint32 max_cipher_len = 0;
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;

    encrypt_ctx->swap_encrypt_flg = OG_FALSE;
    encrypt_ctx->swap_encrypt_version = 0;

    if (cm_get_cipher_len(OG_VMEM_PAGE_SIZE, &max_cipher_len) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("swap sapce get cipher len error");
        return OG_ERROR;
    }

    max_cipher_len = CM_ALIGN4(max_cipher_len - OG_VMEM_PAGE_SIZE);
    TO_UINT8_OVERFLOW_CHECK(max_cipher_len, uint32);
    encrypt_ctx->swap_cipher_reserve_size = max_cipher_len;
    space->ctrl->extent_size = MAX((OG_VMEM_PAGE_SIZE + max_cipher_len) / DEFAULT_PAGE_SIZE(session) + 1,
        OG_SWAP_EXTENT_SIZE);
    knl_panic(space->ctrl->extent_size * DEFAULT_PAGE_SIZE(session) >= OG_VMEM_PAGE_SIZE + max_cipher_len);
    
    if (db_save_space_ctrl(session, space->ctrl->id) != OG_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
    }
    return OG_SUCCESS;
}

static status_t spc_init_flag(knl_session_t *session, knl_space_def_t *def, space_t *space)
{
    if (def->autooffline) {
        if (SPACE_IS_DEFAULT(space)) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to auto offline system space");
            return OG_ERROR;
        }
        SPACE_SET_AUTOOFFLINE(space);
    }

    // setting fellow previous version
    if (IS_USER_SPACE(space) && !DB_ATTR_CLUSTER(session)) {
        SPACE_SET_AUTOPURGE(space);
    }

    if (def->in_memory) {
        SPACE_SET_INMEMORY(space);
    }

    if (IS_SWAP_SPACE(space)) {
        space->ctrl->extent_size = MAX(def->extent_size, OG_SWAP_EXTENT_SIZE);
        if (spc_prepare_swap_encrypt(session, space) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (def->autoallocate) {
        SPACE_SET_AUTOALLOCATE(space);
        space->ctrl->extent_size = OG_MIN_EXTENT_SIZE;
    }

    if (def->bitmapmanaged) {
        SPACE_SET_BITMAPMANAGED(space);
    }

    if (def->encrypt) {
        if (SPACE_IS_DEFAULT(space)) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to encrypt system space");
            return OG_ERROR;
        }

        if (session->kernel->lsnd_ctx.standby_num > 0 &&
            !DB_IS_RAFT_ENABLED(session->kernel)) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to create encrypt space when database in HA mode");
            return OG_ERROR;
        }

        space->ctrl->encrypt_version = 0;
        if (page_cipher_reserve_size(session, space->ctrl->encrypt_version,
            &space->ctrl->cipher_reserve_size) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (spc_active_undo_encrypt(session, dtc_my_ctrl(session)->undo_space) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (spc_active_undo_encrypt(session, DB_CORE_CTRL(session)->temp_undo_space) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (spc_active_swap_encrypt(session) != OG_SUCCESS) {
            return OG_ERROR;
        }

        SPACE_SET_ENCRYPT(space);
    }

    return OG_SUCCESS;
}

static status_t spc_init_space_ctrl(knl_session_t *session, knl_space_def_t *def, space_t *space)
{
    knl_device_def_t *file = NULL;

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        file = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (spc_create_datafile_precheck(session, space, file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    errno_t ret = memset_sp(&space->lock, sizeof(space->lock), 0, sizeof(space->lock));
    knl_securec_check(ret);
    ret = memset_sp(&space->ctrl_bak_lock, sizeof(space->ctrl_bak_lock), 0, sizeof(space->ctrl_bak_lock));
    knl_securec_check(ret);
    dls_init_spinlock(&space->ctrl_bak_lock, DR_TYPE_SPACE, DR_ID_SPACE_CTRL_BAKUP, space->ctrl->id);
    space->alarm_enabled = OG_TRUE;
    space->purging = OG_FALSE;
    space->swap_bitmap = OG_FALSE;

    space->ctrl->flag = 0;
    space->ctrl->used = OG_TRUE;
    space->ctrl->file_hwm = 0;
    space->ctrl->org_scn = db_inc_scn(session);
    space->ctrl->block_size = DEFAULT_PAGE_SIZE(session);
    space->ctrl->extent_size = (def->extent_size == 0) ? session->kernel->attr.default_extents : def->extent_size;
    space->ctrl->type = def->type;
    space->ctrl->is_for_create_db = def->is_for_create_db;

    cm_text2str(&def->name, space->ctrl->name, OG_NAME_BUFFER_SIZE);

    if (spc_init_flag(session, def, space) != OG_SUCCESS) {
        (void)spc_remove_space(session, space, (uint32)SPC_CLEAN_OPTION, OG_TRUE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t spc_build_space(knl_session_t *session, knl_space_def_t *def, space_t *space)
{
    knl_instance_t *kernel = session->kernel;
    knl_device_def_t *file = NULL;
    uint32 file_no;
    
    for (uint32 i = 0; i < def->datafiles.count; i++) {
        file = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (spc_create_datafile_precheck(session, space, file) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (spc_init_space_ctrl(session, def, space) != OG_SUCCESS) {
        return OG_ERROR;
    }

    space->lock.lock = 0;
    space->alarm_enabled = OG_TRUE;
    space->allow_extend = OG_TRUE;
    space->purging = OG_FALSE;
    space->swap_bitmap = OG_FALSE;
    space->punching = OG_FALSE;

    kernel->db.ctrl.core.space_count++;

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        file = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (spc_create_datafile(session, space, file, &file_no) != OG_SUCCESS) {
            (void)spc_remove_space_online(session, NULL, space, (uint32)SPC_CLEAN_OPTION);
            return OG_ERROR;
        }
    }

    if (db_save_space_ctrl(session, space->ctrl->id) != OG_SUCCESS) {
        (void)spc_remove_space_online(session, NULL, space, (uint32)SPC_CLEAN_OPTION);
        return OG_ERROR;
    }

    log_commit(session);
    return OG_SUCCESS;
}

status_t spc_create_space_precheck(knl_session_t *session, knl_space_def_t *def)
{
    /* check db status */
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "create tablespace");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t spc_check_undo_space(knl_session_t *session, knl_space_def_t *def)
{
    if (def->type == (SPACE_TYPE_UNDO | SPACE_TYPE_TEMP)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace with nologging");
        return OG_ERROR;
    }

    if (def->autoallocate) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace with extent autoallocate");
        return OG_ERROR;
    }

    if (def->encrypt) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace using encrypt");
        return OG_ERROR;
    }

    def->bitmapmanaged = OG_FALSE;
    def->extent_size = UNDO_EXTENT_SIZE;
    return OG_SUCCESS;
}

static status_t spc_create_space_prepare(knl_session_t *session, knl_space_def_t *def, space_t **new_space)
{
    space_t *space = NULL;

    /* autoallocate extent is not support on nologging space */
    if ((def->type & SPACE_TYPE_TEMP) && def->autoallocate) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create nologging tablespace with extent autoallocate");
        return OG_ERROR;
    }

    if (def->type & SPACE_TYPE_UNDO) {
        if (spc_check_undo_space(session, def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    uint32 used_count = 0;
    for (uint32 i = 0; i < OG_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (space->ctrl->used) {
            if (cm_text_str_equal(&def->name, space->ctrl->name) &&
                def->is_for_create_db == space->ctrl->is_for_create_db) {
                OG_THROW_ERROR(ERR_SPACE_ALREADY_EXIST, space->ctrl->name);
                return OG_ERROR;
            }
            used_count++;
            continue;
        }

        if (*new_space == NULL) {
            *new_space = space;
            (*new_space)->ctrl->id = i;
        }
    }

    if (used_count >= OG_MAX_SPACES || *new_space == NULL) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, OG_MAX_SPACES, "spaces");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/*
 * create a new tablespace and return space id
 */
status_t spc_create_space(knl_session_t *session, knl_space_def_t *def, uint32 *id)
{
    space_t *space = NULL;

    if (spc_create_space_prepare(session, def, &space) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (spc_build_space(session, def, space) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (spc_mount_space(session, space, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (db_save_space_ctrl(session, space->ctrl->id) != OG_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
    }

    *id = space->ctrl->id;
    OG_LOG_RUN_INF("[SPACE] succeed to create tablespace %s", space->ctrl->name);
    return OG_SUCCESS;
}

static status_t spc_create_memory_space(knl_session_t *session, space_t *space)
{
    return OG_ERROR;
}

static status_t spc_rebuild_datafile(knl_session_t *session, space_t *space, uint32 fileno)
{
    datafile_t *rb_df = DATAFILE_GET(session, space->ctrl->files[fileno]);
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;

    if (spc_build_datafile(session, rb_df, DATAFILE_FD(session, rb_df->ctrl->id)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SPACE] failed to build datafile %s", rb_df->ctrl->name);
        return OG_ERROR;
    }

    if (spc_open_datafile(session, rb_df, DATAFILE_FD(session, rb_df->ctrl->id)) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SPACE] failed to open datafile %s", rb_df->ctrl->name);
        return OG_ERROR;
    }

    if (cm_add_device_watch(rb_df->ctrl->type, rmon_ctx->watch_fd, rb_df->ctrl->name, &rb_df->wd) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[RMON]: failed to add monitor of datafile %s", rb_df->ctrl->name);
    }

    if (fileno == 0) {
        return spc_rebuild_space(session, space);
    }
    return OG_SUCCESS;
}

status_t spc_mount_space(knl_session_t *session, space_t *space, bool32 auto_offline)
{
    if (SPACE_IS_INMEMORY(space)) {
        if (spc_create_memory_space(session, space) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create space in memory");
            return OG_ERROR;
        }
    }

    space->swap_bitmap = OG_FALSE;

    /* mount datafile in space */
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        uint32 file_id = space->ctrl->files[i];
        if (OG_INVALID_ID32 == file_id) {
            continue;
        }

        datafile_t *df = DATAFILE_GET(session, file_id);
        df->file_no = i;
        df->space_id = space->ctrl->id;

        if (!DATAFILE_IS_ONLINE(df)) {
            OG_LOG_RUN_INF("[SPACE] offline space %s, cause datafile %s is offline",
                space->ctrl->name, df->ctrl->name);
            SPACE_UNSET_ONLINE(space);
            return OG_SUCCESS;
        }

        if (spc_open_datafile(session, df, DATAFILE_FD(session, file_id)) != OG_SUCCESS) {
            if (IS_SWAP_SPACE(space) && !cm_file_exist(df->ctrl->name)) {
                if (spc_rebuild_datafile(session, space, i) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                OG_LOG_RUN_INF("sucessfully rebuild datafile %s", df->ctrl->name);
            } else {
                if (auto_offline && spc_auto_offline_space(session, space, df)) {
                    return OG_SUCCESS;
                }

                OG_THROW_ERROR(ERR_DATAFILE_BREAKDOWN, df->ctrl->name, "try to offline it in MOUNT mode");
                return OG_ERROR;
            }
        }

        /* if the database shutdown abnormally when it's doing resize a datafile, the datafile's size in oper system
         * is bigger than it in database after restart, we will update the datafile's size in database, and if the
         * datafile's size in oper system is smaller than it in database after restart, we should extend it.
         */
        if (!DB_IS_CLUSTER(session) || (DB_IS_CLUSTER(session) && rc_is_master())) {
            int64 actual_size = cm_device_size(df->ctrl->type, session->datafiles[file_id]);
            knl_panic(actual_size != -1);
            knl_instance_t *kernel = (knl_instance_t *)session->kernel;
            if (actual_size > df->ctrl->size && !kernel->lrcv_ctx.is_building && !kernel->db.recover_for_restore) {
                cm_spin_lock(&session->kernel->db.ctrl_lock, NULL);
                df->ctrl->size = actual_size;
                // if the actual_size is not formatted to extent_size, it will be fixed at next auto_extend
                cm_spin_unlock(&session->kernel->db.ctrl_lock);
                if (db_save_datafile_ctrl(session, df->ctrl->id) != OG_SUCCESS) {
                    CM_ABORT(0, "[SPACE] ABORT INFO: failed to save datafile %u control file when mount space %u",
                             df->ctrl->id, space->ctrl->id);
                }
                OG_LOG_RUN_INF("abnormal power failure occurred during the last resize operation on %s ",
                    df->ctrl->name);
            }
            if (actual_size < df->ctrl->size && !kernel->lrcv_ctx.is_building && !kernel->db.recover_for_restore) {
                int64 extend_size = df->ctrl->size - actual_size;
                cm_spin_lock(&session->kernel->db.ctrl_lock, NULL);
                df->ctrl->size = actual_size;
                cm_spin_unlock(&session->kernel->db.ctrl_lock);
                if (spc_extend_datafile(session, df, &session->datafiles[file_id],
                                        extend_size, OG_FALSE) != OG_SUCCESS) {
                    return OG_ERROR;
                }
                OG_LOG_RUN_INF("abnormal power failure occurred during the last resize operation on %s ",
                    df->ctrl->name);
            }
        }
        /* if is the first datafile in space, we need to mount the space head */
        if (i == 0) {
            space->entry.page = SPACE_ENTRY_PAGE;
            space->entry.file = space->ctrl->files[i];
            // set brid 0, for compatibility; in bak, recovery->open both come in
            MEMS_RETURN_IFERR(memset_sp(&(space->lock.drid), sizeof(drid_t), 0, sizeof(drid_t)));
            dls_init_spinlock(&space->lock, DR_TYPE_SPACE, DR_ID_SPACE_OP, space->ctrl->id);

            if (buf_read_page(session, space->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != OG_SUCCESS) {
                if (auto_offline && spc_auto_offline_space(session, space, df)) {
                    return OG_SUCCESS;
                }
                return OG_ERROR;
            }

            space->head = SPACE_HEAD(session);
            buf_leave_page(session, OG_FALSE);
            spc_try_set_swap_bitmap(session, space);
        }

        /* mount the bitmap head of datafile, here NOT init SWAP space */
        if (SPACE_CTRL_IS_BITMAPMANAGED(space)) {
            df->map_head_entry.file = df->ctrl->id;
            df->map_head_entry.page = (df->ctrl->id == 0) ? DW_MAP_HEAD_PAGE : DF_MAP_HEAD_PAGE;

            if (buf_read_page(session, df->map_head_entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != OG_SUCCESS) {
                if (auto_offline && spc_auto_offline_space(session, space, df)) {
                    return OG_SUCCESS;
                }
                return OG_ERROR;
            }
            df->map_head = (df_map_head_t *)CURR_PAGE(session);
            buf_leave_page(session, OG_FALSE);
        }
    }

    if (IS_SWAP_SPACE(space)) {
        if (spc_prepare_swap_encrypt(session, space) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (IS_TEMP2_UNDO_SPACE(space)) {
        spc_rebuild_temp2_undo(session, space);
    }

    space->purging = OG_FALSE;
    space->is_empty = OG_FALSE;
    space->allow_extend = OG_TRUE;
    space->alarm_enabled = OG_TRUE;

    SPACE_SET_ONLINE(space);

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif

