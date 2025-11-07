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
 * knl_db_alter.c
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_alter.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "knl_db_alter.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_ctlg.h"
#include "cm_file.h"
#include "dtc_database.h"
#include "dtc_dc.h"

typedef enum st_failover_fail_type {
    FAILOVER_INVALID_STATUS = 1,
    FAILOVER_INVALID_ROLE = 2,
    FAILOVER_ABORT_BY_OTHER = 3,
    FAILOVER_ABORT_BY_MASTER = 4,
} failover_fail_type_t;

static status_t db_alter_convert_standby_precheck(knl_session_t *session, bool32 is_cascaded)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 log_count;

    if (db->status != DB_STATUS_MOUNT) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "convert standby");
        return OG_ERROR;
    }

    log_count = log_get_count(session);
    if (log_count < OG_MIN_LOG_FILES) {
        OG_THROW_ERROR(ERR_LOG_FILE_NOT_ENOUGH);
        return OG_ERROR;
    }

    if (!DB_IS_PRIMARY(db) && !is_cascaded) {
        OG_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "not in primary mode");
        return OG_ERROR;
    }

    if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && is_cascaded) {
        OG_THROW_ERROR(ERR_DATABASE_ROLE, "operation", "in a cascaded physical standby mode");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_alter_convert_to_standby(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION,
            ",RAFT: alter to standby not supported when raft is enabled, please use failver.sh instead.");
        return OG_ERROR;
    }

    if (db_alter_convert_standby_precheck(session, def->is_cascaded) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (def->is_cascaded) {
        db->ctrl.core.db_role = REPL_ROLE_CASCADED_PHYSICAL_STANDBY;
    } else {
        db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    }

    kernel->lrcv_ctx.reconnected = OG_FALSE;

    if (def->is_mount) {
        if (db_save_core_ctrl(session) != OG_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: save core control file failed when convert database role.");
        }
    } else {
        kernel->rcy_ctx.is_demoting = OG_TRUE;
        db_open_opt_t open_options = {
            OG_FALSE, OG_FALSE, OG_FALSE, OG_FALSE, OG_TRUE, DB_OPEN_STATUS_NORMAL, OG_INVALID_LFN
        };
        if (db_open(session, &open_options) != OG_SUCCESS) {
            kernel->rcy_ctx.is_demoting = OG_FALSE;
            return OG_ERROR;
        }
        kernel->rcy_ctx.is_demoting = OG_TRUE;
    }

    OG_LOG_RUN_INF("[DB] demote to %s completely", def->is_cascaded ? "cascaded standby" : "standby");
    return OG_SUCCESS;
}

static status_t db_notify_open_mode_reset(knl_session_t *session, switch_req_t request)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return OG_ERROR;
    }

    ctrl->keep_sid = session->id;
    ctrl->request = request;

    cm_spin_unlock(&ctrl->lock);

    OG_LOG_RUN_INF("[DB] notify server to set %s", ctrl->request == SWITCH_REQ_READONLY ? "READONLY" : "NON_UPGRADE");

    return OG_SUCCESS;
}

static status_t db_alter_readmode_precheck(knl_session_t *session, bool32 convert_to_readonly)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    OG_LOG_RUN_INF("[DB] start precheck for converting to %s", convert_to_readonly ? "readonly" : "readwrite");
    if (db->status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return OG_ERROR;
    }

    cm_spin_lock(&ctrl->lock, NULL);
    if (ctrl->request == SWITCH_REQ_READONLY) {
        cm_spin_unlock(&ctrl->lock);
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",another operation for readonly mode is running");
        return OG_ERROR;
    }
    cm_spin_unlock(&ctrl->lock);

    if (convert_to_readonly && (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session))) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in READ WRITE mode");
        return OG_ERROR;
    }
    if (!convert_to_readonly && !DB_IS_READONLY(session)) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in READ ONLY mode");
        return OG_ERROR;
    }
    if (!convert_to_readonly && !DB_IS_PRIMARY(db)) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported by primary role");
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[DB] precheck finished for converting to %s", convert_to_readonly ? "readonly" : "readwrite");

    return OG_SUCCESS;
}

status_t db_alter_convert_to_readonly(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (db_alter_readmode_precheck(session, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (db_notify_open_mode_reset(session, SWITCH_REQ_READONLY) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cm_unlatch(&session->kernel->db.ddl_latch.latch, NULL);

    while (!DB_IS_READONLY(session) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            cm_latch_s(&session->kernel->db.ddl_latch.latch, session->id, OG_FALSE, NULL);
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }

        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request != SWITCH_REQ_NONE && ctrl->request != SWITCH_REQ_READONLY) {
            cm_spin_unlock(&ctrl->lock);
            cm_latch_s(&session->kernel->db.ddl_latch.latch, session->id, OG_FALSE, NULL);
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "readonly setting aborted by other request");
            OG_LOG_RUN_ERR("[DB] readonly setting aborted by other request");

            return OG_ERROR;
        }
        cm_spin_unlock(&ctrl->lock);
        cm_sleep(10);
    }

    OG_LOG_RUN_INF("[DB] convert to readonly successfully");
    cm_latch_s(&session->kernel->db.ddl_latch.latch, session->id, OG_FALSE, NULL);

    OG_LOG_RUN_INF("[DB] add latch after readonly");
    return OG_SUCCESS;
}

status_t db_alter_convert_to_readwrite(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    if (db_alter_readmode_precheck(session, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    db->is_readonly = OG_FALSE;
    db->readonly_reason = MANUALLY_SET;

    if (tx_rollback_start(session) != OG_SUCCESS) {
        CM_ABORT(0, "[DB] READWIRTE ABORT INFO: failed to start txn rollback thread, convert to readwrite failed");
    }

    if (db_garbage_segment_clean(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[DB] READWIRTE: failed to clean garbage segment");
    }

    rmon_clean_alarm(session);

    OG_LOG_RUN_INF("[DB] READWIRTE: convert to readwrite successfully");

    return OG_SUCCESS;
}

static status_t db_alter_upgrade_mode_precheck(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    OG_LOG_RUN_INF("[DB] start precheck for cancelling upgrade mode");
    if (!DB_IS_PRIMARY(db)) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in primary database");
        return OG_ERROR;
    }

    if (db->status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return OG_ERROR;
    }

    if (!DB_IS_UPGRADE(session)) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in UPGRADE mode");
        return OG_ERROR;
    }

    if (db->open_status != DB_OPEN_STATUS_UPGRADE_PHASE_2) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported after initializing all objects");
        return OG_ERROR;
    }
    OG_LOG_RUN_INF("[DB] precheck finished for cancelling upgrade mode");

    return OG_SUCCESS;
}

status_t db_alter_cancel_upgrade(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;

    if (db_alter_upgrade_mode_precheck(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (db_notify_open_mode_reset(session, SWITCH_REQ_CANCEL_UPGRADE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (DB_IS_UPGRADE(session) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }

        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request != SWITCH_REQ_NONE && ctrl->request != SWITCH_REQ_CANCEL_UPGRADE) {
            cm_spin_unlock(&ctrl->lock);
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "CANCEL UPGRADE setting aborted by other request");
            OG_LOG_RUN_ERR("[DB] CANCEL UPGRADE setting aborted by other request");

            return OG_ERROR;
        }
        cm_spin_unlock(&ctrl->lock);
        cm_sleep(10);
    }
    OG_LOG_RUN_INF("[DB] cancel upgrade mode successfully");

    return OG_SUCCESS;
}

status_t db_alter_delete_archivelog(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_alterdb_archivelog_t arch_def = def->dele_arch;
    // to delete archive log
    if (arch_def.until_time > session->kernel->attr.timer->now) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "delete later than the present time", "archive log");
        return OG_ERROR;
    }

    if (arch_force_clean(session, &arch_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_alter_delete_backupset(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_alterdb_backupset_t bakset_def = def->dele_bakset;

    if (!DB_IS_OPEN(session)) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "delete backupset operation");
        return OG_ERROR;
    }

    if (DB_IS_READONLY(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "delete backupset operation on read only mode");
        return OG_ERROR;
    }

    if (bak_delete_backup_set(session, &bakset_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_alter_clear_logfile(knl_session_t *session, uint32 file_id)
{
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    logfile_set_t *logfile_set = MY_LOGFILE_SET(session);

    if (file_id >= dtc_my_ctrl(session)->log_hwm) {
        OG_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        return OG_ERROR;
    }

    if (DB_STATUS(session) != DB_STATUS_MOUNT) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "clear logfile");
        return OG_ERROR;
    }

    log_lock_logfile(session);
    logfile = &logfile_set->items[file_id];

    cm_latch_x(&logfile->latch, session->id, NULL);
    if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
        OG_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        cm_unlatch(&logfile->latch, NULL);
        log_unlock_logfile(session);
        return OG_ERROR;
    }

    if (logfile->ctrl->status != LOG_FILE_INACTIVE && logfile->ctrl->status != LOG_FILE_UNUSED) {
        OG_THROW_ERROR(ERR_LOG_IN_USE);
        cm_unlatch(&logfile->latch, NULL);
        log_unlock_logfile(session);
        return OG_ERROR;
    }

    logfile->head.first = OG_INVALID_ID64;
    logfile->head.last = OG_INVALID_ID64;
    logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    logfile->head.block_size = (int32)logfile->ctrl->block_size;
    logfile->head.rst_id = db->ctrl.core.resetlogs.rst_id;
    logfile->head.asn = OG_INVALID_ASN;
    logfile->head.cmp_algorithm = COMPRESS_NONE;

    log_flush_head(session, logfile);

    cm_unlatch(&logfile->latch, NULL);
    log_unlock_logfile(session);

    return OG_SUCCESS;
}

status_t db_alter_rebuild_space(knl_session_t *session, text_t *name)
{
    space_t *space = NULL;
    uint32 space_id;

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in mount mode");
        return OG_ERROR;
    }

    if (OG_SUCCESS != spc_get_space_id(session, name, OG_FALSE, &space_id)) {
        return OG_ERROR;
    }

    space = KNL_GET_SPACE(session, space_id);

    return spc_rebuild_space(session, space);
}

status_t db_alter_protection_mode(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    switch (def->standby.alter_standby_mode) {
        case ALTER_SET_PROTECTION:
            if (lsnd_check_protection_standby_num(session) != OG_SUCCESS) {
                return OG_ERROR;
            }
            db->ctrl.core.protect_mode = MAXIMUM_PROTECTION;
            break;

        case ALTER_SET_AVAILABILITY:
            db->ctrl.core.protect_mode = MAXIMUM_AVAILABILITY;
            break;

        case ALTER_SET_PERFORMANCE:
            db->ctrl.core.protect_mode = MAXIMUM_PERFORMANCE;
            break;

        default:
            cm_assert(OG_FALSE);
    }

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter protection mode");
    }

    return OG_SUCCESS;
}

static status_t db_notify_failover_promote(knl_session_t *session, lrcv_context_t *lrcv, bool32 force)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&lrcv->lock, NULL);
    bool32 connected = (bool32)(lrcv->session != NULL);

    if (connected && !force) {
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "could not issue failover when not disconnected, "
                       "please try force failover");
        return OG_ERROR;
    }

    if (lrcv->state != REP_STATE_NORMAL) {
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return OG_ERROR;
    }

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return OG_ERROR;
    }

    ctrl->keep_sid = session->id;
    ctrl->request = force ? SWITCH_REQ_FORCE_FAILOVER_PROMOTE : SWITCH_REQ_FAILOVER_PROMOTE;

    cm_spin_unlock(&ctrl->lock);
    cm_spin_unlock(&lrcv->lock);

    if (connected) {
        lrcv_close(session);
    }

    OG_LOG_RUN_INF("[DB] notify server to do %sfailover", force ? "force " : "");
    return OG_SUCCESS;
}

static void db_throw_failover_error(bool32 force, failover_fail_type_t type)
{
    switch (type) {
        case FAILOVER_INVALID_STATUS: {
            if (force) {
                OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
                    "force failover cannot be issued when database isn't in open status");
            } else {
                OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
                    "failover cannot be issued when database isn't in open status");
            }
            break;
        }

        case FAILOVER_INVALID_ROLE: {
            if (force) {
                OG_THROW_ERROR(ERR_DATABASE_ROLE, "force failover", "not in standby mode");
            } else {
                OG_THROW_ERROR(ERR_DATABASE_ROLE, "failover", "not in standby mode");
            }
            break;
        }

        case FAILOVER_ABORT_BY_OTHER: {
            if (force) {
                OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "force failover aborted by other request");
                OG_LOG_RUN_ERR("[DB] force failover aborted by other request");
            } else {
                OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failover aborted by other request");
                OG_LOG_RUN_ERR("[DB] failover aborted by other request");
            }
            break;
        }

        case FAILOVER_ABORT_BY_MASTER: {
            if (force) {
                OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "force failover aborted by master");
                OG_LOG_RUN_ERR("[DB] force failover aborted by master");
            } else {
                OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "failover aborted by master");
                OG_LOG_RUN_ERR("[DB] failover aborted by master");
            }
        }
    }
}

static status_t db_alter_failover_check(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        db_throw_failover_error(def->force_failover, FAILOVER_INVALID_STATUS);
        return OG_ERROR;
    }

    if (db->terminate_lfn != OG_INVALID_LFN) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "failover with terminated lfn");
        return OG_ERROR;
    }

    if (DB_IS_PRIMARY(db)) {
        db_throw_failover_error(def->force_failover, FAILOVER_INVALID_ROLE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_alter_failover(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    log_context_t *redo_ctx = &kernel->redo_ctx;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    database_t *db = &kernel->db;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;

    if (db_alter_failover_check(session, def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("[DB] database start to %sfailover", def->force_failover ? "force " : "");
    if (DB_IS_RAFT_ENABLED(kernel)) {
        knl_panic(lrcv->session == NULL);
        lrcv->session = NULL;
        raft_pending_switch_request(session, ctrl);
        if (raft_db_start_leader(session) != OG_SUCCESS) {
            ctrl->request = SWITCH_REQ_NONE;
            ctrl->handling = OG_FALSE;
            OG_LOG_RUN_WAR("RAFT: promote leader failed.");
            return OG_ERROR;
        }
    } else {
        if (db_notify_failover_promote(session, lrcv, def->force_failover) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    redo_ctx->promote_begin_time = cm_now();
    while (!DB_IS_PRIMARY(db) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }

        cm_spin_lock(&ctrl->lock, NULL);
        if (ctrl->request != SWITCH_REQ_NONE && !knl_failover_triggered_pending(session->kernel)) {
            cm_spin_unlock(&ctrl->lock);
            db_throw_failover_error(def->force_failover, FAILOVER_ABORT_BY_OTHER);
            return OG_ERROR;
        }
        if (ctrl->request == SWITCH_REQ_NONE && !ctrl->handling) {
            cm_spin_unlock(&ctrl->lock);
            db_throw_failover_error(def->force_failover, FAILOVER_ABORT_BY_MASTER);
            return OG_ERROR;
        }
        cm_spin_unlock(&ctrl->lock);
        cm_sleep(10);
    }

    redo_ctx->promote_end_time = cm_now();
    OG_LOG_RUN_INF("%sfailover completed", def->force_failover ? "force " : "");

    return OG_SUCCESS;
}

static status_t db_notify_lrcv_switchover(knl_session_t *session, lrcv_context_t *lrcv)
{
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;

    cm_spin_lock(&lrcv->lock, NULL);
    if (lrcv->session == NULL || (lrcv->status != LRCV_PREPARE && lrcv->status != LRCV_READY)) {
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "could not issue switchover when primary isn't connected");
        return OG_ERROR;
    }

    if (lrcv->state != REP_STATE_NORMAL) {
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover aborted by other request");
        return OG_ERROR;
    }

    if (!lrcv_switchover_enabled(session)) {
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST,
            "could not issue switchover for the link from this node to peer(primary) is disabled");
        return OG_ERROR;
    }

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->request != SWITCH_REQ_NONE) {
        cm_spin_unlock(&ctrl->lock);
        cm_spin_unlock(&lrcv->lock);
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "server is handling another switch request");
        return OG_ERROR;
    }

    cm_spin_unlock(&ctrl->lock);

    lrcv->state = REP_STATE_DEMOTE_REQUEST;
    cm_spin_unlock(&lrcv->lock);

    OG_LOG_RUN_INF("[DB] notify log receiver to do switchover");

    return OG_SUCCESS;
}

static bool32 db_switchover_timeout_check(knl_session_t *session, knl_alterdb_def_t *def, date_t begin_time)
{
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;

    if (def->switchover_timeout == 0) {
        return OG_FALSE;
    }

    if ((g_timer()->now - begin_time) / MICROSECS_PER_SECOND >= def->switchover_timeout) {
        cm_spin_lock(&lrcv->lock, NULL);
        if (lrcv->state != REP_STATE_STANDBY_PROMOTING) {
            lrcv->state = REP_STATE_NORMAL;
            cm_spin_unlock(&lrcv->lock);
            return OG_TRUE;
        }
        cm_spin_unlock(&lrcv->lock);
    }

    return OG_FALSE;
}

static status_t db_alter_switchover_check(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover cannot be issued when database isn't in open status");
        return OG_ERROR;
    }

    if (db->terminate_lfn != OG_INVALID_LFN) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "switchover with terminated lfn");
        return OG_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(kernel)) {
        OG_THROW_ERROR(ERR_RAFT_ENABLED);
        return OG_ERROR;
    }

    if (!DB_IS_PHYSICAL_STANDBY(db)) {
        OG_THROW_ERROR(ERR_DATABASE_ROLE, "switchover", "not in standby mode");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_alter_switchover(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;
    database_t *db = &kernel->db;
    date_t begin_time = g_timer()->now;

    ctrl->peer_repl_port = lrcv->peer_repl_port;

    if (db_alter_switchover_check(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (db_notify_lrcv_switchover(session, lrcv) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (DB_IS_PHYSICAL_STANDBY(db) || ctrl->request != SWITCH_REQ_NONE) {
        if (session->killed) {
            OG_THROW_ERROR(ERR_OPERATION_KILLED);
            return OG_ERROR;
        }

        if (lrcv->state == REP_STATE_REJECTED) {
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover request rejected");
            OG_LOG_RUN_ERR("[DB] switchover request rejected");
            lrcv->state = REP_STATE_NORMAL;
            return OG_ERROR;
        }

        if (lrcv->state == REP_STATE_DEMOTE_FAILED) {
            OG_THROW_ERROR(ERR_PEER_CLOSED, "switchover failed, for tcp");
            OG_LOG_RUN_ERR("[DB] switchover failed, for connection is closed");
            lrcv->state = REP_STATE_NORMAL;
            return OG_ERROR;
        }

        if (db_switchover_timeout_check(session, def, begin_time)) {
            OG_THROW_ERROR(ERR_INVALID_SWITCH_REQUEST, "switchover timeout");
            OG_LOG_RUN_ERR("[DB] switchover timeout");
            return OG_ERROR;
        }

        cm_sleep(10);
    }
    OG_LOG_RUN_INF("switchover completed");

    return OG_SUCCESS;
}

status_t db_alter_logicrep(knl_session_t *session, lrep_mode_t logic_mode)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    dtc_node_ctrl_t *node_ctrl = dtc_my_ctrl(session);
    rd_alter_db_logicrep_t redo;

    if (db->status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return OG_ERROR;
    }

    if (logic_mode == LOG_REPLICATION_ON) {
        bool32 has_nolog = OG_FALSE;
        if (knl_database_has_nolog_object(session, &has_nolog) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (has_nolog) {
            OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set logic mode on when database has nolog object");
            return OG_ERROR;
        }
    }
    
    db->ctrl.core.lrep_mode = logic_mode;
    ckpt_get_trunc_point(session, &db->ctrl.core.lrep_point);
    ckpt_get_trunc_point(session, &node_ctrl->lrep_point);

    log_atomic_op_begin(session);
    // logic redo
    redo.op_type = RD_ALTER_DB_LOGICREP;
    redo.logic_mode = logic_mode;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_alter_db_logicrep_t), LOG_ENTRY_FLAG_NONE);
    ckpt_disable(session);
    log_atomic_op_end(session);

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter database");
    }

    if (db_save_node_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save node control file when alter database");
    }

    // sync ddl
    if (DB_IS_CLUSTER(session)) {
        tx_copy_logic_log(session);
        if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
            dtc_sync_ddl(session);
        }
    }
    ckpt_enable(session);
    return OG_SUCCESS;
}

status_t db_alter_archivelog(knl_session_t *session, archive_mode_t archive_mode)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (archive_mode == ARCHIVE_LOG_OFF && arch_has_valid_arch_dest(session)) {
        OG_THROW_ERROR(ERR_CANNOT_CLOSE_ARCHIVE);
        return OG_ERROR;
    }

    db->ctrl.core.log_mode = archive_mode;
    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter database");
    }
    return OG_SUCCESS;
}

status_t db_alter_charset(knl_session_t *session, uint32 charset_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    if (db->status != DB_STATUS_OPEN) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in OPEN mode");
        return OG_ERROR;
    }

    db->ctrl.core.charset_id = charset_id;
    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save core control file when alter database");
    }
    return OG_SUCCESS;
}

status_t db_alter_datafile(knl_session_t *session, knl_alterdb_datafile_t *def)
{
    status_t status = OG_ERROR;

    if (DB_IS_READONLY(session)) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return OG_ERROR;
    }

    switch (def->alter_datafile_mode) {
        case ALTER_DF_AUTOEXTEND_OFF:
        case ALTER_DF_AUTOEXTEND_ON:
            status = spc_alter_datafile_autoextend(session, def);
            break;
        case ALTER_DF_RESIZE:
            status = spc_alter_datafile_resize(session, def);
            break;
        default:
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "alter datafile mode");
            OG_LOG_DEBUG_ERR("the alter datafile mode 0x%8X is not supported.", def->alter_datafile_mode);
            return OG_ERROR;
        }

    return status;
}
