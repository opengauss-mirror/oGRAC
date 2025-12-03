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
 * srv_instance.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_instance.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cm_file.h"
#include "srv_instance.h"
#include "load_others.h"
#include "load_kernel.h"
#include "srv_view.h"
#include "cm_signal.h"
#include "cm_license.h"
#include "pl_ext_proc.h"
#ifndef WIN32
#include "srv_blackbox.h"
#endif

#include "cm_regexp.h"
#include "ogsql_serial.h"
#include "cm_utils.h"
#include "ogsql_self_func.h"
#include "ogsql_type_map.h"
#include "ogsql_service.h"
#include "ogsql_expr.h"
#include "ogsql_serial.h"
#include "ogsql_cond.h"
#include "srv_emerg.h"
#include "ogsql_dependency.h"
#include "ogsql_update.h"
#include "ddl_executor.h"
#include <locale.h>
#include "cm_thread_pool.h"
#include "cm_ip.h"
#include "ogsql_mtrl.h"
#include "pl_ddl_executor.h"
#include "pl_synonym.h"
#include "pl_logic.h"
#include "srv_stat.h"
#include "dtc_dcs.h"
#include "dtc_context.h"
#include "dtc_dls.h"
#include "dtc_database.h"

#ifdef __cplusplus
extern "C" {
#endif


instance_t *g_instance = NULL;
char *g_database_home = NULL;
static const char *g_lock_file = "ogracd.lck";

static status_t srv_wait_agents_done(void);
static void srv_close_threads(bool32 knl_flag);
static void srv_deinit_resource(void);
static status_t init_job_manager(void);

os_run_desc_t g_os_stat_desc_array[TOTAL_OS_RUN_INFO_TYPES] = {
    /* cpu numbers */
    { "NUM_CPUS",        "Number of CPUs or processors available",                                                                                                                OG_FALSE, OG_FALSE },
    { "NUM_CPU_CORES",   "Number of CPU cores available (includes subcores of multicore CPUs as well as single-core CPUs)",                                                       OG_FALSE, OG_FALSE },
    { "NUM_CPU_SOCKETS", "Number of CPU sockets available (represents an absolute count of CPU chips on the system, regardless of ""multithreading or multi-core architectures)", OG_FALSE, OG_FALSE },
    /* cpu times */
    { "IDLE_TIME",   "Number of hundredths of a second that a processor has been idle, totalled over all processors",                                  OG_TRUE, OG_FALSE },
    { "BUSY_TIME",   "Number of hundredths of a second that a processor has been busy executing user or kernel code, totalled over ""all processors",    OG_TRUE, OG_FALSE },
    { "USER_TIME",   "Number of hundredths of a second that a processor has been busy executing user code, totalled over all ""processors",              OG_TRUE, OG_FALSE },
    { "SYS_TIME",    "Number of hundredths of a second that a processor has been busy executing kernel code, totalled over all ""processors",            OG_TRUE, OG_FALSE },
    { "IOWAIT_TIME", "Number of hundredths of a second that a processor has been waiting for I/O to complete, totalled over all ""processors",           OG_TRUE, OG_FALSE },
    { "NICE_TIME",   "Number of hundredths of a second that a processor has been busy executing low-priority user code, totalled over ""all processors", OG_TRUE, OG_FALSE },
    /* avg cpu times */
    { "AVG_IDLE_TIME",   "Number of hundredths of a second that a processor has been idle, averaged over all processors",                                  OG_TRUE, OG_FALSE },
    { "AVG_BUSY_TIME",   "Number of hundredths of a second that a processor has been busy executing user or kernel code, averaged over ""all processors",    OG_TRUE, OG_FALSE },
    { "AVG_USER_TIME",   "Number of hundredths of a second that a processor has been busy executing user code, averaged over all ""processors",              OG_TRUE, OG_FALSE },
    { "AVG_SYS_TIME",    "Number of hundredths of a second that a processor has been busy executing kernel code, averaged over all ""processors",            OG_TRUE, OG_FALSE },
    { "AVG_IOWAIT_TIME", "Number of hundredths of a second that a processor has been waiting for I/O to complete, averaged over all ""processors",           OG_TRUE, OG_FALSE },
    { "AVG_NICE_TIME",   "Number of hundredths of a second that a processor has been busy executing low-priority user code, averaged over ""all processors", OG_TRUE, OG_FALSE },
    /* virtual memory page in/out data */
    { "VM_PAGE_IN_BYTES", "Total number of bytes of data that have been paged in due to virtual memory paging", OG_TRUE, OG_FALSE },
    { "VM_PAGE_OUT_BYTES", "Total number of bytes of data that have been paged out due to virtual memory paging", OG_TRUE, OG_FALSE },
    /* os run load */
    { "LOAD", "Current number of processes that are either running or in the ready state, waiting to be selected by the ""operating-system scheduler to run. On many platforms, this statistic reflects the average load over the past ""minute.", OG_FALSE, OG_FALSE },
    /* physical memory size */
    { "PHYSICAL_MEMORY_BYTES", "Total number of bytes of physical memory", OG_FALSE, OG_FALSE }
};

const char *g_shutdown_mode_desc[SHUTDOWN_MODE_END] = {
    "normal", "immediate", "signal", "abort"
};

static status_t init_job_manager(void)
{
    knl_instance_t *kernel = &g_instance->kernel;

    // start job thread
    return cm_create_thread(jobs_proc, 0, kernel->sessions[SESSION_ID_JOB], &kernel->job_ctx.thread);
}

static void handle_signal_terminal(int sig_no)
{
    g_instance->lsnr_abort_status = OG_TRUE;
}

static void exec_abnormal_terminal(void)
{
    OG_LOG_RUN_WAR("exec_abnormal_terminal");
    srv_instance_abort();
}

static void srv_destory_reserved_session(void)
{
    session_t *session = NULL;
    uint32 i;

    for (i = 0; i < g_instance->kernel.reserved_sessions; i++) {
        session = g_instance->session_pool.sessions[i];
        if (session != NULL) {
            knl_destroy_session(&g_instance->kernel, i);
            CM_FREE_PTR(session->stack);
            CM_FREE_PTR(session);
            g_instance->session_pool.sessions[i] = NULL;
        }
    }

    for (i = 0; i < g_instance->rm_pool.page_count; i++) {
        CM_FREE_PTR(g_instance->rm_pool.pages[i]);
    }
}

static status_t srv_ssl_check_params(int32 *alert_day)
{
    int32 detect_day;
    if (OG_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_EXPIRE_ALERT_THRESHOLD"), alert_day)) {
        return OG_ERROR;
    }

    if (!(*alert_day >= OG_MIN_SSL_EXPIRE_THRESHOLD && *alert_day <= OG_MAX_SSL_EXPIRE_THRESHOLD)) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SSL_EXPIRE_ALERT_THRESHOLD", (int64)OG_MIN_SSL_EXPIRE_THRESHOLD,
            (int64)OG_MAX_SSL_EXPIRE_THRESHOLD);
        return OG_ERROR;
    }

    if (OG_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_PERIOD_DETECTION"), &detect_day)) {
        return OG_ERROR;
    }

    if (!(detect_day >= OG_MIN_SSL_PERIOD_DETECTION && detect_day <= OG_MAX_SSL_PERIOD_DETECTION)) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SSL_PERIOD_DETECTION", (int64)OG_MIN_SSL_PERIOD_DETECTION,
            (int64)OG_MAX_SSL_PERIOD_DETECTION);
        return OG_ERROR;
    }

    if (detect_day > *alert_day) {
        OG_LOG_RUN_ERR("SSL disabled: the value of SSL_PERIOD_DETECTION "
            "is bigger than the value of SSL_EXPIRE_ALERT_THRESHOLD");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_init_ssl_communication()
{
    ssl_config_t para;
    char *keypwd_cipher = NULL;
    char *verify_peer = NULL;
    char plain[OG_PASSWD_MAX_LEN + OG_AESBLOCKSIZE + 4];
    g_instance->ssl_acceptor_fd = NULL;
    int32 alert_day = 0;
    char real_path[OG_FILE_NAME_BUFFER_SIZE] = { 0 };

    MEMS_RETURN_IFERR(memset_s(&para, sizeof(ssl_config_t), 0, sizeof(ssl_config_t)));
    // load SSL parameters
    para.ca_file = cm_get_config_value(&g_instance->config, "SSL_CA");
    para.cert_file = cm_get_config_value(&g_instance->config, "SSL_CERT");
    para.key_file = cm_get_config_value(&g_instance->config, "SSL_KEY");
    para.crl_file = cm_get_config_value(&g_instance->config, "SSL_CRL");
    para.cipher = cm_get_config_value(&g_instance->config, "SSL_CIPHER");
    keypwd_cipher = cm_get_config_value(&g_instance->config, "SSL_KEY_PASSWORD");
    verify_peer = cm_get_config_value(&g_instance->config, "SSL_VERIFY_PEER");
    if (cm_str_equal_ins(verify_peer, "TRUE")) {
        para.verify_peer = OG_TRUE;
    } else if (cm_str_equal_ins(verify_peer, "FALSE")) {
        para.verify_peer = OG_FALSE;
    } else {
        OG_LOG_RUN_ERR("the value of parameter \"SSL_VERIFY_PEER\" is invalid");
        return OG_ERROR;
    }
    (void)cm_alter_config(&g_instance->config, "HAVE_SSL", "FALSE", CONFIG_SCOPE_MEMORY, OG_TRUE);

    if (CM_IS_EMPTY_STR(para.ca_file) && para.verify_peer) {
        para.verify_peer = OG_FALSE;
        (void)cm_alter_config(&g_instance->config, "SSL_VERIFY_PEER", "FALSE", CONFIG_SCOPE_MEMORY, OG_TRUE);
    }

    /* For server side, certifiate and key files are required */
    if (CM_IS_EMPTY_STR(para.cert_file) || CM_IS_EMPTY_STR(para.key_file)) {
        OG_LOG_RUN_INF("SSL disabled: server certificate or private key file is not available.");
        return OG_SUCCESS;
    }

    /* Require no public access to key file */
    OG_RETURN_IFERR(realpath_file(para.ca_file, real_path, OG_FILE_NAME_BUFFER_SIZE));
    if (cs_ssl_verify_file_stat(real_path) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("SSL CA certificate file \"%s\" has execute, group or world access permission.", para.ca_file);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(realpath_file(para.cert_file, real_path, OG_FILE_NAME_BUFFER_SIZE));
    if (cs_ssl_verify_file_stat(real_path) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("SSL server certificate file \"%s\" has execute, group or world access permission.",
            para.cert_file);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(realpath_file(para.key_file, real_path, OG_FILE_NAME_BUFFER_SIZE));
    if (cs_ssl_verify_file_stat(real_path) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("SSL private key file \"%s\" has execute, group or world access permission.", para.key_file);
        return OG_ERROR;
    }

    // decrypt cipher if not null
    if (!CM_IS_EMPTY_STR(keypwd_cipher)) {
        char *factor_key = cm_get_config_value(&g_instance->config, "_FACTOR_KEY");
        char *local_key = cm_get_config_value(&g_instance->config, "LOCAL_KEY");
        uint32 plain_len = sizeof(plain) - 1;
        if (cm_decrypt_passwd(OG_TRUE, keypwd_cipher, (uint32)strlen(keypwd_cipher), plain, &plain_len,
            local_key, factor_key) != OG_SUCCESS) {
            OG_LOG_RUN_INF("SSL disabled: decrypt SSL private key password failed.");
            return OG_SUCCESS;
        }
        plain[plain_len] = '\0';
        para.key_password = plain;
    }

    // create acceptor context
    g_instance->ssl_acceptor_fd = cs_ssl_create_acceptor_fd(&para);

    if (g_instance->ssl_acceptor_fd == NULL) {
        OG_LOG_RUN_INF("SSL disabled: create SSL context failed.");
    } else {
        (void)cm_alter_config(&g_instance->config, "HAVE_SSL", "TRUE", CONFIG_SCOPE_MEMORY, OG_TRUE);

        OG_LOG_RUN_INF("SSL context initialized.");

        OG_RETURN_IFERR(srv_ssl_check_params(&alert_day));

        ssl_ca_cert_expire(g_instance->ssl_acceptor_fd, alert_day);
    }

    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));

    return OG_SUCCESS;
}

static status_t srv_ssl_expire_warning(void)
{
    int32 alert_day;
    int32 detect_day;
    if (OG_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_EXPIRE_ALERT_THRESHOLD"), &alert_day)) {
        return OG_ERROR;
    }

    if (OG_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_PERIOD_DETECTION"), &detect_day)) {
        return OG_ERROR;
    }

    // the range of SSL_PERIOD_DETECTION is [1,180]
    if ((g_timer()->systime / SECONDS_PER_DAY) % detect_day == 0) {
        ssl_ca_cert_expire(g_instance->ssl_acceptor_fd, alert_day);
    }
    return OG_SUCCESS;
}

static status_t srv_init_session_pool(void)
{
    uint32 i;
    uint32 id;

    // init transaction resource manager pool
    rm_pool_init(&g_instance->rm_pool);

    stat_pool_init(&g_instance->stat_pool);

    // init sql cursor pools for all sessions
    g_instance->sql_cur_pool.lock = 0;
    g_instance->sql_cur_pool.cnt = 0;
    OG_RETURN_IFERR(srv_init_sql_cur_pools());
    // init system sessions
    for (i = 0; i < g_instance->kernel.reserved_sessions; i++) {
        if (srv_alloc_reserved_session(&id) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    g_instance->session_pool.lock = 0;

    biqueue_init(&g_instance->session_pool.idle_sessions);
    biqueue_init(&g_instance->session_pool.priv_idle_sessions);
    g_instance->session_pool.service_count = 0;
    g_instance->session_pool.epollfd = epoll_create1(0);
    return OG_SUCCESS;
}

static bool32 srv_need_wait_session(knl_instance_t *kernel)
{
    session_pool_t *pool = &g_instance->session_pool;
    knl_session_t *session = &pool->sessions[0]->knl_session;
    uint32 i;

    // only primary wait rollback threads
    if (!DB_IS_READONLY(session) && DB_IN_BG_ROLLBACK(session)) {
        return OG_TRUE;
    }

    // user sessions
    for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        if (pool->sessions[i]->type == SESSION_TYPE_REPLICA || i == kernel->switch_ctrl.keep_sid ||
            srv_is_kernel_reserve_session(pool->sessions[i]->type)) {
            continue;
        }

        if (!pool->sessions[i]->is_free) {
            return OG_TRUE;
        }
    }

    if (kernel->sessions[SESSION_ID_SMON]->status == SESSION_ACTIVE) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static void srv_kill_active_session(knl_instance_t *kernel)
{
    session_pool_t *pool = &g_instance->session_pool;
    uint32 i;

    srv_pause_lsnr(LSNR_TYPE_SERVICE);
    reactor_pause_pool();

    for (i = g_instance->kernel.reserved_sessions; i < pool->hwm; i++) {
        if (pool->sessions[i]->type == SESSION_TYPE_REPLICA || i == kernel->switch_ctrl.keep_sid ||
            srv_is_kernel_reserve_session(pool->sessions[i]->type)) {
            continue;
        }
        // fix random switchover too long time
        srv_mark_sess_killed(pool->sessions[i], OG_TRUE, pool->sessions[i]->knl_session.serial_id);
    }
}

/**
 * Here we use peer recovery point, because we don't know
 * there are gaps or not, we don't know the peer redo log is correct or not..
 */
static bool32 srv_wait_sync_log(knl_instance_t *kernel)
{
    log_context_t *log_ctx = &kernel->redo_ctx;
    lsnd_context_t *lsnd_ctx = &kernel->lsnd_ctx;
    uint32 i;

    cm_latch_s(&lsnd_ctx->latch, SESSION_ID_KERNEL, OG_FALSE, NULL);

    for (i = 0; i < lsnd_ctx->standby_num; i++) {
        if (lsnd_ctx->lsnd[i] == NULL || lsnd_ctx->lsnd[i]->is_disable ||
            lsnd_ctx->lsnd[i]->status < LSND_STATUS_QUERYING) {
            continue;
        }

        if (lsnd_ctx->lsnd[i]->state == REP_STATE_DEMOTE_REQUEST) {
            if (lsnd_ctx->lsnd[i]->peer_rcy_point.lfn < log_ctx->lfn) {
                cm_unlatch(&lsnd_ctx->latch, NULL);
                return OG_TRUE;
            }

            OG_LOG_RUN_INF("[INST] [SWITCHOVER] Log sync end, local/peer lfn [%llu/%llu], local/peer lsn [%llu/%llu]",
                log_ctx->lfn, (uint64)lsnd_ctx->lsnd[i]->peer_rcy_point.lfn, kernel->lsn,
                lsnd_ctx->lsnd[i]->peer_replay_lsn);
        }
    }

    cm_unlatch(&lsnd_ctx->latch, NULL);
    return OG_FALSE;
}

static bool32 srv_demote_approved(knl_instance_t *kernel)
{
    lsnd_context_t *ogx = &kernel->lsnd_ctx;
    lsnd_t *lsnd = NULL;

    cm_latch_s(&ogx->latch, SESSION_ID_KERNEL, OG_FALSE, NULL);

    for (uint16 i = 0; i < ogx->standby_num; i++) {
        if (ogx->lsnd[i] == NULL || ogx->lsnd[i]->is_disable || ogx->lsnd[i]->status < LSND_STATUS_QUERYING) {
            continue;
        }

        if (ogx->lsnd[i]->state == REP_STATE_DEMOTE_REQUEST) {
            ogx->lsnd[i]->state = REP_STATE_PROMOTE_APPROVE;
            lsnd = ogx->lsnd[i];
            break;
        }
    }

    cm_unlatch(&ogx->latch, NULL);

    if (lsnd == NULL) {
        return OG_FALSE;
    }

    while (lsnd->state != REP_STATE_NORMAL) {
        if (lsnd->state == REP_STATE_DEMOTE_FAILED) {
            return OG_FALSE;
        }
        cm_sleep(10);
    }
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] lsnd state is NORMAL.");

    return OG_TRUE;
}

static inline void srv_reset_switch_request(switch_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->is_rmon_set = OG_FALSE;
    ctrl->request = SWITCH_REQ_NONE;
    ctrl->state = SWITCH_IDLE;
    ctrl->keep_sid = 0;
    ctrl->handling = OG_FALSE;
    cm_spin_unlock(&ctrl->lock);
}

static bool32 srv_killed_session_flush_end(bool32 demote)
{
    knl_instance_t *kernel = &g_instance->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];

    if (!ctrl->handling) {
        ctrl->handling = OG_TRUE;
        OG_LOG_RUN_INF("[INST] %s: process %s request", demote ? "SWITCHOVER" : "RAEDONLY",
            demote ? "demote" : "read only");

        srv_kill_active_session(kernel);
        ctrl->state = SWITCH_WAIT_SESSIONS;
        OG_LOG_RUN_INF("[INST] %s: Kill all active sessions", demote ? "SWITCHOVER" : "RAEDONLY");
    }

    if (ctrl->state == SWITCH_WAIT_SESSIONS) {
        if (srv_need_wait_session(kernel)) {
            return OG_FALSE;
        }

        OG_LOG_RUN_INF("[INST] %s: All active sessions stopped", demote ? "SWITCHOVER" : "RAEDONLY");

        /*
         * maybe log generate during clean nologging guts, so call it before log sync,
         * and knl_free_all_xatlocks will set DB_IN_BG_ROLLBACK that is not allowed to do DDL,
         * so, drop table before it.
         */
        if (demote) {
            if (db_clean_nologging_all(session) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("[INST] %s: failed to clean nologging tables", demote ? "SWITCHOVER" : "RAEDONLY");
                return OG_FALSE;
            }
        }

        srv_shrink_xa_rms((knl_handle_t)session, OG_TRUE);
        knl_close_temp_tables(session->kernel->sessions[SESSION_ID_TMP_STAT], DICT_TYPE_TEMP_TABLE_SESSION);
        ashrink_clean(session);

        ctrl->state = SWITCH_WAIT_LOG_SYNC;
        OG_LOG_RUN_INF("[INST] %s: Wait for log %s", demote ? "SWITCHOVER" : "RAEDONLY", demote ? "sync" : "flush");

        reactor_resume_pool();
        srv_resume_lsnr(LSNR_TYPE_SERVICE);
    }

    if (ctrl->state == SWITCH_WAIT_LOG_SYNC) {
        if (log_need_flush(&session->kernel->redo_ctx)) {
            if (log_flush(session, NULL, NULL, NULL) != OG_SUCCESS) {
                CM_ABORT(0, "[INST] %s ABORT INFO: failed to flush redo log", demote ? "SWITCHOVER" : "RAEDONLY");
            }

            return OG_FALSE;
        }
    }

    return OG_TRUE;
}

static void srv_process_demote_request_core(knl_session_t *session, knl_instance_t *kernel)
{
    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [SWITCHOVER] ABORT INFO: failed to save ctrlfile, demote failed");
    }

    rcy_init_proc(session);

    if (lrpl_init(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] ABORT INFO: failed to create lrpl thread");
    }

    // Start log sender threads if this standby has cascaded physical standby.
    if (lsnd_init(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] ABORT INFO: failed to start log sender thread, demote failed");
    }
}

static void srv_process_demote_request(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    database_t *db = &kernel->db;

    if (db_check_backgroud_blocked(session, OG_TRUE, g_instance->sync_doing)) {
        return;
    }

    if (!cm_spin_try_lock(&db->lock)) {
        return;
    }

    if (!srv_killed_session_flush_end(OG_TRUE)) {
        cm_spin_unlock(&db->lock);
        return;
    }

    if (ctrl->state == SWITCH_WAIT_LOG_SYNC) {
        if (srv_wait_sync_log(kernel)) {
            cm_spin_unlock(&db->lock);
            return;
        }
    }

    if (!srv_demote_approved(kernel)) {
        srv_reset_switch_request(ctrl);
        cm_spin_unlock(&db->lock);
        lsnd_reset_state(session);
        OG_LOG_RUN_INF("[INST] [SWITCHOVER] demote failed, running as primary still");
        return;
    }

    kernel->lrcv_ctx.reconnected = OG_TRUE;
    db->is_readonly = OG_TRUE;
    db->readonly_reason = PHYSICAL_STANDBY_SET;
    db->ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] Log synced, change role to standby");

    tx_rollback_close(session);
    lsnd_close_all_thread(session);

    btree_cache_reset(session);

    srv_process_demote_request_core(session, kernel);

    srv_reset_switch_request(ctrl);
    cm_spin_unlock(&db->lock);

    OG_LOG_RUN_INF("[INST] [SWITCHOVER] demote completed, running as standby");
}

static void srv_promote_get_local_host(promote_record_t *promote_record)
{
    knl_instance_t *kernel = &g_instance->kernel;
    lsnd_context_t *ogx = &kernel->lsnd_ctx;
    errno_t err;

    for (uint16 i = 0; i < OG_MAX_PHYSICAL_STANDBY; i++) {
        if (ogx->lsnd[i] == NULL) {
            continue;
        }
        dest_info_t *dest_info = &ogx->lsnd[i]->dest_info;

        if (strncmp(promote_record->peer_url, dest_info->peer_host, strlen(dest_info->peer_host)) == 0) {
            if (dest_info->local_host[0] == '\0') {
                break;
            }
            err = snprintf_s(promote_record->local_url, sizeof(promote_record->local_url),
                sizeof(promote_record->local_url) - 1, "%s:%u", dest_info->local_host, (uint32)kernel->attr.repl_port);
            knl_securec_check_ss(err);
            return;
        }
    }

    err =
        snprintf_s(promote_record->local_url, sizeof(promote_record->local_url), sizeof(promote_record->local_url) - 1,
        "%s:%u", g_instance->lsnr.tcp_replica.host[0], (uint32)kernel->attr.repl_port);
    knl_securec_check_ss(err);
}

static status_t srv_promote_get_record(knl_session_t *session, uint16 *row_count, date_t *min_date)
{
    knl_cursor_t *cursor = NULL;
    date_t temp_date;
    date_t date = OG_INVALID_INT64;
    uint16 i = 0;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROMOTE_RECORD_ID, 0);

    cursor->index_dsc = OG_TRUE;
    knl_init_index_scan(cursor, OG_FALSE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, 0);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, 0);

    for (;;) {
        if (OG_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return OG_ERROR;
        }
        if (cursor->eof) {
            break;
        } else {
            i++;
            temp_date = *(date_t *)CURSOR_COLUMN_DATA(cursor, PRMOTE_COL_TIME);
            date = (date > temp_date) ? temp_date : date;
        }
    }

    *row_count = i;
    *min_date = date;
    CM_RESTORE_STACK(session->stack);
    return OG_SUCCESS;
}

static status_t srv_promote_update_record(knl_session_t *session, date_t *min_date, promote_record_t *promote_record)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;
    status_t status;

    knl_set_session_scn(session, OG_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROMOTE_RECORD_ID, 0);

    knl_init_index_scan(cursor, OG_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, OG_TYPE_DATE, min_date, sizeof(date_t),
        IX_SYS_PROMOTE_RECORD_001_ID);

    if (knl_fetch(session, cursor) != OG_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), PRMOTE_COL_PEER_HOST + 1);

    (void)row_put_date(&ra, promote_record->time);
    (void)row_put_str(&ra, promote_record->type);
    (void)row_put_str(&ra, promote_record->local_url);
    (void)row_put_str(&ra, promote_record->peer_url);

    cursor->update_info.count = PRMOTE_COL_PEER_HOST + 1;
    cursor->update_info.columns[0] = PRMOTE_COL_TIME;
    cursor->update_info.columns[1] = PRMOTE_COL_TYPE;
    cursor->update_info.columns[2] = PRMOTE_COL_LOCAL_HOST;
    cursor->update_info.columns[3] = PRMOTE_COL_PEER_HOST;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    status = knl_internal_update(session, cursor);
    if (status != OG_SUCCESS) {
        knl_rollback(session, NULL);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t srv_promote_insert_record(knl_session_t *session, promote_record_t *promote_record)
{
    status_t status;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PROMOTE_RECORD_ID, OG_INVALID_ID32);

    uint32 max_size = session->kernel->attr.max_row_size;
    row_init(&ra, (char *)cursor->row, max_size, PRMOTE_COL_PEER_HOST + 1);

    (void)row_put_date(&ra, promote_record->time);
    (void)row_put_str(&ra, promote_record->type);
    (void)row_put_str(&ra, promote_record->local_url);
    (void)row_put_str(&ra, promote_record->peer_url);

    status = knl_internal_insert(session, cursor);
    if (status != OG_SUCCESS) {
        knl_rollback(session, NULL);
        CM_RESTORE_STACK(session->stack);
        return OG_ERROR;
    }

    knl_commit(session);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static void srv_promote_save_record(knl_session_t *session, promote_record_t *promote_record)
{
    status_t status;
    uint16 row_count;
    date_t min_date = OG_INVALID_INT64;

    if (DB_IS_UPGRADE(session) && (cm_strcmpni(promote_record->type, "SWITCHOVER", strlen("SWITCHOVER")) == 0)) {
        return;
    }

    if (srv_promote_get_record(session, &row_count, &min_date) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] [%s] failed to save promote record", promote_record->type);
        return;
    }

    if (row_count >= OG_MAX_PROMOTE_RECORD_COUNT) {
        status = srv_promote_update_record(session, &min_date, promote_record);
    } else {
        status = srv_promote_insert_record(session, promote_record);
    }

    if (status != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] [%s] failed to save promote record", promote_record->type);
    }
}

static void srv_promote_get_peer_url(promote_record_t *promote_record)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    switch_ctrl_t *ctrl = &g_instance->kernel.switch_ctrl;
    lrcv_context_t *lrcv = &g_instance->kernel.lrcv_ctx;
    errno_t err;

    err = snprintf_s(promote_record->peer_url, sizeof(promote_record->peer_url), sizeof(promote_record->peer_url) - 1,
        "%s:%u", lrcv->primary_host, (uint32)ctrl->peer_repl_port);
    knl_securec_check_ss(err);

    ctrl->peer_repl_port = 0;

    err = strncpy_s(promote_record->type, sizeof(promote_record->type), "SWITCHOVER", strlen("SWITCHOVER"));
    knl_securec_check(err);

    promote_record->time = KNL_NOW(session);
}

static void srv_process_promote_request_core(knl_session_t *session, switch_ctrl_t *ctrl,
    promote_record_t *promote_record)
{
    if (lsnd_init(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [SWITCHOVER] ABORT INFO: failed to start log sender thread, promote failed");
    }

    if (tx_rollback_start(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [SWITCHOVER] ABORT INFO: failed to start txn rollback thread, promote failed");
    }

    if (db_garbage_segment_clean(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] [SWITCHOVER] failed to clean garbage segment");
    }

    if (spc_clean_garbage_space(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[SPACE] failed to clean garbage tablespace");
    }

    spc_init_swap_space(session, SPACE_GET(session, dtc_my_ctrl(session)->swap_space));

    heap_remove_cached_pages(session, NULL);

    srv_promote_get_local_host(promote_record);
    srv_promote_save_record(session, promote_record);

    srv_reset_switch_request(ctrl);

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [SWITCHOVER] ABORT INFO: failed to save ctrlfile, promote failed");
    }
}

static void srv_process_promote_request(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    log_context_t *log_ctx = &kernel->redo_ctx;
    promote_record_t promote_record;

    srv_promote_get_peer_url(&promote_record);

    (void)knl_stop_build(session);
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] no build is running now");

    OG_LOG_RUN_INF("[INST] [SWITCHOVER] process promote request");

    ctrl->handling = OG_TRUE;
    ctrl->switch_asn = OG_INVALID_ASN;
    if (log_switch_logfile(session, OG_INVALID_FILEID, OG_INVALID_ASN, NULL) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[INST] failed to switch logfile, promote failed");
        srv_reset_switch_request(ctrl);
        return;
    }

    ctrl->switch_asn = log_ctx->files[log_ctx->curr_file].head.asn;
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] log file switched to %u", ctrl->switch_asn);

    if (kernel->redo_ctx.files[kernel->redo_ctx.curr_file].head.rst_id != kernel->db.ctrl.core.resetlogs.rst_id) {
        kernel->redo_ctx.files[kernel->redo_ctx.curr_file].head.rst_id = kernel->db.ctrl.core.resetlogs.rst_id;
        log_flush_head(session, &kernel->redo_ctx.files[kernel->redo_ctx.curr_file]);
        if (kernel->redo_ctx.files[kernel->redo_ctx.curr_file].head.asn !=
            kernel->db.ctrl.core.resetlogs.last_asn + 1) {
            OG_THROW_ERROR_EX(ERR_ASSERT_ERROR,
                "kernel->redo_ctx.files[kernel->redo_ctx.curr_file].head.asn(%u) == "
                "kernel->db.ctrl.core.resetlogs.last_asn(%u) + 1",
                kernel->redo_ctx.files[kernel->redo_ctx.curr_file].head.asn, kernel->db.ctrl.core.resetlogs.last_asn);
        }
    }

    rcy_wait_replay_complete(session); // need wait parallel replay thread finished
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] LRPL has finished replay work");

    // close the standby threads which are still alive
    lsnd_close_all_thread(session);
    lrcv_close(session);
    lrpl_close(session);
    lftc_clt_close(session);
    rcy_close_proc(session);
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] close lsnd & lrcv & lrpl & lftc & rcy");

    // from now on, we are running as primary
    knl_inc_dc_ver(kernel);
    kernel->db.is_readonly = OG_FALSE;
    kernel->db.readonly_reason = PRIMARY_SET;
    kernel->dc_ctx.completed = OG_FALSE;
    kernel->db.ctrl.core.db_role = REPL_ROLE_PRIMARY;
    OG_LOG_RUN_INF("[INST] [SWITCHOVER] log file switched, change role to primary");

    srv_process_promote_request_core(session, ctrl, &promote_record);

    OG_LOG_RUN_INF("[INST] [SWITCHOVER] promote completed, running as primary");
}

static void srv_process_readonly_request(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    database_t *db = &kernel->db;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];

    if (db_check_backgroud_blocked(session, OG_FALSE, g_instance->sync_doing)) {
        return;
    }

    if (!cm_spin_try_lock(&db->lock)) {
        return;
    }

    if (!srv_killed_session_flush_end(OG_FALSE)) {
        cm_spin_unlock(&db->lock);
        return;
    }

    tx_rollback_close(session);
    smon_close(session);
    rmon_close(session);
    OG_LOG_RUN_INF("[INST] [READONLY] close tx_rollback & smon && rmon");
    db->is_readonly = OG_TRUE;
    db->readonly_reason = ctrl->is_rmon_set ? RMON_SET : MANUALLY_SET;
    if (smon_start(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [READONLY] ABORT INFO: failed to start smon thread, convert to readonly failed");
    }

    if (rmon_start(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [READONLY] ABORT INFO: failed to start smon thread, convert to readonly failed");
    }

    srv_reset_switch_request(ctrl);
    cm_spin_unlock(&db->lock);

    OG_LOG_RUN_INF("[INST] set readonly completed");
}

static void srv_promote_force_get_local_host(promote_record_t *promote_record)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    arch_attr_t *arch_attr = NULL;
    errno_t err;
    uint16 i;

    for (i = 0; i < OG_MAX_ARCH_DEST; i++) {
        arch_attr = &kernel->attr.arch_attr[i];
        if (arch_attr->dest_mode == LOG_ARCH_DEST_SERVICE && arch_attr->local_host[0] != '\0') {
            break;
        }
    }

    if (i < OG_MAX_ARCH_DEST) {
        err = snprintf_s(promote_record->local_url, sizeof(promote_record->local_url),
            sizeof(promote_record->local_url) - 1, "%s:%u", arch_attr->local_host, (uint32)kernel->attr.repl_port);
    } else {
        err = snprintf_s(promote_record->local_url, sizeof(promote_record->local_url),
            sizeof(promote_record->local_url) - 1, "%s:%u", g_instance->lsnr.tcp_replica.host[0],
            (uint32)kernel->attr.repl_port);
    }

    knl_securec_check_ss(err);
    promote_record->time = KNL_NOW(session);
}

static void srv_record_promote_time(knl_session_t *session)
{
    log_context_t *log = &session->kernel->redo_ctx;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    OG_LOG_RUN_INF("[LRPL] replay used time %llums, end point: rst_id:[%llu], asn[%u], lfn[%llu]",
                    (KNL_NOW(session) - log->promote_temp_time) / MILLISECS_PER_SECOND,
                    (uint64)lrpl->curr_point.rst_id, lrpl->curr_point.asn, (uint64)lrpl->curr_point.lfn);

    log->promote_temp_time = KNL_NOW(session);
}

static void srv_process_force_promote_request(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    database_t *db = &kernel->db;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    log_context_t *log = &kernel->redo_ctx;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;
    core_ctrl_t *core = &db->ctrl.core;
    bool32 force = (bool32)(ctrl->request == SWITCH_REQ_FORCE_FAILOVER_PROMOTE);
    promote_record_t promote_record;
    errno_t err;

    if (force) {
        err = strncpy_s(promote_record.type, sizeof(promote_record.type), "FORCE FAILOVER", strlen("FORCE FAILOVER"));
        if (SECUREC_UNLIKELY(err != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return;
        }
    } else {
        err = strncpy_s(promote_record.type, sizeof(promote_record.type), "FAILOVER", strlen("FAILOVER"));
    }
    knl_securec_check(err);

    if ((force && kernel->lrcv_ctx.session != NULL) || !cm_spin_try_lock(&db->lock)) {
        return;
    }

    if (ctrl->state == SWITCH_IDLE) {
        (void)knl_stop_build(session);
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] no build is running now", force ? "FORCE " : "");
    }

    if (!ctrl->handling) {
        ctrl->handling = OG_TRUE;
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] process promote request", force ? "FORCE " : "");

        srv_kill_active_session(kernel);
        ctrl->state = SWITCH_WAIT_SESSIONS;
        ctrl->switch_asn = OG_INVALID_ASN;
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] Kill all active sessions", force ? "FORCE " : "");
    }

    if (ctrl->state == SWITCH_WAIT_SESSIONS) {
        if (srv_need_wait_session(kernel)) {
            cm_spin_unlock(&db->lock);
            return;
        }

        OG_LOG_RUN_INF("[INST] [%sFAILOVER] All active sessions stopped", force ? "FORCE " : "");

        reactor_resume_pool();
        srv_resume_lsnr(LSNR_TYPE_SERVICE);

        ctrl->state = SWITCH_WAIT_RECOVERY;
        log->promote_temp_time = KNL_NOW(session);
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] log replay from [%llu-%u-%u/%llu]", force ? "FORCE " : "",
            (uint64)lrpl->curr_point.rst_id, lrpl->curr_point.asn, lrpl->curr_point.block_id,
            (uint64)lrpl->curr_point.lfn);
    }

    if (ctrl->state == SWITCH_WAIT_RECOVERY) {
        if (!kernel->lrpl_ctx.thread.closed) {
            cm_spin_unlock(&db->lock);
            return;
        }

        rcy_wait_replay_complete(session); // need wait parallel replay thread finished
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] LRPL has finished replay work", force ? "FORCE " : "");
        srv_record_promote_time(session);
        rcy_close_proc(session);
        /*
         * do not trigger full checkpoint when db->ctrl.core.rcy_point.rst_id == log_ctx->curr_point.rst_id
         * because trigger full point(confuse implement) maybe wait long time
         */
        if (dtc_my_ctrl(session)->rcy_point.rst_id != log->curr_point.rst_id) {
            ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_FULL);
        }

        if (log_switch_logfile(session, OG_INVALID_FILEID, OG_INVALID_ASN, NULL) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[INST] [%sFAILOVER] failed to switch logfile", force ? "FORCE " : "");
            ctrl->handling = OG_FALSE;
            ctrl->request = SWITCH_REQ_NONE;
            cm_spin_unlock(&db->lock);
            return;
        }
        ctrl->switch_asn = log->files[log->curr_file].head.asn;
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] Log file switched to %u", force ? "FORCE " : "", ctrl->switch_asn);
        if (dtc_my_ctrl(session)->rcy_point.rst_id != log->curr_point.rst_id) {
            ctrl->state = SWITCH_WAIT_CKPT;
            OG_LOG_RUN_INF("[INST] [%sFAILOVER] Need to wait for checkpoint, rcy point rst_id is %u, "
                "current redo log point rst_id is %u",
                force ? "FORCE " : "", dtc_my_ctrl(session)->rcy_point.rst_id, log->curr_point.rst_id);
        }
    }

    if (ctrl->state == SWITCH_WAIT_CKPT) {
        if (!ckpt_check(session)) {
            cm_spin_unlock(&db->lock);
            return;
        }
        db_reset_log(session, ctrl->switch_asn, OG_TRUE, OG_FALSE);
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] Checkpoint and resetlog finished", force ? "FORCE " : "");
    } else {
        // If current log file is empty and current point lies on current log file,
        // NEED to advance rcy point and lrp point to current log file.
        db_reset_log(session, ctrl->switch_asn, (ctrl->switch_asn == log->curr_point.asn), OG_FALSE);
        OG_LOG_RUN_INF("[INST] [%sFAILOVER] Resetlog finished", force ? "FORCE " : "");
    }

    OG_LOG_RUN_INF("[INST] [%sFAILOVER] lsn:[%llu]", force ? "FORCE " : "", DB_CURR_LSN(session));
    OG_LOG_RUN_INF("[INST] [%sFAILOVER] SCN:[%llu]", force ? "FORCE " : "", DB_CURR_SCN(session));
    OG_LOG_RUN_INF("[INST] [%sFAILOVER] lrp rst_id/asn/lfn/offset:[%u/%u/%llu/%u]", force ? "FORCE " : "",
        dtc_my_ctrl(session)->lrp_point.rst_id, dtc_my_ctrl(session)->lrp_point.asn,
        (uint64)dtc_my_ctrl(session)->lrp_point.lfn, dtc_my_ctrl(session)->lrp_point.block_id);
    OG_LOG_RUN_INF("[INST] [%sFAILOVER] rcy rst_id/asn/lfn/offset:[%u/%u/%llu/%u]", force ? "FORCE " : "",
        dtc_my_ctrl(session)->rcy_point.rst_id, dtc_my_ctrl(session)->rcy_point.asn,
        (uint64)dtc_my_ctrl(session)->rcy_point.lfn, dtc_my_ctrl(session)->rcy_point.block_id);
    OG_LOG_RUN_INF("[INST] [%sFAILOVER] curr point rst_id/asn/lfn/offset:[%u/%u/%llu/%u]", force ? "FORCE " : "",
        log->curr_point.rst_id, log->curr_point.asn, (uint64)log->curr_point.lfn, log->curr_point.block_id);

    /*
     * In previous db_reset_log, current file's resetid has been updated and flushed. We should save resetlog here
     * to prevent inconsistent resetid if failover failed finally.
     */
    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [%sFAILOVER] ABORT INFO: failed to save resetlog ctrlfile", force ? "FORCE " : "");
    }

    dc_reset_not_ready_by_nlg(session);

    knl_inc_dc_ver(kernel);
    kernel->db.is_readonly = OG_FALSE;
    kernel->db.readonly_reason = PRIMARY_SET;
    kernel->dc_ctx.completed = OG_FALSE;
    core->db_role = REPL_ROLE_PRIMARY;
    OG_LOG_RUN_INF("[INST] [%sFAILOVER] Change role to primary", force ? "FORCE " : "");

    if (kernel->db.ctrl.core.is_restored) {
        db_set_ctrl_restored(session, OG_FALSE);
    }
    lrcv_clear_needrepair_for_failover(session);
    lrcv_reset_primary_host(session);
    lsnd_close_all_thread(session);

    if (lsnd_init(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [%sFAILOVER] ABORT INFO: failed to start log sender thread", force ? "FORCE " : "");
    }

    if (tx_rollback_start(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [%sFAILOVER] ABORT INFO: failed to start txn rollback thread", force ? "FORCE " : "");
    }

    if (db_clean_nologging_all(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [%sFAILOVER] ABORT INFO: failed to clean nologging tables", force ? "FORCE " : "");
    }

    dc_set_ready(session);

    if (db_garbage_segment_clean(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] [%sFAILOVER] failed to clean garbage segment", force ? "FORCE " : "");
    }

    if (spc_clean_garbage_space(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] [%sFAILOVER] failed to clean garbage tablespace", force ? "FORCE " : "");
    }

    spc_init_swap_space(session, SPACE_GET(session, dtc_my_ctrl(session)->swap_space));

    heap_remove_cached_pages(session, NULL);

    srv_promote_force_get_local_host(&promote_record);
    srv_promote_save_record(session, &promote_record);

    srv_reset_switch_request(ctrl);
    cm_spin_unlock(&db->lock);

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [%sFAILOVER] ABORT INFO: failed to save core ctrlfile", force ? "FORCE " : "");
    }

    OG_LOG_RUN_INF("[INST] [%sFAILOVER] promote completed, running as primary", force ? "FORCE " : "");
}

static void srv_process_cancel_upgrade_request(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    database_t *db = &kernel->db;
    dc_context_t *dc_ctx = &kernel->dc_ctx;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];

    if (!cm_spin_try_lock(&db->lock)) {
        return;
    }

    ckpt_trigger(session, OG_TRUE, CKPT_TRIGGER_FULL);
    dc_ctx->completed = OG_FALSE;
    db->open_status = DB_OPEN_STATUS_NORMAL;

    if (db_clean_nologging_all(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [CANCEL UPGRADE] ABORT INFO: failed to clean nologging tables, cancel upgrade failed");
    }

    if (db_garbage_segment_clean(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] [FAILOVER] failed to clean garbage segment");
    }

    if (spc_clean_garbage_space(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[SPACE] failed to clean garbage tablespace");
    }

    srv_reset_switch_request(ctrl);
    cm_spin_unlock(&db->lock);

    OG_LOG_RUN_INF("[INST] cancel upgrade mode completed");
}

static status_t srv_adjust_log_sender(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_LSND];
    arch_context_t *ogx = &kernel->arch_ctx;

    if (g_instance->shutdown_ctx.phase >= SHUTDOWN_PHASE_INPROGRESS) {
        return OG_SUCCESS;
    }

    lsnd_close_disabled_thread(session);

    if (ogx->arch_dest_state_changed) {
        if (lsnd_init(session) != OG_SUCCESS) {
            ogx->arch_dest_state_changed = OG_FALSE;
            return OG_ERROR;
        }
        ogx->arch_dest_state_changed = OG_FALSE;
    }

    return OG_SUCCESS;
}

static void srv_process_raft_promote_request_core(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    log_context_t *log_ctx = &kernel->redo_ctx;

    OG_LOG_RUN_INF("[INST] [FAILOVER] lsn:[%llu]", DB_CURR_LSN(session));
    OG_LOG_RUN_INF("[INST] [FAILOVER] SCN:[%llu]", DB_CURR_SCN(session));
    OG_LOG_RUN_INF("[INST] [FAILOVER] lrp rst_id/asn/lfn/offset:[%u/%u/%llu/%u]",
        dtc_my_ctrl(session)->lrp_point.rst_id, dtc_my_ctrl(session)->lrp_point.asn,
        (uint64)dtc_my_ctrl(session)->lrp_point.lfn, dtc_my_ctrl(session)->lrp_point.block_id);
    OG_LOG_RUN_INF("[INST] [FAILOVER] rcy rst_id/asn/lfn/offset:[%u/%u/%llu/%u]",
        dtc_my_ctrl(session)->rcy_point.rst_id, dtc_my_ctrl(session)->rcy_point.asn,
        (uint64)dtc_my_ctrl(session)->rcy_point.lfn, dtc_my_ctrl(session)->rcy_point.block_id);
    OG_LOG_RUN_INF("[INST] [FAILOVER] curr point rst_id/asn/lfn/offset:[%u/%u/%llu/%u]", log_ctx->curr_point.rst_id,
        log_ctx->curr_point.asn, (uint64)log_ctx->curr_point.lfn, log_ctx->curr_point.block_id);

    dc_reset_not_ready_by_nlg(session);

    knl_inc_dc_ver(kernel);
    kernel->db.is_readonly = OG_FALSE;
    kernel->db.readonly_reason = PRIMARY_SET;
    kernel->dc_ctx.completed = OG_FALSE;
    kernel->db.ctrl.core.db_role = REPL_ROLE_PRIMARY;

    if (db_save_core_ctrl(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] ABORT INFO: failed to save core ctrlfile, force promote failed");
    }

    if (tx_rollback_start(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] ABORT INFO: failed to start txn rollback thread, force promote failed");
    }

    if (db_clean_nologging_all(session) != OG_SUCCESS) {
        CM_ABORT(0, "[INST] [FAILOVER] ABORT INFO: failed to clean nologging tables, force promote failed");
    }

    dc_set_ready(session);

    if (db_garbage_segment_clean(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[INST] failed to clean garbage segment");
    }

    if (spc_clean_garbage_space(session) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("[SPACE] failed to clean garbage tablespace");
    }

    spc_init_swap_space(session, SPACE_GET(session, dtc_my_ctrl(session)->swap_space));
}

static void srv_process_force_raft_promote_request(void)
{
    knl_instance_t *kernel = &g_instance->kernel;
    switch_ctrl_t *ctrl = &kernel->switch_ctrl;
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    log_context_t *log_ctx = &kernel->redo_ctx;
    lrpl_context_t *lrpl = &session->kernel->lrpl_ctx;

    if (!ctrl->handling) {
        ctrl->handling = OG_TRUE;
        OG_LOG_RUN_INF("[INST] process force promote request");

        srv_kill_active_session(kernel);
        ctrl->state = SWITCH_WAIT_SESSIONS;
    }

    if (ctrl->state == SWITCH_WAIT_SESSIONS) {
        if (srv_need_wait_session(kernel)) {
            return;
        }

        reactor_resume_pool();
        srv_resume_lsnr(LSNR_TYPE_SERVICE);

        ctrl->state = SWITCH_WAIT_RECOVERY;
        log_ctx->promote_temp_time = KNL_NOW(session);
        OG_LOG_RUN_INF("[INST] failover log repaly from [%llu-%u-%u/%llu]", (uint64)lrpl->curr_point.rst_id,
            lrpl->curr_point.asn, lrpl->curr_point.block_id, (uint64)lrpl->curr_point.lfn);
    }

    if (ctrl->state == SWITCH_WAIT_RECOVERY) {
        if (!kernel->lrpl_ctx.thread.closed) {
            return;
        }

        rcy_wait_replay_complete(session); // need wait parallel replay thread finished
        OG_LOG_RUN_INF("[INST] [FAILOVER] LRPL has finished replay work");
        srv_record_promote_time(session);
        rcy_close_proc(session);
        /*
         * do not trigger full checkpoint when db->ctrl.core.rcy_point.rst_id == log_ctx->curr_point.rst_id
         * because trigger full point(confuse implement) maybe wait long time
         */
        if (dtc_my_ctrl(session)->rcy_point.rst_id != log_ctx->curr_point.rst_id) {
            ckpt_trigger(session, OG_FALSE, CKPT_TRIGGER_FULL);
        }
    }

    srv_process_raft_promote_request_core();

    heap_remove_cached_pages(session, NULL);
    srv_reset_switch_request(ctrl);

    OG_LOG_RUN_INF("[INST] force promote completed, running as primary");
}

static void srv_record_backup(uint32 client_id)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_BRU];
    lsnd_context_t *lsnd_ctx = &g_instance->kernel.lsnd_ctx;
    lsnd_bak_task_t *bak_task = &lsnd_ctx->lsnd[client_id]->bak_task;
    bool32 task_failed = OG_FALSE;

    OG_LOG_RUN_INF("srv_record_backup");

    bak_task->record.status = BACKUP_SUCCESS;
    if (bak_record_backup_set(session, &bak_task->record) != OG_SUCCESS) {
        task_failed = OG_TRUE;
    }

    lsnd_trigger_task_response(session, client_id, task_failed);
}

static void srv_process_record_backup_task(void)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_BRU];
    bak_context_t *ogx = &session->kernel->backup_ctx;
    uint32 build_keep_alive_timeout = session->kernel->attr.build_keep_alive_timeout;
    uint32 i;

    for (i = 0; i < OG_MAX_PHYSICAL_STANDBY; i++) {
        if (!g_instance->kernel.record_backup_trigger[i]) {
            continue;
        }

        srv_record_backup(i);
        g_instance->kernel.record_backup_trigger[i] = OG_FALSE;
    }

    if (!BAK_IS_KEEP_ALIVE(ogx)) {
        return;
    }

    dls_spin_lock(session, &ogx->lock, NULL);
    if (!BAK_IS_KEEP_ALIVE(ogx)) {
        dls_spin_unlock(session, &ogx->lock);
        return;
    }
    if (cm_current_time() - ogx->keep_live_start_time > build_keep_alive_timeout || ogx->bak.build_stopped) {
        knl_panic(!ogx->bak.need_retry);
        ogx->bak_condition = NOT_RUNNING;
        OG_LOG_RUN_INF("[BUILD] cancel keep alive condition while reaching timeout "
            "or build cancelled: %u",
            ogx->bak.build_stopped);
    }
    dls_spin_unlock(session, &ogx->lock);
}

static void srv_terminal_zombie_session(void)
{
    session_t *sess = NULL;
    int loop;
    int nfds;
    struct epoll_event events[OG_EV_WAIT_NUM];
    struct epoll_event *ev = NULL;
    nfds = epoll_wait(g_instance->session_pool.epollfd, events, OG_EV_WAIT_NUM, OG_EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            OG_LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }
    if (nfds == 0) {
        return;
    }

    for (loop = 0; loop < nfds; ++loop) {
        ev = &events[loop];
        sess = (session_t *)ev->data.ptr;

        if (!sess->knl_session.killed && sess->knl_session.status != SESSION_INACTIVE) {
            srv_mark_sess_killed(sess, OG_FALSE, sess->knl_session.serial_id);
        }
    }
}

static void srv_instance_request(void)
{
    cm_reset_error();
    switch (g_instance->kernel.switch_ctrl.request) {
        case SWITCH_REQ_DEMOTE:
            srv_process_demote_request();
            break;
        case SWITCH_REQ_PROMOTE:
            srv_process_promote_request();
            break;
        case SWITCH_REQ_FAILOVER_PROMOTE:
        case SWITCH_REQ_FORCE_FAILOVER_PROMOTE:
            srv_process_force_promote_request();
            break;
        case SWITCH_REQ_RAFT_PROMOTE:
            srv_process_force_raft_promote_request();
            break;
        case SWITCH_REQ_READONLY:
            srv_process_readonly_request();
            break;
        case SWITCH_REQ_CANCEL_UPGRADE:
            srv_process_cancel_upgrade_request();
            break;
        default:
            break;
    }
}

status_t srv_instance_loop(void)
{
    int64 periods = 0;
    int64 period_one_day = MILLISECS_PER_SECOND * SECONDS_PER_DAY / 5;
    g_instance->shutdown_ctx.enabled = OG_TRUE;

    while (1) {
        if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE) {
            srv_close_threads(OG_FALSE);
            srv_deinit_resource();
            return OG_SUCCESS;
        }
        if (g_instance->lsnr_abort_status == OG_TRUE) {
            exec_abnormal_terminal();
            return OG_SUCCESS;
        }

        srv_expire_unauth_timeout_session();
        if (periods == period_one_day && IS_SSL_ENABLED) {
            periods = 0;
            OG_RETURN_IFERR(srv_ssl_expire_warning());
        }

#ifndef WIN32
        srv_terminal_zombie_session();
#endif
        OG_RETURN_IFERR(srv_adjust_log_sender());

        srv_process_record_backup_task();
        srv_instance_request();

        cm_sleep(5);
        periods++;
    }
}

static status_t srv_kernel_startup(bool32 is_coordinator)
{
    knl_instance_t *kernel = &g_instance->kernel;
    kernel->attr.xpurpose_buf = cm_aligned_buf(g_instance->xpurpose_buf);
    kernel->attr.config = &g_instance->config;
    kernel->attr.timer = g_timer();
    kernel->attr.max_sessions = g_instance->session_pool.expanded_max_sessions;

    OG_LOG_RUN_INF("begin start kernel.");
    knl_init_attr(kernel);
    kernel->home = g_instance->home;
    kernel->id = kernel->dtc_attr.inst_id;
    g_local_inst_id = kernel->id;

    if (alck_init_ctx(kernel) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_START_INSTANCE_ERROR);
        return OG_ERROR;
    }
    kernel->id = kernel->dtc_attr.inst_id;
    if (OG_SUCCESS != knl_startup(kernel)) {
        OG_THROW_ERROR(ERR_START_INSTANCE_ERROR);
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("kernel startup finish.");
    return OG_SUCCESS;
}

static status_t srv_kernel_open(db_startup_phase_t phase)
{
    knl_instance_t *kernel = &g_instance->kernel;
    session_pool_t *pool = &g_instance->session_pool;
    knl_session_t *knl_session = kernel->sessions[SESSION_ID_KERNEL];
    session_t *session = pool->sessions[SESSION_ID_KERNEL];
    knl_alterdb_def_t def;
    status_t ret;

    MEMS_RETURN_IFERR(memset_s(&def, sizeof(knl_alterdb_def_t), 0, sizeof(knl_alterdb_def_t)));
    if (phase == STARTUP_MOUNT) {
        def.action = STARTUP_DATABASE_MOUNT;
    } else {
        def.action = STARTUP_DATABASE_OPEN;
    }
    sql_begin_exec_stat(session);
    ret = knl_alter_database(knl_session, &def);
    sql_end_exec_stat(session);
    return ret;
}

static status_t srv_init_resource_manager(knl_handle_t sess)
{
    char *plan_name = srv_get_param("RESOURCE_PLAN");
    biqueue_init(&g_instance->rsrc_mgr.free_plans);
    knl_session_t *session = (knl_session_t *)sess;

    if (cm_event_init(&g_instance->rsrc_mgr.event) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return OG_ERROR;
    }
    if (CM_IS_EMPTY_STR(plan_name)) {
        g_instance->rsrc_mgr.plan = NULL;
        g_instance->rsrc_mgr.started = OG_FALSE;
        return rsrc_calc_cpuset(session->kernel->attr.cpu_bind_lo, session->kernel->attr.cpu_bind_hi, NULL);
    }
    if (rsrc_load_plan(session, plan_name, &g_instance->rsrc_mgr.plan) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Load resource plan failed, plan = %s", plan_name);
        return OG_ERROR;
    }
    if (srv_init_vmem_pool() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("failed to initialize temp pool");
        return OG_ERROR;
    }
    return rsrc_start_manager(&g_instance->rsrc_mgr);
}

status_t srv_init_resource_manager_null(knl_handle_t sess)
{
    return OG_SUCCESS;
}

status_t srv_callback_null_func2_uid(knl_handle_t knl_session, uint32 uid)
{
    return OG_SUCCESS;
}

status_t srv_callback_null_func2_dc(knl_handle_t knl_session, knl_dictionary_t *dc)
{
    return OG_SUCCESS;
}

void srv_callback_null_func2_dc_void(knl_handle_t knl_session, knl_dictionary_t *dc)
{
}

status_t srv_callback_null_func3_text(knl_handle_t sess, uint32 uid, text_t *syn_name)
{
    return OG_SUCCESS;
}

status_t srv_callback_null_func3_ptr(knl_handle_t sess, uint32 uid, void *syn_name)
{
    return OG_SUCCESS;
}

status_t srv_callback_null_func4_dc_text(knl_handle_t knl_session, knl_dictionary_t *dc, text_t *name, text_t *new_name)
{
    return OG_SUCCESS;
}

void rsrc_accumulate_io_null(knl_handle_t sess, io_type_t type)
{
	return;
}

static status_t init_sql_maps_null(knl_handle_t sess)
{
	return OG_SUCCESS;
}

status_t sql_update_dependant_status_null(knl_handle_t sess, obj_info_t *obj)
{
	return OG_SUCCESS;
}

static status_t ogstore_raw_device_op_init_null(const char *conn_path)
{
	return OG_SUCCESS;
}
static void srv_set_kernel_callback_ex(void)
{
    g_knl_callback.set_stmt_check = sql_set_stmt_check;
    g_knl_callback.before_commit = (knl_before_commit_t)knl_clean_before_commit;
    g_knl_callback.alloc_knl_session = srv_alloc_knl_session;
    g_knl_callback.release_knl_session = srv_release_knl_session;
    g_knl_callback.parse_check_from_text = sql_parse_check_from_text;
    g_knl_callback.parse_default_from_text = sql_parse_default_from_text;
    g_knl_callback.verify_default_from_text = sql_verify_default_from_text;
    g_knl_callback.update_depender = sql_update_depender_status;
    g_knl_callback.accumate_io = rsrc_accumate_io;
    g_knl_callback.init_resmgr = srv_init_resource_manager;
    g_knl_callback.import_rows = sql_try_import_rows;
    g_knl_callback.sysdba_privilege = srv_sysdba_privilege;
    g_knl_callback.have_ssl = srv_have_ssl;
    g_knl_callback.clear_sym_cache = NULL; // pl_clear_sym_cache;
    g_knl_callback.get_func_index_size = sql_get_func_index_expr_size;
    g_knl_callback.compare_index_expr = sql_compare_index_expr;
    g_knl_callback.whether_login_with_user = srv_whether_login_with_user;
    g_knl_callback.pl_drop_synonym_by_user = pl_drop_synonym_by_user;
    g_knl_callback.init_vmc = sql_init_mtrl_vmc;
    g_knl_callback.get_ddl_sql = sql_get_ddl_sql;
    g_knl_callback.convert_char = sql_convert_char_cb;
    g_knl_callback.device_init = ogstore_raw_device_op_init_null;
}

static void srv_set_kernel_callback(void)
{
    g_knl_callback.exec_default = sql_exec_default;
    g_knl_callback.set_vm_lob_to_knl = sql_set_vm_lob_to_knl;
    g_knl_callback.keep_stack_variant = sql_keep_stack_var;
    g_knl_callback.alloc_rm = srv_alloc_rm;
    g_knl_callback.release_rm = srv_release_rm;
    g_knl_callback.alloc_auton_rm = srv_alloc_auton_rm;
    g_knl_callback.release_auton_rm = srv_release_auton_rm;
    g_knl_callback.get_xa_xid = srv_get_xa_xid;
    g_knl_callback.add_xa_xid = srv_add_xa_xid;
    g_knl_callback.delete_xa_xid = srv_delete_xa_xid;
    g_knl_callback.attach_suspend_rm = srv_attach_suspend_rm;
    g_knl_callback.detach_suspend_rm = srv_detach_suspend_rm;
    g_knl_callback.attach_pending_rm = srv_attach_pending_rm;
    g_knl_callback.detach_pending_rm = srv_detach_pending_rm;
    g_knl_callback.shrink_xa_rms = srv_shrink_xa_rms;
    g_knl_callback.load_scripts = sql_load_scripts;
    g_knl_callback.exec_sql = (knl_exec_sql_t)sql_execute_directly2;
    g_knl_callback.invalidate_cursor = clean_open_cursors;
    g_knl_callback.invalidate_temp_cursor = clean_open_temp_cursors;
    g_knl_callback.invalidate_space = invalidate_tablespaces;
    g_knl_callback.decode_check_cond = sr_decode_cond;
    g_knl_callback.match_cond_tree = sql_match_cond_tree;
    g_knl_callback.dc_recycle_external = dc_recycle_external;
    g_knl_callback.pl_init = pl_init;
    g_knl_callback.pl_drop_object = pl_drop_object_by_user;
    g_knl_callback.pl_db_drop_triggers = pl_db_drop_triggers;
    g_knl_callback.pl_update_tab_from_sysproc = pl_update_source_for_trigs;
    g_knl_callback.pl_free_trig_entity_by_tab = pl_free_trig_entity_by_tab;
    g_knl_callback.pl_drop_triggers_entry = pl_drop_triggers_entry;
    g_knl_callback.pl_logic_log_replay = pl_logic_log_replay;
    g_knl_callback.exec_check = sql_execute_check;
    g_knl_callback.func_idx_exec = sql_exec_index_col_func;
    g_knl_callback.kill_session = srv_mark_sess_killed;
    g_knl_callback.init_sql_maps = init_sql_maps_null;
    g_knl_callback.get_sql_text = srv_get_sql_text;
    g_knl_callback.set_min_scn = srv_set_min_scn;
    srv_set_kernel_callback_ex();
}

static status_t srv_get_home(void)
{
    bool32 exist;
    char home[OG_MAX_PATH_BUFFER_SIZE];

    if (g_database_home == NULL) {
        g_database_home = getenv(OG_ENV_HOME);
        if (g_database_home == NULL) {
            OG_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, OG_ENV_HOME);
            return OG_ERROR;
        }
    }
    OG_RETURN_IFERR(realpath_file(g_database_home, home, OG_MAX_PATH_BUFFER_SIZE));

    exist = cm_check_exist_special_char(home, (uint32)strlen(home));
    if (exist) {
        OG_THROW_ERROR(ERR_INVALID_DIR, OG_ENV_HOME);
        return OG_ERROR;
    }

    exist = cm_dir_exist(home);
    if (!exist) {
        OG_THROW_ERROR(ERR_HOME_PATH_NOT_FOUND, OG_ENV_HOME);
        return OG_ERROR;
    }

    cm_trim_home_path(g_database_home, (uint32)strlen(g_database_home));
    MEMS_RETURN_IFERR(strncpy_s(g_instance->home, OG_MAX_PATH_BUFFER_SIZE, g_database_home, strlen(g_database_home)));

    return OG_SUCCESS;
}

char *startup_mode(db_startup_phase_t phase)
{
    switch (phase) {
        case STARTUP_NOMOUNT:
            return "nomount";

        case STARTUP_MOUNT:
            return "mount";

        default:
            return "normal";
    }
}

static void srv_reg_os_rinfo(void)
{
    for (int i = 0; i < TOTAL_OS_RUN_INFO_TYPES; i++) {
        g_instance->os_rinfo[i].desc = &g_os_stat_desc_array[i];
    }
}

static void srv_init_lob_locator(void)
{
    g_instance->sql.sql_lob_locator_size = MAX(KNL_LOB_LOCATOR_SIZE, VM_LOB_LOCATOR_SIZE);
}

static void srv_init_uuid_info(st_uuid_info_t *uuid_info)
{
    uuid_info->lock = 0;
    uuid_info->self_increase_seq = cm_random(OG_MAX_RAND_RANGE);
    cm_init_mac_address(uuid_info->mac_address, OG_MAC_ADDRESS_LEN);
}

static status_t srv_init_g_instance(void)
{
    errno_t errcode;
    g_instance = (instance_t *)malloc(sizeof(instance_t));
    if (g_instance == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(instance_t), "creating instance");
        return OG_ERROR;
    }

    errcode = memset_s(g_instance, sizeof(instance_t), 0, sizeof(instance_t));
    if (errcode != EOK) {
        CM_FREE_PTR(g_instance);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OG_ERROR;
    }

    g_instance->lock_fd = -1;
    g_instance->inc_rebalance = OG_FALSE;
    g_instance->frozen_starttime = 0;
    g_instance->frozen_waittime = 0;
    cm_rand((uchar *)g_instance->rand_for_md5, OG_KDF2SALTSIZE);
    srv_init_uuid_info(&g_instance->g_uuid_info);

    errcode = memset_s(g_dtc, sizeof(dtc_instance_t), 0, sizeof(dtc_instance_t));
    if (errcode != EOK) {
        CM_FREE_PTR(g_instance);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OG_ERROR;
    }

    g_dtc->kernel = &g_instance->kernel;
    shutdown_context_t *ogx = &g_instance->shutdown_ctx;
    dls_init_latch(&(ogx->shutdown_latch), DR_TYPE_SHUTDOWN, 0, 0);

    return OG_SUCCESS;
}

status_t srv_sysdba_privilege()
{
    // avoid to rewriting privilege file, when same socket listen conflict. init sysdba must after start lsnr
    if (GET_ENABLE_SYSDBA_LOGIN) {
        if (srv_init_sysdba_privilege() != OG_SUCCESS) {
            srv_instance_destroy();
            OG_LOG_RUN_ERR("[Privilege] failed to init Sysdba Privilege");
            return OG_ERROR;
        }
    } else {
        (void)srv_remove_sysdba_privilege();
    }
    return OG_SUCCESS;
}

static status_t srv_init_par_sessions(void)
{
    sql_par_pool_t *par_pool = &g_instance->sql_par_pool;
    uint32 i;
    uint32 id;

    // init sql parallel sessions
    par_pool->lock = 0;
    par_pool->used_sessions = 0;

    for (i = 0; i < par_pool->max_sessions; i++) {
        OG_RETURN_IFERR(srv_alloc_reserved_session(&id));
        g_instance->session_pool.sessions[id]->type = SESSION_TYPE_SQL_PAR;
        g_instance->session_pool.sessions[id]->knl_session.match_cond = sql_match_cond;
        par_pool->sessions[i] = g_instance->session_pool.sessions[id];
    }

    g_instance->kernel.reserved_sessions += par_pool->max_sessions;

    // init stat of parallel
    par_pool->par_stat.parallel_executions = 0;
    par_pool->par_stat.under_trans_cnt = 0;
    par_pool->par_stat.res_limited_cnt = 0;
    par_pool->par_stat.break_proc_cnt = 0;

    return OG_SUCCESS;
}

static status_t srv_lock_db(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
        g_instance->home, g_lock_file));

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_instance->lock_fd) != OG_SUCCESS) {
        return OG_ERROR;
    }

    status_t ret = cm_lock_fd(g_instance->lock_fd);
    if (ret != OG_SUCCESS) {
        cm_show_lock_info(g_instance->lock_fd);
    }
    return ret;
}

void srv_unlock_db(void)
{
    OG_LOG_RUN_INF("Unlock db lock at %d.", g_instance->lock_fd);
    if (g_instance->lock_fd != -1) {
        cm_unlock_fd(g_instance->lock_fd);
        cm_close_file(g_instance->lock_fd);
    }
}

static void srv_setup_json_mpool(void)
{
    g_instance->sql.json_mpool.lock = 0;
    g_instance->sql.json_mpool.used_json_dyn_buf = 0;
}

static void srv_set_locale(void)
{
    if (setlocale(LC_ALL, "") == NULL) {
        g_instance->is_setlocale_success = OG_FALSE;
        OG_LOG_RUN_ERR("Set locale failed, errno %d", errno);
        printf("Set locale failed, errno %d\n", errno);
        return;
    }
    g_instance->is_setlocale_success = OG_TRUE;
}

void srv_thread_exit(thread_t *thread, session_t *session)
{
    agent_t *agent = session->agent;
    cm_release_thread(thread);
    srv_unbind_sess_agent(session, agent);
    srv_release_session(session);
    srv_free_agent_res(agent, OG_FALSE);
    CM_FREE_PTR(agent);
}


char g_cpu_info_str[CPU_INFO_STR_SIZE];

int g_cpu_info[CPU_SEG_MAX_NUM][SMALL_RECORD_SIZE];
int g_cpu_group_num = 0;
cpu_set_t g_masks[CPU_SEG_MAX_NUM];

int get_cpu_group_num(void)
{
    return g_cpu_group_num;
}

cpu_set_t* get_cpu_masks(void)
{
    return g_masks;
}

char *get_g_cpu_info(void)
{
    return g_cpu_info_str;
}

static int init_cpu_mask(char *cpu_info_str, int *cpu_group_num, int cpu_info[CPU_SEG_MAX_NUM][SMALL_RECORD_SIZE])
{
    errno_t errcode;
    if (cpu_info_str[0] == '0' && strlen(cpu_info_str) == 1) {
        return OG_SUCCESS;
    }
    char *p = NULL;
    char *str = strtok_r(cpu_info_str, " ", &p);
    char cpu_group_str[CPU_SEG_MAX_NUM][SMALL_RECORD_SIZE];
    while (str != NULL) {
        errcode = strcpy_s(cpu_group_str[(*cpu_group_num)++], SMALL_RECORD_SIZE, str);
        MEMS_RETURN_IFERR(errcode);
        str = strtok_r(NULL, " ", &p);
    }
    for (int i = 0; i < *cpu_group_num; i++) {
        char *cpu_p = NULL;
        char cpu_group_str_cp[SMALL_RECORD_SIZE];
        errcode = strcpy_s(cpu_group_str_cp, SMALL_RECORD_SIZE, cpu_group_str[i]);
        MEMS_RETURN_IFERR(errcode);
        char *cpu_str = strtok_r(cpu_group_str_cp, ",", &cpu_p);
        int count = 0;
        while (cpu_str != NULL) {
            int s = 0, e = 0;
            int num = sscanf_s(cpu_str, "%d-%d", &s, &e);
            if (num == 1) {
                e = s;
            } else if (num != 2) {
                OG_LOG_RUN_ERR("cpu configuration error, num = %d, s = %d, e = %d, should be like \"0-3\" or \"0\", but \"%s\"",
                               num, s, e, cpu_str);
                return OG_ERROR;
            }
            for (int j = s; j <= e; j++) {
                cpu_info[i][count++] = j;
            }
            cpu_str = strtok_r(NULL, ",", &cpu_p);
        }
        cpu_info[i][count] = -1;
    }
    return OG_SUCCESS;
}

static void set_cpu_mask(void)
{
    for (int i = 0; i < g_cpu_group_num; i++) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        for (int j = 0; j < SMALL_RECORD_SIZE; j++) {
            if (g_cpu_info[i][j] >= 0) {
                CPU_SET(g_cpu_info[i][j], &mask);
            } else {
                break;
            }
        }
        g_masks[i] = mask;
    }
}

static int init_cpu_info(void)
{
    if (init_cpu_mask(g_cpu_info_str, &g_cpu_group_num, g_cpu_info) != 0 || g_cpu_group_num == 0) {
        OG_LOG_RUN_ERR("g_cpu_group_num init error, g_cpu_group_num is %d", g_cpu_group_num);
        return OG_ERROR;
    }
    set_cpu_mask();
    return OG_SUCCESS;
}

status_t srv_instance_startup(db_startup_phase_t phase, bool32 is_coordinator, bool32 is_datanode, bool32 is_gts)
{
#ifdef WIN32
    if (OG_SUCCESS != epoll_init()) {
        printf("Failed to initialize epoll");
        return OG_ERROR;
    }
#endif
    if (cm_start_timer(g_timer()) != OG_SUCCESS) {
        printf("Aborted due to starting timer thread");
        return OG_ERROR;
    }

    if (srv_init_g_instance() != OG_SUCCESS) {
        return OG_ERROR;
    }

    (void)srv_setup_json_mpool();
    (void)srv_set_locale();
    (void)srv_init_ip_white();
    (void)srv_init_pwd_black();
    (void)srv_init_ip_login_addr();

    if (srv_get_home() != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        printf("%s\n", "Failed to get home");
        return OG_ERROR;
    }

    if (srv_load_params() != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        int32 error_code;
        const char *error_message;
        source_location_t error_location;
        cm_get_error(&error_code, &error_message, &error_location);
        OG_LOG_RUN_ERR("failed to load params");
        if (error_code == 0) {
            printf("Failed to load params\n");
        } else {
            printf("Failed to load params:%s\n", error_message);
        }

        return OG_ERROR;
    }

    if (init_cpu_info() != OG_SUCCESS) {
        srv_instance_destroy();
        OG_LOG_RUN_ERR("failed to initialize CPU instance resorces");
        return OG_ERROR;
    }

    (void)cm_lic_init();
    srv_print_params();

    if (srv_lock_db() != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("Another db is running");
        return OG_ERROR;
    }

    OG_LOG_RUN_INF("starting instance(%s), memory usage(%lu)", startup_mode(phase), cm_print_memory_usage());
    printf("starting instance(%s)\n", startup_mode(phase));


    if (sql_load_self_func() != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to load self function list");
        return OG_ERROR;
    }
    sql_print_self_func();

    if (srv_load_hba(OG_TRUE) != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to load hba");
        return OG_ERROR;
    }
    if (srv_load_pbl(OG_TRUE) != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to load pbl");
        return OG_ERROR;
    }

#ifndef WIN32
    if (sigcap_handle_reg() != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("Failed to initialize SIGSEGV func");
        return OG_ERROR;
    }
#endif

    srv_set_kernel_callback();
    srv_reg_os_rinfo();
    srv_regist_dynamic_views();

    if (srv_create_sga() != OG_SUCCESS) {
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to create sga");
        return OG_ERROR;
    }

    if (sql_instance_startup() != OG_SUCCESS) {
        srv_destroy_sga();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to startup sql instance");
        return OG_ERROR;
    }

    if (sql_load_type_map() != OG_SUCCESS) {
        srv_destroy_sga();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to load type map list");
        return OG_ERROR;
    }

    if (srv_init_session_pool() != OG_SUCCESS) {
        srv_destroy_sga();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to init session pool");
        return OG_ERROR;
    }

    if (srv_kernel_startup(is_coordinator) != OG_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, OG_FALSE);
        srv_destroy_sga();
        srv_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to startup kernel");
        return OG_ERROR;
    }

    /* Caution: parallel sessions pool init below the srv_kernel_startup, because inst->attr.cursor_size assignment
     in knl_init_attr */
    if (srv_init_par_sessions() != OG_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, OG_FALSE);
        srv_destroy_sga();
        srv_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to init parallel sessions");
        return OG_ERROR;
    }

    /* Caution: emerg sessions pool init below the srv_kernel_startup, because inst->attr.cursor_size assignment
          in knl_init_attr */
    if (srv_init_emerg_sessions() != OG_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, OG_FALSE);
        srv_destroy_sga();
        srv_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to init emerg sessions");
        return OG_ERROR;
    }

    srv_init_lob_locator();

    // create reactor thread pool if in shared mode
    if (reactor_create_pool() != OG_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, OG_FALSE);
        srv_destroy_sga();
        srv_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to create reactor pool");
        return OG_ERROR;
    }

    if (srv_start_lsnr() != OG_SUCCESS) {
        knl_shutdown(NULL, &g_instance->kernel, OG_FALSE);
        reactor_destroy_pool();
        srv_destroy_sga();
        srv_destory_reserved_session();
        CM_FREE_PTR(g_instance);
        OG_LOG_RUN_ERR("failed to start lsnr");
        return OG_ERROR;
    }
    // avoid to rewriting privilege file, when same socket listen conflict. init sysdba must after start lsnr
    if (srv_sysdba_privilege() != OG_SUCCESS) {
        return OG_ERROR;
    }
    // create ssl acceptor
    if (srv_init_ssl_communication() != OG_SUCCESS) {
        srv_instance_destroy();
        OG_LOG_RUN_ERR("failed to init SSL communication");
        return OG_ERROR;
    }

    g_instance->kernel.is_ssl_initialized = OG_TRUE;

    if (phase == STARTUP_MOUNT || phase == STARTUP_OPEN) {
        if (srv_kernel_open(phase) != OG_SUCCESS) {
            srv_instance_destroy();
            OG_LOG_RUN_ERR("failed to open kernel");
            return OG_ERROR;
        }
    }


    g_instance->lsnr_abort_status = OG_FALSE;
    if (cm_regist_signal(SIGUSR1, handle_signal_terminal) != OG_SUCCESS) {
        srv_instance_destroy();
        OG_LOG_RUN_ERR("failed to initialize SIGUSR1 func");
        return OG_ERROR;
    }

    if (init_job_manager() != OG_SUCCESS) {
        srv_instance_destroy();
        OG_LOG_RUN_ERR("failed to initialize job manager");
        printf("Aborted due to initialize job manager");
        return OG_ERROR;
    }

#ifndef WIN32
    // Re-register the signal handler in raft mode
    if (DB_IS_RAFT_ENABLED(&(g_instance->kernel))) {
        if (sigcap_handle_reg() != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to initialize SIGSEGV func in raft mode");
        }
    }

    if (sigcap_handle_reg() != OG_SUCCESS) {
        srv_instance_destroy();
        OG_LOG_RUN_ERR("Failed to initialize SIGSEGV func");
        return OG_ERROR;
    }
#endif

    OG_LOG_RUN_INF("instance started, memory usage(%lu)", cm_print_memory_usage());
    printf("%s\n", "instance started");
    fflush(stdout);
    return OG_SUCCESS;
}

void srv_instance_destroy(void)
{
    while (1) {
        if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE || cm_spin_try_lock(&g_instance->kernel.db.lock)) {
            break;
        }
        cm_sleep(SHUTDOWN_WAIT_INTERVAL);
        OG_LOG_RUN_INF("wait for shutdown to complete");
    }

    if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE) {
        return;
    }

    g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_INPROGRESS;
    g_instance->shutdown_ctx.session = NULL;
    g_instance->shutdown_ctx.mode = SHUTDOWN_MODE_ABORT;

    if (OG_SUCCESS != srv_wait_agents_done()) {
        OG_LOG_RUN_INF("kill canceled, all listener resumed");
        reactor_resume_pool();
        srv_resume_lsnr(LSNR_TYPE_ALL);
        g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_NOT_BEGIN;
        cm_spin_unlock(&g_instance->kernel.db.lock);
        return;
    }
    srv_close_threads(OG_TRUE);

    srv_deinit_resource();
    g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_DONE;
    CM_FREE_PTR(g_instance);
}

status_t srv_stop_all_session(shutdown_context_t *ogx)
{
    knl_session_t *session = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    switch (ogx->mode) {
        case SHUTDOWN_MODE_IMMEDIATE:
            if (session->kernel->db.status == DB_STATUS_RECOVERY) {
                OG_THROW_ERROR(ERR_RESTORE_IN_PROGRESS);
                return OG_ERROR;
            }
            srv_kill_all_session(ogx->session, OG_FALSE);
            /* fall-through */
        case SHUTDOWN_MODE_NORMAL:
            if (session->kernel->db.status == DB_STATUS_RECOVERY) {
                OG_THROW_ERROR(ERR_RESTORE_IN_PROGRESS);
                return OG_ERROR;
            }

            // If log receiver thread has been created, need to first stop it.
            if (session->kernel->lrcv_ctx.session != NULL) {
                lrcv_close(session);
            }

            return srv_wait_all_session_be_killed(ogx->session);
        case SHUTDOWN_MODE_ABORT:
            srv_kill_all_session(ogx->session, OG_TRUE);
            return srv_wait_all_session_be_killed(ogx->session);
        default:
            OG_THROW_ERROR(ERR_INVALID_OPERATION, "shutdown signal");
            return OG_ERROR;
    }
}

static status_t srv_wait_agents_done(void)
{
    shutdown_context_t *ogx = &g_instance->shutdown_ctx;

    OG_LOG_RUN_INF("begin to shutdown, mode %s", g_shutdown_mode_desc[ogx->mode]);

    OG_LOG_RUN_INF("begin to pause all listener");
    srv_pause_lsnr(LSNR_TYPE_ALL);

    if (ogx->mode != SHUTDOWN_MODE_NORMAL) {
        OG_LOG_RUN_INF("begin to pause reactor");
        reactor_pause_pool();
    }

    // stop all session
    if (ogx->session != NULL) {
        OG_LOG_RUN_INF("begin to stop all session");
        if (OG_SUCCESS != srv_stop_all_session(ogx)) {
            OG_LOG_RUN_ERR("stop all session failed");
            return OG_ERROR;
        }
    } else {
        OG_LOG_RUN_INF("begin to stop all session without self session");
        srv_kill_all_session(NULL, OG_FALSE);
        srv_wait_all_session_free();
    }

    OG_LOG_RUN_INF("wait all agents done ended");
    return OG_SUCCESS;
}

static void srv_close_threads(bool32 knl_flag)
{
    shutdown_context_t *ogx = &g_instance->shutdown_ctx;
    bool32 need_ckpt = OG_FALSE;
    // stop listener
    OG_LOG_RUN_INF("begin to stop all listener");
    srv_stop_lsnr(LSNR_TYPE_ALL);

    // stop reactor
    OG_LOG_RUN_INF("begin to stop reactor");
    reactor_destroy_pool();

    // stop emerg agents
    srv_close_emerg_agents();


    // stop rsrc manager
    OG_LOG_RUN_INF("begin to stop resource manager");
    rsrc_stop_manager(&g_instance->rsrc_mgr);

    if (knl_flag == OG_TRUE) {
        need_ckpt = ogx->mode > SHUTDOWN_MODE_SIGNAL ? OG_FALSE : OG_TRUE;
        OG_LOG_RUN_INF("begin to stop kernel");
        knl_shutdown(NULL, &g_instance->kernel, need_ckpt);
    }
}

static void srv_deinit_resource()
{
    // free ssl context
    if (g_instance->ssl_acceptor_fd != NULL) {
        OG_LOG_RUN_INF("begin to free ssl acceptor fd.");
        cs_ssl_free_context(g_instance->ssl_acceptor_fd);
        g_instance->ssl_acceptor_fd = NULL;
    }

    OG_LOG_RUN_INF("begin to destory reserved session.");
    srv_destory_reserved_session();

    OG_LOG_RUN_INF("begin to destory user session.");
    srv_destory_session();

    OG_LOG_RUN_INF("begin to destory sequence pool.");

    OG_LOG_RUN_INF("begin to free memory occupied by SGA.");
    srv_destroy_sga();
    OG_LOG_RUN_INF("begin to free configuration buffer.");
    cm_free_config_buf(&g_instance->config);
    OG_LOG_RUN_INF("begin to free null row.");
    sql_free_null_row();
    OG_LOG_RUN_INF("begin to free ctrl buffer.");
    cm_aligned_free(&g_instance->kernel.db.ctrl.buf);

    OG_LOG_RUN_INF("finish to shutdown, mode %s, db lock %s", g_shutdown_mode_desc[g_instance->shutdown_ctx.mode],
        g_instance->kernel.db.lock ? "true" : "false");
    sql_auditlog_deinit(&(cm_log_param_instance()->audit_param));
}

status_t srv_shutdown_wait(session_t *session, shutdown_mode_t mode, shutdown_context_t *ogx)
{
    knl_session_t *knl_session = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    bool32 is_prohibited = OG_TRUE;

    // 1.shutdown is prohibited during some operations that can't be interrupted(include shutdown)
    if (!cm_spin_try_lock(&g_instance->kernel.db.lock)) {
        OG_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
        return OG_ERROR;
    }

    // if reform in progress, shutdown is not allowed;
    if (DB_IS_CLUSTER(&(session->knl_session)) && !DB_CLUSTER_NO_CMS) {
        if (!rc_reform_trigger_disable()) {
            cm_spin_unlock(&g_instance->kernel.db.lock);
            OG_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
            return OG_ERROR;
        }
    }

    do {
        // 2.if rcy is looping,shutdown is allowed to break loop
        cm_spin_lock(&g_instance->kernel.rcy_ctx.lock, NULL);
        if (knl_session->kernel->rcy_ctx.is_working) {
            g_instance->kernel.rcy_ctx.is_closing = OG_TRUE;
            cm_spin_unlock(&g_instance->kernel.rcy_ctx.lock);
            is_prohibited = OG_FALSE;
            break;
        }
        cm_spin_unlock(&g_instance->kernel.rcy_ctx.lock);

        // 3.if db enter srv_instance_loop,shutdown is allowed
        if (g_instance->shutdown_ctx.enabled) {
            is_prohibited = OG_FALSE;
        }
    } while (0);

    if (is_prohibited) {
        cm_spin_unlock(&g_instance->kernel.db.lock);
        rc_reform_trigger_enable();
        OG_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
        return OG_ERROR;
    }

    /* shutdown is always divided into 3 steps:
    step 1: wait other agents process done
    step 2: release sql/sharding/kernel threads
    step 3: free memory resource, for sga
    step 2, step 3 should be processed at main thread */
    ogx->phase = SHUTDOWN_PHASE_INPROGRESS;
    ogx->session = session;
    ogx->mode = mode;

    if (OG_SUCCESS != srv_wait_agents_done()) {
        OG_LOG_RUN_INF("shutdown canceled, all listener resumed");
        reactor_resume_pool();
        srv_resume_lsnr(LSNR_TYPE_ALL);
        ogx->phase = SHUTDOWN_PHASE_NOT_BEGIN;
        cm_spin_unlock(&g_instance->kernel.db.lock);
        rc_reform_trigger_enable();
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t srv_shutdown(session_t *session, shutdown_mode_t mode)
{
    shutdown_context_t *ogx = &g_instance->shutdown_ctx;
    bool32 need_ckpt;

    SYNC_POINT(session, "SP_B1_SHUTDOWN");

    if (session->knl_session.rm->txn != NULL) {
        if (session->knl_session.rm->txn->status != (uint8)XACT_END) {
            OG_THROW_ERROR(ERR_SHUTDOWN_IN_TRANS);
            return OG_ERROR;
        }
    }

    if (DB_IS_CLUSTER(&(session->knl_session)) && !DB_CLUSTER_NO_CMS) {
        if (!dls_latch_timed_x(&(session->knl_session), &(ogx->shutdown_latch), session->knl_session.id, 1, NULL,
            OG_INVALID_ID32)) {
            OG_LOG_RUN_WAR("sql get shutdown lock failed, other node in shutdown progress");
            OG_THROW_ERROR(ERR_SHUTDOWN_IN_PROGRESS, session->knl_session.id);
            return OG_ERROR;
        }
        OG_LOG_RUN_INF("sql get shutdown lock, execute shutdown");
    }

    if (srv_shutdown_wait(session, mode, ogx) != OG_SUCCESS) {
        if (DB_IS_CLUSTER(&(session->knl_session))) {
            dls_unlatch(&(session->knl_session), &(ogx->shutdown_latch), NULL);
        }
        return OG_ERROR;
    }

    need_ckpt = ogx->mode > SHUTDOWN_MODE_SIGNAL ? OG_FALSE : OG_TRUE;
    OG_LOG_RUN_INF("begin to stop kernel");
    knl_shutdown(NULL, &g_instance->kernel, need_ckpt);
    CM_MFENCE;
    ogx->phase = SHUTDOWN_PHASE_DONE;
    OG_LOG_RUN_INF("end of stop kernel");
    return OG_SUCCESS;
}

void srv_instance_abort()
{
    shutdown_context_t *ogx = &g_instance->shutdown_ctx;
    if (!cm_spin_try_lock(&g_instance->kernel.db.lock)) {
        return;
    }
    if (g_instance->shutdown_ctx.phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return;
    }
    ogx->session = NULL;
    ogx->phase = SHUTDOWN_PHASE_INPROGRESS;
    ogx->mode = SHUTDOWN_MODE_SIGNAL;
    (void)srv_wait_agents_done();
    srv_close_threads(OG_TRUE);
    srv_deinit_resource();
    ogx->phase = SHUTDOWN_PHASE_DONE;
}

bool32 srv_is_kernel_reserve_session(session_type_e type)
{
    if (type == SESSION_TYPE_KERNEL_RESERVE) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

#ifdef __cplusplus
}
#endif
