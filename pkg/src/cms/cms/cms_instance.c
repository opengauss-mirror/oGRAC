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
 * cms_instance.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_instance.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_instance.h"
#include "cms_defs.h"
#include "cm_config.h"
#include "cms_gcc.h"
#include "cs_tcp.h"
#include "cms_msg_def.h"
#include "cms_uds_server.h"
#include "cms_work.h"
#include "cms_param.h"
#include "cms_comm.h"
#include "cms_stat.h"
#include "cm_file.h"
#include "cms_vote.h"
#include "cms_msgque.h"
#include "cms_blackbox.h"
#include "cm_io_record.h"
#include "cms_mes.h"
#include "cm_dbs_intf.h"
#include "mes_config.h"
#include "cms_log.h"
#include "cm_dbstor.h"

static cms_instance_t g_cms_instance = {.is_server = OG_FALSE, .is_dbstor_cli_init = OG_FALSE};

cms_instance_t *g_cms_inst = &g_cms_instance;
static const char *g_cms_lock_file = "cms_server.lck";
cms_que_t g_hb_aync_gap_que = {0};

static status_t cms_init_queue_and_sync(void)
{
    if (cms_init_que(&g_cms_inst->recv_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init recv que faild");
        return OG_ERROR;
    }
    if (cms_init_que(&g_cms_inst->send_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init send que faild");
        return OG_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cli_recv_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init cli recv que faild");
        return OG_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cli_send_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init cli recv que faild");
        return OG_ERROR;
    }
    if (cms_init_que(&g_cms_inst->aync_write_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init aync write que faild");
        return OG_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cmd_recv_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init cmd recv que faild");
        return OG_ERROR;
    }
    if (cms_init_que(&g_hb_aync_gap_que) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init hb aync gap que faild");
        return OG_ERROR;
    }
    if (cms_sync_init(&g_cms_inst->try_master_sync) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init try master sync faild");
        return OG_ERROR;
    }
    if (cm_event_init(&g_cms_inst->voting_sync) != OG_SUCCESS) {
        CMS_LOG_ERR("cms init voting sync faild");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cms_instance_init(void)
{
    if (cms_node_is_invalid(g_cms_param->node_id)) {
        OG_THROW_ERROR(ERR_CMS_GCC_NODE_UNREGISTERED);
        CMS_LOG_ERR("cms node(%d) is invalid", g_cms_param->node_id);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cms_init_queue_and_sync());
    OG_RETURN_IFERR(cms_init_stat());

    return OG_SUCCESS;
}

static status_t cms_create_uds_threads(void)
{
    if (cm_create_thread(cms_uds_srv_listen_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_listen_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create uds listen entry thread failed");
        return OG_ERROR;
    }

    if (cm_create_thread(cms_uds_srv_recv_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_recv_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create uds recv entry thread failed");
        return OG_ERROR;
    }

    if (cm_create_thread(cms_uds_srv_send_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_send_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create uds send entry thread failed");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < g_cms_param->uds_worker_thread_count; i++) {
        if (cm_create_thread(cms_uds_worker_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->uds_work_thread[i]) != OG_SUCCESS) {
            CMS_LOG_ERR("cms create uds worker entry thread failed");
            return OG_ERROR;
        }
    }

    CMS_LOG_INF("cms create uds work entry success.");

    if (cm_create_thread(cms_uds_hb_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_hb_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create hb worker entry thread failed");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t cms_get_uuid_lsid_from_config(char* cfg_name, uint32* lsid, char* uuid)
{
    char file_path[CMS_FILE_NAME_BUFFER_SIZE];
    char line[CMS_DBS_CONFIG_MAX_PARAM];
    errno_t ret = sprintf_s(file_path, CMS_FILE_NAME_BUFFER_SIZE, "/opt/ograc/dbstor/conf/dbs/%s", cfg_name);
    PRTS_RETURN_IFERR(ret);
    FILE* fp = fopen(file_path, "r");
    if (fp == NULL) {
        OG_LOG_RUN_ERR("Failed to open file %s\n", file_path);
        return OG_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *context = NULL;
        if (strstr(line, "INST_ID") != NULL) {
            text_t lsid_t;
            lsid_t.str = strtok_s(line, "=", &context);
            lsid_t.str = strtok_s(NULL, "\n", &context);
            lsid_t.len = strlen(lsid_t.str);
            cm_trim_text(&lsid_t);
            OG_RETURN_IFERR(cm_str2uint32((const char *)lsid_t.str, lsid));
        } else if (strstr(line, "DBS_TOOL_UUID") != NULL) {
            text_t uuid_t;
            uuid_t.str = strtok_s(line, "=", &context);
            uuid_t.str = strtok_s(NULL, "\n", &context);
            uuid_t.len = strlen(uuid_t.str);
            cm_trim_text(&uuid_t);
            MEMS_RETURN_IFERR(strcpy_s(uuid, CMS_CLUSTER_UUID_LEN, uuid_t.str));
        }
    }
    (void)fclose(fp);
    return OG_SUCCESS;
}

status_t cms_init_dbs_client(char* cfg_name, dbs_init_mode init_mode)
{
    int64_t start_time = cm_now();
    OG_RETURN_IFERR(dbs_init_lib());
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (!cfg->enable) {
        OG_LOG_RUN_INF("dbstor is not enabled");
        return OG_SUCCESS;
    }

    uint32 lsid;
    char uuid[CMS_CLUSTER_UUID_LEN] = { 0 };

    OG_LOG_RUN_INF("dbstor client is inited by config file %s", cfg_name);
    if (strstr(cfg_name, "tool") != NULL) {
        if (cms_get_uuid_lsid_from_config(cfg_name, &lsid, uuid) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("cms get uuid lsid from config(%s) failed.\n", cfg_name);
            return OG_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(strcpy_s(uuid, CMS_CLUSTER_UUID_LEN, get_config_uuid(g_cms_param->node_id)));
        lsid = get_config_lsid(g_cms_param->node_id);
    }

    cm_set_dbs_uuid_lsid((const char*)uuid, lsid);
    OG_RETURN_IFERR(cm_dbs_init(g_cms_param->cms_home, cfg_name, init_mode));
    g_cms_inst->is_dbstor_cli_init = OG_TRUE;
    int64_t end_time = cm_now();
    OG_LOG_RUN_INF("dbstor client init time %ld (ns)", end_time - start_time);
    return OG_SUCCESS;
}

static status_t cms_create_voting_threads(void)
{
    if (cm_dbs_is_enable_dbs() == OG_TRUE && g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        OG_RETURN_IFERR(cms_init_dbs_client(DBS_CONFIG_NAME, DBS_RUN_CMS_SERVER_NFS));
    }
    OG_RETURN_IFERR(cms_vote_disk_init());
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        if (cm_create_thread(cms_voting_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->voting_thread) != OG_SUCCESS) {
            CMS_LOG_ERR("cms create voting entry thread failed");
            return OG_ERROR;
        }

        if (cm_create_thread(cms_detect_voting_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->detect_voting_thread) != OG_SUCCESS) {
            CMS_LOG_ERR("cms create detect voting entry thread failed");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t cms_create_check_disk_threads(void)
{
    if (cm_create_thread(cms_detect_disk_error_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->detect_disk_error_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create detect disk error entry thread failed");
        return OG_ERROR;
    }
    if (cm_create_thread(cms_judge_disk_error_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->judge_disk_error_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create judge disk error entry thread failed");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cms_create_aync_write_thread(void)
{
    cms_res_stat_t *res_stat_disk;
    res_stat_disk = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_res_stat_t));
    if (res_stat_disk == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_res_stat_t), "cms create stat aync write entry");
        return OG_ERROR;
    }
    if (cm_create_thread(cms_stat_aync_write_entry, OG_DFLT_THREAD_STACK_SIZE, res_stat_disk,
        &g_cms_inst->stat_aync_write_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create stat aync write entry thread failed");
        CM_FREE_PTR(res_stat_disk);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t cms_create_threads(void)
{
    if (cm_create_thread(cms_mes_send_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->send_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create send entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create send entry thread success");

    for (uint32 i = 0; i < g_cms_param->worker_thread_count; i++) {
        if (cm_create_thread(cms_worker_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->work_thread[i]) != OG_SUCCESS) {
            CMS_LOG_ERR("cms create worker entry thread failed");
            return OG_ERROR;
        }
    }
    CMS_LOG_INF("cms create worker entry thread success");

    if (cm_create_thread(cms_worker_entry, OG_DFLT_THREAD_STACK_SIZE, CMS_HB_WORKER_FLAG,
        &g_cms_inst->hb_worker_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create hb worker entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create hb worker entry thread success");

    if (cms_create_uds_threads() != OG_SUCCESS) {
        CMS_LOG_ERR("cms create uds threads failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create uds threads success");

    if (cm_create_thread(cmd_handle_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->cmd_handle_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create cmd worker entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create cmd worker entry thread success");

    if (cm_create_thread(cms_hb_timer_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->hb_timer_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create hb timer entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create hb timer entry thread success");

    if (cm_create_thread(cms_res_check_timer_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->res_check_timer_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create res check timer entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create res check timer entry thread success");

    if (cm_create_thread(cms_gcc_loader_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->gcc_loader_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create gcc loader entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create gcc loader entry thread success");

    if (cm_create_thread(cms_gcc_backup_entry, OG_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->gcc_backup_thread) != OG_SUCCESS) {
        CMS_LOG_ERR("cms create gcc backup entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create gcc backup entry thread success");

    if (cms_create_aync_write_thread() != OG_SUCCESS) {
        CMS_LOG_ERR("cms create stat aync write entry thread failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create stat aync write entry thread success");

    if (cms_create_voting_threads() != OG_SUCCESS) {
        CMS_LOG_ERR("cms create voting threads failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create voting threads success");

    if (cms_create_check_disk_threads() != OG_SUCCESS) {
        CMS_LOG_ERR("cms create check disk threads failed");
        return OG_ERROR;
    }
    CMS_LOG_INF("cms create check disk threads success");

    return OG_SUCCESS;
}

static status_t cms_close_threads(void)
{
    cm_close_thread(&g_cms_inst->send_thread);
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        cm_close_thread(&g_cms_inst->work_thread[i]);
    }
    cm_close_thread(&g_cms_inst->cmd_handle_thread);
    cm_close_thread(&g_cms_inst->hb_timer_thread);
    cm_close_thread(&g_cms_inst->res_check_timer_thread);
    cm_close_thread(&g_cms_inst->hb_worker_thread);
    cm_close_thread(&g_cms_inst->uds_send_thread);
    cm_close_thread(&g_cms_inst->uds_recv_thread);
    cm_close_thread(&g_cms_inst->uds_listen_thread);
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        cm_close_thread(&g_cms_inst->uds_work_thread[i]);
    }
    cm_close_thread(&g_cms_inst->uds_hb_thread);
    cm_close_thread(&g_cms_inst->gcc_loader_thread);
    cm_close_thread(&g_cms_inst->gcc_backup_thread);
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        cm_close_thread(&g_cms_inst->voting_thread);
        cm_close_thread(&g_cms_inst->detect_voting_thread);
    }
    
    return OG_SUCCESS;
}

status_t cms_lock_server(void)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 ret;

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/%s",
        g_cms_param->cms_home, g_cms_lock_file);
    PRTS_RETURN_IFERR(ret);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
        &g_cms_inst->server_lock_fd) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return cm_lockw_file_fd(g_cms_inst->server_lock_fd);
}

status_t cms_force_unlock_server(void)
{
    if (cm_unlock_file_fd(g_cms_inst->server_lock_fd) != OG_SUCCESS) {
        CMS_LOG_ERR("cms unlock server fd failed.");
    }
    cm_close_file(g_cms_inst->server_lock_fd);
    return OG_SUCCESS;
}

static status_t cms_server_loop(void)
{
    g_cms_inst->server_loop = OG_TRUE;
    cms_trigger_voting();
    while (g_cms_inst->server_loop) {
        cms_try_be_master();
        cms_sync_wait(&g_cms_inst->try_master_sync, CMS_INST_TRY_MASTER_WAIT_TIME);
    }
    cm_sleep(CMS_INST_SERVER_SLEEP_TIME);
    return OG_SUCCESS;
}

void cms_do_try_master(void)
{
    cms_sync_notify(&g_cms_inst->try_master_sync);
}

static status_t cms_update_local_cfg(void)
{
    char port[8] = { 0 };
    errno_t ret;
    cms_node_def_t node_def;

    OG_RETURN_IFERR(cms_get_node_by_id(g_cms_param->node_id, &node_def));

    ret = sprintf_s(port, sizeof(port), "%u", node_def.port);
    PRTS_RETURN_IFERR(ret);

    OG_RETURN_IFERR(cms_update_param("_IP", node_def.ip));
    OG_RETURN_IFERR(cms_update_param("_PORT", port));

    return OG_SUCCESS;
}

static void cms_get_dbversion(upgrade_version_t *cms_version)
{
    text_t db_version = { 0 };
    text_t left = { 0 };
    text_t right = { 0 };
    text_t right2 = { 0 };
    text_t version_main = { 0 };
    text_t version_major = { 0 };
    text_t version_revision = { 0 };
    uint32 main_n = 0;
    uint32 major_n = 0;
    uint32 revision_n = 0;
    char *version = (char *)oGRACd_get_dbversion();
    cm_str2text(version, &db_version);
    // for release package the dbversion is like "oGRAC Release 2.0.0"
    // for debug package the dbversion is like "oGRAC Debug 2.0.0 c11fdca072"
    (void)cm_split_text(&db_version, ' ', 0, &left, &right);
    (void)cm_split_text(&right, ' ', 0, &left, &right2);
    (void)cm_split_text(&right2, ' ', 0, &left, &right);
    (void)cm_split_text(&left, '.', 0, &version_main, &right);
    (void)cm_split_text(&right, '.', 0, &version_major, &version_revision);
    (void)cm_text2int(&version_main, (int32 *)&main_n);
    (void)cm_text2int(&version_major, (int32 *)&major_n);
    (void)cm_text2int(&version_revision, (int32 *)&revision_n);
    cms_version->main = (uint16)main_n;
    cms_version->major = (uint16)major_n;
    cms_version->revision = (uint16)revision_n;
    cms_version->inner = CMS_DEFAULT_INNNER_VERSION;
    return;
}

static status_t cms_update_version(void)
{
    status_t ret = OG_ERROR;
    bool32 all_restart = OG_FALSE;
    bool32 cmp_result = OG_FALSE;
    upgrade_version_t cms_version = { 0 };
    (void)cms_get_dbversion(&cms_version);
    CMS_LOG_INF("get dbversion finished, main=%u, major=%u, revision=%u, inner=%u.", cms_version.main,
        cms_version.major, cms_version.revision, cms_version.inner);
 
    cms_gcc_t* resident_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (resident_gcc == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "loading gcc");
        return OG_ERROR;
    }
    (void)memset_sp(resident_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (cms_gcc_read_disk_direct(resident_gcc) != OG_SUCCESS) {
        CM_FREE_PTR(resident_gcc);
        CMS_LOG_ERR("read disk failed when load gcc.");
        return OG_ERROR;
    }
    CMS_LOG_INF("get cms gcc version finished, main=%u, major=%u, revision=%u, inner=%u.",
        resident_gcc->head.ver_main, resident_gcc->head.ver_major, resident_gcc->head.ver_revision,
        resident_gcc->head.ver_inner);
    
    cmp_result = cms_dbversion_cmp(&cms_version, resident_gcc);
    if (cmp_result == OG_TRUE) {
        CM_FREE_PTR(resident_gcc);
        CMS_LOG_ERR("cms gcc version bigger than db version, cmp_result = %d.", cmp_result);
        return OG_ERROR;
    }
 
    // 如果是fullstart，则更新gcc
    OG_RETURN_IFERR(cms_is_all_restart(&all_restart));
    if (!all_restart) {
        CMS_LOG_INF("cms gcc version not need update.");
        CM_FREE_PTR(resident_gcc);
        // 更新内存gcc
        (void)cms_notify_load_gcc();
        return OG_SUCCESS;
    }

    if (resident_gcc->head.ver_main != 0) {
        CMS_LOG_INF("cms gcc version no more need update.");
        CM_FREE_PTR(resident_gcc);
        // 更新内存gcc
        (void)cms_notify_load_gcc();
        return OG_SUCCESS;
    }
    CM_FREE_PTR(resident_gcc);
 
    ret = cms_update_gcc_ver(cms_version.main, cms_version.major, cms_version.revision, cms_version.inner);
    if (ret != OG_SUCCESS) {
        CMS_LOG_ERR("update cms gcc version failed.");
        return OG_ERROR;
    }
    // 更新内存gcc
    (void)cms_notify_load_gcc();
    return OG_SUCCESS;
}

status_t cms_startup(void)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS && cms_lock_server() != OG_SUCCESS) {
        cm_reset_error();
        CMS_LOG_ERR("Another cms server is running");
        OG_THROW_ERROR(ERR_CMS_SERVER_RUNNING);
        return OG_ERROR;
    }

    g_cms_inst->is_server = OG_TRUE;
    CMS_LOG_INF("[cms srv init] cms startup begin.");
    OG_RETURN_IFERR(sigcap_hreg());
    CMS_LOG_INF("[cms srv init] cms sigcap handle reg succ");
    OG_RETURN_IFERR(cms_load_gcc());
    CMS_LOG_INF("[cms srv init] cms load gcc succ");
    OG_RETURN_IFERR(cms_update_local_cfg());
    CMS_LOG_INF("[cms srv init] cms update local cfg succ");
    OG_RETURN_IFERR(cms_update_local_gcc());
    CMS_LOG_INF("[cms srv init] cms update local gcc succ");
    OG_RETURN_IFERR(cms_instance_init());
    CMS_LOG_INF("[cms srv init] cms instance init succ");
    OG_RETURN_IFERR(inc_stat_version());
    CMS_LOG_INF("[cms srv init] cms inc stat ver succ");
    OG_RETURN_IFERR(record_io_stat_init());
    CMS_LOG_INF("[cms srv init] cms record io stat init succ");
    OG_RETURN_IFERR(cms_uds_srv_init());
    CMS_LOG_INF("[cms srv init] cms cms uds srv_init succ");
    OG_RETURN_IFERR(cms_init_mes_channel_version());
    CMS_LOG_INF("[cms srv init] cms init mes channel version succ");
    OG_RETURN_IFERR(cms_startup_mes());
    CMS_LOG_INF("[cms srv init] cms startup mes succ");
    OG_RETURN_IFERR(cms_create_threads());
    CMS_LOG_INF("[cms srv init] cms create threads succ");
    OG_RETURN_IFERR(cms_update_version());
    CMS_LOG_INF("[cms srv init] cms update version succ");
    OG_RETURN_IFERR(cms_server_loop());
    OG_RETURN_IFERR(cms_close_threads());
    return OG_SUCCESS;
}

void cms_shutdown(void)
{
    g_cms_inst->disk_thread.closed = OG_TRUE;
    g_cms_inst->send_thread.closed = OG_TRUE;
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        g_cms_inst->work_thread[i].closed = OG_TRUE;
    }
    g_cms_inst->cmd_handle_thread.closed = OG_TRUE;
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        g_cms_inst->voting_thread.closed = OG_TRUE;
        g_cms_inst->detect_voting_thread.closed = OG_TRUE;
    }
    g_cms_inst->judge_disk_error_thread.closed = OG_TRUE;
    g_cms_inst->detect_disk_error_thread.closed = OG_TRUE;
}

static pthread_key_t        g_inst_local_var;
static pthread_once_t       g_inst_once = PTHREAD_ONCE_INIT;

static void inst_once_init()
{
    (void)pthread_key_create(&g_inst_local_var, NULL);
}

status_t cms_get_local_ctx(cms_local_ctx_t** ogx)
{
    (void)pthread_once(&g_inst_once, inst_once_init);

    cms_local_ctx_t* _ctx = (cms_local_ctx_t*)pthread_getspecific(g_inst_local_var);
    if (_ctx == NULL) {
        _ctx = (cms_local_ctx_t*)malloc(sizeof(cms_local_ctx_t));
        if (_ctx == NULL) {
            CMS_LOG_ERR("alloc memory failed. error code:%d,%s", errno, strerror(errno));
            return OG_ERROR;
        }

        _ctx->gcc_handle = -1;
        _ctx->handle_valid = -1;
        (void)pthread_setspecific(g_inst_local_var, _ctx);
    }

    if (_ctx->handle_valid == -1) {
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
            OG_RETURN_IFERR(cm_get_dbs_last_file_handle(g_cms_param->gcc_home, &_ctx->gcc_dbs_handle));
        } else {
            OG_RETURN_IFERR(cm_open_disk(g_cms_param->gcc_home, &_ctx->gcc_handle));
            OG_LOG_DEBUG_INF("thread id %u, gcc handle %d, gcc %s", cm_get_current_thread_id(),
                _ctx->gcc_handle, g_cms_param->gcc_home);
        }
        _ctx->handle_valid = 1;
    }

    *ogx = _ctx;
    return OG_SUCCESS;
}

static status_t cms_send_srv_msg_to(uint16 node_id, cms_packet_head_t* msg)
{
    biqueue_node_t* node = cms_que_alloc_node(msg->msg_size);
    if (node == NULL) {
        CMS_LOG_ERR("cms malloc msg size %u failed.", msg->msg_size);
        return OG_ERROR;
    }
    cms_packet_head_t* send_msg = (cms_packet_head_t*)cms_que_node_data(node);
    errno_t ret = memcpy_s(send_msg, msg->msg_size, msg, msg->msg_size);
    if (ret != EOK) {
        CMS_LOG_ERR("cms memcpy failed, src msg size %u, errno %d[%s]", msg->msg_size, cm_get_os_error(),
            strerror(errno));
        cms_que_free_node(node);
        return OG_ERROR;
    }
    send_msg->src_node = msg->dest_node;
    send_msg->dest_node = node_id;
    cms_enque(&g_cms_inst->send_que, node);
    return OG_SUCCESS;
}

status_t cms_broadcast_srv_msg(cms_packet_head_t* msg)
{
    status_t ret = OG_SUCCESS;
    uint32 node_count = cms_get_gcc_node_count();
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            continue;
        }
        ret = cms_send_srv_msg_to(i, msg);
        if (ret != OG_SUCCESS) {
            CMS_LOG_ERR("cms send srv msg failed, ret %d, node id %u, msg type %u, msg seq %llu", ret,
                i, msg->msg_type, msg->msg_seq);
            return ret;
        }
    }
    return OG_SUCCESS;
}
