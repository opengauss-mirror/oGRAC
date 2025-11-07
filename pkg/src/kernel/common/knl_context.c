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
 * knl_context.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_context.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "knl_context.h"
#include "cm_file.h"
#include "cm_dbs_intf.h"
#include "mes_config.h"
#include "cms_interface.h"
#include "cm_dbstor.h"

#ifdef __cplusplus
extern "C" {
#endif

extern bool8 g_local_set_disaster_cluster_role;

void knl_init_attr(knl_handle_t kernel)
{
    knl_instance_t *inst = (knl_instance_t *)kernel;
    char *param = NULL;

    uint32 page_size = inst->attr.page_size;
    inst->attr.max_row_size = OG_MAX_ROW_SIZE;
    /* the max value of page_size is 32768 and OG_PLOG_PAGES is 17 */
    inst->attr.plog_buf_size = page_size * OG_PLOG_PAGES;

    /*
     * page_size * 2: is allocated for row buffer and page buffer of cursor;
     * inst->attr.max_column_count * sizeof(uint16) * 2: need to add 2 array size when calculate
     * the cursor size: cursor->offsets, cursor->lens;
     */
    inst->attr.cursor_size = sizeof(knl_cursor_t) + page_size * 2 + inst->attr.max_column_count * sizeof(uint16) * 2;
    inst->attr.commit_batch = OG_FALSE;
    inst->attr.commit_nowait = OG_FALSE;
    /* the min value of inst->attr.max_map_nodes is 8192 */
    inst->attr.max_map_nodes = (page_size - sizeof(map_page_t) - sizeof(page_tail_t)) / sizeof(map_node_t);
    inst->attr.sample_by_map = OG_TRUE;
    param = cm_get_config_value(inst->attr.config, "COMMIT_WAIT");
    if (param != NULL) {
        inst->attr.commit_nowait = cm_str_equal(param, "NOWAIT");
    }
}

static void dbs_link_down_exit(void)
{
    CM_ABORT_REASONABLE(0, "[DBSTOR] All links are disconnected, the process exit.");
}

status_t knl_startup(knl_handle_t kernel)
{
    knl_instance_t *ogx = (knl_instance_t *)kernel;
    knl_session_t *session = ogx->sessions[SESSION_ID_KERNEL];
    int32 ret;

    // try to open database, if db is exists
    session->kernel->db.status = DB_STATUS_CLOSED;

    ret = memset_sp(&ogx->switch_ctrl, sizeof(switch_ctrl_t), 0, sizeof(switch_ctrl_t));
    knl_securec_check(ret);

    if (db_load_lib(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (db_init(session) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (DB_ATTR_CLUSTER(session)) {
        cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
        if (cfg->enable &&
            g_knl_callback.device_init((const char *)session->kernel->dtc_attr.ogstore_inst_path) != OG_SUCCESS) {
            OG_LOG_RUN_INF("RAFT: db init raw type device failed");
            return OG_ERROR;
        }
        if (!cfg->enable) {
            OG_LOG_RUN_INF("Note: dbstor is not enabled, the disaster recovery funcs would not work.");
        } else {
            const char* uuid = get_config_uuid(session->kernel->id);
            uint32 lsid = get_config_lsid(session->kernel->id);
            cm_set_dbs_uuid_lsid(uuid, lsid);
 
            if (dbs_global_handle()->reg_role_info_callback(set_disaster_cluster_role) != OG_SUCCESS) {
                OG_LOG_RUN_INF("Failed to register RoleInfoCallBack.");
                return OG_ERROR;
            }
            if (cm_dbs_init(ogx->home, DBS_CONFIG_NAME, DBS_RUN_OGRACD_SERVER) != OG_SUCCESS) {
                OG_LOG_RUN_INF("DBSTOR: init failed.");
                return OG_ERROR;
            }
            dbs_global_handle()->dbs_link_down_event_reg(dbs_link_down_exit);
            while (OG_TRUE) {
                if (g_local_set_disaster_cluster_role) {
                    g_local_set_disaster_cluster_role = OG_FALSE;
                    break;
                }
                cm_sleep(1);
            }
        }
    }

    session->kernel->db.status = DB_STATUS_NOMOUNT;
    session->kernel->db_startup_time = cm_now();

    // 给cms注册升级处理函数
    cms_res_inst_register_upgrade(knl_set_ctrl_core_version);
    return OG_SUCCESS;
}

void knl_shutdown(knl_handle_t sess, knl_handle_t kernel, bool32 need_ckpt)
{
    knl_handle_t session = sess;
    knl_instance_t *ogx = (knl_instance_t *)kernel;
    
    alck_deinit_ctx(ogx);

    if (session == NULL) {
        session = ogx->sessions[SESSION_ID_KERNEL];
    }
    db_close((knl_session_t *)session, need_ckpt);
}

status_t db_fdatasync_file(knl_session_t *session, int32 file)
{
    if (!session->kernel->attr.enable_fdatasync) {
        return OG_SUCCESS;
    }

    if (cm_fdatasync_file(file) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_fsync_file(knl_session_t *session, int32 file)
{
    if (session->kernel->attr.enable_OSYNC) {
        return OG_SUCCESS;
    }

    if (cm_fsync_file(file) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t db_load_aio_lib(cm_aio_lib_t *procs)
{
    if (cm_open_dl(&procs->lib_handle, "libaio.so.1") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_setup", (void **)(&procs->io_setup)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_destroy", (void **)(&procs->io_destroy)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_submit", (void **)(&procs->io_submit)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_cancel", (void **)(&procs->io_cancel)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_load_symbol(procs->lib_handle, "io_getevents", (void **)(&procs->io_getevents)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t db_load_lib(knl_session_t *session)
{
    if (session->kernel->attr.enable_asynch) {
        if (db_load_aio_lib(&session->kernel->aio_lib) == OG_SUCCESS) {
            return OG_SUCCESS;
        }
        OG_LOG_RUN_ERR("[DB] It is not support async io");
        return OG_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == OG_TRUE) {
        if (dbs_init_lib() != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to init lib.");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

uint32 knl_io_flag(knl_session_t *session)
{
    if (session->kernel->attr.enable_asynch) {
        return O_DIRECT;
    }
    if (session->kernel->attr.enable_directIO) {
        return O_DIRECT | O_SYNC;
    }
    if (session->kernel->attr.enable_dsync) {
        return O_DSYNC;
    }
    if (session->kernel->attr.enable_fdatasync) {
        return 0;
    }
    return O_SYNC;
}

uint32 knl_redo_io_flag(knl_session_t *session)
{
    uint32 flag = 0;

    if (session->kernel->attr.enable_logdirectIO) {
        flag |= O_DIRECT;
    }

    if (session->kernel->attr.enable_OSYNC) {
        flag |= O_SYNC;
    } else {
        flag |= O_DSYNC;
    }

    return flag;
}

uint32 knl_arch_io_flag(knl_session_t *session, bool32 arch_compressed)
{
    uint32 flag = 0;

    if (!arch_compressed && session->kernel->attr.enable_logdirectIO) {
        flag |= O_DIRECT;
    }

    if (session->kernel->attr.enable_OSYNC) {
        flag |= O_SYNC;
    } else {
        flag |= O_DSYNC;
    }

    return flag;
}

#ifdef __cplusplus
}
#endif
