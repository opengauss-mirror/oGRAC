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
 * cm_dbstor.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbstor.c
 *
 * -------------------------------------------------------------------------
 */

#include <dlfcn.h>
#include "cm_log.h"
#include "cm_error.h"
#include "cm_dbstor.h"
#include "cm_dbs_module.h"

#ifdef __cplusplus
extern "C" {
#endif

static dbs_interface_t g_dbs_interface = { 0 };
static dbs_tool_interface_t g_dbs_tool_interface = { .dbs_tool_handle = NULL };

dbs_interface_t *dbs_global_handle(void)
{
    return &g_dbs_interface;
}

dbs_tool_interface_t *dbs_tool_global_handle(void)
{
    return &g_dbs_tool_interface;
}

static status_t dbs_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        OG_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t dbs_init_lib(void)
{
    dbs_interface_t *intf = dbs_global_handle();
    const char *dlopen_err = NULL;
    intf->dbs_handle = dlopen("libdbstorClient.so", RTLD_LAZY);
    dlopen_err = dlerror();
    if (intf->dbs_handle == NULL) {
        OG_LOG_RUN_WAR("Failed to load libdbstorClient.so, trying libdbstoreClient.so instead, original error: %s", dlopen_err);
        intf->dbs_handle = dlopen("libdbstoreClient.so", RTLD_LAZY);
        dlopen_err = dlerror();
        if (intf->dbs_handle == NULL) {
            OG_LOG_RUN_ERR("Failed to load libdbstoreClient.so, maybe lib path error, errno %s", dlopen_err);
            return OG_ERROR;
        }
    }

    // namespace
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreateNameSpace",                (void **)(&intf->create_namespace)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenNameSpace",                  (void **)(&intf->open_namespace)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SetTermAccessModeForNs",         (void **)(&intf->set_term_access_mode_for_ns)));
    (void)dbs_load_symbol(intf->dbs_handle, "DbsNsIoForbidden", (void **)(&intf->dbs_ns_io_forbidden));
    (void)dbs_load_symbol(intf->dbs_handle, "DbsGetIpPairs", (void **)(&intf->dbs_get_ip_pairs));
    (void)dbs_load_symbol(intf->dbs_handle, "DbsCreateLink", (void **)(&intf->dbs_create_link));
    (void)dbs_load_symbol(intf->dbs_handle, "DbsCheckSingleLink", (void **)(&intf->dbs_check_single_link));
    (void)dbs_load_symbol(intf->dbs_handle, "DbsFileOpenRootByVstorId", (void **)(&intf->dbs_file_open_root_by_vstorid));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsFileCreateByPath",            (void **)(&intf->dbs_file_create_by_path)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsFileOpenByPath",              (void **)(&intf->dbs_file_open_by_path)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsFileRename",                  (void **)(&intf->dbs_file_rename)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsFileGetNum",                  (void **)(&intf->dbs_file_get_num)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsFileGetList",                 (void **)(&intf->dbs_file_get_list)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsFileGetListDetail",           (void **)(&intf->dbs_file_get_list_detail)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsGetFileSize",                 (void **)(&intf->dbs_get_file_size)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsUlogArchive",                 (void **)(&intf->dbs_ulog_archive)));
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsGetNsIoForbiddenStat",         (void **)(&intf->dbs_get_ns_io_forbidden_stat)));
    // dbs
    (void)(dbs_load_symbol(intf->dbs_handle, "DbsQueryFsInfo",                          (void **)(&intf->dbs_query_fs_info)));
    cm_reset_error();

    // dbs
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientSetUuidLsid",           (void **)(&intf->dbs_client_set_uuid_lsid)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientLibInit",               (void **)(&intf->dbs_client_lib_init)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsSetInitMode",                 (void **)(&intf->dbs_set_init_mode)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientFlushLog",              (void **)(&intf->dbs_client_flush_log)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "RegisterRoleInfoCallBack",       (void **)(&intf->reg_role_info_callback)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsLinkDownEventReg",            (void **)(&intf->dbs_link_down_event_reg)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsInitLock",                    (void **)(&intf->dbs_init_lock)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsInstLock",                    (void **)(&intf->dbs_inst_lock)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsInstUnlock",                  (void **)(&intf->dbs_inst_unlock)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsInstUnlockForce",             (void **)(&intf->dbs_inst_unlock_force)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsCheckInstHeartBeatIsNormal",  (void **)(&intf->dbs_check_inst_heart_beat_is_normal)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsFileOpenRoot",                (void **)(&intf->dbs_file_open_root)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsFileCreate",                  (void **)(&intf->dbs_file_create)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsFileOpen",                    (void **)(&intf->dbs_file_open)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsFileWrite",                   (void **)(&intf->dbs_file_write)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsFileRead",                    (void **)(&intf->dbs_file_read)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsFileRemove",                  (void **)(&intf->dbs_file_remove)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClearCmsNameSpace",           (void **)(&intf->dbs_clear_cms_name_space)));

    // pagepool
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreatePagePool",                 (void **)(&intf->create_pagepool)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DestroyPagePool",                (void **)(&intf->destroy_pagepool)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenPagePool",                   (void **)(&intf->open_pagepool)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ClosePagePool",                  (void **)(&intf->close_pagepool)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsPutPageAysnc",                (void **)(&intf->dbs_put_page_async)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SyncPageByPartIndex",            (void **)(&intf->sync_page_by_part_index)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsMputContinuePages",           (void **)(&intf->dbs_mput_continue_pages)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsMGetPage",                    (void **)(&intf->dbs_mget_page)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetPagePoolLogicCapacity",       (void **)(&intf->get_pagepool_logic_capacity)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ExpandPagePoolLogicCapacity",    (void **)(&intf->expand_pagepool_logic_capacity)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "RenamePagePool",                 (void **)(&intf->rename_pagepool)));

    // ulog
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreateUlog",                     (void **)(&intf->create_ulog)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DestroyUlog",                    (void **)(&intf->destroy_ulog)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenUlog",                       (void **)(&intf->open_ulog)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "AppendUlogRecord",               (void **)(&intf->append_ulog_record)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "TruncateUlog",                   (void **)(&intf->truncate_ulog)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ReadUlogRecordList",             (void **)(&intf->read_ulog_record_list)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetUlogUsedCap",                 (void **)(&intf->get_ulog_used_cap)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetUlogInitCapacity",            (void **)(&intf->get_ulog_init_capacity)));
    OG_LOG_RUN_INF("load libdbstorClient.so done");

    return OG_SUCCESS;
}

status_t dbs_tool_init_lib(void)
{
    dbs_tool_interface_t *intf = dbs_tool_global_handle();
    intf->dbs_tool_handle = dlopen("libdbstor_tool.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->dbs_tool_handle == NULL) {
        OG_LOG_RUN_WAR("failed to load libdbstor_tool.so, maybe lib path error, errno %s", dlopen_err);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_tool_handle, "get_curr_log_offset",       (void **)(&intf->get_curr_log_offset)));
    OG_RETURN_IFERR(dbs_load_symbol(intf->dbs_tool_handle, "get_correct_page_id",       (void **)(&intf->get_correct_page_id)));
    OG_LOG_RUN_INF("load libdbstor_tool.so done");

    return OG_SUCCESS;
}

void dbs_close_lib(void)
{
    dbs_interface_t *intf = dbs_global_handle();
    if (intf->dbs_handle != NULL) {
        (void)dlclose(intf->dbs_handle);
    }
}

void dbs_tool_close_lib(void)
{
    dbs_tool_interface_t *intf = dbs_tool_global_handle();
    if (intf->dbs_tool_handle != NULL) {
        (void)dlclose(intf->dbs_tool_handle);
    }
}

#ifdef __cplusplus
}
#endif