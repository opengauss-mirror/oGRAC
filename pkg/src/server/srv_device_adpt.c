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
 * srv_device_adpt.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_device_adpt.c
 *
 * -------------------------------------------------------------------------
 */

#include "srv_device_adpt.h"
#include "cm_device.h"
#include "cm_log.h"
#include "cm_utils.h"

#ifdef WIN32
#define DSSAPI "dssapi.dll"
#else
#define DSSAPISO "libdssapi.so"
#endif

status_t srv_device_init(const char *path, uint32 log_level)
{
    raw_device_op_t ops = { 0 };

    if (cm_open_dl(&ops.handle, DSSAPISO) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fcreate", (void **)&ops.raw_create));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fclose", (void **)&ops.raw_close));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fread", (void **)&ops.raw_read));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fopen", (void **)&ops.raw_open));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fremove", (void **)&ops.raw_remove));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fseek", (void **)&ops.raw_seek));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fwrite", (void **)&ops.raw_write));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_dmake", (void **)&ops.raw_create_dir));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_dopen", (void **)&ops.raw_open_dir));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_dread", (void **)&ops.raw_read_dir));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_dclose", (void **)&ops.raw_close_dir));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_dremove", (void **)&ops.raw_remove_dir));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_frename", (void **)&ops.raw_rename));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_align_size", (void **)&ops.raw_align_size));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fsize_physical", (void **)&ops.raw_fsize_pyhsical));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_get_error", (void **)&ops.raw_get_error));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_pread", (void **)&ops.raw_pread));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_pwrite", (void **)&ops.raw_pwrite));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_ftruncate", (void **)&ops.raw_truncate));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_fallocate", (void **)&ops.raw_fallocate));

    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_set_svr_path", (void **)&ops.raw_set_svr_path));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_register_log_callback", (void **)&ops.raw_regist_logger));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_aio_prep_pread", (void **)&ops.aio_prep_pread));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_aio_prep_pwrite", (void **)&ops.aio_prep_pwrite));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_get_au_size", (void **)&ops.get_au_size));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_stat", (void **)&ops.raw_stat));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_set_log_level", (void **)&ops.set_dss_log_level));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_aio_post_pwrite", (void **)&ops.aio_post_pwrite));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_set_conn_opts", (void **)&ops.dss_set_conn_opts));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_set_default_conn_timeout", (void **)&ops.dss_set_def_conn_timeout));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_init_logger", (void **)&ops.dss_init_logger));
    OG_RETURN_IFERR(cm_load_symbol(ops.handle, "dss_get_time_stat", (void **)&ops.dss_get_time_stat));

    if (ops.handle != NULL) {
        cm_raw_device_register(&ops);
        ops.raw_set_svr_path(path);
        ops.dss_init_logger(cm_log_param_instance()->log_home, log_level,
            cm_log_param_instance()->log_backup_file_count, cm_log_param_instance()->max_log_file_size);
    }

    return OG_SUCCESS;
}