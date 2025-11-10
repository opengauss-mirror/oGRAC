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

static void srv_dss_write_log(int id, int level, const char *file_name, uint32 line_num, const char *module,
                              const char *format, ...)
{
    char log_buf[OG_MAX_LOG_CONTENT_LENGTH];
    log_id_t log_id = (log_id_t)id;
    log_level_t log_level = (log_level_t)level;
    va_list va_args;
    va_start(va_args, format);

    int32 ret = vsnprintf_s(log_buf, OG_MAX_LOG_CONTENT_LENGTH, OG_MAX_LOG_CONTENT_LENGTH, format, va_args);
    if (ret < 0) {
        va_end(va_args);
        return;
    }
    va_end(va_args);

    cm_dss_write_normal_log(log_id, log_level, file_name, line_num, DSSAPI, OG_TRUE, log_buf);
}

status_t srv_device_init(const char *path)
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

    if (ops.handle != NULL) {
        cm_raw_device_register(&ops);
        ops.raw_set_svr_path(path);
        ops.raw_regist_logger(srv_dss_write_log, cm_log_param_instance()->log_level);
    }

    return OG_SUCCESS;
}