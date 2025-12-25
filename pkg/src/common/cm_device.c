/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
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
 * cm_device.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_device.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_device_module.h"
#include "cm_device.h"
#include "cm_file.h"
#include "cm_malloc.h"
#include "cm_dbstor.h"
#include "cm_dbs_ulog.h"
#include "cm_dbs_pgpool.h"
#include "cm_dbs_file.h"
#include "cm_dbs_map.h"
#include "cm_io_record.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
// interface for register raw device callback function
raw_device_op_t g_raw_device_op;

cm_check_file_error_t g_check_file_error = NULL;

#define OG_THROW_RAW_ERROR                                \
    do {                                                  \
        int32 errcode;                                    \
        const char *errmsg = NULL;                        \
        g_raw_device_op.raw_get_error(&errcode, &errmsg); \
        OG_THROW_ERROR(ERR_DSS_FAILED, errcode, errmsg);  \
    } while (0)

void cm_raw_device_register(raw_device_op_t *device_op)
{
    g_raw_device_op = *device_op;
}

device_type_t cm_device_type(const char *name)
{
    switch (name[0]) {
        case '+':
            return DEV_TYPE_RAW;
        case '-':
            return DEV_TYPE_PGPOOL;
        case '*':
            return DEV_TYPE_ULOG;
        default:
            return DEV_TYPE_FILE;
    }
}

static inline void cm_check_file_error(void)
{
    if (g_check_file_error != NULL) {
        g_check_file_error();
    }
}

status_t cm_access_device(device_type_t type, const char *file_name, uint32 mode)
{
    if (type == DEV_TYPE_FILE) {
        return cm_access_file(file_name, mode);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_stat == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        dss_stat_t item = { 0 };
        if (g_raw_device_op.raw_stat(file_name, &item) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_map_exist(file_name, DEV_TYPE_ULOG) == OG_TRUE ? OG_SUCCESS : OG_ERROR;
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_exist(file_name) == OG_TRUE ? OG_SUCCESS : OG_ERROR;
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
status_t cm_create_device_dir(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_create_dir(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_create_dir == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        return g_raw_device_op.raw_create_dir(name);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        int32 handle = OG_INVALID_HANDLE;
        return cm_dbs_create_dir(name, &handle);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_create_device(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    uint64_t tv_begin;
    status_t ret = OG_SUCCESS;
    uint32 mode = O_BINARY | O_SYNC | O_RDWR | O_EXCL | flags;
    if (type == DEV_TYPE_FILE) {
        if (cm_create_file(name, mode, handle) != OG_SUCCESS) {
            cm_check_file_error();
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_create == NULL || g_raw_device_op.raw_open == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        if (g_raw_device_op.raw_create(name, mode) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (g_raw_device_op.raw_open(name, mode, handle) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_CREATE_ULOG, &tv_begin);
        ret = cm_dbs_ulog_create(name, 0, flags, handle);
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_CREATE_ULOG, &tv_begin);
        return ret;
    } else if (type == DEV_TYPE_PGPOOL) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_CREATE_PG_POOL, &tv_begin);
        ret = cm_dbs_pg_create(name, 0, flags, handle);
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_CREATE_PG_POOL, &tv_begin);
        return ret;
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        ret = cm_dbs_create_file(name, handle);
        return ret;
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

// 当阵列故障时, create可能失败. 现象:create成功但返回eexist
status_t cm_create_device_retry_when_eexist(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    if (cm_create_device(name, type, flags, handle) == OG_SUCCESS) {
        return OG_SUCCESS;
    }
    OG_LOG_RUN_WAR("failed to create device %s the first time, errno %d", name, errno);
    if (errno == EEXIST) {
        if (cm_remove_device(type, name) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("failed to remove device %s, errno %d", name, errno);
            return OG_ERROR;
        }
        if (cm_create_device(name, type, flags, handle) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("failed to create device %s the second time, errno %d", name, errno);
            return OG_ERROR;
        }
        OG_LOG_RUN_WAR("succ to create device %s the second time", name);
        return OG_SUCCESS;
    }
    return OG_ERROR;
}

status_t cm_rename_device(device_type_t type, const char *src, const char *dst)
{
    if (type == DEV_TYPE_FILE) {
        return cm_rename_file(src, dst);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_rename == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }
        return g_raw_device_op.raw_rename(src, dst);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_rename(src, dst);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        return cm_dbs_rename_file(src, dst);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }
}

// 当阵列故障时, rename可能失败. 现象:rename成功但返回enoent
status_t cm_rename_device_when_enoent(device_type_t type, const char *src, const char *dst)
{
    if (cm_rename_device(type, src, dst) == OG_SUCCESS) {
        return OG_SUCCESS;
    }
    if (errno == ENOENT) {
        if (cm_exist_device(type, dst)) {
            OG_LOG_RUN_WAR(" file %s is exist, errno %d", src, errno);
            return OG_SUCCESS;
        }
    }
    OG_LOG_RUN_ERR("failed to rename file %s to %s, errno %d", src, dst, errno);
    return OG_ERROR;
}

status_t cm_remove_device(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_remove_file(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_remove == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        return g_raw_device_op.raw_remove(name);
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_destroy(name);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_destroy(name);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        return cm_dbs_remove_file(name);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }
}

// 当阵列故障时, remove可能失败. 现象:remove成功但返回enoent
status_t cm_remove_device_when_enoent(device_type_t type, const char *name)
{
    if (cm_remove_device(type, name) == OG_SUCCESS) {
        return OG_SUCCESS;
    }
    if (errno == ENOENT) {
        OG_LOG_RUN_WAR("device %s is not exist, errno %d", name, errno);
        return OG_SUCCESS;
    }
    OG_LOG_RUN_ERR("failed to remove device %s, errno %d", name, errno);
    return OG_ERROR;
}

static status_t cm_open_device_common(const char *name, device_type_t type, uint32 flags, int32 *handle, uint8 is_retry)
{
    uint64_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (*handle != -1) {
            // device already opened, nothing to do.
            return OG_SUCCESS;
        }

        uint32 mode = O_BINARY | O_RDWR | flags;

        if (cm_open_file(name, mode, handle) != OG_SUCCESS) {
            cm_check_file_error();
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (*handle != -1) {
            // device already opened, nothing to do.
            return OG_SUCCESS;
        }
        if (g_raw_device_op.raw_open == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }
        return g_raw_device_op.raw_open(name, O_BINARY | O_RDWR | flags, handle);
    } else if (type == DEV_TYPE_ULOG) {
        if (*handle != -1) {
            return OG_SUCCESS;
        }
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_OPEN_ULOG, &tv_begin);
        if (cm_dbs_ulog_open(name, handle, is_retry) == OG_ERROR) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_ULOG, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_ULOG, &tv_begin);
    } else if (type == DEV_TYPE_PGPOOL) {
        if (*handle != -1) {
            return OG_SUCCESS;
        }
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_OPEN_PG_POOL, &tv_begin);
        if (cm_dbs_pg_open(name, handle) == OG_ERROR) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_PG_POOL, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_OPEN_PG_POOL, &tv_begin);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        if (*handle != -1) {
            return OG_SUCCESS;
        }
        if (cm_dbs_open_file(name, handle) == OG_ERROR) {
            return OG_ERROR;
        }
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_open_device(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    return cm_open_device_common(name, type, flags, handle, OG_TRUE);
}

status_t cm_open_device_no_retry(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    return cm_open_device_common(name, type, flags, handle, OG_FALSE);
}

void cm_close_device(device_type_t type, int32 *handle)
{
    uint64_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        cm_close_file(*handle);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_close != NULL) {
            g_raw_device_op.raw_close(*handle);
        }
    } else if (type == DEV_TYPE_ULOG) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_CLOSE_ULOG, &tv_begin);
        cm_dbs_ulog_close(*handle);
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_CLOSE_ULOG, &tv_begin);
    } else if (type == DEV_TYPE_PGPOOL) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_CLOSE_PG_POOL, &tv_begin);
        cm_dbs_pg_close(*handle);
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_CLOSE_PG_POOL, &tv_begin);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        cm_dbs_close_file(*handle);
    }
    *handle = -1;  // reset handle
}

static inline bool32 cm_is_aligned_ptr(const void *ptr, uint32 align_size)
{
    return (((uintptr_t)ptr & (uintptr_t)(align_size - 1)) == 0);
}

static inline bool32 cm_is_aligned_val(uint64 val, uint32 align_size)
{
    return ((val & (uint64)(align_size - 1)) == 0);
}


static status_t cm_raw_read_file(int32 handle, int64 offset, void *buf, int32 size, int32 *return_size)
{
    if (g_raw_device_op.raw_pread == NULL) {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[CM_DEVICE] Begin to read file handle %d offset %lld size %d.", handle, offset, size);
    if (!cm_is_aligned_val((uint64)offset, FILE_BLOCK_SIZE) ||
        !cm_is_aligned_val((uint64)size, FILE_BLOCK_SIZE) ||
        !cm_is_aligned_ptr(buf, FILE_BLOCK_SIZE)) {
        OG_LOG_RUN_ERR("[CM_DEVICE] read requires %dB alignment: offset=%lld size=%d buff_ptr=%p",
                       FILE_BLOCK_SIZE, (long long)offset, size, buf);
        return OG_ERROR;
    }

    if (g_raw_device_op.raw_pread(handle, buf, size, offset, return_size) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[CM_DEVICE] Failed to read file total_size: %d already read size: %d.", size, *return_size);
        return OG_ERROR;
    }
    OG_LOG_DEBUG_INF("[CM_DEVICE] Success to read file total_size: %d already read size: %d.", size, *return_size);
    return OG_SUCCESS;
}

status_t cm_read_device(device_type_t type, int32 handle, int64 offset, void *buf, int32 size)
{
    int32 read_size;
    uint64_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (cm_pread_file(handle, buf, size, offset, &read_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (cm_raw_read_file(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_READ_ULOG, &tv_begin);
        if (cm_dbs_ulog_read(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_ULOG, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_ULOG, &tv_begin);
    } else if (type == DEV_TYPE_PGPOOL) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_READ_PG_POOL, &tv_begin);
        if (cm_dbs_pg_read(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_PG_POOL, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_PG_POOL, &tv_begin);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_READ_DBSTOR_FILE, &tv_begin);
        if (cm_dbs_read_file(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_DBSTOR_FILE, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_DBSTOR_FILE, &tv_begin);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    if (type != DEV_TYPE_ULOG && read_size != size) {
        OG_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_read_device_nocheck(device_type_t type, int32 handle, int64 offset, void *buf, int32 size,
                                int32 *return_size)
{
    int32 read_size;
    uint64_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (cm_pread_file(handle, buf, size, offset, &read_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL || g_raw_device_op.raw_read == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        if (g_raw_device_op.raw_seek(handle, offset, SEEK_SET) != offset) {
            OG_LOG_RUN_ERR("[cm_read_device] raw_seek handle %d offset %lld size %d.", handle, offset, size);
            return OG_ERROR;
        }
        if (g_raw_device_op.raw_read(handle, buf, size, &read_size) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[cm_read_device] raw_read handle %d offset %lld size %d.", handle, offset, size);
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        if (cm_dbs_ulog_read(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_PGPOOL) {
        if (cm_dbs_pg_read(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_READ_NOCHECK_DBSTOR_FILE, &tv_begin);
        if (cm_dbs_read_file(handle, offset, buf, size, &read_size) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_NOCHECK_DBSTOR_FILE, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_READ_NOCHECK_DBSTOR_FILE, &tv_begin);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    if (return_size != NULL) {
        *return_size = read_size;
        return OG_SUCCESS;
    }
    if (type != DEV_TYPE_ULOG && read_size != size) {
        OG_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_device_read_batch(device_type_t type, int32 handle, uint64 startLsn, uint64 endLsn, void *buf, int32 size,
                              int32 *r_size, uint64 *outLsn)
{
    if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_batch_read(handle, startLsn, endLsn, buf, size, r_size, outLsn);
    }
    OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return OG_ERROR;
}

static status_t cm_device_get_used_cap_common(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb,
                                       uint8 is_retry)
{
    if (type == DEV_TYPE_ULOG) {
        return cm_dbs_get_used_cap(handle, startLsn, sizeKb, is_retry);
    }
    OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return OG_ERROR;
}

status_t cm_device_get_used_cap(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb)
{
    return cm_device_get_used_cap_common(type, handle, startLsn, sizeKb, OG_TRUE);
}

status_t cm_device_get_used_cap_no_retry(device_type_t type, int32 handle, uint64_t startLsn, uint32_t *sizeKb)
{
    return cm_device_get_used_cap_common(type, handle, startLsn, sizeKb, OG_FALSE);
}

status_t cm_device_capacity(device_type_t type, int64 *capacity)
{
    if (capacity == NULL) {
        OG_LOG_RUN_ERR("The input capacity addr is NULL pointer.");
        return OG_ERROR;
    }
    if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_capacity(capacity);
    }
    OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return OG_ERROR;
}

status_t cm_write_device(device_type_t type, int32 handle, int64 offset, const void *buf, int32 size)
{
    uint64_t tv_begin;
    if (type == DEV_TYPE_FILE) {
        if (cm_pwrite_file(handle, buf, size, offset) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_pwrite == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        if (g_raw_device_op.raw_pwrite(handle, buf, size, offset) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_ULOG) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_WRITE_ULOG, &tv_begin);
        if (cm_dbs_ulog_write(handle, offset, buf, size, NULL) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_ULOG, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_ULOG, &tv_begin);
    } else if (type == DEV_TYPE_PGPOOL) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_WRITE_PG_POOL, &tv_begin);
        if (cm_dbs_pg_write(handle, offset, buf, size) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_PG_POOL, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_PG_POOL, &tv_begin);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_WRITE_DBSTOR_FILE, &tv_begin);
        if (cm_dbs_write_file(handle, offset, buf, size) != OG_SUCCESS) {
            oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_DBSTOR_FILE, &tv_begin);
            return OG_ERROR;
        }
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_WRITE_DBSTOR_FILE, &tv_begin);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t cm_query_raw_file_num(const char *name, uint32 *file_num)
{
    raw_dir_handle dss_dir_handle = g_raw_device_op.raw_open_dir(name);
    if (dss_dir_handle == NULL) {
        OG_LOG_RUN_ERR("Failed to open raw dir: %s.", name);
        return OG_ERROR;
    }

    uint32 num = 0;
    raw_dirent_t raw_dirent;
    raw_dir_item_t raw_item;
    while (OG_TRUE) {
        if (g_raw_device_op.raw_read_dir(dss_dir_handle, &raw_dirent, &raw_item) != OG_SUCCESS) {
            (void)g_raw_device_op.raw_close_dir(dss_dir_handle);
            OG_LOG_RUN_ERR("Failed to read raw dir: %s.", name);
            return OG_ERROR;
        }

        if (raw_item == NULL) {
            break;
        }

        num++;
    }
    if (g_raw_device_op.raw_close_dir(dss_dir_handle) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to close raw dir: %s.", name);
            return OG_ERROR;
    }
    *file_num = num;
    return OG_SUCCESS;
}

static status_t cm_query_file_num_device(device_type_t type, const char *name, uint32 *file_num)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_query_file_num(name, file_num) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("query file num failed, path %s.", name);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (type == DEV_TYPE_DBSTOR_FILE) {
        if (cm_dbs_query_file_num(name, file_num) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("query DBSTOR file num failed, path %s.", name);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (type == DEV_TYPE_RAW) {
        if (cm_query_raw_file_num(name, file_num) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("query raw file num failed, path %s.", name);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    
    OG_LOG_RUN_ERR("query file num failed, error device type, path %s", name);
    return OG_ERROR;
}

static status_t cm_query_raw_dir(const char *name, void *file_list, uint32 *file_num)
{
    raw_dir_handle dss_dir_handle = g_raw_device_op.raw_open_dir(name);
    if (dss_dir_handle == NULL) {
        OG_LOG_RUN_ERR("Failed to open raw dir: %s.", name);
        return OG_ERROR;
    }

    uint32 num = 0;
    raw_dir_item_t raw_item;
    raw_dirent_t *list = (raw_dirent_t *)file_list;
    while (OG_TRUE) {
        if (g_raw_device_op.raw_read_dir(dss_dir_handle, &list[num], &raw_item) != OG_SUCCESS) {
            (void)g_raw_device_op.raw_close_dir(dss_dir_handle);
            OG_LOG_RUN_ERR("Failed to read raw dir: %s.", name);
            return OG_ERROR;
        }

        if (raw_item == NULL) {
            break;
        }
        num++;
    }
    if (g_raw_device_op.raw_close_dir(dss_dir_handle) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to close raw dir: %s.", name);
            return OG_ERROR;
    }
    *file_num = num;
    return OG_SUCCESS;
}

status_t cm_query_device(device_type_t type, const char *name, void *file_list, uint32 *file_num)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_query_dir(name, file_list, file_num) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        if (cm_dbs_query_dir(name, file_list, file_num) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (cm_query_raw_dir(name, file_list, file_num) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        OG_LOG_RUN_ERR("query file num failed, error device type, path %s", name);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_get_size_device(device_type_t type, int32 handle, int64 *file_size)
{
    if (type == DEV_TYPE_FILE) {
        *file_size = cm_seek_file(handle, 0, SEEK_END);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        if (cm_dbs_get_file_size(handle, file_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL) {
            return OG_ERROR;
        }
        *file_size = g_raw_device_op.raw_seek(handle, 0, SEEK_END);
    } else {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

int64 cm_seek_device(device_type_t type, int32 handle, int64 offset, int32 origin)
{
    if (type == DEV_TYPE_FILE) {
        return cm_seek_file(handle, offset, origin);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_seek == NULL) {
            return (int64)0;
        }

        return g_raw_device_op.raw_seek(handle, offset, origin);
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_seek(handle, offset, origin);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_seek(handle, offset, origin);
    } else {
        return (int64)0;
    }
}

bool32 cm_exist_device_dir(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_dir_exist(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_stat == NULL) {
            return OG_FALSE;
        }

        dss_stat_t item = { 0 };
        if (g_raw_device_op.raw_stat(name, &item) != OG_SUCCESS) {
            return OG_FALSE;
        }
        return OG_TRUE;
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        return cm_dbs_exist_file(name, DIR_TYPE);
    } else {
        return OG_FALSE;
    }
}

static status_t cm_create_device_dir_ex2(const char *dir_name)
{
    char dir[OG_MAX_FILE_NAME_LEN + 1];
    size_t dir_len = strlen(dir_name);
    uint32 i;

    errno_t errcode = strncpy_s(dir, (size_t)OG_MAX_FILE_NAME_LEN, dir_name, (size_t)dir_len);
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return OG_ERROR;
    }
    if (dir[dir_len - 1] != '\\' && dir[dir_len - 1] != '/') {
        dir[dir_len] = '/';
        dir_len++;
        dir[dir_len] = '\0';
    }

    for (i = 0; i < dir_len; i++) {
        if (dir[i] == '\\' || dir[i] == '/') {
            if (i == 0) {
                continue;
            }

            dir[i] = '\0';
            if (cm_exist_device_dir(DEV_TYPE_RAW, dir)) {
                dir[i] = '/';
                continue;
            }

            if (cm_create_device_dir(DEV_TYPE_RAW, dir) != OG_SUCCESS) {
                return OG_ERROR;
            }
            dir[i] = '/';
        }
    }

    return OG_SUCCESS;
}

bool32 cm_create_device_dir_ex(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_create_dir_ex(name);
    } else if (type == DEV_TYPE_RAW) {
        return cm_create_device_dir_ex2(name);
    } else {
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

DIR *cm_open_device_dir(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return opendir(name);
    }

    if (type == DEV_TYPE_RAW) {
        raw_dir_handle *dss_dir_handle = (raw_dir_handle*)cm_malloc(sizeof(raw_dir_handle));
        if (dss_dir_handle == NULL) {
            OG_LOG_RUN_ERR("malloc dss dir handle failed");
            return NULL;
        }
        if (g_raw_device_op.raw_open_dir == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return NULL;
        }
        *dss_dir_handle = g_raw_device_op.raw_open_dir(name);
        return (DIR*)dss_dir_handle;
    }
    OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return NULL;
}

int cm_close_device_dir(device_type_t type, DIR *dir_handle)
{
    if (type == DEV_TYPE_RAW) {
        raw_dir_handle *dss_dir_handle = (raw_dir_handle *)dir_handle;
        int result = g_raw_device_op.raw_close_dir(*dss_dir_handle);
        free(dss_dir_handle);
        return result;
    }

    return closedir(dir_handle);
}

status_t cm_read_device_dir(device_type_t type, DIR *dirp, struct dirent *result)
{
    if (dirp == NULL) {
        OG_LOG_RUN_ERR("The handle of dir to read is NULL.");
        return OG_ERROR;
    }

    if (type == DEV_TYPE_RAW) {
        raw_dir_handle *dss_dir_handle = (raw_dir_handle *)dirp;
        raw_dirent_t raw_dirent;
        raw_dir_item_t raw_item;
        if (g_raw_device_op.raw_read_dir(*dss_dir_handle, &raw_dirent, &raw_item) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("read dir by dss failed.");
            return OG_ERROR;
        }

        if (raw_dirent.d_type != DSS_PATH && raw_dirent.d_type != DSS_FILE && raw_dirent.d_type != DSS_LINK) {
            OG_LOG_RUN_ERR("Invalide file type %u", raw_dirent.d_type);
            return OG_ERROR;
        }
        
        result->d_type = raw_dirent.d_type;
        errno_t ret = strcpy_sp(result->d_name, DSS_MAX_NAME_LEN, raw_dirent.d_name);
        if (ret != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to copy d_name");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    
    result = readdir(dirp);
    if (result == NULL) {
        OG_LOG_RUN_ERR("exec readdir failed.");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

bool32 cm_exist_device(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_file_exist(name);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_stat == NULL) {
            return OG_FALSE;
        }

        dss_stat_t item = { 0 };
        if (g_raw_device_op.raw_stat(name, &item) != OG_SUCCESS) {
            return OG_FALSE;
        }
        return OG_TRUE;
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_map_exist(name, DEV_TYPE_ULOG);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_exist(name);
    } else if (type == DEV_TYPE_DBSTOR_FILE) {
        return cm_dbs_exist_file(name, FILE_TYPE);
    } else {
        return OG_FALSE;
    }
}

// prealloc file by fallocate
static status_t cm_prealloc_device(device_type_t type, int32 handle, int64 offset, int64 size)
{
    if (type == DEV_TYPE_FILE) {
        return cm_fallocate_file(handle, 0, offset, size);
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_fallocate == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        return g_raw_device_op.raw_fallocate(handle, 0, offset, size);
    } else if (type == DEV_TYPE_ULOG || type == DEV_TYPE_PGPOOL) {
        // dbstor support preallocate internally.
        return OG_SUCCESS;
    } else {
        OG_LOG_RUN_ERR("Unsupported operation(truncate) for device(%u).", type);
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }
}

static status_t cm_write_device_by_zero(int32 handle, device_type_t type, char *buf,
                                        uint32 buf_size, int64 offset, int64 size)
{
    int64 offset_tmp = offset;
    if (type == DEV_TYPE_PGPOOL || type == DEV_TYPE_ULOG) {
        return OG_SUCCESS;
    }
    errno_t err = memset_sp(buf, (size_t)buf_size, 0, (size_t)buf_size);
    if (err != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return OG_ERROR;
    }

    int64 remain_size = size;
    int32 curr_size;
    while (remain_size > 0) {
        curr_size = (remain_size > buf_size) ? (int32)buf_size : (int32)remain_size;
        if (cm_write_device(type, handle, offset_tmp, buf, curr_size) != OG_SUCCESS) {
            return OG_ERROR;
        }

        offset_tmp += curr_size;
        remain_size -= curr_size;
    }

    return OG_SUCCESS;
}

status_t cm_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size, bool32 prealloc)
{
    int64 offset = cm_device_size(type, handle);
    if (offset == -1) {
        OG_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return OG_ERROR;
    }
    if (type == DEV_TYPE_PGPOOL) {
        uint64_t tv_begin;
        oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_EXTENT_PG_POOL, &tv_begin);
        status_t ret = cm_dbs_pg_extend(handle, offset, size);
        oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_EXTENT_PG_POOL, &tv_begin);
        return ret;
    }
    if (prealloc) {
        // use falloc to fast build device
        return cm_prealloc_device(type, handle, offset, size);
    }

    return cm_write_device_by_zero(handle, type, buf, buf_size, offset, size);
}

status_t cm_try_prealloc_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
                                       bool32 prealloc)
{
    int64 offset = cm_device_size(type, handle);
    if (offset == -1) {
        OG_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return OG_ERROR;
    }

    if (prealloc) {
        // use falloc to fast build device
        if (cm_prealloc_device(type, handle, offset, size) == OG_SUCCESS) {
            return OG_SUCCESS;
        }

        // if there is no space lefe on disk, return error
        if (errno == ENOSPC) {
            return OG_ERROR;
        }
        cm_reset_error();
        OG_LOG_RUN_WAR("extent device by prealloc failed error code %u, will try extent device by write 0", errno);
    }

    return cm_write_device_by_zero(handle, type, buf, buf_size, offset, size);
}

status_t cm_truncate_device(device_type_t type, int32 handle, int64 keep_size)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_truncate_file(handle, keep_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_truncate == NULL) {
            OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
            return OG_ERROR;
        }

        return g_raw_device_op.raw_truncate(handle, keep_size);
    } else if (type == DEV_TYPE_PGPOOL) {
        return cm_dbs_pg_truncate(handle, keep_size);
    } else {
        OG_LOG_RUN_ERR("Unsupported operation(truncate) for device(%u).", type);
        OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

int32 cm_align_device_size(device_type_t type, int32 size)
{
    if (type == DEV_TYPE_RAW) {
        if (g_raw_device_op.raw_align_size == NULL) {
            return size;
        }

        return g_raw_device_op.raw_align_size(size);
    } else if (type == DEV_TYPE_ULOG) {
        return cm_dbs_ulog_align_size(size);
    } else {
        return size;
    }
}

bool32 cm_check_device_offset_valid(device_type_t type, int32 handle, int64 offset)
{
    if (type == DEV_TYPE_ULOG) {
        if (offset <= 0) {
            OG_LOG_RUN_ERR("Invalid offset(%lld).", offset);
            return OG_FALSE;
        }
        return cm_dbs_ulog_is_lsn_valid(handle, (uint64)offset);
    }
    OG_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
    return OG_FALSE;
}

status_t cm_build_device(const char *name, device_type_t type, char *buf, uint32 buf_size, int64 size, uint32 flags,
                         bool32 prealloc, int32 *handle)
{
    *handle = -1;
    if (type == DEV_TYPE_PGPOOL) {
        status_t ret = cm_dbs_pg_create(name, size, flags, handle);
        cm_close_device(type, handle);
        return ret;
    }
    if (cm_create_device(name, type, flags, handle) != OG_SUCCESS) {
        cm_close_device(type, handle);
        return OG_ERROR;
    }
    status_t status;
    if (prealloc) {
        status = cm_prealloc_device(type, *handle, 0, size);
    } else {
        status = cm_write_device_by_zero(*handle, type, buf, buf_size, 0, size);
    }

    if (status != OG_SUCCESS) {
        cm_close_device(type, handle);
        return OG_ERROR;
    }

    if (type == DEV_TYPE_FILE) {
        if (cm_fsync_file(*handle) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("failed to fsync datafile %s", name);
            cm_close_device(type, handle);
            return OG_ERROR;
        }
    }

    cm_close_device(type, handle);
    return OG_SUCCESS;
}

status_t cm_aio_setup(cm_aio_lib_t *lib_ctx, int maxevents, cm_io_context_t *io_ctx)
{
    int32 aio_ret;

    aio_ret = lib_ctx->io_setup(maxevents, io_ctx);
    if (aio_ret < 0) {
        OG_LOG_RUN_ERR("failed to io_setup by async io: aio_ret: %d, error code: %d", aio_ret, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_aio_destroy(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx)
{
    if (lib_ctx->io_destroy(io_ctx) < 0) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_aio_getevents(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long min_nr, long nr, cm_io_event_t *events,
                          int32 *aio_ret)
{
    struct timespec timeout = { 0, 200 };
    *aio_ret = lib_ctx->io_getevents(io_ctx, min_nr, nr, events, &timeout);
    if (*aio_ret < 0) {
        if (*aio_ret != -EINTR) {
            OG_LOG_RUN_ERR("failed to io_getevents by async io: error code: %d, aio_ret: %d", errno, *aio_ret);
        }
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_aio_submit(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long nr, cm_iocb_t *ios[])
{
    if (lib_ctx->io_submit(io_ctx, nr, ios) != nr) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void cm_aio_prep_read(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
#ifndef WIN32
    io_prep_pread(iocb, fd, buf, count, offset);
#endif
}

void cm_aio_prep_write(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
#ifndef WIN32
    io_prep_pwrite(iocb, fd, buf, count, offset);
#endif
}

void cm_aio_set_callback(cm_iocb_t *iocb, cm_io_callback_t cb)
{
#ifndef WIN32
    io_set_callback(iocb, cb);
#endif
}

status_t cm_aio_prep_write_by_part(int32 handle, int64 offset, void *buf, int32 size, int32 part_id)
{
    uint64_t tv_begin;
    oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_PUT_PAGE, &tv_begin);

    status_t ret = cm_dbs_pg_asyn_write(handle, offset, buf, size, part_id);
    oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_PUT_PAGE, &tv_begin);
    return ret;
}

status_t cm_sync_device_by_part(int32 handle, int32 part_id)
{
    uint64_t tv_begin;
    oGRAC_record_io_stat_begin(IO_RECORD_EVENT_NS_SYNC_PAGE, &tv_begin);

    status_t ret = cm_dbs_sync_page(handle, part_id);
    oGRAC_record_io_stat_end(IO_RECORD_EVENT_NS_SYNC_PAGE, &tv_begin);
    return ret;
}

status_t cm_cal_partid_by_pageid(uint64 page_id, uint32 page_size, uint32 *part_id)
{
    return cm_dbs_pg_cal_part_id(page_id, page_size, part_id);
}

void cm_free_file_list(void **file_list)
{
    if (*file_list != NULL) {
        free(*file_list);
    }
    *file_list = NULL;
}

status_t cm_malloc_file_list(device_type_t type, void **file_list, const char *file_path, uint32 *file_num)
{
    if (cm_query_file_num_device(type, file_path, file_num) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("query file num failed, device type %u, file_path %s", type, file_path);
        return OG_ERROR;
    }
    if (*file_num > DBS_DIR_MAX_FILE_NUM) {
        OG_LOG_RUN_ERR("dbstor malloc file list array size %u exceeds max size %u", *file_num, DBS_DIR_MAX_FILE_NUM);
        return OG_ERROR;
    }
    if (*file_num < DBS_DIR_DEFAULT_FILE_NUM) {
        *file_num = DBS_DIR_DEFAULT_FILE_NUM;
    }

    if (type == DEV_TYPE_DBSTOR_FILE) {
        *file_list = cm_malloc((*file_num) * sizeof(dbstor_file_info));
        if (*file_list == NULL) {
            OG_LOG_RUN_ERR("malloc dbstor arch file list array failed");
            return OG_ERROR;
        }
        errno_t mem_ret = memset_sp(*file_list, sizeof(dbstor_file_info) * (*file_num), 0,
                                    sizeof(dbstor_file_info) * (*file_num));
        if (mem_ret != EOK) {
            OG_LOG_RUN_ERR("memset dbstor arch file list array failed");
            cm_free_file_list(file_list);
            return OG_ERROR;
        }
    } else if (type == DEV_TYPE_FILE || type == DEV_TYPE_RAW) {
        *file_list = cm_malloc((*file_num) * sizeof(cm_file_info));
        if (*file_list == NULL) {
            OG_LOG_RUN_ERR("malloc arch file list array failed");
            return OG_ERROR;
        }
        errno_t mem_ret = memset_sp(*file_list, sizeof(cm_file_info) * (*file_num), 0,
                                    sizeof(cm_file_info) * (*file_num));
        if (mem_ret != EOK) {
            OG_LOG_RUN_ERR("memset arch file list array failed");
            cm_free_file_list(file_list);
            return OG_ERROR;
        }
    } else {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cm_malloc_file_list_by_version_id(file_info_version_t version, uint32 vstore_id, void **file_list,
                                           const char *file_path, uint32 *file_num)
{
    if (cm_dbs_query_file_num_by_vstore_id(file_path, file_num, vstore_id) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("dbstor query file num failed, file_path %s", file_path);
        return OG_ERROR;
    }
    if (*file_num > DBS_DIR_MAX_FILE_NUM) {
        OG_LOG_RUN_ERR("dbstor malloc file list array size %u exceeds max size %u", *file_num, DBS_DIR_MAX_FILE_NUM);
        return OG_ERROR;
    }
    if (*file_num < DBS_DIR_DEFAULT_FILE_NUM) {
        *file_num = DBS_DIR_DEFAULT_FILE_NUM;
    }

    if (version == DBS_FILE_INFO_VERSION_1) {
        *file_list = cm_malloc((*file_num) * sizeof(dbstor_file_info));
        if (*file_list == NULL) {
            OG_LOG_RUN_ERR("malloc dbstor arch file list array failed");
            return OG_ERROR;
        }
        errno_t mem_ret = memset_sp(*file_list, sizeof(dbstor_file_info) * (*file_num), 0,
                                    sizeof(dbstor_file_info) * (*file_num));
        if (mem_ret != EOK) {
            OG_LOG_RUN_ERR("memset dbstor arch file list array failed");
            cm_free_file_list(file_list);
            return OG_ERROR;
        }
    } else if (version == DBS_FILE_INFO_VERSION_2) {
        *file_list = cm_malloc((*file_num) * sizeof(dbstor_file_info_detail));
        if (*file_list == NULL) {
            OG_LOG_RUN_ERR("malloc dbstor arch file list array failed");
            return OG_ERROR;
        }
        errno_t mem_ret = memset_sp(*file_list, sizeof(dbstor_file_info_detail) * (*file_num), 0,
                                    sizeof(dbstor_file_info_detail) * (*file_num));
        if (mem_ret != EOK) {
            OG_LOG_RUN_ERR("memset dbstor arch file list array failed");
            cm_free_file_list(file_list);
            return OG_ERROR;
        }
    } else {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

char *cm_get_name_from_file_list(device_type_t type, void *list, int32 index)
{
    if (type == DEV_TYPE_DBSTOR_FILE) {
        dbstor_file_info *file_list = (dbstor_file_info *)((char *)list + index * sizeof(dbstor_file_info));
        return file_list->file_name;
    }
    if (type == DEV_TYPE_FILE) {
        cm_file_info *file_list = (cm_file_info *)((char *)list + index * sizeof(cm_file_info));
        return file_list->file_name;
    }
    if (type == DEV_TYPE_RAW) {
        raw_dirent_t *file_list = (raw_dirent_t *)((char *)list + index * sizeof(raw_dirent_t));
        return file_list->d_name;
    }
    return NULL;
}

bool32 cm_check_dir_type_by_file_list(device_type_t type, void *list, int32 index)
{
    if (type == DEV_TYPE_DBSTOR_FILE) {
        dbstor_file_info *file_list = (dbstor_file_info *)((char *)list + index * sizeof(dbstor_file_info));
        return file_list->type == CS_FILE_TYPE_DIR;
    } else if (type == DEV_TYPE_FILE) {
        cm_file_info *file_list = (cm_file_info *)((char *)list + index * sizeof(cm_file_info));
        return file_list->type == FILE_TYPE_DIR;
    }
    return OG_FALSE;
}

bool32 cm_match_arch_pattern(const char *filename)
{
    const char *prefix = "arch";
    const char *suffix = ".arc";
    size_t filename_len = strlen(filename);
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    if (filename_len < prefix_len + suffix_len) {
        return OG_FALSE;
    }
    if (strncmp(filename, prefix, prefix_len) == 0 && strcmp(filename + filename_len - suffix_len, suffix) == 0) {
        return OG_TRUE;  // Match
    }
    return OG_FALSE;
}

int cm_aio_dss_prep_read(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
    if (SECUREC_UNLIKELY(g_raw_device_op.aio_prep_pread == NULL)) {
        OG_LOG_RUN_ERR("File aio_prep_pread function is not defined.");
        return OG_ERROR;
    }

    if (g_raw_device_op.aio_prep_pread(iocb, fd, buf, count, offset) != OG_SUCCESS) {
        OG_THROW_RAW_ERROR;
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

int cm_aio_dss_prep_write(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
    if (SECUREC_UNLIKELY(g_raw_device_op.aio_prep_pwrite == NULL)) {
        OG_LOG_RUN_ERR("File aio_prep_pread function is not defined.");
        return OG_ERROR;
    }

    if (g_raw_device_op.aio_prep_pwrite(iocb, fd, buf, count, offset) != OG_SUCCESS) {
        OG_THROW_RAW_ERROR;
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

int cm_aio_dss_post_write(cm_iocb_t *iocb, int fd, size_t count, long long offset)
{
    if (SECUREC_UNLIKELY(g_raw_device_op.aio_post_pwrite == NULL)) {
        OG_LOG_RUN_ERR("File aio_prep_pwrite function is not defined.");
        return OG_ERROR;
    }

    int ret = g_raw_device_op.aio_post_pwrite(iocb, fd, count, offset);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("File aio_pre_pwrite execute failed, ret: %d.", ret);
        OG_THROW_RAW_ERROR;
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t cm_fdatasync_device(device_type_t type, int32 handle)
{
    if (type == DEV_TYPE_FILE) {
        return cm_fdatasync_file(handle);
    } else if (type == DEV_TYPE_RAW) {
        // dss default flag has O_SYNC | O_DIRECT
        return OG_SUCCESS;
    } else {
        OG_LOG_RUN_ERR("File cm_fdatasync_device type %d is not supported.", type);
        return OG_ERROR;
    }
}

status_t cm_fsync_device(device_type_t type, int32 handle)
{
    if (type == DEV_TYPE_FILE) {
        return cm_fsync_file(handle);
    } else if (type == DEV_TYPE_RAW) {
        // dss default flag has O_SYNC | O_DIRECT
        return OG_SUCCESS;
    } else {
        OG_LOG_RUN_ERR("File cm_fdatasync_device type %d is not supported.", type);
        return OG_ERROR;
    }
}

#ifdef __cplusplus
}
#endif
