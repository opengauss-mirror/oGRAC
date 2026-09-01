/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_storage_adapter.h
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_storage_adapter.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_BAK_STORAGE_ADAPTER_H
#define OGRACDB_BAK_STORAGE_ADAPTER_H

#include "cm_defs.h"
#include "cm_device.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t bak_offline_join_path(const char *dir, const char *name, char *path, uint32 path_size);
status_t bak_offline_resolve_target_path(const char *target_dir, const char *target, char *path, uint32 path_size);
status_t bak_offline_check_target_dir(const char *target_dir, bool32 force, bool32 dry_run);
status_t bak_offline_check_no_symlink(const char *path, bool32 path_may_not_exist);
status_t bak_offline_write_marker(const char *target_dir, const char *name, const char *content);
status_t bak_offline_copy_file_stream(const char *src, const char *dst);
status_t bak_offline_init_dss_device_from_env(void);
void bak_offline_set_dss_inplace_offline_vg_check(bool32 enabled);
void bak_offline_clear_last_dss_error(void);
const char *bak_offline_get_last_dss_error(void);
status_t bak_offline_validate_dss_device_target(device_type_t type, const char *path);
status_t bak_offline_probe_dss_device_target(device_type_t type, const char *path, uint32 flags);
status_t bak_offline_stat_dss_device_target(device_type_t type, const char *path, uint64 *size,
    uint64 *written_size);
status_t bak_offline_create_device_parent(device_type_t type, const char *path);
status_t bak_offline_open_or_create_device(const char *path, device_type_t type, uint32 flags, int32 *handle);
status_t bak_offline_write_device_stream(const char *src, const char *dst, device_type_t type);
status_t bak_offline_write_device_buffer(const char *dst, device_type_t type, const char *buf, uint64 size);

#ifdef __cplusplus
}
#endif

#endif
