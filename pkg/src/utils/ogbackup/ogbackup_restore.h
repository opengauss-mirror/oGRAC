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
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * ogbackup_restore.h
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_restore.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_RESTORE_H
#define OGRACDB_OGBACKUP_RESTORE_H

#include <getopt.h>
#include "ogbackup_info.h"
#include "ogbackup_scheme_d.h"
#include "cm_defs.h"
#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OGBAK_OFFLINE_MANIFEST_NAME "offline_restore.manifest"
#define OGBAK_OFFLINE_MANIFEST_FALLBACK "manifest"

typedef enum en_ogbak_offline_backup_type {
    OGBAK_RESTORE_BAK_FULL = 0,
    OGBAK_RESTORE_BAK_INCREMENTAL = 1,
    OGBAK_RESTORE_BAK_CUMULATIVE = 2,
} ogbak_offline_backup_type_t;

typedef enum en_ogbak_offline_file_type {
    OGBAK_RESTORE_FILE_CONTROL = 0,
    OGBAK_RESTORE_FILE_DATA = 1,
    OGBAK_RESTORE_FILE_LOG = 2,
    OGBAK_RESTORE_FILE_ARCHIVE = 3,
    OGBAK_RESTORE_FILE_OTHER = 4,
    OGBAK_RESTORE_FILE_SYMLINK = 5,
} ogbak_offline_file_type_t;

typedef struct st_ogbak_offline_backup {
    char id[OG_NAME_BUFFER_SIZE];
    char parent_id[OG_NAME_BUFFER_SIZE];
    char backupset_path[OG_MAX_FILE_PATH_LENGH];
    ogbak_offline_backup_type_t type;
    uint32 level;
    uint32 version_major;
    uint32 version_minor;
    uint32 version_magic;
    uint32 db_id;
    uint32 cluster_id;
    int64 db_init_time;
    uint32 df_struc_version;
    uint32 rst_id;
    char db_name[OG_DB_NAME_LEN];
    char control_files[OG_MAX_CONFIG_LINE_SIZE];
    char db_version[OG_DB_NAME_LEN];
    uint64 start_lsn;
    uint64 end_lsn;
    uint64 checkpoint_lsn;
    uint64 completion_time;
    bool32 from_backupset;
    bool32 encrypted;
    bool32 compressed;
} ogbak_offline_backup_t;

typedef struct st_ogbak_offline_file {
    char backup_id[OG_NAME_BUFFER_SIZE];
    ogbak_offline_file_type_t type;
    char src[OG_MAX_FILE_PATH_LENGH];
    char target[OG_MAX_FILE_PATH_LENGH];
    char original_path[OG_MAX_FILE_PATH_LENGH];
    char owner[OG_NAME_BUFFER_SIZE];
    char group[OG_NAME_BUFFER_SIZE];
    uint64 size;
    uint32 checksum;
    bool32 has_checksum;
    uint32 mode;
    uint32 device_type;
    uint32 page_size;
    bool32 compressed;
    compress_algo_e compress_algo;
    encrypt_algorithm_t encrypt_alg;
    bak_encrypt_t encrypt_info;
    char sys_pwd[OG_PASSWORD_BUFFER_SIZE];
    char gcm_iv[BAK_DEFAULT_GCM_IV_LENGTH];
    char gcm_tag[EVP_GCM_TLS_TAG_LEN];
    bool32 sparse;
    bool32 parallel_stream;
    uint32 node_id;
    uint32 thread_id;
    bool32 from_backupset;
    uint32 file_id;
    uint32 backup_level;
    uint32 sec_id;
    uint32 rst_id;
    uint64 sec_start;
    uint64 sec_end;
    uint32 format_flags;
} ogbak_offline_file_t;

typedef struct st_ogbak_offline_arch_range {
    char backup_id[OG_NAME_BUFFER_SIZE];
    uint32 node_id;
    uint32 rst_id;
    uint32 start_asn;
    uint32 end_asn;
    uint64 start_lsn;
    uint64 end_lsn;
} ogbak_offline_arch_range_t;

typedef struct st_ogbak_offline_manifest {
    uint32 manifest_version;
    bool32 archive_required;
    uint32 backup_count;
    uint32 file_count;
    uint32 arch_count;
    ogbak_offline_backup_t *backups;
    ogbak_offline_file_t *files;
    ogbak_offline_arch_range_t *archs;
} ogbak_offline_manifest_t;

typedef struct st_ogbak_offline_plan {
    uint32 chain_count;
    uint32 file_count;
    ogbak_offline_backup_t **chain;
    ogbak_offline_file_t **files;
    bool32 need_recovery;
    bool32 parallel_pieces;
} ogbak_offline_plan_t;

status_t ogbak_parse_restore_args(int32 argc, char **argv, ogbak_param_t *ogbak_param);
status_t ogbak_do_offline_restore(ogbak_param_t *ogbak_param);
ogbak_cmd_t *ogbak_generate_restore_cmd(void);

status_t ogbak_offline_load_manifest(const char *backup_dir, ogbak_offline_manifest_t *manifest);
void ogbak_offline_free_manifest(ogbak_offline_manifest_t *manifest);
status_t ogbak_offline_build_plan(ogbak_offline_manifest_t *manifest, ogbak_param_t *param,
    ogbak_offline_plan_t *plan);
void ogbak_offline_free_plan(ogbak_offline_plan_t *plan);
uint32 ogbak_offline_calc_file_checksum(const char *path, uint64 *size);

#ifdef CMS_UT_TEST
typedef status_t (*ogbak_scheme_d_provider_check_hook_t)(const ogbak_scheme_d_evidence_t *evidence,
    ogbak_scheme_d_provider_t *provider, char *err_buf, uint32 err_size);
typedef status_t (*ogbak_scheme_d_stat_target_hook_t)(device_type_t type, const char *path, uint64 *size,
    uint64 *written_size);
typedef status_t (*ogbak_scheme_d_init_dss_hook_t)(void);
typedef status_t (*ogbak_scheme_d_preflight_probe_hook_t)(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size);
typedef status_t (*ogbak_restore_execute_files_hook_t)(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size);

void ogbak_restore_set_scheme_d_unit_test_hooks(ogbak_scheme_d_provider_check_hook_t provider_hook,
    ogbak_scheme_d_stat_target_hook_t stat_hook, ogbak_scheme_d_init_dss_hook_t init_dss_hook,
    ogbak_scheme_d_preflight_probe_hook_t preflight_probe_hook, ogbak_restore_execute_files_hook_t execute_hook);
void ogbak_restore_clear_scheme_d_unit_test_hooks(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
