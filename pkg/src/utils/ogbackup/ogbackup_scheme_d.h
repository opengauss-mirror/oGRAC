/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * ogbackup_scheme_d.h
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_scheme_d.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_OGBACKUP_SCHEME_D_H
#define OGRACDB_OGBACKUP_SCHEME_D_H

#include <stdio.h>
#include "cm_defs.h"
#include "cm_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OGBAK_SCHEME_D_MAX_VGS 16
#define OGBAK_SCHEME_D_MAX_WWIDS 16
#define OGBAK_SCHEME_D_HASH_HEX_LEN 64
#define OGBAK_SCHEME_D_PLAN_VERSION 1
#define OGBAK_SCHEME_D_EVIDENCE_SCHEMA_VERSION 1
#define OGBAK_SCHEME_D_MAX_PLAN_RANGES 16384

typedef struct st_ogbak_scheme_d_range {
    char target[OG_MAX_FILE_PATH_LENGH];
    uint32 file_id;
    uint64 start;
    uint64 end;
} ogbak_scheme_d_range_t;

typedef struct st_ogbak_scheme_d_evidence {
    char path[OG_MAX_FILE_PATH_LENGH];
    char hash[OGBAK_SCHEME_D_HASH_HEX_LEN + 1];
    char cluster_id[OG_NAME_BUFFER_SIZE];
    char operator_name[OG_NAME_BUFFER_SIZE];
    char restore_user[OG_NAME_BUFFER_SIZE];
    char expected_dss_home[OG_MAX_FILE_PATH_LENGH];
    char expected_dssserver_exe[OG_MAX_FILE_PATH_LENGH];
    char backupset_path[OG_MAX_FILE_PATH_LENGH];
    char backupset_checksum[OGBAK_SCHEME_D_HASH_HEX_LEN + 1];
    char snapshot_id[OG_NAME_BUFFER_SIZE];
    char rollback_reference[OG_MAX_FILE_PATH_LENGH];
    char environment_class[OG_NAME_BUFFER_SIZE];
    char snapshot_mode[OG_NAME_BUFFER_SIZE];
    char rollback_mode[OG_NAME_BUFFER_SIZE];
    char waiver_reason[OG_MAX_CONFIG_LINE_SIZE];
    char authorized_by[OG_NAME_BUFFER_SIZE];
    char reset_procedure[OG_MAX_CONFIG_LINE_SIZE];
    char vg_names[OGBAK_SCHEME_D_MAX_VGS][OG_NAME_BUFFER_SIZE];
    char target_wwids[OGBAK_SCHEME_D_MAX_WWIDS][OG_NAME_BUFFER_SIZE];
    uint32 vg_count;
    uint32 target_wwid_count;
    uint32 node_count;
    uint64 generated_at;
    uint64 expires_at;
    uint64 snapshot_created_at;
    uint64 authorized_at;
    bool32 disposable_waiver;
} ogbak_scheme_d_evidence_t;

typedef struct st_ogbak_scheme_d_provider {
    bool32 allowed;
    char pid[OG_NAME_BUFFER_SIZE];
    char owner[OG_NAME_BUFFER_SIZE];
    char exe[OG_MAX_FILE_PATH_LENGH];
    char cmdline[OG_MAX_CONFIG_LINE_SIZE];
    char dss_home[OG_MAX_FILE_PATH_LENGH];
    char socket_path[OG_MAX_FILE_PATH_LENGH];
} ogbak_scheme_d_provider_t;

typedef struct st_ogbak_scheme_d_plan {
    FILE *fp;
    char path[OG_MAX_FILE_PATH_LENGH];
    char hash[OGBAK_SCHEME_D_HASH_HEX_LEN + 1];
    char tmp_path[OG_MAX_FILE_PATH_LENGH];
    uint32 entry_count;
    ogbak_scheme_d_range_t ranges[OGBAK_SCHEME_D_MAX_PLAN_RANGES];
    uint32 range_count;
    bool32 has_unsupported;
} ogbak_scheme_d_plan_t;

status_t ogbak_scheme_d_validate_evidence(const char *path, const char *backup_dir, bool32 disposable_waiver_requested,
    ogbak_scheme_d_evidence_t *evidence, char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_verify_backupset_checksum(const char *backup_dir, const char *expected_checksum,
    char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_validate_current_user(const ogbak_scheme_d_evidence_t *evidence,
    char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_check_processes(const ogbak_scheme_d_evidence_t *evidence,
    ogbak_scheme_d_provider_t *provider, char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_check_unsafe_marker(const char *target_dir, char *err_buf, uint32 err_size);

bool32 ogbak_scheme_d_vg_allowed(const ogbak_scheme_d_evidence_t *evidence, const char *dss_path);
const char *ogbak_scheme_d_file_type_name(uint32 type);
status_t ogbak_scheme_d_begin_plan(const char *path, const ogbak_scheme_d_evidence_t *evidence,
    const ogbak_scheme_d_provider_t *provider, ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_append_plan_entry(ogbak_scheme_d_plan_t *plan, const char *target, const char *file_type,
    uint64 offset, uint64 length, uint64 existing_size, uint64 written_size, const char *unsupported_reason,
    char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_append_plan_range(ogbak_scheme_d_plan_t *plan, const char *target, const char *file_type,
    uint32 file_id, uint64 offset, uint64 length, uint64 existing_size, uint64 written_size,
    uint64 required_min_size, uint64 source_offset, const char *payload_source, char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_assert_plan_range(const ogbak_scheme_d_plan_t *plan, const char *target, uint32 file_id,
    uint64 offset, uint64 length, char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_finish_plan(ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size);
void ogbak_scheme_d_abort_plan(ogbak_scheme_d_plan_t *plan);

status_t ogbak_scheme_d_mark_first_write(const char *target_dir, const ogbak_scheme_d_evidence_t *evidence,
    const ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size);
status_t ogbak_scheme_d_mark_complete(const char *target_dir, const ogbak_scheme_d_evidence_t *evidence,
    const ogbak_scheme_d_plan_t *plan, char *err_buf, uint32 err_size);

status_t ogbak_scheme_d_parse_dssserver_cmdline(const char *cmdline, const char *expected_dss_home,
    char *parsed_dss_home, uint32 home_size);
bool32 ogbak_scheme_d_provider_getstatus_ready(const char *output);
status_t ogbak_scheme_d_sha256_file(const char *path, char *hex, uint32 hex_size, char *err_buf, uint32 err_size);

#ifdef __cplusplus
}
#endif

#endif
