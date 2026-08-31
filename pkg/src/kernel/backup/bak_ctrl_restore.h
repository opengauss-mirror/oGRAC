/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_ctrl_restore.h
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_ctrl_restore.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_BAK_CTRL_RESTORE_H
#define OGRACDB_BAK_CTRL_RESTORE_H

#include "cm_defs.h"
#include "cm_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAK_OFFLINE_CTRL_FILE_COUNT 3

typedef enum en_bak_offline_ctrl_path_type {
    BAK_OFFLINE_CTRL_PATH_DATAFILE = 0,
    BAK_OFFLINE_CTRL_PATH_LOGFILE = 1,
    BAK_OFFLINE_CTRL_PATH_ARCHIVE = 2,
} bak_offline_ctrl_path_type_t;

typedef enum en_bak_offline_restore_storage_mode {
    BAK_OFFLINE_RESTORE_STORAGE_LOCAL = 0,
    BAK_OFFLINE_RESTORE_STORAGE_DSS = 1,
} bak_offline_restore_storage_mode_t;

typedef struct st_bak_offline_ctrl_path_map_item {
    bak_offline_ctrl_path_type_t type;
    uint32 file_id;
    uint32 node_id;
    uint32 rst_id;
    char original_path[OG_FILE_NAME_BUFFER_SIZE];
    char target_path[OG_FILE_NAME_BUFFER_SIZE];
    char source_path[OG_MAX_FILE_PATH_LENGH];
    uint64 source_size;
    bool32 source_temp;
    uint64 target_size;
    uint32 ctrl_page_id;
    uint32 node_ctrl_page_id;
    uint32 arch_locator;
    bool32 archive_register;
    bool32 generated_from_control;
    bool32 dss_mapped;
    uint32 arch_block_size;
    int32 arch_blocks;
    uint64 arch_first;
    uint64 arch_last;
    uint64 arch_start_lsn;
    uint64 arch_end_lsn;
    int64 arch_real_size;
    int64 arch_stamp;
    uint32 arch_dest_id;
    uint16 log_block_size;
    uint32 log_status;
    uint32 log_rst_id;
    uint32 log_dbid;
    uint32 log_hwm;
    uint32 log_first;
    uint32 log_last;
    uint32 rcy_rst_id;
    uint32 rcy_asn;
    uint32 rcy_block_id;
    uint64 rcy_lfn;
    uint64 rcy_lsn;
    uint32 lrp_rst_id;
    uint32 lrp_asn;
    uint32 lrp_block_id;
    uint64 lrp_lfn;
    uint64 lrp_lsn;
    uint32 generated_log_head_asn;
    char log_asn_reason[64];
    bool32 datafile_required;
    uint32 datafile_flag;
    uint32 datafile_space_id;
    uint32 datafile_file_no;
    uint32 datafile_space_type;
} bak_offline_ctrl_path_map_item_t;

typedef struct st_bak_offline_ctrl_path_map {
    const char *target_dir;
    bak_offline_ctrl_path_map_item_t *items;
    uint32 item_capacity;
    uint32 item_count;
    uint32 rewritten_datafiles;
    uint32 rewritten_logfiles;
    uint32 rewritten_archives;
    uint32 preserved_dss_datafiles;
    uint32 preserved_dss_logfiles;
    uint32 preserved_dss_archives;
    uint32 mapped_dss_datafiles;
    uint32 mapped_dss_logfiles;
    uint32 mapped_dss_archives;
    uint32 planned_datafiles;
    uint32 created_datafiles;
    uint32 planned_logfiles;
    uint32 created_logfiles;
    bool32 residual_original_path;
    bool32 residual_dss_path;
    bool32 checksum_recalculated;
    bool32 checksum_kept_invalid;
    bak_offline_restore_storage_mode_t storage_mode;
    const char *dss_map;
    bool32 dss_map_required;
    bool32 dss_map_active;
    bool32 dss_inplace_restore;
    bool32 dss_inplace_preview;
    bool32 inplace_restore;
} bak_offline_ctrl_path_map_t;

typedef struct st_bak_offline_ctrl_restore_opts {
    const char *target_dir;
    uint64 expected_payload_size;
    bool32 reject_dss_to_local;
    bool32 dry_run;
    bool32 rewrite_paths;
    bak_offline_restore_storage_mode_t storage_mode;
    const char *control_files;
    bak_offline_ctrl_path_map_t *path_map;
    bool32 control_commit_only;
} bak_offline_ctrl_restore_opts_t;

typedef struct st_bak_offline_ctrl_restore_result {
    char raw_ctrl_files[BAK_OFFLINE_CTRL_FILE_COUNT][OG_MAX_FILE_PATH_LENGH];
    uint32 raw_ctrl_file_count;
    uint64 raw_ctrl_file_size;
    uint32 ctrl_page_count;
    bool32 checksum_checked;
    bool32 contains_dss_paths;
    bool32 control_rewrite_done;
    uint32 rewritten_datafiles;
    uint32 rewritten_logfiles;
    uint32 rewritten_archives;
    uint32 preserved_dss_datafiles;
    uint32 preserved_dss_logfiles;
    uint32 preserved_dss_archives;
    uint32 mapped_dss_datafiles;
    uint32 mapped_dss_logfiles;
    uint32 mapped_dss_archives;
    uint32 planned_datafiles;
    uint32 created_datafiles;
    uint32 planned_logfiles;
    uint32 created_logfiles;
    bool32 checksum_recalculated;
    bool32 checksum_kept_invalid;
} bak_offline_ctrl_restore_result_t;

/*
 * Session-free control backup piece restore for ordinary local offline restore.
 * It mirrors the online control restore boundary: read the backed-up control
 * page stream, verify control page checksums, then materialize raw control
 * files. It does not start a database instance and does not execute SQL.
 */
status_t bak_offline_restore_ctrlfile(const char *src_path, const bak_offline_ctrl_restore_opts_t *opts,
    bak_offline_ctrl_restore_result_t *result);

bool32 bak_offline_ctrl_result_has_dss_paths(const bak_offline_ctrl_restore_result_t *result);
status_t bak_offline_ctrl_load_buffer(const char *src_path, uint64 expected_payload_size, char **buf, uint64 *size,
    uint32 *page_count);
void bak_offline_ctrl_free_buffer(char *buf);
status_t bak_offline_ctrl_build_path_map(char *buf, uint64 size, const char *target_dir,
    bak_offline_ctrl_path_map_t *map);
status_t bak_offline_ctrl_rewrite_paths(char *buf, uint64 size, bak_offline_ctrl_path_map_t *map);
status_t bak_offline_ctrl_write_raw_files(const char *target_dir, const char *buf, uint64 size,
    bak_offline_ctrl_restore_result_t *result);
bool32 bak_offline_ctrl_buffer_has_dss_path(const char *buf, uint64 size);
status_t bak_offline_ctrl_prepare_non_control_files(bak_offline_ctrl_path_map_t *map,
    bak_offline_ctrl_restore_result_t *result);

#ifdef __cplusplus
}
#endif

#endif
