/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_page_restore.h
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_page_restore.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_BAK_PAGE_RESTORE_H
#define OGRACDB_BAK_PAGE_RESTORE_H

#include "cm_defs.h"
#include "cm_device.h"
#include "bak_offline_decoder.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_bak_offline_page_apply_opts {
    uint32 expected_file_id;
    uint32 backup_level;
    uint64 expected_payload_size;
    bool32 verify_page_checksum;
    bool32 skip_empty_pages;
    device_type_t target_device_type;
    status_t (*write_guard)(const char *target_path, uint32 file_id, uint32 page_no, uint64 offset, uint32 length,
        void *ctx);
    void *write_guard_ctx;
} bak_offline_page_apply_opts_t;

typedef status_t (*bak_offline_page_range_cb_t)(uint32 file_id, uint32 page_no, uint32 page_size,
    uint64 source_offset, void *ctx);
typedef status_t (*bak_offline_page_data_cb_t)(uint32 file_id, uint32 page_no, uint32 page_size, uint64 source_offset,
    const char *page_buf, void *ctx);

/*
 * Session-free data page applier for ordinary local, uncompressed backupset
 * payloads. Unsupported complex formats must be detected and rejected here,
 * not silently copied by the ogbackup tool.
 */
status_t bak_offline_apply_data_pages(const char *src_path, const char *dst_path,
    const bak_offline_page_apply_opts_t *opts);
status_t bak_offline_apply_decoded_data_pages(const char *src_path, const char *dst_path,
    const bak_offline_page_apply_opts_t *opts, const bak_offline_decode_opts_t *decode_opts);
status_t bak_offline_calc_page_write_range(uint32 page_no, uint32 page_size, uint64 *offset, uint64 *length);
status_t bak_offline_scan_data_page_ranges(const char *src_path, const bak_offline_page_apply_opts_t *opts,
    bak_offline_page_range_cb_t cb, void *ctx);
status_t bak_offline_scan_decoded_data_page_ranges(const char *src_path, const bak_offline_page_apply_opts_t *opts,
    const bak_offline_decode_opts_t *decode_opts, bak_offline_page_range_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
