/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_format_reader.h
 *
 * IDENTIFICATION
 * src/utils/ogbackup/bak_format_reader.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_BAK_FORMAT_READER_H
#define OGRACDB_BAK_FORMAT_READER_H

#include "cm_defs.h"
#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_bak_offline_backupset_catalog {
    char path[OG_MAX_FILE_PATH_LENGH];
    char dir[OG_MAX_FILE_PATH_LENGH];
    bak_head_t head;
    bak_file_t files[BAK_MAX_FILE_NUM];
    bak_dependence_t depends[BAK_MAX_INCR_NUM];
} bak_offline_backupset_catalog_t;

/*
 * Session-free backupset catalog reader.
 * This intentionally reads only disk-format metadata: bak_head_t,
 * bak_file_t[] and bak_dependence_t[]. Database state validation remains in
 * the caller or in the online kernel restore path.
 */
status_t bak_read_backupset_catalog_offline(const char *backupset_path, bak_offline_backupset_catalog_t *catalog);

#ifdef __cplusplus
}
#endif

#endif
