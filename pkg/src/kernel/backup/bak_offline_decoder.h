/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_offline_decoder.h
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_offline_decoder.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OGRACDB_BAK_OFFLINE_DECODER_H
#define OGRACDB_BAK_OFFLINE_DECODER_H

#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_bak_offline_decode_opts {
    compress_algo_e compress;
    encrypt_algorithm_t encrypt_alg;
    bak_encrypt_t encrypt_info;
    char sys_pwd[OG_PASSWORD_BUFFER_SIZE];
    const char *password;
    const bak_file_t *file;
    uint64 physical_size;
    bool32 allow_legacy_log_prefix;
} bak_offline_decode_opts_t;

typedef status_t (*bak_offline_plaintext_cb_t)(const char *buf, uint32 size, uint64 logical_offset, void *ctx);

/*
 * Session-free backup payload decoder. The implementation reuses the product
 * backup catalog encryption metadata, password verifier, AES-256-GCM key
 * derivation, and kernel decompression codecs, then emits plaintext logical
 * chunks to a caller-provided sink.
 */
status_t bak_offline_decode_backup_file(const char *src_path, const bak_offline_decode_opts_t *opts,
    bak_offline_plaintext_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
