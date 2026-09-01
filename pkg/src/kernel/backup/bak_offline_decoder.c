/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_offline_decoder.c
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_offline_decoder.c
 *
 * -------------------------------------------------------------------------
 */

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bak_offline_decoder.h"
#include "cm_checksum.h"
#include "cm_encrypt.h"
#include "cm_file.h"
#include "knl_compress.h"
#include "openssl/evp.h"

#define BAK_OFFLINE_DECODER_READ_SIZE SIZE_K(64)
#define BAK_OFFLINE_DECODER_WRITE_SIZE SIZE_K(128)

typedef struct st_bak_offline_decoder {
    const bak_offline_decode_opts_t *opts;
    EVP_CIPHER_CTX *cipher;
    char key[OG_AES256KEYSIZE];
    char *read_buf;
    char *decode_buf;
    char *plain_buf;
    uint64 logical_offset;
    knl_compress_t compress_ctx;
    bool32 compress_allocated;
    bool32 compress_started;
    bool32 has_plain_log_head;
    uint32 plain_prefix_size;
    log_file_head_t log_head;
} bak_offline_decoder_t;

static bool32 bak_offline_decoder_is_log_piece(const bak_offline_decode_opts_t *opts)
{
    return (opts->file != NULL &&
        (opts->file->type == BACKUP_LOG_FILE || opts->file->type == BACKUP_ARCH_FILE)) ? OG_TRUE : OG_FALSE;
}

static bool32 bak_offline_decoder_log_head_valid(const bak_offline_decode_opts_t *opts,
    const log_file_head_t *source, uint64 physical_size, uint32 *prefix_size)
{
    if (source->block_size < (int32)OG_DFLT_LOG_BLOCK_SIZE ||
        (uint32)source->block_size > OG_DFLT_CTRL_BLOCK_SIZE ||
        ((uint32)source->block_size & ((uint32)source->block_size - 1)) != 0 ||
        (source->cmp_algorithm != COMPRESS_NONE && source->cmp_algorithm != COMPRESS_ZSTD)) {
        return OG_FALSE;
    }
    uint32 aligned_head = CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)source->block_size);
    if (aligned_head > BAK_OFFLINE_DECODER_READ_SIZE || (uint64)aligned_head > physical_size ||
        source->write_pos < aligned_head || source->asn == 0) {
        return OG_FALSE;
    }
    if (opts->file->type == BACKUP_ARCH_FILE && source->asn != opts->file->id) {
        return OG_FALSE;
    }
    if (opts->file->rst_id != 0 && source->rst_id != opts->file->rst_id) {
        return OG_FALSE;
    }
    if ((opts->file->reserved & BAK_FILE_FLAG_PLAIN_LOG_HEAD) == 0 &&
        source->checksum == OG_INVALID_CHECKSUM) {
        return OG_FALSE;
    }
    if (source->checksum != OG_INVALID_CHECKSUM) {
        log_file_head_t checked = *source;
        uint32 stored = checked.checksum;
        checked.checksum = OG_INVALID_CHECKSUM;
        if (cm_get_checksum(&checked, sizeof(checked)) != stored) {
            return OG_FALSE;
        }
    }
    *prefix_size = aligned_head;
    return OG_TRUE;
}

static status_t bak_offline_decoder_prepare_log_prefix(int32 fd, const char *src_path,
    bak_offline_decoder_t *decoder)
{
    const bak_offline_decode_opts_t *opts = decoder->opts;
    bool32 flagged = (opts->file != NULL &&
        (opts->file->reserved & BAK_FILE_FLAG_PLAIN_LOG_HEAD) != 0) ? OG_TRUE : OG_FALSE;
    bool32 try_legacy = (flagged != OG_TRUE && opts->allow_legacy_log_prefix == OG_TRUE) ? OG_TRUE : OG_FALSE;
    if (flagged != OG_TRUE && try_legacy != OG_TRUE) {
        return OG_SUCCESS;
    }
    if (bak_offline_decoder_is_log_piece(opts) != OG_TRUE || opts->physical_size < sizeof(log_file_head_t)) {
        printf("[ogbackup]backup payload has invalid plain log-header metadata: %s\n", src_path);
        return OG_ERROR;
    }
    log_file_head_t head;
    ssize_t read_size = pread(fd, &head, sizeof(head), 0);
    uint32 prefix_size = 0;
    bool32 valid = (read_size == (ssize_t)sizeof(head) &&
        bak_offline_decoder_log_head_valid(opts, &head, opts->physical_size, &prefix_size) == OG_TRUE) ?
        OG_TRUE : OG_FALSE;
    if (valid != OG_TRUE) {
        if (flagged == OG_TRUE) {
            printf("[ogbackup]plain redo/archive header validation failed for %s\n", src_path);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (pread(fd, decoder->read_buf, prefix_size, 0) != (ssize_t)prefix_size) {
        return OG_ERROR;
    }
    decoder->has_plain_log_head = OG_TRUE;
    decoder->plain_prefix_size = prefix_size;
    decoder->log_head = head;
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_check_password(bak_offline_decoder_t *decoder)
{
    const bak_offline_decode_opts_t *opts = decoder->opts;
    if (opts->encrypt_alg == ENCRYPT_NONE) {
        return OG_SUCCESS;
    }
    if (opts->password == NULL || opts->password[0] == '\0') {
        printf("[ogbackup]encrypted backupset requires --password for offline decode\n");
        return OG_ERROR;
    }
    text_t plain;
    text_t stored;
    cm_str2text((char *)opts->password, &plain);
    cm_str2text((char *)opts->sys_pwd, &stored);
    if (cm_check_password(&plain, &stored) != OG_SUCCESS) {
        printf("[ogbackup]encrypted backupset password verification failed\n");
        return OG_ERROR;
    }
    if (cm_encrypt_KDF2((uchar *)opts->password, (uint32)strlen(opts->password),
        (uchar *)opts->encrypt_info.salt, OG_KDF2SALTSIZE, OG_KDF2DEFITERATION,
        (uchar *)decoder->key, OG_AES256KEYSIZE) != OG_SUCCESS) {
        printf("[ogbackup]encrypted backupset key derivation failed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_init_crypto(bak_offline_decoder_t *decoder)
{
    const bak_offline_decode_opts_t *opts = decoder->opts;
    if (opts->encrypt_alg == ENCRYPT_NONE) {
        return OG_SUCCESS;
    }
    if (opts->encrypt_alg != AES_256_GCM) {
        printf("[ogbackup]unsupported encrypted backupset algorithm %u for offline decode\n",
            (uint32)opts->encrypt_alg);
        return OG_ERROR;
    }
    if (opts->file == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_decoder_check_password(decoder) != OG_SUCCESS) {
        return OG_ERROR;
    }
    decoder->cipher = EVP_CIPHER_CTX_new();
    if (decoder->cipher == NULL) {
        return OG_ERROR;
    }
    int32 ret = EVP_DecryptInit_ex(decoder->cipher, EVP_aes_256_gcm(), NULL,
        (const unsigned char *)decoder->key, (const unsigned char *)opts->file->gcm_iv);
    if (ret == 0) {
        printf("[ogbackup]encrypted backupset decrypt init failed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_init_compress(bak_offline_decoder_t *decoder)
{
    if (decoder->opts->compress == COMPRESS_NONE) {
        return OG_SUCCESS;
    }
    errno_t ret = memset_s(&decoder->compress_ctx, sizeof(decoder->compress_ctx), 0, sizeof(decoder->compress_ctx));
    if (ret != EOK) {
        return OG_ERROR;
    }
    if (knl_compress_alloc(decoder->opts->compress, &decoder->compress_ctx, OG_FALSE) != OG_SUCCESS) {
        printf("[ogbackup]offline decode compression resource allocation failed, algorithm=%u\n",
            (uint32)decoder->opts->compress);
        return OG_ERROR;
    }
    decoder->compress_allocated = OG_TRUE;
    if (knl_compress_init(decoder->opts->compress, &decoder->compress_ctx, OG_FALSE) != OG_SUCCESS) {
        printf("[ogbackup]offline decode decompressor init failed, algorithm=%u\n",
            (uint32)decoder->opts->compress);
        return OG_ERROR;
    }
    decoder->compress_started = OG_TRUE;
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_init(bak_offline_decoder_t *decoder, const bak_offline_decode_opts_t *opts)
{
    if (decoder == NULL) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(decoder, sizeof(*decoder), 0, sizeof(*decoder));
    if (ret != EOK) {
        return OG_ERROR;
    }
    if (opts == NULL || opts->physical_size > (uint64)LLONG_MAX) {
        return OG_ERROR;
    }
    decoder->opts = opts;
    decoder->read_buf = (char *)malloc(BAK_OFFLINE_DECODER_READ_SIZE);
    decoder->decode_buf = (char *)malloc(BAK_OFFLINE_DECODER_READ_SIZE * 2);
    decoder->plain_buf = (char *)malloc(BAK_OFFLINE_DECODER_WRITE_SIZE);
    if (decoder->read_buf == NULL || decoder->decode_buf == NULL || decoder->plain_buf == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_decoder_init_crypto(decoder) != OG_SUCCESS ||
        bak_offline_decoder_init_compress(decoder) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void bak_offline_decoder_clean(bak_offline_decoder_t *decoder)
{
    if (decoder == NULL) {
        return;
    }
    if (decoder->cipher != NULL) {
        EVP_CIPHER_CTX_free(decoder->cipher);
        decoder->cipher = NULL;
    }
    if (decoder->compress_allocated == OG_TRUE) {
        knl_compress_free(decoder->opts->compress, &decoder->compress_ctx, OG_FALSE);
    } else if (decoder->compress_started == OG_TRUE) {
        knl_compress_end(decoder->opts->compress, &decoder->compress_ctx, OG_FALSE);
    }
    (void)memset_s(decoder->key, sizeof(decoder->key), 0, sizeof(decoder->key));
    CM_FREE_PTR(decoder->read_buf);
    CM_FREE_PTR(decoder->decode_buf);
    CM_FREE_PTR(decoder->plain_buf);
}

static status_t bak_offline_decoder_emit(bak_offline_decoder_t *decoder, const char *buf, uint32 size,
    bak_offline_plaintext_cb_t cb, void *ctx)
{
    if (size == 0) {
        return OG_SUCCESS;
    }
    status_t status = cb(buf, size, decoder->logical_offset, ctx);
    if (status == OG_SUCCESS) {
        decoder->logical_offset += size;
    }
    return status;
}

static status_t bak_offline_decoder_decompress_emit(bak_offline_decoder_t *decoder, char *buf, uint32 size,
    bool32 read_end, bak_offline_plaintext_cb_t cb, void *ctx)
{
    if (decoder->opts->compress == COMPRESS_NONE) {
        return bak_offline_decoder_emit(decoder, buf, size, cb, ctx);
    }
    knl_compress_set_input(decoder->opts->compress, &decoder->compress_ctx, buf, size);
    for (;;) {
        if (knl_decompress(decoder->opts->compress, &decoder->compress_ctx, read_end, decoder->plain_buf,
            BAK_OFFLINE_DECODER_WRITE_SIZE) != OG_SUCCESS) {
            printf("[ogbackup]offline backup payload decompression failed\n");
            return OG_ERROR;
        }
        if (bak_offline_decoder_emit(decoder, decoder->plain_buf, decoder->compress_ctx.write_len,
            cb, ctx) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (decoder->compress_ctx.finished == OG_TRUE) {
            break;
        }
    }
    if (decoder->compress_ctx.last_left_size > 0) {
        errno_t ret = memmove_s(decoder->decode_buf, BAK_OFFLINE_DECODER_READ_SIZE * 2,
            buf, decoder->compress_ctx.last_left_size);
        if (ret != EOK) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_decode_chunk(bak_offline_decoder_t *decoder, const char *buf, uint32 size,
    uint32 prefix_size)
{
    if (decoder->opts->encrypt_alg == ENCRYPT_NONE) {
        if (memcpy_s(decoder->decode_buf + prefix_size, BAK_OFFLINE_DECODER_READ_SIZE * 2 - prefix_size,
            buf, size) != EOK) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    int32 out_len = 0;
    if (EVP_DecryptUpdate(decoder->cipher, (unsigned char *)decoder->decode_buf + prefix_size, &out_len,
        (const unsigned char *)buf, (int32)size) == 0 || out_len != (int32)size) {
        printf("[ogbackup]offline backup payload decryption failed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_finish_crypto(bak_offline_decoder_t *decoder)
{
    if (decoder->opts->encrypt_alg == ENCRYPT_NONE) {
        return OG_SUCCESS;
    }
    if (EVP_CIPHER_CTX_ctrl(decoder->cipher, EVP_CTRL_AEAD_SET_TAG, EVP_GCM_TLS_TAG_LEN,
        (void *)decoder->opts->file->gcm_tag) == 0) {
        printf("[ogbackup]offline backup payload decrypt tag setup failed\n");
        return OG_ERROR;
    }
    int32 out_len = 0;
    if (EVP_DecryptFinal_ex(decoder->cipher, (unsigned char *)decoder->decode_buf, &out_len) == 0 ||
        out_len != 0) {
        printf("[ogbackup]offline backup payload authentication failed; data may be changed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decoder_validate_log_size(bak_offline_decoder_t *decoder)
{
    if (decoder->has_plain_log_head != OG_TRUE) {
        return OG_SUCCESS;
    }
    if ((decoder->log_head.cmp_algorithm == COMPRESS_NONE &&
        decoder->logical_offset != decoder->log_head.write_pos) ||
        (decoder->log_head.cmp_algorithm != COMPRESS_NONE &&
        decoder->logical_offset < decoder->log_head.write_pos)) {
        printf("[ogbackup]decoded redo/archive length does not match plain header: decoded=%llu write_pos=%llu "
               "cmp_algorithm=%d\n", decoder->logical_offset, decoder->log_head.write_pos,
            decoder->log_head.cmp_algorithm);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t bak_offline_decode_backup_file(const char *src_path, const bak_offline_decode_opts_t *opts,
    bak_offline_plaintext_cb_t cb, void *ctx)
{
    if (src_path == NULL || opts == NULL || cb == NULL) {
        return OG_ERROR;
    }
    int32 fd = open(src_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        printf("[ogbackup]open backup payload %s failed, error %d\n", src_path, errno);
        return OG_ERROR;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || (uint64)st.st_size != opts->physical_size) {
        printf("[ogbackup]backup payload physical size mismatch for %s, expected %llu, actual %llu\n",
            src_path, opts->physical_size, (uint64)(st.st_size < 0 ? 0 : st.st_size));
        (void)close(fd);
        return OG_ERROR;
    }
    bak_offline_decoder_t decoder;
    if (bak_offline_decoder_init(&decoder, opts) != OG_SUCCESS) {
        (void)close(fd);
        bak_offline_decoder_clean(&decoder);
        return OG_ERROR;
    }

    if (bak_offline_decoder_prepare_log_prefix(fd, src_path, &decoder) != OG_SUCCESS) {
        bak_offline_decoder_clean(&decoder);
        (void)close(fd);
        return OG_ERROR;
    }
    if (decoder.has_plain_log_head == OG_TRUE &&
        bak_offline_decoder_emit(&decoder, decoder.read_buf, decoder.plain_prefix_size, cb, ctx) != OG_SUCCESS) {
        bak_offline_decoder_clean(&decoder);
        (void)close(fd);
        return OG_ERROR;
    }

    uint64 physical_offset = decoder.plain_prefix_size;
    status_t status = OG_SUCCESS;
    while (physical_offset < opts->physical_size) {
        uint32 request = (opts->physical_size - physical_offset > BAK_OFFLINE_DECODER_READ_SIZE) ?
            BAK_OFFLINE_DECODER_READ_SIZE : (uint32)(opts->physical_size - physical_offset);
        ssize_t read_size = pread(fd, decoder.read_buf, request, (off_t)physical_offset);
        if (read_size != (ssize_t)request) {
            printf("[ogbackup]read backup payload %s failed at offset %llu\n", src_path, physical_offset);
            status = OG_ERROR;
            break;
        }
        physical_offset += (uint64)read_size;
        uint32 prefix_size = decoder.compress_ctx.last_left_size;
        if (prefix_size > BAK_OFFLINE_DECODER_READ_SIZE ||
            bak_offline_decoder_decode_chunk(&decoder, decoder.read_buf, (uint32)read_size, prefix_size) !=
            OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }
        bool32 read_end = physical_offset == opts->physical_size ? OG_TRUE : OG_FALSE;
        if (bak_offline_decoder_decompress_emit(&decoder, decoder.decode_buf, (uint32)read_size + prefix_size,
            read_end, cb, ctx) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }
    }
    if (status == OG_SUCCESS) {
        status = bak_offline_decoder_finish_crypto(&decoder);
    }
    if (status == OG_SUCCESS) {
        status = bak_offline_decoder_validate_log_size(&decoder);
    }
    bak_offline_decoder_clean(&decoder);
    (void)close(fd);
    return status;
}
