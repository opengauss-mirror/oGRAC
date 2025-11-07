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
 * knl_compress.c
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_compress.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "knl_compress.h"

static status_t zlib_init(knl_compress_t *ogx, bool32 is_compress)
{
    errno_t ret;

    ret = memset_sp(&ogx->stream, sizeof(z_stream), 0, sizeof(z_stream));
    knl_securec_check(ret);

    ogx->stream.zalloc = Z_NULL;
    ogx->stream.zfree = Z_NULL;
    ogx->stream.opaque = Z_NULL;

    if (is_compress) {
        knl_panic(ogx->compress_level >= Z_BEST_SPEED);
        knl_panic(ogx->compress_level <= Z_BEST_COMPRESSION);
        ret = deflateInit(&ogx->stream, ogx->compress_level);
        if (ret != Z_OK) {
            OG_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "zlib", ret, ogx->stream.msg);
            return OG_ERROR;
        }
    } else {
        ret = inflateInit(&ogx->stream);
        if (ret != Z_OK) {
            OG_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "zlib", ret, ogx->stream.msg);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static void zlib_set_input(knl_compress_t *zctx, char *read_buf, uint32 buf_len)
{
    zctx->stream.next_in = (uint8_t *)read_buf;
    zctx->stream.avail_in = buf_len;
}

static status_t zlib_compress(knl_compress_t *zctx, bool32 stream_end, char *write_buf, uint32 buf_len)
{
    int32 ret;
    int32 flush = stream_end ? Z_FINISH : Z_NO_FLUSH;

    zctx->stream.next_out = (uint8_t *)write_buf;
    zctx->stream.avail_out = buf_len;

    ret = deflate(&zctx->stream, flush);
    if (flush == Z_NO_FLUSH && ret != Z_OK) {
        OG_THROW_ERROR(ERR_COMPRESS_ERROR, "zlib", ret, zctx->stream.msg);
        return OG_ERROR;
    }

    if (flush == Z_FINISH && ret != Z_STREAM_END) {
        OG_THROW_ERROR(ERR_COMPRESS_ERROR, "zlib", ret, zctx->stream.msg);
        return OG_ERROR;
    }

    zctx->write_len = buf_len - zctx->stream.avail_out;
    zctx->finished = (zctx->stream.avail_out != 0);

    return OG_SUCCESS;
}

static status_t zlib_decompress(knl_compress_t *zctx, bool32 end_stream, char *write_buf, uint32 buf_len)
{
    int32 ret;
    int32 flush = end_stream ? Z_FINISH : Z_NO_FLUSH;

    zctx->stream.next_out = (uint8_t *)write_buf;
    zctx->stream.avail_out = buf_len;

    ret = inflate(&zctx->stream, flush);
    if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
        OG_THROW_ERROR(ERR_DECOMPRESS_ERROR, "zlib", ret, zctx->stream.msg);
        return OG_ERROR;
    }

    zctx->write_len = buf_len - zctx->stream.avail_out;
    zctx->finished = (zctx->stream.avail_out != 0);

    return OG_SUCCESS;
}

static void zlib_end(knl_compress_t *zctx, bool32 is_compress)
{
    if (is_compress) {
        (void)deflateEnd(&zctx->stream);
    } else {
        (void)inflateEnd(&zctx->stream);
    }
}

static status_t zstd_alloc(knl_compress_t *ogx, bool32 is_compress)
{
    bool32 created = OG_FALSE;
    if (is_compress) {
        ogx->zstd_cstream = ZSTD_createCStream();
        created = (ogx->zstd_cstream != NULL);
    } else {
        ogx->zstd_dstream = ZSTD_createDStream();
        created = (ogx->zstd_dstream != NULL);
    }

    if (!created) {
        OG_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "zstd", 0, "Create zstd stream failed.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t zstd_init(knl_compress_t *ogx, bool32 is_compress)
{
    size_t ret;

    if (is_compress) {
        ret = ZSTD_initCStream(ogx->zstd_cstream, ogx->compress_level);
    } else {
        ret = ZSTD_initDStream(ogx->zstd_dstream);
    }

    if (ZSTD_isError(ret)) {
        OG_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "zstd", ret, ZSTD_getErrorName(ret));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static void zstd_set_input(knl_compress_t *ogx, char *read_buf, uint32 buf_len)
{
    ogx->zstd_in_buf.src = read_buf;
    ogx->zstd_in_buf.size = buf_len;
    ogx->zstd_in_buf.pos = 0;
}

static status_t zstd_compress(knl_compress_t *ogx, bool32 stream_end, char *write_buf, uint32 buf_len)
{
    size_t ret;
    ZSTD_outBuffer buf_out;

    buf_out.dst = write_buf;
    buf_out.size = buf_len;
    buf_out.pos = 0;

    if (!stream_end) {
        ret = ZSTD_compressStream(ogx->zstd_cstream, &buf_out, &(ogx->zstd_in_buf));
    } else {
        ret = ZSTD_endStream(ogx->zstd_cstream, &buf_out);
    }
    if (ZSTD_isError(ret)) {
        OG_THROW_ERROR(ERR_COMPRESS_ERROR, "zstd", ret, ZSTD_getErrorName(ret));
        return OG_ERROR;
    }

    ogx->write_len = (uint32)buf_out.pos;
    ogx->finished = (buf_out.pos < buf_out.size);

    return OG_SUCCESS;
}

static status_t zstd_decompress(knl_compress_t *ogx, bool32 end_stream, char *write_buf, uint32 buf_len)
{
    size_t ret;
    ZSTD_outBuffer buf_out;

    buf_out.dst = write_buf;
    buf_out.size = buf_len;
    buf_out.pos = 0;

    ret = ZSTD_decompressStream(ogx->zstd_dstream, &buf_out, &(ogx->zstd_in_buf));
    if (ZSTD_isError(ret)) {
        OG_THROW_ERROR(ERR_DECOMPRESS_ERROR, "zstd", ret, ZSTD_getErrorName(ret));
        return OG_ERROR;
    }

    ogx->write_len = (uint32)buf_out.pos;
    ogx->finished = (buf_out.pos < buf_out.size);

    return OG_SUCCESS;
}

static void zstd_end(knl_compress_t *zctx, bool32 is_compress)
{
    size_t ret;
    if (is_compress) {
        ret = ZSTD_freeCStream(zctx->zstd_cstream);
    } else {
        ret = ZSTD_freeDStream(zctx->zstd_dstream);
    }

    zctx->zstd_cstream = NULL;

    if (ZSTD_isError(ret)) {
        OG_THROW_ERROR(ERR_COMPRESS_FREE_ERROR, "ZSTD", ret, ZSTD_getErrorName(ret));
    }
}

static status_t lz4f_alloc(knl_compress_t *ogx, bool32 is_compress)
{
    size_t ret;

    if (is_compress) {
        ret = LZ4F_createCompressionContext(&(ogx->lz4f_cstream), LZ4F_VERSION);
    } else {
        ret = LZ4F_createDecompressionContext(&(ogx->lz4f_dstream), LZ4F_VERSION);
    }

    if (LZ4F_isError(ret)) {
        OG_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "lz4f", ret, LZ4F_getErrorName(ret));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t lz4f_init(knl_compress_t *ogx, bool32 is_compress)
{
    // lz4's compression will init the resource in the end of each subtask automatically,
    // so we do not need to do the initialization of compression here
    if (!is_compress) {
        LZ4F_resetDecompressionContext(ogx->lz4f_dstream);
    }

    return OG_SUCCESS;
}

static void lz4f_set_input(knl_compress_t *ogx, char *read_buf, uint32 buf_len)
{
    ogx->lz4f_in_buf.src = read_buf;
    ogx->lz4f_in_buf.size = buf_len;
    ogx->lz4f_in_buf.pos = 0;
}

static status_t lz4f_compress(knl_compress_t *ogx, bool32 stream_end, char *write_buf, uint32 write_buf_len)
{
    LZ4F_compressOptions_t option = {0, {0, 0, 0}};
    size_t res;

    if (!stream_end) {
        res = LZ4F_compressUpdate(ogx->lz4f_cstream, write_buf, write_buf_len, ogx->lz4f_in_buf.src,
            ogx->lz4f_in_buf.size, &option);
    } else {
        res = LZ4F_compressEnd(ogx->lz4f_cstream, write_buf, write_buf_len, &option);
    }

    if (LZ4F_isError(res)) {
        OG_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
        return OG_ERROR;
    }

    ogx->write_len = (uint32)res;
    ogx->finished = (res < write_buf_len);

    return OG_SUCCESS;
}

static status_t lz4f_decompress(knl_compress_t *ogx, bool32 end_stream, char *write_buf, uint32 write_buf_len)
{
    errno_t ret;
    size_t res;
    size_t in_len = ogx->lz4f_in_buf.size - ogx->lz4f_in_buf.pos;
    size_t out_len = write_buf_len;
    const LZ4F_decompressOptions_t option = {0, 0, 0, 0};

    res = LZ4F_decompress(ogx->lz4f_dstream, write_buf, &out_len,
        ogx->lz4f_in_buf.src + ogx->lz4f_in_buf.pos, &in_len, &option);
    if (LZ4F_isError(res)) {
        OG_THROW_ERROR(ERR_DECOMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
        return OG_ERROR;
    }

    ogx->write_len = (uint32)out_len;
    ogx->lz4f_in_buf.pos += in_len;

    // res==0 means that lz4f has decompressed a frame completely
    if (res == 0) {
        ogx->finished = OG_TRUE;
        return OG_SUCCESS;
    }

    /*
    * res!=0&&out_len!=0 means lz4f has not decompressed a frame completely but the in_buf can not be decompressed
    * this case means that the rest of in_buf should be decompressed together with the next stream data, so we copy
    * the rest data in in_buf into the beginning of read_buf and record its length for next read
    * res!=&&out_len==0 means lz4f has not decompressed a frame completely but the out_buf can not be written in
    * this case means that the out_buf should be used by others and emptied for next decompression
    */
    ogx->finished = (out_len == 0);
    if (!ogx->finished) {
        return OG_SUCCESS;
    } else {
        ogx->last_left_size = (uint32)(ogx->lz4f_in_buf.size - ogx->lz4f_in_buf.pos);
        if (ogx->last_left_size == 0) {
            return OG_SUCCESS;
        }
        ret = memmove_s(ogx->lz4f_in_buf.src, ogx->lz4f_in_buf.size,
            ogx->lz4f_in_buf.src + ogx->lz4f_in_buf.pos, ogx->last_left_size);
        knl_securec_check(ret);
    }

    return OG_SUCCESS;
}

static void lz4f_end(knl_compress_t *zctx, bool32 is_compress)
{
    size_t ret;
    if (is_compress) {
        ret = LZ4F_freeCompressionContext(zctx->lz4f_cstream);
    } else {
        ret = LZ4F_freeDecompressionContext(zctx->lz4f_dstream);
    }

    zctx->lz4f_cstream = NULL;

    if (LZ4F_isError(ret)) {
        OG_THROW_ERROR(ERR_COMPRESS_FREE_ERROR, "LZ4F", ret, LZ4F_getErrorName(ret));
    }
}

/*
* Alloc resource needed by compression or decompression.
* @param the attributes of backup or restore
* @param compress context
* @param the action is backup or restore
* @return
* - OG_SUCCESS
* _ OG_ERROR
* @note must call in the beginning of the backup or restore task
*/
status_t knl_compress_alloc(compress_algo_e compress, knl_compress_t *ogx, bool32 is_compress)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            /*
            * zlib's resource is allocated during initialization in knl_compress_init, because that the allocation
            * and initialization of zlib are coupled and it must be executed in the beginning of each subtask.
            */
            return OG_SUCCESS;
        case COMPRESS_ZSTD:
            return zstd_alloc(ogx, is_compress);
        case COMPRESS_LZ4:
            return lz4f_alloc(ogx, is_compress);
        default:
            break;
    }

    return OG_SUCCESS;
}

/*
* Init resource of the compression or decompression.
* @param the attributes of backup or restore
* @param compress context
* @param the action is backup or restore
* @return
* - OG_SUCCESS
* _ OG_ERROR
* @note must call in the beginning of each subtask
*/
status_t knl_compress_init(compress_algo_e compress, knl_compress_t *ogx, bool32 is_compress)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            return zlib_init(ogx, is_compress);
        case COMPRESS_ZSTD:
            return zstd_init(ogx, is_compress);
        case COMPRESS_LZ4:
            return lz4f_init(ogx, is_compress);
        default:
            break;
    }

    return OG_SUCCESS;
}

void knl_compress_set_input(compress_algo_e compress, knl_compress_t *ogx, char *read_buf, uint32 buf_len)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            zlib_set_input(ogx, read_buf, buf_len);
            break;
        case COMPRESS_ZSTD:
            zstd_set_input(ogx, read_buf, buf_len);
            break;
        case COMPRESS_LZ4:
            lz4f_set_input(ogx, read_buf, buf_len);
            break;
        default:
            break;
        }
}

status_t knl_compress(compress_algo_e compress, knl_compress_t *ogx, bool32 stream_end,
    char *write_buf, uint32 buf_len)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            return zlib_compress(ogx, stream_end, write_buf, buf_len);
        case COMPRESS_ZSTD:
            return zstd_compress(ogx, stream_end, write_buf, buf_len);
        case COMPRESS_LZ4:
            return lz4f_compress(ogx, stream_end, write_buf, buf_len);
        default:
            break;
    }

    return OG_SUCCESS;
}

status_t knl_decompress(compress_algo_e compress, knl_compress_t *ogx, bool32 end_stream,
    char *write_buf, uint32 buf_len)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            return zlib_decompress(ogx, end_stream, write_buf, buf_len);
        case COMPRESS_ZSTD:
            return zstd_decompress(ogx, end_stream, write_buf, buf_len);
        case COMPRESS_LZ4:
            return lz4f_decompress(ogx, end_stream, write_buf, buf_len);
        default:
            break;
    }

    return OG_SUCCESS;
}

/*
* Do something needed in the end of each subtask of the compression or decompression.
* @param the attributes of backup or restore
* @param compress context
* @param the action is backup or restore
* @return
* - OG_SUCCESS
* _ OG_ERROR
* @note must call in the end of each subtask
*/
void knl_compress_end(compress_algo_e compress, knl_compress_t *ogx, bool32 is_compress)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            zlib_end(ogx, is_compress);
            break;
        default:
            // zlib needs to free resource in the end of each subtask, while zstd and lz4 need do nothing here
            break;
    }
}

/*
* Free the resource of the compression or decompression.
* @param the attributes of backup or restore
* @param compress context
* @param the action is backup or restore
* @return
* - OG_SUCCESS
* _ OG_ERROR
* @note must call in the end of the backup or restore task
*/
void knl_compress_free(compress_algo_e compress, knl_compress_t *ogx, bool32 is_compress)
{
    switch (compress) {
        case COMPRESS_ZLIB:
            zlib_end(ogx, is_compress);
            break;
        case COMPRESS_ZSTD:
            zstd_end(ogx, is_compress);
            break;
        case COMPRESS_LZ4:
            lz4f_end(ogx, is_compress);
            break;
        default:
            break;
    }
}
