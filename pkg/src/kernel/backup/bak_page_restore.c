/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_page_restore.c
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_page_restore.c
 *
 * -------------------------------------------------------------------------
 */

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bak_page_restore.h"
#include "bak_storage_adapter.h"
#include "cm_file.h"
#include "knl_page.h"

#define BAK_OFFLINE_DEFAULT_PAGE_SIZE SIZE_K(8)
#define BAK_OFFLINE_PAGE_UNIT_SIZE SIZE_K(4)

static void bak_offline_decode_page_id(const char *id, uint32 *page, uint32 *file)
{
    uint32 page_no;
    uint16 file_no;
    errno_t ret = memcpy_s(&page_no, sizeof(page_no), id, sizeof(page_no));
    ret |= memcpy_s(&file_no, sizeof(file_no), id + sizeof(page_no), sizeof(file_no));
    if (ret != EOK) {
        *page = 0;
        *file = 0;
        return;
    }
    *page = page_no;
    *file = file_no;
}

static status_t bak_offline_mkdir_parent(const char *path)
{
    char tmp[OG_MAX_FILE_PATH_LENGH] = {0};
    if (path == NULL || strlen(path) >= sizeof(tmp) || strcpy_s(tmp, sizeof(tmp), path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(tmp, '/');
    if (slash == NULL) {
        return OG_SUCCESS;
    }
    *slash = '\0';
    if (tmp[0] == '\0') {
        return OG_SUCCESS;
    }
    if (cm_dir_exist(tmp)) {
        return OG_SUCCESS;
    }
    return cm_create_dir_ex(tmp);
}

static status_t bak_offline_read_page_size(int32 fd, uint32 *page_size)
{
    page_head_t head;
    ssize_t read_size = pread(fd, &head, sizeof(head), 0);
    if (read_size != (ssize_t)sizeof(head)) {
        printf("[ogbackup]read data backup page header failed\n");
        return OG_ERROR;
    }
    if (head.size_units == 0) {
        *page_size = BAK_OFFLINE_DEFAULT_PAGE_SIZE;
        return OG_SUCCESS;
    }
    *page_size = (uint32)head.size_units * BAK_OFFLINE_PAGE_UNIT_SIZE;
    if (*page_size == 0 || *page_size > SIZE_K(32) || *page_size % BAK_OFFLINE_PAGE_UNIT_SIZE != 0) {
        printf("[ogbackup]unsupported datafile page size %u in backupset file\n", *page_size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_write_exact_at(int32 fd, const char *buf, uint32 size, uint64 offset)
{
    const char *pos = buf;
    uint32 left = size;
    uint64 cur_offset = offset;
    while (left > 0) {
        ssize_t write_size = pwrite(fd, pos, left, (off_t)cur_offset);
        if (write_size <= 0) {
            return OG_ERROR;
        }
        pos += write_size;
        left -= (uint32)write_size;
        cur_offset += (uint64)write_size;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_write_page_to_device(device_type_t type, int32 handle, const char *buf, uint32 size,
    uint64 offset)
{
    if (type == DEV_TYPE_FILE) {
        return bak_offline_write_exact_at(handle, buf, size, offset);
    }
    if (type != DEV_TYPE_RAW || offset > (uint64)LLONG_MAX || size > (uint32)INT32_MAX) {
        return OG_ERROR;
    }
    return cm_write_device(type, handle, (int64)offset, buf, (int32)size);
}

static status_t bak_offline_verify_page(page_head_t *page, uint32 page_size, const char *src_path)
{
    if (PAGE_CHECKSUM(page, page_size) == OG_INVALID_CHECKSUM) {
        return OG_SUCCESS;
    }
    if (!page_verify_checksum(page, page_size)) {
        page_id_t *page_id = AS_PAGID_PTR(page->id);
        printf("[ogbackup]data page checksum mismatch in %s at page %u-%u\n",
            src_path, page_id->file, page_id->page);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 bak_offline_is_empty_page(page_head_t *page)
{
    return page->size_units == 0 ? OG_TRUE : OG_FALSE;
}

status_t bak_offline_calc_page_write_range(uint32 page_no, uint32 page_size, uint64 *offset, uint64 *length)
{
    if (offset == NULL || length == NULL || page_size == 0) {
        return OG_ERROR;
    }
    if ((uint64)page_no > UINT64_MAX / (uint64)page_size) {
        return OG_ERROR;
    }
    uint64 start = (uint64)page_no * (uint64)page_size;
    if (UINT64_MAX - start < (uint64)page_size) {
        return OG_ERROR;
    }
    *offset = start;
    *length = (uint64)page_size;
    return OG_SUCCESS;
}

static status_t bak_offline_prepare_scan(const char *src_path, const bak_offline_page_apply_opts_t *opts,
    int32 *src_fd, uint32 *page_size)
{
    if (src_path == NULL || opts == NULL || src_fd == NULL || page_size == NULL) {
        return OG_ERROR;
    }
    *src_fd = open(src_path, O_RDONLY | O_BINARY);
    if (*src_fd < 0) {
        printf("[ogbackup]open backup datafile %s failed, error %d\n", src_path, errno);
        return OG_ERROR;
    }
    struct stat src_stat;
    if (fstat(*src_fd, &src_stat) != 0) {
        printf("[ogbackup]stat backup datafile %s failed, error %d\n", src_path, errno);
        (void)close(*src_fd);
        return OG_ERROR;
    }
    if ((uint64)src_stat.st_size != opts->expected_payload_size) {
        printf("[ogbackup]backup datafile payload size mismatch for %s, expected %llu, actual %llu\n",
            src_path, opts->expected_payload_size, (uint64)src_stat.st_size);
        (void)close(*src_fd);
        return OG_ERROR;
    }
    if (src_stat.st_size == 0) {
        printf("[ogbackup]skip empty datafile backup piece %s, file_id=%u, backup_level=%u\n",
            src_path, opts->expected_file_id, opts->backup_level);
        return OG_SUCCESS;
    }
    if (bak_offline_read_page_size(*src_fd, page_size) != OG_SUCCESS) {
        (void)close(*src_fd);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t bak_offline_scan_data_page_ranges(const char *src_path, const bak_offline_page_apply_opts_t *opts,
    bak_offline_page_range_cb_t cb, void *ctx)
{
    if (src_path == NULL || opts == NULL || cb == NULL) {
        return OG_ERROR;
    }
    int32 src_fd = OG_INVALID_HANDLE;
    uint32 page_size = 0;
    if (bak_offline_prepare_scan(src_path, opts, &src_fd, &page_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (opts->expected_payload_size == 0) {
        (void)close(src_fd);
        return OG_SUCCESS;
    }

    char *page_buf = (char *)malloc(page_size);
    if (page_buf == NULL) {
        (void)close(src_fd);
        return OG_ERROR;
    }

    uint64 offset = 0;
    status_t status = OG_SUCCESS;
    for (;;) {
        ssize_t read_size = pread(src_fd, page_buf, page_size, (off_t)offset);
        if (read_size == 0) {
            break;
        }
        if (read_size != (ssize_t)page_size) {
            printf("[ogbackup]data backup file %s size is not aligned to page size %u\n", src_path, page_size);
            status = OG_ERROR;
            break;
        }
        page_head_t *page = (page_head_t *)page_buf;
        if (opts->skip_empty_pages == OG_TRUE && bak_offline_is_empty_page(page)) {
            offset += page_size;
            continue;
        }
        if (page->size_units != 0 && (uint32)page->size_units * BAK_OFFLINE_PAGE_UNIT_SIZE != page_size) {
            printf("[ogbackup]mixed page size detected in %s; offline restore does not support it\n", src_path);
            status = OG_ERROR;
            break;
        }
        if (page->compressed) {
            printf("[ogbackup]compressed data page detected in %s; offline restore does not support compressed pages yet\n",
                src_path);
            status = OG_ERROR;
            break;
        }
        uint32 page_no;
        uint32 file_no;
        bak_offline_decode_page_id(page->id, &page_no, &file_no);
        if (file_no != opts->expected_file_id) {
            printf("[ogbackup]data page file id mismatch in %s at offset %llu, expected %u, actual %u, "
                "page=%u, page_size=%u, page_type=%u, size_units=%u, backup_level=%u, skip_empty=%u\n",
                src_path, offset, opts->expected_file_id, file_no, page_no, page_size, (uint32)page->type,
                (uint32)page->size_units, opts->backup_level, (uint32)opts->skip_empty_pages);
            status = OG_ERROR;
            break;
        }
        if (opts->verify_page_checksum == OG_TRUE &&
            bak_offline_verify_page(page, page_size, src_path) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }
        if (cb(file_no, page_no, page_size, offset, ctx) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }
        offset += page_size;
    }

    CM_FREE_PTR(page_buf);
    (void)close(src_fd);
    return status;
}

typedef struct st_bak_offline_apply_ctx {
    const char *src_path;
    const char *dst_path;
    const bak_offline_page_apply_opts_t *opts;
    device_type_t target_type;
    int32 dst_fd;
} bak_offline_apply_ctx_t;

typedef struct st_bak_offline_decoded_scan_ctx {
    const char *src_path;
    const bak_offline_page_apply_opts_t *opts;
    bak_offline_page_range_cb_t range_cb;
    bak_offline_page_data_cb_t data_cb;
    void *cb_ctx;
    char *page_buf;
    uint32 page_size;
    uint32 page_buf_used;
} bak_offline_decoded_scan_ctx_t;

static status_t bak_offline_noop_page_cb(uint32 file_id, uint32 page_no, uint32 page_size, uint64 source_offset,
    void *ctx)
{
    (void)file_id;
    (void)page_no;
    (void)page_size;
    (void)source_offset;
    (void)ctx;
    return OG_SUCCESS;
}

static status_t bak_offline_apply_page_cb(uint32 file_id, uint32 page_no, uint32 page_size, uint64 source_offset,
    void *ctx)
{
    bak_offline_apply_ctx_t *apply = (bak_offline_apply_ctx_t *)ctx;
    uint64 write_offset = 0;
    uint64 write_length = 0;
    if (bak_offline_calc_page_write_range(page_no, page_size, &write_offset, &write_length) != OG_SUCCESS ||
        write_length > (uint64)UINT32_MAX) {
        printf("[ogbackup]data page range overflow in %s at source offset %llu page=%u-%u page_size=%u\n",
            apply->src_path, source_offset, file_id, page_no, page_size);
        return OG_ERROR;
    }
    if (apply->opts->write_guard != NULL &&
        apply->opts->write_guard(apply->dst_path, file_id, page_no, write_offset, (uint32)write_length,
        apply->opts->write_guard_ctx) != OG_SUCCESS) {
        printf("[ogbackup]data page write rejected before device write: target=%s page=%u-%u offset=%llu length=%llu\n",
            apply->dst_path, file_id, page_no, write_offset, write_length);
        return OG_ERROR;
    }
    char *page_buf = (char *)malloc(page_size);
    if (page_buf == NULL) {
        return OG_ERROR;
    }
    int32 src_fd = open(apply->src_path, O_RDONLY | O_BINARY);
    if (src_fd < 0) {
        CM_FREE_PTR(page_buf);
        return OG_ERROR;
    }
    ssize_t read_size = pread(src_fd, page_buf, page_size, (off_t)source_offset);
    (void)close(src_fd);
    if (read_size != (ssize_t)page_size) {
        CM_FREE_PTR(page_buf);
        return OG_ERROR;
    }
    status_t status = bak_offline_write_page_to_device(apply->target_type, apply->dst_fd, page_buf, page_size,
        write_offset);
    CM_FREE_PTR(page_buf);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]write data page %u-%u to %s failed, error %d\n", file_id, page_no, apply->dst_path, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_apply_page_data_cb(uint32 file_id, uint32 page_no, uint32 page_size, uint64 source_offset,
    const char *page_buf, void *ctx)
{
    bak_offline_apply_ctx_t *apply = (bak_offline_apply_ctx_t *)ctx;
    uint64 write_offset = 0;
    uint64 write_length = 0;
    if (bak_offline_calc_page_write_range(page_no, page_size, &write_offset, &write_length) != OG_SUCCESS ||
        write_length > (uint64)UINT32_MAX) {
        printf("[ogbackup]data page range overflow in %s at source offset %llu page=%u-%u page_size=%u\n",
            apply->src_path, source_offset, file_id, page_no, page_size);
        return OG_ERROR;
    }
    if (apply->opts->write_guard != NULL &&
        apply->opts->write_guard(apply->dst_path, file_id, page_no, write_offset, (uint32)write_length,
        apply->opts->write_guard_ctx) != OG_SUCCESS) {
        printf("[ogbackup]data page write rejected before device write: target=%s page=%u-%u offset=%llu length=%llu\n",
            apply->dst_path, file_id, page_no, write_offset, write_length);
        return OG_ERROR;
    }
    status_t status = bak_offline_write_page_to_device(apply->target_type, apply->dst_fd, page_buf, page_size,
        write_offset);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]write decoded data page %u-%u to %s failed, error %d\n", file_id, page_no,
            apply->dst_path, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decode_page_payload(bak_offline_decoded_scan_ctx_t *scan, page_head_t *page,
    uint64 logical_page_offset)
{
    if (scan->opts->skip_empty_pages == OG_TRUE && bak_offline_is_empty_page(page)) {
        return OG_SUCCESS;
    }
    if (page->size_units != 0 && (uint32)page->size_units * BAK_OFFLINE_PAGE_UNIT_SIZE != scan->page_size) {
        printf("[ogbackup]mixed page size detected in decoded payload %s; offline restore does not support it\n",
            scan->src_path);
        return OG_ERROR;
    }
    if (page->compressed) {
        printf("[ogbackup]compressed database page detected after backup payload decode in %s\n", scan->src_path);
        return OG_ERROR;
    }
    uint32 page_no;
    uint32 file_no;
    bak_offline_decode_page_id(page->id, &page_no, &file_no);
    if (file_no != scan->opts->expected_file_id) {
        printf("[ogbackup]decoded data page file id mismatch in %s at logical offset %llu, expected %u, actual %u, "
            "page=%u, page_size=%u, page_type=%u, size_units=%u, backup_level=%u, skip_empty=%u\n",
            scan->src_path, logical_page_offset, scan->opts->expected_file_id, file_no, page_no, scan->page_size,
            (uint32)page->type, (uint32)page->size_units, scan->opts->backup_level,
            (uint32)scan->opts->skip_empty_pages);
        return OG_ERROR;
    }
    if (scan->opts->verify_page_checksum == OG_TRUE &&
        bak_offline_verify_page(page, scan->page_size, scan->src_path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (scan->range_cb != NULL &&
        scan->range_cb(file_no, page_no, scan->page_size, logical_page_offset, scan->cb_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (scan->data_cb != NULL &&
        scan->data_cb(file_no, page_no, scan->page_size, logical_page_offset, (const char *)page,
        scan->cb_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_decoded_plaintext_cb(const char *buf, uint32 size, uint64 logical_offset, void *ctx)
{
    bak_offline_decoded_scan_ctx_t *scan = (bak_offline_decoded_scan_ctx_t *)ctx;
    uint32 consumed = 0;
    while (consumed < size) {
        if (scan->page_size == 0) {
            uint32 need = (uint32)sizeof(page_head_t) - scan->page_buf_used;
            uint32 copy_size = (size - consumed < need) ? (size - consumed) : need;
            errno_t ret = memcpy_s(scan->page_buf + scan->page_buf_used, BAK_OFFLINE_DEFAULT_PAGE_SIZE,
                buf + consumed, copy_size);
            if (ret != EOK) {
                return OG_ERROR;
            }
            scan->page_buf_used += copy_size;
            consumed += copy_size;
            if (scan->page_buf_used < sizeof(page_head_t)) {
                return OG_SUCCESS;
            }
            page_head_t *head = (page_head_t *)scan->page_buf;
            scan->page_size = head->size_units == 0 ? BAK_OFFLINE_DEFAULT_PAGE_SIZE :
                (uint32)head->size_units * BAK_OFFLINE_PAGE_UNIT_SIZE;
            if (scan->page_size == 0 || scan->page_size > SIZE_K(32) ||
                scan->page_size % BAK_OFFLINE_PAGE_UNIT_SIZE != 0) {
                printf("[ogbackup]unsupported decoded datafile page size %u in %s\n", scan->page_size,
                    scan->src_path);
                return OG_ERROR;
            }
            if (scan->page_size > BAK_OFFLINE_DEFAULT_PAGE_SIZE) {
                char *new_buf = (char *)realloc(scan->page_buf, scan->page_size);
                if (new_buf == NULL) {
                    return OG_ERROR;
                }
                scan->page_buf = new_buf;
            }
        }
        uint32 page_left = scan->page_size - scan->page_buf_used;
        uint32 copy_size = (size - consumed < page_left) ? (size - consumed) : page_left;
        errno_t ret = memcpy_s(scan->page_buf + scan->page_buf_used, scan->page_size - scan->page_buf_used,
            buf + consumed, copy_size);
        if (ret != EOK) {
            return OG_ERROR;
        }
        scan->page_buf_used += copy_size;
        consumed += copy_size;
        if (scan->page_buf_used == scan->page_size) {
            uint64 page_offset = logical_offset + consumed - scan->page_size;
            if (bak_offline_decode_page_payload(scan, (page_head_t *)scan->page_buf, page_offset) != OG_SUCCESS) {
                return OG_ERROR;
            }
            scan->page_buf_used = 0;
        }
    }
    return OG_SUCCESS;
}

static status_t bak_offline_scan_decoded_data_pages(const char *src_path, const bak_offline_page_apply_opts_t *opts,
    const bak_offline_decode_opts_t *decode_opts, bak_offline_page_range_cb_t range_cb,
    bak_offline_page_data_cb_t data_cb, void *ctx)
{
    if (src_path == NULL || opts == NULL || decode_opts == NULL || (range_cb == NULL && data_cb == NULL)) {
        return OG_ERROR;
    }
    if (opts->expected_payload_size == 0) {
        printf("[ogbackup]skip empty decoded datafile backup piece %s, file_id=%u, backup_level=%u\n",
            src_path, opts->expected_file_id, opts->backup_level);
        return OG_SUCCESS;
    }
    bak_offline_decoded_scan_ctx_t scan = {0};
    scan.src_path = src_path;
    scan.opts = opts;
    scan.range_cb = range_cb;
    scan.data_cb = data_cb;
    scan.cb_ctx = ctx;
    scan.page_buf = (char *)malloc(BAK_OFFLINE_DEFAULT_PAGE_SIZE);
    if (scan.page_buf == NULL) {
        return OG_ERROR;
    }
    status_t status = bak_offline_decode_backup_file(src_path, decode_opts, bak_offline_decoded_plaintext_cb, &scan);
    if (status == OG_SUCCESS && scan.page_buf_used != 0) {
        printf("[ogbackup]decoded data backup file %s size is not aligned to page size %u\n",
            src_path, scan.page_size == 0 ? BAK_OFFLINE_DEFAULT_PAGE_SIZE : scan.page_size);
        status = OG_ERROR;
    }
    CM_FREE_PTR(scan.page_buf);
    return status;
}

status_t bak_offline_apply_data_pages(const char *src_path, const char *dst_path,
    const bak_offline_page_apply_opts_t *opts)
{
    if (src_path == NULL || dst_path == NULL || opts == NULL) {
        return OG_ERROR;
    }
    if (opts->expected_payload_size == 0) {
        return bak_offline_scan_data_page_ranges(src_path, opts, bak_offline_noop_page_cb, NULL);
    }
    device_type_t target_type = opts->target_device_type == 0 ? DEV_TYPE_FILE : opts->target_device_type;
    if (target_type != DEV_TYPE_FILE && target_type != DEV_TYPE_RAW) {
        printf("[ogbackup]unsupported datafile restore target device type %u for %s\n",
            (uint32)target_type, dst_path);
        return OG_ERROR;
    }
    int32 dst_fd = OG_INVALID_HANDLE;
    if (target_type == DEV_TYPE_FILE) {
        if (bak_offline_mkdir_parent(dst_path) != OG_SUCCESS ||
            bak_offline_check_no_symlink(dst_path, OG_TRUE) != OG_SUCCESS) {
            return OG_ERROR;
        }
        dst_fd = open(dst_path, O_CREAT | O_RDWR | O_BINARY, S_IRUSR | S_IWUSR);
        if (dst_fd < 0) {
            printf("[ogbackup]open target datafile %s failed, error %d\n", dst_path, errno);
            return OG_ERROR;
        }
    } else if (bak_offline_open_or_create_device(dst_path, target_type, O_BINARY | O_SYNC | O_RDWR,
        &dst_fd) != OG_SUCCESS) {
        return OG_ERROR;
    }

    bak_offline_apply_ctx_t ctx = {src_path, dst_path, opts, target_type, dst_fd};
    status_t status = bak_offline_scan_data_page_ranges(src_path, opts, bak_offline_apply_page_cb, &ctx);
    if (status == OG_SUCCESS) {
        status = cm_fsync_device(target_type, dst_fd);
        if (status != OG_SUCCESS) {
            printf("[ogbackup]persist restored datafile failed: %s\n", dst_path);
        }
    }
    if (target_type == DEV_TYPE_FILE) {
        (void)close(dst_fd);
    } else {
        cm_close_device(target_type, &dst_fd);
    }
    return status;
}

status_t bak_offline_scan_decoded_data_page_ranges(const char *src_path, const bak_offline_page_apply_opts_t *opts,
    const bak_offline_decode_opts_t *decode_opts, bak_offline_page_range_cb_t cb, void *ctx)
{
    return bak_offline_scan_decoded_data_pages(src_path, opts, decode_opts, cb, NULL, ctx);
}

status_t bak_offline_apply_decoded_data_pages(const char *src_path, const char *dst_path,
    const bak_offline_page_apply_opts_t *opts, const bak_offline_decode_opts_t *decode_opts)
{
    if (src_path == NULL || dst_path == NULL || opts == NULL || decode_opts == NULL) {
        return OG_ERROR;
    }
    device_type_t target_type = opts->target_device_type == 0 ? DEV_TYPE_FILE : opts->target_device_type;
    if (target_type != DEV_TYPE_FILE && target_type != DEV_TYPE_RAW) {
        printf("[ogbackup]unsupported decoded datafile restore target device type %u for %s\n",
            (uint32)target_type, dst_path);
        return OG_ERROR;
    }
    int32 dst_fd = OG_INVALID_HANDLE;
    if (target_type == DEV_TYPE_FILE) {
        if (bak_offline_mkdir_parent(dst_path) != OG_SUCCESS ||
            bak_offline_check_no_symlink(dst_path, OG_TRUE) != OG_SUCCESS) {
            return OG_ERROR;
        }
        dst_fd = open(dst_path, O_CREAT | O_RDWR | O_BINARY, S_IRUSR | S_IWUSR);
        if (dst_fd < 0) {
            printf("[ogbackup]open target datafile %s failed, error %d\n", dst_path, errno);
            return OG_ERROR;
        }
    } else if (bak_offline_open_or_create_device(dst_path, target_type, O_BINARY | O_SYNC | O_RDWR,
        &dst_fd) != OG_SUCCESS) {
        return OG_ERROR;
    }
    bak_offline_apply_ctx_t apply = {src_path, dst_path, opts, target_type, dst_fd};
    status_t status = bak_offline_scan_decoded_data_pages(src_path, opts, decode_opts, NULL,
        bak_offline_apply_page_data_cb, &apply);
    if (status == OG_SUCCESS) {
        status = cm_fsync_device(target_type, dst_fd);
        if (status != OG_SUCCESS) {
            printf("[ogbackup]persist restored decoded datafile failed: %s\n", dst_path);
        }
    }
    if (target_type == DEV_TYPE_FILE) {
        (void)close(dst_fd);
    } else {
        cm_close_device(target_type, &dst_fd);
    }
    return status;
}
