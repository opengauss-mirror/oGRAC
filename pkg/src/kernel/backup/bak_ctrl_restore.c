/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_ctrl_restore.c
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_ctrl_restore.c
 *
 * -------------------------------------------------------------------------
 */

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bak_ctrl_restore.h"
#include "bak_storage_adapter.h"
#include "cm_device.h"
#include "cm_file.h"
#include "cm_text.h"
#include "knl_page.h"
#include "knl_db_ctrl.h"
#include "knl_log_persistent.h"

#define BAK_OFFLINE_SPACE_FLAG_ONLINE 0x0001
#define BAK_OFFLINE_DATAFILE_FLAG_ONLINE 0x01

typedef struct st_bak_offline_ctrl_layout {
    ctrl_page_t *pages;
    char *buf;
    uint64 size;
    uint32 page_count;
    bool32 clustered;
    uint32 node_count;
    uint32 log_segment;
    uint32 space_segment;
    uint32 datafile_segment;
    uint32 arch_segment;
} bak_offline_ctrl_layout_t;

static uint32 bak_offline_ctrl_item_page_id(uint32 id, uint32 item_size, uint32 offset);
static const char *bak_offline_ctrl_log_asn_reason(const bak_offline_ctrl_path_map_item_t *item);

/*
 * DSS fallocate reserves space but does not guarantee that a reused extent
 * reads as zero.  Control-only redo files are scanned from the first block
 * after the header during recovery, so initialize that scan window explicitly
 * after extending the target device.
 */
static status_t bak_offline_zero_device_range(device_type_t type, int32 handle, int64 offset, int64 size,
    const char *target)
{
    if (size <= 0) {
        return OG_SUCCESS;
    }

    char zero_buf[SIZE_K(64)] = {0};
    int64 remain = size;
    while (remain > 0) {
        int32 write_size = (remain > (int64)sizeof(zero_buf)) ? (int32)sizeof(zero_buf) : (int32)remain;
        if (cm_write_device(type, handle, offset, zero_buf, write_size) != OG_SUCCESS) {
            printf("[ogbackup]zero mapped redo/log scan window failed: target=%s offset=%lld size=%d\n",
                target, offset, write_size);
            return OG_ERROR;
        }
        offset += write_size;
        remain -= write_size;
    }
    return OG_SUCCESS;
}

/*
 * Prefix mirror of dtc_node_ctrl_t on the control page.  The session-free
 * offline reader only needs archived_start/end to iterate archive control ring
 * slots.  Keep this field order synchronized with dtc_database.h; this is a
 * persistent control-page layout, not an independent runtime structure.
 */
typedef struct st_dtc_node_ctrl {
    atomic_t scn;
    log_point_t rcy_point;
    log_point_t lrp_point;
    uint64 ckpt_id;
    atomic_t lsn;
    atomic_t lfn;
    uint32 log_count;
    uint32 log_hwm;
    uint32 log_first;
    uint32 log_last;
    bool32 shutdown_consistency;
    bool32 open_inconsistency;
    uint64 consistent_lfn;
    uint32 undo_space;
    uint32 swap_space;
    uint32 archived_start;
    uint32 archived_end;
} dtc_node_ctrl_t;

static status_t bak_offline_read_exact(int32 fd, char *buf, uint64 size, const char *path)
{
    uint64 offset = 0;

    while (offset < size) {
        ssize_t read_size = pread(fd, buf + offset, (size_t)(size - offset), (off_t)offset);
        if (read_size <= 0) {
            printf("[ogbackup]read control backup piece %s failed at offset %llu, error %d (%s)\n",
                path, offset, errno, strerror(errno));
            return OG_ERROR;
        }
        offset += (uint64)read_size;
    }
    return OG_SUCCESS;
}

static bool32 bak_offline_ctrl_size_supported(uint64 size)
{
    uint64 nonclustered_size = (uint64)CTRL_MAX_PAGES_NONCLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE;
    uint64 clustered_size = (uint64)CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE;

    return (size == nonclustered_size || size == clustered_size) ? OG_TRUE : OG_FALSE;
}

bool32 bak_offline_ctrl_buffer_has_dss_path(const char *buf, uint64 size)
{
    if (buf == NULL || size < 3) {
        return OG_FALSE;
    }

    for (uint64 i = 0; i + 2 < size; i++) {
        if (buf[i] != '+') {
            continue;
        }
        if ((buf[i + 1] == 'v' || buf[i + 1] == 'V') && (buf[i + 2] == 'g' || buf[i + 2] == 'G')) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static bool32 bak_offline_ctrl_buffer_contains(const char *buf, uint64 size, const char *value)
{
    size_t len = (value == NULL) ? 0 : strlen(value);
    if (buf == NULL || len == 0 || size < len) {
        return OG_FALSE;
    }
    for (uint64 i = 0; i + len <= size; i++) {
        if (memcmp(buf + i, value, len) == 0) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t bak_offline_verify_ctrl_checksum(const char *buf, uint32 page_count, const char *path)
{
    ctrl_page_t *pages = (ctrl_page_t *)buf;

    for (uint32 i = 0; i < page_count; i++) {
        if (pages[i].tail.checksum == OG_INVALID_CHECKSUM) {
            continue;
        }
        if (!page_verify_checksum((page_head_t *)&pages[i], OG_DFLT_CTRL_BLOCK_SIZE)) {
            printf("[ogbackup]control page checksum mismatch in %s at page %u, block size %u\n",
                path, i, (uint32)OG_DFLT_CTRL_BLOCK_SIZE);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t bak_offline_ctrl_load_buffer(const char *src_path, uint64 expected_payload_size, char **buf, uint64 *size,
    uint32 *page_count)
{
    if (src_path == NULL || buf == NULL || size == NULL || page_count == NULL) {
        return OG_ERROR;
    }
    *buf = NULL;
    *size = 0;
    *page_count = 0;

    int32 fd = open(src_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        printf("[ogbackup]open control backup piece %s failed, error %d (%s)\n", src_path, errno, strerror(errno));
        return OG_ERROR;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        printf("[ogbackup]stat control backup piece %s failed, error %d (%s)\n", src_path, errno, strerror(errno));
        (void)close(fd);
        return OG_ERROR;
    }
    uint64 actual_size = (uint64)st.st_size;
    if (expected_payload_size != actual_size) {
        printf("[ogbackup]control backup piece size mismatch for %s, expected %llu, actual %llu\n",
            src_path, expected_payload_size, actual_size);
        (void)close(fd);
        return OG_ERROR;
    }
    if (actual_size == 0 || actual_size % OG_DFLT_CTRL_BLOCK_SIZE != 0 ||
        bak_offline_ctrl_size_supported(actual_size) != OG_TRUE) {
        printf("[ogbackup]unsupported control backup piece size %llu for %s; expected %llu or %llu bytes\n",
            actual_size, src_path,
            (uint64)CTRL_MAX_PAGES_NONCLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE,
            (uint64)CTRL_MAX_PAGES_CLUSTERED * OG_DFLT_CTRL_BLOCK_SIZE);
        (void)close(fd);
        return OG_ERROR;
    }

    char *local_buf = (char *)malloc((size_t)actual_size);
    if (local_buf == NULL) {
        printf("[ogbackup]allocate control restore buffer failed, size=%llu\n", actual_size);
        (void)close(fd);
        return OG_ERROR;
    }
    status_t status = bak_offline_read_exact(fd, local_buf, actual_size, src_path);
    (void)close(fd);
    if (status != OG_SUCCESS) {
        CM_FREE_PTR(local_buf);
        return OG_ERROR;
    }
    uint32 local_page_count = (uint32)(actual_size / OG_DFLT_CTRL_BLOCK_SIZE);
    if (bak_offline_verify_ctrl_checksum(local_buf, local_page_count, src_path) != OG_SUCCESS) {
        CM_FREE_PTR(local_buf);
        return OG_ERROR;
    }

    *buf = local_buf;
    *size = actual_size;
    *page_count = local_page_count;
    return OG_SUCCESS;
}

void bak_offline_ctrl_free_buffer(char *buf)
{
    CM_FREE_PTR(buf);
}

static status_t bak_offline_write_exact(int32 fd, const char *buf, uint64 size, const char *path)
{
    uint64 offset = 0;

    while (offset < size) {
        ssize_t write_size = write(fd, buf + offset, (size_t)(size - offset));
        if (write_size <= 0) {
            printf("[ogbackup]write raw control file %s failed at offset %llu, error %d (%s)\n",
                path, offset, errno, strerror(errno));
            return OG_ERROR;
        }
        offset += (uint64)write_size;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_fsync_parent(const char *path)
{
    char parent[OG_MAX_FILE_PATH_LENGH] = {0};
    if (path == NULL || strlen(path) >= sizeof(parent) || strcpy_s(parent, sizeof(parent), path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(parent, '/');
    if (slash == NULL) {
        return OG_SUCCESS;
    }
    *slash = '\0';
    const char *dir = parent[0] == '\0' ? "/" : parent;
    int32 fd = open(dir, O_RDONLY | O_BINARY);
    if (fd < 0) {
        printf("[ogbackup]open control parent directory for fsync failed: %s errno=%d (%s)\n",
            dir, errno, strerror(errno));
        return OG_ERROR;
    }
    status_t status = fsync(fd) == 0 ? OG_SUCCESS : OG_ERROR;
    if (status != OG_SUCCESS) {
        printf("[ogbackup]fsync control parent directory failed: %s errno=%d (%s)\n",
            dir, errno, strerror(errno));
    }
    (void)close(fd);
    return status;
}

static status_t bak_offline_write_raw_ctrl_file(const char *path, const char *buf, uint64 size)
{
    if (bak_offline_check_no_symlink(path, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    int32 fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        printf("[ogbackup]open raw control file %s failed, error %d (%s)\n", path, errno, strerror(errno));
        return OG_ERROR;
    }

    status_t status = bak_offline_write_exact(fd, buf, size, path);
    if (status == OG_SUCCESS && fsync(fd) != 0) {
        printf("[ogbackup]fsync raw control file %s failed, error %d (%s)\n", path, errno, strerror(errno));
        status = OG_ERROR;
    }
    (void)close(fd);
    if (status == OG_SUCCESS) {
        status = bak_offline_fsync_parent(path);
    }
    return status;
}

static status_t bak_offline_create_ctrl_parent(const char *path);

static uint32 bak_offline_ctrl_ring_distance(uint32 first, uint32 id, uint32 hwm, bool32 *in_range, uint32 last)
{
    *in_range = OG_FALSE;
    if (hwm == 0 || hwm > OG_MAX_LOG_FILES || first >= hwm || last >= hwm || id >= hwm) {
        return 0;
    }

    uint32 pos = first;
    for (uint32 distance = 0; distance < hwm; distance++) {
        if (pos == id) {
            *in_range = OG_TRUE;
            return distance;
        }
        if (pos == last) {
            break;
        }
        pos = (pos + 1) % hwm;
    }
    return 0;
}

static status_t bak_offline_ctrl_set_log_asn_reason(bak_offline_ctrl_path_map_item_t *item, const char *reason)
{
    errno_t ret = strcpy_s(item->log_asn_reason, sizeof(item->log_asn_reason), reason);
    return ret == EOK ? OG_SUCCESS : OG_ERROR;
}

static status_t bak_offline_ctrl_select_log_head_asn(bak_offline_ctrl_path_map_item_t *item)
{
    if (item->log_status == LOG_FILE_UNUSED) {
        item->generated_log_head_asn = OG_INVALID_ASN;
        return bak_offline_ctrl_set_log_asn_reason(item, "unused");
    }

    if (item->rcy_asn == 0 || item->rcy_asn == OG_INVALID_ASN || item->log_hwm == 0 ||
        item->log_hwm > OG_MAX_LOG_FILES || item->log_first >= item->log_hwm ||
        item->log_last >= item->log_hwm) {
        printf("[ogbackup]cannot derive mapped redo/log header ASN from control recovery state: "
               "node=%u file=%u status=%u rcy=[%u-%u/%u/%llu] lrp=[%u-%u/%u/%llu] "
               "log_first=%u log_last=%u log_hwm=%u\n",
            item->node_id, item->file_id, item->log_status, item->rcy_rst_id, item->rcy_asn,
            item->rcy_block_id, item->rcy_lfn, item->lrp_rst_id, item->lrp_asn, item->lrp_block_id,
            item->lrp_lfn, item->log_first, item->log_last, item->log_hwm);
        return OG_ERROR;
    }

    bool32 in_active_range = OG_FALSE;
    uint32 distance = bak_offline_ctrl_ring_distance(item->log_first, item->file_id,
        item->log_hwm, &in_active_range, item->log_last);
    if (in_active_range != OG_TRUE) {
        item->generated_log_head_asn = OG_INVALID_ASN;
        return bak_offline_ctrl_set_log_asn_reason(item, "outside-active-range");
    }

    if (item->file_id == item->log_last || item->log_status == LOG_FILE_CURRENT) {
        item->generated_log_head_asn = (item->rcy_block_id <= 1) ? item->rcy_asn : item->rcy_asn + 1;
        return bak_offline_ctrl_set_log_asn_reason(item, "current-from-rcy-point");
    }

    item->generated_log_head_asn = item->rcy_asn + distance;
    return bak_offline_ctrl_set_log_asn_reason(item, "active-range-from-rcy-point");
}

static const char *bak_offline_ctrl_log_asn_reason(const bak_offline_ctrl_path_map_item_t *item)
{
    return item->log_asn_reason[0] == '\0' ? "not-selected" : item->log_asn_reason;
}

static status_t bak_offline_build_log_head_file(bak_offline_ctrl_path_map_t *map,
    bak_offline_ctrl_path_map_item_t *item)
{
    if (item->target_size == 0 || item->target_size > (uint64)LLONG_MAX) {
        printf("[ogbackup]mapped redo/log file has invalid control size: file=%u node=%u size=%llu target=%s\n",
            item->file_id, item->node_id, item->target_size, item->target_path);
        return OG_ERROR;
    }
    uint16 block_size = item->log_block_size == 0 ? OG_DFLT_LOG_BLOCK_SIZE : item->log_block_size;
    uint32 head_size = CM_CALC_ALIGN((uint32)sizeof(log_file_head_t), block_size);
    if (item->target_size < head_size) {
        printf("[ogbackup]mapped redo/log file is smaller than log header: file=%u node=%u size=%llu "
               "head_size=%u target=%s\n",
            item->file_id, item->node_id, item->target_size, head_size, item->target_path);
        return OG_ERROR;
    }

    device_type_t type = map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS ? DEV_TYPE_RAW : DEV_TYPE_FILE;
    int32 handle = OG_INVALID_HANDLE;
    if (type == DEV_TYPE_FILE) {
        if (bak_offline_check_no_symlink(item->target_path, OG_TRUE) != OG_SUCCESS ||
            bak_offline_create_ctrl_parent(item->target_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        uint32 open_flags = O_CREAT | O_RDWR | O_BINARY;
        if (map->inplace_restore != OG_TRUE) {
            open_flags |= O_EXCL;
        }
        handle = open(item->target_path, (int32)open_flags, S_IRUSR | S_IWUSR);
        if (handle < 0) {
            printf("[ogbackup]create mapped redo/log file %s failed, error %d (%s)\n",
                item->target_path, errno, strerror(errno));
            return OG_ERROR;
        }
    } else {
        if (cm_device_type(item->target_path) != DEV_TYPE_RAW) {
            printf("[ogbackup]mapped DSS redo/log target is not a DSS path: file=%u node=%u target=%s\n",
                item->file_id, item->node_id, item->target_path);
            return OG_ERROR;
        }
        if (bak_offline_create_device_parent(type, item->target_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (cm_exist_device(type, item->target_path) && map->dss_inplace_restore != OG_TRUE) {
            printf("[ogbackup]mapped DSS redo/log target already exists and will not be overwritten: %s\n",
                item->target_path);
            return OG_ERROR;
        }
        if (map->dss_inplace_restore == OG_TRUE) {
            if (bak_offline_open_or_create_device(item->target_path, type, O_BINARY | O_SYNC | O_RDWR,
                &handle) != OG_SUCCESS) {
                printf("[ogbackup]open in-place DSS redo/log device %s failed\n", item->target_path);
                return OG_ERROR;
            }
        } else if (cm_create_device(item->target_path, type, O_BINARY | O_SYNC | O_RDWR, &handle) != OG_SUCCESS) {
            printf("[ogbackup]create mapped DSS redo/log device %s failed\n", item->target_path);
            return OG_ERROR;
        }
        if (map->dss_inplace_restore == OG_TRUE && cm_truncate_device(type, handle, 0) != OG_SUCCESS) {
            printf("[ogbackup]truncate in-place DSS redo/log device %s failed\n", item->target_path);
            cm_close_device(type, &handle);
            return OG_ERROR;
        }
    }

    char *head_buf = (char *)malloc(head_size);
    if (head_buf == NULL) {
        printf("[ogbackup]allocate mapped redo/log header buffer failed: size=%u target=%s\n",
            head_size, item->target_path);
        if (type == DEV_TYPE_FILE) {
            (void)close(handle);
        } else {
            cm_close_device(type, &handle);
        }
        return OG_ERROR;
    }
    errno_t ret = memset_s(head_buf, head_size, 0, head_size);
    if (ret != EOK) {
        CM_FREE_PTR(head_buf);
        if (type == DEV_TYPE_FILE) {
            (void)close(handle);
        } else {
            cm_close_device(type, &handle);
        }
        return OG_ERROR;
    }

    log_file_head_t *head = (log_file_head_t *)head_buf;
    if (item->log_asn_reason[0] == '\0') {
        printf("[ogbackup]mapped redo/log file has no ASN selection reason: file=%u node=%u target=%s\n",
            item->file_id, item->node_id, item->target_path);
        CM_FREE_PTR(head_buf);
        if (type == DEV_TYPE_FILE) {
            (void)close(handle);
        } else {
            cm_close_device(type, &handle);
        }
        return OG_ERROR;
    }
    uint32 head_asn = item->generated_log_head_asn;
    head->first = OG_INVALID_ID64;
    head->last = OG_INVALID_ID64;
    head->write_pos = head_size;
    head->asn = head_asn;
    head->block_size = (int32)block_size;
    head->cmp_algorithm = COMPRESS_NONE;
    head->rst_id = item->log_rst_id;
    head->checksum = OG_INVALID_CHECKSUM;
    head->dbid = item->log_dbid;

    status_t status = OG_SUCCESS;
    uint64 scan_window = 0;
    if (type == DEV_TYPE_FILE) {
        if (cm_truncate_file(handle, (int64)item->target_size) != OG_SUCCESS) {
            printf("[ogbackup]truncate mapped redo/log file failed: file=%u node=%u size=%llu target=%s\n",
                item->file_id, item->node_id, item->target_size, item->target_path);
            status = OG_ERROR;
        } else if (bak_offline_write_exact(handle, head_buf, head_size, item->target_path) != OG_SUCCESS) {
            status = OG_ERROR;
        } else if (fsync(handle) != 0) {
            printf("[ogbackup]fsync mapped redo/log file %s failed, error %d (%s)\n",
                item->target_path, errno, strerror(errno));
            status = OG_ERROR;
        }
    } else {
        char zero_buf[SIZE_K(64)] = {0};
        scan_window = item->target_size - head_size;
        if (scan_window > (uint64)OG_MAX_BATCH_SIZE) {
            scan_window = (uint64)OG_MAX_BATCH_SIZE;
        }
        if (cm_extend_device(type, handle, zero_buf, sizeof(zero_buf), (int64)item->target_size,
            OG_TRUE) != OG_SUCCESS) {
            printf("[ogbackup]extend mapped DSS redo/log file failed: file=%u node=%u size=%llu target=%s\n",
                item->file_id, item->node_id, item->target_size, item->target_path);
            status = OG_ERROR;
        } else if (bak_offline_zero_device_range(type, handle, (int64)head_size, (int64)scan_window,
                       item->target_path) != OG_SUCCESS) {
            status = OG_ERROR;
        } else if (cm_write_device(type, handle, 0, head_buf, (int32)head_size) != OG_SUCCESS) {
            printf("[ogbackup]write mapped DSS redo/log header failed: file=%u node=%u target=%s\n",
                item->file_id, item->node_id, item->target_path);
            status = OG_ERROR;
        } else if (cm_fsync_device(type, handle) != OG_SUCCESS) {
            printf("[ogbackup]fsync mapped DSS redo/log file %s failed\n", item->target_path);
            status = OG_ERROR;
        }
    }

    CM_FREE_PTR(head_buf);
    if (type == DEV_TYPE_FILE) {
        (void)close(handle);
        if (status == OG_SUCCESS) {
            status = bak_offline_fsync_parent(item->target_path);
        }
    } else {
        cm_close_device(type, &handle);
    }
    if (status == OG_SUCCESS) {
        printf("[ogbackup][ctrl-debug] mapped redo/log file initialized: file=%u node=%u target=%s "
               "control_size=%llu head_size=%u block_size=%u status=%u asn=%u rst=%u dbid=%u "
               "zeroed_scan_window=%llu "
               "checksum=kept-invalid rcy_point=[%u-%u/%u/%llu/%llu] lrp_point=[%u-%u/%u/%llu/%llu] "
               "selected_current_log=%u asn_reason=%s\n",
            item->file_id, item->node_id, item->target_path, item->target_size, head_size,
            (uint32)block_size, item->log_status, head_asn, item->log_rst_id, item->log_dbid, scan_window,
            item->rcy_rst_id, item->rcy_asn, item->rcy_block_id, item->rcy_lfn, item->rcy_lsn,
            item->lrp_rst_id, item->lrp_asn, item->lrp_block_id, item->lrp_lfn, item->lrp_lsn,
            item->log_last, bak_offline_ctrl_log_asn_reason(item));
    }
    return status;
}

static status_t bak_offline_prepare_ctrl_targets(const char *target_dir, bak_offline_ctrl_restore_result_t *result)
{
    char rel_path[OG_MAX_FILE_PATH_LENGH] = {0};

    for (uint32 i = 0; i < BAK_OFFLINE_CTRL_FILE_COUNT; i++) {
        int32 ret = snprintf_s(rel_path, sizeof(rel_path), sizeof(rel_path) - 1, "data/ctrl%u", i + 1);
        if (ret == -1) {
            return OG_ERROR;
        }
        if (bak_offline_resolve_target_path(target_dir, rel_path, result->raw_ctrl_files[i],
            OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    result->raw_ctrl_file_count = BAK_OFFLINE_CTRL_FILE_COUNT;
    return OG_SUCCESS;
}

static status_t bak_offline_create_ctrl_parent(const char *path)
{
    char parent[OG_MAX_FILE_PATH_LENGH] = {0};
    if (path == NULL || strlen(path) >= sizeof(parent) || strcpy_s(parent, sizeof(parent), path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(parent, '/');
    if (slash == NULL) {
        return OG_SUCCESS;
    }
    *slash = '\0';
    if (parent[0] == '\0' || cm_dir_exist(parent)) {
        return OG_SUCCESS;
    }
    if (cm_create_dir_ex(parent) != OG_SUCCESS) {
        printf("[ogbackup]create raw control file parent %s failed, error %d (%s)\n",
            parent, errno, strerror(errno));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 bak_offline_ctrl_space_is_required(space_ctrl_t *space)
{
    return (space != NULL && space->used == OG_TRUE &&
        (space->flag & BAK_OFFLINE_SPACE_FLAG_ONLINE) != 0) ? OG_TRUE : OG_FALSE;
}

static bool32 bak_offline_ctrl_datafile_is_required(datafile_ctrl_t *ctrl)
{
    return (ctrl != NULL && ctrl->used == OG_TRUE &&
        (ctrl->flag & BAK_OFFLINE_DATAFILE_FLAG_ONLINE) != 0) ? OG_TRUE : OG_FALSE;
}

static status_t bak_offline_ctrl_set_datafile_space_info(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_item_t *item, datafile_ctrl_t *df_ctrl)
{
    item->datafile_required = OG_FALSE;
    item->datafile_flag = (uint32)df_ctrl->flag;
    item->datafile_space_id = OG_INVALID_ID32;
    item->datafile_file_no = OG_INVALID_ID32;
    item->datafile_space_type = 0;

    for (uint32 space_id = 0; space_id < OG_MAX_SPACES; space_id++) {
        uint32 page_id = bak_offline_ctrl_item_page_id(space_id, sizeof(space_ctrl_t), layout->space_segment);
        if (page_id >= layout->page_count) {
            return OG_ERROR;
        }
        space_ctrl_t *space = (space_ctrl_t *)db_get_ctrl_item(layout->pages, space_id, sizeof(space_ctrl_t),
            layout->space_segment);
        for (uint32 file_no = 0; file_no < space->file_hwm && file_no < OG_MAX_SPACE_FILES; file_no++) {
            if (space->files[file_no] != item->file_id) {
                continue;
            }
            item->datafile_space_id = space_id;
            item->datafile_file_no = file_no;
            item->datafile_space_type = space->type;
            if (bak_offline_ctrl_datafile_is_required(df_ctrl) == OG_TRUE &&
                bak_offline_ctrl_space_is_required(space) == OG_TRUE) {
                item->datafile_required = OG_TRUE;
            }
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_init_layout(char *buf, uint64 size, bak_offline_ctrl_layout_t *layout)
{
    if (buf == NULL || layout == NULL || size % OG_DFLT_CTRL_BLOCK_SIZE != 0) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(layout, sizeof(bak_offline_ctrl_layout_t), 0, sizeof(bak_offline_ctrl_layout_t));
    if (ret != EOK) {
        return OG_ERROR;
    }

    layout->pages = (ctrl_page_t *)buf;
    layout->buf = buf;
    layout->size = size;
    layout->page_count = (uint32)(size / OG_DFLT_CTRL_BLOCK_SIZE);
    if (layout->page_count != CTRL_MAX_PAGES_NONCLUSTERED && layout->page_count != CTRL_MAX_PAGES_CLUSTERED) {
        return OG_ERROR;
    }

    core_ctrl_t *core = (core_ctrl_t *)layout->pages[CORE_CTRL_PAGE_ID].buf;
    layout->clustered = (core->clustered == OG_TRUE || layout->page_count == CTRL_MAX_PAGES_CLUSTERED) ?
        OG_TRUE : OG_FALSE;
    layout->node_count = layout->clustered == OG_TRUE ? core->node_count : 1;
    if (layout->node_count == 0 || layout->node_count > OG_MAX_INSTANCES) {
        layout->node_count = layout->clustered == OG_TRUE ? OG_MAX_INSTANCES : 1;
    }

    uint32 offset = layout->clustered == OG_TRUE ? (OG_MAX_INSTANCES + CTRL_LOG_SEGMENT) :
        (1 + CTRL_LOG_SEGMENT);
    layout->log_segment = offset;

    uint32 log_count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 log_pages_per_inst = (OG_MAX_LOG_FILES - 1) / log_count + 1;
    uint32 inst_count = layout->clustered == OG_TRUE ? OG_MAX_INSTANCES : 1;
    offset += log_pages_per_inst * inst_count;

    layout->space_segment = offset;
    uint32 space_count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    offset += (OG_MAX_SPACES - 1) / space_count + 1;

    layout->datafile_segment = offset;
    uint32 datafile_count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    offset += (OG_MAX_DATA_FILES - 1) / datafile_count + 1;

    layout->arch_segment = offset;
    if (layout->arch_segment >= layout->page_count) {
        printf("[ogbackup]control file layout is invalid: arch segment %u page_count %u\n",
            layout->arch_segment, layout->page_count);
        return OG_ERROR;
    }
    printf("[ogbackup][ctrl-debug] raw control size=%llu page_count=%u clustered=%u node_count=%u "
           "log_segment=%u space_segment=%u datafile_segment=%u arch_segment=%u\n",
        size, layout->page_count, (uint32)layout->clustered, layout->node_count, layout->log_segment,
        layout->space_segment, layout->datafile_segment, layout->arch_segment);
    return OG_SUCCESS;
}

static void bak_offline_ctrl_debug_scan_token(bak_offline_ctrl_layout_t *layout, const char *token)
{
    size_t token_len = (token == NULL) ? 0 : strlen(token);
    if (layout == NULL || layout->buf == NULL || token_len == 0 || layout->size < token_len) {
        return;
    }

    uint32 printed = 0;
    for (uint64 i = 0; i + token_len <= layout->size && printed < 8; i++) {
        if (memcmp(layout->buf + i, token, token_len) == 0) {
            printf("[ogbackup][ctrl-debug] control buffer token \"%s\" offset=%llu page=%llu page_offset=%llu\n",
                token, i, i / OG_DFLT_CTRL_BLOCK_SIZE, i % OG_DFLT_CTRL_BLOCK_SIZE);
            printed++;
        }
    }
    if (printed == 0) {
        printf("[ogbackup][ctrl-debug] control buffer token \"%s\" not found\n", token);
    }
}

static uint32 bak_offline_ctrl_item_page_id(uint32 id, uint32 item_size, uint32 offset)
{
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    return offset + id / count;
}

static uint32 bak_offline_ctrl_log_item_page_id(uint32 id, uint32 item_size, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    uint32 pages_per_inst = (OG_MAX_LOG_FILES - 1) / count + 1;
    return offset + pages_per_inst * node_id + id / count;
}

static uint32 bak_offline_ctrl_arch_item_page_id(uint32 id, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 pages_per_inst = (OG_MAX_ARCH_NUM - 1) / count + 1;
    return offset + pages_per_inst * node_id + id / count;
}

static arch_ctrl_t *bak_offline_ctrl_get_arch_item(ctrl_page_t *pages, uint32 id, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 page_id = bak_offline_ctrl_arch_item_page_id(id, offset, node_id);
    uint32 slot = id % count;
    return (arch_ctrl_t *)(pages[page_id].buf + slot * sizeof(arch_ctrl_t));
}

static dtc_node_ctrl_t *bak_offline_ctrl_get_node_ctrl(bak_offline_ctrl_layout_t *layout, uint32 node_id)
{
    uint32 node_page_id = CTRL_LOG_SEGMENT + node_id;
    if (node_page_id >= layout->page_count) {
        return NULL;
    }
    return (dtc_node_ctrl_t *)layout->pages[node_page_id].buf;
}

static status_t bak_offline_ctrl_read_archive_head(bak_offline_ctrl_path_map_item_t *item)
{
    if (item->source_path[0] == '\0') {
        printf("[ogbackup]archive control path rewrite unsupported for this backupset/control layout: "
               "asn=%u rst=%u node=%u source path is empty\n",
            item->file_id, item->rst_id, item->node_id);
        return OG_ERROR;
    }

    int32 fd = open(item->source_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        printf("[ogbackup]open archive backup piece %s failed, error %d (%s)\n",
            item->source_path, errno, strerror(errno));
        return OG_ERROR;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        printf("[ogbackup]stat archive backup piece %s failed, error %d (%s)\n",
            item->source_path, errno, strerror(errno));
        (void)close(fd);
        return OG_ERROR;
    }
    uint64 actual_size = (uint64)st.st_size;
    if (item->source_size != 0 && item->source_size != actual_size) {
        printf("[ogbackup]archive backup piece size mismatch for %s, expected %llu, actual %llu\n",
            item->source_path, item->source_size, actual_size);
        (void)close(fd);
        return OG_ERROR;
    }
    if (actual_size < sizeof(log_file_head_t)) {
        printf("[ogbackup]archive backup piece %s is too short for log header, size=%llu header=%u\n",
            item->source_path, actual_size, (uint32)sizeof(log_file_head_t));
        (void)close(fd);
        return OG_ERROR;
    }

    log_file_head_t head;
    errno_t ret = memset_s(&head, sizeof(head), 0, sizeof(head));
    if (ret != EOK) {
        (void)close(fd);
        return OG_ERROR;
    }
    ssize_t read_size = pread(fd, &head, sizeof(head), 0);
    (void)close(fd);
    if (read_size != (ssize_t)sizeof(head)) {
        printf("[ogbackup]read archive backup piece header %s failed, read=%zd, error %d (%s)\n",
            item->source_path, read_size, errno, strerror(errno));
        return OG_ERROR;
    }
    if (head.asn != item->file_id || (item->rst_id != 0 && head.rst_id != item->rst_id)) {
        printf("[ogbackup]archive backup piece header mismatch for %s, catalog asn=%u rst=%u, "
               "header asn=%u rst=%u\n",
            item->source_path, item->file_id, item->rst_id, head.asn, head.rst_id);
        return OG_ERROR;
    }
    if (head.block_size <= 0 || (uint32)head.block_size > OG_DFLT_CTRL_BLOCK_SIZE ||
        head.write_pos < CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)head.block_size) ||
        head.write_pos > actual_size) {
        printf("[ogbackup]archive backup piece header is invalid for %s, block_size=%d write_pos=%llu size=%llu\n",
            item->source_path, head.block_size, head.write_pos, actual_size);
        return OG_ERROR;
    }

    item->rst_id = head.rst_id;
    item->arch_block_size = (uint32)head.block_size;
    item->arch_blocks = (int32)(head.write_pos / (uint32)head.block_size);
    item->arch_first = (uint64)head.first;
    item->arch_last = (uint64)head.last;
    item->arch_start_lsn = head.first_lsn;
    item->arch_end_lsn = head.last_lsn;
    item->arch_real_size = (int64)actual_size;
    item->arch_stamp = head.arch_ctrl_stamp;
    item->arch_dest_id = head.dest_id;
    printf("[ogbackup][ctrl-debug] archive catalog/header source=%s asn=%u rst=%u node=%u "
           "size=%llu block_size=%u blocks=%d start_lsn=%llu end_lsn=%llu\n",
        item->source_path, item->file_id, item->rst_id, item->node_id, actual_size,
        item->arch_block_size, item->arch_blocks, item->arch_start_lsn, item->arch_end_lsn);
    return OG_SUCCESS;
}

static bool32 bak_offline_ctrl_path_has_dss_prefix(const char *path)
{
    return (path != NULL && path[0] == '+' && path[1] != '\0') ? OG_TRUE : OG_FALSE;
}

static bool32 bak_offline_ctrl_text_empty(const char *str)
{
    return (str == NULL || str[0] == '\0') ? OG_TRUE : OG_FALSE;
}

static bool32 bak_offline_ctrl_dss_prefix_matches(const char *path, const char *prefix, uint32 prefix_len)
{
    if (path == NULL || prefix == NULL || prefix_len == 0 || strncmp(path, prefix, prefix_len) != 0) {
        return OG_FALSE;
    }
    return (path[prefix_len] == '\0' || path[prefix_len] == '/') ? OG_TRUE : OG_FALSE;
}

static status_t bak_offline_ctrl_copy_dss_segment(char *dst, uint32 dst_size, const char *src, uint32 len)
{
    if (src == NULL || len == 0 || len >= dst_size || src[0] != '+') {
        return OG_ERROR;
    }
    errno_t ret = memset_s(dst, dst_size, 0, dst_size);
    ret |= memcpy_s(dst, dst_size, src, len);
    return ret == EOK ? OG_SUCCESS : OG_ERROR;
}

static status_t bak_offline_ctrl_apply_dss_map(const bak_offline_ctrl_path_map_t *map, const char *src_path,
    char *dst_path, uint32 dst_size, bool32 *mapped)
{
    if (src_path == NULL || dst_path == NULL || mapped == NULL ||
        bak_offline_ctrl_path_has_dss_prefix(src_path) != OG_TRUE) {
        return OG_ERROR;
    }
    *mapped = OG_FALSE;
    if (bak_offline_ctrl_text_empty(map->dss_map) == OG_TRUE) {
        if (strcpy_s(dst_path, dst_size, src_path) != EOK) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    const char *pos = map->dss_map;
    while (*pos != '\0') {
        const char *comma = strchr(pos, ',');
        uint32 pair_len = comma == NULL ? (uint32)strlen(pos) : (uint32)(comma - pos);
        const char *colon = memchr(pos, ':', pair_len);
        if (colon == NULL) {
            printf("[ogbackup]invalid --dss-map item, expected SRC:DST in %.*s\n", (int32)pair_len, pos);
            return OG_ERROR;
        }
        uint32 src_len = (uint32)(colon - pos);
        uint32 dst_len = pair_len - src_len - 1;
        char src_prefix[OG_NAME_BUFFER_SIZE] = {0};
        char dst_prefix[OG_NAME_BUFFER_SIZE] = {0};
        if (bak_offline_ctrl_copy_dss_segment(src_prefix, sizeof(src_prefix), pos, src_len) != OG_SUCCESS ||
            bak_offline_ctrl_copy_dss_segment(dst_prefix, sizeof(dst_prefix), colon + 1, dst_len) != OG_SUCCESS) {
            printf("[ogbackup]invalid --dss-map item, source and target must be DSS paths: %.*s\n",
                (int32)pair_len, pos);
            return OG_ERROR;
        }
        if (bak_offline_ctrl_dss_prefix_matches(src_path, src_prefix, src_len) == OG_TRUE) {
            const char *suffix = src_path + src_len;
            if (snprintf_s(dst_path, dst_size, dst_size - 1, "%s%s", dst_prefix, suffix) == -1) {
                return OG_ERROR;
            }
            if (strcmp(dst_path, src_path) == 0) {
                printf("[ogbackup]DSS target mapping keeps original path and is refused: %s -> %s\n",
                    src_path, dst_path);
                return OG_ERROR;
            }
            *mapped = OG_TRUE;
            return OG_SUCCESS;
        }
        if (comma == NULL) {
            break;
        }
        pos = comma + 1;
    }

    if (map->dss_map_required == OG_TRUE) {
        printf("[ogbackup]DSS target mapping missing for path: %s\n", src_path);
        return OG_ERROR;
    }
    if (strcpy_s(dst_path, dst_size, src_path) != EOK) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 bak_offline_ctrl_path_under_dir(const char *target_dir, const char *target_path)
{
    size_t len = (target_dir == NULL) ? 0 : strlen(target_dir);
    if (len == 0 || target_path == NULL || target_path[0] != '/' ||
        strncmp(target_path, target_dir, len) != 0) {
        return OG_FALSE;
    }
    return (target_path[len] == '\0' || target_path[len] == '/') ? OG_TRUE : OG_FALSE;
}

static status_t bak_offline_ctrl_validate_target_path(const char *target_dir,
    bak_offline_ctrl_path_map_item_t *item, bool32 inplace_restore)
{
    if (item->target_path[0] == '\0' || strlen(item->target_path) >= OG_FILE_NAME_BUFFER_SIZE) {
        printf("[ogbackup]path-map target path is too long for control item type=%u file=%u node=%u: %s\n",
            (uint32)item->type, item->file_id, item->node_id, item->target_path);
        return OG_ERROR;
    }
    if (item->target_path[0] == '+') {
        return bak_offline_ctrl_path_has_dss_prefix(item->target_path) == OG_TRUE ? OG_SUCCESS : OG_ERROR;
    }
    if (inplace_restore == OG_TRUE) {
        if (item->target_path[0] != '/' || strstr(item->target_path, "/../") != NULL ||
            strstr(item->target_path, "/./") != NULL) {
            printf("[ogbackup]in-place restore target from control metadata is unsafe: %s\n", item->target_path);
            return OG_ERROR;
        }
        return bak_offline_check_no_symlink(item->target_path, OG_TRUE);
    }
    if (bak_offline_ctrl_path_under_dir(target_dir, item->target_path) != OG_TRUE) {
        printf("[ogbackup]path-map target path escapes target-dir, target-dir=%s target=%s\n",
            target_dir, item->target_path);
        return OG_ERROR;
    }
    if (strstr(item->target_path, "/../") != NULL || strstr(item->target_path, "/./") != NULL ||
        bak_offline_ctrl_path_has_dss_prefix(item->target_path) == OG_TRUE) {
        printf("[ogbackup]path-map target path is unsafe: %s\n", item->target_path);
        return OG_ERROR;
    }
    return bak_offline_check_no_symlink(item->target_path, OG_TRUE);
}

static status_t bak_offline_ctrl_copy_original_path(char *dst, uint32 dst_size, const char *src)
{
    errno_t ret = memset_s(dst, dst_size, 0, dst_size);
    if (ret != EOK) {
        return OG_ERROR;
    }
    if (src == NULL || src[0] == '\0') {
        return OG_SUCCESS;
    }
    if (strlen(src) >= dst_size) {
        return OG_ERROR;
    }
    ret = strcpy_s(dst, dst_size, src);
    return ret == EOK ? OG_SUCCESS : OG_ERROR;
}

static bool32 bak_offline_ctrl_same_map_item(bak_offline_ctrl_path_map_item_t *item,
    bak_offline_ctrl_path_type_t type, uint32 file_id, uint32 node_id)
{
    return (item->type == type && item->file_id == file_id && item->node_id == node_id) ? OG_TRUE : OG_FALSE;
}

static bool32 bak_offline_ctrl_map_contains(bak_offline_ctrl_path_map_t *map,
    bak_offline_ctrl_path_type_t type, uint32 file_id, uint32 node_id)
{
    for (uint32 i = 0; i < map->item_count; i++) {
        if (bak_offline_ctrl_same_map_item(&map->items[i], type, file_id, node_id) == OG_TRUE) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t bak_offline_ctrl_append_map_item(bak_offline_ctrl_path_map_t *map,
    bak_offline_ctrl_path_type_t type, uint32 file_id, uint32 node_id, const char *target_rel, uint64 target_size)
{
    if (map->item_count >= map->item_capacity) {
        printf("[ogbackup]path-map auto has too many control items, capacity=%u\n", map->item_capacity);
        return OG_ERROR;
    }

    char dst_path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
        bool32 mapped = OG_FALSE;
        if (target_rel == NULL || bak_offline_ctrl_apply_dss_map(map, target_rel, dst_path,
            sizeof(dst_path), &mapped) != OG_SUCCESS) {
            printf("[ogbackup]DSS offline restore requires a +vg target path for control item type=%u file=%u node=%u\n",
                (uint32)type, file_id, node_id);
            return OG_ERROR;
        }
        if (mapped == OG_TRUE) {
            printf("[ogbackup]DSS target mapping: type=%u file=%u node=%u original=%s target=%s\n",
                (uint32)type, file_id, node_id, target_rel, dst_path);
        }
    } else if (map->inplace_restore == OG_TRUE) {
        if (target_rel == NULL || target_rel[0] != '/' ||
            strcpy_s(dst_path, sizeof(dst_path), target_rel) != EOK) {
            printf("[ogbackup]local in-place control target is not an absolute original path: %s\n",
                target_rel == NULL ? "<null>" : target_rel);
            return OG_ERROR;
        }
    } else if (bak_offline_resolve_target_path(map->target_dir, target_rel, dst_path,
        sizeof(dst_path)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (strlen(dst_path) >= OG_FILE_NAME_BUFFER_SIZE) {
        printf("[ogbackup]path-map auto target path is too long for control item field: %s\n", dst_path);
        return OG_ERROR;
    }

    bak_offline_ctrl_path_map_item_t *item = &map->items[map->item_count++];
    errno_t ret = memset_s(item, sizeof(bak_offline_ctrl_path_map_item_t), 0,
        sizeof(bak_offline_ctrl_path_map_item_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    item->type = type;
    item->file_id = file_id;
    item->node_id = node_id;
    item->target_size = target_size;
    item->generated_from_control = OG_TRUE;
    item->dss_mapped = map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS &&
        strcmp(dst_path, target_rel) != 0 ? OG_TRUE : OG_FALSE;
    ret = strcpy_s(item->target_path, sizeof(item->target_path), dst_path);
    return ret == EOK ? OG_SUCCESS : OG_ERROR;
}

static const char *bak_offline_ctrl_basename(const char *path)
{
    const char *slash = (path == NULL) ? NULL : strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static dtc_node_ctrl_t *bak_offline_ctrl_get_node_ctrl(bak_offline_ctrl_layout_t *layout, uint32 node_id);

static status_t bak_offline_ctrl_append_datafile_from_ctrl(bak_offline_ctrl_path_map_t *map,
    datafile_ctrl_t *ctrl, uint32 file_id)
{
    if (ctrl->name[0] == '\0' || bak_offline_ctrl_map_contains(map, BAK_OFFLINE_CTRL_PATH_DATAFILE,
        file_id, 0) == OG_TRUE) {
        return OG_SUCCESS;
    }

    if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS || map->inplace_restore == OG_TRUE) {
        return bak_offline_ctrl_append_map_item(map, BAK_OFFLINE_CTRL_PATH_DATAFILE, file_id, 0,
            ctrl->name, (uint64)ctrl->size);
    }

    const char *base = bak_offline_ctrl_basename(ctrl->name);
    char target_rel[OG_MAX_FILE_PATH_LENGH] = {0};
    errno_t ret;
    if (base != NULL && base[0] != '\0' && strlen(base) < OG_NAME_BUFFER_SIZE) {
        ret = snprintf_s(target_rel, sizeof(target_rel), sizeof(target_rel) - 1,
            "data/data_%u_%s", file_id, base);
    } else {
        ret = snprintf_s(target_rel, sizeof(target_rel), sizeof(target_rel) - 1,
            "data/data_%u.dbf", file_id);
    }
    if (ret == -1) {
        return OG_ERROR;
    }
    return bak_offline_ctrl_append_map_item(map, BAK_OFFLINE_CTRL_PATH_DATAFILE, file_id, 0, target_rel,
        (uint64)ctrl->size);
}

static status_t bak_offline_ctrl_append_logfile_from_ctrl(bak_offline_ctrl_path_map_t *map,
    log_file_ctrl_t *ctrl, uint32 file_id, uint32 node_id)
{
    if (ctrl->name[0] == '\0' || LOG_IS_DROPPED(ctrl->flg) ||
        bak_offline_ctrl_map_contains(map, BAK_OFFLINE_CTRL_PATH_LOGFILE, file_id, node_id) == OG_TRUE) {
        return OG_SUCCESS;
    }

    if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS || map->inplace_restore == OG_TRUE) {
        return bak_offline_ctrl_append_map_item(map, BAK_OFFLINE_CTRL_PATH_LOGFILE, file_id, node_id,
            ctrl->name, (uint64)ctrl->size);
    }

    char target_rel[OG_MAX_FILE_PATH_LENGH] = {0};
    errno_t ret = snprintf_s(target_rel, sizeof(target_rel), sizeof(target_rel) - 1,
        "redo/log_%u_%u.bak", node_id, file_id);
    if (ret == -1) {
        return OG_ERROR;
    }
    return bak_offline_ctrl_append_map_item(map, BAK_OFFLINE_CTRL_PATH_LOGFILE, file_id, node_id, target_rel,
        (uint64)ctrl->size);
}

static void bak_offline_ctrl_refresh_plan_counts(bak_offline_ctrl_path_map_t *map)
{
    map->planned_logfiles = 0;
    map->planned_datafiles = 0;
    for (uint32 i = 0; i < map->item_count; i++) {
        if (map->items[i].type == BAK_OFFLINE_CTRL_PATH_LOGFILE &&
            map->items[i].generated_from_control == OG_TRUE) {
            map->planned_logfiles++;
        } else if (map->items[i].type == BAK_OFFLINE_CTRL_PATH_DATAFILE &&
            map->items[i].datafile_required == OG_TRUE) {
            map->planned_datafiles++;
        }
    }
}

static const char *bak_offline_ctrl_map_bool(bool32 value)
{
    return value == OG_TRUE ? "true" : "false";
}

static status_t bak_offline_ctrl_refresh_dss_preserve_counts(bak_offline_ctrl_path_map_t *map)
{
    map->preserved_dss_datafiles = 0;
    map->preserved_dss_logfiles = 0;
    map->preserved_dss_archives = 0;
    map->mapped_dss_datafiles = 0;
    map->mapped_dss_logfiles = 0;
    map->mapped_dss_archives = 0;
    if (map->storage_mode != BAK_OFFLINE_RESTORE_STORAGE_DSS) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (bak_offline_ctrl_path_has_dss_prefix(item->target_path) != OG_TRUE) {
            printf("[ogbackup]DSS control path preserve missing: type=%u file=%u node=%u target=%s\n",
                (uint32)item->type, item->file_id, item->node_id, item->target_path);
            return OG_ERROR;
        }
        if (item->original_path[0] != '\0' &&
            bak_offline_ctrl_path_has_dss_prefix(item->original_path) != OG_TRUE) {
            printf("[ogbackup]DSS control path preserve found non-DSS original path: type=%u file=%u node=%u "
                   "original=%s target=%s\n",
                (uint32)item->type, item->file_id, item->node_id, item->original_path, item->target_path);
            return OG_ERROR;
        }
        if (map->dss_map_required == OG_TRUE && item->dss_mapped != OG_TRUE) {
            printf("[ogbackup]DSS target mapping missing for control item: type=%u file=%u node=%u "
                   "original=%s target=%s\n",
                (uint32)item->type, item->file_id, item->node_id, item->original_path, item->target_path);
            return OG_ERROR;
        }

        if (item->type == BAK_OFFLINE_CTRL_PATH_DATAFILE) {
            if (item->dss_mapped == OG_TRUE) {
                map->mapped_dss_datafiles++;
            } else {
                map->preserved_dss_datafiles++;
            }
        } else if (item->type == BAK_OFFLINE_CTRL_PATH_LOGFILE) {
            if (item->dss_mapped == OG_TRUE) {
                map->mapped_dss_logfiles++;
            } else {
                map->preserved_dss_logfiles++;
            }
        } else if (item->type == BAK_OFFLINE_CTRL_PATH_ARCHIVE) {
            if (item->dss_mapped == OG_TRUE) {
                map->mapped_dss_archives++;
            } else {
                map->preserved_dss_archives++;
            }
        }
    }
    return OG_SUCCESS;
}

static void bak_offline_ctrl_print_path_map_plan(bak_offline_ctrl_path_map_t *map)
{
    bak_offline_ctrl_refresh_plan_counts(map);
    printf("[ogbackup]  control rewrite mapping plan: items=%u planned_datafiles=%u planned_logfiles=%u\n",
        map->item_count, map->planned_datafiles, map->planned_logfiles);
    if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
        const char *control_path_handling = map->dss_map_active == OG_TRUE ? "dss-map" :
            (map->dss_inplace_preview == OG_TRUE ? "dss-inplace-preview" :
            (map->dss_inplace_restore == OG_TRUE ? "dss-inplace" : "dss-preserve"));
        printf("[ogbackup]  storage=dss control path handling=%s "
               "preserved DSS data/log/archive=%u/%u/%u mapped DSS data/log/archive=%u/%u/%u\n",
            control_path_handling,
            map->preserved_dss_datafiles, map->preserved_dss_logfiles, map->preserved_dss_archives,
            map->mapped_dss_datafiles, map->mapped_dss_logfiles, map->mapped_dss_archives);
        if (map->dss_map_active == OG_TRUE) {
            printf("[ogbackup]  DSS target mapping rules: %s\n", map->dss_map);
        } else {
            char printed[OG_MAX_CONFIG_LINE_SIZE] = {0};
            uint32 used = 0;
            bool32 any = OG_FALSE;
            for (uint32 i = 0; i < map->item_count; i++) {
                const char *target = map->items[i].target_path;
                if (target == NULL || target[0] != '+') {
                    continue;
                }
                uint32 len = 0;
                while (target[len] != '\0' && target[len] != '/') {
                    len++;
                }
                if (len == 0 || used + len + 2 >= sizeof(printed)) {
                    continue;
                }
                bool32 exists = OG_FALSE;
                uint32 pos = 0;
                while (pos < used) {
                    uint32 token_len = 0;
                    while (pos + token_len < used && printed[pos + token_len] != ',') {
                        token_len++;
                    }
                    if (token_len == len && strncmp(printed + pos, target, len) == 0) {
                        exists = OG_TRUE;
                        break;
                    }
                    pos += token_len + 1;
                }
                if (exists == OG_TRUE) {
                    continue;
                }
                if (any == OG_TRUE) {
                    printed[used++] = ',';
                }
                if (memcpy_s(printed + used, sizeof(printed) - used, target, len) != EOK) {
                    return;
                }
                used += len;
                printed[used] = '\0';
                any = OG_TRUE;
            }
            printf("[ogbackup]  target DSS paths preserved=%s\n", any == OG_TRUE ? printed : "<unknown>");
        }
    }
    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->type == BAK_OFFLINE_CTRL_PATH_DATAFILE) {
            printf("[ogbackup]    datafile mapping: id=%u space=%u file_no=%u flag=%u space_type=%u "
                   "required=%s original=%s target=%s generated_from_control=%s\n",
                item->file_id, item->datafile_space_id, item->datafile_file_no, item->datafile_flag,
                item->datafile_space_type, bak_offline_ctrl_map_bool(item->datafile_required),
                item->original_path, item->target_path, bak_offline_ctrl_map_bool(item->generated_from_control));
        } else if (item->type == BAK_OFFLINE_CTRL_PATH_LOGFILE) {
            printf("[ogbackup]    redo/log mapping: node=%u id=%u original=%s target=%s "
                   "generated_from_control=%s status=%u log_first=%u log_last=%u log_hwm=%u "
                   "rcy_point=[%u-%u/%u/%llu/%llu] lrp_point=[%u-%u/%u/%llu/%llu] "
                   "selected_current_log=%u generated_header_asn=%u asn_reason=%s\n",
                item->node_id, item->file_id, item->original_path, item->target_path,
                bak_offline_ctrl_map_bool(item->generated_from_control), item->log_status, item->log_first,
                item->log_last, item->log_hwm, item->rcy_rst_id, item->rcy_asn, item->rcy_block_id,
                item->rcy_lfn, item->rcy_lsn, item->lrp_rst_id, item->lrp_asn, item->lrp_block_id,
                item->lrp_lfn, item->lrp_lsn, item->log_last, item->generated_log_head_asn,
                bak_offline_ctrl_log_asn_reason(item));
            if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
                printf("[ogbackup]    redo/log DSS preserve: node=%u id=%u original=%s target=%s "
                       "generated_from_control=%s\n",
                    item->node_id, item->file_id, item->original_path, item->target_path,
                    bak_offline_ctrl_map_bool(item->generated_from_control));
            }
        } else if (item->type == BAK_OFFLINE_CTRL_PATH_ARCHIVE) {
            printf("[ogbackup]    archive mapping: asn=%u rst=%u node=%u locator=%u original=%s target=%s "
                   "archive_register=%s\n",
                item->file_id, item->rst_id, item->node_id, item->arch_locator, item->original_path,
                item->target_path, bak_offline_ctrl_map_bool(item->archive_register));
            if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
                printf("[ogbackup]    archive DSS preserve: asn=%u rst=%u node=%u locator=%u target=%s\n",
                    item->file_id, item->rst_id, item->node_id, item->arch_locator, item->target_path);
            }
        }
    }
}

static status_t bak_offline_ctrl_append_control_discovered_paths(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_t *map)
{
    for (uint32 id = 0; id < OG_MAX_DATA_FILES; id++) {
        uint32 page_id = bak_offline_ctrl_item_page_id(id, sizeof(datafile_ctrl_t), layout->datafile_segment);
        if (page_id >= layout->page_count) {
            return OG_ERROR;
        }
        datafile_ctrl_t *ctrl = (datafile_ctrl_t *)db_get_ctrl_item(layout->pages, id, sizeof(datafile_ctrl_t),
            layout->datafile_segment);
        if (ctrl->name[0] != '\0' &&
            bak_offline_ctrl_append_datafile_from_ctrl(map, ctrl, id) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    for (uint32 node_id = 0; node_id < layout->node_count; node_id++) {
        dtc_node_ctrl_t *node_ctrl = bak_offline_ctrl_get_node_ctrl(layout, node_id);
        uint32 log_hwm = (node_ctrl == NULL || node_ctrl->log_hwm == 0 ||
            node_ctrl->log_hwm > OG_MAX_LOG_FILES) ? OG_MAX_LOG_FILES : node_ctrl->log_hwm;
        for (uint32 id = 0; id < log_hwm; id++) {
            uint32 page_id = bak_offline_ctrl_log_item_page_id(id, sizeof(log_file_ctrl_t),
                layout->log_segment, node_id);
            if (page_id >= layout->page_count) {
                return OG_ERROR;
            }
            log_file_ctrl_t *ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(layout->pages, id,
                sizeof(log_file_ctrl_t), layout->log_segment, node_id);
            if (ctrl->name[0] != '\0' &&
                bak_offline_ctrl_append_logfile_from_ctrl(map, ctrl, id, node_id) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_match_datafile(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_item_t *item)
{
    uint32 page_id = bak_offline_ctrl_item_page_id(item->file_id, sizeof(datafile_ctrl_t),
        layout->datafile_segment);
    if (page_id >= layout->page_count) {
        return OG_ERROR;
    }
    datafile_ctrl_t *ctrl = (datafile_ctrl_t *)db_get_ctrl_item(layout->pages, item->file_id,
        sizeof(datafile_ctrl_t), layout->datafile_segment);
    if (item->generated_from_control != OG_TRUE && (ctrl->used != OG_TRUE || ctrl->id != item->file_id)) {
        printf("[ogbackup]datafile control item %u is not used or mismatched\n", item->file_id);
        return OG_ERROR;
    }
    if (ctrl->name[0] == '\0') {
        printf("[ogbackup]datafile control item %u has empty path\n", item->file_id);
        return OG_ERROR;
    }
    if (item->target_path[0] == '+') {
        if (ctrl->type != 0 && ctrl->type != DEV_TYPE_RAW) {
            printf("[ogbackup]datafile control item %u uses unsupported DSS device type %u\n",
                item->file_id, (uint32)ctrl->type);
            return OG_ERROR;
        }
    } else if (ctrl->type != 0 && ctrl->type != DEV_TYPE_FILE) {
        printf("[ogbackup]datafile control item %u uses unsupported device type %u for path-map auto\n",
            item->file_id, (uint32)ctrl->type);
        return OG_ERROR;
    }
    if (bak_offline_ctrl_copy_original_path(item->original_path, sizeof(item->original_path),
        ctrl->name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    item->ctrl_page_id = page_id;
    item->target_size = (uint64)ctrl->size;
    if (bak_offline_ctrl_set_datafile_space_info(layout, item, ctrl) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_match_logfile(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_item_t *item)
{
    uint32 page_id = bak_offline_ctrl_log_item_page_id(item->file_id, sizeof(log_file_ctrl_t),
        layout->log_segment, item->node_id);
    if (page_id >= layout->page_count) {
        return OG_ERROR;
    }
    log_file_ctrl_t *ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(layout->pages, item->file_id,
        sizeof(log_file_ctrl_t), layout->log_segment, item->node_id);
    dtc_node_ctrl_t *node_ctrl = bak_offline_ctrl_get_node_ctrl(layout, item->node_id);
    if (node_ctrl == NULL) {
        printf("[ogbackup]logfile control item file=%u node=%u cannot read node control page\n",
            item->file_id, item->node_id);
        return OG_ERROR;
    }
    if (ctrl->name[0] == '\0') {
        printf("[ogbackup]logfile control item file=%u node=%u is empty\n", item->file_id, item->node_id);
        return OG_ERROR;
    }
    if (item->target_path[0] == '+') {
        if (ctrl->type != 0 && ctrl->type != DEV_TYPE_RAW) {
            printf("[ogbackup]logfile control item file=%u node=%u uses unsupported DSS device type %u\n",
                item->file_id, item->node_id, (uint32)ctrl->type);
            return OG_ERROR;
        }
    } else if (ctrl->type != 0 && ctrl->type != DEV_TYPE_FILE) {
        printf("[ogbackup]logfile control item file=%u node=%u uses unsupported device type %u for path-map auto\n",
            item->file_id, item->node_id, (uint32)ctrl->type);
        return OG_ERROR;
    }
    if (bak_offline_ctrl_copy_original_path(item->original_path, sizeof(item->original_path),
        ctrl->name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    core_ctrl_t *core = (core_ctrl_t *)layout->pages[CORE_CTRL_PAGE_ID].buf;
    item->log_block_size = ctrl->block_size == 0 ? OG_DFLT_LOG_BLOCK_SIZE : ctrl->block_size;
    item->log_status = (uint32)ctrl->status;
    item->log_rst_id = core->resetlogs.rst_id;
    item->log_dbid = core->dbid;
    item->log_hwm = node_ctrl->log_hwm;
    item->log_first = node_ctrl->log_first;
    item->log_last = node_ctrl->log_last;
    item->rcy_rst_id = (uint32)node_ctrl->rcy_point.rst_id;
    item->rcy_asn = node_ctrl->rcy_point.asn;
    item->rcy_block_id = node_ctrl->rcy_point.block_id;
    item->rcy_lfn = (uint64)node_ctrl->rcy_point.lfn;
    item->rcy_lsn = node_ctrl->rcy_point.lsn;
    item->lrp_rst_id = (uint32)node_ctrl->lrp_point.rst_id;
    item->lrp_asn = node_ctrl->lrp_point.asn;
    item->lrp_block_id = node_ctrl->lrp_point.block_id;
    item->lrp_lfn = (uint64)node_ctrl->lrp_point.lfn;
    item->lrp_lsn = node_ctrl->lrp_point.lsn;
    if (bak_offline_ctrl_select_log_head_asn(item) != OG_SUCCESS) {
        return OG_ERROR;
    }
    item->ctrl_page_id = page_id;
    return OG_SUCCESS;
}

static uint32 bak_offline_ctrl_planned_archive_registers(bak_offline_ctrl_path_map_t *map, uint32 current_index,
    uint32 node_id)
{
    uint32 count = 0;
    for (uint32 i = 0; i < current_index; i++) {
        if (map->items[i].type == BAK_OFFLINE_CTRL_PATH_ARCHIVE &&
            map->items[i].node_id == node_id &&
            map->items[i].archive_register == OG_TRUE) {
            count++;
        }
    }
    return count;
}

static status_t bak_offline_ctrl_prepare_archive_register(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_t *map, uint32 current_index, bak_offline_ctrl_path_map_item_t *item,
    dtc_node_ctrl_t *node_ctrl)
{
    uint32 planned = bak_offline_ctrl_planned_archive_registers(map, current_index, item->node_id);
    uint32 locator = (node_ctrl->archived_end + planned) % OG_MAX_ARCH_NUM;
    uint32 end_pos = (locator + 1) % OG_MAX_ARCH_NUM;
    if (end_pos == node_ctrl->archived_start && node_ctrl->archived_start != node_ctrl->archived_end) {
        printf("[ogbackup]archive control path rewrite unsupported for this backupset/control layout: "
               "archive ring is full, node=%u start=%u end=%u planned=%u\n",
            item->node_id, node_ctrl->archived_start, node_ctrl->archived_end, planned);
        return OG_ERROR;
    }

    uint32 page_id = bak_offline_ctrl_arch_item_page_id(locator, layout->arch_segment, item->node_id);
    if (page_id >= layout->page_count) {
        printf("[ogbackup]archive control path rewrite unsupported for this backupset/control layout: "
               "planned locator=%u page=%u page_count=%u\n", locator, page_id, layout->page_count);
        return OG_ERROR;
    }
    if (bak_offline_ctrl_read_archive_head(item) != OG_SUCCESS) {
        return OG_ERROR;
    }

    item->archive_register = OG_TRUE;
    item->arch_locator = locator;
    item->ctrl_page_id = page_id;
    item->node_ctrl_page_id = CTRL_LOG_SEGMENT + item->node_id;
    item->original_path[0] = '\0';
    printf("[ogbackup][ctrl-debug] archive control item will be registered from backup piece: "
           "asn=%u rst=%u node=%u locator=%u node_page=%u arch_page=%u archived_start=%u archived_end=%u\n",
        item->file_id, item->rst_id, item->node_id, item->arch_locator, item->node_ctrl_page_id,
        item->ctrl_page_id, node_ctrl->archived_start, node_ctrl->archived_end);
    return OG_SUCCESS;
}

static void bak_offline_ctrl_dump_archive_candidates(bak_offline_ctrl_layout_t *layout, uint32 node_id)
{
    dtc_node_ctrl_t *node_ctrl = bak_offline_ctrl_get_node_ctrl(layout, node_id);
    if (node_ctrl == NULL) {
        return;
    }
    uint32 archived_start = node_ctrl->archived_start;
    uint32 archived_end = node_ctrl->archived_end;
    uint32 arch_num = (archived_end - archived_start + OG_MAX_ARCH_NUM) % OG_MAX_ARCH_NUM;
    printf("[ogbackup][ctrl-debug] node control node=%u page=%u archived_start=%u archived_end=%u arch_num=%u\n",
        node_id, CTRL_LOG_SEGMENT + node_id, archived_start, archived_end, arch_num);

    uint32 dump_count = arch_num > 0 ? arch_num : 8;
    if (dump_count > 8) {
        dump_count = 8;
    }
    for (uint32 i = 0; i < dump_count; i++) {
        uint32 locator = (arch_num > 0) ? (archived_start + i) % OG_MAX_ARCH_NUM : i;
        uint32 page_id = bak_offline_ctrl_arch_item_page_id(locator, layout->arch_segment, node_id);
        if (page_id >= layout->page_count) {
            break;
        }
        arch_ctrl_t *ctrl = bak_offline_ctrl_get_arch_item(layout->pages, locator, layout->arch_segment, node_id);
        printf("[ogbackup][ctrl-debug] arch_ctrl candidate node=%u locator=%u page=%u recid=%u "
               "asn=%u rst=%u dest=%u name=%s\n",
            node_id, locator, page_id, ctrl->recid, ctrl->asn, ctrl->rst_id, ctrl->dest_id, ctrl->name);
    }
}

static status_t bak_offline_ctrl_match_archive(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_t *map, uint32 current_index, bak_offline_ctrl_path_map_item_t *item)
{
    dtc_node_ctrl_t *node_ctrl = bak_offline_ctrl_get_node_ctrl(layout, item->node_id);
    if (node_ctrl == NULL) {
        printf("[ogbackup]archive control path rewrite unsupported for this backupset/control layout: "
               "node=%u control node page is out of range\n", item->node_id);
        return OG_ERROR;
    }

    uint32 archived_start = node_ctrl->archived_start;
    uint32 archived_end = node_ctrl->archived_end;
    uint32 arch_num = (archived_end - archived_start + OG_MAX_ARCH_NUM) % OG_MAX_ARCH_NUM;
    printf("[ogbackup][ctrl-debug] archive path-map lookup asn=%u rst=%u node=%u node_page=%u "
           "archived_start=%u archived_end=%u arch_num=%u\n",
        item->file_id, item->rst_id, item->node_id, CTRL_LOG_SEGMENT + item->node_id,
        archived_start, archived_end, arch_num);
    bak_offline_ctrl_dump_archive_candidates(layout, item->node_id);
    for (uint32 i = 0; i < arch_num; i++) {
        uint32 locator = (archived_start + i) % OG_MAX_ARCH_NUM;
        uint32 page_id = bak_offline_ctrl_arch_item_page_id(locator, layout->arch_segment, item->node_id);
        if (page_id >= layout->page_count) {
            printf("[ogbackup]archive control path rewrite unsupported for this backupset/control layout: "
                   "locator=%u page=%u page_count=%u\n", locator, page_id, layout->page_count);
            return OG_ERROR;
        }
        arch_ctrl_t *ctrl = bak_offline_ctrl_get_arch_item(layout->pages, locator,
            layout->arch_segment, item->node_id);
        if (ctrl->recid == 0 || ctrl->name[0] == '\0' || ctrl->asn != item->file_id) {
            continue;
        }
        /*
         * bak_file_t.id records the archive ASN.  db_get_arch_ctrl() is indexed by
         * archive ring locator, not ASN, so mirror arch_get_archived_log_info():
         * iterate archived_start..archived_end and compare arch_ctrl_t.asn.  Older
         * local backup catalogs can expose rst_id=0 here; treat 0 as unknown/wildcard.
         */
        if (item->rst_id != 0 && ctrl->rst_id != item->rst_id) {
            continue;
        }
        if (bak_offline_ctrl_copy_original_path(item->original_path, sizeof(item->original_path),
            ctrl->name) != OG_SUCCESS) {
            return OG_ERROR;
        }
        item->rst_id = ctrl->rst_id;
        item->arch_locator = locator;
        item->archive_register = OG_FALSE;
        item->ctrl_page_id = page_id;
        item->node_ctrl_page_id = CTRL_LOG_SEGMENT + item->node_id;
        printf("[ogbackup][ctrl-debug] archive control item matched existing locator: "
               "asn=%u rst=%u node=%u locator=%u page=%u path=%s\n",
            item->file_id, item->rst_id, item->node_id, item->arch_locator, item->ctrl_page_id,
            item->original_path);
        return OG_SUCCESS;
    }

    /*
     * The control backup piece is produced before BACKUP_ARCH_FILE payloads are
     * restored from the backupset.  Online restore handles this by recording the
     * restored archive file into control pages from the archive log header.  Mirror
     * that session-free here instead of requiring the backed-up control image to
     * already contain this backupset archive.
     */
    return bak_offline_ctrl_prepare_archive_register(layout, map, current_index, item, node_ctrl);
}

static arch_ctrl_t *bak_offline_ctrl_get_matched_arch_item(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_item_t *item)
{
    uint32 page_id = bak_offline_ctrl_arch_item_page_id(item->arch_locator, layout->arch_segment, item->node_id);
    if (page_id != item->ctrl_page_id || page_id >= layout->page_count) {
        return NULL;
    }
    arch_ctrl_t *ctrl = bak_offline_ctrl_get_arch_item(layout->pages, item->arch_locator,
        layout->arch_segment, item->node_id);
    if (ctrl->recid == 0 || ctrl->name[0] == '\0' || ctrl->asn != item->file_id ||
        (item->rst_id != 0 && ctrl->rst_id != item->rst_id)) {
        printf("[ogbackup]archive control path rewrite unsupported for this backupset/control layout: "
               "matched locator became invalid, asn=%u rst=%u node=%u locator=%u\n",
            item->file_id, item->rst_id, item->node_id, item->arch_locator);
        return NULL;
    }
    return ctrl;
}

status_t bak_offline_ctrl_build_path_map(char *buf, uint64 size, const char *target_dir,
    bak_offline_ctrl_path_map_t *map)
{
    if (buf == NULL || target_dir == NULL || map == NULL || map->items == NULL ||
        map->item_count > map->item_capacity) {
        return OG_ERROR;
    }

    map->target_dir = target_dir;
    map->rewritten_datafiles = 0;
    map->rewritten_logfiles = 0;
    map->rewritten_archives = 0;
    map->preserved_dss_datafiles = 0;
    map->preserved_dss_logfiles = 0;
    map->preserved_dss_archives = 0;
    map->mapped_dss_datafiles = 0;
    map->mapped_dss_logfiles = 0;
    map->mapped_dss_archives = 0;
    map->dss_map_active = bak_offline_ctrl_text_empty(map->dss_map) == OG_TRUE ? OG_FALSE : OG_TRUE;
    map->planned_datafiles = 0;
    map->created_datafiles = 0;
    map->planned_logfiles = 0;
    map->created_logfiles = 0;
    map->residual_original_path = OG_FALSE;
    map->residual_dss_path = OG_FALSE;
    map->checksum_recalculated = OG_FALSE;
    map->checksum_kept_invalid = OG_FALSE;

    bak_offline_ctrl_layout_t layout;
    if (bak_offline_ctrl_init_layout(buf, size, &layout) != OG_SUCCESS) {
        return OG_ERROR;
    }
    bak_offline_ctrl_debug_scan_token(&layout, "arch");
    bak_offline_ctrl_debug_scan_token(&layout, "/arch");
    if (bak_offline_ctrl_append_control_discovered_paths(&layout, map) != OG_SUCCESS) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (bak_offline_ctrl_validate_target_path(target_dir, item, map->inplace_restore) != OG_SUCCESS) {
            return OG_ERROR;
        }
        status_t status;
        if (item->type == BAK_OFFLINE_CTRL_PATH_DATAFILE) {
            status = bak_offline_ctrl_match_datafile(&layout, item);
        } else if (item->type == BAK_OFFLINE_CTRL_PATH_LOGFILE) {
            status = bak_offline_ctrl_match_logfile(&layout, item);
        } else {
            status = bak_offline_ctrl_match_archive(&layout, map, i, item);
        }
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (map->inplace_restore == OG_TRUE && item->original_path[0] != '\0' &&
            !cm_str_equal(item->target_path, item->original_path)) {
            if (strcpy_s(item->target_path, sizeof(item->target_path), item->original_path) != EOK ||
                bak_offline_ctrl_validate_target_path(target_dir, item, OG_TRUE) != OG_SUCCESS) {
                printf("[ogbackup]cannot preserve original control target for in-place restore: %s\n",
                    item->original_path);
                return OG_ERROR;
            }
        }
        if (map->storage_mode != BAK_OFFLINE_RESTORE_STORAGE_DSS &&
            bak_offline_ctrl_path_has_dss_prefix(item->original_path) == OG_TRUE) {
            printf("[ogbackup]source backup/control file contains DSS paths; local target-dir offline restore does not "
                   "support automatic DSS path mapping yet; require DSS restore provider or manifest path "
                   "mapping/controlfile rewrite\n");
            return OG_ERROR;
        }
    }
    bak_offline_ctrl_refresh_plan_counts(map);
    if (bak_offline_ctrl_refresh_dss_preserve_counts(map) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS &&
        map->planned_logfiles > 0 && map->preserved_dss_logfiles == 0 && map->mapped_dss_logfiles == 0) {
        printf("[ogbackup]DSS redo/log path handling missing: planned_logfiles=%u "
               "preserved_dss_logfiles=0 mapped_dss_logfiles=0\n", map->planned_logfiles);
        return OG_ERROR;
    }
    bak_offline_ctrl_print_path_map_plan(map);
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_write_name(char *name, uint32 name_size, const char *path)
{
    if (strlen(path) >= name_size) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(name, name_size, 0, name_size);
    if (ret != EOK) {
        return OG_ERROR;
    }
    ret = strcpy_s(name, name_size, path);
    return ret == EOK ? OG_SUCCESS : OG_ERROR;
}

static status_t bak_offline_ctrl_register_archive(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_item_t *item, bool32 *changed)
{
    arch_ctrl_t *ctrl = bak_offline_ctrl_get_arch_item(layout->pages, item->arch_locator,
        layout->arch_segment, item->node_id);
    if (ctrl == NULL) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(ctrl, sizeof(arch_ctrl_t), 0, sizeof(arch_ctrl_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    ctrl->recid = item->arch_locator + 1;
    ctrl->dest_id = item->arch_dest_id;
    ctrl->stamp = item->arch_stamp;
    ctrl->block_size = (int32)item->arch_block_size;
    ctrl->blocks = item->arch_blocks;
    ctrl->first = (knl_scn_t)item->arch_first;
    ctrl->last = (knl_scn_t)item->arch_last;
    ctrl->rst_id = item->rst_id;
    ctrl->asn = item->file_id;
    ctrl->real_size = item->arch_real_size;
    ctrl->start_lsn = item->arch_start_lsn;
    ctrl->end_lsn = item->arch_end_lsn;
    if (bak_offline_ctrl_write_name(ctrl->name, sizeof(ctrl->name), item->target_path) != OG_SUCCESS) {
        return OG_ERROR;
    }

    dtc_node_ctrl_t *node_ctrl = bak_offline_ctrl_get_node_ctrl(layout, item->node_id);
    if (node_ctrl == NULL || item->node_ctrl_page_id >= layout->page_count) {
        return OG_ERROR;
    }
    uint32 next_end = (item->arch_locator + 1) % OG_MAX_ARCH_NUM;
    node_ctrl->archived_end = next_end;
    changed[item->node_ctrl_page_id] = OG_TRUE;
    printf("[ogbackup][ctrl-debug] archive control item registered: asn=%u rst=%u node=%u "
           "locator=%u arch_page=%u node_page=%u target=%s archived_start=%u archived_end=%u\n",
        item->file_id, item->rst_id, item->node_id, item->arch_locator, item->ctrl_page_id,
        item->node_ctrl_page_id, item->target_path, node_ctrl->archived_start, node_ctrl->archived_end);
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_rewrite_one(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_t *map, uint32 index, bool32 *changed)
{
    bak_offline_ctrl_path_map_item_t *item = &map->items[index];
    if (item->ctrl_page_id >= layout->page_count) {
        return OG_ERROR;
    }

    status_t status;
    if (item->type == BAK_OFFLINE_CTRL_PATH_DATAFILE) {
        datafile_ctrl_t *ctrl = (datafile_ctrl_t *)db_get_ctrl_item(layout->pages, item->file_id,
            sizeof(datafile_ctrl_t), layout->datafile_segment);
        status = bak_offline_ctrl_write_name(ctrl->name, sizeof(ctrl->name), item->target_path);
        map->rewritten_datafiles++;
    } else if (item->type == BAK_OFFLINE_CTRL_PATH_LOGFILE) {
        log_file_ctrl_t *ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(layout->pages, item->file_id,
            sizeof(log_file_ctrl_t), layout->log_segment, item->node_id);
        status = bak_offline_ctrl_write_name(ctrl->name, sizeof(ctrl->name), item->target_path);
        map->rewritten_logfiles++;
    } else {
        if (item->archive_register == OG_TRUE) {
            status = bak_offline_ctrl_register_archive(layout, item, changed);
        } else {
            arch_ctrl_t *ctrl = bak_offline_ctrl_get_matched_arch_item(layout, item);
            if (ctrl == NULL) {
                return OG_ERROR;
            }
            status = bak_offline_ctrl_write_name(ctrl->name, sizeof(ctrl->name), item->target_path);
        }
        map->rewritten_archives++;
    }
    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }
    changed[item->ctrl_page_id] = OG_TRUE;
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_refresh_checksums(bak_offline_ctrl_layout_t *layout, bool32 *changed,
    bool32 *checksum_recalculated, bool32 *checksum_kept_invalid)
{
    *checksum_recalculated = OG_FALSE;
    *checksum_kept_invalid = OG_FALSE;
    for (uint32 i = 0; i < layout->page_count; i++) {
        if (changed[i] != OG_TRUE) {
            continue;
        }
        if (layout->pages[i].tail.checksum == OG_INVALID_CHECKSUM) {
            *checksum_kept_invalid = OG_TRUE;
            continue;
        }
        layout->pages[i].tail.checksum = OG_INVALID_CHECKSUM;
        page_calc_checksum((page_head_t *)&layout->pages[i], OG_DFLT_CTRL_BLOCK_SIZE);
        *checksum_recalculated = OG_TRUE;
    }
    return bak_offline_verify_ctrl_checksum((char *)layout->pages, layout->page_count, "rewritten control buffer");
}

static status_t bak_offline_ctrl_check_rewritten_path(const char *type_name, uint32 file_id, uint32 node_id,
    const char *target_dir, const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return OG_SUCCESS;
    }
    if (bak_offline_ctrl_path_has_dss_prefix(path) == OG_TRUE) {
        printf("[ogbackup]path-map auto residual DSS path found after control rewrite: type=%s file=%u node=%u path=%s\n",
            type_name, file_id, node_id, path);
        return OG_ERROR;
    }
    if (bak_offline_ctrl_path_under_dir(target_dir, path) != OG_TRUE) {
        printf("[ogbackup]path-map auto residual original path found after control rewrite: "
               "type=%s file=%u node=%u path=%s\n",
            type_name, file_id, node_id, path);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_validate_no_residual_paths(bak_offline_ctrl_layout_t *layout,
    bak_offline_ctrl_path_map_t *map)
{
    for (uint32 id = 0; id < OG_MAX_DATA_FILES; id++) {
        uint32 page_id = bak_offline_ctrl_item_page_id(id, sizeof(datafile_ctrl_t), layout->datafile_segment);
        if (page_id >= layout->page_count) {
            return OG_ERROR;
        }
        datafile_ctrl_t *ctrl = (datafile_ctrl_t *)db_get_ctrl_item(layout->pages, id, sizeof(datafile_ctrl_t),
            layout->datafile_segment);
        if (bak_offline_ctrl_check_rewritten_path("datafile/temp/undo", id, 0, map->target_dir,
            ctrl->name) != OG_SUCCESS) {
            map->residual_original_path = OG_TRUE;
            return OG_ERROR;
        }
    }

    for (uint32 node_id = 0; node_id < layout->node_count; node_id++) {
        dtc_node_ctrl_t *node_ctrl = bak_offline_ctrl_get_node_ctrl(layout, node_id);
        uint32 log_hwm = (node_ctrl == NULL || node_ctrl->log_hwm == 0 ||
            node_ctrl->log_hwm > OG_MAX_LOG_FILES) ? OG_MAX_LOG_FILES : node_ctrl->log_hwm;
        for (uint32 id = 0; id < log_hwm; id++) {
            uint32 page_id = bak_offline_ctrl_log_item_page_id(id, sizeof(log_file_ctrl_t),
                layout->log_segment, node_id);
            if (page_id >= layout->page_count) {
                return OG_ERROR;
            }
            log_file_ctrl_t *ctrl = (log_file_ctrl_t *)db_get_log_ctrl_item(layout->pages, id,
                sizeof(log_file_ctrl_t), layout->log_segment, node_id);
            if (LOG_IS_DROPPED(ctrl->flg)) {
                continue;
            }
            if (bak_offline_ctrl_check_rewritten_path("redo/log", id, node_id, map->target_dir,
                ctrl->name) != OG_SUCCESS) {
                map->residual_original_path = OG_TRUE;
                return OG_ERROR;
            }
        }
    }

    for (uint32 i = 0; i < map->item_count; i++) {
        if (map->items[i].type != BAK_OFFLINE_CTRL_PATH_ARCHIVE) {
            continue;
        }
        arch_ctrl_t *ctrl = bak_offline_ctrl_get_matched_arch_item(layout, &map->items[i]);
        if (ctrl == NULL) {
            return OG_ERROR;
        }
        if (bak_offline_ctrl_check_rewritten_path("archive", map->items[i].file_id, map->items[i].node_id,
            map->target_dir, ctrl->name) != OG_SUCCESS) {
            map->residual_original_path = OG_TRUE;
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t bak_offline_ctrl_rewrite_paths(char *buf, uint64 size, bak_offline_ctrl_path_map_t *map)
{
    if (buf == NULL || map == NULL || map->items == NULL) {
        return OG_ERROR;
    }
    bak_offline_ctrl_layout_t layout;
    if (bak_offline_ctrl_init_layout(buf, size, &layout) != OG_SUCCESS) {
        return OG_ERROR;
    }

    bool32 changed[CTRL_MAX_PAGES_CLUSTERED] = {0};
    for (uint32 i = 0; i < map->item_count; i++) {
        if (bak_offline_ctrl_rewrite_one(&layout, map, i, changed) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    bak_offline_ctrl_refresh_plan_counts(map);
    if (map->storage_mode != BAK_OFFLINE_RESTORE_STORAGE_DSS && map->inplace_restore != OG_TRUE &&
        map->planned_logfiles > 0 && map->rewritten_logfiles == 0) {
        printf("[ogbackup]redo/log path rewrite missing: planned_logfiles=%u rewritten_logfiles=0; "
               "path-map=auto cannot leave redo/log control paths pointing outside target-dir\n",
            map->planned_logfiles);
        return OG_ERROR;
    }

    if (bak_offline_ctrl_refresh_checksums(&layout, changed, &map->checksum_recalculated,
        &map->checksum_kept_invalid) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (map->storage_mode != BAK_OFFLINE_RESTORE_STORAGE_DSS && map->inplace_restore != OG_TRUE) {
        for (uint32 i = 0; i < map->item_count; i++) {
            if (map->items[i].original_path[0] != '\0' &&
                bak_offline_ctrl_buffer_contains(buf, size, map->items[i].original_path) == OG_TRUE) {
                printf("[ogbackup]path-map auto residual original path found after control rewrite: %s\n",
                    map->items[i].original_path);
                map->residual_original_path = OG_TRUE;
                return OG_ERROR;
            }
        }
    }
    if (map->storage_mode != BAK_OFFLINE_RESTORE_STORAGE_DSS && map->inplace_restore != OG_TRUE) {
        if (bak_offline_ctrl_validate_no_residual_paths(&layout, map) != OG_SUCCESS) {
            return OG_ERROR;
        }
        map->residual_dss_path = bak_offline_ctrl_buffer_has_dss_path(buf, size);
        if (map->residual_dss_path == OG_TRUE) {
            printf("[ogbackup]path-map auto residual DSS path found after control rewrite\n");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t bak_offline_ctrl_write_raw_files(const char *target_dir, const char *buf, uint64 size,
    bak_offline_ctrl_restore_result_t *result)
{
    if (target_dir == NULL || buf == NULL || result == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_prepare_ctrl_targets(target_dir, result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < result->raw_ctrl_file_count; i++) {
        if (bak_offline_create_ctrl_parent(result->raw_ctrl_files[i]) != OG_SUCCESS ||
            bak_offline_write_raw_ctrl_file(result->raw_ctrl_files[i], buf, size) != OG_SUCCESS) {
            return OG_ERROR;
        }
        printf("[ogbackup]restored raw control file %s from control backup piece, size=%llu, checksum=checked\n",
            result->raw_ctrl_files[i], size);
    }
    return OG_SUCCESS;
}

static status_t bak_offline_parse_next_control_file(text_t *files, char *name, uint32 name_size)
{
    text_t file_name;
    cm_trim_text(files);
    if (files->len == 0) {
        return OG_ERROR;
    }
    if (files->str[0] == '(') {
        files->str++;
        files->len--;
    }
    cm_trim_text(files);
    cm_fetch_text(files, ',', '\0', &file_name);
    cm_trim_text(&file_name);
    if (file_name.len > 0 && file_name.str[file_name.len - 1] == ')') {
        file_name.len--;
        cm_trim_text(&file_name);
    }
    if (file_name.len == 0 || file_name.len >= name_size) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(name, name_size, 0, name_size);
    ret |= memcpy_s(name, name_size, file_name.str, file_name.len);
    return ret == EOK ? OG_SUCCESS : OG_ERROR;
}

static status_t bak_offline_ctrl_write_dss_files(const char *control_files, const char *buf, uint64 size,
    const bak_offline_ctrl_path_map_t *map, bak_offline_ctrl_restore_result_t *result)
{
    if (control_files == NULL || control_files[0] == '\0') {
        printf("[ogbackup]DSS offline restore requires CONTROL_FILES from backupset header\n");
        return OG_ERROR;
    }
    if (map == NULL ||
        (map->dss_inplace_restore != OG_TRUE && (map->dss_map_required != OG_TRUE || map->dss_map_active != OG_TRUE))) {
        printf("[ogbackup]DSS non-dry-run restore requires explicit DSS target mapping to avoid overwriting "
               "source/online control files\n");
        return OG_ERROR;
    }
    text_t files;
    cm_str2text((char *)control_files, &files);
    uint32 count = 0;
    while (files.len > 0 && count < BAK_OFFLINE_CTRL_FILE_COUNT) {
        char ctrl_path[OG_FILE_NAME_BUFFER_SIZE] = {0};
        if (bak_offline_parse_next_control_file(&files, ctrl_path, sizeof(ctrl_path)) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (cm_device_type(ctrl_path) != DEV_TYPE_RAW) {
            printf("[ogbackup]DSS offline restore refuses non-DSS control file path: %s\n", ctrl_path);
            return OG_ERROR;
        }
        char mapped_ctrl_path[OG_FILE_NAME_BUFFER_SIZE] = {0};
        bool32 mapped = OG_FALSE;
        if (bak_offline_ctrl_apply_dss_map(map, ctrl_path, mapped_ctrl_path, sizeof(mapped_ctrl_path),
            &mapped) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (mapped != OG_TRUE && map->dss_inplace_restore != OG_TRUE) {
            printf("[ogbackup]DSS target mapping missing for control file: %s\n", ctrl_path);
            return OG_ERROR;
        }
        if (bak_offline_write_device_buffer(mapped_ctrl_path, DEV_TYPE_RAW, buf, size) != OG_SUCCESS) {
            return OG_ERROR;
        }
        errno_t ret = strcpy_s(result->raw_ctrl_files[count], sizeof(result->raw_ctrl_files[count]),
            mapped_ctrl_path);
        if (ret != EOK) {
            return OG_ERROR;
        }
        printf("[ogbackup]restored raw DSS control file %s from control backup piece, original=%s size=%llu, "
               "checksum=checked, in_place=%s\n", mapped_ctrl_path, ctrl_path, size,
            map->dss_inplace_restore == OG_TRUE ? "true" : "false");
        count++;
    }
    if (count == 0) {
        return OG_ERROR;
    }
    result->raw_ctrl_file_count = count;
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_write_original_local_files(const char *control_files, const char *buf, uint64 size,
    const bak_offline_ctrl_path_map_t *map, bak_offline_ctrl_restore_result_t *result)
{
    if (control_files == NULL || control_files[0] == '\0' || map == NULL ||
        map->inplace_restore != OG_TRUE) {
        printf("[ogbackup]local in-place control commit requires original CONTROL_FILES metadata\n");
        return OG_ERROR;
    }
    text_t files;
    cm_str2text((char *)control_files, &files);
    uint32 count = 0;
    while (files.len > 0 && count < BAK_OFFLINE_CTRL_FILE_COUNT) {
        char ctrl_path[OG_FILE_NAME_BUFFER_SIZE] = {0};
        if (bak_offline_parse_next_control_file(&files, ctrl_path, sizeof(ctrl_path)) != OG_SUCCESS ||
            ctrl_path[0] != '/' || cm_device_type(ctrl_path) != DEV_TYPE_FILE ||
            strstr(ctrl_path, "/../") != NULL || strstr(ctrl_path, "/./") != NULL) {
            printf("[ogbackup]commit original local control file failed: %s\n",
                ctrl_path[0] == '\0' ? "<invalid>" : ctrl_path);
            return OG_ERROR;
        }
        for (uint32 i = 0; i < count; i++) {
            if (cm_str_equal(result->raw_ctrl_files[i], ctrl_path)) {
                printf("[ogbackup]duplicate original CONTROL_FILES target is not allowed: %s\n", ctrl_path);
                return OG_ERROR;
            }
        }
        if (bak_offline_check_no_symlink(ctrl_path, OG_TRUE) != OG_SUCCESS ||
            bak_offline_create_ctrl_parent(ctrl_path) != OG_SUCCESS ||
            bak_offline_write_raw_ctrl_file(ctrl_path, buf, size) != OG_SUCCESS) {
            printf("[ogbackup]commit original local control file failed: %s\n", ctrl_path);
            return OG_ERROR;
        }
        if (strcpy_s(result->raw_ctrl_files[count], sizeof(result->raw_ctrl_files[count]), ctrl_path) != EOK) {
            return OG_ERROR;
        }
        printf("[ogbackup]committed deferred original local control file %s size=%llu checksum=checked\n",
            ctrl_path, size);
        count++;
    }
    cm_trim_text(&files);
    if (count == 0 || files.len != 0) {
        printf("[ogbackup]CONTROL_FILES contains zero or more than %u control targets\n",
            (uint32)BAK_OFFLINE_CTRL_FILE_COUNT);
        return OG_ERROR;
    }
    result->raw_ctrl_file_count = count;
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_create_logfiles(bak_offline_ctrl_path_map_t *map, uint32 *created)
{
    if (created != NULL) {
        *created = 0;
    }
    if (map == NULL || map->items == NULL) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->type != BAK_OFFLINE_CTRL_PATH_LOGFILE || item->generated_from_control != OG_TRUE) {
            continue;
        }
        if (bak_offline_build_log_head_file(map, item) != OG_SUCCESS) {
            printf("[ogbackup]create mapped redo/log file failed: file=%u node=%u target=%s\n",
                item->file_id, item->node_id, item->target_path);
            return OG_ERROR;
        }
        if (created != NULL) {
            (*created)++;
        }
        printf("[ogbackup][ctrl-debug] mapped redo/log file created: file=%u node=%u target=%s "
               "control_size=%llu initialized_header=true\n",
            item->file_id, item->node_id, item->target_path, item->target_size);
    }
    return OG_SUCCESS;
}

static status_t bak_offline_ctrl_create_datafiles(bak_offline_ctrl_path_map_t *map, uint32 *created)
{
    if (created != NULL) {
        *created = 0;
    }
    if (map == NULL || map->items == NULL) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->type != BAK_OFFLINE_CTRL_PATH_DATAFILE || item->datafile_required != OG_TRUE) {
            continue;
        }
        if (item->target_size == 0 || item->target_size > (uint64)LLONG_MAX) {
            printf("[ogbackup]mapped datafile has invalid control size: file=%u size=%llu target=%s\n",
                item->file_id, item->target_size, item->target_path);
            return OG_ERROR;
        }
        if (map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
            if (cm_device_type(item->target_path) != DEV_TYPE_RAW) {
                printf("[ogbackup]mapped DSS datafile target is not a DSS path: file=%u target=%s\n",
                    item->file_id, item->target_path);
                return OG_ERROR;
            }
            if (bak_offline_create_device_parent(DEV_TYPE_RAW, item->target_path) != OG_SUCCESS) {
                return OG_ERROR;
            }
            if (cm_exist_device(DEV_TYPE_RAW, item->target_path) && map->dss_inplace_restore != OG_TRUE) {
                printf("[ogbackup]mapped DSS datafile target already exists and will not be overwritten: %s\n",
                    item->target_path);
                return OG_ERROR;
            }
            int32 handle = OG_INVALID_HANDLE;
            if (map->dss_inplace_restore == OG_TRUE) {
                if (bak_offline_open_or_create_device(item->target_path, DEV_TYPE_RAW, O_BINARY | O_SYNC | O_RDWR,
                    &handle) != OG_SUCCESS) {
                    printf("[ogbackup]open in-place DSS datafile device failed: file=%u target=%s\n",
                        item->file_id, item->target_path);
                    return OG_ERROR;
                }
            } else if (cm_create_device(item->target_path, DEV_TYPE_RAW, O_BINARY | O_SYNC | O_RDWR,
                &handle) != OG_SUCCESS) {
                printf("[ogbackup]create mapped DSS datafile device failed: file=%u target=%s\n",
                    item->file_id, item->target_path);
                return OG_ERROR;
            }
            if (map->dss_inplace_restore == OG_TRUE &&
                cm_truncate_device(DEV_TYPE_RAW, handle, 0) != OG_SUCCESS) {
                printf("[ogbackup]truncate in-place DSS datafile device failed: file=%u target=%s\n",
                    item->file_id, item->target_path);
                cm_close_device(DEV_TYPE_RAW, &handle);
                return OG_ERROR;
            }
            char zero_buf[SIZE_K(64)] = {0};
            /* DSS fallocate may reuse historical extents; zero the complete datafile
             * before sparse Full pages are applied by offline restore. */
            status_t status = cm_extend_device(DEV_TYPE_RAW, handle, zero_buf, sizeof(zero_buf),
                (int64)item->target_size, OG_FALSE);
            if (status != OG_SUCCESS) {
                printf("[ogbackup]extend mapped DSS datafile failed: file=%u size=%llu target=%s\n",
                    item->file_id, item->target_size, item->target_path);
            } else if (cm_fsync_device(DEV_TYPE_RAW, handle) != OG_SUCCESS) {
                printf("[ogbackup]fsync mapped DSS datafile failed: file=%u target=%s\n",
                    item->file_id, item->target_path);
                status = OG_ERROR;
            }
            cm_close_device(DEV_TYPE_RAW, &handle);
            if (status != OG_SUCCESS) {
                return status;
            }
            if (created != NULL) {
                (*created)++;
            }
            printf("[ogbackup][ctrl-debug] mapped datafile prepared: file=%u space=%u file_no=%u "
                   "target=%s control_size=%llu generated_from_control=%s storage=dss\n",
                item->file_id, item->datafile_space_id, item->datafile_file_no, item->target_path,
                item->target_size, bak_offline_ctrl_map_bool(item->generated_from_control));
            continue;
        }
        if (bak_offline_check_no_symlink(item->target_path, OG_TRUE) != OG_SUCCESS ||
            bak_offline_create_ctrl_parent(item->target_path) != OG_SUCCESS) {
            return OG_ERROR;
        }

        int32 fd = open(item->target_path, O_CREAT | O_RDWR | O_BINARY, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            printf("[ogbackup]create mapped datafile %s failed, error %d (%s)\n",
                item->target_path, errno, strerror(errno));
            return OG_ERROR;
        }
        status_t status = OG_SUCCESS;
        if (cm_truncate_file(fd, 0) != OG_SUCCESS ||
            cm_truncate_file(fd, (int64)item->target_size) != OG_SUCCESS) {
            printf("[ogbackup]truncate mapped datafile failed: file=%u size=%llu target=%s\n",
                item->file_id, item->target_size, item->target_path);
            status = OG_ERROR;
        } else if (fsync(fd) != 0) {
            printf("[ogbackup]fsync mapped datafile %s failed, error %d (%s)\n",
                item->target_path, errno, strerror(errno));
            status = OG_ERROR;
        }
        (void)close(fd);
        if (status == OG_SUCCESS) {
            status = bak_offline_fsync_parent(item->target_path);
        }
        if (status != OG_SUCCESS) {
            return status;
        }
        if (created != NULL) {
            (*created)++;
        }
        printf("[ogbackup][ctrl-debug] mapped datafile prepared: file=%u space=%u file_no=%u "
               "target=%s control_size=%llu generated_from_control=%s\n",
            item->file_id, item->datafile_space_id, item->datafile_file_no, item->target_path,
            item->target_size, bak_offline_ctrl_map_bool(item->generated_from_control));
    }
    return OG_SUCCESS;
}

status_t bak_offline_ctrl_prepare_non_control_files(bak_offline_ctrl_path_map_t *map,
    bak_offline_ctrl_restore_result_t *result)
{
    if (map == NULL || result == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_ctrl_create_datafiles(map, &result->created_datafiles) != OG_SUCCESS ||
        bak_offline_ctrl_create_logfiles(map, &result->created_logfiles) != OG_SUCCESS) {
        return OG_ERROR;
    }
    map->created_datafiles = result->created_datafiles;
    map->created_logfiles = result->created_logfiles;
    result->planned_datafiles = map->planned_datafiles;
    result->planned_logfiles = map->planned_logfiles;
    return OG_SUCCESS;
}

bool32 bak_offline_ctrl_result_has_dss_paths(const bak_offline_ctrl_restore_result_t *result)
{
    return (result != NULL && result->contains_dss_paths == OG_TRUE) ? OG_TRUE : OG_FALSE;
}

status_t bak_offline_restore_ctrlfile(const char *src_path, const bak_offline_ctrl_restore_opts_t *opts,
    bak_offline_ctrl_restore_result_t *result)
{
    if (src_path == NULL || opts == NULL || opts->target_dir == NULL || result == NULL) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(result, sizeof(bak_offline_ctrl_restore_result_t), 0,
        sizeof(bak_offline_ctrl_restore_result_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    if (opts->storage_mode != BAK_OFFLINE_RESTORE_STORAGE_DSS &&
        (opts->path_map == NULL || opts->path_map->inplace_restore != OG_TRUE) &&
        bak_offline_prepare_ctrl_targets(opts->target_dir, result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    char *buf = NULL;
    uint64 actual_size = 0;
    uint32 page_count = 0;
    if (bak_offline_ctrl_load_buffer(src_path, opts->expected_payload_size, &buf, &actual_size,
        &page_count) != OG_SUCCESS) {
        return OG_ERROR;
    }
    result->raw_ctrl_file_size = actual_size;
    result->ctrl_page_count = page_count;
    result->checksum_checked = OG_TRUE;

    result->contains_dss_paths = bak_offline_ctrl_buffer_has_dss_path(buf, actual_size);
    if (opts->reject_dss_to_local == OG_TRUE && result->contains_dss_paths == OG_TRUE) {
        printf("[ogbackup]source backup/control file contains DSS paths; local target-dir offline restore does not "
               "support automatic DSS path mapping yet; require DSS restore provider or manifest path "
               "mapping/controlfile rewrite\n");
        CM_FREE_PTR(buf);
        return OG_ERROR;
    }
    if (opts->path_map != NULL) {
        opts->path_map->storage_mode = opts->storage_mode;
    }
    if (opts->rewrite_paths == OG_TRUE || opts->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
        bool32 map_ready = opts->control_commit_only == OG_TRUE && opts->path_map != NULL &&
            opts->path_map->item_count > 0 ? OG_TRUE : OG_FALSE;
        if (opts->path_map == NULL ||
            (map_ready != OG_TRUE &&
            bak_offline_ctrl_build_path_map(buf, actual_size, opts->target_dir, opts->path_map) != OG_SUCCESS)) {
            CM_FREE_PTR(buf);
            return OG_ERROR;
        }
        if (opts->rewrite_paths == OG_TRUE &&
            bak_offline_ctrl_rewrite_paths(buf, actual_size, opts->path_map) != OG_SUCCESS) {
            CM_FREE_PTR(buf);
            return OG_ERROR;
        }
        result->control_rewrite_done = opts->rewrite_paths;
        result->rewritten_datafiles = opts->path_map->rewritten_datafiles;
        result->rewritten_logfiles = opts->path_map->rewritten_logfiles;
        result->rewritten_archives = opts->path_map->rewritten_archives;
        result->preserved_dss_datafiles = opts->path_map->preserved_dss_datafiles;
        result->preserved_dss_logfiles = opts->path_map->preserved_dss_logfiles;
        result->preserved_dss_archives = opts->path_map->preserved_dss_archives;
        result->mapped_dss_datafiles = opts->path_map->mapped_dss_datafiles;
        result->mapped_dss_logfiles = opts->path_map->mapped_dss_logfiles;
        result->mapped_dss_archives = opts->path_map->mapped_dss_archives;
        result->planned_datafiles = opts->path_map->planned_datafiles;
        result->planned_logfiles = opts->path_map->planned_logfiles;
        result->checksum_recalculated = opts->path_map->checksum_recalculated;
        result->checksum_kept_invalid = opts->path_map->checksum_kept_invalid;
    }
    if (opts->dry_run == OG_TRUE) {
        printf("[ogbackup]validated control backup piece %s -> raw control files: %s, %s, %s; "
               "raw size=%llu, page_count=%u, checksum=checked, control_rewrite=%s, "
               "rewritten data/log/archive=%u/%u/%u, created_datafiles=0 dry-run=true planned_datafiles=%u, "
               "created_logfiles=0 dry-run=true planned_logfiles=%u, "
               "preserved DSS data/log/archive=%u/%u/%u, mapped DSS data/log/archive=%u/%u/%u\n",
            src_path, result->raw_ctrl_files[0], result->raw_ctrl_files[1], result->raw_ctrl_files[2],
            result->raw_ctrl_file_size, result->ctrl_page_count,
            result->control_rewrite_done == OG_TRUE ? "done" : "disabled",
            result->rewritten_datafiles, result->rewritten_logfiles, result->rewritten_archives,
            result->planned_datafiles, result->planned_logfiles,
            result->preserved_dss_datafiles, result->preserved_dss_logfiles, result->preserved_dss_archives,
            result->mapped_dss_datafiles, result->mapped_dss_logfiles, result->mapped_dss_archives);
        CM_FREE_PTR(buf);
        return OG_SUCCESS;
    }

    if (opts->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS) {
        if (bak_offline_ctrl_write_dss_files(opts->control_files, buf, actual_size, opts->path_map,
            result) != OG_SUCCESS) {
            CM_FREE_PTR(buf);
            return OG_ERROR;
        }
    } else if (opts->path_map != NULL && opts->path_map->inplace_restore == OG_TRUE) {
        if (bak_offline_ctrl_write_original_local_files(opts->control_files, buf, actual_size, opts->path_map,
            result) != OG_SUCCESS) {
            CM_FREE_PTR(buf);
            return OG_ERROR;
        }
    } else if (bak_offline_ctrl_write_raw_files(opts->target_dir, buf, actual_size, result) != OG_SUCCESS) {
        CM_FREE_PTR(buf);
        return OG_ERROR;
    }
    if (opts->rewrite_paths == OG_TRUE && opts->control_commit_only != OG_TRUE &&
        bak_offline_ctrl_prepare_non_control_files(opts->path_map, result) != OG_SUCCESS) {
        CM_FREE_PTR(buf);
        return OG_ERROR;
    }

    CM_FREE_PTR(buf);
    return OG_SUCCESS;
}
