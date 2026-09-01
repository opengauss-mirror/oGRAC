/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_format_reader.c
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_format_reader.c
 *
 * -------------------------------------------------------------------------
 */

#include <fcntl.h>
#include <unistd.h>
#include "bak_format_reader.h"
#include "cm_checksum.h"
#include "cm_file.h"

static status_t bak_offline_copy_str(char *dst, uint32 dst_size, const char *src)
{
    if (src == NULL) {
        return OG_SUCCESS;
    }
    if (strlen(src) >= dst_size) {
        printf("[ogbackup]backupset catalog path is too long: %s\n", src);
        return OG_ERROR;
    }
    return strcpy_s(dst, dst_size, src) == EOK ? OG_SUCCESS : OG_ERROR;
}

static status_t bak_offline_split_path(const char *path, char *dir, uint32 dir_size)
{
    if (path == NULL || dir == NULL || strlen(path) >= dir_size) {
        return OG_ERROR;
    }
    if (strcpy_s(dir, dir_size, path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(dir, '/');
    if (slash == NULL) {
        return strcpy_s(dir, dir_size, ".") == EOK ? OG_SUCCESS : OG_ERROR;
    }
    if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    return OG_SUCCESS;
}

static uint16 bak_offline_calc_head_checksum(bak_head_t *head, uint32 size)
{
    uint16 org_head = head->attr.head_checksum;
    uint16 org_file = head->attr.file_checksum;
    head->attr.head_checksum = OG_INVALID_CHECKSUM;
    head->attr.file_checksum = OG_INVALID_CHECKSUM;
    uint16 checksum = REDUCE_CKS2UINT16(cm_get_checksum(head, size));
    head->attr.head_checksum = org_head;
    head->attr.file_checksum = org_file;
    return checksum;
}

static status_t bak_offline_verify_head_checksum(bak_head_t *head, uint32 size, bool32 is_file,
    const char *backupset_path)
{
    uint16 org = is_file == OG_TRUE ? head->attr.file_checksum : head->attr.head_checksum;
    uint16 checksum = bak_offline_calc_head_checksum(head, size);
    if (org != checksum) {
        printf("[ogbackup]backupset %s checksum mismatch in %s, expected %u, actual %u, check_size=%u, "
            "file_count=%u, depend_num=%u\n", head->attr.tag, backupset_path, org, checksum, size,
            head->file_count, head->depend_num);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_build_checksum_buffer(bak_offline_backupset_catalog_t *catalog, uint32 disk_head_size,
    char **buf, uint32 *buf_size)
{
    uint32 file_size = catalog->head.file_count * (uint32)sizeof(bak_file_t);
    uint32 depend_size = catalog->head.depend_num * (uint32)sizeof(bak_dependence_t);
    uint32 total_size = disk_head_size + file_size + depend_size;
    char *checksum_buf = NULL;

    if (total_size < disk_head_size) {
        return OG_ERROR;
    }
    checksum_buf = (char *)malloc(total_size);
    if (checksum_buf == NULL) {
        return OG_ERROR;
    }
    if (memset_s(checksum_buf, total_size, 0, total_size) != EOK ||
        memcpy_s(checksum_buf, total_size, &catalog->head, disk_head_size) != EOK) {
        CM_FREE_PTR(checksum_buf);
        return OG_ERROR;
    }
    if (file_size > 0 &&
        memcpy_s(checksum_buf + disk_head_size, total_size - disk_head_size, catalog->files, file_size) != EOK) {
        CM_FREE_PTR(checksum_buf);
        return OG_ERROR;
    }
    if (depend_size > 0 && memcpy_s(checksum_buf + disk_head_size + file_size,
        total_size - disk_head_size - file_size, catalog->depends, depend_size) != EOK) {
        CM_FREE_PTR(checksum_buf);
        return OG_ERROR;
    }

    *buf = checksum_buf;
    *buf_size = total_size;
    return OG_SUCCESS;
}

static status_t bak_offline_get_head_left_size(bak_version_t *version, uint32 *left_size, bool32 *old_version)
{
    if (version->major_ver != BAK_VERSION_MAJOR || version->min_ver != BAK_VERSION_MIN ||
        version->magic != BAK_VERSION_MAGIC) {
        printf("[ogbackup]backupset version mismatch, expected %u-%u-%u, input is %u-%u-%u\n",
            BAK_VERSION_MAJOR, BAK_VERSION_MIN, BAK_VERSION_MAGIC,
            version->major_ver, version->min_ver, version->magic);
    }
    if (version->major_ver < BAK_VERSION_MIN_WITH_ENCRYPTION) {
        printf("[ogbackup]backupset version %u-%u-%u is too old for offline restore\n",
            version->major_ver, version->min_ver, version->magic);
        return OG_ERROR;
    }
    if (version->major_ver == BAK_VERSION_MIN_WITH_ENCRYPTION && version->min_ver == 0) {
        *left_size = (uint32)sizeof(bak_old_version_head_t) - (uint32)sizeof(bak_version_t);
        *old_version = OG_TRUE;
    } else {
        *left_size = (uint32)sizeof(bak_head_t) - (uint32)sizeof(bak_version_t);
        *old_version = OG_FALSE;
    }
    return OG_SUCCESS;
}

static status_t bak_offline_read_exact(int32 fd, void *buf, uint32 size)
{
    char *pos = (char *)buf;
    uint32 left = size;
    while (left > 0) {
        ssize_t read_size = read(fd, pos, left);
        if (read_size <= 0) {
            return OG_ERROR;
        }
        pos += read_size;
        left -= (uint32)read_size;
    }
    return OG_SUCCESS;
}

status_t bak_read_backupset_catalog_offline(const char *backupset_path, bak_offline_backupset_catalog_t *catalog)
{
    if (backupset_path == NULL || catalog == NULL) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(catalog, sizeof(bak_offline_backupset_catalog_t), 0,
        sizeof(bak_offline_backupset_catalog_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    if (bak_offline_copy_str(catalog->path, OG_MAX_FILE_PATH_LENGH, backupset_path) != OG_SUCCESS ||
        bak_offline_split_path(backupset_path, catalog->dir, OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (!cm_file_exist(backupset_path)) {
        printf("[ogbackup]backupset catalog does not exist: %s\n", backupset_path);
        return OG_ERROR;
    }

    int32 fd = open(backupset_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        printf("[ogbackup]open backupset catalog %s failed, error %d\n", backupset_path, errno);
        return OG_ERROR;
    }

    bak_version_t version;
    if (bak_offline_read_exact(fd, &version, sizeof(version)) != OG_SUCCESS) {
        printf("[ogbackup]read backupset version from %s failed\n", backupset_path);
        (void)close(fd);
        return OG_ERROR;
    }
    uint32 left_size;
    bool32 old_version;
    if (bak_offline_get_head_left_size(&version, &left_size, &old_version) != OG_SUCCESS) {
        (void)close(fd);
        return OG_ERROR;
    }

    errno_t copy_ret = memcpy_s(&catalog->head.version, sizeof(bak_version_t), &version, sizeof(version));
    if (copy_ret != EOK || bak_offline_read_exact(fd, (char *)&catalog->head + sizeof(bak_version_t),
        left_size) != OG_SUCCESS) {
        printf("[ogbackup]read backupset header from %s failed\n", backupset_path);
        (void)close(fd);
        return OG_ERROR;
    }
    uint32 disk_head_size = (old_version == OG_TRUE) ? (uint32)sizeof(bak_old_version_head_t) :
        (uint32)sizeof(bak_head_t);
    if (bak_offline_verify_head_checksum(&catalog->head, disk_head_size, OG_FALSE, backupset_path) != OG_SUCCESS) {
        (void)close(fd);
        return OG_ERROR;
    }
    if (catalog->head.file_count > BAK_MAX_FILE_NUM || catalog->head.depend_num > BAK_MAX_INCR_NUM) {
        printf("[ogbackup]backupset %s catalog count is invalid, file_count=%u depend_num=%u\n",
            backupset_path, catalog->head.file_count, catalog->head.depend_num);
        (void)close(fd);
        return OG_ERROR;
    }
    uint32 file_size = catalog->head.file_count * (uint32)sizeof(bak_file_t);
    if (file_size > 0 && bak_offline_read_exact(fd, catalog->files, file_size) != OG_SUCCESS) {
        printf("[ogbackup]read backupset file catalog from %s failed\n", backupset_path);
        (void)close(fd);
        return OG_ERROR;
    }
    uint32 depend_size = catalog->head.depend_num * (uint32)sizeof(bak_dependence_t);
    if (depend_size > 0 && bak_offline_read_exact(fd, catalog->depends, depend_size) != OG_SUCCESS) {
        printf("[ogbackup]read backupset dependencies from %s failed\n", backupset_path);
        (void)close(fd);
        return OG_ERROR;
    }
    (void)close(fd);

    char *checksum_buf = NULL;
    uint32 checksum_size = 0;
    if (bak_offline_build_checksum_buffer(catalog, disk_head_size, &checksum_buf, &checksum_size) != OG_SUCCESS) {
        printf("[ogbackup]build backupset checksum buffer for %s failed\n", backupset_path);
        return OG_ERROR;
    }
    status_t status = bak_offline_verify_head_checksum((bak_head_t *)checksum_buf, checksum_size, OG_TRUE,
        backupset_path);
    CM_FREE_PTR(checksum_buf);
    return status;
}
