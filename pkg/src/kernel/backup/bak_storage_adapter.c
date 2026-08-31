/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * oGRAC is licensed under Mulan PSL v2.
 * -------------------------------------------------------------------------
 *
 * bak_storage_adapter.c
 *
 * IDENTIFICATION
 * src/kernel/backup/bak_storage_adapter.c
 *
 * -------------------------------------------------------------------------
 */

#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bak_storage_adapter.h"
#include "cm_device.h"
#include "cm_error.h"
#include "cm_file.h"
#include "srv_device_adpt.h"

#define BAK_OFFLINE_COPY_BUFFER_SIZE SIZE_M(1)
#define BAK_OFFLINE_DSS_CONN_PREFIX "UDS:"
#define BAK_OFFLINE_DSS_VG_CONF "dss_vg_conf.ini"

extern raw_device_op_t g_raw_device_op;

static bool32 g_bak_offline_dss_inplace_offline_vg_check = OG_FALSE;
static char g_bak_offline_last_dss_error[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};

void bak_offline_clear_last_dss_error(void)
{
    g_bak_offline_last_dss_error[0] = '\0';
}

const char *bak_offline_get_last_dss_error(void)
{
    return g_bak_offline_last_dss_error[0] == '\0' ? NULL : g_bak_offline_last_dss_error;
}

static void bak_offline_set_last_dss_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int32 ret = vsnprintf_s(g_bak_offline_last_dss_error, sizeof(g_bak_offline_last_dss_error),
        sizeof(g_bak_offline_last_dss_error) - 1, fmt, args);
    va_end(args);
    if (ret == -1) {
        g_bak_offline_last_dss_error[0] = '\0';
    }
}

void bak_offline_set_dss_inplace_offline_vg_check(bool32 enabled)
{
    g_bak_offline_dss_inplace_offline_vg_check = enabled;
}

static void bak_offline_format_cm_error(char *buf, uint32 buf_size)
{
    if (buf == NULL || buf_size == 0) {
        return;
    }
    int32 code = 0;
    const char *message = NULL;
    cm_get_error(&code, &message, NULL);
    int32 os_error = cm_get_os_error();
    const char *safe_message = (message == NULL || message[0] == '\0') ? "<none>" : message;
    if (code != 0) {
        (void)snprintf_s(buf, buf_size, buf_size - 1, "cm_error=%d message=%s os_errno=%d (%s)",
            code, safe_message, os_error, strerror(os_error));
    } else {
        (void)snprintf_s(buf, buf_size, buf_size - 1, "cm_error=0 os_errno=%d (%s)",
            os_error, strerror(os_error));
    }
}

status_t bak_offline_join_path(const char *dir, const char *name, char *path, uint32 path_size)
{
    if (dir == NULL || name == NULL || path == NULL || dir[0] == '\0' || name[0] == '\0') {
        return OG_ERROR;
    }
    const char *sep = (dir[strlen(dir) - 1] == '/') ? "" : "/";
    errno_t ret = snprintf_s(path, path_size, path_size - 1, "%s%s%s", dir, sep, name);
    if (ret == -1) {
        printf("[ogbackup]offline restore path is too long: %s/%s\n", dir, name);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 bak_offline_dir_is_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return OG_FALSE;
    }
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            (void)closedir(dir);
            return OG_FALSE;
        }
    }
    (void)closedir(dir);
    return OG_TRUE;
}

static bool32 bak_offline_target_looks_live(const char *target_dir)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    const char *markers[] = {
        "cfg/ogracd.ini",
        "cfg/ogsql.ini",
        "data",
        "dbs",
        "redo",
        "ctrl",
        "database.ctrl"
    };
    for (uint32 i = 0; i < (uint32)(sizeof(markers) / sizeof(markers[0])); i++) {
        if (bak_offline_join_path(target_dir, markers[i], path, OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
            return OG_TRUE;
        }
        if (cm_file_exist(path) || cm_dir_exist(path)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static bool32 bak_offline_target_dir_is_dangerous(const char *target_dir)
{
    if (target_dir == NULL || target_dir[0] == '\0' || strcmp(target_dir, "/") == 0 ||
        strcmp(target_dir, ".") == 0 || strcmp(target_dir, "..") == 0) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static status_t bak_offline_validate_relative_path(const char *target)
{
    if (target == NULL || target[0] == '\0') {
        return OG_ERROR;
    }
    if (target[0] == '/') {
        printf("[ogbackup]offline restore target path must be relative: %s\n", target);
        return OG_ERROR;
    }
    char copy[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strlen(target) >= sizeof(copy) || strcpy_s(copy, sizeof(copy), target) != EOK) {
        return OG_ERROR;
    }
    char *save_ptr = NULL;
    char *token = strtok_r(copy, "/", &save_ptr);
    while (token != NULL) {
        if (strcmp(token, "..") == 0 || strcmp(token, ".") == 0 || token[0] == '\0') {
            printf("[ogbackup]offline restore target path contains unsafe component: %s\n", target);
            return OG_ERROR;
        }
        token = strtok_r(NULL, "/", &save_ptr);
    }
    return OG_SUCCESS;
}

status_t bak_offline_resolve_target_path(const char *target_dir, const char *target, char *path, uint32 path_size)
{
    if (bak_offline_validate_relative_path(target) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (bak_offline_join_path(target_dir, target, path, path_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return bak_offline_check_no_symlink(path, OG_TRUE);
}

status_t bak_offline_check_no_symlink(const char *path, bool32 path_may_not_exist)
{
    if (path == NULL || path[0] == '\0' || strlen(path) >= OG_MAX_FILE_PATH_LENGH) {
        return OG_ERROR;
    }
    char copy[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strcpy_s(copy, sizeof(copy), path) != EOK) {
        return OG_ERROR;
    }

    char partial[OG_MAX_FILE_PATH_LENGH] = {0};
    char *cursor = copy;
    if (copy[0] == '/') {
        if (strcpy_s(partial, sizeof(partial), "/") != EOK) {
            return OG_ERROR;
        }
        cursor++;
    }
    char *save_ptr = NULL;
    char *token = strtok_r(cursor, "/", &save_ptr);
    while (token != NULL) {
        if (partial[0] == '\0' || strcmp(partial, "/") == 0) {
            errno_t ret = snprintf_s(partial, sizeof(partial), sizeof(partial) - 1,
                "%s%s", strcmp(partial, "/") == 0 ? "/" : "", token);
            if (ret == -1) {
                return OG_ERROR;
            }
        } else {
            char next[OG_MAX_FILE_PATH_LENGH] = {0};
            if (bak_offline_join_path(partial, token, next, sizeof(next)) != OG_SUCCESS ||
                strcpy_s(partial, sizeof(partial), next) != EOK) {
                return OG_ERROR;
            }
        }

        struct stat st;
        if (lstat(partial, &st) != 0) {
            if (path_may_not_exist == OG_TRUE && errno == ENOENT) {
                return OG_SUCCESS;
            }
            printf("[ogbackup]stat restore path %s failed, error %d\n", partial, errno);
            return OG_ERROR;
        }
        if (S_ISLNK(st.st_mode)) {
            printf("[ogbackup]offline restore refuses symlink path component: %s\n", partial);
            return OG_ERROR;
        }
        token = strtok_r(NULL, "/", &save_ptr);
    }
    return OG_SUCCESS;
}

status_t bak_offline_check_target_dir(const char *target_dir, bool32 force, bool32 dry_run)
{
    if (bak_offline_target_dir_is_dangerous(target_dir) == OG_TRUE) {
        printf("[ogbackup]target-dir %s is too dangerous for offline restore\n",
            target_dir == NULL ? "<null>" : target_dir);
        return OG_ERROR;
    }
    if (bak_offline_check_no_symlink(target_dir, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_dir_exist(target_dir)) {
        if (bak_offline_target_looks_live(target_dir) == OG_TRUE) {
            printf("[ogbackup]target-dir %s looks like an existing database directory; offline restore refuses it even with --force\n",
                target_dir);
            return OG_ERROR;
        }
        if (bak_offline_dir_is_empty(target_dir) != OG_TRUE && force != OG_TRUE) {
            printf("[ogbackup]target-dir %s is not empty; use --force to overwrite\n", target_dir);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (dry_run == OG_TRUE) {
        return OG_SUCCESS;
    }
    if (cm_create_dir_ex(target_dir) != OG_SUCCESS) {
        printf("[ogbackup]create target-dir %s failed, error %d\n", target_dir, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t bak_offline_write_marker(const char *target_dir, const char *name, const char *content)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (bak_offline_join_path(target_dir, name, path, sizeof(path)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    int32 fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        printf("[ogbackup]write restore marker %s failed, error %d\n", path, errno);
        return OG_ERROR;
    }
    size_t len = content == NULL ? 0 : strlen(content);
    if (len > 0 && write(fd, content, len) != (ssize_t)len) {
        (void)close(fd);
        printf("[ogbackup]write restore marker %s failed, error %d\n", path, errno);
        return OG_ERROR;
    }
    if (fsync(fd) != 0) {
        (void)close(fd);
        printf("[ogbackup]fsync restore marker %s failed, error %d\n", path, errno);
        return OG_ERROR;
    }
    (void)close(fd);
    int32 dir_fd = open(target_dir, O_RDONLY | O_BINARY);
    if (dir_fd < 0 || fsync(dir_fd) != 0) {
        if (dir_fd >= 0) {
            (void)close(dir_fd);
        }
        printf("[ogbackup]fsync restore marker directory %s failed, error %d\n", target_dir, errno);
        return OG_ERROR;
    }
    (void)close(dir_fd);
    return OG_SUCCESS;
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
    if (tmp[0] == '\0' || cm_dir_exist(tmp)) {
        return OG_SUCCESS;
    }
    if (cm_create_dir_ex(tmp) != OG_SUCCESS) {
        printf("[ogbackup]create parent directory %s failed for %s, error %d\n", tmp, path, errno);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 bak_offline_dss_parent_is_vg_root(const char *parent)
{
    if (parent == NULL || parent[0] != '+' || parent[1] == '\0') {
        return OG_FALSE;
    }
    return strchr(parent + 1, '/') == NULL ? OG_TRUE : OG_FALSE;
}

static char *bak_offline_trim_ascii(char *text)
{
    if (text == NULL) {
        return NULL;
    }
    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)*(end - 1))) {
        *(--end) = '\0';
    }
    return text;
}

static bool32 bak_offline_dss_vg_name_equal(const char *config_name, const char *vg)
{
    if (config_name == NULL || vg == NULL || vg[0] != '+') {
        return OG_FALSE;
    }
    if (strcmp(config_name, vg) == 0) {
        return OG_TRUE;
    }
    return strcmp(config_name, vg + 1) == 0 ? OG_TRUE : OG_FALSE;
}

static status_t bak_offline_validate_dss_vg_from_config(const char *vg, const char *path)
{
    const char *dss_home = getenv("DSS_HOME");
    if (dss_home == NULL || dss_home[0] == '\0') {
        bak_offline_set_last_dss_error("DSS provider unavailable: DSS_HOME is not set while validating %s target=%s",
            vg, path);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    char conf_path[OG_MAX_FILE_PATH_LENGH] = {0};
    int32 ret = snprintf_s(conf_path, sizeof(conf_path), sizeof(conf_path) - 1,
        "%s/cfg/%s", dss_home, BAK_OFFLINE_DSS_VG_CONF);
    if (ret == -1) {
        bak_offline_set_last_dss_error("DSS provider unavailable: DSS VG config path is too long, DSS_HOME=%s",
            dss_home);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    FILE *fp = fopen(conf_path, "r");
    if (fp == NULL) {
        bak_offline_set_last_dss_error("DSS provider unavailable: cannot read DSS VG config %s for %s target=%s, "
            "errno=%d (%s)", conf_path, vg, path, errno, strerror(errno));
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    char line[OG_MAX_CONFIG_LINE_SIZE] = {0};
    uint32 line_no = 0;
    bool32 found = OG_FALSE;
    char entry_path[OG_MAX_FILE_PATH_LENGH] = {0};
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_no++;
        char *comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }
        char *trimmed = bak_offline_trim_ascii(line);
        if (trimmed == NULL || trimmed[0] == '\0') {
            continue;
        }
        char *sep = strchr(trimmed, ':');
        if (sep == NULL) {
            continue;
        }
        *sep = '\0';
        char *name = bak_offline_trim_ascii(trimmed);
        char *value = bak_offline_trim_ascii(sep + 1);
        if (name == NULL || value == NULL || name[0] == '\0' || value[0] == '\0') {
            continue;
        }
        if (bak_offline_dss_vg_name_equal(name, vg) == OG_TRUE) {
            found = OG_TRUE;
            if (strlen(value) >= sizeof(entry_path) || strcpy_s(entry_path, sizeof(entry_path), value) != EOK) {
                (void)fclose(fp);
                bak_offline_set_last_dss_error("DSS parent VG configured but entry path is too long: %s line=%u "
                    "target=%s", vg, line_no, path);
                printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
                return OG_ERROR;
            }
            break;
        }
    }
    (void)fclose(fp);

    if (found != OG_TRUE) {
        bak_offline_set_last_dss_error("DSS parent VG does not exist: %s target=%s config=%s",
            vg, path, conf_path);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    if (access(entry_path, F_OK) != 0) {
        bak_offline_set_last_dss_error("DSS parent VG configured but target volume entry does not exist: %s "
            "entry=%s target=%s errno=%d (%s)", vg, entry_path, path, errno, strerror(errno));
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    if (access(entry_path, R_OK | W_OK) != 0) {
        bak_offline_set_last_dss_error("DSS parent VG configured but target volume entry has insufficient "
            "permissions: %s entry=%s target=%s errno=%d (%s)", vg, entry_path, path, errno, strerror(errno));
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    printf("[ogbackup]storage=dss DSS parent VG validated=%s target=%s source=dss_vg_conf entry=%s\n",
        vg, path, entry_path);
    return OG_SUCCESS;
}

static status_t bak_offline_validate_dss_vg_root(device_type_t type, const char *vg, const char *path)
{
    char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
    cm_reset_error();
    if (cm_exist_device_dir(type, vg)) {
        printf("[ogbackup]storage=dss DSS parent VG validated=%s target=%s source=dss-provider\n", vg, path);
        return OG_SUCCESS;
    }
    bak_offline_format_cm_error(provider_error, sizeof(provider_error));

    char vg_path[OG_MAX_FILE_PATH_LENGH] = {0};
    int32 ret = snprintf_s(vg_path, sizeof(vg_path), sizeof(vg_path) - 1, "%s/", vg);
    cm_reset_error();
    if (ret != -1 && cm_exist_device_dir(type, vg_path)) {
        printf("[ogbackup]storage=dss DSS parent VG validated=%s target=%s source=dss-provider\n", vg, path);
        return OG_SUCCESS;
    }
    if (ret != -1) {
        bak_offline_format_cm_error(provider_error, sizeof(provider_error));
    }

    if (g_bak_offline_dss_inplace_offline_vg_check != OG_TRUE &&
        bak_offline_validate_dss_vg_from_config(vg, path) == OG_SUCCESS) {
        printf("[ogbackup]storage=dss DSS provider stat unavailable for parent=%s target=%s; "
               "using offline dss_vg_conf validation; provider_status=%s\n",
            vg, path, provider_error);
        return OG_SUCCESS;
    }

    bak_offline_set_last_dss_error("DSS parent VG does not exist or is not accessible: %s target=%s; "
        "provider_status=%s", vg, path, provider_error);
    printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
    return OG_ERROR;
}

status_t bak_offline_validate_dss_device_target(device_type_t type, const char *path)
{
    if (type != DEV_TYPE_RAW) {
        printf("[ogbackup]DSS device target resolve failed: unsupported device type=%u target=%s\n",
            (uint32)type, path == NULL ? "<null>" : path);
        return OG_ERROR;
    }
    if (path == NULL || path[0] == '\0' || cm_device_type(path) != DEV_TYPE_RAW) {
        printf("[ogbackup]DSS device target resolve failed: target is not a DSS +vg path: %s\n",
            path == NULL ? "<null>" : path);
        return OG_ERROR;
    }

    char parent[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strlen(path) >= sizeof(parent) || strcpy_s(parent, sizeof(parent), path) != EOK) {
        printf("[ogbackup]DSS device target resolve failed: target path is too long: %s\n", path);
        return OG_ERROR;
    }
    char *slash = strrchr(parent, '/');
    if (slash == NULL) {
        printf("[ogbackup]DSS device target resolve failed: target has no parent VG: %s\n", path);
        return OG_ERROR;
    }
    *slash = '\0';
    if (parent[0] == '\0') {
        printf("[ogbackup]DSS device target resolve failed: target has empty parent VG: %s\n", path);
        return OG_ERROR;
    }

    printf("[ogbackup]storage=dss dss path detected; DSS device target resolved=%s parent=%s\n", path, parent);
    if (bak_offline_dss_parent_is_vg_root(parent) == OG_TRUE) {
        printf("[ogbackup]storage=dss skip local mkdir for DSS virtual path parent=%s target=%s\n", parent, path);
        return bak_offline_validate_dss_vg_root(type, parent, path);
    }
    if (cm_exist_device_dir(type, parent)) {
        printf("[ogbackup]storage=dss DSS parent directory validated=%s target=%s\n", parent, path);
        return OG_SUCCESS;
    }
    printf("[ogbackup]DSS parent directory does not exist or is not accessible: %s target=%s\n", parent, path);
    return OG_ERROR;
}

status_t bak_offline_probe_dss_device_target(device_type_t type, const char *path, uint32 flags)
{
    if (type != DEV_TYPE_RAW) {
        printf("[ogbackup]DSS target preparation probe failed: unsupported device type=%u target=%s\n",
            (uint32)type, path == NULL ? "<null>" : path);
        return OG_ERROR;
    }
    if (bak_offline_validate_dss_device_target(type, path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (g_raw_device_op.raw_stat == NULL || g_raw_device_op.raw_open == NULL) {
        bak_offline_set_last_dss_error("DSS target preparation probe failed: DSS provider API is not loaded "
            "target=%s raw_stat=%s raw_open=%s", path,
            g_raw_device_op.raw_stat == NULL ? "missing" : "loaded",
            g_raw_device_op.raw_open == NULL ? "missing" : "loaded");
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    dss_stat_t item = {0};
    cm_reset_error();
    status_t stat_status = g_raw_device_op.raw_stat(path, &item);
    char stat_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
    bak_offline_format_cm_error(stat_error, sizeof(stat_error));
    printf("[ogbackup]storage=dss DSS target preparation probe: target=%s provider=libdssapi api=dss_stat "
           "rc=%d cm_status=%s depends_uds=yes no_write=true\n",
        path, (int32)stat_status, stat_error);

    if (stat_status != OG_SUCCESS) {
        /* Parent validation above used the loaded provider and proved that the
         * planned +vg namespace is reachable.  A missing leaf is valid because
         * restore must be able to recreate lost data, redo, archive or control objects.
         * Recheck it after the failed stat so a provider/UDS outage is not
         * misclassified as a missing leaf. */
        char parent[OG_MAX_FILE_PATH_LENGH] = {0};
        if (strlen(path) >= sizeof(parent) || strcpy_s(parent, sizeof(parent), path) != EOK) {
            return OG_ERROR;
        }
        char *slash = strrchr(parent, '/');
        if (slash == NULL) {
            return OG_ERROR;
        }
        *slash = '\0';
        cm_reset_error();
        if (cm_exist_device_dir(type, parent) != OG_TRUE) {
            char parent_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
            bak_offline_format_cm_error(parent_error, sizeof(parent_error));
            bak_offline_set_last_dss_error("DSS target preparation probe failed: leaf stat and subsequent "
                "provider parent check both failed; target=%s parent=%s stat_status=%s parent_status=%s",
                path, parent, stat_error, parent_error);
            printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
            return OG_ERROR;
        }
        printf("[ogbackup]storage=dss target object is absent and will be created after marker: "
               "target=%s no_write=true parent_provider_validated=true\n", path);
        cm_reset_error();
        return OG_SUCCESS;
    }

    int32 handle = OG_INVALID_HANDLE;
    uint32 open_flags = (flags & ~(uint32)O_RDWR) | O_RDONLY | O_BINARY;
    cm_reset_error();
    status_t open_status = g_raw_device_op.raw_open(path, open_flags, &handle);
    char open_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
    bak_offline_format_cm_error(open_error, sizeof(open_error));
    printf("[ogbackup]storage=dss DSS target preparation probe: target=%s provider=libdssapi api=dss_fopen "
           "flags=%u rc=%d cm_status=%s depends_uds=yes no_write=true no_create=true\n",
        path, open_flags, (int32)open_status, open_error);
    if (open_status != OG_SUCCESS) {
        bak_offline_set_last_dss_error("DSS target preparation probe failed: provider unavailable or target "
            "read-only open failed; target=%s provider=libdssapi api=dss_fopen flags=%u depends_uds=yes "
            "stat_status=%s open_status=%s", path, open_flags, stat_error, open_error);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    if (g_raw_device_op.raw_close != NULL) {
        g_raw_device_op.raw_close(handle);
    }
    printf("[ogbackup]storage=dss DSS target preparation probe succeeded: target=%s provider=libdssapi "
           "api=dss_fopen flags=%u read_only=true no_write=true no_create=true\n",
        path, open_flags);
    return OG_SUCCESS;
}

status_t bak_offline_stat_dss_device_target(device_type_t type, const char *path, uint64 *size,
    uint64 *written_size)
{
    if (type != DEV_TYPE_RAW || path == NULL || size == NULL || written_size == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_validate_dss_device_target(type, path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (g_raw_device_op.raw_stat == NULL) {
        bak_offline_set_last_dss_error("DSS target stat failed: DSS provider API is not loaded target=%s", path);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    dss_stat_t item = {0};
    if (g_raw_device_op.raw_stat(path, &item) != OG_SUCCESS) {
        char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
        bak_offline_format_cm_error(provider_error, sizeof(provider_error));
        bak_offline_set_last_dss_error("DSS target stat failed: target=%s provider=libdssapi api=dss_stat; %s",
            path, provider_error);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    *size = item.size;
    *written_size = item.written_size;
    return OG_SUCCESS;
}

status_t bak_offline_init_dss_device_from_env(void)
{
    bak_offline_clear_last_dss_error();
    const char *dss_home = getenv("DSS_HOME");
    if (dss_home == NULL || dss_home[0] == '\0') {
        bak_offline_set_last_dss_error("--storage=dss requires DSS_HOME in the environment");
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }

    char conn_path[OG_MAX_FILE_PATH_LENGH] = {0};
    int32 ret = snprintf_s(conn_path, sizeof(conn_path), sizeof(conn_path) - 1,
        "%s%s/.dss_unix_d_socket", BAK_OFFLINE_DSS_CONN_PREFIX, dss_home);
    if (ret == -1) {
        bak_offline_set_last_dss_error("DSS connection path is too long for DSS_HOME=%s", dss_home);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    if (srv_device_init(conn_path, DSS_LOG_LEVEL_WARN) != OG_SUCCESS) {
        char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
        bak_offline_format_cm_error(provider_error, sizeof(provider_error));
        bak_offline_set_last_dss_error("DSS provider unavailable: init DSS device provider failed, conn_path=%s; %s",
            conn_path, provider_error);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    printf("[ogbackup]DSS device provider initialized, conn_path=%s\n", conn_path);
    return OG_SUCCESS;
}

status_t bak_offline_create_device_parent(device_type_t type, const char *path)
{
    if (type == DEV_TYPE_FILE) {
        return bak_offline_mkdir_parent(path);
    }
    if (type != DEV_TYPE_RAW) {
        printf("[ogbackup]offline restore device type %u is not supported\n", (uint32)type);
        return OG_ERROR;
    }
    char parent[OG_MAX_FILE_PATH_LENGH] = {0};
    if (path == NULL || strlen(path) >= sizeof(parent) || strcpy_s(parent, sizeof(parent), path) != EOK) {
        return OG_ERROR;
    }
    char *slash = strrchr(parent, '/');
    if (slash == NULL) {
        printf("[ogbackup]DSS device target resolve failed: target has no parent VG: %s\n", path);
        return OG_ERROR;
    }
    *slash = '\0';
    printf("[ogbackup]storage=dss dss path detected; DSS device target resolved=%s parent=%s\n", path, parent);
    if (bak_offline_dss_parent_is_vg_root(parent) == OG_TRUE) {
        printf("[ogbackup]storage=dss skip local mkdir for DSS virtual path parent=%s target=%s\n", parent, path);
        return bak_offline_validate_dss_vg_root(type, parent, path);
    }
    if (parent[0] == '\0' || cm_exist_device_dir(type, parent)) {
        printf("[ogbackup]storage=dss DSS parent directory validated=%s target=%s\n",
            parent[0] == '\0' ? "<none>" : parent, path);
        return OG_SUCCESS;
    }
    if (cm_create_device_dir_ex(type, parent) != OG_TRUE) {
        printf("[ogbackup]create DSS parent directory %s failed for %s\n", parent, path);
        return OG_ERROR;
    }
    printf("[ogbackup]storage=dss DSS parent directory validated=%s target=%s\n", parent, path);
    return OG_SUCCESS;
}

status_t bak_offline_open_or_create_device(const char *path, device_type_t type, uint32 flags, int32 *handle)
{
    if (path == NULL || handle == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_create_device_parent(type, path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (type == DEV_TYPE_RAW && g_bak_offline_dss_inplace_offline_vg_check == OG_TRUE &&
        bak_offline_validate_dss_device_target(type, path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_exist_device(type, path)) {
        if (cm_open_device(path, type, flags, handle) != OG_SUCCESS) {
            char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
            bak_offline_format_cm_error(provider_error, sizeof(provider_error));
            bak_offline_set_last_dss_error("open restore device failed: target=%s type=%u flags=%u; %s",
                path, (uint32)type, flags, provider_error);
            printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (cm_create_device(path, type, flags, handle) != OG_SUCCESS) {
        char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
        bak_offline_format_cm_error(provider_error, sizeof(provider_error));
        bak_offline_set_last_dss_error("create restore device failed: target=%s type=%u flags=%u; %s",
            path, (uint32)type, flags, provider_error);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t bak_offline_write_device_buffer(const char *dst, device_type_t type, const char *buf, uint64 size)
{
    if (dst == NULL || buf == NULL || size > (uint64)INT32_MAX) {
        return OG_ERROR;
    }
    int32 handle = OG_INVALID_HANDLE;
    if (bak_offline_open_or_create_device(dst, type, O_BINARY | O_SYNC | O_RDWR, &handle) != OG_SUCCESS) {
        return OG_ERROR;
    }
    status_t status = cm_truncate_device(type, handle, 0);
    if (status == OG_SUCCESS) {
        status = cm_write_device(type, handle, 0, buf, (int32)size);
    }
    if (status == OG_SUCCESS) {
        status = cm_fsync_device(type, handle);
    }
    if (status != OG_SUCCESS) {
        char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
        bak_offline_format_cm_error(provider_error, sizeof(provider_error));
        bak_offline_set_last_dss_error("write restore device failed: target=%s type=%u size=%llu; %s",
            dst, (uint32)type, size, provider_error);
        printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
    }
    cm_close_device(type, &handle);
    return status;
}

static status_t bak_offline_copy_exact(int32 src_fd, int32 dst_fd, char *buf)
{
    for (;;) {
        ssize_t read_size = read(src_fd, buf, BAK_OFFLINE_COPY_BUFFER_SIZE);
        if (read_size < 0) {
            return OG_ERROR;
        }
        if (read_size == 0) {
            return OG_SUCCESS;
        }
        char *pos = buf;
        ssize_t left = read_size;
        while (left > 0) {
            ssize_t write_size = write(dst_fd, pos, (size_t)left);
            if (write_size <= 0) {
                return OG_ERROR;
            }
            pos += write_size;
            left -= write_size;
        }
    }
}

static status_t bak_offline_fsync_local_parent(const char *path)
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
    if (fd < 0 || fsync(fd) != 0) {
        if (fd >= 0) {
            (void)close(fd);
        }
        printf("[ogbackup]fsync restored file parent %s failed, error %d (%s)\n",
            dir, errno, strerror(errno));
        return OG_ERROR;
    }
    (void)close(fd);
    return OG_SUCCESS;
}

status_t bak_offline_copy_file_stream(const char *src, const char *dst)
{
    if (src == NULL || dst == NULL) {
        return OG_ERROR;
    }
    if (bak_offline_check_no_symlink(src, OG_FALSE) != OG_SUCCESS ||
        bak_offline_mkdir_parent(dst) != OG_SUCCESS ||
        bak_offline_check_no_symlink(dst, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    int32 src_fd = open(src, O_RDONLY | O_BINARY);
    if (src_fd < 0) {
        printf("[ogbackup]open source backup file %s failed, error %d (%s)\n", src, errno, strerror(errno));
        return OG_ERROR;
    }
    int32 dst_fd = open(dst, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
    if (dst_fd < 0) {
        printf("[ogbackup]open target restore file %s failed, parent exists=%s, error %d (%s)\n",
            dst, "unknown", errno, strerror(errno));
        (void)close(src_fd);
        return OG_ERROR;
    }

    char *buf = (char *)malloc(BAK_OFFLINE_COPY_BUFFER_SIZE);
    if (buf == NULL) {
        printf("[ogbackup]allocate restore copy buffer failed, size=%u\n", (uint32)BAK_OFFLINE_COPY_BUFFER_SIZE);
        (void)close(dst_fd);
        (void)close(src_fd);
        return OG_ERROR;
    }
    status_t status = bak_offline_copy_exact(src_fd, dst_fd, buf);
    int32 saved_errno = errno;
    CM_FREE_PTR(buf);
    if (status != OG_SUCCESS) {
        printf("[ogbackup]stream copy backup file %s to %s failed, error %d (%s)\n",
            src, dst, saved_errno, strerror(saved_errno));
    }
    if (fsync(dst_fd) != 0) {
        printf("[ogbackup]fsync restored file %s failed, error %d (%s)\n", dst, errno, strerror(errno));
        status = OG_ERROR;
    }
    (void)close(dst_fd);
    (void)close(src_fd);
    if (status == OG_SUCCESS) {
        status = bak_offline_fsync_local_parent(dst);
    }
    return status;
}

status_t bak_offline_write_device_stream(const char *src, const char *dst, device_type_t type)
{
    if (type == DEV_TYPE_FILE) {
        return bak_offline_copy_file_stream(src, dst);
    }
    if (src == NULL || dst == NULL || type != DEV_TYPE_RAW) {
        return OG_ERROR;
    }
    int32 src_fd = open(src, O_RDONLY | O_BINARY);
    if (src_fd < 0) {
        printf("[ogbackup]open source backup file %s failed, error %d (%s)\n", src, errno, strerror(errno));
        return OG_ERROR;
    }
    int32 dst_handle = OG_INVALID_HANDLE;
    if (bak_offline_open_or_create_device(dst, type, O_BINARY | O_SYNC | O_RDWR, &dst_handle) != OG_SUCCESS) {
        (void)close(src_fd);
        return OG_ERROR;
    }
    if (cm_truncate_device(type, dst_handle, 0) != OG_SUCCESS) {
        cm_close_device(type, &dst_handle);
        (void)close(src_fd);
        return OG_ERROR;
    }
    char *buf = (char *)malloc(BAK_OFFLINE_COPY_BUFFER_SIZE);
    if (buf == NULL) {
        cm_close_device(type, &dst_handle);
        (void)close(src_fd);
        return OG_ERROR;
    }

    int64 offset = 0;
    status_t status = OG_SUCCESS;
    for (;;) {
        ssize_t read_size = read(src_fd, buf, BAK_OFFLINE_COPY_BUFFER_SIZE);
        if (read_size < 0) {
            status = OG_ERROR;
            break;
        }
        if (read_size == 0) {
            break;
        }
        if (cm_write_device(type, dst_handle, offset, buf, (int32)read_size) != OG_SUCCESS) {
            char provider_error[OG_MAX_CONFIG_LINE_SIZE] = {0};
            bak_offline_format_cm_error(provider_error, sizeof(provider_error));
            bak_offline_set_last_dss_error("write backup file to DSS device failed: source=%s target=%s "
                "offset=%lld size=%zd; %s", src, dst, offset, read_size, provider_error);
            printf("[ogbackup]%s\n", bak_offline_get_last_dss_error());
            status = OG_ERROR;
            break;
        }
        offset += read_size;
    }

    if (status == OG_SUCCESS && cm_fsync_device(type, dst_handle) != OG_SUCCESS) {
        bak_offline_set_last_dss_error("fsync restored DSS device failed: target=%s", dst);
        status = OG_ERROR;
    }

    CM_FREE_PTR(buf);
    cm_close_device(type, &dst_handle);
    (void)close(src_fd);
    return status;
}
