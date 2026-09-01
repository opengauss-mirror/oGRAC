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
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * ogbackup_restore.c
 *
 *
 * IDENTIFICATION
 * src/utils/ogbackup/ogbackup_restore.c
 *
 * -------------------------------------------------------------------------
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#include "ogbackup_module.h"
#include "ogbackup_restore.h"
#include "ogbackup_common.h"
#include "bak_format_reader.h"
#include "bak_offline_decoder.h"
#include "bak_page_restore.h"
#include "bak_storage_adapter.h"
#include "bak_ctrl_restore.h"
#include "ogbackup_scheme_d.h"
#include "cm_file.h"
#include "bak_common.h"

#define OGBAK_RESTORE_MAX_BACKUPS 1024
#define OGBAK_RESTORE_MAX_FILES 8192
#define OGBAK_RESTORE_MAX_ARCH_RANGES 8192
#define OGBAK_RESTORE_READ_BUF_SIZE SIZE_K(64)
#define OGBAK_RESTORE_FNV_OFFSET 2166136261U
#define OGBAK_RESTORE_FNV_PRIME 16777619U
#define OGBAK_RESTORE_EXPECTED_MAJOR BAK_VERSION_MAJOR
#define OGBAK_RESTORE_EXPECTED_MINOR BAK_VERSION_MIN
#define OGBAK_RESTORE_EXPECTED_MAGIC BAK_VERSION_MAGIC
#define OGBAK_RESTORE_MARKER_IN_PROGRESS ".ogbackup_offline_restore_in_progress"
#define OGBAK_RESTORE_MARKER_FAILED ".ogbackup_offline_restore_failed"
#define OGBAK_RESTORE_MARKER_COMPLETE ".ogbackup_offline_restore_file_phase_complete"
#define OGBAK_RESTORE_PATH_MAP_NONE "none"
#define OGBAK_RESTORE_PATH_MAP_AUTO "auto"
#define OGBAK_RESTORE_STORAGE_LOCAL "local"
#define OGBAK_RESTORE_STORAGE_DSS "dss"
#define OGBAK_RESTORE_DSS_INPLACE_PROCESS_COUNT 4
#define OGBAK_RESTORE_PROC_CMDLINE_SIZE SIZE_K(4)
#define OGBAK_RESTORE_TMP_TEMPLATE "/tmp/ogbackup_decoded_XXXXXX"

static const struct option g_ogbak_restore_options[] = {
    {OGBAK_LONG_OPTION_OFFLINE_RESTORE, no_argument, NULL, OGBAK_SHORT_OPTION_OFFLINE},
    {OGBAK_LONG_OPTION_BACKUP_DIR, required_argument, NULL, OGBAK_SHORT_OPTION_BACKUP_DIR},
    {OGBAK_LONG_OPTION_TARGET_DIR, required_argument, NULL, OGBAK_SHORT_OPTION_TARGET_DIR},
    {OGBAK_LONG_OPTION_BACKUP_ID, required_argument, NULL, OGBAK_SHORT_OPTION_BACKUP_ID},
    {OGBAK_LONG_OPTION_TARGET_TIME, required_argument, NULL, OGBAK_SHORT_OPTION_TARGET_TIME},
    {OGBAK_LONG_OPTION_PASSWORD, required_argument, NULL, OGBAK_SHORT_OPTION_PASSWORD},
    {OGBAK_LONG_OPTION_PASSWORD_FILE, required_argument, NULL, OGBAK_PARSE_OPTION_PASSWORD_FILE},
    {OGBAK_LONG_OPTION_DRY_RUN, no_argument, NULL, OGBAK_SHORT_OPTION_DRY_RUN},
    {OGBAK_LONG_OPTION_IN_PLACE, no_argument, NULL, OGBAK_PARSE_OPTION_IN_PLACE},
    {OGBAK_LONG_OPTION_FORCE, no_argument, NULL, OGBAK_SHORT_OPTION_FORCE},
    {OGBAK_LONG_OPTION_PARALLEL, required_argument, NULL, OGBAK_SHORT_OPTION_PARALLEL},
    {0, 0, 0, 0}
};

static bool32 ogbak_restore_storage_dss(ogbak_param_t *param);
static status_t ogbak_restore_configure_storage(ogbak_param_t *param, ogbak_offline_plan_t *plan);
static ogbak_offline_backup_t *ogbak_restore_find_plan_backup(ogbak_offline_plan_t *plan, const char *backup_id);
static status_t ogbak_restore_build_decode_opts(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    ogbak_offline_file_t *file, bak_file_t *scratch_file, bak_offline_decode_opts_t *opts);
static status_t ogbak_restore_decode_payload_to_temp(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    ogbak_offline_file_t *file, const char *src_path, char *tmp_path, uint32 tmp_path_size, uint64 *logical_size);
static status_t ogbak_restore_resolve_src(const char *backup_dir, const char *src, char *path);

/* Build an archive name using the same destination and format as online
 * restore. bak_file_t does not persist the original archive target. */
static status_t ogbak_restore_resolve_original_archive_target(const char *archive_path,
    ogbak_offline_file_t *file, bool32 expect_dss, char *target, uint32 target_size)
{
    if (archive_path == NULL || file == NULL || target == NULL || target_size == 0 ||
        file->type != OGBAK_RESTORE_FILE_ARCHIVE) {
        return OG_ERROR;
    }
    const char *data_home = getenv("OGDB_DATA");
    if (data_home == NULL || data_home[0] == '\0') {
        printf("[ogbackup]in-place archive target requires OGDB_DATA to locate ogracd.ini\n");
        return OG_ERROR;
    }
    char cfg_path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (snprintf_s(cfg_path, sizeof(cfg_path), sizeof(cfg_path) - 1, "%s/cfg/ogracd.ini", data_home) == -1) {
        return OG_ERROR;
    }
    char cfg_buf[OG_MAX_CONFIG_FILE_SIZE] = {0};
    uint32 cfg_size = sizeof(cfg_buf);
    if (cm_read_config_file(cfg_path, cfg_buf, &cfg_size, OG_FALSE, OG_TRUE) != OG_SUCCESS) {
        printf("[ogbackup]read in-place archive configuration failed: %s\n", cfg_path);
        return OG_ERROR;
    }
    char dest[OG_FILE_NAME_BUFFER_SIZE] = {0};
    char format[OG_PARAM_BUFFER_SIZE] = "arch_%t_%r_%s.arc";
    text_t all = {cfg_buf, cfg_size};
    text_t line;
    while (cm_fetch_text(&all, '\n', '\0', &line)) {
        cm_trim_text(&line);
        if (line.len == 0 || line.str[0] == '#') {
            continue;
        }
        text_t name;
        text_t value;
        cm_split_text(&line, '=', '\0', &name, &value);
        cm_trim_text(&name);
        cm_trim_text(&value);
        if (cm_text_str_equal_ins(&name, "ARCHIVE_DEST_1")) {
            if (value.len >= OG_FILE_NAME_BUFFER_SIZE ||
                memcpy_s(dest, sizeof(dest), value.str, value.len) != EOK) {
                return OG_ERROR;
            }
            dest[value.len] = '\0';
            if (strncmp(dest, "location=", strlen("location=")) == 0) {
                (void)memmove(dest, dest + strlen("location="), strlen(dest) - strlen("location=") + 1);
            }
        } else if (cm_text_str_equal_ins(&name, "ARCHIVE_FORMAT")) {
            if (value.len >= sizeof(format) || memcpy_s(format, sizeof(format), value.str, value.len) != EOK) {
                return OG_ERROR;
            }
            format[value.len] = '\0';
        }
    }
    if ((expect_dss == OG_TRUE && (dest[0] != '+' || dest[1] == '\0')) ||
        (expect_dss != OG_TRUE && dest[0] != '/')) {
        printf("[ogbackup]archive destination storage type mismatches restore plan: %s\n", dest);
        return OG_ERROR;
    }

    int32 fd = open(archive_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        return OG_ERROR;
    }
    log_file_head_t head;
    ssize_t nread = pread(fd, &head, sizeof(head), 0);
    (void)close(fd);
    if (nread != (ssize_t)sizeof(head)) {
        printf("[ogbackup]read archive payload header failed: %s\n", archive_path);
        return OG_ERROR;
    }
    if (head.asn != file->file_id || (file->rst_id != 0 && head.rst_id != file->rst_id)) {
        printf("[ogbackup]archive payload header does not match backup catalog: source=%s "
               "catalog_asn=%u catalog_rst=%u header_asn=%u header_rst=%u\n",
            archive_path, file->file_id, file->rst_id, head.asn, head.rst_id);
        return OG_ERROR;
    }
    char name[OG_FILE_NAME_BUFFER_SIZE] = {0};
    uint32 used = 0;
    for (const char *p = format; *p != '\0'; p++) {
        if (*p != '%') {
            if (used + 1 >= sizeof(name)) return OG_ERROR;
            name[used++] = *p;
            continue;
        }
        p++;
        uint64 value = 0;
        if (*p == 't' || *p == 'T') value = file->node_id;
        else if (*p == 'r' || *p == 'R') value = head.rst_id;
        else if (*p == 's' || *p == 'S') value = head.asn;
        else if (*p == 'd' || *p == 'D') value = head.first_lsn;
        else if (*p == 'e' || *p == 'E') value = head.last_lsn;
        else return OG_ERROR;
        int32 written = snprintf_s(name + used, sizeof(name) - used, sizeof(name) - used - 1,
            "%llu", (unsigned long long)value);
        if (written < 0) return OG_ERROR;
        used += (uint32)written;
    }
    if (snprintf_s(target, target_size, target_size - 1, "%s/%s", dest, name) == -1) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

typedef struct st_ogbak_scheme_d_target_size {
    char path[OG_MAX_FILE_PATH_LENGH];
    char type[OG_NAME_BUFFER_SIZE];
    uint32 file_id;
    uint32 node_id;
    uint64 control_size;
    uint64 payload_max_end;
    uint64 required_min_size;
    uint64 total_payload_bytes;
    uint32 range_count;
    uint32 unique_page_count;
    bool32 payload_present;
    bool32 payload_full_coverage;
    bool32 create_required;
    bool32 blocked;
    char blocked_reason[OG_MAX_CONFIG_LINE_SIZE];
} ogbak_scheme_d_target_size_t;

typedef struct st_ogbak_scheme_d_target_manifest {
    ogbak_scheme_d_target_size_t targets[OGBAK_RESTORE_MAX_FILES];
    uint32 target_count;
    uint32 unknown_count;
} ogbak_scheme_d_target_manifest_t;

typedef struct st_ogbak_scheme_d_page_scan_ctx {
    ogbak_scheme_d_target_size_t *target;
    ogbak_scheme_d_plan_t *plan;
    uint64 existing_size;
    uint64 written_size;
    const char *payload_source;
    char *err_buf;
    uint32 err_size;
} ogbak_scheme_d_page_scan_ctx_t;

static const ogbak_scheme_d_plan_t *g_ogbak_scheme_d_active_plan = NULL;

#ifdef CMS_UT_TEST
static ogbak_scheme_d_provider_check_hook_t g_scheme_d_provider_hook = NULL;
static ogbak_scheme_d_stat_target_hook_t g_scheme_d_stat_hook = NULL;
static ogbak_scheme_d_init_dss_hook_t g_scheme_d_init_dss_hook = NULL;
static ogbak_scheme_d_preflight_probe_hook_t g_scheme_d_preflight_probe_hook = NULL;
static ogbak_restore_execute_files_hook_t g_restore_execute_hook = NULL;

void ogbak_restore_set_scheme_d_unit_test_hooks(ogbak_scheme_d_provider_check_hook_t provider_hook,
    ogbak_scheme_d_stat_target_hook_t stat_hook, ogbak_scheme_d_init_dss_hook_t init_dss_hook,
    ogbak_scheme_d_preflight_probe_hook_t preflight_probe_hook, ogbak_restore_execute_files_hook_t execute_hook)
{
    g_scheme_d_provider_hook = provider_hook;
    g_scheme_d_stat_hook = stat_hook;
    g_scheme_d_init_dss_hook = init_dss_hook;
    g_scheme_d_preflight_probe_hook = preflight_probe_hook;
    g_restore_execute_hook = execute_hook;
}

void ogbak_restore_clear_scheme_d_unit_test_hooks(void)
{
    g_scheme_d_provider_hook = NULL;
    g_scheme_d_stat_hook = NULL;
    g_scheme_d_init_dss_hook = NULL;
    g_scheme_d_preflight_probe_hook = NULL;
    g_restore_execute_hook = NULL;
}
#endif

static bool32 ogbak_restore_is_empty_str(const char *str)
{
    return (str == NULL || str[0] == '\0') ? OG_TRUE : OG_FALSE;
}

static void ogbak_restore_hide_sensitive_arg(char *value)
{
    while (value != NULL && *value != '\0') {
        *value++ = 'x';
    }
}

static bool32 ogbak_restore_str_equal_ins(const char *left, const char *right)
{
    if (left == NULL || right == NULL) {
        return OG_FALSE;
    }
    return strcasecmp(left, right) == 0 ? OG_TRUE : OG_FALSE;
}

static status_t ogbak_restore_copy_str(char *dst, uint32 dst_size, const char *src)
{
    if (src == NULL) {
        return OG_SUCCESS;
    }
    if (strlen(src) >= dst_size) {
        printf("[ogbackup]offline restore manifest value is too long: %s\n", src);
        return OG_ERROR;
    }
    errno_t ret = strcpy_s(dst, dst_size, src);
    if (ret != EOK) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_join_path(const char *dir, const char *name, char *path, uint32 path_size)
{
    if (dir == NULL || name == NULL || path == NULL) {
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

static status_t ogbak_restore_resolve_backupset_path(const char *backup_dir, const char *value, char *path)
{
    char candidate[OG_MAX_FILE_PATH_LENGH] = {0};
    if (value != NULL && value[0] != '\0') {
        if (value[0] == '/') {
            if (ogbak_restore_copy_str(candidate, OG_MAX_FILE_PATH_LENGH, value) != OG_SUCCESS) {
                return OG_ERROR;
            }
        } else if (ogbak_restore_join_path(backup_dir, value, candidate, OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (ogbak_restore_join_path(backup_dir, "backupset", candidate, OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (cm_dir_exist(candidate)) {
        return ogbak_restore_join_path(candidate, "backupset", path, OG_MAX_FILE_PATH_LENGH);
    }
    if (cm_file_exist(candidate) || strcmp(strrchr(candidate, '/') == NULL ? candidate : strrchr(candidate, '/') + 1,
        "backupset") == 0) {
        return ogbak_restore_copy_str(path, OG_MAX_FILE_PATH_LENGH, candidate);
    }
    return ogbak_restore_join_path(candidate, "backupset", path, OG_MAX_FILE_PATH_LENGH);
}

static status_t ogbak_restore_generate_bak_file_name(const char *backupset_dir, bak_head_t *head,
    bak_file_t *file, char *path, uint32 path_size)
{
    errno_t ret;
    switch (file->type) {
        case BACKUP_CTRL_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "%s/ctrl_%d_%d.bak", backupset_dir, 0, 0);
            break;
        case BACKUP_DATA_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "%s/data_%s_%u_%u.bak", backupset_dir,
                file->spc_name, file->id, file->sec_id);
            break;
        case BACKUP_LOG_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "%s/log_%u_%u_0.bak", backupset_dir,
                file->inst_id, file->id);
            break;
        case BACKUP_ARCH_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "%s/arch_%u_%u_0.bak", backupset_dir,
                file->inst_id, file->id);
            break;
        case BACKUP_HEAD_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "%s/backupset", backupset_dir);
            break;
        default:
            printf("[ogbackup]unsupported backupset file type %u in %s\n", (uint32)file->type, head->attr.tag);
            return OG_ERROR;
    }
    if (ret == -1) {
        printf("[ogbackup]backupset file path is too long under %s\n", backupset_dir);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_reject_dbstor_payload(const char *backupset_dir, bak_file_t *file)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    errno_t ret;

    if (file->type == BACKUP_LOG_FILE) {
        ret = snprintf_s(path, OG_MAX_FILE_PATH_LENGH, OG_MAX_FILE_PATH_LENGH - 1,
            "%s/log_%u_%u_%llx_%llx.bak", backupset_dir, file->inst_id, file->id,
            file->start_lsn, file->end_lsn);
    } else if (file->type == BACKUP_ARCH_FILE) {
        ret = snprintf_s(path, OG_MAX_FILE_PATH_LENGH, OG_MAX_FILE_PATH_LENGH - 1,
            "%s/arch_%u_%u_%llx_%llx.bak", backupset_dir, file->inst_id, file->id,
            file->start_lsn, file->end_lsn);
    } else {
        return OG_SUCCESS;
    }
    if (ret == -1) {
        return OG_ERROR;
    }
    if (cm_file_exist(path)) {
        printf("[ogbackup]backup payload %s uses DBStor naming; offline restore does not support DBStor yet\n", path);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_generate_target_name(bak_file_t *file, char *path, uint32 path_size)
{
    errno_t ret;
    switch (file->type) {
        case BACKUP_CTRL_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "data/ctrl1");
            break;
        case BACKUP_DATA_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "data/data_%s_%u.dbf", file->spc_name, file->id);
            break;
        case BACKUP_LOG_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "redo/log_%u_%u.bak", file->inst_id, file->id);
            break;
        case BACKUP_ARCH_FILE:
            ret = snprintf_s(path, path_size, path_size - 1, "arch/arch_%u_%u_%u.bak", file->inst_id,
                file->rst_id, file->id);
            break;
        default:
            ret = snprintf_s(path, path_size, path_size - 1, "other/file_%u_%u.bak", (uint32)file->type, file->id);
            break;
    }
    if (ret == -1) {
        printf("[ogbackup]offline restore target path is too long for backup file %u\n", file->id);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void ogbak_restore_set_failure(char *err_buf, uint32 err_size, const char *fmt, ...)
{
    if (err_buf == NULL || err_size == 0) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    int32 ret = vsnprintf_s(err_buf, err_size, err_size - 1, fmt, args);
    va_end(args);
    if (ret == -1) {
        (void)strcpy_s(err_buf, err_size, "offline restore failed; see previous errors");
    }
}

static const char *ogbak_restore_type_name(ogbak_offline_backup_type_t type)
{
    switch (type) {
        case OGBAK_RESTORE_BAK_FULL:
            return "full";
        case OGBAK_RESTORE_BAK_INCREMENTAL:
            return "incremental";
        case OGBAK_RESTORE_BAK_CUMULATIVE:
            return "cumulative";
        default:
            return "unknown";
    }
}

static const char *ogbak_restore_file_type_name(ogbak_offline_file_type_t type)
{
    switch (type) {
        case OGBAK_RESTORE_FILE_CONTROL:
            return "control";
        case OGBAK_RESTORE_FILE_DATA:
            return "data";
        case OGBAK_RESTORE_FILE_LOG:
            return "log";
        case OGBAK_RESTORE_FILE_ARCHIVE:
            return "arch";
        case OGBAK_RESTORE_FILE_SYMLINK:
            return "symlink";
        default:
            return "other";
    }
}

static status_t ogbak_restore_parse_backup_type(const char *value, ogbak_offline_backup_type_t *type)
{
    if (ogbak_restore_str_equal_ins(value, "full") || ogbak_restore_str_equal_ins(value, "level0")) {
        *type = OGBAK_RESTORE_BAK_FULL;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(value, "incremental") || ogbak_restore_str_equal_ins(value, "diff")) {
        *type = OGBAK_RESTORE_BAK_INCREMENTAL;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(value, "cumulative")) {
        *type = OGBAK_RESTORE_BAK_CUMULATIVE;
        return OG_SUCCESS;
    }
    printf("[ogbackup]unknown offline backup type: %s\n", value);
    return OG_ERROR;
}

static status_t ogbak_restore_parse_file_type(const char *value, ogbak_offline_file_type_t *type)
{
    if (ogbak_restore_str_equal_ins(value, "control") || ogbak_restore_str_equal_ins(value, "ctrl")) {
        *type = OGBAK_RESTORE_FILE_CONTROL;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(value, "data") || ogbak_restore_str_equal_ins(value, "datafile")) {
        *type = OGBAK_RESTORE_FILE_DATA;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(value, "log") || ogbak_restore_str_equal_ins(value, "redo") ||
        ogbak_restore_str_equal_ins(value, "wal")) {
        *type = OGBAK_RESTORE_FILE_LOG;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(value, "arch") || ogbak_restore_str_equal_ins(value, "archive")) {
        *type = OGBAK_RESTORE_FILE_ARCHIVE;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(value, "symlink") || ogbak_restore_str_equal_ins(value, "link")) {
        *type = OGBAK_RESTORE_FILE_SYMLINK;
        return OG_SUCCESS;
    }
    *type = OGBAK_RESTORE_FILE_OTHER;
    return OG_SUCCESS;
}

static status_t ogbak_restore_parse_uint64(const char *value, uint64 *result)
{
    if (value == NULL || value[0] == '\0') {
        return OG_ERROR;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long val = strtoull(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0') {
        printf("[ogbackup]invalid unsigned integer in offline manifest: %s\n", value);
        return OG_ERROR;
    }
    *result = (uint64)val;
    return OG_SUCCESS;
}

static status_t ogbak_restore_parse_uint32(const char *value, uint32 *result)
{
    uint64 val;
    if (ogbak_restore_parse_uint64(value, &val) != OG_SUCCESS || val > UINT32_MAX) {
        return OG_ERROR;
    }
    *result = (uint32)val;
    return OG_SUCCESS;
}

static char *ogbak_restore_token_value(char *token, char **name)
{
    char *eq = strchr(token, '=');
    if (eq == NULL) {
        return NULL;
    }
    *eq = '\0';
    *name = token;
    return eq + 1;
}

static void ogbak_restore_trim_line(char *line)
{
    uint32 len = (uint32)strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' ' ||
        line[len - 1] == '\t')) {
        line[len - 1] = '\0';
        len--;
    }
}

static status_t ogbak_restore_parse_backup_token(ogbak_offline_backup_t *bak, const char *name, const char *value)
{
    if (ogbak_restore_str_equal_ins(name, "id")) {
        return ogbak_restore_copy_str(bak->id, OG_NAME_BUFFER_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "parent") || ogbak_restore_str_equal_ins(name, "parent_id")) {
        return ogbak_restore_copy_str(bak->parent_id, OG_NAME_BUFFER_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "backupset") || ogbak_restore_str_equal_ins(name, "backupset_path") ||
        ogbak_restore_str_equal_ins(name, "path")) {
        return ogbak_restore_copy_str(bak->backupset_path, OG_MAX_FILE_PATH_LENGH, value);
    }
    if (ogbak_restore_str_equal_ins(name, "type")) {
        return ogbak_restore_parse_backup_type(value, &bak->type);
    }
    if (ogbak_restore_str_equal_ins(name, "level") || ogbak_restore_str_equal_ins(name, "backup_level")) {
        return ogbak_restore_parse_uint32(value, &bak->level);
    }
    if (ogbak_restore_str_equal_ins(name, "version_major")) {
        return ogbak_restore_parse_uint32(value, &bak->version_major);
    }
    if (ogbak_restore_str_equal_ins(name, "version_minor")) {
        return ogbak_restore_parse_uint32(value, &bak->version_minor);
    }
    if (ogbak_restore_str_equal_ins(name, "version_magic")) {
        return ogbak_restore_parse_uint32(value, &bak->version_magic);
    }
    if (ogbak_restore_str_equal_ins(name, "db_id") || ogbak_restore_str_equal_ins(name, "database_id")) {
        return ogbak_restore_parse_uint32(value, &bak->db_id);
    }
    if (ogbak_restore_str_equal_ins(name, "cluster_id")) {
        return ogbak_restore_parse_uint32(value, &bak->cluster_id);
    }
    if (ogbak_restore_str_equal_ins(name, "control_files")) {
        return ogbak_restore_copy_str(bak->control_files, OG_MAX_CONFIG_LINE_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "db_version")) {
        return ogbak_restore_copy_str(bak->db_version, OG_DB_NAME_LEN, value);
    }
    if (ogbak_restore_str_equal_ins(name, "start_lsn")) {
        return ogbak_restore_parse_uint64(value, &bak->start_lsn);
    }
    if (ogbak_restore_str_equal_ins(name, "end_lsn")) {
        return ogbak_restore_parse_uint64(value, &bak->end_lsn);
    }
    if (ogbak_restore_str_equal_ins(name, "checkpoint_lsn")) {
        return ogbak_restore_parse_uint64(value, &bak->checkpoint_lsn);
    }
    if (ogbak_restore_str_equal_ins(name, "completion_time")) {
        return ogbak_restore_parse_uint64(value, &bak->completion_time);
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_parse_file_token(ogbak_offline_file_t *file, const char *name, const char *value)
{
    if (ogbak_restore_str_equal_ins(name, "backup_id")) {
        return ogbak_restore_copy_str(file->backup_id, OG_NAME_BUFFER_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "type")) {
        return ogbak_restore_parse_file_type(value, &file->type);
    }
    if (ogbak_restore_str_equal_ins(name, "src") || ogbak_restore_str_equal_ins(name, "source")) {
        return ogbak_restore_copy_str(file->src, OG_MAX_FILE_PATH_LENGH, value);
    }
    if (ogbak_restore_str_equal_ins(name, "target") || ogbak_restore_str_equal_ins(name, "target_path")) {
        return ogbak_restore_copy_str(file->target, OG_MAX_FILE_PATH_LENGH, value);
    }
    if (ogbak_restore_str_equal_ins(name, "original_path")) {
        return ogbak_restore_copy_str(file->original_path, OG_MAX_FILE_PATH_LENGH, value);
    }
    if (ogbak_restore_str_equal_ins(name, "owner")) {
        return ogbak_restore_copy_str(file->owner, OG_NAME_BUFFER_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "group")) {
        return ogbak_restore_copy_str(file->group, OG_NAME_BUFFER_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "size")) {
        return ogbak_restore_parse_uint64(value, &file->size);
    }
    if (ogbak_restore_str_equal_ins(name, "checksum")) {
        if (ogbak_restore_str_equal_ins(value, "none")) {
            file->has_checksum = OG_FALSE;
            return OG_SUCCESS;
        }
        file->has_checksum = OG_TRUE;
        return ogbak_restore_parse_uint32(value, &file->checksum);
    }
    if (ogbak_restore_str_equal_ins(name, "mode")) {
        return ogbak_restore_parse_uint32(value, &file->mode);
    }
    if (ogbak_restore_str_equal_ins(name, "device_type")) {
        return ogbak_restore_parse_uint32(value, &file->device_type);
    }
    if (ogbak_restore_str_equal_ins(name, "storage") || ogbak_restore_str_equal_ins(name, "storage_type")) {
        if (ogbak_restore_str_equal_ins(value, "file") || ogbak_restore_str_equal_ins(value, "local")) {
            file->device_type = DEV_TYPE_FILE;
        } else if (ogbak_restore_str_equal_ins(value, "dss") ||
                   ogbak_restore_str_equal_ins(value, "raw")) {
            file->device_type = DEV_TYPE_RAW;
        } else if (ogbak_restore_str_equal_ins(value, "dbstor")) {
            file->device_type = DEV_TYPE_DBSTOR_FILE;
        } else {
            printf("[ogbackup]unsupported storage type in offline restore manifest: %s\n", value);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(name, "page_size")) {
        return ogbak_restore_parse_uint32(value, &file->page_size);
    }
    if (ogbak_restore_str_equal_ins(name, "level") || ogbak_restore_str_equal_ins(name, "backup_level")) {
        return ogbak_restore_parse_uint32(value, &file->backup_level);
    }
    if (ogbak_restore_str_equal_ins(name, "compressed")) {
        file->compressed = (ogbak_restore_str_equal_ins(value, "true") || ogbak_restore_str_equal_ins(value, "1")) ?
            OG_TRUE : OG_FALSE;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(name, "sparse") || ogbak_restore_str_equal_ins(name, "punched")) {
        file->sparse = (ogbak_restore_str_equal_ins(value, "true") || ogbak_restore_str_equal_ins(value, "1")) ?
            OG_TRUE : OG_FALSE;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(name, "parallel") || ogbak_restore_str_equal_ins(name, "parallel_stream") ||
        ogbak_restore_str_equal_ins(name, "stream")) {
        file->parallel_stream = (ogbak_restore_str_equal_ins(value, "true") ||
            ogbak_restore_str_equal_ins(value, "1")) ? OG_TRUE : OG_FALSE;
        return OG_SUCCESS;
    }
    if (ogbak_restore_str_equal_ins(name, "node") || ogbak_restore_str_equal_ins(name, "node_id")) {
        return ogbak_restore_parse_uint32(value, &file->node_id);
    }
    if (ogbak_restore_str_equal_ins(name, "rst_id")) {
        return ogbak_restore_parse_uint32(value, &file->rst_id);
    }
    if (ogbak_restore_str_equal_ins(name, "file_id") || ogbak_restore_str_equal_ins(name, "id")) {
        return ogbak_restore_parse_uint32(value, &file->file_id);
    }
    if (ogbak_restore_str_equal_ins(name, "sec_id") || ogbak_restore_str_equal_ins(name, "section_id")) {
        return ogbak_restore_parse_uint32(value, &file->sec_id);
    }
    if (ogbak_restore_str_equal_ins(name, "sec_start") || ogbak_restore_str_equal_ins(name, "section_start")) {
        return ogbak_restore_parse_uint64(value, &file->sec_start);
    }
    if (ogbak_restore_str_equal_ins(name, "sec_end") || ogbak_restore_str_equal_ins(name, "section_end")) {
        return ogbak_restore_parse_uint64(value, &file->sec_end);
    }
    if (ogbak_restore_str_equal_ins(name, "thread") || ogbak_restore_str_equal_ins(name, "thread_id")) {
        return ogbak_restore_parse_uint32(value, &file->thread_id);
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_parse_arch_token(ogbak_offline_arch_range_t *arch, const char *name, const char *value)
{
    if (ogbak_restore_str_equal_ins(name, "backup_id")) {
        return ogbak_restore_copy_str(arch->backup_id, OG_NAME_BUFFER_SIZE, value);
    }
    if (ogbak_restore_str_equal_ins(name, "node") || ogbak_restore_str_equal_ins(name, "node_id")) {
        return ogbak_restore_parse_uint32(value, &arch->node_id);
    }
    if (ogbak_restore_str_equal_ins(name, "rst_id")) {
        return ogbak_restore_parse_uint32(value, &arch->rst_id);
    }
    if (ogbak_restore_str_equal_ins(name, "start_asn")) {
        return ogbak_restore_parse_uint32(value, &arch->start_asn);
    }
    if (ogbak_restore_str_equal_ins(name, "end_asn")) {
        return ogbak_restore_parse_uint32(value, &arch->end_asn);
    }
    if (ogbak_restore_str_equal_ins(name, "start_lsn")) {
        return ogbak_restore_parse_uint64(value, &arch->start_lsn);
    }
    if (ogbak_restore_str_equal_ins(name, "end_lsn")) {
        return ogbak_restore_parse_uint64(value, &arch->end_lsn);
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_parse_global_token(ogbak_offline_manifest_t *manifest, const char *name,
    const char *value)
{
    if (ogbak_restore_str_equal_ins(name, "version") || ogbak_restore_str_equal_ins(name, "manifest_version")) {
        return ogbak_restore_parse_uint32(value, &manifest->manifest_version);
    }
    if (ogbak_restore_str_equal_ins(name, "archive_required")) {
        manifest->archive_required = (ogbak_restore_str_equal_ins(value, "true") || ogbak_restore_str_equal_ins(value, "1")) ?
            OG_TRUE : OG_FALSE;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_parse_manifest_line(char *line, ogbak_offline_manifest_t *manifest)
{
    char *save = NULL;
    char *kind = strtok_s(line, " \t", &save);
    if (kind == NULL || kind[0] == '#') {
        return OG_SUCCESS;
    }

    ogbak_offline_backup_t *bak = NULL;
    ogbak_offline_file_t *file = NULL;
    ogbak_offline_arch_range_t *arch = NULL;
    if (ogbak_restore_str_equal_ins(kind, "backup")) {
        if (manifest->backup_count >= OGBAK_RESTORE_MAX_BACKUPS) {
            printf("[ogbackup]too many backup entries in offline manifest\n");
            return OG_ERROR;
        }
        bak = &manifest->backups[manifest->backup_count];
        bak->version_major = OGBAK_RESTORE_EXPECTED_MAJOR;
        bak->version_minor = OGBAK_RESTORE_EXPECTED_MINOR;
        bak->version_magic = OGBAK_RESTORE_EXPECTED_MAGIC;
    } else if (ogbak_restore_str_equal_ins(kind, "file")) {
        if (manifest->file_count >= OGBAK_RESTORE_MAX_FILES) {
            printf("[ogbackup]too many file entries in offline manifest\n");
            return OG_ERROR;
        }
        file = &manifest->files[manifest->file_count];
        file->type = OGBAK_RESTORE_FILE_OTHER;
    } else if (ogbak_restore_str_equal_ins(kind, "arch")) {
        if (manifest->arch_count >= OGBAK_RESTORE_MAX_ARCH_RANGES) {
            printf("[ogbackup]too many archive entries in offline manifest\n");
            return OG_ERROR;
        }
        arch = &manifest->archs[manifest->arch_count];
    } else if (ogbak_restore_str_equal_ins(kind, "global")) {
        /* parsed below */
    } else {
        printf("[ogbackup]unknown offline manifest entry: %s\n", kind);
        return OG_ERROR;
    }

    char *token = NULL;
    while ((token = strtok_s(NULL, " \t", &save)) != NULL) {
        char *name = NULL;
        char *value = ogbak_restore_token_value(token, &name);
        if (value == NULL) {
            printf("[ogbackup]invalid token in offline manifest: %s\n", token);
            return OG_ERROR;
        }
        if (bak != NULL && ogbak_restore_parse_backup_token(bak, name, value) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (file != NULL && ogbak_restore_parse_file_token(file, name, value) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (arch != NULL && ogbak_restore_parse_arch_token(arch, name, value) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (bak == NULL && file == NULL && arch == NULL &&
            ogbak_restore_parse_global_token(manifest, name, value) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (bak != NULL) {
        if (ogbak_restore_is_empty_str(bak->id) || bak->completion_time == 0) {
            printf("[ogbackup]backup manifest entry must contain id and completion_time\n");
            return OG_ERROR;
        }
        manifest->backup_count++;
    } else if (file != NULL) {
        if (ogbak_restore_is_empty_str(file->backup_id) || ogbak_restore_is_empty_str(file->src) ||
            ogbak_restore_is_empty_str(file->target)) {
            printf("[ogbackup]file manifest entry must contain backup_id, src and target\n");
            return OG_ERROR;
        }
        manifest->file_count++;
    } else if (arch != NULL) {
        if (ogbak_restore_is_empty_str(arch->backup_id) || arch->end_asn < arch->start_asn) {
            printf("[ogbackup]archive manifest entry must contain backup_id and a valid ASN range\n");
            return OG_ERROR;
        }
        manifest->arch_count++;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_alloc_manifest(ogbak_offline_manifest_t *manifest)
{
    errno_t ret = memset_s(manifest, sizeof(ogbak_offline_manifest_t), 0, sizeof(ogbak_offline_manifest_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    manifest->manifest_version = 1;
    manifest->backups = (ogbak_offline_backup_t *)malloc(sizeof(ogbak_offline_backup_t) * OGBAK_RESTORE_MAX_BACKUPS);
    manifest->files = (ogbak_offline_file_t *)malloc(sizeof(ogbak_offline_file_t) * OGBAK_RESTORE_MAX_FILES);
    manifest->archs = (ogbak_offline_arch_range_t *)malloc(sizeof(ogbak_offline_arch_range_t) *
        OGBAK_RESTORE_MAX_ARCH_RANGES);
    if (manifest->backups == NULL || manifest->files == NULL || manifest->archs == NULL) {
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }
    ret = memset_s(manifest->backups, sizeof(ogbak_offline_backup_t) * OGBAK_RESTORE_MAX_BACKUPS, 0,
        sizeof(ogbak_offline_backup_t) * OGBAK_RESTORE_MAX_BACKUPS);
    ret |= memset_s(manifest->files, sizeof(ogbak_offline_file_t) * OGBAK_RESTORE_MAX_FILES, 0,
        sizeof(ogbak_offline_file_t) * OGBAK_RESTORE_MAX_FILES);
    ret |= memset_s(manifest->archs, sizeof(ogbak_offline_arch_range_t) * OGBAK_RESTORE_MAX_ARCH_RANGES, 0,
        sizeof(ogbak_offline_arch_range_t) * OGBAK_RESTORE_MAX_ARCH_RANGES);
    if (ret != EOK) {
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static ogbak_offline_backup_type_t ogbak_restore_backup_type_from_head(bak_head_t *head)
{
    if (head->attr.backup_type == BACKUP_MODE_INCREMENTAL_CUMULATIVE) {
        return OGBAK_RESTORE_BAK_CUMULATIVE;
    }
    if (head->attr.backup_type == BACKUP_MODE_INCREMENTAL) {
        return head->attr.level == 0 ? OGBAK_RESTORE_BAK_FULL : OGBAK_RESTORE_BAK_INCREMENTAL;
    }
    return OGBAK_RESTORE_BAK_FULL;
}

static ogbak_offline_file_type_t ogbak_restore_file_type_from_bak(bak_file_type_t type)
{
    switch (type) {
        case BACKUP_CTRL_FILE:
            return OGBAK_RESTORE_FILE_CONTROL;
        case BACKUP_DATA_FILE:
            return OGBAK_RESTORE_FILE_DATA;
        case BACKUP_LOG_FILE:
            return OGBAK_RESTORE_FILE_LOG;
        case BACKUP_ARCH_FILE:
            return OGBAK_RESTORE_FILE_ARCHIVE;
        default:
            return OGBAK_RESTORE_FILE_OTHER;
    }
}

static status_t ogbak_restore_fill_backup_from_catalog(ogbak_offline_backup_t *bak,
    bak_offline_backupset_catalog_t *catalog, const char *parent_id)
{
    bak_head_t *head = &catalog->head;
    const char *real_parent_id = ogbak_restore_is_empty_str(parent_id) ? head->attr.base_tag : parent_id;
    if (ogbak_restore_copy_str(bak->id, OG_NAME_BUFFER_SIZE, head->attr.tag) != OG_SUCCESS ||
        ogbak_restore_copy_str(bak->parent_id, OG_NAME_BUFFER_SIZE, real_parent_id) != OG_SUCCESS ||
        ogbak_restore_copy_str(bak->backupset_path, OG_MAX_FILE_PATH_LENGH, catalog->path) != OG_SUCCESS ||
        ogbak_restore_copy_str(bak->control_files, OG_MAX_CONFIG_LINE_SIZE, head->control_files) != OG_SUCCESS ||
        ogbak_restore_copy_str(bak->db_version, OG_DB_NAME_LEN, head->db_version) != OG_SUCCESS) {
        return OG_ERROR;
    }
    bak->type = ogbak_restore_backup_type_from_head(head);
    bak->level = head->attr.level;
    bak->version_major = head->version.major_ver;
    bak->version_minor = head->version.min_ver;
    bak->version_magic = head->version.magic;
    bak->db_id = head->db_id;
    bak->cluster_id = 0; // real bak_head_t does not currently persist cluster_id
    bak->db_init_time = (int64)head->db_init_time;
    bak->df_struc_version = head->df_struc_version;
    bak->rst_id = (uint32)head->ctrlinfo.lrp_point.rst_id;
    if (ogbak_restore_copy_str(bak->db_name, OG_DB_NAME_LEN, head->db_name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    bak->start_lsn = head->attr.base_lsn;
    bak->end_lsn = head->ctrlinfo.lrp_point.lsn;
    bak->checkpoint_lsn = head->ctrlinfo.rcy_point.lsn;
    bak->completion_time = head->completion_time;
    bak->from_backupset = OG_TRUE;
    bak->encrypted = head->encrypt_info.encrypt_alg != ENCRYPT_NONE ? OG_TRUE : OG_FALSE;
    bak->compressed = head->attr.compress != COMPRESS_NONE ? OG_TRUE : OG_FALSE;
    return OG_SUCCESS;
}

static status_t ogbak_restore_append_backup_from_catalog(ogbak_offline_manifest_t *manifest,
    bak_offline_backupset_catalog_t *catalog, const char *parent_id)
{
    if (manifest->backup_count >= OGBAK_RESTORE_MAX_BACKUPS) {
        printf("[ogbackup]too many backup entries while reading real backupsets\n");
        return OG_ERROR;
    }
    return ogbak_restore_fill_backup_from_catalog(&manifest->backups[manifest->backup_count++], catalog, parent_id);
}

static status_t ogbak_restore_append_arch_from_file(ogbak_offline_manifest_t *manifest,
    const char *backup_id, bak_file_t *file)
{
    if (file->type != BACKUP_ARCH_FILE) {
        return OG_SUCCESS;
    }
    if (manifest->arch_count >= OGBAK_RESTORE_MAX_ARCH_RANGES) {
        printf("[ogbackup]too many archive entries while reading real backupsets\n");
        return OG_ERROR;
    }
    ogbak_offline_arch_range_t *arch = &manifest->archs[manifest->arch_count++];
    if (ogbak_restore_copy_str(arch->backup_id, OG_NAME_BUFFER_SIZE, backup_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    arch->node_id = file->inst_id;
    arch->rst_id = file->rst_id;
    arch->start_asn = file->id;
    arch->end_asn = file->id;
    arch->start_lsn = file->start_lsn;
    arch->end_lsn = file->end_lsn;
    return OG_SUCCESS;
}

static status_t ogbak_restore_append_file_from_catalog(ogbak_offline_manifest_t *manifest,
    bak_offline_backupset_catalog_t *catalog, bak_file_t *bak_file)
{
    if (bak_file->type == BACKUP_HEAD_FILE) {
        return OG_SUCCESS;
    }
    if (manifest->file_count >= OGBAK_RESTORE_MAX_FILES) {
        printf("[ogbackup]too many file entries while reading real backupsets\n");
        return OG_ERROR;
    }

    ogbak_offline_file_t *file = &manifest->files[manifest->file_count];
    if (ogbak_restore_copy_str(file->backup_id, OG_NAME_BUFFER_SIZE, catalog->head.attr.tag) != OG_SUCCESS ||
        ogbak_restore_generate_bak_file_name(catalog->dir, &catalog->head, bak_file, file->src,
            OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS ||
        ogbak_restore_generate_target_name(bak_file, file->target, OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (!cm_file_exist(file->src) && ogbak_restore_reject_dbstor_payload(catalog->dir, bak_file) != OG_SUCCESS) {
        return OG_ERROR;
    }
    file->type = ogbak_restore_file_type_from_bak(bak_file->type);
    file->size = bak_file->size;
    file->from_backupset = OG_TRUE;
    file->compressed = catalog->head.attr.compress != COMPRESS_NONE ? OG_TRUE : OG_FALSE;
    file->compress_algo = catalog->head.attr.compress;
    file->encrypt_alg = catalog->head.encrypt_info.encrypt_alg;
    errno_t ret = memcpy_s(&file->encrypt_info, sizeof(file->encrypt_info), &catalog->head.encrypt_info,
        sizeof(catalog->head.encrypt_info));
    ret |= memcpy_s(file->sys_pwd, sizeof(file->sys_pwd), catalog->head.sys_pwd, sizeof(file->sys_pwd));
    ret |= memcpy_s(file->gcm_iv, sizeof(file->gcm_iv), bak_file->gcm_iv, sizeof(file->gcm_iv));
    ret |= memcpy_s(file->gcm_tag, sizeof(file->gcm_tag), bak_file->gcm_tag, sizeof(file->gcm_tag));
    if (ret != EOK) {
        return OG_ERROR;
    }
    file->file_id = bak_file->id;
    file->node_id = bak_file->inst_id;
    file->rst_id = bak_file->rst_id;
    file->backup_level = catalog->head.attr.level;
    file->sec_id = bak_file->sec_id;
    file->sec_start = bak_file->sec_start;
    file->sec_end = bak_file->sec_end;
    file->format_flags = bak_file->reserved;
    manifest->file_count++;
    return ogbak_restore_append_arch_from_file(manifest, catalog->head.attr.tag, bak_file);
}

static status_t ogbak_restore_append_files_from_catalog(ogbak_offline_manifest_t *manifest,
    bak_offline_backupset_catalog_t *catalog)
{
    for (uint32 i = 0; i < catalog->head.file_count; i++) {
        if (ogbak_restore_append_file_from_catalog(manifest, catalog, &catalog->files[i]) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_load_catalog_into_manifest(ogbak_offline_manifest_t *manifest,
    const char *backupset_path, const char *parent_id)
{
    bak_offline_backupset_catalog_t *catalog =
        (bak_offline_backupset_catalog_t *)malloc(sizeof(bak_offline_backupset_catalog_t));
    if (catalog == NULL) {
        return OG_ERROR;
    }
    status_t status = bak_read_backupset_catalog_offline(backupset_path, catalog);
    if (status == OG_SUCCESS) {
        status = ogbak_restore_append_backup_from_catalog(manifest, catalog, parent_id);
    }
    if (status == OG_SUCCESS) {
        status = ogbak_restore_append_files_from_catalog(manifest, catalog);
    }
    CM_FREE_PTR(catalog);
    return status;
}

static status_t ogbak_restore_load_raw_backupset_chain(const char *backup_dir, ogbak_offline_manifest_t *manifest)
{
    char selected_path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (ogbak_restore_resolve_backupset_path(backup_dir, NULL, selected_path) != OG_SUCCESS) {
        return OG_ERROR;
    }

    bak_offline_backupset_catalog_t *selected =
        (bak_offline_backupset_catalog_t *)malloc(sizeof(bak_offline_backupset_catalog_t));
    if (selected == NULL) {
        return OG_ERROR;
    }
    if (bak_read_backupset_catalog_offline(selected_path, selected) != OG_SUCCESS) {
        CM_FREE_PTR(selected);
        return OG_ERROR;
    }

    for (int32 i = (int32)selected->head.depend_num - 1; i >= 0; i--) {
        char dep_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_backupset_path(backup_dir, selected->depends[i].file_dest, dep_path) != OG_SUCCESS) {
            CM_FREE_PTR(selected);
            return OG_ERROR;
        }
        if (ogbak_restore_load_catalog_into_manifest(manifest, dep_path, "") != OG_SUCCESS) {
            CM_FREE_PTR(selected);
            return OG_ERROR;
        }
    }

    status_t status = ogbak_restore_append_backup_from_catalog(manifest, selected, "");
    if (status == OG_SUCCESS) {
        status = ogbak_restore_append_files_from_catalog(manifest, selected);
    }
    CM_FREE_PTR(selected);
    return status;
}

static status_t ogbak_restore_enrich_manifest_from_backupsets(const char *backup_dir,
    ogbak_offline_manifest_t *manifest)
{
    uint32 original_backup_count = manifest->backup_count;
    for (uint32 i = 0; i < original_backup_count; i++) {
        if (ogbak_restore_is_empty_str(manifest->backups[i].backupset_path)) {
            continue;
        }
        char backupset_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_backupset_path(backup_dir, manifest->backups[i].backupset_path,
            backupset_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        bak_offline_backupset_catalog_t *catalog =
            (bak_offline_backupset_catalog_t *)malloc(sizeof(bak_offline_backupset_catalog_t));
        if (catalog == NULL) {
            return OG_ERROR;
        }
        status_t status = bak_read_backupset_catalog_offline(backupset_path, catalog);
        if (status == OG_SUCCESS) {
            status = ogbak_restore_fill_backup_from_catalog(&manifest->backups[i], catalog,
                manifest->backups[i].parent_id);
        }
        if (status == OG_SUCCESS) {
            status = ogbak_restore_append_files_from_catalog(manifest, catalog);
        }
        CM_FREE_PTR(catalog);
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t ogbak_offline_load_manifest(const char *backup_dir, ogbak_offline_manifest_t *manifest)
{
    char manifest_path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (backup_dir == NULL || manifest == NULL) {
        return OG_ERROR;
    }
    if (ogbak_restore_alloc_manifest(manifest) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ogbak_restore_join_path(backup_dir, OGBAK_OFFLINE_MANIFEST_NAME, manifest_path,
        OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }
    if (!cm_file_exist(manifest_path)) {
        if (ogbak_restore_join_path(backup_dir, OGBAK_OFFLINE_MANIFEST_FALLBACK, manifest_path,
            OG_MAX_FILE_PATH_LENGH) != OG_SUCCESS) {
            ogbak_offline_free_manifest(manifest);
            return OG_ERROR;
        }
    }
    if (!cm_file_exist(manifest_path)) {
        if (ogbak_restore_load_raw_backupset_chain(backup_dir, manifest) != OG_SUCCESS) {
            printf("[ogbackup]offline restore manifest not found in %s, and no readable real backupset catalog was found\n",
                backup_dir);
            ogbak_offline_free_manifest(manifest);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    FILE *fp = fopen(manifest_path, "r");
    if (fp == NULL) {
        printf("[ogbackup]open offline restore manifest %s failed, error %d\n", manifest_path, errno);
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }

    char line[OG_MAX_FILE_PATH_LENGH * 4];
    uint32 line_no = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_no++;
        ogbak_restore_trim_line(line);
        if (ogbak_restore_parse_manifest_line(line, manifest) != OG_SUCCESS) {
            printf("[ogbackup]parse offline restore manifest failed at line %u\n", line_no);
            (void)fclose(fp);
            ogbak_offline_free_manifest(manifest);
            return OG_ERROR;
        }
    }
    (void)fclose(fp);

    if (manifest->backup_count == 0) {
        printf("[ogbackup]offline restore manifest has no backup entry\n");
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }
    if (manifest->manifest_version != 1) {
        printf("[ogbackup]offline restore manifest version %u is not supported\n", manifest->manifest_version);
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }
    if (ogbak_restore_enrich_manifest_from_backupsets(backup_dir, manifest) != OG_SUCCESS) {
        ogbak_offline_free_manifest(manifest);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void ogbak_offline_free_manifest(ogbak_offline_manifest_t *manifest)
{
    if (manifest == NULL) {
        return;
    }
    CM_FREE_PTR(manifest->backups);
    CM_FREE_PTR(manifest->files);
    CM_FREE_PTR(manifest->archs);
    (void)memset_s(manifest, sizeof(ogbak_offline_manifest_t), 0, sizeof(ogbak_offline_manifest_t));
}

static ogbak_offline_backup_t *ogbak_restore_find_backup(ogbak_offline_manifest_t *manifest, const char *id)
{
    for (uint32 i = 0; i < manifest->backup_count; i++) {
        if (cm_str_equal(manifest->backups[i].id, id)) {
            return &manifest->backups[i];
        }
    }
    return NULL;
}

static bool32 ogbak_restore_chain_has_backup(ogbak_offline_plan_t *plan, const char *backup_id)
{
    for (uint32 i = 0; i < plan->chain_count; i++) {
        if (cm_str_equal(plan->chain[i]->id, backup_id)) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t ogbak_restore_select_last_backup(ogbak_offline_manifest_t *manifest, ogbak_param_t *param,
    ogbak_offline_backup_t **selected)
{
    *selected = NULL;
    if (param->backup_id.str != NULL) {
        *selected = ogbak_restore_find_backup(manifest, param->backup_id.str);
        if (*selected == NULL) {
            printf("[ogbackup]backup-id %s does not exist in offline manifest\n", param->backup_id.str);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    uint64 target_time = UINT64_MAX;
    if (param->target_time.str != NULL &&
        ogbak_restore_parse_uint64(param->target_time.str, &target_time) != OG_SUCCESS) {
        printf("[ogbackup]target-time must be an unsigned timestamp in offline restore manifest time domain\n");
        return OG_ERROR;
    }
    for (uint32 i = 0; i < manifest->backup_count; i++) {
        ogbak_offline_backup_t *bak = &manifest->backups[i];
        if (bak->completion_time > target_time) {
            continue;
        }
        if (*selected == NULL || bak->completion_time > (*selected)->completion_time) {
            *selected = bak;
        }
    }
    if (*selected == NULL) {
        printf("[ogbackup]no backupset can satisfy the requested offline restore target\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_backup_compatibility(ogbak_offline_backup_t *base,
    ogbak_offline_backup_t *bak)
{
    if (bak->version_major != OGBAK_RESTORE_EXPECTED_MAJOR ||
        bak->version_minor != OGBAK_RESTORE_EXPECTED_MINOR ||
        bak->version_magic != OGBAK_RESTORE_EXPECTED_MAGIC) {
        printf("[ogbackup]backupset %s version %u-%u-%u is not compatible with offline restore %u-%u-%u\n",
            bak->id, bak->version_major, bak->version_minor, bak->version_magic,
            OGBAK_RESTORE_EXPECTED_MAJOR, OGBAK_RESTORE_EXPECTED_MINOR, OGBAK_RESTORE_EXPECTED_MAGIC);
        return OG_ERROR;
    }
    if (base == NULL) {
        return OG_SUCCESS;
    }
    if (base->db_id != 0 && bak->db_id != 0 && base->db_id != bak->db_id) {
        printf("[ogbackup]backupset %s db_id %u mismatches base db_id %u\n", bak->id, bak->db_id, base->db_id);
        return OG_ERROR;
    }
    if (base->cluster_id != 0 && bak->cluster_id != 0 && base->cluster_id != bak->cluster_id) {
        printf("[ogbackup]backupset %s cluster_id %u mismatches base cluster_id %u\n",
            bak->id, bak->cluster_id, base->cluster_id);
        return OG_ERROR;
    }
    if (base->db_init_time != 0 && bak->db_init_time != 0 && base->db_init_time != bak->db_init_time) {
        printf("[ogbackup]backupset %s db_init_time %lld mismatches base db_init_time %lld\n",
            bak->id, (long long)bak->db_init_time, (long long)base->db_init_time);
        return OG_ERROR;
    }
    if (base->df_struc_version != 0 && bak->df_struc_version != 0 &&
        base->df_struc_version != bak->df_struc_version) {
        printf("[ogbackup]backupset %s datafile structure version %u mismatches base version %u\n",
            bak->id, bak->df_struc_version, base->df_struc_version);
        return OG_ERROR;
    }
    if (base->rst_id != 0 && bak->rst_id != 0 && base->rst_id != bak->rst_id) {
        printf("[ogbackup]backupset %s resetlogs id %u mismatches base resetlogs id %u\n",
            bak->id, bak->rst_id, base->rst_id);
        return OG_ERROR;
    }
    if (!ogbak_restore_is_empty_str(base->db_name) && !ogbak_restore_is_empty_str(bak->db_name) &&
        !cm_str_equal(base->db_name, bak->db_name)) {
        printf("[ogbackup]backupset %s database name %s mismatches base database name %s\n",
            bak->id, bak->db_name, base->db_name);
        return OG_ERROR;
    }
    if (!ogbak_restore_is_empty_str(base->db_version) && !ogbak_restore_is_empty_str(bak->db_version) &&
        !cm_str_equal(base->db_version, bak->db_version)) {
        printf("[ogbackup]backupset %s db_version %s mismatches base db_version %s\n",
            bak->id, bak->db_version, base->db_version);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_append_chain(ogbak_offline_plan_t *plan, ogbak_offline_backup_t *bak)
{
    if (plan->chain_count >= OGBAK_RESTORE_MAX_BACKUPS) {
        return OG_ERROR;
    }
    plan->chain[plan->chain_count++] = bak;
    return OG_SUCCESS;
}

static void ogbak_restore_reverse_chain(ogbak_offline_plan_t *plan)
{
    for (uint32 i = 0; i < plan->chain_count / 2; i++) {
        ogbak_offline_backup_t *tmp = plan->chain[i];
        plan->chain[i] = plan->chain[plan->chain_count - i - 1];
        plan->chain[plan->chain_count - i - 1] = tmp;
    }
}

static status_t ogbak_restore_build_chain(ogbak_offline_manifest_t *manifest, ogbak_param_t *param,
    ogbak_offline_plan_t *plan)
{
    for (uint32 i = 0; i < manifest->backup_count; i++) {
        for (uint32 j = i + 1; j < manifest->backup_count; j++) {
            if (cm_str_equal(manifest->backups[i].id, manifest->backups[j].id)) {
                printf("[ogbackup]duplicate backup tag is not allowed: %s\n", manifest->backups[i].id);
                return OG_ERROR;
            }
        }
    }
    ogbak_offline_backup_t *selected = NULL;
    if (ogbak_restore_select_last_backup(manifest, param, &selected) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ogbak_offline_backup_t *cur = selected;
    while (cur != NULL) {
        if (ogbak_restore_chain_has_backup(plan, cur->id)) {
            printf("[ogbackup]cycle detected in offline backup chain at backupset %s\n", cur->id);
            return OG_ERROR;
        }
        if (ogbak_restore_append_chain(plan, cur) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (cur->type == OGBAK_RESTORE_BAK_FULL) {
            break;
        }
        if (ogbak_restore_is_empty_str(cur->parent_id)) {
            printf("[ogbackup]backupset %s is incremental/cumulative but has no parent\n", cur->id);
            return OG_ERROR;
        }
        cur = ogbak_restore_find_backup(manifest, cur->parent_id);
        if (cur == NULL) {
            printf("[ogbackup]parent backupset %s is missing from offline manifest\n",
                plan->chain[plan->chain_count - 1]->parent_id);
            return OG_ERROR;
        }
    }

    ogbak_restore_reverse_chain(plan);
    if (plan->chain_count == 0 || plan->chain[0]->type != OGBAK_RESTORE_BAK_FULL) {
        printf("[ogbackup]offline restore chain must start with a full backupset\n");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < plan->chain_count; i++) {
        if (ogbak_restore_validate_backup_compatibility(plan->chain[0], plan->chain[i]) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (i > 0 && !cm_str_equal(plan->chain[i]->parent_id, plan->chain[i - 1]->id)) {
            printf("[ogbackup]backupset %s expects parent %s, but previous chain item is %s\n",
                plan->chain[i]->id, plan->chain[i]->parent_id, plan->chain[i - 1]->id);
            return OG_ERROR;
        }
        if (i > 0 && plan->chain[i]->start_lsn != 0 && plan->chain[i - 1]->start_lsn != 0 &&
            plan->chain[i]->start_lsn < plan->chain[i - 1]->start_lsn) {
            printf("[ogbackup]backupset %s start LSN %llu regresses from parent start LSN %llu\n",
                plan->chain[i]->id, plan->chain[i]->start_lsn, plan->chain[i - 1]->start_lsn);
            return OG_ERROR;
        }
        if (i > 0 && plan->chain[i]->end_lsn != 0 && plan->chain[i - 1]->end_lsn != 0 &&
            plan->chain[i]->end_lsn < plan->chain[i - 1]->end_lsn) {
            printf("[ogbackup]backupset %s end LSN %llu regresses from parent end LSN %llu\n",
                plan->chain[i]->id, plan->chain[i]->end_lsn, plan->chain[i - 1]->end_lsn);
            return OG_ERROR;
        }
        if (i > 0 && plan->chain[i]->type == OGBAK_RESTORE_BAK_CUMULATIVE &&
            plan->chain[i - 1]->type != OGBAK_RESTORE_BAK_FULL) {
            printf("[ogbackup]cumulative backupset %s must directly depend on the selected level-0 baseline\n",
                plan->chain[i]->id);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_append_file_plan(ogbak_offline_plan_t *plan, ogbak_offline_file_t *file)
{
    if (plan->file_count >= OGBAK_RESTORE_MAX_FILES) {
        return OG_ERROR;
    }
    plan->files[plan->file_count++] = file;
    return OG_SUCCESS;
}

static status_t ogbak_restore_load_password_file(ogbak_param_t *param)
{
    return ogbak_load_password_file(param);
}

static uint32 ogbak_restore_file_chain_index(ogbak_offline_plan_t *plan, ogbak_offline_file_t *file)
{
    for (uint32 i = 0; i < plan->chain_count; i++) {
        if (cm_str_equal(plan->chain[i]->id, file->backup_id)) {
            return i;
        }
    }
    return OG_INVALID_ID32;
}

static bool32 ogbak_restore_file_after(ogbak_offline_plan_t *plan, ogbak_offline_file_t *left,
    ogbak_offline_file_t *right)
{
    uint32 left_chain = ogbak_restore_file_chain_index(plan, left);
    uint32 right_chain = ogbak_restore_file_chain_index(plan, right);
    if (left_chain != right_chain) {
        return left_chain > right_chain ? OG_TRUE : OG_FALSE;
    }
    if (left->type != right->type) {
        return left->type > right->type ? OG_TRUE : OG_FALSE;
    }
    if (left->file_id != right->file_id) {
        return left->file_id > right->file_id ? OG_TRUE : OG_FALSE;
    }
    if (left->node_id != right->node_id) {
        return left->node_id > right->node_id ? OG_TRUE : OG_FALSE;
    }
    return left->sec_id > right->sec_id ? OG_TRUE : OG_FALSE;
}

static status_t ogbak_restore_validate_and_sort_pieces(ogbak_offline_plan_t *plan)
{
    for (uint32 i = 1; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        uint32 pos = i;
        while (pos > 0 && ogbak_restore_file_after(plan, plan->files[pos - 1], file) == OG_TRUE) {
            plan->files[pos] = plan->files[pos - 1];
            pos--;
        }
        plan->files[pos] = file;
    }

    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *left = plan->files[i];
        for (uint32 j = i + 1; j < plan->file_count; j++) {
            ogbak_offline_file_t *right = plan->files[j];
            if (!cm_str_equal(left->backup_id, right->backup_id) || left->type != right->type ||
                left->file_id != right->file_id || left->node_id != right->node_id) {
                continue;
            }
            bool32 duplicate = left->type == OGBAK_RESTORE_FILE_DATA ?
                (left->sec_id == right->sec_id ? OG_TRUE : OG_FALSE) : OG_TRUE;
            if (left->type == OGBAK_RESTORE_FILE_ARCHIVE && left->rst_id != right->rst_id) {
                duplicate = OG_FALSE;
            }
            if (duplicate == OG_TRUE && (left->from_backupset == OG_TRUE || right->from_backupset == OG_TRUE ||
                left->parallel_stream == OG_TRUE || right->parallel_stream == OG_TRUE)) {
                printf("[ogbackup]duplicate backup piece: backup=%s type=%s file=%u node=%u section=%u\n",
                    left->backup_id, ogbak_restore_file_type_name(left->type), left->file_id,
                    left->node_id, left->sec_id);
                return OG_ERROR;
            }
        }
    }

    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->type != OGBAK_RESTORE_FILE_DATA) {
            continue;
        }
        uint32 group_end = i + 1;
        while (group_end < plan->file_count &&
            cm_str_equal(file->backup_id, plan->files[group_end]->backup_id) &&
            plan->files[group_end]->type == OGBAK_RESTORE_FILE_DATA &&
            plan->files[group_end]->file_id == file->file_id) {
            group_end++;
        }
        uint32 piece_count = group_end - i;
        bool32 has_section_metadata = OG_FALSE;
        for (uint32 j = i; j < group_end; j++) {
            ogbak_offline_file_t *piece = plan->files[j];
            if (piece->from_backupset == OG_TRUE || piece->parallel_stream == OG_TRUE || piece->sec_id != 0 ||
                piece->sec_start != 0 || piece->sec_end != 0) {
                has_section_metadata = OG_TRUE;
                break;
            }
        }
        if (piece_count > 1 && has_section_metadata == OG_TRUE) {
            plan->parallel_pieces = OG_TRUE;
            if (file->sec_id != 0 || file->sec_start != 0 || file->sec_end <= file->sec_start) {
                printf("[ogbackup]parallel backup pieces for backup=%s file=%u must start at section 0 offset 0\n",
                    file->backup_id, file->file_id);
                return OG_ERROR;
            }
            for (uint32 j = i + 1; j < group_end; j++) {
                ogbak_offline_file_t *prev = plan->files[j - 1];
                ogbak_offline_file_t *cur = plan->files[j];
                if (cur->sec_id != prev->sec_id + 1) {
                    printf("[ogbackup]missing or duplicate backup section: backup=%s file=%u previous=%u current=%u\n",
                        cur->backup_id, cur->file_id, prev->sec_id, cur->sec_id);
                    return OG_ERROR;
                }
                if (cur->sec_start != prev->sec_end || cur->sec_end <= cur->sec_start) {
                    printf("[ogbackup]backup section gap/overlap: backup=%s file=%u section=%u "
                           "previous_end=%llu start=%llu end=%llu\n",
                        cur->backup_id, cur->file_id, cur->sec_id, prev->sec_end, cur->sec_start, cur->sec_end);
                    return OG_ERROR;
                }
            }
        } else if (piece_count == 1 && file->sec_id != 0) {
            printf("[ogbackup]backup section set is incomplete: backup=%s file=%u only section=%u is present\n",
                file->backup_id, file->file_id, file->sec_id);
            return OG_ERROR;
        }
        i = group_end - 1;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_final_control_source(ogbak_param_t *param, ogbak_offline_plan_t *plan)
{
    if (param->is_in_place != OG_TRUE) {
        return OG_SUCCESS;
    }
    if (plan->chain_count == 0) {
        return OG_ERROR;
    }
    ogbak_offline_file_t *final_ctrl = NULL;
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset == OG_TRUE &&
            plan->files[i]->type == OGBAK_RESTORE_FILE_CONTROL) {
            final_ctrl = plan->files[i];
        }
    }
    if (final_ctrl == NULL ||
        !cm_str_equal(final_ctrl->backup_id, plan->chain[plan->chain_count - 1]->id)) {
        printf("[ogbackup]final control image must come from selected chain endpoint %s; actual=%s\n",
            plan->chain[plan->chain_count - 1]->id,
            final_ctrl == NULL ? "<missing>" : final_ctrl->backup_id);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_collect_files(ogbak_offline_manifest_t *manifest, ogbak_offline_plan_t *plan)
{
    for (uint32 i = 0; i < plan->chain_count; i++) {
        for (uint32 j = 0; j < manifest->file_count; j++) {
            if (!cm_str_equal(plan->chain[i]->id, manifest->files[j].backup_id)) {
                continue;
            }
            if (manifest->files[j].type == OGBAK_RESTORE_FILE_SYMLINK) {
                printf("[ogbackup]offline restore does not restore symlink %s yet; record it in report/TODO\n",
                    manifest->files[j].target);
                return OG_ERROR;
            }
            if (manifest->files[j].compressed == OG_TRUE && manifest->files[j].from_backupset != OG_TRUE) {
                printf("[ogbackup]offline restore compressed payload requires real backupset decoder metadata: %s\n",
                    manifest->files[j].target);
                return OG_ERROR;
            }
            if (manifest->files[j].sparse == OG_TRUE) {
                printf("[ogbackup]offline restore does not support punched/sparse datafile restore yet: %s\n",
                    manifest->files[j].target);
                return OG_ERROR;
            }
            if (manifest->files[j].device_type != 0 && manifest->files[j].device_type != DEV_TYPE_FILE &&
                !(manifest->files[j].device_type == DEV_TYPE_RAW && manifest->files[j].target[0] == '+')) {
                printf("[ogbackup]offline restore does not support DSS/DBStor/non-local device restore yet: %s\n",
                    manifest->files[j].target);
                return OG_ERROR;
            }
            if (manifest->files[j].parallel_stream == OG_TRUE && manifest->files[j].from_backupset != OG_TRUE) {
                printf("[ogbackup]offline restore parallel stream payload requires real backupset decoder metadata: %s\n",
                    manifest->files[j].target);
                return OG_ERROR;
            }
            if (ogbak_restore_append_file_plan(plan, &manifest->files[j]) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
    }
    if (plan->file_count == 0) {
        printf("[ogbackup]offline restore plan contains no files\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static int ogbak_restore_arch_compare(const void *left, const void *right)
{
    const ogbak_offline_arch_range_t *a = *(const ogbak_offline_arch_range_t * const *)left;
    const ogbak_offline_arch_range_t *b = *(const ogbak_offline_arch_range_t * const *)right;
    if (a->node_id != b->node_id) {
        return (a->node_id < b->node_id) ? -1 : 1;
    }
    if (a->rst_id != b->rst_id) {
        return (a->rst_id < b->rst_id) ? -1 : 1;
    }
    if (a->start_asn != b->start_asn) {
        return (a->start_asn < b->start_asn) ? -1 : 1;
    }
    return 0;
}

static status_t ogbak_restore_check_arch_continuity(ogbak_offline_manifest_t *manifest, ogbak_offline_plan_t *plan)
{
    ogbak_offline_arch_range_t **ranges = (ogbak_offline_arch_range_t **)malloc(
        sizeof(ogbak_offline_arch_range_t *) * manifest->arch_count);
    if (ranges == NULL) {
        return OG_ERROR;
    }
    uint32 range_count = 0;
    for (uint32 i = 0; i < manifest->arch_count; i++) {
        if (ogbak_restore_chain_has_backup(plan, manifest->archs[i].backup_id)) {
            ranges[range_count++] = &manifest->archs[i];
        }
    }
    if (range_count == 0) {
        CM_FREE_PTR(ranges);
        if (manifest->archive_required == OG_TRUE) {
            printf("[ogbackup]offline restore requires archive/redo ranges, but none are present in the selected chain\n");
            return OG_ERROR;
        }
        plan->need_recovery = OG_TRUE;
        printf("[ogbackup]archive/redo range is not recorded in manifest; startup recovery requirement is unknown\n");
        return OG_SUCCESS;
    }

    qsort(ranges, range_count, sizeof(ogbak_offline_arch_range_t *), ogbak_restore_arch_compare);
    ogbak_offline_arch_range_t *prev = ranges[0];
    for (uint32 i = 1; i < range_count; i++) {
        ogbak_offline_arch_range_t *cur = ranges[i];
        if (cur->node_id != prev->node_id || cur->rst_id != prev->rst_id) {
            prev = cur;
            continue;
        }
        if (prev->end_asn != OG_INVALID_ID32 && cur->start_asn > prev->end_asn + 1) {
            printf("[ogbackup]archive/redo gap detected: node %u rst %u ASN %u is followed by %u\n",
                prev->node_id, prev->rst_id, prev->end_asn, cur->start_asn);
            CM_FREE_PTR(ranges);
            return OG_ERROR;
        }
        if (cur->end_asn > prev->end_asn) {
            prev = cur;
        }
    }
    plan->need_recovery = OG_TRUE;
    CM_FREE_PTR(ranges);
    return OG_SUCCESS;
}

status_t ogbak_offline_build_plan(ogbak_offline_manifest_t *manifest, ogbak_param_t *param,
    ogbak_offline_plan_t *plan)
{
    errno_t ret = memset_s(plan, sizeof(ogbak_offline_plan_t), 0, sizeof(ogbak_offline_plan_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    plan->chain = (ogbak_offline_backup_t **)malloc(sizeof(ogbak_offline_backup_t *) * OGBAK_RESTORE_MAX_BACKUPS);
    plan->files = (ogbak_offline_file_t **)malloc(sizeof(ogbak_offline_file_t *) * OGBAK_RESTORE_MAX_FILES);
    if (plan->chain == NULL || plan->files == NULL) {
        ogbak_offline_free_plan(plan);
        return OG_ERROR;
    }
    ret = memset_s(plan->chain, sizeof(ogbak_offline_backup_t *) * OGBAK_RESTORE_MAX_BACKUPS, 0,
        sizeof(ogbak_offline_backup_t *) * OGBAK_RESTORE_MAX_BACKUPS);
    ret |= memset_s(plan->files, sizeof(ogbak_offline_file_t *) * OGBAK_RESTORE_MAX_FILES, 0,
        sizeof(ogbak_offline_file_t *) * OGBAK_RESTORE_MAX_FILES);
    if (ret != EOK) {
        ogbak_offline_free_plan(plan);
        return OG_ERROR;
    }
    if (ogbak_restore_build_chain(manifest, param, plan) != OG_SUCCESS ||
        ogbak_restore_collect_files(manifest, plan) != OG_SUCCESS ||
        ogbak_restore_validate_and_sort_pieces(plan) != OG_SUCCESS ||
        ogbak_restore_validate_final_control_source(param, plan) != OG_SUCCESS ||
        ogbak_restore_check_arch_continuity(manifest, plan) != OG_SUCCESS) {
        ogbak_offline_free_plan(plan);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void ogbak_offline_free_plan(ogbak_offline_plan_t *plan)
{
    if (plan == NULL) {
        return;
    }
    CM_FREE_PTR(plan->chain);
    CM_FREE_PTR(plan->files);
    (void)memset_s(plan, sizeof(ogbak_offline_plan_t), 0, sizeof(ogbak_offline_plan_t));
}

uint32 ogbak_offline_calc_file_checksum(const char *path, uint64 *size)
{
    uint32 hash = OGBAK_RESTORE_FNV_OFFSET;
    char buf[OGBAK_RESTORE_READ_BUF_SIZE];
    int32 handle = OG_INVALID_HANDLE;
    int32 read_size = 0;
    *size = 0;
    if (cm_open_file(path, O_RDONLY | O_BINARY, &handle) != OG_SUCCESS) {
        return 0;
    }
    do {
        if (cm_read_file(handle, buf, OGBAK_RESTORE_READ_BUF_SIZE, &read_size) != OG_SUCCESS) {
            cm_close_file(handle);
            return 0;
        }
        for (int32 i = 0; i < read_size; i++) {
            hash ^= (uint8)buf[i];
            hash *= OGBAK_RESTORE_FNV_PRIME;
        }
        *size += (uint64)read_size;
    } while (read_size > 0);
    cm_close_file(handle);
    return hash;
}

static status_t ogbak_restore_resolve_src(const char *backup_dir, const char *src, char *path)
{
    if (src[0] == '/') {
        return ogbak_restore_copy_str(path, OG_MAX_FILE_PATH_LENGH, src);
    }
    return ogbak_restore_join_path(backup_dir, src, path, OG_MAX_FILE_PATH_LENGH);
}

static status_t ogbak_restore_resolve_target(const char *target_dir, const char *target, char *path)
{
    return bak_offline_resolve_target_path(target_dir, target, path, OG_MAX_FILE_PATH_LENGH);
}

static bool32 ogbak_restore_path_map_auto(ogbak_param_t *param)
{
    return (param->path_map.str != NULL &&
        ogbak_restore_str_equal_ins(param->path_map.str, OGBAK_RESTORE_PATH_MAP_AUTO)) ? OG_TRUE : OG_FALSE;
}

static bool32 ogbak_restore_plan_uses_dss(ogbak_offline_plan_t *plan)
{
    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->device_type == DEV_TYPE_RAW || file->target[0] == '+' || file->original_path[0] == '+') {
            return OG_TRUE;
        }
    }
    for (uint32 i = 0; i < plan->chain_count; i++) {
        if (strchr(plan->chain[i]->control_files, '+') != NULL) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t ogbak_restore_configure_storage(ogbak_param_t *param, ogbak_offline_plan_t *plan)
{
    char storage_dss[] = OGBAK_RESTORE_STORAGE_DSS;
    char storage_local[] = OGBAK_RESTORE_STORAGE_LOCAL;
    char path_map_auto[] = OGBAK_RESTORE_PATH_MAP_AUTO;
    bool32 uses_dss = ogbak_restore_plan_uses_dss(plan);
    CM_FREE_PTR(param->storage.str);
    param->storage.len = 0;
    CM_FREE_PTR(param->path_map.str);
    param->path_map.len = 0;
    if (ogbak_parse_single_arg(uses_dss == OG_TRUE ? storage_dss : storage_local, &param->storage) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (uses_dss == OG_TRUE) {
        param->allow_inplace_dss_restore = param->is_force;
        return OG_SUCCESS;
    }
    if (param->is_in_place == OG_TRUE) {
        return OG_SUCCESS;
    }
    return ogbak_parse_single_arg(path_map_auto, &param->path_map);
}

static bool32 ogbak_restore_storage_dss(ogbak_param_t *param)
{
    return (param->storage.str != NULL &&
        ogbak_restore_str_equal_ins(param->storage.str, OGBAK_RESTORE_STORAGE_DSS)) ? OG_TRUE : OG_FALSE;
}

static bool32 ogbak_restore_dss_inplace(ogbak_param_t *param)
{
    return ogbak_restore_storage_dss(param);
}

static const char *ogbak_restore_path_map_mode(ogbak_param_t *param)
{
    return ogbak_restore_path_map_auto(param) == OG_TRUE ? OGBAK_RESTORE_PATH_MAP_AUTO :
        OGBAK_RESTORE_PATH_MAP_NONE;
}

static const char *ogbak_restore_storage_mode_name(ogbak_param_t *param)
{
    return ogbak_restore_storage_dss(param) == OG_TRUE ? OGBAK_RESTORE_STORAGE_DSS : OGBAK_RESTORE_STORAGE_LOCAL;
}

static ogbak_offline_backup_t *ogbak_restore_find_plan_backup(ogbak_offline_plan_t *plan, const char *backup_id)
{
    for (uint32 i = 0; i < plan->chain_count; i++) {
        if (cm_str_equal(plan->chain[i]->id, backup_id)) {
            return plan->chain[i];
        }
    }
    return NULL;
}

static bool32 ogbak_restore_is_latest_control_file(ogbak_offline_plan_t *plan, uint32 file_index)
{
    for (uint32 i = file_index + 1; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset == OG_TRUE &&
            plan->files[i]->type == OGBAK_RESTORE_FILE_CONTROL) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 ogbak_restore_same_mapping_item(bak_offline_ctrl_path_map_item_t *item,
    bak_offline_ctrl_path_type_t type, ogbak_offline_file_t *file)
{
    if (item->type != type || item->file_id != file->file_id || item->node_id != file->node_id) {
        return OG_FALSE;
    }
    if (type == BAK_OFFLINE_CTRL_PATH_ARCHIVE && item->rst_id != file->rst_id) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static status_t ogbak_restore_append_mapping_item(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    ogbak_offline_file_t *file,
    bak_offline_ctrl_path_map_t *map)
{
    bak_offline_ctrl_path_type_t type;
    if (file->type == OGBAK_RESTORE_FILE_DATA) {
        type = BAK_OFFLINE_CTRL_PATH_DATAFILE;
    } else if (file->type == OGBAK_RESTORE_FILE_LOG) {
        type = BAK_OFFLINE_CTRL_PATH_LOGFILE;
    } else if (file->type == OGBAK_RESTORE_FILE_ARCHIVE) {
        type = BAK_OFFLINE_CTRL_PATH_ARCHIVE;
    } else {
        return OG_SUCCESS;
    }
    for (uint32 i = 0; i < map->item_count; i++) {
        if (ogbak_restore_same_mapping_item(&map->items[i], type, file) == OG_TRUE) {
            return OG_SUCCESS;
        }
    }
    if (map->item_count >= map->item_capacity) {
        return OG_ERROR;
    }

    char dst_path[OG_MAX_FILE_PATH_LENGH] = {0};
    char decoded_archive_path[OG_MAX_FILE_PATH_LENGH] = {0};
    uint64 decoded_archive_size = file->size;
    const char *archive_source = NULL;
    if (param->is_in_place != OG_TRUE &&
        ogbak_restore_resolve_target(param->target_dir.str, file->target, dst_path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if ((ogbak_restore_storage_dss(param) == OG_TRUE || param->is_in_place == OG_TRUE) &&
        file->type == OGBAK_RESTORE_FILE_ARCHIVE) {
        char source_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_src(param->backup_dir.str, file->src, source_path) != OG_SUCCESS ||
            ogbak_restore_decode_payload_to_temp(param, plan, file, source_path,
            decoded_archive_path, sizeof(decoded_archive_path), &decoded_archive_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
        archive_source = decoded_archive_path;
        if (ogbak_restore_resolve_original_archive_target(archive_source, file,
            ogbak_restore_storage_dss(param),
            dst_path, sizeof(dst_path)) != OG_SUCCESS) {
            (void)remove(decoded_archive_path);
            return OG_ERROR;
        }
    }
    if (strlen(dst_path) >= OG_FILE_NAME_BUFFER_SIZE) {
        printf("[ogbackup]path-map auto target path is too long for control item field: %s\n", dst_path);
        if (decoded_archive_path[0] != '\0') {
            (void)remove(decoded_archive_path);
        }
        return OG_ERROR;
    }

    bak_offline_ctrl_path_map_item_t *item = &map->items[map->item_count++];
    errno_t ret = memset_s(item, sizeof(bak_offline_ctrl_path_map_item_t), 0,
        sizeof(bak_offline_ctrl_path_map_item_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    item->type = type;
    item->file_id = file->file_id;
    item->node_id = file->node_id;
    item->rst_id = file->rst_id;
    ret = strcpy_s(item->target_path, sizeof(item->target_path), dst_path);
    if (ret != EOK) {
        if (decoded_archive_path[0] != '\0') {
            (void)remove(decoded_archive_path);
        }
        return OG_ERROR;
    }
    if (type == BAK_OFFLINE_CTRL_PATH_ARCHIVE) {
        if (archive_source != NULL) {
            if (strcpy_s(item->source_path, sizeof(item->source_path), archive_source) != EOK) {
                (void)remove(decoded_archive_path);
                return OG_ERROR;
            }
            item->source_temp = OG_TRUE;
        } else if (ogbak_restore_resolve_src(param->backup_dir.str, file->src, item->source_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        item->source_size = archive_source == NULL ? file->size : decoded_archive_size;
        printf("[ogbackup][ctrl-debug] backup catalog archive file=%s id/asn=%u rst=%u node=%u "
               "size=%llu target=%s\n",
            item->source_path, item->file_id, item->rst_id, item->node_id, item->source_size,
            item->target_path);
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_build_ctrl_path_map(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    bak_offline_ctrl_path_map_t *map)
{
    errno_t ret = memset_s(map, sizeof(bak_offline_ctrl_path_map_t), 0, sizeof(bak_offline_ctrl_path_map_t));
    if (ret != EOK) {
        return OG_ERROR;
    }
    /*
     * Automatic local path rewriting must cover control-only data/log entries as well as
     * backupset payload entries. Online restore creates/updates those from
     * control items even when no BACKUP_LOG_FILE payload exists.
     */
    map->item_capacity = plan->file_count + OG_MAX_DATA_FILES + OG_MAX_LOG_FILES * OG_MAX_INSTANCES;
    map->items = (bak_offline_ctrl_path_map_item_t *)malloc(sizeof(bak_offline_ctrl_path_map_item_t) *
        map->item_capacity);
    if (map->items == NULL) {
        return OG_ERROR;
    }
    ret = memset_s(map->items, sizeof(bak_offline_ctrl_path_map_item_t) * map->item_capacity, 0,
        sizeof(bak_offline_ctrl_path_map_item_t) * map->item_capacity);
    if (ret != EOK) {
        CM_FREE_PTR(map->items);
        return OG_ERROR;
    }
    map->storage_mode = ogbak_restore_storage_dss(param) == OG_TRUE ? BAK_OFFLINE_RESTORE_STORAGE_DSS :
        BAK_OFFLINE_RESTORE_STORAGE_LOCAL;
    map->dss_map = NULL;
    map->dss_inplace_restore = (ogbak_restore_dss_inplace(param) == OG_TRUE &&
        param->is_dry_run != OG_TRUE) ? OG_TRUE : OG_FALSE;
    map->dss_inplace_preview = (ogbak_restore_dss_inplace(param) == OG_TRUE &&
        param->is_dry_run == OG_TRUE) ? OG_TRUE : OG_FALSE;
    map->inplace_restore = param->is_in_place;
    map->dss_map_required = OG_FALSE;
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset != OG_TRUE) {
            continue;
        }
        if (param->is_in_place == OG_TRUE &&
            (plan->files[i]->type == OGBAK_RESTORE_FILE_DATA ||
            plan->files[i]->type == OGBAK_RESTORE_FILE_LOG)) {
            continue;
        }
        if (ogbak_restore_append_mapping_item(param, plan, plan->files[i], map) != OG_SUCCESS) {
            for (uint32 j = 0; j < map->item_count; j++) {
                if (map->items[j].source_temp == OG_TRUE && map->items[j].source_path[0] != '\0') {
                    (void)remove(map->items[j].source_path);
                }
            }
            CM_FREE_PTR(map->items);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static void ogbak_restore_free_ctrl_path_map(bak_offline_ctrl_path_map_t *map)
{
    if (map == NULL) {
        return;
    }
    if (map->items != NULL) {
        for (uint32 i = 0; i < map->item_count; i++) {
            if (map->items[i].source_temp == OG_TRUE && map->items[i].source_path[0] != '\0') {
                (void)remove(map->items[i].source_path);
            }
        }
    }
    CM_FREE_PTR(map->items);
    (void)memset_s(map, sizeof(bak_offline_ctrl_path_map_t), 0, sizeof(bak_offline_ctrl_path_map_t));
}

static status_t ogbak_restore_apply_original_targets_from_map(ogbak_offline_plan_t *plan,
    bak_offline_ctrl_path_map_t *map)
{
    if (plan == NULL || map == NULL || map->items == NULL) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->from_backupset != OG_TRUE || file->type == OGBAK_RESTORE_FILE_CONTROL) {
            continue;
        }
        bak_offline_ctrl_path_type_t expected_type = file->type == OGBAK_RESTORE_FILE_ARCHIVE ?
            BAK_OFFLINE_CTRL_PATH_ARCHIVE : (file->type == OGBAK_RESTORE_FILE_LOG ?
            BAK_OFFLINE_CTRL_PATH_LOGFILE : BAK_OFFLINE_CTRL_PATH_DATAFILE);
        bool32 found = OG_FALSE;
        for (uint32 j = 0; j < map->item_count; j++) {
            bak_offline_ctrl_path_map_item_t *item = &map->items[j];
            if (item->type != expected_type || item->file_id != file->file_id || item->node_id != file->node_id ||
                (expected_type == BAK_OFFLINE_CTRL_PATH_ARCHIVE && item->rst_id != file->rst_id)) {
                continue;
            }
            device_type_t expected_device = map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS ?
                DEV_TYPE_RAW : DEV_TYPE_FILE;
            if (cm_device_type(item->target_path) != expected_device) {
                printf("[ogbackup]control target storage type mismatch: file=%u target=%s storage=%s\n",
                    file->file_id, item->target_path,
                    expected_device == DEV_TYPE_RAW ? "dss" : "local");
                return OG_ERROR;
            }
            if (file->type == OGBAK_RESTORE_FILE_DATA && file->sec_end != 0 &&
                item->target_size != 0 && file->sec_end > item->target_size) {
                printf("[ogbackup]backup section exceeds control file size: backup=%s file=%u section=%u "
                       "section_end=%llu control_size=%llu\n",
                    file->backup_id, file->file_id, file->sec_id, file->sec_end, item->target_size);
                return OG_ERROR;
            }
            if (file->type == OGBAK_RESTORE_FILE_DATA && file->sec_end != 0 && item->target_size != 0) {
                bool32 last_section = OG_TRUE;
                for (uint32 k = i + 1; k < plan->file_count; k++) {
                    if (plan->files[k]->type == OGBAK_RESTORE_FILE_DATA &&
                        plan->files[k]->file_id == file->file_id &&
                        cm_str_equal(plan->files[k]->backup_id, file->backup_id)) {
                        last_section = OG_FALSE;
                        break;
                    }
                }
                if (last_section == OG_TRUE && file->sec_end < item->target_size) {
                    printf("[ogbackup]datafile backup covers logical HWM; preallocated tail will be cleared: "
                           "backup=%s file=%u logical_end=%llu physical_size=%llu tail=%llu\n",
                        file->backup_id, file->file_id, file->sec_end, item->target_size,
                        item->target_size - file->sec_end);
                }
            }
            errno_t ret = strcpy_s(file->target, sizeof(file->target), item->target_path);
            if (ret != EOK) {
                return OG_ERROR;
            }
            file->device_type = expected_device;
            found = OG_TRUE;
            printf("[ogbackup]in-place %s target resolved from control: file=%u target=%s\n",
                ogbak_restore_file_type_name(file->type),
                file->file_id, file->target);
            break;
        }
        if (found != OG_TRUE) {
            printf("[ogbackup]in-place restore cannot find control target for backup payload "
                   "type=%s file=%u src=%s\n", ogbak_restore_file_type_name(file->type), file->file_id, file->src);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_original_write_plan(ogbak_offline_plan_t *plan,
    bak_offline_ctrl_path_map_t *map)
{
    if (plan == NULL || map == NULL || map->items == NULL || map->item_count == 0) {
        return OG_ERROR;
    }
    device_type_t expected = map->storage_mode == BAK_OFFLINE_RESTORE_STORAGE_DSS ?
        DEV_TYPE_RAW : DEV_TYPE_FILE;
    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->target_path[0] == '\0' || cm_device_type(item->target_path) != expected) {
            printf("[ogbackup]restore write plan has invalid target storage: type=%u file=%u node=%u target=%s\n",
                (uint32)item->type, item->file_id, item->node_id, item->target_path);
            return OG_ERROR;
        }
        for (uint32 j = i + 1; j < map->item_count; j++) {
            bak_offline_ctrl_path_map_item_t *other = &map->items[j];
            if (!cm_str_equal(item->target_path, other->target_path)) {
                continue;
            }
            if (item->type != other->type || item->file_id != other->file_id ||
                item->node_id != other->node_id || item->rst_id != other->rst_id) {
                printf("[ogbackup]duplicate restore target conflicts: target=%s first=%u/%u/%u/%u "
                       "second=%u/%u/%u/%u\n",
                    item->target_path, (uint32)item->type, item->file_id, item->node_id, item->rst_id,
                    (uint32)other->type, other->file_id, other->node_id, other->rst_id);
                return OG_ERROR;
            }
        }
    }
    return ogbak_restore_apply_original_targets_from_map(plan, map);
}

static status_t ogbak_restore_append_dss_root(char *printed, uint32 printed_size, uint32 *used, const char *path)
{
    if (printed == NULL || used == NULL || path == NULL || path[0] != '+') {
        return OG_ERROR;
    }
    uint32 len = 0;
    while (path[len] != '\0' && path[len] != '/') {
        len++;
    }
    if (len == 0 || len >= OG_NAME_BUFFER_SIZE || *used + len + 2 >= printed_size) {
        printf("[ogbackup]DSS device target resolve failed: invalid or too long DSS VG root in target=%s\n", path);
        return OG_ERROR;
    }

    uint32 pos = 0;
    while (pos < *used) {
        uint32 token_len = 0;
        while (pos + token_len < *used && printed[pos + token_len] != ',') {
            token_len++;
        }
        if (token_len == len && strncmp(printed + pos, path, len) == 0) {
            return OG_SUCCESS;
        }
        pos += token_len + 1;
    }

    if (*used > 0) {
        printed[(*used)++] = ',';
    }
    if (memcpy_s(printed + *used, printed_size - *used, path, len) != EOK) {
        return OG_ERROR;
    }
    *used += len;
    printed[*used] = '\0';
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_dss_preview_path(const char *path, char *printed,
    uint32 printed_size, uint32 *used)
{
    if (bak_offline_validate_dss_device_target(DEV_TYPE_RAW, path) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return ogbak_restore_append_dss_root(printed, printed_size, used, path);
}

static status_t ogbak_restore_probe_dss_target_path(const char *path, char *printed,
    uint32 printed_size, uint32 *used)
{
    if (bak_offline_probe_dss_device_target(DEV_TYPE_RAW, path, O_RDONLY | O_BINARY) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return ogbak_restore_append_dss_root(printed, printed_size, used, path);
}

static bool32 ogbak_restore_control_file_token_boundary(char ch)
{
    return (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' ||
        ch == '(' || ch == ')' || ch == ',') ? OG_TRUE : OG_FALSE;
}

static status_t ogbak_restore_normalize_control_file_token(const char *start, const char *end,
    char *path, uint32 path_size, const char *control_files)
{
    while (start < end && ogbak_restore_control_file_token_boundary(*start) == OG_TRUE) {
        start++;
    }
    while (end > start && ogbak_restore_control_file_token_boundary(end[-1]) == OG_TRUE) {
        end--;
    }

    uint32 len = (uint32)(end - start);
    if (len == 0 || len >= path_size) {
        printf("[ogbackup]DSS device target resolve failed: invalid CONTROL_FILES item in %s\n", control_files);
        return OG_ERROR;
    }
    if (memset_s(path, path_size, 0, path_size) != EOK ||
        memcpy_s(path, path_size, start, len) != EOK) {
        return OG_ERROR;
    }
    path[len] = '\0';
    printf("[ogbackup]storage=dss normalized DSS control file token=%s\n", path);
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_dss_preview_control_files(const char *control_files,
    char *printed, uint32 printed_size, uint32 *used)
{
    if (control_files == NULL || control_files[0] == '\0') {
        printf("[ogbackup]DSS in-place dry-run requires CONTROL_FILES from backupset header\n");
        return OG_ERROR;
    }

    const char *pos = control_files;
    while (*pos != '\0') {
        const char *end = strchr(pos, ',');
        const char *token_end = end == NULL ? pos + strlen(pos) : end;
        while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') {
            pos++;
        }
        while (token_end > pos &&
            (token_end[-1] == ' ' || token_end[-1] == '\t' || token_end[-1] == '\r' || token_end[-1] == '\n')) {
            token_end--;
        }
        char path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_normalize_control_file_token(pos, token_end, path, sizeof(path),
            control_files) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (ogbak_restore_validate_dss_preview_path(path, printed, printed_size, used) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (end == NULL) {
            break;
        }
        pos = end + 1;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_probe_dss_control_files(const char *control_files,
    char *printed, uint32 printed_size, uint32 *used)
{
    if (control_files == NULL || control_files[0] == '\0') {
        printf("[ogbackup]DSS target preparation probe requires CONTROL_FILES from backupset header\n");
        return OG_ERROR;
    }

    const char *pos = control_files;
    while (*pos != '\0') {
        const char *end = strchr(pos, ',');
        const char *token_end = end == NULL ? pos + strlen(pos) : end;
        while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') {
            pos++;
        }
        while (token_end > pos &&
            (token_end[-1] == ' ' || token_end[-1] == '\t' || token_end[-1] == '\r' || token_end[-1] == '\n')) {
            token_end--;
        }
        char path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_normalize_control_file_token(pos, token_end, path, sizeof(path),
            control_files) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (ogbak_restore_probe_dss_target_path(path, printed, printed_size, used) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (end == NULL) {
            break;
        }
        pos = end + 1;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_dss_inplace_preview_targets(const char *control_files,
    bak_offline_ctrl_path_map_t *map)
{
    if (map == NULL || map->items == NULL) {
        return OG_ERROR;
    }

    char printed[OG_MAX_CONFIG_LINE_SIZE] = {0};
    uint32 used = 0;
    if (ogbak_restore_validate_dss_preview_control_files(control_files, printed, sizeof(printed),
        &used) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->target_path[0] == '\0') {
            printf("[ogbackup]DSS device target resolve failed: empty control-discovered target type=%u file=%u node=%u\n",
                (uint32)item->type, item->file_id, item->node_id);
            return OG_ERROR;
        }
        if (ogbak_restore_validate_dss_preview_path(item->target_path, printed, sizeof(printed),
            &used) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    printf("[ogbackup]  target DSS paths preserved=%s\n", used > 0 ? printed : "<unknown>");
    return used > 0 ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_restore_probe_dss_inplace_targets(const char *control_files,
    bak_offline_ctrl_path_map_t *map)
{
    if (map == NULL || map->items == NULL) {
        return OG_ERROR;
    }

    char printed[OG_MAX_CONFIG_LINE_SIZE] = {0};
    uint32 used = 0;
    printf("[ogbackup]storage=dss DSS target preparation probe begin; mode=no-write "
           "forbid=cm_create,cm_extend,cm_write,truncate,O_RDWR\n");
    if (ogbak_restore_probe_dss_control_files(control_files, printed, sizeof(printed),
        &used) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->target_path[0] == '\0') {
            printf("[ogbackup]DSS target preparation probe failed: empty control-discovered target "
                   "type=%u file=%u node=%u\n", (uint32)item->type, item->file_id, item->node_id);
            return OG_ERROR;
        }
        if (ogbak_restore_probe_dss_target_path(item->target_path, printed, sizeof(printed),
            &used) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    printf("[ogbackup]storage=dss DSS target preparation probe complete; target DSS paths preserved=%s "
           "no_write=true\n", used > 0 ? printed : "<unknown>");
    return used > 0 ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_restore_validate_files(ogbak_param_t *param, ogbak_offline_plan_t *plan)
{
    for (uint32 i = 0; i < plan->file_count; i++) {
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        uint64 actual_size = 0;
        if (ogbak_restore_resolve_src(param->backup_dir.str, plan->files[i]->src, src_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (!cm_file_exist(src_path)) {
            printf("[ogbackup]backup file does not exist: %s\n", src_path);
            return OG_ERROR;
        }
        if (bak_offline_check_no_symlink(src_path, OG_FALSE) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (param->is_in_place != OG_TRUE) {
            char dst_path[OG_MAX_FILE_PATH_LENGH] = {0};
            if (ogbak_restore_resolve_target(param->target_dir.str, plan->files[i]->target,
                dst_path) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
        if (plan->files[i]->from_backupset == OG_TRUE && plan->files[i]->type == OGBAK_RESTORE_FILE_CONTROL) {
            continue;
        }
        uint32 checksum = ogbak_offline_calc_file_checksum(src_path, &actual_size);
        if (actual_size != plan->files[i]->size) {
            printf("[ogbackup]backup file size mismatch for %s, expected %llu, actual %llu\n",
                src_path, plan->files[i]->size, actual_size);
            return OG_ERROR;
        }
        if (plan->files[i]->has_checksum == OG_TRUE && checksum != plan->files[i]->checksum) {
            printf("[ogbackup]backup file checksum mismatch for %s, expected %u, actual %u\n",
                src_path, plan->files[i]->checksum, checksum);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_precheck_target(ogbak_param_t *param)
{
    if (param->is_in_place == OG_TRUE) {
        if (cm_dir_exist(param->target_dir.str) != OG_TRUE ||
            bak_offline_check_no_symlink(param->target_dir.str, OG_FALSE) != OG_SUCCESS ||
            access(param->target_dir.str, R_OK | W_OK) != 0) {
            printf("[ogbackup]in-place fail-stop marker directory is unavailable or not writable: %s\n",
                param->target_dir.str);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    return bak_offline_check_target_dir(param->target_dir.str, param->is_force, param->is_dry_run);
}

static status_t ogbak_restore_validate_control_files(ogbak_param_t *param, ogbak_offline_plan_t *plan)
{
    if (param->is_dry_run != OG_TRUE) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset != OG_TRUE || plan->files[i]->type != OGBAK_RESTORE_FILE_CONTROL) {
            continue;
        }
        if (ogbak_restore_is_latest_control_file(plan, i) != OG_TRUE) {
            continue;
        }
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_src(param->backup_dir.str, plan->files[i]->src, src_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        bak_offline_ctrl_restore_opts_t opts = {0};
        bak_offline_ctrl_restore_result_t result;
        char decoded_ctrl_path[OG_MAX_FILE_PATH_LENGH] = {0};
        const char *control_src_path = src_path;
        uint64 control_payload_size = plan->files[i]->size;
        opts.target_dir = param->target_dir.str;
        opts.reject_dss_to_local = ogbak_restore_storage_dss(param) == OG_TRUE ? OG_FALSE : OG_TRUE;
        opts.dry_run = OG_TRUE;
        opts.storage_mode = ogbak_restore_storage_dss(param) == OG_TRUE ? BAK_OFFLINE_RESTORE_STORAGE_DSS :
            BAK_OFFLINE_RESTORE_STORAGE_LOCAL;
        ogbak_offline_backup_t *ctrl_bak = ogbak_restore_find_plan_backup(plan, plan->files[i]->backup_id);
        opts.control_files = ctrl_bak == NULL ? NULL : ctrl_bak->control_files;
        bak_offline_ctrl_path_map_t path_map;
        if (ogbak_restore_path_map_auto(param) == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE) {
            if (ogbak_restore_build_ctrl_path_map(param, plan, &path_map) != OG_SUCCESS) {
                return OG_ERROR;
            }
            /* DSS restore must register backup archive pieces in the control
             * ring; this is a rewrite of the decoded control image, not a
             * local path relocation. */
            opts.rewrite_paths = ogbak_restore_storage_dss(param) == OG_TRUE ? OG_TRUE :
                ogbak_restore_path_map_auto(param);
            opts.path_map = &path_map;
        }
        if (ogbak_restore_decode_payload_to_temp(param, plan, plan->files[i], src_path, decoded_ctrl_path,
            sizeof(decoded_ctrl_path), &control_payload_size) != OG_SUCCESS) {
            if (ogbak_restore_path_map_auto(param) == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE) {
                ogbak_restore_free_ctrl_path_map(&path_map);
            }
            return OG_ERROR;
        }
        control_src_path = decoded_ctrl_path;
        opts.expected_payload_size = control_payload_size;
        if (bak_offline_restore_ctrlfile(control_src_path, &opts, &result) != OG_SUCCESS) {
            if (ogbak_restore_path_map_auto(param) == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE) {
                ogbak_restore_free_ctrl_path_map(&path_map);
            }
            (void)remove(decoded_ctrl_path);
            return OG_ERROR;
        }
        (void)remove(decoded_ctrl_path);
        if (ogbak_restore_path_map_auto(param) == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE) {
            printf("[ogbackup]  dry-run control rewrite summary: rewritten data/log/archive=%u/%u/%u "
                   "created_datafiles=0 dry-run=true planned_datafiles=%u "
                   "created_logfiles=0 dry-run=true planned_logfiles=%u "
                   "preserved DSS data/log/archive=%u/%u/%u "
                   "mapped DSS data/log/archive=%u/%u/%u\n",
                result.rewritten_datafiles, result.rewritten_logfiles, result.rewritten_archives,
                result.planned_datafiles, result.planned_logfiles,
                result.preserved_dss_datafiles, result.preserved_dss_logfiles, result.preserved_dss_archives,
                result.mapped_dss_datafiles, result.mapped_dss_logfiles, result.mapped_dss_archives);
            if (ogbak_restore_storage_dss(param) == OG_TRUE &&
                result.planned_logfiles > 0 && result.preserved_dss_logfiles == 0 &&
                result.mapped_dss_logfiles == 0) {
                printf("[ogbackup]DSS redo/log path handling missing: planned_logfiles=%u "
                       "preserved_dss_logfiles=0 mapped_dss_logfiles=0\n", result.planned_logfiles);
                ogbak_restore_free_ctrl_path_map(&path_map);
                return OG_ERROR;
            }
            if (ogbak_restore_storage_dss(param) != OG_TRUE &&
                result.planned_logfiles > 0 && result.rewritten_logfiles == 0) {
                printf("[ogbackup]redo/log path rewrite missing: planned_logfiles=%u rewritten_logfiles=0\n",
                    result.planned_logfiles);
                ogbak_restore_free_ctrl_path_map(&path_map);
                return OG_ERROR;
            }
            if (ogbak_restore_dss_inplace(param) == OG_TRUE && param->is_dry_run == OG_TRUE) {
                if (ogbak_restore_apply_original_targets_from_map(plan, &path_map) != OG_SUCCESS ||
                    ogbak_restore_validate_dss_inplace_preview_targets(opts.control_files,
                    &path_map) != OG_SUCCESS) {
                    ogbak_restore_free_ctrl_path_map(&path_map);
                    return OG_ERROR;
                }
            }
        }
        if (ogbak_restore_path_map_auto(param) == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE) {
            ogbak_restore_free_ctrl_path_map(&path_map);
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_probe_dss_inplace_preflight(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size)
{
    if (ogbak_restore_dss_inplace(param) != OG_TRUE) {
        return OG_SUCCESS;
    }
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset != OG_TRUE || plan->files[i]->type != OGBAK_RESTORE_FILE_CONTROL ||
            ogbak_restore_is_latest_control_file(plan, i) != OG_TRUE) {
            continue;
        }
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_src(param->backup_dir.str, plan->files[i]->src, src_path) != OG_SUCCESS) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "DSS target preparation preflight failed while resolving control piece source %s\n",
                plan->files[i]->src);
            return OG_ERROR;
        }
        bak_offline_ctrl_restore_opts_t opts = {0};
        bak_offline_ctrl_restore_result_t result;
        char decoded_ctrl_path[OG_MAX_FILE_PATH_LENGH] = {0};
        const char *control_src_path = src_path;
        uint64 control_payload_size = plan->files[i]->size;
        opts.target_dir = param->target_dir.str;
        opts.reject_dss_to_local = OG_FALSE;
        opts.dry_run = OG_TRUE;
        opts.storage_mode = BAK_OFFLINE_RESTORE_STORAGE_DSS;
        ogbak_offline_backup_t *ctrl_bak = ogbak_restore_find_plan_backup(plan, plan->files[i]->backup_id);
        opts.control_files = ctrl_bak == NULL ? NULL : ctrl_bak->control_files;
        bak_offline_ctrl_path_map_t path_map;
        if (ogbak_restore_build_ctrl_path_map(param, plan, &path_map) != OG_SUCCESS) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "DSS target preparation preflight failed while building control path map\n");
            return OG_ERROR;
        }
        opts.rewrite_paths = OG_TRUE;
        opts.path_map = &path_map;
        status_t status = ogbak_restore_decode_payload_to_temp(param, plan, plan->files[i], src_path,
            decoded_ctrl_path, sizeof(decoded_ctrl_path), &control_payload_size);
        if (status == OG_SUCCESS) {
            control_src_path = decoded_ctrl_path;
            opts.expected_payload_size = control_payload_size;
            status = bak_offline_restore_ctrlfile(control_src_path, &opts, &result);
        }
        if (status == OG_SUCCESS) {
            status = ogbak_restore_apply_original_targets_from_map(plan, &path_map);
        }
        if (status == OG_SUCCESS) {
            status = ogbak_restore_validate_dss_inplace_preview_targets(opts.control_files, &path_map);
        }
        if (status == OG_SUCCESS) {
            status = ogbak_restore_probe_dss_inplace_targets(opts.control_files, &path_map);
        }
        if (status != OG_SUCCESS) {
            const char *last_dss_error = bak_offline_get_last_dss_error();
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "DSS target preparation preflight failed before file writes: %s\n",
                last_dss_error == NULL ? "see DSS target preparation probe diagnostics" : last_dss_error);
            if (decoded_ctrl_path[0] != '\0') {
                (void)remove(decoded_ctrl_path);
            }
            ogbak_restore_free_ctrl_path_map(&path_map);
            return OG_ERROR;
        }
        (void)remove(decoded_ctrl_path);
        ogbak_restore_free_ctrl_path_map(&path_map);
        return OG_SUCCESS;
    }

    ogbak_restore_set_failure(failure_reason, failure_reason_size,
        "DSS target preparation preflight failed: no latest control backup piece found\n");
    return OG_ERROR;
}

static status_t ogbak_restore_scheme_d_reject_unsupported(ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size)
{
    if (plan->chain_count != 1 || plan->chain[0]->type != OGBAK_RESTORE_BAK_FULL ||
        plan->chain[0]->level != 0) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "Scheme D P0 supports only a single full level-0 backupset; chain_count=%u first_type=%u level=%u\n",
            plan->chain_count, plan->chain_count == 0 ? 0 : (uint32)plan->chain[0]->type,
            plan->chain_count == 0 ? 0 : plan->chain[0]->level);
        return OG_ERROR;
    }
    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->sparse == OG_TRUE) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "Scheme D P0 unsupported sparse payload target=%s\n", file->target);
            return OG_ERROR;
        }
        if (file->type == OGBAK_RESTORE_FILE_LOG || file->type == OGBAK_RESTORE_FILE_ARCHIVE) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "Scheme D P0 does not support independent DSS redo/archive payload: target=%s type=%u\n",
                file->target, (uint32)file->type);
            return OG_ERROR;
        }
        if (file->type != OGBAK_RESTORE_FILE_CONTROL && file->type != OGBAK_RESTORE_FILE_DATA) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "Scheme D P0 unsupported backup payload type=%u target=%s\n", (uint32)file->type,
                file->target);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_scheme_d_stat_target(device_type_t type, const char *path, uint64 *size,
    uint64 *written_size)
{
#ifdef CMS_UT_TEST
    if (g_scheme_d_stat_hook != NULL) {
        return g_scheme_d_stat_hook(type, path, size, written_size);
    }
#endif
    return bak_offline_stat_dss_device_target(type, path, size, written_size);
}

static const char *ogbak_restore_scheme_d_ctrl_type_name(bak_offline_ctrl_path_type_t type)
{
    switch (type) {
        case BAK_OFFLINE_CTRL_PATH_DATAFILE:
            return "datafile";
        case BAK_OFFLINE_CTRL_PATH_LOGFILE:
            return "redo";
        case BAK_OFFLINE_CTRL_PATH_ARCHIVE:
            return "archive";
        default:
            return "unknown";
    }
}

static ogbak_scheme_d_target_size_t *ogbak_scheme_d_find_target(ogbak_scheme_d_target_manifest_t *manifest,
    const char *path, uint32 file_id, const char *type)
{
    for (uint32 i = 0; i < manifest->target_count; i++) {
        ogbak_scheme_d_target_size_t *target = &manifest->targets[i];
        if (target->file_id == file_id && strcmp(target->path, path) == 0 && strcmp(target->type, type) == 0) {
            return target;
        }
    }
    return NULL;
}

static ogbak_scheme_d_target_size_t *ogbak_scheme_d_add_target(ogbak_scheme_d_target_manifest_t *manifest,
    const char *path, const char *type, uint32 file_id, uint32 node_id, uint64 control_size)
{
    ogbak_scheme_d_target_size_t *target = ogbak_scheme_d_find_target(manifest, path, file_id, type);
    if (target != NULL) {
        if (control_size > target->control_size) {
            target->control_size = control_size;
        }
        return target;
    }
    if (manifest->target_count >= OGBAK_RESTORE_MAX_FILES) {
        return NULL;
    }
    target = &manifest->targets[manifest->target_count++];
    if (memset_s(target, sizeof(*target), 0, sizeof(*target)) != EOK ||
        strcpy_s(target->path, sizeof(target->path), path) != EOK ||
        strcpy_s(target->type, sizeof(target->type), type) != EOK) {
        return NULL;
    }
    target->file_id = file_id;
    target->node_id = node_id;
    target->control_size = control_size;
    target->required_min_size = control_size;
    target->create_required = OG_TRUE;
    return target;
}

static status_t ogbak_scheme_d_collect_ctrl_targets(ogbak_scheme_d_target_manifest_t *manifest,
    bak_offline_ctrl_path_map_t *map)
{
    for (uint32 i = 0; i < map->item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &map->items[i];
        if (item->type == BAK_OFFLINE_CTRL_PATH_DATAFILE && item->datafile_required != OG_TRUE) {
            continue;
        }
        const char *type = ogbak_restore_scheme_d_ctrl_type_name(item->type);
        if (ogbak_scheme_d_add_target(manifest, item->target_path, type, item->file_id, item->node_id,
            item->target_size) == NULL) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_page_scan_cb(uint32 file_id, uint32 page_no, uint32 page_size, uint64 source_offset,
    void *ctx)
{
    ogbak_scheme_d_page_scan_ctx_t *scan = (ogbak_scheme_d_page_scan_ctx_t *)ctx;
    uint64 offset = 0;
    uint64 length = 0;
    if (bak_offline_calc_page_write_range(page_no, page_size, &offset, &length) != OG_SUCCESS ||
        UINT64_MAX - offset < length) {
        ogbak_restore_set_failure(scan->err_buf, scan->err_size,
            "Scheme D data page range overflow file_id=%u page_no=%u page_size=%u\n",
            file_id, page_no, page_size);
        return OG_ERROR;
    }
    uint64 end = offset + length;
    if (scan->target != NULL) {
        scan->target->payload_present = OG_TRUE;
        scan->target->total_payload_bytes += length;
        scan->target->range_count++;
        scan->target->unique_page_count++;
        if (end > scan->target->payload_max_end) {
            scan->target->payload_max_end = end;
        }
        if (end > scan->target->required_min_size) {
            scan->target->required_min_size = end;
        }
    }
    if (scan->plan != NULL &&
        ogbak_scheme_d_append_plan_range(scan->plan, scan->target->path, scan->target->type, file_id,
        offset, length, scan->existing_size, scan->written_size, scan->target->required_min_size, source_offset,
        scan->payload_source, scan->err_buf, scan->err_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_scan_data_payload(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    const char *src_path, ogbak_offline_file_t *file, ogbak_scheme_d_target_size_t *target,
    ogbak_scheme_d_plan_t *scheme_plan, uint64 existing_size, uint64 written_size, char *failure_reason,
    uint32 failure_reason_size)
{
    bak_offline_page_apply_opts_t opts = {0};
    opts.expected_file_id = file->file_id;
    opts.backup_level = file->backup_level;
    opts.expected_payload_size = file->size;
    opts.verify_page_checksum = OG_TRUE;
    opts.skip_empty_pages = file->backup_level == 0 ? OG_TRUE : OG_FALSE;
    ogbak_scheme_d_page_scan_ctx_t ctx = {target, scheme_plan, existing_size, written_size, file->src,
        failure_reason, failure_reason_size};
    bak_offline_decode_opts_t decode_opts;
    bak_file_t scratch_file;
    if (ogbak_restore_build_decode_opts(param, plan, file, &scratch_file, &decode_opts) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return bak_offline_scan_decoded_data_page_ranges(src_path, &opts, &decode_opts, ogbak_scheme_d_page_scan_cb,
        &ctx);
}

static status_t ogbak_scheme_d_runtime_write_guard(const char *target_path, uint32 file_id, uint32 page_no,
    uint64 offset, uint32 length, void *ctx)
{
    (void)ctx;
    char err[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
    if (ogbak_scheme_d_assert_plan_range(g_ogbak_scheme_d_active_plan, target_path, file_id, offset, length,
        err, sizeof(err)) != OG_SUCCESS) {
        printf("[ogbackup]scheme_d=true runtime write range assertion failed before dss_pwrite: %s page_no=%u\n",
            err, page_no);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_build_decode_opts(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    ogbak_offline_file_t *file, bak_file_t *scratch_file, bak_offline_decode_opts_t *opts)
{
    if (param == NULL || plan == NULL || file == NULL || scratch_file == NULL || opts == NULL) {
        return OG_ERROR;
    }
    errno_t ret = memset_s(opts, sizeof(*opts), 0, sizeof(*opts));
    if (ret != EOK) {
        return OG_ERROR;
    }
    ogbak_offline_backup_t *bak = ogbak_restore_find_plan_backup(plan, file->backup_id);
    opts->compress = file->compress_algo;
    opts->encrypt_alg = file->encrypt_alg;
    opts->password = param->password.str;
    opts->physical_size = file->size;
    ret = memcpy_s(&opts->encrypt_info, sizeof(opts->encrypt_info), &file->encrypt_info,
        sizeof(file->encrypt_info));
    ret |= memcpy_s(opts->sys_pwd, sizeof(opts->sys_pwd), file->sys_pwd, sizeof(file->sys_pwd));
    if (ret != EOK) {
        return OG_ERROR;
    }
    ret = memset_s(scratch_file, sizeof(*scratch_file), 0, sizeof(*scratch_file));
    ret |= memcpy_s(scratch_file->gcm_iv, sizeof(scratch_file->gcm_iv), file->gcm_iv, sizeof(file->gcm_iv));
    ret |= memcpy_s(scratch_file->gcm_tag, sizeof(scratch_file->gcm_tag), file->gcm_tag, sizeof(file->gcm_tag));
    if (ret != EOK) {
        return OG_ERROR;
    }
    scratch_file->size = file->size;
    scratch_file->type = file->type == OGBAK_RESTORE_FILE_LOG ? BACKUP_LOG_FILE :
        (file->type == OGBAK_RESTORE_FILE_ARCHIVE ? BACKUP_ARCH_FILE :
        (file->type == OGBAK_RESTORE_FILE_DATA ? BACKUP_DATA_FILE : BACKUP_CTRL_FILE));
    scratch_file->id = file->file_id;
    scratch_file->sec_id = file->sec_id;
    scratch_file->rst_id = file->rst_id;
    scratch_file->reserved = file->format_flags;
    opts->file = scratch_file;
    opts->allow_legacy_log_prefix = (scratch_file->type == BACKUP_LOG_FILE ||
        scratch_file->type == BACKUP_ARCH_FILE) ? OG_TRUE : OG_FALSE;
    if ((opts->compress != COMPRESS_NONE || opts->encrypt_alg != ENCRYPT_NONE) && file->from_backupset != OG_TRUE) {
        printf("[ogbackup]offline decode metadata is valid only for real backupset payloads: %s\n", file->src);
        return OG_ERROR;
    }
    if (opts->compress == COMPRESS_NONE && bak != NULL && bak->compressed == OG_TRUE && file->compressed != OG_TRUE) {
        printf("[ogbackup]backupset is marked compressed but file lacks compression metadata: %s\n", file->src);
        return OG_ERROR;
    }
    if (opts->encrypt_alg == ENCRYPT_NONE && bak != NULL && bak->encrypted == OG_TRUE) {
        printf("[ogbackup]backupset is marked encrypted but file lacks encryption metadata: %s\n", file->src);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

typedef struct st_ogbak_decoded_temp_ctx {
    int32 fd;
    uint64 size;
} ogbak_decoded_temp_ctx_t;

static status_t ogbak_restore_write_decoded_temp(const char *buf, uint32 size, uint64 logical_offset, void *ctx)
{
    ogbak_decoded_temp_ctx_t *temp = (ogbak_decoded_temp_ctx_t *)ctx;
    if (logical_offset != temp->size || size == 0) {
        return size == 0 ? OG_SUCCESS : OG_ERROR;
    }
    const char *pos = buf;
    uint32 left = size;
    while (left > 0) {
        ssize_t written = write(temp->fd, pos, left);
        if (written <= 0) {
            return OG_ERROR;
        }
        pos += written;
        left -= (uint32)written;
        temp->size += (uint64)written;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_decode_payload_to_temp(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    ogbak_offline_file_t *file, const char *src_path, char *tmp_path, uint32 tmp_path_size, uint64 *logical_size)
{
    struct statvfs temp_fs;
    if (file == NULL || statvfs("/tmp", &temp_fs) != 0) {
        printf("[ogbackup]cannot inspect temporary decode space, errno=%d (%s)\n", errno, strerror(errno));
        return OG_ERROR;
    }
    uint64 available = (uint64)temp_fs.f_bavail * (uint64)temp_fs.f_frsize;
    uint64 reserve = SIZE_M(64);
    if (available < file->size || available - file->size < reserve) {
        printf("[ogbackup]insufficient temporary decode space: available=%llu payload=%llu reserve=%llu\n",
            available, file->size, reserve);
        return OG_ERROR;
    }
    if (tmp_path == NULL || logical_size == NULL ||
        strcpy_s(tmp_path, tmp_path_size, OGBAK_RESTORE_TMP_TEMPLATE) != EOK) {
        return OG_ERROR;
    }
    int32 fd = mkstemp(tmp_path);
    if (fd < 0) {
        printf("[ogbackup]create temporary decoded backup payload failed, errno=%d\n", errno);
        return OG_ERROR;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        (void)close(fd);
        (void)remove(tmp_path);
        return OG_ERROR;
    }
    bak_offline_decode_opts_t opts;
    bak_file_t scratch_file;
    ogbak_decoded_temp_ctx_t ctx = {fd, 0};
    status_t status = ogbak_restore_build_decode_opts(param, plan, file, &scratch_file, &opts);
    if (status == OG_SUCCESS) {
        status = bak_offline_decode_backup_file(src_path, &opts, ogbak_restore_write_decoded_temp, &ctx);
    }
    if (status == OG_SUCCESS && fsync(fd) != 0) {
        status = OG_ERROR;
    }
    (void)close(fd);
    if (status != OG_SUCCESS) {
        (void)remove(tmp_path);
        tmp_path[0] = '\0';
        return OG_ERROR;
    }
    *logical_size = ctx.size;
    return OG_SUCCESS;
}

static status_t ogbak_restore_validate_original_control_targets(ogbak_param_t *param,
    const char *control_files)
{
    if (control_files == NULL || control_files[0] == '\0' || strlen(control_files) >= OG_MAX_CONFIG_LINE_SIZE) {
        printf("[ogbackup]in-place restore requires valid CONTROL_FILES metadata\n");
        return OG_ERROR;
    }
    char copy[OG_MAX_CONFIG_LINE_SIZE] = {0};
    if (strcpy_s(copy, sizeof(copy), control_files) != EOK) {
        return OG_ERROR;
    }
    char targets[BAK_OFFLINE_CTRL_FILE_COUNT][OG_FILE_NAME_BUFFER_SIZE] = {{0}};
    uint32 count = 0;
    char *save = NULL;
    char *token = strtok_r(copy, ",", &save);
    while (token != NULL) {
        if (count >= BAK_OFFLINE_CTRL_FILE_COUNT ||
            ogbak_restore_normalize_control_file_token(token, token + strlen(token), targets[count],
            sizeof(targets[count]), control_files) != OG_SUCCESS) {
            printf("[ogbackup]CONTROL_FILES contains too many or malformed targets: %s\n", control_files);
            return OG_ERROR;
        }
        device_type_t expected = ogbak_restore_storage_dss(param) == OG_TRUE ? DEV_TYPE_RAW : DEV_TYPE_FILE;
        if (cm_device_type(targets[count]) != expected ||
            (expected == DEV_TYPE_FILE && targets[count][0] != '/') ||
            strstr(targets[count], "/../") != NULL || strstr(targets[count], "/./") != NULL) {
            printf("[ogbackup]CONTROL_FILES target conflicts with in-place storage plan: %s\n", targets[count]);
            return OG_ERROR;
        }
        if (expected == DEV_TYPE_FILE &&
            bak_offline_check_no_symlink(targets[count], OG_TRUE) != OG_SUCCESS) {
            return OG_ERROR;
        }
        for (uint32 i = 0; i < count; i++) {
            if (cm_str_equal(targets[i], targets[count])) {
                printf("[ogbackup]duplicate CONTROL_FILES target is not allowed: %s\n", targets[count]);
                return OG_ERROR;
            }
        }
        count++;
        token = strtok_r(NULL, ",", &save);
    }
    return count == 0 ? OG_ERROR : OG_SUCCESS;
}

static status_t ogbak_restore_predecode_protected_payloads(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size)
{
    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->from_backupset != OG_TRUE ||
            (file->encrypt_alg == ENCRYPT_NONE && file->compress_algo == COMPRESS_NONE)) {
            continue;
        }
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        char decoded_path[OG_MAX_FILE_PATH_LENGH] = {0};
        uint64 logical_size = file->size;
        if (ogbak_restore_resolve_src(param->backup_dir.str, file->src, src_path) != OG_SUCCESS ||
            ogbak_restore_decode_payload_to_temp(param, plan, file, src_path, decoded_path,
            sizeof(decoded_path), &logical_size) != OG_SUCCESS) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "protected backup payload authentication/decode failed before target mutation: %s\n", file->src);
            if (decoded_path[0] != '\0') {
                (void)remove(decoded_path);
            }
            return OG_ERROR;
        }
        (void)remove(decoded_path);
    }
    printf("[ogbackup]all compressed/encrypted payloads authenticated and decoded successfully before target mutation\n");
    return OG_SUCCESS;
}

static status_t ogbak_scheme_d_collect_control_file_targets(ogbak_scheme_d_target_manifest_t *manifest,
    const char *control_files, uint64 control_size)
{
    if (control_files == NULL || control_files[0] == '\0') {
        return OG_ERROR;
    }
    char copy[OG_MAX_CONFIG_LINE_SIZE] = {0};
    if (strlen(control_files) >= sizeof(copy) || strcpy_s(copy, sizeof(copy), control_files) != EOK) {
        return OG_ERROR;
    }
    char *save = NULL;
    char *token = strtok_r(copy, ",", &save);
    while (token != NULL) {
        char path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_normalize_control_file_token(token, token + strlen(token), path, sizeof(path),
            control_files) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (path[0] == '+' &&
            ogbak_scheme_d_add_target(manifest, path, "control", 0, 0, control_size) == NULL) {
            return OG_ERROR;
        }
        token = strtok_r(NULL, ",", &save);
    }
    return OG_SUCCESS;
}

static ogbak_scheme_d_target_size_t *ogbak_scheme_d_find_data_target_by_file(
    ogbak_scheme_d_target_manifest_t *manifest, uint32 file_id, const char *path)
{
    ogbak_scheme_d_target_size_t *target = ogbak_scheme_d_find_target(manifest, path, file_id, "datafile");
    if (target != NULL) {
        return target;
    }
    return ogbak_scheme_d_add_target(manifest, path, "datafile", file_id, 0, 0);
}

static void ogbak_scheme_d_finalize_target_manifest(ogbak_scheme_d_target_manifest_t *manifest)
{
    manifest->unknown_count = 0;
    for (uint32 i = 0; i < manifest->target_count; i++) {
        ogbak_scheme_d_target_size_t *target = &manifest->targets[i];
        if (target->payload_max_end > target->required_min_size) {
            target->required_min_size = target->payload_max_end;
        }
        target->payload_full_coverage = (target->payload_present == OG_TRUE &&
            target->payload_max_end >= target->required_min_size) ? OG_TRUE : OG_FALSE;
        if (strcmp(target->type, "datafile") == 0 && target->control_size == 0) {
            target->blocked = OG_TRUE;
            (void)strcpy_s(target->blocked_reason, sizeof(target->blocked_reason),
                "data payload target has no matching required control metadata entry");
            manifest->unknown_count++;
            continue;
        }
        if (target->required_min_size == 0) {
            target->blocked = OG_TRUE;
            (void)strcpy_s(target->blocked_reason, sizeof(target->blocked_reason),
                "required target size unknown from control metadata and payload page headers");
            manifest->unknown_count++;
        }
    }
}

static status_t ogbak_scheme_d_publish_target_manifest(const char *path, const char *backupset_sha256,
    ogbak_scheme_d_target_manifest_t *manifest, char *failure_reason, uint32 failure_reason_size)
{
    char tmp_path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (path == NULL || snprintf_s(tmp_path, sizeof(tmp_path), sizeof(tmp_path) - 1, "%s.tmp", path) == -1) {
        return OG_ERROR;
    }
    FILE *fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "Scheme D target manifest create failed path=%s errno=%d\n", tmp_path, errno);
        return OG_ERROR;
    }
    const char *status = manifest->unknown_count == 0 ? "READY" : "BLOCKED";
    (void)fprintf(fp,
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"scheme_d\": true,\n"
        "  \"mode\": \"target_manifest_only\",\n"
        "  \"backupset_sha256\": \"%s\",\n"
        "  \"status\": \"%s\",\n"
        "  \"targets\": [\n",
        backupset_sha256, status);
    for (uint32 i = 0; i < manifest->target_count; i++) {
        ogbak_scheme_d_target_size_t *target = &manifest->targets[i];
        (void)fprintf(fp,
            "%s    {\"path\":\"%s\",\"type\":\"%s\",\"file_id\":%u,\"node_id\":%u,"
            "\"control_size\":%llu,\"payload_max_end\":%llu,\"header_min_size\":0,"
            "\"required_min_size\":%llu,\"payload_full_coverage\":%s,\"payload_present\":%s,"
            "\"create_required\":%s,\"range_count\":%u,\"unique_page_count\":%u,"
            "\"total_payload_bytes\":%llu,\"status\":\"%s\",\"blocked_reason\":\"%s\"}",
            i == 0 ? "" : ",\n", target->path, target->type, target->file_id, target->node_id,
            target->control_size, target->payload_max_end, target->required_min_size,
            target->payload_full_coverage == OG_TRUE ? "true" : "false",
            target->payload_present == OG_TRUE ? "true" : "false",
            target->create_required == OG_TRUE ? "true" : "false", target->range_count,
            target->unique_page_count, target->total_payload_bytes,
            target->blocked == OG_TRUE ? "BLOCKED" : "READY", target->blocked_reason);
    }
    (void)fprintf(fp, "\n  ],\n  \"unknown_targets\": [");
    bool32 first = OG_TRUE;
    for (uint32 i = 0; i < manifest->target_count; i++) {
        ogbak_scheme_d_target_size_t *target = &manifest->targets[i];
        if (target->blocked != OG_TRUE) {
            continue;
        }
        (void)fprintf(fp, "%s\"%s\"", first == OG_TRUE ? "" : ",", target->path);
        first = OG_FALSE;
    }
    (void)fprintf(fp, "],\n  \"unknown_target_count\": %u\n}\n", manifest->unknown_count);
    int fd = fileno(fp);
    if (fflush(fp) != 0 || fsync(fd) != 0 || fclose(fp) != 0 || rename(tmp_path, path) != 0) {
        (void)remove(tmp_path);
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "Scheme D target manifest publish failed path=%s errno=%d\n", path, errno);
        return OG_ERROR;
    }
    char hash[OGBAK_SCHEME_D_HASH_HEX_LEN + 1] = {0};
    if (ogbak_scheme_d_sha256_file(path, hash, sizeof(hash), failure_reason, failure_reason_size) == OG_SUCCESS) {
        printf("[ogbackup]scheme_d=true target_manifest_path=%s target_manifest_sha256=%s status=%s targets=%u "
               "unknown_targets=%u\n", path, hash, status, manifest->target_count, manifest->unknown_count);
    }
    return manifest->unknown_count == 0 ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_scheme_d_export_target_manifest(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size)
{
    ogbak_scheme_d_target_manifest_t *manifest =
        (ogbak_scheme_d_target_manifest_t *)malloc(sizeof(ogbak_scheme_d_target_manifest_t));
    if (manifest == NULL || memset_s(manifest, sizeof(*manifest), 0, sizeof(*manifest)) != EOK) {
        CM_FREE_PTR(manifest);
        return OG_ERROR;
    }
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset != OG_TRUE || plan->files[i]->type != OGBAK_RESTORE_FILE_CONTROL ||
            ogbak_restore_is_latest_control_file(plan, i) != OG_TRUE) {
            continue;
        }
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_src(param->backup_dir.str, plan->files[i]->src, src_path) != OG_SUCCESS) {
            return OG_ERROR;
        }
        char *buf = NULL;
        uint64 size = 0;
        uint32 page_count = 0;
        char decoded_ctrl_path[OG_MAX_FILE_PATH_LENGH] = {0};
        uint64 control_payload_size = plan->files[i]->size;
        if (ogbak_restore_decode_payload_to_temp(param, plan, plan->files[i], src_path, decoded_ctrl_path,
            sizeof(decoded_ctrl_path), &control_payload_size) != OG_SUCCESS ||
            bak_offline_ctrl_load_buffer(decoded_ctrl_path, control_payload_size, &buf, &size, &page_count) !=
            OG_SUCCESS) {
            if (decoded_ctrl_path[0] != '\0') {
                (void)remove(decoded_ctrl_path);
            }
            return OG_ERROR;
        }
        bak_offline_ctrl_path_map_t path_map;
        status_t status = ogbak_restore_build_ctrl_path_map(param, plan, &path_map);
        if (status == OG_SUCCESS) {
            const char *target_dir = param->target_dir.str == NULL ? param->backup_dir.str : param->target_dir.str;
            status = bak_offline_ctrl_build_path_map(buf, size, target_dir, &path_map);
        }
        ogbak_offline_backup_t *ctrl_bak = ogbak_restore_find_plan_backup(plan, plan->files[i]->backup_id);
        if (status == OG_SUCCESS) {
            status = ogbak_scheme_d_collect_control_file_targets(manifest,
                ctrl_bak == NULL ? NULL : ctrl_bak->control_files, control_payload_size);
        }
        if (status == OG_SUCCESS) {
            status = ogbak_scheme_d_collect_ctrl_targets(manifest, &path_map);
        }
        if (status == OG_SUCCESS) {
            status_t map_status = ogbak_restore_apply_original_targets_from_map(plan, &path_map);
            if (map_status != OG_SUCCESS) {
                printf("[ogbackup]scheme_d=true target_manifest_only continuing with BLOCKED partial manifest "
                       "after control-to-payload DSS target mapping failed\n");
            }
        }
        ogbak_restore_free_ctrl_path_map(&path_map);
        bak_offline_ctrl_free_buffer(buf);
        (void)remove(decoded_ctrl_path);
        if (status != OG_SUCCESS) {
            CM_FREE_PTR(manifest);
            return OG_ERROR;
        }
        break;
    }
    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->type != OGBAK_RESTORE_FILE_DATA || file->from_backupset != OG_TRUE) {
            continue;
        }
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_src(param->backup_dir.str, file->src, src_path) != OG_SUCCESS) {
            CM_FREE_PTR(manifest);
            return OG_ERROR;
        }
        ogbak_scheme_d_target_size_t *target = ogbak_scheme_d_find_data_target_by_file(manifest,
            file->file_id, file->target);
        if (target == NULL ||
            ogbak_scheme_d_scan_data_payload(param, plan, src_path, file, target, NULL, 0, 0, failure_reason,
            failure_reason_size) != OG_SUCCESS) {
            CM_FREE_PTR(manifest);
            return OG_ERROR;
        }
        if (target->control_size != 0 && target->payload_max_end > target->control_size) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "Scheme D target manifest rejects payload beyond control size target=%s payload_max_end=%llu "
                "control_size=%llu\n", target->path, target->payload_max_end, target->control_size);
            CM_FREE_PTR(manifest);
            return OG_ERROR;
        }
    }
    ogbak_scheme_d_finalize_target_manifest(manifest);
    char backupset_sha[OGBAK_SCHEME_D_HASH_HEX_LEN + 1] = {0};
    if (ogbak_scheme_d_sha256_file(param->backup_dir.str, backupset_sha, sizeof(backupset_sha), failure_reason,
        failure_reason_size) != OG_SUCCESS) {
        CM_FREE_PTR(manifest);
        return OG_ERROR;
    }
    status_t status = ogbak_scheme_d_publish_target_manifest(param->dss_target_manifest_out.str, backupset_sha, manifest,
        failure_reason, failure_reason_size);
    CM_FREE_PTR(manifest);
    return status;
}

static status_t ogbak_restore_init_dss_device_from_env(void)
{
#ifdef CMS_UT_TEST
    if (g_scheme_d_init_dss_hook != NULL) {
        return g_scheme_d_init_dss_hook();
    }
#endif
    return bak_offline_init_dss_device_from_env();
}

static status_t ogbak_restore_scheme_d_append_control_plan(const char *control_files,
    const ogbak_scheme_d_evidence_t *evidence, uint64 payload_size, ogbak_scheme_d_plan_t *scheme_plan,
    char *failure_reason, uint32 failure_reason_size)
{
    if (control_files == NULL || control_files[0] == '\0') {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "Scheme D P0 cannot plan control restore because CONTROL_FILES is empty\n");
        return OG_ERROR;
    }
    char copy[OG_MAX_CONFIG_LINE_SIZE] = {0};
    if (strlen(control_files) >= sizeof(copy) || strcpy_s(copy, sizeof(copy), control_files) != EOK) {
        return OG_ERROR;
    }
    char *save = NULL;
    char *token = strtok_r(copy, ",", &save);
    uint32 count = 0;
    while (token != NULL) {
        char path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_normalize_control_file_token(token, token + strlen(token), path, sizeof(path),
            control_files) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (path[0] == '+') {
            uint64 size = 0;
            uint64 written_size = 0;
            if (ogbak_scheme_d_vg_allowed(evidence, path) != OG_TRUE) {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "Scheme D control target VG is not listed in evidence: %s\n", path);
                return OG_ERROR;
            }
            if (ogbak_restore_scheme_d_stat_target(DEV_TYPE_RAW, path, &size, &written_size) != OG_SUCCESS) {
                const char *last_dss_error = bak_offline_get_last_dss_error();
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "Scheme D control target stat failed before first write: %s\n",
                    last_dss_error == NULL ? path : last_dss_error);
                return OG_ERROR;
            }
            if (payload_size > size) {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "Scheme D P0 existing-file writer rejects control extend: target=%s payload=%llu existing_size=%llu\n",
                    path, payload_size, size);
                return OG_ERROR;
            }
            if (ogbak_scheme_d_append_plan_entry(scheme_plan, path, "control", 0, payload_size, size, written_size,
                NULL, failure_reason, failure_reason_size) != OG_SUCCESS) {
                return OG_ERROR;
            }
            count++;
        }
        token = strtok_r(NULL, ",", &save);
    }
    if (count == 0) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "Scheme D P0 did not find DSS control targets in CONTROL_FILES=%s\n", control_files);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_scheme_d_build_write_plan(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    const ogbak_scheme_d_evidence_t *evidence, const ogbak_scheme_d_provider_t *provider,
    ogbak_scheme_d_plan_t *scheme_plan, char *failure_reason, uint32 failure_reason_size)
{
    if (ogbak_restore_scheme_d_reject_unsupported(plan, failure_reason, failure_reason_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (ogbak_scheme_d_begin_plan(param->dss_write_plan_out.str, evidence, provider, scheme_plan,
        failure_reason, failure_reason_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
    status_t status = OG_SUCCESS;
    for (uint32 i = 0; i < plan->file_count; i++) {
        ogbak_offline_file_t *file = plan->files[i];
        if (file->type == OGBAK_RESTORE_FILE_CONTROL) {
            ogbak_offline_backup_t *ctrl_bak = ogbak_restore_find_plan_backup(plan, file->backup_id);
            char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
            char decoded_ctrl_path[OG_MAX_FILE_PATH_LENGH] = {0};
            uint64 control_payload_size = file->size;
            if (ogbak_restore_resolve_src(param->backup_dir.str, file->src, src_path) != OG_SUCCESS ||
                ogbak_restore_decode_payload_to_temp(param, plan, file, src_path, decoded_ctrl_path,
                sizeof(decoded_ctrl_path), &control_payload_size) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
            (void)remove(decoded_ctrl_path);
            status = ogbak_restore_scheme_d_append_control_plan(ctrl_bak == NULL ? NULL : ctrl_bak->control_files,
                evidence, control_payload_size, scheme_plan, failure_reason, failure_reason_size);
            if (status != OG_SUCCESS) {
                break;
            }
            continue;
        }
        if (file->type == OGBAK_RESTORE_FILE_DATA) {
            if (file->target[0] != '+' || ogbak_scheme_d_vg_allowed(evidence, file->target) != OG_TRUE) {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "Scheme D datafile target is not an allowed DSS path: %s\n", file->target);
                status = OG_ERROR;
                break;
            }
            uint64 existing_size = 0;
            uint64 written_size = 0;
            if (ogbak_restore_scheme_d_stat_target(DEV_TYPE_RAW, file->target, &existing_size,
                &written_size) != OG_SUCCESS) {
                const char *last_dss_error = bak_offline_get_last_dss_error();
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "Scheme D datafile target stat failed before first write: %s\n",
                    last_dss_error == NULL ? file->target : last_dss_error);
                status = OG_ERROR;
                break;
            }
            ogbak_scheme_d_target_size_t target;
            if (memset_s(&target, sizeof(target), 0, sizeof(target)) != EOK ||
                strcpy_s(target.path, sizeof(target.path), file->target) != EOK ||
                strcpy_s(target.type, sizeof(target.type), "datafile") != EOK) {
                status = OG_ERROR;
                break;
            }
            target.file_id = file->file_id;
            target.control_size = existing_size;
            target.required_min_size = existing_size;
            char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
            if (ogbak_restore_resolve_src(param->backup_dir.str, file->src, src_path) != OG_SUCCESS) {
                status = OG_ERROR;
                break;
            }
            status = ogbak_scheme_d_scan_data_payload(param, plan, src_path, file, &target, NULL, existing_size,
                written_size, failure_reason, failure_reason_size);
            if (status != OG_SUCCESS) {
                break;
            }
            if (target.payload_max_end > existing_size) {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "Scheme D P0 existing-file writer rejects extend: target=%s payload_max_end=%llu "
                    "existing_size=%llu\n", file->target, target.payload_max_end, existing_size);
                status = OG_ERROR;
                break;
            }
            status = ogbak_scheme_d_scan_data_payload(param, plan, src_path, file, &target, scheme_plan,
                existing_size, written_size, failure_reason, failure_reason_size);
            if (status != OG_SUCCESS) {
                break;
            }
        }
    }
    if (status == OG_SUCCESS) {
        status = ogbak_scheme_d_finish_plan(scheme_plan, failure_reason, failure_reason_size);
    } else {
        ogbak_scheme_d_abort_plan(scheme_plan);
    }
    return status;
}

typedef struct st_ogbak_deferred_ctrl {
    bak_offline_ctrl_path_map_t path_map;
    bak_offline_ctrl_restore_opts_t opts;
    bak_offline_ctrl_restore_result_t result;
    ogbak_offline_file_t *file;
    char src_path[OG_MAX_FILE_PATH_LENGH];
    char decoded_path[OG_MAX_FILE_PATH_LENGH];
    uint64 payload_size;
    bool32 has_path_map;
} ogbak_deferred_ctrl_t;

/* The command is single-threaded; keep the preflight-frozen control plan
 * available to the execution helper without widening the unit-test hook ABI. */
static ogbak_deferred_ctrl_t *g_ogbak_preflight_deferred_ctrl = NULL;

static void ogbak_restore_release_deferred_ctrl(ogbak_deferred_ctrl_t *ctrl)
{
    if (ctrl == NULL) {
        return;
    }
    if (ctrl->decoded_path[0] != '\0') {
        (void)remove(ctrl->decoded_path);
    }
    if (ctrl->has_path_map == OG_TRUE) {
        ogbak_restore_free_ctrl_path_map(&ctrl->path_map);
    }
    (void)memset_s(ctrl, sizeof(*ctrl), 0, sizeof(*ctrl));
}

static status_t ogbak_restore_stage_deferred_ctrl(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    ogbak_deferred_ctrl_t *ctrl, char *failure_reason, uint32 failure_reason_size)
{
    if (memset_s(ctrl, sizeof(*ctrl), 0, sizeof(*ctrl)) != EOK) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset == OG_TRUE &&
            plan->files[i]->type == OGBAK_RESTORE_FILE_CONTROL &&
            ogbak_restore_is_latest_control_file(plan, i) == OG_TRUE) {
            ctrl->file = plan->files[i];
            break;
        }
    }
    if (ctrl->file == NULL ||
        ogbak_restore_resolve_src(param->backup_dir.str, ctrl->file->src, ctrl->src_path) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "selected backup chain has no readable final control backup piece\n");
        return OG_ERROR;
    }

    ctrl->opts.target_dir = param->target_dir.str;
    ctrl->opts.reject_dss_to_local = ogbak_restore_storage_dss(param) == OG_TRUE ? OG_FALSE : OG_TRUE;
    ctrl->opts.dry_run = OG_TRUE;
    ctrl->opts.storage_mode = ogbak_restore_storage_dss(param) == OG_TRUE ?
        BAK_OFFLINE_RESTORE_STORAGE_DSS : BAK_OFFLINE_RESTORE_STORAGE_LOCAL;
    ogbak_offline_backup_t *ctrl_bak = ogbak_restore_find_plan_backup(plan, ctrl->file->backup_id);
    ctrl->opts.control_files = ctrl_bak == NULL ? NULL : ctrl_bak->control_files;
    if (param->is_in_place == OG_TRUE &&
        ogbak_restore_validate_original_control_targets(param, ctrl->opts.control_files) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "final control image has invalid original CONTROL_FILES targets\n");
        return OG_ERROR;
    }
    if (ogbak_restore_path_map_auto(param) == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE ||
        param->is_in_place == OG_TRUE) {
        if (ogbak_restore_build_ctrl_path_map(param, plan, &ctrl->path_map) != OG_SUCCESS) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "build immutable restore target plan failed before target mutation\n");
            return OG_ERROR;
        }
        ctrl->has_path_map = OG_TRUE;
        ctrl->opts.path_map = &ctrl->path_map;
        ctrl->opts.rewrite_paths = OG_TRUE;
    }
    ctrl->payload_size = ctrl->file->size;
    if (ogbak_restore_decode_payload_to_temp(param, plan, ctrl->file, ctrl->src_path,
        ctrl->decoded_path, sizeof(ctrl->decoded_path), &ctrl->payload_size) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "authenticate/decode final control backup piece failed before target mutation: %s\n", ctrl->src_path);
        ogbak_restore_release_deferred_ctrl(ctrl);
        return OG_ERROR;
    }
    ctrl->opts.expected_payload_size = ctrl->payload_size;
    if (bak_offline_restore_ctrlfile(ctrl->decoded_path, &ctrl->opts, &ctrl->result) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "parse/validate final control image failed before target mutation: %s\n", ctrl->src_path);
        ogbak_restore_release_deferred_ctrl(ctrl);
        return OG_ERROR;
    }
    if (ctrl->has_path_map == OG_TRUE &&
        ogbak_restore_validate_original_write_plan(plan, &ctrl->path_map) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "restore write plan conflicts with final control metadata\n");
        ogbak_restore_release_deferred_ctrl(ctrl);
        return OG_ERROR;
    }
    printf("[ogbackup]final control image parsed and deferred: source=%s size=%llu control_targets=%s\n",
        ctrl->src_path, ctrl->payload_size,
        ctrl->opts.control_files == NULL ? "<missing>" : ctrl->opts.control_files);
    return OG_SUCCESS;
}

static status_t ogbak_restore_prepare_deferred_targets(ogbak_deferred_ctrl_t *ctrl,
    char *failure_reason, uint32 failure_reason_size)
{
    if (ctrl->has_path_map != OG_TRUE) {
        return OG_SUCCESS;
    }
    if (bak_offline_ctrl_prepare_non_control_files(&ctrl->path_map, &ctrl->result) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "prepare/create/truncate non-control restore targets failed\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_probe_local_target(const char *path, uint64 expected_size)
{
    if (path == NULL || path[0] != '/' || strlen(path) >= OG_MAX_FILE_PATH_LENGH ||
        bak_offline_check_no_symlink(path, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }
    char probe[OG_MAX_FILE_PATH_LENGH] = {0};
    if (strcpy_s(probe, sizeof(probe), path) != EOK) {
        return OG_ERROR;
    }
    struct stat st;
    uint64 existing_size = 0;
    if (lstat(probe, &st) == 0) {
        if (!S_ISREG(st.st_mode) || access(probe, W_OK) != 0) {
            printf("[ogbackup]local in-place target is not a writable regular file: %s\n", path);
            return OG_ERROR;
        }
        existing_size = (uint64)st.st_size;
    } else if (errno == ENOENT) {
        for (;;) {
            char *slash = strrchr(probe, '/');
            if (slash == NULL) {
                return OG_ERROR;
            }
            *slash = '\0';
            if (probe[0] == '\0') {
                (void)strcpy_s(probe, sizeof(probe), "/");
            }
            if (lstat(probe, &st) == 0) {
                if (!S_ISDIR(st.st_mode) || access(probe, W_OK | X_OK) != 0) {
                    printf("[ogbackup]local in-place target parent is not writable: target=%s parent=%s\n",
                        path, probe);
                    return OG_ERROR;
                }
                break;
            }
            if (errno != ENOENT || strcmp(probe, "/") == 0) {
                return OG_ERROR;
            }
        }
    } else {
        printf("[ogbackup]stat local in-place target failed: %s errno=%d (%s)\n",
            path, errno, strerror(errno));
        return OG_ERROR;
    }

    struct statvfs fs;
    if (statvfs(probe, &fs) != 0) {
        printf("[ogbackup]inspect local target free space failed: %s errno=%d (%s)\n",
            probe, errno, strerror(errno));
        return OG_ERROR;
    }
    uint64 growth = expected_size > existing_size ? expected_size - existing_size : 0;
    uint64 available = (uint64)fs.f_bavail * (uint64)fs.f_frsize;
    if (growth > available) {
        printf("[ogbackup]insufficient local target space: target=%s expected=%llu existing=%llu "
               "growth=%llu available=%llu\n",
            path, expected_size, existing_size, growth, available);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_probe_local_inplace_plan(ogbak_deferred_ctrl_t *ctrl)
{
    if (ctrl == NULL || ctrl->has_path_map != OG_TRUE || ctrl->path_map.items == NULL ||
        ctrl->opts.control_files == NULL) {
        return OG_ERROR;
    }
    for (uint32 i = 0; i < ctrl->path_map.item_count; i++) {
        bak_offline_ctrl_path_map_item_t *item = &ctrl->path_map.items[i];
        uint64 expected_size = item->target_size != 0 ? item->target_size : item->source_size;
        if (ogbak_restore_probe_local_target(item->target_path, expected_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    char control_files[OG_MAX_CONFIG_LINE_SIZE] = {0};
    if (strcpy_s(control_files, sizeof(control_files), ctrl->opts.control_files) != EOK) {
        return OG_ERROR;
    }
    char *save = NULL;
    char *token = strtok_r(control_files, ",", &save);
    uint32 count = 0;
    while (token != NULL) {
        char path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (count >= BAK_OFFLINE_CTRL_FILE_COUNT ||
            ogbak_restore_normalize_control_file_token(token, token + strlen(token), path, sizeof(path),
            ctrl->opts.control_files) != OG_SUCCESS ||
            ogbak_restore_probe_local_target(path, ctrl->payload_size) != OG_SUCCESS) {
            return OG_ERROR;
        }
        count++;
        token = strtok_r(NULL, ",", &save);
    }
    printf("[ogbackup]local in-place target preflight complete: mapped_targets=%u control_targets=%u\n",
        ctrl->path_map.item_count, count);
    return count > 0 ? OG_SUCCESS : OG_ERROR;
}

static status_t ogbak_restore_commit_deferred_ctrl(ogbak_deferred_ctrl_t *ctrl,
    char *failure_reason, uint32 failure_reason_size)
{
    ctrl->opts.dry_run = OG_FALSE;
    ctrl->opts.control_commit_only = OG_TRUE;
    if (bak_offline_restore_ctrlfile(ctrl->decoded_path, &ctrl->opts, &ctrl->result) != OG_SUCCESS) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "final control commit failed after non-control files were persisted\n");
        return OG_ERROR;
    }
    printf("[ogbackup]deferred control commit complete: copies=%u size=%llu\n",
        ctrl->result.raw_ctrl_file_count, ctrl->result.raw_ctrl_file_size);
    return OG_SUCCESS;
}

static status_t ogbak_restore_execute_files(ogbak_param_t *param, ogbak_offline_plan_t *plan,
    char *failure_reason, uint32 failure_reason_size)
{
    ogbak_deferred_ctrl_t *deferred_ctrl = g_ogbak_preflight_deferred_ctrl;
    bool32 has_deferred_ctrl = OG_FALSE;
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset == OG_TRUE &&
            plan->files[i]->type == OGBAK_RESTORE_FILE_CONTROL) {
            has_deferred_ctrl = OG_TRUE;
            break;
        }
    }
    if (has_deferred_ctrl != OG_TRUE && param->is_in_place == OG_TRUE) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "in-place restore requires a final control backup piece\n");
        return OG_ERROR;
    }
    if (has_deferred_ctrl == OG_TRUE &&
        (deferred_ctrl == NULL || deferred_ctrl->file == NULL || deferred_ctrl->decoded_path[0] == '\0' ||
        ((param->is_in_place == OG_TRUE || ogbak_restore_storage_dss(param) == OG_TRUE ||
        ogbak_restore_path_map_auto(param) == OG_TRUE) && deferred_ctrl->has_path_map != OG_TRUE))) {
        ogbak_restore_set_failure(failure_reason, failure_reason_size,
            "validated immutable control/write plan is unavailable at execution time\n");
        return OG_ERROR;
    }
    if (param->is_dry_run == OG_TRUE) {
        return OG_SUCCESS;
    }
    if (has_deferred_ctrl == OG_TRUE &&
        ogbak_restore_prepare_deferred_targets(deferred_ctrl, failure_reason,
        failure_reason_size) != OG_SUCCESS) {
        return OG_ERROR;
    }
#define OGBAK_DEFERRED_EXEC_FAIL() do { \
        return OG_ERROR; \
    } while (0)
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset == OG_TRUE &&
            plan->files[i]->type == OGBAK_RESTORE_FILE_CONTROL) {
            printf("[ogbackup]defer control backup piece until every non-control file is persisted: %s\n",
                plan->files[i]->src);
            continue;
        }
        char src_path[OG_MAX_FILE_PATH_LENGH] = {0};
        char dst_path[OG_MAX_FILE_PATH_LENGH] = {0};
        if (ogbak_restore_resolve_src(param->backup_dir.str, plan->files[i]->src, src_path) != OG_SUCCESS) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "resolve restore path failed for source %s target %s\n",
                plan->files[i]->src, plan->files[i]->target);
            OGBAK_DEFERRED_EXEC_FAIL();
        }
        if ((ogbak_restore_storage_dss(param) == OG_TRUE || param->is_in_place == OG_TRUE) &&
            plan->files[i]->type != OGBAK_RESTORE_FILE_CONTROL) {
            if (strcpy_s(dst_path, sizeof(dst_path), plan->files[i]->target) != EOK) {
                OGBAK_DEFERRED_EXEC_FAIL();
            }
        } else if (ogbak_restore_resolve_target(param->target_dir.str, plan->files[i]->target,
            dst_path) != OG_SUCCESS) {
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "resolve restore path failed for source %s target %s\n",
                plan->files[i]->src, plan->files[i]->target);
            OGBAK_DEFERRED_EXEC_FAIL();
        }
        if (plan->files[i]->from_backupset == OG_TRUE && plan->files[i]->type == OGBAK_RESTORE_FILE_DATA) {
            bak_offline_page_apply_opts_t opts = {0};
            char decoded_data_path[OG_MAX_FILE_PATH_LENGH] = {0};
            uint64 decoded_payload_size = plan->files[i]->size;
            opts.expected_file_id = plan->files[i]->file_id;
            opts.backup_level = plan->files[i]->backup_level;
            opts.expected_payload_size = plan->files[i]->size;
            opts.verify_page_checksum = OG_TRUE;
            opts.skip_empty_pages = plan->files[i]->backup_level == 0 ? OG_TRUE : OG_FALSE;
            opts.target_device_type = ogbak_restore_storage_dss(param) == OG_TRUE ? DEV_TYPE_RAW : DEV_TYPE_FILE;
            if (param->dss_scheme_d == OG_TRUE) {
                opts.write_guard = ogbak_scheme_d_runtime_write_guard;
            }
            /* Authenticate/decode the complete payload before opening the restore target. */
            status_t status = ogbak_restore_decode_payload_to_temp(param, plan, plan->files[i], src_path,
                decoded_data_path, sizeof(decoded_data_path), &decoded_payload_size);
            if (status == OG_SUCCESS) {
                opts.expected_payload_size = decoded_payload_size;
                status = bak_offline_apply_data_pages(decoded_data_path, dst_path, &opts);
            }
            if (decoded_data_path[0] != '\0') {
                (void)remove(decoded_data_path);
            }
            if (status != OG_SUCCESS) {
                const char *last_dss_error = ogbak_restore_storage_dss(param) == OG_TRUE ?
                    bak_offline_get_last_dss_error() : NULL;
                if (last_dss_error != NULL) {
                    ogbak_restore_set_failure(failure_reason, failure_reason_size,
                        "DSS datafile restore failed: %s\n", last_dss_error);
                } else {
                    ogbak_restore_set_failure(failure_reason, failure_reason_size,
                        "apply datafile pages failed, backup file=%s, target file=%s\n", src_path, dst_path);
                }
                OGBAK_DEFERRED_EXEC_FAIL();
            }
            continue;
        }
        const char *stream_src = src_path;
        char decoded_stream_path[OG_MAX_FILE_PATH_LENGH] = {0};
        uint64 decoded_stream_size = plan->files[i]->size;
        if (plan->files[i]->from_backupset == OG_TRUE &&
            (plan->files[i]->type == OGBAK_RESTORE_FILE_LOG ||
            plan->files[i]->type == OGBAK_RESTORE_FILE_ARCHIVE)) {
            if (ogbak_restore_decode_payload_to_temp(param, plan, plan->files[i], src_path,
                decoded_stream_path, sizeof(decoded_stream_path), &decoded_stream_size) != OG_SUCCESS) {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "decode redo/archive backup payload failed, source=%s\n", src_path);
                OGBAK_DEFERRED_EXEC_FAIL();
            }
            stream_src = decoded_stream_path;
        }
        status_t stream_status = bak_offline_write_device_stream(stream_src, dst_path,
            ogbak_restore_storage_dss(param) == OG_TRUE ? DEV_TYPE_RAW : DEV_TYPE_FILE);
        if (decoded_stream_path[0] != '\0') {
            (void)remove(decoded_stream_path);
        }
        if (stream_status != OG_SUCCESS) {
            const char *last_dss_error = ogbak_restore_storage_dss(param) == OG_TRUE ?
                bak_offline_get_last_dss_error() : NULL;
            if (last_dss_error != NULL) {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "DSS file restore failed: %s\n", last_dss_error);
            } else {
                ogbak_restore_set_failure(failure_reason, failure_reason_size,
                    "copy backup file failed, source=%s, target=%s, errno=%d (%s)\n",
                    src_path, dst_path, errno, strerror(errno));
            }
            OGBAK_DEFERRED_EXEC_FAIL();
        }
        if (ogbak_restore_storage_dss(param) != OG_TRUE &&
            plan->files[i]->mode != 0 && chmod(dst_path, (mode_t)plan->files[i]->mode) != 0) {
            printf("[ogbackup]chmod restored file %s failed, error %d\n", dst_path, errno);
            ogbak_restore_set_failure(failure_reason, failure_reason_size,
                "chmod restored file failed, target=%s, errno=%d (%s)\n", dst_path, errno, strerror(errno));
            OGBAK_DEFERRED_EXEC_FAIL();
        }
    }
    status_t commit_status = has_deferred_ctrl == OG_TRUE ?
        ogbak_restore_commit_deferred_ctrl(deferred_ctrl, failure_reason, failure_reason_size) : OG_SUCCESS;
#undef OGBAK_DEFERRED_EXEC_FAIL
    return commit_status;
}

static bool32 ogbak_restore_is_empty_datafile_piece(ogbak_offline_file_t *file)
{
    return (file->from_backupset == OG_TRUE && file->type == OGBAK_RESTORE_FILE_DATA && file->size == 0) ?
        OG_TRUE : OG_FALSE;
}

static bool32 ogbak_restore_cluster_validation_incomplete(ogbak_offline_plan_t *plan)
{
    for (uint32 i = 0; i < plan->chain_count; i++) {
        if (plan->chain[i]->from_backupset == OG_TRUE && plan->chain[i]->cluster_id == 0) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t ogbak_restore_remove_marker(const char *target_dir, const char *name)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (ogbak_restore_join_path(target_dir, name, path, sizeof(path)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (!cm_file_exist(path)) {
        return OG_SUCCESS;
    }
    if (cm_remove_file(path) != OG_SUCCESS) {
        printf("[ogbackup]remove restore marker %s failed\n", path);
        return OG_ERROR;
    }
    int32 dir_fd = open(target_dir, O_RDONLY | O_BINARY);
    if (dir_fd < 0 || fsync(dir_fd) != 0) {
        if (dir_fd >= 0) {
            (void)close(dir_fd);
        }
        printf("[ogbackup]persist restore marker removal in %s failed, errno=%d (%s)\n",
            target_dir, errno, strerror(errno));
        return OG_ERROR;
    }
    (void)close(dir_fd);
    return OG_SUCCESS;
}

static bool32 ogbak_restore_marker_exists(const char *target_dir, const char *name)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    if (ogbak_restore_join_path(target_dir, name, path, sizeof(path)) != OG_SUCCESS) {
        return OG_TRUE;
    }
    return cm_file_exist(path) ? OG_TRUE : OG_FALSE;
}

static status_t ogbak_restore_check_existing_markers(ogbak_param_t *param)
{
    if (param->is_dry_run == OG_TRUE || !cm_dir_exist(param->target_dir.str)) {
        return OG_SUCCESS;
    }
    if (ogbak_restore_marker_exists(param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED) == OG_TRUE) {
        if (param->is_force == OG_TRUE) {
            printf("[ogbackup]--force restarts failed restore from scratch; no file or piece is resumed/skipped\n");
            return OG_SUCCESS;
        }
        printf("[ogbackup]target-dir %s contains %s from a previous failed offline restore; "
               "clean the directory or remove the marker after manual inspection\n",
               param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED);
        return OG_ERROR;
    }
    if (ogbak_restore_marker_exists(param->target_dir.str, OGBAK_RESTORE_MARKER_IN_PROGRESS) == OG_TRUE) {
        if (param->is_force == OG_TRUE) {
            printf("[ogbackup]--force restarts incomplete restore from scratch; every planned target is prepared again\n");
            return OG_SUCCESS;
        }
        printf("[ogbackup]target-dir %s contains %s from an incomplete offline restore; "
               "clean the directory before retrying\n",
               param->target_dir.str, OGBAK_RESTORE_MARKER_IN_PROGRESS);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t ogbak_restore_write_complete_marker(ogbak_param_t *param, ogbak_offline_plan_t *plan)
{
    char content[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
    time_t now = time(NULL);
    int32 ret = snprintf_s(content, sizeof(content), sizeof(content) - 1,
        "status=FILE_PHASE_COMPLETE\n"
        "offline restore file phase completed; start ogracd and let the database kernel perform recovery before OPEN\n"
        "completed_at=%lld\n"
        "backup_dir=%s\n"
        "marker_dir=%s\n"
        "in_place=%s\n"
        "chain_count=%u\n"
        "end_lsn=%llu\n",
        (long long)now, param->backup_dir.str, param->target_dir.str,
        param->is_in_place == OG_TRUE ? "true" : "false", plan->chain_count,
        plan->chain_count == 0 ? 0 : plan->chain[plan->chain_count - 1]->end_lsn);
    if (ret == -1) {
        return OG_ERROR;
    }
    size_t used = strlen(content);
    for (uint32 i = 0; i < plan->chain_count && used < sizeof(content) - 1; i++) {
        ret = snprintf_s(content + used, sizeof(content) - used, sizeof(content) - used - 1,
            "chain.%u=%s\n", i + 1, plan->chain[i]->id);
        if (ret == -1) {
            return OG_ERROR;
        }
        used += (size_t)ret;
    }
    uint32 mapping_count = 0;
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->type == OGBAK_RESTORE_FILE_DATA ||
            plan->files[i]->type == OGBAK_RESTORE_FILE_LOG ||
            plan->files[i]->type == OGBAK_RESTORE_FILE_ARCHIVE) {
            mapping_count++;
        }
    }
    ret = snprintf_s(content + used, sizeof(content) - used, sizeof(content) - used - 1,
        "path_mapping=%s\n"
        "control_rewrite=%s\n"
        "mapping_count=%u\n",
        param->is_in_place == OG_TRUE ? "original/no-remap" : ogbak_restore_path_map_mode(param),
        (ogbak_restore_path_map_auto(param) == OG_TRUE || param->is_in_place == OG_TRUE) ? "done" : "disabled",
        mapping_count);
    if (ret == -1) {
        return OG_ERROR;
    }
    return bak_offline_write_marker(param->target_dir.str, OGBAK_RESTORE_MARKER_COMPLETE, content);
}

static void ogbak_restore_print_dss_inplace_targets(ogbak_offline_plan_t *plan)
{
    char printed[OG_MAX_CONFIG_LINE_SIZE] = {0};
    uint32 used = 0;
    bool32 any = OG_FALSE;

    for (uint32 i = 0; i < plan->file_count; i++) {
        const char *target = plan->files[i]->target;
        if (target == NULL || target[0] != '+') {
            continue;
        }
        uint32 len = 0;
        while (target[len] != '\0' && target[len] != '/') {
            len++;
        }
        if (len == 0 || len >= OG_NAME_BUFFER_SIZE || used + len + 2 >= sizeof(printed)) {
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
        errno_t ret = memcpy_s(printed + used, sizeof(printed) - used, target, len);
        if (ret != EOK) {
            return;
        }
        used += len;
        printed[used] = '\0';
        any = OG_TRUE;
    }

    printf("[ogbackup]  target DSS paths preserved=%s\n", any == OG_TRUE ? printed : "<unknown>");
}

static void ogbak_restore_print_report(ogbak_param_t *param, ogbak_offline_manifest_t *manifest,
    ogbak_offline_plan_t *plan)
{
    printf("[ogbackup]offline restore report\n");
    printf("[ogbackup]  operation: %s\n", param->is_dry_run == OG_TRUE ? "dry-run" : "restore");
    printf("[ogbackup]  backup-dir: %s\n", param->backup_dir.str);
    printf("[ogbackup]  restore location: %s\n",
        param->is_in_place == OG_TRUE ? "original paths from final control image" : param->target_dir.str);
    printf("[ogbackup]  fail-stop marker dir: %s\n", param->target_dir.str);
    printf("[ogbackup]  dry-run: %s\n", param->is_dry_run == OG_TRUE ? "true" : "false");
    printf("[ogbackup]  storage mode: %s\n", ogbak_restore_storage_mode_name(param));
    printf("[ogbackup]  path mapping mode: %s\n",
        param->is_in_place == OG_TRUE ? "original/no-remap" : ogbak_restore_path_map_mode(param));
    if (ogbak_restore_storage_dss(param) == OG_TRUE) {
        printf("[ogbackup]  storage=dss\n");
        printf("[ogbackup]  control path handling=%s\n",
            param->is_dry_run == OG_TRUE ? "dss-inplace-preview" : "dss-inplace");
        if (param->is_dry_run == OG_TRUE) {
            printf("[ogbackup]  destructive in-place DSS restore=preview dry-run=true\n");
        } else {
            printf("[ogbackup]  destructive in-place DSS restore=true\n");
        }
        ogbak_restore_print_dss_inplace_targets(plan);
        printf("[ogbackup]  DSS restore strategy: in-place DSS disaster restore; original +vg control/data/log "
               "paths are preserved and overwritten after stopped-cluster validation\n");
    } else if (param->is_in_place == OG_TRUE) {
        printf("[ogbackup]  local restore strategy: original absolute control/data/redo/archive paths; "
               "no redirect or remap\n");
        printf("[ogbackup]  control commit: deferred until every non-control target is fsynced and closed\n");
    } else if (ogbak_restore_path_map_auto(param) == OG_TRUE) {
        printf("[ogbackup]  control rewrite: enabled; datafile/logfile/archive paths are rewritten to target-dir\n");
    } else {
        printf("[ogbackup]  control rewrite: disabled; control file may still reference original paths\n");
        printf("[ogbackup]  OPEN readiness: restored target-dir is not guaranteed to be OPEN-ready with path-map=none\n");
    }
    printf("[ogbackup]  selected backup chain:\n");
    for (uint32 i = 0; i < plan->chain_count; i++) {
        ogbak_offline_backup_t *bak = plan->chain[i];
        printf("[ogbackup]    %u. id=%s type=%s level=%u parent=%s db_id=%u cluster_id=%u lsn=%llu-%llu checkpoint=%llu\n",
            i + 1, bak->id, ogbak_restore_type_name(bak->type),
            bak->level,
            ogbak_restore_is_empty_str(bak->parent_id) ? "-" : bak->parent_id,
            bak->db_id, bak->cluster_id, bak->start_lsn, bak->end_lsn, bak->checkpoint_lsn);
    }
    printf("[ogbackup]  files to restore:\n");
    for (uint32 i = 0; i < plan->file_count; i++) {
        printf("[ogbackup]    %u. backup=%s type=%s level=%u src=%s target=%s size=%llu checksum=%s%u\n",
            i + 1, plan->files[i]->backup_id, ogbak_restore_file_type_name(plan->files[i]->type),
            plan->files[i]->backup_level, plan->files[i]->src, plan->files[i]->target, plan->files[i]->size,
            plan->files[i]->has_checksum == OG_TRUE ? "" : "not-recorded/",
            plan->files[i]->has_checksum == OG_TRUE ? plan->files[i]->checksum : 0);
    }
    printf("[ogbackup]  control restore:\n");
    uint32 ctrl_printed = 0;
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (plan->files[i]->from_backupset != OG_TRUE || plan->files[i]->type != OGBAK_RESTORE_FILE_CONTROL) {
            continue;
        }
        ctrl_printed++;
        printf("[ogbackup]    control backup piece=%s -> %s; deferred_commit=true; "
               "raw size is validated from 16K control page count; checksum=checked before file mutation\n",
            plan->files[i]->src, param->is_in_place == OG_TRUE ?
            "original CONTROL_FILES paths" : "raw control files=data/ctrl1,data/ctrl2,data/ctrl3");
    }
    if (ctrl_printed == 0) {
        printf("[ogbackup]    no real backupset control piece in selected chain\n");
    }
    if (ogbak_restore_storage_dss(param) == OG_TRUE) {
        printf("[ogbackup]  DSS strategy: in-place path preserve; requires DSS_HOME/DSS server; "
               "redo/archive payload targets are restored from control metadata\n");
    } else if (param->is_in_place == OG_TRUE) {
        printf("[ogbackup]  local in-place strategy: data/redo/archive targets and CONTROL_FILES come from "
               "the final control image; remapping is disabled\n");
    } else {
        printf("[ogbackup]  DSS/path mapping strategy: local target-dir restore rejects source control files containing "
               "+vg/DSS paths; path-map=auto supports local FS path rewrite only, not DSS/DBStor providers\n");
    }
    printf("[ogbackup]  skipped empty datafile pieces:\n");
    uint32 skip_count = 0;
    for (uint32 i = 0; i < plan->file_count; i++) {
        if (ogbak_restore_is_empty_datafile_piece(plan->files[i]) != OG_TRUE) {
            continue;
        }
        skip_count++;
        printf("[ogbackup]    backup=%s level=%u src=%s target=%s reason=zero-size datafile piece\n",
            plan->files[i]->backup_id, plan->files[i]->backup_level, plan->files[i]->src, plan->files[i]->target);
    }
    if (skip_count == 0) {
        printf("[ogbackup]    none\n");
    }
    printf("[ogbackup]  archive/redo ranges:\n");
    uint32 arch_printed = 0;
    for (uint32 i = 0; i < manifest->arch_count; i++) {
        if (!ogbak_restore_chain_has_backup(plan, manifest->archs[i].backup_id)) {
            continue;
        }
        arch_printed++;
        printf("[ogbackup]    backup=%s node=%u rst=%u asn=%u-%u lsn=%llu-%llu\n",
            manifest->archs[i].backup_id, manifest->archs[i].node_id, manifest->archs[i].rst_id,
            manifest->archs[i].start_asn, manifest->archs[i].end_asn,
            manifest->archs[i].start_lsn, manifest->archs[i].end_lsn);
    }
    if (arch_printed == 0) {
        printf("[ogbackup]    no archive/redo range recorded\n");
    }
    printf("[ogbackup]  validation: version/db identity/chain/file size/file checksum/page checksum/archive continuity checked\n");
    printf("[ogbackup]  parallel backup pieces: %s; restore execution=serial\n",
        plan->parallel_pieces == OG_TRUE ? "validated and ordered by section" : "none");
    if (ogbak_restore_cluster_validation_incomplete(plan) == OG_TRUE) {
        printf("[ogbackup]  validation warning: cluster_id validation incomplete for real backupsets because bak_head_t does not persist a reliable cluster_id; require manifest extension for strict cluster identity\n");
    }
    printf("[ogbackup]  failure handling: non-dry-run restore writes %s while applying files, renames it to %s on write failure, and writes %s on success; no rollback/resume is guaranteed yet\n",
        OGBAK_RESTORE_MARKER_IN_PROGRESS, OGBAK_RESTORE_MARKER_FAILED, OGBAK_RESTORE_MARKER_COMPLETE);
    printf("[ogbackup]  post-restore: start database instance to complete redo/WAL recovery; offline restore does not "
           "execute RECOVER DATABASE or RESETLOGS\n");
    if (ogbak_restore_path_map_auto(param) == OG_TRUE) {
        printf("[ogbackup]  OPEN readiness: file phase completed with control path rewrite; database startup recovery "
               "is still required\n");
    }
}

typedef struct st_ogbak_restore_blocked_process {
    char pid[OG_NAME_BUFFER_SIZE];
    char comm[OG_NAME_BUFFER_SIZE];
    char cmdline[OGBAK_RESTORE_PROC_CMDLINE_SIZE];
    const char *rule;
} ogbak_restore_blocked_process_t;

static void ogbak_restore_strip_proc_text(char *text)
{
    uint32 len = (uint32)strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[--len] = '\0';
    }
}

static bool32 ogbak_restore_read_proc_comm(const char *pid, char *comm, uint32 comm_size)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    int32 ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/comm", pid);
    if (ret == -1) {
        return OG_FALSE;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return OG_FALSE;
    }
    if (fgets(comm, comm_size, fp) == NULL) {
        (void)fclose(fp);
        return OG_FALSE;
    }
    (void)fclose(fp);
    ogbak_restore_strip_proc_text(comm);
    return OG_TRUE;
}

static bool32 ogbak_restore_read_proc_cmdline(const char *pid, char *cmdline, uint32 cmdline_size)
{
    char path[OG_MAX_FILE_PATH_LENGH] = {0};
    int32 ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/cmdline", pid);
    if (ret == -1) {
        return OG_FALSE;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return OG_FALSE;
    }
    size_t read_size = fread(cmdline, 1, cmdline_size - 1, fp);
    (void)fclose(fp);
    if (read_size == 0) {
        return OG_FALSE;
    }
    cmdline[read_size] = '\0';
    for (size_t i = 0; i < read_size; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    ogbak_restore_strip_proc_text(cmdline);
    return OG_TRUE;
}

static bool32 ogbak_restore_cmdline_has_token(const char *cmdline, const char *token)
{
    return (cmdline != NULL && strstr(cmdline, token) != NULL) ? OG_TRUE : OG_FALSE;
}

static bool32 ogbak_restore_cms_cmdline_is_server(const char *cmdline)
{
    if (ogbak_restore_is_empty_str(cmdline) == OG_TRUE) {
        return OG_TRUE;
    }
    if (ogbak_restore_cmdline_has_token(cmdline, "cms_server") == OG_TRUE ||
        ogbak_restore_cmdline_has_token(cmdline, "cms server") == OG_TRUE ||
        ogbak_restore_cmdline_has_token(cmdline, "/cms server") == OG_TRUE) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 ogbak_restore_process_is_blocked(const char *comm, const char *cmdline, const char **rule)
{
    if (strcmp(comm, "ogracd") == 0) {
        *rule = "comm=ogracd";
        return OG_TRUE;
    }
    if (strcmp(comm, "cms_server") == 0) {
        *rule = "comm=cms_server";
        return OG_TRUE;
    }
    if (strcmp(comm, "cms") == 0 && ogbak_restore_cms_cmdline_is_server(cmdline) == OG_TRUE) {
        *rule = ogbak_restore_is_empty_str(cmdline) == OG_TRUE ? "comm=cms cmdline-unreadable" : "comm=cms cmdline=cms server";
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 ogbak_restore_pid_is_blocked(const char *pid, ogbak_restore_blocked_process_t *blocked)
{
    if (strcmp(pid, "self") == 0) {
        return OG_FALSE;
    }
    if (ogbak_restore_read_proc_comm(pid, blocked->comm, sizeof(blocked->comm)) != OG_TRUE) {
        return OG_FALSE;
    }
    errno_t ret = strcpy_s(blocked->pid, sizeof(blocked->pid), pid);
    if (ret != EOK) {
        return OG_FALSE;
    }
    blocked->cmdline[0] = '\0';
    (void)ogbak_restore_read_proc_cmdline(pid, blocked->cmdline, sizeof(blocked->cmdline));
    blocked->rule = NULL;
    if (ogbak_restore_process_is_blocked(blocked->comm, blocked->cmdline, &blocked->rule) != OG_TRUE) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

static status_t ogbak_restore_check_dss_inplace_processes(ogbak_param_t *param,
    const ogbak_scheme_d_evidence_t *scheme_d_evidence, ogbak_scheme_d_provider_t *scheme_d_provider)
{
    if (param->is_in_place != OG_TRUE && ogbak_restore_dss_inplace(param) != OG_TRUE) {
        return OG_SUCCESS;
    }
    if (param->dss_scheme_d == OG_TRUE) {
        char err_buf[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
#ifdef CMS_UT_TEST
        status_t status = (g_scheme_d_provider_hook == NULL) ?
            ogbak_scheme_d_check_processes(scheme_d_evidence, scheme_d_provider, err_buf, sizeof(err_buf)) :
            g_scheme_d_provider_hook(scheme_d_evidence, scheme_d_provider, err_buf, sizeof(err_buf));
#else
        status_t status = ogbak_scheme_d_check_processes(scheme_d_evidence, scheme_d_provider, err_buf,
            sizeof(err_buf));
#endif
        if (status != OG_SUCCESS) {
            printf("[ogbackup]scheme_d=true provider=official_dss_maintenance identity guard failed: %s\n",
                err_buf);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        printf("[ogbackup]scan /proc failed before DSS in-place restore, error %d (%s)\n", errno, strerror(errno));
        return OG_ERROR;
    }
    struct dirent *entry = NULL;
    uint32 dssserver_count = 0;
    uint32 controlled_dssserver_count = 0;
    const char *dss_home = getenv("DSS_HOME");
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }
        char comm[OG_NAME_BUFFER_SIZE] = {0};
        if (ogbak_restore_read_proc_comm(entry->d_name, comm, sizeof(comm)) == OG_TRUE &&
            strcmp(comm, "dssserver") == 0) {
            dssserver_count++;
            char cmdline[OGBAK_RESTORE_PROC_CMDLINE_SIZE] = {0};
            char parsed_home[OG_MAX_FILE_PATH_LENGH] = {0};
            char proc_path[OG_MAX_FILE_PATH_LENGH] = {0};
            struct stat proc_stat;
            if (ogbak_restore_storage_dss(param) == OG_TRUE && dss_home != NULL && dss_home[0] != '\0' &&
                ogbak_restore_read_proc_cmdline(entry->d_name, cmdline, sizeof(cmdline)) == OG_TRUE &&
                ogbak_scheme_d_parse_dssserver_cmdline(cmdline, dss_home, parsed_home,
                sizeof(parsed_home)) == OG_SUCCESS &&
                snprintf_s(proc_path, sizeof(proc_path), sizeof(proc_path) - 1,
                "/proc/%s", entry->d_name) != -1 && stat(proc_path, &proc_stat) == 0 &&
                proc_stat.st_uid == geteuid()) {
                controlled_dssserver_count++;
            }
            continue;
        }
        ogbak_restore_blocked_process_t blocked = {0};
        if (ogbak_restore_pid_is_blocked(entry->d_name, &blocked) == OG_TRUE) {
            (void)closedir(dir);
            printf("[ogbackup]in-place restore blocked process: pid=%s comm=%s cmdline=%s matched rule=%s\n",
                blocked.pid, blocked.comm, ogbak_restore_is_empty_str(blocked.cmdline) == OG_TRUE ? "<unreadable>" :
                blocked.cmdline, blocked.rule);
            printf("[ogbackup]in-place restore requires every ogracd and CMS server to be stopped\n");
            return OG_ERROR;
        }
    }
    (void)closedir(dir);
    uint32 expected_dssserver_count = ogbak_restore_storage_dss(param) == OG_TRUE ? 1 : 0;
    if (dssserver_count != expected_dssserver_count) {
        printf("[ogbackup]in-place restore requires dssserver count=%u for storage=%s; found %u\n",
            expected_dssserver_count, ogbak_restore_storage_mode_name(param), dssserver_count);
        return OG_ERROR;
    }
    if (ogbak_restore_storage_dss(param) == OG_TRUE && controlled_dssserver_count != 1) {
        printf("[ogbackup]DSS in-place restore requires one current-user dssserver -D DSS_HOME -M; "
               "found controlled=%u total=%u DSS_HOME=%s\n",
            controlled_dssserver_count, dssserver_count,
            dss_home == NULL || dss_home[0] == '\0' ? "<unset>" : dss_home);
        return OG_ERROR;
    }
    printf("[ogbackup]in-place process preflight complete: ogracd=0 cms_server=0 dssserver=%u storage=%s\n",
        dssserver_count, ogbak_restore_storage_mode_name(param));
    return OG_SUCCESS;
}

static status_t ogbak_restore_check_params(ogbak_param_t *param)
{
    if (param->is_offline != OG_TRUE) {
        printf("[ogbackup]use --offline-restore for file-level offline restore\n");
        return OG_ERROR;
    }
    if (param->backup_dir.str == NULL || param->backup_dir.len == 0) {
        printf("[ogbackup]The --backup-dir parameter cannot be NULL for offline restore!\n");
        return OG_ERROR;
    }
    if (param->is_in_place == OG_TRUE && param->target_dir.str != NULL) {
        printf("[ogbackup]--in-place restores paths from backup control metadata and cannot use --target-dir\n");
        return OG_ERROR;
    }
    if (param->backup_dir.str[0] == '+' || cm_device_type(param->backup_dir.str) != DEV_TYPE_FILE) {
        printf("[ogbackup]offline restore backupset source must be a local filesystem directory\n");
        return OG_ERROR;
    }
    if (param->is_in_place == OG_TRUE && param->is_force != OG_TRUE) {
        printf("[ogbackup]--in-place is destructive and requires explicit --force confirmation\n");
        return OG_ERROR;
    }
    if (param->is_in_place != OG_TRUE && (param->target_dir.str == NULL || param->target_dir.len == 0)) {
        printf("[ogbackup]The --target-dir parameter cannot be NULL for offline restore!\n");
        return OG_ERROR;
    }
    if (param->backup_dir.len >= OG_MAX_FILE_PATH_LENGH ||
        (param->target_dir.str != NULL && param->target_dir.len >= OG_MAX_FILE_PATH_LENGH)) {
        printf("[ogbackup]offline restore path parameter is too long\n");
        return OG_ERROR;
    }
    if (param->is_in_place != OG_TRUE && param->target_dir.str[0] != '/') {
        printf("[ogbackup]--target-dir must be an absolute path for offline restore\n");
        return OG_ERROR;
    }
    if (!cm_dir_exist(param->backup_dir.str)) {
        printf("[ogbackup]backup-dir %s does not exist\n", param->backup_dir.str);
        return OG_ERROR;
    }
    int32 parallelism_count;
    if (param->parallelism.str != NULL && param->parallelism.len != 0) {
        if (cm_str2int(param->parallelism.str, &parallelism_count) != OG_SUCCESS ||
            parallelism_count > MAX_PARALLELISM_COUNT || parallelism_count <= 0) {
            printf("[ogbackup]The --parallel parameter value should be in [1, 16].\n");
            return OG_ERROR;
        }
        if (parallelism_count != 1) {
            printf("[ogbackup]offline restore execution is serial; --parallel only describes readable backup pieces "
                   "and must be 1\n");
            return OG_ERROR;
        }
    }
    if (param->backup_id.str != NULL && param->target_time.str != NULL) {
        printf("[ogbackup]--backup-id and --target-time cannot be specified together for offline restore\n");
        return OG_ERROR;
    }
    if (param->password.str != NULL && param->password_file.str != NULL) {
        printf("[ogbackup]--password and --password-file cannot be specified together\n");
        return OG_ERROR;
    }
    if (param->password_file.len >= OG_MAX_FILE_PATH_LENGH) {
        printf("[ogbackup]--password-file path is too long\n");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t ogbak_do_offline_restore(ogbak_param_t *ogbak_param)
{
    ogbak_offline_manifest_t manifest;
    ogbak_offline_plan_t plan;
    ogbak_scheme_d_evidence_t scheme_d_evidence;
    ogbak_scheme_d_provider_t scheme_d_provider;
    ogbak_scheme_d_plan_t *scheme_d_plan = NULL;
    errno_t init_ret = memset_s(&scheme_d_evidence, sizeof(scheme_d_evidence), 0, sizeof(scheme_d_evidence));
    init_ret |= memset_s(&scheme_d_provider, sizeof(scheme_d_provider), 0, sizeof(scheme_d_provider));
    if (init_ret != EOK) {
        return OG_ERROR;
    }
    if (ogbak_restore_check_params(ogbak_param) != OG_SUCCESS) {
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_restore_load_password_file(ogbak_param) != OG_SUCCESS) {
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_param->is_in_place == OG_TRUE && ogbak_param->target_dir.str == NULL) {
        /* In-place has no target redirection.  Keep fail-stop markers beside the
         * local backup repository, which remains available for both local and DSS targets. */
        if (ogbak_parse_single_arg(ogbak_param->backup_dir.str, &ogbak_param->target_dir) != OG_SUCCESS) {
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    if (ogbak_offline_load_manifest(ogbak_param->backup_dir.str, &manifest) != OG_SUCCESS) {
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_offline_build_plan(&manifest, ogbak_param, &plan) != OG_SUCCESS) {
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_restore_configure_storage(ogbak_param, &plan) != OG_SUCCESS) {
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_restore_storage_dss(ogbak_param) == OG_TRUE && ogbak_param->is_in_place != OG_TRUE &&
        ogbak_param->dss_scheme_d != OG_TRUE && ogbak_param->dss_scheme_d_target_manifest_only != OG_TRUE) {
        printf("[ogbackup]DSS offline restore is only supported by the formal explicit --in-place mode\n");
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_restore_storage_dss(ogbak_param) == OG_TRUE && ogbak_param->is_dry_run != OG_TRUE &&
        ogbak_param->is_force != OG_TRUE) {
        printf("[ogbackup]DSS in-place restore overwrites original DSS paths; confirm it with --force\n");
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_param->dss_scheme_d_target_manifest_only == OG_TRUE) {
        char failure_reason[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
        status_t status = ogbak_scheme_d_export_target_manifest(ogbak_param, &plan, failure_reason,
            sizeof(failure_reason));
        if (status != OG_SUCCESS) {
            printf("[ogbackup]scheme_d=true target_manifest_only blocked: %s", failure_reason);
        }
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return status;
    }
    if (ogbak_param->dss_scheme_d == OG_TRUE) {
        char err_buf[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
        if (ogbak_param->dss_scheme_d_preflight_only == OG_TRUE) {
            printf("[ogbackup]Scheme D preflight-only begin\n");
        }
        if (ogbak_scheme_d_validate_evidence(ogbak_param->dss_scheme_d_evidence.str,
            ogbak_param->backup_dir.str, ogbak_param->dss_scheme_d_disposable_waiver, &scheme_d_evidence, err_buf,
            sizeof(err_buf)) != OG_SUCCESS ||
            ogbak_scheme_d_validate_current_user(&scheme_d_evidence, err_buf, sizeof(err_buf)) != OG_SUCCESS ||
            ogbak_scheme_d_check_unsafe_marker(ogbak_param->target_dir.str, err_buf,
            sizeof(err_buf)) != OG_SUCCESS) {
            printf("[ogbackup]scheme_d=true evidence validation failed: %s\n", err_buf);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
        printf("[ogbackup]scheme_d=true evidence_path=%s evidence_sha256=%s snapshot_id=%s "
               "expected_dss_home=%s restore_user=%s\n",
            scheme_d_evidence.path, scheme_d_evidence.hash, scheme_d_evidence.snapshot_id,
            scheme_d_evidence.expected_dss_home, scheme_d_evidence.restore_user);
        if (scheme_d_evidence.disposable_waiver == OG_TRUE) {
            printf("[ogbackup]DEVELOPMENT-ONLY DISPOSABLE WAIVER ACTIVE\n");
            printf("[ogbackup]NO STORAGE SNAPSHOT OR ROLLBACK GUARANTEE\n");
            printf("[ogbackup]PRODUCTION USE FORBIDDEN\n");
        }
    }
    if (ogbak_restore_dss_inplace(ogbak_param) == OG_TRUE && ogbak_param->is_dry_run == OG_TRUE &&
        ogbak_restore_init_dss_device_from_env() != OG_SUCCESS) {
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_restore_validate_files(ogbak_param, &plan) != OG_SUCCESS ||
        ogbak_restore_validate_control_files(ogbak_param, &plan) != OG_SUCCESS ||
        ogbak_restore_precheck_target(ogbak_param) != OG_SUCCESS ||
        ogbak_restore_check_existing_markers(ogbak_param) != OG_SUCCESS ||
        ogbak_restore_check_dss_inplace_processes(ogbak_param,
        ogbak_param->dss_scheme_d == OG_TRUE ? &scheme_d_evidence : NULL,
        ogbak_param->dss_scheme_d == OG_TRUE ? &scheme_d_provider : NULL) != OG_SUCCESS) {
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_param->dss_scheme_d_preflight_only == OG_TRUE) {
        printf("[ogbackup]Scheme D preflight-only provider validated\n");
    }
    if (ogbak_restore_storage_dss(ogbak_param) == OG_TRUE && ogbak_param->is_dry_run != OG_TRUE &&
        ogbak_restore_init_dss_device_from_env() != OG_SUCCESS) {
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }

    char failure_reason[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
    if (ogbak_restore_dss_inplace(ogbak_param) == OG_TRUE && ogbak_param->is_dry_run != OG_TRUE) {
        bak_offline_set_dss_inplace_offline_vg_check(OG_TRUE);
        bak_offline_clear_last_dss_error();
#ifdef CMS_UT_TEST
        status_t preflight_status = (g_scheme_d_preflight_probe_hook == NULL) ?
            ogbak_restore_probe_dss_inplace_preflight(ogbak_param, &plan, failure_reason, sizeof(failure_reason)) :
            g_scheme_d_preflight_probe_hook(ogbak_param, &plan, failure_reason, sizeof(failure_reason));
#else
        status_t preflight_status = ogbak_restore_probe_dss_inplace_preflight(ogbak_param, &plan,
            failure_reason, sizeof(failure_reason));
#endif
        if (preflight_status != OG_SUCCESS) {
            bak_offline_set_dss_inplace_offline_vg_check(OG_FALSE);
            printf("[ogbackup]offline restore stopped before file writes; %s", failure_reason);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
        if (ogbak_param->dss_scheme_d == OG_TRUE &&
            scheme_d_plan == NULL) {
            scheme_d_plan = (ogbak_scheme_d_plan_t *)malloc(sizeof(ogbak_scheme_d_plan_t));
            if (scheme_d_plan == NULL || memset_s(scheme_d_plan, sizeof(*scheme_d_plan), 0,
                sizeof(*scheme_d_plan)) != EOK) {
                CM_FREE_PTR(scheme_d_plan);
                bak_offline_set_dss_inplace_offline_vg_check(OG_FALSE);
                ogbak_offline_free_plan(&plan);
                ogbak_offline_free_manifest(&manifest);
                free_input_params(ogbak_param);
                return OG_ERROR;
            }
        }
        if (ogbak_param->dss_scheme_d == OG_TRUE &&
            ogbak_restore_scheme_d_build_write_plan(ogbak_param, &plan, &scheme_d_evidence,
            &scheme_d_provider, scheme_d_plan, failure_reason, sizeof(failure_reason)) != OG_SUCCESS) {
            bak_offline_set_dss_inplace_offline_vg_check(OG_FALSE);
            printf("[ogbackup]scheme_d=true offline restore stopped before first payload write; %s",
                failure_reason);
            CM_FREE_PTR(scheme_d_plan);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
        if (ogbak_param->dss_scheme_d_preflight_only == OG_TRUE) {
            bak_offline_set_dss_inplace_offline_vg_check(OG_FALSE);
            printf("[ogbackup]Scheme D preflight-only write-plan published path=%s sha256=%s\n",
                scheme_d_plan == NULL ? "" : scheme_d_plan->path, scheme_d_plan == NULL ? "" : scheme_d_plan->hash);
            printf("[ogbackup]Scheme D preflight-only complete; no restore payload write executed\n");
            CM_FREE_PTR(scheme_d_plan);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_SUCCESS;
        }
        bak_offline_set_dss_inplace_offline_vg_check(OG_FALSE);
    }
    /* Parse/authenticate the final control image and freeze every target before
     * the fail-stop marker or any target create/truncate/write operation. */
    ogbak_deferred_ctrl_t preflight_ctrl = {0};
    bool32 has_preflight_ctrl = OG_FALSE;
    for (uint32 i = 0; i < plan.file_count; i++) {
        if (plan.files[i]->from_backupset == OG_TRUE &&
            plan.files[i]->type == OGBAK_RESTORE_FILE_CONTROL) {
            has_preflight_ctrl = OG_TRUE;
            break;
        }
    }
    if (has_preflight_ctrl == OG_TRUE &&
        ogbak_restore_stage_deferred_ctrl(ogbak_param, &plan, &preflight_ctrl,
        failure_reason, sizeof(failure_reason)) != OG_SUCCESS) {
        printf("[ogbackup]offline restore stopped before target mutation; %s", failure_reason);
        CM_FREE_PTR(scheme_d_plan);
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (has_preflight_ctrl == OG_TRUE && ogbak_param->is_in_place == OG_TRUE &&
        ogbak_restore_storage_dss(ogbak_param) != OG_TRUE &&
        ogbak_restore_probe_local_inplace_plan(&preflight_ctrl) != OG_SUCCESS) {
        ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
        printf("[ogbackup]offline restore stopped before target mutation; local target preflight failed\n");
        CM_FREE_PTR(scheme_d_plan);
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_param->is_in_place == OG_TRUE && has_preflight_ctrl != OG_TRUE) {
        printf("[ogbackup]in-place restore requires a real final control backup piece\n");
        ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
        CM_FREE_PTR(scheme_d_plan);
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    if (ogbak_restore_predecode_protected_payloads(ogbak_param, &plan, failure_reason,
        sizeof(failure_reason)) != OG_SUCCESS) {
        ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
        printf("[ogbackup]offline restore stopped before target mutation; %s", failure_reason);
        CM_FREE_PTR(scheme_d_plan);
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    ogbak_restore_print_report(ogbak_param, &manifest, &plan);
    if (ogbak_param->is_dry_run != OG_TRUE) {
        if (ogbak_restore_remove_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED) != OG_SUCCESS ||
            ogbak_restore_remove_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_COMPLETE) != OG_SUCCESS) {
            ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
            CM_FREE_PTR(scheme_d_plan);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
        if (bak_offline_write_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_IN_PROGRESS,
            "offline restore is in progress; do not start this database directory\n") != OG_SUCCESS) {
            ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
            CM_FREE_PTR(scheme_d_plan);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    if (ogbak_param->dss_scheme_d == OG_TRUE) {
        if (ogbak_scheme_d_verify_backupset_checksum(ogbak_param->backup_dir.str,
            scheme_d_evidence.backupset_checksum, failure_reason, sizeof(failure_reason)) != OG_SUCCESS) {
            printf("[ogbackup]scheme_d=true backup content changed before first payload write; %s\n",
                failure_reason);
            (void)ogbak_restore_remove_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_IN_PROGRESS);
            ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
            CM_FREE_PTR(scheme_d_plan);
            ogbak_offline_free_plan(&plan);
            ogbak_offline_free_manifest(&manifest);
            free_input_params(ogbak_param);
            return OG_ERROR;
        }
    }
    if (ogbak_param->dss_scheme_d == OG_TRUE &&
        ogbak_scheme_d_mark_first_write(ogbak_param->target_dir.str, &scheme_d_evidence, scheme_d_plan,
        failure_reason, sizeof(failure_reason)) != OG_SUCCESS) {
        printf("[ogbackup]scheme_d=true stopped before payload write; %s\n", failure_reason);
        if (bak_offline_write_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED,
            "offline restore stopped after publishing the in-progress marker and before payload writes; "
            "do not start this database directory\n") == OG_SUCCESS) {
            (void)ogbak_restore_remove_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_IN_PROGRESS);
        }
        ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
        CM_FREE_PTR(scheme_d_plan);
        ogbak_offline_free_plan(&plan);
        ogbak_offline_free_manifest(&manifest);
        free_input_params(ogbak_param);
        return OG_ERROR;
    }
    bool32 offline_dss_vg_check = (ogbak_restore_dss_inplace(ogbak_param) == OG_TRUE &&
        ogbak_param->is_dry_run != OG_TRUE) ? OG_TRUE : OG_FALSE;
    bak_offline_set_dss_inplace_offline_vg_check(offline_dss_vg_check);
    bak_offline_clear_last_dss_error();
    g_ogbak_preflight_deferred_ctrl = has_preflight_ctrl == OG_TRUE ? &preflight_ctrl : NULL;
#ifdef CMS_UT_TEST
    g_ogbak_scheme_d_active_plan = ogbak_param->dss_scheme_d == OG_TRUE ? scheme_d_plan : NULL;
    status_t status = (g_restore_execute_hook == NULL) ?
        ogbak_restore_execute_files(ogbak_param, &plan, failure_reason, sizeof(failure_reason)) :
        g_restore_execute_hook(ogbak_param, &plan, failure_reason, sizeof(failure_reason));
#else
    g_ogbak_scheme_d_active_plan = ogbak_param->dss_scheme_d == OG_TRUE ? scheme_d_plan : NULL;
    status_t status = ogbak_restore_execute_files(ogbak_param, &plan, failure_reason, sizeof(failure_reason));
#endif
    g_ogbak_preflight_deferred_ctrl = NULL;
    g_ogbak_scheme_d_active_plan = NULL;
    bak_offline_set_dss_inplace_offline_vg_check(OG_FALSE);
    ogbak_restore_release_deferred_ctrl(&preflight_ctrl);
    if (status == OG_SUCCESS) {
        if (ogbak_param->is_dry_run != OG_TRUE) {
            if (ogbak_param->dss_scheme_d == OG_TRUE &&
                ogbak_scheme_d_mark_complete(ogbak_param->target_dir.str, &scheme_d_evidence, scheme_d_plan,
                failure_reason, sizeof(failure_reason)) != OG_SUCCESS) {
                printf("[ogbackup]scheme_d=true complete marker failed after writes; %s\n", failure_reason);
                if (bak_offline_write_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED,
                    "offline restore wrote files but could not publish the Scheme D completion marker; "
                    "do not start this database directory\n") == OG_SUCCESS) {
                    (void)ogbak_restore_remove_marker(ogbak_param->target_dir.str,
                        OGBAK_RESTORE_MARKER_IN_PROGRESS);
                }
                CM_FREE_PTR(scheme_d_plan);
                ogbak_offline_free_plan(&plan);
                ogbak_offline_free_manifest(&manifest);
                free_input_params(ogbak_param);
                return OG_ERROR;
            }
            if (ogbak_restore_write_complete_marker(ogbak_param, &plan) != OG_SUCCESS) {
                if (bak_offline_write_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED,
                    "offline restore wrote files but could not publish the file-phase completion marker; "
                    "do not start this database directory\n") == OG_SUCCESS) {
                    (void)ogbak_restore_remove_marker(ogbak_param->target_dir.str,
                        OGBAK_RESTORE_MARKER_IN_PROGRESS);
                }
                ogbak_offline_free_plan(&plan);
                ogbak_offline_free_manifest(&manifest);
                CM_FREE_PTR(scheme_d_plan);
                free_input_params(ogbak_param);
                return OG_ERROR;
            }
            if (ogbak_restore_remove_marker(ogbak_param->target_dir.str,
                OGBAK_RESTORE_MARKER_IN_PROGRESS) != OG_SUCCESS) {
                (void)bak_offline_write_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED,
                    "offline restore completed but the in-progress marker could not be removed durably; "
                    "do not start this database directory\n");
                ogbak_offline_free_plan(&plan);
                ogbak_offline_free_manifest(&manifest);
                CM_FREE_PTR(scheme_d_plan);
                free_input_params(ogbak_param);
                return OG_ERROR;
            }
        }
        printf("[ogbackup]offline restore %s\n", ogbak_param->is_dry_run == OG_TRUE ? "dry-run success" : "success");
    } else if (ogbak_param->is_dry_run != OG_TRUE) {
        if (failure_reason[0] == '\0') {
            (void)strcpy_s(failure_reason, sizeof(failure_reason),
                "offline restore failed after writing began; do not start this database directory\n");
        }
        char failed_content[OG_MAX_CONFIG_LINE_SIZE * 2] = {0};
        int32 ret = snprintf_s(failed_content, sizeof(failed_content), sizeof(failed_content) - 1,
            "offline restore failed after writing began; do not start this database directory\nreason=%s",
            failure_reason);
        if (ret == -1) {
            (void)strcpy_s(failed_content, sizeof(failed_content),
                "offline restore failed after writing began; do not start this database directory\n");
        }
        if (bak_offline_write_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_FAILED,
            failed_content) != OG_SUCCESS) {
            printf("[ogbackup]offline restore failed and writing failed marker also failed; target-dir is unsafe\n");
        } else {
            (void)ogbak_restore_remove_marker(ogbak_param->target_dir.str, OGBAK_RESTORE_MARKER_IN_PROGRESS);
        }
        printf("[ogbackup]offline restore failed after file writes began; target-dir is not safe to start\n");
    }

    ogbak_offline_free_plan(&plan);
    ogbak_offline_free_manifest(&manifest);
    CM_FREE_PTR(scheme_d_plan);
    free_input_params(ogbak_param);
    return status;
}

status_t ogbak_parse_restore_args(int32 argc, char **argv, ogbak_param_t *ogbak_param)
{
    int opt_s;
    int opt_index;
    optind = 1;
    while (optind < argc) {
        OG_RETURN_IFERR(check_input_params(argv[optind]));
        opt_s = getopt_long(argc, argv, OGBAK_SHORT_OPTION_EXP, g_ogbak_restore_options, &opt_index);
        if (opt_s == OGBAK_PARSE_OPTION_ERR) {
            break;
        }
        switch (opt_s) {
            case OGBAK_PARSE_OPTION_COMMON:
                break;
            case OGBAK_SHORT_OPTION_OFFLINE:
                ogbak_param->is_offline = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_BACKUP_DIR:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->backup_dir));
                break;
            case OGBAK_SHORT_OPTION_TARGET_DIR:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->target_dir));
                break;
            case OGBAK_SHORT_OPTION_BACKUP_ID:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->backup_id));
                break;
            case OGBAK_SHORT_OPTION_TARGET_TIME:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->target_time));
                break;
            case OGBAK_SHORT_OPTION_PASSWORD:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->password));
                ogbak_restore_hide_sensitive_arg(optarg);
                break;
            case OGBAK_PARSE_OPTION_PASSWORD_FILE:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->password_file));
                break;
            case OGBAK_SHORT_OPTION_DRY_RUN:
                ogbak_param->is_dry_run = OG_TRUE;
                break;
            case OGBAK_PARSE_OPTION_IN_PLACE:
                ogbak_param->is_in_place = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_FORCE:
                ogbak_param->is_force = OG_TRUE;
                break;
            case OGBAK_SHORT_OPTION_PARALLEL:
                OG_RETURN_IFERR(ogbak_parse_single_arg(optarg, &ogbak_param->parallelism));
                break;
            case OGBAK_SHORT_OPTION_UNRECOGNIZED:
            case OGBAK_SHORT_OPTION_NO_ARG:
                printf("[ogbackup]Parse option arguments of restore failed!\n");
                return OG_ERROR;
            default:
                break;
        }
    }
    return OG_SUCCESS;
}

ogbak_cmd_t *ogbak_generate_restore_cmd(void)
{
    ogbak_cmd_t *ogbak_cmd = (ogbak_cmd_t *)malloc(sizeof(ogbak_cmd_t));
    if (ogbak_cmd == NULL) {
        printf("[ogbackup]failed to malloc memory for restore ogbak_cmd!\n");
        return (ogbak_cmd_t *)NULL;
    }
    ogbak_cmd->parse_args = ogbak_parse_restore_args;
    ogbak_cmd->do_exec = ogbak_do_offline_restore;
    return ogbak_cmd;
}
