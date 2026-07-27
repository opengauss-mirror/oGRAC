/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
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
 * cms_disk_usage.c
 *
 * IDENTIFICATION
 * src/cms/cms/cms_disk_usage.c
 *
 * -------------------------------------------------------------------------
 */

#include "cms_disk_usage.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cms_log.h"
#include "cms_param.h"
#include "cm_file.h"
#include "cm_text.h"
#include "cms_comm.h"
#include "cms_interface.h"
#include "cms_stat.h"
#include "cms_uds_server.h"

extern char **g_environ __asm__("environ");

#define CMS_DISK_USAGE_DEFAULT_INTERVAL 30
#define CMS_DISK_USAGE_DEFAULT_THRESHOLD 85
#define CMS_DISK_USAGE_MIN_INTERVAL 5
#define CMS_DISK_USAGE_MAX_INTERVAL 3600
#define CMS_DISK_USAGE_CMD_TIMEOUT 30
#define CMS_DISK_USAGE_ALARM_LOG_INTERVAL (10 * 60 * MICROSECS_PER_SECOND_LL)
#define CMS_DISK_USAGE_OUTPUT_SIZE SIZE_K(8)
#define CMS_DISK_USAGE_GIB ((double)SIZE_K(1) * SIZE_K(1) * SIZE_K(1))
#define CMS_DISK_USAGE_DSS_SOCKET ".dss_unix_d_socket"
#define CMS_DISK_READONLY_DEFAULT_COOLDOWN 120
#define CMS_DISK_READONLY_MAX_COOLDOWN 3600
#define CMS_DISK_USAGE_PERCENT_MAX 100U
#define CMS_DISK_USAGE_PERCENT_PRECISION 1000U
#define CMS_DISK_USAGE_PERCENT_SCALE (CMS_DISK_USAGE_PERCENT_MAX * CMS_DISK_USAGE_PERCENT_PRECISION)
#define CMS_DISK_USAGE_FILE_MODE_MASK (S_IRWXU | S_IRWXG | S_IRWXO)
#define CMS_DISK_USAGE_OPT_D_LEN 2
#define CMS_DISK_USAGE_EXEC_FAILED_CODE 127
#define CMS_DISK_USAGE_WAIT_INTERVAL_MS 100
#define CMS_DISK_USAGE_SIGNAL_CODE_BASE 128
#define CMS_DISK_USAGE_ROUNDING 0.5
#define CMS_DISK_USAGE_DSS_CMD_ARG_COUNT 10
#define CMS_DISK_USAGE_DSS_CMD_BASE_ARG_COUNT 4
#define CMS_DISK_USAGE_FALLBACK_SIZE_MIN_COUNT 3
#define CMS_DISK_USAGE_FALLBACK_SIZE_NORMAL_COUNT 4
#define CMS_DISK_USAGE_FALLBACK_SIZE_EXT_COUNT 5
#define CMS_DISK_USAGE_FALLBACK_TOTAL_IDX 0
#define CMS_DISK_USAGE_FALLBACK_FREE_IDX 1
#define CMS_DISK_USAGE_FALLBACK_USED_IDX 2
#define CMS_DISK_USAGE_FALLBACK_PERCENT_IDX 3
#define CMS_DISK_USAGE_FALLBACK_EXT_TOTAL_IDX 1
#define CMS_DISK_USAGE_FALLBACK_EXT_FREE_IDX 2
#define CMS_DISK_USAGE_FALLBACK_EXT_USED_IDX 3
#define CMS_DISK_USAGE_FALLBACK_EXT_PERCENT_IDX 4

typedef struct st_cms_disk_usage_config {
    bool32 protect_enabled;
    uint32 interval_sec;
    uint32 threshold_percent;
    uint32 readonly_cooldown_sec;
} CmsDiskUsageConfigT;

typedef struct st_cms_disk_usage_cmd_result {
    int32 return_code;
    bool32 timeout;
    char output[CMS_DISK_USAGE_OUTPUT_SIZE];
    char error[CMS_INFO_BUFFER_SIZE];
} CmsDiskUsageCmdResultT;

typedef struct st_cms_disk_usage_parsed_vg {
    bool32 valid;
    char name[CMS_NAME_BUFFER_SIZE];
    uint64 total_bytes;
    uint64 used_bytes;
    uint64 free_bytes;
    uint32 use_percent_x1000;
} CmsDiskUsageParsedVgT;

typedef struct st_cms_disk_usage_parsed_dss {
    uint32 count;
    CmsDiskUsageParsedVgT vg[CMS_DISK_USAGE_MAX_DSS_VG];
} CmsDiskUsageParsedDssT;

typedef struct st_cms_disk_usage_failed_item {
    uint32 item_type;
    const char *name;
    const char *source;
    uint32 threshold;
    const char *info;
} CmsDiskUsageFailedItemT;

typedef struct st_cms_disk_usage_dss_ctx {
    char dssHome[CMS_FILE_NAME_BUFFER_SIZE];
    char dsscmd[CMS_FILE_NAME_BUFFER_SIZE];
    char uds[CMS_FILE_NAME_BUFFER_SIZE];
    char homeInfo[CMS_INFO_BUFFER_SIZE];
    char cmdInfo[CMS_INFO_BUFFER_SIZE];
    bool32 udsFound;
} CmsDiskUsageDssCtxT;

static thread_lock_t g_disk_usage_lock;
static CmsDiskUsageSnapshotT g_diskUsageSnapshot;
static pthread_once_t g_diskUsageOnce = PTHREAD_ONCE_INIT;
static bool32 g_disk_readonly_triggered = OG_FALSE;
static date_t g_disk_readonly_last_action_time = 0;
static date_t g_disk_readonly_last_trigger_time = 0;
static date_t g_disk_readonly_last_recover_time = 0;
static char g_disk_readonly_state[CMS_NAME_BUFFER_SIZE] = "NORMAL";
static char g_disk_readonly_info[CMS_INFO_BUFFER_SIZE] = "not triggered";
static char g_disk_readonly_trigger_items[CMS_FILE_NAME_BUFFER_SIZE] = "";

static void CmsDiskUsageFillReadonlyConfig(CmsDiskReadonlyConfigInfoT *info,
    const CmsDiskUsageConfigT *cfg);
static void CmsDiskUsageSetReadonlyState(const char *state, const char *fmt, ...);
static void cms_disk_usage_copy_str(char *dst, uint32 dst_size, const char *src);

#define CMS_DISK_USAGE_MEMSET(dst, destMax, count) \
    CmsDiskUsageCheckMemset(memset_s((dst), (destMax), 0, (count)))
#define CMS_DISK_USAGE_MEMCPY(dst, destMax, src, count) \
    CmsDiskUsageCheckMemcpy(memcpy_s((dst), (destMax), (src), (count)))

static status_t CmsDiskUsageCheckMemset(errno_t err)
{
    if (err != EOK) {
        CMS_LOG_ERR("memset_s failed, err %d", (int32)err);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t CmsDiskUsageCheckMemcpy(errno_t err)
{
    if (err != EOK) {
        CMS_LOG_ERR("memcpy_s failed, err %d", (int32)err);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void CmsDiskUsageOnceInit(void)
{
    cm_init_thread_lock(&g_disk_usage_lock);
    if (CMS_DISK_USAGE_MEMSET(&g_diskUsageSnapshot, sizeof(g_diskUsageSnapshot), sizeof(g_diskUsageSnapshot)) !=
        OG_SUCCESS) {
        return;
    }
    g_diskUsageSnapshot.interval_sec = CMS_DISK_USAGE_DEFAULT_INTERVAL;
    g_diskUsageSnapshot.threshold_percent = CMS_DISK_USAGE_DEFAULT_THRESHOLD;
    g_diskUsageSnapshot.readonly_config.protect_enabled = OG_TRUE;
    g_diskUsageSnapshot.readonly_config.cooldown_sec = CMS_DISK_READONLY_DEFAULT_COOLDOWN;
    cms_disk_usage_copy_str(g_diskUsageSnapshot.readonly_config.state, CMS_NAME_BUFFER_SIZE, "NORMAL");
    cms_disk_usage_copy_str(g_diskUsageSnapshot.readonly_config.info, CMS_INFO_BUFFER_SIZE, "not triggered");
    cms_disk_usage_copy_str(g_diskUsageSnapshot.info, CMS_INFO_BUFFER_SIZE, "not collected yet");
}

static void CmsDiskUsageEnsureInit(void)
{
    (void)pthread_once(&g_diskUsageOnce, CmsDiskUsageOnceInit);
}

static void CmsDiskUsageSetInfo(char *dst, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int32 ret = vsnprintf_s(dst, CMS_INFO_BUFFER_SIZE, CMS_INFO_BUFFER_SIZE - 1, fmt, args);
    va_end(args);
    if (ret == -1) {
        dst[0] = '\0';
    }
}

static void cms_disk_usage_set_errno_info(char *dst, const char *prefix, int32 err_no)
{
    CmsDiskUsageSetInfo(dst, "%s, errno %d", prefix, err_no);
}

static char *CmsDiskUsageTrim(char *text)
{
    if (text == NULL) {
        return NULL;
    }
    while (isspace((unsigned char)*text)) {
        text++;
    }
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)*(end - 1))) {
        end--;
    }
    *end = '\0';
    return text;
}

static bool32 cms_disk_usage_str_equal(const char *left, const char *right)
{
    return left != NULL && right != NULL && cm_strcmpi(left, right) == 0;
}

static void cms_disk_usage_copy_str(char *dst, uint32 dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    errno_t err = strncpy_sp(dst, dst_size, src, dst_size - 1);
    if (err != EOK) {
        dst[0] = '\0';
    }
}

static void cms_disk_usage_append_ld_path(char *ldPath, uint32 len, const char *path)
{
    if (ldPath == NULL || len == 0 || path == NULL || path[0] == '\0') {
        return;
    }
    size_t used = strlen(ldPath);
    if (used >= len - 1) {
        return;
    }
    uint32 remain = len - (uint32)used;
    int32 ret = snprintf_s(ldPath + used, remain, remain - 1, ":%s", path);
    if (ret == -1) {
        ldPath[used] = '\0';
    }
}

static bool32 cms_disk_usage_copy_env_value(const char *name, char *value, uint32 value_size)
{
    if (name == NULL || value == NULL || value_size == 0) {
        return OG_FALSE;
    }

    size_t nameLen = strlen(name);
    for (char **envp = g_environ; envp != NULL && *envp != NULL; envp++) {
        if (strncmp(*envp, name, nameLen) != 0 || (*envp)[nameLen] != '=') {
            continue;
        }
        cms_disk_usage_copy_str(value, value_size, *envp + nameLen + 1);
        return value[0] != '\0' ? OG_TRUE : OG_FALSE;
    }
    return OG_FALSE;
}

static uint32 cms_disk_usage_percent_int(uint32 percent_x1000)
{
    return percent_x1000 / CMS_DISK_USAGE_PERCENT_PRECISION;
}

static uint32 cms_disk_usage_percent_frac(uint32 percent_x1000)
{
    return percent_x1000 % CMS_DISK_USAGE_PERCENT_PRECISION;
}

static uint64 cms_disk_usage_bytes_gib_int(uint64 bytes)
{
    return bytes / SIZE_G(1);
}

static uint32 cms_disk_usage_bytes_gib_frac(uint64 bytes)
{
    return (uint32)(((bytes % SIZE_G(1)) * CMS_DISK_USAGE_PERCENT_PRECISION) / SIZE_G(1));
}

static void CmsDiskUsageConfigDefault(CmsDiskUsageConfigT *cfg)
{
    if (CMS_DISK_USAGE_MEMSET(cfg, sizeof(CmsDiskUsageConfigT), sizeof(CmsDiskUsageConfigT)) != OG_SUCCESS) {
        return;
    }
    cfg->protect_enabled = OG_TRUE;
    cfg->interval_sec = CMS_DISK_USAGE_DEFAULT_INTERVAL;
    cfg->threshold_percent = CMS_DISK_USAGE_DEFAULT_THRESHOLD;
    cfg->readonly_cooldown_sec = CMS_DISK_READONLY_DEFAULT_COOLDOWN;
}

static void CmsDiskUsageApplyConfigValue(CmsDiskUsageConfigT *cfg, const char *key, const char *value)
{
    uint32 num_value;
    bool32 bool_value;

    if (cms_disk_usage_str_equal(key, "_DISK_USAGE_PROTECT_ENABLE")) {
        if (cm_str2bool(value, &bool_value) == OG_SUCCESS) {
            cfg->protect_enabled = bool_value;
        }
    } else if (cms_disk_usage_str_equal(key, "_DISK_USAGE_CHECK_INTERVAL")) {
        if (cm_str2uint32(value, &num_value) == OG_SUCCESS && num_value >= CMS_DISK_USAGE_MIN_INTERVAL &&
            num_value <= CMS_DISK_USAGE_MAX_INTERVAL) {
            cfg->interval_sec = num_value;
        }
    } else if (cms_disk_usage_str_equal(key, "_DISK_USAGE_READONLY_COOLDOWN")) {
        if (cm_str2uint32(value, &num_value) == OG_SUCCESS && num_value > 0 &&
            num_value <= CMS_DISK_READONLY_MAX_COOLDOWN) {
            cfg->readonly_cooldown_sec = num_value;
        }
    } else if (cms_disk_usage_str_equal(key, "_DISK_USAGE_THRESHOLD")) {
        if (cm_str2uint32(value, &num_value) == OG_SUCCESS && num_value > 0 &&
            num_value <= CMS_DISK_USAGE_PERCENT_MAX) {
            cfg->threshold_percent = num_value;
        }
    }
}

static void CmsDiskUsageLoadConfig(CmsDiskUsageConfigT *cfg)
{
    CmsDiskUsageConfigDefault(cfg);

    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    int32 ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/cfg/%s",
        g_cms_param->cms_home, CMS_CFG_FILENAME);
    if (ret == -1) {
        CMS_LOG_WAR("build cms disk usage config path failed");
        return;
    }

    FILE *fp = fopen(file_name, "r");
    if (fp == NULL) {
        CMS_LOG_WAR("open cms disk usage config failed, file %s, errno %d", file_name, errno);
        return;
    }

    char line[CMS_FILE_NAME_BUFFER_SIZE * 2];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }
        char *equal = strchr(line, '=');
        if (equal == NULL) {
            continue;
        }
        *equal = '\0';
        char *key = CmsDiskUsageTrim(line);
        char *value = CmsDiskUsageTrim(equal + 1);
        if (key == NULL || value == NULL || key[0] == '\0') {
            continue;
        }
        CmsDiskUsageApplyConfigValue(cfg, key, value);
    }
    (void)fclose(fp);
}

static status_t cms_disk_usage_build_config_path(char *file_name, uint32 len)
{
    int32 ret = snprintf_s(file_name, len, len - 1, "%s/cfg/%s", g_cms_param->cms_home, CMS_CFG_FILENAME);
    if (ret == -1) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static bool32 cms_disk_usage_config_key_equal(char *line, const char *key)
{
    char line_copy[CMS_FILE_NAME_BUFFER_SIZE * 2];
    cms_disk_usage_copy_str(line_copy, sizeof(line_copy), line);
    char *comment = strchr(line_copy, '#');
    if (comment != NULL) {
        *comment = '\0';
    }
    char *equal = strchr(line_copy, '=');
    if (equal == NULL) {
        return OG_FALSE;
    }
    *equal = '\0';
    char *lineKey = CmsDiskUsageTrim(line_copy);
    return cms_disk_usage_str_equal(lineKey, key);
}

static status_t cms_disk_usage_validate_update_value(const char *key, const char *value, char *err_info, uint32 err_len)
{
    (void)err_len;
    bool32 bool_value;
    uint32 num_value;

    if (value == NULL) {
        CmsDiskUsageSetInfo(err_info, "value is null");
        return OG_ERROR;
    }
    if (cms_disk_usage_str_equal(key, "_DISK_USAGE_PROTECT_ENABLE")) {
        if (cm_str2bool(value, &bool_value) != OG_SUCCESS) {
            CmsDiskUsageSetInfo(err_info, "invalid boolean value %s", value);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (cms_disk_usage_str_equal(key, "_DISK_USAGE_CHECK_INTERVAL")) {
        if (cm_str2uint32(value, &num_value) != OG_SUCCESS || num_value < CMS_DISK_USAGE_MIN_INTERVAL ||
            num_value > CMS_DISK_USAGE_MAX_INTERVAL) {
            CmsDiskUsageSetInfo(err_info, "interval must be an integer in [5,3600]");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (cms_disk_usage_str_equal(key, "_DISK_USAGE_READONLY_COOLDOWN")) {
        if (cm_str2uint32(value, &num_value) != OG_SUCCESS || num_value == 0 ||
            num_value > CMS_DISK_READONLY_MAX_COOLDOWN) {
            CmsDiskUsageSetInfo(err_info, "cooldown must be an integer in [1,3600]");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (cms_disk_usage_str_equal(key, "_DISK_USAGE_THRESHOLD")) {
        if (cm_str2uint32(value, &num_value) != OG_SUCCESS || num_value == 0 ||
            num_value > CMS_DISK_USAGE_PERCENT_MAX) {
            CmsDiskUsageSetInfo(err_info, "threshold must be an integer in [1,100]");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    CmsDiskUsageSetInfo(err_info, "unsupported config key %s", key);
    return OG_ERROR;
}

static void CmsDiskUsageWriteUpdateLine(FILE *dst, const char *key, const char *value)
{
    (void)fprintf(dst, "%s = %s\n", key, value);
}

static status_t CmsDiskUsageRewriteConfig(FILE *src, FILE *dst, const char *key, const char *value)
{
    bool32 found = OG_FALSE;
    char line[CMS_FILE_NAME_BUFFER_SIZE * 2];
    while (fgets(line, sizeof(line), src) != NULL) {
        if (cms_disk_usage_config_key_equal(line, key)) {
            CmsDiskUsageWriteUpdateLine(dst, key, value);
            found = OG_TRUE;
        } else {
            (void)fputs(line, dst);
        }
    }
    if (found != OG_TRUE) {
        CmsDiskUsageWriteUpdateLine(dst, key, value);
    }
    return (ferror(src) || ferror(dst)) ? OG_ERROR : OG_SUCCESS;
}

static status_t CmsDiskUsageCloseConfigFiles(FILE *src, FILE *dst, char *errInfo)
{
    status_t ret = OG_SUCCESS;
    (void)fclose(src);
    if (fclose(dst) != 0) {
        ret = OG_ERROR;
        cms_disk_usage_set_errno_info(errInfo, "close temp config failed", errno);
    }
    return ret;
}

static mode_t CmsDiskUsageGetConfigMode(const char *fileName)
{
    struct stat st;
    if (stat(fileName, &st) == 0) {
        return st.st_mode & CMS_DISK_USAGE_FILE_MODE_MASK;
    }
    return S_IRUSR | S_IWUSR;
}

status_t cms_disk_usage_update_config(const char *key, const char *value, char *err_info, uint32 err_len)
{
    if (cms_disk_usage_validate_update_value(key, value, err_info, err_len) != OG_SUCCESS) {
        return OG_ERROR;
    }

    char file_name[CMS_FILE_NAME_BUFFER_SIZE];
    if (cms_disk_usage_build_config_path(file_name, sizeof(file_name)) != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "build cms config path failed");
        return OG_ERROR;
    }

    char tmp_name[CMS_FILE_NAME_BUFFER_SIZE];
    if (snprintf_s(tmp_name, sizeof(tmp_name), sizeof(tmp_name) - 1, "%s.tmp.%d", file_name, (int)getpid()) == -1) {
        CmsDiskUsageSetInfo(err_info, "build temp config path failed");
        return OG_ERROR;
    }

    mode_t mode = CmsDiskUsageGetConfigMode(file_name);

    FILE *src = fopen(file_name, "r");
    if (src == NULL) {
        CmsDiskUsageSetInfo(err_info, "open config failed, file %s, errno %d", file_name, errno);
        return OG_ERROR;
    }
    FILE *dst = fopen(tmp_name, "w");
    if (dst == NULL) {
        (void)fclose(src);
        CmsDiskUsageSetInfo(err_info, "open temp config failed, file %s, errno %d", tmp_name, errno);
        return OG_ERROR;
    }

    status_t ret = CmsDiskUsageRewriteConfig(src, dst, key, value);
    if (ret != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "read or write config failed");
    }
    if (CmsDiskUsageCloseConfigFiles(src, dst, err_info) != OG_SUCCESS) {
        ret = OG_ERROR;
    }
    if (ret != OG_SUCCESS) {
        (void)unlink(tmp_name);
        return OG_ERROR;
    }
    (void)chmod(tmp_name, mode);
    if (rename(tmp_name, file_name) != 0) {
        cms_disk_usage_set_errno_info(err_info, "rename temp config failed", errno);
        (void)unlink(tmp_name);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t cms_disk_usage_update_readonly_config(const char *key, const char *value, char *err_info, uint32 err_len)
{
    return cms_disk_usage_update_config(key, value, err_info, err_len);
}

void CmsDiskUsageGetReadonlyConfig(CmsDiskReadonlyConfigInfoT *config)
{
    CmsDiskUsageConfigT cfg;
    CmsDiskUsageLoadConfig(&cfg);
    CmsDiskUsageFillReadonlyConfig(config, &cfg);
}

static bool32 cms_disk_usage_parse_pgdata_from_argv(char *buf, char *pgdata, uint32 pgdata_size)
{
    char *pos = buf;
    while (pos != NULL && *pos != '\0') {
        char *arg = pos;
        size_t len = strlen(arg);
        pos = arg + len + 1;
        if (strcmp(arg, "-D") == 0 && *pos != '\0') {
            cms_disk_usage_copy_str(pgdata, pgdata_size, pos);
            return OG_TRUE;
        }
        if (strncmp(arg, "-D", CMS_DISK_USAGE_OPT_D_LEN) == 0 && strlen(arg) > CMS_DISK_USAGE_OPT_D_LEN) {
            cms_disk_usage_copy_str(pgdata, pgdata_size, arg + CMS_DISK_USAGE_OPT_D_LEN);
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static bool32 cms_disk_usage_read_pgdata_from_pid(const char *pid, char *pgdata, uint32 pgdata_size)
{
    char path[CMS_FILE_NAME_BUFFER_SIZE];
    int32 ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/cmdline", pid);
    if (ret == -1) {
        return OG_FALSE;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return OG_FALSE;
    }
    char buf[CMS_DISK_USAGE_OUTPUT_SIZE];
    size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
    (void)fclose(fp);
    if (nread == 0) {
        return OG_FALSE;
    }
    buf[nread] = '\0';
    return cms_disk_usage_parse_pgdata_from_argv(buf, pgdata, pgdata_size);
}

static bool32 cms_disk_usage_is_db_process_pid(const char *pid)
{
    char path[CMS_FILE_NAME_BUFFER_SIZE];
    int32 ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/comm", pid);
    if (ret == -1) {
        return OG_FALSE;
    }
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        char comm[CMS_NAME_BUFFER_SIZE] = {0};
        if (fgets(comm, sizeof(comm), fp) != NULL) {
            char *text = CmsDiskUsageTrim(comm);
            if (strcmp(text, "ogracd") == 0) {
                (void)fclose(fp);
                return OG_TRUE;
            }
        }
        (void)fclose(fp);
    }

    ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/cmdline", pid);
    if (ret == -1) {
        return OG_FALSE;
    }
    fp = fopen(path, "rb");
    if (fp == NULL) {
        return OG_FALSE;
    }
    char buf[CMS_DISK_USAGE_OUTPUT_SIZE];
    size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
    (void)fclose(fp);
    if (nread == 0) {
        return OG_FALSE;
    }
    buf[nread] = '\0';
    for (size_t i = 0; i < nread; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    return strstr(buf, "ogracd") != NULL;
}

static void CmsDiskUsageAppendDsscmdLibPath(char *ldPath, uint32 len, const char *dsscmd)
{
    if (dsscmd == NULL || dsscmd[0] == '\0') {
        return;
    }
    char cmdCopy[CMS_FILE_NAME_BUFFER_SIZE];
    cms_disk_usage_copy_str(cmdCopy, sizeof(cmdCopy), dsscmd);
    char *binDir = strrchr(cmdCopy, '/');
    if (binDir == NULL) {
        return;
    }
    *binDir = '\0';
    char *homeEnd = strrchr(cmdCopy, '/');
    if (homeEnd == NULL) {
        return;
    }
    *homeEnd = '\0';
    char cmdLib[CMS_FILE_NAME_BUFFER_SIZE];
    if (snprintf_s(cmdLib, sizeof(cmdLib), sizeof(cmdLib) - 1, "%s/lib", cmdCopy) != -1) {
        cms_disk_usage_append_ld_path(ldPath, len, cmdLib);
    }
}

static void CmsDiskUsagePrepareCmdEnv(const char *dssHome, const char *dsscmd)
{
    if (dssHome == NULL || dssHome[0] == '\0') {
        return;
    }
    (void)setenv("DSS_HOME", dssHome, 1);

    char ldPath[CMS_DISK_USAGE_OUTPUT_SIZE];
    if (snprintf_s(ldPath, sizeof(ldPath), sizeof(ldPath) - 1, "%s/lib", dssHome) == -1) {
        return;
    }
    CmsDiskUsageAppendDsscmdLibPath(ldPath, sizeof(ldPath), dsscmd);

    char oldLd[CMS_DISK_USAGE_OUTPUT_SIZE];
    if (cms_disk_usage_copy_env_value("LD_LIBRARY_PATH", oldLd, sizeof(oldLd)) == OG_TRUE) {
        cms_disk_usage_append_ld_path(ldPath, sizeof(ldPath), oldLd);
    }
    (void)setenv("LD_LIBRARY_PATH", ldPath, 1);
}

static void CmsDiskUsageReadCmdPipe(int32 pipefd, CmsDiskUsageCmdResultT *result, size_t *offset)
{
    while (*offset < sizeof(result->output) - 1) {
        ssize_t nread = read(pipefd, result->output + *offset, sizeof(result->output) - 1 - *offset);
        if (nread <= 0) {
            break;
        }
        *offset += (size_t)nread;
    }
}

static void CmsDiskUsageWaitCmd(pid_t pid, int32 pipefd, uint32 timeoutSec, CmsDiskUsageCmdResultT *result,
    int32 *status)
{
    date_t start = cm_now();
    size_t offset = 0;
    bool32 childDone = OG_FALSE;
    while (childDone == OG_FALSE) {
        CmsDiskUsageReadCmdPipe(pipefd, result, &offset);

        pid_t waitRet = waitpid(pid, status, WNOHANG);
        if (waitRet == pid) {
            childDone = OG_TRUE;
            break;
        }
        if (waitRet < 0) {
            cms_disk_usage_set_errno_info(result->error, "waitpid failed", errno);
            break;
        }
        if ((cm_now() - start) > (date_t)timeoutSec * MICROSECS_PER_SECOND_LL) {
            result->timeout = OG_TRUE;
            CmsDiskUsageSetInfo(result->error, "command timeout");
            break;
        }
        cm_sleep(CMS_DISK_USAGE_WAIT_INTERVAL_MS);
    }
    CmsDiskUsageReadCmdPipe(pipefd, result, &offset);
    result->output[offset] = '\0';
}

static void cms_disk_usage_run_cmd(char *const argv[], const char *dssHome, const char *dsscmd,
    uint32 timeout_sec, CmsDiskUsageCmdResultT *result)
{
    if (CMS_DISK_USAGE_MEMSET(result, sizeof(CmsDiskUsageCmdResultT), sizeof(CmsDiskUsageCmdResultT)) != OG_SUCCESS) {
        return;
    }
    result->return_code = -1;

    int32 pipefd[2];
    if (pipe(pipefd) != 0) {
        cms_disk_usage_set_errno_info(result->error, "pipe failed", errno);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        cms_disk_usage_set_errno_info(result->error, "fork failed", errno);
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        (void)close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        (void)close(pipefd[1]);
        CmsDiskUsagePrepareCmdEnv(dssHome, dsscmd);
        execvp(argv[0], argv);
        _exit(CMS_DISK_USAGE_EXEC_FAILED_CODE);
    }

    (void)close(pipefd[1]);
    int32 flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    int32 status = 0;
    CmsDiskUsageWaitCmd(pid, pipefd[0], timeout_sec, result, &status);
    (void)close(pipefd[0]);

    if (result->timeout == OG_TRUE) {
        return;
    }
    if (WIFEXITED(status)) {
        result->return_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->return_code = CMS_DISK_USAGE_SIGNAL_CODE_BASE + WTERMSIG(status);
    }
    if (result->return_code != 0 && result->error[0] == '\0') {
        CmsDiskUsageSetInfo(result->error, "command return code %d", result->return_code);
    }
}

static bool32 cms_disk_usage_discover_pgdata(char *pgdata, uint32 pgdata_size)
{
    DIR *procDir = opendir("/proc");
    if (procDir == NULL) {
        CMS_LOG_WAR("open /proc failed, errno %d", errno);
        return OG_FALSE;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(procDir)) != NULL) {
        bool32 is_pid = OG_TRUE;
        for (char *p = entry->d_name; *p != '\0'; p++) {
            if (!isdigit((unsigned char)*p)) {
                is_pid = OG_FALSE;
                break;
            }
        }
        if (is_pid != OG_TRUE) {
            continue;
        }
        if (cms_disk_usage_is_db_process_pid(entry->d_name) &&
            cms_disk_usage_read_pgdata_from_pid(entry->d_name, pgdata, pgdata_size)) {
            (void)closedir(procDir);
            return OG_TRUE;
        }
    }
    (void)closedir(procDir);
    return OG_FALSE;
}

static void CmsDiskUsageFillFailedItem(CmsDiskUsageItemT *item, const CmsDiskUsageFailedItemT *failed)
{
    if (CMS_DISK_USAGE_MEMSET(item, sizeof(CmsDiskUsageItemT), sizeof(CmsDiskUsageItemT)) != OG_SUCCESS) {
        return;
    }
    item->valid = OG_TRUE;
    item->collect_success = OG_FALSE;
    item->item_type = failed->item_type;
    item->threshold_percent = failed->threshold;
    item->last_check_time = cm_now();
    cms_disk_usage_copy_str(item->name, CMS_NAME_BUFFER_SIZE, failed->name);
    cms_disk_usage_copy_str(item->source, CMS_FILE_NAME_BUFFER_SIZE, failed->source);
    cms_disk_usage_copy_str(item->info, CMS_INFO_BUFFER_SIZE, failed->info);
}

static void CmsDiskUsageCollectLocal(const CmsDiskUsageConfigT *cfg, CmsDiskUsageItemT *item)
{
    char path[CMS_FILE_NAME_BUFFER_SIZE] = {0};
    if (!cms_disk_usage_discover_pgdata(path, sizeof(path))) {
        CmsDiskUsageFailedItemT failed = {CMS_DISK_USAGE_TYPE_LOCAL, "local", "", cfg->threshold_percent,
            "local disk path discovery failed: no local ogracd process with -D found"};
        CmsDiskUsageFillFailedItem(item, &failed);
        return;
    }

    struct statvfs st;
    if (statvfs(path, &st) != 0) {
        char info[CMS_INFO_BUFFER_SIZE];
        cms_disk_usage_set_errno_info(info, "statvfs failed", errno);
        CmsDiskUsageFailedItemT failed = {CMS_DISK_USAGE_TYPE_LOCAL, "local", path, cfg->threshold_percent, info};
        CmsDiskUsageFillFailedItem(item, &failed);
        return;
    }

    if (CMS_DISK_USAGE_MEMSET(item, sizeof(CmsDiskUsageItemT), sizeof(CmsDiskUsageItemT)) != OG_SUCCESS) {
        return;
    }
    item->valid = OG_TRUE;
    item->collect_success = OG_TRUE;
    item->item_type = CMS_DISK_USAGE_TYPE_LOCAL;
    item->threshold_percent = cfg->threshold_percent;
    item->last_check_time = cm_now();
    item->total_bytes = (uint64)st.f_blocks * (uint64)st.f_frsize;
    item->free_bytes = (uint64)st.f_bavail * (uint64)st.f_frsize;
    item->used_bytes = (item->total_bytes > item->free_bytes) ? (item->total_bytes - item->free_bytes) : 0;
    if (item->total_bytes > 0) {
        item->use_percent_x1000 = (uint32)((item->used_bytes * CMS_DISK_USAGE_PERCENT_SCALE) / item->total_bytes);
    }
    item->alarm = (item->use_percent_x1000 >= item->threshold_percent * CMS_DISK_USAGE_PERCENT_PRECISION);
    cms_disk_usage_copy_str(item->name, CMS_NAME_BUFFER_SIZE, "local");
    cms_disk_usage_copy_str(item->source, CMS_FILE_NAME_BUFFER_SIZE, path);
    cms_disk_usage_copy_str(item->info, CMS_INFO_BUFFER_SIZE, "OK");
}

static double CmsDiskUsageParseSizeGib(const char *token, bool32 *ok)
{
    *ok = OG_FALSE;
    if (token == NULL || token[0] == '\0') {
        return 0;
    }
    char buf[CMS_NAME_BUFFER_SIZE];
    cms_disk_usage_copy_str(buf, sizeof(buf), token);
    char *text = CmsDiskUsageTrim(buf);
    size_t len = strlen(text);
    if (len > 0 && text[len - 1] == '%') {
        return 0;
    }
    char unit = '\0';
    if (len > 0 && isalpha((unsigned char)text[len - 1])) {
        unit = (char)toupper((unsigned char)text[len - 1]);
        text[len - 1] = '\0';
    }
    char *end = NULL;
    double value = strtod(text, &end);
    if (end == text) {
        return 0;
    }
    *ok = OG_TRUE;
    if (unit == 'M') {
        return value / SIZE_K(1);
    }
    if (unit == 'K') {
        return value / SIZE_K(1) / SIZE_K(1);
    }
    if (unit == 'B') {
        return value / CMS_DISK_USAGE_GIB;
    }
    return value;
}

static uint32 cms_disk_usage_parse_percent_x1000(const char *token, bool32 *ok)
{
    *ok = OG_FALSE;
    if (token == NULL || token[0] == '\0') {
        return 0;
    }
    char buf[CMS_NAME_BUFFER_SIZE];
    cms_disk_usage_copy_str(buf, sizeof(buf), token);
    char *text = CmsDiskUsageTrim(buf);
    size_t len = strlen(text);
    if (len > 0 && text[len - 1] == '%') {
        text[len - 1] = '\0';
    }
    char *end = NULL;
    double value = strtod(text, &end);
    if (end == text) {
        return 0;
    }
    *ok = OG_TRUE;
    if (value < 0) {
        value = 0;
    }
    return (uint32)(value * CMS_DISK_USAGE_PERCENT_PRECISION + CMS_DISK_USAGE_ROUNDING);
}

static bool32 cms_disk_usage_looks_like_size(const char *token)
{
    bool32 ok;
    (void)CmsDiskUsageParseSizeGib(token, &ok);
    return ok;
}

static uint64 cms_disk_usage_gib_to_bytes(double gib)
{
    if (gib <= 0) {
        return 0;
    }
    return (uint64)(gib * CMS_DISK_USAGE_GIB + CMS_DISK_USAGE_ROUNDING);
}

static void CmsDiskUsageFinalizeVg(CmsDiskUsageParsedVgT *vg)
{
    if (vg->total_bytes == 0 && vg->used_bytes > 0 && vg->free_bytes > 0) {
        vg->total_bytes = vg->used_bytes + vg->free_bytes;
    }
    if (vg->used_bytes == 0 && vg->total_bytes > 0 && vg->free_bytes > 0 && vg->total_bytes >= vg->free_bytes) {
        vg->used_bytes = vg->total_bytes - vg->free_bytes;
    }
    if (vg->free_bytes == 0 && vg->total_bytes > 0 && vg->used_bytes > 0 && vg->total_bytes >= vg->used_bytes) {
        vg->free_bytes = vg->total_bytes - vg->used_bytes;
    }
    if (vg->use_percent_x1000 == 0 && vg->total_bytes > 0 && vg->used_bytes > 0) {
        vg->use_percent_x1000 = (uint32)((vg->used_bytes * CMS_DISK_USAGE_PERCENT_SCALE) / vg->total_bytes);
    }
}

static CmsDiskUsageParsedVgT *CmsDiskUsageGetOrAddVg(CmsDiskUsageParsedDssT *parsed,
    const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (uint32 i = 0; i < parsed->count; i++) {
        if (strcmp(parsed->vg[i].name, name) == 0) {
            return &parsed->vg[i];
        }
    }
    if (parsed->count >= CMS_DISK_USAGE_MAX_DSS_VG) {
        return NULL;
    }
    CmsDiskUsageParsedVgT *vg = &parsed->vg[parsed->count++];
    if (CMS_DISK_USAGE_MEMSET(vg, sizeof(CmsDiskUsageParsedVgT), sizeof(CmsDiskUsageParsedVgT)) != OG_SUCCESS) {
        return NULL;
    }
    vg->valid = OG_TRUE;
    cms_disk_usage_copy_str(vg->name, CMS_NAME_BUFFER_SIZE, name);
    return vg;
}

static void CmsDiskUsageParseDetailLine(CmsDiskUsageParsedDssT *parsed, char *line,
    CmsDiskUsageParsedVgT **current)
{
    char *colon = strchr(line, ':');
    if (colon == NULL) {
        return;
    }
    *colon = '\0';
    char *key = CmsDiskUsageTrim(line);
    char *value = CmsDiskUsageTrim(colon + 1);
    if (key == NULL || value == NULL) {
        return;
    }
    if (cms_disk_usage_str_equal(key, "vg_name")) {
        *current = CmsDiskUsageGetOrAddVg(parsed, value);
        return;
    }
    if (*current == NULL) {
        return;
    }

    bool32 ok;
    if (cms_disk_usage_str_equal(key, "vg_size") || cms_disk_usage_str_equal(key, "size") ||
        cms_disk_usage_str_equal(key, "total") || cms_disk_usage_str_equal(key, "total_size")) {
        double bytes = strtod(value, NULL);
        (*current)->total_bytes = (uint64)(bytes + CMS_DISK_USAGE_ROUNDING);
    } else if (cms_disk_usage_str_equal(key, "vg_free") || cms_disk_usage_str_equal(key, "free") ||
        cms_disk_usage_str_equal(key, "free_size")) {
        double bytes = strtod(value, NULL);
        (*current)->free_bytes = (uint64)(bytes + CMS_DISK_USAGE_ROUNDING);
    } else if (cms_disk_usage_str_equal(key, "vg_used") || cms_disk_usage_str_equal(key, "used") ||
        cms_disk_usage_str_equal(key, "used_size")) {
        double bytes = strtod(value, NULL);
        (*current)->used_bytes = (uint64)(bytes + CMS_DISK_USAGE_ROUNDING);
    } else if (cms_disk_usage_str_equal(key, "vg_used_percent") || cms_disk_usage_str_equal(key, "used_percent") ||
        cms_disk_usage_str_equal(key, "use_percent") || cms_disk_usage_str_equal(key, "percent")) {
        (*current)->use_percent_x1000 = cms_disk_usage_parse_percent_x1000(value, &ok);
    }
    CmsDiskUsageFinalizeVg(*current);
}

static void cms_disk_usage_split_fields(char *line, char fields[][CMS_NAME_BUFFER_SIZE], uint32 *field_count)
{
    *field_count = 0;
    for (char *p = line; *p != '\0'; p++) {
        if (*p == '|') {
            *p = ' ';
        }
    }
    char *save = NULL;
    char *token = strtok_r(line, " \t\r\n", &save);
    while (token != NULL && *field_count < CMS_DISK_USAGE_MAX_DSS_VG) {
        cms_disk_usage_copy_str(fields[*field_count], CMS_NAME_BUFFER_SIZE, token);
        (*field_count)++;
        token = strtok_r(NULL, " \t\r\n", &save);
    }
}

static void CmsDiskUsageNormalizeKey(char *key)
{
    for (char *p = key; *p != '\0'; p++) {
        if (*p == '-') {
            *p = '_';
        } else {
            *p = (char)toupper((unsigned char)*p);
        }
    }
    char *paren = strchr(key, '(');
    if (paren != NULL) {
        *paren = '\0';
    }
}

static bool32 cms_disk_usage_is_header(char fields[][CMS_NAME_BUFFER_SIZE], uint32 field_count)
{
    bool32 has_size = OG_FALSE;
    bool32 has_used = OG_FALSE;
    for (uint32 i = 0; i < field_count; i++) {
        char key[CMS_NAME_BUFFER_SIZE];
        cms_disk_usage_copy_str(key, sizeof(key), fields[i]);
        CmsDiskUsageNormalizeKey(key);
        if (strcmp(key, "TOTAL") == 0 || strcmp(key, "SIZE") == 0 || strcmp(key, "VG_SIZE") == 0) {
            has_size = OG_TRUE;
        }
        if (strcmp(key, "USED") == 0 || strcmp(key, "USE%") == 0 || strcmp(key, "PERCENT") == 0 ||
            strcmp(key, "VG_USED") == 0 || strcmp(key, "VG_USED_PERCENT") == 0) {
            has_used = OG_TRUE;
        }
    }
    return has_size && has_used;
}

static void cms_disk_usage_parse_table_with_header(CmsDiskUsageParsedVgT *vg,
    char header[][CMS_NAME_BUFFER_SIZE], uint32 header_count, char fields[][CMS_NAME_BUFFER_SIZE], uint32 field_count)
{
    for (uint32 i = 0; i < header_count && i < field_count; i++) {
        char key[CMS_NAME_BUFFER_SIZE];
        cms_disk_usage_copy_str(key, sizeof(key), header[i]);
        CmsDiskUsageNormalizeKey(key);
        bool32 ok;
        if (strcmp(key, "TOTAL") == 0 || strcmp(key, "TOTAL_SIZE") == 0 || strcmp(key, "SIZE") == 0 ||
            strcmp(key, "VG_SIZE") == 0) {
            vg->total_bytes = cms_disk_usage_gib_to_bytes(CmsDiskUsageParseSizeGib(fields[i], &ok));
        } else if (strcmp(key, "USED") == 0 || strcmp(key, "USED_SIZE") == 0 || strcmp(key, "VG_USED") == 0) {
            vg->used_bytes = cms_disk_usage_gib_to_bytes(CmsDiskUsageParseSizeGib(fields[i], &ok));
        } else if (strcmp(key, "FREE") == 0 || strcmp(key, "FREE_SIZE") == 0 || strcmp(key, "VG_FREE") == 0 ||
            strcmp(key, "AVAIL") == 0 || strcmp(key, "AVAILABLE") == 0) {
            vg->free_bytes = cms_disk_usage_gib_to_bytes(CmsDiskUsageParseSizeGib(fields[i], &ok));
        } else if (strcmp(key, "USE%") == 0 || strcmp(key, "USED%") == 0 || strcmp(key, "PERCENT") == 0 ||
            strcmp(key, "USE_RATE") == 0 || strcmp(key, "USED_RATE") == 0 || strcmp(key, "USAGE") == 0 ||
            strcmp(key, "USED_PERCENT") == 0 || strcmp(key, "VG_USED_PERCENT") == 0) {
            vg->use_percent_x1000 = cms_disk_usage_parse_percent_x1000(fields[i], &ok);
        }
    }
    CmsDiskUsageFinalizeVg(vg);
}

static void cms_disk_usage_parse_table_fallback(CmsDiskUsageParsedVgT *vg,
    char fields[][CMS_NAME_BUFFER_SIZE], uint32 field_count)
{
    char sizes[CMS_DISK_USAGE_MAX_DSS_VG][CMS_NAME_BUFFER_SIZE];
    uint32 size_count = 0;
    for (uint32 i = 1; i < field_count && size_count < CMS_DISK_USAGE_MAX_DSS_VG; i++) {
        if (cms_disk_usage_looks_like_size(fields[i])) {
            cms_disk_usage_copy_str(sizes[size_count], CMS_NAME_BUFFER_SIZE, fields[i]);
            size_count++;
        }
    }

    bool32 ok;
    if (size_count >= CMS_DISK_USAGE_FALLBACK_SIZE_EXT_COUNT) {
        vg->total_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_EXT_TOTAL_IDX], &ok));
        vg->free_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_EXT_FREE_IDX], &ok));
        vg->used_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_EXT_USED_IDX], &ok));
        vg->use_percent_x1000 =
            cms_disk_usage_parse_percent_x1000(sizes[CMS_DISK_USAGE_FALLBACK_EXT_PERCENT_IDX], &ok);
    } else if (size_count >= CMS_DISK_USAGE_FALLBACK_SIZE_NORMAL_COUNT) {
        vg->total_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_TOTAL_IDX], &ok));
        vg->free_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_FREE_IDX], &ok));
        vg->used_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_USED_IDX], &ok));
        vg->use_percent_x1000 =
            cms_disk_usage_parse_percent_x1000(sizes[CMS_DISK_USAGE_FALLBACK_PERCENT_IDX], &ok);
    } else if (size_count == CMS_DISK_USAGE_FALLBACK_SIZE_MIN_COUNT) {
        vg->total_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_TOTAL_IDX], &ok));
        vg->free_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_FREE_IDX], &ok));
        vg->used_bytes = cms_disk_usage_gib_to_bytes(
            CmsDiskUsageParseSizeGib(sizes[CMS_DISK_USAGE_FALLBACK_USED_IDX], &ok));
    }
    CmsDiskUsageFinalizeVg(vg);
}

static void CmsDiskUsageParseDssTableLine(CmsDiskUsageParsedDssT *parsed, char *text,
    char header[][CMS_NAME_BUFFER_SIZE], uint32 *headerCount)
{
    char fields[CMS_DISK_USAGE_MAX_DSS_VG][CMS_NAME_BUFFER_SIZE] = {{0}};
    uint32 fieldCount = 0;
    cms_disk_usage_split_fields(text, fields, &fieldCount);
    if (fieldCount == 0) {
        return;
    }
    if (cms_disk_usage_is_header(fields, fieldCount)) {
        if (CMS_DISK_USAGE_MEMCPY(header, CMS_DISK_USAGE_MAX_DSS_VG * CMS_NAME_BUFFER_SIZE,
            fields, CMS_DISK_USAGE_MAX_DSS_VG * CMS_NAME_BUFFER_SIZE) == OG_SUCCESS) {
            *headerCount = fieldCount;
        }
        return;
    }
    if (strchr(fields[0], ':') != NULL || cms_disk_usage_looks_like_size(fields[0]) ||
        cms_disk_usage_str_equal(fields[0], "succeed")) {
        return;
    }

    CmsDiskUsageParsedVgT *vg = CmsDiskUsageGetOrAddVg(parsed, fields[0]);
    if (vg == NULL) {
        return;
    }
    if (*headerCount > 0) {
        cms_disk_usage_parse_table_with_header(vg, header, *headerCount, fields, fieldCount);
    }
    if (vg->total_bytes == 0 && vg->used_bytes == 0 && vg->free_bytes == 0) {
        cms_disk_usage_parse_table_fallback(vg, fields, fieldCount);
    }
}

static void CmsDiskUsageParseDssOutput(const char *output, CmsDiskUsageParsedDssT *parsed)
{
    if (CMS_DISK_USAGE_MEMSET(parsed, sizeof(CmsDiskUsageParsedDssT), sizeof(CmsDiskUsageParsedDssT)) != OG_SUCCESS) {
        return;
    }

    char buf[CMS_DISK_USAGE_OUTPUT_SIZE * 2];
    cms_disk_usage_copy_str(buf, sizeof(buf), output);
    char header[CMS_DISK_USAGE_MAX_DSS_VG][CMS_NAME_BUFFER_SIZE] = {{0}};
    uint32 header_count = 0;
    CmsDiskUsageParsedVgT *current = NULL;

    char *save = NULL;
    char *line = strtok_r(buf, "\n", &save);
    while (line != NULL) {
        char line_copy[CMS_FILE_NAME_BUFFER_SIZE * 2];
        cms_disk_usage_copy_str(line_copy, sizeof(line_copy), line);
        char *text = CmsDiskUsageTrim(line_copy);
        if (text == NULL || text[0] == '\0') {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        if (strchr(text, ':') != NULL) {
            CmsDiskUsageParseDetailLine(parsed, text, &current);
            line = strtok_r(NULL, "\n", &save);
            continue;
        }

        CmsDiskUsageParseDssTableLine(parsed, text, header, &header_count);
        line = strtok_r(NULL, "\n", &save);
    }
}

static bool32 cms_disk_usage_read_env_from_pid(const char *pid, const char *env_name, char *value, uint32 value_size)
{
    char path[CMS_FILE_NAME_BUFFER_SIZE];
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/environ", pid) == -1) {
        return OG_FALSE;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return OG_FALSE;
    }
    char buf[CMS_DISK_USAGE_OUTPUT_SIZE];
    size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
    (void)fclose(fp);
    if (nread == 0) {
        return OG_FALSE;
    }
    buf[nread] = '\0';

    size_t envLen = strlen(env_name);
    char *pos = buf;
    while (pos < buf + nread && *pos != '\0') {
        if (strncmp(pos, env_name, envLen) == 0 && pos[envLen] == '=') {
            cms_disk_usage_copy_str(value, value_size, pos + envLen + 1);
            return value[0] != '\0' ? OG_TRUE : OG_FALSE;
        }
        pos += strlen(pos) + 1;
    }
    return OG_FALSE;
}

static bool32 cms_disk_usage_is_dss_process_pid(const char *pid)
{
    char path[CMS_FILE_NAME_BUFFER_SIZE];
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%s/comm", pid) == -1) {
        return OG_FALSE;
    }
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        char comm[CMS_NAME_BUFFER_SIZE] = {0};
        if (fgets(comm, sizeof(comm), fp) != NULL) {
            char *text = CmsDiskUsageTrim(comm);
            if (strcmp(text, "dssserver") == 0) {
                (void)fclose(fp);
                return OG_TRUE;
            }
        }
        (void)fclose(fp);
    }
    return OG_FALSE;
}

static bool32 cms_disk_usage_read_dss_home_from_pid(const char *pid, char *dssHome, uint32 len)
{
    if (cms_disk_usage_read_env_from_pid(pid, "DSS_HOME", dssHome, len) == OG_TRUE) {
        return OG_TRUE;
    }
    return cms_disk_usage_read_pgdata_from_pid(pid, dssHome, len);
}

static bool32 cms_disk_usage_discover_dss_home_from_proc(char *dssHome, uint32 len)
{
    DIR *procDir = opendir("/proc");
    if (procDir == NULL) {
        CMS_LOG_WAR("open /proc failed when discover DSS_HOME, errno %d", errno);
        return OG_FALSE;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(procDir)) != NULL) {
        bool32 is_pid = OG_TRUE;
        for (char *p = entry->d_name; *p != '\0'; p++) {
            if (!isdigit((unsigned char)*p)) {
                is_pid = OG_FALSE;
                break;
            }
        }
        if (is_pid == OG_TRUE && cms_disk_usage_is_dss_process_pid(entry->d_name) == OG_TRUE &&
            cms_disk_usage_read_dss_home_from_pid(entry->d_name, dssHome, len) == OG_TRUE) {
            (void)closedir(procDir);
            return OG_TRUE;
        }
    }
    (void)closedir(procDir);
    return OG_FALSE;
}

static bool32 cms_disk_usage_dir_exists(const char *path)
{
    struct stat st;
    return (path != NULL && path[0] != '\0' && stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? OG_TRUE : OG_FALSE;
}

static bool32 cms_disk_usage_discover_dss_home_from_cms_home(char *dssHome, uint32 len)
{
    char home[CMS_FILE_NAME_BUFFER_SIZE];
    cms_disk_usage_copy_str(home, sizeof(home), g_cms_param->cms_home);
    char *last = strrchr(home, '/');
    if (last == NULL) {
        return OG_FALSE;
    }
    *last = '\0';

    char candidate[CMS_FILE_NAME_BUFFER_SIZE];
    if (snprintf_s(candidate, sizeof(candidate), sizeof(candidate) - 1, "%s/dss", home) != -1 &&
        cms_disk_usage_dir_exists(candidate) == OG_TRUE) {
        cms_disk_usage_copy_str(dssHome, len, candidate);
        return OG_TRUE;
    }
    if (snprintf_s(candidate, sizeof(candidate), sizeof(candidate) - 1, "%s/ograc/dss", home) != -1 &&
        cms_disk_usage_dir_exists(candidate) == OG_TRUE) {
        cms_disk_usage_copy_str(dssHome, len, candidate);
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 cms_disk_usage_resolve_dss_home(char *dssHome, uint32 len, char *info, uint32 info_len)
{
    (void)info_len;
    char envHome[CMS_FILE_NAME_BUFFER_SIZE];
    if (cms_disk_usage_copy_env_value("DSS_HOME", envHome, sizeof(envHome)) == OG_TRUE) {
        cms_disk_usage_copy_str(dssHome, len, envHome);
        CmsDiskUsageSetInfo(info, "DSS_HOME discovered from environment");
        return OG_TRUE;
    }
    if (cms_disk_usage_discover_dss_home_from_proc(dssHome, len) == OG_TRUE) {
        CmsDiskUsageSetInfo(info, "DSS_HOME discovered from dssserver process");
        return OG_TRUE;
    }
    if (cms_disk_usage_discover_dss_home_from_cms_home(dssHome, len) == OG_TRUE) {
        CmsDiskUsageSetInfo(info, "DSS_HOME discovered from install structure");
        return OG_TRUE;
    }
    CmsDiskUsageSetInfo(info, "DSS_HOME discovery failed: env/process/install structure not found");
    return OG_FALSE;
}

static bool32 cms_disk_usage_find_cmd_in_path(const char *cmd, char *path, uint32 len)
{
    char envPath[CMS_DISK_USAGE_OUTPUT_SIZE];
    if (cms_disk_usage_copy_env_value("PATH", envPath, sizeof(envPath)) != OG_TRUE) {
        return OG_FALSE;
    }
    char buf[CMS_DISK_USAGE_OUTPUT_SIZE];
    cms_disk_usage_copy_str(buf, sizeof(buf), envPath);
    char *save = NULL;
    char *dir = strtok_r(buf, ":", &save);
    while (dir != NULL) {
        char candidate[CMS_FILE_NAME_BUFFER_SIZE];
        if (snprintf_s(candidate, sizeof(candidate), sizeof(candidate) - 1, "%s/%s", dir, cmd) != -1 &&
            access(candidate, X_OK) == 0) {
            cms_disk_usage_copy_str(path, len, candidate);
            return OG_TRUE;
        }
        dir = strtok_r(NULL, ":", &save);
    }
    return OG_FALSE;
}

static bool32 cms_disk_usage_resolve_dsscmd(const char *dssHome, char *dsscmd, uint32 len, char *info,
    uint32 info_len)
{
    (void)info_len;
    if (dssHome != NULL && dssHome[0] != '\0') {
        char candidate[CMS_FILE_NAME_BUFFER_SIZE];
        if (snprintf_s(candidate, sizeof(candidate), sizeof(candidate) - 1, "%s/bin/dsscmd", dssHome) != -1 &&
            access(candidate, X_OK) == 0) {
            cms_disk_usage_copy_str(dsscmd, len, candidate);
            CmsDiskUsageSetInfo(info, "dsscmd discovered from DSS_HOME");
            return OG_TRUE;
        }
    }
    if (cms_disk_usage_find_cmd_in_path("dsscmd", dsscmd, len) == OG_TRUE) {
        CmsDiskUsageSetInfo(info, "dsscmd discovered from PATH");
        return OG_TRUE;
    }
    CmsDiskUsageSetInfo(info, "dsscmd discovery failed: %s/bin/dsscmd and PATH dsscmd not found",
        dssHome == NULL ? "" : dssHome);
    return OG_FALSE;
}

static bool32 CmsDiskUsageTryBuildUds(char *line, char *uds, uint32 len)
{
    char *text = CmsDiskUsageTrim(line);
    if (text == NULL || text[0] == '#' || text[0] == '\0') {
        return OG_FALSE;
    }
    if (strncmp(text, "LSNR_PATH", strlen("LSNR_PATH")) != 0) {
        return OG_FALSE;
    }
    char *equal = strchr(text, '=');
    if (equal == NULL) {
        return OG_FALSE;
    }
    char *value = CmsDiskUsageTrim(equal + 1);
    if (value == NULL || value[0] == '\0') {
        return OG_FALSE;
    }
    int32 ret = snprintf_s(uds, len, len - 1, "UDS:%s/%s", value, CMS_DISK_USAGE_DSS_SOCKET);
    if (ret == -1) {
        uds[0] = '\0';
        return OG_FALSE;
    }
    return OG_TRUE;
}

static void CmsDiskUsageReadLsnrPath(const char *dssHome, char *uds, uint32 len)
{
    if (dssHome == NULL || dssHome[0] == '\0') {
        return;
    }
    char ini_path[CMS_FILE_NAME_BUFFER_SIZE];
    if (snprintf_s(ini_path, sizeof(ini_path), sizeof(ini_path) - 1, "%s/cfg/dss_inst.ini", dssHome) == -1) {
        return;
    }
    FILE *fp = fopen(ini_path, "r");
    if (fp == NULL) {
        return;
    }
    char line[CMS_FILE_NAME_BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (CmsDiskUsageTryBuildUds(line, uds, len) == OG_TRUE) {
            break;
        }
    }
    (void)fclose(fp);
}

static bool32 cms_disk_usage_resolve_uds(const char *dssHome, char *uds, uint32 len)
{
    CmsDiskUsageReadLsnrPath(dssHome, uds, len);
    if (uds[0] != '\0') {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void CmsDiskUsageAddDssItem(CmsDiskUsageSnapshotT *snapshot, const CmsDiskUsageConfigT *cfg,
    const char *dsscmd, CmsDiskUsageParsedVgT *vg, const char *info)
{
    if (snapshot->dss_count >= CMS_DISK_USAGE_MAX_DSS_VG || vg == NULL) {
        return;
    }
    CmsDiskUsageItemT *item = &snapshot->dss[snapshot->dss_count++];
    if (CMS_DISK_USAGE_MEMSET(item, sizeof(CmsDiskUsageItemT), sizeof(CmsDiskUsageItemT)) != OG_SUCCESS) {
        return;
    }
    item->valid = OG_TRUE;
    item->collect_success = OG_TRUE;
    item->item_type = CMS_DISK_USAGE_TYPE_DSS;
    item->threshold_percent = cfg->threshold_percent;
    item->last_check_time = cm_now();
    item->total_bytes = vg->total_bytes;
    item->used_bytes = vg->used_bytes;
    item->free_bytes = vg->free_bytes;
    item->use_percent_x1000 = vg->use_percent_x1000;
    item->alarm = (item->use_percent_x1000 >= item->threshold_percent * CMS_DISK_USAGE_PERCENT_PRECISION);
    cms_disk_usage_copy_str(item->name, CMS_NAME_BUFFER_SIZE, vg->name);
    cms_disk_usage_copy_str(item->source, CMS_FILE_NAME_BUFFER_SIZE, dsscmd);
    cms_disk_usage_copy_str(item->info, CMS_INFO_BUFFER_SIZE, info);
}

static bool32 CmsDiskUsageResolveDssCtx(const CmsDiskUsageConfigT *cfg, CmsDiskUsageSnapshotT *snapshot,
    CmsDiskUsageDssCtxT *ctx)
{
    if (CMS_DISK_USAGE_MEMSET(ctx, sizeof(CmsDiskUsageDssCtxT), sizeof(CmsDiskUsageDssCtxT)) != OG_SUCCESS) {
        return OG_FALSE;
    }
    if (cms_disk_usage_resolve_dss_home(ctx->dssHome, sizeof(ctx->dssHome), ctx->homeInfo,
        sizeof(ctx->homeInfo)) != OG_TRUE) {
        CmsDiskUsageFailedItemT failed = {CMS_DISK_USAGE_TYPE_DSS, "dss", "", cfg->threshold_percent, ctx->homeInfo};
        CmsDiskUsageFillFailedItem(&snapshot->dss[snapshot->dss_count++], &failed);
        return OG_FALSE;
    }
    if (cms_disk_usage_resolve_dsscmd(ctx->dssHome, ctx->dsscmd, sizeof(ctx->dsscmd), ctx->cmdInfo,
        sizeof(ctx->cmdInfo)) != OG_TRUE) {
        CmsDiskUsageFailedItemT failed = {CMS_DISK_USAGE_TYPE_DSS, "dss", ctx->dssHome, cfg->threshold_percent,
            ctx->cmdInfo};
        CmsDiskUsageFillFailedItem(&snapshot->dss[snapshot->dss_count++], &failed);
        return OG_FALSE;
    }
    ctx->udsFound = cms_disk_usage_resolve_uds(ctx->dssHome, ctx->uds, sizeof(ctx->uds));
    return OG_TRUE;
}

static void CmsDiskUsageRunDssCmds(CmsDiskUsageDssCtxT *ctx, CmsDiskUsageCmdResultT *detail,
    CmsDiskUsageCmdResultT *table)
{
    char *argvDetail[CMS_DISK_USAGE_DSS_CMD_ARG_COUNT] = {ctx->dsscmd, "lsvg", "-t", "d"};
    char *argvTable[CMS_DISK_USAGE_DSS_CMD_ARG_COUNT] = {ctx->dsscmd, "lsvg", "-m", "G"};
    uint32 detailIdx = CMS_DISK_USAGE_DSS_CMD_BASE_ARG_COUNT;
    uint32 tableIdx = CMS_DISK_USAGE_DSS_CMD_BASE_ARG_COUNT;
    if (ctx->udsFound == OG_TRUE && ctx->uds[0] != '\0') {
        argvDetail[detailIdx++] = "-U";
        argvDetail[detailIdx++] = ctx->uds;
        argvTable[tableIdx++] = "-U";
        argvTable[tableIdx++] = ctx->uds;
    }
    cms_disk_usage_run_cmd(argvDetail, ctx->dssHome, ctx->dsscmd, CMS_DISK_USAGE_CMD_TIMEOUT, detail);
    cms_disk_usage_run_cmd(argvTable, ctx->dssHome, ctx->dsscmd, CMS_DISK_USAGE_CMD_TIMEOUT, table);
}

static void CmsDiskUsageCollectDss(const CmsDiskUsageConfigT *cfg, CmsDiskUsageSnapshotT *snapshot)
{
    CmsDiskUsageDssCtxT ctx;
    if (CmsDiskUsageResolveDssCtx(cfg, snapshot, &ctx) != OG_TRUE) {
        return;
    }
    CmsDiskUsageCmdResultT detail;
    CmsDiskUsageCmdResultT table;
    CmsDiskUsageRunDssCmds(&ctx, &detail, &table);

    char combined[CMS_DISK_USAGE_OUTPUT_SIZE * 2];
    combined[0] = '\0';
    int32 ret = snprintf_s(combined, sizeof(combined), sizeof(combined) - 1, "%s\n%s", detail.output, table.output);
    if (ret == -1) {
        combined[0] = '\0';
    }

    CmsDiskUsageParsedDssT parsed;
    CmsDiskUsageParseDssOutput(combined, &parsed);
    if (parsed.count == 0) {
        const char *info = detail.error[0] != '\0' ? detail.error : table.error;
        if (info == NULL || info[0] == '\0') {
            info = "no VG parsed from dsscmd lsvg";
        }
        CmsDiskUsageFailedItemT failed = {CMS_DISK_USAGE_TYPE_DSS, "dss", ctx.dsscmd, cfg->threshold_percent, info};
        CmsDiskUsageFillFailedItem(&snapshot->dss[snapshot->dss_count++], &failed);
        return;
    }

    for (uint32 i = 0; i < parsed.count && snapshot->dss_count < CMS_DISK_USAGE_MAX_DSS_VG; i++) {
        CmsDiskUsageAddDssItem(snapshot, cfg, ctx.dsscmd, &parsed.vg[i],
            ctx.udsFound == OG_TRUE ? "discovered from environment" : "discovered without UDS");
    }
}

static void CmsDiskUsageFillReadonlyConfig(CmsDiskReadonlyConfigInfoT *info,
    const CmsDiskUsageConfigT *cfg)
{
    if (CMS_DISK_USAGE_MEMSET(info, sizeof(CmsDiskReadonlyConfigInfoT), sizeof(CmsDiskReadonlyConfigInfoT)) !=
        OG_SUCCESS) {
        return;
    }
    info->protect_enabled = cfg->protect_enabled;
    info->cooldown_sec = cfg->readonly_cooldown_sec;
    info->last_trigger_time = g_disk_readonly_last_trigger_time;
    info->last_recover_time = g_disk_readonly_last_recover_time;
    info->last_action_time = g_disk_readonly_last_action_time;
    cms_disk_usage_copy_str(info->state, CMS_NAME_BUFFER_SIZE, g_disk_readonly_state);
    cms_disk_usage_copy_str(info->info, CMS_INFO_BUFFER_SIZE, g_disk_readonly_info);
}

static void cms_disk_usage_build_item_id(const CmsDiskUsageItemT *item, char *id, uint32 id_len)
{
    const char *type = (item->item_type == CMS_DISK_USAGE_TYPE_LOCAL) ? "LOCAL" : "DSS";
    int32 ret = snprintf_s(id, id_len, id_len - 1, "%s:%s", type, item->name);
    if (ret == -1) {
        id[0] = '\0';
    }
}

static void cms_disk_usage_append_item_id(const CmsDiskUsageItemT *item, char *names, uint32 names_len)
{
    char id[CMS_NAME_BUFFER_SIZE * 2];
    cms_disk_usage_build_item_id(item, id, sizeof(id));

    size_t used = strlen(names);
    if (used >= names_len - 1) {
        return;
    }
    uint32 remain = names_len - (uint32)used;
    if (used == 0) {
        int32 ret = snprintf_s(names + used, remain, remain - 1, "%s", id);
        if (ret == -1) {
            names[used] = '\0';
        }
    } else {
        int32 ret = snprintf_s(names + used, remain, remain - 1, ",%s", id);
        if (ret == -1) {
            names[used] = '\0';
        }
    }
}

static CmsDiskUsageItemT *CmsDiskUsageFindItemById(CmsDiskUsageSnapshotT *snapshot, const char *id)
{
    char item_id[CMS_NAME_BUFFER_SIZE * 2];
    if (snapshot->local.valid == OG_TRUE) {
        cms_disk_usage_build_item_id(&snapshot->local, item_id, sizeof(item_id));
        if (strcmp(item_id, id) == 0) {
            return &snapshot->local;
        }
    }
    for (uint32 i = 0; i < snapshot->dss_count; i++) {
        if (snapshot->dss[i].valid != OG_TRUE) {
            continue;
        }
        cms_disk_usage_build_item_id(&snapshot->dss[i], item_id, sizeof(item_id));
        if (strcmp(item_id, id) == 0) {
            return &snapshot->dss[i];
        }
    }
    return NULL;
}

static bool32 cms_disk_usage_has_success_alarm(CmsDiskUsageSnapshotT *snapshot, char *alarm_items,
    uint32 alarm_items_len)
{
    bool32 has_alarm = OG_FALSE;
    if (snapshot->local.valid == OG_TRUE && snapshot->local.collect_success == OG_TRUE &&
        snapshot->local.alarm == OG_TRUE) {
        cms_disk_usage_append_item_id(&snapshot->local, alarm_items, alarm_items_len);
        has_alarm = OG_TRUE;
    }
    for (uint32 i = 0; i < snapshot->dss_count; i++) {
        CmsDiskUsageItemT *item = &snapshot->dss[i];
        if (item->valid == OG_TRUE && item->collect_success == OG_TRUE && item->alarm == OG_TRUE) {
            cms_disk_usage_append_item_id(item, alarm_items, alarm_items_len);
            has_alarm = OG_TRUE;
        }
    }
    return has_alarm;
}

static bool32 cms_disk_usage_all_success_items_recovered(CmsDiskUsageSnapshotT *snapshot)
{
    uint32 success_count = 0;
    if (snapshot->local.valid == OG_TRUE && snapshot->local.collect_success == OG_TRUE) {
        success_count++;
        if (snapshot->local.alarm == OG_TRUE) {
            return OG_FALSE;
        }
    }
    for (uint32 i = 0; i < snapshot->dss_count; i++) {
        CmsDiskUsageItemT *item = &snapshot->dss[i];
        if (item->valid != OG_TRUE || item->collect_success != OG_TRUE) {
            continue;
        }
        success_count++;
        if (item->alarm == OG_TRUE) {
            return OG_FALSE;
        }
    }
    return success_count > 0 ? OG_TRUE : OG_FALSE;
}

static bool32 cms_disk_usage_trigger_items_recovered(CmsDiskUsageSnapshotT *snapshot)
{
    if (g_disk_readonly_trigger_items[0] == '\0') {
        return OG_TRUE;
    }
    char buf[CMS_FILE_NAME_BUFFER_SIZE];
    cms_disk_usage_copy_str(buf, sizeof(buf), g_disk_readonly_trigger_items);
    char *save = NULL;
    char *token = strtok_r(buf, ",", &save);
    while (token != NULL) {
        char *id = CmsDiskUsageTrim(token);
        CmsDiskUsageItemT *item = CmsDiskUsageFindItemById(snapshot, id);
        if (item == NULL || item->collect_success != OG_TRUE || item->alarm == OG_TRUE) {
            return OG_FALSE;
        }
        token = strtok_r(NULL, ",", &save);
    }
    return OG_TRUE;
}

static bool32 cms_disk_usage_readwrite_should_recover(CmsDiskUsageSnapshotT *snapshot)
{
    return (cms_disk_usage_all_success_items_recovered(snapshot) == OG_TRUE &&
        cms_disk_usage_trigger_items_recovered(snapshot) == OG_TRUE) ? OG_TRUE : OG_FALSE;
}

static status_t cms_disk_usage_find_local_db_session(uint64 *session_id, char *err_info, uint32 err_len)
{
    cms_res_status_list_t stat_list;
    if (CMS_DISK_USAGE_MEMSET(&stat_list, sizeof(stat_list), sizeof(stat_list)) != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "init DB resource status failed");
        return OG_ERROR;
    }

    if (cms_get_cluster_stat_bytype(CMS_RES_TYPE_DB, 0, &stat_list) != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "get DB resource status failed");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < stat_list.inst_count; i++) {
        cms_res_status_t *stat = &stat_list.inst_list[i];
        if (stat->node_id == g_cms_param->node_id && stat->stat == CMS_RES_ONLINE &&
            stat->session_id != (uint64)CMS_CLI_INVALID_SESS_ID) {
            *session_id = stat->session_id;
            return OG_SUCCESS;
        }
    }

    CmsDiskUsageSetInfo(err_info, "local DB resource is not online or not registered");
    return OG_ERROR;
}

static status_t cms_disk_usage_execute_readmode_message(const CmsDiskUsageConfigT *cfg, uint32 action,
    const char *items, char *err_info, uint32 err_len)
{
    uint64 session_id = 0;
    if (cms_disk_usage_find_local_db_session(&session_id, err_info, err_len) != OG_SUCCESS) {
        return OG_ERROR;
    }

    CmsCliMsgReqReadmodeSwitchT req;
    CmsCliMsgResReadmodeSwitchT res;
    if (CMS_DISK_USAGE_MEMSET(&req, sizeof(req), sizeof(req)) != OG_SUCCESS ||
        CMS_DISK_USAGE_MEMSET(&res, sizeof(res), sizeof(res)) != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "init readmode message failed");
        return OG_ERROR;
    }

    req.head.msg_type = CMS_CLI_MSG_REQ_READMODE_SWITCH;
    req.head.msg_size = sizeof(CmsCliMsgReqReadmodeSwitchT);
    req.head.msg_version = CMS_MSG_VERSION;
    req.head.msg_seq = cm_now();
    req.head.src_node = g_cms_param->node_id;
    req.head.dest_node = g_cms_param->node_id;
    req.head.uds_sid = session_id;
    req.action = action;
    req.reason = CMS_READMODE_REASON_DISK_USAGE;
    req.timeout_sec = CMS_DISK_USAGE_CMD_TIMEOUT;
    req.threshold = cfg->threshold_percent;
    cms_disk_usage_copy_str(req.vg_names, sizeof(req.vg_names), items == NULL ? "" : items);
    cms_disk_usage_copy_str(req.match_mode, sizeof(req.match_mode), "ANY");
    int32 printRet = snprintf_s(req.detail, sizeof(req.detail), sizeof(req.detail) - 1,
        "disk usage action %s, objects %s, mode MESSAGE, match ANY, threshold %u",
        action == CMS_READMODE_ACTION_READONLY ? "READONLY" : "READWRITE", req.vg_names, req.threshold);
    if (printRet == -1) {
        req.detail[0] = '\0';
    }

    status_t ret = cms_uds_srv_request(&req.head, &res.head, sizeof(res),
        CMS_DISK_USAGE_CMD_TIMEOUT * MILLISECS_PER_SECOND);
    if (ret != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "send readmode message failed, ret %d", ret);
        return OG_ERROR;
    }
    res.info[CMS_MAX_INFO_SIZE - 1] = '\0';
    if (res.result != OG_SUCCESS) {
        CmsDiskUsageSetInfo(err_info, "readmode message failed, result %d, info %s", res.result, res.info);
        return OG_ERROR;
    }
    CmsDiskUsageSetInfo(err_info, "readmode message succeed, info %s", res.info);
    return OG_SUCCESS;
}

static status_t CmsDiskUsageExecuteReadmodeAction(const CmsDiskUsageConfigT *cfg, bool32 toReadonly,
    const char *items, char *err_info, uint32 err_len)
{
    return cms_disk_usage_execute_readmode_message(cfg,
        toReadonly == OG_TRUE ? CMS_READMODE_ACTION_READONLY : CMS_READMODE_ACTION_READWRITE,
        items, err_info, err_len);
}

static status_t cms_disk_usage_execute_readwrite_recover(const CmsDiskUsageConfigT *cfg, const char *action,
    char *err_info, uint32 err_len)
{
    date_t now = cm_now();
    g_disk_readonly_last_action_time = now;
    char detail[CMS_INFO_BUFFER_SIZE] = {0};
    status_t ret = CmsDiskUsageExecuteReadmodeAction(cfg, OG_FALSE, g_disk_readonly_trigger_items, detail,
        sizeof(detail));
    if (ret == OG_SUCCESS) {
        char recovered_items[CMS_FILE_NAME_BUFFER_SIZE];
        cms_disk_usage_copy_str(recovered_items, sizeof(recovered_items), g_disk_readonly_trigger_items);
        g_disk_readonly_triggered = OG_FALSE;
        g_disk_readonly_trigger_items[0] = '\0';
        g_disk_readonly_last_recover_time = now;
        CmsDiskUsageSetReadonlyState("NORMAL", "%s", detail);
        CMS_LOG_WAR("cms disk usage readwrite recovered, action %s, mode MESSAGE, objects %s, detail %s",
            action, recovered_items, detail);
        return OG_SUCCESS;
    }

    CmsDiskUsageSetReadonlyState("READWRITE_FAILED", "%s", detail);
    if (err_info != NULL && err_len > 0) {
        CmsDiskUsageSetInfo(err_info, "readwrite recover failed, detail %s", detail);
    }
    CMS_LOG_ERR("cms disk usage readwrite recover failed, action %s, mode MESSAGE, detail %s", action, detail);
    return OG_ERROR;
}

status_t cms_disk_usage_recover_readwrite_now(char *err_info, uint32 err_len)
{
    CmsDiskUsageEnsureInit();

    CmsDiskUsageConfigT cfg;
    CmsDiskUsageLoadConfig(&cfg);
    return cms_disk_usage_execute_readwrite_recover(&cfg, "manual", err_info, err_len);
}

static void CmsDiskUsageSetReadonlyState(const char *state, const char *fmt, ...)
{
    cms_disk_usage_copy_str(g_disk_readonly_state, sizeof(g_disk_readonly_state), state);

    va_list args;
    va_start(args, fmt);
    int32 ret = vsnprintf_s(g_disk_readonly_info, sizeof(g_disk_readonly_info), sizeof(g_disk_readonly_info) - 1,
        fmt, args);
    va_end(args);
    if (ret == -1) {
        g_disk_readonly_info[0] = '\0';
    }
}

static void CmsDiskUsageHandleReadonlyAction(const CmsDiskUsageConfigT *cfg,
    CmsDiskUsageSnapshotT *snapshot)
{
    date_t now = cm_now();
    date_t cooldown = (date_t)cfg->readonly_cooldown_sec * MICROSECS_PER_SECOND_LL;
    bool32 should_recover = cms_disk_usage_readwrite_should_recover(snapshot);
    char alarm_items[CMS_FILE_NAME_BUFFER_SIZE] = {0};
    bool32 should_trigger = cms_disk_usage_has_success_alarm(snapshot, alarm_items, sizeof(alarm_items));

    if (cfg->protect_enabled != OG_TRUE) {
        CmsDiskUsageSetReadonlyState(g_disk_readonly_triggered == OG_TRUE ? "READONLY_TRIGGERED" : "NORMAL",
            "disk usage protect disabled");
        return;
    }

    if (g_disk_readonly_triggered != OG_TRUE && should_trigger == OG_TRUE) {
        if (g_disk_readonly_last_action_time != 0 && now - g_disk_readonly_last_action_time < cooldown) {
            CmsDiskUsageSetReadonlyState("READONLY_PENDING", "readonly action is in cooldown, objects %s",
                alarm_items);
            return;
        }

        g_disk_readonly_last_action_time = now;
        char detail[CMS_INFO_BUFFER_SIZE] = {0};
        if (CmsDiskUsageExecuteReadmodeAction(cfg, OG_TRUE, alarm_items, detail, sizeof(detail)) == OG_SUCCESS) {
            g_disk_readonly_triggered = OG_TRUE;
            cms_disk_usage_copy_str(g_disk_readonly_trigger_items, sizeof(g_disk_readonly_trigger_items), alarm_items);
            g_disk_readonly_last_trigger_time = now;
            CmsDiskUsageSetReadonlyState("READONLY_TRIGGERED", "%s", detail);
            CMS_LOG_WAR("cms disk usage readonly triggered, mode MESSAGE, match ANY, objects %s, detail %s",
                alarm_items, detail);
        } else {
            CmsDiskUsageSetReadonlyState("READONLY_FAILED", "%s", detail);
            CMS_LOG_ERR("cms disk usage readonly trigger failed, mode MESSAGE, objects %s, detail %s",
                alarm_items, detail);
        }
        return;
    }

    if (g_disk_readonly_triggered == OG_TRUE && should_recover == OG_TRUE) {
        if (g_disk_readonly_last_action_time != 0 && now - g_disk_readonly_last_action_time < cooldown) {
            CmsDiskUsageSetReadonlyState("READWRITE_PENDING", "readwrite action is in cooldown");
            return;
        }

        (void)cms_disk_usage_execute_readwrite_recover(cfg, "auto", NULL, 0);
        return;
    }

    if (g_disk_readonly_triggered == OG_TRUE) {
        CmsDiskUsageSetReadonlyState("READONLY_TRIGGERED", should_recover == OG_TRUE ?
            "readonly triggered" : "readonly triggered, disk objects are still above threshold or unavailable");
    } else {
        CmsDiskUsageSetReadonlyState("NORMAL", should_trigger == OG_TRUE ?
            "readonly condition matched but no action executed" : "readonly condition not matched");
    }
}

static void CmsDiskUsageAppendSnapshotInfo(CmsDiskUsageSnapshotT *snapshot, CmsDiskUsageItemT *item)
{
    if (item->valid != OG_TRUE || item->collect_success == OG_TRUE) {
        return;
    }

    char item_id[CMS_NAME_BUFFER_SIZE * 2];
    cms_disk_usage_build_item_id(item, item_id, sizeof(item_id));
    size_t used = strlen(snapshot->info);
    if (used >= sizeof(snapshot->info) - 1) {
        return;
    }
    uint32 remain = (uint32)(sizeof(snapshot->info) - used);
    if (used == 0) {
        int32 ret = snprintf_s(snapshot->info + used, remain, remain - 1, "collect failed: %s(%s)",
            item_id, item->info);
        if (ret == -1) {
            snapshot->info[used] = '\0';
        }
    } else {
        int32 ret = snprintf_s(snapshot->info + used, remain, remain - 1, "; %s(%s)", item_id, item->info);
        if (ret == -1) {
            snapshot->info[used] = '\0';
        }
    }
}

static void CmsDiskUsageBuildSnapshotInfo(CmsDiskUsageSnapshotT *snapshot)
{
    snapshot->info[0] = '\0';
    CmsDiskUsageAppendSnapshotInfo(snapshot, &snapshot->local);
    for (uint32 i = 0; i < snapshot->dss_count; i++) {
        CmsDiskUsageAppendSnapshotInfo(snapshot, &snapshot->dss[i]);
    }
    if (snapshot->info[0] == '\0') {
        cms_disk_usage_copy_str(snapshot->info, CMS_INFO_BUFFER_SIZE, "OK");
    }
}

static CmsDiskUsageItemT *CmsDiskUsageFindOldItem(CmsDiskUsageSnapshotT *oldSnapshot,
    const CmsDiskUsageItemT *newItem)
{
    if (newItem->item_type == CMS_DISK_USAGE_TYPE_LOCAL) {
        return &oldSnapshot->local;
    }
    for (uint32 i = 0; i < oldSnapshot->dss_count; i++) {
        CmsDiskUsageItemT *oldItem = &oldSnapshot->dss[i];
        if (oldItem->valid && oldItem->item_type == newItem->item_type &&
            strcmp(oldItem->name, newItem->name) == 0) {
            return oldItem;
        }
    }
    return NULL;
}

static void CmsDiskUsageLogItem(CmsDiskUsageItemT *item, CmsDiskUsageSnapshotT *oldSnapshot)
{
    if (item->valid != OG_TRUE) {
        return;
    }
    CmsDiskUsageItemT *oldItem = CmsDiskUsageFindOldItem(oldSnapshot, item);
    if (oldItem != NULL) {
        item->last_alarm_log_time = oldItem->last_alarm_log_time;
    }

    date_t now = cm_now();
    const char *type = (item->item_type == CMS_DISK_USAGE_TYPE_LOCAL) ? "LOCAL" : "DSS";
    if (item->collect_success == OG_FALSE) {
        if (oldItem == NULL || oldItem->collect_success == OG_TRUE ||
            now - item->last_alarm_log_time >= CMS_DISK_USAGE_ALARM_LOG_INTERVAL) {
            CMS_LOG_WAR("cms disk usage collect failed, type %s, name %s, source %s, detail %s",
                type, item->name, item->source, item->info);
            item->last_alarm_log_time = now;
        }
        return;
    }

    if (item->alarm == OG_TRUE) {
        if (oldItem == NULL || oldItem->alarm == OG_FALSE ||
            now - item->last_alarm_log_time >= CMS_DISK_USAGE_ALARM_LOG_INTERVAL) {
            CMS_LOG_WAR("cms disk usage alarm, type %s, name %s, used %u.%03u%%, threshold %u%%, total %llu.%03uGB, "
                "free %llu.%03uGB", type, item->name, cms_disk_usage_percent_int(item->use_percent_x1000),
                cms_disk_usage_percent_frac(item->use_percent_x1000), item->threshold_percent,
                cms_disk_usage_bytes_gib_int(item->total_bytes), cms_disk_usage_bytes_gib_frac(item->total_bytes),
                cms_disk_usage_bytes_gib_int(item->free_bytes), cms_disk_usage_bytes_gib_frac(item->free_bytes));
            item->last_alarm_log_time = now;
        }
        return;
    }

    if (oldItem != NULL && oldItem->alarm == OG_TRUE) {
        CMS_LOG_INF("cms disk usage recovered, type %s, name %s, used %u.%03u%%, threshold %u%%",
            type, item->name, cms_disk_usage_percent_int(item->use_percent_x1000),
            cms_disk_usage_percent_frac(item->use_percent_x1000), item->threshold_percent);
    }
}

static void CmsDiskUsagePublishSnapshot(CmsDiskUsageSnapshotT *snapshot)
{
    CmsDiskUsageSnapshotT oldSnapshot;
    cm_thread_lock(&g_disk_usage_lock);
    if (CMS_DISK_USAGE_MEMCPY(&oldSnapshot, sizeof(oldSnapshot), &g_diskUsageSnapshot, sizeof(g_diskUsageSnapshot)) !=
        OG_SUCCESS) {
        cm_thread_unlock(&g_disk_usage_lock);
        return;
    }
    cm_thread_unlock(&g_disk_usage_lock);

    CmsDiskUsageLogItem(&snapshot->local, &oldSnapshot);
    for (uint32 i = 0; i < snapshot->dss_count; i++) {
        CmsDiskUsageLogItem(&snapshot->dss[i], &oldSnapshot);
    }

    cm_thread_lock(&g_disk_usage_lock);
    (void)CMS_DISK_USAGE_MEMCPY(&g_diskUsageSnapshot, sizeof(g_diskUsageSnapshot), snapshot, sizeof(*snapshot));
    cm_thread_unlock(&g_disk_usage_lock);
}

static void CmsDiskUsageCollectOnce(void)
{
    CmsDiskUsageConfigT cfg;
    CmsDiskUsageLoadConfig(&cfg);

    CmsDiskUsageSnapshotT snapshot;
    if (CMS_DISK_USAGE_MEMSET(&snapshot, sizeof(snapshot), sizeof(snapshot)) != OG_SUCCESS) {
        return;
    }
    snapshot.interval_sec = cfg.interval_sec;
    snapshot.threshold_percent = cfg.threshold_percent;
    snapshot.last_check_time = cm_now();
    CmsDiskUsageFillReadonlyConfig(&snapshot.readonly_config, &cfg);

    CmsDiskUsageCollectLocal(&cfg, &snapshot.local);
    CmsDiskUsageCollectDss(&cfg, &snapshot);
    CmsDiskUsageHandleReadonlyAction(&cfg, &snapshot);
    CmsDiskUsageFillReadonlyConfig(&snapshot.readonly_config, &cfg);
    CmsDiskUsageBuildSnapshotInfo(&snapshot);
    CmsDiskUsagePublishSnapshot(&snapshot);
}

void CmsDiskUsageGetSnapshot(CmsDiskUsageSnapshotT *snapshot)
{
    CmsDiskUsageEnsureInit();
    cm_thread_lock(&g_disk_usage_lock);
    (void)CMS_DISK_USAGE_MEMCPY(snapshot, sizeof(CmsDiskUsageSnapshotT), &g_diskUsageSnapshot,
        sizeof(g_diskUsageSnapshot));
    cm_thread_unlock(&g_disk_usage_lock);
}

void cms_disk_usage_check_entry(thread_t *thread)
{
    CmsDiskUsageEnsureInit();
    CMS_LOG_INF("start cms disk usage check thread");
    while (!thread->closed) {
        CmsDiskUsageCollectOnce();
        CmsDiskUsageSnapshotT snapshot;
        CmsDiskUsageGetSnapshot(&snapshot);
        uint32 interval = snapshot.interval_sec;
        if (interval < CMS_DISK_USAGE_MIN_INTERVAL) {
            interval = CMS_DISK_USAGE_DEFAULT_INTERVAL;
        }
        for (uint32 i = 0; i < interval && !thread->closed; i++) {
            cm_sleep(MILLISECS_PER_SECOND);
        }
    }
    CMS_LOG_INF("end cms disk usage check thread");
}
