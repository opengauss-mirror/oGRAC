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
 * load_server.c
 *
 *
 * IDENTIFICATION
 * src/server/params/load_server.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "load_server.h"
#include "mes_config.h"
#include "dtc_context.h"
#include "dtc_dls.h"
#include "knl_temp.h"
#include "cm_io_record.h"
#include "cm_kmc.h"
#include "cm_log.h"
#include "cm_file_iofence.h"
#include "srv_device_adpt.h"

extern bool32 g_enable_fdsa;
extern bool32 g_crc_verify;

#ifdef __cplusplus
extern "C" {
#endif

static void srv_check_file_errno(void)
{
    if (errno == EMFILE || errno == ENFILE) {
        OG_LOG_ALARM(WARN_FILEDESC, "'instance-name':'%s'}", g_instance->kernel.instance_name);
    }
}

static status_t verify_log_path_permission(uint16 permission)
{
    uint16 num = permission;
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > OG_MAX_LOG_USER_PERMISSION || grp_perm > OG_MAX_LOG_USER_PERMISSION ||
        oth_perm > OG_MAX_LOG_USER_PERMISSION) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_PATH_PERMISSIONS");
        return OG_ERROR;
    }

    if (num < OG_DEF_LOG_PATH_PERMISSIONS || num > OG_MAX_LOG_PERMISSIONS) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_PATH_PERMISSIONS", (int64)OG_DEF_LOG_PATH_PERMISSIONS,
            (int64)OG_MAX_LOG_PERMISSIONS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t verify_log_file_permission(uint16 permission)
{
    uint16 num = permission;
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > OG_MAX_LOG_USER_PERMISSION || grp_perm > OG_MAX_LOG_USER_PERMISSION ||
        oth_perm > OG_MAX_LOG_USER_PERMISSION) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_FILE_PERMISSIONS");
        return OG_ERROR;
    }

    if (num < OG_DEF_LOG_FILE_PERMISSIONS || num > OG_MAX_LOG_PERMISSIONS) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_FILE_PERMISSIONS", (int64)OG_DEF_LOG_PATH_PERMISSIONS,
            (int64)OG_MAX_LOG_PERMISSIONS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_init_loggers(void)
{
    char file_name[OG_FILE_NAME_BUFFER_SIZE] = { '\0' };
    cm_log_allinit();
    log_param_t *log_param = cm_log_param_instance();
    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_ALARM);

    MEMS_RETURN_IFERR(strcpy_sp(log_param->instance_name, OG_MAX_NAME_LEN, g_instance->kernel.instance_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/run/%s",
        log_param->log_home, "ogracd.rlog"));
    cm_log_init(LOG_RUN, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/debug/%s",
        log_param->log_home, "ogracd.dlog"));
    cm_log_init(LOG_DEBUG, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/audit/%s",
        log_param->log_home, "ogracd.aud"));
    cm_log_init(LOG_AUDIT, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/%s_alarm.log",
        g_instance->kernel.alarm_log_dir, g_instance->kernel.instance_name));
    cm_log_init(LOG_ALARM, file_name);

    cm_log_open_file(log_file_handle);
    OG_LOG_RUN_FILE_INF(OG_TRUE, "[LOG] file '%s' is added", log_file_handle->file_name);

#ifndef WIN32
    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/raft/%s",
        log_param->log_home, "ogracd.raft"));
    cm_log_init(LOG_RAFT, file_name);
#endif

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/longsql/%s",
        log_param->log_home, "ogracd.lsql"));
    cm_log_init(LOG_LONGSQL, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/opt/%s",
        log_param->log_home, "ogracd.opt"));
    cm_log_init(LOG_OPTINFO, file_name);

#ifndef WIN32
    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/blackbox/%s",
        log_param->log_home, "ogracd.blog"));
    cm_log_init(LOG_BLACKBOX, file_name);
#endif

    g_check_file_error = &srv_check_file_errno;

    if (g_instance->sql_style == SQL_STYLE_CT) {
        cm_init_error_handler(cm_set_sql_error);
    }

    log_file_handle = cm_log_logger_file(LOG_TRACE);
    PRTS_RETURN_IFERR(snprintf_s(file_name, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN,
        "%s/trc/ogracd_smon_%05u.trc", g_instance->home, (uint32)SESSION_ID_SMON));

    cm_log_init(LOG_TRACE, file_name);
    cm_log_open_file(log_file_handle);

    sql_auditlog_init(&(log_param->audit_param));

    return OG_SUCCESS;
}

static status_t verify_als_file_dir(char *file_path)
{
    if (!cm_dir_exist(file_path)) {
        OG_THROW_ERROR(ERR_PATH_NOT_EXIST, file_path);
        return OG_ERROR;
    }
    char path[OG_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    OG_RETURN_IFERR(realpath_file(file_path, path, OG_FILE_NAME_BUFFER_SIZE));
    if (access(path, W_OK | R_OK) != 0) {
        OG_THROW_ERROR(ERR_PATH_NOT_ACCESSABLE, file_path);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t srv_get_log_params_core(log_param_t *log_param)
{
    uint16 val_uint16;

    OG_RETURN_IFERR(srv_get_param_uint32("_LOG_BACKUP_FILE_COUNT", &log_param->log_backup_file_count));
    if (log_param->log_backup_file_count > OG_MAX_LOG_FILE_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_BACKUP_FILE_COUNT");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("_AUDIT_BACKUP_FILE_COUNT", &log_param->audit_backup_file_count));
    if (log_param->audit_backup_file_count > OG_MAX_LOG_FILE_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_AUDIT_BACKUP_FILE_COUNT");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_size_uint64("_LOG_MAX_FILE_SIZE", &log_param->max_log_file_size));
    if ((log_param->max_log_file_size < OG_MIN_LOG_FILE_SIZE) ||
        (log_param->max_log_file_size > OG_MAX_LOG_FILE_SIZE)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_MAX_FILE_SIZE");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_size_uint64("_AUDIT_MAX_FILE_SIZE", &log_param->max_audit_file_size));
    if ((log_param->max_audit_file_size < OG_MIN_LOG_FILE_SIZE) ||
        (log_param->max_audit_file_size > OG_MAX_LOG_FILE_SIZE)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_AUDIT_MAX_FILE_SIZE");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_size_uint64("MAX_PBL_FILE_SIZE", &log_param->max_pbl_file_size));
    if ((log_param->max_pbl_file_size < OG_MIN_PBL_FILE_SIZE) ||
        (log_param->max_pbl_file_size > OG_MAX_PBL_FILE_SIZE)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "PBL_MAX_FILE_SIZE");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("_LOG_LEVEL", &log_param->log_level));
    if (log_param->log_level > MAX_LOG_LEVEL && log_param->log_level != LOG_FATAL_LEVEL) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_LEVEL");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint16("_LOG_FILE_PERMISSIONS", &val_uint16));
    OG_RETURN_IFERR(verify_log_file_permission(val_uint16));
    cm_log_set_file_permissions(val_uint16);

    OG_RETURN_IFERR(srv_get_param_uint16("_LOG_PATH_PERMISSIONS", &val_uint16));
    OG_RETURN_IFERR(verify_log_path_permission(val_uint16));
    cm_log_set_path_permissions(val_uint16);

    // must do it after load all log params, SQL_COMPAT and INSTANCE_NAME
    OG_RETURN_IFERR(srv_init_loggers());

    return OG_SUCCESS;
}

static status_t srv_get_log_params_extra(log_param_t *log_param, bool32 *log_cfg)
{
    char *value = NULL;
    uint32 val_len;

    OG_RETURN_IFERR(srv_get_param_uint32("AUDIT_LEVEL", &log_param->audit_param.audit_level));
    if (log_param->audit_param.audit_level > DDL_AUDIT_ALL) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "AUDIT_LEVEL");
        return OG_ERROR;
    }

    value = srv_get_param("AUDIT_TRAIL_MODE");
    OG_RETURN_IFERR(sql_parse_audit_trail_mode(value, &(log_param->audit_param.audit_trail_mode)));
    value = srv_get_param("AUDIT_SYSLOG_LEVEL");
    OG_RETURN_IFERR(sql_parse_audit_syslog(value, &(log_param->audit_param)));

    value = srv_get_param("LOG_HOME");
    val_len = (uint32)strlen(value);
    if (val_len >= OG_MAX_LOG_HOME_LEN) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_HOME");
        return OG_ERROR;
    } else if (val_len > 0) {
        MEMS_RETURN_IFERR(strncpy_s(log_param->log_home, OG_MAX_PATH_BUFFER_SIZE, value, OG_MAX_LOG_HOME_LEN));
        *log_cfg = OG_TRUE;
    } else {
        PRTS_RETURN_IFERR(
            snprintf_s(log_param->log_home, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_LEN, "%s/log", g_instance->home));
    }
    return OG_SUCCESS;
}

static status_t srv_get_log_params(void)
{
    char *value = NULL;
    uint32 val_len;
    bool32 alarm_log_cfg = OG_FALSE;
    bool32 log_cfg = OG_FALSE;
    log_param_t *log_param = cm_log_param_instance();

    OG_RETURN_IFERR(srv_get_param_uint32("_BLACKBOX_STACK_DEPTH", &g_instance->attr.black_box_depth));
    if (g_instance->attr.black_box_depth > OG_MAX_BLACK_BOX_DEPTH) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_BLACKBOX_STACK_DEPTH");
        return OG_ERROR;
    }
    if (g_instance->attr.black_box_depth < OG_INIT_BLACK_BOX_DEPTH) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_BLACKBOX_STACK_DEPTH");
        return OG_ERROR;
    }

    value = srv_get_param("ALARM_LOG_DIR");
    val_len = (uint32)strlen(value);
    if (val_len >= OG_MAX_LOG_HOME_LEN) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "ALARM_LOG_DIR");
        return OG_ERROR;
    }
    if (val_len != 0) {
        MEMS_RETURN_IFERR(
            strncpy_s(g_instance->kernel.alarm_log_dir, OG_MAX_PATH_BUFFER_SIZE, value, OG_MAX_LOG_HOME_LEN));
        alarm_log_cfg = OG_TRUE;
    } else {
        PRTS_RETURN_IFERR(snprintf_s(g_instance->kernel.alarm_log_dir, OG_MAX_PATH_BUFFER_SIZE, OG_MAX_PATH_LEN,
            "%s/log", g_instance->home));
    }

    OG_RETURN_IFERR(srv_get_log_params_extra(log_param, &log_cfg));
    OG_RETURN_IFERR(srv_get_log_params_core(log_param));

    // srv_init_loggers has tryed to create the dir of the LOG_HOME and ALARM_LOG_DIR
    // read LOG_HOME from cfg, check it
    if (log_cfg && verify_als_file_dir(log_param->log_home) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_HOME");
        printf("%s\n", "Failed to check param:LOG_HOME");
        return OG_ERROR;
    }
    // read ALARM_LOG_DIR from cfg, check it
    if (alarm_log_cfg && verify_als_file_dir(g_instance->kernel.alarm_log_dir) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "ALARM_LOG_DIR");
        printf("%s\n", "Failed to check param:ALARM_LOG_DIR");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t srv_load_max_allowed_packet(void)
{
    int64 max_allowed_packet_size = 0;
    if (cm_str2size(srv_get_param("MAX_ALLOWED_PACKET"), &max_allowed_packet_size) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_ALLOWED_PACKET");
        return OG_ERROR;
    }
    if (max_allowed_packet_size < OG_MAX_PACKET_SIZE || max_allowed_packet_size > OG_MAX_ALLOWED_PACKET_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "MAX_ALLOWED_PACKET", SIZE_K(96), SIZE_M(64));
        return OG_ERROR;
    }
    g_instance->attr.max_allowed_packet = (uint32)max_allowed_packet_size;
    return OG_SUCCESS;
}

static status_t srv_get_param_dbtimezone(timezone_info_t *dbtimezone)
{
    char *value = srv_get_param("DB_TIMEZONE");
    text_t text;
    timezone_info_t tz;

    text.str = value;
    text.len = (uint32)strlen(value);
    if (cm_text2tzoffset(&text, &tz) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "DB_TIMEZONE");
        return OG_ERROR;
    }

    *dbtimezone = tz;
    return OG_SUCCESS;
}

static status_t srv_load_keyfiles(void)
{
    return OG_SUCCESS;
}

static status_t srv_generate_factor_key(char *file_name1, char *file_name2, char *factor_key, uint32 flen)
{
    char *value = srv_get_param("_FACTOR_KEY");
    if (value[0] == '\0') {
        char rand_buf[OG_AESBLOCKSIZE + 1];
        uint32 rand_len = OG_AESBLOCKSIZE;
        /* generate 128bit rand_buf and then base64 encode */
        OG_RETURN_IFERR(cm_rand((uchar *)rand_buf, rand_len));
        OG_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, rand_len, factor_key, &flen));
    } else {
        MEMS_RETURN_IFERR(strncpy_s(factor_key, OG_MAX_FACTOR_KEY_STR_LEN + 1, value, strlen(value)));
    }
    OG_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
    OG_RETURN_IFERR(srv_save_factor_key_file(file_name2, factor_key));
    return OG_SUCCESS;
}

static status_t srv_load_factor_key_file(const char *file_name, char *key_buf, uint32 key_len)
{
    status_t ret;
    int32 handle;
    int32 file_size;
    uchar file_buf[OG_AESBLOCKSIZE + OG_HMAC256MAXSIZE + 4];
    uchar cipher[OG_HMAC256MAXSTRSIZE + 4];
    uint32 cipher_len;

    OG_RETURN_IFERR(cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    ret = cm_read_file(handle, file_buf, sizeof(file_buf), &file_size);
    cm_close_file(handle);
    OG_RETURN_IFERR(ret);

    if (file_size < OG_AESBLOCKSIZE + OG_HMAC256MAXSIZE) {
        OG_LOG_RUN_ERR("key file is invalid");
        return OG_ERROR;
    }
    file_size -= OG_AESBLOCKSIZE;

    // verify hmac
    cipher_len = sizeof(cipher);
    OG_RETURN_IFERR(
        cm_encrypt_HMAC(file_buf, OG_AESBLOCKSIZE, file_buf, OG_AESBLOCKSIZE, (uchar *)cipher, &cipher_len));

    if ((uint32)file_size != cipher_len || 0 != memcmp(cipher, (file_buf + OG_AESBLOCKSIZE), cipher_len)) {
        OG_LOG_RUN_ERR("verify key failed");
        return OG_ERROR;
    }
    return cm_base64_encode((uchar *)file_buf, OG_AESBLOCKSIZE, key_buf, &key_len);
}

static status_t srv_load_factor_key(void)
{
    char *value = NULL;
    char file_name1[OG_FILE_NAME_BUFFER_SIZE];
    char file_name2[OG_FILE_NAME_BUFFER_SIZE];
    char dbs_dir[OG_FILE_NAME_BUFFER_SIZE];
    char factor_key[OG_MAX_FACTOR_KEY_STR_LEN + 1];
    char work_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];

    PRTS_RETURN_IFERR(
        snprintf_s(dbs_dir, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/", g_instance->home));
    PRTS_RETURN_IFERR(snprintf_s(file_name1, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
        g_instance->home, OG_FKEY_FILENAME1));
    PRTS_RETURN_IFERR(snprintf_s(file_name2, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
        g_instance->home, OG_FKEY_FILENAME2));

    if (!cm_dir_exist(dbs_dir)) {
        if (cm_create_dir(dbs_dir) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("unable to create directory %s", dbs_dir);
            return OG_ERROR;
        }
    }

    if (access(file_name1, R_OK | F_OK) == 0) {
        if (OG_SUCCESS != srv_load_factor_key_file(file_name1, factor_key, sizeof(factor_key))) {
            OG_RETURN_IFERR(srv_load_factor_key_file(file_name2, factor_key, sizeof(factor_key)));
            OG_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
        }
    } else if (access(file_name2, R_OK | F_OK) == 0) {
        OG_RETURN_IFERR(srv_load_factor_key_file(file_name2, factor_key, sizeof(factor_key)));
        OG_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
    } else {
        // generate factor key
        OG_RETURN_IFERR(srv_generate_factor_key(file_name1, file_name2, factor_key, OG_MAX_FACTOR_KEY_STR_LEN + 1));
    }
    OG_RETURN_IFERR(cm_alter_config(&g_instance->config, "_FACTOR_KEY", factor_key, CONFIG_SCOPE_MEMORY, OG_TRUE));

    // verify local key
    value = srv_get_param("LOCAL_KEY");
    if (value[0] == '\0') {
        OG_RETURN_IFERR(cm_generate_work_key(factor_key, work_key, sizeof(work_key)));
        OG_RETURN_IFERR(cm_alter_config(&g_instance->config, "LOCAL_KEY", work_key, CONFIG_SCOPE_BOTH, OG_TRUE));
    } else if (strlen(value) != OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE) {
        OG_LOG_RUN_ERR("LOCAL_KEY is invalid");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
void shm_set_thread_cool_time(uint32_t time_us);

static status_t srv_load_dss_path()
{
    char *value = NULL;
    MEMS_RETURN_IFERR(memset_s(g_instance->kernel.dtc_attr.ogstore_inst_path, OG_UNIX_PATH_MAX, 0, OG_UNIX_PATH_MAX));
    value = srv_get_param("OGSTORE_INST_PATH");
    if (value == NULL) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "OGSTORE_INST_PATH");
        return OG_ERROR;
    }
    uint32 val_len = (uint32)strlen(value);
    if (val_len >= OG_UNIX_PATH_MAX || val_len == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "OGSTORE_INST_PATH");
        return OG_ERROR;
    } else {
        OG_PRINT_IFERR2(snprintf_s(g_instance->kernel.dtc_attr.ogstore_inst_path, OG_UNIX_PATH_MAX,
                                   OG_UNIX_PATH_MAX - 1, "%s", value),
                        "OGSTORE_INST_PATH", OG_UNIX_PATH_MAX - 1);
    }
    return OG_SUCCESS;
}

status_t srv_load_server_params(void)
{
    session_pool_t *session_pool = NULL;
    reactor_pool_t *reactor_pool = NULL;
    sql_emerg_pool_t *emerg_pool = NULL;
    uint16 job_process_count;
    timezone_info_t dbtimezone = TIMEZONE_OFFSET_DEFAULT;
    log_param_t *log_param = cm_log_param_instance();
    char *cpu_info = get_g_cpu_info();

    // only support the ogdb engine
    g_instance->sql_style = SQL_STYLE_CT;
    dls_init_spinlock(&g_instance->dblink_lock, DR_TYPE_DATABASE, DR_ID_DATABASE_LINK, 0);

    const char *value = srv_get_param("INSTANCE_NAME");
    session_pool = &g_instance->session_pool;
    reactor_pool = &g_instance->reactor_pool;
    emerg_pool = &g_instance->sql_emerg_pool;

    MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.instance_name, OG_MAX_NAME_LEN, value, strlen(value)));

    char *cpu_info_param = srv_get_param("CPU_GROUP_INFO");
    OG_PRINT_IFERR(memcpy_s(cpu_info, CPU_INFO_STR_SIZE, cpu_info_param, strlen(cpu_info_param) + 1),
                   "CPU_GROUP_INFO", CPU_INFO_STR_SIZE - 1);

    OG_RETURN_IFERR(srv_get_log_params());

    log_param->log_instance_startup = OG_TRUE;
    g_instance->kernel.reserved_sessions = OG_SYS_SESSIONS;

    value = srv_get_param("LSNR_ADDR");
    if (cm_verify_lsnr_addr(value, (uint32)strlen(value), NULL) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "LSNR_ADDR");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_split_host_ip(g_instance->lsnr.tcp_service.host, value));

    value = srv_get_param("REPL_ADDR");
    if (strlen(value) > 0) {
        // if REPL_ADDR is configured, use it
        if (cm_verify_lsnr_addr(value, (uint32)strlen(value), NULL) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_INVALID_PARAMETER, "REPL_ADDR");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(cm_split_host_ip(g_instance->lsnr.tcp_replica.host, value));
    } else {
        // else use LSNR_ADDR
        value = srv_get_param("LSNR_ADDR");
        OG_RETURN_IFERR(cm_split_host_ip(g_instance->lsnr.tcp_replica.host, value));
    }

    OG_RETURN_IFERR(srv_get_param_uint16("LSNR_PORT", &g_instance->lsnr.tcp_service.port));
    if (g_instance->lsnr.tcp_service.port < OG_MIN_PORT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LSNR_PORT", (int64)OG_MIN_PORT);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint16("REPL_PORT", &g_instance->lsnr.tcp_replica.port));
    if ((g_instance->lsnr.tcp_replica.port < OG_MIN_PORT) && (g_instance->lsnr.tcp_replica.port != 0)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "REPL_PORT");
        return OG_ERROR;
    }

    /* uds communication mode, g_instance->lsnr.uds_service.names[0] for emerg session */
    PRTS_RETURN_IFERR(snprintf_s(g_instance->lsnr.uds_service.names[0], OG_UNIX_PATH_MAX, OG_UNIX_PATH_MAX - 1,
        "%s/protect/%s", g_instance->home, OGDB_UDS_EMERG_SERVER));

    char protect_dir[OG_FILE_NAME_BUFFER_SIZE];
    PRTS_RETURN_IFERR(snprintf_s(protect_dir, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/",
        g_instance->home));

    if (!cm_dir_exist(protect_dir)) {
        if (cm_create_dir(protect_dir) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("[Privilege] failed to create dir %s", protect_dir);
            return OG_ERROR;
        }
    }

    char realfile[OG_UNIX_PATH_MAX];
    OG_RETURN_IFERR(realpath_file(g_instance->lsnr.uds_service.names[0], realfile, OG_UNIX_PATH_MAX));
    if (cm_file_exist((const char *)realfile)) {
        OG_RETURN_IFERR(cm_remove_file((const char *)realfile));
    }

    value = srv_get_param("UDS_FILE_PATH");
    if (strlen(value) != 0) {
        if (strlen(value) >= OG_UNIX_PATH_MAX) {
            OG_THROW_ERROR(ERR_INVALID_FILE_NAME, value, OG_UNIX_PATH_MAX);
            return OG_ERROR;
        }

        OG_RETURN_IFERR(realpath_file(value, realfile, OG_UNIX_PATH_MAX));
        if (cm_file_exist((const char *)realfile)) {
            OG_RETURN_IFERR(cm_remove_file((const char *)realfile));
        }

        OG_RETURN_IFERR(verify_uds_file_path(value));
        PRTS_RETURN_IFERR(
            snprintf_s(g_instance->lsnr.uds_service.names[1], OG_UNIX_PATH_MAX, OG_UNIX_PATH_MAX - 1, value));
    }
    uint16 file_perm = 0;
    OG_RETURN_IFERR(srv_get_param_uint16("UDS_FILE_PERMISSIONS", &file_perm));
    if (verify_uds_file_permission(file_perm) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "UDS_FILE_PERMISSIONS");
        return OG_ERROR;
    }

    g_instance->lsnr.uds_service.permissions = cm_file_permissions(file_perm);

    OG_RETURN_IFERR(srv_get_param_uint32("OPTIMIZED_WORKER_THREADS", &g_instance->attr.optimized_worker_count));
    if (g_instance->attr.optimized_worker_count > OG_MAX_OPTIMIZED_WORKER_COUNT ||
        g_instance->attr.optimized_worker_count < OG_MIN_OPTIMIZED_WORKER_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "OPTIMIZED_WORKER_COUNT");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("MAX_WORKER_THREADS", &g_instance->attr.max_worker_count));
    if (g_instance->attr.max_worker_count > OG_MAX_OPTIMIZED_WORKER_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_WORKER_THREADS");
        return OG_ERROR;
    }

    if (g_instance->attr.max_worker_count < g_instance->attr.optimized_worker_count) {
        g_instance->attr.max_worker_count = g_instance->attr.optimized_worker_count;
        char new_value[OG_PARAM_BUFFER_SIZE] = { 0 };
        PRTS_RETURN_IFERR(snprintf_s(new_value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%u",
            g_instance->attr.max_worker_count));
        OG_RETURN_IFERR(
            cm_alter_config(&g_instance->config, "MAX_WORKER_THREADS", new_value, CONFIG_SCOPE_BOTH, OG_TRUE));
        OG_RETURN_IFERR(cm_modify_runtimevalue(&g_instance->config, "MAX_WORKER_THREADS", new_value));
    }

    OG_RETURN_IFERR(srv_get_param_dbtimezone(&dbtimezone));
    cm_set_db_timezone(dbtimezone);
    OG_RETURN_IFERR(srv_get_param_uint32("REACTOR_THREADS", &reactor_pool->reactor_count));
    if (reactor_pool->reactor_count == 0 || reactor_pool->reactor_count > OG_MAX_REACTOR_POOL_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREADS");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("WORKER_THREADS_SHRINK_THRESHOLD", &reactor_pool->agents_shrink_threshold));
    if (g_instance->attr.optimized_worker_count < reactor_pool->reactor_count ||
        g_instance->attr.max_worker_count < reactor_pool->reactor_count) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREADS");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("SUPER_USER_RESERVED_SESSIONS", &emerg_pool->max_sessions));
    if (emerg_pool->max_sessions < 1) {
        emerg_pool->max_sessions = 1;
    } else if (emerg_pool->max_sessions >= OG_MAX_EMERG_SESSIONS) {
        emerg_pool->max_sessions = OG_MAX_EMERG_SESSIONS;
    }

    OG_RETURN_IFERR(srv_get_param_double("NORMAL_USER_RESERVED_SESSIONS_FACTOR",
        &g_instance->kernel.attr.normal_emerge_sess_factor));
    if (g_instance->kernel.attr.normal_emerge_sess_factor < 0 ||
        g_instance->kernel.attr.normal_emerge_sess_factor > 1) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "NORMAL_USER_RESERVED_SESSIONS_FACTOR");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("SESSIONS", &session_pool->max_sessions));
    if (session_pool->max_sessions > OG_MAX_SESSIONS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SESSIONS", OG_MAX_SESSIONS);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("PARALLEL_MAX_THREADS", &g_instance->sql_par_pool.max_sessions));
    if (g_instance->sql_par_pool.max_sessions > OG_PARALLEL_MAX_THREADS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "PARALLEL_MAX_THREADS", OG_PARALLEL_MAX_THREADS);
        return OG_ERROR;
    }

    session_pool->expanded_max_sessions = MIN(OG_MAX_SESSIONS, EXPANDED_SESSIONS(session_pool->max_sessions));
    OG_RETURN_IFERR(srv_get_param_uint32("_PREFETCH_ROWS", &g_instance->sql.prefetch_rows));
    if (g_instance->sql.prefetch_rows < 1) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_PREFETCH_ROWS");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_bool32("ARRAY_STORAGE_OPTIMIZATION", &g_instance->sql.enable_arr_store_opt));
    OG_RETURN_IFERR(
        srv_get_param_size_uint64("_MAX_JSON_DYNAMIC_BUFFER_SIZE", &g_instance->sql.json_mpool.max_json_dyn_buf));
    if (g_instance->sql.json_mpool.max_json_dyn_buf < OG_JSON_MIN_DYN_BUF_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_MAX_JSON_DYNAMIC_BUFFER_SIZE", OG_JSON_MIN_DYN_BUF_SIZE);
        return OG_ERROR;
    }

    if (g_instance->sql.json_mpool.max_json_dyn_buf > OG_JSON_MAX_DYN_BUF_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_JSON_DYNAMIC_BUFFER_SIZE", OG_JSON_MAX_DYN_BUF_SIZE);
        return OG_ERROR;
    }

    value = srv_get_param("_ENCRYPTION_ALG");
    if (cm_str_equal_ins(value, "PBKDF2")) {
        OG_LOG_RUN_WAR("The PBKDF2 encryption algorithm is insecure and has been deprecated, "
            "please use SCRAM_SHA256 instead");

        MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.attr.pwd_alg, OG_NAME_BUFFER_SIZE, value, strlen(value)));
    } else if (cm_str_equal_ins(value, "SCRAM_SHA256")) {
        MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.attr.pwd_alg, OG_NAME_BUFFER_SIZE, value, strlen(value)));
    } else {
        OG_LOG_RUN_ERR("_ENCRYPTION_ALG is invalid");
        return OG_ERROR;
    }

    value = srv_get_param("_SYS_PASSWORD");
    if (strlen(value) == OG_KDF2MAXSTRSIZE) {
        if (cm_convert_kdf2_scram_sha256(value, g_instance->kernel.attr.sys_pwd, OG_PASSWORD_BUFFER_SIZE) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("_SYS_PASSWORD is invalid");
            return OG_ERROR;
        }
    } else if (cm_is_password_valid(value)) {
        MEMS_RETURN_IFERR(strcpy_s(g_instance->kernel.attr.sys_pwd, OG_PASSWORD_BUFFER_SIZE, value));
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYS_PASSWORD");
        OG_LOG_RUN_ERR("_SYS_PASSWORD is invalid");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("_ENCRYPTION_ITERATION", &g_instance->kernel.attr.alg_iter));
    if (g_instance->kernel.attr.alg_iter > OG_KDF2MAXITERATION ||
        g_instance->kernel.attr.alg_iter < OG_KDF2MINITERATION) {
        OG_LOG_RUN_ERR("_ENCRYPTION_ITERATION must between %u and %u", OG_KDF2MINITERATION, OG_KDF2MAXITERATION);
        return OG_ERROR;
    }

    if (srv_load_factor_key() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("load or save _FACTOR_KEY failed");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_SYSDBA_LOGIN", &g_instance->session_pool.enable_sysdba_login));
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_SYS_REMOTE_LOGIN", &g_instance->session_pool.enable_sys_remote_login));
    OG_RETURN_IFERR(
        srv_get_param_bool32("ENABLE_SYSDBA_REMOTE_LOGIN", &g_instance->session_pool.enable_sysdba_remote_login));
    OG_RETURN_IFERR(srv_get_param_bool32("COMMIT_ON_DISCONNECT", &g_instance->sql.commit_on_disconn));
    OG_RETURN_IFERR(srv_get_param_uint32("_MAX_CONNECT_BY_LEVEL", &g_instance->sql.max_connect_by_level));
    OG_RETURN_IFERR(srv_get_param_uint32("_INDEX_SCAN_RANGE_CACHE", &g_instance->sql.index_scan_range_cache));
    OG_RETURN_IFERR(srv_get_param_bool32("_OPTIM_VM_VIEW_ENABLED", &g_instance->sql.vm_view_enabled));
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_PASSWORD_CIPHER", &g_instance->sql.enable_password_cipher));
    OG_RETURN_IFERR(srv_get_param_uint32("_OPTIM_INDEX_SCAN_MAX_PARTS", &g_instance->sql.optim_index_scan_max_parts));
    OG_RETURN_IFERR(srv_load_max_allowed_packet());
    OG_RETURN_IFERR(srv_get_param_uint32("INTERACTIVE_TIMEOUT", &g_instance->sql.interactive_timeout));
    OG_RETURN_IFERR(srv_get_param_onoff("PARALLEL_POLICY", &g_instance->sql.parallel_policy));
    OG_RETURN_IFERR(srv_get_param_bool32("ZERO_DIVISOR_ACCEPTED", &g_opr_options.div0_accepted));
    OG_RETURN_IFERR(srv_get_param_bool32("STRING_AS_HEX_FOR_BINARY", &g_instance->sql.string_as_hex_binary));
    OG_RETURN_IFERR(
        srv_get_param_uint32("UNAUTH_SESSION_EXPIRE_TIME", &g_instance->session_pool.unauth_session_expire_time));
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_ERR_SUPERPOSED", &g_enable_err_superposed));
    OG_RETURN_IFERR(srv_get_param_bool32("EMPTY_STRING_AS_NULL", &g_instance->sql.enable_empty_string_null));

    uint32 temp_difftime = 0;
    OG_RETURN_IFERR(srv_get_param_uint32("MASTER_SLAVE_DIFFTIME", &temp_difftime));
    g_instance->attr.master_slave_difftime = temp_difftime * MILLISECS_PER_SECOND * MICROSECS_PER_MILLISEC;
    value = srv_get_param("TYPE_MAP_FILE");
    g_instance->sql.type_map.do_typemap = OG_FALSE;
    if (strlen(value) != 0) {
        g_instance->sql.type_map.do_typemap = OG_TRUE;
        MEMS_RETURN_IFERR(
            strncpy_s(g_instance->sql.type_map.file_name, OG_FILE_NAME_BUFFER_SIZE, value, strlen(value)));
    }

    OG_RETURN_IFERR(srv_get_param_uint32("_SGA_CORE_DUMP_CONFIG", &g_instance->attr.core_dump_config));
    if (g_instance->attr.core_dump_config > OG_MAX_SGA_CORE_DUMP_CONFIG) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SGA_CORE_DUMP_CONFIG");
        return OG_ERROR;
    }

    /* Check JOB_QUEUE_PROCESSES is valid */
    OG_RETURN_IFERR(srv_get_param_uint16("JOB_THREADS", &job_process_count));
    if (job_process_count > OG_MAX_JOB_THREADS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "JOB_THREADS");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint64("XA_FORMAT_ID", &g_instance->attr.xa_fmt_id));
    if (g_instance->attr.xa_fmt_id > OG_MAX_INT64) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "XA_FORMAT_ID");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(
        srv_get_param_uint32("_DEADLOCK_DETECT_INTERVAL", &g_instance->kernel.attr.deadlock_detect_interval));
    if (!IS_DEADLOCK_INTERVAL_PARAM_VALID(g_instance->kernel.attr.deadlock_detect_interval)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_DEADLOCK_DETECT_INTERVAL");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("_AUTO_UNDO_RETENTION", &g_instance->kernel.attr.auto_undo_retention));

    OG_RETURN_IFERR(srv_get_param_uint32("INT_SYSINDEX_TRANS", &g_instance->kernel.attr.init_sysindex_trans));

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_HWN_CHANGE", &g_instance->kernel.attr.enable_hwm_change));

    bool32 enable_dbstor = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR", &enable_dbstor));
    if (enable_dbstor) {
        OG_RETURN_IFERR(srv_load_keyfiles());
    }

    bool32 enable_dss = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_DSS", &enable_dss));
    if (enable_dss) {
        g_instance->kernel.attr.enable_dss = enable_dss;
        OG_RETURN_IFERR(srv_load_dss_path());
        OG_RETURN_IFERR(srv_device_init(g_instance->kernel.dtc_attr.ogstore_inst_path));
    }

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_LOCAL_INFILE", &g_instance->attr.enable_local_infile));
    OG_RETURN_IFERR(srv_get_param_bool32("_STRICT_CASE_DATATYPE", &g_instance->sql.strict_case_datatype));

    OG_RETURN_IFERR(srv_get_param_bool32("CLUSTER_NO_CMS", &g_cluster_no_cms));
    OG_RETURN_IFERR(srv_get_param_bool32("DRC_IN_REFORMER_MODE", &g_instance->kernel.attr.drc_in_reformer_mode));
    OG_RETURN_IFERR(srv_get_param_uint32("RES_RECYCLE_RATIO", &g_instance->kernel.attr.res_recycle_ratio));
    OG_RETURN_IFERR(
        srv_get_param_uint32("CREATE_INDEX_PARALLELISM", &g_instance->kernel.attr.create_index_parallelism));
    return OG_SUCCESS;
}

static status_t srv_get_interconnect_type_param(cs_pipe_type_t *type)
{
    char *value;

    value = srv_get_param("INTERCONNECT_TYPE");
    if (cm_str_equal_ins(value, "TCP")) {
        *type = CS_TYPE_TCP;
    } else if (cm_str_equal_ins(value, "UC")) {
        *type = CS_TYPE_UC;
    } else if (cm_str_equal_ins(value, "UC_RDMA")) {
        *type = CS_TYPE_UC_RDMA;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "INTERCONNECT_TYPE");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t srv_load_gdv_params(void)
{
    OG_RETURN_IFERR(srv_get_param_uint32("OG_GDV_SQL_SESS_TMOUT", &g_dtc->profile.gdv_sql_sess_tmout));

    return OG_SUCCESS;
}

static status_t srv_get_dbs_cfg(void)
{
    char *value = NULL;
    bool32 enable = OG_FALSE;
    knl_attr_t *attr = &g_instance->kernel.attr;
    uint32 partition_num = attr->dbwr_processes; // partition_num same with dbwr count
    bool32 enable_batch_flush = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR", &enable));
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR_BATCH_FLUSH", &enable_batch_flush));
    value = srv_get_param("DBSTOR_NAMESPACE");

    uint32 deploy_mode = 0;
    if (srv_get_param_size_uint32("DBSTOR_DEPLOY_MODE", &deploy_mode) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "DBSTOR_DEPLOY_MODE");
        return OG_ERROR;
    }
    return cm_dbs_set_cfg(enable, attr->page_size, OG_DFLT_CTRL_BLOCK_SIZE,
        value, partition_num, enable_batch_flush, deploy_mode);
}

status_t srv_load_cluster_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    dtc_attr_t *dtc_attr = &g_instance->kernel.dtc_attr;
    const char *value = NULL;

    OG_RETURN_IFERR(srv_get_param_bool32("CLUSTER_DATABASE", &attr->clustered));

    if (!attr->clustered) {
        dtc_attr->inst_id = 0;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(srv_get_dbs_cfg());

    value = srv_get_param("INTERCONNECT_ADDR");
    if (cm_verify_lsnr_addr(value, (uint32)strlen(value), NULL) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "INTERCONNECT_ADDR");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_split_node_ip(g_dtc->profile.nodes, value));

    value = srv_get_param("INTERCONNECT_PORT");
    OG_RETURN_IFERR(cm_split_host_port(g_dtc->profile.ports, value));

    OG_RETURN_IFERR(srv_get_interconnect_type_param(&g_dtc->profile.pipe_type));

    OG_RETURN_IFERR(srv_get_param_uint32("INTERCONNECT_CHANNEL_NUM", &g_dtc->profile.channel_num));
    if ((g_dtc->profile.channel_num == 0) || (g_dtc->profile.channel_num > OG_MES_MAX_CHANNEL_NUM)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "INTERCONNECT_CHANNEL_NUM");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("REACTOR_THREAD_NUM", &g_dtc->profile.reactor_thread_num));
    if ((g_dtc->profile.reactor_thread_num == 0) ||
        (g_dtc->profile.reactor_thread_num > OG_MES_MAX_REACTOR_THREAD_NUM)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREAD_NUM");
        return OG_ERROR;
    }

    char *cpu_info = get_g_mes_cpu_info();
    char *cpu_info_param = srv_get_param("MES_CPU_INFO");
    if (cpu_info_param != NULL) {
        OG_PRINT_IFERR(memcpy_s(cpu_info, OG_MES_MAX_CPU_STR, cpu_info_param, strlen(cpu_info_param) + 1),
                       "MES_CPU_INFO", OG_MES_MAX_CPU_STR - 1);
    } else {
        cpu_info_param = NULL;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("OGRAC_TASK_NUM", &g_dtc->profile.task_num));
    if ((g_dtc->profile.task_num < OG_DTC_MIN_TASK_NUM) || (OG_DTC_MAX_TASK_NUM < g_dtc->profile.task_num)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "OGRAC_TASK_NUM");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_uint32("INSTANCE_ID", &dtc_attr->inst_id));
    if (dtc_attr->inst_id > OG_MES_MAX_INSTANCE_ID) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "INSTANCE_ID");
        return OG_ERROR;
    }
    g_instance->id = dtc_attr->inst_id;

    OG_RETURN_IFERR(srv_get_param_uint32("MES_POOL_SIZE", &g_dtc->profile.mes_pool_size));
    if ((g_dtc->profile.mes_pool_size < OG_MES_MIN_POOL_SIZE) ||
        (OG_MES_MAX_POOL_SIZE < g_dtc->profile.mes_pool_size)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "MES_POOL_SIZE");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_bool32("INTERCONNECT_BY_PROFILE", &g_dtc->profile.conn_by_profile));

    bool32 mes_elapsed_switch = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("MES_ELAPSED_SWITCH", &mes_elapsed_switch));
    mes_set_elapsed_switch(mes_elapsed_switch);

    bool32 mes_crc_check_switch = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("MES_CRC_CHECK_SWITCH", &mes_crc_check_switch));
    mes_set_crc_check_switch(mes_crc_check_switch);

    /* mes use ssl */
    bool32 mes_use_ssl_switch = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("MES_SSL_SWITCH", &mes_use_ssl_switch));
    mes_set_ssl_switch(mes_use_ssl_switch);

    if (mes_use_ssl_switch) {
        char *mes_ssl_crt_path = srv_get_param("MES_SSL_CRT_KEY_PATH");
        if (mes_ssl_crt_path == NULL) {
            return OG_ERROR;
        }
        char cert_dir_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_dir_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, mes_ssl_crt_path));
        char ca_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(ca_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/ca.crt", mes_ssl_crt_path));
        char cert_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.crt", mes_ssl_crt_path));
        char key_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(key_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.key", mes_ssl_crt_path));
        char crl_file_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(crl_file_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.crl", mes_ssl_crt_path));
        char mes_pass_path[OG_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(mes_pass_path, OG_FILE_NAME_BUFFER_SIZE, OG_MAX_FILE_NAME_LEN, "%s/mes.pass", mes_ssl_crt_path));
        OG_RETURN_IFERR(mes_set_ssl_crt_file(cert_dir_path, ca_file_path, cert_file_path, key_file_path, crl_file_path,
            mes_pass_path));
        mes_set_ssl_verify_peer(OG_TRUE);
        char *enc_pwd = srv_get_param("MES_SSL_KEY_PWD");
        OG_RETURN_IFERR(mes_set_ssl_key_pwd(enc_pwd));
    }

    bool32 enable_dbstor = OG_FALSE;
    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR", &enable_dbstor));
    mes_set_dbstor_enable(enable_dbstor);

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_FDSA", &g_enable_fdsa));

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_BROADCAST_ON_COMMIT", &attr->enable_boc));

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_CHECK_SECURITY_LOG", &g_filter_enable));

    OG_RETURN_IFERR(srv_get_param_bool32("ENABLE_SYS_CRC_CHECK", &g_crc_verify));

    OG_RETURN_IFERR(srv_get_param_uint32("MES_CHANNEL_UPGRADE_TIME_MS", &g_dtc->profile.upgrade_time_ms));

    OG_RETURN_IFERR(srv_get_param_uint32("MES_CHANNEL_DEGRADE_TIME_MS", &g_dtc->profile.degrade_time_ms));

    uint16 cluster_id;
    OG_RETURN_IFERR(srv_get_param_uint16("CLUSTER_ID", &cluster_id));

    if (g_dtc->profile.pipe_type == CS_TYPE_UC || g_dtc->profile.pipe_type == CS_TYPE_UC_RDMA || enable_dbstor) {
        OG_RETURN_IFERR(set_all_inst_lsid(cluster_id, 0));
    }

    if (!enable_dbstor) {
        value = srv_get_param("SHARED_PATH");
        if (value == NULL) {
            OG_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'SHARED_PATH'");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(cm_set_file_iof_cfg(cluster_id, 0, value));
    }

    OG_RETURN_IFERR(srv_get_param_bool32("_ENABLE_RMO_CR", &g_dtc->profile.enable_rmo_cr));

    OG_RETURN_IFERR(srv_get_param_uint32("_REMOTE_ACCESS_LIMIT", &g_dtc->profile.remote_access_limit));
    if (g_dtc->profile.remote_access_limit > OG_REMOTE_ACCESS_LIMIT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_REMOTE_ACCESS_LIMIT");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_double("DTC_CKPT_NOTIFY_TASK_RATIO", &g_dtc->profile.ckpt_notify_task_ratio));
    if ((g_dtc->profile.ckpt_notify_task_ratio < OG_MES_MIN_TASK_RATIO) ||
        (g_dtc->profile.ckpt_notify_task_ratio > OG_MES_MAX_TASK_RATIO)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "DTC_CKPT_NOTIFY_TASK_RATIO");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_double("DTC_CLEAN_EDP_TASK_RATIO", &g_dtc->profile.clean_edp_task_ratio));
    if ((g_dtc->profile.clean_edp_task_ratio < OG_MES_MIN_TASK_RATIO) ||
        (g_dtc->profile.clean_edp_task_ratio > OG_MES_MAX_TASK_RATIO)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "DTC_CLEAN_EDP_TASK_RATIO");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(srv_get_param_double("DTC_TXN_INFO_TASK_RATIO", &g_dtc->profile.txn_info_task_ratio));
    if ((g_dtc->profile.txn_info_task_ratio < OG_MES_MIN_TASK_RATIO) ||
        (g_dtc->profile.txn_info_task_ratio > OG_MES_MAX_TASK_RATIO)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "DTC_TXN_INFO_TASK_RATIO");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
