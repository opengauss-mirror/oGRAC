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
 * set_server.c
 *
 *
 * IDENTIFICATION
 * src/server/params/set_server.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_param.h"
#include "ddl_parser.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "knl_spm.h"
#include "dtc_context.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_als_uds_file_path(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    word_t word;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type != WORD_TYPE_STRING) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return OG_ERROR;
    }
    LEX_REMOVE_WRAP(&word);
    OG_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE));
    return verify_uds_file_path((const char *)sys_def->value);
}

status_t sql_verify_als_uds_file_permissions(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return verify_uds_file_permission((uint16)num);
}

status_t sql_verify_als_deadlock_detect_interval(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!IS_DEADLOCK_INTERVAL_PARAM_VALID(num)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_DEADLOCK_DETECT_INTERVAL");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_auto_undo_retention(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_bool_only_sys_allowed(void *se, void *lex, void *def)
{
    knl_session_t *session = (knl_session_t *)se;
    if (session->uid != DB_SYS_USER_ID) {
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }
    return sql_verify_als_bool(se, lex, def);
}

status_t sql_notify_als_access_dc_enable_bool(void *se, void *item, char *value)
{
    g_instance->attr.access_dc_enable = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_view_access_dc_bool(void *se, void *item, char *value)
{
    g_instance->attr.view_access_dc = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_optimized_worker_threads(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_OPTIMIZED_WORKER_COUNT || num > OG_MAX_OPTIMIZED_WORKER_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "OPTIMIZED_WORKER_THREADS");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_max_worker_threads(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_OPTIMIZED_WORKER_COUNT || num > OG_MAX_OPTIMIZED_WORKER_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_WORKER_THREADS");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_agent_shrink_threshold(void *se, void *lex, void *def)
{
    uint32 num;

    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_SECS_AGENTS_SHRINK) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "WORKER_THREADS_SHRINK_THRESHOLD", (int32)OG_MAX_SECS_AGENTS_SHRINK);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_db_tz(void *se, void *lex, void *def)
{
    word_t value;
    timezone_info_t dbtz_new;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    char param_new_value[TIMEZONE_OFFSET_STRLEN] = { 0 };
    text_t normal_tz;

    OG_RETURN_IFERR(lex_expected_fetch_string(lex, &value));
    sql_remove_quota(&value.text.value);

    if (value.text.value.len >= OG_PARAM_BUFFER_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, sys_def->param, (int64)OG_PARAM_BUFFER_SIZE - 1);
        return OG_ERROR;
    }

    // normalize this tz str and to check if this value is valid
    OG_RETURN_IFERR(cm_text2tzoffset(&value.text.value, &dbtz_new));
    normal_tz.str = param_new_value;
    OG_RETURN_IFERR(cm_tzoffset2text(dbtz_new, &normal_tz));

    OG_RETURN_IFERR(cm_text2str(&normal_tz, sys_def->value, OG_PARAM_BUFFER_SIZE));

    return OG_SUCCESS;
}

status_t sql_verify_als_reactor_threads(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num == 0 || num > OG_MAX_REACTOR_POOL_COUNT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREADS");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_super_user_sessions(void *se, void *lex, void *def)
{
    uint32 num = 0;

    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_EMERG_SESSIONS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SUPER_USER_RESERVED_SESSIONS", (int64)OG_MAX_EMERG_SESSIONS);
        return OG_ERROR;
    }

    if (num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SUPER_USER_RESERVED_SESSIONS", (int64)1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_normal_emerge_sess_factor(void *se, void *lex, void *def)
{
    double num;
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    if (cm_text2real((text_t *)&word.text, &num)) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE));

    if (num > 1 || num < 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "NORMAL_USER_RESERVED_SESSIONS_FACTOR");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_normal_emerge_sess_factor(void *se, void *item, char *value)
{
    return cm_str2real(value, &g_instance->kernel.attr.normal_emerge_sess_factor);
}

status_t sql_verify_als_sessions(void *se, void *lex, void *def)
{
    uint32 num;

    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num <= g_instance->kernel.reserved_sessions + g_instance->sql_emerg_pool.max_sessions) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SESSIONS",
            (int64)(g_instance->kernel.reserved_sessions + g_instance->sql_emerg_pool.max_sessions + 1));
        return OG_ERROR;
    }

    if (num > OG_MAX_SESSIONS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SESSIONS", (int64)OG_MAX_SESSIONS);
        return OG_ERROR;
    }

    // SESSIONS modified:  current_value <= num <= expanded_max_sessions will work immediately,
    // otherwise use SCOPE=PFILE to work after reboot
    if (num <= g_instance->session_pool.expanded_max_sessions && num >= g_instance->session_pool.max_sessions) {
        g_instance->session_pool.max_sessions = num;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_parse_scope_clause(sys_def, (lex_t *)lex) != OG_SUCCESS);
    if (sys_def->scope != CONFIG_SCOPE_DISK) {
        OG_SET_HINT("[NOTICE]%s", "Use SCOPE=PFILE to take effect after reboot.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_prefetch_rows(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PREFETCH_ROWS", (int64)1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_prefetch_rows(void *se, void *item, char *value)
{
    uint32 prefetch_rows = 0;

    if (cm_str2uint32(value, &prefetch_rows) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (prefetch_rows < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PREFETCH_ROWS", (int64)1);
        return OG_ERROR;
    }

    g_instance->sql.prefetch_rows = prefetch_rows;
    return OG_SUCCESS;
}

/* The default value of ARRAY_STORAGE_OPTIMIZATION is FALSE, and when set to TRUE, forbidden to set back to FALSE */
status_t sql_notify_als_enable_arr_store_opt(void *se, void *item, char *value)
{
    bool32 set_value = (bool32)value[0];
    if (g_instance->sql.enable_arr_store_opt && !set_value) {
        OG_SET_HINT("[NOTICE]%s", "parameter ARRAY_STORAGE_OPTIMIZATION is TRUE now,"
            " and it is forbidden to set back to FALSE, or there is compatible problem for array data");
        return OG_ERROR;
    }

    g_instance->sql.enable_arr_store_opt = set_value;

    if (set_value) {
        OG_LOG_RUN_WAR("parameter ARRAY_STORAGE_OPTIMIZATION has been setted to TRUE,"
            " and it is forbidden to set back to FALSE, or there is compatible problem for array data");
    }

    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_json_dyn_buf_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_JSON_MIN_DYN_BUF_SIZE, OG_JSON_MAX_DYN_BUF_SIZE);
}

status_t sql_notify_json_dyn_buf_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->sql.json_mpool.max_json_dyn_buf = (uint64)val_int64;
    return OG_SUCCESS;
}

status_t sql_verify_als_encryption_alg(void *se, void *lex, void *def)
{
    bool32 result = OG_FALSE;
    const char *match_words = "SCRAM_SHA256";
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_try_fetch(lex, match_words, &result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (!result) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_ENCRYPTION_ALG");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(sys_def->value, OG_PARAM_BUFFER_SIZE, match_words));
    return OG_SUCCESS;
}

status_t sql_verify_als_sys_password(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }
    OG_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE));

    if (word.text.len == OG_KDF2MAXSTRSIZE) {
        if (cm_convert_kdf2_scram_sha256(sys_def->value, sys_def->value, OG_PARAM_BUFFER_SIZE) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYS_PASSWORD");
            return OG_ERROR;
        }
    } else if (!cm_is_password_valid(sys_def->value)) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYS_PASSWORD");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_sys_password(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    if (session->uid != DB_SYS_USER_ID) {
        OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_encrypt_iteration(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_KDF2MINITERATION) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_ENCRYPTION_ITERATION", (int64)OG_KDF2MINITERATION);
        return OG_ERROR;
    } else if (num > OG_KDF2MAXITERATION) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_ENCRYPTION_ITERATION", (int64)OG_KDF2MAXITERATION);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_encrypt_iteration(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    g_instance->kernel.attr.alg_iter = val;
    return OG_SUCCESS;
}

status_t sql_verify_als_factor_key(void *se, void *lex, void *def)
{
    word_t word;
    char buf[OG_AESBLOCKSIZE * 2];
    char key_buf[OG_MAX_FACTOR_KEY_STR_LEN + 4];
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_parse_scope_clause(sys_def, (lex_t *)lex));

    if (sys_def->scope != CONFIG_SCOPE_BOTH) {
        OG_THROW_ERROR(ERR_PARAMETER_NOT_MODIFIABLE, "_FACTOR_KEY");
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    OG_RETURN_IFERR(cm_text2str(&word.text.value, key_buf, sizeof(key_buf)));

    if (word.text.value.len != OG_MAX_FACTOR_KEY_STR_LEN ||
        cm_base64_decode(key_buf, word.text.value.len, (uchar *)buf, sizeof(buf)) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_FACTOR_KEY");
        return OG_ERROR;
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_local_key(void *se, void *lex, void *def)
{
    word_t word;
    char cipher[OG_PASSWORD_BUFFER_SIZE];
    char key_buf[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4];
    uint32 cipher_len = sizeof(cipher);

    char *factor_key = cm_get_config_value(&g_instance->config, "_FACTOR_KEY");
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "LOCAL_KEY");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_parse_scope_clause(sys_def, (lex_t *)lex));

    if (sys_def->scope != CONFIG_SCOPE_BOTH) {
        OG_THROW_ERROR(ERR_PARAMETER_NOT_MODIFIABLE, "LOCAL_KEY");
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    OG_RETURN_IFERR(cm_text2str(&word.text.value, key_buf, sizeof(key_buf)));

    if (word.text.value.len != OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE || cm_encrypt_passwd(OG_TRUE, (char *)"sys",
        SYS_USER_NAME_LEN, cipher, &cipher_len, key_buf, factor_key) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "LOCAL_KEY");
        return OG_ERROR;
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);
}

static status_t srv_update_ssl_key_passwd(char *old_fk, char *old_lk, char *new_fk, char *new_lk)
{
    char *old_cipher = NULL;
    char temp_plain_buf[OG_ENCRYPTION_SIZE + 1] = { 0 };
    uint32 temp_plain_len = OG_ENCRYPTION_SIZE;
    char new_cipher_buf[OG_ENCRYPTION_SIZE + 1] = { 0 };
    uint32 new_cipher_len = OG_ENCRYPTION_SIZE;

    old_cipher = srv_get_param("SSL_KEY_PASSWORD");
    if (CM_IS_EMPTY_STR(old_cipher)) {
        return OG_SUCCESS;
    }

    if (cm_decrypt_passwd(OG_TRUE, old_cipher, (uint32)strlen(old_cipher), temp_plain_buf, &temp_plain_len,
        old_lk, old_fk) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Decrypt ssl key password failed");
        MEMS_RETURN_IFERR(memset_sp(temp_plain_buf, sizeof(temp_plain_buf), 0, sizeof(temp_plain_buf)));
        return OG_SUCCESS;
    }
    temp_plain_buf[temp_plain_len] = '\0';

    if (cm_encrypt_passwd(OG_TRUE, temp_plain_buf, temp_plain_len, new_cipher_buf, &new_cipher_len,
        new_lk, new_fk) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Re-encrypt ssl key password failed");
        MEMS_RETURN_IFERR(memset_sp(temp_plain_buf, sizeof(temp_plain_buf), 0, sizeof(temp_plain_buf)));
        return OG_SUCCESS;
    }
    MEMS_RETURN_IFERR(memset_sp(temp_plain_buf, sizeof(temp_plain_buf), 0, sizeof(temp_plain_buf)));

    /* try to update the config */
    if (cm_alter_config(&g_instance->config, "SSL_KEY_PASSWORD", new_cipher_buf, CONFIG_SCOPE_BOTH, OG_TRUE) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t srv_save_factor_key(const char *factor_key)
{
    char file_name1[OG_FILE_NAME_BUFFER_SIZE];
    char file_name2[OG_FILE_NAME_BUFFER_SIZE];

    PRTS_RETURN_IFERR(snprintf_s(file_name1, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
        g_instance->home, OG_FKEY_FILENAME1));
    PRTS_RETURN_IFERR(snprintf_s(file_name2, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
        g_instance->home, OG_FKEY_FILENAME2));
    OG_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
    return srv_save_factor_key_file(file_name2, factor_key);
}

status_t sql_notify_als_factor_key(void *se, void *item, char *value)
{
    char new_local_key[OG_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];
    char *old_factor_key = srv_get_param("_FACTOR_KEY");
    char *new_factor_key = value;
    char *old_local_key = srv_get_param("LOCAL_KEY");

    if (cm_str_equal(old_factor_key, value)) {
        return OG_SUCCESS;
    }

    /*
     * new root key FK must has a derived and matched work key LK, LK may be temporary
     * for matched the root FK until execute SQL 'alter system set LOCAL_KEY = "XXX"'.
     */
    OG_RETURN_IFERR(cm_generate_work_key(new_factor_key, new_local_key, sizeof(new_local_key)));

    /*
     * firstly update FK, update ssl key passwd(cipher) with new FK assigned by user and LK assigned internally;
     * save new FK and LK to config;
     * secondly, update srv_update_ssl_key_passwd again, see sql_notify_als_local_key
     * finally, ssl key passwd will be encrypted by user
     */
    if (srv_update_ssl_key_passwd(old_factor_key, old_local_key, new_factor_key, new_local_key) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_UPDATE_PARAMETER_FAIL, "_FACTOR_KEY", "re-encrypting SSL_KEY_PASSWORD error");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_alter_config(&g_instance->config, "LOCAL_KEY", new_local_key, CONFIG_SCOPE_BOTH, OG_TRUE));
    return srv_save_factor_key(new_factor_key);
}

status_t sql_notify_als_local_key(void *se, void *item, char *value)
{
    config_item_t *it = (config_item_t *)item;
    char *old_key = (it->is_default ? it->default_value : it->value);
    char *old_or_new_factor_key = srv_get_param("_FACTOR_KEY");

    if (cm_str_equal(old_key, value)) {
        return OG_SUCCESS;
    }

    if (srv_update_ssl_key_passwd(old_or_new_factor_key, old_key, old_or_new_factor_key, value) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_UPDATE_PARAMETER_FAIL, "LOCAL_KEY", "re-encrypting SSL_KEY_PASSWORD error");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_login_as_sysdba(void *se, void *item, char *value)
{
    // enable online modify for debug version only
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_instance->session_pool.enable_sysdba_login = (bool32)value[0];
#endif
    OG_RETURN_IFERR(sql_notify_als_bool(se, item, value));

    if (OG_TRUE == GET_ENABLE_SYSDBA_LOGIN) {
        if (srv_init_sysdba_privilege() != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_PRIVS_NOT_GRANT, "sysdba", "logined user");
            return OG_ERROR;
        }
    } else {
        return srv_remove_sysdba_privilege();
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_sys_remote_login(void *se, void *item, char *value)
{
    g_instance->session_pool.enable_sys_remote_login = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_sysdba_remote_login(void *se, void *item, char *value)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_instance->session_pool.enable_sysdba_remote_login = (bool32)value[0];
#endif
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_commit_on_disconn(void *se, void *item, char *value)
{
    g_instance->sql.commit_on_disconn = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_max_connect_by_level(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->sql.max_connect_by_level);
}

status_t sql_verify_als_range_cache(void *se, void *lex, void *def)
{
    uint32 num;

    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_OPT_THRESHOLD) {
        OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_SMALL, "_INDEX_SCAN_RANGE_CACHE",
            (int64)OG_MIN_OPT_THRESHOLD);
        return OG_ERROR;
    }

    if (num > OG_MAX_OPT_THRESHOLD) {
        OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_LARGE, "_INDEX_SCAN_RANGE_CACHE",
            (int64)OG_MAX_OPT_THRESHOLD);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_min_range_cache(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->sql.index_scan_range_cache);
}

status_t sql_notify_als_vm_view_mtrl(void *se, void *item, char *value)
{
    g_instance->sql.vm_view_enabled = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_password_cipher(void *se, void *item, char *value)
{
    g_instance->sql.enable_password_cipher = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_max_allowed_packet(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MAX_PACKET_SIZE, OG_MAX_ALLOWED_PACKET_SIZE);
}

status_t sql_notify_als_max_allowed_packet(void *se, void *item, char *value)
{
    int64 size = 0;
    OG_RETURN_IFERR(cm_str2size(value, &size));
    g_instance->attr.max_allowed_packet = (uint32)size;
    return OG_SUCCESS;
}

status_t sql_notify_als_parallel_policy(void *se, void *item, char *value)
{
    if (g_instance->sql.parallel_policy != (bool32)value[0]) {
        g_instance->sql.parallel_policy = (bool32)value[0];
    }

    return sql_notify_als_onoff(se, item, value);
}

status_t sql_verify_als_interactive_timeout(void *se, void *lex, void *def)
{
    uint32 num;

    OG_RETURN_IFERR(sql_verify_uint32(lex, def, &num));
    if (num == 0) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "INTERACTIVE_TIMEOUT", (int64)1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_interactive_timeout(void *se, void *item, char *value)
{
    uint32 timeout = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &timeout));
    g_instance->sql.interactive_timeout = (uint32)timeout;
    return OG_SUCCESS;
}

status_t sql_notify_zero_divisor_accepted(void *se, void *item, char *value)
{
    // enable only modify for debug version only
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_opr_options.div0_accepted = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
#else
    OG_THROW_ERROR(ERR_NOT_COMPATIBLE, "ZERO_DIVISOR_ACCEPTED");
    return OG_ERROR;
#endif
}

status_t sql_notify_string_as_hex_binary(void *se, void *item, char *value)
{
    // enable only modify for debug version only
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_instance->sql.string_as_hex_binary = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
#else
    OG_THROW_ERROR(ERR_NOT_COMPATIBLE, "STRING_AS_HEX_FOR_BINARY");
    return OG_ERROR;
#endif
}

status_t sql_notify_als_enable_err_superposed(void *se, void *item, char *value)
{
    g_enable_err_superposed = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_unauth_session_expire_time(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    g_instance->session_pool.unauth_session_expire_time = val;
    return OG_SUCCESS;
}

status_t sql_notify_empty_string_null(void *se, void *item, char *value)
{
    // enable only modify for debug version only
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_instance->sql.enable_empty_string_null = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
#else
    OG_THROW_ERROR(ERR_NOT_COMPATIBLE, "EMPTY_STRING_AS_NULL");
    return OG_ERROR;
#endif
}

status_t sql_notify_als_master_backup_synctime(void *se, void *item, char *value)
{
    uint32 size = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &size));
    g_instance->attr.master_slave_difftime = size * MILLISECS_PER_SECOND * MICROSECS_PER_MILLISEC;
    return OG_SUCCESS;
}

status_t sql_notify_als_deadlock_detect_interval(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.deadlock_detect_interval = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_auto_undo_retention(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.auto_undo_retention = val;
    // turn off auto undo retention set undo_ctx.retention as before parameter value
    if (g_instance->kernel.attr.auto_undo_retention == 0) {
        OG_LOG_RUN_INF("_set_undo_retention %u -> %u \n", g_instance->kernel.undo_ctx.retention,
            g_instance->kernel.attr.undo_retention_time);
        g_instance->kernel.undo_ctx.retention = g_instance->kernel.attr.undo_retention_time;
    }
    if (g_instance->kernel.attr.auto_undo_retention > g_instance->kernel.attr.undo_retention_time) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "auto_undo_retention", g_instance->kernel.attr.undo_retention_time);
        return OG_ERROR;
    }
    // set retention time immediately
    if (g_instance->kernel.attr.auto_undo_retention > g_instance->kernel.undo_ctx.retention) {
        OG_LOG_RUN_INF("_set_undo_retention %u -> %u \n", g_instance->kernel.undo_ctx.retention, val);
        g_instance->kernel.undo_ctx.retention = g_instance->kernel.attr.auto_undo_retention;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_res_recycle_ratio(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.res_recycle_ratio);
}

status_t sql_notify_als_create_index_parallelism(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.create_index_parallelism);
}

status_t sql_verify_als_sga_core_dump_config(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SGA_CORE_DUMP_CONFIG");
        return OG_ERROR;
    }

    if (num > OG_MAX_SGA_CORE_DUMP_CONFIG) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SGA_CORE_DUMP_CONFIG");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_sga_core_dump_config(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->attr.core_dump_config);
}

status_t sql_verify_als_job_queue_processes(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_JOB_THREADS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "JOB_THREADS");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_xa_format_id(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    OG_THROW_ERROR(ERR_ALTER_READONLY_PARAMETER, sys_def->param);
    return OG_ERROR;
}

status_t sql_notify_enable_local_infile(void *se, void *item, char *value)
{
    g_instance->attr.enable_local_infile = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_permissive_unicode(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->attr.enable_permissive_unicode = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_disable_var_peek(void *se, void *item, char *value)
{
    g_instance->attr.disable_var_peek = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

static status_t sql_verify_interconnect_port(lex_t *lex, char *portstr, uint32 len)
{
    uint32 port_len = 0;
    uint32 port_count = 0;
    char *port = portstr;
    uint16 value;
    char *pos = NULL;
    uint32 tmp_len = len;
    for (pos = portstr; tmp_len > 0; tmp_len--) {
        if (*pos != ',') {
            port_len++;
            pos++;
            continue;
        }

        *pos = '\0';
        if (cm_str2uint16(port, &value) != OG_SUCCESS) {
            cm_reset_error();
            OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_INVALID_PARAMETER, "port");
            return OG_ERROR;
        }

        if (value < OG_MIN_PORT) {
            OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_SMALL, "port", (int64)OG_MIN_PORT);
            return OG_ERROR;
        }

        *pos = ',';
        port += (port_len + 1);
        port_count++;
        port_len = 0;
        pos = port;
    }

    if (port_len > 0) {
        if (cm_str2uint16(port, &value) != OG_SUCCESS) {
            cm_reset_error();
            OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_INVALID_PARAMETER, "port");
            return OG_ERROR;
        }

        if (value < OG_MIN_PORT) {
            OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_SMALL, "port", (int64)OG_MIN_PORT);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_interconnect_port(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    cm_trim_text((text_t *)&word.text);
    cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);

    /* check if the interconnect port specified is valid */
    return sql_verify_interconnect_port((lex_t *)lex, sys_def->value, (uint32)strlen(sys_def->value));
}

status_t sql_verify_als_interconnect_type(void *se, void *lex, void *def)
{
    // 禁止通过ogsql命令修改 INTERCONNECT_TYPE
    OG_THROW_ERROR(ERR_PARAMETER_NOT_MODIFIABLE, "INTERCONNECT_TYPE");
    return OG_ERROR;
}

status_t sql_verify_als_remote_access_limit(void *se, void *lex, void *def)
{
    uint32 num;

    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_REMOTE_ACCESS_LIMIT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_REMOTE_ACCESS_LIMIT", (int64)OG_REMOTE_ACCESS_LIMIT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_mes_elapsed_switch(void *se, void *item, char *value)
{
    mes_set_elapsed_switch(value[0]);
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_tx_free_page_list(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_tx_free_page_list = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_rmo_cr(void *se, void *item, char *value)
{
    g_dtc->profile.enable_rmo_cr = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_remote_access_limit(void *se, void *item, char *value)
{
    uint32 num;

    if (cm_str2uint32(value, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_REMOTE_ACCESS_LIMIT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_REMOTE_ACCESS_LIMIT", (int64)OG_REMOTE_ACCESS_LIMIT);
        return OG_ERROR;
    }

    g_dtc->profile.remote_access_limit = num;
    return OG_SUCCESS;
}

status_t sql_notify_als_gdv_sess_tmout(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_dtc->profile.gdv_sql_sess_tmout);
}

status_t sql_verify_als_mes_task_ratio(void *se, void *lex, void *def)
{
    double num;
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    if (cm_text2real((text_t *)&word.text, &num)) {
        return OG_ERROR;
    }

    cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);

    if (num > OG_MES_MAX_TASK_RATIO || num < OG_MES_MIN_TASK_RATIO) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "MES_TASK_RATIO");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
