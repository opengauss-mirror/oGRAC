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
 * srv_param_common.c
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_instance.h"
#include "srv_param_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// ADD CONFIG VERIFY-NOTIFY FUNC HERE
status_t sql_verify_als_comm(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (word.text.value.len >= OG_PARAM_BUFFER_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, sys_def->param, (int64)OG_PARAM_BUFFER_SIZE - 1);
        return OG_ERROR;
    }

    return cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_onoff(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2((lex_t *)lex, "OFF", "ON", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    sys_def->value[0] = (char)match_id;
    return OG_SUCCESS;
}

status_t sql_verify_als_uint32(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_uint32(void *lex, void *def, uint32 *num)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    if (cm_text2uint32((text_t *)&word.text, num)) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, *num));
    return OG_SUCCESS;
}

status_t sql_verify_als_bool(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    // match_id matched with OG_FALSE/OG_TRUE
    if (lex_expected_fetch_1of2((lex_t *)lex, "FALSE", "TRUE", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    sys_def->value[0] = (char)match_id;
    return OG_SUCCESS;
}

status_t sql_notify_als_bool(void *se, void *item, char *value)
{
    if ((bool32)value[0] == OG_TRUE) {
        PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "TRUE"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "FALSE"));
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_onoff(void *se, void *item, char *value)
{
    int iret_snprintf;
    if ((bool32)value[0] == OG_TRUE) {
        iret_snprintf = snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "ON");
        if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_ERROR;
        }
    } else {
        iret_snprintf = snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "OFF");
    }
    if (iret_snprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

char *srv_get_param(const char *name)
{
    return cm_get_config_value(&g_instance->config, name);
}

status_t srv_get_param_bool32(char *param_name, bool32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (cm_str_equal_ins(value, "TRUE")) {
        *param_value = OG_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        *param_value = OG_FALSE;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t srv_get_param_onoff(char *param_name, bool32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (cm_str_equal_ins(value, "ON")) {
        *param_value = OG_TRUE;
    } else if (cm_str_equal_ins(value, "OFF")) {
        *param_value = OG_FALSE;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t srv_get_param_uint16(char *param_name, uint16 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2uint16(value, param_value) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t srv_get_param_uint32(char *param_name, uint32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2uint32(value, param_value) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t srv_get_param_uint64(char *param_name, uint64 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2uint64(value, param_value) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t srv_get_param_second(char *param_name, uint64 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2microsecond(value, param_value) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t srv_get_param_double(char *param_name, double *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2real(value, param_value) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t srv_get_param_size_uint32(char *param_name, uint32 *param_value)
{
    char *value = srv_get_param(param_name);
    int64 val_int64 = 0;

    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2size(value, &val_int64) != OG_SUCCESS || val_int64 < 0 || val_int64 > UINT_MAX) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    *param_value = (uint32)val_int64;
    return OG_SUCCESS;
}

status_t srv_get_param_size_uint64(char *param_name, uint64 *param_value)
{
    char *value = srv_get_param(param_name);
    int64 val_int64 = 0;

    if (value == NULL || strlen(value) == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    if (cm_str2size(value, &val_int64) != OG_SUCCESS || val_int64 < 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return OG_ERROR;
    }

    *param_value = (uint64)val_int64;
    return OG_SUCCESS;
}

status_t srv_verf_param_uint64(char *param_name, uint64 param_value, uint64 min_value, uint64 max_value)
{
    if (param_value < min_value) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, param_name, (int64)min_value);
        return OG_ERROR;
    }
    if (param_value > max_value) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, param_name, (int64)max_value);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_pool_size(void *lex, void *def, int64 min_size, int64 max_size)
{
    word_t word;
    int64 size;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_push(lex, &word.text));
    if (lex_expected_fetch_size(lex, &size, min_size, max_size) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);

    return cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);
}

#define HOUR_MAX 23
#define MINUTE_MAX 59
#define SECOND_MAX 59
#define TIME_MIN 0
status_t srv_get_index_auto_rebuild(char *time_str, knl_attr_t *attr)
{
    text_t time_text;
    uint32 hour;
    uint32 minute;
    uint32 second;
    cm_str2text(time_str, &time_text);
    cm_trim_text(&time_text);

    if (time_text.len == 0) {
        attr->idx_auto_rebuild_start_date = OG_INVALID_ID32;
        return OG_SUCCESS;
    }

    if (cm_fetch_date_field(&time_text, TIME_MIN, HOUR_MAX, ':', &hour) != OG_SUCCESS ||
        cm_fetch_date_field(&time_text, TIME_MIN, MINUTE_MAX, ':', &minute) != OG_SUCCESS ||
        cm_fetch_date_field(&time_text, TIME_MIN, SECOND_MAX, '\0', &second) != OG_SUCCESS || time_text.len != 0) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "time");
        return OG_ERROR;
    }

    attr->idx_auto_rebuild_start_date = hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MIN + second;
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
