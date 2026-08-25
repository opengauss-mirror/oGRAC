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

static bool32 srv_match_bool_text_true_false(const text_t *bool_text, bool32 *bool_value)
{
    text_t text;

    if (bool_text == NULL) {
        return OG_FALSE;
    }

    text = *bool_text;
    cm_trim_text(&text);
    if (text.len == 0) {
        return OG_FALSE;
    }

    if (cm_compare_text_str_ins(&text, "FALSE") == 0) {
        *bool_value = OG_FALSE;
        return OG_TRUE;
    }
    if (cm_compare_text_str_ins(&text, "TRUE") == 0) {
        *bool_value = OG_TRUE;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static bool32 srv_match_bool_text_zero_one(const text_t *bool_text, bool32 *bool_value)
{
    text_t text;

    if (bool_text == NULL) {
        return OG_FALSE;
    }

    text = *bool_text;
    cm_trim_text(&text);
    if (text.len != 1) {
        return OG_FALSE;
    }

    if (text.str[0] == '0') {
        *bool_value = OG_FALSE;
        return OG_TRUE;
    }
    if (text.str[0] == '1') {
        *bool_value = OG_TRUE;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 srv_match_bool_text_onoff(const text_t *bool_text, bool32 *bool_value)
{
    text_t text;

    if (bool_text == NULL) {
        return OG_FALSE;
    }

    text = *bool_text;
    cm_trim_text(&text);
    if (cm_compare_text_str_ins(&text, "OFF") == 0) {
        *bool_value = OG_FALSE;
        return OG_TRUE;
    }
    if (cm_compare_text_str_ins(&text, "ON") == 0) {
        *bool_value = OG_TRUE;
        return OG_TRUE;
    }
    return OG_FALSE;
}

bool32 srv_match_bool_text_ext(const text_t *bool_text, bool32 *bool_value)
{
    return srv_match_bool_text_true_false(bool_text, bool_value) ||
        srv_match_bool_text_zero_one(bool_text, bool_value) ||
        srv_match_bool_text_onoff(bool_text, bool_value);
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
    bool32 bool_value = ((bool32)value[0] == OG_TRUE) ? OG_TRUE : OG_FALSE;

    if (value[1] != '\0') {
        bool_value = (bool32)cm_str_equal_ins(value, "TRUE");
    }

    value[0] = (char)bool_value;
    value[1] = '\0';

    if (bool_value == OG_TRUE) {
        PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "TRUE"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "FALSE"));
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_zero_one(void *se, void *lex, void *def)
{
    /* TODO: implement native parser validation for the 0/1 syntax. */
    return sql_verify_als_bool(se, lex, def);
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
    if (lex_parse_and_valid_pool_size(lex, &size, min_size, max_size) != OG_SUCCESS) {
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


/* Bison ALTER SYSTEM verifier adapters. */

status_t sql_bison_copy_sys_param_value(bison_sys_param_value_t *source, knl_alter_sys_def_t *def)
{
    text_t value = source->text;

    if (value.len == 0) {
        OG_SRC_THROW_ERROR(source->loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    if (value.len >= 2 && value.str[0] == '\'' && value.str[0] == CM_TEXT_END(&value)) {
        if (!source->is_string) {
            OG_SRC_THROW_ERROR(source->extra_token_loc, ERR_SQL_SYNTAX_ERROR, "syntax error");
            return OG_ERROR;
        }
        value = source->decoded_string;
    } else if (value.len >= 2 && CM_IS_QUOTE_CHAR(value.str[0]) && value.str[0] == CM_TEXT_END(&value)) {
        value.str++;
        value.len -= 2;
    }
    OG_RETURN_IFERR(sql_bison_store_sys_param_text(&value, def));
    return OG_SUCCESS;
}

status_t sql_bison_store_sys_param_text(const text_t *value, knl_alter_sys_def_t *def)
{
    if (value->len >= sizeof(def->value)) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, def->param, (int64)sizeof(def->value) - 1);
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memmove_s(def->value, sizeof(def->value), value->str, value->len));
    def->value[value->len] = '\0';
    return OG_SUCCESS;
}

status_t sql_bison_reset_sys_param_value(knl_alter_sys_def_t *def)
{
    /* Native verifiers write binary values into a zero-initialized value buffer. */
    MEMS_RETURN_IFERR(memset_s(def->value, sizeof(def->value), 0, sizeof(def->value)));
    return OG_SUCCESS;
}

void sql_bison_extra_init_reader(bison_param_reader_t *reader, const text_t *value,
    source_location_t loc)
{
    reader->remaining = *value;
    reader->loc = loc;
}

static bool32 sql_bison_extra_is_punctuation(char ch)
{
    return ch == '(' || ch == ')' || ch == ',' || ch == '=';
}

static status_t sql_bison_extra_append_token_char(bison_param_token_t *token, char ch)
{
    if (token->text.len >= sizeof(token->value) - 1) {
        OG_THROW_ERROR(ERR_BUFFER_OVERFLOW, token->text.len + 1, sizeof(token->value) - 1);
        return OG_ERROR;
    }
    token->value[token->text.len++] = ch;
    token->value[token->text.len] = '\0';
    return OG_SUCCESS;
}

static status_t sql_bison_extra_fetch_quoted_token(bison_param_reader_t *reader,
    bison_param_token_t *token, bool32 *found)
{
    text_t *text = &reader->remaining;
    char quote = text->str[0];

    if (quote == '\'') {
        token->type = BISON_PARAM_TOKEN_STRING;
    } else if (quote == '"') {
        token->type = BISON_PARAM_TOKEN_DQ_STRING;
    } else {
        token->type = BISON_PARAM_TOKEN_BACKTICK_STRING;
    }
    text->str++;
    text->len--;

    while (text->len > 0) {
        if (text->str[0] != quote) {
            OG_RETURN_IFERR(sql_bison_extra_append_token_char(token, text->str[0]));
            text->str++;
            text->len--;
            continue;
        }
        if (text->len > 1 && text->str[1] == quote) {
            OG_RETURN_IFERR(sql_bison_extra_append_token_char(token, quote));
            text->str += 2;
            text->len -= 2;
            continue;
        }
        text->str++;
        text->len--;
        *found = OG_TRUE;
        return OG_SUCCESS;
    }

    OG_SRC_THROW_ERROR_EX(reader->loc, ERR_SQL_SYNTAX_ERROR, "unterminated quoted parameter value");
    return OG_ERROR;
}

status_t sql_bison_extra_fetch_token(bison_param_reader_t *reader, bison_param_token_t *token,
    bool32 *found)
{
    text_t *text = &reader->remaining;

    MEMS_RETURN_IFERR(memset_s(token, sizeof(*token), 0, sizeof(*token)));
    token->text.str = token->value;
    OG_RETURN_IFERR(sql_bison_skip_sys_param_separators(&reader->remaining, reader->loc));
    if (text->len == 0) {
        *found = OG_FALSE;
        return OG_SUCCESS;
    }

    if (sql_bison_extra_is_punctuation(text->str[0])) {
        token->type = BISON_PARAM_TOKEN_PUNCTUATION;
        OG_RETURN_IFERR(sql_bison_extra_append_token_char(token, text->str[0]));
        text->str++;
        text->len--;
        *found = OG_TRUE;
        return OG_SUCCESS;
    }

    if (CM_IS_QUOTE_CHAR(text->str[0])) {
        return sql_bison_extra_fetch_quoted_token(reader, token, found);
    }

    while (text->len > 0 && !cm_is_space(text->str[0]) && !sql_bison_extra_is_punctuation(text->str[0]) &&
        !(text->len >= 2 && text->str[0] == '-' && text->str[1] == '-') &&
        !(text->len >= 2 && text->str[0] == '/' && text->str[1] == '*')) {
        OG_RETURN_IFERR(sql_bison_extra_append_token_char(token, text->str[0]));
        text->str++;
        text->len--;
    }
    *found = OG_TRUE;
    return OG_SUCCESS;
}

status_t sql_bison_extra_expected_end(bison_param_reader_t *reader)
{
    OG_RETURN_IFERR(sql_bison_skip_sys_param_separators(&reader->remaining, reader->loc));
    if (reader->remaining.len != 0) {
        OG_SRC_THROW_ERROR_EX(reader->loc, ERR_SQL_SYNTAX_ERROR, "unexpected text in parameter value");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_bison_extra_make_string_token(const text_t *value, bison_param_token_t *token)
{
    MEMS_RETURN_IFERR(memset_s(token, sizeof(*token), 0, sizeof(*token)));
    token->text.str = token->value;
    token->type = BISON_PARAM_TOKEN_STRING;
    if (value->len >= sizeof(token->value)) {
        OG_THROW_ERROR(ERR_BUFFER_OVERFLOW, value->len, sizeof(token->value) - 1);
        return OG_ERROR;
    }
    if (value->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(token->value, sizeof(token->value), value->str, value->len));
    }
    token->value[value->len] = '\0';
    token->text.len = value->len;
    return OG_SUCCESS;
}

status_t sql_bison_extra_get_single_token(const bison_sys_param_value_t *source, bison_param_token_t *token)
{
    bison_param_reader_t reader;
    bison_param_token_t extra;
    text_t value;
    bool32 found;

    if (source->is_string) {
        value = source->text;
        if (value.len >= 2 && CM_IS_QUOTE_CHAR(value.str[0]) && value.str[0] == CM_TEXT_END(&value)) {
            value.str++;
            value.len -= 2;
        }
        return sql_bison_extra_make_string_token(&value, token);
    }

    sql_bison_extra_init_reader(&reader, &source->text, source->loc);
    OG_RETURN_IFERR(sql_bison_extra_fetch_token(&reader, token, &found));
    if (!found) {
        OG_SRC_THROW_ERROR(source->loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_bison_extra_fetch_token(&reader, &extra, &found));
    if (found) {
        OG_SRC_THROW_ERROR_EX(source->extra_token_loc, ERR_SQL_SYNTAX_ERROR, "expected end but %.*s found",
            (int)extra.text.len, extra.text.str);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_bison_extra_get_decoded_single_token(const bison_sys_param_value_t *source,
    bison_param_token_t *token)
{
    if (!source->is_string) {
        return sql_bison_extra_get_single_token(source, token);
    }
    return sql_bison_extra_make_string_token(&source->decoded_string, token);
}

status_t sql_bison_extra_expected_fetch_1ofn(const bison_sys_param_value_t *source, uint32 *matched_id,
    int num, ...)
{
    int iret_snprintf;
    va_list ap;
    uint32 msg_len;
    uint32 remain_msg_len;
    int i = num;
    uint32 j = 0;
    char message[OG_MESSAGE_BUFFER_SIZE] = { 0 };
    bison_param_token_t token;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    va_start(ap, num);
    while (i > 0) {
        const char *word = (const char *)va_arg(ap, const char *);

        if (cm_text_str_equal_ins(&token.text, word)) {
            *matched_id = j;
            va_end(ap);
            return OG_SUCCESS;
        }

        msg_len = (uint32)strlen(message);
        remain_msg_len = OG_MESSAGE_BUFFER_SIZE - msg_len;
        if (i != 1) {
            iret_snprintf = snprintf_s(message + msg_len, remain_msg_len, remain_msg_len - 1, "%s or ", word);
            if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
                va_end(ap);
                OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
                return OG_ERROR;
            }
        } else {
            iret_snprintf = snprintf_s(message + msg_len, remain_msg_len, remain_msg_len - 1, "%s", word);
        }
        if (iret_snprintf == -1) {
            va_end(ap);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_ERROR;
        }

        j++;
        i--;
    }
    va_end(ap);

    *matched_id = OG_INVALID_ID32;
    OG_SRC_THROW_ERROR_EX(source->loc, ERR_SQL_SYNTAX_ERROR, "%s expected", message);
    return OG_ERROR;
}

status_t sql_bison_extra_expected_fetch_1of2(const bison_sys_param_value_t *source, const char *word1,
    const char *word2, uint32 *matched_id)
{
    return sql_bison_extra_expected_fetch_1ofn(source, matched_id, 2, word1, word2);
}

status_t sql_bison_extra_expected_fetch_1of3(const bison_sys_param_value_t *source, const char *word1,
    const char *word2, const char *word3, uint32 *matched_id)
{
    return sql_bison_extra_expected_fetch_1ofn(source, matched_id, 3, word1, word2, word3);
}

status_t sql_bison_extra_expected_fetch_word(const bison_sys_param_value_t *source, const char *word)
{
    uint32 matched_id;
    return sql_bison_extra_expected_fetch_1ofn(source, &matched_id, 1, word);
}

status_t sql_bison_extra_parse_uint32(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def,
    uint32 *value)
{
    bison_param_token_t token;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    cm_trim_text(&token.text);
    if (token.text.len == 0) {
        OG_SRC_THROW_ERROR(source->loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }
    /* The native scanner returns only the leading minus for an unquoted negative value. */
    if (token.type == BISON_PARAM_TOKEN_WORD && token.text.str[0] == '-') {
        token.text.len = 1;
    }
    if (cm_text2uint32(&token.text, value) != OG_SUCCESS) {
        cm_try_set_error_loc(source->loc);
        return OG_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(def->value, sizeof(def->value), sizeof(def->value) - 1,
        PRINT_FMT_UINT32, *value));
    return OG_SUCCESS;
}

static status_t sql_bison_extra_invalid_size(source_location_t loc)
{
    cm_reset_error();
    OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "size must be a positive long integer");
    return OG_ERROR;
}

static status_t sql_bison_extra_invalid_number(source_location_t loc)
{
    cm_reset_error();
    cm_set_error((char *)__FILE__, (uint32)__LINE__, ERR_INVALID_NUMBER, "Invalid number");
    cm_set_error_loc(loc);
    return OG_ERROR;
}

static status_t sql_bison_parse_size_value(const bison_sys_param_value_t *source, const text_t *value,
    bool32 is_unquoted, bool32 is_pool_size, int64 *size)
{
    text_t digits = *value;
    num_part_t np;
    og_type_t type;
    bool32 has_unit = OG_FALSE;

    if (is_unquoted && CM_IS_SIGN_CHAR(CM_TEXT_FIRST(&digits))) {
        return sql_bison_extra_invalid_size(source->loc);
    }

    np.excl_flag = NF_DOT | NF_EXPN | NF_NEGATIVE_SIGN;
    switch (UPPER(CM_TEXT_END(&digits))) {
        case 'B':
        case 'K':
        case 'M':
        case 'G':
        case 'T':
        case 'P':
        case 'E':
            has_unit = OG_TRUE;
            np.sz_indicator = CM_TEXT_END(&digits);
            digits.len--;
            break;
        case 'S':
            has_unit = OG_TRUE;
            if (digits.len > 1 && UPPER(digits.str[digits.len - 2]) == 'M') {
                np.sz_indicator = digits.str[digits.len - 2];
                digits.len -= 2;
            } else {
                np.sz_indicator = CM_TEXT_END(&digits);
                digits.len--;
            }
            break;
        default:
            break;
    }
    if (digits.len == 0) {
        return sql_bison_extra_invalid_size(source->loc);
    }
    for (uint32 i = 0; i < value->len; i++) {
        if (value->str[i] == '.') {
            if (is_unquoted && has_unit) {
                return sql_bison_extra_invalid_number(source->loc);
            }
            return sql_bison_extra_invalid_size(source->loc);
        }
    }

    if (cm_split_num_text(&digits, &np) != NERR_SUCCESS ||
        cm_decide_numtype(&np, &type) != NERR_SUCCESS || !OG_IS_INTEGER_TYPE(type)) {
        return sql_bison_extra_invalid_size(source->loc);
    }

    if (!has_unit) {
        if (cm_numpart2bigint(&np, size) != NERR_SUCCESS) {
            return sql_bison_extra_invalid_size(source->loc);
        }
        return OG_SUCCESS;
    }
    if (is_pool_size && UPPER(np.sz_indicator) != 'S' && value->len > np.digit_text.len + 1) {
        return sql_bison_extra_invalid_size(source->loc);
    }
    if (cm_numpart2size(&np, size) != NERR_SUCCESS) {
        return sql_bison_extra_invalid_size(source->loc);
    }
    return OG_SUCCESS;
}

status_t sql_bison_extra_verify_pool_size(const bison_sys_param_value_t *source,
    knl_alter_sys_def_t *def, int64 min_size, int64 max_size)
{
    bison_param_token_t token;
    text_t normalized;
    int64 size;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    normalized = token.text;
    cm_trim_text(&normalized);
    if (normalized.len == 0) {
        return sql_bison_extra_invalid_size(source->loc);
    }
    OG_RETURN_IFERR(sql_bison_parse_size_value(source, &normalized,
        token.type == BISON_PARAM_TOKEN_WORD, OG_TRUE, &size));
    if (size < min_size) {
        OG_SRC_THROW_ERROR_EX(source->loc, ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum("
            PRINT_FMT_INT64 ") required", min_size);
        return OG_ERROR;
    }
    if (size > max_size) {
        OG_SRC_THROW_ERROR_EX(source->loc, ERR_SQL_SYNTAX_ERROR, "size value is bigger than maximum("
            PRINT_FMT_INT64 ") required", max_size);
        return OG_ERROR;
    }
    return sql_bison_store_sys_param_text(&normalized, def);
}

status_t sql_bison_verify_pool_size(SQL_BISON_VERIFY_ARGS)
{
    return sql_bison_extra_verify_pool_size((const bison_sys_param_value_t *)source,
        (knl_alter_sys_def_t *)def, min_value, max_value);
}

status_t sql_bison_extra_parse_real(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def,
    double *value)
{
    bison_param_token_t token;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    cm_trim_text(&token.text);
    if (token.text.len == 0) {
        OG_SRC_THROW_ERROR(source->loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }
    if (cm_text2real(&token.text, value) != OG_SUCCESS) {
        cm_try_set_error_loc(source->loc);
        return OG_ERROR;
    }
    return sql_bison_store_sys_param_text(&token.text, def);
}

status_t sql_bison_extra_parse_size(const bison_sys_param_value_t *source, knl_alter_sys_def_t *def,
    int64 *value)
{
    bison_param_token_t token;
    text_t normalized;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    normalized = token.text;
    cm_trim_text(&normalized);
    if (normalized.len == 0) {
        OG_SRC_THROW_ERROR(source->loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_bison_parse_size_value(source, &normalized,
        token.type == BISON_PARAM_TOKEN_WORD, OG_FALSE, value));
    return sql_bison_store_sys_param_text(&normalized, def);
}

status_t sql_bison_verify_onoff(SQL_BISON_VERIFY_ARGS)
{
    uint32 matched_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    OG_RETURN_IFERR(sql_bison_extra_expected_fetch_1of2((bison_sys_param_value_t *)source,
        "OFF", "ON", &matched_id));
    OG_RETURN_IFERR(sql_bison_reset_sys_param_value(sys_def));
    sys_def->value[0] = (char)matched_id;
    sys_def->value[1] = '\0';
    return OG_SUCCESS;
}

static status_t sql_bison_invalid_uint32_range(source_location_t loc, int64 min_value, int64 max_value)
{
    cm_reset_error();
    cm_set_error((char *)__FILE__, (uint32)__LINE__, ERR_INVALID_NUMBER,
        "Invalid number, range is [" PRINT_FMT_INT64 "," PRINT_FMT_INT64 "]", min_value, max_value);
    cm_set_error_loc(loc);
    return OG_ERROR;
}

status_t sql_bison_verify_uint32_range(SQL_BISON_VERIFY_ARGS)
{
    uint32 num;
    const bison_sys_param_value_t *value = (const bison_sys_param_value_t *)source;

    if (sql_bison_extra_parse_uint32(source, def, &num) != OG_SUCCESS) {
        return sql_bison_invalid_uint32_range(value->loc, min_value, max_value);
    }
    if ((int64)num < min_value || (int64)num > max_value) {
        return sql_bison_invalid_uint32_range(value->loc, min_value, max_value);
    }
    return OG_SUCCESS;
}

status_t sql_bison_skip_sys_param_separators(text_t *remaining, source_location_t loc)
{
    for (;;) {
        cm_ltrim_text(remaining);
        if (remaining->len < 2) {
            return OG_SUCCESS;
        }

        if (remaining->str[0] == '-' && remaining->str[1] == '-') {
            remaining->str += 2;
            remaining->len -= 2;
            while (remaining->len > 0 && remaining->str[0] != '\n' && remaining->str[0] != '\r') {
                remaining->str++;
                remaining->len--;
            }
            continue;
        }

        if (remaining->str[0] != '/' || remaining->str[1] != '*') {
            return OG_SUCCESS;
        }

        uint32 depth = 1;
        remaining->str += 2;
        remaining->len -= 2;
        while (remaining->len > 0 && depth > 0) {
            if (remaining->len >= 2 && remaining->str[0] == '/' && remaining->str[1] == '*') {
                depth++;
                remaining->str += 2;
                remaining->len -= 2;
            } else if (remaining->len >= 2 && remaining->str[0] == '*' && remaining->str[1] == '/') {
                depth--;
                remaining->str += 2;
                remaining->len -= 2;
            } else {
                remaining->str++;
                remaining->len--;
            }
        }
        if (depth != 0) {
            OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR, "unterminated comment in parameter value");
            return OG_ERROR;
        }
    }
}

status_t sql_bison_verify_bool(SQL_BISON_VERIFY_ARGS)
{
    bison_param_token_t token;
    bool32 bool_value;
    bool32 supported_token;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    supported_token = token.type == BISON_PARAM_TOKEN_WORD || token.type == BISON_PARAM_TOKEN_STRING;
    if (!supported_token || !srv_match_bool_text_ext(&token.text, &bool_value)) {
        OG_SRC_THROW_ERROR_EX(((bison_sys_param_value_t *)source)->loc, ERR_SQL_SYNTAX_ERROR,
            "invalid parameter value");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_bison_reset_sys_param_value(sys_def));
    sys_def->value[0] = (char)bool_value;
    sys_def->value[1] = '\0';
    return OG_SUCCESS;
}

status_t sql_bison_verify_zero_one(SQL_BISON_VERIFY_ARGS)
{
    bison_param_token_t token;
    bool32 bool_value;
    bool32 supported_token;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    OG_RETURN_IFERR(sql_bison_extra_get_single_token(source, &token));
    supported_token = token.type == BISON_PARAM_TOKEN_WORD || token.type == BISON_PARAM_TOKEN_STRING;
    if (!supported_token || !srv_match_bool_text_zero_one(&token.text, &bool_value)) {
        OG_SRC_THROW_ERROR_EX(((bison_sys_param_value_t *)source)->loc, ERR_SQL_SYNTAX_ERROR,
            "invalid parameter value");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_bison_reset_sys_param_value(sys_def));
    sys_def->value[0] = bool_value == OG_TRUE ? '1' : '0';
    sys_def->value[1] = '\0';
    return OG_SUCCESS;
}

status_t sql_bison_verify_comm(SQL_BISON_VERIFY_ARGS)
{
    bison_param_token_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (sql_bison_extra_get_single_token(source, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.text.len >= OG_PARAM_BUFFER_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, sys_def->param, (int64)OG_PARAM_BUFFER_SIZE - 1);
        return OG_ERROR;
    }

    return cm_text2str(&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);
}


#ifdef __cplusplus
}
#endif
