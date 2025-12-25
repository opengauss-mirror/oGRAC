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
 * set_kernel.c
 *
 *
 * IDENTIFICATION
 * src/server/params/set_kernel.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_param.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "cm_io_record.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

extern bool32 g_crc_verify;
status_t sql_verify_als_page_size(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "8K", "16K", "32K" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return OG_SUCCESS;
}

// verify the column count parameter when execute alter system set COLUMN_COUNT clause
status_t sql_verify_als_max_column_count(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    uint32 param_value;
    char *match_word[] = { "1024", "2048", "3072", "4096" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1ofn(lex, &match_id, 4, match_word[0], match_word[1], match_word[2], match_word[3]) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    iret_sprintf =
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return OG_ERROR;
    }

    if (cm_str2uint32(sys_def->value, &param_value) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, sys_def->value);
        return OG_ERROR;
    }

    if (g_instance->kernel.attr.max_column_count > param_value) {
        OG_THROW_ERROR(ERR_UPDATE_PARAMETER_FAIL, sys_def->param, "new value should be larger than the current value");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_ini_trans(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_TRANS || num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INI_TRANS", (int64)1, (int64)OG_MAX_TRANS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_ini_sysindex_trans(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_SYSINDEX_TRANS || num < OG_INI_TRANS) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INI_SYSINDEX_TRANS", (int64)OG_INI_TRANS, (int64)OG_MAX_SYSINDEX_TRANS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_cr_mode(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    char *match_word[] = { "PAGE", "ROW" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    iret_sprintf = sprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_row_format(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    char *match_word[] = { "ASF", "CSF" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    iret_sprintf = sprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_undo_segments(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_UNDO_SEGMENT || num > OG_MAX_UNDO_SEGMENT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_SEGMENTS");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_active_undo_segments(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > g_instance->kernel.attr.undo_segments || num < OG_MIN_UNDO_SEGMENT || num > OG_MAX_UNDO_SEGMENT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_ACTIVE_SEGMENTS");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_undo_prefetch_pages(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_MIN_UNDO_PREFETCH_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_PREFETCH_PAGE_NUM", (uint32)OG_MIN_UNDO_PREFETCH_PAGES);
        return OG_ERROR;
    }
    if (num > OG_MAX_UNDO_PREFETCH_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_PREFETCH_PAGE_NUM", (uint32)OG_MAX_UNDO_PREFETCH_PAGES);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_auton_trans_segments(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num >= g_instance->kernel.attr.undo_segments || num < OG_MIN_AUTON_TRANS_SEGMENT ||
        num >= OG_MAX_UNDO_SEGMENT) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_AUTON_TRANS_SEGMENTS");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_active_undo_segments(void *se, void *item, char *value)
{
    uint32 active_undo_segments = 0;
    uint32 old_active_segments = g_instance->kernel.attr.undo_active_segments;
    knl_session_t *session = (knl_session_t *)se;

    if (cm_str2uint32(value, &active_undo_segments) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (active_undo_segments > g_instance->kernel.attr.undo_segments) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_UNDO_ACTIVE_SEGMENTS", (int64)g_instance->kernel.attr.undo_segments);
        return OG_ERROR;
    }

    if (active_undo_segments < OG_MIN_UNDO_SEGMENT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_UNDO_ACTIVE_SEGMENTS", (int64)OG_MIN_UNDO_SEGMENT);
        return OG_ERROR;
    }

    g_instance->kernel.attr.undo_active_segments = active_undo_segments;
    if ((active_undo_segments < old_active_segments) && g_instance->kernel.attr.undo_auto_shrink_inactive) {
        session->kernel->smon_ctx.shrink_inactive = OG_TRUE;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_auton_trans_segments(void *se, void *item, char *value)
{
    uint32 auton_trans_segments;

    if (cm_str2uint32(value, &auton_trans_segments) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (auton_trans_segments >= g_instance->kernel.attr.undo_segments) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_UNDO_AUTON_TRANS_SEGMENTS",
            (int64)g_instance->kernel.attr.undo_segments - 1);
        return OG_ERROR;
    }

    if (auton_trans_segments < OG_MIN_AUTON_TRANS_SEGMENT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_UNDO_AUTON_TRANS_SEGMENTS", (int64)OG_MIN_AUTON_TRANS_SEGMENT);
        return OG_ERROR;
    }

    g_instance->kernel.attr.undo_auton_trans_segments = auton_trans_segments;
    return OG_SUCCESS;
}

status_t sql_notify_als_undo_auton_bind_own_seg(void *se, void *item, char *value)
{
    g_instance->kernel.attr.undo_auton_bind_own = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_undo_auto_shrink(void *se, void *item, char *value)
{
    g_instance->kernel.attr.undo_auto_shrink = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_undo_auto_shrink_inactive(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    g_instance->kernel.attr.undo_auto_shrink_inactive = (bool32)value[0];
    if (g_instance->kernel.attr.undo_auto_shrink_inactive) {
        session->kernel->smon_ctx.shrink_inactive = OG_TRUE;
    }

    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_undo_prefetch_pages(void *se, void *item, char *value)
{
    uint32 undo_prefetch_page_num = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &undo_prefetch_page_num));
    g_instance->kernel.attr.undo_prefetch_page_num = (uint32)undo_prefetch_page_num;
    return OG_SUCCESS;
}

status_t sql_verify_als_rollback_proc_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_ROLLBACK_PROC || num > OG_MAX_ROLLBACK_PROC) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_TX_ROLLBACK_PROC_NUM", (int64)OG_MIN_ROLLBACK_PROC,
            (int64)OG_MAX_ROLLBACK_PROC);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_data_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_DATA_BUFFER_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_page_clean_period(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_page_clean_period(void *se, void *item, char *value)
{
    uint32 period = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &period));
    g_instance->kernel.attr.page_clean_period = (uint32)period;
    return OG_SUCCESS;
}

status_t sql_verify_als_page_clean_ratio(void *se, void *lex, void *def)
{
    double num;
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

    if (cm_text2real((text_t *)&word.text, &num)) {
        return OG_ERROR;
    }

    cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);

    if (num > OG_MAX_PAGE_CLEAN_RATIO || num < OG_MIN_PAGE_CLEAN_RATIO) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "BUFFER_PAGE_CLEAN_RATIO");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_page_clean_ratio(void *se, void *item, char *value)
{
    if (cm_str2real(value, &g_instance->kernel.attr.page_clean_ratio) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_lru_search_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_LRU_SEARCH_THRESHOLD || num < OG_MIN_LRU_SEARCH_THRESHOLD) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "BUFFER_LRU_SEARCH_THRE");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_lru_search_threshold(void *se, void *item, char *value)
{
    uint32 ratio = 1;
    OG_RETURN_IFERR(cm_str2uint32(value, &ratio));
    g_instance->kernel.attr.lru_search_threshold = (uint32)ratio;
    return OG_SUCCESS;
}

status_t sql_notify_als_delay_cleanout(void *se, void *item, char *value)
{
    g_instance->kernel.attr.delay_cleanout = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_cr_pool_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_CR_POOL_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_cr_pool_count(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (value > OG_MAX_CR_POOL_COUNT || value < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CR_POOL_COUNT", (int64)1, (int64)OG_MAX_CR_POOL_COUNT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_buf_pool_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_BUF_POOL_NUM || num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUFFER_POOL_NUMBER", (int64)1, (int64)OG_MAX_BUF_POOL_NUM);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_default_extents(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num != 8 && num != 16 && num != 32 && num != 64 && num != 128) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_EXTENTS");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_default_extents(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.default_extents = val;
    return OG_SUCCESS;
}

status_t sql_verify_als_default_space_type(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    char *match_word[] = { "NORMAL", "BITMAP" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    iret_sprintf = sprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_tablespace_alarm_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "TABLESPACE_USAGE_ALARM_THRESHOLD");
        return OG_ERROR;
    }

    if (num > OG_MAX_SPC_ALARM_THRESHOLD) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "TABLESPACE_USAGE_ALARM_THRESHOLD");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_undo_alarm_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "UNDO_USAGE_ALARM_THRESHOLD");
        return OG_ERROR;
    }

    if (num > OG_MAX_UNDO_ALARM_THRESHOLD) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_USAGE_ALARM_THRESHOLD", (int64)OG_MAX_UNDO_ALARM_THRESHOLD);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_txn_undo_alarm_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "TXN_UNDO_USAGE_ALARM_THRESHOLD");
        return OG_ERROR;
    }

    if (num > OG_MAX_TXN_UNDO_ALARM_THRESHOLD) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "TXN_UNDO_USAGE_ALARM_THRESHOLD",
            (int64)OG_MAX_TXN_UNDO_ALARM_THRESHOLD);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_systime_increase_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYSTIME_INCREASE_THREASHOLD");
        return OG_ERROR;
    }

    if (num > OG_MAX_SYSTIME_INC_THRE) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYSTIME_INCREASE_THREASHOLD");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_tablespace_alarm_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.spc_usage_alarm_threshold = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_undo_alarm_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.undo_usage_alarm_threshold = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_txn_undo_alarm_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.txn_undo_usage_alarm_threshold = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_systime_increase_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.systime_inc_threshold = (uint64)DAY2SECONDS(val);
    return OG_SUCCESS;
}

status_t sql_notify_als_vmp_caches(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.vmp_cache_pages);
}

status_t sql_verify_als_vma_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_VMA_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_large_vma_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_LARGE_VMA_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_shared_pool_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_SHARED_POOL_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_sql_pool_fat(void *se, void *lex, void *def)
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

    if (num > OG_MAX_SQL_POOL_FACTOR || num < OG_MIN_SQL_POOL_FACTOR) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SQL_POOL_FACTOR");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_large_pool_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_LARGE_POOL_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_log_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_LOG_BUFFER_SIZE, OG_MAX_LOG_BUFFER_SIZE);
}

status_t sql_verify_als_log_buffer_count(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_LOG_BUFFERS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LOG_BUFFER_COUNT", (int64)OG_MAX_LOG_BUFFERS);
        return OG_ERROR;
    }

    if (num <= 0) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LOG_BUFFER_COUNT", (int64)OG_MIN_LOG_BUFFERS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_temp_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_TEMP_BUFFER_SIZE, OG_MAX_TEMP_BUFFER_SIZE);
}

status_t sql_verify_als_max_temp_tables(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_RESERVED_TEMP_TABLES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "MAX_TEMP_TABLES", (int64)OG_RESERVED_TEMP_TABLES);
        return OG_ERROR;
    }

    if (num > OG_MAX_TEMP_TABLES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_TEMP_TABLES", (int64)OG_MAX_TEMP_TABLES);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_temp_pool_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_TEMP_POOL_NUM || num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "TEMP_POOL_NUM", (int64)1, (int64)OG_MAX_TEMP_POOL_NUM);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_vm_func_stack_count(void *se, void *item, char *value)
{
    uint32 count;
    knl_session_t *knl_sess = se;

    OG_RETURN_IFERR(cm_str2uint32(value, &count));
    if (g_vm_max_stack_count == count) {
        return OG_SUCCESS;
    }

    vm_pool_t *pool = knl_sess->temp_pool;
    cm_spin_lock(&pool->lock, NULL);
    if (pool->func_stacks == NULL) {
        g_vm_max_stack_count = count;
        cm_spin_unlock(&pool->lock);
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < g_vm_max_stack_count; i++) {
        vm_func_stack_t *func_stack = pool->func_stacks[i];
        if (func_stack != NULL) {
            free(func_stack);
            continue;
        }
    }

    free(pool->func_stacks);
    pool->func_stacks = NULL;
    g_vm_max_stack_count = count;
    cm_spin_unlock(&pool->lock);
    return OG_SUCCESS;
}

status_t sql_verify_als_max_link_tables(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_LINK_TABLES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_LINK_TABLES", (int64)OG_MAX_LINK_TABLES);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_index_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_INDEX_CACHE_SIZE, OG_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_checkpoint_interval(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num == 0) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PAGES", (int64)1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_checkpoint_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num == 0) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PERIOD", (int64)1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_checkpoint_io_capacity(void *se, void *lex, void *def)
{
    knl_session_t *session = (knl_session_t *)se;
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num == 0) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_IO_CAPACITY", (int64)1);
        return OG_ERROR;
    }

    if (num > OG_CKPT_GROUP_SIZE(session)) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CHECKPOINT_IO_CAPACITY", (int64)OG_CKPT_GROUP_SIZE(session));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_ckpt_period(void *se, void *item, char *value)
{
    uint32 period = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &period));
    g_instance->kernel.attr.ckpt_timeout = (uint32)period;
    return OG_SUCCESS;
}

status_t sql_notify_als_ckpt_pages(void *se, void *item, char *value)
{
    uint32 page_count = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &page_count));
    g_instance->kernel.attr.ckpt_interval = (uint32)page_count;
    return OG_SUCCESS;
}

status_t sql_notify_als_ckpt_io_capacity(void *se, void *item, char *value)
{
    uint32 io_capacity = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &io_capacity));
    g_instance->kernel.attr.ckpt_io_capacity = (uint32)io_capacity;
    return OG_SUCCESS;
}

status_t sql_notify_als_ckpt_merge_io(void *se, void *item, char *value)
{
    g_instance->kernel.attr.ckpt_flush_neighbors = value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_ini_trans(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.initrans = val;
    return OG_SUCCESS;
}

status_t sql_verify_als_auto_index_recycle(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "ON", "OFF" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return OG_SUCCESS;
}

status_t sql_verify_als_index_recycle_percent(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_INDEX_RECYCLE_PERCENT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_PERCENT", (int64)OG_MAX_INDEX_RECYCLE_PERCENT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_force_index_recycle(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_INDEX_FORCE_RECYCLE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_FORCE_INDEX_RECYCLE", (int64)OG_MAX_INDEX_FORCE_RECYCLE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_index_auto_rebuild_start_time(void *se, void *lex, void *def)
{
    OG_RETURN_IFERR(sql_verify_als_comm(se, lex, def));
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    knl_session_t *session = (knl_session_t *)se;
    OG_RETURN_IFERR(srv_get_index_auto_rebuild(sys_def->value, &session->kernel->attr));
    return OG_SUCCESS;
}

status_t sql_notify_als_index_auto_rebuild(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    struct st_knl_instance *kernel = session->kernel;
    knl_session_t *rebuild_session = kernel->sessions[SESSION_ID_IDX_REBUILD];

    OG_LOG_RUN_INF("index auto rebuild swicth from state %u to %u", kernel->attr.idx_auto_rebuild, (bool32)value[0]);

    if (kernel->attr.idx_auto_rebuild && !(bool32)value[0]) {
        rebuild_session->canceled = OG_TRUE;
    }
    session->kernel->attr.idx_auto_rebuild = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_index_recycle_reuse(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_INDEX_RECYCLE_REUSE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_REUSE", (int64)OG_MAX_INDEX_RECYCLE_REUSE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_index_rebuild_keep_storage(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_INDEX_REBUILD_STORAGE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_REBUILD_KEEP_STORAGE", (int64)OG_MAX_INDEX_REBUILD_STORAGE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_index_recycle_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_INDEX_RECYCLE_SIZE, OG_MAX_INDEX_RECYCLE_SIZE);
}

status_t sql_notify_als_auto_index_recycle(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_attr_t *attr = &session->kernel->attr;
    if (cm_str_equal_ins(value, "ON")) {
        attr->idx_auto_recycle = OG_TRUE;
    } else if (cm_str_equal_ins(value, "OFF")) {
        attr->idx_auto_recycle = OG_FALSE;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_AUTO_INDEX_RECYCLE");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_index_recycle_percent(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.idx_recycle_percent = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_index_recycle_size(void *se, void *item, char *value)
{
    int64 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2size(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.idx_recycle_size = (uint64)val;
    return OG_SUCCESS;
}

status_t sql_notify_als_index_recycle_reuse(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.idx_recycle_reuse_time = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_force_index_recycle(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.idx_force_recycle_time = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_index_rebuild_keep_storage(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.idx_rebuild_keep_storage_time = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_backup_log_parallel(void *se, void *item, char *value)
{
    g_instance->kernel.attr.backup_log_prealloc = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_lsnd_wait_time(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    session->kernel->attr.lsnd_wait_time = val;
    return OG_SUCCESS;
}

status_t sql_verify_als_private_key_locks(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_PRIVATE_LOCKS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_KEY_LOCKS", (int64)OG_MIN_PRIVATE_LOCKS);
        return OG_ERROR;
    }

    if (num > OG_MAX_PRIVATE_LOCKS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_KEY_LOCKS", (int64)OG_MAX_PRIVATE_LOCKS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_private_key_locks(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.private_key_locks = (uint8)num;
    return OG_SUCCESS;
}

status_t sql_verify_als_private_row_locks(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_PRIVATE_LOCKS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_ROW_LOCKS", (int64)OG_MIN_PRIVATE_LOCKS);
        return OG_ERROR;
    }

    if (num > OG_MAX_PRIVATE_LOCKS) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_ROW_LOCKS", (int64)OG_MAX_PRIVATE_LOCKS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_private_row_locks(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.private_row_locks = (uint8)num;
    return OG_SUCCESS;
}

status_t sql_verify_als_commit_logging(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "IMMEDIATE", "BATCH" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return OG_SUCCESS;
}

status_t sql_notify_als_commit_mode(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;

    if (cm_str_equal_ins(value, "BATCH")) {
        g_instance->kernel.attr.commit_batch = OG_TRUE;
        session->commit_batch = OG_TRUE;
    } else if (cm_str_equal_ins(value, "IMMEDIATE")) {
        g_instance->kernel.attr.commit_batch = OG_FALSE;
        session->commit_batch = OG_FALSE;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "COMMIT_MODE", value);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_commit_wait(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "WAIT", "NOWAIT" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return OG_SUCCESS;
}

status_t sql_notify_als_commit_wait_logging(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;

    if (cm_str_equal_ins(value, "NOWAIT")) {
        g_instance->kernel.attr.commit_nowait = OG_TRUE;
        session->commit_nowait = OG_TRUE;
    } else if (cm_str_equal_ins(value, "WAIT")) {
        g_instance->kernel.attr.commit_nowait = OG_FALSE;
        session->commit_nowait = OG_FALSE;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "COMMIT_WAIT_LOGGING", value);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_dbwr_processes(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!(num > 0 && num <= OG_MAX_DBWR_PROCESS)) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DBWR_PROCESSES", (int64)1, (int64)OG_MAX_DBWR_PROCESS);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_rcy_params(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num > OG_MAX_PARAL_RCY || num < OG_DEFAULT_PARAL_RCY) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_REPLAY_PROCESSES", (int64)OG_DEFAULT_PARAL_RCY,
            (int64)OG_MAX_PARAL_RCY);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_rcy_preload_process(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num > OG_MAX_PARAL_RCY) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "REPLAY_PRELOAD_PROCESSES", 0, (int64)OG_MAX_PARAL_RCY);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_rcy_sleep_interval(void *se, void *lex, void *def)
{
    uint32 interval;
    if (sql_verify_uint32(lex, def, &interval) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (interval < OG_MIN_RCY_SLEEP_INTERVAL || interval > OG_MAX_RCY_SLEEP_INTERVAL) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_RCY_SLEEP_INTERVAL", (int64)OG_MIN_RCY_SLEEP_INTERVAL,
            (int64)OG_MAX_RCY_SLEEP_INTERVAL);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_rcy_sleep_interval(void *se, void *item, char *value)
{
    uint32 interval;
    OG_RETURN_IFERR(cm_str2uint32(value, &interval));
    g_instance->kernel.attr.rcy_sleep_interval = interval;
    return OG_SUCCESS;
}

status_t sql_verify_als_cpu_node_bind(void *se, void *lex, void *def)
{
    bool32 is_string = OG_FALSE;
    word_t word;
    uint32 lo_num;
    uint32 hi_num;
    uint32 nprocs;
    lex_t *lexer = (lex_t *)lex;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    OG_RETURN_IFERR(lex_expected_fetch(lexer, &word));
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
        OG_RETURN_IFERR(lex_push(lexer, &word.text));
        is_string = OG_TRUE;
        OG_RETURN_IFERR(lex_expected_fetch(lexer, &word));
    }

    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2uint32(&word.text.value, &lo_num));
    OG_RETURN_IFERR(lex_expected_fetch(lexer, &word));
    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_text2uint32(&word.text.value, &hi_num));
    if (is_string) {
        lex_pop(lexer);
    }

    nprocs = cm_sys_get_nprocs() - 1;
    if (hi_num > nprocs || hi_num < lo_num) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CPU_NODE_BIND", (int64)0, (int64)nprocs);
        return OG_ERROR;
    }

    *(uint32 *)sys_def->value = lo_num;
    *(uint32 *)(sys_def->value + sizeof(uint32)) = hi_num;
    return OG_SUCCESS;
}

status_t sql_notify_als_cpu_node_bind(void *se, void *item, char *value)
{
    uint32 cpu_lo;
    uint32 cpu_hi;
    cpu_lo = *(uint32 *)value;
    cpu_hi = *(uint32 *)(value + sizeof(uint32));
    g_instance->kernel.attr.cpu_bind_lo = cpu_lo;
    g_instance->kernel.attr.cpu_bind_hi = cpu_hi;
    g_instance->kernel.attr.cpu_count = cpu_hi - cpu_lo + 1;
    PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%u %u", cpu_lo, cpu_hi));
    return rsrc_calc_cpuset(cpu_lo, cpu_hi, GET_RSRC_MGR->plan);
}

status_t sql_verify_als_qos_ctrl_fat(void *se, void *lex, void *def)
{
    double num;
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

    if (cm_text2real((text_t *)&word.text, &num)) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE));
    if (num > OG_MAX_QOS_CTRL_FACTOR || num <= OG_MIN_QOS_CTRL_FACTOR) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_CTRL_FACTOR");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_qos_slee_time(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_SLEEP_TIME");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_qos_rand_range(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num == 0) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_RANDOM_RANGE");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_enable_qos(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.enable_qos = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_qos_ctrl(void *se, void *item, char *value)
{
    if (cm_str2real(value, &g_instance->kernel.attr.qos_factor) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.qos_threshold =
        (uint32)(int32)(g_instance->kernel.attr.cpu_count * g_instance->kernel.attr.qos_factor);
    return OG_SUCCESS;
}

status_t sql_notify_als_qos_sleep_time(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.qos_sleep_time);
}

status_t sql_notify_als_qos_random_range(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.qos_random_range);
}

status_t sql_notify_als_disable_soft_parse(void *se, void *item, char *value)
{
    // _DISABLE_SOFT_PARSE only effect in config file.
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.disable_soft_parse = (bool32)value[0];
#endif
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_db_block_checksum(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of3((lex_t *)lex, "OFF", "TYPICAL", "FULL", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (match_id == 0) {
        PRTS_RETURN_IFERR(snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "OFF"));
    } else if (match_id == 1) {
        PRTS_RETURN_IFERR(snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "TYPICAL"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "FULL"));
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_db_isolevel(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2((lex_t *)lex, "RC", "CC", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (match_id == 0) {
        sys_def->value[0] = (char)ISOLATION_READ_COMMITTED;
    } else {
        sys_def->value[0] = (char)ISOLATION_CURR_COMMITTED;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_db_isolevel_value(void *se, void *item, char *value)
{
    int iret_snprintf;
    if ((uint8)value[0] == (uint8)ISOLATION_READ_COMMITTED) {
        iret_snprintf = snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "RC");
        if (SECUREC_UNLIKELY(iret_snprintf == -1)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return OG_ERROR;
        }
    } else {
        iret_snprintf = snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "CC");
    }

    if (iret_snprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_db_isolevel(void *se, void *item, char *value)
{
    g_instance->kernel.attr.db_isolevel = (uint8)value[0];
    return sql_notify_als_db_isolevel_value(se, item, value);
}

status_t sql_verify_als_thread_stack_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_THREAD_STACK_SIZE, OG_MAX_THREAD_STACK_SIZE - OG_STACK_DEPTH_SLOP);
}

status_t sql_verify_als_undo_reserve_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_UNDO_MIN_RESERVE_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RESERVE_SIZE", (int64)OG_UNDO_MIN_RESERVE_SIZE);
        return OG_ERROR;
    } else if (num > OG_UNDO_MAX_RESERVE_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_RESERVE_SIZE", (int64)OG_UNDO_MAX_RESERVE_SIZE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_undo_retention_time(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RETENTION_TIME", (int64)1);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_undo_reserve_size(void *se, void *item, char *value)
{
    uint32 reserve_size;
    if (cm_str2uint32(value, &reserve_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (reserve_size < OG_UNDO_MIN_RESERVE_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RESERVE_SIZE", (int64)OG_UNDO_MIN_RESERVE_SIZE);
        return OG_ERROR;
    } else if (reserve_size > OG_UNDO_MAX_RESERVE_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_RESERVE_SIZE", (int64)OG_UNDO_MAX_RESERVE_SIZE);
        return OG_ERROR;
    }

    g_instance->kernel.attr.undo_reserve_size = reserve_size;
    return OG_SUCCESS;
}

status_t sql_notify_als_undo_retention_time(void *se, void *item, char *value)
{
    uint32 retention_time;
    if (cm_str2uint32(value, &retention_time) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (retention_time < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RETENTION_TIME", (int64)1);
        return OG_ERROR;
    }

    g_instance->kernel.attr.undo_retention_time = retention_time;
    g_instance->kernel.undo_ctx.retention = retention_time;
    return OG_SUCCESS;
}

status_t sql_notify_als_index_defer_recycle_time(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.index_defer_recycle_time = val;

    return OG_SUCCESS;
}

status_t sql_verify_als_xa_suspend_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "XA_SUSPEND_TIMEOUT", (int64)1);
        return OG_ERROR;
    }

    if (num > OG_MAX_SUSPEND_TIMEOUT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "XA_SUSPEND_TIMEOUT", (int64)OG_MAX_SUSPEND_TIMEOUT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_xa_suspend_timeout(void *se, void *item, char *value)
{
    uint32 timeout;
    if (cm_str2uint32(value, &timeout) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (timeout < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "XA_SUSPEND_TIMEOUT", (int64)1);
        return OG_ERROR;
    }

    if (timeout > OG_MAX_SUSPEND_TIMEOUT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "XA_SUSPEND_TIMEOUT", (int64)OG_MAX_SUSPEND_TIMEOUT);
        return OG_ERROR;
    }

    g_instance->kernel.attr.xa_suspend_timeout = timeout;
    return OG_SUCCESS;
}

status_t sql_notify_als_lock_wait_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.lock_wait_timeout = val;
    return OG_SUCCESS;
}

status_t sql_notify_als_double_write(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    ckpt_context_t *ogx = &session->kernel->ckpt_ctx;
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    ogx->double_write = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_build_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (val < OG_BUILD_MIN_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BUILD_KEEP_ALIVE_TIMEOUT", (int64)OG_BUILD_MIN_WAIT_TIME);
        return OG_ERROR;
    }

    g_instance->kernel.attr.build_keep_alive_timeout = val;
    return OG_SUCCESS;
}

status_t sql_verify_als_repl_wait_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_REPL_MIN_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "REPL_WAIT_TIMEOUT", (int64)OG_REPL_MIN_WAIT_TIME);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_repl_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.repl_wait_timeout = val;
    knl_set_repl_timeout(se, val);
    return OG_SUCCESS;
}

status_t sql_verify_als_repl_max_pkg_size(void *se, void *lex, void *def)
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
    if (lex_expected_fetch_size(lex, &size, OG_INVALID_INT64, OG_INVALID_INT64) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    if (size > 0) {
        if (size < OG_MIN_REPL_PKG_SIZE) {
            OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_REPL_MAX_PKG_SIZE", OG_MIN_REPL_PKG_SIZE);
            return OG_ERROR;
        }

        if (size > OG_MAX_REPL_PKG_SIZE) {
            OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_REPL_MAX_PKG_SIZE", OG_MAX_REPL_PKG_SIZE);
            return OG_ERROR;
        }
    }

    cm_text2str((text_t *)&word.text, sys_def->value, OG_PARAM_BUFFER_SIZE);
    return OG_SUCCESS;
}

status_t sql_notify_als_repl_max_pkg_size(void *se, void *item, char *value)
{
    int64 size = 0;
    OG_RETURN_IFERR(cm_str2size(value, &size));
    (void)cm_atomic_set(&g_instance->kernel.attr.repl_pkg_size, size);
    return OG_SUCCESS;
}

status_t sql_notify_als_repl_host(void *se, void *item, char *value)
{
    errno_t errcode;
    errcode = strncpy_s(g_instance->kernel.attr.repl_trust_host, OG_HOST_NAME_BUFFER_SIZE * OG_MAX_LSNR_HOST_COUNT,
        value, strlen(value));
    if (errcode != EOK) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_filesystemio_options(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "NONE", "DIRECTIO", "FULLDIRECTIO", "ASYNCH", "DSYNC", "FDATASYNC", "SETALL" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1ofn(lex, &match_id, 7, match_word[0], match_word[1], match_word[2], match_word[3],
        match_word[4], match_word[5], match_word[6]) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));

    return OG_SUCCESS;
}

status_t sql_notify_als_rcy_check_pcn(void *se, void *item, char *value)
{
    g_instance->kernel.attr.rcy_check_pcn = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_local_tmp_tbl_enabled(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_ltt = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_upper_case_table_names(void *se, void *item, char *value)
{
    // enable online modify for debug version only
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_instance->kernel.attr.enable_upper_case_names = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
#else
    OG_THROW_ERROR(ERR_NOT_COMPATIBLE, "UPPER_CASE_TABLE_NAMES");
    return OG_ERROR;
#endif
}

status_t sql_notify_als_cbo(void *se, void *item, char *value)
{
    if ((bool32)value[0] != OG_TRUE) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "RBO");
        return OG_ERROR;
    }
    return sql_notify_als_onoff(se, item, value);
}

status_t sql_notify_als_resource_limit(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    session->kernel->attr.enable_resource_limit = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_drop_nologging(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.drop_nologging = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_recyclebin(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.recyclebin = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_auto_inherit(void *se, void *item, char *value)
{
    if (g_instance->kernel.attr.enable_auto_inherit != (bool32)value[0]) {
        g_instance->kernel.attr.enable_auto_inherit = (bool32)value[0];
    }

    return sql_notify_als_onoff(se, item, value);
}

status_t sql_notify_password_verify(void *se, void *item, char *value)
{
    g_instance->kernel.attr.password_verify = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_idx_duplicate_enable(void *se, void *lex, void *def)
{
    OG_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_CAPABILITY_NOT_SUPPORT, "index and contraint duplicate name");
    return OG_ERROR;
}

status_t sql_notify_als_idx_duplicate(void *se, void *item, char *value)
{
    OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "index and contraint duplicate name");
    return OG_ERROR;
}

status_t sql_notify_idx_key_len_check(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    session->kernel->attr.enable_idx_key_len_check = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_tc_level(void *se, void *item, char *value)
{
    uint32 val;
    OG_RETURN_IFERR(cm_str2uint32(value, &val));
    g_instance->kernel.attr.tc_level = val;
    return OG_SUCCESS;
}

status_t sql_verify_als_ddl_lock_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_DDL_LOCK_TIMEOUT || num > OG_MAX_DDL_LOCK_TIMEOUT) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DDL_LOCK_TIMEOUT", (int64)OG_MIN_DDL_LOCK_TIMEOUT,
            (int64)OG_MAX_DDL_LOCK_TIMEOUT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_ddl_lock_timeout(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.ddl_lock_timeout = (num == 0) ? LOCK_INF_WAIT : num;
    return OG_SUCCESS;
}

status_t sql_verify_als_max_rm_count(void *se, void *lex, void *def)
{
    uint32 max_sessions = g_instance->session_pool.expanded_max_sessions;
    uint32 num = 0;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_MAX_RM_COUNT");
        return OG_ERROR;
    }

    if (num != 0) {
        if (CM_CALC_ALIGN(num, OG_EXTEND_RMS) < max_sessions) {
            OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_MAX_RM_COUNT", (int64)max_sessions);
            return OG_ERROR;
        }

        if (CM_CALC_ALIGN(num, OG_EXTEND_RMS) > CM_CALC_ALIGN_FLOOR(OG_MAX_RM_COUNT, OG_EXTEND_RMS)) {
            OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_RM_COUNT",
                (int64)CM_CALC_ALIGN_FLOOR(OG_MAX_RM_COUNT, OG_EXTEND_RMS));
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_ashrink_wait_time(void *se, void *lex, void *def)
{
    uint32 num = 0;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_ASHRINK_WAIT_TIME");
        return OG_ERROR;
    }

    if (num < OG_MIN_ASHRINK_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_ASHRINK_WAIT_TIME", (int64)OG_MIN_ASHRINK_WAIT_TIME);
        return OG_ERROR;
    }

    if (num > OG_MAX_ASHRINK_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_ASHRINK_WAIT_TIME", (int64)OG_MAX_ASHRINK_WAIT_TIME);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_ashrink_wait_time(void *se, void *item, char *value)
{
    uint32 num = 0;
    if (cm_str2uint32(value, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_ASHRINK_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_ASHRINK_WAIT_TIME", (int64)OG_MIN_ASHRINK_WAIT_TIME);
        return OG_ERROR;
    }

    if (num > OG_MAX_ASHRINK_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_ASHRINK_WAIT_TIME", (int64)OG_MAX_ASHRINK_WAIT_TIME);
        return OG_ERROR;
    }

    g_instance->kernel.attr.ashrink_wait_time = num;
    return OG_SUCCESS;
}

status_t sql_verify_als_shrink_wait_recycled_pages(void *se, void *lex, void *def)
{
    uint32 num = 0;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "_SHRINK_WAIT_RECYCLED_PAGES");
        return OG_ERROR;
    }

    if (num < OG_MIN_SHRINK_WAIT_RECYCLED_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)OG_MIN_SHRINK_WAIT_RECYCLED_PAGES);
        return OG_ERROR;
    }

    if (num > OG_MAX_SHRINK_WAIT_RECYCLED_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)OG_MAX_SHRINK_WAIT_RECYCLED_PAGES);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_shrink_wait_recycled_pages(void *se, void *item, char *value)
{
    uint32 num = 0;
    if (cm_str2uint32(value, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_MIN_SHRINK_WAIT_RECYCLED_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)OG_MIN_SHRINK_WAIT_RECYCLED_PAGES);
        return OG_ERROR;
    }

    if (num > OG_MAX_SHRINK_WAIT_RECYCLED_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)OG_MAX_SHRINK_WAIT_RECYCLED_PAGES);
        return OG_ERROR;
    }

    g_instance->kernel.attr.shrink_wait_recycled_pages = num;
    return OG_SUCCESS;
}

status_t sql_notify_als_temptable_support_batch(void *se, void *item, char *value)
{
    g_instance->kernel.attr.temptable_support_batch = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_small_table_sampling_threshold(void *se, void *lex, void *def)
{
    uint32 num = 0;
    return sql_verify_uint32(lex, def, &num);
}

status_t sql_notify_als_small_table_sampling_threshold(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.small_table_sampling_threshold);
}

status_t sql_notify_als_block_repair_enable(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_abr = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_block_repair_timeout(void *se, void *item, char *value)
{
    uint32 abr_timeout;
    if (cm_str2uint32(value, &abr_timeout) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (abr_timeout < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BLOCK_REPAIR_TIMEOUT", (int64)1);
        return OG_ERROR;
    }

    if (abr_timeout > ABR_MAX_TIMEOUT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "BLOCK_REPAIR_TIMEOUT", (int64)ABR_MAX_TIMEOUT);
        return OG_ERROR;
    }

    g_instance->kernel.attr.abr_timeout = abr_timeout;
    return OG_SUCCESS;
}

status_t sql_verify_als_block_repair_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < 1) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BLOCK_REPAIR_TIMEOUT", (int64)1);
        return OG_ERROR;
    }

    if (num > ABR_MAX_TIMEOUT) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "BLOCK_REPAIR_TIMEOUT", (int64)ABR_MAX_TIMEOUT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_nbu_backup_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (num < OG_NBU_BACKUP_MIN_WAIT_TIME) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "NBU_BACKUP_TIMEOUT", (int64)OG_NBU_BACKUP_MIN_WAIT_TIME);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_notify_als_nbu_backup_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != OG_SUCCESS) {
        return OG_ERROR;
    }
    g_instance->kernel.attr.nbu_backup_timeout = val;
    return OG_SUCCESS;
}

status_t sql_notify_degrade_search(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.enable_degrade_search = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_lob_reuse_threshold(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, OG_MIN_LOB_REUSE_SIZE, OG_INVALID_ID32);
}

status_t sql_notify_als_lob_reuse_threshold(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.lob_reuse_threshold = (uint64)val_int64;
    return OG_SUCCESS;
}

status_t sql_notify_build_datafile_paral(void *se, void *item, char *value)
{
    g_instance->kernel.attr.build_datafile_parallel = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_init_lockpool_pages(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (value < OG_MIN_LOCK_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "INIT_LOCK_POOL_PAGES", (int64)OG_MIN_LOCK_PAGES);
        return OG_ERROR;
    }
    if (value > OG_MAX_LOCK_PAGES) {
        OG_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "INIT_LOCK_POOL_PAGES", (int64)OG_MAX_LOCK_PAGES);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_init_lockpool_pages(void *se, void *item, char *value)
{
    uint32 init_lockpool_pages;
    if (cm_str2uint32(value, &init_lockpool_pages) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.init_lockpool_pages = init_lockpool_pages;
    return OG_SUCCESS;
}

status_t sql_notify_build_datafile_prealloc(void *se, void *item, char *value)
{
    g_instance->kernel.attr.build_datafile_prealloc = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_ctrllog_backup_level(void *se, void *lex, void *def)
{
    uint32 match_id;
    const char *match_word[] = { "NONE", "TYPICAL", "FULL" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(sys_def->value, OG_PARAM_BUFFER_SIZE, match_word[match_id]));
    return OG_SUCCESS;
}

status_t sql_notify_ctrllog_backup_level(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "NONE")) {
        g_instance->kernel.attr.ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_NONE;
    } else if (cm_str_equal_ins(value, "TYPICAL")) {
        g_instance->kernel.attr.ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_TYPICAL;
    } else if (cm_str_equal_ins(value, "FULL")) {
        g_instance->kernel.attr.ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_FULL;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "CTRLLOG_BACKUP_LEVEL", value);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_compress_algo(void *se, void *lex, void *def)
{
    uint32 match_id;
    const char *match_word[] = { "NONE", "ZSTD" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(sys_def->value, OG_PARAM_BUFFER_SIZE, match_word[match_id]));
    return OG_SUCCESS;
}

status_t sql_notify_als_compress_algo(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "NONE")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_NONE;
    } else if (cm_str_equal_ins(value, "ZSTD")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_ZSTD;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "_TABLE_COMPRESS_ALGO", value);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_als_compress_buf_size(void *se, void *lex, void *def)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    if (sql_verify_pool_size(lex, def, (int64)OG_MIN_TAB_COMPRESS_BUF_SIZE,
        MIN(attr->temp_buf_size, (int64)OG_MAX_TAB_COMPRESS_BUF_SIZE)) != OG_SUCCESS) {
        OG_THROW_ERROR((int64)ERR_PARAMETER_OVER_RANGE, "_TABLE_COMPRESS_BUFFER_SIZE ",
            (int64)OG_MIN_TAB_COMPRESS_BUF_SIZE, MIN(attr->temp_buf_size, (int64)OG_MAX_TAB_COMPRESS_BUF_SIZE));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_compress_buf_size(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != OG_SUCCESS) {
        return OG_ERROR;
    }

    g_instance->kernel.attr.tab_compress_buf_size = (uint64)val_int64;
    return OG_SUCCESS;
}

status_t sql_notify_als_compress_enable_buf(void *se, void *item, char *value)
{
    g_instance->kernel.attr.tab_compress_enable_buf = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_page_clean_wait_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_als_page_clean_wait_timeout(void *se, void *item, char *value)
{
    uint32 timeout = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &timeout));
    g_instance->kernel.attr.page_clean_wait_timeout = (uint32)timeout;
    return OG_SUCCESS;
}

status_t sql_notify_als_ckpt_wait_timeout(void *se, void *item, char *value)
{
    uint32 timeout = 0;
    OG_RETURN_IFERR(cm_str2uint32(value, &timeout));
    g_instance->kernel.attr.ckpt_timed_task_delay = (uint32)timeout;
    return OG_SUCCESS;
}

status_t sql_notify_event_tracking_stats(bool32 *param, char *value)
{
    status_t ret = OG_SUCCESS;
    if (!(bool32)value[0]) {
        PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "OFF"));
        *param = false;
        return OG_SUCCESS;
    }
    
    PRTS_RETURN_IFERR(snprintf_s(value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "ON"));
    if ((bool32)value[0] && !(*param)) {
        ret = record_io_stat_reset();
        if (ret != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_GENERIC_INTERNAL_ERROR, ": failed to initialize statistics.");
            return OG_ERROR;
        }
        ret = get_clock_frequency();
        if (ret != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_GENERIC_INTERNAL_ERROR, ": failed to get cpu frequency.");
            return OG_ERROR;
        }
        *param = true;
    }
    
    OG_LOG_RUN_WAR("[IO RECORD] Performance Statistic recording is OPEN. It will SEVERELY degrade performance.");
    return OG_SUCCESS;
}

status_t sql_notify_ograc_stats(void *se, void *item, char *value)
{
    return sql_notify_event_tracking_stats(&g_cm_ograc_event_tracking_open, value);
}

status_t sql_verify_als_page_clean_mode(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "SINGLE", "ALL" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, OG_PARAM_BUFFER_SIZE, OG_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return OG_SUCCESS;
}

status_t sql_notify_als_page_clean_mode(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "SINGLE")) {
        g_instance->kernel.attr.page_clean_mode = PAGE_CLEAN_MODE_SINGLESET;
    } else if (cm_str_equal_ins(value, "ALL")) {
        g_instance->kernel.attr.page_clean_mode = PAGE_CLEAN_MODE_ALLSET;
    } else {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "PAGE_CLEAN_MODE", value);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_verify_als_batch_flush_capacity(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_MIN_BATCH_FLUSH_CAPACITY || num > OG_MAX_BATCH_FLUSH_CAPACITY) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_notify_enable_broadcast_on_commit(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_boc = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_enable_enable_check_security_log(void *se, void *item, char *value)
{
    g_filter_enable = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_enable_crc_check(void *se, void *item, char *value)
{
    g_crc_verify = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}


status_t sql_verify_als_ckpt_group_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (num < OG_MIN_CKPT_GROUP_SIZE || num > OG_MAX_CKPT_GROUP_SIZE) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
#ifdef __cplusplus
}
#endif
