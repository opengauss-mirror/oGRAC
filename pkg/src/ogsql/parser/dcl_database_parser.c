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
 * dcl_database_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/dcl_database_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "srv_instance.h"
#include "ddl_parser.h"
#include "dml_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_set_backup_type(knl_backup_t *param, backup_type_t type)
{
    if (param->type != BACKUP_MODE_INVALID) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not contain backup type more than once");
        return OG_ERROR;
    }

    param->type = type;
    return OG_SUCCESS;
}

static status_t sql_parse_backup_format(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    status_t status;
    text_t sub_param;

    status = lex_expected_fetch_string(stmt->session->lex, word);
    OG_RETURN_IFERR(status);
    if (param->format.len > 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "can not set format more than once");
        return OG_ERROR;
    }

    if (!cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, can not find policy name");
        return OG_ERROR;
    }

    if (word->text.value.len > 0) {
        if (!cm_compare_text_str(&sub_param, "nbu")) {
            param->device = DEVICE_UDS;
            if (!cm_fetch_text(&word->text.value, ':', '\0', &param->policy)) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, can not find policy name");
                return OG_ERROR;
            }

            if (param->policy.len >= OG_BACKUP_PARAM_SIZE) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "policy name exceeded the maximum length %u", OG_BACKUP_PARAM_SIZE);
                return OG_ERROR;
            }
        } else if (cm_compare_text_str(&sub_param, "disk")) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid device type:%s", T2S(&sub_param));
            return OG_ERROR;
        }

        if (!cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, no dest path specified");
            return OG_ERROR;
        }
    }

    status = sql_copy_file_name(stmt->context, &sub_param, &param->format);
    OG_RETURN_IFERR(status);

    if (cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, %s value is invalid",
            T2S(&sub_param));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_backup_incremental(lex_t *lex, word_t *word, knl_backup_t *param)
{
    int32 level;

    if (sql_set_backup_type(param, BACKUP_MODE_INCREMENTAL) != OG_SUCCESS) {
        cm_try_set_error_loc(LEX_LOC);
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "level") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &level) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (level != 0 && level != 1) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "level must be 0 or 1");
        return OG_ERROR;
    }

    param->level = level;
    return OG_SUCCESS;
}

static status_t sql_set_backup_prepare(knl_backup_t *param)
{
    if (param->finish_scn != OG_INVALID_ID64) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set prepare and finish at the same time");
        return OG_ERROR;
    }

    param->prepare = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_set_backup_finish(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    if (param->prepare) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set prepare and finish at the same time");
        return OG_ERROR;
    }

    if (param->finish_scn != OG_INVALID_ID64) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set finish more than once");
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "scn") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_uint64(stmt->session->lex, &param->finish_scn) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_backup_tag(sql_stmt_t *stmt, word_t *word, char *tag)
{
    if (strlen(tag) > 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set tag more than once");
        return OG_ERROR;
    }

    if (lex_expected_fetch_string(stmt->session->lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->text.len > OG_MAX_NAME_LEN) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tag name exceed max name lengths %u", OG_MAX_NAME_LEN);
        return OG_ERROR;
    }

    if (word->text.len == 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tag name can not set empty string");
        return OG_ERROR;
    }

    return cm_text2str(&word->text.value, tag, OG_NAME_BUFFER_SIZE);
}

static status_t sql_set_backup_cumulative(knl_backup_t *param)
{
    if (param->cumulative) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set cumulative more than once");
        return OG_ERROR;
    }

    param->cumulative = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_set_backup_as(sql_stmt_t *stmt, knl_backup_t *param)
{
    bool32 fetch_result = OG_FALSE;
    uint32 level;
    uint32 matched_id = OG_INVALID_ID32;
    compress_algo_e algo = COMPRESS_ZSTD;

    if (lex_try_fetch_1of3(stmt->session->lex, "zlib", "zstd", "lz4", &matched_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch (matched_id) {
        case 0:
            // warning "zlib compression algorithm is no longer supported"
            algo = COMPRESS_ZLIB;
            break;
        case 1:
            algo = COMPRESS_ZSTD;
            break;
        case 2:
            algo = COMPRESS_LZ4;
            break;
        default:
            break;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "compressed") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "backupset") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (param->compress_algo != COMPRESS_NONE) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set compressed more than once");
        return OG_ERROR;
    }
    param->compress_algo = algo;

    if (lex_try_fetch(stmt->session->lex, "level", &fetch_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!fetch_result) {
        param->compress_level = Z_BEST_SPEED; // level 1 with best speed
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, &level) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (level < Z_BEST_SPEED || level > Z_BEST_COMPRESSION) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "level value should be in [1, 9]");
        return OG_ERROR;
    }
    param->compress_level = level;
    return OG_SUCCESS;
}


static status_t sql_verify_backup_passwd(char *password)
{
    const char *pText;
    size_t len;
    bool32 num_flag = OG_FALSE;
    bool32 upper_flag = OG_FALSE;
    bool32 lower_flag = OG_FALSE;
    bool32 special_flag = OG_FALSE;
    uint32 type_count = 0;

    pText = password;
    len = strlen(pText);
    /* enforce minimum length */
    if (len < OG_PASSWD_MIN_LEN) {
        OG_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can't be less than min length characters");
        return OG_ERROR;
    }
    /* check maximum length */
    if (len > OG_PASSWD_MAX_LEN) {
        OG_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can't be greater than max length characters");
        return OG_ERROR;
    }

    /* The pwd should contain at least two type the following characters:
    A. at least one lowercase letter
    B. at least one uppercase letter
    C. at least one digit
    D. at least one special character: `~!@#$%^&*()-_=+\|[{}];:'",<.>/? and space
    If pwd contains the other character ,will return error. */
    for (uint32 i = 0; i < len; i++) {
        if (cm_verify_password_check(pText, i, &type_count, &num_flag, &upper_flag, &lower_flag, &special_flag) !=
            OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (type_count < CM_PASSWD_MIN_TYPE) {
        OG_THROW_ERROR(ERR_PASSWORD_IS_TOO_SIMPLE);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_set_backup_password(sql_stmt_t *stmt, char *password, bool32 is_backup)
{
    word_t word;
    status_t status;

    status = lex_expected_fetch(stmt->session->lex, &word);
    OG_RETURN_IFERR(status);

    if (word.type != WORD_TYPE_VARIANT && word.type != WORD_TYPE_STRING && word.type != WORD_TYPE_DQ_STRING) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The password must be identifier or string");
        return OG_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }
    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid identifier, length 0");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_text2str((text_t *)&word.text, password, OG_PASSWORD_BUFFER_SIZE));
    if (OG_SUCCESS != sql_replace_password(stmt, &word.text.value)) {
        return OG_ERROR;
    }

    if (!is_backup) {
        // do not check restore's pwd
        return OG_SUCCESS;
    }

    return sql_verify_backup_passwd(password);
}

static status_t sql_set_backup_encrypt(sql_stmt_t *stmt, knl_backup_cryptinfo_t *crypt_info, bool32 is_backup)
{
    status_t status;

    SQL_SET_IGNORE_PWD(stmt->session);

    if (crypt_info->encrypt_alg != ENCRYPT_NONE) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set encrypted more than once");
        return OG_ERROR;
    }
    status = sql_set_backup_password(stmt, crypt_info->password, is_backup);
    crypt_info->encrypt_alg = AES_256_GCM;

    return status;
}

static status_t sql_set_backup_section(sql_stmt_t *stmt, knl_backup_t *param)
{
    int64 sec_thresh;

    if (param->section_threshold > 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set section threshold more than once");
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(stmt->session->lex, "threshold") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_size(stmt->session->lex, &sec_thresh, BAK_MIN_SECTION_THRESHOLD,
        BAK_MAX_SECTION_THRESHOLD) != OG_SUCCESS) {
        return OG_ERROR;
    }

    param->section_threshold = sec_thresh;
    return OG_SUCCESS;
}

static status_t sql_set_backup_parallelism(sql_stmt_t *stmt, uint32 *paral_num)
{
    if (paral_num == NULL) {
        return OG_ERROR;
    }

    if (*paral_num > 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set parallelism more than once");
        return OG_ERROR;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, paral_num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (*paral_num < 1 || *paral_num > (OG_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "parallelism value should be in [%u, %u]", (uint32)1,
            (uint32)(OG_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_check_backup_param(sql_stmt_t *stmt, knl_backup_t *param)
{
    bool32 result;
    uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;

    result = (param->prepare || param->finish_scn != OG_INVALID_ID64 || param->device == DEVICE_UDS);
    if (result) {
        if (strlen(param->tag) == 0) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tag is not specified in bakcup command");
            return OG_ERROR;
        }
    }

    if (param->finish_scn != OG_INVALID_ID64) {
        if (param->type != BACKUP_MODE_INVALID) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify backup type when specified finish");
            return OG_ERROR;
        }

        if (param->format.len != 0) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify format when specified finish");
            return OG_ERROR;
        }

        if (param->crypt_info.encrypt_alg != ENCRYPT_NONE) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify password when specified finish");
            return OG_ERROR;
        }

        if (param->buffer_size != 0) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify buffer size when specified finish");
            return OG_ERROR;
        }

        param->type = BACKUP_MODE_FINISH_LOG;
    }

    if (param->type == BACKUP_MODE_INVALID) {
        param->type = BACKUP_MODE_FULL;
    }

    if (param->exclude_spcs->count > 0 && param->type == BACKUP_MODE_TABLESPACE) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "can not specify exclude with copy of");
        return OG_ERROR;
    }

    if (param->cumulative && param->type != BACKUP_MODE_INCREMENTAL) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify cumulative without incremental");
        return OG_ERROR;
    }

    if (param->finish_scn != OG_INVALID_ID64 && param->compress_algo) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not specify compress in finish");
        return OG_ERROR;
    }

    if (param->buffer_size == 0) {
        param->buffer_size = buffer_size;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_backup_exclude(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    lex_t *lex = stmt->session->lex;
    text_t *spc_name = NULL;
    sql_text_t save_text;

    if (param->exclude_spcs->count > 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set exclude more than once");
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "for") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "tablespace") != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (;;) {
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (cm_galist_new(param->exclude_spcs, sizeof(text_t), (pointer_t *)&spc_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, spc_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        save_text = *(lex->curr_text);
        if (lex_fetch(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        if (!(IS_SPEC_CHAR(word, ','))) {
            *(lex->curr_text) = save_text;
            break;
        }

        if (param->exclude_spcs->count >= OG_MAX_SPACES) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "exclude spaces number out of max spaces number");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_backup_target(sql_stmt_t *stmt, word_t *word, knl_backup_t *param)
{
    lex_t *lex = stmt->session->lex;
    text_t *spc_name = NULL;
    sql_text_t save_text;

    status_t status = lex_expected_fetch_word(stmt->session->lex, "of");
    OG_RETURN_IFERR(status);
    status = lex_expected_fetch_word(lex, "tablespace");
    OG_RETURN_IFERR(status);

    if (param->type != BACKUP_MODE_INVALID && param->type != BACKUP_MODE_FULL) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ", because there has a incompatible backup type for tablespace");
        return OG_ERROR;
    }

    for (;;) {
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (cm_galist_new(param->target_info.target_list, sizeof(text_t), (pointer_t *)&spc_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, spc_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        save_text = *(lex->curr_text);
        if (lex_fetch(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        if (!(IS_SPEC_CHAR(word, ','))) {
            *(lex->curr_text) = save_text;
            break;
        }

        if (param->target_info.target_list->count >= OG_MAX_SPACES) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "spaces number out of max spaces number");
            return OG_ERROR;
        }
    }

    param->type = BACKUP_MODE_TABLESPACE;
    param->target_info.target = TARGET_TABLESPACE;
    return OG_SUCCESS;
}

static status_t sql_parse_buffer_size(sql_stmt_t *stmt, uint32 *buffer_size)
{
    int64 size;

    if (lex_expected_fetch_word(stmt->session->lex, "size") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_size(stmt->session->lex, &size, OG_MIN_BACKUP_BUF_SIZE, OG_MAX_BACKUP_BUF_SIZE) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    *buffer_size = size;

    if ((*buffer_size) < OG_MIN_BACKUP_BUF_SIZE || (*buffer_size) > OG_MAX_BACKUP_BUF_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BACKUP_BUFFER_SIZE", (int64)OG_MIN_BACKUP_BUF_SIZE,
            (int64)OG_MAX_BACKUP_BUF_SIZE);
        return OG_ERROR;
    }
    if ((*buffer_size) % (uint32)SIZE_M(8) != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "buffer size (%u) is not an integral multiple of 8M.", *buffer_size);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_set_backup_skip_badblock(sql_stmt_t *stmt, knl_backup_t *param)
{
    status_t status = lex_expected_fetch_word(stmt->session->lex, "BADBLOCK");
    OG_RETURN_IFERR(status);
   
    param->skip_badblock = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_parse_repair_type(sql_stmt_t *stmt, restore_repair_type_t *repair_type)
{
    status_t status;
    status = lex_expected_fetch_word(stmt->session->lex, "TYPE");
    OG_RETURN_IFERR(status);
 
    uint32 match_id;
    status = lex_expected_fetch_1of3(stmt->session->lex, "RETURN_ERROR", "REPLACE_CHECKSUM", "DISCARD_BADBLOCK",
                                     &match_id);
    OG_RETURN_IFERR(status);
 
    if (match_id == 0) {
        *repair_type = RESTORE_REPAIR_TYPE_NULL;
    } else if (match_id == 1) {
        *repair_type = RESTORE_REPAIR_REPLACE_CHECKSUN;
    } else {
        *repair_type = RESTORE_REPAIR_DISCARD_BADBLOCK;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_backup_arch_from(sql_stmt_t *stmt, knl_backup_t *param)
{
    if (lex_expected_fetch_word(stmt->session->lex, "asn") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, &param->target_info.backup_begin_asn) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_backup_archivelog(sql_stmt_t *stmt, knl_backup_t *param)
{
    status_t status;
    word_t word;
    uint32 match_id;

    param->target_info.target = TARGET_ARCHIVE;
    param->type = BACKUP_MODE_ARCHIVELOG;
    param->target_info.backup_arch_mode = ARCHIVELOG_ALL;
    status = lex_expected_fetch_1of2(stmt->session->lex, "all", "from", &match_id);
    OG_RETURN_IFERR(status);

    if (match_id == 1) {
        param->target_info.backup_arch_mode = ARCHIVELOG_FROM;
        status = sql_parse_backup_arch_from(stmt, param);
        OG_RETURN_IFERR(status);
    }

    for (;;) {
        status = lex_fetch(stmt->session->lex, &word);
        OG_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        switch (word.id) {
            case KEY_WORD_FORMAT:
                status = sql_parse_backup_format(stmt, &word, param);
                break;
            case KEY_WORD_AS:
                status = sql_set_backup_as(stmt, param);
                break;
            case KEY_WORD_TAG:
                status = sql_parse_backup_tag(stmt, &word, param->tag);
                break;
            case KEY_WORD_BUFFER:
                status = sql_parse_buffer_size(stmt, &param->buffer_size);
                break;
            default:
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found",
                    W2S(&word));
                return OG_ERROR;
        }

        if (status != OG_SUCCESS) {
            cm_try_set_error_loc(word.text.loc);
            return OG_ERROR;
        }
    }

    if (sql_check_backup_param(stmt, param) != OG_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_prase_backup_cancel(sql_stmt_t *stmt, knl_backup_t *param)
{
    status_t status;

    status = lex_expected_fetch_word(stmt->session->lex, "current");
    OG_RETURN_IFERR(status);
    status = lex_expected_fetch_word(stmt->session->lex, "process");
    OG_RETURN_IFERR(status);

    status = lex_expected_end(stmt->session->lex);
    OG_RETURN_IFERR(status);

    param->force_cancel = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_parse_backup_core(sql_stmt_t *stmt, word_t word, knl_backup_t *backup)
{
    status_t status;
    switch (word.id) {
        case KEY_WORD_FULL:
            status = sql_set_backup_type(backup, BACKUP_MODE_FULL);
            break;
        case KEY_WORD_INCREMENTAL:
            status = sql_parse_backup_incremental(stmt->session->lex, &word, backup);
            break;
        case KEY_WORD_FORMAT:
            status = sql_parse_backup_format(stmt, &word, backup);
            break;
        case KEY_WORD_PREPARE:
            status = sql_set_backup_prepare(backup);
            break;
        case KEY_WORD_FINISH:
            status = sql_set_backup_finish(stmt, &word, backup);
            break;
        case KEY_WORD_TAG:
            status = sql_parse_backup_tag(stmt, &word, backup->tag);
            break;
        case KEY_WORD_CUMULATIVE:
            status = sql_set_backup_cumulative(backup);
            break;
        case KEY_WORD_AS:
            status = sql_set_backup_as(stmt, backup);
            break;
        case KEY_WORD_SECTION:
            status = sql_set_backup_section(stmt, backup);
            break;
        case KEY_WORD_PARALLELISM:
            status = sql_set_backup_parallelism(stmt, &backup->parallelism);
            break;
        case KEY_WORD_EXCLUDE:
            status = sql_parse_backup_exclude(stmt, &word, backup);
            break;
        case KEY_WORD_PASSWORD:
            status = sql_set_backup_encrypt(stmt, &backup->crypt_info, OG_TRUE);
            break;
        case KEY_WORD_COPY:
            status = sql_parse_backup_target(stmt, &word, backup);
            break;
        case KEY_WORD_BUFFER:
            status = sql_parse_buffer_size(stmt, &backup->buffer_size);
            break;
        case KEY_WORD_SKIP:
            status = sql_set_backup_skip_badblock(stmt, backup);
            break;
        default:
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return OG_ERROR;
    }
    if (status != OG_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_parse_backup(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    knl_backup_t *param = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_backup_t), (void **)&param);
    OG_RETURN_IFERR(status);
    stmt->context->entry = param;

    MEMS_RETURN_IFERR(memset_s(param, sizeof(knl_backup_t), 0, sizeof(knl_backup_t)));

    param->finish_scn = OG_INVALID_ID64;
    param->type = BACKUP_MODE_INVALID;

    if (sql_create_list(stmt, &param->exclude_spcs) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_list(stmt, &param->target_info.target_list) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 match_id;
    status = lex_expected_fetch_1of3(stmt->session->lex, "archivelog", "cancel", "database", &match_id);
    OG_RETURN_IFERR(status);

    if (match_id == 0) {
        return sql_parse_backup_archivelog(stmt, param);
    }

    if (match_id == 1) {
        return sql_prase_backup_cancel(stmt, param);
    }

    for (;;) {
        status = lex_fetch(stmt->session->lex, &word);
        OG_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        OG_RETURN_IFERR(sql_parse_backup_core(stmt, word, param));
    }

    if (sql_check_backup_param(stmt, param) != OG_SUCCESS) {
        cm_try_set_error_loc(word.text.loc);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_until(sql_stmt_t *stmt, knl_restore_t *param)
{
    if (lex_expected_fetch_word(stmt->session->lex, "lfn") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_uint64(stmt->session->lex, &param->lfn) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_restore_from(sql_stmt_t *stmt, word_t *word, knl_restore_t *param, bool32 block_recover)
{
    text_t sub_param;

    OG_RETURN_IFERR(lex_expected_fetch_string(stmt->session->lex, word));

    if (param->path.len > 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "can not set from more than once");
        return OG_ERROR;
    }

    (void)cm_fetch_text(&word->text.value, ':', '\0', &sub_param);
    if (word->text.value.len > 0) {
        if (!cm_compare_text_str(&sub_param, "nbu") && !block_recover) {
            param->device = DEVICE_UDS;
            if (!cm_fetch_text(&word->text.value, ':', '\0', &param->policy)) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, can not find policy name");
                return OG_ERROR;
            }

            if (param->policy.len >= OG_BACKUP_PARAM_SIZE) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "policy name exceeded the maximum length %u", OG_BACKUP_PARAM_SIZE);
                return OG_ERROR;
            }
        } else if (cm_compare_text_str(&sub_param, "disk")) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid device type:%s", T2S(&sub_param));
            return OG_ERROR;
        }

        if (!cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, no dest path specified");
            return OG_ERROR;
        }
    }

    OG_RETURN_IFERR(sql_copy_file_name(stmt->context, &sub_param, &param->path));

    if (cm_fetch_text(&word->text.value, ':', '\0', &sub_param)) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid format, %s value is invalid",
            T2S(&sub_param));
        return OG_ERROR;
    }

    param->type = block_recover ? RESTORE_BLOCK_RECOVER : RESTORE_FROM_PATH;
    return OG_SUCCESS;
}

static status_t sql_parse_restore_blockrecover(sql_stmt_t *stmt, knl_restore_t *param)
{
    status_t status;
    uint32 value;

    status = lex_expected_fetch_word(stmt->session->lex, "datafile");
    OG_RETURN_IFERR(status);

    if (lex_expected_fetch_uint32(stmt->session->lex, &value) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (value >= INVALID_FILE_ID) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile value should be in [%u, %u]", (uint32)0,
            (uint32)(INVALID_FILE_ID - 1));
        return OG_ERROR;
    }

    param->page_need_repair.file = value;

    status = lex_expected_fetch_word(stmt->session->lex, "page");
    OG_RETURN_IFERR(status);

    if (lex_expected_fetch_uint32(stmt->session->lex, &value) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (value == 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "page value should not be 0");
        return OG_ERROR;
    }

    param->page_need_repair.page = value;
    return status;
}

static status_t sql_parse_restore_filerecover(sql_stmt_t *stmt, knl_restore_t *param)
{
    uint32 match_id;
    uint32 value;
    word_t word;

    status_t status = lex_expected_fetch_1of2(stmt->session->lex, "filename", "fileid", &match_id);
    OG_RETURN_IFERR(status);

    if (match_id == 0) {
        if (lex_expected_fetch_string(stmt->session->lex, &word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word.text, &param->file_repair_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        param->file_repair = OG_INVALID_FILEID;
    } else {
        if (lex_expected_fetch_uint32(stmt->session->lex, &value) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (value >= INVALID_FILE_ID) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "fileid value should be in [%u, %u]", (uint32)0,
                (uint32)(INVALID_FILE_ID - 1));
            return OG_ERROR;
        }

        param->file_repair = value;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_disconnect(sql_stmt_t *stmt, knl_restore_t *param)
{
    status_t status;

    if (param->disconnect == OG_TRUE) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not set disconnect more than once");
        return OG_ERROR;
    }

    status = lex_expected_fetch_word(stmt->session->lex, "from");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_word(stmt->session->lex, "session");
    OG_RETURN_IFERR(status);

    param->disconnect = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_parse_restore_type(sql_stmt_t *stmt, knl_restore_t *param)
{
    status_t status;
    uint32 match_id = OG_INVALID_ID32;

    if (IS_CTRST_INSTANCE) {
        status = lex_expected_fetch_1of2(stmt->session->lex, "database", "blockrecover", &match_id);
    } else {
        status = lex_expected_fetch_1ofn(stmt->session->lex, &match_id, 5, "database", "filerecover", "archivelog", "flushpage", "COPYCTRL");
    }
    OG_RETURN_IFERR(status);

    if (match_id == 1) {
        if (IS_CTRST_INSTANCE) {
            param->type = RESTORE_BLOCK_RECOVER;
            status = sql_parse_restore_blockrecover(stmt, param);
        } else {
            param->file_type = RESTORE_DATAFILE;
            status = sql_parse_restore_filerecover(stmt, param);
        }

        OG_RETURN_IFERR(status);
    }

    if (match_id == 2) {
        param->file_type = RESTORE_ARCHFILE;
    }

    if (match_id == 3) {
        param->file_type = RESTORE_FLUSHPAGE;
    }

    if (match_id == 4) {
        param->file_type = RESTORE_COPYCTRL;
    }
    return OG_SUCCESS;
}

static status_t sql_check_restore_param(sql_stmt_t *stmt, knl_restore_t *param, word_t *word)
{
    uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;

    if (param->type != RESTORE_FROM_PATH) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "backup set path is not specified");
        return OG_ERROR;
    }

    if (param->buffer_size == 0) {
        param->buffer_size = buffer_size;
    }

    return OG_SUCCESS;
}

status_t sql_parse_restore(sql_stmt_t *stmt)
{
    knl_restore_t *param = NULL;
    word_t word;
    status_t status;

    status = sql_alloc_mem(stmt->context, sizeof(knl_restore_t), (void **)&param);
    OG_RETURN_IFERR(status);
    stmt->context->entry = param;

    MEMS_RETURN_IFERR(memset_s(param, sizeof(knl_restore_t), 0, sizeof(knl_restore_t)));

    status = sql_parse_restore_type(stmt, param);
    OG_RETURN_IFERR(status);

    if (param->file_type == RESTORE_COPYCTRL) {
        status = lex_expected_fetch_word(stmt->session->lex, "to");
        OG_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_word(stmt->session->lex, "from");
        OG_RETURN_IFERR(status);
    }

    status = sql_parse_restore_from(stmt, &word, param, param->type == RESTORE_BLOCK_RECOVER);
    OG_RETURN_IFERR(status);

    if (param->file_type == RESTORE_ARCHFILE || param->file_type == RESTORE_DATAFILE) {
        status = lex_fetch(stmt->session->lex, &word);
        OG_RETURN_IFERR(status);

        if (word.id == KEY_WORD_BUFFER) {
            status = sql_parse_buffer_size(stmt, &param->buffer_size);
            OG_RETURN_IFERR(status);
        }
        uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;
        if (param->buffer_size == 0) {
            param->buffer_size = buffer_size;
        }

        return lex_expected_end(stmt->session->lex);
    }

    if (param->type == RESTORE_BLOCK_RECOVER) {
        status = lex_fetch(stmt->session->lex, &word);
        OG_RETURN_IFERR(status);

        if (word.id == KEY_WORD_UNTIL) {
            status = sql_parse_until(stmt, param);
            OG_RETURN_IFERR(status);
        } else if (word.type != WORD_TYPE_EOF) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(&word));
            return OG_ERROR;
        }

        return OG_SUCCESS;
    }

    for (;;) {
        status = lex_fetch(stmt->session->lex, &word);
        OG_RETURN_IFERR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        switch (word.id) {
            case KEY_WORD_DISCONNECT:
                status = sql_parse_disconnect(stmt, param);
                break;
            case KEY_WORD_PARALLELISM:
                status = sql_set_backup_parallelism(stmt, &param->parallelism);
                break;
            case KEY_WORD_TABLESPACE:
                status = lex_expected_fetch_variant(stmt->session->lex, &word);
                OG_RETURN_IFERR(status);
                status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &param->spc_name);
                OG_RETURN_IFERR(status);
                break;
            case KEY_WORD_PASSWORD:
                status = sql_set_backup_encrypt(stmt, &param->crypt_info, OG_FALSE);
                break;
            case KEY_WORD_BUFFER:
                status = sql_parse_buffer_size(stmt, &param->buffer_size);
                break;
            case KEY_WORD_REPAIR:
                status = sql_parse_repair_type(stmt, &param->repair_type);
                break;
            default:
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found",
                    W2S(&word));
                return OG_ERROR;
        }

        if (status != OG_SUCCESS) {
            cm_try_set_error_loc(word.text.loc);
            return OG_ERROR;
        }
    }

    if (sql_check_restore_param(stmt, param, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_recover(sql_stmt_t *stmt)
{
    knl_recover_t *param = NULL;
    word_t word;
    text_t fmt_text;
    date_t date;
    uint32 match_id;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_recover_t), (void **)&param));
    stmt->context->entry = param;
    param->time.tv_sec = (long)OG_INVALID_INT64;
    param->time.tv_usec = 0;

    if (lex_expected_fetch_word(stmt->session->lex, "database") != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_fetch(stmt->session->lex, &word));

    if (word.type == WORD_TYPE_EOF) {
        param->action = RECOVER_NORMAL;
        return OG_SUCCESS;
    }

    if (word.id != KEY_WORD_UNTIL) {
        OG_SRC_THROW_ERROR_EX(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR, "until expected");
        return OG_ERROR;
    }

    if (lex_expected_fetch_1of3(stmt->session->lex, "time", "scn", "cancel", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (match_id == 0) {
        if (lex_expected_fetch_string(stmt->session->lex, &word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        sql_session_nlsparam_geter(stmt, NLS_DATE_FORMAT, &fmt_text);
        if (cm_text2date(&word.text.value, &fmt_text, &date) != OG_SUCCESS) {
            return OG_ERROR;
        }

        cm_date2timeval(date, &param->time);
        param->action = RECOVER_UNTIL_TIME;
        OG_LOG_RUN_INF("[RCY] start pitr until to time %s", T2S(&word.text.value));
    } else if (match_id == 1) {
        if (lex_expected_fetch_uint64(stmt->session->lex, &param->scn) != OG_SUCCESS) {
            return OG_ERROR;
        }
        param->action = RECOVER_UNTIL_SCN;
    } else {
        param->action = RECOVER_UNTIL_CANCEL;
    }

    return lex_expected_end(stmt->session->lex);
}

status_t sql_parse_shutdown(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    shutdown_context_t *param = NULL;
    uint32 matched_id;

    if (sql_alloc_mem(stmt->context, sizeof(shutdown_context_t), (void **)&param) != OG_SUCCESS) {
        return OG_ERROR;
    }

    stmt->context->entry = param;

    if (lex_try_fetch_1of2(lex, "immediate", "abort", &matched_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (matched_id == 0) {
        param->mode = SHUTDOWN_MODE_IMMEDIATE;
    } else if (matched_id == 1) {
        param->mode = SHUTDOWN_MODE_ABORT;
    } else {
        param->mode = SHUTDOWN_MODE_NORMAL;
    }

    return lex_expected_end(lex);
}

status_t sql_parse_ograc(sql_stmt_t *stmt)
{
    knl_ograc_recover_t *param = NULL;
    status_t status;

    status = sql_alloc_mem(stmt->context, sizeof(knl_ograc_recover_t), (void **)&param);
    OG_RETURN_IFERR(status);
    stmt->context->entry = param;

    status = lex_expected_fetch_word(stmt->session->lex, "recover");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_uint32(stmt->session->lex, &param->full);
    OG_RETURN_IFERR(status);

    if (param->full > 1) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "recover mode %u should be 1(if recover) or 0(if analysis)",
            param->full);
        return OG_ERROR;
    }

    status = lex_expected_fetch_word(stmt->session->lex, "start");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_uint32(stmt->session->lex, &param->start);
    OG_RETURN_IFERR(status);

    if (param->start >= OG_MAX_INSTANCES) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "start node id should be in [%u, %u]", (uint32)0,
            (uint32)(OG_MAX_INSTANCES - 1));
        return OG_ERROR;
    }

    status = lex_expected_fetch_word(stmt->session->lex, "count");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_uint32(stmt->session->lex, &param->count);
    OG_RETURN_IFERR(status);

    if (param->count > OG_MAX_INSTANCES) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "node count should be less or euqal than %u", OG_MAX_INSTANCES);
        return OG_ERROR;
    }

    return lex_expected_end(stmt->session->lex);
}

#ifdef __cplusplus
}
#endif
