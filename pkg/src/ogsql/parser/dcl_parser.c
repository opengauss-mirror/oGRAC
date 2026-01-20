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
 * dcl_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/dcl_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#ifdef DB_DEBUG_VERSION
#endif /* DB_DEBUG_VERSION */
#include "dcl_parser.h"
#include "dcl_database_parser.h"
#include "dcl_transaction_parser.h"
#include "dcl_alter_parser.h"
#include "expr_parser.h"
#include "ogsql_verifier.h"
#include "ddl_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static compress_algo_e compress_algo[] = {COMPRESS_ZLIB, COMPRESS_ZSTD, COMPRESS_LZ4};

static status_t sql_parse_validate_datafile_page(sql_stmt_t *stmt, knl_validate_t *param)
{
    status_t status;
    uint32 datafile;
    uint32 page;

    status = lex_expected_fetch_uint32(stmt->session->lex, &datafile);
    OG_RETURN_IFERR(status);

    if (datafile >= INVALID_FILE_ID) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile value should be in [%u, %u]", (uint32)0,
            (uint32)(INVALID_FILE_ID - 1));
        return OG_ERROR;
    }

    status = lex_expected_fetch_word(stmt->session->lex, "page");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_uint32(stmt->session->lex, &page);
    OG_RETURN_IFERR(status);

    if (page == 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "page value should not be 0");
        return OG_ERROR;
    }

    param->validate_type = VALIDATE_DATAFILE_PAGE;
    param->page_id.file = datafile;
    param->page_id.page = page;
    return OG_SUCCESS;
}

static status_t sql_parse_validate(sql_stmt_t *stmt)
{
    knl_validate_t *param = NULL;
    status_t status;
    uint32 matched_id;

    status = sql_alloc_mem(stmt->context, sizeof(knl_validate_t), (void **)&param);
    OG_RETURN_IFERR(status);
    stmt->context->entry = param;

    MEMS_RETURN_IFERR(memset_s(param, sizeof(knl_validate_t), 0, sizeof(knl_validate_t)));

    status = lex_expected_fetch_1of2(stmt->session->lex, "datafile", "backupset", &matched_id);
    OG_RETURN_IFERR(status);

    if (matched_id == 0) {
        status = sql_parse_validate_datafile_page(stmt, param);
        OG_RETURN_IFERR(status);
    } else {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "validate backupset not supported");
        return OG_ERROR;
    }

    return lex_expected_end(stmt->session->lex);
}

static status_t sql_parse_compress_for_build(lex_t *lex, build_param_ctrl_t *ctrl)
{
    uint32 matched_id = OG_INVALID_ID32;
    compress_algo_e algorithm = COMPRESS_ZSTD;
    bool32 fetch_result = OG_FALSE;
    uint32 level;

    ctrl->parallelism = 0;
    ctrl->is_increment = OG_FALSE;
    ctrl->base_lsn = 0;

    if (ctrl->is_repair) {
        return OG_SUCCESS;
    }

    if (lex_try_fetch(lex, "incremental", &fetch_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (fetch_result) {
        ctrl->is_increment = OG_TRUE;
    }

    if (lex_try_fetch(lex, "compress", &fetch_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!fetch_result) {
        ctrl->compress = COMPRESS_NONE;
        return OG_SUCCESS;
    }

    if (lex_try_fetch_1of3(lex, "zlib", "zstd", "lz4", &matched_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (matched_id != OG_INVALID_ID32) {
        algorithm = compress_algo[matched_id];
    }

    ctrl->compress = algorithm;

    if (lex_try_fetch(lex, "level", &fetch_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!fetch_result) {
        ctrl->compress_level = Z_BEST_SPEED; // level 1 with best speed
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_uint32(lex, &level) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (level < Z_BEST_SPEED || level > Z_BEST_COMPRESSION) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "level value should be in [1, 9]");
        return OG_ERROR;
    }
    ctrl->compress_level = level;

    return OG_SUCCESS;
}

static status_t sql_parse_paral_for_build(lex_t *lex, build_param_ctrl_t *ctrl)
{
    bool32 fetch_result = OG_FALSE;
    uint32 paral_num;

    if (lex_try_fetch(lex, "parallelism", &fetch_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!fetch_result) {
        ctrl->parallelism = 0;
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_uint32(lex, &paral_num) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (paral_num < 1 || paral_num > (OG_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "parallelism value should be in [%u, %u]", (uint32)1,
            (uint32)(OG_MAX_BACKUP_PROCESS - BAK_PARAL_LOG_PROC_NUM - 1));
        return OG_ERROR;
    }

    ctrl->parallelism = paral_num;
    return OG_SUCCESS;
}

static status_t sql_parse_buffer_for_build(lex_t *lex, build_param_ctrl_t *ctrl)
{
    int64 size;
    bool32 fetch_result = OG_FALSE;

    if (lex_try_fetch(lex, "buffer", &fetch_result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!fetch_result) {
        ctrl->buffer_size = 0;
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "size") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_size(lex, &size, OG_MIN_BACKUP_BUF_SIZE, OG_MAX_BACKUP_BUF_SIZE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    ctrl->buffer_size = size;

    if (ctrl->buffer_size < OG_MIN_BACKUP_BUF_SIZE || ctrl->buffer_size > OG_MAX_BACKUP_BUF_SIZE) {
        OG_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BACKUP_BUFFER_SIZE", (int64)OG_MIN_BACKUP_BUF_SIZE,
            (int64)OG_MAX_BACKUP_BUF_SIZE);
        return OG_ERROR;
    }

    if (ctrl->buffer_size % (uint32)SIZE_M(8) != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "buffer size (%u) is not an integral multiple of 8M.",
            ctrl->buffer_size);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_build(sql_stmt_t *stmt)
{
    word_t word;
    knl_build_def_t *param = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 buffer_size = (uint32)stmt->session->knl_session.kernel->attr.backup_buf_size;

    if (sql_alloc_mem(stmt->context, sizeof(knl_build_def_t), (void **)&param) != OG_SUCCESS) {
        return OG_ERROR;
    }

    stmt->context->entry = param;

    if (lex_expected_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_DATABASE:
            param->build_type = BUILD_AUTO;
            break;

        case KEY_WORD_CASCADED:
            param->build_type = BUILD_CASCADED_STANDBY;
            if (lex_expected_fetch_word(lex, "standby") != OG_SUCCESS) {
                return OG_ERROR;
            }

            if (lex_expected_fetch_word(lex, "database") != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;

        case KEY_WORD_STANDBY:
            param->build_type = BUILD_STANDBY;
            if (lex_expected_fetch_word(lex, "database") != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;

        case KEY_WORD_REPAIR:
            param->build_type = BUILD_AUTO;
            param->param_ctrl.is_repair = OG_TRUE;
            if (lex_expected_fetch_word(lex, "database") != OG_SUCCESS) {
                return OG_ERROR;
            }
            break;

        default:
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpectd word %s for build", W2S(&word));
            return OG_ERROR;
    }

    if (sql_parse_compress_for_build(lex, &param->param_ctrl) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_paral_for_build(lex, &param->param_ctrl) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_buffer_for_build(lex, &param->param_ctrl) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (param->param_ctrl.buffer_size == 0) {
        param->param_ctrl.buffer_size = buffer_size;
    }

    return lex_expected_end(lex);
}

#ifdef DB_DEBUG_VERSION
static status_t sql_parse_syncpoint_signal_wait(sql_stmt_t *stmt, lex_t *lex, syncpoint_def_t *def)
{
    status_t status;
    word_t word;
    int32 count;

    status = lex_fetch(lex, &word);
    OG_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_WAIT:
            if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "signal name expected but %s found",
                    W2S(&word));
                return OG_ERROR;
            }
            status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->wait_for);
            OG_RETURN_IFERR(status);
            break;

        case KEY_WORD_SIGNAL:
            if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "signal name expected but %s found",
                    W2S(&word));
                return OG_ERROR;
            }

            status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->signal);
            OG_RETURN_IFERR(status);

            if (lex_expected_fetch_word(lex, "RAISE") != OG_SUCCESS) {
                if (lex_expected_end(lex) != OG_SUCCESS) {
                    OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise expected");
                    return OG_ERROR;
                }

                def->raise_count = 1;
                return OG_SUCCESS;
            }

            if (lex_expected_fetch_int32(lex, &count) != OG_SUCCESS) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count not found");
                return OG_ERROR;
            }

            if (count < 1) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count %d, should larger than 1",
                    count);
                return OG_ERROR;
            }

            def->raise_count = (uint32)count;
            break;
        case KEY_WORD_SET:
            if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "enable expected true/false but %s found",
                    W2S(&word));
                return OG_ERROR;
            }
            if (cm_compare_str_ins(W2S(&word), "enable") && cm_compare_str_ins(W2S(&word), "disable")) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "set expected enable/disable but %s found",
                    W2S(&word));
                return OG_ERROR;
            }
            status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->enable);
            OG_RETURN_IFERR(status);
            if (lex_expected_fetch_word(lex, "RAISE") != OG_SUCCESS) {
                if (lex_expected_end(lex) != OG_SUCCESS) {
                    OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise expected");
                    return OG_ERROR;
                }
                def->raise_count = 1;
                return OG_SUCCESS;
            }

            if (lex_expected_fetch_int32(lex, &count) != OG_SUCCESS) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count not found");
                return OG_ERROR;
            }

            if (count < 1) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "raise count %d, should larger than 1",
                    count);
                return OG_ERROR;
            }

            def->raise_count = (uint32)count;
            break;
        default:
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "syncpoint action expected but %s found",
                W2S(&word));
            return OG_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_syncpoint(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    syncpoint_def_t *def = NULL;

    stmt->context->type = OGSQL_TYPE_SYNCPOINT;

    if (sql_alloc_mem(stmt->context, sizeof(syncpoint_def_t), (void **)&def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if ((key_wid_t)word.id == KEY_WORD_RESET) {
        stmt->context->entry = def;
        return lex_expected_end(lex);
    }

    if (!IS_VARIANT(&word)) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "syncpoint name expected but %s found", W2S(&word));
        return OG_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->syncpoint_name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    stmt->context->entry = def;
    return sql_parse_syncpoint_signal_wait(stmt, lex, def);
}
#endif /* DB_DEBUG_VERSION */

#define SQL_CHECK_DUPLICATE_TABLE(stmt, list, entityTypeName, fld_schema, owner, fld_name, table_name)           \
    do {                                                                                                         \
        for (uint32 i = 0; i < (list)->count; i++) {                                                             \
            entityTypeName *entity = (entityTypeName *)cm_galist_get((list), i);                                 \
            if (cm_text_equal(&(entity->fld_schema), owner) && cm_text_equal(&(entity->fld_name), table_name)) { \
                OG_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(owner), T2S(table_name));                                \
                return OG_ERROR;                                                                                 \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)

static status_t sql_parse_table_defs(sql_stmt_t *stmt, lex_t *lex, lock_tables_def_t *def)
{
    word_t word;
    lock_table_t *table = NULL;
    text_t owner;
    text_t table_name;
    bool32 result = OG_FALSE;

    for (;;) {
        lex->flags |= LEX_WITH_OWNER;
        if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_convert_object_name(stmt, &word, &owner, NULL, &table_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        SQL_CHECK_DUPLICATE_TABLE(stmt, (&def->tables), lock_table_t, schema, &owner, name, &table_name);

        if (cm_galist_new(&def->tables, sizeof(lock_table_t), (pointer_t *)&table) != OG_SUCCESS) {
            return OG_ERROR;
        }

        table->name = table_name;
        table->schema = owner;

        if (lex_try_fetch(lex, "in", &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (result) {
            break;
        }

        if (lex_fetch(lex, &word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

#ifdef OG_RAC_ING
// for online update
static shd_lock_unlock_type_t shd_diag_lock_type(sql_stmt_t *stmt)
{
    uint32 matched_id;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != OG_SUCCESS) {
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "TABLE", "NODE", &matched_id) != OG_SUCCESS) {
        lex_pop(stmt->session->lex);
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    } else {
        if (matched_id != OG_INVALID_ID32) {
            lex_pop(stmt->session->lex);
            return ((matched_id == 0) ? SHD_LOCK_UNLOCK_TYPE_TALBE : SHD_LOCK_UNLOCK_TYPE_NODE);
        }
    }
    lex_pop(stmt->session->lex);
    return SHD_LOCK_UNLOCK_TYPE_TALBE;
}

static shd_lock_unlock_type_t shd_diag_unlock_type(sql_stmt_t *stmt)
{
    uint32 matched_id;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != OG_SUCCESS) {
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "TABLE", "NODE", &matched_id) != OG_SUCCESS) {
        lex_pop(stmt->session->lex);
        return SHD_LOCK_UNLOCK_TYPE_TALBE;
    } else {
        if (matched_id != OG_INVALID_ID32) {
            lex_pop(stmt->session->lex);
            return ((matched_id == 0) ? SHD_LOCK_UNLOCK_TYPE_TALBE : SHD_LOCK_UNLOCK_TYPE_NODE);
        }
    }
    lex_pop(stmt->session->lex);
    return SHD_LOCK_UNLOCK_TYPE_TALBE;
}

static status_t shd_parse_lock_node(sql_stmt_t *stmt)
{
    status_t status;
    int32 wait_time;
    uint32 match_id;
    shd_lock_node_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    stmt->context->type = OGSQL_TYPE_LOCK_NODE;

    status = sql_alloc_mem(stmt->context, sizeof(shd_lock_node_def_t), (void **)&def);
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "node");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "in");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_1ofn(lex, &match_id, 2, "share", "exclusive");
    OG_RETURN_IFERR(status);

    def->lock_mode = (shd_lock_node_mode_t)(match_id + 1);

    status = lex_expected_fetch_word(lex, "mode");
    OG_RETURN_IFERR(status);

    def->wait_mode = SHD_WAIT_MODE_WAIT;
    def->wait_time = OG_INVALID_ID32;

    status = lex_try_fetch_1ofn(lex, &match_id, 2, "nowait", "wait");
    OG_RETURN_IFERR(status);

    if (SHD_WAIT_MODE_NO_WAIT == match_id) {
        def->wait_mode = SHD_WAIT_MODE_NO_WAIT;
        def->wait_time = 0;
    } else if (SHD_WAIT_MODE_WAIT == match_id) {
        status = lex_expected_fetch_int32(lex, &wait_time);
        OG_RETURN_IFERR(status);

        if (wait_time < 0) {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "missing or invalid WAIT interval");
            return OG_ERROR;
        }
        if (wait_time == 0) {
            def->wait_mode = SHD_WAIT_MODE_NO_WAIT;
        } else {
            def->wait_time = (uint32)wait_time;
        }
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}


static status_t shd_parse_unlock_node(sql_stmt_t *stmt)
{
    status_t status;

    lex_t *lex = stmt->session->lex;
    stmt->context->type = OGSQL_TYPE_UNLOCK_NODE;

    status = lex_expected_fetch_word(lex, "node");
    OG_RETURN_IFERR(status);

    stmt->context->entry = NULL;
    return lex_expected_end(lex);
}

#endif

static status_t sql_parse_locktable(sql_stmt_t *stmt)
{
    status_t status;
    int32 wait_time;
    uint32 match_id;
    lock_tables_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    stmt->context->type = OGSQL_TYPE_LOCK_TABLE;

    status = sql_alloc_mem(stmt->context, sizeof(lock_tables_def_t), (void **)&def);
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "table");
    OG_RETURN_IFERR(status);

    cm_galist_init(&def->tables, stmt->context, sql_alloc_mem);

    status = sql_parse_table_defs(stmt, lex, def);
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_1ofn(lex, &match_id, 2, "share", "exclusive");
    OG_RETURN_IFERR(status);

    def->lock_mode = (lock_table_mode_t)match_id;

    status = lex_expected_fetch_word(lex, "mode");
    OG_RETURN_IFERR(status);
    /*
    If you specify neither NOWAIT nor WAIT, then the database waits indefinitely until the
    table is available, locks it, and returns control to you. When the database is executing
    DDL statements concurrently with DML statements, a timeout or deadlock can
    sometimes result. The database detects such timeouts and deadlocks and returns an
    error.
    */
    def->wait_mode = WAIT_MODE_WAIT;
    def->wait_time = OG_INVALID_ID32;

    status = lex_try_fetch_1ofn(lex, &match_id, 2, "nowait", "wait");
    OG_RETURN_IFERR(status);

    if (WAIT_MODE_NO_WAIT == match_id) {
        def->wait_mode = WAIT_MODE_NO_WAIT;
        def->wait_time = 0;
    } else if (WAIT_MODE_WAIT == match_id) {
        status = lex_expected_fetch_int32(lex, &wait_time);
        OG_RETURN_IFERR(status);

        if (wait_time < 0) {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "missing or invalid WAIT interval");
            return OG_ERROR;
        }
        if (wait_time == 0) {
            def->wait_mode = WAIT_MODE_NO_WAIT;
        } else {
            def->wait_time = (uint32)wait_time;
        }
    }

    stmt->context->entry = def;
    return lex_expected_end(lex);
}

#ifdef OG_RAC_ING
static status_t sql_init_route(sql_stmt_t *stmt, sql_route_t *route_ctx)
{
    if (sql_create_list(stmt, &route_ctx->pairs) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&route_ctx->rule) != OG_SUCCESS) {
        return OG_ERROR;
    }

    route_ctx->pairs_count = 0;
    return OG_SUCCESS;
}

static status_t sql_try_parse_route_pair(sql_stmt_t *stmt, lex_t *lex, sql_route_t *route_ctx, word_t *word)
{
    column_value_pair_t *pair = NULL;

    OG_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
    OG_RETURN_IFERR(cm_galist_new(route_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
    OG_RETURN_IFERR(sql_create_list(stmt, &pair->exprs));

    if (word->type == WORD_TYPE_DQ_STRING) {
        pair->column_name_has_quote = OG_TRUE;
    }
    return sql_copy_object_name_loc(stmt->context, word->type, &word->text, &pair->column_name);
}

static status_t sql_try_parse_route_columns(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;

    if (word->type != WORD_TYPE_BRACKET) {
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word->text);

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    if (lex_try_fetch(lex, "SELECT", &result) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (result) {
        lex_pop(lex);
        return OG_SUCCESS;
    }

    for (;;) {
        lex->flags = LEX_SINGLE_WORD;
        if (sql_try_parse_route_pair(stmt, lex, route_ctx, word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (lex_fetch(lex, word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    lex_pop(lex);
    route_ctx->cols_specified = OG_TRUE;
    return lex_fetch(lex, word);
}

static status_t sql_parse_single_route_core(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word, bool32 is_first,
    lex_t *lex)
{
    uint32 pair_id = 0;
    column_value_pair_t *pair = NULL;
    expr_tree_t *expr = NULL;

    for (;;) {
        lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

        if (route_ctx->cols_specified) {
            if (pair_id > route_ctx->pairs->count - 1) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found",
                    W2S(word));
                return OG_ERROR;
            }

            pair = (column_value_pair_t *)cm_galist_get(route_ctx->pairs, pair_id);
        } else {
            if (is_first) {
                OG_RETURN_IFERR(cm_galist_new(route_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
                OG_RETURN_IFERR(sql_create_list(stmt, &pair->exprs));
            } else {
                pair = (column_value_pair_t *)cm_galist_get(route_ctx->pairs, pair_id);
            }
        }

        OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
        OG_RETURN_IFERR(cm_galist_insert(pair->exprs, expr));

        pair_id++;

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    if (pair_id != route_ctx->pairs->count) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "more value expressions expected");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_single_route_values(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word, bool32 is_first)
{
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    OG_RETURN_IFERR(lex_push(lex, &word->text));
    if (sql_parse_single_route_core(stmt, route_ctx, word, is_first, lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return lex_fetch(stmt->session->lex, word);
}

static status_t sql_parse_route_values(sql_stmt_t *stmt, sql_route_t *route_ctx, word_t *word)
{
    bool32 is_first = OG_TRUE;

    if (word->id != KEY_WORD_VALUES) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "VALUES expected but %s found", W2S(word));
        return OG_ERROR;
    }

    for (;;) {
        OG_RETURN_IFERR(sql_parse_single_route_values(stmt, route_ctx, word, is_first));
        route_ctx->pairs_count++;

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }

        // insert into t1(f1, f2) values(1,2),(3,4),(5,6)...
        is_first = OG_FALSE;
    }

    return OG_SUCCESS;
}


static status_t sql_create_route_context(sql_stmt_t *stmt, sql_route_t **route_ctx)
{
    lex_t *lex = stmt->session->lex;
    word_t word;
    sql_table_t *rule = NULL;

    uint32 matched_id;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_route_t), (void **)route_ctx));

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "by"));

    OG_RETURN_IFERR(lex_expected_fetch_1of3(lex, "rule", "node", "null", &matched_id));

    switch (matched_id) {
        case LEX_MATCH_FIRST_WORD: {
            (*route_ctx)->type = SHD_ROUTE_BY_RULE;

            OG_RETURN_IFERR(sql_init_route(stmt, *route_ctx));

            rule = (*route_ctx)->rule;
            rule->is_distribute_rule = OG_TRUE;

            OG_RETURN_IFERR(sql_parse_table(stmt, rule, &word));
            OG_RETURN_IFERR(sql_try_parse_route_columns(stmt, *route_ctx, &word));
            OG_RETURN_IFERR(sql_parse_route_values(stmt, *route_ctx, &word));

            if (word.type != WORD_TYPE_EOF) {
                OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
                return OG_ERROR;
            }
            break;
        }
        case LEX_MATCH_SECOND_WORD:
            (*route_ctx)->type = SHD_ROUTE_BY_NODE;
            uint32 group_id = 0;

            OG_RETURN_IFERR(lex_expected_fetch_uint32(lex, &group_id));

            (*route_ctx)->group_id = group_id;

            OG_RETURN_IFERR(lex_fetch(lex, &word));
            if (word.type != WORD_TYPE_EOF) {
                OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
                return OG_ERROR;
            }
            break;
        case LEX_MATCH_THIRD_WORD:
            (*route_ctx)->type = SHD_ROUTE_BY_NULL;
            OG_RETURN_IFERR(lex_fetch(lex, &word));
            if (word.type != WORD_TYPE_EOF) {
                OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
                return OG_ERROR;
            }
            break;
        default:
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_route(sql_stmt_t *stmt)
{
    OG_LOG_DEBUG_INF("Begin direct route");

    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        sql_context_t *ogx = stmt->context;

        sql_route_t **route_ctx = (sql_route_t **)&(ogx->entry);

        OG_RETURN_IFERR(sql_create_route_context(stmt, route_ctx));

        if ((*route_ctx)->type == SHD_ROUTE_BY_RULE) {
            return sql_verify_route(stmt, (sql_route_t *)stmt->context->entry);
        }

        return OG_SUCCESS;
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ROUTE is only supported at Coordinator Node.");
        return OG_ERROR;
    }
}
#endif

static status_t sql_parse_prepare_dcl(sql_stmt_t *stmt)
{
    return sql_parse_commit_phase1(stmt);
}

static status_t sql_parse_alter_dcl(sql_stmt_t *stmt)
{
    return sql_parse_dcl_alter(stmt);
}

static status_t sql_parse_commit_dcl(sql_stmt_t *stmt)
{
    return sql_parse_commit(stmt);
}

static status_t sql_parse_rollback_dcl(sql_stmt_t *stmt)
{
    return sql_parse_rollback(stmt);
}

static status_t sql_parse_savepoint_dcl(sql_stmt_t *stmt)
{
    return sql_parse_savepoint(stmt);
}

static status_t sql_parse_release_dcl(sql_stmt_t *stmt)
{
    return sql_parse_release_savepoint(stmt);
}

static status_t sql_parse_set_dcl(sql_stmt_t *stmt)
{
    return sql_parse_set(stmt);
}

static status_t sql_parse_backup_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_BACKUP;
    return sql_parse_backup(stmt);
}

static status_t sql_parse_restore_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_RESTORE;
    return sql_parse_restore(stmt);
}

static status_t sql_parse_recover_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_RECOVER;
    return sql_parse_recover(stmt);
}

static status_t sql_parse_ograc_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_OGRAC;
    return sql_parse_ograc(stmt);
}

static status_t sql_parse_shutdown_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_SHUTDOWN;
    return sql_parse_shutdown(stmt);
}

static status_t sql_parse_build_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_BUILD;
    return sql_parse_build(stmt);
}

static status_t sql_parse_repair_page_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_REPAIR_PAGE;
    return OG_SUCCESS;
}

static status_t sql_parse_repair_copyctrl_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_REPAIR_COPYCTRL;
    return OG_SUCCESS;
}

#ifdef DB_DEBUG_VERSION
static status_t sql_parse_syncpoint_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_SYNCPOINT;
    return sql_parse_syncpoint(stmt);
}
#endif

static status_t sql_parse_lock_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_LOCK_TABLE;
    return sql_parse_locktable(stmt);
}

static status_t sql_parse_checkpoint_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_CHECKPOINT;
    return lex_expected_end(stmt->session->lex);
}

static status_t sql_parse_validate_dcl(sql_stmt_t *stmt)
{
    stmt->context->type = OGSQL_TYPE_VALIDATE;
    return sql_parse_validate(stmt);
}

static status_t sql_dispatch_dcl_parse(sql_stmt_t *stmt, key_wid_t key_wid)
{
    switch (key_wid) {
        case KEY_WORD_PREPARE:
            return sql_parse_prepare_dcl(stmt);
        case KEY_WORD_ALTER:
            return sql_parse_alter_dcl(stmt);
        case KEY_WORD_COMMIT:
            return sql_parse_commit_dcl(stmt);
        case KEY_WORD_ROLLBACK:
            return sql_parse_rollback_dcl(stmt);
        case KEY_WORD_SAVEPOINT:
            return sql_parse_savepoint_dcl(stmt);
        case KEY_WORD_RELEASE:
            return sql_parse_release_dcl(stmt);
        case KEY_WORD_SET:
            return sql_parse_set_dcl(stmt);
        case KEY_WORD_BACKUP:
            return sql_parse_backup_dcl(stmt);
        case KEY_WORD_RESTORE:
            return sql_parse_restore_dcl(stmt);
        case KEY_WORD_RECOVER:
            return sql_parse_recover_dcl(stmt);
        case KEY_WORD_OGRAC:
            return sql_parse_ograc_dcl(stmt);
        case KEY_WORD_SHUTDOWN:
            return sql_parse_shutdown_dcl(stmt);
        case KEY_WORD_BUILD:
            return sql_parse_build_dcl(stmt);
        case KEY_WORD_REPAIR_PAGE:
            return sql_parse_repair_page_dcl(stmt);
        case KEY_WORD_REPAIR_COPYCTRL:
            return sql_parse_repair_copyctrl_dcl(stmt);
#ifdef DB_DEBUG_VERSION
        case KEY_WORD_SYNCPOINT:
            return sql_parse_syncpoint_dcl(stmt);
#endif
        case KEY_WORD_LOCK:
            return sql_parse_lock_dcl(stmt);
        case KEY_WORD_CHECKPOINT:
            return sql_parse_checkpoint_dcl(stmt);
        case KEY_WORD_VALIDATE:
            return sql_parse_validate_dcl(stmt);
        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected");
            return OG_ERROR;
    }
}

status_t sql_parse_dcl(sql_stmt_t *stmt, word_t *leader_word)
{
    status_t status;
    key_wid_t key_wid = leader_word->id;

    stmt->session->sql_audit.audit_type = SQL_AUDIT_DCL;
    status = sql_alloc_context(stmt);
    OG_RETURN_IFERR(status);

    return sql_dispatch_dcl_parse(stmt, key_wid);
}

#ifdef __cplusplus
}
#endif