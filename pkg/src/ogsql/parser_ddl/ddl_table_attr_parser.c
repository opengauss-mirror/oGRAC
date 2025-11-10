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
 * ddl_table_attr_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_table_attr_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_table_attr_parser.h"
#include "ddl_partition_parser.h"
#include "ddl_parser_common.h"

status_t sql_parse_row_format(lex_t *lex, word_t *word, bool8 *csf)
{
    uint32 match_id;
    if (*csf != OG_INVALID_ID8) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return OG_ERROR;
    }

    if (lex_expected_fetch_1of2(lex, "CSF", "ASF", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    *csf = (match_id == 0) ? OG_TRUE : OG_FALSE;

    return OG_SUCCESS;
}

static inline status_t sql_check_sysid(word_t *word, int32 sysid)
{
    if (sysid <= 0 || sysid >= OG_EX_SYSID_END || (sysid >= OG_RESERVED_SYSID && sysid < OG_EX_SYSID_START)) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "%s must between 1 and %d or %d and %d ", W2S(word),
            OG_RESERVED_SYSID, OG_EX_SYSID_START, OG_EX_SYSID_END);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_sysid(lex_t *lex, word_t *word, uint32 *id)
{
    int32 tmp_id;
    if (*id != OG_INVALID_ID32) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate %s specification", W2S(word));
        return OG_ERROR;
    }

    if (lex_expected_fetch_int32(lex, &tmp_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_check_sysid(word, tmp_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    *id = (uint32)tmp_id;
    return OG_SUCCESS;
}


static status_t sql_parse_lob_inrow(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch_word(lex, "STORAGE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "IN") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_expected_fetch_word(lex, "ROW");
}

static status_t sql_parse_lob_parameter(sql_stmt_t *stmt, lex_t *lex, knl_lobstor_def_t *def, word_t *word)
{
    bool32 result = OG_FALSE;
    status_t status = OG_SUCCESS;

    def->in_row = OG_TRUE;
    if (lex_try_fetch_bracket(lex, word, &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result || word->type == WORD_TYPE_EOF) {
        def->in_row = OG_TRUE;
        def->space.len = 0;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    if (lex_fetch(lex, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "A LOB storage option was not specified");
        lex_pop(lex);
        return OG_ERROR;
    }

    for (;;) {
        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &def->space);
                break;
            case KEY_WORD_ENABLE:
            case KEY_WORD_DISABLE:
                def->in_row = (word->id == KEY_WORD_ENABLE);
                status = sql_parse_lob_inrow(lex, word);
                break;
            default:
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
                status = OG_ERROR;
                break;
        }

        if (lex_fetch(lex, word) != OG_SUCCESS) {
            status = OG_ERROR;
            break;
        }

        if (word->type == WORD_TYPE_EOF) {
            break;
        }
    }

    lex_pop(lex);

    return status;
}

status_t sql_parse_lob_store(sql_stmt_t *stmt, lex_t *lex, word_t *word, galist_t *defs)
{
    status_t status;
    bool32 result = OG_FALSE;
    knl_lobstor_def_t *def = NULL;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        status = lex_expected_fetch_variant(lex, word);
        OG_BREAK_IF_ERROR(status);

        // check duplicate column
        for (uint32 i = 0; i < defs->count; i++) {
            def = (knl_lobstor_def_t *)cm_galist_get(defs, i);
            if (cm_text_equal_ins(&def->col_name, &word->text.value)) {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate lob storage option specificed");
                status = OG_ERROR;
                break;
            }
        }
        OG_BREAK_IF_ERROR(status);

        status = cm_galist_new(defs, sizeof(knl_lobstor_def_t), (pointer_t *)&def);
        OG_BREAK_IF_ERROR(status);

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->col_name);
        OG_BREAK_IF_ERROR(status);

        status = lex_fetch(lex, word);
        OG_BREAK_IF_ERROR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "\",\" expected but %s found", W2S(word));
            status = OG_ERROR;
            break;
        }
    }

    lex_pop(lex);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "STORE"));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "AS"));
    OG_RETURN_IFERR(lex_try_fetch_variant(lex, word, &result));

    if (result) {
        OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->seg_name));
    } else {
        def->seg_name.len = 0;
        def->seg_name.str = NULL;
    }

    return sql_parse_lob_parameter(stmt, lex, def, word);
}


static status_t sql_parse_external_type(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;
    bool32 result = OG_FALSE;
    status_t status;

    status = lex_try_fetch(lex, "type", &result);
    OG_RETURN_IFERR(status);

    if (result) {
        status = lex_expected_fetch(lex, &word);
        OG_RETURN_IFERR(status);

        if (cm_text_str_equal_ins((text_t *)&word.text, "loader")) {
            def->external_type = LOADER;
        } else if (cm_text_str_equal_ins((text_t *)&word.text, "datapump")) {
            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datapump external table");
            return OG_ERROR;
        } else {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "external type error, expect(loader/datapump) but found %s", W2S(&word));
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_external_directory(sql_stmt_t *stmt, lex_t *lex, knl_ext_def_t *def)
{
    word_t word;
    status_t status;

    status = lex_expected_fetch_word(lex, "directory");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    OG_RETURN_IFERR(status);

    return sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->directory);
}

static status_t sql_parse_records_delimiter(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;

    if (lex_expected_fetch_word(lex, "records") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "delimited") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "by") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_text_str_equal_ins((text_t *)&word.text, "newline")) {
        def->records_delimiter = '\n';
    } else {
        LEX_REMOVE_WRAP(&word);
        if (word.text.len != 1) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "only single character is supported for records delimiter");
            return OG_ERROR;
        }

        def->records_delimiter = word.text.str[0];
    }

    return OG_SUCCESS;
}

static status_t sql_parse_fields_delimiter(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;

    if (lex_expected_fetch_word(lex, "fields") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "terminated") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "by") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_string(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.text.len != 1) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
            "only single character is supported for fields delimiter");
        return OG_ERROR;
    }
    def->fields_terminator = word.text.str[0];
    return OG_SUCCESS;
}

/*
optional access parameters for "LOADER":
access parameters( records delimited by newline
fields terminated by ',')
*/
static status_t sql_parse_external_params(lex_t *lex, knl_ext_def_t *def)
{
    word_t word;
    bool32 result = OG_FALSE;
    status_t status;

    if (lex_try_fetch(lex, "access", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        status = lex_expected_fetch_word(lex, "parameters");
        OG_RETURN_IFERR(status);

        status = lex_expected_fetch_bracket(lex, &word);
        OG_RETURN_IFERR(status);

        OG_RETURN_IFERR(lex_push(lex, &word.text));

        if (sql_parse_records_delimiter(lex, def) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        if (sql_parse_fields_delimiter(lex, def) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (lex_fetch(lex, &word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (word.type != WORD_TYPE_EOF) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected string %s found", W2S(&word));
            lex_pop(lex);
            return OG_ERROR;
        }

        if (def->fields_terminator == def->records_delimiter) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the records delimiter must different from fields delimiter");
            lex_pop(lex);
            return OG_ERROR;
        }

        lex_pop(lex);
    }

    return OG_SUCCESS;
}

static status_t sql_parse_external_location(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_ext_def_t *def)
{
    if (lex_expected_fetch_word(lex, "location") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

#ifdef WIN32
    if (cm_strstri(word->text.str, "..\\") != NULL || cm_strstri(word->text.str, ".\\") != NULL) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "File name cannot contain a path specification: ..\\ or .\\");
        return OG_ERROR;
    }
#else
    if (cm_strstri(word->text.str, "../") != NULL || cm_strstri(word->text.str, "./") != NULL) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "File name cannot contain a path specification: ../ or ./");
        return OG_ERROR;
    }
#endif

    return sql_copy_text(stmt->context, (text_t *)&word->text, &def->location);
}

status_t sql_check_organization_column(knl_table_def_t *def)
{
    uint16 col_count;
    knl_column_def_t *col_def = NULL;

    for (col_count = 0; col_count < def->columns.count; col_count++) {
        col_def = cm_galist_get(&def->columns, col_count);
        if (col_def->is_serial) {
            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify seialize column on external table");
            return OG_ERROR;
        }

        if (col_def->is_check) {
            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify check on external table column");
            return OG_ERROR;
        }

        if (col_def->is_ref) {
            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify reference for external table column");
            return OG_ERROR;
        }

        if (col_def->is_default) {
            OG_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "specify default value for external table column");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_organization(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_ext_def_t *def)
{
    status_t status;

    def->external_type = LOADER;
    def->fields_terminator = ',';
    def->records_delimiter = '\n';

    status = lex_expected_fetch_word(lex, "external");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_bracket(lex, word);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    if (sql_parse_external_type(lex, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_parse_external_directory(stmt, lex, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (def->external_type == LOADER) {
        if (sql_parse_external_params(lex, def) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
    }

    if (sql_parse_external_location(stmt, lex, word, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected string %s found", W2S(word));
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected string %s found", W2S(word));
        return OG_ERROR;
    }

    return status;
}

static status_t sql_parse_temp_table(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_table_def_t *def)
{
    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_COMMIT) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "COMMIT expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id == KEY_WORD_DELETE) {
        def->type = TABLE_TYPE_TRANS_TEMP;
    } else if (word->id == KEY_WORD_PRESERVE) {
        def->type = TABLE_TYPE_SESSION_TEMP;
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "DELETE/PRESERVE expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_ROWS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ROWS expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (IS_LTT_BY_NAME(def->name.str) && def->type == TABLE_TYPE_TRANS_TEMP) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "local temporary table don't support on commit delete rows");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}


status_t sql_parse_appendonly(lex_t *lex, word_t *word, bool32 *appendonly)
{
    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!(word->id == KEY_WORD_ON || word->id == KEY_WORD_OFF)) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but %s found", W2S(word));
        return OG_ERROR;
    }

    *appendonly = (word->id == KEY_WORD_ON) ? OG_TRUE : OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_parse_check_auto_increment(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    sql_table_entry_t *table = NULL;
    sql_context_t *context = stmt->context;
    table = (sql_table_entry_t *)cm_galist_get(context->tables, 0);
    dc_entity_t *entity = DC_ENTITY(&table->dc);
    if (!entity->has_serial_col) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "AUTO INCREMENT is not allowed setting");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_parse_init_auto_increment(sql_stmt_t *stmt, lex_t *lex, int64 *serial_start)
{
    bool32 result = OG_FALSE;
    if (lex_try_fetch(lex, "=", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_expected_fetch_size(lex, serial_start, 0, OG_INVALID_INT64);
}

status_t sql_parse_charset(sql_stmt_t *stmt, lex_t *lex, uint8 *charset)
{
    word_t word;
    bool32 result = OG_FALSE;
    uint16 charset_id;

    if (lex_try_fetch(lex, "SET", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_try_fetch(lex, "=", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    charset_id = cm_get_charset_id_ex(&word.text.value);
    if (charset_id == OG_INVALID_ID16) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown charset option %s", T2S(&word.text.value));
        return OG_ERROR;
    }

    *charset = (uint8)charset_id;
    return OG_SUCCESS;
}

status_t sql_parse_collate(sql_stmt_t *stmt, lex_t *lex, uint8 *collate)
{
    word_t word;
    bool32 result = OG_FALSE;
    uint16 collate_id;

    if (lex_try_fetch(lex, "=", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    collate_id = cm_get_collation_id(&word.text.value);
    if (collate_id == OG_INVALID_ID16) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown collation option %s",
            T2S(&word.text.value));
        return OG_ERROR;
    }

    *collate = (uint8)collate_id;
    return OG_SUCCESS;
}

status_t sql_parse_table_compress(sql_stmt_t *stmt, lex_t *lex, uint8 *type, uint8 *algo)
{
    bool32 result = OG_FALSE;
    uint32 matched_id;
    if (lex_try_fetch(lex, "for", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        *type = COMPRESS_TYPE_GENERAL;
        if (*algo > COMPRESS_NONE) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "duplicate compress specification");
            return OG_ERROR;
        }
        *algo = COMPRESS_ZSTD;
        return OG_SUCCESS;
    }

    if (OG_SUCCESS != lex_expected_fetch_1of2(lex, "ALL", "DIRECT_LOAD", &matched_id)) {
        return OG_ERROR;
    }
    if (matched_id == LEX_MATCH_FIRST_WORD) {
        *type = COMPRESS_TYPE_ALL;
    } else {
        *type = COMPRESS_TYPE_DIRECT_LOAD;
    }

    return lex_expected_fetch_word(lex, "operations");
}

status_t sql_parse_coalesce_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    if (lex_expected_fetch_word(lex, "PARTITION") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_set_table_attrs(sql_stmt_t *stmt, knl_table_def_t *def)
{
    if (def->initrans == 0) {
        def->initrans = cm_text_str_equal_ins(&def->schema, "SYS") ? OG_INI_TRANS :
                                                                     stmt->session->knl_session.kernel->attr.initrans;
    }

    if (def->pctfree == OG_INVALID_ID32) {
        def->pctfree = OG_PCT_FREE;
    }

    if (def->cr_mode == OG_INVALID_ID8) {
        def->cr_mode = stmt->session->knl_session.kernel->attr.cr_mode;
    }

    if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
        if (def->csf == ROW_FORMAT_CSF) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " not support csf for current table type.");
            return OG_ERROR;
        }
    }

    if (def->sysid != OG_INVALID_ID32 || def->csf == OG_INVALID_ID8) {
        def->csf = OG_FALSE;
        if (def->type == TABLE_TYPE_HEAP || def->type == TABLE_TYPE_NOLOGGING) {
            def->csf = (stmt->session->knl_session.kernel->attr.row_format == ROW_FORMAT_CSF);
        }
    }
    return OG_SUCCESS;
}

bool32 sql_default_dist_check_uq_outline(knl_table_def_t *def)
{
    knl_constraint_def_t *cons = NULL;
    bool32 single_uq = OG_FALSE;

    for (uint32 i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type != CONS_TYPE_UNIQUE) {
            continue;
        }
        if (single_uq) {
            return OG_FALSE;
        }
        single_uq = OG_TRUE;
    }
    return OG_TRUE;
}

static status_t sql_default_dist_check_uq_inline(knl_table_def_t *def)
{
    knl_column_def_t *column = NULL;
    bool32 single_uq = OG_FALSE;
    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (!column->unique) {
            continue;
        }
        if (single_uq) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
            return OG_ERROR;
        }
        single_uq = OG_TRUE;
    }
    return OG_SUCCESS;
}

static bool32 sql_check_pk_with_uq_outline(knl_table_def_t *def, text_t *col_name)
{
    knl_constraint_def_t *cons = NULL;
    knl_index_col_def_t *index_col = NULL;

    for (uint32 i = 0; i < def->constraints.count; i++) {
        cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        if (cons->type != CONS_TYPE_UNIQUE) {
            continue;
        }
        for (uint32 j = 0; j < cons->columns.count; j++) {
            index_col = (knl_index_col_def_t *)cm_galist_get(&cons->columns, j);
            if (cm_text_equal(col_name, &index_col->name)) {
                break;
            }
            if (j == cons->columns.count - 1) {
                return OG_FALSE;
            }
        }
    }
    return OG_TRUE;
}

status_t sql_default_dist_pk_with_uq_outline(knl_table_def_t *def, knl_constraint_def_t *pk_cons, sql_text_t *dist_info,
    bool32 *is_find)
{
    knl_index_col_def_t *pk_col = NULL;
    errno_t err;

    for (uint32 i = 0; i < pk_cons->columns.count; i++) {
        pk_col = (knl_index_col_def_t *)cm_galist_get(&pk_cons->columns, i);
        if (sql_check_pk_with_uq_outline(def, &pk_col->name) == OG_TRUE) {
            err = snprintf_s(dist_info->str + dist_info->len, OG_MAX_NAME_LEN + 1, OG_MAX_NAME_LEN, "%s",
                T2S(&pk_col->name));
            PRTS_RETURN_IFERR(err);
            dist_info->len += err;

            *is_find = OG_TRUE;
            return OG_SUCCESS;
        }
    }
    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
    return OG_ERROR;
}

status_t sql_default_dist_pk_with_uq_inline(knl_table_def_t *def, knl_constraint_def_t *cons, sql_text_t *dist_info,
    bool32 *is_find)
{
    knl_column_def_t *column = NULL;
    knl_index_col_def_t *index_col = NULL;
    errno_t err;

    OG_RETURN_IFERR(sql_default_dist_check_uq_inline(def));

    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (!column->unique) {
            continue;
        }
        for (uint32 j = 0; j < cons->columns.count; j++) {
            index_col = (knl_index_col_def_t *)cm_galist_get(&cons->columns, j);
            if (cm_text_equal(&column->name, &index_col->name)) {
                if (sql_check_pk_with_uq_outline(def, &column->name) == OG_FALSE) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
                    return OG_ERROR;
                }
                err = snprintf_s(dist_info->str + dist_info->len, OG_MAX_NAME_LEN + 1, OG_MAX_NAME_LEN, "%s",
                    T2S(&column->name));
                PRTS_RETURN_IFERR(err);
                dist_info->len += err;

                *is_find = OG_TRUE;
                return OG_SUCCESS;
            }
        }
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_default_dist_pk_inline(knl_table_def_t *def, sql_text_t *dist_info, bool32 *is_find)
{
    knl_column_def_t *column = NULL;
    errno_t err;
    if (def->uq_inline) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
        return OG_ERROR;
    }

    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (!column->primary) {
            continue;
        }

        if (sql_check_pk_with_uq_outline(def, &column->name) == OG_FALSE) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Calculating default distribute column failed");
            return OG_ERROR;
        }
        err =
            snprintf_s(dist_info->str + dist_info->len, OG_MAX_NAME_LEN + 1, OG_MAX_NAME_LEN, "%s", T2S(&column->name));
        PRTS_RETURN_IFERR(err);
        dist_info->len += err;

        *is_find = OG_TRUE;
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

bool32 sql_check_uq_not_null(knl_table_def_t *def, text_t *col_name)
{
    knl_column_def_t *column = NULL;
    const text_t null_text = {
        .str = "null",
        .len = (uint32)strlen("null")
    };

    for (uint32 i = 0; i < def->columns.count; i++) {
        column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (cm_text_equal(col_name, &column->name)) {
            if ((column->nullable && !column->is_default) ||
                cm_compare_text_ins(&column->default_text, &null_text) == 0) {
                return OG_FALSE;
            }
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

status_t sql_parse_table_attrs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *table_def,
                               bool32 *expect_as, word_t *word)
{
    status_t status = OG_ERROR;
    uint32 matched_id;
    uint32 ex_flags = 0;
    uint8 algo = COMPRESS_NONE;
    uint8 type = COMPRESS_TYPE_NO;

    table_def->cr_mode = OG_INVALID_ID8;
    table_def->pctfree = OG_INVALID_ID32;
    table_def->csf = OG_INVALID_ID8;

    for (;;) {
        status = lex_fetch(lex, word);
        OG_RETURN_IFERR(status);
        if (word->type == WORD_TYPE_EOF || word->id == KEY_WORD_AS) {
            break;
        }

        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &table_def->space);
                break;

            case KEY_WORD_INITRANS:
                status = sql_parse_trans(lex, word, &table_def->initrans);
                break;

            case KEY_WORD_MAXTRANS:
                status = sql_parse_trans(lex, word, &table_def->maxtrans);
                break;

            case KEY_WORD_PCTFREE:
                status = sql_parse_pctfree(lex, word, &table_def->pctfree);
                break;

            case KEY_WORD_CRMODE:
                status = sql_parse_crmode(lex, word, &table_def->cr_mode);
                if ((table_def->type == TABLE_TYPE_SESSION_TEMP || table_def->type == TABLE_TYPE_TRANS_TEMP)
                    && table_def->cr_mode == CR_PAGE) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                        "Temporary tables do not support page CR_MODE");
                    return OG_ERROR;
                }
                break;

            case KEY_WORD_FORMAT:
                status = sql_parse_row_format(lex, word, &table_def->csf);
                break;

            case KEY_WORD_SYSTEM:
                status = sql_parse_sysid(lex, word, &table_def->sysid);
                break;

            case KEY_WORD_STORAGE:
                status = sql_parse_storage(lex, word, &table_def->storage_def, OG_FALSE);
                break;

            case KEY_WORD_LOB:
                if (table_def->type == TABLE_TYPE_SESSION_TEMP || table_def->type == TABLE_TYPE_TRANS_TEMP) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "Temporary tables do not support LOB clauses");
                    return OG_ERROR;
                }
                status = sql_parse_lob_store(stmt, lex, word, &table_def->lob_stores);
                break;

            case KEY_WORD_ON:
                if (table_def->type == TABLE_TYPE_HEAP) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ON COMMIT only used on temporary table");
                    return OG_ERROR;
                }
                if (ex_flags & TEMP_TBL_ATTR_PARSED) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "too many option for table");
                    return OG_ERROR;
                }
                status = sql_parse_temp_table(stmt, lex, word, table_def);
                ex_flags |= TEMP_TBL_ATTR_PARSED;
                break;
            case KEY_WORD_APPENDONLY:
                status = sql_parse_appendonly(lex, word, &table_def->appendonly);
                break;
            case KEY_WORD_PARTITION:
                status = sql_part_parse_table(stmt, word, expect_as, table_def);
                break;
            case KEY_WORD_AUTO_INCREMENT:
                if (ex_flags & TBLOPTS_EX_AUTO_INCREMENT) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "duplicate or conflicting auto_increment specifications");
                    return OG_ERROR;
                }
                status = sql_parse_init_auto_increment(stmt, lex, (int64 *)&table_def->serial_start);
                ex_flags |= TBLOPTS_EX_AUTO_INCREMENT;
                break;
            case RES_WORD_DEFAULT:
                if (OG_SUCCESS !=
                    lex_expected_fetch_1ofn(stmt->session->lex, &matched_id, 3, "CHARACTER", "CHARSET", "COLLATE")) {
                    return OG_ERROR;
                }

                if (matched_id == LEX_MATCH_FIRST_WORD || matched_id == LEX_MATCH_SECOND_WORD) {
                    status = sql_parse_charset(stmt, lex, &table_def->charset);
                } else if (matched_id == LEX_MATCH_THIRD_WORD) {
                    status = sql_parse_collate(stmt, lex, &table_def->collate);
                } else {
                    status = OG_ERROR;
                }
                break;
            case KEY_WORD_CHARSET:
            case KEY_WORD_CHARACTER:
                status = sql_parse_charset(stmt, lex, &table_def->charset);
                break;
            case KEY_WORD_COLLATE:
                status = sql_parse_collate(stmt, lex, &table_def->collate);
                break;
            case KEY_WORD_CACHE:
            case KEY_WORD_NO_CACHE:
                break;
            case KEY_WORD_LOGGING:
                break;
            case KEY_WORD_NO_LOGGING:
                if (table_def->type == TABLE_TYPE_TRANS_TEMP || table_def->type == TABLE_TYPE_SESSION_TEMP) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "cannot sepecify NOLOGGING on temporary table");
                    status = OG_ERROR;
                } else if (table_def->compress_algo > COMPRESS_NONE) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "unexpected text %s, table compress only supported on (part)table", W2S(word));
                    status = OG_ERROR;
                } else {
                    table_def->type = TABLE_TYPE_NOLOGGING;
                }
                break;
            case KEY_WORD_COMPRESS:
                // ordinary table and partition table support compress, but sub partition table don't support.
                if (table_def->type == TABLE_TYPE_HEAP) {
                    status = sql_parse_table_compress(stmt, lex, &type, &algo);
                    table_def->compress_type = type;
                    table_def->compress_algo = algo;
                    break;
                }
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "unexpected text %s, table compress only supported on (part)table", W2S(word));
                return OG_ERROR;

            case KEY_WORD_NO_COMPRESS:
                table_def->compress_type = COMPRESS_TYPE_NO;
                break;

            default:
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
                return OG_ERROR;
        }

        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    OG_RETURN_IFERR(sql_set_table_attrs(stmt, table_def));

    return OG_SUCCESS;
}
