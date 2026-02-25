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
 * ddl_space_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_space_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_space_parser.h"
#include "scanner.h"
#include "srv_instance.h"


status_t sql_parse_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *space)
{
    if (space->len != 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate tablespace specification");
        return OG_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &(*space));
}

static inline status_t sql_parse_space_all_inmem(lex_t *lex, knl_space_def_t *def, word_t *word)
{
    /* got "ALL", move to the next */
    OG_RETURN_IFERR(lex_fetch(lex, word));
    if (word->id == KEY_WORD_IN) {
        /* got "ALL IN", move to the next */
        OG_RETURN_IFERR(lex_fetch(lex, word));
        if (word->id == KEY_WORD_MEMORY) {
            /*
             * got "ALL IN MEMORY", assign the "in_memory" property,
             * and move to the next word to take out of this function
             */
            def->in_memory = OG_TRUE;
            OG_RETURN_IFERR(lex_fetch(lex, word));
        }
    }

    return OG_SUCCESS;
}


static status_t sql_parse_extent_clause_core(sql_stmt_t *stmt, knl_space_def_t *def, word_t *next_word)
{
    lex_t *lex = stmt->session->lex;

    if (def->extent_size != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid extent clause");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_expected_fetch(lex, next_word));
    if (next_word->id == KEY_WORD_AUTOALLOCATE) {
        def->autoallocate = OG_TRUE;
        def->extent_size = OG_MIN_EXTENT_SIZE;
    } else {
        OG_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR, "AUTOALLOCATE expected but \"%s\" found.",
            (*(W2S(next_word)) == '\0' ? "emtpy string" : W2S(next_word)));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_fetch(lex, next_word));
    return OG_SUCCESS;
}

static status_t sql_parse_autooffline_clause_core(sql_stmt_t *stmt, bool32 *autooffline, word_t *next_word)
{
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch(lex, next_word));
    if (next_word->type != WORD_TYPE_KEYWORD) {
        OG_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(next_word)) == '\0' ? "emtpy string" : W2S(next_word)));
        return OG_ERROR;
    }

    if (next_word->id == KEY_WORD_OFF) {
        *autooffline = OG_FALSE;
    } else if (next_word->id == KEY_WORD_ON) {
        *autooffline = OG_TRUE;
    } else {
        OG_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(next_word)) == '\0' ? "emtpy string" : W2S(next_word)));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(lex_fetch(lex, next_word));

    return OG_SUCCESS;
}

static status_t sql_parse_space_attr(sql_stmt_t *stmt, lex_t *lex, knl_space_def_t *def, word_t *word)
{
    bool32 parsed_offline = OG_FALSE;
    bool32 parsed_all = OG_FALSE;
    bool32 parsed_nologging = OG_FALSE;
    bool32 parsed_extent = OG_FALSE;
    def->in_memory = OG_FALSE;

    while (word->type == WORD_TYPE_KEYWORD) {
        switch ((key_wid_t)word->id) {
            case KEY_WORD_ALL:
                if ((def->type & SPACE_TYPE_TEMP) || parsed_all) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return OG_ERROR;
                }

                OG_RETURN_IFERR(sql_parse_space_all_inmem(lex, def, word));

                parsed_all = OG_TRUE;
                break;
            case KEY_WORD_NO_LOGGING:
                if (def->in_memory || parsed_nologging) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return OG_ERROR;
                }

                def->type |= SPACE_TYPE_TEMP;
                OG_RETURN_IFERR(lex_fetch(lex, word));
                parsed_nologging = OG_TRUE;
                break;
            case KEY_WORD_ENCRYPTION:
                if (def->in_memory) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return OG_ERROR;
                }
                OG_THROW_ERROR_EX(ERR_INVALID_OPERATION, "unsupport encrypt space");
                def->encrypt = OG_TRUE;
                OG_RETURN_IFERR(lex_fetch(lex, word));
                break;
            case KEY_WORD_AUTOOFFLINE:
                if (parsed_offline) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return OG_ERROR;
                }

                OG_RETURN_IFERR(sql_parse_autooffline_clause_core(stmt, &def->autooffline, word));

                parsed_offline = OG_TRUE;
                break;
            case KEY_WORD_EXTENT:
                if (parsed_extent) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
                    return OG_ERROR;
                }

                OG_RETURN_IFERR(sql_parse_extent_clause_core(stmt, def, word));

                def->bitmapmanaged = OG_TRUE;
                parsed_extent = OG_TRUE;
                break;
            default:
                OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(word));
                return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_auto_extend_on(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def)
{
    bool32 next_sized = OG_FALSE;
    bool32 max_sized = OG_FALSE;
    bool32 max_ulimited = OG_FALSE;
    int64 tmp_next_size = 0;
    int64 tmp_max_size = 0;
    lex_t *lex = stmt->session->lex;

    uint32 page_size = 0;
    autoextend_def->enabled = OG_TRUE;

    /* check if next clause exists */
    OG_RETURN_IFERR(lex_try_fetch(lex, "NEXT", &next_sized));
    if (next_sized == OG_TRUE) {
        OG_RETURN_IFERR(
            lex_expected_fetch_size(lex, (int64 *)(&tmp_next_size), OG_MIN_AUTOEXTEND_SIZE, OG_INVALID_INT64));
    } else {
        /* "NEXTSIZE" not specified, set 0, and knl_datafile will init this value by DEFALUD VAULE */
        tmp_next_size = 0;
    }

    /* check if maxsize clause exists */
    OG_RETURN_IFERR(knl_get_page_size(KNL_SESSION(stmt), &page_size));
    OG_RETURN_IFERR(lex_try_fetch(lex, "MAXSIZE", &max_sized));
    if (max_sized == OG_TRUE) {
        OG_RETURN_IFERR(lex_try_fetch(lex, "UNLIMITED", &max_ulimited));
        if (max_ulimited != OG_TRUE) {
            OG_RETURN_IFERR(
                lex_expected_fetch_size(lex, (int64 *)(&tmp_max_size), OG_MIN_AUTOEXTEND_SIZE, OG_INVALID_INT64));
            if (tmp_max_size > ((int64)OG_MAX_DATAFILE_PAGES * page_size)) {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                    "\"MAXSIZE\" specified in autoextend clause cannot "
                    "be greater than %lld. \"MAXSIZE\": %lld",
                    ((int64)OG_MAX_DATAFILE_PAGES * page_size), tmp_max_size);
                return OG_ERROR;
            }
        } else {
            tmp_max_size = 0;
        }
    } else {
        /* "MAXSIZE" not specified, take (OG_MAX_DATAFILE_PAGES * page_size) as the default value */
        tmp_max_size = 0;
    }

    if ((tmp_max_size > 0) && (tmp_next_size > tmp_max_size)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "\"NEXT\" size specified in autoextend clause cannot be "
            "greater than the \"MAX\" size. \"Next\" size is %lld, \"MAX\" size is %lld",
            tmp_next_size, tmp_max_size);
        return OG_ERROR;
    }

    /* assign the parsed size value respectively */
    autoextend_def->nextsize = tmp_next_size;
    autoextend_def->maxsize = tmp_max_size;

    return OG_SUCCESS;
}

/*
 * the common routine for parsing auto-extend clause (keyword "AUTOEXTEND" excluded)
 * auto-extend clause (excluding "AUTOEXTEND") means:
 * { OFF | ON [ NEXT size_clause] [ MAXSIZE { UNLIMITED | size_clause }] }
 *
 * @Note:
 * 1. when "ON" specified but "NEXT" size not specified, take 16MB as the default "NEXT" size
 * 2. when "ON" specified but "MAXSIZE" size not specified, take the de-facto maxsize(*) as the default "MAXSIZE"
 * the de-facto maxsize is max_pages(4194303 pages per datafile) * length of page(8KB)
 * 3. if "ON" specified, even "MAXSIZE UNLIMITED" specified, the de-facto value of "MAXSIZE" is
 * max_pages(4194303 pages per datafile) * length of page(8KB)
 * 4. if "OFF" specified, do not use the "nextsize" and "maxsize" of the argument "autoextend_def"
 */
status_t sql_parse_autoextend_clause_core(device_type_t type, sql_stmt_t *stmt, knl_autoextend_def_t *autoextend_def,
    word_t *next_word)
{
    CM_POINTER3(stmt, autoextend_def, next_word);
    word_t word;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));
    if (word.type != WORD_TYPE_KEYWORD) {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(&word)) == '\0' ? "emtpy string" : W2S(&word)));
        return OG_ERROR;
    }

    if (word.id == KEY_WORD_OFF) {
        autoextend_def->enabled = OG_FALSE;
    } else if (word.id == KEY_WORD_ON) {
        OG_RETURN_IFERR(sql_parse_auto_extend_on(type, stmt, autoextend_def));
    } else {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but \"%s\" found.",
            (*(W2S(&word)) == '\0' ? "emtpy string" : W2S(&word)));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_fetch(lex, next_word));

    return OG_SUCCESS;
}


status_t sql_parse_datafile(sql_stmt_t *stmt, knl_device_def_t *dev_def, word_t *word, bool32 *isRelative)
{
    status_t status;
    lex_t *lex = stmt->session->lex;
    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
    bool32 reuse_specified = OG_FALSE;

    status = lex_expected_fetch_string(lex, word);
    OG_RETURN_IFERR(status);

    if (word->text.str[0] != '/') {
        *isRelative = OG_TRUE;
    }

    status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name);
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_word(lex, "SIZE");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_size(lex, &dev_def->size, OG_MIN_USER_DATAFILE_SIZE, max_filesize);
    OG_RETURN_IFERR(status);

    device_type_t type = cm_device_type(dev_def->name.str);

    OG_RETURN_IFERR(lex_try_fetch(lex, "REUSE", &reuse_specified));
    if (reuse_specified == OG_TRUE) {
        /* support "REUSE" only for the syntax compatibility */
        OG_LOG_RUN_WAR("\"REUSE\" specified in statement \"%s\", but it will not take effect.",
            T2S(&(lex->text.value)));
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "COMPRESS", &dev_def->compress));
    
    // not allowed COMPRESS datafile for now
    if (dev_def->compress) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                              "not allowed build compress datafile in cluster mode");
        return OG_ERROR;
    }

    /*
     * read the next word.
     * if it is "AUTOEXTEND", start to parse the auto-extend clause
     * if not, take the word out of the function and let the caller to judge
     */
    status = lex_fetch(lex, word);
    OG_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_KEYWORD && word->id == KEY_WORD_AUTOEXTEND) {
        OG_RETURN_IFERR(sql_parse_autoextend_clause_core(type, stmt, &dev_def->autoextend, word));

        if (dev_def->autoextend.enabled && dev_def->autoextend.maxsize > 0 &&
            (dev_def->autoextend.maxsize < dev_def->size)) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "\"MAXSIZE\" specified in autoextend clause "
                "cannot be less than the value of \"SIZE\". \"MAXSIZE\": %lld, \"SIZE\": %lld",
                dev_def->autoextend.maxsize, dev_def->size);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}


static status_t sql_parse_datafile_spec(sql_stmt_t *stmt, lex_t *lex, knl_space_def_t *def, word_t *word,
    bool32 *isRelative)
{
    status_t status;
    knl_device_def_t *dev_def = NULL;

    while (1) {
        uint32 i;
        knl_device_def_t *cur = NULL;

        status = cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def);
        OG_RETURN_IFERR(status);

        status = sql_parse_datafile(stmt, dev_def, word, isRelative);
        OG_RETURN_IFERR(status);

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < def->datafiles.count; i++) {
            cur = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                        "it is not allowed to specify duplicate datafile");
                    return OG_ERROR;
                }
            }
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_create_space(sql_stmt_t *stmt, bool32 is_temp, bool32 is_undo)
{
    knl_space_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    word_t word;
    status_t status;
    bool32 result = OG_FALSE;
    bool32 isRelative = OG_FALSE;
    int64 size;

    status = sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (void **)&def);
    OG_RETURN_IFERR(status);

    stmt->context->entry = def;
    stmt->context->type = OGSQL_TYPE_CREATE_TABLESPACE;
    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);

    if (is_undo) {
        def->type = SPACE_TYPE_UNDO;
    } else {
        def->type = SPACE_TYPE_USERS;
    }

    if (is_temp) {
        def->type |= SPACE_TYPE_TEMP;
    }

    def->in_shard = OG_FALSE;
    def->autoallocate = OG_FALSE;
    def->bitmapmanaged = OG_FALSE;

    status = lex_expected_fetch_variant(lex, &word);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name));

    if (lex_try_fetch(lex, "EXTENTS", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        if (def->type & SPACE_TYPE_UNDO) {
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace using extents option");
            return OG_ERROR;
        }

        if (lex_expected_fetch_size(lex, &size, OG_MIN_EXTENT_SIZE, OG_MAX_EXTENT_SIZE) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (((uint64)size & ((uint64)size - 1)) != 0) {
            OG_THROW_ERROR(ERR_INVALID_PARAMETER, "EXTENTS");
            return OG_ERROR;
        }
        def->extent_size = (int32)size;
    } else {
        if (stmt->session->knl_session.kernel->attr.default_space_type == SPACE_BITMAP) {
            def->autoallocate = OG_TRUE;
            def->bitmapmanaged = OG_TRUE;
        }
    }

    if (is_temp) {
        status = lex_expected_fetch_word(lex, "TEMPFILE");
        OG_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_word(lex, "DATAFILE");
        OG_RETURN_IFERR(status);
    }

    status = sql_parse_datafile_spec(stmt, lex, def, &word, &isRelative);
    OG_RETURN_IFERR(status);

    status = sql_parse_space_attr(stmt, lex, def, &word);
    OG_RETURN_IFERR(status);

    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}


status_t sql_parse_create_undo_space(sql_stmt_t *stmt)
{
    lex_t *lex = stmt->session->lex;
    status_t status;

    status = lex_expected_fetch_word(lex, "tablespace");
    OG_RETURN_IFERR(status);

    status = sql_parse_create_space(stmt, OG_FALSE, OG_TRUE);

    return status;
}


static status_t sql_parse_datafile_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    knl_device_def_t *dev_def = NULL;
    bool32 isRelative = OG_FALSE;

    def->action = ALTSPACE_ADD_DATAFILE;

    if (lex_expected_fetch_word(lex, "DATAFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (1) {
        uint32 i;
        knl_device_def_t *cur = NULL;

        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_parse_datafile(stmt, dev_def, word, &isRelative) != OG_SUCCESS) {
            return OG_ERROR;
        }

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < def->datafiles.count; i++) {
            cur = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                    return OG_ERROR;
                }
            }
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    return OG_SUCCESS;
}


static status_t sql_parse_drop_datafile(sql_stmt_t *stmt, lex_t *lex, knl_device_def_t *dev_def, word_t *word)
{
    if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_drop_datafile_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    knl_device_def_t *dev_def = NULL;

    def->action = ALTSPACE_DROP_DATAFILE;

    if (lex_expected_fetch_word(lex, "DATAFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (1) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_parse_drop_datafile(stmt, lex, dev_def, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_try_fetch_char(lex, ',', &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!result) {
            break;
        }
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}


static status_t sql_parse_autoextend_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    device_type_t type;
    def->action = ALTSPACE_SET_AUTOEXTEND;

    /*
     * the storage engine does not support auto-extend maxsize property,
     * neither does the structure of knl_altspace_def_t.
     * so the 5th~7th argument are all left NULL until the maxsize property
     * implemented in the storage engine
     */
    OG_RETURN_IFERR(knl_get_space_type(KNL_SESSION(stmt), &def->name, &type));
    OG_RETURN_IFERR(sql_parse_autoextend_clause_core(type, stmt, &def->autoextend, word));

    return OG_SUCCESS;
}


static status_t sql_parse_autooffline_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    def->action = ALTSPACE_SET_AUTOOFFLINE;

    OG_RETURN_IFERR(sql_parse_autooffline_clause_core(stmt, &def->auto_offline, word));

    return OG_SUCCESS;
}


static status_t sql_parse_datafiles_name(sql_stmt_t *stmt, galist_t *list, lex_t *lex, word_t *word)
{
    bool32 result = OG_FALSE;
    knl_device_def_t *dev_def = NULL;

    while (1) {
        if (cm_galist_new(list, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_try_fetch_char(lex, ',', &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!result) {
            return OG_SUCCESS;
        }
    }
}

static status_t sql_parse_rename_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;

    if (lex_try_fetch(lex, "TO", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        def->action = ALTSPACE_RENAME_SPACE;

        if (word->text.len > OG_MAX_NAME_LEN) {
            OG_THROW_ERROR(ERR_NAME_TOO_LONG, "tablespace", word->text.len, OG_MAX_NAME_LEN);
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->rename_space));
        if (cm_text_equal(&def->name, &def->rename_space)) {
            OG_THROW_ERROR(ERR_SPACE_NAME_INVALID, "the same name already exists");
            return OG_ERROR;
        }

        if (lex_fetch(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        return OG_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "DATAFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    def->action = ALTSPACE_RENAME_DATAFILE;
    if (sql_parse_datafiles_name(stmt, &def->datafiles, lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "TO") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_datafiles_name(stmt, &def->rename_datafiles, lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_offline_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    knl_device_def_t *dev_def = NULL;

    def->action = ALTSPACE_OFFLINE_DATAFILE;

    if (lex_expected_fetch_word(lex, "DATAFILE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (1) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_try_fetch_char(lex, ',', &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!result) {
            break;
        }
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}


static status_t sql_parse_autopurge_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;

    def->action = ALTSPACE_SET_AUTOPURGE;

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id == KEY_WORD_ON) {
        def->auto_purge = OG_TRUE;
    } else if (word->id == KEY_WORD_OFF) {
        def->auto_purge = OG_FALSE;
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "ON or OFF expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_shrink_spc_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    int64 max_size = (int64)OG_MAX_SPACE_FILES * g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
    def->action = ALTSPACE_SHRINK_SPACE;

    OG_RETURN_IFERR(lex_expected_fetch_word2(lex, "space", "keep"));
    OG_RETURN_IFERR(lex_expected_fetch_size(lex, &def->shrink.keep_size, OG_MIN_USER_DATAFILE_SIZE, max_size));

    return lex_fetch(lex, word);
}

static status_t sql_parse_extend_segments(sql_stmt_t *stmt, knl_altspace_def_t *def, word_t *word)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(KNL_SESSION(stmt));
    uint32 undo_segments = core_ctrl->undo_segments;
    lex_t *lex = stmt->session->lex;
    uint32 text_len;
    uint32 num = 0;

    if (lex_match_head(&word->text, "SEGMENTS", &text_len) && (text_len == strlen("SEGMENTS"))) {
        if (def->datafiles.count > 1) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "extend undo segments only supports one file ");
            return OG_ERROR;
        }

        if (lex_fetch(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (word->type == WORD_TYPE_NUMBER) {
            if (cm_text2uint32((text_t *)&word->text, &num) != OG_SUCCESS) {
                cm_reset_error();
                OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid segments number");
                return OG_ERROR;
            }
            if (num < 1 || num + undo_segments > OG_MAX_UNDO_SEGMENT) {
                OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid segments number");
                return OG_ERROR;
            }
        } else {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "number expected but %s found", W2S(word));
            return OG_ERROR;
        }

        if (lex_fetch(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    def->undo_segments = num;

    return OG_SUCCESS;
}

static status_t sql_parse_punch_spc_clause(sql_stmt_t *stmt, word_t *word, knl_altspace_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    int64 punc_size;
    bool32 result = OG_FALSE;
    def->action = ALTSPACE_PUNCH;

    if (lex_try_fetch(lex, "size", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        def->punch_size = OG_INVALID_INT64;
        return lex_fetch(lex, word);
    }

    OG_RETURN_IFERR(lex_expected_fetch_size(lex, &punc_size, OG_MIN_USER_DATAFILE_SIZE, OG_MAX_PUNCH_SIZE));
    def->punch_size = punc_size;
    return lex_fetch(lex, word);
}

status_t sql_parse_alter_space(sql_stmt_t *stmt)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_altspace_def_t *altspace_def = NULL;
    status_t status;

    lex->flags |= LEX_WITH_OWNER;
    stmt->context->type = OGSQL_TYPE_ALTER_TABLESPACE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_altspace_def_t), (void **)&altspace_def);
    OG_RETURN_IFERR(status);

    stmt->context->entry = altspace_def;

    status = lex_expected_fetch(lex, &word);
    OG_RETURN_IFERR(status);

    if (word.id == KEY_WORD_DB) {
        altspace_def->is_for_create_db = OG_TRUE;
        status = lex_expected_fetch_variant(lex, &word);
        OG_RETURN_IFERR(status);
    } else if (IS_VARIANT(&word)) {
        altspace_def->is_for_create_db = OG_FALSE;
    } else {
        OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid variant/object name was found");
        return OG_ERROR;
    }
 

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &altspace_def->name);
    OG_RETURN_IFERR(status);

    cm_galist_init(&altspace_def->datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&altspace_def->rename_datafiles, stmt->context, sql_alloc_mem);

    status = lex_expected_fetch(lex, &word);
    OG_RETURN_IFERR(status);
    altspace_def->in_shard = OG_FALSE;

    switch ((key_wid_t)word.id) {
        case KEY_WORD_ADD:
            status = sql_parse_datafile_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_DROP:
            status = sql_parse_drop_datafile_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_AUTOEXTEND:
            status = sql_parse_autoextend_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_AUTOOFFLINE:
            status = sql_parse_autooffline_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_RENAME:
            status = sql_parse_rename_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_OFFLINE:
            status = sql_parse_offline_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_AUTOPURGE:
            status = sql_parse_autopurge_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_SHRINK:
            status = sql_parse_shrink_spc_clause(stmt, &word, altspace_def);
            break;
        case KEY_WORD_PUNCH:
            status = sql_parse_punch_spc_clause(stmt, &word, altspace_def);
            break;
        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            status = OG_ERROR;
            break;
    }

    if (sql_parse_extend_segments(stmt, altspace_def, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type != WORD_TYPE_EOF) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(&word));
        return OG_ERROR;
    }

    return status;
}


static status_t sql_parse_drop_tablespace_opt(lex_t *lex, knl_drop_space_def_t *def)
{
    status_t status;
    bool32 result = OG_FALSE;
    uint32 mid;

    status = lex_try_fetch(lex, "including", &result);
    OG_RETURN_IFERR(status);

    if (result) {
        status = lex_expected_fetch_word(lex, "contents");
        OG_RETURN_IFERR(status);
        def->options |= TABALESPACE_INCLUDE;

        status = lex_try_fetch_1of2(lex, "and", "keep", &mid);
        OG_RETURN_IFERR(status);

        def->options |= TABALESPACE_DFS_AND;
        if (mid != OG_INVALID_ID32) {
            status = lex_expected_fetch_word(lex, "datafiles");
            OG_RETURN_IFERR(status);
            if (mid == 1) {
                def->options &= ~TABALESPACE_DFS_AND;
            }
        }

        status = lex_try_fetch(lex, "cascade", &result);
        OG_RETURN_IFERR(status);

        if (result) {
            status = lex_expected_fetch_word(lex, "constraints");
            OG_RETURN_IFERR(status);
            def->options |= TABALESPACE_CASCADE;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_drop_tablespace(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;
    knl_drop_space_def_t *def = NULL;

    stmt->context->type = OGSQL_TYPE_DROP_TABLESPACE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_drop_space_def_t), (void **)&def);
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_variant(lex, &word);
    OG_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->obj_name);
    OG_RETURN_IFERR(status);

    def->options = 0;
    status = sql_parse_drop_tablespace_opt(lex, def);
    OG_RETURN_IFERR(status);

    status = lex_fetch(lex, &word);
    OG_RETURN_IFERR(status);
    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid or duplicate drop tablespace option");
        return OG_ERROR;
    }

    stmt->context->entry = def;
    return OG_SUCCESS;
}

status_t sql_parse_purge_tablespace(sql_stmt_t *stmt, knl_purge_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;

    lex->flags = LEX_SINGLE_WORD;
    stmt->context->entry = def;

    status = lex_expected_fetch_variant(lex, &word);
    OG_RETURN_IFERR(status);

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->name);
    OG_RETURN_IFERR(status);

    status = lex_expected_end(lex);
    OG_RETURN_IFERR(status);

    def->type = PURGE_TABLESPACE;

    return OG_SUCCESS;
}


static status_t sql_rebuild_ctrlfile_parse_filelist(sql_stmt_t *stmt, galist_t *filelist, word_t *word)
{
    status_t status;
    knl_device_def_t *file = NULL;
    lex_t *lex = stmt->session->lex;

    if (filelist->count != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile is already defined");
        return OG_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    while (OG_TRUE) {
        status = lex_expected_fetch_string(lex, word);
        OG_BREAK_IF_ERROR(status);

        status = cm_galist_new(filelist, sizeof(knl_device_def_t), (pointer_t *)&file);
        OG_BREAK_IF_ERROR(status);

        status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &file->name);
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
    return lex_fetch(lex, word);
}

static status_t sql_rebuild_ctrlfile_parse_charset(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (def->charset.len != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CHARACTER SET is already defined");
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "SET") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_copy_text(stmt->context, (text_t *)&word->text, &def->charset) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_rebuild_ctrlfile_parse_database(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t *ctrlfile_def)
{
    word_t word;
    status_t status;
    status = lex_fetch(stmt->session->lex, &word);
    OG_RETURN_IFERR(status);

    while (word.type != WORD_TYPE_EOF) {
        switch (word.id) {
            case KEY_WORD_LOGFILE:
                status = sql_rebuild_ctrlfile_parse_filelist(stmt, &ctrlfile_def->logfiles, &word);
                break;

            case KEY_WORD_DATAFILE:
                status = sql_rebuild_ctrlfile_parse_filelist(stmt, &ctrlfile_def->datafiles, &word);
                break;

            case KEY_WORD_CHARSET:
                status = sql_rebuild_ctrlfile_parse_charset(stmt, ctrlfile_def, &word);
                break;

            case KEY_WORD_ARCHIVELOG:
                ctrlfile_def->arch_mode = ARCHIVE_LOG_ON;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            case KEY_WORD_NOARCHIVELOG:
                ctrlfile_def->arch_mode = ARCHIVE_LOG_OFF;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            default:
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
                return OG_ERROR;
        }

        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_create_ctrlfiles(sql_stmt_t *stmt)
{
    status_t status;
    knl_rebuild_ctrlfile_def_t *ctrlfile_def = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_rebuild_ctrlfile_def_t), (pointer_t *)&ctrlfile_def);
    OG_RETURN_IFERR(status);

    stmt->context->entry = ctrlfile_def;
    stmt->context->type = OGSQL_TYPE_CREATE_CTRLFILE;

    cm_galist_init(&ctrlfile_def->logfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&ctrlfile_def->datafiles, stmt->context, sql_alloc_mem);
    if (cm_dbs_is_enable_dbs() != OG_TRUE) {
        OG_THROW_ERROR(ERR_REBUILD_WITH_STORAGE);
        return OG_ERROR;
    }
    /* parse create ctrlfile sql statement */
    status = sql_rebuild_ctrlfile_parse_database(stmt, ctrlfile_def);
    OG_RETURN_IFERR(status);

    return OG_SUCCESS;
}

static status_t og_parse_space_datafiles(knl_space_def_t *space_def, galist_t *datafiles)
{
    knl_device_def_t *dev_def = NULL;
    status_t status;

    for (uint32 i = 0; i < datafiles->count; i++) {
        knl_device_def_t *cur = NULL;

        dev_def = (knl_device_def_t*)cm_galist_get(datafiles, i);
        for (uint32 j = 0; j < i; j++) {
            cur = (knl_device_def_t*)cm_galist_get(datafiles, j);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                    return OG_ERROR;
                }
            }
        }
    }
    status = cm_galist_copy(&space_def->datafiles, datafiles);
    OG_RETURN_IFERR(status);
    return OG_SUCCESS;
}

static status_t og_parse_space_attr(knl_space_def_t *def, galist_t *ts_opts)
{
    createts_opt *opt = NULL;
    bool32 parsed_offline = OG_FALSE;
    bool32 parsed_all = OG_FALSE;
    bool32 parsed_nologging = OG_FALSE;
    bool32 parsed_extent = OG_FALSE;
    def->in_memory = OG_FALSE;

    for (uint32 i = 0; i < ts_opts->count; i++) {
        opt = (createts_opt*)cm_galist_get(ts_opts, i);

        switch (opt->type) {
            case CREATETS_ALL_OPT:
                if ((def->type & SPACE_TYPE_TEMP) || parsed_all) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but all found");
                    return OG_ERROR;
                }
                def->in_memory = OG_TRUE;
                parsed_all = OG_TRUE;
                break;
            case CREATETS_NOLOGGING_OPT:
                if (def->in_memory || parsed_nologging) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but nologging found");
                    return OG_ERROR;
                }
                def->type |= SPACE_TYPE_TEMP;
                parsed_nologging = OG_TRUE;
                break;
            case CREATETS_AUTOOFFLINE_OPT:
                if (parsed_offline) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but autooffline found");
                    return OG_ERROR;
                }
                def->autooffline = opt->val;
                parsed_offline = OG_TRUE;
                break;
            case CREATETS_EXTENT_OPT:
                if (parsed_extent) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but extent found");
                    return OG_ERROR;
                }
                if (def->extent_size != 0) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid extent clause");
                    return OG_ERROR;
                }
                def->autoallocate = OG_TRUE;
                def->extent_size = OG_MIN_EXTENT_SIZE;
                def->bitmapmanaged = OG_TRUE;
                parsed_extent = OG_TRUE;
                break;
            default:
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid option");
                return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t og_parse_create_space(sql_stmt_t *stmt, knl_space_def_t **ts_def, bool is_undo, char *space_name,
    uint32 extentsize, galist_t *datafiles, galist_t *ts_opts)
{
    status_t status;
    knl_space_def_t *def = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_space_def_t), (pointer_t *)ts_def);
    OG_RETURN_IFERR(status);
    def = *ts_def;

    stmt->context->type = OGSQL_TYPE_CREATE_TABLESPACE;
    cm_galist_init(&def->datafiles, stmt->context, sql_alloc_mem);

    if (is_undo) {
        def->type = SPACE_TYPE_UNDO;
    } else {
        def->type = SPACE_TYPE_USERS;
    }

    def->in_shard = OG_FALSE;
    def->autoallocate = OG_FALSE;
    def->bitmapmanaged = OG_FALSE;
    def->name.str = space_name;
    def->name.len = strlen(space_name);

    if (extentsize != 0) {
        def->extent_size = extentsize;
    } else if (stmt->session->knl_session.kernel->attr.default_space_type == SPACE_BITMAP) {
        def->autoallocate = OG_TRUE;
        def->bitmapmanaged = OG_TRUE;
    }

    status = og_parse_space_datafiles(def, datafiles);
    OG_RETURN_IFERR(status);

    if (ts_opts != NULL) {
        status = og_parse_space_attr(def, ts_opts);
        OG_RETURN_IFERR(status);
    }

    return OG_SUCCESS;
}

static status_t og_parse_ctrlfile_filelist(galist_t *dst, galist_t *src)
{
    if (dst->count != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "datafile is already defined");
        return OG_ERROR;
    }
    return cm_galist_copy(dst, src);
}

static status_t og_parse_ctrlfile_charset(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t *def, char *charset)
{
    text_t raw;

    if (def->charset.len != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CHARACTER SET is already defined");
        return OG_ERROR;
    }

    raw.str = charset;
    raw.len = strlen(charset);
    return sql_copy_text(stmt->context, &raw, &def->charset);
}

status_t og_parse_create_ctrlfile(sql_stmt_t *stmt, knl_rebuild_ctrlfile_def_t **def, galist_t *ctrlfile_opts)
{
    status_t status;
    knl_rebuild_ctrlfile_def_t *ctrlfile_def = NULL;

    status = sql_alloc_mem(stmt->context, sizeof(knl_rebuild_ctrlfile_def_t), (pointer_t *)def);
    OG_RETURN_IFERR(status);
    ctrlfile_def = *def;

    stmt->context->type = OGSQL_TYPE_CREATE_CTRLFILE;

    cm_galist_init(&ctrlfile_def->logfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&ctrlfile_def->datafiles, stmt->context, sql_alloc_mem);
    if (cm_dbs_is_enable_dbs() != OG_TRUE) {
        OG_THROW_ERROR(ERR_REBUILD_WITH_STORAGE);
        return OG_ERROR;
    }

    if (ctrlfile_opts == NULL) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < ctrlfile_opts->count; i++) {
        ctrlfile_opt *opt = (ctrlfile_opt *)cm_galist_get(ctrlfile_opts, i);
        switch (opt->type) {
            case CTRLFILE_LOGFILE_OPT:
                status = og_parse_ctrlfile_filelist(&ctrlfile_def->logfiles, opt->file_list);
                break;
            case CTRLFILE_DATAFILE_OPT:
                status = og_parse_ctrlfile_filelist(&ctrlfile_def->datafiles, opt->file_list);
                break;
            case CTRLFILE_CHARSET_OPT:
                status = og_parse_ctrlfile_charset(stmt, ctrlfile_def, opt->charset);
                break;
            case CTRLFILE_ARCHIVELOG_OPT:
                ctrlfile_def->arch_mode = ARCHIVE_LOG_ON;
                break;
            case CTRLFILE_NOARCHIVELOG_OPT:
                ctrlfile_def->arch_mode = ARCHIVE_LOG_OFF;
                break;
            default:
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but unknown ctrlfile option");
                return OG_ERROR;
        }

        OG_RETURN_IFERR(status);
    }

    return OG_SUCCESS;
}

static status_t og_parse_datafile_clause(sql_stmt_t *stmt, knl_altspace_def_t *altspace_def, galist_t *datafiles)
{
    knl_device_def_t *dev_def = NULL;

    altspace_def->action = ALTSPACE_ADD_DATAFILE;

    for (uint32 i = 0; i < datafiles->count; i++) {
        knl_device_def_t *cur = NULL;
        dev_def = (knl_device_def_t*)cm_galist_get(datafiles, i);
        if (cm_galist_insert(&altspace_def->datafiles, dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }

        for (uint32 j = 0; j < i; j++) {
            cur = (knl_device_def_t*)cm_galist_get(datafiles, j);
            if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t og_parse_drop_datafile_clause(sql_stmt_t *stmt, knl_altspace_def_t *def, galist_t *datafiles)
{
    knl_device_def_t *dev_def = NULL;
    text_t *datafile_name = NULL;
    def->action = ALTSPACE_DROP_DATAFILE;

    for (uint32 i = 0; i < datafiles->count; i++) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
        datafile_name = (text_t*)cm_galist_get(datafiles, i);
        dev_def->name = *datafile_name;
    }
    return OG_SUCCESS;
}

static status_t og_parse_autoextend_clause(sql_stmt_t *stmt, knl_altspace_def_t *def, alterts_opt *opt)
{
    device_type_t type;
    int64 tmp_next_size = 0;
    int64 tmp_max_size = 0;
    uint32 page_size = 0;

    def->action = ALTSPACE_SET_AUTOEXTEND;

    /*
     * the storage engine does not support auto-extend maxsize property,
     * neither does the structure of knl_altspace_def_t.
     * so the 5th~7th argument are all left NULL until the maxsize property
     * implemented in the storage engine
     */
    OG_RETURN_IFERR(knl_get_space_type(KNL_SESSION(stmt), &def->name, &type));
    if (opt->type == ALTERTS_AUTOEXTEND_OFF_OPT) {
        def->autoextend.enabled = OG_FALSE;
    } else {
        def->autoextend.enabled = OG_TRUE;
        tmp_next_size = opt->autoextend.next_size;
        tmp_max_size = opt->autoextend.max_size;
        OG_RETURN_IFERR(knl_get_page_size(KNL_SESSION(stmt), &page_size));
        if (tmp_max_size != 0 && tmp_max_size > ((int64)OG_MAX_DATAFILE_PAGES * page_size)) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "\"MAXSIZE\" specified in autoextend clause cannot "
                "be greater than %lld. \"MAXSIZE\": %lld",
                ((int64)OG_MAX_DATAFILE_PAGES * page_size), tmp_max_size);
            return OG_ERROR;
        }
        if ((tmp_max_size > 0) && (tmp_next_size > tmp_max_size)) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "\"NEXT\" size specified in autoextend clause cannot be "
                "greater than the \"MAX\" size. \"Next\" size is %lld, \"MAX\" size is %lld",
                tmp_next_size, tmp_max_size);
            return OG_ERROR;
        }

        /* assign the parsed size value respectively */
        def->autoextend.nextsize = tmp_next_size;
        def->autoextend.maxsize = tmp_max_size;
    }
    return OG_SUCCESS;
}

static status_t og_parse_rename_datafiles_clause(sql_stmt_t *stmt, knl_altspace_def_t *def, alterts_opt *opt)
{
    knl_device_def_t *dev_def = NULL;
    text_t *name = NULL;
    def->action = ALTSPACE_RENAME_DATAFILE;

    for (uint32 i = 0; i < opt->rename_datafiles.old_files->count; i++) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
        name = (text_t*)cm_galist_get(opt->rename_datafiles.old_files, i);
        dev_def->name = *name;
    }

    for (uint32 i = 0; i < opt->rename_datafiles.new_files->count; i++) {
        if (cm_galist_new(&def->rename_datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
        name = (text_t*)cm_galist_get(opt->rename_datafiles.new_files, i);
        dev_def->name = *name;
    }
    return OG_SUCCESS;
}

static status_t og_parse_offline_clause(sql_stmt_t *stmt, knl_altspace_def_t *def, galist_t *datafiles)
{
    knl_device_def_t *dev_def = NULL;
    text_t *name = NULL;

    def->action = ALTSPACE_OFFLINE_DATAFILE;
    for (uint32 i = 0; i < datafiles->count; i++) {
        if (cm_galist_new(&def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
        name = (text_t*)cm_galist_get(datafiles, i);
        dev_def->name = *name;
    }
    return OG_SUCCESS;
}

static status_t og_parse_extend_segments(sql_stmt_t *stmt, knl_altspace_def_t *def, int64 segments_num)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(KNL_SESSION(stmt));
    uint32 undo_segments = core_ctrl->undo_segments;

    if (segments_num == OG_INVALID_INT64) {
        return OG_SUCCESS;
    }

    if (def->datafiles.count > 1) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "extend undo segments only supports one file ");
        return OG_ERROR;
    }
    if (segments_num < 1 || segments_num + undo_segments > OG_MAX_UNDO_SEGMENT) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid segments number");
        return OG_ERROR;
    }
    def->undo_segments = segments_num;
    return OG_SUCCESS;
}

status_t og_parse_alter_tablespace(sql_stmt_t *stmt, knl_altspace_def_t **def, bool32 is_for_create_db,
    char *tablespace_name, alterts_opt *opt, int64 segments_num)
{
    knl_altspace_def_t *altspace_def = NULL;

    stmt->context->type = OGSQL_TYPE_ALTER_TABLESPACE;

    if (sql_alloc_mem(stmt->context, sizeof(knl_altspace_def_t), (void **)def) != OG_SUCCESS) {
        return OG_ERROR;
    }
    altspace_def = *def;

    altspace_def->is_for_create_db = is_for_create_db;
    cm_str2text(tablespace_name, &altspace_def->name);

    cm_galist_init(&altspace_def->datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&altspace_def->rename_datafiles, stmt->context, sql_alloc_mem);

    altspace_def->in_shard = OG_FALSE;

    switch (opt->type) {
        case ALTERTS_ADD_DATAFILE_OPT:
            OG_RETURN_IFERR(og_parse_datafile_clause(stmt, altspace_def, opt->datafiles));
            break;
        case ALTERTS_DROP_DATAFILE_OPT:
            OG_RETURN_IFERR(og_parse_drop_datafile_clause(stmt, altspace_def, opt->datafiles));
            break;
        case ALTERTS_AUTOEXTEND_OFF_OPT:
            OG_RETURN_IFERR(og_parse_autoextend_clause(stmt, altspace_def, opt));
            break;
        case ALTERTS_AUTOEXTEND_ON_OPT:
            OG_RETURN_IFERR(og_parse_autoextend_clause(stmt, altspace_def, opt));
            break;
        case ALTERTS_AUTOOFFLINE_OPT:
            altspace_def->action = ALTSPACE_SET_AUTOOFFLINE;
            altspace_def->auto_offline = opt->on_off;
            break;
        case ALTERTS_RENAME_OPT:
            altspace_def->action = ALTSPACE_RENAME_SPACE;
            if (strlen(opt->new_name) > OG_MAX_NAME_LEN) {
                OG_THROW_ERROR(ERR_NAME_TOO_LONG, "tablespace", strlen(opt->new_name), OG_MAX_NAME_LEN);
                return OG_ERROR;
            }
            cm_str2text(opt->new_name, &altspace_def->rename_space);
            if (cm_text_equal(&altspace_def->name, &altspace_def->rename_space)) {
                OG_THROW_ERROR(ERR_SPACE_NAME_INVALID, "the same name already exists");
                return OG_ERROR;
            }
            break;
        case ALTERTS_RENAME_DATAFILE_OPT:
            OG_RETURN_IFERR(og_parse_rename_datafiles_clause(stmt, altspace_def, opt));
            break;
        case ALTERTS_OFFLINE_DATAFILE_OPT:
            OG_RETURN_IFERR(og_parse_offline_clause(stmt, altspace_def, opt->datafiles));
            break;
        case ALTERTS_AUTOPURGE_OPT:
            altspace_def->action = ALTSPACE_SET_AUTOPURGE;
            altspace_def->auto_purge = opt->on_off;
            break;
        case ALTERTS_SHRINK_SPACE_OPT:
            altspace_def->action = ALTSPACE_SHRINK_SPACE;
            altspace_def->shrink.keep_size = opt->size;
            break;
        case ALTERTS_PUNCH_OPT:
            altspace_def->action = ALTSPACE_PUNCH;
            altspace_def->punch_size = opt->size;
            break;
        default:
            break;
    }

    OG_RETURN_IFERR(og_parse_extend_segments(stmt, altspace_def, segments_num));

    return OG_SUCCESS;
}
