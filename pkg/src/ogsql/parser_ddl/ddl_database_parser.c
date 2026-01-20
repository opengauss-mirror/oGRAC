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
 * ddl_database_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_database_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_database_parser.h"
#include "dcl_database_parser.h"
#include "ddl_space_parser.h"
#include "ddl_user_parser.h"
#include "srv_instance.h"
#include "dtc_database.h"
#include "dtc_parser.h"


status_t sql_parse_password(sql_stmt_t *stmt, char *password, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "IDENTIFIED"));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "BY"));
    OG_RETURN_IFERR(lex_expected_fetch(stmt->session->lex, word));
    if (word->type != WORD_TYPE_VARIANT && word->type != WORD_TYPE_STRING && word->type != WORD_TYPE_DQ_STRING) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "The password must be identifier or string");
        return OG_ERROR;
    }
    if (word->type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(word);
    }
    if (word->text.len > OG_PASSWORD_BUFFER_SIZE - 1) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "The password length must be less than %u",
            OG_PASSWORD_BUFFER_SIZE);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_text2str((text_t *)&word->text, password, OG_PASSWORD_BUFFER_SIZE));

    if (OG_SUCCESS != sql_replace_password(stmt, &word->text.value)) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
static status_t sql_parse_dbca_sys_user(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    text_t user_name;
    lex_t *lex = stmt->session->lex;
    char log_pwd[OG_PWD_BUFFER_SIZE] = {0};

    if (strlen(def->sys_password) != 0) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "sys user is already defined");
        return OG_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &user_name));
    if (!cm_text_str_equal(&user_name, "SYS")) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "user name SYS expected but %s found", W2S(word));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_parse_password(stmt, def->sys_password, word));
    if (cm_check_pwd_black_list(GET_PWD_BLACK_CTX, SYS_USER_NAME, def->sys_password, log_pwd)) {
        OG_THROW_ERROR_EX(ERR_PASSWORD_FORMAT_ERROR, "The password violates the pbl rule");
        return OG_ERROR;
    }
    return lex_fetch(lex, word);
}

static status_t sql_parse_dbca_ctrlfiles(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    status_t status;
    text_t *file_name = NULL;
    lex_t *lex = stmt->session->lex;

    if (def->ctrlfiles.count != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CONTROLFILE is already defined");
        return OG_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    if (status != OG_SUCCESS) {
        return status;
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    while (1) {
        if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (cm_galist_new(&def->ctrlfiles, sizeof(text_t), (pointer_t *)&file_name) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (sql_copy_file_name(stmt->context, (text_t *)&word->text, file_name) != OG_SUCCESS) {
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
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "\",\" expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    lex_pop(lex);

    return lex_fetch(lex, word);
}

static status_t sql_parse_dbca_charset(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
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

static status_t sql_try_parse_file_blocksize(lex_t *lex, int32 *blocksize)
{
    bool32 result = OG_FALSE;
    int64 size;

    if (lex_try_fetch(lex, "BLOCKSIZE", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_size(lex, &size, FILE_BLOCK_SIZE_512, FILE_BLOCK_SIZE_4096) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (size != FILE_BLOCK_SIZE_512 && size != FILE_BLOCK_SIZE_4096) {
            OG_THROW_ERROR(ERR_INVALID_PARAMETER, "BLOCKSIZE");
            return OG_ERROR;
        }
        *blocksize = (int32)size;
    }

    return OG_SUCCESS;
}

static status_t sql_try_parse_logfile_instance(lex_t *lex, uint32 *node_id)
{
    bool32 result = OG_FALSE;

    *node_id = 0;
    if (lex_try_fetch(lex, "INSTANCE", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        *node_id = g_instance->kernel.dtc_attr.inst_id;
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_uint32(lex, node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (*node_id != g_instance->kernel.dtc_attr.inst_id || *node_id > OG_MAX_INSTANCES - 1) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "INSTANCE");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_dbca_logfiles(sql_stmt_t *stmt, galist_t *logfiles, word_t *word)
{
    status_t status;
    knl_device_def_t *log_file = NULL;
    lex_t *lex = stmt->session->lex;

    if (logfiles->count != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "LOGFILE is already defined");
        return OG_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    while (OG_TRUE) {
        status = lex_expected_fetch_string(lex, word);
        OG_BREAK_IF_ERROR(status);

        status = cm_galist_new(logfiles, sizeof(knl_device_def_t), (pointer_t *)&log_file);
        OG_BREAK_IF_ERROR(status);

        status = sql_copy_file_name(stmt->context, (text_t *)&word->text, &log_file->name);
        OG_BREAK_IF_ERROR(status);

        status = lex_expected_fetch_word(lex, "SIZE");
        OG_BREAK_IF_ERROR(status);

        status = lex_expected_fetch_size(lex, &log_file->size, OG_INVALID_INT64, OG_INVALID_INT64);
        OG_BREAK_IF_ERROR(status);

        status = sql_try_parse_file_blocksize(lex, &log_file->block_size);
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


static status_t sql_check_filesize(const text_t *space_name, knl_device_def_t *dev_def)
{
    int64 min_filesize;
    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;

    if (cm_text_equal(space_name, &g_system) || cm_text_equal(space_name, &g_undo)) {
        min_filesize = OG_MIN_SYSTEM_DATAFILE_SIZE;
    } else if (cm_text_equal(space_name, &g_sysaux)) {
        min_filesize = OG_MIN_SYSAUX_DATAFILE_SIZE;
    } else {
        min_filesize = OG_MIN_USER_DATAFILE_SIZE;
    }

    if (dev_def->size > max_filesize) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is bigger than maximum(%llu) required", max_filesize);
        return OG_ERROR;
    }

    if (dev_def->size < min_filesize) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum(%llu) required", min_filesize);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_dbca_datafile_spec(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_space_def_t *space_def)
{
    status_t status;
    bool32 isRelative = OG_FALSE;
    knl_device_def_t *dev_def = NULL;

    while (1) {
        uint32 i;
        knl_device_def_t *cur = NULL;

        status = cm_galist_new(&space_def->datafiles, sizeof(knl_device_def_t), (pointer_t *)&dev_def);
        OG_RETURN_IFERR(status);

        status = sql_parse_datafile(stmt, dev_def, word, &isRelative);
        OG_RETURN_IFERR(status);

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < space_def->datafiles.count; i++) {
            cur = (knl_device_def_t *)cm_galist_get(&space_def->datafiles, i);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                    return OG_ERROR;
                }
            }
        }

        status = sql_check_filesize(&space_def->name, dev_def);
        OG_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    if (word->id == KEY_WORD_ALL) {
        status = lex_expected_fetch_word(lex, "IN");
        OG_RETURN_IFERR(status);

        status = lex_expected_fetch_word(lex, "MEMORY");
        OG_RETURN_IFERR(status);

        space_def->in_memory = OG_TRUE;
        return lex_fetch(lex, word);
    } else {
        space_def->in_memory = OG_FALSE;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_dbca_space(sql_stmt_t *stmt, knl_database_def_t *db_def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    knl_space_def_t *space_def = NULL;
    bool32 is_temp = OG_FALSE;
    status_t status;

    if (word->id == KEY_WORD_TEMPORARY) {
        knl_panic(stmt->context->type == OGSQL_TYPE_CREATE_DATABASE);
        dtc_node_def_t *node = cm_galist_get(&db_def->nodes, 0); /* single node goes here. */
        is_temp = OG_TRUE;
        space_def = &node->swap_space;
        space_def->name = g_swap;
    } else if (word->id == KEY_WORD_NO_LOGGING) {
        is_temp = OG_TRUE;
        bool32 result = OG_FALSE;
        status = lex_try_fetch(lex, "UNDO", &result);
        OG_RETURN_IFERR(status);
        if (result) {
            space_def = &db_def->temp_undo_space;
            space_def->name = g_temp_undo;
        } else {
            space_def = &db_def->temp_space;
            space_def->name = g_temp;
        }
    } else if (word->id == KEY_WORD_SYSTEM) {
        space_def = &db_def->system_space;
        space_def->name = g_system;
    } else if (word->id == KEY_WORD_UNDO) {
        knl_panic(stmt->context->type == OGSQL_TYPE_CREATE_DATABASE);
        dtc_node_def_t *node = cm_galist_get(&db_def->nodes, 0); /* single node goes here. */
        space_def = &node->undo_space;
        space_def->name = g_undo;
    } else if (word->id == KEY_WORD_SYSAUX) {
        space_def = &db_def->sysaux_space;
        space_def->name = g_sysaux;
    } else {
        space_def = &db_def->user_space;
        space_def->name = g_users;
    }

    if (space_def->datafiles.count != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s tablesapce is already defined", W2S(word));
        return OG_ERROR;
    }

    status = lex_expected_fetch_word(lex, "TABLESPACE");
    OG_RETURN_IFERR(status);

    if (is_temp) {
        status = lex_expected_fetch_word(lex, "TEMPFILE");
        OG_RETURN_IFERR(status);
    } else {
        status = lex_expected_fetch_word(lex, "DATAFILE");
        OG_RETURN_IFERR(status);
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, space_def);
}

static status_t sql_parse_config_ctrlfiles(sql_stmt_t *stmt, knl_database_def_t *db_def)
{
    status_t status = OG_ERROR;
    text_t files;
    text_t name;
    text_t *file_name = NULL;
    char *value = cm_get_config_value(&g_instance->config, "CONTROL_FILES");

    if (CM_IS_EMPTY_STR(value)) {
        return OG_SUCCESS;
    }
    if (db_def->ctrlfiles.count > 0) {
        return OG_SUCCESS;
    }

    cm_str2text(value, &files);
    cm_remove_brackets(&files);

    while (OG_TRUE) {
        if (!cm_fetch_text(&files, ',', '\0', &name)) {
            status = OG_SUCCESS;
            break;
        }
        cm_trim_text(&name);
        if (name.str[0] == '\'') {
            name.str++;
            name.len -= 2;
            cm_trim_text(&name);
        }

        if (cm_galist_new(&db_def->ctrlfiles, sizeof(text_t), (pointer_t *)&file_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_file_name(stmt->context, &name, file_name) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (status != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "CONTROL_FILES");
    }
    return status;
}

static status_t sql_try_set_files(sql_stmt_t *stmt, galist_t *files, const char *name, int32 count)
{
    char str[OG_FILE_NAME_BUFFER_SIZE];
    text_t *file_name = NULL;
    char file_path[OG_FILE_NAME_BUFFER_SIZE];

    if (files->count != 0) {
        return OG_SUCCESS;
    }

    for (int32 i = 1; i <= count; i++) {
        PRTS_RETURN_IFERR(snprintf_s(file_path, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1, "%s/data/%s%d",
            g_instance->home, name, i));
        if (realpath_file(file_path, str, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (cm_galist_new(files, sizeof(text_t), (void **)&file_name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_str_safe(stmt->context, file_path, (uint32)strlen(file_path), file_name) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_try_set_devices(sql_stmt_t *stmt, galist_t *devices, const char *name, int32 count, int64 size,
    int64 extend_size, int64 max_extend_size)
{
    char str[OG_FILE_NAME_BUFFER_SIZE];
    knl_device_def_t *dev = NULL;
    text_t src_text;
    char file_path[OG_FILE_NAME_BUFFER_SIZE];

    if (devices->count != 0) {
        return OG_SUCCESS;
    }

    for (int32 i = 1; i <= count; i++) {
        if (cm_galist_new(devices, sizeof(knl_device_def_t), (void **)&dev) != OG_SUCCESS) {
            return OG_ERROR;
        }

        dev->size = size;
        dev->autoextend.enabled = (extend_size != OG_INVALID_INT64) ? OG_TRUE : OG_FALSE;
        dev->autoextend.nextsize = extend_size;
        dev->autoextend.maxsize = max_extend_size;

        if (count > 1) {
            PRTS_RETURN_IFERR(snprintf_s(file_path, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1,
                "%s/data/%s%d", g_instance->home, name, i));
            if (realpath_file(file_path, str, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
                return OG_ERROR;
            }
        } else {
            PRTS_RETURN_IFERR(snprintf_s(file_path, OG_FILE_NAME_BUFFER_SIZE, OG_FILE_NAME_BUFFER_SIZE - 1,
                "%s/data/%s", g_instance->home, name));
            if (realpath_file(file_path, str, OG_FILE_NAME_BUFFER_SIZE) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }

        cm_str2text_safe(file_path, (uint32)strlen(file_path), &src_text);
        if (sql_copy_file_name(stmt->context, &src_text, &dev->name) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_set_database_default(sql_stmt_t *stmt, knl_database_def_t *db_def, bool32 clustered)
{
    galist_t *list = NULL;
    uint32 page_size;

    OG_RETURN_IFERR(sql_parse_config_ctrlfiles(stmt, db_def));

    OG_RETURN_IFERR(sql_try_set_files(stmt, &db_def->ctrlfiles, "ctrl", DEFAULT_CTRL_FILE_COUNT));

    OG_RETURN_IFERR(knl_get_page_size(KNL_SESSION(stmt), &page_size));

    list = &db_def->system_space.datafiles;
    if (sql_try_set_devices(stmt, list, "system", 1, DEFAULT_SYSTEM_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
        ((int64)OG_MAX_DATAFILE_PAGES * page_size)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    dtc_node_def_t *node = NULL;

    /* log, undo and swap space must be specified explicitly for clustered database */
    for (uint32 i = 0; i < db_def->nodes.count && !clustered; i++) {
        node = cm_galist_get(&db_def->nodes, i);

        list = &node->logfiles;
        if (sql_try_set_devices(stmt, list, "redo", 3, DEFAULT_LOGFILE_SIZE, OG_INVALID_INT64,
            ((int64)OG_MAX_DATAFILE_PAGES * page_size)) != OG_SUCCESS) {
            return OG_ERROR;
        }

        list = &node->undo_space.datafiles;
        if (sql_try_set_devices(stmt, list, "undo", 1, DEFAULT_UNDO_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
            ((int64)OG_MAX_UNDOFILE_PAGES * page_size)) != OG_SUCCESS) {
            return OG_ERROR;
        }

        list = &node->swap_space.datafiles;
        if (sql_try_set_devices(stmt, list, "temp", 1, DEFAULT_TEMP_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
            ((int64)OG_MAX_DATAFILE_PAGES * page_size)) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    list = &db_def->user_space.datafiles;
    if (sql_try_set_devices(stmt, list, "user", 1, DEFAULT_USER_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
        ((int64)OG_MAX_DATAFILE_PAGES * page_size)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    list = &db_def->temp_space.datafiles;
    if (sql_try_set_devices(stmt, list, "temp2_01", 1, DEFAULT_USER_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
        ((int64)OG_MAX_DATAFILE_PAGES * page_size)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    list = &db_def->temp_undo_space.datafiles;
    if (sql_try_set_devices(stmt, list, "temp2_undo", 1, DEFAULT_UNDO_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
        ((int64)OG_MAX_UNDOFILE_PAGES * page_size)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    list = &db_def->sysaux_space.datafiles;
    if (sql_try_set_devices(stmt, list, "sysaux", 1, DEFAULT_SYSAUX_SPACE_SIZE, DEFAULT_AUTOEXTEND_SIZE,
        ((int64)OG_MAX_DATAFILE_PAGES * page_size)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_create_database(sql_stmt_t *stmt, bool32 clustered)
{
    word_t word;
    status_t status;
    knl_database_def_t *db_def = NULL;
    archive_mode_t arch_mode = ARCHIVE_LOG_OFF;
    dtc_node_def_t *node = NULL;

    SQL_SET_IGNORE_PWD(stmt->session);
    status = sql_alloc_mem(stmt->context, sizeof(knl_database_def_t), (pointer_t *)&db_def);
    OG_RETURN_IFERR(status);

    stmt->context->entry = db_def;
    stmt->context->type = clustered ? OGSQL_TYPE_CREATE_CLUSTERED_DATABASE : OGSQL_TYPE_CREATE_DATABASE;
    status = lex_expected_fetch_variant(stmt->session->lex, &word);
    OG_RETURN_IFERR(status);

    cm_galist_init(&db_def->ctrlfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->nodes, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->system_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->user_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->temp_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->sysaux_space.datafiles, stmt->context, sql_alloc_mem);

    db_def->system_space.name = g_system;
    db_def->system_space.type = SPACE_TYPE_SYSTEM | SPACE_TYPE_DEFAULT;
    db_def->user_space.name = g_users;
    db_def->user_space.type = SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    db_def->temp_space.name = g_temp;
    db_def->temp_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    db_def->temp_undo_space.name = g_temp_undo;
    db_def->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT;
    db_def->sysaux_space.name = g_sysaux;
    db_def->sysaux_space.type = SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT;
    db_def->max_instance = clustered ? OG_DEFAULT_INSTANCE : 1;
    if (!clustered) {
        if (cm_galist_new(&db_def->nodes, sizeof(dtc_node_def_t), (pointer_t *)&node) != OG_SUCCESS) {
            return OG_ERROR;
        }
        cm_galist_init(&node->logfiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->undo_space.datafiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->swap_space.datafiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);
        node->undo_space.name = g_undo;
        node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;
        node->swap_space.name = g_swap;
        node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT | SPACE_TYPE_SWAP;
        node->temp_undo_space.name = g_temp_undo;
        node->temp_undo_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT | SPACE_TYPE_UNDO;
    }

    if (word.text.len > OG_DB_NAME_LEN - 2) {
        OG_THROW_ERROR(ERR_NAME_TOO_LONG, "database", word.text.len, OG_DB_NAME_LEN - 2);
        return OG_ERROR;
    }

    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &db_def->name);
    OG_RETURN_IFERR(status);
    status = lex_fetch(stmt->session->lex, &word);
    OG_RETURN_IFERR(status);

    while (word.type != WORD_TYPE_EOF) {
        switch (word.id) {
            case RES_WORD_USER:
                status = sql_parse_dbca_sys_user(stmt, db_def, &word);
                break;

            case KEY_WORD_CONTROLFILE:
                status = sql_parse_dbca_ctrlfiles(stmt, db_def, &word);
                break;

            case KEY_WORD_CHARACTER:
                status = sql_parse_dbca_charset(stmt, db_def, &word);
                break;

            case KEY_WORD_LOGFILE:
                status = sql_parse_dbca_logfiles(stmt, &node->logfiles, &word);
                break;

            case KEY_WORD_ARCHIVELOG:
                arch_mode = ARCHIVE_LOG_ON;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            case KEY_WORD_NOARCHIVELOG:
                arch_mode = ARCHIVE_LOG_OFF;
                status = lex_fetch(stmt->session->lex, &word);
                break;

            case RES_WORD_DEFAULT: /* default tablespace */
            case KEY_WORD_TEMPORARY:
            case KEY_WORD_NO_LOGGING:
            case KEY_WORD_UNDO:
            case KEY_WORD_SYSAUX:
            case KEY_WORD_SYSTEM:
                status = sql_parse_dbca_space(stmt, db_def, &word);
                break;

            case KEY_WORD_INSTANCE:
                status = dtc_parse_instance(stmt, db_def, &word);
                break;

            case KEY_WORD_MAXINSTANCES:
                status = dtc_parse_maxinstance(stmt, db_def, &word);
                if (status != OG_SUCCESS) {
                    return OG_ERROR;
                }
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

    db_def->arch_mode = arch_mode;
    status = sql_set_database_default(stmt, db_def, clustered);
    OG_RETURN_IFERR(status);

    return dtc_verify_database_def(stmt, db_def);
}

status_t sql_create_database_lead(sql_stmt_t *stmt)
{
    bool32 result = OG_FALSE;

    if (lex_try_fetch(stmt->session->lex, "CLUSTERED", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_parse_create_database(stmt, result);
}

static status_t sql_parse_alterdb_upgrade(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    db_open_opt_t *options = &def->open_options;
    lex_t *lex = stmt->session->lex;
    bool32 is_found = OG_FALSE;
    uint64 value;
    options->open_status = DB_OPEN_STATUS_UPGRADE;

    if (lex_try_fetch2(lex, "replay", "until", &is_found) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (!is_found) {
        return OG_SUCCESS;
    }
    if (lex_expected_fetch_uint64(stmt->session->lex, &value) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (value == OG_INVALID_LFN) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "Zero for LFN is");
        return OG_ERROR;
    }

    def->open_options.lfn = value;
    return OG_SUCCESS;
}

static status_t sql_parse_alterdb_get_lfn(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    uint64 value;

    if (lex_expected_fetch_uint64(stmt->session->lex, &value) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (value == OG_INVALID_LFN) {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "Zero for LFN is");
        return OG_ERROR;
    }

    def->open_options.lfn = value;

    return OG_SUCCESS;
}

static status_t sql_parse_for_upgrade(sql_stmt_t *stmt, knl_alterdb_def_t *def, bool32 *is_found)
{
    lex_t *lex = stmt->session->lex;

    if (lex_try_fetch2(lex, "replay", "until", is_found) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (*is_found) {
        if (sql_parse_alterdb_get_lfn(stmt, def) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (lex_try_fetch(lex, "upgrade", is_found) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (*is_found) {
        if (sql_parse_alterdb_upgrade(stmt, def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_alterdb_alter_open(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    bool32 is_found = OG_FALSE;
    db_open_opt_t *options = &def->open_options;

    def->open_options.lfn = OG_INVALID_LFN;
    def->open_options.is_creating = OG_FALSE;
    for (;;) {
        if (lex_try_fetch2(lex, "read", "only", &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (is_found) {
            options->readonly = OG_TRUE;
            break;
        }

        if (sql_parse_for_upgrade(stmt, def, &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (is_found) {
            break;
        }

        if (lex_try_fetch(lex, "maxfix", &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (is_found) {
            options->open_status = DB_OPEN_STATUS_MAX_FIX;
            break;
        }

        if (lex_try_fetch(lex, "restricted", &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (is_found) {
            options->open_status = DB_OPEN_STATUS_RESTRICT;
            break;
        }

        if (lex_try_fetch2(lex, "read", "write", &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_try_fetch(stmt->session->lex, "resetlogs", &options->resetlogs) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_try_fetch3(lex, "force", "ignore", "logs", &is_found) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (is_found) {
            options->ignore_logs = OG_TRUE;
            if (options->readonly || options->open_status >= DB_OPEN_STATUS_RESTRICT || options->resetlogs) {
                OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR);
                return OG_ERROR;
            }
        }
        break;
    }

    if (lex_try_fetch2(lex, "ignore", "systime", &options->ignore_systime) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_altdb_update_mk(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    if (lex_expected_fetch_word(lex, "MASTERKEY")) {
        OG_THROW_ERROR(ERR_JOB_UNSUPPORT, "UPDATE masterkey");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_altdb_alter_tempfile(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    return OG_ERROR;
}

static status_t sql_get_datafile_type(knl_alterdb_datafile_t *df_def, device_type_t *type)
{
    if (df_def->datafiles.count == 0) {
        OG_THROW_ERROR(ERR_ASSERT_ERROR, "no datafile in alter database datafile statment");
        return OG_ERROR;
    }
    text_t *name = (text_t *)cm_galist_get(&df_def->datafiles, 0);
    *type = cm_device_type(name->str);
    return OG_SUCCESS;
}

static status_t sql_parse_alter_database_autoextend_clause(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    word_t clause_end_word;
    knl_alterdb_datafile_t *df_def = NULL;
    device_type_t type;

    if (stmt->context->type != OGSQL_TYPE_ALTER_DATABASE) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "stmt->context->type(%u) == OGSQL_TYPE_ALTER_DATABASE(%u)",
            (uint32)stmt->context->type, (uint32)OGSQL_TYPE_ALTER_DATABASE);
        return OG_ERROR;
    }
    /* "ALTER DATABASE TMPFILE" might need this function, too */
    if (def->action != ALTER_DATAFILE) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "def->action(%u) == ALTER_DATAFILE(%u)", (uint32)def->action,
            (uint32)ALTER_DATAFILE);
        return OG_ERROR;
    }

    df_def = &def->datafile;
    OG_RETURN_IFERR(sql_get_datafile_type(df_def, &type));
    OG_RETURN_IFERR(sql_parse_autoextend_clause_core(type, stmt, &df_def->autoextend, &clause_end_word));

    if (df_def->autoextend.enabled == OG_TRUE) {
        df_def->alter_datafile_mode = ALTER_DF_AUTOEXTEND_ON;
    } else {
        df_def->alter_datafile_mode = ALTER_DF_AUTOEXTEND_OFF;
    }

    if (clause_end_word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(clause_end_word.loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found",
            W2S(&clause_end_word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_alter_database_resize_clause(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    int64 size = 0;
    int64 max_filesize = (int64)g_instance->kernel.attr.page_size * OG_MAX_DATAFILE_PAGES;
    lex_t *lex = stmt->session->lex;

    if (stmt->context->type != OGSQL_TYPE_ALTER_DATABASE) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "stmt->context->type(%u) == OGSQL_TYPE_ALTER_DATABASE(%u)",
            (uint32)stmt->context->type, (uint32)OGSQL_TYPE_ALTER_DATABASE);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_expected_fetch_size(lex, &size, OG_MIN_USER_DATAFILE_SIZE, max_filesize));
    def->datafile.size = (uint64)size;
    def->datafile.alter_datafile_mode = ALTER_DF_RESIZE;

    return lex_expected_end(lex);
}

static status_t sql_parse_alter_datafile_core(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *next_word)
{
    switch (next_word->id) {
        case KEY_WORD_AUTOEXTEND:
            return sql_parse_alter_database_autoextend_clause(stmt, def);
        case KEY_WORD_RESIZE:
            return sql_parse_alter_database_resize_clause(stmt, def);
        case KEY_WORD_ONLINE:
        case KEY_WORD_OFFLINE:
        case KEY_WORD_END:
            OG_SRC_THROW_ERROR(next_word->loc, ERR_CAPABILITY_NOT_SUPPORT,
                "end clause in the \"ALTER DATABASE DATAFILE\" statement ");
            return OG_ERROR;
        default:
            OG_SRC_THROW_ERROR_EX(next_word->loc, ERR_SQL_SYNTAX_ERROR,
                "invalid clause in \"ALTER DATABASE DATAFILE\" statement");
            return OG_ERROR;
    }
}

/* the internal function used for parsing the datafile clause in "ALTER DATABASE" */
static status_t sql_parse_alterdb_alter_datafile(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    word_t word;
    word_t next_word;
    lex_t *lex = stmt->session->lex;

    if (stmt->context->type != OGSQL_TYPE_ALTER_DATABASE) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "stmt->context->type(%u) == OGSQL_TYPE_ALTER_DATABASE(%u)",
            (uint32)stmt->context->type, (uint32)OGSQL_TYPE_ALTER_DATABASE);
        return OG_ERROR;
    }

    cm_galist_init(&(def->datafile.datafiles), stmt->context, sql_alloc_mem);
    cm_galist_init(&(def->datafile.changed_datafiles), stmt->context, sql_alloc_mem);

    do {
        uint32 i;
        text_t *datafile_name = NULL;
        text_t *cur = NULL;

        OG_RETURN_IFERR(lex_expected_fetch(lex, &word));
        if ((word.type != WORD_TYPE_STRING) && (word.type != WORD_TYPE_NUMBER)) {
            OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "file name or file number expected.");
            return OG_ERROR;
        }

        /* add the filename to knl_alterdb_def_t, filename is stored as text_t */
        if (word.type == WORD_TYPE_STRING) {
            LEX_REMOVE_WRAP(&word);

            OG_RETURN_IFERR(cm_galist_new(&(def->datafile.datafiles), sizeof(text_t), (pointer_t *)&datafile_name));
            /* W.T.F. the order of arguments in sql_copy_text() differed from sql_copy_str() */
            OG_RETURN_IFERR(sql_copy_file_name(stmt->context, &(word.text.value), datafile_name));
        } else {
            int32 file_number;
            char *df_name = NULL;

            OG_RETURN_IFERR(cm_text2int(&word.text.value, &file_number));

            OG_RETURN_IFERR(knl_get_dfname_by_number(KNL_SESSION(stmt), file_number, &df_name));

            OG_RETURN_IFERR(cm_galist_new(&(def->datafile.datafiles), sizeof(text_t), (pointer_t *)&datafile_name));
            OG_RETURN_IFERR(sql_copy_str(stmt->context, df_name, datafile_name));
        }

        /* prevent the duplicate datafile being passed to storage engine */
        for (i = 0; i < def->datafile.datafiles.count; i++) {
            cur = (text_t *)cm_galist_get(&(def->datafile.datafiles), i);
            if (cur != datafile_name) {
                if (cm_text_equal_ins(datafile_name, cur)) {
                    OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "it is not allowed to specify duplicate datafile");
                    return OG_ERROR;
                }
            }
        }

        /* there must be a word next to the fetched one */
        OG_RETURN_IFERR(lex_expected_fetch(lex, &next_word));
    } while (IS_SPEC_CHAR(&next_word, ','));

    if (next_word.type == WORD_TYPE_KEYWORD) {
        /* use the kind of keyword to decide which clause it is */
        return sql_parse_alter_datafile_core(stmt, def, &next_word);
    }
    OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected \"%s\" in \"ALTER DATABASE\" statement ",
        (*(W2S(&next_word)) == '\0' ? "emtpy string" : W2S(&next_word)));
    return OG_ERROR;
}


static status_t sql_set_standby_mode(key_wid_t id, knl_alterdb_def_t *alterdb_def, word_t *word)
{
    switch (id) {
        case KEY_WORD_PROTECTION:
            alterdb_def->standby.alter_standby_mode = ALTER_SET_PROTECTION;
            break;

        case KEY_WORD_AVAILABILITY:
            alterdb_def->standby.alter_standby_mode = ALTER_SET_AVAILABILITY;
            break;

        case KEY_WORD_PERFORMANCE:
            alterdb_def->standby.alter_standby_mode = ALTER_SET_PERFORMANCE;
            break;

        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for protection mode",
                W2S(word), word->loc.column);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_altdb_maximize_standby(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def, word_t *word)
{
    status_t status;
    lex_t *lex = stmt->session->lex;

    if ((key_wid_t)word->id != KEY_WORD_STANDBY) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for protection mode",
            W2S(word), word->loc.column);
        return OG_ERROR;
    }
    status = lex_expected_fetch(lex, word);
    OG_RETURN_IFERR(status);

    if ((key_wid_t)word->id != KEY_WORD_DATABASE) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for protection mode",
            W2S(word), word->loc.column);
        return OG_ERROR;
    }
    status = lex_expected_fetch(lex, word);
    OG_RETURN_IFERR(status);

    if ((key_wid_t)word->id != KEY_WORD_TO) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for protection mode",
            W2S(word), word->loc.column);
        return OG_ERROR;
    }

    status = lex_expected_fetch(lex, word);
    OG_RETURN_IFERR(status);
    if ((key_wid_t)word->id != KEY_WORD_MAXIMIZE) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for protection mode",
            W2S(word), word->loc.column);
        return OG_ERROR;
    }

    status = lex_expected_fetch(lex, word);
    OG_RETURN_IFERR(status);
    status = sql_set_standby_mode((key_wid_t)word->id, alterdb_def, word);
    OG_RETURN_IFERR(status);
    return lex_expected_end(lex);
}

static status_t sql_parse_altdb_set_dbtimezone(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def)
{
    word_t value;
    lex_t *lex = stmt->session->lex;
    timezone_info_t dbtz_new;
    text_t normal_tz;
    char param_new_value[TIMEZONE_OFFSET_STRLEN] = { 0 };

    if (lex_expected_fetch_word(lex, "=") != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_expected_fetch_string(lex, &value));

    // normalize this tz str and must check if tz is valid
    OG_RETURN_IFERR(cm_text2tzoffset(&value.text.value, &dbtz_new));
    normal_tz.str = param_new_value;
    OG_RETURN_IFERR(cm_tzoffset2text(dbtz_new, &normal_tz));

    OG_RETURN_IFERR(sql_copy_name(stmt->context, &normal_tz, &alterdb_def->timezone_offset_name));

    return lex_expected_end(lex);
}


static status_t sql_parse_convert_physical_standby(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if ((key_wid_t)word->id != KEY_WORD_STANDBY) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for convert", W2S(word),
            word->loc.column);
        return OG_ERROR;
    }

    alterdb_def->is_cascaded = OG_FALSE;

    if (lex_try_fetch(lex, "mount", &alterdb_def->is_mount) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_convert_cascaded_standby(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if ((key_wid_t)word->id != KEY_WORD_PHYSICAL) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for convert", W2S(word),
            word->loc.column);
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if ((key_wid_t)word->id != KEY_WORD_STANDBY) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for convert", W2S(word),
            word->loc.column);
        return OG_ERROR;
    }

    alterdb_def->is_cascaded = OG_TRUE;
    if (lex_try_fetch(lex, "mount", &alterdb_def->is_mount) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_altdb_convert(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    status_t status;

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if ((key_wid_t)word->id != KEY_WORD_TO) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "key word \"%s\" is unexpected for convert", W2S(word));
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch ((key_wid_t)word->id) {
        case KEY_WORD_CASCADED:
            alterdb_def->action = CONVERT_TO_STANDBY;
            status = sql_parse_convert_cascaded_standby(stmt, alterdb_def, word);
            break;

        case KEY_WORD_PHYSICAL:
            alterdb_def->action = CONVERT_TO_STANDBY;
            status = sql_parse_convert_physical_standby(stmt, alterdb_def, word);
            break;

        case KEY_WORD_READ_ONLY:
            alterdb_def->action = CONVERT_TO_READ_ONLY;
            status = OG_SUCCESS;
            break;

        case KEY_WORD_READ_WRITE:
            alterdb_def->action = CONVERT_TO_READ_WRITE;
            status = OG_SUCCESS;
            break;

        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for convert", W2S(word),
                word->loc.column);
            return OG_ERROR;
    }

    return status;
}

static status_t sql_parse_altdb_failover(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_try_fetch(lex, "force", &def->force_failover) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_altdb_switchover(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        def->switchover_timeout = 0;
        return OG_SUCCESS;
    }

    if ((key_wid_t)word->id != KEY_WORD_TIMEOUT) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "\"%s\" is unexpected for switchover", W2S(word));
        return OG_ERROR;
    }

    if (lex_expected_fetch_uint32(lex, &def->switchover_timeout) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (def->switchover_timeout != 0 &&
        (def->switchover_timeout < OG_MIN_SWITCHOVER_TIMEOUT || def->switchover_timeout > OG_MAX_SWITCHOVER_TIMEOUT)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "valid timeout range for switchover is 0 or [%u, %u]",
            OG_MIN_SWITCHOVER_TIMEOUT, OG_MAX_SWITCHOVER_TIMEOUT);
        return OG_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_altdb_set(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch(lex, word));

    /* altdb_set_dbtimezone */
    if ((key_wid_t)word->id == KEY_WORD_TIMEZONE) {
        def->action = ALTER_DB_TIMEZONE;
        return sql_parse_altdb_set_dbtimezone(stmt, def);
    }
    /* altdb_maximize_standby */
    def->action = MAXIMIZE_STANDBY_DB;
    OG_RETURN_IFERR(sql_parse_altdb_maximize_standby(stmt, def, word));

    return OG_SUCCESS;
}

static status_t sql_parse_altdb_rebuild_space(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    status_t status;

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if ((key_wid_t)word->id != KEY_WORD_TABLESPACE) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &def->rebuild_spc.space_name);
    OG_RETURN_IFERR(status);

    return lex_expected_end(lex);
}

static status_t sql_parse_altdb_cancel_upgrade(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "upgrade") != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_add_logfile(sql_stmt_t *stmt, lex_t *lex, knl_device_def_t *dev_def, word_t *word)
{
    if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != OG_SUCCESS) {
        cm_set_error_loc(word->text.loc);
        return OG_ERROR;
    }

    dev_def->autoextend.enabled = OG_FALSE;

    if (lex_expected_fetch_word(lex, "SIZE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_size(lex, &dev_def->size, OG_INVALID_INT64, OG_INVALID_INT64) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_try_parse_file_blocksize(lex, &dev_def->block_size) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_try_parse_logfile_instance(lex, &dev_def->node_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_archive_logfile(sql_stmt_t *stmt, lex_t *lex, knl_device_def_t *dev_def, word_t *word)
{
    if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != OG_SUCCESS) {
        cm_set_error_loc(word->text.loc);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_drop_logfile(sql_stmt_t *stmt, lex_t *lex, knl_device_def_t *dev_def, word_t *word)
{
    if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_copy_file_name(stmt->context, (text_t *)&word->text, &dev_def->name) != OG_SUCCESS) {
        cm_set_error_loc(word->text.loc);
        return OG_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_altdb_logfile(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    knl_device_def_t *log_file = NULL;
    status_t status;
    cm_galist_init(&def->logfile.logfiles, stmt->context, sql_alloc_mem);

    status = lex_try_fetch(lex, "STANDBY", &result);
    OG_RETURN_IFERR(status);

    if (result) {
        OG_SRC_THROW_ERROR(LEX_LOC, ERR_CAPABILITY_NOT_SUPPORT, "alter standby logfile");
        return OG_ERROR;
    }
    status = lex_expected_fetch_word(lex, "LOGFILE");
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch_bracket(lex, word);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    if (def->action == ADD_LOGFILE || def->action == ARCHIVE_LOGFILE) {
        for (;;) {
            status = cm_galist_new(&def->logfile.logfiles, sizeof(knl_device_def_t), (pointer_t *)&log_file);
            OG_BREAK_IF_ERROR(status);

            if (def->action == ADD_LOGFILE) {
                status = sql_parse_add_logfile(stmt, lex, log_file, word);
            } else {
                status = sql_parse_archive_logfile(stmt, lex, log_file, word);
            }
            OG_BREAK_IF_ERROR(status);

            status = lex_try_fetch_char(lex, ',', &result);
            OG_BREAK_IF_ERROR(status);
            OG_BREAK_IF_TRUE(!result);
        }
    } else {
        do {
            status = cm_galist_new(&def->logfile.logfiles, sizeof(knl_device_def_t), (pointer_t *)&log_file);
            OG_BREAK_IF_ERROR(status);
            status = sql_parse_drop_logfile(stmt, lex, log_file, word);
            OG_BREAK_IF_ERROR(status);
        } while (OG_FALSE);
    }

    lex_pop(lex);
    OG_RETURN_IFERR(status);
    return lex_expected_end(lex);
}


static status_t sql_parse_delete_archivelog_time(sql_stmt_t *stmt, knl_alterdb_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "time") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_string(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_text2date(&word->text.value, NULL, &def->dele_arch.until_time) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if ((key_wid_t)word->id == KEY_WORD_FORCE) {
        def->dele_arch.force_delete = OG_TRUE;
    } else if (word->type == WORD_TYPE_EOF) {
        def->dele_arch.force_delete = OG_FALSE;
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_altdb_delete_archivelog(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    word_t word;
    status_t status = OG_SUCCESS;

    if (lex_expected_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_ALL:
            if (lex_fetch(lex, &word) != OG_SUCCESS) {
                status = OG_ERROR;
            }

            def->dele_arch.all_delete = OG_TRUE;
            def->dele_arch.delete_abnormal = OG_FALSE;

            if ((key_wid_t)word.id == KEY_WORD_FORCE) {
                def->dele_arch.force_delete = OG_TRUE;
            } else if (word.type == WORD_TYPE_EOF) {
                def->dele_arch.force_delete = OG_FALSE;
            } else {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
                return OG_ERROR;
            }
            break;

        case KEY_WORD_UNTIL:
            def->dele_arch.all_delete = OG_FALSE;
            def->dele_arch.delete_abnormal = OG_FALSE;
            status = sql_parse_delete_archivelog_time(stmt, def, &word);
            break;
        
        case KEY_WORD_ABNORMAL:
            def->dele_arch.all_delete = OG_FALSE;
            def->dele_arch.delete_abnormal = OG_TRUE;
            break;

        default:
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            break;
    }

    return status;
}

static status_t sql_parse_altdb_delete_backupset(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    word_t word;

    if (lex_expected_fetch_word(lex, "TAG") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_backup_tag(stmt, &word, def->dele_bakset.tag) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if ((key_wid_t)word.id == KEY_WORD_FORCE) {
        def->dele_bakset.force_delete = OG_TRUE;
    } else if (word.type == WORD_TYPE_EOF) {
        def->dele_bakset.force_delete = OG_FALSE;
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_alterdb_delete(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def)
{
    lex_t *lex = stmt->session->lex;
    uint32 match_id;

    if (lex_expected_fetch_1of2(lex, "ARCHIVELOG", "BACKUPSET", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (match_id == 0) {
        alterdb_def->action = DELETE_ARCHIVELOG;
        return sql_parse_altdb_delete_archivelog(stmt, alterdb_def);
    } else {
        alterdb_def->action = DELETE_BACKUPSET;
        return sql_parse_altdb_delete_backupset(stmt, alterdb_def);
    }
}

static status_t sql_parse_alterdb_enable_logic_replication(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    status_t status;
    word_t word;

    status = lex_expected_fetch(lex, &word);
    OG_RETURN_IFERR(status);

    if ((key_wid_t)word.id != KEY_WORD_ON && (key_wid_t)word.id != KEY_WORD_OFF) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word \"%s\" found at %d is unexpected for protection mode",
            W2S(&word), word.loc.column);
        return OG_ERROR;
    }

    if ((key_wid_t)word.id == KEY_WORD_ON) {
        def->action = ENABLE_LOGIC_REPLICATION;
    } else {
        def->action = DISABLE_LOGIC_REPLICATION;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_alterdb_alter_charset(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def)
{
    lex_t *lex = stmt->session->lex;
    word_t word;
    uint16 charset_id;

#ifndef DB_DEBUG_VERSION

    OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "do not support character when alter database");
    return OG_ERROR;

#endif

    if (lex_expected_fetch_word(lex, "SET") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    charset_id = cm_get_charset_id_ex((text_t *)&word.text);
    if (charset_id == OG_INVALID_ID16) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid CHARACTER SET name");
        return OG_ERROR;
    }

    alterdb_def->action = ALTER_CHARSET;
    alterdb_def->charset_id = (uint32)charset_id;

    return OG_SUCCESS;
}


static status_t sql_parse_alterdb_key_fetch(sql_stmt_t *stmt, knl_alterdb_def_t *alterdb_def, word_t *word)
{
    status_t status = OG_ERROR;

    switch ((key_wid_t)word->id) {
        case KEY_WORD_MOUNT:
            alterdb_def->action = STARTUP_DATABASE_MOUNT;
            status = OG_SUCCESS;
            break;

        case KEY_WORD_OPEN:
            alterdb_def->action = STARTUP_DATABASE_OPEN;
            status = sql_parse_alterdb_alter_open(stmt, alterdb_def);
            break;

        case KEY_WORD_UPDATE:
            status = sql_parse_altdb_update_mk(stmt, alterdb_def);
            break;

        case KEY_WORD_TEMPFILE:
            alterdb_def->action = ALTER_TEMPFILE;
            status = sql_parse_altdb_alter_tempfile(stmt, alterdb_def, word);
            break;

        case KEY_WORD_DATAFILE:
            alterdb_def->action = ALTER_DATAFILE;
            status = sql_parse_alterdb_alter_datafile(stmt, alterdb_def);
            break;

        case KEY_WORD_SET:
            status = sql_parse_altdb_set(stmt, alterdb_def, word);
            break;

        case KEY_WORD_SWITCHOVER:
            alterdb_def->action = SWITCHOVER_STANDBY;
            status = sql_parse_altdb_switchover(stmt, alterdb_def, word);
            break;

        case KEY_WORD_FAILOVER:
            alterdb_def->action = FAILOVER_STANDBY;
            status = sql_parse_altdb_failover(stmt, alterdb_def, word);
            break;

        case KEY_WORD_CONVERT:
            status = sql_parse_altdb_convert(stmt, alterdb_def, word);
            break;

        case KEY_WORD_ARCHIVELOG:
            alterdb_def->action = DATABASE_ARCHIVELOG;
            status = OG_SUCCESS;
            break;

        case KEY_WORD_NOARCHIVELOG:
            alterdb_def->action = DATABASE_NOARCHIVELOG;
            status = OG_SUCCESS;
            break;

        case KEY_WORD_ADD:
            alterdb_def->action = ADD_LOGFILE;
            status = sql_parse_altdb_logfile(stmt, alterdb_def, word);
            break;

        case KEY_WORD_DROP:
            alterdb_def->action = DROP_LOGFILE;
            status = sql_parse_altdb_logfile(stmt, alterdb_def, word);
            break;

        case KEY_WORD_ARCHIVE:
            alterdb_def->action = ARCHIVE_LOGFILE;
            status = sql_parse_altdb_logfile(stmt, alterdb_def, word);
            break;

        case KEY_WORD_DELETE:
            status = sql_parse_alterdb_delete(stmt, alterdb_def);
            break;

        case KEY_WORD_ENABLE_LOGIC_REPLICATION:
            status = sql_parse_alterdb_enable_logic_replication(stmt, alterdb_def);
            break;

        case KEY_WORD_CHARACTER:
            status = sql_parse_alterdb_alter_charset(stmt, alterdb_def);
            break;

        case KEY_WORD_REBUILD:
            alterdb_def->action = REBUILD_TABLESPACE;
            status = sql_parse_altdb_rebuild_space(stmt, alterdb_def, word);
            break;

        case KEY_WORD_CANCEL:
            alterdb_def->action = CANCEL_UPGRADE;
            status = sql_parse_altdb_cancel_upgrade(stmt, alterdb_def);
            break;

        default:
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected, but %s found", W2S(word));
            return OG_ERROR;
    }

    if (status == OG_SUCCESS) {
        status = lex_expected_end(stmt->session->lex);
    }

    return status;
}

static status_t sql_parse_alterdb_clear(sql_stmt_t *stmt, knl_alterdb_def_t *def)
{
    def->action = DATABASE_CLEAR_LOGFILE;

    if (lex_expected_fetch_word(stmt->session->lex, "logfile") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_uint32(stmt->session->lex, &def->clear_logfile_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_expected_end(stmt->session->lex);
}


static status_t sql_parse_alter_database(sql_stmt_t *stmt)
{
    word_t word;
    knl_alterdb_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    char *db_name = NULL;
    text_t name;
    bool32 is_clear_logfile = OG_FALSE;
    status_t status;
    bool32 upgrade_pl;

    stmt->context->type = OGSQL_TYPE_ALTER_DATABASE;

    status = sql_alloc_mem(stmt->context, sizeof(knl_alterdb_def_t), (void **)&def);
    OG_RETURN_IFERR(status);

    stmt->context->entry = def;

    OG_RETURN_IFERR(lex_try_fetch2(lex, "UPGRADE", "PROCEDURE", &upgrade_pl));
    if (upgrade_pl) {
        def->action = UPGRADE_PROCEDURE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));

    if (IS_VARIANT(&word)) {
        status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &name);
        OG_RETURN_IFERR(status);

        db_name = knl_get_db_name(&stmt->session->knl_session);
        if (cm_text_str_equal(&name, db_name)) {
            def->name = name;
            def->is_named = OG_TRUE;
        } else if (cm_text_str_equal_ins(&name, "CLEAR")) {
            is_clear_logfile = OG_TRUE;
        }
    }

    if (def->is_named) {
        if (word.type != WORD_TYPE_KEYWORD) {
            status = lex_expected_fetch(lex, &word);
            OG_RETURN_IFERR(status);
        }

        status = sql_parse_alterdb_key_fetch(stmt, def, &word);
        OG_RETURN_IFERR(status);
    } else if (is_clear_logfile) {
        status = sql_parse_alterdb_clear(stmt, def);
        OG_RETURN_IFERR(status);
    } else {
        if (word.type == WORD_TYPE_KEYWORD) {
            status = sql_parse_alterdb_key_fetch(stmt, def, &word);
            OG_RETURN_IFERR(status);
        } else {
            if (knl_get_db_status(&stmt->session->knl_session) == DB_STATUS_NOMOUNT) {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "database name input is NOT supported in nomount status");
            } else {
                OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "name %s does not match actual database name", W2S(&word));
            }
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

// not support ,Reserved fuction sql_drop_database_lead return error
status_t sql_drop_database_lead(sql_stmt_t *stmt)
{
    {
        OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "DROP DATABASE");
        return OG_ERROR;
    }
}

status_t sql_parse_alter_database_lead(sql_stmt_t *stmt)
{
    {
        return sql_parse_alter_database(stmt);
    }
}

static status_t og_parse_createdb_user(sql_stmt_t *stmt, knl_database_def_t *def, createdb_user *user)
{
    text_t user_name;
    size_t passwd_len;
    char log_pwd[OG_PWD_BUFFER_SIZE] = {0};

    if (strlen(def->sys_password) != 0) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "sys user is already defined");
        return OG_ERROR;
    }

    user_name.str = user->user_name;
    user_name.len = strlen(user->user_name);
    if (!cm_text_str_equal(&user_name, "SYS")) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "user name SYS expected");
        return OG_ERROR;
    }

    passwd_len = strlen(user->password);
    if (passwd_len > OG_PASSWORD_BUFFER_SIZE - 1) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "The password length must be less than 512");
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_sp(def->sys_password, OG_PASSWORD_BUFFER_SIZE - 1, user->password, passwd_len));
    def->sys_password[OG_PASSWORD_BUFFER_SIZE - 1] = '\0';

    if (stmt->pl_exec == NULL && stmt->pl_compiler == NULL) { // can't modify sql in pl
        if (passwd_len != 0) {
            MEMS_RETURN_IFERR(memset_s(user->password, passwd_len, '*', passwd_len));
        }
    }

    if (cm_check_pwd_black_list(GET_PWD_BLACK_CTX, SYS_USER_NAME, def->sys_password, log_pwd)) {
        OG_THROW_ERROR_EX(ERR_PASSWORD_FORMAT_ERROR, "The password violates the pbl rule");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_parse_createdb_controlfile(knl_database_def_t *def, galist_t *ctrlfiles)
{
    if (def->ctrlfiles.count != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CONTROLFILE is already defined");
        return OG_ERROR;
    }
    return cm_galist_copy(&def->ctrlfiles, ctrlfiles);
}

static status_t og_parse_createdb_charset(sql_stmt_t *stmt, knl_database_def_t *def, char *charset)
{
    text_t raw;

    if (def->charset.len != 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CHARACTER SET is already defined");
        return OG_ERROR;
    }

    raw.str = charset;
    raw.len = strlen(charset);
    if (sql_copy_text(stmt->context, (text_t *)&raw, &def->charset) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_parse_createdb_space(knl_space_def_t *space_def, createdb_space *space)
{
    knl_device_def_t *dev_def = NULL;
    status_t status;

    if (space_def->datafiles.count != 0) {
        return OG_ERROR;
    }

    for (uint32 i = 0; i < space->datafiles->count; i++) {
        knl_device_def_t *cur = NULL;

        dev_def = (knl_device_def_t*)cm_galist_get(space->datafiles, i);
        for (uint32 j = 0; j < i; j++) {
            cur = (knl_device_def_t*)cm_galist_get(space->datafiles, j);
            if (cur != dev_def) {
                if (cm_text_equal_ins(&dev_def->name, &cur->name)) {
                    return OG_ERROR;
                }
            }

            status = sql_check_filesize(&space_def->name, dev_def);
            OG_RETURN_IFERR(status);
        }
    }
    status = cm_galist_copy(&space_def->datafiles, space->datafiles);
    OG_RETURN_IFERR(status);
    space_def->in_memory = space->in_memory;
    return OG_SUCCESS;
}

static status_t og_parse_node_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, createdb_space *space)
{
    char *name;
    errno_t code;

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (void **)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    code = snprintf_s(name, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "UNDO_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->undo_space.name.str = name;
    node->undo_space.name.len = (uint32)strlen(name);
    if (node->id == 0) {
        node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE0;
    } else {
        node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE1;
    }
    return og_parse_createdb_space(&node->undo_space, space);
}

static status_t og_parse_node_logfiles(galist_t *logfiles, galist_t *list)
{
    if (logfiles->count != 0) {
        return OG_ERROR;
    }
    return cm_galist_copy(logfiles, list);
}

static status_t og_parse_node_swap_space(sql_stmt_t *stmt, dtc_node_def_t *node, createdb_space *space)
{
    char *name;
    errno_t code;

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (void **)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    code = snprintf_s(name, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "SWAP_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->swap_space.name.str = name;
    node->swap_space.name.len = (uint32)strlen(name);
    if (node->id == 0) {
        node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE0;
    } else {
        node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT | SPACE_TYPE_NODE1;
    }
    return og_parse_createdb_space(&node->swap_space, space);
}

static status_t og_parse_node_temp_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, createdb_space *space)
{
    char *name;
    errno_t code;

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (void **)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }
    code = snprintf_s(name, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "TEMP_UNDO_%u1", node->id);
    PRTS_RETURN_IFERR(code);

    node->temp_undo_space.name.str = name;
    node->temp_undo_space.name.len = (uint32)strlen(name);
    if (node->id == 0) {
        node->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_TEMP | SPACE_TYPE_NODE0;
    } else {
        node->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_TEMP | SPACE_TYPE_NODE1;
    }
    return og_parse_createdb_space(&node->temp_undo_space, space);
}

static status_t og_parse_createdb_instance(sql_stmt_t *stmt, knl_database_def_t *def, galist_t *node_list)
{
    dtc_node_def_t *node = NULL;
    createdb_instance_node *inode = NULL;
    createdb_opt *opt = NULL;

    for (uint32 i = 0; i < node_list->count; i++) {
        inode = (createdb_instance_node*)cm_galist_get(node_list, i);
        if (inode->id != i) {
            return OG_ERROR;
        }

        if (cm_galist_new(&def->nodes, sizeof(dtc_node_def_t), (pointer_t *)&node) != OG_SUCCESS) {
            return OG_ERROR;
        }
        node->id = def->nodes.count - 1;
        cm_galist_init(&node->logfiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->undo_space.datafiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->swap_space.datafiles, stmt->context, sql_alloc_mem);
        cm_galist_init(&node->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);

        for (uint32 j = 0; j < inode->opts->count; j++) {
            opt = (createdb_opt*)cm_galist_get(inode->opts, j);
            switch (opt->type) {
                case CREATEDB_INSTANCE_NODE_UNDO_OPT:
                    if (og_parse_node_undo_space(stmt, node, &opt->space) != OG_SUCCESS) {
                        return OG_ERROR;
                    }
                    break;
                case CREATEDB_INSTANCE_NODE_LOGFILE_OPT:
                    if (og_parse_node_logfiles(&node->logfiles, opt->list) != OG_SUCCESS) {
                        return OG_ERROR;
                    }
                    break;
                case CREATEDB_INSTANCE_NODE_TEMPORARY_OPT:
                    if (og_parse_node_swap_space(stmt, node, &opt->space) != OG_SUCCESS) {
                        return OG_ERROR;
                    }
                    break;
                case CREATEDB_INSTANCE_NODE_NOLOGGING_OPT:
                    if (og_parse_node_temp_undo_space(stmt, node, &opt->space) != OG_SUCCESS) {
                        return OG_ERROR;
                    }
                    break;
                default:
                    return OG_SUCCESS;
            }
        }
    }
    return OG_SUCCESS;
}

status_t og_parse_create_database(sql_stmt_t *stmt, knl_database_def_t **def, char *db_name, galist_t *db_opts)
{
    status_t status;
    archive_mode_t arch_mode = ARCHIVE_LOG_OFF;
    createdb_opt *opt = NULL;
    knl_space_def_t *space_def = NULL;
    knl_database_def_t *db_def = NULL;

    SQL_SET_IGNORE_PWD(stmt->session);
    status = sql_alloc_mem(stmt->context, sizeof(knl_database_def_t), (pointer_t *)def);
    OG_RETURN_IFERR(status);
    db_def = *def;

    stmt->context->type = OGSQL_TYPE_CREATE_CLUSTERED_DATABASE;

    cm_galist_init(&db_def->ctrlfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->nodes, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->system_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->user_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->temp_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&db_def->sysaux_space.datafiles, stmt->context, sql_alloc_mem);

    db_def->system_space.name = g_system;
    db_def->system_space.type = SPACE_TYPE_SYSTEM | SPACE_TYPE_DEFAULT;
    db_def->user_space.name = g_users;
    db_def->user_space.type = SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    db_def->temp_space.name = g_temp;
    db_def->temp_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    db_def->temp_undo_space.name = g_temp_undo;
    db_def->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT;
    db_def->sysaux_space.name = g_sysaux;
    db_def->sysaux_space.type = SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT;
    db_def->max_instance = OG_DEFAULT_INSTANCE;

    db_def->name.str = db_name;
    db_def->name.len = strlen(db_name);

    for (uint32 i = 0; i < db_opts->count; i++) {
        opt = (createdb_opt*)cm_galist_get(db_opts, i);

        switch (opt->type) {
            case CREATEDB_USER_OPT:
                status = og_parse_createdb_user(stmt, db_def, &opt->user);
                break;
            case CREATEDB_CONTROLFILE_OPT:
                status = og_parse_createdb_controlfile(db_def, opt->list);
                break;
            case CREATEDB_CHARSET_OPT:
                status = og_parse_createdb_charset(stmt, db_def, opt->charset);
                break;
            case CREATEDB_ARCHIVELOG_OPT:
                arch_mode = opt->archivelog_enable;
                break;
            case CREATEDB_DEFAULT_OPT:
                space_def = &db_def->user_space;
                space_def->name = g_users;
                status = og_parse_createdb_space(space_def, &opt->space);
                break;
            case CREATEDB_NOLOGGING_UNDO_OPT:
                space_def = &db_def->temp_undo_space;
                space_def->name = g_temp_undo;
                status = og_parse_createdb_space(space_def, &opt->space);
                break;
            case CREATEDB_NOLOGGING_OPT:
                space_def = &db_def->temp_space;
                space_def->name = g_temp;
                status = og_parse_createdb_space(space_def, &opt->space);
                break;
            case CREATEDB_SYSAUX_OPT:
                space_def = &db_def->sysaux_space;
                space_def->name = g_sysaux;
                status = og_parse_createdb_space(space_def, &opt->space);
                break;
            case CREATEDB_SYSTEM_OPT:
                space_def = &db_def->system_space;
                space_def->name = g_system;
                status = og_parse_createdb_space(space_def, &opt->space);
                break;
            case CREATEDB_INSTANCE_OPT:
                status = og_parse_createdb_instance(stmt, db_def, opt->list);
                break;
            case CREATEDB_MAXINSTANCE_OPT:
                db_def->max_instance = opt->max_instance;
                break;
            default:
                return OG_ERROR;
        }
        if (status != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    db_def->arch_mode = arch_mode;
    status = sql_set_database_default(stmt, db_def, true);
    OG_RETURN_IFERR(status);

    return dtc_verify_database_def(stmt, db_def);
}
