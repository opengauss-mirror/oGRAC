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
 * ogsql_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_parser.h"
#include "dml_parser.h"
#include "ddl_parser.h"
#include "dcl_parser.h"
#include "srv_instance.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "ogsql_audit.h"
#include "dml_executor.h"

#ifdef __cplusplus
extern "C" {
#endif


#define SQL_REFORM_CALL_HEAD_SIZE 6
#define SQL_COMMENT_MARK_LEN 2
#define SQL_LABEL_MARK_LEN 2

typedef struct st_sql_bison_diag_keyword {
    const char *name;
    key_wid_t id;
} sql_bison_diag_keyword_t;

static const sql_bison_diag_keyword_t g_sql_bison_diag_keywords[] = {
    { "alter", KEY_WORD_ALTER },
    { "analyze", KEY_WORD_ANALYZE },
    { "backup", KEY_WORD_BACKUP },
    { "begin", KEY_WORD_BEGIN },
    { "build", KEY_WORD_BUILD },
    { "call", KEY_WORD_CALL },
    { "comment", KEY_WORD_COMMENT },
    { "commit", KEY_WORD_COMMIT },
    { "create", KEY_WORD_CREATE },
    { "declare", KEY_WORD_DECLARE },
    { "delete", KEY_WORD_DELETE },
    { "drop", KEY_WORD_DROP },
    { "end", KEY_WORD_END },
    { "exec", KEY_WORD_EXEC },
    { "execute", KEY_WORD_EXECUTE },
    { "explain", KEY_WORD_EXPLAIN },
    { "flashback", KEY_WORD_FLASHBACK },
    { "grant", KEY_WORD_GRANT },
    { "insert", KEY_WORD_INSERT },
    { "lock", KEY_WORD_LOCK },
    { "merge", KEY_WORD_MERGE },
    { "ograc", KEY_WORD_OGRAC },
    { "prepare", KEY_WORD_PREPARE },
    { "purge", KEY_WORD_PURGE },
    { "recover", KEY_WORD_RECOVER },
    { "release", KEY_WORD_RELEASE },
    { "repair_copyctrl", KEY_WORD_REPAIR_COPYCTRL },
    { "repair_page", KEY_WORD_REPAIR_PAGE },
    { "replace", KEY_WORD_REPLACE },
    { "restore", KEY_WORD_RESTORE },
    { "revoke", KEY_WORD_REVOKE },
    { "rollback", KEY_WORD_ROLLBACK },
    { "savepoint", KEY_WORD_SAVEPOINT },
    { "select", KEY_WORD_SELECT },
    { "session", KEY_WORD_SESSION },
    { "set", KEY_WORD_SET },
    { "shutdown", KEY_WORD_SHUTDOWN },
    { "start", KEY_WORD_START },
#ifdef DB_DEBUG_VERSION
    { "syncpoint", KEY_WORD_SYNCPOINT },
#endif
    { "system", KEY_WORD_SYSTEM },
    { "transaction", KEY_WORD_TRANSACTION },
    { "truncate", KEY_WORD_TRUNCATE },
    { "update", KEY_WORD_UPDATE },
    { "validate", KEY_WORD_VALIDATE },
    { "with", KEY_WORD_WITH },
};

static void sql_skip_blank_chars(text_t *text, uint32 *pos)
{
    while (*pos < text->len && cm_is_space((int)text->str[*pos])) {
        (*pos)++;
    }
}

static bool32 sql_is_name_char(char ch)
{
    return (bool32)(CM_IS_NAMING_LETER(ch) || CM_IS_DIGIT(ch) || ch == '$' || ch == '#' || ch == '_');
}

static status_t sql_read_call_name_part(text_t *text, uint32 *pos, text_t *part)
{
    uint32 start;

    part->str = NULL;
    part->len = 0;
    sql_skip_blank_chars(text, pos);
    if (*pos >= text->len) {
        return OG_SUCCESS;
    }

    if (text->str[*pos] == '"') {
        (*pos)++;
        start = *pos;
        while (*pos < text->len && text->str[*pos] != '"') {
            (*pos)++;
        }
        if (*pos >= text->len) {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid quoted procedure name");
            return OG_ERROR;
        }
        part->str = text->str + start;
        part->len = *pos - start;
        (*pos)++;
        return OG_SUCCESS;
    }

    start = *pos;
    while (*pos < text->len) {
        char ch = text->str[*pos];
        if (!sql_is_name_char(ch)) {
            break;
        }
        (*pos)++;
    }
    if (*pos > start) {
        part->str = text->str + start;
        part->len = *pos - start;
    }
    return OG_SUCCESS;
}

sql_text_t *sql_current_parse_text(sql_stmt_t *stmt)
{
    if (g_instance->sql.use_bison_parser && stmt->parser_text_valid) {
        return &stmt->parser_text;
    }
    return &stmt->session->lex->text;
}

static void sql_bison_skip_comment(text_t *sql, uint32 *pos)
{
    if (*pos + 1 >= sql->len) {
        return;
    }
    if (sql->str[*pos] == '-' && sql->str[*pos + 1] == '-') {
        *pos += SQL_COMMENT_MARK_LEN;
        while (*pos < sql->len && sql->str[*pos] != '\n') {
            (*pos)++;
        }
        return;
    }
    if (sql->str[*pos] == '/' && sql->str[*pos + 1] == '*') {
        *pos += SQL_COMMENT_MARK_LEN;
        while (*pos + 1 < sql->len) {
            if (sql->str[*pos] == '*' && sql->str[*pos + 1] == '/') {
                *pos += SQL_COMMENT_MARK_LEN;
                return;
            }
            (*pos)++;
        }
    }
}

static void sql_bison_skip_blank_and_comments(text_t *sql, uint32 *pos)
{
    while (*pos < sql->len) {
        while (*pos < sql->len && cm_is_space((int)sql->str[*pos])) {
            (*pos)++;
        }
        if (*pos + 1 >= sql->len ||
            !((sql->str[*pos] == '-' && sql->str[*pos + 1] == '-') ||
            (sql->str[*pos] == '/' && sql->str[*pos + 1] == '*'))) {
            return;
        }
        sql_bison_skip_comment(sql, pos);
    }
}

static key_wid_t sql_bison_keyword_id(text_t *word)
{
    for (uint32 i = 0; i < ELEMENT_COUNT(g_sql_bison_diag_keywords); i++) {
        if (cm_text_str_equal_ins(word, g_sql_bison_diag_keywords[i].name)) {
            return g_sql_bison_diag_keywords[i].id;
        }
    }
    return KEY_WORD_0_UNKNOWN;
}

static void sql_bison_read_word(sql_text_t *sql_text, uint32 *pos, word_t *word)
{
    text_t sql = sql_text->value;
    uint32 start;
    key_wid_t key_wid;

    *word = (word_t){ 0 };
    sql_bison_skip_blank_and_comments(&sql, pos);
    word->loc = sql_text->loc;
    word->text.loc = sql_text->loc;
    if (*pos >= sql.len) {
        word->type = WORD_TYPE_EOF;
        return;
    }

    start = *pos;
    if (sql.str[*pos] == '(') {
        word->type = WORD_TYPE_BRACKET;
        word->id = KEY_WORD_SELECT;
        word->text.str = sql.str + start;
        word->text.len = sql.len - start;
        return;
    }
    if (*pos + 1 < sql.len && sql.str[*pos] == '<' && sql.str[*pos + 1] == '<') {
        word->type = WORD_TYPE_KEYWORD;
        word->id = KEY_WORD_DECLARE;
        word->text.str = sql.str + start;
        word->text.len = SQL_LABEL_MARK_LEN;
        *pos += SQL_LABEL_MARK_LEN;
        return;
    }

    while (*pos < sql.len && sql_is_name_char(sql.str[*pos])) {
        (*pos)++;
    }
    word->text.str = sql.str + start;
    word->text.len = *pos - start;
    key_wid = sql_bison_keyword_id(&word->text.value);
    word->id = key_wid;
    word->type = (key_wid == KEY_WORD_0_UNKNOWN) ? WORD_TYPE_VARIANT : WORD_TYPE_KEYWORD;
}

static lang_type_t sql_diag_begin_type_bison(sql_text_t *sql, uint32 pos)
{
    word_t word;

    sql_bison_read_word(sql, &pos, &word);
    if (word.type == WORD_TYPE_EOF || word.id == KEY_WORD_TRANSACTION) {
        return LANG_DCL;
    }
    return LANG_PL;
}

static lang_type_t sql_diag_alter_type_bison(sql_text_t *sql, uint32 pos)
{
    word_t word;

    sql_bison_read_word(sql, &pos, &word);
    if (word.id == KEY_WORD_SYSTEM || word.id == KEY_WORD_SESSION) {
        return LANG_DCL;
    }
    return LANG_DDL;
}

static lang_type_t sql_diag_direct_lang_type_bison(key_wid_t word_id)
{
    switch (word_id) {
        case KEY_WORD_SELECT:
        case KEY_WORD_INSERT:
        case KEY_WORD_UPDATE:
        case KEY_WORD_DELETE:
        case KEY_WORD_MERGE:
        case KEY_WORD_WITH:
        case KEY_WORD_REPLACE:
            return LANG_DML;
        case KEY_WORD_EXPLAIN:
            return LANG_EXPLAIN;
        case KEY_WORD_DECLARE:
        case KEY_WORD_CALL:
        case KEY_WORD_EXEC:
        case KEY_WORD_EXECUTE:
            return LANG_PL;
        default:
            return LANG_INVALID;
    }
}

static bool32 sql_diag_is_ddl_bison(key_wid_t word_id)
{
    switch (word_id) {
        case KEY_WORD_CREATE:
        case KEY_WORD_DROP:
        case KEY_WORD_TRUNCATE:
        case KEY_WORD_FLASHBACK:
        case KEY_WORD_PURGE:
        case KEY_WORD_COMMENT:
        case KEY_WORD_GRANT:
        case KEY_WORD_REVOKE:
        case KEY_WORD_ANALYZE:
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
}

static bool32 sql_diag_is_dcl_bison(key_wid_t word_id)
{
    switch (word_id) {
        case KEY_WORD_START:
        case KEY_WORD_END:
        case KEY_WORD_PREPARE:
        case KEY_WORD_COMMIT:
        case KEY_WORD_SAVEPOINT:
        case KEY_WORD_RELEASE:
        case KEY_WORD_SET:
        case KEY_WORD_ROLLBACK:
        case KEY_WORD_BACKUP:
        case KEY_WORD_RESTORE:
        case KEY_WORD_RECOVER:
        case KEY_WORD_OGRAC:
        case KEY_WORD_SHUTDOWN:
        case KEY_WORD_BUILD:
        case KEY_WORD_VALIDATE:
        case KEY_WORD_REPAIR_PAGE:
        case KEY_WORD_REPAIR_COPYCTRL:
#ifdef DB_DEBUG_VERSION
        case KEY_WORD_SYNCPOINT:
#endif
        case KEY_WORD_LOCK:
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
}

static lang_type_t sql_diag_lang_type_bison(sql_text_t *sql, word_t *leader_word)
{
    uint32 pos = 0;
    lang_type_t lang_type;

    sql_bison_read_word(sql, &pos, leader_word);
    if (leader_word->type == WORD_TYPE_EOF) {
        return LANG_INVALID;
    }

    lang_type = sql_diag_direct_lang_type_bison(leader_word->id);
    if (lang_type != LANG_INVALID) {
        return lang_type;
    }
    if (leader_word->id == KEY_WORD_BEGIN) {
        return sql_diag_begin_type_bison(sql, pos);
    }
    if (leader_word->id == KEY_WORD_ALTER) {
        return sql_diag_alter_type_bison(sql, pos);
    }
    if (sql_diag_is_ddl_bison(leader_word->id)) {
        return LANG_DDL;
    }
    return sql_diag_is_dcl_bison(leader_word->id) ? LANG_DCL : LANG_INVALID;
}

static status_t sql_aud_proc_check_text(sql_stmt_t *stmt, word_t *leader)
{
    text_t clean_aud_log_name = {
        .str = "AUD$CLEAN_AUD_LOG",
        .len = 17
    };
    text_t modify_setting_name = {
        .str = "AUD$MODIFY_SETTING",
        .len = 18
    };
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    text_t *curr_user = &stmt->session->curr_user;
    text_t sql = sql_current_parse_text(stmt)->value;
    text_t first;
    text_t second;
    text_t owner;
    text_t name;
    char owner_buf[OG_NAME_BUFFER_SIZE];
    uint32 pos = (uint32)((leader->text.value.str + leader->text.value.len) - sql.str);

    OG_RETURN_IFERR(sql_read_call_name_part(&sql, &pos, &first));
    if (first.len == 0 || cm_text_str_equal_ins(&first, "immediate")) {
        return OG_SUCCESS;
    }

    sql_skip_blank_chars(&sql, &pos);
    if (pos < sql.len && sql.str[pos] == '.') {
        pos++;
        OG_RETURN_IFERR(sql_read_call_name_part(&sql, &pos, &second));
        if (second.len == 0) {
            return OG_SUCCESS;
        }
        OG_RETURN_IFERR(cm_text2str(&first, owner_buf, OG_NAME_BUFFER_SIZE));
        OG_RETURN_IFERR(sql_user_prefix_tenant(stmt->session, owner_buf));
        cm_str2text_safe(owner_buf, (uint32)strlen(owner_buf), &owner);
        name = second;
    } else {
        owner.str = stmt->session->curr_schema;
        owner.len = (uint32)strlen(stmt->session->curr_schema);
        name = first;
    }

    if ((cm_compare_text_ins(&name, &modify_setting_name) == 0) ||
        (cm_compare_text_ins(&name, &clean_aud_log_name) == 0)) {
        if (cm_compare_text_ins(&owner, &sys_user_name) == 0) {
            if (cm_compare_text_ins(curr_user, &sys_user_name) != 0) {
                OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "The common user can't call this procedure, only for sys.");
                return OG_ERROR;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t sql_reform_call(sql_stmt_t *stmt)
{
    sql_text_t origin_sql;
    uint32 buf_len = stmt->session->lex->curr_text->len + (uint32)strlen("begin\n") + (uint32)strlen(";\nend;\n/");
    char *buffer = NULL;

    OG_RETURN_IFERR(sql_push(stmt, buf_len, (void **)&buffer));
    text_t sql = {
        .str = buffer,
        .len = 0
    };
    source_location_t loc = {
        .line = 0,
        .column = 1
    };
    status_t status;

    // save origin sql like 'call proc'
    origin_sql = stmt->session->lex->text;

    cm_concat_string(&sql, buf_len, "begin\n");
    cm_concat_text(&sql, buf_len, &stmt->session->lex->curr_text->value);
    cm_concat_string(&sql, buf_len, ";\nend;\n/");
    stmt->is_reform_call = OG_TRUE;
    stmt->text_shift =
        (int32)(stmt->session->lex->curr_text->str - stmt->session->lex->text.str) - SQL_REFORM_CALL_HEAD_SIZE;

    status = sql_parse(stmt, &sql, &loc);

    // recovery origin sql like 'call proc' avoid to record wrong audit log
    stmt->session->sql_audit.sql = origin_sql.value;

    return status;
}

static status_t sql_aud_proc_check(sql_stmt_t *stmt, word_t *leader)
{
    text_t clean_aud_log_name = {
        .str = "AUD$CLEAN_AUD_LOG",
        .len = 17
    };
    text_t modify_setting_name = {
        .str = "AUD$MODIFY_SETTING",
        .len = 18
    };
    text_t sys_user_name = {
        .str = SYS_USER_NAME,
        .len = SYS_USER_NAME_LEN
    };
    text_t *curr_user = &stmt->session->curr_user;
    text_t owner;
    text_t name;
    char buffer[OG_NAME_BUFFER_SIZE];
    lex_t *lex = stmt->session->lex;
    word_t word;
    LEX_SAVE(lex);
    uint32 prev_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    if (word.ex_count == 1) {
        OG_RETURN_IFERR(cm_text2str(&word.text.value, buffer, OG_MAX_NAME_LEN));
        OG_RETURN_IFERR(sql_user_prefix_tenant(stmt->session, buffer));
        cm_str2text_safe(buffer, (uint32)strlen(buffer), &owner);
        name = word.ex_words[0].text.value;
    } else if (word.ex_count == 0) {
        owner.str = stmt->session->curr_schema;
        owner.len = (uint32)strlen(stmt->session->curr_schema);
        name = word.text.value;
    } else {
        LEX_RESTORE(lex);
        lex->flags = prev_flags;
        return OG_SUCCESS;
    }
    if ((cm_compare_text_ins(&name, &modify_setting_name) == 0) ||
        (cm_compare_text_ins(&name, &clean_aud_log_name) == 0)) {
        if (cm_compare_text_ins(&owner, &sys_user_name) == 0) {
            if (cm_compare_text_ins(curr_user, &sys_user_name) != 0) {
                LEX_RESTORE(lex);
                lex->flags = prev_flags;
                OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "The common user can't call this procedure, only for sys.");
                return OG_ERROR;
            }
        }
    }
    LEX_RESTORE(lex);
    lex->flags = prev_flags;
    return OG_SUCCESS;
}

static status_t sql_parse_anonymous(sql_stmt_t *stmt, word_t *leader)
{
    if (!GET_PL_MGR->initialized) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return OG_ERROR;
    }

    {
        OG_RETURN_IFERR(sql_parse_anonymous_directly(stmt, leader, &stmt->session->lex->text));
    }

    return OG_SUCCESS;
}

static status_t sql_parse_pl_bison_text(sql_stmt_t *stmt, sql_text_t *sql_text)
{
    status_t status;
    text_t origin_sql = sql_text->value;

    if (!GET_PL_MGR->initialized) {
        OG_THROW_ERROR(ERR_DATABASE_NOT_AVAILABLE);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_alloc_context(stmt));
    OG_RETURN_IFERR(sql_create_list(stmt, &stmt->context->params));
    OG_RETURN_IFERR(sql_create_list(stmt, &stmt->context->ref_objects));

    status = raw_parser(stmt, sql_text, &stmt->context->entry);
    if (status != OG_SUCCESS) {
        return status;
    }

    if (!SQL_OPT_PWD_DDL_TYPE(stmt->context->type)) {
        OG_RETURN_IFERR(ogx_write_text(&stmt->context->ctrl, &origin_sql));
        stmt->context->ctrl.hash_value = cm_hash_text(&origin_sql, INFINITE_HASH_RANGE);
    }

    return OG_SUCCESS;
}

static status_t sql_parse_pl_bison(sql_stmt_t *stmt)
{
    return sql_parse_pl_bison_text(stmt, sql_current_parse_text(stmt));
}

static status_t sql_reform_pl_text_bison(sql_stmt_t *stmt, text_t *body, source_location_t loc, int32 text_shift)
{
    sql_text_t reform_sql = { 0 };
    uint32 buf_len = body->len + (uint32)strlen("begin\n") + (uint32)strlen(";\nend;\n/");
    char *buffer = NULL;
    status_t status;

    OG_RETURN_IFERR(sql_push(stmt, buf_len, (void **)&buffer));
    reform_sql.str = buffer;
    reform_sql.len = 0;
    reform_sql.loc = loc;
    reform_sql.implicit = OG_FALSE;

    cm_concat_string((text_t *)&reform_sql, buf_len, "begin\n");
    cm_concat_text((text_t *)&reform_sql, buf_len, body);
    cm_concat_string((text_t *)&reform_sql, buf_len, ";\nend;\n/");

    stmt->is_reform_call = OG_TRUE;
    stmt->text_shift = text_shift;
    status = sql_parse_pl_bison_text(stmt, &reform_sql);
    stmt->session->sql_audit.sql = sql_current_parse_text(stmt)->value;
    return status;
}

static status_t sql_reform_call_bison(sql_stmt_t *stmt, word_t *leader)
{
    sql_text_t *origin_sql = sql_current_parse_text(stmt);
    uint32 body_offset = (uint32)((leader->text.value.str + leader->text.value.len) - origin_sql->str);
    text_t body = {
        .str = origin_sql->str + body_offset,
        .len = origin_sql->len - body_offset
    };
    source_location_t loc = {
        .line = 0,
        .column = 1
    };

    return sql_reform_pl_text_bison(stmt, &body, loc, (int32)body_offset - SQL_REFORM_CALL_HEAD_SIZE);
}

static status_t sql_reform_execute_immediate_bison(sql_stmt_t *stmt)
{
    sql_text_t *origin_sql = sql_current_parse_text(stmt);
    source_location_t loc = {
        .line = 0,
        .column = 1
    };

    return sql_reform_pl_text_bison(stmt, &origin_sql->value, loc, -SQL_REFORM_CALL_HEAD_SIZE);
}

static bool32 sql_is_execute_immediate(sql_stmt_t *stmt, word_t *leader)
{
    sql_text_t *sql_text = sql_current_parse_text(stmt);
    text_t sql = sql_text->value;
    uint32 pos = (uint32)((leader->text.value.str + leader->text.value.len) - sql.str);
    uint32 immediate_len = (uint32)strlen("immediate");

    if (leader->id != KEY_WORD_EXECUTE) {
        return OG_FALSE;
    }

    sql_skip_blank_chars(&sql, &pos);
    return (bool32)(pos + immediate_len <= sql.len &&
        cm_strcmpni(sql.str + pos, "immediate", immediate_len) == 0 &&
        (pos + immediate_len == sql.len || !sql_is_name_char(sql.str[pos + immediate_len])));
}

static bool32 sql_need_reform_pl_call(sql_stmt_t *stmt, word_t *leader)
{
    return leader->id == KEY_WORD_CALL || leader->id == KEY_WORD_EXEC ||
        (leader->id == KEY_WORD_EXECUTE && !sql_is_execute_immediate(stmt, leader));
}

static status_t sql_parse_pl(sql_stmt_t *stmt, word_t *leader)
{
    status_t status;

    SQL_SET_IGNORE_PWD(stmt->session);
    SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
    if (leader->id == KEY_WORD_CALL || leader->id == KEY_WORD_EXEC || leader->id == KEY_WORD_EXECUTE) {
        if (g_instance->sql.use_bison_parser) {
            OG_RETURN_IFERR(sql_aud_proc_check_text(stmt, leader));
        } else {
            OG_RETURN_IFERR(sql_aud_proc_check(stmt, leader));
        }
    }
    // maybe need load entity from proc$
    knl_set_session_scn(&stmt->session->knl_session, OG_INVALID_ID64);
    stmt->session->sql_audit.audit_type = SQL_AUDIT_PL;

    OGSQL_SAVE_STACK(stmt);
    if (g_instance->sql.use_bison_parser) {
        if (sql_is_execute_immediate(stmt, leader)) {
            status = sql_reform_execute_immediate_bison(stmt);
        } else {
            status = sql_need_reform_pl_call(stmt, leader) ?
                sql_reform_call_bison(stmt, leader) : sql_parse_pl_bison(stmt);
        }
    } else if (sql_need_reform_pl_call(stmt, leader)) {
        status = sql_reform_call(stmt);
    } else {
        status = sql_parse_anonymous(stmt, leader);
    }
    OGSQL_RESTORE_STACK(stmt);

    return status;
}

static lang_type_t sql_diag_begin_type(sql_stmt_t *stmt)
{
    word_t word;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != OG_SUCCESS) {
        return LANG_INVALID;
    }

    if (lex_fetch(stmt->session->lex, &word) != OG_SUCCESS) {
        lex_pop(stmt->session->lex);
        return LANG_INVALID;
    }
    lex_pop(stmt->session->lex);
    if (word.type == WORD_TYPE_EOF || word.id == KEY_WORD_TRANSACTION) {
        return LANG_DCL;
    }
    return LANG_PL;
}
static lang_type_t sql_diag_alter_type(sql_stmt_t *stmt)
{
    uint32 matched_id;

    if (lex_push(stmt->session->lex, stmt->session->lex->curr_text) != OG_SUCCESS) {
        return LANG_DDL;
    }
    if (lex_try_fetch_1of2(stmt->session->lex, "SYSTEM", "SESSION", &matched_id) != OG_SUCCESS) {
        lex_pop(stmt->session->lex);
        return LANG_DDL;
    } else {
        if (matched_id != OG_INVALID_ID32) {
            lex_pop(stmt->session->lex);
            return LANG_DCL;
        }
    }
    lex_pop(stmt->session->lex);
    return LANG_DDL;
}

lang_type_t sql_diag_lang_type(sql_stmt_t *stmt, sql_text_t *sql, word_t *leader_word)
{
    if (g_instance->sql.use_bison_parser) {
        return sql_diag_lang_type_bison(sql, leader_word);
    }

    lex_init_for_native_type(stmt->session->lex, sql, &stmt->session->curr_user, stmt->session->call_version,
        USE_NATIVE_DATATYPE);

    OG_RETVALUE_IFTRUE((lex_fetch(stmt->session->lex, leader_word) != OG_SUCCESS), LANG_INVALID);

    /* sql text enclosed by brackets must be select statement */
    if (leader_word->type == WORD_TYPE_BRACKET) {
        leader_word->id = KEY_WORD_SELECT;
    }

    if (IS_PL_LABEL(leader_word)) {
        leader_word->id = KEY_WORD_DECLARE;
    }

    switch (leader_word->id) {
        case KEY_WORD_SELECT:
        case KEY_WORD_INSERT:
        case KEY_WORD_UPDATE:
        case KEY_WORD_DELETE:
        case KEY_WORD_MERGE:
        case KEY_WORD_WITH:
        case KEY_WORD_REPLACE:
            return LANG_DML;
        case KEY_WORD_EXPLAIN:
            return LANG_EXPLAIN;
        case KEY_WORD_DECLARE:
        case KEY_WORD_CALL:
        case KEY_WORD_EXEC:
        case KEY_WORD_EXECUTE:
            return LANG_PL;
        /* pgs protocol special */
        case KEY_WORD_BEGIN:
            return sql_diag_begin_type(stmt);
        case KEY_WORD_START:
        case KEY_WORD_END:
            return LANG_DCL;
        case KEY_WORD_CREATE:
        case KEY_WORD_DROP:
        case KEY_WORD_TRUNCATE:
        case KEY_WORD_FLASHBACK:
        case KEY_WORD_PURGE:
        case KEY_WORD_COMMENT:
        case KEY_WORD_GRANT:
        case KEY_WORD_REVOKE:
        case KEY_WORD_ANALYZE:
            return LANG_DDL;
        case KEY_WORD_ALTER:
            return sql_diag_alter_type(stmt);
        case KEY_WORD_PREPARE:
        case KEY_WORD_COMMIT:
        case KEY_WORD_SAVEPOINT:
        case KEY_WORD_RELEASE:
        case KEY_WORD_SET:
        case KEY_WORD_ROLLBACK:
        case KEY_WORD_BACKUP:
        case KEY_WORD_RESTORE:
        case KEY_WORD_RECOVER:
        case KEY_WORD_OGRAC:
        case KEY_WORD_SHUTDOWN:
        case KEY_WORD_BUILD:
        // case KEY_WORD_CHECKPOINT:
        case KEY_WORD_VALIDATE:
        case KEY_WORD_REPAIR_PAGE:
        case KEY_WORD_REPAIR_COPYCTRL:
#ifdef DB_DEBUG_VERSION
        case KEY_WORD_SYNCPOINT:
#endif /* DB_DEBUG_VERSION */
        case KEY_WORD_LOCK:
            return LANG_DCL;

        default:
            return LANG_INVALID;
    }
}

sql_parser_t g_sql_parser[] = { { LANG_DML,         sql_parse_dml },
                                { LANG_DCL,         sql_parse_dcl },
                                { LANG_DDL,         sql_parse_ddl },
                                { LANG_PL,          sql_parse_pl },
                                { LANG_EXPLAIN,     ogsql_parse_explain_sql } };

static status_t sql_parse_by_lang_type(sql_stmt_t *stmt, sql_text_t *sql_text, word_t *leader_word)
{
    status_t status;

    if (stmt->lang_type < LANG_MAX && stmt->lang_type != LANG_INVALID) {
        status = g_sql_parser[stmt->lang_type - LANG_DML].sql_parse(stmt, leader_word);
    } else {
        OG_SRC_THROW_ERROR(sql_text->loc, ERR_SQL_SYNTAX_ERROR, "key word expected");
        status = OG_ERROR;
    }

    text_t sql_log_text = stmt->session->sql_audit.sql;
    if (LOG_DEBUG_ERR_ON || LOG_DEBUG_INF_ON) {
        sql_ignore_passwd_log(stmt->session, &sql_log_text);
    }
    sql_free_vmemory(stmt);

    if (status != OG_SUCCESS) {
        sql_unlock_lnk_tabs(stmt);
        sql_release_context(stmt);
        OBJ_STACK_RESET(&stmt->ssa_stack);
        OBJ_STACK_RESET(&stmt->node_stack);
        OG_LOG_DEBUG_ERR("Parse SQL failed, SQL = %s", T2S(&sql_log_text));
    } else {
        OG_LOG_DEBUG_INF("Parse SQL successfully, SQL = %s", T2S(&sql_log_text));
    }

    return status;
}

static status_t sql_parse_core(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    sql_text_t sql_text;
    word_t leader_word;
    status_t status;
    timeval_t timeval_end;
    timeval_t timeval_begin;
    sql_text_t parser_text_bak = stmt->parser_text;
    bool32 parser_text_valid_bak = stmt->parser_text_valid;

    stmt->pl_failed = OG_FALSE;
    stmt->bison_pl_create_pending = OG_FALSE;
    stmt->session->sql_audit.sql = *sql;

    sql_text.value = *sql;
    sql_text.loc = *loc;

    SQL_SET_COPY_LOG(stmt->session, OG_FALSE);

    if (stmt->pl_exec != NULL || stmt->pl_compiler != NULL) { // can't modify sql in pl
        SQL_SET_COPY_LOG(stmt->session, OG_TRUE);
    }

    (void)cm_gettimeofday(&timeval_begin);
    OGSQL_SAVE_STACK(stmt);
    stmt->lang_type = sql_diag_lang_type(stmt, &sql_text, &leader_word);
    if (g_instance->sql.use_bison_parser) {
        stmt->parser_text = sql_text;
        stmt->parser_text_valid = OG_TRUE;
    }

    status = sql_parse_by_lang_type(stmt, &sql_text, &leader_word);
    stmt->parser_text = parser_text_bak;
    stmt->parser_text_valid = parser_text_valid_bak;
    OGSQL_RESTORE_STACK(stmt);
    (void)cm_gettimeofday(&timeval_end);
    stmt->session->stat.parses++;
    stmt->session->stat.parses_time_elapse += TIMEVAL_DIFF_US(&timeval_begin, &timeval_end);
    g_instance->library_cache_info[stmt->lang_type].lang_type = stmt->lang_type;
    return status;
}

static inline bool32 sql_bootstrap_use_native_parser(sql_stmt_t *stmt)
{
    /*
     * initdb/initplsql bootstrap runs before all SYS PL entries and built-in
     * package grants are fully visible through dictionary lookups. Keep that
     * bootstrap script path on the native parser; after bootstrap the
     * USE_BISON_PARSER parameter controls normal SQL parsing.
     */
    return g_instance->sql.use_bison_parser && KNL_SESSION(stmt)->bootstrap;
}

status_t sql_parse(sql_stmt_t *stmt, text_t *sql, source_location_t *loc)
{
    word_t leader_word;
    status_t status;
    sql_text_t sql_text = { 0 };
    bool32 use_bison_bak = g_instance->sql.use_bison_parser;
    bool32 use_native = sql_bootstrap_use_native_parser(stmt);
    if (use_native) {
        g_instance->sql.use_bison_parser = OG_FALSE;
    }
    OGSQL_SAVE_STACK(stmt);
    sql_text.value = *sql;
    sql_text.loc = *loc;
    stmt->lang_type = sql_diag_lang_type(stmt, &sql_text, &leader_word);

    status = sql_parse_core(stmt, sql, loc);

    OGSQL_RESTORE_STACK(stmt);
    if (use_native) {
        g_instance->sql.use_bison_parser = use_bison_bak;
    }
    return status;
}

#ifdef __cplusplus
}
#endif
