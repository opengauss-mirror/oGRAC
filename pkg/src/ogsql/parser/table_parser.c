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
 * table_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/table_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "cbo_base.h"
#include "ogsql_json_table.h"
#include "ogsql_select_parser.h"
#include "pivot_parser.h"
#include "cond_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_try_parse_table_alias_word(sql_stmt_t *stmt, sql_text_t *alias, word_t *word,
    const char *expect_alias)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;

    if (lex_try_fetch(lex, expect_alias, &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        return OG_SUCCESS;
    }

    return sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias);
}

static status_t sql_try_parse_table_alias_limit(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;

    LEX_SAVE(lex);

    if (lex_fetch(lex, &tmp_word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (tmp_word.type == WORD_TYPE_NUMBER || tmp_word.type == WORD_TYPE_PARAM || tmp_word.type == WORD_TYPE_RESERVED ||
        tmp_word.type == WORD_TYPE_STRING || tmp_word.type == WORD_TYPE_BRACKET ||
        tmp_word.type == WORD_TYPE_HEXADECIMAL) {
        LEX_RESTORE(lex);
        return OG_SUCCESS;
    }
    LEX_RESTORE(lex);

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return lex_fetch(lex, word);
}

static status_t sql_try_parse_table_alias_using(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (stmt->context->type == OGSQL_TYPE_MERGE || stmt->context->type == OGSQL_TYPE_DELETE) {
        return sql_try_parse_table_alias_word(stmt, alias, word, "USING");
    } else {
        if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != OG_SUCCESS) {
            return OG_ERROR;
        }

        return lex_fetch(lex, word);
    }
}

static status_t sql_try_parse_table_alias_inner(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;

    LEX_SAVE(lex);

    if (lex_fetch(lex, &tmp_word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (tmp_word.id == KEY_WORD_JOIN) {
        LEX_RESTORE(lex);
        return OG_SUCCESS;
    }
    LEX_RESTORE(lex);

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_try_parse_table_alias_outer(sql_stmt_t *stmt, sql_text_t *alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t tmp_word;

    LEX_SAVE(lex);

    if (lex_fetch(lex, &tmp_word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (tmp_word.id == KEY_WORD_JOIN || tmp_word.id == KEY_WORD_OUTER) {
        LEX_RESTORE(lex);
        return OG_SUCCESS;
    }
    LEX_RESTORE(lex);

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, alias) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_fetch(lex, word);
}

status_t sql_try_parse_table_alias(sql_stmt_t *stmt, sql_text_t *table_alias, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (word->id == KEY_WORD_AS) {
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, table_alias));
        return lex_fetch(lex, word);
    }

    if (word->type == WORD_TYPE_EOF || !IS_VARIANT(word)) {
        return OG_SUCCESS;
    }

    switch (word->id) {
        case KEY_WORD_LIMIT:
            return sql_try_parse_table_alias_limit(stmt, table_alias, word);
        case KEY_WORD_USING:
            return sql_try_parse_table_alias_using(stmt, table_alias, word);
        case KEY_WORD_INNER:
        case KEY_WORD_CROSS:
            return sql_try_parse_table_alias_inner(stmt, table_alias, word);
        case KEY_WORD_RIGHT:
        case KEY_WORD_LEFT:
        case KEY_WORD_FULL:
            return sql_try_parse_table_alias_outer(stmt, table_alias, word);
        case KEY_WORD_JOIN:
            return sql_try_parse_table_alias_word(stmt, table_alias, word, "JOIN");
        case KEY_WORD_OFFSET:
            return sql_try_parse_table_alias_word(stmt, table_alias, word, "OFFSET");
        default:
            if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, table_alias) != OG_SUCCESS) {
                return OG_ERROR;
            }

            return lex_fetch(lex, word);
    }
}

static status_t sql_try_parse_column_alias(sql_stmt_t *stmt, sql_table_t *table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    uint32 i;
    query_column_t *query_col = NULL;
    bool32 result = OG_FALSE;

    OG_RETSUC_IFTRUE(word->type != WORD_TYPE_BRACKET ||
        !(table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE));

    lex_remove_brackets(&word->text);

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (i = 0; i < table->select_ctx->first_query->columns->count; ++i) {
        if (lex_fetch(lex, word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        query_col = (query_column_t *)cm_galist_get(table->select_ctx->first_query->columns, i);
        if (query_col->exist_alias) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "cloumn already have alias");
            return OG_ERROR;
        }

        if (IS_VARIANT(word) || word->type == WORD_TYPE_STRING) {
            if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &query_col->alias) !=
                OG_SUCCESS) {
                lex_pop(lex);
                return OG_ERROR;
            }
        } else {
            lex_pop(lex);
            OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid cloumn alias");
            return OG_ERROR;
        }

        if (i < table->select_ctx->first_query->columns->count - 1) {
            if (lex_try_fetch_char(lex, ',', &result) != OG_SUCCESS) {
                lex_pop(lex);
                return OG_ERROR;
            }
            if (!result) {
                lex_pop(lex);
                OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "expect ','");
                return OG_ERROR;
            }
        }
    }

    if (lex_expected_end(lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);

    return lex_fetch(lex, word);
}

status_t sql_decode_object_name(sql_stmt_t *stmt, word_t *word, sql_text_t *user, sql_text_t *name)
{
    var_word_t var_word;

    if (sql_word_as_table(stmt, word, &var_word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    *user = var_word.table.user;
    *name = var_word.table.name;

    return OG_SUCCESS;
}

status_t sql_try_match_withas_table(sql_stmt_t *stmt, sql_table_t *query_table, bool32 *is_withas_table)
{
    sql_withas_t *sql_withas = NULL;
    sql_withas_factor_t *factor = NULL;
    uint32 i;
    uint32 tmp_delta;
    uint32 match_idx = OG_INVALID_ID32;
    uint32 delta = OG_INVALID_INT32;
    uint32 level = OG_INVALID_INT32;

    *is_withas_table = OG_FALSE;

    sql_withas = (sql_withas_t *)stmt->context->withas_entry;
    if (sql_withas == NULL) {
        return OG_SUCCESS;
    }
    /* if found table in with as list, can't use with as list to check tables in sub query sql
    in some case and throws error in lex_push:
    nok: with A as (select * from t1), B as (select * from B) select * from A,B
    nok: with A as (select * from B), B as (select * from t1) select * from A,B
    ok:  with A as (select * from t1), B as (select * from A) select * from A,B */
    for (i = 0; i < sql_withas->withas_factors->count; i++) {
        factor = (sql_withas_factor_t *)cm_galist_get(sql_withas->withas_factors, i);
        if (cm_text_equal(&query_table->user.value, &factor->user.value) &&
            cm_text_equal(&query_table->name.value, &factor->name.value)) {
            if (sql_withas->cur_match_idx == i) {
                OG_SRC_THROW_ERROR(factor->name.loc, ERR_SQL_SYNTAX_ERROR,
                    "recursive WITH clause must have column alias list");
                return OG_ERROR;
            }

            /* match the nearest and firstly withas table in select level */
            tmp_delta = CM_DELTA(stmt->node_stack.depth, factor->depth);
            if (tmp_delta < delta || (tmp_delta == delta && level < factor->level)) {
                match_idx = i;
                delta = tmp_delta;
                level = factor->level;
            }
        }
    }

    if (match_idx != OG_INVALID_ID32) {
        factor = (sql_withas_factor_t *)cm_galist_get(sql_withas->withas_factors, match_idx);
        *is_withas_table = OG_TRUE;
        query_table->type = WITH_AS_TABLE;
        query_table->select_ctx = (sql_select_t *)factor->subquery_ctx;
        query_table->select_ctx->is_withas = OG_TRUE;
        query_table->entry = NULL;
        factor->refs++;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_dblink(sql_stmt_t *stmt, word_t *word, sql_text_t *dblink, sql_text_t *tab_user)
{
    lex_t *lex = stmt->session->lex;
    bool32 result;

    OG_RETURN_IFERR(lex_try_fetch_database_link(lex, word, &result));

    if (!result) {
        return OG_SUCCESS;
    }

    if (stmt->context->type != OGSQL_TYPE_SELECT) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "dml", "dblink table");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_name_loc(stmt->context, &word->text, dblink));

    return OG_SUCCESS;
}

#ifdef OG_RAC_ING
static status_t sql_regist_distribute_rule(sql_stmt_t *stmt, sql_text_t *name, sql_table_entry_t **rule)
{
    text_t curr_user = stmt->session->curr_user;

    uint32 i;
    knl_handle_t knl = &stmt->session->knl_session;
    sql_context_t *ogx = stmt->context;

    for (i = 0; i < ogx->rules->count; i++) {
        *rule = (sql_table_entry_t *)cm_galist_get(ogx->rules, i);

        if (cm_text_equal(&(*rule)->name, &name->value)) {
            return OG_SUCCESS;
        }
    }

    if (cm_galist_new(ogx->rules, sizeof(sql_table_entry_t), (pointer_t *)rule) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*rule)->name = name->value;
    (*rule)->user = curr_user;
    ((*rule)->dc).type = DICT_TYPE_DISTRIBUTE_RULE;

    if (knl_open_dc_with_public(knl, &curr_user, OG_TRUE, &name->value, &(*rule)->dc) != OG_SUCCESS) {
        int32 code;
        const char *message = NULL;
        cm_get_error(&code, &message, NULL);
        if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            cm_reset_error();
            OG_THROW_ERROR(ERR_DISTRIBUTE_RULE_NOT_EXIST, T2S(&name->value));
        }
        return OG_ERROR;
    }

    return OG_SUCCESS;
}
#endif

status_t sql_regist_table(sql_stmt_t *stmt, sql_table_t *table)
{
    uint32 i;
    sql_context_t *ogx = stmt->context;
    sql_table_entry_t *entry = NULL;

    for (i = 0; i < ogx->tables->count; i++) {
        entry = (sql_table_entry_t *)cm_galist_get(ogx->tables, i);
        if (cm_text_equal(&entry->name, &table->name.value) &&
            cm_text_equal(&entry->user, &table->user.value) &&
            cm_text_equal(&entry->dblink, &table->dblink.value)) {
            table->entry = entry;
            return OG_SUCCESS;
        }
    }

    OG_RETURN_IFERR(cm_galist_new(ogx->tables, sizeof(sql_table_entry_t), (pointer_t *)&entry));

    entry->name = table->name.value;
    entry->user = table->user.value;
    entry->dblink = table->dblink.value;
    entry->dc.type = DICT_TYPE_UNKNOWN;

    entry->tab_hash_val = cm_hash_text(&entry->name, OG_TRANS_TAB_HASH_BUCKET);

    table->entry = entry;
    return OG_SUCCESS;
}

static status_t sql_convert_normal_table(sql_stmt_t *stmt, word_t *word, sql_table_t *table)
{
    bool32 is_withas_table = OG_FALSE;

    if (word->ex_count == 1) {
        if (word->type == WORD_TYPE_DQ_STRING) {
            table->user_has_quote = OG_TRUE;
        }
        table->tab_name_has_quote = (word->ex_words[0].type == WORD_TYPE_DQ_STRING) ? OG_TRUE : OG_FALSE;
    } else {
        if (word->type == WORD_TYPE_DQ_STRING) {
            table->tab_name_has_quote = OG_TRUE;
        }
    }

    if (sql_decode_object_name(stmt, word, &table->user, &table->name) != OG_SUCCESS) {
        cm_set_error_loc(word->loc);
        return OG_ERROR;
    }

    // table can be with as or normal
    if (sql_try_match_withas_table(stmt, table, &is_withas_table) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (is_withas_table) {
        return OG_SUCCESS;
    }

#ifdef OG_RAC_ING
    if (table->is_distribute_rule) {
        if (sql_regist_distribute_rule(stmt, &table->name, &table->entry) != OG_SUCCESS) {
            cm_set_error_loc(word->loc);
            return OG_ERROR;
        }

        return OG_SUCCESS;
    }
#endif

    if (sql_parse_dblink(stmt, word, &table->dblink, &table->user) != OG_SUCCESS) {
        cm_set_error_loc(word->loc);
        return OG_ERROR;
    }

    if (sql_regist_table(stmt, table) != OG_SUCCESS) {
        cm_set_error_loc(word->loc);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_table_part_name(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table, lex_t *lex)
{
    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (!IS_VARIANT(word)) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "illegal partition-extended table name syntax");
        return OG_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &query_table->part_info.part_name) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    if (lex_expected_end(lex) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_table_part_value(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    expr_tree_t *value_expr = NULL;

    if (sql_create_list(stmt, &query_table->part_info.values) != OG_SUCCESS) {
        return OG_ERROR;
    }
    while (OG_TRUE) {
        if (sql_create_expr_until(stmt, &value_expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (cm_galist_insert(query_table->part_info.values, value_expr) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (word->type == WORD_TYPE_EOF) {
            break;
        }
        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_try_parse_table_partition(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;
    status_t status;

    OG_RETURN_IFERR(lex_try_fetch(lex, "FOR", &result));
    query_table->part_info.type = result ? SPECIFY_PART_VALUE : SPECIFY_PART_NAME;

#ifdef OG_RAC_ING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session) && query_table->part_info.type == SPECIFY_PART_VALUE) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_CAPABILITY_NOT_SUPPORT, "select from partition for");
        return OG_ERROR;
    }
#endif
    if (!result) {
        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (!result) {
            query_table->part_info.type = SPECIFY_PART_NONE;
            OG_RETURN_IFERR(sql_copy_str(stmt->context, "PARTITION", &query_table->alias.value));
            query_table->alias.loc = word->loc;
            return lex_fetch(lex, word);
        }
    } else {
        OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    }

    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition name or key value expected");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(lex_push(lex, &word->text));
    uint32 flags = lex->flags;
    lex->flags |= LEX_WITH_ARG;
    if (query_table->part_info.type == SPECIFY_PART_NAME) {
        status = sql_parse_table_part_name(stmt, word, query_table, lex);
    } else {
        status = sql_parse_table_part_value(stmt, word, query_table);
    }
    lex->flags = flags;
    lex_pop(lex);
    OG_RETURN_IFERR(status);

    if (IS_DBLINK_TABLE(query_table)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "partition on dblink table");
        return OG_ERROR;
    }

    return lex_fetch(lex, word);
}

static status_t sql_try_parse_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word);

static status_t sql_try_parse_table_attribute(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table,
    bool32 *pivot_table)
{
    OG_RETURN_IFERR(sql_parse_dblink(stmt, word, &query_table->dblink, &query_table->user));

    uint32 flags = stmt->session->lex->flags;
    stmt->session->lex->flags = LEX_SINGLE_WORD;
    OG_RETURN_IFERR(sql_try_parse_table_version(stmt, &query_table->version, word));
    if (query_table->version.type != CURR_VERSION && IS_DBLINK_TABLE(query_table)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "pivot or unpivot on dblink table");
        return OG_ERROR;
    }

    if (word->id == KEY_WORD_PARTITION || word->id == KEY_WORD_SUBPARTITION) {
        if (word->id == KEY_WORD_PARTITION) {
            query_table->part_info.is_subpart = OG_FALSE;
        } else {
            query_table->part_info.is_subpart = OG_TRUE;
        }

        OG_RETURN_IFERR(sql_try_parse_table_partition(stmt, word, query_table));
    }

    stmt->session->lex->flags = flags;
    OG_RETURN_IFERR(sql_try_create_pivot_unpivot_table(stmt, query_table, word, pivot_table));
    stmt->session->lex->flags = LEX_SINGLE_WORD;
    if (query_table->alias.len == 0) {
        OG_RETURN_IFERR(sql_try_parse_table_alias(stmt, &query_table->alias, word));
    }

    if (query_table->alias.len > 0) {
        if (query_table->type == JOIN_AS_TABLE) {
            OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "table join does not support aliases");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_try_parse_column_alias(stmt, query_table, word));
    }

    stmt->session->lex->flags = flags;

    return OG_SUCCESS;
}

#define IS_INCLUDE_SPEC_WORD(word)                                                                             \
    (((*(word)).id == KEY_WORD_LEFT) || ((*(word)).id == KEY_WORD_RIGHT) || ((*(word)).id == KEY_WORD_FULL) || \
        ((*(word)).id == KEY_WORD_JOIN) || ((*(word)).id == KEY_WORD_INNER) || (IS_SPEC_CHAR((word), ',')))

static status_t sql_try_parse_join_in_bracket(sql_stmt_t *stmt, sql_table_t *query_table, word_t *word, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    if (query_table->alias.len == 0) {
        *result = IS_INCLUDE_SPEC_WORD(word);
        if (!(*result)) {
            OG_RETURN_IFERR(lex_fetch(lex, word));
            *result = IS_INCLUDE_SPEC_WORD(word);
        }
    } else {
        *result = IS_INCLUDE_SPEC_WORD(word);
    }
    return OG_SUCCESS;
}

static status_t sql_try_parse_partition_table_outside_alias(sql_stmt_t *stmt, sql_table_t *query_table, lex_t *lex,
    word_t *word, sql_array_t *tables)
{
    sql_text_t table_alias;
    // select * from ((tableA) partition(p2)) aliasA
    if (query_table->alias.len == 0) {
        OG_RETURN_IFERR(sql_try_parse_table_attribute(stmt, word, query_table, NULL));
    } else {
        uint32 old_flags = lex->flags;
        OG_BIT_RESET(lex->flags, LEX_WITH_ARG);
        OG_RETURN_IFERR(lex_fetch(lex, word));
        lex->flags = old_flags;
        // select * from ((tableA) partition(p2) aliasA) aliasB --expected error
        table_alias.len = 0;
        OG_RETURN_IFERR(sql_try_parse_table_alias(stmt, &table_alias, word));
        if (table_alias.len != 0) {
            OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid table alias");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_create_query_table_in_bracket(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t *query_table, word_t *word);
static status_t sql_parse_table_in_nested_brackets(sql_stmt_t *stmt, sql_array_t *tables,
    sql_join_assist_t *join_assist, sql_table_t *query_table, word_t *word, bool32 *eof)
{
    lex_t *lex = stmt->session->lex;
    word_t sub_select_word;
    bool32 result = OG_FALSE;
    bool32 pivot_table = OG_FALSE;
    sql_table_t *table = NULL;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_count = sizeof(words) / sizeof(char *);
    status_t status = OG_ERROR;

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    LEX_SAVE(lex);
    if (lex_fetch(lex, &sub_select_word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    if (lex_try_fetch_anyone(lex, words_count, words, &result) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (result) {
        // this branch handle one case. case1: select * from ((select * from t1) union all (select * from t2))
        lex_pop(lex);
        return OG_SUCCESS;
    }
    OG_RETSUC_IFTRUE(sub_select_word.type != WORD_TYPE_BRACKET);
    *eof = OG_TRUE;
    do {
        word_t temp_word = *word;
        OG_BREAK_IF_ERROR(sql_try_parse_table_attribute(stmt, &temp_word, query_table, &pivot_table));

        OG_BREAK_IF_ERROR(sql_try_parse_join_in_bracket(stmt, query_table, &temp_word, &result));

        LEX_RESTORE(lex);
        if (result) {
            /* this branch handle two cases:
             * case2: select * from ((select * from t1) aliasA left join (select * from t2) aliasB
             * on aliasA.a = aliasB.a);
             * case3: select * from ((t1) left join (t2) on t1.a = t2.a)
             */
            status = sql_create_query_table_in_bracket(stmt, tables, join_assist, query_table, word);
            break;
        }
        if ((&temp_word)->type != WORD_TYPE_EOF) {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end in bracket but %s found",
                W2S(&temp_word));
            break;
        }

        // this branch handle one case: case4: select * from((select * from t1) aliasA)
        table = pivot_table ? (sql_table_t *)query_table->select_ctx->first_query->tables.items[0] : query_table;
        status = sql_create_query_table(stmt, tables, join_assist, table, &sub_select_word);
    } while (0);

    lex_pop(lex);
    OG_RETURN_IFERR(status);
    return sql_try_parse_partition_table_outside_alias(stmt, query_table, lex, word, tables);
}

static status_t sql_try_parse_table_wrapped(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t *query_table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 eof = OG_FALSE;
    OG_RETURN_IFERR(lex_expected_fetch(lex, word));
    if (word->type != WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word->text.value);
        cm_remove_brackets(&word->text.value);
    }

    if (word->text.len > 0 && word->text.str[0] == '(' && word->type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(sql_parse_table_in_nested_brackets(stmt, tables, join_assist, query_table, word, &eof));
        if (eof) {
            return OG_SUCCESS;
        }
    }

    OG_RETURN_IFERR(sql_create_query_table(stmt, tables, join_assist, query_table, word));
    return sql_try_parse_partition_table_outside_alias(stmt, query_table, lex, word, tables);
}

static status_t sql_parse_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t **query_table, word_t *word)
{
    if (sql_array_new(tables, sizeof(sql_table_t), (void **)query_table) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*query_table)->id = tables->count - 1;
    (*query_table)->rs_nullable = OG_FALSE;

    return sql_try_parse_table_wrapped(stmt, tables, join_assist, *query_table, word);
}

static status_t sql_create_normal_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    return sql_convert_normal_table(stmt, word, query_table);
}

static status_t sql_bracket_as_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    text_t curr_schema;
    cm_str2text(stmt->session->curr_schema, &curr_schema);
    query_table->user.value = curr_schema;
    query_table->user.loc = word->text.loc;
    query_table->type = SUBSELECT_AS_TABLE;
    OG_RETURN_IFERR(sql_create_select_context(stmt, &word->text, SELECT_AS_TABLE, &query_table->select_ctx));
    query_table->select_ctx->parent = OGSQL_CURR_NODE(stmt);
    return OG_SUCCESS;
}

static inline status_t sql_word_as_table_func(sql_stmt_t *stmt, word_t *word, table_func_t *func)
{
    text_t schema;
    func->loc = word->text.loc;
    sql_copy_func_t sql_copy_func;
    sql_copy_func = sql_copy_name;

    if (word->ex_count == 0) {
        OG_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->text, &func->name));
        cm_str2text(stmt->session->curr_schema, &schema);
        func->user = schema;
        func->package = CM_NULL_TEXT;
    } else if (word->ex_count == 1) {
        OG_RETURN_IFERR(sql_copy_prefix_tenant(stmt, (text_t *)&word->text, &func->user, sql_copy_func));
        OG_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->ex_words[0].text, &func->name));

        func->package = CM_NULL_TEXT;
    } else if (word->ex_count == 2) {
        OG_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->ex_words[1].text, &func->name));
        OG_RETURN_IFERR(sql_copy_func(stmt->context, (text_t *)&word->ex_words[0].text, &func->package));
        OG_RETURN_IFERR(sql_copy_prefix_tenant(stmt, (text_t *)&word->text, &func->user, sql_copy_func));
    } else {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid function or procedure name is found");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_table_cast_type(sql_stmt_t *stmt, expr_tree_t **arg2, word_t *word)
{
    expr_tree_t *arg = NULL;
    lex_t *lex = stmt->session->lex;
    if (sql_create_expr(stmt, arg2) != OG_SUCCESS) {
        return OG_ERROR;
    }
    arg = *arg2;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_fetch(lex, word));

    arg->root->value.type = OG_TYPE_TYPMODE;
    arg->root->type = EXPR_NODE_CONST;
    arg->loc = word->loc;
    arg->root->exec_default = OG_TRUE;
    OG_RETURN_IFERR(sql_word_as_func(stmt, word, &arg->root->word));
    return OG_SUCCESS;
}

static status_t sql_parse_table_cast_arg(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *arg = NULL;

    if (lex_push(lex, &word->text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_expr_until(stmt, &arg, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_AS) {
        lex_pop(lex);
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "key word AS expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (sql_parse_table_cast_type(stmt, &arg->next, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (lex_expected_end(lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    *expr = arg;

    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_func_as_query_table(sql_stmt_t *stmt, word_t *word, sql_table_t *query_table)
{
    lex_t *lex = stmt->session->lex;
    uint32 prev_flags = lex->flags;
    bool32 result = OG_FALSE;
    text_t cast = { "CAST", 4 };
    stmt->context->has_func_tab = OG_TRUE;
    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    lex->flags = LEX_WITH_OWNER;
    if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex->flags = prev_flags;

    if (sql_word_as_table_func(stmt, word, &query_table->func) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (lex_try_fetch_bracket(lex, word, &result) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (result) {
        if (word->text.len == 0) {
            query_table->func.args = NULL;
        } else if (cm_compare_text_ins(&query_table->func.name, &cast) == 0) {
            if (sql_parse_table_cast_arg(stmt, word, &query_table->func.args) != OG_SUCCESS) {
                lex_pop(lex);
                return OG_ERROR;
            }
        } else if (sql_create_expr_list(stmt, &word->text, &query_table->func.args) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
    }

    query_table->user.value.str = stmt->session->curr_schema;
    query_table->user.value.len = (uint32)strlen(stmt->session->curr_schema);
    query_table->user.loc = word->text.loc;
    query_table->type = FUNC_AS_TABLE;
    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_parse_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass, word_t *word);

static status_t sql_is_subquery_table(sql_stmt_t *stmt, word_t *word, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    word_t sub_select_word;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_count = sizeof(words) / sizeof(char *);
    *result = OG_FALSE;
    if (word->text.len > 0 && word->text.str[0] == '(') {
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        if (lex_fetch(lex, &sub_select_word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(lex_try_fetch_anyone(lex, words_count, words, result));
        lex_pop(lex);
    }

    return OG_SUCCESS;
}

static status_t sql_create_json_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word, bool32 is_jsonb_table);
static status_t sql_parse_table_without_join(sql_stmt_t *stmt, sql_table_t *query_table, lex_t *lex, word_t *first_word,
    word_t *second_word)
{
    bool32 pivot_table = OG_FALSE;
    OG_RETURN_IFERR(sql_try_parse_table_attribute(stmt, second_word, query_table, &pivot_table));
    if (second_word->type == WORD_TYPE_EOF) {
        if (first_word->id == KEY_WORD_JSON_TABLE && first_word->ex_count > 0) {
            OG_RETURN_IFERR(sql_create_json_table(stmt, query_table, first_word, OG_FALSE));
        } else if (first_word->id == KEY_WORD_JSONB_TABLE && first_word->ex_count > 0) {
            OG_RETURN_IFERR(sql_create_json_table(stmt, query_table, first_word, OG_TRUE));
        } else if (!pivot_table) {
            OG_RETURN_IFERR(sql_create_normal_query_table(stmt, first_word, query_table));
        } else {
            OG_RETURN_IFERR(
                sql_create_normal_query_table(stmt, first_word, query_table->select_ctx->first_query->tables.items[0]));
        }
    }
    return OG_SUCCESS;
}

static status_t sql_parse_table_with_join(sql_stmt_t *stmt, sql_array_t *tables, sql_table_t *query_table, word_t *word,
    sql_join_assist_t *join_assist)
{
    lex_t *lex = stmt->session->lex;
    sql_join_assist_t join_assist_tmp;
    OG_RETURN_IFERR(lex_push(lex, &word->text));
    join_assist_tmp.join_node = query_table->join_node;
    join_assist_tmp.outer_node_count = 0;
    if (sql_parse_join(stmt, tables, &join_assist_tmp, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    join_assist->outer_node_count += join_assist_tmp.outer_node_count;
    query_table->join_node = join_assist_tmp.join_node;
    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);

    query_table->type = JOIN_AS_TABLE;
    if (query_table->join_node == NULL) {
        OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "Don't support the sql");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_parse_json_table_in_bracket(sql_stmt_t *statement, lex_t *lex,
    word_t *current_word, word_t *next_word, sql_table_t *tbl, bool32 *is_early_return)
{
    OG_RETURN_IFERR(sql_parse_table_without_join(statement, tbl, lex, current_word, next_word));
    if (is_eof_word(next_word)) {
        *is_early_return = OG_TRUE;
    }
    return OG_SUCCESS;
}

static status_t og_parse_general_table_in_bracket(sql_stmt_t *statement, word_t *word, sql_table_t *tbl)
{
    OG_RETURN_IFERR(sql_func_as_query_table(statement, word, tbl));
    bool32 pivot_tbl = OG_FALSE;
    if (tbl->alias.len > 0) {
        return OG_ERROR;
    }
    return sql_try_parse_table_attribute(statement, word, tbl, &pivot_tbl);
}

static status_t sql_create_query_table_in_bracket(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_assist,
    sql_table_t *query_table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_t current_word;
    word_t next_word;
    OG_RETURN_IFERR(lex_push(lex, &word->text));
    OG_RETURN_IFERR(lex_fetch(lex, &current_word));
    bool32 is_select_with = is_slct_with_word(&current_word);
    if (!is_select_with) {
        if (sql_is_subquery_table(stmt, word, &is_select_with) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
    }
    if (is_select_with) {
        lex_pop(lex);
        return sql_bracket_as_query_table(stmt, word, query_table);
    }
    
    bool32 is_early_return = OG_FALSE;
    status_t ret = OG_SUCCESS;
    if (IS_VARIANT(&current_word) || is_json_table_word(&current_word)) {
        ret = og_parse_json_table_in_bracket(stmt, lex, &current_word, &next_word, query_table, &is_early_return);
        if (ret != OG_SUCCESS || is_early_return) {
            lex_pop(lex);
            return ret;
        }
    }

    if (is_table_word(&current_word)) {
        ret = og_parse_general_table_in_bracket(stmt, &current_word, query_table);
        lex_pop(lex);
        return ret;
    }

    lex_pop(lex);
    return sql_parse_table_with_join(stmt, tables, query_table, word, join_assist);
}

void sql_init_json_table_info(sql_stmt_t *stmt, json_table_info_t *json_info)
{
    json_info->data_expr = NULL;
    json_info->json_error_info.default_value = NULL;
    json_info->json_error_info.type = JSON_RETURN_NULL;
    json_info->depend_table_count = 0;
    json_info->depend_tables = NULL;
    cm_galist_init(&json_info->columns, stmt->context, sql_alloc_mem);
}

static status_t sql_create_json_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word, bool32 is_jsonb_table)
{
    lex_t *lex = stmt->session->lex;

    table->type = JSON_TABLE;
    table->is_jsonb_table = is_jsonb_table;
    OG_RETURN_IFERR(lex_push(lex, &word->ex_words[0].text));
    word->ex_count = 0;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(json_table_info_t), (void **)&table->json_table_info));
    sql_init_json_table_info(stmt, table->json_table_info);
    OG_RETURN_IFERR(sql_parse_json_table(stmt, table, word));
    lex_pop(lex);
    return OG_SUCCESS;
}

status_t sql_create_query_table(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_table_t *query_table, word_t *word)
{
    if (IS_VARIANT(word)) {
        return sql_create_normal_query_table(stmt, word, query_table);
    } else if (word->type == WORD_TYPE_BRACKET) {
        return sql_create_query_table_in_bracket(stmt, tables, join_ass, query_table, word);
    } else if (word->id == KEY_WORD_TABLE) {
        return sql_func_as_query_table(stmt, word, query_table);
    } else if (word->id == KEY_WORD_JSON_TABLE) {
        return sql_create_json_table(stmt, query_table, word, OG_FALSE);
    } else if (word->id == KEY_WORD_JSONB_TABLE) {
        return sql_create_json_table(stmt, query_table, word, OG_TRUE);
    } else {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table name or subselect expected but %s found.",
            W2S(word));
        return OG_ERROR;
    }
}

static status_t sql_verify_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word)
{
    sql_verifier_t verf = { 0 };
    og_type_t expr_type;
    expr_node_type_t node_type;

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SEQUENCE | SQL_EXCL_SUBSELECT |
        SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT |
        SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID;

    if (sql_verify_expr(&verf, (expr_tree_t *)version->expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    expr_type = TREE_DATATYPE((expr_tree_t *)version->expr);
    node_type = TREE_EXPR_TYPE((expr_tree_t *)version->expr);
    if (version->type == SCN_VERSION) {
        if (!OG_IS_WEAK_NUMERIC_TYPE(expr_type) && node_type != EXPR_NODE_PARAM) {
            cm_try_set_error_loc(word->text.loc);
            OG_SET_ERROR_MISMATCH(OG_TYPE_BIGINT, expr_type);
            return OG_ERROR;
        }
    } else {
        if (!OG_IS_DATETIME_TYPE(expr_type)) {
            cm_try_set_error_loc(word->text.loc);
            OG_SET_ERROR_MISMATCH(OG_TYPE_TIMESTAMP, expr_type);
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_try_parse_table_version(sql_stmt_t *stmt, sql_table_snapshot_t *version, word_t *word)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;
    uint32 matched_id;
    uint32 flags = lex->flags;

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_AS) {
        version->type = CURR_VERSION;
        return OG_SUCCESS;
    }

    if (lex_try_fetch(lex, "OF", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        version->type = CURR_VERSION;
        return OG_SUCCESS;
    }

#ifdef OG_RAC_ING
    if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_CAPABILITY_NOT_SUPPORT, "AS OF");
        return OG_ERROR;
    }
#endif

    if (lex_expected_fetch_1of2(lex, "SCN", "TIMESTAMP", &matched_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    version->type = (matched_id == 0) ? SCN_VERSION : TIMESTAMP_VERSION;

    lex->flags = LEX_WITH_ARG;
    if (sql_create_expr_until(stmt, (expr_tree_t **)&version->expr, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_verify_table_version(stmt, version, word));

    lex->flags = flags;
    return OG_SUCCESS;
}

status_t sql_create_join_node(sql_stmt_t *stmt, sql_join_type_t join_type, sql_table_t *table, cond_tree_t *cond,
    sql_join_node_t *left, sql_join_node_t *right, sql_join_node_t **join_node)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_join_node_t), (void **)join_node));
    OG_RETURN_IFERR(sql_create_array(stmt->context, &(*join_node)->tables, "JOINS TABLES", OG_MAX_JOIN_TABLES));
    (*join_node)->type = join_type;
    (*join_node)->cost.cost = CBO_MIN_COST;
    (*join_node)->cost.card = CBO_MAX_ROWS;
    (*join_node)->join_cond = cond;
    (*join_node)->left = left;
    (*join_node)->right = right;
    (*join_node)->is_cartesian_join = OG_FALSE;
    // table is not NULL only when dml parse
    if (table != NULL) {
        OG_RETURN_IFERR(sql_array_put(&(*join_node)->tables, table));
    }
    // adjust join tree, left and right node is not NULL
    if (left != NULL) {
        OG_RETURN_IFERR(sql_array_concat(&(*join_node)->tables, &left->tables));
    }
    if (right != NULL) {
        OG_RETURN_IFERR(sql_array_concat(&(*join_node)->tables, &right->tables));
    }
    return OG_SUCCESS;
}

static void sql_add_join_node(sql_join_chain_t *chain_node, sql_join_node_t *join_node)
{
    if (chain_node->count == 0) {
        chain_node->first = join_node;
    } else {
        chain_node->last->next = join_node;
        join_node->prev = chain_node->last;
    }

    chain_node->last = join_node;
    chain_node->count++;
}

status_t sql_generate_join_node(sql_stmt_t *stmt, sql_join_chain_t *join_chain, sql_join_type_t join_type,
    sql_table_t *table, cond_tree_t *cond)
{
    sql_join_node_t *join_node = NULL;

    if (table != NULL && table->type == JOIN_AS_TABLE) {
        join_node = table->join_node;
    } else {
        OG_RETURN_IFERR(sql_create_join_node(stmt, join_type, table, cond, NULL, NULL, &join_node));
    }

    sql_add_join_node(join_chain, join_node);
    return OG_SUCCESS;
}

static inline status_t sql_parse_comma_cross_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word, sql_join_type_t join_type)
{
    if (join_chain->count == 0) {
        OG_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL));
    }
    OG_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, join_type, NULL, NULL));
    OG_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_ass, table, word));

    return sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL);
}

status_t sql_parse_comma_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word)
{
    return sql_parse_comma_cross_join(stmt, tables, join_ass, join_chain, table, word, JOIN_TYPE_COMMA);
}

static inline status_t sql_parse_cross_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word)
{
    OG_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "JOIN"));
    return sql_parse_comma_cross_join(stmt, tables, join_ass, join_chain, table, word, JOIN_TYPE_CROSS);
}

static status_t sql_parse_explicit_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass,
    sql_join_chain_t *join_chain, sql_table_t **table, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    sql_join_type_t join_type;
    cond_tree_t *join_cond = NULL;

    if (join_chain->count == 0) {
        OG_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL));
    }

    for (;;) {
        join_cond = NULL;
        if (word->id == KEY_WORD_LEFT || word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL) {
            join_type = (word->id == KEY_WORD_LEFT) ? JOIN_TYPE_LEFT :
                                                      ((word->id == KEY_WORD_RIGHT) ? JOIN_TYPE_RIGHT : JOIN_TYPE_FULL);
            join_ass->outer_node_count++;
            OG_RETURN_IFERR(lex_try_fetch(lex, "OUTER", &result));
        } else {
            join_type = JOIN_TYPE_INNER;
        }
        if (word->id != KEY_WORD_JOIN) {
            OG_RETURN_IFERR(lex_expected_fetch_word(lex, "JOIN"));
        }

        OG_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_ass, table, word));
        if ((*table)->type == JSON_TABLE) {
            if (join_type == JOIN_TYPE_RIGHT) {
                join_type = JOIN_TYPE_INNER;
                join_ass->outer_node_count--;
            } else if (join_type == JOIN_TYPE_FULL) {
                join_type = JOIN_TYPE_LEFT;
            }
        }

        if ((word->id != KEY_WORD_ON) && (join_type != JOIN_TYPE_INNER)) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "ON expected but '%s' found", W2S(word));
            return OG_ERROR;
        }

        if (word->id == KEY_WORD_ON) {
            OG_RETURN_IFERR(sql_create_cond_until(stmt, &join_cond, word));
        }
        OG_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, join_type, NULL, join_cond));
        OG_RETURN_IFERR(sql_generate_join_node(stmt, join_chain, JOIN_TYPE_NONE, *table, NULL));

        OG_BREAK_IF_TRUE(!(word->id == KEY_WORD_JOIN || word->id == KEY_WORD_INNER || word->id == KEY_WORD_LEFT ||
            word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL));
    }

    return OG_SUCCESS;
}

static void sql_down_table_join_node(sql_join_chain_t *chain, sql_join_node_t *join_node)
{
    join_node->left = join_node->prev;
    join_node->right = join_node->next;

    join_node->next = join_node->next->next;
    join_node->prev = join_node->prev->prev;

    if (join_node->prev != NULL) {
        join_node->prev->next = join_node;
    } else {
        chain->first = join_node;
    }

    if (join_node->next != NULL) {
        join_node->next->prev = join_node;
    } else {
        chain->last = join_node;
    }

    join_node->left->prev = NULL;
    join_node->left->next = NULL;
    join_node->right->prev = NULL;
    join_node->right->next = NULL;

    chain->count -= 2;
}

status_t sql_form_table_join_with_opers(sql_join_chain_t *join_chain, uint32 opers)
{
    sql_join_node_t *node = join_chain->first;

    /* get next cond node, merge node is needed at least two nodes */
    while (node != NULL) {
        if (((uint32)node->type & opers) == 0 || node->left != NULL) {
            node = node->next;
            continue;
        }

        sql_down_table_join_node(join_chain, node);

        if (node->left->type == JOIN_TYPE_NONE) {
            OG_RETURN_IFERR(sql_array_put(&node->tables, TABLE_OF_JOIN_LEAF(node->left)));
        } else {
            OG_RETURN_IFERR(sql_array_concat(&node->tables, &node->left->tables));
        }

        if (node->right->type == JOIN_TYPE_NONE) {
            OG_RETURN_IFERR(sql_array_put(&node->tables, TABLE_OF_JOIN_LEAF(node->right)));
        } else {
            OG_RETURN_IFERR(sql_array_concat(&node->tables, &node->right->tables));
        }

        node = node->next;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_join(sql_stmt_t *stmt, sql_array_t *tables, sql_join_assist_t *join_ass, word_t *word)
{
    sql_join_chain_t join_chain = { 0 };
    sql_table_t *table = NULL;
    join_ass->join_node = NULL;

    OG_RETURN_IFERR(sql_stack_safe(stmt));

    OG_RETURN_IFERR(sql_parse_query_table(stmt, tables, join_ass, &table, word));

    for (;;) {
        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (word->id == KEY_WORD_JOIN || word->id == KEY_WORD_INNER || word->id == KEY_WORD_LEFT ||
            word->id == KEY_WORD_RIGHT || word->id == KEY_WORD_FULL) {
            OG_RETURN_IFERR(sql_parse_explicit_join(stmt, tables, join_ass, &join_chain, &table, word));
        }

        if (IS_SPEC_CHAR(word, ',')) {
            OG_RETURN_IFERR(sql_parse_comma_join(stmt, tables, join_ass, &join_chain, &table, word));
        } else if (word->id == KEY_WORD_CROSS) {
            OG_RETURN_IFERR(sql_parse_cross_join(stmt, tables, join_ass, &join_chain, &table, word));
        } else {
            break;
        }
    }

    if (join_chain.count > 0) {
        OG_RETURN_IFERR(sql_form_table_join_with_opers(&join_chain,
            JOIN_TYPE_INNER | JOIN_TYPE_LEFT | JOIN_TYPE_RIGHT | JOIN_TYPE_FULL | JOIN_TYPE_CROSS));
        OG_RETURN_IFERR(sql_form_table_join_with_opers(&join_chain, JOIN_TYPE_COMMA));
        join_ass->join_node = join_chain.first;
    } else {
        join_ass->join_node = table->join_node;
    }

    return OG_SUCCESS;
}

status_t sql_remove_join_table(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_array_t new_tables;

    OG_RETURN_IFERR(sql_create_array(stmt->context, &new_tables, "QUERY TABLES", OG_MAX_JOIN_TABLES));

    for (uint32 i = 0; i < query->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == JOIN_AS_TABLE) {
            continue;
        }
        table->id = new_tables.count;
        OG_RETURN_IFERR(sql_array_put(&new_tables, table));
    }

    query->tables = new_tables;

    return OG_SUCCESS;
}

static void sql_traverse_join_tree_set_nullable(sql_join_node_t *node)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < node->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&(node->tables), i);
        table->rs_nullable = OG_TRUE;
    }
    return;
}

void sql_parse_join_set_table_nullable(sql_join_node_t *node)
{
    if (node->type == JOIN_TYPE_NONE) {
        return;
    }
    /* if parent node is left join, so right tree should be null */
    if (node->type == JOIN_TYPE_LEFT) {
        sql_traverse_join_tree_set_nullable(node->right);
    } else if (node->type == JOIN_TYPE_RIGHT) {
        /* if parent node is right join, so left tree should be null */
        sql_traverse_join_tree_set_nullable(node->left);
    } else if (node->type == JOIN_TYPE_FULL) {
        /* if parent node is full join, so left tree and right tree should be null */
        sql_traverse_join_tree_set_nullable(node->right);
        sql_traverse_join_tree_set_nullable(node->left);
    }

    sql_parse_join_set_table_nullable(node->left);
    sql_parse_join_set_table_nullable(node->right);
}

status_t sql_parse_join_entry(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    OG_RETURN_IFERR(sql_parse_join(stmt, &query->tables, &query->join_assist, word));
    if (query->join_assist.outer_node_count > 0) {
        sql_parse_join_set_table_nullable(query->join_assist.join_node);
    }
    return sql_remove_join_table(stmt, query);
}

status_t sql_parse_query_tables(sql_stmt_t *stmt, sql_query_t *sql_query, word_t *word)
{
    sql_table_t *table = NULL;
    lex_t *lex = NULL;

    CM_POINTER3(stmt, sql_query, word);
    lex = stmt->session->lex;

    if (word->type == WORD_TYPE_EOF) {
        word->ex_count = 0;
        word->type = WORD_TYPE_VARIANT;
        word->text.str = "SYS_DUMMY";
        word->text.len = (uint32)strlen(word->text.str);
        word->text.loc = LEX_LOC;

        OG_RETURN_IFERR(sql_array_new(&sql_query->tables, sizeof(sql_table_t), (void **)&table));
        table->id = sql_query->tables.count - 1;
        table->rs_nullable = OG_FALSE;
        table->ineliminable = OG_FALSE;
#ifdef OG_RAC_ING
        table->is_ancestor = 0;
#endif

        OG_RETURN_IFERR(sql_create_query_table(stmt, &sql_query->tables, &sql_query->join_assist, table, word));
        word->type = WORD_TYPE_EOF;

        return OG_SUCCESS;
    }

    if (word->id != KEY_WORD_FROM) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "FROM expected but %s found", W2S(word));
        return OG_ERROR;
    }

    return sql_parse_join_entry(stmt, sql_query, word);
}

status_t sql_parse_table(sql_stmt_t *stmt, sql_table_t *table, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    lex->flags = LEX_WITH_OWNER;

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!IS_VARIANT(word)) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "table name expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (word->type == WORD_TYPE_DQ_STRING) {
        table->tab_name_has_quote = OG_TRUE;
    }

    if (sql_convert_normal_table(stmt, word, table) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE) {
        return OG_SUCCESS;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!table->is_distribute_rule) {
        if (sql_try_parse_table_alias(stmt, &table->alias, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    return OG_SUCCESS;
}

status_t sql_set_table_qb_name(sql_stmt_t *stmt, sql_query_t *query)
{
    sql_table_t *table = NULL;
    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        OG_RETURN_IFERR(sql_copy_text(stmt->context, &query->block_info->origin_name, &table->qb_name));
    }
    return OG_SUCCESS;
}

uint32 sql_outer_join_count(sql_join_node_t *join_node)
{
    if (join_node->type == JOIN_TYPE_NONE) {
        return 0;
    }

    uint32 res = 0;

    if (join_node->type == JOIN_TYPE_LEFT || join_node->type == JOIN_TYPE_RIGHT || join_node->type == JOIN_TYPE_FULL) {
        res++;
    }

    res += sql_outer_join_count(join_node->left);
    res += sql_outer_join_count(join_node->right);

    return res;
}

#ifdef __cplusplus
}
#endif
