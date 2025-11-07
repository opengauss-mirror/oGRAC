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
 * ogsql_insert_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_insert_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_insert_parser.h"
#include "srv_instance.h"
#include "ogsql_select_parser.h"
#include "ogsql_update_parser.h"
#include "hint_parser.h"
#include "expr_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_init_insert(sql_stmt_t *stmt, sql_insert_t *insert_context)
{
    if (sql_create_list(stmt, &insert_context->pairs) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_list(stmt, &insert_context->pl_dc_lst) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_list(stmt, &insert_context->into_list) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_array(stmt->context, &insert_context->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&insert_context->table) != OG_SUCCESS) {
        return OG_ERROR;
    }

    insert_context->select_ctx = NULL;
    insert_context->plan = NULL;
    insert_context->pairs_count = 0;
    insert_context->flags = INSERT_SET_NONE;
    insert_context->ret_columns = NULL;
    insert_context->hint_info = NULL;
    insert_context->syntax_flag = INSERT_SET_NONE;
    return OG_SUCCESS;
}

static status_t sql_parse_single_insert_values(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word,
    bool32 is_first)
{
    lex_t *lex = stmt->session->lex;
    uint32 pair_id = 0;
    column_value_pair_t *pair = NULL;
    expr_tree_t *expr = NULL;
    status_t ret = OG_SUCCESS;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
        if ((insert_context->flags & INSERT_COLS_SPECIFIED)) {
            OG_BREAK_IF_TRUE(pair_id > insert_context->pairs->count - 1);
            pair = (column_value_pair_t *)cm_galist_get(insert_context->pairs, pair_id);
        } else {
            if (is_first) {
                ret = cm_galist_new(insert_context->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair);
                OG_BREAK_IF_ERROR(ret);
                ret = sql_create_list(stmt, &pair->exprs);
                OG_BREAK_IF_ERROR(ret);
            } else {
                OG_BREAK_IF_TRUE(pair_id > insert_context->pairs->count - 1);
                pair = (column_value_pair_t *)cm_galist_get(insert_context->pairs, pair_id);
            }
        }
        ret = sql_create_expr_until(stmt, &expr, word);
        OG_BREAK_IF_ERROR(ret);
        ret = cm_galist_insert(pair->exprs, expr);
        OG_BREAK_IF_ERROR(ret);
        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
        pair_id++;
    }

    lex_pop(lex);
    OG_RETURN_IFERR(ret);
    if (pair_id != insert_context->pairs->count - 1) {
        OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "number of arguments in expressions is not uniform");
        return OG_ERROR;
    }

    /* insert into xx values(xx) returning xx */
    uint32 org_flags = lex->flags;
    lex->flags = 0;
    ret = lex_fetch(lex, word);
    lex->flags = org_flags;
    return ret;
}

status_t sql_parse_insert_values(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word)
{
    bool32 is_first = OG_TRUE;

    if (word->id != KEY_WORD_VALUES) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "VALUES expected but %s found", W2S(word));
        return OG_ERROR;
    }

    insert_context->flags |= INSERT_VALS_SPECIFIED;
    for (;;) {
        OG_RETURN_IFERR(sql_parse_single_insert_values(stmt, insert_context, word, is_first));
        insert_context->pairs_count++;

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }

        // insert into t1(f1, f2) values(1,2),(3,4),(5,6)...
        is_first = OG_FALSE;
    }
    insert_context->flags &= ~INSERT_VALS_SPECIFIED;
    return OG_SUCCESS;
}

status_t sql_try_parse_insert_select(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word, bool32 *result)
{
    lex_t *lex = stmt->session->lex;

    if (word->id != KEY_WORD_SELECT && word->type != WORD_TYPE_BRACKET && word->id != KEY_WORD_WITH) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    lex_back(lex, word);

    *result = OG_TRUE;
    return sql_parse_select_context(stmt, SELECT_AS_VALUES, word, &insert_context->select_ctx);
}

status_t sql_convert_insert_column(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word, sql_text_t *column)
{
    status_t status;
    bool32 result = OG_FALSE;
    text_t *table = &insert_context->table->name.value;
    text_t *alias = (insert_context->table->alias.len > 0) ? &insert_context->table->alias.value : table;
    text_t *owner = &insert_context->table->user.value;

    if (word->ex_count == 2) {
        if (!cm_text_equal_ins(owner, (text_t *)&word->text)) {
            word->text.len = (uint32)((word->ex_words[1].text.str - word->text.str) + word->ex_words[1].text.len);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
            return OG_ERROR;
        }
        if (IS_DQ_STRING(word->ex_words[0].type) || !IS_CASE_INSENSITIVE) {
            result = cm_text_equal(table, (text_t *)&word->ex_words[0].text) ||
                cm_text_equal(alias, (text_t *)&word->ex_words[0].text);
        } else {
            result = cm_text_equal_ins(table, (text_t *)&word->ex_words[0].text) ||
                cm_text_equal_ins(alias, (text_t *)&word->ex_words[0].text);
        }
        if (!result) {
            word->text.len = (uint32)((word->ex_words[1].text.str - word->text.str) + word->ex_words[1].text.len);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
            return OG_ERROR;
        }
        status = sql_copy_object_name_loc(stmt->context, word->ex_words[1].type, &word->ex_words[1].text, column);
    } else if (word->ex_count == 1) {
        if (IS_DQ_STRING(word->type) || !IS_CASE_INSENSITIVE) {
            result = cm_text_equal(table, (text_t *)&word->text) || cm_text_equal(alias, (text_t *)&word->text);
        } else {
            result = cm_text_equal_ins(table, (text_t *)&word->text) || cm_text_equal_ins(alias, (text_t *)&word->text);
        }
        if (!result) {
            word->text.len = (uint32)((word->ex_words[0].text.str - word->text.str) + word->ex_words[0].text.len);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
            return OG_ERROR;
        }
        status = sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text, column);
    } else if (word->ex_count == 0) {
        status = sql_copy_object_name_loc(stmt->context, word->type, &word->text, column);
    } else {
        status = OG_ERROR;
    }

    if (status != OG_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name '%s'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_parse_insert_column_quote_info(word_t *word, column_value_pair_t *pair)
{
    if (word == NULL || pair == NULL) {
        return OG_ERROR;
    }

    if (word->ex_count == 2) {
        pair->column_name_has_quote = (word->ex_words[1].type == WORD_TYPE_DQ_STRING) ? OG_TRUE : OG_FALSE;
    } else if (word->ex_count == 1) {
        pair->column_name_has_quote = (word->ex_words[0].type == WORD_TYPE_DQ_STRING) ? OG_TRUE : OG_FALSE;
    } else if (word->ex_count == 0) {
        pair->column_name_has_quote = (word->type == WORD_TYPE_DQ_STRING) ? OG_TRUE : OG_FALSE;
    }
    return OG_SUCCESS;
}

status_t sql_try_parse_insert_columns(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word)
{
    word_t word2;
    lex_t *lex = stmt->session->lex;
    column_value_pair_t *pair = NULL;
    status_t status = OG_ERROR;

    if (word->type != WORD_TYPE_BRACKET) {
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word->text);
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    LEX_SAVE(lex);

    if (lex_fetch(lex, &word2) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (word2.type == WORD_TYPE_BRACKET || word2.id == KEY_WORD_SELECT || word2.id == KEY_WORD_WITH) {
        lex_pop(lex);
        return OG_SUCCESS;
    }
    LEX_RESTORE(lex);

    // insert into t1 (f1, f2 ...)
    for (;;) {
        lex->flags = LEX_WITH_OWNER;
        OG_BREAK_IF_ERROR(lex_expected_fetch_variant(lex, word));

        OG_BREAK_IF_ERROR(cm_galist_new(insert_context->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));

        OG_BREAK_IF_ERROR(sql_create_list(stmt, &pair->exprs));

        OG_BREAK_IF_ERROR(sql_parse_insert_column_quote_info(word, pair));

        OG_BREAK_IF_ERROR(sql_convert_insert_column(stmt, insert_context, word, &pair->column_name));

        OG_BREAK_IF_ERROR(lex_fetch(lex, word));

        if (word->type == WORD_TYPE_EOF) {
            status = OG_SUCCESS;
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            break;
        }
    }

    lex_pop(lex);
    OG_RETURN_IFERR(status);
    insert_context->flags |= INSERT_COLS_SPECIFIED;
    return lex_fetch(lex, word);
}


static status_t sql_parse_insert_update(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word3(lex, "DUPLICATE", "KEY", "UPDATE") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_update_t), (void **)&insert_context->update_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_init_update(stmt, insert_context->update_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_array_put(&insert_context->update_ctx->query->tables, insert_context->table) != OG_SUCCESS) {
        return OG_ERROR;
    }

    insert_context->update_ctx->param_start_pos = stmt->context->params->count;
    return sql_parse_update_pairs(stmt, insert_context->update_ctx, word);
}

static void set_insert_ctx(sql_insert_t *insert_context, uint32 num)
{
    insert_all_t *into_item = NULL;
    into_item = (insert_all_t *)cm_galist_get(insert_context->into_list, num);
    insert_context->table = into_item->table;
    insert_context->pairs = into_item->pairs;
    insert_context->pairs_count = into_item->pairs_count;
    insert_context->flags = into_item->flags;
}

static status_t sql_parse_into_info(sql_stmt_t *stmt, sql_insert_t *insert_context, word_t *word)
{
    insert_all_t *into_item = NULL;
    OG_RETURN_IFERR(sql_parse_table(stmt, insert_context->table, word));
    OG_RETURN_IFERR(sql_try_parse_insert_columns(stmt, insert_context, word));
    OG_RETURN_IFERR(sql_parse_insert_values(stmt, insert_context, word));
    OG_RETURN_IFERR(cm_galist_new(insert_context->into_list, sizeof(insert_all_t), (pointer_t *)&into_item));
    into_item->table = insert_context->table;
    into_item->pairs = insert_context->pairs;
    into_item->pairs_count = insert_context->pairs_count;
    into_item->flags = insert_context->flags;

    return OG_SUCCESS;
}

static status_t sql_parse_insert_all(sql_stmt_t *stmt, sql_insert_t *insert_context)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    uint32 len;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "INTO"));
    OG_RETURN_IFERR(sql_parse_into_info(stmt, insert_context, &word));

    while (lex_match_head(&word.text, "INTO", &len)) {
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&insert_context->table));
        OG_RETURN_IFERR(sql_create_list(stmt, &insert_context->pairs));

        insert_context->pairs_count = 0;
        insert_context->flags = INSERT_SET_NONE;
        OG_RETURN_IFERR(sql_parse_into_info(stmt, insert_context, &word));
    }

    set_insert_ctx(insert_context, 0);
    OG_RETURN_IFERR(sql_try_parse_insert_select(stmt, insert_context, &word, &result));

    if (!result) {
        OG_SRC_THROW_ERROR(word.loc, ERR_SQL_SYNTAX_ERROR, "select_clause expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_normal_insert(sql_stmt_t *stmt, sql_insert_t *insert_context)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    status_t status = OG_ERROR;

    OG_RETURN_IFERR(lex_try_fetch(lex, "IGNORE", &result));
    if (result == OG_TRUE) {
        insert_context->syntax_flag |= INSERT_IS_IGNORE;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "INTO", &result));

    OG_RETURN_IFERR(SQL_SSA_PUSH(stmt, &insert_context->ssa));

    do {
        OG_BREAK_IF_ERROR(sql_parse_table(stmt, insert_context->table, &word));

        OG_BREAK_IF_ERROR(sql_try_parse_insert_columns(stmt, insert_context, &word));

        OG_BREAK_IF_ERROR(sql_try_parse_insert_select(stmt, insert_context, &word, &result));

        if (!result) {
            OG_BREAK_IF_ERROR(sql_parse_insert_values(stmt, insert_context, &word));
        } else {
            OG_BREAK_IF_ERROR(lex_fetch(lex, &word));
        }

        if (word.id == KEY_WORD_ON) {
            OG_BREAK_IF_ERROR(sql_parse_insert_update(stmt, insert_context, &word));
        }

        if (word.id == KEY_WORD_RETURN || word.id == KEY_WORD_RETURNING) {
            OG_BREAK_IF_ERROR(sql_parse_return_columns(stmt, &insert_context->ret_columns, &word));
        }

        if (word.type != WORD_TYPE_EOF) {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
            break;
        }
        status = OG_SUCCESS;
    } while (0);

    SQL_SSA_POP(stmt);
    return status;
}

static status_t sql_parse_insert(sql_stmt_t *stmt, sql_insert_t *insert_context)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    status_t status;

    OG_RETURN_IFERR(sql_init_insert(stmt, insert_context));

    OG_RETURN_IFERR(lex_try_fetch(lex, "ALL", &result));

    if (result == OG_TRUE) {
        insert_context->syntax_flag |= INSERT_IS_ALL;
        OG_RETURN_IFERR(SQL_SSA_PUSH(stmt, &insert_context->ssa));
        status = sql_parse_insert_all(stmt, insert_context);
        SQL_SSA_POP(stmt);
        return status;
    } else {
        return sql_parse_normal_insert(stmt, insert_context);
    }
}

status_t sql_create_insert_context(sql_stmt_t *stmt, sql_text_t *sql, sql_insert_t **insert_context)
{
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(sql_insert_t), (void **)insert_context) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_push(lex, sql) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "INSERT") != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_parse_insert(stmt, *insert_context) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
