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
 * ogsql_replace_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_replace_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_replace_parser.h"
#include "ogsql_insert_parser.h"
#include "hint_parser.h"
#include "expr_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_init_replace(sql_stmt_t *stmt, sql_replace_t *replace_context)
{
    if (sql_create_list(stmt, &replace_context->insert_ctx.pairs) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_list(stmt, &replace_context->insert_ctx.pl_dc_lst) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_array(stmt->context, &replace_context->insert_ctx.ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&replace_context->insert_ctx.table) != OG_SUCCESS) {
        return OG_ERROR;
    }

    replace_context->insert_ctx.flags = INSERT_SET_NONE;
    replace_context->insert_ctx.select_ctx = NULL;
    replace_context->insert_ctx.plan = NULL;
    replace_context->insert_ctx.pairs_count = 0;
    replace_context->insert_ctx.hint_info = NULL;
    return OG_SUCCESS;
}

static status_t sql_parse_replace_set(sql_stmt_t *stmt, sql_replace_t *replace_context, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    column_value_pair_t *pair = NULL;
    expr_tree_t *expr = NULL;
    sql_insert_t *insert_ctx = &replace_context->insert_ctx;

    for (;;) {
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        OG_RETURN_IFERR(cm_galist_new(insert_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&pair));
        OG_RETURN_IFERR(sql_create_list(stmt, &pair->exprs));

        OG_RETURN_IFERR(sql_parse_insert_column_quote_info(word, pair));
        OG_RETURN_IFERR(sql_convert_insert_column(stmt, insert_ctx, word, &pair->column_name));
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "="));

        OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
        OG_RETURN_IFERR(cm_galist_insert(pair->exprs, expr));

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    insert_ctx->pairs_count++;
    insert_ctx->flags |= INSERT_COLS_SPECIFIED;
    return OG_SUCCESS;
}

static status_t sql_parse_replace_clause(sql_stmt_t *stmt, sql_replace_t *replace_context, sql_insert_t *insert_ctx)
{
    word_t word;
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(sql_parse_table(stmt, insert_ctx->table, &word));

    OG_RETURN_IFERR(sql_try_parse_insert_columns(stmt, insert_ctx, &word));

    OG_RETURN_IFERR(sql_try_parse_insert_select(stmt, insert_ctx, &word, &result));

    if (!result) {
        if (word.id == KEY_WORD_SET) {
            if (insert_ctx->pairs->count != 0) {
                OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "not supported to specify column in replace set");
                return OG_ERROR;
            }
            OG_RETURN_IFERR(sql_parse_replace_set(stmt, replace_context, &word));
        } else {
            OG_RETURN_IFERR(sql_parse_insert_values(stmt, insert_ctx, &word));
        }
    }

    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_replace(sql_stmt_t *stmt, sql_replace_t *replace_context)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    status_t status;
    sql_insert_t *insert_ctx = &(replace_context->insert_ctx);
    OG_RETURN_IFERR(sql_init_replace(stmt, replace_context));

    OG_RETURN_IFERR(lex_try_fetch(lex, "INTO", &result));

    OG_RETURN_IFERR(SQL_SSA_PUSH(stmt, &insert_ctx->ssa));
    status = sql_parse_replace_clause(stmt, replace_context, insert_ctx);
    SQL_SSA_POP(stmt);
    return status;
}


status_t sql_create_replace_context(sql_stmt_t *stmt, sql_text_t *sql, sql_replace_t **replace_context)
{
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(sql_replace_t), (void **)replace_context) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_push(lex, sql) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "REPLACE") != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_parse_replace(stmt, *replace_context) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
