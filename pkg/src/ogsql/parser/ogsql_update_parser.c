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
 * ogsql_update_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_update_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_update_parser.h"
#include "srv_instance.h"
#include "ogsql_select_parser.h"
#include "hint_parser.h"
#include "cond_parser.h"
#include "table_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_parse_update_multi_sets(sql_stmt_t *stmt, sql_update_t *update_ctx, expr_tree_t *expr,
    column_value_pair_t *val_pair)
{
    sql_select_t *select_ctx = NULL;
    expr_tree_t *tmp_expr = NULL;
    int rs_no = 1;

    // Easier to verify expr type here than in sql_verify_update_pair.
    if (expr->root->type != EXPR_NODE_SELECT) {
        OG_SRC_THROW_ERROR(expr->root->loc, ERR_SQL_SYNTAX_ERROR, "UPDATE ... SET expression must be a subquery");
        return OG_ERROR;
    }
    select_ctx = (sql_select_t *)expr->root->value.v_obj.ptr;
    select_ctx->type = SELECT_AS_MULTI_VARIANT;

    tmp_expr = val_pair->column_expr->next;
    val_pair->column_expr->next = NULL;
    val_pair->rs_no = rs_no = 1; // Ref to subquery rs_column, start with 1, 0 for non-multi set
    while (tmp_expr != NULL) {
        column_value_pair_t *next_pair = NULL;
        OG_RETURN_IFERR(cm_galist_new(update_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&next_pair));
        OG_RETURN_IFERR(sql_create_list(stmt, &next_pair->exprs));
        OG_RETURN_IFERR(cm_galist_insert(next_pair->exprs, expr));

        next_pair->column_expr = tmp_expr;
        tmp_expr = tmp_expr->next;
        next_pair->column_expr->next = NULL;
        ++rs_no;
        next_pair->rs_no = rs_no;
    }
    return OG_SUCCESS;
}

status_t sql_parse_update_pairs(sql_stmt_t *stmt, sql_update_t *update_ctx, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    column_value_pair_t *val_pair = NULL;
    uint32 len;
    expr_tree_t *expr = NULL;

    for (;;) {
        bool32 result = OG_FALSE;

        OG_RETURN_IFERR(cm_galist_new(update_ctx->pairs, sizeof(column_value_pair_t), (pointer_t *)&val_pair));
        OG_RETURN_IFERR(sql_create_list(stmt, &val_pair->exprs));

        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (result) {
            OG_RETURN_IFERR(sql_create_expr_list(stmt, &word->text, &val_pair->column_expr));
            OG_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
        } else {
            OG_RETURN_IFERR(sql_create_expr_until(stmt, &val_pair->column_expr, word));
        }

        if (word->type != WORD_TYPE_COMPARE || !lex_match_head(&word->text, "=", &len)) {
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "= expected");
            return OG_ERROR;
        } else if (word->id == CMP_TYPE_EQUAL_ALL || word->id == CMP_TYPE_EQUAL_ANY) {
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "unexpected ALL or ANY");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
        OG_RETURN_IFERR(cm_galist_insert(val_pair->exprs, expr));

        // update multi set
        if (val_pair->column_expr->next != NULL) {
            OG_RETURN_IFERR(sql_parse_update_multi_sets(stmt, update_ctx, expr, val_pair));
        }

        if (word->type == WORD_TYPE_EOF) {
            return OG_SUCCESS;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }
    return OG_SUCCESS;
}

status_t sql_parse_update_set(sql_stmt_t *stmt, sql_update_t *update_ctx, word_t *word)
{
    if (word->id != KEY_WORD_SET) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "SET expected but %s found", W2S(word));
        return OG_ERROR;
    }
    return sql_parse_update_pairs(stmt, update_ctx, word);
}

status_t sql_init_update(sql_stmt_t *stmt, sql_update_t *update_ctx)
{
    OG_RETURN_IFERR(sql_create_list(stmt, &update_ctx->pairs));
    OG_RETURN_IFERR(sql_create_list(stmt, &update_ctx->objects));
    OG_RETURN_IFERR(sql_create_list(stmt, &update_ctx->pl_dc_lst));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&update_ctx->query));
    OG_RETURN_IFERR(sql_init_query(stmt, NULL, stmt->session->lex->loc, update_ctx->query));
    OG_RETURN_IFERR(sql_copy_str(stmt->context, "UPD$1", &update_ctx->query->block_info->origin_name));
    update_ctx->plan = NULL;
    update_ctx->ret_columns = NULL;
    update_ctx->param_start_pos = 0;
    update_ctx->hint_info = NULL;
    return OG_SUCCESS;
}

status_t sql_parse_return_columns(sql_stmt_t *stmt, galist_t **ret_columns, word_t *word)
{
    galist_t *columns = NULL;
    expr_tree_t *expr = NULL;

    /* parse returning exprs */
    OG_RETURN_IFERR(sql_create_list(stmt, &columns));

    for (;;) {
        OG_RETURN_IFERR(sql_parse_column(stmt, columns, word));

        if (IS_SPEC_CHAR(word, ',')) {
            continue;
        }
        break;
    }

    *ret_columns = columns;

    /* try parse into exprs */
    if (word->id == KEY_WORD_INTO) {
        for (;;) {
            OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
            if (expr->root->type != EXPR_NODE_PARAM) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "params expected but %s found", W2S(word));
                return OG_ERROR;
            }

            if (IS_SPEC_CHAR(word, ',')) {
                continue;
            }
            break;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_update(sql_stmt_t *stmt, sql_update_t *update_ctx)
{
    word_t word;
    status_t status = OG_ERROR;

    OG_RETURN_IFERR(sql_init_update(stmt, update_ctx));

    OG_RETURN_IFERR(SQL_NODE_PUSH(stmt, update_ctx->query));
    OG_RETURN_IFERR(SQL_SSA_PUSH(stmt, &update_ctx->query->ssa));

    do {
        OG_BREAK_IF_ERROR(sql_parse_join_entry(stmt, update_ctx->query, &word));
        OG_BREAK_IF_ERROR(sql_parse_update_set(stmt, update_ctx, &word));

        /* update where clause */
        if (word.id == KEY_WORD_WHERE) {
            OG_BREAK_IF_ERROR(sql_create_cond_until(stmt, &update_ctx->query->cond, &word));
        }

        if (word.id == KEY_WORD_RETURN || word.id == KEY_WORD_RETURNING) {
            OG_BREAK_IF_ERROR(sql_parse_return_columns(stmt, &update_ctx->ret_columns, &word));
        }

        if (word.id == KEY_WORD_LIMIT || word.id == KEY_WORD_OFFSET) {
            if (update_ctx->query->tables.count > 1) {
                OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "multi update do not support limit");
                return OG_ERROR;
            }
            OG_BREAK_IF_ERROR(sql_parse_limit_offset(stmt, &update_ctx->query->limit, &word));
        }

        if (word.type != WORD_TYPE_EOF) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "text end expected but %s found", W2S(&word));
            break;
        }
        status = OG_SUCCESS;
    } while (0);

    OG_RETURN_IFERR(sql_set_table_qb_name(stmt, update_ctx->query));

    SQL_SSA_POP(stmt);
    SQL_NODE_POP(stmt);
    return status;
}

status_t sql_create_update_context(sql_stmt_t *stmt, sql_text_t *sql, sql_update_t **update_ctx)
{
    lex_t *lex = stmt->session->lex;

    if (sql_alloc_mem(stmt->context, sizeof(sql_update_t), (void **)update_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_push(lex, sql) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "UPDATE") != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_parse_update(stmt, *update_ctx) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
