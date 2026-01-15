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
 * expr_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/expr_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __EXPR_PARSER_H__
#define __EXPR_PARSER_H__

#include "ogsql_expr.h"
#include "scanner.h"
#include "ogsql_cond.h"
#include "knl_database.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_timezone_type {
    WITHOUT_TIMEZONE,
    WITH_TIMEZONE,
    WITH_LOCAL_TIMEZONE,
} timezone_type_t;

typedef struct st_type_word {
    char *str;
    galist_t *typemode;
    source_location_t loc;
    union {
        // for timestamp
        struct {
            timezone_type_t timezone;
        };
        // for interval day[d_n] to second[s_n], d_n represent in typemode while s_n represent in second_typemde
        struct {
            galist_t *second_typemde;
        };
        // for string
        struct {
            int array_size;
            uint8 charset;
            uint8 collation;
            bool8 is_char;
            bool8 is_array;
        };
    };
} type_word_t;

#define IS_DUAL_TABLE_NAME(tab_name) \
    (cm_text_str_equal_ins(tab_name, "DUAL") || cm_text_str_equal(tab_name, "SYS_DUMMY"))

static inline status_t sql_word_as_table(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var->table.name) != OG_SUCCESS) {
            return OG_ERROR;
        }
        var->table.user.loc = word->text.loc;
        var->table.user.implicit = OG_TRUE;
        text_t user_name = { stmt->session->curr_schema, (uint32)strlen(stmt->session->curr_schema) };
        if (IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }

        if (sql_copy_name(stmt->context, &user_name, (text_t *)&var->table.user) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (word->ex_count == 1) {
        if (sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->table.name) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->table.user) != OG_SUCCESS) {
            return OG_ERROR;
        }
        var->table.user.implicit = OG_FALSE;
        if (cm_text_str_equal_ins(&var->table.user.value, "SYS") && IS_DUAL_TABLE_NAME(&var->table.name.value)) {
            cm_text_upper(&var->table.name.value);
        }
    } else {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline status_t sql_word_as_column(sql_stmt_t *stmt, word_t *word, var_word_t *var)
{
    if (word->ex_count == 0) {
        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var->column.name));

        var->column.table.value = CM_NULL_TEXT;
        var->column.table.loc = word->text.loc;

        var->column.user.value = CM_NULL_TEXT;
        var->column.user.loc = word->text.loc;
    } else if (word->ex_count == 1) {
        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->column.name));

        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var->column.table));

        OG_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->column.user_ex));

        var->column.user.value = CM_NULL_TEXT;
        var->column.user.loc = word->text.loc;
    } else if (word->ex_count == 2) {
        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[1].type, &word->ex_words[1].text,
            &var->column.name));

        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ex_words[0].type, &word->ex_words[0].text,
            &var->column.table));

        OG_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var->column.user));
    } else {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name is found");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline status_t sql_word_as_func(sql_stmt_t *stmt, word_t *word, var_word_t *var_word)
{
    if (word->ex_count == 0) {
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var_word->func.name));

        var_word->func.args.value = CM_NULL_TEXT;
        var_word->func.args.loc = word->text.loc;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = word->text.loc;
        var_word->func.user.value = CM_NULL_TEXT;
        var_word->func.user.loc = word->text.loc;
    } else if (word->ex_count == 1) {
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->type | word->ori_type, &word->text, &var_word->func.name));

        var_word->func.args = word->ex_words[0].text;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = word->text.loc;
        var_word->func.user.value = CM_NULL_TEXT;
        var_word->func.user.loc = word->text.loc;
    } else if (word->ex_count == 2) {
        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->ori_type,
                                                 &word->text, &var_word->func.org_user));
        OG_RETURN_IFERR(sql_copy_object_name_prefix_tenant_loc(stmt, word->ori_type,
                                                               &word->text, &var_word->func.user));
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[0].type,
                                     &word->ex_words[0].text, &var_word->func.name));

        var_word->func.args = word->ex_words[1].text;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = word->text.loc;
    } else if (word->ex_count == 3) {
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[1].type,
                                     &word->ex_words[1].text, &var_word->func.name));

        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, word->ex_words[0].type,
                                     &word->ex_words[0].text, &var_word->func.pack));

        OG_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &word->text, &var_word->func.user));

        var_word->func.args = word->ex_words[2].text;
    } else {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid function or procedure name is found");
        return OG_ERROR;
    }

    var_word->func.count = word->ex_count;

    return OG_SUCCESS;
}

static inline status_t sql_expr_list_as_func(sql_stmt_t *stmt, galist_t *list, var_word_t *var_word)
{
    /* the caller should check the list content, it should be all const string epxr in the list */
    expr_tree_t *list_expr = cm_galist_get(list, 0);
    sql_text_t sql_text;
    sql_text.value = list_expr->root->value.v_text;
    sql_text.loc = list_expr->root->loc;
    if (list->count == 1) {
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, WORD_TYPE_FUNCTION, &sql_text, &var_word->func.name));

        /* we will deal with args later */
        var_word->func.args.value = CM_NULL_TEXT;
        var_word->func.args.loc = sql_text.loc;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = sql_text.loc;
        var_word->func.user.value = CM_NULL_TEXT;
        var_word->func.user.loc = sql_text.loc;
    } else if (list->count == 2) {
        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, WORD_TYPE_UNKNOWN,
                                                 &sql_text, &var_word->func.org_user));
        OG_RETURN_IFERR(sql_copy_object_name_prefix_tenant_loc(stmt, WORD_TYPE_UNKNOWN,
                                                               &sql_text, &var_word->func.user));
        list_expr = cm_galist_get(list, 1);
        sql_text.value = list_expr->root->value.v_text;
        sql_text.loc = list_expr->root->loc;
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, WORD_TYPE_FUNCTION, &sql_text, &var_word->func.name));

        /* we will deal with args later */
        var_word->func.args.value = CM_NULL_TEXT;
        var_word->func.args.loc = sql_text.loc;
        var_word->func.pack.value = CM_NULL_TEXT;
        var_word->func.pack.loc = sql_text.loc;
    } else if (list->count == 3) {
        OG_RETURN_IFERR(sql_copy_name_prefix_tenant_loc(stmt, &sql_text, &var_word->func.user));
        list_expr = cm_galist_get(list, 1);
        sql_text.value = list_expr->root->value.v_text;
        sql_text.loc = list_expr->root->loc;
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, WORD_TYPE_UNKNOWN, &sql_text, &var_word->func.pack));
        list_expr = cm_galist_get(list, 2);
        sql_text.value = list_expr->root->value.v_text;
        sql_text.loc = list_expr->root->loc;
        OG_RETURN_IFERR(
            sql_copy_object_name_loc(stmt->context, WORD_TYPE_FUNCTION, &sql_text, &var_word->func.name));

        /* we will deal with args later */
        var_word->func.args.value = CM_NULL_TEXT;
        var_word->func.args.loc = sql_text.loc;
    } else {
        OG_SRC_THROW_ERROR(sql_text.loc, ERR_SQL_SYNTAX_ERROR, "invalid function or procedure name is found");
        return OG_ERROR;
    }

    var_word->func.count = list->count;
    return OG_SUCCESS;
}

#define EXPR_EXPECT_NONE 0x00000000
#define EXPR_EXPECT_UNARY_OP 0x00000001
#define EXPR_EXPECT_OPER 0x00000002
#define EXPR_EXPECT_VAR 0x00000004
#define EXPR_EXPECT_UNARY 0x00000008
#define EXPR_EXPECT_STAR 0x00000010
#define EXPR_EXPECT_ALPHA 0x00000020

/* The modes of datatype parsing */
typedef enum en_parsing_mode {
    PM_NORMAL, /* parsing SQL column datatype or cast function  */
    PM_PL_VAR, /* parsing for procedure variables */
    PM_PL_ARG, /* parsing for procedure argument, no type attr is allowed */
} pmode_t;

status_t sql_init_expr_node(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t **node,
    og_type_t type, expr_node_type_t expr_type, source_location_t loc);
status_t sql_create_expr_tree(sql_stmt_t *stmt, expr_tree_t **expr, og_type_t type, expr_node_type_t expr_type,
    source_location_t loc);
status_t sql_create_int_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, int val, source_location_t loc);
status_t sql_create_float_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, source_location_t loc);
status_t sql_create_string_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, source_location_t loc);
status_t sql_create_bool_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, bool32 val, source_location_t loc);
status_t sql_create_null_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, source_location_t loc);
status_t sql_create_columnref_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, galist_t *list,
    source_location_t loc);
status_t sql_create_indices_expr(sql_stmt_t *stmt, expr_tree_t **expr, int32 start, int32 end, source_location_t loc);
status_t sql_create_paramref_expr(sql_stmt_t *stmt, expr_tree_t **expr, uint32 token_len, lex_location_t lex_loc);
status_t sql_create_case_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t* case_arg,
    galist_t* case_pair, expr_tree_t* default_expr, source_location_t loc);
status_t sql_expr_tree_to_cond_node(sql_stmt_t *stmt, expr_tree_t *expr, cond_node_t **node);
status_t sql_create_select_expr(sql_stmt_t *stmt, expr_tree_t **expr, sql_select_t *select_ctx, sql_array_t *array,
    source_location_t loc);
status_t sql_build_type_expr(sql_stmt_t *stmt, type_word_t *type, expr_tree_t *type_expr);

status_t sql_create_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word);
status_t sql_create_expr_from_text(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr, word_flag_t word_flag);
status_t sql_create_expr_list(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr);
status_t sql_create_expr(sql_stmt_t *stmt, expr_tree_t **expr);
status_t sql_add_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word);
status_t sql_create_expr_from_word(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr);
status_t sql_generate_expr(expr_tree_t *expr);
status_t sql_parse_typmode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t sql_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword);
status_t sql_parse_datatype_typemode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword, word_t *tword);
status_t sql_parse_case_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_build_default_reserved_expr(sql_stmt_t *stmt, expr_tree_t **r_result);
status_t sql_build_column_expr(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **r_result);
status_t sql_copy_text_remove_quotes(sql_context_t *context, text_t *src, text_t *dst);
status_t sql_word2text(sql_stmt_t *stmt, word_t *word, expr_node_t *node);
status_t sql_word2number(word_t *word, expr_node_t *node);

#define EXPR_VAR_WORDS                                                                                        \
    (WORD_TYPE_VARIANT | WORD_TYPE_FUNCTION | WORD_TYPE_STRING | WORD_TYPE_PARAM | WORD_TYPE_NUMBER |         \
        WORD_TYPE_RESERVED | WORD_TYPE_DATATYPE | WORD_TYPE_BRACKET | WORD_TYPE_KEYWORD | WORD_TYPE_PL_ATTR | \
        WORD_TYPE_PL_NEW_COL | WORD_TYPE_PL_OLD_COL | WORD_TYPE_DQ_STRING | WORD_TYPE_HEXADECIMAL |           \
        WORD_TYPE_JOIN_COL | WORD_TYPE_ARRAY)

#define EXPR_IS_UNARY_OP(word)                                                             \
    ((word)->type == (uint32)WORD_TYPE_OPERATOR && ((word)->id == (uint32)OPER_TYPE_SUB || \
        (word)->id == (uint32)OPER_TYPE_ADD || (word)->id == (uint32)OPER_TYPE_PRIOR))

#define EXPR_IS_UNARY_OP_ROOT(word) \
    ((word)->type == (uint32)WORD_TYPE_OPERATOR && ((word)->id == (uint32)OPER_TYPE_ROOT))

#define EXPR_IS_OPER(word) ((word)->type == (uint32)WORD_TYPE_OPERATOR)

#define EXPR_IS_STAR(word)                                        \
    ((word)->text.len > 0 && CM_TEXT_END(&(word)->text) == '*' && \
        (word)->type != WORD_TYPE_DQ_STRING) /* the last char of word is * */
status_t sql_add_param_mark(sql_stmt_t *stmt, word_t *word, bool32 *is_repeated, uint32 *pnid);
status_t sql_create_star_expr(sql_stmt_t *stmt, expr_tree_t **expr, lex_location_t loc);
status_t sql_create_prior_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t *column, source_location_t loc);
status_t sql_create_reserved_expr(sql_stmt_t *stmt, expr_tree_t **expr, uint32 res_id, bool32 namable,
    source_location_t loc);

#ifdef __cplusplus
}
#endif

#endif
