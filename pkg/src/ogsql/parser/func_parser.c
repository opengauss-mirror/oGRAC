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
 * func_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/func_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "func_parser.h"
#include "cond_parser.h"
#include "ogsql_select_parser.h"
#include "ogsql_self_func.h"
#include "pl_udt.h"
#include "decl_cl.h"
#include "typedef_cl.h"
#include "json/ogsql_json.h"


#ifdef __cplusplus
extern "C" {
#endif

status_t sql_try_fetch_func_arg(sql_stmt_t *stmt, text_t *arg_name)
{
    char curr;
    char next;
    word_t word;
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;

    LEX_SAVE(lex);

    if (lex_try_fetch_variant(lex, &word, &result) != OG_SUCCESS) {
        LEX_RESTORE(lex);
        return OG_ERROR;
    }

    if (!result) {
        LEX_RESTORE(lex);
        return OG_SUCCESS;
    }

    lex_trim(lex->curr_text);
    lex->loc = lex->curr_text->loc;
    lex->begin_addr = lex->curr_text->str;

    if (lex->curr_text->len < sizeof("=>") - 1) {
        LEX_RESTORE(lex);
        return OG_SUCCESS;
    }

    curr = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);
    (void)lex_skip(lex, 1);

    if (curr != '=' || next != '>') {
        LEX_RESTORE(lex);
        return OG_SUCCESS;
    }

    return sql_copy_object_name_ci(stmt->context, word.type, &word.text.value, arg_name);
}

static key_word_t g_pkg_key_words[] = {
    { (uint32)KEY_WORD_ALL, OG_TRUE, { (char *)"all", 3 } }
};

/* the parse logic of the argument expression for the most generic case (syntax:  function(arg1, arg2, ...)) */
static status_t sql_build_func_args(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = NULL;
    bool32 assign_arg = OG_FALSE;
    text_t arg_name;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_cnt = lex->key_word_count;
    arg_expr = &func_node->argument;
    lex->key_words = g_pkg_key_words;
    lex->key_word_count = ELEMENT_COUNT(g_pkg_key_words);
    for (;;) {
        arg_name.len = 0;
        if (sql_try_fetch_func_arg(stmt, &arg_name)) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_cnt;
            return OG_ERROR;
        }
        if (arg_name.len == 0 && assign_arg) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_cnt;
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, " '=>' expected");
            return OG_ERROR;
        }

        if (sql_create_expr_until(stmt, arg_expr, word) != OG_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_cnt;
            return OG_ERROR;
        }

        if (arg_name.len > 0) {
            assign_arg = OG_TRUE;
            (*arg_expr)->arg_name = arg_name;
        }

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);
        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_OPERATOR);

        if (!IS_SPEC_CHAR(word, ',')) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_cnt;
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
            return OG_ERROR;
        }

        arg_expr = &(*arg_expr)->next;
    }
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_cnt;
    return OG_SUCCESS;
}

/*
 * the parse logic of the special argument expression for trim
 * - syntax:  TRIM([ { { LEADING | TRAILING | BOTH } [ trim_character ] | trim_character }   FROM ]  trim_source )
 * and it also compatible with the generic function call syntax:
 * - compatibility: TRIM(trim_source[, trim_character])
 */
static status_t sql_build_func_args_trim(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    uint32 match_id;
    bool32 exist = OG_FALSE;
    bool32 reverse = OG_FALSE;
    lex_t *lex = stmt->session->lex;
    expr_tree_t *temp = (expr_tree_t *)NULL;
    func_node->ext_args = FUNC_BOTH;
    OG_RETURN_IFERR(lex_try_fetch_1of3(lex, "TRAILING", "LEADING", "BOTH", &match_id));
    if (OG_INVALID_ID32 != match_id) {
        if (match_id == 0) {
            func_node->ext_args = FUNC_RTRIM;
        } else if (match_id == 1) {
            func_node->ext_args = FUNC_LTRIM;
        } else {
            func_node->ext_args = FUNC_BOTH;
        }
        /*
         * if trim type specified, check whether the trim type is next to keyword FROM
         * if yes, skip the "FROM" to avoid error in sql_create_expr_until()
         * this skip is intended to support TRIM( {LEADING | TRAILING | BOTH} FROM {trimSource} )
         */
        OG_RETURN_IFERR(lex_try_fetch(lex, "FROM", &exist));
    }

    if (sql_create_expr_until(stmt, &func_node->argument, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        return OG_SUCCESS;
    }

    if ((word->id != KEY_WORD_FROM) && !(IS_SPEC_CHAR(word, ','))) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "from or \",\" expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (word->id == KEY_WORD_FROM) {
        reverse = OG_TRUE;
    }

    if (sql_create_expr_until(stmt, &func_node->argument->next, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        return OG_ERROR;
    }

    if (reverse) {
        temp = func_node->argument;
        func_node->argument = temp->next;
        temp->next = NULL;
        func_node->argument->next = temp;
    }

    return OG_SUCCESS;
}

/*
 * create a expression of a const node according to the c-style string specified.
 * the c-style string is expected to be terminated with '\0'
 */
status_t sql_create_const_string_expr(sql_stmt_t *stmt, expr_tree_t **new_expr, const char *char_str)
{
    expr_tree_t *ret_val = NULL;
    expr_node_t *const_node = NULL;
    char *txt_buf = NULL;
    uint32 txt_len;

    CM_POINTER3(stmt, new_expr, char_str);

    OG_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, sizeof(expr_tree_t), (void **)&ret_val));
    OG_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, sizeof(expr_node_t), (void **)&const_node));
    txt_len = (uint32)strlen(char_str);
    if (txt_len > 0) {
        OG_RETURN_IFERR(sql_alloc_mem((void *)stmt->context, (uint32)strlen(char_str), (void **)&txt_buf));
        MEMS_RETURN_IFERR(memcpy_s(txt_buf, txt_len, char_str, txt_len));
    }
    const_node->type = EXPR_NODE_CONST;
    const_node->owner = ret_val;
    const_node->datatype = OG_TYPE_STRING;
    const_node->value.is_null = OG_FALSE;
    const_node->value.type = OG_TYPE_STRING;
    const_node->value.v_text.len = txt_len;
    const_node->value.v_text.str = txt_buf;

    ret_val->owner = stmt->context;
    ret_val->root = const_node;
    ret_val->generated = OG_TRUE;
    ret_val->next = NULL;

    *new_expr = ret_val;
    return OG_SUCCESS;
}

static inline void sql_set_arg_target_formal(expr_tree_t **next, expr_tree_t **target, expr_tree_t *target_formal)
{
    if (*next != NULL) {
        (*next)->next = target_formal;
    } else {
        (*target) = target_formal;
    }
    (*next) = target_formal;
}

static status_t sql_build_func_args_group_concat(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node,
    sql_text_t *arg_text)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *arg_target = NULL;
    expr_tree_t *arg_sep = NULL;
    expr_tree_t *arg_next = NULL;
    expr_tree_t *target_formal = NULL;
    bool32 has_separator = OG_FALSE;

    for (;;) {
        OG_RETURN_IFERR(sql_create_expr_until(stmt, &target_formal, word));

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_OPERATOR);

        /*
         * currently, we only support "GROUP_CONCAT(expr[, expr...] [SEPARATOR sep_char])",
         * so we stop the loop for parsing the next argument as the sep_char
         */
        if (word->type == WORD_TYPE_KEYWORD && word->id == KEY_WORD_SEPARATOR) {
            has_separator = OG_TRUE;
            break;
        }

        /* "GROUP_CONCAT(expr [order by expr [ASC | DESC]])" */
        if (word->type == WORD_TYPE_KEYWORD && word->id == KEY_WORD_ORDER) {
            OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&func_node->sort_items));
            cm_galist_init(func_node->sort_items, stmt->context, sql_alloc_mem);
            OG_RETURN_IFERR(sql_parse_order_by_items(stmt, func_node->sort_items, word));

            /* "SEPARATOR" or EOF is expected when "ORDER BY" is encounted */
            has_separator = (word->type == WORD_TYPE_KEYWORD && word->id == KEY_WORD_SEPARATOR);
            break;
        }
        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
            return OG_ERROR;
        }
        sql_set_arg_target_formal(&arg_next, &arg_target, target_formal);
    }

    sql_set_arg_target_formal(&arg_next, &arg_target, target_formal);
    if (has_separator == OG_TRUE) {
        OG_RETURN_IFERR(sql_create_expr_until(stmt, &arg_sep, word));
    } else {
        /* construct the default separator */
        OG_RETURN_IFERR(sql_create_const_string_expr(stmt, &arg_sep, ","));
    }
    arg_sep->next = arg_target;

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "end expected but \"%s\" found", W2S(word));
        return OG_ERROR;
    }

    func_node->argument = arg_sep;
    return OG_SUCCESS;
}

/*
 * syntax substr('xxx' from xx for xx)
 * parse substr/substring args alone
 */
static status_t sql_build_func_args_substr(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text)
{
    bool32 has_from = OG_FALSE;
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = &func_node->argument;

    for (;;) {
        if (sql_create_expr_until(stmt, arg_expr, word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            break;
        }
        arg_expr = &(*arg_expr)->next;

        if (word->id == KEY_WORD_FROM) {
            has_from = OG_TRUE;
            continue;
        }

        if (!has_from && !(IS_SPEC_CHAR(word, ','))) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
            return OG_ERROR;
        }

        if (has_from && word->id != KEY_WORD_FOR) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "'for' expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

/*
 * EXTRACT( { YEAR|MONTH|DAY|HOUR|MINUTE|SECOND } FROM { datetime_expr|interval_expr } )
 */
static status_t sql_build_func_args_extract(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node,
    sql_text_t *arg_text)
{
    uint32 match_id;
    lex_t *lex = stmt->session->lex;
    expr_tree_t *arg_expr = NULL;
    // datetime unit expr
    OG_RETURN_IFERR(lex_expected_fetch(lex, word));
    // verify word text
    OG_RETURN_IFERR(lex_push(lex, &word->text));
    if (lex_expected_fetch_1ofn(lex, &match_id, 6, "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND") != OG_SUCCESS) {
        lex_pop(lex);
        cm_set_error_loc(word->loc);
        return OG_ERROR;
    }
    lex_pop(lex);
    OG_RETURN_IFERR(sql_create_expr_from_word(stmt, word, &arg_expr));
    OG_RETURN_IFERR(sql_generate_expr(arg_expr));
    func_node->argument = arg_expr;

    // expect FROM
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "FROM"));

    // datetime/interval expr
    OG_RETURN_IFERR(sql_create_expr_until(stmt, &arg_expr, word));
    func_node->argument->next = arg_expr;

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_build_func_arg_first_last_value(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node,
    sql_text_t *arg_text)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t **arg_expr = &func_node->argument;

    func_node->ignore_nulls = OG_FALSE;
    if (lex->curr_text->len == 0) {
        OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "argument expected");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_create_expr_until(stmt, arg_expr, word));
    if (word->id == KEY_WORD_IGNORE) {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "NULLS"));
        func_node->ignore_nulls = OG_TRUE;
    } else if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", T2S(&word->text.value));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

typedef status_t (*arg_build_func_t)(sql_stmt_t *stmt, word_t *word, expr_node_t *func_node, sql_text_t *arg_text);

typedef struct st_arg_build {
    const char *func_name;
    arg_build_func_t invoke;
} arg_build_t;

static arg_build_t g_arg_build_tab[] = {
    { "TRIM", sql_build_func_args_trim },
    { "GROUP_CONCAT", sql_build_func_args_group_concat },
    { "SUBSTR", sql_build_func_args_substr },
    { "SUBSTRING", sql_build_func_args_substr },
    { "EXTRACT", sql_build_func_args_extract },
    { "JSON_ARRAY", sql_build_func_args_json_array },
    { "JSON_OBJECT", sql_build_func_args_json_object },
    { "JSON_QUERY", sql_build_func_args_json_query },
    { "JSON_MERGEPATCH", sql_build_func_args_json_query },
    { "JSON_VALUE", sql_build_func_args_json_retrieve },
    { "JSON_EXISTS", sql_build_func_args_json_retrieve },
    { "JSON_SET", sql_build_func_args_json_set },
    { "JSONB_QUERY", sql_build_func_args_json_query },
    { "JSONB_MERGEPATCH", sql_build_func_args_json_query },
    { "JSONB_VALUE", sql_build_func_args_json_retrieve },
    { "JSONB_EXISTS", sql_build_func_args_json_retrieve },
    { "JSONB_SET", sql_build_func_args_json_set },
    { "FIRST_VALUE", sql_build_func_arg_first_last_value },
    { "LAST_VALUE", sql_build_func_arg_first_last_value },
};

static status_t sql_build_func_args_group(sql_stmt_t *stmt, lex_t *lex, expr_node_t *node)
{
    word_t bracket_word;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "group"));
    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, &bracket_word));
    // lex location (order by a,b,...)
    lex_push(lex, &bracket_word.text);
    galist_t *sort_items = NULL;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "order"));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&sort_items));
    cm_galist_init(sort_items, stmt->context, sql_alloc_mem);
    OG_RETURN_IFERR(sql_parse_order_by_items(stmt, sort_items, &bracket_word));
    if (bracket_word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(&bracket_word));
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);
    node->sort_items = sort_items;
    return OG_SUCCESS;
}

// to support within group(order by a,b,...)
static status_t sql_expected_build_func_args_within_group(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "within"));
    OG_RETURN_IFERR(sql_build_func_args_group(stmt, lex, node));
    return OG_SUCCESS;
}

static status_t sql_try_build_func_args_within_group(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    OG_RETURN_IFERR(lex_try_fetch(lex, "within", &result));

    if (node->word.func.args.value.len > 0) {
        if (result) {
            OG_RETURN_IFERR(sql_build_func_args_group(stmt, lex, node));
        } else {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "%s expected", "within");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t pl_try_find_cast_type(sql_stmt_t *stmt, lex_t *lex, expr_tree_t *arg, word_t *typword, bool32 *found)
{
    plv_decl_t *decl = NULL;
    bool32 is_found = OG_FALSE;
    uint32 save_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    OG_RETURN_IFERR(lex_fetch(lex, typword));
    lex->flags = save_flags;
    *found = OG_FALSE;
    if (stmt->pl_compiler != NULL) {
        pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
        plc_find_decl_ex(compiler, typword, PLV_TYPE, NULL, &decl);
        if (decl == NULL) {
            OG_RETURN_IFERR(plc_try_find_global_type(compiler, typword, &decl, &is_found));
        } else {
            is_found = OG_TRUE;
        }
    } else {
        pl_compiler_t compiler;
        compiler.stmt = stmt;
        OG_RETURN_IFERR(plc_try_find_global_type(&compiler, typword, &decl, &is_found));
    }
    if (is_found) {
        if (decl->typdef.type == PLV_COLLECTION) {
            if (decl->typdef.collection.attr_type != UDT_SCALAR) {
                OG_SRC_THROW_ERROR(lex->loc, ERR_PLSQL_VALUE_ERROR_FMT,
                    "the 2nd-arg's data type in cast func is not supported");
                return OG_ERROR;
            }
            arg->root->datatype = OG_TYPE_COLLECTION;
            arg->root->udt_type = &decl->typdef.collection;
            arg->loc = typword->loc;
            *found = OG_TRUE;
        } else {
            OG_SRC_THROW_ERROR(lex->loc, ERR_FUNC_ARGUMENT_WRONG_TYPE, 2, "udt collection, global or local");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_create_cast_arg2(sql_stmt_t *stmt, lex_t *lex, expr_tree_t **arg2)
{
    expr_tree_t *arg = NULL;
    word_t typword;
    typmode_t *v_type = NULL;

    if (sql_create_expr(stmt, arg2) != OG_SUCCESS) {
        return OG_ERROR;
    }

    arg = *arg2;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    v_type = &arg->root->value.v_type;
    bool32 is_found = OG_FALSE;
    word_t tword;
    LEX_SAVE(lex);
    if (lex_try_fetch_datatype(lex, &tword, &is_found) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (is_found) {
        OG_RETURN_IFERR(sql_parse_datatype_typemode(lex, PM_NORMAL, v_type, &typword, &tword));
        arg->root->value.type = OG_TYPE_TYPMODE;
        arg->root->typmod = *v_type;
        arg->root->type = EXPR_NODE_CONST;
        arg->loc = typword.loc;
        /* if cast to array type, e.g. '{1,2,3}'::int[], expression can NOT be optimized,
        static because we need temporay (rather than persistent) vm_lob pages to save the
        array elements. Once optimized, the vm_lob page will be freed after the first
        execution of statement, and next time we will get an invalid vm page, and this
        must cause an error.
        */
        if (v_type->is_array != OG_TRUE) {
            SQL_SET_OPTMZ_MODE(arg->root, OPTIMIZE_AS_CONST);
        }
    } else {
        LEX_RESTORE(lex);
        OG_RETURN_IFERR(pl_try_find_cast_type(stmt, lex, arg, &typword, &is_found));
    }
    if (!is_found) {
        OG_SRC_THROW_ERROR_EX(typword.loc, ERR_SQL_SYNTAX_ERROR, "datatype expected, but got '%s'", W2S(&typword));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_build_cast_node(sql_stmt_t *stmt, lex_t *lex, word_t *word, expr_node_t *node)
{
    sql_text_t *arg_text = &word->ex_words[0].text;
    bool32 wd_signed = OG_FALSE;

    node->word.func.name = word->text;
    node->type = EXPR_NODE_FUNC;

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, &node->word.func.name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_push(lex, arg_text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_expr_until(stmt, &node->argument, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_AS) {
        lex_pop(lex);
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "key word AS expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (lex_try_fetch(lex, "signed", &wd_signed) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_create_cast_arg2(stmt, lex, &node->argument->next) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (wd_signed && node->argument->next->root->datatype != OG_TYPE_INTEGER) {
        lex_pop(lex);
        OG_SRC_THROW_ERROR(node->argument->next->root->loc, ERR_SQL_SYNTAX_ERROR, "type INTEGER expected");
        return OG_ERROR;
    }

    if (lex_expected_end(lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_build_convert_node(sql_stmt_t *stmt, lex_t *lex, word_t *word, expr_node_t *node)
{
    sql_text_t *arg_text = &word->ex_words[0].text;
    bool32 wd_signed = OG_FALSE;

    node->word.func.name = word->text;
    node->type = EXPR_NODE_FUNC;

    if (sql_copy_object_name_loc(stmt->context, word->type, &word->text, &node->word.func.name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    lex_remove_brackets(arg_text);

    if (lex_push(lex, arg_text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_expr_until(stmt, &node->argument, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (!IS_SPEC_CHAR(word, ',')) {
        lex_pop(lex);
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (lex_try_fetch(lex, "signed", &wd_signed) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_create_cast_arg2(stmt, lex, &node->argument->next) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (wd_signed && node->argument->next->root->datatype != OG_TYPE_INTEGER) {
        lex_pop(lex);
        OG_SRC_THROW_ERROR(node->argument->next->root->loc, ERR_SQL_SYNTAX_ERROR, "type INTEGER expected");
        return OG_ERROR;
    }

    if (lex_expected_end(lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_build_if_node(sql_stmt_t *stmt, lex_t *lex, word_t *word, expr_node_t *node)
{
    sql_text_t *arg_text = &word->ex_words[0].text;

    node->type = EXPR_NODE_FUNC;

    OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, &node->word.func.name));

    OG_RETURN_IFERR(lex_push(lex, arg_text));
    lex->flags |= LEX_IN_FUNCTION;
    if (sql_create_cond_until(stmt, &node->cond_arg, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_create_expr_until(stmt, &node->argument, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (sql_create_expr_until(stmt, &node->argument->next, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (lex_expected_end(lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex->flags &= ~LEX_IN_FUNCTION;
    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_build_case_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    bool32 result = OG_FALSE;
    case_pair_t *pair = NULL;
    case_expr_t *case_expr = NULL;
    sql_text_t *arg_text = &word->ex_words[0].text;

    node->type = EXPR_NODE_CASE;
    if (sql_alloc_mem(stmt->context, sizeof(case_expr_t), (void **)&case_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    cm_galist_init(&case_expr->pairs, (void *)stmt->context, (ga_alloc_func_t)sql_alloc_mem);

    case_expr->is_cond = OG_FALSE;
    OG_RETURN_IFERR(lex_push(stmt->session->lex, arg_text));

    if (sql_create_expr_until(stmt, &case_expr->expr, word) != OG_SUCCESS) {
        lex_pop(stmt->session->lex);
        return OG_ERROR;
    }

    lex_pop(stmt->session->lex);

    OG_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "WHEN", &result));

    if (!result) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN expected but %s found", W2S(word));
        return OG_ERROR;
    }

    for (;;) {
        OG_RETURN_IFERR(cm_galist_new(&case_expr->pairs, sizeof(case_pair_t), (void **)&pair));

        OG_RETURN_IFERR(sql_create_expr_until(stmt, &pair->when_expr, word));

        if (word->id != KEY_WORD_THEN) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_create_expr_until(stmt, &pair->value, word));

        if (!(word->id == KEY_WORD_WHEN || word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END)) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN/ELSE/END expected but %s found",
                W2S(word));
            return OG_ERROR;
        }

        if (word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END) {
            break;
        }
    }

    if (word->id == KEY_WORD_ELSE) {
        OG_RETURN_IFERR(sql_create_expr_until(stmt, &case_expr->default_expr, word));

        if (word->id != KEY_WORD_END) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    VALUE(pointer_t, &node->value) = case_expr;

    return OG_SUCCESS;
}

static status_t sql_build_lnnvl_node(sql_stmt_t *stmt, lex_t *lex, word_t *word, expr_node_t *node)
{
    sql_text_t *arg_text = &word->ex_words[0].text;

    node->type = EXPR_NODE_FUNC;

    OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, &node->word.func.name));

    OG_RETURN_IFERR(lex_push(lex, arg_text));
    lex->flags |= LEX_IN_FUNCTION;
    if (sql_create_cond_until(stmt, &node->cond_arg, word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (lex_expected_end(lex) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex->flags &= ~LEX_IN_FUNCTION;
    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_build_func_node_unconfiged(sql_stmt_t *stmt, word_t *word, expr_node_t *node, bool32 *matched)
{
    lex_t *lex = stmt->session->lex;
    switch (word->id) {
        case KEY_WORD_CAST:
            return sql_build_cast_node(stmt, lex, word, node);
        case KEY_WORD_CONVERT:
            return sql_build_convert_node(stmt, lex, word, node);
        case KEY_WORD_IF:
            return sql_build_if_node(stmt, lex, word, node);
        case KEY_WORD_CASE:
            return sql_build_case_node(stmt, word, node);
        case KEY_WORD_LNNVL:
            return sql_build_lnnvl_node(stmt, lex, word, node);
        default:
            break;
    }
    *matched = OG_FALSE;
    return OG_SUCCESS;
}

static status_t sql_build_func_node_arg(sql_stmt_t *stmt, word_t *word, expr_node_t *node, sql_text_t *arg_text)
{
    lex_t *lex = stmt->session->lex;
    OG_RETURN_IFERR(lex_try_fetch(lex, "DISTINCT", &node->dis_info.need_distinct));
    if (node->dis_info.need_distinct && ((cm_compare_text_str_ins(&word->text.value, "DENSE_RANK") == 0) ||
        (cm_compare_text_str_ins(&word->text.value, "RANK") == 0))) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "DISTINCT option not allowed for this function");
        return OG_ERROR;
    }

    if (!node->dis_info.need_distinct && (cm_compare_text_str_ins((text_t *)&node->word.func.name, "COUNT") ||
        cm_compare_text_str_ins((text_t *)&node->word.func.name, "SUM"))) {
        bool32 has_all;
        OG_RETURN_IFERR(lex_try_fetch(lex, "ALL", &has_all));
    }
    if (node->word.func.user_func_first) {
        /* the function is defined in udf.ini,build as user function */
        return sql_build_func_args(stmt, word, node, arg_text);
    }
    /*
     * for more special functions, the parse logic of the argument expression
     * can be called respectively. SUCH AS TRIM expression, SUBSTRING expression, etc.
     */
    uint32 len = sizeof(g_arg_build_tab) / sizeof(arg_build_t);

    for (uint32 i = 0; i < len; i++) {
        if (cm_compare_text_str_ins(&node->word.func.name.value, g_arg_build_tab[i].func_name) == 0) {
            return g_arg_build_tab[i].invoke(stmt, word, node, arg_text);
        }
    }
    /*
     * execute the generic parse logic by default,
     * for the generic argument expression, like func(arg1, arg2, ...)
     */
    return sql_build_func_args(stmt, word, node, arg_text);
}

/*
 * in SQL standard, the argument expression in some function is not always like "func(arg1, arg2, ...)"
 * so it is necessary to implement some special expression rules for the special functions, such as
 * - TRIM(arg2 FROM arg1)
 * - SUBSTRING(arg1 FROM arg2 FOR arg3)
 * - etc.
 *
 * in the future, we can use a function point(status_t *fn_ptr(sql_stmt_t * stmt, word_t * word, expr_node_t * node)) to
 * handle the special argument expression respectively
 */
status_t sql_build_func_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    sql_text_t *arg_text = NULL;
    lex_t *lex = stmt->session->lex;
    status_t status;
    text_t user;

    user.str = stmt->session->db_user;
    user.len = (uint32)strlen(stmt->session->db_user);
    node->word.func.user_func_first = OG_FALSE;
    if (word->ex_count == 1) {
        if (sql_self_func_configed(&user, &word->text.value)) {
            /* the function(CAST,CONVERT,IF...) is defined in udf.ini, build as user function */
            node->word.func.user_func_first = OG_TRUE;
        } else {
            bool32 built = OG_TRUE;
            OG_RETURN_IFERR(sql_build_func_node_unconfiged(stmt, word, node, &built));
            OG_RETSUC_IFTRUE(built);
        }
    }

    OG_RETURN_IFERR(plc_try_obj_access_node(stmt, word, node));
    OG_RETSUC_IFTRUE(IS_UDT_EXPR(node->type));

    if (word->type != WORD_TYPE_FUNCTION && plc_prepare_noarg_call(word) != OG_SUCCESS) {
        // dedicate no_args UDF/PROC call, eg.begin f1; p1; end;
        OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "too complex function to call");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_word_as_func(stmt, word, &node->word));

    /*
    1. if call by user.func, build as user func.
    2. function is in udf.ini, build as user func first, such as SLEEP, "sleep", so compare case sensitive.
    */
    if (node->word.func.user.len > 0 || sql_self_func_configed_direct(&user, &node->word.func.name.value)) {
        node->word.func.user_func_first = OG_TRUE;
    }

    if (cm_compare_text_str_ins(&word->text.value, "LISTAGG") == 0) {
        OG_RETURN_IFERR(sql_expected_build_func_args_within_group(stmt, word, node));
    }

    if (cm_compare_text_str_ins(&word->text.value, "CUME_DIST") == 0 ||
        cm_compare_text_str_ins(&word->text.value, "DENSE_RANK") == 0 ||
        cm_compare_text_str_ins(&word->text.value, "RANK") == 0) {
        OG_RETURN_IFERR(sql_try_build_func_args_within_group(stmt, word, node));
    }

    arg_text = &node->word.func.args;

    if (arg_text->len == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_push(lex, arg_text));

    status = sql_build_func_node_arg(stmt, word, node, arg_text);
    lex_pop(lex);
    return status;
}

static status_t sql_create_winsort_partlist(sql_stmt_t *stmt, word_t *word, winsort_args_t *winsort_args)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *expr = NULL;

    if (lex_expected_fetch_word(lex, "by") != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_create_list(stmt, &winsort_args->group_exprs) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (;;) {
        if (sql_create_expr_until(stmt, &expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (cm_galist_insert(winsort_args->group_exprs, expr) != OG_SUCCESS) {
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(!IS_SPEC_CHAR(word, ','));
    }

    return OG_SUCCESS;
}

static status_t sql_create_winsort_sortlist(sql_stmt_t *stmt, word_t *word, winsort_args_t *winsort_args)
{
    lex_t *lex = stmt->session->lex;
    uint32 matched = OG_INVALID_ID32;
    uint32 tmp_flags;

    if (lex_expected_fetch_word(lex, "by") != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_create_list(stmt, &winsort_args->sort_items) != OG_SUCCESS) {
        return OG_ERROR;
    }

    for (;;) {
        sort_item_t *item = NULL;
        if (cm_galist_new(winsort_args->sort_items, sizeof(sort_item_t), (void **)&item) != OG_SUCCESS) {
            return OG_ERROR;
        }
        item->direction = SORT_MODE_ASC;
        item->nulls_pos = SORT_NULLS_DEFAULT;

        if (sql_create_expr_until(stmt, &item->expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        tmp_flags = lex->flags;
        CM_CLEAN_FLAG(lex->flags, LEX_WITH_ARG);
        if (word->id == KEY_WORD_DESC || word->id == KEY_WORD_ASC) {
            item->direction = (word->id == KEY_WORD_DESC) ? SORT_MODE_DESC : SORT_MODE_ASC;
            if (lex_fetch(lex, word) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }

        if (word->id == KEY_WORD_NULLS) { // NULLS FIRST | LAST
            if (lex_expected_fetch_1of2(lex, "FIRST", "LAST", &matched) != OG_SUCCESS) {
                return OG_ERROR;
            }
            item->nulls_pos = (matched == 0) ? SORT_NULLS_FIRST : SORT_NULLS_LAST;
            if (lex_fetch(lex, word) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }

        if (item->nulls_pos == SORT_NULLS_DEFAULT) {
            item->nulls_pos = DEFAULT_NULLS_SORTING_POSITION(item->direction);
        }
        lex->flags = tmp_flags;
        OG_BREAK_IF_TRUE(!IS_SPEC_CHAR(word, ','));
    }

    return OG_SUCCESS;
}

static status_t sql_create_windowing_border(sql_stmt_t *stmt, word_t *word, uint32 *border_type, expr_tree_t **expr)
{
    lex_t *lex = stmt->session->lex;
    bool32 result;
    uint32 is_following;

    if (lex_try_fetch(lex, "unbounded", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (result) {
        if (lex_expected_fetch_1of2(lex, "preceding", "following", &is_following) != OG_SUCCESS) {
            return OG_ERROR;
        }
        *border_type = is_following ? WB_TYPE_UNBOUNDED_FOLLOW : WB_TYPE_UNBOUNDED_PRECED;
        return OG_SUCCESS;
    }

    if (lex_try_fetch(lex, "current", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (result) {
        if (lex_expected_fetch_word(lex, "row") != OG_SUCCESS) {
            return OG_ERROR;
        }
        *border_type = WB_TYPE_CURRENT_ROW;
        return OG_SUCCESS;
    }

    if (sql_create_expr_until(stmt, expr, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (word->id == KEY_WORD_PRECEDING) {
        *border_type = WB_TYPE_VALUE_PRECED;
    } else if (word->id == KEY_WORD_FOLLOWING) {
        *border_type = WB_TYPE_VALUE_FOLLOW;
    } else {
        OG_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "preceding or following expected");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_create_windowing_clause(sql_stmt_t *stmt, word_t *word, winsort_args_t *winsort_args)
{
    windowing_args_t *windowing = NULL;
    lex_t *lex = stmt->session->lex;
    bool32 result;

    if (word->id != KEY_WORD_RANGE && word->id != KEY_WORD_ROWS) {
        return OG_SUCCESS;
    }

    if (sql_alloc_mem(stmt->context, sizeof(windowing_args_t), (void **)&windowing) != OG_SUCCESS) {
        return OG_ERROR;
    }

    windowing->is_range = (word->id == KEY_WORD_RANGE);
    if (lex_try_fetch(lex, "between", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_windowing_border(stmt, word, &windowing->l_type, &windowing->l_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        if (lex_expected_fetch_word(lex, "and") != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (sql_create_windowing_border(stmt, word, &windowing->r_type, &windowing->r_expr) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        windowing->r_type = WB_TYPE_CURRENT_ROW;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    winsort_args->windowing = windowing;
    return OG_SUCCESS;
}

static status_t sql_create_winsort_args(sql_stmt_t *stmt, word_t *word, winsort_args_t *winsort_args)
{
    lex_t *lex = stmt->session->lex;
    bool32 is_order = OG_FALSE;
    uint32 matched;

    if (lex_expected_fetch_1of2(lex, "partition", "order", &matched) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (matched == 0) {
        if (sql_create_winsort_partlist(stmt, word, winsort_args) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (word->id == KEY_WORD_ORDER) {
            is_order = OG_TRUE;
        }
    }

    if (matched == 1 || is_order) {
        if (sql_create_winsort_sortlist(stmt, word, winsort_args) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (sql_create_windowing_clause(stmt, word, winsort_args) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_build_winsort_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    winsort_args_t *winsort_args = NULL;
    sql_text_t *arg_text = NULL;
    lex_t *lex = stmt->session->lex;
    expr_tree_t *expr = NULL;

    var_word_t *var_word = &node->word;

    OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, word->type, &word->text, &var_word->func.name));
    var_word->func.args = word->ex_words[0].text;
    var_word->func.pack.value = CM_NULL_TEXT;
    var_word->func.pack.loc = word->text.loc;
    var_word->func.user.value = CM_NULL_TEXT;
    var_word->func.user.loc = word->text.loc;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(winsort_args_t), (void **)&winsort_args));

    arg_text = &var_word->func.args;
    if (arg_text->len == 0) {
        OG_RETURN_IFERR(sql_create_list(stmt, &winsort_args->group_exprs));
        OG_RETURN_IFERR(sql_create_const_expr_false(stmt, &expr, word, 1));
        OG_RETURN_IFERR(cm_galist_insert(winsort_args->group_exprs, expr));
        node->win_args = winsort_args;
        return OG_SUCCESS;
    }

    // PUSH [1] PARTITION BY   expr_node   ORDER BY   expr_node
    // PUSH [2] PARTITION BY ( expr_list ) ORDER BY ( expr_list )
    OG_RETURN_IFERR(lex_push(lex, arg_text));
    if (sql_create_winsort_args(stmt, word, winsort_args) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    node->win_args = winsort_args;
    return OG_SUCCESS;
}

static status_t sql_create_winsort_node(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t **node)
{
    expr_node_t *func_node = *node;
    expr_tree_t *n_expr = NULL;
    OG_RETURN_IFERR(sql_create_expr(stmt, &n_expr));
    APPEND_CHAIN(&n_expr->chain, func_node);
    n_expr->root = func_node;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*node)->owner = expr;
    (*node)->type = EXPR_NODE_OVER;
    (*node)->unary = expr->unary;
    (*node)->loc = word->text.loc;
    (*node)->argument = n_expr;
    return sql_build_winsort_node(stmt, word, *node);
}

static status_t sql_valid_winsort_node_sp(expr_node_t *node, word_t *word)
{
    if (cm_compare_text_str_ins(&node->argument->root->word.func.name.value, "LEAD") == 0) {
        if (node->win_args->sort_items == NULL || node->win_args->sort_items->count == 0) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "missing ORDER BY expression in the window specification");
            return OG_ERROR;
        }

        // lead ... order by a asc b desc  == lag ... order by a desc b asc
        for (uint32 i = 0; i < node->win_args->sort_items->count; i++) {
            sort_item_t *item = (sort_item_t *)cm_galist_get(node->win_args->sort_items, i);
            item->direction = (item->direction == SORT_MODE_DESC) ? SORT_MODE_ASC : SORT_MODE_DESC;
            item->nulls_pos = (item->nulls_pos == SORT_NULLS_FIRST) ? SORT_NULLS_LAST : SORT_NULLS_FIRST;
        }
    } else if (cm_compare_text_str_ins(&node->argument->root->word.func.name.value, "LAG") == 0) {
        if (node->win_args->sort_items == NULL || node->win_args->sort_items->count == 0) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "missing ORDER BY expression in the window specification");
            return OG_ERROR;
        }
    } else if (cm_compare_text_str_ins(&node->argument->root->word.func.name.value, "CUME_DIST") == 0) {
        if (node->win_args->sort_items == NULL || node->win_args->sort_items->count == 0) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "missing ORDER BY expression in the window specification");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static inline bool32 sql_check_must_has_over_word(word_t *word)
{
    if (cm_compare_text_str_ins(&word->text.value, "CUME_DIST") == 0) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

status_t sql_build_func_over(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t **node)
{
    lex_t *lex = stmt->session->lex;
    word_t word_ahead;
    bool32 must_has_over = sql_check_must_has_over_word(word);

    LEX_SAVE(lex);
    OG_RETURN_IFERR(lex_fetch(lex, &word_ahead));
    if (cm_text_str_equal_ins((text_t *)&word_ahead.text, "over") && (word_ahead.ex_count != 0)) {
        OG_RETURN_IFERR(sql_create_winsort_node(stmt, expr, &word_ahead, node));

        // for special check,
        OG_RETURN_IFERR(sql_valid_winsort_node_sp(*node, word));
    } else {
        LEX_RESTORE(lex);
        if (must_has_over) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing window specification for this function");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_build_cast_expr(sql_stmt_t *stmt, source_location_t loc, expr_tree_t *expr, typmode_t *type,
    expr_tree_t **res)
{
    sql_text_t cast_name;
    expr_node_t *cast_node = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *cast_expr = NULL;

    if (sql_create_expr(stmt, &cast_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cast_expr->expecting = EXPR_EXPECT_OPER;

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&cast_node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    cast_node->owner = cast_expr;
    cast_node->type = EXPR_NODE_FUNC;
    cast_node->loc = loc;
    cm_str2text(CAST_FUNCTION_NAME, &cast_name.value);
    cast_name.str = CAST_FUNCTION_NAME;
    cast_name.len = (uint32)strlen(CAST_FUNCTION_NAME);
    cast_name.loc = loc;
    cast_node->word.func.name = cast_name;
    cast_node->argument = expr;
    if (sql_create_expr(stmt, &expr->next) != OG_SUCCESS) {
        return OG_ERROR;
    }

    arg2 = expr->next;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&arg2->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    arg2->root->value.v_type = *type;
    arg2->root->value.type = (int16)OG_TYPE_TYPMODE;
    arg2->root->datatype = type->datatype;
    arg2->root->type = EXPR_NODE_CONST;
    arg2->root->exec_default = OG_TRUE;

    APPEND_CHAIN(&(cast_expr->chain), cast_node);

    *res = cast_expr;
    return sql_generate_expr(*res);
}

status_t sql_convert_to_cast(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    expr_tree_t *arg2 = NULL;
    expr_node_t *node = NULL;
    expr_node_t *last = NULL;
    lex_t *lex = stmt->session->lex;
    if (expr->chain.count == 0) {
        // error
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the word \"%s\" is not correct", W2S(word));
        return OG_ERROR;
    }
    if (expr->chain.last->type < EXPR_NODE_OPCEIL && expr->chain.last->left == NULL) {
        /*     +  -> :: datatype
        / \
        a   b
        error */
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the word \"%s\" is not correct", W2S(word));
        return OG_ERROR;
    }
    if (sql_create_cast_arg2(stmt, lex, &arg2) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // GENERATE A CAST NODE
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    node->owner = expr;
    node->type = EXPR_NODE_FUNC;
    node->unary = expr->unary;
    node->loc = word->text.loc;
    node->word.func.name.str = "CAST";
    node->word.func.name.len = sizeof("CAST") - 1;

    if (sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)&node->argument) != OG_SUCCESS) {
        return OG_ERROR;
    }
    node->argument->next = arg2;
    node->datatype = arg2->root->value.v_type.datatype;
    node->typmod = arg2->root->value.v_type;

    last = expr->chain.last;

    node->argument->root = last;
    node->prev = last->prev;
    if (last->prev != NULL) {
        last->prev->next = node;
    }

    if (expr->chain.count == 1) {
        expr->chain.first = node;
    }
    expr->chain.last = node;

    return OG_SUCCESS;
}

status_t sql_create_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, galist_t *func_name,
    expr_tree_t *arg_list, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_FUNC, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    text_t user;
    expr_tree_t *list_expr;
    user.str = stmt->session->db_user;
    user.len = (uint32)strlen(stmt->session->db_user);
    node->word.func.user_func_first = OG_FALSE;

    for (int i = 0; i < func_name->count; i++) {
        list_expr = cm_galist_get(func_name, i);
        if (list_expr->root->type != EXPR_NODE_CONST || list_expr->root->value.type != OG_TYPE_CHAR) {
            OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "Invalid funcname expr");
            return OG_ERROR;
        }
    }

    if (func_name->count == 1) {
        list_expr = cm_galist_get(func_name, 0);
        text_t text_word = list_expr->root->value.v_text;
        if (sql_self_func_configed(&user, &text_word)) {
            /* the function(CAST,CONVERT,IF...) is defined in udf.ini, build as user function */
            node->word.func.user_func_first = OG_TRUE;
        }
    }

    sql_expr_list_as_func(stmt, func_name, &node->word);

    /*
     * 1. if call by user.func, build as user func.
     * 2. function is in udf.ini, build as user func first, such as SLEEP, "sleep", so compare case sensitive.
    */
    if (node->word.func.user.len > 0 || sql_self_func_configed_direct(&user, &node->word.func.name.value)) {
        node->word.func.user_func_first = OG_TRUE;
    }

    node->argument = arg_list;
    (*expr)->root = node;
    return OG_SUCCESS;
}

status_t sql_build_winsort_node_bison(sql_stmt_t *stmt, winsort_args_t **winsort_args, galist_t* group_exprs,
    galist_t *sort_items, windowing_args_t *windowing, source_location_t loc)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(winsort_args_t), (void **)winsort_args));
    (*winsort_args)->group_exprs = group_exprs;
    (*winsort_args)->sort_items = sort_items;
    (*winsort_args)->windowing = windowing;
    return OG_SUCCESS;
}

status_t sql_create_winsort_node_bison(sql_stmt_t *stmt, expr_tree_t *func_expr, expr_node_t *func_node,
    winsort_args_t *winsort_args, source_location_t loc)
{
    expr_tree_t *n_expr = NULL;
    expr_node_t *over_node = NULL;
    sql_text_t over_test;

    if (winsort_args != NULL) {
        OG_RETURN_IFERR(sql_create_expr(stmt, &n_expr));
        APPEND_CHAIN(&n_expr->chain, func_node);
        n_expr->root = func_node;
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&over_node));
        over_node->owner = func_expr;
        over_node->type = EXPR_NODE_OVER;
        over_node->unary = func_expr->unary;
        over_node->loc = loc;
        over_node->argument = n_expr;
        over_test.str = "over";
        over_test.len = strlen("over");
        over_test.loc = loc;

        OG_RETURN_IFERR(sql_copy_object_name_loc(stmt->context, WORD_TYPE_UNKNOWN, &over_test,
            &over_node->word.func.name));
        over_node->word.func.args.value = CM_NULL_TEXT;
        over_node->word.func.args.loc = loc;
        over_node->word.func.pack.value = CM_NULL_TEXT;
        over_node->word.func.pack.loc = loc;
        over_node->word.func.user.value = CM_NULL_TEXT;
        over_node->word.func.user.loc = loc;

        if (winsort_args->sort_items == NULL && winsort_args->group_exprs == NULL && winsort_args->windowing == NULL) {
            expr_tree_t *expr = NULL;
            OG_RETURN_IFERR(sql_create_list(stmt, &winsort_args->group_exprs));
            OG_RETURN_IFERR(sql_create_const_expr_false(stmt, &expr, NULL, 0));
            OG_RETURN_IFERR(cm_galist_insert(winsort_args->group_exprs, expr));
        }

        over_node->win_args = winsort_args;
        APPEND_CHAIN(&func_expr->chain, over_node);
    } else {
        APPEND_CHAIN(&func_expr->chain, func_node);
    }

    sql_generate_expr(func_expr);
    return OG_SUCCESS;
}

status_t sql_create_windowing_arg(sql_stmt_t *stmt, windowing_args_t **windowing_args,
    windowing_border_t *l_border, windowing_border_t *r_border)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(windowing_args_t), (void **)windowing_args) != OG_SUCCESS);
    (*windowing_args)->l_expr = l_border->expr;
    (*windowing_args)->l_type = l_border->border_type;
    if (r_border != NULL) {
        (*windowing_args)->r_expr = r_border->expr;
        (*windowing_args)->r_type = r_border->border_type;
    } else {
        (*windowing_args)->r_type = WB_TYPE_CURRENT_ROW;
    }
    return OG_SUCCESS;
}

static status_t sql_create_special_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t **node,
    char *func_name, source_location_t loc)
{
    if (sql_init_expr_node(stmt, expr, node, OG_TYPE_INTEGER, EXPR_NODE_FUNC, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*node)->word.func.user_func_first = OG_FALSE;
    sql_text_t text;
    text.str = func_name;
    text.len = strlen(func_name);
    text.loc = loc;
    if (sql_copy_object_name_loc(stmt->context, WORD_TYPE_UNKNOWN, &text, &(*node)->word.func.name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_create_cast_convert_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *arg, type_word_t *type,
    char *func_name, source_location_t loc)
{
    expr_tree_t *type_expr = NULL;
    expr_node_t *node = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, func_name, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->argument = arg;

    if (sql_create_expr(stmt, &type_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&type_expr->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_build_type_expr(stmt, type, type_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->argument->next = type_expr;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_if_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, cond_tree_t *cond_tree,
    expr_tree_t *first_arg, expr_tree_t *second_arg, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, "if", loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->cond_arg = cond_tree;
    node->argument = first_arg;
    node->argument->next = second_arg;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_lnnvl_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, cond_tree_t *cond_tree,
    source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, "lnnvl", loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->cond_arg = cond_tree;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_trim_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, trim_list_t *trim,
    func_trim_type_t trim_type, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, "trim", loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->ext_args = trim_type;
    if (trim->reverse) {
        node->argument = trim->second_expr;
        node->argument->next = trim->first_expr;
    } else {
        node->argument = trim->first_expr;
        node->argument->next = trim->second_expr;
    }
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_groupconcat_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *expr_list,
    galist_t *sort_list, char *separator, source_location_t loc)
{
    expr_node_t *node = NULL;
    expr_tree_t *arg_sep = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, "group_concat", loc) != OG_SUCCESS) {
        return OG_ERROR;
    }
    bool32 has_separator = separator != NULL;
    node->sort_items = sort_list;

    OG_RETURN_IFERR(sql_create_const_string_expr(stmt, &arg_sep, has_separator ? separator : ","));
    arg_sep->next = expr_list;
    node->argument = arg_sep;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_substr_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *arg_list,
    char *func_name, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, func_name, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->argument = arg_list;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_extract_funccall_expr(sql_stmt_t *stmt, expr_tree_t **expr, extract_list_t *extract_list,
    source_location_t loc)
{
    expr_node_t *node = NULL;
    expr_tree_t *arg_expr = NULL;
    if (sql_create_special_funccall_expr(stmt, expr, &node, "extract", loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_create_columnref_expr(stmt, &arg_expr, extract_list->extract_type, NULL, loc));
    node->argument = arg_expr;
    node->argument->next = extract_list->arg;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
