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
 * dml_cl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/dml_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml_cl.h"
#include "dml.h"
#include "base_compiler.h"
#include "ast_cl.h"
#include "srv_instance.h"
#include "pl_compiler.h"
#include "dml_parser.h"
#include "func_parser.h"
#include "trigger_decl_cl.h"
#include "decl_cl.h"
#include "pl_udt.h"
#include "ogsql_parser.h"
#include "ogsql_dependency.h"
#include "param_decl_cl.h"
#include "ogsql_package.h"
#include "lines_cl.h"
#include "ogsql_privilege.h"

static status_t plc_compile_select_into(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    OG_RETURN_IFERR(plc_compile_select(compiler, sql, word, OG_TRUE));
    if (word->type != WORD_TYPE_PL_TERM) {
        pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * If the input word is head with hint, then add hint info to sql.
 */
static status_t plc_compile_hint(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    if (lex_try_fetch_hint_comment(lex, word, &result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (result) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "/*+"));
        cm_concat_text(sql, compiler->convert_buf_size, &word->text.value);
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "*/ "));
    }

    return OG_SUCCESS;
}

static status_t plc_compile_dml_org(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 is_skip_bracket)
{
    source_location_t loc;
    lex_t *lex = compiler->stmt->session->lex;
    OG_RETURN_IFERR(plc_stack_safe(compiler));
    lex->flags = LEX_WITH_OWNER;
    while (OG_TRUE) {
        loc = word->text.loc;
        OG_RETURN_IFERR(lex_fetch(lex, word));
        if (loc.line != 0 && loc.line != word->text.loc.line) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "\n"));
        }

        switch (word->type) {
            case WORD_TYPE_EOF:
            case WORD_TYPE_PL_TERM:
                return OG_SUCCESS;

            case WORD_TYPE_BRACKET:
                if (!is_skip_bracket) {
                    return OG_SUCCESS;
                }
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
                PLC_SAVE_KW_HOOK(compiler);
                compiler->keyword_hook = plc_dmlhook_none;
                OG_RETURN_IFERR(lex_push(lex, &word->text));
                if (plc_compile_dml_org(compiler, sql, word, is_skip_bracket) != OG_SUCCESS) {
                    lex_pop(lex);
                    return OG_ERROR;
                }
                lex_pop(lex);
                PLC_RESTORE_KW_HOOK(compiler);
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
                break;

            case WORD_TYPE_KEYWORD:
                if (compiler->keyword_hook(word) == OG_TRUE) {
                    return OG_SUCCESS;
                }
                /* fall-through */
            default:
                plc_concat_word(sql, compiler->convert_buf_size, word);
                break;
        }
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));
    }
}

static inline status_t plc_try_compile_select_dml(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 result)
{
    if (!result) {
        OG_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, OG_TRUE));
    } else {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));
        OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    }
    return OG_SUCCESS;
}

static status_t plc_compile_returning(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
    // syntax: insert/delete/update return|returning f1, f2 into var1, var2
    if (word->id == KEY_WORD_RETURN || word->id == KEY_WORD_RETURNING) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "returning "));

        compiler->keyword_hook = plc_dmlhook_return_into;
        OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, 0, NULL));

        if (word->id != KEY_WORD_INTO && word->id != KEY_WORD_BULK) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "returning clause",
                "missing INTO or BULK keyword");
            return OG_ERROR;
        }
#ifdef Z_SHARDING
        if (IS_COORDINATOR && word->id == KEY_WORD_BULK) {
            OG_SRC_THROW_ERROR(word->loc, ERR_CAPABILITY_NOT_SUPPORT, "'bulk collect' on coordinator is");
            return OG_ERROR;
        }
#endif
    }

    // deal with into variable-list
    if (word->id == KEY_WORD_INTO) {
        OG_RETURN_IFERR(plc_compile_into_clause(compiler, &line->into, word));
    } else {
        OG_RETURN_IFERR(plc_compile_bulk_into_clause(compiler, &line->into, word));
    }

    return OG_SUCCESS;
}

static status_t plc_compile_insert_head(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 result = OG_FALSE;

    compiler->keyword_hook = plc_dmlhook_insert_head;
    OG_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, OG_FALSE));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "insert values or select clause", "EOF or ';'");
        return OG_ERROR;
    }
    if (word->type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        if (lex_try_fetch(lex, "SELECT", &result) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        PLC_SAVE_KW_HOOK(compiler);
        compiler->keyword_hook = plc_dmlhook_none;
        if (plc_try_compile_select_dml(compiler, sql, word, result) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
        PLC_RESTORE_KW_HOOK(compiler);
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ") "));
    } else {
        if (word->id == KEY_WORD_VALUES) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "values "));
        }
        if (word->id == KEY_WORD_SELECT) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));
        }
    }

    return OG_SUCCESS;
}

static status_t plc_compile_insert_all(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "all "));

    while (OG_TRUE) {
        OG_RETURN_IFERR(plc_compile_insert_head(compiler, sql, word));
        compiler->keyword_hook = plc_dmlhook_all_into;
        OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

        if (PLC_IS_ALL_INTO_WORD(word)) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "into "));
            continue;
        }

        if (word->type != WORD_TYPE_PL_TERM) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
            return OG_ERROR;
        }

        break;
    }

    return OG_SUCCESS;
}

static status_t plc_compile_insert(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
    lex_t *lex = compiler->stmt->session->lex;
    bool32 isall;

    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "insert "));
    OG_RETURN_IFERR(plc_compile_hint(compiler, sql, word));

    if (lex_try_fetch(lex, "ALL", &isall) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (isall) {
        return plc_compile_insert_all(compiler, sql, word);
    }

    OG_RETURN_IFERR(plc_compile_insert_head(compiler, sql, word));
    compiler->keyword_hook = plc_dmlhook_return_returning;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

    if (PLC_IS_RETURNING_WORD(word)) {
        OG_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_currowid_variant(void *anchor)
{
    plv_decl_t *decl = NULL;
    char name_buf[OG_MAX_NAME_LEN];
    text_t name = {
        .str = NULL,
        .len = 0
    };

    variant_complier_t *def = (variant_complier_t *)anchor;
    pl_compiler_t *compiler = def->compiler;
    text_t *sql_text = def->sql;
    word_t *word = def->word;
    galist_t *input = compiler->current_input;

    if (word->type == WORD_TYPE_PL_NEW_COL || word->type == WORD_TYPE_PL_OLD_COL) {
        return plc_compile_trigger_variant(compiler, sql_text, word);
    }

    OG_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_CUR, NULL, &decl);
    if (decl == NULL) {
        plc_concat_word(sql_text, compiler->convert_buf_size, word);
        return OG_SUCCESS;
    }
    // here only allow cursor-variant, so it must be a single vid
    OG_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, input, decl, UDT_STACK_ADDR));
    decl->vid.is_rowid = OG_TRUE;

    OG_RETURN_IFERR(plc_make_input_name(input, name_buf, OG_MAX_NAME_LEN, &name));
    cm_concat_text(sql_text, compiler->convert_buf_size, &name);
    return OG_SUCCESS;
}

static status_t pl_compile_current_of(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 is_of = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

#ifdef Z_SHARDING
    if (IS_COORDINATOR && IS_APP_CONN(compiler->stmt->session)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "CURRENT OF is not supported at CN.");
        return OG_ERROR;
    }
#endif

    OG_RETURN_IFERR(lex_try_fetch(lex, "OF", &is_of));
    if (is_of) {
        OG_RETURN_IFERR(lex_fetch(lex, word));

        if (IS_VARIANT(word) && word->ex_count <= 1) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " rowid = "));
            variant_complier_t def;
            def.compiler = compiler;
            def.sql = sql;
            def.word = word;
            def.types = PLV_CUR;
            def.usrdef = NULL;
            OG_RETURN_IFERR(plc_compile_currowid_variant(&def));
        } else {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "'current of' should follow a update cursor.");
            return OG_ERROR;
        }
    } else {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " CURRENT "));
    }
    return OG_SUCCESS;
}

static status_t plc_compile_update(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;

    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "update "));
    OG_RETURN_IFERR(plc_compile_hint(compiler, sql, word));

    compiler->keyword_hook = plc_dmlhook_update_head;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "update set clause", "EOF or ';'");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "set "));

    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        plc_concat_word(sql, compiler->convert_buf_size, word);
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    } else {
        OG_RETURN_IFERR(lex_fetch(lex, word));
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }

    compiler->keyword_hook = plc_dmlhook_current;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    if (word->type == WORD_TYPE_PL_TERM) {
        return OG_SUCCESS;
    }

    // translate current of cursor into rowid = rowid_variant
    if (word->id == KEY_WORD_CURRENT) {
        OG_RETURN_IFERR(pl_compile_current_of(compiler, sql, word));
        if (word->type == WORD_TYPE_PL_TERM) {
            return OG_SUCCESS;
        }

        compiler->keyword_hook = plc_dmlhook_return_returning;
        OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
        if (PLC_IS_RETURNING_WORD(word)) {
            OG_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
        }
    } else if (PLC_IS_RETURNING_WORD(word)) {
        OG_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_delete(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = NULL;

    line = (pl_line_sql_t *)compiler->last_line;
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "delete "));
    OG_RETURN_IFERR(plc_compile_hint(compiler, sql, word));

    compiler->keyword_hook = plc_dmlhook_current;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    if (word->type == WORD_TYPE_PL_TERM) {
        return OG_SUCCESS;
    }

    if (word->id == KEY_WORD_CURRENT) {
        OG_RETURN_IFERR(pl_compile_current_of(compiler, sql, word));
        if (word->type == WORD_TYPE_PL_TERM) {
            return OG_SUCCESS;
        }

        compiler->keyword_hook = plc_dmlhook_return_returning;
        OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
        if (PLC_IS_RETURNING_WORD(word)) {
            OG_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
        }
    } else if (PLC_IS_RETURNING_WORD(word)) {
        OG_RETURN_IFERR(plc_compile_returning(compiler, sql, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_set_clause(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    while (OG_TRUE) {
        // column
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, word));
        plc_concat_word(sql, compiler->convert_buf_size, word);
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));

        lex->flags = LEX_SINGLE_WORD;
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "= "));

        OG_RETURN_IFERR(lex_try_fetch(lex, "case", &result));
        if (result) {
            OG_RETURN_IFERR(lex_expected_fetch_word(lex, "when"));
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "case when "));
            compiler->keyword_hook = plc_dmlhook_end;
            OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "end", "EOF or ';'");
                return OG_ERROR;
            }
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "end "));
            lex->flags = LEX_SINGLE_WORD;
            OG_RETURN_IFERR(lex_fetch(lex, word));
        } else {
            lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
            compiler->keyword_hook = plc_dmlhook_spec_char;
            OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
        }

        if (IS_SPEC_CHAR(word, ',')) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ", "));
            continue;
        }
        break;
    }

    return OG_SUCCESS;
}

static status_t plc_compile_merge(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    pl_line_sql_t *line = NULL;
    bool32 result = OG_FALSE;
    bool32 loop_flag;
    lex_t *lex = compiler->stmt->session->lex;

    line = (pl_line_sql_t *)compiler->last_line;
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "merge "));

    if (plc_compile_hint(compiler, sql, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    compiler->keyword_hook = plc_dmlhook_merge_head;
    OG_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, OG_TRUE));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "merge using clause", "EOF or ';'");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "using "));

    compiler->keyword_hook = plc_dmlhook_merge_when;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "when "));

    do {
        loop_flag = OG_FALSE;
        OG_RETURN_IFERR(lex_try_fetch(lex, "not", &result));
        if (result) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "not "));
            compiler->keyword_hook = plc_dmlhook_merge_insert;
            OG_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, OG_TRUE));
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "insert values clause", "EOF or ';'");
                return OG_ERROR;
            }
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "values "));
        } else {
            compiler->keyword_hook = plc_dmlhook_update_head;
            OG_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, OG_TRUE));
            if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "update set clause", "EOF or ';'");
                return OG_ERROR;
            }
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "set "));
            OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
            if (result) {
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
                plc_concat_word(sql, compiler->convert_buf_size, word);
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
            } else {
                uint32 flags = lex->flags;
                if (plc_compile_set_clause(compiler, sql, word) != OG_SUCCESS) {
                    lex->flags = flags;
                    return OG_ERROR;
                }
                lex->flags = flags;

                if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
                    break;
                }
                plc_concat_word(sql, compiler->convert_buf_size, word);
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));
            }
        }

        compiler->keyword_hook = plc_dmlhook_merge_when;
        OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

        if (word->id == KEY_WORD_WHEN) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "when "));
            loop_flag = OG_TRUE;
        }
    } while (loop_flag);

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_dml_end(pl_compiler_t *compiler, text_t *sql, word_t *word, pl_line_sql_t *line)
{
    compiler->keyword_hook = plc_dmlhook_none;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));
    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_replace(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    pl_line_sql_t *line = (pl_line_sql_t *)compiler->last_line;
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "replace "));

    if (plc_compile_hint(compiler, sql, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    compiler->keyword_hook = plc_dmlhook_replace_head;
    OG_RETURN_IFERR(plc_compile_dml_org(compiler, sql, word, OG_FALSE));
    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "replace values or select or set clause",
            "EOF or ';'");
        return OG_ERROR;
    }

    if (word->type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        if (lex_try_fetch(lex, "SELECT", &result) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        PLC_SAVE_KW_HOOK(compiler);
        compiler->keyword_hook = plc_dmlhook_none;
        if (plc_try_compile_select_dml(compiler, sql, word, result) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
        PLC_RESTORE_KW_HOOK(compiler);
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    } else {
        switch (word->id) {
            case KEY_WORD_VALUES:
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "values "));
                break;
            case KEY_WORD_SELECT:
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));
                break;
            case KEY_WORD_SET:
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "set "));
                break;
            default:
                OG_SRC_THROW_ERROR(word->loc, ERR_PL_UNEXPECTED_FMT, W2S(word));
                return OG_ERROR;
        }
    }

    return plc_compile_dml_end(compiler, sql, word, line);
}

static status_t plc_create_dynamic_sql_expr(sql_stmt_t *stmt, expr_tree_t **expr, text_t *sql, source_location_t loc)
{
    expr_node_t *node = NULL;
    text_t *value_text = NULL;
    char *str = NULL;

    OG_RETURN_IFERR(sql_create_expr(stmt, expr));
    (*expr)->loc = loc;

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->owner = (*expr);
    node->type = EXPR_NODE_CONST;
    node->unary = (*expr)->unary;
    node->loc = loc;
    node->dis_info.need_distinct = OG_FALSE;
    node->dis_info.idx = OG_INVALID_ID32;

    if (sql_alloc_mem(stmt->context, sql->len + 1, (void **)&str) != OG_SUCCESS) {
        return OG_ERROR;
    }

    value_text = VALUE_PTR(text_t, &node->value);
    value_text->str = str;
    value_text->len = sql->len;
    if (sql->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(str, sql->len + 1, sql->str, sql->len));
    }
    node->value.ctrl = 0;
    node->value.type = OG_TYPE_STRING;
    APPEND_CHAIN(&(*expr)->chain, node);
    (*expr)->unary = UNARY_OPER_NONE;
    (*expr)->generated = OG_TRUE;
    (*expr)->root = (*expr)->chain.first;

    return OG_SUCCESS;
}

static status_t plc_check_column_match(pl_compiler_t *compiler, sql_type_t type, pl_line_sql_t *line)
{
    if (!IS_DML_INTO_PL_VAR(type) || line->context->rs_columns == NULL) {
        return OG_SUCCESS;
    }

    return plc_verify_into_clause(line->context, &line->into, line->ctrl.loc);
}

status_t pl_compile_parse_sql(sql_stmt_t *stmt, sql_context_t **ogx, text_t *sql, source_location_t *loc,
    galist_t *sql_list)
{
    sql_stmt_t *sub_stmt = NULL;
    lex_t *lex_bak = NULL;
    status_t status = OG_ERROR;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    OG_RETURN_IFERR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));
    OG_RETURN_IFERR(pl_save_lex(stmt, &lex_bak));

    sql_init_stmt(stmt->session, sub_stmt, stmt->id);
    sub_stmt->pl_compiler = stmt->pl_compiler;
    sub_stmt->context = NULL;
    sub_stmt->session->current_stmt = sub_stmt;
    do {
        if (sql_parse(sub_stmt, sql, loc) != OG_SUCCESS) {
            pl_check_and_set_loc(*loc);
            break;
        }

        if (sql_check_dml_privs(sub_stmt, OG_TRUE) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            pl_check_and_set_loc(*loc);
            sql_release_context(sub_stmt);
            break;
        }

        if (cm_galist_insert(sql_list, sub_stmt->context) != OG_SUCCESS) {
            sql_release_context(sub_stmt);
            break;
        }
        status = OG_SUCCESS;
    } while (0);
    stmt->session->current_stmt = save_curr_stmt;
    *ogx = sub_stmt->context;
    pl_restore_lex(stmt, lex_bak);
    sql_release_lob_info(sub_stmt);
    sql_release_resource(sub_stmt, OG_TRUE);
    return status;
}

status_t plc_compile_sql(pl_compiler_t *compiler, word_t *word)
{
    text_t sql;
    pl_line_sql_t *sql_line = NULL;
    source_location_t loc;
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    OG_RETURN_IFERR(plc_stack_safe(compiler));
    // convert statement to large page addr
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_sql_t), LINE_SQL, (pl_line_ctrl_t **)&sql_line));
    OG_RETURN_IFERR(plc_init_galist(compiler, &sql_line->input));
    sql.len = 0;
    // reserve a quato for dynamic sql.
    sql.str = compiler->convert_buf;

    compiler->keyword_hook = plc_dmlhook_none;
    compiler->current_input = sql_line->input;
    loc = word->loc;
    switch (word->id) {
        case KEY_WORD_SELECT:
            OG_RETURN_IFERR(plc_compile_select_into(compiler, &sql, word));
            break;

        case KEY_WORD_INSERT:
            OG_RETURN_IFERR(plc_compile_insert(compiler, &sql, word));
            break;

        case KEY_WORD_UPDATE:
            OG_RETURN_IFERR(plc_compile_update(compiler, &sql, word));
            break;

        case KEY_WORD_DELETE:
            OG_RETURN_IFERR(plc_compile_delete(compiler, &sql, word));
            break;

        case KEY_WORD_MERGE:
            OG_RETURN_IFERR(plc_compile_merge(compiler, &sql, word));
            break;

        case KEY_WORD_REPLACE:
            OG_RETURN_IFERR(plc_compile_replace(compiler, &sql, word));
            break;

        default:
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_UNEXPECTED_FMT, W2S(word));
            return OG_ERROR;
    }

    cm_trim_text(&sql);

    /* sql has local temp table will be treated as dynamic sql */
    if (sql_has_ltt(compiler->stmt, &sql)) {
        OG_RETURN_IFERR(plc_create_dynamic_sql_expr(compiler->stmt, &sql_line->dynamic_sql, &sql, loc));
        OG_RETURN_IFERR(plc_verify_expr(compiler, sql_line->dynamic_sql));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &sql_line->dynamic_sql));
        sql_line->is_dynamic_sql = OG_TRUE;
        return OG_SUCCESS;
    } else {
        sql_line->is_dynamic_sql = OG_FALSE;
    }

    OGSQL_SAVE_STACK(stmt);
    if (pl_compile_parse_sql(stmt, &sql_line->context, &sql, &loc, &entity->sqls) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    if (plc_check_column_match(compiler, sql_line->context->type, sql_line) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_append_references(&entity->ref_list, sql_line->context);
}

static status_t plc_compile_sql_try_complex(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 *result)
{
    plc_var_type_t var_type;
    plv_decl_t *decl = NULL;
    expr_node_t *node = NULL;
    char name_buf[OG_MAX_NAME_LEN];
    text_t name = {
        .str = NULL,
        .len = 0
    };
    galist_t *input = compiler->current_input;

    plc_try_verify_word_as_var(word, result);
    if (!(*result)) {
        return OG_SUCCESS;
    }
    plc_find_decl_ex(compiler, word, PLV_COMPLEX_VARIANT, &var_type, &decl);
    if (decl == NULL || !PLC_IS_MULTIEX_VARIANT(var_type)) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }
    *result = OG_TRUE;
    OG_RETURN_IFERR(cm_galist_new(input, sizeof(expr_node_t), (void **)&node));
    if (plc_try_obj_access_bracket(compiler->stmt, word, node) != OG_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return OG_ERROR;
    }
    if (NODE_EXPR_TYPE(node) != EXPR_NODE_V_ADDR && NODE_EXPR_TYPE(node) != EXPR_NODE_V_METHOD) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "identifier \'%s\' must be declared", W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_address_expr(compiler, node));
    OG_RETURN_IFERR(plc_make_input_name(input, name_buf, OG_MAX_NAME_LEN, &name));
    cm_concat_text(sql, compiler->convert_buf_size, &name);
    return OG_SUCCESS;
}

static inline void plc_concat_pack_word_core(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 has_bracket)
{
    if (has_bracket) {
        plc_concat_word_ex(sql, compiler->convert_buf_size, word);
    } else {
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }
}

static status_t plc_concat_pack_word(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 has_bracket)
{
    plv_decl_t *spec_obj = NULL;
    function_t *func = NULL;
    galist_t *spec_objs = NULL;
    pl_dc_t *spec_dc = compiler->spec_dc;

    if (word->ex_count > 0) {
        plc_concat_pack_word_core(compiler, sql, word, has_bracket);
        return OG_SUCCESS;
    }

    if (spec_dc != NULL) {
        spec_objs = spec_dc->entity->package_spec->defs;
        for (uint32 i = 0; i < spec_objs->count; i++) {
            spec_obj = (plv_decl_t *)cm_galist_get(spec_objs, i);
            func = spec_obj->func;
            if (func->desc.pl_type != PL_FUNCTION) {
                continue;
            }
            if (cm_text_str_equal_ins(&word->text.value, func->desc.name)) {
                cm_concat_string(sql, compiler->convert_buf_size, spec_dc->entry->desc.name);
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "."));
                plc_concat_pack_word_core(compiler, sql, word, has_bracket);
                return OG_SUCCESS;
            }
        }
    }

    plc_concat_pack_word_core(compiler, sql, word, has_bracket);
    return OG_SUCCESS;
}

static status_t plc_compile_sql_func(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef)
{
    word_t func_name;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_compile_sql_try_complex(compiler, sql, word, &result));
    if (result) {
        return OG_SUCCESS;
    }

    sql_text_t *args = &word->ex_words[word->ex_count - 1].text; // not overflow

    func_name = *word;
    func_name.ex_count--;
    OG_RETURN_IFERR(plc_concat_pack_word(compiler, sql, &func_name, OG_TRUE));

    if (args->len == 0) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        return plc_concat_str(sql, compiler->convert_buf_size, ")");
    }

    PLC_SAVE_KW_HOOK(compiler);
    compiler->keyword_hook = plc_dmlhook_none;
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
    OG_RETURN_IFERR(lex_push(lex, args));
    if (plc_compile_dml(compiler, sql, word, types, usrdef) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    PLC_RESTORE_KW_HOOK(compiler);
    return OG_SUCCESS;
}

static status_t plc_compile_array_var(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    int32 start;
    int32 end;
    text_t text;
    lex_t *lex = compiler->stmt->session->lex;

    text.str = lex->curr_text->value.str;
    OG_RETURN_IFERR(lex_try_fetch_subscript(lex, &start, &end));

    text.len = (uint32)(lex->curr_text->value.str - text.str);
    cm_concat_text(sql, compiler->convert_buf_size, &text);
    return OG_SUCCESS;
}

static status_t plc_concat_variant(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef)
{
    if (IS_VARIANT(word)) {
        variant_complier_t complier_def;
        complier_def.compiler = compiler;
        complier_def.sql = sql;
        complier_def.word = word;
        complier_def.types = types;
        complier_def.usrdef = usrdef;
        OG_RETURN_IFERR(plc_compile_sql_variant(&complier_def));
        OG_RETURN_IFERR(plc_compile_array_var(compiler, sql, word));
    } else {
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }

    return OG_SUCCESS;
}

static status_t plc_compile_sql_verify_next_space(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    bool32 current_flag = PLC_NOT_NEED_NEXT_SPACE(word);
    lex_t *lex = compiler->stmt->session->lex;
    OG_RETURN_IFERR(lex_fetch(lex, word));
    if (current_flag || PLC_NOT_NEED_NEXT_SPACE(word) || word->type == WORD_TYPE_EOF ||
        word->type == WORD_TYPE_PL_TERM) {
        return OG_SUCCESS;
    }
    return plc_concat_str(sql, compiler->convert_buf_size, " ");
}

static status_t plc_compile_as_or_from(pl_compiler_t *compiler, text_t *sql, lex_t *lex, word_t *word, uint32 types,
    void *usrdef)
{
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, (word->id == KEY_WORD_AS) ? "as " : "from "));
    // don't care the word follow key_word_as
    OG_RETURN_IFERR(lex_fetch(lex, word));
    if (word->type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
        PLC_SAVE_KW_HOOK(compiler);
        compiler->keyword_hook = plc_dmlhook_none;
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        if (plc_compile_dml(compiler, sql, word, types, usrdef) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
        PLC_RESTORE_KW_HOOK(compiler);
        OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
    } else {
        plc_concat_word(sql, compiler->convert_buf_size, word);
    }
    return OG_SUCCESS;
}

// reform DML parser in PL/SQL.
status_t plc_compile_dml(pl_compiler_t *compiler, text_t *sql, word_t *word, uint32 types, void *usrdef)
{
    source_location_t loc;
    lex_t *lex = compiler->stmt->session->lex;
    OG_RETURN_IFERR(plc_stack_safe(compiler));

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    if (plc_compile_hint(compiler, sql, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    loc = word->text.loc;
    OG_RETURN_IFERR(lex_fetch(lex, word));

    while (OG_TRUE) {
        if (loc.line != 0 && loc.line != word->text.loc.line) {
            OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "\n"));
            loc = word->text.loc;
        }

        switch (word->type) {
            case WORD_TYPE_EOF:
            case WORD_TYPE_PL_TERM:
                return OG_SUCCESS;

            case WORD_TYPE_FUNCTION:
                OG_RETURN_IFERR(plc_compile_sql_func(compiler, sql, word, types, usrdef));
                break;

            case WORD_TYPE_PARAM:
                OG_RETURN_IFERR(plc_compile_sql_param(compiler, sql, word));
                break;

            case WORD_TYPE_BRACKET:
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "("));
                PLC_SAVE_KW_HOOK(compiler);
                compiler->keyword_hook = plc_dmlhook_none;
                OG_RETURN_IFERR(lex_push(lex, &word->text));
                if (plc_compile_dml(compiler, sql, word, types, usrdef) != OG_SUCCESS) {
                    lex_pop(lex);
                    return OG_ERROR;
                }
                lex_pop(lex);
                PLC_RESTORE_KW_HOOK(compiler);
                if (word->type == WORD_TYPE_PL_TERM) {
                    OG_RETURN_IFERR(lex_fetch(lex, word));
                    OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "unexpected word ';' found");
                    return OG_ERROR;
                }
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, ")"));
                break;
            case WORD_TYPE_COMPARE:
                plc_concat_word(sql, compiler->convert_buf_size, word);
                if (word->id == CMP_TYPE_EQUAL_ANY || word->id == CMP_TYPE_NOT_EQUAL_ANY ||
                    word->id == CMP_TYPE_GREAT_EQUAL_ANY || word->id == CMP_TYPE_GREAT_ANY ||
                    word->id == CMP_TYPE_LESS_ANY || word->id == CMP_TYPE_LESS_EQUAL_ANY) {
                    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " any "));
                } else if (word->id == CMP_TYPE_EQUAL_ALL || word->id == CMP_TYPE_NOT_EQUAL_ALL ||
                    word->id == CMP_TYPE_GREAT_EQUAL_ALL || word->id == CMP_TYPE_GREAT_ALL ||
                    word->id == CMP_TYPE_LESS_ALL || word->id == CMP_TYPE_LESS_EQUAL_ALL) {
                    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " all "));
                }
                break;
            case WORD_TYPE_KEYWORD:
                if (compiler->keyword_hook(word) == OG_TRUE) {
                    return OG_SUCCESS;
                }
                // else do as variant check.
                if (word->id == KEY_WORD_AS || word->id == KEY_WORD_FROM) {
                    OG_RETURN_IFERR(plc_compile_as_or_from(compiler, sql, lex, word, types, usrdef));
                    break;
                }

                OG_RETURN_IFERR(plc_concat_variant(compiler, sql, word, types, usrdef));
                if (PLC_IS_DML_WORD(word)) {
                    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, " "));
                    OG_RETURN_IFERR(plc_compile_hint(compiler, sql, word));
                }
                break;

            case WORD_TYPE_ARRAY:
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "array["));
                OG_RETURN_IFERR(lex_fetch_array(lex, word));
                OG_RETURN_IFERR(plc_concat_variant(compiler, sql, word, types, usrdef));
                OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "]"));
                break;
            case WORD_TYPE_SPEC_CHAR:
                if (compiler->keyword_hook(word) == OG_TRUE) {
                    return OG_SUCCESS;
                }
                /* fall-through */
            default:
                OG_RETURN_IFERR(plc_concat_variant(compiler, sql, word, types, usrdef));
                break;
        }
        OG_RETURN_IFERR(plc_compile_sql_verify_next_space(compiler, sql, word));
    }
}

static status_t plc_compile_select_columns(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    compiler->keyword_hook = plc_dmlhook_qrylist;
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL));

    if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "more clause", "EOF or ';'");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t plc_compile_select(pl_compiler_t *compiler, text_t *sql, word_t *word, bool32 is_select_into)
{
    pl_line_sql_t *line = NULL;
    line = (pl_line_sql_t *)compiler->last_line;

    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "select "));

    if (plc_compile_hint(compiler, sql, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // column name
    OG_RETURN_IFERR(plc_compile_select_columns(compiler, sql, word));

    if (is_select_into) {
        if (word->id != KEY_WORD_INTO && word->id != KEY_WORD_BULK) {
            OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT,
                "an INTO clause is expected in this SELECT statement");
            return OG_ERROR;
        }
        if (word->id == KEY_WORD_INTO) {
            OG_RETURN_IFERR(plc_compile_into_clause(compiler, &line->into, word));
            line->into.prefetch_rows = INTO_VALUES_PREFETCH_COUNT;
        } else {
            OG_RETURN_IFERR(plc_compile_bulk_into_clause(compiler, &line->into, word));
        }
    }

    // deal with others
    if (word->id != KEY_WORD_FROM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT,
            "an FROM clause is expected in this SELECT statement");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_concat_str(sql, compiler->convert_buf_size, "from "));

    compiler->keyword_hook = plc_dmlhook_none;
    return plc_compile_dml(compiler, sql, word, PLV_VARIANT_ALL, NULL);
}

static status_t plc_try_compile_cursor_arg(pl_compiler_t *compiler, text_t *sql, word_t *word, variant_complier_t *def,
    plv_decl_t **decl)
{
    plv_decl_t *input = def->usrdef;
    if ((input == NULL) || (input->type != PLV_CUR) || (input->cursor.ogx == NULL)) {
        return plc_concat_pack_word(compiler, sql, word, OG_FALSE);
    }

    plv_decl_t *select = NULL;
    plc_find_in_decls(input->cursor.ogx->args, (text_t *)&word->text, IS_DQ_STRING(word->type), &select);
    if ((select == NULL) || (select->type & def->types) == 0) {
        plc_concat_word(sql, compiler->convert_buf_size, word);
        return OG_SUCCESS;
    }

    *decl = select;
    return OG_ERROR;
}

// it's the time replace variant name in dml's sql
status_t plc_compile_sql_variant(void *anchor)
{
    plv_decl_t *decl = NULL;
    char name_buf[OG_MAX_NAME_LEN];
    text_t name = {
        .str = NULL,
        .len = 0
    };
    plc_var_type_t var_type;

    variant_complier_t *def = (variant_complier_t *)anchor;
    pl_compiler_t *compiler = def->compiler;
    text_t *sql_text = def->sql;
    word_t *word = def->word;
    galist_t *input = compiler->current_input;
    expr_node_t *node = NULL;
    if (IS_TRIGGER_WORD_TYPE(word)) {
        return plc_compile_trigger_variant(compiler, sql_text, word);
    }

    OG_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, def->types, &var_type, &decl);
    if (decl == NULL || (PLC_IS_MULTIEX_VARIANT(var_type) && decl->type == PLV_VAR)) {
        if (plc_try_compile_cursor_arg(compiler, sql_text, word, def, &decl) != OG_ERROR) {
            return OG_SUCCESS;
        }
    }

    OG_RETURN_IFERR(cm_galist_new(input, sizeof(expr_node_t), (void **)&node));
    if (PLC_IS_MULTIEX_VARIANT(var_type)) {
        if (plc_try_obj_access_bracket(compiler->stmt, word, node) != OG_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return OG_ERROR;
        }

        if (NODE_EXPR_TYPE(node) != EXPR_NODE_V_ADDR) {
            OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "identifier \'%s\' must be declared", W2S(word));
            return OG_ERROR;
        }

        OG_RETURN_IFERR(plc_verify_address_expr(compiler, node));
    } else {
        OG_RETURN_IFERR(plc_build_var_address(compiler->stmt, decl, node, UDT_STACK_ADDR));
        SET_FUNC_RETURN_TYPE(decl, node);
    }
    OG_RETURN_IFERR(plc_make_input_name(input, name_buf, OG_MAX_NAME_LEN, &name));
    cm_concat_text(sql_text, compiler->convert_buf_size, &name);
    return OG_SUCCESS;
}

static status_t plc_word2var_column(sql_stmt_t *stmt, word_t *word, expr_node_t *node, var_func_t *v, bool32 *result)
{
    if (node->type != EXPR_NODE_COLUMN) {
        return OG_SUCCESS;
    }

    bool32 flag = OG_FALSE;
    text_t *package = NULL;
    text_t *name = NULL;

    /* deal with the case of dbms const, such as:DBE_STATS.AUTO_SAMPLE_SIZE */
    if (word->ex_count == 1) {
        package = &word->text.value;
        name = &word->ex_words[0].text.value;
        flag = OG_TRUE;
    } else if (word->ex_count == 2) { // number 2 ex_count, such as: user.package.function
        if (cm_text_str_equal_ins(&word->text.value, SYS_USER_NAME)) {
            package = &word->ex_words[0].text.value;
            name = &word->ex_words[1].text.value;
            flag = OG_TRUE;
        }
    }

    if (!flag) {
        return OG_SUCCESS;
    }

    sql_convert_pack_func(package, name, v);
    if (v->pack_id != OG_INVALID_ID32 && v->func_id != OG_INVALID_ID32) {
        *result = OG_TRUE;
        node->value.type = OG_TYPE_COLUMN;
        return sql_word_as_column(stmt, word, &node->word);
    }
    return OG_SUCCESS;
}

/*
 * @brief    an important expression's node convert function, search block decls'
 * variants then record the vid in node's pair->stack
 */
status_t plc_word2var(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    var_func_t v;
    bool32 result = OG_FALSE;
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;

    if (compiler == NULL) {
        // If not in compiler-phase, do as column.
        node->value.type = OG_TYPE_COLUMN;
        return sql_word_as_column(stmt, word, &node->word);
    }

    OG_RETURN_IFERR(plc_word2var_column(stmt, word, node, &v, &result));
    if (result) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    OG_RETURN_IFERR(plc_try_obj_access_single(stmt, word, node));
    if (IS_UDT_EXPR(node->type)) {
        return OG_SUCCESS;
    }

    /* deal with the case of dbe_std function without parameters, such as:sqlcode, sqlerrm and so on. */
    if (node->type == EXPR_NODE_COLUMN && word->ex_count == 0) {
        text_t standard_pack_name = {
            .str = STANDARD_PACK_NAME,
            .len = (uint32)strlen(STANDARD_PACK_NAME)
        };
        sql_convert_pack_func(&standard_pack_name, &word->text.value, &v);
        if (v.pack_id != OG_INVALID_ID32 && v.func_id != OG_INVALID_ID32) {
            node->type = EXPR_NODE_FUNC;
            return sql_build_func_node(stmt, word, node);
        }
    }

    // can't find in pl, need to check if column indeed.
    node->value.type = OG_TYPE_COLUMN;
    return sql_word_as_column(stmt, word, &node->word);
}