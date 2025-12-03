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
 * lines_cl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/lines_cl.c
 *
 * -------------------------------------------------------------------------
 */

#include "lines_cl.h"
#include "ast_cl.h"
#include "dml_cl.h"
#include "pl_memory.h"
#include "base_compiler.h"
#include "decl_cl.h"
#include "pragma_cl.h"
#include "cond_parser.h"
#include "func_parser.h"
#include "pl_common.h"
#include "cursor_cl.h"
#include "call_cl.h"
#include "pl_executor.h"
#include "param_decl_cl.h"
#include "pl_udt.h"

typedef status_t (*plc_compile_lines_t)(pl_compiler_t *compiler, word_t *word);
struct st_plc_compile_lines_map {
    key_wid_t type;
    plc_compile_lines_t func;
};

static status_t plc_compile_declare_ln(pl_compiler_t *compiler, word_t *word)
{
    galist_t *decls = NULL;
    galist_t *type_decls = NULL;
    OG_RETURN_IFERR(plc_init_galist(compiler, &decls));
    OG_RETURN_IFERR(plc_init_galist(compiler, &type_decls));
    compiler->type_decls = type_decls;
    return plc_compile_block(compiler, decls, NULL, word);
}

static status_t plc_compile_begin_ln(pl_compiler_t *compiler, word_t *unused_word)
{
    galist_t *decls = NULL;
    pl_line_begin_t *line = NULL;
    word_t word;
    bool32 result = OG_FALSE;
    text_t block_name;
    pl_line_label_t *label = NULL;
    bool32 body_empty = OG_TRUE;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;

    label = (pl_line_label_t *)compiler->last_line;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_begin_t), LINE_BEGIN, (pl_line_ctrl_t **)&line));
    line->name = ((label != NULL) && (label->ctrl.type == LINE_LABEL)) ? &label->name : NULL;
    block_name = (line->name != NULL) ? *line->name : CM_NULL_TEXT;
    line->decls = decls;
    OG_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)line, &block_name));

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, &word));

        plc_check_end_symbol(&word);
        OG_RETURN_IFERR(plc_check_word_eof(word.type, word.loc));
        OG_RETURN_IFERR(plc_try_compile_end_ln(compiler, &result, NULL, &word));

        if (result) {
            if (body_empty) {
                OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "lines", "END");
                return OG_ERROR;
            }
            break;
        }

        if (plc_compile_lines(compiler, &word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, &word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }

            if (word.type == WORD_TYPE_EOF) {
                break;
            }
        }
        body_empty = OG_FALSE;
    }

    return status;
}

static status_t plc_compile_end_ln(pl_compiler_t *compiler, word_t *word)
{
    OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "OTHERS", "END");
    return OG_ERROR;
}

static status_t plc_compile_exception_line(pl_compiler_t *cmpl, word_t *word, lex_t *lex, status_t *status, bool32 *result)
{
    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_expected_fetch(lex, word));
        if (word->type == WORD_TYPE_BRACKET) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_KEYWORD_ERROR);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_try_compile_end_when(cmpl, result, word));
        OG_BREAK_IF_TRUE(*result);
        if (plc_compile_lines(cmpl, word) != OG_SUCCESS) {
            *status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(cmpl, word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            if (word->type == WORD_TYPE_EOF) {
                break;
            }
        }
    }
    return OG_SUCCESS;
}

static status_t plc_compile_exception(pl_compiler_t *compiler, word_t *word)
{
    pl_line_begin_t *begin_line = NULL;
    pl_line_except_t *except_line = NULL;
    pl_line_ctrl_t *except_end = NULL;
    plv_decl_t *decl = NULL;
    var_udo_t *block_obj = NULL;
    bool32 result = OG_FALSE;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    char block_buf[OG_MAX_NAME_LEN] = { 0 };
    text_t block_name = {
        .str = block_buf,
        .len = 0
    };
    word_t save_word;

    begin_line = (pl_line_begin_t *)plc_get_current_beginln(compiler);
    if (begin_line == NULL) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_UNEXPECTED_FMT, "symbol exception");
        return OG_ERROR;
    }

    /* check exception has existed or not */
    if (begin_line->except != NULL) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "exception has existed in this \"begin-exception-end\"");
        return OG_ERROR;
    }

    /* alloc exception line */
    OG_RETURN_IFERR(
        plc_alloc_line(compiler, sizeof(pl_line_except_t), LINE_EXCEPTION, (pl_line_ctrl_t **)&except_line));
    OG_RETURN_IFERR(plc_init_galist(compiler, &except_line->excpts));
    begin_line->except = (pl_line_ctrl_t *)except_line;
    OG_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)except_line, &block_name));

    OG_RETURN_IFERR(lex_expected_fetch(lex, word));
    if (word->id != KEY_WORD_WHEN) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "WHEN", W2S(word));
        return OG_ERROR;
    }

    /* Compile the when line */
    do {
        pl_line_when_t *line = NULL;
        pl_line_ctrl_t *line_end = NULL;

        compiler->line_loc = word->loc;
        OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_when_t), LINE_WHEN, (pl_line_ctrl_t **)&line));
        cm_galist_init(&line->excepts, pl_entity, pl_alloc_mem);

        do {
            pl_exception_t *except = NULL;

            OG_RETURN_IFERR(lex_expected_fetch(lex, word));
            OG_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(pl_exception_t), (void **)&except));

            /* Find the exception name from user defined exception and predefined exception. */
            OG_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
            plc_find_decl_ex(compiler, word, PLV_EXCPT, NULL, &decl);
            OG_RETURN_IFERR(plc_compile_exception_set_except(decl, word, except));

            /* Check the exception has not existed. */
            if (plc_find_line_except(compiler, line, except, &word->text) == OG_SUCCESS) {
                return OG_ERROR;
            }
            if (plc_check_except_exists(compiler, ((pl_line_except_t *)begin_line->except)->excpts, except,
                &word->text) == OG_SUCCESS) {
                return OG_ERROR;
            }
            if (except->is_userdef == OG_FALSE && except->error_code == OTHERS && line->excepts.count > 0) {
                OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
                    "no choices may appear with choice OTHERS in an exception handler");
                return OG_ERROR;
            }

            OG_RETURN_IFERR(cm_galist_insert(&line->excepts, (pointer_t)except));
            OG_RETURN_IFERR(lex_expected_fetch(lex, word));
        } while (word->id == KEY_WORD_OR);

        if (word->id != KEY_WORD_THEN) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "THEN", W2S(word));
            return OG_ERROR;
        }

        OG_RETURN_IFERR(plc_compile_exception_line(compiler, word, lex, &status, &result));
        OG_RETURN_IFERR(cm_galist_insert(((pl_line_except_t *)begin_line->except)->excpts, line));
        OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END_WHEN, (pl_line_ctrl_t **)&line_end));
    } while (word->id == KEY_WORD_WHEN);

    OG_RETURN_IFERR(
        plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END_EXCEPTION, (pl_line_ctrl_t **)&except_end));
    OG_RETURN_IFERR(plc_pop(compiler, compiler->line_loc, PBE_END_EXCEPTION, &except_end));
    if (result) {
        except_line->end = compiler->last_line;
    }

    /* make sure following the end of begin...end */
    block_obj = (compiler->stack.depth == 1) ? compiler->obj : NULL;
    save_word = *word;
    OG_RETURN_IFERR(plc_expected_end_ln(compiler, &result, block_obj, word));
    if (!result) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "expected END of BEGIN...END");
        return OG_ERROR;
    }
    *word = save_word;
    lex_back(lex, word);

    return status;
}

static status_t plc_try_compile_elsif_cond(pl_compiler_t *compiler, pl_line_elsif_t *line, word_t *word)
{
    if (sql_create_cond_until(compiler->stmt, &line->cond, word) != OG_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_cond(compiler, line->cond));
    OG_RETURN_IFERR(plc_clone_cond_tree(compiler, &line->cond));
    return OG_SUCCESS;
}

static status_t plc_try_compile_end_if(pl_compiler_t *compiler, bool32 *result, word_t *word)
{
    pl_line_ctrl_t *line = NULL;
    pl_line_ctrl_t *pop_line = NULL;
    pl_line_if_t *if_line = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    if (word->id != KEY_WORD_END) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    compiler->line_loc = word->loc;
    OG_RETURN_IFERR(lex_try_fetch(lex, "IF", result));
    if (!(*result)) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_END_IF, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(plc_pop(compiler, compiler->line_loc, PBE_END_IF, &pop_line));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));

    if ((pop_line->type == LINE_IF) || (pop_line->type == LINE_ELIF)) {
        if_line = (pl_line_if_t *)pop_line;
        if_line->f_line = line;
    }

    return OG_SUCCESS;
}

static status_t plc_try_compile_elsif(pl_compiler_t *compiler, bool32 *result, word_t *word)
{
    pl_line_elsif_t *line = NULL;
    pl_line_ctrl_t *brother_line = NULL;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;

    if (word->id != KEY_WORD_ELSIF) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }
    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    *result = OG_TRUE;
    compiler->line_loc = word->loc;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_elsif_t), LINE_ELIF, (pl_line_ctrl_t **)&line));
    PLC_RESET_WORD_LOC(lex, word);
    OG_RETURN_IFERR(plc_try_compile_elsif_cond(compiler, line, word));

    if (word->id != KEY_WORD_THEN) {
        OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_EXPECTED_FAIL_FMT, "THEN", W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_pop(compiler, compiler->line_loc, PBE_ELIF, (pl_line_ctrl_t **)&brother_line));
    line->if_line = (pl_line_if_t *)brother_line;
    line->if_line->f_line = (pl_line_ctrl_t *)line;
    line->t_line = NULL;
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT));

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, word));
        plc_check_end_symbol(word);
        OG_RETURN_IFERR(plc_check_word_eof(word->type, word->loc));

        OG_RETURN_IFERR(plc_try_compile_end_if(compiler, result, word));
        OG_BREAK_IF_TRUE(*result);
        OG_RETURN_IFERR(plc_try_compile_elsif(compiler, result, word));
        OG_BREAK_IF_TRUE(*result);
        if (plc_compile_lines(compiler, word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            if (word->type == WORD_TYPE_EOF) {
                break;
            }
        }
    }

    if (*result) {
        line->next = compiler->last_line;
    }

    return status;
}

static status_t plc_compile_if(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_if_t *line = NULL;
    bool32 result = OG_FALSE;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_if_t), LINE_IF, (pl_line_ctrl_t **)&line));

    word.text.loc = lex->loc;
    if (sql_create_cond_until(compiler->stmt, &line->cond, &word) != OG_SUCCESS) {
        pl_check_and_set_loc(line->ctrl.loc);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_cond(compiler, line->cond));
    OG_RETURN_IFERR(plc_clone_cond_tree(compiler, &line->cond));
    if (word.id != KEY_WORD_THEN) {
        OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_EXPECTED_FAIL_FMT, "THEN", W2S(&word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT));
    line->t_line = NULL;

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, &word));
        plc_check_end_symbol(&word);
        OG_RETURN_IFERR(plc_check_word_eof(word.type, word.loc));
        OG_RETURN_IFERR(plc_try_compile_end_if(compiler, &result, &word));
        OG_BREAK_IF_TRUE(result);
        OG_RETURN_IFERR(plc_try_compile_elsif(compiler, &result, &word));
        OG_BREAK_IF_TRUE(result);
        if (plc_compile_lines(compiler, &word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, &word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            OG_BREAK_IF_TRUE(word.type == WORD_TYPE_EOF);
        }
    }

    if (result) {
        line->next = compiler->last_line;
    }

    return status;
}

static status_t plc_compile_elsif(pl_compiler_t *compiler, word_t *word)
{
    OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_EXPECTED_FAIL_FMT, "OTHERS", "ELSIF");
    return OG_ERROR;
}

static status_t plc_compile_else(pl_compiler_t *compiler, word_t *unused_word)
{
    pl_line_ctrl_t *brother_line = NULL;
    pl_line_else_t *else_line = NULL;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_else_t), LINE_ELSE, (pl_line_ctrl_t **)&else_line));
    OG_RETURN_IFERR(plc_pop(compiler, compiler->line_loc, PBE_ELSE, (pl_line_ctrl_t **)&brother_line));
    else_line->if_line = (pl_line_if_t *)brother_line;
    else_line->if_line->f_line = (pl_line_ctrl_t *)else_line;
    return plc_push_ctl(compiler, (pl_line_ctrl_t *)else_line, &CM_NULL_TEXT);
}

static status_t plc_try_compile_end_case(pl_compiler_t *compiler, bool32 *result, word_t *word, pl_line_case_t *case_ln)
{
    pl_line_when_case_t *end_case = NULL;
    pl_line_ctrl_t *brother_line = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    if (word->id != KEY_WORD_END) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    compiler->line_loc = word->loc;
    OG_RETURN_IFERR(lex_try_fetch(lex, "CASE", result));
    if (!(*result)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_when_case_t), LINE_END_CASE, (pl_line_ctrl_t **)&end_case));
    OG_RETURN_IFERR(plc_pop(compiler, word->loc, PBE_END_CASE, (pl_line_ctrl_t **)&brother_line));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));

    if (brother_line->type == LINE_WHEN_CASE) {
        pl_line_when_case_t *when_case = (pl_line_when_case_t *)brother_line;
        when_case->f_line = &end_case->ctrl;
    }
    end_case->selector = case_ln->selector;

    return OG_SUCCESS;
}

static status_t plc_try_compile_when_case(pl_compiler_t *compiler, bool32 *result, word_t *word,
    pl_line_case_t *case_ln)
{
    pl_line_when_case_t *line = NULL;
    pl_line_ctrl_t *brother_line = NULL;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_stack_safe(compiler));

    if (word->id != KEY_WORD_WHEN) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    *result = OG_TRUE;

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    compiler->line_loc = word->loc;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_when_case_t), LINE_WHEN_CASE, (pl_line_ctrl_t **)&line));

    LEX_SAVE(lex);
    OG_RETURN_IFERR(lex_expected_fetch(lex, word));
    /* fetch excpt_id */
    int32 except_id = pl_get_exception_id(word);
    if (except_id != INVALID_EXCEPTION) {
        OG_SRC_THROW_ERROR_EX(lex->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "indentifier %s is reserved in the exception body",
            W2S(word));
        return OG_ERROR;
    }
    LEX_RESTORE(lex);

    PLC_RESET_WORD_LOC(lex, word);
    if (case_ln->selector == NULL) {
        if (sql_create_cond_until(compiler->stmt, (cond_tree_t **)&line->cond, word) != OG_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)line->cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)&line->cond));
    } else {
        bool32 word_flag = OG_FALSE;
        OG_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &word_flag));
        if (word_flag) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
                "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
            return OG_ERROR;
        }
        if (sql_create_expr_until(compiler->stmt, (expr_tree_t **)&line->cond, word) != OG_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_expr(compiler, (expr_tree_t *)line->cond));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, (expr_tree_t **)&line->cond));
    }

    if (word->id != KEY_WORD_THEN) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "THEN", W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_pop(compiler, word->loc, PBE_WHEN_CASE, (pl_line_ctrl_t **)&brother_line));
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT));
    line->if_line = (brother_line->type == LINE_CASE) ? NULL : (pl_line_if_t *)brother_line;
    line->t_line = NULL;
    line->selector = case_ln->selector;

    if (brother_line->type == LINE_WHEN_CASE) {
        pl_line_when_case_t *when_case = (pl_line_when_case_t *)brother_line;
        when_case->f_line = (pl_line_ctrl_t *)line;
    }

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, word));
        plc_check_end_symbol(word);
        OG_RETURN_IFERR(plc_check_word_eof(word->type, word->loc));

        OG_RETURN_IFERR(plc_try_compile_end_case(compiler, result, word, case_ln));
        OG_BREAK_IF_TRUE(*result);

        OG_RETURN_IFERR(plc_try_compile_when_case(compiler, result, word, case_ln));
        OG_BREAK_IF_TRUE(*result);

        if (plc_compile_lines(compiler, word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            if (word->type == WORD_TYPE_EOF) {
                break;
            }
        }
    }

    if (*result) {
        line->next = compiler->last_line;
    }

    return status;
}

static status_t plc_compile_case(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_case_t *line = NULL;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_case_t), LINE_CASE, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &CM_NULL_TEXT));

    OG_RETURN_IFERR(lex_try_fetch(lex, "WHEN", &result));
    if (result) {
        // Searched case statement
        line->selector = NULL;
        word.id = KEY_WORD_WHEN;
        word.loc = compiler->line_loc;
        OG_RETURN_IFERR(plc_try_compile_when_case(compiler, &result, &word, line));
    } else {
        // Simple case statement
        OG_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &line->selector, &word));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->selector));
        OG_RETURN_IFERR(plc_try_compile_when_case(compiler, &result, &word, line));
        if (!result) {
            OG_SRC_THROW_ERROR(word.loc, ERR_PL_SYNTAX_ERROR_FMT, "case statement must has when statement.");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t plc_compile_goto(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_goto_t *line = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_goto_t), LINE_GOTO, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    OG_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word.type, (text_t *)&word.text, &line->label));
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_try_compile_end_loop(pl_compiler_t *compiler, bool32 *result, word_t *word)
{
    pl_line_end_loop_t *line = NULL;
    pl_line_ctrl_t *pop_line = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    if (word->id != KEY_WORD_END) {
        *result = OG_FALSE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "LOOP", result));
    if (!(*result)) {
        return OG_SUCCESS;
    }

    compiler->line_loc = word->loc;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_end_loop_t), LINE_END_LOOP, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(plc_pop(compiler, compiler->line_loc, PBE_END_LOOP, &pop_line));
    OG_RETURN_IFERR(lex_fetch(lex, word));
    if (IS_VARIANT(word)) {
        // check if LOOP NAME
        OG_RETURN_IFERR(lex_fetch(lex, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    line->loop = pop_line;
    return OG_SUCCESS;
}

static status_t plc_compile_loop(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_loop_t *line = NULL;
    pl_line_label_t *label = NULL;
    text_t loop_name;
    bool32 result = OG_FALSE;
    bool32 body_empty = OG_TRUE;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;
    label = (pl_line_label_t *)compiler->last_line;
    loop_name = ((label != NULL) && (label->ctrl.type == LINE_LABEL)) ? label->name : CM_NULL_TEXT;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_loop_t), LINE_LOOP, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &loop_name));

    line->stack_line = CURR_BLOCK_BEGIN(compiler);

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, &word));
        plc_check_end_symbol(&word);
        OG_RETURN_IFERR(plc_check_word_eof(word.type, word.loc));
        OG_RETURN_IFERR(plc_try_compile_end_loop(compiler, &result, &word));
        if (result) {
            if (body_empty) {
                OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "lines", "END LOOP");
                return OG_ERROR;
            }
            break;
        }
        if (plc_compile_lines(compiler, &word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, &word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            if (word.type == WORD_TYPE_EOF) {
                break;
            }
        }
        body_empty = OG_FALSE;
    }

    if (result) {
        line->next = compiler->last_line;
    }

    return status;
}

static status_t plc_expected_fetch_range(pl_compiler_t *compiler, pl_line_for_t *line)
{
    word_t word;
    bool32 err_flag = OG_FALSE;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    PLC_RESET_WORD_LOC(lex, &word);
    OG_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
    if (result) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
        return OG_ERROR;
    }
    if (sql_create_expr_until(compiler->stmt, &line->lower_expr, &word) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR(word.loc, ERR_PL_EXPECTED_FAIL_FMT, "lower_bound expr", W2S(&word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_expr(compiler, line->lower_expr));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->lower_expr));
    if (word.type != WORD_TYPE_PL_RANGE) {
        OG_SRC_THROW_ERROR(word.loc, ERR_PL_EXPECTED_FAIL_FMT, "..", W2S(&word));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_try_fetch_char(lex, '.', &err_flag));
    if (err_flag) {
        OG_SRC_THROW_ERROR(word.loc, ERR_PL_EXPECTED_FAIL_FMT, "upper_bound", "'.'");
        return OG_ERROR;
    }

    PLC_RESET_WORD_LOC(lex, &word);
    OG_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
    if (result) {
        OG_SRC_THROW_ERROR(word.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
        return OG_ERROR;
    }
    if (sql_create_expr_until(compiler->stmt, &line->upper_expr, &word) != OG_SUCCESS) {
        cm_reset_error();
        OG_SRC_THROW_ERROR(word.loc, ERR_PL_EXPECTED_FAIL_FMT, "upper_bound expr", W2S(&word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_expr(compiler, line->upper_expr));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->upper_expr));
    if (word.id != KEY_WORD_LOOP) {
        OG_SRC_THROW_ERROR(word.loc, ERR_PL_EXPECTED_FAIL_FMT, "LOOP", W2S(&word));
        return OG_ERROR;
    }
    lex_back(lex, &word);

    return OG_SUCCESS;
}

static status_t plc_compile_for(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_for_t *line = NULL;
    pl_line_label_t *label = NULL;
    text_t loop_name;
    bool32 result = OG_FALSE;
    plv_decl_t *id = NULL;
    bool32 body_empty = OG_TRUE;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_stack_safe(compiler));
    label = (pl_line_label_t *)compiler->last_line;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_for_t), LINE_FOR, (pl_line_ctrl_t **)&line));
    line->name = ((label != NULL) && (label->ctrl.type == LINE_LABEL)) ? &label->name : NULL;
    loop_name = (line->name != NULL) ? *line->name : CM_NULL_TEXT;
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->decls));
    OG_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&line->id));
    id = line->id;
    id->vid.block = (int16)compiler->stack.depth;
    id->vid.id = 0;
    OG_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)line, &loop_name));
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &loop_name));
    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));
    OG_RETURN_IFERR(plc_diagnose_for_is_cursor(compiler, &line->is_cur));
    if (line->is_cur) {
        OG_RETURN_IFERR(plc_compile_for_cursor(compiler, line, &word));
    } else {
        /*
         * FOR LOOP Statement, The statement has this structure:
         * [label] FOR index IN [REVERSE] lower_bound..upper_bound LOOP
         * statements
         * END LOOP[label];
         * NOTE:
         * 1.If lower_bound is greater than upper_bound, then the statements never run.
         * 2.If the lower_bound or upper_bound is number type, the the i should use the round of the number.
         */
        if (!IS_VARIANT(&word)) {
            OG_SRC_THROW_ERROR(word.loc, ERR_PL_EXPECTED_FAIL_FMT, "variant", W2S(&word));
            return OG_ERROR;
        }
        id->type = PLV_VAR;
        OG_RETURN_IFERR(pl_copy_object_name_ci(compiler->entity, word.type, (text_t *)&word.text, &id->name));
        id->variant.type.datatype = OG_TYPE_INTEGER;

        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "in"));
        OG_RETURN_IFERR(lex_try_fetch(lex, "reverse", &line->reverse));
        OG_RETURN_IFERR(plc_expected_fetch_range(compiler, line));
    }

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "LOOP"));

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, &word));
        plc_check_end_symbol(&word);
        OG_RETURN_IFERR(plc_check_word_eof(word.type, word.loc));
        OG_RETURN_IFERR(plc_try_compile_end_loop(compiler, &result, &word));
        if (result) {
            if (body_empty) {
                OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "lines", "END LOOP");
                return OG_ERROR;
            }
            break;
        }
        if (plc_compile_lines(compiler, &word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, &word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            if (word.type == WORD_TYPE_EOF) {
                break;
            }
        }
        body_empty = OG_FALSE;
    }

    if (result) {
        line->next = compiler->last_line;
    }

    return status;
}

static status_t plc_compile_forall(pl_compiler_t *compiler, word_t *unused_word)
{
    OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_UNSUPPORT);
    return OG_ERROR;
}

static status_t plc_compile_while(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_while_t *line = NULL;
    pl_line_label_t *label = NULL;
    text_t loop_name;
    bool32 result = OG_FALSE;
    bool32 body_empty = OG_TRUE;
    status_t status = OG_SUCCESS;
    lex_t *lex = compiler->stmt->session->lex;

    label = (pl_line_label_t *)compiler->last_line;
    loop_name = ((label != NULL) && (label->ctrl.type == LINE_LABEL)) ? label->name : CM_NULL_TEXT;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_while_t), LINE_WHILE, (pl_line_ctrl_t **)&line));
    PLC_RESET_WORD_LOC(lex, &word);
    if (sql_create_cond_until(compiler->stmt, &line->cond, &word) != OG_SUCCESS) {
        pl_check_and_set_loc(word.loc);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_cond(compiler, line->cond));
    OG_RETURN_IFERR(plc_clone_cond_tree(compiler, &line->cond));
    OG_RETURN_IFERR(plc_push_ctl(compiler, (pl_line_ctrl_t *)line, &loop_name));

    line->stack_line = CURR_BLOCK_BEGIN(compiler);

    while (OG_TRUE) {
        lex->flags = LEX_WITH_OWNER;
        OG_RETURN_IFERR(lex_fetch(lex, &word));
        plc_check_end_symbol(&word);
        OG_RETURN_IFERR(plc_check_word_eof(word.type, word.loc));

        OG_RETURN_IFERR(plc_try_compile_end_loop(compiler, &result, &word));
        if (result) {
            if (body_empty) {
                OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "lines", "END LOOP");
                return OG_ERROR;
            }
            break;
        }
        if (plc_compile_lines(compiler, &word) != OG_SUCCESS) {
            status = OG_ERROR;
            OG_RETURN_IFERR(plc_skip_error_line(compiler, &word));
            if (g_tls_error.is_full) {
                return OG_ERROR;
            }
            if (word.type == WORD_TYPE_EOF) {
                break;
            }
        }
        body_empty = OG_FALSE;
    }

    if (result) {
        line->next = compiler->last_line;
    }

    return status;
}

static status_t plc_compile_when(pl_compiler_t *compiler, word_t *word)
{
    OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_UNSUPPORT);
    return OG_ERROR;
}

static status_t plc_compile_null(pl_compiler_t *compiler, word_t *unused_word)
{
    pl_line_ctrl_t *line = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_NULL, (pl_line_ctrl_t **)&line));
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_compile_open_decl(pl_compiler_t *compiler, lex_t *lex, word_t *word, plv_decl_t **decl)
{
    OG_RETURN_IFERR(lex_expected_fetch(lex, word));
    if (word->type != WORD_TYPE_PARAM) {
        OG_RETURN_IFERR(plc_find_decl(compiler, word, PLV_CUR, NULL, decl));
    } else {
        OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "the declaration of the cursor of this expression is incomplete or malformed");
        return OG_ERROR;
    }

    if ((*decl)->cursor.ogx->is_err) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_INCOMPLETE_DECL_FMT, T2S(&(*decl)->name));
        return OG_ERROR;
    }
    if ((*decl)->drct == PLV_DIR_IN) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PLE_CURSOR_IN_OPEN, T2S(&(*decl)->name));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_open(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_open_t *line = NULL;
    plv_decl_t *decl = NULL;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_stack_safe(compiler));
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_open_t), LINE_OPEN, (pl_line_ctrl_t **)&line));

    uint32 save_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    OG_RETURN_IFERR(plc_compile_open_decl(compiler, lex, &word, &decl));
    line->vid = decl->vid;

    /* open cursor [( actual_cursor_parameter [,...] )] explicit cursors scenario */
    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    if (result) {
        lex_trim(&word.text);
        if (word.text.len == 0) {
            result = OG_FALSE;
        }
    }

    lex->flags = save_flags;
    if (result) {
        OG_RETURN_IFERR(plc_init_galist(compiler, &line->exprs));
        OG_RETURN_IFERR(plc_build_open_cursor_args(compiler, &word, line->exprs));
        OG_RETURN_IFERR(plc_verify_cursor_args(compiler, line->exprs, decl->cursor.ogx->args, line->ctrl.loc));
    } else {
        line->exprs = NULL;
    }

    if (!decl->cursor.ogx->is_sysref) {
        if (decl->cursor.ogx->context == NULL) {
            OG_SRC_THROW_ERROR(decl->loc, ERR_PL_INCOMPLETE_DECL_FMT, T2S(&decl->name));
            return OG_ERROR;
        }
        OG_RETURN_IFERR(lex_fetch(lex, &word));

        if (IS_SPEC_CHAR(&word, ';')) {
            return OG_SUCCESS;
        }
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(&word));
        return OG_ERROR;
    } else {
        if (decl->cursor.ogx->context != NULL) {
            OG_SRC_THROW_ERROR(decl->loc, ERR_PL_INCOMPLETE_DECL_FMT, T2S(&decl->name));
            return OG_ERROR;
        }
    }

    return plc_compile_refcur(compiler, &word, decl, line);
}

static status_t plc_compile_bulk_limit_clause(pl_compiler_t *compiler, pl_into_t *into, word_t *word)
{
    if (word->id != KEY_WORD_LIMIT) {
        return OG_SUCCESS;
    }

    variant_t var;
    if (sql_create_expr_until(compiler->stmt, &into->limit, word) != OG_SUCCESS) {
        pl_check_and_set_loc(word->loc);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_verify_limit_expr(compiler, into->limit));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &into->limit));

    if (TREE_EXPR_TYPE(into->limit) != EXPR_NODE_CONST) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_exec_expr(compiler->stmt, into->limit, &var));
    if (OG_IS_NUMERIC_TYPE(var.type)) {
        OG_RETURN_IFERR(sql_convert_variant(compiler->stmt, &var, OG_TYPE_INTEGER));
    }
    if (var.is_null || var.type != OG_TYPE_INTEGER || var.v_int <= 0) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "numberic or value error");
        return OG_ERROR;
    }
    into->limit = NULL;
    into->prefetch_rows = var.v_int;
    return OG_SUCCESS;
}

static status_t plc_compile_into_record_clause(pl_into_t *into, word_t *word)
{
    expr_node_t *node = (expr_node_t *)cm_galist_get(into->output, 0);
    if (NODE_DATATYPE(node) == OG_TYPE_RECORD) {
        into->into_type = INTO_AS_REC;
    }

    if (NODE_DATATYPE(node) == OG_TYPE_OBJECT) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "type mismatch found at OBJECT type between anonymous record and INTO variables");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_check_param_into(pl_compiler_t *compiler, source_location_t loc)
{
    sql_stmt_t *stmt = (sql_stmt_t *)compiler->stmt;
    if (stmt == NULL || stmt->context->type != OGSQL_TYPE_ANONYMOUS_BLOCK) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_PARAM_USE);
        return OG_ERROR;
    }

    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    if (exec == NULL || exec->dynamic_parent == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "into clause cannot use param decl until in dynamic sql");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t plc_into_clause_check_decl(plv_decl_t *decl, word_t *word)
{
    if (decl == NULL) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "identifier \'%s\' must be declared", W2S(word));
        return OG_ERROR;
    }
    if (decl->type == PLV_CUR) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPR_AS_INTO_FMT, T2S(&decl->name));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t plc_compile_into_clause(pl_compiler_t *compiler, pl_into_t *into, word_t *word)
{
    plv_decl_t *decl = NULL;
    plc_var_type_t var_type;
    expr_node_t *node = NULL;
    into->is_bulk = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;
    OG_RETURN_IFERR(plc_init_galist(compiler, &into->output));

    while (OG_TRUE) {
        OG_RETURN_IFERR(lex_fetch(lex, word));
        OG_RETURN_IFERR(cm_galist_new(into->output, sizeof(expr_node_t), (void **)&node));

        if (word->type == WORD_TYPE_PARAM) {
            OG_RETURN_IFERR(plc_check_param_into(compiler, word->loc));
            OG_RETURN_IFERR(plc_find_param_as_expr_left(compiler, word, &decl));
            OG_RETURN_IFERR(plc_build_var_address(compiler->stmt, decl, node, UDT_STACK_ADDR));
        } else {
            OG_RETURN_IFERR(plc_find_decl(compiler, word, PLV_VARIANT_AND_CUR, &var_type, &decl));
            OG_RETURN_IFERR(plc_into_clause_check_decl(decl, word));

            if (PLC_IS_MULTIEX_VARIANT(var_type)) {
                if (plc_try_obj_access_bracket(compiler->stmt, word, node) != OG_SUCCESS) {
                    pl_check_and_set_loc(word->loc);
                    return OG_ERROR;
                }
                OG_RETURN_IFERR(plc_verify_address_expr(compiler, node));
            } else {
                OG_RETURN_IFERR(plc_build_var_address(compiler->stmt, decl, node, UDT_STACK_ADDR));
                SET_FUNC_RETURN_TYPE(decl, node);
            }
        }

        OG_RETURN_IFERR(plc_check_var_as_left(compiler, node, word->loc, NULL));
        OG_RETURN_IFERR(lex_fetch(lex, word));
        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    into->into_type = INTO_AS_VALUE;
    if (into->output->count == 1) {
        OG_RETURN_IFERR(plc_compile_into_record_clause(into, word));
    }

    return OG_SUCCESS;
}

status_t plc_compile_bulk_into_clause(pl_compiler_t *compiler, pl_into_t *into, word_t *word)
{
    plc_var_type_t var_type;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    expr_node_t *node = NULL;
    uint8 attr_type = 0;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "COLLECT"));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "INTO"));
    OG_RETURN_IFERR(plc_init_galist(compiler, &into->output));

    into->is_bulk = OG_TRUE;
    into->prefetch_rows = OG_INVALID_ID32;
    for (;;) {
        OG_RETURN_IFERR(lex_fetch(lex, word));
        OG_RETURN_IFERR(plc_find_decl(compiler, word, PLV_COLLECTION, &var_type, &decl));
        if (decl->collection->attr_type == UDT_COLLECTION || PLC_IS_MULTIEX_VARIANT(var_type)) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "cannot mix between single row and multi-row (BULK) in INTO list");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(cm_galist_new(into->output, sizeof(expr_node_t), (void **)&node));
        OG_RETURN_IFERR(plc_build_var_address(compiler->stmt, decl, node, UDT_STACK_ADDR));
        SET_FUNC_RETURN_TYPE(decl, node);
        if (into->output->count == 1) {
            attr_type = decl->collection->attr_type;
        }

        OG_RETURN_IFERR(lex_fetch(lex, word));
        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    into->into_type = INTO_AS_COLL;
    if (into->output->count == 1) {
        if (attr_type == UDT_RECORD) {
            into->into_type = INTO_AS_COLL_REC;
        } else if (attr_type == UDT_OBJECT) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "type mismatch found at OBJECT type between anonymous record and INTO variables");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t plc_compile_fetch(pl_compiler_t *compiler, word_t *unused_word)
{
    uint32 matched_id;
    word_t word;
    pl_line_fetch_t *line = NULL;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_fetch_t), LINE_FETCH, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    if (word.type != WORD_TYPE_PARAM) {
        OG_RETURN_IFERR(plc_find_decl(compiler, &word, PLV_CUR, NULL, &decl));
    } else {
        OG_SRC_THROW_ERROR(word.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "the declaration of the cursor of this expression is incomplete or malformed");
        return OG_ERROR;
    }

    line->vid = decl->vid;
    OG_RETURN_IFERR(lex_expected_fetch_1of2(lex, "INTO", "BULK", &matched_id));

    if (matched_id == 0) {
        OG_RETURN_IFERR(plc_compile_into_clause(compiler, &line->into, &word));
        line->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    } else {
        OG_RETURN_IFERR(plc_compile_bulk_into_clause(compiler, &line->into, &word));
        OG_RETURN_IFERR(plc_compile_bulk_limit_clause(compiler, &line->into, &word));
    }

    if (decl->cursor.ogx->is_sysref == OG_FALSE) {
        if (decl->cursor.ogx->context == NULL) {
            OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_UNDEFINED_SYMBOL_FMT, T2S(&decl->name));
            return OG_ERROR;
        }

        OG_RETURN_IFERR(plc_verify_into_clause(decl->cursor.ogx->context, &line->into, line->ctrl.loc));
    } else {
        if (decl->cursor.ogx->context != NULL) {
            OG_SRC_THROW_ERROR(decl->loc, ERR_PL_INCOMPLETE_DECL_FMT, T2S(&decl->name));
            return OG_ERROR;
        }
    }

    if (word.type == WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_UNEXPECTED_FMT, "EOF");
        return OG_ERROR;
    }
    if (word.type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(&word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_close(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_close_t *line = NULL;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_close_t), LINE_CLOSE, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    if (word.type != WORD_TYPE_PARAM) {
        OG_RETURN_IFERR(plc_find_decl(compiler, &word, PLV_CUR, NULL, &decl));
    } else {
        OG_SRC_THROW_ERROR(word.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "the declaration of the cursor of this expression is incomplete or malformed");
        return OG_ERROR;
    }

    line->vid = decl->vid;
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_top_loop(pl_compiler_t *compiler, source_location_t loc, pl_line_ctrl_t **line)
{
    int32 i;
    for (i = (int32)compiler->control_stack.depth - 1; i >= 0; i--) { // not overflow
        pl_line_type_t type = compiler->control_stack.items[i].entry->type;
        if ((type == LINE_LOOP) || (type == LINE_WHILE) || (type == LINE_FOR)) {
            *line = compiler->control_stack.items[i].entry;
            return OG_SUCCESS;
        }
    }

    *line = NULL;
    OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "no in loop statement.");
    return OG_ERROR;
}

static status_t plc_verify_loop(pl_compiler_t *compiler, source_location_t loc, text_t *name, pl_line_ctrl_t **line)
{
    text_t *cmp = NULL;
    int32 i;
    for (i = (int32)compiler->control_stack.depth - 1; i >= 0; i--) { // not overflow
        pl_line_type_t type = compiler->control_stack.items[i].entry->type;
        if ((type == LINE_LOOP) || (type == LINE_WHILE) || (type == LINE_FOR)) {
            cmp = &compiler->control_stack.items[i].name;
            if (cm_text_equal_ins(cmp, name)) {
                *line = compiler->control_stack.items[i].entry;
                return OG_SUCCESS;
            }
        }
    }

    *line = NULL;
    OG_SRC_THROW_ERROR_EX(loc, ERR_PL_SYNTAX_ERROR_FMT, "no in loop name %s statement.", T2S(name));
    return OG_ERROR;
}

static status_t plc_compile_exit(pl_compiler_t *compiler, word_t *unused_word)
{
    pl_line_exit_t *line = NULL;
    word_t word;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_exit_t), LINE_EXIT, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_try_fetch(lex, ";", &result));
    if (result) {
        line->cond = NULL;
        return plc_top_loop(compiler, compiler->line_loc, &line->next);
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "when", &result));
    if (result) {
        PLC_RESET_WORD_LOC(lex, &word);
        if (sql_create_cond_until(compiler->stmt, (cond_tree_t **)&line->cond, &word) != OG_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)line->cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)&line->cond));
        return plc_top_loop(compiler, compiler->line_loc, &line->next);
    }

    // EXIT [LABEL] [WHEN COND]
    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));
    // The label must exists, and the next must be a loop statement.
    OG_RETURN_IFERR(plc_verify_loop(compiler, compiler->line_loc, (text_t *)&word.text, &line->next));

    OG_RETURN_IFERR(lex_try_fetch(lex, ";", &result));
    if (result) {
        line->cond = NULL;
        // NO LABEL MEANS LATEST LOOP IN THE STACK
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "when", &result));
    if (result) {
        PLC_RESET_WORD_LOC(lex, &word);
        if (sql_create_cond_until(compiler->stmt, (cond_tree_t **)&line->cond, &word) != OG_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)line->cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)&line->cond));
        return OG_SUCCESS;
    }

    OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_SYNTAX_ERROR_FMT, "mismatch EXIT [LABEL] [WHEN COND].");
    return OG_ERROR;
}

static status_t plc_compile_continue(pl_compiler_t *compiler, word_t *unused_word)
{
    pl_line_continue_t *line = NULL;
    word_t word;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_continue_t), LINE_CONTINUE, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_try_fetch(lex, ";", &result));

    if (result) {
        line->cond = NULL;
        return plc_top_loop(compiler, line->ctrl.loc, &line->next);
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "when", &result));
    if (result) {
        PLC_RESET_WORD_LOC(lex, &word);
        if (sql_create_cond_until(compiler->stmt, (cond_tree_t **)&line->cond, &word) != OG_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)line->cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)&line->cond));
        return plc_top_loop(compiler, line->ctrl.loc, &line->next);
    }

    // EXIT [LABEL] [WHEN COND]
    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));
    // The label must exists, and the next must be a loop statement.
    OG_RETURN_IFERR(plc_verify_loop(compiler, line->ctrl.loc, (text_t *)&word.text, &line->next));
    OG_RETURN_IFERR(lex_try_fetch(lex, ";", &result));
    if (result) {
        line->cond = NULL;
        // NO LABEL MEANS LATEST LOOP IN THE STACK
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "when", &result));
    if (result) {
        PLC_RESET_WORD_LOC(lex, &word);
        if (sql_create_cond_until(compiler->stmt, (cond_tree_t **)&line->cond, &word) != OG_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_cond(compiler, (cond_tree_t *)line->cond));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, (cond_tree_t **)&line->cond));
        return OG_SUCCESS;
    }

    OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT, "mismatched CONTINUE [LABEL] [WHEN COND].");
    return OG_ERROR;
}

static status_t plc_compile_commit(pl_compiler_t *compiler, word_t *unused_word)
{
    pl_line_ctrl_t *line = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_ctrl_t), LINE_COMMIT, (pl_line_ctrl_t **)&line));
    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_compile_rollback(pl_compiler_t *compiler, word_t *word)
{
    pl_entity_t *entity = compiler->entity;
    lex_t *lex = compiler->stmt->session->lex;
    pl_line_rollback_t *line = NULL;
    bool32 result = OG_FALSE;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_rollback_t), LINE_ROLLBACK, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));

    if (result) {
        OG_RETURN_IFERR(lex_try_fetch(lex, "SAVEPOINT", &result));
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        OG_RETURN_IFERR(pl_copy_name(entity, (text_t *)&word->text, &line->savepoint));
    }

    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_compile_savepoint(pl_compiler_t *compiler, word_t *word)
{
    pl_line_savepoint_t *line = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_savepoint_t), LINE_SAVEPOINT, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
    OG_RETURN_IFERR(pl_copy_name(compiler->entity, (text_t *)&word->text, &line->savepoint));

    return lex_expected_fetch_word(lex, ";");
}

static status_t plc_compile_with(pl_compiler_t *compiler, word_t *word)
{
    OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_UNSUPPORT);
    return OG_ERROR;
}

static status_t plc_compile_raise_decl(pl_compiler_t *compiler, plv_decl_t *decl, word_t *word,
    pl_line_raise_t *raise_line)
{
    int32 except_id;
    pl_entity_t *entity = compiler->entity;

    if (decl != NULL) {
        OG_RETURN_IFERR(pl_copy_name(entity, (text_t *)&word->text, &raise_line->excpt_name));
        raise_line->excpt_info.is_userdef = decl->excpt.is_userdef;
        raise_line->excpt_info.error_code =
            (decl->excpt.err_code == INVALID_EXCEPTION) ? ERR_USER_DEFINED_EXCEPTION : (int32)decl->excpt.err_code;
        raise_line->excpt_info.vid = decl->vid;
    } else {
        except_id = pl_get_exception_id(word);
        if (except_id == INVALID_EXCEPTION) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_PL_INVALID_EXCEPTION_FMT, W2S(word));
            return OG_ERROR;
        }
        OG_RETURN_IFERR(pl_copy_name(entity, (text_t *)&word->text, &raise_line->excpt_name));
        raise_line->excpt_info.is_userdef = OG_FALSE;
        raise_line->excpt_info.error_code = except_id;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_raise(pl_compiler_t *compiler, word_t *unused_word)
{
    word_t word;
    pl_line_raise_t *raise_line = NULL;
    pl_line_ctrl_t *ctrl_line = NULL;
    bool32 result = OG_FALSE;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    int i;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_raise_t), LINE_RAISE, (pl_line_ctrl_t **)&raise_line));
    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));

    /* check the exception name is defined by user or predefined. */
    if (IS_VARIANT(&word)) {
        OG_RETURN_IFERR(plc_verify_word_as_var(compiler, &word));
        plc_find_decl_ex(compiler, &word, PLV_EXCPT, NULL, &decl);
        OG_RETURN_IFERR(plc_compile_raise_decl(compiler, decl, &word, raise_line));

        OG_RETURN_IFERR(lex_try_fetch(lex, ";", &result));

        if (!result) {
            OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", "OTHERS");
            return OG_ERROR;
        }
    } else if (word.type == WORD_TYPE_PL_TERM) {
        /* Check this is used in a exception block */
        for (i = (int)compiler->stack.depth; i > 0; i--) {
            ctrl_line = compiler->stack.items[i - 1].entry;
            if (ctrl_line->type == LINE_EXCEPTION) {
                break;
            }
        }

        if (i == 0) {
            OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_SYNTAX_ERROR_FMT,
                "a RAISE statement with no exception name must be inside an exception handler");
            return OG_ERROR;
        }
        raise_line->excpt_name = CM_NULL_TEXT;
        raise_line->excpt_info.is_userdef = OG_FALSE;
        raise_line->excpt_info.error_code = INVALID_EXCEPTION;
    } else {
        OG_SRC_THROW_ERROR(compiler->line_loc, ERR_PL_INVALID_EXCEPTION_FMT, W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t plc_verify_variant_assign(pl_compiler_t *compiler, plv_decl_t *decl, expr_tree_t *right,
    source_location_t loc)
{
    if (decl->variant.type.datatype == OG_TYPE_CURSOR) {
        return plc_verify_cursor_setval(compiler, right);
    }

    if (!var_datatype_matched(decl->variant.type.datatype, TREE_DATATYPE(right))) {
        OG_SRC_THROW_ERROR(TREE_LOC(right), ERR_TYPE_MISMATCH,
            get_datatype_name_str((int32)(decl->variant.type.datatype)),
            get_datatype_name_str((int32)(right->root->datatype)));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t plc_verify_array_assign(plv_decl_t *decl, expr_tree_t *right)
{
    if (!TREE_TYPMODE(right).is_array) {
        OG_SRC_THROW_ERROR(TREE_LOC(right), ERR_TYPE_MISMATCH, "ARRAY",
            get_datatype_name_str((int32)(right->root->datatype)));
        return OG_ERROR;
    }

    if (!var_datatype_matched(decl->array.type.datatype, TREE_DATATYPE(right))) {
        OG_SRC_THROW_ERROR(TREE_LOC(right), ERR_TYPE_MISMATCH,
            get_datatype_name_str((int32)(decl->variant.type.datatype)),
            get_datatype_name_str((int32)(right->root->datatype)));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t plc_verify_stack_var_assign(pl_compiler_t *compiler, plv_decl_t *left_decl, expr_tree_t *right)
{
    switch (left_decl->type) {
        case PLV_PARAM:
            break;
        case PLV_CUR:
            OG_RETURN_IFERR(plc_verify_cursor_setval(compiler, right));
            break;
        case PLV_RECORD:
            if (udt_verify_record_assign(right->root, left_decl->record) != OG_SUCCESS) {
                cm_reset_error();
                OG_SRC_THROW_ERROR(right->loc, ERR_PL_EXPR_WRONG_TYPE);
                return OG_ERROR;
            }
            break;
        case PLV_OBJECT:
            if (udt_verify_object_assign(right->root, left_decl->object) != OG_SUCCESS) {
                cm_reset_error();
                OG_SRC_THROW_ERROR(right->loc, ERR_PL_EXPR_WRONG_TYPE);
                return OG_ERROR;
            }
            break;
        case PLV_COLLECTION:
            if (!UDT_VERIFY_COLL_ASSIGN(right->root, left_decl->collection)) {
                OG_SRC_THROW_ERROR(right->loc, ERR_PL_EXPR_WRONG_TYPE);
                return OG_ERROR;
            }
            break;
        case PLV_VAR:
            OG_RETURN_IFERR(plc_verify_variant_assign(compiler, left_decl, right, left_decl->loc));
            break;
        case PLV_ARRAY:
            OG_RETURN_IFERR(plc_verify_array_assign(left_decl, right));
            break;
        case PLV_EXCPT:
        case PLV_TYPE:
        default:
            OG_SRC_THROW_ERROR(right->loc, ERR_PL_EXPR_WRONG_TYPE);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_return(pl_compiler_t *compiler, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    pl_line_return_t *line = NULL;
    bool32 result = OG_FALSE;
    plv_decl_t *decl = NULL;
    plv_id_t ret_vid = {
        .block = 0,
        .id = 0,
        .input_id = 0
    };
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_return_t), LINE_RETURN, (pl_line_ctrl_t **)&line));

    if (compiler->type == PL_FUNCTION) {
        PLC_RESET_WORD_LOC(lex, word);
        OG_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
        if (result) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
                "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
            return OG_ERROR;
        }

        if (sql_create_expr_until(compiler->stmt, &line->expr, word) != OG_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return OG_ERROR;
        }
        if (word->type != WORD_TYPE_PL_TERM) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
            return OG_ERROR;
        }
        decl = plc_find_param_by_id(compiler, ret_vid);
        if (decl == NULL) {
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_check_decl_as_left(compiler, decl, compiler->last_line->loc, NULL));
        OG_RETURN_IFERR(plc_verify_expr(compiler, line->expr));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->expr));
        if (sql_is_skipped_expr(line->expr)) {
            return OG_SUCCESS;
        }
        return plc_verify_stack_var_assign(compiler, decl, line->expr);
    }

    return lex_expected_fetch_word(lex, ";");
}

/*
 * @brief    pl verify expr after using. ATTENTION: bind param can not be used after using.
 */
static inline status_t plc_verify_using_expr(pl_compiler_t *compiler, expr_tree_t *expr)
{
    uint32 excl_flags;

    excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT |
        SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID | SQL_EXCL_METH_PROC |
        SQL_EXCL_PL_PROC;
    return plc_verify_expr_node(compiler, expr->root, NULL, excl_flags);
}

static status_t plc_compile_using_clause(pl_compiler_t *compiler, pl_line_execute_t *line, word_t *word)
{
    plv_direction_t dir = PLV_DIR_NONE;
    expr_tree_t *expr = NULL;
    bool32 result = OG_FALSE;
    pl_using_expr_t *using_expr = NULL;
    text_t decl_name;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_init_galist(compiler, &line->using_exprs));
    while (OG_TRUE) {
        OG_RETURN_IFERR(plc_using_clause_get_dir(&dir, lex, &decl_name));

        PLC_RESET_WORD_LOC(lex, word);
        OG_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
        if (result) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
                "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
            return OG_ERROR;
        }

        if (sql_create_expr_until(compiler->stmt, &expr, word) != OG_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_using_expr(compiler, expr));
        if (dir == PLV_DIR_OUT || dir == PLV_DIR_INOUT) {
            OG_RETURN_IFERR(plc_verify_out_expr(compiler, expr, NULL));
            OG_RETURN_IFERR(plc_verify_using_out_cursor(compiler, expr));
        }
        decl_name.len = (uint32)(word->text.str - decl_name.str); // not overflow
        cm_trim_text(&decl_name);
        if (decl_name.len > OG_MAX_NAME_LEN) {
            decl_name.len = OG_MAX_NAME_LEN;
        }

        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &expr));
        OG_RETURN_IFERR(pl_alloc_mem(compiler->entity, sizeof(pl_using_expr_t), (void **)&using_expr));
        using_expr->expr = expr;
        using_expr->dir = dir;

        OG_RETURN_IFERR(cm_galist_insert(line->using_exprs, using_expr));
        if (word->text.len != 1 || word->text.str[0] != ',') {
            break;
        }
    }
    return OG_SUCCESS;
}

static status_t plc_compile_exec_immediate(pl_compiler_t *compiler, word_t *word)
{
    pl_line_execute_t *line = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "IMMEDIATE"));
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_execute_t), LINE_EXECUTE, (pl_line_ctrl_t **)&line));

    PLC_RESET_WORD_LOC(lex, word);
    OG_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &line->dynamic_sql, word));
    OG_RETURN_IFERR(plc_verify_expr(compiler, line->dynamic_sql));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->dynamic_sql));

    if (word->id == KEY_WORD_INTO) {
        OG_RETURN_IFERR(plc_compile_into_clause(compiler, &line->into, word));
        line->into.prefetch_rows = INTO_VALUES_PREFETCH_COUNT;
    } else if (word->id == KEY_WORD_BULK) {
        OG_RETURN_IFERR(plc_compile_bulk_into_clause(compiler, &line->into, word));
    }

    if (word->id == KEY_WORD_USING) {
        OG_RETURN_IFERR(plc_compile_using_clause(compiler, line, word));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static plc_compile_lines_map_t g_plc_compile_lines_map[] = {
    { KEY_WORD_DECLARE,   plc_compile_declare_ln },
    { KEY_WORD_BEGIN,     plc_compile_begin_ln },
    { KEY_WORD_END,       plc_compile_end_ln },
    { KEY_WORD_EXCEPTION, plc_compile_exception },
    { KEY_WORD_IF,        plc_compile_if },
    { KEY_WORD_ELSIF,     plc_compile_elsif },
    { KEY_WORD_ELSE,      plc_compile_else },
    { KEY_WORD_CASE,      plc_compile_case },
    { KEY_WORD_GOTO,      plc_compile_goto },
    { KEY_WORD_LOOP,      plc_compile_loop },
    { KEY_WORD_FOR,       plc_compile_for },
    { KEY_WORD_FORALL,    plc_compile_forall },
    { KEY_WORD_WHILE,     plc_compile_while },
    { KEY_WORD_WHEN,      plc_compile_when },
    { RES_WORD_NULL,      plc_compile_null },
    { KEY_WORD_NULL,      plc_compile_null },
    { KEY_WORD_OPEN,      plc_compile_open },
    { KEY_WORD_FETCH,     plc_compile_fetch },
    { KEY_WORD_CLOSE,     plc_compile_close },
    { KEY_WORD_EXIT,      plc_compile_exit },
    { KEY_WORD_CONTINUE,  plc_compile_continue },
    { KEY_WORD_SELECT,    plc_compile_sql },
    { KEY_WORD_INSERT,    plc_compile_sql },
    { KEY_WORD_UPDATE,    plc_compile_sql },
    { KEY_WORD_DELETE,    plc_compile_sql },
    { KEY_WORD_MERGE,     plc_compile_sql },
    { KEY_WORD_REPLACE,   plc_compile_sql },
    { KEY_WORD_COMMIT,    plc_compile_commit },
    { KEY_WORD_ROLLBACK,  plc_compile_rollback },
    { KEY_WORD_SAVEPOINT, plc_compile_savepoint },
    { KEY_WORD_WITH,      plc_compile_with },
    { KEY_WORD_RAISE,     plc_compile_raise },
    { KEY_WORD_RETURN,    plc_compile_return },
    { KEY_WORD_EXECUTE,   plc_compile_exec_immediate },
};

static status_t plc_add_label(pl_compiler_t *compiler, pl_line_ctrl_t *line)
{
    if (compiler->labels.count >= PL_MAX_BLOCK_DEPTH) {
        OG_SRC_THROW_ERROR(line->loc, ERR_PL_EXCEED_LABEL_MAX, PL_MAX_BLOCK_DEPTH);
        return OG_ERROR;
    }

    compiler->labels.lines[compiler->labels.count] = line;
    compiler->labels.count++;
    return OG_SUCCESS;
}

status_t plc_compile_label(pl_compiler_t *compiler, word_t *word, text_t *label_name)
{
    pl_line_label_t *line = NULL;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_label_t), LINE_LABEL, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(pl_copy_object_name_ci(compiler->entity, word->type, (text_t *)&word->text, &line->name));
    OG_RETURN_IFERR(plc_add_label(compiler, (pl_line_ctrl_t *)line));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, ">>"));
    *label_name = line->name;

    line->stack_line = CURR_BLOCK_BEGIN(compiler);
    return OG_SUCCESS;
}

static status_t plc_verify_var_assign(pl_compiler_t *compiler, expr_node_t *left_node, expr_tree_t *right)
{
    status_t status = OG_SUCCESS;
    OG_RETURN_IFERR(plc_verify_address_expr(compiler, left_node));

    switch (left_node->datatype) {
        case OG_TYPE_RECORD:
            status = udt_verify_record_assign(right->root, (plv_record_t *)left_node->udt_type);
            break;
        case OG_TYPE_OBJECT:
            status = udt_verify_object_assign(right->root, (plv_object_t *)left_node->udt_type);
            break;
        case OG_TYPE_COLLECTION:
            status =
                UDT_VERIFY_COLL_ASSIGN(right->root, (plv_collection_t *)left_node->udt_type) ? OG_SUCCESS : OG_ERROR;
            break;
        case OG_TYPE_CURSOR:
            status = plc_verify_cursor_setval(compiler, right);
            break;
        default:
            if (CM_IS_SCALAR_DATATYPE(left_node->datatype) &&
                !var_datatype_matched(left_node->datatype, TREE_DATATYPE(right))) {
                OG_SRC_THROW_ERROR(TREE_LOC(right), ERR_TYPE_MISMATCH,
                    get_datatype_name_str((int32)left_node->datatype),
                    get_datatype_name_str((int32)TREE_DATATYPE(right)));
                return OG_ERROR;
            }
            break;
    }
    if (status != OG_SUCCESS) {
        cm_reset_error();
        OG_SRC_THROW_ERROR(right->loc, ERR_PL_EXPR_WRONG_TYPE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_verify_setval(pl_compiler_t *compiler, expr_node_t *left, expr_tree_t *right)
{
    OG_RETURN_IFERR(plc_verify_expr(compiler, right));
    if (sql_is_skipped_expr(right)) {
        return OG_SUCCESS;
    }

    return plc_verify_var_assign(compiler, left, right);
}

static status_t plc_compile_setval(pl_compiler_t *compiler, word_t *word, expr_node_t *expr, pl_line_normal_t *line)
{
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    line->left = expr;
    OG_RETURN_IFERR(plc_check_var_as_left(compiler, line->left, compiler->last_line->loc, NULL));
    LEX_SAVE(lex);

    PLC_RESET_WORD_LOC(lex, word);
    OG_RETURN_IFERR(lex_try_fetch(lex, "PRIOR", &result));
    if (result) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "function or pseudo-column 'PRIOR' may be used inside a SQL statement");
        return OG_ERROR;
    }

    if (sql_create_expr_until(compiler->stmt, &line->expr, word) != OG_SUCCESS) {
        LEX_RESTORE(lex);
        line->expr = NULL;

        PLC_RESET_WORD_LOC(lex, word);
        if (sql_create_cond_until(compiler->stmt, &line->cond, word) != OG_SUCCESS) {
            pl_check_and_set_loc(word->loc);
            cm_reset_error();
            return OG_ERROR;
        }
        cm_reset_error();
        OG_RETURN_IFERR(plc_verify_cond(compiler, line->cond));
    } else {
        OG_RETURN_IFERR(plc_verify_setval(compiler, line->left, line->expr));
    }

    if (word->type != WORD_TYPE_PL_TERM) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t plc_label_name_verify(pl_compiler_t *compiler, const word_t *word)
{
    if (word->type != WORD_TYPE_VARIANT && word->type != WORD_TYPE_DQ_STRING) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_LABEL_INVALID_TYPE);
        return OG_ERROR;
    }
    if (word->ex_count > 0) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, ">>", ".");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_normal_ln(pl_compiler_t *compiler, word_t *word)
{
    text_t label_name = CM_NULL_TEXT;
    lex_t *lex = compiler->stmt->session->lex;
    expr_node_t *expr = NULL;
    pl_line_normal_t *line = NULL;

    lex_back(lex, word);
    OG_RETURN_IFERR(lex_fetch(lex, word));

    if (IS_PL_LABEL(word)) {
        OG_RETURN_IFERR(lex_fetch_pl_label(lex, word));
        OG_RETURN_IFERR(plc_label_name_verify(compiler, word));
        return plc_compile_label(compiler, word, &label_name);
    }

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_normal_t), LINE_SETVAL, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(sql_alloc_mem(compiler->stmt->context, sizeof(expr_node_t), (void **)&expr));
    expr->owner = NULL;
    expr->type = EXPR_NODE_PROC;
    expr->unary = UNARY_OPER_NONE;
    expr->loc = word->text.loc;
    OG_RETURN_IFERR(sql_build_func_node(compiler->stmt, word, expr));
    if (word->type == WORD_TYPE_PL_OLD_COL) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "Assigning value to ':old.' is not supported. word = %s", W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(lex_fetch(lex, word));
    if (word->type == WORD_TYPE_PL_TERM) {
        OG_RETURN_IFERR(plc_compile_call(compiler, expr, line));
        OG_RETURN_IFERR(plc_clone_expr_node(compiler, &line->proc));
    } else if (word->type == WORD_TYPE_PL_SETVAL) {
        OG_RETURN_IFERR(plc_compile_setval(compiler, word, expr, line));
        OG_RETURN_IFERR(plc_clone_expr_node(compiler, &line->left));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->expr));
        OG_RETURN_IFERR(plc_clone_cond_tree(compiler, &line->cond));
    } else {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "';' or ':='", W2S(word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t plc_compile_lines(pl_compiler_t *compiler, word_t *word)
{
    OG_RETURN_IFERR(plc_stack_safe(compiler));
    compiler->line_loc = word->loc;
    lex_t *lex = compiler->stmt->session->lex;
    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;
    uint32 func_index;
    uint32 func_cnt = sizeof(g_plc_compile_lines_map) / sizeof(plc_compile_lines_map_t);

    for (func_index = 0; func_index < func_cnt; func_index++) {
        if (word->id == g_plc_compile_lines_map[func_index].type) {
            OG_RETURN_IFERR(g_plc_compile_lines_map[func_index].func(compiler, word));
            break;
        }
    }
    if (func_index == func_cnt) {
        OG_RETURN_IFERR(plc_compile_normal_ln(compiler, word));
    }

    return OG_SUCCESS;
}
