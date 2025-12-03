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
 * ast.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/ast/ast.c
 *
 * -------------------------------------------------------------------------
 */

#include "ast.h"
/*
 * @brief   check symbol /
 */
void plc_check_end_symbol(word_t *word)
{
    if (word->type != WORD_TYPE_OPERATOR) {
        return;
    }
    if (word->text.str[0] == '/' && word->text.len == 1) {
        word->type = WORD_TYPE_EOF;
    }
}

status_t plc_check_word_eof(word_type_t type, source_location_t loc)
{
    if (type == WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_EXPECTED_FAIL_FMT, "more text", "EOF");
        return OG_ERROR;
    }
    if (type == WORD_TYPE_BRACKET) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_KEYWORD_ERROR);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t plc_compile_exception_set_except(plv_decl_t *decl, word_t *word, pl_exception_t *pl_except)
{
    int32 except_id;
    if (decl != NULL) {
        pl_except->is_userdef = decl->excpt.is_userdef;
        if (decl->excpt.err_code == INVALID_EXCEPTION) {
            pl_except->error_code = ERR_USER_DEFINED_EXCEPTION;
        } else {
            pl_except->error_code = (int32)decl->excpt.err_code;
        }
        pl_except->vid = decl->vid;
    } else {
        except_id = pl_get_exception_id(word);
        if (except_id == INVALID_EXCEPTION) {
            OG_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S_EX(word));
            return OG_ERROR;
        }

        pl_except->is_userdef = OG_FALSE;
        pl_except->error_code = except_id;
    }

    return OG_SUCCESS;
}

status_t plc_using_clause_get_dir(plv_direction_t *dir, lex_t *lex, text_t *decl_name)
{
    bool32 result = OG_FALSE;
    *dir = PLV_DIR_NONE;
    OG_RETURN_IFERR(lex_try_fetch(lex, "IN", &result));
    if (result) {
        *dir = PLV_DIR_IN;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "OUT", &result));
    decl_name->str = lex->curr_text->str;
    if (result) {
        *dir = (*dir == PLV_DIR_IN) ? PLV_DIR_INOUT : PLV_DIR_OUT;
    } else {
        *dir = PLV_DIR_IN;
    }
    return OG_SUCCESS;
}

status_t plc_prepare_noarg_call(word_t *word)
{
    uint32 count = word->ex_count;

    if (count >= MAX_EXTRA_TEXTS) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT, "more than extra word max limit");
        return OG_ERROR;
    }
    word->ex_words[count].type = WORD_TYPE_BRACKET;
    word->ex_words[count].text.value = CM_NULL_TEXT;
    word->ex_count++;
    return OG_SUCCESS;
}

status_t plc_ctl_block_count_change(pl_line_type_t line_type, uint32 *block_depth, uint32 *block_count,
    uint32 count_size)
{
    switch (line_type) {
        case LINE_FOR:
        case LINE_WHILE:
        case LINE_LOOP:
        case LINE_IF:
        case LINE_BEGIN:
            if (*block_depth >= count_size) {
                return OG_ERROR;
            }
            block_count[*block_depth]++;
            (*block_depth)++;
            break;

        case LINE_CASE:
            if (*block_depth >= count_size) {
                return OG_ERROR;
            }
            (*block_depth)++;
            break;

        case LINE_ELIF:
        case LINE_ELSE:
        case LINE_WHEN_CASE:
        case LINE_EXCEPTION:
            block_count[*block_depth - 1]++;
            break;

        case LINE_END_IF:
        case LINE_END_LOOP:
        case LINE_END_CASE:
        case LINE_END:
            if ((*block_depth) > 0) {
                (*block_depth)--;
            } else {
                return OG_ERROR;
            }
            break;

        default:
            break;
    }

    return OG_SUCCESS;
}

status_t plc_find_ctl_block_id(pl_line_ctl_block_t *ogl_block_lines, pl_line_ctrl_t *line,
    pl_ctl_block_id_t *ogl_block_id)
{
    pl_line_ctl_block_t *ogl_block_ln = ogl_block_lines;

    while (ogl_block_ln != NULL) {
        if (ogl_block_ln->line == line) {
            *ogl_block_id = ogl_block_ln->ogl_block_id;
            return OG_SUCCESS;
        }
        ogl_block_ln = ogl_block_ln->next;
    }
    return OG_ERROR;
}

bool32 plc_ctl_block_equal(pl_ctl_block_id_t *block_id1, pl_ctl_block_id_t *block_id2)
{
    uint32 miner_depth = (block_id1->depth < block_id2->depth) ? block_id1->depth : block_id2->depth;

    return (block_id1->id[miner_depth - 1] == block_id2->id[miner_depth - 1]);
}

void plc_copy_ctl_block_id(pl_ctl_block_id_t *ogl_block_id, uint32 block_depth, uint32 *block_count, uint32 cnt_size)
{
    uint32 i;
    uint32 depth = (block_depth <= cnt_size) ? block_depth : cnt_size;
    ogl_block_id->depth = depth;
    for (i = 0; i < depth; i++) {
        ogl_block_id->id[i] = block_count[i];
    }
}

status_t plc_verify_label_next(sql_stmt_t *plc_stmt, pl_line_ctl_block_t **curr_ctl_block_ln)
{
    if ((*curr_ctl_block_ln)->line != NULL) {
        if (sql_push(plc_stmt, sizeof(pl_line_ctl_block_t), (void **)&(*curr_ctl_block_ln)->next) != OG_SUCCESS) {
            return OG_ERROR;
        }
        *curr_ctl_block_ln = (*curr_ctl_block_ln)->next;
        errno_t rc_memzero = memset_s(*curr_ctl_block_ln, sizeof(pl_line_ctl_block_t), 0, sizeof(pl_line_ctl_block_t));
        if (rc_memzero != EOK) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
            OGSQL_POP(plc_stmt);
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t plc_make_input_name(galist_t *input, char *buf, uint32 buf_len, text_t *name)
{
    int iret_snprintf = snprintf_s(buf, buf_len, buf_len - 1, ":%u ", input->count);
    if (iret_snprintf == -1) {
        OG_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return OG_ERROR;
    }

    if (name != NULL) {
        name->str = buf;
        name->len = (uint32)iret_snprintf;
    }
    return OG_SUCCESS;
}