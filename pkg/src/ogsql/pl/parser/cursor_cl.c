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
 * cursor_cl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/cursor_cl.c
 *
 * -------------------------------------------------------------------------
 */

#include "cursor_cl.h"
#include "base_compiler.h"
#include "decl_cl.h"
#include "pl_memory.h"
#include "pl_common.h"
#include "ogsql_parser.h"
#include "dml.h"
#include "ogsql_dependency.h"
#include "typedef_cl.h"
#include "ast_cl.h"
#include "pl_udt.h"
#include "dml_cl.h"
#include "pl_dc.h"
#include "func_parser.h"

static status_t plc_compile_cursor_select(pl_compiler_t *compiler, plv_decl_t *decl, word_t *word, text_t *sql_text)
{
    sql_text->len = 0;
    sql_text->str = compiler->convert_buf;

    OG_RETURN_IFERR(plc_concat_str(sql_text, compiler->convert_buf_size, "select "));
    compiler->current_input = decl->cursor.input;
    compiler->keyword_hook = plc_dmlhook_none;
    // column name
    OG_RETURN_IFERR(plc_compile_dml(compiler, sql_text, word, PLV_VARIANT_ALL | PLV_CUR, (void *)decl));

    if (word->type != WORD_TYPE_PL_TERM && word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR(decl->loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_expanse_cursor_def(pl_compiler_t *compiler, plv_decl_t *decl, pl_line_open_t *line,
    bool32 dynamic_check)
{
    word_t word;
    text_t sql_text;
    source_location_t loc;
    sql_context_t *cursor_ctx = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    loc = lex->loc;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SELECT"));

    PLC_RESET_WORD_LOC(lex, &word);
    OG_RETURN_IFERR(plc_compile_cursor_select(compiler, decl, &word, &sql_text));
    cm_trim_text(&sql_text);

    CM_ASSERT(decl->cursor.ogx->context == NULL);
    OGSQL_SAVE_STACK(stmt);
    if (pl_compile_parse_sql(stmt, &cursor_ctx, &sql_text, &loc, &entity->sqls) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    if (decl->cursor.ogx->is_sysref == OG_FALSE) {
        decl->cursor.ogx->context = cursor_ctx;
    } else {
        ((pl_line_open_t *)line)->context = cursor_ctx;
    }

    if (!cursor_ctx->cacheable) {
        // if not cached, need inherit for reparse next time.
        pl_entity_uncacheable(compiler->entity);
    }

    /* add referenced object info to current compiler statement */
    OG_RETURN_IFERR(sql_append_references(&entity->ref_list, cursor_ctx));

    return OG_SUCCESS;
}

static status_t plc_copy_context_rscols(pl_compiler_t *compiler, sql_context_t *sql_ctx, plv_record_t *record)
{
    uint32 col_id;
    plv_record_attr_t *attr = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;

    for (col_id = 0; col_id < sql_ctx->rs_columns->count; col_id++) {
        rs_column_t *col = cm_galist_get(sql_ctx->rs_columns, col_id);
        /* column type do not support the array type */
        if (col->typmod.is_array) {
            OG_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
            return OG_ERROR;
        }
        attr = udt_record_alloc_attr(pl_entity, record);
        if (attr == NULL) {
            pl_check_and_set_loc(lex->loc);
            return OG_ERROR;
        }
        OG_RETURN_IFERR(pl_copy_name_cs(pl_entity, &col->name, &attr->name, OG_FALSE));
        attr->type = UDT_SCALAR;
        OG_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(field_scalar_info_t), (void **)&attr->scalar_field));
        attr->scalar_field->type_mode = col->typmod;
        attr->default_expr = NULL;
        attr->nullable = OG_FALSE;
        if (attr->scalar_field->type_mode.datatype != OG_TYPE_UNKNOWN) {
            OG_RETURN_IFERR(plc_check_datatype(compiler, &attr->scalar_field->type_mode, OG_FALSE));
        }
    }
    return OG_SUCCESS;
}

static status_t plc_expanse_cursor_defs_core(pl_compiler_t *compiler, plv_decl_t *decl, lex_t *lex)
{
    if (decl->cursor.sql.len != 0) {
        OG_RETURN_IFERR(lex_push(lex, &decl->cursor.sql));
        if (plc_expanse_cursor_def(compiler, decl, NULL, OG_FALSE) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        if (decl->cursor.record != NULL) {
            if (plc_copy_context_rscols(compiler, decl->cursor.ogx->context, decl->cursor.record) != OG_SUCCESS) {
                lex_pop(lex);
                return OG_ERROR;
            }
        }
        lex_pop(lex);
    }
    return OG_SUCCESS;
}


static status_t plc_compile_static_refcur(pl_compiler_t *compiler, bool32 bracketed, sql_text_t *sql, word_t *word,
    plv_decl_t *decl, pl_line_open_t *line)
{
    lex_t *lex = compiler->stmt->session->lex;
    if (bracketed) {
        OG_RETURN_IFERR(lex_push(lex, sql));
        if (plc_expanse_cursor_def(compiler, decl, line, OG_TRUE) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
        OG_RETURN_IFERR(lex_fetch(lex, word));
        if (IS_SPEC_CHAR(word, ';')) {
            return OG_SUCCESS;
        }
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_EXPECTED_FAIL_FMT, "';'", W2S(word));
        return OG_ERROR;
    }

    return plc_expanse_cursor_def(compiler, decl, line, OG_TRUE);
}

static status_t plc_compile_refcur_using(pl_compiler_t *compiler, word_t *word, pl_line_open_t *line)
{
    expr_tree_t *expr = NULL;
    bool32 result = OG_FALSE;
    lex_t *lex = compiler->stmt->session->lex;

    OG_RETURN_IFERR(plc_init_galist(compiler, &line->using_exprs));

    while (OG_TRUE) {
        OG_RETURN_IFERR(lex_try_fetch(lex, "IN", &result));
        // allow 'IN', except 'OUT' OR 'IN OUT'
        OG_RETURN_IFERR(lex_try_fetch(lex, "OUT", &result));
        if (result) {
            OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
                "OUT and IN/OUT modes cannot be opened in refcursor");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &expr, word));
        OG_RETURN_IFERR(plc_verify_expr(compiler, expr));
        OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &expr));
        OG_RETURN_IFERR(cm_galist_insert(line->using_exprs, expr));
        if (word->text.len != 1 || word->text.str[0] != ',') {
            break;
        }
    }

    return OG_SUCCESS;
}

static status_t plc_compile_dynamic_refcur(pl_compiler_t *compiler, word_t *word, pl_line_open_t *line)
{
    OG_RETURN_IFERR(sql_create_expr_until(compiler->stmt, &line->dynamic_sql, word));
    OG_RETURN_IFERR(plc_verify_expr(compiler, line->dynamic_sql));
    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &line->dynamic_sql));

    if (IS_SPEC_CHAR(word, ';')) {
        return OG_SUCCESS;
    }

    if (word->id != KEY_WORD_USING) {
        OG_SRC_THROW_ERROR(line->ctrl.loc, ERR_SQL_SYNTAX_ERROR, "USING expected");
        return OG_ERROR;
    }

    return plc_compile_refcur_using(compiler, word, line);
}

static status_t plc_check_same_cursor_args_name(pl_compiler_t *compiler, galist_t *args)
{
    uint32 i;
    uint32 j;
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    for (i = 0; i < args->count; i++) {
        arg1 = (expr_tree_t *)cm_galist_get(args, i);
        OG_CONTINUE_IFTRUE(arg1->arg_name.len == 0);

        for (j = i + 1; j < args->count; j++) { // not overflow
            arg2 = (expr_tree_t *)cm_galist_get(args, j);
            OG_CONTINUE_IFTRUE(arg2->arg_name.len == 0);

            if (cm_compare_text_ins(&arg1->arg_name, &arg2->arg_name) == 0) {
                OG_SRC_THROW_ERROR(arg1->loc, ERR_PL_DUP_ARG_FMT, T2S(&arg1->arg_name), "cursor");
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

status_t plc_build_open_cursor_args(pl_compiler_t *compiler, word_t *word, galist_t *expr_list)
{
    expr_tree_t *arg_expr = NULL;
    sql_text_t *arg_text = NULL;
    sql_stmt_t *stmt = compiler->stmt;
    lex_t *lex = stmt->session->lex;
    bool32 assign_arg = OG_FALSE;
    text_t arg_name;
    text_t pl_arg_name;

    arg_text = &word->text;
    lex_remove_brackets(arg_text);

    OG_RETURN_IFERR(lex_push(lex, arg_text));
    while (OG_TRUE) {
        arg_name.len = 0;
        if (sql_try_fetch_func_arg(stmt, &arg_name) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (pl_copy_text(compiler->entity, &arg_name, &pl_arg_name) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (arg_name.len == 0 && assign_arg) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "'=>'", "NULL");
            return OG_ERROR;
        }

        PLC_RESET_WORD_LOC(lex, word);
        if (sql_create_expr_until(stmt, &arg_expr, word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        if (plc_verify_expr(compiler, arg_expr) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        if (plc_clone_expr_tree(compiler, &arg_expr) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        if (arg_name.len > 0) {
            assign_arg = OG_TRUE;
            arg_expr->arg_name = pl_arg_name;
        }

        if (cm_galist_insert(expr_list, arg_expr) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (word->type == WORD_TYPE_EOF || word->type == WORD_TYPE_OPERATOR) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR(word->text.loc, ERR_PL_EXPECTED_FAIL_FMT, "','", W2S(word));
            return OG_ERROR;
        }
    }
    lex_pop(lex);

    return plc_check_same_cursor_args_name(compiler, expr_list);
}

/*
 * @brief    implicit cursor's attribiute must equal 'SQL'
 */
static status_t plc_check_cursor_name(pl_compiler_t *compiler, source_location_t loc, text_t *name)
{
    if (cm_text_str_equal_ins(name, "SQL")) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT,
            "Encountered the symbol 'SQL' when expecting one of the following:"
            "<an identifier> <a double-quoted delimited-identifier>");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t plc_compile_cursor_arg(pl_compiler_t *compiler, plv_decl_t *cur, galist_t *decls, word_t *word)
{
    bool32 result = OG_FALSE;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    OG_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = decls->count - 1; // not overflow

    OG_RETURN_IFERR(lex_fetch(lex, word));
    if (!IS_VARIANT(word)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, "VARIANT", W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    OG_RETURN_IFERR(lex_try_fetch(lex, "in", &result));

    decl->drct = PLV_DIR_IN;
    OG_RETURN_IFERR(plc_compile_variant_def(compiler, word, decl, OG_TRUE, decls, OG_TRUE));
    OG_RETURN_IFERR(plc_compile_default_def(compiler, word, decl, OG_TRUE));

    // add args check here to avoid generate error.
    if ((word->type != WORD_TYPE_EOF) && !(IS_SPEC_CHAR(word, ','))) {
        if (word->type == WORD_TYPE_BRACKET) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, ":= or default or another arg or end of args",
                "BRACKET symbol '('");
        } else {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_EXPECTED_FAIL_FMT, ":= or default or another arg or end of args",
                W2S(word));
        }
        return OG_ERROR;
    }

    if ((decl->type & PLV_VAR) == 0) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "cursor arg should be variant.");
        return OG_ERROR;
    }
    // give a tag for cursor arg, actual only PLV_VAR.
    decl->type = PLV_VAR;
    decl->arg_type = PLV_CURSOR_ARG;
    // temp support curr size.
    if (OG_IS_VARLEN_TYPE(decl->variant.type.datatype)) {
        decl->variant.type.size = OG_STRING_BUFFER_SIZE;
    }
    return cm_galist_insert(cur->cursor.ogx->args, decl);
}

static status_t plc_compile_cursor_args(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    cm_trim_text((text_t *)&word->text);
    if (((text_t *)&word->text)->len == 0) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(plc_init_galist(compiler, &decl->cursor.ogx->args));

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    while (OG_TRUE) {
        if (plc_compile_cursor_arg(compiler, decl, decls, word) != OG_SUCCESS) {
            decl->cursor.ogx->is_err = (bool8)OG_TRUE;
            lex_pop(lex);
            return OG_ERROR;
        }
        if ((word->type == WORD_TYPE_EOF) || !(IS_SPEC_CHAR(word, ','))) {
            break;
        }
    }
    lex_pop(lex);

    return OG_SUCCESS;
}

status_t plc_compile_cursor_def(pl_compiler_t *compiler, galist_t *decls, word_t *word)
{
    bool32 result = OG_FALSE;
    plv_decl_t *decl = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;

    OG_RETURN_IFERR(lex_fetch(lex, word));
    OG_RETURN_IFERR(plc_check_cursor_name(compiler, word->loc, (text_t *)&word->text));

    OG_RETURN_IFERR(plc_verify_word_as_var(compiler, word));
    plc_find_decl_ex(compiler, word, PLV_CUR, NULL, &decl);
    if (decl != NULL && decl->cursor.ogx->is_sysref) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "%s is sys_refcursor conflict with cursor def.",
            W2S(word));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_galist_new(decls, sizeof(plv_decl_t), (void **)&decl));
    OG_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ogx));
    OG_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    decl->vid.block = (int16)compiler->stack.depth;
    decl->vid.id = decls->count - 1; // not overflow
    decl->type = PLV_CUR;
    decl->cursor.ogx->is_sysref = (bool8)OG_FALSE;
    decl->loc = word->text.loc;
    decl->cursor.ogx->is_err = (bool8)OG_FALSE;
    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        OG_RETURN_IFERR(plc_compile_cursor_args(compiler, decl, decls, word));
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "RETURN", &result));
    if (result) {
        OG_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT); // don't return OG_ERROR
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "IS", &result));
    if (result) {
        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (!result) {
            decl->cursor.sql = *(lex->curr_text);
        } else {
            decl->cursor.sql = word->text;
        }
        OG_RETURN_IFERR(lex_fetch_to_char(lex, word, ';'));
    } else {
        decl->cursor.sql.value = CM_NULL_TEXT;
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, ";"));
        word->type = WORD_TYPE_PL_TERM;
    }

    return plc_init_galist(compiler, &decl->cursor.input);
}

static status_t plc_compile_for_impcur(pl_compiler_t *compiler, pl_line_for_t *line, word_t *word)
{
    text_t sql;
    plv_decl_t *id = line->id;
    plv_decl_t *imp_cur = NULL;
    source_location_t loc;
    lex_t *lex = compiler->stmt->session->lex;
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;

    sql.str = compiler->convert_buf;
    sql.len = 0;
    OG_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&imp_cur));
    OG_RETURN_IFERR(pl_alloc_mem(entity, sizeof(plv_cursor_context_t), (void **)&imp_cur->cursor.ogx));
    OG_RETURN_IFERR(plc_init_galist(compiler, &imp_cur->cursor.input));
    compiler->current_input = imp_cur->cursor.input;
    imp_cur->vid.block = id->vid.block;
    imp_cur->vid.id = line->decls->count - 1; // not overflow
    imp_cur->type = PLV_IMPCUR;
    line->cursor_id = imp_cur->vid;

    loc = word->loc;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SELECT"));
    OG_RETURN_IFERR(plc_compile_select(compiler, &sql, word, OG_FALSE));

    cm_trim_text(&sql);

    OGSQL_SAVE_STACK(stmt);
    if (pl_compile_parse_sql(stmt, &line->context, &sql, &loc, &entity->sqls) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    if (!line->context->cacheable) {
        // if not cached, need inherit for reparse next time.
        pl_entity_uncacheable(entity);
    }

    /* add referenced object info to entity's ref_list */
    OG_RETURN_IFERR(sql_append_references(&entity->ref_list, line->context));
    OG_RETURN_IFERR(plc_copy_context_rscols(compiler, line->context, line->id->record));
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->into.output));
    OG_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, line->into.output, line->id, UDT_STACK_ADDR));

    line->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    line->into.into_type = (uint8)INTO_AS_REC;
    line->into.is_bulk = OG_FALSE;

    // UNAME.IMPILICT CURSOR.
    imp_cur->cursor.sql.value = CM_NULL_TEXT;
    imp_cur->drct = PLV_DIR_NONE;
    imp_cur->cursor.ogx->context = line->context;
    return OG_SUCCESS;
}

status_t plc_compile_for_cursor(pl_compiler_t *compiler, pl_line_for_t *line, word_t *word)
{
    plv_decl_t *decl = NULL;
    bool32 result = OG_FALSE;
    uint32 save_flags;
    plv_decl_t *id = line->id;
    plv_decl_t *type_record = NULL;
    lex_t *lex = compiler->stmt->session->lex;
    pl_entity_t *pl_entity = compiler->entity;
    id->type = PLV_RECORD;
    OG_RETURN_IFERR(pl_copy_name(pl_entity, (text_t *)&word->text, &id->name));
    /* alloc anonymous record type */
    OG_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&type_record));
    type_record->type = PLV_TYPE;
    type_record->typdef.type = PLV_RECORD;
    type_record->typdef.record.root = type_record;
    type_record->typdef.record.is_anonymous = OG_TRUE;
    id->record = &type_record->typdef.record;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "in"));
    // (1) for variant in (...)
    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        line->is_impcur = OG_TRUE;
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        status_t status = plc_compile_for_impcur(compiler, line, word);
        lex_pop(lex);
        return status;
    }

    // (2) for variant in  Explicit cursor loop
    save_flags = lex->flags;
    lex->flags = LEX_WITH_OWNER;
    OG_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type != WORD_TYPE_PARAM) {
        OG_RETURN_IFERR(plc_find_decl(compiler, word, PLV_CUR, NULL, &decl));
        if (cm_text_equal(&id->name, &decl->name)) {
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_INVALID_LOOP_INDEX, T2S(&line->id->name));
            return OG_ERROR;
        }
    } else {
        OG_SRC_THROW_ERROR(word->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "the declaration of the cursor of this expression is incomplete or malformed");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
    if (result) {
        lex_trim(&word->text);
        if (word->text.len == 0) {
            result = OG_FALSE;
        }
    }

    if (result) {
        OG_RETURN_IFERR(plc_init_galist(compiler, &line->exprs));
        OG_RETURN_IFERR(plc_build_open_cursor_args(compiler, word, line->exprs));
        OG_RETURN_IFERR(plc_verify_cursor_args(compiler, line->exprs, decl->cursor.ogx->args, line->ctrl.loc));
    } else {
        line->exprs = NULL;
    }
    lex->flags = save_flags;

    if (decl->cursor.ogx->is_sysref) {
        OG_SRC_THROW_ERROR(word->loc, ERR_INVALID_CURSOR);
        return OG_ERROR;
    }
    line->is_impcur = OG_FALSE;
    line->cursor_id = decl->vid;

    if (decl->cursor.ogx->context == NULL) {
        OG_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_copy_context_rscols(compiler, decl->cursor.ogx->context, line->id->record));
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->into.output));
    OG_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, line->into.output, id, UDT_STACK_ADDR));

    line->into.prefetch_rows = INTO_COMMON_PREFETCH_COUNT;
    line->into.into_type = (uint8)INTO_AS_REC;
    line->into.is_bulk = OG_FALSE;
    return OG_SUCCESS;
}

status_t plc_compile_refcur(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl, pl_line_open_t *line)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 bracketed = OG_FALSE;
    sql_text_t sql;

    /* open cursor FOR {select_statement | dynamic_string} [USING_CLAUSE]
    hit cursors variables scenario */
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "FOR"));
    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &bracketed));

    if (bracketed) {
        sql = word->text;
        OG_RETURN_IFERR(lex_extract_first(&word->text, word));
    } else {
        OG_RETURN_IFERR(lex_extract_first(lex->curr_text, word));
    }

    if (word->id == KEY_WORD_SELECT) {
        line->is_dynamic_sql = OG_FALSE;
        OG_RETURN_IFERR(plc_init_galist(compiler, &line->input));
        decl->cursor.input = line->input;
        OG_RETURN_IFERR(plc_compile_static_refcur(compiler, bracketed, &sql, word, decl, line));
        decl->cursor.input = NULL;
    } else {
        lex_back(lex, word);
        line->is_dynamic_sql = OG_TRUE;
        OG_RETURN_IFERR(plc_compile_dynamic_refcur(compiler, word, line));
    }

    return OG_SUCCESS;
}

status_t plc_diagnose_for_is_cursor(pl_compiler_t *compiler, bool8 *is_cur)
{
    bool32 result = OG_FALSE;
    word_t word;
    lex_t *lex = compiler->stmt->session->lex;

    LEX_SAVE(lex);
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "in"));
    // (1) for variant in (...)
    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    OG_RETURN_IFERR(lex_fetch(lex, &word));
    if (result) {
        if (word.type == WORD_TYPE_PL_RANGE) {
            result = OG_FALSE;
        }
    }
    if (!result) {
        // (2) for variant in cur loop
        OG_RETURN_IFERR(lex_try_fetch(lex, "loop", &result));
    }
    LEX_RESTORE(lex);

    *is_cur = (bool8)result;
    return OG_SUCCESS;
}

status_t plc_expanse_cursor_defs(pl_compiler_t *compiler, galist_t *decls)
{
    lex_t *lex = compiler->stmt->session->lex;
    plv_decl_t *decl = NULL;
    uint32 i;
    uint32 count = decls->count;
    for (i = 0; i < count; i++) {
        decl = (plv_decl_t *)cm_galist_get(decls, i);
        if (decl->type == PLV_CUR) {
            OG_RETURN_IFERR(plc_expanse_cursor_defs_core(compiler, decl, lex));
        }
    }

    return OG_SUCCESS;
}

status_t plc_verify_cursor_args(pl_compiler_t *compiler, galist_t *expr_list, galist_t *args, source_location_t loc)
{
    if (args == NULL) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "open cursor have no args definition");
        return OG_ERROR;
    }

    if (expr_list->count > args->count) {
        OG_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "open cursor args no match definition");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * @brief    compile sys_refcursor define
 */
status_t plc_compile_syscursor_def(pl_compiler_t *compiler, word_t *word, plv_decl_t *decl)
{
    pl_entity_t *pl_entity = compiler->entity;
    OG_RETURN_IFERR(pl_copy_object_name_ci(pl_entity, word->type, (text_t *)&word->text, &decl->name));
    OG_RETURN_IFERR(pl_alloc_mem(pl_entity, sizeof(plv_cursor_context_t), (void **)&decl->cursor.ogx));
    decl->cursor.ogx->is_sysref = (bool8)OG_TRUE;
    decl->cursor.input = NULL;
    return OG_SUCCESS;
}

status_t plc_compile_type_refcur_def(pl_compiler_t *compiler, plv_decl_t *decl, galist_t *decls, word_t *word)
{
    lex_t *lex = compiler->stmt->session->lex;
    bool32 result = OG_FALSE;
    decl->typdef.type = PLV_CUR;
    OG_RETURN_IFERR(lex_try_fetch(lex, "RETURN", &result));
    if (result) {
        OG_SRC_THROW_ERROR(lex->loc, ERR_PL_UNSUPPORT);
        return OG_ERROR;
    }
    return lex_expected_fetch_word(lex, ";");
}

status_t plc_verify_cursor_setval(pl_compiler_t *compiler, expr_tree_t *expr)
{
    if (expr->root->datatype != OG_TYPE_CURSOR) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return OG_ERROR;
    }
    if (expr->root->type == EXPR_NODE_USER_FUNC) {
        return OG_SUCCESS;
    }
    if (expr->root->type != EXPR_NODE_V_ADDR || compiler->stack.depth == 0) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return OG_ERROR;
    }
    var_address_pair_t *pair = sql_get_last_addr_pair(expr->root);
    if (pair == NULL || pair->type != UDT_STACK_ADDR) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return OG_ERROR;
    }

    plv_decl_t *decl = pair->stack->decl;
    if (decl->cursor.ogx != NULL && (decl->cursor.ogx->is_sysref == OG_FALSE ||
        (decl->cursor.ogx->args != NULL && decl->cursor.ogx->args->count != 0))) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_PL_EXPR_WRONG_TYPE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t plc_verify_using_out_cursor(pl_compiler_t *compiler, expr_tree_t *expr)
{
    expr_node_t *node = expr->root;
    if (node->type == EXPR_NODE_V_ADDR) {
        if (compiler == NULL) {
            return OG_SUCCESS;
        }
        var_address_pair_t *pair = sql_get_last_addr_pair(node);
        if (pair == NULL || pair->type != UDT_STACK_ADDR) {
            return OG_SUCCESS;
        }
        if (pair->stack->decl != NULL && pair->stack->decl->type == PLV_CUR) {
            OG_SRC_THROW_ERROR(expr->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "out param of using clause only support normal variable, not cursor");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}
