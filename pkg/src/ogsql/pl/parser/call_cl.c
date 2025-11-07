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
 * call_cl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/call_cl.c
 *
 * -------------------------------------------------------------------------
 */

#include "call_cl.h"
#include "base_compiler.h"
#include "pl_dc.h"
#include "pl_common.h"
#include "func_mgr.h"
#include "ast_cl.h"
#include "ogsql_privilege.h"

static status_t plc_check_is_proc(expr_node_t *node)
{
    if (node->type == EXPR_NODE_V_METHOD) {
        uint16 option = g_coll_methods[0][node->value.v_method.id].option;
        if (option == AS_FUNC) {
            OG_SRC_THROW_ERROR_EX(node->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s method is not allowed here.",
                GET_COLL_METHOD_DESC(node->value.v_method.id));
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (node->type != EXPR_NODE_PROC && node->type != EXPR_NODE_USER_PROC) {
        OG_SRC_THROW_ERROR(node->loc, ERR_PL_SYNTAX_ERROR_FMT, "an undefined procedure was called");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t plc_compile_call(pl_compiler_t *compiler, expr_node_t *expr, pl_line_normal_t *line)
{
    uint32 excl_flags;
    line->ctrl.type = LINE_PROC;
    line->proc = expr;

    excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_JOIN | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT |
        SQL_EXCL_SUBSELECT | SQL_EXCL_COLUMN | SQL_EXCL_ROWSCN | SQL_EXCL_ROWNODEID;
    OG_RETURN_IFERR(plc_verify_expr_node(compiler, line->proc, (void *)line, excl_flags));
    return plc_check_is_proc(line->proc);
}

static status_t plc_language_verify_args(galist_t *decls)
{
    plv_decl_t *decl = NULL;

    for (uint32 i = 0; i < decls->count; i++) {
        decl = (plv_decl_t *)cm_galist_get(decls, i);
        if (decl->type != PLV_VAR) {
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "language c only support scalar datatype argument");
            return OG_ERROR;
        }
        typmode_t type = decl->variant.type;

        switch (type.datatype) {
            case OG_TYPE_BOOLEAN:
            case OG_TYPE_SMALLINT:
            case OG_TYPE_USMALLINT:
            case OG_TYPE_INTEGER:
            case OG_TYPE_UINT32:
            case OG_TYPE_UINT64:
            case OG_TYPE_BIGINT:
            case OG_TYPE_FLOAT:
            case OG_TYPE_REAL:
            case OG_TYPE_BINARY:
            case OG_TYPE_VARBINARY:
            case OG_TYPE_RAW:
            case OG_TYPE_VARCHAR:
            case OG_TYPE_CHAR:
                break;
            default:
                OG_SET_ERROR_MISMATCH_EX(type.datatype);
                return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t pl_convert_object_name(sql_stmt_t *stmt, pl_entity_t *entity, word_t *word, pl_line_begin_t *begin_line)
{
    if (word->ex_count == 1) {
        if (pl_copy_prefix_tenant(stmt, (text_t *)&word->text, &begin_line->lib_user, pl_copy_name) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (pl_copy_object_name(entity, word->ex_words[0].type, (text_t *)&word->ex_words[0].text,
            &begin_line->lib_name) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else if (word->ex_count == 0) {
        text_t user;

        cm_str2text(stmt->session->curr_schema, &user);
        pl_copy_text(entity, &user, &begin_line->lib_user);
        if (pl_copy_object_name(entity, word->type, (text_t *)&word->text, &begin_line->lib_name) != OG_SUCCESS) {
            return OG_ERROR;
        }
    } else {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid name");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t plc_compile_language_prepare(pl_compiler_t *compiler, function_t *func, pl_line_begin_t *begin_line)
{
    sql_stmt_t *stmt = compiler->stmt;
    pl_entity_t *entity = compiler->entity;
    lex_t *lex = compiler->stmt->session->lex;
    uint32 save_flags = lex->flags;
    uint32 matched_id;
    word_t word;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "c"));
    OG_RETURN_IFERR(lex_expected_fetch_1of2(lex, "name", "library", &matched_id));

    lex->flags = LEX_WITH_OWNER;
    if (matched_id == 0) {
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
        OG_RETURN_IFERR(pl_copy_object_name_ci(entity, word.type, (text_t *)&word.text, &begin_line->func));
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "library"));
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
        OG_RETURN_IFERR(pl_convert_object_name(stmt, entity, &word, begin_line));
    } else {
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
        OG_RETURN_IFERR(pl_convert_object_name(stmt, entity, &word, begin_line));
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "name"));
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
        OG_RETURN_IFERR(pl_copy_object_name_ci(entity, word.type, (text_t *)&word.text, &begin_line->func));
    }
    lex->flags = save_flags;
    func->desc.lang_type = LANG_C;

    return OG_SUCCESS;
}

status_t plc_compile_language(pl_compiler_t *compiler, function_t *func)
{
    galist_t *decls = func->desc.params;
    pl_entity_t *entity = compiler->entity;
    sql_stmt_t *stmt = compiler->stmt;
    pl_line_begin_t *begin_line = NULL;
    uint32 param_count = (entity->pl_type == PL_PROCEDURE) ? decls->count : (decls->count - 1);
    if (param_count > FUNC_MAX_ARGS) {
        OG_THROW_ERROR(ERR_TOO_MANY_OBJECTS, param_count, "C-LANG function params count(100)");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_begin_t), LINE_BEGIN, (pl_line_ctrl_t **)&begin_line));
    func->body = (void *)begin_line;
    OG_RETURN_IFERR(plc_compile_language_prepare(compiler, func, begin_line));

    bool32 exists = OG_FALSE;
    uint32 uid = 0;
    text_t curr_user;

    if (!knl_get_user_id(KNL_SESSION(stmt), &begin_line->lib_user, &uid)) {
        OG_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&begin_line->lib_user));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(pl_find_library(KNL_SESSION(stmt), uid, &begin_line->lib_name, NULL, &exists));
    if (!exists) {
        OG_SRC_THROW_ERROR(compiler->line_loc, ERR_LIBRARY_NOT_EXIST, T2S(&begin_line->lib_user),
            T2S_EX(&begin_line->lib_name));
        return OG_ERROR;
    }

    if (stmt->session->switched_schema) {
        cm_str2text(stmt->session->curr_schema, &curr_user);
    } else {
        curr_user = stmt->session->curr_user;
    }

    OG_RETURN_IFERR(sql_check_library_priv_core(stmt, &begin_line->lib_user, &begin_line->lib_name, &curr_user));
    OG_RETURN_IFERR(plc_language_verify_args(decls));

    return OG_SUCCESS;
}
