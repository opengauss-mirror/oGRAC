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
 * trigger_decl_cl.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/parser/trigger_decl_cl.c
 *
 * -------------------------------------------------------------------------
 */
#include "trigger_decl_cl.h"
#include "srv_instance.h"
#include "pl_dc_util.h"
#include "pl_memory.h"
#include "decl_cl.h"
#include "ast_cl.h"
#include "pl_base.h"
#include "pl_udt.h"
#include "base_compiler.h"

status_t plc_verify_trigger_modified_var(pl_compiler_t *compiler, plv_decl_t *decl)
{
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    trig_desc_t *trig_desc = &entity->trigger->desc;

    if (!PLC_IS_TRIGGER_CONTEXT(compiler)) {
        return OG_SUCCESS;
    }

    if (decl->trig_type == PLV_OLD_COL) {
        OG_SRC_THROW_ERROR_EX(decl->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "':old.' can not modified in a row trigger, word = %s", T2S(&decl->name));
        return OG_ERROR;
    }

    if (decl->trig_type == PLV_NEW_COL) {
        if (trig_desc->type != TRIG_BEFORE_EACH_ROW ||
            ((trig_desc->events & TRIG_EVENT_INSERT) == 0 && (trig_desc->events & TRIG_EVENT_UPDATE) == 0)) {
            OG_SRC_THROW_ERROR_EX(decl->loc, ERR_PL_SYNTAX_ERROR_FMT,
                "':new.' can only modified in before insert/update row trigger, word = %s", T2S(&decl->name));
            return OG_ERROR;
        }
        decl->trig_type |= PLV_MODIFIED_NEW_COL; // modified by Owen
    }

    return OG_SUCCESS;
}

static status_t plc_verify_trigger_variant(pl_compiler_t *compiler, word_t *word)
{
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    sql_context_t *sql_context = entity->context;
    trig_desc_t *trig_desc = &entity->trigger->desc;

    if (sql_context->type != OGSQL_TYPE_CREATE_TRIG || (trig_desc->type != TRIG_AFTER_EACH_ROW &&
        trig_desc->type != TRIG_BEFORE_EACH_ROW && trig_desc->type != TRIG_INSTEAD_OF)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "':new.' or ':old.' can only appear in row trigger or instead of trigger.");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

void plc_get_trig_decl_name(pl_compiler_t *compiler, text_t *out, word_t *word, bool32 *is_upper_case)
{
    uint32 pos = 0;
    uint32 begin_cp;
    uint32 end_cp;

    // :new."f1", :old."f1", new will upper to NEW, old will upper to OLD
    for (uint32 i = 0; i < PLC_TRIG_NAME_RESERVERD_LEN; i++) {
        out->str[pos++] = UPPER(word->text.str[i]);
    }

    /* skip quote char */
    if (word->ex_words[0].type == WORD_TYPE_DQ_STRING) {
        begin_cp = PLC_TRIG_NAME_RESERVERD_LEN + 1;
        end_cp = word->text.len - 1;
        *is_upper_case = OG_FALSE;
    } else {
        begin_cp = PLC_TRIG_NAME_RESERVERD_LEN;
        end_cp = word->text.len;
        *is_upper_case = IS_CASE_INSENSITIVE;
    }

    for (uint32 i = begin_cp; i < end_cp; i++) {
        out->str[pos++] = *is_upper_case ? UPPER(word->text.str[i]) : word->text.str[i];
    }
    out->len = pos;
}


status_t plc_add_trigger_decl(pl_compiler_t *compiler, uint32 stack_id, word_t *word, uint32 type,
    plv_decl_t **res_decl)
{
    plv_decl_t *decl = NULL;
    expr_tree_t *expr = NULL;
    knl_column_t *column = NULL;
    plc_block_t *block = &compiler->stack.items[stack_id];
    pl_line_begin_t *line = (pl_line_begin_t *)block->entry;
    text_t col_name;
    knl_dictionary_t dc;
    trig_desc_t *trig_desc = NULL;
    bool8 col_find = OG_FALSE;
    text_t decl_name;
    uint16 col;
    bool32 is_upper_case = OG_TRUE;
    pl_entity_t *pl_entity = (pl_entity_t *)compiler->entity;
    sql_context_t *sql_context = pl_entity->context;

    OG_RETURN_IFERR(plc_verify_trigger_variant(compiler, word));
    if ((type & PLV_VAR) == 0) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "':old/:new' can only used as var in a row trigger, word = %s", W2S(word));
        return OG_ERROR;
    }

    trig_desc = &pl_entity->trigger->desc;
    OG_RETURN_IFERR(pl_alloc_mem(pl_entity, word->text.len, (void **)&decl_name.str));
    plc_get_trig_decl_name(compiler, &decl_name, word, &is_upper_case);

    OG_RETURN_IFERR(
        knl_open_dc_by_id(KNL_SESSION(compiler->stmt), trig_desc->obj_uid, (uint32)trig_desc->base_obj, &dc, OG_FALSE));
    col_name.len = decl_name.len - PLC_TRIG_NAME_RESERVERD_LEN;
    col_name.str = decl_name.str + PLC_TRIG_NAME_RESERVERD_LEN; // not overflow
    col = knl_get_column_id(&dc, &col_name);

    do {
        if (OG_INVALID_ID16 == col) {
            break;
        }
        column = knl_get_column(dc.handle, col);
        if (KNL_COLUMN_INVISIBLE(column)) {
            break;
        }
        col_find = OG_TRUE;
    } while (0);

    dc_close(&dc);
    if (col_find == OG_FALSE && plc_trigger_verify_row_pesudo(&col_name, &col, &decl_name) == OG_FALSE) {
        OG_SRC_THROW_ERROR(word->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(word));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(cm_galist_new(line->decls, sizeof(plv_decl_t), (void **)&decl));
    decl->vid.block = 0;
    decl->vid.id = line->decls->count - 1; // not overflow
    decl->type = PLV_VAR;
    decl->trig_type = ((word->type == WORD_TYPE_PL_NEW_COL) ? PLV_NEW_COL : PLV_OLD_COL);
    decl->name = decl_name;
    decl->loc = word->loc;

    OG_RETURN_IFERR(sql_create_expr(compiler->stmt, &expr));
    OG_RETURN_IFERR(sql_alloc_mem(sql_context, sizeof(expr_node_t), (void **)&expr->root));
    expr->root->owner = expr;
    expr->root->type = (word->type == WORD_TYPE_PL_NEW_COL) ? EXPR_NODE_NEW_COL : EXPR_NODE_OLD_COL;
    expr->root->unary = expr->unary;
    expr->root->loc = word->text.loc;
    expr->root->value.v_col.col = col;
    decl->default_expr = expr;

    if (col_find) {
        expr->root->value.v_col.tab = TRIG_REAL_COLUMN_TABLE;
        expr->root->value.v_col.datatype = column->datatype;
        expr->root->datatype = column->datatype;
        expr->root->size = column->size;
        sql_typmod_from_knl_column(&decl->variant.type, column);
        expr->root->value.v_col.is_array = KNL_COLUMN_IS_ARRAY(column);
        expr->root->value.v_col.is_jsonb = KNL_COLUMN_IS_JSONB(column);
        expr->root->value.v_col.ss_start = OG_INVALID_ID32;
        expr->root->value.v_col.ss_end = OG_INVALID_ID32;
        OG_RETURN_IFERR(plc_check_datatype(compiler, &decl->variant.type, OG_FALSE));
        decl->drct = (word->type == WORD_TYPE_PL_NEW_COL) ? PLV_DIR_INOUT : PLV_DIR_IN;
    } else {
        expr->root->value.v_col.tab = TRIG_PSEUDO_COLUMN_TALBE;
        decl->drct = PLV_DIR_IN;
        if (col == TRIG_RES_WORD_ROWID) {
            expr->root->value.v_col.datatype = OG_TYPE_STRING;
            decl->variant.type.datatype = OG_TYPE_STRING;
            decl->variant.type.size = OG_MAX_ROWID_BUFLEN;
            expr->root->size = OG_MAX_ROWID_BUFLEN;
        } else {
            expr->root->value.v_col.datatype = OG_TYPE_BIGINT;
            decl->variant.type.datatype = OG_TYPE_BIGINT;
        }
    }

    OG_RETURN_IFERR(plc_clone_expr_tree(compiler, &decl->default_expr));
    *res_decl = decl;
    return OG_SUCCESS;
}

status_t plc_init_trigger_decls(pl_compiler_t *compiler)
{
    // new or old column, for example, ":new.f1"
    text_t block_name;
    pl_line_begin_t *line = NULL;

    block_name.len = 0;

    OG_RETURN_IFERR(plc_alloc_line(compiler, sizeof(pl_line_begin_t), LINE_BEGIN, (pl_line_ctrl_t **)&line));
    OG_RETURN_IFERR(plc_push(compiler, (pl_line_ctrl_t *)line, &block_name));
    OG_RETURN_IFERR(plc_init_galist(compiler, &line->decls));
    compiler->body = line;

    return OG_SUCCESS;
}

status_t plc_add_modified_new_cols(pl_compiler_t *compiler)
{
    galist_t *trig_decls = compiler->body->decls;
    galist_t *modified_new_cols = NULL;
    plv_decl_t *decl = NULL;
    uint32 i;
    uint32 j;
    uint16 col_id;
    pl_entity_t *entity = (pl_entity_t *)compiler->entity;
    trig_desc_t *trig = &entity->trigger->desc;
    bool32 has_new_modify = OG_FALSE;

    for (i = 0; i < trig_decls->count; ++i) {
        decl = (plv_decl_t *)cm_galist_get(trig_decls, i);
        if (decl->trig_type & PLV_MODIFIED_NEW_COL) {
            has_new_modify = OG_TRUE;
            break;
        }
    }

    if (!has_new_modify) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(plc_init_galist(compiler, &entity->trigger->modified_new_cols));
    modified_new_cols = entity->trigger->modified_new_cols;
    for (j = 0; j < trig->col_count; ++j) {
        OG_RETURN_IFERR(cm_galist_insert(modified_new_cols, NULL));
    }

    for (i = 0; i < trig_decls->count; ++i) {
        decl = (plv_decl_t *)cm_galist_get(trig_decls, i);
        if ((decl->trig_type & PLV_MODIFIED_NEW_COL) == 0) {
            continue;
        }
        col_id = decl->default_expr->root->value.v_col.col;
        cm_galist_set(modified_new_cols, col_id, decl);
    }
    return OG_SUCCESS;
}

static status_t plc_get_trigger_decl(pl_compiler_t *compiler, uint32 stack_id, word_t *word, uint32 types,
    plv_decl_t **res_decl)
{
    plc_block_t *block = &compiler->stack.items[stack_id];
    plc_variant_name_t var;
    var.block_name = block->name;
    var.name = word->text.value;
    var.case_sensitive = OG_FALSE;

    plc_find_in_begin_block(compiler, stack_id, &var, types, res_decl);
    if (*res_decl != NULL) {
        return OG_SUCCESS;
    }

    return plc_add_trigger_decl(compiler, stack_id, word, types, res_decl);
}

status_t plc_compile_trigger_variant(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    plv_decl_t *decl = NULL;
    char param[OG_NAME_BUFFER_SIZE] = { 0 };
    text_t name = {
        .str = NULL,
        .len = 0
    };

    OG_RETURN_IFERR(plc_get_trigger_decl(compiler, 0, word, PLV_VAR, &decl));

    // here only allow trigger-variant, so it must be a single vid
    OG_RETURN_IFERR(udt_build_list_address_single(compiler->stmt, compiler->current_input, decl, UDT_STACK_ADDR));
    OG_RETURN_IFERR(plc_make_input_name(compiler->current_input, param, OG_NAME_BUFFER_SIZE, &name));
    cm_concat_text(sql, compiler->convert_buf_size, &name);
    return OG_SUCCESS;
}
