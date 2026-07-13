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

#define PLC_TRIG_QUOTE_ESCAPE_LEN 2
#define PLC_TRIG_COMMENT_DELIM_LEN 2

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

static bool32 plc_trigger_ident_start(char c)
{
    unsigned char ch = (unsigned char)c;

    return (bool32)(ch >= 0x80 || CM_IS_LETER(c) || c == '_' || c == '#');
}

static bool32 plc_trigger_ident_char(char c)
{
    return (bool32)(plc_trigger_ident_start(c) || CM_IS_DIGIT(c) || c == '$');
}

static bool32 plc_trigger_has_ident_left(text_t *src, uint32 pos)
{
    return (bool32)(pos > 0 && plc_trigger_ident_char(src->str[pos - 1]));
}

static void plc_trigger_advance_loc(source_location_t *loc, char c)
{
    if (c == '\n') {
        loc->line++;
        loc->column = 1;
        return;
    }
    loc->column++;
}

static void plc_trigger_advance_chars(text_t *src, uint32 *pos, source_location_t *loc, uint32 count)
{
    for (uint32 i = 0; i < count && *pos < src->len; i++) {
        plc_trigger_advance_loc(loc, src->str[(*pos)++]);
    }
}

static source_location_t plc_trigger_range_end_loc(text_t *src, source_location_t loc, uint32 begin, uint32 end)
{
    for (uint32 i = begin; i < end; i++) {
        plc_trigger_advance_loc(&loc, src->str[i]);
    }
    return loc;
}

static bool32 plc_trigger_is_extended_quote(text_t *src, uint32 pos, char quote)
{
    if (quote != '\'' || pos == 0) {
        return OG_FALSE;
    }

    uint32 prefix_pos = pos - 1;
    if (UPPER(src->str[prefix_pos]) != 'E') {
        return OG_FALSE;
    }

    return (bool32)(!plc_trigger_has_ident_left(src, prefix_pos));
}

static uint32 plc_trigger_skip_quoted(text_t *src, uint32 pos, source_location_t *loc, char quote,
    bool32 escape_backslash)
{
    uint32 i = pos;

    plc_trigger_advance_loc(loc, src->str[i++]);
    while (i < src->len) {
        char c = src->str[i++];
        plc_trigger_advance_loc(loc, c);
        if (escape_backslash && c == '\\' && i < src->len) {
            plc_trigger_advance_loc(loc, src->str[i++]);
            continue;
        }
        if (c == quote) {
            if (i < src->len && src->str[i] == quote) {
                plc_trigger_advance_loc(loc, src->str[i++]);
                continue;
            }
            break;
        }
    }
    return i;
}

static bool32 plc_trigger_dolq_left_boundary(text_t *src, uint32 pos)
{
    return (bool32)(pos == 0 || !plc_trigger_ident_char(src->str[pos - 1]));
}

static bool32 plc_trigger_dolq_start(char c)
{
    unsigned char ch = (unsigned char)c;

    return (bool32)(ch >= 0x80 || CM_IS_LETER(c) || c == '_');
}

static bool32 plc_trigger_dolq_char(char c)
{
    return (bool32)(plc_trigger_dolq_start(c) || CM_IS_DIGIT(c));
}

static uint32 plc_trigger_dolq_delim_len(text_t *src, uint32 pos)
{
    uint32 i = pos + 1;

    if (pos >= src->len || src->str[pos] != '$' || i >= src->len ||
        !plc_trigger_dolq_left_boundary(src, pos)) {
        return 0;
    }
    if (src->str[i] == '$') {
        return i - pos + 1;
    }
    if (!plc_trigger_dolq_start(src->str[i])) {
        return 0;
    }
    i++;
    while (i < src->len && plc_trigger_dolq_char(src->str[i])) {
        i++;
    }
    return (i < src->len && src->str[i] == '$') ? (i - pos + 1) : 0;
}

static uint32 plc_trigger_skip_dollar_quote(text_t *src, uint32 pos, source_location_t *loc)
{
    uint32 delim_len = plc_trigger_dolq_delim_len(src, pos);
    uint32 i = pos;

    if (delim_len == 0) {
        return pos;
    }
    while (i < pos + delim_len) {
        plc_trigger_advance_loc(loc, src->str[i++]);
    }
    while (i + delim_len <= src->len) {
        if (memcmp(src->str + i, src->str + pos, delim_len) == 0) {
            uint32 end = i + delim_len;
            while (i < end) {
                plc_trigger_advance_loc(loc, src->str[i++]);
            }
            return i;
        }
        plc_trigger_advance_loc(loc, src->str[i++]);
    }
    while (i < src->len) {
        plc_trigger_advance_loc(loc, src->str[i++]);
    }
    return i;
}

static uint32 plc_trigger_skip_comment(text_t *src, uint32 pos, source_location_t *loc)
{
    uint32 i = pos;
    uint32 depth = 1;

    if (pos + 1 >= src->len) {
        plc_trigger_advance_loc(loc, src->str[i++]);
        return i;
    }

    if (src->str[pos] == '-' && src->str[pos + 1] == '-') {
        while (i < src->len) {
            char c = src->str[i++];
            plc_trigger_advance_loc(loc, c);
            if (c == '\n') {
                break;
            }
        }
        return i;
    }

    plc_trigger_advance_chars(src, &i, loc, PLC_TRIG_COMMENT_DELIM_LEN);
    while (i < src->len && depth > 0) {
        if (i + 1 < src->len && src->str[i] == '/' && src->str[i + 1] == '*') {
            plc_trigger_advance_chars(src, &i, loc, PLC_TRIG_COMMENT_DELIM_LEN);
            depth++;
            continue;
        }

        if (i + 1 < src->len && src->str[i] == '*' && src->str[i + 1] == '/') {
            plc_trigger_advance_chars(src, &i, loc, PLC_TRIG_COMMENT_DELIM_LEN);
            depth--;
            continue;
        }

        plc_trigger_advance_loc(loc, src->str[i++]);
    }
    return i;
}

static bool32 plc_trigger_match_word(text_t *src, uint32 pos, const char *word)
{
    uint32 len = (uint32)strlen(word);
    if (pos + len > src->len) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i < len; i++) {
        if (UPPER(src->str[pos + i]) != UPPER(word[i])) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 plc_trigger_prefix(text_t *src, uint32 pos, word_type_t *type)
{
    if (plc_trigger_match_word(src, pos, ":new.")) {
        *type = WORD_TYPE_PL_NEW_COL;
        return OG_TRUE;
    }

    if (plc_trigger_match_word(src, pos, ":old.")) {
        *type = WORD_TYPE_PL_OLD_COL;
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t plc_trigger_make_quoted_word(text_t *src, uint32 pos, uint32 name_start,
    source_location_t name_loc, word_t *word, uint32 *end_pos)
{
    uint32 i = name_start + 1;
    uint32 quoted_start = name_start;

    word->ex_words[0].type = WORD_TYPE_DQ_STRING;
    word->ex_words[0].text.value.str = src->str + i;
    word->ex_words[0].text.loc = name_loc;
    while (i < src->len) {
        if (src->str[i] != '"') {
            i++;
            continue;
        }

        if (i + 1 < src->len && src->str[i + 1] == '"') {
            i += PLC_TRIG_QUOTE_ESCAPE_LEN;
            continue;
        }

        word->ex_words[0].text.value.len = i - quoted_start - 1;
        i++;
        word->text.len = i - pos;
        *end_pos = i;
        return OG_SUCCESS;
    }
    return OG_ERROR;
}

static status_t plc_trigger_make_word(text_t *src, uint32 pos, source_location_t loc, word_t *word, uint32 *end_pos)
{
    uint32 name_start = pos + PLC_TRIG_NAME_RESERVERD_LEN;
    uint32 i = name_start;
    word_type_t word_type;
    source_location_t name_loc;

    if (!plc_trigger_prefix(src, pos, &word_type) || i >= src->len) {
        return OG_ERROR;
    }
    name_loc = plc_trigger_range_end_loc(src, loc, pos, name_start);

    *word = (word_t){ 0 };
    word->type = word_type;
    word->ori_type = word_type;
    word->loc = loc;
    word->text.str = src->str + pos;
    word->text.len = 0;
    word->text.loc = loc;
    word->ex_count = 1;

    if (src->str[i] == '"') {
        return plc_trigger_make_quoted_word(src, pos, i, name_loc, word, end_pos);
    }

    if (!plc_trigger_ident_start(src->str[i])) {
        return OG_ERROR;
    }

    word->ex_words[0].type = WORD_TYPE_VARIANT;
    word->ex_words[0].text.value.str = src->str + i;
    word->ex_words[0].text.loc = name_loc;
    while (i < src->len && plc_trigger_ident_char(src->str[i])) {
        i++;
    }
    word->ex_words[0].text.value.len = i - name_start;
    word->text.len = i - pos;
    *end_pos = i;
    return OG_SUCCESS;
}

static status_t plc_trigger_concat_range(text_t *dst, uint32 max_len, text_t *src, uint32 begin, uint32 end)
{
    text_t part;

    if (end <= begin) {
        return OG_SUCCESS;
    }
    if (dst->len + end - begin > max_len) {
        OG_THROW_ERROR(ERR_BUFFER_OVERFLOW, dst->len + end - begin, max_len);
        return OG_ERROR;
    }

    part.str = src->str + begin;
    part.len = end - begin;
    cm_concat_text(dst, max_len, &part);
    return OG_SUCCESS;
}

static status_t plc_trigger_concat_decl_name(text_t *dst, uint32 max_len, const text_t *name)
{
    OG_RETURN_IFERR(plc_concat_str(dst, max_len, "\""));
    for (uint32 i = 0; i < name->len; i++) {
        if (name->str[i] == '"') {
            OG_RETURN_IFERR(plc_concat_str(dst, max_len, "\"\""));
        } else {
            if (dst->len + 1 > max_len) {
                OG_THROW_ERROR(ERR_BUFFER_OVERFLOW, dst->len + 1, max_len);
                return OG_ERROR;
            }
            CM_TEXT_APPEND(dst, name->str[i]);
        }
    }
    return plc_concat_str(dst, max_len, "\"");
}

static status_t plc_compile_trigger_variant_name(pl_compiler_t *compiler, text_t *sql, word_t *word)
{
    plv_decl_t *decl = NULL;

    OG_RETURN_IFERR(plc_get_trigger_decl(compiler, 0, word, PLV_VAR, &decl));
    return plc_trigger_concat_decl_name(sql, compiler->convert_buf_size, &decl->name);
}

static status_t plc_rewrite_one_trigger_variant(pl_compiler_t *compiler, text_t *dst, word_t *word,
    plc_trigger_rewrite_mode_t mode)
{
    if (mode == PLC_TRIGGER_REWRITE_AS_PARAM) {
        return plc_compile_trigger_variant(compiler, dst, word);
    }

    return plc_compile_trigger_variant_name(compiler, dst, word);
}

status_t plc_rewrite_trigger_variants(pl_compiler_t *compiler, text_t *src, text_t *rewritten,
    source_location_t loc, plc_trigger_rewrite_mode_t mode)
{
    uint32 pos = 0;
    uint32 segment_start = 0;
    bool32 changed = OG_FALSE;
    source_location_t cur_loc = loc;

    if (compiler == NULL || compiler->type != PL_TRIGGER ||
        (mode == PLC_TRIGGER_REWRITE_AS_PARAM && compiler->current_input == NULL)) {
        *rewritten = *src;
        return OG_SUCCESS;
    }

    rewritten->str = compiler->convert_buf;
    rewritten->len = 0;

    while (pos < src->len) {
        word_t word = { 0 };
        uint32 end_pos = pos;

        if (src->str[pos] == '$') {
            uint32 next_pos = plc_trigger_skip_dollar_quote(src, pos, &cur_loc);
            if (next_pos != pos) {
                pos = next_pos;
                continue;
            }
        }

        if (src->str[pos] == '\'' || src->str[pos] == '"' || src->str[pos] == '`') {
            bool32 escape_backslash = plc_trigger_is_extended_quote(src, pos, src->str[pos]);
            pos = plc_trigger_skip_quoted(src, pos, &cur_loc, src->str[pos], escape_backslash);
            continue;
        }

        if (pos + 1 < src->len &&
            ((src->str[pos] == '-' && src->str[pos + 1] == '-') ||
                (src->str[pos] == '/' && src->str[pos + 1] == '*'))) {
            pos = plc_trigger_skip_comment(src, pos, &cur_loc);
            continue;
        }

        if (plc_trigger_make_word(src, pos, cur_loc, &word, &end_pos) == OG_SUCCESS) {
            OG_RETURN_IFERR(plc_trigger_concat_range(rewritten, compiler->convert_buf_size, src, segment_start, pos));
            OG_RETURN_IFERR(plc_rewrite_one_trigger_variant(compiler, rewritten, &word, mode));
            while (pos < end_pos) {
                plc_trigger_advance_loc(&cur_loc, src->str[pos++]);
            }
            segment_start = end_pos;
            changed = OG_TRUE;
            continue;
        }

        plc_trigger_advance_loc(&cur_loc, src->str[pos++]);
    }

    if (!changed) {
        *rewritten = *src;
        return OG_SUCCESS;
    }

    return plc_trigger_concat_range(rewritten, compiler->convert_buf_size, src, segment_start, src->len);
}
