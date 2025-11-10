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
 * ddl_constraint_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_constraint_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_constraint_parser.h"
#include "srv_instance.h"
#include "ogsql_serial.h"
#include "ddl_index_parser.h"
#include "ddl_column_parser.h"
#include "ddl_parser_common.h"
#include "cond_parser.h"

/*
 * a recursive process which will stop when encountering the first non-constraint-state word.
 * the so-called constraint-state word(s) are:
 * "USING INDEX", "ENABLE", "DISABLE", "DEFERRABLE", "NOT DEFERRABLE", "INITIALLY IMMEDIATE", "INITIALLY DEFERRED",
 * "RELY", "NORELY", "VALIDATE", "NOVALIDATE"
 * use a recursive calling because multiple constraint-state word(s) can be specified in one constraint_state clause.
 */
static status_t sql_parse_constraint_state(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def, word_t
    *next_word)
{
    knl_constraint_state_t *cons_state = NULL;
    word_t word;
    uint32 hit_index = OG_INVALID_ID32;
    CM_POINTER3(stmt, lex, cons_def);

    cons_state = &cons_def->cons_state;

    OG_RETURN_IFERR(lex_fetch(lex, &word));
    switch (word.id) {
        case KEY_WORD_USING:
            OG_RETURN_IFERR(lex_expected_fetch_word(lex, "index"));
            OG_RETURN_IFERR(sql_parse_using_index(stmt, lex, cons_def));
            if ((cons_def->type != CONS_TYPE_PRIMARY) && (cons_def->type != CONS_TYPE_UNIQUE)) {
                OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR,
                    "\"USING INDEX\" cannot be specified in a constraint clause other than primary "
                    "key constraint and unique constraint.");
                return OG_ERROR;
            }
            cons_state->is_use_index = OG_TRUE;
            break;
        case KEY_WORD_ENABLE:
            cons_state->is_enable = OG_TRUE;
            break;
        case KEY_WORD_DISABLE:
            cons_state->is_enable = OG_FALSE;
            break;
        case KEY_WORD_NOT:
            OG_RETURN_IFERR(lex_expected_fetch_word(lex, "deferrable"));
            cons_state->deferrable_ops = STATE_NOT_DEFERRABLE;
            break;
        case KEY_WORD_DEFERRABLE:
            cons_state->deferrable_ops = STATE_DEFERRABLE;
            break;
        case KEY_WORD_INITIALLY:
            OG_RETURN_IFERR(lex_expected_fetch_1of2(lex, "immediate", "deferred", &hit_index));
            if (hit_index == 0) {
                cons_state->initially_ops = STATE_INITIALLY_IMMEDIATE;
            } else {
                cons_state->initially_ops = STATE_INITIALLY_DEFERRED;
            }
            break;
        case KEY_WORD_RELY:
            cons_state->rely_ops = STATE_RELY;
            break;
        case KEY_WORD_NO_RELY:
            cons_state->rely_ops = STATE_NO_RELY;
            break;
        case KEY_WORD_VALIDATE:
            cons_state->is_validate = OG_TRUE;
            break;
        case KEY_WORD_NO_VALIDATE:
            cons_state->is_validate = OG_FALSE;
            break;
        case KEY_WORD_PARALLEL:
            if ((cons_def->type != CONS_TYPE_PRIMARY) && (cons_def->type != CONS_TYPE_UNIQUE)) {
                OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR,
                    "\"PARALLEL\" cannot be specified in a constraint clause other than primary "
                    "key constraint and unique constraint.");
                return OG_ERROR;
            }
            OG_RETURN_IFERR(sql_parse_parallelism(lex, &word, &cons_def->index.parallelism, OG_MAX_INDEX_PARALLELISM));
            break;
        case KEY_WORD_REVERSE:
            if ((cons_def->type != CONS_TYPE_PRIMARY) && (cons_def->type != CONS_TYPE_UNIQUE)) {
                OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR,
                    "\"REVERSE\" cannot be specified in a constraint clause other than primary "
                    "key constraint and unique constraint.");
                return OG_ERROR;
            }

            OG_RETURN_IFERR(sql_parse_reverse(&word, &cons_def->index.is_reverse));
            break;

        default:
            /* unrecognized word, stop the recurse and take the word out */
            *next_word = word;
            return OG_SUCCESS;
    }

    /* call sql_parse_constraint_state() itself recursivly in order to handle multiple constraint state properties */
    OG_RETURN_IFERR(sql_parse_constraint_state(stmt, lex, cons_def, &word));
    *next_word = word;
    return OG_SUCCESS;
}

status_t sql_parse_foreign_key(sql_stmt_t *stmt, lex_t *lex, knl_constraint_def_t *cons_def)
{
    knl_reference_def_t *ref = NULL;

    cons_def->type = CONS_TYPE_REFERENCE;

    if (lex_expected_fetch_word(lex, "KEY") != OG_SUCCESS) {
        return OG_ERROR;
    }

    ref = &cons_def->ref;
    if (sql_parse_column_list(stmt, lex, &cons_def->columns, OG_FALSE, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "REFERENCES") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_references_clause(stmt, lex, &ref->ref_user, &ref->ref_table, &ref->refactor, &ref->ref_columns) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cons_def->columns.count != ref->ref_columns.count) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of referencing columns must match referenced columns.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_primary_unique_cons(sql_stmt_t *stmt, lex_t *lex, constraint_type_t type,
                                       knl_constraint_def_t *cons_def)
{
    word_t word;

    cons_def->type = type;
    cons_def->index.cr_mode = OG_INVALID_ID8;
    cons_def->index.pctfree = OG_INVALID_ID32;

    if (type == CONS_TYPE_PRIMARY) {
        if (lex_expected_fetch_word(lex, "KEY") != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (sql_parse_column_list(stmt, lex, &cons_def->columns, OG_FALSE, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_parse_constraint_state(stmt, lex, cons_def, &word));
    if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
        if (!IS_USEINDEX_FLAG_SPECIFIED(cons_def)) {
            if (type == CONS_TYPE_PRIMARY) {
                cons_def->index.primary = OG_TRUE;
            } else {
                cons_def->index.unique = OG_TRUE;
            }
        }

        lex_back(lex, &word);
        return OG_SUCCESS;
    }

    OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
    return OG_ERROR;
}

static status_t sql_fetch_column_in_expr(visit_assist_t *va, expr_node_t **node)
{
    if ((*node)->type != EXPR_NODE_COLUMN && (*node)->type != EXPR_NODE_DIRECT_COLUMN) {
        return OG_SUCCESS;
    }

    sql_walker_t *walker = (sql_walker_t *)va->param0;
    text_t *new_col = NULL;
    text_t *col = NULL;

    for (uint32 i = 0; i < walker->columns->count; i++) {
        col = (text_t *)cm_galist_get(walker->columns, i);
        if (!cm_compare_text(col, &(*node)->word.column.name.value)) {
            return OG_SUCCESS;
        }
    }

    OG_RETURN_IFERR(cm_galist_new(walker->columns, sizeof(text_t), (void **)&new_col));
    *new_col = (*node)->word.column.name.value;

    return OG_SUCCESS;
}

static status_t sql_verify_outline_check(sql_stmt_t *stmt, knl_table_def_t *verf_data, knl_constraint_def_t *cons_def,
    cond_tree_t *cond)
{
    text_t save_check_text;
    knl_check_def_t *check = &cons_def->check;
    sql_verifier_t verf = { 0 };
    sql_walker_t walker = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.is_check_cons = OG_TRUE;
    verf.table_def = verf_data;
    verf.create_table_define = OG_TRUE;

    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_BIND_PARAM | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_SEQUENCE | SQL_EXCL_CASE |
        SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    if (sql_verify_cond(&verf, cond) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (check->text.len > OG_MAX_CHECK_VALUE_LEN) {
        OG_SRC_THROW_ERROR_EX(cond->loc, ERR_SQL_SYNTAX_ERROR, "length of CHECK's value exceed maximum: %d",
            OG_MAX_CHECK_VALUE_LEN);
        return OG_ERROR;
    }

    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);
    walker.context = stmt->context;
    walker.stmt = stmt;
    walker.columns = &cons_def->columns;
    visit_assist_t v_ast = { 0 };
    sql_init_visit_assist(&v_ast, stmt, NULL);
    v_ast.param0 = (void*) &walker;
    OG_RETURN_IFERR(visit_cond_node(&v_ast, cond->root, sql_fetch_column_in_expr));
    save_check_text = check->text;
    return sql_copy_text(stmt->context, &save_check_text, &check->text);
}

static status_t sql_verify_inline_check(sql_stmt_t *stmt, knl_column_def_t *def, cond_tree_t *cond)
{
    text_t save_check_text;
    sql_verifier_t verf = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.table_def = (knl_table_def_t *)def->table;
    verf.column = def;
    verf.is_check_cons = OG_TRUE;
    verf.create_table_define = OG_TRUE;

    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_PRIOR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_BIND_PARAM | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_LOB_COL | SQL_EXCL_SEQUENCE | SQL_EXCL_CASE |
        SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    if (sql_verify_cond(&verf, cond) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (def->check_text.len > OG_MAX_CHECK_VALUE_LEN) {
        OG_SRC_THROW_ERROR_EX(cond->loc, ERR_SQL_SYNTAX_ERROR, "length of CHECK's value exceed maximum: %d",
            OG_MAX_CHECK_VALUE_LEN);
        return OG_ERROR;
    }
    save_check_text = def->check_text;

    return sql_copy_text(stmt->context, &save_check_text, &def->check_text);
}

status_t sql_parse_add_check(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def, knl_constraint_def_t *cons_def)
{
    word_t word;
    status_t status;
    cond_tree_t *cond = NULL;

    cons_def->type = CONS_TYPE_CHECK;
    status = lex_expected_fetch_bracket(lex, &word);
    OG_RETURN_IFERR(status);
    OG_RETURN_IFERR(lex_push(lex, &word.text));

    cons_def->check.text = word.text.value;
    cm_trim_text(&cons_def->check.text);
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    stmt->is_check = OG_TRUE;
    status = sql_create_cond_until(stmt, &cond, &word);
    stmt->is_check = OG_FALSE;
    lex_pop(lex);
    OG_RETURN_IFERR(status);

    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "expected end but \"%s\" found", W2S(&word));
        return OG_ERROR;
    }

    cons_def->check.cond = cond;

    return sql_verify_outline_check(stmt, NULL, cons_def, cond);
}


status_t sql_parse_constraint(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    status_t status;
    uint32 save_flags;
    knl_constraint_def_t *cons_def = &def->cons_def.new_cons;
    if (def->action == ALTABLE_ADD_CONSTRAINT) {
        OG_RETURN_IFERR(sql_try_parse_if_not_exists(lex, &def->options));
    }
    save_flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    status = lex_expected_fetch_variant(lex, &word);
    lex->flags = save_flags;
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &cons_def->name));

    cons_def->cons_state.is_anonymous = OG_FALSE;

    OG_RETURN_IFERR(lex_expected_fetch(lex, &word));

    switch ((key_wid_t)word.id) {
        case KEY_WORD_PRIMARY:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, cons_def);
            break;
        case KEY_WORD_FOREIGN:
            status = sql_parse_foreign_key(stmt, lex, cons_def);
            break;
        case KEY_WORD_CHECK:
            status = sql_parse_add_check(stmt, lex, def, cons_def);
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, cons_def);
            break;
        default:
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            status = OG_ERROR;
            break;
    }

    return status;
}

static status_t sql_append_inline_checks_column(sql_stmt_t *stmt, knl_constraint_def_t *cons_def,
    const knl_column_def_t *column)
{
    text_t *col = NULL;

    if (!CM_IS_EMPTY(&column->inl_chk_cons_name)) {
        cons_def->cons_state.is_anonymous = OG_FALSE;
        cons_def->name = column->inl_chk_cons_name;
    }

    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);
    if (cm_galist_new(&cons_def->columns, sizeof(text_t), (pointer_t *)&col) != OG_SUCCESS) {
        return OG_ERROR;
    }
    *col = column->name;
    cons_def->check.text = column->check_text;
    cons_def->check.cond = column->check_cond;
    return OG_SUCCESS;
}

static status_t sql_alloc_inline_cons(sql_stmt_t *stmt, constraint_type_t type, galist_t *constraints,
    knl_constraint_def_t **cons_def)
{
    if (cm_galist_new(constraints, sizeof(knl_constraint_def_t), (pointer_t *)cons_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*cons_def)->type = type;

    if (sql_alloc_mem(stmt->context, OG_NAME_BUFFER_SIZE, (pointer_t *)&(*cons_def)->name.str) != OG_SUCCESS) {
        return OG_ERROR;
    }

    knl_get_system_name(&stmt->session->knl_session, type, (*cons_def)->name.str, OG_NAME_BUFFER_SIZE);
    (*cons_def)->name.len = (uint32)strlen((*cons_def)->name.str);
    (*cons_def)->cons_state.is_anonymous = OG_TRUE;
    (*cons_def)->cons_state.is_enable = OG_TRUE;
    (*cons_def)->cons_state.is_validate = OG_TRUE;
    (*cons_def)->cons_state.is_cascade = OG_TRUE;
    return OG_SUCCESS;
}

static status_t sql_create_inline_checks(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;
    knl_constraint_def_t *cons_def = NULL;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if (!column->is_check) {
            continue;
        }

        if (sql_alloc_inline_cons(stmt, CONS_TYPE_CHECK, &def->constraints, &cons_def) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (sql_append_inline_checks_column(stmt, cons_def, column) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_append_inline_ref_column(sql_stmt_t *stmt, knl_table_def_t *def, const knl_column_def_t *column)
{
    knl_constraint_def_t *cons_def = NULL;
    text_t *name = NULL;

    if (sql_alloc_inline_cons(stmt, CONS_TYPE_REFERENCE, &def->constraints, &cons_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!CM_IS_EMPTY(&column->inl_ref_cons_name)) {
        cons_def->name = column->inl_ref_cons_name;
        cons_def->cons_state.is_anonymous = OG_FALSE;
    }
    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);

    cons_def->ref.ref_user = column->ref_user;
    cons_def->ref.ref_table = column->ref_table;

    if (cm_galist_new(&cons_def->columns, sizeof(text_t), (pointer_t *)&name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    *name = column->name;
    cons_def->ref.ref_columns = column->ref_columns;
    cons_def->ref.refactor = column->refactor;
    return OG_SUCCESS;
}

static status_t sql_create_inline_refs(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if (!column->is_ref) {
            continue;
        }

        if (column->typmod.is_array == OG_TRUE) {
            OG_THROW_ERROR(ERR_REF_ON_ARRAY_COLUMN);
            return OG_ERROR;
        }

        if (sql_append_inline_ref_column(stmt, def, column) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}
static status_t sql_create_inline_cons_index(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 i;
    knl_column_def_t *column = NULL;
    knl_constraint_def_t *cons_def = NULL;
    knl_index_col_def_t *index_column = NULL;
    constraint_type_t type;

    for (i = 0; i < def->columns.count; i++) {
        column = cm_galist_get(&def->columns, i);
        if ((!column->primary) && (!column->unique)) {
            continue;
        }

        if (column->typmod.is_array == OG_TRUE) {
            OG_THROW_ERROR(ERR_INDEX_ON_ARRAY_FIELD, T2S(&column->name));
            return OG_ERROR;
        }

        type = column->primary ? CONS_TYPE_PRIMARY : CONS_TYPE_UNIQUE;
        if (sql_alloc_inline_cons(stmt, type, &def->constraints, &cons_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (type == CONS_TYPE_PRIMARY) {
            if (!CM_IS_EMPTY(&column->inl_pri_cons_name)) {
                cons_def->name = column->inl_pri_cons_name;
                cons_def->cons_state.is_anonymous = OG_FALSE;
            }
        } else {
            if (!CM_IS_EMPTY(&column->inl_uq_cons_name)) {
                cons_def->name = column->inl_uq_cons_name;
                cons_def->cons_state.is_anonymous = OG_FALSE;
            }
        }
        cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);

        if (cm_galist_new(&cons_def->columns, sizeof(knl_index_col_def_t), (pointer_t *)&index_column) != OG_SUCCESS) {
            return OG_ERROR;
        }

        index_column->name = column->name;
        index_column->mode = SORT_MODE_ASC;
        cons_def->index.primary = (type == CONS_TYPE_PRIMARY);
        cons_def->index.unique = (type == CONS_TYPE_UNIQUE);
        cons_def->index.cr_mode = OG_INVALID_ID8;
        cons_def->index.pctfree = OG_INVALID_ID32;
    }

    return OG_SUCCESS;
}

status_t sql_create_inline_cons(sql_stmt_t *stmt, knl_table_def_t *def)
{
    if (def->pk_inline || def->uq_inline) {
        if (sql_create_inline_cons_index(stmt, def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (def->rf_inline) {
        if (sql_create_inline_refs(stmt, def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (def->chk_inline) {
        if (sql_create_inline_checks(stmt, def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}


static status_t sql_parse_check_outline_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def,
    knl_constraint_def_t *cons_def)
{
    status_t status;
    word_t word;
    cond_tree_t *cond = NULL;

    if (cons_def == NULL) {
        status = sql_alloc_inline_cons(stmt, CONS_TYPE_CHECK, &def->constraints, &cons_def);
        OG_RETURN_IFERR(status);
    }
    cons_def->type = CONS_TYPE_CHECK;
    status = lex_expected_fetch_bracket(lex, &word);
    OG_RETURN_IFERR(status);

    OG_RETURN_IFERR(lex_push(lex, &word.text));

    cons_def->check.text = lex->curr_text->value;
    cm_trim_text(&cons_def->check.text);
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    stmt->is_check = OG_TRUE;
    status = sql_create_cond_until(stmt, &cond, &word);
    stmt->is_check = OG_FALSE;
    lex_pop(lex);
    OG_RETURN_IFERR(status);

    lex->flags = LEX_SINGLE_WORD;
    if (word.type != WORD_TYPE_EOF) {
        return OG_ERROR;
    }

    cons_def->check.cond = cond;
    return OG_SUCCESS;
}

static status_t sql_try_parse_constraint(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *result)
{
    word_t word;
    status_t status;
    knl_constraint_def_t *cons_def = NULL;

    status = lex_try_fetch_variant_excl(lex, &word, WORD_TYPE_DATATYPE, result);
    OG_RETURN_IFERR(status);

    if (*result == OG_FALSE) {
        return OG_SUCCESS;
    }

    status = cm_galist_new(&def->constraints, sizeof(knl_constraint_def_t), (pointer_t *)&cons_def);
    OG_RETURN_IFERR(status);
    cons_def->cons_state.is_enable = OG_TRUE;
    cons_def->cons_state.is_validate = OG_TRUE;
    cons_def->cons_state.is_cascade = OG_TRUE;
    status = sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &cons_def->name);
    OG_RETURN_IFERR(status);

    status = lex_expected_fetch(lex, &word);
    OG_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_PRIMARY:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, cons_def);
            break;
        case KEY_WORD_FOREIGN:
            status = sql_parse_foreign_key(stmt, lex, cons_def);
            break;
        case KEY_WORD_CHECK:
            status = sql_parse_check_outline_cons(stmt, lex, def, cons_def);
            break;
        case KEY_WORD_UNIQUE:
            status = sql_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, cons_def);
            break;
        default:
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(&word));
            status = OG_ERROR;
            break;
    }
    return status;
}

status_t sql_parse_auto_primary_key_constr_name(sql_stmt_t *stmt, text_t *constr_name, text_t *sch_name,
    text_t *tab_name)
{
    text_t md5_text;
    uint32 len;
    uint32 max_len;
    char name[DDL_MAX_CONSTR_NAME_LEN + 1] = { 0 };
    char md5_name[OG_MD5_SIZE + 1] = { 0 };
    uchar digest[OG_MD5_HASH_SIZE] = { 0 };
    binary_t bin = {
        .bytes = digest,
        .size = OG_MD5_HASH_SIZE
    };

    len = 0;
    max_len = DDL_MAX_CONSTR_NAME_LEN + 1;
    MEMS_RETURN_IFERR(strncpy_s(name, max_len, sch_name->str, sch_name->len));
    len += sch_name->len;
    MEMS_RETURN_IFERR(strncpy_s(name + len, max_len - len, tab_name->str, tab_name->len));
    len += tab_name->len;
    cm_calc_md5((const uchar *)&name, len, (uchar *)digest, &bin.size);

    md5_text.str = md5_name;
    md5_text.len = (uint32)sizeof(md5_name);

    if (cm_bin2text(&bin, OG_FALSE, &md5_text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(constr_name->str, OG_MAX_NAME_LEN, OG_MAX_NAME_LEN - 1, "_PK_SYS_"));
    MEMS_RETURN_IFERR(
        strncat_s(constr_name->str, OG_MAX_NAME_LEN - strlen(constr_name->str), md5_text.str, md5_text.len));
    constr_name->len = (uint32)strlen(constr_name->str);

    return OG_SUCCESS;
}


static status_t sql_try_parse_primary_unique_cons(sql_stmt_t *stmt, lex_t *lex, constraint_type_t type,
    knl_table_def_t *def, bool32 *result)
{
    status_t status;
    word_t word;
    knl_constraint_def_t *cons_def = NULL;

    if (type == CONS_TYPE_PRIMARY) {
        status = lex_try_fetch(lex, "KEY", result);
        OG_RETURN_IFERR(status);
        if (*result == OG_FALSE) {
            return OG_SUCCESS;
        }
        status = sql_alloc_inline_cons(stmt, type, &def->constraints, &cons_def);
        OG_RETURN_IFERR(status);
        cons_def->index.primary = OG_TRUE;
        cons_def->index.cr_mode = OG_INVALID_ID8;
        cons_def->index.pctfree = OG_INVALID_ID32;

        status = sql_parse_column_list(stmt, lex, &cons_def->columns, OG_FALSE, NULL);
        OG_RETURN_IFERR(status);
    } else {
        LEX_SAVE(lex);
        status = lex_try_fetch_bracket(lex, &word, result);
        OG_RETURN_IFERR(status);
        if (*result == OG_FALSE) {
            return OG_SUCCESS;
        }
        LEX_RESTORE(lex);
        status = sql_alloc_inline_cons(stmt, type, &def->constraints, &cons_def);
        OG_RETURN_IFERR(status);
        cons_def->index.unique = OG_TRUE;
        cons_def->index.cr_mode = OG_INVALID_ID8;
        cons_def->index.pctfree = OG_INVALID_ID32;

        status = sql_parse_column_list(stmt, lex, &cons_def->columns, OG_FALSE, NULL);
        OG_RETURN_IFERR(status);
    }

    OG_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type == WORD_TYPE_EOF || IS_SPEC_CHAR(&word, ',')) {
        lex_back(lex, &word);
        return OG_SUCCESS;
    }

    switch (word.id) {
        case KEY_WORD_USING:
            status = lex_expected_fetch_word(lex, "index");
            OG_RETURN_IFERR(status);
            return sql_parse_index_attrs(stmt, lex, &cons_def->index);
        case KEY_WORD_ENABLE:
        case KEY_WORD_DISABLE:
        case KEY_WORD_NOT:
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "key word \"not\" for constraints");
            return OG_ERROR;
        default:
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(&word));
            return OG_ERROR;
    }
}

static status_t sql_append_primary_key_cols(sql_stmt_t *stmt, text_t *ref_user, text_t *ref_table,
    galist_t *ref_columns)
{
    knl_dictionary_t dc;
    uint32 i;
    uint32 count;
    status_t status = OG_SUCCESS;
    knl_index_desc_t *index_desc = NULL;
    knl_column_t *column = NULL;
    knl_index_col_def_t *index_column = NULL;

    if (ref_columns->count != 0) {
        return OG_SUCCESS;
    }

    if (OG_SUCCESS != knl_open_dc(stmt->session, ref_user, ref_table, &dc)) {
        return OG_ERROR;
    }

    count = knl_get_index_count(dc.handle);
    for (i = 0; i < count; i++) {
        index_desc = knl_get_index(dc.handle, i);
        if (index_desc->primary) {
            break;
        }
    }

    if (i == count) {
        knl_close_dc(&dc);
        OG_THROW_ERROR(ERR_REFERENCED_NO_PRIMARY_KEY);
        return OG_ERROR;
    }

    for (i = 0; i < index_desc->column_count; i++) {
        column = knl_get_column(dc.handle, index_desc->columns[i]);
        status = cm_galist_new(ref_columns, sizeof(knl_index_col_def_t), (void **)&index_column);
        OG_BREAK_IF_ERROR(status);
        index_column->mode = SORT_MODE_ASC;
        status = sql_copy_str(stmt->context, column->name, &index_column->name);
        OG_BREAK_IF_ERROR(status);
    }

    knl_close_dc(&dc);
    return status;
}

status_t sql_parse_references_clause(sql_stmt_t *stmt, lex_t *lex, text_t *ref_user, text_t *ref_table,
    knl_refactor_t *refactor, galist_t *ref_columns)
{
    bool32 result = OG_FALSE;
    word_t word;
    status_t status;

    lex->flags = LEX_WITH_OWNER;

    status = lex_expected_fetch_variant(lex, &word);
    OG_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, ref_user, NULL, ref_table);
    OG_RETURN_IFERR(status);

    cm_galist_init(ref_columns, stmt->context, sql_alloc_mem);
    if (lex_try_fetch_bracket(lex, &word, &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        lex_back(lex, &word);
        status = sql_parse_column_list(stmt, lex, ref_columns, OG_FALSE, NULL);
        OG_RETURN_IFERR(status);
    }

    *refactor = REF_DEL_NOT_ALLOWED;

    if (lex_try_fetch(lex, "ON", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        /* on delete/update set null/cascade not supported yet */
        if (OG_SUCCESS != lex_expected_fetch_word(lex, "DELETE")) {
            return OG_ERROR;
        }

        status = lex_expected_fetch(lex, &word);
        OG_RETURN_IFERR(status);

        if (word.id == KEY_WORD_CASCADE) {
            *refactor |= REF_DEL_CASCADE;
        } else if (word.id == KEY_WORD_SET) {
            status = lex_expected_fetch_word(lex, "NULL");
            OG_RETURN_IFERR(status);
            *refactor |= REF_DEL_SET_NULL;
        } else {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CASCADE/SET NULL expected but %s found.", W2S(&word));
            return OG_ERROR;
        }
    }

    return sql_append_primary_key_cols(stmt, ref_user, ref_table, ref_columns);
}

static status_t sql_try_parse_foreign_key(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *result)
{
    status_t status;
    knl_reference_def_t *ref = NULL;
    knl_constraint_def_t *cons_def = NULL;

    if (lex_try_fetch(lex, "KEY", result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (*result == OG_FALSE) {
        return OG_SUCCESS;
    }

    status = sql_alloc_inline_cons(stmt, CONS_TYPE_REFERENCE, &def->constraints, &cons_def);
    OG_RETURN_IFERR(status);
    ref = &cons_def->ref;
    if (sql_parse_column_list(stmt, lex, &cons_def->columns, OG_FALSE, NULL) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "REFERENCES") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_references_clause(stmt, lex, &ref->ref_user, &ref->ref_table, &ref->refactor, &ref->ref_columns) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cons_def->columns.count != ref->ref_columns.count) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of referencing columns must match referenced columns.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_column_ref(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_REF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "duplicate or conflicting references specifications");
        return OG_ERROR;
    }

    *ex_flags |= COLUMN_EX_REF;
    column->is_ref = OG_TRUE;

    if (OG_SUCCESS != sql_parse_references_clause(stmt, lex, &column->ref_user, &column->ref_table, &column->refactor,
        &column->ref_columns)) {
        return OG_ERROR;
    }

    if (column->ref_columns.count != 1) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "number of referencing columns must match referenced columns.");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_column_check(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    status_t status;
    uint32 save_flags;
    cond_tree_t *cond = NULL;

    if (*ex_flags & COLUMN_EX_CHECK) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting check specifications");
        return OG_ERROR;
    }

    status = lex_expected_fetch_bracket(lex, word);
    OG_RETURN_IFERR(status);
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    column->check_text = word->text.value;
    cm_trim_text(&column->check_text);
    save_flags = lex->flags;
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    stmt->is_check = OG_TRUE;
    status = sql_create_cond_until(stmt, &cond, word);
    stmt->is_check = OG_FALSE;

    lex_pop(lex);
    OG_RETURN_IFERR(status);
    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "EOF expected but %s found",
            T2S(&word->text.value));
        return OG_ERROR;
    }

    column->is_check = OG_TRUE;
    *ex_flags |= COLUMN_EX_CHECK;

    lex->flags = save_flags;
    column->check_cond = cond;
    return OG_SUCCESS;
}

static status_t sql_parse_column_not_null(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_NULLABLE) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
            "duplicate or conflicting not null/null specifications");
        return OG_ERROR;
    }

    if (lex_expected_fetch_word(lex, "NULL") != OG_SUCCESS) {
        return OG_ERROR;
    }

    *ex_flags |= COLUMN_EX_NULLABLE;
    column->nullable = OG_FALSE;
    column->has_null = OG_TRUE;

    return OG_SUCCESS;
}

static status_t sql_parse_column_primary(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    if (*ex_flags & COLUMN_EX_KEY) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate or conflicting primary key/unique specifications");
        return OG_ERROR;
    }

    CHECK_CONS_TZ_TYPE_RETURN(column->datatype);

    if (lex_expected_fetch_word(lex, "KEY") != OG_SUCCESS) {
        return OG_ERROR;
    }

    *ex_flags |= COLUMN_EX_KEY;
    column->primary = OG_TRUE;
    column->nullable = OG_FALSE;
    column->has_null = OG_TRUE;

    return OG_SUCCESS;
}

status_t sql_parse_inline_constraint_elemt(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags, text_t *cons_name)
{
    status_t status;
    switch (word->id) {
        case KEY_WORD_NOT:
            status = sql_parse_column_not_null(stmt, lex, column, word, ex_flags);
            OG_RETURN_IFERR(status);
            break;

        case KEY_WORD_PRIMARY:
            status = sql_parse_column_primary(stmt, lex, column, word, ex_flags);
            OG_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_pri_cons_name = *cons_name;
            }
            break;

        case RES_WORD_NULL:
            if (*ex_flags & COLUMN_EX_NULLABLE) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "duplicate or conflicting not null/null specifications");
                return OG_ERROR;
            }
            column->has_null = OG_TRUE;
            *ex_flags |= COLUMN_EX_NULLABLE;
            break;

        case KEY_WORD_REFERENCES:
            status = sql_parse_column_ref(stmt, lex, column, word, ex_flags);
            OG_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_ref_cons_name = *cons_name;
            }
            break;

        case KEY_WORD_UNIQUE:
            if (*ex_flags & COLUMN_EX_KEY) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "duplicate or conflicting primary key/unique specifications");
                return OG_ERROR;
            }

            CHECK_CONS_TZ_TYPE_RETURN(column->datatype);

            *ex_flags |= COLUMN_EX_KEY;
            column->unique = OG_TRUE;
            if (cons_name != NULL) {
                column->inl_uq_cons_name = *cons_name;
            }
            break;

        case KEY_WORD_CHECK:
            status = sql_parse_column_check(stmt, lex, column, word, ex_flags);
            OG_RETURN_IFERR(status);
            if (cons_name != NULL) {
                column->inl_chk_cons_name = *cons_name;
            }
            break;

        default:
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "constraint expected but %s found", W2S(word));
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_inline_constraint(sql_stmt_t *stmt, lex_t *lex, knl_column_def_t *column, word_t *word,
    uint32 *ex_flags)
{
    text_t inl_constr = {
        .str = NULL,
        .len = 0
    };

    if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &inl_constr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_parse_inline_constraint_elemt(stmt, lex, column, word, ex_flags, &inl_constr);
}


static status_t sql_parse_out_line_constraint(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word,
    bool32 *res)
{
    status_t status;
    switch (word->id) {
        case KEY_WORD_CONSTRAINT:
            // try_fetch_variant
            status = sql_try_parse_constraint(stmt, lex, def, res);
            break;
        case KEY_WORD_PRIMARY:
            // try fetch_word("key")
            status = sql_try_parse_primary_unique_cons(stmt, lex, CONS_TYPE_PRIMARY, def, res);
            break;
        case KEY_WORD_UNIQUE:
            // try fetch_bracket
            status = sql_try_parse_primary_unique_cons(stmt, lex, CONS_TYPE_UNIQUE, def, res);
            break;
        case KEY_WORD_CHECK:
            *res = OG_TRUE;
            status = sql_parse_check_outline_cons(stmt, lex, def, NULL);
            break;

        case KEY_WORD_FOREIGN:
        default:
            status = sql_try_parse_foreign_key(stmt, lex, def, res); // try fech key
            break;
    }

    return status;
}

status_t sql_try_parse_cons(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, word_t *word, bool32 *result)
{
    status_t status;
    *result = OG_FALSE;
    if (!IS_CONSTRAINT_KEYWORD(word->id)) {
        return OG_SUCCESS;
    }

    status = sql_parse_out_line_constraint(stmt, lex, def, word, result);
    OG_RETURN_IFERR(status);

    if (*result == OG_FALSE) {
        return OG_SUCCESS;
    }
    status = lex_fetch(lex, word);
    OG_RETURN_IFERR(status);

    if (word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, ',')) {
        return OG_SUCCESS;
    }

    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
    return OG_ERROR;
}


status_t sql_verify_check_constraint(sql_stmt_t *stmt, knl_table_def_t *def)
{
    uint32 loop;
    knl_constraint_def_t *cons_def = NULL;
    knl_column_def_t *col = NULL;

    // verify check in out line constraint
    for (loop = 0; loop < def->constraints.count; loop++) {
        cons_def = (knl_constraint_def_t *)cm_galist_get(&def->constraints, loop);
        if (cons_def->type != CONS_TYPE_CHECK) {
            continue;
        }
        OG_RETURN_IFERR(sql_verify_outline_check(stmt, def, cons_def, (cond_tree_t *)cons_def->check.cond));
    }

    // verify check in column definition
    for (loop = 0; loop < def->columns.count; loop++) {
        col = (knl_column_def_t *)cm_galist_get(&def->columns, loop);
        if (!col->is_check) {
            continue;
        }
        OG_RETURN_IFERR(sql_verify_inline_check(stmt, col, (cond_tree_t *)col->check_cond));
    }
    return OG_SUCCESS;
}

static status_t sql_altable_inline_check_cons(sql_stmt_t *stmt, knl_column_def_t *column,
    knl_alt_column_prop_t *column_def)
{
    knl_constraint_def_t *cons_def = NULL;

    if (sql_verify_inline_check(stmt, column, column->check_cond) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_inline_cons(stmt, CONS_TYPE_CHECK, &column_def->constraints, &cons_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_append_inline_checks_column(stmt, cons_def, column) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_altable_inline_cons_index(sql_stmt_t *stmt, knl_column_def_t *column,
    knl_alt_column_prop_t *column_def)
{
    knl_constraint_def_t *cons_def = NULL;
    knl_index_col_def_t *index_col = NULL;
    constraint_type_t type;

    type = column->primary ? CONS_TYPE_PRIMARY : CONS_TYPE_UNIQUE;
    if (sql_alloc_inline_cons(stmt, type, &column_def->constraints, &cons_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (column->unique) {
        if (column->inl_uq_cons_name.len != 0) {
            cons_def->name = column->inl_uq_cons_name;
            cons_def->cons_state.is_anonymous = OG_FALSE;
        }
    } else {
        if (column->inl_pri_cons_name.len != 0) {
            cons_def->name = column->inl_pri_cons_name;
            cons_def->cons_state.is_anonymous = OG_FALSE;
        }
    }
    cm_galist_init(&cons_def->columns, stmt->context, sql_alloc_mem);
    OG_RETURN_IFERR(cm_galist_new(&cons_def->columns, sizeof(knl_index_col_def_t), (pointer_t *)&index_col));
    index_col->mode = SORT_MODE_ASC;
    index_col->name = column->name;
    cons_def->index.primary = column->primary;
    cons_def->index.unique = column->unique;
    cons_def->index.cr_mode = OG_INVALID_ID8;
    cons_def->index.pctfree = OG_INVALID_ID32;

    return OG_SUCCESS;
}

status_t sql_create_altable_inline_cons(sql_stmt_t *stmt, knl_column_def_t *column, knl_alt_column_prop_t *column_def)
{
    cm_galist_init(&column_def->constraints, stmt->context, sql_alloc_mem);

    if (column->is_check) {
        if (sql_altable_inline_check_cons(stmt, column, column_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (column->unique || column->primary) {
        if (sql_altable_inline_cons_index(stmt, column, column_def) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_altable_constraint_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    key_wid_t wid;
    word_t word;
    uint32 pre_flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    def->action = ALTABLE_RENAME_CONSTRAINT;
    if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->cons_def.name) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    wid = (key_wid_t)word.id;
    if (word.type != WORD_TYPE_KEYWORD || wid != KEY_WORD_TO) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "TO expected but %s found", W2S(&word));
        return OG_ERROR;
    }

    if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->cons_def.new_cons.name) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }
    lex->flags = pre_flags;
    return lex_expected_end(lex);
}
