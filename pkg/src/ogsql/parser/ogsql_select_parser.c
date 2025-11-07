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
 * ogsql_select_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/ogsql_select_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_select_parser.h"
#include "srv_instance.h"
#include "ogsql_verifier.h"
#include "table_parser.h"
#include "pivot_parser.h"
#include "hint_parser.h"
#include "cond_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_try_parse_alias(sql_stmt_t *stmt, text_t *alias, word_t *word)
{
    if (word->id == KEY_WORD_FROM || IS_SPEC_CHAR(word, ',')) {
        return OG_SUCCESS;
    }

    if (IS_VARIANT(word)) {
        if (word->ex_count > 0) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column alias");
            return OG_ERROR;
        }
        if (sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, alias) != OG_SUCCESS) {
            return OG_ERROR;
        }
        return lex_fetch(stmt->session->lex, word);
    }
    // do nothing now
    // For select * from (subquery), the (subquery) may not have an alias.
    return OG_SUCCESS;
}

status_t sql_parse_column(sql_stmt_t *stmt, galist_t *columns, word_t *word)
{
    text_t alias;
    query_column_t *query_col = NULL;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(cm_galist_new(columns, sizeof(query_column_t), (void **)&query_col));
    query_col->exist_alias = OG_FALSE;

    alias.str = lex->curr_text->str;

    OG_RETURN_IFERR(sql_create_expr_until(stmt, &query_col->expr, word));

    if (query_col->expr->root->type == EXPR_NODE_STAR) {
        alias.len = (uint32)(word->text.str - alias.str);
        // modified since the right side has an space
        cm_trim_text(&alias);
        query_col->expr->star_loc.end = query_col->expr->star_loc.begin + alias.len;
        return OG_SUCCESS;
    }

    if (word->id == KEY_WORD_AS) {
        OG_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
        OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &query_col->alias));
        OG_RETURN_IFERR(lex_fetch(lex, word));
    } else if (sql_try_parse_alias(stmt, &query_col->alias, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    query_col->exist_alias = OG_TRUE;
    if (query_col->alias.len == 0) {
        query_col->exist_alias = OG_FALSE;
        if (query_col->expr->root->type == EXPR_NODE_COLUMN) {
            alias = query_col->expr->root->word.column.name.value;
            return sql_copy_text(stmt->context, &alias, &query_col->alias);
        }
        /* if ommit alias ,then alias is whole expr string */
        alias.len = (uint32)(word->text.str - alias.str);

        // modified since the right side has an space
        cm_trim_text(&alias);

        if (alias.len > OG_MAX_NAME_LEN) {
            alias.len = OG_MAX_NAME_LEN;
        }
        return sql_copy_name(stmt->context, &alias, &query_col->alias);
    }
    return OG_SUCCESS;
}

static status_t sql_parse_query_columns(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    lex_t *lex = NULL;
    bool32 has_distinct = OG_FALSE;

    CM_POINTER3(stmt, query, word);

    lex = stmt->session->lex;

    if (lex_try_fetch(lex, "DISTINCT", &has_distinct) != OG_SUCCESS) {
        return OG_ERROR;
    }
    query->has_distinct = (uint16)has_distinct;

    for (;;) {
        if (sql_parse_column(stmt, query->columns, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (IS_SPEC_CHAR(word, ',')) {
            continue;
        }
        break;
    }

    return OG_SUCCESS;
}

/* { (),(a),(b),(a,b) } * {(),(c)} = { (),(a),(b),(a,b),(c),(a,c),(b,c),(a,b,c) } */
static status_t sql_extract_group_cube_expr(sql_stmt_t *stmt, galist_t *group_sets, expr_tree_t *expr)
{
    expr_tree_t *next_expr = NULL;
    group_set_t *group_set = NULL;
    group_set_t *new_group_set = NULL;
    uint32 count = group_sets->count;
    galist_t *exprs = NULL;

    OG_RETURN_IFERR(sql_push(stmt, sizeof(galist_t), (void **)&exprs));
    cm_galist_init(exprs, stmt, sql_stack_alloc);

    while (expr != NULL) {
        next_expr = expr->next;
        expr->next = NULL;
        OG_RETURN_IFERR(cm_galist_insert(exprs, expr));
        expr = next_expr;
    }

    for (uint32 i = 0; i < count; i++) {
        group_set = (group_set_t *)cm_galist_get(group_sets, i);

        // group_set memory should be allocated from context
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(group_set_t), (void **)&new_group_set));
        OG_RETURN_IFERR(sql_create_list(stmt, &new_group_set->items));
        OG_RETURN_IFERR(cm_galist_copy(new_group_set->items, group_set->items));
        OG_RETURN_IFERR(cm_galist_copy(new_group_set->items, exprs));
        OG_RETURN_IFERR(cm_galist_insert(group_sets, new_group_set));
    }

    return OG_SUCCESS;
}

/* cube(a,b) = grouping sets((),(a),(b),(a,b)) */
static status_t sql_extract_group_cube(sql_stmt_t *stmt, galist_t *items, galist_t *group_sets)
{
    uint32 i;
    expr_tree_t *expr = NULL;
    group_set_t *group_set = NULL;
    galist_t *cube_sets = NULL;

    // temporary cube sets for cartesian
    OG_RETURN_IFERR(sql_push(stmt, sizeof(galist_t), (void **)&cube_sets));
    cm_galist_init(cube_sets, stmt, sql_stack_alloc);

    // add empty set: group_set memory should be allocated from context
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(group_set_t), (void **)&group_set));
    OG_RETURN_IFERR(sql_create_list(stmt, &group_set->items));
    OG_RETURN_IFERR(cm_galist_insert(cube_sets, group_set));

    for (i = 0; i < items->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(items, i);
        OG_RETURN_IFERR(sql_extract_group_cube_expr(stmt, cube_sets, expr));
    }

    // copy temporary cube sets to group sets
    return cm_galist_copy(group_sets, cube_sets);
}

/* rollup(a,b) = grouping sets((),(a),(a,b)) */
static status_t sql_extract_group_rollup(sql_stmt_t *stmt, galist_t *items, galist_t *group_sets)
{
    expr_tree_t *next_expr = NULL;
    expr_tree_t *expr = NULL;
    group_set_t *group_set = NULL;
    galist_t *src_items = NULL;

    // group_set memory should be allocated from context
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(group_set_t), (void **)&group_set));
    OG_RETURN_IFERR(sql_create_list(stmt, &group_set->items));
    OG_RETURN_IFERR(cm_galist_insert(group_sets, group_set));
    src_items = group_set->items;

    for (uint32 i = 0; i < items->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(items, i);

        // group_set memory should be allocated from context
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(group_set_t), (void **)&group_set));
        OG_RETURN_IFERR(sql_create_list(stmt, &group_set->items));
        OG_RETURN_IFERR(cm_galist_insert(group_sets, group_set));

        OG_RETURN_IFERR(cm_galist_copy(group_set->items, src_items));
        while (expr != NULL) {
            next_expr = expr->next;
            expr->next = NULL;
            OG_RETURN_IFERR(cm_galist_insert(group_set->items, expr));
            expr = next_expr;
        }
        src_items = group_set->items;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_bracket_exprs(sql_stmt_t *stmt, expr_tree_t **exprs, word_t *word)
{
    expr_tree_t *next_expr = NULL;
    expr_tree_t *expr = NULL;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        if (sql_create_expr_until(stmt, &expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (expr->next != NULL) {
            OG_SRC_THROW_ERROR(expr->next->loc, ERR_SQL_SYNTAX_ERROR, "missing right bracket");
            return OG_ERROR;
        }
        if (next_expr == NULL) {
            *exprs = expr;
            next_expr = expr;
        } else {
            next_expr->next = expr;
            next_expr = expr;
        }
        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    OG_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);
    return lex_fetch(lex, word);
}

static status_t sql_parse_cube_rollup(sql_stmt_t *stmt, bool32 is_cube, galist_t *group_sets, word_t *word)
{
    bool32 has_bracket = OG_FALSE;
    expr_tree_t *expr = NULL;
    galist_t *items = NULL;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    OG_RETURN_IFERR(sql_push(stmt, sizeof(galist_t), (void **)&items));
    cm_galist_init(items, stmt, sql_stack_alloc);

    for (;;) {
        // try parse bracket
        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &has_bracket));

        if (has_bracket) {
            OG_RETURN_IFERR(sql_parse_bracket_exprs(stmt, &expr, word));
        } else {
            OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
        }

        if (cm_galist_insert(items, expr) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    OG_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);

    if (is_cube) {
        OG_RETURN_IFERR(sql_extract_group_cube(stmt, items, group_sets));
    } else {
        OG_RETURN_IFERR(sql_extract_group_rollup(stmt, items, group_sets));
    }

    return lex_fetch(lex, word);
}

static status_t sql_parse_grouping_set_items(sql_stmt_t *stmt, galist_t *items, word_t *word)
{
    expr_tree_t *expr = NULL;
    lex_t *lex = stmt->session->lex;

    // empty set is acceptable
    if (word->text.len == 0) {
        return lex_fetch(lex, word);
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        if (sql_create_expr_until(stmt, &expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (expr->next != NULL) {
            OG_SRC_THROW_ERROR(expr->next->loc, ERR_SQL_SYNTAX_ERROR, "missing right bracket");
            return OG_ERROR;
        }

        if (cm_galist_insert(items, expr) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    OG_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);
    return lex_fetch(lex, word);
}

static status_t sql_cartesin_one_group_set(sql_stmt_t *stmt, galist_t *group_sets, group_set_t *group_set,
    galist_t *result)
{
    group_set_t *old_group_set = NULL;
    group_set_t *new_group_set = NULL;

    for (uint32 i = 0; i < group_sets->count; i++) {
        old_group_set = (group_set_t *)cm_galist_get(group_sets, i);

        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(group_set_t), (void **)&new_group_set));
        OG_RETURN_IFERR(cm_galist_insert(result, new_group_set));
        OG_RETURN_IFERR(sql_create_list(stmt, &new_group_set->items));
        OG_RETURN_IFERR(cm_galist_copy(new_group_set->items, old_group_set->items));
        OG_RETURN_IFERR(cm_galist_copy(new_group_set->items, group_set->items));
    }
    return OG_SUCCESS;
}

static status_t sql_cartesian_grouping_sets(sql_stmt_t *stmt, sql_query_t *query, galist_t *group_sets)
{
    group_set_t *group_set = NULL;
    galist_t *new_grp_sets = NULL;

    if (group_sets->count == 0) {
        return OG_SUCCESS;
    }
    if (query->group_sets->count == 0) {
        return cm_galist_copy(query->group_sets, group_sets);
    }

    OG_RETURN_IFERR(sql_create_list(stmt, &new_grp_sets));

    for (uint32 i = 0; i < group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(group_sets, i);
        OG_RETURN_IFERR(sql_cartesin_one_group_set(stmt, query->group_sets, group_set, new_grp_sets));
    }
    query->group_sets = new_grp_sets;
    return OG_SUCCESS;
}

static status_t sql_parse_grouping_sets(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    uint32 match_id;
    bool32 has_bracket = OG_FALSE;
    lex_t *lex = stmt->session->lex;
    group_set_t *group_set = NULL;
    expr_tree_t *expr = NULL;
    galist_t *group_sets = NULL;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SETS"));
    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    // create temporary group sets
    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, sizeof(galist_t), (void **)&group_sets));
    cm_galist_init(group_sets, stmt, sql_stack_alloc);

    for (;;) {
        /* grouping sets({rollup | cube}(a,b),c) */
        OG_RETURN_IFERR(lex_try_fetch_1of2(lex, "CUBE", "ROLLUP", &match_id));
        if (match_id != OG_INVALID_ID32) {
            OG_RETURN_IFERR(sql_parse_cube_rollup(stmt, (match_id == 0), group_sets, word));
        } else {
            /* memory must be allocated from context */
            OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(group_set_t), (void **)&group_set));
            OG_RETURN_IFERR(sql_create_list(stmt, &group_set->items));
            OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &has_bracket));

            if (has_bracket) {
                /* grouping sets((a,b)) */
                OG_RETURN_IFERR(sql_parse_grouping_set_items(stmt, group_set->items, word));
            } else {
                /* grouping sets(a,b) */
                OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
                OG_RETURN_IFERR(cm_galist_insert(group_set->items, expr));
            }
            OG_RETURN_IFERR(cm_galist_insert(group_sets, group_set));
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    // combine grouping sets
    if (sql_cartesian_grouping_sets(stmt, query, group_sets) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);
    lex_pop(lex);
    return lex_fetch(lex, word);
}

static inline status_t sql_parse_group_by_expr(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    expr_tree_t *expr = NULL;
    group_set_t *group_set = NULL;

    if (sql_create_expr_until(stmt, &expr, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (query->group_sets->count == 0) {
        OG_RETURN_IFERR(cm_galist_new(query->group_sets, sizeof(group_set_t), (void **)&group_set));
        OG_RETURN_IFERR(sql_create_list(stmt, &group_set->items));
        return cm_galist_insert(group_set->items, expr);
    }

    for (uint32 i = 0; i < query->group_sets->count; i++) {
        group_set = (group_set_t *)cm_galist_get(query->group_sets, i);
        OG_RETURN_IFERR(cm_galist_insert(group_set->items, expr));
    }
    return OG_SUCCESS;
}

static inline status_t sql_parse_group_by_cube(sql_stmt_t *stmt, sql_query_t *query, bool32 is_cube, word_t *word)
{
    galist_t *group_sets = NULL;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, sizeof(galist_t), (void **)&group_sets));
    cm_galist_init(group_sets, stmt, sql_stack_alloc);

    OG_RETURN_IFERR(sql_parse_cube_rollup(stmt, is_cube, group_sets, word));

    // cartesian group sets
    OG_RETURN_IFERR(sql_cartesian_grouping_sets(stmt, query, group_sets));

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t sql_parse_group_by(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    bool32 has_bracket = OG_FALSE;
    bool32 has_comma = OG_FALSE;
    uint32 group_type;
    const char *words = ",";
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "BY") != OG_SUCCESS) {
        return OG_ERROR;
    }

    LEX_SAVE(lex);

    if (lex_try_fetch_bracket(lex, word, &has_bracket) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (has_bracket) {
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        OG_RETURN_IFERR(lex_inc_special_word(lex, words, &has_comma));

        if (!has_comma) {
            lex_pop(lex);
            /* group by (f1) */
            LEX_RESTORE(lex);
        }
        /* group by (f1, f2), or group by ((f1), (f2)) */
    }

    for (;;) {
        if (lex_try_fetch_1of3(lex, "GROUPING", "CUBE", "ROLLUP", &group_type) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (group_type == 0) {
            OG_RETURN_IFERR(sql_parse_grouping_sets(stmt, query, word));
        } else if (group_type == OG_INVALID_ID32) {
            OG_RETURN_IFERR(sql_parse_group_by_expr(stmt, query, word));
        } else {
            OG_RETURN_IFERR(sql_parse_group_by_cube(stmt, query, (group_type == 1), word));
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    if (has_bracket && has_comma) {
        if (word->type != WORD_TYPE_EOF) {
            /* error scenario : group by ((f1), (f2) d) */
            OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", T2S(&word->text.value));
            return OG_ERROR;
        }

        lex_pop(lex);
        return lex_fetch(lex, word);
    }

    return OG_SUCCESS;
}

status_t sql_parse_order_by_items(sql_stmt_t *stmt, galist_t *sort_items, word_t *word)
{
    sort_item_t *item = NULL;
    uint32 pre_flags;
    uint32 nulls_postion = SORT_NULLS_DEFAULT;

    // return error if missing keyword "by"
    OG_RETURN_IFERR(lex_expected_fetch_word(stmt->session->lex, "by"));

    /* expr alias asc, expr alias desc, ... */
    for (;;) {
        OG_RETURN_IFERR(cm_galist_new(sort_items, sizeof(sort_item_t), (void **)&item));

        item->direction = SORT_MODE_ASC;
        item->nulls_pos = SORT_NULLS_DEFAULT;
        OG_RETURN_IFERR(sql_create_expr_until(stmt, &item->expr, word));

        pre_flags = stmt->session->lex->flags;
        stmt->session->lex->flags = LEX_SINGLE_WORD;

        if (word->id == KEY_WORD_DESC || word->id == KEY_WORD_ASC) {
            item->direction = (word->id == KEY_WORD_DESC) ? SORT_MODE_DESC : SORT_MODE_ASC;
            OG_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
        }

        if (word->id == KEY_WORD_NULLS) {
            OG_RETURN_IFERR(lex_expected_fetch_1of2(stmt->session->lex, "FIRST", "LAST", &nulls_postion));
            item->nulls_pos = (nulls_postion == 0) ? SORT_NULLS_FIRST : SORT_NULLS_LAST;
#ifdef Z_SHARDING
            if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
                OG_SRC_THROW_ERROR(word->text.loc, ERR_CAPABILITY_NOT_SUPPORT, "NULLS FIRST/LAST");
                return OG_ERROR;
            }
#endif
            OG_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
        }

        stmt->session->lex->flags = pre_flags;

        if (item->nulls_pos == SORT_NULLS_DEFAULT) {
            // set the default nulls position, when it is not given
            item->nulls_pos = DEFAULT_NULLS_SORTING_POSITION(item->direction);
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_order_by(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    bool32 result = OG_FALSE;
    if (lex_try_fetch(stmt->session->lex, "SIBLINGS", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (result) {
        if (query->connect_by_cond == NULL || query->group_sets->count > 0 || query->having_cond != NULL) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "ORDER SIBLINGS BY clause not allowed here.");
            return OG_ERROR;
        }
        query->order_siblings = OG_TRUE;
    }
    return sql_parse_order_by_items(stmt, query->sort_items, word);
}

static status_t sql_parse_limit_head(sql_stmt_t *stmt, limit_item_t *limit_item, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;
    bool32 exist_offset = OG_FALSE;
    uint32 save_flags;

    save_flags = lex->flags;
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    if (sql_create_expr_until(stmt, &expr1, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    lex->flags = save_flags;

    if ((key_wid_t)word->id == KEY_WORD_OFFSET) {
        exist_offset = OG_TRUE;
    }

    if (exist_offset) {
        save_flags = lex->flags;
        lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
        if (sql_create_expr_until(stmt, &expr2, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        lex->flags = save_flags;
        limit_item->count = (void *)expr1;
        limit_item->offset = (void *)expr2;
    } else {
        if (IS_SPEC_CHAR(word, ',')) {
            save_flags = lex->flags;
            lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
            if (sql_create_expr_until(stmt, &expr2, word) != OG_SUCCESS) {
                return OG_ERROR;
            }
            lex->flags = save_flags;

            limit_item->count = (void *)expr2;
            limit_item->offset = (void *)expr1;
        } else {
            limit_item->count = (void *)expr1;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_offset_head(sql_stmt_t *stmt, limit_item_t *limit_item, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    expr_tree_t *expr1 = NULL;
    expr_tree_t *expr2 = NULL;
    bool32 exist_limit = OG_FALSE;
    uint32 save_flags;

    save_flags = lex->flags;
    lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
    if (sql_create_expr_until(stmt, &expr1, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    lex->flags = save_flags;

    if ((key_wid_t)word->id == KEY_WORD_LIMIT) {
        exist_limit = OG_TRUE;
    }

    if (exist_limit) {
        save_flags = lex->flags;
        lex->flags = LEX_WITH_ARG | LEX_WITH_OWNER;
        if (sql_create_expr_until(stmt, &expr2, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        lex->flags = save_flags;
        limit_item->offset = (void *)expr1;
        limit_item->count = (void *)expr2;
    } else {
        limit_item->offset = (void *)expr1;
    }

    return OG_SUCCESS;
}

status_t sql_verify_limit_offset(sql_stmt_t *stmt, limit_item_t *limit_item)
{
    sql_verifier_t verf = { 0 };

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_LIMIT_EXCL;
#ifdef Z_SHARDING
    OG_RETURN_IFERR(shd_verfity_excl_user_function(&verf, stmt));
#endif

    if (limit_item->offset != NULL) {
        if (sql_verify_expr(&verf, (expr_tree_t *)limit_item->offset) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (limit_item->count != NULL) {
        if (sql_verify_expr(&verf, (expr_tree_t *)limit_item->count) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t sql_parse_limit_offset(sql_stmt_t *stmt, limit_item_t *limit_item, word_t *word)
{
    status_t status;

    if (word->id == KEY_WORD_LIMIT) {
        status = sql_parse_limit_head(stmt, limit_item, word);
    } else {
        status = sql_parse_offset_head(stmt, limit_item, word);
    }

    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_verify_limit_offset(stmt, limit_item);
}

status_t sql_init_join_assist(sql_stmt_t *stmt, sql_join_assist_t *join_ass)
{
    join_ass->join_node = NULL;
    join_ass->outer_plan_count = 0;
    join_ass->outer_node_count = 0;
    join_ass->inner_plan_count = 0;
    join_ass->mj_plan_count = 0;
    join_ass->has_hash_oper = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_init_query(sql_stmt_t *stmt, sql_select_t *select_ctx, source_location_t loc, sql_query_t *sql_query)
{
    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->aggrs));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->cntdis_columns));

    OG_RETURN_IFERR(sql_create_array(stmt->context, &sql_query->tables, "QUERY TABLES", OG_MAX_JOIN_TABLES));

    OG_RETURN_IFERR(sql_create_array(stmt->context, &sql_query->ssa, "SUB-SELECT", OG_MAX_SUBSELECT_EXPRS));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->columns));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->rs_columns));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->winsort_rs_columns));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->sort_items));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->group_sets));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->distinct_columns));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->winsort_list));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->join_symbol_cmps));

    OG_RETURN_IFERR(sql_create_list(stmt, &sql_query->path_func_nodes));

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(query_block_info_t), (void **)&sql_query->block_info));

    sql_query->owner = select_ctx;
    sql_query->loc = loc;
    sql_query->has_distinct = OG_FALSE;
    sql_query->for_update = OG_FALSE;
    sql_query->cond = NULL;
    sql_query->having_cond = NULL;
    sql_query->filter_cond = NULL;
    sql_query->start_with_cond = NULL;
    sql_query->connect_by_cond = NULL;
    sql_query->connect_by_nocycle = OG_FALSE;
    sql_query->connect_by_iscycle = OG_FALSE;
    sql_query->exists_covar = OG_FALSE;
    sql_query->is_s_query = OG_FALSE;
    sql_query->hint_info = NULL;

    OG_RETURN_IFERR(sql_init_join_assist(stmt, &sql_query->join_assist));
    sql_query->aggr_dis_count = 0;
    sql_query->remote_keys = NULL;
    sql_query->incl_flags = 0;
    sql_query->order_siblings = OG_FALSE;
    sql_query->group_cubes = NULL;
    sql_query->pivot_items = NULL;
    sql_query->vpeek_assist = NULL;
    sql_query->cb_mtrl_info = NULL;
    sql_query->join_card = OG_INVALID_INT64;

    OG_RETURN_IFERR(vmc_alloc_mem(&stmt->vmc, sizeof(vmc_t), (void **)&sql_query->vmc));
    vmc_init(&stmt->session->vmp, sql_query->vmc);
    sql_query->filter_infos = NULL;
    return cm_galist_insert(&stmt->vmc_list, sql_query->vmc);
}

static status_t sql_create_start_with(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    if (lex_expected_fetch_word(stmt->session->lex, "WITH") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_cond_until(stmt, &query->start_with_cond, word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_create_connect_by(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;

    if (lex_expected_fetch_word(stmt->session->lex, "BY") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_try_fetch(lex, "NOCYCLE", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (result) {
        query->connect_by_nocycle = OG_TRUE;
    }

    if (sql_create_cond_until(stmt, &query->connect_by_cond, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_START) {
        return OG_SUCCESS;
    }

    if (query->start_with_cond != NULL) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "The 'START' have already appeared.");
        return OG_ERROR;
    }

    if (sql_create_start_with(stmt, query, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline status_t sql_calc_found_rows_needed(sql_stmt_t *stmt, sql_select_t *select_ctx, select_type_t type,
    bool32 *found_rows_needed)
{
    *found_rows_needed = OG_FALSE;

    /* check if there is "SQL_CALC_FOUND_ROWS" following "SELECT" */
    if ((type == SELECT_AS_RESULT) ||                                  /* simple select statement */
        (type == SELECT_AS_VALUES) || (type == SELECT_AS_SET)) { /* subset select statement in union */
        OG_RETURN_IFERR(lex_try_fetch(stmt->session->lex, "sql_calc_found_rows", found_rows_needed));

        if (*found_rows_needed) {
#ifdef Z_SHARDING
            if (IS_COORDINATOR && IS_APP_CONN(stmt->session)) {
                OG_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_CAPABILITY_NOT_SUPPORT, "SQL_CALC_FOUND_ROWS");
                return OG_ERROR;
            }
#endif
            if (select_ctx->first_query == NULL) {
                /*
                 * we cannot here identify whether the current sql_select_t is a subset sql_selet_t in union,
                 * or a main sql_selet_t for simple query. so set the calc_found_rows of sql_selet_t into true
                 * and pass it to the main sql_selet_t if it is the first subset select in union
                 *
                 * for the value pass of calc_found_rows, please refer to sql_parse_select_wrapped()
                 */
                select_ctx->calc_found_rows = OG_TRUE;
            } else {
                /* "SQL_CALC_FOUND_ROWS" cannot show up in the non-first query of UNION statement */
                OG_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_SQL_SYNTAX_ERROR,
                    "Incorrect usage/placement of \"SQL_CALC_FOUND_ROWS\"");
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static status_t sql_parse_query_clauses(sql_stmt_t *stmt, sql_query_t *query, word_t *word)
{
    OG_RETURN_IFERR(sql_parse_query_columns(stmt, query, word));

    OG_RETURN_IFERR(sql_parse_query_tables(stmt, query, word));

    if (word->id == KEY_WORD_PIVOT) {
        OG_RETURN_IFERR(sql_create_pivot(stmt, query, word));
    } else if (word->id == KEY_WORD_UNPIVOT) {
        OG_RETURN_IFERR(sql_create_unpivot(stmt, query, word));
    }

    if (word->id == KEY_WORD_WHERE) {
        OG_RETURN_IFERR(sql_create_cond_until(stmt, &query->cond, word));
    }
    if (word->id == KEY_WORD_START) {
        OG_RETURN_IFERR(sql_create_start_with(stmt, query, word));

        if (word->id != KEY_WORD_CONNECT) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expect CONNECT BY.");
            return OG_ERROR;
        }
    }

    if (word->id == KEY_WORD_CONNECT) {
        OG_RETURN_IFERR(sql_create_connect_by(stmt, query, word));
    }

    if (word->id == KEY_WORD_GROUP) {
        OG_RETURN_IFERR(sql_parse_group_by(stmt, query, word));
    }

    if (word->id == KEY_WORD_HAVING) {
        OG_RETURN_IFERR(sql_create_cond_until(stmt, &query->having_cond, word));
    }

    if (word->id == KEY_WORD_ORDER) {
        OG_RETURN_IFERR(sql_parse_order_by(stmt, query, word));
    }

    if (word->id == KEY_WORD_LIMIT || word->id == KEY_WORD_OFFSET) {
        OG_RETURN_IFERR(sql_parse_limit_offset(stmt, &query->limit, word));
    }
    return OG_SUCCESS;
}

static status_t sql_parse_for_update_of(sql_stmt_t *stmt, sql_select_t *select_ctx, word_t *word)
{
    expr_tree_t *expr = NULL;

    OG_RETURN_IFERR(sql_create_list(stmt, &select_ctx->for_update_cols));

    for (;;) {
        if (sql_create_expr_until(stmt, &expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (expr->root == NULL || expr->root->type != EXPR_NODE_COLUMN) {
            OG_SRC_THROW_ERROR(expr->loc, ERR_EXPECT_COLUMN_HERE);
            return OG_ERROR;
        }
        if (cm_galist_insert(select_ctx->for_update_cols, expr) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (!IS_SPEC_CHAR(word, ',')) {
            break;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_parse_for_update_params(sql_stmt_t *stmt, sql_select_t *select_context, word_t *word)
{
    status_t status = OG_SUCCESS;
    lex_t *lex = stmt->session->lex;
    uint32 timeout = 0;

    word->ex_count = 0;
    if (lex_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        /* default value */
        select_context->for_update_params.type = ROWMARK_WAIT_BLOCK;
        return status;
    }

    if ((key_wid_t)word->id == KEY_WORD_OF) {
        OG_RETURN_IFERR(sql_parse_for_update_of(stmt, select_context, word));
        if (word->type == WORD_TYPE_EOF) {
            /* default value */
            select_context->for_update_params.type = ROWMARK_WAIT_BLOCK;
            return status;
        }
    }

    /* parse params */
    switch ((key_wid_t)word->id) {
        case KEY_WORD_WAIT:
            if (lex_expected_fetch_uint32(lex, &timeout) != OG_SUCCESS) {
                return OG_ERROR;
            }

            select_context->for_update_params.type = ROWMARK_WAIT_SECOND;
            select_context->for_update_params.wait_seconds = timeout;
            break;

        case KEY_WORD_NOWAIT:
            select_context->for_update_params.type = ROWMARK_NOWAIT;
            break;

        case KEY_WORD_SKIP:
            if (lex_expected_fetch_word(lex, "locked") != OG_SUCCESS) {
                return OG_ERROR;
            }
            select_context->for_update_params.type = ROWMARK_SKIP_LOCKED;
            break;

        default:
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "[wait] | [nowait] | [skip locked] expected");
            return OG_ERROR;
    }

    return status;
}

/* According to oracle, for update must apply to select, not subquery */
static status_t sql_parse_for_update(sql_stmt_t *stmt, sql_select_t *select_ctx, word_t *word)
{
    lex_t *lex = NULL;

    CM_POINTER3(stmt, select_ctx, word);

    if (select_ctx->type != SELECT_AS_RESULT) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_FOR_UPDATE_NOT_ALLOWED);
        return OG_ERROR;
    }

    if (select_ctx->root != NULL && select_ctx->root->type != SELECT_NODE_QUERY) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_FOR_UPDATE_NOT_ALLOWED);
        return OG_ERROR;
    }

    lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "update") != OG_SUCCESS) {
        return OG_ERROR;
    }

    select_ctx->for_update = OG_TRUE;

    /* set default value */
    select_ctx->for_update_params.type = ROWMARK_WAIT_BLOCK;

    /* add for update parameters, support four mode */
    OG_RETURN_IFERR(sql_parse_for_update_params(stmt, select_ctx, word));

    return OG_SUCCESS;
}

static inline void sql_down_select_node(sql_select_t *select_ctx, select_node_t *select_node)
{
    select_node->left = select_node->prev;
    select_node->right = select_node->next;

    select_node->next = select_node->next->next;
    select_node->prev = select_node->prev->prev;

    if (select_node->prev != NULL) {
        select_node->prev->next = select_node;
    } else {
        select_ctx->chain.first = select_node;
    }

    if (select_node->next != NULL) {
        select_node->next->prev = select_node;
    } else {
        select_ctx->chain.last = select_node;
    }

    select_node->left->prev = NULL;
    select_node->left->next = NULL;
    select_node->right->prev = NULL;
    select_node->right->next = NULL;
    select_ctx->chain.count -= 2;
}

static status_t sql_form_select_with_oper(sql_select_t *select_ctx, select_node_type_t type)
{
    select_node_t *prev = NULL;
    select_node_t *next = NULL;
    select_node_t *select_node = NULL;

    /* get next node ,merge node is needed at least two node */
    select_node = select_ctx->chain.first->next;

    while (select_node != NULL) {
        if (((uint32)select_node->type & (uint32)type) == 0) {
            select_node = select_node->next;
            continue;
        }

        prev = select_node->prev;
        next = select_node->next;

        /* if is not a correct condition */
        if (prev == NULL || next == NULL) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " missing SELECT keyword");
            return OG_ERROR;
        }

        sql_down_select_node(select_ctx, select_node);

        select_node = select_node->next;
    }

    return OG_SUCCESS;
}

static status_t sql_generate_select(sql_select_t *select_ctx)
{
    if (select_ctx->chain.count == 0) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "missing SELECT keyword");
        return OG_ERROR;
    }

    if (sql_form_select_with_oper(select_ctx, SELECT_NODE_UNION_ALL | SELECT_NODE_UNION | SELECT_NODE_INTERSECT |
        SELECT_NODE_MINUS | SELECT_NODE_INTERSECT_ALL | SELECT_NODE_EXCEPT_ALL | SELECT_NODE_EXCEPT) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (select_ctx->chain.count != 1) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "missing SELECT keyword");
        return OG_ERROR;
    }

    select_ctx->root = select_ctx->chain.first;
    return OG_SUCCESS;
}

status_t sql_alloc_select_context(sql_stmt_t *stmt, select_type_t type, sql_select_t **select_ctx)
{
    if (sql_alloc_mem(stmt->context, sizeof(sql_select_t), (void **)select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*select_ctx)->type = type;
    (*select_ctx)->for_update = OG_FALSE;
    (*select_ctx)->pending_col_count = 0;
#ifdef Z_SHARDING
    (*select_ctx)->sub_select_sinkall = OG_FALSE;
#endif

    OG_RETURN_IFERR(sql_create_list(stmt, &(*select_ctx)->sort_items));
    OG_RETURN_IFERR(sql_create_list(stmt, &(*select_ctx)->parent_refs));
    OG_RETURN_IFERR(sql_create_list(stmt, &(*select_ctx)->pl_dc_lst));
    (*select_ctx)->plan = NULL;
    (*select_ctx)->for_update_cols = NULL;
    (*select_ctx)->withass = NULL;
    (*select_ctx)->is_withas = OG_FALSE;
    (*select_ctx)->can_sub_opt = OG_TRUE;
    return OG_SUCCESS;
}

// select * from ww1 union all select * from ww1 order by f_int1; order by affects all query
static status_t sql_create_select_order(sql_select_t *select_ctx, sql_query_t *query)
{
    uint32 i;
    sort_item_t *item1 = NULL;
    sort_item_t *item2 = NULL;

    if (query == NULL) {
        return OG_SUCCESS;
    }

    if (select_ctx->sort_items->count > 0) {
        return OG_SUCCESS;
    }

    for (i = 0; i < query->sort_items->count; i++) {
        item1 = (sort_item_t *)cm_galist_get(query->sort_items, i);
        if (cm_galist_new(select_ctx->sort_items, sizeof(sort_item_t), (void **)&item2) != OG_SUCCESS) {
            return OG_ERROR;
        }

        *item2 = *item1;
    }

    cm_galist_reset(query->sort_items);

    return OG_SUCCESS;
}

// select * from ww1 union all select * from ww1 limit 1; limit affects all query
static status_t sql_create_select_limit(sql_select_t *select_ctx, sql_query_t *query)
{
    if (query == NULL) {
        return OG_SUCCESS;
    }

    if (LIMIT_CLAUSE_OCCUR(&select_ctx->limit)) {
        return OG_SUCCESS;
    }

    select_ctx->limit = query->limit;
    query->limit.count = NULL;
    query->limit.offset = NULL;

    return OG_SUCCESS;
}

static status_t sql_create_select_order_limit(sql_select_t *select_ctx, sql_query_t *query, word_t *word)
{
    if (select_ctx->type == SELECT_AS_SET) {
        if (query != NULL && (LIMIT_CLAUSE_OCCUR(&query->limit) || query->sort_items->count > 0)) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "wrong syntax to use 'LIMIT'or 'ORDER'.");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    if (query != NULL && query->order_siblings) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "ORDER SIBLINGS BY clause not allowed here.");
        return OG_ERROR;
    }

    if (sql_create_select_order(select_ctx, query) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_create_select_limit(select_ctx, query) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_select_order_limit(sql_stmt_t *stmt, sql_select_t *select_ctx, word_t *word,
    sql_query_t *query)
{
    if (select_ctx->type == SELECT_AS_SET) {
        return OG_SUCCESS;
    }

    if (word->id == KEY_WORD_ORDER) {
        if (query != NULL && LIMIT_CLAUSE_OCCUR(&query->limit)) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "INVALID ORDER");
            return OG_ERROR;
        }
        if (query != NULL && query->sort_items->count > 0) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "INVALID ORDER");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_parse_order_by_items(stmt, select_ctx->sort_items, word));
    }

    if (word->id == KEY_WORD_LIMIT || word->id == KEY_WORD_OFFSET) {
        if (query != NULL && LIMIT_CLAUSE_OCCUR(&query->limit)) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "INVALID LIMIT");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(sql_parse_limit_offset(stmt, &select_ctx->limit, word));
    }

    /* The sql should end or following with for update. */
    if (select_ctx->sort_items->count > 0 || select_ctx->limit.count != NULL) {
        if ((word->type == WORD_TYPE_EOF || word->id == KEY_WORD_FOR)) {
            return OG_SUCCESS;
        } else {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "SQL SYNTAX ERROR, INVALID ORDER OR LIMIT");
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_create_select_node(sql_stmt_t *stmt, sql_select_t *select_ctx, uint32 wid)
{
    bool32 result = OG_FALSE;
    select_node_t *node = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(select_node_t), (void **)&node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    APPEND_CHAIN(&select_ctx->chain, node);

    if (wid == KEY_WORD_SELECT) {
        node->type = SELECT_NODE_QUERY;
    } else if (wid == KEY_WORD_UNION) {
        if (lex_try_fetch(stmt->session->lex, "ALL", &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        node->type = result ? SELECT_NODE_UNION_ALL : SELECT_NODE_UNION;
    } else if (wid == KEY_WORD_MINUS) {
        node->type = SELECT_NODE_MINUS;
    } else if (wid == KEY_WORD_EXCEPT) {
        if (lex_try_fetch(stmt->session->lex, "ALL", &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!result) {
            bool32 hasDistinct = OG_FALSE;
            if (lex_try_fetch(stmt->session->lex, "DISTINCT", &hasDistinct) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
        node->type = result ? SELECT_NODE_EXCEPT_ALL : SELECT_NODE_EXCEPT;
    } else if (wid == KEY_WORD_INTERSECT) {
        if (lex_try_fetch(stmt->session->lex, "ALL", &result) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!result) {
            bool32 hasDistinct = OG_FALSE;
            if (lex_try_fetch(stmt->session->lex, "DISTINCT", &hasDistinct) != OG_SUCCESS) {
                return OG_ERROR;
            }
        }
        node->type = result ? SELECT_NODE_INTERSECT_ALL : SELECT_NODE_INTERSECT;
    } else {
        node->type = SELECT_NODE_INTERSECT;
    }

    return OG_SUCCESS;
}

status_t sql_set_origin_query_block_name(sql_stmt_t *stmt, sql_query_t *query)
{
    text_t id_text = { 0 };
    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_UINT32_STRLEN + 1, (void **)&id_text.str));
    cm_uint32_to_text(query->block_info->origin_id, &id_text);
    uint32 qb_name_len = id_text.len + SEL_QUERY_BLOCK_PREFIX_LEN;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, qb_name_len, (void **)&query->block_info->origin_name.str));
    OG_RETURN_IFERR(cm_concat_string(&query->block_info->origin_name, qb_name_len, SEL_QUERY_BLOCK_PREFIX));
    cm_concat_text(&query->block_info->origin_name, qb_name_len, &id_text);

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t sql_parse_query(sql_stmt_t *stmt, sql_select_t *select_ctx, select_type_t type, word_t *word,
    sql_query_t **query_res, bool32 *found_rows_needed)
{
    status_t status;
    sql_query_t *query = NULL;

    OG_RETURN_IFERR(sql_stack_safe(stmt));

    OG_RETURN_IFERR(sql_create_select_node(stmt, select_ctx, KEY_WORD_SELECT));

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_query_t), (void **)&query));

    OG_RETURN_IFERR(sql_init_query(stmt, select_ctx, stmt->session->lex->loc, query));
    query->block_info->origin_id = ++stmt->context->query_count;
    OG_RETURN_IFERR(sql_set_origin_query_block_name(stmt, query));

    OG_RETURN_IFERR(sql_calc_found_rows_needed(stmt, select_ctx, type, found_rows_needed));

    *query_res = query;
    if (select_ctx->first_query == NULL) {
        select_ctx->first_query = query;
    }

    select_ctx->chain.last->query = query;

    OG_RETURN_IFERR(SQL_NODE_PUSH(stmt, query));
    OG_RETURN_IFERR(SQL_SSA_PUSH(stmt, &query->ssa));
    status = sql_parse_query_clauses(stmt, query, word);
    SQL_SSA_POP(stmt);
    SQL_NODE_POP(stmt);
    if (status == OG_ERROR) {
        return OG_ERROR;
    }
    return sql_set_table_qb_name(stmt, query);
}

static status_t sql_parse_select_wrapped(sql_stmt_t *stmt, sql_select_t *select_ctx, word_t *word)
{
    sql_select_t *sub_ctx = NULL;
    lex_t *lex = stmt->session->lex;

    if (sql_create_select_context(stmt, &word->text, SELECT_AS_SET, &sub_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (select_ctx->first_query == NULL) {
        select_ctx->first_query = sub_ctx->first_query;
        /* pass the calc_found_rows flag to the parent context and reset the subctx to false */
        if (sub_ctx->calc_found_rows) {
            select_ctx->calc_found_rows = OG_TRUE;
            sub_ctx->calc_found_rows = OG_FALSE;
        }
    }

    /* remove withas from temp sub_ctx to current select_ctx */
    if (sub_ctx->withass != NULL) {
        if (select_ctx->withass == NULL) {
            select_ctx->withass = sub_ctx->withass;
        } else {
            for (uint32 i = 0; i < sub_ctx->withass->count; i++) {
                sql_select_t *withas_ctx = (sql_select_t *)cm_galist_get(sub_ctx->withass, i);
                OG_RETURN_IFERR(cm_galist_insert(select_ctx->withass, withas_ctx));
            }
        }
    }

    APPEND_CHAIN(&select_ctx->chain, sub_ctx->root);
    return lex_fetch(lex, word);
}

static status_t sql_parse_single_select_context(sql_stmt_t *stmt, select_type_t type, word_t *word,
    sql_select_t **select_ctx, sql_query_t **query)
{
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;

    OG_RETURN_IFERR(lex_try_fetch(lex, "select", &result));
    if (result) {
        bool32 found_rows_needed = OG_FALSE;

        stmt->in_parse_query = OG_TRUE;
        OG_RETURN_IFERR(sql_parse_query(stmt, *select_ctx, type, word, query, &found_rows_needed));
        stmt->in_parse_query = OG_FALSE;

        if (found_rows_needed && type == SELECT_AS_RESULT) {
            (*query)->calc_found_rows = found_rows_needed;
        }
    } else {
        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (result) {
            OG_RETURN_IFERR(sql_parse_select_wrapped(stmt, *select_ctx, word));
        } else {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "SELECT or ( expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    OG_RETURN_IFERR(sql_parse_select_order_limit(stmt, *select_ctx, word, *query));
    if (word->type == WORD_TYPE_EOF) {
        return OG_SUCCESS;
    }

    if (word->id == KEY_WORD_FOR) {
        OG_RETURN_IFERR(sql_parse_for_update(stmt, *select_ctx, word));
        OG_RETURN_IFERR(lex_fetch(lex, word));
        if (word->type != WORD_TYPE_EOF) {
            OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(word));
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_parse_withas_factor(sql_stmt_t *stmt, lex_t *lex, word_t *word, sql_select_t *select_ctx,
    sql_withas_factor_t *factor)
{
    sql_text_t user;
    sql_text_t name;

    OG_RETURN_IFERR(lex_expected_fetch(lex, word));

    if (!IS_VARIANT(word)) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_decode_object_name(stmt, word, &user, &name));
    factor->user = user;
    factor->name = name;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "AS"));

    OG_RETURN_IFERR(lex_expected_fetch(lex, word));

    cm_remove_brackets(&word->text.value);

    if (word->type != WORD_TYPE_BRACKET) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing left parenthesis");
        return OG_ERROR;
    }

    factor->subquery_sql = word->text;
    OG_RETURN_IFERR(sql_create_select_context(stmt, &factor->subquery_sql, SELECT_AS_TABLE,
        (sql_select_t **)&factor->subquery_ctx));
    OG_RETURN_IFERR(cm_galist_insert(select_ctx->withass, factor->subquery_ctx));
    return OG_SUCCESS;
}

static status_t sql_parse_withas_context(sql_stmt_t *stmt, select_type_t type, word_t *word, sql_select_t *select_ctx)
{
    lex_t *lex = stmt->session->lex;
    sql_withas_factor_t *factor = NULL;
    sql_withas_t *withas = (sql_withas_t *)stmt->context->withas_entry;

    if (withas == NULL) {
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_withas_t), &stmt->context->withas_entry));
        withas = (sql_withas_t *)stmt->context->withas_entry;
        OG_RETURN_IFERR(sql_create_list(stmt, &withas->withas_factors));
        withas->cur_level = 0;
    }
    withas->cur_match_idx = withas->withas_factors->count;

    if (select_ctx->withass == NULL) {
        OG_RETURN_IFERR(sql_create_list(stmt, &select_ctx->withass));
    }

    // syntax: with t_tmp1 as (select ...),t_tmp2 as (select ...) select * from t_tmp1,t_tmp2
    while (1) {
        OG_RETURN_IFERR(cm_galist_new(withas->withas_factors, sizeof(sql_withas_factor_t), (void **)&factor));
        factor->depth = stmt->node_stack.depth;
        factor->level = withas->cur_level;

        OG_RETURN_IFERR(sql_parse_withas_factor(stmt, lex, word, select_ctx, factor));

        OG_RETURN_IFERR(lex_expected_fetch(lex, word));

        if (word->type == WORD_TYPE_SPEC_CHAR) {
            withas->cur_match_idx++;
            continue;
        } else if (word->id == KEY_WORD_SELECT || word->type == WORD_TYPE_BRACKET) {
            lex_back(lex, word);
            withas->cur_match_idx = OG_INVALID_ID32;
            break;
        } else {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "missing SELECT keyword");
            return OG_ERROR;
        }
    }
    withas->cur_level++;
    return OG_SUCCESS;
}

static status_t sql_try_get_duplicate_key_update(lex_t *lex, bool32 *result)
{
    LEX_SAVE(lex);
    if (lex_try_fetch3(lex, "DUPLICATE", "KEY", "UPDATE", result) != OG_SUCCESS) {
        LEX_RESTORE(lex);
        return OG_ERROR;
    }
    LEX_RESTORE(lex);

    return OG_SUCCESS;
}

status_t sql_parse_select_context(sql_stmt_t *stmt, select_type_t type, word_t *word, sql_select_t **select_ctx)
{
    lex_t *lex = stmt->session->lex;
    sql_query_t *query = NULL;
    bool32 has_set = OG_FALSE;
    bool32 result = OG_FALSE;

    OG_RETURN_IFERR(sql_alloc_select_context(stmt, type, select_ctx));

    lex->flags = LEX_WITH_OWNER | LEX_WITH_ARG;

    // try parse with as select clause
    OG_RETURN_IFERR(lex_try_fetch(lex, "WITH", &result));
    if (result) {
        if (IS_COORDINATOR) {
            OG_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "with as clause");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_parse_withas_context(stmt, type, word, *select_ctx));
    }

    while (1) {
        OG_RETURN_IFERR(sql_parse_single_select_context(stmt, type, word, select_ctx, &query));
        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (word->id == KEY_WORD_UNION || word->id == KEY_WORD_MINUS || word->id == KEY_WORD_EXCEPT ||
            word->id == KEY_WORD_INTERSECT) {
            has_set = OG_TRUE;
            OG_RETURN_IFERR(sql_create_select_node(stmt, *select_ctx, word->id));
            // for insert xxx select xxx on duplicate key update xxx clause
        } else if (word->id == KEY_WORD_ON) {
            OG_RETURN_IFERR(sql_try_get_duplicate_key_update(lex, &result));
            if (result) {
                lex_back(lex, word);
                break;
            }
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", W2S(word));
            return OG_ERROR;
        } else {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "invalid word '%s' found", W2S(word));
            return OG_ERROR;
        }

        /*
         * prevent the ambiguous limit/order by clause in the subset query which has no parentheses.
         *
         * the prevention relied on the following conditions.
         * has_set == OG_TRUE:  the entire SELECT statement encountered a set-operator(UNION/UNION ALL/MINUS)
         * if no set-operator encountered, simple SELECT does not need the check
         * query != NULL:  the query was not parsed by sql_parse_select_wrapped() which means no parenthes enclosed
         * type != SELECT_AS_SET: if SELECT_AS_SET, it means this check is being executed by
         * sql_parse_select_wrapped() which does not need this check
         */
        if (has_set == OG_TRUE && query != NULL &&
            (LIMIT_CLAUSE_OCCUR(&query->limit) || query->sort_items->count > 0)) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "\"LIMIT\" clause or \"ORDER BY\" clause of "
                "the subset should be placed inside the parentheses that enclose the SELECT");
            return OG_ERROR;
        }
    }

    OG_RETURN_IFERR(has_set && sql_create_select_order_limit(*select_ctx, query, word));
    if (sql_generate_select(*select_ctx) != OG_SUCCESS) {
        cm_try_set_error_loc(word->text.loc);
        return OG_ERROR;
    }
    return cm_galist_insert(stmt->context->selects, *select_ctx);
}

status_t sql_create_select_context(sql_stmt_t *stmt, sql_text_t *sql, select_type_t type, sql_select_t **select_ctx)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    uint32 save_flags = lex->flags;

    OG_RETURN_IFERR(sql_stack_safe(stmt));

    if (lex_push(lex, sql) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_parse_select_context(stmt, type, &word, select_ctx) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex->flags = save_flags;
    OG_RETURN_IFERR(lex_expected_end(lex));
    lex_pop(lex);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
