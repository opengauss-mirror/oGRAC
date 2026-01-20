/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * expl_explain_create.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_explain_create.c
 *
 * -------------------------------------------------------------------------
 */

#include "expl_explain_create.h"
#include "expl_executor.h"
#include "ddl_executor.h"

static status_t og_init_vartext(sql_stmt_t *statement, var_text_t *content)
{
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&(content->str)));
    (void)memset_s(content->str, OG_MAX_ROW_SIZE, 0, OG_MAX_ROW_SIZE);
    content->cap = OG_MAX_ROW_SIZE;
    content->len = 0;
    return OG_SUCCESS;
}

static status_t og_make_index_build_row(sql_stmt_t *statement, expl_helper_t *helper, knl_index_def_t *index_def,
    uint32 depth)
{
    const char *unique_status = index_def->unique ? " UNIQUE" : " NON UNIQUE";
    const char *part_status = index_def->parted ? " (LOCAL)" : " (GLOBAL)";
    knl_dictionary_t dict;
    var_text_t content = { 0 };

    OG_RETURN_IFERR(og_init_vartext(statement, &content));
    OG_RETURN_IFERR(cm_concat_var_string(&content, "INDEX BUILD"));
    OG_RETURN_IFERR(cm_concat_var_string(&content, unique_status));
    OG_RETURN_IFERR(dc_open(&statement->session->knl_session, &index_def->user, &index_def->table, &dict));
    dc_entity_t *entity = DC_ENTITY(&dict);
    table_t *table = &entity->table;

    if (table->desc.parted) {
        if (cm_concat_var_string(&content, part_status) != OG_SUCCESS) {
            dc_close(&dict);
            return OG_ERROR;
        }
    }
    dc_close(&dict);
    return expl_format_plan_node_row(statement, helper, NULL, depth, content.str, &index_def->user,
        &index_def->name, NULL);
}

static status_t og_make_index_create_method_row(sql_stmt_t *statement, expl_helper_t *helper,
    knl_index_def_t *index_def, uint32 depth)
{
    var_text_t content = { 0 };

    OG_RETURN_IFERR(og_init_vartext(statement, &content));
    OG_RETURN_IFERR(cm_concat_var_string(&content, "SORT CREATE INDEX"));
    if (index_def->parallelism > 1) {
        OG_RETURN_IFERR(cm_concat_var_string(&content, "(p "));
        cm_concat_int32((text_t *)&content, (uint32)(content.cap - content.len), index_def->parallelism);
        OG_RETURN_IFERR(cm_concat_var_string(&content, ")"));
    }
    return expl_format_plan_node_row(statement, helper, NULL, depth, content.str, NULL, NULL, NULL);
}

static status_t expl_make_create_index_plan_row(sql_stmt_t *statement, expl_helper_t *helper)
{
    knl_index_def_t *index_def = (knl_index_def_t*)statement->context->entry;
    uint32 depth = 0;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, NULL, depth++, "CREATE INDEX STATEMENT",
        NULL, NULL, NULL));
    OG_RETURN_IFERR(og_make_index_build_row(statement, helper, index_def, depth++));
    OG_RETURN_IFERR(og_make_index_create_method_row(statement, helper, index_def, depth++));
    return expl_format_plan_node_row(statement, helper, NULL, depth++, "TABLE ACCESS FULL",
        &index_def->user, &index_def->table, NULL);
}

static status_t expl_make_create_indexes_plan_row(sql_stmt_t *statement, expl_helper_t *helper)
{
    knl_indexes_def_t *defs = (knl_indexes_def_t*)statement->context->entry;
    knl_index_def_t *index_def = NULL;
    uint32 depth = 0;
    uint32 basic_depth;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, NULL, depth++, "CREATE INDEXES STATEMENT",
        NULL, NULL, NULL));
    basic_depth = depth;
    for (uint32 i = 0; i < defs->index_count; i++) {
        index_def = &defs->indexes_def[i];
        OG_RETURN_IFERR(og_make_index_build_row(statement, helper, index_def, depth++));
        OG_RETURN_IFERR(og_make_index_create_method_row(statement, helper, index_def, depth++));
        OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, NULL, depth++, "TABLE ACCESS FULL",
            &index_def->user, &index_def->table, NULL));
        depth = basic_depth;
    }

    return OG_SUCCESS;
}

static status_t expl_format_create_index_plan(sql_stmt_t *statement, sql_cursor_t *cursor)
{
    expl_helper_t helper = { 0 };
    status_t ret;
    OGSQL_SAVE_STACK(statement);
    OG_RETURN_IFERR(expl_init_executors(statement, cursor, &helper, NULL));

    if (statement->context->type == OGSQL_TYPE_CREATE_INDEX) {
        OG_RETURN_IFERR(expl_make_create_index_plan_row(statement, &helper));
    } else {
        OG_RETURN_IFERR(expl_make_create_indexes_plan_row(statement, &helper));
    }

    expl_close_segment(statement, cursor);

    ret = expl_send_explain_rows(statement, cursor, &helper);
    expl_release_executors(&helper);
    OGSQL_RESTORE_STACK(statement);

    return ret;
}

static status_t og_make_cteate_as_select_plan(sql_stmt_t *statement, expl_helper_t *helper, plan_node_t *plan_node,
    knl_table_def_t *table_def)
{
    uint32 depth = 0;
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth++, "CREATE TABLE STATEMENT",
        NULL, NULL, NULL));
    if (statement->context->withas_entry != NULL) {
        OG_RETURN_IFERR(expl_format_withas_plan(statement, helper, plan_node, depth));
    }
    OG_RETURN_IFERR(expl_format_plan_node_row(statement, helper, plan_node, depth++, "LOAD AS SELECT",
        &table_def->schema, &table_def->name, NULL));
    return expl_format_plan_node(statement, helper, plan_node->select_p.next, depth);
}

static status_t og_init_create_as_select_vmc(sql_stmt_t *statement, sql_select_t *select_ctx)
{
    sql_free_vmemory(statement);
    if (statement->context->withas_entry != NULL) {
        OG_RETURN_IFERR(sql_init_withas_vmc(statement, (sql_withas_t*)statement->context->withas_entry));
    }
    return sql_init_select_vmc(statement, select_ctx->root);
}

static status_t expl_format_create_as_select_plan(sql_stmt_t *statement, sql_cursor_t *cursor, text_t *plan_text)
{
    knl_table_def_t *table_def = (knl_table_def_t *)statement->context->entry;
    sql_select_t *select_ctx = (sql_select_t *)statement->context->supplement;
    status_t ret;
    expl_helper_t helper = { 0 };

    if (select_ctx->plan == NULL) {
        if (og_init_create_as_select_vmc(statement, select_ctx) != OG_SUCCESS) {
            sql_free_vmemory(statement);
            return OG_ERROR;
        }
        if (sql_generate_select_plan(statement, select_ctx, NULL) != OG_SUCCESS) {
            sql_free_vmemory(statement);
            return OG_ERROR;
        }
        sql_free_vmemory(statement);
    }

    OGSQL_SAVE_STACK(statement);
    sql_init_ssa_cursor_maps(cursor, OG_MAX_SUBSELECT_EXPRS);
    OG_RETURN_IFERR(expl_init_executors(statement, cursor, &helper, NULL));

    if (og_make_cteate_as_select_plan(statement, &helper, select_ctx->plan, table_def) != OG_SUCCESS) {
        expl_release_executors(&helper);
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    expl_close_segment(statement, cursor);

    // record max-formatted-size for next fetch
    ret = expl_record_fmt_sizes(cursor, &helper);
    if (ret != OG_SUCCESS) {
        expl_release_executors(&helper);
        OGSQL_RESTORE_STACK(statement);
        return OG_ERROR;
    }

    // get explain result and write to response package
    ret = expl_send_explain_rows(statement, cursor, &helper);
    expl_release_executors(&helper);
    OGSQL_RESTORE_STACK(statement);
    return ret;
}

static status_t expl_format_normal_create_table_plan(sql_stmt_t *statement, sql_cursor_t *cursor)
{
    expl_helper_t helper = { 0 };
    status_t ret;
    OG_RETURN_IFERR(expl_init_executors(statement, cursor, &helper, NULL));

    OG_RETURN_IFERR(expl_format_plan_node_row(statement, &helper, NULL, 0, "CREATE TABLE STATEMENT",
        NULL, NULL, NULL));

    expl_close_segment(statement, cursor);

    ret = expl_send_explain_rows(statement, cursor, &helper);
    expl_release_executors(&helper);
    return ret;
}

static status_t expl_format_create_table_plan(sql_stmt_t *statement, sql_cursor_t *cursor, text_t *plan_text)
{
    knl_table_def_t *tab_def = (knl_table_def_t *)statement->context->entry;
    if (tab_def->create_as_select) {
        return expl_format_create_as_select_plan(statement, cursor, plan_text);
    }

    return expl_format_normal_create_table_plan(statement, cursor);
}

status_t og_explain_create_plan(sql_stmt_t *statement, text_t *plan_text)
{
    sql_cursor_t *cursor = NULL;
    status_t ret;

    OG_RETURN_IFERR(expl_pre_execute(statement, &cursor));
    OGSQL_SAVE_STACK(statement);

    if (statement->context->type == OGSQL_TYPE_CREATE_TABLE) {
        ret = expl_format_create_table_plan(statement, cursor, plan_text);
    } else {
        ret = expl_format_create_index_plan(statement, cursor);
    }

    OGSQL_RESTORE_STACK(statement);
    if (plan_text != NULL || ret != OG_SUCCESS) {
        sql_free_cursor(statement, cursor);
    }
    return ret;
}