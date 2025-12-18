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
 * ogsql_merge_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/verifier/ogsql_merge_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_merge_verifier.h"
#include "ogsql_insert_verifier.h"
#include "ogsql_select_verifier.h"
#include "ogsql_update_verifier.h"
#include "ogsql_table_verifier.h"
#include "base_compiler.h"
#include "cond_parser.h"
#include "ogsql_privilege.h"
#include "ogsql_hint_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_create_update_policies_cond(sql_verifier_t *verif, cond_tree_t **cond, text_t *clause_text)
{
    cond_tree_t *plcy_cond_tree = NULL;
    bool32 is_expr = OG_TRUE;
    sql_text_t cond_text;

    if (CM_IS_EMPTY(clause_text)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_copy_text(verif->stmt->context, clause_text, &cond_text.value));
    cond_text.loc.column = 1;
    cond_text.loc.line = 1;

    OG_RETURN_IFERR(sql_create_cond_from_text(verif->stmt, &cond_text, &plcy_cond_tree, &is_expr));

    if ((*cond) == NULL) {
        (*cond) = plcy_cond_tree;
        return OG_SUCCESS;
    }
    return sql_add_cond_node((*cond), plcy_cond_tree->root);
}

static status_t sql_init_merge_policies(sql_verifier_t *verif, sql_table_t *table, sql_merge_t *merge_ctx,
    bool32 is_insert)
{
    text_t clause_text;
    bool32 exists;
    OGSQL_SAVE_STACK(verif->stmt);
    if (sql_get_table_policies(verif, table, &clause_text, &exists) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(verif->stmt);
        return OG_ERROR;
    }

    if (!exists) {
        OGSQL_RESTORE_STACK(verif->stmt);
        return OG_SUCCESS;
    }
    cond_tree_t **cond = is_insert ? &merge_ctx->insert_filter_cond : &merge_ctx->update_filter_cond;
    if (sql_create_update_policies_cond(verif, cond, &clause_text) != OG_SUCCESS) {
        cm_reset_error();
        OGSQL_RESTORE_STACK(verif->stmt);
        OG_THROW_ERROR(ERR_POLICY_EXEC_FUNC, "function convert to condition failed");
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(verif->stmt);
    return OG_SUCCESS;
}

static status_t sql_merge_handle_policies(sql_verifier_t *verif, sql_merge_t *merge_ctx, bool32 is_insert)
{
    sql_array_t *tables = &merge_ctx->query->tables;
    for (uint32 i = 0; i < tables->count; i++) {
        sql_table_t *table = (sql_table_t *)sql_array_get(tables, i);
        if (table->type != NORMAL_TABLE) {
            continue;
        }
        if (sql_init_merge_policies(verif, table, merge_ctx, is_insert) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}


static status_t sql_verify_merge_update(sql_stmt_t *stmt, sql_merge_t *merge_ctx)
{
    sql_verifier_t verif = { 0 };
    uint32 i;
    column_value_pair_t *pair = NULL;
    expr_tree_t *expr = NULL;

    if (merge_ctx->update_ctx == NULL) {
        return OG_SUCCESS;
    }

    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_ROWID | SQL_EXCL_PRIOR | SQL_EXCL_ROWNUM |
        SQL_EXCL_ROWSCN | SQL_EXCL_JOIN | SQL_EXCL_GROUPING | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;
    verif.curr_query = merge_ctx->query;

    for (i = 0; i < merge_ctx->update_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(merge_ctx->update_ctx->pairs, i);
        expr = (expr_tree_t *)cm_galist_get(pair->exprs, 0);

        verif.tables = &merge_ctx->update_ctx->query->tables;
        if (sql_verify_update_pair(&stmt->session->knl_session, &verif, pair, merge_ctx->update_ctx) != OG_SUCCESS) {
            return OG_ERROR;
        }

        verif.tables = &merge_ctx->query->tables;
        if (sql_verify_expr(&verif, expr) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (verif.has_ddm_col == OG_TRUE) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return OG_ERROR;
    }

    if (sql_verify_upd_object_pairs(&verif, merge_ctx->update_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_merge_handle_policies(&verif, merge_ctx, OG_FALSE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (merge_ctx->update_filter_cond == NULL) {
        return OG_SUCCESS;
    }

    verif.tables = &merge_ctx->query->tables;
    return sql_verify_cond(&verif, merge_ctx->update_filter_cond);
}

static status_t sql_verify_merge_insert(sql_stmt_t *stmt, sql_merge_t *merge_ctx)
{
    sql_verifier_t verif = { 0 };

    if (merge_ctx->insert_ctx == NULL) {
        return OG_SUCCESS;
    }

    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_ROWID | SQL_EXCL_PRIOR | SQL_EXCL_ROWNUM |
        SQL_EXCL_ROWSCN | SQL_EXCL_JOIN | SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING | SQL_EXCL_ROWNODEID;
    verif.tables = &merge_ctx->query->tables;
    verif.merge_insert_status = SQL_MERGE_INSERT_COLUMNS;
    verif.curr_query = merge_ctx->query;

    if (sql_verify_insert_context(&stmt->session->knl_session, &verif, merge_ctx->insert_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (verif.has_ddm_col == OG_TRUE) {
        OG_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
        return OG_ERROR;
    }

    if (sql_merge_handle_policies(&verif, merge_ctx, OG_TRUE) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (merge_ctx->insert_filter_cond == NULL) {
        return OG_SUCCESS;
    }
    verif.merge_insert_status = SQL_MERGE_INSERT_COND;
    return sql_verify_cond(&verif, merge_ctx->insert_filter_cond);
}

static status_t sql_verify_merge_tabs_type(sql_merge_t *merge_ctx)
{
    sql_table_t *sql_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
    if (sql_table->type == SUBSELECT_AS_TABLE || sql_table->type == WITH_AS_TABLE) {
        OG_SRC_THROW_ERROR(sql_table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "merge into", "subquery");
        return OG_ERROR;
    }
    {
        if (sql_table->entry->dc.type > DICT_TYPE_TABLE_EXTERNAL) {
            OG_SRC_THROW_ERROR(sql_table->name.loc, ERR_OPERATIONS_NOT_SUPPORT, "parse table", "view or system table");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t sql_verify_merge(sql_stmt_t *stmt, sql_merge_t *merge_ctx)
{
    sql_verifier_t verif = { 0 };
    verif.stmt = stmt;
    verif.context = stmt->context;
    verif.pl_dc_lst = merge_ctx->pl_dc_lst;
    verif.curr_query = merge_ctx->query;
    plc_get_verify_obj(stmt, &verif);
    verif.excl_flags = SQL_MERGE_EXCL;
    verif.do_expr_optmz = OG_TRUE;

    OG_RETURN_IFERR(sql_verify_tables(&verif, merge_ctx->query));
    verif.tables = &merge_ctx->query->tables;

    OG_RETURN_IFERR(sql_verify_merge_tabs_type(merge_ctx));
    OG_RETURN_IFERR(sql_verify_cond(&verif, merge_ctx->query->cond));
    OG_RETURN_IFERR(sql_verify_query_joins(&verif, merge_ctx->query));

    sql_table_t *using_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 1);
    OG_RETURN_IFERR(sql_create_project_columns(stmt, using_table));
    if (sql_verify_merge_update(stmt, merge_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_verify_merge_insert(stmt, merge_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    merge_ctx->hint_info = stmt->context->hint_info;
    og_hint_verify(verif.stmt, OGSQL_TYPE_MERGE, (void *)merge_ctx);

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
