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
 * ogsql_transform.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_transform.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_transform.h"
#include "ogsql_verifier.h"
#include "table_parser.h"
#include "ogsql_select_parser.h"
#include "ogsql_table_func.h"
#include "ogsql_func.h"
#include "srv_instance.h"
#include "ogsql_cond_rewrite.h"
#include "ogsql_plan.h"
#include "ogsql_subquery_rewrite.h"

#ifdef __cplusplus
extern "C" {
#endif

static transform_sql_t g_transformers[] = {
    { OGSQL_TYPE_NONE,    ogsql_transform_dummy        },
    { OGSQL_TYPE_SELECT,  ogsql_optimize_logic_select  },
    { OGSQL_TYPE_UPDATE,  ogsql_optimize_logic_update  },
    { OGSQL_TYPE_INSERT,  ogsql_optimize_logic_insert  },
    { OGSQL_TYPE_DELETE,  ogsql_optimize_logic_delete  },
    { OGSQL_TYPE_MERGE,   ogsql_optimize_logic_merge   },
    { OGSQL_TYPE_REPLACE, ogsql_optimize_logic_replace },
    };

static status_t ogsql_optimize_logic_select_node_p1(sql_stmt_t *statement, select_node_t *node);
static status_t ogsql_optimize_logic_select_node_p2(sql_stmt_t *statement, select_node_t *node);

status_t ogsql_transform_dummy(sql_stmt_t *statement, void *entry)
{
    text_t *ogsql = (text_t *)&statement->session->lex->text;
    if (ogsql) {
        OG_LOG_DEBUG_INF("transfrom sql nothing to do, SQL is %s.", T2S(ogsql));
    }

    return OG_SUCCESS;
}

status_t og_create_sqltable(sql_stmt_t *statement, sql_query_t *qry, sql_select_t *select)
{
    sql_table_t *sql_tab = NULL;

    (void)sql_init_join_assist(statement, &qry->join_assist);
    OG_RETURN_IFERR(sql_create_array(statement->context, &qry->tables, "JOINS TABLES", OG_MAX_JOIN_TABLES));
    OG_RETURN_IFERR(sql_array_new(&qry->tables, sizeof(sql_table_t), (void **)&sql_tab));
    sql_tab->id = 0;
    sql_tab->type = SUBSELECT_AS_TABLE;
    sql_tab->select_ctx = select;
    OG_RETURN_IFERR(sql_copy_text(statement->context, &qry->block_info->origin_name, &sql_tab->qb_name));
    TABLE_CBO_ATTR_OWNER(sql_tab) = qry->vmc;

    sql_query_t *subqry = sql_tab->select_ctx->first_query;
    cm_bilist_init(&(sql_tab)->query_fields);
    uint32 i = 0;
    while (i < subqry->rs_columns->count) {
        rs_column_t *col = (rs_column_t *)cm_galist_get(subqry->rs_columns, i);
        query_field_t field;
        SQL_SET_QUERY_FIELD_INFO(&field, col->datatype, i, col->v_col.is_array, col->v_col.ss_start, col->v_col.ss_end);
        if (sql_table_cache_query_field(statement, sql_tab, &field) != OG_SUCCESS) {
            return OG_ERROR;
        }
        i++;
    }

    cm_bilist_init(&sql_tab->func_expr);
    return OG_SUCCESS;
}

status_t og_get_join_cond_from_table_cond(sql_stmt_t *statement, sql_array_t *l_tbls, sql_array_t *r_tbls,
                                          cond_tree_t *ctree, bilist_t *jcond_blst)
{
    bool32 has_join_cond = OG_FALSE;
    join_cond_t *jcond = NULL;
    sql_table_t *left_tbl = NULL;
    sql_table_t *right_tbl = NULL;
    uint32 m = 0;
    uint32 n = 0;
    uint32 left_count = l_tbls->count;
    uint32 right_count = r_tbls->count;
    bool32 is_same_array = (l_tbls == r_tbls);
    
    if (ctree == NULL) {
        cm_bilist_init(jcond_blst);
        return OG_SUCCESS;
    }

    cm_bilist_init(jcond_blst);
    OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(join_cond_t), (void **)&jcond));
    cm_galist_init(&jcond->cmp_nodes, statement, sql_stack_alloc);

    while (m < left_count) {
        n = 0;
        left_tbl = (sql_table_t *)sql_array_get(l_tbls, m);
        while (n < right_count) {
            right_tbl = (sql_table_t *)sql_array_get(r_tbls, n);
            if (is_same_array && left_tbl->id <= right_tbl->id) {
                n++;
                continue;
            }
            has_join_cond = OG_FALSE;
            OG_RETURN_IFERR(sql_extract_join_from_cond(ctree->root, left_tbl->id, right_tbl->id,
                                                       &jcond->cmp_nodes, &has_join_cond));
            if (has_join_cond) {
                jcond->table1 = left_tbl->id;
                jcond->table2 = right_tbl->id;
                cm_bilist_add_tail(&jcond->bilist_node, jcond_blst);
                OG_RETURN_IFERR(sql_stack_alloc(statement, sizeof(join_cond_t), (void **)&jcond));
                cm_galist_init(&jcond->cmp_nodes, statement, sql_stack_alloc);
            }
            n++;
        }
        m++;
    }
    
    return OG_SUCCESS;
}

status_t ogsql_optimize_logically(sql_stmt_t *statement)
{
    uint32 count = sizeof(g_transformers) / sizeof(transform_sql_t) - 1;
    uint32 index = (uint32)statement->context->type;
    SAVE_AND_RESET_NODE_STACK(statement);

    // first optmize logically with as sql.
    if (ogsql_optimize_logic_withas(statement, statement->context->withas_entry)) {
        return OG_ERROR;
    }

    if (index <= count) {
        OG_RETURN_IFERR(g_transformers[index].tranform(statement, statement->context->entry));
    }

    SQL_RESTORE_NODE_STACK(statement);
    return OG_SUCCESS;
}

status_t ogsql_transform_one_rule(sql_stmt_t *statement, sql_query_t *query, const char *rule_name,
                                  sql_tranform_rule_func_t proc)
{
    if (proc(statement, query) == OG_SUCCESS) {
        OG_LOG_DEBUG_INF("Succeed to transform rule:%s", rule_name);
        return OG_SUCCESS;
    }
    return OG_ERROR;
}

static status_t ogsql_apply_rule_set_1(sql_stmt_t *statement, sql_query_t *qry)
{
    return OG_SUCCESS;
}

static status_t ogsql_tranf_table_type(sql_stmt_t *statement, sql_query_t *query)
{
    sql_table_t *table = (sql_table_t *)sql_array_get(&query->tables, 0);
    if (table->type != FUNC_AS_TABLE) {
        return OG_SUCCESS;
    }
    if (table->func.desc->method == TFM_MEMORY) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(sql_regist_table(statement, table));
    OG_RETURN_IFERR(sql_init_table_dc(statement, table));
    table->type = NORMAL_TABLE;
    table->tf_scan_flag = table->func.desc->get_scan_flag ? table->func.desc->get_scan_flag(&table->func)
                                                          : SEQ_SQL_SCAN;
    if (table->func.desc->method == TFM_TABLE_ROW) {
        query->owner->rs_type = RS_TYPE_ROW;
        statement->rs_type = RS_TYPE_ROW;
    }
    return OG_SUCCESS;
}

status_t ogsql_apply_rule_set_2(sql_stmt_t *statement, sql_query_t *qry)
{
    OG_RETURN_IFERR(ogsql_tranf_table_type(statement, qry));
    // transform sub-select to table
    OGSQL_RETURN_IF_APPLY_RULE_ERR(statement, qry, og_transf_subquery_rewrite);
    return OG_SUCCESS;
}

static status_t ogsql_tranform_subselect_in_expr(sql_stmt_t *statement, sql_query_t *query, bool32 is_phase_1)
{
    sql_array_t *ssa = &query->ssa;
    sql_select_t *select = NULL;
    uint32 index = 0;
    while (index < ssa->count) {
        select = (sql_select_t *)sql_array_get(ssa, index++);
        if (is_phase_1) {
            OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p1(statement, select->root));
        } else {
            OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p2(statement, select->root));
        }
    }

    return OG_SUCCESS;
}

static inline bool32 ogsql_check_subselect_if_as_table(sql_table_t *table)
{
    if ((table->type == SUBSELECT_AS_TABLE || table->type == VIEW_AS_TABLE) &&
        table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t ogsql_tranform_subselect_as_table(sql_stmt_t *statement, sql_query_t *query, bool32 is_phase_1)
{
    sql_array_t *tables = &query->tables;
    sql_table_t *tab = NULL;
    uint32 index = 0;
    while (index < tables->count) {
        tab = (sql_table_t *)sql_array_get(tables, index++);
        if (ogsql_check_subselect_if_as_table(tab)) {
            if (is_phase_1) {
                OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p1(statement, tab->select_ctx->root));
            } else {
                // the phase 2 apply all rule for subtable.
                OG_RETURN_IFERR(ogsql_optimize_logic_select(statement, tab->select_ctx));
            }
            continue;
        }
        // continue to optimize after subquery rewrite to table.
        if ((is_phase_1 == OG_FALSE) && (tab->type == SUBSELECT_AS_TABLE)) {
            OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p2(statement, tab->select_ctx->root));
        }
    }

    return OG_SUCCESS;
}

status_t ogsql_transform_query(sql_stmt_t *statement, sql_query_t *query, bool32 is_phase_1)
{
    SET_NODE_STACK_CURR_QUERY(statement, query);
    if (is_phase_1) {
        if (ogsql_apply_rule_set_1(statement, query) != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("Failed to apply rule set1.");
            return OG_ERROR;
        }
    } else {
        if (ogsql_apply_rule_set_2(statement, query) != OG_SUCCESS) {
            OG_LOG_DEBUG_ERR("Failed to apply rule set2.");
            return OG_ERROR;
        }

        if (query->is_s_query) {
            SQL_RESTORE_NODE_STACK(statement);
            return OG_SUCCESS;
        }
    }

    // transform subselect in expressions.
    OG_RETURN_IFERR(ogsql_tranform_subselect_in_expr(statement, query, is_phase_1));
    // transform subselect in 'from table'.
    OG_RETURN_IFERR(ogsql_tranform_subselect_as_table(statement, query, is_phase_1));
    SQL_RESTORE_NODE_STACK(statement);

    return OG_SUCCESS;
}

// the first phase
static status_t ogsql_optimize_logic_select_node_p1(sql_stmt_t *statement, select_node_t *node)
{
    if (node->type == SELECT_NODE_QUERY) {
        return ogsql_transform_query(statement, node->query, OG_TRUE);
    }
    OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p1(statement, node->left));
    return ogsql_optimize_logic_select_node_p1(statement, node->right);
}

// the last phase
static status_t ogsql_optimize_logic_select_node_p2(sql_stmt_t *statement, select_node_t *node)
{
    if (node->type == SELECT_NODE_QUERY) {
        return ogsql_transform_query(statement, node->query, OG_FALSE);
    }
    OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p2(statement, node->left));
    return ogsql_optimize_logic_select_node_p2(statement, node->right);
}

status_t ogsql_optimize_logic_select(sql_stmt_t *statement, void *entry)
{
    select_node_t *node = ((sql_select_t *)entry)->root;
    OG_RETURN_IFERR(ogsql_optimize_logic_select_node_p1(statement, node));
    return ogsql_optimize_logic_select_node_p2(statement, node);
}

status_t ogsql_optimize_logic_insert(sql_stmt_t *statement, void *entry)
{
    sql_insert_t *insert = (sql_insert_t *)entry;
    if (insert->select_ctx) {
        return ogsql_optimize_logic_select(statement, insert->select_ctx);
    }
    return OG_SUCCESS;
}

status_t ogsql_optimize_logic_replace(sql_stmt_t *statement, void *entry)
{
    sql_replace_t *replace = (sql_replace_t *)entry;
    return ogsql_optimize_logic_insert(statement, &replace->insert_ctx);
}

status_t ogsql_optimize_logic_delete(sql_stmt_t *statement, void *entry)
{
    sql_delete_t *delete = (sql_delete_t *)entry;
    OG_RETURN_IFERR(ogsql_transform_query(statement, delete->query, OG_TRUE));
    return ogsql_transform_query(statement, delete->query, OG_FALSE);
}

status_t ogsql_optimize_logic_update(sql_stmt_t *statement, void *entry)
{
    sql_update_t *update = (sql_update_t *)entry;
    if (ogsql_transform_query(statement, update->query, OG_TRUE)) {
        OG_LOG_DEBUG_ERR("Failed to transform update sql in phase 1.");
        return OG_ERROR;
    }

    if (ogsql_transform_query(statement, update->query, OG_FALSE)) {
        OG_LOG_DEBUG_ERR("Failed to transform update sql in phase 2.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogsql_optimize_logic_merge(sql_stmt_t *statement, void *entry)
{
    sql_merge_t *merge = (sql_merge_t *)entry;
    // transform subselect in expressions.
    if (ogsql_tranform_subselect_in_expr(statement, merge->query, OG_TRUE)) {
        OG_LOG_DEBUG_ERR("Failed to transform merge sql in expr in phase 1.");
        return OG_ERROR;
    }

    // transform subselect in expressions.
    if (ogsql_tranform_subselect_in_expr(statement, merge->query, OG_FALSE)) {
        OG_LOG_DEBUG_ERR("Failed to transform merge sql in expr in phase 2.");
        return OG_ERROR;
    }

    // transform subselect in 'from table', apply all rules.
    if (ogsql_tranform_subselect_as_table(statement, merge->query, OG_FALSE)) {
        OG_LOG_DEBUG_ERR("Failed to transform merge sql in subtable.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t ogsql_optimize_logic_withas(sql_stmt_t *statement, void *entry)
{
    sql_withas_t *withas = (sql_withas_t *)entry;
    uint32 i = 0;
    if (!withas) {
        return OG_SUCCESS;
    }

    while (i < withas->withas_factors->count) {
        sql_withas_factor_t *item = (sql_withas_factor_t *)cm_galist_get(withas->withas_factors, i++);
        if (ogsql_optimize_logic_select(statement, item->subquery_ctx)) {
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
