/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "plan_join.h"
#include "cbo_base.h"
#include "plan_assist.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline status_t og_choose_table_index(sql_stmt_t *statement, plan_assist_t *p_ast, sql_query_t *qry)
{
    p_ast->has_parent_join = (bool8)p_ast->query->cond_has_acstor_col;
    const uint32 check_flags = CBO_CHECK_FILTER_IDX | CBO_CHECK_JOIN_IDX;
    CBO_SET_FLAGS(p_ast, check_flags);
    return sql_check_table_indexable(statement, p_ast, p_ast->tables[0], qry->cond);
}

// 创建查询的join tree，用于rewrite, 获取索引使用情况和代价
status_t og_create_qry_jtree_4_rewrite(sql_stmt_t *statement, sql_query_t *qry, sql_join_node_t **result_jnode)
{
    if (IS_WITHAS_QUERY(qry) && qry->join_root != NULL) {
        OG_RETVALUE_IFTRUE(result_jnode == NULL, OG_SUCCESS);
        *result_jnode = qry->join_root;
    }

    plan_assist_t p_ast;
    sql_init_plan_assist(statement, &p_ast, qry, SQL_QUERY_NODE, NULL);

    SQL_LOG_OPTINFO(statement, ">>> Initializing join tree construction for query, table count=%u", qry->tables.count);

    status_t status;
    sql_join_node_t *root_jnode = NULL;
    if (p_ast.table_count > 1) {
        status = sql_build_join_tree(statement, &p_ast, &root_jnode);
    } else {
        status = og_choose_table_index(statement, &p_ast, qry);
    }

    if (status == OG_SUCCESS) {
        if (result_jnode != NULL) {
            *result_jnode = root_jnode;
        }

        if (qry->join_assist.join_node != NULL && root_jnode != NULL) {
            qry->join_assist.join_node->cost = root_jnode->cost;
        }
        SQL_LOG_OPTINFO(statement, ">>> Succeed to  create query tree");
        return OG_SUCCESS;
    }

    SQL_LOG_OPTINFO(statement, ">>> Failed to create query tree, status=%u", status);
    return status;
}

void og_get_query_cbo_cost(sql_query_t *qry, cbo_cost_t *qry_cost)
{
    if (qry->tables.count == 1) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, 0);
        qry_cost->cost = tbl->cost;
        qry_cost->card = tbl->card;
        return;
    }

    if (qry->join_root) {
        *qry_cost = qry->join_root->cost;
    } else {
        *qry_cost = qry->join_assist.join_node->cost;
    }
}

void og_free_query_vmc(sql_query_t *qry)
{
    if (IS_WITHAS_QUERY(qry)) {
        return;
    }

    bool8 cte_flag = OG_FALSE;
    uint32 table_idx = 0;
    while (table_idx < qry->tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&qry->tables, table_idx);
        table_idx++;

        if (tbl->type == WITH_AS_TABLE) {
            cte_flag = OG_TRUE;
            continue;
        }

        // 注意：当前plan没有使用表的 CBO 状态

        if (tbl->type == SUBSELECT_AS_TABLE || tbl->type == VIEW_AS_TABLE) {
            og_free_select_node_vmc(tbl->select_ctx->root);
        }
    }

    qry->join_root = NULL;
    if (!cte_flag && qry->vmc != NULL) {
        vmc_free(qry->vmc);
    }
}

void og_free_select_node_vmc(select_node_t *slct_node)
{
    if (!slct_node) {
        return;
    }

    if (SELECT_NODE_QUERY == slct_node->type) {
        og_free_query_vmc(slct_node->query);
    } else {
        og_free_select_node_vmc(slct_node->left);
        og_free_select_node_vmc(slct_node->right);
    }
}

static status_t og_cbo_check_index_cost(sql_stmt_t *statement, sql_query_t *qry,
    ck_type_t check_type, bool32 *is_rewritable)
{
    // 待实现：用hash semi join跟走索引的NL代价做比较
    *is_rewritable = OG_TRUE;
    return OG_SUCCESS;
}

status_t og_check_index_4_rewrite(sql_stmt_t *statement, sql_query_t *qry, ck_type_t type, bool32 *is_rewritable)
{
    if (CBO_ON) {
        status_t status = OG_ERROR;
        SYNC_POINT_GLOBAL_START(CBO_CANNOT_REWRITE_BY_INDEX, (int32 *)is_rewritable, OG_FALSE);
        status = og_cbo_check_index_cost(statement, qry, type, is_rewritable);
        SYNC_POINT_GLOBAL_END;
        return status;
    }
    return OG_SUCCESS;
}

void og_set_dst_qry_field(query_field_t *src_field, query_field_t *dst_field)
{
    dst_field->start = src_field->start;
    dst_field->end = src_field->end;
    dst_field->col_id = src_field->col_id;
    dst_field->is_cond_col = src_field->is_cond_col;
    dst_field->ref_count = src_field->ref_count;
    dst_field->datatype = src_field->datatype;
    dst_field->is_array = src_field->is_array;
}

status_t og_clone_qry_fields(sql_stmt_t *statement, sql_table_t *src_tbl, sql_table_t *dest_tbl)
{
    query_field_t *dst_field = NULL;
    cm_bilist_init(&dest_tbl->query_fields);
    bilist_node_t *src_blst_node = cm_bilist_head(&src_tbl->query_fields);

    while (src_blst_node != NULL) {
        query_field_t *src_field = BILIST_NODE_OF(query_field_t, src_blst_node, bilist_node);
        OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(query_field_t), (void **)&dst_field));
        og_set_dst_qry_field(src_field, dst_field);
        cm_bilist_add_tail(&dst_field->bilist_node, &dest_tbl->query_fields);
        src_blst_node = BINODE_NEXT(src_blst_node);
    }

    return OG_SUCCESS;
}

void og_disable_func_idx_only(sql_query_t *sql_qry)
{
    sql_table_t *tbl = NULL;
    uint32 i = 0;
    while (i < sql_qry->tables.count) {
        tbl = (sql_table_t *)sql_array_get(&sql_qry->tables, i);
        if (tbl->scan_mode == SCAN_MODE_INDEX && tbl->index->is_func && INDEX_ONLY_SCAN(tbl->scan_flag)) {
            CM_CLEAN_FLAG(tbl->scan_flag, RBO_INDEX_ONLY_FLAG);
            tbl->index_ffs = OG_FALSE;
        }
        i++;
    }
}

#ifdef __cplusplus
}
#endif
