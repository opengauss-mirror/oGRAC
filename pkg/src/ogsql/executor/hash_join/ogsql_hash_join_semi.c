/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
 * This file is part of the oGRAC project.
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
 * ogsql_hash_join_semi.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/hash_join/ogsql_hash_join_semi.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_hash_join_semi.h"
#include "ogsql_nl_join.h"
#include "ogsql_hash_join.h"
#include "ogsql_hash_join_fetch.h"
#include "ogsql_hash_join_common.h"

static status_t og_exec_semi_join_core(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
                                 semi_flag_t *semi_join_flag, bool32 *end)
{
    CM_POINTER5(statement, sql_cur, plan_node, semi_join_flag, end);
    plan_node_t *hash_plan = NULL;
    plan_node_t *probe_plan = NULL;
    if (plan_node->join_p.hash_left) {
        hash_plan = plan_node->join_p.left;
        probe_plan = plan_node->join_p.right;
    } else {
        hash_plan = plan_node->join_p.right;
        probe_plan = plan_node->join_p.left;
    }
    cond_tree_t *saved_cond = sql_cur->cond;
    *end = OG_FALSE;

    if (sql_execute_for_join(statement, sql_cur, hash_plan) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute for hash plan");
        return OG_ERROR;
    }
    if (sql_execute_for_join(statement, sql_cur, probe_plan) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute for probe plan");
        return OG_ERROR;
    }

    sql_cur->cond = plan_node->join_p.hash_left
        ? plan_node->join_p.left_hash.filter_cond
        : plan_node->join_p.right_hash.filter_cond;
    if (sql_fetch_for_join(statement, sql_cur, hash_plan, &semi_join_flag->eof) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to fetch for hash plan");
        return OG_ERROR;
    }

    bool32 is_semi_join = (plan_node->join_p.oper == JOIN_OPER_HASH_SEMI);
    if ((is_semi_join && semi_join_flag->eof) || (!is_semi_join && !semi_join_flag->eof)) {
        // no need to fetch rows from the outer table since the result set is empty
        og_end_hash_join_fetch(sql_cur, probe_plan);
    }
    sql_cur->cond = saved_cond;
    semi_join_flag->flag = OG_TRUE;
    return OG_SUCCESS;
}

static inline bool32 og_is_trans_column(join_info_t *hj_info)
{
    CM_POINTER(hj_info);
    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(hj_info->key_items, 0);
    return EXPR_NODE_TRANS_COLUMN == TREE_EXPR_TYPE(expr);
}

status_t og_hash_join_exec_semi(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    join_info_t *hj_info = NULL;
    if (plan_node->join_p.hash_left) {
        hj_info = &plan_node->join_p.right_hash;
    } else {
        hj_info = &plan_node->join_p.left_hash;
    }
    uint32 pos = plan_node->join_p.hj_pos;
    semi_flag_t *semi_join_flag = &sql_cur->semi_anchor.semi_flags[pos];
    semi_join_flag->flag = OG_FALSE;

    if (og_is_trans_column(hj_info)) {
        // for semi/anti join that has no parent node
        if (og_exec_semi_join_core(statement, sql_cur, plan_node, semi_join_flag, end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to og_exec_semi_join_core");
            return OG_ERROR;
        }
    } else {
        if (og_hash_join_execute_core(statement, sql_cur, plan_node, end, OG_TRUE) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to og_hash_join_execute_core");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_hash_join_setup_right_semi(sql_cursor_t *hash_sql_cur, hash_right_semi_t *hash_right_semi)
{
    CM_POINTER2(hash_sql_cur, hash_right_semi);
    hash_right_semi->deleted_rows = 0;
    hash_right_semi->is_first = OG_TRUE;
    if (vm_hash_table_get_rows(&hash_right_semi->total_rows, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to get rows from hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_hash_join_alloc_right_semi(sql_cursor_t *hash_sql_cur, hash_right_semi_t **hash_right_semi)
{
    CM_POINTER(hash_sql_cur);
    if (vmc_alloc(&hash_sql_cur->vmc, sizeof(hash_right_semi_t), (void **)hash_right_semi) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to alloc memory for key types on vmc, size: %lu",
                       sizeof(hash_right_semi_t));
        return OG_ERROR;
    }
    OG_RETURN_IFERR(og_hash_join_setup_right_semi(hash_sql_cur, *hash_right_semi));
    hash_sql_cur->exec_data.right_semi = *hash_right_semi;
    return OG_SUCCESS;
}

static inline bool32 og_hash_join_is_right_semi_reusable(sql_cursor_t *hash_sql_cur)
{
    return hash_sql_cur->exec_data.right_semi != NULL;
}

static void og_hash_join_reuse_right_semi(sql_cursor_t *hash_sql_cur, hash_right_semi_t **hash_right_semi)
{
    (*hash_right_semi) = hash_sql_cur->exec_data.right_semi;
    (*hash_right_semi)->is_first = OG_FALSE;
}

static status_t og_hash_join_create_right_semi(sql_cursor_t *hash_sql_cur, hash_right_semi_t **hash_right_semi)
{
    CM_POINTER2(hash_sql_cur, hash_right_semi);
    if (og_hash_join_is_right_semi_reusable(hash_sql_cur)) {
        og_hash_join_reuse_right_semi(hash_sql_cur, hash_right_semi);
        return OG_SUCCESS;
    }
    return og_hash_join_alloc_right_semi(hash_sql_cur, hash_right_semi);
}

static status_t og_hash_join_exec_right_cursor(sql_cursor_t *hash_sql_cur, uint16 flags)
{
    CM_POINTER(hash_sql_cur);
    bool32 match_found = OG_FALSE;
    hash_scan_assist_t hash_scan_ast = { HASH_FULL_SCAN, NULL, 0 };
    hash_sql_cur->hash_join_ctx->iter.flags = flags;
    hash_sql_cur->hash_join_ctx->iter.scan_mode = HASH_FULL_SCAN;
    if (vm_hash_table_init(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, NULL,
        og_fetch_next_row_cb, hash_sql_cur) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to initialize hash table");
        return OG_ERROR;
    }
    return vm_hash_table_open(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
        &hash_scan_ast, &match_found, &hash_sql_cur->hash_join_ctx->iter);
}

static bool32 og_hash_join_exec_right_semi_first(hash_right_semi_t *hash_right_semi)
{
    CM_POINTER(hash_right_semi);
    return hash_right_semi->is_first;
}

status_t og_hash_join_exec_right_semi(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    if (og_hash_join_execute_core(statement, sql_cur, plan_node, end, OG_FALSE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute plan");
        return OG_ERROR;
    }
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (og_hash_join_sql_cursor_eof(hash_sql_cur)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    hash_right_semi_t *hash_right_semi = NULL;
    if (og_hash_join_create_right_semi(hash_sql_cur, &hash_right_semi) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to init right semi data");
        return OG_ERROR;
    }
    if (og_hash_join_exec_right_semi_first(hash_right_semi)) {
        /* During the first time of right semi/anti join is executed,
         * mark the rows in the hash table as deleted if the join condition is satisfied.
         */
        hash_sql_cur->hash_join_ctx->iter.flags = ITER_IGNORE_DEL;
        if (vm_hash_table_init(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, NULL,
            og_fetch_right_semi_row_cb, hash_sql_cur) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to init hash table");
            return OG_ERROR;
        }
    }
    
    plan_node_t *probe_plan = plan_node->join_p.hash_left? plan_node->join_p.right : plan_node->join_p.left;
    og_end_hash_join_fetch(sql_cur, probe_plan);
    return og_hash_join_exec_right_cursor(hash_sql_cur, ITER_FETCH_DEL);
}

/* next_row_buf is the hash table fetch direction's new_buf, which is NULL by design. */
static status_t og_delete_matched_row_cb(void *sql_cur, const char *next_row_buf,
    uint32 next_row_size, const char *curr_row_buf, uint32 curr_row_size, bool32 match_found)
{
    CM_POINTER(curr_row_buf);
    OG_RETVALUE_IFTRUE(sql_cur == NULL, OG_SUCCESS);
    sql_cursor_t *hash_sql_cur = (sql_cursor_t *)sql_cur;
    OG_RETVALUE_IFTRUE(hash_sql_cur->exec_data.right_semi == NULL, OG_SUCCESS);
    hash_sql_cur->exec_data.right_semi->deleted_rows++;
    if (vm_hash_table_delete(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
        &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to delete hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * skip mathing rows in right anti join
 */
static status_t og_hash_join_skip_match_rows(sql_cursor_t *hash_sql_cur, char *buf)
{
    CM_POINTER2(hash_sql_cur, buf);
    row_head_t *row_head = (row_head_t *)buf;
    hash_scan_assist_t hash_scan_ast = { HASH_KEY_SCAN, buf, row_head->size };
    hash_sql_cur->hash_join_ctx->iter.flags = ITER_IGNORE_DEL;
    bool32 match_found = OG_FALSE;
    if (vm_hash_table_open(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
        &hash_scan_ast, &match_found, &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to open hash table");
        return OG_ERROR;
    }
    bool32 end = OG_FALSE;
    while (OG_TRUE) {
        if (vm_hash_table_fetch(&end, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
            &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch from hash table");
            return OG_ERROR;
        }
        if (end) {
            hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
            break;
        }
    }
    return OG_SUCCESS;
}

static bool32 og_hash_join_are_all_rows_processed(hash_right_semi_t *hash_right_semi)
{
    CM_POINTER(hash_right_semi);
    return hash_right_semi->deleted_rows == hash_right_semi->total_rows;
}

/* Returns rows from the right table that don't have matching rows in the left table */
static status_t og_hash_join_mtrl_insert_rows_anti(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur,
    plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, hash_sql_cur, plan_node, end);
    char *buf = NULL;
    bool32 end_fetch = OG_FALSE;
    bool32 contains_null_key = OG_FALSE;
    row_assist_t ra;
    OGSQL_SAVE_STACK(statement);
    galist_t *hash_keys = NULL;
    galist_t *prob_keys = NULL;
    plan_node_t *probe_plan = NULL;
    og_get_prob_keys(&prob_keys, &plan_node->join_p);
    og_get_hash_keys(&hash_keys, &plan_node->join_p);
    og_get_probe_plan(&probe_plan, &plan_node->join_p);
    hash_right_semi_t *hash_right_semi = hash_sql_cur->exec_data.right_semi;
    join_info_t *hj_info = &plan_node->join_p.left_hash;
    OG_RETURN_IFERR(og_hash_join_get_hash_keys_type(statement, hash_sql_cur, &plan_node->join_p,
        hash_keys, prob_keys, hj_info));
    while (OG_TRUE) {
        end_fetch = OG_FALSE;
        if (sql_fetch_for_join(statement, hash_sql_cur, probe_plan, &end_fetch) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch rows for hash plan id: %d, type: %d", probe_plan->plan_id,
                           (uint8)probe_plan->type);
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }
        OG_BREAK_IF_ERROR(end_fetch);
        contains_null_key = OG_FALSE;
        OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&buf));
        if (sql_make_hash_key(statement, &ra, buf, hash_keys, hash_sql_cur->hash_join_ctx->key_types,
            &contains_null_key) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to make hash key");
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }

        if (contains_null_key) {
            if (plan_node->join_p.oper == JOIN_OPER_HASH_RIGHT_ANTI_NA) {
                OGSQL_RESTORE_STACK(statement);
                hash_right_semi->deleted_rows = hash_right_semi->total_rows;
                *end = OG_TRUE;
                break;
            }
        } else {
            if (og_hash_join_skip_match_rows(hash_sql_cur, buf) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to skip matching rows");
                OGSQL_RESTORE_STACK(statement);
                return OG_ERROR;
            }
        }
        OGSQL_RESTORE_STACK(statement);
        if (og_hash_join_are_all_rows_processed(hash_right_semi)) {
            *end = OG_TRUE;
            break;
        }
    }
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

/*
 * Builds a hash table for right anti join
 *
 * @param statement    SQL statement context
 * @param sql_cur  Parent cursor
 * @param plan    Join plan node
 * @param end     [out] End of fetch indicator
 * @return OG_SUCCESS on success, error code on failure
 */
static status_t og_hash_join_mtrl_hash_table_right_anti(sql_stmt_t *statement,
    sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (vm_hash_table_init(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, NULL, og_delete_matched_row_cb,
                           hash_sql_cur) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to initialize hash table");
        return OG_ERROR;
    }

    cond_tree_t *saved_cond = sql_cur->cond;
    join_plan_t *join_plan = &plan_node->join_p;
    sql_cur->cond = join_plan->hash_left ? join_plan->right_hash.filter_cond : join_plan->left_hash.filter_cond;

    if (og_hash_join_mtrl_insert_rows_anti(statement, hash_sql_cur, plan_node, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to insert rows to mtrl hash table");
        return OG_ERROR;
    }
    sql_cur->cond = saved_cond;
    return OG_SUCCESS;
}

/*
 * Executes a right anti join operation using hash join strategy.
 * A right anti join returns rows from the right table that do not have matching rows in the left table.
 *
 * @param statement    SQL statement context containing execution state
 * @param sql_cur  Parent cursor for the join operation
 * @param plan    Join plan node containing join conditions and table information
 * @param end     [out] Pointer to boolean indicating if end of result set reached
 *
 * @return OG_SUCCESS on success, error code on failure
 */
status_t og_hash_join_exec_right_anti(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    if (og_hash_join_execute_core(statement, sql_cur, plan_node, end, OG_FALSE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute hash join");
        return OG_ERROR;
    }
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (og_hash_join_sql_cursor_eof(hash_sql_cur)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    plan_node_t *probe_plan = plan_node->join_p.hash_left? plan_node->join_p.right : plan_node->join_p.left;
    hash_right_semi_t *hash_right_semi = NULL;
    
    if (og_hash_join_create_right_semi(hash_sql_cur, &hash_right_semi) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to init data for semi hash join");
        return OG_ERROR;
    }
    if (og_hash_join_exec_right_semi_first(hash_right_semi)) {
        if (og_hash_join_mtrl_hash_table_right_anti(statement, sql_cur, plan_node, end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to create hash table");
            return OG_ERROR;
        }
    } else {
        og_end_hash_join_fetch(sql_cur, probe_plan);
    }
    return og_hash_join_exec_right_cursor(hash_sql_cur, ITER_IGNORE_DEL);
}