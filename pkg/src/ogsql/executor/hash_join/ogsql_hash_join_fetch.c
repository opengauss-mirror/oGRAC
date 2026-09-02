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
 * ogsql_hash_join_fetch.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/hash_join/ogsql_hash_join_fetch.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_hash_join_fetch.h"
#include "ogsql_hash_join.h"
#include "ogsql_nl_join.h"
#include "ogsql_hash_join_common.h"

/* Fetch rows from hash table and set cursor row IDs to which on materialized table */
static status_t og_fetch_mtrl_rows(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur, mtrl_rowid_t *row_ids)
{
    CM_POINTER3(statement, hash_sql_cur, row_ids);
    mtrl_context_t *mtrl_ctx = NULL;
    if ((hash_sql_cur->hash_join_ctx != NULL) && (hash_sql_cur->hash_join_ctx->mtrl_ctx != NULL)) {
        mtrl_ctx = hash_sql_cur->hash_join_ctx->mtrl_ctx;
    } else {
        mtrl_ctx = &statement->mtrl;
    }
    if (sql_mtrl_fetch_tables_row(mtrl_ctx, &hash_sql_cur->mtrl.cursor, hash_sql_cur->exec_data.join,
        row_ids, hash_sql_cur->table_count) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to fetch tables row");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* Callback function to fetch a single row from hash table */
status_t og_fetch_next_row_cb(void *sql_cur, const char *next_row_buf, uint32 next_row_size,
    const char *curr_row_buf, uint32 curr_row_size, bool32 match_found)
{
    CM_POINTER3(sql_cur, next_row_buf, curr_row_buf);
    sql_cursor_t *hash_sql_cur = (sql_cursor_t *)sql_cur;
    row_head_t *row_head = (row_head_t *)curr_row_buf;
    mtrl_rowid_t *mtrl_ids = (mtrl_rowid_t *)(curr_row_buf + row_head->size);
    return og_fetch_mtrl_rows(hash_sql_cur->stmt, (sql_cursor_t *)sql_cur, mtrl_ids);
}

static status_t og_fetch_and_delete_row(void *sql_cur, const char *next_row_buf, uint32 next_row_size,
    const char *curr_row_buf, uint32 curr_row_size, bool32 match_found)
{
    CM_POINTER3(sql_cur, next_row_buf, curr_row_buf);
    sql_cursor_t *hash_sql_cur = (sql_cursor_t *)sql_cur;
    if (og_fetch_next_row_cb(sql_cur, next_row_buf, next_row_size,
        curr_row_buf, curr_row_size, match_found) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to fetch row");
        return OG_ERROR;
    }
    return vm_hash_table_delete(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, &hash_sql_cur->hash_join_ctx->iter);
}

/* Callback function to fetch and delete a row from hash table (left join use outer table as hash table) */
status_t og_fetch_right_left_row_cb(void *sql_cur, const char *next_row_buf, uint32 next_row_size,
    const char *curr_row_buf, uint32 curr_row_size, bool32 match_found)
{
    CM_POINTER3(sql_cur, next_row_buf, curr_row_buf);
    return og_fetch_and_delete_row(sql_cur, next_row_buf, next_row_size, curr_row_buf, curr_row_size, match_found);
}

static inline void og_count_deleted_rows(sql_cursor_t *hash_sql_cur)
{
    CM_POINTER(hash_sql_cur);
    hash_sql_cur->exec_data.right_semi->deleted_rows++;
}
/*
 * Callback function to fetch and delete a row from hash table (semi/anti join use outer table as hash table)
 *
 * This function fetches a row from the hash table, increments the deleted rows counter,
 * and then mark the row as deleted on hash table. It's used in right semi-join scenarios
 * to track how many rows have been processed.
 */
status_t og_fetch_right_semi_row_cb(void *sql_cur, const char *next_row_buf, uint32 next_row_size,
    const char *curr_row_buf, uint32 curr_row_size, bool32 match_found)
{
    CM_POINTER3(sql_cur, next_row_buf, curr_row_buf);
    og_count_deleted_rows(sql_cur);   // count the processed rows
    return og_fetch_and_delete_row(sql_cur, next_row_buf, next_row_size, curr_row_buf, curr_row_size, match_found);
}

static void og_end_fetch_hash_table_row(sql_cursor_t *hash_sql_cur)
{
    vm_hash_close_page(&hash_sql_cur->hash_seg, &(hash_sql_cur->hash_table_entry.page));
    hash_sql_cur->hash_join_ctx->iter.hash_table = NULL;
}

/* For each row in the outer table, match the hash table and fetch the matched row */
static status_t og_fetch_hash_table_row(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
                                          bool32 *end, bool32 is_early_return, bool32 is_full_join)
{
    CM_POINTER3(sql_cur, plan_node, end);
    bool32 right_eof = OG_FALSE;
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    galist_t *hash_keys = NULL;
    plan_node_t *probe_plan = NULL;
    og_get_hash_keys(&hash_keys, &plan_node->join_p);
    og_get_probe_plan(&probe_plan, &plan_node->join_p);

    char *row_buf_ptr = NULL;
    row_assist_t ra;
    MEMS_RETURN_IFERR(memset_s(&ra, sizeof(row_assist_t), 0, sizeof(row_assist_t)));
    hash_scan_assist_t hash_scan_ast;
    MEMS_RETURN_IFERR(memset_s(&hash_scan_ast, sizeof(hash_scan_assist_t), 0, sizeof(hash_scan_assist_t)));
    bool32 contains_null_key = OG_FALSE;
    bool32 match_found = OG_FALSE;
    while (OG_TRUE) {
        OGSQL_SAVE_STACK(statement);

        // fetch one row from outer table
        RET_IFERR_RESTORE_STACK(sql_fetch_for_join(statement, sql_cur, probe_plan, end), statement);
        if (*end) {
            if (!is_full_join && hash_sql_cur->hash_join_ctx->iter.hash_table != NULL) {
                og_end_fetch_hash_table_row(hash_sql_cur);
            }
            OGSQL_RESTORE_STACK(statement);
            return OG_SUCCESS;
        }
        hash_sql_cur->hash_join_ctx->has_match = OG_FALSE;
        RET_IFERR_RESTORE_STACK(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&row_buf_ptr), statement);
        RET_IFERR_RESTORE_STACK(sql_make_hash_key(statement, &ra, row_buf_ptr, hash_keys,
            hash_sql_cur->hash_join_ctx->key_types, &contains_null_key), statement);
        
        /* In case of null key, since no matching will be found in hash table.
         *  case 1: return early for left join and full join, but still need to send the row to client.
         *  case 2: continue to fetch the next row in outer table for other join types
         */
        if (contains_null_key) {
            hash_sql_cur->hash_join_ctx->right_eof = OG_TRUE;
            OGSQL_RESTORE_STACK(statement);
            OG_RETVALUE_IFTRUE(is_early_return, OG_SUCCESS);
            continue;
        }
        
        sql_init_scan_assist(row_buf_ptr, &hash_scan_ast);
        if (is_full_join) {
            sql_cur->last_table = get_last_table_id(plan_node);
        }
        
        // open the hash table and fetch the matched row with the hash key
        RET_IFERR_RESTORE_STACK(vm_hash_table_open(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
            &hash_scan_ast, &match_found, &hash_sql_cur->hash_join_ctx->iter), statement);
        RET_IFERR_RESTORE_STACK(vm_hash_table_fetch(&right_eof, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
            &hash_sql_cur->hash_join_ctx->iter), statement);

        OGSQL_RESTORE_STACK(statement);
        hash_sql_cur->hash_join_ctx->right_eof = right_eof;
        OG_BREAK_IF_TRUE(!right_eof); // return the row if matched
        hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
        OG_BREAK_IF_TRUE(is_early_return); // not matched but still need to return for left join and full join
    }
    return OG_SUCCESS;
}

static inline bool32 og_is_full_hash_table_scan(sql_cursor_t *hash_sql_cur)
{
    CM_POINTER(hash_sql_cur);
    return hash_sql_cur->hash_join_ctx->scan_hash_table;
}

static inline void og_process_fetch_right_eof(sql_cursor_t *hash_sql_cur)
{
    CM_POINTER(hash_sql_cur);
    hash_sql_cur->hash_join_ctx->right_eof = OG_TRUE;
    hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
}

static status_t og_fetch_hash_table_with_same_key(plan_node_t *plan_node, sql_cursor_t *hash_sql_cur,
    sql_cursor_t *sql_cur, bool32 *end, bool32 is_early_return, bool32 *keep_fetching)
{
    CM_POINTER5(plan_node, hash_sql_cur, sql_cur, end, keep_fetching);
    bool32 right_eof = OG_FALSE;
    sql_cur->last_table = get_last_table_id(plan_node);
    if (vm_hash_table_fetch(&right_eof, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
        &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to fetch rows for phash table");
        return OG_ERROR;
    }
    
    // matched in hash table and return the row
    OG_RETVALUE_IFTRUE(!right_eof, OG_SUCCESS);
    og_process_fetch_right_eof(hash_sql_cur);
    // still need to return the row for left and full join if no match found
    OG_RETVALUE_IFTRUE(is_early_return, OG_SUCCESS);
    if (og_is_full_hash_table_scan(hash_sql_cur)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    *keep_fetching = OG_TRUE;
    return OG_SUCCESS;
}

static inline bool32 og_last_fetch_is_matched(sql_cursor_t *hash_sql_cur)
{
    CM_POINTER(hash_sql_cur);
    return !hash_sql_cur->hash_join_ctx->right_eof;
}

static status_t og_fetch_hash_table_matched_row(sql_stmt_t *statement, sql_cursor_t *sql_cur,
    plan_node_t *plan_node, bool32 *end, bool32 is_early_return, bool32 is_full_join)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    sql_cur->cond = NULL;
    if (plan_node->join_p.hash_left) {
        sql_cur->cond = plan_node->join_p.right_hash.filter_cond;
    } else {
        sql_cur->cond = plan_node->join_p.left_hash.filter_cond;
    }
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    bool32 keep_fetching = OG_FALSE;
    if (og_last_fetch_is_matched(hash_sql_cur)) {
        /*  the hash key has been matched in the last fetch iteration
         *  so that try to use the same hash key to fetch row from the hash table until no match
         */
        status_t ret = og_fetch_hash_table_with_same_key(plan_node, hash_sql_cur, sql_cur, end,
            is_early_return, &keep_fetching);
        OG_RETVALUE_IFTRUE(!keep_fetching, ret);
    }

    return og_fetch_hash_table_row(statement, sql_cur, plan_node, end, is_early_return, is_full_join);
}

static inline bool32 og_hash_join_validate_cursor(sql_cursor_t *hash_sql_cur, bool32 check_eof)
{
    if (hash_sql_cur == NULL) {
        return OG_FALSE;
    }
    if (check_eof && hash_sql_cur->eof) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

status_t og_hash_join_fetch(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (!og_hash_join_validate_cursor(hash_sql_cur, OG_TRUE)) {
        // return directly when hash table is empty table because the result set is empty for inner join.
        *end = OG_TRUE;
        return OG_SUCCESS;
    }

    uint32 last_table = get_last_table_id(plan_node);
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    plan_node_t *hash_plan_node = NULL;
    if (plan_node->join_p.hash_left) {
        hash_plan_node = plan_node->join_p.left;
    } else {
        hash_plan_node = plan_node->join_p.right;
    }
    bool32 match_found = OG_FALSE;
    *end = OG_FALSE;
    while (!match_found) {
        if (og_fetch_hash_table_matched_row(statement, sql_cur, plan_node, end,
            OG_FALSE, OG_FALSE) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch row from hash table");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(*end);
        sql_cur->last_table = last_table;
        if (match_hash_join_final_cond(statement, saved_cond_tree,
            plan_node->join_p.filter, &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to match cond");
            return OG_ERROR;
        }
    }
    if (*end) {
        og_end_hash_join_fetch(sql_cur, hash_plan_node);
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = last_table;
    return OG_SUCCESS;
}

static inline bool32 og_need_match_outer_join_cond(sql_cursor_t *sql_cur)
{
    CM_POINTER(sql_cur);
    return sql_cur->hash_join_ctx->need_match_cond;
}

/* For full join, fetch the matched row and set the match flag */
status_t og_fetch_full_join_row_cb(void *sql_cur, const char *next_row_buf, uint32 next_row_size,
    const char *curr_row_buf, uint32 curr_row_size, bool32 match_found)
{
    CM_POINTER3(sql_cur, next_row_buf, curr_row_buf);
    row_head_t *row_head = (row_head_t *)curr_row_buf;
    bool8 *match_flag = (bool8 *)(curr_row_buf + row_head->size);
    sql_cursor_t *hash_sql_cur = (sql_cursor_t *)sql_cur;
    mtrl_rowid_t *mtrl_id = (mtrl_rowid_t *)(curr_row_buf + row_head->size + sizeof(bool8));
    sql_stmt_t *statement = hash_sql_cur->stmt;
    if (og_need_match_outer_join_cond(hash_sql_cur)) {
        if (og_fetch_mtrl_rows(statement, hash_sql_cur, mtrl_id) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch mtrl rows");
            return OG_ERROR;
        }
        if (og_match_outerjoin_condition(statement, hash_sql_cur->hash_join_ctx->join_cond,
            &hash_sql_cur->hash_join_ctx->is_find) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to match cond");
            return OG_ERROR;
        }
        if (hash_sql_cur->hash_join_ctx->is_find) {
            hash_sql_cur->hash_join_ctx->has_match = OG_TRUE;
            *match_flag = OG_TRUE;
        }
    } else if (*match_flag) {
        *match_flag = OG_FALSE;
        hash_sql_cur->hash_join_ctx->is_find = OG_FALSE;
    } else {
        hash_sql_cur->hash_join_ctx->is_find = OG_TRUE;
        if (og_fetch_mtrl_rows(statement, hash_sql_cur, mtrl_id) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch vm rows");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t og_hash_join_fetch_left(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (!og_hash_join_validate_cursor(hash_sql_cur, OG_FALSE)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    uint32 last_table = get_last_table_id(plan_node);
    bool32 match_found = OG_FALSE;
    *end = OG_FALSE;
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    while (!match_found) {
        if (og_fetch_hash_table_matched_row(statement, sql_cur, plan_node, end, OG_TRUE, OG_FALSE) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch hash table");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(*end);
        sql_cur->last_table = last_table;
        if (og_last_fetch_is_matched(hash_sql_cur)) {
            if (og_match_outerjoin_condition(statement, plan_node->join_p.cond, &match_found) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to match cond");
                return OG_ERROR;
            }
            OG_CONTINUE_IFTRUE(!match_found);
            hash_sql_cur->hash_join_ctx->has_match = OG_TRUE;
        } else {
            OG_CONTINUE_IFTRUE(hash_sql_cur->hash_join_ctx->has_match);
            if (sql_fetch_null_row(statement, hash_sql_cur) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to fetch null rows");
                return OG_ERROR;
            }
        }

        if (match_hash_join_final_cond(statement, saved_cond_tree, plan_node->join_p.filter,
            &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to match cond");
            return OG_ERROR;
        }
    }
    if (*end) {
        og_end_hash_join_fetch(sql_cur, plan_node->join_p.right);
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = last_table;
    return OG_SUCCESS;
}

static void og_init_hash_ast(hash_scan_assist_t *hash_scan_ast)
{
    hash_scan_ast->buf = NULL;
    hash_scan_ast->size = 0;
    hash_scan_ast->scan_mode = HASH_FULL_SCAN;
}

static void og_set_hash_ctx(hash_join_ctx_t *hash_join_ctx, sql_cursor_t *hash_sql_cur)
{
    sql_init_hash_iter(&hash_join_ctx->iter, hash_sql_cur);
    hash_join_ctx->iter.flags = ITER_IGNORE_DEL;
    hash_join_ctx->right_eof = OG_FALSE;
    hash_join_ctx->scan_hash_table = OG_TRUE;
}

static status_t og_open_hash_right_left_cursor(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur)
{
    CM_POINTER2(statement, hash_sql_cur);
    bool32 match_found = OG_FALSE;
    hash_scan_assist_t hash_scan_ast;
    og_init_hash_ast(&hash_scan_ast);
    og_set_hash_ctx(hash_sql_cur->hash_join_ctx, hash_sql_cur);
    if (vm_hash_table_init(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, NULL, og_fetch_next_row_cb, hash_sql_cur)
        != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to init hash table");
        return OG_ERROR;
    }

    if (vm_hash_table_open(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, &hash_scan_ast, &match_found,
        &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to open hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t og_hash_join_fetch_right_left(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (!og_hash_join_validate_cursor(hash_sql_cur, OG_TRUE)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    bool32 match_found = OG_FALSE;
    *end = OG_FALSE;
    plan_node_t *probe_plan = NULL;
    og_get_probe_plan(&probe_plan, &plan_node->join_p);
    uint32 last_table = get_last_table_id(plan_node);
    while (!match_found) {
        if (og_fetch_hash_table_matched_row(statement, sql_cur, plan_node, end, OG_FALSE, OG_FALSE) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch rows from hash table");
            return OG_ERROR;
        }
        if (!(*end)) {
            sql_cur->last_table = last_table;
            if (match_hash_join_final_cond(statement, saved_cond_tree, plan_node->join_p.filter,
                &match_found) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to match cond");
                return OG_ERROR;
            }
        } else {
            OG_BREAK_IF_TRUE(og_is_full_hash_table_scan(hash_sql_cur));
            *end = OG_FALSE;
            sql_end_plan_cursor_fetch(sql_cur, probe_plan);
            if (og_open_hash_right_left_cursor(statement, hash_sql_cur) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to open hash right left cursor");
                return OG_ERROR;
            }
        }
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = last_table;
    return OG_SUCCESS;
}

static status_t og_prepare_hash_full_unmatched_inner(sql_cursor_t *sql_cur, sql_cursor_t *hash_sql_cur,
                                                      plan_node_t *plan_node)
{
    CM_POINTER3(sql_cur, hash_sql_cur, plan_node);
    sql_cur->last_table = get_last_table_id(plan_node);
    join_info_t *hj_info = NULL;
    if (plan_node->join_p.hash_left) {
        hj_info = &plan_node->join_p.right_hash;
    } else {
        hj_info = &plan_node->join_p.left_hash;
    }
    hash_sql_cur->hash_join_ctx->need_swap_driver = OG_TRUE;
    hash_sql_cur->hash_join_ctx->need_match_cond = OG_FALSE;
    sql_reset_cursor_eof(sql_cur, hj_info, OG_TRUE);
    
    bool32 match_found = OG_FALSE;
    hash_scan_assist_t hash_scan_ast;
    og_init_hash_ast(&hash_scan_ast);
    return vm_hash_table_open(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, &hash_scan_ast, &match_found,
        &hash_sql_cur->hash_join_ctx->iter);
}

static status_t og_fetch_hash_full_unmatched_inner(sql_cursor_t *hash_sql_cur, bool32 *end)
{
    CM_POINTER2(hash_sql_cur, end);
    *end = OG_FALSE;
    while (OG_TRUE) {
        if (vm_hash_table_fetch(end, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
            &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
            hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(*end);
        if (hash_sql_cur->hash_join_ctx->is_find) {
            return OG_SUCCESS;
        }
    }
    hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
    return OG_SUCCESS;
}

static status_t og_fetch_hash_full_outer(sql_stmt_t *statement, sql_cursor_t *sql_cur, sql_cursor_t *hash_sql_cur,
                                       plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER5(statement, sql_cur, hash_sql_cur, plan_node, end);
    while (OG_TRUE) {
        if (og_fetch_hash_table_matched_row(statement, sql_cur, plan_node, end, OG_TRUE, OG_TRUE) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch rows from hash table");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(*end);
        if (og_last_fetch_is_matched(hash_sql_cur)) {
            OG_BREAK_IF_TRUE(hash_sql_cur->hash_join_ctx->is_find);
        } else {
            OG_CONTINUE_IFTRUE(hash_sql_cur->hash_join_ctx->has_match);
            if (sql_fetch_null_row(statement, hash_sql_cur) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to fetch null rows");
                return OG_ERROR;
            }
            break;
        }
    }
    return OG_SUCCESS;
}

/* Two-phase execution for full join,
 * Phase 1: fetch the rows from the outer table, match the hash table and set the match flag
 * Phase 2: swap the role of inner and outer table, fetch the unmatched rows for inner table in phase 1
 */
status_t og_hash_join_fetch_full(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (!og_hash_join_validate_cursor(hash_sql_cur, OG_FALSE)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    bool32 match_found = OG_FALSE;
    *end = OG_FALSE;
    
    while (!match_found) {
        if (hash_sql_cur->hash_join_ctx->need_swap_driver) {
            if (og_fetch_hash_full_unmatched_inner(hash_sql_cur, end) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to fetch join plan phase2");
                return OG_ERROR;
            }
            OG_BREAK_IF_TRUE(*end);
        } else {
            if (og_fetch_hash_full_outer(statement, sql_cur, hash_sql_cur, plan_node, end) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to fetch join plan phase 1");
                return OG_ERROR;
            }
            if (*end) {
                OG_RETURN_IFERR(og_prepare_hash_full_unmatched_inner(sql_cur, hash_sql_cur, plan_node));
                continue;
            }
        }
        sql_cur->last_table = get_last_table_id(plan_node);
        if (match_hash_join_final_cond(statement, saved_cond_tree, plan_node->join_p.filter,
            &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch join plan");
            return OG_ERROR;
        }
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = get_last_table_id(plan_node);
    return OG_SUCCESS;
}

static status_t og_fetch_hash_table_semi(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    bool32 *end, bool32 is_semi_join, bool32 has_in_clause)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    plan_node_t *probe_plan = NULL;
    og_get_probe_plan(&probe_plan, &plan_node->join_p);
    galist_t *hash_keys = NULL;
    og_get_hash_keys(&hash_keys, &plan_node->join_p);
    char *buf = NULL;
    row_assist_t ra;
    MEMS_RETURN_IFERR(memset_s(&ra, sizeof(row_assist_t), 0, sizeof(row_assist_t)));
    hash_scan_assist_t hash_scan_ast;
    MEMS_RETURN_IFERR(memset_s(&hash_scan_ast, sizeof(hash_scan_assist_t), 0, sizeof(hash_scan_assist_t)));
    bool32 contains_null_key = OG_FALSE;
    bool32 hash_table_eof = OG_FALSE;
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    sql_cur->cond = plan_node->join_p.hash_left ? plan_node->join_p.right_hash.filter_cond :
        plan_node->join_p.left_hash.filter_cond;
    if (plan_node->join_p.oper == JOIN_OPER_HASH_ANTI_NA) {
        // for null aware anti join, result set is empty when the hash table has null key
        if (vm_hash_table_has_null_key(&contains_null_key, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to check null key");
            return OG_ERROR;
        }
        if (contains_null_key) {
            *end = OG_TRUE;
            return OG_SUCCESS;
        }
    }
    // for semi-join, early return if the hash table is empty
    if (is_semi_join && og_hash_join_sql_cursor_eof(hash_sql_cur)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }

    OGSQL_SAVE_STACK(statement);
    while (OG_TRUE) {
        if (sql_fetch_for_join(statement, sql_cur, probe_plan, end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch for probe plan id: %d, type: %d", probe_plan->plan_id,
                           (uint8)probe_plan->type);
            OGSQL_RESTORE_STACK(statement);
            return OG_ERROR;
        }
        /*
         * return condition:
         * 1. no more row to fetch
         * 2. for anti join, return the row of outer table if the hash table is empty
         */
        OG_BREAK_IF_TRUE(*end || (!is_semi_join && hash_sql_cur->eof));
        if (is_semi_join) {
            hash_sql_cur->hash_join_ctx->has_match = OG_FALSE;
        }
        RET_IFERR_RESTORE_STACK(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&buf), statement);
        RET_IFERR_RESTORE_STACK(sql_make_hash_key(statement, &ra, buf, hash_keys,
            hash_sql_cur->hash_join_ctx->key_types, &contains_null_key), statement);
        if (contains_null_key) {
            /* NOT EXIST NULL is regarded as true, so return the row
             * NOT IN NULL is regarded as false, so continue to fetch the next row
             */
            OGSQL_RESTORE_STACK(statement);
            OG_BREAK_IF_TRUE(!is_semi_join && !has_in_clause);
            continue;
        }
        sql_init_scan_assist(buf, &hash_scan_ast);
        RET_IFERR_RESTORE_STACK(vm_hash_table_probe(&hash_table_eof, &hash_sql_cur->hash_seg,
            HASH_TABLE_ENTRY, &hash_scan_ast), statement);
        OGSQL_RESTORE_STACK(statement);

        // for semi-join, return the row if matched, vice versa
        OG_BREAK_IF_TRUE(hash_table_eof ^ is_semi_join);
    }
    OGSQL_RESTORE_STACK(statement);
    return OG_SUCCESS;
}

static status_t og_fetch_table_root_semi(sql_stmt_t *statement, sql_cursor_t *sql_cur,
    plan_node_t *plan_node, bool32 *end, bool32 is_semi_join, semi_flag_t *semi_join_flag)
{
    CM_POINTER5(statement, sql_cur, plan_node, end, semi_join_flag);
    // early return if the result set is empty
    if ((is_semi_join && semi_join_flag->eof) || (!is_semi_join && !semi_join_flag->eof)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    plan_node_t *probe_plan = NULL;
    og_get_probe_plan(&probe_plan, &plan_node->join_p);
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    bool32 match_found = OG_FALSE;
    join_plan_t *join_plan = &plan_node->join_p;
    while (OG_TRUE) {
        sql_cur->cond = join_plan->hash_left ? join_plan->right_hash.filter_cond : join_plan->left_hash.filter_cond;
        if (sql_fetch_for_join(statement, sql_cur, probe_plan, end) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch join plan");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(*end);
        sql_cur->last_table = get_last_table_id(plan_node);
        if (match_hash_join_final_cond(statement, saved_cond_tree, join_plan->filter, &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch join plan");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(match_found);
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = get_last_table_id(plan_node);
    return OG_SUCCESS;
}

static bool32 og_is_root_semi(sql_cursor_t *sql_cur, plan_node_t *plan_node, semi_flag_t **out_semi_join_flag)
{
    CM_POINTER3(sql_cur, plan_node, out_semi_join_flag);
    semi_flag_t *semi_join_flag = &sql_cur->semi_anchor.semi_flags[plan_node->join_p.hj_pos];
    *out_semi_join_flag = semi_join_flag;
    return semi_join_flag->flag;
}

static inline bool32 og_hash_join_semi_is_semi(plan_node_t *plan_node)
{
    CM_POINTER(plan_node);
    return plan_node->join_p.oper == JOIN_OPER_HASH_SEMI;
}

static inline bool32 og_hash_join_semi_is_in(plan_node_t *plan_node)
{
    CM_POINTER(plan_node);
    return plan_node->join_p.oper == JOIN_OPER_HASH_SEMI || plan_node->join_p.oper == JOIN_OPER_HASH_ANTI_NA;
}

static status_t og_hash_join_fetch_semi_core(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    bool32 is_semi_join = og_hash_join_semi_is_semi(plan_node);
    bool32 has_in_clause = og_hash_join_semi_is_in(plan_node);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (!og_hash_join_validate_cursor(hash_sql_cur, OG_FALSE)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    
    *end = OG_FALSE;
    bool32 match_found = OG_FALSE;
    uint32 last_table = get_last_table_id(plan_node);
    sql_cur->last_table = last_table;
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    while (OG_TRUE) {
        if (og_fetch_hash_table_semi(statement, sql_cur, plan_node, end, is_semi_join, has_in_clause) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch semi/ anti table");
            return OG_ERROR;
        }
        if (*end) {
            // clean up the hash table cursor by filling with null row
            if (sql_fetch_null_row(statement, hash_sql_cur) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to fetch null row semi table");
                return OG_ERROR;
            }
            break;
        }
        sql_cur->last_table = last_table;
        if (match_hash_join_final_cond(statement, saved_cond_tree, plan_node->join_p.filter,
            &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch semi table");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(match_found);
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = last_table;
    return OG_SUCCESS;
}

status_t og_hash_join_fetch_semi(sql_stmt_t *statement,
    sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    bool32 is_semi_join = og_hash_join_semi_is_semi(plan_node);
    semi_flag_t *semi_join_flag = NULL;
    if (og_is_root_semi(sql_cur, plan_node, &semi_join_flag)) {
        // fetch the result set in case of semi/anti-join with no parent node
        if (og_fetch_table_root_semi(statement, sql_cur, plan_node, end, is_semi_join, semi_join_flag) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to fetch semi table");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }
    return og_hash_join_fetch_semi_core(statement, sql_cur, plan_node, end);
}

static status_t og_hash_join_fetch_semi_right_core(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
                                        bool32 *end, bool32 is_semi_join)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    bool32 match_found = OG_FALSE;
    if (!is_semi_join) {
        *end = OG_FALSE;
    }
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    uint32 last_table = get_last_table_id(plan_node);
    cond_tree_t *saved_cond_tree = sql_cur->cond;
    while (OG_TRUE) {
        if (vm_hash_table_fetch(end, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
            &hash_sql_cur->hash_join_ctx->iter) != OG_SUCCESS) {
            if (!is_semi_join) {
                hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
            }
            return OG_ERROR;
        }
        if (*end) {
            if (is_semi_join) {
                hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
            }
            break;
        }
        sql_cur->last_table = last_table;
        if (match_hash_join_final_cond(statement, saved_cond_tree, plan_node->join_p.filter,
            &match_found) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to match cond");
            return OG_ERROR;
        }
        OG_BREAK_IF_TRUE(match_found);
    }
    sql_cur->cond = saved_cond_tree;
    sql_cur->last_table = last_table;
    return OG_SUCCESS;
}

static inline bool32 og_hash_join_get_right_semi(sql_cursor_t *sql_cur, plan_node_t *plan_node,
    hash_right_semi_t **out_right_semi)
{
    CM_POINTER3(sql_cur, plan_node, out_right_semi);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (!og_hash_join_validate_cursor(hash_sql_cur, OG_TRUE)) {
        return OG_FALSE;
    }
    *out_right_semi = hash_sql_cur->exec_data.right_semi;
    return OG_TRUE;
}

static bool32 og_hash_join_fetch_right_semi_first(hash_right_semi_t *hash_right_semi)
{
    CM_POINTER(hash_right_semi);
    return hash_right_semi->is_first;
}

static inline bool32 og_hash_join_right_semi_fetch_eof(hash_right_semi_t *hash_right_semi)
{
    CM_POINTER(hash_right_semi);
    return hash_right_semi->deleted_rows == hash_right_semi->total_rows;
}

/* Usually the inner table is used to build hash table, eg
 *   SELECT * FROM A WHERE [NOT] EXISTS (SELECT * FROM B);
 * Table A is outer table and table B is inner table, during the fetch stage,
 *  each row of table A is used as hash key to match with the hash table built on table B.
 * But when the cardinality of table A is much smaller than table B, it is more efficient to use table A as hash table.
*/
status_t og_hash_join_fetch_anti_right(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    hash_right_semi_t *hash_right_semi = NULL;
    if (!og_hash_join_get_right_semi(sql_cur, plan_node, &hash_right_semi)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }

    // end of fetch when all rows in hash table has been fetched
    if (og_hash_join_right_semi_fetch_eof(hash_right_semi)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    return og_hash_join_fetch_semi_right_core(statement, sql_cur, plan_node, end, OG_FALSE);
}

status_t og_hash_join_fetch_right_semi(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    hash_right_semi_t *hash_right_semi = NULL;
    if (!og_hash_join_get_right_semi(sql_cur, plan_node, &hash_right_semi)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    if (og_hash_join_fetch_right_semi_first(hash_right_semi)) {
        if (og_hash_join_right_semi_fetch_eof(hash_right_semi)) {
            *end = OG_TRUE;
            return OG_SUCCESS;
        }
        return og_hash_join_fetch(statement, sql_cur, plan_node, end);
    }
    return og_hash_join_fetch_semi_right_core(statement, sql_cur, plan_node, end, OG_TRUE);
}