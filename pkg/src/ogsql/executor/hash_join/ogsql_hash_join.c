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
 * ogsql_hash_join.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/hash_join/ogsql_hash_join.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_hash_join.h"
#include "ogsql_nl_join.h"
#include "ogsql_hash_join_common.h"

/*
 * Resets hash join context and cursor information
 *
 * @param cursor Parent SQL cursor
 * @param hash_sql_cur   Hash join cursor to reset
 * @param join_plan       Join plan containing hash information
 * @return OG_SUCCESS on success, error code on failure
 */
static status_t og_hash_join_reset_hash_info(sql_cursor_t *sql_cur, sql_cursor_t *hash_sql_cur,
    join_plan_t *join_plan)
{
    if (sql_cur == NULL || hash_sql_cur == NULL || join_plan == NULL) {
        OG_LOG_RUN_ERR("Invalid input parameters");
        return OG_ERROR;
    }
    join_info_t *hj_info = join_plan->hash_left ? &join_plan->left_hash : &join_plan->right_hash;
    if (hj_info == NULL) {
        OG_LOG_RUN_ERR("Invalid join info");
        return OG_ERROR;
    }
    if (hash_sql_cur->hash_join_ctx->iter.hash_table != NULL) {
        vm_hash_close_page(&hash_sql_cur->hash_seg, &HASH_TABLE_ENTRY->page);
        hash_sql_cur->hash_join_ctx->iter.hash_table = NULL;
    }
    sql_reset_cursor_eof(sql_cur, hj_info, OG_FALSE);
    return init_hash_join_ctx(hash_sql_cur, join_plan->cond);
}

static status_t og_hash_join_alloc_cursor(sql_stmt_t *statement, sql_cursor_t *sql_cur, join_plan_t *join_plan,
    join_info_t *hj_info, sql_cursor_t **hash_sql_cur, plan_node_t *hash_plan_node)
{
    /* allocate hash table cursor and initialize its context
     * the cursor helps to locate rows in the materialized table for sending data to the client
     */
    if (sql_mtrl_alloc_cursor(statement, sql_cur, hash_sql_cur, hj_info, hash_plan_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to allocate mtrl cursor");
        return OG_ERROR;
    }
    (*hash_sql_cur)->hash_table_status = HASH_TABLE_STATUS_CREATE;
    sql_cur->hash_mtrl.hj_tables[join_plan->hj_pos] = *hash_sql_cur;
    if (init_hash_join_ctx(*hash_sql_cur, join_plan->cond) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to init hash join ctx");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_hash_join_open_cursor(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    sql_cursor_t **hash_sql_cur, plan_node_t *hash_plan_node)
{
    CM_POINTER5(statement, sql_cur, plan_node, hash_sql_cur, hash_plan_node);
    join_plan_t *join_plan = &plan_node->join_p;
    join_info_t *hj_info = NULL;
    if (join_plan->hash_left) {
        hj_info = &join_plan->left_hash;
    } else {
        hj_info = &join_plan->right_hash;
    }
    return og_hash_join_alloc_cursor(statement, sql_cur, join_plan, hj_info, hash_sql_cur, hash_plan_node);
}

/*
 * Creates materialized result rows for hash join tables
 *
 * @param statement          SQL statement context
 * @param sql_cur        SQL cursor
 * @param tbl_cursors Array of table cursors
 * @param hj_info     Join information containing result tables
 * @param row_ids      [out] Array to store generated row IDs
 * @return OG_SUCCESS on success, OG_ERROR on failure
 */
static status_t og_hash_join_mtrl_rs_row(sql_stmt_t *statement, sql_cursor_t *sql_cur, sql_table_cursor_t *tbl_cursors,
                                     join_info_t *hj_info, mtrl_rowid_t *row_ids)
{
    if (statement == NULL || sql_cur == NULL || tbl_cursors == NULL || hj_info == NULL || row_ids == NULL) {
        OG_LOG_RUN_ERR("Invalid input parameters");
        return OG_ERROR;
    }

    if (hj_info->rs_tables.count > OG_MAX_JOIN_TABLES) {
        OG_LOG_RUN_ERR("Too many joined tables: %u, max: %u", hj_info->rs_tables.count, OG_MAX_JOIN_TABLES);
        return OG_ERROR;
    }

    char *buf = NULL;

    if (sql_push(statement, OG_MAX_ROW_SIZE, (void **)&buf) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Faild to allocate memory of size: %u", OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }
    uint32 tbl_idx = 0;
    while (tbl_idx < hj_info->rs_tables.count) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(&hj_info->rs_tables, tbl_idx);
        if (tbl == NULL) {
            OGSQL_POP(statement);
            OG_LOG_RUN_ERR("Failed to get table for join table %u", tbl_idx);
            return OG_ERROR;
        }
        if (tbl->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
            // make result set row of query fields for normal join types
            if (sql_make_mtrl_table_rs_row(statement, sql_cur, tbl_cursors, tbl, buf, OG_MAX_ROW_SIZE) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to mtrl row at table %u", tbl_idx);
                OGSQL_POP(statement);
                return OG_ERROR;
            }
            if (mtrl_insert_row(&statement->mtrl, sql_cur->mtrl.hash_table_rs, buf, &row_ids[tbl_idx]) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to insert mtrl row for join table %u", tbl_idx);
                OGSQL_POP(statement);
                return OG_ERROR;
            }
        } else {
            // make result set row that only stores NULL for anti/semi join
            if (sql_make_mtrl_null_rs_row(&statement->mtrl, sql_cur->mtrl.hash_table_rs,
                &row_ids[tbl_idx]) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to make null row for join table %u", tbl_idx);
                OGSQL_POP(statement);
                return OG_ERROR;
            }
        }
        tbl_idx++;
    }
    OGSQL_POP(statement);
    return OG_SUCCESS;
}

static status_t og_append_hash_key_precheck(char *row_buf, uint32 *row_size, mtrl_rowid_t *mtrl_rowids, uint32 count)
{
    if (row_buf == NULL || row_size == NULL || mtrl_rowids == NULL || count == 0) {
        OG_LOG_RUN_ERR("Invalid input parameters");
        return OG_ERROR;
    }

    if (count > OG_MAX_JOIN_TABLES) {
        OG_LOG_RUN_ERR("Too many joined tables: %u, max allowed: %u", count, OG_MAX_JOIN_TABLES);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}


/*
 * Appends row IDs to a hash join key buffer after the row header
 *
 * @param row_buf       Target buffer containing row header
 * @param row_size      [in/out] Size of appended data
 * @param mtrl_rowids Array of row IDs to append
 * @param count     Number of row IDs to append
 * @return OG_SUCCESS on success, error code on failure
 */
static status_t og_append_hash_key_cb(char *row_buf, uint32 *row_size, mtrl_rowid_t *mtrl_rowids, uint32 count)
{
    OG_RETURN_IFERR(og_append_hash_key_precheck(row_buf, row_size, mtrl_rowids, count));

    row_head_t *row_hdr = (row_head_t *)row_buf;
    uint32 mtrl_rowids_size = sizeof(mtrl_rowid_t) * count;
    char *dst = row_buf + row_hdr->size;
    uint32 free_space = OG_MAX_ROW_SIZE - row_hdr->size;
    *row_size = mtrl_rowids_size + row_hdr->size;
    if (*row_size > OG_MAX_ROW_SIZE) {
        OG_LOG_RUN_ERR("Buffer overflow: required %u, max %u", *row_size, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_s(dst, free_space, mtrl_rowids, mtrl_rowids_size));
    return OG_SUCCESS;
}

/*
 * Appends result set row ids to a hash join key buffer after the row header for full join
 * match_flag is appended after the row ids which indicates if join condition is satisfied
 *
 * @param row_buf       Target buffer containing row header
 * @param row_size      [in/out] Size of appended data
 * @param mtrl_rowids Array of row IDs to append
 * @param count     Number of row IDs to append
 * @return OG_SUCCESS on success, error code on failure
 */
static status_t og_append_hash_key_for_full_join_cb(char *row_buf, uint32 *row_size,
    mtrl_rowid_t *mtrl_rowids, uint32 count)
{
    OG_RETURN_IFERR(og_append_hash_key_precheck(row_buf, row_size, mtrl_rowids, count));

    row_head_t *row_hdr = (row_head_t *)row_buf;
    uint32 mtrl_rowids_size = sizeof(mtrl_rowid_t) * count;
    *row_size = (uint32)row_hdr->size;
    *row_size += sizeof(bool8);

    if (*row_size + mtrl_rowids_size > OG_MAX_ROW_SIZE) {
        OG_LOG_RUN_ERR("Buffer overflow: required %u, max %u", *row_size, OG_MAX_ROW_SIZE);
        return OG_ERROR;
    }
    *(bool8*)(row_buf + row_hdr->size) = OG_FALSE; // match_flag is initialized to false for full join
    MEMS_RETURN_IFERR(memcpy_s(row_buf + (*row_size), OG_MAX_ROW_SIZE - (*row_size), mtrl_rowids, mtrl_rowids_size));
    *row_size += mtrl_rowids_size;
    return OG_SUCCESS;
}

static inline bool og_hash_join_skip_mtrl(mtrl_insert_func_t *mtrl_funcs, bool contains_null_key)
{
    return !mtrl_funcs->is_full_join && contains_null_key;
}

/*
 * Creates a hash key containing null values for all columns
 *
 * @param null_key_buffer   Target buffer to store the null hash key
 * @param null_val_cnt Number of null values to write
 * @return OG_SUCCESS on success, OG_ERROR on failure
 */
static status_t og_hash_join_put_null_key(char *null_key_buffer, uint32 null_val_cnt)
{
    if (null_key_buffer == NULL || null_val_cnt == 0) {
        return OG_ERROR;
    }
    row_assist_t row_ast = {0};
    row_init(&row_ast, null_key_buffer, OG_MAX_ROW_SIZE, null_val_cnt);
    uint32 idx = 0;
    while (idx < null_val_cnt) {
        if (row_put_null(&row_ast) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to put null row");
            return OG_ERROR;
        }
        idx++;
    }
    return OG_SUCCESS;
}

/*
 * Constructs a hash key for hash join operation, with special handling for NULL keys.
 *
 * @param statement     The SQL statement context
 * @param key_types     Array of data types for each key column
 * @param ra            Row assist structure for building the key
 * @param buf           Buffer to store the generated hash key
 * @param hash_keys     List of expressions that form the hash key
 * @param contains_null_key [OUT] Returns whether the generated key contains any NULL values
 * @param put_null_key  If true, special NULL key values will be inserted into the hash table
 * @param null_val_cnt  Number of key columns (used for NULL key representation)
 *
 * @return OG_SUCCESS on success, OG_ERROR on failure
 *
 * @note For NULL-aware joins: when put_null_key is true and a NULL key is found,
 *       a special NULL key entry is inserted into the hash table to ensure correct
 *       join semantics for operations like ANTI JOIN with NULL values.
 */
static status_t og_hash_join_put_hash_key(sql_stmt_t *statement, og_type_t *key_types, row_assist_t *ra, char *buf,
    galist_t *hash_keys, bool32 *contains_null_key, bool32 put_null_key, uint32 null_val_cnt)
{
    CM_POINTER5(statement, ra, buf, hash_keys, contains_null_key);
    CM_POINTER(key_types);
    if (sql_make_hash_key(statement, ra, buf, hash_keys, key_types, contains_null_key) == OG_SUCCESS) {
        if (SECUREC_UNLIKELY(*contains_null_key && put_null_key)) {
            if (og_hash_join_put_null_key(buf, null_val_cnt) != OG_SUCCESS) {
                OG_LOG_RUN_ERR("Failed to put null key");
                return OG_ERROR;
            }
            *contains_null_key = OG_FALSE;
        }
    } else {
        OG_LOG_RUN_ERR("Failed to make hash key");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * Gets the hash key type based on the joined columns
 *
 * @param statement          SQL statement context
 * @param hash_sql_cur   Hash join cursor
 * @param join_plan     Join plan
 * @param hash_keys     [out] Pointer to store hash key list
 * @param hj_info     [out] Pointer to store join info
 * @return OG_SUCCESS on success, error code on failure
 */
status_t og_hash_join_get_hash_keys_type(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur, join_plan_t *join_plan,
    galist_t *hash_keys, galist_t *probe_keys, join_info_t *hj_info)
{
    CM_POINTER4(statement, hash_sql_cur, join_plan, hj_info);
    CM_POINTER2(hash_keys, probe_keys);
    if (vmc_alloc(&hash_sql_cur->vmc, sizeof(og_type_t) * hj_info->key_items->count,
                  (void **)&hash_sql_cur->hash_join_ctx->key_types) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to alloc memory for key types on vmc, size: %lu",
                       sizeof(og_type_t) * hj_info->key_items->count);
        return OG_ERROR;
    }
    if (sql_get_hash_key_types(statement, hash_sql_cur->query, hash_keys, probe_keys,
                               hash_sql_cur->hash_join_ctx->key_types) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to get data type for hash key");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * Reads rows from inner table and inserts them into the materialized hash table
 *
 * @param statement          SQL statement context
 * @param hash_sql_cur   Hash join cursor
 * @param plan          Join plan
 * @param join_plan     Join plan
 * @param tbl_cursors Array of table cursors
 * @param mtrl_funcs    Materialized insert functions
 * @return OG_SUCCESS on success, error code on failure
 */
static status_t og_hash_join_mtrl_insert_rows(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur, plan_node_t *plan_node,
                                   join_plan_t *join_plan, sql_table_cursor_t *tbl_cursors,
                                   mtrl_insert_func_t *mtrl_funcs)
{
    CM_POINTER4(statement, hash_sql_cur, tbl_cursors, mtrl_funcs);
    CM_POINTER2(plan_node, join_plan);
    if (join_plan->left_hash.key_items->count > OG_MAX_JOIN_TABLES) {
        OG_LOG_RUN_ERR("Too many joined tables: %u, max: %u", join_plan->left_hash.key_items->count,
            OG_MAX_JOIN_TABLES);
        return OG_ERROR;
    }

    join_info_t *hj_info = join_plan->hash_left ? &join_plan->left_hash : &join_plan->right_hash;
    galist_t *hash_keys = hj_info->key_items;
    galist_t *probe_keys = join_plan->hash_left ? join_plan->right_hash.key_items : join_plan->left_hash.key_items;
    // determine the hash key type for two joined tables
    OG_RETURN_IFERR(og_hash_join_get_hash_keys_type(statement, hash_sql_cur, join_plan, hash_keys,
        probe_keys, hj_info));

    char *buf = NULL;
    mtrl_rowid_t row_ids[OG_MAX_JOIN_TABLES];
    bool32 end = OG_FALSE;
    uint32 row_size = 0;
    bool32 match_found = OG_FALSE;
    bool32 contains_null_key = OG_FALSE;
    row_assist_t ra;
    // the null key is not needed for the inner table
    bool32 put_null_key = ((join_plan->oper == JOIN_OPER_HASH_RIGHT_ANTI) ||
                            (join_plan->oper == JOIN_OPER_HASH_RIGHT_ANTI_NA) ||
                            (join_plan->oper == JOIN_OPER_HASH_RIGHT_LEFT));
    OGSQL_SAVE_STACK(statement);
    while (OG_TRUE) {
        RET_IFERR_RESTORE_STACK(sql_fetch_for_join(statement, hash_sql_cur, plan_node, &end), statement);
        if (end) {
            OGSQL_RESTORE_STACK(statement);
            break;
        }
        RET_IFERR_RESTORE_STACK(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&buf), statement);
        RET_IFERR_RESTORE_STACK(og_hash_join_put_hash_key(statement, hash_sql_cur->hash_join_ctx->key_types,
        &ra, buf, hash_keys, &contains_null_key, put_null_key, join_plan->left_hash.key_items->count), statement);
        if (og_hash_join_skip_mtrl(mtrl_funcs, contains_null_key)) {
            buf = NULL;
            row_size = 0;
        } else {
            /* Make result set row for materialized table */
            RET_IFERR_RESTORE_STACK(og_hash_join_mtrl_rs_row(statement, hash_sql_cur, tbl_cursors,
                hj_info, row_ids), statement);

            /* Append key to row, the key is the row id of the inner table.
             * Depends on the join type, there are different append key functions.
             * For full join, there are extra match_flag to indicate if the row is matched.
             * Due to the full join result set includes all rows from both tables whether there is a match.
             */
            RET_IFERR_RESTORE_STACK(mtrl_funcs->append_key(buf, &row_size, row_ids,
                hj_info->rs_tables.count), statement);
        }

        /* Insert the row into the hash table, the insert function is determined by the join type.
         * For semi join and anti join, no need to include duplicate rows.
         */
        RET_IFERR_RESTORE_STACK(mtrl_funcs->vm_insert(&match_found, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY,
            buf, row_size), statement);
        OGSQL_RESTORE_STACK(statement);

        // return early for NULL-AWARE anti join since a null key is found in the inner table, the result set is empty
        OG_BREAK_IF_TRUE(join_plan->oper == JOIN_OPER_HASH_ANTI_NA && contains_null_key);
    }
    return OG_SUCCESS;
}

static status_t og_hash_join_free_hash_table(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node)
{
    CM_POINTER3(statement, sql_cur, plan_node);
    if (sql_stack_safe(statement) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("stack not safe");
        return OG_ERROR;
    }

    if (plan_node->type != PLAN_NODE_JOIN) {
        return OG_SUCCESS;
    }

    join_oper_t oper = plan_node->join_p.oper;

    if (oper == JOIN_OPER_NL || oper == JOIN_OPER_NL_LEFT || oper == JOIN_OPER_NL_FULL || oper == JOIN_OPER_NL_BATCH) {
        if (og_hash_join_free_hash_table(statement, sql_cur, plan_node->join_p.left) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to free left table");
            return OG_ERROR;
        }
        if (og_hash_join_free_hash_table(statement, sql_cur, plan_node->join_p.right) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to free right table");
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    if (oper == JOIN_OPER_HASH || oper == JOIN_OPER_HASH_LEFT || oper == JOIN_OPER_HASH_SEMI ||
        oper == JOIN_OPER_HASH_ANTI || oper == JOIN_OPER_HASH_ANTI_NA ||
        oper == JOIN_OPER_HASH_FULL || oper == JOIN_OPER_HASH_PAR) {
        (void)og_hash_join_free_mtrl_cursor(statement, sql_cur, plan_node);
        return OG_SUCCESS;
    }
    
    if (oper == JOIN_OPER_MERGE || oper == JOIN_OPER_MERGE_LEFT || oper == JOIN_OPER_MERGE_FULL) {
        return OG_SUCCESS;
    }

    return OG_SUCCESS;
}

static status_t og_create_hash_mtrl_segment(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur, plan_node_t *plan_node,
                                        oper_func_t q_oper, bool32 is_full_join)
{
    CM_POINTER3(statement, hash_sql_cur, plan_node);
    uint32 num_buckets = (uint32)(plan_node->rows * OG_HASH_FACTOR);
    vm_hash_segment_init(KNL_SESSION(statement), KNL_SESSION(statement)->temp_pool, &hash_sql_cur->hash_seg, PMA_POOL,
        HASH_PAGES_HOLD, HASH_AREA_SIZE);
    if (vm_hash_table_alloc(HASH_TABLE_ENTRY, &hash_sql_cur->hash_seg, num_buckets) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to allocate hash table");
        return OG_ERROR;
    }

    if (vm_hash_table_init(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, NULL, q_oper, hash_sql_cur) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to initialize hash table");
        return OG_ERROR;
    }

    if (!is_full_join) {
        hash_sql_cur->hash_join_ctx->iter.curr_bucket = 0;
        hash_sql_cur->hash_join_ctx->iter.curr_match.vmid = OG_INVALID_ID32;
    }

    if (mtrl_create_segment(&statement->mtrl, MTRL_SEGMENT_HASHMAP_RS, NULL, &hash_sql_cur->mtrl.hash_table_rs)
        != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to create materialized segment");
        return OG_ERROR;
    }
    if (!is_full_join) {
        if (sql_set_segment_pages_hold(&statement->mtrl, hash_sql_cur->mtrl.hash_table_rs,
                                       g_instance->sql.segment_pages_hold) != OG_SUCCESS) {
            OG_LOG_RUN_ERR("Failed to set segment pages hold");
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t og_hash_join_create_mtrl_hash_table(sql_stmt_t *statement, sql_cursor_t *hash_sql_cur,
    plan_node_t *plan_node, join_plan_t *join_plan, sql_table_cursor_t *table, mtrl_insert_func_t *mtrl_funcs)
{
    CM_POINTER4(statement, hash_sql_cur, table, mtrl_funcs);
    CM_POINTER2(plan_node, join_plan);
    if (og_create_hash_mtrl_segment(statement, hash_sql_cur, plan_node, mtrl_funcs->q_oper, mtrl_funcs->is_full_join)
        != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to create hash mtrl segment");
        return OG_ERROR;
    }

    if (mtrl_open_segment(&statement->mtrl, hash_sql_cur->mtrl.hash_table_rs) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to open hash mtrl segment");
        return OG_ERROR;
    }

    if (SQL_CURSOR_PUSH(statement, hash_sql_cur) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to push cursor");
        return OG_ERROR;
    }

    if (og_hash_join_mtrl_insert_rows(statement, hash_sql_cur, plan_node, join_plan,
        table, mtrl_funcs) != OG_SUCCESS) {
        SQL_CURSOR_POP(statement);
        OG_LOG_RUN_ERR("Failed to insert rows to mtrl hash table");
        return OG_ERROR;
    }
    SQL_CURSOR_POP(statement);
    mtrl_close_segment(&statement->mtrl, hash_sql_cur->mtrl.hash_table_rs);

    if (vm_hash_table_empty(&hash_sql_cur->eof, &hash_sql_cur->hash_seg, HASH_TABLE_ENTRY) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to find out if hash table is empty");
        return OG_ERROR;
    }
    if (og_hash_join_free_hash_table(statement, hash_sql_cur, plan_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to free hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/*
 * join types that the result set will be empty once the hash table is empty
 *
 * @param oper The join operation
 * @return OG_TRUE if the hash table is driven by the outer table, OG_FALSE otherwise
 */
static bool32 hash_table_is_drive(join_oper_t oper)
{
    switch (oper) {
        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_RIGHT_LEFT:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_RIGHT_SEMI:
        case JOIN_OPER_HASH_RIGHT_ANTI:
        case JOIN_OPER_HASH_RIGHT_ANTI_NA:
            return OG_TRUE;
        default:
            break;
    }
    return OG_FALSE;
}

/*
 * Execute the hash plan for hash join by:
 * 1. Getting or creating the hash cursor
 * 2. Building the materialized hash table
 *
 * @param statement          The SQL statement context
 * @param cursor The parent cursor
 * @param plan         The plan node containing join info
 * @param end          End of fetch indicator
 * @param is_distinct  Whether to use distinct hash table insert
 * @return Status code
 */
static status_t og_build_join_hash_table(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node,
    bool32 *end, bool32 is_distinct)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    plan_node_t *hash_plan_node = plan_node->join_p.hash_left? plan_node->join_p.left : plan_node->join_p.right;

    /* If the hash table is existed, do not need to rebuild it, just reset the hash info */
    plan_node_t *probe_plan = NULL;
    og_get_probe_plan(&probe_plan, &plan_node->join_p);
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (hash_sql_cur != NULL) {
        if (hash_sql_cur->eof && hash_table_is_drive(plan_node->join_p.oper)) {
            // the result set is empty
            og_end_hash_join_fetch(sql_cur, probe_plan);
            return OG_SUCCESS;
        }
        return og_hash_join_reset_hash_info(sql_cur, hash_sql_cur, &plan_node->join_p);
    }

    if (og_hash_join_open_cursor(statement, sql_cur, plan_node, &hash_sql_cur, hash_plan_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to open cursor for hash plan");
        return OG_ERROR;
    }

    if (sql_execute_for_join(statement, hash_sql_cur, hash_plan_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute hash plan");
        return OG_ERROR;
    }
    mtrl_insert_func_t mtrl_funcs = {
        .append_key = og_append_hash_key_cb,
        .vm_insert = is_distinct ? vm_hash_table_insert2 : vm_hash_table_insert,
        .q_oper = og_fetch_next_row_cb,
        .is_full_join = OG_FALSE,
    };
    if (og_hash_join_create_mtrl_hash_table(statement, hash_sql_cur, hash_plan_node, &plan_node->join_p,
                                        sql_cur->tables, &mtrl_funcs) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to create mtrl hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t og_hash_join_exec_probe_plan(sql_stmt_t *statement, sql_cursor_t *sql_cur,
    plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    join_plan_t *join_plan = &plan_node->join_p;
    plan_node_t *probe_plan = join_plan->hash_left ? join_plan->right : join_plan->left;

    cond_tree_t *saved_cond = sql_cur->cond;
    sql_cur->cond = join_plan->hash_left ? join_plan->right_hash.filter_cond : join_plan->left_hash.filter_cond;
    if (sql_execute_for_join(statement, sql_cur, probe_plan) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute for probe plan");
        return OG_ERROR;
    }
    sql_cur->cond = saved_cond;
    return OG_SUCCESS;
}

/*
 * core function to execute the hash join plan
 */
status_t og_hash_join_execute_core(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end,
                               bool32 is_distinct)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    *end = OG_FALSE;
    // build materialized hash table from smaller table
    if (og_build_join_hash_table(statement, sql_cur, plan_node, end, is_distinct) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to build hash table");
        return OG_ERROR;
    }
    if (og_hash_join_exec_probe_plan(statement, sql_cur, plan_node, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to exececute plan for probe table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t og_hash_join_execute(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    if (og_hash_join_execute_core(statement, sql_cur, plan_node, end, OG_FALSE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute hash join");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t og_hash_join_exec_right_left(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    if (og_hash_join_execute_core(statement, sql_cur, plan_node, end, OG_FALSE) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute hash join right left");
        return OG_ERROR;
    }
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (og_hash_join_sql_cursor_eof(hash_sql_cur)) {
        *end = OG_TRUE;
        return OG_SUCCESS;
    }
    if (vm_hash_table_init(&hash_sql_cur->hash_seg, HASH_TABLE_ENTRY, NULL, og_fetch_right_left_row_cb,
        hash_sql_cur) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to init hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

/* Build hash table for full join */
static status_t og_build_full_join_hash_table(sql_stmt_t *statement, sql_cursor_t *sql_cur,
    plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    plan_node_t *hash_plan_node = NULL;
    if (plan_node->join_p.hash_left) {
        hash_plan_node = plan_node->join_p.left;
    } else {
        hash_plan_node = plan_node->join_p.right;
    }
    *end = OG_FALSE;
    sql_cursor_t *hash_sql_cur = og_hash_join_get_hash_cursor(sql_cur, plan_node);
    if (hash_sql_cur != NULL) {
        return og_hash_join_reset_hash_info(sql_cur, hash_sql_cur, &plan_node->join_p);
    }
    if (og_hash_join_open_cursor(statement, sql_cur, plan_node, &hash_sql_cur, hash_plan_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to open cursor");
        return OG_ERROR;
    }
    if (sql_execute_for_join(statement, hash_sql_cur, hash_plan_node) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to execute hash plan");
        return OG_ERROR;
    }
    mtrl_insert_func_t mtrl_funcs = {
        .vm_insert = vm_hash_table_insert,
        .append_key = og_append_hash_key_for_full_join_cb,
        .q_oper = og_fetch_full_join_row_cb,
        .is_full_join = OG_TRUE,
    };
    if (og_hash_join_create_mtrl_hash_table(statement, hash_sql_cur, hash_plan_node, &plan_node->join_p,
        sql_cur->tables, &mtrl_funcs) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to create hash table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t og_hash_join_exec_full(sql_stmt_t *statement, sql_cursor_t *sql_cur, plan_node_t *plan_node, bool32 *end)
{
    CM_POINTER4(statement, sql_cur, plan_node, end);
    *end = OG_FALSE;

    if (og_build_full_join_hash_table(statement, sql_cur, plan_node, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to build hash table");
        return OG_ERROR;
    }

    if (og_hash_join_exec_probe_plan(statement, sql_cur, plan_node, end) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("Failed to exececute plan for probe table");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
