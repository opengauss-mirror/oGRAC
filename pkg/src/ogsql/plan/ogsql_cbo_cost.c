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
 * ogsql_cbo_cost.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/ogsql_cbo_cost.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_scan.h"
#include "plan_query.h"
#include "srv_instance.h"
#include "table_parser.h"
#include "ogsql_table_func.h"
#include "plan_rbo.h"
#include "plan_range.h"
#include "ostat_load.h"
#include "cbo_base.h"
#include "plan_scan.h"
#include "ogsql_cbo_cost.h"
#include "ogsql_join_path.h"

#ifdef __cplusplus
extern "C" {
#endif

static double compute_or_conds_ff(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table, galist_t *or_conds,
    cbo_stats_info_t* stats_info);
static double compute_and_conds_ff(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table, cond_node_t *cond,
    cbo_stats_info_t* stats_info);
static inline sort_direction_t apply_hint_index_sort_scan_direction(sql_table_t *table, knl_index_desc_t *index);

inline static double sql_normalize_ff(double ff)
{
    if (ff < 0) {
        ff = 0;
    } else if (ff > 1) {
        ff = 1;
    }

    return ff;
}

double sql_adjust_est_row(double rows)
{
    if (rows > CBO_JOIN_MAX_CARD) {
        rows = CBO_JOIN_MAX_CARD;
    } else if (rows <= 1.0) {
        rows = 1.0;
    } else {
        rows = rint(rows);
    }

    return rows;
}

static inline bool32 check_index_fast_full_scan(cbo_index_choose_assist_t *ca)
{
    return ca->index_ffs && INDEX_ONLY_SCAN_ONLY(ca->scan_flag);
}

bool32 get_table_skip_index_flag(sql_table_t *table, uint32 id)
{
    uint64 pos = ((uint64)1 << id);
    return (bool32)((table->cbo_attr.idx_ss_flags & pos) != 0);
}

static inline void set_table_skip_index_flag(sql_table_t *table, uint32 id, bool32 flag)
{
    uint64 pos = ((uint64)1 << id);
    if (flag) {
        table->cbo_attr.idx_ss_flags |= pos;
    } else {
        table->cbo_attr.idx_ss_flags &= (~pos);
    }
}

static bool32 cbo_get_index_skip_flag(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, sql_table_t *table,
                                    galist_t *cond_cols, galist_t *conds, cbo_stats_info_t* stats_info)
{
    if (IS_REVERSE_INDEX(ca->index)) {
        return OG_FALSE;
    }

    /* use range scan when the first column of index is an equal cond, a = 1 and b = 10 */
    if (ca->strict_equal_cnt > 0) {
        return OG_FALSE;
    }

    if (ca->idx_match_cnt <= 1) {
        return OG_FALSE;
    }

    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    uint16 leading_col = ca->index->columns[0];
    /* cal num_disdinct: the number of unique value according to this column */
    cbo_stats_column_t *column_stats = cbo_get_column_stats(stats_info->cbo_table_stats, leading_col);
    uint64 num_dist = (column_stats == NULL ? OG_INVALID_ID64 : column_stats->num_distinct);
    if (num_dist == OG_INVALID_ID64) {
        return OG_FALSE;
    }
    
    cbo_stats_index_t *index_stats = stats_info->cbo_index_stats;
    if (index_stats == NULL) {
        return OG_FALSE;
    }

    double ff;
    OGSQL_SAVE_STACK(stmt);
    RET_AND_RESTORE_STACK_IFERR(compute_hist_factor_by_conds(stmt, entity, cond_cols, conds, &ff, stats_info), stmt);
    OGSQL_RESTORE_STACK(stmt);
    uint32 leaf_blks = MAX(index_stats->leaf_blocks, 1);
    if (leaf_blks == 0) {
        return OG_FALSE;
    }
    double ff2 = (double)num_dist / leaf_blks;
    return (bool32)(ff2 < ff);
}

static inline double index_ffs_io_cost(cbo_stats_index_t *idx_stats)
{
    double blocks_fetched;
    if (idx_stats == NULL) {
        blocks_fetched = CBO_INDEX_BASE_BLOCKS;
    } else {
        blocks_fetched = MAX(idx_stats->leaf_blocks, CBO_INDEX_BASE_BLOCKS);
    }

    /* IO cost: cost for index ffs is the same as index full scan nowdays for cantian */
    double cost = blocks_fetched * CBO_DEFAULT_SEQ_PAGE_COST;
    return CBO_COST_SAFETY_RET(cost);
}

static status_t cbo_table_need_cal_ss_column_count(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, index_t *index,
    galist_t *index_cond, galist_t *cond_cols, galist_t *ss_cond_cols,
    galist_t *ss_fisrt_index_bound_quals, galist_t *ss_index_bound_quals)
{
    uint32 col_id = 0;
    uint32 *cond_col = NULL;
    uint32 cond_idx;
    OGSQL_SAVE_STACK(stmt);
    for (cond_idx = 0; cond_idx < index_cond->count; cond_idx++) {
        cmp_node_t *cmp = NULL;

        if (index->desc.columns[col_id] != *(uint32*)cm_galist_get(cond_cols, cond_idx)) {
            col_id++;
            if (index->desc.columns[col_id] != *(uint32*)cm_galist_get(cond_cols, cond_idx)) {
                break;
            }
        }

        cmp = (cmp_node_t*)cm_galist_get(index_cond, cond_idx);
        
        /* a > 1 and b  = 10 and c = 5
        * range scan: idx_match_cnt = 1 = index_bound_quals->count
        * skip scan for not equel of the first column: idx_match_cnt = 3
        * skip scan for lack of the first column: idx_match_cnt = 2 (b  = 10 and c = 5)
        */
        ca->idx_match_cnt++;
        RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(ss_index_bound_quals, cmp), stmt);

        if (index->desc.columns[0] == *(uint32*)cm_galist_get(cond_cols, cond_idx)) {
            RET_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(uint32), (void **)&cond_col), stmt);
            *cond_col = index->desc.columns[col_id];
            RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(ss_cond_cols, cond_col), stmt);
            RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(ss_fisrt_index_bound_quals, cmp), stmt);
        }

        if (col_id != 0 && cmp->type != CMP_TYPE_EQUAL && cmp->type != CMP_TYPE_IN) {
            break;
        }
    }
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t cbo_table_check_skip_scan_index(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, sql_table_t *table,
    index_t *index, galist_t *cond_cols, galist_t *index_cond, galist_t *ss_index_bound_quals,
    cbo_stats_info_t* stats_info, bool32 ss_strict_flag)
{
    galist_t *ss_fisrt_index_bound_quals = NULL;
    galist_t *ss_cond_cols = NULL;
    OGSQL_SAVE_STACK(stmt);
    RET_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&ss_cond_cols), stmt);
    cm_galist_init(ss_cond_cols, stmt, sql_stack_alloc);

    RET_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&ss_fisrt_index_bound_quals), stmt);
    cm_galist_init(ss_fisrt_index_bound_quals, stmt, sql_stack_alloc);

    cbo_table_need_cal_ss_column_count(stmt, ca, index, index_cond, cond_cols, ss_cond_cols,
                                    ss_fisrt_index_bound_quals, ss_index_bound_quals);

    if (ss_strict_flag) {
        ca->idx_match_cnt++;
    }

    if (cbo_get_index_skip_flag(stmt, ca, table, ss_cond_cols, ss_fisrt_index_bound_quals, stats_info)) {
        set_table_skip_index_flag(table, ca->index->id, OG_TRUE);
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }

    if (ss_strict_flag) {
        ca->idx_match_cnt--;
    }
    set_table_skip_index_flag(table, ca->index->id, OG_FALSE);
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static double is_null_hist_factor(cbo_stats_column_t *column_stats)
{
    if (column_stats == NULL) {
        return CBO_DEFAULT_NULL_FF;
    }
    if (column_stats->total_rows == 0) {
        return 0.0;
    }
    return 1.0 * column_stats->num_null / column_stats->total_rows;
}

static status_t sql_calc_cost_index(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t *index_cond, galist_t *cond_cols, double *cost, int64* card,
    cbo_stats_info_t* stats_info, sql_table_t *table)
{
    galist_t *index_bound_quals = NULL;
    bool32 equal_here = OG_FALSE;
    uint32 col_id;
    uint32 cond_idx;
    double index_ff;
    double table_ff;
    galist_t *ss_index_bound_quals = NULL;
    bool32 ss_strict_flag = OG_FALSE;

    /*
     * For a btree scan, only leading '=' conds plus inequality cond for the
     * immediately next attribute contribute to index filter factor (these are
     * the "boundary quals" that determine the starting and stopping points of
     * the index scan).
     */
    OGSQL_SAVE_STACK(stmt);
    RET_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&index_bound_quals), stmt);
    cm_galist_init(index_bound_quals, stmt, sql_stack_alloc);

    RET_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&ss_index_bound_quals), stmt);
    cm_galist_init(ss_index_bound_quals, stmt, sql_stack_alloc);

    col_id = 0;
    for (cond_idx = 0; cond_idx < index_cond->count; cond_idx++) {
        cmp_node_t *cmp = NULL;

        if (index->desc.columns[col_id] != *(uint32*)cm_galist_get(cond_cols, cond_idx)) {
            /* Beginning of a new column's quals */
            if (!equal_here) {
                break; /* done if no '=' qual for indexcol */
            }
            equal_here = false;
            col_id++;
            if (index->desc.columns[col_id] != *(uint32*)cm_galist_get(cond_cols, cond_idx)) {
                break;
            }
        }

        cmp = (cmp_node_t*)cm_galist_get(index_cond, cond_idx);
        if (cmp->type == CMP_TYPE_EQUAL && ca->strict_equal_cnt <= col_id) {
            equal_here = true;
            ca->strict_equal_cnt++;
        }
        cm_galist_insert(index_bound_quals, cmp);
    }
    
    if (index_cond->count != 0 && index_bound_quals->count == 0) {
        ss_strict_flag = true;
    }

    if (index_bound_quals->count == 0) {
        ca->index_full_scan = true;
    }
    // to do ffs scan, cbo_check_skip_ffs_index_hint, now ffs not support. table.index_ffs = ca.index_ffs = true

    if (IS_INDEX_UNIQUE(&index->desc) && index->desc.column_count == ca->strict_equal_cnt) {
        index_ff = table_ff = stats_info->cbo_table_stats->rows == 0 ? 0 : 1.0 / (stats_info->cbo_table_stats->rows);
    } else {
        /* check to use skip index, two condition for matching skip index
         * one condition: lack of the first column of index.
         * two condition: type of the first column of index is not equel.
         */
        if (ss_strict_flag || ((ca->strict_equal_cnt == 0) && (index_bound_quals->count > 0))) {
            cbo_table_check_skip_scan_index(stmt, ca, table, index, cond_cols, index_cond,
                ss_index_bound_quals, stats_info, ss_strict_flag);
        }

        if (get_table_skip_index_flag(table, ca->index->id)) {
            index_bound_quals = ss_index_bound_quals;
            ca->index_full_scan = false;
        }

        RET_AND_RESTORE_STACK_IFERR(compute_hist_factor_by_conds(stmt, entity, cond_cols, index_bound_quals,
            &index_ff, stats_info), stmt);

        /*
        * Additional quals to index_bound_quals can suppress visits to the heap, so
        * it's OK to count them in table_ff.
        */
        RET_AND_RESTORE_STACK_IFERR(compute_hist_factor_by_conds(stmt, entity, cond_cols, index_cond,
            &table_ff, stats_info), stmt);
    }

    OGSQL_RESTORE_STACK(stmt);

    if (card != NULL) {
        *card = round(stats_info->cbo_table_stats->rows * table_ff);
    }

    /*
     * Index_cost = start-up cost + index io cost + index cpu cost + table io cost + table cpu cost
     * start-up cost = blevel * rand_page_cost
     * index io cost = leaf_blocks * index_ff * rand_page_cost
     * index cpu cost = 1/idx_stats->avg_leaf_key * cpu_operator_cost
     * table io cost = table_ff * clustering_factor + table_ff * table_stats->blocks * seq_page_cost
     * table cpu cost = table_rows * table_ff * cpu_operator_cost
     */
    cbo_stats_index_t *index_stats = stats_info->cbo_index_stats;
    *cost = 0;
    uint32 blevel = index_stats->blevel;

    /* start up cost*/
    ca->startup_cost += blevel * CBO_DEFAULT_RANDOM_PAGE_COST;
    ca->startup_cost = CBO_COST_SAFETY_RET(ca->startup_cost);
    *cost += ca->startup_cost;

    /* index io cost */
    if (check_index_fast_full_scan(ca)) {
        // INDEX FAST FULL SCAN, JUST consider single table to lower the impact nowadays.
        double cost_fast_full_scan = index_ffs_io_cost(index_stats);
        *cost += cost_fast_full_scan;
    } else {
        *cost += (index_stats->leaf_blocks) * index_ff * CBO_DEFAULT_RANDOM_PAGE_COST;
    }

    /* index cpu cost */
    if (index_stats->avg_leaf_key != 0) {
        *cost += 1 / index_stats->avg_leaf_key * CBO_DEFAULT_CPU_OPERATOR_COST;
    }

    if (INDEX_ONLY_SCAN(ca->scan_flag)) {
        return OG_SUCCESS;
    }

    /*
     * table io cost: Disk I/O is positively correlated with the clustering factor
     */
    *cost += table_ff * index_stats->clustering_factor +
             table_ff * stats_info->cbo_table_stats->blocks * CBO_DEFAULT_SEQ_PAGE_COST;
    /* table cpu cost */
    *cost += stats_info->cbo_table_stats->rows * table_ff * CBO_DEFAULT_CPU_OPERATOR_COST;

    return OG_SUCCESS;
}

double sql_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity, index_t *index,
    galist_t **idx_cond_array, int64 *card, cbo_stats_info_t* stats_info, sql_table_t *table)
{
    galist_t *index_cond = NULL;
    galist_t *cond_cols = NULL;
    uint32 col_id;
    uint32 cond_idx;
    double cost = RBO_COST_INFINITE;

    /*
     * collect the index conds into a single list, and build an integer list
     * of the index column numbers that each cond should be used with. The conds
     * are ordered by index key, so that the column numbers form a nondecreasing
     * sequence.
     */
    OGSQL_SAVE_STACK(stmt);
    RETVALUE_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&index_cond), stmt, cost);
    cm_galist_init(index_cond, stmt, sql_stack_alloc);

    RETVALUE_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&cond_cols), stmt, cost);
    cm_galist_init(cond_cols, stmt, sql_stack_alloc);

    for (col_id = 0; col_id < index->desc.column_count; col_id++) {
        for (cond_idx = 0; cond_idx < idx_cond_array[col_id]->count; cond_idx++) {
            uint32 *cond_col = NULL;
            RETVALUE_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(uint32), (void **)&cond_col), stmt, cost);
            *cond_col = index->desc.columns[col_id];

            RETVALUE_AND_RESTORE_STACK_IFERR(cm_galist_insert(index_cond,
                cm_galist_get(idx_cond_array[col_id], cond_idx)), stmt, cost);
            RETVALUE_AND_RESTORE_STACK_IFERR(cm_galist_insert(cond_cols, cond_col), stmt, cost);
        }
    }

    RETVALUE_AND_RESTORE_STACK_IFERR(sql_calc_cost_index(stmt, ca, entity, index, index_cond, cond_cols, &cost,
        card, stats_info, table), stmt, cost);
    OGSQL_RESTORE_STACK(stmt);

    return cost;
}

static status_t binary_search_histogram(sql_stmt_t *stmt, dc_entity_t *entity, cbo_stats_column_t *column_stats,
    uint32 col_id, variant_t *const_val, bool isgt, uint32 *res)
{
    uint32 low_bound = 0;
    uint32 high_bound = column_stats->hist_count;
    variant_t ep_var;
    int32 cmp;

    while (low_bound < high_bound) {
        int probe = (low_bound + high_bound) / 2;
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[probe]->ep_value, &ep_var);
        OG_RETURN_IFERR(sql_compare_variant(stmt, &ep_var, const_val, &cmp));

        if (cmp < 0 || (cmp == 0 && isgt)) {
            low_bound = probe + 1;
        } else {
            high_bound = probe;
        }
    }

    *res = low_bound;
    return OG_SUCCESS;
}

#define MAX_STR_COMPARE_LEN 20

static double calc_normalized_string_position(sql_stmt_t *stmt,
    variant_t *start_var, variant_t *middle_var, variant_t *end_var)
{
    int32 cmp;
    OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, middle_var, start_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_INEQ_FF);
    if (cmp <= 0) {
        return 0;
    }
    OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, middle_var, end_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_INEQ_FF);
    if (cmp >= 0) {
        return 1;
    }

    const text_t *start_text = VALUE_PTR(text_t, start_var);
    const text_t *middle_text = VALUE_PTR(text_t, middle_var);
    const text_t *end_text = VALUE_PTR(text_t, end_var);

    int32 max_len = MAX(start_text->len, MAX(middle_text->len, end_text->len));
    max_len = MIN(max_len, MAX_STR_COMPARE_LEN);

    double start_val = 0;
    double middle_val = 0;
    double end_val = 0;
    uchar base_min = OG_MAX_UINT8;
    uchar base_max = 0;
    for (int32 i = 0; i < start_text->len; i++) {
        base_min = MIN(base_min, start_text->str[i]);
        base_max = MAX(base_max, start_text->str[i]);
    }
    for (int32 i = 0; i < middle_text->len; i++) {
        base_min = MIN(base_min, middle_text->str[i]);
        base_max = MAX(base_max, middle_text->str[i]);
    }
    for (int32 i = 0; i < end_text->len; i++) {
        base_min = MIN(base_min, end_text->str[i]);
        base_max = MAX(base_max, end_text->str[i]);
    }
    uint16 base = base_max - base_min + 1;
    for (int32 i = 0; i < max_len; i++) {
        uchar start_c = 0;
        if (i < start_text->len) {
            start_c = start_text->str[i] - base_min + 1;
        }
        start_val = start_val * base + start_c;
        uchar middle_c = 0;
        if (i < middle_text->len) {
            middle_c = middle_text->str[i] - base_min + 1;
        }
        middle_val = middle_val * base + middle_c;
        uchar end_c = 0;
        if (i < end_text->len) {
            end_c = end_text->str[i] - base_min + 1;
        }
        end_val = end_val * base + end_c;
    }
    return (end_val - middle_val) / (end_val - start_val);
}

#undef MAX_STR_COMPARE_LEN

static double ineq_balanced_hist_factor_var(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, variant_t *const_val, bool isgt)
{
    double hist_frac;
    uint32 n_hist = column_stats->hist_count;
    uint32 low_bound = 0;
    int32 cmp;

    OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val, isgt, &low_bound) !=
                       OG_SUCCESS, CBO_DEFAULT_INEQ_FF);

    /*
     * 1. low_bound == 0
     *      a. const_val <= low_value
     *      b. low_value < const_val <= column_hist[0]
     * 2. 0 < low_bound < n_hist
     * 3. low_bound == n_hist
     */
    variant_t low_var;
    knl_cbo_text2variant(entity, col_id, &column_stats->low_value, &low_var);
    OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, const_val, &low_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_INEQ_FF);
    if (low_bound == 0 && cmp <= 0) {
        /* 1.a */
        hist_frac = 0;
    } else if (low_bound == n_hist) {
        /* 3 */
        hist_frac = 1.0 - is_null_hist_factor(column_stats);
    } else {
        /* 1.b && 2 */
        variant_t left_var;
        variant_t right_var;
        if (low_bound == 0) {
            left_var = low_var;
        } else {
            knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[low_bound - 1]->ep_value, &left_var);
        }
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[low_bound]->ep_value, &right_var);

        variant_t bucket_var;
        OG_RETVALUE_IFTRUE(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), const_val, &left_var, &bucket_var) != OG_SUCCESS,
                           CBO_DEFAULT_INEQ_FF);

        variant_t hist_var;
        OG_RETVALUE_IFTRUE(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &right_var, &left_var, &hist_var) != OG_SUCCESS,
                           CBO_DEFAULT_INEQ_FF);

        OG_RETVALUE_IFTRUE(var_as_real(&bucket_var) != OG_SUCCESS, CBO_DEFAULT_INEQ_FF);
        OG_RETVALUE_IFTRUE(var_as_real(&hist_var) != OG_SUCCESS, CBO_DEFAULT_INEQ_FF);
        hist_frac = bucket_var.v_real / hist_var.v_real;

        hist_frac += low_bound;
        hist_frac /= n_hist;
    }

    hist_frac = isgt ? (1.0 - hist_frac) : hist_frac;

    return hist_frac * (1.0 - is_null_hist_factor(column_stats));
}

static double ineq_balanced_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node, bool isgt)
{
    variant_t reserved_value;
    variant_t *const_val = &node->value;
    if (NODE_IS_RES_TRUE(node) || NODE_IS_RES_FALSE(node)) {
        (void)sql_get_reserved_value(stmt, node, &reserved_value);
        const_val = &reserved_value;
    } else if (node->type != EXPR_NODE_CONST) {
        return CBO_DEFAULT_INEQ_FF;
    }

    return ineq_balanced_hist_factor_var(stmt, entity, col_id, column_stats, const_val, isgt);
}

static double eq_balanced_hist_factor_var(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, variant_t *const_val)
{
    double hist_frac;
    uint32 n_hist = column_stats->hist_count;
    uint32 low_bound = 0;
    int32 cmp;

    OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val, false, &low_bound) !=
                       OG_SUCCESS, CBO_DEFAULT_EQ_FF);

    /*
     * 1. low_bound == 0
     *      a. const_val < low_value
     *      b. const_val == column_hist[low_bound]: 查找有几个连续的槽位是一样的，这里面再判断const_val是否等于low_value
     *      c. low_value <= const_val < column_hist[0]
     * 2. 0 < low_bound < n_hist
     *      a. const_val < column_hist[low_bound]
     *      b. const_val == column_hist[low_bound]: 查找有几个连续的槽位是一样的
     * 3. low_bound == n_hist
     */
    if (low_bound == n_hist) {
        /* 3 */
        hist_frac = 0;
        return hist_frac;
    }

    variant_t low_var;
    variant_t left_var;
    variant_t right_var;
    knl_cbo_text2variant(entity, col_id, &column_stats->low_value, &low_var);
    if (low_bound == 0) {
        OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, const_val, &low_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);
        if (cmp < 0) {
            /* 1.a */
            hist_frac = 0;
            return hist_frac;
        }

        left_var = low_var;
    } else {
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[low_bound - 1]->ep_value, &left_var);
    }

    knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[low_bound]->ep_value, &right_var);

    int32 num_eq_slot = 0;
    OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, &left_var, &right_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);
    if (cmp == 0) {
        num_eq_slot++;
    }
    int32 index = low_bound + 1;
    OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, const_val, &right_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);
    while (cmp == 0 && index < n_hist) {
        variant_t index_var;
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[index]->ep_value, &index_var);
        OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, const_val, &index_var, &cmp) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);

        if (cmp != 0) {
            break;
        }
        num_eq_slot++;
        index++;
    }

    if (num_eq_slot != 0) {
        /* 1.b && 2.b */
        hist_frac = num_eq_slot * 1.0 / n_hist;
    } else {
        /* 1.c && 2.a */
        variant_t bucket_var;
        OG_RETVALUE_IFTRUE(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &right_var, &left_var, &bucket_var) !=
                           OG_SUCCESS, CBO_DEFAULT_EQ_FF);

        variant_t high_var;
        knl_cbo_text2variant(entity, col_id, &column_stats->high_value, &high_var);
        variant_t hist_var;
        OG_RETVALUE_IFTRUE(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &high_var, &low_var, &hist_var) != OG_SUCCESS,
                           CBO_DEFAULT_EQ_FF);

        OG_RETVALUE_IFTRUE(var_as_real(&bucket_var) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);
        OG_RETVALUE_IFTRUE(var_as_real(&hist_var) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);
        hist_frac = bucket_var.v_real / hist_var.v_real;

        /* num_distinct in this bucket */
        hist_frac *= column_stats->num_distinct;
        hist_frac = 1.0 / hist_frac / n_hist;
    }

    return hist_frac * (1.0 - is_null_hist_factor(column_stats));
}

static double eq_balanced_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node)
{
    variant_t reserved_value;
    variant_t *const_val = &node->value;
    if (NODE_IS_RES_TRUE(node) || NODE_IS_RES_FALSE(node)) {
        (void)sql_get_reserved_value(stmt, node, &reserved_value);
        const_val = &reserved_value;
    } else if (node->type != EXPR_NODE_CONST) {
        return CBO_DEFAULT_EQ_FF;
    }

    return eq_balanced_hist_factor_var(stmt, entity, col_id, column_stats, const_val);
}

static double eq_frequence_hist_factor_var(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, variant_t *const_val)
{
    double hist_frac;
    uint32 n_hist = column_stats->hist_count;
    uint32 low_bound = 0;
    int32 cmp;

    OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val, false, &low_bound) !=
                       OG_SUCCESS, CBO_DEFAULT_EQ_FF);

    /*
     * 1. low_bound == n_hist
     * 2. 0 <= low_bound < n_hist
     *      a. column_hist[low_bound] == const_val
     *      b. column_hist[low_bound] != const_val
     */
    if (low_bound == n_hist) {
        /* 1 */
        hist_frac = 0;
        return hist_frac;
    }
    variant_t hist_var;
    knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[low_bound]->ep_value, &hist_var);
    OG_RETVALUE_IFTRUE(sql_compare_variant(stmt, &hist_var, const_val, &cmp) != OG_SUCCESS, CBO_DEFAULT_EQ_FF);

    if (cmp == 0) {
        /* 2.a */
        int64 last_num = low_bound == 0 ? 0 : column_stats->column_hist[low_bound - 1]->ep_number;

        hist_frac = column_stats->column_hist[low_bound]->ep_number - last_num;
        hist_frac /= column_stats->total_rows;
    } else {
        /* 2.b */
        hist_frac = 0;
    }

    return hist_frac;
}

static double eq_frequence_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node)
{
    variant_t reserved_value;
    variant_t *const_val = &node->value;
    if (NODE_IS_RES_TRUE(node) || NODE_IS_RES_FALSE(node)) {
        (void)sql_get_reserved_value(stmt, node, &reserved_value);
        const_val = &reserved_value;
    } else if (node->type != EXPR_NODE_CONST) {
        return CBO_DEFAULT_EQ_FF;
    }

    return eq_frequence_hist_factor_var(stmt, entity, col_id, column_stats, const_val);
}

static double ineq_frequence_hist_factor_var(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, variant_t *const_val, bool isgt)
{
    double hist_frac;
    uint32 n_hist = column_stats->hist_count;
    uint32 low_bound = 0;

    OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val, isgt, &low_bound) !=
                       OG_SUCCESS, CBO_DEFAULT_INEQ_FF);

    /*
     * 1. low_bound == n_hist
     * 2. 0 <= low_bound < n_hist
     *      a. column_hist[low_bound] == const_val
     *      b. column_hist[low_bound] != const_val
     */
    if (low_bound == n_hist) {
        /* 1 */
        hist_frac = isgt ? 0 : 1.0 - is_null_hist_factor(column_stats);
        return hist_frac;
    }

    /* 2 */
    int64 last_num = low_bound == 0 ? 0 : column_stats->column_hist[low_bound - 1]->ep_number;

    hist_frac = last_num * 1.0;
    hist_frac /= column_stats->total_rows;

    hist_frac = isgt ? (1 - hist_frac - is_null_hist_factor(column_stats)) : hist_frac;

    return hist_frac;
}

static double ineq_frequence_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node, bool isgt)
{
    variant_t reserved_value;
    variant_t *const_val = &node->value;
    if (NODE_IS_RES_TRUE(node) || NODE_IS_RES_FALSE(node)) {
        (void)sql_get_reserved_value(stmt, node, &reserved_value);
        const_val = &reserved_value;
    } else if (node->type != EXPR_NODE_CONST) {
        return CBO_DEFAULT_INEQ_FF;
    }

    return ineq_frequence_hist_factor_var(stmt, entity, col_id, column_stats, const_val, isgt);
}

static double btw_balanced_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node)
{
    if (node == NULL ||node->owner == NULL || node->owner->next == NULL || node->owner->next->root == NULL) {
        return 0.0;
    }
    
    double hist_frac_left =
        ineq_balanced_hist_factor(stmt, entity, col_id, column_stats, node, false);
    double hist_frac_right =
        ineq_balanced_hist_factor(stmt, entity, col_id, column_stats, node->owner->next->root, true);
    double btw_hist = 1 - hist_frac_right - hist_frac_left - is_null_hist_factor(column_stats);
    if (btw_hist < 0) {
        btw_hist = 0.0;
    }
    return btw_hist;
}

static double btw_frequence_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node)
{
    if (node == NULL || node->owner == NULL || node->owner->next == NULL || node->owner->next->root == NULL) {
        return 0.0;
    }
    
    double hist_frac_left =
        ineq_frequence_hist_factor(stmt, entity, col_id, column_stats, node, false);
    double hist_frac_right =
        ineq_frequence_hist_factor(stmt, entity, col_id, column_stats, node->owner->next->root, true);
    
    double btw_hist = 1 - hist_frac_right - hist_frac_left - is_null_hist_factor(column_stats);
    if (btw_hist < 0) {
        btw_hist = 0.0;
    }
    return btw_hist;
}

static double in_balanced_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node)
{
    if (node == NULL || node->owner == NULL) {
        return 0.0;
    }
    double result = 0.0;
    for (expr_tree_t *pos = node->owner; pos != NULL; pos = pos->next) {
        if (pos->root != NULL) {
            result = result + eq_balanced_hist_factor(stmt, entity, col_id, column_stats, pos->root);
        }
    }
    return result;
}

static double in_frequence_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node)
{
    if (node == NULL || node->owner == NULL) {
        return 0.0;
    }
    double result = 0.0;
    for (expr_tree_t *pos = node->owner; pos != NULL; pos = pos->next) {
        if (pos->root != NULL) {
            result = result + eq_frequence_hist_factor(stmt, entity, col_id, column_stats, pos->root);
        }
    }
    return result;
}

static int32 check_like_fixed_prefix(const text_t *text, bool32 has_escape, char escape)
{
    int32 pos;
    for (pos = 0; pos < text->len; pos++) {
        uchar c = (uchar)text->str[pos];
        if (c == '%' || c == '_') {
            break;
        }
        if (has_escape && c == escape) {
            pos++;
        }
    }
    return (pos >= text->len) ? -1 : pos;
}

#define FIXED_CHAR_SEL 0.20
#define ANY_CHAR_SEL 0.9
#define LIKE_SEL_MIN (0.0001)
#define LIKE_SEL_MAX (1 - (LIKE_SEL_MIN))

static double sql_normalize_likesel(double sel_result)
{
    if (sel_result < LIKE_SEL_MIN) {
        return LIKE_SEL_MIN;
    }
    if (sel_result > LIKE_SEL_MAX) {
        return LIKE_SEL_MAX;
    }
    return sel_result;
}

static double like_selectivity(const text_t *text, bool32 has_escape, char escape)
{
    int32 pos;
    double sel = 1.0;
    double last_sel = 1.0;
    for (pos = 0; pos < text->len; pos++) {
        char c = text->str[pos];
        if (c == '%') {
            break;
        }
        if (c == '_') {
            last_sel = ANY_CHAR_SEL;
            break;
        }
        if (has_escape && c == escape) {
            pos++;
        }
    }
    for (pos = pos + 1; pos < text->len; pos++) {
        char c = text->str[pos];
        if (c == '%') {
            sel = sel * pow(last_sel, FIXED_CHAR_SEL);
            last_sel = 1.0;
            continue;
        }
        if (c == '_') {
            last_sel = last_sel * ANY_CHAR_SEL;
            continue;
        }
        if (has_escape && c == escape) {
            pos++;
            if (pos == text->len) {
                break;
            }
        }
        last_sel = last_sel * FIXED_CHAR_SEL;
    }
    sel *= last_sel;
    return sel;
}

static status_t var_copy_prev(sql_stmt_t* stmt, variant_t *src, variant_t *dst,
    uint32 prev_len, bool32 has_escape, char escape)
{
    char* buff = NULL;
    char* src_buff = NULL;

    *dst = *src;

    if (OG_IS_VARLEN_TYPE(src->type)) {
        src_buff = src->v_text.str;
    } else {
        return OG_ERROR;
    }
    uint32 real_prev_len = prev_len;
    if (has_escape) {
        for (uint32 i = 0; i < prev_len; i++) {
            if (src_buff[i] == escape) {
                real_prev_len = real_prev_len - 1;
                i++;
            }
        }
        OG_RETURN_IFERR(sql_stack_alloc(stmt, real_prev_len, (void **)&buff));
        for (uint32 i = 0, j = 0; i < prev_len; i++) {
            if (src_buff[i] == escape) {
                i++;
                // No need to check because illegal cases will fail to compile
            }
            buff[j] = src_buff[i];
            j++;
        }
    } else {
        OG_RETURN_IFERR(sql_stack_alloc(stmt, prev_len, (void **)&buff));
        MEMS_RETURN_IFERR(memcpy_s(buff, prev_len, src_buff, prev_len));
    }

    dst->v_text.str = buff;
    dst->v_text.len = real_prev_len;

    return OG_SUCCESS;
}

static bool get_var_str_next(variant_t *var)
{
    text_t *text = VALUE_PTR(text_t, var);
    int32 pos;
    for (pos = text->len - 1; pos >= 0; pos--) {
        uchar c = (uchar)text->str[pos];
        if (c != UINT8_MAX) {
            break;
        }
    }
    if (pos == -1) {
        return OG_FALSE;
    }

    text->str[pos] = text->str[pos] + 1;
    for (pos = pos + 1; pos < text->len; pos++) {
        text->str[pos] = 0;
    }

    return OG_TRUE;
}

#define MAXNUM_SAMPLES 3000
#define MAXNUM_SAMPLES_CHAR_LEN 10000000
#define BAD_SAMPLE (-1)
#define MINNUM_SAMPLES 5

static double like_frequence_hist_factor_var(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, variant_t *const_val1, variant_t *const_val2,
    variant_t *like_val, bool32 has_escape, char escape, double *prev_sel)
{
    uint32 left = 0;
    uint32 right = column_stats->hist_count;

    if (const_val1 != NULL) {
        OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val1, false, &left) !=
                           OG_SUCCESS, BAD_SAMPLE);
    }
    if (const_val2 != NULL) {
        OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val2, false, &right) !=
                           OG_SUCCESS, BAD_SAMPLE);
    }

    if (left == column_stats->hist_count || right == 0 || column_stats->total_rows == 0) {
        *prev_sel = 0;
        return BAD_SAMPLE;
    }

    int64 prev_range_num = column_stats->column_hist[right - 1]->ep_number -
        (left == 0 ? 0 : column_stats->column_hist[left - 1]->ep_number);
    *prev_sel = 1.0 * prev_range_num / column_stats->total_rows;

    uint32 step = (right - left < MAXNUM_SAMPLES) ? 1 : (right - left) / MAXNUM_SAMPLES;
    uint32 n_samples = 0;
    uint32 n_hits = 0;

    for (uint32 i = left, sum_char = 0; i < right && sum_char < MAXNUM_SAMPLES_CHAR_LEN; i += step) {
        bool32 cmp;
        variant_t hist_var;
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[i]->ep_value, &hist_var);
        OG_RETVALUE_IFTRUE(var_like(&hist_var, like_val, &cmp, has_escape, escape, GET_CHARSET_ID) != OG_SUCCESS,
            BAD_SAMPLE);

        int32 var_cnt = column_stats->column_hist[i]->ep_number -
            (i == 0 ? 0 : column_stats->column_hist[i - 1]->ep_number);

        n_samples += var_cnt;
        if (cmp) {
            n_hits += var_cnt;
        }

        sum_char += hist_var.v_text.len;
    }

    if (n_samples == 0) {
        return BAD_SAMPLE;
    }

    double hist_frac = 1.0 * prev_range_num * n_hits / n_samples;
    hist_frac /= column_stats->total_rows;

    return hist_frac;
}

static double like_balanced_hist_factor_var(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, variant_t *const_val1, variant_t *const_val2,
    variant_t *like_val, bool32 has_escape, char escape, double *prev_sel)
{
    uint32 n_hist = column_stats->hist_count;
    uint32 left = 0;
    uint32 right = n_hist;

    if (const_val1 != NULL) {
        OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val1, false, &left) !=
                           OG_SUCCESS, BAD_SAMPLE);
    }
    if (const_val2 != NULL) {
        OG_RETVALUE_IFTRUE(binary_search_histogram(stmt, entity, column_stats, col_id, const_val2, false, &right) !=
                           OG_SUCCESS, BAD_SAMPLE);
    }
    
    if (right - left <= MINNUM_SAMPLES) {
        if (left ==  n_hist) {
            *prev_sel = 0;
        } else {
            *prev_sel = 1.0 * (right - left + 1) / n_hist;
            *prev_sel *= 1 - is_null_hist_factor(column_stats);
        }
        return BAD_SAMPLE;
    }

    *prev_sel = 0;
    if (const_val1 != NULL) {
        variant_t left_var;
        if (left == 0) {
            knl_cbo_text2variant(entity, col_id, &column_stats->low_value, &left_var);
        } else {
            knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[left - 1]->ep_value, &left_var);
        }
        variant_t right_var;
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[left]->ep_value, &right_var);
        *prev_sel += 1 - calc_normalized_string_position(stmt, &left_var, const_val1, &right_var);
    }

    if (const_val2 != NULL) {
        variant_t right_var;
        if (right == n_hist) {
            knl_cbo_text2variant(entity, col_id, &column_stats->high_value, &right_var);
        } else {
            knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[right]->ep_value, &right_var);
        }
        variant_t left_var;
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[right - 1]->ep_value, &left_var);
        *prev_sel += calc_normalized_string_position(stmt, &left_var, const_val2, &right_var);
    }

    *prev_sel += right - left;
    *prev_sel /= n_hist;
    *prev_sel *= 1 - is_null_hist_factor(column_stats);

    uint32 n_samples = 0;
    uint32 n_hits = 0;

    for (uint32 i = left, sum_char = 0; i < right && sum_char < MAXNUM_SAMPLES_CHAR_LEN; i++) {
        bool32 cmp;
        variant_t hist_var;
        knl_cbo_text2variant(entity, col_id, &column_stats->column_hist[i]->ep_value, &hist_var);
        OG_RETVALUE_IFTRUE(var_like(&hist_var, like_val, &cmp, has_escape, escape, GET_CHARSET_ID) != OG_SUCCESS,
            BAD_SAMPLE);

        n_samples++;
        if (cmp) {
            n_hits++;
        }

        sum_char += hist_var.v_text.len;
    }

    if (n_samples == 0) {
        return BAD_SAMPLE;
    }

    double hist_frac = 1.0 * n_hits / n_samples;
    hist_frac *= *prev_sel;

    return hist_frac;
}

static double like_frequence_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node, cmp_node_t *cmp)
{
    variant_t *const_val = &node->value;
    if (NODE_IS_RES_TRUE(node) || NODE_IS_RES_FALSE(node)) {
        return eq_frequence_hist_factor(stmt, entity, col_id, column_stats, node);
    } else if (NODE_IS_RES_NULL(node)) {
        return 0.0;
    } else if (node->type != EXPR_NODE_CONST) {
        return CBO_DEFAULT_LIKE_FF;
    }

    bool32 has_escape = (cmp->right->next != NULL);
    char escape = OG_INVALID_INT8;
    if (has_escape) {
        variant_t escape_var;
        OG_RETVALUE_IFTRUE(sql_exec_expr(stmt, cmp->right->next, &escape_var) != OG_SUCCESS,
            CBO_DEFAULT_LIKE_FF);
        OG_RETVALUE_IFTRUE(sql_exec_escape_character(cmp->right->next, &escape_var, &escape) != OG_SUCCESS,
            CBO_DEFAULT_LIKE_FF);
    }

    const text_t *text = VALUE_PTR(text_t, const_val);
    int32 prev_len = check_like_fixed_prefix(text, has_escape, escape);
    if (prev_len == -1) {
        OGSQL_SAVE_STACK(stmt);
        variant_t real_const_val;
        RETVALUE_AND_RESTORE_STACK_IFERR(var_copy_prev(stmt, const_val, &real_const_val, text->len, has_escape, escape),
            stmt, CBO_DEFAULT_EQ_FF);
        double eq_sel = eq_frequence_hist_factor_var(stmt, entity, col_id, column_stats, &real_const_val);
        OGSQL_RESTORE_STACK(stmt);
        return eq_sel;
    }

    double prev_sel = 1 - is_null_hist_factor(column_stats);
    double rest_sel = like_selectivity(text, has_escape, escape);
    double like_sel;
    if (prev_len != 0) {
        OGSQL_SAVE_STACK(stmt);

        variant_t prev_str;
        variant_t prev_str_next;
        RETVALUE_AND_RESTORE_STACK_IFERR(var_copy_prev(stmt, const_val, &prev_str, prev_len, has_escape, escape),
            stmt, sql_normalize_likesel(prev_sel * rest_sel));
        RETVALUE_AND_RESTORE_STACK_IFERR(var_copy_prev(stmt, const_val, &prev_str_next, prev_len, has_escape, escape),
            stmt, sql_normalize_likesel(prev_sel * rest_sel));
        
        if (get_var_str_next(&prev_str_next)) {
            like_sel = like_frequence_hist_factor_var(stmt, entity, col_id, column_stats,
                &prev_str, &prev_str_next, const_val, has_escape, escape, &prev_sel);
        } else {
            like_sel = like_frequence_hist_factor_var(stmt, entity, col_id, column_stats,
                &prev_str, NULL, const_val, has_escape, escape, &prev_sel);
        }
        OGSQL_RESTORE_STACK(stmt);
    } else {
        like_sel = like_frequence_hist_factor_var(stmt, entity, col_id, column_stats,
            NULL, NULL, const_val, has_escape, escape, &prev_sel);
    }
    
    if (like_sel < 0) {
        return sql_normalize_likesel(prev_sel * rest_sel);
    }
    return sql_normalize_likesel(like_sel);
}

static double like_balanced_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, expr_node_t *node, cmp_node_t *cmp)
{
    variant_t *const_val = &node->value;
    if (NODE_IS_RES_TRUE(node) || NODE_IS_RES_FALSE(node)) {
        return eq_balanced_hist_factor(stmt, entity, col_id, column_stats, node);
    } else if (NODE_IS_RES_NULL(node)) {
        return 0.0;
    } else if (node->type != EXPR_NODE_CONST) {
        return CBO_DEFAULT_LIKE_FF;
    }

    bool32 has_escape = (cmp->right->next != NULL);
    char escape = OG_INVALID_INT8;
    if (has_escape) {
        variant_t escape_var;
        OG_RETVALUE_IFTRUE(sql_exec_expr(stmt, cmp->right->next, &escape_var) != OG_SUCCESS,
            CBO_DEFAULT_LIKE_FF);
        OG_RETVALUE_IFTRUE(sql_exec_escape_character(cmp->right->next, &escape_var, &escape) != OG_SUCCESS,
            CBO_DEFAULT_LIKE_FF);
    }

    const text_t *text = VALUE_PTR(text_t, const_val);
    int32 prev_len = check_like_fixed_prefix(text, has_escape, escape);
    if (prev_len == -1) {
        OGSQL_SAVE_STACK(stmt);
        variant_t real_const_val;
        RETVALUE_AND_RESTORE_STACK_IFERR(var_copy_prev(stmt, const_val, &real_const_val, text->len, has_escape, escape),
            stmt, CBO_DEFAULT_EQ_FF);
        double eq_sel = eq_balanced_hist_factor_var(stmt, entity, col_id, column_stats, &real_const_val);
        OGSQL_RESTORE_STACK(stmt);
        return eq_sel;
    }

    double prev_sel = 1 - is_null_hist_factor(column_stats);
    double rest_sel = like_selectivity(text, has_escape, escape);
    double like_sel;
    if (prev_len != 0) {
        OGSQL_SAVE_STACK(stmt);

        variant_t prev_str;
        variant_t prev_str_next;
        RETVALUE_AND_RESTORE_STACK_IFERR(var_copy_prev(stmt, const_val, &prev_str, prev_len, has_escape, escape),
            stmt, sql_normalize_likesel(prev_sel * rest_sel));
        RETVALUE_AND_RESTORE_STACK_IFERR(var_copy_prev(stmt, const_val, &prev_str_next, prev_len, has_escape, escape),
            stmt, sql_normalize_likesel(prev_sel * rest_sel));
        
        if (get_var_str_next(&prev_str_next)) {
            like_sel = like_balanced_hist_factor_var(stmt, entity, col_id, column_stats,
                &prev_str, &prev_str_next, const_val, has_escape, escape, &prev_sel);
        } else {
            like_sel = like_balanced_hist_factor_var(stmt, entity, col_id, column_stats,
                &prev_str, NULL, const_val, has_escape, escape, &prev_sel);
        }
        OGSQL_RESTORE_STACK(stmt);
    } else {
        like_sel = like_balanced_hist_factor_var(stmt, entity, col_id, column_stats,
            NULL, NULL, const_val, has_escape, escape, &prev_sel);
    }

    if (like_sel < 0) {
        return sql_normalize_likesel(prev_sel * rest_sel);
    }
    return sql_normalize_likesel(like_sel);
}


static double compute_hist_factor(sql_stmt_t *stmt, dc_entity_t *entity, uint32 col_id,
    cbo_stats_column_t *column_stats, cmp_node_t *cmp, expr_node_t *node)
{
    if (column_stats == NULL) {
        return CBO_MIDDLE_FF;
    }
    cmp_type_t cmp_type = cmp->type;
    /* const type must be INTERGER */
    if (column_stats->hist_type == HEIGHT_BALANCED) {
        switch (cmp_type) {
            case CMP_TYPE_EQUAL:
                return eq_balanced_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_NOT_EQUAL:
                return 1 - eq_balanced_hist_factor(stmt, entity, col_id, column_stats, node) -
                       is_null_hist_factor(column_stats);
            case CMP_TYPE_LESS:
                return ineq_balanced_hist_factor(stmt, entity, col_id, column_stats, node, false);
            case CMP_TYPE_LESS_EQUAL:
                return ineq_balanced_hist_factor(stmt, entity, col_id, column_stats, node, false) +
                       eq_balanced_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_GREAT:
                return ineq_balanced_hist_factor(stmt, entity, col_id, column_stats, node, true);
            case CMP_TYPE_GREAT_EQUAL:
                return ineq_balanced_hist_factor(stmt, entity, col_id, column_stats, node, true) +
                       eq_balanced_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_BETWEEN:
                return btw_balanced_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_NOT_BETWEEN:
                return 1 - btw_balanced_hist_factor(stmt, entity, col_id, column_stats, node) -
                       is_null_hist_factor(column_stats);
            case CMP_TYPE_IS_NULL:
                return is_null_hist_factor(column_stats);
            case CMP_TYPE_IS_NOT_NULL:
                return 1 - is_null_hist_factor(column_stats);
            case CMP_TYPE_IN:
                return in_balanced_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_NOT_IN:
                return 1 - in_balanced_hist_factor(stmt, entity, col_id, column_stats, node) -
                       is_null_hist_factor(column_stats);
            case CMP_TYPE_LIKE:
                return like_balanced_hist_factor(stmt, entity, col_id, column_stats, node, cmp);
            case CMP_TYPE_NOT_LIKE:
                return 1 - like_balanced_hist_factor(stmt, entity, col_id, column_stats, node, cmp) -
                       is_null_hist_factor(column_stats);
            default:
                break;
        }
    } else {
        /* FREQUENCY HISTOGRAM */
        switch (cmp_type) {
            case CMP_TYPE_EQUAL:
                return eq_frequence_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_NOT_EQUAL:
                return 1 - eq_frequence_hist_factor(stmt, entity, col_id, column_stats, node) -
                       is_null_hist_factor(column_stats);
            case CMP_TYPE_LESS:
                return ineq_frequence_hist_factor(stmt, entity, col_id, column_stats, node, false);
            case CMP_TYPE_LESS_EQUAL:
                return ineq_frequence_hist_factor(stmt, entity, col_id, column_stats, node, false) +
                       eq_frequence_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_GREAT:
                return ineq_frequence_hist_factor(stmt, entity, col_id, column_stats, node, true);
            case CMP_TYPE_GREAT_EQUAL:
                return ineq_frequence_hist_factor(stmt, entity, col_id, column_stats, node, true) +
                       eq_frequence_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_BETWEEN:
                return btw_frequence_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_NOT_BETWEEN:
                return 1 - btw_frequence_hist_factor(stmt, entity, col_id, column_stats, node) -
                       is_null_hist_factor(column_stats);
            case CMP_TYPE_IS_NULL:
                return is_null_hist_factor(column_stats);
            case CMP_TYPE_IS_NOT_NULL:
                return 1 - is_null_hist_factor(column_stats);
            case CMP_TYPE_IN:
                return in_frequence_hist_factor(stmt, entity, col_id, column_stats, node);
            case CMP_TYPE_NOT_IN:
                return 1 - in_frequence_hist_factor(stmt, entity, col_id, column_stats, node) -
                       is_null_hist_factor(column_stats);
            case CMP_TYPE_LIKE:
                return like_frequence_hist_factor(stmt, entity, col_id, column_stats, node, cmp);
            case CMP_TYPE_NOT_LIKE:
                return 1 - like_frequence_hist_factor(stmt, entity, col_id, column_stats, node, cmp) -
                       is_null_hist_factor(column_stats);
            default:
                break;
        }
    }

    return CBO_MIDDLE_FF;
}

status_t sql_cal_table_or_partition_stats(dc_entity_t *entity, sql_table_t *table, cbo_stats_info_t* stats_info,
                                                 knl_handle_t session)
{
    uint32 table_partition_no = stats_info->table_partition_no;
    uint32 table_subpartition_no = stats_info->table_subpartition_no;
    uint32 index_id = stats_info->index_id;
    uint32 index_partition_no = stats_info->index_partition_no;
    uint32 index_subpartition_no = stats_info->index_subpartition_no;

    if (table_partition_no == CBO_GLOBAL_PART_NO) {
        /* cal no partitioned table */
        stats_info->cbo_table_stats = knl_get_cbo_table(session, entity);
    } else if (table_partition_no != CBO_GLOBAL_PART_NO && table_subpartition_no == CBO_GLOBAL_PART_NO) {
        /* only need to cal partition table */
        if (!knl_is_part_table(table->entry->dc.handle)) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION, "cannot get the partitioned stats info for no-partition table.");
            return OG_ERROR;
        }

        stats_info->cbo_table_stats = knl_get_cbo_part_table(session, entity, table_partition_no);
    } else {
        /* only need to cal subpartition table */
        if (!knl_is_compart_table(table->entry->dc.handle)) {
            OG_THROW_ERROR(ERR_INVALID_OPERATION,
                           "cannot get the subpartitioned stats info for no-subpartition table.");
            return OG_ERROR;
        }

        stats_info->cbo_table_stats = knl_get_cbo_subpart_table(session, entity, table_partition_no,
                                                                table_subpartition_no);
    }

    if (stats_info->cbo_table_stats == NULL)
        return OG_ERROR;
    
    if (index_id == OG_INVALID_ID32)
        return OG_SUCCESS;

    if (index_partition_no == CBO_GLOBAL_PART_NO) {
        /* cal no partitioned index */
        stats_info->cbo_index_stats = knl_get_cbo_index(session, entity, index_id);
    } else if (index_partition_no != CBO_GLOBAL_PART_NO && index_subpartition_no == CBO_GLOBAL_PART_NO) {
        /* only need to cal partition index */
        stats_info->cbo_index_stats = knl_get_cbo_part_index(session, entity,
                                                             index_partition_no, index_id);
    } else {
        /* only need to cal subpartition index */
        stats_info->cbo_index_stats = knl_get_cbo_subpart_index(session, entity, index_partition_no,
                                                                index_id, index_subpartition_no);
    }
    return OG_SUCCESS;
}


static status_t add_range_cond(sql_stmt_t *stmt, range_query_cond **rq_cond, cmp_node_t *cmp, bool32 col_on_left,
    double f2, cbo_stats_column_t *column_stats)
{
    range_query_cond *rq_elem = NULL;
    expr_tree_t *column = NULL;
    bool is_lobound = false;

    if (col_on_left) {
        column = cmp->left;
        is_lobound = cmp->type == CMP_TYPE_LESS || cmp->type == CMP_TYPE_LESS_EQUAL ? false : true;
    } else {
        column = cmp->right;
        is_lobound = cmp->type == CMP_TYPE_LESS || cmp->type == CMP_TYPE_LESS_EQUAL ? true : false;
    }

    for (rq_elem = *rq_cond; rq_elem; rq_elem = rq_elem->next) {
        if (!sql_expr_node_matched(stmt, rq_elem->column, column->root)) {
            continue;
        }

        if (is_lobound) {
            if (!rq_elem->have_lobound) {
                rq_elem->have_lobound = true;
                rq_elem->lobound = f2;
            } else {
                if (rq_elem->lobound > f2) {
                    rq_elem->lobound = f2;
                }
            }
        } else {
            if (!rq_elem->have_hibound) {
                rq_elem->have_hibound = true;
                rq_elem->hibound = f2;
            } else {
                if (rq_elem->hibound > f2) {
                    rq_elem->hibound = f2;
                }
            }
        }
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(range_query_cond), (void **)&rq_elem));
    rq_elem->column = column;
    rq_elem->null_hist = is_null_hist_factor(column_stats);
    if (is_lobound) {
        rq_elem->have_lobound = true;
        rq_elem->have_hibound = false;
        rq_elem->lobound = f2;
    } else {
        rq_elem->have_lobound = false;
        rq_elem->have_hibound = true;
        rq_elem->hibound = f2;
    }
    rq_elem->next = *rq_cond;
    *rq_cond = rq_elem;

    return OG_SUCCESS;
}

status_t compute_hist_factor_by_conds(sql_stmt_t *stmt, dc_entity_t *entity, galist_t *cond_cols,
    galist_t *conds, double *ff, cbo_stats_info_t* stats_info)
{
    double f1 = CBO_MAX_FF;
    range_query_cond *rq_cond = NULL;
    uint32 col_id;
    uint32 cond_idx;

    OGSQL_SAVE_STACK(stmt);
    for (cond_idx = 0; cond_idx < conds->count; cond_idx++) {
        cmp_node_t *cmp = (cmp_node_t*)cm_galist_get(conds, cond_idx);
        col_id = *(uint32*)cm_galist_get(cond_cols, cond_idx);
        /* currently functional-index don't have statistics */
        if (stats_info->cbo_table_stats != NULL && stats_info->cbo_table_stats->max_col_id < col_id) {
            f1 = f1 * (cmp->type == CMP_TYPE_EQUAL ? CBO_DEFAULT_EQ_FF : CBO_DEFAULT_INEQ_FF);
            continue;
        }

        cbo_stats_column_t *column_stats = cbo_get_column_stats(stats_info->cbo_table_stats, col_id);
        bool32 col_on_left;
        expr_node_t *other_node = NULL;

        col_on_left = (cmp->left != NULL && cmp->left->root->type == EXPR_NODE_COLUMN) ? true : false;

        if (cmp->right != NULL && cmp->left != NULL) {
            other_node = col_on_left ? cmp->right->root : cmp->left->root;
        }

        double f2;

        f2 = compute_hist_factor(stmt, entity, col_id, column_stats, cmp, other_node);

        if (cmp->type <= CMP_TYPE_LESS_EQUAL && cmp->type >= CMP_TYPE_GREAT_EQUAL &&
            other_node->type == EXPR_NODE_CONST) {
            RET_AND_RESTORE_STACK_IFERR(add_range_cond(stmt, &rq_cond, cmp, col_on_left, f2, column_stats), stmt);
        } else {
            f1 = f1 * f2;
        }
    }

    while (rq_cond != NULL) {
        if (rq_cond->have_lobound && rq_cond->have_hibound) {
            double f2;
            f2 = rq_cond->lobound + rq_cond->hibound - (1.0 - rq_cond->null_hist);
            if (f2 < 0) {
                f2 = 0.0;
            }
            f1 = f1 * f2;
        } else {
            if (rq_cond->have_lobound) {
                f1 *= rq_cond->lobound;
            } else {
                f1 *= rq_cond->hibound;
            }
        }
        rq_cond = rq_cond->next;
    }
    OGSQL_RESTORE_STACK(stmt);

    *ff = f1;
    return OG_SUCCESS;
}

static inline status_t sql_get_table_name(sql_table_t *table, char *dest, int dest_max_len)
{
    MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, T2S(&(table->name.value))));
    if (table->alias.value.str != NULL) {
        MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, " "));
        MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, T2S(&(table->alias.value))));
    }
    return OG_SUCCESS;
}

static status_t sql_parse_join_node_table_name(sql_join_node_t* join_node, char* dest, int dest_max_len)
{
    MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, "["));
    for (uint32 i = 0; i < join_node->tables.count; i++) {
        sql_table_t *table = (sql_table_t *)join_node->tables.items[i];
        OG_RETURN_IFERR(sql_get_table_name(table, dest, dest_max_len));
        if (i != join_node->tables.count - 1) {
            MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, ","));
        }
    }
    MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, "]"));
    return OG_SUCCESS;
}

static status_t sql_parse_outer_table_name(join_assist_t *ja, join_tbl_bitmap_t *outer_rels, char* dest,
    int dest_max_len)
{
    int i;
    int count = 0;
    MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, "["));
    BITMAP_FOREACH(i, outer_rels) {
        sql_table_t *table = ja->pa->tables[i];
        if (count > 0) {
            MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, ","));
        }
        OG_RETURN_IFERR(sql_get_table_name(table, dest, dest_max_len));
        count++;
    }
    MEMS_RETURN_IFERR(strcat_s(dest, dest_max_len, "]"));
    return OG_SUCCESS;
}

void sql_debug_scan_cost_info(sql_stmt_t *stmt, sql_table_t *table, char *extra_info, cbo_index_choose_assist_t *ca,
    double cost, join_assist_t *ja, join_tbl_bitmap_t *outer_rels)
{
    if (!LOG_OPTINFO_ON(stmt)) {
        return;
    }

    char table_name[JOIN_TABLE_NAME_MAX_LEN] = {0};
    char outer_table_name[JOIN_TABLE_NAME_MAX_LEN] = {0};

    (void)sql_get_table_name(table, (char*)&table_name, JOIN_TABLE_NAME_MAX_LEN);

    if (outer_rels != NULL) {
        (void)sql_parse_outer_table_name(ja, outer_rels, (char*)&outer_table_name, JOIN_TABLE_NAME_MAX_LEN);
    }

    if (ca != NULL) {
        /* index scan */
        SQL_LOG_OPTINFO(stmt, "[CBO][SCAN][%s] table:%s, index:%s, cost:%lf, strict_equal_cnt:%d, scan_flag: %d, "
            "outer_rels: %s.",
            extra_info, table_name, ca->index->name, cost, ca->strict_equal_cnt, ca->scan_flag, outer_table_name);
    } else {
        /* seq scan */
        SQL_LOG_OPTINFO(stmt, "[CBO][SCAN][%s] table:%s, cost:%lf.", extra_info, table_name, cost);
    }
}

void sql_debug_join_cost_info(sql_stmt_t *stmt, sql_join_node_t* join_tree, char* join_type, char* extra_info)
{
    if (!LOG_OPTINFO_ON(stmt) || join_tree == NULL || join_tree->left == NULL || join_tree->right == NULL) {
        return;
    }

    sql_join_node_t* outer_path = join_tree->left;
    sql_join_node_t* inner_path = join_tree->right;
    char outer_table_name[JOIN_TABLE_NAME_MAX_LEN] = {0};
    char inner_table_name[JOIN_TABLE_NAME_MAX_LEN] = {0};

    (void)sql_parse_join_node_table_name(outer_path, (char*)&outer_table_name, JOIN_TABLE_NAME_MAX_LEN);
    (void)sql_parse_join_node_table_name(inner_path, (char*)&inner_table_name, JOIN_TABLE_NAME_MAX_LEN);

    SQL_LOG_OPTINFO(stmt, "[CBO][%s][%s] outer_table:%s, outer_startup:%lf, outer_total:%lf, inner_table %s, \
        inner_startup:%lf, inner_total:%lf, join_node_startup:%lf, join_node_total:%lf.",
        join_type, extra_info, outer_table_name, outer_path->cost.startup_cost, outer_path->cost.cost,
        inner_table_name, inner_path->cost.startup_cost, inner_path->cost.cost,
        join_tree->cost.startup_cost, join_tree->cost.cost);
}


double sql_seq_scan_subpartitioned_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table)
{
    // sub partitioned table row estimate
    uint64 part_cnt = table->scan_part_info->part_cnt;
    uint64 cal_part_cnt = MIN(part_cnt, MAX_CBO_CALU_PARTS_COUNT);
    scan_part_range_type_t scan_type = table->scan_part_info->scan_type;
    if (scan_type == SCAN_PART_FULL) {
        return sql_seq_scan_partitioned_cost(stmt, entity, table);
    }
    
    double cost = 0;
    for (uint64 i = 0; i < cal_part_cnt; i++) {
        uint32 table_partition_no = PART_TABLE_SCAN_PART_NO(table, i);
        if (table_partition_no == CBO_GLOBAL_PART_NO) {
            return sql_seq_scan_partitioned_cost(stmt, entity, table);
        }
        cbo_stats_info_t stats_info;
        uint32 table_subpartition_no = COMPART_TABLE_SCAN_SUBPART_NO(table, i);
        OG_RETURN_MAX_COST_IFERR(init_stats_info(&stats_info, scan_type, table_partition_no,
            table_subpartition_no, OG_INVALID_ID32, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
        OG_RETURN_MAX_COST_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(stmt)));
        cost += stats_info.cbo_table_stats->blocks * CBO_DEFAULT_SEQ_PAGE_COST +
            stats_info.cbo_table_stats->rows * CBO_DEFAULT_CPU_OPERATOR_COST;
    }
    if (part_cnt > MAX_CBO_CALU_PARTS_COUNT && cal_part_cnt != 0) {
        cost = cost * part_cnt / cal_part_cnt;
        cost = CBO_COST_SAFETY_RET(cost);
    }
    return cost;
}

double sql_seq_scan_partitioned_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table)
{
    // partitioned table row estimate
    uint64 part_cnt = table->scan_part_info->part_cnt;
    double cost = 0;
    uint64 cal_part_cnt = MIN(part_cnt, MAX_CBO_CALU_PARTS_COUNT);
    scan_part_range_type_t scan_type = table->scan_part_info->scan_type;
    for (uint64 i = 0; i < cal_part_cnt; i++) {
        cbo_stats_info_t stats_info;
        OG_RETURN_MAX_COST_IFERR(init_stats_info(&stats_info, scan_type, PART_TABLE_SCAN_PART_NO(table, i),
            CBO_GLOBAL_SUBPART_NO, OG_INVALID_ID32, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
        OG_RETURN_MAX_COST_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(stmt)));
        cost += stats_info.cbo_table_stats->blocks * CBO_DEFAULT_SEQ_PAGE_COST +
                stats_info.cbo_table_stats->rows * CBO_DEFAULT_CPU_OPERATOR_COST;
        cost = CBO_COST_SAFETY_RET(cost);
    }
    if (part_cnt > MAX_CBO_CALU_PARTS_COUNT && cal_part_cnt != 0) {
        cost = cost * part_cnt / cal_part_cnt;
        cost = CBO_COST_SAFETY_RET(cost);
    }
    return cost;
}

double sql_seq_scan_nopartitioned_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table)
{
    cbo_stats_info_t stats_info;
    OG_RETURN_MAX_COST_IFERR(init_stats_info(&stats_info, SCAN_PART_FULL, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO,
        OG_INVALID_ID32, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
    OG_RETURN_MAX_COST_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(stmt)));
    return stats_info.cbo_table_stats->blocks * CBO_DEFAULT_SEQ_PAGE_COST +
        stats_info.cbo_table_stats->rows * CBO_DEFAULT_CPU_OPERATOR_COST;
}

double sql_seq_scan_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table)
{
    if (knl_is_compart_table(table->entry->dc.handle)) {
        return sql_seq_scan_subpartitioned_cost(stmt, entity, table);
    } else if (knl_is_part_table(table->entry->dc.handle)) {
        return sql_seq_scan_partitioned_cost(stmt, entity, table);
    } else {
        return sql_seq_scan_nopartitioned_cost(stmt, entity, table);
    }
}

double sql_sort_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, uint16 scan_flag)
{
    /* todo: consider rownum and limit */
    if (CAN_INDEX_SORT(scan_flag)) {
        return 0.0;
    }
    return table->card * (CBO_DEFAULT_CPU_QK_SORT_COST + CBO_DEFAULT_CPU_QK_INST_COST) +
        table->card * log(table->card) * CBO_DEFAULT_CPU_QK_COMP_COST;
}

double sql_group_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, uint16 scan_flag)
{
    double group_cost = CBO_DEFAULT_CPU_OPERATOR_COST * table->card;
    if (CAN_INDEX_GROUP(scan_flag)) {
        /* group_cost */
        return group_cost;
    }
    if (pa->query->sort_groups != NULL) {
        /* group_cost + sort_cost */
        return group_cost + sql_sort_cost(stmt, pa, table, scan_flag);
    }
    /* group_cost + hash_cost */
    return group_cost + CBO_DEFAULT_HASH_INIT_COST + table->card * (CBO_DEFAULT_CPU_HASH_BUILD_COST +
        CBO_DEFAULT_CPU_HASH_CALC_COST);
}

static inline bool32 distinct_eliminate_sort(plan_assist_t *pa)
{
    if (pa->query->sort_items->count >= pa->query->distinct_columns->count * SORT_DISTINCT_FACTOR) {
        for (uint32 i = 0; i < pa->query->sort_items->count; ++i) {
            sort_item_t *item = (sort_item_t *)cm_galist_get(pa->query->sort_items, i);
            if (item->expr->root->type != EXPR_NODE_GROUP) {
                return OG_FALSE;
            }
        }
        return OG_TRUE;
    }
    return OG_FALSE;
}

double sql_distinct_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, uint16 scan_flag)
{
    double group_cost = CBO_DEFAULT_CPU_OPERATOR_COST * table->card;
    if (CAN_INDEX_DISTINCT(scan_flag) && CAN_INDEX_SORT(scan_flag)) {
        /* group_cost */
        return group_cost;
    }
    bool32 eliminate_sort = distinct_eliminate_sort(pa);
    if (eliminate_sort) {
        /* group_cost + sort_cost */
        return group_cost + sql_sort_cost(stmt, pa, table, scan_flag);
    }

    /* group_cost + hash_cost */
    return CAN_INDEX_DISTINCT(scan_flag) ? group_cost : group_cost + CBO_DEFAULT_HASH_INIT_COST +
        table->card * (CBO_DEFAULT_CPU_HASH_BUILD_COST + CBO_DEFAULT_CPU_HASH_CALC_COST);
}

static status_t sql_cost_pre_check(sql_join_node_t* join_tree)
{
    sql_join_node_t* outer_path = join_tree->left;
    sql_join_node_t* inner_path = join_tree->right;

    if (inner_path != NULL && outer_path != NULL) {
        return OG_SUCCESS;
    }

    if (inner_path == NULL && outer_path == NULL) {
        join_tree->cost.card = 0;
        join_tree->cost.cost = 0;
        join_tree->cost.startup_cost = 0;
        return OG_ERROR;
    }

    if (inner_path == NULL && outer_path != NULL) {
        outer_path->cost.card = CBO_CARD_SAFETY_SET(TABLE_OF_JOIN_LEAF(outer_path)->card);
        outer_path->cost.cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(outer_path)->cost);
        outer_path->cost.startup_cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(outer_path)->startup_cost);
        join_tree->cost.card = CBO_CARD_SAFETY_SET(TABLE_OF_JOIN_LEAF(outer_path)->card);
        join_tree->cost.cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(outer_path)->cost);
        join_tree->cost.startup_cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(outer_path)->startup_cost);
        return OG_ERROR;
    }

    if (inner_path != NULL && outer_path == NULL) {
        inner_path->cost.card = CBO_CARD_SAFETY_SET(TABLE_OF_JOIN_LEAF(inner_path)->card);
        inner_path->cost.cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(inner_path)->cost);
        inner_path->cost.startup_cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(inner_path)->startup_cost);
        join_tree->cost.card = CBO_CARD_SAFETY_SET(TABLE_OF_JOIN_LEAF(inner_path)->card);
        join_tree->cost.cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(inner_path)->cost);
        join_tree->cost.startup_cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(inner_path)->startup_cost);
        return OG_ERROR;
    }
    
    return OG_ERROR;
}

/**
  * Cost estimation of Rescan related operators, HashJoin needs to consider, Not Rescan cache in nestloop join
  *
  */
 static status_t sql_cost_rescan(sql_join_node_t* join_tree, double * rescan_startup_cost, double * rescan_cost)
{
    /* without inner table cache, keep the rescan table cost same with the first scan. */
    *rescan_startup_cost = join_tree->cost.startup_cost;
    *rescan_cost = join_tree->cost.cost;
    return OG_SUCCESS;
}

static status_t sql_cost_qual_eval_walker(double* qual_startup_cost, double* qual_cost, galist_t* restricts)
{
    // qual_cost: cost for per tuple
    for (uint32 i = 0; i < restricts->count; i++) {
        expr_node_t* node = (expr_node_t*)cm_galist_get(restricts, i);
        switch (node->type) {
            case EXPR_NODE_AGGR:
                // The aggregation node is treated as a variable (vars) with an execution cost of 0, ignoring the
                // cost of the input expression, as the actual execution cost is considered in the specific cost
                // evaluation of the plan node.
                break;
            default:
                // current cost of conditional expressions only considers common operations such as comparisons,
                // with a default coefficient set to 1.0
                *qual_cost += CBO_NORMAL_FUNC_FACTOR * CBO_DEFAULT_CPU_OPERATOR_COST;
                break;
        }
    }
    return OG_SUCCESS;
}

void sql_init_sql_join_node_cost(sql_join_node_t* join_tree)
{
    if (join_tree->tables.count == 1) {
        join_tree->cost.card = CBO_CARD_SAFETY_SET(TABLE_OF_JOIN_LEAF(join_tree)->card);
        join_tree->cost.cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(join_tree)->cost);
        join_tree->cost.startup_cost = CBO_COST_SAFETY_RET(TABLE_OF_JOIN_LEAF(join_tree)->startup_cost);
    }
}

status_t sql_initial_cost_nestloop(join_assist_t *ja, sql_join_node_t* join_tree, join_cost_workspace* join_cost_ws,
    special_join_info_t *sjoininfo)
{
    double startup_cost = 0;
    double run_cost = 0;
    bool method_enabled = true;

    OG_RETURN_IFERR(sql_cost_pre_check(join_tree));

    sql_join_node_t* outer_path = join_tree->left;
    sql_join_node_t* inner_path = join_tree->right;

    double inner_run_cost;
    double inner_rescan_run_cost;
    double inner_rescan_start_cost;
    int64 outer_path_rows = sql_adjust_est_row(outer_path->cost.card);

    sql_debug_join_cost_info(ja->stmt, join_tree, "NL", "initial start");

    /* cost of the inner table reuse */
    (void)sql_cost_rescan(inner_path, &inner_rescan_start_cost, &inner_rescan_run_cost);
    method_enabled = g_instance->sql.enable_nestloop_join;
    if (!method_enabled) {
        startup_cost += CBO_DEFAULT_DISABLE_COST;
    }

    /* The total cost of starting each collision between the outer row and the inner table */
    if (outer_path_rows > 1) {
        run_cost += (outer_path_rows - 1) * inner_rescan_start_cost;
    }

    startup_cost += outer_path->cost.startup_cost + inner_path->cost.startup_cost;
    run_cost += outer_path->cost.cost - outer_path->cost.startup_cost;
    inner_run_cost = inner_path->cost.cost - inner_path->cost.startup_cost;
    /* the rescan run cost */
    inner_rescan_run_cost = inner_path->cost.cost - inner_path->cost.startup_cost;

    if (sjoininfo->jointype >= JOIN_TYPE_SEMI) {
        run_cost += inner_run_cost;

        double outer_matched_rows = rint(outer_path_rows * sjoininfo->semi_anti_factor.outer_match_frac);
        double inner_scan_frac = 2.0 / (sjoininfo->semi_anti_factor.match_count + 1.0);
        if (outer_matched_rows > 1)
            run_cost += (outer_matched_rows - 1) * inner_rescan_run_cost * inner_scan_frac;
        
        join_cost_ws->outer_matched_rows = outer_matched_rows;
        join_cost_ws->inner_scan_frac = inner_scan_frac;
    } else {
        run_cost += inner_run_cost;      // run cost of the inner table
    }

    /* run cost of the loop operation */
    if (outer_path_rows > 1)
        run_cost += (outer_path_rows - 1) * inner_rescan_run_cost;

    join_tree->cost.startup_cost =  CBO_COST_SAFETY_RET(startup_cost);
    join_tree->cost.cost =  CBO_COST_SAFETY_RET(run_cost);

    /* save cost in join_cost_ws, do the initial path cut */
    join_cost_ws->startup_cost = CBO_COST_SAFETY_RET(startup_cost);
    join_cost_ws->total_cost = CBO_COST_SAFETY_RET(startup_cost + run_cost);
    join_cost_ws->run_cost = CBO_COST_SAFETY_RET(run_cost);
    join_cost_ws->inner_rescan_run_cost = CBO_COST_SAFETY_RET(inner_rescan_run_cost);

    sql_debug_join_cost_info(ja->stmt, join_tree, "NL", "initial end");

    return OG_SUCCESS;
}

status_t sql_final_cost_nestloop(join_assist_t *ja, sql_join_node_t* join_tree, join_cost_workspace* join_cost_ws,
    special_join_info_t *sjoininfo, galist_t *restricts)
{
    int64 ntuples = 0;
    double cpu_per_tuple = 0;
    /* cost of the base table */
    double run_cost = join_tree->cost.cost;
    double startup_cost = join_tree->cost.startup_cost;
    double inner_rescan_run_cost = join_cost_ws->inner_rescan_run_cost;
    double qual_startup_cost = 0;
    double qual_cost = 0;

    OG_RETURN_IFERR(sql_cost_pre_check(join_tree));

    sql_join_node_t* outer_path = join_tree->left;
    sql_join_node_t* inner_path = join_tree->right;

    if (outer_path->cost.card == 0 && inner_path->cost.card == 0) {
        return OG_SUCCESS;
    }

    sql_debug_join_cost_info(ja->stmt, join_tree, "NL", "final start");
    double outer_path_rows = sql_adjust_est_row(outer_path->cost.card);
    double inner_path_rows = sql_adjust_est_row(inner_path->cost.card);

    if (sjoininfo->jointype >= JOIN_TYPE_SEMI) {
        double outer_matched_rows = join_cost_ws->outer_matched_rows;
        double inner_scan_frac = join_cost_ws->inner_scan_frac;
        ntuples = sql_adjust_est_row(outer_matched_rows * inner_path_rows* inner_scan_frac);
        run_cost += (outer_path_rows - outer_matched_rows) * inner_rescan_run_cost;
        ntuples += (outer_path_rows - outer_matched_rows) * inner_path_rows;
    } else {
        ntuples = sql_adjust_est_row(outer_path_rows * inner_path_rows);
    }

    (void)sql_cost_qual_eval_walker(&qual_startup_cost, &qual_cost, restricts);

    /* startup_cost */
    startup_cost += qual_startup_cost;
    cpu_per_tuple = CBO_DEFAULT_CPU_SCAN_TUPLE_COST + qual_cost;
    run_cost += cpu_per_tuple * ntuples;

    join_tree->cost.startup_cost =  CBO_COST_SAFETY_RET(startup_cost);
    join_tree->cost.cost =  CBO_COST_SAFETY_RET(run_cost + startup_cost);
    sql_debug_join_cost_info(ja->stmt, join_tree, "NL", "final end");
    
    return OG_SUCCESS;
}

static bool8 sql_calc_join_exprt_factor_per_col(join_assist_t *ja, expr_tree_t* expr, ff_calc_ass_t *ff_ass,
    bool is_left, uint32 *tab_id, uint32 *col_id)
{
    if (expr != NULL && expr->root != NULL && expr->root->type != EXPR_NODE_COLUMN) {
        return OG_FALSE;
    }

    cols_used_t cols_used;
    init_cols_used(&cols_used);
    sql_collect_cols_in_expr_tree(expr, &cols_used);
    if (!HAS_SELF_COLS(cols_used.flags) || HAS_DIFF_TABS(&cols_used, SELF_IDX)) {
        return OG_FALSE;
    }

    expr_node_t *col_node = sql_any_self_col_node(&cols_used);
    if (col_node->type != EXPR_NODE_COLUMN && col_node->type != EXPR_NODE_TRANS_COLUMN) {
        return OG_FALSE;
    }

    sql_table_t *tmp_table = ja->pa->tables[TAB_OF_NODE(col_node)];
    if (tmp_table->type != NORMAL_TABLE || NODE_COL(col_node) == OG_INVALID_ID16) {
        return OG_FALSE;
    }

    *tab_id = NODE_TAB(col_node);
    *col_id = NODE_COL(col_node);
    dc_entity_t* dc_entity = DC_ENTITY(&tmp_table->entry->dc);
    cbo_stats_column_t* col_stats = cbo_get_column_stats(dc_entity->cbo_table_stats, COL_OF_NODE(col_node));
    if (col_stats != NULL) {
        if (is_left) {
            ff_ass->left_distinct = col_stats->num_distinct;
            ff_ass->left_total_rows = col_stats->total_rows;
            ff_ass->left_nulls = 1.0 * col_stats->num_null / col_stats->total_rows;
        } else {
            ff_ass->right_distinct = col_stats->num_distinct;
            ff_ass->right_total_rows = col_stats->total_rows;
            ff_ass->right_nulls = 1.0 * col_stats->num_null / col_stats->total_rows;
        }
    }

    return OG_TRUE;
}

static double sql_calc_join_expr_factor_eq_semi(join_assist_t *ja, ff_calc_ass_t *ff_ass, double inner_rows,
    bool reversed, double select_inner)
{
    ff_calc_ass_t tmp_ff_ass = *ff_ass;
    double selec;

    if (reversed) {
        tmp_ff_ass.left_distinct = ff_ass->right_distinct;
        tmp_ff_ass.right_distinct = ff_ass->left_distinct;
        tmp_ff_ass.left_nulls = ff_ass->right_nulls;
        tmp_ff_ass.right_nulls = ff_ass->left_nulls;
        tmp_ff_ass.left_total_rows = ff_ass->right_total_rows;
        tmp_ff_ass.right_total_rows = ff_ass->left_total_rows;
        tmp_ff_ass.is_left_default = ff_ass->is_right_default;
        tmp_ff_ass.is_right_default = ff_ass->is_left_default;
    }

    if (tmp_ff_ass.is_left_default && tmp_ff_ass.left_total_rows == 0) {
        tmp_ff_ass.left_total_rows = CBO_JOIN_MIN_CARD;
    }

    if (tmp_ff_ass.is_right_default && tmp_ff_ass.right_total_rows == 0) {
        tmp_ff_ass.right_total_rows = CBO_JOIN_MIN_CARD;
    }

    // adjust inner_rows if it is 0
    inner_rows = CBO_CARD_SAFETY_RET(inner_rows);
    tmp_ff_ass.right_distinct = MIN(tmp_ff_ass.right_distinct, inner_rows);
    double default_selec = 0.5 * (1.0 - tmp_ff_ass.left_nulls);
    if (!tmp_ff_ass.is_left_default && !tmp_ff_ass.is_right_default) {
        if (tmp_ff_ass.left_distinct <= tmp_ff_ass.right_distinct || tmp_ff_ass.right_distinct < 0) {
            selec = 1.0 - tmp_ff_ass.left_nulls;
        } else {
            selec = (tmp_ff_ass.right_distinct / tmp_ff_ass.left_distinct) * (1.0 - tmp_ff_ass.left_nulls);
        }
    } else if (!tmp_ff_ass.is_left_default && tmp_ff_ass.is_right_default &&
            tmp_ff_ass.right_total_rows != CBO_JOIN_MIN_CARD) {
        selec = (tmp_ff_ass.right_total_rows / tmp_ff_ass.left_distinct) * (1.0 - tmp_ff_ass.left_nulls);
        selec = MIN(selec, default_selec);
    } else {
        selec = default_selec;
    }

    // ajust select to no more than inner_rows
    selec = MIN(selec, inner_rows * select_inner);
    return selec;
}

static void sql_try_save_semi_factor(double *select_semi, double right_select, double select_inner, double inner_rows,
    special_join_info_t *sjinfo)
{
    double avg_match = 1.0;
    double r_avg_match = 1.0;
    if (*select_semi > 0) {
        avg_match = select_inner * inner_rows / (*select_semi);
        avg_match = MAX(1.0, avg_match);
    }

    if (right_select > 0) {
        r_avg_match = select_inner * inner_rows / right_select;
        r_avg_match = MAX(1.0, r_avg_match);
    }

    if (sjinfo->reversed) {
        sjinfo->semi_anti_factor.outer_match_frac = right_select;
        sjinfo->semi_anti_factor.match_count = r_avg_match;
        sjinfo->semi_anti_factor.r_semi_match_count = *select_semi;
    } else {
        sjinfo->semi_anti_factor.outer_match_frac = *select_semi;
        sjinfo->semi_anti_factor.match_count = avg_match;
        sjinfo->semi_anti_factor.r_semi_match_count = right_select;
    }

    // in case it is reversed
    *select_semi = sjinfo->semi_anti_factor.outer_match_frac;
}

static bool sql_check_same_cond_info(cond_info_t *cond_info, uint32 l_tab, uint32 l_col, uint32 r_tab, uint32 r_col)
{
    for (uint i = 0; i < OG_MAX_JOIN_TABLES; i++) {
        if (!cond_info[i].used) {
            cond_info[i].l_table = l_tab;
            cond_info[i].l_col = l_col;
            cond_info[i].r_table = r_tab;
            cond_info[i].r_col = r_col;
            cond_info[i].used = true;
            break;
        }

        if ((cond_info[i].l_table == l_tab && cond_info[i].l_col == l_col) ||
            (cond_info[i].l_table == r_tab && cond_info[i].l_col == r_col) ||
            (cond_info[i].r_table == r_tab && cond_info[i].r_col == r_col) ||
            (cond_info[i].r_table == l_tab && cond_info[i].r_col == l_col)) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static double sql_calc_join_expr_factor_eq_inner(
    join_assist_t *ja,
    expr_tree_t *left,
    expr_tree_t *right,
    ff_calc_ass_t *ff_ass,
    cond_info_t *cond_info)
{
    uint32 left_table = 0;
    uint32 left_col = 0;
    uint32 right_table = 0;
    uint32 right_col = 0;

    if (sql_calc_join_exprt_factor_per_col(ja, left, ff_ass, true, &left_table, &left_col) == OG_FALSE) {
        ff_ass->is_left_default = true;
    }

    if (sql_calc_join_exprt_factor_per_col(ja, right, ff_ass, false, &right_table, &right_col) == OG_FALSE) {
        ff_ass->is_right_default = true;
    }

    if (ff_ass->is_left_default || ff_ass->is_right_default) {
        return CBO_DEFAULT_EQ_FF;
    }

    if (sql_check_same_cond_info(cond_info, left_table, left_col, right_table, right_col)) {
        return CBO_MAX_FF;
    }

    double ff = (1.0  - ff_ass->left_nulls) * (1.0 - ff_ass->right_nulls) /
        MAX(ff_ass->left_distinct, ff_ass->right_distinct);
    return sql_normalize_ff(ff);
}

static double sql_calc_join_expr_factor_eq(
    join_assist_t *ja,
    cmp_node_t* cmp,
    special_join_info_t *sjinfo,
    cond_info_t *cond_info)
{
    ff_calc_ass_t ff_ass = {0};
    ff_ass.left_distinct = DEFAULT_NUM_DISTINCT;
    ff_ass.right_distinct = DEFAULT_NUM_DISTINCT;
    ff_ass.left_nulls = 0.0;
    ff_ass.right_nulls = 0.0;
    ff_ass.is_left_default = false;
    ff_ass.is_right_default = false;
    ff_ass.left_total_rows = 0;
    ff_ass.right_total_rows = 0;

    double select_inner = sql_calc_join_expr_factor_eq_inner(ja, cmp->left, cmp->right, &ff_ass, cond_info);
    switch (sjinfo->jointype) {
        case JOIN_TYPE_INNER:
        case JOIN_TYPE_LEFT:
        case JOIN_TYPE_FULL:
            return select_inner;
        case JOIN_TYPE_SEMI:
        case JOIN_TYPE_ANTI:
        case JOIN_TYPE_ANTI_NA: {
            // find inner rel from sjinfo
            sql_join_table_t* inner_jtable;
            if (sql_jass_find_jtable(ja, &sjinfo->min_righthand, &inner_jtable) == OG_FALSE) {
                OG_LOG_RUN_ERR("Could not find jtable for given table_ids.");
                break;
            }
            double select_semi = sql_calc_join_expr_factor_eq_semi(ja, &ff_ass, inner_jtable->rows, false,
                select_inner);
            double right_select = sql_calc_join_expr_factor_eq_semi(ja, &ff_ass, inner_jtable->rows, true,
                select_inner);
            sql_try_save_semi_factor(&select_semi, right_select, select_inner, inner_jtable->rows, sjinfo);
            return select_semi;
        }
        default:
            break;
    }

    return CBO_DEFAULT_EQ_FF;
}

static double sql_calc_join_expr_factor_neq(
    join_assist_t *ja,
    cmp_node_t* cmp,
    special_join_info_t *sjinfo,
    cond_info_t *cond_info)
{
    ff_calc_ass_t ff_ass = {0};
    ff_ass.left_distinct = DEFAULT_NUM_DISTINCT;
    ff_ass.right_distinct = DEFAULT_NUM_DISTINCT;
    ff_ass.left_nulls = 0.0;
    ff_ass.right_nulls = 0.0;
    ff_ass.is_left_default = false;
    ff_ass.is_right_default = false;
    ff_ass.left_total_rows = 0;
    ff_ass.right_total_rows = 0;

    double selec_inner = sql_calc_join_expr_factor_eq_inner(ja, cmp->left, cmp->right, &ff_ass, cond_info);
    switch (sjinfo->jointype) {
        case JOIN_TYPE_INNER:
        case JOIN_TYPE_LEFT:
        case JOIN_TYPE_FULL:
            return (1 - selec_inner);
        case JOIN_TYPE_SEMI:
        case JOIN_TYPE_ANTI: {
            if (sjinfo->reversed) {
                return (1- ff_ass.right_nulls);
            }
            return (1- ff_ass.left_nulls);
        }
        default:
            break;
    }

    return (1 - CBO_DEFAULT_EQ_FF);
}

static double sql_calc_join_expr_factor_ineq(
    join_assist_t *ja,
    cmp_node_t* cmp,
    special_join_info_t *sjinfo)
{
    return CBO_DEFAULT_INEQ_FF;
}


static double sql_calc_join_expr_factor(
    join_assist_t *ja,
    cmp_node_t* cmp,
    special_join_info_t *sjinfo,
    cond_info_t *cond_info)
{
    double ff = CBO_DEFAULT_INEQ_FF;

    switch (cmp->type) {
        case CMP_TYPE_EQUAL:
            ff = sql_calc_join_expr_factor_eq(ja, cmp, sjinfo, cond_info);
            break;
        case CMP_TYPE_NOT_EQUAL:
            ff = sql_calc_join_expr_factor_neq(ja, cmp, sjinfo, cond_info);
            break;
        default:
            ff = sql_calc_join_expr_factor_ineq(ja, cmp, sjinfo);
            break;
    }

    return ff;
}

static double sql_calc_join_cond_factor(
    join_assist_t *ja,
    cond_node_t* cond,
    special_join_info_t *sjinfo,
    cond_info_t *cond_info)
{
    double ff = CBO_DEFAULT_INEQ_FF;
    switch (cond->type) {
        case COND_NODE_AND:{
            double ff1 = sql_calc_join_cond_factor(ja, cond->left, sjinfo, cond_info);
            double ff2 = sql_calc_join_cond_factor(ja, cond->right, sjinfo, cond_info);
            ff = ff1 * ff2;
            break;
        }
        case COND_NODE_OR: {
            double ff1 = sql_calc_join_cond_factor(ja, cond->left, sjinfo, cond_info);
            double ff2 = sql_calc_join_cond_factor(ja, cond->right, sjinfo, cond_info);
            ff = ff1 + ff2 - ff1 * ff2;
            break;
        }
        case COND_NODE_COMPARE:
            ff = sql_calc_join_expr_factor(ja, cond->cmp, sjinfo, cond_info);
            break;

        default:
            break;
    }

    return sql_normalize_ff(ff);
}

double sql_compute_join_factor(join_assist_t *ja, galist_t* conds, special_join_info_t *sjinfo)
{
    double ff = 1;
    cond_info_t cond_info[OG_MAX_JOIN_TABLES] = { 0 };
    for (uint32 i = 0; i < conds->count; i++) {
        tbl_join_info_t* jinfo = (tbl_join_info_t *)cm_galist_get(conds, i);
        ff = ff * sql_calc_join_cond_factor(ja, jinfo->cond, sjinfo, cond_info);
    }
    return sql_normalize_ff(ff);
}

static int64 sql_cal_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table, cond_tree_t *cond,
    cbo_stats_info_t* stats_info)
{
    int64 result = cond != NULL ? round(stats_info->cbo_table_stats->rows *
        compute_and_conds_ff(pa, entity, table, cond->root, stats_info)) : stats_info->cbo_table_stats->rows;
    
    return result <= 0 ? 1 : result;
}


double sql_estimate_subpartition_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table)
{
    // sub partitioned table row estimate
    uint64 part_cnt = table->scan_part_info->part_cnt;
    double cost = 0;
    uint32 index_id = index->desc.id;
    scan_part_range_type_t scan_type = table->scan_part_info->scan_type;
    if (scan_type == SCAN_PART_FULL) {
        return sql_estimate_partition_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, table);
    }
    uint64 cal_part_cnt = MIN(part_cnt, MAX_CBO_CALU_PARTS_COUNT);
    for (uint64 i = 0; i < cal_part_cnt; i++) {
        uint32 table_partition_no = PART_TABLE_SCAN_PART_NO(table, i);
        if (table_partition_no == CBO_GLOBAL_PART_NO) {
            return sql_estimate_partition_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, table);
        }
        uint32 table_subpartition_no = COMPART_TABLE_SCAN_SUBPART_NO(table, i);
        uint32 index_partition_no = IS_PART_INDEX(index) ? CBO_GLOBAL_PART_NO : table_partition_no;
        uint32 index_subpartition_no = IS_PART_INDEX(index) ? CBO_GLOBAL_SUBPART_NO : table_subpartition_no;
        cbo_stats_info_t stats_info;
        OG_RETURN_MAX_COST_IFERR(init_stats_info(&stats_info, scan_type, table_partition_no, table_subpartition_no,
            index_id, index_partition_no, index_subpartition_no));
        OG_RETURN_MAX_COST_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(stmt)));
        OG_RETURN_MAX_COST_IFTRUE(stats_info.cbo_index_stats == NULL);
        cost += sql_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, &stats_info, table);
        cost = CBO_COST_SAFETY_RET(cost);
    }
    if (part_cnt > MAX_CBO_CALU_PARTS_COUNT) {
        cost = cost * (double)part_cnt / (double)cal_part_cnt;
        cost = CBO_COST_SAFETY_RET(cost);
        ca->startup_cost = ca->startup_cost * (double)part_cnt / (double)cal_part_cnt;
        ca->startup_cost = CBO_COST_SAFETY_RET(ca->startup_cost);
    }
    return cost;
}

double sql_estimate_partition_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table)
{
    // partitioned table row estimate
    uint64 part_cnt = table->scan_part_info->part_cnt;
    double cost = 0;
    uint32 index_id = index->desc.id;
    scan_part_range_type_t scan_type = table->scan_part_info->scan_type;
    uint64 cal_part_cnt = MIN(part_cnt, MAX_CBO_CALU_PARTS_COUNT);
    for (uint64 i = 0; i < cal_part_cnt; i++) {
        cbo_stats_info_t stats_info;
        uint32 table_partition_no = PART_TABLE_SCAN_PART_NO(table, i);
        uint32 index_partition_no = IS_PART_INDEX(index) ? CBO_GLOBAL_PART_NO : table_partition_no;
        OG_RETURN_MAX_COST_IFERR(init_stats_info(&stats_info, scan_type, table_partition_no, CBO_GLOBAL_SUBPART_NO,
            index_id, index_partition_no, CBO_GLOBAL_SUBPART_NO));
        OG_RETURN_MAX_COST_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(stmt)));
        OG_RETURN_MAX_COST_IFTRUE(stats_info.cbo_index_stats == NULL);
        cost += sql_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, &stats_info, table);
        cost = CBO_COST_SAFETY_RET(cost);
    }
    if (part_cnt > MAX_CBO_CALU_PARTS_COUNT) {
        cost = cost * (double)part_cnt / (double)cal_part_cnt;
        cost = CBO_COST_SAFETY_RET(cost);
        ca->startup_cost = ca->startup_cost * (double)part_cnt / (double)cal_part_cnt;
        ca->startup_cost = CBO_COST_SAFETY_RET(ca->startup_cost);
    }
    return cost;
}

double sql_estimate_nopartition_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table)
{
    // no partitioned table row estimate
    double cost = 0;
    uint32 index_id = index->desc.id;
    cbo_stats_info_t stats_info;
    OG_RETURN_MAX_COST_IFERR(init_stats_info(&stats_info, SCAN_PART_FULL, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO,
        index_id, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
    OG_RETURN_MAX_COST_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(stmt)));
    OG_RETURN_MAX_COST_IFTRUE(stats_info.cbo_index_stats == NULL);
    cost = sql_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, &stats_info, table);
    cost = CBO_COST_SAFETY_RET(cost);
    return cost;
}


double sql_estimate_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table)
{
    if (knl_is_compart_table(table->entry->dc.handle)) {
        return sql_estimate_subpartition_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, table);
    } else if (knl_is_part_table(table->entry->dc.handle)) {
        return sql_estimate_partition_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, table);
    } else {
        return sql_estimate_nopartition_index_scan_cost(stmt, ca, entity, index, idx_cond_array, card, table);
    }
}


int64 sql_estimate_subpartitioned_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond)
{
    // sub partitioned table row estimate
    uint64 part_cnt = table->scan_part_info->part_cnt;
    int64 card = 0;
    uint64 cal_part_cnt = MIN(part_cnt, MAX_CBO_CALU_PARTS_COUNT);
    scan_part_range_type_t scan_type = table->scan_part_info->scan_type;
    if (scan_type == SCAN_PART_FULL) {
        return sql_estimate_partitioned_table_card(pa, entity, table, cond);
    }
    for (uint64 i = 0; i < cal_part_cnt; i++) {
        uint32 table_partition_no = PART_TABLE_SCAN_PART_NO(table, i);
        if (table_partition_no == CBO_GLOBAL_PART_NO) {
            return sql_estimate_partitioned_table_card(pa, entity, table, cond);
        }
        uint32 table_subpartition_no = COMPART_TABLE_SCAN_SUBPART_NO(table, i);
        cbo_stats_info_t stats_info;
        OG_RETURN_MAX_ROWS_IFERR(init_stats_info(&stats_info, scan_type, table_partition_no, table_subpartition_no,
            OG_INVALID_ID32, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
        OG_RETURN_MAX_ROWS_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(pa->stmt)));
        card += sql_cal_table_card(pa, entity, table, cond, &stats_info);
        card = CBO_CARD_SAFETY_SET(card);
    }
    
    if (part_cnt > MAX_CBO_CALU_PARTS_COUNT && cal_part_cnt != 0) {
        card = card * part_cnt / cal_part_cnt;
        card = CBO_CARD_SAFETY_SET(card);
    }
    return card;
}

int64 sql_estimate_partitioned_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond)
{
    // partitioned table row estimate
    uint64 part_cnt = table->scan_part_info->part_cnt;
    int64 card = 0;
    uint64 cal_part_cnt = MIN(part_cnt, MAX_CBO_CALU_PARTS_COUNT);
    scan_part_range_type_t scan_type = table->scan_part_info->scan_type;
    for (uint64 i = 0; i < cal_part_cnt; i++) {
        cbo_stats_info_t stats_info;
        uint32 table_partition_no = PART_TABLE_SCAN_PART_NO(table, i);
        OG_RETURN_MAX_ROWS_IFERR(init_stats_info(&stats_info, scan_type, table_partition_no, CBO_GLOBAL_SUBPART_NO,
            OG_INVALID_ID32, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
        OG_RETURN_MAX_ROWS_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(pa->stmt)));
        card += sql_cal_table_card(pa, entity, table, cond, &stats_info);
        card = CBO_CARD_SAFETY_SET(card);
    }

    if (part_cnt > MAX_CBO_CALU_PARTS_COUNT && cal_part_cnt != 0) {
        card = card * part_cnt / cal_part_cnt;
        card = CBO_CARD_SAFETY_SET(card);
    }
    return card;
}


int64 sql_estimate_nopartitioned_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond)
{
    // no partitioned table row estimate
    int64 card = 0;
    cbo_stats_info_t stats_info;
    OG_RETURN_MAX_ROWS_IFERR(init_stats_info(&stats_info, SCAN_PART_FULL, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO,
        OG_INVALID_ID32, CBO_GLOBAL_PART_NO, CBO_GLOBAL_SUBPART_NO));
    OG_RETURN_MAX_ROWS_IFERR(sql_cal_table_or_partition_stats(entity, table, &stats_info, KNL_SESSION(pa->stmt)));
    card = sql_cal_table_card(pa, entity, table, cond, &stats_info);
    return card;
}


int64 sql_estimate_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond)
{
    if (knl_is_compart_table(table->entry->dc.handle)) {
        return sql_estimate_subpartitioned_table_card(pa, entity, table, cond);
    } else if (knl_is_part_table(table->entry->dc.handle)) {
        return sql_estimate_partitioned_table_card(pa, entity, table, cond);
    }
    return sql_estimate_nopartitioned_table_card(pa, entity, table, cond);
}

static status_t sql_estimate_query_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->query.next == NULL)
        return OG_ERROR;
    
    if (plan->query.next->cost == 0 && plan->query.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->query.next));
    }

    plan->rows = plan->query.next->rows;
    plan->cost = plan->query.next->cost;
    plan->start_cost = plan->query.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_union_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->set_p.left == NULL || plan->set_p.right == NULL)
        return OG_ERROR;

    if (plan->set_p.left->cost == 0 && plan->set_p.left->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->set_p.left));
    }

    if (plan->set_p.right->cost == 0 && plan->set_p.right->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->set_p.right));
    }

    plan->rows = plan->set_p.left->rows + plan->set_p.right->rows;
    plan->cost = plan->set_p.left->cost + plan->set_p.right->cost + plan->rows * CBO_DEFAULT_CPU_OPERATOR_COST;
    plan->start_cost = plan->set_p.left->start_cost + plan->set_p.right->start_cost;

    return OG_SUCCESS;
}

static status_t sql_estimate_union_all_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->set_p.list == NULL)
        return OG_ERROR;

    plan_node_t *sub_node = NULL;
    for (uint32 i = 0; i < plan->set_p.list->count; i++) {
        sub_node = (plan_node_t *)cm_galist_get(plan->set_p.list, i);
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, sub_node));
    }

    for (uint32 i = 0; i < plan->set_p.list->count; i++) {
        sub_node = (plan_node_t *)cm_galist_get(plan->set_p.list, i);
        plan->rows += sub_node->rows;
        plan->cost += sub_node->cost;
        plan->start_cost += sub_node->start_cost;
    }

    plan->cost += plan->rows * CBO_DEFAULT_CPU_OPERATOR_COST;

    return OG_SUCCESS;
}

static status_t sql_estimate_minus_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->set_p.left == NULL || plan->set_p.right == NULL)
        return OG_ERROR;

    if (plan->set_p.left->cost == 0 && plan->set_p.left->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->set_p.left));
    }

    if (plan->set_p.right->cost == 0 && plan->set_p.right->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->set_p.right));
    }

    plan->rows = plan->set_p.left->rows + plan->set_p.right->rows;
    plan->cost = plan->set_p.left->cost + plan->set_p.right->cost;
    plan->start_cost = plan->set_p.left->start_cost + plan->set_p.right->start_cost;
    minus_plan_t *minus_plan = &plan->set_p.minus_p;

    if (minus_plan->minus_type == MINUS) {
        // For MINUS[EXCEPT] opers, left table always as hash mtrl
        minus_plan->minus_left = OG_TRUE;
    } else {
        // For EXCEPT ALL, INTERSECT[ALL] opers, which table as hash mtrl based on rows
        minus_plan->minus_left = (plan->set_p.left->rows > plan->set_p.right->rows) ? OG_FALSE : OG_TRUE;
    }
    
    OG_LOG_DEBUG_INF("[HASH MINUS] type = %u, left_rows = %lld, right_rows = %lld, left_table_hash = %u",
        minus_plan->minus_type, plan->set_p.left->rows, plan->set_p.right->rows, minus_plan->minus_left);
    return OG_SUCCESS;
}

static status_t sql_estimate_hashminus_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    return sql_estimate_minus_cost(stmt, plan);
}

static status_t sql_estimate_merge_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL)
        return OG_ERROR;

    if (plan->merge_p.merge_into_scan_p->cost == 0 && plan->merge_p.merge_into_scan_p->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->merge_p.merge_into_scan_p));
    }

    if (plan->merge_p.using_table_scan_p->cost == 0 && plan->merge_p.using_table_scan_p->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->merge_p.using_table_scan_p));
    }

    plan->rows = plan->merge_p.merge_into_scan_p->rows + plan->merge_p.using_table_scan_p->rows;
    plan->cost = plan->merge_p.merge_into_scan_p->cost + plan->merge_p.using_table_scan_p->cost;
    plan->start_cost = plan->merge_p.merge_into_scan_p->start_cost + plan->merge_p.using_table_scan_p->start_cost;

    return OG_SUCCESS;
}

static status_t sql_estimate_insert_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL)
        return OG_ERROR;

    sql_insert_t *insert_ctx = NULL;
    if (stmt->context->type != OGSQL_TYPE_REPLACE) {
        insert_ctx = (sql_insert_t *)stmt->context->entry;
    } else {
        insert_ctx = &((sql_replace_t *)stmt->context->entry)->insert_ctx;
    }

    plan->rows = insert_ctx->pairs_count;
    plan->cost = plan->rows * CBO_DEFAULT_CPU_OPERATOR_COST ;
    plan->start_cost = 0;
    return OG_SUCCESS;
}

static status_t sql_estimate_update_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->update_p.next == NULL)
        return OG_ERROR;

    if (plan->update_p.next->cost == 0 && plan->update_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->update_p.next));
    }

    plan->rows = plan->update_p.next->rows;
    plan->cost = plan->update_p.next->cost;
    plan->start_cost = plan->update_p.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_delete_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->delete_p.next == NULL)
        return OG_ERROR;

    if (plan->delete_p.next->cost == 0 && plan->delete_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->delete_p.next));
    }

    plan->rows = 0;
    plan->cost = plan->delete_p.next->cost;
    plan->start_cost = plan->delete_p.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_select_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->select_p.next == NULL)
        return OG_ERROR;

    if (plan->select_p.next->cost == 0 && plan->select_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->select_p.next));
    }

    plan->rows = plan->select_p.next->rows;
    plan->cost = plan->select_p.next->cost;
    plan->start_cost = plan->select_p.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_join_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    /* has been done on make one rel, do need to do nothing */
    return OG_SUCCESS;
}

static status_t sql_estimate_group_cost(cbo_cost_t* cost_group, double input_rows, double group_cols, bool with_sort)
{
    double cost = 0;
    double startup_cost = 0;
    if (with_sort) {
        // sort group
        startup_cost += input_rows * log(input_rows) * CBO_DEFAULT_CPU_QK_COMP_COST;
        cost += group_cols * input_rows * (CBO_DEFAULT_CPU_QK_SORT_COST + CBO_DEFAULT_CPU_QK_INST_COST);
        cost += startup_cost;
    } else {
        // hash group
        startup_cost = CBO_DEFAULT_HASH_INIT_COST;
        cost += startup_cost + input_rows * (CBO_DEFAULT_CPU_HASH_BUILD_COST + CBO_DEFAULT_CPU_HASH_CALC_COST);
    }
    cost_group->startup_cost += startup_cost;
    cost_group->cost += cost;
    return OG_SUCCESS;
}

static double get_column_distinct_from_stats(plan_node_t *child, uint32 tab_id, uint32 col_id, double input_rows)
{
    sql_table_t *table = NULL;
    double col_ndistinct = DEFAULT_DISTINCT_FACTOR * input_rows;
    if (child == NULL) {
        return col_ndistinct;
    }
    switch (child->type) {
        case PLAN_NODE_JOIN:
            table = child->join_p.cache_tab;
            break;
        case PLAN_NODE_SCAN:
            table = child->scan_p.table;
            break;
        case PLAN_NODE_QUERY:
            if (child->query.ref != NULL) {
                table = (sql_table_t *)sql_array_get(&child->query.ref->tables, tab_id);
            }
            break;
        default:
            break;
    }
    if (table == NULL || table->type != NORMAL_TABLE) {
        return col_ndistinct;
    }
    dc_entity_t* dc_entity = DC_ENTITY(&table->entry->dc);
    if (dc_entity == NULL || dc_entity->cbo_table_stats == NULL) {
        return col_ndistinct;
    }
    cbo_stats_column_t* col_stats = cbo_get_column_stats(dc_entity->cbo_table_stats, col_id);
    if (col_stats == NULL || col_stats->num_distinct <= 0) {
        return col_ndistinct;
    }
    col_ndistinct = (double)col_stats->num_distinct;
    if (col_ndistinct < 1.0) {
        col_ndistinct = 1.0;
    }
    if (col_ndistinct > input_rows) {
        col_ndistinct = input_rows;
    }
    return col_ndistinct;
}

static double sql_estimate_column_distinct(cols_used_t *cols_used, plan_node_t *child, double input_rows)
{
    expr_node_t *col_node = sql_any_self_col_node(cols_used);
    if (col_node == NULL || (col_node->type != EXPR_NODE_COLUMN && col_node->type != EXPR_NODE_TRANS_COLUMN) ||
        NODE_COL(col_node) == OG_INVALID_ID16) {
        return sqrt(input_rows);
    }
    uint32 tab_id = NODE_TAB(col_node);
    uint32 col_id = NODE_COL(col_node);
    if (tab_id == OG_INVALID_ID32 || col_id == OG_INVALID_ID16) {
        // No statistical information available, using default estimation
        return DEFAULT_DISTINCT_FACTOR * input_rows;
    }
    return get_column_distinct_from_stats(child, tab_id, col_id, input_rows);
}

static double sql_estimate_expr_distinct(expr_tree_t *expr, plan_node_t *child, double input_rows)
{
    double col_ndistinct = 1.0;
    if (expr == NULL || expr->root == NULL) {
        return col_ndistinct;
    }
    expr_node_t *node = expr->root;
    if (node->datatype == OG_TYPE_BOOLEAN) {
        // boolean type has 2 distinct values
        col_ndistinct *= 2.0;
        return col_ndistinct;
    }
    cols_used_t cols_used;
    init_cols_used(&cols_used);
    sql_collect_cols_in_expr_tree(expr, &cols_used);
    if (!HAS_SELF_COLS(cols_used.flags) || HAS_DIFF_TABS(&cols_used, SELF_IDX)) {
        col_ndistinct = sqrt(input_rows);
        return col_ndistinct;
    }
    return sql_estimate_column_distinct(&cols_used, child, input_rows);
}

static double sql_estimate_group_by_distinct(galist_t *groupExprs, plan_node_t *child, double input_rows)
{
    double numdistinct = 1.0;
    double max_ndistinct = 1.0;
    uint32 num_cols = 0;
    for (uint32 i = 0; i < groupExprs->count; i++) {
        expr_tree_t *expr = (expr_tree_t *)cm_galist_get(groupExprs, i);
        double col_ndistinct = sql_estimate_expr_distinct(expr, child, input_rows);
        if (col_ndistinct > max_ndistinct) {
            max_ndistinct = col_ndistinct;
        }
        numdistinct *= col_ndistinct;
        num_cols++;
    }
    if (numdistinct < 1.0) {
        numdistinct = 1.0;
    }
    if (numdistinct > input_rows) {
        numdistinct = input_rows;
    }
    return numdistinct;
}

static double sql_estimate_num_groups(plan_node_t *plan)
{
    galist_t *groupExprs = plan->group.exprs;
    plan_node_t *child = plan->group.next;
    if (groupExprs == NULL || groupExprs->count == 0 || child == NULL) {
        return 1.0;
    }
    double input_rows = (double)child->rows;
    if (input_rows <= 1.0) {
        return (input_rows <= 0.0) ? 1.0 : input_rows;
    }
    return sql_estimate_group_by_distinct(groupExprs, child, input_rows);
}

static status_t sql_get_limit_const_value(plan_node_t *plan, int64 *limit_count_var,
    int64 *limit_offset_var)
{
    if (plan->limit.item.offset != NULL) {
        expr_tree_t* offset_expr = (expr_tree_t *)plan->limit.item.offset;
        if (offset_expr->root->type == EXPR_NODE_CONST) {
            variant_t offset_value = offset_expr->root->value;
            *limit_offset_var = offset_value.v_bigint;
        }
    }

    if (plan->limit.item.count != NULL) {
        expr_tree_t* count_expr = (expr_tree_t *)plan->limit.item.count;
        if (count_expr->root->type == EXPR_NODE_CONST) {
            variant_t count_value = count_expr->root->value;
            *limit_count_var = count_value.v_bigint;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_estimate_group_aggr_cost(cbo_cost_t *cost_group, plan_node_t *plan, bool hash_aggr)
{
    if (plan == NULL || plan->group.aggrs == NULL)
        return OG_ERROR;

    double trans_startup = 0;
    double trans_per = 0;
    double final_cost = 0;
    double numdistincts = cost_group->card;
    double group_cols = (double)plan->group.sets->count;
    double input_rows = (double)plan->rows;
    double start_cost = 0;
    double cost = 0;

    (void)sql_cost_qual_eval_walker(&trans_startup, &trans_per, plan->group.aggrs);

    if (plan->group.sort_groups != NULL) {
        final_cost += trans_per;
    }
    if (!hash_aggr) {
        // aggr sort group cost
        cost += trans_startup + trans_per * input_rows + CBO_DEFAULT_CPU_SCAN_TUPLE_COST * numdistincts;
        cost += final_cost * numdistincts;
    } else {
        // hash group cost, currently not consider
        start_cost += trans_startup + trans_per * input_rows;
        start_cost += (CBO_DEFAULT_CPU_OPERATOR_COST * group_cols) * input_rows;
        cost += final_cost * numdistincts + CBO_DEFAULT_CPU_SCAN_TUPLE_COST * numdistincts;
        // todo: memory spilling cost
    }

    cost_group->startup_cost += start_cost;
    cost_group->cost += start_cost + cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_sort_group_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->group.next == NULL)
        return OG_ERROR;

    if (plan->group.next->cost == 0 && plan->group.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->group.next));
    }

    plan->rows = plan->group.next->rows;
    if (plan->rows == 0) {
        plan->cost = plan->group.next->cost;
        plan->start_cost = plan->group.next->start_cost;
        return OG_SUCCESS;
    }

    double numdistincts = CBO_CARD_SAFETY_RET(sql_estimate_num_groups(plan));
    double total_rows = plan->rows;
    plan->start_cost = plan->group.next->start_cost;
    int64 limit_tuples = 0;
    int64 limit_offset = 0;
    (void)sql_get_limit_const_value(plan, &limit_tuples, &limit_offset);
        
    cbo_cost_t cost_group = {
        .card = (int64)numdistincts,
        .cost = plan->cost,
        .startup_cost = plan->start_cost
    };
    sql_estimate_group_cost(&cost_group, total_rows, (double)plan->group.sets->count, plan->group.sort_groups != NULL);
    sql_estimate_group_aggr_cost(&cost_group, plan, false);
    plan->rows = (int64)numdistincts;
    plan->cost = cost_group.cost + plan->group.next->cost;
    plan->start_cost = cost_group.startup_cost + plan->group.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_merge_sort_group_by_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    return sql_estimate_sort_group_cost(stmt, plan);
}

static status_t sql_estimate_hash_group_by_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->group.next == NULL)
        return OG_ERROR;

    if (plan->group.next->cost == 0 && plan->group.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->group.next));
    }

    plan->rows = plan->group.next->rows;
    if (plan->rows == 0) {
        plan->cost = plan->group.next->cost;
        plan->start_cost = plan->group.next->start_cost;
        return OG_SUCCESS;
    }

    double group_cols = (double)plan->group.sets->count;
    double numdistincts = CBO_CARD_SAFETY_RET(sql_estimate_num_groups(plan));
    plan->rows = (int64)numdistincts;
    cbo_cost_t cost_group = {
        .card = (int64)numdistincts,
        .cost = plan->group.next->cost,
        .startup_cost = plan->group.next->start_cost
    };
    sql_estimate_group_cost(&cost_group, plan->rows, group_cols, false);

    double trans_startup = 0;
    double trans_per = 0;
    double final_cost = 0;
    double start_cost = 0;
    double cost = cost_group.cost;
    if (plan->group.aggrs != NULL) {
        // hash aggr
        (void)sql_cost_qual_eval_walker(&trans_startup, &trans_per, plan->group.aggrs);
        start_cost += trans_startup + trans_per * plan->rows;
        start_cost += (CBO_DEFAULT_CPU_OPERATOR_COST * group_cols) * plan->rows;
        cost += final_cost * numdistincts + CBO_DEFAULT_CPU_SCAN_TUPLE_COST * numdistincts;
        // todo: memory spilling cost
    }

    // currently hash group, not include order by clause
    plan->start_cost += cost_group.startup_cost + start_cost;
    plan->cost = cost_group.cost + cost;
    return OG_SUCCESS;
}


static status_t sql_estimate_index_group_by_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    return sql_estimate_sort_group_cost(stmt, plan);
}

static status_t sql_estimate_query_sort_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->query_sort.next == NULL)
        return OG_ERROR;

    if (plan->query_sort.next->cost == 0 && plan->query_sort.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->query_sort.next));
    }

    plan->rows = plan->query_sort.next->rows;
    if (plan->rows == 0) {
        plan->cost = plan->query_sort.next->cost;
        plan->start_cost = plan->query_sort.next->start_cost;
        return OG_SUCCESS;
    }
    
    double sort_startup = plan->rows * log(plan->rows) * CBO_DEFAULT_CPU_QK_COMP_COST;
    double sort_cost = sort_startup + plan->rows * (CBO_DEFAULT_CPU_QK_SORT_COST + CBO_DEFAULT_CPU_QK_INST_COST);
    plan->cost = plan->query_sort.next->cost + sort_cost;
    plan->start_cost = plan->query_sort.next->start_cost + sort_startup;
    
    return OG_SUCCESS;
}

static status_t sql_estimate_select_sort_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->select_sort.next == NULL)
        return OG_ERROR;

    if (plan->select_sort.next->cost == 0 && plan->select_sort.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->select_sort.next));
    }

    plan->rows = plan->select_sort.next->rows;

    if (plan->rows == 0) {
        plan->cost = plan->query_sort.next->cost;
        plan->start_cost = plan->query_sort.next->start_cost;
        return OG_SUCCESS;
    }
    
    double sort_startup = plan->rows * log(plan->rows) * CBO_DEFAULT_CPU_QK_COMP_COST;
    double sort_cost = sort_startup + plan->rows * (CBO_DEFAULT_CPU_QK_SORT_COST + CBO_DEFAULT_CPU_QK_INST_COST);
    plan->cost = plan->query_sort.next->cost + sort_cost;
    plan->start_cost = plan->query_sort.next->start_cost + sort_startup;
    
    return OG_SUCCESS;
}


static status_t sql_estimate_aggr_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    double trans_startup = 0;
    double trans_per;
    double final_cost;
    if (plan == NULL || plan->aggr.next == NULL)
        return OG_ERROR;

    if (plan->aggr.next->cost == 0 && plan->aggr.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->aggr.next));
    }

    plan->rows = 1;
    trans_per = CBO_NORMAL_FUNC_FACTOR * CBO_DEFAULT_CPU_OPERATOR_COST;
    final_cost = CBO_NORMAL_FUNC_FACTOR * CBO_DEFAULT_CPU_OPERATOR_COST;

    (void)sql_cost_qual_eval_walker(&trans_startup, &trans_per, plan->aggr.items);
    // plain aggr
    plan->start_cost += plan->aggr.next->start_cost + trans_startup + trans_per * plan->aggr.next->rows +
                        final_cost;
    plan->cost += plan->start_cost;
    plan->cost += plan->aggr.next->cost + plan->aggr.next->rows * CBO_DEFAULT_CPU_OPERATOR_COST;
    plan->cost += plan->aggr.items->count * CBO_DEFAULT_CPU_OPERATOR_COST;  // simply for finaly cost
    
    return OG_SUCCESS;
}

static status_t sql_estimate_index_aggr_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    return sql_estimate_aggr_cost(stmt, plan);
}

static status_t sql_estimate_sort_distinct_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->distinct.next == NULL)
        return OG_ERROR;

    if (plan->distinct.next->cost == 0 && plan->distinct.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->distinct.next));
    }

    plan->rows = plan->distinct.next->rows;
    double distinct_cost = CBO_DEFAULT_CPU_OPERATOR_COST * plan->rows + CBO_DEFAULT_HASH_INIT_COST
                           + plan->rows * (CBO_DEFAULT_CPU_HASH_BUILD_COST + CBO_DEFAULT_CPU_HASH_CALC_COST);
    plan->cost = plan->distinct.next->cost + distinct_cost;
    plan->start_cost = plan->distinct.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_hash_distinct_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    return sql_estimate_sort_distinct_cost(stmt, plan);
}

static status_t sql_estimate_index_distinct_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    return sql_estimate_sort_distinct_cost(stmt, plan);
}

static status_t sql_estimate_having_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->having.next == NULL)
        return OG_ERROR;

    if (plan->having.next->cost == 0 && plan->having.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->having.next));
    }

    plan->rows = plan->having.next->rows;
    plan->cost = plan->having.next->cost + plan->rows * CBO_DEFAULT_CPU_OPERATOR_COST; /* do the having filter cost */
    plan->start_cost = plan->having.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_scan_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->scan_p.table == NULL)
        return OG_ERROR;

    sql_table_t *table = plan->scan_p.table;
    sql_table_type_t type = table->type;
    switch (type) {
        case NORMAL_TABLE:
            /* need to do nothing for nornal scan */
            break;

        case VIEW_AS_TABLE:
        case SUBSELECT_AS_TABLE:
            /* subquery cost has estimated before */
            if (table->select_ctx != NULL && table->select_ctx->plan != NULL) {
                plan->rows = table->select_ctx->plan->rows;
                plan->cost = table->select_ctx->plan->cost;
                plan->start_cost = table->select_ctx->plan->start_cost;
            }
            break;

        case FUNC_AS_TABLE:
            // todo
            break;

        case JOIN_AS_TABLE:
            // todo
            break;

        case WITH_AS_TABLE:
            // todo
            break;

        case JSON_TABLE:
            // todo
            break;

        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t sql_estimate_limit_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->limit.next == NULL)
        return OG_ERROR;

    int64 limit_count_var = 0;
    int64 limit_offset_var = 0;

    if (sql_get_limit_const_value(plan, &limit_count_var, &limit_offset_var)) {
        return OG_ERROR;
    }

    if (plan->limit.next->cost == 0 && plan->limit.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->limit.next));
    }

    /* limit */
    plan->rows = plan->limit.next->rows;
    plan->start_cost = plan->limit.next->start_cost;
    plan->cost = plan->limit.next->cost;

    if (plan->rows == 0) {
        return OG_SUCCESS;
    }

    if (limit_offset_var != 0) {
        double offset_rows = MIN((double)limit_offset_var, plan->rows);
        plan->start_cost += (plan->limit.next->cost - plan->limit.next->start_cost) *
            (offset_rows / (double)plan->limit.next->rows);
        plan->rows -= limit_offset_var;
        plan->rows = MAX(1, plan->rows);
    }
    if (limit_count_var != 0) {
        plan->rows = MIN(limit_count_var, plan->rows);
        plan->rows = MAX(1, plan->rows);
        plan->cost += plan->start_cost + (plan->limit.next->cost - plan->limit.next->start_cost) *
            ((double)plan->rows / (double)plan->limit.next->rows);
    }
    return OG_SUCCESS;
}

static status_t sql_estimate_select_limit_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->limit.next == NULL)
        return OG_ERROR;

    int64 limit_count_var = 0;
    int64 limit_offset_var = 0;

    if (sql_get_limit_const_value(plan, &limit_count_var, &limit_offset_var)) {
        return OG_ERROR;
    }

    if (plan->limit.next->cost == 0 && plan->limit.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->limit.next));
    }

    /* limit */
    plan->rows = plan->limit.next->rows;
    plan->start_cost = plan->limit.next->start_cost;
    plan->cost = plan->limit.next->cost;

    if (plan->rows == 0) {
        return OG_SUCCESS;
    }

    if (limit_offset_var != 0) {
        double offset_rows = MIN((double)limit_offset_var, plan->rows);
        plan->start_cost += (plan->limit.next->cost - plan->limit.next->start_cost) *
            (offset_rows / (double)plan->limit.next->rows);
        plan->rows -= limit_offset_var;
        plan->rows = MAX(1, plan->rows);
    }
    if (limit_count_var != 0) {
        plan->rows = MIN(limit_count_var, plan->rows);
        plan->rows = MAX(1, plan->rows);
        plan->cost += plan->start_cost + (plan->limit.next->cost - plan->limit.next->start_cost) *
            ((double)plan->rows / (double)plan->limit.next->rows);
    }
    return OG_SUCCESS;
}

static status_t sql_estimate_connect_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    /* todo */
    return OG_SUCCESS;
}

static status_t sql_estimate_filter_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->filter.next == NULL)
        return OG_ERROR;

    if (plan->filter.next->cost == 0 && plan->filter.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->filter.next));
    }

    plan->rows = plan->filter.next->rows;
    /* do the filter op cost */
    plan->cost = plan->filter.next->cost + plan->rows * CBO_DEFAULT_CPU_OPERATOR_COST;
    plan->start_cost = plan->filter.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_window_sort_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->winsort_p.next == NULL)
        return OG_ERROR;

    if (plan->winsort_p.next->cost == 0 && plan->winsort_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->winsort_p.next));
    }

    plan->rows = plan->winsort_p.next->rows;
    plan->cost = plan->winsort_p.next->cost;
    plan->start_cost = plan->winsort_p.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_remote_scan_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    /* need to do nothing */
    return OG_SUCCESS;
}

static status_t sql_estimate_group_merge_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->group.next == NULL)
        return OG_ERROR;

    if (plan->group.next->cost == 0 && plan->group.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->group.next));
    }

    plan->rows = plan->group.next->rows;
    if (plan->rows == 0) {
        plan->cost = plan->group.next->cost;
        plan->start_cost = plan->group.next->start_cost;
        return OG_SUCCESS;
    }
    
    cbo_cost_t cost_group = {
        .card = plan->rows,
        .cost = plan->cost,
        .startup_cost = plan->start_cost
    };
    sql_estimate_group_cost(&cost_group, plan->rows, (double)plan->group.sets->count,
                            plan->group.sort_groups != NULL);
    plan->cost = plan->group.next->cost + cost_group.cost;
    plan->start_cost = cost_group.startup_cost + LOG2(plan->rows) * CBO_DEFAULT_CPU_OPERATOR_COST
                        + plan->group.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_parallel_group_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->group.next == NULL)
        return OG_ERROR;

    if (plan->group.next->cost == 0 && plan->group.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->group.next));
    }

    plan->rows = plan->group.next->rows;
    if (plan->rows == 0) {
        plan->cost = plan->group.next->cost;
        plan->start_cost = plan->group.next->start_cost;
        return OG_SUCCESS;
    }
    
    cbo_cost_t cost_group = {
        .card = plan->rows,
        .cost = plan->cost,
        .startup_cost = plan->start_cost
    };
    OG_RETURN_IFERR(sql_estimate_group_cost(&cost_group, plan->rows, (double)plan->group.sets->count,
                            plan->group.sort_groups != NULL));
    plan->cost = plan->group.next->cost + cost_group.cost;
    plan->start_cost = cost_group.startup_cost + LOG2(plan->rows) * CBO_DEFAULT_CPU_OPERATOR_COST
                        + plan->group.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_hash_mtrl_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->hash_mtrl.group.next == NULL)
        return OG_ERROR;

    if (plan->hash_mtrl.group.next->cost == 0 && plan->hash_mtrl.group.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->hash_mtrl.group.next));
    }

    plan->rows = plan->hash_mtrl.group.next->rows;
    plan->cost = plan->hash_mtrl.group.next->cost;
    plan->start_cost = plan->hash_mtrl.group.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_concate_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->cnct_p.plans == NULL)
        return OG_ERROR;

    uint32 i = 0;
    plan_node_t *sub_plan = NULL;
    while (i < plan->cnct_p.plans->count) {
        sub_plan = (plan_node_t *)cm_galist_get(plan->cnct_p.plans, i++);
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, sub_plan));

        plan->rows = MAX(sub_plan->rows, plan->rows);
        plan->cost = MAX(sub_plan->cost, plan->cost);
        plan->start_cost = MAX(sub_plan->start_cost, plan->start_cost);
    }

    return OG_SUCCESS;
}

static status_t sql_estimate_cube_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->cube.next == NULL)
        return OG_ERROR;

    if (plan->cube.next->cost == 0 && plan->cube.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->cube.next));
    }

    plan->rows = plan->cube.next->rows;
    plan->cost = plan->cube.next->cost;
    plan->start_cost = plan->cube.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_pivot_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->group.next == NULL)
        return OG_ERROR;

    if (plan->group.next->cost == 0 && plan->group.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->group.next));
    }

    plan->rows = plan->group.next->rows;
    plan->cost = plan->group.next->cost;
    plan->start_cost = plan->group.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_unpivot_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->unpivot_p.next == NULL)
        return OG_ERROR;

    if (plan->unpivot_p.next->cost == 0 && plan->unpivot_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->unpivot_p.next));
    }

    plan->rows = plan->unpivot_p.next->rows;
    plan->cost = plan->unpivot_p.next->cost;
    plan->start_cost = plan->unpivot_p.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_rownum_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->rownum_p.next == NULL)
        return OG_ERROR;

    if (plan->rownum_p.next->cost == 0 && plan->rownum_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->rownum_p.next));
    }

    plan->rows = plan->rownum_p.next->rows;
    plan->cost = plan->rownum_p.next->cost;
    plan->start_cost = plan->rownum_p.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_for_update_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->for_update.next == NULL)
        return OG_ERROR;

    if (plan->for_update.next->cost == 0 && plan->for_update.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->for_update.next));
    }

    plan->rows = plan->for_update.next->rows;
    plan->cost = plan->for_update.next->cost;
    plan->start_cost = plan->for_update.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_withas_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    /* do nothing */
    return OG_SUCCESS;
}

static status_t sql_estimate_connect_mtrl_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->cb_mtrl.next == NULL)
        return OG_ERROR;

    if (plan->cb_mtrl.next->cost == 0 && plan->cb_mtrl.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->cb_mtrl.next));
    }

    plan->rows = plan->cb_mtrl.next->rows;
    plan->cost = plan->cb_mtrl.next->cost;
    plan->start_cost = plan->cb_mtrl.next->start_cost;
    return OG_SUCCESS;
}

static status_t sql_estimate_connect_hash_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    /* do nothing */
    return OG_SUCCESS;
}

static status_t sql_estimate_connect_vm_view_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    if (plan == NULL || plan->vm_view_p.next == NULL)
        return OG_ERROR;

    if (plan->vm_view_p.next->cost == 0 && plan->vm_view_p.next->start_cost == 0) {
        OG_RETURN_IFERR(sql_estimate_node_cost(stmt, plan->vm_view_p.next));
    }

    plan->rows = plan->vm_view_p.next->rows;
    plan->cost = plan->vm_view_p.next->cost;
    plan->start_cost = plan->vm_view_p.next->start_cost;
    return OG_SUCCESS;
}

static sql_estimate_node_cost_funcs g_sql_estimate_node_cost_funcs[] = {{PLAN_NODE_QUERY, sql_estimate_query_cost},
                                          {PLAN_NODE_UNION, sql_estimate_union_cost},
                                          {PLAN_NODE_UNION_ALL, sql_estimate_union_all_cost},
                                          {PLAN_NODE_MINUS, sql_estimate_minus_cost},
                                          {PLAN_NODE_HASH_MINUS, sql_estimate_hashminus_cost},
                                          {PLAN_NODE_MERGE, sql_estimate_merge_cost},
                                          {PLAN_NODE_INSERT, sql_estimate_insert_cost},
                                          {PLAN_NODE_DELETE, sql_estimate_delete_cost},
                                          {PLAN_NODE_UPDATE, sql_estimate_update_cost},
                                          {PLAN_NODE_SELECT, sql_estimate_select_cost},
                                          {PLAN_NODE_JOIN, sql_estimate_join_cost},
                                          {PLAN_NODE_SORT_GROUP, sql_estimate_sort_group_cost},
                                          {PLAN_NODE_MERGE_SORT_GROUP, sql_estimate_merge_sort_group_by_cost},
                                          {PLAN_NODE_HASH_GROUP, sql_estimate_hash_group_by_cost},
                                          {PLAN_NODE_INDEX_GROUP, sql_estimate_index_group_by_cost},
                                          {PLAN_NODE_QUERY_SORT, sql_estimate_query_sort_cost},
                                          {PLAN_NODE_SELECT_SORT, sql_estimate_select_sort_cost},
                                          {PLAN_NODE_AGGR, sql_estimate_aggr_cost},
                                          {PLAN_NODE_INDEX_AGGR, sql_estimate_index_aggr_cost},
                                          {PLAN_NODE_SORT_DISTINCT, sql_estimate_sort_distinct_cost},
                                          {PLAN_NODE_HASH_DISTINCT, sql_estimate_hash_distinct_cost},
                                          {PLAN_NODE_INDEX_DISTINCT, sql_estimate_index_distinct_cost},
                                          {PLAN_NODE_HAVING, sql_estimate_having_cost},
                                          {PLAN_NODE_SCAN, sql_estimate_scan_cost},
                                          {PLAN_NODE_QUERY_LIMIT, sql_estimate_limit_cost},
                                          {PLAN_NODE_SELECT_LIMIT, sql_estimate_select_limit_cost},
                                          {PLAN_NODE_CONNECT, sql_estimate_connect_cost},
                                          {PLAN_NODE_FILTER, sql_estimate_filter_cost},
                                          {PLAN_NODE_WINDOW_SORT, sql_estimate_window_sort_cost},
                                          {PLAN_NODE_REMOTE_SCAN, sql_estimate_remote_scan_cost},
                                          {PLAN_NODE_GROUP_MERGE, sql_estimate_group_merge_cost},
                                          {PLAN_NODE_HASH_GROUP_PAR, sql_estimate_parallel_group_cost},
                                          {PLAN_NODE_HASH_MTRL, sql_estimate_hash_mtrl_cost},
                                          {PLAN_NODE_CONCATE, sql_estimate_concate_cost},
                                          {PLAN_NODE_QUERY_SORT_PAR, sql_estimate_query_sort_cost},
                                          {PLAN_NODE_QUERY_SIBL_SORT, sql_estimate_query_sort_cost},
                                          {PLAN_NODE_GROUP_CUBE, sql_estimate_cube_cost},
                                          {PLAN_NODE_HASH_GROUP_PIVOT, sql_estimate_pivot_cost},
                                          {PLAN_NODE_UNPIVOT, sql_estimate_unpivot_cost},
                                          {PLAN_NODE_ROWNUM, sql_estimate_rownum_cost},
                                          {PLAN_NODE_FOR_UPDATE, sql_estimate_for_update_cost},
                                          {PLAN_NODE_WITHAS_MTRL, sql_estimate_withas_cost},
                                          {PLAN_NODE_CONNECT_MTRL, sql_estimate_connect_mtrl_cost},
                                          {PLAN_NODE_CONNECT_HASH, sql_estimate_connect_hash_cost},
                                          {PLAN_NODE_VM_VIEW_MTRL, sql_estimate_connect_vm_view_cost}};

status_t sql_estimate_node_cost(sql_stmt_t *stmt, plan_node_t *plan)
{
    CM_ASSERT(plan->type <= sizeof(g_sql_estimate_node_cost_funcs) / sizeof(sql_estimate_node_cost_funcs));
    CM_ASSERT(plan->type == g_sql_estimate_node_cost_funcs[plan->type - PLAN_NODE_QUERY].type);
    CM_ASSERT(g_sql_estimate_node_cost_funcs[plan->type - PLAN_NODE_QUERY].estimate_node_cost_funcs != NULL);
    status_t result = g_sql_estimate_node_cost_funcs[plan->type - PLAN_NODE_QUERY].estimate_node_cost_funcs(stmt, plan);
    CBO_PALN_SAFETY_SET(plan);
    return result;
}

/*
* set join size estimate
*/
status_t sql_jtable_estimate_size(join_assist_t *ja, sql_join_table_t *jtable, sql_join_table_t *jtbl1,
    sql_join_table_t *jtbl2, special_join_info_t *sjoininfo, galist_t* restricts)
{
    double selectivity = sql_compute_join_factor(ja, restricts, sjoininfo);
    double nrows = 0;
    switch (sjoininfo->jointype) {
        case JOIN_TYPE_INNER:
            nrows = (int)(selectivity * jtbl1->rows * jtbl2->rows);
            break;
        case JOIN_TYPE_LEFT:
            nrows = (int)(selectivity * jtbl1->rows * jtbl2->rows);
            if (nrows < jtbl1->rows) {
                nrows = jtbl1->rows;
            }
            break;
        case JOIN_TYPE_FULL:
            nrows = (int)(selectivity * jtbl1->rows * jtbl2->rows);
            if (nrows < jtbl1->rows) {
                nrows = jtbl1->rows;
            }
            if (nrows < jtbl2->rows) {
                nrows = jtbl2->rows;
            }
            break;
        case JOIN_TYPE_SEMI:
            nrows = jtbl2->rows * selectivity;
            break;
        case JOIN_TYPE_ANTI:
        case JOIN_TYPE_ANTI_NA:
            nrows = jtbl2->rows * (1 - selectivity);
            break;
        case JOIN_TYPE_RIGHT_SEMI:
            nrows = jtbl1->rows * selectivity;
            break;
        case JOIN_TYPE_RIGHT_ANTI:
        case JOIN_TYPE_RIGHT_ANTI_NA:
            nrows = jtbl1->rows * (1 - selectivity);
            break;
        default:
            return OG_ERROR;
    }

    jtable->rows = sql_adjust_est_row(nrows);
    return OG_SUCCESS;
}

static cbo_stats_column_t* sql_get_col_stat_from_restrict(join_assist_t *ja, cond_node_t *cond, bool8 is_left)
{
    cols_used_t cols_used;
    init_cols_used(&cols_used);
    if (is_left) {
        sql_collect_cols_in_expr_tree(cond->cmp->left, &cols_used);
    } else {
        sql_collect_cols_in_expr_tree(cond->cmp->right, &cols_used);
    }

    if (!HAS_SELF_COLS(cols_used.flags) || HAS_DIFF_TABS(&cols_used, SELF_IDX)) {
        return NULL;
    }
    
    expr_node_t *col_expr = sql_any_self_col_node(&cols_used);
    uint32 col_id = COL_OF_NODE(col_expr);
    uint32 table_id = TAB_OF_NODE(col_expr);
    sql_table_t *table_used = ja->pa->tables[table_id];
    if (table_used->type != NORMAL_TABLE || col_id == OG_INVALID_ID16) {
        return NULL;
    }
    dc_entity_t *entity = DC_ENTITY(&table_used->entry->dc);
    if (entity->cbo_table_stats == NULL || entity->cbo_table_stats->max_col_id < col_id) {
        return NULL;
    }
    return cbo_get_column_stats(entity->cbo_table_stats, col_id);
}

static double sql_estimate_bucket_size(join_assist_t *ja, cond_node_t *cond, bool8 is_left, uint64 num_nbuckets)
{
    // get col stat from cond: first get col id which was extracted from sql_extract_join_from_cond
    cbo_stats_column_t *col_stats = NULL;
    col_stats = sql_get_col_stat_from_restrict(ja, cond, is_left);
    if (col_stats == NULL) {
        return 1.0 / DEFAULT_NUM_DISTINCT;
    }

    double est_fract = 1.0;
    uint32 num_distinct = col_stats->num_distinct;
    if (num_nbuckets > 0 && num_distinct > num_nbuckets) {
        est_fract = 1.0 / num_nbuckets;
    } else if (num_distinct >= 1.0) {
        est_fract = 1.0 / num_distinct;
    }

    if (est_fract < DEFAULT_MIN_EST_FRACT) {
        est_fract = DEFAULT_MIN_EST_FRACT;
    } else if (est_fract >= 1.0) {
        est_fract = 1.0;
    }

    return est_fract;
}

static uint64 log2_of_ull(uint64 a)
{
    uint64 i = 0;
    uint64 step = 1;
    a = MIN(a, ULLONG_MAX / 2);
    for (; step < a; i++, step <<= 1) {
    }
    return i;
}

static status_t sql_calc_hash_nbuckets(int64 inner_rows, uint64* num_nbuckets)
{
    if (inner_rows <= 0) {
        inner_rows = DEFAULT_ESTIMATE_ROWS_COST;
    }

    double temp_nbuckets = 1ULL << log2_of_ull(inner_rows);
    uint64 req_nbuckets = (uint64)temp_nbuckets;
    req_nbuckets = MAX(req_nbuckets, MIN_HASH_BUCKET_SIZE);
    *num_nbuckets = req_nbuckets;
    return OG_SUCCESS;
}

status_t sql_initial_cost_hashjoin(join_assist_t *ja, sql_join_node_t* path,
    cbo_cost_t* cost_info, uint64* num_nbuckets)
{
    double startup_cost = 0;
    double run_cost = 0;

    sql_join_path_t *outer_path = path->left;
    sql_join_path_t *inner_path = path->right;

    sql_debug_join_cost_info(ja->stmt, path, "Hash", "initial start");

    startup_cost += outer_path->cost.startup_cost;
    run_cost += outer_path->cost.cost - outer_path->cost.startup_cost;
    startup_cost += inner_path->cost.cost;

    if (!g_instance->sql.enable_hash_join) {
        startup_cost += CBO_DEFAULT_DISABLE_COST;
    }

    double inner_rows = sql_adjust_est_row(inner_path->cost.card);
    double outer_rows = sql_adjust_est_row(outer_path->cost.card);
    startup_cost += (CBO_DEFAULT_CPU_OPERATOR_COST  + CBO_DEFAULT_CPU_SCAN_TUPLE_COST) * inner_rows;
    run_cost += CBO_DEFAULT_CPU_OPERATOR_COST * outer_rows * (double)(outer_rows / CBO_BHT_ROWS(1));

    OG_RETURN_IFERR(sql_calc_hash_nbuckets(inner_rows, num_nbuckets));

    cost_info->startup_cost = CBO_COST_SAFETY_RET(startup_cost);
    cost_info->cost = CBO_COST_SAFETY_RET(startup_cost + run_cost);
    path->cost.startup_cost = CBO_COST_SAFETY_RET(cost_info->startup_cost);
    path->cost.cost = CBO_COST_SAFETY_RET(cost_info->cost);

    sql_debug_join_cost_info(ja->stmt, path, "Hash", "initial end");
    return OG_SUCCESS;
}

// calc final cost, get the bucketsize of restrict info
void sql_final_cost_hashjoin(join_assist_t *ja, sql_join_node_t* path, cbo_cost_t* cost_info,
    galist_t *restricts, int16* ids, uint64 num_nbuckets, special_join_info_t *sjoininfo)
{
    sql_join_path_t *outer_path = path->left;
    sql_join_path_t *inner_path = path->right;
    if (outer_path->cost.card == 0 && inner_path->cost.card == 0) {
        return;
    }

    sql_debug_join_cost_info(ja->stmt, path, "Hash", "final start");

    double est_bucket_size = 1.0;
    uint32 i = 0;
    for (; i < restricts->count; i++) {
        double clause_bucket_size = 1.0;
        if (ids[i] == -1) {
            break;
        }

        tbl_join_info_t* tmp_jinfo = (tbl_join_info_t *)cm_galist_get(restricts, ids[i]);
        if (sql_bitmap_subset(&tmp_jinfo->table_ids_right, &inner_path->parent->table_ids)) {
            clause_bucket_size = sql_estimate_bucket_size(ja, tmp_jinfo->cond, false, num_nbuckets);
        } else if (sql_bitmap_subset(&tmp_jinfo->table_ids_left, &inner_path->parent->table_ids)) {
            clause_bucket_size = sql_estimate_bucket_size(ja, tmp_jinfo->cond, true, num_nbuckets);
        } else {
            // error
            OG_LOG_DEBUG_ERR("[PATH CREATE] restrictinfo rel doesn't belong to any jtable");
        }

        // there is no multi-column statistic, just get the minimum
        est_bucket_size = MIN(est_bucket_size, clause_bucket_size);
    }

    double outer_rows = sql_adjust_est_row(outer_path->cost.card);
    double inner_rows = sql_adjust_est_row(inner_path->cost.card);
    // adjust est_bucket_size again
    if (inner_rows != 0 && est_bucket_size * inner_rows < 1.0) {
        est_bucket_size = 1 / inner_rows;
    }

    est_bucket_size = MAX(est_bucket_size, DEFAULT_MIN_EST_FRACT);
    double hash_clause_cost = i * CBO_DEFAULT_CPU_OPERATOR_COST;
    if (path->type >= JOIN_TYPE_SEMI && path->type <= JOIN_TYPE_ANTI_NA) {
        double outer_matched_rows = rint(outer_rows * sjoininfo->semi_anti_factor.outer_match_frac);
        double inner_scan_frac = 2.0 / (sjoininfo->semi_anti_factor.match_count + 1.0);

        cost_info->cost += hash_clause_cost * outer_matched_rows *
            sql_adjust_est_row(est_bucket_size * inner_rows * inner_scan_frac) * 0.5;
        cost_info->cost += hash_clause_cost * sql_adjust_est_row(outer_rows - outer_matched_rows) *
            sql_adjust_est_row(inner_rows / num_nbuckets) * 0.05;
    } else if (path->type >= JOIN_TYPE_RIGHT_SEMI || path->type <= JOIN_TYPE_RIGHT_ANTI_NA) {
        double outer_matched_rows = rint(outer_rows * sjoininfo->semi_anti_factor.outer_match_frac);
        outer_matched_rows = MIN(outer_matched_rows, outer_rows);
        double inner_matched_rows = rint(inner_rows * sjoininfo->semi_anti_factor.r_semi_match_count);

        cost_info->cost += hash_clause_cost * sql_adjust_est_row(est_bucket_size * (inner_rows *
            outer_matched_rows - 0.5 * inner_matched_rows * (outer_matched_rows - 1)));
        cost_info->cost += hash_clause_cost * sql_adjust_est_row(outer_rows - outer_matched_rows) *
            sql_adjust_est_row((inner_rows - inner_matched_rows * 0.5) / num_nbuckets) * 0.05;
    } else {
        cost_info->cost += hash_clause_cost * outer_rows * sql_adjust_est_row(est_bucket_size * inner_rows) * 0.5;
    }

    path->cost.startup_cost = CBO_COST_SAFETY_RET(cost_info->startup_cost);
    path->cost.cost = CBO_COST_SAFETY_RET(cost_info->cost);

    sql_debug_join_cost_info(ja->stmt, path, "Hash", "final end");
}

/* check tables of used_cols if exist in outer_rels_list */
bool32 if_table_in_outer_rels_list(cols_used_t *used_cols, int idx, galist_t *outer_rels_list)
{
    biqueue_t *cols_que = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;
    expr_node_t *col = NULL;

    cols_que = &used_cols->cols_que[idx];
    curr = biqueue_first(cols_que);
    end = biqueue_end(cols_que);

    while (curr != end) {
        col = OBJECT_OF(expr_node_t, curr);
        uint32 table_id = TAB_OF_NODE(col);
        int rels_idx = ANCESTOR_OF_NODE(col);
        if (outer_rels_list->count < rels_idx || !sql_bitmap_exist_member(table_id,
            (join_tbl_bitmap_t*)cm_galist_get(outer_rels_list, rels_idx - 1))) {
            return OG_FALSE;
        }

        curr = curr->next;
    }

    return OG_TRUE;
}

static bool32 expr_contain_invisible_table_cols(plan_assist_t *pa, expr_tree_t *expr)
{
    cols_used_t used_cols;
    init_cols_used(&used_cols);
    sql_collect_cols_in_expr_tree(expr, &used_cols);

    if (pa->outer_rels_list != NULL) {
        OG_RETVALUE_IFTRUE(!if_table_in_outer_rels_list(&used_cols, PARENT_IDX, pa->outer_rels_list), OG_TRUE);
        OG_RETVALUE_IFTRUE(!if_table_in_outer_rels_list(&used_cols, ANCESTOR_IDX, pa->outer_rels_list), OG_TRUE);
    }

    return !biqueue_empty(&used_cols.cols_que[SELF_IDX]);
}

static bool32 match_cond_to_indexcol(plan_assist_t *pa, sql_table_t *table, cmp_node_t *cmp, uint16 index_col)
{
    sql_stmt_t *stmt = pa->stmt;
    knl_column_t *knl_col = knl_get_column(table->entry->dc.handle, index_col);
    expr_node_t col_node;
    expr_node_t *node = NULL;
    bool32 result = OG_FALSE;

    expr_tree_t *left = cmp->left;
    expr_tree_t *right = cmp->right;

    OGSQL_SAVE_STACK(stmt);
    RETVALUE_AND_RESTORE_STACK_IFERR(sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id, index_col),
        stmt, OG_FALSE);

    if (left == NULL || right == NULL) {
        if (sql_expr_node_matched(stmt, left != NULL ? left : right, node)) {
            result = OG_TRUE;
        }
        OGSQL_RESTORE_STACK(stmt);
        return result;
    }

    if (type_is_indexable_compatible(node->datatype, right->root->datatype) &&
        sql_expr_node_matched(stmt, left, node)) {
        if (!expr_contain_invisible_table_cols(pa, right)) {
            result = OG_TRUE;
        }
    }

    if (type_is_indexable_compatible(node->datatype, left->root->datatype) &&
        sql_expr_node_matched(stmt, right, node)) {
        if (!expr_contain_invisible_table_cols(pa, left)) {
            result = OG_TRUE;
        }
    }

    OGSQL_RESTORE_STACK(stmt);

    return result;
}

static void match_cond_to_index(plan_assist_t *pa, sql_table_t *table, index_t *index, cmp_node_t *cmp,
    galist_t **idx_cond_array, bool32 *has_matched)
{
    for (uint32 col_id = 0; col_id < index->desc.column_count; col_id++) {
        if (match_cond_to_indexcol(pa, table, cmp, index->desc.columns[col_id])) {
            cm_galist_insert(idx_cond_array[col_id], cmp);
            *has_matched = OG_TRUE;
            return;
        }
    }
}

static void match_conds_to_index(plan_assist_t *pa, sql_table_t *table, index_t *index, const cond_node_t *cond,
    galist_t **idx_cond_array, bool32 *has_matched)
{
    switch (cond->type) {
        case COND_NODE_COMPARE:
            match_cond_to_index(pa, table, index, cond->cmp, idx_cond_array, has_matched);
            break;
        case COND_NODE_AND:
            match_conds_to_index(pa, table, index, cond->left, idx_cond_array, has_matched);
            match_conds_to_index(pa, table, index, cond->right, idx_cond_array, has_matched);
            break;
        case COND_NODE_OR:
            /* OR cond can't be considered as index cond */
            break;
        default:
            break;
    }
}

static bool32 match_cond_to_table_col(plan_assist_t *pa, sql_table_t *table, cmp_node_t *cmp, uint32 column_count,
    uint32 *id)
{
    for (uint32 col_id = 0; col_id < column_count; col_id++) {
        if (match_cond_to_indexcol(pa, table, cmp, col_id)) {
            *id = col_id;
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static bool32 prefer_another_index_choice(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    cbo_index_choose_assist_t *ca, double cost)
{
    /* prefer unique index that all columns match to equal conds */
    if (INDEX_CONTAIN_UNIQUE_COLS(table->index, table->idx_equal_to) &&
        !INDEX_CONTAIN_UNIQUE_COLS(ca->index, ca->strict_equal_cnt)) {
        return OG_FALSE;
    }

    if (!INDEX_CONTAIN_UNIQUE_COLS(table->index, table->idx_equal_to) &&
        INDEX_CONTAIN_UNIQUE_COLS(ca->index, ca->strict_equal_cnt)) {
        return OG_TRUE;
    }

    double new_cost = cost;
    double old_cost = table->cost;
    /* consider subsequent order by/group by/distinct cost */
    if (pa->query->sort_items->count != 0) {
        new_cost += sql_sort_cost(stmt, pa, table, ca->scan_flag);
        old_cost += sql_sort_cost(stmt, pa, table, table->scan_flag);
    }

    if (pa->query->group_sets->count != 0) {
        new_cost += sql_group_cost(stmt, pa, table, ca->scan_flag);
        old_cost += sql_group_cost(stmt, pa, table, table->scan_flag);
    }

    if (pa->query->distinct_columns->count != 0) {
        new_cost += sql_distinct_cost(stmt, pa, table, ca->scan_flag);
        old_cost += sql_distinct_cost(stmt, pa, table, table->scan_flag);
    }

    if (cm_compare_double(old_cost, new_cost) == 1) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static void sql_make_col_ref_map(sql_stmt_t *stmt, expr_node_t *node, uint32 *col_ref_map)
{
    visit_assist_t va;
    sql_init_visit_assist(&va, stmt, NULL);
    va.param0 = (void *)col_ref_map;
    (void)visit_expr_node(&va, &node, sql_get_col_ref_count);
}

static bool32 if_column_in_index(uint16 col_id, knl_index_desc_t *index, uint16 column_count)
{
    for (uint16 i = 0; i < column_count; i++) {
        if (index->columns[i] == col_id) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t judge_func_index_only(sql_stmt_t *stmt, sql_table_t *table, knl_index_desc_t *index,
    bool32 *matched)
{
    bilist_node_t *node = cm_bilist_head(&table->func_expr);
    uint32 index_col;
    uint32 col_count = knl_get_column_count(table->entry->dc.handle);
    uint32 *col_ref_map;

    OG_RETURN_IFERR(sql_stack_alloc(stmt, col_count * sizeof(uint32), (void **)&col_ref_map));

    while (node != NULL) {
        func_expr_t *func_expr = BILIST_NODE_OF(func_expr_t, node, bilist_node);
        uint16 tab = OG_INVALID_ID16;
        uint32 ancestor = 0;
        OG_RETURN_IFERR(sql_get_expr_unique_table(stmt, func_expr->expr, &tab, &ancestor));
        if (sql_match_func_index_col(stmt, func_expr->expr, index, table, &index_col)) {
            if (ancestor > 0) {
                *matched = OG_FALSE;
                break;
            }
            sql_make_col_ref_map(stmt, func_expr->expr, col_ref_map);
        }
        node = node->next;
    }
    OG_RETSUC_IFTRUE(!(*matched));

    node = cm_bilist_head(&table->query_fields);
    while (node != NULL) {
        query_field_t *query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
        if (query_field->ref_count != col_ref_map[query_field->col_id] &&
            !if_column_in_index(query_field->col_id, index, (uint16)index->column_count)) {
            *matched = OG_FALSE;
            break;
        }
        node = node->next;
    }
    return OG_SUCCESS;
}

static bool32 check_can_func_index_only(plan_assist_t *pa, knl_index_desc_t *index, sql_table_t *table)
{
    if (!can_use_func_index_only(pa->query)) {
        return OG_FALSE;
    }

    bilist_node_t *node = cm_bilist_head(&table->query_fields);
    while (node != NULL) {
        query_field_t *query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
        if (!rbo_find_column_in_func_index(query_field, index, table)) {
            return OG_FALSE;
        }
        node = node->next;
    }

    bool32 matched = OG_TRUE;
    OGSQL_SAVE_STACK(pa->stmt);
    RETVALUE_AND_RESTORE_STACK_IFERR(judge_func_index_only(pa->stmt, table, index, &matched),
        pa->stmt, OG_FALSE);

    OGSQL_RESTORE_STACK(pa->stmt);
    return matched;
}

bool32 check_can_index_only(plan_assist_t *pa, sql_table_t *table, knl_index_desc_t *index)
{
    if (index->column_count < table->query_fields.count) {
        return OG_FALSE;
    }
    if (index->is_func) {
        return check_can_func_index_only(pa, index, table);
    }

    bilist_node_t *cur = NULL;
    query_field_t *field = NULL;
    join_tbl_bitmap_t fields_used;
    join_tbl_bitmap_t index_fields;

    sql_bitmap_init(&fields_used);
    sql_bitmap_init(&index_fields);

    cur = cm_bilist_head(&table->query_fields);
    while (cur != NULL) {
        field = BILIST_NODE_OF(query_field_t, cur, bilist_node);
        join_tbl_bitmap_t elem;
        sql_bitmap_make_singleton(field->col_id, &elem);
        sql_bitmap_union(&fields_used, &elem, &fields_used);
        cur = cur->next;
    }

    for (int i = 0; i < index->column_count; i++) {
        if (index->columns[i] >= DC_VIRTUAL_COL_START) {
            continue;
        }
        join_tbl_bitmap_t elem;
        sql_bitmap_make_singleton(index->columns[i], &elem);
        sql_bitmap_union(&index_fields, &elem, &index_fields);
    }

    return sql_bitmap_subset(&fields_used, &index_fields);
}

static void sql_clone_table_cond_tree(sql_stmt_t *stmt, sql_table_t *table)
{
    cond_tree_t *table_cond = NULL;
    OG_RETVOID_IFERR(sql_clone_cond_tree(stmt->context, table->cond, &table_cond, sql_alloc_mem));
    table->cond = table_cond;

    if (table->sub_tables != NULL) {
        for (uint32 i = 0; i < table->sub_tables->count; i++) {
            sql_table_t *sub_table = (sql_table_t *)cm_galist_get(table->sub_tables, i);
            if (sub_table->cond != NULL) {
                OG_RETVOID_IFERR(sql_clone_cond_tree(stmt->context, sub_table->cond, &table_cond, sql_alloc_mem));
                sub_table->cond = table_cond;
            }
        }
    }
}

static void split_to_and_or_conds(plan_assist_t *pa, sql_table_t *table, cond_node_t *cond, uint32 column_count,
    galist_t *and_conds, galist_t *and_conds_col, galist_t *or_conds)
{
    switch (cond->type) {
        case COND_NODE_COMPARE: {
            uint32 col_id;
            if (match_cond_to_table_col(pa, table, cond->cmp, column_count, &col_id)) {
                cm_galist_insert(and_conds, cond->cmp);

                uint32 *cond_col = NULL;
                OG_RETVOID_IFERR(sql_stack_alloc(pa->stmt, sizeof(uint32), (void **)&cond_col));
                *cond_col = col_id;
                cm_galist_insert(and_conds_col, cond_col);
            }
            break;
        }
        case COND_NODE_AND:
            split_to_and_or_conds(pa, table, cond->left, column_count, and_conds, and_conds_col, or_conds);
            split_to_and_or_conds(pa, table, cond->right, column_count, and_conds, and_conds_col, or_conds);
            break;
        case COND_NODE_OR:
            cm_galist_insert(or_conds, cond);
            break;
        default:
            break;
    }
}

static double compute_and_conds_ff(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table, cond_node_t *cond,
                                   cbo_stats_info_t* stats_info)
{
    sql_stmt_t *stmt = pa->stmt;
    galist_t *and_conds;
    galist_t *and_conds_col;
    galist_t *or_conds;
    double and_ff;
    double or_ff;

    OG_RETVALUE_IFTRUE(sql_stack_safe(stmt) != OG_SUCCESS, CBO_MAX_FF);

    OGSQL_SAVE_STACK(stmt);
    RETVALUE_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&and_conds),
        stmt, CBO_MAX_FF);
    cm_galist_init(and_conds, stmt, sql_stack_alloc);

    RETVALUE_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&and_conds_col),
        stmt, CBO_MAX_FF);
    cm_galist_init(and_conds_col, stmt, sql_stack_alloc);

    RETVALUE_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&or_conds),
        stmt, CBO_MAX_FF);
    cm_galist_init(or_conds, stmt, sql_stack_alloc);

    split_to_and_or_conds(pa, table, cond, entity->table.desc.column_count, and_conds, and_conds_col, or_conds);
    if (and_conds->count != and_conds_col->count) {
        OGSQL_RESTORE_STACK(stmt);
        return CBO_MAX_FF;
    }

    RETVALUE_AND_RESTORE_STACK_IFERR(compute_hist_factor_by_conds(stmt, entity,
        and_conds_col, and_conds, &and_ff, stats_info), stmt, CBO_MAX_FF);

    or_ff = compute_or_conds_ff(pa, entity, table, or_conds, stats_info);

    OGSQL_RESTORE_STACK(stmt);

    return and_ff * or_ff;
}

static double compute_or_conds_ff(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table, galist_t *or_conds,
                                  cbo_stats_info_t* stats_info)
{
    double ff = CBO_MAX_FF;
    for (uint32 count = 0; count < or_conds->count; count++) {
        cond_node_t *or_cond = cm_galist_get(or_conds, count);

        double f1 = compute_and_conds_ff(pa, entity, table, or_cond->left, stats_info);
        double f2 = compute_and_conds_ff(pa, entity, table, or_cond->right, stats_info);
        f1 = f1 + f2 - f1 * f2;

        ff = ff * f1;
    }
    return ff;
}

static bool32 match_index_equal_to_col(sql_stmt_t *stmt, sql_table_t *table, cbo_index_choose_assist_t *ca,
    expr_tree_t *expr, uint16 after_idx_equal_to)
{
    bool32 result = OG_FALSE;
    OGSQL_SAVE_STACK(stmt);
    for (uint32 idx = 0; idx < ca->strict_equal_cnt + after_idx_equal_to; idx++) {
        knl_column_t *knl_col = knl_get_column(table->entry->dc.handle, ca->index->columns[idx]);
        expr_node_t col_node;
        expr_node_t *node = NULL;

        RETVALUE_AND_RESTORE_STACK_IFERR(sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id,
            ca->index->columns[idx]), stmt, OG_FALSE);

        if (expr->root->type == EXPR_NODE_GROUP) {
            /* sort expr is the same as group expr */
            expr_node_t *group_node = (expr_node_t *)(VALUE_PTR(var_vm_col_t, &expr->root->value)->origin_ref);
            if (sql_expr_node_equal(stmt, group_node, node, NULL)) {
                result = OG_TRUE;
                break;
            }
        } else if (sql_expr_node_matched(stmt, expr, node)) {
            result = OG_TRUE;
            break;
        }
    }

    OGSQL_RESTORE_STACK(stmt);
    return result;
}

static bool32 match_index_after_equal_to_col(sql_stmt_t *stmt, sql_table_t *table, knl_index_desc_t *index,
    expr_tree_t *expr, uint32 idx_id)
{
    if (idx_id >= index->column_count) {
        return OG_FALSE;
    }
    bool32 result = OG_FALSE;
    knl_column_t *knl_col = knl_get_column(table->entry->dc.handle, index->columns[idx_id]);
    expr_node_t col_node;
    expr_node_t *node = NULL;

    OGSQL_SAVE_STACK(stmt);

    RETVALUE_AND_RESTORE_STACK_IFERR(sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id,
        index->columns[idx_id]), stmt, OG_FALSE);

    if (expr->root->type == EXPR_NODE_GROUP) {
        expr_node_t *group_node = (expr_node_t *)(VALUE_PTR(var_vm_col_t, &expr->root->value)->origin_ref);
        if (sql_expr_node_equal(stmt, group_node, node, NULL)) {
            result = OG_TRUE;
        }
    } else if (sql_expr_node_matched(stmt, expr, node)) {
        result = OG_TRUE;
    }

    OGSQL_RESTORE_STACK(stmt);
    return result;
}

static inline bool32 match_index_equal_to_rs_col(sql_table_t *table, cbo_index_choose_assist_t *ca,
    rs_column_t *rs_col, uint32 after_idx_equal_to)
{
    bool32 result = OG_FALSE;
    for (uint32 idx = 0; idx < ca->strict_equal_cnt + after_idx_equal_to; idx++) {
        if (rs_col->v_col.tab == table->id && rs_col->v_col.col == ca->index->columns[idx]) {
            result = OG_TRUE;
            break;
        }
    }
    return result;
}

static inline bool32 match_index_after_equal_to_rs_col(sql_table_t *table, knl_index_desc_t *index,
    rs_column_t *rs_col, uint32 idx_id)
{
    if (idx_id >= index->column_count) {
        return OG_FALSE;
    }

    if (rs_col->v_col.tab == table->id && rs_col->v_col.col == index->columns[idx_id]) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

/* determined if RBO_INDEX_SORT_FLAG can be set, and scan direction. */
static void determined_sort_flag(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cbo_index_choose_assist_t *ca)
{
    uint8 index_dsc = 0;
    sort_direction_t index_sort_dir = apply_hint_index_sort_scan_direction(table, ca->index);

    // In once condition which neither order by nor hint sort index were used, return strightly.
    // In twice condition which only hint sort index was used, return after set flag.
    if ((pa->sort_items == NULL || pa->sort_items->count == 0)) {
        if (TABLE_HAS_INDEX_SORT_HINT(table)) {
            index_dsc = (index_sort_dir == SORT_MODE_DESC);
            ca->scan_flag |= RBO_INDEX_SORT_FLAG;
            ca->index_dsc = index_dsc;
        }
        return;
    }

    galist_t *sort_items = pa->sort_items;
    uint32 pos = 0;

    /*
     * Determine whether each sorting column matches the leading columns that have equality
     * conditions,  or sequentially matches the columns that immediately follow. strict_equal_cnt
     * in ca indicates how many leading columns that have equality conditions. Otherwise, direction
     * and nulls_pos must be matched too.
     *
     * For example: table t1 has index(a,b,c), sql like: select * from t1 where a = 1 order by b;
     * the sorting column 'b' matches the index column that immediately follows column a which has
     * an equality condition. So flag can be set. And sql like: select * from t1 where a = 1 order by c;
     * is not OK.
     */
    uint32 after_idx_equal_to = 0;
    for (pos = 0; pos < sort_items->count; pos++) {
        sort_item_t *sort_item = (sort_item_t *)cm_galist_get(sort_items, pos);

        /*
         * hint sort conflict with sort_item, for example: index_asc(t0) and (order by column desc)
         * is conflict. so return strightly not to do sort. sort_dir = SORT_MODE_NONE indicates that
         * it have no index_asc or index_desc. so  no need to check confilct.
         */
        if (index_sort_dir != SORT_MODE_NONE && index_sort_dir != sort_item->direction) {
            return;
        }
        /* currently, index only support asc and nulls last */
        if (pos == 0) {
            index_dsc = sort_item->direction == SORT_MODE_DESC;
        } else if (index_dsc && sort_item->direction == SORT_MODE_ASC) {
            return;
        } else if (!index_dsc && sort_item->direction == SORT_MODE_DESC) {
            return;
        } else if (sort_item->nulls_pos == SORT_NULLS_FIRST) {
            return;
        }

        /* check if sort_item matches to 0..strict_equal_cnt + after_idx_equal_to - 1 of index columns */
        if (match_index_equal_to_col(stmt, table, ca, sort_item->expr, after_idx_equal_to)) {
            continue;
        }

        /* check if sort_item matches to strict_equal_cnt + after_idx_equal_to of index columns */
        if (!match_index_after_equal_to_col(stmt, table, ca->index, sort_item->expr,
                                            ca->strict_equal_cnt + after_idx_equal_to)) {
            return;
        }
        after_idx_equal_to++;
    }

    ca->scan_flag |= RBO_INDEX_SORT_FLAG;
    ca->index_dsc = index_dsc;
}

/* determined if RBO_INDEX_GROUP_FLAG can be set */
static void determined_group_flag(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    cbo_index_choose_assist_t *ca)
{
    if (pa->query->group_sets->count != 1) {
        return;
    }
    group_set_t *group_set = (group_set_t *)cm_galist_get(pa->query->group_sets, 0);
    uint32 pos;

    /* see determined_sort_flag. */
    uint32 after_idx_equal_to = 0;
    for (pos = 0; pos < group_set->count; pos++) {
        expr_tree_t *group_expr = (expr_tree_t *)cm_galist_get(group_set->items, pos);
        if (match_index_equal_to_col(stmt, table, ca, group_expr, after_idx_equal_to)) {
            continue;
        }

        if (!match_index_after_equal_to_col(stmt, table, ca->index, group_expr,
            ca->strict_equal_cnt + after_idx_equal_to)) {
            return;
        }
        after_idx_equal_to++;
    }

    ca->scan_flag |= RBO_INDEX_GROUP_FLAG;
}

/* determined if RBO_INDEX_DISTINCT_FLAG can be set */
static void determined_distinct_flag(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    cbo_index_choose_assist_t *ca)
{
    if (pa->query->distinct_columns->count == 0) {
        return;
    }
    galist_t *distinct_columns = pa->query->distinct_columns;
    uint32 pos;

    /* see determined_sort_flag */
    uint32 after_idx_equal_to = 0;
    for (pos = 0; pos < distinct_columns->count; pos++) {
        rs_column_t *distinct_column = (rs_column_t *)cm_galist_get(distinct_columns, pos);

        if (match_index_equal_to_rs_col(table, ca, distinct_column, after_idx_equal_to)) {
            continue;
        }

        if (!match_index_after_equal_to_rs_col(table, ca->index, distinct_column,
            ca->strict_equal_cnt + after_idx_equal_to)) {
            return;
        }
        after_idx_equal_to++;
    }

    ca->scan_flag |= RBO_INDEX_DISTINCT_FLAG;
}

bool32 prefer_table_scan(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, double seq_cost)
{
    if (INDEX_CONTAIN_UNIQUE_COLS(table->index, table->idx_equal_to)) {
        return OG_FALSE;
    }

    double new_cost = seq_cost;
    double old_cost = table->cost;
    /* consider subsequent sort cost */
    if (pa->query->sort_items->count != 0) {
        new_cost += sql_sort_cost(stmt, pa, table, 0);
        old_cost += sql_sort_cost(stmt, pa, table, table->scan_flag);
    }

    if (pa->query->group_sets->count != 0) {
        new_cost += sql_group_cost(stmt, pa, table, 0);
        old_cost += sql_group_cost(stmt, pa, table, table->scan_flag);
    }

    if (pa->query->distinct_columns->count != 0) {
        new_cost += sql_distinct_cost(stmt, pa, table, 0);
        old_cost += sql_distinct_cost(stmt, pa, table, table->scan_flag);
    }

    if (cm_compare_double(old_cost, new_cost) == 1) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static uint32 sql_get_max_subpart_by_part_no(knl_handle_t session, knl_dictionary_t* dc, uint32 part_no)
{
    table_t *table_dc = DC_TABLE(dc);
    table_part_t *table_part = TABLE_GET_PART(table_dc, part_no);
    uint32 max_rows = 0;
    uint32 max_row_subpart_no = 0;
    dc_entity_t *entity = DC_ENTITY(dc);

    for (uint32 sub_part_no = 0; sub_part_no < table_part->desc.subpart_cnt; sub_part_no++) {
        cbo_stats_table_t* cbo_stats_table = knl_get_cbo_subpart_table(session, entity, part_no, sub_part_no);
        if (cbo_stats_table->rows > max_rows) {
            max_rows = cbo_stats_table->rows;
            max_row_subpart_no = sub_part_no;
        }
    }
    return max_row_subpart_no;
}

static uint32 sql_get_subpart_by_part_no(sql_stmt_t *stmt, sql_table_cursor_t *table_cur,
    scan_part_range_type_t scan_subpart_type, uint32 part_no)
{
    if (scan_subpart_type == SCAN_PART_ANY || scan_subpart_type == SCAN_PART_UNKNOWN) {
        return sql_get_max_subpart_by_part_no(stmt->session, &table_cur->table->entry->dc, part_no);
    } else {
        return CBO_GLOBAL_SUBPART_NO;
    }
}

static void sql_init_part_info(sql_table_cursor_t *table_cur, uint32* parts, uint64* offset)
{
    do {
        for (uint32 part_no = table_cur->curr_part.left; part_no < table_cur->curr_part.right; part_no++) {
            if (*offset <= MAX_CBO_CALU_PARTS_COUNT) {
                parts[*offset] = part_no;
            }
            (*offset)++;
        }
    } while (sql_load_part_scan_key(table_cur));
}

static void sql_init_compart_part_info(sql_stmt_t *stmt, sql_table_cursor_t *table_cur, uint32* parts, uint32* subparts,
                                uint64* offset, scan_part_range_type_t scan_subpart_type)
{
    do {
        for (uint32 part_no = table_cur->curr_part.left; part_no < table_cur->curr_part.right; part_no++) {
            if (*offset <= MAX_CBO_CALU_PARTS_COUNT) {
                parts[*offset] = part_no;
                subparts[*offset] = sql_get_subpart_by_part_no(stmt, table_cur, scan_subpart_type, part_no);
            }
            (*offset)++;
        }
    } while (sql_load_part_scan_key(table_cur));
}

static void sql_init_subpart_info(sql_table_cursor_t *table_cur, uint32* parts, uint32* subparts, uint64* offset)
{
    for (uint32 part_no = table_cur->curr_part.left; part_no < table_cur->curr_part.right; part_no++) {
        for (uint32 subpart_no = table_cur->curr_subpart.left; subpart_no < table_cur->curr_subpart.right;
             subpart_no++) {
            if (*offset <= MAX_CBO_CALU_PARTS_COUNT) {
                parts[*offset] = part_no;
                subparts[*offset] = subpart_no;
            }
            (*offset)++;
        }
    }
}

static status_t sql_create_temp_scan_plan(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    scan_plan_t** scan_plan)
{
    sql_array_t partition_array;
    sql_array_t subpartition_array;

    OG_RETURN_IFERR(sql_create_part_scan_ranges(stmt, pa, table, &partition_array));
    if (knl_is_compart_table(table->entry->dc.handle)) {
        OG_RETURN_IFERR(sql_create_subpart_scan_ranges(stmt, pa, table, &subpartition_array));
    }

    if (sql_alloc_mem(stmt->context, sizeof(scan_plan_t), (void **)scan_plan) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*scan_plan)->table = table;
    (*scan_plan)->part_array = partition_array;
    (*scan_plan)->subpart_array = subpartition_array;
    return OG_SUCCESS;
}


static status_t sql_init_scan_part_info(sql_stmt_t *stmt, sql_table_t *table)
{
    if (sql_alloc_mem(stmt->context, sizeof(scan_part_info_t), (void **)&table->scan_part_info) != OG_SUCCESS) {
        return OG_ERROR;
    }
    
    if (sql_alloc_mem(stmt->context, sizeof(uint32) * MAX_CBO_CALU_PARTS_COUNT,
        (void **)&table->scan_part_info->part_no) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_alloc_mem(stmt->context, sizeof(uint32) * MAX_CBO_CALU_PARTS_COUNT,
        (void **)&table->scan_part_info->subpart_no) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static scan_part_range_type_t sql_scan_flags_to_scan_type(uint32 part_arrays_flags)
{
    if (part_arrays_flags == 0) {
        return SCAN_PART_SPECIFIED;
    }
    if (part_arrays_flags & LIST_EXIST_LIST_UNKNOWN) {
        return SCAN_PART_UNKNOWN;
    }
    if (part_arrays_flags & LIST_EXIST_LIST_ANY) {
        return SCAN_PART_ANY;
    }
    if (part_arrays_flags & LIST_EXIST_LIST_FULL) {
        return SCAN_PART_FULL;
    }
    if (part_arrays_flags & LIST_EXIST_LIST_EMPTY) {
        return SCAN_PART_EMPTY;
    }
    return SCAN_PART_SPECIFIED;
}

static void build_part_scan_info_by_table_cursor(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t* table_cur,
                                                                    scan_part_flags_t scan_part_flags)
{
    table->scan_part_info->scan_type = sql_scan_flags_to_scan_type(scan_part_flags.scan_part_flags);

    if (PART_TABLE_ANY_SINGLE_SCAN(table) || PART_TABLE_UNKNOWN_SCAN(table)) {
        table->scan_part_info->part_cnt = 1;
        if (knl_is_compart_table(table->entry->dc.handle)) {
            table->scan_part_info->part_no[0] = knl_get_max_rows_subpart(DC_ENTITY(&(table->entry->dc))).part_no;
            table->scan_part_info->subpart_no[0] = knl_get_max_rows_subpart(DC_ENTITY(&(table->entry->dc))).subpart_no;
        } else {
            table->scan_part_info->part_no[0] = knl_get_max_rows_part(DC_ENTITY(&(table->entry->dc)));
            table->scan_part_info->subpart_no[0] = CBO_GLOBAL_SUBPART_NO;
        }
    } else if (PART_TABLE_FULL_SCAN(table)) {
        table->scan_part_info->part_cnt = 1;
        table->scan_part_info->part_no[0] = CBO_GLOBAL_PART_NO;
        table->scan_part_info->subpart_no[0] = CBO_GLOBAL_SUBPART_NO;
    } else if (PART_TABLE_EMPTY_SCAN(table)) {
        table->scan_part_info->part_cnt = 0;
    } else {
        if (!can_print_subpart_no(table_cur)) {
            if (knl_is_compart_table(table->entry->dc.handle)) {
                scan_part_range_type_t subpart_type = sql_scan_flags_to_scan_type(scan_part_flags.scan_subpart_flags);
                sql_init_compart_part_info(stmt, table_cur, table->scan_part_info->part_no,
                    table->scan_part_info->subpart_no,
                    &table->scan_part_info->part_cnt, subpart_type);
            } else {
                sql_init_part_info(table_cur, table->scan_part_info->part_no, &table->scan_part_info->part_cnt);
            }
        } else {
            sql_init_subpart_info(table_cur, table->scan_part_info->part_no, table->scan_part_info->subpart_no,
                                  &table->scan_part_info->part_cnt);
        }
    }
}

status_t sql_init_table_scan_partition_info(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table)
{
    knl_dictionary_t *dc = &table->entry->dc;
    if (!knl_is_part_table(dc->handle)) {
        return OG_SUCCESS;
    }

    OGSQL_SAVE_STACK(stmt);

    sql_table_cursor_t table_cur;
    scan_plan_t *scan_plan;
    RET_AND_RESTORE_STACK_IFERR(sql_create_temp_scan_plan(stmt, pa, table, &scan_plan), stmt);

    do {
        table_cur.table = table;
        table->scan_part_info = NULL;
        table_cur.part_set.key_data = NULL;
        scan_part_flags_t scan_part_flags = {
            .scan_part_flags = 0,
            .scan_subpart_flags = 0
        };
        vmc_init(&stmt->session->vmp, &table_cur.vmc);
        RET_AND_RESTORE_STACK_IFERR(sql_init_scan_part_info(stmt, table), stmt);

        if (sql_make_part_scan_keys(stmt, scan_plan, &table_cur, NULL, CALC_IN_PLAN, CALC_IN_PLAN,
                                    &scan_part_flags)!= OG_SUCCESS) {
            table->scan_part_info->part_cnt = 1;
            table->scan_part_info->part_no[0] = CBO_GLOBAL_PART_NO;
            table->scan_part_info->subpart_no[0] = CBO_GLOBAL_SUBPART_NO;
            break;
        }

        if (table_cur.part_set.type == KEY_SET_EMPTY) {
            table->scan_part_info->part_cnt = 0;
            table->scan_part_info->subpart_no = 0;
            break;
        }

        build_part_scan_info_by_table_cursor(stmt, table, &table_cur, scan_part_flags);
    } while (OG_FALSE);

    OGSQL_RESTORE_STACK(stmt);
    vmc_free(&table_cur.vmc);
    return OG_SUCCESS;
}

static bool32 cbo_check_use_index_ffs(plan_assist_t * pa, sql_table_t *table, knl_index_desc_t *index, uint32 scan_flag)
{
    if (pa->query->connect_by_cond != NULL) {
        return OG_FALSE;
    }
    
    /* no index only is conflict with ffs */
    if (!INDEX_ONLY_SCAN(scan_flag)) {
        return OG_FALSE;
    }

    /* sort(no index sort) is not with ffs */
    if (pa->sort_items != NULL && pa->sort_items->count > 0 && !CAN_INDEX_SORT(scan_flag)) {
        return OG_TRUE;
    }
    
    /* with multi_index no conflict */
    if (CBO_INDEX_HAS_FLAG(pa, USE_MULTI_INDEX)) {
        return OG_TRUE;
    }

    return OG_TRUE;
}

static void cbo_try_choose_fast_full_scan_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, index_t *index,
    uint16 scan_flag, bool32 index_dsc)
{
    if (!cbo_check_use_index_ffs(pa, table, &index->desc, scan_flag)) {
        return;
    }

    cbo_index_choose_assist_t ca = {
        .index = &index->desc,
        .strict_equal_cnt = 0,
        .match_mode = COLUMN_MATCH_1_BORDER_RANGE,
        .scan_flag = scan_flag & RBO_INDEX_ONLY_FLAG,
        .index_full_scan = OG_TRUE,
        .index_ffs = OG_TRUE
    };
    
    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    double cost_ffs = 0.0;
    bool32 matched = false;
    
    OGSQL_SAVE_STACK(stmt);
    galist_t *idx_cond_array[OG_MAX_INDEX_COLUMNS];
    RETVOID_AND_RESTORE_STACK_IFERR(init_idx_cond_array(stmt, idx_cond_array), stmt);

    /* collect conditions matched to index, except OR conds */
    if (pa->cond != NULL) {
        match_conds_to_index(pa, table, index, pa->cond->root, idx_cond_array, &matched);
    }

    cost_ffs = sql_estimate_index_scan_cost(stmt, &ca, entity, index, idx_cond_array, NULL, table);

    OGSQL_RESTORE_STACK(stmt);

    /* Besides a lower cost, we prefer index scan containing unqiue. */
    if (table->index == NULL || prefer_another_index_choice(stmt, pa, table, &ca, cost_ffs)
        || HAS_SPEC_TYPE_HINT(table->hint_info, INDEX_HINT, HINT_KEY_WORD_INDEX_FFS)) {
        table->cost = cost_ffs;
        table->index = &index->desc;
        table->scan_flag = ca.scan_flag;
        table->scan_mode = SCAN_MODE_INDEX;
        table->index_full_scan = ca.index_full_scan;
        table->idx_equal_to = ca.strict_equal_cnt;
        table->index_dsc = ca.index_dsc;
        table->index_ffs = ca.index_ffs;
        table->index_skip_scan = get_table_skip_index_flag(table, ca.index->id);
    }
}

void cbo_try_choose_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, index_t *index)
{
    cbo_index_choose_assist_t ca = {
        .index = &index->desc,
        .strict_equal_cnt = 0,
        .startup_cost = 0.0
    };

    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    double cost = 0.0;
    double startup_cost = 0.0;
    bool32 matched = false;

    OGSQL_SAVE_STACK(stmt);
    galist_t *idx_cond_array[OG_MAX_INDEX_COLUMNS];
    RETVOID_AND_RESTORE_STACK_IFERR(init_idx_cond_array(stmt, idx_cond_array), stmt);

    /* collect conditions matched to index, except OR conds */
    if (pa->cond != NULL) {
        match_conds_to_index(pa, table, index, pa->cond->root, idx_cond_array, &matched);
    }

    if (check_can_index_only(pa, table, &index->desc)) {
        ca.scan_flag |= RBO_INDEX_ONLY_FLAG;
    }

    cost = sql_estimate_index_scan_cost(stmt, &ca, entity, index, idx_cond_array, NULL, table);
    startup_cost = ca.startup_cost;

    OGSQL_RESTORE_STACK(stmt);

    /* Determined scan flag. It must be called after sql_index_sacn_cost, because it needs strict_equal_cnt */
    determined_sort_flag(stmt, pa, table, &ca);
    determined_group_flag(stmt, pa, table, &ca);
    determined_distinct_flag(stmt, pa, table, &ca);

    if (!matched && !CAN_INDEX_SORT(ca.scan_flag) && !INDEX_ONLY_SCAN(ca.scan_flag) &&
        !CAN_INDEX_GROUP(ca.scan_flag) && !CAN_INDEX_DISTINCT(ca.scan_flag)) {
        return;
    }

    sql_debug_scan_cost_info(stmt, table, "INDEX", &ca, cost, NULL, NULL);

    /* Besides a lower cost, we prefer index scan containing unqiue. */
    if (table->index == NULL || prefer_another_index_choice(stmt, pa, table, &ca, cost)) {
        table->cost = cost;
        table->startup_cost = startup_cost;
        table->index = &index->desc;
        table->scan_flag = ca.scan_flag;
        table->scan_mode = SCAN_MODE_INDEX;
        table->index_full_scan = ca.index_full_scan;
        table->idx_equal_to = ca.strict_equal_cnt;
        table->index_dsc = ca.index_dsc;
        table->index_skip_scan = get_table_skip_index_flag(table, ca.index->id);
    }

    if ((ca.index_full_scan = true && INDEX_ONLY_SCAN_ONLY(ca.scan_flag)) || ca.index_full_scan == false) {
        /* compare with ffs */
        cbo_try_choose_fast_full_scan_index(stmt, pa, table, index, ca.scan_flag, table->index_dsc);
    }
}

static void cbo_try_choose_multi_index_internal(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table,
    cond_tree_t *and, cond_node_t *sub_or_cond)
{
    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    cond_node_t *save_cond = pa->cond->root;
    cond_node_t *cond = NULL;

    /* try choose index with AND conds and one-side of OR-condition if any */
    if (and != NULL) {
        OG_RETVOID_IFERR(sql_stack_alloc(stmt, sizeof(cond_node_t), (void **)&cond));
        cond->type = COND_NODE_AND;
        cond->left = and->root;
        cond->right = sub_or_cond;
    } else {
        cond = sub_or_cond;
    }
    pa->cond->root = cond;

    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        index_t *index = DC_TABLE_INDEX(&entity->table, idx_id);
        cbo_try_choose_index(stmt, pa, table, index);
    }

    /* process sub-or conditions, but only consider same index */
    cbo_try_choose_multi_index(stmt, pa, table, true);
    OG_RETVOID_IFERR(sql_stack_alloc(stmt, sizeof(cond_tree_t), (void **)&table->cond));
    sql_init_cond_tree(stmt, table->cond, sql_stack_alloc);
    table->cond->root = cond;
    pa->cond->root = save_cond;
}

static inline status_t sql_add_sub_table(sql_stmt_t *stmt, galist_t *sub_tables, sql_table_t *table, cond_node_t *cond)
{
    sql_table_t *element = NULL;

    OG_RETURN_IFERR(cm_galist_new(sub_tables, sizeof(sql_table_t), (void **)&element));
    *element = *table;
    element->is_sub_table = OG_TRUE;

    if (INDEX_ONLY_SCAN(element->scan_flag)) {
        OG_RETURN_IFERR(sql_make_index_col_map(NULL, stmt, element));
    }
    return sql_union_cond_node(stmt->context, (cond_tree_t **)&element->cond, cond);
}

static inline status_t sql_collect_or_cond(sql_stmt_t *stmt, cond_node_t *src_cond, cond_tree_t **and_cond,
    galist_t *or_list)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    switch (src_cond->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_collect_or_cond(stmt, src_cond->left, and_cond, or_list));
            return sql_collect_or_cond(stmt, src_cond->right, and_cond, or_list);

        case COND_NODE_OR:
            return cm_galist_insert(or_list, src_cond);

        case COND_NODE_COMPARE:
            if (*and_cond == NULL) {
                OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(cond_tree_t), (void **)and_cond));
                sql_init_cond_tree(stmt, *and_cond, sql_stack_alloc);
            }
            return sql_merge_cond_tree_shallow(*and_cond, src_cond);

        default:
            return OG_SUCCESS;
    }
}

static inline status_t sql_try_add_sub_table(sql_stmt_t *stmt, sql_table_t *parent, sql_table_t *sub_table,
    cond_node_t *cond)
{
    if (sub_table->index->id == parent->index->id) {
        return sql_union_cond_node(stmt->context, (cond_tree_t **)&parent->cond, cond);
    }

    if (parent->sub_tables == NULL) {
        OG_RETURN_IFERR(sql_create_list(stmt, &parent->sub_tables));
        return sql_add_sub_table(stmt, parent->sub_tables, sub_table, cond);
    }

    for (uint32 i = 0; i < parent->sub_tables->count; i++) {
        sql_table_t *element = (sql_table_t *)cm_galist_get(parent->sub_tables, i);
        if (element->index->id == sub_table->index->id) {
            return sql_union_cond_node(stmt->context, (cond_tree_t **)&element->cond, cond);
        }
    }
    return sql_add_sub_table(stmt, parent->sub_tables, sub_table, cond);
}

void cbo_try_choose_multi_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, bool only_same_index)
{
    if (pa->cond == NULL) {
        return;
    }
    cond_tree_t *and_cond = NULL;
    galist_t *or_list = NULL;
    bool32 updated = OG_FALSE;

    OGSQL_SAVE_STACK(stmt);
    RETVOID_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&or_list), stmt);
    cm_galist_init(or_list, stmt, sql_stack_alloc);

    RETVOID_AND_RESTORE_STACK_IFERR(sql_collect_or_cond(stmt, pa->cond->root, &and_cond, or_list), stmt);

    for (uint32 i = 0; i < or_list->count; i++) {
        cond_node_t *or_cond = (cond_node_t*)cm_galist_get(or_list, i);
        sql_table_t *left_table = NULL;
        sql_table_t *right_table = NULL;

        RETVOID_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(sql_table_t), (void **)&left_table), stmt);
        sql_init_table_indexable(left_table, table);
        cbo_try_choose_multi_index_internal(stmt, pa, left_table, and_cond, or_cond->left);
        /* continue if choose table full access */
        if (left_table->index == NULL) {
            continue;
        }

        RETVOID_AND_RESTORE_STACK_IFERR(sql_stack_alloc(stmt, sizeof(sql_table_t), (void **)&right_table), stmt);
        sql_init_table_indexable(right_table, table);
        cbo_try_choose_multi_index_internal(stmt, pa, right_table, and_cond, or_cond->right);
        if (right_table->index == NULL) {
            continue;
        }

        if ((left_table->index->id != right_table->index->id) && only_same_index) {
            continue;
        }

        right_table->cond = NULL;
        RETVOID_AND_RESTORE_STACK_IFERR(sql_try_add_sub_table(stmt, left_table, right_table, or_cond->right), stmt);
        /*
         * Calculate the total cost, including the costs of accessing left/right child tables
         * and the concatenate operation.
         */
        if (left_table->sub_tables != NULL) {
            left_table->cost += right_table->cost + table->card *
                (CBO_DEFAULT_CPU_HASH_BUILD_COST + CBO_DEFAULT_CPU_HASH_CALC_COST);
        }

        if (table->cost > left_table->cost) {
            table->scan_info = left_table->scan_info;
            updated = OG_TRUE;
        }
    }

    if (updated && table->cond != NULL) {
        sql_clone_table_cond_tree(stmt, table);
    }

    OGSQL_RESTORE_STACK(stmt);
}

static inline sort_direction_t apply_hint_index_sort_scan_direction(sql_table_t *table, knl_index_desc_t *index)
{
    return SORT_MODE_NONE;
}

#ifdef __cplusplus
}
#endif
