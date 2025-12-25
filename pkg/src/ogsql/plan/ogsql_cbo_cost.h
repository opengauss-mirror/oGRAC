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
 * ogsql_cbo_cost.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/ogsql_cbo_cost.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OGSQL_CBO_COST_H__
#define __OGSQL_CBO_COST_H__

#include "dml_parser.h"
#include "ostat_load.h"
#include "plan_range.h"
#include "plan_rbo.h"
#include "cbo_base.h"
#include "cbo_join.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CBO_DEFAULT_EQ_FF 0.005
#define CBO_DEFAULT_INEQ_FF 0.3333333333333333
#define CBO_DEFAULT_DISABLE_COST (double)(1.0e10)

#define DEFAULT_CPU_INDEX_TUP_COST (0.005)
#define DEFAULT_CPU_HASH_COST (0.02)
#define DEFAULT_ESTIMATE_ROWS_COST (1000)
#define DEFAULT_NUM_DISTINCT (200)
#define DEFAULT_MIN_EST_FRACT (1.0e-7)
#define DEFAULT_MULTI_COL_FRACT (0.75)
#define MAX_HASH_BUCKET_SIZE (uint32)16777216 // 1<<24
#define MIN_HASH_BUCKET_SIZE (uint32)16384    // 1<<14
#define HASH_FILL_FACTOR (float)0.75
#define HASH_BUCKET_NODE_SIZE (uint32)(sizeof(hash_entry_t))

#define CBO_PALN_SAFETY_SET(plan)                                \
do {                                                             \
    plan->rows = CBO_CARD_SAFETY_SET(plan->rows);                \
    plan->cost = CBO_COST_SAFETY_RET(plan->cost);                \
    plan->start_cost = CBO_COST_SAFETY_RET(plan->start_cost);    \
} while (0)
#define INDEX_CONTAIN_UNIQUE_COLS(index, idx_equal_to) (IS_INDEX_UNIQUE(index) && index->column_count == idx_equal_to)

// return expect if ret == expect
#define CBO_RETURN_IF_RES(ret, expect) \
    do {                               \
        if ((ret) == (expect)) {       \
            return (expect);           \
        }                              \
    } while (0)

#define COND_IS_FILTER 0x01
#define COND_IS_JOIN_COND 0x02
#define COND_IS_OUTER_DELAYED 0x04
#define COND_HAS_OUTER_RELS 0x08
#define COND_HAS_DYNAMIC_SUBSEL 0x10
#define COND_HAS_ROWNUM 0x20

typedef struct st_join_cost_workspace {
    /* Preliminary cost estimates --- must not be larger than final ones! */
    double startup_cost; /* cost expended before fetching any tuples */
    double total_cost;   /* total cost (assuming all tuples fetched) */

    /* Fields below here should be treated as private to costsize.c */
    double run_cost; /* non-startup cost components */

    /* private for cost_nestloop code */
    double inner_rescan_run_cost;
    double outer_matched_rows;
    double inner_scan_frac;

    /* private for cost_mergejoin code */
    double inner_run_cost;
    double outer_rows;
    double inner_rows;
    double outer_skip_rows;
    double inner_skip_rows;

    /* private for cost_hashjoin code */
    int num_buckets;
    int num_batches;

    /* private for cost_asofjoin code */
    double inner_distinct_num;
    double outer_distinct_num;
} join_cost_workspace;

typedef struct st_cbo_stats_info {
    scan_part_range_type_t scan_type;

    /* stats for table */
    uint32 table_partition_no;
    uint32 table_subpartition_no;
    cbo_stats_table_t* cbo_table_stats;

    /* stats for index */
    uint32 index_id;
    uint32 index_partition_no;
    uint32 index_subpartition_no;
    cbo_stats_index_t* cbo_index_stats;
} cbo_stats_info_t;

typedef struct range_query_cond {
    struct range_query_cond *next; /* next in linked list */
    expr_tree_t *column;         /* The common variable of the conds */
    bool have_lobound;           /* found a low-bound cond yet? */
    bool have_hibound;           /* found a high-bound cond yet? */
    double lobound;              /* ff of a var > something cond */
    double hibound;              /* ff of a var < something cond */
} range_query_cond;

// //////////////////////////////////////////////////////////////////////////////////////
// function interface
void og_get_query_cbo_cost(sql_query_t *query, cbo_cost_t *cost);

double sql_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity, index_t *index,
    galist_t **idx_cond_array, int64 *card, cbo_stats_info_t* stats_info);
status_t compute_hist_factor_by_conds(sql_stmt_t *stmt, dc_entity_t *entity, galist_t *cond_cols,
    galist_t *conds, double *ff, cbo_stats_info_t* stats_info);
double sql_seq_scan_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table);
double sql_sort_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, uint16 scan_flag);
double sql_group_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, uint16 scan_flag);
double sql_distinct_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, uint16 scan_flag);

status_t sql_cal_table_or_partition_stats(dc_entity_t *entity, sql_table_t *table,
                                               cbo_stats_info_t* stats_info, knl_handle_t session);

double sql_estimate_subpartition_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table);

double sql_estimate_partition_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table);

double sql_estimate_nopartition_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table);

double sql_estimate_index_scan_cost(sql_stmt_t *stmt, cbo_index_choose_assist_t *ca, dc_entity_t *entity,
    index_t *index, galist_t **idx_cond_array, int64 *card, sql_table_t *table);

int64 sql_estimate_subpartitioned_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond);

int64 sql_estimate_partitioned_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond);

int64 sql_estimate_nopartitioned_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table,
    cond_tree_t *cond);

int64 sql_estimate_table_card(plan_assist_t *pa, dc_entity_t *entity, sql_table_t *table, cond_tree_t *cond);

double sql_seq_scan_subpartitioned_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table);

double sql_seq_scan_partitioned_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table);

double sql_seq_scan_nopartitioned_cost(sql_stmt_t *stmt, dc_entity_t *entity, sql_table_t *table);

typedef struct st_ff_calc_ass {
    double left_nulls;
    double right_nulls;
    uint32 left_distinct;
    uint32 right_distinct;
    uint32 left_total_rows;
    uint32 right_total_rows;
    bool is_left_default;
    bool is_right_default;
} ff_calc_ass_t;

typedef struct st_cond_info {
    uint32 l_table;
    uint32 l_col;
    uint32 r_table;
    uint32 r_col;
    bool used;
} cond_info_t;

status_t sql_initial_cost_nestloop(join_assist_t *ja, sql_join_node_t* join_tree, join_cost_workspace* join_cost_ws,
    special_join_info_t *sjoininfo);
status_t sql_final_cost_nestloop(join_assist_t *ja, sql_join_node_t* join_tree, join_cost_workspace* join_cost_ws,
    special_join_info_t *sjoininfo);
void sql_init_sql_join_node_cost(sql_join_node_t* join_tree);
status_t sql_estimate_node_cost(sql_stmt_t *stmt, plan_node_t *plan);
double sql_compute_join_factor(join_assist_t *ja, galist_t* conds, special_join_info_t *sjinfo);
void sql_debug_scan_cost_info(sql_stmt_t *stmt, sql_table_t *table, char *extra_info, cbo_index_choose_assist_t *ca,
    double cost, join_assist_t *ja, join_tbl_bitmap_t *outer_rels);
bool32 if_table_in_outer_rels_list(cols_used_t *used_cols, int idx, galist_t *outer_rels_list);
void sql_final_cost_hashjoin(join_assist_t *ja, sql_join_node_t* path, cbo_cost_t* cost_info,
    galist_t *restricts, int16* ids, uint64 num_nbuckets, special_join_info_t *sjoininfo);
status_t sql_initial_cost_hashjoin(join_assist_t *ja, sql_join_node_t* path,
    cbo_cost_t* cost_info, uint64* num_nbuckets);
status_t sql_jtable_estimate_size(join_assist_t *ja, sql_join_table_t *jtable, sql_join_table_t *jtbl1,
    sql_join_table_t *jtbl2, special_join_info_t *sjoininfo, galist_t* restricts);
bool32 check_can_index_only(plan_assist_t *pa, sql_table_t *table, knl_index_desc_t *index);
void cbo_try_choose_multi_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, bool only_same_index);
bool32 prefer_table_scan(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, double seq_cost);
status_t sql_init_table_scan_partition_info(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table);
void cbo_try_choose_index(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, index_t *index);

typedef status_t (*sql_estimate_node_cost_funcs_t)(sql_stmt_t *stmt, plan_node_t *plan);
    
typedef struct st_sql_estimate_node_cost_funcs {
    plan_node_type_t type;
    sql_estimate_node_cost_funcs_t estimate_node_cost_funcs;
} sql_estimate_node_cost_funcs;

static inline status_t init_idx_cond_array(sql_stmt_t *stmt, galist_t **idx_cond_array)
{
    for (int i = 0; i < OG_MAX_INDEX_COLUMNS; i++) {
        OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&idx_cond_array[i]));
        cm_galist_init(idx_cond_array[i], stmt, sql_stack_alloc);
    }

    return OG_SUCCESS;
}

static inline status_t init_stats_info(cbo_stats_info_t* stats_info, scan_part_range_type_t scan_type,
                                   uint32 table_partition_no, uint32 table_subpartition_no,
                                   uint32 index_id, uint32 index_partition_no, uint32 index_subpartition_no)
{
    MEMS_RETURN_IFERR(memset_sp(stats_info, sizeof(cbo_stats_info_t), 0, sizeof(cbo_stats_info_t)));
    stats_info->scan_type = scan_type;
    stats_info->table_partition_no = table_partition_no;
    stats_info->table_subpartition_no = table_subpartition_no;
    stats_info->index_id = index_id;
    stats_info->index_partition_no = index_partition_no;
    stats_info->index_subpartition_no = index_subpartition_no;
    stats_info->cbo_table_stats = NULL;
    stats_info->cbo_index_stats = NULL;
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif
