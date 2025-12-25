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
 * ogsql_join_path.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/ogsql_join_path.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OGSQL_JOIN_PATH_H__
#define __OGSQL_JOIN_PATH_H__

#include "ogsql_context.h"

#define JOINTBL_HASH_INIT_SIZE 1024
#define THRESHOLD_JOINTBL_LIST 32 /* Switch to hash table to accelerate join tbl query when exceeding this threshold. */

// return MAX ROWS if error occurs
#define OG_RETURN_MAX_ROWS_IFERR(ret)                            \
    do {                                                \
        status_t _status_ = (ret);                      \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) { \
            cm_set_error_pos(__FILE__, __LINE__);       \
            return CBO_MAX_ROWS;                            \
        }                                               \
    } while (0)

// return MAX COST if error occurs
#define OG_RETURN_MAX_COST_IFERR(ret)                            \
    do {                                                \
        status_t _status_ = (ret);                      \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) { \
            cm_set_error_pos(__FILE__, __LINE__);       \
            return CBO_MAX_COST;                            \
        }                                               \
    } while (0)

// return MAX COST if true
#define OG_RETURN_MAX_COST_IFTRUE(cond) \
    if (cond) {                 \
        return CBO_MAX_COST;                 \
    }

// return value and restore stack if error occurs
#define RETVALUE_AND_RESTORE_STACK_IFERR(ret, stmt, value)                  \
    do {                                                                    \
        status_t _status_ = (ret);                                          \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) {                     \
            cm_set_error_pos(__FILE__, __LINE__);                           \
            OGSQL_RESTORE_STACK(stmt);                                      \
            return (value);                                                 \
        }                                                                   \
    } while (0)

// return and restore stack if error occurs
#define RET_AND_RESTORE_STACK_IFERR(ret, stmt)                              \
    do {                                                                    \
        status_t _status_ = (ret);                                          \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) {                     \
            cm_set_error_pos(__FILE__, __LINE__);                           \
            OGSQL_RESTORE_STACK(stmt);                                      \
            return _status_;                                                \
        }                                                                   \
    } while (0)

// return out and restore stack if error occurs
#define RETVOID_AND_RESTORE_STACK_IFERR(ret, stmt)                          \
    do {                                                                    \
        status_t _status_ = (ret);                                          \
        if (SECUREC_UNLIKELY(_status_ != OG_SUCCESS)) {                     \
            cm_set_error_pos(__FILE__, __LINE__);                           \
            OGSQL_RESTORE_STACK(stmt);                                      \
            return;                                                         \
        }                                                                   \
    } while (0)

#define JOIN_TABLE_NAME_MAX_LEN 512

typedef sql_join_node_t sql_join_path_t;
// 基本等价于 RestrictInfo
// 定义的变量名建议简写为 jinfo
typedef struct st_tbl_join_info {
    join_tbl_bitmap_t table_ids; // bitmap of table ids
    join_tbl_bitmap_t table_ids_left;
    join_tbl_bitmap_t table_ids_right;
    join_tbl_bitmap_t* outer_tableids;
    join_tbl_bitmap_t* nullable_tableids;
    cond_node_t* cond;
    uint8 jinfo_flag;
} tbl_join_info_t;

typedef struct st_semi_anti_factor {
    double outer_match_frac;
    double match_count;
    double r_semi_match_count;
} semi_anti_fac_t;

// 基本等价于 SpecialJoinInfo
// 定义的变量名建议简写为 sjinfo、sjoininfo
typedef struct st_special_join_info {
    bilist_node_t bilist_node;
    join_tbl_bitmap_t min_lefthand;  /* base table ids in minimum LHS for join */
    join_tbl_bitmap_t min_righthand; /* base table ids in minimum RHS for join */
    join_tbl_bitmap_t syn_lefthand;  /* base table ids syntactically within LHS */
    join_tbl_bitmap_t syn_righthand; /* base table ids syntactically within RHS */
    sql_join_type_t jointype;        /* always INNER, LEFT, FULL, SEMI, or ANTI */
    bool lhs_strict;                 /* join cond is strict for some LHS tables */
    bool delay_upper_joins;          /* can't commute with upper RHS */
    bool varratio_cached;
    bool is_straight_join;           /* MySQL compatibility, currently not used */
    bool reversed;
    semi_anti_fac_t semi_anti_factor;
} special_join_info_t;

typedef enum join_table_type_t {
    BASE_TABLE,
    JOIN_TABLE
} join_table_type_t;


// 等价于 reloptinfo
// 定义的变量名建议简写为 jtable、jtbl、jtbl1
typedef struct st_sql_join_table {
    bilist_node_t bilist_node;

    join_table_type_t table_type;
    join_tbl_bitmap_t table_ids;
    galist_t* join_info;

    // 基础信息
    double rows;
    int encode_width;

    // 路径列表(等价于 reloptinfo.pathlist)
    bilist_t paths;
    sql_join_path_t* cheapest_total_path;
    sql_join_path_t* cheapest_startup_path;
    bilist_t cheapest_parameterized_paths;
    bool push_down_join;
    galist_t* push_down_refs;
} sql_join_table_t;

#define DP_MAX_TABLE_A_GROUP  8

typedef enum en_group_or_table_item_type {
    IS_BASE_TABLE_ITEM = 0x0,
    IS_GROUP_TABLE_ITEM,
} group_or_table_item_type;

typedef struct st_join_group_or_table_item {
    group_or_table_item_type type;
    pointer_t item;
} join_group_or_table_item;

/* split 8 table as a group to do dp search
 *
 */
typedef struct st_join_grouped_table {
    int group_id;
    galist_t *group_items;   /* type is join_group_or_table_item */
    sql_join_node_t* join_node;   /* current level join node */
    sql_join_table_t* group_result;
} join_grouped_table_t;

/*
* 新 join assist
* 存放join路径动态规划优化过程中的所有信息
* 方便分类管理，也能减少很多函数入参，不然太多了。
* 定名的变量名建议简写为 ja、jass、join_ass
*/
typedef struct st_join_assist {
    /**********************************
    * case:sql_build_join_tree_without_cost
    ***********************************/
    uint32 count;
    uint32 total;
    sql_join_node_t *maps[OG_MAX_JOIN_TABLES];
    sql_join_node_t *nodes[OG_MAX_JOIN_TABLES];
    sql_join_node_t *selected_nodes[OG_MAX_JOIN_TABLES];

    /**********************************
    * case: sql_build_join_tree_with_cost
    ***********************************/
    sql_stmt_t* stmt;               // Used to reduce parameter passing
    plan_assist_t *pa;              // Used to reduce parameter passing
    uint32 table_count;             // Number of tables
    bilist_t* join_tbl_level;       // DP table
    uint32 curr_level;              // Current DP level being generated
    galist_t join_tbl_list;         // Cache for joined tables, used when the number of tables is less than 32
    cm_oamap_t join_tbl_hash;       // Hashmap for caching joined tables to accelerate lookups
    sql_join_table_t* base_jtables[OG_MAX_JOIN_JTABLES];
    join_tbl_bitmap_t all_table_ids;
    bilist_t left_join_clauses;
    bilist_t right_join_clauses;
    bilist_t full_join_clauses;
    bilist_t join_info_list;
    cond_tree_t *cond;
    sql_table_t *tables_sort_by_id[OG_MAX_JOIN_TABLES];      // sorted by id
    join_grouped_table_t* root_grouped_table;
    join_grouped_table_t* dp_grouped_table;
    int grouped_table_id;

    cond_tree_t* join_cond;
    cond_tree_t* filter;
} join_assist_t;

void sql_debug_join_cost_info(sql_stmt_t *stmt, sql_join_node_t* join_tree, char* join_type, char* extra_info);

status_t sql_generate_join_assist_new(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *ja);
bool sql_jass_find_jtable(join_assist_t *ja, join_tbl_bitmap_t *table_ids, sql_join_table_t **jtable);
double sql_adjust_est_row(double rows);
bool32 check_leftjoin_and_leading_conflict(sql_join_node_t *join_node, join_assist_t *ja);
bool32 check_depend_json_table_conflict_with_leading(join_assist_t *ja);
status_t sql_build_join_tree_cost(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_root);

#endif