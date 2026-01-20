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
 * expl_common.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __EXPL_COMMON_H__
#define __EXPL_COMMON_H__

#include "cm_memory.h"
#include "cm_row.h"
#include "cm_defs.h"
#include "cm_list.h"
#include "cm_vma.h"
#include "ogsql_plan_defs.h"
#include "ogsql_stmt.h"
#include "srv_instance.h"

typedef enum {
    EXPL_COL_TYPE_ID,
    EXPL_COL_TYPE_OPERATION,
    EXPL_COL_TYPE_OWNER,
    EXPL_COL_TYPE_TABLE,
    EXPL_COL_TYPE_ROWS,
    EXPL_COL_TYPE_COST,
    EXPL_COL_TYPE_BYTES,
    EXPL_COL_TYPE_REMARK,
    EXPL_COL_TYPE_MAX
} expl_col_type_t;

typedef struct st_row_helper {
    int32 id;
    text_t *operation;
    text_t *owner;
    text_t *name;       // Table name
    text_t *alias;      // Table name alias
    int64 rows;
    double cost;
    int64 bytes;
    int64 remark;
} row_helper_t;

typedef enum {
    PREDICATE_FILTER = 0,
    PREDICATE_ACCESS,
    PREDICATE_JOIN_FILTER,
} predicate_type_t;

typedef enum {
    NO_CONCATE = 0,
    TABLE_CONCATE,
    JOIN_CONCATE,
} concat_type_t;

struct st_expl_helper;

typedef struct st_pred_helper {
    mtrl_rowid_t row_id;
    uint32 mtrl_id;

    row_assist_t ra;
    char *row_buf;
    var_text_t content;  // for description

    struct st_expl_helper *parent;

    bool32 is_enabled;
    bool32 is_start_with;
    bool32 is_merge_hash;
    predicate_type_t type;

    concat_type_t concate_type;
    cond_tree_t *cond;
    cond_tree_t *hash_filter;
    cond_tree_t *outer_cond;
    cond_tree_t *nl_filter;
    cond_tree_t *l_hash_filter;
    cond_tree_t *r_hash_filter;
    sql_query_t *query;  // reference sql query context

    cond_tree_t *merge_cond;
    cond_tree_t *idx_cond;
    vmc_t vmc;
} pred_helper_t;

typedef struct st_expl_helper {
    mtrl_rowid_t row_id;
    uint32 mtrl_id;

    row_assist_t ra;
    char *row_buf;
    text_t content;  // for operation

    row_helper_t row_helper;              // for format;
    uint32 fmt_sizes[EXPL_COL_TYPE_MAX];  // format sizes for every column
    int32 depth;                          // depth

    pred_helper_t pred_helper;  // predicate explain helper

    sql_cursor_t *cursor;
    sql_query_t *query;  // reference sql query context
    sql_array_t *ssa;    // SubSelect Array for subselect expr

    // format
    uint32 width;
    uint32 display_option;

    text_t *plan_output;
    bool32 first_fetch;
} expl_helper_t;

#endif
