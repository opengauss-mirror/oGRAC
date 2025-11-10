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
 * ogsql_or2union.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/optimizer/ogsql_or2union.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_or2union.h"
#include "ogsql_transform.h"
#include "ogsql_verifier.h"
#include "ogsql_func.h"
#include "ogsql_plan.h"
#include "srv_instance.h"
#include "ogsql_table_func.h"
#include "cond_parser.h"
#include "func_convert.h"
#include "ogsql_select_parser.h"

status_t clone_tables_4_subqry(sql_stmt_t *stmt, sql_query_t *query, sql_query_t *sub_query)
{
    sql_table_t *table = NULL;
    sql_table_t *new_table = NULL;
    bilist_node_t *node = NULL;
    query_field_t *query_field = NULL;
    for (uint32 i = 0; i < query->tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        OG_RETURN_IFERR(sql_array_new(&sub_query->tables, sizeof(sql_table_t), (void **)&new_table));
        *new_table = *table;
        cm_bilist_init(&new_table->query_fields);
        node = cm_bilist_head(&table->query_fields);
        for (; node != NULL; node = BINODE_NEXT(node)) {
            query_field = BILIST_NODE_OF(query_field_t, node, bilist_node);
            OG_RETURN_IFERR(sql_table_cache_query_field(stmt, new_table, query_field));
        }
    }
    return OG_SUCCESS;
}

