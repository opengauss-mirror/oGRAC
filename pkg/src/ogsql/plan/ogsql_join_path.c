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
 * ogsql_join_path.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/ogsql_join_path.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "table_parser.h"
#include "ogsql_transform.h"
#include "ogsql_plan_defs.h"
#include "plan_join.h"
#include "plan_scan.h"
#include "plan_rbo.h"
#include "ogsql_bitmap.h"
#include "ogsql_cbo_cost.h"
#include "ogsql_join_path.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_build_subselect_single_query(plan_assist_t *parent_pa, sql_table_t *table,
    join_tbl_bitmap_t *table_ids, sql_query_t *query, sql_join_node_t *jnode);
static status_t sql_init_join_ids(sql_join_node_t *join_node, join_tbl_bitmap_t *qualscope,
    join_tbl_bitmap_t *inner_join_rels, join_assist_t *join_ass, join_tbl_bitmap_t* leftids,
    join_tbl_bitmap_t* left_inners, join_tbl_bitmap_t* rightids, join_tbl_bitmap_t* right_inners,
    join_tbl_bitmap_t* nonnullable_rels, sql_join_type_t join_type, bool32* isok);

status_t sql_generate_join_assist_new(sql_stmt_t *stmt, plan_assist_t *pa, join_assist_t *ja)
{
    ja->stmt = stmt;
    ja->pa = pa;
    ja->table_count = pa->table_count;
    sql_bitmap_init(&ja->all_table_ids);

    // create dp table
    OG_RETURN_IFERR(sql_stack_alloc(stmt, (ja->table_count + 1) * sizeof(bilist_t), (void **)&ja->join_tbl_level));
    for (uint32 i = 0; i < ja->table_count; i++) {
        cm_bilist_init(&ja->join_tbl_level[i]);
    }
    ja->curr_level = 1;
    ja->cond = ja->pa->cond;

    // Initialize the join table list and hash table.
    cm_galist_init(&ja->join_tbl_list, stmt->context, sql_alloc_mem);
    cm_oamap_init_mem(&ja->join_tbl_hash);

    return OG_SUCCESS;
}

static status_t sql_create_base_table_bitmap(join_assist_t *ja, sql_join_node_t* join_node, join_tbl_bitmap_t** result)
{
    join_tbl_bitmap_t* table_id_bitmap = NULL;
    OG_RETURN_IFERR(sql_stack_alloc(ja->stmt, sizeof(join_tbl_bitmap_t), (void **)&table_id_bitmap));
    sql_bitmap_init(table_id_bitmap);
    
    for (uint32 i = 0; i < join_node->tables.count; i++) {
        sql_table_t *table = (sql_table_t *)join_node->tables.items[i];
        sql_bitmap_add_member(table->id, table_id_bitmap);
    }
    
    *result = table_id_bitmap;
    return OG_SUCCESS;
}

static status_t sql_create_base_table_item(join_assist_t *ja, sql_table_t *table, join_group_or_table_item** output)
{
    join_group_or_table_item* item;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(join_group_or_table_item), (void **)&item));
    item->item = table;
    item->type = IS_BASE_TABLE_ITEM;
    *output = item;

    return OG_SUCCESS;
}

static status_t sql_create_grouped_table_item(join_assist_t *ja, join_grouped_table_t* group_table_item,
    join_group_or_table_item** output)
{
    join_group_or_table_item* item;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(join_group_or_table_item), (void **)&item));
    item->item = group_table_item;
    item->type = IS_GROUP_TABLE_ITEM;
    *output = item;
    
    return OG_SUCCESS;
}

static status_t sql_make_a_tables_group(join_assist_t *ja, join_tbl_bitmap_t* table_ids, sql_join_node_t* join_node,
    join_grouped_table_t** output)
{
    join_grouped_table_t* join_grouped_table;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(join_grouped_table_t), (void **)&join_grouped_table));
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(galist_t), (void **)&join_grouped_table->group_items));
    cm_galist_init(join_grouped_table->group_items, ja->stmt->context, sql_alloc_mem);
    join_grouped_table->group_id = ja->grouped_table_id;
    ja->grouped_table_id++;
    if (ja->grouped_table_id > OG_MAX_JOIN_JTABLES) {
        OG_LOG_RUN_ERR("The number of CBO join tables exceeds the limit.");
        return OG_ERROR;
    }
    join_grouped_table->join_node = join_node;

    if (table_ids != NULL) {
        uint32 tab_id;
        BITMAP_FOREACH(tab_id, table_ids) {
            join_group_or_table_item* table_item;
            OG_RETURN_IFERR(sql_create_base_table_item(ja, ja->tables_sort_by_id[tab_id], &table_item));
            OG_RETURN_IFERR(cm_galist_insert(join_grouped_table->group_items, table_item));
        }
    }
    *output = join_grouped_table;

    return OG_SUCCESS;
}

static status_t sql_add_group_to_parent(join_assist_t *ja, join_grouped_table_t* left_grouped,
    join_grouped_table_t* right_grouped, join_grouped_table_t* parent)
{
    if (left_grouped != NULL && parent != NULL) {
        join_group_or_table_item* left_group_item;
        OG_RETURN_IFERR(sql_create_grouped_table_item(ja, left_grouped, &left_group_item));
        OG_RETURN_IFERR(cm_galist_insert(parent->group_items, left_group_item));
    }

    if (right_grouped != NULL && parent != NULL) {
        join_group_or_table_item* right_group_item;
        OG_RETURN_IFERR(sql_create_grouped_table_item(ja, right_grouped, &right_group_item));
        OG_RETURN_IFERR(cm_galist_insert(parent->group_items, right_group_item));
    }
    return OG_SUCCESS;
}

static status_t sql_add_cond_node_with_init(join_assist_t *ja, cond_tree_t** cond_tree, cond_node_t* cond)
{
    if (*cond_tree == NULL) {
        OG_RETURN_IFERR(sql_create_cond_tree(ja->stmt->context, cond_tree));
    }
    OG_RETURN_IFERR(sql_add_cond_node(*cond_tree, cond));
    return OG_SUCCESS;
}

static void sql_set_split_flag(sql_join_node_t* join_node, int left_id, int right_id)
{
    join_node->is_split_as_group = true;
    join_node->left_group_id = left_id;
    join_node->right_group_id = right_id;
}

static status_t sql_group_dp_tables_recurse(join_assist_t *ja, sql_join_node_t* join_node, join_tbl_bitmap_t** result,
    join_grouped_table_t* parent)
{
    if (join_node == NULL)
        return OG_SUCCESS;

    // base table
    if (join_node->oper == JOIN_OPER_NONE) {
        return sql_create_base_table_bitmap(ja, join_node, result);
    } else {
        join_tbl_bitmap_t* left_result = NULL;
        join_tbl_bitmap_t* right_result = NULL;
        join_grouped_table_t* left_parent;
        join_grouped_table_t* right_parent;
        OG_RETURN_IFERR(sql_make_a_tables_group(ja, NULL, join_node->left, &left_parent));
        OG_RETURN_IFERR(sql_make_a_tables_group(ja, NULL, join_node->right, &right_parent));
        OG_RETURN_IFERR(sql_group_dp_tables_recurse(ja, join_node->left, &left_result, left_parent));
        OG_RETURN_IFERR(sql_group_dp_tables_recurse(ja, join_node->right, &right_result, right_parent));

        *result = NULL;
        if (left_result != NULL && right_result != NULL) {
            uint32 left_count = sql_bitmap_number_count(left_result);
            uint32 right_count = sql_bitmap_number_count(right_result);
            // split as two group to do dp
            if ((join_node->type == JOIN_TYPE_FULL) || (left_count + right_count > DP_MAX_TABLE_A_GROUP)) {
                join_grouped_table_t* left_join_grouped_table;
                join_grouped_table_t* right_join_grouped_table;
                OG_RETURN_IFERR(sql_make_a_tables_group(ja, left_result, join_node->left, &left_join_grouped_table));
                OG_RETURN_IFERR(sql_make_a_tables_group(ja, right_result, join_node->right, &right_join_grouped_table));
                OG_RETURN_IFERR(sql_add_group_to_parent(ja, left_join_grouped_table, right_join_grouped_table, parent));
                sql_set_split_flag(join_node, left_join_grouped_table->group_id, right_join_grouped_table->group_id);
                *result = NULL;
                return OG_SUCCESS;
            }
            sql_bitmap_union(left_result, right_result, left_result);
            *result = left_result;
        } else if (left_result != NULL && right_result == NULL) {
            join_grouped_table_t* left_join_grouped_table;
            OG_RETURN_IFERR(sql_make_a_tables_group(ja, left_result, join_node->left, &left_join_grouped_table));
            OG_RETURN_IFERR(sql_add_group_to_parent(ja, left_join_grouped_table, NULL, parent));
            sql_set_split_flag(join_node, left_join_grouped_table->group_id, -1);
        } else if (left_result == NULL && right_result != NULL) {
            join_grouped_table_t* right_join_grouped_table;
            OG_RETURN_IFERR(sql_make_a_tables_group(ja, right_result, join_node->right, &right_join_grouped_table));
            OG_RETURN_IFERR(sql_add_group_to_parent(ja, right_join_grouped_table, NULL, parent));
            sql_set_split_flag(join_node, -1, right_join_grouped_table->group_id);
        }
        if (left_parent->group_items->count > 0) {
            OG_RETURN_IFERR(sql_add_group_to_parent(ja, left_parent, NULL, parent));
        }
        if (right_parent->group_items->count > 0) {
            OG_RETURN_IFERR(sql_add_group_to_parent(ja, NULL, right_parent, parent));
        }
        return OG_SUCCESS;
    }
}

static status_t sql_group_dp_tables(join_assist_t *ja)
{
    if (ja->pa->join_assist->join_node != NULL) {
        for (uint32 i = 0; i < ja->table_count; i++) {
            sql_table_t* table = ja->pa->tables[i];
            ja->tables_sort_by_id[table->id] = table;
        }
        ja->grouped_table_id = ja->table_count + 1;
        join_tbl_bitmap_t *result = NULL;
        join_grouped_table_t *root_grouped_table;
        OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(join_grouped_table_t), (void **)&root_grouped_table));
        OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(galist_t), (void **)&root_grouped_table->group_items));
        cm_galist_init(root_grouped_table->group_items, ja->stmt->context, sql_alloc_mem);
        root_grouped_table->join_node = ja->pa->join_assist->join_node;
        OG_RETURN_IFERR(sql_group_dp_tables_recurse(ja, ja->pa->join_assist->join_node, &result, root_grouped_table));
        if (result != NULL) {  // do the final group
            join_grouped_table_t* final_grouped_table;
            OG_RETURN_IFERR(sql_make_a_tables_group(ja, result, root_grouped_table->join_node, &final_grouped_table));
            OG_RETURN_IFERR(sql_add_group_to_parent(ja, final_grouped_table, NULL, root_grouped_table));
        }
        ja->root_grouped_table = root_grouped_table;
    }
    return OG_SUCCESS;
}

static status_t sql_jass_store_jtable(join_assist_t *ja, sql_join_table_t *jtable)
{
    // 1. store jtable to hash table
    if (jtable->table_type == JOIN_TABLE) {
        if (cm_oamap_size(&ja->join_tbl_hash) > 0) {
            cm_oamap_insert(&ja->join_tbl_hash, sql_hash_bitmap((join_tbl_bitmap_t *)&jtable->table_ids),
                            &jtable->table_ids, jtable);
        } else {
            OG_RETURN_IFERR(cm_galist_insert(&ja->join_tbl_list, jtable));
        }
    }

    // 2. store jtable to dp table
    if (ja->join_tbl_level) {
        cm_bilist_add_tail(&jtable->bilist_node, &ja->join_tbl_level[ja->curr_level]);
    }
    return OG_SUCCESS;
}

static status_t sql_create_base_jtable(join_assist_t *ja, sql_table_t *table, sql_join_table_t **out_jtable)
{
    sql_join_table_t* jtable;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(sql_join_table_t), (void **)&jtable));
    *out_jtable = jtable;

    jtable->table_type = BASE_TABLE;
    sql_bitmap_make_singleton(table->id, &jtable->table_ids);

    cm_bilist_init(&jtable->paths);
    jtable->cheapest_total_path = NULL;
    jtable->cheapest_startup_path = NULL;
    jtable->join_info = NULL;
    jtable->push_down_join = TABLE_CBO_HAS_FLAG(table, SELTION_PUSH_DOWN_JOIN) ? true : false;
    jtable->push_down_refs = NULL;
    OG_RETURN_IFERR(sql_jass_store_jtable(ja, jtable));

    return OG_SUCCESS;
}

static status_t sql_create_join_info(join_assist_t* ja, cond_node_t* cond, bool is_filter,
    tbl_join_info_t** out_join_info)
{
    join_tbl_bitmap_t table_ids_left;
    join_tbl_bitmap_t table_ids_right;
    join_tbl_bitmap_t table_ids;
    uint8 check = 0;

    if (cond->type == COND_NODE_COMPARE) {
        table_ids_left = sql_collect_table_ids_in_expr(cond->cmp->left, ja->pa->outer_rels_list, &check);
        OG_RETVALUE_IFTRUE(!(check & COND_HAS_OUTER_RELS), OG_SUCCESS);
        table_ids_right = sql_collect_table_ids_in_expr(cond->cmp->right, ja->pa->outer_rels_list, &check);
        OG_RETVALUE_IFTRUE(!(check & COND_HAS_OUTER_RELS), OG_SUCCESS);
        sql_bitmap_union(&table_ids_left, &table_ids_right, &table_ids);
    } else {
        table_ids = sql_collect_table_ids_in_cond(cond, ja->pa->outer_rels_list, &check);
        OG_RETVALUE_IFTRUE(!(check & COND_HAS_OUTER_RELS), OG_SUCCESS);
    }
    tbl_join_info_t* join_info;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(tbl_join_info_t), (void **)&join_info));

    join_info->cond = cond;
    join_info->jinfo_flag = 0;
    join_info->table_ids_left = table_ids_left;
    join_info->table_ids_right = table_ids_right;
    join_info->table_ids = table_ids;
    join_info->outer_tableids = NULL;
    join_info->nullable_tableids = NULL;
    if (is_filter) {
        join_info->jinfo_flag |= COND_IS_FILTER;
    } else {
        join_info->jinfo_flag |= COND_IS_JOIN_COND;
    }

    if (check & COND_HAS_DYNAMIC_SUBSEL) {
        join_info->jinfo_flag |= COND_HAS_DYNAMIC_SUBSEL;
    }

    if (check & COND_HAS_ROWNUM) {
        join_info->jinfo_flag |= COND_HAS_ROWNUM;
    }

    *out_join_info = join_info;
    return OG_SUCCESS;
}

/*
 * add a path into jtable
 */
static status_t sql_jtable_add_path(sql_stmt_t *stmt, sql_join_table_t *jtable, sql_join_path_t* jpath)
{
    const double fuzzy_factor = 1.01;
    const double small_fuzzy_factor = 1.0000000001;
    bool accept_new = true;
    jpath->parent = NULL;
    bilist_node_t *node;

    BILIST_FOREACH(node, jtable->paths) {
        sql_join_path_t* old_jpath = BILIST_NODE_OF(sql_join_path_t, node, bilist_node);

        /* COSTS OLD BETTER */
        if (jpath->cost.cost > old_jpath->cost.cost * fuzzy_factor) {
            /* old_path which has better costs also requires no outer rels not required by the new path. */
            if ((sql_bitmap_same(&jpath->outer_rels, &old_jpath->outer_rels) ||
                sql_bitmap_subset(&old_jpath->outer_rels, &jpath->outer_rels)) &&
                jpath->cost.card >= old_jpath->cost.card) {
                accept_new = false;
                break;
            }
            continue;
        }

        /* COSTS NEW BETTER */
        if (old_jpath->cost.cost > jpath->cost.cost * fuzzy_factor) {
            /* new_path which has better costs also requires no outer rels not required by the old path. */
            if ((sql_bitmap_same(&jpath->outer_rels, &old_jpath->outer_rels) ||
                sql_bitmap_subset(&jpath->outer_rels, &old_jpath->outer_rels)) &&
                jpath->cost.card <= old_jpath->cost.card) {
                bilist_node_t* next = node->next;
                cm_bilist_del(node, &jtable->paths);
                node->next = next;
            }
            continue;
        }

        /* COSTS EQUAL */
        if (sql_bitmap_same(&jpath->outer_rels, &old_jpath->outer_rels)) {
            if (jpath->cost.card < old_jpath->cost.card) {
                bilist_node_t* next = node->next;
                cm_bilist_del(node, &jtable->paths);
                node->next = next;
            } else if (jpath->cost.card > old_jpath->cost.card) {
                accept_new = false;
                break;
            } else {
                if (jpath->cost.cost < old_jpath->cost.cost * small_fuzzy_factor) {
                    bilist_node_t* next = node->next;
                    cm_bilist_del(node, &jtable->paths);
                    node->next = next;
                } else {
                    accept_new = false;
                    break;
                }
            }
        } else if (sql_bitmap_subset(&jpath->outer_rels, &old_jpath->outer_rels) &&
                   jpath->cost.card <= old_jpath->cost.card) {
            bilist_node_t* next = node->next;
            cm_bilist_del(node, &jtable->paths);
            node->next = next;
        } else if (sql_bitmap_subset(&old_jpath->outer_rels, &jpath->outer_rels) &&
                   jpath->cost.card >= old_jpath->cost.card) {
            accept_new = false;
            break;
        }
    }

    if (!accept_new) {
        return OG_SUCCESS;
    }
    
    // accept, update cheapest pointer
    cm_bilist_add_tail(&jpath->bilist_node, &jtable->paths);
    jpath->parent = jtable;
    sql_join_path_t* best_path = jtable->cheapest_total_path;
    if (!sql_bitmap_empty(&jpath->outer_rels)) {
        sql_join_node_t *copy_jpath = NULL;
        sql_clone_join_root(stmt, stmt->context, jpath, &copy_jpath, NULL, sql_alloc_mem);
        cm_bilist_add_tail(&copy_jpath->bilist_node, &jtable->cheapest_parameterized_paths);
    } else if (best_path == NULL || best_path->cost.cost > jpath->cost.cost) {
        jtable->cheapest_total_path = jpath;
    }
    return OG_SUCCESS;
}

static status_t sql_check_outerjoin_delayed(join_assist_t* ja, tbl_join_info_t* join_info)
{
    if (ja->join_info_list.count == 0) {
        return OG_SUCCESS;
    }

    bool found = false;
    join_tbl_bitmap_t tbl_ids;
    join_tbl_bitmap_t nullable_tblids;
    sql_bitmap_init(&tbl_ids);
    sql_bitmap_init(&nullable_tblids);
    sql_bitmap_copy(&join_info->table_ids, &tbl_ids);
    do {
        found = false;
        bilist_node_t *info_node = cm_bilist_head(&ja->join_info_list);
        for (; info_node != NULL; info_node = BINODE_NEXT(info_node)) {
            special_join_info_t *sjinfo = BILIST_NODE_OF(special_join_info_t, info_node, bilist_node);
            if (sql_bitmap_overlap(&tbl_ids, &sjinfo->min_righthand) ||
                (sjinfo->jointype == JOIN_TYPE_FULL && sql_bitmap_overlap(&tbl_ids, &sjinfo->min_lefthand))) {
                if (!sql_bitmap_subset(&sjinfo->min_righthand, &tbl_ids) ||
                    !sql_bitmap_subset(&sjinfo->min_lefthand, &tbl_ids)) {
                    sql_bitmap_union(&tbl_ids, &sjinfo->min_righthand, &tbl_ids);
                    sql_bitmap_union(&tbl_ids, &sjinfo->min_lefthand, &tbl_ids);
                    join_info->jinfo_flag |= COND_IS_OUTER_DELAYED;
                    found = true;
                }
                sql_bitmap_union(&nullable_tblids, &sjinfo->min_righthand, &nullable_tblids);
                if (sjinfo->jointype == JOIN_TYPE_FULL) {
                    sql_bitmap_union(&nullable_tblids, &sjinfo->min_lefthand, &nullable_tblids);
                }
                if ((join_info->jinfo_flag & COND_IS_JOIN_COND) && sjinfo->jointype != JOIN_TYPE_FULL &&
                    sql_bitmap_overlap(&tbl_ids, &sjinfo->min_lefthand)) {
                    sjinfo->delay_upper_joins = true;
                }
            }
        }
    } while (found);

    sql_bitmap_intersect(&nullable_tblids, &join_info->table_ids, &nullable_tblids);
    sql_bitmap_copy(&tbl_ids, &join_info->table_ids);
    if (!sql_bitmap_empty(&nullable_tblids)) {
        if (join_info->nullable_tableids == NULL) {
            OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(join_tbl_bitmap_t),
                (void **)&(join_info->nullable_tableids)));
        }
        sql_bitmap_init(join_info->nullable_tableids);
        sql_bitmap_copy(&nullable_tblids, join_info->nullable_tableids);
    }

    return OG_SUCCESS;
}

static status_t sql_jinfo_list_append_unique(join_assist_t *ja, galist_t** jinfo_list, tbl_join_info_t* jinfo)
{
    if (*jinfo_list == NULL) {
        OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(galist_t), (void **)jinfo_list));
        cm_galist_init(*jinfo_list, ja->stmt->context, sql_alloc_mem);
    }

    bool accept = true;
    for (uint32 i = 0; i < (*jinfo_list)->count; i++) {
        tbl_join_info_t* old_jinfo = (tbl_join_info_t *)cm_galist_get(*jinfo_list, i);
        if (old_jinfo->cond == jinfo->cond) {
            accept = false;
            break;
        }
    }
    if (accept) {
        OG_RETURN_IFERR(cm_galist_insert(*jinfo_list, jinfo));
    }
    return OG_SUCCESS;
}

static status_t sql_add_join_cond_to_jtable(join_assist_t* ja, tbl_join_info_t* join_info, uint32 table_id,
    sql_join_node_t *join_node)
{
    join_grouped_table_t* current_grouped = ja->dp_grouped_table;
    if (current_grouped == NULL) {
        return OG_ERROR;
    }

    galist_t* group_items = current_grouped->group_items;
    for (uint32 i = 0; i < group_items->count; i++) {
        join_group_or_table_item* item_cell = (join_group_or_table_item*)cm_galist_get(group_items, i);
        if (item_cell->type == IS_BASE_TABLE_ITEM && ja->base_jtables[table_id] != NULL) {
            sql_join_table_t* jtable = ja->base_jtables[table_id];
            OG_RETURN_IFERR(sql_jinfo_list_append_unique(ja, &jtable->join_info, join_info));
            return OG_SUCCESS;
        } else if (item_cell->type == IS_GROUP_TABLE_ITEM) {
            join_grouped_table_t *group_temp = (join_grouped_table_t *)item_cell->item;
            sql_join_table_t* jtable = group_temp->group_result;
            if (jtable == NULL) {
                return OG_ERROR;
            }
            if (sql_bitmap_exist_member(table_id, &jtable->table_ids) &&
                join_node == current_grouped->join_node) {
                OG_RETURN_IFERR(sql_jinfo_list_append_unique(ja, &jtable->join_info, join_info));
            }
        }
    }

    return OG_SUCCESS;
}

static status_t sql_distribute_jinfo_to_jtables(join_assist_t* ja, sql_join_node_t *join_node, cond_node_t* cond,
    bool is_filter, join_tbl_bitmap_t* ojscope, join_tbl_bitmap_t* outerjoin_nonnullable)
{
    tbl_join_info_t* join_info = NULL;
    OG_RETURN_IFERR(sql_create_join_info(ja, cond, is_filter, &join_info));
    OG_RETVALUE_IFTRUE(join_info == NULL, OG_SUCCESS);
    if (sql_bitmap_empty(&join_info->table_ids)) {
        if (!sql_bitmap_empty(ojscope)) {
            sql_bitmap_copy(ojscope, &join_info->table_ids);
        } else {
            if (join_node != NULL) {
                for (int count = 0; count < join_node->tables.count; count++) {
                    sql_bitmap_add_member(((sql_table_t*)join_node->tables.items[count])->id, &join_info->table_ids);
                }
            } else {
                sql_bitmap_copy(&ja->all_table_ids, &join_info->table_ids);
            }
        }
    }

    (void)sql_check_outerjoin_delayed(ja, join_info);
    if (!sql_bitmap_empty(outerjoin_nonnullable) &&
        sql_bitmap_overlap(&join_info->table_ids, outerjoin_nonnullable)) {
        sql_bitmap_union(&join_info->table_ids, ojscope, &join_info->table_ids);
        if (join_info->outer_tableids == NULL) {
            OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(join_tbl_bitmap_t),
                (void **)&(join_info->outer_tableids)));
        }

        sql_bitmap_init(join_info->outer_tableids);
        sql_bitmap_copy(outerjoin_nonnullable, join_info->outer_tableids);
    }

    if ((join_info->jinfo_flag & COND_HAS_ROWNUM) && join_node == NULL) {
        if (ja->dp_grouped_table->join_node->filter == NULL) {
            sql_add_cond_node_with_init(ja, &(ja->dp_grouped_table->join_node->filter), cond);
        }
    }

    if ((join_info->jinfo_flag & COND_HAS_DYNAMIC_SUBSEL) || (join_info->jinfo_flag & COND_HAS_ROWNUM)) {
        if (join_node != NULL) {
            for (int count = 0; count < join_node->tables.count; count++) {
                sql_bitmap_add_member(((sql_table_t*)join_node->tables.items[count])->id, &join_info->table_ids);
            }
        }
    }

    int i = 0;
    BITMAP_FOREACH(i, &join_info->table_ids) {
        OG_RETURN_IFERR(sql_add_join_cond_to_jtable(ja,
            join_info, i, join_node));
    }

    return OG_SUCCESS;
}

static status_t sql_extract_filters_to_jtables(join_assist_t *ja, sql_join_node_t *join_node, cond_node_t* cond,
    bool is_filter, join_tbl_bitmap_t* ojscope, join_tbl_bitmap_t* outerjoin_nonnullable)
{
    switch (cond->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_extract_filters_to_jtables(ja, join_node, cond->left, is_filter,
                ojscope, outerjoin_nonnullable));
            OG_RETURN_IFERR(sql_extract_filters_to_jtables(ja, join_node, cond->right, is_filter,
                ojscope, outerjoin_nonnullable));
            return OG_SUCCESS;
        case COND_NODE_OR:
        case COND_NODE_COMPARE:
            return sql_distribute_jinfo_to_jtables(ja, join_node, cond, is_filter,
                ojscope, outerjoin_nonnullable);

        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
        case COND_NODE_NOT:
            return sql_distribute_jinfo_to_jtables(ja, join_node, cond, is_filter,
                ojscope, outerjoin_nonnullable);

        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static void sql_try_set_2_semi_anti_join(sql_join_type_t *join_type, join_oper_t join_oper)
{
    switch (join_oper) {
        case JOIN_OPER_HASH_SEMI:
            *join_type = JOIN_TYPE_SEMI;
            return;
        case JOIN_OPER_HASH_ANTI:
            *join_type = JOIN_TYPE_ANTI;
            return;
        case JOIN_OPER_HASH_ANTI_NA:
            *join_type = JOIN_TYPE_ANTI_NA;
            return;
        default:
            return;
    }
}

static status_t sql_get_join_cond_by_relid(plan_assist_t *pa, join_cond_t **join_cond,
    join_tbl_bitmap_t *leftids, join_tbl_bitmap_t *rightids)
{
    bilist_node_t *node = cm_bilist_head(&pa->join_conds);

    for (; node != NULL; node = BINODE_NEXT(node)) {
        join_cond_t *tmp_cond = BILIST_NODE_OF(join_cond_t, node, bilist_node);
        if ((sql_bitmap_exist_member(tmp_cond->table1, leftids) &&
             sql_bitmap_exist_member(tmp_cond->table2, rightids)) ||
            (sql_bitmap_exist_member(tmp_cond->table2, leftids) &&
             sql_bitmap_exist_member(tmp_cond->table1, rightids))) {
            *join_cond = tmp_cond;
            break;
        }
    }
    return OG_SUCCESS;
}

static inline bool join_cond_has_rownum(struct st_cond_tree *clause)
{
    if (clause == NULL || clause->root == NULL) {
        return false;
    }
    cols_used_t cols_used;
    init_cols_used(&cols_used);
    sql_collect_cols_in_cond(clause->root, &cols_used);
    return HAS_ROWNUM(&cols_used);
}


static bool32 sql_is_cmp_oper_strict(cmp_type_t type)
{
    switch (type) {
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
}

static bool32 sql_is_expr_oper_strict(expr_node_type_t type)
{
    switch (type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_MOD:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
        case EXPR_NODE_NEGATIVE:
            return OG_TRUE;
        default:
            return OG_FALSE;
    }
}

static status_t sql_pull_nonnullable_tblids_walker(visit_assist_t *va, expr_node_t **node)
{
    join_tbl_bitmap_t *clause_tblids = (join_tbl_bitmap_t *)va->param0;

    if (!node || !(*node)) {
        return OG_SUCCESS;
    }

    if ((*node)->type == EXPR_NODE_COLUMN) {
        uint32 tab_id = TAB_OF_NODE((*node));
        sql_bitmap_add_member(tab_id, clause_tblids);
    } else if (sql_is_expr_oper_strict((*node)->type)) {
        if ((*node)->type == EXPR_NODE_NEGATIVE) {
            return sql_pull_nonnullable_tblids_walker(va, &(*node)->right);
        } else {
            OG_RETURN_IFERR(sql_pull_nonnullable_tblids_walker(va, &(*node)->left));
            return sql_pull_nonnullable_tblids_walker(va, &(*node)->right);
        }
    } else if ((*node)->type == EXPR_NODE_FUNC) {
        return OG_SUCCESS;
    }
    return OG_SUCCESS;
}

static status_t sql_pull_tblids_walker(visit_assist_t *va, expr_node_t **node)
{
    join_tbl_bitmap_t *clause_tblids = (join_tbl_bitmap_t *)va->param0;

    if (!node || !(*node)) {
        return OG_SUCCESS;
    }

    if ((*node)->type != EXPR_NODE_COLUMN) {
        return OG_SUCCESS;
    }
    uint32 tab_id = TAB_OF_NODE((*node));
    sql_bitmap_add_member(tab_id, clause_tblids);
    return OG_SUCCESS;
}

static inline status_t sql_check_cmp_node_strict(visit_assist_t *visit_ass, expr_tree_t *tree)
{
    while (tree != NULL) {
        OG_RETURN_IFERR(sql_pull_nonnullable_tblids_walker(visit_ass, &tree->root));
        tree = tree->next;
    }
    return OG_SUCCESS;
}

static status_t sql_pull_nonnullable_tblids_from_clause(join_assist_t *ja, cond_node_t *cond, bool is_top,
                                             join_tbl_bitmap_t *clause_relids)
{
    join_tbl_bitmap_t result;
    sql_bitmap_init(&result);

    switch (cond->type) {
        case COND_NODE_AND: {
            if (is_top) {
                OG_RETURN_IFERR(sql_pull_nonnullable_tblids_from_clause(ja, cond->left, is_top, &result));
                OG_RETURN_IFERR(sql_pull_nonnullable_tblids_from_clause(ja, cond->right, is_top, &result));
                break;
            }
            /* fall through */
        }
        case COND_NODE_OR: {
            OG_RETURN_IFERR(sql_pull_nonnullable_tblids_from_clause(ja, cond->left, is_top, &result));
            if (sql_bitmap_empty(&result)) {
                break;
            }
            join_tbl_bitmap_t sub_result;
            sql_bitmap_init(&sub_result);
            OG_RETURN_IFERR(sql_pull_nonnullable_tblids_from_clause(ja, cond->right, is_top, &sub_result));
            sql_bitmap_intersect(&sub_result, &result, &result);
            if (sql_bitmap_empty(&result)) {
                break;
            }
        } break;
        case COND_NODE_COMPARE: {
            cmp_node_t *cmp = cond->cmp;
            if (is_top && cmp->type == CMP_TYPE_IS_NOT_NULL) {
                visit_assist_t va = { 0 };
                sql_init_visit_assist(&va, ja->stmt, NULL);
                va.param0 = (void *)&result;
                OG_RETURN_IFERR(sql_check_cmp_node_strict(&va, cmp->left));
            } else if (sql_is_cmp_oper_strict(cmp->type)) {
                visit_assist_t va = { 0 };
                sql_init_visit_assist(&va, ja->stmt, NULL);
                va.param0 = (void *)&result;
                OG_RETURN_IFERR(sql_check_cmp_node_strict(&va, cmp->left));
                OG_RETURN_IFERR(sql_check_cmp_node_strict(&va, cmp->right));
            }
        } break;
        default:
            return OG_SUCCESS;
    }
    sql_bitmap_union(&result, clause_relids, clause_relids);
    return OG_SUCCESS;
}

static status_t sql_pull_nonnullable_tblids_from_joincond(join_assist_t *ja, join_cond_t *cond,
    join_tbl_bitmap_t *clause_relids)
{
    if (cond == NULL) {
        return OG_SUCCESS;
    }

    join_tbl_bitmap_t result;
    sql_bitmap_init(&result);
    for (uint32 i = 0; i < cond->cmp_nodes.count; i++) {
        cmp_node_t *cmp = (cmp_node_t *)cm_galist_get(&cond->cmp_nodes, i);
        if (sql_is_cmp_oper_strict(cmp->type)) {
            visit_assist_t va = { 0 };
            sql_init_visit_assist(&va, ja->stmt, NULL);
            va.param0 = (void *)&result;
            OG_RETURN_IFERR(sql_check_cmp_node_strict(&va, cmp->left));
            OG_RETURN_IFERR(sql_check_cmp_node_strict(&va, cmp->right));
        }
    }

    sql_bitmap_union(&result, clause_relids, clause_relids);
    return OG_SUCCESS;
}

static status_t sql_pull_tblids_from_clause(join_assist_t *join_ass, struct st_cond_tree *cond,
    join_tbl_bitmap_t *clause_relids)
{
    if (cond == NULL) {
        return OG_SUCCESS;
    }

    visit_assist_t va = { 0 };
    sql_init_visit_assist(&va, join_ass->stmt, NULL);
    va.param0 = (void *)clause_relids;

    OG_RETURN_IFERR(visit_cond_node(&va, cond->root, sql_pull_tblids_walker));
    return OG_SUCCESS;
}

static status_t sql_pull_tblids_from_joincond(join_assist_t *join_ass, join_cond_t *join_cond,
    join_tbl_bitmap_t *clause_relids)
{
    if (join_cond == NULL) {
        return OG_SUCCESS;
    }

    sql_bitmap_add_member(join_cond->table1, clause_relids);
    sql_bitmap_add_member(join_cond->table2, clause_relids);
    return OG_SUCCESS;
}

static status_t sql_make_special_joininfo(join_assist_t *join_ass, join_tbl_bitmap_t *left_rels,
    join_tbl_bitmap_t *right_rels, join_tbl_bitmap_t *inner_join_rels, sql_join_type_t join_type,
    struct st_cond_tree *clause, special_join_info_t **sjinfo_p, join_cond_t *join_cond_for_semi)
{
    OG_RETURN_IFERR(sql_alloc_mem(join_ass->stmt->context, sizeof(special_join_info_t), (void **)sjinfo_p));
    special_join_info_t *sjinfo = *sjinfo_p;

    sql_bitmap_copy(left_rels, &sjinfo->syn_lefthand);
    sql_bitmap_copy(right_rels, &sjinfo->syn_righthand);
    sjinfo->jointype = join_type;
    sjinfo->delay_upper_joins = false;

    if (join_type == JOIN_TYPE_FULL || join_cond_has_rownum(clause)) {
        sql_bitmap_copy(left_rels, &sjinfo->min_lefthand);
        sql_bitmap_copy(right_rels, &sjinfo->min_righthand);
        sjinfo->lhs_strict = false;
        return OG_SUCCESS;
    }

    join_tbl_bitmap_t clause_relids;
    join_tbl_bitmap_t strict_relids;
    sql_bitmap_init(&clause_relids);
    sql_bitmap_init(&strict_relids);
    bool join_type_is_semi = (join_type == JOIN_TYPE_SEMI || join_type == JOIN_TYPE_ANTI ||
        join_type == JOIN_TYPE_ANTI_NA);

    if (clause != NULL) {
        OG_RETURN_IFERR(sql_pull_tblids_from_clause(join_ass, clause, &clause_relids));
    } else if (join_type_is_semi && join_cond_for_semi != NULL) {
        OG_RETURN_IFERR(sql_pull_tblids_from_joincond(join_ass, join_cond_for_semi, &clause_relids));
    }

    if (clause != NULL && clause->root != NULL) {
        OG_RETURN_IFERR(sql_pull_nonnullable_tblids_from_clause(join_ass, clause->root, true, &strict_relids));
    } else if (join_type_is_semi && join_cond_for_semi != NULL) {
        OG_RETURN_IFERR(sql_pull_nonnullable_tblids_from_joincond(join_ass, join_cond_for_semi, &strict_relids));
    }

    sjinfo->lhs_strict = sql_bitmap_overlap(&strict_relids, left_rels);

    join_tbl_bitmap_t min_lefthand;
    join_tbl_bitmap_t min_righthand;
    sql_bitmap_init(&min_lefthand);
    sql_bitmap_init(&min_righthand);

    sql_bitmap_intersect(left_rels, &clause_relids, &min_lefthand);
    sql_bitmap_union(&clause_relids, inner_join_rels, &min_righthand);
    sql_bitmap_intersect(right_rels, &min_righthand, &min_righthand);

    /* Check the previous sjinfo */
    bilist_node_t *table_node = cm_bilist_head(&join_ass->join_info_list);
    for (; table_node != NULL; table_node = BINODE_NEXT(table_node)) {
        special_join_info_t *otherinfo = BILIST_NODE_OF(special_join_info_t, table_node, bilist_node);
        bool other_join_type_is_semi = (otherinfo->jointype == JOIN_TYPE_SEMI ||
            otherinfo->jointype == JOIN_TYPE_ANTI || otherinfo->jointype == JOIN_TYPE_ANTI_NA);

        /* e.g. if A left join (B out join C), then we must have min_lefthand={A}, min_righthand={B,C} */
        if (otherinfo->jointype == JOIN_TYPE_FULL) {
            if (sql_bitmap_overlap(left_rels, &otherinfo->syn_lefthand) ||
                sql_bitmap_overlap(left_rels, &otherinfo->syn_righthand)) {
                sql_bitmap_union(&otherinfo->syn_lefthand, &min_lefthand, &min_lefthand);
                sql_bitmap_union(&otherinfo->syn_righthand, &min_lefthand, &min_lefthand);
            }

            if (sql_bitmap_overlap(right_rels, &otherinfo->syn_lefthand) ||
                sql_bitmap_overlap(right_rels, &otherinfo->syn_righthand)) {
                sql_bitmap_union(&otherinfo->syn_lefthand, &min_righthand, &min_righthand);
                sql_bitmap_union(&otherinfo->syn_righthand, &min_righthand, &min_righthand);
            }
            continue;
        }

        /* The lower outer join appears in the LHS of the current join, and the join condition references the RHS of the
         * lower outer join. */
        if (sql_bitmap_overlap(left_rels, &otherinfo->syn_righthand)) {
            /* e.g. if (A left join B on Pab) left join C on Pbc && Pbc is not strict, then we must have
             * min_lefthand={A,B} */
            if (sql_bitmap_overlap(&clause_relids, &otherinfo->syn_righthand) &&
                (join_type_is_semi || !sql_bitmap_overlap(&strict_relids, &otherinfo->min_righthand))) {
                sql_bitmap_union(&otherinfo->syn_lefthand, &min_lefthand, &min_lefthand);
                sql_bitmap_union(&otherinfo->syn_righthand, &min_lefthand, &min_lefthand);
            }
        }

        /* The lower outer join appears in the RHS of the current join. */
        if (sql_bitmap_overlap(right_rels, &otherinfo->syn_righthand)) {
            /* e.g. if A left join (B left join C on Pbc) on Pac ||
                       A left join (B left join C on Pbc) on Pc  ||
                       A left join (B left join C on Pbc) on Pab & Pbc is not strict ||
                       TODO: A left join (B left join C on Pbc where Pc) on Pab, Pc is not strict. delay_upper_joins
               computed during the processing of condition pushdown */
            if (sql_bitmap_overlap(&clause_relids, &otherinfo->syn_righthand) ||
                !sql_bitmap_overlap(&clause_relids, &otherinfo->min_lefthand) ||
                join_type_is_semi || other_join_type_is_semi ||
                !otherinfo->lhs_strict) {
                sql_bitmap_union(&otherinfo->syn_lefthand, &min_righthand, &min_righthand);
                sql_bitmap_union(&otherinfo->syn_righthand, &min_righthand, &min_righthand);
            }
        }
    }

    if (sql_bitmap_empty(&min_lefthand)) {
        sql_bitmap_copy(left_rels, &min_lefthand);
    }

    if (sql_bitmap_empty(&min_righthand)) {
        sql_bitmap_copy(right_rels, &min_righthand);
    }

    sql_bitmap_copy(&min_lefthand, &sjinfo->min_lefthand);
    sql_bitmap_copy(&min_righthand, &sjinfo->min_righthand);

    return OG_SUCCESS;
}

static status_t sql_deconstruct_jointree(sql_join_node_t *join_node, join_tbl_bitmap_t *qualscope,
                              join_tbl_bitmap_t *inner_join_rels, join_assist_t *join_ass)
{
    special_join_info_t *sjinfo = NULL;
    join_tbl_bitmap_t leftids, left_inners;
    join_tbl_bitmap_t rightids, right_inners;
    join_tbl_bitmap_t nonnullable_rels, ojscope;
    sql_bitmap_init(&leftids);
    sql_bitmap_init(&rightids);
    sql_bitmap_init(&left_inners);
    sql_bitmap_init(&right_inners);
    sql_bitmap_init(&ojscope);
    sql_bitmap_init(&nonnullable_rels);
    sql_join_type_t join_type = join_node->type;
    sql_try_set_2_semi_anti_join(&join_type, join_node->oper);

    bool32 isok = false;
    OG_RETURN_IFERR(sql_init_join_ids(join_node, qualscope, inner_join_rels, join_ass, &leftids, &left_inners,
        &rightids, &right_inners, &nonnullable_rels, join_type, &isok));
    if (!isok) {
        return OG_SUCCESS;
    }

    if (join_type != JOIN_TYPE_INNER && join_type != JOIN_TYPE_COMMA &&
        join_type != JOIN_TYPE_CROSS) {
        join_cond_t *join_cond_for_semi = NULL;
        if (join_node->join_cond == NULL &&
            (join_type == JOIN_TYPE_SEMI || join_type == JOIN_TYPE_ANTI || join_type == JOIN_TYPE_ANTI_NA)) {
            OG_RETURN_IFERR(sql_get_join_cond_by_relid(join_ass->pa, &join_cond_for_semi, &leftids, &rightids));
        }
        OG_RETURN_IFERR(sql_make_special_joininfo(join_ass, &leftids, &rightids, inner_join_rels, join_type,
            join_node->join_cond, &sjinfo, join_cond_for_semi));
        sql_bitmap_union(&sjinfo->min_lefthand, &sjinfo->min_righthand, &ojscope);
    }

    if (join_node->filter != NULL && join_node->filter->root != NULL) {
        OG_RETURN_IFERR(sql_extract_filters_to_jtables(join_ass, join_node, join_node->filter->root,
            true, &ojscope, &nonnullable_rels));
    }
    if (join_node->join_cond != NULL && join_node->join_cond->root != NULL) {
        OG_RETURN_IFERR(sql_extract_filters_to_jtables(join_ass, join_node, join_node->join_cond->root,
            false, &ojscope, &nonnullable_rels));
    }

    /* Now we can add the specialjoininfo to join_info_list */
    if (sjinfo != NULL) {
        cm_bilist_add_tail(&sjinfo->bilist_node, &join_ass->join_info_list);
    }
    return OG_SUCCESS;
}

static status_t sql_init_join_ids(sql_join_node_t *join_node, join_tbl_bitmap_t *qualscope,
    join_tbl_bitmap_t *inner_join_rels, join_assist_t *join_ass, join_tbl_bitmap_t* leftids,
    join_tbl_bitmap_t* left_inners, join_tbl_bitmap_t* rightids, join_tbl_bitmap_t* right_inners,
    join_tbl_bitmap_t* nonnullable_rels, sql_join_type_t join_type, bool32* isok)
{
    switch (join_type) {
        case JOIN_TYPE_NONE: {
            sql_table_t *r = (sql_table_t *)sql_array_get(&join_node->tables, 0);
            sql_bitmap_setbit(r->id, qualscope);
            return OG_SUCCESS;
        }

        case JOIN_TYPE_CROSS:
        case JOIN_TYPE_COMMA:
        case JOIN_TYPE_INNER: {
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->left, leftids, left_inners, join_ass));
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->right, rightids, right_inners, join_ass));
            sql_bitmap_union(leftids, rightids, qualscope);
            sql_bitmap_union(leftids, rightids, inner_join_rels);
            break;
        }

        case JOIN_TYPE_ANTI:
        case JOIN_TYPE_ANTI_NA:
        case JOIN_TYPE_LEFT: {
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->left, leftids, left_inners, join_ass));
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->right, rightids, right_inners, join_ass));
            sql_bitmap_union(leftids, rightids, qualscope);
            sql_bitmap_union(left_inners, right_inners, inner_join_rels);
            sql_bitmap_copy(leftids, nonnullable_rels);
            break;
        }

        case JOIN_TYPE_SEMI: {
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->left, leftids, left_inners, join_ass));
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->right, rightids, right_inners, join_ass));
            sql_bitmap_union(leftids, rightids, qualscope);
            sql_bitmap_union(left_inners, right_inners, inner_join_rels);
            break;
        }

        case JOIN_TYPE_FULL: {
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->left, leftids, left_inners, join_ass));
            OG_RETURN_IFERR(sql_deconstruct_jointree(join_node->right, rightids, right_inners, join_ass));
            sql_bitmap_union(leftids, rightids, qualscope);
            sql_bitmap_union(left_inners, right_inners, inner_join_rels);
            sql_bitmap_copy(qualscope, nonnullable_rels);
            break;
        }

        default:
            break;
    }
    *isok = true;
    return OG_SUCCESS;
}

static status_t sql_generate_sjoininfo(sql_join_node_t *join_node, join_assist_t *ja)
{
    cm_bilist_init(&ja->join_info_list);
    join_tbl_bitmap_t qualscope;
    join_tbl_bitmap_t inner_join_rels;
    sql_bitmap_init(&inner_join_rels);
    sql_bitmap_init(&qualscope);
    OG_RETURN_IFERR(sql_deconstruct_jointree(join_node, &qualscope, &inner_join_rels, ja));
    return OG_SUCCESS;
}

static status_t sql_build_subselect_path_internal(plan_assist_t *parent_pa, sql_table_t *table,
    sql_join_table_t *jtable, join_tbl_bitmap_t *table_ids, galist_t *considered_relids)
{
    sql_stmt_t *stmt = parent_pa->stmt;
    select_node_t *select_node = table->select_ctx->root;

    sql_join_node_t *jnode;
    OG_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &jnode));
    jnode->cost.card = 0;

    /*
     * collect all queries of select_node, which may be set-op. Calculate them separately
     * and then summarize into join_node.
     */
    biqueue_t que;
    biqueue_init(&que);
    sql_collect_select_nodes(&que, select_node);

    select_node_t *obj = NULL;
    biqueue_node_t *curr_node = biqueue_first(&que);
    biqueue_node_t *end_node = biqueue_end(&que);

    while (curr_node != end_node) {
        obj = OBJECT_OF(select_node_t, curr_node);
        if (obj != NULL && obj->query != NULL) {
            OG_RETURN_IFERR(sql_build_subselect_single_query(parent_pa, table, table_ids, obj->query, jnode));
        }
        curr_node = BINODE_NEXT(curr_node);
    }

    jnode->outer_rels = *table_ids;

    SQL_LOG_OPTINFO(stmt, "[CBO]Add jpath oper:%d, type:%d, cost:%f, startup:%f",
        jnode->oper, jnode->type, jnode->cost.cost, jnode->cost.startup_cost);
    if (jtable != NULL) {
        jtable->push_down_refs = table->select_ctx->parent_refs;
        jtable->rows = jnode->cost.card;
        OG_RETURN_IFERR(sql_jtable_add_path(stmt, jtable, jnode));
    } else {
        table->cost = jnode->cost.cost;
        table->card = jnode->cost.card;
    }

    if (considered_relids != NULL) {
        join_tbl_bitmap_t *stored_table_ids = NULL;
        OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(join_tbl_bitmap_t), (void **)&stored_table_ids));
        sql_bitmap_copy(table_ids, stored_table_ids);
        OG_RETURN_IFERR(cm_galist_insert(considered_relids, stored_table_ids));
    }

    return OG_SUCCESS;
}

static status_t sql_build_subselect_single_query(plan_assist_t *parent_pa, sql_table_t *table,
    join_tbl_bitmap_t *table_ids, sql_query_t *query, sql_join_node_t *jnode)
{
    sql_stmt_t *stmt = parent_pa->stmt;
    plan_assist_t pa;
    sql_init_plan_assist(stmt, &pa, query, SQL_QUERY_NODE, parent_pa);
    pa.ignore_hj = table->is_push_down;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_stack_alloc(stmt, sizeof(galist_t), (void **)&pa.outer_rels_list));
    cm_galist_init(pa.outer_rels_list, stmt, sql_stack_alloc);

    RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(pa.outer_rels_list, table_ids), stmt);
    /*
     * outer_rels_list from parent-select need also, and index in new outer_rels_list
     * goes to be + 1 for match to ancestor node
     */
    for (uint32 i = 0; parent_pa->outer_rels_list != NULL && i < parent_pa->outer_rels_list->count; i++) {
        RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(pa.outer_rels_list,
            cm_galist_get(parent_pa->outer_rels_list, i)), stmt);
    }

    if (pa.table_count > 1) {
        OG_RETURN_IFERR(sql_build_join_tree(stmt, &pa, &query->join_root));
        jnode->cost.cost += query->join_root->cost.cost;
        jnode->cost.card += query->join_root->cost.card;
    } else if (pa.tables[0]->type == SUBSELECT_AS_TABLE || pa.tables[0]->type == WITH_AS_TABLE) {
        join_tbl_bitmap_t empty_table_ids;
        sql_bitmap_init(&empty_table_ids);
        RET_AND_RESTORE_STACK_IFERR(
            sql_build_subselect_path_internal(&pa, pa.tables[0], NULL, &empty_table_ids, NULL), stmt);
        jnode->cost.card += pa.tables[0]->card;
        jnode->cost.cost += pa.tables[0]->cost;
    } else {
        RET_AND_RESTORE_STACK_IFERR(sql_check_table_indexable(stmt, &pa, pa.tables[0], pa.cond), stmt);
        jnode->cost.card += pa.tables[0]->card;
        jnode->cost.cost += pa.tables[0]->cost;
    }

    OGSQL_RESTORE_STACK(stmt);

    return OG_SUCCESS;
}

static status_t sql_build_subselect_path(plan_assist_t *pa, sql_table_t *table,
    sql_join_table_t *jtable)
{
    galist_t *refs = table->select_ctx->parent_refs;
    galist_t *considered_relids;
    sql_stmt_t *stmt = pa->stmt;

    OGSQL_SAVE_STACK(stmt);
    RET_AND_RESTORE_STACK_IFERR(
        sql_stack_alloc(stmt, sizeof(galist_t), (void **)&considered_relids), stmt);
    cm_galist_init(considered_relids, stmt, sql_stack_alloc);

    /* First, construct paths that do not rely on any parent query tables. */
    join_tbl_bitmap_t empty_table_ids;
    sql_bitmap_init(&empty_table_ids);
    RET_AND_RESTORE_STACK_IFERR(
        sql_build_subselect_path_internal(pa, table, jtable, &empty_table_ids, considered_relids), stmt);

    int32_t i = 0;
    while (i < refs->count) {
        parent_ref_t *ref = (parent_ref_t *)cm_galist_get(refs, i++);
        uint32 ref_tab = ref->tab;

        join_tbl_bitmap_t table_ids;
        sql_bitmap_init(&table_ids);
        sql_bitmap_add_member(ref_tab, &table_ids);

        for (uint32 i = 0; i < considered_relids->count; i++) {
            join_tbl_bitmap_t *old_table_ids = (join_tbl_bitmap_t *)cm_galist_get(considered_relids, i);

            join_tbl_bitmap_t new_table_ids;
            sql_bitmap_union(&table_ids, old_table_ids, &new_table_ids);

            if (sql_bitmap_same_as_any(&new_table_ids, considered_relids)) {
                continue;
            }

            /*
             * Second, combine with the previously referenced parent query tables
             * to form new dependencies, and then construct paths for these.
             */
            RET_AND_RESTORE_STACK_IFERR(
                sql_build_subselect_path_internal(pa, table, jtable, &new_table_ids, considered_relids), stmt);
        }
    }

    OGSQL_RESTORE_STACK(stmt);

    return OG_SUCCESS;
}

static void sql_pre_init_jtable_cost(sql_table_t *table)
{
    if (table == NULL) {
        return;
    }

    switch (table->type) {
        case VIEW_AS_TABLE:
        case SUBSELECT_AS_TABLE:
            if (table->select_ctx != NULL && table->select_ctx->plan != NULL) {
                table->card = table->select_ctx->plan->rows;
                table->cost = table->select_ctx->plan->cost;
                table->startup_cost = table->select_ctx->plan->start_cost;
            }
            break;

        case NORMAL_TABLE:
        case FUNC_AS_TABLE:
        case JOIN_AS_TABLE:
        case WITH_AS_TABLE:
        case JSON_TABLE:
        default:
            break;
    }
}

static bool32 match_joininfo_to_indexcol(sql_stmt_t *stmt, sql_table_t *table, tbl_join_info_t *jinfo, uint16 index_col)
{
    knl_column_t *knl_col = knl_get_column(table->entry->dc.handle, index_col);
    expr_node_t col_node;
    expr_node_t *node = NULL;
    bool32 result = OG_FALSE;

    if (jinfo == NULL || jinfo->cond == NULL || jinfo->cond->type != COND_NODE_COMPARE) {
        return OG_FALSE;
    }
    expr_tree_t *left = jinfo->cond->cmp->left;
    expr_tree_t *right = jinfo->cond->cmp->right;

    if (left == NULL || right == NULL) {
        return OG_FALSE;
    }

    OGSQL_SAVE_STACK(stmt);
    RETVALUE_AND_RESTORE_STACK_IFERR(sql_get_index_col_node(stmt, knl_col, &col_node,
        &node, table->id, index_col), stmt, OG_FALSE);

    /* one side reference target table, and other side not. */
    if (sql_expr_node_matched(stmt, left, node)) {
        if (!sql_bitmap_exist_member(table->id, &jinfo->table_ids_right)) {
            result = OG_TRUE;
        }
    }

    if (sql_expr_node_matched(stmt, right, node)) {
        if (!sql_bitmap_exist_member(table->id, &jinfo->table_ids_left)) {
            result = OG_TRUE;
        }
    }

    OGSQL_RESTORE_STACK(stmt);

    return result;
}

static status_t match_joininfo_to_index(sql_stmt_t *stmt, sql_table_t *table, index_t *index, tbl_join_info_t *jinfo,
    galist_t **idx_jinfo_array, join_tbl_bitmap_t *self_table_id, bool32 *has_matched)
{
    for (uint32 col_id = 0; col_id < index->desc.column_count; col_id++) {
        if (match_joininfo_to_indexcol(stmt, table, jinfo, index->desc.columns[col_id])) {
            OG_RETURN_IFERR(cm_galist_insert(idx_jinfo_array[col_id], jinfo));

            if (!sql_bitmap_same(&jinfo->table_ids, self_table_id)) {
                *has_matched = OG_TRUE;
            }
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

static status_t get_parameterized_path_internal(join_assist_t *ja, uint32 table_id, index_t *index,
    galist_t **idx_cond_array, join_tbl_bitmap_t outer_rels, cond_tree_t* cond)
{
    sql_stmt_t *stmt = ja->stmt;
    sql_table_t *table = ja->pa->tables[table_id];
    sql_join_table_t *jtable = ja->base_jtables[table_id];
    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    cbo_index_choose_assist_t ca = {
        .index = &index->desc,
        .strict_equal_cnt = 0
    };

    sql_table_t *tmp_table = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(sql_table_t), (void **)&tmp_table));

    sql_init_table_indexable(tmp_table, table);

    if (check_can_index_only(ja->pa, tmp_table, &index->desc)) {
        ca.scan_flag |= RBO_INDEX_ONLY_FLAG;
    }

    int64 card;
    double cost = sql_estimate_index_scan_cost(stmt, &ca, entity, index, idx_cond_array, &card, table);

    tmp_table->cost = cost;
    tmp_table->index = &index->desc;
    tmp_table->scan_flag = ca.scan_flag;
    tmp_table->scan_mode = SCAN_MODE_INDEX;
    tmp_table->index_full_scan = ca.index_full_scan;
    tmp_table->idx_equal_to = ca.strict_equal_cnt;
    tmp_table->index_dsc = ca.index_dsc;
    tmp_table->cond = cond;

    if (INDEX_ONLY_SCAN(tmp_table->scan_flag)) {
        OG_RETURN_IFERR(sql_make_index_col_map(ja->pa, stmt, tmp_table));
    }

    sql_debug_scan_cost_info(stmt, tmp_table, "PARAM_INDEX", &ca, cost, ja, &outer_rels);

    sql_join_node_t* jnode;
    OG_RETURN_IFERR(sql_create_join_node(stmt, JOIN_TYPE_NONE, tmp_table, NULL, NULL, NULL, &jnode));
    jnode->cost.card = card;
    jnode->cost.cost = cost;
    jnode->outer_rels = outer_rels;

    OG_RETURN_IFERR(sql_jtable_add_path(ja->stmt, jtable, jnode));
    return OG_SUCCESS;
}

static status_t get_parameterized_path(join_assist_t *ja, uint32 table_id, index_t *index, galist_t **idx_jinfo_array,
    join_tbl_bitmap_t *table_ids, galist_t *considered_relids)
{
    if (sql_bitmap_same_as_any(table_ids, considered_relids)) {
        return OG_SUCCESS;
    }

    sql_stmt_t *stmt = ja->stmt;
    sql_table_t *table = ja->pa->tables[table_id];

    OGSQL_SAVE_STACK(stmt);
    galist_t *idx_cond_array[OG_MAX_INDEX_COLUMNS];
    RET_AND_RESTORE_STACK_IFERR(init_idx_cond_array(stmt, idx_cond_array), stmt);

    join_tbl_bitmap_t outer_rels;
    sql_bitmap_init(&outer_rels);

    cond_tree_t* cond = NULL;
    sql_create_cond_tree(stmt->context, &cond);

    /*
     * Retrieve all conditions from the idx_cond_array that belong to the specified
     * table_ids, including conditions that involve all index columns.
     */
    for (uint32 col_id = 0; col_id < index->desc.column_count; col_id++) {
        for (uint32 cond_idx = 0; cond_idx < idx_jinfo_array[col_id]->count; cond_idx++) {
            tbl_join_info_t *jinfo = (tbl_join_info_t*)cm_galist_get(idx_jinfo_array[col_id], cond_idx);

            if (sql_bitmap_subset(&jinfo->table_ids, table_ids)) {
                RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(idx_cond_array[col_id], jinfo->cond->cmp), stmt);
                sql_bitmap_union(&outer_rels, &jinfo->table_ids, &outer_rels);
                sql_add_cond_node(cond, jinfo->cond);
            }
        }
    }
    sql_bitmap_delete_member(table->id, &outer_rels);

    /* start generating parameterized index paths */
    RET_AND_RESTORE_STACK_IFERR(
        get_parameterized_path_internal(ja, table_id, index, idx_cond_array, outer_rels, cond), stmt);

    OGSQL_RESTORE_STACK(stmt);

    /* considered_relids would be free during generate_parameterized_paths */
    join_tbl_bitmap_t *stored_table_ids = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(join_tbl_bitmap_t), (void **)&stored_table_ids));
    sql_bitmap_copy(table_ids, stored_table_ids);
    OG_RETURN_IFERR(cm_galist_insert(considered_relids, stored_table_ids));

    return OG_SUCCESS;
}

static status_t consider_index_join_info(join_assist_t *ja, galist_t **idx_jinfo_array, uint32 table_id, index_t *index,
    join_tbl_bitmap_t *self_table_id, galist_t *considered_relids, uint32 col_id, int considered_jinfos)
{
    const int considered_limit = 10;

    for (uint32 cond_idx = 0; cond_idx < idx_jinfo_array[col_id]->count; cond_idx++) {
        tbl_join_info_t *jinfo = (tbl_join_info_t*)cm_galist_get(idx_jinfo_array[col_id], cond_idx);
        join_tbl_bitmap_t *table_ids = &jinfo->table_ids;

        /* If we already tried its table_id set, no need to do so again */
        if (sql_bitmap_same(table_ids, self_table_id) ||
            sql_bitmap_same_as_any(table_ids, considered_relids)) {
            continue;
        }

        /* Generate the union of this jinfo's table_ids set with each previously-tried set. */
        for (uint32 i = 0; i < considered_relids->count; i++) {
            join_tbl_bitmap_t *old_table_ids = (join_tbl_bitmap_t *)cm_galist_get(considered_relids, i);

            if (sql_bitmap_subset(table_ids, old_table_ids) || sql_bitmap_subset(old_table_ids, table_ids)) {
                continue;
            }

            /*
             * stop considering combinations of previously-tried set if the size of considered_relids
             * is too big. But current table_ids is still be considered out of this loop.
             *
             * considered_limit is an empirical value.
             */
            if (considered_relids->count >= considered_limit * considered_jinfos) {
                break;
            }

            join_tbl_bitmap_t new_table_ids;
            sql_bitmap_union(table_ids, old_table_ids, &new_table_ids);

            OG_RETURN_IFERR(get_parameterized_path(ja, table_id, index, idx_jinfo_array,
                &new_table_ids, considered_relids));
        }

        /* Also try this set of table_ids by itself */
        OG_RETURN_IFERR(get_parameterized_path(ja, table_id, index, idx_jinfo_array,
            table_ids, considered_relids));
    }
    return OG_SUCCESS;
}

static status_t generate_parameterized_paths(join_assist_t *ja, sql_join_table_t *jtable, sql_table_t *table)
{
    if (table->type != NORMAL_TABLE || (table->index != NULL &&
        INDEX_CONTAIN_UNIQUE_COLS(table->index, table->idx_equal_to))) {
        return OG_SUCCESS;
    }
    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    sql_stmt_t *stmt = ja->stmt;
    if (!is_analyzed_table(stmt, table) || entity->cbo_table_stats == NULL ||
        !entity->cbo_table_stats->global_stats_exist) {
        return OG_SUCCESS;
    }

    join_tbl_bitmap_t self_table_id;
    sql_bitmap_make_singleton(table->id, &self_table_id);

    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        index_t *index = DC_TABLE_INDEX(&entity->table, idx_id);
        OG_CONTINUE_IFTRUE(index->desc.is_invalid);

        OGSQL_SAVE_STACK(stmt);

        galist_t *idx_jinfo_array[OG_MAX_INDEX_COLUMNS];
        RET_AND_RESTORE_STACK_IFERR(init_idx_cond_array(stmt, idx_jinfo_array), stmt);

        bool32 matched = false;

        if (jtable->join_info == NULL) {
            continue;
        }

        for (uint32 i = 0; i < jtable->join_info->count; i++) {
            tbl_join_info_t* jinfo = (tbl_join_info_t *)cm_galist_get(jtable->join_info, i);
            /* here cond must be COND_NODE_OR OR or COND_NODE_COMPARE, we only consider latter */
            if (jinfo->cond->type != COND_NODE_OR) {
                RET_AND_RESTORE_STACK_IFERR(match_joininfo_to_index(stmt, table, index, jinfo, idx_jinfo_array,
                    &self_table_id, &matched), stmt);
            }
        }
        if (!matched) {
            continue;
        }

        int considered_jinfos = 0;
        galist_t *considered_relids;
        RET_AND_RESTORE_STACK_IFERR(sql_alloc_mem(stmt->context, sizeof(galist_t), (void **)&considered_relids), stmt);
        cm_galist_init(considered_relids, stmt->context, sql_alloc_mem);

        for (uint32 col_id = 0; col_id < index->desc.column_count; col_id++) {
            considered_jinfos += idx_jinfo_array[col_id]->count;
            RET_AND_RESTORE_STACK_IFERR(consider_index_join_info(ja, idx_jinfo_array, table->id, index, &self_table_id,
                considered_relids, col_id, considered_jinfos), stmt);
        }

        OGSQL_RESTORE_STACK(stmt);
    }

    return OG_SUCCESS;
}

static status_t sql_build_base_jtable_path(join_assist_t *ja, sql_table_t *table, sql_join_table_t *jtable)
{
    if (table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE) {
        if (table->select_ctx->plan != NULL) {
            sql_join_node_t* jnode;
            OG_RETURN_IFERR(sql_create_join_node(ja->stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &jnode));
            jnode->cost.cost = table->select_ctx->plan->cost;
            jnode->cost.card = table->select_ctx->plan->rows;
            OG_RETURN_IFERR(sql_jtable_add_path(ja->stmt, jtable, jnode));
        } else {
            OG_RETURN_IFERR(sql_build_subselect_path(ja->pa, table, jtable));
        }
        return OG_SUCCESS;
    }

    cond_tree_t* cond = NULL;

    if (jtable->join_info != NULL) {
        for (uint32 i = 0; i < jtable->join_info->count; i++) {
            tbl_join_info_t* jinfo = (tbl_join_info_t *)cm_galist_get(jtable->join_info, i);
            if (jinfo->cond == NULL || (jinfo->cond->type != COND_NODE_AND && jinfo->cond->type != COND_NODE_OR &&
                jinfo->cond->type != COND_NODE_COMPARE)) {
                continue;
            }

            if (!jinfo->jinfo_flag) {
                continue;
            }

            if (cond == NULL) {
                sql_create_cond_tree(ja->stmt->context, &cond);
            }
            sql_add_cond_node(cond, jinfo->cond);
        }
    }

    OG_RETURN_IFERR(sql_check_table_indexable(ja->stmt, ja->pa, table, cond));
    jtable->rows = table->card;

    sql_join_node_t* jnode;
    OG_RETURN_IFERR(sql_create_join_node(ja->stmt, JOIN_TYPE_NONE, table, NULL, NULL, NULL, &jnode));
    sql_pre_init_jtable_cost(table);
    sql_init_sql_join_node_cost(jnode);
    SQL_LOG_OPTINFO(ja->stmt, "[CBO]Add jpath oper:%d, type:%d, cost:%f, startup:%f",
        jnode->oper, jnode->type, jnode->cost.cost, jnode->cost.startup_cost);
    OG_RETURN_IFERR(sql_jtable_add_path(ja->stmt, jtable, jnode));

    /* generate parameterized path from jtable->join_info which contains join conditions */
    OG_RETURN_IFERR(generate_parameterized_paths(ja, jtable, table));
    return OG_SUCCESS;
}

static bool32 check_json_table_conflict_with_normal(join_assist_t *ja, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2)
{
    join_tbl_bitmap_t rely_tables_rel;
    sql_bitmap_init(&rely_tables_rel);
    int tab_id;
    BITMAP_FOREACH(tab_id, &jtbl1->table_ids) {
        if (tab_id >= ja->table_count) {
            break;
        }
        sql_table_t *tmp_table = ja->pa->tables[tab_id];
        json_table_info_t *get_json_table_info = tmp_table->json_table_info;
        if (get_json_table_info != NULL) {
            if (get_json_table_info->depend_table_count > BITMAP_WORD_COUNT) {
                break;
            }
            for (uint32 j = 0; j < get_json_table_info->depend_table_count; j++) {
                sql_bitmap_setbit(get_json_table_info->depend_tables[j], &rely_tables_rel);
            }
        }
    }

    return sql_bitmap_overlap(&rely_tables_rel, &jtbl2->table_ids);
}

static bool sql_jtable_check_push_down(sql_join_table_t *jtbl1, sql_join_table_t *jtbl2)
{
    join_tbl_bitmap_t *other_tables;
    sql_join_table_t *tmp_jtable = NULL;

    if (jtbl1->push_down_join && !jtbl2->push_down_join && jtbl1->join_info != NULL) {
        other_tables = &jtbl2->table_ids;
        tmp_jtable = jtbl1;
    } else if (!jtbl1->push_down_join && jtbl2->push_down_join && jtbl2->join_info != NULL) {
        other_tables = &jtbl1->table_ids;
        tmp_jtable = jtbl2;
    } else {
        return OG_FALSE;
    }

    if (tmp_jtable->push_down_refs == NULL) {
        return OG_FALSE;
    }

    join_tbl_bitmap_t push_down_cond_tbls;
    sql_bitmap_init(&push_down_cond_tbls);
    for (uint32 i = 0; i < tmp_jtable->push_down_refs->count; i++) {
        parent_ref_t *ref = (parent_ref_t *)cm_galist_get(tmp_jtable->push_down_refs, i);
        sql_bitmap_add_member(ref->tab, &push_down_cond_tbls);
    }

    return !sql_bitmap_subset(&push_down_cond_tbls, other_tables);
}

static bool sql_jtable_check_cond_restrict(sql_join_table_t *jtbl1, sql_join_table_t *jtbl2)
{
    if (jtbl1->join_info == NULL && jtbl2->join_info == NULL) {
        return OG_FALSE;
    }

    galist_t *join_list = NULL;
    join_tbl_bitmap_t *other_tables;

    if (jtbl2->join_info == NULL || (jtbl1->join_info != NULL && jtbl1->join_info->count <= jtbl2->join_info->count)) {
        join_list = jtbl1->join_info;
        other_tables = &jtbl2->table_ids;
    } else {
        join_list = jtbl2->join_info;
        other_tables = &jtbl1->table_ids;
    }

    for (uint32 i = 0; i < join_list->count; i++) {
        tbl_join_info_t* tmp_join_info = (tbl_join_info_t *)cm_galist_get(join_list, i);
        if (sql_bitmap_overlap(&tmp_join_info->table_ids, other_tables) == OG_TRUE) {
            return OG_TRUE; // there is join relation between jtbl1 and jtbl2
        }
    }
    return OG_FALSE;
}

static bool32 sql_jtable_join_is_legal(join_assist_t *ja, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2,
                                         join_tbl_bitmap_t *join_tables_ids, bool *out_reverse,
                                         special_join_info_t **out_sjoininfo)
{
    special_join_info_t *match_sjinfo = NULL;
    bool reverse = false;
    bool must_be_leftjoin = false;

    bilist_node_t *info_node = cm_bilist_head(&ja->join_info_list);
    for (; info_node != NULL; info_node = BINODE_NEXT(info_node)) {
        special_join_info_t *sjoininfo = BILIST_NODE_OF(special_join_info_t, info_node, bilist_node);

        /* input has an intersection with SJ's min-RHS, so this SJ cannot be skipped */
        if (!sql_bitmap_overlap(&sjoininfo->min_righthand, join_tables_ids)) {
            continue;
        }

        /* The above branch ensures that the current join has an intersection with SJ's min-RHS:
         * There are two cases here: (1) the current join is entirely a subset of SJ's min-RHS, completely on one side;
         * (2) not a subset */
        if (sql_bitmap_subset(join_tables_ids, &sjoininfo->min_righthand)) {
            continue;
        }

        /* Any input fully contains the relations of the current SJ -> already processed earlier */
        if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl1->table_ids) &&
            sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl1->table_ids)) {
            continue;
        }
        if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl2->table_ids) &&
            sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl2->table_ids)) {
            continue;
        }

        if (sjoininfo->jointype == JOIN_TYPE_SEMI) {
            if (sql_bitmap_subset(&sjoininfo->syn_righthand, &jtbl1->table_ids) &&
                !sql_bitmap_same(&sjoininfo->syn_righthand, &jtbl1->table_ids)) {
                continue;
            }
            if (sql_bitmap_subset(&sjoininfo->syn_righthand, &jtbl2->table_ids) &&
                !sql_bitmap_same(&sjoininfo->syn_righthand, &jtbl2->table_ids)) {
                continue;
            }
        }

        /* normal case */
        if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl1->table_ids) &&
            sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl2->table_ids)) {
            if (match_sjinfo != NULL) {
                return OG_FALSE;
            }
            match_sjinfo = sjoininfo;
            reverse = false;
        } else if (sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl1->table_ids) &&
                   sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl2->table_ids)) {
            if (match_sjinfo != NULL) {
                return OG_FALSE;
            }
            match_sjinfo = sjoininfo;
            reverse = true;
        } else {
            /* special case: A left join (B inner join C) left join D */
            if (sql_bitmap_overlap(&jtbl1->table_ids, &sjoininfo->min_righthand) &&
                sql_bitmap_overlap(&jtbl2->table_ids, &sjoininfo->min_righthand)) {
                continue;
            }

            if (sjoininfo->jointype != JOIN_TYPE_LEFT ||
                sql_bitmap_overlap(join_tables_ids, &sjoininfo->min_lefthand)) {
                return OG_FALSE;
            }

            must_be_leftjoin = true;
        }
    }

    if (must_be_leftjoin &&
        (match_sjinfo == NULL || match_sjinfo->jointype != JOIN_TYPE_LEFT || !match_sjinfo->lhs_strict)) {
        return OG_FALSE;
    }

    *out_sjoininfo = match_sjinfo;
    *out_reverse = reverse;
    return OG_TRUE;
}

static bool sql_has_legal_joinclause(join_assist_t *ja, sql_join_table_t *jtbl1)
{
    bilist_node_t *node = NULL;
    bilist_t *dp = ja->join_tbl_level;
    BILIST_FOREACH(node, dp[1]) {
        sql_join_table_t *jtbl2 = BILIST_NODE_OF(sql_join_table_t, node, bilist_node);

        if (sql_bitmap_overlap(&jtbl1->table_ids, &jtbl2->table_ids))
            continue;

        if (sql_jtable_check_push_down(jtbl1, jtbl2)) {
            continue;
        }

        if (sql_jtable_check_cond_restrict(jtbl1, jtbl2)) {
            join_tbl_bitmap_t table_ids;
            sql_bitmap_init(&table_ids);
            sql_bitmap_union(&jtbl2->table_ids, &jtbl2->table_ids, &table_ids);
            special_join_info_t* sjoininfo = NULL;
            bool reversed = false;
            if (!sql_jtable_join_is_legal(ja, jtbl1, jtbl2, &table_ids, &reversed, &sjoininfo)) {
                return true;
            }
        }
    }
    return false;
}

static bool sql_jtable_check_order_restrict(join_assist_t *ja, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2)
{
    bool result = false;

    bilist_node_t *info_node = cm_bilist_head(&ja->join_info_list);
    for (; info_node != NULL; info_node = BINODE_NEXT(info_node)) {
        special_join_info_t *sjoininfo = BILIST_NODE_OF(special_join_info_t, info_node, bilist_node);

        if (sjoininfo->jointype == JOIN_TYPE_FULL) {
            continue;
        }

        if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl1->table_ids) &&
            sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl2->table_ids)) {
            result = true;
            break;
        }
        if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl2->table_ids) &&
            sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl1->table_ids)) {
            result = true;
            break;
        }
        
        if (sql_bitmap_overlap(&sjoininfo->min_righthand, &jtbl1->table_ids) &&
            sql_bitmap_overlap(&sjoininfo->min_righthand, &jtbl2->table_ids)) {
            result = true;
            break;
        }

        if (sql_bitmap_overlap(&sjoininfo->min_lefthand, &jtbl1->table_ids) &&
            sql_bitmap_overlap(&sjoininfo->min_lefthand, &jtbl2->table_ids)) {
            result = true;
            break;
        }
    }

    if (result) {
        if (sql_has_legal_joinclause(ja, jtbl1) || sql_has_legal_joinclause(ja, jtbl2))
            result = false;
    }

    return result;
}

static bool sql_jtable_has_order_restrict(join_assist_t *ja, sql_join_table_t *jtbl)
{
    bilist_node_t *info_node = cm_bilist_head(&ja->join_info_list);
    for (; info_node != NULL; info_node = BINODE_NEXT(info_node)) {
        special_join_info_t *sjoininfo = BILIST_NODE_OF(special_join_info_t, info_node, bilist_node);

        if (sjoininfo->jointype == JOIN_TYPE_FULL) {
            continue;
        }
        
        if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl->table_ids) &&
            sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl->table_ids))
            continue;

        if (sql_bitmap_overlap(&sjoininfo->min_lefthand, &jtbl->table_ids) ||
            sql_bitmap_overlap(&sjoininfo->min_righthand, &jtbl->table_ids))
            return true;
    }
    return false;
}

static void sql_build_join_tbl_hash(join_assist_t *ja)
{
    cm_oamap_init(&ja->join_tbl_hash, JOINTBL_HASH_INIT_SIZE, sql_oamap_bitmap_compare,
        ja->stmt->context, sql_alloc_mem);

    for (int i = 0; i < ja->join_tbl_list.count; i++) {
        sql_join_table_t *join_tbl = (sql_join_table_t *)cm_galist_get(&ja->join_tbl_list, i);
        cm_oamap_insert(&ja->join_tbl_hash, sql_hash_bitmap((join_tbl_bitmap_t *)&join_tbl->table_ids),
                        &join_tbl->table_ids, join_tbl);
    }

    // In DP algorithm, join_tbl_list is no longer needed at this point, so we clean it up here.
    cm_galist_clean(&ja->join_tbl_list);
}

static bool sql_jass_find_base_table(join_assist_t *ja, join_tbl_bitmap_t *table_ids, sql_join_table_t **jtable)
{
    for (uint32 i = 0; i < ja->table_count; i++) {
        if (sql_bitmap_same(&ja->base_jtables[i]->table_ids, table_ids)) {
            *jtable = ja->base_jtables[i];
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static bool sql_jass_find_base_table_id(join_assist_t *ja, join_tbl_bitmap_t *table_ids, uint32 *table_id)
{
    for (uint32 i = 0; i < ja->table_count; i++) {
        if (sql_bitmap_same(&ja->base_jtables[i]->table_ids, table_ids)) {
            *table_id = i;
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

/*
 * find jtable in hash-table or list
 */
static bool sql_jass_find_join_table(join_assist_t *ja, join_tbl_bitmap_t *table_ids, sql_join_table_t **jtable)
{
    if (cm_oamap_size(&ja->join_tbl_hash) == 0 && ja->join_tbl_list.count > THRESHOLD_JOINTBL_LIST) {
        sql_build_join_tbl_hash(ja);
    }

    if (cm_oamap_size(&ja->join_tbl_hash) > 0) {
        sql_join_table_t *join_tbl = (sql_join_table_t *)cm_oamap_lookup(&ja->join_tbl_hash,
            sql_hash_bitmap((join_tbl_bitmap_t *)table_ids), table_ids);
        if (join_tbl) {
            *jtable = join_tbl;
            return OG_TRUE;
        }
    } else {
        for (int i = 0; i < ja->join_tbl_list.count; i++) {
            sql_join_table_t *join_tbl = (sql_join_table_t *)cm_galist_get(&ja->join_tbl_list, i);
            if (sql_oamap_bitmap_compare((void *)(&join_tbl->table_ids), (void *)table_ids) == OG_TRUE) {
                *jtable = join_tbl;
                return OG_TRUE;
            }
        }
    }
    return OG_FALSE;
}

bool sql_jass_find_jtable(join_assist_t *ja, join_tbl_bitmap_t *table_ids, sql_join_table_t **jtable)
{
    if (sql_bitmap_empty(table_ids)) {
        return OG_FALSE;
    }

    if (sql_bitmap_is_multi(table_ids)) {
        return sql_jass_find_join_table(ja, table_ids, jtable);
    } else {
        return sql_jass_find_base_table(ja, table_ids, jtable);
    }

    return OG_FALSE;
}

static status_t sql_build_join_restrict(join_assist_t *ja,
    sql_join_table_t *jtable, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2,
    galist_t** out_restricts)
{
    galist_t* restricts = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(galist_t), (void **)&restricts));
    cm_galist_init(restricts, ja->stmt->context, sql_alloc_mem);
    *out_restricts = restricts;

    if (jtbl1->join_info != NULL) {
        for (uint32 i = 0; i < jtbl1->join_info->count; i++) {
            tbl_join_info_t* join_info = (tbl_join_info_t *)cm_galist_get(jtbl1->join_info, i);
            if (sql_bitmap_subset(&join_info->table_ids, &jtable->table_ids)) {
                OG_RETURN_IFERR(sql_jinfo_list_append_unique(ja, &restricts, join_info));
            }
        }
    }

    if (jtbl2->join_info != NULL) {
        for (uint32 j = 0; j < jtbl2->join_info->count; j++) {
            tbl_join_info_t* join_info = (tbl_join_info_t *)cm_galist_get(jtbl2->join_info, j);
            if (sql_bitmap_subset(&join_info->table_ids, &jtable->table_ids)) {
                OG_RETURN_IFERR(sql_jinfo_list_append_unique(ja, &restricts, join_info));
            }
        }
    }

    return OG_SUCCESS;
}

static status_t sql_build_join_info(join_assist_t *ja,
    sql_join_table_t *jtable, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2)
{
    if (jtbl1->join_info != NULL) {
        for (uint32 i = 0; i < jtbl1->join_info->count; i++) {
            tbl_join_info_t* join_info = (tbl_join_info_t *)cm_galist_get(jtbl1->join_info, i);
            if (!sql_bitmap_subset(&join_info->table_ids, &jtable->table_ids)) {
                OG_RETURN_IFERR(sql_jinfo_list_append_unique(ja, &jtable->join_info, join_info));
            }
        }
    }

    if (jtbl2->join_info != NULL) {
        for (uint32 j = 0; j < jtbl2->join_info->count; j++) {
            tbl_join_info_t* join_info = (tbl_join_info_t *)cm_galist_get(jtbl2->join_info, j);
            if (!sql_bitmap_subset(&join_info->table_ids, &jtable->table_ids)) {
                OG_RETURN_IFERR(sql_jinfo_list_append_unique(ja, &jtable->join_info, join_info));
            }
        }
    }

    return OG_SUCCESS;
}

static status_t sql_build_join_cond_tree(join_assist_t *ja, galist_t* restricts, sql_join_type_t jointype)
{
    ja->filter = NULL;
    ja->join_cond = NULL;
    if (restricts == NULL || restricts->count == 0) {
        return OG_SUCCESS;
    }

    cond_tree_t* filter_cond = NULL;
    cond_tree_t* join_cond = NULL;
    for (uint32 i = 0; i < restricts->count; i++) {
        tbl_join_info_t* join_info = (tbl_join_info_t *)cm_galist_get(restricts, i);
        if (jointype == JOIN_TYPE_INNER) {
            OG_RETURN_IFERR(sql_add_cond_node_with_init(ja, &filter_cond, join_info->cond));
        } else {
            if (join_info->jinfo_flag & COND_IS_FILTER) {
                OG_RETURN_IFERR(sql_add_cond_node_with_init(ja, &filter_cond, join_info->cond));
            } else if (join_info->jinfo_flag & COND_IS_JOIN_COND) {
                OG_RETURN_IFERR(sql_add_cond_node_with_init(ja, &join_cond, join_info->cond));
            }
        }
    }

    if (filter_cond != NULL) {
        ja->filter = filter_cond;
    }

    if (join_cond != NULL) {
        ja->join_cond = join_cond;
    }

    return OG_SUCCESS;
}

/*
* create a JOIN-jtable by two jtable, and build there join restricts
* maybe jtable already exist, just find it.
*/
static status_t sql_create_join_jtable(join_assist_t *ja, join_tbl_bitmap_t *table_ids,
    sql_join_table_t *jtbl1, sql_join_table_t *jtbl2, special_join_info_t *sjoininfo,
    sql_join_table_t** out_jtable, galist_t** out_restricts)
{
    sql_join_table_t* jtable;
    galist_t* restricts = NULL;

    if (sql_jass_find_join_table(ja, table_ids, &jtable) != OG_FALSE) {
        OG_RETURN_IFERR(sql_build_join_restrict(ja, jtable, jtbl1, jtbl2, &restricts));
        *out_jtable = jtable;
        *out_restricts = restricts;
        return OG_SUCCESS;
    }
    
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(sql_join_table_t), (void **)&jtable));
    *out_jtable = jtable;

    jtable->table_type = JOIN_TABLE;
    sql_bitmap_copy(table_ids, &jtable->table_ids);

    jtable->join_info = NULL;
    /* build join info and join restricts */
    OG_RETURN_IFERR(sql_build_join_info(ja, jtable, jtbl1, jtbl2));
    OG_RETURN_IFERR(sql_build_join_restrict(ja, jtable, jtbl1, jtbl2, &restricts));
    *out_restricts = restricts;

    /* store it into a hash table */
    OG_RETURN_IFERR(sql_jass_store_jtable(ja, jtable));

    /* set jtable size estimate */
    OG_RETURN_IFERR(sql_jtable_estimate_size(ja, jtable, jtbl1, jtbl2, sjoininfo, restricts));

    /* init join path list */
    cm_bilist_init(&jtable->paths);
    return OG_SUCCESS;
}

static bool sql_add_path_precheck(sql_join_table_t *jtable, double startup_cost, double total_cost)
{
    sql_join_path_t* best_path = jtable->cheapest_total_path;
    if (best_path == NULL) {
        return true;
    }

    double cost_old = best_path->cost.cost;
    double startup_cost_old = best_path->cost.startup_cost;

    if (cost_old <= total_cost && startup_cost_old <= startup_cost) {
        /* no need to build this path */
        return false;
    }
    
    return true;
}

static void sql_set_rel_path_rows(sql_join_node_t* join_tree, double rows)
{
    join_tree->cost.card = (int64)rows;
}

static status_t sql_add_nestloop_path_single(join_assist_t *ja, sql_join_table_t *jtable, sql_join_node_t* path,
    join_cost_workspace* join_cost_ws, special_join_info_t *sjoininfo)
{
    OG_RETURN_IFERR(sql_final_cost_nestloop(ja, path, join_cost_ws, sjoininfo));
    /* join row estimate */
    sql_set_rel_path_rows(path, jtable->rows);
    sql_debug_join_cost_info(ja->stmt, path, "NL", "add path");
    OG_RETURN_IFERR(sql_jtable_add_path(ja->stmt, jtable, path));
    return OG_SUCCESS;
}

static status_t sql_build_nestloop_path(join_assist_t *ja, sql_join_type_t jointype, sql_join_table_t *jtable,
    sql_join_node_t *outerpath, sql_join_node_t *innerpath, special_join_info_t *sjoininfo, galist_t* restricts,
    join_tbl_bitmap_t *param_source_rels)
{
    if (outerpath == NULL || innerpath == NULL) {
        OG_LOG_RUN_ERR("path is NULL");
        return OG_ERROR;
    }

    sql_join_node_t temp_path;
    MEMS_RETURN_IFERR(memset_s(&temp_path, sizeof(sql_join_node_t), 0, sizeof(sql_join_node_t)));
    sql_join_node_t* temp_path_p = &temp_path;
    temp_path_p->type = jointype;
    temp_path_p->left = outerpath;
    temp_path_p->right = innerpath;
    join_cost_workspace join_cost_ws;
    MEMS_RETURN_IFERR(memset_s(&join_cost_ws, sizeof(join_cost_ws), 0, sizeof(join_cost_ws)));
    
    join_tbl_bitmap_t outer_rels;
    sql_bitmap_init(&outer_rels);
    sql_bitmap_union(&outerpath->outer_rels, &innerpath->outer_rels, &outer_rels);
    sql_bitmap_delete_members(&outer_rels, &outerpath->parent->table_ids);
    /* if outer rel provides some but not all of the inner rel's paramterization, build ok. */
    if (!sql_bitmap_empty(&outer_rels) && !sql_bitmap_overlap(&outer_rels, param_source_rels) &&
        !(sql_bitmap_overlap(&innerpath->outer_rels, &outerpath->parent->table_ids) &&
        !sql_bitmap_same(&innerpath->outer_rels, &outerpath->parent->table_ids))) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_initial_cost_nestloop(ja, temp_path_p, &join_cost_ws, sjoininfo));
    if (!sql_add_path_precheck(jtable, join_cost_ws.startup_cost, join_cost_ws.total_cost)) {
        return OG_SUCCESS;
    }
    
    sql_join_node_t* path = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(sql_join_node_t), (void **)&path));
    uint32 count = outerpath->tables.count + innerpath->tables.count;
    OG_RETURN_IFERR(sql_create_array(ja->stmt->context, &path->tables, "JOIN TABLES", count));
    path->type = jointype;
    path->left = outerpath;
    path->right = innerpath;
    path->outer_rels = outer_rels;

    switch (jointype) {
        case JOIN_TYPE_CROSS:
        case JOIN_TYPE_COMMA:
        case JOIN_TYPE_INNER:
            path->oper = JOIN_OPER_NL;
            break;
        case JOIN_TYPE_LEFT:
            path->oper = JOIN_OPER_NL_LEFT;
            break;
        case JOIN_TYPE_FULL:
            path->oper = JOIN_OPER_NL_FULL;
            break;
        case JOIN_TYPE_SEMI:
            path->oper = JOIN_OPER_NL_SEMI;
            break;
        case JOIN_TYPE_ANTI:
            path->oper = JOIN_OPER_NL_ANTI;
            break;
        default:
            return OG_ERROR;
    }
    path->join_cond = ja->join_cond;
    path->filter = ja->filter;
    OG_RETURN_IFERR(sql_array_concat(&path->tables, &outerpath->tables));
    OG_RETURN_IFERR(sql_array_concat(&path->tables, &innerpath->tables));
    path->cost.startup_cost =  temp_path_p->cost.startup_cost;
    path->cost.cost =  temp_path_p->cost.cost;
    OG_RETURN_IFERR(sql_add_nestloop_path_single(ja, jtable, path, &join_cost_ws, sjoininfo));
    return OG_SUCCESS;
}

/*
 * generate all the nestloop paths for unsort outer table
 *
 */
static status_t sql_gen_unsorted_outer_nestloop_paths(join_assist_t *ja, sql_join_type_t jointype,
    sql_join_table_t *jtable, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2,
    special_join_info_t *sjoininfo, galist_t* restricts, join_tbl_bitmap_t *param_source_rels)
{
    bool nest_join_ok = true;
    // nl does not support semi-join & anti-join
    if (jointype >= JOIN_TYPE_SEMI) {
        nest_join_ok = false;
    }

    if (jointype == JOIN_TYPE_RIGHT) {
        nest_join_ok = false;
    }

    if (ja->pa->type == SQL_MERGE_NODE && sjoininfo->jointype == JOIN_TYPE_INNER &&
        sql_bitmap_same(&jtbl1->table_ids, &sjoininfo->min_lefthand)) {
        nest_join_ok = false;
    }

    bilist_node_t *outer_paths;
    BILIST_FOREACH(outer_paths, jtbl1->paths) {
        sql_join_node_t* outer_path = BILIST_NODE_OF(sql_join_node_t, outer_paths, bilist_node);
        /* todo: support unique path */
        /* todo: support materia inner table */

        /* cannot use an outer path that is parameterized by the inner rel. */
        if (sql_bitmap_overlap(&outer_path->outer_rels, &jtbl2->table_ids)) {
            continue;
        }

        if (nest_join_ok) {
            sql_join_node_t* inner_path = jtbl2->cheapest_total_path;
            OG_RETURN_IFERR(sql_build_nestloop_path(ja, jointype, jtable, outer_path, inner_path,
                sjoininfo, restricts, param_source_rels));

            bilist_node_t *inner_paths;
            BILIST_FOREACH (inner_paths, jtbl2->cheapest_parameterized_paths) {
                inner_path = BILIST_NODE_OF(sql_join_node_t, inner_paths, bilist_node);
                OG_RETURN_IFERR(sql_build_nestloop_path(ja, jointype, jtable, outer_path, inner_path,
                    sjoininfo, restricts, param_source_rels));
            }
        }
    }
    return OG_SUCCESS;
}

static inline join_oper_t sql_set_hash_join_oper(sql_join_type_t jointype)
{
    if (jointype == JOIN_TYPE_NONE) {
        OG_THROW_ERROR(ERR_INVALID_PARAMETER, "join type is none");
    }

    switch (jointype) {
        case JOIN_TYPE_LEFT:
            return JOIN_OPER_HASH_LEFT;
        case JOIN_TYPE_FULL:
            return JOIN_OPER_HASH_FULL;
        case JOIN_TYPE_SEMI:
            return JOIN_OPER_HASH_SEMI;
        case JOIN_TYPE_ANTI:
            return JOIN_OPER_HASH_ANTI;
        case JOIN_TYPE_RIGHT_SEMI:
            return JOIN_OPER_HASH_RIGHT_SEMI;
        case JOIN_TYPE_RIGHT_ANTI:
            return JOIN_OPER_HASH_RIGHT_ANTI;
        case JOIN_TYPE_ANTI_NA:
            return JOIN_OPER_HASH_ANTI_NA;
        case JOIN_TYPE_RIGHT_ANTI_NA:
            return JOIN_OPER_HASH_RIGHT_ANTI_NA;
        default:
            return JOIN_OPER_HASH;
    }
}

static status_t sql_build_hashjoin_path(join_assist_t *ja, sql_join_table_t *jtable, sql_join_type_t jointype,
    sql_join_path_t *outer_path, sql_join_path_t *inner_path, galist_t *restricts, int16* ids, uint32 clause_counts,
    join_tbl_bitmap_t *param_source_rels, special_join_info_t *sjoininfo)
{
    join_tbl_bitmap_t outer_rels;

    if (outer_path == NULL || inner_path == NULL) {
        OG_LOG_RUN_ERR("path is NULL");
        return OG_ERROR;
    }

    if (ja->join_cond == NULL && ja->filter == NULL) {
        OG_LOG_RUN_WAR("The join cond and filter are both null for hashjoin.");
        return OG_ERROR;
    }
    
    sql_bitmap_init(&outer_rels);
    sql_bitmap_union(&outer_path->outer_rels, &inner_path->outer_rels, &outer_rels);
    if (!sql_bitmap_empty(&outer_rels) && !sql_bitmap_overlap(&outer_rels, param_source_rels)) {
        return OG_SUCCESS;
    }

    sql_join_node_t temp_path;
    MEMS_RETURN_IFERR(memset_s(&temp_path, sizeof(sql_join_node_t), 0, sizeof(sql_join_node_t)));
    sql_join_node_t* temp_path_p = &temp_path;
    temp_path_p->type = jointype;
    temp_path_p->left = outer_path;
    temp_path_p->right = inner_path;
    cbo_cost_t cost_info = { 0 };
    uint64 num_nbuckets = 0;
    OG_RETURN_IFERR(sql_initial_cost_hashjoin(ja, temp_path_p, &cost_info, &num_nbuckets));
    if (!sql_add_path_precheck(jtable, cost_info.startup_cost, cost_info.cost)) {
        return OG_SUCCESS;
    }

    sql_join_node_t* path = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(sql_join_node_t), (pointer_t *)&path));
    uint32 count = outer_path->tables.count + inner_path->tables.count;
    OG_RETURN_IFERR(sql_create_array(ja->stmt->context, &path->tables, "JOIN TABLES", count));
    path->type = jointype;
    path->oper = sql_set_hash_join_oper(jointype);
    path->hash_left = OG_FALSE;
    path->left = outer_path;
    path->right = inner_path;
    path->join_cond = ja->join_cond;
    path->filter = ja->filter;

    path->cost.startup_cost =  temp_path_p->cost.startup_cost;
    path->cost.cost =  temp_path_p->cost.cost;
    path->cost.card = CBO_CARD_SAFETY_SET(jtable->rows);
    OG_RETURN_IFERR(sql_array_concat(&path->tables, &outer_path->tables));
    OG_RETURN_IFERR(sql_array_concat(&path->tables, &inner_path->tables));

    sql_final_cost_hashjoin(ja, path, &cost_info, restricts, ids, num_nbuckets, sjoininfo);
    sql_debug_join_cost_info(ja->stmt, path, "Hash", "add path");
    OG_RETURN_IFERR(sql_jtable_add_path(ja->stmt, jtable, path));
    return OG_SUCCESS;
}

static bool sql_check_hash_semi_inner(join_assist_t *ja, sql_join_table_t *inner_rel)
{
    if (inner_rel->table_type != BASE_TABLE) {
        return false;
    } else {
        uint32 id = 0;
        if (sql_jass_find_base_table_id(ja, &inner_rel->table_ids, &id)) {
            sql_table_t *inner_table = ja->pa->tables[id];
            if (inner_table->subslct_tab_usage == SUBSELECT_4_NORMAL_JOIN) {
                return false;
            }
        } else {
            OG_LOG_RUN_WAR("Can't find base table according to the inner table.");
            return false;
        }
    }

    return true;
}

static status_t sql_hashjoin_inner_outer(join_assist_t *ja, sql_join_type_t jointype,
    sql_join_table_t *jtable, sql_join_table_t *outer_rel, sql_join_table_t *inner_rel,
    special_join_info_t *sjoininfo, galist_t* restricts, join_tbl_bitmap_t *param_source_rels)
{
    if (restricts == NULL) {
        OG_LOG_RUN_WAR("Can't find any hash join clause as there is no restricts.");
        return OG_ERROR;
    }

    if (jointype == JOIN_TYPE_SEMI || jointype == JOIN_TYPE_ANTI || jointype == JOIN_TYPE_ANTI_NA) {
        if (!sql_check_hash_semi_inner(ja, inner_rel)) {
            return OG_SUCCESS;
        }
    }

    if (ja->pa->type == SQL_MERGE_NODE && sjoininfo->jointype == JOIN_TYPE_INNER &&
        sql_bitmap_same(&outer_rel->table_ids, &sjoininfo->min_lefthand)) {
        return OG_SUCCESS;
    }

    int16 *idx_of_restrics = NULL;
    OGSQL_SAVE_STACK(ja->stmt);
    RET_AND_RESTORE_STACK_IFERR(sql_stack_alloc(ja->stmt, sizeof(int16) * (restricts->count),
        (void **)&idx_of_restrics), ja->stmt);
    errno_t ret = memset_sp(idx_of_restrics, (restricts->count) * sizeof(int16), -1,
        (restricts->count) * sizeof(int16));
    knl_securec_check(ret);

    uint32 hash_clause_count = 0;
    uint32 index = 0;
    for (uint32 i = 0; i < restricts->count; i++) {
        tbl_join_info_t* tmp_jinfo = (tbl_join_info_t *)cm_galist_get(restricts, i);
        if (tmp_jinfo->cond == NULL || tmp_jinfo->cond->cmp == NULL) {
            index++;
            continue;
        }

        if (tmp_jinfo->cond->type != COND_NODE_COMPARE || tmp_jinfo->cond->cmp->type != CMP_TYPE_EQUAL) {
            index++;
            continue;
        }

        if (!sql_cmp_can_used_by_hash(tmp_jinfo->cond->cmp)) {
            index++;
            continue;
        }

        if (sql_bitmap_empty(&tmp_jinfo->table_ids_left) || sql_bitmap_empty(&tmp_jinfo->table_ids_right) ||
            sql_bitmap_overlap(&tmp_jinfo->table_ids_left, &tmp_jinfo->table_ids_right)) {
            index++;
            continue;
        }

        if ((sql_bitmap_subset(&tmp_jinfo->table_ids_left, &inner_rel->table_ids) &&
            sql_bitmap_subset(&tmp_jinfo->table_ids_right, &outer_rel->table_ids)) ||
            (sql_bitmap_subset(&tmp_jinfo->table_ids_left, &outer_rel->table_ids) &&
            sql_bitmap_subset(&tmp_jinfo->table_ids_right, &inner_rel->table_ids))) {
            // add to hash clause list
            idx_of_restrics[hash_clause_count++] = index;
            index++;
        }
    }

    if (hash_clause_count != 0) {
        sql_join_path_t *outer_spath = outer_rel->cheapest_startup_path;
        sql_join_path_t *outer_tpath = outer_rel->cheapest_total_path;
        sql_join_path_t *inner_tpath = inner_rel->cheapest_total_path;
        RET_AND_RESTORE_STACK_IFERR(sql_build_hashjoin_path(ja, jtable, jointype, outer_tpath, inner_tpath,
            restricts, idx_of_restrics, hash_clause_count, param_source_rels, sjoininfo), ja->stmt);
        if (outer_spath != NULL && outer_spath != outer_tpath) {
            RET_AND_RESTORE_STACK_IFERR(sql_build_hashjoin_path(ja, jtable, jointype, outer_spath, inner_tpath,
                restricts, idx_of_restrics, hash_clause_count, param_source_rels, sjoininfo), ja->stmt);
        }

        bilist_node_t *outer_paths;
        BILIST_FOREACH (outer_paths, outer_rel->cheapest_parameterized_paths) {
            sql_join_path_t *outer_path = BILIST_NODE_OF(sql_join_node_t, outer_paths, bilist_node);

            if (outer_path == NULL) {
                continue;
            }

            if (sql_bitmap_overlap(&outer_path->outer_rels, &inner_rel->table_ids)) {
                continue;
            }

            bilist_node_t *inner_paths;
            BILIST_FOREACH (inner_paths, inner_rel->cheapest_parameterized_paths) {
                sql_join_path_t *inner_path = BILIST_NODE_OF(sql_join_node_t, inner_paths, bilist_node);

                if (inner_path == NULL) {
                    continue;
                }

                if (sql_bitmap_overlap(&inner_path->outer_rels, &outer_rel->table_ids)) {
                    continue;
                }
                RET_AND_RESTORE_STACK_IFERR(sql_build_hashjoin_path(ja, jtable, jointype, outer_path, inner_path,
                    restricts, idx_of_restrics, hash_clause_count, param_source_rels, sjoininfo), ja->stmt);
            }
        }
    } else {
        OG_LOG_RUN_WAR("Can't find any hash join clause in the restricts.");
    }
    OGSQL_RESTORE_STACK(ja->stmt);
    return OG_SUCCESS;
}

static status_t sql_jtable_create_paths(join_assist_t *ja, sql_join_type_t jointype,
    sql_join_table_t *jtable, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2,
    special_join_info_t *sjoininfo, galist_t *restricts)
{
    if (check_json_table_conflict_with_normal(ja, jtbl1, jtbl2)) {
        OG_LOG_RUN_WAR("Current table and json table which it depend on have a order conflict.");
        return OG_SUCCESS;
    }

    bilist_node_t *sj;
    join_tbl_bitmap_t param_source_rels;
    sql_bitmap_init(&param_source_rels);
    BILIST_FOREACH (sj, ja->join_info_list) {
        special_join_info_t* ja_sjinfo = BILIST_NODE_OF(special_join_info_t, sj, bilist_node);

        if (sql_bitmap_overlap(&jtable->table_ids, &ja_sjinfo->min_righthand) &&
            !sql_bitmap_overlap(&jtable->table_ids, &ja_sjinfo->min_lefthand)) {
            join_tbl_bitmap_t tmp_bitmap;
            sql_bitmap_copy(&tmp_bitmap, &ja->all_table_ids);
            sql_bitmap_delete_members(&tmp_bitmap, &ja_sjinfo->min_righthand);
            sql_bitmap_union(&param_source_rels, &tmp_bitmap, &param_source_rels);
        }

        if (jointype == JOIN_TYPE_FULL && sql_bitmap_overlap(&jtable->table_ids, &ja_sjinfo->min_lefthand) &&
            !sql_bitmap_overlap(&jtable->table_ids, &ja_sjinfo->min_righthand)) {
            join_tbl_bitmap_t tmp_bitmap;
            sql_bitmap_copy(&tmp_bitmap, &ja->all_table_ids);
            sql_bitmap_delete_members(&tmp_bitmap, &ja_sjinfo->min_lefthand);
            sql_bitmap_union(&param_source_rels, &tmp_bitmap, &param_source_rels);
        }
    }

    sql_gen_unsorted_outer_nestloop_paths(ja, jointype, jtable, jtbl1, jtbl2, sjoininfo, restricts,
        &param_source_rels);
    sql_hashjoin_inner_outer(ja, jointype, jtable, jtbl1, jtbl2, sjoininfo, restricts, &param_source_rels);
    return OG_SUCCESS;
}

static status_t sql_synthesize_new_jtable(join_assist_t *ja, sql_join_table_t *jtbl1, sql_join_table_t *jtbl2)
{
    sql_join_table_t *jtable = NULL;
    special_join_info_t* sjoininfo = NULL;
    galist_t* restricts = NULL;
    join_tbl_bitmap_t table_ids;
    sql_bitmap_union(&jtbl1->table_ids, &jtbl2->table_ids, &table_ids);
    
    bool reversed = false;
    if (!sql_jtable_join_is_legal(ja, jtbl1, jtbl2, &table_ids, &reversed, &sjoininfo)) {
        return OG_SUCCESS;
    }
    if (reversed) {
        sql_join_table_t *tmp_jtbl = jtbl1;
        jtbl1 = jtbl2;
        jtbl2 = tmp_jtbl;
        if (sjoininfo != NULL) {
            sjoininfo->reversed = true;
        }
    }

    // generate inner join info
    special_join_info_t inner_joininfo;
    if (sjoininfo == NULL) {
        sjoininfo = &inner_joininfo;
        sql_bitmap_copy(&jtbl1->table_ids, &sjoininfo->min_lefthand);
        sql_bitmap_copy(&jtbl2->table_ids, &sjoininfo->min_righthand);
        sql_bitmap_copy(&jtbl1->table_ids, &sjoininfo->syn_lefthand);
        sql_bitmap_copy(&jtbl2->table_ids, &sjoininfo->syn_righthand);
        sjoininfo->jointype = JOIN_TYPE_INNER;
        sjoininfo->lhs_strict = false;
        sjoininfo->delay_upper_joins = false;
        sjoininfo->reversed = false;
    }

    if (sql_create_join_jtable(ja, &table_ids, jtbl1, jtbl2, sjoininfo, &jtable, &restricts) != OG_SUCCESS) {
        OG_LOG_RUN_WAR("CBO dp failed to create join jtable, jtbl1:%d, jtbl2:%d", jtbl1->table_ids.words[0],
            jtbl2->table_ids.words[0]);
        return OG_ERROR;
    }

    // generate join path by JOIN TYPE, and add join path to join_tbl
    switch (sjoininfo->jointype) {
        case JOIN_TYPE_INNER:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_INNER));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_INNER, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_INNER, jtable, jtbl2, jtbl1, sjoininfo, restricts));
            break;
        case JOIN_TYPE_LEFT:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_LEFT));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_LEFT, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            break;
        case JOIN_TYPE_COMMA:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_COMMA));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_COMMA, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_COMMA, jtable, jtbl2, jtbl1, sjoininfo, restricts));
            break;
        case JOIN_TYPE_CROSS:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_CROSS));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_CROSS, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_CROSS, jtable, jtbl2, jtbl1, sjoininfo, restricts));
            break;
        case JOIN_TYPE_FULL:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_FULL));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_FULL, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_FULL, jtable, jtbl2, jtbl1, sjoininfo, restricts));
            break;
        case JOIN_TYPE_SEMI:
            if (sql_bitmap_subset(&sjoininfo->min_lefthand, &jtbl1->table_ids) &&
                sql_bitmap_subset(&sjoininfo->min_righthand, &jtbl2->table_ids)) {
                OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_SEMI));
                OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_SEMI, jtable, jtbl1, jtbl2, sjoininfo,
                                                        restricts));
                OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_SEMI, jtable, jtbl2, jtbl1, sjoininfo,
                                                        restricts));
            }
            break;
        case JOIN_TYPE_ANTI:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_ANTI));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_ANTI, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_ANTI, jtable, jtbl2, jtbl1, sjoininfo, restricts));
            break;
        case JOIN_TYPE_ANTI_NA:
            OG_RETURN_IFERR(sql_build_join_cond_tree(ja, restricts, JOIN_TYPE_ANTI_NA));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_ANTI_NA, jtable, jtbl1, jtbl2, sjoininfo, restricts));
            OG_RETURN_IFERR(sql_jtable_create_paths(ja, JOIN_TYPE_ANTI_NA, jtable, jtbl2, jtbl1, sjoininfo, restricts));
            break;
        default:
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_jass_dp_advance(join_assist_t *ja)
{
    bilist_t *dp = ja->join_tbl_level;
    uint32 level_curr = ja->curr_level;

    bilist_node_t *node = NULL;

    /*
     * 1. left-side and right-side tree
     *  DP state transition equation:
     *      level(curr) = level(1) + level(curr - 1)
     */
    uint32 level_prev = level_curr - 1;
    BILIST_FOREACH(node, dp[level_prev]) {
        sql_join_table_t *jtbl1 = BILIST_NODE_OF(sql_join_table_t, node, bilist_node);
        bilist_node_t *other_jtables = NULL;

        if (level_prev == 1) {
            other_jtables = BINODE_NEXT(node);
        } else { /* when level  >= 2, consider all initial rels */
            other_jtables = cm_bilist_head(&dp[1]);
        }

        for (bilist_node_t *n = other_jtables; n != NULL; n = BINODE_NEXT(n)) {
            sql_join_table_t *jtbl2 = BILIST_NODE_OF(sql_join_table_t, n, bilist_node);
            // when a table_ids overlap another table_ids, then skip it
            if (sql_bitmap_overlap(&jtbl1->table_ids, &jtbl2->table_ids) == OG_TRUE) {
                continue;
            }

            if (sql_jtable_check_push_down(jtbl1, jtbl2)) {
                continue;
            }

            // when the join_table has no join relation with another one, then skip it
            if (sql_jtable_check_cond_restrict(jtbl1, jtbl2) ||
                sql_jtable_check_order_restrict(ja, jtbl1, jtbl2)) {
                OG_RETURN_IFERR(sql_synthesize_new_jtable(ja, jtbl1, jtbl2));
            }
        }
    }

    /*
     * 2. bushy tree
     *  DP state transition equation:
     *      level(curr) = level(i) + level(j),  {i + j = curr, 2 <= i <= j}
     */
    int level_i, level_j;
    for (level_i = 2; ; level_i++) {
        level_j = level_curr - level_i;
        if (level_i > level_j) {
            break;
        }

        BILIST_FOREACH(node, dp[level_i]) {
            sql_join_table_t *jtbl1 = BILIST_NODE_OF(sql_join_table_t, node, bilist_node);
            bilist_node_t *other_jtables = NULL;

            if ((jtbl1->join_info == NULL || jtbl1->join_info->count == 0) &&
                !sql_jtable_has_order_restrict(ja, jtbl1)) {
                continue;
            }

            if (level_i == level_j)
                other_jtables = BINODE_NEXT(node);
            else
                other_jtables = cm_bilist_head(&dp[level_j]);

            for (bilist_node_t *n = other_jtables; n != NULL; n = BINODE_NEXT(n)) {
                sql_join_table_t *jtbl2 = BILIST_NODE_OF(sql_join_table_t, n, bilist_node);
                if (sql_bitmap_overlap(&jtbl1->table_ids, &jtbl2->table_ids)) {
                    continue;
                }

                if (sql_jtable_check_push_down(jtbl1, jtbl2)) {
                    continue;
                }

                if (sql_jtable_check_cond_restrict(jtbl1, jtbl2) ||
                    sql_jtable_check_order_restrict(ja, jtbl1, jtbl2)) {
                    OG_RETURN_IFERR(sql_synthesize_new_jtable(ja, jtbl1, jtbl2));
                }
            }
        }
    }

    /*
     * 3. if failed to find any usable join-table, forcea set of cartesian-product join-tables to
     * be generated
     */
    if (dp[level_curr].count == 0) {
        BILIST_FOREACH(node, dp[level_prev]) {
            sql_join_table_t *jtbl1 = BILIST_NODE_OF(sql_join_table_t, node, bilist_node);
            bilist_node_t *node2 = NULL;
            BILIST_FOREACH(node2, dp[1]) {
                sql_join_table_t *jtbl2 = BILIST_NODE_OF(sql_join_table_t, node2, bilist_node);
                if (sql_bitmap_overlap(&jtbl1->table_ids, &jtbl2->table_ids)) {
                    continue;
                }
                OG_RETURN_IFERR(sql_synthesize_new_jtable(ja, jtbl1, jtbl2));
            }
        }

        if (dp[level_curr].count == 0 && ja->join_info_list.count == 0) {
            OG_LOG_RUN_WAR("CBO dp can't find any usable join-table:%d", level_curr);
            return OG_ERROR;
        }
    }
    
    return OG_SUCCESS;
}

static status_t sql_create_grouped_join_tree(join_assist_t *ja, sql_join_node_t **_out_join_root)
{
    // build first level, the base join tables
    ja->curr_level = 1;
    join_grouped_table_t* current_grouped = ja->dp_grouped_table;
    galist_t* group_items = current_grouped->group_items;
    uint32 table_count = 0;
    
    for (uint32 i = 0; i < group_items->count; i++) {
        join_group_or_table_item* item_cell = (join_group_or_table_item*)cm_galist_get(group_items, i);
        if (item_cell->type == IS_BASE_TABLE_ITEM) {
            sql_join_table_t *jtable = NULL;    // sql_join_table_t is brief of sql_table_t
            sql_table_t *table_temp = (sql_table_t *)item_cell->item;
            OG_RETURN_IFERR(sql_create_base_jtable(ja, table_temp, &jtable));
            ja->base_jtables[table_temp->id] = jtable;
            sql_bitmap_add_member(table_temp->id, &ja->all_table_ids);
            table_count++;
        }
    }

    // add pre group jtable result to do dp
    for (uint32 i = 0; i < group_items->count; i++) {
        join_group_or_table_item* item_cell = (join_group_or_table_item*)cm_galist_get(group_items, i);
        if (item_cell->type == IS_GROUP_TABLE_ITEM) {
            join_grouped_table_t *group_temp = (join_grouped_table_t *)item_cell->item;
            if (group_temp->group_result == NULL) {
                return OG_ERROR;
            }
            cm_bilist_add_tail(&(group_temp->group_result->bilist_node), &ja->join_tbl_level[ja->curr_level]);
            ja->base_jtables[group_temp->group_id] = group_temp->group_result;
            table_count++;
        }
    }

    // generate join info and special join info
    if (ja->cond != NULL && ja->cond->root != NULL) {
        OG_RETURN_IFERR(sql_extract_filters_to_jtables(ja, NULL, ja->cond->root, true, NULL, NULL));
    }
    OG_RETURN_IFERR(sql_generate_sjoininfo(current_grouped->join_node, ja));

    for (uint32 i = 0; i < group_items->count; i++) {
        join_group_or_table_item* item_cell = (join_group_or_table_item*)cm_galist_get(group_items, i);
        if (item_cell->type == IS_BASE_TABLE_ITEM) {
            sql_table_t *table_temp = (sql_table_t *)item_cell->item;
            OG_RETURN_IFERR(sql_build_base_jtable_path(ja, table_temp, ja->base_jtables[table_temp->id]));
        }
    }

    // dp to search all join tables and join path
    for (uint32 level = 2; level <= table_count; level++) {
        ja->curr_level = level;
        OG_RETURN_IFERR(sql_jass_dp_advance(ja));
    }

    // highest level is the result level, must only one jtable.
    bilist_node_t *n = cm_bilist_head(&ja->join_tbl_level[table_count]);
    sql_join_table_t* jtable = BILIST_NODE_OF(sql_join_table_t, n, bilist_node);
    if (jtable == NULL) {
        OG_LOG_RUN_WAR("CBO jtable is NULL.");
        return OG_ERROR;
    }
    
    current_grouped->group_result = jtable;
    sql_join_node_t* result_jpath = jtable->cheapest_total_path;
    if (result_jpath == NULL) {
        OG_LOG_RUN_WAR("CBO result jpath is NULL.");
        return OG_ERROR;
    }
    *_out_join_root = result_jpath;

    // clear dp
    for (uint32 i = 0; i <= table_count; i++) {
        cm_bilist_init(&ja->join_tbl_level[i]);
    }

    return OG_SUCCESS;
}

static status_t sql_create_grouped_join_tree_recuse(join_assist_t *ja, join_grouped_table_t* node_join_grouped_table,
    sql_join_node_t **_out_join_root)
{
    for (int i = 0; i < node_join_grouped_table->group_items->count; i++) {
        join_group_or_table_item* grouped_table =
            (join_group_or_table_item*)cm_galist_get(node_join_grouped_table->group_items, i);
        if (grouped_table->type == IS_GROUP_TABLE_ITEM) {  // still a group
            join_grouped_table_t* sub_node_join_grouped_table = (join_grouped_table_t*)grouped_table->item;
            OG_RETURN_IFERR(sql_create_grouped_join_tree_recuse(ja, sub_node_join_grouped_table, _out_join_root));
        }
    }
    ja->dp_grouped_table = node_join_grouped_table;
    OG_RETURN_IFERR(sql_create_grouped_join_tree(ja, _out_join_root));
    return OG_SUCCESS;
}

static status_t sql_complete_join_path(join_assist_t *ja, sql_join_node_t *jpath)
{
    jpath->plan_id_start = ja->pa->plan_count;

    if (jpath->type == JOIN_TYPE_NONE) {
        sql_table_t *table = TABLE_OF_JOIN_LEAF(jpath);
        sql_plan_assist_set_table(ja->pa, table);
        if (table->type == SUBSELECT_AS_TABLE || table->type == WITH_AS_TABLE) {
            table->cost = jpath->cost.cost;
            table->card = jpath->cost.card;
        }
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_complete_join_path(ja, jpath->left));
    OG_RETURN_IFERR(sql_complete_join_path(ja, jpath->right));

    return OG_SUCCESS;
}

static void og_disable_index_distinct(sql_join_node_t *jnode)
{
    if (jnode->type == JOIN_TYPE_NONE) {
        return;
    }
    if (jnode->type == JOIN_TYPE_FULL) {
        sql_table_t *tbl = NULL;
        uint32 i = 0;
        while (i < jnode->tables.count) {
            tbl = (sql_table_t *)sql_array_get(&jnode->tables, i);
            CM_CLEAN_FLAG(tbl->scan_flag, RBO_INDEX_DISTINCT_FLAG);
            i++;
        }
    } else {
        og_disable_index_distinct(jnode->left);
        og_disable_index_distinct(jnode->right);
    }
}

static status_t sql_create_join_tree_new(join_assist_t *ja, sql_join_node_t **_out_join_root)
{
    OG_RETURN_IFERR(sql_group_dp_tables(ja));
    OG_RETURN_IFERR(sql_create_grouped_join_tree_recuse(ja, ja->root_grouped_table, _out_join_root));
    OG_RETURN_IFERR(sql_complete_join_path(ja, *_out_join_root));
    og_disable_index_distinct(*_out_join_root);
    return OG_SUCCESS;
}

status_t sql_build_join_tree_cost(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_join_node_t **join_root)
{
    join_assist_t ja = { 0 };
    sql_generate_join_assist(plan_ass, plan_ass->join_assist->join_node, &ja);
    OG_RETURN_IFERR(sql_generate_join_assist_new(stmt, plan_ass, &ja));
    OG_RETURN_IFERR(
        og_get_join_cond_from_table_cond(plan_ass->stmt, &plan_ass->query->tables, &plan_ass->query->tables,
            plan_ass->cond, &plan_ass->join_conds));
    OG_RETURN_IFERR(sql_create_join_tree_new(&ja, join_root));
    return OG_SUCCESS;
}