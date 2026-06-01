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
 * plan_join_merge.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/plan_join_merge.c
 *
 * -------------------------------------------------------------------------
 */

#include "plan_join_merge.h"
#include "cbo_join.h"
#include "plan_join.h"
#include "plan_scan.h"
#include "table_parser.h"
#include "plan_hint.h"

#ifdef __cplusplus
extern "C" {
#endif

static uint32 og_get_merge_join_batch_size(sql_query_t *qry)
{
    if (qry->aggrs->count || qry->sort_items->count) {
        return OG_INFINITE32;
    }
    return g_instance->attr.merge_sort_batch_size;
}

status_t og_create_merge_join_plan(sql_stmt_t *statement, plan_assist_t *p_ast, sql_join_node_t *jnode,
    plan_node_t *out_plan)
{
    out_plan->join_p.mj_pos = p_ast->join_assist->mj_plan_count;
    p_ast->join_assist->mj_plan_count++;

    if (sql_create_base_join_plan(statement, p_ast, jnode, &out_plan->join_p.left, &out_plan->join_p.right)) {
        OG_LOG_DEBUG_ERR("Failed to create base join plan.");
        cm_set_error_pos(__FILE__, __LINE__);
        return OG_ERROR;
    }

    if (sql_fill_join_info(statement, &out_plan->join_p, jnode) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to fill join info.");
        cm_set_error_pos(__FILE__, __LINE__);
        return OG_ERROR;
    }

    if (sql_create_list(statement, &out_plan->join_p.cmp_list) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to create list.");
        cm_set_error_pos(__FILE__, __LINE__);
        return OG_ERROR;
    }

    out_plan->join_p.batch_size = og_get_merge_join_batch_size(p_ast->query);

    if (sql_plan_extract_cond(statement, &out_plan->join_p, jnode) != OG_SUCCESS) {
        OG_LOG_DEBUG_ERR("Failed to extract join cond.");
        cm_set_error_pos(__FILE__, __LINE__);
        return OG_ERROR;
    }
    
    out_plan->join_p.filter = jnode->filter;
    return OG_SUCCESS;
}

// mergejoin cond cmp support: >, <, >=, <=, =
bool32 og_check_cmp_is_mergeable(cmp_node_t *cmp_node)
{
    cmp_type_t cmp_type = cmp_node->type;
    if (cmp_type != CMP_TYPE_GREAT && cmp_type != CMP_TYPE_LESS && cmp_type != CMP_TYPE_GREAT_EQUAL &&
        cmp_type != CMP_TYPE_LESS_EQUAL && cmp_type != CMP_TYPE_EQUAL) {
        return OG_FALSE;
    }

    expr_tree_t *left = cmp_node->left;
    expr_tree_t *right = cmp_node->right;
    if (left == NULL || right == NULL || left->root == NULL || right->root == NULL) {
        return OG_FALSE;
    }
    if (get_cmp_datatype(left->root->datatype, right->root->datatype) == INVALID_CMP_DATATYPE) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static join_oper_t get_oper_type_4_merge_join(sql_join_type_t jtype)
{
    if (jtype == JOIN_TYPE_CROSS || jtype == JOIN_TYPE_COMMA || jtype == JOIN_TYPE_INNER) {
        return JOIN_OPER_MERGE;
    } else if (jtype == JOIN_TYPE_LEFT) {
        return JOIN_OPER_MERGE_LEFT;
    } else if (jtype == JOIN_TYPE_FULL) {
        return JOIN_OPER_MERGE_FULL;
    } else {
        return JOIN_OPER_NONE;
    }
}

status_t og_create_merge_join_sort_item(galist_t *sort_lst, expr_tree_t *exprtr, sort_direction_t direction,
    og_type_t cmp_type)
{
    sort_item_t *sort_item = NULL;
    OG_RETURN_IFERR(cm_galist_new(sort_lst, sizeof(sort_item_t), (void **)&sort_item));
    sort_item->expr = exprtr;
    sort_item->direction = direction;
    sort_item->cmp_type = cmp_type;
    sort_item->nulls_pos = DEFAULT_NULLS_SORTING_POSITION(sort_item->direction);
    return OG_SUCCESS;
}

// Construct pathkeys based on given column
static status_t sql_create_path_keys(sql_stmt_t *stmt, tbl_join_info_t *jinfo,
    galist_t *path_keys, merge_path_key_input_t *input)
{
    sql_table_t *table = input->table;
    uint32 col_id = input->col_id;
    bool32 idx_dsc = input->idx_dsc;

    expr_tree_t *left = jinfo->cond->cmp->left;
    expr_tree_t *right = jinfo->cond->cmp->right;
    if (left == NULL || right == NULL) {
        return OG_ERROR;
    }
    expr_node_t col_node;
    expr_node_t *node = NULL;
    knl_column_t *knl_col = knl_get_column(table->entry->dc.handle, col_id);
    OG_RETVALUE_IFTRUE(sql_get_index_col_node(stmt, knl_col, &col_node, &node, table->id, col_id) != OG_SUCCESS,
                       OG_ERROR);

    sort_direction_t dir = (idx_dsc ? SORT_MODE_DESC : SORT_MODE_ASC);
    cmp_rule_t *rule = get_cmp_rule(left->root->datatype, right->root->datatype);
    /* one side reference target table, and other side not. */
    if (sql_expr_node_matched(stmt, left, node)) {
        if (!sql_bitmap_exist_member(table->id, &jinfo->table_ids_right)) {
            OG_RETURN_IFERR(og_create_merge_join_sort_item(path_keys, left, dir, rule->cmp_type));
        }
    }
    if (sql_expr_node_matched(stmt, right, node)) {
        if (!sql_bitmap_exist_member(table->id, &jinfo->table_ids_left)) {
            OG_RETURN_IFERR(og_create_merge_join_sort_item(path_keys, right, dir, rule->cmp_type));
        }
    }
    return OG_SUCCESS;
}

static void og_set_merge_table_scan(sql_table_t *tbl, cbo_index_choose_assist_t *ca, double cost,
    index_t *index, cond_tree_t *condtr)
{
    tbl->startup_cost = ca->startup_cost;
    tbl->cost = cost;
    tbl->index = &index->desc;
    tbl->scan_flag = ca->scan_flag;
    tbl->scan_mode = SCAN_MODE_INDEX;
    tbl->index_full_scan = ca->index_full_scan;
    tbl->idx_equal_to = ca->strict_equal_cnt;
    tbl->index_dsc = ca->index_dsc;
    tbl->cond = condtr;
}

static void og_init_merge_table_scan_ca(cbo_index_choose_assist_t *ca, index_t *index, uint8 idx_dsc)
{
    ca->index = &index->desc;
    ca->strict_equal_cnt = 0;
    ca->index_dsc = idx_dsc;
    ca->index_full_scan = true;
    ca->scan_flag = RBO_MERGE_JOIN_SCAN_FLAG;
    ca->startup_cost = 0.0;
}

static void og_reset_merge_jnode(sql_join_node_t *jnode, int64 card, double startup_cost,
    double cost, join_tbl_bitmap_t outer_rels)
{
    jnode->cost.card = card;
    jnode->cost.cost = cost;
    jnode->cost.startup_cost = startup_cost;
    jnode->outer_rels = outer_rels;
    jnode->path_keys = NULL;
}

// index scan paths produce ordered output
static status_t og_create_index_scan_paths(join_assist_t *j_ast, tbl_join_info_t *jinfo,
    galist_t **idx_cond_array, cond_tree_t *condtr, merge_index_scan_input_t *idx_scan_input)
{
    sql_table_t *tbl = idx_scan_input->tbl;
    index_t *index = idx_scan_input->index;
    uint8 idx_dsc = idx_scan_input->idx_dsc;
    sql_stmt_t *statement = j_ast->stmt;
    uint32 idx_1st_col_id = index->desc.columns[0];
    sql_join_table_t *jtbl = j_ast->base_jtables[tbl->id];
    dc_entity_t *entity = DC_ENTITY(&tbl->entry->dc);
    cbo_index_choose_assist_t ca = { 0 };
    og_init_merge_table_scan_ca(&ca, index, idx_dsc);

    int64 card;
    sql_table_t *tmp_tbl = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(statement->context, sizeof(sql_table_t), (void **)&tmp_tbl));
    sql_init_table_indexable(tmp_tbl, tbl);

    if (check_can_index_only(j_ast->pa, tmp_tbl, &index->desc)) {
        ca.scan_flag |= RBO_INDEX_ONLY_FLAG;
    }

    double cost = sql_estimate_index_scan_cost(statement, &ca, entity, index, idx_cond_array, &card, tbl);
    og_set_merge_table_scan(tmp_tbl, &ca, cost, index, condtr);
    if (INDEX_ONLY_SCAN(tmp_tbl->scan_flag)) {
        OG_RETURN_IFERR(sql_make_index_col_map(j_ast->pa, statement, tmp_tbl));
    }

    join_tbl_bitmap_t outer_rels;
    sql_bitmap_init(&outer_rels);
    sql_join_node_t *jnode = NULL;
    OG_RETURN_IFERR(sql_create_join_node(statement, JOIN_TYPE_NONE, tmp_tbl, NULL, NULL, NULL, &jnode));
    og_reset_merge_jnode(jnode, tmp_tbl->card, ca.startup_cost, cost, outer_rels);

    merge_path_key_input_t input = {
        .table = tbl,
        .col_id = idx_1st_col_id,
        .idx_dsc = idx_dsc
    };
    OG_RETURN_IFERR(sql_create_list(j_ast->stmt, &jnode->path_keys));
    // Create pathkey using the first column of the index
    OG_RETURN_IFERR(sql_create_path_keys(statement, jinfo, jnode->path_keys, &input));

    OG_RETURN_IFERR(sql_jtable_add_path(j_ast->stmt, jtbl, jnode));
    return OG_SUCCESS;
}

// generate scan paths that produce ordered results
status_t og_gen_sorted_paths(join_assist_t *ja, sql_join_table_t *jtable, sql_table_t *table)
{
    OG_RETSUC_IFTRUE(table->type != NORMAL_TABLE || jtable->join_info == NULL);
    tbl_join_info_t *jinfo = NULL;
    dc_entity_t *entity = DC_ENTITY(&table->entry->dc);
    sql_stmt_t *stmt = ja->stmt;
    bool32 is_sys_table = IS_SYS_TABLE(&entity->table);
    if (entity->cbo_table_stats == NULL || (!is_sys_table &&
        (!is_analyzed_table(stmt, table) || !entity->cbo_table_stats->global_stats_exist))) {
        return OG_SUCCESS;
    }
    cond_tree_t* cond = NULL;
    sql_create_cond_tree(stmt->context, &cond);
    status_t status = OG_SUCCESS;
    OGSQL_SAVE_STACK(stmt);
    // attempt to generate index scan paths for each available index.
    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        index_t *index = DC_TABLE_INDEX(&entity->table, idx_id);
        OG_CONTINUE_IFTRUE(index->desc.is_invalid);
        galist_t *idx_cond_array[OG_MAX_INDEX_COLUMNS];
        status = init_idx_cond_array(stmt, idx_cond_array);
        OG_BREAK_IF_ERROR(status);
        bool32 matched = false;

        for (uint32 i = 0; i < jtable->join_info->count; i++) {
            jinfo = (tbl_join_info_t *)cm_galist_get(jtable->join_info, i);
            OG_CONTINUE_IFTRUE(jinfo->cond->type != COND_NODE_COMPARE);
            cmp_node_t *cmp = jinfo->cond->cmp;
            if (!og_check_cmp_is_mergeable(cmp)) {
                continue;
            }
            if (cmp->left->root->type != EXPR_NODE_COLUMN || cmp->right->root->type != EXPR_NODE_COLUMN) {
                continue;
            }
            // For a composite index, scanning follows the leading column's order
            if (match_joininfo_to_indexcol(stmt, table, jinfo, index->desc.columns[0])) {
                sql_add_cond_node(cond, jinfo->cond);
                RET_AND_RESTORE_STACK_IFERR(cm_galist_insert(idx_cond_array[0], cmp), stmt);
                matched = true;
                break;
            }
        }
        OG_CONTINUE_IFTRUE(!matched);

        merge_index_scan_input_t input = {
            .idx_dsc = true,
            .index = index,
            .tbl = table
        };

        // The sort direction (ascending/descending) cannot be determined in advance
        status = og_create_index_scan_paths(ja, jinfo, idx_cond_array, cond, &input);
        OG_BREAK_IF_ERROR(status);
        input.idx_dsc = false;
        status = og_create_index_scan_paths(ja, jinfo, idx_cond_array, cond, &input);
        OG_BREAK_IF_ERROR(status);
    }

    OGSQL_RESTORE_STACK(stmt);
    return status;
}

/*
 * extract mergeable condition from join conditions as pathkeys
 * join condition may contain multiple mergeable conditions, but only the first one is considered for pathkeys here.
 *
 */
static status_t sql_extract_path_keys_for_merge(cond_node_t *cond_node, sql_join_node_t *outerpath,
    sql_join_node_t *innerpath, galist_t *outer_path_keys, galist_t *inner_path_keys, join_oper_t oper)
{
    if (outer_path_keys != NULL && outer_path_keys->count > 0) {
        return OG_SUCCESS;
    }
    switch (cond_node->type) {
        case COND_NODE_AND:
            OG_RETURN_IFERR(sql_extract_path_keys_for_merge(cond_node->left, outerpath, innerpath,
                outer_path_keys, inner_path_keys, oper));
            OG_RETURN_IFERR(sql_extract_path_keys_for_merge(cond_node->right, outerpath, innerpath,
                outer_path_keys, inner_path_keys, oper));
            break;

        case COND_NODE_COMPARE: {
            cmp_node_t *cmp_node = cond_node->cmp;
            if (!og_check_cmp_is_mergeable(cmp_node)) {
                break;
            }
            cmp_type_t type = cmp_node->type;
            sort_direction_t dir = (type == CMP_TYPE_LESS ||
                type == CMP_TYPE_LESS_EQUAL ? SORT_MODE_DESC : SORT_MODE_ASC);
            cmp_rule_t *rule = get_cmp_rule(cmp_node->left->root->datatype, cmp_node->right->root->datatype);
            uint16 l_tbl_id;
            uint16 r_tbl_id;
            if (!sql_get_cmp_join_tab_id(cmp_node, &l_tbl_id, &r_tbl_id, oper)) {
                break;
            }
            // a join b on a.c1 = b.c1;
            if (sql_table_in_list(&outerpath->tables, l_tbl_id) &&
                sql_table_in_list(&innerpath->tables, r_tbl_id)) {
                    OG_RETURN_IFERR(og_create_merge_join_sort_item(outer_path_keys,
                        cmp_node->left, dir, rule->cmp_type));
                    OG_RETURN_IFERR(og_create_merge_join_sort_item(inner_path_keys,
                        cmp_node->right, dir, rule->cmp_type));
                    break;
            }
            // a join b on b.c1 = a.c1;
            if (sql_table_in_list(&outerpath->tables, r_tbl_id) &&
                sql_table_in_list(&innerpath->tables, l_tbl_id)) {
                    type = sql_reverse_cmp(type);
                    dir = (type == CMP_TYPE_LESS || type == CMP_TYPE_LESS_EQUAL ? SORT_MODE_DESC : SORT_MODE_ASC);
                    OG_RETURN_IFERR(og_create_merge_join_sort_item(outer_path_keys,
                        cmp_node->right, dir, rule->cmp_type));
                    OG_RETURN_IFERR(og_create_merge_join_sort_item(inner_path_keys,
                        cmp_node->left, dir, rule->cmp_type));
                    break;
            }
            break;
        }
        default:
            break;
    }
    return OG_SUCCESS;
}

// compare pathkeys1 and pathkeys2 with the leftmost prefix rule.
static bool32 sql_path_keys_contained_in(sql_stmt_t *statement, galist_t *path_keys1, galist_t *path_keys2)
{
    sort_item_t *item1 = NULL;
    sort_item_t *item2 = NULL;
    expr_node_t *node1 = NULL;
    expr_node_t *node2 = NULL;
    if (path_keys1 == NULL || path_keys2 == NULL) {
        return OG_FALSE;
    }
    if (path_keys1->count > path_keys2->count) {
        return OG_FALSE;
    }
    for (uint32 i = 0; i < path_keys1->count; i++) {
        item1 = (sort_item_t *)cm_galist_get(path_keys1, i);
        item2 = (sort_item_t *)cm_galist_get(path_keys2, i);
        if (item1->cmp_type != item2->cmp_type) {
            return OG_FALSE;
        }
        if (item1->direction != item2->direction) {
            return OG_FALSE;
        }
        if (item1->nulls_pos != item2->nulls_pos) {
            return OG_FALSE;
        }
        node1 = item1->expr->root;
        node2 = item2->expr->root;
        if (!sql_expr_node_equal(statement, node1, node2, NULL)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static status_t sql_init_merge_path(join_assist_t *ja, sql_join_table_t *jtable,
    sql_join_node_t *outerpath, sql_join_node_t *innerpath, sql_join_node_t *path)
{
    path->left = outerpath;
    path->right = innerpath;
    path->cost.card = CBO_CARD_SAFETY_SET(jtable->rows);
    path->join_cond = ja->join_cond;
    path->filter = ja->filter;
    OG_RETURN_IFERR(sql_array_concat(&path->tables, &outerpath->tables));
    OG_RETURN_IFERR(sql_array_concat(&path->tables, &innerpath->tables));
    join_tbl_bitmap_t outer_rels;
    sql_bitmap_init(&outer_rels);
    sql_bitmap_union(&outerpath->outer_rels, &innerpath->outer_rels, &outer_rels);
    sql_bitmap_delete_members(&outer_rels, &outerpath->parent->table_ids);
    path->outer_rels = outer_rels;
    return OG_SUCCESS;
}

static status_t sql_add_merge_path_single(join_assist_t *ja, sql_join_table_t *jtable, sql_join_node_t* path,
    join_cost_workspace* join_cost_ws, galist_t *restricts)
{
    sql_final_cost_merge(path, join_cost_ws, restricts);
    sql_debug_join_cost_info(ja->stmt, path, "Merge", "add path");
    OG_RETURN_IFERR(sql_jtable_add_path(ja->stmt, jtable, path));
    return OG_SUCCESS;
}

static void sql_init_tmp_path(sql_join_node_t* temp_path_p, sql_join_type_t jointype,
    sql_join_node_t *outerpath, sql_join_node_t *innerpath, sql_join_table_t *jtable)
{
    temp_path_p->type = jointype;
    temp_path_p->left = outerpath;
    temp_path_p->right = innerpath;
    temp_path_p->cost.card = CBO_CARD_SAFETY_SET(jtable->rows);
    join_oper_t oper = get_oper_type_4_merge_join(jointype);
    temp_path_p->oper = oper;
}

/*
 * The mergejoin path is constructed using the outer path and inner path.
 * During merge join operations, the output from both the outer path and inner path must be ordered.
 * acquire the sort keys for both paths and comparing them with the output order of the outer and inner paths
 *
 */
static status_t sql_build_merge_path(join_assist_t *ja, sql_join_type_t jointype, sql_join_table_t *jtable,
    sql_join_node_t *outerpath, sql_join_node_t *innerpath, special_join_info_t *sjoininfo, galist_t *restricts,
    join_tbl_bitmap_t *param_source_rels, bool outerpath_requires_reorder, bool innerpath_requires_reorder)
{
    bool match_hint = false;
    join_hint_key_wid_t join_hint_type;
    hint_info_t *info = ja->pa->query->hint_info;
    if (outerpath == NULL || innerpath == NULL) {
        if (HAS_SPEC_TYPE_HINT(info, JOIN_HINT, HINT_KEY_WORD_LEADING)) {
            return OG_SUCCESS;
        } else {
            OG_LOG_RUN_ERR("path is NULL");
            return OG_ERROR;
        }
    }

    join_oper_t oper = get_oper_type_4_merge_join(jointype);
    OG_RETVALUE_IFTRUE(oper == JOIN_OPER_NONE, OG_ERROR);
    galist_t *outer_sort_keys = NULL;
    OG_RETURN_IFERR(sql_create_list(ja->stmt, &outer_sort_keys));
    galist_t *path_keys = outer_sort_keys;
    galist_t *inner_sort_keys = NULL;
    OG_RETURN_IFERR(sql_stack_alloc(ja->stmt, sizeof(galist_t), (void **)&inner_sort_keys));
    cm_galist_init(inner_sort_keys, ja->stmt, sql_stack_alloc);
    cond_tree_t* filter = ja->filter;
    OG_RETSUC_IFTRUE(filter == NULL);
    OG_RETURN_IFERR(sql_extract_path_keys_for_merge(filter->root, outerpath, innerpath,
        outer_sort_keys, inner_sort_keys, oper));
    OG_RETVALUE_IFTRUE((outer_sort_keys->count == 0 || inner_sort_keys->count == 0), OG_SUCCESS);
     // If the outerpath output order matches the sort order required by the merge join,
    // the sorting cost will not be calculated.
    if (sql_path_keys_contained_in(ja->stmt, outer_sort_keys, outerpath->path_keys)) {
        outer_sort_keys = NULL;
    } else if (!outerpath_requires_reorder) {
        return OG_SUCCESS;
    }
    if (sql_path_keys_contained_in(ja->stmt, inner_sort_keys, innerpath->path_keys)) {
        inner_sort_keys = NULL;
    } else if (!innerpath_requires_reorder) {
        return OG_SUCCESS;
    }

    sql_join_node_t temp_path;
    sql_join_node_t* temp_path_p = &temp_path;
    join_cost_workspace join_cost_ws;
    MEMS_RETURN_IFERR(memset_s(&temp_path, sizeof(sql_join_node_t), 0, sizeof(sql_join_node_t)));
    MEMS_RETURN_IFERR(memset_s(&join_cost_ws, sizeof(join_cost_ws), 0, sizeof(join_cost_ws)));

    sql_init_tmp_path(temp_path_p, jointype, outerpath, innerpath, jtable);

    OG_RETURN_IFERR(sql_initial_cost_merge(temp_path_p, &join_cost_ws, outer_sort_keys, inner_sort_keys));
    
    if (!sql_add_path_precheck(jtable, join_cost_ws.startup_cost, join_cost_ws.total_cost)) {
        return OG_SUCCESS;
    }

    sql_join_node_t *path = NULL;
    OG_RETURN_IFERR(sql_alloc_mem(ja->stmt->context, sizeof(sql_join_node_t), (pointer_t *)&path));
    uint32 count = outerpath->tables.count + innerpath->tables.count;
    OG_RETURN_IFERR(sql_create_array(ja->stmt->context, &path->tables, "JOIN TABLES", count));
    OG_RETURN_IFERR(sql_init_merge_path(ja, jtable, outerpath, innerpath, path));
    path->path_keys = path_keys;
    path->type = jointype;
    path->oper = oper;

    // leading check
    if (!check_apply_hint_leading(ja, path)) {
        return OG_SUCCESS;
    }

    // merge hint check
    if (has_join_hint_id(info) &&
        check_apply_join_hint(innerpath, HINT_KEY_WORD_USE_MERGE, &match_hint, &join_hint_type)) {
        if (!match_hint &&
            (!check_apply_join_hint_conflict(outerpath->parent, innerpath->parent,
            jointype, restricts, join_hint_type))) {
            return OG_SUCCESS;
        }
    }

    /* if outer rel provides some but not all of the inner rel's paramterization, build ok. */
    if (!sql_bitmap_empty(&path->outer_rels) && !sql_bitmap_overlap(&path->outer_rels, param_source_rels) &&
        !(sql_bitmap_overlap(&innerpath->outer_rels, &outerpath->parent->table_ids) &&
        !sql_bitmap_same(&innerpath->outer_rels, &outerpath->parent->table_ids))) {
        return OG_SUCCESS;
    }

    path->cost.startup_cost = temp_path_p->cost.startup_cost;
    path->cost.cost = temp_path_p->cost.cost;
    OG_RETURN_IFERR(sql_add_merge_path_single(ja, jtable, path, &join_cost_ws, restricts));
  
    return OG_SUCCESS;
}

// Merge Join execution module only supports inner joins
// requires the join condition to be a comparison between columns from the outer and inner tables
bool32 og_check_can_merge_join(sql_join_table_t *jtbl1, sql_join_table_t *jtbl2,
    sql_join_type_t jointype, galist_t *restricts)
{
    if (!g_instance->sql.enable_merge_join) {
        return OG_FALSE;
    }

    if (jointype != JOIN_TYPE_COMMA && jointype != JOIN_TYPE_CROSS && jointype != JOIN_TYPE_INNER) {
        return OG_FALSE;
    }

    if (restricts == NULL || restricts->count == 0) {
        return OG_FALSE;
    }

    bool32 restrict_is_mergeable = OG_FALSE;
    cols_used_t l_cols_used;
    cols_used_t r_cols_used;
    for (uint32 i = 0; i < restricts->count; i++) {
        tbl_join_info_t* tmp_jinfo = (tbl_join_info_t *)cm_galist_get(restricts, i);
        if (tmp_jinfo->cond == NULL || tmp_jinfo->cond->cmp == NULL) {
            continue;
        }

        if (tmp_jinfo->cond->type != COND_NODE_COMPARE) {
            continue;
        }

        if (!og_check_cmp_is_mergeable(tmp_jinfo->cond->cmp)) {
            continue;
        }
        
        if (!check_and_get_join_column(tmp_jinfo->cond->cmp, &l_cols_used, &r_cols_used)) {
            continue;
        }

        // a JOIN b ON a cmp 1, constant condition cannot effectively utilize sorting
        // a JOIN b ON a.c1+b.c1 cmp a.c1+b.c1, condition is not a simple column-to-column cmp
        if (sql_bitmap_empty(&tmp_jinfo->table_ids_left) || sql_bitmap_empty(&tmp_jinfo->table_ids_right) ||
            sql_bitmap_overlap(&tmp_jinfo->table_ids_left, &tmp_jinfo->table_ids_right)) {
            continue;
        }
        
        // a JOIN b ON a.c1 cmp b.c1， a JOIN b ON b.c1 cmp a.c1, Merge Join may be ok.
        if ((sql_bitmap_subset(&tmp_jinfo->table_ids_left, &jtbl2->table_ids) &&
            sql_bitmap_subset(&tmp_jinfo->table_ids_right, &jtbl1->table_ids)) ||
            (sql_bitmap_subset(&tmp_jinfo->table_ids_left, &jtbl1->table_ids) &&
            sql_bitmap_subset(&tmp_jinfo->table_ids_right, &jtbl2->table_ids))) {
            restrict_is_mergeable = OG_TRUE;
            break;
        }
    }
    return restrict_is_mergeable;
}

// Check if the base table scan method is a function index scan. Merge Join does not support this.
static bool32 sql_is_func_idx_scan(sql_join_node_t *path)
{
    sql_table_t *tbl = NULL;
    for (uint32 i = 0; i < path->tables.count; i++) {
        tbl = (sql_table_t *)sql_array_get(&path->tables, i);
        if (tbl->scan_mode == SCAN_MODE_INDEX && tbl->index->is_func &&
            INDEX_ONLY_SCAN(tbl->scan_flag)) {
                return OG_TRUE;
            }
    }
    return OG_FALSE;
}

/*
 * Both outer and inner tables require sorting
 * therefore attempting cheapest_total_path for both outer and inner tables
 */
status_t og_gen_sort_inner_and_outer_merge_paths(merge_path_input_t *input)
{
    join_assist_t *ja = input->ja;
    sql_join_type_t jointype = input->jointype;
    sql_join_table_t *jtable = input->jtable;
    sql_join_table_t *jtbl1 = input->jtbl1;
    sql_join_table_t *jtbl2 = input->jtbl2;
    special_join_info_t *sjoininfo = input->sjoininfo;
    galist_t* restricts = input->restricts;
    join_tbl_bitmap_t *param_source_rels = input->param_source_rels;

    if (ja->pa->type == SQL_MERGE_NODE) {
        return OG_SUCCESS;
    }

    if (!og_check_can_merge_join(jtbl1, jtbl2, jointype, restricts)) {
        return OG_SUCCESS;
    }

    sql_join_node_t *outer_path = jtbl1->cheapest_total_path;
    sql_join_node_t *inner_path = jtbl2->cheapest_total_path;
    if (outer_path == NULL || inner_path == NULL) {
        if (HAS_SPEC_TYPE_HINT(ja->pa->query->hint_info, JOIN_HINT, HINT_KEY_WORD_LEADING)) {
            return OG_SUCCESS;
        } else {
            OG_LOG_RUN_ERR("path is NULL");
            return OG_ERROR;
        }
    }
    if (sql_is_func_idx_scan(outer_path) || sql_is_func_idx_scan(inner_path)) {
        return OG_SUCCESS;
    }
    /* mergejoin require Independent Sortability && Non-Interdependence */
    if (sql_bitmap_overlap(&outer_path->outer_rels, &jtbl2->table_ids) ||
        sql_bitmap_overlap(&inner_path->outer_rels, &jtbl1->table_ids)) {
            return OG_SUCCESS;
    }

    OGSQL_SAVE_STACK(ja->stmt);
    status_t ret = sql_build_merge_path(ja, jointype, jtable, outer_path, inner_path, sjoininfo,
        restricts, param_source_rels, true, true);
    OGSQL_RESTORE_STACK(ja->stmt);
    return ret;
}

// select pre-sorted paths to construct the merge join path
status_t og_gen_unsorted_merge_paths(merge_path_input_t *input)
{
    join_assist_t *ja = input->ja;
    sql_join_type_t jointype = input->jointype;
    sql_join_table_t *jtable = input->jtable;
    sql_join_table_t *jtbl1 = input->jtbl1;
    sql_join_table_t *jtbl2 = input->jtbl2;
    special_join_info_t *sjoininfo = input->sjoininfo;
    galist_t* restricts = input->restricts;

    if (ja->pa->type == SQL_MERGE_NODE || !og_check_can_merge_join(jtbl1, jtbl2, jointype, restricts)) {
        return OG_SUCCESS;
    }

    sql_join_node_t* outer_path;
    sql_join_node_t *inner_path;

    if (jtbl1->cheapest_total_path == NULL || jtbl2->cheapest_total_path == NULL) {
        if (HAS_SPEC_TYPE_HINT(ja->pa->query->hint_info, JOIN_HINT, HINT_KEY_WORD_LEADING)) {
            return OG_SUCCESS;
        } else {
            return OG_ERROR;
        }
    }
    inner_path = jtbl2->cheapest_total_path;
    /* cannot use an inner path that is parameterized by the outer rel. */
    if (sql_bitmap_overlap(&inner_path->outer_rels, &jtbl1->table_ids)) {
        return OG_SUCCESS;
    }

    if (sql_is_func_idx_scan(inner_path)) {
        return OG_SUCCESS;
    }

    // sorted_path join cheapest_total_path
    OGSQL_SAVE_STACK(ja->stmt);

    for (int i = 0; i < jtbl1->sorted_paths->count; i++) {
        outer_path = (sql_join_node_t*)cm_galist_get(jtbl1->sorted_paths, i);
        /* cannot use an outer path that is parameterized by the inner rel. */
        if (sql_bitmap_overlap(&outer_path->outer_rels, &jtbl2->table_ids)) {
            continue;
        }
        RET_AND_RESTORE_STACK_IFERR(sql_build_merge_path(ja, jointype, jtable, outer_path, inner_path, sjoininfo,
            restricts, input->param_source_rels, false, true), ja->stmt);
    }

    // sorted_path join sorted_path
    for (int i = 0; i < jtbl1->sorted_paths->count; i++) {
        outer_path = (sql_join_node_t*)cm_galist_get(jtbl1->sorted_paths, i);
        for (int j = 0; j < jtbl2->sorted_paths->count; j++) {
            inner_path =  (sql_join_node_t*)cm_galist_get(jtbl2->sorted_paths, j);
            if (sql_bitmap_overlap(&outer_path->outer_rels, &jtbl2->table_ids) ||
                sql_bitmap_overlap(&inner_path->outer_rels, &jtbl1->table_ids)) {
                    continue;
            }
            RET_AND_RESTORE_STACK_IFERR(sql_build_merge_path(ja, jointype, jtable, outer_path, inner_path, sjoininfo,
                restricts, input->param_source_rels, false, false), ja->stmt);
        }
    }
    OGSQL_RESTORE_STACK(ja->stmt);
    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
