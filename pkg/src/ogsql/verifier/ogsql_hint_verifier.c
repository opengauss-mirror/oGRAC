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
 * ogsql_hint_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ogsql_hint_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ogsql_hint_verifier.h"
#include "dml_parser.h"
#include "ogsql_hint_parser.h"
#include "srv_instance.h"
#include "ogsql_plan.h"
#include "cbo_base.h"
#include "ogsql_context.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t og_verify_hint_index(sql_hint_verifier_t *verif, hint_item_t *hint_item, hint_info_t *hint_info);
static status_t og_verify_hint_tables(sql_hint_verifier_t *verif, hint_item_t *hint_item, hint_info_t *hint_info);

sql_opt_param_t g_opt_param_hint[] = {
    { { (char *)"_OPT_CBO_STAT_SAMPLING_LEVEL", 20 },        OPT_DYNAMIC_SAMPLING},
};

static sql_hint_t g_hint_infos[] = {
    {(uint32)ID_HINT_FULL,             INDEX_HINT,    (uint32)HINT_KEY_WORD_FULL,            og_verify_hint_tables},
    {(uint32)ID_HINT_INDEX,            INDEX_HINT,    (uint32)HINT_KEY_WORD_INDEX,            og_verify_hint_index},
};

static inline status_t og_set_hint_mask(sql_stmt_t *statement, hint_info_t **hint_info, hint_id_t hint_id)
{
    hint_type_t hint_type = g_hint_infos[hint_id].hint_type;
    if (*hint_info == NULL) {
        OG_RETURN_IFERR(og_alloc_hint(statement, hint_info));
    }
    SET_HINT_MASK((*hint_info)->mask, hint_type, g_hint_infos[hint_id].hint_key);
    return OG_SUCCESS;
}

static sql_table_t *find_table_from_array(sql_array_t *tbls, text_t *name)
{
    for (uint32 i = 0; i < tbls->count; i++) {
        sql_table_t *tbl = (sql_table_t *)sql_array_get(tbls, i);
        text_t *tab_name = tbl->alias.value.len > 0 ? &tbl->alias.value : &tbl->name.value;
        if (cm_compare_text_ins(tab_name, name) == 0) {
            return tbl;
        }
    }
    return NULL;
}

/* "+ OPT_ESTIMATE(<object type> <object> <data to be adjust>=<number>)"
object type: table
obeject: table name
data to be adjust：scale_rows rows min max
number: set number
example: OPT_ESTIMATE(table t1 scale_rows = -1 min = 500 ...)
ONLY FOR CBO MODE
*/
static status_t og_verify_hint_tables(sql_hint_verifier_t *verif, hint_item_t *hint_item, hint_info_t *hint_info)
{
    OG_RETSUC_IFTRUE(verif->tables == NULL || hint_item->args == NULL);
    expr_tree_t *arg_exprtr = hint_item->args;
    while (arg_exprtr != NULL) {
        if (!EXPR_IS_CONST_CHAR(arg_exprtr)) {
            arg_exprtr = arg_exprtr->next;
            continue;
        }
        sql_table_t *tbl = find_table_from_array(verif->tables, &arg_exprtr->root->value.v_text);
        if (!tbl) {
            arg_exprtr = arg_exprtr->next;
            continue;
        }
        OG_RETURN_IFERR(og_set_hint_mask(verif->statement, &tbl->hint_info, hint_item->id));
        arg_exprtr = arg_exprtr->next;
    }

    return OG_SUCCESS;
}

static bool32 galist_contains_uint32(galist_t *list, uint32 target)
{
    if (list == NULL || list->count == 0) {
        return OG_FALSE;
    }

    for (uint32 i = 0; i < list->count; i++) {
        uint32 *val = (uint32 *)cm_galist_get(list, i);
        if (val != NULL && *val == target) {
            return OG_TRUE;
        }
    }

    return OG_FALSE;
}

static bool32 is_index_in_list(galist_t *idx_lst, uint32 idx_id)
{
    return galist_contains_uint32(idx_lst, idx_id);
}

static bool32 is_normal_table(sql_table_t *tbl)
{
    return (tbl != NULL) && (tbl->type == NORMAL_TABLE);
}

static status_t init_table_hint_info(sql_stmt_t *stmt, sql_table_t *tbl)
{
    return (tbl == NULL || stmt == NULL) ? OG_ERROR :
           (tbl->hint_info != NULL)      ? OG_SUCCESS :
                                    og_alloc_hint(stmt, &tbl->hint_info);
}

static status_t og_verify_hint_index(sql_hint_verifier_t *verif, hint_item_t *hint_item, hint_info_t *hint_info)
{
    if (verif->tables == NULL || hint_item->args == NULL) {
        return OG_SUCCESS;
    }
    if (!EXPR_IS_CONST_CHAR(hint_item->args)) {
        return OG_SUCCESS;
    }

    const uint64 curr_hint_id = hint_item->id;
    expr_tree_t *tbl_name_expr = hint_item->args;
    expr_tree_t *index_param_expr = tbl_name_expr->next;
    sql_table_t *target_table = find_table_from_array(verif->tables, &tbl_name_expr->root->value.v_text);
    status_t op_status = OG_SUCCESS;

    bool32 res = is_normal_table(target_table);
    if (!res) {
        return OG_SUCCESS;
    }

    op_status = init_table_hint_info(verif->statement, target_table);
    if (op_status != OG_SUCCESS) {
        return op_status;
    }

    tbl_name_expr = hint_item->args;
    index_param_expr = tbl_name_expr->next;
    if (index_param_expr == NULL) {
        return og_set_hint_mask(verif->statement, &target_table->hint_info, curr_hint_id);
    }

    if (target_table->hint_info->args[curr_hint_id] == NULL) {
        op_status = sql_create_list(verif->statement, (galist_t **)&target_table->hint_info->args[curr_hint_id]);
        if (op_status != OG_SUCCESS) {
            return op_status;
        }
    }

    galist_t *index_list = (galist_t *)(target_table->hint_info->args[curr_hint_id]);
    expr_tree_t *curr_param = index_param_expr;
    while (curr_param != NULL) {
        if (!EXPR_IS_CONST_CHAR(curr_param)) {
            curr_param = curr_param->next;
            continue;
        }

        index_t *target_index = dc_find_index_by_name_ins(DC_ENTITY(&target_table->entry->dc),
                                                          &curr_param->root->value.v_text);
        if (target_index == NULL) {
            curr_param = curr_param->next;
            continue;
        }

        const uint32 index_id = target_index->desc.slot;
        if (!is_index_in_list(index_list, index_id)) {
            uint32 *new_index_id = NULL;
            op_status = cm_galist_new(index_list, sizeof(uint32), (void **)&new_index_id);
            if (op_status != OG_SUCCESS) {
                return op_status;
            }
            *new_index_id = index_id;
        }

        curr_param = curr_param->next;
    }

    return og_set_hint_mask(verif->statement, &target_table->hint_info, curr_hint_id);
}

static void og_verify_hint_items(sql_hint_verifier_t *hint_verify, hint_info_t *hint_info)
{
    hint_item_t *hint_item = NULL;
    galist_t *items_lst = hint_info->items;
    sql_hint_verifier_func verify_func = NULL;
    int i = 0;
    uint32 total_hint = ELEMENT_COUNT(g_hint_infos);
    while (i < items_lst->count) {
        hint_item = (hint_item_t *)cm_galist_get(items_lst, i++);
        if (hint_item->id >= total_hint) {
            continue;
        }
        verify_func = g_hint_infos[hint_item->id].hint_verify_func;
        if (verify_func != NULL && verify_func(hint_verify, hint_item, hint_info) != OG_SUCCESS) {
            cm_reset_error();
        }
    }
}

static void og_hint_verify_inner(sql_hint_verifier_t *hint_verify, hint_info_t **hint_info)
{
    // if sql has no hint and set _HINT_FORCE ,then set every table's
    if (g_instance->attr.hint_force) {
        if (*hint_info == NULL && og_alloc_hint(hint_verify->statement, hint_info) != OG_SUCCESS) {
            cm_reset_error();
            return;
        }

        if ((*hint_info)->items == NULL) {
            return;
        }
    }

    if (*hint_info != NULL && (*hint_info)->items != NULL) {
        og_verify_hint_items(hint_verify, *hint_info);
    }
}

void og_hint_verify(sql_stmt_t *statement, sql_type_t sql_type, void *ctx_entry)
{
    hint_info_t **hint_info = NULL;
    sql_hint_verifier_t hint_verify = {
        .statement = statement,
        .tables = NULL,
        .table = NULL
    };
    // verify context hint
    if (ctx_entry == NULL) {
        return og_hint_verify_inner(&hint_verify, &statement->context->hint_info);
    }

    switch (sql_type) {
        case OGSQL_TYPE_SELECT: {
            sql_query_t *curr_query = (sql_query_t *)ctx_entry;
            hint_verify.tables = &curr_query->tables;
            hint_info = &curr_query->hint_info;
            break;
        }
        case OGSQL_TYPE_UPDATE: {
            sql_update_t *update_ctx = (sql_update_t *)ctx_entry;
            hint_verify.tables = &update_ctx->query->tables;
            hint_info = &update_ctx->hint_info;
            break;
        }
        case OGSQL_TYPE_INSERT:
        case OGSQL_TYPE_REPLACE: {
            sql_insert_t *insert_ctx = (sql_insert_t *)ctx_entry;
            hint_verify.table = insert_ctx->table;
            hint_info = &insert_ctx->hint_info;
            break;
        }
        case OGSQL_TYPE_DELETE: {
            sql_delete_t *delete_ctx = (sql_delete_t *)ctx_entry;
            hint_verify.tables = &delete_ctx->query->tables;
            hint_info = &delete_ctx->hint_info;
            break;
        }
        case OGSQL_TYPE_MERGE: {
            sql_merge_t *merge_ctx = (sql_merge_t *)ctx_entry;
            hint_verify.tables = &merge_ctx->query->tables;
            hint_info = &merge_ctx->hint_info;
        }
        default:
            break;
    }
    
    og_hint_verify_inner(&hint_verify, hint_info);
}

static hint_id_t find_hint_id_by_type_and_key(hint_type_t target_type, index_hint_key_wid_t target_key)
{
    uint32 total_hint = ELEMENT_COUNT(g_hint_infos);
    if (total_hint == 0) {
        return OG_INFINITE32;
    }

    for (uint32 i = 0; i < total_hint; i++) {
        const sql_hint_t *curr_hint = &g_hint_infos[i];
        if (curr_hint->hint_type == target_type && curr_hint->hint_key == target_key) {
            return i;
        }
    }

    return OG_INFINITE32;
}

hint_id_t get_hint_id_4_index(index_hint_key_wid_t access_hint)
{
    return find_hint_id_by_type_and_key(INDEX_HINT, access_hint);
}

static galist_t *get_table_hint_index_list(sql_table_t *t, hint_id_t hint_id)
{
    if (t == NULL || t->hint_info == NULL) {
        return NULL;
    }
    return (galist_t *)(t->hint_info->args[hint_id]);
}

bool32 is_hint_specified_index(sql_table_t *t, hint_id_t hint_id, uint32 idx_id)
{
    galist_t *idx_list = get_table_hint_index_list(t, hint_id);

    if (idx_list == NULL) {
        return OG_TRUE;
    }

    return galist_contains_uint32(idx_list, idx_id);
}

bool32 if_index_in_hint(sql_table_t *t, hint_id_t hint_id, uint32 idx_id)
{
    OG_RETVALUE_IFTRUE(t->hint_info == NULL, OG_FALSE);
    index_hint_key_wid_t hint_access_key = HINT_ACCESS_METHOD_GET(t->hint_info);
    hint_id_t id = get_hint_id_4_index(hint_access_key);
    OG_RETVALUE_IFTRUE(id != hint_id, OG_FALSE);
    return is_hint_specified_index(t, hint_id, idx_id);
}

typedef bool32 (*IndexSkipStrategy)(sql_table_t *table, hint_id_t hint_id, uint32 index_id);

static bool32 skip_strategy_full_scan(sql_table_t *table, hint_id_t hint_id, uint32 index_id)
{
    (void)table;
    (void)hint_id;
    (void)index_id;
    return OG_TRUE;
}

static bool32 skip_strategy_specified_index(sql_table_t *table, hint_id_t hint_id, uint32 index_id)
{
    return !is_hint_specified_index(table, hint_id, index_id);
}

static bool32 skip_strategy_default(sql_table_t *table, hint_id_t hint_id, uint32 index_id)
{
    (void)table;
    (void)hint_id;
    (void)index_id;
    return OG_FALSE;
}

static const struct {
    index_hint_key_wid_t hint_key;
    IndexSkipStrategy strategy;
} index_skip_strategy_map[] = {
    {HINT_KEY_WORD_FULL,          skip_strategy_full_scan},
    {HINT_KEY_WORD_INDEX,         skip_strategy_specified_index},
};
#define STRATEGY_MAP_CNT (sizeof(index_skip_strategy_map)/sizeof(index_skip_strategy_map[0]))

static IndexSkipStrategy find_index_skip_strategy(index_hint_key_wid_t hint_key_val)
{
    IndexSkipStrategy matched_strategy = skip_strategy_default;
    uint32 map_index = 0;

    while (map_index < STRATEGY_MAP_CNT) {
        if (index_skip_strategy_map[map_index].hint_key == hint_key_val) {
            matched_strategy = index_skip_strategy_map[map_index].strategy;
            break;
        }
        map_index++;
    }

    return matched_strategy;
}

bool32 index_skip_in_hints(sql_table_t *table, uint32 index_id)
{
    if (table == NULL || table->hint_info == NULL) {
        return OG_FALSE;
    }
    index_hint_key_wid_t access_hint = HINT_ACCESS_METHOD_GET(table->hint_info);
    hint_id_t hint_id = get_hint_id_4_index(access_hint);
    if (hint_id == OG_INFINITE32) {
        return OG_FALSE;
    }
    IndexSkipStrategy strategy = find_index_skip_strategy(access_hint);
    return strategy(table, hint_id, index_id);
}

#ifdef __cplusplus
}
#endif