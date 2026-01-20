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
 * expl_predicate.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/executor/explain/expl_predicate.c
 *
 * -------------------------------------------------------------------------
 */

#include "expl_predicate.h"
#include "plan_rbo.h"

#define EXPL_SIGN_JOIN     " * "
#define EXPL_SIGN_NOJOIN   " - "
#define EXPL_SIGN_LEN      3
#define EXPL_COND_HEAD     "    "
#define EXPL_COND_HEAD_LEN 4
#define LINE_WRAP_LIMIT (uint32)100
#define LINE_PREFIX_LEN (uint32)16

typedef struct {
    bool32 tbl_cond;
    cond_tree_t *cond_tree;
} get_cond_node_t;

static inline bool32 expl_pred_explain_enabled(sql_stmt_t *statement)
{
    if (statement->hide_plan_extras) {
        return OG_FALSE;
    }

    if (statement->context->has_dblink) {
        return OG_FALSE;
    }

    if (statement->session->plan_display_format != 0) {
        return OG_BIT_TEST(statement->session->plan_display_format, FORMAT_MASK_PREDICATE);
    }
    
    return OG_BIT_TEST(g_instance->sql.plan_display_format, FORMAT_MASK_PREDICATE);
}

status_t expl_pred_helper_init(sql_stmt_t *statement, pred_helper_t *helper, uint32 mtrl_id)
{
    (void)memset_s(helper, sizeof(pred_helper_t), 0, sizeof(pred_helper_t));
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&(helper->row_buf)));
    OG_RETURN_IFERR(sql_push(statement, OG_MAX_ROW_SIZE, (void **)&(helper->content.str)));
    helper->content.cap = OG_MAX_ROW_SIZE;
    vmc_init(&statement->session->vmp, &helper->vmc);

    helper->mtrl_id = mtrl_id;
    helper->is_start_with = OG_FALSE;
    helper->type = PREDICATE_FILTER;
    helper->is_enabled = expl_pred_explain_enabled(statement);
    helper->concate_type = NO_CONCATE;
    helper->is_merge_hash = OG_FALSE;
    helper->merge_cond = NULL;
    helper->idx_cond = NULL;

    return OG_SUCCESS;
}

void expl_pred_helper_release(pred_helper_t *helper)
{
    vmc_free(&helper->vmc);
}

static status_t merge_cond_by_copy(cond_node_t *src_cond, cond_tree_t *dst_tree)
{
    cond_node_t *dst_cond = NULL;
    // shallow copy
    OG_RETURN_IFERR(vmc_alloc_mem(dst_tree->owner, sizeof(cond_node_t), (void **)&dst_cond));
    *dst_cond = *src_cond;
    return sql_add_cond_node_core(dst_tree, dst_cond, OG_FALSE);
}

static bool32 single_table_related_column(visit_assist_t *v_ast, expr_node_t *exprn, bool32 observe_ancestor)
{
    sql_table_t *tbl = (sql_table_t *)v_ast->param0;
    if (v_ast->query == NULL) {
        return OG_TRUE;
    }
    sql_array_t *tbl_ary = &v_ast->query->tables;
    uint32 tab_id = TAB_OF_NODE(exprn);
    if ((observe_ancestor && ANCESTOR_OF_NODE(exprn) > 0) || (tbl->id == tab_id)) {
        return OG_TRUE;
    }
    if (tbl_ary->count <= tab_id) {
        return OG_FALSE;
    }
    sql_table_t *tmp_tbl = (sql_table_t *)sql_array_get(tbl_ary, tab_id);
    return (tbl->plan_id >= tmp_tbl->plan_id);
}

static bool32 single_table_related_parent_ref(visit_assist_t *v_ast, parent_ref_t *parent_ref)
{
    galist_t *ref_column_lst = parent_ref->ref_columns;

    uint32 i = 0;
    while (i < ref_column_lst->count) {
        expr_node_t *exprn = (expr_node_t *)cm_galist_get(ref_column_lst, i++);
        if (!single_table_related_column(v_ast, exprn, OG_FALSE)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static bool32 single_table_related_select_node(visit_assist_t *v_ast, sql_select_t *slct)
{
    galist_t *parent_ref_lst = slct->parent_refs;
    uint32 i = 0;
    while (i < parent_ref_lst->count) {
        parent_ref_t *pref = (parent_ref_t *)cm_galist_get(parent_ref_lst, i++);
        if (!single_table_related_parent_ref(v_ast, pref)) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

static status_t single_table_related_expr(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if (v_ast->result0) {
        expr_node_type_t expr_type = (*exprn)->type;
        if (expr_type == EXPR_NODE_COLUMN) {
            v_ast->result0 = single_table_related_column(v_ast, *exprn, OG_TRUE);
        } else if (expr_type == EXPR_NODE_RESERVED) {
            reserved_wid_t wid = VAR_RES_ID(&(*exprn)->value);
            if (wid == RES_WORD_ROWID) {
                v_ast->result0 = single_table_related_column(v_ast, *exprn, OG_TRUE);
            } else if (wid == RES_WORD_ROWNUM) {
                v_ast->result0 = OG_FALSE;
            }
        } else if (expr_type == EXPR_NODE_SELECT) {
            sql_select_t *slct = (sql_select_t *)(*exprn)->value.v_obj.ptr;
            if (slct->has_ancestor > 0) {
                v_ast->result0 = single_table_related_select_node(v_ast, slct);
            }
        }
    }
    return OG_SUCCESS;
}

// the condition only belong to the input tbl
static bool32 single_table_related_cmp_cond(sql_query_t *qry, sql_table_t *tbl, cmp_node_t *node)
{
    status_t ret;
    visit_assist_t v_ast;

    sql_init_visit_assist(&v_ast, NULL, NULL);
    v_ast.query = qry;
    v_ast.excl_flags = VA_EXCL_PRIOR;
    v_ast.param0 = (void *)tbl;
    v_ast.result0 = OG_TRUE;  // belong to the tbl by default

    ret = visit_expr_tree(&v_ast, node->left, single_table_related_expr);
    if (ret != OG_SUCCESS || !v_ast.result0) {
        return OG_FALSE;
    }

    ret = visit_expr_tree(&v_ast, node->right, single_table_related_expr);
    if (ret != OG_SUCCESS || !v_ast.result0) {
        return OG_FALSE;
    }
    return OG_TRUE;
}

// for an "or" condition, all the columns at its current and lower level must belong to this tbl
// before the overall extraction can be carried out.
static bool32 single_table_related_or_cond(sql_query_t *qry, sql_table_t *tbl, cond_node_t *cond)
{
    if (cond->type == COND_NODE_AND || cond->type == COND_NODE_OR) {
        return single_table_related_or_cond(qry, tbl, cond->left) &&
               single_table_related_or_cond(qry, tbl, cond->right);
    } else if (cond->type == COND_NODE_COMPARE) {
        return single_table_related_cmp_cond(qry, tbl, cond->cmp);
    }
    return OG_FALSE;
}

static status_t expl_extract_cond_by_table(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    cond_node_t *src_cond, cond_tree_t *dst_tree)
{
    if (src_cond->type == COND_NODE_AND) {
        OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, src_cond->left, dst_tree));
        OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, src_cond->right, dst_tree));
        try_eval_logic_and(src_cond);
    } else if (src_cond->type == COND_NODE_OR) {
        if (single_table_related_or_cond(qry, tbl, src_cond)) {
            OG_RETURN_IFERR(merge_cond_by_copy(src_cond, dst_tree));
            // Set the extracted parts to "true" to facilitate the identification
            // of the remaining parts.
            src_cond->type = COND_NODE_TRUE;
        }
    } else if (src_cond->type == COND_NODE_COMPARE) {
        if (single_table_related_cmp_cond(qry, tbl, src_cond->cmp)) {
            OG_RETURN_IFERR(merge_cond_by_copy(src_cond, dst_tree));
            // Set the extracted parts to "true" to facilitate the identification
            // of the remaining parts.
            src_cond->type = COND_NODE_TRUE;
        }
    }
    return OG_SUCCESS;
}

static uint32 extract_break_positions(text_t *content, uint32 *space_pos)
{
    bool32 in_single_quote = false;
    bool32 in_double_quote = false;
    uint32 count = 0;
    uint32 last_space = OG_INVALID_ID32;
    uint32 last_break = LINE_PREFIX_LEN;

    for (uint32 i = LINE_PREFIX_LEN; i < content->len; i++) {
        char c = content->str[i];

        if (c == '\'' && !in_double_quote) {
            in_single_quote = !in_single_quote;
        } else if (c == '\"' && !in_single_quote) {
            in_double_quote = !in_double_quote;
        }

        if (in_single_quote || in_double_quote || c != ' ') {
            continue;
        }

        if (i - last_break < LINE_WRAP_LIMIT) {
            last_space = i;
            continue;
        }
        
        uint32 brk = i;
        if (last_space != OG_INVALID_ID32) {
            uint32 left_dist = LINE_WRAP_LIMIT + last_break - last_space;
            uint32 right_dist = i - last_break - LINE_WRAP_LIMIT;
            brk = left_dist < right_dist ? last_space : i;
        }
        space_pos[count++] = brk;
        last_break = brk + 1;
        last_space = OG_INVALID_ID32;
    }
    return count;
}

static status_t expl_format_newline_text(sql_stmt_t *statement, pred_helper_t *helper, text_t *row_data)
{
    uint32 *space_pos = NULL;
    OG_RETURN_IFERR(sql_push(statement, sizeof(uint32) * row_data->len, (void **)&space_pos));
    uint32 space_count = extract_break_positions(row_data, space_pos);
    if (space_count == 0) {
        OGSQL_POP(statement);
        return OG_SUCCESS;
    }

    uint32 start = 0;
    uint32 offset = 0;
    for (uint32 i = 0; i < space_count; i++) {
        offset = start;
        if (start != 0) {
            uint32 j = start - LINE_PREFIX_LEN;
            while (j < start) {
                row_data->str[j++] = ' ';
            }
            offset = start - LINE_PREFIX_LEN;
        }
        text_t content = {.str = (row_data->str + offset), .len = (space_pos[i] - offset)};
        row_init(&helper->ra, helper->row_buf, OG_MAX_ROW_SIZE, EXPL_PRED_COL_NUM);
        OG_RETURN_IFERR(row_put_text(&helper->ra, &content));
        OG_RETURN_IFERR(mtrl_insert_row(&statement->mtrl, helper->mtrl_id, helper->row_buf, &helper->row_id));
        start = space_pos[i] + 1;
    }

    OGSQL_POP(statement);
    uint32 k = start - LINE_PREFIX_LEN;
    while (k < start) {
        row_data->str[k++] = ' ';
    }
    offset = start - LINE_PREFIX_LEN;
    row_data->str = row_data->str + offset;
    row_data->len = row_data->len - offset;
    return OG_SUCCESS;
}

static status_t expl_put_pred_data(sql_stmt_t *statement, pred_helper_t *helper, var_text_t *content)
{
    text_t row_data = {.str = content->str, .len = content->len};
    OG_RETURN_IFERR(expl_format_newline_text(statement, helper, &row_data));
    row_init(&helper->ra, helper->row_buf, OG_MAX_ROW_SIZE, EXPL_PRED_COL_NUM);
    OG_RETURN_IFERR(row_put_text(&helper->ra, &row_data));
    return mtrl_insert_row(&statement->mtrl, helper->mtrl_id, helper->row_buf, &helper->row_id);
}

static status_t expl_format_cond_head(var_text_t *content, int32 row_id, bool32 is_join)
{
    char row_id_str[OG_MAX_INT32_STRLEN + 1] = {0};
    row_id--;
    int32 row_id_len = snprintf_s(row_id_str, OG_MAX_INT32_STRLEN + 1, OG_MAX_INT32_STRLEN, "%d", row_id);
    PRTS_RETURN_IFERR(row_id_len);

    OG_RETURN_IFERR(cm_concat_n_var_string(content, EXPL_COND_HEAD, EXPL_COND_HEAD_LEN));
    OG_RETURN_IFERR(cm_concat_n_var_string(content, row_id_str, row_id_len));
    char *sign = is_join ? EXPL_SIGN_JOIN : EXPL_SIGN_NOJOIN;
    return cm_concat_n_var_string(content, sign, EXPL_SIGN_LEN);
}

static const char *expl_get_pred_type(predicate_type_t type)
{
    if (type == PREDICATE_FILTER) {
        return "filter: ";
    }
    return "access: ";
}

status_t expl_put_pred_info(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper, cond_tree_t *tree)
{
    if (tree == NULL || tree->root == NULL || tree->root->type == COND_NODE_TRUE) {
        return OG_SUCCESS;
    }

    int row_id = helper->parent->row_helper.id;
    var_text_t *content = &helper->content;
    CM_TEXT_CLEAR(content);
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(helper->type)));
    // format condition data;
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, tree->root, OG_FALSE, content));
    OG_RETURN_IFERR(expl_put_pred_data(statement, helper, content));

    return OG_SUCCESS;
}

#define DECIMAL_BASE 10

static inline uint32 get_row_id_len(int32 row_id)
{
    uint32 row_id_len = 0;
    while (row_id > 0) {
        row_id /= DECIMAL_BASE;
        row_id_len++;
    }
    return row_id_len;
}

static status_t expl_format_hash_filter(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    cond_tree_t *tree, var_text_t *content)
{
    int row_id = helper->parent->row_helper.id;
    uint32 row_id_len = get_row_id_len(row_id);
    if (row_id_len == 0) {
        return OG_SUCCESS;
    }
    MEMS_RETURN_IFERR(memset_s(content->str, OG_MAX_ROW_SIZE, (char)' ', (uint32)strlen(" - ") + row_id_len));
    content->len += row_id_len;
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_FILTER)));
    return ogsql_unparse_cond_node(qry, tree->root, OG_FALSE, content);
}

static status_t ogsql_process_hash_filter_cond(sql_stmt_t *statement, pred_helper_t *helper, sql_query_t *qry,
    cond_tree_t *tree, var_text_t *content)
{
    if (content->len == 0) {
        return expl_format_hash_filter(statement, qry, helper, tree, content);
    }
    OG_RETURN_IFERR(cm_concat_var_string(content, " AND "));
    return ogsql_unparse_cond_node(qry, tree->root, OG_FALSE, content);
}

static cond_tree_t *expl_get_join_filter(plan_node_t *plan)
{
    if (plan->join_p.cond == NULL) {
        return NULL;
    }

    if (plan->join_p.cond->root->type == COND_NODE_TRUE) {
        return NULL;
    }

    join_oper_t oper = plan->join_p.oper;
    if (oper == JOIN_OPER_HASH_LEFT || oper == JOIN_OPER_HASH_FULL || oper == JOIN_OPER_HASH_RIGHT_LEFT) {
        return plan->join_p.cond;
    }

    return plan->join_p.filter;
}

static status_t expl_format_merge_join_filter(sql_stmt_t *statement,  pred_helper_t *helper, sql_query_t *qry,
    plan_node_t *plan, var_text_t *content)
{
    cond_tree_t *tree = plan->join_p.filter;
    if ((tree && tree->root->type != COND_NODE_TRUE)) {
        OG_RETURN_IFERR(cm_concat_n_var_string(content, EXPL_COND_HEAD, EXPL_COND_HEAD_LEN));
        int row_id = helper->parent->row_helper.id;
        uint32 row_id_len = get_row_id_len(row_id);
        MEMS_RETURN_IFERR(memset_s(content->str + content->len, OG_MAX_ROW_SIZE,
            (char)' ', EXPL_SIGN_LEN + row_id_len));
        content->len += (EXPL_SIGN_LEN + row_id_len);
        OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_FILTER)));
        OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, tree->root, OG_FALSE, content));
    }
    return content->len > 0 ? expl_put_pred_data(statement, helper, content) : OG_SUCCESS;
}

static status_t expl_format_hash_join_filter(sql_stmt_t *statement,  pred_helper_t *helper, sql_query_t *qry,
    plan_node_t *plan, var_text_t *content)
{
    cond_tree_t *tree = expl_get_join_filter(plan);
    if (tree && tree->root->type != COND_NODE_TRUE) {
        OG_RETURN_IFERR(expl_format_hash_filter(statement, qry, helper, tree, content));
        helper->hash_filter = tree;
    }

    if (helper->l_hash_filter) {
        OG_RETURN_IFERR(ogsql_process_hash_filter_cond(statement, helper, qry, helper->l_hash_filter, content));
        helper->l_hash_filter = NULL;
    } else if (helper->r_hash_filter) {
        OG_RETURN_IFERR(ogsql_process_hash_filter_cond(statement, helper, qry, helper->r_hash_filter, content));
        helper->r_hash_filter = NULL;
    }

    return content->len > 0 ? expl_put_pred_data(statement, helper, content) : OG_SUCCESS;
}

static status_t expl_format_hash_join(sql_query_t *qry, pred_helper_t *helper, plan_node_t *plan, var_text_t *content)
{
    int row_id = helper->parent->row_helper.id;
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_ACCESS)));
    return ogsql_unparse_hash_join_node(qry, plan, content);
}

static status_t expl_format_merge_join(sql_query_t *qry, pred_helper_t *helper, plan_node_t *plan, var_text_t *content)
{
    int row_id = helper->parent->row_helper.id;
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_ACCESS)));
    return ogsql_unparse_merge_join_node(qry, plan, content);
}

static status_t expl_format_nl_join(sql_query_t *qry, pred_helper_t *helper, plan_node_t *plan, var_text_t *content)
{
    if (plan->join_p.right->type != PLAN_NODE_JOIN) {
        return OG_SUCCESS;
    }
    cond_tree_t *tree = helper->outer_cond ? helper->outer_cond : helper->nl_filter;
    if (tree == NULL) {
        return OG_SUCCESS;
    }

    int row_id = helper->parent->row_helper.id;
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_ACCESS)));
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, tree->root, OG_FALSE, content));

    if (helper->outer_cond) {
        helper->outer_cond = NULL;
    } else if (helper->nl_filter) {
        helper->nl_filter = NULL;
    }
    return OG_SUCCESS;
}

static status_t expl_format_node_join(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper, plan_node_t *plan)
{
    join_oper_t join_oper = plan->join_p.oper;
    if (join_oper == JOIN_OPER_NONE) {
        return OG_SUCCESS;
    }

    bool32 is_hash_join = chk_if_hash_join(join_oper);
    bool32 is_nl_join = chk_if_nl_join(join_oper);
    bool32 is_merge_join = (join_oper == JOIN_OPER_MERGE);
    var_text_t *content = &helper->content;

    CM_TEXT_CLEAR(content);
    if (is_hash_join) {
        OG_RETURN_IFERR(expl_format_hash_join(qry, helper, plan, content));
    } else if (is_merge_join) {
        OG_RETURN_IFERR(expl_format_merge_join(qry, helper, plan, content));
    } else if (is_nl_join) {
        OG_RETURN_IFERR(expl_format_nl_join(qry, helper, plan, content));
    }

    if (content->len > 0) {
        OG_RETURN_IFERR(expl_put_pred_data(statement, helper, content));
        CM_TEXT_CLEAR(content);
    }

    if (is_hash_join) {
        OG_RETURN_IFERR(expl_format_hash_join_filter(statement, helper, qry, plan, content));
    } else if (is_merge_join) {
        OG_RETURN_IFERR(expl_format_merge_join_filter(statement, helper, qry, plan, content));
    }

    return OG_SUCCESS;
}

static status_t expl_format_node_having(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    plan_node_t *plan)
{
    cond_tree_t *tree = plan->having.cond;
    return expl_put_pred_info(statement, qry, helper, tree);
}

static void extract_cond_and_set_null(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl, cond_tree_t **tree,
                               cond_node_t *tmp_cond, cond_tree_t *dst_tree)
{
    // tmp_cond is a copy of tree->root
    if (tmp_cond != NULL) {
        status_t ret = expl_extract_cond_by_table(statement, qry, tbl, tmp_cond, dst_tree);
        // aLL the exprs have been extracted
        if (ret == OG_SUCCESS && tmp_cond->type == COND_NODE_TRUE) {
            *tree = NULL;
        }
    } else {
        status_t ret = expl_extract_cond_by_table(statement, qry, tbl, (*tree)->root, dst_tree);
        if ((ret == OG_SUCCESS) && ((*tree)->root->type == COND_NODE_TRUE)) {
            *tree = NULL;
        }
    }
}

static status_t expl_get_table_scan_cond(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    pred_helper_t *helper, bool32 extracted, cond_tree_t *dst_tree)
{
    cond_tree_t *src_cond = qry->cond;
    if (!extracted && src_cond != NULL && src_cond->root->type != COND_NODE_TRUE &&
        src_cond != helper->hash_filter) {
        OG_RETURN_IFERR(sql_clone_cond_tree(&helper->vmc, src_cond, &helper->cond, vmc_alloc_mem));
        OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, helper->cond->root, dst_tree));
    } else {
        if (helper->nl_filter != NULL) {
            OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, helper->nl_filter->root, dst_tree));
        }
        if (helper->outer_cond != NULL) {
            cond_node_t *tmp_outer_cond = NULL;
            OG_RETURN_IFERR(sql_clone_cond_node(&helper->vmc, helper->outer_cond->root, &tmp_outer_cond,
                vmc_alloc_mem));
            extract_cond_and_set_null(statement, qry, tbl, &helper->outer_cond, tmp_outer_cond, dst_tree);
        }
    }

    if (dst_tree->root == NULL && helper->l_hash_filter != NULL) {
        extract_cond_and_set_null(statement, qry, tbl, &helper->l_hash_filter, NULL, dst_tree);
    }
    if (dst_tree->root == NULL && helper->r_hash_filter != NULL) {
        extract_cond_and_set_null(statement, qry, tbl, &helper->r_hash_filter, NULL, dst_tree);
    }

    src_cond = tbl->cond;  // indexscan
    if (dst_tree->root == NULL && src_cond != NULL && tbl->type == NORMAL_TABLE && !tbl->index_cond_pruning &&
        src_cond->root->type != COND_NODE_TRUE) {
        cond_node_t *tmp_cond = NULL;
        OG_RETURN_IFERR(sql_clone_cond_node(&helper->vmc, src_cond->root, &tmp_cond, vmc_alloc_mem));
        OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, tmp_cond, dst_tree));
    }

    return OG_SUCCESS;
}

static bool32 index_cond_need_to_extract(sql_table_t *tbl, cond_tree_t *dst_tree)
{
    return (tbl->type == NORMAL_TABLE && !tbl->index_full_scan && dst_tree->root != NULL);
}

static void init_index_node_for_cmp(expr_node_t *exprn, sql_table_t *tbl, uint32 col_id, knl_column_t *knl_col)
{
    exprn->type = EXPR_NODE_COLUMN;
    exprn->unary = UNARY_OPER_NONE;
    exprn->datatype = knl_col->datatype;
    exprn->value.v_col.tab = tbl->id;
    exprn->value.v_col.ancestor = 0;
    exprn->value.v_col.col = (uint16)col_id;
    exprn->value.v_col.datatype = knl_col->datatype;

    return;
}

static bool32 init_index_node_of_virtual_col_for_cmp(expr_node_t **exprn, sql_stmt_t *statement, sql_table_t *tbl,
                                              knl_column_t *knl_col)
{
    if (sql_clone_expr_node((void *)statement, ((expr_tree_t *)knl_col->default_expr)->root, exprn,
                            sql_stack_alloc) == OG_SUCCESS) {
        rbo_update_column_in_func(statement, exprn, tbl->id);
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 index_related_cmp_for_virtual_col(sql_stmt_t *statement, sql_table_t *tbl, cmp_node_t *cmp_node,
                                         knl_column_t *knl_col)
{
    // Initialize a temporary node for comparison
    expr_node_t *exprn = NULL;
    OGSQL_SAVE_STACK(statement);
    if (!init_index_node_of_virtual_col_for_cmp(&exprn, statement, tbl, knl_col)) {
        OGSQL_RESTORE_STACK(statement);
        return OG_FALSE;
    }
    if ((cmp_node->left != NULL && sql_expr_node_equal(statement, exprn, cmp_node->left->root, NULL)) ||
        (cmp_node->right != NULL && sql_expr_node_equal(statement, exprn, cmp_node->right->root, NULL))) {
        OGSQL_RESTORE_STACK(statement);
        return OG_TRUE;
    }
    OGSQL_RESTORE_STACK(statement);
    return OG_FALSE;
}

static bool32 index_related_cmp_for_col(sql_stmt_t *statement, sql_table_t *tbl, cmp_node_t *cmp_node, uint32 col_id,
                                 knl_column_t *knl_col)
{
    expr_node_t exprn = { 0 };
    // Initialize a temporary node for comparison
    init_index_node_for_cmp(&exprn, tbl, col_id, knl_col);

    if ((cmp_node->left != NULL && sql_expr_node_equal(statement, &exprn, cmp_node->left->root, NULL)) ||
        (cmp_node->right != NULL && sql_expr_node_equal(statement, &exprn, cmp_node->right->root, NULL))) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static bool32 index_related_cmp_node(sql_stmt_t *statement, sql_table_t *tbl, cmp_node_t *cmp_node)
{
    for (uint32 i = 0; i < tbl->index->column_count; i++) {
        uint32 col_id = tbl->index->columns[i];
        knl_column_t *knl_col = knl_get_column(tbl->entry->dc.handle, col_id);
        if (KNL_COLUMN_IS_VIRTUAL(knl_col)) {
            if (index_related_cmp_for_virtual_col(statement, tbl, cmp_node, knl_col)) {
                return OG_TRUE;
            }
        } else {
            if (index_related_cmp_for_col(statement, tbl, cmp_node, col_id, knl_col)) {
                return OG_TRUE;
            }
        }
    }
    return OG_FALSE;
}

static bool32 index_related_cond(sql_stmt_t *statement, sql_table_t *tbl, cond_node_t *cond)
{
    if (cond->type == COND_NODE_AND || cond->type == COND_NODE_OR) {
        return index_related_cond(statement, tbl, cond->left) && index_related_cond(statement, tbl, cond->right);
    }
    if (cond->type == COND_NODE_COMPARE) {
        return index_related_cmp_node(statement, tbl, cond->cmp);
    }
    return OG_TRUE;
}

static status_t expl_extract_index_cond(sql_stmt_t *statement, sql_table_t *tbl, cond_node_t *src_cond,
    cond_tree_t *dst_tree)
{
    if (src_cond->type == COND_NODE_AND) {
        OG_RETURN_IFERR(expl_extract_index_cond(statement, tbl, src_cond->left, dst_tree));
        OG_RETURN_IFERR(expl_extract_index_cond(statement, tbl, src_cond->right, dst_tree));
        try_eval_logic_and(src_cond);
        return OG_SUCCESS;
    }
    
    if ((src_cond->type == COND_NODE_OR &&
         index_related_cond(statement, tbl, src_cond->left) &&
         index_related_cond(statement, tbl, src_cond->right)) ||
        (src_cond->type == COND_NODE_COMPARE &&
         index_related_cmp_node(statement, tbl, src_cond->cmp))) {
        OG_RETURN_IFERR(merge_cond_by_copy(src_cond, dst_tree));
        src_cond->type = COND_NODE_TRUE;
    }

    return OG_SUCCESS;
}

static status_t expl_extract_concat_index_cond(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    sql_table_t *tbl)
{
    cond_tree_t *cond_tree = NULL;
    cond_node_t *tbl_cond = NULL;
    helper->idx_cond->root = NULL;
    OG_RETURN_IFERR(vmc_alloc_mem(&helper->vmc, sizeof(cond_tree_t), (void **)&cond_tree));
    sql_init_cond_tree(&helper->vmc, cond_tree, vmc_alloc_mem);
    OG_RETURN_IFERR(sql_clone_cond_node(&helper->vmc, tbl->cond->root, &tbl_cond, vmc_alloc_mem));
    OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, tbl_cond, cond_tree));
    return expl_extract_index_cond(statement, tbl, cond_tree->root, helper->idx_cond);
}

static status_t expl_get_table_index_cond(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    sql_table_t *tbl, cond_tree_t *dst_tree)
{
    if (tbl->index == NULL) {
        return OG_SUCCESS;
    }
    // tbl->cond only contains conds related to index
    if (tbl->index->column_count == tbl->idx_equal_to && tbl->index_cond_pruning) {
        helper->idx_cond = tbl->cond;
        return OG_SUCCESS;
    }

    // extract cond nodes related to index of dst_tree and add them to the right subtree
    if (index_cond_need_to_extract(tbl, dst_tree)) {
        // initialize
        OG_RETURN_IFERR(vmc_alloc_mem(&helper->vmc, sizeof(cond_tree_t), (void **)&helper->idx_cond));
        sql_init_cond_tree(&helper->vmc, helper->idx_cond, vmc_alloc_mem);

        OG_RETURN_IFERR(expl_extract_index_cond(statement, tbl, dst_tree->root, helper->idx_cond));
        if (helper->concate_type == JOIN_CONCATE) {
            OG_RETURN_IFERR(expl_extract_concat_index_cond(statement, qry, helper, tbl));
        }
    }

    //  conds related to index are added to the left subtree
    if (tbl->index->column_count != tbl->idx_equal_to && tbl->index_cond_pruning) {
        if (helper->idx_cond == NULL) {
            OG_RETURN_IFERR(vmc_alloc_mem(&helper->vmc, sizeof(cond_tree_t), (void **)&helper->idx_cond));
            sql_init_cond_tree(&helper->vmc, helper->idx_cond, vmc_alloc_mem);
        }
        OG_RETURN_IFERR(sql_add_cond_node_left(helper->idx_cond, tbl->cond->root));
    }
    return OG_SUCCESS;
}

static status_t expl_extract_merge_hash_cond(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
    pred_helper_t *helper, cond_tree_t *dst_tree)
{
    cond_node_t *cond = NULL;
    OG_RETURN_IFERR(sql_clone_cond_node(&helper->vmc, helper->merge_cond->root, &cond, vmc_alloc_mem));
    OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, cond, dst_tree));
    return expl_get_table_index_cond(statement, qry, helper, tbl, dst_tree);
}

static void expl_get_concate_table_cond(sql_query_t *qry, pred_helper_t *helper, cond_node_t **cond)
{
    get_cond_node_t get_cond_node[] = {
        { qry->cond != NULL && qry->cond->root->type != COND_NODE_TRUE, qry->cond },
        { helper->nl_filter != NULL, helper->nl_filter },
        { helper->outer_cond != NULL, helper->outer_cond },
        { helper->l_hash_filter != NULL, helper->l_hash_filter },
        { helper->r_hash_filter != NULL, helper->r_hash_filter }
    };
    for (uint32 i = 0; i < sizeof(get_cond_node) / sizeof(get_cond_node[0]); i++) {
        if (get_cond_node[i].tbl_cond) {
            *cond = get_cond_node[i].cond_tree->root;
            break;
        }
    }
    return;
}

static status_t expl_extract_concate_table_cond(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
                                         pred_helper_t *helper, cond_tree_t *dst_tree)
{
    cond_node_t *tbl_cond = NULL;
    cond_node_t *tmp_cond = NULL;
    expl_get_concate_table_cond(qry, helper, &tbl_cond);
    if (tbl_cond != NULL) {
        if (helper->nl_filter != NULL && tbl_cond == helper->nl_filter->root) {
            tmp_cond = tbl_cond;
        } else {
            OG_RETURN_IFERR(sql_clone_cond_node(&helper->vmc, tbl_cond, &tmp_cond, vmc_alloc_mem));
        }
        OG_RETURN_IFERR(expl_extract_cond_by_table(statement, qry, tbl, tmp_cond, dst_tree));
    }
    
    if (tbl->index == NULL || tbl->index_full_scan) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(vmc_alloc_mem(&helper->vmc, sizeof(cond_tree_t), (void **)&helper->idx_cond));
    sql_init_cond_tree(&helper->vmc, helper->idx_cond, vmc_alloc_mem);
    if (dst_tree->root != NULL) {
        OG_RETURN_IFERR(expl_extract_index_cond(statement, tbl, dst_tree->root, helper->idx_cond));
    }
    return expl_extract_concat_index_cond(statement, qry, helper, tbl);
}

static status_t expl_extract_normal_table_cond(sql_stmt_t *statement, sql_query_t *qry, sql_table_t *tbl,
                                        pred_helper_t *helper, cond_tree_t *dst_tree)
{
    bool32 extracted = OG_FALSE;
    if (helper->cond != NULL) {
        extract_cond_and_set_null(statement, qry, tbl, &helper->cond, NULL, dst_tree);
        extracted = OG_TRUE;
    }

    if (dst_tree->root == NULL) {
        OG_RETURN_IFERR(expl_get_table_scan_cond(statement, qry, tbl, helper, extracted, dst_tree));
    }
    return expl_get_table_index_cond(statement, qry, helper, tbl, dst_tree);
}

static status_t expl_format_node_scan(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper, plan_node_t *plan)
{
    cond_tree_t *dst_tree;
    OG_RETURN_IFERR(vmc_alloc_mem(&helper->vmc, sizeof(cond_tree_t), (void **)&dst_tree));
    sql_init_cond_tree(&helper->vmc, dst_tree, vmc_alloc_mem);

    sql_table_t *tbl = plan->scan_p.table;

    if (helper->is_merge_hash && helper->merge_cond == NULL) {
        return OG_SUCCESS;
    }

    if (helper->is_merge_hash) {
        OG_RETURN_IFERR(expl_extract_merge_hash_cond(statement, qry, tbl, helper, dst_tree));
    } else if (helper->concate_type == TABLE_CONCATE) {
        OG_RETURN_IFERR(expl_extract_concate_table_cond(statement, qry, tbl, helper, dst_tree));
    } else {
        // normal tbl scan cond
        OG_RETURN_IFERR(expl_extract_normal_table_cond(statement, qry, tbl, helper, dst_tree));
    }

    return expl_put_pred_info(statement, qry, helper, dst_tree);
}

static status_t expl_format_node_connect(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    plan_node_t *plan)
{
    cond_tree_t *tree = NULL;
    if (helper->is_start_with) {
        tree = plan->connect.start_with_cond;
    } else {
        tree = plan->connect.connect_by_cond;
    }

    return expl_put_pred_info(statement, qry, helper, tree);
}

static status_t expl_format_node_filter(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    plan_node_t *plan)
{
    cond_tree_t *tree = plan->filter.cond;
    return expl_put_pred_info(statement, qry, helper, tree);
}

static status_t expl_format_node_hash_mtrl(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    plan_node_t *plan)
{
    int row_id = helper->parent->row_helper.id;
    var_text_t *content = &helper->content;

    CM_TEXT_CLEAR(content);
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_ACCESS)));
    OG_RETURN_IFERR(ogsql_unparse_hash_mtrl_node(qry, plan, content));
    OG_RETURN_IFERR(expl_put_pred_data(statement, helper, content));
    CM_TEXT_CLEAR(content);

    return OG_SUCCESS;
}

static status_t ogsql_expr_is_row_num(visit_assist_t *v_ast, expr_node_t **exprn)
{
    if (!v_ast->result0 && NODE_IS_RES_ROWNUM(*exprn)) {
        v_ast->result0 = OG_TRUE;
    }

    return OG_SUCCESS;
}

static bool32 ogsql_cmp_node_has_rownum(sql_stmt_t *statement, sql_query_t *qry, cmp_node_t* cmp)
{
    visit_assist_t v_ast;
    sql_init_visit_assist(&v_ast, statement, qry);
    v_ast.result0 = OG_FALSE;
    visit_cmp_node(&v_ast, cmp, ogsql_expr_is_row_num);

    return v_ast.result0;
}

static bool32 ogsql_cond_tree_has_rownum(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond)
{
    if (cond->type == COND_NODE_AND || cond->type == COND_NODE_OR) {
        return ogsql_cond_tree_has_rownum(statement, qry, cond->left) ||
               ogsql_cond_tree_has_rownum(statement, qry, cond->right);
    } else if (cond->type == COND_NODE_COMPARE) {
        return ogsql_cmp_node_has_rownum(statement, qry, cond->cmp);
    }

    return OG_FALSE;
}

static status_t ogsql_unparse_rownumm_cond_tree(sql_stmt_t *statement, sql_query_t *qry, cond_node_t *cond,
    var_text_t *result, bool32 *has_cond)
{
    if (cond->type == COND_NODE_AND) {
        OG_RETURN_IFERR(ogsql_unparse_rownumm_cond_tree(statement, qry, cond->left, result, has_cond));
        return ogsql_unparse_rownumm_cond_tree(statement, qry, cond->right, result, has_cond);
    } else if (cond->type == COND_NODE_OR) {
        if (ogsql_cond_tree_has_rownum(statement, qry, cond)) {
            if (!(*has_cond)) {
                *has_cond = OG_TRUE;
            } else {
                OG_RETURN_IFERR(cm_concat_var_string(result, "AND"));
            }
            return ogsql_unparse_cond_node(qry, cond, OG_TRUE, result);
        }
    } else if (cond->type == COND_NODE_COMPARE) {
        if (!ogsql_cmp_node_has_rownum(statement, qry, cond->cmp)) {
            return OG_SUCCESS;
        }
        if (!(*has_cond)) {
            *has_cond = OG_TRUE;
        } else {
            OG_RETURN_IFERR(cm_concat_var_string(result, "AND"));
        }
        return ogsql_unparse_cond_node(qry, cond, OG_FALSE, result);
    }

    return OG_SUCCESS;
}

static status_t expl_format_node_rownum(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    plan_node_t *plan)
{
    cond_tree_t *tree = NULL;
    if (qry->join_assist.outer_node_count > 0) {
        tree = qry->filter_cond;
    } else {
        tree = qry->cond;
    }
    if (tree == NULL) {
        return OG_SUCCESS;
    }
    int row_id = helper->parent->row_helper.id;
    var_text_t *content = &helper->content;
    bool32 has_cond = OG_FALSE;  // if CT_TRUE: need add "AND" in front

    CM_TEXT_CLEAR(content);
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_FILTER)));
    OG_RETURN_IFERR(ogsql_unparse_rownumm_cond_tree(statement, qry, tree->root, content, &has_cond));
    return expl_put_pred_data(statement, helper, content);
}

static status_t expl_format_node_connect_mtrl(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
    plan_node_t *plan)
{
    int row_id = helper->parent->row_helper.id;
    var_text_t *content = &helper->content;

    CM_TEXT_CLEAR(content);
    OG_RETURN_IFERR(expl_format_cond_head(content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(content, expl_get_pred_type(PREDICATE_ACCESS)));
    OG_RETURN_IFERR(ogsql_unparse_connect_mtrl_join_node(qry, plan, content));
    OG_RETURN_IFERR(expl_put_pred_data(statement, helper, content));

    cond_tree_t *tree = plan->cb_mtrl.start_with_cond;
    if (tree == NULL || tree->root->type == COND_NODE_TRUE) {
        return OG_SUCCESS;
    }
    helper->type = PREDICATE_FILTER;
    return expl_put_pred_info(statement, qry, helper, tree);
}

static expl_pred_t g_expl_pred_funcs[] = {{PLAN_NODE_JOIN, expl_format_node_join},
                                          {PLAN_NODE_HAVING, expl_format_node_having},
                                          {PLAN_NODE_SCAN, expl_format_node_scan},
                                          {PLAN_NODE_CONNECT, expl_format_node_connect},
                                          {PLAN_NODE_FILTER, expl_format_node_filter},
                                          {PLAN_NODE_HASH_MTRL, expl_format_node_hash_mtrl},
                                          {PLAN_NODE_ROWNUM, expl_format_node_rownum},
                                          {PLAN_NODE_CONNECT_MTRL, expl_format_node_connect_mtrl},
                                          {PLAN_NODE_CONNECT_HASH, expl_format_node_connect}};

static inline bool32 expl_is_support_predicate(plan_node_type_t type)
{
    for (int32 i = 0; i < sizeof(g_expl_pred_funcs) / sizeof(expl_pred_t); i++) {
        if (type == g_expl_pred_funcs[i].type) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

static status_t expl_format_pred_row_by_type(sql_stmt_t *statement, sql_query_t *qry, pred_helper_t *helper,
                                             plan_node_t *plan)
{
    expl_pred_t *pred_func = NULL;
    for (int32 i = 0; i < sizeof(g_expl_pred_funcs) / sizeof(expl_pred_t); i++) {
        if (plan->type == g_expl_pred_funcs[i].type) {
            pred_func = &g_expl_pred_funcs[i];
            break;
        }
    }

    if (pred_func == NULL) {
        return OG_SUCCESS;
    }

    return pred_func->expl_pred_func(statement, qry, helper, plan);
}

status_t expl_format_predicate_row(sql_stmt_t *statement, pred_helper_t *helper, plan_node_t *plan)
{
    sql_query_t *qry = NULL;
    if (!helper->is_enabled || !expl_is_support_predicate(plan->type)) {
        return OG_SUCCESS;
    }

    if (helper->is_start_with && helper->parent->query != NULL && helper->parent->query->s_query != NULL) {
        qry = helper->parent->query->s_query;
    } else if (helper->parent->query != NULL) {
        qry = helper->parent->query;
    } else if (statement->context->type == OGSQL_TYPE_MERGE) {
        qry = ((sql_merge_t *)statement->context->entry)->query;
    }

    if (qry == NULL) {
        return OG_SUCCESS;
    }

    if (IS_COND_FALSE(qry->cond)) {
        return expl_put_pred_info(statement, qry, helper, qry->cond);
    }
    return expl_format_pred_row_by_type(statement, qry, helper, plan);
}

status_t expl_format_merge_hash_cond(sql_stmt_t *statement, pred_helper_t *helper, plan_node_t *plan)
{
    CM_TEXT_CLEAR(&helper->content);
    int row_id = helper->parent->row_helper.id;
    sql_merge_t *merge_ctx = (sql_merge_t *)statement->context->entry;
    
    OG_RETURN_IFERR(expl_format_cond_head(&helper->content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(&helper->content, expl_get_pred_type(PREDICATE_ACCESS)));
    OG_RETURN_IFERR(ogsql_unparse_merge_hash_cond_node(merge_ctx->query, plan, &helper->content));
    return expl_put_pred_data(statement, helper, &helper->content);
}

status_t expl_format_pred_index_cond(sql_stmt_t *statement, pred_helper_t *helper, plan_node_t *plan)
{
    sql_query_t *qry = NULL;
    CM_TEXT_CLEAR(&helper->content);
    int row_id = helper->parent->row_helper.id;

    if (helper->parent->query != NULL) {
        qry = helper->parent->query;
    } else if (statement->context->type == OGSQL_TYPE_MERGE) {
        qry = ((sql_merge_t *)statement->context->entry)->query;
    }
    
    OG_RETURN_IFERR(expl_format_cond_head(&helper->content, row_id, OG_FALSE));
    OG_RETURN_IFERR(cm_concat_var_string(&helper->content, expl_get_pred_type(PREDICATE_ACCESS)));
    OG_RETURN_IFERR(ogsql_unparse_cond_node(qry, helper->idx_cond->root, OG_FALSE, &helper->content));
    // after unparsing, the node should be null
    helper->idx_cond = NULL;
    return expl_put_pred_data(statement, helper, &helper->content);
}