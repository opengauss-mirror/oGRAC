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
 * pl_rbt.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/type/pl_rbt.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_rbt.h"

static status_t get_left_rowid(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, mtrl_rowid_t *result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    *result = node->left;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t get_right_rowid(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, mtrl_rowid_t *result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    *result = node->right;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t get_parent_rowid(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, mtrl_rowid_t *result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    *result = node->parent;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t get_color(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, int32 *result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    *result = node->color;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t set_left_rowid(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, mtrl_rowid_t result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    node->left = result;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t set_right_rowid(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, mtrl_rowid_t result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    node->right = result;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t set_parent_rowid(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, mtrl_rowid_t result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    node->parent = result;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

static status_t set_color(sql_stmt_t *stmt, mtrl_rowid_t node_rowid, int32 result)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node = NULL;

    OPEN_VM_PTR(&node_rowid, vm_ctx);
    node = (rbt_node_t *)d_ptr;
    node->color = result;
    CLOSE_VM_PTR(&node_rowid, vm_ctx);
    return OG_SUCCESS;
}

/* If node_x or node_y node's either child is NIL node:
 * Left / right rotation might change the NIL's parent.
 * NIL's parent shouldn't be changed.
 * If NIL's parent node changes,
 * then delete_fixUp function might access NIL's parent's right/left child,
 * which might lead to error.
 * Solution: So we record the NIL's parent and at the end of the rotaion,
 * replace the NIL's parent with the recorded node.
 */
status_t rbt_left_rotate_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t node_x)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t nil_parent;
    mtrl_rowid_t node_y;
    mtrl_rowid_t node_ly;
    mtrl_rowid_t left;
    mtrl_rowid_t parent;

    if (rbt_tree == NULL || IS_INVALID_MTRL_ROWID(node_x)) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    nil_node = rbt_tree->nil_node;
    OG_RETURN_IFERR(get_parent_rowid(stmt, nil_node, &nil_parent));

    /*
     * x                       y
     * / \                     / \
     * lx  y      ----->       x  ry
     * / \                 / \
     * ly ry               lx ly
     */
    OG_RETURN_IFERR(get_right_rowid(stmt, node_x, &node_y));
    OG_RETURN_IFERR(get_left_rowid(stmt, node_y, &node_ly));
    OG_RETURN_IFERR(set_right_rowid(stmt, node_x, node_ly));
    OG_RETURN_IFERR(set_parent_rowid(stmt, node_ly, node_x));
    OG_RETURN_IFERR(get_parent_rowid(stmt, node_x, &parent));
    OG_RETURN_IFERR(set_parent_rowid(stmt, node_y, parent));

    if (IS_SAME_MTRL_ROWID(nil_node, parent)) {
        rbt_tree->root = node_y;
    } else {
        OG_RETURN_IFERR(get_left_rowid(stmt, parent, &left));
        if (IS_SAME_MTRL_ROWID(node_x, left)) {
            OG_RETURN_IFERR(set_left_rowid(stmt, parent, node_y));
        } else {
            OG_RETURN_IFERR(set_right_rowid(stmt, parent, node_y));
        }
    }
    OG_RETURN_IFERR(set_parent_rowid(stmt, node_x, node_y));
    OG_RETURN_IFERR(set_left_rowid(stmt, node_y, node_x));
    return set_parent_rowid(stmt, nil_node, nil_parent);
}

status_t rbt_right_rotate_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t node_y)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t nil_parent;
    mtrl_rowid_t node_x;
    mtrl_rowid_t node_rx;
    mtrl_rowid_t right;
    mtrl_rowid_t parent;

    if (rbt_tree == NULL || IS_INVALID_MTRL_ROWID(node_y)) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    nil_node = rbt_tree->nil_node;
    OG_RETURN_IFERR(get_parent_rowid(stmt, nil_node, &nil_parent));
    /*
     * y                   x
     * / \                 / \
     * x  ry   ----->      lx  y
     * / \                     / \
     * lx  rx                   rx ry
     */
    OG_RETURN_IFERR(get_left_rowid(stmt, node_y, &node_x));
    OG_RETURN_IFERR(get_right_rowid(stmt, node_x, &node_rx));
    OG_RETURN_IFERR(set_left_rowid(stmt, node_y, node_rx));
    OG_RETURN_IFERR(set_parent_rowid(stmt, node_rx, node_y));
    OG_RETURN_IFERR(get_parent_rowid(stmt, node_y, &parent));
    OG_RETURN_IFERR(set_parent_rowid(stmt, node_x, parent));

    if (IS_SAME_MTRL_ROWID(nil_node, parent)) {
        rbt_tree->root = node_x;
    } else {
        OG_RETURN_IFERR(get_right_rowid(stmt, parent, &right));
        if (IS_SAME_MTRL_ROWID(node_y, right)) {
            OG_RETURN_IFERR(set_right_rowid(stmt, parent, node_x));
        } else {
            OG_RETURN_IFERR(set_left_rowid(stmt, parent, node_x));
        }
    }
    OG_RETURN_IFERR(set_parent_rowid(stmt, node_y, node_x));
    OG_RETURN_IFERR(set_right_rowid(stmt, node_x, node_y));
    return set_parent_rowid(stmt, nil_node, nil_parent);
}

// using to judge whether the the key of dest_node is the same as the key of other nodes
status_t rbt_search_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, variant_t *index, mtrl_rowid_t *parent,
    mtrl_rowid_t *result)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t node;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    int32 cmp_result = 0;

    if (rbt_tree == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    node = rbt_tree->root;
    nil_node = rbt_tree->nil_node;
    while (!IS_SAME_MTRL_ROWID(nil_node, node)) {
        *parent = node;
        OG_RETURN_IFERR(rbt_tree->key_cmp(stmt, node, index, &cmp_result));
        if (cmp_result < 0) {
            OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
            node = right;
        } else if (cmp_result > 0) {
            OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
            node = left;
        } else {
            *result = node;
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

status_t rbt_get_rowid_by_key(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, variant_t *index, mtrl_rowid_t *result)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t node;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    int32 cmp_result = 0;

    if (rbt_tree == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    node = rbt_tree->root;
    nil_node = rbt_tree->nil_node;
    while (!IS_SAME_MTRL_ROWID(nil_node, node)) {
        OG_RETURN_IFERR(rbt_tree->key_cmp(stmt, node, index, &cmp_result));
        if (cmp_result < 0) {
            OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
            node = right;
        } else if (cmp_result > 0) {
            OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
            node = left;
        } else {
            *result = node;
            return OG_SUCCESS;
        }
    }
    return OG_SUCCESS;
}

static status_t rbt_insert_fixup_left_black(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t grand_parent,
    mtrl_rowid_t parent, mtrl_rowid_t *curr_node)
{
    mtrl_rowid_t right;
    mtrl_rowid_t curr_parent;
    OG_RETURN_IFERR(get_right_rowid(stmt, parent, &right));
    if (IS_SAME_MTRL_ROWID(right, *curr_node)) {
        *curr_node = parent;
        OG_RETURN_IFERR(rbt_left_rotate_node(stmt, rbt_tree, *curr_node));
    }

    OG_RETURN_IFERR(get_parent_rowid(stmt, *curr_node, &curr_parent));
    OG_RETURN_IFERR(set_color(stmt, curr_parent, RBT_BLACK));
    OG_RETURN_IFERR(set_color(stmt, grand_parent, RBT_RED));
    return rbt_right_rotate_node(stmt, rbt_tree, grand_parent);
}

static status_t rbt_insert_fixup_right_black(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t grand_parent,
    mtrl_rowid_t parent, mtrl_rowid_t *curr_node)
{
    mtrl_rowid_t left;
    mtrl_rowid_t curr_parent;
    OG_RETURN_IFERR(get_left_rowid(stmt, parent, &left));
    if (IS_SAME_MTRL_ROWID(left, *curr_node)) {
        *curr_node = parent;
        OG_RETURN_IFERR(rbt_right_rotate_node(stmt, rbt_tree, *curr_node));
    }

    OG_RETURN_IFERR(get_parent_rowid(stmt, *curr_node, &curr_parent)); // curr_parent is different from parent
    OG_RETURN_IFERR(set_color(stmt, curr_parent, RBT_BLACK));
    OG_RETURN_IFERR(set_color(stmt, grand_parent, RBT_RED));
    return rbt_left_rotate_node(stmt, rbt_tree, grand_parent);
}

static status_t rbt_insert_node_fixup(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_curr_node)
{
    mtrl_rowid_t parent;
    mtrl_rowid_t grand_parent;
    mtrl_rowid_t uncle;
    mtrl_rowid_t left;
    mtrl_rowid_t curr_node = tmp_curr_node;
    int32 curr_par_color;
    int32 color;

    if (rbt_tree == NULL || IS_INVALID_MTRL_ROWID(curr_node)) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    /* NIL is forbidden. */
    CM_ASSERT(!IS_SAME_MTRL_ROWID(curr_node, rbt_tree->nil_node));
    rbt_tree->node_count++;

    OG_RETURN_IFERR(get_parent_rowid(stmt, curr_node, &parent));
    OG_RETURN_IFERR(get_color(stmt, parent, &curr_par_color));

    while (RBT_RED == curr_par_color) {
        OG_RETURN_IFERR(get_parent_rowid(stmt, parent, &grand_parent));
        OG_RETURN_IFERR(get_left_rowid(stmt, grand_parent, &left));

        if (IS_SAME_MTRL_ROWID(parent, left)) {
            OG_RETURN_IFERR(get_right_rowid(stmt, grand_parent, &uncle));
            OG_RETURN_IFERR(get_color(stmt, uncle, &color));
            if (RBT_RED == color) {
                OG_RETURN_IFERR(set_color(stmt, uncle, RBT_BLACK));
                OG_RETURN_IFERR(set_color(stmt, parent, RBT_BLACK));
                OG_RETURN_IFERR(set_color(stmt, grand_parent, RBT_RED));
                curr_node = grand_parent;
                OG_RETURN_IFERR(get_parent_rowid(stmt, curr_node, &parent));
                OG_RETURN_IFERR(get_color(stmt, parent, &curr_par_color));
                continue;
            }
            OG_RETURN_IFERR(rbt_insert_fixup_left_black(stmt, rbt_tree, grand_parent, parent, &curr_node));
        } else {
            uncle = left;
            OG_RETURN_IFERR(get_color(stmt, uncle, &color));
            if (RBT_RED == color) {
                OG_RETURN_IFERR(set_color(stmt, uncle, RBT_BLACK));
                OG_RETURN_IFERR(set_color(stmt, parent, RBT_BLACK));
                OG_RETURN_IFERR(set_color(stmt, grand_parent, RBT_RED));
                curr_node = grand_parent;
                OG_RETURN_IFERR(get_parent_rowid(stmt, curr_node, &parent));
                OG_RETURN_IFERR(get_color(stmt, parent, &curr_par_color));
                continue;
            }
            OG_RETURN_IFERR(rbt_insert_fixup_right_black(stmt, rbt_tree, grand_parent, parent, &curr_node));
        }
        OG_RETURN_IFERR(get_parent_rowid(stmt, curr_node, &parent));
        OG_RETURN_IFERR(get_color(stmt, parent, &curr_par_color));
    }

    return set_color(stmt, rbt_tree->root, RBT_BLACK);
}

status_t rbt_insert_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t *parent, mtrl_rowid_t new_node,
    bool8 flag)
{
    mtrl_rowid_t temp;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t nil_node;
    int32 cmp_result = 0;
    temp = rbt_tree->root;
    nil_node = rbt_tree->nil_node;

    while (flag && IS_VALID_MTRL_ROWID(temp) && !IS_SAME_MTRL_ROWID(nil_node, temp)) {
        *parent = temp;
        OG_RETURN_IFERR(rbt_tree->node_cmp(stmt, temp, new_node, &cmp_result));
        if (cmp_result < 0) {
            OG_RETURN_IFERR(get_right_rowid(stmt, temp, &right));
            temp = right;
        } else if (cmp_result > 0) {
            OG_RETURN_IFERR(get_left_rowid(stmt, temp, &left));
            temp = left;
        } else {
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "this red black tree node is existent");
            return OG_ERROR;
        }
    }

    if (IS_INVALID_MTRL_ROWID(*parent)) {
        OG_RETURN_IFERR(set_parent_rowid(stmt, new_node, nil_node));
        rbt_tree->root = new_node;
    } else {
        OG_RETURN_IFERR(set_parent_rowid(stmt, new_node, *parent));
        OG_RETURN_IFERR(rbt_tree->node_cmp(stmt, *parent, new_node, &cmp_result));
        if (cmp_result < 0) {
            OG_RETURN_IFERR(set_right_rowid(stmt, *parent, new_node));
        } else {
            OG_RETURN_IFERR(set_left_rowid(stmt, *parent, new_node));
        }
    }
    OG_RETURN_IFERR(set_left_rowid(stmt, new_node, nil_node));
    OG_RETURN_IFERR(set_right_rowid(stmt, new_node, nil_node));
    OG_RETURN_IFERR(set_color(stmt, new_node, RBT_RED));

    return rbt_insert_node_fixup(stmt, rbt_tree, new_node);
}

static status_t rbt_delete_node_fixup_left(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t parent,
    mtrl_rowid_t *curr_node)
{
    mtrl_rowid_t brother;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t node;
    int32 color;
    int32 color2;
    node = *curr_node;

    OG_RETURN_IFERR(get_right_rowid(stmt, parent, &brother));
    OG_RETURN_IFERR(get_color(stmt, brother, &color));
    if (RBT_RED == color) {
        OG_RETURN_IFERR(set_color(stmt, brother, RBT_BLACK));
        OG_RETURN_IFERR(set_color(stmt, parent, RBT_RED));
        OG_RETURN_IFERR(rbt_left_rotate_node(stmt, rbt_tree, parent));
        OG_RETURN_IFERR(get_right_rowid(stmt, parent, &brother));
    }

    OG_RETURN_IFERR(get_left_rowid(stmt, brother, &left));
    OG_RETURN_IFERR(get_color(stmt, left, &color));
    OG_RETURN_IFERR(get_right_rowid(stmt, brother, &right));
    OG_RETURN_IFERR(get_color(stmt, left, &color2));

    if (RBT_BLACK == color && RBT_BLACK == color2) {
        OG_RETURN_IFERR(set_color(stmt, brother, RBT_RED));
        OG_RETURN_IFERR(get_parent_rowid(stmt, node, &node));
    } else {
        OG_RETURN_IFERR(get_parent_rowid(stmt, node, &parent));
        if (RBT_BLACK == color2) {
            OG_RETURN_IFERR(set_color(stmt, left, RBT_BLACK));
            OG_RETURN_IFERR(set_color(stmt, brother, RBT_RED));
            OG_RETURN_IFERR(rbt_right_rotate_node(stmt, rbt_tree, brother));
            OG_RETURN_IFERR(get_right_rowid(stmt, parent, &brother));
        }
        OG_RETURN_IFERR(get_color(stmt, parent, &color));
        OG_RETURN_IFERR(set_color(stmt, brother, color));
        OG_RETURN_IFERR(set_color(stmt, parent, RBT_BLACK));

        OG_RETURN_IFERR(get_right_rowid(stmt, brother, &right));
        OG_RETURN_IFERR(set_color(stmt, right, RBT_BLACK));
        OG_RETURN_IFERR(rbt_left_rotate_node(stmt, rbt_tree, parent));
        node = rbt_tree->root;
    }

    *curr_node = node;
    return OG_SUCCESS;
}

static status_t rbt_delete_node_fixup_right(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t parent, mtrl_rowid_t brother,
    mtrl_rowid_t *curr_node)
{
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t node;
    int32 color;
    int32 color2;
    node = *curr_node;

    OG_RETURN_IFERR(get_color(stmt, brother, &color));
    if (RBT_RED == color) {
        OG_RETURN_IFERR(set_color(stmt, brother, RBT_BLACK));
        OG_RETURN_IFERR(set_color(stmt, parent, RBT_RED));
        OG_RETURN_IFERR(rbt_right_rotate_node(stmt, rbt_tree, parent));
        OG_RETURN_IFERR(get_left_rowid(stmt, parent, &brother));
    }

    OG_RETURN_IFERR(get_left_rowid(stmt, brother, &left));
    OG_RETURN_IFERR(get_color(stmt, left, &color));
    OG_RETURN_IFERR(get_right_rowid(stmt, brother, &right));
    OG_RETURN_IFERR(get_color(stmt, left, &color2));
    if (RBT_BLACK == color && RBT_BLACK == color2) {
        OG_RETURN_IFERR(set_color(stmt, brother, RBT_RED));
        OG_RETURN_IFERR(get_parent_rowid(stmt, node, &node));
    } else {
        OG_RETURN_IFERR(get_parent_rowid(stmt, node, &parent));
        if (RBT_BLACK == color) {
            OG_RETURN_IFERR(set_color(stmt, right, RBT_BLACK));
            OG_RETURN_IFERR(set_color(stmt, brother, RBT_RED));
            OG_RETURN_IFERR(rbt_left_rotate_node(stmt, rbt_tree, brother));
            OG_RETURN_IFERR(get_left_rowid(stmt, parent, &brother));
        }
        OG_RETURN_IFERR(get_color(stmt, parent, &color));
        OG_RETURN_IFERR(set_color(stmt, brother, color));
        OG_RETURN_IFERR(set_color(stmt, parent, RBT_BLACK));

        OG_RETURN_IFERR(get_left_rowid(stmt, brother, &left));
        OG_RETURN_IFERR(set_color(stmt, left, RBT_BLACK));
        OG_RETURN_IFERR(rbt_right_rotate_node(stmt, rbt_tree, parent));
        node = rbt_tree->root;
    }

    *curr_node = node;
    return OG_SUCCESS;
}

static status_t rbt_delete_node_fixup(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t node)
{
    mtrl_rowid_t brother;
    mtrl_rowid_t left;
    mtrl_rowid_t parent;
    int32 node_color;

    if (rbt_tree == NULL || IS_INVALID_MTRL_ROWID(node)) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    if (IS_SAME_MTRL_ROWID(node, rbt_tree->nil_node)) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(get_color(stmt, node, &node_color));

    while (!IS_SAME_MTRL_ROWID(rbt_tree->root, node) && RBT_BLACK == node_color) {
        OG_RETURN_IFERR(get_parent_rowid(stmt, node, &parent));
        OG_RETURN_IFERR(get_left_rowid(stmt, parent, &left));

        if (IS_SAME_MTRL_ROWID(left, node)) {
            OG_RETURN_IFERR(rbt_delete_node_fixup_left(stmt, rbt_tree, parent, &node));
        } else {
            brother = left;
            OG_RETURN_IFERR(rbt_delete_node_fixup_right(stmt, rbt_tree, parent, brother, &node));
        }
        OG_RETURN_IFERR(get_color(stmt, node, &node_color));
    }

    return set_color(stmt, node, RBT_BLACK);
}

static status_t rbt_node_clone(sql_stmt_t *stmt, mtrl_rowid_t new_node, mtrl_rowid_t dest_node)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    rbt_node_t *node_left = NULL;
    rbt_node_t *node_right = NULL;

    OPEN_VM_PTR(&dest_node, vm_ctx);
    node_right = (rbt_node_t *)d_ptr;
    if (vmctx_open_row_id(vm_ctx, &new_node, (char **)&node_left) != OG_SUCCESS) {
        CLOSE_VM_PTR_EX(&dest_node, vm_ctx);
        return OG_ERROR;
    }
    node_left->parent = node_right->parent;
    node_left->left = node_right->left;
    node_left->right = node_right->right;
    node_left->color = node_right->color;
    vmctx_close_row_id(vm_ctx, &new_node);
    CLOSE_VM_PTR(&dest_node, vm_ctx);
    return OG_SUCCESS;
}

static status_t rbt_delete_node_has_child(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t del_node,
    mtrl_rowid_t child_node)
{
    mtrl_rowid_t left;
    mtrl_rowid_t parent;
    int32 color = 0;
    OG_RETURN_IFERR(get_parent_rowid(stmt, del_node, &parent));
    OG_RETURN_IFERR(set_parent_rowid(stmt, child_node, parent));

    if (IS_SAME_MTRL_ROWID(rbt_tree->nil_node, parent)) {
        rbt_tree->root = child_node;
    } else {
        OG_RETURN_IFERR(get_left_rowid(stmt, parent, &left));
        if (IS_SAME_MTRL_ROWID(left, del_node)) {
            OG_RETURN_IFERR(set_left_rowid(stmt, parent, child_node));
        } else {
            OG_RETURN_IFERR(set_right_rowid(stmt, parent, child_node));
        }
    }

    OG_RETURN_IFERR(get_color(stmt, del_node, &color));
    if (RBT_BLACK == color) {
        OG_RETURN_IFERR(rbt_delete_node_fixup(stmt, rbt_tree, child_node));
    }
    return OG_SUCCESS;
}

static status_t rbt_delete_node_insert_next(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t del_node, mtrl_rowid_t temp)
{
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t parent;
    OG_RETURN_IFERR(rbt_node_clone(stmt, del_node, temp));

    OG_RETURN_IFERR(get_parent_rowid(stmt, temp, &parent));
    if (IS_SAME_MTRL_ROWID(rbt_tree->nil_node, parent)) {
        rbt_tree->root = del_node;
    } else {
        OG_RETURN_IFERR(get_left_rowid(stmt, parent, &left));
        if (IS_SAME_MTRL_ROWID(left, temp)) {
            OG_RETURN_IFERR(set_left_rowid(stmt, parent, del_node));
        } else {
            OG_RETURN_IFERR(set_right_rowid(stmt, parent, del_node));
        }
    }

    OG_RETURN_IFERR(get_left_rowid(stmt, temp, &left));
    OG_RETURN_IFERR(set_parent_rowid(stmt, left, del_node));

    OG_RETURN_IFERR(get_right_rowid(stmt, temp, &right));
    return set_parent_rowid(stmt, right, del_node);
}

status_t rbt_delete_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_del_node)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t child_node;
    mtrl_rowid_t temp;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t parent;
    mtrl_rowid_t del_node = tmp_del_node;
    int32 color = 0;

    if (rbt_tree == NULL || IS_INVALID_MTRL_ROWID(del_node)) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }
    nil_node = rbt_tree->nil_node;
    /* NIL is forbidden. */
    CM_ASSERT(!IS_SAME_MTRL_ROWID(nil_node, del_node));
    rbt_tree->node_count--;

    OG_RETURN_IFERR(get_left_rowid(stmt, del_node, &left));
    OG_RETURN_IFERR(get_right_rowid(stmt, del_node, &right));

    if (IS_SAME_MTRL_ROWID(nil_node, left) || IS_SAME_MTRL_ROWID(nil_node, right)) {
        child_node = (!IS_SAME_MTRL_ROWID(nil_node, left) ? left : right);
        OG_RETURN_IFERR(rbt_delete_node_has_child(stmt, rbt_tree, del_node, child_node));
        return OG_SUCCESS;
    }

    temp = del_node;
    /* assign del_node's next node to del_node */
    del_node = right; // right is not changed, but left may be changed
    OG_RETURN_IFERR(get_left_rowid(stmt, del_node, &left));
    while (!IS_SAME_MTRL_ROWID(nil_node, left)) {
        del_node = left;
        OG_RETURN_IFERR(get_left_rowid(stmt, del_node, &left));
    }

    /* Because left is nilT, so child must be right. */
    OG_RETURN_IFERR(get_right_rowid(stmt, del_node, &child_node));
    OG_RETURN_IFERR(get_color(stmt, del_node, &color));

    /* Remove next node out of tree. */
    OG_RETURN_IFERR(get_parent_rowid(stmt, del_node, &parent));
    OG_RETURN_IFERR(set_parent_rowid(stmt, child_node, parent));

    if (IS_SAME_MTRL_ROWID(nil_node, parent)) {
        rbt_tree->root = child_node;
    } else {
        OG_RETURN_IFERR(get_left_rowid(stmt, parent, &left));
        if (IS_SAME_MTRL_ROWID(left, del_node)) {
            OG_RETURN_IFERR(set_left_rowid(stmt, parent, child_node));
        } else {
            OG_RETURN_IFERR(set_right_rowid(stmt, parent, child_node));
        }
    }

    /* Insert next node into tree and remove del_node out of tree. */
    OG_RETURN_IFERR(rbt_delete_node_insert_next(stmt, rbt_tree, del_node, temp));

    if (RBT_BLACK == color) {
        OG_RETURN_IFERR(rbt_delete_node_fixup(stmt, rbt_tree, child_node));
    }
    return OG_SUCCESS;
}

status_t rbt_first_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t *result)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t node;
    mtrl_rowid_t left;

    if (rbt_tree == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    node = rbt_tree->root;
    nil_node = rbt_tree->nil_node;

    if (IS_SAME_MTRL_ROWID(nil_node, node)) {
        *result = g_invalid_entry;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
    while (IS_VALID_MTRL_ROWID(node) && !IS_SAME_MTRL_ROWID(nil_node, left)) {
        node = left;
        OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
    }
    *result = node;
    return OG_SUCCESS;
}

status_t rbt_last_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t *result)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t node;
    mtrl_rowid_t right;

    if (rbt_tree == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    node = rbt_tree->root;
    nil_node = rbt_tree->nil_node;

    if (IS_INVALID_MTRL_ROWID(node) || IS_SAME_MTRL_ROWID(nil_node, node)) {
        *result = g_invalid_entry;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
    while (IS_VALID_MTRL_ROWID(node) && !IS_SAME_MTRL_ROWID(nil_node, right)) {
        node = right;
        OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
    }
    *result = node;
    return OG_SUCCESS;
}

status_t rbt_next_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_node, mtrl_rowid_t *result)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t node_y;
    mtrl_rowid_t parent;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t node = tmp_node;
    if (rbt_tree == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    if (IS_INVALID_MTRL_ROWID(node)) {
        *result = g_invalid_entry;
        return OG_SUCCESS;
    }
    nil_node = rbt_tree->nil_node;
    /* NIL is forbidden. */
    CM_ASSERT(!IS_SAME_MTRL_ROWID(nil_node, node));

    OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
    if (!IS_SAME_MTRL_ROWID(nil_node, right)) {
        node = right;

        OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
        while (!IS_SAME_MTRL_ROWID(nil_node, left)) {
            node = left;
            OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
        }
        *result = node;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(get_parent_rowid(stmt, node, &node_y));

    OG_RETURN_IFERR(get_right_rowid(stmt, node_y, &right));
    while (!IS_SAME_MTRL_ROWID(nil_node, node_y) && IS_SAME_MTRL_ROWID(node, right)) {
        node = node_y;
        OG_RETURN_IFERR(get_parent_rowid(stmt, node_y, &parent));
        node_y = parent;
        OG_RETURN_IFERR(get_right_rowid(stmt, node_y, &right));
    }

    *result = (IS_SAME_MTRL_ROWID(nil_node, node_y) ? g_invalid_entry : node_y);
    return OG_SUCCESS;
}

status_t rbt_prior_node(sql_stmt_t *stmt, rbt_tree_t *rbt_tree, mtrl_rowid_t tmp_node, mtrl_rowid_t *result)
{
    mtrl_rowid_t nil_node;
    mtrl_rowid_t node_y;
    mtrl_rowid_t parent;
    mtrl_rowid_t left;
    mtrl_rowid_t right;
    mtrl_rowid_t node = tmp_node;

    if (rbt_tree == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "wrong red black tree parameter");
        return OG_ERROR;
    }

    if (IS_INVALID_MTRL_ROWID(node)) {
        *result = g_invalid_entry;
        return OG_SUCCESS;
    }
    nil_node = rbt_tree->nil_node;
    /* NIL is forbidden. */
    CM_ASSERT(!IS_SAME_MTRL_ROWID(nil_node, node));

    OG_RETURN_IFERR(get_left_rowid(stmt, node, &left));
    if (!IS_SAME_MTRL_ROWID(nil_node, left)) {
        node = left;

        OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
        while (!IS_SAME_MTRL_ROWID(nil_node, right)) {
            node = right;
            OG_RETURN_IFERR(get_right_rowid(stmt, node, &right));
        }
        *result = node;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(get_parent_rowid(stmt, node, &node_y));

    OG_RETURN_IFERR(get_left_rowid(stmt, node_y, &left));
    while (!IS_SAME_MTRL_ROWID(nil_node, node_y) && IS_SAME_MTRL_ROWID(node, left)) {
        node = node_y;
        OG_RETURN_IFERR(get_parent_rowid(stmt, node_y, &parent));
        node_y = parent;
        OG_RETURN_IFERR(get_left_rowid(stmt, node_y, &left));
    }

    *result = (IS_SAME_MTRL_ROWID(nil_node, node_y) ? g_invalid_entry : node_y);
    return OG_SUCCESS;
}
