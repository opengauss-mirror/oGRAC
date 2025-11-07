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
 * pl_hash_tb.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/type/pl_hash_tb.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_hash_tb.h"
#include "ogsql_verifier.h"
#include "pl_base.h"
#include "pl_scalar.h"
#include "pl_udt.h"
#include "pl_compiler.h"

static status_t udt_hash_table_count(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_count(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_delete(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_delete(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_exists(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_exists(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_verify_hash_table_extend(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_first(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_first_last(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_hash_table_limit(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_limit(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_next(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_prior_next(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_prior(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output);
static status_t udt_verify_hash_table_trim(sql_verifier_t *verif, expr_node_t *method);
static status_t udt_hash_table_constructor(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output);
static status_t udt_verify_hash_table(sql_verifier_t *verif, expr_node_t *node, plv_collection_t *collection,
    expr_tree_t *args);
static status_t udt_hash_table_read_element(sql_stmt_t *stmt, hstb_node_t *node, plv_collection_t *coll_meta,
    variant_t *output);
static status_t udt_hash_table_delete_element(sql_stmt_t *stmt, hstb_node_t *node, plv_collection_t *coll_meta,
    variant_t *var);

static status_t udt_hash_table_key_cmp(sql_stmt_t *stmt, mtrl_rowid_t node, variant_t *index, int32 *cmp_result);
static status_t udt_hash_table_node_cmp(sql_stmt_t *stmt, mtrl_rowid_t rowid_left, mtrl_rowid_t rowid_right,
    int32 *cmp_result);

static const plv_collection_method_t g_hash_table_methods[METHOD_END] = {
    { udt_hash_table_count,  udt_verify_hash_table_count, AS_FUNC, { 0 } },
    { udt_hash_table_delete, udt_verify_hash_table_delete, AS_PROC, { 0 } },
    { udt_hash_table_exists, udt_verify_hash_table_exists, AS_FUNC, { 0 } },
    { NULL, udt_verify_hash_table_extend, AS_PROC, { 0 } },
    { udt_hash_table_first,  udt_verify_hash_table_first_last, AS_FUNC, { 0 } },
    { udt_hash_table_last,   udt_verify_hash_table_first_last, AS_FUNC, { 0 } },
    { udt_hash_table_limit,  udt_verify_hash_table_limit, AS_FUNC, { 0 } },
    { udt_hash_table_next,   udt_verify_hash_table_prior_next, AS_FUNC, { 0 } },
    { udt_hash_table_prior,  udt_verify_hash_table_prior_next, AS_FUNC, { 0 } },
    { NULL,   udt_verify_hash_table_trim, AS_PROC, { 0 } }
};

static const plv_coll_construct_t g_hash_table_constructor = { udt_hash_table_constructor, udt_verify_hash_table };

static status_t udt_hash_table_intr_trim(sql_stmt_t *stmt, variant_t *var, void *arg);
static status_t udt_hash_table_intr_extend_num(sql_stmt_t *stmt, variant_t *var, void *arg);

static const intr_method_t g_hash_table_intr_method[METHOD_INTR_END] = {
    udt_hash_table_intr_trim,
    udt_hash_table_intr_extend_num
};

static status_t udt_verify_hash_table_count(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != OG_SUCCESS) {
        return OG_ERROR;
    }

    method->datatype = OG_TYPE_UINT32;
    method->size = OG_INTEGER_SIZE;
    return OG_SUCCESS;
}

static status_t udt_hash_table_init_rbt(sql_stmt_t *stmt, rbt_tree_t *rbt_tree)
{
    rbt_node_t *nil = NULL;
    status_t status;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, sizeof(rbt_node_t), (void **)&nil));
    nil->parent = g_invalid_entry;
    nil->left = g_invalid_entry;
    nil->right = g_invalid_entry;
    nil->color = RBT_BLACK;
    status = vmctx_insert(GET_VM_CTX(stmt), (const char *)nil, sizeof(rbt_node_t), &rbt_tree->nil_node);

    rbt_tree->root = rbt_tree->nil_node;
    rbt_tree->node_count = 0;
    rbt_tree->key_cmp = udt_hash_table_key_cmp;
    rbt_tree->node_cmp = udt_hash_table_node_cmp;
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t udt_alloc_hash_table(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t *result)
{
    pl_hash_table_t *hash_tb = NULL;
    status_t status;

    OG_RETURN_IFERR(sql_push(stmt, sizeof(pl_hash_table_t), (void **)&hash_tb));
    if (udt_hash_table_init_rbt(stmt, &hash_tb->rbt) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    hash_tb->datatype = GET_COLLECTION_ELEMENT_TYPE(coll_meta);
    status = vmctx_insert(GET_VM_CTX(stmt), (const char *)hash_tb, sizeof(pl_hash_table_t), result);
    OGSQL_POP(stmt);
    return status;
}

status_t udt_hash_table_init_var(sql_stmt_t *stmt, variant_t *value)
{
    plv_collection_t *coll_meta = (plv_collection_t *)value->v_collection.coll_meta;
    // hash table is empty before assigning, but not null.
    value->is_null = OG_FALSE;
    return udt_alloc_hash_table(stmt, coll_meta, &value->v_collection.value);
}

static status_t udt_hash_table_find_key(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t src_rowid,
    variant_t *output)
{
    hstb_node_t *node = NULL;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    output->type = coll_meta->index_typmod.datatype;
    if (IS_VALID_MTRL_ROWID(src_rowid)) {
        output->is_null = OG_FALSE;

        OPEN_VM_PTR(&src_rowid, vm_ctx);
        node = (hstb_node_t *)d_ptr;
        if (node->key.type == OG_TYPE_INTEGER) {
            VALUE(int32, output) = node->key.int_idx;
        } else {
            if (udt_read_scalar_value(stmt, &node->key.txt_idx, output) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(&src_rowid, vm_ctx);
                return OG_ERROR;
            }
        }
        CLOSE_VM_PTR(&src_rowid, vm_ctx);
    }
    return OG_SUCCESS;
}

static status_t udt_hash_table_init_node(hstb_node_t *node, plv_collection_t *coll_meta)
{
    RBT_INIT_NODE(&node->rbt_node);

    node->key.type = coll_meta->index_typmod.datatype;
    if (node->key.type == OG_TYPE_INTEGER) {
        node->key.int_idx = 0;
    } else {
        node->key.txt_idx = g_invalid_entry;
    }

    node->value = g_invalid_entry;
    return OG_SUCCESS;
}

static inline status_t udt_hash_table_make_key(sql_stmt_t *stmt, plv_collection_t *coll_meta, hstb_node_t *node,
    variant_t *index)
{
    if (node->key.type == OG_TYPE_INTEGER) {
        node->key.int_idx = VALUE(int32, index);
    } else {
        OG_RETURN_IFERR(udt_make_scalar_elemt(stmt, coll_meta->index_typmod, index, &node->key.txt_idx, NULL));
    }
    return OG_SUCCESS;
}

static status_t udt_make_key_var(sql_stmt_t *stmt, variant_t *var, mtrl_rowid_t *node)
{
    hstb_node_t *hash_node = NULL;
    OG_RETURN_IFERR(vmctx_open_row_id(GET_VM_CTX(stmt), node, (char **)&hash_node));
    var->is_null = OG_FALSE;
    if (hash_node->key.type == OG_TYPE_INTEGER) {
        var->type = OG_TYPE_INTEGER;
        VALUE(int32, var) = hash_node->key.int_idx;
    } else {
        var->type = OG_TYPE_VARCHAR;
        if (udt_read_scalar_value(stmt, &hash_node->key.txt_idx, var) != OG_SUCCESS) {
            vmctx_close_row_id(GET_VM_CTX(stmt), node);
            return OG_ERROR;
        }
    }
    vmctx_close_row_id(GET_VM_CTX(stmt), node);
    return OG_SUCCESS;
}

static status_t udt_hash_table_node_cmp(sql_stmt_t *stmt, mtrl_rowid_t rowid_left, mtrl_rowid_t rowid_right,
    int32 *cmp_result)
{
    variant_t left;
    variant_t right;
    OG_RETURN_IFERR(udt_make_key_var(stmt, &left, &rowid_left));
    OG_RETURN_IFERR(udt_make_key_var(stmt, &right, &rowid_right));
    return sql_compare_variant(stmt, &left, &right, cmp_result);
}

static status_t udt_hash_table_make_element(sql_stmt_t *stmt, hstb_node_t *node, plv_collection_t *coll_meta, variant_t *value)
{
    variant_t left;
    plv_decl_t *type_decl = plm_get_type_decl_by_coll(coll_meta);
    mtrl_rowid_t row_id = g_invalid_entry;
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            if (value->is_null) {
                return OG_SUCCESS;
            }
            if (value->type >= OG_TYPE_OPERAND_CEIL) {
                OG_THROW_ERROR(ERR_PL_WRONG_ARG_METHOD_INVOKE, T2S(&type_decl->name));
                return OG_ERROR;
            }
            OG_RETURN_IFERR(udt_make_scalar_elemt(stmt, coll_meta->type_mode, value, &node->value, NULL));
            break;

        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, coll_meta->elmt_type, row_id);
            OG_RETURN_IFERR(udt_coll_assign(stmt, &left, value));
            node->value = left.v_collection.value;
            break;

        case UDT_RECORD:
            OG_RETURN_IFERR(udt_record_alloc_mtrl_head(stmt, UDT_GET_TYPE_DEF_RECORD(coll_meta->elmt_type), &row_id));
            MAKE_REC_VAR(&left, coll_meta->elmt_type, row_id);
            OG_RETURN_IFERR(udt_record_assign(stmt, &left, value));
            node->value = left.v_record.value;
            break;
        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, coll_meta->elmt_type, row_id);
            OG_RETURN_IFERR(udt_object_assign(stmt, &left, value));
            node->value = left.v_object.value;
            break;
        default:
            OG_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t udt_hash_table_replace_element(sql_stmt_t *stmt, pl_hash_table_t *hash_table, plv_collection_t *coll_meta,
    mtrl_rowid_t result, variant_t *right)
{
    hstb_node_t *node = NULL;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    variant_t del_elmt;
    status_t status;

    OPEN_VM_PTR(&result, vm_ctx);
    node = (hstb_node_t *)d_ptr;
    if (IS_VALID_MTRL_ROWID(node->value)) {
        del_elmt.type = hash_table->datatype;
        if (coll_meta->attr_type != UDT_SCALAR) {
            if (udt_hash_table_read_element(stmt, node, coll_meta, &del_elmt) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(&result, vm_ctx);
                return OG_ERROR;
            }
        }
        if (udt_hash_table_delete_element(stmt, node, coll_meta, &del_elmt) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(&result, vm_ctx);
            return OG_ERROR;
        }
    }
    status = udt_hash_table_make_element(stmt, node, coll_meta, right);
    CLOSE_VM_PTR(&result, vm_ctx);
    return status;
}

static status_t udt_hash_table_insert_element(sql_stmt_t *stmt, plv_collection_t *coll_meta, rbt_tree_t *rbt_tree,
    hstb_node_t *node, variant_t *index, variant_t *right, mtrl_rowid_t *parent)
{
    mtrl_rowid_t row_id = g_invalid_entry;
    OG_RETURN_IFERR(udt_hash_table_init_node(node, coll_meta));
    OG_RETURN_IFERR(udt_hash_table_make_key(stmt, coll_meta, node, index));
    OG_RETURN_IFERR(udt_hash_table_make_element(stmt, node, coll_meta, right));
    OG_RETURN_IFERR(vmctx_insert(GET_VM_CTX(stmt), (const char *)node, sizeof(hstb_node_t), &row_id));
    return rbt_insert_node(stmt, rbt_tree, parent, row_id, OG_FALSE);
}

status_t udt_hash_table_address_write(sql_stmt_t *stmt, variant_t *var, variant_t *index, variant_t *right)
{
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var_coll->coll_meta;
    hstb_node_t *node = NULL;
    mtrl_rowid_t result = g_invalid_entry;
    mtrl_rowid_t parent = g_invalid_entry;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    pl_hash_table_t *hash_table = NULL;
    status_t status;

    OPEN_VM_PTR(&var_coll->value, vm_ctx);
    hash_table = (pl_hash_table_t *)d_ptr;
    if (rbt_search_node(stmt, &hash_table->rbt, index, &parent, &result) != OG_SUCCESS) {
        CLOSE_VM_PTR_EX(&var_coll->value, vm_ctx);
        return OG_ERROR;
    }

    if (IS_VALID_MTRL_ROWID(result)) {
        status = udt_hash_table_replace_element(stmt, hash_table, coll_meta, result, right);
        CLOSE_VM_PTR_EX(&var_coll->value, vm_ctx);
        return status;
    }

    OGSQL_SAVE_STACK(stmt);
    if (sql_push(stmt, sizeof(hstb_node_t), (void **)&node) != OG_SUCCESS) {
        CLOSE_VM_PTR_EX(&var_coll->value, vm_ctx);
        return OG_ERROR;
    }
    status = udt_hash_table_insert_element(stmt, coll_meta, &hash_table->rbt, node, index, right, &parent);
    OGSQL_RESTORE_STACK(stmt);
    CLOSE_VM_PTR(&var_coll->value, vm_ctx);
    return status;
}

static status_t udt_hash_table_key_cmp(sql_stmt_t *stmt, mtrl_rowid_t node, variant_t *index, int32 *cmp_result)
{
    variant_t key;
    OG_RETURN_IFERR(udt_make_key_var(stmt, &key, &node));
    return sql_compare_variant(stmt, &key, index, cmp_result);
}

static status_t udt_hash_table_read_element(sql_stmt_t *stmt, hstb_node_t *node, plv_collection_t *coll_meta,
    variant_t *output)
{
    output->is_null = OG_FALSE;
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            OG_RETURN_IFERR(udt_read_scalar_value(stmt, &node->value, output));
            break;
        case UDT_COLLECTION:
            output->type = OG_TYPE_COLLECTION;
            output->v_collection.type = ELMT_COLL_TYPE(coll_meta);
            output->v_collection.coll_meta = &coll_meta->elmt_type->typdef.collection;
            output->v_collection.value = node->value;
            output->v_collection.is_constructed = OG_FALSE;
            break;
        case UDT_RECORD:
            output->type = OG_TYPE_RECORD;
            output->v_record.count = coll_meta->elmt_type->typdef.record.count;
            output->v_record.record_meta = &coll_meta->elmt_type->typdef.record;
            output->v_record.value = node->value;
            output->v_record.is_constructed = OG_FALSE;
            break;
        case UDT_OBJECT:
            output->type = OG_TYPE_OBJECT;
            output->v_object.count = coll_meta->elmt_type->typdef.object.count;
            output->v_object.object_meta = &coll_meta->elmt_type->typdef.object;
            output->v_object.value = node->value;
            output->v_object.is_constructed = OG_FALSE;
            break;
        default:
            OG_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline status_t udt_hash_table_find_rowid(sql_stmt_t *stmt, var_collection_t *var_coll, variant_t *index,
    mtrl_rowid_t *result)
{
    pl_hash_table_t *hash_table = NULL;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    status_t status;

    OPEN_VM_PTR(&var_coll->value, vm_ctx);
    hash_table = (pl_hash_table_t *)d_ptr;
    status = rbt_get_rowid_by_key(stmt, &hash_table->rbt, index, result);
    CLOSE_VM_PTR(&var_coll->value, vm_ctx);
    return status;
}

static status_t udt_hash_table_address_read(sql_stmt_t *stmt, variant_t *var, variant_t *index, variant_t *output)
{
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var_coll->coll_meta;
    hstb_node_t *node = NULL;
    mtrl_rowid_t row_id = g_invalid_entry;
    pl_hash_table_t *hash_table = NULL;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    status_t status;

    OPEN_VM_PTR(&var_coll->value, vm_ctx);
    hash_table = (pl_hash_table_t *)d_ptr;
    output->type = hash_table->datatype;
    CLOSE_VM_PTR(&var_coll->value, vm_ctx);
    output->is_null = OG_TRUE;

    OG_RETURN_IFERR(udt_hash_table_find_rowid(stmt, &var->v_collection, index, &row_id));
    if (IS_INVALID_MTRL_ROWID(row_id)) {
        OG_THROW_ERROR(ERR_PL_NO_DATA_FOUND);
        return OG_ERROR;
    }

    OPEN_VM_PTR(&row_id, vm_ctx);
    node = (hstb_node_t *)d_ptr;
    if (IS_INVALID_MTRL_ROWID(node->value)) {
        output->is_null = OG_TRUE;
        CLOSE_VM_PTR_EX(&row_id, vm_ctx);
        return OG_SUCCESS;
    }

    status = udt_hash_table_read_element(stmt, node, coll_meta, output);
    CLOSE_VM_PTR(&row_id, vm_ctx);
    return status;
}

static status_t udt_hash_table_address(sql_stmt_t *stmt, variant_t *var, variant_t *index, addr_type_t type, variant_t *output,
    variant_t *right)
{
    status_t status;
    plv_collection_t *collection = (plv_collection_t *)var->v_collection.coll_meta;
    CM_ASSERT(!index->is_null);
    OGSQL_SAVE_STACK(stmt);
    if (sql_convert_variant(stmt, index, collection->index_typmod.datatype) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    sql_keep_stack_variant(stmt, index);
    if (collection->index_typmod.datatype == OG_TYPE_VARCHAR && index->v_text.len > collection->index_typmod.size) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "index's length exceed the size");
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    if (type == READ_ADDR) {
        status = udt_hash_table_address_read(stmt, var, index, output);
    } else {
        status = udt_hash_table_address_write(stmt, var, index, right);
    }
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t udt_hash_table_clone_key(sql_stmt_t *stmt, plv_collection_t *coll_meta, entry_key_t *right_key,
    entry_key_t *left_key)
{
    variant_t right;
    left_key->type = right_key->type;
    if (right_key->type == OG_TYPE_INTEGER) {
        left_key->int_idx = right_key->int_idx;
    } else {
        right.type = OG_TYPE_VARCHAR;
        OG_RETURN_IFERR(udt_read_scalar_value(stmt, &right_key->txt_idx, &right));
        OG_RETURN_IFERR(udt_make_scalar_elemt(stmt, coll_meta->index_typmod, &right, &left_key->txt_idx, NULL));
    }
    return OG_SUCCESS;
}

static status_t udt_hash_table_clone_node(sql_stmt_t *stmt, plv_collection_t *right_coll_meta,
                                   pl_hash_table_t *right_hash_table, mtrl_rowid_t right_id, hstb_node_t *left_node)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    hstb_node_t *right_node = NULL;
    variant_t value;

    OG_RETURN_IFERR(udt_hash_table_init_node(left_node, right_coll_meta));
    OPEN_VM_PTR(&right_id, vm_ctx);
    right_node = (hstb_node_t *)d_ptr;
    if (udt_hash_table_clone_key(stmt, right_coll_meta, &right_node->key, &left_node->key) != OG_SUCCESS) {
        CLOSE_VM_PTR_EX(&right_id, vm_ctx);
        return OG_ERROR;
    }

    if (IS_INVALID_MTRL_ROWID(right_node->value)) {
        CLOSE_VM_PTR_EX(&right_id, vm_ctx);
        return OG_SUCCESS;
    }

    value.type = right_hash_table->datatype;
    if (udt_hash_table_read_element(stmt, right_node, right_coll_meta, &value) != OG_SUCCESS) {
        CLOSE_VM_PTR_EX(&right_id, vm_ctx);
        return OG_ERROR;
    }
    CLOSE_VM_PTR(&right_id, vm_ctx);
    return udt_hash_table_make_element(stmt, left_node, right_coll_meta, &value);
}

static status_t udt_hash_table_clone_element(sql_stmt_t *stmt, plv_collection_t *right_coll_meta,
    pl_hash_table_t *right_hash_table, mtrl_rowid_t right_id, mtrl_rowid_t *result)
{
    hstb_node_t *left_node = NULL;
    mtrl_rowid_t left_id = g_invalid_entry;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    pl_hash_table_t *left_hash_tb = NULL;
    mtrl_rowid_t parent = g_invalid_entry;
    status_t status;

    OG_RETURN_IFERR(sql_push(stmt, sizeof(hstb_node_t), (void **)&left_node));
    if (udt_hash_table_clone_node(stmt, right_coll_meta, right_hash_table, right_id, left_node) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    if (vmctx_insert(GET_VM_CTX(stmt), (const char *)left_node, sizeof(hstb_node_t), &left_id) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    if (vmctx_open_row_id(vm_ctx, result, (char **)&left_hash_tb) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    status = rbt_insert_node(stmt, &left_hash_tb->rbt, &parent, left_id, OG_TRUE);
    vmctx_close_row_id(vm_ctx, result);
    OGSQL_POP(stmt);
    return status;
}

static status_t udt_clone_hash_table(sql_stmt_t *stmt, variant_t *right, mtrl_rowid_t *result)
{
    var_collection_t *right_coll = &right->v_collection;
    plv_collection_t *right_coll_meta = (plv_collection_t *)right_coll->coll_meta;
    pl_hash_table_t *right_hash_table = NULL;
    mtrl_rowid_t right_id = g_invalid_entry;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);

    if (IS_INVALID_MTRL_ROWID(*result)) {
        OG_RETURN_IFERR(udt_alloc_hash_table(stmt, right_coll_meta, result));
    }

    OPEN_VM_PTR(&right_coll->value, vm_ctx);
    right_hash_table = (pl_hash_table_t *)d_ptr;

    RBT_SCAN(stmt, &right_hash_table->rbt, &right_id)
    {
        if (udt_hash_table_clone_element(stmt, right_coll_meta, right_hash_table, right_id, result) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(&right_coll->value, vm_ctx);
            return OG_ERROR;
        }
    }
    CLOSE_VM_PTR(&right_coll->value, vm_ctx);
    return OG_SUCCESS;
}

static status_t udt_verify_hash_table(sql_verifier_t *verif, expr_node_t *node, plv_collection_t *collection,
    expr_tree_t *args)
{
    // DOES NOT SUPPORT HASHTB(XX,XX,XX), JUST RETURN SUCCESS
    return OG_SUCCESS;
}

static status_t udt_hash_table_constructor(sql_stmt_t *stmt, udt_constructor_t *v_construct, expr_tree_t *args,
    variant_t *output)
{
    plv_collection_t *coll_meta = (plv_collection_t *)v_construct->meta;
    output->type = OG_TYPE_COLLECTION;
    output->v_collection.type = UDT_HASH_TABLE;
    output->v_collection.coll_meta = coll_meta;
    output->v_collection.value = g_invalid_entry;
    output->v_collection.is_constructed = OG_FALSE;
    return udt_hash_table_init_var(stmt, output);
}

static status_t udt_hash_table_delete_args(sql_stmt_t *stmt, expr_tree_t *args, variant_t *start, variant_t *end,
    bool32 *is_null)
{
    bool32 pending = OG_FALSE;
    variant_t *element_vars = NULL;

    uint32 args_count = sql_expr_list_len(args);
    CM_ASSERT(args_count <= UDT_NTBL_MAX_ARGS);
    OGSQL_SAVE_STACK(stmt);

    OG_RETURN_IFERR(sql_push(stmt, args_count * sizeof(variant_t), (void **)&element_vars));
    if (sql_exec_expr_list(stmt, args, args_count, element_vars, &pending, NULL) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (element_vars[0].is_null) {
        *is_null = OG_TRUE;
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }
    *start = element_vars[0];

    if (args_count == UDT_NTBL_MAX_ARGS) {
        if (element_vars[1].is_null) {
            *is_null = OG_TRUE;
            OGSQL_RESTORE_STACK(stmt);
            return OG_SUCCESS;
        }
        *end = element_vars[1];
    } else {
        *end = *start;
    }

    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t udt_hash_table_delete_element(sql_stmt_t *stmt, hstb_node_t *node, plv_collection_t *coll_meta,
    variant_t *var)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));

    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), &node->value));
            node->value = g_invalid_entry;
            break;
        case UDT_COLLECTION:
            OG_RETURN_IFERR(udt_delete_collection(stmt, var));
            OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), &node->value));
            node->value = g_invalid_entry;
            break;
        case UDT_RECORD:
            OG_RETURN_IFERR(udt_record_delete(stmt, var, OG_TRUE));
            node->value = g_invalid_entry;
            break;
        case UDT_OBJECT:
            OG_RETURN_IFERR(udt_object_delete(stmt, var));
            node->value = g_invalid_entry;
            break;
        default:
            OG_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t udt_hash_table_free_node(sql_stmt_t *stmt, mtrl_rowid_t *dest, plv_collection_t *coll_meta,
    pl_hash_table_t *hash_table)
{
    hstb_node_t *node = NULL;
    if (IS_INVALID_MTRL_ROWID(*dest)) {
        return OG_SUCCESS;
    }
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    OPEN_VM_PTR(dest, vm_ctx);
    node = (hstb_node_t *)d_ptr;

    // firstly free key
    if (node->key.type != OG_TYPE_INTEGER) {
        if (vmctx_free(vm_ctx, &node->key.txt_idx) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(dest, vm_ctx);
            return OG_ERROR;
        }
        node->key.txt_idx = g_invalid_entry;
    }

    if (IS_VALID_MTRL_ROWID(node->value)) {
        variant_t del_elmt;
        del_elmt.type = hash_table->datatype;
        if (coll_meta->attr_type != UDT_SCALAR) {
            if (udt_hash_table_read_element(stmt, node, coll_meta, &del_elmt) != OG_SUCCESS) {
                CLOSE_VM_PTR_EX(dest, vm_ctx);
                return OG_ERROR;
            }
        }
        if (udt_hash_table_delete_element(stmt, node, coll_meta, &del_elmt) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(dest, vm_ctx);
            return OG_ERROR;
        }
    }

    CLOSE_VM_PTR(dest, vm_ctx);
    OG_RETURN_IFERR(rbt_delete_node(stmt, &hash_table->rbt, *dest));
    OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), dest));
    *dest = g_invalid_entry;
    return OG_SUCCESS;
}

static status_t udt_hash_table_delete_elements(sql_stmt_t *stmt, var_collection_t *var_coll, pl_hash_table_t *hash_table,
    variant_t *start, variant_t *end)
{
    mtrl_rowid_t curr_rowid = g_invalid_entry;
    mtrl_rowid_t nex_rowid = g_invalid_entry;
    int32 cmp_start = 0;
    int32 cmp_end = 0;

    RBT_INORDER_SCAN(stmt, &hash_table->rbt, &curr_rowid, &nex_rowid)
    {
        // delete current element
        OG_RETURN_IFERR(udt_hash_table_key_cmp(stmt, curr_rowid, start, &cmp_start));
        OG_RETURN_IFERR(udt_hash_table_key_cmp(stmt, curr_rowid, end, &cmp_end));
        if (cmp_start >= 0 && cmp_end <= 0) {
            OG_RETURN_IFERR(
                udt_hash_table_free_node(stmt, &curr_rowid, (plv_collection_t *)var_coll->coll_meta, hash_table));
        }
        if (cmp_end == 0) {
            break;
        }
    }
    return OG_SUCCESS;
}

static status_t udt_hash_table_delete_all(sql_stmt_t *stmt, plv_collection_t *coll_meta, mtrl_rowid_t *dest_value)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_rowid_t curr_rowid = g_invalid_entry;
    mtrl_rowid_t nex_rowid = g_invalid_entry;
    pl_hash_table_t *hash_table = NULL;
    OPEN_VM_PTR(dest_value, vm_ctx);
    hash_table = (pl_hash_table_t *)d_ptr;

    RBT_INORDER_SCAN(stmt, &hash_table->rbt, &curr_rowid, &nex_rowid)
    {
        if (udt_hash_table_free_node(stmt, &curr_rowid, coll_meta, hash_table) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(dest_value, vm_ctx);
            return OG_ERROR;
        }
    }
    CLOSE_VM_PTR(dest_value, vm_ctx);
    return OG_SUCCESS;
}

static status_t udt_hash_table_delete_core(sql_stmt_t *stmt, variant_t *var, variant_t *start, variant_t *end)
{
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var->v_collection.coll_meta;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    pl_hash_table_t *hash_table = NULL;
    status_t status;

    OG_RETURN_IFERR(sql_convert_variant(stmt, start, coll_meta->index_typmod.datatype));
    sql_keep_stack_variant(stmt, start);
    OG_RETURN_IFERR(sql_convert_variant(stmt, end, coll_meta->index_typmod.datatype));
    sql_keep_stack_variant(stmt, end);

    OPEN_VM_PTR(&var_coll->value, vm_ctx);
    hash_table = (pl_hash_table_t *)d_ptr;
    status = udt_hash_table_delete_elements(stmt, var_coll, hash_table, start, end);
    CLOSE_VM_PTR(&var_coll->value, vm_ctx);
    return status;
}

static status_t udt_hash_table_delete(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    variant_t start;
    variant_t end;
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var->v_collection.coll_meta;
    bool32 is_null = OG_FALSE;
    int32 cmp_result = 0;
    CM_ASSERT(IS_VALID_MTRL_ROWID(var_coll->value));
    status_t status = OG_SUCCESS;

    OGSQL_SAVE_STACK(stmt);
    if (args == NULL) {
        status = udt_hash_table_delete_all(stmt, coll_meta, &var_coll->value);
        OGSQL_RESTORE_STACK(stmt);
        return status;
    }

    if (udt_hash_table_delete_args(stmt, args, &start, &end, &is_null) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (is_null) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }

    if (var_compare(SESSION_NLS(stmt), &start, &end, &cmp_result) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (cmp_result > 0) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }

    status = udt_hash_table_delete_core(stmt, var, &start, &end);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t udt_hash_table_free(sql_stmt_t *stmt, variant_t *var)
{
    plv_collection_t *coll_meta = (plv_collection_t *)var->v_collection.coll_meta;
    mtrl_rowid_t *dest_value = &var->v_collection.value;
    if (IS_INVALID_MTRL_ROWID(*dest_value)) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(udt_hash_table_delete_all(stmt, coll_meta, dest_value));
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    OPEN_VM_PTR(dest_value, vm_ctx);
    pl_hash_table_t *hash_table = (pl_hash_table_t *)d_ptr;
    if (IS_VALID_MTRL_ROWID(hash_table->rbt.nil_node)) {
        if (vmctx_free(vm_ctx, &hash_table->rbt.nil_node) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(dest_value, vm_ctx);
            return OG_ERROR;
        }
        hash_table->rbt.nil_node = g_invalid_entry;
    }
    CLOSE_VM_PTR(dest_value, vm_ctx);
    return OG_SUCCESS;
}

static status_t udt_hash_table_record_write(sql_stmt_t *stmt, plv_collection_t *coll_meta, variant_t *temp_obj,
    variant_t *index)
{
    variant_t value;
    value.is_null = OG_TRUE;
    CM_ASSERT(!temp_obj->is_null);
    status_t status = OG_SUCCESS;

    OGSQL_SAVE_STACK(stmt);
    switch (coll_meta->attr_type) {
        case UDT_SCALAR:
            break;
        case UDT_COLLECTION:
            if (ELMT_IS_HASH_TABLE(coll_meta)) {
                MAKE_COLL_VAR(&value, coll_meta->elmt_type, g_invalid_entry);
                status = udt_hash_table_init_var(stmt, &value);
                if (status != OG_SUCCESS) {
                    OGSQL_RESTORE_STACK(stmt);
                    return status;
                }
                value.v_collection.is_constructed = OG_TRUE;
                status = udt_hash_table_address_write(stmt, temp_obj, index, &value);
            } else {
                OG_THROW_ERROR(ERR_COLLECTION_IS_NULL);
                status = OG_ERROR;
            }
            break;
        case UDT_RECORD:
            status = udt_hash_table_address_write(stmt, temp_obj, index, &value);
            break;
        case UDT_OBJECT:
            OG_THROW_ERROR(ERR_ACCESS_INTO_NULL);
            status = OG_ERROR;
            break;
        default:
            OG_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "element type", coll_meta->attr_type);
            status = OG_ERROR;
            break;
    }
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t udt_hash_table_get_index(sql_stmt_t *stmt, plv_collection_t *coll_meta, expr_tree_t *expr,
    variant_t *index)
{
    OG_RETURN_IFERR(sql_exec_expr(stmt, expr, index));
    OG_RETURN_IFERR(sql_convert_variant(stmt, index, coll_meta->index_typmod.datatype));
    sql_keep_stack_variant(stmt, index);
    return OG_SUCCESS;
}

status_t udt_hash_table_record_init(sql_stmt_t *stmt, var_collection_t *var_coll, var_address_pair_t *pair,
    variant_t *index, variant_t *temp_obj)
{
    mtrl_rowid_t result = g_invalid_entry;
    plv_collection_t *coll_meta = (plv_collection_t *)var_coll->coll_meta;
    OGSQL_SAVE_STACK(stmt);
    if (udt_hash_table_get_index(stmt, coll_meta, pair->coll_elemt->id, index) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (index->is_null) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "subscript");
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (coll_meta->index_typmod.datatype == OG_TYPE_VARCHAR && index->v_text.len > coll_meta->index_typmod.size) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "index's length exceed the size");
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    if (udt_hash_table_find_rowid(stmt, var_coll, index, &result) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    if (IS_INVALID_MTRL_ROWID(result)) {
        if (udt_hash_table_record_write(stmt, coll_meta, temp_obj, index) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
    }
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t udt_verify_hash_table_delete(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, UDT_NTBL_MIN_ARGS, UDT_NTBL_MAX_ARGS) != OG_SUCCESS) {
        return OG_ERROR;
    }
    method->datatype = OG_TYPE_VARCHAR;
    method->size = 0;
    return OG_SUCCESS;
}

static status_t udt_verify_hash_table_trim(sql_verifier_t *verif, expr_node_t *method)
{
    OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "associative arrays do not support trim method");
    return OG_ERROR;
}

static status_t udt_verify_hash_table_extend(sql_verifier_t *verif, expr_node_t *method)
{
    OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "associative arrays do not support extend method");
    return OG_ERROR;
}

static status_t udt_hstb_get_index_datatype(sql_verifier_t *verif, expr_node_t *method)
{
    galist_t *pairs = method->value.v_method.pairs;
    if (pairs->count == 0) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "pairs count is zero");
        return OG_ERROR;
    }

    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(pairs, pairs->count - 1);
    plv_decl_t *decl = plc_get_last_addr_decl(verif->stmt, pair);
    plv_collection_t *coll_meta = NULL;

    if (decl == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "decl is null");
        return OG_ERROR;
    }

    if (decl->type == PLV_TYPE) {
        coll_meta = &decl->typdef.collection;
    } else if (decl->type == PLV_COLLECTION) {
        coll_meta = decl->collection;
    } else {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "error element type");
        return OG_ERROR;
    }

    if (coll_meta->index_typmod.datatype == OG_TYPE_INTEGER) {
        method->datatype = OG_TYPE_INTEGER;
        method->size = OG_INTEGER_SIZE;
    } else if (coll_meta->index_typmod.datatype == OG_TYPE_VARCHAR) {
        method->datatype = OG_TYPE_VARCHAR;
        method->size = OG_VARCHAR_SIZE;
    } else {
        OG_THROW_ERROR(ERR_PL_HSTB_INDEX_TYPE);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t udt_verify_hash_table_first_last(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return udt_hstb_get_index_datatype(verif, method);
}

static status_t udt_verify_hash_table_prior_next(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != OG_SUCCESS) {
        return OG_ERROR;
    }
    return udt_hstb_get_index_datatype(verif, method);
}

// bulk collect will enter here
static status_t udt_hash_table_intr_trim(sql_stmt_t *stmt, variant_t *var, void *arg)
{
    plv_collection_t *coll_meta = var->v_collection.coll_meta;
    if (coll_meta->index_typmod.datatype != OG_TYPE_INTEGER) {
        OG_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "associative array's index of type must be integer in bulk sql");
        return OG_ERROR;
    }
    return udt_hash_table_delete(stmt, var, NULL, NULL); // delete all
}

static status_t udt_verify_hash_table_exists(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 1, 1) != OG_SUCCESS) {
        return OG_ERROR;
    }

    method->datatype = OG_TYPE_BOOLEAN;
    method->size = OG_BOOLEAN_SIZE;
    return OG_SUCCESS;
}

static status_t udt_hash_table_exists(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var_coll->coll_meta;
    variant_t index;
    mtrl_rowid_t result = g_invalid_entry;

    output->type = OG_TYPE_BOOLEAN;
    output->is_null = OG_FALSE;
    output->v_bool = OG_FALSE;
    OGSQL_SAVE_STACK(stmt);
    if (udt_hash_table_get_index(stmt, coll_meta, args, &index) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (index.is_null) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }
    if (udt_hash_table_find_rowid(stmt, &var->v_collection, &index, &result) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (IS_VALID_MTRL_ROWID(result)) {
        output->v_bool = OG_TRUE;
    }
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t udt_hash_table_first_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output, bool32 first)
{
    var_collection_t *var_coll = &var->v_collection;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_rowid_t result = g_invalid_entry;
    pl_hash_table_t *hash_table = NULL;
    status_t status;
    output->is_null = OG_TRUE;

    OPEN_VM_PTR(&var_coll->value, vm_ctx);
    hash_table = (pl_hash_table_t *)d_ptr;
    if (first == OG_TRUE) {
        if (rbt_first_node(stmt, &hash_table->rbt, &result) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(&var_coll->value, vm_ctx);
            return OG_ERROR;
        }
    } else {
        if (rbt_last_node(stmt, &hash_table->rbt, &result) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(&var_coll->value, vm_ctx);
            return OG_ERROR;
        }
    }

    status = udt_hash_table_find_key(stmt, (plv_collection_t *)var_coll->coll_meta, result, output);
    CLOSE_VM_PTR(&var_coll->value, vm_ctx);
    return status;
}

static status_t udt_hash_table_first(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    return udt_hash_table_first_last(stmt, var, args, output, OG_TRUE);
}
static status_t udt_hash_table_last(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    return udt_hash_table_first_last(stmt, var, args, output, OG_FALSE);
}

static status_t udt_hash_table_count(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    pl_hash_table_t *hash_table = NULL;

    output->type = OG_TYPE_UINT32;
    output->is_null = OG_FALSE;
    if (IS_VALID_MTRL_ROWID(var->v_collection.value)) {
        OPEN_VM_PTR(&var->v_collection.value, vm_ctx);
        hash_table = (pl_hash_table_t *)d_ptr;
        output->v_uint32 = hash_table->rbt.node_count;
        CLOSE_VM_PTR(&var->v_collection.value, vm_ctx);
    } else {
        output->v_uint32 = 0;
    }
    return OG_SUCCESS;
}

static status_t udt_verify_hash_table_limit(sql_verifier_t *verif, expr_node_t *method)
{
    if (udt_verify_method_node(verif, method, 0, 0) != OG_SUCCESS) {
        return OG_ERROR;
    }

    method->datatype = OG_TYPE_UINT32;
    method->size = OG_INTEGER_SIZE;
    return OG_SUCCESS;
}

static status_t udt_hash_table_limit(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    output->type = OG_TYPE_INTEGER;
    output->is_null = OG_TRUE;
    return OG_SUCCESS;
}

static status_t udt_hash_table_prior(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var_coll->coll_meta;
    variant_t index;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_rowid_t curr_rowid = g_invalid_entry;
    mtrl_rowid_t nex_rowid = g_invalid_entry;
    mtrl_rowid_t prior = g_invalid_entry;
    int32 cmp_result = 0;
    pl_hash_table_t *hash_table = NULL;
    status_t status;

    output->is_null = OG_TRUE;
    output->type = coll_meta->index_typmod.datatype;
    OGSQL_SAVE_STACK(stmt);
    if (udt_hash_table_get_index(stmt, coll_meta, args, &index) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (index.is_null) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }
    if (vmctx_open_row_id(vm_ctx, &var_coll->value, (char **)&hash_table) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    RBT_INORDER_SCAN(stmt, &hash_table->rbt, &curr_rowid, &nex_rowid)
    {
        if (udt_hash_table_key_cmp(stmt, curr_rowid, &index, &cmp_result) != OG_SUCCESS) {
            vmctx_close_row_id(vm_ctx, &var_coll->value);
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
        if (cmp_result >= 0) {
            break;
        } else {
            prior = curr_rowid;
        }
    }

    status = udt_hash_table_find_key(stmt, coll_meta, prior, output);
    vmctx_close_row_id(vm_ctx, &var_coll->value);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t udt_hash_table_next(sql_stmt_t *stmt, variant_t *var, expr_tree_t *args, variant_t *output)
{
    var_collection_t *var_coll = &var->v_collection;
    plv_collection_t *coll_meta = (plv_collection_t *)var_coll->coll_meta;
    variant_t index;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    mtrl_rowid_t curr_rowid = g_invalid_entry;
    mtrl_rowid_t prior_rowid = g_invalid_entry;
    mtrl_rowid_t next = g_invalid_entry;
    int32 cmp_result = 0;
    pl_hash_table_t *hash_table = NULL;
    status_t status;

    output->is_null = OG_TRUE;
    output->type = coll_meta->index_typmod.datatype;
    OGSQL_SAVE_STACK(stmt);
    if (udt_hash_table_get_index(stmt, coll_meta, args, &index) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    if (index.is_null) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_SUCCESS;
    }
    if (vmctx_open_row_id(vm_ctx, &var_coll->value, (char **)&hash_table) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    RBT_BACK_SCAN(stmt, &hash_table->rbt, &curr_rowid, &prior_rowid)
    {
        if (udt_hash_table_key_cmp(stmt, curr_rowid, &index, &cmp_result) != OG_SUCCESS) {
            vmctx_close_row_id(vm_ctx, &var_coll->value);
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
        if (cmp_result <= 0) {
            break;
        } else {
            next = curr_rowid;
        }
    }

    status = udt_hash_table_find_key(stmt, coll_meta, next, output);
    vmctx_close_row_id(vm_ctx, &var_coll->value);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

static status_t udt_hash_table_intr_extend_num(sql_stmt_t *stmt, variant_t *var, void *arg)
{
    return OG_SUCCESS;
}

void udt_reg_hash_table_method(void)
{
    handle_mutiple_ptrs_t mutiple_ptrs;
    mutiple_ptrs.ptr1 = (void *)g_hash_table_methods;
    mutiple_ptrs.ptr2 = (void *)(&g_hash_table_constructor);
    mutiple_ptrs.ptr3 = (void *)udt_hash_table_free;
    mutiple_ptrs.ptr4 = (void *)g_hash_table_intr_method;
    mutiple_ptrs.ptr5 = (void *)udt_clone_hash_table;
    mutiple_ptrs.ptr6 = (void *)udt_hash_table_address;
    udt_reg_coll_method(UDT_HASH_TABLE, &mutiple_ptrs);
}
