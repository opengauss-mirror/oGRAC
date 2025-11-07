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
 * pl_udt.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/type/pl_udt.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_udt.h"
#include "pl_executor.h"
#include "pl_hash_tb.h"
#include "pl_compiler.h"
#include "srv_instance.h"
#include "ogsql_expr_verifier.h"
#include "pl_varray.h"
#include "pl_nested_tb.h"
#include "pl_memory.h"
#include "base_compiler.h"
#include "trigger_decl_cl.h"
#include "ast_cl.h"
#include "param_decl_cl.h"
#include "decl_cl.h"
#include "typedef_cl.h"

static inline status_t udt_address_get_index(sql_stmt_t *stmt, var_address_pair_t *addr_pair, variant_t *index_var)
{
    expr_tree_t *index = addr_pair->coll_elemt->id;
    OG_RETURN_IFERR(sql_exec_expr(stmt, index, index_var));

    if (index_var->is_null) {
        OG_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "subscript");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t udt_get_pl_array_var(sql_stmt_t *stmt, int32 start, int32 end, typmode_t *typmod, variant_t *value,
    variant_t *result)
{
    array_assist_t aa;

    if (value->is_null) {
        result->is_null = OG_TRUE;
        result->type = typmod->datatype;
        return OG_SUCCESS;
    }

    if (value->v_array.value.type == OG_LOB_FROM_KERNEL) {
        vm_lob_t vlob;
        OG_RETURN_IFERR(sql_get_array_from_knl_lob(stmt, (knl_handle_t)(value->v_array.value.knl_lob.bytes), &vlob));
        value->v_array.value.vm_lob = vlob;
        value->v_array.value.type = OG_LOB_FROM_VMPOOL;
    }

    ARRAY_INIT_ASSIST_INFO(&aa, stmt);
    vm_lob_t *src_lob = &value->v_array.value.vm_lob;
    if (start > 0 && end == OG_INVALID_ID32) {
        /* extract single element */
        return sql_get_element_to_value(stmt, &aa, src_lob, start, end, typmod->datatype, result);
    }

    /* extract sub-array */
    return sql_get_subarray_to_value(&aa, src_lob, start, end, typmod->datatype, result);
}

static status_t udt_stack_address(sql_stmt_t *stmt, ple_var_t *var, variant_t *temp_result, variant_t *right)
{
    if (right == NULL) {
        if (var->decl->type == PLV_PARAM) {
            return sql_get_param_value(stmt, var->decl->param.param_id, temp_result);
        }
    } else {
        OG_RETURN_IFERR(ple_move_value(stmt, right, var));
    }
    var_copy(&var->value, temp_result);
    return OG_SUCCESS;
}

static status_t udt_array_address(sql_stmt_t *stmt, var_address_pair_t *addr_pair, expr_node_t *node, variant_t *obj,
    variant_t *temp_result, variant_t *right)
{
    if (right == NULL) {
        return udt_get_pl_array_var(stmt, addr_pair->arr_addr->ss_start, addr_pair->arr_addr->ss_end, &node->typmod,
            obj,
            temp_result);
    } else {
        var_address_pair_t *tmp_pair = (var_address_pair_t *)cm_galist_get(node->value.v_address.pairs, 0);
        ple_var_t *left = ple_get_plvar((pl_executor_t *)stmt->pl_exec, tmp_pair->stack->decl->vid);
        return ple_move_value(stmt, right, left);
    }
}

static status_t udt_address_core(sql_stmt_t *stmt, var_address_pair_t *addr_pair, expr_node_t *node, variant_t *obj,
    variant_t *right)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    ple_var_t *var = NULL;
    variant_t index_var;
    variant_t temp_result;

    switch (addr_pair->type) {
        case UDT_STACK_ADDR:
            var = ple_get_plvar(exec, addr_pair->stack->decl->vid);
            OG_RETVALUE_IFTRUE(var == NULL, OG_ERROR);
            OG_RETURN_IFERR(udt_stack_address(stmt, var, &temp_result, right));
            *obj = temp_result;
            return OG_SUCCESS;

        case UDT_COLL_ELEMT_ADDR:
            OG_RETURN_IFERR(udt_address_get_index(stmt, addr_pair, &index_var));
            sql_keep_stack_variant(stmt, &index_var);
            OG_RETURN_IFERR(udt_coll_elemt_address(stmt, obj, &index_var, &temp_result, right));
            break;

        case UDT_REC_FIELD_ADDR:
            OG_RETSUC_IFTRUE(obj->is_null);
            OG_RETURN_IFERR(udt_record_field_address(stmt, obj, addr_pair->rec_field->id, &temp_result, right));
            break;
        case UDT_OBJ_FIELD_ADDR:
            OG_RETSUC_IFTRUE(obj->is_null);
            OG_RETURN_IFERR(udt_object_field_address(stmt, obj, addr_pair->obj_field->id, &temp_result, right));
            break;
        case UDT_ARRAY_ADDR:
            OG_RETURN_IFERR(udt_array_address(stmt, addr_pair, node, obj, &temp_result, right));
            break;
        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect udt type");
            return OG_ERROR;
    }
    if (right == NULL) {
        *obj = temp_result;
    }
    return OG_SUCCESS;
}

status_t udt_address(sql_stmt_t *stmt, var_address_pair_t *addr_pair, expr_node_t *node, variant_t *obj,
                     variant_t *right)
{
    status_t status;
    OGSQL_SAVE_STACK(stmt);
    status = udt_address_core(stmt, addr_pair, node, obj, right);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

status_t check_invalid_var_ref(var_address_pair_t *addr_pair, variant_t *value, variant_t *right)
{
    switch (addr_pair->type) {
        case UDT_STACK_ADDR:
        case UDT_REC_FIELD_ADDR:
        case UDT_ARRAY_ADDR:
            return OG_SUCCESS;
        case UDT_OBJ_FIELD_ADDR:
            if (value->is_null && right != NULL) {
                OG_THROW_ERROR(ERR_ACCESS_INTO_NULL);
                return OG_ERROR;
            }
            break;
        case UDT_COLL_ELEMT_ADDR:
            if (value->is_null) {
                OG_THROW_ERROR(ERR_COLLECTION_IS_NULL);
                return OG_ERROR;
            }
            break;
        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect udt type");
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t udt_var_address(sql_stmt_t *stmt, galist_t *pairs, expr_node_t *node, variant_t *obj, variant_t *right)
{
    var_address_pair_t *addr_pair = NULL;
    variant_t temp_obj;
    temp_obj.is_null = OG_TRUE;

    for (int64 i = 0; i < pairs->count - 1; i++) {
        addr_pair = (var_address_pair_t *)cm_galist_get(pairs, (uint32)i);
        if (i > 0) {
            OG_RETURN_IFERR(check_invalid_var_ref(addr_pair, &temp_obj, right));
        }

        // direct write operation of hash table subtype requires node application in advance
        if (right != NULL && i > 0 && !temp_obj.is_null && temp_obj.type == OG_TYPE_COLLECTION) {
            plv_collection_t *coll_meta = (plv_collection_t *)temp_obj.v_collection.coll_meta;
            variant_t index;
            if (coll_meta->type == UDT_HASH_TABLE) {
                OG_RETURN_IFERR(udt_hash_table_record_init(stmt, &temp_obj.v_collection, addr_pair, &index, &temp_obj));
            }
        }

        OG_RETURN_IFERR(udt_address(stmt, addr_pair, node, &temp_obj, NULL));
    }

    addr_pair = (var_address_pair_t *)cm_galist_get(pairs, pairs->count - 1);
    OG_RETURN_IFERR(check_invalid_var_ref(addr_pair, &temp_obj, right));
    OG_RETURN_IFERR(udt_address(stmt, addr_pair, node, &temp_obj, right));
    if (obj != NULL) {
        *obj = temp_obj;
    }
    return OG_SUCCESS;
}

status_t udt_exec_v_addr(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, variant_t *right)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    OG_RETURN_IFERR(udt_var_address(stmt, node->value.v_address.pairs, node, result, right));
    if (result != NULL && result->is_null) {
        result->type = node->datatype;
    }
    return OG_SUCCESS;
}

status_t udt_exec_v_method(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    status_t status;
    variant_t obj;
    udt_method_t *v_method = &node->value.v_method;

    OG_RETURN_IFERR(sql_stack_safe(stmt));
    status = udt_var_address(stmt, v_method->pairs, node, &obj, NULL);
    OG_RETURN_IFERR(status);

    if (obj.is_null) {
        OG_SRC_THROW_ERROR(node->loc, ERR_ACCESS_INTO_NULL);
        return OG_ERROR;
    }
    return udt_invoke_coll_method(stmt, v_method, node, &obj, result);
}

status_t udt_exec_v_construct(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    udt_constructor_t *v_construct = &node->value.v_construct;
    OG_RETURN_IFERR(sql_stack_safe(stmt));

    if (v_construct->is_coll) {
        result->v_collection.is_constructed = OG_TRUE;
        return udt_invoke_coll_construct(stmt, v_construct, node->argument, result);
    } else {
        result->v_object.is_constructed = OG_TRUE;
        return udt_object_constructor(stmt, (plv_object_t *)v_construct->meta, node->argument, result);
    }
}

status_t udt_verify_v_construct(sql_verifier_t *verifier, expr_node_t *node)
{
    udt_constructor_t *v_construct = &node->value.v_construct;

    node->udt_type = v_construct->meta;

    if (v_construct->is_coll) {
        node->datatype = OG_TYPE_COLLECTION;
        return udt_verify_coll_construct(verifier, v_construct, node);
    } else {
        node->datatype = OG_TYPE_OBJECT;
        return udt_verify_object_construct(verifier, v_construct, node);
    }
}

status_t udt_verify_v_method(sql_verifier_t *verifier, expr_node_t *node)
{
    udt_method_t *v_method = &node->value.v_method;
    source_location_t loc;
    uint16 option = g_coll_methods[0][v_method->id].option;

    if ((option == AS_PROC && (verifier->excl_flags & SQL_EXCL_METH_PROC)) ||
        (option == AS_FUNC && (verifier->excl_flags & SQL_EXCL_METH_FUNC))) {
        loc = node->loc;
        if (loc.line == 0 && node->argument != NULL) {
            loc.line = node->argument->loc.line;
            loc.column = 1;
        }
        OG_SRC_THROW_ERROR_EX(loc, ERR_PL_SYNTAX_ERROR_FMT, "%s method is not allowed here.",
            GET_COLL_METHOD_DESC(v_method->id));
        return OG_ERROR;
    }

    return udt_verify_coll_method(verifier, v_method, node);
}

static void udt_get_addr_record_node(int8 type, typmode_t type_mode, plv_decl_t *field, expr_node_t *node)
{
    switch (type) {
        case UDT_SCALAR:
            node->typmod = type_mode;
            break;
        case UDT_COLLECTION:
            node->typmod.datatype = OG_TYPE_COLLECTION;
            node->udt_type = UDT_GET_TYPE_DEF_COLLECTION(field);
            break;
        case UDT_OBJECT:
            node->datatype = OG_TYPE_OBJECT;
            node->udt_type = UDT_GET_TYPE_DEF_OBJECT(field);
            break;
        default:
            node->typmod.datatype = OG_TYPE_RECORD;
            node->udt_type = UDT_GET_TYPE_DEF_RECORD(field);
            break;
    }
    return;
}

static void udt_get_addr_object_node(int8 type, typmode_t type_mode, plv_decl_t *field, expr_node_t *node)
{
    switch (type) {
        case UDT_SCALAR:
            node->typmod = type_mode;
            break;
        case UDT_COLLECTION:
            node->typmod.datatype = OG_TYPE_COLLECTION;
            node->udt_type = UDT_GET_TYPE_DEF_COLLECTION(field);
            break;
        case UDT_OBJECT:
            node->datatype = OG_TYPE_OBJECT;
            node->udt_type = UDT_GET_TYPE_DEF_OBJECT(field);
            break;
        default:
            break;
    }
    return;
}

static status_t pl_verify_array_addr(sql_verifier_t *verifier, var_address_pair_t *addr_pair, expr_node_t *node)
{
    var_address_pair_t *pair_new = (var_address_pair_t *)cm_galist_get(node->value.v_address.pairs, 0);
    OG_RETURN_IFERR(sql_verify_pl_var(verifier, pair_new->stack->decl->vid, node));
    node->typmod.is_array = (addr_pair->arr_addr->ss_end == OG_INVALID_ID32) ? OG_FALSE : OG_TRUE;
    return OG_SUCCESS;
}


static status_t udt_get_addr_node_type_core(sql_verifier_t *verifier, var_address_pair_t *addr_pair, expr_node_t *node)
{
    plv_collection_t *coll = NULL;
    plv_record_t *rec = NULL;
    plv_record_attr_t *attr = NULL;
    plv_object_t *obj = NULL;
    plv_object_attr_t *obj_attr = NULL;

    switch (addr_pair->type) {
        case UDT_STACK_ADDR:
            return sql_verify_pl_var(verifier, addr_pair->stack->decl->vid, node);

        case UDT_COLL_ELEMT_ADDR:
            coll = (plv_collection_t *)addr_pair->coll_elemt->parent;
            switch (coll->attr_type) {
                case UDT_SCALAR:
                    node->typmod = coll->type_mode;
                    break;
                case UDT_COLLECTION:
                    node->datatype = OG_TYPE_COLLECTION;
                    node->udt_type = UDT_GET_TYPE_DEF_COLLECTION(coll->elmt_type);
                    break;
                case UDT_OBJECT:
                    node->datatype = OG_TYPE_OBJECT;
                    node->udt_type = UDT_GET_TYPE_DEF_OBJECT(coll->elmt_type);
                    break;
                default:
                    node->datatype = OG_TYPE_RECORD;
                    node->udt_type = UDT_GET_TYPE_DEF_RECORD(coll->elmt_type);
                    break;
            }
            break;
        case UDT_REC_FIELD_ADDR:
            rec = (plv_record_t *)addr_pair->rec_field->parent;
            attr = udt_seek_field_by_id(rec, addr_pair->rec_field->id);
            udt_get_addr_record_node(attr->type, attr->scalar_field->type_mode, attr->udt_field, node);
            break;
        case UDT_OBJ_FIELD_ADDR:
            obj = (plv_object_t *)addr_pair->obj_field->parent;
            obj_attr = udt_seek_obj_field_byid(obj, addr_pair->obj_field->id);
            udt_get_addr_object_node(obj_attr->type, obj_attr->scalar_field->type_mode, obj_attr->udt_field, node);
            break;
        case UDT_ARRAY_ADDR:
            return pl_verify_array_addr(verifier, addr_pair, node);
        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect udt type");
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t udt_get_addr_node_type(sql_verifier_t *verifier, expr_node_t *node)
{
    var_address_pair_t *addr_pair = sql_get_last_addr_pair(node);
    if (addr_pair == NULL) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "addr_pair is null");
        return OG_ERROR;
    }

    if (udt_get_addr_node_type_core(verifier, addr_pair, node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t udt_verify_v_address(sql_verifier_t *verifier, expr_node_t *node)
{
    OG_RETURN_IFERR(udt_get_addr_node_type(verifier, node));
    if ((node->datatype == OG_TYPE_COLLECTION) && (verifier->excl_flags & SQL_EXCL_COLL)) {
        OG_THROW_ERROR(ERR_PL_NOT_ALLOW_COLL);
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t udt_copy_array(sql_stmt_t *stmt, variant_t *src, expr_node_t *node)
{
    uint32 vmid;
    uint32 prev;
    uint32 next;
    vm_lob_t *src_lob = NULL;
    vm_lob_t *dst_lob = NULL;
    vm_pool_t *pool = NULL;
    id_list_t *list = NULL;
    var_address_pair_t *addr_pair = (var_address_pair_t *)cm_galist_get(node->value.v_address.pairs, 0);
    ple_var_t *left = ple_get_plvar((pl_executor_t *)stmt->pl_exec, addr_pair->stack->decl->vid);
    variant_t *dst = &left->value;

    dst->is_null = src->is_null;
    dst->type = OG_TYPE_ARRAY;
    OG_RETVALUE_IFTRUE(src->is_null, OG_SUCCESS);

    /* convert the element datatype if needed */
    OG_RETURN_IFERR(sql_convert_to_array(stmt, src, &left->exec_type, OG_FALSE));

    dst->v_array = src->v_array;
    if (stmt->is_sub_stmt) {
        /* Because the vm pages in sub-stmt lob list maybe freed (for sql line, not for proc line),
        here we should realloc vm pages from parent statement lob list.
        */
        src_lob = &src->v_array.value.vm_lob;
        dst_lob = &dst->v_array.value.vm_lob;
        cm_reset_vm_lob(dst_lob);
        pool = ((sql_stmt_t *)(stmt->parent_stmt))->mtrl.pool;
        list = sql_get_exec_lob_list((sql_stmt_t *)(stmt->parent_stmt));

        /* move the page to parent lob list */
        vmid = src_lob->entry_vmid;
        while (vmid != OG_INVALID_ID32) {
            next = vm_get_ctrl(stmt->mtrl.pool, vmid)->sort_next;
            vm_remove(stmt->mtrl.pool, sql_get_exec_lob_list(stmt), vmid);
            prev = list->last;
            vm_append(pool, list, vmid);
            if (dst_lob->entry_vmid == OG_INVALID_ID32) {
                dst_lob->entry_vmid = vmid;
                dst_lob->last_vmid = vmid;
                vm_get_ctrl(pool, vmid)->sort_next = OG_INVALID_ID32;
            } else {
                vm_get_ctrl(pool, prev)->sort_next = vmid;
                vm_get_ctrl(pool, vmid)->sort_next = OG_INVALID_ID32;
                dst_lob->last_vmid = vmid;
            }
            vmid = next;
        }

        dst_lob->size = src_lob->size;
    }

    return OG_SUCCESS;
}

status_t udt_into_as_value(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right)
{
    sql_stmt_t *parent_stmt = NULL;
    // hit scenario select col1, col2 into scalar_var1, scalar_var2 ...
    expr_node_t *node = (expr_node_t *)cm_galist_get(into->output, stmt->ra.col_id);
    if (node == NULL || node->type != EXPR_NODE_V_ADDR) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return OG_ERROR;
    }
    var_address_pair_t *addr_pair = sql_get_last_addr_pair(node);
    if (addr_pair == NULL) {
        OG_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected pl-variant occurs");
        return OG_ERROR;
    }

    if (addr_pair->type == UDT_ARRAY_ADDR) {
        OG_THROW_ERROR(ERR_UNSUPPORT_FUNC, "select into an array element is", "in PL");
        return OG_ERROR;
    }

    if ((addr_pair->type == UDT_STACK_ADDR && addr_pair->stack->decl->type == PLV_ARRAY)) {
        return udt_copy_array(stmt, right, node);
    }

    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;
    /* SCALAR ASSIGN */
    return udt_exec_v_addr(parent_stmt, node, NULL, right);
}

status_t udt_into_as_coll(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right)
{
    variant_t var_idx;
    variant_t obj;
    ple_var_t *left = NULL;
    sql_stmt_t *parent_stmt = NULL;
    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;

    // hit scenario select col1, col2, ... bulk collect into coll_var1[c_type], coll_var2[c_type], ...,
    // type c_type  is varray(x) of scalar_type
    OG_RETURN_IFERR(ple_get_output_plvar((pl_executor_t *)exec, into, &left, stmt->ra.col_id));

    obj = left->value;
    var_idx.is_null = OG_FALSE;
    var_idx.type = OG_TYPE_INTEGER;
    var_idx.v_int = stmt->batch_rows + 1;
    return udt_coll_elemt_address(parent_stmt, &obj, &var_idx, NULL, right);
}

static status_t udt_var_address_into_record(sql_stmt_t *stmt, galist_t *pairs, variant_t *obj, variant_t *right)
{
    var_address_pair_t *addr_pair;
    variant_t temp_obj;
    plv_collection_t *coll_meta = NULL;
    variant_t var_idx;
    uint32 i = 0;
    addr_pair = (var_address_pair_t *)cm_galist_get(pairs, i);
    OG_RETURN_IFERR(udt_address(stmt, addr_pair, NULL, &temp_obj, NULL));

    for (i = 1; i < pairs->count; i++) {
        addr_pair = (var_address_pair_t *)cm_galist_get(pairs, i);
        OG_RETURN_IFERR(check_invalid_var_ref(addr_pair, &temp_obj, right));
        if (temp_obj.type == OG_TYPE_COLLECTION) {
            coll_meta = (plv_collection_t *)temp_obj.v_collection.coll_meta;
            if (coll_meta->type == UDT_HASH_TABLE) {
                OG_RETURN_IFERR(udt_hash_table_record_init(stmt, &temp_obj.v_collection, addr_pair, &var_idx,
                    &temp_obj));
            }
        }
        OG_RETURN_IFERR(udt_address(stmt, addr_pair, NULL, &temp_obj, NULL));
    }

    if (obj != NULL) {
        *obj = temp_obj;
    }
    return OG_SUCCESS;
}

status_t udt_into_as_record(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right)
{
    variant_t obj;
    var_address_t *var_addr = NULL;
    sql_stmt_t *parent_stmt = NULL;

    CM_ASSERT(into->output->count == 1);
    // hit scenario select col1, col2, ... bulk collect into rec_var1[r_type]
    // type r_type  is record(f1, f2, ...)
    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;
    expr_node_t *node = (expr_node_t *)cm_galist_get(into->output, 0);
    var_addr = NODE_VALUE_PTR(var_address_t, node);
    OG_RETURN_IFERR(udt_var_address_into_record(parent_stmt, var_addr->pairs, &obj, NULL));

    if (stmt->context->rs_columns->count != obj.v_record.count) {
        OG_THROW_ERROR(ERR_RESULT_NOT_MATCH);
        return OG_ERROR;
    }

    return udt_record_field_address(parent_stmt, &obj, stmt->ra.col_id, NULL, right);
}

status_t udt_into_as_coll_rec(sql_stmt_t *stmt, pl_into_t *into, void *exec, variant_t *right)
{
    ple_var_t *left = NULL;
    sql_stmt_t *parent_stmt = NULL;

    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;

    // hit scenario select col1, col2, ... bulk collect into coll_var [c_r_type],
    // type r_type is record (f1, f2,...)
    // type c_r_type  is collection of r_type
    OG_RETURN_IFERR(ple_get_output_plvar((pl_executor_t *)exec, into, &left, 0));

    return udt_record_field_address(parent_stmt, &left->temp, stmt->ra.col_id, NULL, right);
}

static status_t plc_build_construct_args(sql_stmt_t *stmt, expr_tree_t **expr, sql_text_t *args_text,
    bool32 multi_permit)
{
    lex_t *lex = stmt->session->lex;
    status_t status = OG_ERROR;
    word_t leader;
    word_t *word = &leader;

    if (args_text == NULL || args_text->len == 0) {
        *expr = NULL;
        return OG_SUCCESS;
    }

    if (lex_push(lex, args_text) != OG_SUCCESS) {
        return OG_ERROR;
    }

    while (OG_TRUE) {
        if (sql_create_expr_until(stmt, expr, word) != OG_SUCCESS) {
            break;
        }

        if (word->type == WORD_TYPE_EOF) {
            status = OG_SUCCESS;
            break;
        }

        if (!multi_permit) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "wrong argument type");
            break;
        }

        if (word->type == WORD_TYPE_OPERATOR) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(word));
            break;
        }
        expr = &(*expr)->next;
    }

    lex_pop(lex);
    return status;
}

static status_t plc_build_construct(sql_stmt_t *stmt, plv_decl_t *decl, expr_node_t *node, sql_text_t *args_text)
{
    node->type = EXPR_NODE_V_CONSTRUCT;
    node->value.is_null = OG_FALSE;
    udt_constructor_t *v_construct = &node->value.v_construct;
    if (decl->typdef.type == PLV_COLLECTION) {
        if (decl->typdef.collection.type == UDT_HASH_TABLE) {
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "associative arrays do not support constructor");
            return OG_ERROR;
        }
        v_construct->is_coll = OG_TRUE;
        v_construct->meta = (void *)&decl->typdef.collection;
    } else {
        v_construct->is_coll = OG_FALSE;
        v_construct->meta = (void *)&decl->typdef.object;
    }

    return plc_build_construct_args(stmt, &node->argument, args_text, OG_TRUE);
}

static status_t plc_try_resolve_construct(sql_stmt_t *stmt, word_t *word, expr_node_t *node, plv_decl_t *decl)
{
    if (!(decl->typdef.type == PLV_COLLECTION || decl->typdef.type == PLV_OBJECT)) {
        return OG_SUCCESS;
    }

    if (word->ex_count == 0 || word->ex_count > 2 || word->ex_words[word->ex_count - 1].type != WORD_TYPE_BRACKET) {
        OG_SRC_THROW_ERROR(node->loc, ERR_PL_SYNTAX_ERROR_FMT, "the word can not be builded to construct");
        return OG_ERROR;
    }

    return plc_build_construct(stmt, decl, node, &word->ex_words[word->ex_count - 1].text);
}

static void plc_trim_word_without_block(word_t *word)
{
    if (word->ex_count < 1) {
        return;
    }
    word->text = word->ex_words[0].text;
    for (uint32 i = 1; i < word->ex_count; i++) {
        word->ex_words[i - 1].text = word->ex_words[i].text;
    }
    word->ex_count--;
}

status_t plc_add_udt_pair(sql_stmt_t *stmt, galist_t *owner, udt_addr_type_t pair_type, var_address_pair_t **addr_pair)
{
    var_address_pair_t *u_pair = NULL;
    handle_t addr = NULL;
    pl_compiler_t *compile = (pl_compiler_t *)stmt->pl_compiler;

    OG_RETURN_IFERR(cm_galist_new(owner, sizeof(var_address_pair_t), (void **)&u_pair));

    u_pair->type = pair_type;

    switch (pair_type) {
        case UDT_STACK_ADDR:
            OG_RETURN_IFERR(pl_alloc_mem(compile->entity, sizeof(udt_stack_addr_t), (void **)&addr));
            u_pair->stack = (udt_stack_addr_t *)addr;
            break;
        case UDT_REC_FIELD_ADDR:
            OG_RETURN_IFERR(pl_alloc_mem(compile->entity, sizeof(udt_rec_field_addr_t), (void **)&addr));
            u_pair->rec_field = (udt_rec_field_addr_t *)addr;
            break;
        case UDT_OBJ_FIELD_ADDR:
            OG_RETURN_IFERR(pl_alloc_mem(compile->entity, sizeof(udt_obj_field_addr_t), (void **)&addr));
            u_pair->obj_field = (udt_obj_field_addr_t *)addr;
            break;
        case UDT_COLL_ELEMT_ADDR:
            OG_RETURN_IFERR(pl_alloc_mem(compile->entity, sizeof(udt_coll_elemt_addr_t), (void **)&addr));
            u_pair->coll_elemt = (udt_coll_elemt_addr_t *)addr;
            break;
        case UDT_ARRAY_ADDR:
            OG_RETURN_IFERR(pl_alloc_mem(compile->entity, sizeof(udt_array_addr_t), (void **)&addr));
            u_pair->arr_addr = (udt_array_addr_t *)addr;
            break;
        default:
            OG_THROW_ERROR(ERR_PL_WRONG_ADDR_TYPE);
            return OG_ERROR;
    }

    *addr_pair = u_pair;
    return OG_SUCCESS;
}

static inline status_t plc_try_build_array_address(sql_stmt_t *stmt, galist_t *pairs)
{
    var_address_pair_t *addr_pair = NULL;
    int32 start = OG_INVALID_ID32;
    int32 end = OG_INVALID_ID32;
    if (stmt->session->lex->curr_text->len == 0) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(lex_try_fetch_subscript(stmt->session->lex, &start, &end));
    if (start == OG_INVALID_ID32 && end == OG_INVALID_ID32) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(plc_add_udt_pair(stmt, pairs, UDT_ARRAY_ADDR, &addr_pair));
    addr_pair->arr_addr->ss_start = start;
    addr_pair->arr_addr->ss_end = end;
    return OG_SUCCESS;
}

status_t plc_build_var_address(sql_stmt_t *stmt, plv_decl_t *decl, expr_node_t *node, udt_addr_type_t pair_type)
{
    var_address_pair_t *addr_pair = NULL;
    pl_compiler_t *compile = (pl_compiler_t *)stmt->pl_compiler;

    node->type = EXPR_NODE_V_ADDR;
    OG_RETURN_IFERR(plc_init_galist(compile, &node->value.v_address.pairs));
    galist_t *pairs = (galist_t *)node->value.v_address.pairs;

    OG_RETURN_IFERR(plc_add_udt_pair(stmt, pairs, pair_type, &addr_pair));
    addr_pair->stack->decl = decl;

    if (decl->type == PLV_ARRAY) {
        OG_RETURN_IFERR(plc_try_build_array_address(stmt, node->value.v_address.pairs));
    }
    return OG_SUCCESS;
}

static status_t plc_build_method_args_extra(sql_stmt_t *stmt, expr_tree_t **arguments, sql_text_t *args)
{
    lex_t *lex = stmt->session->lex;
    word_t word;
    status_t status = OG_ERROR;
    if (args->len == 0) {
        *arguments = NULL;
        return OG_SUCCESS;
    }
    if (lex_push(lex, args) != OG_SUCCESS) {
        return OG_ERROR;
    }
    expr_tree_t **arg_expr = arguments;
    while (OG_TRUE) {
        status = sql_create_expr_until(stmt, arg_expr, &word);
        OG_BREAK_IF_ERROR(status);

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "',' expected but %s found", W2S(&word));
            lex_pop(lex);
            return OG_ERROR;
        }

        arg_expr = &(*arg_expr)->next;
    }

    lex_pop(lex);
    return status;
}

static status_t plc_recurse_parse_coll_address(sql_stmt_t *stmt, plv_typdef_t *type_def, galist_t *pairs, uint32 *index,
    word_t *ex_word, expr_node_t *node)
{
    uint32 i = *index;
    var_address_pair_t *addr_pair = NULL;
    plv_collection_t *collection = &type_def->collection;

    if (ex_word->ex_words[i].type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(plc_add_udt_pair(stmt, pairs, UDT_COLL_ELEMT_ADDR, &addr_pair));
        addr_pair->coll_elemt->parent = collection;
        OG_RETURN_IFERR(plc_build_method_args_extra(stmt, &addr_pair->coll_elemt->id, &ex_word->ex_words[i].text));
        OG_RETURN_IFERR(plc_clone_expr_tree(stmt->pl_compiler, &addr_pair->coll_elemt->id));
        if (addr_pair->coll_elemt->id == NULL) {
            OG_THROW_ERROR(ERR_PL_REF_VARIABLE_FAILED, T2S(&ex_word->ex_words[0].text));
            return OG_ERROR;
        }
        OG_RETURN_IFERR(plc_verify_limit_expr(stmt->pl_compiler, addr_pair->coll_elemt->id));
        *index = *index + 1;
        if (collection->attr_type == UDT_SCALAR) {
            return OG_SUCCESS;
        } else {
            OG_RETURN_IFERR(
                plc_recurse_parse_udt_address(stmt, &collection->elmt_type->typdef, pairs, index, ex_word, node));
        }
    } else if (ex_word->ex_words[i].type == WORD_TYPE_VARIANT || ex_word->ex_words[i].type == WORD_TYPE_KEYWORD) {
        uint8 id = 0;
        if (lex_match_coll_method_name(&ex_word->ex_words[i].text, &id)) {
            *index = *index + 1;
            if ((i + 1 < ex_word->ex_count) && ex_word->ex_words[i + 1].type == WORD_TYPE_BRACKET) {
                OG_RETURN_IFERR(plc_build_method_args_extra(stmt, &node->argument, &ex_word->ex_words[i + 1].text));
                OG_RETURN_IFERR(plc_clone_expr_tree(stmt->pl_compiler, &node->argument));
                *index = *index + 1;
            }
            node->type = EXPR_NODE_V_METHOD;
            node->value.is_null = OG_FALSE;
            node->value.type = OG_TYPE_INTEGER;
            node->value.v_method.id = id;
            node->value.v_method.meta = (void *)collection;
            node->value.v_method.pairs = pairs;
        } else {
            OG_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "component \'%s\' must be declared",
                T2S(&ex_word->ex_words[i].text));
            return OG_ERROR;
        }
    } else {
        OG_THROW_ERROR_EX(ERR_PL_SYNTAX_ERROR_FMT, "component \'%s\' must be declared",
            T2S(&ex_word->ex_words[i].text));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t plc_recurse_parse_rec_address(sql_stmt_t *stmt, plv_typdef_t *type_def, galist_t *pairs, uint32 *index,
    word_t *ex_word, expr_node_t *node)
{
    uint32 i = *index;
    plv_record_t *record = NULL;
    plv_record_attr_t *field = NULL;
    var_address_pair_t *addr_pair = NULL;

    if (ex_word->ex_words[i].type == WORD_TYPE_BRACKET) {
        OG_SRC_THROW_ERROR(ex_word->ex_words[i].text.loc, ERR_PL_SYNTAX_ERROR_FMT,
            "addressing of record type is \'.\'");
        return OG_ERROR;
    }
    record = &type_def->record;
    field = udt_seek_field_by_name(stmt, record, &ex_word->ex_words[i].text,
        IS_DQ_STRING(ex_word->ex_words[i].type) || !IS_CASE_INSENSITIVE);
    if (field == NULL) {
        OG_SRC_THROW_ERROR_EX(ex_word->ex_words[i].text.loc, ERR_PL_SYNTAX_ERROR_FMT, "invalid field name \'%s\'",
            T2S(&ex_word->ex_words[i].text));

        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_add_udt_pair(stmt, pairs, UDT_REC_FIELD_ADDR, &addr_pair));
    addr_pair->rec_field->id = field->field_id;
    addr_pair->rec_field->parent = record;
    *index = *index + 1;
    /* if field type is SCALAR, no need to recurse */
    if (field->type == UDT_SCALAR) {
        return OG_SUCCESS;
    }

    return plc_recurse_parse_udt_address(stmt, &field->udt_field->typdef, pairs, index, ex_word, node);
}

static status_t plc_recurse_parse_obj_address(sql_stmt_t *stmt, plv_typdef_t *type_def, galist_t *pairs, uint32 *index,
    word_t *ex_word, expr_node_t *node)
{
    uint32 i = *index;
    plv_object_t *object = NULL;
    plv_object_attr_t *attr = NULL;
    var_address_pair_t *addr_pair = NULL;

    if (ex_word->ex_words[i].type == WORD_TYPE_BRACKET) {
        OG_SRC_THROW_ERROR(ex_word->ex_words[i].text.loc, ERR_PL_SYNTAX_ERROR_FMT,
            "addressing of object type is \'.\'");
        return OG_ERROR;
    }
    object = &type_def->object;
    attr = udt_seek_obj_field_byname(stmt, object, &ex_word->ex_words[i].text,
        IS_DQ_STRING(ex_word->ex_words[i].type) || !IS_CASE_INSENSITIVE);
    if (attr == NULL) {
        OG_SRC_THROW_ERROR_EX(ex_word->ex_words[i].text.loc, ERR_PL_SYNTAX_ERROR_FMT, "invalid field name \'%s\'",
            T2S(&ex_word->ex_words[i].text));

        return OG_ERROR;
    }
    OG_RETURN_IFERR(plc_add_udt_pair(stmt, pairs, UDT_OBJ_FIELD_ADDR, &addr_pair));
    addr_pair->obj_field->id = attr->field_id;
    addr_pair->obj_field->parent = object;
    *index = *index + 1;
    /* if field type is SCALAR, no need to recurse */
    if (attr->type == UDT_SCALAR) {
        return OG_SUCCESS;
    }

    return plc_recurse_parse_udt_address(stmt, &attr->udt_field->typdef, pairs, index, ex_word, node);
}

status_t plc_recurse_parse_udt_address(sql_stmt_t *stmt, plv_typdef_t *type_def, galist_t *pairs, uint32 *index,
    word_t *ex_word, expr_node_t *node)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    if (*index >= ex_word->ex_count) {
        return OG_SUCCESS;
    }

    switch (type_def->type) {
        case PLV_RECORD:
            OG_RETURN_IFERR(plc_recurse_parse_rec_address(stmt, type_def, pairs, index, ex_word, node));
            break;
        case PLV_OBJECT:
            OG_RETURN_IFERR(plc_recurse_parse_obj_address(stmt, type_def, pairs, index, ex_word, node));
            break;
        case PLV_COLLECTION:
            /* record variable address only support [() | .function() | .function] */
            OG_RETURN_IFERR(plc_recurse_parse_coll_address(stmt, type_def, pairs, index, ex_word, node));
            break;
        default:
            OG_SRC_THROW_ERROR(node->loc, ERR_PL_WRONG_TYPE_VALUE, "Complex type", type_def->type);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t udt_address_find_decl(pl_compiler_t *compiler, word_t *word, plc_var_type_t *type, plv_decl_t **decl)
{
    if (word->type == WORD_TYPE_PARAM) {
        return plc_find_param_as_expr_left(compiler, word, decl);
    }

    plc_find_decl_ex(compiler, word, PLV_TYPE | PLV_VARIANT_AND_CUR, type, decl);
    if (*decl == NULL && IS_TRIGGER_WORD_TYPE(word)) {
        OG_RETURN_IFERR(plc_add_trigger_decl(compiler, 0, word, PLV_VAR, decl));
    }
    return OG_SUCCESS;
}

static inline plv_decl_t *plm_get_type_decl_by_obj(plv_object_t *object_meta)
{
    pl_entity_t *entity = (pl_entity_t *)object_meta->root;
    return entity->type_spec->decl;
}

static inline plv_decl_t *plm_get_type_decl_by_rec(plv_record_t *record_meta)
{
    return ((plv_decl_t *)record_meta->root);
}

plv_decl_t *plm_get_type_decl_by_coll(plv_collection_t *coll_meta)
{
    if (coll_meta->is_global) {
        pl_entity_t *entity = (pl_entity_t *)coll_meta->root;
        return entity->type_spec->decl;
    } else {
        return ((plv_decl_t *)coll_meta->root);
    }
}

static status_t udt_address_parse_multiex_variant(sql_stmt_t *stmt, word_t *word, expr_node_t *node, plv_decl_t *decl)
{
    uint32 index = 0;
    plv_decl_t *type = NULL;

    switch (decl->type) {
        case PLV_RECORD:
            type = plm_get_type_decl_by_rec(decl->record);
            break;
        case PLV_OBJECT:
            type = plm_get_type_decl_by_obj(decl->object);
            break;
        case PLV_COLLECTION:
            type = plm_get_type_decl_by_coll(decl->collection);
            break;
        default:
            OG_SRC_THROW_ERROR(word->loc, ERR_PL_REF_VARIABLE_FAILED, T2S(&word->text));
            return OG_ERROR;
    }

    OG_RETURN_IFERR(
        plc_recurse_parse_udt_address(stmt, &type->typdef, node->value.v_address.pairs, &index, word, node));
    if (index != word->ex_count) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_REF_VARIABLE_FAILED, T2S(&word->text.value));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t plc_try_obj_access_single(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    plv_decl_t *decl = NULL;
    plc_var_type_t var_type = PLC_NORMAL_VAR;
    bool32 found = OG_FALSE;

    OG_RETURN_IFERR(udt_address_find_decl(stmt->pl_compiler, word, &var_type, &decl));
    if (decl == NULL) {
        OG_RETURN_IFERR(plc_try_find_global_type(stmt->pl_compiler, word, &decl, &found));
        if (!found) {
            return OG_SUCCESS;
        }
    }
    if (var_type == PLC_BLOCK_MULTIEX_VAR) {
        plc_trim_word_without_block(word);
    }
    if (decl->type == PLV_TYPE) {
        return plc_try_resolve_construct(stmt, word, node, decl);
    }

    OG_RETURN_IFERR(plc_build_var_address(stmt, decl, node, UDT_STACK_ADDR));
    if (PLC_IS_MULTIEX_VARIANT(var_type)) {
        OG_RETURN_IFERR(udt_address_parse_multiex_variant(stmt, word, node, decl));
    }
    return OG_SUCCESS;
}

static status_t plc_try_obj_access_extra(sql_stmt_t *stmt, word_t *word, expr_node_t *node, word_t *ex_word)
{
    OG_RETURN_IFERR(plc_try_obj_access_single(stmt, word, node));
    if (node->type != EXPR_NODE_V_ADDR) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_REF_VARIABLE_FAILED, T2S(&word->text.value));
        return OG_ERROR;
    }
    var_address_pair_t *addr_pair = sql_get_last_addr_pair(node);
    plv_decl_t *decl = plc_get_last_addr_decl(stmt, addr_pair);
    if (decl == NULL) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_SYNTAX_ERROR_FMT,
            "object \'%s\' must be of type function or array to be used this way", T2S(&word->text.value));
        return OG_ERROR;
    }

    if (decl->type != PLV_TYPE && !CM_IS_PLV_UDT_DATATYPE(decl->type)) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_REF_VARIABLE_FAILED, T2S(&word->text.value));
        return OG_ERROR;
    }

    uint32 index = 0;
    OG_RETURN_IFERR(
        plc_recurse_parse_udt_address(stmt, &decl->typdef, node->value.v_address.pairs, &index, ex_word, node));
    if (index != ex_word->ex_count) {
        OG_SRC_THROW_ERROR_EX(word->loc, ERR_PL_REF_VARIABLE_FAILED, T2S(&word->text.value));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t plc_prepare_method_extra(sql_stmt_t *stmt, word_t *word, uint32 *count, ex_text_t extend[])
{
    uint32 ex_count = 0;
    lex_t *lex = stmt->session->lex;
    bool32 result = OG_FALSE;
    uint32 flag = lex->flags;
    key_word_t *save_key_words = NULL;
    uint32 save_key_word_count;

    lex->flags = LEX_SINGLE_WORD;
    do {
        if (ex_count >= MAX_EXTRA_TEXTS) {
            OG_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "too deep to call record or collection variant");
            break;
        }
        OG_BREAK_IF_ERROR(lex_try_fetch_bracket(lex, word, &result));
        if (result) {
            extend[ex_count].type = word->type;
            extend[ex_count].text = word->text;
            ex_count++;
            continue;
        }
        OG_BREAK_IF_ERROR(lex_try_fetch_char(lex, '.', &result));
        if (!result) {
            // no word need to fetch more
            *count = ex_count;
            lex->flags = flag;
            return OG_SUCCESS;
        }

        SAVE_LEX_KEY_WORD(lex, save_key_words, save_key_word_count);
        SET_LEX_KEY_WORD(lex, (key_word_t *)g_method_key_words, METHOD_KEY_WORDS_COUNT);
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            SET_LEX_KEY_WORD(lex, save_key_words, save_key_word_count);
            return OG_ERROR;
        }
        SET_LEX_KEY_WORD(lex, save_key_words, save_key_word_count);
        extend[ex_count].type = word->type;
        extend[ex_count].text = word->text;
        ex_count++;
    } while (1);
    lex->flags = flag;

    return OG_ERROR;
}

status_t plc_try_obj_access_bracket(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    word_t ex_word;
    word_t leader;

    ex_word.ex_count = 0;
    // step 1, text may be not complete, fetch until eof
    OG_RETURN_IFERR(plc_prepare_method_extra(stmt, &leader, &ex_word.ex_count, ex_word.ex_words));

    if (ex_word.ex_count == 0) {
        OG_RETURN_IFERR(plc_try_obj_access_single(stmt, word, node));
    } else {
        OG_RETURN_IFERR(plc_try_obj_access_extra(stmt, word, node, &ex_word));
    }

    return OG_SUCCESS;
}

status_t plc_try_obj_access_node(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    if (stmt->pl_compiler == NULL) {
        // method impossiable
        return OG_SUCCESS;
    }

    /* coll_var[(expr)|.fd]* */
    OGSQL_SAVE_STACK(stmt);
    status_t status = plc_try_obj_access_bracket(stmt, word, node);
    OGSQL_RESTORE_STACK(stmt);

    return status;
}

status_t udt_build_list_address_single(sql_stmt_t *stmt, galist_t *list, plv_decl_t *decl, udt_addr_type_t pair_type)
{
    expr_node_t *node = NULL;
    OG_RETURN_IFERR(cm_galist_new(list, sizeof(expr_node_t), (void **)&node));
    OG_RETURN_IFERR(plc_build_var_address(stmt, decl, node, pair_type));
    if (decl->type != PLV_PARAM) {
        SET_FUNC_RETURN_TYPE(decl, node);
    }
    return OG_SUCCESS;
}

void pl_init_udt_method(void)
{
    udt_reg_varray_method();
    udt_reg_nested_table_method();
    udt_reg_hash_table_method();
}
