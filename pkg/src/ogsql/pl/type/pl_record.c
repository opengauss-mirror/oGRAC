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
 * pl_record.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/type/pl_record.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_record.h"
#include "srv_instance.h"
#include "pl_hash_tb.h"
#include "pl_scalar.h"
#include "pl_memory.h"

static status_t udt_record_delete_field(sql_stmt_t *stmt, plv_record_attr_t *attr, mtrl_rowid_t *row_id, bool8 clean);

status_t udt_record_delete(sql_stmt_t *stmt, variant_t *var, bool8 clean)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    if (IS_INVALID_MTRL_ROWID(var->v_record.value)) {
        return OG_SUCCESS;
    }

    udt_mtrl_record_head_t *mtrl_head = NULL;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    plv_record_attr_t *attr = NULL;
    plv_record_t *record = (plv_record_t *)var->v_record.record_meta;
    OPEN_VM_PTR(&var->v_record.value, vm_context);
    mtrl_head = (udt_mtrl_record_head_t *)d_ptr;
    for (uint16 i = 0; i < record->count; i++) {
        attr = udt_seek_field_by_id(record, i);
        if (udt_record_delete_field(stmt, attr, &mtrl_head->field[i].rowid, clean) != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(&var->v_record.value, vm_context);
            return OG_ERROR;
        }
    }
    CLOSE_VM_PTR(&var->v_record.value, vm_context);

    if (clean) {
        OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), &var->v_record.value));
        var->v_record.value = g_invalid_entry;
        var->is_null = OG_TRUE;
    }
    return OG_SUCCESS;
}

plv_record_attr_t *udt_record_alloc_attr(void *entity, plv_record_t *record)
{
    pl_entity_t *pl_entity = (pl_entity_t *)entity;
    pl_rmap_extent_t *extent = NULL;
    plv_record_attr_t *attr = NULL;
    if (record->hwm == record->count) {
        if (record->hwm >= PL_REC_MAX_FIELD_SIZE) {
            OG_THROW_ERROR(ERR_OUT_OF_INDEX, "record", PL_REC_MAX_FIELD_SIZE);
            return NULL;
        }

        if (pl_alloc_mem(pl_entity, sizeof(pl_rmap_extent_t), (void **)&extent) != OG_SUCCESS) {
            return NULL;
        }
        SET_RECORD_EXTENT(record, extent);
        record->extent_count++;
        record->hwm += PL_RMAP_EXTENT_SIZE;
    }

    attr = udt_seek_field_by_id(record, record->count);
    attr->field_id = record->count;
    record->count++;

    return attr;
}

plv_record_attr_t *udt_record_recurse_find_attr(sql_stmt_t *stmt, uint16 *id, plv_record_t *record, word_t *word)
{
    if (*id == word->ex_count) {
        return NULL;
    }

    if (word->ex_words[*id].type == WORD_TYPE_BRACKET) {
        return NULL;
    }

    plv_record_attr_t *record_attr = udt_seek_field_by_name(stmt, record, &word->ex_words[*id].text,
        IS_DQ_STRING(word->ex_words[*id].type) || !IS_CASE_INSENSITIVE);
    if (record_attr == NULL) {
        return NULL;
    }
    if (record_attr->type == UDT_SCALAR) {
        if (*id != (word->ex_count - 1)) {
            return NULL;
        }
    } else if (record_attr->type == UDT_RECORD) {
        (*id)++;
        record_attr = udt_record_recurse_find_attr(stmt, id, &record_attr->udt_field->typdef.record, word);
    }
    return record_attr;
}

static status_t udt_verify_record_attr_rec(plv_record_attr_t *from_attr, plv_record_attr_t *to_attr)
{
    plv_record_t *sub_from_record = &from_attr->udt_field->typdef.record;
    plv_record_t *sub_to_record = &to_attr->udt_field->typdef.record;
    if (sub_from_record == sub_to_record) {
        return OG_SUCCESS;
    }
    if (!sub_to_record->is_anonymous && !sub_from_record->is_anonymous) {
        OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "left attr and right attr need be the same record type");
        return OG_ERROR;
    }
    return udt_verify_record_attr(sub_from_record, sub_to_record);
}

status_t udt_verify_record_attr(plv_record_t *from_record, plv_record_t *to_record)
{
    plv_record_attr_t *from_attr = NULL;
    plv_record_attr_t *to_attr = NULL;

    for (uint32 i = 0; i < from_record->count; i++) {
        from_attr = udt_seek_field_by_id(from_record, i);
        to_attr = udt_seek_field_by_id(to_record, i);
        if (to_attr->type != from_attr->type) {
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "left attr and right attr need be the same type");
            return OG_ERROR;
        }
        switch (to_attr->type) {
            case UDT_SCALAR:
                if (!var_datatype_matched(PL_ATTR_SCALAR_DATATYPE(to_attr), PL_ATTR_SCALAR_DATATYPE(from_attr))) {
                    OG_SET_ERROR_MISMATCH(PL_ATTR_SCALAR_DATATYPE(to_attr), PL_ATTR_SCALAR_DATATYPE(from_attr));
                    return OG_ERROR;
                }
                break;
            case UDT_COLLECTION:
                if (to_attr->udt_field != from_attr->udt_field) {
                    OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT,
                        "left attr and right attr need be the same collection type");
                    return OG_ERROR;
                }
                break;
            case UDT_RECORD:
                OG_RETURN_IFERR(udt_verify_record_attr_rec(from_attr, to_attr));
                break;
            case UDT_OBJECT:
                if (to_attr->udt_field != from_attr->udt_field) {
                    OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "left attr and right attr need be the same object type");
                    return OG_ERROR;
                }
                break;
            default:
                OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
                return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t udt_record_clone_field(sql_stmt_t *stmt, plv_record_attr_t *from_attr,
                                       udt_mtrl_record_field_t *copy_from, plv_record_attr_t *to_attr,
                                       udt_mtrl_record_field_t *copy_to)
{
    status_t status;
    variant_t var;
    plv_decl_t *ele_meta = NULL;

    OG_RETURN_IFERR(udt_record_field_addr_read(stmt, from_attr, &var, copy_from));

    if (var.is_null) {
        copy_to->rowid = g_invalid_entry;
        return OG_SUCCESS;
    }

    switch (to_attr->type) {
        case UDT_SCALAR:
            status = udt_make_scalar_elemt(stmt, to_attr->scalar_field->type_mode, &var,
                                           &copy_to->rowid, &copy_to->type);
            break;
        case UDT_COLLECTION:
            ele_meta = to_attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            status = udt_clone_collection(stmt, &var, &copy_to->rowid);
            break;

        case UDT_RECORD:
            ele_meta = to_attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_RECORD);
            status = udt_record_clone(stmt, &var, &to_attr->udt_field->typdef.record, &copy_to->rowid);
            break;

        case UDT_OBJECT:
            ele_meta = to_attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            status = udt_object_clone(stmt, &var, &copy_to->rowid);
            break;

        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return OG_ERROR;
    }

    return status;
}

status_t udt_record_clone(sql_stmt_t *stmt, variant_t *from, plv_record_t *to_record, mtrl_rowid_t *to_row)
{
    status_t status = OG_SUCCESS;
    plv_record_t *from_record = (plv_record_t *)from->v_record.record_meta;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    udt_mtrl_record_head_t *to_head = NULL;
    plv_record_attr_t *from_attr = NULL;
    plv_record_attr_t *to_attr = NULL;
    udt_mtrl_record_head_t *from_head = NULL;

    OPEN_VM_PTR(&from->v_record.value, vm_context);
    from_head = (udt_mtrl_record_head_t *)d_ptr;
    if (vmctx_open_row_id(vm_context, to_row, (char **)&to_head) != OG_SUCCESS) {
        CLOSE_VM_PTR_EX(&from->v_record.value, vm_context);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < from_record->count; i++) {
        from_attr = udt_seek_field_by_id(from_record, i);
        to_attr = udt_seek_field_by_id(to_record, i);
        status = udt_record_clone_field(stmt, from_attr, &from_head->field[i], to_attr, &to_head->field[i]);
        if (status != OG_SUCCESS) {
            break;
        }
    }
    vmctx_close_row_id(vm_context, to_row);
    CLOSE_VM_PTR(&from->v_record.value, vm_context);
    return status;
}

static status_t udt_record_delete_field(sql_stmt_t *stmt, plv_record_attr_t *attr, mtrl_rowid_t *row_id, bool8 clean)
{
    variant_t var;
    plv_decl_t *fld_meta = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    if (IS_INVALID_MTRL_ROWID(*row_id)) {
        return OG_SUCCESS;
    }

    switch (attr->type) {
        case UDT_SCALAR:
            break;
        case UDT_COLLECTION:
            fld_meta = attr->udt_field;
            CM_ASSERT(fld_meta->type == PLV_TYPE);
            CM_ASSERT(fld_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, fld_meta, *row_id);
            OG_RETURN_IFERR(udt_delete_collection(stmt, &var));
            break;
        case UDT_RECORD:
            fld_meta = attr->udt_field;
            CM_ASSERT(fld_meta->type == PLV_TYPE);
            CM_ASSERT(fld_meta->typdef.type == PLV_RECORD);
            MAKE_REC_VAR(&var, fld_meta, *row_id);
            /* local record no need to free mtrl head */
            return udt_record_delete(stmt, &var, clean);
        case UDT_OBJECT:
            fld_meta = attr->udt_field;
            CM_ASSERT(fld_meta->type == PLV_TYPE);
            CM_ASSERT(fld_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, fld_meta, *row_id);
            OG_RETURN_IFERR(udt_object_delete(stmt, &var));
            *row_id = g_invalid_entry;
            return OG_SUCCESS;
        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return OG_ERROR;
    }

    OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), row_id));
    *row_id = g_invalid_entry;

    return OG_SUCCESS;
}

status_t udt_record_field_addr_write(sql_stmt_t *stmt, plv_record_attr_t *attr, udt_mtrl_record_field_t *field,
    variant_t *right)
{
    variant_t left;

    switch (attr->type) {
        case UDT_SCALAR:
            OG_RETURN_IFERR(udt_record_delete_field(stmt, attr, &field->rowid, OG_FALSE));
            if (!right->is_null) {
                OG_RETURN_IFERR(
                    udt_make_scalar_elemt(stmt, attr->scalar_field->type_mode, right, &field->rowid, &field->type));
            }
            break;

        case UDT_COLLECTION:
            MAKE_COLL_VAR(&left, attr->udt_field, field->rowid);
            OG_RETURN_IFERR(udt_coll_assign(stmt, &left, right));
            field->rowid = left.v_collection.value;
            break;

        case UDT_RECORD:
            MAKE_REC_VAR(&left, attr->udt_field, field->rowid);
            OG_RETURN_IFERR(udt_record_assign(stmt, &left, right));
            field->rowid = left.v_record.value;
            break;

        case UDT_OBJECT:
            MAKE_OBJ_VAR(&left, attr->udt_field, field->rowid);
            OG_RETURN_IFERR(udt_object_assign(stmt, &left, right));
            field->rowid = left.v_object.value;
            break;

        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t udt_record_field_addr_read(sql_stmt_t *stmt, plv_record_attr_t *attr, variant_t *res,
    udt_mtrl_record_field_t *field)
{
    if (IS_INVALID_MTRL_ROWID(field->rowid)) {
        res->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    res->is_null = OG_FALSE;
    switch (attr->type) {
        case UDT_SCALAR:
            res->type = field->type;
            OG_RETURN_IFERR(udt_read_scalar_value(stmt, &field->rowid, res));
            break;

        case UDT_COLLECTION:
            res->type = OG_TYPE_COLLECTION;
            res->v_collection.type = attr->udt_field->typdef.collection.type;
            res->v_collection.coll_meta = &attr->udt_field->typdef.collection;
            res->v_collection.value = field->rowid;
            res->v_collection.is_constructed = OG_FALSE;
            break;

        case UDT_RECORD:
            res->type = OG_TYPE_RECORD;
            res->v_record.count = attr->udt_field->typdef.record.count;
            res->v_record.record_meta = &attr->udt_field->typdef.record;
            res->v_record.value = field->rowid;
            res->v_record.is_constructed = OG_FALSE;
            break;

        case UDT_OBJECT:
            res->type = OG_TYPE_OBJECT;
            res->v_object.count = attr->udt_field->typdef.object.count;
            res->v_object.object_meta = &attr->udt_field->typdef.object;
            res->v_object.value = field->rowid;
            res->v_object.is_constructed = OG_FALSE;
            break;

        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t udt_record_field_address(sql_stmt_t *stmt, variant_t *var, uint16 id, variant_t *res, variant_t *right)
{
    status_t status;
    var_record_t *v_record = &var->v_record;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    udt_mtrl_record_head_t *mtrl_head = NULL;
    plv_record_t *record = v_record->record_meta;
    addr_type_t type = (right != NULL ? WRITE_ADDR : READ_ADDR);

    if (id >= record->count) {
        OG_THROW_ERROR(ERR_PL_REC_FIELD_INVALID);
        return OG_ERROR;
    }

    plv_record_attr_t *attr = udt_seek_field_by_id(record, id);

    OPEN_VM_PTR(&v_record->value, vm_context);
    mtrl_head = (udt_mtrl_record_head_t *)d_ptr;
    if (type == WRITE_ADDR) {
        status = udt_record_field_addr_write(stmt, attr, &mtrl_head->field[id], right);
    } else {
        status = udt_record_field_addr_read(stmt, attr, res, &mtrl_head->field[id]);
    }
    CLOSE_VM_PTR(&v_record->value, vm_context);

    return status;
}

static og_type_t udt_record_field_type_init(plv_record_attr_t *attr)
{
    switch (attr->type) {
        case UDT_COLLECTION:
            return OG_TYPE_COLLECTION;
        case UDT_RECORD:
            return OG_TYPE_RECORD;
        case UDT_OBJECT:
            return OG_TYPE_OBJECT;
        default:
            return (int16)attr->scalar_field->type_mode.datatype;
    }
}

static status_t udt_record_init_field(sql_stmt_t *stmt, udt_mtrl_record_head_t *record_head, plv_record_t *record,
    mtrl_rowid_t *rowid)
{
    plv_record_attr_t *attr = NULL;
    plv_record_t *attr_record = NULL;

    for (uint32 i = 0; i < record_head->count; i++) {
        attr = udt_seek_field_by_id((plv_record_t *)record, i);
        attr_record = &attr->udt_field->typdef.record;
        if (attr->type == UDT_RECORD) {
            OG_RETURN_IFERR(udt_record_alloc_mtrl_head(stmt, attr_record, rowid));
            record_head->field[i].rowid = *rowid;
        }
        if (attr->type == UDT_COLLECTION) {
            variant_t left;
            MAKE_COLL_VAR(&left, attr->udt_field, g_invalid_entry);
            if (FIELD_IS_HASH_TABLE(attr)) {
                OG_RETURN_IFERR(udt_hash_table_init_var(stmt, &left));
            }
            record_head->field[i].rowid = left.v_collection.value;
        }
        record_head->field[i].type = udt_record_field_type_init(attr);
    }
    return OG_SUCCESS;
}

status_t udt_record_alloc_mtrl_head(sql_stmt_t *stmt, plv_record_t *record, mtrl_rowid_t *rowid)
{
    uint16 head_size;
    status_t status;
    udt_mtrl_record_head_t *record_head = NULL;
    errno_t err;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    head_size = record->count * sizeof(udt_mtrl_record_field_t) + sizeof(udt_mtrl_record_head_t);
    OG_RETURN_IFERR(sql_push(stmt, head_size, (void **)&record_head));
    record_head->size = head_size;
    record_head->count = record->count;
    err = memset_sp(record_head->field, record->count * sizeof(udt_mtrl_record_field_t), 0xFF,
        record_head->count * sizeof(udt_mtrl_record_field_t));
    if (err != EOK) {
        OGSQL_POP(stmt);
        OG_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return OG_ERROR;
    }

    if (udt_record_init_field(stmt, record_head, record, rowid) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }
    status = vmctx_insert(GET_VM_CTX(stmt), (const char *)record_head, head_size, rowid);
    OGSQL_POP(stmt);
    return status;
}

status_t udt_record_assign(sql_stmt_t *stmt, variant_t *left, variant_t *right)
{
    plv_record_t *record = (plv_record_t *)left->v_record.record_meta;
    if (right->type == OG_TYPE_RECORD && UDT_IS_EQUAL_RECORD_VAR(left, right)) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_stack_safe(stmt));

    OG_RETURN_IFERR(udt_record_delete(stmt, left, OG_FALSE));
    /* mtrl head no free */
    if (right->is_null) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(udt_verify_record_assign_ex(right, record));

    if (UDT_REC_NEED_DEEP_COPY(right)) {
        OG_RETURN_IFERR(udt_record_clone(stmt, right, record, &left->v_record.value));
    } else {
        // before shallow copy, need to free left head's vmctx
        OG_RETURN_IFERR(vmctx_free(GET_VM_CTX(stmt), &left->v_record.value));
        left->v_record.value = right->v_record.value;
    }
    left->is_null = right->is_null;
    return OG_SUCCESS;
}

static status_t udt_record_clone_field_all(sql_stmt_t *stmt, plv_record_attr_t *attr, mtrl_rowid_t copy_from,
    mtrl_rowid_t *copy_to)
{
    status_t status;
    variant_t var;
    plv_decl_t *ele_meta = NULL;

    if (IS_INVALID_MTRL_ROWID(ROWID_ID2_UINT64(copy_from))) {
        *copy_to = g_invalid_entry;
        return OG_SUCCESS;
    }

    switch (attr->type) {
        case UDT_SCALAR:
            status = udt_clone_scalar(stmt, copy_from, copy_to);
            break;

        case UDT_COLLECTION:
            ele_meta = attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_COLLECTION);
            MAKE_COLL_VAR(&var, ele_meta, copy_from);
            status = udt_clone_collection(stmt, &var, copy_to);
            break;

        case UDT_RECORD:
            ele_meta = attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_RECORD);
            MAKE_REC_VAR(&var, ele_meta, copy_from);
            status = udt_record_clone_all(stmt, &var, copy_to);
            break;

        case UDT_OBJECT:
            ele_meta = attr->udt_field;
            CM_ASSERT(ele_meta->type == PLV_TYPE);
            CM_ASSERT(ele_meta->typdef.type == PLV_OBJECT);
            MAKE_OBJ_VAR(&var, ele_meta, copy_from);
            status = udt_object_clone(stmt, &var, copy_to);
            break;

        default:
            OG_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return OG_ERROR;
    }

    return status;
}

// Used to clone for which record head has not been applied for.
status_t udt_record_clone_all(sql_stmt_t *stmt, variant_t *right, mtrl_rowid_t *res)
{
    status_t status;
    plv_record_t *record = (plv_record_t *)right->v_record.record_meta;
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    udt_mtrl_record_head_t *record_head = NULL;
    plv_record_attr_t *attr = NULL;

    OPEN_VM_PTR(&right->v_record.value, vm_context);
    status = vmctx_insert(vm_context, (const char *)d_ptr, d_chunk->requested_size, res);
    CLOSE_VM_PTR(&right->v_record.value, vm_context);
    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }

    OPEN_VM_PTR(res, vm_context);
    record_head = (udt_mtrl_record_head_t *)d_ptr;

    for (uint32 i = 0; i < record->count; i++) {
        attr = udt_seek_field_by_id(record, i);
        status = udt_record_clone_field_all(stmt, attr, record_head->field[i].rowid, &record_head->field[i].rowid);
        if (status != OG_SUCCESS) {
            CLOSE_VM_PTR_EX(res, vm_context);
            return OG_ERROR;
        }
    }
    CLOSE_VM_PTR(res, vm_context);
    return status;
}

void udt_release_rec(sql_stmt_t *stmt, variant_t *val)
{
    var_record_t *rec = &val->v_record;
    int32 code = 0;
    const char *message = NULL;

    if (IS_INVALID_MTRL_ROWID(rec->value)) {
        return;
    }
    if (udt_record_delete(stmt, val, OG_TRUE) != OG_SUCCESS) {
        cm_get_error(&code, &message, NULL);
        OG_LOG_DEBUG_ERR("record type release execute error[%d]:%s.", code, message);
    }
}

status_t plc_verify_record_field_assign(plv_record_attr_t *left_attr, rs_column_t *right, source_location_t loc)
{
    if (left_attr->type != UDT_SCALAR) {
        og_type_t datatype = (left_attr->type == UDT_COLLECTION) ?
            OG_TYPE_COLLECTION :
            (left_attr->type == UDT_RECORD ? OG_TYPE_RECORD : OG_TYPE_OBJECT);
        OG_SRC_ERROR_MISMATCH(loc, datatype, right->typmod.datatype);
        return OG_ERROR;
    }

    if (right->type == RS_COL_COLUMN) {
        if (!var_datatype_matched(left_attr->scalar_field->type_mode.datatype, right->typmod.datatype)) {
            OG_SRC_ERROR_MISMATCH(loc, left_attr->scalar_field->type_mode.datatype, right->typmod.datatype);
            return OG_ERROR;
        }
        return OG_SUCCESS;
    }

    // right->type is RS_COL_CALC now
    if (!var_datatype_matched(left_attr->scalar_field->type_mode.datatype, TREE_DATATYPE(right->expr))) {
        OG_SRC_ERROR_MISMATCH(loc, left_attr->scalar_field->type_mode.datatype, TREE_DATATYPE(right->expr));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}
