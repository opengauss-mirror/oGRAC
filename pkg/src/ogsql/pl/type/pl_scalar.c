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
 * pl_scalar.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/pl/type/pl_scalar.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_scalar.h"
#include "srv_instance.h"

static status_t udt_check_varlen_type_size(typmode_t *cmode, variant_t *pvar)
{
    uint32 value_len;
    switch (cmode->datatype) {
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            if (cmode->is_char) {
                OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&pvar->v_text, &value_len));
                if (pvar->v_text.len > OG_MAX_COLUMN_SIZE) {
                    OG_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
                    return OG_ERROR;
                }
            } else {
                value_len = pvar->v_text.len;
            }
            if (!pvar->is_null && value_len > cmode->size) {
                OG_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
                return OG_ERROR;
            }
            break;

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            if (!pvar->is_null && pvar->v_bin.size > cmode->size) {
                OG_THROW_ERROR(ERR_VALUE_ERROR, "binary buffer too small");
                return OG_ERROR;
            }
            break;

        default:
            break;
    }
    return OG_SUCCESS;
}

static status_t udt_adjust_scalar_by_type(typmode_t *cmode, variant_t *pvar)
{
    status_t status = OG_SUCCESS;
    switch (cmode->datatype) {
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
            status = cm_adjust_dec(&pvar->v_dec, cmode->precision, cmode->scale);
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            status = cm_adjust_timestamp(&pvar->v_tstamp, cmode->precision);
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            status = cm_adjust_timestamp_tz(&pvar->v_tstamp_tz, cmode->precision);
            break;

        case OG_TYPE_INTERVAL_DS:
            status = cm_adjust_dsinterval(&pvar->v_itvl_ds, (uint32)cmode->day_prec, (uint32)cmode->frac_prec);
            break;

        case OG_TYPE_INTERVAL_YM:
            status = cm_adjust_yminterval(&pvar->v_itvl_ym, (uint32)cmode->year_prec);
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            status = udt_check_varlen_type_size(cmode, pvar);
            break;

        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BIGINT:
        case OG_TYPE_REAL:
        case OG_TYPE_DATE:
            return OG_SUCCESS;

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            return OG_SUCCESS;

        default:
            OG_THROW_ERROR(ERR_VALUE_ERROR, "the data type of column is not supported");
            return OG_ERROR;
    }
    return status;
}

status_t udt_verify_scalar(sql_verifier_t *verf, typmode_t *cmode, expr_tree_t *tree)
{
    status_t status;
    variant_t *pvar = NULL;
    if (sql_is_skipped_expr(tree)) {
        return OG_SUCCESS;
    }

    if (!var_datatype_matched(cmode->datatype, TREE_DATATYPE(tree))) {
        OG_SRC_ERROR_MISMATCH(TREE_LOC(tree), cmode->datatype, TREE_DATATYPE(tree));
        return OG_ERROR;
    }

    if (OG_IS_LOB_TYPE(cmode->datatype) || !TREE_IS_CONST(tree)) {
        return OG_SUCCESS;
    }

    pvar = &tree->root->value;
    if (cmode->datatype != TREE_DATATYPE(tree)) {
        if (pvar->is_null) {
            return OG_SUCCESS;
        }
        OG_RETURN_IFERR(sql_convert_variant(verf->stmt, pvar, cmode->datatype));
        TREE_DATATYPE(tree) = cmode->datatype;
    }

    if ((!pvar->is_null) && OG_IS_VARLEN_TYPE(pvar->type)) {
        text_t text_bak = pvar->v_text;
        OG_RETURN_IFERR(sql_copy_text(verf->stmt->context, &text_bak, &pvar->v_text));
    }
    status = udt_adjust_scalar_by_type(cmode, pvar);
    if (status != OG_SUCCESS) {
        cm_set_error_loc(TREE_LOC(tree));
    }
    return status;
}

status_t udt_put_scalar_value(sql_stmt_t *stmt, variant_t *value, mtrl_rowid_t *row_id)
{
    dec2_t dec2;
    switch (value->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(int32), row_id);

        case OG_TYPE_BIGINT:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(int64), row_id);
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(date_t), row_id);

        case OG_TYPE_TIMESTAMP_LTZ:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(timestamp_ltz_t), row_id);

        case OG_TYPE_TIMESTAMP_TZ:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(timestamp_tz_t), row_id);

        case OG_TYPE_INTERVAL_DS:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(interval_ds_t), row_id);

        case OG_TYPE_INTERVAL_YM:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(interval_ym_t), row_id);

        case OG_TYPE_REAL:
        case OG_TYPE_FLOAT:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value, sizeof(double), row_id);

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            return vmctx_insert(GET_VM_CTX(stmt), value->v_text.str, value->v_text.len, row_id);

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL: {
            dec4_t d4;
            OG_RETURN_IFERR(cm_dec_8_to_4(&d4, VALUE_PTR(dec8_t, value)));
            uint32 original_size = cm_dec4_stor_sz(&d4);
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)&d4, original_size, row_id);
        }

        case OG_TYPE_NUMBER2:
            OG_RETURN_IFERR(cm_dec_8_to_2(&dec2, VALUE_PTR(dec8_t, value)));
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)GET_PAYLOAD(&dec2), cm_dec2_stor_sz(&dec2), row_id);

        case OG_TYPE_BLOB:
        case OG_TYPE_CLOB:
        case OG_TYPE_IMAGE:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value->v_lob.normal_lob.value.str,
                value->v_lob.normal_lob.size, row_id);

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
            return vmctx_insert(GET_VM_CTX(stmt), (const char *)value->v_bin.bytes, value->v_bin.size, row_id);
        default:
            OG_SET_ERROR_MISMATCH_EX(value->type);
            return OG_ERROR;
    }
}

status_t udt_get_varlen_databuf(typmode_t typmode, uint32 *max_len)
{
    switch (typmode.datatype) {
        case OG_TYPE_CHAR:
            if (!typmode.is_char) {
                *max_len = typmode.size;
                return OG_SUCCESS;
            }
            *max_len = typmode.size * MAX_BYTES2CHAR;
            *max_len = (*max_len > OG_MAX_COLUMN_SIZE) ? OG_MAX_COLUMN_SIZE : *max_len;
            return OG_SUCCESS;

        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            if (!typmode.is_char) {
                *max_len = typmode.size;
                return OG_SUCCESS;
            }
            *max_len = typmode.size * MAX_BYTES2CHAR;
            *max_len = (*max_len > OG_MAX_STRING_LEN) ? OG_MAX_STRING_LEN : *max_len;
            return OG_SUCCESS;

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_BLOB:
        case OG_TYPE_CLOB:
        case OG_TYPE_IMAGE:
            *max_len = typmode.size;
            return OG_SUCCESS;

        default:
            OG_THROW_ERROR(ERR_INVALID_DATA_TYPE, "expect varlen datatype");
            return OG_ERROR;
    }
}


status_t udt_check_char(variant_t *src, typmode_t type)
{
    uint32 value_len;
    uint32 max_len;

    if (type.is_char) {
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&src->v_text, &value_len));
    } else {
        value_len = src->v_text.len;
    }
    OG_RETURN_IFERR(udt_get_varlen_databuf(type, &max_len));
    if ((value_len > type.size) || (src->v_text.len > max_len)) {
        OG_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t udt_convert_char(variant_t *src, variant_t *dst, typmode_t type)
{
    uint32 max_len;
    if (src->is_null) {
        dst->is_null = src->is_null;
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(udt_check_char(src, type));
    OG_RETURN_IFERR(udt_get_varlen_databuf(type, &max_len));
    if (src->v_text.len != 0) {
        MEMS_RETURN_IFERR(memmove_s(dst->v_text.str, max_len, src->v_text.str, src->v_text.len));
    }
    dst->v_text.len = src->v_text.len;
    dst->is_null = src->is_null;
    return OG_SUCCESS;
}

status_t udt_get_lob_value(sql_stmt_t *stmt, variant_t *result)
{
    if (result->is_null) {
        result->type = (result->type == OG_TYPE_CLOB || result->type == OG_TYPE_IMAGE) ? OG_TYPE_STRING : OG_TYPE_RAW;
        return OG_SUCCESS;
    }

    switch (result->v_lob.type) {
        case OG_LOB_FROM_KERNEL:
            OG_RETURN_IFERR(sql_get_lob_value_from_knl(stmt, result));
            break;

        case OG_LOB_FROM_VMPOOL:
            OG_RETURN_IFERR(sql_get_lob_value_from_vm(stmt, result));
            break;

        case OG_LOB_FROM_NORMAL:
            OG_RETURN_IFERR(sql_get_lob_value_from_normal(stmt, result));
            break;

        default:
            OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do get lob value");
            return OG_ERROR;
    }

    if (g_instance->sql.enable_empty_string_null == OG_TRUE && result->v_text.len == 0 &&
        (OG_IS_STRING_TYPE(result->type) || OG_IS_BINARY_TYPE(result->type) || OG_IS_RAW_TYPE(result->type))) {
        result->is_null = OG_TRUE;
    }
    return OG_SUCCESS;
}

static status_t udt_scalar_copy_char(sql_stmt_t *stmt, typmode_t typmode, variant_t *src, variant_t *dst)
{
    uint32 value_len;
    uint32 max_len;
    int32 code;
    if (typmode.is_char) {
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&src->v_text, &value_len));
    } else {
        value_len = src->v_text.len;
    }
    OG_RETURN_IFERR(udt_get_varlen_databuf(typmode, &max_len));
    if ((value_len > typmode.size) || (src->v_text.len > max_len)) {
        OG_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_push(stmt, max_len, (void **)&dst->v_text.str));
    if (src->v_text.len != 0) {
        code = memmove_s(dst->v_text.str, max_len, src->v_text.str, src->v_text.len);
        if (SECUREC_UNLIKELY(code != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, code);
            OGSQL_POP(stmt);
            return OG_ERROR;
        }
    }
    uint32 blank_count = MIN((src->v_text.len + (typmode.size - value_len)), max_len) - src->v_text.len;
    if (blank_count > 0) {
        code = memset_s(dst->v_text.str + src->v_text.len, blank_count, ' ', blank_count);
        if (SECUREC_UNLIKELY(code != EOK)) {
            OG_THROW_ERROR(ERR_SYSTEM_CALL, code);
            OGSQL_POP(stmt);
            return OG_ERROR;
        }
    }
    dst->v_text.len = src->v_text.len + blank_count;
    return OG_SUCCESS;
}

void udt_typemode_default_init(typmode_t *type, variant_t *value)
{
    type->datatype = value->type;
    if (OG_IS_DATETIME_TYPE(value->type)) {
        type->precision = OG_MAX_DATETIME_PRECISION;
        type->scale = 0;
        type->size = sizeof(timestamp_t);
    } else if (OG_IS_NUMBER_TYPE(value->type)) {
        type->precision = 0;
        type->scale = 0;
        type->size = sizeof(dec8_t);
    } else if (OG_IS_VARLEN_TYPE(value->type)) {
        type->precision = 0;
        type->scale = 0;
        type->size = udt_outparam_default_size(value->type);
    } else {
        type->precision = 0;
        type->scale = 0;
        type->size = var_get_size(value);
    }
}

status_t udt_copy_scalar_element(sql_stmt_t *stmt, typmode_t dst_typmode, variant_t *right, variant_t *result)
{
    if (dst_typmode.datatype == OG_TYPE_UNKNOWN) {
        udt_typemode_default_init(&dst_typmode, right);
    }
    result->type = dst_typmode.datatype;
    result->is_null = right->is_null;
    if (result->is_null) {
        return OG_SUCCESS;
    }

    if (OG_IS_LOB_TYPE((og_type_t)right->type)) {
        OG_RETURN_IFERR(udt_get_lob_value(stmt, right));
        // Lob types' is_null may be OG_FALSE at the beginning and becomes OG_TRUE after get_lob_value.
        result->is_null = right->is_null;
        if (result->is_null) {
            return OG_SUCCESS;
        }
    }

    if (right->type != result->type) {
        if (dst_typmode.is_array == OG_TRUE) {
            OG_RETURN_IFERR(sql_convert_to_array(stmt, right, &dst_typmode, OG_FALSE));
        } else {
            OG_RETURN_IFERR(sql_convert_variant(stmt, right, result->type));
        }
    }

    if (result->type == OG_TYPE_CHAR) {
        OG_RETURN_IFERR(udt_scalar_copy_char(stmt, dst_typmode, right, result));
    } else {
        OG_RETURN_IFERR(udt_adjust_scalar_by_type(&dst_typmode, right));
        sql_keep_stack_variant(stmt, right);
        var_copy(right, result);
    }
    return OG_SUCCESS;
}

status_t udt_make_scalar_elemt(sql_stmt_t *stmt, typmode_t type_mode, variant_t *value, mtrl_rowid_t *row_id,
    int16 *type)
{
    status_t status = OG_ERROR;
    variant_t dst;

    OGSQL_SAVE_STACK(stmt);
    do {
        OG_BREAK_IF_ERROR(udt_copy_scalar_element(stmt, type_mode, value, &dst));
        if (dst.is_null) {
            status = OG_SUCCESS;
            break;
        }
        if (type != NULL && (*type != dst.type)) {
            *type = dst.type;
        }
        OG_BREAK_IF_ERROR(udt_put_scalar_value(stmt, &dst, row_id));
        status = OG_SUCCESS;
    } while (0);
    OGSQL_RESTORE_STACK(stmt);
    return status;
}

status_t udt_clone_scalar(sql_stmt_t *stmt, mtrl_rowid_t copy_from, mtrl_rowid_t *copy_to)
{
    status_t status;
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    OPEN_VM_PTR(&copy_from, vm_ctx);
    /* NO NEED TO CONSIDER THE  BITMAP EX SIZE, COLUMN COUNT = 1 */
    status = vmctx_insert(vm_ctx, (const char *)d_ptr, d_chunk->requested_size, copy_to);
    CLOSE_VM_PTR(&copy_from, vm_ctx);

    return status;
}

static status_t udt_read_lob_scalar_value(sql_stmt_t *stmt, const char *d_ptr, pvm_chunk_t d_chunk, variant_t *value)
{
    VALUE_PTR(var_lob_t, value)->type = OG_LOB_FROM_NORMAL;
    VALUE_PTR(var_lob_t, value)->normal_lob.size = d_chunk->requested_size;
    VALUE_PTR(var_lob_t, value)->normal_lob.type = OG_LOB_FROM_NORMAL;
    VALUE_PTR(var_lob_t, value)->normal_lob.value.len = d_chunk->requested_size;

    if (d_chunk->requested_size == 0) {
        VALUE_PTR(var_lob_t, value)->normal_lob.value.str = NULL;
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(
        sql_push(stmt, d_chunk->requested_size, (void **)&(VALUE_PTR(var_lob_t, value)->normal_lob.value.str)));
    errno_t ret = memcpy_sp(VALUE_PTR(var_lob_t, value)->normal_lob.value.str, d_chunk->requested_size, d_ptr,
        d_chunk->requested_size);
    if (ret != EOK) {
        OGSQL_POP(stmt);
        OG_THROW_ERROR(ERR_RESET_MEMORY, "extending variate");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t udt_read_varlen_scalar_value(sql_stmt_t *stmt, const char *d_ptr, pvm_chunk_t d_chunk, variant_t *value)
{
    if (d_chunk->requested_size == 0) {
        value->v_text.str = NULL;
        value->v_text.len = 0;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, d_chunk->requested_size, (void **)&(VALUE_PTR(text_t, value)->str)));

    errno_t ret = memcpy_sp(VALUE_PTR(text_t, value)->str, d_chunk->requested_size, d_ptr, d_chunk->requested_size);
    if (ret != EOK) {
        OGSQL_POP(stmt);
        OG_THROW_ERROR(ERR_RESET_MEMORY, "extending variate");
        return OG_ERROR;
    }
    VALUE_PTR(text_t, value)->len = d_chunk->requested_size;
    return OG_SUCCESS;
}

static status_t udt_read_scalar_value_core(sql_stmt_t *stmt, char *d_ptr, pvm_chunk_t d_chunk, variant_t *value)
{
    switch ((og_type_t)value->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
            VALUE(int32, value) = *(int32 *)d_ptr;
            break;

        case OG_TYPE_BIGINT:
            VALUE(int64, value) = *(int64 *)d_ptr;
            break;
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            VALUE(date_t, value) = *(date_t *)d_ptr;
            break;

        case OG_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_ltz_t, value) = *(timestamp_ltz_t *)d_ptr;
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, value) = *(timestamp_tz_t *)d_ptr;
            break;

        case OG_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, value) = *(interval_ds_t *)d_ptr;
            break;

        case OG_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, value) = *(interval_ym_t *)d_ptr;
            break;

        case OG_TYPE_REAL:
        case OG_TYPE_FLOAT:
            VALUE(double, value) = *(double *)d_ptr;
            break;
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
            cm_dec_4_to_8(VALUE_PTR(dec8_t, value), (dec4_t *)d_ptr, d_chunk->requested_size);
            break;

        case OG_TYPE_NUMBER2:
            OG_RETURN_IFERR(cm_dec_2_to_8(VALUE_PTR(dec8_t, value), (const payload_t *)d_ptr, d_chunk->requested_size));
            break;

        case OG_TYPE_BLOB:
        case OG_TYPE_CLOB:
        case OG_TYPE_IMAGE:
            OG_RETURN_IFERR(udt_read_lob_scalar_value(stmt, d_ptr, d_chunk, value));
            break;

        default:
            OG_RETURN_IFERR(udt_read_varlen_scalar_value(stmt, d_ptr, d_chunk, value));
            break;
    }
    return OG_SUCCESS;
}

status_t udt_read_scalar_value(sql_stmt_t *stmt, mtrl_rowid_t *row_id, variant_t *value)
{
    pvm_context_t vm_ctx = GET_VM_CTX(stmt);
    status_t status;

    OPEN_VM_PTR(row_id, vm_ctx);
    status = udt_read_scalar_value_core(stmt, d_ptr, d_chunk, value);
    CLOSE_VM_PTR(row_id, vm_ctx);
    value->is_null = OG_FALSE;
    return status;
}
