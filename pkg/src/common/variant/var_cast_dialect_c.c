/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "var_cast.h"

status_t var_convert_dialect_c(const nlsparams_t *nls, variant_t *var, og_type_t type, text_buf_t *buf)
{
    status_t status = OG_SUCCESS;

    OG_RETVALUE_IFTRUE((var->type == type), OG_SUCCESS);
    // NULL value, set type
    if (var->is_null) {
        var->type = type;
        return OG_SUCCESS;
    }

    switch (type) {
        case OG_TYPE_UINT32:
            status = var_as_uint32_dialect_c(var);
            break;

        case OG_TYPE_INTEGER:
            status = var_as_integer_dialect_c(var);
            break;

        case OG_TYPE_BOOLEAN:
            status = var_as_bool_dialect_c(var);
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER3:
        case OG_TYPE_DECIMAL:
            status = var_as_number_dialect_c(var);
            break;

        case OG_TYPE_NUMBER2:
            status = var_as_number2_dialect_c(var);
            break;

        case OG_TYPE_BIGINT:
            status = var_as_bigint_dialect_c(var);
            break;

        case OG_TYPE_UINT64:
            status = var_as_ubigint_dialect_c(var);
            break;

        case OG_TYPE_REAL:
            status = var_as_real_dialect_c(var);
            break;

        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
            status = var_as_string_dialect_c(nls, var, buf);
            break;

        case OG_TYPE_DATE:
            status = var_as_date_dialect_c(nls, var);
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            status = var_as_timestamp_dialect_c(nls, var);
            break;

        case OG_TYPE_TIMESTAMP_LTZ:
            status = var_as_timestamp_ltz_dialect_c(nls, var);
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            status = var_as_timestamp_tz_dialect_c(nls, var);
            break;

        case OG_TYPE_VARBINARY:
        case OG_TYPE_BINARY:
            status = var_as_binary_dialect_c(nls, var, buf);
            break;

        case OG_TYPE_RAW:
            status = var_as_raw_dialect_c(var, buf->str, buf->max_size);
            break;

        case OG_TYPE_INTERVAL_YM:
            status = var_as_yminterval_dialect_c(var);
            break;

        case OG_TYPE_INTERVAL_DS:
            status = var_as_dsinterval_dialect_c(var);
            break;

        case OG_TYPE_CLOB:
            status = var_as_clob_dialect_c(nls, var, buf);
            break;

        case OG_TYPE_BLOB:
            status = var_as_blob_dialect_c(var, buf);
            break;

        case OG_TYPE_IMAGE:
            status = var_as_image_dialect_c(nls, var, buf);
            break;

        case OG_TYPE_CURSOR:
        case OG_TYPE_COLUMN:
        case OG_TYPE_ARRAY:
        case OG_TYPE_BASE:
        default:
            return OG_ERROR;
    }
    
    OG_RETURN_IFERR(status);
    var->type = type;
    return status;
}

status_t var_to_round_bigint_dialect_c(const variant_t *var, round_mode_t rnd_mode, int64 *i64, int *overflow)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_RAW:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_to_round_ubigint_dialect_c(const variant_t *uvar, round_mode_t rnd_mode, uint64 *ui64, int *uoverflow)
{
    CM_POINTER(uvar);
    switch (uvar->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_RAW:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_to_round_int32_dialect_c(const variant_t *var, round_mode_t rnd_mode, int32 *i32)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BINARY:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_VARBINARY:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_to_round_uint32_dialect_c(const variant_t *var, round_mode_t rnd_mode, uint32 *u32)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BINARY:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_bool_dialect_c(variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_BINARY:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        default:
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t var_as_number_dialect_c(variant_t *var)
{
    return OG_ERROR;
}

status_t var_as_number2_dialect_c(variant_t *var)
{
    return OG_ERROR;
}

status_t var_as_real_dialect_c(variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_BINARY:
        case OG_TYPE_STRING:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARBINARY:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_string_dialect_c(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_RAW:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_ARRAY:
        default:
            OG_SET_ERROR_MISMATCH(OG_TYPE_STRING, var->type);
    }
    return OG_SUCCESS;
}

status_t var_as_date_dialect_c(const nlsparams_t *nls, variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_timestamp_dialect_c(const nlsparams_t *nls, variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_timestamp_ltz_dialect_c(const nlsparams_t *nls, variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_timestamp_tz_dialect_c(const nlsparams_t *nls, variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_binary_dialect_c(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_INTERVAL_YM:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_raw_dialect_c(variant_t *var, char *buf, uint32 buf_size)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_yminterval_dialect_c(variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_BINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_dsinterval_dialect_c(variant_t *var)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_BINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_blob_dialect_c(variant_t *var, text_buf_t *buf)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_image_dialect_c(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_RAW:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_INTERVAL_YM:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t var_as_clob_dialect_c(const nlsparams_t *nls, variant_t *var, text_buf_t *buf)
{
    CM_POINTER(var);
    switch (var->type) {
        case OG_TYPE_STRING:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BIGINT:
        case OG_TYPE_UINT64:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_RAW:
        default:
            return OG_ERROR;
    }
    return OG_SUCCESS;
}
