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
 * ogsql_jsonb_utils.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/json/ogsql_jsonb_utils.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_defs.h"
#include "cm_error.h"
#include "cm_decimal.h"
#include "cm_lex.h"
#include "ogsql_func.h"

#include "ogsql_json_utils.h"
#include "ogsql_jsonb_utils.h"
#include "ogsql_jsonb_table.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 ==========================================================================================
 load jsonb binary data into a continuous memory
 ==========================================================================================
*/
static status_t jsonb_flatten_lob_knl(json_assist_t *json_ass, variant_t *var)
{
    knl_handle_t locator = (knl_handle_t)var->v_lob.knl_lob.bytes;
    unsigned char *lob_buf = NULL;
    uint32 lob_size = knl_lob_size(locator);
    uint32 remain_size = lob_size;
    uint32 read_size = 0;
    uint32 offset = 0;

    JSON_CHECK_MAX_SIZE(lob_size);
    if (lob_size == 0) {
        var->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(JSON_ALLOC(json_ass, lob_size, (void **)&lob_buf));
    while (remain_size > 0) {
        OG_RETURN_IFERR(
            knl_read_lob(json_ass->stmt->session, locator, offset, lob_buf + offset, remain_size, &read_size, NULL));
        remain_size -= read_size;
        offset += read_size;
    }

    var->v_bin.bytes = lob_buf;
    var->v_bin.size = lob_size;
    var->v_bin.is_hex_const = OG_FALSE;
    var->type = OG_TYPE_BINARY;

    return OG_SUCCESS;
}

static status_t jsonb_flatten_lob_vm(json_assist_t *json_ass, variant_t *var)
{
    sql_stmt_t *stmt = json_ass->stmt;
    unsigned char *lob_buf = NULL;
    uint32 lob_size = var->v_lob.vm_lob.size;
    uint32 remain_size = lob_size;
    uint32 offset = 0;
    uint32 vmid;
    errno_t ret;

    JSON_CHECK_MAX_SIZE(lob_size);
    if (lob_size == 0) {
        var->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(JSON_ALLOC(json_ass, lob_size, (void **)&lob_buf));

    vmid = var->v_lob.vm_lob.entry_vmid;
    while (remain_size > 0) {
        uint32 copy_size;
        vm_page_t *page = NULL;

        OG_RETURN_IFERR(vm_open(stmt->session, stmt->mtrl.pool, vmid, &page));

        copy_size = (remain_size > OG_VMEM_PAGE_SIZE) ? OG_VMEM_PAGE_SIZE : remain_size;
        ret = memcpy_s(lob_buf + offset, copy_size, page->data, copy_size);
        if (ret != EOK) {
            vm_close(stmt->session, stmt->mtrl.pool, vmid, VM_ENQUE_HEAD);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return OG_ERROR;
        }
        remain_size -= copy_size;
        offset += copy_size;

        vm_close(stmt->session, stmt->mtrl.pool, vmid, VM_ENQUE_HEAD);
        vmid = vm_get_ctrl(stmt->mtrl.pool, vmid)->sort_next;
    }

    var->v_bin.bytes = lob_buf;
    var->v_bin.size = lob_size;
    var->v_bin.is_hex_const = OG_FALSE;
    var->type = OG_TYPE_BINARY;

    return OG_SUCCESS;
}

static status_t jsonb_flatten_lob_normal(json_assist_t *json_ass, variant_t *var)
{
    uint32 lob_size = var->v_lob.normal_lob.value.len;

    if (lob_size == 0) {
        var->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    var->v_bin.bytes = (unsigned char *)var->v_lob.normal_lob.value.str;
    var->v_bin.size = var->v_lob.normal_lob.value.len;
    var->v_bin.is_hex_const = OG_FALSE;
    var->type = OG_TYPE_BINARY;

    return OG_SUCCESS;
}

static status_t jsonb_flatten_lob(json_assist_t *json_ass, variant_t *var)
{
    switch (var->v_lob.type) {
        case OG_LOB_FROM_KERNEL:
            return jsonb_flatten_lob_knl(json_ass, var);
        case OG_LOB_FROM_VMPOOL:
            return jsonb_flatten_lob_vm(json_ass, var);
        case OG_LOB_FROM_NORMAL:
            return jsonb_flatten_lob_normal(json_ass, var);
        default:
            OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do json flatten lob");
            return OG_ERROR;
    }
}

/* @result: set to null if arg null
 * @var   : var to eval arg
 * 		  : CAUTION!!!: var->v_bin keeps flattened continuous memory
 * this func is used in load jsonb binary from value-expr into a continuous memory.
 */
static status_t sql_exec_jsonb_func_arg(json_assist_t *json_ass, expr_tree_t *arg, variant_t *var, variant_t *result)
{
    sql_stmt_t *stmt = json_ass->stmt;

    CM_POINTER(arg);
    OGSQL_SAVE_STACK(stmt);
    result->is_null = OG_FALSE;
    SQL_EXEC_FUNC_ARG_EX3(arg, var, result, stmt);
    sql_keep_stack_variant(stmt, var);

    if (OG_IS_BLOB_TYPE(var->type)) {
        if (jsonb_flatten_lob(json_ass, var) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
    } else if (!OG_IS_BINARY_TYPE(var->type) && !OG_IS_RAW_TYPE(var->type)) {
        cm_set_error_loc(arg->loc);
        OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "Input to JSONB generation function has unsupported data type.");
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    if (var->is_null || var->v_bin.size == 0) {
        var->is_null = OG_TRUE;
        result->is_null = OG_TRUE;
        result->type = OG_TYPE_STRING;
    }
    return OG_SUCCESS;
}

// @result: set to null if arg null
// @var   : var(any type) to var(varchar type)
//        : CAUTION!!!: var->v_text keeps flattened continuous memory
// this func is used in inserting data into jsonb column, convert clob or string value into a continuous memory.
status_t sql_exec_flatten_to_binary(json_assist_t *json_ass, variant_t *var)
{
    sql_stmt_t *stmt = json_ass->stmt;

    OGSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, var);

    if (OG_IS_BLOB_TYPE(var->type)) {
        if (jsonb_flatten_lob(json_ass, var) != OG_SUCCESS) {
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
    } else if (!OG_IS_BINARY_TYPE(var->type) && !OG_IS_RAW_TYPE(var->type)) {
        OG_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "Input to JSON generation function has unsupported data type.");
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/*
 ==========================================================================================
 convert json tree to jsonb serialized binary.
 ==========================================================================================
*/
status_t jsonb_push_jv_object(json_assist_write_t *json_ass_w, json_value_t *jv);
status_t jsonb_push_jv_array(json_assist_write_t *json_ass_w, json_value_t *jv);

static uint32 jsonb_get_jv_entry(uint8 *base_ptr, uint32 i, uint8 head_bytes, uint8 entry_bytes)
{
    uint8 *entry_ptr = base_ptr + JSONB_GET_HEADER_LEN(head_bytes) + JSONB_GET_TYPE_LEN_BY_PTR(base_ptr, head_bytes) +
        JSONB_GET_ENTRY_LEN(entry_bytes) * i;
    uint32 entry_data = 0;
    switch (entry_bytes) {
        case JSONB_ENTRY_BYTES_1:
            return (uint32)(*entry_ptr);

        case JSONB_ENTRY_BYTES_2:
            return (uint32)(*((uint16 *)entry_ptr));

        case JSONB_ENTRY_BYTES_3:
            entry_data = entry_data | ((*((uint16 *)entry_ptr)) << JSONB_OP_BITS_8) | (*(entry_ptr + JSONB_OP_BYTES_2));
            return entry_data;

        case JSONB_ENTRY_BYTES_4:
            return *((uint32 *)entry_ptr);

        default:
            CM_ASSERT(OG_FALSE); /* nerver reach here. */
            break;
    }
    /* nerver reach here. */
    return 0;
}

static JBType jsonb_get_jv_type(uint8 *base_ptr, uint32 i, uint8 head_bytes)
{
    uint32 real_i = i % JSONB_GET_HEADER_ELEM_COUNT(base_ptr, head_bytes);
    uint8 *type_loc = base_ptr + JSONB_GET_HEADER_LEN(head_bytes) + (real_i / JBT_NUM_EACH_UINT8);
    if (real_i % JBT_NUM_EACH_UINT8 == 0) {
        return (((*type_loc) & JBT_HIGN_4BIT_MASK) >> JBT_MASK_LEN);
    } else {
        return (*type_loc) & JBT_LOW_4BIT_MASK;
    }
}

static void jsonb_push_jv_type(json_assist_write_t *json_ass_w, uint8 *base_ptr, JBType type, uint32 i)
{
    if (JSONB_GET_HEADER_ELEM_COUNT(base_ptr, json_ass_w->head_bytes) == 0) {
        OG_THROW_ERROR(ERR_ZERO_DIVIDE, "invalid dividend");
        knl_panic(0);
    } else {
        uint32 real_i = i % JSONB_GET_HEADER_ELEM_COUNT(base_ptr, json_ass_w->head_bytes);
        uint8 *type_loc = base_ptr + JSONB_GET_HEADER_LEN(json_ass_w->head_bytes) + (real_i / JBT_NUM_EACH_UINT8);
        if (real_i % JBT_NUM_EACH_UINT8 == 0) {
            *type_loc = ((type) << JBT_MASK_LEN) | ((*type_loc) & 0x0F);
        } else {
            *type_loc = ((*type_loc) & 0xF0) | (type);
        }
    }
}

static void jsonb_push_jv_entry(json_assist_write_t *json_ass_w, uint8 *base_ptr, uint32 entry_offset, uint32 i)
{
    uint8 *entry_ptr = base_ptr + JSONB_GET_HEADER_LEN(json_ass_w->head_bytes) +
        JSONB_GET_TYPE_LEN_BY_PTR(base_ptr, json_ass_w->head_bytes) + JSONB_GET_ENTRY_LEN(json_ass_w->entry_bytes) * i;
    uint32 data = entry_offset;
    switch (json_ass_w->entry_bytes) {
        case JSONB_ENTRY_BYTES_1:
            *entry_ptr = (uint8)data;
            break;
        case JSONB_ENTRY_BYTES_2:
            *((uint16 *)entry_ptr) = (uint16)data;
            break;
        case JSONB_ENTRY_BYTES_3:
            *(entry_ptr + JSONB_OP_BYTES_2) = (uint8)(data & 0x000000FF);
            *((uint16 *)entry_ptr) = (uint16)((data & 0x00FFFF00) >> JSONB_OP_BITS_8);
            break;
        case JSONB_ENTRY_BYTES_4:
            *((uint32 *)entry_ptr) = data;
            break;
        default:
            CM_ASSERT(OG_FALSE); /* nerver reach here. */
            break;
    }
}

static void jsonb_push_jv_header(json_assist_write_t *json_ass_w, uint8 *base_ptr, uint32 nNodes, bool32 isObject)
{
    uint32 header = nNodes;
    switch (json_ass_w->head_bytes) {
        case JSONB_HEAD_BYTES_1:
            header = header | (isObject ? JSONB_HEAD_1B_ISOBJECT : JSONB_HEAD_1B_ISARRAY);
            *base_ptr = (uint8)header;
            break;
        case JSONB_HEAD_BYTES_2:
            header = header | (isObject ? JSONB_HEAD_2B_ISOBJECT : JSONB_HEAD_2B_ISARRAY);
            *((uint16 *)base_ptr) = (uint16)header;
            break;
        case JSONB_HEAD_BYTES_3:
            header = header | (isObject ? JSONB_HEAD_3B_ISOBJECT : JSONB_HEAD_3B_ISARRAY);
            *(base_ptr + JSONB_OP_BYTES_2) = (uint8)(header & 0x000000FF);
            *((uint16 *)base_ptr) = (uint16)((header & 0x00FFFF00) >> JSONB_OP_BITS_8);
            break;
        case JSONB_HEAD_BYTES_4:
            header = header | (isObject ? JSONB_HEAD_4B_ISOBJECT : JSONB_HEAD_4B_ISARRAY);
            *((uint32 *)base_ptr) = header;
            break;
        default:
            CM_ASSERT(OG_FALSE); /* nerver reach here. */
            break;
    }

    json_ass_w->push_offset += JSONB_GET_HEADER_LEN(json_ass_w->head_bytes);
}

static status_t jsonb_push_jv_real_data(json_assist_write_t *json_ass_w, text_t *data)
{
    // copy the data
    MEMS_RETURN_IFERR(memcpy_s((void *)(json_ass_w->lob_buf + json_ass_w->push_offset), json_ass_w->max_size,
        data->str, data->len));
    json_ass_w->push_offset += data->len;

    return OG_SUCCESS;
}

static status_t jsonb_push_jv_value(json_assist_write_t *json_ass_w, json_value_t *jv, uint32 base_offset, uint32 i, bool32
    is_value)
{
    uint8 *base_ptr = json_ass_w->lob_buf + base_offset;

    // fill the entry, it is stored the offset in the jsonb binary data
    jsonb_push_jv_entry(json_ass_w, base_ptr, (json_ass_w->push_offset - base_offset), i);

    switch (jv->type) {
        case JSON_VAL_NULL:
            jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_NULL, i);

            // no need to fill any data
            break;

        case JSON_VAL_BOOL:
            if (jv->boolean) {
                jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_BOOL_TRUE, i);
            } else {
                jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_BOOL_FALSE, i);
            }

            // no need to fill any data
            break;

        case JSON_VAL_STRING:
            if (is_value) { // for object element, no need to push type for key, its type must be JBT_STRING
                jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_STRING, i);
            }

            OG_RETURN_IFERR(jsonb_push_jv_real_data(json_ass_w, &jv->string));
            break;

        case JSON_VAL_NUMBER:
            jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_NUMBER, i);

            OG_RETURN_IFERR(jsonb_push_jv_real_data(json_ass_w, &jv->number));
            break;

        case JSON_VAL_ARRAY:
            jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_BOX, i);

            OG_RETURN_IFERR(jsonb_push_jv_array(json_ass_w, jv));
            break;

        case JSON_VAL_OBJECT:
            jsonb_push_jv_type(json_ass_w, base_ptr, (JBType)JBT_BOX, i);

            OG_RETURN_IFERR(jsonb_push_jv_object(json_ass_w, jv));
            break;

        default:
            OG_THROW_ERROR(ERR_JSON_UNKNOWN_TYPE, (int)jv->type, "do json deparse");
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t jsonb_push_jv_array(json_assist_write_t *json_ass_w, json_value_t *jv)
{
    uint32 nNodes = JSON_ARRAY_SIZE(jv);
    uint32 base_offset = json_ass_w->push_offset;
    uint8 *base_ptr = json_ass_w->lob_buf + base_offset;

    // 1. push hearders
    jsonb_push_jv_header(json_ass_w, base_ptr, nNodes, OG_FALSE);

    // because the type length is known, so skip this length directly.
    json_ass_w->push_offset += JSONB_GET_TYPE_LEN(nNodes);

    // because the entry length is known, so skip this length directly.
    json_ass_w->push_offset += JSONB_ARRAY_GET_ENTRY_LEN(nNodes, json_ass_w->entry_bytes);

    for (uint32 i = 0; i < nNodes; i++) {
        // 2. fill the entry of this node and push its data
        OG_RETURN_IFERR(jsonb_push_jv_value(json_ass_w, JSON_ARRAY_ITEM(jv, i), base_offset, i, OG_TRUE));
    }

    return OG_SUCCESS;
}

status_t jsonb_push_jv_object(json_assist_write_t *json_ass_w, json_value_t *jv)
{
    uint32 nNodes = JSON_OBJECT_SIZE(jv);
    uint32 base_offset = json_ass_w->push_offset;
    uint8 *base_ptr = json_ass_w->lob_buf + base_offset;

    // 1. push hearder
    jsonb_push_jv_header(json_ass_w, base_ptr, nNodes, OG_TRUE);

    // because the type length is known, so skip this length directly.
    json_ass_w->push_offset += JSONB_GET_TYPE_LEN(nNodes);

    // because the entry length is known, so skip this length directly.
    json_ass_w->push_offset += JSONB_OBJECT_GET_ENTRY_LEN(nNodes, json_ass_w->entry_bytes);

    // must keys first
    for (uint32 i = 0; i < nNodes; i++) {
        // 2.1. fill the entry of this node and push its key data
        OG_RETURN_IFERR(jsonb_push_jv_value(json_ass_w, &JSON_OBJECT_ITEM(jv, i)->key, base_offset, i, OG_FALSE));
    }
    // and then values laster.
    for (uint32 i = 0; i < nNodes; i++) {
        // 2.2. fill the entry of this node and push its value data
        OG_RETURN_IFERR(jsonb_push_jv_value(json_ass_w, &JSON_OBJECT_ITEM(jv, i)->val, base_offset, i + nNodes,
            OG_TRUE));
    }

    return OG_SUCCESS;
}

static status_t jsonb_push_jv(json_assist_write_t *json_ass_w, json_value_t *jv)
{
    switch (jv->type) {
        case JSON_VAL_ARRAY:
            OG_RETURN_IFERR(jsonb_push_jv_array(json_ass_w, jv));
            break;

        case JSON_VAL_OBJECT:
            OG_RETURN_IFERR(jsonb_push_jv_object(json_ass_w, jv));
            break;

        case JSON_VAL_NULL:
        case JSON_VAL_BOOL:
        case JSON_VAL_STRING:
        case JSON_VAL_NUMBER:
            OG_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, (int)jv->type, "jsonb value must be non-scaler value.");
            return OG_ERROR;

        default:
            OG_THROW_ERROR(ERR_JSON_UNKNOWN_TYPE, (int)jv->type, "do json deparse");
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

// when finished to push jsonvalue into a continuous memory, we should flush this continuous memory into vm.
static status_t jsonb_flush_jv_into_vm(json_assist_write_t *json_ass_w)
{
    uint8 ver = JSONB_VERSION;
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)&json_ass_w->real_size, sizeof(uint32)));
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)&ver, sizeof(uint8)));
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)&json_ass_w->head_entry_bytes, sizeof(uint8)));
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)json_ass_w->lob_buf, json_ass_w->real_size));

    return OG_SUCCESS;
}

static status_t jsonb_write_to_lob_vm(json_assist_write_t *json_ass_w, char *bytes, uint32 len)
{
    sql_stmt_t *stmt = json_ass_w->stmt;
    json_vlob_t *ja_vlob = (json_vlob_t *)json_ass_w->arg;
    uint32 remain_size = len;
    id_list_t *vm_list = sql_get_exec_lob_list(json_ass_w->stmt);
    uint32 copy_size;

    while (remain_size > 0) {
        copy_size = 0;

        JSON_EXTEND_LOB_VMEM_IF_NEEDED(ja_vlob, stmt);
        copy_size = MIN((uint32)ja_vlob->last_free_size, remain_size);
        MEMS_RETURN_IFERR(memcpy_s(ja_vlob->last_page->data + OG_VMEM_PAGE_SIZE - ja_vlob->last_free_size, copy_size,
            bytes + len - remain_size, copy_size));

        ja_vlob->last_free_size -= copy_size;
        remain_size -= copy_size;
        ja_vlob->vlob.size += copy_size;
    }

    if (ja_vlob->last_free_size == 0) {
        vm_close(json_ass_w->stmt->session, json_ass_w->stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
        ja_vlob->last_page = NULL;
    }

    return OG_SUCCESS;
}

static status_t jsonb_calculate_max_size(json_assist_write_t *json_ass_w, json_analyse_t *janalys)
{
    // Estimated Length, it is quitely enough.
    uint64 baseLen = janalys->string_number_len +
        JSONB_GET_HEADER_LEN(json_ass_w->head_bytes) * (janalys->array_count + janalys->object_count) +
        JSONB_GET_TYPE_LEN(janalys->array_elems_count + janalys->object_elems_count + janalys->odd_elems_count);

    uint32 entry_count = janalys->array_elems_count + janalys->object_elems_count * JSONB_OBJ_ENTRY_COUNT_TIMES;

    if ((baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_1) * entry_count) <=
        JBE_OFFSET_1B_MAX_LEN) {
        json_ass_w->entry_bytes = JSONB_ENTRY_BYTES_1;
        json_ass_w->max_size = baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_1) * entry_count;
    } else if ((baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_2) * entry_count) <=
        JBE_OFFSET_2B_MAX_LEN) {
        json_ass_w->entry_bytes = JSONB_ENTRY_BYTES_2;
        json_ass_w->max_size = baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_2) * entry_count;
    } else if ((baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_3) * entry_count) <=
        JBE_OFFSET_3B_MAX_LEN) {
        json_ass_w->entry_bytes = JSONB_ENTRY_BYTES_3;
        json_ass_w->max_size = baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_3) * entry_count;
    } else if ((baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_4) * entry_count) <=
        JBE_OFFSET_4B_MAX_LEN) {
        json_ass_w->entry_bytes = JSONB_ENTRY_BYTES_4;
        json_ass_w->max_size = baseLen + JSONB_GET_ENTRY_LEN(JSONB_ENTRY_BYTES_4) * entry_count;
    } else {
        // set error.
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "address space of jsonb exceeds the maximum of 4G.");
        return OG_ERROR;
    }

    json_ass_w->max_size += (4 - (json_ass_w->max_size % 4)); // 4 bytes aligin
    return OG_SUCCESS;
}

static status_t jsonb_calculate_head_bytes(json_assist_write_t *json_ass_w, uint32 max_elems_count)
{
    if (max_elems_count <= JSONB_HEAD_1B_MAX_NUM) {
        json_ass_w->head_bytes = JSONB_HEAD_BYTES_1;
    } else if (max_elems_count <= JSONB_HEAD_2B_MAX_NUM) {
        json_ass_w->head_bytes = JSONB_HEAD_BYTES_2;
    } else if (max_elems_count <= JSONB_HEAD_3B_MAX_NUM) {
        json_ass_w->head_bytes = JSONB_HEAD_BYTES_3;
    } else if (max_elems_count <= JSONB_HEAD_4B_MAX_NUM) {
        json_ass_w->head_bytes = JSONB_HEAD_BYTES_4;
    } else {
        // set error.
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t jsonb_calculate_values(json_analyse_t *janalys, json_assist_write_t *json_ass_w)
{
    OG_RETURN_IFERR(jsonb_calculate_head_bytes(json_ass_w, janalys->max_elems_count));
    json_ass_w->real_size = 0;
    OG_RETURN_IFERR(jsonb_calculate_max_size(json_ass_w, janalys));

    return OG_SUCCESS;
}

/* convert json_value_t into jsonb, (convert json tree to serialized jsonb binary), return blob type. */
status_t get_jsonb_from_jsonvalue(json_assist_t *json_ass, json_value_t *jv, variant_t *result, bool32 write_vm)
{
    json_vlob_t arg;
    json_assist_write_t json_ass_w;
    id_list_t *vm_list = sql_get_exec_lob_list(json_ass->stmt);
    uint8 *lob_buf = NULL;

    // 1. fill some statistics information
    OG_RETURN_IFERR(jsonb_calculate_values(json_ass->janalys, &json_ass_w));
    json_ass->head_entry_bytes = json_ass_w.head_entry_bytes;

    // malloc a continuous memory
    OG_RETURN_IFERR(JSON_ALLOC(json_ass, json_ass_w.max_size, (void **)&lob_buf));
    MEMS_RETURN_IFERR(memset_sp((void *)lob_buf, json_ass_w.max_size, 0, json_ass_w.max_size));

    // init json_ass_w
    json_ass_w.lob_buf = lob_buf;
    if (write_vm) {
        JSON_INIT_VLOB(&arg);
        JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, jsonb_write_to_lob_vm, &arg, OG_FALSE);
    }

    // 2. then push jsonvalue into this continuous memory
    OG_RETURN_IFERR(jsonb_push_jv(&json_ass_w, jv));

    if (write_vm) {
        // 3. copy this continuous memory to VM lob
        OG_RETURN_IFERR(jsonb_flush_jv_into_vm(&json_ass_w));

        // avoid last page not closed
        if (arg.last_free_size != 0) {
            vm_close(json_ass->stmt->session, json_ass->stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
        }

        // finally, we get our jsonb value.
        result->type = OG_TYPE_BLOB;
        result->v_lob.type = OG_LOB_FROM_VMPOOL;
        result->v_lob.vm_lob = arg.vlob;
    } else {
        // finally, we get our jsonb value.
        result->type = OG_TYPE_BINARY;
        result->v_bin.bytes = lob_buf;
        result->v_bin.size = json_ass_w.real_size;

        json_ass->max_len = json_ass_w.real_size;
        json_ass->original_ptr_loc = (uint64)lob_buf;
    }

    return OG_SUCCESS;
}

/* Although not guaranteed to be all formatted correctly, it is guaranteed to access memory correctly. */
static status_t jsonb_simple_verify(jsonb_value_t *jb, uint32 real_size)
{
    uint8 head_bytes;
    uint8 entry_bytes;
    if (real_size < JSONB_MIN_LENTH || jb->length != (real_size - JSONB_BEGIN_LENTH)) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "length is not correct.");
        return OG_ERROR;
    }
    if (jb->version > JSONB_VERSION || jb->version == 0) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "version is not correct.");
        return OG_ERROR;
    }

    head_bytes = JsonbHeadBytesNum(jb->head_entry_bytes);
    if (head_bytes >= JSONB_HEAD_BYTES_MAX || head_bytes == 0) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "head bytes number is not correct.");
        return OG_ERROR;
    }

    entry_bytes = JsonbEntryBytesNum(jb->head_entry_bytes);
    if (entry_bytes >= JSONB_ENTRY_BYTES_MAX || entry_bytes == 0) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "entry bytes number is not correct.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t jsonb_parse(json_assist_t *json_ass, variant_t *var_expr, jsonb_value_t **jb)
{
    *jb = (jsonb_value_t *)var_expr->v_bin.bytes;
    OG_RETURN_IFERR(jsonb_simple_verify((*jb), var_expr->v_bin.size));

    json_ass->version = (*jb)->version;
    json_ass->head_entry_bytes = (*jb)->head_entry_bytes;

    // for Securely access to memory
    json_ass->max_len = (*jb)->length;
    json_ass->original_ptr_loc = (uint64)(&((*jb)->data));

    return OG_SUCCESS;
}

/*
 ==========================================================================================
 retrieve jsonb data.
 ==========================================================================================
*/
status_t jsonb_path_extract_find(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path, uint32 level,
    jsonb_results_t *jb_result_array);

static status_t jsonb_array_get_elem(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, uint32 i, jsonb_result_elem_t *node)
{
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes); /* only (nNodes gt 0) can reach here. */
    if (SECUREC_UNLIKELY(!JSONB_ACCESS_MEM_SECURELY(jar,
        ((uint64)(jre->data)) + JSONB_ARRAY_GET_HEADERS_LEN(nNodes, jar->head_bytes, jar->entry_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid headers of jsonb format.");
        return OG_ERROR;
    }

    uint32 offset = jsonb_get_jv_entry(jre->data, i, jar->head_bytes, jar->entry_bytes);
    if (SECUREC_UNLIKELY(!JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + offset))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    }

    node->type = jsonb_get_jv_type(jre->data, i, jar->head_bytes);
    node->is_scaler = JBT_ISSCALER(node->type);

    // the offset is non-reduced.
    uint32 end = ((i == (nNodes - 1)) ? (jre->length) :
                                        (jsonb_get_jv_entry(jre->data, i + 1, jar->head_bytes, jar->entry_bytes)));
    if (SECUREC_UNLIKELY(end < offset)) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    } else if (SECUREC_UNLIKELY((end == offset) && !JBT_MEANS_NODATA(node->type) && !JBT_ISSTRING(node->type))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    } else if (SECUREC_UNLIKELY(JBT_MEANS_NODATA(node->type) && (end != offset))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    } else if (SECUREC_UNLIKELY(!JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + end))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    }

    node->length = end - offset;
    node->data = jre->data + offset;

    return OG_SUCCESS;
}

static status_t jsonb_object_get_elem(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, uint32 i, jsonb_result_elem_t *node,
    bool32 isKey)
{
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes); /* only (nNodes gt 0) can reach here. */
    if (SECUREC_UNLIKELY(!JSONB_ACCESS_MEM_SECURELY(jar,
        ((uint64)(jre->data)) + JSONB_OBJECT_GET_HEADERS_LEN(nNodes, jar->head_bytes, jar->entry_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid headers of jsonb format.");
        return OG_ERROR;
    }

    uint32 offset = jsonb_get_jv_entry(jre->data, i, jar->head_bytes, jar->entry_bytes);
    if (SECUREC_UNLIKELY(!JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + offset))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    }

    node->type = isKey ? JBT_STRING : jsonb_get_jv_type(jre->data, i, jar->head_bytes);
    node->is_scaler = JBT_ISSCALER(node->type);

    // the offset is non-reduced.
    uint32 end = ((i == (JSONB_OBJ_ENTRY_COUNT_TIMES * nNodes - 1)) ?
        (jre->length) :
        (jsonb_get_jv_entry(jre->data, i + 1, jar->head_bytes, jar->entry_bytes)));
    if (SECUREC_UNLIKELY(end < offset)) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    } else if (SECUREC_UNLIKELY((end == offset) && !JBT_MEANS_NODATA(node->type) && !JBT_ISSTRING(node->type))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    } else if (SECUREC_UNLIKELY(JBT_MEANS_NODATA(node->type) && (end != offset))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    } else if (SECUREC_UNLIKELY(!JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + end))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid entry offset of jsonb format.");
        return OG_ERROR;
    }

    node->length = end - offset;
    node->data = jre->data + offset;

    return OG_SUCCESS;
}

// match indexes for step which json type  if array
static status_t jsonb_path_extract_find_indexs_array(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path,
    uint32 level, jsonb_results_t *jb_result_array)
{
    uint32 loop = 0;
    uint32 from_index = 0;
    uint32 to_index = 0;
    uint32 nestloop = 0;
    jsonb_result_elem_t node;

    json_path_step_t *step = &path->steps[level];

    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar->head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    if (step->index_pairs_count > 0) {
        for (; loop < step->index_pairs_count; loop++) {
            from_index = step->index_pairs_list[loop].from_index;
            to_index = step->index_pairs_list[loop].to_index;

            nestloop = (nestloop <= from_index) ? from_index : nestloop;
            if (nestloop >= nNodes) {
                break;
            }

            for (; (nestloop < nNodes) && (nestloop <= to_index); nestloop++) {
                OG_RETURN_IFERR(jsonb_array_get_elem(jar, jre, nestloop, &node));
                OG_RETURN_IFERR(jsonb_path_extract_find(jar, &node, path, level + 1, jb_result_array));
            }
        }
    } else {
        // when reach the end, and it is array, it will return this array when it has no any index or * flag ,
        // XXX at the end node
        if (((level + 1) == JSON_PATH_SIZE(path)) && ((step->index_flag & JSON_PATH_INDEX_IS_STAR) == 0)) {
            jsonb_result_elem_t *new_jb = NULL;
            OG_RETURN_IFERR(cm_galist_new(jb_result_array->results, sizeof(jsonb_result_elem_t), (pointer_t *)&new_jb));
            *new_jb = *jre;
            return OG_SUCCESS;
        }

        // XX or XX[*]
        for (; loop < nNodes; loop++) {
            OG_RETURN_IFERR(jsonb_array_get_elem(jar, jre, loop, &node));
            OG_RETURN_IFERR(jsonb_path_extract_find(jar, &node, path, level + 1, jb_result_array));
        }
    }

    return OG_SUCCESS;
}

static status_t jsonb_path_extract_find_indexs(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path,
    uint32 level, jsonb_results_t *jb_result_array)
{
    json_path_step_t *step = &path->steps[level];

    if (jre->is_scaler) {
        if ((step->index_pairs_count > 0) && (step->index_pairs_list[0].from_index != 0)) {
            return OG_SUCCESS;
        }

        if (JSON_PATH_SIZE(path) > (level + 1)) {
            return OG_SUCCESS; // scaler value don't have children
        }

        // stop at the scaler value , $ , $[*], $[0,...]
        jsonb_result_elem_t *new_jb = NULL;
        OG_RETURN_IFERR(cm_galist_new(jb_result_array->results, sizeof(jsonb_result_elem_t), (pointer_t *)&new_jb));
        *new_jb = *jre;
    } else if (JSONB_HEAD_IS_OBJECT(jre->root, jar->head_bytes)) {
        if ((step->index_pairs_count > 0) && (step->index_pairs_list[0].from_index != 0)) {
            return OG_SUCCESS;
        }

        // XX.    , XX[*].   , XX[0,...].  jump to the next deep level.
        OG_RETURN_IFERR(jsonb_path_extract_find(jar, jre, path, level + 1, jb_result_array));
    } else if (JSONB_HEAD_IS_ARRAY(jre->root, jar->head_bytes)) {
        // in the same level.
        OG_RETURN_IFERR(jsonb_path_extract_find_indexs_array(jar, jre, path, level, jb_result_array));
    } else {
        // set error
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t jsonb_path_extract_binary_search_range(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path,
    uint32 level, jsonb_results_t *jb_result_array)
{
    jsonb_result_elem_t key;
    jsonb_result_elem_t val;
    text_t tmp1;
    text_t tmp2;
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    json_path_step_t *step = &path->steps[level]; /* get this step */
    tmp2.len = step->keyname_length;
    tmp2.str = step->keyname;

    for (int32 loop = jar->mid; loop >= 0; loop--) {
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, (uint32)loop, &key, OG_TRUE));
        tmp1.len = key.length;
        tmp1.str = (char *)key.data;

        if (cm_compare_text(&tmp1, &tmp2) != 0) {
            break;
        }
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, nNodes + loop, &val, OG_FALSE));
        OG_RETURN_IFERR(jsonb_path_extract_find_indexs(jar, &val, path, level, jb_result_array));
    }

    for (uint32 loop = jar->mid + 1; loop < nNodes; loop++) {
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, loop, &key, OG_TRUE));
        tmp1.len = key.length;
        tmp1.str = (char *)key.data;

        if (cm_compare_text(&tmp1, &tmp2) != 0) {
            break;
        }
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, nNodes + loop, &val, OG_FALSE));
        OG_RETURN_IFERR(jsonb_path_extract_find_indexs(jar, &val, path, level, jb_result_array));
    }

    return OG_SUCCESS;
}

static status_t jsonb_path_extract_binary_search(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path,
    uint32 level, jsonb_results_t *jb_result_array)
{
    jsonb_result_elem_t key;
    text_t tmp1;
    text_t tmp2;
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);
    uint32 left = 0;
    uint32 right = nNodes - 1;
    uint32 mid = 0;
    bool32 found = OG_FALSE;

    json_path_step_t *step = &path->steps[level]; /* get this step */
    tmp2.len = step->keyname_length;
    tmp2.str = step->keyname;

    OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, left, &key, OG_TRUE));
    tmp1.len = key.length;
    tmp1.str = (char *)key.data;
    if (cm_compare_text(&tmp1, &tmp2) > 0) { /* beyond the range */
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, right, &key, OG_TRUE));
    tmp1.len = key.length;
    tmp1.str = (char *)key.data;
    if (cm_compare_text(&tmp1, &tmp2) < 0) { /* beyond the range */
        return OG_SUCCESS;
    }

    while (left <= right) {
        mid = (left + right) / 2;
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, mid, &key, OG_TRUE));
        tmp1.len = key.length;
        tmp1.str = (char *)key.data;

        int32 cmp = cm_compare_text(&tmp1, &tmp2);
        if (cmp > 0) {
            if (mid == 0) {
                break;
            }
            right = mid - 1;
        } else if (cmp < 0) {
            if (mid == 0xFFFFFFFF) {
                break;
            }
            left = mid + 1;
        } else {
            found = OG_TRUE;
            break;
        }
    }

    if (!found) {
        return OG_SUCCESS;
    }

    /* allow reapted k-v pairs. */
    jar->mid = mid;
    return jsonb_path_extract_binary_search_range(jar, jre, path, level, jb_result_array);
}

static status_t jsonb_path_extract_object_foreach(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path,
    uint32 level, jsonb_results_t *jb_result_array)
{
    jsonb_result_elem_t key;
    jsonb_result_elem_t val;
    text_t tmp1;
    text_t tmp2;
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    json_path_step_t *step = &path->steps[level]; /* get this step */
    tmp2.len = step->keyname_length;
    tmp2.str = step->keyname;

    for (uint32 loop = 0; loop < nNodes; loop++) {
        if ((step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR) == 0) {
            OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, loop, &key, OG_TRUE));
            tmp1.len = key.length;
            tmp1.str = (char *)key.data;

            if (cm_compare_text(&tmp1, &tmp2) != 0) {
                continue; // if not match name
            }
        }

        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, nNodes + loop, &val, OG_FALSE));
        OG_RETURN_IFERR(jsonb_path_extract_find_indexs(jar, &val, path, level, jb_result_array));
    }

    return OG_SUCCESS;
}

static status_t jsonb_path_extract_find_object(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path,
    uint32 level, jsonb_results_t *jb_result_array)
{
    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar->head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }

    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);
    if (nNodes == 0) {
        return OG_SUCCESS;
    }

    json_path_step_t *step = &path->steps[level]; /* get this step */

    // char * can match any key-value pair
    if ((step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR) == 1) {
        return jsonb_path_extract_object_foreach(jar, jre, path, level, jb_result_array);
    }

    /* if step keyname is not *, it must be a valid string. */
    if (step->keyname_length == 0) {
        return OG_SUCCESS;
    }

    if (nNodes < JSONB_OBJECT_MIN_BINARY_SEARCH) {
        /* for each item to match */
        return jsonb_path_extract_object_foreach(jar, jre, path, level, jb_result_array);
    }

    /* binary search the mid idx, and then to match */
    return jsonb_path_extract_binary_search(jar, jre, path, level, jb_result_array);
}

status_t jsonb_path_extract_find(jsonb_assist_read_t *jar, jsonb_result_elem_t *jre, json_path_t *path, uint32 level,
    jsonb_results_t *jb_result_array)
{
    // reach the end of path, it may be any type
    if (level >= JSON_PATH_SIZE(path)) {
        jsonb_result_elem_t *new_jb = NULL;
        OG_RETURN_IFERR(cm_galist_new(jb_result_array->results, sizeof(jsonb_result_elem_t), (pointer_t *)&new_jb));
        *new_jb = *jre;
        return OG_SUCCESS;
    }

    json_path_step_t *step = &path->steps[level];

    // internal node must be object or array!
    if (jre->is_scaler) {
        return OG_SUCCESS;
    }

    // if it is array, no keyname, one *, just find in index pairs.
    if (JSONB_HEAD_IS_ARRAY(jre->root, jar->head_bytes)) {
        if (!step->keyname_exists && (step->keyname_length == 0 || (step->keyname_flag & JSON_PATH_KEYNAME_IS_STAR))) {
            OG_RETURN_IFERR(jsonb_path_extract_find_indexs_array(jar, jre, path, level, jb_result_array));
        }
        return OG_SUCCESS;
    }

    // if it is object, foreach every key-value pairs.
    /* binary search in object. */
    return jsonb_path_extract_find_object(jar, jre, path, level, jb_result_array);
}

static status_t jsonb_transform_values(jsonb_value_t *jb, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre)
{
    // init the jsonb_assist_read_t, set the version, head_bytes and entry_bytes
    // global information for this total jsonb data.
    jar->version = jb->version;
    jar->head_entry_bytes = jb->head_entry_bytes;
    jar->max_len = jb->length;
    jar->original_ptr_loc = (uint64)&jb->data;

    // init jsonb_result_elem_t
    jre->is_scaler = OG_FALSE;
    jre->type = JBT_BOX;
    jre->length = jb->length;
    jre->root = &jb->data;

    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar->head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t jsonb_path_extract(jsonb_value_t *jb, json_path_t *path, jsonb_results_t *jb_result_array)
{
    CM_POINTER2(path, jb);

    uint32 headlevel = 0;

    jsonb_assist_read_t jar;
    jsonb_result_elem_t jre;

    // init the jsonb_assist_read_t, set the version, head_bytes and entry_bytes
    // init jsonb_result_elem_t
    OG_RETURN_IFERR(jsonb_transform_values(jb, &jar, &jre));

    /* get results, maybe we can get more than one node in the end. */
    return jsonb_path_extract_find_indexs(&jar, &jre, path, headlevel, jb_result_array);
}

/*
 ==========================================================================================
 convert jsonb binary to visible text.
 ==========================================================================================
*/
#define JSONB_CHAR_LEN 1
#define JSONB_NULL_LEN 4
#define JSONB_TRUE_LEN 4
#define JSONB_FALSE_LEN 5

status_t jsonb_deparse_value(json_assist_write_t *json_ass_w, jsonb_result_elem_t *jre, uint32 *level);
static status_t jsonb_deparse_string(json_assist_write_t *json_ass_w, jsonb_result_elem_t *jre)
{
    if (!json_ass_w->is_scalar) {
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "\"", JSONB_CHAR_LEN));
    }

    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)jre->data, jre->length));

    if (!json_ass_w->is_scalar) {
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "\"", JSONB_CHAR_LEN));
    }

    return OG_SUCCESS;
}

static status_t jsonb_deparse_number(json_assist_write_t *json_ass_w, jsonb_result_elem_t *jre)
{
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)jre->data, jre->length));

    return OG_SUCCESS;
}

static status_t jsonb_deparse_null(json_assist_write_t *json_ass_w)
{
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "null", JSONB_NULL_LEN));

    return OG_SUCCESS;
}

static status_t jsonb_deparse_bool(json_assist_write_t *json_ass_w, bool32 val)
{
    if (val) {
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "true", JSONB_TRUE_LEN));
    } else {
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "false", JSONB_FALSE_LEN));
    }

    return OG_SUCCESS;
}

static status_t jsonb_deparse_array(json_assist_write_t *json_ass_w, jsonb_result_elem_t *jre, uint32 *level)
{
    jsonb_result_elem_t node;
    jsonb_assist_read_t jar;

    jar.version = json_ass_w->version;
    jar.head_entry_bytes = json_ass_w->head_entry_bytes;
    jar.max_len = json_ass_w->max_len;
    jar.original_ptr_loc = json_ass_w->original_ptr_loc;

    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY((&jar), ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar.head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, json_ass_w->head_bytes);

    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "[", JSONB_CHAR_LEN));

    for (uint32 i = 0; i < nNodes; i++) {
        OG_RETURN_IFERR(jsonb_array_get_elem(&jar, jre, i, &node));
        OG_RETURN_IFERR(jsonb_deparse_value(json_ass_w, &node, level));

        // not last elem
        if (i != (uint32)(nNodes - 1)) {
            OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, ",", JSONB_CHAR_LEN));
        }
    }

    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "]", JSONB_CHAR_LEN));

    return OG_SUCCESS;
}

static status_t jsonb_deparse_object(json_assist_write_t *json_ass_w, jsonb_result_elem_t *jre, uint32 *level)
{
    jsonb_result_elem_t key;
    jsonb_result_elem_t val;
    jsonb_assist_read_t jar;

    jar.version = json_ass_w->version;
    jar.head_entry_bytes = json_ass_w->head_entry_bytes;
    jar.max_len = json_ass_w->max_len;
    jar.original_ptr_loc = json_ass_w->original_ptr_loc;

    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY((&jar), ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar.head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, json_ass_w->head_bytes);

    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "{", JSONB_CHAR_LEN));

    for (uint32 i = 0; i < nNodes; i++) {
        OG_RETURN_IFERR(jsonb_object_get_elem(&jar, jre, i, &key, OG_TRUE));
        OG_RETURN_IFERR(jsonb_deparse_value(json_ass_w, &key, level));

        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, ":", JSONB_CHAR_LEN));

        OG_RETURN_IFERR(jsonb_object_get_elem(&jar, jre, nNodes + i, &val, OG_FALSE));
        OG_RETURN_IFERR(jsonb_deparse_value(json_ass_w, &val, level));

        // not last pair
        if (i != (uint32)(nNodes - 1)) {
            OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, ",", JSONB_CHAR_LEN));
        }
    }

    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "}", JSONB_CHAR_LEN));

    return OG_SUCCESS;
}


status_t jsonb_deparse_value(json_assist_write_t *json_ass_w, jsonb_result_elem_t *jre, uint32 *level)
{
    status_t status;

    switch (jre->type) {
        case JBT_NULL:
            return jsonb_deparse_null(json_ass_w);

        case JBT_BOOL_TRUE:
            return jsonb_deparse_bool(json_ass_w, OG_TRUE);

        case JBT_BOOL_FALSE:
            return jsonb_deparse_bool(json_ass_w, OG_FALSE);

        case JBT_STRING:
            return jsonb_deparse_string(json_ass_w, jre);

        case JBT_NUMBER:
            return jsonb_deparse_number(json_ass_w, jre);

        case JBT_BOX:
            TO_UINT32_OVERFLOW_CHECK((uint64)(*level) + 1, uint64);
            ++(*level);
            if (JSONB_HEAD_IS_ARRAY(jre->data, json_ass_w->head_bytes)) {
                status = jsonb_deparse_array(json_ass_w, jre, level);
            } else {
                status = jsonb_deparse_object(json_ass_w, jre, level);
            }
            --(*level);
            return status;

        default:
            OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "the type of element is wrong.");
            return OG_ERROR;
    }

    return status;
}

static status_t jsonb_deparse(json_assist_write_t *json_ass_w, jsonb_results_t *jb_result_array)
{
    uint32 level = 0;

    if (json_ass_w->jsonb_result_is_list) {
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "[", JSONB_CHAR_LEN));
    }

    // if jsonb_result_is_list is false, the list size must be 1.
    for (uint32 i = 0; i < JSONB_RESULT_ELEM_COUNT(jb_result_array); i++) {
        OG_RETURN_IFERR(jsonb_deparse_value(json_ass_w, JSONB_RESULT_GET_ITEM(jb_result_array, i), &level));

        // not last elem, write ,
        if (i != (uint32)(JSONB_RESULT_ELEM_COUNT(jb_result_array) - 1)) {
            OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, ",", JSONB_CHAR_LEN));
        }
    }

    if (json_ass_w->jsonb_result_is_list) {
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, "]", JSONB_CHAR_LEN));
    }

    return OG_SUCCESS;
}

static status_t jsonb_deparse_to_string_core(json_assist_t *json_ass, jsonb_results_t *jb_result_array, variant_t *result,
    bool32 is_scalar)
{
    json_assist_write_t json_ass_w;
    text_buf_t arg;
    char *buf = NULL;
    jsonb_result_elem_t *jb_result = JSONB_RESULT_GET_ITEM(jb_result_array, 0);

    if (is_scalar && ((json_ass->jsonb_result_is_list) || (!jb_result->is_scaler))) {
        OG_THROW_ERROR_EX(ERR_JSON_SYNTAX_ERROR, "unexpected non-scalar type");
        return OG_ERROR;
    }

    // init the memory
    OG_RETURN_IFERR(JSON_ALLOC(json_ass, JSON_MAX_STRING_LEN, (void **)&buf));
    CM_INIT_TEXTBUF(&arg, JSON_MAX_STRING_LEN, buf);

    // init the json_ass_w
    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, is_scalar ? json_write_to_textbuf_unescaped :
        json_write_to_textbuf, &arg,
        is_scalar);
    json_ass_w.jsonb_result_is_list = json_ass->jsonb_result_is_list;
    json_ass_w.version = json_ass->version;
    json_ass_w.head_entry_bytes = json_ass->head_entry_bytes;
    json_ass_w.max_len = json_ass->max_len;
    json_ass_w.original_ptr_loc = json_ass->original_ptr_loc;

    // deparse the jsonb value into clob/varchar.
    OG_RETURN_IFERR(jsonb_deparse(&json_ass_w, jb_result_array));

    result->type = OG_TYPE_STRING;
    result->is_null = OG_FALSE;
    result->v_text = arg.value;

    return OG_SUCCESS;
}

static status_t jsonb_deparse_to_string_scalar(json_assist_t *json_ass, jsonb_results_t *jb_result_array, variant_t *result)
{
    return jsonb_deparse_to_string_core(json_ass, jb_result_array, result, OG_TRUE);
}

static status_t jsonb_deparse_to_string(json_assist_t *json_ass, jsonb_results_t *jb_result_array, variant_t *result)
{
    return jsonb_deparse_to_string_core(json_ass, jb_result_array, result, OG_FALSE);
}

static status_t jsonb_deparse_to_clob_normal_core(json_assist_t *json_ass, jsonb_results_t *jb_result_array,
    variant_t *result, bool32 is_scalar)
{
    json_assist_write_t json_ass_w;
    text_buf_t arg;
    char *buf = NULL;
    jsonb_result_elem_t *jb_result = JSONB_RESULT_GET_ITEM(jb_result_array, 0);

    if (is_scalar && ((json_ass->jsonb_result_is_list) || (!jb_result->is_scaler))) {
        OG_THROW_ERROR_EX(ERR_JSON_SYNTAX_ERROR, "unexpected non-scalar type");
        return OG_ERROR;
    }

    // init the memory
    OG_RETURN_IFERR(JSON_ALLOC(json_ass, OG_MAX_EXEC_LOB_SIZE, (void **)&buf));
    CM_INIT_TEXTBUF(&arg, OG_MAX_EXEC_LOB_SIZE, buf);

    // init the json_ass_w
    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, is_scalar ? json_write_to_textbuf_unescaped :
        json_write_to_textbuf, &arg,
        is_scalar);
    json_ass_w.jsonb_result_is_list = json_ass->jsonb_result_is_list;
    json_ass_w.version = json_ass->version;
    json_ass_w.head_entry_bytes = json_ass->head_entry_bytes;
    json_ass_w.max_len = json_ass->max_len;
    json_ass_w.original_ptr_loc = json_ass->original_ptr_loc;

    // deparse the jsonb value into clob/varchar.
    OG_RETURN_IFERR(jsonb_deparse(&json_ass_w, jb_result_array));

    result->type = OG_TYPE_CLOB;
    result->v_lob.type = OG_LOB_FROM_NORMAL;
    result->v_lob.normal_lob.type = OG_LOB_FROM_NORMAL;
    result->v_lob.normal_lob.size = arg.value.len;
    result->v_lob.normal_lob.value = arg.value;

    return OG_SUCCESS;
}

static status_t jsonb_deparse_to_clob_normal_scalar(json_assist_t *json_ass, jsonb_results_t *jb_result_array, variant_t
    *result)
{
    return jsonb_deparse_to_clob_normal_core(json_ass, jb_result_array, result, OG_TRUE);
}

static status_t jsonb_deparse_to_clob_vm(json_assist_t *json_ass, jsonb_results_t *jb_result_array, variant_t *result)
{
    json_vlob_t arg;
    json_assist_write_t json_ass_w;
    id_list_t *vm_list = sql_get_exec_lob_list(json_ass->stmt);

    JSON_INIT_VLOB(&arg);
    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, jsonb_write_to_lob_vm, &arg, OG_FALSE);
    json_ass_w.jsonb_result_is_list = json_ass->jsonb_result_is_list;
    json_ass_w.version = json_ass->version;
    json_ass_w.head_entry_bytes = json_ass->head_entry_bytes;
    json_ass_w.max_len = json_ass->max_len;
    json_ass_w.original_ptr_loc = json_ass->original_ptr_loc;

    OG_RETURN_IFERR(jsonb_deparse(&json_ass_w, jb_result_array));

    // avoid last page not closed
    if (arg.last_free_size != 0) {
        vm_close(json_ass->stmt->session, json_ass->stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
    }

    result->type = OG_TYPE_CLOB;
    result->v_lob.type = OG_LOB_FROM_VMPOOL;
    result->v_lob.vm_lob = arg.vlob;

    return OG_SUCCESS;
}

static status_t jsonb_recombine_core(json_assist_write_t *json_ass_w, jsonb_results_t *jb_result_array)
{
    jsonb_result_elem_t *jre = NULL;
    uint32 header_offset = json_ass_w->total_size - json_ass_w->pure_data_size;

    // write jsob head data
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)&json_ass_w->total_size, sizeof(uint32)));
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)&json_ass_w->version, sizeof(uint8)));

    // keep Consistent with original data, just for convenience
    OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)&json_ass_w->head_entry_bytes, sizeof(uint8)));

    // write jsob data, if jsonb_result_is_list is true, we need insert a header.
    if (json_ass_w->jsonb_result_is_list) {
        jsonb_push_jv_header(json_ass_w, json_ass_w->lob_buf, JSONB_RESULT_ELEM_COUNT(jb_result_array), OG_FALSE);

        for (uint32 i = 0; i < JSONB_RESULT_ELEM_COUNT(jb_result_array); i++) {
            jre = JSONB_RESULT_GET_ITEM(jb_result_array, i);

            // push (head, type, entry) of each elem
            jsonb_push_jv_type(json_ass_w, json_ass_w->lob_buf, jre->type, i);
            jsonb_push_jv_entry(json_ass_w, json_ass_w->lob_buf, header_offset, i);
            header_offset += jre->length;
        }

        /* write the header */
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)json_ass_w->lob_buf, (json_ass_w->total_size -
            json_ass_w->pure_data_size)));
    }

    // write real data
    for (uint32 i = 0; i < JSONB_RESULT_ELEM_COUNT(jb_result_array); i++) {
        jre = JSONB_RESULT_GET_ITEM(jb_result_array, i);
        OG_RETURN_IFERR(json_ass_w->json_write(json_ass_w, (char *)jre->data, jre->length));
    }

    return OG_SUCCESS;
}

static status_t jsonb_recombine_analyse(json_assist_write_t *json_ass_w, jsonb_results_t *jb_result_array)
{
    jsonb_result_elem_t *jb_result = NULL;

    json_ass_w->pure_data_size = 0;
    for (uint32 i = 0; i < JSONB_RESULT_ELEM_COUNT(jb_result_array); i++) {
        jb_result = JSONB_RESULT_GET_ITEM(jb_result_array, i);
        json_ass_w->pure_data_size += jb_result->length;
    }

    json_ass_w->total_size = json_ass_w->pure_data_size;
    if (json_ass_w->jsonb_result_is_list) {
        json_ass_w->total_size +=
            JSONB_ARRAY_GET_HEADERS_LEN(JSONB_RESULT_ELEM_COUNT(jb_result_array), json_ass_w->head_bytes,
                json_ass_w->entry_bytes);
    }
    return OG_SUCCESS;
}

static status_t jsonb_deparse_to_blob_vm(json_assist_t *json_ass, jsonb_results_t *jb_result_array, variant_t *result)
{
    json_vlob_t arg;
    json_assist_write_t json_ass_w;
    id_list_t *vm_list = sql_get_exec_lob_list(json_ass->stmt);

    /* init json_ass_w */
    JSON_INIT_VLOB(&arg);
    JSON_INIT_ASSIST_WRITE(&json_ass_w, json_ass->stmt, jsonb_write_to_lob_vm, &arg, OG_FALSE);
    json_ass_w.jsonb_result_is_list = json_ass->jsonb_result_is_list;
    json_ass_w.version = json_ass->version;
    json_ass_w.head_entry_bytes = json_ass->head_entry_bytes;

    /* beigin to analyse the jb_result_array */
    OG_RETURN_IFERR(jsonb_recombine_analyse(&json_ass_w, jb_result_array)); /* get real_size and total_size */
    if (json_ass->jsonb_result_is_list) {
        uint32 len = json_ass_w.total_size - json_ass_w.pure_data_size;
        OG_RETURN_IFERR(JSON_ALLOC(json_ass, len, (void **)&json_ass_w.lob_buf));
        MEMS_RETURN_IFERR(memset_sp((void *)json_ass_w.lob_buf, len, 0, len));
    }

    OG_RETURN_IFERR(jsonb_recombine_core(&json_ass_w, jb_result_array)); /* recombine many jsonb values. */

    // avoid last page not closed
    if (arg.last_free_size != 0) {
        vm_close(json_ass->stmt->session, json_ass->stmt->mtrl.pool, vm_list->last, VM_ENQUE_TAIL);
    }

    result->type = OG_TYPE_BLOB;
    result->v_lob.type = OG_LOB_FROM_VMPOOL;
    result->v_lob.vm_lob = arg.vlob;

    return OG_SUCCESS;
}

static status_t jsonb_handle_returning_clause(json_assist_t *json_ass, jsonb_results_t *jb_result_array,
    json_func_attr_t json_func_attr, variant_t *result, bool32 scalar_retrieve)
{
    json_func_att_id_t return_type = JSON_FUNC_ATT_GET_RETURNING(json_func_attr.ids);
    jsonb_result_elem_t *jb = JSONB_RESULT_GET_ITEM(jb_result_array, 0);

    result->is_null = OG_FALSE;
    switch (return_type) {
        case JSON_FUNC_ATT_RETURNING_VARCHAR2:
            if (scalar_retrieve) {
                OG_RETURN_IFERR(jsonb_deparse_to_string_scalar(json_ass, jb_result_array, result));
            } else {
                OG_RETURN_IFERR(jsonb_deparse_to_string(json_ass, jb_result_array, result));
            }
            if (result->v_text.len > json_func_attr.return_size) {
                OG_THROW_ERROR(ERR_JSON_OUTPUT_TOO_LARGE);
                return OG_ERROR;
            }
            break;

        case JSON_FUNC_ATT_RETURNING_CLOB:
            if (scalar_retrieve && (JBT_ISNULL(jb->type) || JBT_ISBOOL(jb->type) ||
                ((JBT_ISSTRING(jb->type) || JBT_ISNUMERIC(jb->type)) && jb->length <= OG_MAX_EXEC_LOB_SIZE))) {
                OG_RETURN_IFERR(jsonb_deparse_to_clob_normal_scalar(json_ass, jb_result_array, result));
            } else {
                OG_RETURN_IFERR(jsonb_deparse_to_clob_vm(json_ass, jb_result_array, result));
            }
            break;

        case JSON_FUNC_ATT_RETURNING_JSONB:
            // to be here, the result must be non-scaler.
            OG_RETURN_IFERR(jsonb_deparse_to_blob_vm(json_ass, jb_result_array, result));
            break;

        default:
            OG_THROW_ERROR(ERR_JSON_INVLID_CLAUSE, "RETURNING", "unexpected returning type");
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t jsonb_handle_wrapper_clause(json_assist_t *json_ass, json_func_attr_t attr, jsonb_results_t *jb_result_array,
    variant_t *result)
{
    jsonb_result_elem_t *jb_result = JSONB_RESULT_GET_ITEM(jb_result_array, 0);
    switch (JSON_FUNC_ATT_GET_WRAPPER(attr.ids)) {
        case JSON_FUNC_ATT_WITHOUT_WRAPPER:
            if (JSONB_RESULT_ELEM_COUNT(jb_result_array) > 1) {
                OG_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE",
                    "multiple");
                JSON_RETURN_IF_ON_ERROR_HANDLED(OG_ERROR, json_ass, attr, result);
            }
            if (jb_result->is_scaler) {
                OG_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE",
                    "scalar");
                JSON_RETURN_IF_ON_ERROR_HANDLED(OG_ERROR, json_ass, attr, result);
            }
            json_ass->jsonb_result_is_list = OG_FALSE; // the result should be the only one elem in the list
            break;

        case JSON_FUNC_ATT_WITH_WRAPPER:
            json_ass->jsonb_result_is_list = OG_TRUE; // the result should be all the list
            break;

        case JSON_FUNC_ATT_WITH_CON_WRAPPER:
            if ((JSONB_RESULT_ELEM_COUNT(jb_result_array) == 1) && (!jb_result->is_scaler)) {
                json_ass->jsonb_result_is_list = OG_FALSE; // the result should be the only one elem in the list
                break;
            }
            json_ass->jsonb_result_is_list = OG_TRUE; // the result should be all the list
            break;

        default:
            // Never reached here.
            CM_ASSERT(0);
            break;
    }

    // 5. handle returning clause
    JSON_RETURN_IF_ON_ERROR_HANDLED(jsonb_handle_returning_clause(json_ass, jb_result_array, attr, result, OG_FALSE),
        json_ass,
        attr, result);
    return OG_SUCCESS;
}

/*
 ==========================================================================================
 user query data func interfaces.
 ==========================================================================================
*/
static status_t sql_get_jsonb_query_result(json_assist_t *json_ass, variant_t *result, json_func_attr_t attr,
    jsonb_results_t *jb_result_array)
{
    JSON_RETURN_IF_ON_EMPTY_HANDLED(JSONB_RESULT_ELEM_COUNT(jb_result_array) > 0, json_ass, attr, result);
    return jsonb_handle_wrapper_clause(json_ass, attr, jb_result_array, result);
}

static status_t sql_get_jsonb_exists_result(variant_t *result, jsonb_results_t *jb_result_array)
{
    result->is_null = OG_FALSE;
    result->type = OG_TYPE_BOOLEAN;
    result->v_bool = (JSONB_RESULT_ELEM_COUNT(jb_result_array) == 0) ? OG_FALSE : OG_TRUE;

    return OG_SUCCESS;
}

static status_t sql_get_jsonb_value_result(json_assist_t *json_ass, variant_t *result, json_func_attr_t attr,
    jsonb_results_t *jb_result_array)
{
    JSON_RETURN_IF_ON_EMPTY_HANDLED(JSONB_RESULT_ELEM_COUNT(jb_result_array) > 0, json_ass, attr, result);
    if (JSONB_RESULT_ELEM_COUNT(jb_result_array) > 1) {
        OG_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE", "multiple");
        JSON_RETURN_IF_ON_ERROR_HANDLED(OG_ERROR, json_ass, attr, result);
    }

    jsonb_result_elem_t *jb_result = JSONB_RESULT_GET_ITEM(jb_result_array, 0);
    if (!jb_result->is_scaler) {
        OG_THROW_ERROR(ERR_JSON_VALUE_MISMATCHED, json_ass->is_json_retrieve ? "JSON_VALUE" : "JSONB_VALUE", "non-scalar");
        JSON_RETURN_IF_ON_ERROR_HANDLED(OG_ERROR, json_ass, attr, result);
    }

    // treat JSON_VAL_NULL as NULL
    if (JBT_ISNULL(jb_result->type)) {
        result->is_null = OG_TRUE;
        result->type = OG_TYPE_STRING;
        return OG_SUCCESS;
    }

    // handle returning clause
    json_ass->jsonb_result_is_list = OG_FALSE;
    JSON_RETURN_IF_ON_ERROR_HANDLED(jsonb_handle_returning_clause(json_ass, jb_result_array, attr, result, OG_TRUE),
        json_ass, attr,
        result);

    return OG_SUCCESS;
}

static status_t jsonb_func_get_result(json_assist_t *json_ass, expr_node_t *func, variant_t *result, json_path_t *path,
    variant_t *var_expr)
{
    // 3. parse json text to json_value_t, in jsonb, we can directly get the values, no need to parse it.
    jsonb_value_t *jb = NULL;
    json_ass->is_json_retrieve = OG_FALSE;
    OG_RETURN_IFERR(jsonb_parse(json_ass, var_expr, &jb));

    // 4. extract scalar from json_value_t according to path
    jsonb_results_t jb_result_array;
    OG_RETURN_IFERR(json_item_array_init(json_ass, &jb_result_array.results, JSON_MEM_LARGE_POOL));
    OG_RETURN_IFERR(jsonb_path_extract(jb, path, &jb_result_array));

    // 5. output the result
    switch (func->value.v_func.func_id) {
        case ID_FUNC_ITEM_JSONB_QUERY:
            return sql_get_jsonb_query_result(json_ass, result, func->json_func_attr, &jb_result_array);
        case ID_FUNC_ITEM_JSONB_EXISTS:
            return sql_get_jsonb_exists_result(result, &jb_result_array);
        case ID_FUNC_ITEM_JSONB_VALUE:
            return sql_get_jsonb_value_result(json_ass, result, func->json_func_attr, &jb_result_array);
        default:
            OG_SRC_THROW_ERROR(func->loc, ERR_ASSERT_ERROR, "invalid func type");
            return OG_ERROR;
    }
}

status_t jsonb_retrieve_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    variant_t var_target;
    variant_t var_path;
    json_path_t path;

    // 1. eval path expr, then compile
    OG_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument->next, &var_path, result));
    OG_RETSUC_IFTRUE(result->type == OG_TYPE_COLUMN);
    if (result->is_null) {
        OG_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return OG_ERROR;
    }
    path.count = 0;
    OG_RETURN_IFERR(json_path_compile(json_ass, &var_path.v_text, &path, func->argument->next->loc));

    if (path.func != NULL && func->value.v_func.func_id == ID_FUNC_ITEM_JSON_EXISTS) {
        OG_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return OG_ERROR;
    }

    // 2. eval jsonb binary data
    OG_RETURN_IFERR(sql_exec_jsonb_func_arg(json_ass, func->argument, &var_target, result));
    OG_RETSUC_IFTRUE(result->is_null || result->type == OG_TYPE_COLUMN);

    return jsonb_func_get_result(json_ass, func, result, &path, &var_target);
}

status_t jsonb_to_jsonvalue_values(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre,
    json_value_t *jv);

static status_t jsonb_to_jsonvalue_array(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre,
    json_value_t *jv)
{
    jv->type = JSON_VAL_ARRAY;
    OG_RETURN_IFERR(json_item_array_init(json_ass, &jv->array, JSON_MEM_VMC));

    jsonb_result_elem_t node;

    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar->head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    for (uint32 i = 0; i < nNodes; i++) {
        json_value_t *elem = NULL;
        OG_RETURN_IFERR(cm_galist_new(jv->array, sizeof(json_value_t), (pointer_t *)&elem));

        OG_RETURN_IFERR(jsonb_array_get_elem(jar, jre, i, &node));
        OG_RETURN_IFERR(jsonb_to_jsonvalue_values(json_ass, jar, &node, elem));
    }

    return OG_SUCCESS;
}

static status_t jsonb_to_jsonvalue_object(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre,
    json_value_t *jv)
{
    jv->type = JSON_VAL_OBJECT;
    OG_RETURN_IFERR(json_item_array_init(json_ass, &jv->object, JSON_MEM_VMC));

    jsonb_result_elem_t key;
    jsonb_result_elem_t val;

    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar->head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    for (uint32 i = 0; i < nNodes; i++) {
        json_pair_t *pair = NULL;
        OG_RETURN_IFERR(cm_galist_new(jv->object, sizeof(json_pair_t), (pointer_t *)&pair));

        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, i, &key, OG_TRUE));
        OG_RETURN_IFERR(jsonb_to_jsonvalue_values(json_ass, jar, &key, &pair->key));

        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, i + nNodes, &val, OG_FALSE));
        OG_RETURN_IFERR(jsonb_to_jsonvalue_values(json_ass, jar, &val, &pair->val));
    }

    return OG_SUCCESS;
}

status_t jsonb_to_jsonvalue_values(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre,
    json_value_t *jv)
{
    status_t status = OG_SUCCESS;

    switch (jre->type) {
        case JBT_NULL:
            jv->type = JSON_VAL_NULL;
            break;

        case JBT_BOOL_FALSE:
            jv->type = JSON_VAL_BOOL;
            jv->boolean = OG_FALSE;
            break;

        case JBT_BOOL_TRUE:
            jv->type = JSON_VAL_BOOL;
            jv->boolean = OG_TRUE;
            break;

        case JBT_NUMBER:
            jv->type = JSON_VAL_NUMBER;
            jv->number.str = (char *)jre->data;
            jv->number.len = jre->length;
            break;

        case JBT_STRING:
            jv->type = JSON_VAL_STRING;
            jv->number.str = (char *)jre->data;
            jv->number.len = jre->length;
            break;

        case JBT_BOX:
            if (JSONB_HEAD_IS_ARRAY(jre->data, jar->head_bytes)) {
                status = jsonb_to_jsonvalue_array(json_ass, jar, jre, jv);
            } else {
                status = jsonb_to_jsonvalue_object(json_ass, jar, jre, jv);
            }
            break;

        default:
            OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "the type of element is wrong.");
            return OG_ERROR;
    }

    return status;
}

/* convert json tree from jsonb */
static status_t get_jsonvalue_from_jsonb(json_assist_t *json_ass, jsonb_value_t *jb, json_value_t *jv)
{
    json_ass->version = jb->version;
    json_ass->head_entry_bytes = jb->head_entry_bytes;

    jsonb_assist_read_t jar;
    jsonb_result_elem_t jre;
    OG_RETURN_IFERR(jsonb_transform_values(jb, &jar, &jre));

    return jsonb_to_jsonvalue_values(json_ass, &jar, &jre, jv);
}

static status_t jsonb_return_process(json_assist_t *json_ass, json_value_t *jv_result, json_func_attr_t attr, variant_t
    *result)
{
    // handle returning clause
    if (JSON_FUNC_ATT_GET_RETURNING(attr.ids) != JSON_FUNC_ATT_RETURNING_JSONB) {
        JSON_RETURN_IF_ON_ERROR_HANDLED(handle_returning_clause(json_ass, jv_result, attr, result, OG_FALSE), json_ass,
            attr,
            result);
        return OG_SUCCESS;
    }

    // 5. convert the result(json tree) to jsonb binary.
    variant_t var_target;
    json_analyse_t analyse = { 0 };
    OG_RETURN_IFERR(json_analyse(json_ass, jv_result, &analyse)); // must do this step before converting to jsonb.
    json_ass->janalys = &analyse;

    jsonb_result_elem_t jb_result;
    OG_RETURN_IFERR(get_jsonb_from_jsonvalue(json_ass, jv_result, &var_target, OG_FALSE));
    jb_result.is_scaler = OG_FALSE;
    jb_result.type = JBT_BOX;
    jb_result.length = var_target.v_bin.size;
    jb_result.data = (uint8 *)var_target.v_bin.bytes;

    // 6. handle returning clause.
    jsonb_results_t jb_result_array;
    OG_RETURN_IFERR(json_item_array_init(json_ass, &jb_result_array.results, JSON_MEM_LARGE_POOL));

    jsonb_result_elem_t *jre = NULL;
    OG_RETURN_IFERR(cm_galist_new(jb_result_array.results, sizeof(jsonb_result_elem_t), (pointer_t *)&jre));
    *jre = jb_result;

    json_ass->jsonb_result_is_list = OG_FALSE;
    JSON_RETURN_IF_ON_ERROR_HANDLED(jsonb_handle_returning_clause(json_ass, &jb_result_array, attr, result, OG_FALSE),
        json_ass,
        attr, result);

    return OG_SUCCESS;
}

status_t jsonb_mergepatch_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    expr_tree_t *arg = NULL;
    variant_t var_target;
    variant_t var_patch;
    json_value_t jv_target;
    json_value_t jv_patch;
    json_value_t *jv_result = NULL;
    json_func_attr_t attr = func->json_func_attr;

    // 1. eval patch_expr, parse
    arg = func->argument->next;
    OG_RETURN_IFERR(sql_exec_json_func_arg(json_ass, arg, &var_patch, result));
    OG_RETSUC_IFTRUE(result->type == OG_TYPE_COLUMN);
    var_patch.v_text.len = var_patch.is_null ? 0 : var_patch.v_text.len;
    cm_trim_text(&var_patch.v_text);
    if (var_patch.v_text.len == 0 || (var_patch.v_text.str[0] != '{' && var_patch.v_text.str[0] != '[')) {
        OG_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "patch is not valid JSON");
        return OG_ERROR;
    }
    if (json_parse(json_ass, &var_patch.v_text, &jv_patch, arg->loc) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_JSON_SYNTAX_ERROR, "patch is not valid JSON");
        return OG_ERROR;
    }
    // sort all objects in jv_patch
    OG_RETURN_IFERR(json_analyse(json_ass, &jv_patch, NULL));

    // 2. eval target_expr
    arg = func->argument;
    OG_RETURN_IFERR(sql_exec_jsonb_func_arg(json_ass, arg, &var_target, result));
    OG_RETSUC_IFTRUE(var_target.is_null || result->type == OG_TYPE_COLUMN);

    // 3.1 parse target_expr, in jsonb, we can directly get the values, no need to parse it.
    jsonb_value_t *jb_target = NULL;
    OG_RETURN_IFERR(jsonb_parse(json_ass, &var_target, &jb_target));

    // 3.2 convert the jsonb to json tree in memory, it is very convenitent for Delete/Update/Insert.
    OG_RETURN_IFERR(get_jsonvalue_from_jsonb(json_ass, jb_target, &jv_target));

    // 4. do merge
    JSON_RETURN_IF_ON_ERROR_HANDLED(json_merge_patch(json_ass, &jv_target, &jv_patch, &jv_result), json_ass, attr,
        result);

    // handle returning clause
    OG_RETURN_IFERR(jsonb_return_process(json_ass, jv_result, attr, result));

    return OG_SUCCESS;
}

static status_t jsonb_set_core(json_assist_t *json_ass, json_value_t *jv_target, json_path_t *path, json_func_attr_t attr,
    variant_t *result)
{
    // extract the json tree, according the path and policy, and ignore the filter path && json_func.
    json_ass->need_sort = OG_TRUE;
    OG_RETURN_IFERR(json_set_iteration(json_ass, jv_target, path));

    if (JSON_VAL_IS_DELETED(jv_target)) {
        result->is_null = OG_TRUE;
        result->type = OG_TYPE_STRING;
        return OG_SUCCESS;
    }

    // handle returning clause
    OG_RETURN_IFERR(jsonb_return_process(json_ass, jv_target, attr, result));

    return OG_SUCCESS;
}

#define JSONB_SET_BOOL_IDX 4
status_t jsonb_set(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    variant_t var_target;
    variant_t var_path;
    variant_t var_new_val;
    variant_t var_create;
    json_path_t path;
    json_value_t jv_target;
    json_value_t jv_new_val;
    json_func_attr_t attr = func->json_func_attr;

    // 1. parse the 2nd parameter, eval path expr, then compile
    OG_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument->next, &var_path, result));
    OG_RETSUC_IFTRUE(result->type == OG_TYPE_COLUMN);
    if (result->is_null) {
        OG_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return OG_ERROR;
    }
    path.count = 0;
    OG_RETURN_IFERR(json_path_compile(json_ass, &var_path.v_text, &path, func->argument->next->loc));
    if (path.func != NULL && func->value.v_func.func_id == ID_FUNC_ITEM_JSON_EXISTS) {
        OG_THROW_ERROR(ERR_JSON_PATH_SYNTAX_ERROR, "missing expression");
        return OG_ERROR;
    }

    if (func->argument->next->next != NULL) {
        // 2. parse the 3rd parameter, parse json text to json_value_t
        OG_RETURN_IFERR(sql_exec_json_func_arg(json_ass, func->argument->next->next, &var_new_val, result));
        OG_RETSUC_IFTRUE(result->is_null || result->type == OG_TYPE_COLUMN);
        JSON_RETURN_IF_ON_ERROR_HANDLED(
            json_parse(json_ass, &var_new_val.v_text, &jv_new_val, func->argument->next->next->loc), json_ass, attr,
                result);

        // sort all objects in jv_new_val
        OG_RETURN_IFERR(json_analyse(json_ass, &jv_new_val, NULL));
        json_ass->jv_new_val = &jv_new_val;

        var_create.type = OG_TYPE_BOOLEAN;
        var_create.v_bool = OG_TRUE; /* default value */
        if (func->argument->next->next->next != NULL) {
            // 3. parse the 4th parameter, get the bool value (whether creating on missing).
            OG_RETURN_IFERR(sql_exec_expr(json_ass->stmt, func->argument->next->next->next, &var_create) != OG_SUCCESS);
            OG_RETSUC_IFTRUE(var_create.is_null || var_create.type == OG_TYPE_COLUMN);
            if (!OG_IS_BOOLEAN_TYPE(var_create.type)) {
                OG_THROW_ERROR(ERR_FUNC_ARGUMENT_WRONG_TYPE, JSONB_SET_BOOL_IDX, "boolean");
                return OG_ERROR;
            }
        }

        json_ass->policy = var_create.v_bool ? JEP_REPLACE_OR_INSERT : JEP_REPLACE_ONLY;
    } else {
        json_ass->policy = JEP_DELETE;
    }

    // 4.1 parse the 1st parameter, parse json text to json_value_tparse target_expr, in jsonb,
    // we can directly get the values, no need to parse it.
    OG_RETURN_IFERR(sql_exec_jsonb_func_arg(json_ass, func->argument, &var_target, result));
    OG_RETSUC_IFTRUE(var_target.is_null || result->type == OG_TYPE_COLUMN);

    jsonb_value_t *jb_target = NULL;
    OG_RETURN_IFERR(jsonb_parse(json_ass, &var_target, &jb_target));

    // 4.2 convert the jsonb to json tree in memory, it is very convenitent for Delete/Update/Insert.
    OG_RETURN_IFERR(get_jsonvalue_from_jsonb(json_ass, jb_target, &jv_target));

    /* 5. after get all the parameters, we can do set procession. */
    OG_RETURN_IFERR(jsonb_set_core(json_ass, &jv_target, &path, attr, result));
    return OG_SUCCESS;
}

status_t jsonb_array_length_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result)
{
    variant_t var_target;

    // 1. Parse argument(BINARY) to var_json_val and result.
    OG_RETURN_IFERR(sql_exec_jsonb_func_arg(json_ass, func->argument, &var_target, result));
    if (result->is_null || result->type == OG_TYPE_COLUMN) {
        return OG_SUCCESS;
    }

    // 2. parse target_expr, in jsonb, we can directly get the values, no need to parse it.
    jsonb_value_t *jb = NULL;
    OG_RETURN_IFERR(jsonb_parse(json_ass, &var_target, &jb));

    // check if access memory SECURELY.
    jsonb_assist_read_t jar;
    jsonb_result_elem_t jre;
    OG_RETURN_IFERR(jsonb_transform_values(jb, &jar, &jre));

    // 3. get result
    if (!JSONB_HEAD_IS_ARRAY(&jb->data, jar.head_bytes)) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "the data type is not json array.");
        return OG_ERROR;
    }

    result->type = OG_TYPE_UINT32;
    result->is_null = OG_FALSE;
    result->v_uint32 = JSONB_GET_HEADER_ELEM_COUNT(&jb->data, jar.head_bytes);
    return OG_SUCCESS;
}

// param2: arg is expr_tree_t of original jsonb data, param3: jv is output param to be filled
status_t sql_func_jsonb_to_jv(json_assist_t *json_ass, expr_tree_t *arg, json_value_t *jv, variant_t *result)
{
    variant_t var_target;

    OG_RETURN_IFERR(sql_exec_jsonb_func_arg(json_ass, arg, &var_target, result));
    OG_RETSUC_IFTRUE(var_target.is_null || result->type == OG_TYPE_COLUMN);

    jsonb_value_t *jb_target = NULL;
    OG_RETURN_IFERR(jsonb_parse(json_ass, &var_target, &jb_target));

    OG_RETURN_IFERR(get_jsonvalue_from_jsonb(json_ass, jb_target, jv));

    return OG_SUCCESS;
}

status_t jsonb_format_valiate_box(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre);
static status_t jsonb_format_valiate_array(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre)
{
    jsonb_result_elem_t node;
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    for (uint32 i = 0; i < nNodes; i++) {
        OG_RETURN_IFERR(jsonb_array_get_elem(jar, jre, i, &node));
        if (node.is_scaler) {
            continue;
        }
        OG_RETURN_IFERR(jsonb_format_valiate_box(json_ass, jar, &node));
    }

    return OG_SUCCESS;
}

static status_t jsonb_format_valiate_object(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre)
{
    jsonb_result_elem_t key;
    jsonb_result_elem_t val;
    uint32 nNodes = JSONB_GET_HEADER_ELEM_COUNT(jre->data, jar->head_bytes);

    for (uint32 i = 0; i < nNodes; i++) {
        // key is scaler string, no need to check again.
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, i, &key, OG_TRUE));

        // val
        OG_RETURN_IFERR(jsonb_object_get_elem(jar, jre, i + nNodes, &val, OG_FALSE));
        if (val.is_scaler) {
            continue;
        }
        OG_RETURN_IFERR(jsonb_format_valiate_box(json_ass, jar, &val));
    }

    return OG_SUCCESS;
}

status_t jsonb_format_valiate_box(json_assist_t *json_ass, jsonb_assist_read_t *jar, jsonb_result_elem_t *jre)
{
    // check if access memory SECURELY.
    if (SECUREC_UNLIKELY(
        !JSONB_ACCESS_MEM_SECURELY(jar, ((uint64)(jre->data)) + JSONB_GET_HEADER_LEN(jar->head_bytes)))) {
        OG_THROW_ERROR(ERR_JSONB_SYNTAX_ERROR, "invalid header length of jsonb format.");
        return OG_ERROR;
    }

    if (JSONB_HEAD_IS_ARRAY(jre->data, jar->head_bytes)) {
        return jsonb_format_valiate_array(json_ass, jar, jre);
    } else {
        return jsonb_format_valiate_object(json_ass, jar, jre);
    }
}

status_t jsonb_format_valiate_core(json_assist_t *json_ass, variant_t *value)
{
    jsonb_value_t *jb = NULL;
    OG_RETURN_IFERR(jsonb_parse(json_ass, value, &jb));

    jsonb_assist_read_t jar;
    jsonb_result_elem_t jre;
    OG_RETURN_IFERR(jsonb_transform_values(jb, &jar, &jre));

    return jsonb_format_valiate_box(json_ass, &jar, &jre);
}

#ifdef __cplusplus
}
#endif
