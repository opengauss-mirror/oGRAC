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
 * ogsql_serial.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/node/ogsql_serial.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "cm_list.h"
#include "ogsql_serial.h"
#include "ogsql_func.h"
#include "ogsql_package.h"

static status_t inline sr_alloc_mem(memory_context_t *ogx, uint32 size, void **ptr)
{
    if (ogx->pool->mem_alloc.ogx != NULL) {
        OG_RETURN_IFERR(ogx->pool->mem_alloc.mem_func(ogx->pool->mem_alloc.ogx, ogx, size, ptr));
    } else {
        OG_RETURN_IFERR(mctx_alloc(ogx, size, ptr));
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memset_s(*ptr, size, 0, size));
    }
    return OG_SUCCESS;
}

status_t sr_encode_variant(sql_stmt_t *stmt, serializer_t *sr, variant_t *var, uint32 *offset)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, var, offset);

    if (var->is_null) {
        *offset = SR_NULL;
        return OG_SUCCESS;
    }

    SR_PUT_FIXED(sr, og_type_t, var->type);

    switch (var->type) {
        case OG_TYPE_UINT32:
            SR_PUT_FIXED(sr, uint32, var->v_uint32);
            break;

        case OG_TYPE_INTEGER:
            SR_PUT_FIXED(sr, int32, var->v_int);
            break;

        case OG_TYPE_BOOLEAN:
            SR_PUT_FIXED(sr, bool32, var->v_bool);
            break;

        case OG_TYPE_BIGINT:
            SR_PUT_FIXED(sr, int64, var->v_bigint);
            break;

        case OG_TYPE_REAL:
            SR_PUT_FIXED(sr, double, var->v_real);
            break;

        case OG_TYPE_DATE:
            SR_PUT_DATA(sr, &var->v_date, sizeof(date_t));
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
            SR_PUT_DATA(sr, &var->v_tstamp, sizeof(timestamp_t));
            break;

        case OG_TYPE_TIMESTAMP_LTZ:
            SR_PUT_DATA(sr, &var->v_tstamp_ltz, sizeof(timestamp_ltz_t));
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            SR_PUT_DATA(sr, &var->v_tstamp_tz, sizeof(timestamp_tz_t));
            break;

        case OG_TYPE_INTERVAL_DS:
            SR_PUT_DATA(sr, &var->v_itvl_ds, sizeof(interval_ds_t));
            break;

        case OG_TYPE_INTERVAL_YM:
            SR_PUT_DATA(sr, &var->v_itvl_ym, sizeof(interval_ym_t));
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL: {
            dec4_t d4;
            OG_RETURN_IFERR(cm_dec_8_to_4(&d4, &var->v_dec));
            uint32 len = cm_dec4_stor_sz(&d4);
            SR_PUT_VARLEN(sr, &d4, len);
            break;
        }
        case OG_TYPE_NUMBER2: {
            dec2_t d2;
            OG_RETURN_IFERR(cm_dec_8_to_2(&d2, &var->v_dec));
            uint32 len = cm_dec2_stor_sz(&d2);
            SR_PUT_VARLEN(sr, GET_PAYLOAD(&d2), len);
            break;
        }
        case OG_TYPE_TYPMODE:
            SR_PUT_DATA(sr, &var->v_type, sizeof(typmode_t));
            break;

        case OG_TYPE_ITVL_UNIT:
            SR_PUT_DATA(sr, &var->v_itvl_unit_id, sizeof(interval_unit_t));
            break;
        case OG_TYPE_BLOB:
        case OG_TYPE_CLOB:
        case OG_TYPE_IMAGE:
            break;
        case OG_TYPE_STRING:
        default:
            SR_PUT_VARLEN(sr, var->v_text.str, var->v_text.len);
            break;
    }

    return OG_SUCCESS;
}

static status_t sr_encode_func(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);
    sql_func_t *func = NULL;
    sql_package_t *pack = NULL;
    char buf[OG_NAME_BUFFER_SIZE * 2];
    text_t text;
    uint32 max_len = OG_NAME_BUFFER_SIZE * 2;

    text.str = buf;
    text.len = 0;

    if (node->value.v_func.pack_id != OG_INVALID_ID32) {
        pack = sql_get_pack(node->value.v_func.pack_id);
        cm_concat_text(&text, max_len, &pack->name);
    }

    OG_RETURN_IFERR(cm_concat_string(&text, max_len, "."));
    func = sql_get_func(&node->value.v_func);
    cm_concat_text(&text, max_len, &func->name);
    SR_PUT_VARLEN(sr, text.str, text.len);
    return OG_SUCCESS;
}

static status_t sr_encode_user_func(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);
    char buf[OG_NAME_BUFFER_SIZE * 3];
    text_t text;
    var_udo_t *obj = sql_node_get_obj(node);
    uint32 max_len = OG_NAME_BUFFER_SIZE * 3;

    text.str = buf;
    text.len = 0;

    cm_concat_text(&text, max_len, &obj->user);
    OG_RETURN_IFERR(cm_concat_string(&text, max_len, "."));
    if (!CM_IS_EMPTY(&obj->pack)) {
        cm_concat_text(&text, max_len, &obj->pack);
        OG_RETURN_IFERR(cm_concat_string(&text, max_len, "."));
    }

    cm_concat_text(&text, max_len, &obj->name);

    SR_PUT_VARLEN(sr, text.str, text.len);
    return OG_SUCCESS;
}

/* !
 * \brief Encode and serialize an expr node
 */
static status_t sr_encode_sequence(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);
    var_seq_t *seq = &node->value.v_seq;
    SR_PUT_VARLEN(sr, seq->user.str, seq->user.len);
    SR_PUT_VARLEN(sr, seq->name.str, seq->name.len);
    SR_PUT_FIXED(sr, seq_mode_t, seq->mode);
    return OG_SUCCESS;
}

#ifdef Z_SHARDING
static status_t sr_encode_column(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);
    var_column_t *col = &node->value.v_col;
    SR_PUT_FIXED(sr, uint16, col->col);
    SR_PUT_FIXED(sr, uint16, col->tab);
    SR_PUT_FIXED(sr, og_type_t, col->datatype);

    return OG_SUCCESS;
}

static status_t sr_decode_column(const char *sr_data, uint32 temp_offset, variant_t *var)
{
    uint32 offset = temp_offset;
    var_column_t *col = &var->v_col;
    col->col = *((uint16 *)(sr_data + offset));
    offset += CM_ALIGN4(sizeof(uint16));
    col->tab = *((uint16 *)(sr_data + offset));
    offset += CM_ALIGN4(sizeof(uint16));
    col->datatype = *(og_type_t *)(sr_data + offset);
    var->type = OG_TYPE_COLUMN;
    return OG_SUCCESS;
}
#endif

static status_t sr_encode_list(sql_stmt_t *stmt, serializer_t *sr, galist_t *list, uint32 *offset,
    sr_encode_cell_t encode_cell)
{
    sr_list_t *sr_list = NULL;
    uint32 size;
    pointer_t cell;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT_LIST(sr, list->count, offset);
    size = sizeof(sr_list_t) + list->count * sizeof(uint32);
    OG_RETURN_IFERR(sr_push(sr, size, (void **)&sr_list));
    sr_list->count = list->count;
    for (uint32 i = 0; i < list->count; i++) {
        cell = cm_galist_get(list, i);
        OG_RETURN_IFERR(encode_cell(stmt, sr, cell, &sr_list->cell[i]));
    }

    return OG_SUCCESS;
}

static status_t sr_decode_list(memory_context_t *ogx, char *sr_data, uint32 offset, galist_t *list,
    sr_decode_cell_t decode_cell)
{
    if (offset == SR_NULL) {
        list->count = 0;
        return OG_SUCCESS;
    }

    sr_list_t *sr_list = (sr_list_t *)(sr_data + offset);

    for (uint32 i = 0; i < sr_list->count; i++) {
        OG_RETURN_IFERR(decode_cell(ogx, sr_data, sr_list->cell[i], list));
    }

    return OG_SUCCESS;
}

static status_t sr_encode_simple_case_pair(sql_stmt_t *stmt, serializer_t *sr, void *context, uint32 *offset)
{
    case_pair_t *case_pair = (case_pair_t *)context;
    sr_case_pair_t *sr_pair = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, case_pair, offset);

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_case_pair_t), (void **)&sr_pair));
    OG_RETURN_IFERR(sr_encode_expr(stmt, sr, case_pair->when_expr, &sr_pair->when_expr));
    return sr_encode_expr(stmt, sr, case_pair->value, &sr_pair->value);
}

static status_t sr_encode_searched_case_pair(sql_stmt_t *stmt, serializer_t *sr, void *context, uint32 *offset)
{
    case_pair_t *case_pair = (case_pair_t *)context;
    sr_case_pair_t *sr_pair = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, case_pair, offset);

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_case_pair_t), (void **)&sr_pair));
    OG_RETURN_IFERR(sr_encode_cond(stmt, sr, case_pair->when_cond, &sr_pair->when_cond));
    return sr_encode_expr(stmt, sr, case_pair->value, &sr_pair->value);
}

static status_t sr_encode_case_when(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset)
{
    case_expr_t *case_expr = (case_expr_t *)VALUE(pointer_t, &node->value);
    sr_case_expr_t *sr_case_expr = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, case_expr, offset);

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_case_expr_t), (void **)&sr_case_expr));
    sr_case_expr->is_cond = case_expr->is_cond;

    if (!sr_case_expr->is_cond) {
        OG_RETURN_IFERR(sr_encode_expr(stmt, sr, case_expr->expr, &sr_case_expr->expr));
        OG_RETURN_IFERR(sr_encode_list(stmt, sr, &case_expr->pairs, &sr_case_expr->pairs, sr_encode_simple_case_pair));
    } else {
        OG_RETURN_IFERR(
            sr_encode_list(stmt, sr, &case_expr->pairs, &sr_case_expr->pairs, sr_encode_searched_case_pair));
    }

    return sr_encode_expr(stmt, sr, case_expr->default_expr, &sr_case_expr->default_expr);
}
status_t sr_encode_expr_node(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);
    sr_expr_node_t *sr_node = NULL;

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_expr_node_t), (void **)&sr_node));

    sr_node->type = node->type;
    sr_node->datatype = node->datatype;
    sr_node->unary = node->unary;

    sr_node->format_json = node->format_json;
    sr_node->json_func_attr = node->json_func_attr;

    if (node->type == EXPR_NODE_FUNC || node->type == EXPR_NODE_USER_FUNC) {
        OG_RETURN_IFERR(sr_encode_expr(stmt, sr, node->argument, &sr_node->args));
    }

    switch (node->type) {
        case EXPR_NODE_CONST:
        case EXPR_NODE_RESERVED:
            OG_RETURN_IFERR(sr_encode_variant(stmt, sr, &node->value, &sr_node->value));
            break;

        case EXPR_NODE_SEQUENCE:
            OG_RETURN_IFERR(sr_encode_sequence(stmt, sr, node, &sr_node->value));
            break;

        case EXPR_NODE_FUNC:
            OG_RETURN_IFERR(sr_encode_func(stmt, sr, node, &sr_node->value));
            if (IS_BUILDIN_FUNCTION(node, ID_FUNC_ITEM_TRIM)) {
                sr_node->ext_args = node->ext_args;
            }

            if (IS_BUILDIN_FUNCTION(node, ID_FUNC_ITEM_IF) || IS_BUILDIN_FUNCTION(node, ID_FUNC_ITEM_LNNVL)) {
                OG_RETURN_IFERR(sr_encode_cond(stmt, sr, (cond_tree_t *)node->cond_arg, &sr_node->cond_arg));
            }
            break;
        case EXPR_NODE_USER_FUNC:
            OG_RETURN_IFERR(sr_encode_user_func(stmt, sr, node, &sr_node->value));
            break;
        case EXPR_NODE_CASE:
            OG_RETURN_IFERR(sr_encode_case_when(stmt, sr, node, &sr_node->value));
            break;

        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            OG_RETURN_IFERR(sr_encode_expr_node(stmt, sr, node->left, &sr_node->left));
            OG_RETURN_IFERR(sr_encode_expr_node(stmt, sr, node->right, &sr_node->right));
            break;

        case EXPR_NODE_NEGATIVE:
            OG_RETURN_IFERR(sr_encode_expr_node(stmt, sr, node->right, &sr_node->right));
            break;

#ifdef Z_SHARDING
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            OG_RETURN_IFERR(sr_encode_column(stmt, sr, node, &sr_node->value));
            break;
        case EXPR_NODE_STAR:
            break;
#endif
        case EXPR_NODE_ARRAY:
            break;
        default:
            OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid symbol for serialization");
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sr_encode_expr(sql_stmt_t *stmt, serializer_t *sr, expr_tree_t *expr, uint32 *offset)
{
    sr_expr_tree_t *sr_expr = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, expr, offset);

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_expr_tree_t), (void **)&sr_expr));

    OG_RETURN_IFERR(sr_encode_expr_node(stmt, sr, expr->root, &sr_expr->root));

    return sr_encode_expr(stmt, sr, expr->next, &sr_expr->next);
}

status_t sr_encode_expr_list(sql_stmt_t *stmt, serializer_t *sr, uint32 *offset, int num, ...)
{
    sr_list_t *sr_list = NULL;
    va_list list;
    int i = num;
    uint32 size;
    serializer_t move_sr = *sr;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT_LIST(sr, num, offset);
    size = sizeof(sr_list_t) + num * sizeof(uint32);
    OG_RETURN_IFERR(sr_push(sr, size, (void **)&sr_list));
    sr_list->count = num;
    va_start(list, num);
    for (i = 0; i < num; i++) {
        expr_tree_t *expr = va_arg(list, expr_tree_t *);
        sr_list->cell[i] = sr->pos;
        // move step the sr
        SR_MOVE_STEP(&move_sr, sr);
        if (sr_encode_expr(stmt, &move_sr, expr, offset) != OG_SUCCESS) {
            va_end(list);
            return OG_ERROR;
        }
        sr->pos += move_sr.pos;
    }
    va_end(list);

    return OG_SUCCESS;
}

static status_t sr_encode_cmp_node(sql_stmt_t *stmt, serializer_t *sr, cmp_node_t *node, uint32 *offset)
{
    sr_cmp_node_t *sr_node = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);
    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_cmp_node_t), (void **)&sr_node));
    sr_node->join_type = node->join_type;
    sr_node->type = node->type;
    OG_RETURN_IFERR(sr_encode_expr(stmt, sr, node->left, &sr_node->left));
    return sr_encode_expr(stmt, sr, node->right, &sr_node->right);
}

static status_t sr_encode_cond_node(sql_stmt_t *stmt, serializer_t *sr, cond_node_t *node, uint32 *offset)
{
    sr_cond_node_t *sr_node = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, node, offset);

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_cond_node_t), (void **)&sr_node));
    sr_node->type = node->type;

    switch (node->type) {
        case COND_NODE_COMPARE:
            OG_RETURN_IFERR(sr_encode_cmp_node(stmt, sr, node->cmp, &sr_node->cmp));
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        default:
            OG_RETURN_IFERR(sr_encode_cond_node(stmt, sr, node->left, &sr_node->left));
            OG_RETURN_IFERR(sr_encode_cond_node(stmt, sr, node->right, &sr_node->right));
            break;
    }

    return OG_SUCCESS;
}

status_t sr_encode_cond(sql_stmt_t *stmt, serializer_t *sr, cond_tree_t *cond, uint32 *offset)
{
    sr_cond_tree_t *sr_cond = NULL;
    OG_RETURN_IFERR(sql_stack_safe(stmt));
    SR_CHECK_OBJECT(sr, cond, offset);

    OG_RETURN_IFERR(sr_push(sr, sizeof(sr_cond_tree_t), (void **)&sr_cond));

    sr_cond->rownum_upper = cond->rownum_upper;
    sr_cond->loc = cond->loc;

    return sr_encode_cond_node(stmt, sr, cond->root, &sr_cond->root);
}

status_t sr_decode_variant(char *sr_data, uint32 temp_offset, variant_t *var)
{
    uint32 offset = temp_offset;
    if (offset == SR_NULL) {
        var->type = OG_TYPE_INTEGER;
        var->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    var->is_null = OG_FALSE;
    var->type = *(og_type_t *)(sr_data + offset);
    offset += CM_ALIGN4(sizeof(og_type_t));

    switch (var->type) {
        case OG_TYPE_UINT32:
            var->v_uint32 = *(uint32 *)(sr_data + offset);
            break;
        case OG_TYPE_INTEGER:
            var->v_int = *(int32 *)(sr_data + offset);
            break;

        case OG_TYPE_BOOLEAN:
            var->v_bool = *(bool32 *)(sr_data + offset);
            break;

        case OG_TYPE_BIGINT:
            var->v_bigint = *(int64 *)(sr_data + offset);
            break;

        case OG_TYPE_REAL:
            var->v_real = *(double *)(sr_data + offset);
            break;

        case OG_TYPE_DATE:
            MEMS_RETURN_IFERR(memcpy_s(&var->v_date, sizeof(date_t), sr_data + offset, sizeof(date_t)));
            break;

        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_LTZ:
            MEMS_RETURN_IFERR(memcpy_s(&var->v_tstamp, sizeof(timestamp_t), sr_data + offset, sizeof(timestamp_t)));
            break;

        case OG_TYPE_TIMESTAMP_TZ:
            MEMS_RETURN_IFERR(
                memcpy_s(&var->v_tstamp_tz, sizeof(timestamp_tz_t), sr_data + offset, sizeof(timestamp_tz_t)));
            break;

        case OG_TYPE_INTERVAL_DS:
            MEMS_RETURN_IFERR(
                memcpy_s(&var->v_itvl_ds, sizeof(interval_ds_t), sr_data + offset, sizeof(interval_ds_t)));
            break;

        case OG_TYPE_INTERVAL_YM:
            MEMS_RETURN_IFERR(
                memcpy_s(&var->v_itvl_ym, sizeof(interval_ym_t), sr_data + offset, sizeof(interval_ym_t)));
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_DECIMAL: {
            uint32 len = *(uint32 *)(sr_data + offset);
            void *data_ptr = (void *)(sr_data + offset + sizeof(uint32));
            return cm_dec_4_to_8(&var->v_dec, data_ptr, len);
        }
        case OG_TYPE_NUMBER2: {
            uint32 len = *(uint32 *)(sr_data + offset);
            void *data_ptr = (void *)(sr_data + offset + sizeof(uint32));
            return cm_dec_2_to_8(&var->v_dec, (const payload_t *)data_ptr, len);
        }
        case OG_TYPE_TYPMODE: {
            MEMS_RETURN_IFERR(memcpy_s(&var->v_type, sizeof(typmode_t), sr_data + offset, sizeof(typmode_t)));
            break;
        }

        case OG_TYPE_ITVL_UNIT: {
            MEMS_RETURN_IFERR(
                memcpy_s(&var->v_itvl_unit_id, sizeof(interval_unit_t), sr_data + offset, sizeof(interval_unit_t)));
            break;
        }

        case OG_TYPE_STRING:
        default:
            var->v_text.len = *(uint32 *)(sr_data + offset);
            var->v_text.str = (sr_data + offset + sizeof(uint32));
            break;
    }

    return OG_SUCCESS;
}

static void sr_decode_func(char *sr_data, uint32 offset, variant_t *var)
{
    text_t text;
    text_t pack_name;
    text_t func_name;

    text.len = *(uint32 *)(sr_data + offset);
    text.str = (sr_data + offset + sizeof(uint32));
    cm_split_text(&text, '.', '\0', &pack_name, &func_name);

    var->type = OG_TYPE_INTEGER;
    if (pack_name.len == 0) {
        var->v_func.func_id = (uint32)sql_get_func_id(&func_name);
        var->v_func.pack_id = OG_INVALID_ID32;
        var->v_func.orig_func_id = OG_INVALID_ID32;
    } else {
        sql_convert_pack_func(&pack_name, &func_name, &var->v_func);
    }
}

static status_t sr_decode_user_func(memory_context_t *ogx, char *sr_data, uint32 offset, variant_t *var)
{
    text_t text;
    text_t pack_or_user;
    text_t user;
    text_t pack_name;
    text_t func_name;
    var_udo_t *object = NULL;

    text.len = *(uint32 *)(sr_data + offset);
    text.str = (sr_data + offset + sizeof(uint32));
    (void)cm_split_rtext(&text, '.', '\0', &pack_or_user, &func_name);
    (void)cm_split_rtext(&pack_or_user, '.', '\0', &user, &pack_name);

    var->type = OG_TYPE_INTEGER;
    var->type_for_pl = VAR_UDO;
    OG_RETURN_IFERR(sr_alloc_mem(ogx, sizeof(expr_node_t), (void **)&var->v_udo));
    object = var->v_udo;
    object->name = func_name;
    object->pack = pack_name;
    object->user = user;

    return OG_SUCCESS;
}

/* !
 * \brief Decode a sequence from raw data into an expr_node
 *
 */
static void sr_decode_sequence(char *sr_data, uint32 temp_offset, variant_t *var)
{
    uint32 offset = temp_offset;
    var_seq_t *sequence = &var->v_seq;
    sequence->user.len = *((uint32 *)(sr_data + offset));
    offset += sizeof(uint32);
    sequence->user.str = sr_data + offset;
    offset += CM_ALIGN4(sequence->user.len);
    sequence->name.len = *((uint32 *)(sr_data + offset));
    offset += sizeof(uint32);
    sequence->name.str = sr_data + offset;
    offset += CM_ALIGN4(sequence->name.len);
    sequence->mode = *(seq_mode_t *)(sr_data + offset);
    var->type = OG_TYPE_BIGINT;
}

static status_t sr_decode_expr_tree(memory_context_t *mem_ctx, char *sr_data, uint32 offset, expr_tree_t **expr);
static status_t sr_decode_cond_tree(memory_context_t *mem_ctx, char *sr_data, uint32 offset, cond_tree_t **cond);
static status_t sr_decode_case_when(memory_context_t *mem_ctx, char *sr_data, uint32 offset, case_expr_t **case_expr);

status_t sr_decode_expr_node(memory_context_t *mem_ctx, char *sr_data, uint32 offset, expr_node_t **node)
{
    if (offset == SR_NULL) {
        *node = NULL;
        return OG_SUCCESS;
    }

    sr_expr_node_t *sr_node = (sr_expr_node_t *)(sr_data + offset);
    OG_RETURN_IFERR(sr_alloc_mem(mem_ctx, sizeof(expr_node_t), (void **)node));

    (*node)->type = sr_node->type;
    (*node)->datatype = sr_node->datatype;
    (*node)->unary = sr_node->unary;
    (*node)->format_json = sr_node->format_json;
    (*node)->json_func_attr = sr_node->json_func_attr;

    if ((*node)->type == EXPR_NODE_FUNC || (*node)->type == EXPR_NODE_USER_FUNC) {
        OG_RETURN_IFERR(sr_decode_expr_tree(mem_ctx, sr_data, sr_node->args, &(*node)->argument));
    }

    switch ((*node)->type) {
        case EXPR_NODE_RESERVED:
        case EXPR_NODE_CONST:
            OG_RETURN_IFERR(sr_decode_variant(sr_data, sr_node->value, &(*node)->value));
            break;

        case EXPR_NODE_SEQUENCE:
            sr_decode_sequence(sr_data, sr_node->value, &(*node)->value);
            break;

        case EXPR_NODE_FUNC:
            sr_decode_func(sr_data, sr_node->value, &(*node)->value);
            if (IS_BUILDIN_FUNCTION(*node, ID_FUNC_ITEM_TRIM)) {
                (*node)->ext_args = sr_node->ext_args;
            }

            if (IS_BUILDIN_FUNCTION(*node, ID_FUNC_ITEM_IF) || IS_BUILDIN_FUNCTION(*node, ID_FUNC_ITEM_LNNVL)) {
                OG_RETURN_IFERR(sr_decode_cond_tree(mem_ctx, sr_data, sr_node->cond_arg, &((*node)->cond_arg)));
            }
            break;
        case EXPR_NODE_USER_FUNC:
            OG_RETURN_IFERR(sr_decode_user_func(mem_ctx, sr_data, sr_node->value, &(*node)->value));
            break;

        case EXPR_NODE_CASE:
            OG_RETURN_IFERR(sr_decode_case_when(mem_ctx, sr_data, sr_node->value,
                (case_expr_t **)VALUE_PTR(pointer_t, &(*node)->value)));
            break;

        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            OG_RETURN_IFERR(sr_decode_expr_node(mem_ctx, sr_data, sr_node->left, &(*node)->left));
            OG_RETURN_IFERR(sr_decode_expr_node(mem_ctx, sr_data, sr_node->right, &(*node)->right));
            break;

        case EXPR_NODE_NEGATIVE:
            OG_RETURN_IFERR(sr_decode_expr_node(mem_ctx, sr_data, sr_node->right, &(*node)->right));
            break;

#ifdef Z_SHARDING
        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            OG_RETURN_IFERR(sr_decode_column(sr_data, sr_node->value, &(*node)->value));
            break;
        case EXPR_NODE_STAR:
            break;
#endif

        default:
            break;
    }

    return OG_SUCCESS;
}

static status_t sr_decode_expr_tree(memory_context_t *mem_ctx, char *sr_data, uint32 offset, expr_tree_t **expr)
{
    if (offset == SR_NULL) {
        *expr = NULL;
        return OG_SUCCESS;
    }

    sr_expr_tree_t *sr_expr = (sr_expr_tree_t *)(sr_data + offset);

    OG_RETURN_IFERR(sr_alloc_mem(mem_ctx, sizeof(expr_tree_t), (void **)expr));

    OG_RETURN_IFERR(sr_decode_expr_node(mem_ctx, sr_data, sr_expr->root, &(*expr)->root));

    return sr_decode_expr_tree(mem_ctx, sr_data, sr_expr->next, &(*expr)->next);
}

status_t sr_decode_expr(memory_context_t *mem_ctx, void *data, void **expr)
{
    return sr_decode_expr_tree(mem_ctx, (char *)data, 0, (expr_tree_t **)expr);
}

status_t sr_decode_expr_list(memory_context_t *mem_ctx, void *data, uint32 offset, uint32 num, ...)
{
    errno_t errcode = 0;
    sr_list_t *sr_list = (sr_list_t *)data;
    va_list list;
    char *expr_data = NULL;
    uint32 len;
    status_t status = OG_SUCCESS;

    va_start(list, num);

    for (uint32 i = 0; i < num; i++) {
        void **expr = va_arg(list, void **);
        if (num == 1 || i == num - 1) {
            len = offset - sr_list->cell[i];
        } else {
            len = sr_list->cell[i + 1] - sr_list->cell[i];
        }

        status = sr_alloc_mem(mem_ctx, len, (void **)&expr_data);
        OG_BREAK_IF_TRUE(status != OG_SUCCESS);
        if (len != 0) {
            errcode = memcpy_s(expr_data, len, (char *)data + sr_list->cell[i], len);
            if (errcode != EOK) {
                OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                status = OG_ERROR;
                break;
            }
        }
        status = sr_decode_expr(mem_ctx, (void *)expr_data, expr);
        OG_BREAK_IF_TRUE(status != OG_SUCCESS);
    }

    va_end(list);
    return status;
}

static status_t sr_decode_cmp_node(memory_context_t *mem_ctx, char *sr_data, uint32 offset, cmp_node_t **node)
{
    if (offset == SR_NULL) {
        *node = NULL;
        return OG_SUCCESS;
    }

    sr_cmp_node_t *sr_cmp_node = (sr_cmp_node_t *)(sr_data + offset);
    OG_RETURN_IFERR(sr_alloc_mem(mem_ctx, sizeof(cmp_node_t), (void **)node));

    (*node)->join_type = sr_cmp_node->join_type;
    (*node)->type = sr_cmp_node->type;
    OG_RETURN_IFERR(sr_decode_expr_tree(mem_ctx, sr_data, sr_cmp_node->left, &(*node)->left));
    return sr_decode_expr_tree(mem_ctx, sr_data, sr_cmp_node->right, &(*node)->right);
}

static status_t sr_decode_cond_node(memory_context_t *mem_ctx, char *sr_data, uint32 offset, cond_node_t **node)
{
    if (offset == SR_NULL) {
        *node = NULL;
        return OG_SUCCESS;
    }

    sr_cond_node_t *sr_cond_node = (sr_cond_node_t *)(sr_data + offset);
    OG_RETURN_IFERR(sr_alloc_mem(mem_ctx, sizeof(cond_node_t), (void **)node));

    (*node)->type = sr_cond_node->type;

    switch (sr_cond_node->type) {
        case COND_NODE_COMPARE:
            OG_RETURN_IFERR(sr_decode_cmp_node(mem_ctx, sr_data, sr_cond_node->cmp, &(*node)->cmp));
            break;
        case COND_NODE_TRUE:
        case COND_NODE_FALSE:
            break;
        default:
            OG_RETURN_IFERR(sr_decode_cond_node(mem_ctx, sr_data, sr_cond_node->left, &(*node)->left));
            OG_RETURN_IFERR(sr_decode_cond_node(mem_ctx, sr_data, sr_cond_node->right, &(*node)->right));
            break;
    }

    return OG_SUCCESS;
}

static status_t sr_decode_cond_tree(memory_context_t *mem_ctx, char *sr_data, uint32 offset, cond_tree_t **cond)
{
    if (offset == SR_NULL) {
        *cond = NULL;
        return OG_SUCCESS;
    }

    sr_cond_tree_t *sr_cond = (sr_cond_tree_t *)(sr_data + offset);

    OG_RETURN_IFERR(sr_alloc_mem(mem_ctx, sizeof(cond_tree_t), (void **)cond));
    sql_init_cond_tree(mem_ctx, (*cond), (ga_alloc_func_t)sr_alloc_mem);
    (*cond)->rownum_upper = sr_cond->rownum_upper;
    (*cond)->loc = sr_cond->loc;

    return sr_decode_cond_node(mem_ctx, sr_data, sr_cond->root, &(*cond)->root);
}

status_t sr_decode_cond(memory_context_t *context, void *data, void **expr)
{
    return sr_decode_cond_tree(context, (char *)data, 0, (cond_tree_t **)expr);
}
static status_t sr_decode_simple_case_pair(memory_context_t *context, char *sr_data, uint32 offset, galist_t *list)
{
    case_pair_t *pair = NULL;

    if (offset == SR_NULL) {
        list->count = 0;
        return OG_SUCCESS;
    }

    sr_case_pair_t *sr_case_pair = (sr_case_pair_t *)(sr_data + offset);
    OG_RETURN_IFERR(cm_galist_new(list, sizeof(case_pair_t), (void **)&pair));

    OG_RETURN_IFERR(sr_decode_expr_tree(context, sr_data, sr_case_pair->when_expr, &pair->when_expr));

    return sr_decode_expr_tree(context, sr_data, sr_case_pair->value, &pair->value);
}

static status_t sr_decode_searched_case_pair(memory_context_t *context, char *sr_data, uint32 offset, galist_t *list)
{
    case_pair_t *pair = NULL;

    if (offset == SR_NULL) {
        list->count = 0;
        return OG_SUCCESS;
    }

    sr_case_pair_t *sr_case_pair = (sr_case_pair_t *)(sr_data + offset);
    OG_RETURN_IFERR(cm_galist_new(list, sizeof(case_pair_t), (void **)&pair));

    OG_RETURN_IFERR(sr_decode_cond_tree(context, sr_data, sr_case_pair->when_cond, &pair->when_cond));
    return sr_decode_expr_tree(context, sr_data, sr_case_pair->value, &pair->value);
}

static status_t sr_decode_case_when(memory_context_t *mem_ctx, char *sr_data, uint32 offset, case_expr_t **case_expr)
{
    if (offset == SR_NULL) {
        *case_expr = NULL;
        return OG_SUCCESS;
    }

    sr_case_expr_t *sr_case_expr = (sr_case_expr_t *)(sr_data + offset);
    OG_RETURN_IFERR(sr_alloc_mem(mem_ctx, sizeof(case_expr_t), (void **)case_expr));

    (*case_expr)->is_cond = sr_case_expr->is_cond;
    cm_galist_init(&(*case_expr)->pairs, (void *)mem_ctx, (ga_alloc_func_t)sr_alloc_mem);

    if (!sr_case_expr->is_cond) {
        OG_RETURN_IFERR(sr_decode_expr_tree(mem_ctx, sr_data, sr_case_expr->expr, &(*case_expr)->expr));
        OG_RETURN_IFERR(
            sr_decode_list(mem_ctx, sr_data, sr_case_expr->pairs, &(*case_expr)->pairs, sr_decode_simple_case_pair));
    } else {
        OG_RETURN_IFERR(
            sr_decode_list(mem_ctx, sr_data, sr_case_expr->pairs, &(*case_expr)->pairs, sr_decode_searched_case_pair));
    }

    return sr_decode_expr_tree(mem_ctx, sr_data, sr_case_expr->default_expr, &(*case_expr)->default_expr);
}
