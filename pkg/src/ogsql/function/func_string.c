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
 * func_string.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/function/func_string.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_string.h"
#include "srv_instance.h"
#include "dml_executor.h"

status_t sql_func_concat_string(sql_stmt_t *stmt, text_t *result, text_t *sub, uint32 len)
{
    if (result->len + len > OG_MAX_COLUMN_SIZE) {
        OGSQL_POP(stmt);
        OG_THROW_ERROR(ERR_VALUE_ERROR, "result string length is too long, beyond the max");
        return OG_ERROR;
    }
    if (len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(result->str + result->len, OG_MAX_COLUMN_SIZE - result->len, sub->str, len));
    }
    result->len += len;
    return OG_SUCCESS;
}

static status_t sql_func_concat_arg_to_string(sql_stmt_t *stmt, expr_node_t *func, variant_t *arg_var, text_buf_t *buf)
{
    if (!OG_IS_STRING_TYPE(arg_var->type) && !OG_IS_NUMERIC_TYPE(arg_var->type) &&
        !OG_IS_DATETIME_TYPE(arg_var->type)) {
        OGSQL_POP(stmt);
        OG_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAMS,
            "the separator argument of concat_ws or concat must be a string or number or date variant.");
        return OG_ERROR;
    }

    if (var_as_string(SESSION_NLS(stmt), arg_var, buf) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_func_concat(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    char *result_buf = NULL;
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)&result_buf));
    text_t result_text = { result_buf, 0 };

    expr_tree_t *arg = func->argument;
    variant_t arg_var;

    result->is_null = OG_TRUE;
    result->type = OG_TYPE_STRING;

    while (arg != NULL) {
        SQL_EXEC_FUNC_ARG(arg, &arg_var, result, stmt);
        if (!arg_var.is_null) {
            char arg_buf[OG_MAX_NUMBER_LEN] = { 0 };
            text_buf_t buffer;

            CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN, arg_buf);
            OG_RETURN_IFERR(sql_func_concat_arg_to_string(stmt, func, &arg_var, &buffer));
            OG_RETURN_IFERR(sql_func_concat_string(stmt, &result_text, &arg_var.v_text, arg_var.v_text.len));

            result->is_null = OG_FALSE;
        }
        arg = arg->next;
    }

    result->v_text = result_text;
    if (!result->is_null && (result->v_text.len == 0 && g_instance->sql.enable_empty_string_null)) {
        OGSQL_POP(stmt);
        SQL_SET_NULL_VAR(result);
    }

    return OG_SUCCESS;
}

status_t sql_verify_concat(sql_verifier_t *verf, expr_node_t *func)
{
    uint32 concat_len = 0;

    CM_POINTER2(verf, func);
    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 1, OG_INVALID_ID16, OG_INVALID_ID32));
    func->datatype = OG_TYPE_STRING;

    expr_tree_t *expr = func->argument;
    while (expr != NULL) {
        concat_len += cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
        if (concat_len > OG_MAX_COLUMN_SIZE) {
            concat_len = OG_MAX_COLUMN_SIZE;
            break;
        }
        expr = expr->next;
    }

    func->size = (uint16)concat_len;
    return OG_SUCCESS;
}

status_t sql_func_concat_ws(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t seperator_var;
    expr_tree_t *sep_arg = func->argument;
    char seperator_buf[OG_MAX_NUMBER_LEN] = { 0 };
    text_buf_t buffer;

    SQL_EXEC_FUNC_ARG_EX(sep_arg, &seperator_var, result);

    CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN, seperator_buf);
    OG_RETURN_IFERR(sql_func_concat_arg_to_string(stmt, func, &seperator_var, &buffer));
    sql_keep_stack_variant(stmt, &seperator_var);

    char *result_buf = NULL;
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)&result_buf));
    text_t result_text = { result_buf, 0 };
    expr_tree_t *arg = sep_arg->next;
    variant_t arg_var;

    result->is_null = OG_TRUE;
    result->type = OG_TYPE_STRING;

    bool32 need_append_seperator = OG_FALSE;
    while (arg != NULL) {
        SQL_EXEC_FUNC_ARG(arg, &arg_var, result, stmt);
        if (!arg_var.is_null) {
            char arg_buf[OG_MAX_NUMBER_LEN] = { 0 };

            CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN, arg_buf);
            OG_RETURN_IFERR(sql_func_concat_arg_to_string(stmt, func, &arg_var, &buffer));

            if (need_append_seperator) {
                OG_RETURN_IFERR(
                    sql_func_concat_string(stmt, &result_text, &seperator_var.v_text, seperator_var.v_text.len));
            }
            OG_RETURN_IFERR(sql_func_concat_string(stmt, &result_text, &arg_var.v_text, arg_var.v_text.len));
            need_append_seperator = OG_TRUE;

            result->is_null = OG_FALSE;
        }
        arg = arg->next;
    }

    result->v_text = result_text;
    if (!result->is_null && result->v_text.len == 0 && g_instance->sql.enable_empty_string_null) {
        OGSQL_POP(stmt);
        SQL_SET_NULL_VAR(result);
    }

    return OG_SUCCESS;
}

status_t sql_verify_concat_ws(sql_verifier_t *verf, expr_node_t *func)
{
    expr_tree_t *sep_arg = NULL;
    expr_tree_t *expr = NULL;
    uint16 seperator_size;
    uint32 concat_len;

    CM_POINTER2(verf, func);
    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, OG_INVALID_ID16, OG_INVALID_ID32));
    func->datatype = OG_TYPE_STRING;

    sep_arg = func->argument;
    seperator_size = cm_get_datatype_strlen(sep_arg->root->datatype, sep_arg->root->size);
    expr = sep_arg->next;
    concat_len = cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
    expr = expr->next;
    while (expr != NULL) {
        concat_len += seperator_size;
        concat_len += cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
        if (concat_len > OG_MAX_COLUMN_SIZE) {
            concat_len = OG_MAX_COLUMN_SIZE;
            break;
        }
        expr = expr->next;
    }

    func->size = (uint16)concat_len;
    return OG_SUCCESS;
}

static status_t sql_verify_empty_lob(sql_verifier_t *verf, expr_node_t *func, og_type_t datatype)
{
    CM_POINTER2(verf, func);
    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 0, 0, OG_INVALID_ID32));
    func->datatype = datatype;
    func->size = g_instance->sql.sql_lob_locator_size;
    return OG_SUCCESS;
}

static status_t sql_func_empty_lob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, og_type_t datatype)
{
    cm_reset_vm_lob(&result->v_lob.vm_lob);
    result->v_lob.type = OG_LOB_FROM_VMPOOL;
    result->type = datatype;
    result->is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_func_empty_blob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_empty_lob(stmt, func, result, OG_TYPE_BLOB);
}

status_t sql_verify_empty_blob(sql_verifier_t *verf, expr_node_t *func)
{
    return sql_verify_empty_lob(verf, func, OG_TYPE_BLOB);
}

status_t sql_func_empty_clob(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_empty_lob(stmt, func, result, OG_TYPE_CLOB);
}

status_t sql_verify_empty_clob(sql_verifier_t *verf, expr_node_t *func)
{
    return sql_verify_empty_lob(verf, func, OG_TYPE_CLOB);
}

static int32 sql_get_pos_in_set(const text_t *sub, const text_t *src_text)
{
    uint32 pos = 1;
    char *pre_comma = src_text->str;
    char *after_comma = src_text->str;

    if ((src_text->len == 0) && (sub->len == 0)) {
        return 0;
    }

    for (uint32 i = 0; i < src_text->len; i++) {
        if (src_text->str[i] == ',') {
            text_t phrase = { pre_comma, (uint32)(after_comma - pre_comma) };
            if (cm_text_equal(&phrase, sub)) {
                return pos;
            } else {
                pre_comma = src_text->str + i + 1;
                after_comma = src_text->str + i + 1;
            }
            pos++;
        } else {
            after_comma++;
        }
    }

    text_t phrase = { pre_comma, (uint32)(after_comma - pre_comma) };
    if (cm_text_equal(&phrase, sub)) {
        return pos;
    }

    return 0;
}

status_t sql_func_find_in_set(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    text_t *text1 = NULL;
    text_t *text2 = NULL;
    variant_t var1;
    variant_t var2;

    arg1 = func->argument;
    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg1, &var1, &text1));
    SQL_CHECK_COLUMN_VAR(&var1, res);
    if (var1.is_null) {
        res->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    arg2 = arg1->next;
    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg2, &var2, &text2));
    SQL_CHECK_COLUMN_VAR(&var2, res);
    if (var2.is_null) {
        res->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    res->v_int = sql_get_pos_in_set(text1, text2);
    res->is_null = OG_FALSE;
    res->type = OG_TYPE_INTEGER;
    return OG_SUCCESS;
}

status_t sql_verify_find_in_set(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32));

    func->datatype = OG_TYPE_INTEGER;
    func->size = sizeof(int32);

    return OG_SUCCESS;
}

static status_t sql_func_insert_core(sql_stmt_t *stmt, text_t *str, int32 pos, int32 temp_len, text_t *newstr,
    variant_t *res)
{
    uint32 chr_len;
    uint32 bytes_len;
    uint32 newstr_len;
    int32 keep_chr_len;
    int32 left_chr_len;
    int len = temp_len;

    OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(str, &chr_len));
    OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(newstr, &newstr_len));

    // pos can be [1, chr_len+1), if not return str as result
    if (pos < 1 || pos >= (int32)chr_len + 1) {
        res->v_text = *str;
        return OG_SUCCESS;
    }

    if (len < 0 || len > (int32)chr_len - 1) {
        len = (int32)chr_len > (int32)newstr_len ? (int32)chr_len : (int32)newstr_len;
    }

    // keep_chr_len can be [0, chr_len)
    keep_chr_len = pos - 1;
    left_chr_len = (int32)chr_len - keep_chr_len - len;

    OG_RETURN_IFERR(sql_push(stmt, (str->len + newstr->len), (void *)&res->v_text.str));
    res->v_text.len = 0;

    if (keep_chr_len > 0) {
        bytes_len = 0;
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->get_start_byte_pos(str, (uint32)keep_chr_len, &bytes_len));
        if (bytes_len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(res->v_text.str, bytes_len, str->str, bytes_len));
        }
        res->v_text.len += bytes_len;
    }
    if (newstr->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(res->v_text.str + res->v_text.len, newstr->len, newstr->str, newstr->len));
    }
    res->v_text.len += newstr->len;

    if (left_chr_len > 0) {
        bytes_len = 0;
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->get_start_byte_pos(str, (uint32)(keep_chr_len + len), &bytes_len));
        if ((str->len - bytes_len) != 0) {
            MEMS_RETURN_IFERR(memcpy_s(res->v_text.str + res->v_text.len, (str->len - bytes_len),
                (str->str + bytes_len), (str->len - bytes_len)));
        }
        res->v_text.len += (str->len - bytes_len);
    }

    return OG_SUCCESS;
}


status_t sql_func_insert(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    /* Syntax: insert(str, pos, len, newstr) */
    variant_t var1;
    variant_t var2;
    variant_t var3;
    variant_t var4;

    CM_POINTER3(stmt, func, res);

    res->type = OG_TYPE_STRING;
    res->is_null = OG_FALSE;

    // get argument str
    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    sql_keep_stack_variant(stmt, &var1);
    if (!OG_IS_STRING_TYPE(var1.type)) {
        OG_RETURN_IFERR(sql_var_as_string(stmt, &var1));
    }

    // get argument pos
    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    OG_RETURN_IFERR(var_as_integer(&var2));

    // get argument len
    expr_tree_t *arg3 = arg2->next;
    SQL_EXEC_FUNC_ARG_EX(arg3, &var3, res);
    OG_RETURN_IFERR(var_as_integer(&var3));

    // get argument newstr
    expr_tree_t *arg4 = arg3->next;
    SQL_EXEC_FUNC_ARG_EX(arg4, &var4, res);
    sql_keep_stack_variant(stmt, &var4);
    if (!OG_IS_STRING_TYPE(var4.type)) {
        OG_RETURN_IFERR(sql_var_as_string(stmt, &var4));
    }

    OG_RETURN_IFERR(sql_func_insert_core(stmt, &var1.v_text, var2.v_int, var3.v_int, &var4.v_text, res));
    // result size can't be large than func verified size
    res->v_text.len = MIN(res->v_text.len, func->size);
    return OG_SUCCESS;
}

status_t sql_verify_insert_func(sql_verifier_t *verifier, expr_node_t *func)
{
    uint32 insert_len;

    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 4, 4, OG_INVALID_ID32));

    func->datatype = OG_TYPE_STRING;

    expr_tree_t *expr = func->argument;
    insert_len = cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
    expr = expr->next->next->next;
    insert_len += cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
    func->size = (uint16)MIN(insert_len, OG_MAX_COLUMN_SIZE);

    return OG_SUCCESS;
}

static inline status_t sql_func_instr_char(const text_t *str, const text_t *substr, int32 pos, uint32 nth,
    bool32 *has_utf8, uint32 *result)
{
    *result = GET_DATABASE_CHARSET->instr(str, substr, pos, nth, has_utf8);

    // transform binary len to utf-8 len
    if (*result > 0 && *has_utf8) {
        text_t v_text = { str->str, *result - (uint32)1 };
        uint32 char_len = 0;
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&v_text, &char_len));
        *result = char_len + (uint32)1;
    }
    return OG_SUCCESS;
}

static status_t sql_func_instr_get_s_n(sql_stmt_t *stmt, variant_t *result, expr_tree_t *expr, variant_t *var_p,
    variant_t *var_n, bool32 *is_over)
{
    *is_over = OG_TRUE;

    expr_tree_t *expr_p = expr->next;

    if (expr_p != NULL) {
        if (sql_exec_expr(stmt, expr_p, var_p) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_CALC_EXPRESSION, "start_position expression node");
            return OG_ERROR;
        }
        SQL_CHECK_COLUMN_VAR(var_p, result);
        if (var_p->is_null) {
            SQL_SET_NULL_VAR(result);
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(var_as_floor_integer(var_p));

        expr_tree_t *expr_n = expr_p->next;

        if (expr_n != NULL) {
            if (sql_exec_expr(stmt, expr_n, var_n) != OG_SUCCESS) {
                OG_THROW_ERROR(ERR_CALC_EXPRESSION, "nth_appearance expression node");
                return OG_ERROR;
            }
            SQL_CHECK_COLUMN_VAR(var_n, result);
            if (var_n->is_null) {
                SQL_SET_NULL_VAR(result);
                return OG_SUCCESS;
            }

            OG_RETURN_IFERR(var_as_floor_integer(var_n));

            if (var_n->v_int <= 0) {
                OG_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "argument '%d' is out of range", var_n->v_int);
                return OG_ERROR;
            }
        } else {
            var_n->v_int = 1;
        }
    } else {
        var_p->v_int = 1;
        var_n->v_int = 1;
    }

    *is_over = OG_FALSE;
    return OG_SUCCESS;
}

static status_t sql_func_instr_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *res, bool32 is_special)
{
    expr_tree_t *arg1 = func->argument;
    variant_t var1;
    variant_t var2;
    variant_t var3;
    variant_t var4;
    bool32 is_over = OG_TRUE;
    bool32 has_utf8 = OG_FALSE;

    CM_POINTER3(stmt, func, res);

    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    sql_keep_stack_variant(stmt, &var1);
    if (sql_var_as_string(stmt, &var1) != OG_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return OG_ERROR;
    }

    if (var1.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    sql_keep_stack_variant(stmt, &var2);
    if (sql_var_as_string(stmt, &var2) != OG_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return OG_ERROR;
    }

    if (var2.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    // get start_position and nth_appearance
    OG_RETURN_IFERR(sql_func_instr_get_s_n(stmt, res, arg2, &var3, &var4, &is_over));
    if (is_over) {
        return OG_SUCCESS;
    }

    if (is_special) {
        OG_RETURN_IFERR(sql_func_instr_char(&var1.v_text, &var2.v_text, var3.v_int, var4.v_int, &has_utf8,
            (uint32 *)&res->v_int));
    } else {
        res->v_int = cm_instrb(&var1.v_text, &var2.v_text, var3.v_int, var4.v_int);
    }

    res->type = OG_TYPE_INTEGER;
    res->is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_func_instr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_instr_core(stmt, func, result, OG_TRUE);
}

status_t sql_func_instrb(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_instr_core(stmt, func, result, OG_FALSE);
}

status_t sql_verify_instr(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 4, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_INTEGER;
    func->size = OG_INTEGER_SIZE;

    return OG_SUCCESS;
}

static void sql_func_inet_aton_core(sql_stmt_t *stmt, text_t *ip, variant_t *res)
{
    uint32 dot_count = 0;
    char *end = ip->str + ip->len;

    // current byte value after prev '.'
    uint32 byte = 0;

    // ip value before prev '.'
    res->v_bigint = 0;
    for (char *p = ip->str; p < end; p++) {
        uint32 digit;

        digit = *p - '0';
        if (digit >= 0 && digit <= 9) {
            byte = byte * 10 + digit;
            if (byte > 255) {
                SQL_SET_NULL_VAR(res);
                return;
            }
        } else if (*p == '.') {
            // return NULL if '.' is last char or too many '.'
            if (++dot_count > 3 || p + 1 == end) {
                SQL_SET_NULL_VAR(res);
                return;
            }
            res->v_bigint = (int64)(((uint64)res->v_bigint << 8) + byte);
            byte = 0;
        } else {
            SQL_SET_NULL_VAR(res);
            return;
        }
    }

    res->type = OG_TYPE_BIGINT;
    res->is_null = OG_FALSE;
    res->v_bigint = (int64)(((uint64)res->v_bigint << (8 * (4 - dot_count))) + byte);
}

status_t sql_func_inet_aton(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    variant_t var1;

    CM_POINTER3(stmt, func, res);

    res->type = OG_TYPE_BIGINT;

    expr_tree_t *arg1 = func->argument;
    CM_POINTER(arg1);
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    sql_keep_stack_variant(stmt, &var1);

    OG_RETURN_IFERR(sql_var_as_string(stmt, &var1));
    if (var1.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    sql_func_inet_aton_core(stmt, &var1.v_text, res);
    return OG_SUCCESS;
}

status_t sql_verify_inet_aton(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));

    func->datatype = OG_TYPE_BIGINT;
    func->size = sizeof(int64);
    return OG_SUCCESS;
}

static status_t _get_strlen_from_var(variant_t *var, uint32 *len)
{
    int overflow;
    if (var_as_bigint_ex(var, &overflow) == OG_SUCCESS) {
        if (var->v_bigint > 0 && var->v_bigint <= OG_MAX_UINT32) {
            *len = (uint32)var->v_bigint;
            return OG_SUCCESS;
        } else if (var->v_bigint <= 0) {
            *len = 0;
            return OG_SUCCESS;
        } else {
            *len = OG_MAX_UINT32;
            return OG_SUCCESS;
        }
    }

    switch (overflow) {
        case OVERFLOW_UPWARD:
            *len = OG_MAX_UINT32;
            return OG_SUCCESS;

        case OVERFLOW_DOWNWARD:
            *len = 0;
            return OG_SUCCESS;

        case OVERFLOW_NONE:
        default:
            return OG_ERROR;
    }
}

static status_t sql_func_left_right_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *res, int direction)
{
    uint32 len;
    variant_t arg_str;
    variant_t arg_len;
    status_t ret;

    CM_POINTER3(stmt, func, res);

    if (sql_exec_expr_node(stmt, func->argument->root, &arg_str) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return OG_ERROR;
    }

    SQL_CHECK_COLUMN_VAR(&arg_str, res);
    sql_keep_stack_variant(stmt, &arg_str);
    if (arg_str.is_null) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    if (sql_var_as_string(stmt, &arg_str) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "convert to string failed.");
        return OG_ERROR;
    }

    if (sql_exec_expr_node(stmt, func->argument->next->root, &arg_len) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return OG_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(&arg_len, res);

    if (arg_len.is_null) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    if (_get_strlen_from_var(&arg_len, &len) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        res->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, arg_str.v_text.len, (void **)&res->v_text.str));
    res->type = OG_TYPE_STRING;
    res->is_null = OG_FALSE;

    ret = (direction == SQL_FUNC_LEFT) ?
        GET_DATABASE_CHARSET->substr_left(&arg_str.v_text, 1, len, &res->v_text) :
        GET_DATABASE_CHARSET->substr_right(&arg_str.v_text, len, len, &res->v_text, OG_TRUE);
    OG_RETURN_IFERR(ret);

    if (res->v_text.len == 0 && g_instance->sql.enable_empty_string_null) {
        res->is_null = OG_TRUE;
    }
    return OG_SUCCESS;
}

/*
    left(str, len): Returns the leftmost len characters from the string str.
    Note:
        1.Return empty string if len <= 0.
        2.Return null if any parameter is illegal.
*/
status_t sql_func_left(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_left_right_core(stmt, func, res, SQL_FUNC_LEFT);
}

/*
    right(str, len): Returns the rightmost len characters from the string str
    Note:
        1.Return empty string if len <= 0.
        2.Return null if any parameter is illegal.
*/
status_t sql_func_right(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_left_right_core(stmt, func, res, SQL_FUNC_RIGHT);
}

static inline status_t sql_verify_lr(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 2, 2, OG_INVALID_ID32));

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return OG_SUCCESS;
}

status_t sql_verify_left(sql_verifier_t *verif, expr_node_t *func)
{
    return sql_verify_lr(verif, func);
}

status_t sql_verify_right(sql_verifier_t *verif, expr_node_t *func)
{
    return sql_verify_lr(verif, func);
}

status_t sql_func_length_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *res, bool32 is_lob_func)
{
    expr_tree_t *arg_node = NULL;
    variant_t arg_var;
    char *buf = NULL;
    text_buf_t buffer;
    uint32 len;

    CM_POINTER3(stmt, func, res);
    arg_node = func->argument;
    CM_POINTER(arg_node);

    SQL_EXEC_LENGTH_FUNC_ARG(arg_node, &arg_var, res, stmt);

    if (is_lob_func && !sql_verify_lob_func_args(arg_var.type)) {
        OG_SRC_THROW_ERROR(arg_node->root->loc, ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(arg_var.type));
        return OG_ERROR;
    }

    sql_keep_stack_variant(stmt, &arg_var);

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_NUMBER_LEN + 1, (void **)&buf));
    CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN + 1, buf);

    switch (arg_var.type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BIGINT:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DECIMAL:
            if (var_as_string(SESSION_NLS(stmt), &arg_var, &buffer) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            res->v_bigint = arg_var.v_text.len;
            break;

        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_INTERVAL_DS:
            if (datetype_as_string(SESSION_NLS(stmt), &arg_var, &arg_node->root->typmod, &buffer) != OG_SUCCESS) {
                OGSQL_POP(stmt);
                return OG_ERROR;
            }
            res->v_bigint = arg_var.v_text.len;
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&arg_var.v_text, &len));
            res->v_bigint = len;
            break;

        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
            res->v_bigint = arg_var.v_bin.size;
            break;
        case OG_TYPE_RAW: // oracle length(raw)
            if (g_instance->sql.string_as_hex_binary) {
                res->v_bigint = arg_var.v_bin.size;
            } else {
                res->v_bigint = arg_var.v_bin.size * 2;
            }
            break;

        case OG_TYPE_CLOB:
            res->v_bigint = 0;
            OG_RETURN_IFERR(sql_get_utf8_clob_char_len(stmt, &arg_var, &len));
            res->v_bigint = len;
            break;

        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            res->v_bigint = sql_get_lob_var_length(&arg_var);
            break;

        default:
            OG_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(arg_var.type));
            return OG_ERROR;
    }
    res->type = OG_TYPE_BIGINT;
    res->is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_func_length(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_length_core(stmt, func, res, OG_FALSE);
}

static status_t sql_func_lengthb_core(sql_stmt_t *stmt, variant_t *arg_var, expr_tree_t *arg_node, variant_t *res,
    text_buf_t buffer)
{
    switch (arg_var->type) {
        case OG_TYPE_UINT32:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BOOLEAN:
        case OG_TYPE_BIGINT:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DECIMAL:
            OG_RETURN_IFERR(var_as_string(SESSION_NLS(stmt), arg_var, &buffer));
            res->v_bigint = arg_var->v_text.len;
            break;

        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_TIMESTAMP_TZ_FAKE:
        case OG_TYPE_TIMESTAMP_TZ:
        case OG_TYPE_TIMESTAMP_LTZ:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_INTERVAL_DS:
            OG_RETURN_IFERR(datetype_as_string(SESSION_NLS(stmt), arg_var, &arg_node->root->typmod, &buffer));
            res->v_bigint = arg_var->v_text.len;
            break;

        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
            res->v_bigint = arg_var->v_text.len;
            break;
        case OG_TYPE_BINARY:
        case OG_TYPE_VARBINARY:
            res->v_bigint = arg_var->v_bin.size;
            break;
        case OG_TYPE_RAW:
            res->v_bigint = (g_instance->sql.string_as_hex_binary) ? arg_var->v_bin.size : arg_var->v_bin.size * 2;
            break;

        case OG_TYPE_CLOB:
        case OG_TYPE_BLOB:
        case OG_TYPE_IMAGE:
            res->v_bigint = sql_get_lob_var_length(arg_var);
            break;

        default:
            OG_THROW_ERROR(ERR_UNSUPPORT_DATATYPE, get_datatype_name_str(arg_var->type));
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_func_lengthb(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg_node = func->argument;
    variant_t arg_var;
    char *buf = NULL;
    text_buf_t buffer;

    CM_POINTER3(stmt, func, res);

    SQL_EXEC_LENGTH_FUNC_ARG(arg_node, &arg_var, res, stmt);
    sql_keep_stack_variant(stmt, &arg_var);

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_NUMBER_LEN + 1, (void **)&buf));
    CM_INIT_TEXTBUF(&buffer, OG_MAX_NUMBER_LEN + 1, buf);
    if (sql_func_lengthb_core(stmt, &arg_var, arg_node, res, buffer) != OG_SUCCESS) {
        OGSQL_POP(stmt);
        return OG_ERROR;
    }

    res->type = OG_TYPE_BIGINT;
    res->is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_verify_length(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_BIGINT;
    func->size = OG_BIGINT_SIZE;

    return OG_SUCCESS;
}

static status_t sql_func_locate_core(variant_t *res, variant_t *var1, variant_t *var2, uint32 pos)
{
    bool32 has_utf8 = OG_FALSE;

    res->v_int = GET_DATABASE_CHARSET->instr(&var2->v_text, &var1->v_text, pos, 1, &has_utf8);
    // transform binary len to char len
    if (res->v_int > 0 && has_utf8) {
        text_t v_text = { var2->v_text.str, res->v_int - 1 };
        uint32 char_len = 0;
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(&v_text, &char_len));
        res->v_int = char_len + 1;
    }
    return OG_SUCCESS;
}

status_t sql_func_locate(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    /* Syntax: locate(substr, str, [pos]) */
    variant_t var1;
    variant_t var2;
    variant_t var3;
    uint32 pos = 0;

    CM_POINTER3(stmt, func, res);

    res->type = OG_TYPE_INTEGER;
    res->is_null = OG_FALSE;

    // get argument substr
    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    sql_keep_stack_variant(stmt, &var1);
    if (!OG_IS_STRING_TYPE(var1.type)) {
        OG_RETURN_IFERR(sql_var_as_string(stmt, &var1));
    }

    // get argument str
    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    sql_keep_stack_variant(stmt, &var2);
    if (!OG_IS_STRING_TYPE(var2.type)) {
        OG_RETURN_IFERR(sql_var_as_string(stmt, &var2));
    }

    // get argument pos
    expr_tree_t *arg3 = arg2->next;
    if (arg3 != NULL) {
        SQL_EXEC_FUNC_ARG(arg3, &var3, res, stmt);
        if (var3.is_null) {
            res->v_int = 0;
            return OG_SUCCESS;
        }

        OG_RETURN_IFERR(var_as_integer(&var3));
        if (var3.v_int <= 0) {
            res->v_int = 0;
            return OG_SUCCESS;
        }

        pos = var3.v_int;
    } else {
        pos = 1;
    }

    OG_RETURN_IFERR(sql_func_locate_core(res, &var1, &var2, pos));

    return OG_SUCCESS;
}

status_t sql_verify_locate(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 2, 3, OG_INVALID_ID32));

    func->datatype = OG_TYPE_INTEGER;
    func->size = sizeof(int32);
    return OG_SUCCESS;
}

static status_t sql_func_lower_upper_utf8(sql_stmt_t *stmt, variant_t *res, bool32 isUpper)
{
    wchar_t *tmp_w = NULL;
    size_t temp_c_size;
    size_t temp_w_size;
    size_t num_of_wchar;
    size_t num_of_char;
    status_t stat = OG_ERROR;

    OGSQL_SAVE_STACK(stmt);
    do {
        temp_w_size = (res->v_text.len + 1) * sizeof(wchar_t);
        OG_BREAK_IF_ERROR(sql_push(stmt, (uint32)temp_w_size, (void **)&tmp_w));
        MEMS_RETURN_IFERR(memset_s(tmp_w, temp_w_size, 0, temp_w_size));
        temp_c_size = res->v_text.len;
        char *temp_c = res->v_text.str;

#ifdef WIN32
        OG_BREAK_IF_ERROR(cm_multibyte_to_widechar(cm_get_cp_id(GET_CHARSET_ID), temp_c, temp_c_size, tmp_w,
            temp_w_size, &num_of_wchar));
#else
        OG_BREAK_IF_ERROR(cm_multibyte_to_widechar(stmt->session->agent->env[0], temp_c, temp_c_size, tmp_w,
            temp_w_size, &num_of_wchar));
#endif

        size_t i = 0;
        if (isUpper) {
            while (i < num_of_wchar) {
                tmp_w[i] = towupper(tmp_w[i]);
                i++;
            }
        } else {
            while (i < num_of_wchar) {
                tmp_w[i] = towlower(tmp_w[i]);
                i++;
            }
        }

        temp_c_size = num_of_wchar * cm_get_max_size(GET_CHARSET_ID);
        OG_BREAK_IF_ERROR(sql_push(stmt, (uint32)temp_c_size, (void **)&temp_c));
        MEMS_RETURN_IFERR(memset_s(temp_c, temp_c_size, 0, temp_c_size));
        temp_w_size = num_of_wchar * sizeof(wchar_t);

#ifdef WIN32
        OG_BREAK_IF_ERROR(cm_widechar_to_multibyte(cm_get_cp_id(GET_CHARSET_ID), tmp_w, temp_w_size, temp_c,
            temp_c_size, &num_of_char));
#else
        OG_BREAK_IF_ERROR(cm_widechar_to_multibyte(stmt->session->agent->env[1], tmp_w, temp_w_size, temp_c,
            temp_c_size, &num_of_char));
#endif

        res->v_text.str = temp_c;
        res->v_text.len = (uint32)num_of_char;

        stat = OG_SUCCESS;
    } while (0);
    OGSQL_RESTORE_STACK(stmt);

    return stat;
}

static status_t sql_func_lower_upper_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 isUpper)
{
    expr_tree_t *arg_node = func->argument;
    variant_t arg_var;
    char *buf = NULL;

    CM_POINTER3(stmt, func, result);

    SQL_EXEC_FUNC_ARG_EX(arg_node, &arg_var, result);

    sql_keep_stack_variant(stmt, &arg_var);

    if (!OG_IS_STRING_TYPE(arg_var.type) && !OG_IS_BINARY_TYPE(arg_var.type)) {
        if (sql_var_as_string(stmt, &arg_var) != OG_SUCCESS) {
            cm_set_error_loc(arg_node->loc);
            return OG_ERROR;
        }
        result->v_text = arg_var.v_text;
    } else {
        OG_RETURN_IFERR(sql_push(stmt, arg_var.v_text.len, (void **)&buf));
        if (arg_var.v_text.len != 0) {
            MEMS_RETURN_IFERR(memcpy_s(buf, arg_var.v_text.len, arg_var.v_text.str, arg_var.v_text.len));
        }
        result->v_text.str = buf;
        result->v_text.len = arg_var.v_text.len;
    }

    bool32 has_multibyte = GET_DATABASE_CHARSET->has_multibyte(result->v_text.str, result->v_text.len);
    // single byte character or setlocale failed
    if (has_multibyte && g_instance->is_setlocale_success == OG_TRUE) {
        if (sql_func_lower_upper_utf8(stmt, result, isUpper) == OG_SUCCESS) {
            result->type = func->datatype;
            result->is_null = OG_FALSE;
            OGSQL_POP(stmt);
            return OG_SUCCESS;
        } else {
            cm_reset_error();
        }
    }

    if (isUpper) {
        cm_text_upper(&result->v_text);
    } else {
        cm_text_lower(&result->v_text);
    }

    result->type = func->datatype;
    result->is_null = OG_FALSE;
    OGSQL_POP(stmt);
    return OG_SUCCESS;
}

status_t sql_func_lower(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_lower_upper_core(stmt, func, result, OG_FALSE);
}

status_t sql_verify_lower(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = (OG_TYPE_CHAR == func->argument->root->datatype) ? OG_TYPE_CHAR : OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return OG_SUCCESS;
}

static status_t sql_func_is_pad(text_t *res_str, text_t *param_str, text_t *param_pad, uint32 pad_num,
    uint32 str_size, uint32 pad_start, bool32 is_lpad)
{
    uint32 pos = 0;

    if (is_lpad) {
        for (uint32 i = 0; i < pad_num; i++) {
            MEMS_RETURN_IFERR(memcpy_sp(res_str->str + pos, str_size - pos, param_pad->str, param_pad->len));
            pos += param_pad->len;
        }
        if (pad_start != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(res_str->str + pos, str_size - pos, param_pad->str, pad_start));
        }
        pos += pad_start;
        if (param_str->len != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(res_str->str + pos, str_size - pos, param_str->str, param_str->len));
        }
    } else {
        if (param_str->len != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(res_str->str + pos, str_size - pos, param_str->str, param_str->len));
        }
        pos += param_str->len;
        for (uint32 i = 0; i < pad_num; i++) {
            MEMS_RETURN_IFERR(memcpy_sp(res_str->str + pos, str_size - pos, param_pad->str, param_pad->len));
            pos += param_pad->len;
        }
        if (pad_start != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(res_str->str + pos, str_size - pos, param_pad->str, pad_start));
        }
    }
    res_str->len = str_size;
    return OG_SUCCESS;
}

static status_t sql_compute_pad_charnum(text_t *param_str, text_t *param_pad, uint32 *pad_char_n, uint32 *pad_bytes_m,
    uint32 *totatl_size)
{
    uint32 pad_tatal_size;
    uint32 pad_m_tatal_size;
    uint32 bytes = 0;
    char *pos = param_pad->str;

    if (*totatl_size <= OG_MAX_COLUMN_SIZE) {
        return OG_SUCCESS;
    }
    *pad_bytes_m = 0;
    pad_tatal_size = OG_MAX_COLUMN_SIZE - param_str->len;
    *pad_char_n = pad_tatal_size / param_pad->len;
    pad_m_tatal_size = pad_tatal_size % param_pad->len;
    while (*pad_bytes_m < pad_m_tatal_size) {
        OG_RETURN_IFERR(GET_DATABASE_CHARSET->str_bytes(pos, (uint32)(param_pad->len - *pad_bytes_m), &bytes));
        if (*pad_bytes_m + bytes > pad_m_tatal_size) {
            break;
        }
        *pad_bytes_m += bytes;
        pos += bytes;
    }

    *totatl_size = param_str->len + (*pad_char_n) * param_pad->len + *pad_bytes_m;
    return OG_SUCCESS;
}

/* return a char string and it's bytes <= 8000
* param_n: char length
* lengthb(param_str)+n*lengthb(param_pad) + lengthb(left(param_pad, m)) <=8000
* char_length(param_str)+n*char_lengthb(param_pad) + char_length(left(param_pad, m)) =
            case last one is full utf-8 then param_n else param_n -1
*/
static status_t sql_func_pad_core(sql_stmt_t *stmt, text_t *param_str, uint32 param_n, text_t *param_pad,
    text_t *result_str, bool32 is_lpad)
{
    uint32 str_len;
    uint32 pad_len;
    uint32 remain_len;
    uint32 pad_start;
    uint32 str_size;
    uint32 pad_num;
    uint32 loop = 0;
    uint32 bytes = 0;
    uint32 cul_bytes = 0;
    char *c_pos = param_str->str;

    OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(param_str, (uint32 *)&str_len));
    if (param_str->len >= OG_MAX_COLUMN_SIZE || str_len >= param_n) {
        *result_str = *param_str;
        while (loop < param_n && cul_bytes < OG_MAX_COLUMN_SIZE) {
            OG_RETURN_IFERR(GET_DATABASE_CHARSET->str_bytes(c_pos, (uint32)(param_str->len - cul_bytes), &bytes));
            if (cul_bytes + bytes > OG_MAX_COLUMN_SIZE) {
                break;
            }
            c_pos += bytes;
            cul_bytes += bytes;
            loop++;
        }
        result_str->len = cul_bytes;
        return OG_SUCCESS;
    }

    remain_len = param_n - str_len;
    OG_RETURN_IFERR(GET_DATABASE_CHARSET->length(param_pad, (uint32 *)&pad_len));
    if (pad_len == 0) {
        OG_THROW_ERROR(ERR_ZERO_DIVIDE);
        return OG_ERROR;
    }
    OG_RETURN_IFERR(GET_DATABASE_CHARSET->get_start_byte_pos(param_pad, remain_len % pad_len, (uint32 *)&pad_start));
    pad_num = remain_len / pad_len;
    str_size = param_str->len + pad_num * param_pad->len + pad_start;
    OG_RETURN_IFERR(sql_compute_pad_charnum(param_str, param_pad, &pad_num, &pad_start, &str_size));
    OG_RETURN_IFERR(sql_push(stmt, str_size, (void **)&result_str->str));
    result_str->len = 0;

    OG_RETURN_IFERR(sql_func_is_pad(result_str, param_str, param_pad, pad_num, str_size, pad_start, is_lpad));
    return OG_SUCCESS;
}

static status_t sql_func_pad(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 is_lpad)
{
    variant_t var1;
    variant_t var2;
    variant_t var3;
    char *space = NULL;

    CM_POINTER3(stmt, func, result);

    result->is_null = OG_FALSE;
    result->type = OG_TYPE_STRING;

    // param string
    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    sql_keep_stack_variant(stmt, &var1);
    if (!OG_IS_STRING_TYPE(var1.type)) {
        OG_RETURN_IFERR(sql_var_as_string(stmt, &var1));
    }

    // param n
    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);

    OG_RETURN_IFERR(var_as_floor_integer(&var2));

    if (var2.v_int == 0) {
        // empty string as null or not
        result->v_text.len = 0;
        result->is_null = g_instance->sql.enable_empty_string_null;
        return OG_SUCCESS;
    } else if (var2.v_int < 0) {
        SQL_SET_NULL_VAR(result);
        return OG_SUCCESS;
    }

    // param pad
    expr_tree_t *arg3 = arg2->next;
    if (arg3 == NULL) {
        space = (char *)" ";
        var3.v_text.str = space;
        var3.v_text.len = 1;
    } else {
        SQL_EXEC_FUNC_ARG_EX(arg3, &var3, result);
        sql_keep_stack_variant(stmt, &var3);
        if (!OG_IS_STRING_TYPE(var3.type)) {
            OG_RETURN_IFERR(sql_var_as_string(stmt, &var3));
        }
        if (var3.v_text.len == 0) {
            OGSQL_POP(stmt);
            SQL_SET_NULL_VAR(result);
            return OG_SUCCESS;
        }
    }
    OG_RETURN_IFERR(sql_func_pad_core(stmt, &var1.v_text, (uint32)var2.v_int, &var3.v_text, &result->v_text, is_lpad));
    return OG_SUCCESS;
}

status_t sql_func_lpad(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_pad(stmt, func, result, OG_TRUE);
}

status_t sql_func_rpad(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_pad(stmt, func, result, OG_FALSE);
}

status_t sql_verify_pad(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 3, OG_INVALID_ID32));

    func->datatype = OG_TYPE_STRING;
    func->size = OG_MAX_COLUMN_SIZE;
    return OG_SUCCESS;
}

status_t sql_func_repeat(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    text_t result_buf;
    variant_t var1;
    variant_t var2;
    CM_POINTER3(stmt, func, result);
    result->is_null = OG_TRUE;
    result->type = OG_TYPE_STRING;
    result_buf.str = (char *)"";
    result_buf.len = 0;
    // param string
    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, result);
    sql_keep_stack_variant(stmt, &var1);
    if (!OG_IS_STRING_TYPE(var1.type)) {
        OG_RETURN_IFERR(sql_var_as_string(stmt, &var1));
    }
    
    // param n
    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);

    OG_RETURN_IFERR(var_as_floor_integer(&var2));

    if (var2.v_int == 0) {
        // empty string as null or not
        result->v_text.len = 0;
        result->is_null = g_instance->sql.enable_empty_string_null;
        return OG_SUCCESS;
    } else if (var2.v_int < 0) {
        SQL_SET_NULL_VAR(result);
        return OG_SUCCESS;
    } else {
        result->is_null = OG_FALSE;
    }
    uint32 total_len = (uint32)var2.v_int * var1.v_text.len;

    OG_RETURN_IFERR(sql_func_pad_core(stmt, &result_buf, total_len, &var1.v_text, &result->v_text, OG_FALSE));

    return OG_SUCCESS;
}

status_t sql_verify_repeat(sql_verifier_t *verf, expr_node_t *func)
{
    uint64 concat_len = 0;
    uint32 str_num = 0;

    CM_POINTER2(verf, func);
    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32));
    func->datatype = OG_TYPE_STRING;

    expr_tree_t *expr = func->argument;
    expr_tree_t *expr_num = func->argument->next;
    CM_POINTER(expr_num);

    if (!sql_match_num_and_str_type(TREE_DATATYPE(expr_num))) {
        OG_SRC_ERROR_REQUIRE_NUM_OR_STR(TREE_LOC(expr_num), TREE_DATATYPE(expr_num));
        return OG_ERROR;
    }
    str_num = EXPR_VALUE(uint32, expr_num);
    concat_len = cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
    concat_len *= str_num;
    if (concat_len > OG_MAX_COLUMN_SIZE) {
        concat_len = OG_MAX_COLUMN_SIZE;
    }
    func->size = (uint16)concat_len ;
    return OG_SUCCESS;
}

static status_t sql_func_trim_get_set(sql_stmt_t *stmt, expr_tree_t *expr, variant_t *set, variant_t *result,
    bool32 *is_over)
{
    expr_node_t *arg_node = expr->root;
    CM_POINTER(arg_node);

    if (sql_exec_expr_node(stmt, arg_node, set) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return OG_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(set, result);
    *is_over = OG_FALSE;

    if (set->is_null) {
        *is_over = OG_TRUE;
        SQL_SET_NULL_VAR(result);
        return OG_SUCCESS;
    }

    if (!OG_IS_STRING_TYPE(set->type)) {
        OG_RETURN_IFERR(sql_convert_variant(stmt, set, OG_TYPE_STRING));
    }

    if (set->v_text.len == 0) {
        *is_over = OG_TRUE;
        SQL_SET_NULL_VAR(result);
        return OG_SUCCESS;
    }

    sql_keep_stack_variant(stmt, set);

    return OG_SUCCESS;
}

static status_t sql_func_ltrim_core(text_t *text, const text_t *set)
{
    uint32 len;
    uint32 pos;
    text_t sub_str;

    while (text->len > 0) {
        if (GET_DATABASE_CHARSET->str_bytes((char *)text->str, text->len, &len) != OG_SUCCESS) {
            if (!g_instance->attr.enable_permissive_unicode) {
                OG_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
                return OG_ERROR;
            } else {
                cm_reset_error();
                return OG_SUCCESS;
            }
        }
        if (len == 1) {
            if (!cm_char_in_text(*text->str, set)) {
                break;
            }
        } else {
            sub_str.str = text->str;
            sub_str.len = len;
            pos = cm_instr_core(set, &sub_str, 1, 1, 0);
            if (pos == 0) {
                break;
            }
        }
        text->str += len;
        text->len -= len;
    }
    return OG_SUCCESS;
}

static status_t sql_func_ltrim_rtrim(sql_stmt_t *stmt, expr_node_t *func, variant_t *res, func_trim_type_t trim_type)
{
    status_t status;
    bool32 is_over = OG_TRUE;
    variant_t arg_var;
    variant_t arg_set;
    char *result_buff = NULL;

    CM_POINTER3(stmt, func, res);

    expr_node_t *arg_node = func->argument->root;
    CM_POINTER(arg_node);

    if (sql_exec_expr_node(stmt, arg_node, &arg_var) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_CALC_EXPRESSION, "expression node");
        return OG_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(&arg_var, res);
    if (arg_var.is_null) {
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    if (!OG_IS_STRING_TYPE(arg_var.type)) {
        OG_RETURN_IFERR(sql_convert_variant(stmt, &arg_var, OG_TYPE_STRING));
    }

    sql_keep_stack_variant(stmt, &arg_var);
    /* prepare result buffer */
    OG_RETURN_IFERR(sql_push(stmt, arg_var.v_text.len, (void **)&result_buff));

    if (func->argument->next != NULL) {
        status = sql_func_trim_get_set(stmt, func->argument->next, &arg_set, res, &is_over);
        if (status != OG_SUCCESS || is_over) {
            return status;
        }
    } else {
        /* default */
        arg_set.v_text.str = OG_BLANK_CHAR_SET;
        arg_set.v_text.len = (uint32)strlen(arg_set.v_text.str);
    }

    res->v_text = arg_var.v_text;
    switch (trim_type) {
        case FUNC_LTRIM:
            OG_RETURN_IFERR(sql_func_ltrim_core(&res->v_text, &arg_set.v_text));
            break;
        case FUNC_RTRIM:
            cm_rtrim_text_func(&res->v_text, &arg_set.v_text);
            break;
        case FUNC_BOTH:
            OG_RETURN_IFERR(sql_func_ltrim_core(&res->v_text, &arg_set.v_text));
            cm_rtrim_text_func(&res->v_text, &arg_set.v_text);
            break;
        default:
            OG_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, (int32)trim_type);
            return OG_ERROR;
    }
    if (res->v_text.len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(result_buff, arg_var.v_text.len, res->v_text.str, res->v_text.len));
    }
    res->v_text.str = result_buff;
    res->is_null = (res->v_text.len == 0 && g_instance->sql.enable_empty_string_null);
    res->type = OG_TYPE_STRING;
    return OG_SUCCESS;
}

status_t sql_func_ltrim(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_ltrim_rtrim(stmt, func, res, FUNC_LTRIM);
}

status_t sql_func_rtrim(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_ltrim_rtrim(stmt, func, res, FUNC_RTRIM);
}

/*
 * sql_func_rtrim: the actual implementation of Oracle's TRIM function
 *
 * @Note:
 * the syntax of Oracle's TRIM() is
 *
 * TRIM( { LEADING|TRAILING|BOTH [trimCharacter] FROM | trimCharacter FROM } trimSource)
 *
 */
status_t sql_func_trim(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    return sql_func_ltrim_rtrim(stmt, func, res, (func_trim_type_t)func->ext_args);
}

status_t sql_verify_rltrim(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 2, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    func->typmod.is_char = func->argument->root->typmod.is_char;

    return OG_SUCCESS;
}
/* ********************************************************************** */
/* the meaning of argument :                                            */
/* 1st arg : the trim source                                            */
/* 2nd arg : the trim characters set(optional)                          */
/* 3rd arg : the trim type(optional)                                    */
/* ********************************************************************** */
status_t sql_verify_trim(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    /* basic check */
    OG_RETURN_IFERR(sql_verify_func_node(verf, func, 1, FUNC_TRIM_ARGUMENTS_MAX_NUM, OG_INVALID_ID32));

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    func->typmod.is_char = func->argument->root->typmod.is_char;

    return OG_SUCCESS;
}

status_t sql_func_replace(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var;
    variant_t var1;
    variant_t var2;
    expr_tree_t *arg = func->argument;
    text_t *text = NULL;
    text_t *text1 = NULL;
    text_t *text2 = NULL;
    text_t *res = VALUE_PTR(text_t, result);

    result->type = OG_TYPE_STRING;

    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &var, &text));
    SQL_CHECK_COLUMN_VAR(&var, result);
    if (var.is_null) {
        result->is_null = OG_TRUE;
        return OG_SUCCESS;
    }
    arg = arg->next;
    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &var1, &text1));
    SQL_CHECK_COLUMN_VAR(&var1, result);
    int32 pos = cm_text_text(text, text1);
    if (text1->len == 0 || pos < 0) {
        *res = *text;
        result->is_null = OG_FALSE;
        return OG_SUCCESS;
    }
    arg = arg->next;
    if (arg == NULL) {
        text2 = VALUE_PTR(text_t, &var2);
        text2->str = NULL;
        text2->len = 0;
    } else {
        OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &var2, &text2));
        SQL_CHECK_COLUMN_VAR(&var2, result);
    }

    res->len = 0;
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)&res->str));

    do {
        // copy pos characters which not matched
        OG_RETURN_IFERR(sql_func_concat_string(stmt, res, text, pos));

        // copy replaced characters
        OG_RETURN_IFERR(sql_func_concat_string(stmt, res, text2, text2->len));

        // remove pos+replaced characters
        if (text->len < (pos + text1->len)) {
            OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "text->len(%u) >= pos(%d) + text1->len(%u)", text->len, pos,
                text1->len);
            return OG_ERROR;
        }
        CM_REMOVE_FIRST_N(text, pos + text1->len);
        pos = cm_text_text(text, text1);
    } while (pos >= 0);

    OG_RETURN_IFERR(sql_func_concat_string(stmt, res, text, text->len));
    result->is_null = (res->len == 0 && g_instance->sql.enable_empty_string_null);
    sql_keep_stack_variant(stmt, result);
    return OG_SUCCESS;
}

status_t sql_verify_replace(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 3, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_STRING;
    func->size = OG_MAX_COLUMN_SIZE;
    return OG_SUCCESS;
}

status_t sql_func_reverse(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t arg_var;
    uint32 pos_dst = 0;
    uint32 pos_src = 0;
    uint32 one_char_len = 0;
    text_t temp_tx;

    expr_tree_t *arg_node = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg_node, &arg_var, result);

    if (!OG_IS_STRING_TYPE(arg_var.type)) {
        OG_SRC_ERROR_REQUIRE_STRING(arg_node->loc, arg_var.type);
        return OG_ERROR;
    }

    if (arg_var.v_text.len > 0) {
        sql_keep_stack_variant(stmt, &arg_var);

        OG_RETURN_IFERR(sql_push(stmt, arg_var.v_text.len, (void **)&result->v_text.str));

        temp_tx = arg_var.v_text;
        while (pos_src < temp_tx.len) {
            if (GET_DATABASE_CHARSET->str_bytes(temp_tx.str + pos_src, temp_tx.len - pos_src, &one_char_len) !=
                OG_SUCCESS) {
                OGSQL_POP(stmt);
                OG_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
                return OG_ERROR;
            }

            pos_dst += one_char_len;
            errno_t errcode =
                memcpy_s(result->v_text.str + temp_tx.len - pos_dst, one_char_len, temp_tx.str + pos_src, one_char_len);
            if (errcode != EOK) {
                OGSQL_POP(stmt);
                OG_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
                return OG_ERROR;
            }
            pos_src += one_char_len;
        }
        OGSQL_POP(stmt);
    }

    result->v_text.len = arg_var.v_text.len;
    result->type = OG_TYPE_STRING;
    result->is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_verify_reverse(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!sql_match_string_type(TREE_DATATYPE(func->argument))) {
        OG_SRC_ERROR_REQUIRE_STRING(func->argument->loc, TREE_DATATYPE(func->argument));
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->type, func->argument->root->size);

    return OG_SUCCESS;
}

status_t sql_func_space(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg = func->argument;
    variant_t argVar;
    SQL_EXEC_FUNC_ARG_EX(arg, &argVar, result);
    int32 size = 0;
    OG_RETURN_IFERR(var_to_round_int32(&argVar, ROUND_HALF_UP, &size));
    if (size > 4000) {
        OG_THROW_ERROR_EX(ERR_INVALID_FUNC_PARAMS, "space argument size should be less than %u.", 4000);
        return OG_ERROR;
    } else if (size <= 0) {
        result->type = OG_TYPE_STRING;
        result->v_text.len = 0;
        result->is_null = g_instance->sql.enable_empty_string_null;
        return OG_SUCCESS;
    }

    char *buff = NULL;
    OG_RETURN_IFERR(sql_push(stmt, (uint32)size, (void *)&buff));
    MEMS_RETURN_IFERR(memset_s(buff, size, ' ', size));
    result->type = OG_TYPE_STRING;
    result->is_null = OG_FALSE;
    result->v_text.len = (uint32)size;
    result->v_text.str = buff;

    return OG_SUCCESS;
}

status_t sql_verify_space(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);
    OG_RETURN_IFERR(sql_verify_func_node(verifier, func, 1, 1, OG_INVALID_ID32));
    func->datatype = OG_TYPE_STRING;
    func->size = OG_MAX_COLUMN_SIZE;
    return OG_SUCCESS;
}

static status_t sql_func_substring_index_core(variant_t *var1, variant_t *var2, int count, variant_t *res)
{
    const char *str1 = var1->v_text.str;
    const char *str2 = var2->v_text.str;
    int len1 = var1->v_text.len;
    int len2 = var2->v_text.len;
    const char *str1_end = str1 + len1;
    const char *str1_end_new = str1_end - len2 + 1;
    const char *str2_end = str2 + len2;
    const char *ptr = str1;
    int n = 0;
    int cnt = count;
    int pass;

    res->type = OG_TYPE_STRING;
    res->is_null = OG_FALSE;

    for (pass = (count > 0); pass < 2; ++pass) {
        while (ptr < str1_end_new) {
            uint32 mb_len;

            if (*ptr != *str2) {
                OG_RETURN_IFERR(GET_DATABASE_CHARSET->str_bytes(ptr, (uint32)(str1_end - ptr), &mb_len));
                ptr += mb_len;
                continue;
            }
            char *p1 = (char *)ptr + 1;
            char *p2 = (char *)str2 + 1;
            while (p2 != str2_end) {
                if (*p1++ != *p2++) {
                    goto skip;
                }
            }
            if (pass == 0) {
                ++n;
            } else if (!--cnt) {
                break;
            }

            ptr += len2;
            continue;

        skip:
            OG_RETURN_IFERR(GET_DATABASE_CHARSET->str_bytes(ptr, (uint32)(str1_end - ptr), &mb_len));
            ptr += mb_len;
        }
        if (pass == 0) {
            cnt += n + 1;
            if (cnt <= 0) {
                if (len1 != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(res->v_text.str, OG_STRING_BUFFER_SIZE, str1, len1));
                }
                res->v_text.len = len1;
                return OG_SUCCESS;
            }
            ptr = str1;
        } else {
            if (cnt) {
                if (len1 != 0) {
                    MEMS_RETURN_IFERR(memcpy_s(res->v_text.str, OG_STRING_BUFFER_SIZE, str1, len1));
                }
                res->v_text.len = len1;
                return OG_SUCCESS;
            }
            if (count > 0) {
                if (ptr - str1 > 0) {
                    MEMS_RETURN_IFERR(memcpy_s(res->v_text.str, OG_STRING_BUFFER_SIZE, str1, ptr - str1));
                }
                res->v_text.len = (uint32)(ptr - str1);
            } else {
                ptr += len2;
                if (str1_end - ptr > 0) {
                    MEMS_RETURN_IFERR(
                        memcpy_s(res->v_text.str, OG_STRING_BUFFER_SIZE, str1 + (int)(ptr - str1), str1_end - ptr));
                }
                res->v_text.len = (uint32)(str1_end - ptr);
            }
        }
    }

    res->type = OG_TYPE_STRING;
    res->is_null = (res->v_text.len == 0 && g_instance->sql.enable_empty_string_null);

    return OG_SUCCESS;
}

status_t sql_func_substring_index(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    char *buf = NULL;
    variant_t var1;
    variant_t var2;
    variant_t var3;
    uint32 str_char_len;

    CM_POINTER3(stmt, func, res);

    expr_tree_t *arg1 = func->argument;
    SQL_EXEC_FUNC_ARG_EX(arg1, &var1, res);
    sql_keep_stack_variant(stmt, &var1);
    if (sql_var_as_string(stmt, &var1) != OG_SUCCESS) {
        cm_set_error_loc(arg1->loc);
        return OG_ERROR;
    }

    if (var1.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        if (!g_instance->sql.enable_empty_string_null) {
            res->v_text.len = 0;
            res->is_null = OG_FALSE;
        }
        return OG_SUCCESS;
    }

    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, res);
    sql_keep_stack_variant(stmt, &var2);
    if (sql_var_as_string(stmt, &var2) != OG_SUCCESS) {
        cm_set_error_loc(arg2->loc);
        return OG_ERROR;
    }

    if (var2.v_text.len == 0) {
        SQL_SET_NULL_VAR(res);
        if (!g_instance->sql.enable_empty_string_null) {
            res->v_text.len = 0;
            res->is_null = OG_FALSE;
        }
        return OG_SUCCESS;
    }

    expr_tree_t *arg3 = arg2->next;
    SQL_EXEC_FUNC_ARG_EX(arg3, &var3, res);
    OG_RETURN_IFERR(var_as_floor_integer(&var3));
    if (var3.v_int == 0) {
        SQL_SET_NULL_VAR(res);
        if (!g_instance->sql.enable_empty_string_null) {
            res->v_text.len = 0;
            res->is_null = OG_FALSE;
        }
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, OG_STRING_BUFFER_SIZE, (void **)&buf));
    res->v_text.str = buf;
    res->v_text.len = 0;
    res->type = OG_TYPE_STRING;
    res->is_null = OG_FALSE;

    if ((GET_DATABASE_CHARSET->length(&var1.v_text, (uint32 *)&str_char_len) != OG_SUCCESS ||
        GET_DATABASE_CHARSET->length(&var2.v_text, (uint32 *)&str_char_len) != OG_SUCCESS)) {
        // return NULL if multi-bytes invalid
        SQL_SET_NULL_VAR(res);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_func_substring_index_core(&var1, &var2, var3.v_int, res));

    return OG_SUCCESS;
}

static status_t sql_func_substr_core2(sql_stmt_t *stmt, variant_t *result, variant_t *var1, variant_t *var2,
    uint32 substr_len, bool32 is_special)
{
    if (is_special) {
        if (GET_DATABASE_CHARSET->substr(&var1->v_text, var2->v_int, substr_len, &result->v_text) != OG_SUCCESS) {
            OGSQL_POP(stmt);
            return OG_ERROR;
        }
    } else {
        cm_substrb(&var1->v_text, var2->v_int, substr_len, &result->v_text);
    }

    if (result->v_text.len == 0 && g_instance->sql.enable_empty_string_null) {
        SQL_SET_NULL_VAR(result);
    }

    return OG_SUCCESS;
}

static status_t sql_exec_func_arg_substr(sql_stmt_t *statement, expr_tree_t *arg_expr,
    variant_t *arg_var, variant_t *res_var)
{
    OG_RETURN_IFERR(sql_exec_expr(statement, arg_expr, arg_var));
    SQL_CHECK_COLUMN_VAR(arg_var, res_var);

    if (!OG_IS_LOB_TYPE(arg_var->type) || (arg_var->is_null)) {
        return OG_SUCCESS;
    }

    if (arg_var->v_lob.type == OG_LOB_FROM_KERNEL) {
        if (((lob_locator_t *)(arg_var->v_lob.knl_lob.bytes))->head.size >
            g_instance->attr.lob_max_exec_size) {
            ((lob_locator_t *)(arg_var->v_lob.knl_lob.bytes))->head.size = OG_LOB_LOCATOR_BUF_SIZE;
        }
    }

    if (arg_var->v_lob.type == OG_LOB_FROM_VMPOOL) {
        if (arg_var->v_lob.vm_lob.size > g_instance->attr.lob_max_exec_size) {
            arg_var->v_lob.vm_lob.size = OG_LOB_LOCATOR_BUF_SIZE;
        }
    }

    return sql_get_lob_value(statement, arg_var);
}

static status_t sql_func_substr_core(sql_stmt_t *stmt, expr_node_t *func, variant_t *result, bool32 is_special)
{
    variant_t var1;
    variant_t var2;
    variant_t var3;
    char *buf = NULL;
    uint32 substr_len = 0;

    CM_POINTER3(stmt, func, result);

    result->type = OG_TYPE_STRING;

    expr_tree_t *arg1 = func->argument;
    result->is_null = OG_FALSE;

    expr_tree_t *arg2 = arg1->next;
    SQL_EXEC_FUNC_ARG_EX(arg2, &var2, result);

    OG_RETURN_IFERR(var_as_floor_integer(&var2));

    expr_tree_t *arg3 = arg2->next;
    if (arg3 != NULL) {
        SQL_EXEC_FUNC_ARG_EX(arg3, &var3, result);
        OG_RETURN_IFERR(var_as_floor_integer(&var3));

        if (var3.v_int <= 0) {
            result->v_text.len = 0;
            result->is_null = g_instance->sql.enable_empty_string_null;
            return OG_SUCCESS;
        }

        substr_len = (uint32)var3.v_int;
    } else {
        substr_len = OG_MAX_UINT32;
    }

    /* incase substr_len + var2->v_int is overflow */
    OG_RETURN_IFERR(sql_exec_func_arg_substr(stmt, arg1, &var1, result));
    if (var1.is_null) {
        SQL_SET_NULL_VAR(result);
        return OG_SUCCESS;
    }

    sql_keep_stack_variant(stmt, &var1);
    OG_RETURN_IFERR(sql_var_as_string(stmt, &var1));
    if (var1.v_text.len == 0 && g_instance->sql.enable_empty_string_null) {
        SQL_SET_NULL_VAR(result);
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, OG_STRING_BUFFER_SIZE, (void **)&buf));

    result->v_text.str = buf;
    result->v_text.len = 0;

    // var3.v_int > 0
    OG_RETURN_IFERR(sql_func_substr_core2(stmt, result, &var1, &var2, substr_len, is_special));

    return OG_SUCCESS;
}

status_t sql_func_substr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_substr_core(stmt, func, result, OG_TRUE);
}

status_t sql_func_substrb(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_substr_core(stmt, func, result, OG_FALSE);
}

status_t sql_verify_substr(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 2, 3, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    func->typmod.is_char = func->argument->root->typmod.is_char;

    return OG_SUCCESS;
}

status_t sql_verify_substring_index(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 3, 3, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return OG_SUCCESS;
}

status_t sql_verify_sys_connect_by_path(sql_verifier_t *verf, expr_node_t *func)
{
    expr_node_t *origin_ref = NULL;
    verf->excl_flags |= (SQL_EXCL_AGGR | SQL_EXCL_WIN_SORT);

    if (verf->excl_flags & SQL_EXCL_PATH_FUNC) {
        OG_THROW_ERROR(ERR_FUNC_LOCATION, T2S(&func->word.func.name));
        return OG_ERROR;
    }

    if (sql_verify_func_node(verf, func, 2, 2, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (verf->curr_query == NULL || verf->curr_query->connect_by_cond == NULL) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
        return OG_ERROR;
    }

    // the 2nd arg is delimiter, verify delimiter
    if (sql_is_single_const_or_param(func->argument->next->root) != OG_TRUE) {
        OG_SRC_THROW_ERROR_EX(func->argument->next->root->loc, ERR_INVALID_SEPARATOR, T2S(&func->word.func.name));
        return OG_ERROR;
    }
    func->datatype = OG_TYPE_STRING;
    func->size = OG_MAX_ROW_SIZE;
    OG_RETURN_IFERR(sql_clone_expr_node(verf->stmt->context, func, &origin_ref, sql_alloc_mem));
    if (cm_galist_insert(verf->curr_query->path_func_nodes, origin_ref) != OG_SUCCESS) {
        return OG_ERROR;
    }
    func->argument->root->type = EXPR_NODE_CONST;
    func->argument->root->value.type = OG_TYPE_INTEGER;
    func->argument->root->value.v_int = (int32)verf->curr_query->path_func_nodes->count - 1;
    func->argument->root->value.is_null = OG_FALSE;
    return OG_SUCCESS;
}

status_t sql_func_sys_connect_by_path(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    text_t *buf = NULL;
    char *tmp_buf = NULL;
    char *buf2 = NULL;
    cm_stack_t tmp_stack;
    text_buf_t text_buf;
    sql_cursor_t *first_level_cursor = (OGSQL_CURR_CURSOR(stmt))->connect_data.first_level_cursor;
    CM_ASSERT(first_level_cursor->connect_data.path_func_nodes->count > 0);
    // each sys_connect_by_path corresponds to a stack
    cm_stack_t *path_stack = first_level_cursor->connect_data.path_stack + func->argument->root->value.v_int;
    res->type = OG_TYPE_STRING;
    res->v_text.len = 0;

    OGSQL_SAVE_STACK(stmt);
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&tmp_buf));

    cm_stack_init(&tmp_stack, tmp_buf, OG_MAX_ROW_SIZE);

    uint32 push_offset = path_stack->push_offset;
    /* reverse the path */
    while (push_offset < path_stack->size) {
        buf = (text_t *)(path_stack->buf + push_offset + OG_PUSH_RESERVE_SIZE);
        buf2 = cm_push(&tmp_stack, sizeof(text_t) + buf->len);
        errno_t errcode = memcpy_s(buf2, sizeof(text_t) + buf->len, buf, sizeof(text_t) + buf->len);
        if (errcode != EOK) {
            OGSQL_RESTORE_STACK(stmt);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
        push_offset = *(uint32 *)(path_stack->buf + push_offset + OG_PUSH_OFFSET_POS);
    }

    /* get the complete connect path */
    if (sql_push(stmt, OG_MAX_ROW_SIZE, (void **)&res->v_text.str) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }

    text_buf.str = res->v_text.str;
    text_buf.len = 0;
    text_buf.max_size = OG_MAX_ROW_SIZE;
    push_offset = tmp_stack.push_offset;
    while (push_offset < tmp_stack.size) {
        buf = (text_t *)(tmp_stack.buf + push_offset + OG_PUSH_RESERVE_SIZE);
        if (!cm_buf_append_text(&text_buf, buf)) {
            OG_THROW_ERROR(ERR_VALUE_ERROR, "result string length is too long, beyond the max");
            OGSQL_RESTORE_STACK(stmt);
            return OG_ERROR;
        }
        push_offset = *(uint32 *)(tmp_stack.buf + push_offset + OG_PUSH_OFFSET_POS);
    }
    res->v_text.len = text_buf.len;
    if (text_buf.len == 0) {
        res->is_null = OG_TRUE;
    }
    OGSQL_RESTORE_STACK(stmt);
    return OG_SUCCESS;
}

static status_t sql_func_translate_core2(sql_stmt_t *stmt, text_t *char_text, text_t *from_text, text_t *to_text,
    text_t *res, const uint16 *ascii_map, int16 *to_char_pos, uint16 to_count)
{
    uint32 pos = 0;
    uint32 char_len;
    uint32 to_len;
    uint32 char_pos;
    int32 to_pos;
    bool32 has_utf8 = OG_FALSE;
    text_t sub_str;

    while (pos < char_text->len) {
        if (res->len > OG_MAX_COLUMN_SIZE) {
            OG_THROW_ERROR(ERR_SIZE_ERROR, res->len, OG_MAX_COLUMN_SIZE, "column");
            return OG_ERROR;
        }

        if (GET_DATABASE_CHARSET->str_bytes(&(char_text->str[pos]), char_text->len - pos, &char_len) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return OG_ERROR;
        }

        sub_str.str = char_text->str + pos;
        sub_str.len = char_len;

        if (sub_str.len == 1) {
            char_pos = (uint32)ascii_map[(uint8)(sub_str.str[0])];
        } else {
            OG_RETURN_IFERR(sql_func_instr_char(from_text, &sub_str, 1, 1, &has_utf8, &char_pos));
        }

        if (char_pos > (uint32)0) {
            char_pos--;
            if (char_pos < to_count && to_char_pos[char_pos + 1] >= 0) {
                to_pos = (int32)to_char_pos[char_pos];
                to_len = (uint32)(to_char_pos[char_pos + 1] - to_char_pos[char_pos]);
                for (uint32 j = 0; j < to_len; j++) {
                    res->len++;
                    *(res->str) = to_text->str[(uint32)to_pos + j];
                    res->str++;
                }
            }
            pos += char_len;
            continue;
        }
        for (uint32 j = 0; j < char_len; j++) {
            res->len++;
            *(res->str) = char_text->str[pos + j];
            res->str++;
        }
        pos += char_len;
    }
    return OG_SUCCESS;
}

static status_t sql_filling_ascii_map(text_t *text, uint16 *ascii_map, int16 len)
{
    uint32 pos = 0;
    uint32 char_len;
    uint16 count = 0;

    while (pos < text->len) {
        if (GET_DATABASE_CHARSET->str_bytes((char *)(text->str + pos), text->len - pos, &char_len) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return OG_ERROR;
        }

        if (char_len == 1 && (int16)text->str[pos] <= len && ascii_map[(int16)text->str[pos]] == 0) {
            ascii_map[(int16)text->str[pos]] = count + (uint16)1;
        }
        pos += char_len;

        count++;
    }
    return OG_SUCCESS;
}

static status_t sql_get_char_bytes_array(text_t *text, int16 *char_pos, uint16 *count)
{
    uint32 pos = 0;
    uint32 char_len;
    char_pos[0] = 0;
    *count = 0;

    while (pos < text->len) {
        (*count)++;
        if (GET_DATABASE_CHARSET->str_bytes((char *)(text->str + pos), text->len - pos, &char_len) != OG_SUCCESS) {
            OG_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return OG_ERROR;
        }
        pos += char_len;
        char_pos[*count] = char_pos[*count - 1] + (int16)char_len;
    }
    return OG_SUCCESS;
}

static status_t sql_func_translate_core(sql_stmt_t *stmt, text_t *char_text, text_t *from_text, text_t *to_text,
    text_t *result)
{
    int16 *to_char_pos = NULL;
    uint16 ascii_map[SQL_ASCII_COUNT] = { 0 };
    uint16 *ascii_map_add = &ascii_map[0];
    uint16 to_count;
    char *origin = result->str;
    result->len = 0;
    status_t status = OG_ERROR;

    OGSQL_SAVE_STACK(stmt);
    do {
        OG_BREAK_IF_ERROR(sql_filling_ascii_map(from_text, ascii_map_add, (int16)(sizeof(ascii_map) / sizeof(uint16))));
        OG_BREAK_IF_ERROR(sql_push(stmt, sizeof(int16) * (to_text->len + 1), (void **)(&to_char_pos)));
        errno_t errcode =
            memset_sp(to_char_pos, sizeof(int16) * (to_text->len + 1), 0, sizeof(int16) * (to_text->len + 1));
        if (errcode != EOK) {
            OGSQL_RESTORE_STACK(stmt);
            OG_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return OG_ERROR;
        }
        OG_BREAK_IF_ERROR(sql_get_char_bytes_array(to_text, to_char_pos, &to_count));
        OG_BREAK_IF_ERROR(
            sql_func_translate_core2(stmt, char_text, from_text, to_text, result, ascii_map, to_char_pos, to_count));
        result->str = origin;
        status = OG_SUCCESS;
    } while (0);

    OGSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_func_translate(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    expr_tree_t *arg = NULL;
    variant_t char_var;
    variant_t from_var;
    variant_t to_var;
    text_t *char_text = NULL;
    text_t *from_text = NULL;
    text_t *to_text = NULL;
    text_t *result = NULL;

    OGSQL_SAVE_STACK(stmt);
    res->type = OG_TYPE_STRING;
    result = VALUE_PTR(text_t, res);

    arg = func->argument;
    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &char_var, &char_text));
    SQL_CHECK_COLUMN_VAR(&char_var, res);

    arg = arg->next;
    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &from_var, &from_text));
    SQL_CHECK_COLUMN_VAR(&from_var, res);

    arg = arg->next;
    OG_RETURN_IFERR(sql_exec_expr_as_string(stmt, arg, &to_var, &to_text));
    SQL_CHECK_COLUMN_VAR(&to_var, res);
    if (char_var.is_null || from_var.is_null || to_var.is_null) {
        res->is_null = OG_TRUE;
        return OG_SUCCESS;
    }

    if (char_text->len == 0 || from_text->len == 0 || to_text->len == 0) {
        result->len = 0;
        res->is_null = g_instance->sql.enable_empty_string_null;
        return OG_SUCCESS;
    }

    res->is_null = OG_FALSE;
    result->len = char_text->len * 3 > OG_MAX_COLUMN_SIZE ? OG_MAX_COLUMN_SIZE : char_text->len * 3;
    OG_RETURN_IFERR(sql_push(stmt, result->len, (void **)&result->str));

    OG_RETURN_IFERR(sql_func_translate_core(stmt, char_text, from_text, to_text, result));
    OGSQL_RESTORE_STACK(stmt);

    return OG_SUCCESS;
}

status_t sql_verify_translate(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 3, 3, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);
    func->typmod.is_char = func->argument->root->typmod.is_char;
    return OG_SUCCESS;
}

status_t sql_func_upper(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    return sql_func_lower_upper_core(stmt, func, result, OG_TRUE);
}

status_t sql_verify_upper(sql_verifier_t *verf, expr_node_t *func)
{
    CM_POINTER2(verf, func);

    if (sql_verify_func_node(verf, func, 1, 1, OG_INVALID_ID32) != OG_SUCCESS) {
        return OG_ERROR;
    }

    func->datatype = (OG_TYPE_CHAR == func->argument->root->datatype) ? OG_TYPE_CHAR : OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return OG_SUCCESS;
}
