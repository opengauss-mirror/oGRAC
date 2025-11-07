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
 * func_regexp.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/function/func_regexp.c
 *
 * -------------------------------------------------------------------------
 */
#include "func_regexp.h"
#include "cm_regexp.h"
#include "srv_instance.h"
#include "func_string.h"

static status_t sql_verify_regexp_args(sql_verifier_t *verf, expr_node_t *func, regexp_arg_type_t *arg_types,
    const char *name)
{
    int32 arg_count;
    expr_tree_t *current = func->argument;
    arg_count = 0;
    while (current != NULL) {
        ++arg_count;
        OG_RETURN_IFERR(sql_verify_current_expr(verf, current));
        switch (arg_types[arg_count - 1]) {
            case REGEXP_ARG_SOURCE:
            case REGEXP_ARG_REPLACE:
                if (!sql_match_numeric_type(current->root->datatype) &&
                    !sql_match_string_type(current->root->datatype)) {
                    OG_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(OG_TYPE_STRING),
                        get_datatype_name_str((int32)current->root->datatype));
                    return OG_ERROR;
                }
                break;
            case REGEXP_ARG_PATTERN:
            case REGEXP_ARG_MATCH_PARAM:
                if (!sql_match_string_type(current->root->datatype)) {
                    OG_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(OG_TYPE_STRING),
                        get_datatype_name_str((int32)current->root->datatype));
                    return OG_ERROR;
                }
                break;
            case REGEXP_ARG_POSITION:
            case REGEXP_ARG_OCCUR:
            case REGEXP_ARG_RETURN_OPT:
            case REGEXP_ARG_SUBEXPR:
                if (!sql_match_numeric_type(current->root->datatype)) {
                    OG_THROW_ERROR(ERR_TYPE_MISMATCH, get_datatype_name_str(OG_TYPE_INTEGER),
                        get_datatype_name_str((int32)current->root->datatype));
                    return OG_ERROR;
                }
                break;
            default: // REGEXP_ARG_DUMB the last one in the args type array, represent invalid
                OG_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, name, 2, arg_count - 1);
                return OG_ERROR;
        }
        current = current->next;
    }
    if (arg_count < 2) {
        while (arg_types[arg_count] != REGEXP_ARG_DUMB) {
            ++arg_count;
        }
        OG_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, name, 2, arg_count);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_verify_regexp_count(sql_verifier_t *verf, expr_node_t *func)
{
    OG_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_count_arg_types, "REGEXP_COUNT"));

    func->datatype = OG_TYPE_INTEGER;
    func->size = OG_INTEGER_SIZE;

    return OG_SUCCESS;
}

static status_t sql_func_regexp_count_core(sql_stmt_t *stmt, variant_t *result, void *code, regexp_args_t *args)
{
    bool32 match_null = OG_FALSE;
    int32 pos;
    int32 count;
    status_t ret;
    text_t posstr;
    regexp_substr_assist_t substr_ass;

    do {
        // if result is null, just return success
        if (result->is_null) {
            ret = OG_SUCCESS;
            break;
        }

        pos = 0;
        for (count = 0; (uint32)pos <= args->src->len; count++) {
            substr_ass.code = code;
            substr_ass.subject = *(args->src);
            substr_ass.offset = args->offset - 1;
            substr_ass.occur = 1;
            substr_ass.subexpr = 0;
            substr_ass.charset = GET_CHARSET_ID;
            ret = cm_regexp_instr(&pos, &substr_ass, OG_TRUE);
            OG_BREAK_IF_ERROR(ret);

            if (pos == 0) {
                break;
            } else if (pos >= 1) {
                if (pos == args->offset) {
                    args->offset += 1;
                    match_null = OG_TRUE;
                } else {
                    posstr.str = args->src->str;
                    posstr.len = (uint32)pos - 1;
                    ret = GET_DATABASE_CHARSET->length(&posstr, (uint32 *)&pos);
                    OG_BREAK_IF_ERROR(ret);
                    pos += 1;
                    args->offset = pos;
                }
            }
        }
        if (match_null) {
            count += 1;
        }
        *(VALUE_PTR(int32, result)) = count;
    } while (OG_FALSE);

    return ret;
}

static status_t sql_regexp_calc_args(sql_stmt_t *stmt, expr_node_t *func, regexp_arg_type_t *arg_types,
    regexp_args_t *regexp_args, variant_t *res)
{
    int32 arg_count;

    expr_tree_t *curr = func->argument;
    arg_count = 0;
    cm_regexp_args_init(regexp_args);

    // if argument source, pattern, position, occur, return_opt, subexpr is null, then the result will be null
    while (curr != NULL) {
        ++arg_count;
        switch (arg_types[arg_count - 1]) {
            case REGEXP_ARG_SOURCE:
                SQL_EXEC_FUNC_ARG_EX2(curr, &regexp_args->var_src, res);
                sql_keep_stack_variant(stmt, &regexp_args->var_src);
                OG_RETURN_IFERR(sql_convert_variant(stmt, &regexp_args->var_src, OG_TYPE_STRING));
                sql_keep_stack_variant(stmt, &regexp_args->var_src);
                regexp_args->src = VALUE_PTR(text_t, &regexp_args->var_src);
                break;
            case REGEXP_ARG_PATTERN:
                SQL_EXEC_FUNC_ARG_EX2(curr, &regexp_args->var_pattern, res);
                sql_keep_stack_variant(stmt, &regexp_args->var_pattern);
                OG_RETURN_IFERR(sql_convert_variant(stmt, &regexp_args->var_pattern, OG_TYPE_STRING));
                sql_keep_stack_variant(stmt, &regexp_args->var_pattern);
                regexp_args->pattern = VALUE_PTR(text_t, &regexp_args->var_pattern);
                break;
            case REGEXP_ARG_REPLACE:
                SQL_EXEC_FUNC_ARG_EX2(curr, &regexp_args->var_replace_str, res);
                sql_keep_stack_variant(stmt, &regexp_args->var_replace_str);
                OG_RETURN_IFERR(sql_convert_variant(stmt, &regexp_args->var_replace_str, OG_TYPE_STRING));
                sql_keep_stack_variant(stmt, &regexp_args->var_replace_str);
                regexp_args->replace_str = VALUE_PTR(text_t, &regexp_args->var_replace_str);
                break;
            case REGEXP_ARG_POSITION:
                SQL_EXEC_FUNC_ARG_EX(curr, &regexp_args->var_pos, res);
                OG_RETURN_IFERR(var_as_floor_integer(&regexp_args->var_pos));
                regexp_args->offset = *VALUE_PTR(int32, &regexp_args->var_pos);
                break;
            case REGEXP_ARG_OCCUR:
                SQL_EXEC_FUNC_ARG_EX(curr, &regexp_args->var_occur, res);
                OG_RETURN_IFERR(var_as_floor_integer(&regexp_args->var_occur));
                regexp_args->occur = *VALUE_PTR(int32, &regexp_args->var_occur);
                break;
            case REGEXP_ARG_RETURN_OPT:
                SQL_EXEC_FUNC_ARG_EX(curr, &regexp_args->var_retopt, res);
                OG_RETURN_IFERR(var_as_floor_integer(&regexp_args->var_retopt));
                regexp_args->retopt = *VALUE_PTR(int32, &regexp_args->var_retopt);
                break;
            case REGEXP_ARG_MATCH_PARAM:
                OG_RETURN_IFERR(sql_exec_expr(stmt, curr, &regexp_args->var_match_param));
                if (regexp_args->var_match_param.is_null) {
                    regexp_args->match_param = NULL;
                    break;
                }
                SQL_CHECK_COLUMN_VAR(&regexp_args->var_match_param, res);
                sql_keep_stack_variant(stmt, &regexp_args->var_match_param);
                OG_RETURN_IFERR(sql_convert_variant(stmt, &regexp_args->var_match_param, OG_TYPE_STRING));
                sql_keep_stack_variant(stmt, &regexp_args->var_match_param);
                regexp_args->match_param = VALUE_PTR(text_t, &regexp_args->var_match_param);
                break;
            case REGEXP_ARG_SUBEXPR:
                SQL_EXEC_FUNC_ARG_EX(curr, &regexp_args->var_subexpr, res);
                OG_RETURN_IFERR(var_as_floor_integer(&regexp_args->var_subexpr));
                regexp_args->subexpr = *VALUE_PTR(int32, &regexp_args->var_subexpr);
                break;
            default: // REGEXP_ARG_DUMB the last one in the args type array, represent invalid
                break;
        }
        curr = curr->next;
    }
    return OG_SUCCESS;
}

status_t sql_func_regexp_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    regexp_args_t regexp_args;
    void *code = NULL;
    char *psz = NULL;
    int32 count;
    bool32 args_error_found;
    status_t ret;

    result->is_null = OG_FALSE;
    result->type = OG_TYPE_UNKNOWN;

    OG_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_count_arg_types, &regexp_args, result));

    args_error_found = (!regexp_args.var_pos.is_null && regexp_args.offset <= 0);
    if (args_error_found) {
        OG_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "position must be greater than 0");
        return OG_ERROR;
    }

    // if result is null, normally function should return
    // but if the pattern is not null, we should first make sure the pattern is correct
    // if some column is pending while calculating expr node, just return success
    if (regexp_args.var_pattern.is_null || result->type == OG_TYPE_COLUMN) {
        return OG_SUCCESS;
    }

    result->type = OG_TYPE_INTEGER;
    if ((uint32)regexp_args.offset > regexp_args.src->len) {
        count = 0;
        *(VALUE_PTR(int32, result)) = count;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(sql_push(stmt, regexp_args.pattern->len * 2 + 1, (void **)&psz));
    OG_RETURN_IFERR(cm_replace_regexp_spec_chars(regexp_args.pattern, psz, regexp_args.pattern->len * 2 + 1));
    OG_LOG_DEBUG_INF("regular expression is: %s", psz);

    OG_RETURN_IFERR(cm_regexp_compile(&code, psz, regexp_args.match_param, GET_CHARSET_ID));

    ret = sql_func_regexp_count_core(stmt, result, code, &regexp_args);

    cm_regexp_free(code);
    code = NULL;
    return ret;
}

status_t sql_verify_regexp_instr(sql_verifier_t *verf, expr_node_t *func)
{
    OG_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_instr_arg_types, "REGEXP_INSTR"));

    func->datatype = OG_TYPE_INTEGER;
    func->size = OG_INTEGER_SIZE;

    return OG_SUCCESS;
}

status_t sql_verify_regexp_substr(sql_verifier_t *verf, expr_node_t *func)
{
    OG_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_substr_arg_types, "REGEXP_SUBSTR"));

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return OG_SUCCESS;
}

static status_t sql_regexp_instr_run(variant_t *result, regexp_args_t args, void *code)
{
    text_t posstr;
    regexp_substr_assist_t substr_ass;
    status_t ret;
    int32 pos;
    do {
        // if result is null, just return success
        if (result->is_null) {
            ret = OG_SUCCESS;
            break;
        }

        result->type = OG_TYPE_INTEGER;
        substr_ass.code = code;
        substr_ass.subject = *args.src;
        substr_ass.offset = args.offset - 1;
        substr_ass.occur = args.occur;
        substr_ass.subexpr = args.subexpr;
        substr_ass.charset = GET_CHARSET_ID;
        ret = cm_regexp_instr(&pos, &substr_ass, args.retopt);
        OG_BREAK_IF_ERROR(ret);

        if (pos > 1) {
            posstr.str = args.src->str;
            posstr.len = (uint32)pos - 1;
            ret = GET_DATABASE_CHARSET->length(&posstr, (uint32 *)&pos);
            OG_BREAK_IF_ERROR(ret);
            pos += 1;
        }

        *(VALUE_PTR(int32, result)) = pos;
    } while (OG_FALSE);
    return ret;
}


status_t sql_func_regexp_instr(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    bool32 args_error_found;
    status_t ret;

    result->is_null = OG_FALSE;
    result->type = OG_TYPE_UNKNOWN;

    OG_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_instr_arg_types, &args, result));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0) || (!args.var_occur.is_null && args.occur <= 0) ||
        (!args.var_subexpr.is_null && args.subexpr < 0) || (!args.var_retopt.is_null && args.retopt < 0);
    if (args_error_found) {
        OG_THROW_ERROR(ERR_INVALID_REGEXP_INSTR_PARAM, args.offset, args.occur, args.subexpr, args.retopt);
        return OG_ERROR;
    }

    // if result is null, normally function should return
    // but if the pattern is not null, we should first make sure the pattern is correct
    // if some column is pending while calculating expr node, just return success
    OG_RETSUC_IFTRUE(args.var_pattern.is_null || result->type == OG_TYPE_COLUMN);

    OG_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    OG_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    OG_LOG_DEBUG_INF("regular expression is: %s", psz);

    OG_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    ret = sql_regexp_instr_run(result, args, code);

    cm_regexp_free(code);
    code = NULL;
    return ret;
}

static inline void sql_construct_rsa(regexp_substr_assist_t *rsa, void *code, regexp_args_t *regexp_args)
{
    rsa->code = code;
    rsa->subject = *(regexp_args->src);
    rsa->offset = regexp_args->offset - 1;
    rsa->occur = regexp_args->occur;
    rsa->subexpr = regexp_args->subexpr;
    rsa->charset = GET_CHARSET_ID;
}

status_t sql_func_regexp_substr(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    bool32 args_error_found;
    res->is_null = OG_FALSE;
    res->type = OG_TYPE_UNKNOWN;
    regexp_substr_assist_t assist;
    status_t ret = OG_SUCCESS;

    OG_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_substr_arg_types, &args, res));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0) || (!args.var_occur.is_null && args.occur <= 0) ||
        (!args.var_subexpr.is_null && args.subexpr < 0);
    if (args_error_found) {
        OG_THROW_ERROR(ERR_INVALID_REGEXP_INSTR_PARAM_NO_OPT, args.offset, args.occur, args.subexpr);
        return OG_ERROR;
    }

    // if result is null, normally function should return
    // but if the pattern is not null, we should first make sure the pattern is correct
    // if some column is pending while calculating expr node, just return success
    OG_RETSUC_IFTRUE(args.var_pattern.is_null || res->type == OG_TYPE_COLUMN);

    OG_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    OG_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    OG_LOG_DEBUG_INF("regular expression is: %s", psz);

    OG_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    do {
        // if result is null, just return success
        if (res->is_null) {
            cm_regexp_free(code);
            return OG_SUCCESS;
        }

        res->type = OG_TYPE_STRING;
        sql_construct_rsa(&assist, code, &args);
        ret = cm_regexp_substr(VALUE_PTR(text_t, res), &assist);
        OG_BREAK_IF_ERROR(ret);
    } while (0);

    cm_regexp_free(code);
    code = NULL;
    OG_RETURN_IFERR(ret);

    if (res->v_text.len > 0) {
        // rebuild result buffer
        OG_RETURN_IFERR(sql_push(stmt, res->v_text.len, (void **)&psz));
        MEMS_RETURN_IFERR(memcpy_s(psz, res->v_text.len, res->v_text.str, res->v_text.len));
        res->v_text.str = psz;
    } else if (g_instance->sql.enable_empty_string_null) {
        SQL_SET_NULL_VAR(res);
    }

    return OG_SUCCESS;
}

status_t sql_verify_regexp_replace(sql_verifier_t *verf, expr_node_t *func)
{
    OG_RETURN_IFERR(sql_verify_regexp_args(verf, func, g_replace_arg_types, "REGEXP_REPLACE"));

    func->datatype = OG_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, OG_MAX_COLUMN_SIZE);
    return OG_SUCCESS;
}

static status_t sql_func_regexp_replace_core(sql_stmt_t *stmt, text_t *res, const void *code,
                                             regexp_args_t *regexp_args)
{
    uint32 pos_start;
    uint32 pos_end;
    text_t sub_str;
    text_t replace;
    bool32 is_first = OG_TRUE;
    regexp_substr_assist_t assist;

    if (regexp_args->var_replace_str.is_null) {
        replace.str = NULL;
        replace.len = 0;
    } else {
        replace = *regexp_args->replace_str;
    }
    if (regexp_args->var_occur.is_null) {
        regexp_args->occur = 0;
    }

    do {
        assist.code = code;
        assist.subject = *(regexp_args->src);
        assist.offset = regexp_args->offset - 1;
        assist.occur = regexp_args->occur;
        assist.subexpr = 0;
        assist.charset = GET_CHARSET_ID;
        OG_BREAK_IF_TRUE((uint32)regexp_args->offset > regexp_args->src->len);
        OG_RETURN_IFERR(cm_regexp_substr(&sub_str, &assist));
        OG_BREAK_IF_TRUE(sub_str.str == NULL);

        pos_start = (uint32)(sub_str.str - regexp_args->src->str);
        if (sub_str.len == 0) {
            if (is_first) {
                is_first = OG_FALSE;
            } else {
                pos_start++;
            }
        }
        pos_end = pos_start + sub_str.len;

        // copy pos characters which not matched
        OG_RETURN_IFERR(sql_func_concat_string(stmt, res, regexp_args->src, pos_start));
        // copy replaced characters
        OG_RETURN_IFERR(sql_func_concat_string(stmt, res, &replace, replace.len));
        // remove pos+replaced characters
        if (regexp_args->src->len < pos_end) {
            OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "source text len(%u) >= pos(%u) + replaced text len(%u)",
                regexp_args->src->len, pos_start, sub_str.len);
            return OG_ERROR;
        }
        CM_REMOVE_FIRST_N(regexp_args->src, pos_end);
        // if occur > 0, replace only once, if occur = 0, replace all
        OG_BREAK_IF_TRUE(regexp_args->occur > 0);
        regexp_args->offset = 1;
    } while (regexp_args->src->len > 0);

    OG_RETURN_IFERR(sql_func_concat_string(stmt, res, regexp_args->src, regexp_args->src->len));
    return OG_SUCCESS;
}

status_t sql_func_regexp_replace(sql_stmt_t *stmt, expr_node_t *func, variant_t *res)
{
    regexp_args_t args;
    void *code = NULL;
    char *psz = NULL;
    bool32 args_error_found;
    status_t ret;
    text_t *result = VALUE_PTR(text_t, res);

    if (res->is_null) {
        return OG_SUCCESS;
    }

    res->is_null = OG_FALSE;
    res->type = OG_TYPE_UNKNOWN;
    args.var_pos.type = OG_TYPE_UNKNOWN;
    args.var_occur.type = OG_TYPE_UNKNOWN;

    OG_RETURN_IFERR(sql_regexp_calc_args(stmt, func, g_replace_arg_types, &args, res));

    args_error_found = (!args.var_pos.is_null && args.offset <= 0) || (!args.var_occur.is_null && args.occur < 0);
    if (args_error_found) {
        OG_THROW_ERROR(ERR_INVALID_REGEXP_INSTR_PARAM_NO_OPT, args.offset, args.occur, 0);
        return OG_ERROR;
    }
    // if some column is pending while calculating expr node, just return success
    OG_RETSUC_IFTRUE(res->type == OG_TYPE_COLUMN);

    res->type = OG_TYPE_STRING;
    result->len = 0;
    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)&result->str));

    if (args.var_pattern.is_null || args.var_src.is_null) {
        res->is_null = args.var_src.is_null;
        if (!args.var_src.is_null) {
            OG_RETURN_IFERR(cm_concat_n_string(result, OG_MAX_COLUMN_SIZE, args.src->str, args.src->len));
        }
        return OG_SUCCESS;
    }

    // if input of offset/ocuur is 'null' or '', just return
    if ((args.var_pos.is_null && args.var_pos.type != OG_TYPE_UNKNOWN) ||
        (args.var_occur.is_null && args.var_occur.type != OG_TYPE_UNKNOWN)) {
        return OG_SUCCESS;
    }

    // alloc memory for processing regular expressions
    OG_RETURN_IFERR(sql_push(stmt, args.pattern->len * 2 + 1, (void **)&psz));
    OG_RETURN_IFERR(cm_replace_regexp_spec_chars(args.pattern, psz, args.pattern->len * 2 + 1));
    OG_LOG_DEBUG_INF("regular expression is: %s", psz);
    OG_RETURN_IFERR(cm_regexp_compile(&code, psz, args.match_param, GET_CHARSET_ID));

    ret = sql_func_regexp_replace_core(stmt, result, code, &args);
    res->is_null = (result->len == 0 && g_instance->sql.enable_empty_string_null);
    cm_regexp_free(code);
    code = NULL;
    return ret;
}
