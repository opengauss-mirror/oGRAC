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
 * expr_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/expr_parser.c
 *
 * -------------------------------------------------------------------------
 */
#include "expr_parser.h"
#include "cond_parser.h"
#include "func_parser.h"
#include "srv_instance.h"
#include "pl_executor.h"
#include "ogsql_type_map.h"
#include "dml_cl.h"
#include "decl_cl.h"
#include "param_decl_cl.h"
#include "ogsql_select_parser.h"

#define MIN_TYPEMODE_COUNT 1
#define MAX_TYPEMODE_COUNT 2

#ifdef __cplusplus
extern "C" {
#endif

static inline void sql_var2entype(word_t *word, expr_node_type_t *node_type)
{
    switch (word->type) {
        case WORD_TYPE_PARAM:
            *node_type = EXPR_NODE_PARAM;
            break;
        case WORD_TYPE_FUNCTION:
            *node_type = EXPR_NODE_FUNC;
            break;
        case WORD_TYPE_VARIANT:
        case WORD_TYPE_DQ_STRING:
        case WORD_TYPE_JOIN_COL:
            *node_type = EXPR_NODE_COLUMN;
            break;
        case WORD_TYPE_BRACKET:
            *node_type = EXPR_NODE_UNKNOWN;
            break;
        case WORD_TYPE_RESERVED:
            *node_type = EXPR_NODE_RESERVED;
            break;
        case WORD_TYPE_KEYWORD:
        case WORD_TYPE_DATATYPE:
            if (word->id == KEY_WORD_CASE) {
                *node_type = EXPR_NODE_CASE;
            } else {
                *node_type = (word->namable) ? EXPR_NODE_COLUMN : EXPR_NODE_UNKNOWN;
            }
            break;
        case WORD_TYPE_PL_NEW_COL:
            *node_type = EXPR_NODE_NEW_COL;
            break;
        case WORD_TYPE_PL_OLD_COL:
            *node_type = EXPR_NODE_OLD_COL;
            break;
        case WORD_TYPE_PL_ATTR:
            *node_type = EXPR_NODE_PL_ATTR;
            break;
        case WORD_TYPE_ARRAY:
            *node_type = EXPR_NODE_ARRAY;
            break;
        default:
            *node_type = EXPR_NODE_CONST;
            break;
    }
}

static inline void sql_oper2entype(word_t *word, expr_node_type_t *node_type)
{
    switch ((operator_type_t)word->id) {
        case OPER_TYPE_ADD:
            *node_type = EXPR_NODE_ADD;
            break;

        case OPER_TYPE_SUB:
            *node_type = EXPR_NODE_SUB;
            break;

        case OPER_TYPE_MUL:
            *node_type = EXPR_NODE_MUL;
            break;

        case OPER_TYPE_DIV:
            *node_type = EXPR_NODE_DIV;
            break;

        case OPER_TYPE_MOD:
            *node_type = EXPR_NODE_MOD;
            break;

        case OPER_TYPE_CAT:
            *node_type = EXPR_NODE_CAT;
            break;
        case OPER_TYPE_BITAND:
            *node_type = EXPR_NODE_BITAND;
            break;
        case OPER_TYPE_BITOR:
            *node_type = EXPR_NODE_BITOR;
            break;
        case OPER_TYPE_BITXOR:
            *node_type = EXPR_NODE_BITXOR;
            break;
        case OPER_TYPE_LSHIFT:
            *node_type = EXPR_NODE_LSHIFT;
            break;
        case OPER_TYPE_RSHIFT:
            *node_type = EXPR_NODE_RSHIFT;
            break;
        default:
            *node_type = EXPR_NODE_UNKNOWN;
            break;
    }
}

static bool32 sql_match_expected(expr_tree_t *expr, word_t *word, expr_node_type_t *node_type)
{
    if (expr->expecting == EXPR_EXPECT_UNARY) {
        expr->expecting = EXPR_EXPECT_VAR;
        if (word->id == OPER_TYPE_PRIOR) {
            *node_type = (expr_node_type_t)EXPR_NODE_PRIOR;
        } else {
            *node_type = (expr_node_type_t)EXPR_NODE_NEGATIVE;
        }
        return OG_TRUE;
    }

    if ((expr->expecting & EXPR_EXPECT_ALPHA) && word->type == WORD_TYPE_ALPHA_PARAM) {
        expr->expecting = EXPR_EXPECT_ALPHA;
        *node_type = (expr_node_type_t)EXPR_NODE_CSR_PARAM;
        return OG_TRUE;
    }

    /* BEGIN for the parse of count(*) branch */
    if (((expr)->expecting & EXPR_EXPECT_STAR) != 0 && EXPR_IS_STAR(word)) {
        expr->expecting = 0;
        *node_type = (expr_node_type_t)EXPR_NODE_STAR;
        return OG_TRUE;
    }

    /* END for the parse of count(*) branch */
    if ((expr->expecting & EXPR_EXPECT_VAR) && ((uint32)word->type & EXPR_VAR_WORDS)) {
        expr->expecting = EXPR_EXPECT_OPER;
        sql_var2entype(word, node_type);
        return OG_TRUE;
    }

    if ((expr->expecting & EXPR_EXPECT_OPER) != 0 && EXPR_IS_OPER(word)) {
        sql_oper2entype(word, node_type);
        expr->expecting = EXPR_EXPECT_VAR | EXPR_EXPECT_UNARY_OP;
        return OG_TRUE;
    }
    return OG_FALSE;
}

static status_t sql_parse_size(lex_t *lex, uint16 max_size, bool32 is_requred, typmode_t *type,
                               datatype_wid_t datatype_id)
{
    bool32 result = OG_FALSE;
    word_t word;
    int32 size;
    text_t text_size;
    text_t text_char;

    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {        // if no bracket found, i.e., the size is not specified
        if (is_requred) { // but the size must be specified, then throw an error
            OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "the column size must be specified");
            return OG_ERROR;
        }
        type->size = 1;
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    text_size = *(text_t *)&word.text;

    // try get char or byte attr
    if (type->datatype == OG_TYPE_CHAR || type->datatype == OG_TYPE_VARCHAR) {
        cm_trim_text((text_t *)&word.text);
        cm_split_text((text_t *)&word.text, ' ', '\0', &text_size, &text_char);

        if (text_char.len > 0) {
            if (datatype_id == DTYP_NCHAR || datatype_id == DTYP_NVARCHAR) {
                source_location_t loc;
                loc.line = word.text.loc.line;
                loc.column = word.text.loc.column + text_size.len;
                OG_SRC_THROW_ERROR(loc, ERR_SQL_SYNTAX_ERROR, "missing right parenthesis");
                return OG_ERROR;
            }
            cm_trim_text(&text_char);
            if (cm_text_str_equal_ins(&text_char, "CHAR")) {
                type->is_char = OG_TRUE;
            } else if (!cm_text_str_equal_ins(&text_char, "BYTE")) {
                OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "the column char type must be CHAR or BYTE");
                return OG_ERROR;
            }
        }
    }

    if (!cm_is_int(&text_size)) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "integer size value expected but %s found",
            W2S(&word));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_text2int(&text_size, &size));

    if (size <= 0 || size > (int32)max_size) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "size value must between 1 and %u", max_size);
        return OG_ERROR;
    }

    type->size = (uint16)size;

    return OG_SUCCESS;
}

static status_t sql_parse_size_bison(type_word_t *type_word, uint16 max_size, bool32 is_requred, typmode_t *type,
    datatype_wid_t datatype_id)
{
    int32 size;

     // if no typemode found, i.e., the size is not specified
    if (type_word->typemode == NULL || type_word->typemode->count == 0) {
        if (is_requred) { // but the size must be specified, then throw an error
            OG_SRC_THROW_ERROR(type_word->loc, ERR_SQL_SYNTAX_ERROR, "the column size must be specified");
            return OG_ERROR;
        }
        type->size = 1;
        return OG_SUCCESS;
    }

    // try get char or byte attr
    if (type->datatype == OG_TYPE_CHAR || type->datatype == OG_TYPE_VARCHAR) {
        type->is_char = type_word->is_char;
    }

    if (type_word->typemode->count != 1) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR,
            "only support 1 type modifiers, but %u found", type_word->typemode->count);
        return OG_ERROR;
    }

    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(type_word->typemode, 0);
    if (expr->root->type != EXPR_NODE_CONST || expr->root->value.type != OG_TYPE_INTEGER) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected");
        return OG_ERROR;
    }
    size = expr->root->value.v_int;
    if (size <= 0 || size > (int32)max_size) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "size value must between 1 and %u", max_size);
        return OG_ERROR;
    }

    type->size = (uint16)size;
    return OG_SUCCESS;
}

static status_t sql_get_precision_typemode(expr_node_t *expr_node, int32 *precision)
{
    if (expr_node->type == EXPR_NODE_CONST) {
        *precision *= expr_node->value.v_int;
        return OG_SUCCESS;
    } else if (expr_node->type == EXPR_NODE_NEGATIVE) {
        *precision *= -1;
        return sql_get_precision_typemode(expr_node->right, precision);
    } else {
        return OG_ERROR;
    }
}

static status_t sql_parse_precision_bison(type_word_t *type_word, typmode_t *type)
{
    expr_tree_t *expr = NULL;
    int32 precision = 1; /* set default value to 1 not 0, incase we get negative number */
    int32 scale = 1; /* set default value to 1 not 0, incase we get negative number */

    if (type_word->typemode == NULL || type_word->typemode->count == 0)  { // both precision and scale are not specified
        type->precision = OG_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = OG_UNSPECIFIED_NUM_SCALE;
        type->size = OG_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_SZ : (uint16)MAX_DEC_BYTE_SZ;
        return OG_SUCCESS;
    }

    /* 2 means a precision value and a scanle value */
    if (type_word->typemode->count > 2) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR,
            "only support 2 type modifiers, but %u found", type_word->typemode->count);
        return OG_ERROR;
    }

    expr = (expr_tree_t *)cm_galist_get(type_word->typemode, 0);
    if (sql_get_precision_typemode(expr->root, &precision) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected");
        return OG_ERROR;
    }

    if (precision < OG_MIN_NUM_PRECISION || precision > OG_MAX_NUM_PRECISION) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
            OG_MIN_NUM_PRECISION, OG_MAX_NUM_PRECISION);
        return OG_ERROR;
    }
    type->precision = (uint8)precision;
    type->size = OG_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_BY_PREC(type->precision) :
                                                      (uint16)MAX_DEC_BYTE_BY_PREC(type->precision);

    if (type_word->typemode->count == 1) { // Only the precision is specified and the scale is not specified
        type->scale = 0;       // then the scale is 0
        return OG_SUCCESS;
    }

    expr = (expr_tree_t *)cm_galist_get(type_word->typemode, 1);
    if (sql_get_precision_typemode(expr->root, &scale) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected");
        return OG_ERROR;
    }
    int32 min_scale = OG_MIN_NUM_SCALE;
    int32 max_scale = OG_MAX_NUM_SCALE;
    if (scale > max_scale || scale < min_scale) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR,
            "numeric scale specifier is out of range (%d to %d)", min_scale, max_scale);
        return OG_ERROR;
    }
    type->scale = (int8)scale;
    return OG_SUCCESS;
}

static status_t sql_parse_precision(lex_t *lex, typmode_t *type)
{
    bool32 result = OG_FALSE;
    text_t text_prec;
    text_t text_scale;
    word_t word;
    int32 precision, scale; // to avoid overflow

    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {                                 // both precision and scale are not specified
        type->precision = OG_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = OG_UNSPECIFIED_NUM_SCALE;
        type->size = OG_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_SZ : (uint16)MAX_DEC_BYTE_SZ;
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    cm_split_text((text_t *)&word.text, ',', '\0', &text_prec, &text_scale);

    if (!cm_is_int(&text_prec)) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision expected but %s found", W2S(&word));
        return OG_ERROR;
    }

    // type->precision
    OG_RETURN_IFERR(cm_text2int(&text_prec, &precision));

    if (precision < OG_MIN_NUM_PRECISION || precision > OG_MAX_NUM_PRECISION) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
            OG_MIN_NUM_PRECISION, OG_MAX_NUM_PRECISION);
        return OG_ERROR;
    }
    type->precision = (uint8)precision;
    type->size = OG_IS_NUMBER2_TYPE(type->datatype) ? (uint16)MAX_DEC2_BYTE_BY_PREC(type->precision) :
                                                      (uint16)MAX_DEC_BYTE_BY_PREC(type->precision);

    cm_trim_text(&text_scale);
    if (text_scale.len == 0) { // Only the precision is specified and the scale is not specified
        type->scale = 0;       // then the scale is 0
        return OG_SUCCESS;
    }

    if (!cm_is_int(&text_scale)) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale expected but %s found", W2S(&word));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_text2int(&text_scale, &scale));

    int32 min_scale = OG_MIN_NUM_SCALE;
    int32 max_scale = OG_MAX_NUM_SCALE;
    if (scale > max_scale || scale < min_scale) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "numeric scale specifier is out of range (%d to %d)",
            min_scale, max_scale);
        return OG_ERROR;
    }
    type->scale = (int8)scale;
    return OG_SUCCESS;
}

static status_t sql_parse_real_mode_bison(type_word_t *type_word, pmode_t pmod, typmode_t *type)
{
    int32 precision = 1; /* set default value to 1 not 0, incase we get negative number */
    int32 scale = 1; /* set default value to 1 not 0, incase we get negative number */
    type->size = sizeof(double);

    // both precision and scale are not specified
    if (pmod == PM_PL_ARG || type_word->typemode == NULL || type_word->typemode->count == 0) {
        type->precision = OG_UNSPECIFIED_REAL_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = OG_UNSPECIFIED_REAL_SCALE;
        return OG_SUCCESS;
    }

    /* 2 means a precision value and a scanle value */
    if (type_word->typemode->count > 2) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR,
            "only support 2 type modifiers, but %u found", type_word->typemode->count);
        return OG_ERROR;
    }

    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(type_word->typemode, 0);
    if (sql_get_precision_typemode(expr->root, &precision) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected");
        return OG_ERROR;
    }
    if (precision < OG_MIN_REAL_PRECISION || precision > OG_MAX_REAL_PRECISION) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
            OG_MIN_NUM_PRECISION, OG_MAX_NUM_PRECISION);
        return OG_ERROR;
    }
    type->precision = (uint8)precision;

    if (type_word->typemode->count == 1) { // Only the precision is specified and the scale is not specified
        type->scale = 0;       // then the scale is 0
        return OG_SUCCESS;
    }

    expr = (expr_tree_t *)cm_galist_get(type_word->typemode, 1);
    if (sql_get_precision_typemode(expr->root, &scale) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected");
        return OG_ERROR;
    }
    if (scale > OG_MAX_REAL_SCALE || scale < OG_MIN_REAL_SCALE) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "scale must between %d and %d", OG_MIN_REAL_SCALE,
            OG_MAX_REAL_SCALE);
        return OG_ERROR;
    }
    type->scale = (int8)scale;
    return OG_SUCCESS;
}

static status_t sql_parse_real_mode(lex_t *lex, pmode_t pmod, typmode_t *type)
{
    bool32 result = OG_FALSE;
    text_t text_prec;
    text_t text_scale;
    word_t word;
    int32 precision, scale; // to avoid overflow

    type->size = sizeof(double);
    do {
        if (pmod == PM_PL_ARG) {
            result = OG_FALSE;
            break;
        }
        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    } while (0);

    if (!result) {                                  // both precision and scale are not specified
        type->precision = OG_UNSPECIFIED_REAL_PREC; /* *< 0 stands for precision is not defined when create table */
        type->scale = OG_UNSPECIFIED_REAL_SCALE;
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    cm_split_text((text_t *)&word.text, ',', '\0', &text_prec, &text_scale);

    if (cm_text2int_ex(&text_prec, &precision) != NERR_SUCCESS) {
        OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must be an integer");
        return OG_ERROR;
    }

    if (precision < OG_MIN_REAL_PRECISION || precision > OG_MAX_REAL_PRECISION) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "precision must between %d and %d",
            OG_MIN_NUM_PRECISION, OG_MAX_NUM_PRECISION);
        return OG_ERROR;
    }
    type->precision = (uint8)precision;

    cm_trim_text(&text_scale);
    if (text_scale.len == 0) { // Only the precision is specified and the scale is not specified
        type->scale = 0;       // then the scale is 0
        return OG_SUCCESS;
    }

    if (cm_text2int_ex(&text_scale, &scale) != NERR_SUCCESS) {
        OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale must be an integer");
        return OG_ERROR;
    }

    if (scale > OG_MAX_REAL_SCALE || scale < OG_MIN_REAL_SCALE) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "scale must between %d and %d", OG_MIN_REAL_SCALE,
            OG_MAX_REAL_SCALE);
        return OG_ERROR;
    }
    type->scale = (int8)scale;
    return OG_SUCCESS;
}

/* used for parsing a number/decimal type in PL argument
 * e.g. the type of t_column, the precison and scale of NUMBER are not allowed here.
 * CREATE OR REPLACE PROCEDURE select_item ( *   t_column in NUMBER,
 * )
 * IS
 * temp1 VARCHAR2(10);
 * BEGIN
 * temp1 := t_column;
 * DBE_OUTPUT.PRINT_LINE ('No Data found for SELECT on ' || temp1);
 * END;
 * /
 *
 * @see sql_parse_rough_interval_attr
 *  */
static inline status_t sql_parse_rough_precision(lex_t *lex, typmode_t *type)
{
    type->precision = OG_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
    type->scale = OG_UNSPECIFIED_NUM_SCALE;
    type->size = OG_IS_NUMBER2_TYPE(type->datatype) ? MAX_DEC2_BYTE_SZ : MAX_DEC_BYTE_SZ;
    return OG_SUCCESS;
}

/**
 * Parse the precision of a DATATIME or INTERVAL datatype
 * The specified precision must be between *min_prec* and *max_prec*.
 * If it not specified, then the default value is used
 */
status_t sql_parse_datetime_precision_bison(galist_t *typemode, source_location_t loc, int32 *val_int32,
    int32 def_prec, int32 min_prec, int32 max_prec, const char *field_name)
{
    if (typemode == NULL || typemode->count == 0) {
        *val_int32 = def_prec;
        return OG_SUCCESS;
    }

    if (typemode->count != 1) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR,
            "only support 1 type modifiers, but %u found", typemode->count);
        return OG_ERROR;
    }

    expr_tree_t *expr = (expr_tree_t *)cm_galist_get(typemode, 0);
    if (expr->root->type != EXPR_NODE_CONST || expr->root->value.type != OG_TYPE_INTEGER) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected");
        return OG_ERROR;
    }
    *val_int32 = expr->root->value.v_int;
    if (*val_int32 < min_prec || *val_int32 > max_prec) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR, "%s precision must be between %d and %d", field_name,
            min_prec, max_prec);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/**
 * Parse the precision of a DATATIME or INTERVAL datatype
 * The specified precision must be between *min_prec* and *max_prec*.
 * If it not specified, then the default value is used
 */
static status_t sql_parse_datetime_precision(lex_t *lex, int32 *val_int32, int32 def_prec, int32 min_prec,
    int32 max_prec, const char *field_name)
{
    bool32 result = OG_FALSE;
    word_t word;

    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {
        *val_int32 = def_prec;
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word.text);

    if (cm_text2int_ex((text_t *)&word.text, val_int32) != NERR_SUCCESS) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid %s precision, expected integer",
            field_name);
        return OG_ERROR;
    }

    if (*val_int32 < min_prec || *val_int32 > max_prec) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s precision must be between %d and %d", field_name,
            min_prec, max_prec);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/**
 * Parse the leading precision and fractional_seconds_precsion of SECOND
 *
 */
static status_t sql_parse_second_precision(lex_t *lex, int32 *lead_prec, int32 *frac_prec)
{
    bool32 result = OG_FALSE;
    word_t word;
    status_t status;

    OG_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));

    if (!result) {
        *lead_prec = ITVL_DEFAULT_DAY_PREC;
        *frac_prec = ITVL_DEFAULT_SECOND_PREC;
        return OG_SUCCESS;
    }

    lex_remove_brackets(&word.text);
    OG_RETURN_IFERR(lex_push(lex, &word.text));

    do {
        status = OG_ERROR;
        OG_BREAK_IF_ERROR(lex_fetch(lex, &word));

        if (cm_text2int_ex((text_t *)&word.text, lead_prec) != NERR_SUCCESS) {
            OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid precision, expected integer");
            break;
        }

        if (*lead_prec > ITVL_MAX_DAY_PREC || *lead_prec < ITVL_MIN_DAY_PREC) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "DAY precision must be between %d and %d",
                ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC);
            break;
        }

        OG_BREAK_IF_ERROR(lex_try_fetch_char(lex, ',', &result));
        if (!result) {
            *frac_prec = ITVL_DEFAULT_SECOND_PREC;
            status = OG_SUCCESS;
            break;
        }

        OG_BREAK_IF_ERROR(lex_fetch(lex, &word));
        if (cm_text2int_ex((text_t *)&word.text, frac_prec) != NERR_SUCCESS) {
            OG_SRC_THROW_ERROR(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid precision, expected integer");
            break;
        }

        if (*frac_prec > ITVL_MAX_SECOND_PREC || *frac_prec < ITVL_MIN_SECOND_PREC) {
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                "fractional second precision must be between %d and %d", ITVL_MIN_SECOND_PREC, ITVL_MAX_SECOND_PREC);
            break;
        }
        status = OG_SUCCESS;
    } while (0);

    lex_pop(lex);
    return status;
}

/**
* Parse the leading precision and fractional_seconds_precsion of SECOND for bison
* Support SECOND(5) and SECOND(5,2) syntax
*/
status_t sql_parse_second_precision_bison(galist_t *typemode, source_location_t loc, int32 *lead_prec,
    int32 *frac_prec)
{
    if (typemode == NULL || typemode->count == 0) {
        *lead_prec = ITVL_DEFAULT_DAY_PREC;
        *frac_prec = ITVL_DEFAULT_SECOND_PREC;
        return OG_SUCCESS;
    }

    if (typemode->count < MIN_TYPEMODE_COUNT || typemode->count > MAX_TYPEMODE_COUNT) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR,
            "only support 1 or 2 type modifiers for SECOND, but %u found", typemode->count);
        return OG_ERROR;
    }

    // Parse leading precision
    expr_tree_t *expr1 = (expr_tree_t *)cm_galist_get(typemode, 0);
    if (expr1->root->type != EXPR_NODE_CONST || expr1->root->value.type != OG_TYPE_INTEGER) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected for leading precision");
        return OG_ERROR;
    }
    *lead_prec = expr1->root->value.v_int;
    if (*lead_prec < ITVL_MIN_DAY_PREC || *lead_prec > ITVL_MAX_DAY_PREC) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR, "SECOND precision must be between %d and %d",
            ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC);
        return OG_ERROR;
    }

    // Parse fractional precision if provided
    if (typemode->count == MAX_TYPEMODE_COUNT) {
        expr_tree_t *expr2 = (expr_tree_t *)cm_galist_get(typemode, 1);
        if (expr2->root->type != EXPR_NODE_CONST || expr2->root->value.type != OG_TYPE_INTEGER) {
            OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR, "int const modifiers expected for fractional precision");
            return OG_ERROR;
        }
        *frac_prec = expr2->root->value.v_int;
        if (*frac_prec < ITVL_MIN_SECOND_PREC || *frac_prec > ITVL_MAX_SECOND_PREC) {
            OG_SRC_THROW_ERROR_EX(loc, ERR_SQL_SYNTAX_ERROR,
                "fractional second precision must be between %d and %d", ITVL_MIN_SECOND_PREC, ITVL_MAX_SECOND_PREC);
            return OG_ERROR;
        }
    } else {
        *frac_prec = ITVL_DEFAULT_SECOND_PREC;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_timestamp_mod_bison(type_word_t *type_word, typmode_t *type, pmode_t pmod,
    word_t *word)
{
    int32 prec_val = OG_MAX_DATETIME_PRECISION;

    type->datatype = OG_TYPE_TIMESTAMP;

    if (pmod != PM_PL_ARG) {
        if (sql_parse_datetime_precision_bison(type_word->typemode, type_word->loc, &prec_val,
            OG_DEFAULT_DATETIME_PRECISION, OG_MIN_DATETIME_PRECISION, OG_MAX_DATETIME_PRECISION,
            "timestamp") != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    type->precision = (uint8)prec_val;
    type->scale = 0;
    type->size = sizeof(timestamp_t);
    if (type_word->timezone == WITHOUT_TIMEZONE) {
        return OG_SUCCESS;
    }

    if (type_word->timezone == WITH_LOCAL_TIMEZONE) {
        type->datatype = OG_TYPE_TIMESTAMP_LTZ;
        word->id = DTYP_TIMESTAMP_LTZ;
    } else {
        type->datatype = OG_TYPE_TIMESTAMP_TZ;
        type->size = sizeof(timestamp_tz_t);
        word->id = DTYP_TIMESTAMP_TZ;
    }

    return OG_SUCCESS;
}

static inline status_t sql_parse_timestamp_mod(lex_t *lex, typmode_t *type, pmode_t pmod, word_t *word)
{
    uint32 match_id;
    bool32 is_local = OG_FALSE;
    int32 prec_val = OG_MAX_DATETIME_PRECISION;

    type->datatype = OG_TYPE_TIMESTAMP;

    if (pmod != PM_PL_ARG) {
        if (sql_parse_datetime_precision(lex, &prec_val, OG_DEFAULT_DATETIME_PRECISION, OG_MIN_DATETIME_PRECISION,
            OG_MAX_DATETIME_PRECISION, "timestamp") != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    type->precision = (uint8)prec_val;
    type->scale = 0;
    type->size = sizeof(timestamp_t);

    if (lex_try_fetch_1of2(lex, "WITH", "WITHOUT", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (match_id == OG_INVALID_ID32) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "LOCAL", &is_local));

    OG_RETURN_IFERR(lex_expected_fetch_word2(lex, "TIME", "ZONE"));

    if (match_id == 1) {
        /* timestamp without time zone : do the same as timestamp. */
        return OG_SUCCESS;
    }

    if (is_local) {
        type->datatype = OG_TYPE_TIMESTAMP_LTZ;
        word->id = DTYP_TIMESTAMP_LTZ;
    } else {
        if (lex->call_version >= CS_VERSION_8) {
            type->datatype = OG_TYPE_TIMESTAMP_TZ;
            type->size = sizeof(timestamp_tz_t);
        } else {
            /* OG_TYPE_TIMESTAMP_TZ_FAKE is same with timestamp */
            type->datatype = OG_TYPE_TIMESTAMP_TZ_FAKE;
            type->size = sizeof(timestamp_t);
        }
        word->id = DTYP_TIMESTAMP_TZ;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_interval_ds(lex_t *lex, typmode_t *type, uint32 *pfmt, uint32 match_id, uint32 *itvl_fmt)
{
    int32 prec;
    int32 frac;
    bool32 result = OG_FALSE;
    uint32 match_id2;
    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };

    type->datatype = OG_TYPE_INTERVAL_DS;
    type->size = sizeof(interval_ds_t);

    if (match_id < 5) {
        // parse leading precision
        OG_RETURN_IFERR(sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC,
            ITVL_MAX_DAY_PREC, "DAY"));
        type->day_prec = (uint8)prec;
        type->frac_prec = 0;

        OG_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));
        if (!result) {
            if (pfmt != NULL) {
                (*pfmt) = *itvl_fmt;
            }
            return OG_SUCCESS;
        }
        OG_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id2, 4, "DAY", "HOUR", "MINUTE", "SECOND"));
        match_id2 += 2;

        if (match_id2 < match_id) {
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_INTERVAL_TEXT, "-- invalid field name");
            return OG_ERROR;
        }
        for (uint32 i = match_id + 1; i <= match_id2; ++i) {
            *itvl_fmt |= itvl_uints[i];
        }
        if (match_id2 == 5) {
            // parse second frac_precision
            OG_RETURN_IFERR(sql_parse_datetime_precision(lex, &frac, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
                ITVL_MAX_SECOND_PREC, "fractional second"));
            type->frac_prec = (uint8)frac;
        }
    } else {
        // parse leading and fractional precision
        OG_RETURN_IFERR(sql_parse_second_precision(lex, &prec, &frac));
        type->day_prec = (uint8)prec;
        type->frac_prec = (uint8)frac;
    }
    return OG_SUCCESS;
}

/* parsing an interval literal in a SQL expression
 * e.g., INTERVAL '123-2' YEAR(3) TO MONTH, INTERVAL '4 5:12' DAY TO MINUTE */
static inline status_t sql_parse_interval_literal(lex_t *lex, typmode_t *type, uint32 *pfmt)
{
    uint32 match_id;
    uint32 match_id2;
    int32 prec;
    bool32 result = OG_FALSE;
    uint32 itvl_fmt;

    const interval_unit_t itvl_uints[] = { IU_YEAR, IU_MONTH, IU_DAY, IU_HOUR, IU_MINUTE, IU_SECOND };

    OG_RETURN_IFERR(lex_expected_fetch_1ofn(lex, &match_id, 6, "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND"));

    itvl_fmt = itvl_uints[match_id];

    if (match_id < 2) {
        type->datatype = OG_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        // parse leading precision
        OG_RETURN_IFERR(sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC,
            ITVL_MAX_YEAR_PREC, "YEAR"));
        type->year_prec = (uint8)prec;
        type->reserved = 0;

        if (match_id == 0) {
            OG_RETURN_IFERR(lex_try_fetch(lex, "TO", &result));
            if (result) {
                OG_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "MONTH", &match_id2));
                itvl_fmt |= itvl_uints[match_id2];
            }
        }
    } else {
        OG_RETURN_IFERR(sql_parse_interval_ds(lex, type, pfmt, match_id, &itvl_fmt));
    }

    if (pfmt != NULL) {
        (*pfmt) = itvl_fmt;
    }
    return OG_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR [( year_precision)]  TO  MONTH
 * INTERVAL  DAY [( day_precision)]  TO  SECOND[( fractional_seconds_precision)]
 */
static status_t sql_parse_interval_attr_bison(type_word_t *type_word, typmode_t *type, word_t *word,
    datatype_wid_t dwid)
{
    int32 prec;

    if (dwid == DTYP_INTERVAL_YM) {
        // parse year_precision
        if (sql_parse_datetime_precision_bison(type_word->typemode, type_word->loc, &prec, ITVL_DEFAULT_YEAR_PREC,
            ITVL_MIN_YEAR_PREC, ITVL_MAX_YEAR_PREC, "YEAR") != OG_SUCCESS) {
            return OG_ERROR;
        }
        type->year_prec = (uint8)prec;
        type->reserved = 0;
        type->datatype = OG_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        // parse day_precision
        if (sql_parse_datetime_precision_bison(type_word->typemode, type_word->loc, &prec, ITVL_DEFAULT_DAY_PREC,
            ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC, "DAY") != OG_SUCCESS) {
            return OG_ERROR;
        }
        type->day_prec = (uint8)prec;
        // parse fractional_seconds_precision
        if (sql_parse_datetime_precision_bison(type_word->second_typemde, type_word->loc, &prec,
            ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC, ITVL_MAX_SECOND_PREC, "SECOND") != OG_SUCCESS) {
            return OG_ERROR;
        }
        type->frac_prec = (uint8)prec;
        type->datatype = OG_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return OG_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR TO  MONTH
 * INTERVAL  DAY TO  SECOND
 *
 * @see sql_parse_rough_precision
 */
static status_t sql_parse_rough_interval_attr_bison(type_word_t *type_word, typmode_t *type, word_t *word,
    datatype_wid_t dwid)
{
    if (type_word->typemode != NULL || type_word->second_typemde != NULL) {
        OG_SRC_THROW_ERROR_EX(type_word->loc, ERR_SQL_SYNTAX_ERROR, "don't support any type modifiers");
        return OG_ERROR;
    }
    if (dwid == DTYP_INTERVAL_YM) {
        // set year_precision
        type->year_prec = (uint8)ITVL_MAX_YEAR_PREC;
        type->reserved = 0;
        type->datatype = OG_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        // set day_precision
        type->day_prec = (uint8)ITVL_MAX_DAY_PREC;
        // set fractional_seconds_precision
        type->frac_prec = (uint8)ITVL_MAX_SECOND_PREC;
        type->datatype = OG_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return OG_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR [( year_precision)]  TO  MONTH
 * INTERVAL  DAY [( day_precision)]  TO  SECOND[( fractional_seconds_precision)]
 */
static inline status_t sql_parse_interval_attr(lex_t *lex, typmode_t *type, word_t *word)
{
    uint32 match_id;
    int32 prec;

    OG_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "DAY", &match_id));

    if (match_id == 0) {
        // parse year_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_YEAR_PREC, ITVL_MIN_YEAR_PREC, ITVL_MAX_YEAR_PREC,
            "YEAR") != OG_SUCCESS) {
            return OG_ERROR;
        }
        type->year_prec = (uint8)prec;
        type->reserved = 0;
        OG_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "MONTH"));

        type->datatype = OG_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        // parse day_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_DAY_PREC, ITVL_MIN_DAY_PREC, ITVL_MAX_DAY_PREC,
            "DAY") != OG_SUCCESS) {
            return OG_ERROR;
        }
        type->day_prec = (uint8)prec;

        OG_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "SECOND"));

        // parse fractional_seconds_precision
        if (sql_parse_datetime_precision(lex, &prec, ITVL_DEFAULT_SECOND_PREC, ITVL_MIN_SECOND_PREC,
            ITVL_MAX_SECOND_PREC, "SECOND") != OG_SUCCESS) {
            return OG_ERROR;
        }
        type->frac_prec = (uint8)prec;

        type->datatype = OG_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return OG_SUCCESS;
}

/**
 * Further distinguish two INTERVAL datatypes, with syntax:
 * INTERVAL  YEAR TO  MONTH
 * INTERVAL  DAY TO  SECOND
 *
 * @see sql_parse_rough_precision
 */
static inline status_t sql_parse_rough_interval_attr(lex_t *lex, typmode_t *type, word_t *word)
{
    uint32 match_id;

    OG_RETURN_IFERR(lex_expected_fetch_1of2(lex, "YEAR", "DAY", &match_id));

    if (match_id == 0) {
        OG_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "MONTH"));

        // set year_precision
        type->year_prec = (uint8)ITVL_MAX_YEAR_PREC;
        type->reserved = 0;
        type->datatype = OG_TYPE_INTERVAL_YM;
        type->size = sizeof(interval_ym_t);
        word->id = DTYP_INTERVAL_YM;
    } else {
        OG_RETURN_IFERR(lex_expected_fetch_word2(lex, "TO", "SECOND"));

        // set day_precision
        type->day_prec = (uint8)ITVL_MAX_DAY_PREC;
        // set fractional_seconds_precision
        type->frac_prec = (uint8)ITVL_MAX_SECOND_PREC;
        type->datatype = OG_TYPE_INTERVAL_DS;
        type->size = sizeof(interval_ds_t);
        word->id = DTYP_INTERVAL_DS;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_datatype_charset(lex_t *lex, uint8 *charset)
{
    word_t word;
    bool32 result = OG_FALSE;
    uint16 charset_id;

    if (lex_try_fetch(lex, "CHARACTER", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "SET") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    charset_id = cm_get_charset_id_ex(&word.text.value);
    if (charset_id == OG_INVALID_ID16) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown charset option %s", T2S(&word.text.value));
        return OG_ERROR;
    }

    *charset = (uint8)charset_id;

    return OG_SUCCESS;
}

static status_t sql_parse_datatype_collate(lex_t *lex, uint8 *collate)
{
    word_t word;
    bool32 result = OG_FALSE;
    uint16 collate_id;

    if (lex_try_fetch(lex, "COLLATE", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        return OG_SUCCESS;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }

    collate_id = cm_get_collation_id(&word.text.value);
    if (collate_id == OG_INVALID_ID16) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "unknown collation option %s",
            T2S(&word.text.value));
        return OG_ERROR;
    }

    *collate = (uint8)collate_id;
    return OG_SUCCESS;
}

#define sql_set_default_typmod(typmod, typsz) ((typmod)->size = (uint16)(typsz), OG_SUCCESS)

static inline status_t sql_parse_varchar_mode(lex_t *lex, pmode_t pmod, typmode_t *typmod, datatype_wid_t dword_id)
{
    if (pmod == PM_PL_ARG) {
        return sql_set_default_typmod(typmod, OG_MAX_STRING_LEN);
    }
    return sql_parse_size(lex, (pmod == PM_NORMAL) ? OG_MAX_COLUMN_SIZE : OG_MAX_STRING_LEN, OG_TRUE, typmod,
        dword_id);
}

static inline status_t sql_parse_varchar_mode_bison(type_word_t *type_word, pmode_t pmod, typmode_t *typmod,
    datatype_wid_t dword_id)
{
    if (pmod == PM_PL_ARG) {
        return sql_set_default_typmod(typmod, OG_MAX_STRING_LEN);
    }
    return sql_parse_size_bison(type_word, (pmod == PM_NORMAL) ? OG_MAX_COLUMN_SIZE : OG_MAX_STRING_LEN,
        OG_TRUE, typmod, dword_id);
}

static status_t sql_parse_orcl_typmod_bison(type_word_t *type, pmode_t pmod, typmode_t *typmode, word_t *typword)
{
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        case DTYP_BIGINT:
        case DTYP_UBIGINT:
        case DTYP_INTEGER:
        case DTYP_UINTEGER:
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
            typmode->datatype = OG_TYPE_NUMBER;
            typmode->precision = OG_MAX_NUM_PRECISION;
            typmode->scale = 0;
            typmode->size = MAX_DEC_BYTE_BY_PREC(OG_MAX_NUM_PRECISION);
            return OG_SUCCESS;

        case DTYP_BOOLEAN:
            typmode->datatype = OG_TYPE_BOOLEAN;
            typmode->size = sizeof(bool32);
            return OG_SUCCESS;

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_NUMBER:
        case DTYP_DECIMAL:
            typmode->datatype = OG_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision_bison(type, typmode) :
                sql_parse_rough_precision(NULL, typmode);
        case DTYP_NUMBER2:
            typmode->datatype = OG_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision_bison(type, typmode) :
                sql_parse_rough_precision(NULL, typmode);

        case DTYP_BINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmode->datatype = OG_TYPE_RAW;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmode->datatype = OG_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
            typmode->datatype = OG_TYPE_VARCHAR;
            return sql_parse_varchar_mode_bison(type, pmod, typmode, dword_id);

        case DTYP_DATE:
            typmode->datatype = OG_TYPE_DATE;
            typmode->size = sizeof(date_t);
            return OG_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod_bison(type, typmode, pmod, typword);

        case DTYP_INTERVAL_DS:
        case DTYP_INTERVAL_YM:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr_bison(type, typmode, typword, dword_id) :
                                         sql_parse_rough_interval_attr_bison(type, typmode, typword, dword_id);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmode->datatype = OG_TYPE_REAL;
            typmode->size = sizeof(double);
            return OG_SUCCESS;

        case DTYP_BINARY_UINTEGER:
            typmode->datatype = OG_TYPE_UINT32;
            typmode->size = sizeof(uint32);
            return OG_SUCCESS;
        case DTYP_BINARY_INTEGER:
            typmode->datatype = OG_TYPE_INTEGER;
            typmode->size = sizeof(int32);
            return OG_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmode->datatype = OG_TYPE_BIGINT;
            typmode->size = sizeof(int64);
            return OG_SUCCESS;

        case DTYP_BLOB: {
            typmode->datatype = OG_TYPE_BLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmode->datatype = OG_TYPE_CLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
            typmode->datatype = OG_TYPE_IMAGE;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmode->datatype = OG_TYPE_VARCHAR;
            OG_RETURN_IFERR(sql_parse_varchar_mode_bison(type, pmod, typmode, dword_id));
            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_NCHAR:
            typmode->datatype = OG_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                OG_RETURN_IFERR(sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id));
            } else {
                OG_RETURN_IFERR(sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE));
            }

            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_BINARY_UBIGINT:
            OG_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return OG_ERROR;

        default:
            OG_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                T2S(&typword->text.value));
            return OG_ERROR;
    }
}

static status_t sql_parse_orcl_typmod(lex_t *lex, pmode_t pmod, typmode_t *typmode, word_t *typword)
{
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        case DTYP_BIGINT:
        case DTYP_UBIGINT:
        case DTYP_INTEGER:
        case DTYP_UINTEGER:
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
            typmode->datatype = OG_TYPE_NUMBER;
            typmode->precision = OG_MAX_NUM_PRECISION;
            typmode->scale = 0;
            typmode->size = MAX_DEC_BYTE_BY_PREC(OG_MAX_NUM_PRECISION);
            return OG_SUCCESS;

        case DTYP_BOOLEAN:
            typmode->datatype = OG_TYPE_BOOLEAN;
            typmode->size = sizeof(bool32);
            return OG_SUCCESS;

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_NUMBER:
        case DTYP_DECIMAL:
            typmode->datatype = OG_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);
        case DTYP_NUMBER2:
            typmode->datatype = OG_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);

        case DTYP_BINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmode->datatype = OG_TYPE_RAW;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmode->datatype = OG_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
            typmode->datatype = OG_TYPE_VARCHAR;
            return sql_parse_varchar_mode(lex, pmod, typmode, dword_id);

        case DTYP_DATE:
            typmode->datatype = OG_TYPE_DATE;
            typmode->size = sizeof(date_t);
            return OG_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod(lex, typmode, pmod, typword);

        case DTYP_INTERVAL:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr(lex, typmode, typword) :
                                         sql_parse_rough_interval_attr(lex, typmode, typword);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmode->datatype = OG_TYPE_REAL;
            typmode->size = sizeof(double);
            return OG_SUCCESS;

        case DTYP_BINARY_UINTEGER:
            typmode->datatype = OG_TYPE_UINT32;
            typmode->size = sizeof(uint32);
            return OG_SUCCESS;
        case DTYP_BINARY_INTEGER:
            typmode->datatype = OG_TYPE_INTEGER;
            typmode->size = sizeof(int32);
            return OG_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmode->datatype = OG_TYPE_BIGINT;
            typmode->size = sizeof(int64);
            return OG_SUCCESS;

        case DTYP_BLOB: {
            typmode->datatype = OG_TYPE_BLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmode->datatype = OG_TYPE_CLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
#ifdef OG_RAC_ING
            if (IS_COORDINATOR) {
                OG_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT,
                    "IMAGE Type(includes IMAGE and LONGBLOB and MEDIUMBLOB)");
                return OG_ERROR;
            }
#endif
            typmode->datatype = OG_TYPE_IMAGE;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmode->datatype = OG_TYPE_VARCHAR;
            OG_RETURN_IFERR(sql_parse_varchar_mode(lex, pmod, typmode, dword_id));
            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_NCHAR:
            typmode->datatype = OG_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                OG_RETURN_IFERR(sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id));
            } else {
                OG_RETURN_IFERR(sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE));
            }

            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_BINARY_UBIGINT:
            OG_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return OG_ERROR;

        default:
            OG_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                T2S(&typword->text.value));
            return OG_ERROR;
    }
}

static status_t sql_parse_native_typmod(lex_t *lex, pmode_t pmod, typmode_t *typmode, word_t *typword)
{
    status_t status;
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        /* now we map smallint/tinyint unsigned into uint */
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
        case DTYP_USMALLINT:
        case DTYP_UTINYINT:
            typmode->datatype = OG_TYPE_UINT32;
            typmode->size = sizeof(uint32);
            return OG_SUCCESS;
        /* now we map smallint/tinyint signed into int */
        case DTYP_SMALLINT:
        case DTYP_TINYINT:
        case DTYP_INTEGER:
        case DTYP_PLS_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmode->datatype = OG_TYPE_INTEGER;
            typmode->size = sizeof(int32);
            return OG_SUCCESS;

        case DTYP_BOOLEAN:
            typmode->datatype = OG_TYPE_BOOLEAN;
            typmode->size = sizeof(bool32);
            return OG_SUCCESS;

        case DTYP_NUMBER:
            typmode->datatype = OG_TYPE_NUMBER;
            status = (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);
            OG_RETURN_IFERR(status);
            sql_try_match_type_map(lex->curr_user, typmode);
            return status;

        case DTYP_NUMBER2:
            typmode->datatype = OG_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);

        case DTYP_DECIMAL:
            typmode->datatype = OG_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision(lex, typmode) : sql_parse_rough_precision(lex, typmode);

        case DTYP_BINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmode->datatype = OG_TYPE_RAW;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmode->datatype = OG_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ? sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                                         sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
        case DTYP_STRING:
            typmode->datatype = OG_TYPE_VARCHAR;
            return sql_parse_varchar_mode(lex, pmod, typmode, dword_id);

        case DTYP_DATE:
            typmode->datatype = OG_TYPE_DATE;
            typmode->size = sizeof(date_t);
            return OG_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod(lex, typmode, pmod, typword);

        case DTYP_INTERVAL:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr(lex, typmode, typword) :
                                         sql_parse_rough_interval_attr(lex, typmode, typword);

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
            typmode->datatype = OG_TYPE_REAL;
            return sql_parse_real_mode(lex, pmod, typmode);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmode->datatype = OG_TYPE_REAL;
            typmode->size = sizeof(double);
            typmode->precision = OG_UNSPECIFIED_REAL_PREC;
            typmode->scale = OG_UNSPECIFIED_REAL_SCALE;
            return OG_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BIGINT:
        case DTYP_BINARY_BIGINT:
            typmode->datatype = OG_TYPE_BIGINT;
            typmode->size = sizeof(int64);
            return OG_SUCCESS;

        case DTYP_JSONB:
        case DTYP_BLOB: {
            typmode->datatype = OG_TYPE_BLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmode->datatype = OG_TYPE_CLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
            typmode->datatype = OG_TYPE_IMAGE;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmode->datatype = OG_TYPE_VARCHAR;
            OG_RETURN_IFERR(sql_parse_varchar_mode(lex, pmod, typmode, dword_id));
            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_NCHAR:
            typmode->datatype = OG_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                OG_RETURN_IFERR(sql_parse_size(lex, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id));
            } else {
                OG_RETURN_IFERR(sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE));
            }

            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_UBIGINT:
        case DTYP_BINARY_UBIGINT:
            OG_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return OG_ERROR;

        default:
            OG_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                T2S(&typword->text.value));
            return OG_ERROR;
    }
}

static status_t sql_parse_native_typmod_bison(char *user, type_word_t *type, pmode_t pmod,
    typmode_t *typmode, word_t *typword)
{
    text_t curr_user;
    status_t status;
    datatype_wid_t dword_id = (datatype_wid_t)typword->id;
    switch (dword_id) {
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
            typmode->datatype = OG_TYPE_UINT32;
            typmode->size = sizeof(uint32);
            return OG_SUCCESS;
        case DTYP_USMALLINT:
        case DTYP_UTINYINT:
        case DTYP_SMALLINT:
        case DTYP_TINYINT:
        case DTYP_INTEGER:
        case DTYP_PLS_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmode->datatype = OG_TYPE_INTEGER;
            typmode->size = sizeof(int32);
            return OG_SUCCESS;

        case DTYP_BOOLEAN:
            typmode->datatype = OG_TYPE_BOOLEAN;
            typmode->size = sizeof(bool32);
            return OG_SUCCESS;

        case DTYP_NUMBER:
            typmode->datatype = OG_TYPE_NUMBER;
            status = (pmod != PM_PL_ARG) ? sql_parse_precision_bison(type, typmode) :
                sql_parse_rough_precision(NULL, typmode);
            OG_RETURN_IFERR(status);
            curr_user.str = user;
            curr_user.len = (uint32)strlen(user);
            sql_try_match_type_map(&curr_user, typmode);
            return status;

        case DTYP_NUMBER2:
            typmode->datatype = OG_TYPE_NUMBER2;
            return (pmod != PM_PL_ARG) ? sql_parse_precision_bison(type, typmode) :
                sql_parse_rough_precision(NULL, typmode);

        case DTYP_DECIMAL:
            typmode->datatype = OG_TYPE_NUMBER;
            return (pmod != PM_PL_ARG) ? sql_parse_precision_bison(type, typmode) :
                sql_parse_rough_precision(NULL, typmode);

        case DTYP_BINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_BINARY;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARBINARY:
            typmode->datatype = g_instance->sql.string_as_hex_binary ? OG_TYPE_RAW : OG_TYPE_VARBINARY;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_RAW:
            typmode->datatype = OG_TYPE_RAW;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_TRUE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_CHAR:
            typmode->datatype = OG_TYPE_CHAR;
            return (pmod != PM_PL_ARG) ?
                    sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id) :
                    sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_VARCHAR:
        case DTYP_STRING:
            typmode->datatype = OG_TYPE_VARCHAR;
            return sql_parse_varchar_mode_bison(type, pmod, typmode, dword_id);

        case DTYP_DATE:
            typmode->datatype = OG_TYPE_DATE;
            typmode->size = sizeof(date_t);
            return OG_SUCCESS;

        case DTYP_TIMESTAMP:
            return sql_parse_timestamp_mod_bison(type, typmode, pmod, typword);

        case DTYP_INTERVAL_DS:
        case DTYP_INTERVAL_YM:
            return (pmod != PM_PL_ARG) ? sql_parse_interval_attr_bison(type, typmode, typword, dword_id) :
                                         sql_parse_rough_interval_attr_bison(type, typmode, typword, dword_id);

        case DTYP_DOUBLE:
        case DTYP_FLOAT:
            typmode->datatype = OG_TYPE_REAL;
            return sql_parse_real_mode_bison(type, pmod, typmode);

        case DTYP_BINARY_DOUBLE:
        case DTYP_BINARY_FLOAT:
            typmode->datatype = OG_TYPE_REAL;
            typmode->size = sizeof(double);
            typmode->precision = OG_UNSPECIFIED_REAL_PREC;
            typmode->scale = OG_UNSPECIFIED_REAL_SCALE;
            return OG_SUCCESS;

        case DTYP_SERIAL:
        case DTYP_BIGINT:
        case DTYP_BINARY_BIGINT:
            typmode->datatype = OG_TYPE_BIGINT;
            typmode->size = sizeof(int64);
            return OG_SUCCESS;

        case DTYP_JSONB:
        case DTYP_BLOB: {
            typmode->datatype = OG_TYPE_BLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_CLOB: {
            typmode->datatype = OG_TYPE_CLOB;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);
        }

        case DTYP_IMAGE:
            typmode->datatype = OG_TYPE_IMAGE;
            return sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE);

        case DTYP_NVARCHAR:
            typmode->datatype = OG_TYPE_VARCHAR;
            OG_RETURN_IFERR(sql_parse_varchar_mode_bison(type, pmod, typmode, dword_id));
            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_NCHAR:
            typmode->datatype = OG_TYPE_CHAR;
            if (pmod != PM_PL_ARG) {
                OG_RETURN_IFERR(sql_parse_size_bison(type, (uint16)OG_MAX_COLUMN_SIZE, OG_FALSE, typmode, dword_id));
            } else {
                OG_RETURN_IFERR(sql_set_default_typmod(typmode, OG_MAX_COLUMN_SIZE));
            }

            typmode->is_char = OG_TRUE;
            return OG_SUCCESS;

        case DTYP_UBIGINT:
        case DTYP_BINARY_UBIGINT:
            OG_SRC_THROW_ERROR(typword->loc, ERR_CAPABILITY_NOT_SUPPORT, "datatype");
            return OG_ERROR;

        default:
            OG_SRC_THROW_ERROR_EX(typword->loc, ERR_SQL_SYNTAX_ERROR, "unrecognized datatype word: %s",
                T2S(&typword->text.value));
            return OG_ERROR;
    }
}

static status_t sql_parse_typmode_bison(char *user, type_word_t *type, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    status_t status;
    typmode_t tmode = { 0 };

    if (USE_NATIVE_DATATYPE) {
        status = sql_parse_native_typmod_bison(user, type, pmod, &tmode, typword);
        OG_RETURN_IFERR(status);
    } else {
        status = sql_parse_orcl_typmod_bison(type, pmod, &tmode, typword);
        OG_RETURN_IFERR(status);
    }
    if (OG_IS_STRING_TYPE(tmode.datatype)) {
        tmode.charset = type->charset;
        tmode.collate = type->collation;
    }

    if (typmod != NULL) {
        *typmod = tmode;
    }

    return OG_SUCCESS;
}


status_t sql_parse_typmode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    status_t status;
    typmode_t tmode = { 0 };
    uint8 charset = 0;
    uint8 collate = 0;

    if (USE_NATIVE_DATATYPE) {
        status = sql_parse_native_typmod(lex, pmod, &tmode, typword);
        OG_RETURN_IFERR(status);
    } else {
        status = sql_parse_orcl_typmod(lex, pmod, &tmode, typword);
        OG_RETURN_IFERR(status);
    }

    if (OG_IS_STRING_TYPE(tmode.datatype)) {
        status = sql_parse_datatype_charset(lex, &charset);
        OG_RETURN_IFERR(status);
        tmode.charset = charset;

        status = sql_parse_datatype_collate(lex, &collate);
        OG_RETURN_IFERR(status);
        tmode.collate = collate;
    }

    if (typmod != NULL) {
        *typmod = tmode;
    }

    return OG_SUCCESS;
}

status_t sql_parse_datatype_typemode(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword, word_t *tword)
{
    OG_RETURN_IFERR(sql_parse_typmode(lex, pmod, typmod, tword));

    if (typword != NULL) {
        *typword = *tword;
    }

    if (lex_try_match_array(lex, &typmod->is_array, typmod->datatype) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/**
 * An important interface to parse a datatype starting from the current LEX,
 * Argument description:
 * + pmod    : see definition of @pmode_t
 * + typmode : The typemode of the parsing datatype. If it is NULL, the output typmode is ignored.
 * + typword : The word of a datatype. It includes type location in SQL, type ID. If it is NULL, it is ignored.

 */
status_t sql_parse_datatype(lex_t *lex, pmode_t pmod, typmode_t *typmod, word_t *typword)
{
    bool32 is_found = OG_FALSE;
    word_t tword;
    if (lex_try_fetch_datatype(lex, &tword, &is_found) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!is_found) {
        OG_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "datatype expected, but got '%s'", W2S(&tword));
        return OG_ERROR;
    }

    if (sql_parse_datatype_typemode(lex, pmod, typmod, typword, &tword) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

/*
    INTERVAL 'integer [-integer]' {YEAR|MONTH}[(prec)] [TO {YEAR|MONTH}]
    OR
    INTERVAL '{integer|integer time_expr|time_expr}'
        {DAY|HOUR|MINUTE|SECOND}[(prec)] [TO {DAY|HOUR|MINUTE|SECOND[(sec_prec)]}]
*/
static status_t sql_try_parse_interval_expr(sql_stmt_t *stmt, expr_node_t *node, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    text_t itvl_text;
    typmode_t type = { 0 };
    uint32 itvl_fmt = 0;
    interval_detail_t interval_detail;
    word_t word;

    OG_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_STRING) {
        (*result) = OG_FALSE;
        lex_back(lex, &word);
        return OG_SUCCESS;
    }
    (*result) = OG_TRUE;
    itvl_text = word.text.value;
    itvl_text.str += 1;
    itvl_text.len -= 2;

    OG_RETURN_IFERR(sql_parse_interval_literal(lex, &type, &itvl_fmt));

    node->type = EXPR_NODE_CONST;
    node->datatype = type.datatype;
    node->value.type = (int16)type.datatype;
    node->value.is_null = OG_FALSE;
    node->typmod = type;

    OG_RETURN_IFERR(cm_text2intvl_detail(&itvl_text, type.datatype, &interval_detail, itvl_fmt));

    if (type.datatype == OG_TYPE_INTERVAL_YM) {
        OG_RETURN_IFERR(cm_encode_yminterval(&interval_detail, &node->value.v_itvl_ym));
        OG_RETURN_IFERR(cm_adjust_yminterval(&node->value.v_itvl_ym, type.year_prec));
    } else {
        OG_RETURN_IFERR(cm_encode_dsinterval(&interval_detail, &node->value.v_itvl_ds));
        OG_RETURN_IFERR(cm_adjust_dsinterval(&node->value.v_itvl_ds, type.day_prec, type.frac_prec));
    }

    return OG_SUCCESS;
}

/*
  DATE '1995-01-01' OR TIMESTAMP '1995-01-01 11:22:33.456'
*/
static status_t sql_try_parse_date_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node, bool32 *result)
{
    lex_t *lex = stmt->session->lex;
    uint32 type_id = word->id;
    word_t next_word;

    if (!cm_text_str_equal_ins(&word->text.value, "DATE") && !cm_text_str_equal_ins(&word->text.value, "TIMESTAMP")) {
        (*result) = OG_FALSE;
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_fetch(lex, &next_word));
    if (next_word.type != WORD_TYPE_STRING) {
        (*result) = OG_FALSE;
        lex_back(lex, &next_word);
        return OG_SUCCESS;
    }
    (*result) = OG_TRUE;
    CM_REMOVE_ENCLOSED_CHAR(&next_word.text.value);

    if (type_id == DTYP_DATE) {
        node->datatype = OG_TYPE_DATE;
        node->typmod.precision = 0;
        OG_RETURN_IFERR(cm_text2date_def(&next_word.text.value, &node->value.v_date));
    } else if (type_id == DTYP_TIMESTAMP) {
        node->datatype = OG_TYPE_TIMESTAMP;
        node->typmod.precision = OG_DEFAULT_DATETIME_PRECISION;
        OG_RETURN_IFERR(cm_text2timestamp_def(&next_word.text.value, &node->value.v_date));
    } else {
        OG_SRC_THROW_ERROR_EX(next_word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid datatype word id: %u", type_id);
        return OG_ERROR;
    }

    node->type = EXPR_NODE_CONST;
    node->value.type = node->datatype;
    node->value.is_null = OG_FALSE;
    node->typmod.size = sizeof(date_t);

    return OG_SUCCESS;
}

status_t sql_copy_text_remove_quotes(sql_context_t *context, text_t *src, text_t *dst)
{
    if (sql_alloc_mem(context, src->len, (void **)&dst->str) != OG_SUCCESS) {
        return OG_ERROR;
    }
    dst->len = 0;
    for (uint32 i = 0; i < src->len; i++) {
        CM_TEXT_APPEND(dst, CM_GET_CHAR(src, i));
        // if existing two continuous '
        if (CM_GET_CHAR(src, i) == '\'') {
            ++i;
            if (i >= src->len) {
                break;
            }
            if (CM_GET_CHAR(src, i) != '\'') {
                CM_TEXT_APPEND(dst, CM_GET_CHAR(src, i));
            }
        }
    }
    return OG_SUCCESS;
}

status_t sql_word2text(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    text_t const_text;
    text_t *val_text = NULL;

    const_text = word->text.value;
    CM_REMOVE_ENCLOSED_CHAR(&const_text);

    /*
     * The max size of text in sql is OG_MAX_COLUMN_SIZE.
     * The max size of text in plsql is OG_SHARED_PAGE_SIZE.
     */
    if (SQL_TYPE(stmt) <= OGSQL_TYPE_DDL_CEIL && const_text.len > OG_MAX_COLUMN_SIZE) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR, "constant string in SQL is too long, can not exceed %u",
            OG_MAX_COLUMN_SIZE);
        return OG_ERROR;
    }
    if (SQL_TYPE(stmt) >= OGSQL_TYPE_CREATE_PROC && SQL_TYPE(stmt) < OGSQL_TYPE_PL_CEIL_END &&
        const_text.len > sql_pool->memory->page_size) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR,
            "constant string in PL/SQL is too long, can not exceed %u", sql_pool->memory->page_size);
        return OG_ERROR;
    }

    val_text = VALUE_PTR(text_t, &node->value);
    node->value.type = OG_TYPE_CHAR;

    if (const_text.len == 0) {
        if (g_instance->sql.enable_empty_string_null) {
            // empty text is used as NULL like oracle
            val_text->str = NULL;
            val_text->len = 0;
            node->value.is_null = OG_TRUE;
            return OG_SUCCESS;
        }
    }

    return sql_copy_text_remove_quotes(stmt->context, &const_text, val_text);
}

static status_t word_to_variant_number(word_t *word, variant_t *var)
{
    num_errno_t err_num = NERR_ERROR;
    var->is_null = OG_FALSE;
    var->type = (og_type_t)word->id;

    switch (var->type) {
        case OG_TYPE_UINT32:
            err_num = cm_numpart2uint32(&word->np, &var->v_uint32);
            break;
        case OG_TYPE_INTEGER:
            err_num = cm_numpart2int(&word->np, &var->v_int);
            break;

        case OG_TYPE_BIGINT:
            err_num = cm_numpart2bigint(&word->np, &var->v_bigint);
            if (var->v_bigint == (int64)(OG_MIN_INT32)) {
                var->type = OG_TYPE_INTEGER;
                var->v_int = OG_MIN_INT32;
            }
            break;
        case OG_TYPE_UINT64:
            err_num = cm_numpart2uint64(&word->np, &var->v_ubigint);
            break;
        case OG_TYPE_REAL:
            err_num = cm_numpart2real(&word->np, &var->v_real);
            break;

        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_DECIMAL: {
            err_num = cm_numpart_to_dec8(&word->np, &var->v_dec);
            if (NUMPART_IS_ZERO(&word->np) && word->np.has_dot) {
                var->type = OG_TYPE_INTEGER;
                var->v_int = 0;
            }
            break;
        }

        default:
            CM_NEVER;
            break;
    }

    if (err_num != NERR_SUCCESS) {
        if (err_num == NERR_OVERFLOW) {
            OG_THROW_ERROR(ERR_NUM_OVERFLOW);
        } else {
            OG_SRC_THROW_ERROR(word->loc, ERR_INVALID_NUMBER, cm_get_num_errinfo(err_num));
        }
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_word2number(word_t *word, expr_node_t *node)
{
    if (UNARY_INCLUDE_NEGATIVE(node)) {
        word->np.is_neg = !word->np.is_neg;
    }

    OG_RETURN_IFERR(word_to_variant_number(word, &node->value));

    if (UNARY_INCLUDE_ROOT(node)) {
        node->unary = UNARY_OPER_ROOT;
    } else {
        node->unary = UNARY_OPER_NONE;
    }

    return OG_SUCCESS;
}

#define CHECK_PARAM_NAME_NEEDED(stmt) \
    ((stmt)->context->type == OGSQL_TYPE_ANONYMOUS_BLOCK || (stmt)->plsql_mode == PLSQL_DYNSQL)

status_t sql_add_param_mark(sql_stmt_t *stmt, word_t *word, bool32 *is_repeated, uint32 *pnid)
{
    sql_param_mark_t *param_mark = NULL;
    text_t name;
    uint32 i;
    uint32 num;
    text_t num_text;

    *is_repeated = OG_FALSE;

    if (word->text.len >= 2 && word->text.str[0] == '$') { // $parameter minimum length2
        /* using '$' as param identifier can only be followed with number */
        num_text.str = word->text.str + 1;
        num_text.len = word->text.len - 1;
        OG_RETURN_IFERR(cm_text2uint32(&num_text, &num)); /* here just checking whether it can be tranform */
    }
    if (word->text.len >= 2 && CHECK_PARAM_NAME_NEEDED(stmt)) { // $parameter minimum length2
        *pnid = stmt->context->pname_count;                     // paramter name id
        for (i = 0; i < stmt->context->params->count; i++) {
            param_mark = (sql_param_mark_t *)cm_galist_get(stmt->context->params, i);
            name.len = param_mark->len;
            name.str = stmt->session->lex->text.str + param_mark->offset - stmt->text_shift;

            if (cm_text_equal_ins(&name, &word->text.value)) {
                // parameter name is found
                *is_repeated = OG_TRUE;
                *pnid = param_mark->pnid;
                break;
            }
        }

        // not found
        if (!(*is_repeated)) {
            stmt->context->pname_count++;
        }
    } else {
        *is_repeated = OG_FALSE;
        *pnid = stmt->context->pname_count;
        stmt->context->pname_count++;
    }

    if (cm_galist_new(stmt->context->params, sizeof(sql_param_mark_t), (void **)&param_mark) != OG_SUCCESS) {
        return OG_ERROR;
    }

    param_mark->offset = LEX_OFFSET(stmt->session->lex, word) + stmt->text_shift;
    param_mark->len = word->text.len;
    param_mark->pnid = *pnid;
    return OG_SUCCESS;
}

static status_t sql_word2csrparam(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    if (!(stmt->context->type < OGSQL_TYPE_DML_CEIL)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "cursor sharing param only allowed in dml");
        return OG_ERROR;
    }

    node->value.is_null = OG_FALSE;
    node->value.type = OG_TYPE_INTEGER;
    VALUE(uint32, &node->value) = stmt->context->csr_params->count;
    OG_RETURN_IFERR(cm_galist_insert(stmt->context->csr_params, node));
    return OG_SUCCESS;
}

static status_t sql_word2param(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    uint32 param_id;
    bool32 is_repeated = OG_FALSE;
    if (IS_DDL(stmt) || IS_DCL(stmt)) {
        OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "param only allowed in dml or anonymous block or call");
        return OG_ERROR;
    }
    if (stmt->context->params == NULL) {
        OG_SRC_THROW_ERROR(word->loc, ERR_SQL_SYNTAX_ERROR, "Current position cannot use params");
        return OG_ERROR;
    }

    node->value.is_null = OG_FALSE;
    node->value.type = OG_TYPE_INTEGER;
    VALUE(uint32, &node->value) = stmt->context->params->count;

    OG_RETURN_IFERR(sql_add_param_mark(stmt, word, &is_repeated, &param_id));

    if (stmt->context->type == OGSQL_TYPE_ANONYMOUS_BLOCK) {
        return plc_convert_param_node(stmt, node, is_repeated, param_id);
    }

    return OG_SUCCESS;
}

static status_t sql_word2plattr_type(word_t *word, uint16 *attr_type)
{
    switch (word->id) {
        case PL_ATTR_WORD_ISOPEN:
            *attr_type = PLV_ATTR_ISOPEN;
            break;
        case PL_ATTR_WORD_FOUND:
            *attr_type = PLV_ATTR_FOUND;
            break;
        case PL_ATTR_WORD_NOTFOUND:
            *attr_type = PLV_ATTR_NOTFOUND;
            break;
        case PL_ATTR_WORD_ROWCOUNT:
            *attr_type = PLV_ATTR_ROWCOUNT;
            break;
        default:
            OG_THROW_ERROR(ERR_PL_INVALID_ATTR_FMT);
            return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_word2plattr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    plv_decl_t *plv_decl = NULL;
    if (!cm_text_str_equal_ins(&word->text.value, "SQL")) {
        pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
        if (compiler != NULL) {
            plc_find_decl_ex(compiler, word, PLV_CUR, NULL, &plv_decl);
            if (plv_decl == NULL) {
                OG_SRC_THROW_ERROR(node->loc, ERR_UNDEFINED_SYMBOL_FMT, W2S(word));
                return OG_ERROR;
            }
        }
    }
    node->value.type = OG_TYPE_INTEGER;
    if (plv_decl != NULL) {
        node->value.v_plattr.id = plv_decl->vid;
        node->value.v_plattr.is_implicit = (bool8)OG_FALSE;
    } else {
        node->value.v_plattr.is_implicit = (bool8)OG_TRUE;
    }
    return sql_word2plattr_type(word, &node->value.v_plattr.type);
}

static status_t sql_word2column(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;

    node->value.type = OG_TYPE_COLUMN;
    if (sql_word_as_column(stmt, word, &node->word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return lex_try_fetch_subscript(lex, &node->word.column.ss_start, &node->word.column.ss_end);
}

static status_t sql_word2reserved(expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    node->value.type = OG_TYPE_INTEGER;
    node->value.v_res.res_id = word->id;
    node->value.v_res.namable = word->namable;
    return OG_SUCCESS;
}

static inline bool32 is_for_each_row_trigger(sql_stmt_t *stmt)
{
    pl_compiler_t *compiler = (pl_compiler_t *)stmt->pl_compiler;
    trig_desc_t *trig = NULL;

    if (compiler == NULL || compiler->type != PL_TRIGGER) {
        return OG_FALSE;
    }

    trig = &((pl_entity_t *)compiler->entity)->trigger->desc;

    if ((trig->type != TRIG_AFTER_EACH_ROW && trig->type != TRIG_BEFORE_EACH_ROW && trig->type != TRIG_INSTEAD_OF)) {
        return OG_FALSE;
    }

    return OG_TRUE;
}

static status_t hex2assic(const text_t *text, bool32 hex_prefix, binary_t *bin)
{
    uint32 i;
    uint32 pos;
    uint8 half_byte;

    CM_POINTER2(text, bin);

    if (hex_prefix) {
        if (text->len < 3) { // min hex string is 0x0
            OG_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return OG_ERROR;
        }
    }

    // set the starting position
    i = hex_prefix ? sizeof("0x") - 1 : 0;
    uint32 len = text->len;
    bool32 is_quotes = (text->str[0] == 'X') && (text->str[1] == '\'');
    if (is_quotes) {
        len = text->len - 1;
        if (len % 2 == 1) {
            OG_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return OG_ERROR;
        }
    }
    uint32 val;
    pos = 0;
    if (len % 2 == 1) { // handle odd length hex string
        val = 0;
        val <<= 4;

        val += cm_hex2int8(text->str[i]);
        bin->bytes[pos] = (uint8)val;
        pos++;
        i++;
    }

    for (; i < len; i += 2) {
        half_byte = cm_hex2int8((uint8)text->str[i]);
        if (half_byte == 0xFF) {
            OG_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return OG_ERROR;
        }

        bin->bytes[pos] = (uint8)(half_byte << 4);

        half_byte = cm_hex2int8((uint8)text->str[i + 1]);
        if (half_byte == 0xFF) {
            OG_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return OG_ERROR;
        }

        bin->bytes[pos] += half_byte;
        pos++;
    }

    bin->size = pos;

    return OG_SUCCESS;
}

static status_t sql_word2hexadecimal(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    bool32 has_prefix = OG_FALSE;
    binary_t bin;
    char *str = NULL;
    text_t const_text = word->text.value;

    if (word->text.len > OG_MAX_COLUMN_SIZE * 2) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_VALUE_ERROR, "hexadecimal string is too long, can not exceed %u",
            2 * OG_MAX_COLUMN_SIZE);
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, (const_text.len + 1) / 2, (void **)&str) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 len = word->text.len;
    has_prefix = (word->text.len >= 2) &&
        ((word->text.str[0] == 'X' && word->text.str[1] == '\'' && word->text.str[len - 1] == '\'') ||
        (word->text.str[0] == '0' && word->text.str[1] == 'x'));
    bin.bytes = (uint8 *)str;
    bin.size = 0;
    if (hex2assic(&word->text.value, has_prefix, &bin) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->value.is_null = OG_FALSE;
    node->value.v_bin = bin;
    node->value.v_bin.is_hex_const = OG_TRUE;
    node->value.type = OG_TYPE_BINARY;
    return OG_SUCCESS;
}

static status_t sql_convert_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_t *node)
{
    switch (word->type) {
        case WORD_TYPE_STRING:
            return sql_word2text(stmt, word, node);
        case WORD_TYPE_NUMBER:
            return sql_word2number(word, node);
        case WORD_TYPE_PARAM:
            return sql_word2param(stmt, word, node);
        case WORD_TYPE_ALPHA_PARAM:
            return sql_word2csrparam(stmt, word, node);
        case WORD_TYPE_RESERVED:
            OG_RETURN_IFERR(sql_word2reserved(expr, word, node));
            return word->namable ? sql_word2column(stmt, expr, word, node) : OG_SUCCESS;
        case WORD_TYPE_VARIANT:
        case WORD_TYPE_DQ_STRING:
        case WORD_TYPE_JOIN_COL:
            if (stmt->context->type >= OGSQL_TYPE_CREATE_PROC && stmt->context->type < OGSQL_TYPE_PL_CEIL_END) {
                return plc_word2var(stmt, word, node);
            }
            return sql_word2column(stmt, expr, word, node);
        case WORD_TYPE_KEYWORD:
        case WORD_TYPE_DATATYPE:
            /* when used as variant */
            if (stmt->context->type >= OGSQL_TYPE_CREATE_PROC && stmt->context->type < OGSQL_TYPE_PL_CEIL_END &&
                word->namable == OG_TRUE) {
                return plc_word2var(stmt, word, node);
            }
            return sql_word2column(stmt, expr, word, node);
        case WORD_TYPE_PL_ATTR:
            return sql_word2plattr(stmt, expr, word, node);
        case WORD_TYPE_PL_NEW_COL:
        case WORD_TYPE_PL_OLD_COL: {
            if (!is_for_each_row_trigger(stmt)) {
                OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR,
                    "':new.' or ':old.' can only appear in row trigger. word = %s", W2S(word));
                return OG_ERROR;
            }
            return plc_word2var(stmt, word, node);
        }
        case WORD_TYPE_HEXADECIMAL:
            return sql_word2hexadecimal(stmt, word, node);
        default:
            OG_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found", W2S(word));
            return OG_ERROR;
    }
}

static inline status_t sql_parse_one_case_pair(sql_stmt_t *stmt, word_t *word, galist_t *case_pairs, bool32 is_cond)
{
    status_t status;
    case_pair_t *pair = NULL;

    if (cm_galist_new(case_pairs, sizeof(case_pair_t), (void **)&pair) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (is_cond) {
        status = sql_create_cond_until(stmt, &pair->when_cond, word);
    } else {
        status = sql_create_expr_until(stmt, &pair->when_expr, word);
    }

    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word->id != KEY_WORD_THEN) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (sql_create_expr_until(stmt, &pair->value, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static inline status_t sql_parse_case_pairs(sql_stmt_t *stmt, word_t *word, galist_t *case_pairs, bool32 is_cond)
{
    for (;;) {
        if (sql_parse_one_case_pair(stmt, word, case_pairs, is_cond) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (!(word->id == KEY_WORD_WHEN || word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END)) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN/ELSE/END expected but %s found",
                W2S(word));
            return OG_ERROR;
        }

        if (word->id == KEY_WORD_ELSE || word->id == KEY_WORD_END) {
            break;
        }
    }
    return OG_SUCCESS;
}

static inline status_t sql_parse_case_default_expr(sql_stmt_t *stmt, word_t *word, expr_tree_t **default_expr)
{
    if (word->id == KEY_WORD_ELSE) {
        if (sql_create_expr_until(stmt, default_expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (word->id != KEY_WORD_END) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "THEN expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

status_t sql_parse_case_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;
    key_word_t *save_key_words = lex->key_words;
    uint32 save_key_word_count = lex->key_word_count;
    bool32 is_cond = OG_FALSE;
    case_expr_t *case_expr = NULL;
    key_word_t key_words[] = { { (uint32)KEY_WORD_END, OG_FALSE, { (char *)"end", 3 } },
                               { (uint32)KEY_WORD_WHEN, OG_FALSE, { (char *)"when", 4 } }
                             };

    node->type = EXPR_NODE_CASE;
    if (sql_alloc_mem(stmt->context, sizeof(case_expr_t), (void **)&case_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_try_fetch(stmt->session->lex, "WHEN", &is_cond) != OG_SUCCESS) {
        return OG_SUCCESS;
    }

    cm_galist_init(&case_expr->pairs, (void *)stmt->context, (ga_alloc_func_t)sql_alloc_mem);
    case_expr->is_cond = is_cond;

    lex->key_words = key_words;
    lex->key_word_count = ELEMENT_COUNT(key_words);

    if (!is_cond) {
        if (sql_create_expr_until(stmt, &case_expr->expr, word) != OG_SUCCESS) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            return OG_ERROR;
        }

        if (word->id != KEY_WORD_WHEN) {
            lex->key_words = save_key_words;
            lex->key_word_count = save_key_word_count;
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "WHEN expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    if (sql_parse_case_pairs(stmt, word, &case_expr->pairs, is_cond) != OG_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return OG_ERROR;
    }

    if (sql_parse_case_default_expr(stmt, word, &case_expr->default_expr) != OG_SUCCESS) {
        lex->key_words = save_key_words;
        lex->key_word_count = save_key_word_count;
        return OG_ERROR;
    }

    VALUE(pointer_t, &node->value) = case_expr;
    lex->key_words = save_key_words;
    lex->key_word_count = save_key_word_count;

    return OG_SUCCESS;
}

static status_t sql_parse_array_element_expr(sql_stmt_t *stmt, lex_t *lex, expr_node_t *node)
{
    uint32 subscript = 1;
    word_t next_word;
    expr_tree_t **expr = NULL;
    bool32 expect_expr = OG_FALSE;
    var_array_t *val = &node->value.v_array;

    expr = &node->argument;
    val->count = 0;

    while (lex->curr_text->len > 0) {
        if (sql_create_expr_until(stmt, expr, &next_word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        val->count++;
        (*expr)->subscript = subscript;
        subscript++;

        if (next_word.type == WORD_TYPE_SPEC_CHAR && IS_SPEC_CHAR(&next_word, ',')) {
            expr = &(*expr)->next;
            expect_expr = OG_TRUE;
            lex_trim(lex->curr_text);
        } else if (next_word.type == WORD_TYPE_EOF) {
            /* end of the array elements */
            expect_expr = OG_FALSE;
            break;
        } else {
            OG_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_ARRAY_FORMAT);
            return OG_ERROR;
        }
    }

    if (expect_expr) {
        OG_SRC_THROW_ERROR(LEX_LOC, ERR_INVALID_ARRAY_FORMAT);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_array_expr(sql_stmt_t *stmt, word_t *word, expr_node_t *node)
{
    lex_t *lex = stmt->session->lex;

    if (lex_fetch_array(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_push(lex, &word->text)) {
        return OG_ERROR;
    }

    if (sql_parse_array_element_expr(stmt, lex, node) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_create_expr_node(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_type_t node_type,
    expr_node_t **node)
{
    OG_RETURN_IFERR(sql_stack_safe(stmt));

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*node)->owner = expr;
    (*node)->type = (word->type == WORD_TYPE_JOIN_COL) ? EXPR_NODE_JOIN : node_type;
    (*node)->unary = expr->unary;
    (*node)->loc = word->text.loc;
    (*node)->dis_info.need_distinct = OG_FALSE;
    (*node)->dis_info.idx = OG_INVALID_ID32;
    (*node)->optmz_info = (expr_optmz_info_t) { OPTIMIZE_NONE, 0 };
    (*node)->format_json = OG_FALSE;
    (*node)->json_func_attr = (json_func_attr_t) { 0, 0 };
    (*node)->typmod.is_array = 0;
    (*node)->value.v_col.ss_start = OG_INVALID_ID32;
    (*node)->value.v_col.ss_end = OG_INVALID_ID32;

    if (word->type == WORD_TYPE_DATATYPE && (word->id == DTYP_DATE || word->id == DTYP_TIMESTAMP)) {
        bool32 result = OG_FALSE;
        OG_RETURN_IFERR(sql_try_parse_date_expr(stmt, word, *node, &result));
        OG_RETSUC_IFTRUE(result);
    }

    if (node_type <= EXPR_NODE_OPCEIL) {
        return OG_SUCCESS;
    }

    if (node_type == EXPR_NODE_NEGATIVE) {
        word->flag_type = (uint32)word->flag_type ^ (uint32)WORD_FLAG_NEGATIVE;
        return OG_SUCCESS;
    }

    if (node_type == EXPR_NODE_FUNC) {
        OG_RETURN_IFERR(sql_build_func_node(stmt, word, *node));
        // to support analytic function
        OG_RETURN_IFERR(sql_build_func_over(stmt, expr, word, node));

        return OG_SUCCESS;
    }

    if (node_type == EXPR_NODE_CASE) {
        return sql_parse_case_expr(stmt, word, *node);
    }

    if (node_type == EXPR_NODE_ARRAY) {
        return sql_parse_array_expr(stmt, word, *node);
    }

    if (word->type == WORD_TYPE_DATATYPE && word->id == DTYP_INTERVAL) {
        bool32 result = OG_FALSE;
        OG_RETURN_IFERR(sql_try_parse_interval_expr(stmt, *node, &result));
        OG_RETSUC_IFTRUE(result);
    }

    return sql_convert_expr_word(stmt, expr, word, *node);
}

static status_t sql_add_expr_word_inside(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word, expr_node_type_t node_type)
{
    expr_node_t *node = NULL;
    expr_tree_t *sub_expr = NULL;

    if (word->type == (uint32)WORD_TYPE_BRACKET) {
        if (sql_create_expr_from_text(stmt, &word->text, &sub_expr, word->flag_type) != OG_SUCCESS) {
            return OG_ERROR;
        }

        node = sub_expr->root;

        if (expr->chain.count > 0 &&
            (expr->chain.last->type == EXPR_NODE_NEGATIVE || expr->chain.last->type == EXPR_NODE_PRIOR) &&
            word->type != WORD_TYPE_OPERATOR) {
            expr->chain.last->right = node;
        } else {
            APPEND_CHAIN(&expr->chain, node);
            UNARY_REDUCE_NEST(expr, node);
        }
    } else {
        if (sql_create_expr_node(stmt, expr, word, node_type, &node) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (expr->chain.count > 0 &&
            (expr->chain.last->type == EXPR_NODE_NEGATIVE || expr->chain.last->type == EXPR_NODE_PRIOR) &&
            word->type != WORD_TYPE_OPERATOR) {
            expr->chain.last->right = node;
        } else {
            APPEND_CHAIN(&expr->chain, node);
        }
    }
    return OG_SUCCESS;
}

static status_t inline oper2unary(sql_stmt_t *stmt, word_t *word, unary_oper_t *unary_oper)
{
    switch (word->id) {
        case OPER_TYPE_SUB:
            *unary_oper = UNARY_OPER_NEGATIVE;
            break;
        case OPER_TYPE_ADD:
            *unary_oper = UNARY_OPER_POSITIVE;
            break;
        case OPER_TYPE_ROOT: {
            if (!stmt->in_parse_query) {
                OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "CONNECT BY clause required in this query block");
                return OG_ERROR;
            }
            *unary_oper = UNARY_OPER_ROOT;
            break;
        }
        default:
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "Unknown unary operator id \"%u\"", word->id);
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_add_expr_word(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    expr_node_type_t node_type;

    if (word->type == WORD_TYPE_ANCHOR) {
        return sql_convert_to_cast(stmt, expr, word);
    }

    if ((expr->expecting & EXPR_EXPECT_UNARY_OP) && EXPR_IS_UNARY_OP_ROOT(word)) {
        expr->expecting = EXPR_EXPECT_VAR;
        OG_RETURN_IFERR(oper2unary(stmt, word, &expr->unary));
        return OG_SUCCESS;
    }

    if ((expr->expecting & EXPR_EXPECT_UNARY_OP) && EXPR_IS_UNARY_OP(word)) {
        if (word->id == (uint32)OPER_TYPE_ADD) {
            expr->expecting = EXPR_EXPECT_VAR;
            return OG_SUCCESS;
        }
        expr->expecting = EXPR_EXPECT_UNARY;
    }

    if (!sql_match_expected(expr, word, &node_type)) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "the word \"%s\" is not correct", W2S(word));
        return OG_ERROR;
    }

    if (sql_add_expr_word_inside(stmt, expr, word, node_type) != OG_SUCCESS) {
        return OG_ERROR;
    }

    expr->unary = UNARY_OPER_NONE;
    return OG_SUCCESS;
}

status_t sql_create_expr(sql_stmt_t *stmt, expr_tree_t **expr)
{
    if (sql_alloc_mem(stmt->context, sizeof(expr_tree_t), (void **)expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*expr)->owner = stmt->context;
    (*expr)->expecting = (EXPR_EXPECT_UNARY_OP | EXPR_EXPECT_VAR | EXPR_EXPECT_STAR);
    (*expr)->next = NULL;

    return OG_SUCCESS;
}

static status_t sql_build_star_expr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (expr->chain.count > 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "expression expected but %s found", W2S(word));
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_word_as_column(stmt, word, &expr->root->word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    expr->root->type = EXPR_NODE_STAR;
    expr->root->loc = word->text.loc;
    expr->star_loc.begin = word->ori_type == WORD_TYPE_DQ_STRING ? LEX_OFFSET(lex, word) - 1 : LEX_OFFSET(lex, word);
    return lex_fetch(lex, word);
}

status_t sql_create_expr_until(sql_stmt_t *stmt, expr_tree_t **expr, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    word_type_t word_type;
    uint32 save_flags = stmt->session->lex->flags;

    word->flag_type = WORD_FLAG_NONE;
    word_type = WORD_TYPE_OPERATOR;

    OG_RETURN_IFERR(sql_create_expr(stmt, expr));

    OG_RETURN_IFERR(lex_skip_comments(lex, NULL));

    (*expr)->loc = LEX_LOC;

    for (;;) {
        if ((*expr)->expecting == EXPR_EXPECT_OPER) {
            stmt->session->lex->flags &= (~LEX_WITH_ARG);
        } else {
            stmt->session->lex->flags = save_flags;
        }

        OG_RETURN_IFERR(lex_fetch(stmt->session->lex, word));
        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if ((IS_SPEC_CHAR(word, '*') && word_type == WORD_TYPE_OPERATOR) || word->type == WORD_TYPE_STAR) {
            return sql_build_star_expr(stmt, *expr, word);
        }

        OG_BREAK_IF_TRUE((IS_UNNAMABLE_KEYWORD(word) && word->id != KEY_WORD_CASE) || IS_SPEC_CHAR(word, ',') ||
            (word->type == WORD_TYPE_COMPARE) || (word->type == WORD_TYPE_PL_TERM) ||
            (word->type == WORD_TYPE_PL_RANGE));

        OG_BREAK_IF_TRUE((word->type == WORD_TYPE_VARIANT || word->type == WORD_TYPE_JOIN_COL ||
            word->type == WORD_TYPE_STRING || word->type == WORD_TYPE_KEYWORD || word->type == WORD_TYPE_DATATYPE ||
            word->type == WORD_TYPE_DQ_STRING || word->type == WORD_TYPE_FUNCTION ||
            word->type == WORD_TYPE_RESERVED) &&
            word_type != WORD_TYPE_OPERATOR);

        if (word->id == KEY_WORD_PRIMARY) {
            bool32 ret;
            OG_RETURN_IFERR(lex_try_fetch(lex, "KEY", &ret));

            // KEY WORD NOT VARIANT.
            OG_BREAK_IF_TRUE(ret);
        }
        word_type = word->type;
        OG_RETURN_IFERR(sql_add_expr_word(stmt, *expr, word));
    }
    OG_RETURN_IFERR(sql_generate_expr(*expr));
    stmt->session->lex->flags = save_flags;
    return OG_SUCCESS;
}

static status_t sql_parse_select_expr(sql_stmt_t *stmt, expr_tree_t *expr, sql_text_t *sql)
{
    sql_select_t *select_ctx = NULL;

    if (stmt->ssa_stack.depth == 0) {
        OG_SRC_THROW_ERROR(stmt->session->lex->loc, ERR_UNEXPECTED_KEY, "SUBSELECT");
        return OG_ERROR;
    }

    if (sql_create_select_context(stmt, sql, SELECT_AS_VARIANT, &select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    expr->generated = OG_TRUE;
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&expr->root) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_array_put(OGSQL_CURR_SSA(stmt), select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    select_ctx->parent = OGSQL_CURR_NODE(stmt);
    expr->root->type = EXPR_NODE_SELECT;
    expr->root->value.type = OG_TYPE_INTEGER;
    expr->root->value.v_obj.id = OGSQL_CURR_SSA(stmt)->count - 1;
    expr->root->value.v_obj.ptr = select_ctx;
    OG_RETURN_IFERR(sql_slct_add_ref_node(stmt->context, expr->root, sql_alloc_mem));
    return OG_SUCCESS;
}

static status_t sql_parse_normal_expr(sql_stmt_t *stmt, expr_tree_t *expr, word_t *word)
{
    while (word->type != WORD_TYPE_EOF) {
        if (sql_add_expr_word(stmt, expr, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (lex_fetch(stmt->session->lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (sql_generate_expr(expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_create_expr_list(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr)
{
    word_t word;
    expr_tree_t *last_expr = NULL;
    expr_tree_t *curr_expr = NULL;
    lex_t *lex = stmt->session->lex;
    last_expr = NULL;

    OG_RETURN_IFERR(lex_push(lex, text));

    for (;;) {
        /* Here, curr_expr->next is set by NULL at initializing phase.
         * See function sql_create_expr. */
        if (sql_create_expr_until(stmt, &curr_expr, &word) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (last_expr == NULL) {
            *expr = curr_expr;
        } else {
            last_expr->next = curr_expr;
        }
        last_expr = curr_expr;

        if (word.type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(&word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but '%s' found", W2S(&word));
            return OG_ERROR;
        }
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

status_t sql_create_expr_from_text(sql_stmt_t *stmt, sql_text_t *text, expr_tree_t **expr, word_flag_t word_flag)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;
    const char *words[] = { "UNION", "MINUS", "EXCEPT", "INTERSECT" };
    const uint32 words_cnt = sizeof(words) / sizeof(char *);
    bool32 result = OG_FALSE;

    word.flag_type = word_flag;
    *expr = NULL;

    OG_RETURN_IFERR(sql_stack_safe(stmt));

    OG_RETURN_IFERR(lex_push(lex, text));

    if (sql_create_expr(stmt, expr) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    LEX_SAVE(lex);
    // Judge whether the next word is UNION/MINUS/EXCEPT/INTERSECT.
    if (lex_try_fetch_anyone(lex, words_cnt, words, &result) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    LEX_RESTORE(lex);

    if (result || word.id == KEY_WORD_SELECT || word.id == KEY_WORD_WITH) {
        word.text = *text;
        status = sql_parse_select_expr(stmt, *expr, &word.text);
    } else {
        status = sql_parse_normal_expr(stmt, *expr, &word);
    }
    lex_pop(lex);
    return status;
}

status_t sql_create_expr_from_word(sql_stmt_t *stmt, word_t *word, expr_tree_t **expr)
{
    if (sql_create_expr(stmt, expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return sql_add_expr_word(stmt, *expr, word);
}

static void sql_down_expr_node(expr_tree_t *expr, expr_node_t *root)
{
    root->left = root->prev;
    root->right = root->next;
    root->next = root->next->next;
    root->prev = root->prev->prev;
    if (root->prev != NULL) {
        root->prev->next = root;
    } else {
        expr->chain.first = root;
    }
    if (root->next != NULL) {
        root->next->prev = root;
    } else {
        expr->chain.last = root;
    }
    root->left->prev = NULL;
    root->left->next = NULL;
    root->right->prev = NULL;
    root->right->next = NULL;
    expr->chain.count -= 2;
}

static status_t sql_form_expr_with_opers(expr_tree_t *expr, uint32 opers)
{
    expr_node_t *prev = NULL;
    expr_node_t *next = NULL;
    expr_node_t *head;

    /* get next expr node ,merge node is needed at least two node */
    head = expr->chain.first->next;

    while (head != NULL) {
        if (head->type >= EXPR_NODE_CONST || head->left != NULL ||
            (IS_OPER_NODE(head) && g_opr_priority[head->type] != g_opr_priority[opers])) {
            head = head->next;
            continue;
        }

        prev = head->prev;
        next = head->next;

        /* if is not a correct expression */
        if (prev == NULL || next == NULL) {
            OG_SRC_THROW_ERROR(head->loc, ERR_SQL_SYNTAX_ERROR, "expression error");
            return OG_ERROR;
        }

        sql_down_expr_node(expr, head);

        head = head->next;
    }

    return OG_SUCCESS;
}

status_t sql_generate_expr(expr_tree_t *expr)
{
    if (expr->chain.count == 0) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "invalid expression");
        return OG_ERROR;
    }

    for (uint32 oper_mode = OPER_TYPE_MUL; oper_mode <= OPER_TYPE_CAT; ++oper_mode) {
        if (sql_form_expr_with_opers(expr, oper_mode) != OG_SUCCESS) {
            return OG_ERROR;
        }
    }

    if (expr->chain.count != 1) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "expression error");
        return OG_ERROR;
    }

    expr->generated = OG_TRUE;
    expr->root = expr->chain.first;
    return OG_SUCCESS;
}

status_t sql_build_column_expr(sql_stmt_t *stmt, knl_column_t *column, expr_tree_t **r_result)
{
    expr_node_t *col_node = NULL;
    expr_tree_t *column_expr = NULL;

    if (sql_create_expr(stmt, &column_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&col_node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    col_node->owner = column_expr;
    col_node->type = EXPR_NODE_COLUMN;

    col_node->value.is_null = OG_FALSE;
    col_node->value.type = OG_TYPE_COLUMN;
    col_node->value.v_col.ancestor = 0;
    col_node->value.v_col.datatype = column->datatype;
    col_node->value.v_col.tab = column->table_id;
    col_node->value.v_col.col = column->id;

    APPEND_CHAIN(&(column_expr->chain), col_node);

    *r_result = column_expr;
    return sql_generate_expr(*r_result);
}

status_t sql_build_default_reserved_expr(sql_stmt_t *stmt, expr_tree_t **r_result)
{
    expr_node_t *reserved_node = NULL;
    expr_tree_t *reserved_expr = NULL;

    if (sql_create_expr(stmt, &reserved_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&reserved_node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    reserved_node->owner = reserved_expr;
    reserved_node->type = EXPR_NODE_RESERVED;
    reserved_node->datatype = OG_TYPE_UNKNOWN;

    reserved_node->value.is_null = OG_FALSE;
    reserved_node->value.type = OG_TYPE_INTEGER;

    reserved_node->value.v_rid.res_id = RES_WORD_DEFAULT;
    APPEND_CHAIN(&(reserved_expr->chain), reserved_node);

    *r_result = reserved_expr;
    return sql_generate_expr(*r_result);
}

status_t sql_init_expr_node(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t **node,
    og_type_t type, expr_node_type_t expr_type, source_location_t loc)
{
    if (sql_create_expr(stmt, expr) != OG_SUCCESS) {
        return OG_ERROR;
    }
    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    (*node)->owner = *expr;
    (*node)->type = expr_type;
    (*node)->unary = (*expr)->unary;
    (*node)->loc = loc;
    (*node)->dis_info.need_distinct = OG_FALSE;
    (*node)->dis_info.idx = OG_INVALID_ID32;
    (*node)->optmz_info = (expr_optmz_info_t) { OPTIMIZE_NONE, 0 };
    (*node)->format_json = OG_FALSE;
    (*node)->json_func_attr = (json_func_attr_t) { 0, 0 };
    (*node)->typmod.is_array = 0;
    (*node)->value.v_col.ss_start = OG_INVALID_ID32;
    (*node)->value.v_col.ss_end = OG_INVALID_ID32;
    (*node)->value.is_null = OG_FALSE;
    (*node)->value.type = type;

    return OG_SUCCESS;
}

status_t sql_create_int_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, int val, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_CONST, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }
    node->value.v_int = val;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_expr_tree(sql_stmt_t *stmt, expr_tree_t **expr, og_type_t type, expr_node_type_t expr_type,
    source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, type, expr_type, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_float_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_NUMBER, EXPR_NODE_CONST, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (cm_str_to_dec8(val, &node->value.v_dec) != OG_SUCCESS) {
        return OG_ERROR;
    }
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_hex_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_BINARY, EXPR_NODE_CONST, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // create a temporary word_t to hold the hex string
    word_t word;
    word.text.str = (char *)val;
    word.text.len = strlen(val);
    word.text.loc = loc;
    word.type = WORD_TYPE_HEXADECIMAL;
    word.flag_type = 0;
    word.id = 0;
    word.namable = OG_FALSE;

    // convert hex string to binary using existing function
    if (sql_word2hexadecimal(stmt, &word, node) != OG_SUCCESS) {
        return OG_ERROR;
    }
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_string_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_CHAR, EXPR_NODE_CONST, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    uint32 len = strlen(val);
    if (len > OG_MAX_COLUMN_SIZE) {
        OG_SRC_THROW_ERROR_EX(loc, ERR_VALUE_ERROR, "constant string in SQL is too long, can not exceed %u",
            OG_MAX_COLUMN_SIZE);
        return OG_ERROR;
    }

    if (len == 0) {
        if (g_instance->sql.enable_empty_string_null) {
            // empty text is used as NULL like oracle
            node->value.v_text.str = NULL;
            node->value.v_text.len = 0;
            node->value.is_null = OG_TRUE;
            APPEND_CHAIN(&((*expr)->chain), node);
            sql_generate_expr(*expr);
            return OG_SUCCESS;
        }
    }

    text_t src = {(char*)val, len};
    OG_RETURN_IFERR(sql_copy_text_remove_quotes(stmt->context, (text_t *)&src, &node->value.v_text));
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_bool_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, bool32 val, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_RESERVED, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->value.v_res.res_id = val ? RES_WORD_TRUE : RES_WORD_FALSE;
    node->value.v_res.namable = OG_FALSE;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_null_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_RESERVED, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->value.v_res.res_id = RES_WORD_NULL;
    node->value.v_res.namable = OG_FALSE;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_interval_const_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val,
    interval_info_t info, source_location_t loc)
{
    expr_node_t *node = NULL;
    text_t itvl_text;
    itvl_text.str = (char*)val;
    itvl_text.len = strlen(val);
    interval_detail_t interval_detail;

    if (sql_init_expr_node(stmt, expr, &node, info.type.datatype, EXPR_NODE_CONST, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->datatype = info.type.datatype;
    node->value.type = (int16)info.type.datatype;
    node->value.is_null = OG_FALSE;
    node->typmod = info.type;

    OG_RETURN_IFERR(cm_text2intvl_detail(&itvl_text, info.type.datatype, &interval_detail, info.fmt));

    if (info.type.datatype == OG_TYPE_INTERVAL_YM) {
        OG_RETURN_IFERR(cm_encode_yminterval(&interval_detail, &node->value.v_itvl_ym));
        OG_RETURN_IFERR(cm_adjust_yminterval(&node->value.v_itvl_ym, info.type.year_prec));
    } else {
        OG_RETURN_IFERR(cm_encode_dsinterval(&interval_detail, &node->value.v_itvl_ds));
        OG_RETURN_IFERR(cm_adjust_dsinterval(&node->value.v_itvl_ds, info.type.day_prec, info.type.frac_prec));
    }

    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_columnref_expr(sql_stmt_t *stmt, expr_tree_t **expr, const char* val, galist_t *list,
    expr_node_type_t type, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_COLUMN, type, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    var_word_t *var = &node->word;
    if (list == NULL) {
        var->column.name.value.str = (char*)val;
        var->column.name.value.len = strlen(val);
        var->column.ss_start = OG_INVALID_ID32;
        var->column.ss_end = OG_INVALID_ID32;
    } else {
        uint32 list_count = list->count;
        expr_tree_t *last_node = (expr_tree_t *)cm_galist_get(list, list_count - 1);
        if (last_node->root->type == EXPR_NODE_ARRAY_INDICES) {
            var->column.ss_start = last_node->root->word.column.ss_start;
            var->column.ss_end = last_node->root->word.column.ss_end;
            list_count--;
        } else {
            var->column.ss_start = OG_INVALID_ID32;
            var->column.ss_end = OG_INVALID_ID32;
        }
        if (last_node->root->type == EXPR_NODE_STAR) {
            node->type = EXPR_NODE_STAR;
            (*expr)->star_loc.begin = last_node->star_loc.begin;
            (*expr)->star_loc.end = last_node->star_loc.end;
        }
        switch (list_count) {
            case 1:
                var->column.table.value.str = (char*)val;
                var->column.table.value.len = strlen(val);

                var->column.name.value = ((expr_tree_t*)cm_galist_get(list, 0))->root->value.v_text;
                break;
            case 2:
                var->column.user.value.str = (char*)val;
                var->column.user.value.len = strlen(val);

                var->column.table.value = ((expr_tree_t*)cm_galist_get(list, 0))->root->value.v_text;
                var->column.name.value = ((expr_tree_t*)cm_galist_get(list, 1))->root->value.v_text;
                break;
            default:
                return OG_ERROR;
        }
    }

    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_indices_expr(sql_stmt_t *stmt, expr_tree_t **expr, int32 start, int32 end, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_ARRAY_INDICES, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->word.column.ss_start = start;
    node->word.column.ss_end = end;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_paramref_expr(sql_stmt_t *stmt, expr_tree_t **expr, uint32 token_len, lex_location_t lex_loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_PARAM, lex_loc.loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (IS_DDL(stmt) || IS_DCL(stmt)) {
        OG_SRC_THROW_ERROR(lex_loc.loc, ERR_SQL_SYNTAX_ERROR, "param only allowed in dml or anonymous block or call");
        return OG_ERROR;
    }
    if (stmt->context->params == NULL) {
        OG_SRC_THROW_ERROR(lex_loc.loc, ERR_SQL_SYNTAX_ERROR, "Current position cannot use params");
        return OG_ERROR;
    }

    VALUE(uint32, &node->value) = stmt->context->params->count;
    sql_param_mark_t *param_mark = NULL;
    if (cm_galist_new(stmt->context->params, sizeof(sql_param_mark_t), (void **)&param_mark) != OG_SUCCESS) {
        return OG_ERROR;
    }

    param_mark->offset = lex_loc.offset;
    param_mark->len = token_len;
    param_mark->pnid = stmt->context->pname_count++;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_create_case_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t* case_arg,
    galist_t* case_pair, expr_tree_t* default_expr, source_location_t loc)
{
    expr_node_t *node = NULL;
    case_expr_t *case_expr = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_CASE, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(case_expr_t), (void **)&case_expr) != OG_SUCCESS) {
        return OG_ERROR;
    }

    case_expr->is_cond = case_arg == NULL;
    case_expr->expr = case_arg;
    case_expr->pairs = *case_pair;
    case_expr->default_expr = default_expr;
    VALUE(pointer_t, &node->value) = case_expr;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

status_t sql_expr_tree_to_cond_node(sql_stmt_t *stmt, expr_tree_t *expr, cond_node_t **node)
{
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cond_node_t), (void **)node));
    (*node)->type = COND_NODE_COMPARE;

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(cmp_node_t), (void **)&(*node)->cmp));

    cmp_node_t *cmp_node = (*node)->cmp;

    cmp_node->right = expr;
    cmp_node->type = CMP_TYPE_NOT_EQUAL;

    OG_RETURN_IFERR(sql_create_const_expr_false(stmt, &cmp_node->left, NULL, 0));
    return OG_SUCCESS;
}

status_t sql_create_select_expr(sql_stmt_t *stmt, expr_tree_t **expr, sql_select_t *select_ctx, sql_array_t *array,
    source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_SELECT, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (sql_array_put(array, select_ctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->value.v_obj.id = array->count - 1;
    node->value.v_obj.ptr = select_ctx;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);
    return OG_SUCCESS;
}

static status_t sql_parse_datatype_typemode_bison(char *user, type_word_t *type, typmode_t *v_type)
{
    word_t typword;
    typword.text.str = type->str;
    typword.text.len = strlen(type->str);
    if (lex_try_match_datatype_bison(&typword) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR(type->loc, ERR_SQL_SYNTAX_ERROR, "Invalid datatype");
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_parse_typmode_bison(user, type, PM_NORMAL, v_type, &typword));

    /* array size is useless in this case */
    v_type->is_array = type->is_array;
    if (type->is_array && !cm_datatype_arrayable(v_type->datatype)) {
        OG_THROW_ERROR(ERR_DATATYPE_NOT_SUPPORT_ARRAY, get_datatype_name_str(v_type->datatype));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t sql_build_type_expr(sql_stmt_t *stmt, type_word_t *type, expr_tree_t *type_expr)
{
    typmode_t *v_type = &type_expr->root->value.v_type;
    if (sql_parse_datatype_typemode_bison(stmt->session->db_user, type, v_type) != OG_SUCCESS) {
        return OG_ERROR;
    }

    type_expr->root->value.type = OG_TYPE_TYPMODE;
    type_expr->root->typmod = *v_type;
    type_expr->root->type = EXPR_NODE_CONST;
    type_expr->loc = type->loc;
    /* if cast to array type, e.g. '{1,2,3}'::int[], expression can NOT be optimized,
    because we need temporay (rather than persistent) vm_lob pages to save the
    array elements. Once optimized, the vm_lob page will be freed after the first
    execution of statement, and next time we will get an invalid vm page, and this
    must cause an error.
    */
    if (v_type->is_array != OG_TRUE) {
        SQL_SET_OPTMZ_MODE(type_expr->root, OPTIMIZE_AS_CONST);
    }

    return OG_SUCCESS;
}

status_t sql_create_star_expr(sql_stmt_t *stmt, expr_tree_t **expr, lex_location_t loc)
{
    OG_RETURN_IFERR(sql_create_expr(stmt, expr));
    expr_node_t **node = &(*expr)->root;

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    (*node)->word.column.name.str = "*";
    (*node)->word.column.name.len = 1;

    (*node)->type = EXPR_NODE_STAR;
    (*node)->loc = loc.loc;
    (*expr)->star_loc.begin = loc.offset;
    (*expr)->star_loc.end = loc.offset + 1;

    return OG_SUCCESS;
}

status_t sql_create_prior_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t *column, source_location_t loc)
{
    OG_RETURN_IFERR(sql_create_expr(stmt, expr));
    expr_node_t *node = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(expr_node_t), (void **)&node) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->type = EXPR_NODE_PRIOR;
    node->loc = loc;
    node->right = column;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_negative_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t *operand, source_location_t loc)
{
    OG_RETURN_IFERR(sql_create_expr(stmt, expr));
    expr_node_t *node = NULL;

    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_UNKNOWN, EXPR_NODE_NEGATIVE, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->loc = loc;
    node->right = operand;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_oper_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_node_t *left, expr_node_t *right,
    expr_node_type_t node_type, source_location_t loc)
{
    OG_RETURN_IFERR(sql_create_expr(stmt, expr));
    expr_node_t *node = NULL;

    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_UNKNOWN, node_type, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->loc = loc;
    node->left = left;
    node->right = right;
    left->owner = *expr;
    right->owner = *expr;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_array_expr(sql_stmt_t *stmt, expr_tree_t **expr, expr_tree_t *array_elements, source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_ARRAY, EXPR_NODE_ARRAY, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    // Set up array elements
    node->argument = array_elements;
    var_array_t *val = &node->value.v_array;
    uint32 subscript = 1;
    val->count = 0;
    
    // Count the number of elements
    expr_tree_t *curr_expr = array_elements;
    while (curr_expr != NULL) {
        val->count++;
        curr_expr->subscript = subscript++;
        curr_expr = curr_expr->next;
    }
    
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

status_t sql_create_reserved_expr(sql_stmt_t *stmt, expr_tree_t **expr, uint32 res_id, bool32 namable,
    source_location_t loc)
{
    expr_node_t *node = NULL;
    if (sql_init_expr_node(stmt, expr, &node, OG_TYPE_INTEGER, EXPR_NODE_RESERVED, loc) != OG_SUCCESS) {
        return OG_ERROR;
    }

    node->value.v_res.res_id = res_id;
    node->value.v_res.namable = namable;
    APPEND_CHAIN(&((*expr)->chain), node);
    sql_generate_expr(*expr);

    return OG_SUCCESS;
}

#ifdef __cplusplus
}
#endif
