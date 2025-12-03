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
 * ddl_partition_parser.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_partition_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddl_partition_parser.h"
#include "ddl_table_attr_parser.h"
#include "ddl_parser_common.h"
#include "ogsql_expr.h"
#include "expr_parser.h"
#include "ogsql_package.h"
#include "ogsql_verifier.h"
#include "cm_license.h"
#include "knl_heap.h"
#include "knl_dc.h"

static status_t sql_check_part_range_values(sql_stmt_t *stmt, word_t *word)
{
    word_t word_temp;
    status_t stat;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    stat = lex_fetch(lex, &word_temp);
    if (stat != OG_SUCCESS) {
        lex_pop(lex);
        return stat;
    }

    if (word_temp.type == WORD_TYPE_OPERATOR && word_temp.id == OPER_TYPE_SUB) {
        stat = lex_fetch(lex, &word_temp);
        if (stat != OG_SUCCESS) {
            lex_pop(lex);
            return stat;
        }
    }

    while (word_temp.type != WORD_TYPE_EOF) {
        if (word_temp.type == WORD_TYPE_OPERATOR) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word_temp.text.loc, ERR_SQL_SYNTAX_ERROR,
                "can not specify an expression for a range partition boundval");
            return OG_ERROR;
        }
        stat = lex_fetch(lex, &word_temp);
        if (stat != OG_SUCCESS) {
            lex_pop(lex);
            return stat;
        }
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_range_verify_keys(sql_stmt_t *stmt, knl_part_obj_def_t *obj_def, knl_part_def_t *part_def,
    knl_part_def_t *parent_def)
{
    int32 cmp_result = 0;
    knl_part_def_t *prev_part = NULL;
    galist_t *tmp_parts = &obj_def->parts;
    galist_t *tmp_part_keys = &obj_def->part_keys;

    if (parent_def != NULL) {
        tmp_parts = &parent_def->subparts;
        tmp_part_keys = &obj_def->subpart_keys;
    }

    if (tmp_parts->count >= 2) {
        prev_part = cm_galist_get(tmp_parts, tmp_parts->count - 2);
        cmp_result = knl_compare_defined_key(tmp_part_keys, prev_part->partkey, part_def->partkey);
        if (cmp_result >= 0) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "partition %s boundary invalid", T2S(&part_def->name));
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static void sql_init_verifier(sql_stmt_t *stmt, sql_verifier_t *verf)
{
    verf->context = stmt->context;
    verf->stmt = stmt;
    verf->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;
}

static status_t sql_parse_range_values(sql_stmt_t *stmt, word_t *word, knl_part_def_t *part_def,
    knl_part_obj_def_t *obj_def, knl_part_def_t *parent_def)
{
    bool32 result = OG_FALSE;
    uint32 count = 0;
    variant_t value;
    expr_tree_t *value_expr = NULL;
    lex_t *lex = stmt->session->lex;
    sql_verifier_t verf = { 0 };
    knl_part_column_def_t *key = NULL;
    galist_t *tmp_part_keys = &obj_def->part_keys;

    sql_init_verifier(stmt, &verf);

    OG_RETURN_IFERR(sql_check_part_range_values(stmt, word));

    if (parent_def != NULL) {
        tmp_part_keys = &obj_def->subpart_keys;
    }

    part_key_init(part_def->partkey, tmp_part_keys->count);

    for (;;) {
        if (count >= tmp_part_keys->count) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "value count must equal to partition keys");
            return OG_ERROR;
        }

        OG_RETURN_IFERR(lex_try_fetch(lex, PART_VALUE_MAX, &result));
        if ((obj_def->is_interval) && (result) && parent_def == NULL) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                "Maxvalue partition cannot be specified for interval partitioned");
            return OG_ERROR;
        }

        if (result) {
            OG_RETURN_IFERR(lex_fetch(lex, word));
            part_put_max(part_def->partkey);
        } else {
            key = cm_galist_get(tmp_part_keys, count);

            OG_RETURN_IFERR(sql_create_expr_until(stmt, &value_expr, word));

            OG_RETURN_IFERR(sql_verify_expr(&verf, value_expr));

            OG_RETURN_IFERR(sql_exec_expr(stmt, value_expr, &value));

            OG_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                key->scale, part_def->partkey));
        }

        count++;

        OG_BREAK_IF_TRUE(word->type == WORD_TYPE_EOF);

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    if (count != tmp_part_keys->count) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "value count must equal to partition keys");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_put_list_key(sql_stmt_t *stmt, knl_part_def_t *part_def, knl_part_obj_def_t *obj_def,
    knl_part_def_t *parent_part_def)
{
    variant_t value;
    uint32 group_count;
    uint32 remainder;
    galist_t *value_list = &part_def->value_list;
    galist_t *tmp_part_keys = &obj_def->part_keys;

    part_key_init(part_def->partkey, value_list->count);

    if (parent_part_def != NULL) {
        tmp_part_keys = &obj_def->subpart_keys;
    }

    remainder = value_list->count % tmp_part_keys->count;
    group_count = value_list->count / tmp_part_keys->count;

    if (remainder != 0) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "remainder(%u) == 0", remainder);
        return OG_ERROR;
    }
    if (group_count > PART_MAX_LIST_COUNT) {
        OG_THROW_ERROR(ERR_PART_LIST_COUNT);
        return OG_ERROR;
    }

    for (uint32 i = 0; i < group_count; i++) {
        for (uint32 j = 0; j < tmp_part_keys->count; j++) {
            knl_part_column_def_t *key = cm_galist_get(tmp_part_keys, j);
            expr_tree_t *value_expr = cm_galist_get(value_list, i * tmp_part_keys->count + j);

            OG_RETURN_IFERR(sql_exec_expr(stmt, value_expr, &value));

            OG_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
                key->scale, part_def->partkey));
        }
    }
    return OG_SUCCESS;
}

static status_t sql_parse_list_default(lex_t *lex, knl_part_def_t *parent_part_def, knl_part_def_t *part_def,
    knl_part_obj_def_t *obj_def, bool32 *end)
{
    status_t status;
    bool32 result = OG_FALSE;
    bool32 *has_default = &obj_def->has_default;

    if (parent_part_def != NULL) {
        has_default = &obj_def->sub_has_default;
    }

    if (*has_default) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "default must be in last partition");
        return OG_ERROR;
    }

    status = lex_try_fetch(lex, PART_VALUE_DEFAULT, &result);
    OG_RETURN_IFERR(status);

    if (result) {
        status = lex_expected_end(lex);
        OG_RETURN_IFERR(status);

        *has_default = OG_TRUE;
        part_key_init(part_def->partkey, 1);
        part_put_default(part_def->partkey);
        *end = OG_TRUE;
        return OG_SUCCESS;
    }

    *end = OG_FALSE;
    return OG_SUCCESS;
}


static status_t sql_part_parse_type(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *part_def)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "BY") != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch(lex, word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    switch (word->id) {
        case KEY_WORD_RANGE:
            if (part_def->is_composite) {
                part_def->subpart_type = PART_TYPE_RANGE;
            } else {
                part_def->part_type = PART_TYPE_RANGE;
            }
            break;

        case KEY_WORD_LIST:
            if (part_def->is_composite) {
                part_def->subpart_type = PART_TYPE_LIST;
            } else {
                part_def->part_type = PART_TYPE_LIST;
            }
            break;

        case KEY_WORD_HASH:
            if (part_def->is_composite) {
                part_def->subpart_type = PART_TYPE_HASH;
            } else {
                part_def->part_type = PART_TYPE_HASH;
            }
            break;

        default:
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text %s", W2S(word));
            return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_part_verify_key_type(typmode_t *typmod)
{
    if (typmod->is_array) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "invalid partition key type - got ARRAY");
        return OG_ERROR;
    }

    switch (typmod->datatype) {
        case OG_TYPE_UINT32:
        case OG_TYPE_UINT64:
        case OG_TYPE_INTEGER:
        case OG_TYPE_BIGINT:
        case OG_TYPE_REAL:
        case OG_TYPE_NUMBER:
        case OG_TYPE_NUMBER2:
        case OG_TYPE_NUMBER3:
        case OG_TYPE_DECIMAL:
        case OG_TYPE_DATE:
        case OG_TYPE_TIMESTAMP:
        case OG_TYPE_INTERVAL_DS:
        case OG_TYPE_INTERVAL_YM:
        case OG_TYPE_CHAR:
        case OG_TYPE_VARCHAR:
        case OG_TYPE_STRING:
        case OG_TYPE_BINARY:
        case OG_TYPE_RAW:
            return OG_SUCCESS;
        default:
            break;
    }

    if (OG_IS_LOB_TYPE(typmod->datatype)) {
        OG_THROW_ERROR(ERR_LOB_PART_COLUMN);
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid partition key type - got %s",
            get_datatype_name_str((int32)(typmod->datatype)));
    }

    return OG_ERROR;
}

static status_t sql_check_part_keys(word_t *word, knl_table_def_t *table_def, knl_part_column_def_t *part_column)
{
    knl_part_column_def_t *column_def = NULL;
    knl_part_obj_def_t *def = table_def->part_def;

    if (def->part_keys.count > OG_MAX_PARTKEY_COLUMNS) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "part key count %u more than max value %u",
            def->part_keys.count, OG_MAX_PARTKEY_COLUMNS);
        return OG_ERROR;
    }

    if (def->subpart_keys.count > OG_MAX_PARTKEY_COLUMNS) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", subpart key count %u more than max value %u",
            def->subpart_keys.count, OG_MAX_PARTKEY_COLUMNS);
        return OG_ERROR;
    }

    if (def->is_composite) {
        for (uint32 i = 0; i < def->subpart_keys.count - 1; i++) {
            column_def = (knl_part_column_def_t *)cm_galist_get(&def->subpart_keys, i);
            if (part_column->column_id == column_def->column_id) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate column name %s", W2S(word));
                return OG_ERROR;
            }
        }
    } else {
        for (uint32 i = 0; i < def->part_keys.count - 1; i++) {
            column_def = (knl_part_column_def_t *)cm_galist_get(&def->part_keys, i);
            if (part_column->column_id == column_def->column_id) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate column name %s", W2S(word));
                return OG_ERROR;
            }
        }
    }

    return OG_SUCCESS;
}

static status_t sql_part_parse_keys(sql_stmt_t *stmt, word_t *word, bool32 *expect_as, knl_table_def_t *table_def)
{
    status_t status;
    text_t col_name;
    lex_t *lex = stmt->session->lex;
    knl_part_column_def_t *part_col = NULL;
    knl_part_obj_def_t *def = table_def->part_def;

    // table column info is not complete, must be create table (...) as select or create table as select
    if (def->delay_partition == 0) {
        if (table_def->columns.count == 0) {
            def->save_key = word->text;
            def->delay_partition = OG_TRUE;
            *expect_as = OG_TRUE;

            return OG_SUCCESS;
        } else {
            for (uint32 i = 0; i < table_def->columns.count; i++) {
                knl_column_def_t *column_def = cm_galist_get(&table_def->columns, i);
                if (column_def->typmod.datatype == OG_TYPE_UNKNOWN) {
                    def->save_key = word->text;
                    *expect_as = OG_TRUE;
                    def->delay_partition = OG_TRUE;
                    return OG_SUCCESS;
                }
            }
        }
    }

    for (;;) {
        status = lex_expected_fetch_variant(lex, word);
        OG_RETURN_IFERR(status);

        if (def->is_composite) {
            status = cm_galist_new(&def->subpart_keys, sizeof(knl_part_column_def_t), (pointer_t *)&part_col);
        } else {
            status = cm_galist_new(&def->part_keys, sizeof(knl_part_column_def_t), (pointer_t *)&part_col);
        }
        OG_RETURN_IFERR(status);

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &col_name);
        OG_RETURN_IFERR(status);

        part_col->column_id = OG_INVALID_ID32;
        for (uint32 i = 0; i < table_def->columns.count; i++) {
            knl_column_def_t *column_def = cm_galist_get(&table_def->columns, i);

            if (cm_text_equal(&col_name, &column_def->name)) {
                part_col->column_id = i;

                status = sql_part_verify_key_type(&column_def->typmod);
                OG_RETURN_IFERR(status);
                part_col->datatype = column_def->datatype;
                if (column_def->typmod.size > OG_MAX_PART_COLUMN_SIZE) {
                    OG_THROW_ERROR(ERR_MAX_PART_CLOUMN_SIZE, T2S(&column_def->name), OG_MAX_PART_COLUMN_SIZE);
                    return OG_ERROR;
                }
                part_col->is_char = column_def->typmod.is_char;
                part_col->precision = column_def->typmod.precision;
                part_col->scale = column_def->typmod.scale;
                part_col->size = column_def->size;
                break;
            }
        }

        if (part_col->column_id == OG_INVALID_ID32) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition key %s can not find in table",
                W2S(word));
            return OG_ERROR;
        }

        if (sql_check_part_keys(word, table_def, part_col) != OG_SUCCESS) {
            return OG_ERROR;
        }

        status = lex_fetch(lex, word);
        OG_RETURN_IFERR(status);

        if (word->type == WORD_TYPE_EOF) {
            return OG_SUCCESS;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }
}

status_t sql_list_store_define_key(part_key_t *curr_key, knl_part_def_t *parent_part_def, knl_part_obj_def_t *obj_def,
    const text_t *part_name)
{
    int32 cmp_result;
    part_key_t *prev_key = NULL;
    galist_t *tmp_part_keys = &obj_def->part_keys;
    galist_t *temp_group_keys = &obj_def->group_keys;

    if (parent_part_def != NULL) {
        tmp_part_keys = &obj_def->subpart_keys;
        temp_group_keys = &parent_part_def->group_subkeys;
    }

    for (uint32 i = 0; i < temp_group_keys->count; i++) {
        prev_key = cm_galist_get(temp_group_keys, i);
        cmp_result = knl_compare_defined_key(tmp_part_keys, prev_key, curr_key);
        if (cmp_result == 0) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate value in partition %s", T2S(part_name));
            return OG_ERROR;
        }
    }

    return cm_galist_insert(temp_group_keys, curr_key);
}

static status_t sql_list_verify_multi_key(sql_stmt_t *stmt, galist_t *expr_list, knl_part_def_t *parent_part_def,
    knl_part_obj_def_t *obj_def, const text_t *part_name)
{
    variant_t value;
    part_key_t *curr_key = NULL;
    knl_part_column_def_t *def_key = NULL;
    galist_t *tmp_part_key = &obj_def->part_keys;

    if (parent_part_def != NULL) {
        tmp_part_key = &obj_def->subpart_keys;
    }

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&curr_key));
    if (expr_list->count < tmp_part_key->count) {
        OG_THROW_ERROR_EX(ERR_ASSERT_ERROR, "expr_list->count(%u) >= obj_def->part_keys.count(%u)", expr_list->count,
            tmp_part_key->count);
        return OG_ERROR;
    }
    part_key_init(curr_key, tmp_part_key->count);

    for (uint32 i = 0; i < tmp_part_key->count; i++) {
        expr_tree_t *expr = cm_galist_get(expr_list, expr_list->count - tmp_part_key->count + i);

        OG_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        def_key = cm_galist_get(tmp_part_key, i);
        OG_RETURN_IFERR(sql_part_put_key(stmt, &value, def_key->datatype, def_key->size, def_key->is_char,
            def_key->precision, def_key->scale, curr_key));
    }

    return sql_list_store_define_key(curr_key, parent_part_def, obj_def, part_name);
}

static status_t sql_list_verify_one_key(sql_stmt_t *stmt, expr_tree_t *expr, knl_part_def_t *parent_part_def,
    knl_part_obj_def_t *obj_def, const text_t *part_name)
{
    variant_t value;
    part_key_t *curr_key = NULL;
    galist_t *tmp_part_keys = &obj_def->part_keys;

    if (parent_part_def != NULL) {
        tmp_part_keys = &obj_def->subpart_keys;
    }

    knl_part_column_def_t *def_key = cm_galist_get(tmp_part_keys, 0);
    OG_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&curr_key));
    part_key_init(curr_key, 1);
    OG_RETURN_IFERR(sql_part_put_key(stmt, &value, def_key->datatype, def_key->size, def_key->is_char,
        def_key->precision, def_key->scale, curr_key));
    return sql_list_store_define_key(curr_key, parent_part_def, obj_def, part_name);
}

static status_t sql_part_parse_bracket_value(sql_stmt_t *stmt, word_t *word, knl_part_def_t *parent_part_def,
    knl_part_def_t *part_def, uint32 *count, knl_part_obj_def_t *obj_def, bool32 is_multi_key)
{
    status_t status;
    bool32 result = OG_FALSE;
    expr_tree_t *value_expr = NULL;
    lex_t *lex = stmt->session->lex;
    galist_t *value_list = &part_def->value_list;
    sql_verifier_t verf = { 0 };
    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    *count = 0;
    for (;;) {
        status = lex_try_fetch(lex, PART_VALUE_DEFAULT, &result);
        OG_RETURN_IFERR(status);

        if (result) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but (%s) found", W2S(word));
            return OG_ERROR;
        }

        status = sql_create_expr_until(stmt, &value_expr, word);
        OG_RETURN_IFERR(status);

        status = sql_verify_expr(&verf, value_expr);
        OG_RETURN_IFERR(status);

        status = cm_galist_insert(value_list, value_expr);
        OG_RETURN_IFERR(status);
        (*count)++;
        if (!is_multi_key) {
            OG_RETURN_IFERR(sql_list_verify_one_key(stmt, value_expr, parent_part_def, obj_def, &part_def->name));
        }

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }
    return OG_SUCCESS;
}

static status_t sql_parse_list_values(sql_stmt_t *stmt, word_t *word, knl_part_def_t *parent_part_def,
    knl_part_def_t *part_def, knl_part_obj_def_t *obj_def)
{
    bool32 end = OG_FALSE;
    uint32 count;
    status_t status;
    lex_t *lex = stmt->session->lex;
    galist_t *tmp_part_keys = parent_part_def == NULL ? &obj_def->part_keys : &obj_def->subpart_keys;

    OG_RETURN_IFERR(sql_parse_list_default(lex, parent_part_def, part_def, obj_def, &end));
    OG_RETSUC_IFTRUE(end);

    if (tmp_part_keys->count == 1) {
        status = sql_part_parse_bracket_value(stmt, word, parent_part_def, part_def, &count, obj_def, OG_FALSE);
        OG_RETURN_IFERR(status);
    } else {
        for (;;) {
            status = lex_expected_fetch_bracket(lex, word);
            OG_RETURN_IFERR(status);

            OG_RETURN_IFERR(lex_push(lex, &word->text));

            if (sql_part_parse_bracket_value(stmt, word, parent_part_def, part_def, &count, obj_def, OG_TRUE) !=
                OG_SUCCESS) {
                lex_pop(lex);
                return OG_ERROR;
            }

            if (count != tmp_part_keys->count) {
                lex_pop(lex);
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "value count must equal to partition keys");
                return OG_ERROR;
            }
            if (sql_list_verify_multi_key(stmt, &part_def->value_list, parent_part_def, obj_def, &part_def->name) !=
                OG_SUCCESS) {
                lex_pop(lex);
                return OG_ERROR;
            }
            lex_pop(lex);

            status = lex_fetch(lex, word);
            OG_RETURN_IFERR(status);

            if (word->type == WORD_TYPE_EOF) {
                break;
            }

            if (!IS_SPEC_CHAR(word, ',')) {
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
                return OG_ERROR;
            }
        }
    }

    return sql_put_list_key(stmt, part_def, obj_def, parent_part_def);
}

static status_t sql_parse_range_partition(sql_stmt_t *stmt, word_t *word, knl_part_def_t *part_def,
    knl_part_obj_def_t *obj_def, knl_part_def_t *parent_def)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "VALUES"));

    if (stmt->context->type == OGSQL_TYPE_ALTER_TABLE) {
        OG_RETURN_IFERR(lex_try_fetch(lex, "LESS", &result));
        if (!result) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_TYPE, "key", "not consistent with partition type");
            return OG_ERROR;
        }
    } else {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "LESS"));
    }
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "THAN"));
    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition boundary expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_text(stmt->context, &word->text.value, &part_def->hiboundval));

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    if (sql_parse_range_values(stmt, word, part_def, obj_def, parent_def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    if (sql_range_verify_keys(stmt, obj_def, part_def, parent_def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

static status_t sql_parse_list_partition(sql_stmt_t *stmt, word_t *word, knl_part_def_t *part_def,
    knl_part_obj_def_t *obj_def, knl_part_def_t *parent_part_def)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "VALUES"));

    if (stmt->context->type == OGSQL_TYPE_ALTER_TABLE) {
        OG_RETURN_IFERR(lex_try_fetch_bracket(lex, word, &result));
        if (!result) {
            OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_TYPE, "key", "not consistent with partition type");
            return OG_ERROR;
        }
    } else {
        OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    }

    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition boundary expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_text(stmt->context, &word->text.value, &part_def->hiboundval));

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    if (sql_parse_list_values(stmt, word, parent_part_def, part_def, obj_def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }

    lex_pop(lex);
    return OG_SUCCESS;
}

static bool32 sql_check_sys_interval_part(knl_part_obj_def_t *obj_def, text_t *part_name)
{
    if (obj_def->part_type == PART_TYPE_RANGE && obj_def->is_interval &&
        part_name->len >= NEW_PREFIX_SYS_PART_NAME_LEN &&
        strncmp(part_name->str, NEW_PREFIX_SYS_PART_NAME, NEW_PREFIX_SYS_PART_NAME_LEN) == 0) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

status_t sql_parse_partition_attrs(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *def)
{
    status_t status;
    def->pctfree = OG_INVALID_ID32;
    def->is_csf = OG_INVALID_ID8;
    uint32 flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    uint8 algo = COMPRESS_NONE;
    uint8 type = COMPRESS_TYPE_NO;

    for (;;) {
        if (lex_fetch(lex, word) != OG_SUCCESS) {
            lex->flags = flags;
            return OG_ERROR;
        }
        if (word->type != WORD_TYPE_KEYWORD) {
            break;
        }
        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &def->space);
                break;

            case KEY_WORD_INITRANS:
                status = sql_parse_trans(lex, word, &def->initrans);
                break;

            case KEY_WORD_PCTFREE:
                status = sql_parse_pctfree(lex, word, &def->pctfree);
                break;

            case KEY_WORD_STORAGE:
                status = sql_parse_storage(lex, word, &def->storage_def, OG_FALSE);
                break;

            case KEY_WORD_COMPRESS:
                if (!def->exist_subparts) {
                    status = sql_parse_table_compress(stmt, lex, &type, &algo);
                    def->compress_type = type;
                    def->compress_algo = algo;
                    break;
                }
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "unexpected text %s, table part doesn't support compress if exists subpartitons", W2S(word));
                return OG_ERROR;

            case KEY_WORD_FORMAT:
                // don't support format clause
                if (!def->support_csf) {
                    OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "unexpected text format clause.");
                    lex->flags = flags;
                    return OG_ERROR;
                }

                status = sql_parse_row_format(lex, word, &def->is_csf);
                break;

            default:
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
                lex->flags = flags;
                return OG_ERROR;
        }

        if (status != OG_SUCCESS) {
            lex->flags = flags;
            return OG_ERROR;
        }
    }
    lex->flags = flags;
    return OG_SUCCESS;
}

status_t sql_parse_subpartition_attrs(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *part_def)
{
    status_t status;
    part_def->pctfree = OG_INVALID_ID32;
    uint32 flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;

    for (;;) {
        if (lex_fetch(lex, word) != OG_SUCCESS) {
            lex->flags = flags;
            return OG_ERROR;
        }

        if (word->type != WORD_TYPE_KEYWORD) {
            break;
        }

        switch (word->id) {
            case KEY_WORD_TABLESPACE:
                status = sql_parse_space(stmt, lex, word, &part_def->space);
                break;

            case KEY_WORD_INITRANS:
            case KEY_WORD_PCTFREE:
            case KEY_WORD_STORAGE:
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR,
                    "this physical attribute may not be specified for a table subpartition");
                return OG_ERROR;

            default:
                OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
                lex->flags = flags;
                return OG_ERROR;
        }

        if (status != OG_SUCCESS) {
            lex->flags = flags;
            return OG_ERROR;
        }
    }

    lex->flags = flags;
    return OG_SUCCESS;
}

static status_t sql_part_parse_partition_key(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *part_obj,
    knl_part_def_t *part_def, knl_part_def_t *parent_def)
{
    part_key_t *partkey = NULL;
    uint32 alloc_size = sizeof(part_key_t);
    status_t status;
    part_type_t part_type = part_obj->part_type;

    OG_RETURN_IFERR(sql_push(stmt, OG_MAX_COLUMN_SIZE, (void **)&partkey));
    MEMS_RETURN_IFERR(memset_s(partkey, OG_MAX_COLUMN_SIZE, 0x00, OG_MAX_COLUMN_SIZE));
    part_def->partkey = partkey;

    if (parent_def != NULL) {
        part_type = part_obj->subpart_type;
    }

    cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
    switch (part_type) {
        case PART_TYPE_LIST:
            status = sql_parse_list_partition(stmt, word, part_def, part_obj, parent_def);
            break;

        case PART_TYPE_RANGE:
            status = sql_parse_range_partition(stmt, word, part_def, part_obj, parent_def);
            break;

        default:
            status = OG_SUCCESS;
            break;
    }

    if (status == OG_ERROR) {
        return OG_ERROR;
    }

    if (partkey->size > 0) {
        alloc_size = partkey->size;
    }

    if (sql_alloc_mem(stmt->context, alloc_size, (pointer_t *)&part_def->partkey) != OG_SUCCESS) {
        return OG_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_sp(part_def->partkey, alloc_size, partkey, alloc_size));

    return OG_SUCCESS;
}


static status_t sql_part_parse_partition(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *obj_def,
    knl_part_def_t *part_def)
{
    lex_t *lex = stmt->session->lex;
    uint32 flags;

    flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
        cm_reset_error();
        OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &part_def->name));
    lex->flags = flags;
    if (sql_check_sys_interval_part(obj_def, &part_def->name)) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create table with interval part name _SYS_P");
        return OG_ERROR;
    }

    OGSQL_SAVE_STACK(stmt);
    if (sql_part_parse_partition_key(stmt, word, obj_def, part_def, NULL) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    part_def->support_csf = OG_TRUE;
    part_def->exist_subparts = obj_def->is_composite ? OG_TRUE : OG_FALSE;
    return sql_parse_partition_attrs(stmt, lex, word, part_def);
}

static bool32 sql_check_sys_interval_subpart(knl_part_obj_def_t *obj_def, text_t *part_name)
{
    if (obj_def->subpart_type == PART_TYPE_RANGE && obj_def->is_interval &&
        part_name->len >= PREFIX_SYS_SUBPART_NAME_LEN &&
        strncmp(part_name->str, PREFIX_SYS_SUBPART_NAME, PREFIX_SYS_SUBPART_NAME_LEN) == 0) {
        return OG_TRUE;
    }

    return OG_FALSE;
}

static status_t sql_part_parse_subpartition(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *obj_def,
    knl_part_def_t *parent_def)
{
    knl_part_def_t *subpart_def = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 flags = lex->flags;
    lex->flags = LEX_SINGLE_WORD;

    if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
        return OG_ERROR;
    }

    OG_RETURN_IFERR(cm_galist_new(&parent_def->subparts, sizeof(knl_part_def_t), (pointer_t *)&subpart_def));
    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &subpart_def->name));
    lex->flags = flags;

    if (sql_check_sys_interval_subpart(obj_def, &subpart_def->name)) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "create table with interval subpart name _SYS_SUBP");
        return OG_ERROR;
    }

    OGSQL_SAVE_STACK(stmt);
    if (sql_part_parse_partition_key(stmt, word, obj_def, subpart_def, parent_def) != OG_SUCCESS) {
        OGSQL_RESTORE_STACK(stmt);
        return OG_ERROR;
    }
    OGSQL_RESTORE_STACK(stmt);

    return sql_parse_subpartition_attrs(stmt, lex, word, subpart_def);
}

static status_t sql_part_parse_subpartitions(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *obj_def,
    knl_part_def_t *parent_def)
{
    lex_t *lex = stmt->session->lex;
    lex->flags |= LEX_WITH_ARG;
    obj_def->sub_has_default = OG_FALSE;

    for (;;) {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SUBPARTITION"));
        OG_RETURN_IFERR(sql_part_parse_subpartition(stmt, word, obj_def, parent_def));

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

static status_t sql_part_generate_space_name(sql_stmt_t *stmt, knl_store_in_set_t *store_in, galist_t *part_list)
{
    knl_part_def_t *part_def = NULL;
    text_t *space_name = NULL;

    for (uint32 i = 0; i < store_in->part_cnt; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(part_list, i);
        space_name = (text_t *)cm_galist_get(&store_in->space_list, i % store_in->space_cnt);
        OG_RETURN_IFERR(sql_copy_text(stmt->context, space_name, &part_def->space));
    }

    return OG_SUCCESS;
}

static status_t sql_part_new_part_def(sql_stmt_t *stmt, uint32 part_cnt, galist_t *part_list)
{
    knl_part_def_t *part_def = NULL;

    for (uint32 i = 0; i < part_cnt; i++) {
        OG_RETURN_IFERR(cm_galist_new(part_list, sizeof(knl_part_def_t), (pointer_t *)&part_def));
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&part_def->partkey));
        cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
    }

    return OG_SUCCESS;
}

static status_t sql_part_parse_hash_attrs(sql_stmt_t *stmt, galist_t *part_list, uint32 part_cnt)
{
    knl_part_def_t *part_def = NULL;

    for (uint32 i = 0; i < part_cnt; i++) {
        OG_RETURN_IFERR(cm_galist_new(part_list, sizeof(knl_part_def_t), (pointer_t *)&part_def));
        OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(part_key_t), (pointer_t *)&part_def->partkey));
        cm_galist_init(&part_def->value_list, stmt->context, sql_alloc_mem);
        part_def->is_csf = OG_INVALID_ID8;
        part_def->pctfree = OG_INVALID_ID32;
        part_def->initrans = 0;
    }

    return OG_SUCCESS;
}

static status_t sql_generate_default_subpart(sql_stmt_t *stmt, knl_part_obj_def_t *def, galist_t *part_list)
{
    text_t text;
    knl_part_def_t *subpart_def = NULL;

    OG_RETURN_IFERR(cm_galist_new(part_list, sizeof(knl_part_def_t), (pointer_t *)&subpart_def));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&subpart_def->partkey));
    cm_galist_init(&subpart_def->value_list, stmt->context, sql_alloc_mem);
    if (def->subpart_type == PART_TYPE_LIST) {
        text.str = PART_VALUE_DEFAULT;
        text.len = (uint32)strlen(PART_VALUE_DEFAULT);
        OG_RETURN_IFERR(sql_copy_text(stmt->context, &text, &subpart_def->hiboundval));
        part_key_init(subpart_def->partkey, 1);
        part_put_default(subpart_def->partkey);
    }

    if (def->subpart_type == PART_TYPE_RANGE) {
        char *hiboundval_buf = NULL;
        uint32 hiboundval_len = OG_MAX_PARTKEY_COLUMNS * OG_MAX_HIBOUND_VALUE_LEN;
        OG_RETURN_IFERR(sql_push(stmt, hiboundval_len, (void **)&hiboundval_buf));
        MEMS_RETURN_IFERR(memset_sp(hiboundval_buf, hiboundval_len, 0, hiboundval_len));
        part_key_init(subpart_def->partkey, def->subpart_keys.count);
        for (uint32 i = 0; i < def->subpart_keys.count; i++) {
            MEMS_RETURN_IFERR(strcat_sp(hiboundval_buf, hiboundval_len, PART_VALUE_MAX));
            if (i != def->subpart_keys.count - 1) {
                MEMS_RETURN_IFERR(strcat_sp(hiboundval_buf, hiboundval_len, ", "));
            } else {
                MEMS_RETURN_IFERR(strcat_sp(hiboundval_buf, hiboundval_len, "\0"));
            }
            part_put_max(subpart_def->partkey);
        }
        text.str = hiboundval_buf;
        text.len = (uint32)strlen(hiboundval_buf);
        OG_RETURN_IFERR(sql_copy_text(stmt->context, &text, &subpart_def->hiboundval));
    }

    int64 part_name_id;
    text_t part_name;
    char name_arr[OG_NAME_BUFFER_SIZE] = { '\0' };

    OG_RETURN_IFERR(sql_alloc_object_id(stmt, &part_name_id));
    PRTS_RETURN_IFERR(snprintf_s(name_arr, OG_NAME_BUFFER_SIZE, OG_NAME_BUFFER_SIZE - 1, "SYS_SUBP%llX", part_name_id));
    part_name.len = (uint32)strlen(name_arr);
    part_name.str = name_arr;
    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, WORD_TYPE_STRING, &part_name, &subpart_def->name));

    subpart_def->initrans = 0;
    subpart_def->is_csf = OG_INVALID_ID8;
    subpart_def->pctfree = OG_INVALID_ID32;

    return OG_SUCCESS;
}

static status_t sql_part_parse_store_in_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_store_in_set_t *store_in)
{
    text_t *space = NULL;
    status_t status;

    lex->flags = LEX_SINGLE_WORD;

    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        status = lex_expected_fetch_variant(lex, word);
        OG_BREAK_IF_ERROR(status);

        status = cm_galist_new(&store_in->space_list, sizeof(text_t), (pointer_t *)&space);
        OG_BREAK_IF_ERROR(status);

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, space);
        OG_BREAK_IF_ERROR(status);

        store_in->space_cnt++;

        status = lex_fetch(lex, word);
        OG_BREAK_IF_ERROR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    lex_pop(lex);
    return status;
}

static status_t sql_part_parse_store_in_clause(sql_stmt_t *stmt, word_t *word, knl_store_in_set_t *store_in)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;

    if (lex_try_fetch(lex, "STORE", &result) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (!result) {
        return OG_SUCCESS;
    }

    if (lex_expected_fetch_word(lex, "IN") != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "tablespace expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_part_parse_store_in_space(stmt, lex, word, store_in));
    return OG_SUCCESS;
}

static status_t sql_part_parse_partcnt(sql_stmt_t *stmt, knl_store_in_set_t *store_in)
{
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_uint32(lex, &store_in->part_cnt) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (store_in->part_cnt == 0) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid partition number");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_subpartitions_for_compart(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_obj_def_t *def,
    knl_part_def_t *part_def)
{
    knl_store_in_set_t store_in;

    cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&part_def->group_subkeys, stmt->context, sql_alloc_mem);
    if (word->type == WORD_TYPE_VARIANT && cm_compare_text_str_ins(&word->text.value, "SUBPARTITIONS") == 0) {
        store_in.is_store_in = OG_TRUE;
        store_in.space_cnt = 0;
        cm_galist_init(&store_in.space_list, stmt->context, sql_alloc_mem);
        OG_RETURN_IFERR(sql_part_parse_partcnt(stmt, &store_in));
        OG_RETURN_IFERR(sql_part_parse_store_in_clause(stmt, word, &store_in));
        OG_RETURN_IFERR(sql_part_new_part_def(stmt, store_in.part_cnt, &part_def->subparts));
        if (store_in.space_cnt > 0) {
            OG_RETURN_IFERR(sql_part_generate_space_name(stmt, &store_in, &part_def->subparts));
        }
        OG_RETURN_IFERR(lex_fetch(lex, word));
    } else if (def->subpart_store_in.is_store_in) {
        OG_RETURN_IFERR(sql_part_new_part_def(stmt, def->subpart_store_in.part_cnt, &part_def->subparts));
        if (def->subpart_store_in.space_cnt > 0) {
            OG_RETURN_IFERR(sql_part_generate_space_name(stmt, &def->subpart_store_in, &part_def->subparts));
        }
    } else if (word->type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        OG_RETURN_IFERR(sql_part_parse_subpartitions(stmt, word, def, part_def));
        lex_pop(lex);
        OG_RETURN_IFERR(lex_fetch(lex, word));
    } else {
        OG_RETURN_IFERR(sql_generate_default_subpart(stmt, def, &part_def->subparts));
    }

    part_def->is_parent = OG_TRUE;

    return OG_SUCCESS;
}

static status_t sql_part_parse_partitions(sql_stmt_t *stmt, word_t *word, knl_table_def_t *table_def)
{
    status_t status;
    knl_part_def_t *part_def = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 flags = lex->flags;
    knl_part_obj_def_t *def = table_def->part_def;

    lex->flags |= LEX_WITH_ARG;
    for (;;) {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "PARTITION"));
        OG_RETURN_IFERR(cm_galist_new(&def->parts, sizeof(knl_part_def_t), (pointer_t *)&part_def));
        OG_RETURN_IFERR(sql_part_parse_partition(stmt, word, def, part_def));

        if (def->is_composite) {
            OG_RETURN_IFERR(sql_parse_subpartitions_for_compart(stmt, lex, word, def, part_def));
        }

        if (word->type == WORD_TYPE_EOF) {
            status = OG_SUCCESS;
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            status = OG_ERROR;
            break;
        }
    }

    lex->flags = flags;
    return status;
}

static status_t sql_part_parse_interval_space(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_obj_def_t *obj_def)
{
    text_t *interval_space = NULL;
    status_t status;

    lex->flags = LEX_SINGLE_WORD;
    OG_RETURN_IFERR(lex_push(lex, &word->text));

    for (;;) {
        status = lex_expected_fetch_word(lex, "TABLESPACE");
        OG_BREAK_IF_ERROR(status);
        status = lex_expected_fetch_variant(lex, word);
        OG_BREAK_IF_ERROR(status);
        status = cm_galist_new(&obj_def->part_store_in.space_list, sizeof(text_t), (pointer_t *)&interval_space);
        OG_BREAK_IF_ERROR(status);
        obj_def->part_store_in.space_cnt++;

        status = sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, interval_space);
        OG_BREAK_IF_ERROR(status);
        status = lex_fetch(lex, word);
        OG_BREAK_IF_ERROR(status);

        if (word->type == WORD_TYPE_EOF) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            lex_pop(lex);
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }
    lex_pop(lex);
    return status;
}

static status_t sql_parse_interval_key(sql_stmt_t *stmt, word_t *word, part_key_t *interval_key,
    knl_part_obj_def_t *obj_def)
{
    expr_tree_t *value_expr = NULL;
    sql_verifier_t verf = { 0 };
    variant_t value;
    knl_part_column_def_t *key = NULL;
    lex_t *lex = stmt->session->lex;

    if (obj_def->part_keys.count > 1) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "only support one interval partition column");
        return OG_ERROR;
    }

    key = cm_galist_get(&obj_def->part_keys, 0);
    if (!OG_IS_NUMERIC_TYPE(key->datatype) && !OG_IS_DATETIME_TYPE(key->datatype)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid interval partition column data type");
        return OG_ERROR;
    }

    part_key_init(interval_key, 1);

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    lex->flags |= LEX_WITH_ARG;

    OG_RETURN_IFERR(sql_create_expr_until(stmt, &value_expr, word));

    OG_RETURN_IFERR(sql_verify_expr(&verf, value_expr));

    OG_RETURN_IFERR(sql_exec_expr(stmt, value_expr, &value));

    if (value.is_null) {
        OG_SRC_THROW_ERROR(value_expr->loc, ERR_OPERATIONS_NOT_ALLOW, "set inerval to null");
        return OG_ERROR;
    }

    if (OG_IS_NUMERIC_TYPE(key->datatype)) {
        OG_RETURN_IFERR(sql_part_put_key(stmt, &value, key->datatype, key->size, key->is_char, key->precision,
            key->scale, interval_key));
        if (var_as_decimal(&value) != OG_SUCCESS || IS_DEC8_NEG(&value.v_dec)) {
            OG_SRC_THROW_ERROR(value_expr->loc, ERR_INVALID_PART_TYPE, "interval key data", "");
            return OG_ERROR;
        }
    } else {
        if (!OG_IS_DSITVL_TYPE(value.type) && !OG_IS_YMITVL_TYPE(value.type)) {
            OG_SRC_THROW_ERROR(value_expr->loc, ERR_INVALID_PART_TYPE, "interval key data", "");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_part_put_key(stmt, &value, value.type, key->size, key->is_char, key->precision, key->scale,
            interval_key));
    }
    return lex_expected_end(lex);
}

static status_t sql_parse_interval(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *obj_def)
{
    bool32 result = OG_FALSE;
    lex_t *lex = stmt->session->lex;
    part_key_t *interval_key = NULL;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "interval key expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&interval_key));
    if (obj_def->delay_partition == OG_TRUE) {
        obj_def->save_interval_part = word->text;
    } else {
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        if (sql_copy_text(stmt->context, &word->text.value, &obj_def->interval) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }

        if (sql_parse_interval_key(stmt, word, interval_key, obj_def) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
    }
    obj_def->binterval.bytes = (uint8 *)interval_key;
    obj_def->binterval.size = interval_key->size;
    OG_RETURN_IFERR(lex_try_fetch(lex, "STORE", &result));

    if (result) {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "IN"));

        OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
        if (word->text.len == 0) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "tablespace expected");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_part_parse_interval_space(stmt, lex, word, obj_def));
    }
    return OG_SUCCESS;
}

static status_t sql_try_parse_interval(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *obj_def)
{
    lex_t *lex = stmt->session->lex;
    uint32 flags = lex->flags;

    OG_RETURN_IFERR(lex_try_fetch(lex, "INTERVAL", &obj_def->is_interval));
    if (!obj_def->is_interval) {
        return OG_SUCCESS;
    }
    OG_RETURN_IFERR(sql_parse_interval(stmt, word, obj_def));
    lex->flags = flags;
    return OG_SUCCESS;
}

static status_t sql_part_parse_store_in(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *def)
{
    lex_t *lex = stmt->session->lex;

    if (def->part_type != PART_TYPE_HASH) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "partitions", &def->part_store_in.is_store_in));
    if (def->part_store_in.is_store_in) {
        OG_RETURN_IFERR(sql_part_parse_partcnt(stmt, &def->part_store_in));
        OG_RETURN_IFERR(sql_part_parse_hash_attrs(stmt, &def->parts, def->part_store_in.part_cnt));
        OG_RETURN_IFERR(sql_part_parse_store_in_clause(stmt, word, &def->part_store_in));
        if (def->part_store_in.space_cnt > 0) {
            OG_RETURN_IFERR(sql_part_generate_space_name(stmt, &def->part_store_in, &def->parts));
        }
    }

    return OG_SUCCESS;
}

static status_t sql_subpart_parse_store_in(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *def)
{
    lex_t *lex = stmt->session->lex;

    if (!def->is_composite) {
        return OG_SUCCESS;
    }

    if (def->subpart_type != PART_TYPE_HASH) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "subpartitions", &def->subpart_store_in.is_store_in));
    if (def->subpart_store_in.is_store_in) {
        OG_RETURN_IFERR(sql_part_parse_partcnt(stmt, &def->subpart_store_in));
        OG_RETURN_IFERR(sql_part_parse_store_in_clause(stmt, word, &def->subpart_store_in));
    }

    return OG_SUCCESS;
}

static status_t sql_generate_subpart_for_storein(sql_stmt_t *stmt, word_t *word, knl_part_obj_def_t *def)
{
    knl_part_def_t *part_def = NULL;

    if (!def->is_composite) {
        return OG_SUCCESS;
    }

    for (uint32 i = 0; i < def->parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->parts, i);
        part_def->is_parent = OG_TRUE;
        cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
        if (def->subpart_store_in.is_store_in) { // subpart is also defined in "store in"
            knl_part_def_t *subpart_def = NULL;
            for (uint32 j = 0; j < def->subpart_store_in.part_cnt; j++) {
                OG_RETURN_IFERR(cm_galist_new(&part_def->subparts, sizeof(knl_part_def_t), (pointer_t *)&subpart_def));
                OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(part_key_t), (pointer_t *)&subpart_def->partkey));
                subpart_def->initrans = 0;
                subpart_def->is_parent = OG_FALSE;
                subpart_def->is_csf = OG_INVALID_ID8;
                subpart_def->pctfree = OG_INVALID_ID32;
            }
        } else { // it's not specify subpartition desc
            OG_RETURN_IFERR(sql_generate_default_subpart(stmt, def, &part_def->subparts));
        }
    }

    lex_t *lex = stmt->session->lex;
    if (lex_expected_end(lex) != OG_SUCCESS) {
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_part_type_keys(sql_stmt_t *stmt, word_t *word, bool32 *expect_as, knl_table_def_t *table_def)
{
    lex_t *lex = stmt->session->lex;
    knl_part_obj_def_t *def = table_def->part_def;
    status_t status;

    OG_RETURN_IFERR(sql_part_parse_type(stmt, word, def));
    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition key expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    status = sql_part_parse_keys(stmt, word, expect_as, table_def);
    lex_pop(lex);
    OG_RETURN_IFERR(status);

    if (def->part_type == PART_TYPE_RANGE) {
        OG_RETURN_IFERR(sql_try_parse_interval(stmt, word, def));
    }

    OG_RETURN_IFERR(lex_try_fetch(lex, "SUBPARTITION", &def->is_composite));
    if (def->is_composite) { // parse subpart keys in case of subpartition
        OG_RETURN_IFERR(sql_part_parse_type(stmt, word, def));
        OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
        if (word->text.len == 0) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "subpartition key expected");
            return OG_ERROR;
        }

        if (def->delay_partition) {
            def->save_subkey = word->text;
        } else {
            OG_RETURN_IFERR(lex_push(lex, &word->text));
            status = sql_part_parse_keys(stmt, word, expect_as, table_def);
            lex_pop(lex);
            OG_RETURN_IFERR(status);
        }
    }

    return OG_SUCCESS;
}

status_t sql_part_parse_table(sql_stmt_t *stmt, word_t *word, bool32 *expect_as, knl_table_def_t *table_def)
{
    knl_part_obj_def_t *def = NULL;
    lex_t *lex = stmt->session->lex;
    status_t status;

    if (cm_lic_check(LICENSE_PARTITION) != OG_SUCCESS) {
        OG_THROW_ERROR(ERR_LICENSE_CHECK_FAIL, " effective partition function license is required.");
        return OG_ERROR;
    }

    if (table_def->part_def != NULL) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate partition definition");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&table_def->part_def));
    def = table_def->part_def;
    table_def->parted = OG_TRUE;

    cm_galist_init(&def->parts, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->group_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->part_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->subpart_store_in.space_list, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->subpart_keys, stmt->context, sql_alloc_mem);

    OG_RETURN_IFERR(sql_parse_part_type_keys(stmt, word, expect_as, table_def));
    OG_RETURN_IFERR(sql_part_parse_store_in(stmt, word, def));
    OG_RETURN_IFERR(sql_subpart_parse_store_in(stmt, word, def));
    if (def->part_store_in.is_store_in) {
        return sql_generate_subpart_for_storein(stmt, word, def);
    }

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partitions expected");
        return OG_ERROR;
    }
    if (def->delay_partition == OG_TRUE) {
        def->save_part = word->text;
    } else {
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        status = sql_part_parse_partitions(stmt, word, table_def);
        lex_pop(lex);
        OG_RETURN_IFERR(status);
    }

    return OG_SUCCESS;
}


static status_t sql_parse_split_part_def(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    knl_part_def_t *part_def = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 flag = lex->flags;
    lex->flags = LEX_SINGLE_WORD;
    for (uint32 i = 0;; i++) {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "PARTITION"));
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            cm_reset_error();
            OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
            return OG_ERROR;
        }

        part_def = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, i);
        OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &part_def->name));

        part_def->support_csf = OG_FALSE;
        part_def->exist_subparts = def->part_def.obj_def->is_composite ? OG_TRUE : OG_FALSE;
        OG_RETURN_IFERR(sql_parse_partition_attrs(stmt, lex, word, part_def));

        if (i == 1) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition define error");
        return OG_ERROR;
    }
    lex->flags = flag;
    return OG_SUCCESS;
}


static status_t sql_parse_split_parts_def(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    knl_part_def_t *first_part = NULL;
    knl_part_def_t *second_part = NULL;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition define expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    if (sql_parse_split_part_def(stmt, word, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);

    first_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, (uint32)0);
    second_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, (uint32)1);
    if ((cm_compare_text(&def->part_def.name, &first_part->name) == 0) ||
        (cm_compare_text(&first_part->name, &second_part->name) == 0)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "partition name duplicate");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_update_index_clause(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    OG_RETURN_IFERR(lex_fetch(lex, word));

    if (word->type == WORD_TYPE_EOF) {
        def->part_def.global_index_option = OG_FALSE;
        return OG_SUCCESS;
    }

    if (word->id == KEY_WORD_UPDATE) {
        def->part_def.global_index_option = OG_TRUE;
    } else if (word->id == KEY_WORD_INVALIDATE) {
        def->part_def.global_index_option = OG_FALSE;
    } else {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(word));
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "GLOBAL"));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "INDEXES"));

    return lex_expected_end(lex);
}

static status_t sql_parse_first_part_hiboundval(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def, bool32 is_subpart)
{
    word_t word;
    galist_t *part_list = NULL;
    knl_part_def_t *first_part = NULL;
    knl_part_def_t *parent_part = NULL;

    lex->flags |= LEX_WITH_ARG;
    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, &word));
    if (word.text.len == 0) {
        OG_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "split value of partition expected");
        return OG_ERROR;
    }

    if (is_subpart) {
        parent_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
        part_list = &parent_part->subparts;
    } else {
        part_list = &def->part_def.obj_def->parts;
    }

    OG_RETURN_IFERR(cm_galist_new(part_list, sizeof(knl_part_def_t), (pointer_t *)&first_part));
    OG_RETURN_IFERR(sql_copy_text(stmt->context, &word.text.value, &first_part->hiboundval));

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&first_part->partkey));

    OG_RETURN_IFERR(lex_push(lex, &word.text));
    if (sql_parse_range_values(stmt, &word, first_part, def->part_def.obj_def, parent_part) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);

    return OG_SUCCESS;
}

static status_t sql_parse_second_part_hiboundval(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_altable_def_t *def,
    bool32 is_subpart)
{
    uint32 part_no;
    uint32 subpart_no;
    galist_t *part_list = NULL;
    knl_part_def_t *secend_part = NULL;
    knl_part_def_t *parent_part = NULL;

    if (is_subpart) {
        parent_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
        part_list = &parent_part->subparts;
    } else {
        part_list = &def->part_def.obj_def->parts;
    }

    OG_RETURN_IFERR(cm_galist_new(part_list, sizeof(knl_part_def_t), (pointer_t *)&secend_part));
    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&secend_part->partkey));

    dc_entity_t *entity = DC_ENTITY(dc);

    if (is_subpart) {
        OG_RETURN_IFERR(knl_find_subpart_by_name(entity, &def->part_def.name, &part_no, &subpart_no));
        table_part_t *table_part = TABLE_GET_PART(&entity->table, part_no);
        table_part_t *table_subpart = PART_GET_SUBENTITY(entity->table.part_table, table_part->subparts[subpart_no]);
        OG_RETURN_IFERR(sql_copy_text(stmt->context, &table_subpart->desc.hiboundval, &secend_part->hiboundval));

        MEMS_RETURN_IFERR(memcpy_s(secend_part->partkey, OG_MAX_COLUMN_SIZE,
            (part_key_t *)table_subpart->desc.bhiboundval.bytes, table_subpart->desc.bhiboundval.size));
    } else {
        OG_RETURN_IFERR(knl_find_table_part_by_name(entity, &def->part_def.name, &part_no));
        table_part_t *table_part = TABLE_GET_PART(&entity->table, part_no);
        OG_RETURN_IFERR(sql_copy_text(stmt->context, &table_part->desc.hiboundval, &secend_part->hiboundval));

        MEMS_RETURN_IFERR(memcpy_s(secend_part->partkey, OG_MAX_COLUMN_SIZE,
            (part_key_t *)table_part->desc.bhiboundval.bytes, table_part->desc.bhiboundval.size));
    }

    if (sql_range_verify_keys(stmt, def->part_def.obj_def, secend_part, parent_part) != OG_SUCCESS) {
        cm_reset_error();
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "split partition value invalid");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_get_tab_part_key(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_column_t *knl_column = NULL;
    knl_part_column_def_t *part_col = NULL;

    for (uint16 i = 0; i < knl_part_key_count(dc->handle); i++) {
        if (cm_galist_new(&def->part_def.obj_def->part_keys, sizeof(knl_part_column_def_t),
            (pointer_t *)&part_col) != OG_SUCCESS) {
            return OG_ERROR;
        }
        part_col->column_id = knl_part_key_column_id(dc->handle, i);
        knl_column = knl_get_column(dc->handle, part_col->column_id);
        part_col->datatype = knl_column->datatype;
        part_col->size = knl_column->size;
        part_col->precision = knl_column->precision;
        part_col->scale = knl_column->scale;
        part_col->is_char = KNL_COLUMN_IS_CHARACTER(knl_column);
    }

    return OG_SUCCESS;
}

static status_t sql_get_tab_subpart_key(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_column_t *knl_column = NULL;
    knl_part_column_def_t *part_col = NULL;

    for (uint16 i = 0; i < knl_subpart_key_count(dc->handle); i++) {
        if (cm_galist_new(&def->part_def.obj_def->subpart_keys, sizeof(knl_part_column_def_t),
            (pointer_t *)&part_col) != OG_SUCCESS) {
            return OG_ERROR;
        }
        part_col->column_id = knl_subpart_key_column_id(dc->handle, i);
        knl_column = knl_get_column(dc->handle, part_col->column_id);
        part_col->datatype = knl_column->datatype;
        part_col->size = knl_column->size;
        part_col->precision = knl_column->precision;
        part_col->scale = knl_column->scale;
        part_col->is_char = KNL_COLUMN_IS_CHARACTER(knl_column);
    }

    return OG_SUCCESS;
}

static status_t sql_parse_split_subpart_def(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    knl_part_def_t *part_def = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 flag = lex->flags;
    lex->flags = LEX_SINGLE_WORD;

    knl_part_def_t *parent_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    for (uint32 i = 0; i < OG_SPLIT_PART_COUNT; i++) {
        OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SUBPARTITION"));
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            cm_reset_error();
            OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
            return OG_ERROR;
        }

        part_def = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, i);
        OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &part_def->name));
        OG_RETURN_IFERR(sql_parse_subpartition_attrs(stmt, lex, word, part_def));

        if (i == OG_SPLIT_PART_COUNT - 1) {
            break;
        }

        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    if (word->type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "partition define error");
        return OG_ERROR;
    }

    lex->flags = flag;
    return OG_SUCCESS;
}

static status_t sql_parse_split_subpart_defs(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    lex_t *lex = stmt->session->lex;
    knl_part_def_t *first_part = NULL;
    knl_part_def_t *second_part = NULL;

    OG_RETURN_IFERR(lex_expected_fetch_bracket(lex, word));
    if (word->text.len == 0) {
        OG_SRC_THROW_ERROR(word->text.loc, ERR_SQL_SYNTAX_ERROR, "subpartition define expected");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    if (sql_parse_split_subpart_def(stmt, word, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);

    knl_part_def_t *parent_part = (knl_part_def_t *)cm_galist_get(&def->part_def.obj_def->parts, 0);
    first_part = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 0);
    second_part = (knl_part_def_t *)cm_galist_get(&parent_part->subparts, 1);
    if ((cm_compare_text(&def->part_def.name, &first_part->name) == 0) ||
        (cm_compare_text(&first_part->name, &second_part->name) == 0)) {
        OG_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "subpartition name duplicate");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t sql_parse_split_subpartition_clause(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def,
    knl_dictionary_t *dc)
{
    word_t word;
    OG_RETURN_IFERR(sql_get_tab_subpart_key(stmt, dc, def));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "AT"));
    OG_RETURN_IFERR(sql_parse_first_part_hiboundval(stmt, lex, def, OG_TRUE));
    OG_RETURN_IFERR(sql_parse_second_part_hiboundval(stmt, dc, def, OG_TRUE));
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "INTO"));
    OG_RETURN_IFERR(sql_parse_split_subpart_defs(stmt, &word, def));
    return sql_parse_update_index_clause(stmt, &word, def);
}

static status_t sql_parse_split_subpartition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    knl_dictionary_t dc;
    knl_session_t *session = &stmt->session->knl_session;

    def->action = ALTABLE_SPLIT_SUBPARTITION;
    if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_def.name));
    if (knl_open_dc(session, (text_t *)&def->user, (text_t *)&def->name, &dc) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not found", T2S(&def->name));
        return OG_ERROR;
    }

    if (!knl_is_part_table(dc.handle) || !knl_is_compart_table(dc.handle)) {
        knl_close_dc(&dc);
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s is not composite partition table", T2S(&def->name));
        return OG_ERROR;
    }

    def->part_def.obj_def->part_type = knl_part_table_type(dc.handle);
    def->part_def.obj_def->subpart_type = knl_subpart_table_type(dc.handle);
    if (def->part_def.obj_def->subpart_type != PART_TYPE_RANGE) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "split subpartition", "non-range subpartitioned table");
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    knl_part_def_t *virtual_part = NULL;
    cm_galist_init(&def->part_def.obj_def->subpart_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
    if (cm_galist_new(&def->part_def.obj_def->parts, sizeof(knl_part_def_t), (pointer_t *)&virtual_part) !=
        OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    cm_galist_init(&virtual_part->subparts, stmt->context, sql_alloc_mem);
    if (sql_parse_split_subpartition_clause(stmt, lex, def, &dc) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    knl_close_dc(&dc);
    return OG_SUCCESS;
}

static status_t sql_split_check_part_type(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    if (!knl_is_part_table(dc->handle)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        return OG_ERROR;
    }

    def->part_def.obj_def->part_type = knl_part_table_type(dc->handle);

    table_t *table = DC_TABLE(dc);

    if (def->part_def.obj_def->part_type != PART_TYPE_RANGE || table->part_table->desc.interval_key != NULL) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "split partition", "non-range partitioned table");
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_split_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    uint32 match_id;
    word_t word;
    knl_handle_t knl = &stmt->session->knl_session;
    knl_dictionary_t dc;
    status_t status = OG_SUCCESS;

    if (sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def.obj_def) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (lex_expected_fetch_1of2(lex, "SUBPARTITION", "PARTITION", &match_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (match_id == 0) {
        return sql_parse_split_subpartition(stmt, lex, def);
    }

    def->action = ALTABLE_SPLIT_PARTITION;
    if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }
    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &def->part_def.name));

    if (knl_open_dc(knl, (text_t *)&def->user, (text_t *)&def->name, &dc) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
        return OG_ERROR;
    }

    if (sql_split_check_part_type(stmt, &dc, def) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    cm_galist_init(&def->part_def.obj_def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);

    do {
        status = sql_get_tab_part_key(stmt, &dc, def);
        OG_BREAK_IF_ERROR(status);

        status = lex_expected_fetch_word(lex, "AT");
        OG_BREAK_IF_ERROR(status);

        status = sql_parse_first_part_hiboundval(stmt, lex, def, OG_FALSE);
        OG_BREAK_IF_ERROR(status);

        status = sql_parse_second_part_hiboundval(stmt, &dc, def, OG_FALSE);
        OG_BREAK_IF_ERROR(status);

        status = lex_expected_fetch_word(lex, "INTO");
        OG_BREAK_IF_ERROR(status);

        status = sql_parse_split_parts_def(stmt, &word, def);
        OG_BREAK_IF_ERROR(status);

        status = sql_parse_update_index_clause(stmt, &word, def);
    } while (OG_FALSE);

    knl_close_dc(&dc);
    return status;
}

static status_t sql_parse_altable_set_range_part(knl_dictionary_t *dc)
{
    part_table_t *part_table = NULL;

    part_table = DC_ENTITY(dc)->table.part_table;
    if (part_table->desc.interval_key == NULL) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "not support convert range to range partition");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_altable_set_interval_part_core(sql_stmt_t *stmt, lex_t *lex, word_t *word,
    knl_altable_def_t *def, knl_column_t *knl_col)
{
    variant_t value;
    expr_tree_t *expr = NULL;
    sql_verifier_t verf = { 0 };
    part_key_t *partkey = NULL;

    verf.context = stmt->context;
    verf.stmt = stmt;
    verf.excl_flags = SQL_EXCL_AGGR | SQL_EXCL_COLUMN | SQL_EXCL_STAR | SQL_EXCL_SUBSELECT | SQL_EXCL_JOIN |
        SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_DEFAULT | SQL_EXCL_ROWSCN | SQL_EXCL_WIN_SORT | SQL_EXCL_ROWNODEID;

    lex->flags |= LEX_WITH_ARG;

    OG_RETURN_IFERR(sql_copy_text(stmt->context, &word->text.value, &def->part_def.part_interval.interval));
    OG_RETURN_IFERR(sql_create_expr_until(stmt, &expr, word));
    OG_RETURN_IFERR(sql_verify_expr(&verf, expr));
    OG_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));

    if (value.is_null) {
        OG_SRC_THROW_ERROR(expr->loc, ERR_OPERATIONS_NOT_ALLOW, "set inerval to null");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_alloc_mem(stmt->context, OG_MAX_COLUMN_SIZE, (pointer_t *)&partkey));
    part_key_init(partkey, 1);
    if (OG_IS_NUMERIC_TYPE(knl_col->datatype)) {
        OG_RETURN_IFERR(sql_part_put_key(stmt, &value, knl_col->datatype, knl_col->size,
            KNL_COLUMN_IS_CHARACTER(knl_col), knl_col->precision, knl_col->scale, partkey));
        if (var_as_decimal(&value) != OG_SUCCESS || IS_DEC8_NEG(&value.v_dec)) {
            OG_SRC_THROW_ERROR(expr->loc, ERR_INVALID_PART_TYPE, "interval key data", "");
            return OG_ERROR;
        }
    } else {
        if (!OG_IS_DSITVL_TYPE(value.type) && !OG_IS_YMITVL_TYPE(value.type)) {
            OG_SRC_THROW_ERROR(expr->loc, ERR_INVALID_PART_TYPE, "interval key data", "");
            return OG_ERROR;
        }
        OG_RETURN_IFERR(sql_part_put_key(stmt, &value, value.type, knl_col->size, KNL_COLUMN_IS_CHARACTER(knl_col),
            knl_col->precision, knl_col->scale, partkey));
    }
    def->part_def.part_interval.binterval.bytes = (uint8 *)partkey;
    def->part_def.part_interval.binterval.size = partkey->size;
    return lex_expected_end(lex);
}

static status_t sql_parse_altable_set_interval_part(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_dictionary_t *dc,
    knl_altable_def_t *def)
{
    uint16 col_id;
    knl_column_t *knl_col = NULL;

#ifdef Z_SHARDING
    if ((IS_COORDINATOR || IS_DATANODE) && def->action == ALTABLE_SET_INTERVAL_PART) {
        OG_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "alter table set interval");
        return OG_ERROR;
    }
#endif

    if (knl_part_key_count(dc->handle) > 1) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "only support one interval partition column");
        return OG_ERROR;
    }

    col_id = knl_part_key_column_id(dc->handle, 0);
    knl_col = knl_get_column(dc->handle, col_id);
    if (!OG_IS_NUMERIC_TYPE(knl_col->datatype) && !OG_IS_DATETIME_TYPE(knl_col->datatype)) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid interval partition column data type");
        return OG_ERROR;
    }

    OG_RETURN_IFERR(lex_push(lex, &word->text));
    status_t status = sql_parse_altable_set_interval_part_core(stmt, lex, word, def, knl_col);
    lex_pop(lex);
    return status;
}

status_t sql_parse_altable_set_clause(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def)
{
    status_t status = OG_ERROR;
    knl_dictionary_t dc;

    def->action = ALTABLE_SET_INTERVAL_PART;

    if (knl_open_dc(KNL_SESSION(stmt), (text_t *)&def->user, (text_t *)&def->name, &dc) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
        return OG_ERROR;
    }

    do {
        if (!knl_is_part_table(dc.handle)) {
            OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
            break;
        }
        OG_BREAK_IF_ERROR(lex_expected_fetch_word(lex, "INTERVAL"));
        OG_BREAK_IF_ERROR(lex_expected_fetch_bracket(lex, word));
        if (word->text.len == 0) {
            OG_BREAK_IF_ERROR(sql_parse_altable_set_range_part(&dc));
        } else {
            OG_BREAK_IF_ERROR(sql_parse_altable_set_interval_part(stmt, lex, word, &dc, def));
        }
        status = lex_expected_end(lex);
    } while (OG_FALSE);

    knl_close_dc(&dc);
    return status;
}

status_t sql_parse_altable_partition(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def)
{
    uint32 i;
    knl_part_def_t *part_def = NULL;
    knl_part_def_t *parts_def = NULL;
    lex_t *lex = stmt->session->lex;
    uint32 flag = lex->flags;

    def->logical_log_def.is_parts_logical = OG_TRUE;
    lex->flags = LEX_SINGLE_WORD;
    for (;;) {
        if (lex_expected_fetch_variant(lex, word) != OG_SUCCESS) {
            cm_reset_error();
            OG_SRC_THROW_ERROR(word->text.loc, ERR_INVALID_PART_NAME);
            return OG_ERROR;
        }

        OG_RETURN_IFERR(cm_galist_new(&def->logical_log_def.parts, sizeof(knl_part_def_t), (pointer_t *)&part_def));
        OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word->type, (text_t *)&word->text, &part_def->name));

        for (i = 0; i < def->logical_log_def.parts.count - 1; i++) {
            parts_def = (knl_part_def_t *)cm_galist_get(&def->logical_log_def.parts, i);
            if (cm_text_equal(&part_def->name, &parts_def->name)) {
                OG_THROW_ERROR(ERR_DUPLICATE_NAME, "partition", T2S(&parts_def->name));
                return OG_ERROR;
            }
        }

        if (lex_fetch(lex, word) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (word->type == WORD_TYPE_EOF) {
            break;
        }
        if (!IS_SPEC_CHAR(word, ',')) {
            OG_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, ", expected but %s found", W2S(word));
            return OG_ERROR;
        }
    }

    lex->flags = flag;
    return OG_SUCCESS;
}

static status_t sql_parse_add_subpartitions(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_dictionary_t *dc,
    knl_altable_def_t *def)
{
    knl_column_t *column = NULL;
    knl_part_column_def_t *subpart_column = NULL;
    knl_part_obj_def_t *obj_def = def->part_def.obj_def;
    knl_part_def_t *parent_def = cm_galist_get(&def->part_def.obj_def->parts, 0);

    def->part_def.obj_def->subpart_type = knl_subpart_table_type(dc->handle);
    cm_galist_init(&obj_def->subpart_keys, stmt->context, sql_alloc_mem);
    parent_def->is_parent = OG_TRUE;

    for (uint16 i = 0; i < knl_subpart_key_count(dc->handle); i++) {
        OG_RETURN_IFERR(cm_galist_new(&obj_def->subpart_keys, sizeof(knl_part_column_def_t), (void **)&subpart_column));
        subpart_column->column_id = knl_subpart_key_column_id(dc->handle, i);
        column = knl_get_column(dc->handle, subpart_column->column_id);
        subpart_column->datatype = column->datatype;
        subpart_column->is_char = KNL_COLUMN_IS_CHARACTER(column);
        subpart_column->precision = column->precision;
        subpart_column->scale = column->scale;
        subpart_column->size = column->size;
    }

    cm_galist_init(&parent_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&parent_def->group_subkeys, stmt->context, sql_alloc_mem);

    if (word->type == WORD_TYPE_BRACKET) {
        OG_RETURN_IFERR(lex_push(lex, &word->text));
        OG_RETURN_IFERR(sql_part_parse_subpartitions(stmt, word, obj_def, parent_def));
        lex_pop(lex);
    } else {
        /* generate default subpartition for parent part */
        OG_RETURN_IFERR(sql_generate_default_subpart(stmt, obj_def, &parent_def->subparts));
    }

    return OG_SUCCESS;
}

static status_t sql_add_partition_parse_partkeys(knl_part_obj_def_t *obj_def, knl_dictionary_t *dc)
{
    knl_column_t *knl_column = NULL;
    knl_part_column_def_t *part_col = NULL;

    for (uint16 i = 0; i < knl_part_key_count(dc->handle); i++) {
        if (cm_galist_new(&obj_def->part_keys, sizeof(knl_part_column_def_t), (pointer_t *)&part_col) !=
            OG_SUCCESS) {
            return OG_ERROR;
        }
        part_col->column_id = knl_part_key_column_id(dc->handle, i);
        knl_column = knl_get_column(dc->handle, part_col->column_id);
        part_col->datatype = knl_column->datatype;
        part_col->size = knl_column->size;
        part_col->precision = knl_column->precision;
        part_col->scale = knl_column->scale;
        part_col->is_char = KNL_COLUMN_IS_CHARACTER(knl_column);
    }

    return OG_SUCCESS;
}

status_t sql_parse_add_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def)
{
    word_t word;
    knl_dictionary_t dc;
    knl_part_def_t *part_def = NULL;
    knl_handle_t knl = &stmt->session->knl_session;

    def->action = ALTABLE_ADD_PARTITION;

    if (knl_open_dc(knl, (text_t *)&def->user, (text_t *)&def->name, &dc) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
        return OG_ERROR;
    }

    if (!knl_is_part_table(dc.handle)) {
        knl_close_dc(&dc);
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (pointer_t *)&def->part_def.obj_def) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    def->part_def.obj_def->part_type = knl_part_table_type(dc.handle);

    cm_galist_init(&def->part_def.obj_def->part_keys, stmt->context, sql_alloc_mem);
    cm_galist_init(&def->part_def.obj_def->group_keys, stmt->context, sql_alloc_mem);

    if (sql_add_partition_parse_partkeys(def->part_def.obj_def, &dc) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    lex->flags |= LEX_WITH_ARG;
    cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
    if (cm_galist_new(&def->part_def.obj_def->parts, sizeof(knl_part_def_t), (void **)&part_def) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    def->part_def.obj_def->is_composite = (bool32)knl_is_compart_table(dc.handle);
    if (sql_part_parse_partition(stmt, &word, def->part_def.obj_def, part_def) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    if (def->part_def.obj_def->is_composite) {
        if (sql_parse_add_subpartitions(stmt, lex, &word, &dc, def) != OG_SUCCESS) {
            knl_close_dc(&dc);
            return OG_ERROR;
        }
    }

    knl_close_dc(&dc);
    if ((word.type != WORD_TYPE_EOF) && (word.id != RES_WORD_DEFAULT)) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(&word));
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static status_t sql_parse_modify_partition_storage(sql_stmt_t *stmt, lex_t *lex, word_t *word,
    knl_altable_def_t *tab_def)
{
    tab_def->action = ALTABLE_MODIFY_PART_STORAGE;
    OG_RETURN_IFERR(sql_parse_storage(lex, word, &tab_def->part_def.storage_def, OG_TRUE));

    return OG_SUCCESS;
}

static status_t sql_parse_modify_partition_initrans(sql_stmt_t *stmt, lex_t *lex, word_t *word,
    knl_altable_def_t *tab_def)
{
    tab_def->action = ALTABLE_MODIFY_PART_INITRANS;
    OG_RETURN_IFERR(sql_parse_trans(lex, word, &tab_def->part_def.part_prop.initrans));
    return lex_fetch(lex, word);
}

static status_t sql_parse_add_subpartition(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def)
{
    knl_dictionary_t dc;

    def->action = ALTABLE_ADD_SUBPARTITION;

    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SUBPARTITION"));
    if (knl_open_dc(&stmt->session->knl_session, &def->user, &def->name, &dc) != OG_SUCCESS) {
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not find", T2S(&def->name));
        return OG_ERROR;
    }

    if (!knl_is_part_table(dc.handle) || !knl_is_compart_table(dc.handle)) {
        knl_close_dc(&dc);
        OG_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not composite partition table", T2S(&def->name));
        return OG_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(knl_part_obj_def_t), (void **)&def->part_def.obj_def) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    def->part_def.obj_def->subpart_type = knl_subpart_table_type(dc.handle);
    def->part_def.obj_def->is_composite = OG_TRUE;
    cm_galist_init(&def->part_def.obj_def->subpart_keys, stmt->context, sql_alloc_mem);

    knl_column_t *column = NULL;
    knl_part_column_def_t *part_col = NULL;
    for (uint16 i = 0; i < knl_subpart_key_count(dc.handle); i++) {
        if (cm_galist_new(&def->part_def.obj_def->subpart_keys, sizeof(knl_part_column_def_t), (void **)&part_col) !=
            OG_SUCCESS) {
            knl_close_dc(&dc);
            return OG_ERROR;
        }
        part_col->column_id = knl_subpart_key_column_id(dc.handle, i);
        column = knl_get_column(dc.handle, part_col->column_id);
        part_col->datatype = column->datatype;
        part_col->size = column->size;
        part_col->precision = column->precision;
        part_col->scale = column->scale;
        part_col->is_char = KNL_COLUMN_IS_CHARACTER(column);
    }

    knl_part_def_t *part_def = NULL;
    lex->flags |= LEX_WITH_ARG;
    cm_galist_init(&def->part_def.obj_def->parts, stmt->context, sql_alloc_mem);
    cm_galist_new(&def->part_def.obj_def->parts, sizeof(knl_part_def_t), (void **)&part_def);
    cm_galist_init(&part_def->subparts, stmt->context, sql_alloc_mem);
    cm_galist_init(&part_def->group_subkeys, stmt->context, sql_alloc_mem);
    if (sql_part_parse_subpartition(stmt, word, def->part_def.obj_def, part_def) != OG_SUCCESS) {
        knl_close_dc(&dc);
        return OG_ERROR;
    }

    knl_close_dc(&dc);
    return OG_SUCCESS;
}

static status_t sql_parse_coalesce_subpartition(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def)
{
    def->action = ALTABLE_COALESCE_SUBPARTITION;
    OG_RETURN_IFERR(lex_expected_fetch_word(lex, "SUBPARTITION"));
    return lex_fetch(lex, word);
}

status_t sql_parse_modify_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def)
{
    status_t status;
    word_t word;

    if (lex_expected_fetch_variant(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    OG_RETURN_IFERR(sql_copy_object_name(stmt->context, word.type, (text_t *)&word.text, &tab_def->part_def.name));

    if (lex_fetch(lex, &word) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type != WORD_TYPE_KEYWORD) {
        OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
        return OG_ERROR;
    }

    switch (word.id) {
        case KEY_WORD_STORAGE:
            status = sql_parse_modify_partition_storage(stmt, lex, &word, tab_def);
            break;
        case KEY_WORD_INITRANS:
            status = sql_parse_modify_partition_initrans(stmt, lex, &word, tab_def);
            break;
        case KEY_WORD_ADD:
            status = sql_parse_add_subpartition(stmt, lex, &word, tab_def);
            break;
        case KEY_WORD_COALESCE:
            status = sql_parse_coalesce_subpartition(stmt, lex, &word, tab_def);
            break;
        default:
            OG_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "unexpected word %s found.", W2S(&word));
            status = OG_ERROR;
            break;
    }

    if (status != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (word.type != WORD_TYPE_EOF) {
        OG_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "expected end but %s found", W2S(&word));
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

status_t sql_parse_purge_partition(sql_stmt_t *stmt, knl_purge_def_t *def)
{
    word_t word;
    lex_t *lex = stmt->session->lex;
    status_t status;

    lex->flags = LEX_WITH_OWNER;
    stmt->context->entry = def;

    status = lex_expected_fetch_string(lex, &word);
    OG_RETURN_IFERR(status);

    status = sql_convert_object_name(stmt, &word, &def->owner, NULL, &def->name);
    OG_RETURN_IFERR(status);

    def->type = PURGE_PART_OBJECT;

    return lex_expected_end(lex);
}

// verify part attr after column datatype get from  'as select' clause
status_t sql_delay_verify_part_attrs(sql_stmt_t *stmt, knl_table_def_t *def, bool32 *expect_as, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    part_key_t *interval_key = NULL;
    knl_part_obj_def_t *part_def = def->part_def;

    if (part_def == NULL || part_def->delay_partition == OG_FALSE) {
        return OG_SUCCESS;
    }

    bool32 is_composite_old = part_def->is_composite;
    OG_RETURN_IFERR(lex_push(lex, &part_def->save_key));
    part_def->is_composite = OG_FALSE;
    if (sql_part_parse_keys(stmt, word, expect_as, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);
    if (part_def->is_interval) {
        interval_key = (part_key_t *)part_def->binterval.bytes;
        OG_RETURN_IFERR(lex_push(lex, &part_def->save_interval_part)); // &def->part_def->interval
        if (sql_parse_interval_key(stmt, word, interval_key, part_def) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
        part_def->binterval.size = interval_key->size;
    }

    part_def->is_composite = is_composite_old;
    if (part_def->is_composite) {
        OG_RETURN_IFERR(lex_push(lex, &part_def->save_subkey));
        if (sql_part_parse_keys(stmt, word, expect_as, def) != OG_SUCCESS) {
            lex_pop(lex);
            return OG_ERROR;
        }
        lex_pop(lex);
    }

    /* in case of store in, it's no need to parse partitions */
    if (part_def->part_store_in.is_store_in) {
        return OG_SUCCESS;
    }

    OG_RETURN_IFERR(lex_push(lex, &part_def->save_part));
    if (sql_part_parse_partitions(stmt, word, def) != OG_SUCCESS) {
        lex_pop(lex);
        return OG_ERROR;
    }
    lex_pop(lex);

    return OG_SUCCESS;
}
