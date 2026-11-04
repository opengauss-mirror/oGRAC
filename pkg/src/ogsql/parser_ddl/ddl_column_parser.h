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
 * ddl_column_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_column_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_COLUMN_PARSER_H__
#define __DDL_COLUMN_PARSER_H__

#include "cm_defs.h"
#include "ogsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif
#define COLUMN_EX_NULLABLE 0x00000001
#define COLUMN_EX_KEY 0x00000002
#define COLUMN_EX_DEFAULT 0x00000004
#define COLUMN_EX_REF 0x00000008
#define COLUMN_EX_INL_CONSTR 0x00000010
#define COLUMN_EX_CHECK 0x00000020
#define COLUMN_EX_COMMENT 0x00000040
#define COLUMN_EX_UPDATE_DEFAULT 0x00000080
#define COLUMN_EX_AUTO_INCREMENT 0x00000100
#define COLUMN_EX_COLLATE 0x00000200
#define ALTAB_AUTO_INCREMENT_COLUMN 0x00000001

#define IS_CONSTRAINT_KEYWORD(id)                                                                                      \
    ((id) == KEY_WORD_CONSTRAINT || (id) == KEY_WORD_PRIMARY || (id) == KEY_WORD_UNIQUE || (id) == KEY_WORD_FOREIGN || \
        (id) == KEY_WORD_CHECK || (id) == KEY_WORD_PARTITION || (id) == KEY_WORD_LOGICAL)

#ifdef OG_RAC_ING
#define SHARDING_NOT_SUPPORT_ERROR(loc, error_no, err_msg)       \
    do {                                                         \
        if (IS_COORDINATOR) {                                    \
            OG_SRC_THROW_ERROR_EX((loc), (error_no), (err_msg)); \
            return OG_ERROR;                                     \
        }                                                        \
    } while (0)
#endif

#ifdef OG_RAC_ING
#define SHARDING_NOT_SUPPORT_ERROR_EX(loc, error_no, err_msg, text)      \
    do {                                                                 \
        if (IS_COORDINATOR) {                                            \
            OG_SRC_THROW_ERROR_EX((loc), (error_no), (err_msg), (text)); \
            return OG_ERROR;                                             \
        }                                                                \
    } while (0)
#endif

typedef enum en_add_column_type {
    CREATE_TABLE_ADD_COLUMN = 0,
    ALTER_TABLE_ADD_COLUMN = 1,
} def_column_action_t;

typedef enum {
    CONS_STATE_ENABLE = 0,
    CONS_STATE_DISABLE,
    CONS_STATE_NOT_DEFEREABLE,
    CONS_STATE_DEFEREABLE,
    CONS_STATE_INITIALLY_IMMEDIATE,
    CONS_STATE_INITIALLY_DEFERRED,
    CONS_STATE_RELY,
    CONS_STATE_NO_RELY,
    CONS_STATE_VALIDATE,
    CONS_STATE_NO_VALIDATE,
    CONS_STATE_USING_INDEX,
    CONS_STATE_PARALLEL,
    CONS_STATE_REVERSE
} constraint_state_type;

typedef struct {
    constraint_state_type type;
    union {
        uint32 parallelism;
        galist_t *index_opts;
    };
} constraint_state;

typedef struct {
    constraint_type_t type;
    char *name;
    union {
        struct {
            galist_t *state_opts;
            galist_t *column_list;
        };
        struct {
            galist_t *cols;
            name_with_owner *ref;
            galist_t *ref_cols;
            knl_refactor_t refactor;
        };
        struct {
            text_t check_text;
            cond_tree_t *cond;
        };
    };
} parse_constraint_t;

typedef enum {
    COL_ATTR_DEFAULT,
    COL_ATTR_COMMENT,
    COL_ATTR_AUTO_INCREMENT,
    COL_ATTR_COLLATE,
    COL_ATTR_PRIMARY,
    COL_ATTR_UNIQUE,
    COL_ATTR_REFERENCES,
    COL_ATTR_CHECK,
    COL_ATTR_NOT_NULL,
    COL_ATTR_NULL
} column_attr_type;

typedef struct {
    column_attr_type type;
    char *cons_name;
    union {
        struct {
            text_t default_text;
            expr_tree_t *insert_expr;
            expr_tree_t *update_expr;
        };
        char *comment;
        char *collate;
        struct {
            name_with_owner *ref;
            galist_t *ref_cols;
            knl_refactor_t refactor;
        };
        struct {
            text_t check_text;
            cond_tree_t *cond;
        };
    };
} column_attr_t;

typedef struct {
    char *col_name;
    source_location_t loc;
    bool32 has_datatype;
    type_word_t *type;
    galist_t *column_attrs;
} parse_column_t;

typedef struct {
    bool32 is_constraint;
    union {
        parse_constraint_t *cons;
        parse_column_t *col;
    };
} parse_table_element_t;

status_t sql_parse_lob_store(sql_stmt_t *stmt, lex_t *lex, word_t *word, galist_t *defs);
status_t sql_parse_modify_lob(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def);
status_t sql_parse_charset(sql_stmt_t *stmt, lex_t *lex, uint8 *charset);
status_t sql_parse_collate(sql_stmt_t *stmt, lex_t *lex, uint8 *collate);

status_t sql_verify_columns(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_column_default_expr(sql_verifier_t *verf, expr_tree_t *cast_expr, knl_column_def_t *def);
status_t sql_verify_auto_increment(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_verify_array_columns(table_type_t type, galist_t *columns);
status_t sql_verify_cons_def(knl_table_def_t *def);
status_t sql_check_duplicate_column(galist_t *columns, const text_t *name);
status_t sql_create_inline_cons(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_column_property(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def, uint32 *flags);
status_t sql_delay_verify_default(sql_stmt_t *stmt, knl_table_def_t *def);
status_t sql_parse_altable_add_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed, knl_altable_def_t *def);
status_t sql_parse_altable_modify_brackets_recurse(sql_stmt_t *stmt, lex_t *lex, bool32 enclosed,
    knl_altable_def_t *def);
status_t sql_parse_altable_column_rename(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_column_defs(sql_stmt_t *stmt, lex_t *lex, knl_table_def_t *def, bool32 *expect_as);
status_t sql_check_duplicate_column_name(galist_t *columns, const text_t *name);
status_t og_parse_column_defs(sql_stmt_t *stmt, knl_table_def_t *def, bool32 *expect_as, galist_t *table_elements);
status_t og_verify_create_table_columns(sql_stmt_t *stmt, knl_table_def_t *def, galist_t *table_elements);

#ifdef __cplusplus
}
#endif

#endif
