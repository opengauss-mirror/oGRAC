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
 * ddl_partition_parser.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser_ddl/ddl_partition_parser.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DDL_PARTITION_PARSER_H__
#define __DDL_PARTITION_PARSER_H__

#include "cm_defs.h"
#include "ogsql_stmt.h"
#include "cm_lex.h"
#include "ddl_parser.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum index_partition_opt_type {
    INDEX_PARTITION_OPT_TABLESPACE,
    INDEX_PARTITION_OPT_INITRANS,
    INDEX_PARTITION_OPT_PCTFREE,
    INDEX_PARTITION_OPT_STORAGE,
    INDEX_PARTITION_OPT_COMPRESS,
    INDEX_PARTITION_OPT_FORMAT
} index_partition_opt_type;

typedef struct index_partition_opt {
    index_partition_opt_type type;
    source_location_t loc;
    union {
        char *name;
        uint32 size;
        knl_storage_def_t *storage_def;
        compress_type_t compress_type;
        bool8 csf;
    };
} index_partition_opt;

typedef struct {
    text_t interval_text;
    expr_tree_t *expr;
    galist_t *tablespaces;
} parser_interval_part;

typedef struct {
    part_type_t part_type;
    galist_t *column_list;
} parser_table_subpart;

typedef struct {
    uint32 num;
    galist_t *tablespaces;
} part_store_in_clause;

typedef struct {
    bool32 is_store_in;
    union {
        part_store_in_clause *subpart_store_in;
        galist_t *subparts;
    };
} subpart_clause_t;

typedef struct {
    char *name;
    text_t hiboundval;
    galist_t *boundaries;
    galist_t *opts;
    char *tablespace; /* for subpart */
    subpart_clause_t *subpart_clause;
} part_item_t;

typedef struct {
    part_type_t part_type;
    galist_t *column_list;

    parser_interval_part *interval; /* for range part */
    parser_table_subpart *subpart;
    part_store_in_clause *part_store_in;
    part_store_in_clause *subpart_store_in;
    galist_t *partitions;
} parser_table_part;

status_t sql_parse_partition_attrs(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *def);
status_t sql_delay_verify_part_attrs(sql_stmt_t *stmt, knl_table_def_t *def, bool32 *expect_as, word_t *word);
status_t sql_parse_altable_set_clause(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_altable_def_t *def);

status_t sql_parse_add_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_modify_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *tab_def);
status_t sql_part_parse_table(sql_stmt_t *stmt, word_t *word, bool32 *expect_as, knl_table_def_t *table_def);
status_t sql_parse_altable_partition(sql_stmt_t *stmt, word_t *word, knl_altable_def_t *def);
status_t sql_parse_split_partition(sql_stmt_t *stmt, lex_t *lex, knl_altable_def_t *def);
status_t sql_parse_purge_partition(sql_stmt_t *stmt, knl_purge_def_t *def);
status_t sql_parse_subpartition_attrs(sql_stmt_t *stmt, lex_t *lex, word_t *word, knl_part_def_t *part_def);
status_t og_parse_partition_attrs(knl_part_def_t *def, galist_t *opts);
status_t og_part_parse_table(sql_stmt_t *stmt, knl_table_def_t *table_def, parser_table_part *partition);

#ifdef __cplusplus
}
#endif

#endif