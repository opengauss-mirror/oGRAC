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
 * keywords.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/parser/keywords.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef KEYWORDS_H
#define KEYWORDS_H

/* Keyword categories --- should match lists in gram.y */
#define UNRESERVED_KEYWORD 0
#define COL_NAME_KEYWORD 1
#define RESERVED_KEYWORD 2

#include "kwlookup.h"
typedef struct PlpgsqlKeywordValue {
    int16 procedure;
    int16 function;
    int16 begin;
    int16 select;
    int16 update;
    int16 insert;
    int16 Delete;
    int16 merge;
} PlpgsqlKeywordValue;

extern const ScanKeywordList ScanKeywords;
extern const uint8 ScanKeywordCategories[];
extern const bool8 ScanKeywordDirectLabel[];

/* Globals from keywords.c */
extern const ScanKeywordList SQLScanKeywords[];

#endif /* KEYWORDS_H */
