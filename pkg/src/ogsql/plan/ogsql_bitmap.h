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
 * ogsql_bitmap.h
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/ogsql_bitmap.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OGSQL_BITMAP_H__
#define __OGSQL_BITMAP_H__

#include "cm_defs.h"
#include "cm_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BITMAP_WORD_SIZE (sizeof(uint32) * 8)
#define BITMAP_WORD_COUNT (OG_MAX_JOIN_JTABLES / BITMAP_WORD_SIZE)
#define BITMAP_RIGHTMOST_ONE(w) ((int32)(w) & -((int32)(w)))
#define BITMAP_HAS_MULTI(w) ((uint32)BITMAP_RIGHTMOST_ONE(w)!= (w))

typedef struct st_join_tbl_bitmap {
    uint32 words[BITMAP_WORD_COUNT];
} join_tbl_bitmap_t;

void sql_bitmap_init(join_tbl_bitmap_t *result);
void sql_bitmap_setbit(uint32 id, join_tbl_bitmap_t* bms);
void sql_bitmap_make_singleton(uint32 table_id, join_tbl_bitmap_t* tables_bms);
void sql_bitmap_copy(join_tbl_bitmap_t *a, join_tbl_bitmap_t *result);
void sql_bitmap_union_singleton(uint32 a, uint32 b, join_tbl_bitmap_t* result);
void sql_bitmap_union(join_tbl_bitmap_t *a, join_tbl_bitmap_t *b, join_tbl_bitmap_t* result);
bool8 sql_bitmap_overlap(join_tbl_bitmap_t* a, join_tbl_bitmap_t* b);
bool8 sql_bitmap_empty(const join_tbl_bitmap_t* a);
bool8 sql_bitmap_subset(const join_tbl_bitmap_t* a, const join_tbl_bitmap_t* b);
bool8 sql_bitmap_same(const join_tbl_bitmap_t* a, const join_tbl_bitmap_t* b);
uint32 sql_hash_bitmap(join_tbl_bitmap_t* bms);
bool32 sql_oamap_bitmap_compare(void *key1, void *key2);
void sql_bitmap_add_member(uint32 id, join_tbl_bitmap_t* bms);
void sql_bitmap_delete_member(uint32 id, join_tbl_bitmap_t* bms);
void sql_bitmap_delete_members(join_tbl_bitmap_t* a, join_tbl_bitmap_t* b);
void sql_bitmap_intersect(join_tbl_bitmap_t *a, join_tbl_bitmap_t *b, join_tbl_bitmap_t* result);
bool32 sql_bitmap_exist_member(uint32 id, join_tbl_bitmap_t* bms);
int sql_bitmap_next_member(join_tbl_bitmap_t* bms, uint32 id_from_and_include);
bool8 sql_bitmap_is_multi(const join_tbl_bitmap_t* a);
uint32 sql_bitmap_number_count(join_tbl_bitmap_t *bms);
bool32 sql_bitmap_same_as_any(join_tbl_bitmap_t *table_ids, galist_t *table_ids_list);

#define BITMAP_FOREACH(i, bms_ptr) \
    for ((i) = sql_bitmap_next_member((bms_ptr), 0); \
         (i) < OG_MAX_JOIN_TABLES; \
         (i) = sql_bitmap_next_member((bms_ptr), (i) + 1))

#ifdef __cplusplus
}
#endif

#endif
