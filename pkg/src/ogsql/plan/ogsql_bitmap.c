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
 * ogsql_bitmap.c
 *
 *
 * IDENTIFICATION
 * src/ogsql/plan/ogsql_bitmap.c
 *
 * -------------------------------------------------------------------------
 */

#include "ogsql_bitmap.h"

#ifdef __cplusplus
extern "C" {
#endif

void sql_bitmap_init(join_tbl_bitmap_t *result)
{
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        result->words[i] = 0;
    }
}

void sql_bitmap_setbit(uint32 id, join_tbl_bitmap_t* bms)
{
    uint32 wordnum = id / BITMAP_WORD_SIZE;
    uint32 bitnum = id % BITMAP_WORD_SIZE;
    bms->words[wordnum] = (1 << bitnum);
}

void sql_bitmap_make_singleton(uint32 id, join_tbl_bitmap_t* bms)
{
    sql_bitmap_init(bms);

    sql_bitmap_setbit(id, bms);
}

void sql_bitmap_copy(join_tbl_bitmap_t *a, join_tbl_bitmap_t *result)
{
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        result->words[i] = a->words[i];
    }
}

void sql_bitmap_union_singleton(uint32 id1, uint32 id2, join_tbl_bitmap_t* bms)
{
    sql_bitmap_init(bms);

    uint32 wordnum = id1 / BITMAP_WORD_SIZE;
    uint32 bitnum = id1 % BITMAP_WORD_SIZE;
    bms->words[wordnum] |= (1 << bitnum);

    wordnum = id2 / BITMAP_WORD_SIZE;
    bitnum = id2 % BITMAP_WORD_SIZE;
    bms->words[wordnum] |= (1 << bitnum);
}


void sql_bitmap_union(join_tbl_bitmap_t *a, join_tbl_bitmap_t *b, join_tbl_bitmap_t* result)
{
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        result->words[i] = (a->words[i] | b->words[i]);
    }
    return;
}


bool8 sql_bitmap_overlap(join_tbl_bitmap_t* a, join_tbl_bitmap_t* b)
{
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        if ((a->words[i] & b->words[i]) != 0) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}


bool8 sql_bitmap_empty(const join_tbl_bitmap_t* a)
{
    if (a == NULL) {
        return OG_TRUE;
    }
    for (int i = 0; i < BITMAP_WORD_COUNT; i++) {
        if (a->words[i] != 0) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

bool8 sql_bitmap_is_multi(const join_tbl_bitmap_t* a)
{
    bool is_singleton = false;
    for (int i = 0; i < BITMAP_WORD_COUNT; i++) {
        uint32 w = a->words[i];
        if (w != 0) {
            if (is_singleton || BITMAP_HAS_MULTI(w)) {
                return OG_TRUE;
            }
            is_singleton = true;
        }
    }
    return OG_FALSE;
}

// return true if a is subset of b
bool8 sql_bitmap_subset(const join_tbl_bitmap_t* a, const join_tbl_bitmap_t* b)
{
    /* Handle cases where either input is NULL */
    if (a == NULL) {
        return OG_TRUE; /* empty set is a subset of anything */
    }

    if (b == NULL) {
        return sql_bitmap_empty(a);
    }

    /* Check common words */
    for (int i = 0; i < BITMAP_WORD_COUNT; i++) {
        if ((a->words[i] & ~b->words[i]) != 0) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}


// return true if a is as asme as b
bool8 sql_bitmap_same(const join_tbl_bitmap_t* a, const join_tbl_bitmap_t* b)
{
    for (int i = 0; i < BITMAP_WORD_COUNT; i++) {
        if (a->words[i] != b->words[i]) {
            return OG_FALSE;
        }
    }
    return OG_TRUE;
}

uint32 sql_hash_bitmap(join_tbl_bitmap_t *a)
{
    if (!a) {
        return 0;
    }
    int lastid = BITMAP_WORD_COUNT;
    for (; --lastid >= 0;) {
        if (a->words[lastid] != 0) {
            break;
        }
    }
    /* all empty sets hash to 0. */
    if (lastid < 0) {
        return 0;
    }
    return cm_hash_bytes((uint8 *)a->words, (lastid + 1) * sizeof(uint32), (uint32)0);
}

bool32 sql_oamap_bitmap_compare(void *a, void *b)
{
    if (!a) {
        return (!b) ? OG_TRUE : sql_bitmap_empty(b);
    } else if (!b) {
        return sql_bitmap_empty(a);
    }

    return sql_bitmap_same(a, b);
}

void sql_bitmap_add_member(uint32 id, join_tbl_bitmap_t* bms)
{
    uint32 wordnum = id / BITMAP_WORD_SIZE;
    uint32 bitnum = id % BITMAP_WORD_SIZE;
    bms->words[wordnum] |= (1 << bitnum);
}

void sql_bitmap_delete_member(uint32 id, join_tbl_bitmap_t* bms)
{
    uint32 wordnum = id / BITMAP_WORD_SIZE;
    uint32 bitnum = id % BITMAP_WORD_SIZE;
    bms->words[wordnum] &= ~((uint32)1 << bitnum);
}

void sql_bitmap_delete_members(join_tbl_bitmap_t* a, join_tbl_bitmap_t* b)
{
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        a->words[i] &= ~b->words[i];
    }
}

void sql_bitmap_intersect(join_tbl_bitmap_t *a, join_tbl_bitmap_t *b, join_tbl_bitmap_t* result)
{
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        result->words[i] = (a->words[i] & b->words[i]);
    }
    return;
}

bool32 sql_bitmap_exist_member(uint32 id, join_tbl_bitmap_t* bms)
{
    uint32 wordnum = id / BITMAP_WORD_SIZE;
    uint32 bitnum = id % BITMAP_WORD_SIZE;
    return bms->words[wordnum] & (1 << bitnum);
}


int sql_bitmap_next_member(join_tbl_bitmap_t* bms, uint32 id_from_and_include)
{
    for (uint32 id = id_from_and_include; id < OG_MAX_JOIN_TABLES; id++) {
        if (sql_bitmap_exist_member(id, bms)) {
            return id;
        }
    }
    return OG_MAX_JOIN_TABLES;
}

uint32 sql_bitmap_number_count(join_tbl_bitmap_t *bms)
{
    uint32 count = 0;
    for (uint32 i = 0; i < BITMAP_WORD_COUNT; i++) {
        uint32 word = bms->words[i];
        while (word) {
            word &= word - 1;
            count++;
        }
    }
    return count;
}

/* true if table_ids is same as any member of table_ids_list */
bool32 sql_bitmap_same_as_any(join_tbl_bitmap_t *table_ids, galist_t *table_ids_list)
{
    for (uint32 i = 0; i < table_ids_list->count; i++) {
        if (sql_bitmap_same(table_ids, (join_tbl_bitmap_t*)cm_galist_get(table_ids_list, i))) {
            return OG_TRUE;
        }
    }
    return OG_FALSE;
}

#ifdef __cplusplus
}
#endif
