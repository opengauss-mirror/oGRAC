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
 * cm_context_pool.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_context_pool.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_hash.h"
#include "cm_context_pool.h"

status_t ogx_pool_create(context_pool_profile_t *profile, context_pool_t **pool)
{
    uint32 pool_size = OFFSET_OF(context_pool_t, buckets) + profile->bucket_count * sizeof(context_bucket_t);
    pool_size = CM_ALIGN8(pool_size);

    uint32 map_size = OFFSET_OF(context_map_t, items) + profile->optimize_pages * sizeof(uint32);
    map_size = CM_ALIGN8(map_size);

    uint32 total_size = pool_size + sizeof(memory_pool_t) + map_size + OG_LRU_LIST_CNT * sizeof(lru_list_t);
    total_size = CM_ALIGN8(total_size);
    context_pool_t *ogx_pool = (context_pool_t *)malloc(total_size);
    if (ogx_pool == NULL) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)total_size, profile->name);
        return OG_ERROR;
    }
    errno_t rc_memzero = memset_sp(ogx_pool, (size_t)total_size, 0, (size_t)total_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(ogx_pool);
        OG_THROW_ERROR(ERR_RESET_MEMORY, "ogx_pool");
        return OG_ERROR;
    }

    /* initialize ogx_pool memory object */
    ogx_pool->memory = (memory_pool_t *)((char*)ogx_pool + pool_size);

    /* initialize ogx_pool ogx_map */
    ogx_pool->map = (context_map_t *)((char*)ogx_pool + pool_size + sizeof(memory_pool_t));
    ogx_pool->map->map_size = profile->optimize_pages;
    ogx_pool->map->free_items.first = OG_INVALID_ID32;

    /* initialize ogx_pool lru_list */
    ogx_pool->lru_list = (lru_list_t *)((char*)ogx_pool + pool_size + sizeof(memory_pool_t) + map_size);
    ogx_pool->lru_list_cnt = OG_LRU_LIST_CNT;

    if (mpool_create(profile->area, profile->name,
                     profile->init_pages, profile->optimize_pages, ogx_pool->memory) != OG_SUCCESS) {
        CM_FREE_PTR(ogx_pool);
        return OG_ERROR;
    }

    *pool = ogx_pool;
    ogx_pool->context_size = profile->context_size;
    ogx_pool->bucket_count = profile->bucket_count;
    ogx_pool->clean = profile->clean;
    ogx_pool->memory->mem_alloc.ogx = ogx_pool;
    ogx_pool->memory->mem_alloc.mem_func = (mem_func_t)sql_ctx_alloc_mem;
    return OG_SUCCESS;
}

// context pool's life cycle is same with the instance
void ogx_pool_destroy(context_pool_t *pool)
{
    CM_FREE_PTR(pool);
}

static void ogx_lru_add(lru_list_t *lru_list, context_ctrl_t *ctrl)
{
    if (lru_list->lru_head == NULL) {
        lru_list->lru_head = ctrl;
        lru_list->lru_tail = ctrl;
        ctrl->lru_prev = NULL;
        ctrl->lru_next = NULL;
    } else {
        ctrl->lru_next = lru_list->lru_head;
        ctrl->lru_prev = NULL;
        lru_list->lru_head->lru_prev = ctrl;
        lru_list->lru_head = ctrl;
    }

    lru_list->lru_count++;
}

static inline void ogx_lru_remove(lru_list_t *lru_list, context_ctrl_t *ctrl)
{
    /* remove from context LRU queue */
    if (lru_list->lru_head == ctrl) {
        lru_list->lru_head = ctrl->lru_next;
    }

    if (lru_list->lru_tail == ctrl) {
        lru_list->lru_tail = ctrl->lru_prev;
    }

    if (ctrl->lru_prev != NULL) {
        ctrl->lru_prev->lru_next = ctrl->lru_next;
    }

    if (ctrl->lru_next != NULL) {
        ctrl->lru_next->lru_prev = ctrl->lru_prev;
    }
    ctrl->lru_prev = NULL;
    ctrl->lru_next = NULL;
    lru_list->lru_count--;
}

static inline void ogx_bucket_remove(context_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->bucket->enque_lock, NULL);

    /* remove from context hash pageex */
    if (ctrl->hash_prev != NULL) {
        ctrl->hash_prev->hash_next = ctrl->hash_next;
    }

    if (ctrl->hash_next != NULL) {
        ctrl->hash_next->hash_prev = ctrl->hash_prev;
    }

    if (ctrl == ctrl->bucket->first) {
        ctrl->bucket->first = ctrl->hash_next;
    }
    ctrl->hash_next = NULL;
    ctrl->hash_prev = NULL;
    cm_spin_unlock(&ctrl->bucket->enque_lock);
}

void ogx_bucket_insert(context_bucket_t *bucket, context_ctrl_t *ctrl)
{
    cm_spin_lock(&bucket->enque_lock, NULL);
    HASH_BUCKET_INSERT(bucket, ctrl);
    cm_spin_unlock(&bucket->enque_lock);
}

static void ogx_map_remove(context_pool_t *pool, context_ctrl_t *ctrl)
{
    if (ctrl->map_id == OG_INVALID_ID32) {
        return;
    }

    pool->map->items[ctrl->map_id] = pool->map->free_items.first;
    pool->map->free_items.first = (0x80000000 | ctrl->map_id);
    pool->map->free_items.count++;
}

static void ogx_map_add(context_pool_t *pool, context_ctrl_t *ctrl)
{
    uint32 id = OG_INVALID_ID32;

    if (pool->map->free_items.count > 0) {
        id = pool->map->free_items.first & 0x7FFFFFFF;
        pool->map->free_items.count--;
        pool->map->free_items.first = pool->map->items[id];
    } else if (pool->map->hwm < pool->map->map_size) {
        id = pool->map->hwm;
        pool->map->hwm++;
    }

    ctrl->map_id = id;

    if (id != OG_INVALID_ID32) {
        pool->map->items[id] = ctrl->memory->pages.first;
    }
}

void ogx_insert(context_pool_t *pool, context_ctrl_t *ctrl)
{
    lru_list_t *lru_list = &pool->lru_list[ctrl->hash_value % pool->lru_list_cnt];
    cm_spin_lock(&lru_list->lock, NULL);
    ogx_lru_add(lru_list, ctrl);
    cm_spin_unlock(&lru_list->lock);

#ifndef TEST_MEM
    cm_spin_lock(&pool->lock, NULL);
    ogx_map_add(pool, ctrl);
    cm_spin_unlock(&pool->lock);
#endif
}

static bool32 ogx_pool_try_remove(context_pool_t *pool, context_ctrl_t *ctrl)
{
    lru_list_t *lru_list = NULL;

    cm_spin_lock(&ctrl->lock, NULL);

    if (ctrl->ref_count > 0) {
        cm_spin_unlock(&ctrl->lock);
        return OG_FALSE;
    }

    ctrl->valid = OG_FALSE;
    pool->clean(ctrl);
    cm_spin_unlock(&ctrl->lock);

    cm_spin_lock(&pool->lock, NULL);
    ogx_map_remove(pool, ctrl);
    cm_spin_unlock(&pool->lock);
    
    lru_list = &pool->lru_list[ctrl->hash_value % pool->lru_list_cnt];
    ogx_lru_remove(lru_list, ctrl);

    return OG_TRUE;
}

static inline void ogx_pool_lru_shift(lru_list_t *lru_list, context_ctrl_t *ctrl)
{
    ogx_lru_remove(lru_list, ctrl);
    ogx_lru_add(lru_list, ctrl);
}

void ogx_pool_lru_move_to_head(context_pool_t *pool, context_ctrl_t *ctrl)
{
    if (mpool_has_remain_page(pool->memory)) {
        return;
    }

    lru_list_t *lru_list = &pool->lru_list[ctrl->hash_value % pool->lru_list_cnt];
    if (lru_list->lru_head == ctrl) {
        return;
    }

    cm_spin_lock(&lru_list->lock, NULL);
    ogx_pool_lru_shift(lru_list, ctrl);
    cm_spin_unlock(&lru_list->lock);
}

static inline void ogx_destroy(context_ctrl_t *ctrl)
{
    if (ctrl->subpool != NULL) {
        ogx_recycle_all_core(ctrl->subpool);
    }
    ogx_bucket_remove(ctrl);
    mctx_destroy(ctrl->memory);
}

static void ogx_recycle_referred_objects(context_pool_t *pool, context_ctrl_t *ctrl)
{
    if (ctrl->subpool != NULL) {
        ogx_recycle_all_core(ctrl->subpool);
    }

    cm_spin_lock(&ctrl->lock, NULL);
    if (!ctrl->valid && ctrl->exec_count == 0) {
        pool->clean(ctrl);
    }
    cm_spin_unlock(&ctrl->lock);
}

void ogx_recycle_all_core(context_pool_t *pool)
{
    context_ctrl_t *ctrl = NULL;
    context_ctrl_t *prev = NULL;
    lru_list_t *lru_list = NULL;

    for (uint32 i = 0; i < pool->lru_list_cnt; i++) {
        lru_list = &pool->lru_list[i];
        cm_spin_lock(&lru_list->lock, NULL);
        ctrl = lru_list->lru_tail;

        while (ctrl != NULL) {
            prev = ctrl->lru_prev;
            if (ogx_pool_try_remove(pool, ctrl)) {
                ogx_destroy(ctrl);
            } else {
                ogx_recycle_referred_objects(pool, ctrl);
            }
            ctrl = prev;
        }
        cm_spin_unlock(&lru_list->lock);
    }
}

bool32 ogx_recycle_internal_core(context_pool_t *pool)
{
    context_ctrl_t *ctrl = NULL;
    context_ctrl_t *head = NULL;
    context_ctrl_t *prev = NULL;
    lru_list_t *lru_list = NULL;
    bool32 removed = OG_FALSE;
    uint32 idx = pool->lru_list_idx++ % pool->lru_list_cnt;

    for (uint32 i = 0 ; i < pool->lru_list_cnt; i++) {
        lru_list = &pool->lru_list[(idx + i) % pool->lru_list_cnt];

        cm_spin_lock(&lru_list->lock, NULL);
        head = lru_list->lru_head;
        ctrl = lru_list->lru_tail;

        while (ctrl != NULL) {
            if (!ctrl->fixed && ogx_pool_try_remove(pool, ctrl)) {
                ogx_destroy(ctrl);
                removed = OG_TRUE;
                break;
            }

            if (ctrl->subpool != NULL && ogx_recycle_internal_core(ctrl->subpool)) {
                removed = OG_TRUE;
                break;
            }

            if (ctrl == head) {
                break;
            }

            prev = ctrl->lru_prev;

            // the ctrl's ref_count > 0
            if (ctrl->valid) {
                // ref_count > 0 and is_valid,  the ctrl is used now
                ogx_pool_lru_shift(lru_list, ctrl);
            }

            ctrl = prev;
        }
        cm_spin_unlock(&lru_list->lock);

        if (removed == OG_TRUE) {
            break;
        }
    }

    return removed;
}

static bool32 ogx_recycle_external(context_pool_t *pool)
{
    if (pool->external_recycle == NULL) {
        return OG_FALSE;
    }

    return pool->external_recycle();
}

static bool32 ogx_recycle(context_pool_t *pool)
{
    if (ogx_recycle_internal_core(pool)) {
        return OG_TRUE;
    }

    if (ogx_recycle_external(pool)) {
        return OG_TRUE;
    }

    OG_THROW_ERROR(ERR_ALLOC_GA_MEMORY, pool->memory->name);
    return OG_FALSE;
}

status_t ogx_alloc_exhausted(context_ctrl_t *ctrl, uint32 size, void **buf, uint32 *buf_size)
{
    while (!mctx_try_alloc_exhausted(ctrl->memory, size, buf, buf_size)) {
        if (!ogx_recycle(ctrl->pool)) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

#ifndef TEST_MEM
status_t ogx_write_text(context_ctrl_t *ctrl, text_t *text)
{
    uint32 buf_size;
    uint32 remain_size;
    uint32 copy_size;
    ctrl->text_size = text->len;
    remain_size = text->len;
    char *piece_str = text->str;
    char *buf = NULL;

    while (remain_size > 0) {
        if (ogx_alloc_exhausted(ctrl, remain_size, (void **)&buf, &buf_size) != OG_SUCCESS) {
            return OG_ERROR;
        }

        if (ctrl->text_addr == NULL) {
            ctrl->text_addr = buf;
        }

        copy_size = buf_size > remain_size ? remain_size : buf_size;
        if (copy_size != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(buf, (size_t)buf_size, piece_str, (size_t)copy_size));
        }
        piece_str += copy_size;
        remain_size -= copy_size;
    }

    return OG_SUCCESS;
}
#else
status_t ogx_write_text(context_ctrl_t *ctrl, text_t *text)
{
    errno_t errcode;
    ctrl->text_size = text->len;
    if (text->len == 0) {
        OG_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, text->len);
        return OG_ERROR;
    }
    ctrl->text_addr = (char *)malloc(text->len + 1);
    if (ctrl->text_addr == NULL) {
        OG_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, text->len);
        return OG_ERROR;
    }

    errcode = memcpy_sp(ctrl->text_addr, text->len + 1, text->str, text->len);
    if (errcode != EOK) {
        CM_FREE_PTR(ctrl->text_addr);
        OG_THROW_ERROR(ERR_RESET_MEMORY, "ctrl->text_addr");
        return OG_ERROR;
    }
    ctrl->text_addr[text->len] = '\0';

    return OG_SUCCESS;
}
#endif  // TEST_MEM

void ogx_reuse(context_pool_t *pool, context_ctrl_t *ctrl)
{
    memory_context_t *mctx = ctrl->memory;

    if (pool->context_size != 0) {
        MEMS_RETVOID_IFERR(memset_sp(ctrl, (size_t)pool->context_size, 0, (size_t)pool->context_size));
    }

    mctx->alloc_pos = sizeof(memory_context_t) + pool->context_size;
    mctx->curr_page_id = mctx->pages.first;
    mctx->curr_page_addr = mpool_page_addr(pool->memory, mctx->curr_page_id);
    ctrl->valid = OG_TRUE;
    ctrl->memory = mctx;
    ctrl->pool = pool;
    ctrl->subpool = NULL;
}

status_t ogx_create_mctx(context_pool_t *pool, memory_context_t **mctx)
{
    while (!mctx_try_create(pool->memory, mctx)) {
        if (!ogx_recycle(pool)) {
            return OG_ERROR;
        }
    }

    return OG_SUCCESS;
}

status_t ogx_create(context_pool_t *pool, context_ctrl_t **ctrl)
{
    memory_context_t *mctx = NULL;
    context_ctrl_t *ogx_ctrl = NULL;

    if (ogx_create_mctx(pool, &mctx) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (mctx_alloc(mctx, pool->context_size, (void **)&ogx_ctrl) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (pool->context_size != 0) {
        MEMS_RETURN_IFERR(memset_sp(ogx_ctrl, (size_t)pool->context_size, 0, (size_t)pool->context_size));
    }

    ogx_ctrl->valid = OG_TRUE;
    ogx_ctrl->memory = mctx;
    ogx_ctrl->pool = pool;
    ogx_ctrl->subpool = NULL;
    *ctrl = ogx_ctrl;
    return OG_SUCCESS;
}

static inline void ogx_ctrl_dec_ref(context_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->ref_count--;
    cm_spin_unlock(&ctrl->lock);
}

#ifndef TEST_MEM
static bool32 ogx_matched(context_pool_t *pool, context_ctrl_t *ctrl, uint32 hash_value, text_t *text, uint32 uid,
                          uint32 remote_conn_type, bool32 is_direct_route)
{
    text_t piece;
    text_t sub_text;
    uint32 remain_size;
    uint32 page_id;
    char *page = NULL;

    /* firstly check: hash value,sql length,valid,etc */
    cm_spin_lock(&ctrl->lock, NULL);
    bool32 cond = (ctrl->hash_value != hash_value || text->len != ctrl->text_size || !ctrl->valid || ctrl->uid != uid ||
                   ctrl->remote_conn_type != remote_conn_type || ctrl->is_direct_route != is_direct_route);
    if (cond) {
        cm_spin_unlock(&ctrl->lock);
        return OG_FALSE;
    }

    ctrl->ref_count++;
    cm_spin_unlock(&ctrl->lock);

    /* secondly check: sql content */
    page_id = ctrl->memory->pages.first;
    remain_size = ctrl->text_size;
    sub_text.str = text->str;

    while (remain_size > 0) {
        page = mpool_page_addr(pool->memory, page_id);

        if (page_id == ctrl->memory->pages.first) {
            piece.str = ctrl->text_addr;
            piece.len = (uint32)(pool->memory->page_size - (ctrl->text_addr - page));
        } else {
            piece.str = page;
            piece.len = pool->memory->page_size;
        }

        piece.len = (piece.len > remain_size) ? remain_size : piece.len;
        sub_text.len = piece.len;

        if (!cm_text_equal(&piece, &sub_text)) {
            ogx_ctrl_dec_ref(ctrl);
            return OG_FALSE;
        }

        sub_text.str += piece.len;
        remain_size -= piece.len;

        if (page_id == ctrl->memory->pages.last) {
            break;
        }

        page_id = MEM_NEXT_PAGE(pool->memory, page_id);
    }

    if (remain_size != 0) {
        ogx_ctrl_dec_ref(ctrl);
        return OG_FALSE;
    }
    
    return OG_TRUE;
}
#else
static bool32 ogx_matched(context_pool_t *pool, context_ctrl_t *ctrl, uint32 hash_value, text_t *text, uint32 uid,
                          uint32 remote_conn_type, bool32 is_direct_route)
{
    /* firstly check: hash value,sql length,valid,etc */
    cm_spin_lock(&ctrl->lock, NULL);
    if (ctrl->hash_value != hash_value
        || text->len != ctrl->text_size || !ctrl->valid
        || ctrl->uid != uid
        || ctrl->remote_conn_type != remote_conn_type
        || ctrl->is_direct_route != is_direct_route) {
        cm_spin_unlock(&ctrl->lock);
        return OG_FALSE;
    }

    ctrl->ref_count++;
    cm_spin_unlock(&ctrl->lock);

    /* secondly check: sql content */
    if (!cm_text_str_equal(text, ctrl->text_addr)) {
        ogx_ctrl_dec_ref(ctrl);
        return OG_FALSE;
    }

    return OG_TRUE;
}
#endif  // TEST_MEM

void *ogx_pool_find(context_pool_t *pool, text_t *text, uint32 hash_value, uint32 uid, uint32 remote_conn_type,
                    bool32 is_direct_route)
{
    context_bucket_t *bucket = NULL;
    context_ctrl_t *ctrl = NULL;

    bucket = &pool->buckets[hash_value % pool->bucket_count];

    cm_spin_lock(&bucket->enque_lock, NULL);
    ctrl = bucket->first;

    while (ctrl != NULL) {
        if (ogx_matched(pool, ctrl, hash_value, text, uid, remote_conn_type, is_direct_route)) {
            cm_spin_unlock(&bucket->enque_lock);
            return ctrl;
        }
        ctrl = ctrl->hash_next;
    }

    cm_spin_unlock(&bucket->enque_lock);
    return ctrl;
}

void ogx_dec_exec(context_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    ctrl->exec_count--;
    CM_ASSERT(ctrl->exec_count >= 0);
    cm_spin_unlock(&ctrl->lock);
}

void ogx_dec_ref(context_pool_t *pool, context_ctrl_t *ctrl)
{
    cm_spin_lock(&ctrl->lock, NULL);
    if (ctrl->ref_count > 1 || ctrl->valid) {
        ctrl->ref_count--;
        cm_spin_unlock(&ctrl->lock);
        return;
    }

    pool->clean(ctrl);
    cm_spin_unlock(&ctrl->lock);

    cm_spin_lock(&pool->lock, NULL);
    ogx_map_remove(pool, ctrl);
    cm_spin_unlock(&pool->lock);

    lru_list_t *lru_list = &pool->lru_list[ctrl->hash_value % pool->lru_list_cnt];
    cm_spin_lock(&lru_list->lock, NULL);
    ogx_lru_remove(lru_list, ctrl);
    cm_spin_unlock(&lru_list->lock);
    ogx_destroy(ctrl);
}

static inline uint32 ogx_get_first_sql_page_id(context_pool_t *pool, context_ctrl_t *ctrl)
{
    uint32 page_id = ctrl->memory->pages.first;
    char *page = NULL;

    /* for dml sql must be saved at first page; for ddl sql may saved at second or other page */
    while (page_id != ctrl->memory->pages.last) {
        page = mpool_page_addr(pool->memory, page_id);
        if (ctrl->text_addr >= page && ctrl->text_addr < (page + pool->memory->page_size)) {
            break;
        }

        page_id = MEM_NEXT_PAGE(pool->memory, page_id);
    }

    return page_id;
}

// for dv_sqlarea/dv_open_cursor/dv_sessions sqltext display
#ifndef TEST_MEM
void ogx_read_first_page_text(context_pool_t *pool, context_ctrl_t *ctrl, text_t *text)
{
    uint32 remain_size;
    uint32 piece_len;
    uint32 page_id;

    page_id = ogx_get_first_sql_page_id(pool, ctrl);
    remain_size = ctrl->text_size;
    piece_len = remain_size;

    if (remain_size > 0) {
        char *page = mpool_page_addr(pool->memory, page_id);

        piece_len = (uint32)(pool->memory->page_size - (ctrl->text_addr - page));
        piece_len = (piece_len > remain_size) ? remain_size : piece_len;
    }

    text->str = ctrl->text_addr;
    text->len = piece_len;
}
#else
void ogx_read_first_page_text(context_pool_t *pool, context_ctrl_t *ctrl, text_t *text)
{
    text->str = ctrl->text_addr;
    text->len = ctrl->text_size;
}
#endif  // TEST_MEM

#ifndef TEST_MEM
status_t ogx_read_text(context_pool_t *pool, context_ctrl_t *ctrl, text_t *text, bool32 is_cut)
{
    char *page = NULL;
    char *piece_str = NULL;
    uint32 remain_size;
    uint32 piece_len;
    uint32 first_page_id;
    uint32 page_id;
    uint32 offset;

    if (text->len <= ctrl->text_size && is_cut == OG_FALSE) {
        OG_THROW_ERROR(ERR_BUFFER_OVERFLOW, ctrl->text_size, text->len);
        return OG_ERROR;
    } else if (text->len <= ctrl->text_size &&
               is_cut == OG_TRUE) {  //  when buffer length is not enough and sql_text needs cut off.
        remain_size = text->len - 1;
    } else {
        remain_size = ctrl->text_size;
    }

    offset = 0;
    first_page_id = ogx_get_first_sql_page_id(pool, ctrl);
    page_id = first_page_id;

    while (remain_size > 0) {
        page = mpool_page_addr(pool->memory, page_id);

        if (page_id == first_page_id) {
            piece_str = ctrl->text_addr;
            piece_len = (uint32)(pool->memory->page_size - (ctrl->text_addr - page));
        } else {
            piece_str = page;
            piece_len = pool->memory->page_size;
        }

        piece_len = (piece_len > remain_size) ? remain_size : piece_len;
        if (piece_len != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(text->str + offset, (size_t)(text->len - offset), piece_str,
                (size_t)piece_len));
        }
        offset += piece_len;
        remain_size -= piece_len;

        if (page_id == ctrl->memory->pages.last) {
            break;
        }

        page_id = MEM_NEXT_PAGE(pool->memory, page_id);
    }

    text->str[offset] = '\0';
    text->len = offset;
    return OG_SUCCESS;
}
#else
status_t ogx_read_text(context_pool_t *pool, context_ctrl_t *ctrl, text_t *text, bool32 is_cut)
{
    text->str = ctrl->text_addr;
    text->len = ctrl->text_size;
    return OG_SUCCESS;
}
#endif

status_t sql_ctx_alloc_mem(context_pool_t *pool, memory_context_t *memory, uint32 size, void **buf)
{
    uint32 align_size = CM_ALIGN8(size);
    if (align_size > memory->pool->page_size) {
        OG_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "context memory");
        return OG_ERROR;
    }

    while (!mctx_try_alloc(memory, size, buf)) {
        if (!ogx_recycle(pool)) {
            return OG_ERROR;
        }
    }

    if (size != 0) {
        MEMS_RETURN_IFERR(memset_sp(*buf, (size_t)size, 0, (size_t)size));
    }
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    test_memory_pool_maps(pool->memory);
#endif  // DEBUG

    return OG_SUCCESS;
}

context_ctrl_t *ogx_get(context_pool_t *pool, uint32 id)
{
    if (pool->map->items[id] >= 0x80000000 || id >= pool->map->hwm) {
        return NULL;
    }

    char *page_addr = mpool_page_addr(pool->memory, pool->map->items[id]);
    return (context_ctrl_t *)(page_addr + sizeof(memory_context_t));
}

/*
 * flush all sql context in shared pool
 */
void ogx_flush_shared_pool(context_pool_t *pool)
{
    /*
     * shouldn't lock pool->lock, otherwise
     * one sql thread may lock bucket->parsing_lock, then pool->lock (context recycle to realloc)
     * flush shared pool thread lock pool->lock, then bucket->parsing_lock
     * A-B B-A deadlock
     */
    for (uint32 i = 0; i < OG_SQL_BUCKETS; i++) {
        context_bucket_t *bucket = &pool->buckets[i];
        context_ctrl_t *ctrl = NULL;
        cm_spin_lock(&bucket->parsing_lock.mutex, NULL);
        cm_spin_lock(&bucket->enque_lock, NULL);

        ctrl = bucket->first;
        while (ctrl != NULL) {
            ctrl->fixed = OG_FALSE;
            ctrl->valid = OG_FALSE;
            ctrl = ctrl->hash_next;
        }

        cm_spin_unlock(&bucket->enque_lock);
        cm_spin_unlock(&bucket->parsing_lock.mutex);
    }
}

uint32 ogx_pool_get_lru_cnt(context_pool_t *pool)
{
    uint32 lru_cnt = 0;

    for (uint32 i = 0; i < pool->lru_list_cnt; i++) {
        lru_cnt += pool->lru_list[i].lru_count;
    }

    return lru_cnt;
}
