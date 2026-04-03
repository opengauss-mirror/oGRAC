/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
 * This file is part of the oGRAC project.
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
 * dtc_global_atomic_lock.h
 *
 * IDENTIFICATION
 * src/cluster/dtc_global_atomic_lock.h
 *
 * -------------------------------------------------------------------------
 */

#include "dtc_global_atomic_lock.h"

static drc_global_lock_pool_header_t *g_lock_pool_headers[OG_MAX_INSTANCES] = { NULL };
static drc_global_lock_bitmap_t *g_lock_pool_bitmaps[OG_MAX_INSTANCES] = { NULL };
static void *g_lock_pool_locks_bases[OG_MAX_INSTANCES] = { NULL };
__thread uint32 drc_g_node_id = 0;

status_t drc_global_lock_pool_init(void *shmem_base_addr, uint32 lock_count, uint8 node_id)
{
    if (!shmem_base_addr) {
        OG_LOG_RUN_ERR("[DRC-LOCK] shmem_base_addr is NULL");
        return OG_ERROR;
    }

    g_lock_pool_headers[node_id] = (drc_global_lock_pool_header_t *)shmem_base_addr;
    uint64 bitmap_size = drc_calc_bitmap_size(lock_count);
    uint64 lock_pool_size = drc_calc_lock_pool_size(lock_count);

    g_lock_pool_bitmaps[node_id] =
        (drc_global_lock_bitmap_t *)((char *)shmem_base_addr + sizeof(drc_global_lock_pool_header_t));
    g_lock_pool_locks_bases[node_id] = (char *)shmem_base_addr + sizeof(drc_global_lock_pool_header_t) + bitmap_size;

    // Initialize header
    drc_global_lock_pool_header_t *header = g_lock_pool_headers[node_id];
    atomic_store(&header->allocated_locks, 0);
    atomic_store(&header->next_free, 0);
    header->total_locks = lock_count;
    header->base_addr = (uint64)(uintptr_t)shmem_base_addr;
    header->lock_pool_size = lock_pool_size;
    header->bitmap_size = bitmap_size;

    // Initialize bitmap
    size_t bitmap_words = (lock_count + 63) / 64;
    drc_global_lock_bitmap_t *bitmap = g_lock_pool_bitmaps[node_id];
    for (size_t i = 0; i < bitmap_words; i++) {
        atomic_store(&bitmap[i], 0);
    }

    drc_g_node_id = node_id;

    OG_LOG_RUN_INF("[DRC-LOCK] Initializing %u atomic locks on node %u (bitmap: %llu bytes, locks: %llu bytes)...",
                   lock_count, node_id, bitmap_size, lock_pool_size);

    // Initialize all locks
    for (uint32 i = 0; i < lock_count; i++) {
        rw_lock_t *lock = (rw_lock_t *)((char *)g_lock_pool_locks_bases[node_id] + (size_t)i * DRC_GLOBAL_LOCK_SIZE);
        errno_t err = memset_s(lock, sizeof(rw_lock_t), 0, sizeof(rw_lock_t));
        knl_securec_check(err);
        atomic_store(&lock->state, 0);
        atomic_store(&lock->owner_node, 0);
        atomic_store(&lock->write_waiters, 0);
    }

    OG_LOG_RUN_INF("[DRC-LOCK] Global atomic lock pool initialized: %u locks, base: %p", lock_count, shmem_base_addr);

    return OG_SUCCESS;
}

status_t drc_global_lock_pool_attach(void *shmem_base_addr, uint8 remote_node_id, uint8 current_node_id)
{
    if (!shmem_base_addr) {
        OG_LOG_RUN_ERR("[DRC-LOCK] shmem_base_addr is NULL");
        return OG_ERROR;
    }

    drc_g_node_id = current_node_id;
    g_lock_pool_headers[remote_node_id] = (drc_global_lock_pool_header_t *)shmem_base_addr;
    drc_global_lock_pool_header_t *header = g_lock_pool_headers[remote_node_id];
    uint64 bitmap_size = header->bitmap_size;
    g_lock_pool_bitmaps[remote_node_id] =
        (drc_global_lock_bitmap_t *)((char *)shmem_base_addr + sizeof(drc_global_lock_pool_header_t));
    g_lock_pool_locks_bases[remote_node_id] = (char *)shmem_base_addr + sizeof(drc_global_lock_pool_header_t) +
                                              bitmap_size;

    OG_LOG_RUN_INF("[DRC-LOCK] Node %u: Attached to node %u global atomic lock pool: %u locks, base: %p",
                   current_node_id, remote_node_id, header->total_locks, shmem_base_addr);

    return OG_SUCCESS;
}

status_t drc_global_lock_alloc(uint8 node_id, uint32 *lock_offset)
{
    if (!g_lock_pool_headers[node_id]) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Lock pool not initialized");
        return OG_ERROR;
    }

    drc_global_lock_pool_header_t *header = g_lock_pool_headers[node_id];
    drc_global_lock_bitmap_t *bitmap = g_lock_pool_bitmaps[node_id];

    uint32 total_locks = header->total_locks;
    uint32 start_index = atomic_load(&header->next_free);
    uint32 index = start_index;

    do {
        uint32 word_idx = index / 64;
        uint32 bit_idx = index % 64;
        uint64 bit_mask = (uint64)1 << bit_idx;
        uint64 old_word = atomic_load(&bitmap[word_idx]);
        // Check if bit is free
        if ((old_word & bit_mask) == 0) {
            uint64 new_word = old_word | bit_mask;

            // Try to claim it
            if (atomic_compare_exchange_strong(&bitmap[word_idx], &old_word, new_word)) {
                atomic_fetch_add(&header->allocated_locks, 1);

                uint32 next_hint = (index + 1) % total_locks;
                atomic_store(&header->next_free, next_hint);

                *lock_offset = (uint32)(sizeof(drc_global_lock_pool_header_t) + header->bitmap_size +
                                        index * DRC_GLOBAL_LOCK_SIZE);

                OG_LOG_DEBUG_INF("[DRC-LOCK] Allocated lock from pool %u at index %u, offset: %u", node_id, index,
                                 *lock_offset);

                return OG_SUCCESS;
            }
        }
        // Move to next lock
        index = (index + 1) % total_locks;
    } while (index != start_index);

    uint32 allocated = atomic_load(&header->allocated_locks);
    OG_LOG_RUN_ERR("[DRC-LOCK] No free locks in pool %u (allocated: %u/%u)", node_id, allocated, total_locks);

    return OG_ERROR;
}

status_t drc_hot_page_lock(page_id_t page_id, uint32 lock_offset, drc_lock_mode_e mode)
{
    uint8 node_id = OG_INVALID_ID8;
    (void)drc_get_page_master_id(page_id, &node_id);

    rw_lock_t *lock = (rw_lock_t *)drc_global_lock_get_addr(node_id, lock_offset);
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Invalid lock offset: %u for page (%u-%u)", lock_offset, page_id.file, page_id.page);
        return OG_ERROR;
    }

    int ret;
    const char *lock_type;

    if (mode == DRC_LOCK_EXCLUSIVE) {
        ret = rw_lock_x_lock(lock);
        lock_type = "exclusive";
    } else {
        ret = rw_lock_s_lock(lock);
        lock_type = "shared";
    }

    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Failed to acquire %s lock for page (%u-%u): %d", lock_type, page_id.file,
                       page_id.page, ret);
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[DRC-LOCK] Acquired %s lock for page (%u-%u), offset: %u", lock_type, page_id.file, page_id.page,
                     lock_offset);

    return OG_SUCCESS;
}

status_t drc_hot_page_unlock(page_id_t page_id, uint32 lock_offset, drc_lock_mode_e mode)
{
    uint8 node_id = OG_INVALID_ID8;
    (void)drc_get_page_master_id(page_id, &node_id);

    rw_lock_t *lock = (rw_lock_t *)drc_global_lock_get_addr(node_id, lock_offset);
    if (lock == NULL) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Invalid lock offset: %u for page (%u-%u)", lock_offset, page_id.file, page_id.page);
        return OG_ERROR;
    }

    int ret;
    const char *lock_type;

    if (mode == DRC_LOCK_EXCLUSIVE) {
        ret = rw_lock_x_unlock(lock);
        lock_type = "exclusive";
    } else {
        ret = rw_lock_s_unlock(lock);
        lock_type = "shared";
    }

    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Failed to release %s lock for page (%u-%u): %d", lock_type, page_id.file,
                       page_id.page, ret);
        return OG_ERROR;
    }

    OG_LOG_DEBUG_INF("[DRC-LOCK] Released %s lock for page (%u-%u), offset: %u", lock_type, page_id.file, page_id.page,
                     lock_offset);

    return OG_SUCCESS;
}

status_t drc_hot_page_alloc_lock(page_id_t page_id, uint32 *lock_offset)
{
    uint8 node_id = OG_INVALID_ID8;
    (void)drc_get_page_master_id(page_id, &node_id);

    status_t ret = drc_global_lock_alloc(node_id, lock_offset);
    if (ret != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Failed to allocate lock for page (%u-%u) from pool %u", page_id.file, page_id.page,
                       node_id);
        return ret;
    }

    OG_LOG_RUN_INF("[DRC-LOCK] Allocated lock for hot page (%u-%u) from pool %u, offset: %u", page_id.file,
                   page_id.page, node_id, *lock_offset);

    return OG_SUCCESS;
}

status_t drc_hot_page_free_lock(page_id_t page_id, uint32 lock_offset)
{
    uint8 node_id = OG_INVALID_ID8;
    (void)drc_get_page_master_id(page_id, &node_id);

    rw_lock_t *lock = (rw_lock_t *)drc_global_lock_get_addr(node_id, lock_offset);
    if (!lock) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Failed to get lock address for offset: %u", lock_offset);
        return OG_ERROR;
    }

    int state = atomic_load(&lock->state);
    uint32 waiters = atomic_load(&lock->write_waiters);

    if (state != 0) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Cannot free lock for page (%u-%u): lock is held (state=%d)", page_id.file,
                       page_id.page, state);
        return OG_ERROR;
    }

    if (waiters != 0) {
        OG_LOG_RUN_ERR("[DRC-LOCK] Cannot free lock for page (%u-%u): writers waiting (waiters=%u)", page_id.file,
                       page_id.page, waiters);
        return OG_ERROR;
    }

    drc_global_lock_pool_header_t *header = g_lock_pool_headers[node_id];
    uint32 meta_size = sizeof(drc_global_lock_pool_header_t) + header->bitmap_size;
    uint32 offset_from_locks = lock_offset - meta_size;
    uint32 index = offset_from_locks / DRC_GLOBAL_LOCK_SIZE;
    uint32 word_idx = index / 64;
    uint32 bit_idx = index % 64;
    uint64 bit_mask = (uint64)1 << bit_idx;
    drc_global_lock_bitmap_t *bitmap = g_lock_pool_bitmaps[node_id];
    uint64 old_word;
    uint64 new_word;

    do {
        old_word = atomic_load(&bitmap[word_idx]);
        if ((old_word & bit_mask) == 0) {
            OG_LOG_RUN_WAR("[DRC-LOCK] Lock at pool %u, index %u already free", node_id, index);
            return OG_ERROR;
        }
        new_word = old_word & ~bit_mask;
    } while (!atomic_compare_exchange_weak(&bitmap[word_idx], &old_word, new_word));

    atomic_fetch_sub(&header->allocated_locks, 1);
    OG_LOG_RUN_INF("[DRC-LOCK] Freed lock for hot page (%u-%u) from pool %u, offset: %u", page_id.file, page_id.page,
                   node_id, lock_offset);

    return OG_SUCCESS;
}

void *drc_global_lock_get_addr(uint8 node_id, uint32 lock_offset)
{
    drc_global_lock_pool_header_t *header = g_lock_pool_headers[node_id];
    if (!header || lock_offset == DRC_INVALID_LOCK_OFFSET) {
        return NULL;
    }

    uint32 meta_size = (uint32)(sizeof(drc_global_lock_pool_header_t) + header->bitmap_size);

    if (lock_offset < meta_size || lock_offset >= meta_size + (uint32)header->lock_pool_size) {
        return NULL;
    }

    return (char *)header + (size_t)lock_offset;
}