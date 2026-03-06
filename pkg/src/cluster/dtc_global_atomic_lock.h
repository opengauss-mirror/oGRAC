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

#ifndef DTC_GLOBAL_ATOMIC_LOCK_H
#define DTC_GLOBAL_ATOMIC_LOCK_H

#include <limits.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "cm_defs.h"
#include "cm_error.h"
#include "cm_log.h"
#include "cm_ubs_mem.h"
#include "cm_ubs_mem_def.h"
#include "dtc_drc.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

// Size of rw_lock_t
#define DRC_GLOBAL_LOCK_SIZE 64

// Invalid lock offset, to check if lock has been set or not
#define DRC_INVALID_LOCK_OFFSET UINT32_MAX

extern _Thread_local uint32 drc_g_node_id;

typedef struct {
    atomic_int state;                 // Lock state (0=unlocked, >0=shared, INT32_MIN=exclusive)
    atomic_uint_fast32_t owner_node;  // we might not need it afterall
    atomic_uint_fast32_t write_waiters;
    char padding[DRC_GLOBAL_LOCK_SIZE - sizeof(atomic_int) - 2 * sizeof(atomic_uint_fast32_t)];
} rw_lock_t;

typedef struct {
    atomic_uint_fast64_t allocated_locks;
    uint32 total_locks;
    atomic_uint_fast64_t next_free;
    uint64 base_addr;
    uint64 lock_pool_size;
    uint64 bitmap_size;
} drc_global_lock_pool_header_t;

typedef atomic_uint_fast64_t drc_global_lock_bitmap_t;

status_t drc_global_lock_pool_init(void *shmem_base_addr, uint32 lock_count, uint8 node_id);

status_t drc_global_lock_pool_attach(void *shmem_base_addr, uint8 remote_node_id, uint8 current_node_id);

status_t drc_global_lock_alloc(uint8 node_id, uint32 *lock_offset);

void *drc_global_lock_get_addr(uint8 node_id, uint32 lock_offset);

status_t drc_hot_page_lock(page_id_t page_id, uint32 lock_offset, drc_lock_mode_e modee);

status_t drc_hot_page_unlock(page_id_t page_id, uint32 lock_offset, drc_lock_mode_e mode);

status_t drc_hot_page_alloc_lock(page_id_t page_id, uint32 *lock_offset);

status_t drc_hot_page_free_lock(page_id_t page_id, uint32 lock_offset);

static int __attribute__((unused)) rw_lock_s_lock(rw_lock_t *lock)
{
    for (;;) {
        int state = atomic_load(&lock->state);
        // Can only acquire iff non-exclusive lock
        if (state >= 0) {
            uint32 waiters = atomic_load(&lock->write_waiters);
            if (waiters == 0 && atomic_compare_exchange_weak(&lock->state, &state, state + 1)) {
                return OG_SUCCESS;
            }
        }
    }
}

static inline int rw_lock_s_unlock(rw_lock_t *lock)
{
    int state = atomic_load(&lock->state);
    if (state <= 0) {
        return OG_ERROR;
    }
    atomic_fetch_sub(&lock->state, 1);
    return OG_SUCCESS;
}

static inline int rw_lock_x_lock(rw_lock_t *lock)
{
    atomic_fetch_add(&lock->write_waiters, 1);

    for (;;) {
        int expected = 0;
        if (atomic_compare_exchange_weak(&lock->state, &expected, INT32_MIN)) {
            atomic_store(&lock->owner_node, drc_g_node_id);
            atomic_fetch_sub(&lock->write_waiters, 1);
            return OG_SUCCESS;
        }
    }
}

static inline int rw_lock_x_unlock(rw_lock_t *lock)
{
    uint32 cur_node = atomic_load(&lock->owner_node);
    if (cur_node != drc_g_node_id) {
        return OG_ERROR;
    }
    atomic_store(&lock->owner_node, 0);
    // Release lock
    int expected = INT32_MIN;
    if (!atomic_compare_exchange_strong(&lock->state, &expected, 0)) {
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

static inline uint64 drc_calc_lock_pool_size(uint32 lock_count)
{
    return (uint64)lock_count * DRC_GLOBAL_LOCK_SIZE;
}

static inline uint64 drc_calc_bitmap_size(uint32 lock_count)
{
    size_t bitmap_words = (lock_count + 63) / 64;
    return bitmap_words * sizeof(atomic_uint_fast64_t);
}

static inline uint64 drc_calc_total_lock_region_size(uint32 lock_count)
{
    return sizeof(drc_global_lock_pool_header_t) + drc_calc_bitmap_size(lock_count) +
           drc_calc_lock_pool_size(lock_count);
}

#ifdef __cplusplus
}
#endif

#endif /* DTC_GLOBAL_ATOMIC_LOCK_H */