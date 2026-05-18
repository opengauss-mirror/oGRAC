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
 * ub_atomic_dist_lock.c
 *
 *
 * IDENTIFICATION
 * src/cluster/ub_atomic_dist_lock.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdatomic.h>
#include <sched.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include "cm_defs.h"
#include "cm_log.h"
#include "knl_cluster_module.h"
#include "ub_dist_lock.h"

#if defined(__x86_64__)
#include <immintrin.h>
#define cpu_pause()  \
    {                \
        _mm_pause(); \
    }
#elif defined(__aarch64__)
#define cpu_pause()                    \
    {                                  \
        __asm__ __volatile__("yield"); \
    }
#else
#define cpu_pause() \
    {               \
    }
#endif

#define SPIN_YIELD_THRESHOLD 100

struct ub_rw_lock {
    atomic_int state;                  /* 0=unlocked, >0=shared count, INT32_MIN=exclusive */
    atomic_uint_fast64_t ownerNode;    /* node_id of the current exclusive holder */
    atomic_uint_fast32_t writeWaiters; /* count of threads waiting for X lock */
    atomic_bool readonly;
    char padding[UB_RW_LOCK_SIZE       /* UB_RW_LOCK_SIZE is originally 640 bytes */
                 - sizeof(atomic_int) - sizeof(atomic_uint_fast64_t)
                 - sizeof(atomic_uint_fast32_t) - sizeof(atomic_bool)];
};

static inline uint64_t make_global_owner(uint8_t node_id, int32_t tid)
{
    return ((uint64_t)node_id << 32) | (uint32_t)tid;
}

void ub_rw_lock_set_readonly(ub_rw_lock_t *lock, bool32 readonly)
{
    atomic_store_explicit(&lock->readonly, readonly ? true : false, memory_order_relaxed);
}

bool32 ub_rw_lock_get_readonly(ub_rw_lock_t *lock)
{
    return atomic_load_explicit(&lock->readonly, memory_order_relaxed) ? OG_TRUE : OG_FALSE;
}

void ub_rw_lock_create(ub_rw_lock_t *lock, const ub_lock_config_t *config, const ub_location_t *location)
{
    (void)config;
    (void)location;

    atomic_store(&lock->state, 0);
    atomic_store(&lock->ownerNode, 0);
    atomic_store(&lock->writeWaiters, 0);
    atomic_store(&lock->readonly, false);
}

void ub_rw_lock_free(ub_rw_lock_t *lock, const ub_location_t *location)
{
    (void)location;

    atomic_store(&lock->state, 0);
    atomic_store(&lock->ownerNode, 0);
    atomic_store(&lock->writeWaiters, 0);
}

ub_lock_result_t ub_rw_lock_s_lock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;
    (void)location;

    uint32_t spinCount = 0;

    for (;;) {
        int state = atomic_load_explicit(&lock->state, memory_order_acquire);
        if (state >= 0 && atomic_load_explicit(&lock->writeWaiters, memory_order_relaxed) == 0) {
            if (atomic_compare_exchange_weak_explicit(&lock->state, &state, state + 1, memory_order_acquire,
                                                      memory_order_relaxed)) {
                return UB_LOCK_SUCCESS;
            }
        }

        cpu_pause();

        spinCount++;
        if (spinCount > SPIN_YIELD_THRESHOLD) {
            sched_yield();
            spinCount = 0;
        }
    }
}

ub_lock_result_t ub_rw_lock_s_unlock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;
    (void)location;

    int state = atomic_load_explicit(&lock->state, memory_order_relaxed);
    if (state <= 0) {
        return UB_LOCK_ERROR;
    }
    atomic_fetch_sub_explicit(&lock->state, 1, memory_order_release);
    OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] release s lock node:%u tid:%d state: %d",
                     location->node_id, location->tid, lock->state);
    return UB_LOCK_SUCCESS;
}

ub_lock_result_t ub_rw_lock_x_lock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;
    uint32 times = 0;
    uint32_t spinCount = 0;

    uint64_t identify = make_global_owner(location->node_id, location->tid);

    /* Re-entrant X lock: same thread already holds exclusive. */
    uint64_t ownernode = atomic_load_explicit(&lock->ownerNode, memory_order_acquire);
    if (ownernode == identify) {
        OG_LOG_RUN_INF("[DRC-GBP-LOCK] re enter X lock node:%u tid:%d identify:%lu owner:%lu", location->node_id,
                       location->tid, (unsigned long)identify, (unsigned long)ownernode);
        return UB_LOCK_SUCCESS;
    }

    atomic_fetch_add_explicit(&lock->writeWaiters, 1, memory_order_relaxed);

    for (;;) {
        bool32 readonly = atomic_load_explicit(&lock->readonly, memory_order_relaxed);
        while (readonly) {
            ownernode = atomic_load_explicit(&lock->ownerNode, memory_order_acquire);
            if (ownernode == identify) {
                break;
            }

            times++;
            if (SECUREC_UNLIKELY(times > OG_SPIN_COUNT)) {
                cm_sleep(100);
                times = 0;
            }
            readonly = atomic_load_explicit(&lock->readonly, memory_order_relaxed);
        }

        int state = atomic_load_explicit(&lock->state, memory_order_relaxed);
        OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] X lock node:%u tid:%d identify:%lu owner:%lu, readonly: %d, state: %d",
            location->node_id, location->tid, (unsigned long)identify, (unsigned long)ownernode, readonly, state);

        int expected = 0;
        if (atomic_compare_exchange_weak_explicit(&lock->state, &expected, INT32_MIN, memory_order_acquire,
                                                  memory_order_relaxed)) {
            atomic_store_explicit(&lock->ownerNode, identify, memory_order_relaxed);
            atomic_fetch_sub_explicit(&lock->writeWaiters, 1, memory_order_relaxed);
            return UB_LOCK_SUCCESS;
        }

        cpu_pause();

        spinCount++;
        if (spinCount > SPIN_YIELD_THRESHOLD) {
            sched_yield();
            spinCount = 0;
        }
    }
}

ub_lock_result_t ub_rw_lock_x_unlock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;
    uint64_t currentOwner = atomic_load_explicit(&lock->ownerNode, memory_order_relaxed);
    uint64_t identify = make_global_owner(location->node_id, location->tid);
    if (currentOwner != identify) {
        OG_LOG_RUN_ERR("[GBP-LOCK] X unlock fail because owner is unequel node :%u tid:%d identify:%lu owner:%lu",
                        location->node_id, location->tid, (unsigned long)identify, (unsigned long)currentOwner);
        return UB_LOCK_ERROR;
    }

    int state = atomic_load_explicit(&lock->state, memory_order_relaxed);

    int expected = INT32_MIN;
    if (!atomic_compare_exchange_strong_explicit(&lock->state, &expected, 0, memory_order_release,
                                                 memory_order_relaxed)) {
        OG_LOG_RUN_ERR("[GBP-LOCK] X unlock fail, node:%u tid:%d identify:%lu owner:%lu, state:%d",
            location->node_id, location->tid, (unsigned long)identify, (unsigned long)currentOwner, state);
        return UB_LOCK_ERROR;
    }
    atomic_store_explicit(&lock->ownerNode, 0, memory_order_relaxed);

    return UB_LOCK_SUCCESS;
}

ub_lock_result_t ub_rw_lock_sx_lock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    /* Not implemented for atomic dist lock */
    return ub_rw_lock_x_lock(lock, policy, location);
}

ub_lock_result_t ub_rw_lock_sx_unlock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    /* Not implemented for atomic dist lock */
    return ub_rw_lock_x_unlock(lock, policy, location);
}
