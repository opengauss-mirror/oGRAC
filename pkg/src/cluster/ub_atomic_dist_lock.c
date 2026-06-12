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
#include "cm_thread.h"
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

/*
 * lock_word layout (64-bit, single atomic CAS):
 *   [63:40] state  (24-bit signed: 0=free, >0=S count, 0x800000=X)
 *   [39:32] node_id (8-bit, 0xFF when no X holder; valid node_id starts from 0)
 *   [31:0]  tid     (32-bit, -1 when no X holder)
 */
#define GBP_LOCK_STATE_SHIFT    40U
#define GBP_LOCK_NODE_SHIFT     32U
#define GBP_LOCK_STATE_MASK     0xFFFFFFULL
#define GBP_LOCK_NODE_MASK      0xFFULL
#define GBP_LOCK_STATE_X_RAW    0x800000U
#define GBP_LOCK_NODE_INVALID   OG_INVALID_ID8
#define GBP_LOCK_TID_INVALID    (-1)

struct ub_rw_lock {
    atomic_uint_fast64_t lock_word;
    atomic_uint_fast32_t writeWaiters;
    atomic_bool readonly;
    char padding[UB_RW_LOCK_SIZE - sizeof(atomic_uint_fast64_t) - sizeof(atomic_uint_fast32_t) -
                 sizeof(atomic_bool)];
};

static inline int32 gbp_lock_state_to_external(uint32 raw24)
{
    int32 st = (int32)(raw24 | ((raw24 & 0x800000U) ? 0xFF000000U : 0U));

    if (raw24 == GBP_LOCK_STATE_X_RAW) {
        return INT32_MIN;
    }
    return st;
}

static inline uint32 gbp_lock_state_to_raw(int32 st)
{
    if (st == INT32_MIN) {
        return GBP_LOCK_STATE_X_RAW;
    }
    return (uint32)(st & 0xFFFFFF);
}

static inline uint64_t gbp_lock_pack(int32 state, uint8 node_id, int32 tid)
{
    uint64_t w = (uint64_t)(uint32_t)tid;

    w |= ((uint64_t)node_id << GBP_LOCK_NODE_SHIFT);
    w |= ((uint64_t)gbp_lock_state_to_raw(state) << GBP_LOCK_STATE_SHIFT);
    return w;
}

static inline void gbp_lock_unpack(uint64_t w, int32 *state, uint8 *node_id, int32 *tid)
{
    *tid = (int32)(uint32_t)(w & 0xFFFFFFFFULL);
    *node_id = (uint8)((w >> GBP_LOCK_NODE_SHIFT) & GBP_LOCK_NODE_MASK);
    *state = gbp_lock_state_to_external((uint32)((w >> GBP_LOCK_STATE_SHIFT) & GBP_LOCK_STATE_MASK));
}

static inline uint64_t gbp_lock_word_empty(void)
{
    return gbp_lock_pack(0, (uint8)GBP_LOCK_NODE_INVALID, GBP_LOCK_TID_INVALID);
}

static inline bool32 gbp_lock_owner_cleared(uint64_t w)
{
    uint8 node_id;
    int32 tid;
    int32 state;

    gbp_lock_unpack(w, &state, &node_id, &tid);
    (void)state;
    (void)tid;
    return node_id == GBP_LOCK_NODE_INVALID;
}

static inline bool32 gbp_lock_is_x_held_word(uint64_t w, uint8 node_id, int32 tid)
{
    int32 state;
    uint8 n;
    int32 t;

    gbp_lock_unpack(w, &state, &n, &t);
    return (bool32)(state == INT32_MIN && n == node_id && t == tid);
}

static inline bool32 gbp_lock_cas(atomic_uint_fast64_t *lock_word, uint64_t *expected, uint64_t desired)
{
    return atomic_compare_exchange_weak_explicit(lock_word, expected, desired, memory_order_acq_rel,
        memory_order_relaxed);
}

static inline uint64_t gbp_lock_make_x(uint8 node_id, int32 tid)
{
    return gbp_lock_pack(INT32_MIN, node_id, tid);
}

bool32 ub_rw_lock_get_readonly(ub_rw_lock_t *lock);
int32 ub_rw_lock_get_state(ub_rw_lock_t *lock);
bool32 ub_rw_lock_is_x_held_by_current_thread(ub_rw_lock_t *lock, uint8_t node_id, int32_t tid);

void ub_rw_lock_set_readonly(ub_rw_lock_t *lock, bool32 readonly, const char *phase)
{
    bool32 oldv;
    bool32 newv;
    int32 state;

    if (lock == NULL) {
        OG_LOG_DEBUG_INF("[GBP-LOCK-READONLY-DIAG][%s] lock is NULL, want:%d tid:%d",
            phase != NULL ? phase : "unknown", (int32)readonly, (int32)cm_get_current_thread_id());
        return;
    }

    oldv = ub_rw_lock_get_readonly(lock);
    state = ub_rw_lock_get_state(lock);
    atomic_store_explicit(&lock->readonly, readonly ? true : false, memory_order_release);
    newv = ub_rw_lock_get_readonly(lock);
    OG_LOG_RUN_INF("[GBP-LOCK-READONLY-DIAG][%s] lock_ptr:%llu old:%d want:%d after:%d lock_state:%d tid:%d",
        phase != NULL ? phase : "unknown", (uint64)(uintptr_t)lock, (int32)oldv, (int32)readonly, (int32)newv,
        state, (int32)cm_get_current_thread_id());
}

bool32 ub_rw_lock_get_readonly(ub_rw_lock_t *lock)
{
    return atomic_load_explicit(&lock->readonly, memory_order_acquire) ? OG_TRUE : OG_FALSE;
}

static inline bool32 gbp_lock_x_try_rollback(ub_rw_lock_t *lock, const ub_location_t *location)
{
    uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
    uint64_t neww;

    if (!gbp_lock_is_x_held_word(oldw, location->node_id, location->tid)) {
        return OG_FALSE;
    }

    neww = gbp_lock_word_empty();
    return gbp_lock_cas(&lock->lock_word, &oldw, neww);
}

/*
 * CAS-acquire X then validate readonly (store fence). If a concurrent begin_page_store
 * raised readonly in the window between pre-check and CAS, roll back X and retry.
 * Not used for x_lock_for_store / x_lock_reenter: store-fence owner may hold X while readonly=1.
 */
static inline bool32 gbp_lock_x_cas_after_readonly_check(ub_rw_lock_t *lock, const ub_location_t *location,
    uint64_t expected, uint64_t neww)
{
    if (ub_rw_lock_get_readonly(lock)) {
        return OG_FALSE;
    }

    if (!gbp_lock_cas(&lock->lock_word, &expected, neww)) {
        return OG_FALSE;
    }

    if (!ub_rw_lock_get_readonly(lock)) {
        return OG_TRUE;
    }

    (void)gbp_lock_x_try_rollback(lock, location);
    return OG_FALSE;
}

uint64 ub_rw_lock_get_owner_node(ub_rw_lock_t *lock)
{
    uint64_t w = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
    int32 state;
    uint8 node_id;
    int32 tid;

    gbp_lock_unpack(w, &state, &node_id, &tid);
    if (state != INT32_MIN) {
        return UINT64_MAX;
    }
    return ((uint64)node_id << 32) | (uint32)tid;
}

int32 ub_rw_lock_get_state(ub_rw_lock_t *lock)
{
    uint64_t w = atomic_load_explicit(&lock->lock_word, memory_order_relaxed);
    int32 state;
    uint8 node_id;
    int32 tid;

    gbp_lock_unpack(w, &state, &node_id, &tid);
    (void)node_id;
    (void)tid;
    return state;
}

void ub_rw_lock_create(ub_rw_lock_t *lock, const ub_lock_config_t *config, const ub_location_t *location)
{
    (void)config;
    (void)location;

    atomic_store_explicit(&lock->lock_word, gbp_lock_word_empty(), memory_order_relaxed);
    atomic_store(&lock->writeWaiters, 0);
    atomic_store(&lock->readonly, false);
}

void ub_rw_lock_free(ub_rw_lock_t *lock, const ub_location_t *location)
{
    (void)location;

    atomic_store_explicit(&lock->lock_word, gbp_lock_word_empty(), memory_order_relaxed);
    atomic_store(&lock->writeWaiters, 0);
}

ub_lock_result_t ub_rw_lock_s_lock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;

    uint32_t spinCount = 0;

    for (;;) {
        uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
        int32 state;
        uint8 node_id;
        int32 tid;

        gbp_lock_unpack(oldw, &state, &node_id, &tid);
        if (state >= 0 && gbp_lock_owner_cleared(oldw) &&
            atomic_load_explicit(&lock->writeWaiters, memory_order_acquire) == 0) {
            uint64_t neww = gbp_lock_pack(state + 1, (uint8)GBP_LOCK_NODE_INVALID, GBP_LOCK_TID_INVALID);
            uint64_t expected = oldw;

            if (gbp_lock_cas(&lock->lock_word, &expected, neww)) {
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

    uint32_t spinCount = 0;

    for (;;) {
        uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
        int32 state;
        uint8 node_id;
        int32 tid;

        gbp_lock_unpack(oldw, &state, &node_id, &tid);
        if (state <= 0) {
            return UB_LOCK_ERROR;
        }
        if (!gbp_lock_owner_cleared(oldw)) {
            return UB_LOCK_ERROR;
        }

        uint64_t neww = gbp_lock_pack(state - 1, (uint8)GBP_LOCK_NODE_INVALID, GBP_LOCK_TID_INVALID);
        uint64_t expected = oldw;
        if (gbp_lock_cas(&lock->lock_word, &expected, neww)) {
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

void ub_rw_lock_begin_page_store(ub_rw_lock_t *lock)
{
    ub_rw_lock_set_readonly(lock, OG_TRUE, "begin_page_store");
}

void ub_rw_lock_end_page_store(ub_rw_lock_t *lock)
{
    ub_rw_lock_set_readonly(lock, OG_FALSE, "end_page_store");
}

ub_lock_result_t ub_rw_lock_x_lock_for_store(ub_rw_lock_t *lock, const ub_location_t *location)
{
    uint32_t spinCount = 0;
    uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
    if (gbp_lock_is_x_held_word(oldw, location->node_id, location->tid)) {
        return UB_LOCK_SUCCESS;
    }

    for (;;) {
        oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
        int32 state;
        uint8 node_id;
        int32 tid;

        gbp_lock_unpack(oldw, &state, &node_id, &tid);
        (void)node_id;
        (void)tid;
        if (state == 0 && gbp_lock_owner_cleared(oldw)) {
            uint64_t neww = gbp_lock_make_x(location->node_id, location->tid);
            uint64_t expected = oldw;

            if (gbp_lock_cas(&lock->lock_word, &expected, neww)) {
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

ub_lock_result_t ub_rw_lock_x_lock_reenter(ub_rw_lock_t *lock, const ub_location_t *location)
{
    uint32_t spinCount = 0;
    uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
    if (gbp_lock_is_x_held_word(oldw, location->node_id, location->tid)) {
        return UB_LOCK_SUCCESS;
    }

    for (;;) {
        oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
        int32 state;
        uint8 node_id;
        int32 tid;

        gbp_lock_unpack(oldw, &state, &node_id, &tid);
        (void)node_id;
        (void)tid;
        if (state == 0 && gbp_lock_owner_cleared(oldw)) {
            uint64_t neww = gbp_lock_make_x(location->node_id, location->tid);
            uint64_t expected = oldw;

            if (gbp_lock_cas(&lock->lock_word, &expected, neww)) {
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

ub_lock_result_t ub_rw_lock_x_lock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;
    uint32 times = 0;
    uint32_t spinCount = 0;
    uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
    
    int32 cur_state;
    uint8 cur_node_id;
    int32 cur_tid;

    gbp_lock_unpack(oldw, &cur_state, &cur_node_id, &cur_tid);
    OG_LOG_RUN_INF("[GBP-LOCK] X lock start, state:%d node_id:%u tid:%d", cur_state, cur_node_id, cur_tid);

    if (gbp_lock_is_x_held_word(oldw, location->node_id, location->tid)) {
        OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] re enter X lock node:%u tid:%d", location->node_id, location->tid);
        return UB_LOCK_SUCCESS;
    }

    atomic_fetch_add_explicit(&lock->writeWaiters, 1, memory_order_release);

    for (;;) {
        bool32 readonly = ub_rw_lock_get_readonly(lock);
        while (readonly) {
            oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
            if (gbp_lock_is_x_held_word(oldw, location->node_id, location->tid)) {
                break;
            }

            times++;
            if (SECUREC_UNLIKELY(times > OG_SPIN_COUNT)) {
                cm_sleep(100);
                times = 0;
            }
            readonly = ub_rw_lock_get_readonly(lock);
        }

        oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
        int32 state;
        uint8 node_id;
        int32 tid;
        gbp_lock_unpack(oldw, &state, &node_id, &tid);
        OG_LOG_DEBUG_INF("[DRC-GBP-LOCK] 11 X lock node:%u tid:%d state:%d readonly:%d",
            node_id, tid, state, (int32)ub_rw_lock_get_readonly(lock));

        if (state == 0 && gbp_lock_owner_cleared(oldw)) {
            uint64_t neww = gbp_lock_make_x(location->node_id, location->tid);
            uint64_t expected = oldw;

            if (gbp_lock_x_cas_after_readonly_check(lock, location, expected, neww)) {
                int32 wr_wait;
                int32 success_state;
                uint8 success_node_id;
                int32 success_tid;
                uint64_t curw;

                wr_wait = (int32)atomic_fetch_sub_explicit(&lock->writeWaiters, 1, memory_order_release) - 1;
                curw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
                gbp_lock_unpack(curw, &success_state, &success_node_id, &success_tid);
                OG_LOG_RUN_INF("[GBP-LOCK] X lock success, state:%d node_id:%u tid:%d, write_waiters:%d",
                    success_state, success_node_id, success_tid, wr_wait);
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

ub_lock_result_t ub_rw_lock_x_unlock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    (void)policy;
    int32 write_waiters = (int32)atomic_load_explicit(&lock->writeWaiters, memory_order_relaxed);
    bool32 readonly = ub_rw_lock_get_readonly(lock);
    uint64_t oldw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
    int32 state;
    uint8 node_id;
    int32 tid;

    gbp_lock_unpack(oldw, &state, &node_id, &tid);

    if (state == 0 && gbp_lock_owner_cleared(oldw)) {
        return UB_LOCK_SUCCESS;
    }

    if (!gbp_lock_is_x_held_word(oldw, location->node_id, location->tid)) {
        OG_LOG_RUN_ERR("[GBP-LOCK] X unlock fail, node:%u tid:%d state:%d node_id:%u tid:%d "
                       "write_waiters:%d readonly:%d",
            location->node_id, location->tid, state, node_id, tid, write_waiters, (int32)readonly);
        return UB_LOCK_ERROR;
    }

    uint64_t neww = gbp_lock_word_empty();
    uint64_t expected = oldw;
    if (!gbp_lock_cas(&lock->lock_word, &expected, neww)) {
        OG_LOG_RUN_ERR("[GBP-LOCK] X unlock CAS fail, node:%u tid:%d state:%d node_id:%u tid:%d "
                       "write_waiters:%d readonly:%d",
            location->node_id, location->tid, state, node_id, tid, write_waiters, (int32)readonly);
        return UB_LOCK_ERROR;
    }

    // test log
    {
        uint64_t curw = atomic_load_explicit(&lock->lock_word, memory_order_acquire);
        int32 cur_state;
        uint8 cur_node_id;
        int32 cur_tid;
        gbp_lock_unpack(curw, &cur_state, &cur_node_id, &cur_tid);
        OG_LOG_RUN_INF("[GBP-LOCK] X unlock success, state:%d node_id:%u tid:%d",
            cur_state, cur_node_id, cur_tid);
    }

    return UB_LOCK_SUCCESS;
}

ub_lock_result_t ub_rw_lock_sx_lock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    return ub_rw_lock_x_lock(lock, policy, location);
}

ub_lock_result_t ub_rw_lock_sx_unlock(ub_rw_lock_t *lock, const ub_lock_policy_t *policy, const ub_location_t *location)
{
    return ub_rw_lock_x_unlock(lock, policy, location);
}

bool32 ub_rw_lock_is_x_held_by_current_thread(ub_rw_lock_t *lock, uint8_t node_id, int32_t tid)
{
    const struct ub_rw_lock *l = (const struct ub_rw_lock *)lock;
    uint64_t w = atomic_load_explicit(&l->lock_word, memory_order_acquire);

    return gbp_lock_is_x_held_word(w, node_id, tid);
}

void ub_rw_lock_debug_read(const ub_rw_lock_t *lock, int32 *out_state, int32 *out_owner_node,
    int32 *out_write_waiters, int32 *out_owner_tid)
{
    const struct ub_rw_lock *l = (const struct ub_rw_lock *)lock;
    uint64_t w = atomic_load_explicit(&l->lock_word, memory_order_relaxed);
    int32 state;
    uint8 node_id;
    int32 tid;

    gbp_lock_unpack(w, &state, &node_id, &tid);
    *out_state = state;
    *out_write_waiters = (int32)atomic_load_explicit(&l->writeWaiters, memory_order_relaxed);
    *out_owner_node = -1;
    *out_owner_tid = -1;
    if (state == INT32_MIN) {
        *out_owner_node = (int32)node_id;
        *out_owner_tid = tid;
    }
}
