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
 * cm_atomic.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_atomic.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ATOMIC_H__
#define __CM_ATOMIC_H__

#include <stdlib.h>
#include "cm_defs.h"
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32

typedef volatile long atomic32_t;
typedef volatile int64 atomic_t;

static inline atomic_t cm_atomic_add(atomic_t *val, int64 count)
{
    return InterlockedAdd64(val, count);
}

static inline atomic_t cm_atomic_get(atomic_t *val)
{
    return InterlockedAdd64(val, 0);
}

static inline atomic_t cm_atomic_set(atomic_t *val, int64 value)
{
    return InterlockedExchange64(val, value);
}

static inline atomic_t cm_atomic_inc(atomic_t *val)
{
    return InterlockedIncrement64(val);
}

static inline atomic_t cm_atomic_dec(atomic_t *val)
{
    return InterlockedDecrement64(val);
}

static inline atomic32_t cm_atomic32_inc(atomic32_t *val)
{
    return InterlockedIncrement(val);
}

static inline atomic32_t cm_atomic32_dec(atomic32_t *val)
{
    return InterlockedDecrement(val);
}


static inline atomic32_t cm_atomic32_add(atomic32_t *val, int32 count)
{
    return InterlockedExchangeAdd(val, count);
}

static inline atomic32_t cm_atomic32_fetch_add(atomic32_t *val, int32 count)
{
    return (atomic32_t)InterlockedExchangeAdd(val, (LONG)count);
}

static inline atomic32_t cm_atomic32_fetch_inc(atomic32_t *val)
{
    return (atomic32_t)InterlockedExchangeAdd(val, (LONG)1);
}

static inline int32 cm_atomic32_set(atomic32_t *val, int32 value)
{
    (void)InterlockedExchange(val, (LONG)value);
    return value;
}

static inline atomic32_t cm_atomic32_get(atomic32_t *val)
{
    return InterlockedCompareExchange(val, 0, 0);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return (InterlockedCompareExchange64(val, newval, oldval) == oldval) ? OG_TRUE : OG_FALSE;
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return (InterlockedCompareExchange(val, newval, oldval) == oldval) ? OG_TRUE : OG_FALSE;
}

#else

typedef volatile int32 atomic32_t;
typedef volatile int64 atomic_t;

typedef union {
    uint128   u128;
    uint64    u64[2];
    uint32    u32[4];
}__attribute__((aligned(16)))  uint128_u;

struct Combined128 {
    uint64 curr_byte_pos;
    uint32 byte_size;
    int32  lrc;
};
union Union128 {
    uint128_u value;
    struct Combined128 struct128;
};

#if defined(__arm__) || defined(__aarch64__)
static inline int64 cm_atomic_get(atomic_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline uint64 cm_atomic_get_u64(atomic_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_set(atomic_t *val, int64 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

static inline uint64 cm_atomic_set_u64(volatile uint64 *val, uint64 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

static inline uint64 cm_atomic_barrier_read(volatile uint64* ptr)
{
    return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
}

static inline int64 cm_atomic_inc(atomic_t *val)
{
    return __atomic_add_fetch(val, 1, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_dec(atomic_t *val)
{
    return __atomic_add_fetch(val, -1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_inc(atomic32_t *val)
{
    return __atomic_add_fetch(val, 1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_fetch_inc(atomic32_t *val)
{
    return __atomic_fetch_add(val, 1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_fetch_add(atomic32_t *val, int32 count)
{
    return __atomic_fetch_add(val, count, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_dec(atomic32_t *val)
{
    return __atomic_add_fetch(val, -1, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_add(atomic32_t *val, int32 count)
{
    return __atomic_add_fetch(val, count, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_get(atomic32_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_set(atomic32_t *val, int32 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

static inline int64 cm_atomic_add(atomic_t *val, int64 count)
{
    return __atomic_add_fetch(val, count, __ATOMIC_SEQ_CST);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return __atomic_compare_exchange(val, &oldval, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return __atomic_compare_exchange(val, &oldval, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline bool cm_atomic32_compare_exchange(atomic32_t* ptr, int32* expected, int32 newval)
{
    bool ret = false;
    int32	current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
}

static inline bool cm_atomic_compare_exchange_64(atomic_t* ptr, int64* expected, int64 newval)
{
    bool ret = false;
    int64	current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
}

static inline bool cm_atomic_compare_exchange_u64(atomic_t* ptr, uint64* expected, uint64 newval)
{
    bool ret = false;
    uint64	current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
}

static inline int64 cm_atomic_exchange(atomic_t *val, int64 newval)
{
    int64 oldval;
    while (true) {
        oldval = cm_atomic_get(val);
        if (cm_atomic_compare_exchange_64(val, &oldval, newval)) {
            break;
        }
    }
    return oldval;
}

static inline uint64 cm_atomic_exchange_uint64(atomic_t *val, uint64 newval)
{
    uint64 oldval;
    while (true) {
        oldval = cm_atomic_get_u64(val);
        if (cm_atomic_compare_exchange_u64(val, &oldval, newval)) {
            break;
        }
    }
    return oldval;
}

static inline int32 cm_atomic32_exchange(atomic32_t *val, int32 newval)
{
    int32 oldval;
    while (true) {
        oldval = cm_atomic32_get(val);
        if (cm_atomic32_compare_exchange(val, &oldval, newval)) {
            break;
        }
    }
    return oldval;
}

/*
 * Exclusive load/store 2 uint64_t variables to fullfil 128bit atomic compare and swap
 */
static inline uint128_u __excl_compare_and_swap_u128(volatile uint128_u *ptr, uint128_u oldval, uint128_u newval)
{
    uint64_t tmp, ret;
    uint128_u old;

    __asm__ __volatile__("1:     ldxp    %0, %1, %4\n"
                 "       eor     %2, %0, %5\n"
                 "       eor     %3, %1, %6\n"
                 "       orr     %2, %3, %2\n"
                 "       cbnz    %2, 2f\n"
                 "       stlxp   %w2, %7, %8, %4\n"
                 "       cbnz    %w2, 1b\n"
                 "       b 3f\n"
                 "2:"
                 "       stlxp   %w2, %0, %1, %4\n"
                 "       cbnz    %w2, 1b\n"
                 "3:"
                 "       dmb ish\n"
                 : "=&r"(old.u64[0]), "=&r"(old.u64[1]), "=&r"(ret), "=&r"(tmp), 
                   "+Q"(ptr->u128)
                 : "r"(oldval.u64[0]), "r"(oldval.u64[1]), "r"(newval.u64[0]), "r"(newval.u64[1])
                 : "memory");
    return old;
}

static inline uint128_u cm_compare_and_swap_u128(volatile uint128_u* ptr, uint128_u oldval, uint128_u newval)
{
    return __excl_compare_and_swap_u128(ptr, oldval, newval);
}

#else

static inline int64 cm_atomic_get(atomic_t *val)
{
    return *val;
}

static inline int64 cm_atomic_set(atomic_t *val, int64 value)
{
    return *val = value;
}

static inline int64 cm_atomic_inc(atomic_t *val)
{
    return __sync_add_and_fetch(val, 1);
}

static inline int64 cm_atomic_dec(atomic_t *val)
{
    return __sync_add_and_fetch(val, -1);
}

static inline int32 cm_atomic32_inc(atomic32_t *val)
{
    return __sync_add_and_fetch(val, 1);
}

static inline int32 cm_atomic32_dec(atomic32_t *val)
{
    return __sync_add_and_fetch(val, -1);
}

static inline int32 cm_atomic32_add(atomic32_t *val, int32 count)
{
    return __sync_add_and_fetch(val, count);
}

static inline int32 cm_atomic32_fetch_add(atomic32_t *val, int32 count)
{
    return __sync_fetch_and_add(val, count);
}

static inline int32 cm_atomic32_fetch_inc(atomic32_t *val)
{
    return __sync_fetch_and_add(val, 1);
}

static inline int32 cm_atomic32_get(atomic32_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int32 cm_atomic32_set(atomic32_t *val, int32 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

static inline int64 cm_atomic_add(atomic_t *val, int64 count)
{
    return __sync_add_and_fetch(val, count);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return __sync_bool_compare_and_swap(val, oldval, newval);
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return __sync_bool_compare_and_swap(val, oldval, newval);
}

static inline uint128_u cm_compare_and_swap_u128(volatile uint128_u* ptr, uint128_u oldval, uint128_u newval)
{
    uint128_u ret;
    ret.u128 = __sync_val_compare_and_swap(&ptr->u128, oldval.u128, newval.u128);
    return ret;
}
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
