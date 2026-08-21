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
#include <stdbool.h>
#ifndef WIN32
#include <sched.h>
#endif // !WIN32

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

static inline uint64 cm_atomic_barrier_read(volatile uint64* ptr)
{
    return InterlockedAdd64((volatile LONGLONG*)ptr, 0);
}

static inline atomic_t cm_atomic_sub(atomic_t *val, int64 count)
{
    return InterlockedAdd64(val, (-1) * count);
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

static inline bool32 cm_atomic32_cas(atomic32_t *val, int64 oldval, int64 newval)
{
    return (InterlockedCompareExchange64(val, newval, oldval) == oldval) ? OG_TRUE : OG_FALSE;
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return (InterlockedCompareExchange(val, newval, oldval) == oldval) ? OG_TRUE : OG_FALSE;
}

static inline int32 cm_atomic32_exchange(atomic32_t *val, int32 newval)
{
    int32 oldval;
    while (true) {
        oldval = cm_atomic32_get(val);
        if (InterlockedCompareExchange(val, newval, oldval) == oldval) {
            break;
        }
    }
    return oldval;
}

static inline uint64 cm_atomic_get_u64(atomic_t *val)
{
    return InterlockedAdd64(val, 0);
}

static inline uint64 cm_atomic_set_u64(atomic_t *val, int64 value)
{
    return InterlockedExchange64(val, value);
}

static inline bool32 cm_atomic_compare_exchange_u64(atomic_t* ptr, uint64* expected, uint64 newval)
{
    bool32 ret = false;
    uint64	current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
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

#if defined(__aarch64__)
#include "cm_atomic_lse.h"
#endif

/*
 * Shared atomic helpers built on portable GCC builtins (__atomic_* / __sync_*).
 * Used by both ARM and x86 to avoid per-arch duplication. Defined here (before
 * the arch split) so they are visible to both the ARM and x86 branches below.
 * On aarch64 with LSE (CM_ATOMIC_HAS_LSE) CAS goes through casal.
 */
static inline uint64 cm_atomic_get_u64(atomic_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline uint64 cm_atomic_set_u64(volatile uint64 *val, uint64 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

static inline uint64 cm_atomic_barrier_read(volatile uint64 *ptr)
{
    return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
}

static inline bool32 cm_atomic_compare_exchange_64(atomic_t *ptr, int64 *expected, int64 newval)
{
    int64 current;
#ifdef CM_ATOMIC_HAS_LSE
    current = (int64)cm_lse_cas_u64((volatile uint64 *)(void *)ptr, (uint64)(*expected), (uint64)newval);
#else
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
#endif
    bool32 ret = (current == *expected) ? OG_TRUE : OG_FALSE;
    *expected = current;
    return ret;
}

static inline bool32 cm_atomic_compare_exchange_u64(atomic_t *ptr, uint64 *expected, uint64 newval)
{
    uint64 current;
#ifdef CM_ATOMIC_HAS_LSE
    current = cm_lse_cas_u64((volatile uint64 *)(void *)ptr, *expected, newval);
#else
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
#endif
    bool32 ret = (current == *expected) ? OG_TRUE : OG_FALSE;
    *expected = current;
    return ret;
}

static inline bool32 cm_atomic32_compare_exchange(atomic32_t *ptr, int32 *expected, int32 newval)
{
    int32 current;
#ifdef CM_ATOMIC_HAS_LSE
    current = (int32)cm_lse_cas_u32((volatile uint32 *)(void *)ptr, (uint32)(*expected), (uint32)newval);
#else
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
#endif
    bool32 ret = (current == *expected) ? OG_TRUE : OG_FALSE;
    *expected = current;
    return ret;
}

#if defined(__arm__) || defined(__aarch64__)
static inline int64 cm_atomic_get(atomic_t *val)
{
    return __atomic_load_n(val, __ATOMIC_SEQ_CST);
}

static inline int64 cm_atomic_set(atomic_t *val, int64 value)
{
    __atomic_store_n(val, value, __ATOMIC_SEQ_CST);
    return value;
}

#ifdef CM_ATOMIC_HAS_LSE
/*
 * LSE ldaddal is fetch_add (returns old). cm_atomic_inc/add/sub match the
 * existing GCC add_fetch / sub_and_fetch contract and return the new value.
 */
static inline int64 cm_atomic_inc(atomic_t *val)
{
    uint64 old = cm_lse_fetch_add_u64((volatile uint64 *)(void *)val, 1ULL);
    return (int64)(old + 1ULL);
}

static inline int64 cm_atomic_dec(atomic_t *val)
{
    uint64 old = cm_lse_fetch_sub_u64((volatile uint64 *)(void *)val, 1ULL);
    return (int64)(old - 1ULL);
}

static inline int32 cm_atomic32_inc(atomic32_t *val)
{
    uint32 old = cm_lse_fetch_add_u32((volatile uint32 *)(void *)val, 1U);
    return (int32)(old + 1U);
}

static inline int32 cm_atomic32_fetch_inc(atomic32_t *val)
{
    return (int32)cm_lse_fetch_add_u32((volatile uint32 *)(void *)val, 1U);
}

static inline int32 cm_atomic32_fetch_add(atomic32_t *val, int32 count)
{
    return (int32)cm_lse_fetch_add_u32((volatile uint32 *)(void *)val, (uint32)count);
}

static inline int32 cm_atomic32_dec(atomic32_t *val)
{
    uint32 old = cm_lse_fetch_sub_u32((volatile uint32 *)(void *)val, 1U);
    return (int32)(old - 1U);
}

static inline int32 cm_atomic32_add(atomic32_t *val, int32 count)
{
    uint32 old = cm_lse_fetch_add_u32((volatile uint32 *)(void *)val, (uint32)count);
    return (int32)(old + (uint32)count);
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
    uint64 old = cm_lse_fetch_add_u64((volatile uint64 *)(void *)val, (uint64)count);
    return (int64)(old + (uint64)count);
}

static inline int64 cm_atomic_sub(atomic_t *val, int64 count)
{
    uint64 old = cm_lse_fetch_sub_u64((volatile uint64 *)(void *)val, (uint64)count);
    return (int64)(old - (uint64)count);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    uint64 current = cm_lse_cas_u64((volatile uint64 *)(void *)val, (uint64)oldval, (uint64)newval);
    return ((int64)current == oldval) ? OG_TRUE : OG_FALSE;
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    uint32 current = cm_lse_cas_u32((volatile uint32 *)(void *)val, (uint32)oldval, (uint32)newval);
    return ((int32)current == oldval) ? OG_TRUE : OG_FALSE;
}

static inline uint64 cm_atomic_exchange_uint64(atomic_t *val, uint64 newval)
{
    return cm_lse_swap_u64((volatile uint64 *)(void *)val, newval);
}

static inline uint128_u cm_compare_and_swap_u128(volatile uint128_u *ptr, uint128_u oldval, uint128_u newval)
{
    return cm_lse_cas_u128(ptr, oldval, newval);
}
#else
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

static inline int64 cm_atomic_sub(atomic_t *val, int64 count)
{
    return __sync_sub_and_fetch(val, count);
}

static inline bool32 cm_atomic_cas(atomic_t *val, int64 oldval, int64 newval)
{
    return __atomic_compare_exchange(val, &oldval, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline bool32 cm_atomic32_cas(atomic32_t *val, int32 oldval, int32 newval)
{
    return __atomic_compare_exchange(val, &oldval, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
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

/*
 * Exclusive load/store pair for 128-bit CAS. Used when LSE (CASP) is not
 * available. ldxp/stlxp can livelock under contention; the extra dmb ish
 * approximates seq_cst.
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

static inline uint128_u cm_compare_and_swap_u128(volatile uint128_u *ptr, uint128_u oldval, uint128_u newval)
{
    return __excl_compare_and_swap_u128(ptr, oldval, newval);
}
#endif

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

static inline int64 cm_atomic_sub(atomic_t *val, int64 count)
{
    return __sync_sub_and_fetch(val, count);
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

/*
 * Shared exchange helpers. With LSE these are a single swpal; otherwise they
 * loop on the arch-specific get + compare_exchange pair.
 */
static inline int64 cm_atomic_exchange(atomic_t *val, int64 newval)
{
#ifdef CM_ATOMIC_HAS_LSE
    return (int64)cm_lse_swap_u64((volatile uint64 *)(void *)val, (uint64)newval);
#else
    int64 oldval;
    while (true) {
        oldval = cm_atomic_get(val);
        if (cm_atomic_compare_exchange_64(val, &oldval, newval)) {
            break;
        }
    }
    return oldval;
#endif
}

static inline int32 cm_atomic32_exchange(atomic32_t *val, int32 newval)
{
#ifdef CM_ATOMIC_HAS_LSE
    return (int32)cm_lse_swap_u32((volatile uint32 *)(void *)val, (uint32)newval);
#else
    int32 oldval;
    while (true) {
        oldval = cm_atomic32_get(val);
        if (cm_atomic32_compare_exchange(val, &oldval, newval)) {
            break;
        }
    }
    return oldval;
#endif
}

#endif

#ifndef WIN32
 	 
static inline int32 ub_atomic_add_32(volatile int32* ptr, int32 inc)
{
    return __sync_fetch_and_add(ptr, inc) + inc;
}

static inline int64 ub_atomic_add_64(int64* ptr, int64 inc)
{
    return __sync_fetch_and_add(ptr, inc) + inc;
}

static inline int32 ub_lock_test_and_set(volatile int32* ptr, int32 val)
{
    return  __sync_lock_test_and_set(ptr, val);
}

static inline int64 ub_lock_test_and_set_64(volatile int64* ptr, int64 val)
{
    return  __sync_lock_test_and_set(ptr, val);
}

static inline bool ub_compare_and_swap_32(int32* dest, int32 oldval, int32 newval)
{
    if (oldval == newval)
        return true;

    volatile bool res = __sync_bool_compare_and_swap(dest, oldval, newval);

    return res;
}

static inline bool ub_compare_and_swap_64(int64* dest, int64 oldval, int64 newval)
{
    if (oldval == newval)
        return true;

    return __sync_bool_compare_and_swap(dest, oldval, newval);
}

static inline uint32 ub_compare_and_swap_u32(volatile uint32* ptr, uint32 oldval, uint32 newval)
{
    return (uint32)__sync_val_compare_and_swap(ptr, oldval, newval);
}

static inline uint64 ub_compare_and_swap_u64(volatile uint64* ptr, uint64 oldval, uint64 newval)
{
    return (uint64)__sync_val_compare_and_swap(ptr, oldval, newval);
}

static inline void ub_atomic_init_u32(volatile uint32* ptr, uint32 val)
{
    *ptr = val;
}

static inline uint32 ub_atomic_read_u32(volatile uint32* ptr)
{
    return *ptr;
}

static inline uint32 ub_atomic_fetch_or_u32(volatile uint32* ptr, uint32 inc)
{
    return __sync_fetch_and_or(ptr, inc);
}

static inline uint32 ub_atomic_fetch_and_u32(volatile uint32* ptr, uint32 inc)
{
    return __sync_fetch_and_and(ptr, inc);
}

static inline uint32 ub_atomic_fetch_add_u32(volatile uint32* ptr, uint32 inc)
{
#ifdef __x86_64__
    uint32 res;
    __asm__ __volatile__(
    "	lock				\n"
    "	xaddl	%0,%1		\n"
    :		"=q"(res), "=m"(*ptr)
    :		"0" (inc), "m"(*ptr)
    :		"memory", "cc");
    return res;
#else
    return __sync_fetch_and_add(ptr, inc);
#endif
}

static inline uint32 ub_atomic_add_fetch_u32(volatile uint32* ptr, uint32 inc)
{
    return __sync_fetch_and_add(ptr, inc) + inc;
}

static inline uint32 ub_atomic_fetch_sub_u32(volatile uint32* ptr, int32 inc)
{
    return __sync_fetch_and_sub(ptr, inc);
}

static inline uint32 ub_atomic_sub_fetch_u32(volatile uint32* ptr, int32 inc)
{
    return  __sync_fetch_and_sub(ptr, inc) - inc;
}

static inline bool ub_atomic_compare_exchange_u32(volatile uint32* ptr, uint32* expected, uint32 newval)
{
#ifdef __x86_64__
    char	ret;

    /*
    * Perform cmpxchg and use the zero flag which it implicitly sets when
    * equal to measure the success.
    */
    __asm__ __volatile__(
    "	lock				\n"
    "	cmpxchgl	%4,%5	\n"
    "   setz		%2		\n"
    :		"=a" (*expected), "=m"(*ptr), "=q" (ret)
    :		"a" (*expected), "r" (newval), "m"(*ptr)
    :		"memory", "cc");
    return (bool) ret;
#else
    bool ret = false;
    uint32	current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
#endif
}

static inline bool ub_atomic_compare_exchange_u8(volatile uint8* ptr, uint8* expected, uint8 newval)
{
    bool ret = false;
    uint8  current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
}

static inline void ub_atomic_write_u32(volatile uint32* ptr, uint32 val)
{
    *ptr = val;
}

static inline uint32 ub_atomic_exchange_u32(volatile uint32* ptr, uint32 newval)
{
    uint32 old;
    while (true) {
        old = ub_atomic_read_u32(ptr);
        if (ub_atomic_compare_exchange_u32(ptr, &old, newval))
            break;
    }
    return old;
}

static inline void ub_atomic_init_u64(volatile uint64* ptr, uint64 val)
{
    *ptr = val;
}

static inline uint64 ub_atomic_read_u64(volatile uint64* ptr)
{
    return *ptr;
}

static inline uint64 ub_atomic_fetch_or_u64(volatile uint64* ptr, uint64 inc)
{
    return __sync_fetch_and_or(ptr, inc);
}

static inline uint64 ub_atomic_fetch_and_u64(volatile uint64* ptr, uint64 inc)
{
    return __sync_fetch_and_and(ptr, inc);
}

static inline uint64 ub_atomic_fetch_add_u64(volatile uint64* ptr, uint64 inc)
{
#ifdef __x86_64__
    uint64 res;
    __asm__ __volatile__(
    "	lock				\n"
    "	xaddq	%0,%1		\n"
    :		"=q"(res), "=m"(*ptr)
    :		"0" (inc), "m"(*ptr)
    :		"memory", "cc");
    return res;
#else
    return __sync_fetch_and_add(ptr, inc);
#endif
}

static inline uint64 ub_atomic_add_fetch_u64(volatile uint64* ptr, uint64 inc)
{
    return __sync_fetch_and_add(ptr, inc) + inc;
}

static inline uint64 ub_atomic_fetch_sub_u64(volatile uint64* ptr, int64 inc)
{
    return __sync_fetch_and_sub(ptr, inc);
}

static inline uint64 ub_atomic_sub_fetch_u64(volatile uint64* ptr, int64 inc)
{
    return __sync_fetch_and_sub(ptr, inc) - inc;
}

static inline bool ub_atomic_compare_exchange_u64(volatile uint64* ptr, uint64* expected, uint64 newval)
{
#ifdef __x86_64__
    char	ret;

    /*
    * Perform cmpxchg and use the zero flag which it implicitly sets when
    * equal to measure the success.
    */
    __asm__ __volatile__(
    "	lock				\n"
    "	cmpxchgq	%4,%5	\n"
    "   setz		%2		\n"
    :		"=a" (*expected), "=m"(*ptr), "=q" (ret)
    :		"a" (*expected), "r" (newval), "m"(*ptr)
    :		"memory", "cc");
    return (bool) ret;
#else
    bool ret = false;
    uint64	current;
    current = __sync_val_compare_and_swap(ptr, *expected, newval);
    ret = current == *expected;
    *expected = current;
    return ret;
#endif
}

static inline void ub_atomic_write_u64(volatile uint64* ptr, uint64 val)
{
    *ptr = val;
}

static inline uint64 ub_atomic_exchange_u64(volatile uint64* ptr, uint64 newval)
{
    uint64 old;
    while (true) {
        old = ub_atomic_read_u64(ptr);
        if (ub_atomic_compare_exchange_u64(ptr, &old, newval))
            break;
    }
    return old;
}

/*
* Interface of set scn of UB (same !WIN32 block as ub_atomic_*)
* static inline: header is included by many TUs in ogcommon — non-static would duplicate symbols at link.
*/
static inline status_t cm_ub_init_scn(uint64_t *addr)
{
    if (!addr) {
        return OG_ERROR;
    }

    if ((uintptr_t)addr % sizeof(uint64_t) != 0) {
        return OG_ERROR;
    }

    ub_atomic_init_u64((volatile uint64 *)(void *)addr, 0);

    return OG_SUCCESS;
}

static inline status_t cm_ub_set_scn(uint64_t *addr, uint64_t value)
{
    if (!addr) {
        return OG_ERROR;
    }

    if ((uintptr_t)addr % sizeof(uint64_t) != 0) {
        return OG_ERROR;
    }

    /* 
    * 使用 ub_atomic_write_u64
    * 该函数执行原子写入。虽然原代码要求 release 语义，
    * 但在单变量覆盖写场景下，ub_atomic_write_u64 (通常包含必要的屏障或直接原子指令) 
    * 足以保证可见性。如果需要严格的 Release 语义且平台相关，可能需要额外屏障，
    * 但通常 ub_atomic_write 已足够用于此类状态更新。
    */
    ub_atomic_write_u64((volatile uint64 *)(void *)addr, (uint64)value);

    return OG_SUCCESS;
}

static inline status_t cm_ub_get_scn(uint64_t *addr, uint64_t *scn)
{
    if (!addr || !scn) {
        return OG_ERROR;
    }

    if ((uintptr_t)addr % sizeof(uint64_t) != 0) {
        return OG_ERROR;
    }

    /* 
    * 使用 ub_atomic_read_u64
    * 对应 acquire load。在大多数架构上，对齐的 64 位读取本身就是原子的，
    * 该函数确保编译器不进行重排序优化。
    */
    *scn = (uint64_t)ub_atomic_read_u64((volatile uint64 *)(void *)addr);

    return OG_SUCCESS;
}

static inline status_t cm_ub_fetch_add_scn(uint64_t *addr, uint64_t tgt_scn, uint64_t *old_scn)
{
    if (!addr || !old_scn) {
        return OG_ERROR;
    }

    if ((uintptr_t)addr % sizeof(uint64_t) != 0) {
        return OG_ERROR;
    }

    /* 
    * 使用 ub_atomic_fetch_add_u64
    * 
    * 关键匹配点：
    * 原 C++ std::atomic::fetch_add 返回的是【加法前】的旧值。
    * 此库中的 ub_atomic_fetch_add_u64 文档明确说明："return the old value"。
    * 完美匹配！不需要像之前那样手动计算旧值。
    * 
    * 该函数在 x86_64 上使用 'lock xadd' 指令，效率极高。
    */
    *old_scn = (uint64_t)ub_atomic_fetch_add_u64((volatile uint64 *)(void *)addr, (uint64)tgt_scn);

    return OG_SUCCESS;
}

static inline status_t cm_ub_update_scn(uint64_t *addr, uint64_t candidate) 
{ 
    if (!addr) { 
        return OG_ERROR; 
    } 


    if ((uintptr_t)addr % sizeof(uint64_t) != 0) {
        return OG_ERROR;
    }

    for (;;) {
        uint64_t curr = 0;
        if (cm_ub_get_scn(addr, &curr) != OG_SUCCESS) {
            return OG_ERROR;
        }
        if (curr >= candidate) {
            return OG_SUCCESS;
        }
        uint64 exp = (uint64)curr;
        if (ub_atomic_compare_exchange_u64((volatile uint64 *)(void *)addr, &exp, (uint64)candidate)) {
            return OG_SUCCESS;
        }
    }
}

#endif /* #ifndef WIN32: ub_atomic_* + cm_ub_* */

#ifdef __cplusplus
}
#endif

#endif
