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
 * cm_atomic_lse.h
 *
 * ARM LSE (ARMv8.1 Large System Extension) primitives for cm_atomic.h.
 * Included from cm_atomic.h after uint128_u is defined. Do not include alone.
 *
 * GCC 8+ sets __ARM_FEATURE_ATOMICS when compiling with +lse. GCC 7.3 on
 * Hi1620/Kunpeng does not, and its assembler rejects LSE opcodes unless
 * .arch_extension lse is emitted. USE_H1620 is the CMake flag for that path.
 *
 * Semantics (match ARM ARM / Linux LSE):
 *   casal    — val-CAS, returns the value observed in memory
 *   ldaddal  — fetch_add, returns the old value
 *   ldclral  — fetch_and with inverted mask, returns the old value
 *   ldsetal  — fetch_or, returns the old value
 *   swpal    — exchange, returns the old value
 *   caspal   — 128-bit val-CAS; Xs/X(s+1) and Xt/X(t+1) must be even/odd pairs
 *
 * IDENTIFICATION
 * src/common/cm_atomic_lse.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ATOMIC_LSE_H__
#define __CM_ATOMIC_LSE_H__

#if defined(__aarch64__)

#if defined(__ARM_FEATURE_ATOMICS) || defined(USE_H1620)
#define CM_ATOMIC_HAS_LSE 1
#endif

#ifdef CM_ATOMIC_HAS_LSE

#define CM_ATOMIC_LSE_ARCH ".arch_extension lse\n"

static inline __attribute__((always_inline)) uint32 cm_lse_cas_u32(volatile uint32 *ptr, uint32 oldval, uint32 newval)
{
    uint32 old = oldval;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "casal %w[old], %w[new], %[mem]\n"
                         : [old] "+r"(old), [mem] "+Q"(*ptr)
                         : [new] "r"(newval)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint64 cm_lse_cas_u64(volatile uint64 *ptr, uint64 oldval, uint64 newval)
{
    uint64 old = oldval;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "casal %x[old], %x[new], %[mem]\n"
                         : [old] "+r"(old), [mem] "+Q"(*ptr)
                         : [new] "r"(newval)
                         : "memory");
    return old;
}

/*
 * 128-bit CASPAL. Registers are hard-wired to x0-x3 so the even/odd pairing
 * required by CASP cannot be broken by the register allocator. always_inline
 * keeps those bindings from colliding with a real function frame.
 * Returns the value observed in memory (equal to oldval on success).
 */
static inline __attribute__((always_inline)) uint128_u cm_lse_cas_u128(volatile uint128_u *ptr, uint128_u oldval,
                                                                       uint128_u newval)
{
    register uint64 old_lo __asm__("x0") = oldval.u64[0];
    register uint64 old_hi __asm__("x1") = oldval.u64[1];
    register uint64 new_lo __asm__("x2") = newval.u64[0];
    register uint64 new_hi __asm__("x3") = newval.u64[1];
    uint128_u old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH
                         "caspal %x[old_lo], %x[old_hi], %x[new_lo], %x[new_hi], [%[ptr]]\n"
                         : [old_lo] "+r"(old_lo), [old_hi] "+r"(old_hi)
                         : [new_lo] "r"(new_lo), [new_hi] "r"(new_hi), [ptr] "r"(ptr)
                         : "memory");

    old.u64[0] = old_lo;
    old.u64[1] = old_hi;
    return old;
}

static inline __attribute__((always_inline)) uint32 cm_lse_fetch_add_u32(volatile uint32 *ptr, uint32 addend)
{
    uint32 old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "ldaddal %w[add], %w[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [add] "r"(addend)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint64 cm_lse_fetch_add_u64(volatile uint64 *ptr, uint64 addend)
{
    uint64 old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "ldaddal %x[add], %x[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [add] "r"(addend)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint32 cm_lse_fetch_sub_u32(volatile uint32 *ptr, uint32 subtrahend)
{
    return cm_lse_fetch_add_u32(ptr, (uint32)(0U - subtrahend));
}

static inline __attribute__((always_inline)) uint64 cm_lse_fetch_sub_u64(volatile uint64 *ptr, uint64 subtrahend)
{
    return cm_lse_fetch_add_u64(ptr, 0ULL - subtrahend);
}

static inline __attribute__((always_inline)) uint32 cm_lse_fetch_and_u32(volatile uint32 *ptr, uint32 mask)
{
    uint32 old;
    uint32 clr = ~mask;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "ldclral %w[clr], %w[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [clr] "r"(clr)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint64 cm_lse_fetch_and_u64(volatile uint64 *ptr, uint64 mask)
{
    uint64 old;
    uint64 clr = ~mask;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "ldclral %x[clr], %x[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [clr] "r"(clr)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint32 cm_lse_fetch_or_u32(volatile uint32 *ptr, uint32 mask)
{
    uint32 old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "ldsetal %w[set], %w[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [set] "r"(mask)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint64 cm_lse_fetch_or_u64(volatile uint64 *ptr, uint64 mask)
{
    uint64 old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "ldsetal %x[set], %x[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [set] "r"(mask)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint32 cm_lse_swap_u32(volatile uint32 *ptr, uint32 newval)
{
    uint32 old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "swpal %w[new], %w[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [new] "r"(newval)
                         : "memory");
    return old;
}

static inline __attribute__((always_inline)) uint64 cm_lse_swap_u64(volatile uint64 *ptr, uint64 newval)
{
    uint64 old;

    __asm__ __volatile__(CM_ATOMIC_LSE_ARCH "swpal %x[new], %x[old], %[mem]\n"
                         : [old] "=r"(old), [mem] "+Q"(*ptr)
                         : [new] "r"(newval)
                         : "memory");
    return old;
}

#endif /* CM_ATOMIC_HAS_LSE */

#endif /* __aarch64__ */

#endif
