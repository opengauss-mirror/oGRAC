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
 * cm_futex.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_futex.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_FUTEX_H__
#define __CM_FUTEX_H__

#ifdef WIN32
#error "cm_futex.h: futex is a Linux-only primitive, WIN32 is not supported"
#else

#include <sys/syscall.h>
#include <unistd.h>
#include <linux/futex.h>
#include <time.h>
#include <errno.h>
#include "cm_atomic.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_FUTEX_INIT          0
#define CM_FUTEX_POSTED        1
#define CM_FUTEX_SPIN_COUNT    100
#define CM_FUTEX_MS_PER_SEC    1000
#define CM_FUTEX_NS_PER_MS     1000000L
#define CM_FUTEX_WAKE_ALL      ((uint32)0x7fffffff)

typedef struct st_cm_futex_args {
    atomic32_t *uaddr;
    int32 op;
    uint32 val;
    const struct timespec *utime;
    atomic32_t *uaddr2;
    int32 val3;
} cm_futex_args_t;

static inline int cm_futex_syscall(const cm_futex_args_t *args)
{
    return (int)syscall(SYS_futex, args->uaddr, args->op | FUTEX_PRIVATE_FLAG, args->val,
                        args->utime, args->uaddr2, args->val3);
}

static inline void cm_futex_rel_timeout_ms(struct timespec *ts, uint32 timeout_ms)
{
    ts->tv_sec = (time_t)(timeout_ms / CM_FUTEX_MS_PER_SEC);
    ts->tv_nsec = (long)(timeout_ms % CM_FUTEX_MS_PER_SEC) * CM_FUTEX_NS_PER_MS;
}

static inline void cm_futex_init(atomic32_t *futex_addr)
{
    (void)cm_atomic32_set(futex_addr, CM_FUTEX_INIT);
}

static inline HOT_FUNCTION bool32 cm_futex_wait(atomic32_t *futex_addr, uint32 timeout_ms)
{
    struct timespec rel_tv;
    struct timespec *ptv = NULL;
    cm_futex_args_t args;
    uint32 retry = 0;
    int32 ret;

    if (timeout_ms != 0) {
        cm_futex_rel_timeout_ms(&rel_tv, timeout_ms);
        ptv = &rel_tv;
    }

    while (retry++ < CM_FUTEX_SPIN_COUNT) {
        if (cm_atomic32_cas(futex_addr, CM_FUTEX_POSTED, CM_FUTEX_INIT)) {
            return OG_TRUE;
        }
        CM_RELEASE_CPU;
    }

    args.uaddr = futex_addr;
    args.op = FUTEX_WAIT;
    args.val = CM_FUTEX_INIT;
    args.utime = ptv;
    args.uaddr2 = NULL;
    args.val3 = 0;

    for (;;) {
        if (cm_atomic32_cas(futex_addr, CM_FUTEX_POSTED, CM_FUTEX_INIT)) {
            return OG_TRUE;
        }

        ret = cm_futex_syscall(&args);
        if (ret == 0) {
            if (cm_atomic32_cas(futex_addr, CM_FUTEX_POSTED, CM_FUTEX_INIT)) {
                return OG_TRUE;
            }
            continue;
        }

        if (errno == EINTR || errno == EAGAIN) {
            if (cm_atomic32_cas(futex_addr, CM_FUTEX_POSTED, CM_FUTEX_INIT)) {
                return OG_TRUE;
            }
            continue;
        }
        return OG_FALSE;
    }
}

static inline HOT_FUNCTION void cm_futex_wake(atomic32_t *futex_addr, uint32 max_wait_count)
{
    cm_futex_args_t args;

    if (cm_atomic32_get(futex_addr) != CM_FUTEX_POSTED) {
        (void)cm_atomic32_cas(futex_addr, CM_FUTEX_INIT, CM_FUTEX_POSTED);
    }

    args.uaddr = futex_addr;
    args.op = FUTEX_WAKE;
    args.val = max_wait_count;
    args.utime = NULL;
    args.uaddr2 = NULL;
    args.val3 = 0;

    (void)cm_futex_syscall(&args);
}

/*
 * Generation futex: wait until the 32-bit word != expected, or timeout.
 * expected is the raw futex word (kernel compares u32, not signed magnitude).
 * Do not mix with cm_futex_wait/wake (those treat the word as POSTED/INIT).
 */
static inline HOT_FUNCTION bool32 cm_futex_wait_value(atomic32_t *futex_addr, uint32 expected, uint32 timeout_ms)
{
    struct timespec rel_tv;
    struct timespec *ptv = NULL;
    cm_futex_args_t args;
    uint32 retry = 0;
    int32 ret;

    while (retry++ < CM_FUTEX_SPIN_COUNT) {
        if ((uint32)cm_atomic32_get(futex_addr) != expected) {
            return OG_TRUE;
        }
        CM_RELEASE_CPU;
    }

    if (timeout_ms != 0) {
        cm_futex_rel_timeout_ms(&rel_tv, timeout_ms);
        ptv = &rel_tv;
    }

    args.uaddr = futex_addr;
    args.op = FUTEX_WAIT;
    args.val = expected;
    args.utime = ptv;
    args.uaddr2 = NULL;
    args.val3 = 0;

    for (;;) {
        if ((uint32)cm_atomic32_get(futex_addr) != expected) {
            return OG_TRUE;
        }

        ret = cm_futex_syscall(&args);
        if (ret == 0 || errno == EAGAIN) {
            return OG_TRUE;
        }
        if (errno == EINTR) {
            continue;
        }
        return OG_FALSE;
    }
}

static inline HOT_FUNCTION void cm_futex_wake_value(atomic32_t *futex_addr, uint32 max_wait_count)
{
    cm_futex_args_t args;

    args.uaddr = futex_addr;
    args.op = FUTEX_WAKE;
    args.val = max_wait_count;
    args.utime = NULL;
    args.uaddr2 = NULL;
    args.val3 = 0;

    (void)cm_futex_syscall(&args);
}

#ifdef __cplusplus
}
#endif

#endif

#endif
