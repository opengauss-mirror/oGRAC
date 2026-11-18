/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) 2026 Huawei Technologies Co.,Ltd.
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
 * dtc_shmem_scn_sigbus.h
 *
 * SCN-only SIGBUS / ESB reliability helpers (not MES SHM path).
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn_sigbus.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef DTC_SHMEM_SCN_SIGBUS_H
#define DTC_SHMEM_SCN_SIGBUS_H

#include <setjmp.h>

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB) && !defined(WIN32)

#include <signal.h>

#define SHMEM_SCN_SIGBUS_JMP_POINT 1

/*
 * Kernel module redirect marker (si_errno). Keep aligned with openGauss CBB.
 */
#define SHMEM_SCN_UB_ESB_SIGBUS_REDIRECT_MARKER 0x55425201

extern __thread sigjmp_buf g_shmem_scn_sigbus_jump_env;
extern __thread bool8 g_shmem_scn_sigbus_jump_active;

/* Last SIGBUS snapshot (filled in handler; read after longjmp for OG_LOG). */
extern volatile sig_atomic_t g_shmem_scn_sigbus_hit_count;
extern volatile sig_atomic_t g_shmem_scn_sigbus_last_sig;
extern volatile sig_atomic_t g_shmem_scn_sigbus_last_code;
extern volatile sig_atomic_t g_shmem_scn_sigbus_last_errno;
extern volatile sig_atomic_t g_shmem_scn_sigbus_last_jump_active;
extern volatile sig_atomic_t g_shmem_scn_sigbus_last_ub_class;
extern volatile sig_atomic_t g_shmem_scn_sigbus_last_class_reason;
extern volatile uint64 g_shmem_scn_sigbus_last_addr;
extern volatile uint64 g_shmem_scn_sigbus_last_pc;

/*
 * Window-edge barrier: dsb nsh retires stores, then esb drains deferred aborts.
 */
#define SHMEM_SCN_ESB_BARRIER()                          \
    do {                                                 \
        __asm__ __volatile__("dsb nsh" ::: "memory");    \
        __asm__ __volatile__("esb" ::: "memory");        \
    } while (0)

status_t shmem_scn_sigbus_register(void);
/* Reinstall if blackbox/sigcap overwrote SIGBUS after first register. */
status_t shmem_scn_sigbus_ensure_registered(void);
void shmem_scn_sigbus_unregister(void);
void shmem_scn_sigbus_log_last_to_runlog(const char *site);

#else

#define SHMEM_SCN_ESB_BARRIER() ((void)0)

static inline status_t shmem_scn_sigbus_register(void)
{
    return OG_SUCCESS;
}

static inline status_t shmem_scn_sigbus_ensure_registered(void)
{
    return OG_SUCCESS;
}

static inline void shmem_scn_sigbus_unregister(void)
{
}

static inline void shmem_scn_sigbus_log_last_to_runlog(const char *site)
{
    (void)site;
}

#endif /* __aarch64__ && ENABLE_ARM64_ESB && !WIN32 */

#ifdef __cplusplus
}
#endif

#endif /* DTC_SHMEM_SCN_SIGBUS_H */
