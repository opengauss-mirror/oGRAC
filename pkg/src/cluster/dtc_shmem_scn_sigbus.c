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
 * dtc_shmem_scn_sigbus.c
 *
 * SCN UB SIGBUS handler: labeled classification (SI_KERNEL / redirect /
 * BUS_OBJERR), windowed siglongjmp, outside-window degrade / chain-old.
 *
 * IDENTIFICATION
 * src/cluster/dtc_shmem_scn_sigbus.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "dtc_shmem_scn_sigbus.h"

#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB) && !defined(WIN32)

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/syscall.h>

#include "cm_memory.h"

/* Defined in dtc_shmem_scn.c — signal path only does async-safe stores. */
extern volatile bool8 g_shmem_scn_degraded;
extern volatile uint64 *g_ub_global_scn;

__thread sigjmp_buf g_shmem_scn_sigbus_jump_env;
__thread bool8 g_shmem_scn_sigbus_jump_active = OG_FALSE;

static struct sigaction g_shmem_scn_old_sigbus_act;
static volatile sig_atomic_t g_shmem_scn_old_sigbus_act_valid = 0;
static volatile bool8 g_shmem_scn_sigbus_registered = OG_FALSE;

/* Dedicated diag fd (open at register). Async-safe write target besides stderr. */
static volatile sig_atomic_t g_shmem_scn_sigbus_diag_fd = -1;
#define SHMEM_SCN_SIGBUS_DIAG_PATH "/tmp/ograc_shmem_scn_sigbus.diag"

/* Last SIGBUS snapshot for post-longjmp OG_LOG (signal path only stores). */
volatile sig_atomic_t g_shmem_scn_sigbus_hit_count = 0;
volatile sig_atomic_t g_shmem_scn_sigbus_last_sig = 0;
volatile sig_atomic_t g_shmem_scn_sigbus_last_code = 0;
volatile sig_atomic_t g_shmem_scn_sigbus_last_errno = 0;
volatile sig_atomic_t g_shmem_scn_sigbus_last_jump_active = 0;
volatile sig_atomic_t g_shmem_scn_sigbus_last_ub_class = 0;
volatile sig_atomic_t g_shmem_scn_sigbus_last_class_reason = 0;
volatile uint64 g_shmem_scn_sigbus_last_addr = 0;
volatile uint64 g_shmem_scn_sigbus_last_pc = 0;

/* class_reason: 0 none, 1 SI_KERNEL, 2 BUS_OBJERR, 3 BUS_MCEERR_AR, 4 BUS_MCEERR_AO */
#define SHMEM_SCN_CLASS_NONE 0
#define SHMEM_SCN_CLASS_SI_KERNEL 1
#define SHMEM_SCN_CLASS_BUS_OBJERR 2
#define SHMEM_SCN_CLASS_BUS_MCEERR_AR 3
#define SHMEM_SCN_CLASS_BUS_MCEERR_AO 4

static void shmem_scn_sigbus_mark_degraded(void)
{
    (void)__atomic_store_n(&g_shmem_scn_degraded, OG_TRUE, __ATOMIC_RELEASE);
    g_ub_global_scn = NULL;
}

static void shmem_scn_sigbus_append_str(char *buf, uint32 *len, uint32 cap, const char *s)
{
    const char *p;

    for (p = s; *p != '\0' && *len + 1 < cap; p++) {
        buf[(*len)++] = *p;
    }
}

static void shmem_scn_sigbus_append_dec(char *buf, uint32 *len, uint32 cap, long val)
{
    char tmp[24];
    uint32 n = 0;
    int neg = 0;
    unsigned long u;

    if (val < 0) {
        neg = 1;
        u = (unsigned long)(-(val + 1)) + 1UL;
    } else {
        u = (unsigned long)val;
    }
    do {
        tmp[n++] = (char)('0' + (int)(u % 10UL));
        u /= 10UL;
    } while (u > 0UL && n < sizeof(tmp));
    if (neg && *len + 1 < cap) {
        buf[(*len)++] = '-';
    }
    while (n > 0 && *len + 1 < cap) {
        buf[(*len)++] = tmp[--n];
    }
}

static void shmem_scn_sigbus_fatal_append_hex(char *buf, uint32 *len, uint32 cap, const char *label, uint64 val)
{
    static const char hexdigits[] = "0123456789abcdef";
    const char *p;
    int shift;

    for (p = label; *p != '\0' && *len + 1 < cap; p++) {
        buf[(*len)++] = *p;
    }
    for (shift = 60; shift >= 0 && *len + 1 < cap; shift -= 4) {
        buf[(*len)++] = hexdigits[(uint32)((val >> (uint32)shift) & 0xfU)];
    }
}

static void shmem_scn_sigbus_write_diag(const char *buf, uint32 len)
{
    int fd;

    if (buf == NULL || len == 0) {
        return;
    }
    (void)write(STDERR_FILENO, buf, len);
    fd = (int)g_shmem_scn_sigbus_diag_fd;
    if (fd >= 0) {
        (void)write(fd, buf, len);
    }
}

/*
 * Async-signal-safe diagnostic: stderr + /tmp/ograc_shmem_scn_sigbus.diag.
 * OG_LOG is not signal-safe.
 */
static void shmem_scn_sigbus_log_event(int sig, siginfo_t *si, void *uc, const char *action,
    bool32 ub_class, int class_reason)
{
    char buf[640];
    uint32 len = 0;
    uint32 cap = (uint32)sizeof(buf);
    ucontext_t *ucp = (ucontext_t *)uc;
    int code = (si != NULL) ? si->si_code : -1;
    int err = (si != NULL) ? si->si_errno : -1;
    uint64 pc = (ucp != NULL) ? (uint64)ucp->uc_mcontext.pc : 0;
    uint64 addr = (si != NULL) ? (uint64)si->si_addr : 0;
    long tid = (long)syscall(SYS_gettid);
    int jump_active = (int)g_shmem_scn_sigbus_jump_active;
    int old_valid = (int)g_shmem_scn_old_sigbus_act_valid;
    int degraded = (int)g_shmem_scn_degraded;

    if (tid < 0) {
        tid = 0;
    }

    g_shmem_scn_sigbus_last_sig = (sig_atomic_t)sig;
    g_shmem_scn_sigbus_last_code = (sig_atomic_t)code;
    g_shmem_scn_sigbus_last_errno = (sig_atomic_t)err;
    g_shmem_scn_sigbus_last_jump_active = (sig_atomic_t)jump_active;
    g_shmem_scn_sigbus_last_ub_class = (sig_atomic_t)ub_class;
    g_shmem_scn_sigbus_last_class_reason = (sig_atomic_t)class_reason;
    g_shmem_scn_sigbus_last_addr = addr;
    g_shmem_scn_sigbus_last_pc = pc;
    (void)__atomic_add_fetch(&g_shmem_scn_sigbus_hit_count, 1, __ATOMIC_RELAXED);

    shmem_scn_sigbus_append_str(buf, &len, cap, "[SHMEM-SCN] SIGBUS handler:");
    shmem_scn_sigbus_append_str(buf, &len, cap, " tid=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, tid);
    shmem_scn_sigbus_append_str(buf, &len, cap, " sig=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)sig);
    shmem_scn_sigbus_append_str(buf, &len, cap, " code=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)code);
    shmem_scn_sigbus_fatal_append_hex(buf, &len, cap, "(0x", (uint64)(uint32)code);
    shmem_scn_sigbus_append_str(buf, &len, cap, ")");
    shmem_scn_sigbus_append_str(buf, &len, cap, " errno=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)err);
    shmem_scn_sigbus_fatal_append_hex(buf, &len, cap, "(0x", (uint64)(uint32)err);
    shmem_scn_sigbus_append_str(buf, &len, cap, ")");
    shmem_scn_sigbus_fatal_append_hex(buf, &len, cap, " addr=0x", addr);
    shmem_scn_sigbus_fatal_append_hex(buf, &len, cap, " pc=0x", pc);
    shmem_scn_sigbus_append_str(buf, &len, cap, " jump_active=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)jump_active);
    shmem_scn_sigbus_append_str(buf, &len, cap, " ub_class=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)ub_class);
    shmem_scn_sigbus_append_str(buf, &len, cap, " class_reason=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)class_reason);
    shmem_scn_sigbus_append_str(buf, &len, cap, " old_valid=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)old_valid);
    shmem_scn_sigbus_append_str(buf, &len, cap, " degraded=");
    shmem_scn_sigbus_append_dec(buf, &len, cap, (long)degraded);
    shmem_scn_sigbus_append_str(buf, &len, cap, " action=");
    shmem_scn_sigbus_append_str(buf, &len, cap, (action != NULL) ? action : "unknown");
    if (len + 1 < cap) {
        buf[len++] = '\n';
    }
    shmem_scn_sigbus_write_diag(buf, len);
}

static void shmem_scn_sigbus_fatal(int sig, siginfo_t *si, void *uc)
{
    struct sigaction dfl;

    shmem_scn_sigbus_log_event(sig, si, uc, "fatal_exit", OG_FALSE, SHMEM_SCN_CLASS_NONE);

    (void)memset_s(&dfl, sizeof(dfl), 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    (void)sigemptyset(&dfl.sa_mask);
    if (sigaction(sig, &dfl, NULL) == 0) {
        (void)raise(sig);
    }
    _exit(128 + sig);
}

static void shmem_scn_sigbus_chain_old(int sig, siginfo_t *si, void *uc)
{
    char note[128];
    uint32 len = 0;
    uint32 cap = (uint32)sizeof(note);

    shmem_scn_sigbus_append_str(note, &len, cap, "[SHMEM-SCN] SIGBUS chain_old begin old_valid=");
    shmem_scn_sigbus_append_dec(note, &len, cap, (long)g_shmem_scn_old_sigbus_act_valid);
    if (len + 1 < cap) {
        note[len++] = '\n';
    }
    shmem_scn_sigbus_write_diag(note, len);

    if (g_shmem_scn_old_sigbus_act_valid) {
        const struct sigaction *old = &g_shmem_scn_old_sigbus_act;

        if (old->sa_flags & SA_SIGINFO) {
            if (old->sa_sigaction != NULL) {
                old->sa_sigaction(sig, si, uc);
                return;
            }
        } else if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) {
            old->sa_handler(sig);
            return;
        }
    }
    shmem_scn_sigbus_fatal(sig, si, uc);
}

static int shmem_scn_sigbus_class_reason(const siginfo_t *si)
{
    if (si == NULL) {
        return SHMEM_SCN_CLASS_NONE;
    }
    if (si->si_code == SI_KERNEL &&
        (si->si_errno == 0 || si->si_errno == (int)SHMEM_SCN_UB_ESB_SIGBUS_REDIRECT_MARKER)) {
        return SHMEM_SCN_CLASS_SI_KERNEL;
    }
    if (si->si_code == BUS_OBJERR) {
        return SHMEM_SCN_CLASS_BUS_OBJERR;
    }
#ifdef BUS_MCEERR_AR
    if (si->si_code == BUS_MCEERR_AR) {
        return SHMEM_SCN_CLASS_BUS_MCEERR_AR;
    }
#endif
#ifdef BUS_MCEERR_AO
    if (si->si_code == BUS_MCEERR_AO) {
        return SHMEM_SCN_CLASS_BUS_MCEERR_AO;
    }
#endif
    return SHMEM_SCN_CLASS_NONE;
}

static bool32 shmem_scn_sigbus_is_ub_class(const siginfo_t *si, int *reason_out)
{
    int reason = shmem_scn_sigbus_class_reason(si);

    if (reason_out != NULL) {
        *reason_out = reason;
    }
    /* Recoverable today: SI_KERNEL / BUS_OBJERR only (MCEERR still logged via reason). */
    if (reason == SHMEM_SCN_CLASS_SI_KERNEL || reason == SHMEM_SCN_CLASS_BUS_OBJERR) {
        return OG_TRUE;
    }
    return OG_FALSE;
}

static void shmem_scn_sigbus_handler(int sig, siginfo_t *si, void *uc)
{
    int class_reason = SHMEM_SCN_CLASS_NONE;
    bool32 ub_class;

    /* Entry: always log before any branch. */
    shmem_scn_sigbus_log_event(sig, si, uc, "enter", OG_FALSE, SHMEM_SCN_CLASS_NONE);

    ub_class = (sig == SIGBUS) ? shmem_scn_sigbus_is_ub_class(si, &class_reason) : OG_FALSE;

    if (ub_class) {
        if (g_shmem_scn_sigbus_jump_active) {
            shmem_scn_sigbus_log_event(sig, si, uc, "siglongjmp", ub_class, class_reason);
            siglongjmp(g_shmem_scn_sigbus_jump_env, SHMEM_SCN_SIGBUS_JMP_POINT);
        }

        shmem_scn_sigbus_mark_degraded();

        if (si != NULL && si->si_code == SI_KERNEL &&
            si->si_errno == (int)SHMEM_SCN_UB_ESB_SIGBUS_REDIRECT_MARKER) {
            shmem_scn_sigbus_log_event(sig, si, uc, "degrade_return_redirect", ub_class, class_reason);
            return;
        }

        shmem_scn_sigbus_log_event(sig, si, uc, "degrade_chain_old", ub_class, class_reason);
        shmem_scn_sigbus_chain_old(sig, si, uc);
        return;
    }

    shmem_scn_sigbus_log_event(sig, si, uc, "non_ub_chain_old", ub_class, class_reason);
    shmem_scn_sigbus_chain_old(sig, si, uc);
}

void shmem_scn_sigbus_log_last_to_runlog(const char *site)
{
    OG_LOG_RUN_WAR("[SHMEM-SCN] last SIGBUS snapshot at %s: hit=%d sig=%d code=%d errno=%d "
                   "jump_active=%d ub_class=%d class_reason=%d addr=0x%llx pc=0x%llx",
        (site != NULL) ? site : "unknown",
        (int)g_shmem_scn_sigbus_hit_count,
        (int)g_shmem_scn_sigbus_last_sig,
        (int)g_shmem_scn_sigbus_last_code,
        (int)g_shmem_scn_sigbus_last_errno,
        (int)g_shmem_scn_sigbus_last_jump_active,
        (int)g_shmem_scn_sigbus_last_ub_class,
        (int)g_shmem_scn_sigbus_last_class_reason,
        (unsigned long long)g_shmem_scn_sigbus_last_addr,
        (unsigned long long)g_shmem_scn_sigbus_last_pc);
}

status_t shmem_scn_sigbus_register(void)
{
    struct sigaction sa;
    struct sigaction old_sa;
    errno_t ret;
    int diag_fd;
    bool8 reinstall = OG_FALSE;

    if (g_shmem_scn_sigbus_registered) {
        if (sigaction(SIGBUS, NULL, &old_sa) == 0 &&
            (old_sa.sa_flags & SA_SIGINFO) &&
            old_sa.sa_sigaction == shmem_scn_sigbus_handler) {
            return OG_SUCCESS;
        }
        /*
         * Instance startup calls sigcap_handle_reg() again after dtc_startup(),
         * which overwrites SIGBUS with blackbox. Re-wrap the current handler.
         */
        OG_LOG_RUN_WAR("[SHMEM-SCN] SIGBUS handler was overwritten, reinstalling");
        g_shmem_scn_sigbus_registered = OG_FALSE;
        reinstall = OG_TRUE;
    }

    ret = memset_s(&sa, sizeof(sa), 0, sizeof(sa));
    if (ret != EOK) {
        return OG_ERROR;
    }
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = shmem_scn_sigbus_handler;
    (void)sigemptyset(&sa.sa_mask);

    if (sigaction(SIGBUS, NULL, &old_sa) != 0) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] get old SIGBUS handler failed, errno=%d", errno);
        return OG_ERROR;
    }
    if (!((old_sa.sa_flags & SA_SIGINFO) && old_sa.sa_sigaction == shmem_scn_sigbus_handler)) {
        g_shmem_scn_old_sigbus_act = old_sa;
        g_shmem_scn_old_sigbus_act_valid = 1;
    }

    if (g_shmem_scn_sigbus_diag_fd < 0) {
        diag_fd = open(SHMEM_SCN_SIGBUS_DIAG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (diag_fd >= 0) {
            g_shmem_scn_sigbus_diag_fd = diag_fd;
        } else {
            OG_LOG_RUN_WAR("[SHMEM-SCN] open diag file %s failed, errno=%d (stderr only)",
                SHMEM_SCN_SIGBUS_DIAG_PATH, errno);
        }
    }

    if (sigaction(SIGBUS, &sa, NULL) != 0) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sigaction SIGBUS failed, errno=%d", errno);
        if (!reinstall && g_shmem_scn_sigbus_diag_fd >= 0) {
            (void)close((int)g_shmem_scn_sigbus_diag_fd);
            g_shmem_scn_sigbus_diag_fd = -1;
        }
        return OG_ERROR;
    }

    g_shmem_scn_sigbus_registered = OG_TRUE;
    OG_LOG_RUN_INF("[SHMEM-SCN] labeled SIGBUS handler %s, old_valid=%d, "
                   "old_sa_flags=0x%x, diag=%s fd=%d (also stderr→ogracstatus.log)",
        reinstall ? "reinstalled" : "registered",
        (int)g_shmem_scn_old_sigbus_act_valid,
        (unsigned)old_sa.sa_flags,
        SHMEM_SCN_SIGBUS_DIAG_PATH,
        (int)g_shmem_scn_sigbus_diag_fd);
    return OG_SUCCESS;
}

status_t shmem_scn_sigbus_ensure_registered(void)
{
    if (!g_shmem_scn_sigbus_registered) {
        return OG_SUCCESS;
    }
    return shmem_scn_sigbus_register();
}

void shmem_scn_sigbus_unregister(void)
{
    int fd;

    if (g_shmem_scn_sigbus_registered && g_shmem_scn_old_sigbus_act_valid) {
        (void)sigaction(SIGBUS, &g_shmem_scn_old_sigbus_act, NULL);
        g_shmem_scn_old_sigbus_act_valid = 0;
        g_shmem_scn_sigbus_registered = OG_FALSE;
    }
    fd = (int)g_shmem_scn_sigbus_diag_fd;
    if (fd >= 0) {
        (void)close(fd);
        g_shmem_scn_sigbus_diag_fd = -1;
    }
}

#endif /* __aarch64__ && ENABLE_ARM64_ESB && !WIN32 */
