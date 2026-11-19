/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * oGRAC is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "knl_cluster_module.h"
#include "dtc_drc.h"
#include "dtc_shmem_scn.h"
#include "dtc_remote_buffer.h"
#include "cm_utils.h"
#include "cm_memory.h"
#include "knl_context.h"
#include "srv_instance.h"
#ifndef WIN32
#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/mman.h>
#endif
#include "cm_checksum.h"
#include "cm_device.h"
#include "cm_file.h"
#include "cm_thread.h"
#include "cm_system.h"
#include "cm_spinlock.h"
#include "cm_ubs_mem.h"
#include "mes_func.h"
#include "mes_tcp.h"
#include "cms_interface.h"
#include "knl_database.h"
#include "knl_interface.h"
#include "dtc_shmem_scn_sigbus.h"

#ifndef WIN32
volatile uint64 *g_ub_global_scn = NULL;
#endif

#define SHMEM_SCN_ALIGN_128M ((uint64)SIZE_M(128))
#define SHMEM_SCN_SHM_SIZE (((uint64)(SHMEM_SCN_SIZE) + SHMEM_SCN_ALIGN_128M - 1) & ~(SHMEM_SCN_ALIGN_128M - 1))
#define SHMEM_SCN_ALLOC_FLAGS (UBSM_FLAG_WR_DELAY_COMP | UBSM_FLAG_ONLY_IMPORT_NONCACHE)
#define SHMEM_SCN_DEALLOC_RETRY 30
#define SHMEM_SCN_DEALLOC_WAIT_MS 1000
/* Wall-clock SCN jumps ~2^32 per second even when idle; persist by time, not seq+10000. */
#define SHMEM_SCN_PERSIST_INTERVAL_MS 1000
#define SHMEM_SCN_PERSIST_SLEEP_MS 100
#define SHMEM_SCN_FILE_PATH "+vg1/scn"
#define SHMEM_SCN_FILE_MAGIC 0x314E4353u /* "SCN1" */
/* v2: per-node ping-pong slots, no cross-node dlock (fixes PR #509 #2/#5). */
#define SHMEM_SCN_FILE_VERSION 2
#define SHMEM_SCN_FILE_SLOT_SIZE FILE_BLOCK_SIZE_4096
#define SHMEM_SCN_FILE_SLOT_COUNT 2 /* ping-pong slots per node */
#define SHMEM_SCN_FALLBACK_GUARD_SECONDS 2ULL
#define SHMEM_SCN_FALLBACK_NOTIFY_RETRY_MAX 10U
#define SHMEM_SCN_FALLBACK_RETRY_DELAY_MIN_MS 100U
#define SHMEM_SCN_FALLBACK_RETRY_DELAY_MAX_MS 2000U
/*
 * Layout: slot[node][ping], no shared lease block.
 * Each node writes only its own pair — no cross-node CAS/lease clock.
 */
#define SHMEM_SCN_OFF_NODE_SLOT(node, ping) \
    (((uint64)(node) * (uint64)SHMEM_SCN_FILE_SLOT_COUNT + (uint64)(ping)) * \
        (uint64)SHMEM_SCN_FILE_SLOT_SIZE)
#define SHMEM_SCN_PERSIST_FILE_SIZE \
    ((uint64)OG_MAX_INSTANCES * (uint64)SHMEM_SCN_FILE_SLOT_COUNT * (uint64)SHMEM_SCN_FILE_SLOT_SIZE)
/* Legacy v1 offsets (dlock 8K + 2 global slots) — read-only migration seed. */
#define SHMEM_SCN_V1_OFF_SLOT0 SIZE_K(8)
#define SHMEM_SCN_IO_BUF_SIZE SHMEM_SCN_FILE_SLOT_SIZE

typedef struct st_shmem_scn_file_slot {
    uint32 magic;
    uint32 version;
    uint64 scn;
    uint64 seq;
    uint32 checksum;
    uint8 reserved[SHMEM_SCN_FILE_SLOT_SIZE - 28];
} shmem_scn_file_slot_t;

static thread_t g_shmem_scn_persist_thread = { 0 };
static knl_session_t *g_shmem_scn_persist_session = NULL;
static bool32 g_shmem_scn_persist_started = OG_FALSE;
static knl_scn_t g_shmem_scn_last_persisted = 0;
static char g_shmem_scn_file_name[OG_FILE_NAME_BUFFER_SIZE] = { 0 };
static device_type_t g_shmem_scn_file_type = DEV_TYPE_FILE;
static int32 g_shmem_scn_file_handle = OG_INVALID_HANDLE;
static aligned_buf_t g_shmem_scn_io_buf = { 0 };
/* Serializes all users of g_shmem_scn_io_buf (persist thread vs fallback worker). */
static spinlock_t g_shmem_scn_file_io_lock = 0;
static uint64 g_shmem_scn_file_seq = 0; /* local node's last written ping-pong seq */
/* Non-static: dtc_shmem_scn_sigbus.c marks degrade from the signal path. */
volatile bool8 g_shmem_scn_degraded = OG_FALSE;
static volatile uint64 g_shmem_scn_fallback_seed = 0;
static thread_t g_shmem_scn_fallback_thread = { 0 };
static volatile bool8 g_shmem_scn_fallback_thread_started = OG_FALSE;
static bool32 g_shmem_scn_fallback_notify_peers = OG_FALSE;
static uint32 g_shmem_scn_fallback_peer_src = 0;

static status_t shmem_scn_file_load_best(knl_scn_t *scn, uint64 *seq);
static void shmem_scn_stop_persist(void);
static void shmem_scn_unmap_node(uint32 node_id);

CM_STATIC_ASSERT(sizeof(shmem_scn_slot_t) == SHMEM_SCN_SIZE);
CM_STATIC_ASSERT((SHMEM_SCN_SIZE % SHMEM_SCN_SLOT_ALIGN) == 0);
CM_STATIC_ASSERT(DRC_SHMEM_SCN_SIZE == SHMEM_SCN_SIZE);
CM_STATIC_ASSERT(sizeof(shmem_scn_file_slot_t) == SHMEM_SCN_FILE_SLOT_SIZE);
CM_STATIC_ASSERT(SHMEM_SCN_NAME_LEN == MAX_REGION_NAME_DESC_LENGTH);
CM_STATIC_ASSERT(SHMEM_SCN_NAME_LEN == MAX_SHM_NAME_LENGTH);

static bool32 shmem_scn_enabled(void)
{
    if (g_instance == NULL) {
        return OG_FALSE;
    }
    /* GBP path (_ENABLE_UBSMEM) or dedicated SCN-only path (_ENABLE_SCN_UBSMEM). */
    return (g_instance->kernel.attr.enable_ubsmem || g_instance->kernel.attr.enable_scn_ubsmem) ?
        OG_TRUE : OG_FALSE;
}

bool32 shmem_scn_use_dedicated_ub(void)
{
    /*
     * Dedicated SCN UB only when GBP is off. With _ENABLE_UBSMEM, SCN always
     * lives in remote SGA regardless of _ENABLE_SCN_UBSMEM.
     */
    return (g_instance != NULL && !g_instance->kernel.attr.enable_ubsmem &&
        g_instance->kernel.attr.enable_scn_ubsmem) ? OG_TRUE : OG_FALSE;
}

static inline shmem_scn_mgr_t *shmem_scn_mgr(void)
{
    return &DRC_RES_CTX->shmem_scn_mgr;
}

static inline remote_sga_t *shmem_scn_remote_sga(void)
{
    return &DRC_RES_CTX->remote_sga;
}

static uint32 shmem_scn_node_count(void)
{
    uint32 node_count;

    if (g_instance == NULL) {
        return 0;
    }

    node_count = g_instance->kernel.db.ctrl.core.node_count;
    if (node_count == 0 || node_count > OG_MAX_INSTANCES) {
        return 0;
    }
    return node_count;
}

static knl_scn_t shmem_scn_read_local(void)
{
    if (g_instance == NULL) {
        return KNL_INVALID_SCN;
    }

    return KNL_GET_SCN(&g_instance->kernel.scn);
}

static void shmem_scn_raise_local(knl_scn_t scn)
{
    if (g_instance == NULL) {
        return;
    }
    knl_set_ub_scn_local(&g_instance->kernel.scn, scn);
}

uint32 shmem_scn_get_owner_id(void)
{
    if (g_instance == NULL) {
        return OG_INVALID_ID32;
    }
    return g_instance->kernel.id;
}

bool32 shmem_scn_is_owner(void)
{
    if (!shmem_scn_enabled() || g_instance == NULL || g_shmem_scn_degraded) {
        return OG_FALSE;
    }
    return (shmem_scn_mgr()->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;
}

static void shmem_scn_publish(shmem_scn_slot_t *slot, uint32 owner_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    mgr->global_scn_slot = slot;
    mgr->owner_id = owner_id;
#ifndef WIN32
    CM_MFENCE;
    g_ub_global_scn = &slot->value;
#endif
}

static void shmem_scn_unpublish(void)
{
#ifndef WIN32
    g_ub_global_scn = NULL;
    CM_MFENCE;
#endif
    shmem_scn_mgr()->global_scn_slot = NULL;
    shmem_scn_mgr()->owner_id = OG_INVALID_ID32;
}

static uint32 shmem_scn_fallback_backoff(uint32 delay_ms)
{
    uint32 next = delay_ms * 2U;
    return (next > SHMEM_SCN_FALLBACK_RETRY_DELAY_MAX_MS) ? SHMEM_SCN_FALLBACK_RETRY_DELAY_MAX_MS : next;
}

static void shmem_scn_raise_kernel(knl_scn_t scn)
{
    if (g_instance == NULL || scn == KNL_INVALID_SCN) {
        return;
    }
    if (scn > KNL_GET_SCN(&g_instance->kernel.scn)) {
        KNL_SET_SCN(&g_instance->kernel.scn, scn);
    }
}

/*
 * seed = max(persist_scn + 2s, hint, kernel->scn, prior fallback seed).
 * Persist lag is ~1s; +2s covers lag + switch window without reading dead UB.
 * read_file: refresh from +vg1/scn (worker path only; avoid I/O on fault catch).
 */
static knl_scn_t shmem_scn_compute_fallback_seed(knl_scn_t hint_scn, bool32 read_file)
{
    knl_scn_t persist_scn = g_shmem_scn_last_persisted;
    knl_scn_t file_scn = KNL_INVALID_SCN;
    uint64 file_seq = 0;
    knl_scn_t seed;
    knl_scn_t prior;

    if (read_file && g_shmem_scn_file_handle != OG_INVALID_HANDLE &&
        shmem_scn_file_load_best(&file_scn, &file_seq) == OG_SUCCESS && file_scn > persist_scn) {
        persist_scn = file_scn;
    }

    seed = persist_scn + (SHMEM_SCN_FALLBACK_GUARD_SECONDS << 32);
    if (hint_scn > seed) {
        seed = hint_scn;
    }
    if (g_instance != NULL) {
        knl_scn_t local = KNL_GET_SCN(&g_instance->kernel.scn);
        if (local > seed) {
            seed = local;
        }
    }
    prior = (knl_scn_t)__atomic_load_n(&g_shmem_scn_fallback_seed, __ATOMIC_ACQUIRE);
    if (prior > seed) {
        seed = prior;
    }
    return seed;
}

static void shmem_scn_apply_fallback_seed(knl_scn_t hint_scn, bool32 read_file)
{
    knl_scn_t seed = shmem_scn_compute_fallback_seed(hint_scn, read_file);
    uint64 expected = __atomic_load_n(&g_shmem_scn_fallback_seed, __ATOMIC_ACQUIRE);

    while (seed > (knl_scn_t)expected) {
        if (__atomic_compare_exchange_n(&g_shmem_scn_fallback_seed, &expected, (uint64)seed, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            break;
        }
    }
    seed = (knl_scn_t)__atomic_load_n(&g_shmem_scn_fallback_seed, __ATOMIC_ACQUIRE);
    shmem_scn_raise_kernel(seed);
    OG_LOG_RUN_WAR("[SHMEM-SCN] fallback seed applied, seed=%llu persist=%llu hint=%llu",
        (uint64)seed, (uint64)g_shmem_scn_last_persisted, (uint64)hint_scn);
}

static void shmem_scn_notify_peers_fallback(uint64 seed_scn)
{
    uint32 node_count = shmem_scn_node_count();
    uint32 self_id;
    uint32 i;

    if (g_instance == NULL || node_count == 0) {
        return;
    }
    self_id = g_instance->kernel.id;

    for (i = 0; i < node_count; i++) {
        uint32 delay_ms;
        bool8 notified;
        uint32 attempt;

        if (i == self_id) {
            continue;
        }
        delay_ms = SHMEM_SCN_FALLBACK_RETRY_DELAY_MIN_MS;
        notified = OG_FALSE;
        for (attempt = 1; attempt <= SHMEM_SCN_FALLBACK_NOTIFY_RETRY_MAX; attempt++) {
            if (mes_tcp_send_scn_fallback_notify(i, seed_scn) == OG_SUCCESS) {
                notified = OG_TRUE;
                break;
            }
            cm_sleep(delay_ms);
            delay_ms = shmem_scn_fallback_backoff(delay_ms);
        }
        if (!notified) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] fallback notify to inst %u failed after %u attempts", i,
                SHMEM_SCN_FALLBACK_NOTIFY_RETRY_MAX);
        }
    }
}

/*
 * Fault degrade keeps UB mappings until shmem_scn_cleanup() (process exit / full
 * shutdown). Aligns with openGauss: unpublish + gate access only; do not unmap
 * while sessions may still hold a local copy of g_ub_global_scn.
 */
static void shmem_scn_run_fallback_sequence(bool32 notify_peers, uint32 peer_src)
{
    uint64 seed;

    (void)peer_src;
    /* Refresh seed from persist file now that we are off the fault path. */
    shmem_scn_apply_fallback_seed((knl_scn_t)__atomic_load_n(&g_shmem_scn_fallback_seed, __ATOMIC_ACQUIRE),
        OG_TRUE);
    seed = __atomic_load_n(&g_shmem_scn_fallback_seed, __ATOMIC_ACQUIRE);

    if (notify_peers) {
        shmem_scn_notify_peers_fallback(seed);
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] fallback sequence done (maps kept until cleanup), seed=%llu notify=%u",
        seed, (uint32)notify_peers);
}

static void shmem_scn_fallback_worker_entry(thread_t *thread)
{
    bool32 notify_peers = g_shmem_scn_fallback_notify_peers;
    uint32 peer_src = g_shmem_scn_fallback_peer_src;

    (void)thread;
    cm_set_thread_name("scn_fallback");
    OG_LOG_RUN_INF("[SHMEM-SCN] fallback worker started (trigger=%s peer=%u)",
        notify_peers ? "local_fault" : "peer_notify", peer_src);

    shmem_scn_run_fallback_sequence(notify_peers, peer_src);

    OG_LOG_RUN_INF("[SHMEM-SCN] fallback worker finished");
}

static status_t shmem_scn_schedule_fallback_worker(bool32 notify_peers, uint32 peer_src)
{
    bool8 expected = OG_FALSE;

    if (!__atomic_compare_exchange_n(&g_shmem_scn_fallback_thread_started, &expected, OG_TRUE, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* Already scheduled; still refresh seed if a higher peer hint arrives. */
        return OG_SUCCESS;
    }

    g_shmem_scn_fallback_notify_peers = notify_peers;
    g_shmem_scn_fallback_peer_src = peer_src;

    if (cm_create_thread(shmem_scn_fallback_worker_entry, 0, NULL, &g_shmem_scn_fallback_thread) != OG_SUCCESS) {
        g_shmem_scn_fallback_thread_started = OG_FALSE;
        OG_LOG_RUN_ERR("[SHMEM-SCN] create fallback worker failed");
        return OG_ERROR;
    }
#ifndef WIN32
    (void)pthread_detach(g_shmem_scn_fallback_thread.id);
#endif
    return OG_SUCCESS;
}

/*
 * Local-first: degrade + unpublish immediately, raise local SCN, then async
 * peer notify. Does not unmap; mappings stay until shmem_scn_cleanup().
 * Safe to call from longjmp catch path (not from the signal handler itself).
 */
void shmem_scn_handle_ub_fault(const char *site)
{
    bool8 was_degraded;

    was_degraded = (bool8)__atomic_exchange_n(&g_shmem_scn_degraded, OG_TRUE, __ATOMIC_ACQ_REL);
    /* Stop all new GETs/SETs from touching UB before any further work. */
    shmem_scn_unpublish();
    shmem_scn_apply_fallback_seed(KNL_INVALID_SCN, OG_FALSE);

    if (was_degraded != OG_TRUE) {
        OG_LOG_RUN_WAR("[SHMEM-SCN] SIGBUS/UB fault captured at %s, falling back to local+broadcast",
            (site != NULL) ? site : "unknown");
    }
    shmem_scn_sigbus_log_last_to_runlog(site);

    if (shmem_scn_schedule_fallback_worker(OG_TRUE, 0) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] schedule fallback worker failed after local fault");
    }
}

void shmem_scn_handle_peer_fallback_notify(uint32 src_inst, uint64 seed_scn)
{
    bool8 was_degraded;

    was_degraded = (bool8)__atomic_exchange_n(&g_shmem_scn_degraded, OG_TRUE, __ATOMIC_ACQ_REL);
    shmem_scn_unpublish();
    shmem_scn_apply_fallback_seed((knl_scn_t)seed_scn, OG_FALSE);

    if (was_degraded != OG_TRUE) {
        OG_LOG_RUN_WAR("[SHMEM-SCN] peer inst %u notified SCN UB fallback, seed=%llu", src_inst, seed_scn);
    }

    if (shmem_scn_schedule_fallback_worker(OG_FALSE, src_inst) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] schedule fallback worker failed on peer notify from %u", src_inst);
    }
}

void shmem_scn_handle_cms_stop_ub(uint32 alarm_id, uint32 alarm_node_id)
{
    if (!shmem_scn_enabled()) {
        OG_LOG_RUN_INF("[SHMEM-SCN] cms stop-ub ignored (UB SCN not enabled), alarmId=%u, faultNode=%u",
            alarm_id, alarm_node_id);
        return;
    }

    if (shmem_scn_is_degraded()) {
        OG_LOG_RUN_INF("[SHMEM-SCN] cms stop-ub ignored (already degraded), alarmId=%u, faultNode=%u",
            alarm_id, alarm_node_id);
        return;
    }

    OG_LOG_RUN_WAR("[SHMEM-SCN] cms/sysSentry stop-ub: leave UB SCN, alarmId=%u, faultNode=%u, mode=%s",
        alarm_id, alarm_node_id, shmem_scn_use_dedicated_ub() ? "dedicated-ub" : "gbp");
    shmem_scn_handle_ub_fault("cms_xalarm_stop_ub");
}

bool32 shmem_scn_is_degraded(void)
{
    return g_shmem_scn_degraded ? OG_TRUE : OG_FALSE;
}

knl_scn_t shmem_scn_ub_atomic_read(volatile uint64 *p)
{
#ifdef WIN32
    (void)p;
    return KNL_INVALID_SCN;
#elif defined(__aarch64__) && defined(ENABLE_ARM64_ESB)
    int rc;

    if (p == NULL || g_shmem_scn_degraded) {
        return KNL_INVALID_SCN;
    }
    rc = sigsetjmp(g_shmem_scn_sigbus_jump_env, 1);
    if (rc == 0) {
        knl_scn_t val;
        g_shmem_scn_sigbus_jump_active = OG_TRUE;
        val = (knl_scn_t)ub_atomic_read_u64(p);
        SHMEM_SCN_ESB_BARRIER();
        g_shmem_scn_sigbus_jump_active = OG_FALSE;
        return val;
    }
    g_shmem_scn_sigbus_jump_active = OG_FALSE;
    OG_LOG_RUN_WAR("[SHMEM-SCN] ub_read catch after SIGBUS longjmp, p=%p rc=%d", (const void *)p, rc);
    shmem_scn_handle_ub_fault("ub_read");
    return KNL_INVALID_SCN;
#else
    return (knl_scn_t)ub_atomic_read_u64(p);
#endif
}

void shmem_scn_ub_atomic_raise(volatile uint64 *p, uint64 scn)
{
#ifdef WIN32
    (void)p;
    (void)scn;
#elif defined(__aarch64__) && defined(ENABLE_ARM64_ESB)
    int rc;

    if (p == NULL || g_shmem_scn_degraded) {
        return;
    }
    rc = sigsetjmp(g_shmem_scn_sigbus_jump_env, 1);
    if (rc == 0) {
        g_shmem_scn_sigbus_jump_active = OG_TRUE;
        ub_atomic_raise_u64(p, scn);
        SHMEM_SCN_ESB_BARRIER();
        g_shmem_scn_sigbus_jump_active = OG_FALSE;
        return;
    }
    g_shmem_scn_sigbus_jump_active = OG_FALSE;
    OG_LOG_RUN_WAR("[SHMEM-SCN] ub_raise catch after SIGBUS longjmp, p=%p scn=%llu rc=%d",
        (const void *)p, (unsigned long long)scn, rc);
    shmem_scn_handle_ub_fault("ub_raise");
#else
    ub_atomic_raise_u64(p, scn);
#endif
}

knl_scn_t shmem_scn_ub_atomic_inc(volatile uint64 *p)
{
#ifdef WIN32
    (void)p;
    return KNL_INVALID_SCN;
#elif defined(__aarch64__) && defined(ENABLE_ARM64_ESB)
    int rc;

    if (p == NULL || g_shmem_scn_degraded) {
        return KNL_INVALID_SCN;
    }
    rc = sigsetjmp(g_shmem_scn_sigbus_jump_env, 1);
    if (rc == 0) {
        knl_scn_t val;
        g_shmem_scn_sigbus_jump_active = OG_TRUE;
        val = (knl_scn_t)ub_atomic_add_fetch_u64(p, 1);
        SHMEM_SCN_ESB_BARRIER();
        g_shmem_scn_sigbus_jump_active = OG_FALSE;
        return val;
    }
    g_shmem_scn_sigbus_jump_active = OG_FALSE;
    OG_LOG_RUN_WAR("[SHMEM-SCN] ub_inc catch after SIGBUS longjmp, p=%p rc=%d", (const void *)p, rc);
    shmem_scn_handle_ub_fault("ub_inc");
    return KNL_INVALID_SCN;
#else
    return (knl_scn_t)ub_atomic_add_fetch_u64(p, 1);
#endif
}


void shmem_scn_invalidate_cache(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot = mgr->global_scn_slot;
    knl_scn_t ub_scn;

    if (slot != NULL && !g_shmem_scn_degraded) {
        ub_scn = shmem_scn_ub_atomic_read(&slot->value);
        if (!g_shmem_scn_degraded && ub_scn != KNL_INVALID_SCN) {
            OG_LOG_RUN_INF("[SHMEM-SCN] invalidate local scn slot, self=%u, scn=%llu", mgr->owner_id, (uint64)ub_scn);
            shmem_scn_raise_local(ub_scn);
        }
    }

    shmem_scn_unpublish();
}

#ifndef WIN32
static shmem_scn_slot_t *shmem_scn_slot_of(uint32 node_id)
{
    char *addr = drc_get_shmem_scn_addr(shmem_scn_remote_sga(), node_id);

    if (addr == NULL) {
        return NULL;
    }
    if (((uint64)addr % SHMEM_SCN_SLOT_ALIGN) != 0) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] slot addr %p on node %u is not %u-byte aligned", addr, node_id,
            (uint32)SHMEM_SCN_SLOT_ALIGN);
        return NULL;
    }
    return (shmem_scn_slot_t *)addr;
}

static status_t shmem_scn_format_names(uint32 node_id, char *region_name, uint32 region_len, char *shm_name,
    uint32 shm_len)
{
    struct passwd *pwd;
    int ret;

    pwd = getpwuid(getuid());
    if (pwd == NULL || pwd->pw_name == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] getpwuid failed, uid=%d", getuid());
        return OG_ERROR;
    }

    ret = sprintf_s(region_name, region_len, "region_scn_%s_%u", pwd->pw_name, node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sprintf region name fail, return error:%d", ret);
        return OG_ERROR;
    }

    ret = sprintf_s(shm_name, shm_len, "shm_scn_%s_%u", pwd->pw_name, node_id);
    if (ret < EOK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sprintf shm name fail, return error:%d", ret);
        return OG_ERROR;
    }

    return OG_SUCCESS;
}

static status_t shmem_scn_map_dedicated_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    char region_name[SHMEM_SCN_NAME_LEN] = { 0 };
    char shm_name[SHMEM_SCN_NAME_LEN] = { 0 };
    void *addr = NULL;
    int ret;

    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (mgr->map_success[node_id] == OG_TRUE && mgr->map_addr[node_id] != NULL) {
        return OG_SUCCESS;
    }

    if (node_id == g_instance->kernel.id && mgr->local_shm_name[0] != '\0') {
        MEMS_RETURN_IFERR(strcpy_s(shm_name, sizeof(shm_name), mgr->local_shm_name));
    } else if (shmem_scn_format_names(node_id, region_name, sizeof(region_name), shm_name, sizeof(shm_name)) !=
        OG_SUCCESS) {
        return OG_ERROR;
    }

    ret = ubsmem_shmem_map(NULL, (size_t)mgr->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_name, 0, &addr);
    if (ret != UBSM_OK) {
        if (g_instance != NULL && node_id == g_instance->kernel.id) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] Failed to map local dedicated %s, return error:%d", shm_name, ret);
        } else {
            OG_LOG_DEBUG_INF("[SHMEM-SCN] map peer dedicated %s node=%u not ready, ret=%d", shm_name, node_id, ret);
        }
        return OG_ERROR;
    }

    mgr->map_addr[node_id] = (char *)addr;
    mgr->map_success[node_id] = OG_TRUE;
    OG_LOG_RUN_INF("[SHMEM-SCN] mapped dedicated %s on node_id %u, addr=%p, size=%llu", shm_name, node_id, addr,
        mgr->shm_size);
    return OG_SUCCESS;
}

static status_t shmem_scn_map_gbp_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    remote_sga_t *rsga = shmem_scn_remote_sga();
    shmem_scn_slot_t *slot;

    if (node_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (mgr->map_success[node_id] == OG_TRUE && mgr->map_addr[node_id] != NULL) {
        return OG_SUCCESS;
    }

    if (rsga->map_success[node_id] != OG_TRUE || rsga->remote_buf_addr[node_id] == NULL) {
        if (dtc_mmap_remote_data_buf(rsga, node_id) != OG_SUCCESS) {
            if (g_instance != NULL && node_id == g_instance->kernel.id) {
                OG_LOG_RUN_ERR("[SHMEM-SCN] map local remote SGA for scn failed, node=%u", node_id);
            } else {
                OG_LOG_DEBUG_INF("[SHMEM-SCN] map peer remote SGA for scn not ready, node=%u", node_id);
            }
            return OG_ERROR;
        }
    }

    slot = shmem_scn_slot_of(node_id);
    if (slot == NULL) {
        return OG_ERROR;
    }

    mgr->map_addr[node_id] = (char *)slot;
    mgr->map_success[node_id] = OG_TRUE;
    OG_LOG_RUN_INF("[SHMEM-SCN] bound GBP remote-sga scn slot node=%u, addr=%p, offset=%llu", node_id, slot,
        drc_get_shmem_scn_offset(rsga));
    return OG_SUCCESS;
}

static status_t shmem_scn_map_node(uint32 node_id)
{
    if (g_shmem_scn_degraded) {
        return OG_ERROR;
    }
    if (shmem_scn_use_dedicated_ub()) {
        return shmem_scn_map_dedicated_node(node_id);
    }
    return shmem_scn_map_gbp_node(node_id);
}

static void shmem_scn_unmap_node(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    int ret;

    if (node_id >= OG_MAX_INSTANCES) {
        return;
    }

    if (shmem_scn_use_dedicated_ub()) {
        if (mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
            return;
        }
        ret = ubsmem_shmem_unmap(mgr->map_addr[node_id], (size_t)mgr->shm_size);
        if (ret != UBSM_OK) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] unmap dedicated node %u addr=%p failed, error:%d", node_id,
                mgr->map_addr[node_id], ret);
        } else {
            OG_LOG_RUN_INF("[SHMEM-SCN] unmap dedicated node %u addr=%p success", node_id, mgr->map_addr[node_id]);
        }
    }

    /* GBP: slot memory belongs to remote SGA; only drop local references. */
    mgr->map_addr[node_id] = NULL;
    mgr->map_success[node_id] = OG_FALSE;
}

static status_t shmem_scn_create_dedicated_local(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    int ret;

    if (g_instance == NULL) {
        return OG_ERROR;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    mgr->shm_size = SHMEM_SCN_SHM_SIZE;
    if (shmem_scn_format_names(self_id, mgr->local_region_name, sizeof(mgr->local_region_name), mgr->local_shm_name,
        sizeof(mgr->local_shm_name)) != OG_SUCCESS) {
        return OG_ERROR;
    }

    {
        ubsmem_region_attributes_t region_attr;
        char *host_name = cm_sys_host_name();
        ubsmem_regions_t regions;
        int i;

        ret = ubsmem_lookup_regions(&regions);
        if (ret != UBSM_OK) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] lookup_regions failed, ret=%d", ret);
            return OG_ERROR;
        }
        if (regions.num <= 0) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] no UB region topology available");
            return OG_ERROR;
        }
        region_attr = regions.region[0];
        for (i = 0; i < region_attr.host_num; i++) {
            region_attr.hosts[i].affinity =
                (host_name != NULL && strcmp(region_attr.hosts[i].host_name, host_name) == 0);
        }
        ret = ubsmem_create_region(mgr->local_region_name, 0, &region_attr);
        if (ret != UBSM_OK && ret != UBSM_ERR_ALREADY_EXIST) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] create region %s failed, ret=%d", mgr->local_region_name, ret);
            return OG_ERROR;
        }
    }

    ret = ubsmem_shmem_allocate(mgr->local_region_name, mgr->local_shm_name, mgr->shm_size, 0600,
        SHMEM_SCN_ALLOC_FLAGS);
    if (ret == UBSM_ERR_ALREADY_EXIST) {
        OG_LOG_RUN_WAR("[SHMEM-SCN] shm %s already exist, ret: %d", mgr->local_shm_name, ret);
    } else if (ret != UBSM_OK) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] allocate shm %s failed, ret: %d, region=%s, size=%llu", mgr->local_shm_name, ret,
            mgr->local_region_name, mgr->shm_size);
        return OG_ERROR;
    }

    mgr->local_created = OG_TRUE;

    if (shmem_scn_map_dedicated_node(self_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    if (ret == UBSM_OK) {
        MEMS_RETURN_IFERR(memset_s(mgr->map_addr[self_id], SHMEM_SCN_SIZE, 0, SHMEM_SCN_SIZE));
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] dedicated local shm ready, region=%s, shm=%s, size=%llu, addr=%p",
        mgr->local_region_name, mgr->local_shm_name, mgr->shm_size, mgr->map_addr[self_id]);
    return OG_SUCCESS;
}

static status_t shmem_scn_create_gbp_local(void)
{
    uint32 self_id;
    remote_sga_t *rsga = shmem_scn_remote_sga();

    if (g_instance == NULL) {
        return OG_ERROR;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return OG_ERROR;
    }

    if (rsga->remote_buf_addr[self_id] == NULL || rsga->shmem_scn == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] remote SGA scn slot not ready, self=%u, remote_buf=%p, shmem_scn=%p", self_id,
            rsga->remote_buf_addr[self_id], rsga->shmem_scn);
        return OG_ERROR;
    }

    if (((uint64)rsga->shmem_scn % SHMEM_SCN_SLOT_ALIGN) != 0) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] remote_sga.shmem_scn %p is not %u-byte aligned", rsga->shmem_scn,
            (uint32)SHMEM_SCN_SLOT_ALIGN);
        return OG_ERROR;
    }

    return shmem_scn_map_gbp_node(self_id);
}

static status_t shmem_scn_create_local(void)
{
    if (shmem_scn_use_dedicated_ub()) {
        return shmem_scn_create_dedicated_local();
    }
    return shmem_scn_create_gbp_local();
}

static void shmem_scn_deallocate_local(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    int ret;
    uint32 i;

    if (!shmem_scn_use_dedicated_ub() || mgr->local_created != OG_TRUE || mgr->local_shm_name[0] == '\0') {
        return;
    }

    for (i = 0; i < SHMEM_SCN_DEALLOC_RETRY; i++) {
        ret = ubsmem_shmem_deallocate(mgr->local_shm_name);
        if (ret == UBSM_OK) {
            OG_LOG_RUN_INF("[SHMEM-SCN] deallocate %s success", mgr->local_shm_name);
            return;
        }
        if (ret != UBSM_ERR_IN_USING) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] deallocate %s failed, error:%d", mgr->local_shm_name, ret);
            return;
        }
        OG_LOG_RUN_WAR("[SHMEM-SCN] deallocate %s IN_USING, retry %u", mgr->local_shm_name, i);
        cm_sleep(SHMEM_SCN_DEALLOC_WAIT_MS);
    }

    OG_LOG_RUN_ERR("[SHMEM-SCN] deallocate %s still IN_USING after %u retries", mgr->local_shm_name,
        SHMEM_SCN_DEALLOC_RETRY);
}

status_t shmem_scn_ensure_ub_mapped(uint32 node_id)
{
    if (g_shmem_scn_degraded) {
        return OG_ERROR;
    }
    return shmem_scn_map_node(node_id);
}

static void shmem_scn_try_map_peers(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    uint32 node_count;
    uint32 i;

    if (g_instance == NULL || g_shmem_scn_degraded) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    if (node_count == 0) {
        return;
    }

    for (i = 0; i < node_count; i++) {
        if (i == self_id) {
            continue;
        }
        if (mgr->map_success[i] == OG_TRUE && mgr->map_addr[i] != NULL) {
            continue;
        }
        (void)shmem_scn_map_node(i);
    }
}

static void shmem_scn_raise_peer_slot(uint32 node_id, uint64 scn)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot;

    if (g_shmem_scn_degraded) {
        return;
    }
    if (node_id >= OG_MAX_INSTANCES || mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[node_id];
    shmem_scn_ub_atomic_raise(&slot->value, scn);
}

void shmem_scn_fanout_raise(uint64 scn)
{
    uint32 self_id;
    uint32 node_count;
    uint32 i;

    if (!shmem_scn_enabled() || scn == 0 || g_instance == NULL || g_shmem_scn_degraded) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    if (node_count == 0) {
        return;
    }

    for (i = 0; i < node_count; i++) {
        if (i == self_id) {
            continue;
        }
        shmem_scn_raise_peer_slot(i, scn);
        if (g_shmem_scn_degraded) {
            return;
        }
    }
}

static uint64 shmem_scn_read_mapped(uint32 node_id)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    shmem_scn_slot_t *slot;

    if (g_shmem_scn_degraded) {
        return 0;
    }
    if (node_id >= OG_MAX_INSTANCES || mgr->map_success[node_id] != OG_TRUE || mgr->map_addr[node_id] == NULL) {
        return 0;
    }
    slot = (shmem_scn_slot_t *)mgr->map_addr[node_id];
    return (uint64)shmem_scn_ub_atomic_read(&slot->value);
}

void shmem_scn_absorb_peers(void)
{
    uint32 self_id;
    uint32 node_count;
    uint32 i;
    uint64 peer_max = 0;

    if (!shmem_scn_enabled() || g_instance == NULL || g_ub_global_scn == NULL || g_shmem_scn_degraded) {
        return;
    }

    self_id = g_instance->kernel.id;
    node_count = shmem_scn_node_count();
    for (i = 0; i < node_count; i++) {
        uint64 peer_scn;

        if (i == self_id) {
            continue;
        }
        peer_scn = shmem_scn_read_mapped(i);
        if (peer_scn > peer_max) {
            peer_max = peer_scn;
        }
        if (g_shmem_scn_degraded) {
            return;
        }
    }
    if (peer_max != 0 && g_ub_global_scn != NULL) {
        shmem_scn_ub_atomic_raise(g_ub_global_scn, peer_max);
    }
}

void shmem_scn_bind(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    shmem_scn_slot_t *slot;
    knl_scn_t local_scn;
    uint64 ub_scn = 0;
    uint64 merged = 0;
    bool32 was_active;

    if (!shmem_scn_enabled() || g_instance == NULL || g_shmem_scn_degraded) {
        return;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return;
    }

    if (mgr->map_success[self_id] != OG_TRUE || mgr->map_addr[self_id] == NULL) {
        return;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[self_id];
    local_scn = shmem_scn_read_local();
    was_active = (mgr->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;

#if defined(__aarch64__) && defined(ENABLE_ARM64_ESB)
    {
        int rc = sigsetjmp(g_shmem_scn_sigbus_jump_env, 1);
        if (rc == 0) {
            g_shmem_scn_sigbus_jump_active = OG_TRUE;
            slot->owner_node = self_id;
            ub_scn = ub_atomic_read_u64(&slot->value);
            merged = MAX((uint64)local_scn, ub_scn);
            ub_atomic_raise_u64(&slot->value, merged);
            SHMEM_SCN_ESB_BARRIER();
            g_shmem_scn_sigbus_jump_active = OG_FALSE;
        } else {
            g_shmem_scn_sigbus_jump_active = OG_FALSE;
            OG_LOG_RUN_WAR("[SHMEM-SCN] bind catch after SIGBUS longjmp, slot=%p rc=%d", (const void *)slot, rc);
            shmem_scn_handle_ub_fault("bind");
            return;
        }
    }
#else
    slot->owner_node = self_id;
    ub_scn = ub_atomic_read_u64(&slot->value);
    merged = MAX((uint64)local_scn, ub_scn);
    ub_atomic_raise_u64(&slot->value, merged);
#endif

    if (g_shmem_scn_degraded) {
        return;
    }

    shmem_scn_raise_local((knl_scn_t)merged);
    shmem_scn_publish(slot, self_id);
    OG_LOG_RUN_INF("[SHMEM-SCN] %s %s scn slot, self=%u, addr=%p, value=%llu",
        was_active ? "rebind" : "bind", shmem_scn_use_dedicated_ub() ? "dedicated-ub" : "gbp-remote-sga",
        self_id, slot, merged);
}
#else
status_t shmem_scn_ensure_ub_mapped(uint32 node_id)
{
    (void)node_id;
    return OG_ERROR;
}

static void shmem_scn_unmap_node(uint32 node_id)
{
    (void)node_id;
}

static status_t shmem_scn_create_local(void)
{
    return OG_SUCCESS;
}

static void shmem_scn_deallocate_local(void)
{
}

void shmem_scn_bind(void)
{
}

static void shmem_scn_try_map_peers(void)
{
}

void shmem_scn_fanout_raise(uint64 scn)
{
    (void)scn;
}

void shmem_scn_absorb_peers(void)
{
}
#endif

static bool32 shmem_scn_is_local_bound(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;
    shmem_scn_slot_t *slot;

    if (g_instance == NULL) {
        return OG_FALSE;
    }

    self_id = g_instance->kernel.id;
    if (self_id >= OG_MAX_INSTANCES) {
        return OG_FALSE;
    }

    if (mgr->global_scn_slot == NULL || mgr->owner_id != self_id) {
        return OG_FALSE;
    }

    if (mgr->map_success[self_id] != OG_TRUE || mgr->map_addr[self_id] == NULL) {
        return OG_FALSE;
    }

    slot = (shmem_scn_slot_t *)mgr->map_addr[self_id];
    return (slot == mgr->global_scn_slot) ? OG_TRUE : OG_FALSE;
}

static status_t shmem_scn_ensure_local_bound(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    uint32 self_id;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (g_shmem_scn_degraded) {
        return OG_SUCCESS;
    }

    if (g_instance == NULL) {
        return OG_ERROR;
    }

    if (shmem_scn_is_local_bound()) {
        return OG_SUCCESS;
    }

    self_id = g_instance->kernel.id;
    if (shmem_scn_ensure_ub_mapped(self_id) != OG_SUCCESS) {
        return OG_ERROR;
    }

    shmem_scn_bind();
    if (mgr->global_scn_slot == NULL) {
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();
    return OG_SUCCESS;
}

status_t shmem_scn_rebind_if_needed(void)
{
    return shmem_scn_ensure_local_bound();
}

static uint32 shmem_scn_io_flag(void)
{
    knl_session_t *se;

    if (g_instance == NULL) {
        return O_SYNC;
    }
    se = g_instance->kernel.sessions[SESSION_ID_KERNEL];
    return (se != NULL) ? knl_io_flag(se) : O_SYNC;
}

static status_t shmem_scn_build_file_path(char *buf, uint32 size)
{
    PRTS_RETURN_IFERR(sprintf_s(buf, size, "%s", SHMEM_SCN_FILE_PATH));
    return OG_SUCCESS;
}

static uint32 shmem_scn_file_slot_checksum(shmem_scn_file_slot_t *slot)
{
    uint32 saved = slot->checksum;
    uint32 crc;

    slot->checksum = 0;
    crc = cm_get_checksum(slot, sizeof(*slot));
    slot->checksum = saved;
    return crc;
}

static bool32 shmem_scn_file_slot_valid(shmem_scn_file_slot_t *slot)
{
    /* Accept v1 (legacy global slots) and v2 (per-node) for migration reads. */
    if (slot->magic != SHMEM_SCN_FILE_MAGIC ||
        (slot->version != SHMEM_SCN_FILE_VERSION && slot->version != 1)) {
        return OG_FALSE;
    }
    return (slot->checksum == shmem_scn_file_slot_checksum(slot)) ? OG_TRUE : OG_FALSE;
}

static shmem_scn_file_slot_t *shmem_scn_file_slot_buf(void)
{
    return (shmem_scn_file_slot_t *)g_shmem_scn_io_buf.aligned_buf;
}

static status_t shmem_scn_file_read_at(int64 offset, shmem_scn_file_slot_t *slot)
{
    cm_spin_lock(&g_shmem_scn_file_io_lock, NULL);
    if (cm_read_device(g_shmem_scn_file_type, g_shmem_scn_file_handle, offset, shmem_scn_file_slot_buf(),
        SHMEM_SCN_FILE_SLOT_SIZE) != OG_SUCCESS) {
        cm_spin_unlock(&g_shmem_scn_file_io_lock);
        return OG_ERROR;
    }
    *slot = *shmem_scn_file_slot_buf();
    cm_spin_unlock(&g_shmem_scn_file_io_lock);
    return OG_SUCCESS;
}

static status_t shmem_scn_file_write_node_slot(uint32 node_id, uint32 ping, const shmem_scn_file_slot_t *slot)
{
    int64 offset;

    if (node_id >= OG_MAX_INSTANCES || ping >= SHMEM_SCN_FILE_SLOT_COUNT) {
        return OG_ERROR;
    }
    offset = (int64)SHMEM_SCN_OFF_NODE_SLOT(node_id, ping);

    cm_spin_lock(&g_shmem_scn_file_io_lock, NULL);
    *shmem_scn_file_slot_buf() = *slot;
    if (cm_write_device(g_shmem_scn_file_type, g_shmem_scn_file_handle, offset, shmem_scn_file_slot_buf(),
        SHMEM_SCN_FILE_SLOT_SIZE) != OG_SUCCESS) {
        cm_spin_unlock(&g_shmem_scn_file_io_lock);
        return OG_ERROR;
    }
    if (g_shmem_scn_file_type == DEV_TYPE_FILE &&
        cm_fsync_device(g_shmem_scn_file_type, g_shmem_scn_file_handle) != OG_SUCCESS) {
        cm_spin_unlock(&g_shmem_scn_file_io_lock);
        return OG_ERROR;
    }
    cm_spin_unlock(&g_shmem_scn_file_io_lock);
    return OG_SUCCESS;
}

static void shmem_scn_file_consider_slot(shmem_scn_file_slot_t *slot, knl_scn_t *best_scn, uint64 *best_seq,
    bool32 *found)
{
    if (!shmem_scn_file_slot_valid(slot)) {
        return;
    }
    if (!(*found) || slot->scn > (uint64)(*best_scn) ||
        (slot->scn == (uint64)(*best_scn) && slot->seq > *best_seq)) {
        *best_scn = (knl_scn_t)slot->scn;
        *best_seq = slot->seq;
        *found = OG_TRUE;
    }
}

/* Scan all nodes' v2 slots; also try legacy v1 global offsets once for upgrade. */
static status_t shmem_scn_file_load_best(knl_scn_t *scn, uint64 *seq)
{
    shmem_scn_file_slot_t slot;
    knl_scn_t best_scn = KNL_INVALID_SCN;
    uint64 best_seq = 0;
    uint32 node;
    uint32 ping;
    bool32 found = OG_FALSE;

    {
        uint32 node_limit = shmem_scn_node_count();

        if (node_limit == 0 || node_limit > OG_MAX_INSTANCES) {
            node_limit = OG_MAX_INSTANCES;
        }
        for (node = 0; node < node_limit; node++) {
            for (ping = 0; ping < SHMEM_SCN_FILE_SLOT_COUNT; ping++) {
                if (shmem_scn_file_read_at((int64)SHMEM_SCN_OFF_NODE_SLOT(node, ping), &slot) != OG_SUCCESS) {
                    continue;
                }
                shmem_scn_file_consider_slot(&slot, &best_scn, &best_seq, &found);
            }
        }
    }

    /* Legacy v1: dlock region + two global slots at 8K / 12K. */
    for (ping = 0; ping < SHMEM_SCN_FILE_SLOT_COUNT; ping++) {
        if (shmem_scn_file_read_at((int64)(SHMEM_SCN_V1_OFF_SLOT0 + (uint64)ping * SHMEM_SCN_FILE_SLOT_SIZE),
            &slot) != OG_SUCCESS) {
            continue;
        }
        shmem_scn_file_consider_slot(&slot, &best_scn, &best_seq, &found);
    }

    *scn = best_scn;
    *seq = best_seq;
    return found ? OG_SUCCESS : OG_ERROR;
}

/* Inspect this node's ping-pong pair only (no cross-node lock). */
static void shmem_scn_file_scan_self(uint32 self_id, knl_scn_t *own_max_scn, uint64 *own_best_seq)
{
    shmem_scn_file_slot_t slot;
    uint32 ping;

    *own_max_scn = 0;
    *own_best_seq = 0;
    if (self_id >= OG_MAX_INSTANCES) {
        return;
    }

    for (ping = 0; ping < SHMEM_SCN_FILE_SLOT_COUNT; ping++) {
        if (shmem_scn_file_read_at((int64)SHMEM_SCN_OFF_NODE_SLOT(self_id, ping), &slot) != OG_SUCCESS ||
            !shmem_scn_file_slot_valid(&slot)) {
            continue;
        }
        if ((knl_scn_t)slot.scn > *own_max_scn) {
            *own_max_scn = (knl_scn_t)slot.scn;
        }
        if (slot.seq > *own_best_seq) {
            *own_best_seq = slot.seq;
        }
    }
}

static status_t shmem_scn_file_init_layout(void)
{
    /*
     * Sparse layout: slots are valid only after a node writes them.
     * Unwritten regions read as zeros / invalid magic and are ignored.
     */
    return OG_SUCCESS;
}

static void shmem_scn_close_persist_file(void)
{
    if (g_shmem_scn_file_handle != OG_INVALID_HANDLE) {
        cm_close_device(g_shmem_scn_file_type, &g_shmem_scn_file_handle);
        g_shmem_scn_file_handle = OG_INVALID_HANDLE;
    }
    cm_spin_lock(&g_shmem_scn_file_io_lock, NULL);
    cm_aligned_free(&g_shmem_scn_io_buf);
    cm_spin_unlock(&g_shmem_scn_file_io_lock);
    g_shmem_scn_file_name[0] = '\0';
    g_shmem_scn_file_seq = 0;
    g_shmem_scn_last_persisted = 0;
}

static status_t shmem_scn_open_persist_file(void)
{
    uint32 flags = shmem_scn_io_flag();
    knl_scn_t file_scn = KNL_INVALID_SCN;
    uint64 file_seq = 0;
    bool32 created = OG_FALSE;
    uint32 self_id;
    knl_scn_t own_max;
    uint64 own_seq;

    if (g_shmem_scn_file_handle != OG_INVALID_HANDLE) {
        return OG_SUCCESS;
    }

    if (shmem_scn_build_file_path(g_shmem_scn_file_name, sizeof(g_shmem_scn_file_name)) != OG_SUCCESS) {
        return OG_ERROR;
    }
    g_shmem_scn_file_type = cm_device_type(g_shmem_scn_file_name);

    if (cm_aligned_malloc((int64)SHMEM_SCN_IO_BUF_SIZE, "scn persist io", &g_shmem_scn_io_buf) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] alloc persist io buf failed");
        g_shmem_scn_file_name[0] = '\0';
        return OG_ERROR;
    }

    if (cm_exist_device(g_shmem_scn_file_type, g_shmem_scn_file_name)) {
        if (cm_open_device(g_shmem_scn_file_name, g_shmem_scn_file_type, flags, &g_shmem_scn_file_handle) !=
            OG_SUCCESS) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] open persist file %s failed", g_shmem_scn_file_name);
            shmem_scn_close_persist_file();
            return OG_ERROR;
        }
    } else if (cm_create_device(g_shmem_scn_file_name, g_shmem_scn_file_type, flags, &g_shmem_scn_file_handle) ==
        OG_SUCCESS) {
        created = OG_TRUE;
        if (shmem_scn_file_init_layout() != OG_SUCCESS) {
            shmem_scn_close_persist_file();
            return OG_ERROR;
        }
    } else if (cm_open_device(g_shmem_scn_file_name, g_shmem_scn_file_type, flags, &g_shmem_scn_file_handle) !=
        OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] create/open persist file %s failed", g_shmem_scn_file_name);
        shmem_scn_close_persist_file();
        return OG_ERROR;
    }

    self_id = (g_instance != NULL) ? g_instance->kernel.id : OG_INVALID_ID32;
    if (!created && shmem_scn_file_load_best(&file_scn, &file_seq) == OG_SUCCESS) {
        g_shmem_scn_last_persisted = file_scn;
        shmem_scn_raise_local(file_scn);
        if (self_id < OG_MAX_INSTANCES) {
            shmem_scn_file_scan_self(self_id, &own_max, &own_seq);
            g_shmem_scn_file_seq = own_seq;
        } else {
            g_shmem_scn_file_seq = 0;
        }
        OG_LOG_RUN_INF("[SHMEM-SCN] loaded persist file %s, scn=%llu (per-node layout, no dlock)",
            g_shmem_scn_file_name, (uint64)file_scn);
    } else {
        g_shmem_scn_last_persisted = 0;
        g_shmem_scn_file_seq = 0;
        OG_LOG_RUN_INF("[SHMEM-SCN] persist file %s ready (layout=%llu), no valid scn yet", g_shmem_scn_file_name,
            (uint64)SHMEM_SCN_PERSIST_FILE_SIZE);
    }
    return OG_SUCCESS;
}

/*
 * Each node writes only its own ping-pong pair. No cross-node dlock:
 * avoids fake CAS (#2) and CLOCK_MONOTONIC lease compare (#5).
 */
static void shmem_scn_persist_once(knl_session_t *session)
{
    shmem_scn_file_slot_t slot;
    knl_scn_t scn;
    knl_scn_t own_max_scn;
    uint64 own_best_seq;
    uint64 next_seq;
    uint32 self_id;
    uint32 ping;

    if (g_shmem_scn_file_handle == OG_INVALID_HANDLE) {
        return;
    }
    if (DB_NOT_READY(session) || DB_IS_READONLY(session) || !DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }

    self_id = session->kernel->id;
    if (self_id >= OG_MAX_INSTANCES) {
        return;
    }

    /* Refresh peer maps periodically so joiners get fan-out without commit spam. */
    shmem_scn_try_map_peers();

    scn = DB_CURR_SCN(session);
    if (scn == KNL_INVALID_SCN) {
        return;
    }

    /* Keep local watermark close to the UB slot. */
    shmem_scn_raise_local(scn);

    if (scn <= g_shmem_scn_last_persisted) {
        return;
    }

    /* Only touch this node's pair — no cross-node lock or full-file scan on hot path. */
    shmem_scn_file_scan_self(self_id, &own_max_scn, &own_best_seq);
    if (own_best_seq > g_shmem_scn_file_seq) {
        g_shmem_scn_file_seq = own_best_seq;
    }
    if (own_max_scn > g_shmem_scn_last_persisted) {
        g_shmem_scn_last_persisted = own_max_scn;
    }
    if (scn <= own_max_scn) {
        return;
    }

    next_seq = own_best_seq + 1;
    ping = (uint32)(own_best_seq % SHMEM_SCN_FILE_SLOT_COUNT);

    if (memset_s(&slot, sizeof(slot), 0, sizeof(slot)) != EOK) {
        return;
    }
    slot.magic = SHMEM_SCN_FILE_MAGIC;
    slot.version = SHMEM_SCN_FILE_VERSION;
    slot.scn = (uint64)scn;
    slot.seq = next_seq;
    slot.checksum = shmem_scn_file_slot_checksum(&slot);
    if (shmem_scn_file_write_node_slot(self_id, ping, &slot) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] persist scn=%llu to %s node=%u ping=%u failed", (uint64)scn,
            g_shmem_scn_file_name, self_id, ping);
        return;
    }

    g_shmem_scn_file_seq = next_seq;
    g_shmem_scn_last_persisted = scn;
}

static void shmem_scn_persist_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    uint32 slept_ms;

    cm_set_thread_name("scn_persist");
    OG_LOG_RUN_INF("[SHMEM-SCN] persist thread started, interval=%ums", SHMEM_SCN_PERSIST_INTERVAL_MS);
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    while (!thread->closed) {
        shmem_scn_persist_once(session);
        for (slept_ms = 0; slept_ms < SHMEM_SCN_PERSIST_INTERVAL_MS && !thread->closed;
             slept_ms += SHMEM_SCN_PERSIST_SLEEP_MS) {
            cm_sleep(SHMEM_SCN_PERSIST_SLEEP_MS);
        }
    }

    OG_LOG_RUN_INF("[SHMEM-SCN] persist thread stopped, last_persisted=%llu",
        (uint64)g_shmem_scn_last_persisted);
}

static void shmem_scn_stop_persist(void)
{
    if (g_shmem_scn_persist_started) {
        cm_close_thread(&g_shmem_scn_persist_thread);
        g_shmem_scn_persist_started = OG_FALSE;
    }

    if (g_shmem_scn_persist_session != NULL) {
        g_knl_callback.release_knl_session(g_shmem_scn_persist_session);
        g_shmem_scn_persist_session = NULL;
    }
    shmem_scn_close_persist_file();
}

status_t shmem_scn_prepare_persist(void)
{
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (shmem_scn_open_persist_file() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] prepare persist file failed");
        return OG_ERROR;
    }
    return OG_SUCCESS;
}

status_t shmem_scn_start_persist(void)
{
    knl_session_t *session = NULL;

    if (!shmem_scn_enabled() || g_shmem_scn_persist_started) {
        return OG_SUCCESS;
    }

    if (g_knl_callback.alloc_knl_session(OG_TRUE, (knl_handle_t *)&session) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] alloc persist session failed");
        return OG_ERROR;
    }

    g_shmem_scn_persist_session = session;
    if (cm_create_thread(shmem_scn_persist_proc, 0, session, &g_shmem_scn_persist_thread) != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] create persist thread failed");
        g_knl_callback.release_knl_session(session);
        g_shmem_scn_persist_session = NULL;
        return OG_ERROR;
    }

    g_shmem_scn_persist_started = OG_TRUE;
    return OG_SUCCESS;
}


static void shmem_scn_reset_mgr(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();

    MEMS_RETVOID_IFERR(memset_s(mgr, sizeof(shmem_scn_mgr_t), 0, sizeof(shmem_scn_mgr_t)));
    mgr->owner_id = OG_INVALID_ID32;
}

status_t shmem_scn_init(void)
{
    shmem_scn_reset_mgr();
    shmem_scn_unpublish();
    g_shmem_scn_degraded = OG_FALSE;
    g_shmem_scn_fallback_seed = 0;
    g_shmem_scn_fallback_thread_started = OG_FALSE;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    mes_set_scn_fallback_notify_cb(shmem_scn_handle_peer_fallback_notify);
    cms_cli_set_xalarm_stop_ub_cb(shmem_scn_handle_cms_stop_ub);
    if (shmem_scn_sigbus_register() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] register SIGBUS handler failed");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    /*
     * GBP mode: scn slot already reserved in drc_init_remote_buffer().
     * Dedicated mode: create/map a separate UB region here.
     */
    if (shmem_scn_create_local() != OG_SUCCESS) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] create/bind local scn slot failed (mode=%s)",
            shmem_scn_use_dedicated_ub() ? "dedicated-ub" : "gbp");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    shmem_scn_bind();
    if (shmem_scn_mgr()->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] publish local scn slot failed");
        shmem_scn_cleanup();
        return OG_ERROR;
    }

    if (shmem_scn_use_dedicated_ub()) {
        OG_LOG_RUN_INF("[SHMEM-SCN] init dedicated UB done, self=%u, shm=%s, size=%llu, local_scn=%llu",
            g_instance->kernel.id, shmem_scn_mgr()->local_shm_name, shmem_scn_mgr()->shm_size,
            (uint64)shmem_scn_read_local());
    } else {
        OG_LOG_RUN_INF("[SHMEM-SCN] init GBP remote SGA done, self=%u, offset=%llu, local_scn=%llu",
            g_instance->kernel.id, drc_get_shmem_scn_offset(shmem_scn_remote_sga()),
            (uint64)shmem_scn_read_local());
    }
    return OG_SUCCESS;
}

void shmem_scn_cleanup(void)
{
    shmem_scn_mgr_t *mgr;
    uint32 i;
    int ret;

    shmem_scn_stop_persist();
    mes_set_scn_fallback_notify_cb(NULL);
    cms_cli_set_xalarm_stop_ub_cb(NULL);
    shmem_scn_sigbus_unregister();

    if (g_instance == NULL || DRC_RES_CTX == NULL) {
        return;
    }

    mgr = shmem_scn_mgr();
    shmem_scn_invalidate_cache();

    for (i = 0; i < OG_MAX_INSTANCES; i++) {
        shmem_scn_unmap_node(i);
    }

    shmem_scn_deallocate_local();
#ifndef WIN32
    if (shmem_scn_use_dedicated_ub() && mgr->local_region_name[0] != '\0') {
        ret = ubsmem_destroy_region(mgr->local_region_name);
        if (ret != UBSM_OK) {
            OG_LOG_RUN_ERR("[SHMEM-SCN] destroy region %s failed, ret=%d", mgr->local_region_name, ret);
        }
        mgr->local_region_name[0] = '\0';
    }
#else
    (void)ret;
#endif
    mgr->local_created = OG_FALSE;
    mgr->local_shm_name[0] = '\0';
}

status_t shmem_scn_sync_to_ub(void)
{
    shmem_scn_mgr_t *mgr = shmem_scn_mgr();
    knl_scn_t scn;

    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (g_shmem_scn_degraded) {
        OG_LOG_RUN_WAR("[SHMEM-SCN] sync skipped, already degraded to local+broadcast");
        return OG_SUCCESS;
    }

    if (shmem_scn_ensure_local_bound() != OG_SUCCESS || mgr->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] sync local scn slot failed (mode=%s), local scn=%llu",
            shmem_scn_use_dedicated_ub() ? "dedicated-ub" : "gbp", (uint64)shmem_scn_read_local());
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();

    scn = KNL_GET_UB_SCN(&g_instance->kernel.scn);
    shmem_scn_fanout_raise((uint64)scn);
    OG_LOG_RUN_INF("[SHMEM-SCN] sync done (mode=%s), self=%u, value=%llu",
        shmem_scn_use_dedicated_ub() ? "dedicated-ub" : "gbp", mgr->owner_id, (uint64)scn);
    return OG_SUCCESS;
}

status_t shmem_scn_ensure_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_SUCCESS;
    }

    if (g_shmem_scn_degraded) {
        return OG_SUCCESS;
    }

    if (shmem_scn_ensure_local_bound() != OG_SUCCESS || shmem_scn_mgr()->global_scn_slot == NULL) {
        OG_LOG_RUN_ERR("[SHMEM-SCN] local scn slot not ready before open");
        return OG_ERROR;
    }

    shmem_scn_try_map_peers();
    return OG_SUCCESS;
}

bool32 shmem_scn_ready(void)
{
    if (!shmem_scn_enabled()) {
        return OG_TRUE;
    }

    /* Degraded means local+broadcast mode is active and operational. */
    if (g_shmem_scn_degraded) {
        return OG_TRUE;
    }

    return (shmem_scn_mgr()->global_scn_slot != NULL) ? OG_TRUE : OG_FALSE;
}

bool32 shmem_scn_need_broadcast(void)
{
#ifndef WIN32
    return (g_ub_global_scn == NULL || g_shmem_scn_degraded) ? OG_TRUE : OG_FALSE;
#else
    return OG_TRUE;
#endif
}

knl_scn_t shmem_scn_read_node(uint32 node_id)
{
    if (!shmem_scn_enabled() || g_shmem_scn_degraded) {
        return 0;
    }
    if (shmem_scn_ensure_ub_mapped(node_id) != OG_SUCCESS) {
        return 0;
    }
    return (knl_scn_t)shmem_scn_read_mapped(node_id);
}

void shmem_scn_raise_local_from_node(knl_session_t *session, uint32 node_id, knl_scn_t fallback_scn)
{
    knl_scn_t peer_scn;
    knl_scn_t target;

    (void)session;
    if (g_instance == NULL) {
        return;
    }
    peer_scn = shmem_scn_read_node(node_id);
    target = (peer_scn > fallback_scn) ? peer_scn : fallback_scn;
    knl_raise_local_ub_scn(&g_instance->kernel.scn, target);
}
