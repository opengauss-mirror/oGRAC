/* -------------------------------------------------------------------------
 *  oGRAC GBP helpers for USE_ATOMIC_LOCK=OFF (libubs-atomic.so backend).
 *  libubs-atomic exports ub_rw_lock_create/s_lock/x_lock/query_holder/...;
 *  the functions below are oGRAC page-store/diag extensions only.
 *
 *  Global shm layout matches libubs-atomic (see ubs-atomic/src/ub_lock/local_lock.h):
 *    +0   int32  lock_word
 *    +4   uint32 waiting_count
 *    +192 uint64 lock_owner_x
 *    +200 uint64 lock_owner_sx
 *    +208 uint64 reserve_lock_owner
 *    +228 uint32 shared_owner_bitmap
 *    +232 uint8  readonly        (oGRAC-only, in _pad_misc[0])
 * ------------------------------------------------------------------------- */
#include <stdatomic.h>
#include <stdint.h>
#include <limits.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "dtc_remote_lock.h"
#include "ub_dist_lock.h"

#if !USE_ATOMIC_LOCK

#define UBT_SHM_LOCK_WORD_OFF         0U
#define UBT_SHM_WAITING_COUNT_OFF     4U
#define UBT_SHM_QUEUE_HEAD_OFF        64U
#define UBT_SHM_QUEUE_TAIL_OFF        128U
#define UBT_SHM_OWNER_X_OFF           192U
#define UBT_SHM_OWNER_SX_OFF          200U
#define UBT_SHM_RESERVE_OWNER_OFF     208U
#define UBT_SHM_SHARED_BITMAP_OFF     228U
/* lib _pad_misc[24] — unused by libubs-atomic; oGRAC page-store fence */
#define UBT_SHM_READONLY_OFF          232U
#define UBT_SHM_WAITQ_BASE_OFF        256U
#define UBT_SPIN_YIELD_THRESHOLD      100U
#define UBT_SHM_WAITQ_SLOT_SZ         16U
#define UBT_SHM_WAITQ_CAP             16U

#define UBT_WAIT_EMPTY    0U
#define UBT_WAIT_WRITING  1U
#define UBT_WAIT_WAITING  2U
#define UBT_WAIT_NOTIFIED 3U
#define UBT_WAIT_TIMEOUT  4U

#define UBT_X_LOCK_DECR               65536   /* 0x10000 idle */
#define UBT_X_LOCK_HALF_DECR          32768   /* 0x8000 */
#define UBT_LOCK_INVALID_OWNER        (0xFF00000000ULL)

static int32 ubt_peek_i32(const ub_rw_lock_t *lock, uint32 off)
{
    return (int32)atomic_load_explicit((const _Atomic int32_t *)((const uint8 *)lock + off), memory_order_acquire);
}

static uint32 ubt_peek_u32(const ub_rw_lock_t *lock, uint32 off)
{
    return atomic_load_explicit((const _Atomic uint32_t *)((const uint8 *)lock + off), memory_order_acquire);
}

static uint64 ubt_peek_u64(const ub_rw_lock_t *lock, uint32 off)
{
    return atomic_load_explicit((const _Atomic uint64_t *)((const uint8 *)lock + off), memory_order_acquire);
}

static bool32 ubt_owner_valid(uint64 owner)
{
    return (bool32)(owner != UBT_LOCK_INVALID_OWNER && owner != 0);
}

static uint8 ubt_owner_node(uint64 owner)
{
    return (uint8)((owner >> 32) & 0xFFU);
}

static int32 ubt_owner_tid(uint64 owner)
{
    return (int32)(uint32_t)(owner & 0xFFFFFFFFULL);
}

static bool32 ubt_load_readonly(const ub_rw_lock_t *lock)
{
    return atomic_load_explicit((const _Atomic uint8_t *)((const uint8 *)lock + UBT_SHM_READONLY_OFF),
        memory_order_acquire) != 0 ? OG_TRUE : OG_FALSE;
}

static void ubt_store_readonly(ub_rw_lock_t *lock, bool32 readonly)
{
    atomic_store_explicit((_Atomic uint8_t *)((uint8 *)lock + UBT_SHM_READONLY_OFF), readonly ? 1U : 0U,
        memory_order_release);
}

static uint32 ubt_s_reader_count(int32 lock_word)
{
    if (lock_word > 0 && lock_word < UBT_X_LOCK_HALF_DECR) {
        return (uint32)(UBT_X_LOCK_HALF_DECR - lock_word);
    }
    if (lock_word > UBT_X_LOCK_HALF_DECR && lock_word < UBT_X_LOCK_DECR) {
        return (uint32)(UBT_X_LOCK_DECR - lock_word);
    }
    return 0;
}

static void ubt_copy_phase(char *phase, size_t phase_size, const char *text)
{
    size_t len;

    if (phase_size == 0) {
        return;
    }
    phase[0] = '\0';
    if (text == NULL) {
        return;
    }
    len = strlen(text);
    if (len >= phase_size) {
        len = phase_size - 1;
    }
    (void)memcpy(phase, text, len);
    phase[len] = '\0';
}

static void ubt_format_phase(int32 lock_word, char *phase, size_t phase_size, uint32 *s_readers)
{
    uint32 readers;
    char buf[16];

    if (phase_size == 0) {
        return;
    }
    phase[0] = '\0';
    readers = ubt_s_reader_count(lock_word);
    if (s_readers != NULL) {
        *s_readers = readers;
    }
    if (lock_word == UBT_X_LOCK_DECR) {
        ubt_copy_phase(phase, phase_size, "IDLE");
        return;
    }
    if (lock_word == 0) {
        ubt_copy_phase(phase, phase_size, "X");
        return;
    }
    if (readers > 0) {
        (void)snprintf(buf, sizeof(buf), "S%u", readers);
        ubt_copy_phase(phase, phase_size, buf);
        return;
    }
    if (lock_word > 0 && lock_word <= UBT_X_LOCK_HALF_DECR) {
        ubt_copy_phase(phase, phase_size, "SX/S");
        return;
    }
    (void)snprintf(buf, sizeof(buf), "?%d", lock_word);
    ubt_copy_phase(phase, phase_size, buf);
}

static void ubt_read_wait_slot(const ub_rw_lock_t *lock, uint32 idx, uint32 *seq, int32 *mode,
    uint8 *node, int32 *tid)
{
    const uint8 *base = (const uint8 *)lock + UBT_SHM_WAITQ_BASE_OFF + idx * UBT_SHM_WAITQ_SLOT_SZ;

    *seq = atomic_load_explicit((const _Atomic uint32_t *)(base + 0), memory_order_acquire);
    *mode = (int32)atomic_load_explicit((const _Atomic int32_t *)(base + 4), memory_order_acquire);
    *tid = atomic_load_explicit((const _Atomic int32_t *)(base + 8), memory_order_acquire);
    *node = (uint8)atomic_load_explicit((const _Atomic uint8_t *)(base + 12), memory_order_acquire);
}

void ub_gbp_lock_read_wait_queue(const ub_rw_lock_t *lock, ub_gbp_wait_q_snap_t *snap)
{
    uint32 head;
    uint32 tail;
    uint32 next_idx;

    (void)memset(snap, 0, sizeof(ub_gbp_wait_q_snap_t));
    if (lock == NULL) {
        return;
    }

    head = ubt_peek_u32(lock, UBT_SHM_QUEUE_HEAD_OFF);
    tail = ubt_peek_u32(lock, UBT_SHM_QUEUE_TAIL_OFF);
    snap->head = head;
    snap->tail = tail;
    snap->waiters = ubt_peek_u32(lock, UBT_SHM_WAITING_COUNT_OFF);
    snap->valid = OG_TRUE;

    if (head == tail) {
        return;
    }

    snap->head_idx = head & (UBT_SHM_WAITQ_CAP - 1U);
    ubt_read_wait_slot(lock, snap->head_idx, &snap->head_seq, &snap->head_mode, &snap->head_node, &snap->head_tid);

    next_idx = (head + 1U) & (UBT_SHM_WAITQ_CAP - 1U);
    if (head + 1U != tail) {
        ubt_read_wait_slot(lock, next_idx, &snap->next_seq, &snap->next_mode, &snap->next_node, &snap->next_tid);
    }
}

void ub_gbp_lock_read_raw(const ub_rw_lock_t *lock, ub_gbp_lock_raw_t *raw)
{
    (void)memset(raw, 0, sizeof(ub_gbp_lock_raw_t));
    raw->owner_x_tid = -1;
    raw->decode_tid = -1;
    if (lock == NULL) {
        return;
    }

    raw->g_lock_word = ubt_peek_i32(lock, UBT_SHM_LOCK_WORD_OFF);
    raw->g_waiters = ubt_peek_u32(lock, UBT_SHM_WAITING_COUNT_OFF);
    raw->owner_x = ubt_peek_u64(lock, UBT_SHM_OWNER_X_OFF);
    raw->owner_sx = ubt_peek_u64(lock, UBT_SHM_OWNER_SX_OFF);
    raw->reserve_owner = ubt_peek_u64(lock, UBT_SHM_RESERVE_OWNER_OFF);
    raw->shared_bitmap = ubt_peek_u32(lock, UBT_SHM_SHARED_BITMAP_OFF);
    raw->readonly = ubt_load_readonly(lock);

    raw->st_le32 = raw->g_lock_word;
    raw->write_waiters = (int32)raw->g_waiters;
    raw->u32_off8 = raw->g_waiters;
    raw->word0 = ((uint64)raw->g_waiters << 32) | (uint32)raw->g_lock_word;
    raw->word1 = raw->owner_x;

    ubt_format_phase(raw->g_lock_word, raw->g_phase, sizeof(raw->g_phase), &raw->s_readers);

    if (ubt_owner_valid(raw->owner_x)) {
        raw->owner_x_node = ubt_owner_node(raw->owner_x);
        raw->owner_x_tid = ubt_owner_tid(raw->owner_x);
    }
    if (ubt_owner_valid(raw->reserve_owner)) {
        raw->reserve_node = ubt_owner_node(raw->reserve_owner);
    }

    /* legacy aliases (do not use for ubturbo semantics) */
    raw->decode_state = raw->g_lock_word;
    raw->decode_node = raw->owner_x_node;
    raw->decode_tid = raw->owner_x_tid;
    raw->state_raw24 = 0;
}

void ub_rw_lock_set_readonly(ub_rw_lock_t *lock, bool32 readonly, const char *phase)
{
    (void)phase;
    if (lock == NULL) {
        return;
    }
    ubt_store_readonly(lock, readonly);
}

bool32 ub_rw_lock_get_readonly(ub_rw_lock_t *lock)
{
    if (lock == NULL) {
        return OG_FALSE;
    }
    return ubt_load_readonly(lock);
}

void ub_rw_lock_begin_page_store(ub_rw_lock_t *lock)
{
    if (lock == NULL) {
        return;
    }
    ubt_store_readonly(lock, OG_TRUE);
}

void ub_rw_lock_end_page_store(ub_rw_lock_t *lock)
{
    if (lock == NULL) {
        return;
    }
    ubt_store_readonly(lock, OG_FALSE);
}

/*
 * Spin until page-store fence clears.  Matches in-tree ub_rw_lock_x_lock /
 * ub_rw_lock_s_lock readonly wait (libubs-atomic x/s lock does not check readonly).
 * Do NOT call from x_lock_for_store — that path must not wait (see atomic impl).
 */
void ub_gbp_wait_readonly_fence(ub_rw_lock_t *lock)
{
    uint32 spin = 0;
    uint32 times = 0;

    if (lock == NULL) {
        return;
    }
    while (ub_rw_lock_get_readonly(lock)) {
        spin++;
        if (spin > UBT_SPIN_YIELD_THRESHOLD) {
            (void)sched_yield();
            spin = 0;
        }
        times++;
        if (SECUREC_UNLIKELY(times > OG_SPIN_COUNT)) {
            cm_sleep(100);
            times = 0;
        }
    }
}

/*
 * Like in-tree x/s lock: re-check readonly after lib returns — fence may flip true
 * while blocked in lib wait queue (atomic re-checks each CAS attempt).
 */
ub_lock_result_t ub_gbp_x_lock_fence(ub_rw_lock_t *lock, const ub_lock_policy_t *policy,
    const ub_location_t *location)
{
    ub_lock_result_t ret;

    if (lock == NULL || policy == NULL || location == NULL) {
        return UB_LOCK_ERROR;
    }
    for (;;) {
        ub_gbp_wait_readonly_fence(lock);
        ret = ub_rw_lock_x_lock(lock, policy, location);
        if (ret != UB_LOCK_SUCCESS) {
            return ret;
        }
        if (!ub_rw_lock_get_readonly(lock)) {
            return UB_LOCK_SUCCESS;
        }
        (void)ub_rw_lock_x_unlock(lock, policy, location);
    }
}

ub_lock_result_t ub_gbp_s_lock_fence(ub_rw_lock_t *lock, const ub_lock_policy_t *policy,
    const ub_location_t *location)
{
    ub_lock_result_t ret;

    if (lock == NULL || policy == NULL || location == NULL) {
        return UB_LOCK_ERROR;
    }
    for (;;) {
        ub_gbp_wait_readonly_fence(lock);
        ret = ub_rw_lock_s_lock(lock, policy, location);
        if (ret != UB_LOCK_SUCCESS) {
            return ret;
        }
        if (!ub_rw_lock_get_readonly(lock)) {
            return UB_LOCK_SUCCESS;
        }
        (void)ub_rw_lock_s_unlock(lock, policy, location);
    }
}

static void ubt_fill_default_policy(ub_lock_policy_t *policy)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    policy->timeout_ts = (time_ms_t)((uint64)ts.tv_sec * 1000ULL + (uint64)ts.tv_nsec / 1000000ULL +
                                     OG_DEFAULT_UB_GBP_LOCK_TIMEOUT_MS);
    policy->allow_delay_release = false;
    policy->recursive = false;
}

ub_lock_result_t ub_rw_lock_x_lock_for_store(ub_rw_lock_t *lock, const ub_location_t *location)
{
    ub_lock_policy_t policy;
    ub_lock_result_t ret;

    if (lock == NULL || location == NULL) {
        return UB_LOCK_ERROR;
    }

    /*
     * Match in-tree atomic semantics (ub_atomic_dist_lock.c): do NOT wait for
     * readonly to clear first — begin_page_store leaves readonly=true until
     * store re-acquires X here.  Waiting would deadlock with that fence.
     */
    if (ub_rw_lock_is_x_held_by_current_thread(lock, location->node_id, location->tid)) {
        ubt_store_readonly(lock, OG_FALSE);
        return UB_LOCK_SUCCESS;
    }

    ubt_fill_default_policy(&policy);
    ret = ub_rw_lock_x_lock(lock, &policy, location);
    if (ret == UB_LOCK_SUCCESS) {
        ubt_store_readonly(lock, OG_FALSE);
    }
    return ret;
}

ub_lock_result_t ub_rw_lock_x_lock_reenter(ub_rw_lock_t *lock, const ub_location_t *location)
{
    ub_lock_policy_t policy;

    ubt_fill_default_policy(&policy);
    policy.recursive = true;
    return ub_rw_lock_x_lock(lock, &policy, location);
}

uint64 ub_rw_lock_get_owner_node(ub_rw_lock_t *lock)
{
    ub_gbp_lock_raw_t raw;

    if (lock == NULL) {
        return UINT64_MAX;
    }
    ub_gbp_lock_read_raw(lock, &raw);
    if (raw.g_lock_word != 0 || !ubt_owner_valid(raw.owner_x)) {
        return UINT64_MAX;
    }
    return (uint64)raw.owner_x_node;
}

int32 ub_rw_lock_get_state(ub_rw_lock_t *lock)
{
    if (lock == NULL) {
        return 0;
    }
    return ubt_peek_i32(lock, UBT_SHM_LOCK_WORD_OFF);
}

bool32 ub_rw_lock_is_x_held_by_current_thread(ub_rw_lock_t *lock, uint8_t node_id, int32_t tid)
{
    ub_gbp_lock_raw_t raw;
    uint64 identify;

    if (lock == NULL) {
        return OG_FALSE;
    }
    ub_gbp_lock_read_raw(lock, &raw);
    if (raw.g_lock_word != 0 || !ubt_owner_valid(raw.owner_x)) {
        return OG_FALSE;
    }
    identify = ((uint64)node_id << 32) | (uint32)tid;
    return (bool32)(raw.owner_x == identify);
}

/* ub_rw_lock_query_holder is provided by libubs-atomic.so (includes local reserve_mode). */

#endif /* !USE_ATOMIC_LOCK */
