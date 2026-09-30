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
 * knl_parallel_log.h
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_parallel_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PARALLEL_LOG_H__
#define __KNL_PARALLEL_LOG_H__

#include "cm_atomic.h"
#include "cm_spinlock.h"
#include "cm_thread.h"
#include "cm_date.h"
#include "knl_log.h"
#include "knl_log_persistent.h"
#include "knl_session.h"
#include "cm_cpu.h"
#ifdef __cplusplus
extern "C" {
#endif

#define RD_NOT_COPIED 0  // Not yet copied to WAL buffer (slot allocatable / flushed-recycled)
#define RD_COPIED 1      // Copied to WAL buffer, not yet flushed

// Number of status slots per NUMA is 2^WAL_STATUS_ENTRIES_POWER (enlarging ring reduces reuse frequency)
#define RD_STATUS_ENTRIES_POWER 17

// Flush entry status array size
#define LOG_FLUSH_ENTRY_COUNT 65536

/* Parallel recovery: read cache size per writer cursor */
#define PARA_LOG_RCY_CACHE_SIZE SIZE_M(2)

/* group tail 4-byte CRC on disk */
#define PARA_LOG_GROUP_CKS_SIZE ((uint32)sizeof(uint32))
#define PARA_LOG_GROUP_DISK_SIZE(group) (LOG_GROUP_ACTUAL_SIZE(group) + PARA_LOG_GROUP_CKS_SIZE)

/* WAL reserve/flush wait timeout. Timeout means lgwr is stuck; abort to avoid sessions spinning forever. */
#define PARA_LOG_WRITE_WAIT_TIMEOUT ((date_t)(60 * MICROSECS_PER_SECOND))

#define PARA_LOG_SWITCH_WAIT_TIMEOUT ((date_t)(600 * MICROSECS_PER_SECOND))
#define PARA_LOG_SPACE_WAIT_SLICE_MS ((uint32)200)
#define PARA_LOG_CKPT_KICK_INTERVAL ((date_t)MICROSECS_PER_SECOND)
#define PARA_LOG_SPACE_WAKE_COUNT ((uint32)1024)

#define PARA_LOG_FLUSH_BATCH_SIZE SIZE_K(512)
#define PARA_LOG_COMMIT_WAIT_SLICE_MS ((uint32)50)
/*
 * Recovery may see curr_lsn retreat vs file offset inside this generation (reserve then
 * INC_LSN, late copy). That invert is bounded by in-flight status slots. Previous-ASN
 * leftover on the same file is millions of LSN earlier — not this slack.
 */
#define PARA_LOG_RCY_GEN_INVERT_SLACK ((uint64)(1U << RD_STATUS_ENTRIES_POWER))

static inline bool32 para_log_wait_timed_out(date_t begin)
{
    return (bool32)((cm_now() - begin) >= PARA_LOG_WRITE_WAIT_TIMEOUT);
}

typedef struct __attribute__((aligned(128))) st_para_log_leader_cond {
    atomic_t wait_lsn;
    atomic32_t futex;
    uint8 cache_align[CACHE_LINESIZE];
} para_log_leader_cond_t;

typedef enum en_para_log_flush_status {
    FLUSH_STATUS_INIT = 0,
    FLUSH_STATUS_FLUSHING = 1,
    FLUSH_STATUS_FLUSHED = 2,
} para_log_flush_status_t;

typedef struct __attribute__((aligned(128))) st_para_log_ins_status_ent {
    volatile uint64 end_log_pos;
    volatile uint64 curr_lsn; /* group->lsn, ckpt/recycle/rcy_off */
    volatile int32 lrc;       // logical record count inside NUMA
    volatile uint8 status;    // COPY / NOT COPIED
    uint8 pad[CACHE_LINESIZE - 8 - 8 - 4 - 1];
} para_log_ins_status_ent_t;

typedef char para_log_status_ent_size_assert[(sizeof(para_log_ins_status_ent_t) == CACHE_LINESIZE) ? 1 : -1];

/* ARM weak ordering: status must use acquire/release, not just volatile. */
static inline uint8 para_log_status_load_acquire(const volatile para_log_ins_status_ent_t *entry)
{
    return __atomic_load_n((volatile uint8 *)&entry->status, __ATOMIC_ACQUIRE);
}

static inline void para_log_status_store_release(volatile para_log_ins_status_ent_t *entry, uint8 val)
{
    __atomic_store_n((volatile uint8 *)&entry->status, val, __ATOMIC_RELEASE);
}

static inline int32 para_log_lrc_load_acquire(const atomic32_t *val)
{
    return __atomic_load_n(val, __ATOMIC_ACQUIRE);
}

static inline void para_log_lrc_store_release(atomic32_t *val, int32 value)
{
    __atomic_store_n(val, value, __ATOMIC_RELEASE);
}

static inline bool32 para_log_lrc_reached(int32 flushed, int32 target)
{
    if (target < 0) {
        return OG_TRUE;
    }
    if (flushed < 0) {
        return OG_FALSE;
    }
    return (bool32)(((flushed - target) & 0x7FFFFFFF) < 0x40000000);
}

typedef union un_para_log_buf_ctl {
    struct {
        uint64 curr_byte_pos;
        uint32 curr_byte_size;
        int32 curr_lrc;
    } struct128;
    uint128_u value;
} __attribute__((aligned(16))) para_log_buf_ctl_t;

typedef struct st_para_log_buf_ctx {
    char *buffer;
    uint64 buffer_size;
    para_log_buf_ctl_t ctl;
    para_log_ins_status_ent_t *status_table;
    uint64 status_tbl_size;
    uint8 pad[CACHE_LINESIZE];
} para_log_buf_ctx_t;

typedef struct st_para_log_flush_entry {
    volatile uint8 status;
    volatile uint64 end_lsn;
    volatile uint64 file_pos;
    volatile uint32 flush_size;
    volatile uint16 numa_id;
    uint8 pad[CACHE_LINESIZE - 1 - 8 - 8 - 4 - 2];
} para_log_flush_entry_t;

static inline uint64 para_log_u64_load(volatile uint64 *ptr)
{
    return cm_atomic_barrier_read(ptr);
}

static inline void para_log_u64_store_release(volatile uint64 *ptr, uint64 value)
{
    __atomic_store_n(ptr, value, __ATOMIC_RELEASE);
}

static inline bool32 para_log_u64_cas(volatile uint64 *ptr, uint64 *expected, uint64 newval)
{
    return cm_atomic_compare_exchange_u64((atomic_t *)(void *)ptr, expected, newval);
}

typedef struct st_para_log_bg_lock {
    spinlock_t lock;
    uint32 lock_align4[15];
} para_log_bg_flush_lock_t;

typedef struct st_para_log_write_lock {
    spinlock_t lock;
    uint32 lock_align4[15];
} para_log_write_lock_t;

typedef struct st_para_log_flush_assist {
    uint64 start_write_pos;
    uint64 end_write_pos;
    uint64 start_flush_pos;
    uint64 end_flush_pos;
    uint32 data_size;
    uint32 aligned_size;
} para_log_flush_assist_t;

typedef struct st_para_log_commit_queue {
    atomic_t atomic_first;
    atomic_t atomic_leader;
    atomic32_t curr_queue_count;
} para_log_commit_queue_t;

/* Per-writer counters for DFX. Dumped when ENABLE_PARA_LOG_DFX=TRUE (period/switch/recycle/close). */
typedef struct st_para_log_dfx {
    uint64 write_cnt;
    uint64 write_bytes;
    uint64 write_retry;
    uint64 slot_wait;
    uint64 flush_cnt;
    uint64 flush_bytes;
    uint64 flush_entries;
    uint64 empty_poll;
    uint64 flush_hold;
    uint64 commit_wait_loop;
    uint64 switch_cnt;
    uint64 recycle_cnt;
    date_t last_dump;
} para_log_dfx_t;

typedef struct __attribute__((aligned(128))) st_para_log_context {
    thread_t thread;
    knl_session_t *session;
    uint32 thread_idx;   /* cluster / WAL group id */
    uint32 file_numa_id; /* 1:1 with thread_idx; reserved field to avoid changing layout call sites */
    para_log_bg_flush_lock_t b_flush_lock;  // lock for background flush
    para_log_write_lock_t write_log_lock;
    atomic32_t lrc_wake_seq; /* +1 after this lane flushed; seq for commit-wait of the stuck lane */
    uint8 lrc_wake_seq_pad[CACHE_LINESIZE - sizeof(atomic32_t)];
    para_log_commit_queue_t tx_queue;
    para_log_leader_cond_t leader_wait_cond;

    atomic_t flush_req;        /* incremented by self_flush, asks writer to do a flush */
    atomic_t flush_ack;        /* writer catches up to flush_req after completing this flush round */
    atomic32_t kick_futex;     /* wake writer (especially DB_NOT_READY waiters) */
    atomic32_t ack_futex;      /* wake self_flush waiters */
    atomic32_t space_futex;    /* wake KEEP / switch-file waiters after recycle success */
    atomic32_t switch_blocked; /* no INACTIVE, lgwr skips flush this round, waits for recycle outside lock */
    date_t last_ckpt_kick;     /* lgwr high watermark kicks ckpt to limit frequency */
    date_t switch_wait_begin;  /* timestamp of first switch-file wait for recycle */
    para_log_buf_ctx_t log_buf_ctx;

    para_log_flush_entry_t *flush_entry_status;
    int32 last_flushed_entry;
    uint8 last_flushed_entry_pad[CACHE_LINESIZE - sizeof(int32)];
    atomic32_t last_flushed_lrc; /* LRC of flushed continuous prefix of this lane; -1 means not flushed yet */
    uint8 last_flushed_lrc_pad[CACHE_LINESIZE - sizeof(atomic32_t)];
    atomic32_t reserved_lrc; /* next lrc after CAS success; snapshot reads this, does not touch 128-bit ctl */
    uint8 reserved_lrc_pad[CACHE_LINESIZE - sizeof(atomic32_t)];
    volatile uint64 last_flushed_pos;
    char *logwr_head_buf;
    char *flush_buf;
    uint64 flush_buf_size;
    uint16 reserved;
    volatile uint64 file_write_pos;

    atomic32_t session_bind_cpu;

    log_file_t *files[CPU_SEG_MAX_NUM];
    uint32 log_file_idx;
    /* use for file control */
    uint16 curr_file;
    uint16 active_file;     // first active file
    atomic32_t ctrl_dirty;  // switch has updated in-memory para_log_last, ctrl not yet persisted
    atomic_t free_size;     // CURRENT remaining + INACTIVE whole-file capacity (ignoring stale write_pos)
    /* Embedded with files[]; both sized CPU_SEG_MAX_NUM, zeroed in para_log_init via context memset. */
    uint64 file_max_lsn[CPU_SEG_MAX_NUM];  // max flushed curr_lsn per file-slot (recycle criterion: <= rcy_point.lsn)

    log_point_t curr_point;
    log_stat_t stat;
    para_log_dfx_t dfx;
} para_log_context_t;

typedef char para_log_files_slot_assert
    [(sizeof(((para_log_context_t *)0)->files) / sizeof(log_file_t *) == CPU_SEG_MAX_NUM) ? 1 : -1];
typedef char para_log_max_lsn_slot_assert
    [(sizeof(((para_log_context_t *)0)->file_max_lsn) / sizeof(uint64) == CPU_SEG_MAX_NUM) ? 1 : -1];
typedef char para_log_sess_group_max_assert[(KNL_PARA_LOG_MAX_GROUPS == CPU_SEG_MAX_NUM) ? 1 : -1];

static inline uint32 para_log_file_slot_count(const para_log_context_t *ogx)
{
    if (ogx == NULL) {
        return 0;
    }
    return (ogx->log_file_idx > CPU_SEG_MAX_NUM) ? (uint32)CPU_SEG_MAX_NUM : ogx->log_file_idx;
}

static inline bool32 para_log_file_slot_valid(const para_log_context_t *ogx, uint32 slot)
{
    return (bool32)(ogx != NULL && slot < para_log_file_slot_count(ogx));
}

static inline int32 get_next_status_entry(uint32 power, int32 entry_idx)
{
    return (entry_idx + 1) & ((1 << power) - 1);
}

static inline int32 get_status_entry_index(uint32 power, int32 entry_idx)
{
    return entry_idx & ((1 << power) - 1);
}

static inline int32 get_log_buf_ring_size(uint32 power)
{
    return (int32)(1U << power);
}

static inline bool32 is_log_buf_same_slot(int32 lrc1, int32 lrc2, uint32 power)
{
    int32 mask = get_log_buf_ring_size(power) - 1;
    return (lrc1 & mask) == (lrc2 & mask);
}

static inline int32 get_log_buf_next_lrc(int32 lrc, uint32 power)
{
    return (lrc + get_log_buf_ring_size(power)) & 0x7FFFFFFF;
}

typedef struct st_para_log_rcy_idx_ent {
    uint64 lsn; /* group->lsn (curr_lsn) */
    int64 offset;
    uint32 file_idx;
    uint32 disk_size;
} para_log_rcy_idx_ent_t;

typedef struct st_para_log_rcy_cursor {
    uint32 group_id;
    uint32 compact_count;
    uint32 first_idx;
    uint32 last_idx;
    uint32 file_idx;
    int64 offset;
    int64 file_limit;
    uint32 blk_size;
    log_file_t *files[CPU_SEG_MAX_NUM];
    int32 handles[CPU_SEG_MAX_NUM];
    aligned_buf_t cache;
    int64 cache_off;
    uint32 cache_valid;
    int32 cache_file_idx; /* which file slot the cache belongs to; -1 means cache invalid */
    uint64 last_group_lsn;
    uint64 rcy_lsn;
    uint64 file_first_lsn; /* this file's first_lsn; leftover previous ASN is below it */
    uint32 file_asn;       /* this file's head.asn; group->asn mismatch means leftover */
    int64 durable_wpos;    /* on-disk write_pos at open; CURRENT scan starts bounded here */
    bool32 has_group;
    bool32 eof;
    bool32 garbage_skip;   /* just skipped padding/CRC misalignment; leftover fragments are not end-of-file */
    bool32 seen_post_ckpt; /* this file has already accepted groups with lsn > rcy_lsn; later <= rcy means leftover */
    para_log_rcy_idx_ent_t *idx; /* when non-NULL idx_cap is allocated count; when NULL cap/count must be 0 */
    uint32 idx_count;
    uint32 idx_cap;
    uint32 idx_pos;
} para_log_rcy_cursor_t;

typedef struct st_para_log_rcy_stream {
    knl_session_t *session;
    uint8 node_id;
    uint64 rcy_lsn;
    uint64 expected;
    uint64 recovered_end;
    uint32 writer_count;
    int32 peeked_writer;
    bool32 done;
    para_log_rcy_cursor_t cursors[CPU_SEG_MAX_NUM];
} para_log_rcy_stream_t;

uint32 para_log_bind_group(const knl_session_t *session);
uint32 para_log_file_lgwr_count(void);
uint32 para_log_group_to_numa(uint32 group_id);
uint32 para_log_numa_home_group(uint32 numa_id);
uint32 para_log_numa_group_end(uint32 numa_id);
para_log_context_t *para_log_ctx_of(const knl_session_t *session);
para_log_context_t *para_log_file_ogx_of(const knl_session_t *session, const para_log_context_t *ogx);
bool32 para_log_has_keep_space(knl_session_t *session, para_log_context_t *ogx);
void para_log_wait_keep_space(knl_session_t *session, para_log_context_t *ogx);
bool32 para_log_need_flush(knl_session_t *session);
status_t para_log_init(knl_session_t *session);
status_t para_log_check_db_mode(knl_session_t *session);
status_t para_log_check_unsupported(knl_session_t *session);
status_t para_log_file_load(knl_session_t *session);
void para_log_close(knl_session_t *session);
status_t para_log_self_flush(knl_session_t *session, log_point_t *point, knl_scn_t *scn, uint64 *lsn);
status_t para_log_flush_by_numa(knl_session_t *session, uint32 numa_id);
void para_log_proc(thread_t *thread);
void para_log_write(knl_session_t *session, uint32 total_size, log_group_t *group, uint32 ori_group_size);
status_t para_log_fredosync(device_type_t type, int32 handle);
/* commit waits for this LRC flushed and all lanes' reserved COPIED prefix flushed; not the global flushed_lsn */
status_t para_log_commit_flush(knl_session_t *session);
status_t para_log_check_asn(knl_session_t *session);
void para_log_recycle_file(knl_session_t *session, uint32 group_id, log_point_t *point);
void para_log_ckpt_flush_rcy_off(knl_session_t *session);

status_t para_log_rcy_stream_create(knl_session_t *session, uint8 node_id, uint64 rcy_lsn, const int32 *handles,
                                    para_log_rcy_stream_t **stream);
void para_log_rcy_stream_close(para_log_rcy_stream_t *stream);
status_t para_log_rcy_stream_reset(para_log_rcy_stream_t *stream);
status_t para_log_rcy_stream_peek(para_log_rcy_stream_t *stream, log_group_t **group);
void para_log_rcy_stream_consume(para_log_rcy_stream_t *stream);
uint64 para_log_rcy_stream_recovered_end(const para_log_rcy_stream_t *stream);
status_t para_log_rcy_apply_reset(knl_session_t *session, uint8 node_id, uint64 recovered_end, uint64 last_curr_lsn,
                                  const int32 *handles);
status_t para_log_recover(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
