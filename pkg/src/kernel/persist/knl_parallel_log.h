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

/*
 * Per-lane independent redo file: file_id = lane / OG_REDO_LANE_FILE_STUB_COUNT fallback
 */
#define OG_LOG_FLUSH_WORD_CACHE_SIZE 128

#ifndef OG_RD_PERF_STUB
#define OG_RD_PERF_STUB 0
#endif

// WAL insertion status definitions
#define RD_NOT_COPIED 0
#define RD_COPIED 1
#define RD_STATUS_ENTRIES_POWER 17
#define LOG_FLUSH_ENTRY_COUNT 65536
#define LOG_FLUSH_BITMAP_WINDOW_SIZE (1U << 23)
#define LOG_FLUSH_BITMAP_WORDS (LOG_FLUSH_BITMAP_WINDOW_SIZE / 64)
#define LOG_FLUSH_BITMAP_WORD_SHIFT 6
#define LOG_FLUSH_BITMAP_WORD_MASK 63
#define LOG_FLUSH_BITMAP_SLIDE_SIZE (LOG_FLUSH_BITMAP_WINDOW_SIZE >> 1)
#define LOG_FLUSH_BITMAP_BACKPRESSURE_SIZE \
    (LOG_FLUSH_BITMAP_WINDOW_SIZE - (LOG_FLUSH_BITMAP_WINDOW_SIZE >> 2))

/* Parallel recovery: read cache size per writer cursor */
#define PARA_LOG_RCY_CACHE_SIZE SIZE_M(2)

/* 4-byte CRC at group disk tail, does not change log_group_t persistent layout */
#define PARA_LOG_GROUP_CKS_SIZE ((uint32)sizeof(uint32))
#define PARA_LOG_GROUP_DISK_SIZE(group) (LOG_GROUP_ACTUAL_SIZE(group) + PARA_LOG_GROUP_CKS_SIZE)

/* WAL reservation/flush wait timeout. Timeout means lgwr/bitmap stuck, abort to avoid session spinning forever. */
#define PARA_LOG_WRITE_WAIT_TIMEOUT ((date_t)(60 * MICROSECS_PER_SECOND))

#define PARA_LOG_SWITCH_WAIT_TIMEOUT ((date_t)(600 * MICROSECS_PER_SECOND))
#define PARA_LOG_SPACE_WAIT_SLICE_MS ((uint32)200)
#define PARA_LOG_CKPT_KICK_INTERVAL ((date_t)MICROSECS_PER_SECOND)
#define PARA_LOG_SPACE_WAKE_COUNT ((uint32)1024)
/* LRC token: next one spins (yield), later ones futex-sleep; slice is only a lost-wakeup fallback */
#define PARA_LOG_LRC_WAIT_SLICE_MS ((uint32)5)
#define PARA_LOG_LRC_WAKE_COUNT ((uint32)1024)

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
    volatile uint64 lsn;
    volatile int32 lrc;
    volatile uint8 status;
    uint8 pad[CACHE_LINESIZE - 8 - 8 - 4 - 1];
} para_log_ins_status_ent_t;

/* ARM weak ordering: status must use acquire/release, not just volatile. */
static inline uint8 para_log_status_load_acquire(const volatile para_log_ins_status_ent_t *entry)
{
    return __atomic_load_n((volatile uint8 *)&entry->status, __ATOMIC_ACQUIRE);
}

static inline void para_log_status_store_release(volatile para_log_ins_status_ent_t *entry, uint8 val)
{
    __atomic_store_n((volatile uint8 *)&entry->status, val, __ATOMIC_RELEASE);
}

typedef union un_para_log_buf_ctl {
    struct {
        uint64 curr_byte_pos;
        uint32 curr_byte_size;
        int32 curr_lrc;
    } struct128;
    uint128_u value;
} __attribute__((aligned(16))) para_log_buf_ctl_t;

typedef union un_para_log_lsn_ctl {
    struct {
        uint64 lsn;
        uint64 commit;
    } s;
    uint128_u value;
} __attribute__((aligned(16))) para_log_lsn_ctl_t;

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

typedef struct st_para_log_flush_lsn_bitmap {
    spinlock_t lock;
    uint32 lock_align[15];
    volatile uint64 seq;
    volatile uint64 base_lsn;
    volatile uint64 flushed_lsn;
    volatile uint64 max_marked_lsn;
    volatile uint64 bitmap[LOG_FLUSH_BITMAP_WORDS];
} para_log_flush_lsn_bitmap_t;

static inline uint64 para_log_u64_load(volatile uint64 *ptr)
{
    return cm_atomic_barrier_read(ptr);
}

static inline void para_log_u64_store(volatile uint64 *ptr, uint64 value)
{
    (void)cm_atomic_set_u64(ptr, value);
}

static inline void para_log_u64_store_release(volatile uint64 *ptr, uint64 value)
{
    __atomic_store_n(ptr, value, __ATOMIC_RELEASE);
}

static inline bool32 para_log_u64_cas(volatile uint64 *ptr, uint64 *expected, uint64 newval)
{
    return cm_atomic_compare_exchange_u64((atomic_t *)(void *)ptr, expected, newval);
}

static inline uint64 para_log_u64_add(volatile uint64 *ptr, int64 count)
{
    return (uint64)cm_atomic_add((atomic_t *)(void *)ptr, count);
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
    uint64 commit_wait_loop;
    uint64 switch_cnt;
    uint64 recycle_cnt;
    uint64 bitmap_block;
    date_t last_dump;
} para_log_dfx_t;

typedef struct __attribute__((aligned(128))) st_para_log_context {
    thread_t thread;
    knl_session_t *session;
    uint32 thread_idx;
    para_log_bg_flush_lock_t b_flush_lock;
    para_log_write_lock_t write_log_lock;
    volatile int32 next_assign_lrc;
    uint8 next_assign_lrc_pad[CACHE_LINESIZE - sizeof(int32)];
    para_log_commit_queue_t tx_queue;
    para_log_leader_cond_t leader_wait_cond;

    atomic_t flush_req;
    atomic_t flush_ack;
    atomic32_t kick_futex;
    atomic32_t ack_futex;
    atomic32_t space_futex;
    atomic32_t switch_blocked;
    date_t last_ckpt_kick;
    date_t switch_wait_begin;
    para_log_buf_ctx_t log_buf_ctx;

    para_log_flush_entry_t *flush_entry_status;
    int32 last_flushed_entry;
    volatile uint64 last_flushed_pos;
    char *logwr_head_buf;
    char* flush_buf;
    uint64 flush_buf_size;
    uint16 reserved;
    volatile uint64 file_write_pos;

    atomic32_t session_bind_cpu;

    log_file_t *files[CPU_SEG_MAX_NUM];
    uint32 log_file_idx;
    /* use for file control */
    uint16 curr_file;
    uint16 active_file;
    atomic32_t ctrl_dirty;
    atomic_t free_size;
    /* Embedded with files[]; both sized CPU_SEG_MAX_NUM, zeroed in para_log_init via context memset. */
    uint64 file_max_lsn[CPU_SEG_MAX_NUM];

    log_point_t curr_point;
    log_stat_t stat;
    para_log_dfx_t dfx;
} para_log_context_t;

typedef char para_log_files_slot_assert[(sizeof(((para_log_context_t *)0)->files) / sizeof(log_file_t *) ==
                                         CPU_SEG_MAX_NUM) ? 1 : -1];
typedef char para_log_max_lsn_slot_assert[(sizeof(((para_log_context_t *)0)->file_max_lsn) / sizeof(uint64) ==
                                           CPU_SEG_MAX_NUM) ? 1 : -1];

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
    uint64 last_commit_lsn;
    uint64 rcy_lsn;
    bool32 has_group;
    bool32 eof;
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
para_log_context_t *para_log_ctx_of(const knl_session_t *session);
bool32 para_log_has_keep_space(knl_session_t *session, para_log_context_t *ogx);
void para_log_wait_keep_space(knl_session_t *session, para_log_context_t *ogx);
para_log_flush_lsn_bitmap_t *para_log_bitmap_of(const knl_session_t *session);
bool32 para_log_need_flush(knl_session_t *session);
status_t para_log_init(knl_session_t *session);
status_t para_log_check_unsupported(knl_session_t *session);
status_t para_log_file_load(knl_session_t *session);
void para_log_close(knl_session_t *session);
status_t para_log_self_flush(knl_session_t *session, log_point_t *point, knl_scn_t *scn, uint64 *lsn);
status_t para_log_flush_by_numa(knl_session_t *session, uint32 numa_id);
void para_log_proc(thread_t *thread);
void para_log_write(knl_session_t *session, uint32 total_size, log_group_t *group, uint32 ori_group_size);
status_t para_log_fredosync(device_type_t type, int32 handle);
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
