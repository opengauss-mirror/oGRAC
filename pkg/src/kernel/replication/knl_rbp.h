/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Cantian is licensed under Mulan PSL v2.
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
 * knl_rbp.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_rbp.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_RBP_H__
#define __KNL_RBP_H__

#include "knl_page.h"
#include "knl_session.h"
#include "knl_rbp_message.h"
#include "knl_log.h"
#include "knl_archive.h"
#include "cs_listener.h"

#ifdef __cplusplus
extern "C"{
#endif

#define RBP_ALY_MAX_FILE            10

#ifdef WIN32
#define RBP_ALY_MAX_BUCKET_PER_FILE 1
#else
#define RBP_ALY_MAX_BUCKET_PER_FILE (uint64)SIZE_K(200)  // total memery 20*5*100K*32=320M, can save 50G tpcc log
#endif

#define RBP_CONNEOG_TIMEOUT         3000 // 3s
#define RBP_RECYCLE_TIMEOUT         (uint64)10000000 // 10s
#define RBP_ALY_BUCKET_AVERAGE_NUM  5

/*
  * Hot-path RBP read diagnostics: 1 enables per-page apply timing, read_skip atomic counts,
  * and read-end timing summaries. Production partial recovery should keep 0.
  */
#define RBP_READ_HOT_DIAG               0

/*
  * PAGE_WRITE assemble/queue/send detailed timing and DEBUG trace. Production keep 0.
  */
#define RBP_PAGE_WRITE_HOT_DIAG         0

#if RBP_PAGE_WRITE_HOT_DIAG
#define RBP_PAGE_WRITE_NOW()            (g_timer()->now)
#else
#define RBP_PAGE_WRITE_NOW()            0
#endif

#if RBP_READ_HOT_DIAG
#define RBP_BUF_TRACE_LOG(...)          OG_LOG_DEBUG_INF(__VA_ARGS__)
#else
#define RBP_BUF_TRACE_LOG(...)          ((void)0)
#endif

#define RBP_ALY_MAX_ITEM            (RBP_ALY_MAX_FILE * RBP_ALY_MAX_BUCKET_PER_FILE * RBP_ALY_BUCKET_AVERAGE_NUM)
#define RBP_ALY_MAX_ITEM_SIZE       (RBP_ALY_MAX_ITEM * sizeof(rbp_analyse_item_t))
#define RBP_ALY_MAX_BUCKET_SIZE     (RBP_ALY_MAX_FILE * RBP_ALY_MAX_BUCKET_PER_FILE * sizeof(rbp_analyse_bucket_t))
#define RBP_ALY_PAGE_COUNT          200000
#define RBP_ALY_PAGE_BUCKET_SIZE    ((RBP_ALY_PAGE_COUNT + 1) * sizeof(rbp_aly_page_t)) // 4.8M

#define RBP_MAX_REQ_BUF_SIZE        (sizeof(rbp_write_req_t))
#define RBP_MAX_RESP_BUF_SIZE       (sizeof(rbp_batch_read_resp_t))
#define RBP_HEARTBEAT_INTERVAL      (2000 * MICROSECS_PER_MILLISEC) // 2s
#define RBP_MAX_READ_WAIT_TIME      3000 // 3s
#define RBP_SNAPSHOT_POOL_SIZE      (OG_RBP_SESSION_COUNT * RBP_BATCH_PAGE_NUM * 4)

/* rbp config params */
typedef struct st_rbp_attr {
    spinlock_t addr_lock;
    bool32 server_addr_changed;
    volatile bool32 rbp_off_triggered;
    volatile bool32 use_rbp;
    char lsnr_addr[CM_MAX_IP_LEN];
    uint16 lsnr_port;

    char server_addr[OG_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN];
    char server_addr2[OG_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN];
    uint32 server_count;
    uint32 server_count2;
    char local_rbp_host[CM_MAX_IP_LEN];
    char trans_type[OG_MAX_NAME_LEN];
    uint64 rbp_buf_size;
    bool32 rbp_for_recovery;
    bool32 rbp_rt_analysis;
    bool32 rbp_debug_rcy_check;
    uint32 rbp_rt_parse_workers;
    uint32 rbp_rt_page_owner_workers;
    uint32 assemble_max_scan;
    uint64 lrpl_res_logsize;
} rbp_attr_t;

typedef struct st_rbp_buf_manager {
    uint32 queue_id;               /* corresponding thread */
    thread_t thread;
    buf_set_t *buf_pool_ctx;       /* pointer to rbp_sga->buf_context_t */
    uint32 buf_pool_count;

    spinlock_t lru_lock;           /* protect following field */
    buf_ctrl_t *lru_first;
    buf_ctrl_t *lru_last;
    uint32 lru_count;              /* buffer count in LRU queue */
    buf_ctrl_t *lru_current;
    bool32 lru_first_read;         /* if first read, reset lru_current to lru_first */

    volatile bool32 rbp_reading;
    volatile bool32 rbp_writing;

    uint64 buf_skip;                /* when failover read, old page skip count */
    uint64 buf_read;                /* when failover read, page read count */
    uint64 buf_write;
    uint64 buf_fresh;

    log_point_t rbp_begin_point;
    log_point_t rbp_trunc_point;
    log_point_t rbp_lrp_point;
    uint64 max_lsn;                 /* max lsn of pages */

    volatile bool32 is_connected;
    uint32 connected_id;
    /* temp pipe may be re-bound to different per-node RBP servers during one recovery run. */
    uint32 temp_connected_node;
    uint32 selected_temp_connected_node;
    cs_pipe_t pipe_const;
    cs_pipe_t pipe_temp;
    cs_pipe_t pipe_selected_temp;

    date_t last_hb_time;
    spinlock_t fisrt_pipe_lock;      /* serialize RBP I/O on pipe_const and pipe_temp for this queue */
    spinlock_t selected_pipe_lock;    /* serialize selected batch reads on pipe_selected_temp */
} rbp_buf_manager_t;

typedef enum en_rbp_queue_item_src {
    RBP_QUEUE_ITEM_LIVE = 0,
    RBP_QUEUE_ITEM_SNAPSHOT,
    RBP_QUEUE_ITEM_DROPPED,
} rbp_queue_item_src_t;

typedef struct st_rbp_snapshot {
    struct st_rbp_snapshot *next;
    page_id_t page_id;
    log_point_t rbp_trunc_point;
    uint64 lastest_lfn;
    uint32 writer_inst_id;
    uint64 writer_global_seq;
    char block[RBP_PAGE_SIZE];
} rbp_snapshot_t;

typedef struct st_rbp_queue_item {
    struct st_rbp_queue_item *next;
    rbp_queue_item_src_t source;
    buf_ctrl_t *ctrl;
    rbp_snapshot_t *snapshot;
    page_id_t page_id;
    uint32 queue_id;
} rbp_queue_item_t;

typedef struct st_rbp_queue {
    spinlock_t lock;
    uint32 id;
    volatile bool32 has_gap;       /* page in queue maybe recycled */
    volatile bool32 has_ckpt_reset; /* non-periodic page_num=0 reset for queue safety events */
    volatile uint32 count;

    log_point_t trunc_point;
    log_point_t ckpt_reset_point;
    log_point_t last_sent_ckpt_purge_point; /* last periodic ckpt purge sent to this shard */
    date_t last_ckpt_purge_check_time;      /* qid-local periodic ckpt purge timer */

    rbp_queue_item_t *first;
    rbp_queue_item_t *last;
} rbp_queue_t;

typedef struct st_rbp_read_apply_diag {
    uint64 resp_pages;
    uint64 not_required;
    uint64 no_expect;
    uint64 ahead;
    uint64 wrong_node;
    uint64 selected;
    uint64 installed;
    uint64 hit;
    uint64 usable;
    uint64 old;
    uint64 miss;
    uint64 other_status;
    uint64 not_newer;
    uint64 select_update_us;
    uint64 enter_page_us;
    uint64 eval_us;
    uint64 replace_us;
    uint64 replace_copy_us;
    uint64 replace_disk_check_us;
    uint64 replace_id_check_us;
    uint64 replace_pcn_check_us;
    uint64 replace_dirty_us;
    uint64 replace_ckpt_enque_us;
    uint64 replace_ckpt_enque;
    uint64 replace_already_dirty;
    uint64 mark_us;
    uint64 leave_page_us;
    uint64 selected_requested;
    uint64 selected_verified;
    uint64 selected_missing;
    uint64 selected_mismatch;
} rbp_read_apply_diag_t;

typedef struct st_rbp_read_worker_diag {
    uint64 ok_batches;
    uint64 nopage_batches;
    uint64 error_batches;
    uint64 pages;
    uint64 total_us;
    uint64 connect_us;
    uint64 pipe_lock_us;
    uint64 ensure_conn_us;
    uint64 send_us;
    uint64 wait_resp_us;
    uint64 process_us;
    date_t slow_last_log_time;
    rbp_read_apply_diag_t apply;
} rbp_read_worker_diag_t;

typedef struct st_rbp_read_skip_diag {
    atomic_t partial_no_expect;
    atomic_t partial_no_expect_no_item;
    atomic_t partial_no_expect_not_required;
    atomic_t partial_selected_scope;
    atomic_t partial_selected_scope_required;
    atomic_t partial_selected_scope_selected_valid;
    atomic_t partial_selected_scope_selected_pulled;
    atomic_t partial_selected_scope_verified;
    atomic_t partial_selected_scope_load_status;
    atomic_t no_expect_lsn;
    atomic_t nolog_space;
} rbp_read_skip_diag_t;

/* rbp context */
typedef struct st_rbp_context {
    knl_session_t *rbp_bg_sessions[OG_RBP_SESSION_COUNT];
    /* buffer manager on rbp */
    rbp_buf_manager_t rbp_buf_manager[OG_RBP_SESSION_COUNT];
    /* page need to send to rbp */
    rbp_queue_t queue[OG_RBP_SESSION_COUNT];
    /* request and response buffer. on primary, it is request buffer. on standby, it is response buffer */
    char *batch_buf[OG_RBP_SESSION_COUNT];
    aligned_buf_t pipe_buf;
    aligned_buf_t snapshot_buf;
    spinlock_t snapshot_lock;
    rbp_snapshot_t *snapshot_free;
    uint32 snapshot_free_count;
    uint32 snapshot_low_watermark;
    uint64 snapshot_alloc_total;
    uint64 snapshot_free_total;
    uint64 snapshot_alloc_fail_total;
    volatile bool32 page_write_suspended;
    volatile bool32 clear_after_partial_recovery;
    /* rbp agnet on kernel */
    thread_t rbp_agent_thread;

    /* concurrent control for sessions read same page from rbp */
    spinlock_t buf_read_lock[OG_RBP_RD_LOCK_COUNT];

    volatile bool32 log_flushing;
    volatile bool32 rbp_read_completed;     /* rbp page read completed flag */
    volatile uint32 rbp_read_version;       /* the version of reading rbp pages */
    atomic_t rbp_read_thread_num;           /* the number of threads which is reading page from rbp */

    log_point_t rbp_begin_point;            /* rbp read begin point */
    log_point_t rbp_end_point;              /* rbp read begin point */
    date_t rbp_begin_read_time;             /* rbp read begin time */
    date_t rbp_end_read_time;               /* rbp read end time */
    date_t rbp_read_workers_done_time;      /* last RBP read worker completion time */
    atomic_t rbp_read_pages;
    atomic_t rbp_read_errors;
    atomic_t rbp_read_batch_elapsed;        /* worker-accumulated batch read elapsed time(us) */
    atomic_t rbp_read_selected_mismatch;
    atomic_t rbp_read_pull_miss_trace;
    atomic_t rbp_read_partial_ahead_detail;
    atomic_t rbp_read_ahead_detail;
    atomic_t rbp_read_partial_disk_fallback;
    atomic_t rbp_read_multi_disk_fallback;
    rbp_read_worker_diag_t read_diag[OG_RBP_SESSION_COUNT];
    rbp_read_skip_diag_t read_skip_diag;
    uint64 rbp_window_start;
    uint64 rbp_window_end;
    bool8 dtc_read_active;                  /* DTC RBP read epoch is active */
    bool8 dtc_read_workers_done;            /* DTC read workers finished; recovery owner still sends READ_END */
    atomic_t dtc_read_failed;               /* DTC RBP read/apply failed; owner must READ_END before fallback */
    uint32 dtc_read_failed_node;
    uint32 dtc_read_failed_result;
    atomic_t dtc_rbp_fallback_required;     /* Persistent DTC partial fallback marker; cleared by owner only */
    uint32 dtc_rbp_fallback_node;
    uint32 dtc_rbp_fallback_result;
    uint32 dtc_rbp_fallback_reason;
    uint16 dtc_read_node_count;
    uint32 dtc_read_nodes[OG_MAX_INSTANCES];
    log_point_t dtc_read_skip_points[OG_MAX_INSTANCES];
    log_point_t dtc_read_rcy_points[OG_MAX_INSTANCES];
    log_point_t dtc_read_lrp_points[OG_MAX_INSTANCES];
    bool8 dtc_use_selected_batch;
    bool8 dtc_need_selected_meta;
    bool8 dtc_sync_selected_pull_at_begin;
    uint8 reserved_dtc_selected;
    spinlock_t dtc_selected_lock[OG_MAX_INSTANCES];
    uint32 dtc_selected_cursor[OG_MAX_INSTANCES];
    uint32 dtc_selected_worker_nodes[OG_RBP_SESSION_COUNT];
    uint16 dtc_verify_node_count;
    uint32 dtc_verify_nodes[OG_MAX_INSTANCES];
    log_point_t dtc_verify_skip_points[OG_MAX_INSTANCES];
    log_point_t dtc_verify_rcy_points[OG_MAX_INSTANCES];
    bool8 dtc_planned_required_built;
    uint32 dtc_planned_required_count;
    uint32 dtc_planned_required_capacity;
    rbp_analyse_item_t **dtc_planned_required_items;
} rbp_context_t;

typedef struct st_rbp_aly_page {
    page_id_t page_id;
    uint64 lsn;         // expect lsn after failover done
    uint64 lfn;         // the lfn of batch contain this page
    uint32 node_id;     // redo stream that produced this touch
} rbp_aly_page_t;

typedef struct st_rbp_page_bucket {
    spinlock_t lock;
    thread_t thread;
    uint32 count;
    volatile uint32 head;
    volatile uint32 tail;
    rbp_aly_page_t *first;
} rbp_page_bucket_t;

typedef struct st_rbp_aly_context {
    thread_t thread;
    uint32 sid;

    spinlock_t extend_lock;
    aligned_buf_t read_buf;
    aligned_buf_t log_decrypt_buf;
    aligned_buf_t bucket_buf;
    rbp_page_bucket_t page_bucket;
    volatile bool32 is_started;
    volatile bool32 is_closing;
    volatile bool32 is_done;
    bool32 has_gap;
    bool32 has_return_replay;
    bool32 loading_curr_file;

    log_point_t begin_point;
    log_point_t curr_point;
    date_t begin_time;
    date_t end_time;
    date_t last_recycle_time;

    arch_file_t arch_file;
    int32 log_handle[OG_MAX_LOG_FILES];
} rbp_aly_ctx_t;

typedef enum en_rbp_page_status {
    RBP_PAGE_NONE = 0,              /* init */
    RBP_PAGE_ERROR = 1,             /* rbp page read error(eg. RBP disconnect or RBP down) */
    RBP_PAGE_MISS = 2,              /* no expected page on RBP */
    RBP_PAGE_HIT = 3,               /* RBP page->LSN = expected LSN */
    RBP_PAGE_USABLE = 4,            /* local page->LSN < RBP page->LSN < expected LSN */
    RBP_PAGE_OLD = 5,               /* RBP page->LSN < local page->LSN */
    RBP_PAGE_AHEAD = 6,             /* RBP page->LSN > expected LSN  */
    RBP_PAGE_NOREAD = 7,            /* page is not loaded to buffer and enter by ENTER_PAGE_NO_READ */
} rbp_page_status_e;

typedef enum en_rbp_dtc_fallback_reason {
    RBP_DTC_FALLBACK_NONE = 0,
    RBP_DTC_FALLBACK_READ_FAILED = 1,
    RBP_DTC_FALLBACK_PAGE_READ = 2,
    RBP_DTC_FALLBACK_VERIFY_MISS = 3,
    RBP_DTC_FALLBACK_TAIL_INCOMPLETE = 4,
    RBP_DTC_FALLBACK_RECOVER_CHECK = 5,
} rbp_dtc_fallback_reason_e;

/* interface */
status_t rbp_agent_start_client(knl_session_t *session);
void rbp_agent_stop_client(knl_session_t *session);
status_t rbp_agent_start(knl_session_t *session);
void rbp_agent_close(knl_session_t *session);

void rbp_enque_pages(knl_session_t *session);
void rbp_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl);
void rbp_queue_set_gap(knl_session_t *session, buf_ctrl_t *ctrl);

/* Cluster multi-write: queue/write RBP by DRC exclusive page ownership, not primary/standby role. */
bool32 rbp_ctrl_may_enqueue(knl_session_t *session, buf_ctrl_t *ctrl);
/* Whether this instance may send PAGE_WRITE to the remote RBP. */
bool32 rbp_instance_may_write_to_remote(knl_session_t *session);
/* Whether this DB should enforce primary-style RBP buffer invariants. */
bool32 rbp_db_enforce_primary_style_invariants(knl_session_t *session);
void rbp_on_page_owner_migrate_or_invalidate(knl_session_t *session, buf_ctrl_t *ctrl);
bool32 rbp_need_wait_before_remote_overwrite(knl_session_t *session, buf_ctrl_t *ctrl);
bool32 rbp_try_detach_pending_page(knl_session_t *session, buf_ctrl_t *ctrl);
void rbp_wait_before_remote_overwrite(knl_session_t *session, buf_ctrl_t *ctrl);
void rbp_suspend_page_write_for_partial_recovery(knl_session_t *session);
void rbp_finish_partial_recovery_page_write(knl_session_t *session);

void rbp_queue_set_trunc_point(knl_session_t *session, log_point_t *point);
void rbp_queue_notify_ckpt_point(knl_session_t *session, log_point_t *point);
log_point_t rbp_queue_get_trunc_point(knl_session_t *session);
uint64 rbp_queue_get_page_count(knl_session_t *session);

/* WAL / quorum visibility before sending PAGE_WRITE (multi-node DSS; replaces single-standby-only barrier). */
status_t rbp_wait_redo_visible(knl_session_t *session, thread_t *thread, uint64 max_page_lsn, uint64 max_page_lfn,
                               log_point_t *rbp_lrp_point);

void rbp_set_unsafe(knl_session_t *session, log_type_t type);
void rbp_reset_unsafe(knl_session_t *session);
void rbp_unsafe_redo_check(knl_session_t *session);
bool32 rbp_pre_check(knl_session_t *session, log_point_t aly_end_point);

/* multi-node recovery commits per-node jump points before calling this; no single-stream jump is done here. */
status_t rbp_knl_begin_dtc_read(knl_session_t *session);
bool32 rbp_knl_dtc_read_failed(knl_session_t *session);
bool32 rbp_knl_dtc_fallback_required(knl_session_t *session);
void rbp_knl_mark_dtc_fallback(knl_session_t *session, uint32 node_id, uint32 result, uint32 reason);
void rbp_knl_clear_dtc_fallback(knl_session_t *session);
void rbp_knl_end_read(knl_session_t *session);
void rbp_knl_finish_dtc_read(knl_session_t *session);
void rbp_knl_abort_dtc_read(knl_session_t *session);

status_t rbp_knl_query_rbp_point_by_node(knl_session_t *session, uint32 node_id, rbp_read_ckpt_resp_t *response,
                                          bool32 check_end_point);
void rbp_knl_check_end_point(knl_session_t *session);
rbp_page_status_e knl_read_page_from_rbp(knl_session_t *session, buf_ctrl_t *ctrl);
status_t rbp_alloc_bg_session(uint8 queue_index, knl_session_t **session);
void rbp_release_bg_session(knl_session_t *session);

status_t rbp_aly_mem_init(knl_session_t *session);
void rbp_aly_mem_free(knl_session_t *session);

/*
  * Set page's latest lsn for standby node. After analysis all redo, we can know all page's expected latest lsn.
  * Analyse item count is limit, if some page is not in rbp_aly_items, it expected latest lsn can be read from disk.
  *
  * Add item(page/lsn/lfn):
  * 1. if find the same page item, update it;
  * 2. if not find, add a new one page item;
  * 3. if item lfn < rcy point lfn, reuse it. Because this page's all redo has been replayed and been flushed to
  *       disk. So this page's latest lsn can be read from disk, and this item can be reused.
  * 4. if can not add a new page item, this page expected lsn can not be record, we will forbide use rbp when failover.
  */
void rbp_aly_set_page_lsn(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn);
uint32 rbp_aly_curr_node_id(knl_session_t *session);
uint64 rbp_aly_get_page_lsn(knl_session_t *session, page_id_t page_id);
rbp_analyse_item_t *rbp_aly_get_page_item(knl_session_t *session, page_id_t page_id);

/*
  * Verify page lsn which need load from RBP, if rbp_page_lsn is large local page lsn, we can use it
  * 1. item == NULL, this page not in redo between rbp_skip_point and lrpl_end_point, we don't need to refresh
  * 2. item->is_verified == 1, this rbp page has been verifyed, we don't need to refresh second time
  * 3. curr_page_lsn == 0, page is not load from disk (include ENTER_PAGE_NO_READ),
  * 4. rbp_page_lsn == expect_lsn, we can refresh local buffer page as rbp page
  * 5. rbp_page_lsn < expect_lsn && rbp_page_lsn > curr_page_lsn, we can refresh it, then replay to expect_lsn
  * 6. rbp_page_lsn < curr_page_lsn(or disk_page_lsn), rbp page is old, can not refresh local page
  *
  * This fuction is runing only rcy_with_rbp == 1, so there two stage to verify rbp page:
  * A. Before failover done:
  *      in this stage, we skip some redo and only replay a few redo, and redo_curr_lsn will increase. and
  *      must have curr_page_lsn <= expect_lsn && disk_page_lsn <= expect_lsn && disk_page_lsn <= redo_curr_lsn,
  * B. After failover done:
  *      in this stage, lrpl has done, DB is open, but rbp_bg_proc still pull pages. redo_curr_lsn is lrpl end lsn and
  *      not change, so redo_curr_lsn may less than curr_page_lsn. Beacause DB is open, curr_page_lsn may large than
  *      expect_lsn, so if rbp_page_lsn == expect_lsn, we must check if rbp_page_lsn > curr_page_lsn.
  * Notify, if page already freshed as rbp page, then it flush to disk and recycled, and we buf_load_page again,
  * curr_page_lsn is 0, and rbp_page_lsn == expect_lsn, but we can not refresh again, becasue disk_page_lsn is newer.
  * So we only verify each page once, then set is_verified = 1, to ensure that page refreshed as rbp page at most once.
  */
rbp_page_status_e rbp_page_verify(knl_session_t *session, page_id_t page_id, uint64 rbp_page_lsn,
                                   uint64 curr_page_lsn);

uint32 rbp_aly_free_space_percent(knl_session_t *session);
status_t rbp_aly_init(knl_session_t *session);
void rbp_aly_close(knl_session_t *session);
void rbp_aly_unsafe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn);
void rbp_aly_safe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn);
status_t rbp_aly_get_file_end_point(knl_session_t *session, log_point_t *point, uint16 file_id);
bool32 rbp_promote_triggered(knl_handle_t knl_handle);
void rbp_record_promote_time(knl_session_t *session, const char *stage, const char *promote_type);
status_t rbp_knl_query_rbp_point(knl_session_t *session, rbp_read_ckpt_resp_t *response, bool32 check_end_point);

/*
  * SQL DEBUG: issue RBP_REQ_PAGE_READ on const pipe (no buf install / no rbp_aly check).
  * out_result: RBP_READ_RESULT_* (see knl_rbp_message.h). Use with rbp_server_demo or real RBP.
  */
status_t knl_rbp_sql_demo_read_page(knl_session_t *session, uint16 file_no, uint32 page_no, uint32 *out_result);

/** @}**/
#ifdef __cplusplus
}
#endif

#endif
