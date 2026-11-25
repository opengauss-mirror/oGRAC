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
 * repl_log_recv.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/repl_log_recv.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __REPL_LOG_RECV_H__
#define __REPL_LOG_RECV_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cs_pipe.h"
#include "knl_log.h"
#include "knl_session.h"
#include "knl_database.h"
#include "repl_msg.h"
#include "knl_archive.h"
#include "zstd.h"

#define LRCV_LOG_POINT_ON_PRE_FILE(pt, file_head)                        \
    ((pt).rst_id < (file_head).rst_id ||                                \
    ((pt).rst_id == (file_head).rst_id && (pt).asn < (file_head).asn))

#define LRCV_LOG_POINT_ON_CURR_FILE(pt, file_head)                       \
    ((pt).rst_id == (file_head).rst_id && (pt).asn == (file_head).asn)

#define LRCV_LOG_POINT_ON_POST_FILE(pt, file_head)                       \
    ((pt).rst_id > (file_head).rst_id || ((pt).rst_id == (file_head).rst_id && (pt).asn > (file_head).asn))

#define LRCV_RECV_INTERVAL   100

typedef enum en_lrcv_status {
    LRCV_DISCONNECTED = 0,
    LRCV_PREPARE = 1,
    LRCV_READY = 2,
    LRCV_NEED_REPAIR = 3,
    LRCV_DETACHED = 4, // stream is removed/disabled
} lrcv_status_t;

typedef enum en_peer_role {
    PEER_UNKNOWN = 0,
    PEER_PRIMARY = 1,
    PEER_STANDBY = 2,
} peer_role_t;

typedef struct st_decompress_ctx {
    ZSTD_DCtx *zstd_dctx;
    uint32 buf_size;
    aligned_buf_t compressed_buf;
    uint32 data_size;
} decompress_ctx;

typedef struct st_log_switch_wait_info {
    log_point_t wait_point;
    uint32 file_id;
    bool32 waiting;
} log_switch_wait_info_t;

typedef struct st_lrcv_context {
    spinlock_t lock;
    uint32 sid;
    thread_t thread;
    cs_pipe_t *pipe;
    cs_packet_t *recv_pack;
    cs_packet_t *send_pack;
    knl_session_t *session;
    rep_msg_header_t header;  // used to receive message header
    rep_buffer_t extend_buf;  // used to receive message body
    decompress_ctx d_ctx;
    rep_buffer_t recv_buf;    // used to receive log batch only
    rep_buffer_t send_buf;    // used to send message
    log_point_t flush_point;
    /*
     * Coordinates of the last flushed batch in the PRIMARY's redo file layout.
     * The local flush_point tracks the standby's own write_pos/block_id; the
     * log sender resumes from peer flush_point in ITS file, so responses must
     * carry primary-side block ids taken from received batch headers.
     */
    log_point_t primary_report_point;
    log_point_t contflush_point;
    log_point_t primary_curr_point;
    uint32 timeout;
    lrcv_status_t status;
    reset_log_t primary_resetlog;
    rep_state_t state;
    uint16 peer_repl_port;
    peer_role_t peer_role;
    volatile bool32 role_spec_building;
    bool32 reconnected;
    knl_scn_t flush_scn;
    rep_bak_task_t task;
    bool32 is_building;
    log_switch_wait_info_t wait_info;
    uint32 dbid;
    uint32 reset_asn;
    bool32 host_changed;
    char primary_host[OG_HOST_NAME_BUFFER_SIZE]; // node is connected by this host
    knl_scn_t primary_reset_log_scn;
    /* ---- redo stream identity (N-to-M replication) ---- */
    uint32 src_dbid;      // bound stream database id
    uint32 src_node_id;   // bound stream node id (slot in the same space as cluster node_id)
    bool32 stream_bound;  // true after REP_QUERY_STATUS_REQ binds this context to a stream
    volatile bool32 taken_over; // set when a newer connection preempts this context's stream
    /* ---- per-stream log file group state ---- */
    logfile_set_t *file_set; // LOGFILE_SET(session, src_node_id), set when stream is bound
    spinlock_t stream_lock;  // protects per-stream log file state
    uint16 stream_curr_file;
    uint16 stream_active_file;
    uint32 stream_logfile_hwm;
    uint64 stream_free_size;
    uint64 stream_flushed_lfn; // latest received batch lfn of this stream
    /*
     * Last batch lfn written into each stream log file, recorded when the
     * receiver rotates out of that file.  Reuse for recycle decisions on a
     * standby: after a (re)send the per-node files carry the PRIMARY node's
     * asn numbering while the saved rcy/lrp point keeps the standby's local
     * asn numbering, so comparing file heads by (rst, asn) is not valid.
     * Batch lfns are monotonic and consistent in both numberings, therefore
     * "last written lfn <= applied lfn" is the correct "file fully consumed"
     * test.  Indexed by stream file id; 0 means the file has no redo of its
     * own (fresh/empty file, safe to recycle once the applied point moved on).
     */
    uint64 stream_file_last_lfn[OG_MAX_LOG_FILES];
    log_point_t stream_curr_point; // per-stream standby current point
    uint64 lsn_frontier;       // drain-certificate LSN frontier for this stream
    bool32 terminal;           // source terminated (cluster demote confirmed): barrier treats it as drained
    int32 stream_handle[OG_MAX_LOG_FILES]; // per-stream log file handles (remote streams only)
} lrcv_context_t;

/*
 * Multi-stream log receiver manager.
 *
 * A standby node can accept multiple redo streams (one per source primary node).
 * Each stream is identified by (src_dbid, src_node_id) and is stored in the
 * per-node log file group LOGFILE_SET(session, src_node_id), reusing the
 * cluster per-node recovery/archiving machinery.
 *
 * The array index is only a connection-pool slot.  Callers must resolve the
 * stream by purpose: lrcv_get_local_stream() for the local redo stream,
 * lrcv_get_stream() for a specified source node, or an explicit all-stream
 * iteration for cluster-wide state.
 */
typedef struct st_lrcv_mgr {
    spinlock_t lock;
    uint32 stream_count; // number of slots ever claimed (diagnostics)
    /*
     * Bitmap of source nodes that have no sender in the current topology
     * (learned from the source cluster's online-node bitmap announced in
     * REP_QUERY_STATUS_REQ).  The replay drain barrier must skip them;
     * otherwise their zero frontier gates every other stream and the standby
     * can never drain after a switchover to a smaller source cluster.
     */
    uint64 source_absent;
    /*
     * Per-node primary-side resume point captured at BUILD / recovery replay.
     * The ctrl rcy/lrp point after recovery is the standby's local replay
     * cursor and may not be a valid batch boundary in the PRIMARY's file;
     * the first bind after BUILD must report this point instead.  Indexed by
     * cluster node id.  Zero lfn means not captured yet.
     */
    log_point_t primary_resume_point[OG_MAX_INSTANCES];
    /*
     * When true for a node, the next (non-reconnect) bind of that stream must
     * use primary_resume_point[] as flush_point, regardless of branch logic.
     * It is armed only by lrcv_seed_primary_resume_points() (build end /
     * recovery end) while the node's stream is NOT bound, and consumed by the
     * next bind; steady-state replay never re-arms it, so runtime reconnects
     * keep the dedicated reconnect path instead of the first-bind shortcut.
     */
    bool32 first_bind_after_build[OG_MAX_INSTANCES];
    /*
     * Bitmask of nodes that currently have a bound redo stream.  Maintained
     * under mgr->lock at bind/unbind.  capture uses it as a lock-free fast
     * path hint to skip the per-batch lock in steady-state replay: while a
     * stream is bound the captured point is never consumed, so updating it
     * only wastes a global spinlock acquisition on the hot replay path.
     * A stale read is benign in both directions (extra lock, or a skipped
     * update that would not be used).
     */
    uint64 bound_mask;
    lrcv_context_t streams[OG_MAX_INSTANCES];
} lrcv_mgr_t;

status_t lrcv_proc(lrcv_context_t *lrcv);
status_t lrcv_get_primary_server(knl_session_t *session, int32 retry_count, char *host,
    uint32 host_buf_size, uint16 *port);
status_t lrcv_buf_alloc(knl_session_t *session, lrcv_context_t *lrcv);
void lrcv_close(knl_session_t *session);
bool32 lrcv_switchover_enabled(knl_session_t *session);

void lrcv_trigger_backup_task(knl_session_t *session);
status_t lrcv_wait_task_process(knl_session_t *session);
void lrcv_wait_status_prepared(knl_session_t *session);
void lrcv_reset_primary_host(knl_session_t *session);
void lrcv_clear_needrepair_for_failover(knl_session_t *session);
lrcv_context_t *lrcv_get_stream(knl_session_t *session, uint32 src_node_id);
lrcv_context_t *lrcv_get_local_stream(knl_session_t *session);
bool32 lrcv_has_active_session(knl_session_t *session);
bool32 lrcv_has_status(knl_session_t *session, lrcv_status_t status);
bool32 lrcv_has_state(knl_session_t *session, rep_state_t state);
bool32 lrcv_has_unready_stream(knl_session_t *session);
void lrcv_set_reconnected(knl_session_t *session, bool32 reconnected);
void lrcv_set_timeout(knl_session_t *session, uint32 timeout);
void lrcv_update_frontier(lrcv_context_t *lrcv, uint64 lsn);
void lrcv_close_stream_files(lrcv_context_t *lrcv);
void lrcv_capture_primary_resume_point(knl_session_t *session, uint32 node_id, const log_point_t *point);
void lrcv_seed_primary_resume_points(knl_session_t *session);

#endif
