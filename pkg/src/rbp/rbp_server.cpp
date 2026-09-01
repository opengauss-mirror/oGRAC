/* -------------------------------------------------------------------------
 *  This file is part of the oGRAC project.
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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
 * rbp_server.cpp
 *
 *
 * IDENTIFICATION
 * src/rbp/rbp_server.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "rbp_log.h"
#include "rbp_server.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <iostream>
#include <thread>
#if !defined(_WIN32)
#include <csignal>
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace rbp {

namespace {

constexpr int RBP_READ_PHASE_INITIAL_DROP_LOG_LIMIT = 8;
constexpr int RBP_READ_PHASE_DROP_LOG_INTERVAL = 1024;
constexpr int RBP_SERVER_MILLISECONDS_PER_SECOND = 1000;
constexpr int RBP_READ_PHASE_WATCHDOG_MS = 100;
constexpr int RBP_SERVER_LISTEN_BACKLOG = 64;
constexpr int RBP_WINSOCK_VERSION_MAJOR = 2;
constexpr int RBP_WINSOCK_VERSION_MINOR = 2;
constexpr double RBP_READ_OWNER_TIMEOUT_MIN_S = 300.0;
constexpr double RBP_READ_OWNER_TIMEOUT_FACTOR = 20.0;
constexpr double RBP_FENCE_REJECT_LOG_INTERVAL_S = 5.0;
constexpr uint32_t RBP_FENCE_REJECT_HEART_BEAT = 0;
constexpr uint32_t RBP_FENCE_REJECT_PAGE_WRITE = 1;
constexpr uint32_t RBP_FENCE_REJECT_KIND_COUNT = 2;
constexpr uint32_t RBP_SHAKE_QUEUE_INDEX = 0;
constexpr uint32_t RBP_SHAKE_TEMP_INDEX = 1;
constexpr uint32_t RBP_SHAKE_STANDBY_INDEX = 2;
constexpr uint32_t RBP_SHAKE_FLAGS_INDEX = 3;
constexpr const char* RBP_GUARD_UDS_FILE = "rbps_guard.sock";
std::atomic<uint64_t> g_connection_id{0};

uint64_t next_connection_id()
{
    uint64_t id = g_connection_id.fetch_add(1, std::memory_order_relaxed) + 1;
    if (id == 0) {
        id = g_connection_id.fetch_add(1, std::memory_order_relaxed) + 1;
    }
    return id;
}

std::string default_guard_uds_path()
{
    const char* home = std::getenv("OGDB_HOME");
    if (home == nullptr || *home == '\0') {
        return "";
    }
    return std::string(home) + "/run/" + RBP_GUARD_UDS_FILE;
}

[[noreturn]] void RbpStartupFatal(const std::string& msg)
{
    rbp_run_log(msg);
    std::cerr << msg << std::endl;
    std::exit(1);
}

}  // namespace

static double now_seconds()
{
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

static bool fence_reject_loggable(uint32_t qid, uint32_t kind, const std::string& reason)
{
    if (qid >= OG_RBP_SESSION_COUNT || kind >= RBP_FENCE_REJECT_KIND_COUNT) {
        return true;
    }

    static std::mutex log_mtx;
    static double last_log[RBP_FENCE_REJECT_KIND_COUNT][OG_RBP_SESSION_COUNT] = {};
    static std::string last_reason[RBP_FENCE_REJECT_KIND_COUNT][OG_RBP_SESSION_COUNT];

    const double now = now_seconds();
    std::lock_guard<std::mutex> g(log_mtx);
    double& last = last_log[kind][qid];
    std::string& prev_reason = last_reason[kind][qid];
    if (last == 0 || prev_reason != reason || now - last >= RBP_FENCE_REJECT_LOG_INTERVAL_S) {
        last = now;
        prev_reason = reason;
        return true;
    }
    return false;
}

ReadPhaseSnapshot get_read_phase_snapshot(ReadPhase& rp)
{
    ReadPhaseSnapshot snap;
    const double now = now_seconds();
    std::lock_guard<std::mutex> g(rp.mtx);
    snap.active = rp.active;
    snap.ending = rp.ending;
    snap.elapsed_s = rp.active ? now - rp.started_at : 0.0;
    snap.idle_s = rp.active ? now - (rp.last_activity_at > 0.0 ? rp.last_activity_at : rp.started_at) : 0.0;
    snap.inflight_reads = rp.inflight_reads;
    snap.dropped_page_writes = rp.dropped_page_writes;
    snap.timeout_warned = rp.timeout_warned;
    snap.owner_connected = rp.owner_connected;
    return snap;
}

static bool read_phase_tracks_request(uint32_t msg_type)
{
    return msg_type == RBP_REQ_PAGE_READ || msg_type == RBP_REQ_BATCH_PAGE_READ ||
           msg_type == RBP_REQ_READ_META_CHUNK || msg_type == RBP_REQ_BATCH_PAGE_READ_SELECTED;
}

class ReadPhaseActivityGuard {
public:
    ReadPhaseActivityGuard(ReadPhase& rp, uint32_t msg_type) : rp_(rp), active_(false)
    {
        if (!read_phase_tracks_request(msg_type)) {
            return;
        }
        const double now = now_seconds();
        std::lock_guard<std::mutex> g(rp_.mtx);
        if (!rp_.active || rp_.ending) {
            return;
        }
        rp_.last_activity_at = now;
        rp_.inflight_reads++;
        active_ = true;
    }

    ~ReadPhaseActivityGuard()
    {
        if (!active_) {
            return;
        }
        const double now = now_seconds();
        std::lock_guard<std::mutex> g(rp_.mtx);
        if (rp_.inflight_reads > 0) {
            rp_.inflight_reads--;
        }
        if (rp_.active) {
            rp_.last_activity_at = now;
        }
        rp_.cv.notify_all();
    }

private:
    ReadPhase& rp_;
    bool active_;
};

static bool read_phase_enter(ReadPhase& rp, ReadPhaseSnapshot& snap)
{
    bool entered = false;
    const double now = now_seconds();
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        if (!rp.active) {
            rp.active = true;
            rp.started_at = now;
            rp.last_activity_at = now;
            rp.inflight_reads = 0;
            rp.dropped_page_writes = 0;
            rp.timeout_warned = false;
            rp.ending = false;
            rp.owner_connected = true;
            entered = true;
        }
        snap.active = rp.active;
        snap.ending = rp.ending;
        snap.elapsed_s = rp.active ? now - rp.started_at : 0.0;
        snap.idle_s = rp.active ? now - (rp.last_activity_at > 0.0 ? rp.last_activity_at : rp.started_at) : 0.0;
        snap.inflight_reads = rp.inflight_reads;
        snap.dropped_page_writes = rp.dropped_page_writes;
        snap.timeout_warned = rp.timeout_warned;
        snap.owner_connected = rp.owner_connected;
        rp.cv.notify_all();
    }
    return entered;
}

static double read_phase_timeout_limit(const Config& cfg, bool owner_connected)
{
    if (!owner_connected) {
        return cfg.read_phase_timeout;
    }
    return std::max(RBP_READ_OWNER_TIMEOUT_MIN_S, cfg.read_phase_timeout * RBP_READ_OWNER_TIMEOUT_FACTOR);
}

static bool read_phase_drop_page_write(ReadPhase& rp, const std::string& peer, uint32_t qid, uint32_t page_num)
{
    int dropped = 0;
    double started_at = 0;
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        if (!rp.active) {
            return false;
        }
        dropped = ++rp.dropped_page_writes;
        started_at = rp.started_at;
    }
    if (dropped <= RBP_READ_PHASE_INITIAL_DROP_LOG_LIMIT || dropped % RBP_READ_PHASE_DROP_LOG_INTERVAL == 0) {
        rbp_run_log("PAGE_WRITE ignored during READ_PHASE peer=" + peer + " qid=" + std::to_string(qid) +
                    " page_num=" + std::to_string(page_num) + " dropped=" + std::to_string(dropped) +
                    " elapsed_ms=" + std::to_string(static_cast<int>((now_seconds() - started_at) *
                                                                      RBP_SERVER_MILLISECONDS_PER_SECOND)));
    }
    return true;
}

static void clear_read_phase_state_sync(RbpServerState& state, const std::string& peer, const char* reason,
                                        bool timing_diag)
{
    state.read_diag().log_summary(peer, reason, timing_diag);
    state.selected_read_diag().log_summary(peer, reason, timing_diag);
    state.read_diag().reset();
    state.selected_read_diag().reset();
    int cache_pages = 0;
    int pending_pages = 0;
    int reset_count = 0;
    int frontier_count = 0;
    state.clear_all(cache_pages, pending_pages, reset_count, frontier_count);
    state.reset_batch_pending_epoch();
    state.clear_evicted_holes();
    rbp_run_log(std::string("RBP state cleared reason=") + reason + " peer=" + peer + " cache_pages=" +
                std::to_string(cache_pages) + " pending=" + std::to_string(pending_pages) +
                " resets=" + std::to_string(reset_count) + " frontiers=" + std::to_string(frontier_count) +
                " mode=sync");
}

static int clear_read_phase_state_async(RbpServerState& state, const std::string& peer, const char* reason,
                                        bool timing_diag)
{
    state.read_diag().log_summary(peer, reason, timing_diag);
    state.selected_read_diag().log_summary(peer, reason, timing_diag);
    state.read_diag().reset();
    state.selected_read_diag().reset();
    RetiredReadPhaseState retired = state.detach_read_phase_generation();
    const int detached_pages = retired.detached_pages;
    state.schedule_retired_destruction(std::move(retired));
    return detached_pages;
}

ReadPhaseEndResult force_read_phase_end(RbpServerState& state, ReadPhase& rp, const Config& cfg,
                                        const std::string& peer, const char* reason)
{
    ReadPhaseEndResult result;
    const double now = now_seconds();
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        result.active_before = rp.active;
        result.ending_before = rp.ending;
        result.elapsed_s = rp.active ? now - rp.started_at : 0.0;
        result.dropped_page_writes = rp.dropped_page_writes;
        if (!rp.active || rp.ending) {
            return result;
        }
        rp.ending = true;
    }

    if (cfg.read_end_mode == ReadEndMode::Sync) {
        clear_read_phase_state_sync(state, peer, reason, cfg.timing_diag);
    } else {
        result.detached_pages = clear_read_phase_state_async(state, peer, reason, cfg.timing_diag);
    }
    state.finish_frozen_read();

    {
        std::lock_guard<std::mutex> g(rp.mtx);
        rp.active = false;
        rp.started_at = 0;
        rp.last_activity_at = 0;
        rp.inflight_reads = 0;
        rp.dropped_page_writes = 0;
        rp.timeout_warned = false;
        rp.ending = false;
        rp.owner_connected = false;
        rp.cv.notify_all();
    }
    result.cleared = true;
    return result;
}

static bool read_phase_expired(ReadPhase& rp, const Config& cfg, ReadPhaseSnapshot& snap)
{
    if (cfg.read_phase_timeout <= 0) {
        return false;
    }
    snap = get_read_phase_snapshot(rp);
    if (!snap.active || snap.ending) {
        return false;
    }
    return snap.idle_s >= read_phase_timeout_limit(cfg, snap.owner_connected);
}

static bool release_read_phase_if_timeout(RbpServerState& state, ReadPhase& rp, const Config& cfg,
                                          const std::string& peer)
{
    ReadPhaseSnapshot snap;
    if (!read_phase_expired(rp, cfg, snap)) {
        return false;
    }
    const double timeout_s = read_phase_timeout_limit(cfg, snap.owner_connected);
    rbp_run_log("READ_PHASE_TIMEOUT force_release peer=" + peer +
                " timeout_s=" + std::to_string(timeout_s) +
                " elapsed_ms=" + std::to_string(static_cast<int>(snap.elapsed_s *
                                                                  RBP_SERVER_MILLISECONDS_PER_SECOND)) +
                " idle_ms=" + std::to_string(static_cast<int>(snap.idle_s * RBP_SERVER_MILLISECONDS_PER_SECOND)) +
                " inflight_reads=" + std::to_string(snap.inflight_reads) +
                " owner_connected=" + std::to_string(static_cast<int>(snap.owner_connected)) +
                " dropped=" + std::to_string(snap.dropped_page_writes) +
                " cache_pages=" + std::to_string(state.total_page_count()) +
                " pending=" + std::to_string(state.pending_total()) + " active_preserved=0");
    const ReadPhaseEndResult ended = force_read_phase_end(state, rp, cfg, peer, "READ_PHASE_TIMEOUT");
    return ended.cleared;
}

static void read_phase_timeout_watchdog(RbpServerState& state, ReadPhase& rp, Config cfg)
{
    while (true) {
        if (cfg.read_phase_timeout > 0) {
            release_read_phase_if_timeout(state, rp, cfg, "watchdog");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(RBP_READ_PHASE_WATCHDOG_MS));
    }
}

static bool finish_page_write_reset(RbpServerState& state, ConnMeta& conn_meta, uint32_t conn_qid,
                                    const PageWriteResult& result, const std::string& peer)
{
    if (!result.reset_applied) {
        rbp_run_log("PAGE_WRITE RESET fence reject peer=" + peer +
                    " qid=" + std::to_string(conn_qid) + " reason=invalid_reset_body");
        throw QuietDisconnect("PAGE_WRITE RESET rejected: invalid reset body");
    }
    const bool reset_ready = state.mark_page_write_reset(conn_meta.page_write_generation, conn_qid,
                                                         conn_meta.connection_id);
    conn_meta.page_write_reset_seen = true;
    if (reset_ready) {
        rbp_run_log("PAGE_WRITE RESET fence ready generation=" +
                    std::to_string(conn_meta.page_write_generation) +
                    " mask=" + std::to_string(RBP_ALL_PAGE_WRITE_RESET_MASK));
    }
    return reset_ready;
}

static void dispatch_msg(socket_t fd, const std::string& peer, const rbp_msg_hdr_t& hdr, const uint8_t* body,
                         size_t body_len, uint32_t conn_qid, RbpServerState& state, ReadPhase& read_phase,
                         ConnMeta& conn_meta, const Config& cfg, int64_t recv_hdr_us, int64_t recv_body_us)
{
    if (hdr.msg_type == RBP_REQ_NOTIFY_MSG) {
        uint32_t notify = MSG_RBP_INVALID;
        if (body_len >= RBP_UINT32_WIRE_SIZE) {
            std::memcpy(&notify, body, RBP_UINT32_WIRE_SIZE);
        }
        if (notify == MSG_RBP_HEART_BEAT && conn_meta.page_write_stream &&
            !state.writer_generation_active(conn_meta.page_write_generation, conn_qid,
                                            conn_meta.connection_id, conn_meta.page_write_reset_seen)) {
            const std::string reason = state.guard_window_reject_reason(conn_meta.page_write_generation, conn_qid,
                                                                        conn_meta.connection_id,
                                                                        conn_meta.page_write_reset_seen, false);
            if (fence_reject_loggable(conn_qid, RBP_FENCE_REJECT_HEART_BEAT, reason)) {
                rbp_run_log("HEART_BEAT fence reject peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            " connection_generation=" + std::to_string(conn_meta.page_write_generation) +
                            " current_generation=" + std::to_string(state.guard_generation()) +
                            " reason=" + reason);
            }
            throw QuietDisconnect("HEART_BEAT rejected: stale PAGE_WRITE generation");
        }
        if (notify == MSG_RBP_READ_BEGIN) {
            ReadPhaseSnapshot snap;
            if (!state.acquire_guard_freeze()) {
                send_ack(fd, hdr, ACK_RBP_INVALID);
                rbp_run_log("READ_BEGIN rejected peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            " reason=disk_guard_unavailable");
                return;
            }
            const bool entered = read_phase_enter(read_phase, snap);
            state.release_guard_freeze();
            if (entered) {
                state.read_diag().reset();
                state.selected_read_diag().reset();
                state.reset_batch_pending_epoch();
                conn_meta.read_phase_owner = true;
            }
            send_ack(fd, hdr, ACK_RBP_READ_BEGIN);
            if (entered) {
                rbp_run_log("READ_PHASE enter peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            " reason=READ_BEGIN (lazy_batch_pending, direct_selected_reads_page_cache)");
            } else {
                rbp_run_log("READ_BEGIN idempotent ack peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            " elapsed_ms=" + std::to_string(static_cast<int>(
                                snap.elapsed_s * RBP_SERVER_MILLISECONDS_PER_SECOND)) +
                            " dropped=" + std::to_string(snap.dropped_page_writes));
            }
        } else if (notify == MSG_RBP_READ_END) {
            const ReadPhaseEndResult ended = force_read_phase_end(state, read_phase, cfg, peer, "READ_END");
            conn_meta.read_phase_owner = false;
            send_ack(fd, hdr, ACK_RBP_INVALID);
            if (!ended.cleared) {
                rbp_run_log("READ_END idempotent ack peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            (ended.ending_before ? " already_ending=1" : " inactive=1"));
            } else if (cfg.read_end_mode == ReadEndMode::Async) {
                rbp_run_log("READ_END ack_immediate peer=" + peer + " detached_pages=" +
                            std::to_string(ended.detached_pages) + " mode=async scheduled_background=1");
            }
            if (ended.cleared) {
                rbp_run_log("READ_PHASE leave peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            (cfg.read_end_mode == ReadEndMode::Sync ? " (state cleared)" : " (ack_sent)"));
            }
        } else {
            send_ack(fd, hdr, ACK_RBP_INVALID);
        }
        return;
    }
    if (hdr.msg_type == RBP_REQ_PAGE_WRITE) {
        uint32_t page_num = 0;
        if (body_len >= RBP_UINT32_WIRE_SIZE) {
            std::memcpy(&page_num, body, RBP_UINT32_WIRE_SIZE);
        }
        const bool reset_write = (page_num == 0);
        bool reset_fence_ready = false;
        release_read_phase_if_timeout(state, read_phase, cfg, peer);
        if (read_phase_drop_page_write(read_phase, peer, conn_qid, page_num)) {
            throw QuietDisconnect("PAGE_WRITE ignored during READ_PHASE");
        }
        if (!state.acquire_guard_window(conn_meta.page_write_generation, conn_qid, conn_meta.connection_id,
                                        conn_meta.page_write_reset_seen, reset_write)) {
            const std::string reason = state.guard_window_reject_reason(conn_meta.page_write_generation, conn_qid,
                                                                        conn_meta.connection_id,
                                                                        conn_meta.page_write_reset_seen, reset_write);
            if (fence_reject_loggable(conn_qid, RBP_FENCE_REJECT_PAGE_WRITE, reason)) {
                rbp_run_log("PAGE_WRITE fence reject peer=" + peer + " qid=" + std::to_string(conn_qid) +
                            " reset=" + std::to_string(static_cast<int>(reset_write)) +
                            " connection_generation=" + std::to_string(conn_meta.page_write_generation) +
                            " current_generation=" + std::to_string(state.guard_generation()) +
                            " reason=" + reason);
            }
            throw QuietDisconnect("PAGE_WRITE rejected: stale generation or RESET fence incomplete");
        }
        const auto apply_begin = std::chrono::steady_clock::now();
        PageWriteResult wr;
        try {
            wr = cache_pages_from_write(body, body_len, state, conn_qid, cfg.verbose, peer);
            if (reset_write) {
                reset_fence_ready = finish_page_write_reset(state, conn_meta, conn_qid, wr, peer);
            }
        } catch (...) {
            state.release_guard_window(reset_write);
            throw;
        }
        state.release_guard_window(reset_write);
        const int64_t apply_us = us_since(apply_begin);
        const bool slow_apply = cfg.page_write_slow_us > 0 &&
                                (apply_us >= cfg.page_write_slow_us || wr.lock_wait_us >= cfg.page_write_slow_us ||
                                 wr.lock_hold_us >= cfg.page_write_slow_us);
        const bool slow_recv =
            cfg.page_write_timing_us > 0 &&
            (recv_body_us >= cfg.page_write_timing_us || apply_us >= cfg.page_write_timing_us);
        const bool reset_summary = reset_write && (reset_fence_ready || slow_apply || slow_recv || wr.pages_off < 0);
        if (reset_summary || wr.pages_off < 0 || wr.capacity_rejected > 0 || slow_apply || slow_recv) {
            rbp_run_log("PAGE_WRITE summary peer=" + peer + " queue=" + std::to_string(hdr.queue_id) +
                        " bytes=" + std::to_string(hdr.msg_length) + " page_num=" + std::to_string(page_num) +
                        " reset=" + std::to_string(static_cast<int>(reset_write)) +
                        " accepted=" + std::to_string(wr.accepted) +
                        " rejected_total=" + std::to_string(wr.rejected) +
                        " rejected_stale=" + std::to_string(wr.rejected - wr.capacity_rejected) +
                        " rejected_capacity=" + std::to_string(wr.capacity_rejected) +
                        " pages_off=" + std::to_string(wr.pages_off) +
                        " item_size=" + std::to_string(RBP_PAGE_ITEM_SIZE) +
                        " body_len=" + std::to_string(body_len) +
                        " layout=" + std::string(wr.pages_off >= 0 ? "v2_ok" : "v2_unresolved") +
                        " recv_hdr_us=" + std::to_string(recv_hdr_us) +
                        " recv_body_us=" + std::to_string(recv_body_us) +
                        " apply_us=" + std::to_string(apply_us) +
                        " plan_hold_us=" + std::to_string(wr.plan_hold_us) +
                        " payload_us=" + std::to_string(wr.payload_us) +
                        " apply_hold_us=" + std::to_string(wr.apply_hold_us) +
                        " lock_wait_us=" + std::to_string(wr.lock_wait_us) +
                        " lock_hold_us=" + std::to_string(wr.lock_hold_us));
        }
        return;
    }
    ReadPhaseActivityGuard read_guard(read_phase, hdr.msg_type);
    if (hdr.msg_type == RBP_REQ_READ_CKPT) {
        send_read_ckpt_resp(fd, hdr, body, body_len, state, cfg.verbose, peer);
        return;
    }
    if (hdr.msg_type == RBP_REQ_DISK_GUARD) {
        if (peer.rfind("uds:", 0) != 0 || !conn_meta.guard_required) {
            send_ack(fd, hdr, ACK_RBP_INVALID);
            return;
        }
        const uint64_t generation =
            state.ensure_guard_session(conn_meta.connection_id, conn_meta.guard_generation);
        if (generation == 0) {
            send_ack(fd, hdr, ACK_RBP_INVALID);
            rbp_run_log("DISK_GUARD fence reject peer=" + peer +
                        " connection=" + std::to_string(conn_meta.connection_id) +
                        " connection_generation=" + std::to_string(conn_meta.guard_generation) +
                        " current_generation=" + std::to_string(state.guard_generation()));
            throw QuietDisconnect("DISK_GUARD rejected: stale owner or frozen read");
        }
        conn_meta.guard_generation = generation;
        handle_disk_guard_req({fd, hdr, body, body_len, state, conn_meta.connection_id,
                               conn_meta.guard_generation, peer});
        return;
    }
    if (hdr.msg_type == RBP_REQ_PAGE_READ) {
        page_id_t req_page_id{};
        if (body_len >= sizeof(req_page_id)) {
            std::memcpy(&req_page_id, body, sizeof(req_page_id));
        }
        const uint64_t pid_key = page_id_key_from_raw(req_page_id);
        RbpShard& shard = state.shard(page_queue_id(req_page_id.page));
        log_point_t trunc{};
        std::shared_ptr<const PagePayload> payload;
        uint64_t guard_lsn = 0;
        uint32_t guard_pcn = 0;
        bool hit = false;
        {
            std::lock_guard<std::mutex> g(shard.mtx);
            auto it = shard.page_cache.find(pid_key);
            if (it != shard.page_cache.end()) {
                trunc = it->second.coverage_begin;
                payload = it->second.payload;
                guard_lsn = it->second.guard_lsn;
                guard_pcn = it->second.guard_pcn;
                hit = true;
            }
        }
        send_page_read_resp(fd, hdr, req_page_id, hit, trunc, hit && payload ? payload->block : nullptr,
                            guard_lsn, guard_pcn);
        return;
    }
    if (hdr.msg_type == RBP_REQ_BATCH_PAGE_READ) {
        log_point_t skip{};
        if (body_len >= sizeof(log_point_t)) {
            std::memcpy(&skip, body, sizeof(log_point_t));
        }
        bool read_active = false;
        {
            std::lock_guard<std::mutex> g(read_phase.mtx);
            read_active = read_phase.active;
        }
        send_batch_read_resp(fd, hdr, skip, conn_qid, state, cfg.verbose, peer, read_active);
        return;
    }
    if (hdr.msg_type == RBP_REQ_READ_META_CHUNK) {
        send_meta_chunk_resp(fd, hdr, body, body_len, state, conn_meta, cfg.verbose, peer);
        return;
    }
    if (hdr.msg_type == RBP_REQ_BATCH_PAGE_READ_SELECTED) {
        send_batch_selected_read_resp(fd, hdr, body, body_len, state, cfg.verbose, peer, conn_qid);
        return;
    }
    if (hdr.msg_type == RBP_REQ_CLOSE_CONN) {
        throw std::runtime_error("close requested");
    }
    rbp_run_log("unknown msg_type=" + std::to_string(hdr.msg_type) + " len=" + std::to_string(hdr.msg_length));
}

void handle_conn(socket_t fd, const std::string& peer, RbpServerState& state, ReadPhase& read_phase,
                 const Config& cfg)
{
    ConnMeta conn_meta;
    conn_meta.connection_id = next_connection_id();
    uint32_t req_qid = 0;
    try {
        uint32_t proto_code = 0;
        if (!recv_full(fd, &proto_code, RBP_UINT32_WIRE_SIZE) || proto_code != OG_PROTO_CODE) {
            throw std::runtime_error("invalid proto_code");
        }
        send_cs_ready_ack(fd);
        rbp_msg_hdr_t hdr{};
        if (!recv_full(fd, &hdr, sizeof(hdr)) || hdr.msg_type != RBP_REQ_SHAKE_HAND) {
            throw std::runtime_error("expect shake hand");
        }
        uint32_t shake_body[4]{};
        if (!recv_full(fd, shake_body, SHAKE_BODY_SIZE)) {
            throw std::runtime_error("short shake body");
        }
        req_qid = shake_body[RBP_SHAKE_QUEUE_INDEX];
        const uint32_t handshake_flags = shake_body[RBP_SHAKE_FLAGS_INDEX];
        const uint32_t wire_version = handshake_flags & RBP_HANDSHAKE_VERSION_MASK;
        if (wire_version != RBP_WIRE_VERSION) {
            throw std::runtime_error("incompatible RBP wire version " + std::to_string(wire_version));
        }
        conn_meta.guard_required = (handshake_flags & RBP_HANDSHAKE_FLAG_DISK_GUARD) != 0;
        conn_meta.page_write_stream = shake_body[RBP_SHAKE_TEMP_INDEX] == 0 &&
                                      shake_body[RBP_SHAKE_STANDBY_INDEX] == 0;
        if (conn_meta.guard_required) {
            state.require_disk_guard();
        }
        conn_meta.page_write_generation = state.guard_generation();
        send_shake_resp(fd, hdr, req_qid, shake_body[RBP_SHAKE_TEMP_INDEX], RBP_WIRE_VERSION);
        if (cfg.verbose) {
            rbp_run_log("rbp handshake peer=" + peer + " qid=" + std::to_string(req_qid) +
                        " connection=" + std::to_string(conn_meta.connection_id) +
                        " wire_version=" + std::to_string(wire_version) +
                        " guard_required=" + std::to_string(static_cast<int>(conn_meta.guard_required)) +
                        " page_write_generation=" + std::to_string(conn_meta.page_write_generation));
        }

        std::vector<uint8_t> body;
        while (true) {
            const auto msg_begin = std::chrono::steady_clock::now();
            if (!recv_full(fd, &hdr, sizeof(hdr))) {
                break;
            }
            const int64_t recv_hdr_us = us_since(msg_begin);
            if (hdr.msg_length < HDR_SIZE) {
                throw std::runtime_error("invalid msg_len");
            }
            const size_t body_len = hdr.msg_length - HDR_SIZE;
            body.resize(body_len);
            int64_t recv_body_us = 0;
            if (body_len > 0) {
                const auto body_begin = std::chrono::steady_clock::now();
                if (!recv_full(fd, body.data(), body_len)) {
                    break;
                }
                recv_body_us = us_since(body_begin);
            }
            dispatch_msg(fd, peer, hdr, body.data(), body_len, req_qid, state, read_phase, conn_meta, cfg,
                         recv_hdr_us, recv_body_us);
        }
    } catch (const QuietDisconnect& exc) {
        if (cfg.verbose) {
            rbp_run_log("client intentionally closed peer=" + peer + " reason=" + exc.what());
        }
    } catch (const std::exception& exc) {
        rbp_run_log("client error peer=" + peer + " err=" + exc.what());
    }
    if (conn_meta.read_phase_owner) {
        (void)force_read_phase_end(state, read_phase, cfg, peer, "READ_OWNER_DISCONNECT");
    }
    if (conn_meta.guard_generation != 0) {
        state.end_guard_session(conn_meta.connection_id);
    }
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
}

#if !defined(_WIN32)
bool setup_guard_uds_server(const std::string& path, socket_t& srv, std::string& err)
{
    if (path.empty()) {
        err = "empty guard uds path";
        return false;
    }
    sockaddr_un addr{};
    if (path.size() >= sizeof(addr.sun_path)) {
        err = "guard uds path is too long: " + path;
        return false;
    }

    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (is_invalid_socket(srv)) {
        err = "guard uds socket create failed";
        return false;
    }

    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    (void)unlink(path.c_str());
    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "guard uds bind failed on " + path;
        close(srv);
        srv = invalid_socket();
        return false;
    }
    (void)chmod(path.c_str(), S_IRUSR | S_IWUSR);
    if (listen(srv, RBP_SERVER_LISTEN_BACKLOG) != 0) {
        err = "guard uds listen failed on " + path;
        close(srv);
        srv = invalid_socket();
        return false;
    }
    return true;
}

void guard_uds_server_loop(socket_t srv, const std::string& path, RbpServerState& state,
                           ReadPhase& read_phase, const Config& cfg)
{
    rbp_run_log("RBPS guard uds listening on " + path);
    while (!is_invalid_socket(srv)) {
        sockaddr_un client{};
        rbp_socklen_t clen = sizeof(client);
        socket_t fd = accept(srv, reinterpret_cast<sockaddr*>(&client), &clen);
        if (is_invalid_socket(fd)) {
            continue;
        }
        std::thread(handle_conn, fd, std::string("uds:") + path, std::ref(state), std::ref(read_phase), cfg).detach();
    }
}
#endif

void run_server(const std::string& host, int port, const Config& cfg, int admin_port, const std::string& admin_host)
{
#if defined(_WIN32)
    WSADATA wsa{};
    WSAStartup(MAKEWORD(RBP_WINSOCK_VERSION_MAJOR, RBP_WINSOCK_VERSION_MINOR), &wsa);
#else
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        rbp_run_log("signal(SIGPIPE) failed");
    }
#endif
    RbpServerState state(cfg);
    ReadPhase read_phase;
    socket_t admin_srv = invalid_socket();
    if (admin_port > 0) {
        std::string err;
        if (!setup_admin_server(admin_host, admin_port, admin_srv, err)) {
            RbpStartupFatal(err);
        }
    }
    state.start_evict_worker();
    if (cfg.read_phase_timeout > 0) {
        std::thread(read_phase_timeout_watchdog, std::ref(state), std::ref(read_phase), cfg).detach();
    }

    socket_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (is_invalid_socket(srv)) {
        RbpStartupFatal("socket create failed: " + RbpSocketErrorDetail(RbpLastSocketError()));
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        const std::string err = "bind failed: invalid host " + host;
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        RbpStartupFatal(err);
    }
    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int code = RbpLastSocketError();
        const std::string err = "bind failed on " + host + ":" + std::to_string(port) + ": " +
                                RbpSocketErrorDetail(code);
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        RbpStartupFatal(err);
    }
    if (listen(srv, RBP_SERVER_LISTEN_BACKLOG) != 0) {
        const int code = RbpLastSocketError();
        const std::string err = "listen failed on " + host + ":" + std::to_string(port) + ": " +
                                RbpSocketErrorDetail(code);
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        RbpStartupFatal(err);
    }
    rbp_run_log("RBPS listening on " + host + ":" + std::to_string(port) +
                " SMB_page_version=" + std::to_string(cfg.smb_version));
    if (!is_invalid_socket(admin_srv)) {
        AdminServerLoopContext admin_ctx{admin_srv, admin_host, admin_port, state, read_phase, cfg};
        std::thread(admin_server_loop, admin_ctx).detach();
    }
#if !defined(_WIN32)
    socket_t guard_srv = invalid_socket();
    const std::string guard_uds_path = default_guard_uds_path();
    if (!guard_uds_path.empty()) {
        std::string err;
        if (!setup_guard_uds_server(guard_uds_path, guard_srv, err)) {
            rbp_run_log(err);
            std::exit(1);
        }
        std::thread(guard_uds_server_loop, guard_srv, guard_uds_path, std::ref(state),
                    std::ref(read_phase), cfg).detach();
    }
#endif

    while (true) {
        sockaddr_in client{};
        rbp_socklen_t clen = sizeof(client);
        socket_t fd = accept(srv, reinterpret_cast<sockaddr*>(&client), &clen);
        if (is_invalid_socket(fd)) {
            continue;
        }
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
        const std::string peer = std::string(ip) + ":" + std::to_string(ntohs(client.sin_port));
        std::thread(handle_conn, fd, peer, std::ref(state), std::ref(read_phase), cfg).detach();
    }
}

}  // namespace rbp
