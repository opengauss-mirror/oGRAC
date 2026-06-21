#include "gbp_log.h"
#include "gbp_server.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
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
#include <unistd.h>
#endif

namespace gbp {

static double now_seconds() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

static void read_phase_enter(ReadPhase& rp, const std::string& peer, const std::string& reason) {
    bool was_active = false;
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        was_active = rp.active;
        if (!was_active) {
            rp.active = true;
            rp.started_at = now_seconds();
            rp.dropped_page_writes = 0;
            rp.timeout_warned = false;
        }
        rp.cv.notify_all();
    }
    if (!was_active) gbp_run_log("READ_PHASE enter peer=" + peer + " reason=" + reason);
}

static bool read_phase_drop_page_write(ReadPhase& rp, const std::string& peer, uint32_t qid, uint32_t page_num) {
    int dropped = 0;
    double started_at = 0;
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        if (!rp.active) return false;
        dropped = ++rp.dropped_page_writes;
        started_at = rp.started_at;
    }
    if (dropped <= 8 || dropped % 1024 == 0) {
        gbp_run_log("PAGE_WRITE ignored during READ_PHASE peer=" + peer + " qid=" + std::to_string(qid) +
                    " page_num=" + std::to_string(page_num) + " dropped=" + std::to_string(dropped) +
                    " elapsed_ms=" + std::to_string(static_cast<int>((now_seconds() - started_at) * 1000)));
    }
    return true;
}

static void end_read_phase_sync(GbpServerState& state, ReadPhase& rp, const std::string& peer, const char* reason,
                                bool timing_diag) {
    state.read_diag().log_summary(peer, reason, timing_diag);
    state.selected_read_diag().log_summary(peer, reason, timing_diag);
    state.read_diag().reset();
    state.selected_read_diag().reset();
    int cache_pages = 0, pending_pages = 0, reset_count = 0, frontier_count = 0;
    state.clear_all(cache_pages, pending_pages, reset_count, frontier_count);
    state.reset_batch_pending_epoch();
    state.clear_evicted_holes();
    gbp_run_log(std::string("GBP state cleared reason=") + reason + " peer=" + peer + " cache_pages=" +
                std::to_string(cache_pages) + " pending=" + std::to_string(pending_pages) +
                " resets=" + std::to_string(reset_count) + " frontiers=" + std::to_string(frontier_count) +
                " mode=sync");
    std::lock_guard<std::mutex> g(rp.mtx);
    rp.active = false;
    rp.started_at = 0;
    rp.cv.notify_all();
}

static int end_read_phase_async(GbpServerState& state, ReadPhase& rp, const std::string& peer, const char* reason,
                                 bool timing_diag) {
    state.read_diag().log_summary(peer, reason, timing_diag);
    state.selected_read_diag().log_summary(peer, reason, timing_diag);
    state.read_diag().reset();
    state.selected_read_diag().reset();
    RetiredReadPhaseState retired = state.detach_read_phase_generation();
    const int detached_pages = retired.detached_pages;
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        rp.active = false;
        rp.started_at = 0;
        rp.cv.notify_all();
    }
    state.schedule_retired_destruction(std::move(retired));
    return detached_pages;
}

static void read_phase_maybe_timeout(ReadPhase& rp, GbpServerState& state, const Config& cfg,
                                     const std::string& peer) {
    if (cfg.read_phase_timeout <= 0) return;
    bool expired = false;
    {
        std::lock_guard<std::mutex> g(rp.mtx);
        if (rp.active && !rp.timeout_warned) {
            const double elapsed = now_seconds() - rp.started_at;
            if (elapsed >= cfg.read_phase_timeout) {
                rp.timeout_warned = true;
                expired = true;
            }
        }
    }
    if (!expired) return;
    gbp_run_log("READ_PHASE_TIMEOUT warning peer=" + peer + " cache_pages=" +
                std::to_string(state.total_page_count()) + " pending=" + std::to_string(state.pending_total()) +
                " active_preserved=1");
}

static void dispatch_msg(socket_t fd, const std::string& peer, const gbp_msg_hdr_t& hdr, const uint8_t* body,
                         size_t body_len, uint32_t conn_qid, GbpServerState& state, ReadPhase& read_phase,
                         ConnMeta& conn_meta, const Config& cfg, int64_t recv_hdr_us, int64_t recv_body_us) {
    read_phase_maybe_timeout(read_phase, state, cfg, peer);
    if (hdr.msg_type == GBP_REQ_NOTIFY_MSG) {
        uint32_t notify = MSG_GBP_INVALID;
        if (body_len >= 4) std::memcpy(&notify, body, 4);
        if (notify == MSG_GBP_READ_BEGIN) {
            state.read_diag().reset();
            state.selected_read_diag().reset();
            state.reset_batch_pending_epoch();
            read_phase_enter(read_phase, peer, "READ_BEGIN");
            send_ack(fd, hdr, ACK_GBP_READ_BEGIN);
            gbp_run_log("READ_PHASE enter peer=" + peer + " qid=" + std::to_string(conn_qid) +
                        " (lazy_batch_pending, direct_selected_reads_page_cache)");
        } else if (notify == MSG_GBP_READ_END) {
            int detached_pages = 0;
            if (cfg.read_end_mode == ReadEndMode::Sync) {
                end_read_phase_sync(state, read_phase, peer, "READ_END", cfg.timing_diag);
            } else {
                detached_pages = end_read_phase_async(state, read_phase, peer, "READ_END", cfg.timing_diag);
            }
            send_ack(fd, hdr, ACK_GBP_INVALID);
            if (cfg.read_end_mode == ReadEndMode::Async) {
                gbp_run_log("READ_END ack_immediate peer=" + peer + " detached_pages=" +
                            std::to_string(detached_pages) + " mode=async scheduled_background=1");
            }
            gbp_run_log("READ_PHASE leave peer=" + peer + " qid=" + std::to_string(conn_qid) +
                        (cfg.read_end_mode == ReadEndMode::Sync ? " (state cleared)" : " (ack_sent)"));
        } else {
            send_ack(fd, hdr, ACK_GBP_INVALID);
        }
        return;
    }
    if (hdr.msg_type == GBP_REQ_PAGE_WRITE) {
        uint32_t page_num = 0;
        if (body_len >= 4) std::memcpy(&page_num, body, 4);
        if (read_phase_drop_page_write(read_phase, peer, conn_qid, page_num)) {
            throw QuietDisconnect("PAGE_WRITE ignored during READ_PHASE");
        }
        const auto apply_begin = std::chrono::steady_clock::now();
        PageWriteResult wr =
            cache_pages_from_write(body, body_len, state, conn_qid, cfg.verbose, peer);
        const int64_t apply_us = us_since(apply_begin);
        const int64_t msg_recv_us = recv_hdr_us + recv_body_us;
        const bool reset_write = (page_num == 0);
        const bool slow_apply = cfg.page_write_slow_us > 0 &&
                                (apply_us >= cfg.page_write_slow_us || wr.lock_wait_us >= cfg.page_write_slow_us ||
                                 wr.lock_hold_us >= cfg.page_write_slow_us);
        const bool slow_recv =
            cfg.page_write_timing_us > 0 &&
            (recv_body_us >= cfg.page_write_timing_us || apply_us >= cfg.page_write_timing_us);
        if (cfg.verbose || reset_write || wr.pages_off < 0 || slow_apply || slow_recv) {
            gbp_run_log("PAGE_WRITE summary peer=" + peer + " queue=" + std::to_string(hdr.queue_id) +
                        " bytes=" + std::to_string(hdr.msg_length) + " page_num=" + std::to_string(page_num) +
                        " reset=" + std::to_string(static_cast<int>(reset_write)) +
                        " accepted=" + std::to_string(wr.accepted) +
                        " rejected_stale=" + std::to_string(wr.rejected) +
                        " pages_off=" + std::to_string(wr.pages_off) +
                        " item_size=" + std::to_string(GBP_PAGE_ITEM_SIZE) +
                        " body_len=" + std::to_string(body_len) +
                        " layout=" + std::string(wr.pages_off >= 0 ? "v2_ok" : "v2_unresolved") +
                        " recv_hdr_us=" + std::to_string(recv_hdr_us) +
                        " recv_body_us=" + std::to_string(recv_body_us) +
                        " msg_recv_us=" + std::to_string(msg_recv_us) +
                        " apply_us=" + std::to_string(apply_us) +
                        " plan_hold_us=" + std::to_string(wr.plan_hold_us) +
                        " payload_us=" + std::to_string(wr.payload_us) +
                        " apply_hold_us=" + std::to_string(wr.apply_hold_us) +
                        " lock_wait_us=" + std::to_string(wr.lock_wait_us) +
                        " lock_hold_us=" + std::to_string(wr.lock_hold_us));
        }
        return;
    }
    if (hdr.msg_type == GBP_REQ_READ_CKPT) {
        read_phase_enter(read_phase, peer, "READ_CKPT");
        send_read_ckpt_resp(fd, hdr, body, body_len, state, cfg.verbose, peer);
        return;
    }
    if (hdr.msg_type == GBP_REQ_PAGE_READ) {
        page_id_t req_page_id{};
        if (body_len >= 8) std::memcpy(&req_page_id, body, 8);
        const uint64_t pid_key = page_id_key_from_raw(req_page_id);
        GbpShard& shard = state.shard(page_queue_id(req_page_id.page));
        log_point_t trunc{};
        std::shared_ptr<const PagePayload> payload;
        bool hit = false;
        {
            std::lock_guard<std::mutex> g(shard.mtx);
            auto it = shard.page_cache.find(pid_key);
            if (it != shard.page_cache.end()) {
                trunc = it->second.coverage_begin;
                payload = it->second.payload;
                hit = true;
            }
        }
        if (cfg.verbose) {
            gbp_run_log("PAGE_READ peer=" + peer + " " +
                        format_page_id(req_page_id.file, req_page_id.page, req_page_id.aligned) +
                        " -> " + (hit ? "HIT" : "MISS"));
        }
        send_page_read_resp(fd, hdr, req_page_id, hit, trunc, hit && payload ? payload->block : nullptr);
        return;
    }
    if (hdr.msg_type == GBP_REQ_BATCH_PAGE_READ) {
        log_point_t skip{};
        if (body_len >= sizeof(log_point_t)) std::memcpy(&skip, body, sizeof(log_point_t));
        bool read_active = false;
        {
            std::lock_guard<std::mutex> g(read_phase.mtx);
            read_active = read_phase.active;
        }
        send_batch_read_resp(fd, hdr, skip, conn_qid, state, cfg.verbose, peer, read_active);
        return;
    }
    if (hdr.msg_type == GBP_REQ_READ_META_CHUNK) {
        send_meta_chunk_resp(fd, hdr, body, body_len, state, conn_meta, cfg.verbose, peer);
        return;
    }
    if (hdr.msg_type == GBP_REQ_BATCH_PAGE_READ_SELECTED) {
        send_batch_selected_read_resp(fd, hdr, body, body_len, state, cfg.verbose, peer, conn_qid);
        return;
    }
    if (hdr.msg_type == GBP_REQ_CLOSE_CONN) throw std::runtime_error("close requested");
    gbp_run_log("unknown msg_type=" + std::to_string(hdr.msg_type) + " len=" + std::to_string(hdr.msg_length));
}

void handle_conn(socket_t fd, const std::string& peer, GbpServerState& state, ReadPhase& read_phase,
                 const Config& cfg) {
    ConnMeta conn_meta;
    uint32_t req_qid = 0;
    try {
        uint32_t proto_code = 0;
        if (!recv_full(fd, &proto_code, 4) || proto_code != OG_PROTO_CODE) {
            throw std::runtime_error("invalid proto_code");
        }
        send_cs_ready_ack(fd);
        gbp_msg_hdr_t hdr{};
        if (!recv_full(fd, &hdr, sizeof(hdr)) || hdr.msg_type != GBP_REQ_SHAKE_HAND) {
            throw std::runtime_error("expect shake hand");
        }
        uint32_t shake_body[4]{};
        if (!recv_full(fd, shake_body, SHAKE_BODY_SIZE)) throw std::runtime_error("short shake body");
        req_qid = shake_body[0];
        send_shake_resp(fd, hdr, req_qid, shake_body[1]);
        if (cfg.verbose) {
            gbp_run_log("gbp handshake peer=" + peer + " qid=" + std::to_string(req_qid));
        }

        std::vector<uint8_t> body;
        while (true) {
            const auto msg_begin = std::chrono::steady_clock::now();
            if (!recv_full(fd, &hdr, sizeof(hdr))) break;
            const int64_t recv_hdr_us = us_since(msg_begin);
            if (hdr.msg_length < HDR_SIZE) throw std::runtime_error("invalid msg_len");
            const size_t body_len = hdr.msg_length - HDR_SIZE;
            body.resize(body_len);
            int64_t recv_body_us = 0;
            if (body_len > 0) {
                const auto body_begin = std::chrono::steady_clock::now();
                if (!recv_full(fd, body.data(), body_len)) break;
                recv_body_us = us_since(body_begin);
            }
            dispatch_msg(fd, peer, hdr, body.data(), body_len, req_qid, state, read_phase, conn_meta, cfg,
                         recv_hdr_us, recv_body_us);
        }
    } catch (const QuietDisconnect& exc) {
        if (cfg.verbose) gbp_run_log("client intentionally closed peer=" + peer + " reason=" + exc.what());
    } catch (const std::exception& exc) {
        gbp_run_log("client error peer=" + peer + " err=" + exc.what());
    }
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
}

void run_server(const std::string& host, int port, const Config& cfg, int admin_port, const std::string& admin_host) {
#if defined(_WIN32)
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    GbpServerState state(cfg);
    ReadPhase read_phase;
    state.start_evict_worker();
    if (admin_port > 0) {
        std::thread(admin_server_loop, admin_host, admin_port, std::ref(state)).detach();
    }

    socket_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (is_invalid_socket(srv)) {
        gbp_run_log("socket create failed");
        std::exit(1);
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        gbp_run_log("bind failed: invalid host " + host);
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        std::exit(1);
    }
    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        gbp_run_log("bind failed on " + host + ":" + std::to_string(port));
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        std::exit(1);
    }
    if (listen(srv, 64) != 0) {
        gbp_run_log("listen failed on " + host + ":" + std::to_string(port));
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        std::exit(1);
    }
    gbp_run_log("GBPS listening on " + host + ":" + std::to_string(port) +
                " SMB_page_version=" + std::to_string(cfg.smb_version));

    while (true) {
        sockaddr_in client{};
        gbp_socklen_t clen = sizeof(client);
        socket_t fd = accept(srv, reinterpret_cast<sockaddr*>(&client), &clen);
        if (is_invalid_socket(fd)) continue;
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
        const std::string peer = std::string(ip) + ":" + std::to_string(ntohs(client.sin_port));
        std::thread(handle_conn, fd, peer, std::ref(state), std::ref(read_phase), cfg).detach();
    }
}

}  // namespace gbp
