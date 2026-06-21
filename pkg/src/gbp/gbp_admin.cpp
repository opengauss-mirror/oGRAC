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
 * gbp_admin.cpp
 *
 *
 * IDENTIFICATION
 * src/gbp/gbp_admin.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "gbp_server.h"

#include "gbp_log.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>

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

namespace {

constexpr int GBP_ADMIN_MAX_FILE_NO = 65535;
constexpr int GBP_ADMIN_HEX_BYTE_WIDTH = 2;
constexpr int GBP_ADMIN_CHECKSUM_HEX_WIDTH = 4;
constexpr size_t GBP_ADMIN_PAGE_HEADER_PREVIEW = 96;
constexpr size_t GBP_ADMIN_PAGE_TAIL_PREVIEW = 64;
constexpr size_t GBP_ADMIN_QUEUE_PREFIX_LEN = 3;
constexpr int GBP_ADMIN_MILLISECONDS_PER_SECOND = 1000;
constexpr int GBP_ADMIN_LISTEN_BACKLOG = 16;
constexpr int GBP_ADMIN_WINSOCK_VERSION_MAJOR = 2;
constexpr int GBP_ADMIN_WINSOCK_VERSION_MINOR = 2;

}  // namespace

static bool parse_nonnegative_int_exact(const std::string& text, int& out)
{
    if (text.empty()) {
        return false;
    }
    size_t parsed = 0;
    try {
        const long value = std::stol(text, &parsed);
        if (parsed != text.size() || value < 0 || value > std::numeric_limits<int>::max()) {
            return false;
        }
        out = static_cast<int>(value);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parse_file_page(const std::string& text, int& file_no, int& page_no)
{
    std::string s = text;
    for (char& c : s) {
        if (c == '_' || c == '/') {
            c = '-';
        }
    }
    const auto pos = s.find('-');
    if (pos == std::string::npos) {
        return false;
    }
    if (!parse_nonnegative_int_exact(s.substr(0, pos), file_no)) {
        return false;
    }
    if (!parse_nonnegative_int_exact(s.substr(pos + 1), page_no)) {
        return false;
    }
    if (file_no > GBP_ADMIN_MAX_FILE_NO) {
        return false;
    }
    return true;
}

static std::string hex_preview(const char* data, size_t len, size_t limit)
{
    std::ostringstream os;
    const size_t n = std::min(len, limit);
    os << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        os << std::setw(GBP_ADMIN_HEX_BYTE_WIDTH) << static_cast<unsigned>(static_cast<unsigned char>(data[i]));
    }
    return os.str();
}

static std::string admin_query_page(GbpServerState& state, int file_no, int page_no)
{
    const uint64_t key = page_id_key(static_cast<uint32_t>(page_no), static_cast<uint16_t>(file_no));
    const uint32_t qid = page_queue_id(static_cast<uint32_t>(page_no));
    GbpShard& shard = state.shard(qid);
    bool pending = false;
    log_point_t reset{};
    log_point_t frontier{};
    int cache_size = 0;
    std::optional<PageRecord> hit_rec;
    {
        std::lock_guard<std::mutex> g(shard.mtx);
        cache_size = static_cast<int>(shard.page_cache.size());
        pending = shard.batch_pending.contains(key);
        reset = shard.reset_point;
        frontier = shard.frontier_point;
        auto it = shard.page_cache.find(key);
        if (it != shard.page_cache.end()) {
            hit_rec = it->second;
        }
    }
    if (!hit_rec) {
        return "NOT_FOUND file=" + std::to_string(file_no) + " page=" + std::to_string(page_no) +
               " qid=" + std::to_string(qid) + " pending=" + std::to_string(static_cast<int>(pending)) +
               " reset[" + format_log_point_short(reset) + "] frontier[" + format_log_point_short(frontier) +
               "] cache_total=" + std::to_string(cache_size) + "\n";
    }
    const PageRecord& hit = *hit_rec;
    uint64_t lsn = 0;
    uint32_t pcn = 0;
    uint16_t cks = 0;
    page_diag_from_block(page_block_cstr(hit), lsn, pcn, cks);
    std::ostringstream cks_os;
    cks_os << std::hex << std::setw(GBP_ADMIN_CHECKSUM_HEX_WIDTH) << std::setfill('0') << cks;
    return "FOUND file=" + std::to_string(file_no) + " page=" + std::to_string(page_no) + " qid=" +
           std::to_string(qid) + " pending=" + std::to_string(static_cast<int>(pending)) + " lsn=" +
           std::to_string(lsn) + " pcn=" + std::to_string(pcn) + " checksum=0x" + cks_os.str() +
           " trunc_lfn=" + std::to_string(log_point_lfn(hit.coverage_begin)) + " lrp_lfn=" +
           std::to_string(log_point_lfn(hit.coverage_lrp)) + " writer_inst=" + std::to_string(hit.writer_inst) +
           " writer_seq=" + std::to_string(hit.writer_seq) + " reset[" + format_log_point_short(reset) +
           "] frontier[" + format_log_point_short(frontier) + "] cache_total=" + std::to_string(cache_size) + "\n";
}

static std::string admin_dump_page(GbpServerState& state, int file_no, int page_no)
{
    const uint64_t key = page_id_key(static_cast<uint32_t>(page_no), static_cast<uint16_t>(file_no));
    const uint32_t qid = page_queue_id(static_cast<uint32_t>(page_no));
    GbpShard& shard = state.shard(qid);
    bool pending = false;
    log_point_t reset{};
    log_point_t frontier{};
    int cache_size = 0;
    std::optional<PageRecord> hit_rec;
    {
        std::lock_guard<std::mutex> g(shard.mtx);
        cache_size = static_cast<int>(shard.page_cache.size());
        pending = shard.batch_pending.contains(key);
        reset = shard.reset_point;
        frontier = shard.frontier_point;
        auto it = shard.page_cache.find(key);
        if (it != shard.page_cache.end()) {
            hit_rec = it->second;
        }
    }
    if (!hit_rec) {
        return "NOT_FOUND file=" + std::to_string(file_no) + " page=" + std::to_string(page_no) +
               " qid=" + std::to_string(qid) + " pending=" + std::to_string(static_cast<int>(pending)) +
               " reset[" + format_log_point_short(reset) + "] frontier[" + format_log_point_short(frontier) +
               "] cache_total=" + std::to_string(cache_size) + "\n";
    }
    const PageRecord& hit = *hit_rec;
    uint64_t lsn = 0;
    uint32_t pcn = 0;
    uint16_t cks = 0;
    page_diag_from_block(page_block_cstr(hit), lsn, pcn, cks);
    uint32_t tr_asn = 0;
    uint32_t tr_blk = 0;
    uint32_t tr_rst = 0;
    uint32_t lr_asn = 0;
    uint32_t lr_blk = 0;
    uint32_t lr_rst = 0;
    uint64_t tr_lfn = 0;
    uint64_t tr_lsn = 0;
    uint64_t lr_lfn = 0;
    uint64_t lr_lsn = 0;
    parse_log_point_fields(hit.coverage_begin, tr_asn, tr_blk, tr_rst, tr_lfn, tr_lsn);
    parse_log_point_fields(hit.coverage_lrp, lr_asn, lr_blk, lr_rst, lr_lfn, lr_lsn);
    std::ostringstream os;
    os << "DUMP_BEGIN\n"
       << "file=" << file_no << "\n"
       << "page=" << page_no << "\n"
       << "qid=" << qid << "\n"
       << "pending=" << static_cast<int>(pending) << "\n"
       << "cache_total=" << cache_size << "\n"
       << "writer_inst=" << hit.writer_inst << "\n"
       << "writer_seq=" << hit.writer_seq << "\n"
       << "page_lsn=" << lsn << "\n"
       << "page_pcn=" << pcn << "\n"
       << "page_checksum=0x" << std::hex << std::setw(GBP_ADMIN_CHECKSUM_HEX_WIDTH) << std::setfill('0') << cks
       << std::dec << "\n"
       << "trunc_rst=" << tr_rst << "\n"
       << "trunc_asn=" << tr_asn << "\n"
       << "trunc_blk=" << tr_blk << "\n"
       << "trunc_lfn=" << tr_lfn << "\n"
       << "trunc_lsn=" << tr_lsn << "\n"
       << "lrp_rst=" << lr_rst << "\n"
       << "lrp_asn=" << lr_asn << "\n"
       << "lrp_blk=" << lr_blk << "\n"
       << "lrp_lfn=" << lr_lfn << "\n"
       << "lrp_lsn=" << lr_lsn << "\n"
       << "reset=" << format_log_point_short(reset) << "\n"
       << "frontier=" << format_log_point_short(frontier) << "\n";
    const char* trunc_bytes = reinterpret_cast<const char*>(&hit.coverage_begin);
    const char* lrp_bytes = reinterpret_cast<const char*>(&hit.coverage_lrp);
    os << "trunc_hex=" << hex_preview(trunc_bytes, LOG_POINT_SIZE, LOG_POINT_SIZE) << "\n"
       << "lrp_hex=" << hex_preview(lrp_bytes, LOG_POINT_SIZE, LOG_POINT_SIZE) << "\n"
       << "page_header_hex=" << hex_preview(page_block_cstr(hit), GBP_PAGE_SIZE, GBP_ADMIN_PAGE_HEADER_PREVIEW) << "\n";
    const char* block = page_block_cstr(hit);
    if (block) {
        os << "page_tail_hex=" << hex_preview(block + GBP_PAGE_SIZE - GBP_ADMIN_PAGE_TAIL_PREVIEW,
                                              GBP_ADMIN_PAGE_TAIL_PREVIEW, GBP_ADMIN_PAGE_TAIL_PREVIEW) << "\n";
    } else {
        os << "page_tail_hex=\n";
    }
    os << "DUMP_END\n";
    return os.str();
}

static std::string admin_window(GbpServerState& state)
{
    const bool lsn_only = state.config().log_cmp_lsn_only;
    const CkptResult ckpt = state.ckpt_snapshot(lsn_only);
    log_point_t resets[OG_GBP_SESSION_COUNT]{};
    log_point_t frontiers[OG_GBP_SESSION_COUNT]{};
    collect_queue_points(state, resets, frontiers);
    const std::string reset_diag = queue_resets_diag(resets, lsn_only);
    const std::string frontier_diag = queue_frontiers_diag(frontiers, lsn_only);
    int pending_pages = 0;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        const GbpShard& shard = state.shard(qid);
        std::lock_guard<std::mutex> g(shard.mtx);
        pending_pages += static_cast<int>(shard.batch_pending.size());
    }
    std::ostringstream os;
    os << "WINDOW_BEGIN\n"
       << "cache_pages=" << ckpt.cache_pages << "\n"
       << "pending_pages=" << pending_pages << "\n"
       << "max_cache_pages=" << state.config().max_cache_pages << "\n"
       << "capacity_evict_on_write=" << static_cast<int>(state.config().capacity_evict_on_write) << "\n"
       << "max_lsn=" << ckpt.max_lsn << "\n"
       << "begin=" << format_log_point_short(ckpt.begin) << "\n"
       << "rcy=" << format_log_point_short(ckpt.rcy) << "\n"
       << "lrp=" << format_log_point_short(ckpt.lrp) << "\n"
       << "evict_in_progress=" << ckpt.diag.evict_in_progress << "\n"
       << "purge_stable=" << ckpt.diag.purge_stable << "\n"
       << "empty_reason=" << ckpt.diag.empty_reason << "\n";
    if (!reset_diag.empty()) {
        os << reset_diag.substr(GBP_ADMIN_QUEUE_PREFIX_LEN) << "\n";
    }
    if (!frontier_diag.empty()) {
        os << frontier_diag.substr(GBP_ADMIN_QUEUE_PREFIX_LEN) << "\n";
    }
    os << "WINDOW_END\n";
    return os.str();
}

static std::string admin_stats(GbpServerState& state)
{
    int cache_total = 0;
    int pending_total = 0;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        const GbpShard& shard = state.shard(qid);
        std::lock_guard<std::mutex> g(shard.mtx);
        cache_total += static_cast<int>(shard.page_cache.size());
        pending_total += static_cast<int>(shard.batch_pending.size());
    }
    return "OK cache_total=" + std::to_string(cache_total) + " pending_total=" + std::to_string(pending_total) +
           " max_cache_pages=" + std::to_string(state.config().max_cache_pages) +
           " capacity_evict_on_write=" + std::to_string(static_cast<int>(state.config().capacity_evict_on_write)) +
           "\n";
}

static std::string admin_read_phase(ReadPhase& read_phase, const Config& cfg)
{
    const ReadPhaseSnapshot snap = get_read_phase_snapshot(read_phase);
    std::ostringstream os;
    os << "READ_PHASE_BEGIN\n"
       << "active=" << static_cast<int>(snap.active) << "\n"
       << "ending=" << static_cast<int>(snap.ending) << "\n"
       << "elapsed_ms=" << static_cast<int>(snap.elapsed_s * GBP_ADMIN_MILLISECONDS_PER_SECOND) << "\n"
       << "idle_ms=" << static_cast<int>(snap.idle_s * GBP_ADMIN_MILLISECONDS_PER_SECOND) << "\n"
       << "inflight_reads=" << snap.inflight_reads << "\n"
       << "timeout_s=" << cfg.read_phase_timeout << "\n"
       << "dropped_page_writes=" << snap.dropped_page_writes << "\n"
       << "timeout_warned=" << static_cast<int>(snap.timeout_warned) << "\n"
       << "READ_PHASE_END\n";
    return os.str();
}

static std::string admin_force_read_end(GbpServerState& state, ReadPhase& read_phase, const Config& cfg)
{
    const ReadPhaseEndResult ended = force_read_phase_end(state, read_phase, cfg, "admin", "FORCE_READ_END");
    std::ostringstream os;
    os << "OK active_before=" << static_cast<int>(ended.active_before)
       << " ending_before=" << static_cast<int>(ended.ending_before)
       << " cleared=" << static_cast<int>(ended.cleared)
       << " elapsed_ms=" << static_cast<int>(ended.elapsed_s * GBP_ADMIN_MILLISECONDS_PER_SECOND)
       << " dropped_page_writes=" << ended.dropped_page_writes
       << " detached_pages=" << ended.detached_pages << "\n";
    return os.str();
}

void admin_server_loop(const std::string& host, int port, GbpServerState& state, ReadPhase& read_phase,
                       const Config& cfg)
{
    socket_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (is_invalid_socket(srv)) {
        gbp_run_log("admin socket create failed");
        return;
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        gbp_run_log("admin bind failed: invalid host " + host);
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        return;
    }
    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        gbp_run_log("admin bind failed on " + host + ":" + std::to_string(port));
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        return;
    }
    if (listen(srv, GBP_ADMIN_LISTEN_BACKLOG) != 0) {
        gbp_run_log("admin listen failed on " + host + ":" + std::to_string(port));
#if defined(_WIN32)
        closesocket(srv);
#else
        close(srv);
#endif
        return;
    }
    gbp_run_log("GBPS admin listening on " + host + ":" + std::to_string(port) +
                " (command: EXISTS|DUMP <file>-<page>, WINDOW, STATS, READ_PHASE, FORCE_READ_END)");

    while (true) {
        sockaddr_in client{};
        gbp_socklen_t clen = sizeof(client);
        socket_t fd = accept(srv, reinterpret_cast<sockaddr*>(&client), &clen);
        if (is_invalid_socket(fd)) {
            continue;
        }
        std::thread([fd, &state, &read_phase, cfg]() {
            char buf[512];
#if defined(_WIN32)
            const int n = recv(fd, buf, sizeof(buf) - 1, 0);
#else
            const ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
#endif
            std::string out = "ERR usage: EXISTS <file>-<page> | DUMP <file>-<page> | WINDOW | STATS | "
                              "READ_PHASE | FORCE_READ_END\n";
            if (n > 0) {
                buf[n] = '\0';
                std::string cmd(buf);
                while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
                    cmd.pop_back();
                }
                std::istringstream iss(cmd);
                std::string verb;
                std::string arg;
                iss >> verb;
                iss >> arg;
                for (char& c : verb) {
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                }
                int file_no = 0;
                int page_no = 0;
                try {
                    if (verb == "EXISTS" && !arg.empty() && parse_file_page(arg, file_no, page_no)) {
                        out = admin_query_page(state, file_no, page_no);
                    } else if (verb == "DUMP" && !arg.empty() && parse_file_page(arg, file_no, page_no)) {
                        out = admin_dump_page(state, file_no, page_no);
                    } else if (verb == "WINDOW") {
                        out = admin_window(state);
                    } else if (verb == "STATS") {
                        out = admin_stats(state);
                    } else if (verb == "READ_PHASE") {
                        out = admin_read_phase(read_phase, cfg);
                    } else if (verb == "FORCE_READ_END") {
                        out = admin_force_read_end(state, read_phase, cfg);
                    }
                } catch (const std::exception& exc) {
                    out = std::string("ERR ") + exc.what() + "\n";
                }
            }
            send_full(fd, out.data(), out.size());
#if defined(_WIN32)
            closesocket(fd);
#else
            close(fd);
#endif
        }).detach();
    }
}

bool admin_query_once(const std::string& host, int port, const std::string& command,
                      std::string& response, std::string& err)
{
    if (port <= 0) {
        err = "gbps admin port is disabled";
        return false;
    }
#if defined(_WIN32)
    WSADATA wsa{};
    WSAStartup(MAKEWORD(GBP_ADMIN_WINSOCK_VERSION_MAJOR, GBP_ADMIN_WINSOCK_VERSION_MINOR), &wsa);
#endif
    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (is_invalid_socket(fd)) {
        err = "failed to create admin socket";
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        err = "invalid admin host: " + host;
#if defined(_WIN32)
        closesocket(fd);
#else
        close(fd);
#endif
        return false;
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "failed to connect gbps admin " + host + ":" + std::to_string(port);
#if defined(_WIN32)
        closesocket(fd);
#else
        close(fd);
#endif
        return false;
    }
    std::string wire = command;
    if (wire.empty() || wire.back() != '\n') {
        wire.push_back('\n');
    }
    if (!send_full(fd, wire.data(), wire.size())) {
        err = "failed to send admin command";
#if defined(_WIN32)
        closesocket(fd);
#else
        close(fd);
#endif
        return false;
    }

    char buf[4096];
    response.clear();
    while (true) {
#if defined(_WIN32)
        const int n = recv(fd, buf, sizeof(buf), 0);
#else
        const ssize_t n = recv(fd, buf, sizeof(buf), 0);
#endif
        if (n <= 0) {
            break;
        }
        response.append(buf, static_cast<size_t>(n));
    }
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
    return true;
}

}  // namespace gbp
