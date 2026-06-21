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
 * gbp_log.h
 *
 *
 * IDENTIFICATION
 * src/gbp/gbp_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef GBP_LOG_H
#define GBP_LOG_H

#include "gbp_wire.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace gbp {

inline constexpr int GBP_LOG_DIR_MODE = 0755;
inline constexpr size_t GBP_WINDOWS_DRIVE_PREFIX_LEN = 2;
inline constexpr size_t GBP_WINDOWS_DRIVE_COLON_INDEX = 1;
inline constexpr size_t GBP_PAGE_LSN_OFFSET = 16;
inline constexpr size_t GBP_PAGE_LSN_SIZE = sizeof(uint64_t);
inline constexpr size_t GBP_PAGE_PCN_OFFSET = 24;
inline constexpr size_t GBP_PAGE_PCN_SIZE = sizeof(uint32_t);
inline constexpr size_t GBP_PAGE_CHECKSUM_TAIL_OFFSET = sizeof(uint64_t);
inline constexpr size_t GBP_PAGE_CHECKSUM_SIZE = sizeof(uint16_t);

inline std::FILE* g_gbp_log_file = stderr;
inline std::mutex g_gbp_log_lock;

inline bool gbp_mkdir_one(const std::string& path)
{
    if (path.empty()) {
        return true;
    }
#if defined(_WIN32)
    if (_mkdir(path.c_str()) == 0 || errno == EEXIST) {
        return true;
    }
#else
    if (mkdir(path.c_str(), GBP_LOG_DIR_MODE) == 0 || errno == EEXIST) {
        return true;
    }
#endif
    return false;
}

inline bool gbp_mkdirs_for_file(const std::string& file, std::string& err)
{
    size_t pos = file.find_last_of("/\\");
    if (pos == std::string::npos) {
        return true;
    }
    std::string dir = file.substr(0, pos);
    if (dir.empty()) {
        return true;
    }
    size_t start = 0;
    if (dir.size() >= GBP_WINDOWS_DRIVE_PREFIX_LEN && dir[GBP_WINDOWS_DRIVE_COLON_INDEX] == ':') {
        start = GBP_WINDOWS_DRIVE_PREFIX_LEN;
    }
    while (start < dir.size() && (dir[start] == '/' || dir[start] == '\\')) {
        start++;
    }
    for (size_t i = start; i <= dir.size(); ++i) {
        if (i != dir.size() && dir[i] != '/' && dir[i] != '\\') {
            continue;
        }
        std::string part = dir.substr(0, i);
        if (part.empty()) {
            continue;
        }
        if (!gbp_mkdir_one(part)) {
            err = "failed to create log directory: " + part;
            return false;
        }
    }
    return true;
}

inline bool gbp_init_log_file(const std::string& file, std::string& err)
{
    if (file.empty()) {
        return true;
    }
    if (!gbp_mkdirs_for_file(file, err)) {
        return false;
    }
    std::FILE* fp = std::fopen(file.c_str(), "a");
    if (fp == nullptr) {
        err = "failed to open log file: " + file;
        return false;
    }
    std::lock_guard<std::mutex> guard(g_gbp_log_lock);
    g_gbp_log_file = fp;
    return true;
}

inline void gbp_run_log(const std::string& msg)
{
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const std::time_t t = clock::to_time_t(now);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::tm tm_buf{};
#if defined(_WIN32)
    if (localtime_s(&tm_buf, &t) != 0) {
        return;
    }
#else
    if (localtime_r(&t, &tm_buf) == nullptr) {
        return;
    }
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    std::lock_guard<std::mutex> guard(g_gbp_log_lock);
    std::fprintf(g_gbp_log_file, "%s.%03d [GBP] %s\n", buf, static_cast<int>(ms.count()), msg.c_str());
    std::fflush(g_gbp_log_file);
}

inline bool log_point_is_zero(const log_point_t& lp)
{
    return lp.asn == 0 && lp.block_id == 0 && lp.rst_id == 0 && lp.lfn == 0 && lp.lsn == 0;
}

inline uint64_t log_point_lfn(const log_point_t& lp)
{
    return lp.lfn;
}

inline void parse_log_point_fields(const log_point_t& lp, uint32_t& asn, uint32_t& blk, uint32_t& rst,
                                   uint64_t& lfn, uint64_t& lsn)
{
    asn = lp.asn;
    blk = lp.block_id;
    rst = static_cast<uint32_t>(lp.rst_id);
    lfn = lp.lfn;
    lsn = lp.lsn;
}

inline int log_point_lfn_cmp(const log_point_t& a, const log_point_t& b)
{
    const uint64_t al = log_point_lfn(a);
    const uint64_t bl = log_point_lfn(b);
    if (al > bl) {
        return 1;
    }
    if (al < bl) {
        return -1;
    }
    return 0;
}

inline int log_point_cmp(const log_point_t& left, const log_point_t& right, bool lsn_only)
{
    if (lsn_only) {
        if (left.lsn > right.lsn) {
            return 1;
        }
        if (left.lsn < right.lsn) {
            return -1;
        }
        return 0;
    }
    if (left.rst_id > right.rst_id) {
        return 1;
    }
    if (left.rst_id < right.rst_id) {
        return -1;
    }
    if (left.asn > right.asn) {
        return 1;
    }
    if (left.asn < right.asn) {
        return -1;
    }
    if (left.block_id > right.block_id) {
        return 1;
    }
    if (left.block_id < right.block_id) {
        return -1;
    }
    return 0;
}

inline log_point_t log_point_min(const log_point_t& a, const log_point_t& b, bool lsn_only)
{
    return log_point_cmp(a, b, lsn_only) <= 0 ? a : b;
}

inline log_point_t log_point_max(const log_point_t& a, const log_point_t& b, bool lsn_only)
{
    return log_point_cmp(a, b, lsn_only) >= 0 ? a : b;
}

inline log_point_t zero_log_point()
{
    return log_point_t{};
}

inline std::string format_log_point_short(const log_point_t& lp)
{
    std::ostringstream os;
    os << "rst=" << lp.rst_id << " asn=" << lp.asn << " blk=" << lp.block_id
       << " lfn=" << lp.lfn << " lsn=" << lp.lsn;
    return os.str();
}

inline std::string format_page_id(uint16_t file, uint32_t page, uint16_t aligned = 0)
{
    if (aligned) {
        return "file=" + std::to_string(file) + " page=" + std::to_string(page) +
               " align=" + std::to_string(aligned);
    }
    return "file=" + std::to_string(file) + " page=" + std::to_string(page);
}

inline uint32_t page_queue_id(uint32_t page_no)
{
    return page_no % OG_GBP_SESSION_COUNT;
}

inline void page_diag_from_block(const char* blk, uint64_t& lsn, uint32_t& pcn, uint16_t& cks)
{
    lsn = 0;
    pcn = 0;
    cks = 0;
    if (!blk) {
        return;
    }
    std::memcpy(&lsn, blk + GBP_PAGE_LSN_OFFSET, GBP_PAGE_LSN_SIZE);
    std::memcpy(&pcn, blk + GBP_PAGE_PCN_OFFSET, GBP_PAGE_PCN_SIZE);
    std::memcpy(&cks, blk + GBP_PAGE_SIZE - GBP_PAGE_CHECKSUM_TAIL_OFFSET, GBP_PAGE_CHECKSUM_SIZE);
}

struct SmbDecision {
    bool replace;
    const char* reason;
};

inline SmbDecision smb_should_replace(uint32_t stored_inst, uint64_t stored_seq,
                                      uint32_t incoming_inst, uint64_t incoming_seq)
{
    if (incoming_seq > stored_seq) {
        return {true, "newer_seq"};
    }
    if (incoming_seq < stored_seq) {
        return {false, "stale_seq"};
    }
    if (incoming_inst == stored_inst) {
        return {true, "idem_same_writer"};
    }
    return {false, "same_seq_diff_writer"};
}

inline void check_little_endian()
{
    const uint16_t one = 1;
    if (*reinterpret_cast<const uint8_t*>(&one) != 1) {
        gbp_run_log("FATAL: little-endian required");
        std::exit(1);
    }
}

inline int64_t us_since(const std::chrono::steady_clock::time_point& start)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
}

}  // namespace gbp

#endif  // GBP_LOG_H
