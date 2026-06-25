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
 * rbp_state.h
 *
 *
 * IDENTIFICATION
 * src/rbp/rbp_state.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef RBP_STATE_H
#define RBP_STATE_H

#include "rbp_config.h"
#include "rbp_log.h"
#include "rbp_std_compat.h"
#include "rbp_wire.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rbp {

inline constexpr size_t RBP_PID_KEY_BYTES = sizeof(uint64_t);
inline constexpr size_t RBP_PENDING_COMPACT_SKIP_THRESHOLD = 4096;
inline constexpr size_t RBP_PENDING_COMPACT_LIVE_RATIO = 2;
inline constexpr int RBP_EVICT_WAIT_SLICE_MS = 50;
inline constexpr int RBP_EVICT_IDLE_WAIT_MS = 500;
inline constexpr size_t RBP_GLOBAL_MIN_LRP_TUPLE_QID_INDEX = 1;
inline constexpr size_t RBP_GLOBAL_MIN_LRP_TUPLE_PID_INDEX = 2;

// Use system_clock timed waits so builds do not depend on pthread_cond_clockwait availability.
inline void cond_wait_for_compatible(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
                                     std::chrono::milliseconds duration)
{
    cv.wait_until(lock, std::chrono::system_clock::now() + duration);
}

struct PageMeta {
    uint64_t pid_key = 0;
    log_point_t trunc_point{};
    uint64_t trunc_lfn = 0;
    log_point_t lrp_point{};
    uint64_t lrp_lfn = 0;
    uint64_t page_lsn = 0;
    uint32_t page_pcn = 0;
    uint32_t writer_inst = 0;
    uint64_t writer_seq = 0;
    uint32_t qid = 0;
};

struct PagePayload {
    char block[RBP_PAGE_SIZE]{};
};

struct PageRecord {
    std::shared_ptr<const PagePayload> payload;
    log_point_t coverage_begin{};
    log_point_t coverage_lrp{};
    uint32_t writer_inst = 0;
    uint64_t writer_seq = 0;
    uint64_t install_gen = 0;
};

inline const char* page_block_cstr(const PageRecord& rec)
{
    return rec.payload ? rec.payload->block : nullptr;
}

struct BatchPageHandle {
    uint64_t pid_key = 0;
    log_point_t coverage_begin{};
    log_point_t coverage_lrp{};
    uint32_t writer_inst = 0;
    uint64_t writer_seq = 0;
    std::shared_ptr<const PagePayload> payload;
};

struct MetaSnapshotRow {
    std::array<uint8_t, RBP_PID_KEY_BYTES> pid_bytes{};
    uint64_t page_lsn = 0;
    uint32_t page_pcn = 0;
    uint32_t writer_inst = 0;
    uint32_t qid = 0;
};

struct PidBytesLess {
    bool operator()(const std::array<uint8_t, RBP_PID_KEY_BYTES>& a,
                    const std::array<uint8_t, RBP_PID_KEY_BYTES>& b) const
    {
        return std::memcmp(a.data(), b.data(), RBP_PID_KEY_BYTES) < 0;
    }
};

using MetaIndexMap = std::map<std::array<uint8_t, RBP_PID_KEY_BYTES>, MetaSnapshotRow, PidBytesLess>;

inline std::array<uint8_t, RBP_PID_KEY_BYTES> meta_index_key_from_pid_key(uint64_t pid_key)
{
    std::array<uint8_t, RBP_PID_KEY_BYTES> key{};
    std::memcpy(key.data(), &pid_key, sizeof(pid_key));
    return key;
}

struct WindowSnap {
    log_point_t min_trunc_point{};
    uint64_t min_trunc_lfn = INF_LFN;
    log_point_t max_lrp_point{};
    uint64_t max_lrp_lfn = 0;
    uint64_t max_writer_seq = 0;
    int page_count = 0;
    bool dirty = false;
};

// Global LFN-ordered page index (replaces fixed bucket ranges that overflow into one bucket).
class LfnBucketIndex {
public:
    using LfnMap = std::multimap<uint64_t, uint64_t>;

    explicit LfnBucketIndex(const Config&)
    {
    }

    LfnBucketIndex(const LfnBucketIndex& other) : by_lfn_(other.by_lfn_)
    {
        rebuild_by_pid_();
    }

    LfnBucketIndex(LfnBucketIndex&&) noexcept = default;

    LfnBucketIndex& operator=(const LfnBucketIndex& other)
    {
        if (this != &other) {
            by_lfn_ = other.by_lfn_;
            rebuild_by_pid_();
        }
        return *this;
    }

    LfnBucketIndex& operator=(LfnBucketIndex&&) noexcept = default;

    void swap(LfnBucketIndex& other) noexcept
    {
        by_lfn_.swap(other.by_lfn_);
        by_pid_.swap(other.by_pid_);
    }

    friend void swap(LfnBucketIndex& a, LfnBucketIndex& b) noexcept { a.swap(b); }

    void add(uint64_t pid, uint64_t lfn)
    {
        erase(pid, 0);
        const LfnMap::iterator it = by_lfn_.emplace(lfn, pid);
        by_pid_[pid] = it;
    }

    void erase(uint64_t pid, uint64_t)
    {
        const auto pit = by_pid_.find(pid);
        if (pit == by_pid_.end()) {
            return;
        }
        by_lfn_.erase(pit->second);
        by_pid_.erase(pit);
    }

    std::optional<std::pair<uint64_t, uint64_t>> find_min_pid() const
    {
        if (by_lfn_.empty()) {
            return std::nullopt;
        }
        const auto& first = *by_lfn_.begin();
        return std::make_pair(first.second, first.first);
    }

    std::optional<std::pair<uint64_t, uint64_t>> find_max_pid() const
    {
        if (by_lfn_.empty()) {
            return std::nullopt;
        }
        const auto& last = *by_lfn_.rbegin();
        return std::make_pair(last.second, last.first);
    }

    std::vector<uint64_t> collect_purge_pids(uint64_t through_lfn, int budget) const
    {
        std::vector<uint64_t> picked;
        if (budget <= 0) {
            return picked;
        }
        for (const auto& entry : by_lfn_) {
            if (entry.first > through_lfn) {
                break;
            }
            picked.push_back(entry.second);
            if (static_cast<int>(picked.size()) >= budget) {
                break;
            }
        }
        return picked;
    }

private:
    void rebuild_by_pid_()
    {
        by_pid_.clear();
        for (LfnMap::iterator it = by_lfn_.begin(); it != by_lfn_.end(); ++it) {
            by_pid_[it->second] = it;
        }
    }

    LfnMap by_lfn_;
    std::unordered_map<uint64_t, LfnMap::iterator> by_pid_;
};

class PendingQueue {
public:
    size_t size() const { return present_.size(); }

    bool contains(uint64_t pid) const { return present_.count(pid) > 0; }

    void pop(uint64_t pid)
    {
        present_.erase(pid);
    }

    void clear()
    {
        order_.clear();
        present_.clear();
        pos_ = 0;
        next_gen_ = 1;
    }

    void enqueue(uint64_t pid)
    {
        const int gen = next_gen_++;
        present_[pid] = gen;
        order_.emplace_back(pid, gen);
        compact_if_needed();
    }

    void rebuild(const std::vector<uint64_t>& pids)
    {
        clear();
        for (uint64_t pid : pids) {
            enqueue(pid);
        }
    }

    struct BatchPick {
        std::vector<std::tuple<uint64_t, int, uint64_t>> picked;
        int skip_stale = 0;
        int skip_missing = 0;
        int skip_lrp = 0;
        int scanned = 0;
    };

    BatchPick take_batch(const std::unordered_map<uint64_t, PageRecord>& cache,
                         const log_point_t& skip, int limit, bool lsn_only)
    {
        (void)lsn_only;
        BatchPick out;
        while (static_cast<int>(out.picked.size()) < limit && pos_ < order_.size()) {
            const auto [pid, gen] = order_[pos_++];
            out.scanned++;
            auto it = present_.find(pid);
            if (it == present_.end() || it->second != gen) {
                out.skip_stale++;
                continue;
            }
            auto cit = cache.find(pid);
            if (cit == cache.end()) {
                present_.erase(pid);
                out.skip_missing++;
                continue;
            }
            if (log_point_lfn_cmp(cit->second.coverage_lrp, skip) <= 0) {
                present_.erase(pid);
                out.skip_lrp++;
                continue;
            }
            out.picked.emplace_back(pid, gen, cit->second.install_gen);
        }
        compact_if_needed();
        return out;
    }

    void mark_sent(const BatchPick& pick, const std::unordered_map<uint64_t, PageRecord>& cache)
    {
        for (const auto& [pid, gen, sent_install_gen] : pick.picked) {
            auto cit = cache.find(pid);
            auto pit = present_.find(pid);
            if (cit != cache.end() && cit->second.install_gen == sent_install_gen && pit != present_.end() &&
                pit->second == gen) {
                present_.erase(pit);
            }
        }
    }

    int mark_sent_and_count(const BatchPick& pick, const std::unordered_map<uint64_t, PageRecord>& cache)
    {
        int removed = 0;
        for (const auto& [pid, gen, sent_install_gen] : pick.picked) {
            auto cit = cache.find(pid);
            auto pit = present_.find(pid);
            if (cit != cache.end() && cit->second.install_gen == sent_install_gen && pit != present_.end() &&
                pit->second == gen) {
                present_.erase(pit);
                ++removed;
            }
        }
        return removed;
    }

private:
    void compact_if_needed()
    {
        if (pos_ < RBP_PENDING_COMPACT_SKIP_THRESHOLD || pos_ * RBP_PENDING_COMPACT_LIVE_RATIO < order_.size()) {
            return;
        }
        std::vector<std::pair<uint64_t, int>> kept;
        kept.reserve(order_.size() - pos_);
        for (size_t i = pos_; i < order_.size(); ++i) {
            const auto [pid, gen] = order_[i];
            auto it = present_.find(pid);
            if (it != present_.end() && it->second == gen) {
                kept.emplace_back(pid, gen);
            }
        }
        order_ = std::move(kept);
        pos_ = 0;
    }

    std::vector<std::pair<uint64_t, int>> order_;
    std::unordered_map<uint64_t, int> present_;
    size_t pos_ = 0;
    int next_gen_ = 1;
};

struct BatchReadDiagSlot {
    int ok = 0;
    int nopage = 0;
    int error = 0;
    int pages = 0;
    int64_t total_us = 0;
    int64_t lock_wait_us = 0;
    int64_t scan_us = 0;
    int64_t pack_us = 0;
    int64_t send_us = 0;
    int64_t pending_lock_us = 0;
    int64_t pending_remove_us = 0;
    int64_t queue_scanned = 0;
    int64_t skip_stale = 0;
    int64_t skip_missing = 0;
    int64_t skip_lrp = 0;
};

class BatchReadDiag {
public:
    void reset();
    void record(uint32_t qid, uint32_t result, int pages, int64_t total_us, int64_t lock_wait_us, int64_t scan_us,
                int64_t pack_us, int64_t send_us, int64_t pending_lock_us, int64_t pending_remove_us,
                int64_t queue_scanned, int64_t skip_stale, int64_t skip_missing, int64_t skip_lrp);
    void record_counts(uint32_t qid, uint32_t result, int pages);
    void log_summary(const std::string& peer, const std::string& reason, bool timing_diag) const;

private:
    mutable std::mutex mtx_;
    std::array<BatchReadDiagSlot, OG_RBP_SESSION_COUNT> slots_{};
};

struct SelectedReadDiagSlot {
    int ok = 0;
    int nopage = 0;
    int error = 0;
    int requested = 0;
    int returned = 0;
    int missing = 0;
    int mismatch = 0;
    int meta_mismatch = 0;
    int64_t total_us = 0;
    int64_t lock_wait_us = 0;
    int64_t lookup_us = 0;
    int64_t pack_us = 0;
    int64_t send_us = 0;
};

class SelectedReadDiag {
public:
    void reset();
    void record(uint32_t qid, uint32_t result, int requested, int returned, int missing, int mismatch,
                int meta_mismatch, int64_t total_us, int64_t lock_wait_us, int64_t lookup_us, int64_t pack_us,
                int64_t send_us);
    void record_counts(uint32_t qid, uint32_t result, int requested, int returned, int missing, int mismatch,
                     int meta_mismatch);
    void log_summary(const std::string& peer, const std::string& reason, bool timing_diag) const;

private:
    mutable std::mutex mtx_;
    std::array<SelectedReadDiagSlot, OG_RBP_SESSION_COUNT> slots_{};
};

struct RetiredShardData {
    std::unordered_map<uint64_t, PageRecord> page_cache;
    std::unordered_map<uint64_t, PageMeta> page_meta;
    MetaIndexMap meta_index_;
    PendingQueue batch_pending;
    std::optional<LfnBucketIndex> lrp_index;
    std::optional<LfnBucketIndex> trunc_index;
    std::optional<LfnBucketIndex> writer_index;
    WindowSnap snap{};
    log_point_t reset_point{};
    log_point_t frontier_point{};
};

struct RetiredReadPhaseState {
    std::array<RetiredShardData, OG_RBP_SESSION_COUNT> shards{};
    int detached_pages = 0;
};

struct RetiredDestructState {
    std::mutex mtx;
    std::deque<RetiredReadPhaseState> queue;
    bool running = false;
};

struct EvictState {
    std::mutex mtx;
    std::condition_variable cv;
    bool job_running = false;
    int job_target = 0;
    int job_deleted = 0;
    bool purge_stable = true;
    bool stop = false;

    bool wait_stable(int timeout_ms)
    {
        std::unique_lock<std::mutex> lock(mtx);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (job_running || !purge_stable) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                                   std::chrono::steady_clock::now());
            if (remaining.count() <= 0) {
                return false;
            }
            const auto chunk = remaining > std::chrono::milliseconds(RBP_EVICT_WAIT_SLICE_MS) ?
                std::chrono::milliseconds(RBP_EVICT_WAIT_SLICE_MS) : remaining;
            cond_wait_for_compatible(cv, lock, chunk);
        }
        return true;
    }
};

class RbpShard {
public:
    explicit RbpShard(const Config& cfg) : lrp_index_(cfg), trunc_index_(cfg), writer_index_(cfg)
    {
    }

    mutable std::mutex mtx;
    std::unordered_map<uint64_t, PageRecord> page_cache;
    PendingQueue batch_pending;
    log_point_t reset_point{};
    log_point_t frontier_point{};
    std::unordered_map<uint64_t, PageMeta> page_meta;
    LfnBucketIndex lrp_index_;
    LfnBucketIndex trunc_index_;
    LfnBucketIndex writer_index_;
    WindowSnap snap{};
    std::map<std::array<uint8_t, RBP_PID_KEY_BYTES>, MetaSnapshotRow, PidBytesLess> meta_index_;
    bool pending_seeded = false;
};

struct CkptDiag {
    int evict_in_progress = 0;
    int purge_stable = 1;
    int wait_timeout = 0;
    std::string empty_reason;
};

struct CkptResult {
    log_point_t begin{};
    log_point_t rcy{};
    log_point_t lrp{};
    uint64_t max_lsn = 0;
    int cache_pages = 0;
    std::array<log_point_t, OG_RBP_SESSION_COUNT> queue_resets{};
    std::array<log_point_t, OG_RBP_SESSION_COUNT> queue_frontiers{};
    CkptDiag diag;
};

class RbpServerState {
public:
    explicit RbpServerState(const Config& cfg);

    RbpShard& shard(uint32_t qid)
    {
        return *shards_[qid % OG_RBP_SESSION_COUNT];
    }
    const RbpShard& shard(uint32_t qid) const { return *shards_[qid % OG_RBP_SESSION_COUNT]; }

    void lock_all();
    void unlock_all();

    void reset_batch_pending_epoch();
    std::optional<int> ensure_batch_pending_seeded(bool read_phase_active, uint32_t conn_qid);

    CkptResult ckpt_snapshot(bool lsn_only);
    void clear_all(int& cache_pages, int& pending_pages, int& reset_count, int& frontier_count);
    RetiredReadPhaseState detach_read_phase_generation();
    void schedule_retired_destruction(RetiredReadPhaseState&& retired);

    void remember_evicted_hole(const log_point_t& lrp, bool log_hole);
    log_point_t apply_evicted_holes_to_begin(const log_point_t& begin, const log_point_t& rcy) const;
    void clear_evicted_holes();

    int total_page_count() const { return total_pages_.load(std::memory_order_relaxed); }
    int pending_total() const { return pending_total_.load(std::memory_order_relaxed); }
    bool try_note_page_installed(bool replaced);
    void note_page_removed();
    void note_pending_delta(int delta);
    BatchReadDiag& read_diag()
    {
        return read_diag_;
    }
    const BatchReadDiag& read_diag() const { return read_diag_; }
    SelectedReadDiag& selected_read_diag()
    {
        return selected_read_diag_;
    }
    const SelectedReadDiag& selected_read_diag() const { return selected_read_diag_; }
    void build_read_meta_snapshot(std::vector<MetaSnapshotRow>& out) const;
    void maybe_start_capacity_evict();
    void start_evict_worker();
    void stop_evict_worker();

    const Config& config() const { return cfg_; }
    EvictState evict_state;
    RetiredDestructState retired_state;

private:
    friend void evict_worker_loop(RbpServerState* state);

    Config cfg_;
    std::atomic<bool> read_end_detaching_{false};
    std::array<std::unique_ptr<RbpShard>, OG_RBP_SESSION_COUNT> shards_{};
    std::thread evict_thread_;
    mutable std::mutex holes_mtx_;
    std::unordered_map<uint64_t, log_point_t> evicted_holes_;
    std::vector<uint64_t> evicted_hole_lfns_;
    std::atomic<int> total_pages_{0};
    std::atomic<int> pending_total_{0};
    BatchReadDiag read_diag_;
    SelectedReadDiag selected_read_diag_;
};

PageRecord page_record_from_item(const rbp_page_item_t& item);
PageRecord page_record_from_payload(std::shared_ptr<PagePayload> payload, uint32_t writer_inst, uint64_t writer_seq);
void wire_item_fill(rbp_page_item_t& item, const BatchPageHandle& handle);
void wire_item_fill(rbp_page_item_t& item, const PageRecord& rec, uint64_t pid_key);
rbp_page_item_t wire_item_for_response(const PageRecord& rec, uint64_t pid_key);

void refresh_shard_snap(RbpShard& shard);
PageMeta build_page_meta(uint64_t pid_key, const PageRecord& rec);
bool install_page(RbpServerState& state, RbpShard& shard, uint64_t pid_key, PageRecord rec, const PageMeta& meta,
                  bool legacy_pending);
void remove_page(RbpServerState& state, RbpShard& shard, uint64_t pid_key, bool record_hole,
                 const char* reason, bool log_hole);
int purge_shard_through_lfn(RbpServerState& state, RbpShard& shard, uint64_t through_lfn, int budget,
                            bool record_hole, const char* reason);
void apply_queue_reset(RbpServerState& state, RbpShard& shard, uint32_t qid, const log_point_t& reset_point,
                       const log_point_t& frontier_point, bool lsn_only, bool verbose, const std::string& peer);
log_point_t select_reset_point(const log_point_t& batch_begin, const log_point_t& batch_lrp, bool lsn_only);
log_point_t update_point_monotonic(const log_point_t& old_pt, const log_point_t& pt, bool lsn_only);
std::optional<std::pair<uint32_t, log_point_t>> min_queue_frontier(
    const log_point_t frontiers[OG_RBP_SESSION_COUNT], bool lsn_only, std::vector<int>& missing);
log_point_t apply_queue_resets_to_begin(const log_point_t& begin,
                                        const log_point_t resets[OG_RBP_SESSION_COUNT], bool lsn_only);
std::optional<std::pair<uint32_t, log_point_t>> max_queue_reset_with_qid(
    const log_point_t resets[OG_RBP_SESSION_COUNT], bool lsn_only);
std::string queue_resets_diag(const log_point_t resets[OG_RBP_SESSION_COUNT], bool lsn_only);
std::string queue_frontiers_diag(const log_point_t frontiers[OG_RBP_SESSION_COUNT], bool lsn_only);
void collect_queue_points(RbpServerState& state, log_point_t resets[OG_RBP_SESSION_COUNT],
                          log_point_t frontiers[OG_RBP_SESSION_COUNT]);
CkptResult merge_ckpt_from_shards(RbpServerState& state, bool lsn_only);
uint64_t compute_global_begin_lfn(RbpServerState& state, bool lsn_only);
bool run_fixed_point_purge(RbpServerState& state, bool lsn_only, int budget);
std::optional<std::pair<uint32_t, uint64_t>> find_global_min_lrp_page(RbpServerState& state);

}  // namespace rbp

#endif  // RBP_STATE_H
