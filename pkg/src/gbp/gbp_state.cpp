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
 * gbp_state.cpp
 *
 *
 * IDENTIFICATION
 * src/gbp/gbp_state.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "gbp_state.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <sstream>
#include <thread>
#include <tuple>

namespace gbp {

namespace {
std::atomic<uint64_t> g_next_install_gen{1};

template <typename Slot>
bool slot_has_activity(const Slot& slot)
{
    return false;
}

template <>
bool slot_has_activity<BatchReadDiagSlot>(const BatchReadDiagSlot& slot)
{
    return (slot.ok + slot.nopage + slot.error) > 0 || slot.pages > 0;
}

template <>
bool slot_has_activity<SelectedReadDiagSlot>(const SelectedReadDiagSlot& slot)
{
    return (slot.ok + slot.nopage + slot.error) > 0 || slot.requested > 0;
}

template <typename Slot>
int slot_batches(const Slot& slot)
{
    return slot.ok + slot.nopage + slot.error;
}
}

void BatchReadDiag::reset()
{
    std::lock_guard<std::mutex> g(mtx_);
    slots_.fill(BatchReadDiagSlot{});
}

void BatchReadDiag::record_counts(uint32_t qid, uint32_t result, int pages)
{
    std::lock_guard<std::mutex> g(mtx_);
    BatchReadDiagSlot& slot = slots_[qid % OG_GBP_SESSION_COUNT];
    if (result == GBP_READ_RESULT_OK) {
        slot.ok++;
    } else if (result == GBP_READ_RESULT_NOPAGE) {
        slot.nopage++;
    } else {
        slot.error++;
    }
    slot.pages += pages;
}

void BatchReadDiag::record(uint32_t qid, uint32_t result, int pages, int64_t total_us, int64_t lock_wait_us,
                           int64_t scan_us, int64_t pack_us, int64_t send_us, int64_t pending_lock_us,
                           int64_t pending_remove_us, int64_t queue_scanned, int64_t skip_stale,
                           int64_t skip_missing, int64_t skip_lrp)
{
    std::lock_guard<std::mutex> g(mtx_);
    BatchReadDiagSlot& slot = slots_[qid % OG_GBP_SESSION_COUNT];
    if (result == GBP_READ_RESULT_OK) {
        slot.ok++;
    } else if (result == GBP_READ_RESULT_NOPAGE) {
        slot.nopage++;
    } else {
        slot.error++;
    }
    slot.pages += pages;
    slot.total_us += total_us;
    slot.lock_wait_us += lock_wait_us;
    slot.scan_us += scan_us;
    slot.pack_us += pack_us;
    slot.send_us += send_us;
    slot.pending_lock_us += pending_lock_us;
    slot.pending_remove_us += pending_remove_us;
    slot.queue_scanned += queue_scanned;
    slot.skip_stale += skip_stale;
    slot.skip_missing += skip_missing;
    slot.skip_lrp += skip_lrp;
}

void BatchReadDiag::log_summary(const std::string& peer, const std::string& reason, bool timing_diag) const
{
    std::array<BatchReadDiagSlot, OG_GBP_SESSION_COUNT> slots;
    {
        std::lock_guard<std::mutex> g(mtx_);
        slots = slots_;
    }

    BatchReadDiagSlot total{};
    int active = 0;
    for (const auto& slot : slots) {
        if (!slot_has_activity(slot)) {
            continue;
        }
        active++;
        total.ok += slot.ok;
        total.nopage += slot.nopage;
        total.error += slot.error;
        total.pages += slot.pages;
        total.total_us += slot.total_us;
        total.lock_wait_us += slot.lock_wait_us;
        total.scan_us += slot.scan_us;
        total.pack_us += slot.pack_us;
        total.send_us += slot.send_us;
        total.pending_lock_us += slot.pending_lock_us;
        total.pending_remove_us += slot.pending_remove_us;
        total.queue_scanned += slot.queue_scanned;
        total.skip_stale += slot.skip_stale;
        total.skip_missing += slot.skip_missing;
        total.skip_lrp += slot.skip_lrp;
    }

    const int batches = slot_batches(total);
    if (batches == 0) {
        return;
    }

    if (!timing_diag) {
        gbp_run_log("server batch read total reason=" + reason + " peer=" + peer +
                    " workers=" + std::to_string(active) +
                    " ok=" + std::to_string(total.ok) + " nopage=" + std::to_string(total.nopage) +
                    " err=" + std::to_string(total.error) + " pages=" + std::to_string(total.pages));
        return;
    }

    gbp_run_log("server batch read total reason=" + reason + " peer=" + peer + " workers=" + std::to_string(active) +
                " ok=" + std::to_string(total.ok) + " nopage=" + std::to_string(total.nopage) +
                " err=" + std::to_string(total.error) + " pages=" + std::to_string(total.pages) +
                " total_us=" + std::to_string(total.total_us) +
                " lock_wait_us=" + std::to_string(total.lock_wait_us) +
                " scan_us=" + std::to_string(total.scan_us) + " pack_us=" + std::to_string(total.pack_us) +
                " send_us=" + std::to_string(total.send_us) +
                " pending_lock_us=" + std::to_string(total.pending_lock_us) +
                " pending_remove_us=" + std::to_string(total.pending_remove_us) +
                " queue_scanned=" + std::to_string(total.queue_scanned) +
                " skip_stale=" + std::to_string(total.skip_stale) +
                " skip_missing=" + std::to_string(total.skip_missing) +
                " skip_lrp=" + std::to_string(total.skip_lrp) +
                " avg_batch_us=" + std::to_string(total.total_us / batches) +
                " avg_scan_us=" + std::to_string(total.scan_us / batches) +
                " avg_send_us=" + std::to_string(total.send_us / batches));

    for (size_t qid = 0; qid < slots.size(); ++qid) {
        const auto& slot = slots[qid];
        const int worker_batches = slot_batches(slot);
        if (worker_batches == 0 && slot.pages == 0) {
            continue;
        }
        gbp_run_log("server batch read worker q=" + std::to_string(qid) + " ok=" + std::to_string(slot.ok) +
                    " nopage=" + std::to_string(slot.nopage) + " err=" + std::to_string(slot.error) +
                    " pages=" + std::to_string(slot.pages) +
                    " avg_batch_us=" + std::to_string(worker_batches == 0 ? 0 : slot.total_us / worker_batches) +
                    " lock_wait_us=" + std::to_string(slot.lock_wait_us) +
                    " scan_us=" + std::to_string(slot.scan_us) + " pack_us=" + std::to_string(slot.pack_us) +
                    " send_us=" + std::to_string(slot.send_us) +
                    " pending_lock_us=" + std::to_string(slot.pending_lock_us) +
                    " pending_remove_us=" + std::to_string(slot.pending_remove_us) +
                    " queue_scanned=" + std::to_string(slot.queue_scanned) +
                    " skip_stale=" + std::to_string(slot.skip_stale) +
                    " skip_missing=" + std::to_string(slot.skip_missing) +
                    " skip_lrp=" + std::to_string(slot.skip_lrp));
    }
}

void SelectedReadDiag::reset()
{
    std::lock_guard<std::mutex> g(mtx_);
    slots_.fill(SelectedReadDiagSlot{});
}

void SelectedReadDiag::record_counts(uint32_t qid, uint32_t result, int requested, int returned, int missing,
                                     int mismatch, int meta_mismatch)
{
    std::lock_guard<std::mutex> g(mtx_);
    SelectedReadDiagSlot& slot = slots_[qid % OG_GBP_SESSION_COUNT];
    if (result == GBP_READ_RESULT_OK) {
        slot.ok++;
    } else if (result == GBP_READ_RESULT_NOPAGE) {
        slot.nopage++;
    } else {
        slot.error++;
    }
    slot.requested += requested;
    slot.returned += returned;
    slot.missing += missing;
    slot.mismatch += mismatch;
    slot.meta_mismatch += meta_mismatch;
}

void SelectedReadDiag::record(uint32_t qid, uint32_t result, int requested, int returned, int missing, int mismatch,
                              int meta_mismatch, int64_t total_us, int64_t lock_wait_us, int64_t lookup_us,
                              int64_t pack_us, int64_t send_us)
{
    std::lock_guard<std::mutex> g(mtx_);
    SelectedReadDiagSlot& slot = slots_[qid % OG_GBP_SESSION_COUNT];
    if (result == GBP_READ_RESULT_OK) {
        slot.ok++;
    } else if (result == GBP_READ_RESULT_NOPAGE) {
        slot.nopage++;
    } else {
        slot.error++;
    }
    slot.requested += requested;
    slot.returned += returned;
    slot.missing += missing;
    slot.mismatch += mismatch;
    slot.meta_mismatch += meta_mismatch;
    slot.total_us += total_us;
    slot.lock_wait_us += lock_wait_us;
    slot.lookup_us += lookup_us;
    slot.pack_us += pack_us;
    slot.send_us += send_us;
}

void SelectedReadDiag::log_summary(const std::string& peer, const std::string& reason, bool timing_diag) const
{
    std::array<SelectedReadDiagSlot, OG_GBP_SESSION_COUNT> slots;
    {
        std::lock_guard<std::mutex> g(mtx_);
        slots = slots_;
    }

    SelectedReadDiagSlot total{};
    int active = 0;
    for (const auto& slot : slots) {
        if (!slot_has_activity(slot)) {
            continue;
        }
        active++;
        total.ok += slot.ok;
        total.nopage += slot.nopage;
        total.error += slot.error;
        total.requested += slot.requested;
        total.returned += slot.returned;
        total.missing += slot.missing;
        total.mismatch += slot.mismatch;
        total.meta_mismatch += slot.meta_mismatch;
        total.total_us += slot.total_us;
        total.lock_wait_us += slot.lock_wait_us;
        total.lookup_us += slot.lookup_us;
        total.pack_us += slot.pack_us;
        total.send_us += slot.send_us;
    }

    const int batches = slot_batches(total);
    if (batches == 0) {
        return;
    }

    const bool has_anomaly = (total.missing > 0 || total.mismatch > 0 || total.meta_mismatch > 0 || total.error > 0);
    if (!timing_diag && !has_anomaly) {
        return;
    }

    if (timing_diag) {
        gbp_run_log("server selected read total reason=" + reason + " peer=" + peer +
                    " workers=" + std::to_string(active) + " ok=" + std::to_string(total.ok) +
                    " nopage=" + std::to_string(total.nopage) + " err=" + std::to_string(total.error) +
                    " requested=" + std::to_string(total.requested) +
                    " returned=" + std::to_string(total.returned) + " missing=" + std::to_string(total.missing) +
                    " mismatch=" + std::to_string(total.mismatch) +
                    " meta_mismatch=" + std::to_string(total.meta_mismatch) +
                    " total_us=" + std::to_string(total.total_us) +
                    " lock_wait_us=" + std::to_string(total.lock_wait_us) +
                    " lookup_us=" + std::to_string(total.lookup_us) +
                    " pack_us=" + std::to_string(total.pack_us) + " send_us=" + std::to_string(total.send_us) +
                    " avg_batch_us=" + std::to_string(total.total_us / batches) +
                    " avg_lookup_us=" + std::to_string(total.lookup_us / batches) +
                    " avg_pack_us=" + std::to_string(total.pack_us / batches) +
                    " avg_send_us=" + std::to_string(total.send_us / batches));
    } else {
        gbp_run_log("server selected read anomaly reason=" + reason + " peer=" + peer +
                    " workers=" + std::to_string(active) + " ok=" + std::to_string(total.ok) +
                    " err=" + std::to_string(total.error) + " requested=" + std::to_string(total.requested) +
                    " returned=" + std::to_string(total.returned) + " missing=" + std::to_string(total.missing) +
                    " mismatch=" + std::to_string(total.mismatch) +
                    " meta_mismatch=" + std::to_string(total.meta_mismatch));
    }

    if (!timing_diag) {
        return;
    }

    for (size_t qid = 0; qid < slots.size(); ++qid) {
        const auto& slot = slots[qid];
        const int worker_batches = slot_batches(slot);
        if (worker_batches == 0 && slot.requested == 0) {
            continue;
        }
        gbp_run_log("server selected read worker q=" + std::to_string(qid) + " ok=" + std::to_string(slot.ok) +
                    " nopage=" + std::to_string(slot.nopage) + " err=" + std::to_string(slot.error) +
                    " requested=" + std::to_string(slot.requested) +
                    " returned=" + std::to_string(slot.returned) +
                    " missing=" + std::to_string(slot.missing) +
                    " mismatch=" + std::to_string(slot.mismatch) +
                    " meta_mismatch=" + std::to_string(slot.meta_mismatch) +
                    " avg_batch_us=" + std::to_string(worker_batches == 0 ? 0 : slot.total_us / worker_batches) +
                    " lock_wait_us=" + std::to_string(slot.lock_wait_us) +
                    " lookup_us=" + std::to_string(slot.lookup_us) +
                    " pack_us=" + std::to_string(slot.pack_us) +
                    " send_us=" + std::to_string(slot.send_us));
    }
}

std::optional<std::pair<uint32_t, log_point_t>> max_queue_reset_with_qid(
    const log_point_t resets[OG_GBP_SESSION_COUNT], bool lsn_only)
{
    std::optional<std::pair<uint32_t, log_point_t>> best;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        if (log_point_is_zero(resets[qid])) {
            continue;
        }
        if (!best || log_point_cmp(resets[qid], best->second, lsn_only) > 0) {
            best = std::make_pair(qid, resets[qid]);
        }
    }
    return best;
}

static log_point_t max_queue_reset(const log_point_t resets[OG_GBP_SESSION_COUNT], bool lsn_only)
{
    auto best = max_queue_reset_with_qid(resets, lsn_only);
    return best ? best->second : zero_log_point();
}

std::string queue_resets_diag(const log_point_t resets[OG_GBP_SESSION_COUNT], bool lsn_only)
{
    int count = 0;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        if (!log_point_is_zero(resets[qid])) {
            count++;
        }
    }
    if (count == 0) {
        return "";
    }
    auto best = max_queue_reset_with_qid(resets, lsn_only);
    if (!best) {
        return "";
    }
    std::ostringstream lfns;
    bool first = true;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        if (log_point_is_zero(resets[qid])) {
            continue;
        }
        if (!first) {
            lfns << ",";
        }
        first = false;
        lfns << qid << ":" << log_point_lfn(resets[qid]);
    }
    return " | queue_resets=" + std::to_string(count) + " max_reset_qid=" + std::to_string(best->first) +
           "[" + format_log_point_short(best->second) + "] reset_lfns=" + lfns.str();
}

std::string queue_frontiers_diag(const log_point_t frontiers[OG_GBP_SESSION_COUNT], bool lsn_only)
{
    int count = 0;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        if (!log_point_is_zero(frontiers[qid])) {
            count++;
        }
    }
    if (count == 0) {
        return " | queue_frontiers=empty";
    }
    std::vector<int> missing;
    auto min_frontier = min_queue_frontier(frontiers, lsn_only, missing);
    std::ostringstream lfns;
    bool first = true;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        if (log_point_is_zero(frontiers[qid])) {
            continue;
        }
        if (!first) {
            lfns << ",";
        }
        first = false;
        lfns << qid << ":" << log_point_lfn(frontiers[qid]);
    }
    if (!min_frontier) {
        std::ostringstream miss;
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i > 0) {
                miss << ",";
            }
            miss << missing[i];
        }
        return " | queue_frontiers=empty missing=" + miss.str();
    }
    std::string miss;
    if (!missing.empty()) {
        std::ostringstream miss_os;
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i > 0) {
                miss_os << ",";
            }
            miss_os << missing[i];
        }
        miss = " missing=" + miss_os.str();
    }
    return " | queue_frontiers=" + std::to_string(count) + " min_frontier_qid=" +
           std::to_string(min_frontier->first) + "[" + format_log_point_short(min_frontier->second) +
           "] frontier_lfns=" + lfns.str() + miss;
}

void collect_queue_points(GbpServerState& state, log_point_t resets[OG_GBP_SESSION_COUNT],
                          log_point_t frontiers[OG_GBP_SESSION_COUNT])
{
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        const GbpShard& shard = state.shard(qid);
        std::lock_guard<std::mutex> g(shard.mtx);
        resets[qid] = shard.reset_point;
        frontiers[qid] = shard.frontier_point;
    }
}

GbpServerState::GbpServerState(const Config& cfg) : cfg_(cfg)
{
    for (auto& p : shards_) {
        p = std::make_unique<GbpShard>(cfg_);
    }
}

PageRecord page_record_from_item(const gbp_page_item_t& item)
{
    PageRecord rec{};
    auto payload = std::make_shared<PagePayload>();
    std::memcpy(payload->block, item.block, GBP_PAGE_SIZE);
    rec.payload = payload;
    rec.writer_inst = item.writer_inst_id;
    rec.writer_seq = item.writer_global_seq;
    return rec;
}

PageRecord page_record_from_payload(std::shared_ptr<PagePayload> payload, uint32_t writer_inst,
                                    uint64_t writer_seq)
{
    PageRecord rec{};
    rec.payload = std::move(payload);
    rec.writer_inst = writer_inst;
    rec.writer_seq = writer_seq;
    return rec;
}

namespace {

MetaSnapshotRow meta_row_from_page_meta(uint64_t pid_key, uint32_t qid, const PageMeta& meta)
{
    MetaSnapshotRow row{};
    std::memcpy(row.pid_bytes.data(), &pid_key, sizeof(pid_key));
    row.page_lsn = meta.page_lsn;
    row.page_pcn = meta.page_pcn;
    row.writer_inst = meta.writer_inst;
    row.qid = qid;
    return row;
}

void shard_meta_index_upsert(GbpShard& shard, uint32_t qid, uint64_t pid_key, const PageMeta& meta)
{
    shard.meta_index_[meta_index_key_from_pid_key(pid_key)] = meta_row_from_page_meta(pid_key, qid, meta);
}

void shard_meta_index_remove(GbpShard& shard, uint64_t pid_key)
{
    shard.meta_index_.erase(meta_index_key_from_pid_key(pid_key));
}

}  // namespace

void wire_item_fill(gbp_page_item_t& item, const BatchPageHandle& handle)
{
    page_id_t pid{};
    std::memcpy(&pid, &handle.pid_key, sizeof(pid));
    pid.aligned = 0;
    item.page_id = pid;
    item.gbp_trunc_point = handle.coverage_begin;
    item.gbp_lrp_point = handle.coverage_lrp;
    item.session_id = 0;
    item.writer_inst_id = handle.writer_inst;
    item.writer_global_seq = handle.writer_seq;
    if (handle.payload) {
        std::memcpy(item.block, handle.payload->block, GBP_PAGE_SIZE);
    } else {
        std::memset(item.block, 0, GBP_PAGE_SIZE);
    }
}

void wire_item_fill(gbp_page_item_t& item, const PageRecord& rec, uint64_t pid_key)
{
    BatchPageHandle handle{};
    handle.pid_key = pid_key;
    handle.coverage_begin = rec.coverage_begin;
    handle.coverage_lrp = rec.coverage_lrp;
    handle.writer_inst = rec.writer_inst;
    handle.writer_seq = rec.writer_seq;
    handle.payload = rec.payload;
    wire_item_fill(item, handle);
}

gbp_page_item_t wire_item_for_response(const PageRecord& rec, uint64_t pid_key)
{
    gbp_page_item_t item{};
    wire_item_fill(item, rec, pid_key);
    return item;
}

void GbpServerState::lock_all()
{
    for (auto& p : shards_) {
        p->mtx.lock();
    }
}

void GbpServerState::unlock_all()
{
    for (auto it = shards_.rbegin(); it != shards_.rend(); ++it) {
        (*it)->mtx.unlock();
    }
}

void GbpServerState::reset_batch_pending_epoch()
{
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        GbpShard& shard = *shards_[qid];
        std::lock_guard<std::mutex> g(shard.mtx);
        shard.pending_seeded = false;
    }
}

std::optional<int> GbpServerState::ensure_batch_pending_seeded(bool read_phase_active, uint32_t conn_qid)
{
    if (!read_phase_active) {
        return std::nullopt;
    }
    const uint32_t qid = conn_qid % OG_GBP_SESSION_COUNT;
    GbpShard& shard = *shards_[qid];
    std::lock_guard<std::mutex> g(shard.mtx);
    if (shard.pending_seeded) {
        return std::nullopt;
    }
    std::vector<uint64_t> pids;
    pids.reserve(shard.page_cache.size());
    for (const auto& kv : shard.page_cache) {
        pids.push_back(kv.first);
    }
    const int old_pending = static_cast<int>(shard.batch_pending.size());
    shard.batch_pending.rebuild(pids);
    note_pending_delta(static_cast<int>(shard.batch_pending.size()) - old_pending);
    shard.pending_seeded = true;
    return static_cast<int>(shard.batch_pending.size());
}

void refresh_shard_snap(GbpShard& shard)
{
    auto& snap = shard.snap;
    snap.page_count = static_cast<int>(shard.page_cache.size());
    if (snap.page_count == 0) {
        snap.min_trunc_lfn = INF_LFN;
        snap.min_trunc_point = zero_log_point();
        snap.max_lrp_lfn = 0;
        snap.max_lrp_point = zero_log_point();
        snap.max_writer_seq = 0;
    } else {
        auto min_trunc = shard.trunc_index_.find_min_pid();
        auto max_lrp = shard.lrp_index_.find_max_pid();
        auto max_writer = shard.writer_index_.find_max_pid();
        bool index_ok = false;

        if (min_trunc && max_lrp && max_writer) {
            auto trunc_it = shard.page_meta.find(min_trunc->first);
            auto lrp_it = shard.page_meta.find(max_lrp->first);
            auto writer_it = shard.page_meta.find(max_writer->first);
            if (trunc_it != shard.page_meta.end() && lrp_it != shard.page_meta.end() &&
                writer_it != shard.page_meta.end()) {
                snap.min_trunc_lfn = min_trunc->second;
                snap.min_trunc_point = trunc_it->second.trunc_point;
                snap.max_lrp_lfn = max_lrp->second;
                snap.max_lrp_point = lrp_it->second.lrp_point;
                snap.max_writer_seq = max_writer->second;
                index_ok = true;
            }
        }
        if (!index_ok) {
            uint64_t min_t = INF_LFN;
            log_point_t min_tp{};
            uint64_t max_l = 0;
            log_point_t max_lp{};
            uint64_t max_w = 0;

            for (const auto& kv : shard.page_meta) {
                const PageMeta& m = kv.second;
                if (m.trunc_lfn < min_t) {
                    min_t = m.trunc_lfn;
                    min_tp = m.trunc_point;
                }
                if (m.lrp_lfn > max_l) {
                    max_l = m.lrp_lfn;
                    max_lp = m.lrp_point;
                }
                if (m.writer_seq > max_w) {
                    max_w = m.writer_seq;
                }
            }
            snap.min_trunc_lfn = min_t;
            snap.min_trunc_point = min_tp;
            snap.max_lrp_lfn = max_l;
            snap.max_lrp_point = max_lp;
            snap.max_writer_seq = max_w;
        }
    }
    snap.dirty = false;
}

static void snap_on_install(GbpShard& shard, const PageMeta& meta, bool replaced)
{
    auto& snap = shard.snap;
    if (!replaced) {
        snap.page_count++;
    }
    if (meta.trunc_lfn < snap.min_trunc_lfn || snap.page_count == 1) {
        snap.min_trunc_lfn = meta.trunc_lfn;
        snap.min_trunc_point = meta.trunc_point;
    }
    if (meta.lrp_lfn > snap.max_lrp_lfn || snap.page_count == 1) {
        snap.max_lrp_lfn = meta.lrp_lfn;
        snap.max_lrp_point = meta.lrp_point;
    }
    if (meta.writer_seq > snap.max_writer_seq) {
        snap.max_writer_seq = meta.writer_seq;
    }
}

static void snap_on_remove(GbpShard& shard, const PageMeta& meta)
{
    auto& snap = shard.snap;
    snap.page_count = std::max(0, snap.page_count - 1);
    if (snap.page_count == 0) {
        snap.min_trunc_lfn = INF_LFN;
        snap.min_trunc_point = zero_log_point();
        snap.max_lrp_lfn = 0;
        snap.max_lrp_point = zero_log_point();
        snap.max_writer_seq = 0;
        snap.dirty = false;
        return;
    }
    if (meta.trunc_lfn == snap.min_trunc_lfn || meta.lrp_lfn == snap.max_lrp_lfn ||
        meta.writer_seq == snap.max_writer_seq) {
        snap.dirty = true;
    }
}

PageMeta build_page_meta(uint64_t pid_key, const PageRecord& rec)
{
    PageMeta m;
    m.pid_key = pid_key;
    m.trunc_point = rec.coverage_begin;
    m.trunc_lfn = log_point_lfn(rec.coverage_begin);
    m.lrp_point = rec.coverage_lrp;
    m.lrp_lfn = log_point_lfn(rec.coverage_lrp);
    uint16_t cks = 0;
    page_diag_from_block(page_block_cstr(rec), m.page_lsn, m.page_pcn, cks);
    (void)cks;
    m.writer_inst = rec.writer_inst;
    m.writer_seq = rec.writer_seq;
    page_id_t pid{};
    std::memcpy(&pid, &pid_key, sizeof(pid));
    m.qid = page_queue_id(pid.page);
    return m;
}

bool install_page(GbpServerState& state, GbpShard& shard, uint64_t pid_key, PageRecord rec, const PageMeta& meta,
                  bool legacy_pending)
{
    rec.install_gen = g_next_install_gen.fetch_add(1, std::memory_order_relaxed);
    auto old_it = shard.page_meta.find(pid_key);
    const bool replaced = old_it != shard.page_meta.end();
    bool replaced_snapshot_edge = false;
    if (replaced) {
        const PageMeta old_meta = old_it->second;

        replaced_snapshot_edge = (old_meta.trunc_lfn == shard.snap.min_trunc_lfn ||
                                  old_meta.lrp_lfn == shard.snap.max_lrp_lfn ||
                                  old_meta.writer_seq == shard.snap.max_writer_seq);
        shard.lrp_index_.erase(pid_key, old_it->second.lrp_lfn);
        shard.trunc_index_.erase(pid_key, old_it->second.trunc_lfn);
        shard.writer_index_.erase(pid_key, old_it->second.writer_seq);
    } else {
        if (!state.try_note_page_installed(false)) {
            return false;
        }
    }
    shard.page_cache[pid_key] = std::move(rec);
    shard.page_meta[pid_key] = meta;
    shard.lrp_index_.add(pid_key, meta.lrp_lfn);
    shard.trunc_index_.add(pid_key, meta.trunc_lfn);
    shard.writer_index_.add(pid_key, meta.writer_seq);
    shard_meta_index_upsert(shard, meta.qid, pid_key, meta);
    snap_on_install(shard, meta, replaced);
    if (replaced_snapshot_edge) {
        shard.snap.dirty = true;
    }
    if (legacy_pending) {
        if (!shard.batch_pending.contains(pid_key)) {
            state.note_pending_delta(1);
        }
        shard.batch_pending.enqueue(pid_key);
    }
    return true;
}

void GbpServerState::remember_evicted_hole(const log_point_t& lrp, bool log_hole)
{
    const uint64_t lfn = log_point_lfn(lrp);
    if (lfn == 0) {
        return;
    }
    std::lock_guard<std::mutex> g(holes_mtx_);
    if (evicted_holes_.count(lfn)) {
        return;
    }
    evicted_holes_[lfn] = lrp;
    auto it = std::lower_bound(evicted_hole_lfns_.begin(), evicted_hole_lfns_.end(), lfn);
    evicted_hole_lfns_.insert(it, lfn);
    if (log_hole) {
        gbp_run_log("[window-hole] remember hole[" + format_log_point_short(lrp) +
                    "] total_holes=" + std::to_string(evicted_holes_.size()));
    }
}

log_point_t GbpServerState::apply_evicted_holes_to_begin(const log_point_t& begin, const log_point_t& rcy) const
{
    const uint64_t rcy_lfn = log_point_lfn(rcy);
    if (rcy_lfn == 0) {
        return begin;
    }
    std::lock_guard<std::mutex> g(holes_mtx_);
    if (evicted_hole_lfns_.empty()) {
        return begin;
    }
    auto it = std::upper_bound(evicted_hole_lfns_.begin(), evicted_hole_lfns_.end(), rcy_lfn);
    if (it == evicted_hole_lfns_.begin()) {
        return begin;
    }
    --it;
    const uint64_t hole_lfn = *it;
    auto hit = evicted_holes_.find(hole_lfn);
    if (hit == evicted_holes_.end()) {
        return begin;
    }
    if (hole_lfn > log_point_lfn(begin)) {
        return hit->second;
    }
    return begin;
}

void GbpServerState::clear_evicted_holes()
{
    std::lock_guard<std::mutex> g(holes_mtx_);
    evicted_holes_.clear();
    evicted_hole_lfns_.clear();
}

void remove_page(GbpServerState& state, GbpShard& shard, uint64_t pid_key, bool record_hole,
                 const char* reason, bool log_hole)
{
    auto cit = shard.page_cache.find(pid_key);
    auto mit = shard.page_meta.find(pid_key);
    if (cit == shard.page_cache.end() || mit == shard.page_meta.end()) {
        return;
    }
    PageRecord rec = cit->second;
    PageMeta meta = mit->second;
    shard.lrp_index_.erase(pid_key, meta.lrp_lfn);
    shard.trunc_index_.erase(pid_key, meta.trunc_lfn);
    shard.writer_index_.erase(pid_key, meta.writer_seq);
    if (shard.batch_pending.contains(pid_key)) {
        state.note_pending_delta(-1);
    }
    shard.batch_pending.pop(pid_key);
    shard.page_cache.erase(cit);
    shard.page_meta.erase(mit);
    shard_meta_index_remove(shard, pid_key);
    state.note_page_removed();
    snap_on_remove(shard, meta);
    if (record_hole) {
        state.remember_evicted_hole(rec.coverage_lrp, log_hole);
        (void)reason;
    }
}

int purge_shard_through_lfn(GbpServerState& state, GbpShard& shard, uint64_t through_lfn, int budget,
                            bool record_hole, const char* reason)
{
    const auto pids = shard.lrp_index_.collect_purge_pids(through_lfn, budget);
    int removed = 0;
    for (uint64_t pid : pids) {
        if (shard.page_cache.find(pid) == shard.page_cache.end()) {
            continue;
        }
        remove_page(state, shard, pid, record_hole, reason, false);
        removed++;
    }
    return removed;
}

log_point_t update_point_monotonic(const log_point_t& old_pt, const log_point_t& pt, bool lsn_only)
{
    if (log_point_is_zero(pt)) {
        return old_pt;
    }
    if (log_point_is_zero(old_pt) || log_point_cmp(pt, old_pt, lsn_only) > 0) {
        return pt;
    }
    return old_pt;
}

log_point_t select_reset_point(const log_point_t& batch_begin, const log_point_t& batch_lrp, bool lsn_only)
{
    log_point_t best = zero_log_point();
    for (const log_point_t* pt : {&batch_begin, &batch_lrp}) {
        if (log_point_is_zero(*pt)) {
            continue;
        }
        if (log_point_is_zero(best) || log_point_cmp(*pt, best, lsn_only) > 0) {
            best = *pt;
        }
    }
    return best;
}

void apply_queue_reset(GbpServerState& state, GbpShard& shard, uint32_t qid, const log_point_t& reset_point,
                       const log_point_t& frontier_point, bool lsn_only, bool verbose, const std::string& peer)
{
    log_point_t reset = reset_point;
    log_point_t frontier = log_point_is_zero(frontier_point) ? reset : frontier_point;
    shard.reset_point = update_point_monotonic(shard.reset_point, reset, lsn_only);
    shard.frontier_point = update_point_monotonic(shard.frontier_point, frontier, lsn_only);
    const uint64_t reset_lfn = log_point_lfn(reset);
    int removed_pages = 0;
    while (true) {
        const int budget = std::max(state.config().purge_budget, static_cast<int>(shard.page_cache.size()));
        const int n = purge_shard_through_lfn(state, shard, reset_lfn, budget, false, "queue-reset");
        removed_pages += n;
        if (n < budget) {
            break;
        }
    }
    if (verbose) {
        gbp_run_log("PAGE_WRITE reset barrier peer=" + peer + " qid=" + std::to_string(qid) +
                    " reset[" + format_log_point_short(reset) + "] frontier[" +
                    format_log_point_short(frontier) + "] purged_cache_pages=" + std::to_string(removed_pages) +
                    " cache_total=" + std::to_string(shard.page_cache.size()) +
                    " pending_total=" + std::to_string(shard.batch_pending.size()));
    }
}

log_point_t apply_queue_resets_to_begin(const log_point_t& begin, const log_point_t resets[OG_GBP_SESSION_COUNT],
                                        bool lsn_only)
{
    log_point_t reset = max_queue_reset(resets, lsn_only);
    if (log_point_is_zero(reset)) {
        return begin;
    }
    if (log_point_cmp(reset, begin, lsn_only) > 0) {
        return reset;
    }
    return begin;
}

std::optional<std::pair<uint32_t, log_point_t>> min_queue_frontier(
    const log_point_t frontiers[OG_GBP_SESSION_COUNT], bool lsn_only, std::vector<int>& missing)
{
    missing.clear();
    std::optional<std::pair<uint32_t, log_point_t>> best;
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        if (log_point_is_zero(frontiers[qid])) {
            missing.push_back(static_cast<int>(qid));
            continue;
        }
        if (!best || log_point_cmp(frontiers[qid], best->second, lsn_only) < 0) {
            best = std::make_pair(qid, frontiers[qid]);
        }
    }
    if (!best || !missing.empty()) {
        return std::nullopt;
    }
    return best;
}

CkptResult merge_ckpt_from_shards(GbpServerState& state, bool lsn_only)
{
    CkptResult out;
    log_point_t resets[OG_GBP_SESSION_COUNT]{};
    log_point_t frontiers[OG_GBP_SESSION_COUNT]{};
    log_point_t min_trunc_point{};
    uint64_t min_trunc_lfn = INF_LFN;
    log_point_t max_lrp_point{};
    uint64_t max_lrp_lfn = 0;
    uint64_t max_writer_seq = 0;

    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        GbpShard& shard = state.shard(qid);
        if (shard.snap.dirty) {
            refresh_shard_snap(shard);
        }
        out.cache_pages += shard.snap.page_count;
        if (!log_point_is_zero(shard.reset_point)) {
            resets[qid] = shard.reset_point;
        }
        if (!log_point_is_zero(shard.frontier_point)) {
            frontiers[qid] = shard.frontier_point;
        }
        if (shard.snap.page_count == 0) {
            continue;
        }
        if (shard.snap.min_trunc_lfn < min_trunc_lfn) {
            min_trunc_lfn = shard.snap.min_trunc_lfn;
            min_trunc_point = shard.snap.min_trunc_point;
        }
        if (shard.snap.max_lrp_lfn > max_lrp_lfn) {
            max_lrp_lfn = shard.snap.max_lrp_lfn;
            max_lrp_point = shard.snap.max_lrp_point;
        }
        if (shard.snap.max_writer_seq > max_writer_seq) {
            max_writer_seq = shard.snap.max_writer_seq;
        }
    }

    out.queue_resets = {};
    out.queue_frontiers = {};
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        out.queue_resets[qid] = resets[qid];
        out.queue_frontiers[qid] = frontiers[qid];
    }

    std::vector<int> missing;
    auto frontier_min = min_queue_frontier(frontiers, lsn_only, missing);
    log_point_t z = zero_log_point();
    if (!frontier_min || out.cache_pages == 0) {
        out.begin = z;
        out.rcy = z;
        out.lrp = z;
        return out;
    }
    log_point_t rcy_b = frontier_min->second;
    log_point_t begin_b = min_trunc_lfn < INF_LFN ? min_trunc_point : z;
    begin_b = apply_queue_resets_to_begin(begin_b, resets, lsn_only);
    begin_b = state.apply_evicted_holes_to_begin(begin_b, rcy_b);
    if (log_point_cmp(rcy_b, begin_b, lsn_only) <= 0) {
        log_point_t closed = log_point_is_zero(begin_b) ? z : begin_b;
        out.begin = closed;
        out.rcy = closed;
        out.lrp = closed;
        out.max_lsn = max_writer_seq;
        return out;
    }
    log_point_t lrp_b = max_lrp_lfn > 0 ? max_lrp_point : rcy_b;
    if (log_point_cmp(lrp_b, rcy_b, lsn_only) < 0) {
        lrp_b = rcy_b;
    }
    out.begin = begin_b;
    out.rcy = rcy_b;
    out.lrp = lrp_b;
    out.max_lsn = max_writer_seq;
    return out;
}

CkptResult GbpServerState::ckpt_snapshot(bool lsn_only)
{
    CkptResult out;
    {
        std::lock_guard<std::mutex> g(evict_state.mtx);
        out.diag.evict_in_progress = evict_state.job_running ? 1 : 0;
        out.diag.purge_stable = evict_state.purge_stable ? 1 : 0;
    }
    if (out.diag.evict_in_progress || !out.diag.purge_stable) {
        if (cfg_.ckpt_wait_evict) {
            if (!evict_state.wait_stable(cfg_.ckpt_wait_ms)) {
                out.diag.wait_timeout = 1;
                out.diag.empty_reason = "wait_timeout";
                return out;
            }
            std::lock_guard<std::mutex> g(evict_state.mtx);
            out.diag.evict_in_progress = evict_state.job_running ? 1 : 0;
            out.diag.purge_stable = evict_state.purge_stable ? 1 : 0;
            if (out.diag.evict_in_progress || !out.diag.purge_stable) {
                out.diag.empty_reason = "purge_unstable";
                return out;
            }
        } else {
            out.diag.empty_reason = out.diag.evict_in_progress ? "evict_in_progress" : "purge_unstable";
            return out;
        }
    }
    lock_all();
    out = merge_ckpt_from_shards(*this, lsn_only);
    unlock_all();
    return out;
}

RetiredReadPhaseState GbpServerState::detach_read_phase_generation()
{
    read_end_detaching_.store(true, std::memory_order_release);
    {
        std::unique_lock<std::mutex> lock(evict_state.mtx);
        while (evict_state.job_running && !evict_state.stop) {
            cond_wait_for_compatible(evict_state.cv, lock, std::chrono::milliseconds(GBP_EVICT_WAIT_SLICE_MS));
        }
    }

    RetiredReadPhaseState retired;
    lock_all();
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        GbpShard& shard = *shards_[qid];
        RetiredShardData& out = retired.shards[qid];
        retired.detached_pages += static_cast<int>(shard.page_cache.size());
        out.page_cache.swap(shard.page_cache);
        out.page_meta.swap(shard.page_meta);
        out.meta_index_.swap(shard.meta_index_);
        std::swap(out.batch_pending, shard.batch_pending);
        out.lrp_index.emplace(cfg_);
        out.trunc_index.emplace(cfg_);
        out.writer_index.emplace(cfg_);
        using std::swap;
        swap(*out.lrp_index, shard.lrp_index_);
        swap(*out.trunc_index, shard.trunc_index_);
        swap(*out.writer_index, shard.writer_index_);
        out.snap = shard.snap;
        out.reset_point = shard.reset_point;
        out.frontier_point = shard.frontier_point;
        shard.snap = WindowSnap{};
        shard.reset_point = zero_log_point();
        shard.frontier_point = zero_log_point();
        shard.pending_seeded = false;
    }
    unlock_all();
    total_pages_.store(0, std::memory_order_relaxed);
    pending_total_.store(0, std::memory_order_relaxed);
    clear_evicted_holes();
    read_end_detaching_.store(false, std::memory_order_release);
    return retired;
}

void GbpServerState::schedule_retired_destruction(RetiredReadPhaseState&& retired)
{
    std::lock_guard<std::mutex> evict_lock(evict_state.mtx);
    {
        std::lock_guard<std::mutex> g(retired_state.mtx);
        retired_state.queue.push_back(std::move(retired));
    }
    evict_state.cv.notify_all();
}

void GbpServerState::clear_all(int& cache_pages, int& pending_pages, int& reset_count, int& frontier_count)
{
    cache_pages = 0;
    pending_pages = 0;
    reset_count = 0;
    frontier_count = 0;
    lock_all();
    for (auto& p : shards_) {
        auto& shard = *p;
        cache_pages += static_cast<int>(shard.page_cache.size());
        pending_pages += static_cast<int>(shard.batch_pending.size());
        if (!log_point_is_zero(shard.reset_point)) {
            reset_count++;
        }
        if (!log_point_is_zero(shard.frontier_point)) {
            frontier_count++;
        }
        shard.page_cache.clear();
        shard.page_meta.clear();
        shard.meta_index_.clear();
        shard.batch_pending.clear();
        shard.pending_seeded = false;
        shard.reset_point = zero_log_point();
        shard.frontier_point = zero_log_point();
        shard.lrp_index_ = LfnBucketIndex(cfg_);
        shard.trunc_index_ = LfnBucketIndex(cfg_);
        shard.writer_index_ = LfnBucketIndex(cfg_);
        shard.snap = WindowSnap{};
    }
    unlock_all();
    total_pages_.store(0, std::memory_order_relaxed);
    pending_total_.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> g(evict_state.mtx);
        evict_state.job_running = false;
        evict_state.job_target = 0;
        evict_state.job_deleted = 0;
        evict_state.purge_stable = true;
        evict_state.cv.notify_all();
    }
}

bool GbpServerState::try_note_page_installed(bool replaced)
{
    if (replaced) {
        return true;
    }
    if (cfg_.max_cache_pages <= 0 || cfg_.capacity_evict_on_write) {
        total_pages_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    int current = total_pages_.load(std::memory_order_relaxed);
    while (true) {
        if (current >= cfg_.max_cache_pages) {
            return false;
        }
        if (total_pages_.compare_exchange_weak(current, current + 1, std::memory_order_relaxed,
                                               std::memory_order_relaxed)) {
            return true;
        }
    }
}

void GbpServerState::note_page_removed()
{
    total_pages_.fetch_sub(1, std::memory_order_relaxed);
}

void GbpServerState::note_pending_delta(int delta)
{
    if (delta == 0) {
        return;
    }
    pending_total_.fetch_add(delta, std::memory_order_relaxed);
}

void GbpServerState::build_read_meta_snapshot(std::vector<MetaSnapshotRow>& out) const
{
    out.clear();
    out.reserve(static_cast<size_t>(total_page_count()));
    for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
        const GbpShard& shard = *shards_[qid];
        std::lock_guard<std::mutex> g(shard.mtx);
        for (const auto& kv : shard.meta_index_) {
            out.push_back(kv.second);
        }
    }
}

uint64_t compute_global_begin_lfn(GbpServerState& state, bool lsn_only)
{
    state.lock_all();
    CkptResult ckpt = merge_ckpt_from_shards(state, lsn_only);
    state.unlock_all();
    return log_point_lfn(ckpt.begin);
}

bool run_fixed_point_purge(GbpServerState& state, bool lsn_only, int budget)
{
    int remaining = budget;
    bool stable = false;
    while (remaining > 0) {
        const uint64_t begin_lfn = compute_global_begin_lfn(state, lsn_only);
        int deleted = 0;
        for (uint32_t qid = 0; qid < OG_GBP_SESSION_COUNT; ++qid) {
            if (remaining <= 0) {
                break;
            }
            GbpShard& shard = state.shard(qid);
            std::lock_guard<std::mutex> g(shard.mtx);
            const int n = purge_shard_through_lfn(state, shard, begin_lfn, remaining, false, "begin-purge");
            deleted += n;
            remaining -= n;
        }
        if (deleted == 0) {
            stable = true;
            break;
        }
    }
    return stable;
}

std::optional<std::pair<uint32_t, uint64_t>> find_global_min_lrp_page(GbpServerState& state)
{
    std::optional<std::tuple<uint64_t, uint32_t, uint64_t>> best;
    for (uint32_t sid = 0; sid < OG_GBP_SESSION_COUNT; ++sid) {
        GbpShard& shard = state.shard(sid);
        std::lock_guard<std::mutex> g(shard.mtx);
        auto found = shard.lrp_index_.find_min_pid();
        if (!found) {
            continue;
        }
        if (!best || found->second < std::get<0>(*best)) {
            best = std::make_tuple(found->second, sid, found->first);
        }
    }
    if (!best) {
        return std::nullopt;
    }
    return std::make_pair(std::get<GBP_GLOBAL_MIN_LRP_TUPLE_QID_INDEX>(*best),
                          std::get<GBP_GLOBAL_MIN_LRP_TUPLE_PID_INDEX>(*best));
}

namespace {

void run_capacity_evict_job(GbpServerState* state, bool lsn_only)
{
    int job_target = 0;
    {
        std::lock_guard<std::mutex> lock(state->evict_state.mtx);
        if (!state->evict_state.job_running) {
            return;
        }
        job_target = state->evict_state.job_target;
        state->evict_state.job_deleted = 0;
        state->evict_state.purge_stable = false;
    }
    int deleted = 0;
    const int sample_limit = state->config().evict_sample_log;
    auto worker_stopped = [&]() {
        std::lock_guard<std::mutex> lk(state->evict_state.mtx);
        return state->evict_state.stop;
    };
    while (deleted < job_target && !worker_stopped()) {
        auto picked = find_global_min_lrp_page(*state);
        if (!picked) {
            break;
        }
        GbpShard& shard = state->shard(picked->first);
        std::lock_guard<std::mutex> g(shard.mtx);
        if (shard.page_cache.find(picked->second) == shard.page_cache.end()) {
            continue;
        }
        remove_page(*state, shard, picked->second, true, "capacity", deleted < sample_limit);
        deleted++;
        if (deleted % state->config().evict_budget == 0) {
            std::lock_guard<std::mutex> lk(state->evict_state.mtx);
            state->evict_state.job_deleted = deleted;
            state->evict_state.cv.notify_all();
        }
    }
    {
        std::lock_guard<std::mutex> lk(state->evict_state.mtx);
        state->evict_state.job_deleted = deleted;
    }
    const bool purge_ok = run_fixed_point_purge(*state, lsn_only, state->config().purge_budget);
    {
        std::lock_guard<std::mutex> lk(state->evict_state.mtx);
        state->evict_state.purge_stable = purge_ok;
        state->evict_state.job_running = false;
        state->evict_state.cv.notify_all();
    }
    if (deleted > 0) {
        gbp_run_log("[capacity-evict] job done deleted=" + std::to_string(deleted) +
                    " target=" + std::to_string(job_target) + " purge_stable=" + std::to_string(purge_ok) +
                    " total_pages=" + std::to_string(state->total_page_count()));
    }
}

}  // namespace

void evict_worker_loop(GbpServerState* state)
{
    const bool lsn_only = state->config().log_cmp_lsn_only;
    while (true) {
        bool do_capacity = false;
        {
            std::unique_lock<std::mutex> lock(state->evict_state.mtx);
            while (true) {
                if (state->evict_state.stop) {
                    return;
                }
                const bool capacity_pending = state->evict_state.job_running;
                bool retired_pending = false;
                {
                    std::lock_guard<std::mutex> rlock(state->retired_state.mtx);
                    retired_pending = !state->retired_state.queue.empty();
                }
                if (capacity_pending) {
                    do_capacity = true;
                    break;
                }
                if (retired_pending) {
                    do_capacity = false;
                    break;
                }
                cond_wait_for_compatible(state->evict_state.cv, lock,
                                         std::chrono::milliseconds(GBP_EVICT_IDLE_WAIT_MS));
            }
        }

        if (do_capacity) {
            run_capacity_evict_job(state, lsn_only);
            continue;
        }

        std::optional<RetiredReadPhaseState> retired;
        {
            std::lock_guard<std::mutex> g(state->retired_state.mtx);
            if (!state->retired_state.queue.empty()) {
                state->retired_state.running = true;
                retired = std::move(state->retired_state.queue.front());
                state->retired_state.queue.pop_front();
            }
        }
        if (!retired) {
            continue;
        }

        const auto begin = std::chrono::steady_clock::now();
        const int pages = retired->detached_pages;
        retired.reset();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - begin)
                                    .count();
        {
            std::lock_guard<std::mutex> g(state->retired_state.mtx);
            state->retired_state.running = false;
        }
        gbp_run_log("READ_END background retired destruct done pages=" + std::to_string(pages) +
                    " elapsed_ms=" + std::to_string(elapsed_ms));
    }
}

void GbpServerState::maybe_start_capacity_evict()
{
    if (!cfg_.capacity_evict_on_write) {
        return;
    }
    if (read_end_detaching_.load(std::memory_order_acquire)) {
        return;
    }
    if (cfg_.max_cache_pages <= 0) {
        return;
    }
    const int total = total_page_count();
    const int high_water = static_cast<int>(cfg_.max_cache_pages * cfg_.cache_high_water);
    if (total < high_water) {
        return;
    }
    if (cfg_.cache_evict_ratio <= 0.0) {
        return;
    }
    const int target = std::max(1, static_cast<int>(cfg_.max_cache_pages * cfg_.cache_evict_ratio));
    std::lock_guard<std::mutex> g(evict_state.mtx);
    if (evict_state.job_running) {
        return;
    }
    if (read_end_detaching_.load(std::memory_order_acquire)) {
        return;
    }
    evict_state.job_target = target;
    evict_state.job_running = true;
    evict_state.purge_stable = false;
    evict_state.cv.notify_all();
    gbp_run_log("[capacity-evict] start target=" + std::to_string(target) + " total_pages=" +
                std::to_string(total) + " max_pages=" + std::to_string(cfg_.max_cache_pages) +
                " high_water=" + std::to_string(high_water));
}

void GbpServerState::start_evict_worker()
{
    evict_thread_ = std::thread(evict_worker_loop, this);
}

void GbpServerState::stop_evict_worker()
{
    {
        std::lock_guard<std::mutex> g(evict_state.mtx);
        evict_state.stop = true;
        evict_state.cv.notify_all();
    }
    if (evict_thread_.joinable()) {
        evict_thread_.join();
    }
}

}  // namespace gbp
