#include "gbp_protocol.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>

namespace gbp {

namespace {

gbp_batch_read_resp_t& tls_batch_read_resp() {
    thread_local gbp_batch_read_resp_t resp;
    return resp;
}

void fill_demo_msg(char* msg, const char* text) {
    std::memset(msg, 0, GBP_MSG_LEN);
    if (text && text[0]) std::memcpy(msg, text, std::strlen(text) + 1);
}

void pad_batch_resp_pages(gbp_batch_read_resp_t& resp, uint32_t count) {
    thread_local uint32_t prev_filled = 0;
    if (count < prev_filled) {
        std::memset(resp.pages + count, 0,
                    static_cast<size_t>(prev_filled - count) * sizeof(gbp_page_item_t));
    }
    prev_filled = count;
}

std::shared_ptr<PagePayload> payload_from_block(const uint8_t* block_ptr) {
    auto payload = std::make_shared<PagePayload>();
    std::memcpy(payload->block, block_ptr, GBP_PAGE_SIZE);
    return payload;
}

struct PreparedPageWrite {
    uint64_t pid_key = 0;
    const uint8_t* block_ptr = nullptr;
    log_point_t trunc{};
    log_point_t lrp{};
    uint32_t writer_inst = 0;
    uint64_t writer_seq = 0;
    bool rejected = false;
    const char* reject_reason = "none";
};

enum class PageWriteOp { Reject, Covered, Install };

struct PageWritePlan {
    PageWriteOp op = PageWriteOp::Reject;
    uint64_t pid_key = 0;
    const uint8_t* block_ptr = nullptr;
    log_point_t trunc{};
    log_point_t lrp{};
    log_point_t coverage_begin{};
    log_point_t coverage_lrp{};
    uint32_t writer_inst = 0;
    uint64_t writer_seq = 0;
    bool had_prev = false;
    uint32_t prev_writer_inst = 0;
    uint64_t prev_writer_seq = 0;
    uint64_t prev_page_lsn = 0;
    uint32_t prev_page_pcn = 0;
    bool counted_reject = false;
    const char* reason = "none";
    std::shared_ptr<PagePayload> payload;
};

const char* page_write_op_name(PageWriteOp op) {
    switch (op) {
        case PageWriteOp::Reject:
            return "reject";
        case PageWriteOp::Covered:
            return "covered";
        case PageWriteOp::Install:
            return "install";
        default:
            return "unknown";
    }
}

bool commit_page_install(PageWritePlan& plan, GbpServerState& state, GbpShard& shard, PageRecord rec,
                         const PageMeta& meta, bool legacy_pending, int& rejected, int& accepted,
                         int& capacity_rejected) {
    if (!install_page(state, shard, plan.pid_key, std::move(rec), meta, legacy_pending)) {
        ++rejected;
        ++capacity_rejected;
        plan.op = PageWriteOp::Reject;
        plan.counted_reject = true;
        plan.reason = "capacity_full";
        return false;
    }
    ++accepted;
    return true;
}

void fill_prev_page_diag(PageWritePlan& plan, const PageRecord& prev) {
    uint16_t cks = 0;

    plan.had_prev = true;
    plan.prev_writer_inst = prev.writer_inst;
    plan.prev_writer_seq = prev.writer_seq;
    page_diag_from_block(page_block_cstr(prev), plan.prev_page_lsn, plan.prev_page_pcn, cks);
}

std::string format_hex_u16(uint16_t value) {
    std::ostringstream os;
    os << std::hex << value;
    return os.str();
}

void log_verbose_page_write_result(const std::string& peer, uint32_t qid, uint32_t index,
                                   const PageWritePlan& plan, bool applied, int accepted_delta,
                                   int rejected_delta, const log_point_t& batch_begin,
                                   const log_point_t& batch_trunc, const log_point_t& batch_lrp,
                                   const GbpShard& shard) {
    page_id_t pid{};
    uint64_t incoming_lsn = 0;
    uint32_t incoming_pcn = 0;
    uint16_t incoming_cks = 0;
    bool has_after = false;
    uint32_t after_writer_inst = 0;
    uint64_t after_writer_seq = 0;
    uint64_t after_page_lsn = 0;
    uint32_t after_page_pcn = 0;
    uint16_t after_cks = 0;

    std::memcpy(&pid, &plan.pid_key, sizeof(pid));
    page_diag_from_block(reinterpret_cast<const char*>(plan.block_ptr), incoming_lsn, incoming_pcn, incoming_cks);

    auto after = shard.page_cache.find(plan.pid_key);
    if (after != shard.page_cache.end()) {
        has_after = true;
        after_writer_inst = after->second.writer_inst;
        after_writer_seq = after->second.writer_seq;
        page_diag_from_block(page_block_cstr(after->second), after_page_lsn, after_page_pcn, after_cks);
    }

    gbp_run_log("PAGE_WRITE page peer=" + peer + " qid=" + std::to_string(qid) +
                " idx=" + std::to_string(index) + " op=" + page_write_op_name(plan.op) +
                " applied=" + std::to_string(static_cast<int>(applied)) +
                " reason=" + std::string(plan.reason ? plan.reason : "none") +
                " counted_reject=" + std::to_string(static_cast<int>(plan.counted_reject)) +
                " accepted_delta=" + std::to_string(accepted_delta) +
                " rejected_delta=" + std::to_string(rejected_delta) + " " +
                format_page_id(pid.file, pid.page, pid.aligned) +
                " incoming_inst=" + std::to_string(plan.writer_inst) +
                " incoming_seq=" + std::to_string(plan.writer_seq) +
                " incoming_lsn=" + std::to_string(incoming_lsn) +
                " incoming_pcn=" + std::to_string(incoming_pcn) +
                " incoming_cks=0x" + format_hex_u16(incoming_cks) +
                " prev_present=" + std::to_string(static_cast<int>(plan.had_prev)) +
                " prev_inst=" + std::to_string(plan.prev_writer_inst) +
                " prev_seq=" + std::to_string(plan.prev_writer_seq) +
                " prev_lsn=" + std::to_string(plan.prev_page_lsn) +
                " prev_pcn=" + std::to_string(plan.prev_page_pcn) +
                " after_present=" + std::to_string(static_cast<int>(has_after)) +
                " after_inst=" + std::to_string(after_writer_inst) +
                " after_seq=" + std::to_string(after_writer_seq) +
                " after_lsn=" + std::to_string(after_page_lsn) +
                " after_pcn=" + std::to_string(after_page_pcn) +
                " after_cks=0x" + format_hex_u16(after_cks) +
                " trunc[" + format_log_point_short(plan.trunc) + "]" +
                " lrp[" + format_log_point_short(plan.lrp) + "]" +
                " coverage_begin[" + format_log_point_short(plan.coverage_begin) + "]" +
                " coverage_lrp[" + format_log_point_short(plan.coverage_lrp) + "]" +
                " batch_begin[" + format_log_point_short(batch_begin) + "]" +
                " batch_trunc[" + format_log_point_short(batch_trunc) + "]" +
                " batch_lrp[" + format_log_point_short(batch_lrp) + "]");
}

bool page_write_passes_reset(const GbpShard& shard, const log_point_t& lrp, bool lsn_only) {
    return log_point_is_zero(shard.reset_point) || log_point_cmp(lrp, shard.reset_point, lsn_only) > 0;
}

PageWritePlan plan_page_write(const PreparedPageWrite& pw, GbpShard& shard, bool strict, bool lsn_only, int& rejected) {
    PageWritePlan plan{};
    plan.pid_key = pw.pid_key;
    plan.block_ptr = pw.block_ptr;
    plan.trunc = pw.trunc;
    plan.lrp = pw.lrp;
    plan.writer_inst = pw.writer_inst;
    plan.writer_seq = pw.writer_seq;

    if (pw.rejected || !page_write_passes_reset(shard, pw.lrp, lsn_only)) {
        if (!pw.rejected) {
            ++rejected;
            plan.counted_reject = true;
            plan.reason = "reset_barrier";
        } else {
            plan.counted_reject = true;
            plan.reason = pw.reject_reason;
        }
        return plan;
    }

    if (!strict) {
        plan.op = PageWriteOp::Install;
        plan.reason = "non_strict";
        auto prev = shard.page_cache.find(pw.pid_key);
        if (prev == shard.page_cache.end()) {
            plan.coverage_begin = pw.trunc;
            plan.coverage_lrp = pw.lrp;
        } else {
            fill_prev_page_diag(plan, prev->second);
            plan.coverage_begin = log_point_min(prev->second.coverage_begin, pw.trunc, lsn_only);
            plan.coverage_lrp = log_point_max(prev->second.coverage_lrp, pw.lrp, lsn_only);
        }
        return plan;
    }

    auto prev_it = shard.page_cache.find(pw.pid_key);
    if (prev_it == shard.page_cache.end()) {
        plan.op = PageWriteOp::Install;
        plan.reason = "new_page";
        plan.coverage_begin = pw.trunc;
        plan.coverage_lrp = pw.lrp;
        return plan;
    }
    PageRecord& prev = prev_it->second;
    fill_prev_page_diag(plan, prev);
    plan.coverage_begin = log_point_min(prev.coverage_begin, pw.trunc, lsn_only);
    plan.coverage_lrp = log_point_max(prev.coverage_lrp, pw.lrp, lsn_only);
    const SmbDecision d = smb_should_replace(prev.writer_inst, prev.writer_seq, pw.writer_inst, pw.writer_seq);
    if (d.replace && std::strcmp(d.reason, "idem_same_writer") != 0) {
        plan.op = PageWriteOp::Install;
        plan.reason = d.reason;
    } else if (prev.writer_seq > pw.writer_seq ||
               (prev.writer_seq == pw.writer_seq && prev.writer_inst == pw.writer_inst)) {
        plan.op = PageWriteOp::Covered;
        plan.reason = d.reason;
    } else {
        ++rejected;
        plan.counted_reject = true;
        plan.reason = d.reason;
    }
    return plan;
}

bool apply_page_write_plan(PageWritePlan& plan, GbpServerState& state, GbpShard& shard, bool strict, bool lsn_only,
                           bool legacy_pending, int& rejected, int& accepted, int& capacity_rejected) {
    if (plan.op == PageWriteOp::Reject) return false;

    if (!page_write_passes_reset(shard, plan.lrp, lsn_only)) {
        ++rejected;
        plan.counted_reject = true;
        plan.reason = "reset_barrier_apply";
        return false;
    }

    if (plan.op == PageWriteOp::Covered) {
        auto prev_it = shard.page_cache.find(plan.pid_key);
        if (prev_it == shard.page_cache.end()) {
            ++rejected;
            plan.counted_reject = true;
            plan.reason = "covered_missing_cache";
            return false;
        }
        PageRecord& prev = prev_it->second;
        if (!(prev.writer_seq > plan.writer_seq ||
              (prev.writer_seq == plan.writer_seq && prev.writer_inst == plan.writer_inst))) {
            ++rejected;
            plan.counted_reject = true;
            plan.reason = "covered_race_stale_check_failed";
            return false;
        }
        prev.coverage_begin = plan.coverage_begin;
        prev.coverage_lrp = plan.coverage_lrp;
        PageMeta meta = build_page_meta(plan.pid_key, prev);
        return commit_page_install(plan, state, shard, prev, meta, legacy_pending, rejected, accepted,
                                   capacity_rejected);
    }

    if (plan.op != PageWriteOp::Install || !plan.payload) {
        ++rejected;
        plan.counted_reject = true;
        plan.reason = (plan.op == PageWriteOp::Install) ? "install_missing_payload" : "unexpected_op";
        return false;
    }

    if (!strict) {
        PageRecord rec = page_record_from_payload(plan.payload, plan.writer_inst, plan.writer_seq);
        auto prev = shard.page_cache.find(plan.pid_key);
        if (prev == shard.page_cache.end()) {
            rec.coverage_begin = plan.coverage_begin;
            rec.coverage_lrp = plan.coverage_lrp;
        } else {
            rec.coverage_begin = log_point_min(prev->second.coverage_begin, plan.trunc, lsn_only);
            rec.coverage_lrp = log_point_max(prev->second.coverage_lrp, plan.lrp, lsn_only);
        }
        PageMeta meta = build_page_meta(plan.pid_key, rec);
        return commit_page_install(plan, state, shard, std::move(rec), meta, legacy_pending, rejected, accepted,
                                   capacity_rejected);
    }

    auto prev_it = shard.page_cache.find(plan.pid_key);
    if (prev_it == shard.page_cache.end()) {
        PageRecord rec = page_record_from_payload(plan.payload, plan.writer_inst, plan.writer_seq);
        rec.coverage_begin = plan.coverage_begin;
        rec.coverage_lrp = plan.coverage_lrp;
        PageMeta meta = build_page_meta(plan.pid_key, rec);
        return commit_page_install(plan, state, shard, std::move(rec), meta, legacy_pending, rejected, accepted,
                                   capacity_rejected);
    }

    PageRecord& prev = prev_it->second;
    const log_point_t coverage_begin = log_point_min(prev.coverage_begin, plan.trunc, lsn_only);
    const log_point_t coverage_lrp = log_point_max(prev.coverage_lrp, plan.lrp, lsn_only);
    const SmbDecision d =
        smb_should_replace(prev.writer_inst, prev.writer_seq, plan.writer_inst, plan.writer_seq);
    if (d.replace && std::strcmp(d.reason, "idem_same_writer") != 0) {
        PageRecord rec = page_record_from_payload(plan.payload, plan.writer_inst, plan.writer_seq);
        rec.coverage_begin = coverage_begin;
        rec.coverage_lrp = coverage_lrp;
        PageMeta meta = build_page_meta(plan.pid_key, rec);
        return commit_page_install(plan, state, shard, std::move(rec), meta, legacy_pending, rejected, accepted,
                                   capacity_rejected);
    }
    if (prev.writer_seq > plan.writer_seq ||
        (prev.writer_seq == plan.writer_seq && prev.writer_inst == plan.writer_inst)) {
        prev.coverage_begin = coverage_begin;
        prev.coverage_lrp = coverage_lrp;
        PageMeta meta = build_page_meta(plan.pid_key, prev);
        return commit_page_install(plan, state, shard, prev, meta, legacy_pending, rejected, accepted,
                                   capacity_rejected);
    }

    ++rejected;
    plan.counted_reject = true;
    plan.reason = "strict_race_reject";
    return false;
}

}  // namespace

void send_cs_ready_ack(socket_t fd) {
    const uint16_t one = 1;
    const uint8_t local_endian = (*reinterpret_cast<const uint8_t*>(&one) == 0) ? 1 : 0;
    uint8_t ack[4];
    ack[0] = local_endian;
    ack[1] = static_cast<uint8_t>(CS_HANDSHAKE_VERSION);
    uint16_t flag = CS_FLAG_DN_CONN;
    std::memcpy(ack + 2, &flag, 2);
    send_full_or_disconnect(fd, ack, sizeof(ack), "CS_READY_ACK");
}

void send_ack(socket_t fd, const gbp_msg_hdr_t& req, uint32_t ack_type, uint32_t ack_data) {
    gbp_msg_ack_t ack{};
    ack.header.msg_type = req.msg_type;
    ack.header.msg_length = static_cast<uint32_t>(sizeof(gbp_msg_ack_t));
    ack.header.queue_id = req.queue_id;
    ack.header.msg_fd = req.msg_fd;
    ack.ack_type = ack_type;
    ack.ack_data = ack_data;
    send_full_or_disconnect(fd, &ack, sizeof(ack), "ACK");
}

void send_shake_resp(socket_t fd, const gbp_msg_hdr_t& req, uint32_t queue_id, uint32_t is_temp) {
    struct {
        gbp_msg_hdr_t header;
        uint32_t queue_id;
        uint32_t is_temp;
    } resp{};
    resp.header.msg_type = req.msg_type;
    resp.header.msg_length = sizeof(resp);
    resp.header.queue_id = queue_id;
    resp.header.msg_fd = req.msg_fd;
    resp.queue_id = queue_id;
    resp.is_temp = is_temp;
    send_full_or_disconnect(fd, &resp, sizeof(resp), "SHAKE_RESP");
}

void send_read_ckpt_resp(socket_t fd, const gbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                         GbpServerState& state, bool verbose, const std::string& peer) {
    (void)verbose;
    const bool lsn_only = state.config().log_cmp_lsn_only;
    const CkptResult ckpt = state.ckpt_snapshot(lsn_only);
    uint32_t check_end = 0;
    log_point_t aly_end = zero_log_point();
    if (body_len >= 4) {
        std::memcpy(&check_end, body, 4);
    }
    if (body_len >= 8 + LOG_POINT_SIZE) {
        std::memcpy(&aly_end, body + 8, LOG_POINT_SIZE);
    }
    gbp_read_ckpt_resp_t resp{};
    resp.header.msg_type = req.msg_type;
    resp.header.msg_length = static_cast<uint32_t>(CKPT_READ_RESP_SIZE);
    resp.header.queue_id = req.queue_id;
    resp.header.msg_fd = req.msg_fd;
    resp.gbp_unsafe = 0;
    resp.begin_point = ckpt.begin;
    resp.rcy_point = ckpt.rcy;
    resp.lrp_point = ckpt.lrp;
    resp.max_lsn = ckpt.max_lsn;
    std::memset(resp.unsafe_reason, 0, GBP_MSG_LEN);
    send_full_or_disconnect(fd, &resp, sizeof(resp), "READ_CKPT");
    const std::string reset_diag = queue_resets_diag(ckpt.queue_resets.data(), lsn_only);
    const std::string frontier_diag = queue_frontiers_diag(ckpt.queue_frontiers.data(), lsn_only);
    std::string extra_diag = reset_diag + frontier_diag +
                             " | evict_in_progress=" + std::to_string(ckpt.diag.evict_in_progress) +
                             " purge_stable=" + std::to_string(ckpt.diag.purge_stable) +
                             " wait_timeout=" + std::to_string(ckpt.diag.wait_timeout);
    if (!ckpt.diag.empty_reason.empty()) {
        extra_diag += " empty_reason=" + ckpt.diag.empty_reason;
    }
    gbp_run_log("READ_CKPT peer=" + peer + " cache_pages=" + std::to_string(ckpt.cache_pages) +
                " max_lsn=" + std::to_string(ckpt.max_lsn) + " check_end=" + std::to_string(check_end) +
                " aly_end=" + format_log_point_short(aly_end) + " | begin[" +
                format_log_point_short(ckpt.begin) + "] rcy(queue_frontier)[" +
                format_log_point_short(ckpt.rcy) + "] lrp/end(max_lrp)[" +
                format_log_point_short(ckpt.lrp) + "]" + extra_diag);
}

void send_page_read_resp(socket_t fd, const gbp_msg_hdr_t& req, const page_id_t& page_id, bool hit,
                         const log_point_t& trunc, const char* block) {
    gbp_read_resp_t resp{};
    resp.header = req;
    resp.header.msg_length = static_cast<uint32_t>(GBP_READ_RESP_SIZE);
    resp.result = hit ? GBP_READ_RESULT_OK : GBP_READ_RESULT_NOPAGE;
    resp.unused = 0;
    resp.pageid = page_id;
    resp.gbp_trunc_point = hit ? trunc : zero_log_point();
    if (hit && block) std::memcpy(resp.block, block, GBP_PAGE_SIZE);
    send_full_or_disconnect(fd, &resp, sizeof(resp), "PAGE_READ");
}

void send_batch_read_resp(socket_t fd, const gbp_msg_hdr_t& req, const log_point_t& skip_point, uint32_t conn_qid,
                          GbpServerState& state, bool verbose, const std::string& peer, bool read_phase_active) {
    const bool timing_diag = state.config().timing_diag;
    const bool lsn_only = state.config().log_cmp_lsn_only;
    const uint32_t qid = conn_qid % OG_GBP_SESSION_COUNT;
    if (auto seeded = state.ensure_batch_pending_seeded(read_phase_active, conn_qid)) {
        gbp_run_log("BATCH_READ lazy pending seed peer=" + peer + " qid=" + std::to_string(conn_qid) +
                    " pending_total=" + std::to_string(*seeded));
    }
    GbpShard& shard = state.shard(qid);
    int64_t lock_wait_us = 0;
    int64_t scan_us = 0;
    std::chrono::steady_clock::time_point batch_begin{};
    if (timing_diag) {
        batch_begin = std::chrono::steady_clock::now();
    }
    const auto lock_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    std::unique_lock<std::mutex> lock(shard.mtx);
    if (timing_diag) {
        lock_wait_us = us_since(lock_begin);
    }
    const auto scan_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    auto pick = shard.batch_pending.take_batch(shard.page_cache, skip_point, static_cast<int>(GBP_BATCH_PAGE_NUM),
                                               lsn_only);
    if (timing_diag) {
        scan_us = us_since(scan_begin);
    }

    std::vector<BatchPageHandle> handles;
    handles.reserve(pick.picked.size());
    for (const auto& [pid_key, gen, install_gen] : pick.picked) {
        (void)gen;
        (void)install_gen;
        auto it = shard.page_cache.find(pid_key);
        if (it == shard.page_cache.end()) continue;
        const PageRecord& rec = it->second;
        handles.push_back({pid_key, rec.coverage_begin, rec.coverage_lrp, rec.writer_inst, rec.writer_seq,
                           rec.payload});
    }
    lock.unlock();

    const uint32_t batch_result = handles.empty() ? GBP_READ_RESULT_NOPAGE : GBP_READ_RESULT_OK;
    int64_t pack_us = 0;
    int64_t send_us = 0;
    int64_t pending_lock_us = 0;
    int64_t pending_remove_us = 0;
    const auto pack_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};

    gbp_batch_read_resp_t& resp = tls_batch_read_resp();
    resp.header = req;
    resp.header.msg_length = static_cast<uint32_t>(BATCH_READ_RESP_SIZE);
    resp.result = batch_result;
    resp.count = static_cast<uint32_t>(handles.size());
    fill_demo_msg(resp.msg, "demo-batch");
    for (size_t i = 0; i < handles.size(); ++i) {
        wire_item_fill(resp.pages[i], handles[i]);
    }
    pad_batch_resp_pages(resp, resp.count);
    if (timing_diag) {
        pack_us = us_since(pack_begin);
    }
    const auto send_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    send_full_or_disconnect(fd, &resp, sizeof(resp), "BATCH_PAGE_READ");
    if (timing_diag) {
        send_us = us_since(send_begin);
    }

    if (batch_result == GBP_READ_RESULT_OK && !handles.empty()) {
        const auto pending_lock_begin =
            timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        lock.lock();
        if (timing_diag) {
            pending_lock_us = us_since(pending_lock_begin);
        }
        const auto pending_remove_begin =
            timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        const int removed = shard.batch_pending.mark_sent_and_count(pick, shard.page_cache);
        if (timing_diag) {
            pending_remove_us = us_since(pending_remove_begin);
        }
        state.note_pending_delta(-removed);
        lock.unlock();
    }
    if (timing_diag) {
        const int64_t total_us = us_since(batch_begin);
        state.read_diag().record(qid, batch_result, static_cast<int>(handles.size()), total_us, lock_wait_us, scan_us,
                                 pack_us, send_us, pending_lock_us, pending_remove_us, pick.scanned, pick.skip_stale,
                                 pick.skip_missing, pick.skip_lrp);
    } else {
        state.read_diag().record_counts(qid, batch_result, static_cast<int>(handles.size()));
    }
    if (verbose && timing_diag) {
        gbp_run_log("BATCH_PAGE_READ peer=" + peer + " conn_qid=" + std::to_string(conn_qid) +
                    " result=" + std::to_string(batch_result) + " sent=" + std::to_string(handles.size()) +
                    " lock_wait_us=" + std::to_string(lock_wait_us) + " scan_us=" + std::to_string(scan_us) +
                    " pack_us=" + std::to_string(pack_us) + " send_us=" + std::to_string(send_us) +
                    " pending_lock_us=" + std::to_string(pending_lock_us) +
                    " pending_remove_us=" + std::to_string(pending_remove_us) +
                    " queue_scanned=" + std::to_string(pick.scanned) +
                    " skip_stale=" + std::to_string(pick.skip_stale) +
                    " skip_missing=" + std::to_string(pick.skip_missing) +
                    " skip_lrp=" + std::to_string(pick.skip_lrp));
    }
}

PageWriteResult cache_pages_from_write(const uint8_t* body, size_t body_len, GbpServerState& state,
                                       uint32_t conn_qid, bool verbose, const std::string& peer) {
    PageWriteResult out;
    if (body_len < 4) return out;
    uint32_t page_num = 0;
    std::memcpy(&page_num, body, 4);
    if (page_num > GBP_BATCH_PAGE_NUM) page_num = GBP_BATCH_PAGE_NUM;
    const uint32_t qid = conn_qid % OG_GBP_SESSION_COUNT;
    GbpShard& shard = state.shard(qid);
    out.pages_off = resolve_write_pages_offset(body, body_len, page_num);
    if (out.pages_off < 0) return out;

    log_point_t batch_begin{}, batch_trunc{}, batch_lrp{};
    parse_write_batch_points(body, body_len, out.pages_off, batch_begin, batch_trunc, batch_lrp);
    const bool lsn_only = state.config().log_cmp_lsn_only;
    const bool strict = state.config().smb_version;
    const bool legacy_pending = state.config().legacy_batch_pending;

    if (page_num == 0) {
        log_point_t reset_point = select_reset_point(batch_begin, batch_lrp, lsn_only);
        if (log_point_is_zero(reset_point)) return out;
        const auto lock_begin = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> g(shard.mtx);
        out.lock_wait_us = us_since(lock_begin);
        const auto hold_begin = std::chrono::steady_clock::now();
        apply_queue_reset(state, shard, qid, reset_point, batch_trunc, lsn_only, verbose, peer);
        out.lock_hold_us = us_since(hold_begin);
        out.apply_hold_us = out.lock_hold_us;
        return out;
    }

    const size_t need = static_cast<size_t>(out.pages_off) + page_num * GBP_PAGE_ITEM_SIZE;
    if (body_len < need) return out;

    std::vector<PreparedPageWrite> prepared;
    prepared.reserve(page_num);
    int off = out.pages_off;
    constexpr size_t kPageItemHeaderSize = offsetof(gbp_page_item_t, block);
    for (uint32_t i = 0; i < page_num; ++i) {
        PreparedPageWrite pw{};
        const uint8_t* item_base = body + static_cast<size_t>(off);
        gbp_page_item_t item{};
        std::memcpy(&item, item_base, kPageItemHeaderSize);
        off += static_cast<int>(GBP_PAGE_ITEM_SIZE);
        pw.pid_key = page_id_key_from_raw(item.page_id);
        pw.block_ptr = item_base + kPageItemHeaderSize;
        pw.trunc = item.gbp_trunc_point;
        pw.lrp = item.gbp_lrp_point;
        pw.writer_inst = item.writer_inst_id;
        pw.writer_seq = item.writer_global_seq;
        if (page_queue_id(item.page_id.page) != qid) {
            pw.rejected = true;
            pw.reject_reason = "wrong_qid";
            prepared.push_back(std::move(pw));
            out.rejected++;
            continue;
        }
        if (log_point_is_zero(item.gbp_lrp_point)) {
            pw.rejected = true;
            pw.reject_reason = "zero_lrp_point";
            prepared.push_back(std::move(pw));
            out.rejected++;
            continue;
        }
        prepared.push_back(std::move(pw));
    }

    std::vector<PageWritePlan> plans;
    plans.reserve(prepared.size());
    {
        const auto lock_begin = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> g(shard.mtx);
        out.lock_wait_us += us_since(lock_begin);
        const auto hold_begin = std::chrono::steady_clock::now();
        for (const PreparedPageWrite& pw : prepared) {
            plans.push_back(plan_page_write(pw, shard, strict, lsn_only, out.rejected));
        }
        out.plan_hold_us = us_since(hold_begin);
        out.lock_hold_us += out.plan_hold_us;
    }

    {
        const auto payload_begin = std::chrono::steady_clock::now();
        for (PageWritePlan& plan : plans) {
            if (plan.op == PageWriteOp::Install) {
                plan.payload = payload_from_block(plan.block_ptr);
            }
        }
        out.payload_us = us_since(payload_begin);
    }

    {
        const auto lock_begin = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> g(shard.mtx);
        out.lock_wait_us += us_since(lock_begin);
        const auto hold_begin = std::chrono::steady_clock::now();
        for (uint32_t i = 0; i < plans.size(); ++i) {
            PageWritePlan& plan = plans[i];
            const int accepted_before = out.accepted;
            const int rejected_before = out.rejected;
            const bool applied = apply_page_write_plan(plan, state, shard, strict, lsn_only, legacy_pending,
                                                       out.rejected, out.accepted, out.capacity_rejected);
            if (verbose) {
                log_verbose_page_write_result(peer, qid, i, plan, applied, out.accepted - accepted_before,
                                              out.rejected - rejected_before, batch_begin, batch_trunc, batch_lrp,
                                              shard);
            }
        }
        if (out.rejected == 0) {
            shard.frontier_point = update_point_monotonic(shard.frontier_point, batch_trunc, lsn_only);
        } else if (verbose && !log_point_is_zero(batch_trunc)) {
            gbp_run_log("PAGE_WRITE frontier not advanced peer=" + peer + " qid=" + std::to_string(qid) +
                        " rejected=" + std::to_string(out.rejected));
        }
        out.apply_hold_us = us_since(hold_begin);
        out.lock_hold_us += out.apply_hold_us;
    }
    if (state.config().capacity_evict_on_write) state.maybe_start_capacity_evict();
    return out;
}

void send_meta_chunk_resp(socket_t fd, const gbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                          GbpServerState& state, ConnMeta& conn_meta, bool verbose, const std::string& peer) {
    uint64_t epoch = 0;
    uint64_t cursor = 0;
    uint32_t max_count = GBP_META_CHUNK_NUM;
    if (body_len >= 8) std::memcpy(&epoch, body, 8);
    if (body_len >= 16) std::memcpy(&cursor, body + 8, 8);
    if (body_len >= 20) std::memcpy(&max_count, body + 16, 4);
    max_count = std::max(1u, std::min(max_count, GBP_META_CHUNK_NUM));

    if (cursor == 0 || !conn_meta.snapshot_built) {
        state.build_read_meta_snapshot(conn_meta.snapshot);
        conn_meta.epoch = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
        epoch = conn_meta.epoch;
        conn_meta.snapshot_built = true;
    } else {
        epoch = conn_meta.epoch;
    }

    const size_t total = conn_meta.snapshot.size();
    const size_t start = std::min(cursor, total);
    const size_t end = std::min(start + max_count, total);
    const size_t picked_n = end - start;
    const uint64_t next_cursor = end;
    const uint32_t done = next_cursor >= total ? 1u : 0u;
    const uint32_t result = total == 0 ? GBP_READ_RESULT_NOPAGE : GBP_READ_RESULT_OK;

    gbp_read_meta_resp_t resp{};
    resp.header = req;
    resp.header.msg_length = static_cast<uint32_t>(READ_META_RESP_SIZE);
    resp.result = result;
    resp.count = static_cast<uint32_t>(picked_n);
    resp.epoch = epoch;
    resp.cursor = start;
    resp.next_cursor = next_cursor;
    resp.total_count = total;
    resp.done = done;
    resp.reserved = 0;
    for (size_t i = 0; i < picked_n; ++i) {
        const MetaSnapshotRow& row = conn_meta.snapshot[start + i];
        std::memcpy(&resp.items[i].page_id, row.pid_bytes.data(), sizeof(page_id_t));
        resp.items[i].page_lsn = row.page_lsn;
        resp.items[i].page_pcn = row.page_pcn;
        resp.items[i].source_node = row.writer_inst;
        resp.items[i].queue_id = row.qid;
    }
    send_full_or_disconnect(fd, &resp, sizeof(resp), "READ_META_CHUNK");
    if (verbose || done) {
        gbp_run_log("READ_META_CHUNK peer=" + peer + " cursor=" + std::to_string(start) +
                    " next=" + std::to_string(next_cursor) + " count=" + std::to_string(picked_n) +
                    " done=" + std::to_string(done) + " total=" + std::to_string(total));
    }
}

void send_batch_selected_read_resp(socket_t fd, const gbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                                   GbpServerState& state, bool verbose, const std::string& peer,
                                   uint32_t conn_qid) {
    const bool timing_diag = state.config().timing_diag;
    std::chrono::steady_clock::time_point batch_begin{};
    if (timing_diag) {
        batch_begin = std::chrono::steady_clock::now();
    }
    uint32_t req_count = 0;
    if (body_len >= 4) std::memcpy(&req_count, body, 4);
    req_count = std::min(req_count, GBP_BATCH_PAGE_NUM);
    struct SelectedPick {
        BatchPageHandle handle{};
    };
    struct SelectedMismatch {
        uint64_t pid_key = 0;
        uint64_t selected_lsn = 0;
        uint64_t block_lsn = 0;
        int64_t meta_lsn = -1;
        bool selected_mismatch = false;
        bool meta_mismatch = false;
    };
    std::vector<SelectedPick> picked;
    std::vector<uint64_t> misses;
    std::vector<SelectedMismatch> mismatches;
    const int mismatch_log_limit = state.config().selected_lsn_mismatch_log;
    const uint32_t qid = conn_qid % OG_GBP_SESSION_COUNT;
    int64_t lock_wait_us = 0;
    int selected_mismatch_count = 0;
    int meta_mismatch_count = 0;
    size_t off = 8;
    const auto lookup_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    for (uint32_t i = 0; i < req_count && off + 16 <= body_len; ++i) {
        page_id_t pid{};
        uint64_t selected_lsn = 0;
        std::memcpy(&pid, body + off, 8);
        std::memcpy(&selected_lsn, body + off + 8, 8);
        off += 16;
        const uint64_t pid_key = page_id_key_from_raw(pid);
        GbpShard& shard = state.shard(page_queue_id(pid.page));
        BatchPageHandle handle{};
        bool found = false;
        int64_t meta_lsn = -1;
        {
            const auto lock_begin =
                timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
            std::lock_guard<std::mutex> g(shard.mtx);
            if (timing_diag) {
                lock_wait_us += us_since(lock_begin);
            }
            auto cit = shard.page_cache.find(pid_key);
            if (cit == shard.page_cache.end()) {
                misses.push_back(pid_key);
                continue;
            }
            const PageRecord& rec = cit->second;
            handle = {pid_key, rec.coverage_begin, rec.coverage_lrp, rec.writer_inst, rec.writer_seq, rec.payload};
            found = true;
            auto mit = shard.page_meta.find(pid_key);
            if (mit != shard.page_meta.end()) meta_lsn = static_cast<int64_t>(mit->second.page_lsn);
        }
        if (!found) continue;
        int64_t block_lsn_value = meta_lsn;
        uint64_t block_lsn = 0;
        uint32_t pcn = 0;
        uint16_t cks = 0;
        if (mismatch_log_limit > 0) {
            page_diag_from_block(handle.payload ? handle.payload->block : nullptr, block_lsn, pcn, cks);
            block_lsn_value = static_cast<int64_t>(block_lsn);
        }
        (void)pcn;
        (void)cks;
        const bool selected_mismatch =
            selected_lsn != 0 && block_lsn_value >= 0 && static_cast<uint64_t>(block_lsn_value) != selected_lsn;
        const bool meta_mismatch =
            mismatch_log_limit > 0 && meta_lsn >= 0 && static_cast<uint64_t>(meta_lsn) != block_lsn;
        if (selected_mismatch) {
            selected_mismatch_count++;
        }
        if (meta_mismatch) {
            meta_mismatch_count++;
        }
        if (selected_mismatch || meta_mismatch) {
            mismatches.push_back(
                {pid_key, selected_lsn, block_lsn_value >= 0 ? static_cast<uint64_t>(block_lsn_value) : 0, meta_lsn,
                 selected_mismatch, meta_mismatch});
        }
        picked.push_back({handle});
    }
    const int64_t lookup_us = timing_diag ? us_since(lookup_begin) : 0;
    const int count = static_cast<int>(picked.size());
    const auto pack_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    gbp_batch_read_resp_t& resp = tls_batch_read_resp();
    resp.header = req;
    resp.header.msg_length = static_cast<uint32_t>(BATCH_READ_RESP_SIZE);
    resp.result = count == 0 ? GBP_READ_RESULT_NOPAGE : GBP_READ_RESULT_OK;
    resp.count = static_cast<uint32_t>(count);
    fill_demo_msg(resp.msg, "demo-selected");
    for (int i = 0; i < count; ++i) {
        wire_item_fill(resp.pages[i], picked[static_cast<size_t>(i)].handle);
    }
    pad_batch_resp_pages(resp, resp.count);
    const int64_t pack_us = timing_diag ? us_since(pack_begin) : 0;
#ifdef GBP_SELECTED_LSN_MISMATCH_TRACE
    if (mismatch_log_limit > 0 && !mismatches.empty()) {
        const size_t log_n = std::min(mismatches.size(), static_cast<size_t>(mismatch_log_limit));
        for (size_t i = 0; i < log_n; ++i) {
            const SelectedMismatch& mm = mismatches[i];
            page_id_t pid{};
            std::memcpy(&pid, &mm.pid_key, sizeof(pid));
            gbp_run_log("[selected-lsn-mismatch] peer=" + peer + " " +
                        format_page_id(pid.file, pid.page) + " block_lsn=" + std::to_string(mm.block_lsn) +
                        " meta_lsn=" + std::to_string(mm.meta_lsn) + " selected_lsn=" +
                        std::to_string(mm.selected_lsn) + " selected_mismatch=" +
                        std::to_string(static_cast<int>(mm.selected_mismatch)) + " meta_mismatch=" +
                        std::to_string(static_cast<int>(mm.meta_mismatch)));
        }
        if (mismatches.size() > log_n) {
            gbp_run_log("[selected-lsn-mismatch] peer=" + peer + " queue=" + std::to_string(req.queue_id) +
                        " batch_more=" + std::to_string(mismatches.size() - log_n) +
                        " batch_total=" + std::to_string(mismatches.size()) +
                        " selected_mismatch=" + std::to_string(selected_mismatch_count) +
                        " meta_mismatch=" + std::to_string(meta_mismatch_count) +
                        " log_limit=" + std::to_string(mismatch_log_limit));
        }
    }
#endif
    if (!misses.empty()) {
        std::ostringstream sample;
        for (size_t i = 0; i < std::min(misses.size(), size_t{3}); ++i) {
            page_id_t pid{};
            std::memcpy(&pid, &misses[i], sizeof(pid));
            if (i > 0) sample << ",";
            sample << format_page_id(pid.file, pid.page);
        }
        gbp_run_log("BATCH_PAGE_READ_SELECTED peer=" + peer + " queue=" + std::to_string(req.queue_id) +
                    " requested=" + std::to_string(req_count) + " sent=" + std::to_string(count) +
                    " missing=" + std::to_string(misses.size()) + " sample=[" + sample.str() + "]");
    }
    const auto send_begin = timing_diag ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    send_full_or_disconnect(fd, &resp, sizeof(resp), "BATCH_PAGE_READ_SELECTED");
    const int64_t send_us = timing_diag ? us_since(send_begin) : 0;
    if (timing_diag) {
        const int64_t total_us = us_since(batch_begin);
        state.selected_read_diag().record(qid, resp.result, static_cast<int>(req_count), count,
                                          static_cast<int>(misses.size()), selected_mismatch_count,
                                          meta_mismatch_count, total_us, lock_wait_us, lookup_us, pack_us, send_us);
    } else {
        state.selected_read_diag().record_counts(qid, resp.result, static_cast<int>(req_count), count,
                                               static_cast<int>(misses.size()), selected_mismatch_count,
                                               meta_mismatch_count);
    }
    if (verbose && timing_diag) {
        gbp_run_log("BATCH_PAGE_READ_SELECTED peer=" + peer + " requested=" + std::to_string(req_count) +
                    " sent=" + std::to_string(count) + " lock_wait_us=" + std::to_string(lock_wait_us) +
                    " lookup_us=" + std::to_string(lookup_us) + " pack_us=" + std::to_string(pack_us) +
                    " send_us=" + std::to_string(send_us));
    }
}

}  // namespace gbp
