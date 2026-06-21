#pragma once

#include "gbp_wire.h"
#include "gbp_state.h"

#include <array>
#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

namespace gbp {

struct ConnMeta {
    std::vector<MetaSnapshotRow> snapshot;
    uint64_t epoch = 0;
    bool snapshot_built = false;
};

struct PageWriteResult {
    int accepted = 0;
    int rejected = 0;
    int capacity_rejected = 0;
    int pages_off = -1;
    int64_t lock_wait_us = 0;
    int64_t lock_hold_us = 0;
    int64_t plan_hold_us = 0;
    int64_t payload_us = 0;
    int64_t apply_hold_us = 0;
};

PageWriteResult cache_pages_from_write(const uint8_t* body, size_t body_len, GbpServerState& state,
                                       uint32_t conn_qid, bool verbose, const std::string& peer);

void send_cs_ready_ack(socket_t fd);
void send_ack(socket_t fd, const gbp_msg_hdr_t& req, uint32_t ack_type, uint32_t ack_data = 0);
void send_shake_resp(socket_t fd, const gbp_msg_hdr_t& req, uint32_t queue_id, uint32_t is_temp);
void send_read_ckpt_resp(socket_t fd, const gbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                         GbpServerState& state, bool verbose, const std::string& peer);
void send_page_read_resp(socket_t fd, const gbp_msg_hdr_t& req, const page_id_t& page_id, bool hit,
                         const log_point_t& trunc, const char* block);
void send_batch_read_resp(socket_t fd, const gbp_msg_hdr_t& req, const log_point_t& skip_point, uint32_t conn_qid,
                          GbpServerState& state, bool verbose, const std::string& peer, bool read_phase_active);
void send_meta_chunk_resp(socket_t fd, const gbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                          GbpServerState& state, ConnMeta& conn_meta, bool verbose, const std::string& peer);
void send_batch_selected_read_resp(socket_t fd, const gbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                                   GbpServerState& state, bool verbose, const std::string& peer,
                                   uint32_t conn_qid);

}  // namespace gbp
