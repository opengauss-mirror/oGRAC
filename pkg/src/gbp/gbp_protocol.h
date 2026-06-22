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
 * gbp_protocol.h
 *
 *
 * IDENTIFICATION
 * src/gbp/gbp_protocol.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef GBP_PROTOCOL_H
#define GBP_PROTOCOL_H

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

#endif  // GBP_PROTOCOL_H
