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
 * rbp_protocol.h
 *
 *
 * IDENTIFICATION
 * src/rbp/rbp_protocol.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef RBP_PROTOCOL_H
#define RBP_PROTOCOL_H

#include "rbp_wire.h"
#include "rbp_state.h"

#include <array>
#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

namespace rbp {

struct ConnMeta {
    std::vector<MetaSnapshotRow> snapshot;
    uint64_t epoch = 0;
    uint64_t connection_id = 0;
    uint64_t guard_generation = 0;
    uint64_t page_write_generation = 0;
    bool snapshot_built = false;
    bool read_phase_owner = false;
    bool guard_required = false;
    bool page_write_stream = false;
    bool page_write_reset_seen = false;
};

struct PageWriteResult {
    int accepted = 0;
    int rejected = 0;
    int capacity_rejected = 0;
    int pages_off = -1;
    bool reset_applied = false;
    int64_t lock_wait_us = 0;
    int64_t lock_hold_us = 0;
    int64_t plan_hold_us = 0;
    int64_t payload_us = 0;
    int64_t apply_hold_us = 0;
};

struct DiskGuardRequest {
    socket_t fd;
    const rbp_msg_hdr_t& req;
    const uint8_t* body;
    size_t body_len;
    RbpServerState& state;
    uint64_t owner_id;
    uint64_t generation;
    const std::string& peer;
};

PageWriteResult cache_pages_from_write(const uint8_t* body, size_t body_len, RbpServerState& state,
                                       uint32_t conn_qid, bool verbose, const std::string& peer);

void send_cs_ready_ack(socket_t fd);
void send_ack(socket_t fd, const rbp_msg_hdr_t& req, uint32_t ack_type, uint32_t ack_data = 0);
void send_shake_resp(socket_t fd, const rbp_msg_hdr_t& req, uint32_t queue_id, uint32_t is_temp,
                     uint32_t wire_version);
void send_read_ckpt_resp(socket_t fd, const rbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                         RbpServerState& state, bool verbose, const std::string& peer);
void send_page_read_resp(socket_t fd, const rbp_msg_hdr_t& req, const page_id_t& page_id, bool hit,
                         const log_point_t& trunc, const char* block, uint64_t guard_lsn, uint32_t guard_pcn);
void send_batch_read_resp(socket_t fd, const rbp_msg_hdr_t& req, const log_point_t& skip_point, uint32_t conn_qid,
                          RbpServerState& state, bool verbose, const std::string& peer, bool read_phase_active);
void send_meta_chunk_resp(socket_t fd, const rbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                          RbpServerState& state, ConnMeta& conn_meta, bool verbose, const std::string& peer);
void send_batch_selected_read_resp(socket_t fd, const rbp_msg_hdr_t& req, const uint8_t* body, size_t body_len,
                                   RbpServerState& state, bool verbose, const std::string& peer,
                                   uint32_t conn_qid);
void handle_disk_guard_req(const DiskGuardRequest& request);

}  // namespace rbp

#endif  // RBP_PROTOCOL_H
