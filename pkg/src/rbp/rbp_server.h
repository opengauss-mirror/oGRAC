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
 * rbp_server.h
 *
 *
 * IDENTIFICATION
 * src/rbp/rbp_server.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef RBP_SERVER_H
#define RBP_SERVER_H

#include "rbp_std_compat.h"
#include "rbp_protocol.h"
#include "rbp_state.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

namespace rbp {

struct ReadPhase {
    std::mutex mtx;
    std::condition_variable cv;
    bool active = false;
    double started_at = 0.0;
    double last_activity_at = 0.0;
    int inflight_reads = 0;
    int dropped_page_writes = 0;
    bool timeout_warned = false;
    bool ending = false;
};

struct ReadPhaseSnapshot {
    bool active = false;
    bool ending = false;
    double elapsed_s = 0.0;
    double idle_s = 0.0;
    int inflight_reads = 0;
    int dropped_page_writes = 0;
    bool timeout_warned = false;
};

struct ReadPhaseEndResult {
    bool active_before = false;
    bool ending_before = false;
    bool cleared = false;
    double elapsed_s = 0.0;
    int dropped_page_writes = 0;
    int detached_pages = 0;
};

struct AdminServerLoopContext {
    socket_t srv;
    std::string host;
    int port;
    RbpServerState& state;
    ReadPhase& read_phase;
    Config cfg;
};

void run_server(const std::string& host, int port, const Config& cfg, int admin_port, const std::string& admin_host);
void handle_conn(socket_t fd, const std::string& peer, RbpServerState& state, ReadPhase& read_phase, const Config& cfg);
ReadPhaseSnapshot get_read_phase_snapshot(ReadPhase& read_phase);
ReadPhaseEndResult force_read_phase_end(RbpServerState& state, ReadPhase& read_phase, const Config& cfg,
                                        const std::string& peer, const char* reason);
bool setup_admin_server(const std::string& host, int port, socket_t& srv, std::string& err);
void admin_server_loop(AdminServerLoopContext ctx);
bool admin_query_once(const std::string& host, int port, const std::string& command,
                      std::string& response, std::string& err);

}  // namespace rbp

#endif  // RBP_SERVER_H
