#pragma once

#include "gbp_protocol.h"
#include "gbp_state.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

namespace gbp {

struct ReadPhase {
    std::mutex mtx;
    std::condition_variable cv;
    bool active = false;
    double started_at = 0.0;
    int dropped_page_writes = 0;
    bool timeout_warned = false;
};

void run_server(const std::string& host, int port, const Config& cfg, int admin_port, const std::string& admin_host);
void handle_conn(socket_t fd, const std::string& peer, GbpServerState& state, ReadPhase& read_phase, const Config& cfg);
void admin_server_loop(const std::string& host, int port, GbpServerState& state);
bool admin_query_once(const std::string& host, int port, const std::string& command,
                      std::string& response, std::string& err);

}  // namespace gbp
