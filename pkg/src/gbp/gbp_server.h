#pragma once

#include "gbp_std_compat.h"
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
    bool ending = false;
};

struct ReadPhaseSnapshot {
    bool active = false;
    bool ending = false;
    double elapsed_s = 0.0;
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

void run_server(const std::string& host, int port, const Config& cfg, int admin_port, const std::string& admin_host);
void handle_conn(socket_t fd, const std::string& peer, GbpServerState& state, ReadPhase& read_phase, const Config& cfg);
ReadPhaseSnapshot get_read_phase_snapshot(ReadPhase& read_phase);
ReadPhaseEndResult force_read_phase_end(GbpServerState& state, ReadPhase& read_phase, const Config& cfg,
                                        const std::string& peer, const char* reason);
void admin_server_loop(const std::string& host, int port, GbpServerState& state, ReadPhase& read_phase,
                       const Config& cfg);
bool admin_query_once(const std::string& host, int port, const std::string& command,
                      std::string& response, std::string& err);

}  // namespace gbp
