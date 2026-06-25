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
 * rbp_config.h
 *
 *
 * IDENTIFICATION
 * src/rbp/rbp_config.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef RBP_CONFIG_H
#define RBP_CONFIG_H

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>

namespace rbp {

enum class ReadEndMode { Async, Sync };

struct Config {
    bool verbose = false;
    bool log_cmp_lsn_only = false;
    bool smb_version = true;
    bool legacy_batch_pending = true;
    bool ckpt_wait_evict = false;
    bool ckpt_parity_check = false;
    int max_cache_pages = 0;
    bool capacity_evict_on_write = false;
    int ckpt_wait_ms = 5000;
    int rcy_diag_lag = 0;
    int evict_sample_log = 20;
    int evict_budget = 4096;
    int purge_budget = 8192;
    // Deprecated: LfnBucketIndex no longer uses fixed buckets; kept for CLI/env compatibility.
    int bucket_count = 4096;
    int bucket_span = 1024;
    int page_write_slow_us = 0;
    int page_write_timing_us = 500000;
    int selected_lsn_mismatch_log = 20;
    double read_phase_timeout = 3.0;
    double cache_high_water = 0.95;
    double cache_evict_ratio = 0.10;
    ReadEndMode read_end_mode = ReadEndMode::Async;
    bool timing_diag = false;
};

struct ServerOptions {
    std::string host = "0.0.0.0";
    int port = 2611;
    std::string admin_host = "127.0.0.1";
    int admin_port = 2711;
    std::string log_file;
    std::string pid_file;
    Config config;
};

struct CliOverrides {
    bool config_path_set = false;
    std::string config_path;
    bool host_set = false;
    std::string host;
    bool port_set = false;
    int port = 0;
    bool admin_host_set = false;
    std::string admin_host;
    bool admin_port_set = false;
    int admin_port = 0;
    bool log_file_set = false;
    std::string log_file;
    bool pid_file_set = false;
    std::string pid_file;
    bool verbose_set = false;
    bool verbose = false;
    bool log_cmp_lsn_set = false;
    bool log_cmp_lsn = false;
    bool smb_version_set = false;
    bool smb_version = true;
    bool max_cache_pages_set = false;
    int max_cache_pages = 0;
    bool capacity_evict_on_write_set = false;
    bool capacity_evict_on_write = false;
    bool admin_query_set = false;
    std::string admin_query;
};

std::string default_config_path();
bool build_server_options(const CliOverrides& cli, ServerOptions& out, std::string& err);

inline bool str_ieq(const char* a, const char* b)
{
    if (!a || !b) {
        return false;
    }
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) != std::tolower(static_cast<unsigned char>(*b))) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

inline bool env_truthy(const char* v)
{
    if (!v || !*v) {
        return false;
    }
    return std::strcmp(v, "1") == 0 || str_ieq(v, "true") || str_ieq(v, "yes") || str_ieq(v, "on");
}

inline bool env_falsy(const char* v)
{
    if (!v || !*v) {
        return false;
    }
    return std::strcmp(v, "0") == 0 || str_ieq(v, "false") || str_ieq(v, "no") || str_ieq(v, "off");
}

inline int env_int(const char* name, int def)
{
    const char* v = std::getenv(name);
    if (!v || !*v) {
        return def;
    }
    try {
        return std::max(0, std::stoi(v));
    } catch (...) {
        return def;
    }
}

inline double env_double(const char* name, double def)
{
    const char* v = std::getenv(name);
    if (!v || !*v) {
        return def;
    }
    try {
        return std::stod(v);
    } catch (...) {
        return def;
    }
}

}  // namespace rbp

#endif  // RBP_CONFIG_H
