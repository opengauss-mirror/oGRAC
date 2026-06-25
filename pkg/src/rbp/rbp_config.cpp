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
 * rbp_config.cpp
 *
 *
 * IDENTIFICATION
 * src/rbp/rbp_config.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "rbp_config.h"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>

namespace rbp {

namespace {

constexpr int RBP_MIN_BUCKET_COUNT = 16;
constexpr int RBP_MAX_TCP_PORT = 65535;

std::string trim(const std::string& s)
{
    size_t begin = 0;
    while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) {
        begin++;
    }
    size_t end = s.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        end--;
    }
    return s.substr(begin, end - begin);
}

std::string upper_key(std::string s)
{
    for (char& ch : s) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return s;
}

bool file_exists(const std::string& path)
{
    if (path.empty()) {
        return false;
    }
    std::ifstream in(path);
    return in.good();
}

std::string expand_env_vars(const std::string& value)
{
    std::string out;
    for (size_t i = 0; i < value.size();) {
        if (value[i] != '$') {
            out.push_back(value[i++]);
            continue;
        }
        size_t name_begin = i + 1;
        size_t name_end = name_begin;
        bool braced = false;
        if (name_begin < value.size() && value[name_begin] == '{') {
            braced = true;
            name_begin++;
            name_end = name_begin;
            while (name_end < value.size() && value[name_end] != '}') {
                name_end++;
            }
        } else {
            while (name_end < value.size() &&
                   (std::isalnum(static_cast<unsigned char>(value[name_end])) || value[name_end] == '_')) {
                name_end++;
            }
        }
        if (name_end == name_begin || (braced && name_end >= value.size())) {
            out.push_back(value[i++]);
            continue;
        }
        std::string name = value.substr(name_begin, name_end - name_begin);
        const char* env = std::getenv(name.c_str());
        if (env != nullptr) {
            out += env;
        }
        i = braced ? name_end + 1 : name_end;
    }
    return out;
}

bool parse_int_value(const std::string& text, int& out, std::string& err, const std::string& key)
{
    try {
        size_t pos = 0;
        int value = std::stoi(text, &pos);
        if (pos != text.size() || value < 0) {
            err = "invalid integer for " + key + ": " + text;
            return false;
        }
        out = value;
        return true;
    } catch (...) {
        err = "invalid integer for " + key + ": " + text;
        return false;
    }
}

bool parse_double_value(const std::string& text, double& out, std::string& err, const std::string& key)
{
    try {
        size_t pos = 0;
        double value = std::stod(text, &pos);
        if (pos != text.size() || value < 0) {
            err = "invalid number for " + key + ": " + text;
            return false;
        }
        out = value;
        return true;
    } catch (...) {
        err = "invalid number for " + key + ": " + text;
        return false;
    }
}

bool parse_bool_value(const std::string& text, bool& out, std::string& err, const std::string& key)
{
    if (env_truthy(text.c_str())) {
        out = true;
        return true;
    }
    if (env_falsy(text.c_str())) {
        out = false;
        return true;
    }
    err = "invalid boolean for " + key + ": " + text;
    return false;
}

bool load_config_file(const std::string& path, std::map<std::string, std::string>& kv, std::string& err)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        err = "failed to open config file: " + path;
        return false;
    }
    std::string line;
    uint32_t line_no = 0;
    while (std::getline(in, line)) {
        line_no++;
        std::string text = trim(line);
        if (text.empty() || text[0] == '#') {
            continue;
        }
        size_t eq = text.find('=');
        if (eq == std::string::npos) {
            err = path + ":" + std::to_string(line_no) + ": expected KEY=VALUE";
            return false;
        }
        std::string key = upper_key(trim(text.substr(0, eq)));
        std::string value = trim(text.substr(eq + 1));
        if (key.empty()) {
            err = path + ":" + std::to_string(line_no) + ": empty key";
            return false;
        }
        kv[key] = expand_env_vars(value);
    }
    return true;
}

bool apply_kv(ServerOptions& opt, const std::string& key, const std::string& value, std::string& err)
{
    Config& c = opt.config;
    if (key == "HOST") {
        opt.host = value;
    } else if (key == "PORT") {
        return parse_int_value(value, opt.port, err, key);
    } else if (key == "ADMIN_HOST") {
        opt.admin_host = value;
    } else if (key == "ADMIN_PORT") {
        return parse_int_value(value, opt.admin_port, err, key);
    } else if (key == "LOG_FILE") {
        opt.log_file = value;
    } else if (key == "PID_FILE") {
        opt.pid_file = value;
    } else if (key == "MAX_CACHE_PAGES") {
        return parse_int_value(value, c.max_cache_pages, err, key);
    } else if (key == "CAPACITY_EVICT_ON_WRITE") {
        return parse_bool_value(value, c.capacity_evict_on_write, err, key);
    } else if (key == "READ_END_MODE") {
        if (str_ieq(value.c_str(), "sync")) {
            c.read_end_mode = ReadEndMode::Sync;
        } else if (str_ieq(value.c_str(), "async")) {
            c.read_end_mode = ReadEndMode::Async;
        } else {
            err = "invalid READ_END_MODE: " + value;
            return false;
        }
    } else if (key == "READ_PHASE_TIMEOUT") {
        return parse_double_value(value, c.read_phase_timeout, err, key);
    } else if (key == "VERBOSE") {
        return parse_bool_value(value, c.verbose, err, key);
    } else if (key == "TIMING_DIAG") {
        return parse_bool_value(value, c.timing_diag, err, key);
    } else if (key == "LOG_CMP_LSN_ONLY") {
        return parse_bool_value(value, c.log_cmp_lsn_only, err, key);
    } else if (key == "SMB_VERSION") {
        return parse_bool_value(value, c.smb_version, err, key);
    } else if (key == "LEGACY_BATCH_PENDING") {
        return parse_bool_value(value, c.legacy_batch_pending, err, key);
    } else if (key == "CKPT_WAIT_EVICT") {
        return parse_bool_value(value, c.ckpt_wait_evict, err, key);
    } else if (key == "CKPT_PARITY_CHECK") {
        return parse_bool_value(value, c.ckpt_parity_check, err, key);
    } else if (key == "CKPT_WAIT_MS") {
        return parse_int_value(value, c.ckpt_wait_ms, err, key);
    } else if (key == "RCY_DIAG_LAG") {
        return parse_int_value(value, c.rcy_diag_lag, err, key);
    } else if (key == "EVICT_SAMPLE_LOG") {
        return parse_int_value(value, c.evict_sample_log, err, key);
    } else if (key == "EVICT_BUDGET") {
        return parse_int_value(value, c.evict_budget, err, key);
    } else if (key == "PURGE_BUDGET") {
        return parse_int_value(value, c.purge_budget, err, key);
    } else if (key == "BUCKET_COUNT") {
        return parse_int_value(value, c.bucket_count, err, key);
    } else if (key == "BUCKET_SPAN") {
        return parse_int_value(value, c.bucket_span, err, key);
    } else if (key == "PAGE_WRITE_SLOW_US") {
        return parse_int_value(value, c.page_write_slow_us, err, key);
    } else if (key == "PAGE_WRITE_TIMING_US") {
        return parse_int_value(value, c.page_write_timing_us, err, key);
    } else if (key == "SELECTED_LSN_MISMATCH_LOG") {
        return parse_int_value(value, c.selected_lsn_mismatch_log, err, key);
    } else if (key == "CACHE_HIGH_WATER") {
        return parse_double_value(value, c.cache_high_water, err, key);
    } else if (key == "CACHE_EVICT_RATIO") {
        return parse_double_value(value, c.cache_evict_ratio, err, key);
    } else {
        err = "unknown config key: " + key;
        return false;
    }
    return true;
}

void apply_env(ServerOptions& opt)
{
    Config& c = opt.config;
    const char* v = nullptr;
    if ((v = std::getenv("RBPS_HOST")) != nullptr && *v) {
        opt.host = v;
    }
    if ((v = std::getenv("RBPS_PORT")) != nullptr && *v) {
        opt.port = env_int("RBPS_PORT", opt.port);
    }
    if ((v = std::getenv("RBPS_ADMIN_HOST")) != nullptr && *v) {
        opt.admin_host = v;
    }
    if ((v = std::getenv("RBPS_ADMIN_PORT")) != nullptr && *v) {
        opt.admin_port = env_int("RBPS_ADMIN_PORT", opt.admin_port);
    }
    if ((v = std::getenv("RBPS_LOG_FILE")) != nullptr) {
        opt.log_file = expand_env_vars(v);
    }
    if ((v = std::getenv("RBPS_PID_FILE")) != nullptr) {
        opt.pid_file = expand_env_vars(v);
    }

    if ((v = std::getenv("RBPS_VERBOSE")) != nullptr) {
        c.verbose = env_truthy(v);
    }
    if ((v = std::getenv("RBPS_TIMING_DIAG")) != nullptr) {
        c.timing_diag = env_truthy(v);
    }
    if ((v = std::getenv("RBPS_LOG_CMP_LSN_ONLY")) != nullptr) {
        c.log_cmp_lsn_only = env_truthy(v);
    }
    if ((v = std::getenv("RBPS_SMB_VERSION")) != nullptr) {
        c.smb_version = !env_falsy(v);
    }
    if ((v = std::getenv("RBPS_MAX_CACHE_PAGES")) != nullptr && *v) {
        c.max_cache_pages = env_int("RBPS_MAX_CACHE_PAGES", c.max_cache_pages);
    }
    if ((v = std::getenv("RBPS_CAPACITY_EVICT_ON_WRITE")) != nullptr) {
        c.capacity_evict_on_write = env_truthy(v);
    }
    if ((v = std::getenv("RBPS_READ_END_MODE")) != nullptr) {
        if (str_ieq(v, "sync")) {
            c.read_end_mode = ReadEndMode::Sync;
        }
        if (str_ieq(v, "async")) {
            c.read_end_mode = ReadEndMode::Async;
        }
    }
    if ((v = std::getenv("RBPS_READ_PHASE_TIMEOUT")) != nullptr && *v) {
        c.read_phase_timeout = env_double("RBPS_READ_PHASE_TIMEOUT", c.read_phase_timeout);
    }

    if ((v = std::getenv("RBP_DEMO_LOG_CMP_LSN_ONLY")) != nullptr) {
        c.log_cmp_lsn_only = env_truthy(v);
    }
    if ((v = std::getenv("RBP_DEMO_SMB_VERSION")) != nullptr) {
        c.smb_version = !env_falsy(v);
    }
    if ((v = std::getenv("RBP_DEMO_MAX_CACHE_PAGES")) != nullptr && *v) {
        c.max_cache_pages = env_int("RBP_DEMO_MAX_CACHE_PAGES", c.max_cache_pages);
    }
    if ((v = std::getenv("RBP_DEMO_CAPACITY_EVICT_ON_WRITE")) != nullptr) {
        c.capacity_evict_on_write = env_truthy(v);
    }
    if ((v = std::getenv("RBP_DEMO_LEGACY_BATCH_PENDING")) != nullptr) {
        c.legacy_batch_pending = !env_falsy(v);
    }
    if ((v = std::getenv("RBP_DEMO_CKPT_WAIT_EVICT")) != nullptr) {
        c.ckpt_wait_evict = env_truthy(v);
    }
    if ((v = std::getenv("RBP_DEMO_CKPT_PARITY_CHECK")) != nullptr) {
        c.ckpt_parity_check = env_truthy(v);
    }
    c.ckpt_wait_ms = env_int("RBP_DEMO_CKPT_WAIT_MS", c.ckpt_wait_ms);
    c.rcy_diag_lag = env_int("RBP_DEMO_RCY_DIAG_LAG", c.rcy_diag_lag);
    c.evict_sample_log = env_int("RBP_DEMO_EVICT_SAMPLE_LOG", c.evict_sample_log);
    c.evict_budget = std::max(1, env_int("RBP_DEMO_EVICT_BUDGET", c.evict_budget));
    c.purge_budget = std::max(1, env_int("RBP_DEMO_PURGE_BUDGET", c.purge_budget));
    c.bucket_count = std::max(RBP_MIN_BUCKET_COUNT, env_int("RBP_DEMO_BUCKET_COUNT", c.bucket_count));
    c.bucket_span = std::max(1, env_int("RBP_DEMO_BUCKET_SPAN", c.bucket_span));
    c.page_write_slow_us = env_int("RBP_DEMO_PAGE_WRITE_SLOW_US", c.page_write_slow_us);
    c.page_write_timing_us = env_int("RBP_DEMO_PAGE_WRITE_TIMING_US", c.page_write_timing_us);
    c.selected_lsn_mismatch_log = env_int("RBP_DEMO_SELECTED_LSN_MISMATCH_LOG", c.selected_lsn_mismatch_log);
    c.read_phase_timeout = env_double("RBP_DEMO_READ_PHASE_TIMEOUT", c.read_phase_timeout);
    c.cache_high_water = std::min(1.0, std::max(0.0, env_double("RBP_DEMO_CACHE_HIGH_WATER", c.cache_high_water)));
    c.cache_evict_ratio = std::min(1.0, std::max(0.0, env_double("RBP_DEMO_CACHE_EVICT_RATIO", c.cache_evict_ratio)));
    if ((v = std::getenv("RBP_DEMO_READ_END_MODE")) != nullptr) {
        if (str_ieq(v, "sync")) {
            c.read_end_mode = ReadEndMode::Sync;
        }
        if (str_ieq(v, "async")) {
            c.read_end_mode = ReadEndMode::Async;
        }
    }
    if ((v = std::getenv("RBP_DEMO_TIMING_DIAG")) != nullptr) {
        c.timing_diag = env_truthy(v);
    }
}

void apply_cli(const CliOverrides& cli, ServerOptions& opt)
{
    if (cli.host_set) {
        opt.host = cli.host;
    }
    if (cli.port_set) {
        opt.port = cli.port;
    }
    if (cli.admin_host_set) {
        opt.admin_host = cli.admin_host;
    }
    if (cli.admin_port_set) {
        opt.admin_port = cli.admin_port;
    }
    if (cli.log_file_set) {
        opt.log_file = expand_env_vars(cli.log_file);
    }
    if (cli.pid_file_set) {
        opt.pid_file = expand_env_vars(cli.pid_file);
    }
    if (cli.verbose_set) {
        opt.config.verbose = cli.verbose;
    }
    if (cli.log_cmp_lsn_set) {
        opt.config.log_cmp_lsn_only = cli.log_cmp_lsn;
    }
    if (cli.smb_version_set) {
        opt.config.smb_version = cli.smb_version;
    }
    if (cli.max_cache_pages_set) {
        opt.config.max_cache_pages = cli.max_cache_pages;
    }
    if (cli.capacity_evict_on_write_set) {
        opt.config.capacity_evict_on_write = cli.capacity_evict_on_write;
    }
}

}  // namespace

std::string default_config_path()
{
    const char* data = std::getenv("OGDB_DATA");
    if (data != nullptr && *data != '\0') {
        std::string data_config = std::string(data) + "/cfg/rbps.conf";
        if (file_exists(data_config)) {
            return data_config;
        }
    }
    const char* home = std::getenv("OGDB_HOME");
    if (home != nullptr && *home != '\0') {
        return std::string(home) + "/cfg/rbps.conf";
    }
    if (data != nullptr && *data != '\0') {
        return std::string(data) + "/cfg/rbps.conf";
    }
    return "";
}

bool build_server_options(const CliOverrides& cli, ServerOptions& out, std::string& err)
{
    out = ServerOptions{};
    std::string config_path = cli.config_path_set ? cli.config_path : default_config_path();
    if (!config_path.empty()) {
        if (!file_exists(config_path)) {
            if (cli.config_path_set) {
                err = "config file does not exist: " + config_path;
                return false;
            }
        } else {
            std::map<std::string, std::string> kv;
            if (!load_config_file(config_path, kv, err)) {
                return false;
            }
            for (const auto& entry : kv) {
                if (!apply_kv(out, entry.first, entry.second, err)) {
                    return false;
                }
            }
        }
    }
    apply_env(out);
    apply_cli(cli, out);
    out.config.cache_high_water = std::min(1.0, std::max(0.0, out.config.cache_high_water));
    out.config.cache_evict_ratio = std::min(1.0, std::max(0.0, out.config.cache_evict_ratio));
    out.config.evict_budget = std::max(1, out.config.evict_budget);
    out.config.purge_budget = std::max(1, out.config.purge_budget);
    if (out.port <= 0 || out.port > RBP_MAX_TCP_PORT) {
        err = "PORT must be in range 1..65535";
        return false;
    }
    if (out.admin_port < 0 || out.admin_port > RBP_MAX_TCP_PORT) {
        err = "ADMIN_PORT must be in range 0..65535";
        return false;
    }
    return true;
}

}  // namespace rbp
