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
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>

namespace rbp {

namespace {

constexpr int RBP_MIN_TCP_PORT = 1024;
constexpr int RBP_MAX_TCP_PORT = 65535;
constexpr int RBP_IPV4_PART_COUNT = 4;
constexpr int RBP_IPV4_RADIX = 10;
constexpr int RBP_IPV4_OCTET_MAX = 255;

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
        long long value = std::stoll(text, &pos);
        if (pos != text.size() || value < 0 || value > std::numeric_limits<int>::max()) {
            err = "invalid integer for " + key + ": " + text;
            return false;
        }
        out = static_cast<int>(value);
        return true;
    } catch (...) {
        err = "invalid integer for " + key + ": " + text;
        return false;
    }
}

bool parse_positive_int_value(const std::string& text, int& out, std::string& err, const std::string& key)
{
    if (!parse_int_value(text, out, err, key)) {
        return false;
    }
    if (out < 1) {
        err = key + " must be >= 1";
        return false;
    }
    return true;
}

bool parse_double_value(const std::string& text, double& out, std::string& err, const std::string& key)
{
    try {
        size_t pos = 0;
        double value = std::stod(text, &pos);
        if (pos != text.size() || !std::isfinite(value) || value < 0) {
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
    const std::string value = trim(text);
    if (env_truthy(value.c_str())) {
        out = true;
        return true;
    }
    if (env_falsy(value.c_str())) {
        out = false;
        return true;
    }
    err = "invalid boolean for " + key + ": " + text + " (expected TRUE/FALSE/OFF/ON/0/1)";
    return false;
}

bool parse_env_int_value(const char* name, int& out, std::string& err)
{
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return true;
    }
    return parse_int_value(trim(value), out, err, name);
}

bool parse_env_positive_int_value(const char* name, int& out, std::string& err)
{
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return true;
    }
    return parse_positive_int_value(trim(value), out, err, name);
}

bool parse_env_double_value(const char* name, double& out, std::string& err)
{
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return true;
    }
    return parse_double_value(trim(value), out, err, name);
}

bool parse_ratio_value(const std::string& text, double& out, std::string& err, const std::string& key)
{
    if (!parse_double_value(text, out, err, key)) {
        return false;
    }
    if (out < 0.0 || out > 1.0) {
        err = key + " must be in range 0..1";
        return false;
    }
    return true;
}

bool parse_env_ratio_value(const char* name, double& out, std::string& err)
{
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return true;
    }
    return parse_ratio_value(trim(value), out, err, name);
}

bool parse_env_bool_value(const char* name, bool& out, std::string& err)
{
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return true;
    }
    return parse_bool_value(value, out, err, name);
}

bool parse_read_end_mode_value(const std::string& value, ReadEndMode& out, std::string& err)
{
    if (str_ieq(value.c_str(), "sync")) {
        out = ReadEndMode::Sync;
        return true;
    }
    if (str_ieq(value.c_str(), "async")) {
        out = ReadEndMode::Async;
        return true;
    }
    err = "invalid READ_END_MODE: " + value + " (expected sync or async)";
    return false;
}

bool parse_ipv4_literal(const std::string& value)
{
    if (value.empty()) {
        return false;
    }
    int parts = 0;
    size_t begin = 0;
    while (begin <= value.size()) {
        const size_t end = value.find('.', begin);
        const size_t part_end = (end == std::string::npos) ? value.size() : end;
        if (part_end == begin || ++parts > RBP_IPV4_PART_COUNT) {
            return false;
        }
        int octet = 0;
        for (size_t i = begin; i < part_end; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(value[i]))) {
                return false;
            }
            octet = octet * RBP_IPV4_RADIX + (value[i] - '0');
            if (octet > RBP_IPV4_OCTET_MAX) {
                return false;
            }
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    return parts == RBP_IPV4_PART_COUNT;
}

bool validate_port_value(const char* key, int port, bool allow_zero, std::string& err)
{
    if (allow_zero && port == 0) {
        return true;
    }
    if (port < RBP_MIN_TCP_PORT || port > RBP_MAX_TCP_PORT) {
        err = std::string(key) + (allow_zero ? " must be 0 or in range 1024..65535"
                                             : " must be in range 1024..65535");
        return false;
    }
    return true;
}

bool validate_endpoint_options(const ServerOptions& opt, std::string& err)
{
    if (!parse_ipv4_literal(opt.host)) {
        err = "HOST must be an IPv4 address literal: " + opt.host;
        return false;
    }
    if (!validate_port_value("PORT", opt.port, false, err)) {
        return false;
    }
    if (!parse_ipv4_literal(opt.admin_host)) {
        err = "ADMIN_HOST must be an IPv4 address literal: " + opt.admin_host;
        return false;
    }
    if (!validate_port_value("ADMIN_PORT", opt.admin_port, true, err)) {
        return false;
    }
    if (opt.admin_port != 0 && opt.port == opt.admin_port) {
        err = "PORT and ADMIN_PORT must not use the same port: " + std::to_string(opt.port);
        return false;
    }
    return true;
}

bool validate_path_options(const ServerOptions& opt, std::string& err)
{
    if (opt.log_file_set && opt.log_file.empty()) {
        err = "LOG_FILE is empty";
        return false;
    }
    if (opt.pid_file_set && opt.pid_file.empty()) {
        err = "PID_FILE is empty";
        return false;
    }
    return true;
}

bool validate_cache_options(const Config& cfg, std::string& err)
{
    if (cfg.max_cache_pages < 0) {
        err = "MAX_CACHE_PAGES must be >= 0";
        return false;
    }
    if (!std::isfinite(cfg.read_phase_timeout) || cfg.read_phase_timeout < 0.0) {
        err = "READ_PHASE_TIMEOUT must be a finite non-negative number";
        return false;
    }
    if (cfg.cache_high_water < 0.0 || cfg.cache_high_water > 1.0) {
        err = "CACHE_HIGH_WATER must be in range 0..1";
        return false;
    }
    if (cfg.cache_evict_ratio < 0.0 || cfg.cache_evict_ratio > 1.0) {
        err = "CACHE_EVICT_RATIO must be in range 0..1";
        return false;
    }
    if (cfg.capacity_evict_on_write && cfg.max_cache_pages > 0 && cfg.cache_evict_ratio <= 0.0) {
        err = "CACHE_EVICT_RATIO must be > 0 when CAPACITY_EVICT_ON_WRITE=true and MAX_CACHE_PAGES>0";
        return false;
    }
    return true;
}

bool validate_budget_options(const Config& cfg, std::string& err)
{
    if (cfg.evict_budget < 1) {
        err = "EVICT_BUDGET must be >= 1";
        return false;
    }
    if (cfg.purge_budget < 1) {
        err = "PURGE_BUDGET must be >= 1";
        return false;
    }
    return true;
}

bool validate_options(const ServerOptions& opt, std::string& err)
{
    return validate_endpoint_options(opt, err) &&
           validate_path_options(opt, err) &&
           validate_cache_options(opt.config, err) &&
           validate_budget_options(opt.config, err);
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

bool apply_server_kv(ServerOptions& opt, const std::string& key, const std::string& value, std::string& err,
                     bool& matched)
{
    matched = true;
    if (key == "HOST") {
        opt.host = value;
    } else if (key == "PORT") {
        return parse_int_value(value, opt.port, err, key);
    } else if (key == "ADMIN_HOST") {
        opt.admin_host = value;
    } else if (key == "ADMIN_PORT") {
        return parse_int_value(value, opt.admin_port, err, key);
    } else if (key == "LOG_FILE") {
        if (value.empty()) {
            err = "LOG_FILE is empty";
            return false;
        }
        opt.log_file = value;
        opt.log_file_set = true;
    } else if (key == "PID_FILE") {
        if (value.empty()) {
            err = "PID_FILE is empty";
            return false;
        }
        opt.pid_file = value;
        opt.pid_file_set = true;
    } else {
        matched = false;
    }
    return true;
}

bool apply_bool_kv(Config& cfg, const std::string& key, const std::string& value, std::string& err, bool& matched)
{
    matched = true;
    if (key == "CAPACITY_EVICT_ON_WRITE") {
        return parse_bool_value(value, cfg.capacity_evict_on_write, err, key);
    } else if (key == "VERBOSE") {
        return parse_bool_value(value, cfg.verbose, err, key);
    } else if (key == "TIMING_DIAG") {
        return parse_bool_value(value, cfg.timing_diag, err, key);
    } else if (key == "LOG_CMP_LSN_ONLY") {
        return parse_bool_value(value, cfg.log_cmp_lsn_only, err, key);
    } else if (key == "SMB_VERSION") {
        return parse_bool_value(value, cfg.smb_version, err, key);
    } else if (key == "LEGACY_BATCH_PENDING") {
        return parse_bool_value(value, cfg.legacy_batch_pending, err, key);
    } else if (key == "CKPT_WAIT_EVICT") {
        return parse_bool_value(value, cfg.ckpt_wait_evict, err, key);
    } else if (key == "CKPT_PARITY_CHECK") {
        return parse_bool_value(value, cfg.ckpt_parity_check, err, key);
    }
    matched = false;
    return true;
}

bool apply_basic_numeric_kv(Config& cfg, const std::string& key, const std::string& value, std::string& err,
                            bool& matched)
{
    matched = true;
    if (key == "MAX_CACHE_PAGES") {
        return parse_int_value(value, cfg.max_cache_pages, err, key);
    } else if (key == "READ_PHASE_TIMEOUT") {
        return parse_double_value(value, cfg.read_phase_timeout, err, key);
    } else if (key == "CKPT_WAIT_MS") {
        return parse_int_value(value, cfg.ckpt_wait_ms, err, key);
    } else if (key == "RCY_DIAG_LAG") {
        return parse_int_value(value, cfg.rcy_diag_lag, err, key);
    } else if (key == "EVICT_SAMPLE_LOG") {
        return parse_int_value(value, cfg.evict_sample_log, err, key);
    } else if (key == "EVICT_BUDGET") {
        return parse_positive_int_value(value, cfg.evict_budget, err, key);
    } else if (key == "PURGE_BUDGET") {
        return parse_positive_int_value(value, cfg.purge_budget, err, key);
    }
    matched = false;
    return true;
}

bool apply_cache_numeric_kv(Config& cfg, const std::string& key, const std::string& value, std::string& err,
                            bool& matched)
{
    matched = true;
    if (key == "BUCKET_COUNT") {
        std::cerr << "rbps: warning: BUCKET_COUNT is deprecated and ignored by current bucket logic\n";
        return parse_int_value(value, cfg.bucket_count, err, key);
    } else if (key == "BUCKET_SPAN") {
        std::cerr << "rbps: warning: BUCKET_SPAN is deprecated and ignored by current bucket logic\n";
        return parse_int_value(value, cfg.bucket_span, err, key);
    } else if (key == "PAGE_WRITE_SLOW_US") {
        return parse_int_value(value, cfg.page_write_slow_us, err, key);
    } else if (key == "PAGE_WRITE_TIMING_US") {
        return parse_int_value(value, cfg.page_write_timing_us, err, key);
    } else if (key == "SELECTED_LSN_MISMATCH_LOG") {
        return parse_int_value(value, cfg.selected_lsn_mismatch_log, err, key);
    } else if (key == "CACHE_HIGH_WATER") {
        return parse_ratio_value(value, cfg.cache_high_water, err, key);
    } else if (key == "CACHE_EVICT_RATIO") {
        return parse_ratio_value(value, cfg.cache_evict_ratio, err, key);
    }
    matched = false;
    return true;
}

bool apply_kv(ServerOptions& opt, const std::string& key, const std::string& value, std::string& err)
{
    bool matched = false;
    Config& cfg = opt.config;

    if (!apply_server_kv(opt, key, value, err, matched)) {
        return false;
    }
    if (matched) {
        return true;
    }
    if (key == "READ_END_MODE") {
        return parse_read_end_mode_value(value, cfg.read_end_mode, err);
    }
    if (!apply_bool_kv(cfg, key, value, err, matched)) {
        return false;
    }
    if (matched) {
        return true;
    }
    if (!apply_basic_numeric_kv(cfg, key, value, err, matched)) {
        return false;
    }
    if (matched) {
        return true;
    }
    if (!apply_cache_numeric_kv(cfg, key, value, err, matched)) {
        return false;
    }
    if (matched) {
        return true;
    }

    err = "unknown config key: " + key;
    return false;
}

bool apply_server_env(ServerOptions& opt, std::string& err)
{
    const char* v = nullptr;

    if ((v = std::getenv("RBPS_HOST")) != nullptr) {
        opt.host = v;
    }
    if (!parse_env_int_value("RBPS_PORT", opt.port, err)) {
        return false;
    }
    if ((v = std::getenv("RBPS_ADMIN_HOST")) != nullptr) {
        opt.admin_host = v;
    }
    if (!parse_env_int_value("RBPS_ADMIN_PORT", opt.admin_port, err)) {
        return false;
    }
    if ((v = std::getenv("RBPS_LOG_FILE")) != nullptr) {
        opt.log_file = expand_env_vars(v);
        opt.log_file_set = true;
    }
    if ((v = std::getenv("RBPS_PID_FILE")) != nullptr) {
        opt.pid_file = expand_env_vars(v);
        opt.pid_file_set = true;
    }
    return true;
}

bool apply_rbps_env(Config& c, std::string& err)
{
    const char* v = nullptr;
    if (!parse_env_bool_value("RBPS_VERBOSE", c.verbose, err) ||
        !parse_env_bool_value("RBPS_TIMING_DIAG", c.timing_diag, err) ||
        !parse_env_bool_value("RBPS_LOG_CMP_LSN_ONLY", c.log_cmp_lsn_only, err) ||
        !parse_env_bool_value("RBPS_SMB_VERSION", c.smb_version, err)) {
        return false;
    }
    if (!parse_env_int_value("RBPS_MAX_CACHE_PAGES", c.max_cache_pages, err)) {
        return false;
    }
    if (!parse_env_bool_value("RBPS_CAPACITY_EVICT_ON_WRITE", c.capacity_evict_on_write, err)) {
        return false;
    }
    if ((v = std::getenv("RBPS_READ_END_MODE")) != nullptr) {
        if (!parse_read_end_mode_value(trim(v), c.read_end_mode, err)) {
            return false;
        }
    }
    if (!parse_env_double_value("RBPS_READ_PHASE_TIMEOUT", c.read_phase_timeout, err)) {
        return false;
    }
    return true;
}

bool apply_demo_basic_env(Config& c, std::string& err)
{
    if (!parse_env_bool_value("RBP_DEMO_LOG_CMP_LSN_ONLY", c.log_cmp_lsn_only, err) ||
        !parse_env_bool_value("RBP_DEMO_SMB_VERSION", c.smb_version, err)) {
        return false;
    }
    if (!parse_env_int_value("RBP_DEMO_MAX_CACHE_PAGES", c.max_cache_pages, err)) {
        return false;
    }
    if (!parse_env_bool_value("RBP_DEMO_CAPACITY_EVICT_ON_WRITE", c.capacity_evict_on_write, err) ||
        !parse_env_bool_value("RBP_DEMO_LEGACY_BATCH_PENDING", c.legacy_batch_pending, err) ||
        !parse_env_bool_value("RBP_DEMO_CKPT_WAIT_EVICT", c.ckpt_wait_evict, err) ||
        !parse_env_bool_value("RBP_DEMO_CKPT_PARITY_CHECK", c.ckpt_parity_check, err)) {
        return false;
    }
    return true;
}

bool apply_demo_numeric_env(Config& c, std::string& err)
{
    if (!parse_env_int_value("RBP_DEMO_CKPT_WAIT_MS", c.ckpt_wait_ms, err) ||
        !parse_env_int_value("RBP_DEMO_RCY_DIAG_LAG", c.rcy_diag_lag, err) ||
        !parse_env_int_value("RBP_DEMO_EVICT_SAMPLE_LOG", c.evict_sample_log, err) ||
        !parse_env_positive_int_value("RBP_DEMO_EVICT_BUDGET", c.evict_budget, err) ||
        !parse_env_positive_int_value("RBP_DEMO_PURGE_BUDGET", c.purge_budget, err) ||
        !parse_env_int_value("RBP_DEMO_BUCKET_COUNT", c.bucket_count, err) ||
        !parse_env_int_value("RBP_DEMO_BUCKET_SPAN", c.bucket_span, err) ||
        !parse_env_int_value("RBP_DEMO_PAGE_WRITE_SLOW_US", c.page_write_slow_us, err) ||
        !parse_env_int_value("RBP_DEMO_PAGE_WRITE_TIMING_US", c.page_write_timing_us, err) ||
        !parse_env_int_value("RBP_DEMO_SELECTED_LSN_MISMATCH_LOG", c.selected_lsn_mismatch_log, err) ||
        !parse_env_double_value("RBP_DEMO_READ_PHASE_TIMEOUT", c.read_phase_timeout, err) ||
        !parse_env_ratio_value("RBP_DEMO_CACHE_HIGH_WATER", c.cache_high_water, err) ||
        !parse_env_ratio_value("RBP_DEMO_CACHE_EVICT_RATIO", c.cache_evict_ratio, err)) {
        return false;
    }
    return true;
}

bool apply_demo_misc_env(Config& c, std::string& err)
{
    const char* v = nullptr;

    if ((v = std::getenv("RBP_DEMO_READ_END_MODE")) != nullptr) {
        if (!parse_read_end_mode_value(trim(v), c.read_end_mode, err)) {
            return false;
        }
    }
    if (!parse_env_bool_value("RBP_DEMO_TIMING_DIAG", c.timing_diag, err)) {
        return false;
    }
    return true;
}

bool apply_env(ServerOptions& opt, std::string& err)
{
    Config& c = opt.config;

    return apply_server_env(opt, err) &&
           apply_rbps_env(c, err) &&
           apply_demo_basic_env(c, err) &&
           apply_demo_numeric_env(c, err) &&
           apply_demo_misc_env(c, err);
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
        opt.log_file_set = true;
    }
    if (cli.pid_file_set) {
        opt.pid_file = expand_env_vars(cli.pid_file);
        opt.pid_file_set = true;
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
    if (!apply_env(out, err)) {
        return false;
    }
    apply_cli(cli, out);
    return validate_options(out, err);
}

}  // namespace rbp
