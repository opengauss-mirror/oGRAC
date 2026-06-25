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
 * main.cpp
 *
 *
 * IDENTIFICATION
 * src/rbp/main.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "rbp_config.h"
#include "rbp_log.h"
#include "rbp_server.h"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#if defined(_WIN32)
#include <stdlib.h>
#endif

static void usage(const char* prog)
{
    std::cerr << "Usage: " << prog
              << " [--config FILE] [--host HOST] [--port PORT] [--verbose]\n"
              << "       [--log-cmp-lsn] [--no-smb-version] [--max-cache-pages N] [--capacity-evict-on-write]\n"
              << "       [--admin-host HOST] [--admin-port PORT] [--log-file FILE] [--pid-file FILE]\n"
              << "       [--admin-query COMMAND]\n";
}

int main(int argc, char** argv)
{
    rbp::check_little_endian();

    rbp::CliOverrides cli;

    try {
        int i = 1;
        while (i < argc) {
            std::string arg = argv[i++];
            if (arg == "--config" && i < argc) {
                cli.config_path = argv[i++];
                cli.config_path_set = true;
            } else if (arg == "--host" && i < argc) {
                cli.host = argv[i++];
                cli.host_set = true;
            } else if (arg == "--port" && i < argc) {
                cli.port = std::stoi(argv[i++]);
                cli.port_set = true;
            } else if (arg == "--verbose") {
                cli.verbose = true;
                cli.verbose_set = true;
            } else if (arg == "--log-cmp-lsn") {
                cli.log_cmp_lsn = true;
                cli.log_cmp_lsn_set = true;
            } else if (arg == "--no-smb-version") {
                cli.smb_version = false;
                cli.smb_version_set = true;
            } else if (arg == "--max-cache-pages" && i < argc) {
                cli.max_cache_pages = std::stoi(argv[i++]);
                cli.max_cache_pages_set = true;
            } else if (arg == "--capacity-evict-on-write") {
                cli.capacity_evict_on_write = true;
                cli.capacity_evict_on_write_set = true;
            } else if (arg == "--admin-host" && i < argc) {
                cli.admin_host = argv[i++];
                cli.admin_host_set = true;
            } else if (arg == "--admin-port" && i < argc) {
                cli.admin_port = std::stoi(argv[i++]);
                cli.admin_port_set = true;
            } else if (arg == "--log-file" && i < argc) {
                cli.log_file = argv[i++];
                cli.log_file_set = true;
            } else if (arg == "--pid-file" && i < argc) {
                cli.pid_file = argv[i++];
                cli.pid_file_set = true;
            } else if (arg == "--admin-query" && i < argc) {
                cli.admin_query = argv[i++];
                cli.admin_query_set = true;
            } else if (arg == "-h" || arg == "--help") {
                usage(argv[0]);
                return 0;
            } else {
                std::cerr << "Unknown arg: " << arg << "\n";
                usage(argv[0]);
                return 1;
            }
        }
    } catch (const std::exception& exc) {
        std::cerr << "rbps: invalid command line: " << exc.what() << "\n";
        usage(argv[0]);
        return 1;
    }

    rbp::ServerOptions options;
    std::string err;
    if (!rbp::build_server_options(cli, options, err)) {
        std::cerr << "rbps: " << err << "\n";
        return 1;
    }
    if (cli.admin_query_set) {
        std::string response;
        if (!rbp::admin_query_once(options.admin_host, options.admin_port, cli.admin_query, response, err)) {
            std::cerr << "rbps: " << err << "\n";
            return 1;
        }
        std::cout << response;
        return 0;
    }
    if (!rbp::rbp_init_log_file(options.log_file, err)) {
        std::cerr << "rbps: " << err << "\n";
        return 1;
    }

    rbp::run_server(options.host, options.port, options.config, options.admin_port, options.admin_host);
    return 0;
}
