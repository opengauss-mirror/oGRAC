#include "gbp_config.h"
#include "gbp_log.h"
#include "gbp_server.h"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#if defined(_WIN32)
#include <stdlib.h>
#endif

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " [--config FILE] [--host HOST] [--port PORT] [--verbose]\n"
              << "       [--log-cmp-lsn] [--no-smb-version] [--max-cache-pages N]\n"
              << "       [--admin-host HOST] [--admin-port PORT] [--log-file FILE] [--pid-file FILE]\n"
              << "       [--admin-query COMMAND]\n";
}

int main(int argc, char** argv) {
    gbp::check_little_endian();

    gbp::CliOverrides cli;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--config" && i + 1 < argc) {
                cli.config_path = argv[++i];
                cli.config_path_set = true;
            } else if (arg == "--host" && i + 1 < argc) {
                cli.host = argv[++i];
                cli.host_set = true;
            } else if (arg == "--port" && i + 1 < argc) {
                cli.port = std::stoi(argv[++i]);
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
            } else if (arg == "--max-cache-pages" && i + 1 < argc) {
                cli.max_cache_pages = std::stoi(argv[++i]);
                cli.max_cache_pages_set = true;
            } else if (arg == "--admin-host" && i + 1 < argc) {
                cli.admin_host = argv[++i];
                cli.admin_host_set = true;
            } else if (arg == "--admin-port" && i + 1 < argc) {
                cli.admin_port = std::stoi(argv[++i]);
                cli.admin_port_set = true;
            } else if (arg == "--log-file" && i + 1 < argc) {
                cli.log_file = argv[++i];
                cli.log_file_set = true;
            } else if (arg == "--pid-file" && i + 1 < argc) {
                cli.pid_file = argv[++i];
                cli.pid_file_set = true;
            } else if (arg == "--admin-query" && i + 1 < argc) {
                cli.admin_query = argv[++i];
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
        std::cerr << "gbps: invalid command line: " << exc.what() << "\n";
        usage(argv[0]);
        return 1;
    }

    gbp::ServerOptions options;
    std::string err;
    if (!gbp::build_server_options(cli, options, err)) {
        std::cerr << "gbps: " << err << "\n";
        return 1;
    }
    if (cli.admin_query_set) {
        std::string response;
        if (!gbp::admin_query_once(options.admin_host, options.admin_port, cli.admin_query, response, err)) {
            std::cerr << "gbps: " << err << "\n";
            return 1;
        }
        std::cout << response;
        return 0;
    }
    if (!gbp::gbp_init_log_file(options.log_file, err)) {
        std::cerr << "gbps: " << err << "\n";
        return 1;
    }

    gbp::run_server(options.host, options.port, options.config, options.admin_port, options.admin_host);
    return 0;
}
