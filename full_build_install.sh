#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
BUILD_SCRIPT="${REPO_ROOT}/build/local_install.sh"
INIT_SCRIPT="${REPO_ROOT}/init.sh"
DEFAULT_BUILD_TYPE="debug"
DEFAULT_DB_USER="ogracdba"
DEFAULT_SYS_PASSWORD="Huawei@1234"

function require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "ERROR: full_build_install.sh must be run as root or with sudo."
        exit 1
    fi
}

function prompt_default() {
    local prompt="$1"
    local default="$2"
    local result

    read -p "${prompt} [${default}]: " result
    if [[ -z "${result// /}" ]]; then
        echo "${default}"
    else
        echo "${result}"
    fi
}

function confirm() {
    local prompt="$1"
    local default="$2"
    local answer

    while true; do
        read -p "${prompt} [${default}]: " answer
        answer="${answer,,}"
        if [[ -z "$answer" ]]; then
            answer="${default,,}"
        fi
        case "$answer" in
            y|yes)
                return 0
                ;;
            n|no)
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

function validate_build_type() {
    local type="$1"
    case "${type,,}" in
        debug|release)
            echo "${type,,}"
            ;;
        *)
            echo "release"
            ;;
    esac
}

function run_init() {
    if [[ ! -f "${INIT_SCRIPT}" ]]; then
        echo "ERROR: ${INIT_SCRIPT} not found."
        exit 1
    fi
    echo "Running initialization script..."
    bash "${INIT_SCRIPT}"
}

function configure_build() {
    local build_type="$1"
    if [[ "${build_type}" == "debug" ]]; then
        if confirm "Disable protect virtual memory in build/Makefile.sh for debug build?" "yes"; then
            sed -i 's/DUSE_PROTECT_VM=ON/DUSE_PROTECT_VM=OFF/g' "${REPO_ROOT}/build/Makefile.sh"
            echo "Disabled USE_PROTECT_VM in build/Makefile.sh."
        fi
    fi
}

function prepare_compile() {
    echo "Preparing build environment..."
    bash "${BUILD_SCRIPT}" prepare
}

function compile_ograc() {
    local build_type="$1"
    echo "Compiling oGRAC (${build_type})..."
    bash "${BUILD_SCRIPT}" compile -b "${build_type}"
}

function install_ograc() {
    local db_user="$1"
    echo "Installing oGRAC using admin user ${db_user}..."
    bash "${BUILD_SCRIPT}" install -u "${db_user}"
}

function connect_db() {
    local db_user="$1"
    echo
    echo "Compilation and installation completed. Connecting as ${db_user}..."
    exec su - "${db_user}" -c "ogsql / as sysdba"
}

function main() {
    require_root

    echo "Full oGRAC compilation and installation script"
    echo "This script will prepare dependencies, configure the build, compile oGRAC, install it, and connect to the database."
    echo

    if confirm "Run initialization step (create user, install dependencies, configure system)?" "yes"; then
        run_init
    else
        echo "Skipping initialization step."
    fi

    local build_type
    build_type=$(prompt_default "Build type" "${DEFAULT_BUILD_TYPE}")
    build_type=$(validate_build_type "${build_type}")

    local db_user
    db_user=$(prompt_default "Database admin user" "${DEFAULT_DB_USER}")

    configure_build "${build_type}"
    prepare_compile
    compile_ograc "${build_type}"
    install_ograc "${db_user}"
    connect_db "${db_user}"
}

main "$@"
