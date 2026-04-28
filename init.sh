#!/bin/bash
set -euo pipefail

DEFAULT_COMPILE_DIR="/opt/oGRAC-compile"
DEFAULT_USER="ogracdba"
DEFAULT_DEPENDENCIES=(libaio-devel openssl openssl-devel ndctl-devel ncurses ncurses-devel libtirpc-devel expect ant bison iputils iproute wget make gcc gcc-c++ gdb gdb-gdbserver python3 python3-devel git net-tools cmake automake byacc libtool unixODBC-devel)

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

function require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "ERROR: init.sh must be run as root or with sudo."
        exit 1
    fi
}

function disable_selinux_firewall() {
    if command -v setenforce >/dev/null 2>&1; then
        setenforce 0 || true
    fi
    if [[ -f /etc/selinux/config ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop firewalld || true
        systemctl disable firewalld || true
    fi

    echo "SELinux and firewall configuration has been updated."
}

function create_compile_path() {
    local compile_dir="$1"
    local user_name="$2"

    mkdir -p "${compile_dir}"
    chmod 755 -R "${compile_dir}"
    if id "${user_name}" >/dev/null 2>&1; then
        echo "User ${user_name} already exists."
    else
        echo "Creating user ${user_name}."
        useradd -m -s /bin/bash "${user_name}"
        set_user_password "${user_name}"
    fi

    chown -R "${user_name}:${user_name}" "${compile_dir}"
    echo "Compile directory ${compile_dir} created and owned by ${user_name}."
}

function set_user_password() {
    local user_name="$1"
    local password
    local password_confirm

    while true; do
        read -s -p "Enter password for ${user_name} (leave blank to use '${user_name}'): " password
        echo
        if [[ -z "${password}" ]]; then
            password="${user_name}"
            password_confirm="${user_name}"
        else
            read -s -p "Confirm password for ${user_name}: " password_confirm
            echo
        fi
        if [[ "${password}" != "${password_confirm}" ]]; then
            echo "Passwords do not match. Please try again."
        else
            break
        fi
    done

    echo "${user_name}:${password}" | chpasswd
    echo "Password for ${user_name} set."
}

function install_dependencies() {
    echo "Installing build dependencies..."
    yum install -y "${DEFAULT_DEPENDENCIES[@]}" --skip-broken
    echo "Dependencies installation complete."
}

function show_summary() {
    local compile_dir="$1"
    local user_name="$2"

    echo
    echo "Initialization complete. Next steps:"
    echo "  1. Change to your oGRAC source directory, or clone the repo into the compile path:" 
    echo "       cd ${compile_dir}"
    echo "       git clone https://gitcode.com/victor-akande/oGRAC.git"
    echo "  2. Change to the build directory and compile:" 
    echo "       cd oGRAC/build"
    echo "       sh local_install.sh prepare"
    echo "       sh local_install.sh compile -b debug"
    echo
    echo "Build artifacts will be generated under the oGRAC source tree, typically in oGRAC/oGRAC-DATABASE-*-64bit."
    echo "The compilation user is: ${user_name}"
}

function main() {
    require_root

    echo "oGRAC compilation environment initializer"
    echo "This script will set up the compile directory, create a user, and install dependencies."
    echo

    local compile_dir
    compile_dir=$(prompt_default "Compile path" "${DEFAULT_COMPILE_DIR}")
    local user_name
    user_name=$(prompt_default "Compilation user name" "${DEFAULT_USER}")

    if confirm "Disable SELinux and firewall?" "yes"; then
        disable_selinux_firewall
    else
        echo "Skipping SELinux/firewall configuration."
    fi

    create_compile_path "${compile_dir}" "${user_name}"

    if confirm "Install required dependencies now?" "yes"; then
        install_dependencies
    else
        echo "Dependency installation skipped. Run the commands from the README manually."
    fi

    show_summary "${compile_dir}" "${user_name}"
}

main "$@"
