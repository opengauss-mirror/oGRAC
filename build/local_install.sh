#!/bin/bash


CURRENT_PATH=$(dirname $(readlink -f $0))
CODE_PATH=$(cd "${CURRENT_PATH}/.."; pwd)
WORK_DIR=$(cd "${CURRENT_PATH}/../../"; pwd)
BUILD_ARGS=""
PATCH="" # 是否在oGRAC中创建元数据
BUILD_TYPE="release"
USER="ogracdba"
BIND_IP=""

function prepare() {
  echo "Prepare env start."
  yum install -y libaio-devel openssl openssl-devel \
  ndctl-devel ncurses ncurses-devel libtirpc-devel \
  expect ant bison iputils iproute wget\
  libtirpc-devel make gcc gcc-c++ gdb gdb-gdbserver\
  python3 python3-devel git net-tools cmake automake\
  byacc libtool unixODBC-devel --skip-broken
  echo "Prepare env success."
}

function oGRAC_patch() {
    escaped_variable=$(echo "${WORK_DIR}" | sed 's/\//\\\//g')
    sed -i "s/\/home\/regress\/ogracKernel/${escaped_variable}\/ograc/g" ${WORK_DIR}/ograc/pkg/install/install.py
    sed -i "s/\/home\/regress/${escaped_variable}/g" ${CODE_PATH}/pkg/install/Common.py
    sed -i "s/\/home\/regress/${escaped_variable}/g" ${CODE_PATH}/pkg/install/funclib.py
}

function compile() {
    oGRAC_patch
    export local_build=true
    cd ${CODE_PATH}/build || exit 1
    sh Makefile.sh package-${BUILD_TYPE} ${BUILD_ARGS}
    if [[ $? -ne 0  ]]; then
        echo "build_ograc failed."
        exit 1
    fi
}

function clean() {
    kill -9 $(pidof ogracd) > /dev/null 2>&1
    kill -9 $(pidof cms) > /dev/null 2>&1
    rm -rf ${WORK_DIR}/ograc_data/* /home/${USER}/install /home/${USER}/data /data/data/*
    sed -i "/${USER}/d" /home/${USER}/.bashrc
}

function install() {
    id "${USER}"
    if [[ $? -ne 0 ]]; then
        echo "add user ${USER}."
        useradd -m -s /bin/bash ${USER}
        echo "${USER}:${USER}" | chpasswd
    fi
    touch /.dockerenv
    clean
    mkdir -p "${WORK_DIR}"/ograc_data -m 755
    chown -R ${USER}:${USER} "${WORK_DIR}"/ograc_data
    local bind_ip
    bind_ip=$(get_bind_ip)
    if [[ $? -ne 0 ]]; then
        echo "Failed to determine bind IP for installation."
        exit 1
    fi

    # Find the database package directory
    # Look for directories matching the pattern, prefer the most recent one
    local pkg_dir
    pkg_dir=$(find "${CODE_PATH}" -maxdepth 1 -type d -name "oGRAC-DATABASE-*-64bit" -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [[ -z "${pkg_dir}" ]]; then
        echo "Error: No oGRAC-DATABASE-* directory found in ${CODE_PATH}"
        exit 1
    fi
    
    echo "Using package directory: ${pkg_dir}"
    cd "${pkg_dir}" || exit 1
    mkdir -p /home/${USER}/logs
    run_mode=ogracd_in_cluster
    python3 install.py -U ${USER}:${USER} -R /home/${USER}/install \
    -D /home/${USER}/data -l /home/${USER}/logs/install.log \
    -M ${run_mode} -Z _LOG_LEVEL=255 -N 0 -W ${bind_ip},127.0.0.1 \
    -Z "LSNR_ADDR=${bind_ip}" -Z "INTERCONNECT_ADDR=${bind_ip}" -g \
    withoutroot -d -c -Z _SYS_PASSWORD=huawei@1234 -Z SESSIONS=1000
    if [[ $? -ne 0  ]]; then
        echo "install oGRAC failed."
        exit 1
    fi
}

function usage() {
    echo 'Usage: sh local_install.sh compile [OPTION]'
    echo 'Options:'
    echo '  -b, --build_type=<type>       Build type, default is release.'
    echo '  -u, --user=<user>             User name, default is ogracdba.'
    echo '  -i, --bind-ip=<ip>            Explicit IPv4 address to bind the database to.'
    echo '  -h, --help                    Display this help and exit.'
}

function parse_params()
{
    ARGS=$(getopt -o b:u:i:h --long build_type:,user:,bind-ip:,help -n "$0" -- "$@")
    if [ $? != 0 ]; then
        echo "Terminating..."
        exit 1
    fi
    eval set -- "${ARGS}"
    while true
    do
        case "$1" in
            -b | --build_type)
                BUILD_TYPE=$2
                shift 2
                ;;
            -u | --user)
                USER=$2
                shift 2
                ;;
            -i | --bind-ip)
                BIND_IP=$2
                shift 2
                ;;
            -h | --help)
                usage
                exit 1
                ;;
            --)
                shift
                break
                ;;
        esac
    done
}

function validate_ipv4() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        for octet in $a $b $c $d; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

function get_default_ip() {
    local ip
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    else
        ip=$(hostname -I 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i !~ /^127\./) {print $i; exit}}')
    fi
    if [[ -n "$ip" ]]; then
        printf '%s' "$ip"
        return 0
    fi
    return 1
}

function get_bind_ip() {
    if [[ -n "$BIND_IP" ]]; then
        if validate_ipv4 "$BIND_IP"; then
            printf '%s' "$BIND_IP"
            return 0
        fi
        echo "Invalid IPv4 address: $BIND_IP" >&2
        return 1
    fi

    local default_ip
    default_ip=$(get_default_ip)
    if [[ -n "$default_ip" ]]; then
        printf '%s' "$default_ip"
        return 0
    fi

    echo "No non-loopback IPv4 address detected. Specify --bind-ip." >&2
    return 1
}

function help() {
    echo 'Usage: sh local_install.sh [OPTION]'
    echo 'Options:'
    echo '  prepare                       Prepare compile and install dependencies.'
    echo '  compile                       Compile oGRAC.'
    echo '  install                       Install and start oGRAC.'
    echo '  clean                         Uninstall and clean env.'
    echo ''
    echo 'Install command options:'
    echo '  -b, --build_type=<type>       Build type, default is release.'
    echo '  -u, --user=<user>             User name, default is ogracdba.'
    echo '  -i, --bind-ip=<ip>            Explicit IPv4 address to bind the database to.'
}

function main()
{
    mode=$1
    shift
    parse_params "$@"
    case $mode in
        prepare)
            prepare
            exit 0
            ;;
        compile)
            compile
            exit 0
            ;;
        install)
            install
            exit 0
            ;;
        clean)
            clean
            exit 0
            ;;
        *)
            help
            exit 1
            ;;
    esac
}

main "$@"