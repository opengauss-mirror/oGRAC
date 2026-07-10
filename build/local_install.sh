#!/bin/bash


CURRENT_PATH=$(dirname $(readlink -f $0))
CODE_PATH=$(cd "${CURRENT_PATH}/.."; pwd)
WORK_DIR=$(cd "${CURRENT_PATH}/../../"; pwd)
BUILD_ARGS=""
PATCH="" # 是否在oGRAC中创建元数据
BUILD_TYPE="release"
INCREMENTAL_BUILD="FALSE"
USER="ogracdba"
COMPATIBILITY_MODE="A"

function prepare() {
  echo "Prepare env start."
  yum install -y libaio-devel openssl openssl-devel \
  ndctl-devel ncurses ncurses-devel libtirpc-devel \
  expect ant bison iputils iproute wget\
  libtirpc-devel make gcc gcc-c++ gdb gdb-gdbserver\
  python3 python3-devel git net-tools cmake automake\
  byacc libtool --skip-broken
  echo "Prepare env success."
}

function oGRAC_patch() {
    escaped_variable=$(echo "${WORK_DIR}" | sed 's/\//\\\//g')
    sed -i "s/\/home\/regress\/ogracKernel/${escaped_variable}\/ograc/g" ${WORK_DIR}/ograc/pkg/install/install.py
    sed -i "s/\/home\/regress/${escaped_variable}/g" ${CODE_PATH}/pkg/install/Common.py
    sed -i "s/\/home\/regress/${escaped_variable}/g" ${CODE_PATH}/pkg/install/funclib.py
    sed -i "s/192.168.86.1/127.0.0.1/g" ${CODE_PATH}/pkg/install/funclib.py
}

function compile() {
    if [[ "${INCREMENTAL_BUILD}" == "TRUE" ]]; then
        compile_incrementally
        return
    fi

    oGRAC_patch
    export local_build=true
    cd ${CODE_PATH}/build || exit 1
    sh Makefile.sh package-${BUILD_TYPE} ${BUILD_ARGS}
    if [[ $? -ne 0  ]]; then
        echo "build_ograc failed."
        exit 1
    fi
}

function compile_incrementally() {
    BUILD_TYPE=${BUILD_TYPE,,}
    if [[ "${BUILD_TYPE}" != "debug" ]]; then
        echo "Error: incremental compile is supported for debug builds only."
        exit 1
    fi

    echo "Starting incremental compile..."
    cd ${CODE_PATH}/build || exit 1
    if ! sh Makefile.sh check-incremental-debug; then
        echo "Please run 'sh local_install.sh compile -b debug' first to do a full debug build."
        exit 1
    fi

    oGRAC_patch
    export local_build=true
    if ! sh Makefile.sh incremental-package-debug; then
        echo "Incremental compile or package failed."
        exit 1
    fi
    echo "Incremental compile and package completed."
}

function check_compatibility_mode() {
    if [ "$COMPATIBILITY_MODE" != "A" ] && [ "$COMPATIBILITY_MODE" != "B" ] && [ "$COMPATIBILITY_MODE" != "C" ]; then
        echo "Error: compatibility mode only support A, B or C."
        exit 2
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
    cd ${CODE_PATH}/oGRAC-DATABASE-*-64bit || exit 1
    mkdir -p /home/${USER}/logs
    run_mode=ogracd_in_cluster
    python3 install.py -U ${USER}:${USER} -R /home/${USER}/install \
    -D /home/${USER}/data -l /home/${USER}/logs/install.log \
    -M ${run_mode} -Z _LOG_LEVEL=255 -N 0 -W 192.168.0.1 -g \
    withoutroot -d -c --COMPATIBILITY_MODE=${COMPATIBILITY_MODE} -Z _SYS_PASSWORD=huawei@1234 -Z SESSIONS=1000
    if [[ $? -ne 0  ]]; then
        echo "install oGRAC failed."
        exit 1
    fi
}

function usage() {
    echo 'Usage: sh local_install.sh compile [OPTION]'
    echo 'Options:'
    echo '  -b, --build_type=<type>       Build type, default is release.'
    echo '  --incremental                 Incremental compile, supported for debug builds only.'
    echo '  -u, --user=<user>             User name, default is ogracdba.'
    echo '  -c, --compatibility=<dbcompatibility>        compatibility mode, default is A.'
    echo '  -h, --help                    Display thishelp and exit.'
}

function parse_params()
{
    ARGS=$(getopt -o b:u:c:h --long build_type:,user:,compatibility:,incremental,help -n "$0" -- "$@")
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
            -c | --compatibility)
                COMPATIBILITY_MODE=$2
                check_compatibility_mode
                shift 2
                ;;
            --incremental)
                INCREMENTAL_BUILD="TRUE"
                shift
                ;;
            --)
                shift
                break
                ;;
            -h | --help)
                usage
                exit 0
                ;;
        esac
    done
}

function help() {
    echo 'Usage: sh local_install.sh [OPTION]'
    echo 'Options:'
    echo '  prepare                       Prepare compile and install dependencies.'
    echo '  compile [--incremental]       Compile oGRAC; --incremental reuses a debug build cache.'
    echo '  install                       Install and start oGRAC.'
    echo '  clean                         Uninstall and clean env.'
}

function main()
{
    mode=$1
    shift
    parse_params "$@"
    if [[ "${INCREMENTAL_BUILD}" == "TRUE" ]] && [[ "${mode}" != "compile" ]]; then
        echo "Error: --incremental is supported by compile mode only."
        exit 1
    fi
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
