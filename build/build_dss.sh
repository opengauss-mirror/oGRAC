#!/bin/bash

set -e
ENV_TYPE=$(uname -p)
CURRENT_PATH=$(dirname $(readlink -f $0))
OGDB_CODE_PATH=$(readlink -f "${CURRENT_PATH}/..")
BUILD_TYPE=$1
THIRD_PARTY_PATH=$2
CHECK_ONLY=$3
if [[ ${THIRD_PARTY_PATH} == "--check-only" ]];then
    THIRD_PARTY_PATH=""
    CHECK_ONLY="--check-only"
fi
if [[ ! -d ${OGDB_CODE_PATH} ]];then
    mkdir -p ${OGDB_CODE_PATH}
fi

if [[ ${BUILD_TYPE} == "release" ]] || [[ x"${BUILD_TYPE}" == x"" ]];then
    BUILD_TYPE="Release"
else
    BUILD_TYPE="Debug"
fi
echo "BUILD_TYPE:${BUILD_TYPE}"

function get_binarylibs_arch_suffix() {
    if [[ ${ENV_TYPE} == "aarch64" ]];then
        echo "arm"
    else
        echo "x86_64"
    fi
}

function get_display_path() {
    local path=$1
    local normalized_path
    local root_name=$(basename "${OGDB_CODE_PATH}")
    if normalized_path=$(readlink -m "${path}" 2>/dev/null);then
        path="${normalized_path}"
    fi

    if [[ "${path}" == "${OGDB_CODE_PATH}" ]];then
        echo "${root_name}"
    elif [[ ${path} == "${OGDB_CODE_PATH}/"* ]];then
        echo "${root_name}/${path#${OGDB_CODE_PATH}/}"
    else
        echo "${path}"
    fi
}

function get_os_release_value() {
    local key=$1
    if [[ ! -f /etc/os-release ]];then
        return
    fi

    grep -E "^${key}=" /etc/os-release | head -n 1 | cut -d= -f2 | tr -d '"'
}

function is_open_euler() {
    local os_id=$(get_os_release_value ID)
    [[ ${os_id} == "openEuler" ]] || [[ ${os_id} == "openeuler" ]]
}

function get_open_euler_version() {
    if ! is_open_euler;then
        return 1
    fi

    local os_version=$(get_os_release_value VERSION_ID)
    if [[ x"${os_version}" == x"" ]];then
        echo "Error: cannot identify openEuler version from /etc/os-release, VERSION_ID is empty." >&2
        exit 1
    fi

    echo "${os_version}"
}

function get_expected_binarylibs_names() {
    local arch_suffix=$(get_binarylibs_arch_suffix)
    local os_version
    if ! os_version=$(get_open_euler_version);then
        return 1
    fi

    case "${os_version}" in
        24.03*)
            echo "openGauss-third_party_binarylibs_openEuler_2403_${arch_suffix}"
            ;;
        22.03*)
            echo "openGauss-third_party_binarylibs_openEuler_2203_${arch_suffix}"
            ;;
        20.03*)
            echo "openGauss-third_party_binarylibs_openEuler_${arch_suffix}"
            echo "openGauss-third_party_binarylibs_openEuler_2003_${arch_suffix}"
            ;;
        *)
            echo "Error: unsupported openEuler version: ${os_version}. Supported versions: 20.03, 22.03, 24.03." >&2
            exit 1
            ;;
    esac
}

function check_open_euler_version() {
    if ! is_open_euler;then
        return
    fi

    local os_version
    if ! os_version=$(get_open_euler_version);then
        exit 1
    fi

    case "${os_version}" in
        20.03* | 22.03* | 24.03*)
            return
            ;;
        *)
            echo "Error: unsupported openEuler version: ${os_version}. Supported versions: 20.03, 22.03, 24.03." >&2
            exit 1
            ;;
    esac
}

function print_expected_binarylibs() {
    local search_dir=$1
    local expected_name
    if is_open_euler;then
        for expected_name in $(get_expected_binarylibs_names); do
            echo "Expected directory: $(get_display_path "${search_dir}/${expected_name}")"
            echo "Expected package:   $(get_display_path "${search_dir}/${expected_name}.tar.gz")"
        done
    else
        echo "Expected directory: $(get_display_path "${search_dir}")/openGauss-third_party_binarylibs*"
        echo "Expected package:   $(get_display_path "${search_dir}")/openGauss-third_party_binarylibs*.tar.gz"
    fi
}

function print_third_party_check_info() {
    local search_dir=$1
    local arch_suffix=$(get_binarylibs_arch_suffix)
    local os_id
    local os_version

    echo "[INFO ] Third-party binarylibs search path: $(get_display_path "${search_dir}")"
    echo "[INFO ] Current architecture: ${ENV_TYPE}, binarylibs arch suffix: ${arch_suffix}"
    if is_open_euler;then
        os_version=$(get_open_euler_version)
        echo "[INFO ] openEuler ${os_version} detected, use exact third-party binarylibs match."
        return
    fi

    os_id=$(get_os_release_value ID)
    os_version=$(get_os_release_value VERSION_ID)
    if [[ x"${os_id}" == x"" ]];then
        os_id="unknown"
    fi
    if [[ x"${os_version}" == x"" ]];then
        os_version="unknown"
    fi
    echo "[INFO ] Non-openEuler system detected (${os_id} ${os_version}), skip strict OS-version match for third-party binarylibs."
    echo "[INFO ] Third-party binarylibs directory pattern: openGauss-third_party_binarylibs*"
}

function find_third_party_path() {
    local search_dir=$1
    local search_basename=$(basename "${search_dir}")
    local expected_name
    local third_path
    local third_pkg
    if is_open_euler;then
        for expected_name in $(get_expected_binarylibs_names); do
            if [[ ${search_basename} == "${expected_name}" ]];then
                export THIRD_PATH="${search_dir}"
                return 0
            fi
            if [[ -d "${search_dir}/${expected_name}" ]];then
                export THIRD_PATH="${search_dir}/${expected_name}"
                return 0
            fi
        done

        for expected_name in $(get_expected_binarylibs_names); do
            if [[ -f "${search_dir}/${expected_name}.tar.gz" ]];then
                echo "Error: third-party binarylibs package found but not extracted: $(get_display_path "${search_dir}/${expected_name}.tar.gz")"
                echo "Please extract it before build. Expected extracted directory: $(get_display_path "${search_dir}/${expected_name}")"
                exit 1
            fi
        done

        return 1
    fi

    if [[ ${search_basename} == openGauss-third_party_binarylibs* ]];then
        export THIRD_PATH="${search_dir}"
        return 0
    fi

    for third_path in "${search_dir}"/openGauss-third_party_binarylibs*; do
        if [[ -d "${third_path}" ]];then
            export THIRD_PATH="${third_path}"
            return 0
        fi
    done

    for third_pkg in "${search_dir}"/openGauss-third_party_binarylibs*.tar.gz; do
        if [[ -f "${third_pkg}" ]];then
            echo "Error: third-party binarylibs package found but not extracted: $(get_display_path "${third_pkg}")"
            echo "Please extract it before build."
            exit 1
        fi
    done

    return 1
}

function check_third_party_path() {
    local search_dir="${THIRD_PARTY_PATH}"
    check_open_euler_version
    if [[ x"${search_dir}" == x"" ]];then
        search_dir="${OGDB_CODE_PATH}"
    fi

    if [[ ! -d "${search_dir}" ]];then
        echo "Error: third-party binarylibs search path does not exist: $(get_display_path "${search_dir}")"
        exit 1
    fi
    search_dir=$(readlink -f "${search_dir}")
    print_third_party_check_info "${search_dir}"

    if find_third_party_path "${search_dir}";then
        return
    fi

    echo "Error: no valid third-party binarylibs found under: $(get_display_path "${search_dir}")"
    print_expected_binarylibs "${search_dir}"
    echo "Please download and extract openGauss-third_party_binarylibs_* or specify the search path with --third-party-path <path>."
    exit 1
}

function download_source() {
    echo "Prepare CBB/DSS source start"
    if [[ x"${proxy_user}" != x"" ]];then
        export http_proxy=http://${proxy_user}:${proxy_pwd}@${proxy_url}
        export https_proxy=${http_proxy}
        export no_proxy=127.0.0.1,.huawei.com,localhost,local,.local
    fi

    local repo_name
    local repo_path
    local repo_url
    for repo_name in CBB DSS; do
        repo_path="${OGDB_CODE_PATH}/${repo_name}"
        repo_url="https://gitcode.com/opengauss/${repo_name}.git"
        if [[ ! -e "${repo_path}" ]] ||
           { [[ -d "${repo_path}" ]] && [[ -z "$(find "${repo_path}" -mindepth 1 -print -quit 2>/dev/null)" ]]; }; then
            git clone "${repo_url}" "${repo_path}"
        elif is_git_repository "${repo_path}"; then
            echo "Reuse existing ${repo_name} source: ${repo_path}"
        else
            echo "Error: ${repo_path} exists but is not a Git work tree."
            echo "Please move it aside or provide a valid ${repo_name} source repository."
            exit 1
        fi
    done

    echo "Prepare CBB/DSS source success"
}

function clean_dss_build_outputs() {
    echo "Clean DSS package output start"
    rm -rf "${OGDB_CODE_PATH}/dss" "${OGDB_CODE_PATH}/dss_symbols"
    echo "Clean DSS package output success"
}

function build_package() {
    if [[ x"${THIRD_PATH}" == x"" ]];then
        check_third_party_path
    fi
    export CC=${THIRD_PATH}/buildtools/gcc10.3/gcc/bin/gcc
    export cc=${THIRD_PATH}/buildtools/gcc10.3/gcc/bin/gcc
    export GCCFOLDER=${THIRD_PATH}/buildtools/gcc10.3
    export LD_LIBRARY_PATH=${THIRD_PATH}/buildtools/gcc10.3/gcc/lib64:$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH=$GCCFOLDER/gcc/lib64:$GCCFOLDER/isl/lib:$GCCFOLDER/mpc/lib/:$GCCFOLDER/mpfr/lib/:$GCCFOLDER/gmp/lib/:$LD_LIBRARY_PATH
    export PATH=${THIRD_PATH}/buildtools/gcc10.3/gcc/bin:${PATH}
    echo "Start to compile CBB."
    local cbb_cmake_file="${OGDB_CODE_PATH}/CBB/CMakeLists.txt"
    local cbb_cmake_backup
    cbb_cmake_backup=$(mktemp)
    cp -p "${cbb_cmake_file}" "${cbb_cmake_backup}"
    (
        trap 'cp -p "${cbb_cmake_backup}" "${cbb_cmake_file}"; rm -f "${cbb_cmake_backup}"' EXIT
        sed -i "s/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" OFF)/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" ON)/g" "${cbb_cmake_file}"
        cd "${OGDB_CODE_PATH}/CBB"
        sh build.sh -3rd "${THIRD_PATH}" -m "${BUILD_TYPE}" -t cmake
    )
    echo "Start to compile DSS."
    (
        cd "${OGDB_CODE_PATH}/DSS/build/linux/opengauss"
        sh build.sh -3rd "${THIRD_PATH}" -m "${BUILD_TYPE}" -t cmake
    )
    echo "Start to copy bin/lib source."
    mkdir -p "${OGDB_CODE_PATH}"/dss/{lib,bin}
    cp -arf ${OGDB_CODE_PATH}/CBB/output/bin/* "${OGDB_CODE_PATH}"/dss/bin/
    cp -arf ${OGDB_CODE_PATH}/CBB/output/lib/* "${OGDB_CODE_PATH}"/dss/lib/
    cp -arf ${OGDB_CODE_PATH}/DSS/output/bin/* "${OGDB_CODE_PATH}"/dss/bin/
    cp -arf ${OGDB_CODE_PATH}/DSS/output/lib/* "${OGDB_CODE_PATH}"/dss/lib/
    echo "end to copy bin/lib source."

    echo "Start to separate debug symbols."
    rm -rf "${OGDB_CODE_PATH}/dss_symbols"
    mkdir -p "${OGDB_CODE_PATH}"/dss_symbols/{bin,lib}
    for dir in bin lib; do
        for f in "${OGDB_CODE_PATH}"/dss/${dir}/*; do
            [ -e "$f" ] || continue
            [ -f "$f" ] || continue
            [ -L "$f" ] && continue
            if ! file "$f" | grep -q "ELF"; then
                continue
            fi
            base_name=$(basename "$f")
            sym_file="${OGDB_CODE_PATH}/dss_symbols/${dir}/${base_name}.symbol"
            if [[ "$base_name" == *.so* ]]; then
                objcopy --only-keep-debug "$f" "$sym_file"
                objcopy --strip-unneeded "$f"
                objcopy --add-gnu-debuglink="$sym_file" "$f"
            else
                objcopy --only-keep-debug "$f" "$sym_file"
                objcopy --strip-all "$f"
                objcopy --add-gnu-debuglink="$sym_file" "$f"
            fi
        done
    done
    echo "End to separate debug symbols."
}

function source_state() {
    local repo_path=$1
    (
        cd "${repo_path}"
        { git rev-parse HEAD; git diff --binary HEAD --; git ls-files --others --exclude-standard -z | xargs -0 -r sha256sum; } |
            sha256sum | awk '{print $1}'
    )
}

function is_git_repository() {
    local repo_path=$1
    local repo_root
    repo_root=$(git -C "${repo_path}" rev-parse --show-toplevel 2>/dev/null || true)
    [[ -n "${repo_root}" ]] &&
        [[ "$(readlink -f "${repo_root}" 2>/dev/null || true)" == "$(readlink -f "${repo_path}" 2>/dev/null || true)" ]]
}

function files_state() {
    find "$@" -type f -print0 | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}'
}

function tree_state() {
    local directory=$1
    (cd "${directory}" && find . -type f -printf '%P %s %T@\n' | sort | sha256sum | awk '{print $1}')
}

function write_dss_build_info() {
    local build_info_file="${OGDB_CODE_PATH}/dss/.build_type"
    local third_party_path
    local third_party_gcc
    third_party_path=$(readlink -f "${THIRD_PATH}")
    third_party_gcc="${third_party_path}/buildtools/gcc10.3/gcc/bin/gcc"

    {
        echo "format=2"
        echo "build_type=${BUILD_TYPE,,}"
        echo "arch=$(uname -m)"
        echo "cbb_source=$(source_state "${OGDB_CODE_PATH}/CBB")"
        echo "dss_source=$(source_state "${OGDB_CODE_PATH}/DSS")"
        echo "third_party_path=${third_party_path}"
        echo "third_party_state=$(tree_state "${third_party_path}")"
        echo "third_party_gcc_version=$("${third_party_gcc}" -dumpfullversion -dumpversion)"
        echo "third_party_gcc_target=$("${third_party_gcc}" -dumpmachine)"
        echo "artifacts=$(files_state "${OGDB_CODE_PATH}/dss/bin" "${OGDB_CODE_PATH}/dss/lib" \
            "${OGDB_CODE_PATH}/dss_symbols/bin" "${OGDB_CODE_PATH}/dss_symbols/lib")"
    } > "${build_info_file}"
}

function get_build_info() {
    local key=$1
    (grep -m1 "^${key}=" "${OGDB_CODE_PATH}/dss/.build_type" 2>/dev/null | cut -d= -f2-) || true
}

function cache_error() {
    echo "Error: $1"
    echo "Please run 'sh build_ograc.sh debug --with-dss' first to do a full two-node debug build."
    exit 1
}

function check_build_info() {
    local key=$1
    local expected=$2
    local actual
    actual=$(get_build_info "${key}")
    [[ -n "${actual}" ]] && [[ "${actual}" == "${expected}" ]] ||
        cache_error "The cached DSS ${key} no longer matches the current build environment."
}

function validate_incremental_cache() {
    local build_info_file="${OGDB_CODE_PATH}/dss/.build_type"
    [[ -f "${build_info_file}" ]] || cache_error "The DSS build information is missing."
    check_build_info format 2
    check_build_info build_type debug
    check_build_info arch "$(uname -m)"

    local required_dir
    for required_dir in "${OGDB_CODE_PATH}/dss/bin" "${OGDB_CODE_PATH}/dss/lib" \
        "${OGDB_CODE_PATH}/dss_symbols/bin" "${OGDB_CODE_PATH}/dss_symbols/lib"; do
        [[ -d "${required_dir}" ]] &&
            [[ -n "$(find "${required_dir}" -mindepth 1 -maxdepth 1 -type f -print -quit 2>/dev/null)" ]] ||
            cache_error "DSS artifacts are missing from ${required_dir}."
    done

    is_git_repository "${OGDB_CODE_PATH}/CBB" ||
        cache_error "The CBB source repository is missing."
    is_git_repository "${OGDB_CODE_PATH}/DSS" ||
        cache_error "The DSS source repository is missing."
    check_build_info cbb_source "$(source_state "${OGDB_CODE_PATH}/CBB")"
    check_build_info dss_source "$(source_state "${OGDB_CODE_PATH}/DSS")"

    local third_party_path
    local requested_path
    local third_party_gcc
    third_party_path=$(get_build_info third_party_path)
    [[ -d "${third_party_path}" ]] || cache_error "The cached third-party binarylibs are unavailable."
    if [[ -n "${THIRD_PARTY_PATH}" ]]; then
        requested_path=$(readlink -f "${THIRD_PARTY_PATH}" 2>/dev/null || true)
        [[ -n "${requested_path}" ]] || cache_error "The requested third-party path does not exist."
        case "${third_party_path}" in
            "${requested_path}"|"${requested_path}"/*) ;;
            *) cache_error "The requested third-party path differs from the full DSS build." ;;
        esac
    fi

    check_build_info third_party_state "$(tree_state "${third_party_path}")"
    third_party_gcc="${third_party_path}/buildtools/gcc10.3/gcc/bin/gcc"
    [[ -x "${third_party_gcc}" ]] || cache_error "The cached DSS GCC toolchain is unavailable."
    check_build_info third_party_gcc_version "$("${third_party_gcc}" -dumpfullversion -dumpversion)"
    check_build_info third_party_gcc_target "$("${third_party_gcc}" -dumpmachine)"
    check_build_info artifacts "$(files_state "${OGDB_CODE_PATH}/dss/bin" "${OGDB_CODE_PATH}/dss/lib" \
        "${OGDB_CODE_PATH}/dss_symbols/bin" "${OGDB_CODE_PATH}/dss_symbols/lib")"
    echo "Reusing verified DSS artifacts from the previous full debug build."
}

echo "build dss start."
cd ${OGDB_CODE_PATH}
if [[ ${CHECK_ONLY} == "--validate-cache" ]];then
    validate_incremental_cache
    exit 0
fi
check_third_party_path
if [[ ${CHECK_ONLY} == "--check-only" ]];then
    echo "third-party binarylibs check success: $(get_display_path "${THIRD_PATH}")"
    exit 0
fi
if [[ ${BUILD_TYPE} == "Debug" ]];then
    sed -i 's/"_LOG_LEVEL": 7,/"_LOG_LEVEL": 255,/g' "${OGDB_CODE_PATH}"/pkg/deploy/action/dss/config.py
fi
clean_dss_build_outputs
download_source
build_package
write_dss_build_info
cd -
echo "build dss success."
