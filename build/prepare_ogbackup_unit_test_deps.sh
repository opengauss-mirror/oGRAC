#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${OGBACKUP_UNIT_TEST_DEPS_SRC:-${ROOT_DIR}/_unit_test_deps_src}"
BUILD_DIR="${OGBACKUP_UNIT_TEST_DEPS_BUILD:-${ROOT_DIR}/_unit_test_deps_build}"

GTEST_URL="${OGBACKUP_UNIT_TEST_GTEST_URL:-https://github.com/google/googletest.git}"
GTEST_COMMIT="2fe3bd994b3189899d93f1d5a881e725e046fdc2"
MOCKCPP_URL="${OGBACKUP_UNIT_TEST_MOCKCPP_URL:-https://gitee.com/sinojelly/mockcpp.git}"
MOCKCPP_COMMIT="e8d8b8fa25830b7f6b94281c5c5aee67ee87836f"

GTEST_HEADER_SHA256="2e02f5f42b124c4a70c8f4cdd8a5c6776cb30a7db343c54d6ab5e5470d4f9640"
GMOCK_HEADER_SHA256="4223beebebddd9c2c15b3148ec6ea14a3db1284c79677e2f9bf23ad017419f29"
MOCKCPP_HEADER_SHA256="5296b102469e25fc312e085e1ebae99fc6b0428c1d86a50a85fe2513ec17d2c8"

usage()
{
    cat <<'EOF'
Usage: build/prepare_ogbackup_unit_test_deps.sh

Prepare googletest/googlemock/mockcpp only for local ogbackup unit-test builds.
The dependencies are fetched into _unit_test_deps_src, built under
_unit_test_deps_build, and copied to the repository layout expected by
pkg/test/unit_test/CMakeLists.txt:

  open_source/googletest/{googletest,googlemock}/include
  open_source/mockcpp/include
  open_source/mockcpp/3rdparty
  library/googletest/lib
  library/mockcpp/lib

No system installation is performed and these dependencies are not part of the
production oGRAC package.

Environment overrides:
  OGBACKUP_UNIT_TEST_DEPS_SRC
  OGBACKUP_UNIT_TEST_DEPS_BUILD
  OGBACKUP_UNIT_TEST_GTEST_URL
  OGBACKUP_UNIT_TEST_MOCKCPP_URL
  OGBACKUP_UNIT_TEST_GIT_PROXY_OFF=1
EOF
}

git_cmd()
{
    if [[ "${OGBACKUP_UNIT_TEST_GIT_PROXY_OFF:-0}" == "1" ]]; then
        git -c http.proxy= -c https.proxy= "$@"
    else
        git "$@"
    fi
}

ensure_repo()
{
    local name="$1"
    local url="$2"
    local commit="$3"
    local path="${SRC_DIR}/${name}"

    mkdir -p "${SRC_DIR}"
    if [[ ! -d "${path}/.git" ]]; then
        git_cmd clone "${url}" "${path}"
    fi

    if ! git -C "${path}" cat-file -e "${commit}^{commit}" 2>/dev/null; then
        git_cmd -C "${path}" fetch --tags --force origin
    fi
    git -C "${path}" checkout --detach "${commit}"
    local actual
    actual="$(git -C "${path}" rev-parse HEAD)"
    if [[ "${actual}" != "${commit}" ]]; then
        echo "unexpected ${name} commit: ${actual}, expected ${commit}" >&2
        exit 1
    fi
}

verify_sha256()
{
    local expected="$1"
    local path="$2"
    local actual
    actual="$(sha256sum "${path}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "sha256 mismatch for ${path}: ${actual}, expected ${expected}" >&2
        exit 1
    fi
}

main()
{
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        exit 0
    fi

    ensure_repo "googletest" "${GTEST_URL}" "${GTEST_COMMIT}"
    ensure_repo "mockcpp" "${MOCKCPP_URL}" "${MOCKCPP_COMMIT}"

    mkdir -p "${ROOT_DIR}/open_source" \
        "${ROOT_DIR}/library/googletest/lib" \
        "${ROOT_DIR}/library/mockcpp/lib" \
        "${BUILD_DIR}"

    rm -rf "${ROOT_DIR}/open_source/googletest" "${ROOT_DIR}/open_source/mockcpp"
    cp -a "${SRC_DIR}/googletest" "${ROOT_DIR}/open_source/googletest"
    cp -a "${SRC_DIR}/mockcpp" "${ROOT_DIR}/open_source/mockcpp"

    verify_sha256 "${GTEST_HEADER_SHA256}" \
        "${ROOT_DIR}/open_source/googletest/googletest/include/gtest/gtest.h"
    verify_sha256 "${GMOCK_HEADER_SHA256}" \
        "${ROOT_DIR}/open_source/googletest/googlemock/include/gmock/gmock.h"
    verify_sha256 "${MOCKCPP_HEADER_SHA256}" \
        "${ROOT_DIR}/open_source/mockcpp/include/mockcpp/mockcpp.hpp"

    cmake -S "${ROOT_DIR}/open_source/googletest" \
        -B "${BUILD_DIR}/googletest" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF
    cmake --build "${BUILD_DIR}/googletest" --target gtest gmock -j"${OGBACKUP_UNIT_TEST_JOBS:-2}"

    cmake -S "${ROOT_DIR}/open_source/mockcpp" \
        -B "${BUILD_DIR}/mockcpp" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF
    cmake --build "${BUILD_DIR}/mockcpp" -j"${OGBACKUP_UNIT_TEST_JOBS:-2}"

    cp -a "${BUILD_DIR}/googletest/googlemock/gtest/libgtest.a" "${ROOT_DIR}/library/googletest/lib/"
    cp -a "${BUILD_DIR}/googletest/googlemock/libgmock.a" "${ROOT_DIR}/library/googletest/lib/"
    cp -a "$(find "${BUILD_DIR}/mockcpp" -type f -name libmockcpp.a | head -n 1)" \
        "${ROOT_DIR}/library/mockcpp/lib/"

    sha256sum \
        "${ROOT_DIR}/library/googletest/lib/libgtest.a" \
        "${ROOT_DIR}/library/googletest/lib/libgmock.a" \
        "${ROOT_DIR}/library/mockcpp/lib/libmockcpp.a"
}

main "$@"
