#!/usr/bin/env bash
# Prepare the parser generator for both single-node and dual-node builds.
set -euo pipefail

BISON_VERSION=3.6.4
BISON_SHA256=8b13473b31ca7fcf65e5e8a74224368ffd5df19275602a9c9567ba393f18577d
BISON_PREFIX=${BISON_INSTALL_PREFIX:-/usr/local}
BISON_JOBS=${BISON_BUILD_JOBS:-2}

bison_is_compatible()
{
    local version
    version=$(LC_ALL=C "$1" --version 2>/dev/null | sed -n \
        '1s/^bison (GNU Bison) \([0-9][0-9.]*\).*$/\1/p') || return 1
    [[ -n "${version}" ]] || return 1
    printf '%s\n%s\n' "${BISON_VERSION}" "${version}" | LC_ALL=C sort -V -C
}

main()
{
    if [[ "${BISON_PREFIX}" != /* || "${BISON_PREFIX}" == / ]]; then
        echo "BISON_INSTALL_PREFIX must be an absolute installation directory." >&2
        exit 1
    fi
    local current_bison
    # Match the default CMake search preference without replacing /usr/bin/bison.
    current_bison=$(PATH="${BISON_PREFIX}/bin:${PATH}" command -v bison || true)
    if [[ -n "${current_bison}" ]] && bison_is_compatible "${current_bison}"; then
        echo "Using compatible Bison: ${current_bison}"
        return
    fi

    if [[ ! "${BISON_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
        echo "BISON_BUILD_JOBS must be a positive integer." >&2
        exit 1
    fi
    local tool
    for tool in gcc make m4 tar xz sha256sum; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "Bison preparation requires ${tool}; install the build dependencies first." >&2
            exit 1
        fi
    done

    local archive
    BISON_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ograc-bison.XXXXXXXX")
    trap 'rm -rf -- "${BISON_WORK_DIR}"' EXIT
    archive="${BISON_WORK_DIR}/bison-${BISON_VERSION}.tar.xz"
    if [[ -n "${BISON_SOURCE_ARCHIVE:-}" ]]; then
        cp -- "${BISON_SOURCE_ARCHIVE}" "${archive}"
    elif command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 15 --max-time 300 \
            "https://ftp.gnu.org/gnu/bison/bison-${BISON_VERSION}.tar.xz" -o "${archive}"
    elif command -v wget >/dev/null 2>&1; then
        wget --timeout=30 --tries=3 \
            "https://ftp.gnu.org/gnu/bison/bison-${BISON_VERSION}.tar.xz" -O "${archive}"
    else
        echo "Install curl or wget, or set BISON_SOURCE_ARCHIVE to the offline source archive." >&2
        exit 1
    fi

    printf '%s  %s\n' "${BISON_SHA256}" "${archive}" | sha256sum -c -
    tar -xJf "${archive}" -C "${BISON_WORK_DIR}"
    echo "Installing Bison ${BISON_VERSION} into ${BISON_PREFIX}"
    (
        cd "${BISON_WORK_DIR}/bison-${BISON_VERSION}"
        FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix="${BISON_PREFIX}"
        make -j"${BISON_JOBS}"
        make install
    )
    if ! bison_is_compatible "${BISON_PREFIX}/bin/bison"; then
        echo "The installed Bison does not meet the ${BISON_VERSION} minimum." >&2
        exit 1
    fi
    echo "Bison preparation complete: ${BISON_PREFIX}/bin/bison"
    echo "For source builds, put ${BISON_PREFIX}/bin first in PATH."
}

main "$@"
