#!/usr/bin/env bash
# Use the official archive and real checksum verification; mock compilation and
# package-manager calls so these checks never install into the host toolchain.
# Usage: bash build/tests/test_prepare_bison.sh /path/to/bison-3.6.4.tar.xz
set -euo pipefail

if [[ $# != 1 ]]; then
    echo "Usage: $0 /path/to/bison-3.6.4.tar.xz" >&2
    exit 2
fi
SCRIPT_DIR=$(cd "$(dirname "$0")/.." && pwd)
export TEST_ARCHIVE
TEST_ARCHIVE=$(readlink -f "$1")
test -f "${TEST_ARCHIVE}"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "${TEST_ROOT}"' EXIT
ORIGINAL_PATH=${PATH}

write_bison()
{
    printf '#!/usr/bin/env bash\necho "bison (GNU Bison) %s"\necho "Copyright Free Software Foundation"\n' \
        "$2" > "$1"
    chmod +x "$1"
}

new_case()
{
    export TEST_CASE="${TEST_ROOT}/$1" TEST_FAIL_STAGE="" TEST_INSTALLED_VERSION=3.6.4 TEST_YUM_EXIT=0
    export PATH="${TEST_CASE}/bin:${ORIGINAL_PATH}"
    export BISON_INSTALL_PREFIX="${TEST_CASE}/install prefix" BISON_SOURCE_ARCHIVE="${TEST_ARCHIVE}"
    export BISON_BUILD_JOBS=2 TMPDIR="${TEST_CASE}/tmp" TEST_ACTIONS="${TEST_CASE}/actions"
    mkdir -p "${TEST_CASE}/bin" "${TMPDIR}"
    write_bison "${TEST_CASE}/bin/bison" 3.5
    for tool in gcc m4; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "${TEST_CASE}/bin/${tool}"
    done
    cat > "${TEST_CASE}/bin/tar" <<'EOF'
#!/usr/bin/env bash
set -eu
echo extract >> "${TEST_ACTIONS}"
source_dir="${@: -1}/bison-3.6.4"
mkdir -p "${source_dir}"
cat > "${source_dir}/configure" <<'CONFIGURE'
#!/usr/bin/env bash
set -eu
echo configure >> "${TEST_ACTIONS}"
[[ "${TEST_FAIL_STAGE}" != configure ]] || exit 42
printf '%s\n' "${1#--prefix=}" > "${TEST_CASE}/prefix"
CONFIGURE
chmod +x "${source_dir}/configure"
EOF
    cat > "${TEST_CASE}/bin/make" <<'EOF'
#!/usr/bin/env bash
set -eu
echo "make $*" >> "${TEST_ACTIONS}"
if [[ "$1" != install ]]; then
    [[ "${TEST_FAIL_STAGE}" != build ]] || exit 42
    exit 0
fi
[[ "${TEST_FAIL_STAGE}" != install ]] || exit 42
prefix=$(cat "${TEST_CASE}/prefix")
mkdir -p "${prefix}/bin"
printf '#!/usr/bin/env bash\necho "bison (GNU Bison) %s"\necho "Copyright Free Software Foundation"\n' \
    "${TEST_INSTALLED_VERSION}" > "${prefix}/bin/bison"
chmod +x "${prefix}/bin/bison"
EOF
    cat > "${TEST_CASE}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -eu
echo download >> "${TEST_ACTIONS}"
[[ "${TEST_FAIL_STAGE}" != download ]] || exit 42
cp "${TEST_ARCHIVE}" "${@: -1}"
EOF
    cat > "${TEST_CASE}/bin/yum" <<'EOF'
#!/usr/bin/env bash
exit "${TEST_YUM_EXIT}"
EOF
    chmod +x "${TEST_CASE}/bin/"*
}

run_script()
{
    if bash "$1" > "${TEST_CASE}/result.log" 2>&1; then
        RESULT=0
    else
        RESULT=$?
    fi
}

assert_result()
{
    if [[ "$1" == success && ${RESULT} != 0 ]] || [[ "$1" == failure && ${RESULT} == 0 ]]; then
        cat "${TEST_CASE}/result.log"
        echo "FAIL: ${TEST_CASE##*/}: expected $1, exit ${RESULT}" >&2
        exit 1
    fi
    [[ -z "$(ls -A "${TMPDIR}")" ]] || { echo "Temporary build directory leaked" >&2; exit 1; }
    echo "PASS: ${TEST_CASE##*/} ($1)"
}

for version in 3.6.4 3.8.2 3.10 4.0; do
    new_case "reuse-${version}"
    write_bison "${TEST_CASE}/bin/bison" "${version}"
    run_script "${SCRIPT_DIR}/prepare_bison.sh"
    assert_result success
    [[ ! -e "${TEST_ACTIONS}" ]]
done

new_case upgrade-offline
run_script "${SCRIPT_DIR}/prepare_bison.sh"
assert_result success
grep -q '^make install$' "${TEST_ACTIONS}"
! grep -q download "${TEST_ACTIONS}"
"${TEST_CASE}/bin/bison" --version | grep -q '3.5'
"${BISON_INSTALL_PREFIX}/bin/bison" --version | grep -q '3.6.4'
cp "${TEST_ACTIONS}" "${TEST_CASE}/before-reuse"
run_script "${SCRIPT_DIR}/prepare_bison.sh"
assert_result success
cmp "${TEST_ACTIONS}" "${TEST_CASE}/before-reuse"

new_case upgrade-download
unset BISON_SOURCE_ARCHIVE
run_script "${SCRIPT_DIR}/prepare_bison.sh"
assert_result success
grep -q '^download$' "${TEST_ACTIONS}"

new_case corrupt-archive
printf 'invalid archive\n' > "${TEST_CASE}/corrupt.tar.xz"
export BISON_SOURCE_ARCHIVE="${TEST_CASE}/corrupt.tar.xz"
run_script "${SCRIPT_DIR}/prepare_bison.sh"
assert_result failure
[[ ! -e "${TEST_ACTIONS}" && ! -e "${BISON_INSTALL_PREFIX}/bin/bison" ]]

for stage in download configure build install; do
    new_case "failed-${stage}"
    export TEST_FAIL_STAGE="${stage}"
    unset BISON_SOURCE_ARCHIVE
    run_script "${SCRIPT_DIR}/prepare_bison.sh"
    assert_result failure
    ! grep -q 'Bison preparation complete' "${TEST_CASE}/result.log"
done

new_case invalid-installed-version
export TEST_INSTALLED_VERSION=3.5
run_script "${SCRIPT_DIR}/prepare_bison.sh"
assert_result failure
grep -q 'does not meet' "${TEST_CASE}/result.log"

new_case prepare-failed-download
export TEST_FAIL_STAGE=download
unset BISON_SOURCE_ARCHIVE
if bash "${SCRIPT_DIR}/local_install.sh" prepare > "${TEST_CASE}/result.log" 2>&1; then RESULT=0; else RESULT=$?; fi
assert_result failure
! grep -q 'Prepare env success' "${TEST_CASE}/result.log"

new_case prepare-failed-yum
export TEST_YUM_EXIT=42
if bash "${SCRIPT_DIR}/local_install.sh" prepare > "${TEST_CASE}/result.log" 2>&1; then RESULT=0; else RESULT=$?; fi
assert_result failure
[[ ! -e "${TEST_ACTIONS}" ]]
! grep -q 'Prepare env success' "${TEST_CASE}/result.log"

echo 'All Bison preparation checks passed (compilation and yum calls mocked).'
