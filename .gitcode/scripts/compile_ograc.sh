#!/usr/bin/env bash
set -euo pipefail

echo "gitcodePullRequestIid: ${GITCODE_PR_IID:-}"
echo "gitcodeAfterCommitSha: ${GITCODE_AFTER_COMMIT_SHA:-}"
echo "gitcodeRef: refs/merge-requests/${GITCODE_PR_IID:-}/merge"
echo "gitcodeMergeRef: ${GITCODE_MERGE_REF:-}"

git config --global core.compression 0

gitcodeTargetBranch="${GITCODE_TARGET_BRANCH:-master}"
if [[ -z "${gitcodeTargetBranch}" ]]; then
  gitcodeTargetBranch=master
fi
echo "gitcodeTargetBranch: ${gitcodeTargetBranch}"
echo "Triggered by gitcode Pull Request #${GITCODE_PR_IID:-}: https://gitcode.com/opengauss/oGRAC/pulls/${GITCODE_PR_IID:-}"

# oGRAC/UB 分支跳过门禁检查
if [[ "${gitcodeTargetBranch}" == "UB" || "${gitcodeTargetBranch}" == "develop" || "${gitcodeTargetBranch}" == "UB_dev" ]]; then
  echo "Skip gate for ${gitcodeTargetBranch}"
  exit 0
fi

oGRAC_repo="${OGRAC_REPO:-https://gitcode.com/opengauss/oGRAC.git}"
WORKSPACE="${WORKSPACE_ROOT:?WORKSPACE_ROOT is required}"
container_name="cantian_dev-dev"

export WORKSPACE
export gitcodeTargetBranch

cleanup() {
  docker stop "${container_name}" >/dev/null 2>&1 || true
  if [[ -n "${WORKSPACE:-}" && -d "${WORKSPACE}" ]]; then
    rm -rf "${WORKSPACE:?}"/*
  fi
}

download_source_from_gitcode() {
  local repo="$1"
  local branch="$2"
  local target_dir="$3"
  local a=0
  local flag=0

  echo "download source [${repo}], branch [${branch}]"

  while [[ "${a}" -lt 10 ]]; do
    echo "${a}"
    rm -rf "${WORKSPACE:?}/${target_dir}"
    if timeout 5m git clone "${repo}" -b "${branch}" "${WORKSPACE}/${target_dir}"; then
      flag=1
      break
    fi
    a=$((a + 1))
    sleep 10
  done

  if [[ "${flag}" == 0 ]]; then
    echo "clone ${target_dir} failed!"
    exit 1
  fi
}

download_source() {
  mkdir -p "${WORKSPACE}"
  download_source_from_gitcode "${oGRAC_repo}" "${gitcodeTargetBranch}" code
}

merge_source_code() {
  cd "${WORKSPACE}/code"

  echo "cbb_repo: ${oGRAC_repo}"
  echo "gitcodeRef: ${GITCODE_MERGE_REF:-}"

  git config --global user.email "${GIT_AUTHOR_EMAIL:-gitcode-actions@users.noreply.gitcode.com}"
  git config --global user.name "${GIT_AUTHOR_NAME:-gitcode-actions}"
  git rev-parse --is-inside-work-tree
  git config remote.origin.url "${oGRAC_repo}"

  if [[ -n "${GITCODE_PR_IID:-}" ]]; then
    git fetch origin "refs/merge-requests/${GITCODE_PR_IID}/head:refs/merge-requests/${GITCODE_PR_IID}/head"
    git merge --no-verify "refs/merge-requests/${GITCODE_PR_IID}/head" --no-edit
  else
    echo "No GITCODE_PR_IID found; skip PR head merge."
  fi
}

oGRAC_run_mtr() {
  cd "${WORKSPACE}/code"
  sh docker/container.sh rundev
  docker exec -i "${container_name}" /bin/bash -c '
    set -e
    dt_res="Error"
    echo "prepare do_all_test"
    git config --global --add safe.directory /home/regress/ogracKernel
    git config --global --add safe.directory /home/regress/ogracKernel/open_source
    OS_VERSION=$(cat /etc/openEuler-release 2>/dev/null | grep -oP "\d+\.\d+" | head -1 || echo "22.03")

    rm -f /etc/yum.repos.d/*.repo
    cat > /etc/yum.repos.d/openEuler.repo << EOF

[OS]
name=OS
baseurl=https://repo.huaweicloud.com/openeuler/openEuler-${OS_VERSION}-LTS/OS/\$basearch/
enabled=1
gpgcheck=0

[everything]
name=everything
baseurl=https://repo.huaweicloud.com/openeuler/openEuler-${OS_VERSION}-LTS/everything/\$basearch/
enabled=1
gpgcheck=0

[update]
name=update
baseurl=https://repo.huaweicloud.com/openeuler/openEuler-${OS_VERSION}-LTS/update/\$basearch/
enabled=1
gpgcheck=0
EOF

    yum clean all
    yum makecache

    echo "Installing iputils and iproute..."
    yum install -y --nogpgcheck iputils iproute numactl-devel

    echo "Fixing lz4 version conflict..."
    echo "Current lz4 version:"
    rpm -q lz4

    rpm -e --nodeps lz4 2>/dev/null || true

    echo "Installing lz4 and lz4-devel with compatible versions..."
    yum install -y --nogpgcheck lz4 lz4-devel  || {
        echo "Failed to install matching versions, trying alternative..."
        yum downgrade -y --nogpgcheck lz4 2>/dev/null || true
        yum install -y --nogpgcheck lz4-devel --allowerasing
    }

    echo "Verifying lz4 packages..."
    rpm -qa | grep lz4

    echo "Fixing lz4 header file paths..."
    if [ -d /usr/include/lz4 ]; then
        ln -sf /usr/include/lz4/*.h /usr/include/ 2>/dev/null || true
        echo "Linked lz4 headers from /usr/include/lz4/ to /usr/include/"
    fi

    if ! echo "#include <lz4.h>" | gcc -E -x c - >/dev/null 2>&1; then
        echo "Warning: lz4.h still not accessible, setting include path..."
        export C_INCLUDE_PATH="/usr/include/lz4:$C_INCLUDE_PATH"
        export CPLUS_INCLUDE_PATH="/usr/include/lz4:$CPLUS_INCLUDE_PATH"
    fi

    echo "Installing lcov..."
    if ! yum install -y --nogpgcheck lcov; then
        echo "lcov not found in repository, trying to install from EPOL or alternative source..."
        cat >> /etc/yum.repos.d/openEuler.repo << EOF

[EPOL]
name=EPOL
baseurl=https://repo.huaweicloud.com/openeuler/openEuler-${OS_VERSION}-LTS/EPOL/\$basearch/main/
enabled=1
gpgcheck=0
EOF
        yum makecache --disablerepo=* --enablerepo=EPOL 2>/dev/null || true
        yum install -y --nogpgcheck lcov || {
            echo "lcov installation failed, but continuing..."
        }
    fi
    echo "Starting regression tests..."
    bash /home/regress/ogracKernel/pkg/test/og_regress/do_all_test.sh need_compile

    if [[ -f "/home/regress/ogracKernel/regress_output/test_result.txt" ]]; then
        dt_res="$(tail -n 1 /home/regress/ogracKernel/regress_output/test_result.txt)"
    fi
    if [ "${dt_res}" != "Test Result: Success" ]; then
        echo "Test Result: ERROR"
        exit 1
    fi
  '
}

main() {
  trap cleanup EXIT
  download_source
  merge_source_code
  echo "hello oGRAC"
  result="Error"
  cd "${WORKSPACE}/code"
  if ! oGRAC_run_mtr; then
    echo "Test Result: ERROR"
    exit 1
  fi

  if [[ -f "${WORKSPACE}/code/regress_output/test_result.txt" ]]; then
    result="$(tail -n 1 "${WORKSPACE}/code/regress_output/test_result.txt")"
  fi

  echo "result: ${result}"
  echo "pwd: $(pwd)"
  if [[ "${result}" != "Test Result: Success" ]]; then
    echo "Test Result: ERROR"
    exit 1
  fi
  echo "SUCCESS ACCESS CONTROL"
}

main
