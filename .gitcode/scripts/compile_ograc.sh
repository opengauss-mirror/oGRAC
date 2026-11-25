#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

echo "BUILD_ID: ${BUILD_ID}"
echo "Branch: ${GITCODE_TARGET_BRANCH:-}"
echo "Triggered by gitcode Pull Request #${GITCODE_PR_IID:-}: https://gitcode.com/opengauss/oGRAC/pulls/${GITCODE_PR_IID:-}"

gitcodeTargetBranch="${GITCODE_TARGET_BRANCH:-}"
gitcodePullRequestIid="${GITCODE_PR_IID:-}"
#oGRAC/UB分支跳过门禁检查
if [[ "${gitcodeTargetBranch}" == "UB" || "${gitcodeTargetBranch}" == "develop"  || "${gitcodeTargetBranch}" == "UB_dev" ]]; then
    exit 0
fi

workspace=/data/jenkins/workspace/oGRAC
oGRAC_repo=https://gitcode.com/opengauss/oGRAC.git

function down_source_from_gitcode() {
    repo=$1
    branch=$2
    target_dir=$3

    a=0
    flag=0
    while [ $a -lt 10 ]; do
        echo $a
        rm -rf ${workspace}/${target_dir}
        timeout 120 git clone ${repo} -b ${branch} "${workspace}/${target_dir}"
        if [[ $? == 0 ]]; then
            flag=1
            break
        fi
        a=$(expr $a + 1)
    done

    if [[ $flag = 0 ]]; then
        echo "clone ${target_dir} failed!"
        exit 1
    fi
}

function merge_source_code() {
    cd ${workspace}/code
    
    #git rev-parse --is-inside-work-tree
    echo "cbb_repo: ${oGRAC_repo}"
    echo "gitcodeRef: ${gitcodeMergeRef}"
    #git config remote.origin.url ${oGRAC_repo}
    #git fetch --tags --force --progress origin ${gitcodeMergeRef}:${gitcodeMergeRef}
    #git checkout -b ${gitcodeMergeRef} ${gitcodeMergeRef}
    git config --global user.email "1234567"
    git config --global user.name "test"
    git rev-parse --is-inside-work-tree
    git config remote.origin.url ${oGRAC_repo}
    git fetch origin refs/merge-requests/${gitcodePullRequestIid}/head:refs/merge-requests/${gitcodePullRequestIid}/head
    git merge --no-verify refs/merge-requests/${gitcodePullRequestIid}/head --no-edit
}

function down_source() {
    
    down_source_from_gitcode ${oGRAC_repo} ${gitcodeTargetBranch} code
}

function oGRAC_run_mtr() {
    cd ${workspace}/code
    echo | sh docker/container.sh dev
    if ! docker exec -i cantian_dev-dev /bin/bash -c '
    set -e
    dt_res="Error"
    echo "prepare do_all_test"
    git config --global --add safe.directory /home/regress/ogracKernel
    git config --global --add safe.directory /home/regress/ogracKernel/open_source
    
    # 检测系统版本
    OS_VERSION=$(cat /etc/openEuler-release 2>/dev/null | grep -oP "\d+\.\d+" | head -1 || echo "22.03")
    
    # 配置仓库
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
    
    # === 安装 iputils 和 iproute ===
    echo "Installing iputils and iproute..."
    yum install -y --nogpgcheck iputils iproute numactl-devel
    
    # === 强制安装匹配的 lz4-devel（先卸载已安装的 lz4） ===
    echo "Fixing lz4 version conflict..."
    echo "Current lz4 version:"
    rpm -q lz4
    
    # 卸载现有的 lz4
    rpm -e --nodeps lz4 2>/dev/null || true
    
    # 安装匹配版本的 lz4 和 lz4-devel
    echo "Installing lz4 and lz4-devel with compatible versions..."
    yum install -y --nogpgcheck lz4 lz4-devel  || {
        echo "Failed to install matching versions, trying alternative..."
        # 如果还是失败，尝试只安装 lz4-devel（看能否自动降级 lz4）
        yum downgrade -y --nogpgcheck lz4 2>/dev/null || true
        yum install -y --nogpgcheck lz4-devel --allowerasing
    }
    
    # === 验证 lz4-devel 安装 ===
    echo "Verifying lz4 packages..."
    rpm -qa | grep lz4
    
    # === 修复 lz4.h 头文件路径 ===
    echo "Fixing lz4 header file paths..."
    if [ -d /usr/include/lz4 ]; then
        ln -sf /usr/include/lz4/*.h /usr/include/ 2>/dev/null || true
        echo "Linked lz4 headers from /usr/include/lz4/ to /usr/include/"
    fi
    
    # 验证 lz4.h 是否可用
    if ! echo "#include <lz4.h>" | gcc -E -x c - >/dev/null 2>&1; then
        echo "Warning: lz4.h still not accessible, setting include path..."
        export C_INCLUDE_PATH="/usr/include/lz4:$C_INCLUDE_PATH"
        export CPLUS_INCLUDE_PATH="/usr/include/lz4:$CPLUS_INCLUDE_PATH"
    fi
    
    # === 安装 lcov（测试覆盖率工具） ===
    echo "Installing lcov..."
    if ! yum install -y --nogpgcheck lcov; then
        echo "lcov not found in repository, trying to install from EPOL or alternative source..."
        # 尝试启用 EPOL 仓库
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
            # lcov 可能不是必需的，只是用于代码覆盖率
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
    '; then
        return 1
    fi
}

down_source
merge_source_code
echo "hello oGRAC"
result="Error"
cd ${workspace}/code
if ! oGRAC_run_mtr; then
    docker stop cantian_dev-dev
    rm -rf ${workspace}/*
    echo "Test Result: ERROR"
    exit 1
fi
cd ${workspace}/code
docker stop cantian_dev-dev
if [ -f "${workspace}/code/regress_output/test_result.txt" ]; then
   result=$(tail -n 1 regress_output/test_result.txt)
fi
rm -rf ${workspace}/*
echo "result: ${result}"
echo "pwd: $(pwd)"
if [ "${result}" != "Test Result: Success" ]; then
  exit 1
fi
echo "SUCCESS ACCESS CONTROL"


