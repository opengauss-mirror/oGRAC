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

set +x
umask 0022

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

MODULE_NAME=ograc
MODULE_VERSION=1.0.0

OGDB_CODE_PATH="${CURRENT_PATH}"/..
oGRAC_component_path="${OGDB_CODE_PATH}/image"

OGRACDB_BIN=$(echo $(dirname $(pwd)))/output/bin

# 打包输出目录
PKG_OUTPUT_PATH="${OGRACDB_BIN}"

###############################################################################################
## 将已有的 ograc.tar.gz 重命名为带版本号的包输出
###############################################################################################
function build_tar_package()
{
    local pkg_name="${MODULE_NAME}-${MODULE_VERSION}"
    local src_tar="${oGRAC_component_path}/${MODULE_NAME}.tar.gz"
    echo "Begin to build ${pkg_name}.tar.gz. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    if [ ! -f "${src_tar}" ]; then
        echo "${src_tar} does not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    mkdir -p "${PKG_OUTPUT_PATH}"
    if [ $? -ne 0 ]; then
        echo "Failed to mkdir ${PKG_OUTPUT_PATH}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    cp -f "${src_tar}" "${PKG_OUTPUT_PATH}/${pkg_name}.tar.gz"
    if [ $? -ne 0 ]; then
        echo "Failed to copy ${pkg_name}.tar.gz to ${PKG_OUTPUT_PATH}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    echo "Succeed in making ${pkg_name}.tar.gz at ${PKG_OUTPUT_PATH}/. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

function main()
{
    build_tar_package
    if [ $? -ne 0 ]; then
        echo "Failed to build tar.gz package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

main
ret=$?
if [ $ret -eq 0 ]; then
    echo "Succeed in building ${MODULE_NAME} package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
else
    echo "Failed to build ${MODULE_NAME} package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi
exit $ret
