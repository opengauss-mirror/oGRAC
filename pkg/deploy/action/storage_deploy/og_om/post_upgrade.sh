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
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
VERSION_YML_PATH="/opt/ograc/"
TAR_PACKAGE_NAME=""
OG_OM_INSTALL_PATH="/opt/ograc/og_om"
source ${CURRENT_PATH}/og_om_log.sh

function get_tar_package_name() {
    TAR_PACKAGE_NAME=$(ls ${VERSION_YML_PATH}/repo | grep og_om-)
}

function main()
{
    logAndEchoInfo "Begin to start og_om post upgrade check. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    if [ ! -d "${OG_OM_INSTALL_PATH}" ] || [ -z "$(ls -A ${OG_OM_INSTALL_PATH} 2>/dev/null)" ]; then
        logAndEchoError "og_om is not installed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    get_tar_package_name
    if [[ -z ${TAR_PACKAGE_NAME} ]]; then
        logAndEchoError "Obtain target tar.gz package name failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Post upgrade check completes, everything goes right. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0

}

main
