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
SERVICE_SCRIPT_PATH=/opt/ograc/og_om/service/ograc_exporter/scripts
ograc_exporter_log=/opt/ograc/log/ograc_exporter/ograc_exporter.log
WAIT_TIME=3

source ${CURRENT_PATH}/ograc_exporter_log.sh

function start_exporter()
{
    sh ${SERVICE_SCRIPT_PATH}/start_ograc_exporter.sh >> ${ograc_exporter_log}
    return $?
}

function main()
{
    logAndEchoInfo "Begin to start og_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    start_exporter > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "The og_exporter start error. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    # 根据进程是否在位确定ograc_exporter拉起成功
    sleep ${WAIT_TIME}
    sh ${CURRENT_PATH}/check_status.sh
    if [ $? -ne 0 ]; then
        logAndEchoError "Failed to start og_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Success to start og_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

main
