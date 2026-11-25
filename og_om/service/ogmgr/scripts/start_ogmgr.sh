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

WAIT_TIME=2
CURRENT_PATH=$(dirname $(readlink -f $0))

export PYTHONPATH=/opt/ograc/og_om/service/ogmgr/
source ${CURRENT_PATH}/log4sh.sh

function check_status() {
    active_service=$(ps -ef | grep /opt/ograc/og_om/service/ogmgr/uds_server.py | grep python)
    if [[ ${active_service} != "" ]]; then
        return 0
    else
        return 1
    fi
}

check_status
if [ $? -eq 0 ]; then
    logAndEchoInfo "ogmgr already in service"
else
    python3 /opt/ograc/og_om/service/ogmgr/uds_server.py &
    sleep ${WAIT_TIME}
    check_status
    if [ $? -ne 0 ]; then
        logAndEchoError "start ogmgr fail please check /opt/ograc/og_om/service/ogmgr/ogmgr_log/deploy.log"
        exit 1
    else
        logAndEchoInfo "start ogmgr success"
        exit 0
    fi
fi