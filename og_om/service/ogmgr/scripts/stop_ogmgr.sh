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

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
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
    ogmgr_pid=$(ps -ef | grep "/opt/ograc/og_om/service/ogmgr/uds_server.py" | grep -v grep | awk '{print $2}')
    kill -9 ${ogmgr_pid}
    if [ $? -eq 0 ]; then
        rm -rf /opt/ograc/og_om/service/og_om.sock
        logAndEchoInfo "success stop ogmgr"
        exit 0
    else
        logAndEchoError "fail to stop ogmgr"
        exit 1
    fi
else
    logAndEchoInfo "ogmgr already stopped"
    exit 0
fi
