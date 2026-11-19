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
set -e
CURRENT_PATH=$(dirname $(readlink -f $0))
source ${CURRENT_PATH}/log4sh.sh
source "${CURRENT_PATH}"/env.sh
OM_DEPLOY_LOG_FILE=/opt/ograc/log/deploy/deploy.log
CHECK_POINT_FILE=${CURRENT_PATH}/ograc/upgrade_checkpoint.sh
CHECK_POINT_FLAG=/opt/ograc/check_point.success
node_zore_ip="127.0.0.1"

function get_user_input() {
    read -s -p "please enter ograc_sys_pwd: " ogsql_pwd
    echo ''
}

# 回滚后同步数据间gap
function recover_gap() {
    logAndEchoInfo "Do check point start."
    su - ${ograc_user} -s /bin/bash -c "sh ${CHECK_POINT_FILE} ${node_zore_ip}" >> ${OM_DEPLOY_LOG_FILE}
    if [[ $? -ne 0 ]];then
        logAndEchoError "Check point failed"
        exit 1
    fi
    touch ${CHECK_POINT_FLAG}
    chmod 400 ${CHECK_POINT_FLAG}
    logAndEchoInfo "Do check point success."
}

function check_status() {
    if [ -f ${CHECK_POINT_FLAG} ];then
        rm -rf ${CHECK_POINT_FLAG}
    fi
    logAndEchoInfo "Before check point check ograc status."
    sh /opt/ograc/action/appctl.sh check_status
    if [[ $? -ne 0 ]];then
        logAndEchoError "ograc if offline, can not do check point."
        exit 1
    fi
}

function main() {
    get_user_input
    check_status
    recover_gap
}
main