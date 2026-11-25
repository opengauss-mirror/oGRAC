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
SERVICE_SCRIPT_PATH=/opt/ograc/og_om/service/

sh ${CURRENT_PATH}/check_status.sh
if [ $? -ne 0 ]; then
    echo "ogmgr has been offline already"
    exit 0
fi


function stop_ogmgr()
{
    sh ${SERVICE_SCRIPT_PATH}/ogmgr/scripts/stop_ogmgr.sh
    return $?
}

function main()
{
    stop_ogmgr
    return $?
}

main
