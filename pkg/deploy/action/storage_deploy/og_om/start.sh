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
SERVICE_SCRIPT_PATH_OGMGR=/opt/ograc/og_om/service/ogmgr/scripts
WAIT_TIME=3

function start_ogmgr() {
    sh ${SERVICE_SCRIPT_PATH_OGMGR}/start_ogmgr.sh
}

function main()
{
    start_ogmgr
    if [ $? -ne 0 ]; then
        return 1
    fi

    sleep ${WAIT_TIME}
    return 0
}

main
