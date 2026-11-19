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

OM_DEPLOY_LOG_PATH=/opt/ograc/og_om/service/ogmgr/ogmgr_log
OM_DEPLOY_LOG_FILE=/opt/ograc/og_om/service/ogmgr/ogmgr_log/ogmgr_deploy.log
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

initLog4sh()
{
    if [ ! -d ${OM_DEPLOY_LOG_PATH} ]; then
        mkdir ${OM_DEPLOY_LOG_PATH}
        touch ${OM_DEPLOY_LOG_FILE}
    fi
}

_logInfo() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "INFO" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}

_logWarn() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "WARN" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;

}

_logError() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "ERROR" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}
logInfo() { _logInfo "$@"; }
logWarn() { _logWarn "$@"; }
logError() { _logError "$@"; }

logAndEchoInfo() { _logInfo "$@"; echo -ne "[INFO ] $@\n"; }
logAndEchoWarn() { _logWarn "$@"; echo -ne "[WARN ] $@\n"; }
logAndEchoError() { _logError "$@"; echo -ne "[ERROR] $@\n"; }
