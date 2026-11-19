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

CURRENT_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ACTION_CONFIG="${CURRENT_PATH}/../../action/config.py"
if [ -f "${ACTION_CONFIG}" ]; then
    eval "$(python3 "${ACTION_CONFIG}" --shell-env 2>/dev/null)"
fi

OGRAC_HOME="${OGRAC_HOME:-$(cd "${CURRENT_PATH}/../.." && pwd)}"
OM_DEPLOY_LOG_PATH="${DEPLOY_LOG_DIR:-${OGRAC_HOME}/log/deploy}"
OM_DEPLOY_LOG_FILE="${DEPLOY_DAEMON_LOG:-${OM_DEPLOY_LOG_FILE:-${OM_DEPLOY_LOG_PATH}/deploy_daemon.log}}"
SCRIPT_NAME=${CURRENT_PATH}/$(basename "${BASH_SOURCE[0]}")
LOG_MOD=640
LOG_MOD_STR='rw-r-----'

initLog4sh()
{
    if [ ! -d "${OM_DEPLOY_LOG_PATH}" ]; then
        mkdir -p "${OM_DEPLOY_LOG_PATH}"
    fi
    if [ ! -f "${OM_DEPLOY_LOG_FILE}" ];then
        touch "${OM_DEPLOY_LOG_FILE}"
        chmod 640 "${OM_DEPLOY_LOG_FILE}"
    fi
    # 修改日志文件权限
    file_mod=$(ls -l "${OM_DEPLOY_LOG_FILE}" | awk '{print $1}')
    if [[ ! "${file_mod}" =~ ${LOG_MOD_STR} ]]; then
        chmod ${LOG_MOD} "${OM_DEPLOY_LOG_FILE}"
        if [ $? -ne 0 ]; then
            logAndEchoError "correct ${OM_DEPLOY_LOG_FILE} mode failed"
            exit 1
        fi
    fi
}

_logInfo() {
    initLog4sh;
    printf "[%s] [%s] [%-5d] [%s] " "$(date "+%Y-%m-%d %H:%M:%S,%N %z")" "INFO" "$$" "$(basename "${BASH_SOURCE[2]}") ${BASH_LINENO[1]}" 1>> "${OM_DEPLOY_LOG_FILE}" 2>&1; echo "$@" 1>> "${OM_DEPLOY_LOG_FILE}" 2>&1;
}

_logWarn() {
    initLog4sh;
    printf "[%s] [%s] [%-5d] [%s] " "$(date "+%Y-%m-%d %H:%M:%S,%N %z")" "WARN" "$$" "$(basename "${BASH_SOURCE[2]}") ${BASH_LINENO[1]}" 1>> "${OM_DEPLOY_LOG_FILE}" 2>&1; echo "$@" 1>> "${OM_DEPLOY_LOG_FILE}" 2>&1;

}

_logError() {
    initLog4sh;
    printf "[%s] [%s] [%-5d] [%s] " "$(date "+%Y-%m-%d %H:%M:%S,%N %z")" "ERROR" "$$" "$(basename "${BASH_SOURCE[2]}") ${BASH_LINENO[1]}" 1>> "${OM_DEPLOY_LOG_FILE}" 2>&1; echo "$@" 1>> "${OM_DEPLOY_LOG_FILE}" 2>&1;
}
logInfo() { _logInfo "$@"; }
logWarn() { _logWarn "$@"; }
logError() { _logError "$@"; }

logAndEchoInfo() { _logInfo "$@"; echo -ne "[INFO ] $@\n"; }
logAndEchoWarn() { _logWarn "$@"; echo -ne "[WARN ] $@\n"; }
logAndEchoError() { _logError "$@"; echo -ne "[ERROR] $@\n"; }
