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

LOG_PATH=${LOG_PATH:-"/opt/ograc/log/deploy"}
LOG_FILE=${LOG_FILE:-"${LOG_PATH}/deploy.log"}

init_deploy_logging() {
    if [ ! -d "${LOG_PATH}" ]; then
        mkdir -p "${LOG_PATH}"
    fi
    if [ ! -f "${LOG_FILE}" ]; then
        touch "${LOG_FILE}"
    fi
}

_log() {
    local level=$1
    shift
    printf "[%s] [%s] [%-5d] [%s:%s] " \
        "$(date -d today "+%Y-%m-%d %H:%M:%S,%N %z")" \
        "${level}" \
        "$$" \
        "$(basename "${BASH_SOURCE[2]}")" \
        "${BASH_LINENO[1]}" 1>> "${LOG_FILE}" 2>&1
    echo "$@" 1>> "${LOG_FILE}" 2>&1
}

logInfo() { _log "INFO" "$@"; }
logWarn() { _log "WARN" "$@"; }
logError() { _log "ERROR" "$@"; }

logAndEchoInfo() { logInfo "$@"; echo -ne "[INFO ] $@\n"; }
logAndEchoWarn() { logWarn "$@"; echo -ne "[WARN ] $@\n"; }
logAndEchoError() { logError "$@"; echo -ne "[ERROR] $@\n"; }

init_deploy_logging