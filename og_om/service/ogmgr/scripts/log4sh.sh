#!/bin/bash
set +x

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME=${CURRENT_PATH}/$(basename "$0")
OGMGR_DIR=$(dirname "${CURRENT_PATH}")
OM_DEPLOY_LOG_PATH="${OGMGR_DIR}/ogmgr_log"
OM_DEPLOY_LOG_FILE="${OM_DEPLOY_LOG_PATH}/ogmgr_deploy.log"

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
