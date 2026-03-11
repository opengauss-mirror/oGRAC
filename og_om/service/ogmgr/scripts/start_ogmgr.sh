#!/bin/bash

WAIT_TIME=2
CURRENT_PATH=$(dirname "$(readlink -f "$0")")
OGMGR_DIR=$(dirname "${CURRENT_PATH}")
SERVICE_DIR=$(dirname "${OGMGR_DIR}")
SOCKET_SCRIPT="${OGMGR_DIR}/uds_server.py"
DEPLOY_LOG="${OGMGR_DIR}/ogmgr_log/ogmgr_deploy.log"

export PYTHONPATH="${OGMGR_DIR}"
source ${CURRENT_PATH}/log4sh.sh

function check_status() {
    active_service=$(ps -ef | grep "python3 ${SOCKET_SCRIPT}" | grep -v grep)
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
    mkdir -p "$(dirname "${DEPLOY_LOG}")"
    nohup python3 "${SOCKET_SCRIPT}" >> "${DEPLOY_LOG}" 2>&1 < /dev/null &
    sleep ${WAIT_TIME}
    check_status
    if [ $? -ne 0 ]; then
        logAndEchoError "start ogmgr fail please check ${OGMGR_DIR}/ogmgr_log/deploy.log"
        exit 1
    else
        logAndEchoInfo "start ogmgr success"
        exit 0
    fi
fi