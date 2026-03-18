#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
STOP_SCRIPT_PATH="/opt/ograc/og_om/service/ograc_exporter/scripts"
FORCE_TYPE=$2

source ${CURRENT_PATH}/og_om_log.sh

OG_OM_INSTALL_PATH="/opt/ograc/og_om"

function check_installed()
{
    [ -d "${OG_OM_INSTALL_PATH}" ] && [ "$(ls -A ${OG_OM_INSTALL_PATH} 2>/dev/null)" ]
    return $?
}

function uninstall_og_om()
{
    rm -rf ${OG_OM_INSTALL_PATH}
    return $?
}

function main()
{
    if [ "x${FORCE_TYPE}" == "xforce" ]; then  # 强制卸载避免ogmgr进程残留
        local ogmgr_pid=$(ps -ef | grep "/opt/ograc/og_om/service/ogmgr/uds_server.py" | grep -v grep | awk '{print $2}')
        if [ -n ${ogmgr_pid} ]; then
            kill -9 ${ogmgr_pid}
        fi
    fi

    # 检查ogmgr是否已经停止
    local active_service=$(ps -ef | grep /opt/ograc/og_om/service/ogmgr/uds_server.py | grep python)
    if [[ ${active_service} != "" ]]; then
        logAndEchoError "please stop ogmgr first"
        exit 1
    fi

    # 检查ograc_exporter是否已经停止
    local py_pid=$(ps -ef | grep "/opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ -n "${py_pid}" ];then
        logAndEchoError "please stop ograc_exporter first"
        exit 1
    fi

    check_installed > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "Start to uninstall og_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"

        uninstall_og_om > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            logAndEchoInfo "Success to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 0
        else
            logAndEchoError "Fail to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi

    else
        logAndEchoInfo "og_om is not installed, no need to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    fi
}

main
