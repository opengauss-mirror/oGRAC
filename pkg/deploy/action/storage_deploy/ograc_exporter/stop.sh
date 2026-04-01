#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
SERVICE_SCRIPT_PATH=/opt/ograc/og_om/service/ograc_exporter/scripts

source ${CURRENT_PATH}/ograc_exporter_log.sh

# 如果ograc_exporter没有拉起，不停止
sh ${CURRENT_PATH}/check_status.sh
if [ $? -ne 0 ]; then
    logAndEchoInfo "og_export has been offline already"
    exit 0
fi

function stop_exporter()
{
    sh ${SERVICE_SCRIPT_PATH}/stop_ograc_exporter.sh
    return $?
}

function main()
{
    logAndEchoInfo "Begin to stop og_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    stop_exporter >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "Fail to stop og_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Success to stop og_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

main
