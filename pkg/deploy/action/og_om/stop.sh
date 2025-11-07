#!/bin/bash
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
