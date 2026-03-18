#!/bin/bash
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
