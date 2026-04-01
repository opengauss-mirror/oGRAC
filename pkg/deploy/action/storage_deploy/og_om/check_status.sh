#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

function check_ogmgr_status() {
    active_service=$(ps -ef | grep /opt/ograc/og_om/service/ogmgr/uds_server.py | grep python)
    if [[ ${active_service} != "" ]]; then
        return 0
    else
        return 1
    fi
}

function main()
{

    check_ogmgr_status
    return $?
}

main
