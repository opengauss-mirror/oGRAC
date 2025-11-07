#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
VERSION_YML_PATH="/opt/ograc/"
RPM_PACKAGE_NAME=""
source ${CURRENT_PATH}/og_om_log.sh

function get_rpm_package_name() {
    RPM_PACKAGE_NAME=$(ls ${VERSION_YML_PATH}/repo | grep og_om-)
}

function main()
{
    logAndEchoInfo "Begin to start og_om post upgrade check. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    installed_package=$(rpm -qa|grep og_om-)
    if [[ -z ${installed_package} ]]; then
        logAndEchoError "Obtain installed rpm package name failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    get_rpm_package_name
    if [[ -z ${RPM_PACKAGE_NAME} ]]; then
        logAndEchoError "Obtain target rpm package name failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    if [[ ${installed_package}.rpm != ${RPM_PACKAGE_NAME} ]]; then
        logAndEchoError "Currently installed version number is inconsistent with the target one. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Post upgrade check completes, everything goes right. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0

}

main