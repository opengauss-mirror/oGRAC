#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
MAIN_PATH=$(dirname $(dirname ${CURRENT_PATH}))

source ${CURRENT_PATH}/og_om_log.sh
version=$(cat ${CURRENT_PATH}/../../versions.yml | grep -E "Version:" | awk '{print $2}' | \sed 's/\([0-9]*\.[0-9]*\)\(\.[0-9]*\)\?\.[A-Z].*/\1\2/')

OG_OM_INSTALL_PATH="/opt/ograc/og_om"

function check_installed()
{
    [ -d "${OG_OM_INSTALL_PATH}" ] && [ "$(ls -A ${OG_OM_INSTALL_PATH} 2>/dev/null)" ]
    return $?
}

function install_og_om()
{
    mkdir -p ${OG_OM_INSTALL_PATH}
    tar -zxf ${MAIN_PATH}/repo/og_om-${version}*.tar.gz -C ${OG_OM_INSTALL_PATH}
    return $?
}

function main()
{
    # 检查rpm是否已经安装
    if [ -f /opt/ograc/installed_by_rpm ]; then
        rpm -qa | grep "ograc_all_in_one"
        if [ $? -eq 0 ]; then
            logAndEchoInfo "Rpm package has been installed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
        return 0
    fi
    check_installed > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "og_om has been installed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoInfo "Begin to remove old installation."
        rm -rf ${OG_OM_INSTALL_PATH}
        if [ $? -ne 0 ]; then
            logAndEchoError "Remove old installation failed."
            return 1
        fi
        logAndEchoInfo "Remove old installation success"
    fi

    install_og_om > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "Success to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    else
        logAndEchoError "Fail to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
}

main
