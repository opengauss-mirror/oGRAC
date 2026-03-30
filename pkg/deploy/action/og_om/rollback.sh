#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
TARGET_PACKAGE_NAME=""
BACKUP_FILE_NAME=$1
version=$(cat ${BACKUP_FILE_NAME}/versions.yml | grep -E "Version:" | awk '{print $2}' | sed 's/\([0-9]*\.[0-9]*\)\(\.[0-9]*\)\?\.[A-Z].*/\1\2/')
source ${CURRENT_PATH}/og_om_log.sh

OG_OM_INSTALL_PATH="/opt/ograc/og_om"

function get_target_package_name() {
    TARGET_PACKAGE_NAME=$(ls ${BACKUP_FILE_NAME}/repo | grep og_om-${version})
}

function main() {
    logAndEchoInfo "Begin to start og_om rollback. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    get_target_package_name
    if [[ -z "${TARGET_PACKAGE_NAME}" ]]; then
        logAndEchoError "Obtain target rollback package name failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    # 卸载已安装的og_om
    if [ -d "${OG_OM_INSTALL_PATH}" ]; then
        rm -rf ${OG_OM_INSTALL_PATH}
        if [ $? -ne 0 ]; then
            logAndEchoError "Uninstall old og_om failed.[Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
    fi

    # 回滚到target版本
    mkdir -p ${OG_OM_INSTALL_PATH}
    tar -zxf ${BACKUP_FILE_NAME}/repo/${TARGET_PACKAGE_NAME} -C ${OG_OM_INSTALL_PATH}
    if [ $? -ne 0 ]; then
        logAndEchoError "Install target package failed.[Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Rollback successful. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

main
