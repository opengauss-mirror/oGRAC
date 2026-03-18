#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
MODULE_NAME=og_om
og_om_log=/opt/ograc/og_om/log/og_om.log
VERSION_YML_PATH="${CURRENT_PATH}/../.."
SOURCE_PATH='/opt/ograc/og_om/service/ograc_exporter/exporter_data'
TARGET_PACKAGE_NAME=""
BACKUP_FILE_NAME=$1
OG_OM_BACKUP_FILE_NAME=og_om_backup_$(date "+%Y%m%d%H%M%S")
version=$(cat ${VERSION_YML_PATH}/versions.yml | grep -E "Version:" | awk '{print $2}' | sed 's/\([0-9]*\.[0-9]*\)\(\.[0-9]*\)\?\.[A-Z].*/\1\2/')
source ${CURRENT_PATH}/og_om_log.sh

OG_OM_INSTALL_PATH="/opt/ograc/og_om"

function get_target_package_name() {
    TARGET_PACKAGE_NAME=$(ls ${VERSION_YML_PATH}/repo | grep og_om-${version})
}

function main()
{
    logAndEchoInfo "Begin to og_om upgrade. ${MODULE_NAME}. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    get_target_package_name
    if [[ -z "${TARGET_PACKAGE_NAME}" ]]; then
      logAndEchoError "Obtain package name failed. 'package name' should be a non-empty string.[Line:${LINENO}, File:${SCRIPT_NAME}]"
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

    # 安装target版本
    mkdir -p ${OG_OM_INSTALL_PATH}
    tar -zxf ${VERSION_YML_PATH}/repo/${TARGET_PACKAGE_NAME} -C ${OG_OM_INSTALL_PATH}
    if [ $? -ne 0 ]; then
        logAndEchoError "Install target package failed.[Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Upgrade successful. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0

}

main
