#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
SCRIPT_TOP_DIR=$(cd ${CURRENT_PATH}; pwd)

CI_TOP_DIR=$(cd ${SCRIPT_TOP_DIR}/..; pwd)
OG_OM_ROOT=$(cd ${CURRENT_PATH}/../og_om; pwd)
OG_REQUIREMENTS_PATH=${OG_OM_ROOT}/requirements.txt

SERVICE_NAME=oGRAC
MODULE_NAME=og_om

TEMP_PATH="${CI_TOP_DIR}/temp/ograc/package/temp"
OG_OM_COMPONENT_PATH="${CI_TOP_DIR}/opt/og_om"
OG_OM_SITE_PACKAGES_PATH="${TEMP_PATH}/venv/lib64/python*/site-packages"


# 清理环境，og_om编译临时路径
function init_temp_dir()
{
    echo "Begin to initialize temporary dir. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d ${TEMP_PATH} ]; then
        rm -rf ${TEMP_PATH}
    fi
    mkdir -p "${TEMP_PATH}" && mkdir -p "${OG_OM_COMPONENT_PATH}"
    return 0
}

# 拷贝og_om下的og_om文件夹
function copy_og_om_src()
{
    if [ -d ${OG_OM_ROOT} ]; then
        cp -rf ${OG_OM_ROOT}/. ${OG_OM_COMPONENT_PATH}
        if [ $? -ne 0 ]; then
            echo "Failed to copy og_om source code. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
        return 0
    else
        echo "${OG_OM_ROOT} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
}

function main()
{
    echo "Begin to build og_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    # 准备环境
    init_temp_dir

    # 复制og_om库的src
    copy_og_om_src
    if [ $? -ne 0 ]; then
        echo "Failed to copy og_om src. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    echo "Succeed in building og_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

main
exit $?