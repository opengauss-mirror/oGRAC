#!/bin/bash
set +x
umask 0022
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

SCRIPT_TOP_DIR=$(cd ${CURRENT_PATH}; pwd)
CI_TOP_DIR=$(cd ${SCRIPT_TOP_DIR}/..; pwd)

MODULE_NAME=og_om

VERSIONS_YML="${CI_TOP_DIR}/build/versions.yml"
if [[ -f "${VERSIONS_YML}" ]]; then
    MODULE_VERSION=$(grep 'Version:' "${VERSIONS_YML}" | awk '{print $2}')
fi
MODULE_VERSION=${MODULE_VERSION:-1.0.0}

# 由 build_ograc_om.sh 创建并填充的源文件目录
og_om_component_path="${CI_TOP_DIR}/opt/og_om"

# 打包输出目录
PKG_OUTPUT_PATH="${CI_TOP_DIR}/temp/${MODULE_NAME}"

###############################################################################################
## 将源文件打成 tar.gz 包
###############################################################################################
function build_tar_package()
{
    local pkg_name="${MODULE_NAME}-${MODULE_VERSION}"
    echo "Begin to build ${pkg_name}.tar.gz. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    if [ ! -d "${og_om_component_path}" ]; then
        echo "${og_om_component_path} does not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    mkdir -p "${PKG_OUTPUT_PATH}"
    if [ $? -ne 0 ]; then
        echo "Failed to mkdir ${PKG_OUTPUT_PATH}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    cd "${og_om_component_path}"
    tar zcvf "${PKG_OUTPUT_PATH}/${pkg_name}.tar.gz" *
    if [ $? -ne 0 ]; then
        echo "Failed to create ${pkg_name}.tar.gz. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    echo "Succeed in making ${pkg_name}.tar.gz at ${PKG_OUTPUT_PATH}/. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

###############################################################################################
## 清理源文件目录
###############################################################################################
function clear_venv()
{
    echo "Begin to delete ${og_om_component_path}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d "${og_om_component_path}" ]; then
        rm -rf "${og_om_component_path}"
        echo "Succeed in deleting ${og_om_component_path}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi

    return 0
}

function main()
{
    build_tar_package
    if [ $? -ne 0 ]; then
        echo "Failed to build tar.gz package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    clear_venv
    return 0
}

main
ret=$?
if [ $ret -eq 0 ]; then
    echo "Succeed in building ${MODULE_NAME} package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
else
    echo "Failed to build ${MODULE_NAME} package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi
exit $ret
