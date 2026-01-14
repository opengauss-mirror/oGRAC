#!/bin/bash
set +x
umask 0022
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/common.sh
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
SCRIPT_TOP_DIR=$(cd ${CURRENT_PATH}; pwd)
RPMSOURCE_PATH="${OGRACDB_OUTPUT}/rpm/SOURCES"
MODULE_NAME=ograc_all_in_one
SPEC_FILE="${CURRENT_PATH}/${MODULE_NAME}.spec"

function tar_console_rpm()
{
    echo "Begin to tar component rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    local name="$(getSpecParamVal "${SPEC_FILE}" Name)"
    local version="$(getSpecParamVal "${SPEC_FILE}" Version)"
    if [ -d "${RPMSOURCE_PATH}" ]; then
        cd ${RPMSOURCE_PATH}
        if [ $? -ne 0 ]; then
            echo "Failed to cd ${RPMSOURCE_PATH}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
        echo "Current directory: $(pwd)"
        echo "Contents of current directory:"
        ls -la
        rm -f ${RPMSOURCE_PATH}/${name}.tar.gz
        echo "Generating all-in-one tar..."
        tar zcvf ${name}.tar.gz * || echo "Generate all-in-one tar failed and errcode is: $?"
        if [ $? -ne 0 ]; then
            echo "Failed to make ${name}.tar.gz package. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi

        echo "Succeed in making ${name}.tar.gz package. [Line:${LINENO}, File:${SCRIPT_NAME} "
        rm -rf ${RPMSOURCE_PATH}/opt
        return 0
    else
        echo "${RPMSOURCE_PATH} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

function build_console_rpm()
{
    echo "Begin to build rpm ${MODULE_NAME}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    local name="$(getSpecParamVal "${SPEC_FILE}" Name)"
    local RPM_TOP_DIR="${OGRACDB_OUTPUT}/rpm"
    cp -rf ${SPEC_FILE} ${RPM_TOP_DIR}/SPECS/
    if [ $? -ne 0 ]; then
        echo "Failed to copy files: ${name} to ${RPM_TOP_DIR}, [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    echo "Begin to build rpm to ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    cd ${RPM_TOP_DIR}/SPECS
    echo "rpmbuild --define '_topdir ${RPM_TOP_DIR}' --define '_build_id_links none' -bb ${MODULE_NAME}.spec"
    eval "rpmbuild --define '_topdir ${RPM_TOP_DIR}' --define '_build_id_links none' -bb ${MODULE_NAME}.spec"
    if [ $? -ne 0 ]; then
        echo "Failed to build rpm package to ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    echo "Succeed in building rpm package. [Line:${LINENO}, File:${SCRIPT_NAME}"
    return 0
}

function clear_venv()
{
    local RPM_TOP_DIR="${OGRACDB_OUTPUT}/rpm"
    echo "Begin to delete ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -d "${RPM_TOP_DIR}" ]; then
        rm -rf "${RPM_TOP_DIR}"
        echo "Succeed in deleting ${RPM_TOP_DIR}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
    return 0
}

###############################################################################################
## 获取spec文件的参数值
###############################################################################################
function getSpecParamVal()
{
    local specFile="$1"
    local paraName="$2"
    local paraVal=""

    [ -f "${specFile}" ] || { return 1; }

    paraVal=$(grep -w  ^"${paraName}" "${specFile}" | awk -F":" '{print $2}')
    echo ${paraVal}
    return 0
}


function main()
{
    tar_console_rpm
    if [ $? -ne 0 ]; then
        echo "Failed to tar console rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    build_console_rpm
    if [ $? -ne 0 ]; then
        echo "Failed to build rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    # clear_venv
    return 0
}

main
ret=$?
if [ $ret -eq 0 ]; then
    echo "Succeed in building all-in-one oGRAC rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
else
    echo "Failed to build all-in-one oGRAC rpm. [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi
exit $ret