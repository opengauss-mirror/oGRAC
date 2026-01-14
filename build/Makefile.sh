#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
PS4=':${LINENO}+'
declare VERSION_DESCRIP=""
declare PACK_PREFIX=""
declare PROJECT_VERSION=""
declare RUN_PACK_DIR_NAME=""
declare ALL_PACK_DIR_NAME=""
declare SYMBOL_PACK_DIR_NAME=""
declare TOOLS_PACK_DIR_NAME=""
declare COMPILE_OPTS=""
declare SHARDING_INNER_TOOLS_PACK_NAME=""
declare JDRIVER_PACK_DIR_NAME=""
declare WITHOUT_DEPS=""
export BUILD_MODE=""
export PYTHON_INCLUDE_DIR=""
export WORKSPACE=$(dirname $(dirname $(pwd)))
DFT_WORKSPACE="/home/regress"

source ./common.sh
source ./function.sh

CONFIG_IN_FILE=${OGRACDB_BUILD}/include/config.h

OGDB_CODE_PATH="${CURRENT_PATH}"/..
CMAKE_C_COMPILER=$(which gcc)
CMAKE_CXX_COMPILER=$(which g++)
PYTHON3_HOME=${PYTHON3_HOME}
INSTALL_DIR=/opt/ogracdb
INITSQL_DIR=../
func_prepare_git_msg
PROJECT_VERSION=$(cat ${CONFIG_IN_FILE} | grep 'PROJECT_VERSION' | awk '{print $3}')
OGRACD_BIN=ogracd-${PROJECT_VERSION}
JDBC_DIR=${OGRACDB_HOME}/src/jdbc/ograc-jdbc/build/oGRAC_PKG
GODRIVER_NAME=go-oGRAC-driver
ZEBRATOOL_DIR=${OGRACDB_HOME}/src/zebratool
OGRAC_LIB_DIR=${OGRACDB_HOME}/../oGRAC_lib
OGRAC_LIB_DIR_TMP=${OGRACDB_HOME}/../oGRAC_lib/tmp/
ENABLE_LLT_GCOV="NO"
ENABLE_LLT_ASAN="NO"
FEATURE_FOR_EVERSQL=${FEATURE_FOR_EVERSQL:-"0"}
OS_ARCH=$(uname -i)

export INTERNAL_BUILD="TRUE"

if [[ ! -d "${OGDB_CODE_PATH}"/../ProductComm_DoradoAA ]];then
    export INTERNAL_BUILD="FALSE"
fi

if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM=`cat /proc/cpuinfo |grep "cores" |wc -l`
    LIB_OS_ARCH="lib_x86"
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then
    export CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    LIB_OS_ARCH="lib_arm"
else
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    export CPU_CORES_NUM=16
fi

echo ${OGRACDB_HOME}
func_prepare_pkg_name()
{
    cd ${OGRACDB_HOME}

    if [[ ! -e "${CONFIG_IN_FILE}" ]]; then
        echo "config file not exist..."
        exit 1
    fi

    VERSION_DESCRIP=$(cat ${CONFIG_IN_FILE} | grep 'VERSION_DESCRIP' | awk '{print $3}')
    PACK_PREFIX=$(cat ${CONFIG_IN_FILE} | grep 'PACK_PREFIX' | awk '{print $3}')
    PROJECT_VERSION=$(cat ${CONFIG_IN_FILE} | grep 'PROJECT_VERSION' | awk '{print $3}')

    # arm_euler临时规避
    if [[ ${OS_ARCH} =~ "aarch64" ]]; then
        OS_SUFFIX=CENTOS
    fi

    RUN_PACK_DIR_NAME=${PACK_PREFIX}-RUN-${OS_SUFFIX}-${ARCH}bit
    ALL_PACK_DIR_NAME=${PACK_PREFIX}-DATABASE-${OS_SUFFIX}-${ARCH}bit
    SYMBOL_PACK_DIR_NAME=${PACK_PREFIX}-DATABASE-${OS_SUFFIX}-${ARCH}bit-SYMBOL
    OGBOX_DIR_NAME=${PACK_PREFIX}-OGBOX
    TOOLS_PACK_DIR_NAME=${PACK_PREFIX}-TOOLS
    JDRIVER_PACK_DIR_NAME=${PACK_PREFIX}-CLIENT-JDBC
    OGSQL_PACK_DIR_NAME=${PACK_PREFIX}-OGSQL-${OS_SUFFIX}-${ARCH}bit

    if [[ ! -d "${OGRACDB_BIN}" ]]; then
        echo "bin dir not exist"
        exit 1
    else
        echo "chmod 755"
        chmod -R 755 ${OGRACDB_BIN}/*
    fi

    cd ${OGRACDB_BIN}
    rm -rf ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}*
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/data
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/log
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/protect
    mkdir -p ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/var
}


func_prepare_no_clean_debug()
{
    export BUILD_MODE=Debug
    cd ${OGRACDB_BUILD}
    # Clean stale CMake cache to avoid source-dir mismatch when switching kernels
    rm -f CMakeCache.txt
    rm -rf CMakeFiles
    cmake -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DUSE32BIT=OFF ${COMPILE_OPTS} ..
}

func_prepare_no_clean_release()
{
    export BUILD_MODE=Release
    cd ${OGRACDB_BUILD}
    # Clean stale CMake cache to avoid source-dir mismatch when switching kernels
    rm -f CMakeCache.txt
    rm -rf CMakeFiles
    cmake -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_BUILD_TYPE=Release -DUSE32BIT=OFF \
          -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} ${COMPILE_OPTS} ..
    sed -i "s/-O3/-O2/g" CMakeCache.txt
}

func_prepare_debug()
{
    export PYTHON_INCLUDE_DIR=${PYTHON3_HOME}
    func_prepare_no_clean_debug
}


func_prepare_release()
{
    export PYTHON_INCLUDE_DIR=${PYTHON3_HOME}
    func_prepare_no_clean_release
}

func_all()
{
    ## download dependency:
    func_prepare_dependency

    local build_mode=$1
    if [[ -z "${build_mode}" ]]; then
        build_mode='Debug'
    fi

    if [[ "${build_mode}" = 'Debug' ]]; then
        func_prepare_debug
    else
        func_prepare_release
    fi

    cd ${OG_SRC_BUILD_DIR}
    set +e
    make all -sj 8
    if [ $? -ne 0 ]; then
        ls -al ${OGRACDB_LIB}
        ls -al /home/regress
        ls -al /home/regress/ogracKernel/build
        exit 1
    fi
    set -e

    if [[ -e "${OGRACDB_BIN}"/ogracd ]]; then
        cd ${OGRACDB_BIN}
        if [ -e "${OGRACD_BIN}" ]; then
          rm ${OGRACD_BIN}
        fi
        ln ogracd ${OGRACD_BIN}
    fi
}

func_release_symbol()
{
    if [ "${ENABLE_LLT_ASAN}" == "NO" ]; then
        echo "release symbol"
        mkdir -p ${OGRACDB_SYMBOL}
        echo ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_LIB}/libogclient.so
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_LIB}/libogclient.so
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_LIB}/libogcommon.so
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_LIB}/libogprotocol.so
        mv -f ${OGRACDB_LIB}/libogclient.${SO}.${SYMBOLFIX} ${OGRACDB_SYMBOL}/libogclient.${SO}.${SYMBOLFIX}
        mv -f ${OGRACDB_LIB}/libogcommon.${SO}.${SYMBOLFIX} ${OGRACDB_SYMBOL}/libogcommon.${SO}.${SYMBOLFIX}
        mv -f ${OGRACDB_LIB}/libogprotocol.${SO}.${SYMBOLFIX} ${OGRACDB_SYMBOL}/libogprotocol.${SO}.${SYMBOLFIX}

        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/${OGRACD_BIN}
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/cms
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/ogencrypt
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/ogsql
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/ogbox
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/ogbackup
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${OGRACDB_BIN}/dbstor
        mv -f ${OGRACDB_BIN}/${OGRACD_BIN}.${SYMBOLFIX} ${OGRACDB_SYMBOL}/${OGRACD_BIN}.${SYMBOLFIX}
        mv -f ${OGRACDB_BIN}/cms.${SYMBOLFIX} ${OGRACDB_SYMBOL}/cms.${SYMBOLFIX}
        mv -f ${OGRACDB_BIN}/ogencrypt.${SYMBOLFIX} ${OGRACDB_SYMBOL}/ogencrypt.${SYMBOLFIX}
        mv -f ${OGRACDB_BIN}/ogsql.${SYMBOLFIX} ${OGRACDB_SYMBOL}/ogsql.${SYMBOLFIX}
        mv -f ${OGRACDB_BIN}/ogbox.${SYMBOLFIX} ${OGRACDB_SYMBOL}/ogbox.${SYMBOLFIX}
        mv -f ${OGRACDB_BIN}/ogbackup.${SYMBOLFIX} ${OGRACDB_SYMBOL}/ogbackup.${SYMBOLFIX}
        mv -f ${OGRACDB_BIN}/dbstor.${SYMBOLFIX} ${OGRACDB_SYMBOL}/dbstor.${SYMBOLFIX}

        ##opensource library
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${LZ4_LIB_PATH}/liblz4.so.1.9.4
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${Z_LIB_PATH}/libz.so.1.2.13
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${PCRE_LIB_PATH}/libpcre2-8.so.0.11.0
        sh  ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${ZSTD_LIB_PATH}/libzstd.so.1.5.2
        mv -f ${LZ4_LIB_PATH}/liblz4.so.1.9.4.${SYMBOLFIX}   ${OGRACDB_SYMBOL}/liblz4.so.1.9.4.${SYMBOLFIX}
        mv -f ${Z_LIB_PATH}/libz.so.1.2.13.${SYMBOLFIX}       ${OGRACDB_SYMBOL}/libz.so.1.2.13.${SYMBOLFIX}
        mv -f ${PCRE_LIB_PATH}/libpcre2-8.so.0.11.0.${SYMBOLFIX} ${OGRACDB_SYMBOL}/libpcre2-8.so.0.11.0.${SYMBOLFIX}
        mv -f ${ZSTD_LIB_PATH}/libzstd.so.1.5.2.${SYMBOLFIX} ${OGRACDB_SYMBOL}/libzstd.so.1.5.2.${SYMBOLFIX}

        sh ${OGRACDB_BUILD}/${DBG_SYMBOL_SCRIPT} ${ZSTD_LIB_PATH}/../bin/zstd
        mv -f ${ZSTD_LIB_PATH}/../bin/zstd.${SYMBOLFIX} ${OGRACDB_SYMBOL}/zstd.${SYMBOLFIX}

        func_pkg_symbol
    fi
}

func_version()
{
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > ${OGRACDB_BIN}/package.xml
    echo "<PackageInfo>" >> ${OGRACDB_BIN}/package.xml
    echo "----------Start build oGRAC-----------" >> ${OGRACDB_BIN}/package.xml
    echo "name=\"oGRACDB\"" >> ${OGRACDB_BIN}/package.xml
    echo "version=\"${VERSION_DESCRIP} ${BUILD_MODE}\"" >> ${OGRACDB_BIN}/package.xml
    echo "desc=\"oGRACDB install\"" >> ${OGRACDB_BIN}/package.xml
    merge_time=$(cat ${OGRACDB_BUILD}/conf/git_message.in | grep merge_time |  awk -F'=' '{print  $2}')
    echo "createDate=\"${merge_time}\"" >> ${OGRACDB_BIN}/package.xml
    oGRAC_merge_time=$(cat ${OGRACDB_BUILD}/conf/git_message.in | grep oGRAC_merge_time |  awk -F'=' '{print  $2}')
    echo "createDate=\"${oGRAC_merge_time}\"" >> ${OGRACDB_BIN}/package.xml
    WHOLE_COMMIT_ID=$(cat ${OGRACDB_BUILD}/conf/git_message.in | grep gitVersion |  awk -F'=' '{print  $2}')
    echo "gitVersion=\"${WHOLE_COMMIT_ID}\"" >> ${OGRACDB_BIN}/package.xml
    echo "</PackageInfo>" >> ${OGRACDB_BIN}/package.xml
}

func_version_run_pkg()
{
    func_version
    cp  ${OGRACDB_BIN}/package.xml ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}
}

func_version_ogsql_pkg()
{
    func_version
    cp  ${OGRACDB_BIN}/package.xml ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}
}

func_pkg_run_basic()
{
    func_version_run_pkg

    cd ${OGRACDB_BIN}
    cp ogsql ogracd ogencrypt cms ogbackup ogbox ogrst dbstor ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp -d ${ZSTD_LIB_PATH}/../bin/zstd ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cd ${OGRACDB_HOME}
    cp ${OGRACDB_INSTALL}/installdb.sh  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${OGRACDB_INSTALL}/shutdowndb.sh  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${OGRACDB_INSTALL}/uninstall.py  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${OGRACDB_INSTALL}/script/cluster/cluster.sh  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${OGRACDB_INSTALL}/sql_process.py  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp ${OGRACDB_INSTALL}/Common.py  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/
    cp -d ${OGRACDB_LIB}/libogclient.so  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${OGRACDB_LIB}/libogcommon.so  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${OGRACDB_LIB}/libogprotocol.so  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${OGRACDB_LIB}/libograc.so  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${OGRACDB_LIB}/libdsslock.so ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib/
    cp -d ${PCRE_LIB_PATH}/libpcre2-8.so*  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${Z_LIB_PATH}/libz.so*  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so*  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/

    cp -R ${OGRACDB_HOME}/admin  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/
    cp -R ${OGRACDB_HOME}/cfg  ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/
    if [ "${ENABLE_LLT_ASAN}" == "YES" ]; then
        if [[ ${OS_ARCH} =~ "x86_64" ]]; then
            cp -d /usr/lib64/libubsan.so* ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
            cp -d /usr/lib64/libasan.so* ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
        elif [[ ${OS_ARCH} =~ "aarch64" ]]; then
            cp -d ${OGRACDB_HOME}/../library/protobuf/${LIB_OS_ARCH}/libubsan.so* ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
            cp -d ${OGRACDB_HOME}/../library/protobuf/${LIB_OS_ARCH}/libasan.so* ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/
        else
            echo "OS_ARCH: ${OS_ARCH} is unknown."
        fi
    fi

    chmod -R 700 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/*
    chmod 500 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/*
    chmod 500 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/*
    chmod 600 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/cfg/*
    chmod 500 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/lib/*
    chmod 500 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/add-ons/*
    chmod 400 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/package.xml
}

func_pkg_run()
{
    func_pkg_run_basic
    find ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/ -type f -print0 | xargs -0 chmod 400
    find ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/ -type d -print0 | xargs -0 chmod 700
    cd ${OGRACDB_BIN} && tar --owner=root --group=root -zcf ${RUN_PACK_DIR_NAME}.tar.gz ${RUN_PACK_DIR_NAME}
    rm -rf ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/script
}

func_pkg_symbol()
{
    echo "pkg symbol"

    rm -rf ${OGRACDB_BIN}/${SYMBOL_PACK_DIR_NAME}*
    mkdir -p ${OGRACDB_BIN}/${SYMBOL_PACK_DIR_NAME}
    cp -rf ${OGRACDB_SYMBOL}/*.${SYMBOLFIX} ${OGRACDB_BIN}/${SYMBOL_PACK_DIR_NAME}/
    chmod 500 ${OGRACDB_BIN}/${SYMBOL_PACK_DIR_NAME}/*
    cd ${OGRACDB_BIN} && tar --owner=root --group=root -zcf ${SYMBOL_PACK_DIR_NAME}.tar.gz ${SYMBOL_PACK_DIR_NAME}
    sha256sum ${OGRACDB_BIN}/${SYMBOL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${OGRACDB_BIN}/${SYMBOL_PACK_DIR_NAME}.sha256
}

func_make_debug()
{
    echo "make debug"
    func_all Debug
    func_prepare_pkg_name
    func_pkg_run
}

func_make_release()
{
    echo "make release"
    func_all Release
    func_prepare_pkg_name
    # func_release_symbol
    func_pkg_run
}

func_test()
{
    echo "make test"
    func_all Debug
    strip -N main ${OGRACDB_LIB}/libogserver.a
    cd ${OG_TEST_BUILD_DIR}
    make -sj 8

    if [[ -e "${OGRACDB_BIN}"/ogracd ]]; then
        cd ${OGRACDB_BIN}
        rm -rf ${OGRACD_BIN} && ln ogracd ${OGRACD_BIN}
    fi

    if [[ ! -d "${OGRACDB_HOME}"/add-ons ]]; then
        mkdir -p  ${OGRACDB_HOME}/add-ons
    fi

    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${OGRACDB_HOME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so* ${OGRACDB_HOME}/add-ons/
    cp -rf ${OGRACDB_BIN} ${OGRACDB_HOME}
    cp -rf ${OGRACDB_LIB} ${OGRACDB_HOME}
    cp -rf ${OGRACDB_LIBRARY} ${OGRACDB_HOME}

}

prepare_bazel_dependency()
{
    echo "prepare_bazel_dependency"
    func_prepare_dependency

    if [[ ! -d "${OGRACDB_HOME}"/add-ons ]]; then
        mkdir -p  ${OGRACDB_HOME}/add-ons
    fi

    cp -d ${ZSTD_LIB_PATH}/libzstd.so*  ${OGRACDB_HOME}/add-ons/
    cp -d ${LZ4_LIB_PATH}/liblz4.so* ${OGRACDB_HOME}/add-ons/
    cp -rf ${OGRACDB_BIN} ${OGRACDB_HOME}
    cp -rf ${OGRACDB_LIB} ${OGRACDB_HOME}
    cp -rf ${OGRACDB_LIBRARY} ${OGRACDB_HOME}

}

func_clean()
{
    echo "make clean"
    func_prepare_debug
    func_prepare_pkg_name

    cd ${OGRACDB_BUILD}
    make clean

    cd ${OG_TEST_BUILD_DIR}
    make clean

    if [[ -d "${OGRACDB_BIN}" ]];then
        echo ${OGRACDB_BIN}
        chmod -R 700 ${OGRACDB_BIN}
    fi

    echo ${OGRACDB_OUTPUT}

    rm -rf ${OGRACDB_OUTPUT}/*
    rm -rf ${OGRACDB_HOME}/../${ALL_PACK_DIR_NAME}

    cd ${OGRACDB_BUILD}
    rm -rf pkg
    rm -rf CMakeFiles
    rm -f Makefile
    rm -f cmake_install.cmake
    rm -f CMakeCache.txt
}

func_pkg_ogsql()
{
    echo "make pkg ogsql"

    rm -rf ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}*
    mkdir -p ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}
    mkdir -p ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/bin
    mkdir -p ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/lib
    mkdir -p ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/add-ons

    func_version_ogsql_pkg

    cp ${OGRACDB_BIN}/ogsql ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/bin/ogsql
    cp -d ${OGRACDB_LIB}/libogclient.so ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/lib/
    cp -d ${OGRACDB_LIB}/libogcommon.so ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/lib/
    cp -d ${OGRACDB_LIB}/libogprotocol.so ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/lib/

    cp -d ${Z_LIB_PATH}/libz.so* ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/add-ons/
    cp -d ${PCRE_LIB_PATH}/libpcre2-8.so* ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/add-ons/

    chmod -R 700 ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/*
    chmod 500 ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/add-ons/*
    chmod 500 ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/bin/*
    chmod 500 ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/lib/*
    chmod 400 ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}/package.xml

    cd ${OGRACDB_BIN} && tar --owner=root --group=root -zcf ${OGSQL_PACK_DIR_NAME}.tar.gz ${OGSQL_PACK_DIR_NAME}
    sha256sum ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${OGRACDB_BIN}/${OGSQL_PACK_DIR_NAME}.sha256

}

func_making_package()
{
    build_package_mode=$1
    if [[ -z "${build_package_mode}" ]]; then
        build_package_mode='Debug'
    fi

    if [[ "${build_package_mode}" = 'Debug' ]] || [[ "${build_package_mode}" = 'Shard_Debug' ]]; then
        func_make_debug
    else
        echo "make release"
        func_all Release
        func_prepare_pkg_name
    fi

    if [[ "${build_package_mode}" = 'Release' ]] || [[ "${build_package_mode}" = 'Shard_Release' ]]; then
        # func_release_symbol
        func_pkg_run
    fi
    rm -rf ${OGRACDB_HOME}/../${ALL_PACK_DIR_NAME}
    rm -rf ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}
    rm -rf ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz
    mkdir -p ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}
    cp ${OGRACDB_HOME}/install/install.py ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${OGRACDB_HOME}/install/funclib.py ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${OGRACDB_HOME}/install/installdb.sh ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    mkdir -p ${OGRACDB_LIBRARY}/shared_lib/lib/
    cp -f ${OGRACDB_HOME}/../platform/HuaweiSecureC/lib/* ${OGRACDB_LIBRARY}/shared_lib/lib/

    chmod -R 500 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/install.py
    chmod -R 500 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/funclib.py
    chmod -R 500 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/installdb.sh
    mv ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}.tar.gz ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    sha256sum ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    chmod 400 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    cd ${OGRACDB_BIN} && tar --owner=root --group=root -zcf ${ALL_PACK_DIR_NAME}.tar.gz ${ALL_PACK_DIR_NAME}
    sha256sum ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}.sha256
    func_pkg_ogsql

    find ${OGRACDB_BIN} -name "*.sha256" -exec chmod 400 {} \;
    cp -arf ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME} ${OGRACDB_HOME}/../${ALL_PACK_DIR_NAME}
}

func_download_3rdparty()
{
    if [[ "${WORKSPACE}" == *"regress"* ]]; then
        DOWNLOAD_PATH=$DFT_WORKSPACE"/ogracKernel"
    else
        DOWNLOAD_PATH=${OGDB_CODE_PATH}
    fi
    
    cd ${DOWNLOAD_PATH}
    if [[ ${INTERNAL_BUILD} == "FALSE" ]]; then
      git submodule init
      git submodule update --recursive
    else
      echo "Clone source start"
      if [[ x"${proxy_user}" != x"" ]]; then
        export http_proxy=http://${proxy_user}:${proxy_pwd}@${proxy_url}
        export https_proxy=${http_proxy}
        export no_proxy=127.0.0.1,.huawei.com,localhost,local,.local
      fi    
      git clone https://gitee.com/cantian-repo/cantian-repo.git
      rm -rf open_source
      mv cantian-repo open_source
    fi    

    cd -

    echo "start compile 3rdparty : "
    sh compile_opensource_new.sh
}

## download 3rd-party lib and platform lib
func_prepare_dependency()
{
    echo "Prepare LCRP_HOME dependency func : "
    if [[ ! -d ${OGRACDB_LIBRARY} ]]; then
        echo "library dir not exist"
        mkdir -p ${OGRACDB_LIBRARY}
    fi

    if [[ ! -d ${OGRACDB_OPEN_SOURCE} ]]; then
        echo "open_source dir not exist"
        mkdir -p ${OGRACDB_OPEN_SOURCE}
    fi

    if [[ ! -d ${OGRACDB_OUTPUT} ]]; then
        echo "output dir not exist"
        mkdir -p ${OGRACDB_OUTPUT}
    fi

    if [[ ! -d ${OGRACDB_PLATFORM} ]]; then
        echo "platform dir not exist"
        mkdir -p ${OGRACDB_PLATFORM}
    fi

    #下载三方库并编译
    if [[ -z ${WITHOUT_DEPS} ]]; then
        func_download_3rdparty
    fi
}

func_prepare_LLT_dependency()
{
    echo "Prepare LCRP_HOME dependency func : "
    if [[ ! -d ${OGRACDB_LIBRARY} ]]; then
        echo "library dir not exist"
        mkdir -p ${OGRACDB_LIBRARY}
    fi

    if [[ ! -d ${OGRACDB_OPEN_SOURCE} ]]; then
        echo "open_source dir not exist"
        mkdir -p ${OGRACDB_OPEN_SOURCE}
    fi

    if [[ ! -d ${OGRACDB_OUTPUT} ]]; then
        echo "output dir not exist"
        mkdir -p ${OGRACDB_OUTPUT}
    fi

    if [[ ! -d ${OGRACDB_PLATFORM} ]]; then
        echo "platform dir not exist"
        mkdir -p ${OGRACDB_PLATFORM}
    fi

    #下载三方库并编译
    func_download_3rdparty

    if [[ $? -ne 0 ]]; then
        echo "dependency download failed"
        exit 1
    else
        echo "dependency download succeed"
    fi
}

#获取最新包地址
function expect_ssh_get_latest_tar_file_path() {
	local ip=$1
    local file_path=$2
    /usr/bin/expect << EOF
    spawn ssh aa_release@${ip} "ls ~${file_path} | sort | uniq | tail -n 1"
    expect {
        "*yes/no" { send "yes\r"; exp_continue }
        "*password:*" { send "aa_release\r"}
    }
    expect eof
EOF
}

# 从sftp服务器上下载包
function down_client_file() {
    local ip=$1
    local file_path=$2
    local local_file=$3
    /usr/bin/expect << EOF
    set timeout -1
    spawn scp -rp aa_release@${ip}:${file_path} ${local_file}
    expect {
        "*yes/no" { send "yes\r"; exp_continue }
        "*password:*" { send "aa_release\r"}
    }
    expect eof
EOF
}

func_make_raft()
{
    ## download dependency:
    func_prepare_dependency

    echo "make raft"

    raft_build_mode=$1
    if [[ -z "${raft_build_mode}" ]]; then
        raft_build_mode='Debug'
    fi

    if [[ "${raft_build_mode}" = 'Debug' ]]; then
        func_prepare_debug
    else
        func_prepare_release
    fi

    cd ${OG_SRC_BUILD_DIR}/raft && make -sj 8
}

func_regress_test()
{
    echo "make debug"
    ## download dependency:
    func_prepare_LLT_dependency
    func_prepare_debug
    cd ${OG_SRC_BUILD_DIR}
    set +e
    make all -sj 8
    if [ $? -ne 0 ]; then
        ls -al ${OGRACDB_LIB}
        ls -al /home/regress
        ls -al /home/regress/ogracKernel/build
        exit 1
    fi
    set -e

    if [[ -e "${OGRACDB_BIN}"/ogracd ]]; then
        cd ${OGRACDB_BIN}
        if [ -e "${OGRACD_BIN}" ]; then
          rm ${OGRACD_BIN}
        fi
        ln ogracd ${OGRACD_BIN}
    fi
}

func_make_test_debug()
{
    echo "make debug"
    ## download dependency:
    func_prepare_LLT_dependency
    func_prepare_debug
    cd ${OG_SRC_BUILD_DIR}
    set +e
    make all -sj 8
    if [ $? -ne 0 ]; then
        ls -al ${OGRACDB_LIB}
        ls -al /home/regress
        ls -al /home/regress/ogracKernel/build
        exit 1
    fi
    set -e

    if [[ -e "${OGRACDB_BIN}"/ogracd ]]; then
        cd ${OGRACDB_BIN}
        if [ -e "${OGRACD_BIN}" ]; then
          rm ${OGRACD_BIN}
        fi
        ln ogracd ${OGRACD_BIN}
    fi
    func_prepare_pkg_name
    func_pkg_run_basic
    chmod 400 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/*
    #chmod 700 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/upgrade
    #chmod 400 ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/admin/scripts/upgrade/*
    cd ${OGRACDB_BIN} && tar --owner=root --group=root -zcf ${RUN_PACK_DIR_NAME}.tar.gz ${RUN_PACK_DIR_NAME}
    rm -rf ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}/bin/script
}

func_making_package_test()
{
    build_package_mode=$1
    if [[ -z "${build_package_mode}" ]]; then
        build_package_mode = 'Debug'
    fi

    func_make_test_debug

    rm -rf ${OGRACDB_HOME}/../${ALL_PACK_DIR_NAME}
    rm -rf ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}
    rm -rf ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz
    mkdir -p ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}
    cp ${OGRACDB_HOME}/install/install.py ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${OGRACDB_HOME}/install/funclib.py ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    cp ${OGRACDB_HOME}/install/installdb.sh ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/

    chmod -R 500 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/install.py
    chmod -R 500 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/funclib.py
    chmod -R 500 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/installdb.sh
    mv ${OGRACDB_BIN}/${RUN_PACK_DIR_NAME}.tar.gz ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/
    sha256sum ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    chmod 400 ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}/${RUN_PACK_DIR_NAME}.sha256
    cd ${OGRACDB_BIN} && tar --owner=root --group=root -zcf ${ALL_PACK_DIR_NAME}.tar.gz ${ALL_PACK_DIR_NAME}
    sha256sum ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}.tar.gz | cut -c1-64 > ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME}.sha256

    find ${OGRACDB_BIN} -name "*.sha256" -exec chmod 400 {} \;
    cp -arf ${OGRACDB_BIN}/${ALL_PACK_DIR_NAME} ${OGRACDB_HOME}/../${ALL_PACK_DIR_NAME}
}

main()
{
    echo "Main Function : "
    arg0=$0
    arg1=$1

    until [[ -z "$2" ]]
    do {
        echo $2
        arg2=$2

        case "${arg2}" in
        'test_cbo=1')
            echo "test_cbo enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_CBOTEST=ON"
            ;;
        'protect_buf=1')
            echo "protect_buf enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_BUF=ON"
            ;;
        'crc=1')
            echo "crc enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_CRC=ON"
            ;;
        'protect_vm=1')
            echo "protect_vm enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
            ;;
        'ogracd_cn=1')
            echo "ogracd_cn enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_OGRACD_CN=ON"
            ;;
        'test_mem=1')
            echo "test_mem enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_TEST_MEM=ON"
            ;;
        'lcov=1')
            echo "lcov enable"
            ENABLE_LLT_GCOV="YES"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_LCOV=ON"
            ;;
        'llt=1')
            echo "llt enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_LLT=ON"
            ;;
        'asan=1')
            echo "ASAN enable"
            ENABLE_LLT_ASAN="YES"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_ASAN=ON"
            ;;
        'fuzzasan=1')
            echo "FUZZ ASAN ENABLE"
            mkdir -p ${OGRACDB_LIB}
            cp -f ${OGRACDB_LIBRARY}/secodefuzz/lib/* ${OGRACDB_LIB}
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_ASAN=ON"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_FUZZASAN=ON"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_LCOV=ON"
            ;;
        'tsan=1')
            echo "TSAN enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_TSAN=ON"
            ;;
        'canalyze=1')
            echo "Canalyze enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DCMAKE_EXPORT_COMPILE_COMMANDS=1 "
            ;;
        'h1620=1')
            echo "h1620 enable"
            COMPILE_OPTS="${COMPILE_OPTS} -DUSE_H1620=ON"
            ;;
        'FEATURE_FOR_EVERSQL=1')
            echo "build with FEATURE FOR_EVERSQL"
            FEATURE_FOR_EVERSQL="1";
            ;;
        '--without-deps')
            echo "no need for 3rdparty dependency compilation"
            WITHOUT_DEPS="true"
            ;;
        *)
            echo "Wrong compile options"
            exit 1
            ;;
        esac
        shift
    }
    done

    case "${arg1}" in
    'all')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_all Debug
        ;;
    'debug')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_make_debug
        ;;
    'release')
        func_make_release
        ;;
    'clean')
        func_clean
        ;;
    'test')
	    COMPILE_OPTS="${COMPILE_OPTS} -DCMS_UT_TEST=ON"
        func_test
        ;;
    'package'|'package-debug')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_making_package Debug
        ;;
    'package-release')
        func_making_package Release
        ;;
    'bazel_dependency')
        prepare_bazel_dependency
        ;;
    'make_regress_test')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON -DCMS_UT_TEST=ON"
        func_regress_test
        ;;
    'make_ograc_pkg_test')
        COMPILE_OPTS="${COMPILE_OPTS} -DUSE_PROTECT_VM=ON"
        func_making_package_test Debug
        ;;
    *)

        echo "Wrong parameters"
        exit 1
        ;;
    esac
}

main $@
