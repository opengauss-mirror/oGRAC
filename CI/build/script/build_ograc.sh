#!/bin/bash
set -e

BUILD_TYPE=${BUILD_TYPE:-"DEBUG"}
ENV_TYPE=${ENV_TYPE:-"x86_64"}
HOME_PATH="/home/regress"
OGDB_CODE_PATH=${HOME_PATH}/ogracKernel
if [ -n "${WORKSPACE}" ]; then
    HOME_PATH=${WORKSPACE}
    OGDB_CODE_PATH=${HOME_PATH}/oGRAC
fi

if [[ ${ENV_TYPE} == "aarch64" ]]; then 
    export C_INCLUDE_PATH=:/usr/include/python3.9/
fi

source /etc/profile

function linkCodeToHome() {
  # 如果代码路径不在HOME_PATH下，需要链接过去
  if [ -d ${OGDB_CODE_PATH} ]; then
      return 0
  fi
  
  if [ -L ${OGDB_CODE_PATH} ]; then
    rm -f ${OGDB_CODE_PATH}
  fi

  local code_home=$(dirname $(realpath ${BASH_SOURCE[0]}))/../../../..
  ln -s ${code_home}/oGRAC ${OGDB_CODE_PATH}
  ln -s ${code_home}/oGRAC_om ${HOME_PATH}/oGRAC_om
}

function buildoGRACDebug() {
  echo "Start buildoGRACDebug..."
  cd ${OGDB_CODE_PATH}/build
  sh Makefile.sh debug
}

function buildoGRACRelease() {
  echo "Start buildoGRACRelease..."
  cd ${OGDB_CODE_PATH}/build
  sh Makefile.sh release
}

echo "Start build oGRAC only"
echo "BUILD_TYPE: ${BUILD_TYPE}"
echo "ENV_TYPE: ${ENV_TYPE}"
echo "BUILD_MODE: ${BUILD_MODE}"
echo "HOME_PATH: ${HOME_PATH}"
echo "code_home: ${code_home}"

linkCodeToHome

if [ "${BUILD_TYPE}" == "DEBUG" ]; then
  buildoGRACDebug
elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
  buildoGRACRelease
fi
